use std::{fmt::Write as _, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, RequestBuilder, Url, header::HeaderValue};
use rsa::{BigUint, Pss, RsaPublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha384};

const CONSENSUS_DEPTH: u64 = 50;
const HASH_SIZE: usize = 32;
const NOTE_SIZE: usize = 32;
const BRANCH_SIZE: usize = HASH_SIZE * 2 + NOTE_SIZE;
const LEAF_SIZE: usize = HASH_SIZE + NOTE_SIZE;
const MAX_CHUNK_SIZE: u128 = 256 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_PROOF_BYTES: usize = 64 * 1024;
const STRICT_DATA_SPLIT_THRESHOLD: u128 = 30_607_159_107_830;
const MERKLE_REBASE_SUPPORT_THRESHOLD: u128 = 151_066_495_197_430;

#[derive(Clone, Debug)]
pub struct Config {
    pub trusted_node_url: String,
    pub archive_url: String,
    pub chunk_sources: Vec<String>,
    pub request_timeout: Duration,
    pub max_peer_attempts: usize,
}

impl Config {
    pub fn new(
        trusted_node_url: impl Into<String>,
        archive_url: impl Into<String>,
        chunk_sources: Vec<String>,
        request_timeout: Duration,
        max_peer_attempts: usize,
    ) -> Result<Self> {
        let trusted_node_url = normalize_base_url(&trusted_node_url.into())?;
        let archive_url = normalize_base_url(&archive_url.into())?;
        let chunk_sources = chunk_sources
            .into_iter()
            .map(|source| normalize_base_url(&source))
            .collect::<Result<Vec<_>>>()?;

        ensure!(
            !chunk_sources.is_empty(),
            "at least one chunk source is required"
        );
        ensure!(max_peer_attempts > 0, "max peer attempts must be positive");
        ensure!(
            !request_timeout.is_zero(),
            "request timeout must be positive"
        );

        Ok(Self {
            trusted_node_url,
            archive_url,
            chunk_sources,
            request_timeout,
            max_peer_attempts,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedData {
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
    pub id: String,
    pub block_height: u64,
    pub content_type: String,
    pub content_length: usize,
    pub etag: String,
    pub sha256: String,
}

pub struct Gateway {
    config: Config,
    client: Client,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { config, client })
    }

    pub async fn retrieve_direct(&self, id: &str) -> Result<VerifiedData> {
        decode_fixed::<32>(id, "transaction ID")?;

        let status: TxStatus = self
            .get_json(&self.config.archive_url, &format!("tx/{id}/status"))
            .await
            .context("failed to fetch transaction status")?;
        ensure!(
            status.block_height > 0,
            "genesis transactions are unsupported"
        );
        decode_fixed::<48>(&status.block_indep_hash, "status block hash")?;

        let info: NodeInfo = self
            .get_json(&self.config.trusted_node_url, "info")
            .await
            .context("failed to fetch trusted node height")?;
        ensure!(
            info.height >= status.block_height.saturating_add(CONSENSUS_DEPTH),
            "transaction block is inside the trusted node consensus window"
        );

        let index_path = format!(
            "block_index/{}/{}",
            status.block_height - 1,
            status.block_height
        );
        let entries: Vec<BlockIndexEntry> = self
            .request_json(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, &index_path))
                    .header("x-block-format", "1"),
            )
            .await
            .context("failed to fetch trusted block index")?;
        ensure!(
            entries.len() == 2,
            "trusted block index returned incomplete geometry"
        );
        let block = &entries[0];
        let previous_block = &entries[1];
        ensure!(
            block.hash == status.block_indep_hash,
            "archival status does not match the trusted block index"
        );

        let transaction: Transaction = self
            .get_json(&self.config.archive_url, &format!("tx/{id}"))
            .await
            .context("failed to fetch transaction header")?;
        verify_transaction(&transaction, id)?;

        let offset: TxOffset = self
            .get_json(&self.config.archive_url, &format!("tx/{id}/offset"))
            .await
            .context("failed to fetch transaction offset")?;
        let data_size = parse_u128(&transaction.data_size, "transaction data size")?;
        let offset_size = parse_u128(&offset.size, "offset data size")?;
        let end_offset = parse_u128(&offset.offset, "transaction end offset")?;
        ensure!(
            data_size > 0,
            "zero-byte direct transactions are unsupported"
        );
        ensure!(
            offset_size == data_size,
            "transaction size and offset size differ"
        );

        let block_weave_size = parse_u128(&block.weave_size, "block weave size")?;
        let previous_weave_size =
            parse_u128(&previous_block.weave_size, "previous block weave size")?;
        ensure!(
            block_weave_size > previous_weave_size,
            "invalid block weave geometry"
        );
        let first_offset = end_offset
            .checked_sub(data_size - 1)
            .context("transaction offset underflow")?;
        ensure!(
            first_offset > previous_weave_size,
            "transaction starts before its block"
        );
        ensure!(
            end_offset <= block_weave_size,
            "transaction ends after its block"
        );

        let geometry = Geometry {
            tx_root: decode_fixed(&block.tx_root, "block tx_root")?,
            data_root: decode_fixed(&transaction.data_root, "transaction data root")?,
            block_weave_size,
            previous_weave_size,
            first_offset,
            end_offset,
            data_size,
        };

        let expected_len = usize::try_from(data_size).context("transaction is too large")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_len)
            .context("unable to reserve transaction buffer")?;
        let max_chunks = data_size.div_ceil(MAX_CHUNK_SIZE) + 1;
        let mut chunks = 0u128;

        while bytes.len() < expected_len {
            ensure!(
                chunks < max_chunks,
                "chunk count exceeded transaction bound"
            );
            let relative_offset = bytes.len() as u128;
            let absolute_offset = first_offset
                .checked_add(relative_offset)
                .context("chunk offset overflow")?;
            let chunk = self
                .fetch_verified_chunk(absolute_offset, relative_offset, &geometry)
                .await?;
            ensure!(!chunk.is_empty(), "verified chunk made no forward progress");
            ensure!(
                chunk.len() <= expected_len - bytes.len(),
                "verified chunk exceeds transaction size"
            );
            bytes.extend_from_slice(&chunk);
            chunks += 1;
        }

        ensure!(
            bytes.len() == expected_len,
            "assembled transaction is incomplete"
        );
        let body_hash = sha256(&[&bytes]);
        let content_type = content_type(&transaction.tags)?;

        Ok(VerifiedData {
            bytes,
            id: id.to_owned(),
            block_height: status.block_height,
            content_type,
            content_length: expected_len,
            etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(body_hash)),
            sha256: hex(&body_hash),
        })
    }

    async fn fetch_verified_chunk(
        &self,
        absolute_offset: u128,
        relative_offset: u128,
        geometry: &Geometry,
    ) -> Result<Vec<u8>> {
        let mut failures = Vec::new();
        let sources = self
            .config
            .chunk_sources
            .iter()
            .take(self.config.max_peer_attempts);

        for source in sources {
            let result = async {
                let chunk: JsonChunk = self
                    .get_json(source, &format!("chunk/{absolute_offset}"))
                    .await?;
                verify_chunk(chunk, absolute_offset, relative_offset, geometry)
            }
            .await;

            match result {
                Ok(chunk) => return Ok(chunk),
                Err(error) => failures.push(format!("{source}: {error:#}")),
            }
        }

        bail!("all bounded chunk attempts failed: {}", failures.join("; "))
    }

    async fn get_json<T: DeserializeOwned>(&self, base: &str, path: &str) -> Result<T> {
        self.request_json(self.client.get(endpoint(base, path)))
            .await
    }

    async fn request_json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let mut response = request
            .send()
            .await
            .context("HTTP request failed")?
            .error_for_status()
            .context("HTTP source rejected request")?;

        if let Some(length) = response.content_length() {
            ensure!(
                length <= MAX_JSON_BYTES as u64,
                "JSON response exceeds size limit"
            );
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.context("failed to read HTTP body")? {
            ensure!(
                body.len().saturating_add(chunk.len()) <= MAX_JSON_BYTES,
                "JSON response exceeds size limit"
            );
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&body).context("source returned malformed JSON")
    }
}

#[derive(Deserialize)]
struct NodeInfo {
    height: u64,
}

#[derive(Deserialize)]
struct TxStatus {
    block_height: u64,
    block_indep_hash: String,
}

#[derive(Deserialize)]
struct BlockIndexEntry {
    tx_root: String,
    weave_size: String,
    hash: String,
}

#[derive(Deserialize)]
struct TxOffset {
    size: String,
    offset: String,
}

#[derive(Deserialize)]
struct Transaction {
    format: u8,
    id: String,
    last_tx: String,
    owner: String,
    tags: Vec<Tag>,
    target: String,
    quantity: String,
    data_size: String,
    data_root: String,
    reward: String,
    signature: String,
}

#[derive(Deserialize)]
struct Tag {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct JsonChunk {
    chunk: String,
    data_path: String,
    tx_path: String,
}

struct Geometry {
    tx_root: [u8; 32],
    data_root: [u8; 32],
    block_weave_size: u128,
    previous_weave_size: u128,
    first_offset: u128,
    end_offset: u128,
    data_size: u128,
}

fn verify_chunk(
    chunk: JsonChunk,
    absolute_offset: u128,
    relative_offset: u128,
    geometry: &Geometry,
) -> Result<Vec<u8>> {
    let bytes = decode_b64(&chunk.chunk, "chunk bytes")?;
    let data_path = decode_b64(&chunk.data_path, "data_path")?;
    let tx_path = decode_b64(&chunk.tx_path, "tx_path")?;
    ensure!(
        bytes.len() <= MAX_CHUNK_SIZE as usize,
        "chunk exceeds protocol limit"
    );
    ensure!(
        data_path.len() <= MAX_PROOF_BYTES,
        "data_path exceeds size limit"
    );
    ensure!(
        tx_path.len() <= MAX_PROOF_BYTES,
        "tx_path exceeds size limit"
    );

    let transaction = validate_tx_path(
        &geometry.tx_root,
        absolute_offset,
        geometry.block_weave_size,
        geometry.previous_weave_size,
        &tx_path,
    )?;
    ensure!(
        transaction.data_root == geometry.data_root,
        "tx_path data root mismatch"
    );
    ensure!(
        transaction.end_offset == geometry.end_offset,
        "tx_path end offset mismatch"
    );
    ensure!(
        transaction.size == geometry.data_size,
        "tx_path transaction size mismatch"
    );
    ensure!(
        transaction.start_bound.checked_add(1) == Some(geometry.first_offset),
        "tx_path start offset mismatch"
    );

    let data = validate_data_path(
        &geometry.data_root,
        geometry.data_size,
        relative_offset,
        absolute_offset,
        &data_path,
    )?;
    ensure!(
        data.start == relative_offset,
        "data_path does not start at requested offset"
    );
    ensure!(
        data.end <= geometry.data_size,
        "data_path ends after transaction"
    );
    let proven_size = usize::try_from(data.end - data.start).context("chunk size overflow")?;
    ensure!(
        bytes.len() == proven_size,
        "chunk length does not match data_path"
    );
    ensure!(
        sha256(&[&bytes]) == data.data_hash,
        "chunk hash does not match data_path"
    );

    Ok(bytes)
}

fn verify_transaction(transaction: &Transaction, expected_id: &str) -> Result<()> {
    ensure!(
        transaction.format == 2,
        "only format-2 transactions are supported"
    );
    ensure!(
        transaction.id == expected_id,
        "transaction header ID mismatch"
    );

    let signature = decode_b64(&transaction.signature, "transaction signature")?;
    let actual_id = sha256(&[&signature]);
    ensure!(
        decode_fixed::<32>(&transaction.id, "transaction ID")? == actual_id,
        "transaction ID is not the signature hash"
    );

    let owner = decode_b64(&transaction.owner, "transaction owner")?;
    ensure!(!owner.is_empty(), "ECDSA transactions are unsupported");
    let mut fields = Vec::with_capacity(9);
    fields.push(deep_hash_blob(b"2"));
    fields.push(deep_hash_blob(&owner));
    fields.push(deep_hash_blob(&decode_b64(
        &transaction.target,
        "transaction target",
    )?));
    fields.push(deep_hash_blob(transaction.quantity.as_bytes()));
    fields.push(deep_hash_blob(transaction.reward.as_bytes()));
    fields.push(deep_hash_blob(&decode_b64(
        &transaction.last_tx,
        "transaction anchor",
    )?));

    let mut tag_hashes = Vec::with_capacity(transaction.tags.len());
    for tag in &transaction.tags {
        tag_hashes.push(deep_hash_list(&[
            deep_hash_blob(&decode_b64(&tag.name, "tag name")?),
            deep_hash_blob(&decode_b64(&tag.value, "tag value")?),
        ]));
    }
    fields.push(deep_hash_list(&tag_hashes));
    fields.push(deep_hash_blob(transaction.data_size.as_bytes()));
    fields.push(deep_hash_blob(&decode_fixed::<32>(
        &transaction.data_root,
        "transaction data root",
    )?));

    let signature_payload = deep_hash_list(&fields);
    let signature_digest = Sha256::digest(signature_payload);
    let key = RsaPublicKey::new(BigUint::from_bytes_be(&owner), BigUint::from(65_537u32))
        .context("invalid RSA transaction owner")?;
    let encoded_len = (key.n().bits().saturating_sub(1) as usize).div_ceil(8);
    let max_salt = encoded_len.saturating_sub(32 + 2);
    let mut valid = false;

    for salt_len in [0, 32, max_salt] {
        if key
            .verify(
                Pss::new_with_salt::<Sha256>(salt_len),
                &signature_digest,
                &signature,
            )
            .is_ok()
        {
            valid = true;
            break;
        }
    }

    ensure!(valid, "transaction signature verification failed");
    Ok(())
}

fn content_type(tags: &[Tag]) -> Result<String> {
    for tag in tags {
        if decode_b64(&tag.name, "tag name")? == b"Content-Type" {
            let value = decode_b64(&tag.value, "Content-Type tag")?;
            let value = HeaderValue::from_bytes(&value)
                .context("invalid Content-Type tag")?
                .to_str()
                .context("non-ASCII Content-Type tag")?
                .to_owned();
            let media_type = value.split(';').next().unwrap_or_default().trim();
            return Ok(if value.contains("charset=") {
                value
            } else if media_type.starts_with("text/")
                || media_type == "application/json"
                || media_type.ends_with("+json")
            {
                format!("{value}; charset=utf-8")
            } else {
                value
            });
        }
    }
    Ok("application/octet-stream".to_owned())
}

struct TxPath {
    data_root: [u8; 32],
    start_bound: u128,
    end_offset: u128,
    size: u128,
}

fn validate_tx_path(
    tx_root: &[u8; 32],
    absolute_offset: u128,
    block_weave_size: u128,
    previous_weave_size: u128,
    path: &[u8],
) -> Result<TxPath> {
    ensure!(path.len() >= LEAF_SIZE, "tx_path is too short");
    ensure!(
        (path.len() - LEAF_SIZE).is_multiple_of(BRANCH_SIZE),
        "tx_path length is malformed"
    );
    ensure!(block_weave_size > previous_weave_size, "invalid block size");
    ensure!(
        absolute_offset > previous_weave_size && absolute_offset <= block_weave_size,
        "requested offset is outside block"
    );

    let block_size = block_weave_size - previous_weave_size;
    let target = absolute_offset - previous_weave_size - 1;
    let mut left_bound = 0u128;
    let mut right_bound = block_size;
    let mut current_hash = *tx_root;
    let mut cursor = 0usize;

    while path.len() - cursor > LEAF_SIZE {
        ensure!(
            cursor + BRANCH_SIZE <= path.len(),
            "truncated tx_path branch"
        );
        let left: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
        let right: [u8; 32] = path[cursor + HASH_SIZE..cursor + HASH_SIZE * 2]
            .try_into()
            .unwrap();
        let note = &path[cursor + HASH_SIZE * 2..cursor + BRANCH_SIZE];
        ensure!(
            hash_branch(&left, &right, note) == current_hash,
            "invalid tx_path branch"
        );
        let offset = note_to_u128(note)?;
        cursor += BRANCH_SIZE;

        if target < offset {
            current_hash = left;
            right_bound = right_bound.min(offset);
        } else {
            current_hash = right;
            left_bound = left_bound.max(offset);
        }
    }

    ensure!(cursor + LEAF_SIZE == path.len(), "truncated tx_path leaf");
    let data_root: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
    let note = &path[cursor + HASH_SIZE..cursor + LEAF_SIZE];
    ensure!(
        hash_leaf(&data_root, note) == current_hash,
        "invalid tx_path leaf"
    );
    let relative_end = note_to_u128(note)?;
    ensure!(
        relative_end > left_bound,
        "tx_path has an empty transaction"
    );
    ensure!(
        relative_end <= right_bound,
        "tx_path end exceeds its branch"
    );

    Ok(TxPath {
        data_root,
        start_bound: previous_weave_size + left_bound,
        end_offset: previous_weave_size + relative_end,
        size: relative_end - left_bound,
    })
}

#[derive(Clone, Copy)]
enum SplitCheck {
    None,
    Strict,
    Relaxed,
}

#[derive(Clone, Copy)]
struct DataContext {
    data_size: u128,
    is_rightmost: Option<bool>,
    left_shift: u128,
    check_borders: bool,
    check_split: SplitCheck,
    allow_rebase: bool,
    rebase_depth: u8,
}

struct DataPath {
    start: u128,
    end: u128,
    data_hash: [u8; 32],
}

fn validate_data_path(
    data_root: &[u8; 32],
    data_size: u128,
    relative_offset: u128,
    absolute_offset: u128,
    path: &[u8],
) -> Result<DataPath> {
    ensure!(data_size > 0, "data_path has zero data size");
    ensure!(
        relative_offset < data_size,
        "data_path offset is outside transaction"
    );
    ensure!(path.len() >= LEAF_SIZE, "data_path is too short");

    let (check_borders, check_split, allow_rebase) =
        if absolute_offset >= MERKLE_REBASE_SUPPORT_THRESHOLD {
            (true, SplitCheck::Relaxed, true)
        } else if absolute_offset >= STRICT_DATA_SPLIT_THRESHOLD {
            (true, SplitCheck::Strict, false)
        } else {
            (false, SplitCheck::None, false)
        };
    let context = DataContext {
        data_size,
        is_rightmost: None,
        left_shift: 0,
        check_borders,
        check_split,
        allow_rebase,
        rebase_depth: 0,
    };

    walk_rebased_data_path(
        Some(data_root),
        relative_offset,
        0,
        data_size,
        path,
        context,
    )
}

fn walk_rebased_data_path(
    root: Option<&[u8; 32]>,
    target: u128,
    left_bound: u128,
    right_bound: u128,
    path: &[u8],
    context: DataContext,
) -> Result<DataPath> {
    let rebased =
        context.allow_rebase && path.len() >= 128 && path[..32].iter().all(|byte| *byte == 0);
    if !rebased {
        return walk_data_path(
            root.context("missing data_path root")?,
            target,
            left_bound,
            right_bound,
            path,
            context,
        );
    }

    ensure!(
        context.rebase_depth < 64,
        "data_path rebasing depth exceeded"
    );
    let left: [u8; 32] = path[32..64].try_into().unwrap();
    let right: [u8; 32] = path[64..96].try_into().unwrap();
    let note = &path[96..128];
    if let Some(root) = root {
        ensure!(
            hash_branch(&left, &right, note) == *root,
            "invalid rebase branch"
        );
    }
    let boundary = note_to_u128(note)?;

    let (next_root, next_target, next_right, next_shift) = if target < boundary {
        let adjusted = right_bound.min(boundary);
        ensure!(adjusted >= left_bound, "invalid left rebase boundary");
        (
            left,
            target
                .checked_sub(left_bound)
                .context("rebase target underflow")?,
            adjusted - left_bound,
            context.left_shift + left_bound,
        )
    } else {
        let adjusted = left_bound.max(boundary);
        ensure!(right_bound >= adjusted, "invalid right rebase boundary");
        (
            right,
            target
                .checked_sub(adjusted)
                .context("rebase target underflow")?,
            right_bound - adjusted,
            context.left_shift + adjusted,
        )
    };
    let next_context = DataContext {
        left_shift: next_shift,
        is_rightmost: None,
        rebase_depth: context.rebase_depth + 1,
        ..context
    };

    walk_rebased_data_path(
        Some(&next_root),
        next_target,
        0,
        next_right,
        &path[128..],
        next_context,
    )
}

fn walk_data_path(
    root: &[u8; 32],
    target: u128,
    left_bound: u128,
    right_bound: u128,
    path: &[u8],
    context: DataContext,
) -> Result<DataPath> {
    ensure!(right_bound > 0, "data_path has empty bounds");
    let mut left = left_bound;
    let mut right = right_bound;
    let mut current_hash = *root;
    let mut cursor = 0usize;
    let mut is_rightmost = context.is_rightmost;

    while path.len() - cursor > LEAF_SIZE {
        ensure!(
            cursor + BRANCH_SIZE <= path.len(),
            "truncated data_path branch"
        );
        let left_hash: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
        let right_hash: [u8; 32] = path[cursor + HASH_SIZE..cursor + HASH_SIZE * 2]
            .try_into()
            .unwrap();
        let note = &path[cursor + HASH_SIZE * 2..cursor + BRANCH_SIZE];
        ensure!(
            hash_branch(&left_hash, &right_hash, note) == current_hash,
            "invalid data_path branch"
        );
        let boundary = note_to_u128(note)?;
        cursor += BRANCH_SIZE;

        if target < boundary {
            current_hash = left_hash;
            right = right.min(boundary);
            is_rightmost = Some(false);
        } else {
            current_hash = right_hash;
            left = left.max(boundary);
            if is_rightmost.is_none() {
                is_rightmost = Some(true);
            }
        }
    }

    ensure!(cursor + LEAF_SIZE == path.len(), "truncated data_path leaf");
    let data_hash: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
    let note = &path[cursor + HASH_SIZE..cursor + LEAF_SIZE];
    let leaf_end = note_to_u128(note)?;
    ensure!(
        hash_leaf(&data_hash, note) == current_hash,
        "invalid data_path leaf"
    );

    if context.check_borders {
        ensure!(
            leaf_end.saturating_sub(left) <= MAX_CHUNK_SIZE
                && right.saturating_sub(left) <= MAX_CHUNK_SIZE,
            "data_path violates chunk borders"
        );
    }
    validate_split(leaf_end, left, right, is_rightmost, context)?;

    let start = context.left_shift + left;
    let end = context.left_shift + right.min(leaf_end).max(left + 1);
    ensure!(end > start, "data_path made no forward progress");

    Ok(DataPath {
        start,
        end,
        data_hash,
    })
}

fn validate_split(
    end: u128,
    left: u128,
    right: u128,
    is_rightmost: Option<bool>,
    context: DataContext,
) -> Result<()> {
    match context.check_split {
        SplitCheck::None => Ok(()),
        SplitCheck::Strict => {
            ensure!(end >= left, "invalid strict split bounds");
            let size = end - left;
            let valid = if size == MAX_CHUNK_SIZE {
                left.is_multiple_of(MAX_CHUNK_SIZE)
            } else if end == context.data_size {
                let border = (right / MAX_CHUNK_SIZE) * MAX_CHUNK_SIZE;
                !right.is_multiple_of(MAX_CHUNK_SIZE) && left <= border
            } else {
                left.is_multiple_of(MAX_CHUNK_SIZE)
                    && context.data_size.saturating_sub(left) > MAX_CHUNK_SIZE
                    && context.data_size.saturating_sub(left) < MAX_CHUNK_SIZE * 2
            };
            ensure!(valid, "data_path violates strict data split");
            Ok(())
        }
        SplitCheck::Relaxed => {
            let shifted_left = context.left_shift + left;
            let shifted_end = context.left_shift + end;
            let valid = if is_rightmost == Some(true) {
                shifted_left.is_multiple_of(MAX_CHUNK_SIZE)
                    || (shifted_left / MAX_CHUNK_SIZE + 1 == shifted_end / MAX_CHUNK_SIZE
                        && !shifted_end.is_multiple_of(MAX_CHUNK_SIZE))
            } else {
                shifted_left.is_multiple_of(MAX_CHUNK_SIZE)
            };
            ensure!(valid, "data_path violates relaxed data split");
            Ok(())
        }
    }
}

fn deep_hash_blob(bytes: &[u8]) -> [u8; 48] {
    let tag = Sha384::digest(format!("blob{}", bytes.len()).as_bytes());
    let data = Sha384::digest(bytes);
    sha384(&[&tag, &data])
}

fn deep_hash_list(items: &[[u8; 48]]) -> [u8; 48] {
    let mut accumulator: [u8; 48] =
        Sha384::digest(format!("list{}", items.len()).as_bytes()).into();
    for item in items {
        accumulator = sha384(&[&accumulator, item]);
    }
    accumulator
}

fn hash_branch(left: &[u8; 32], right: &[u8; 32], note: &[u8]) -> [u8; 32] {
    let left = sha256(&[left]);
    let right = sha256(&[right]);
    let note = sha256(&[note]);
    sha256(&[&left, &right, &note])
}

fn hash_leaf(data_hash: &[u8; 32], note: &[u8]) -> [u8; 32] {
    let data_hash = sha256(&[data_hash]);
    let note = sha256(&[note]);
    sha256(&[&data_hash, &note])
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn note_to_u128(note: &[u8]) -> Result<u128> {
    ensure!(note.len() == NOTE_SIZE, "invalid Merkle note length");
    ensure!(
        note[..NOTE_SIZE - size_of::<u128>()]
            .iter()
            .all(|byte| *byte == 0),
        "Merkle note exceeds u128"
    );
    Ok(u128::from_be_bytes(
        note[NOTE_SIZE - size_of::<u128>()..].try_into().unwrap(),
    ))
}

fn decode_b64(value: &str, label: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid base64url {label}"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == value,
        "non-canonical base64url {label}"
    );
    Ok(decoded)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    decode_b64(value, label)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("invalid {label} length: {}", bytes.len()))
}

fn parse_u128(value: &str, label: &str) -> Result<u128> {
    value
        .parse()
        .with_context(|| format!("invalid {label}: {value}"))
}

fn normalize_base_url(value: &str) -> Result<String> {
    let value = value.trim_end_matches('/');
    let url = Url::parse(value).context("invalid source URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "source URL must use HTTP(S)"
    );
    Ok(value.to_owned())
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{base}/{}", path.trim_start_matches('/'))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(value: u128) -> [u8; 32] {
        let mut note = [0; 32];
        note[16..].copy_from_slice(&value.to_be_bytes());
        note
    }

    #[test]
    fn validates_leaf_paths_and_rejects_corruption() {
        let body = br#"{"hello":"arweave"}"#;
        let data_hash = sha256(&[body]);
        let end = note(body.len() as u128);
        let root = hash_leaf(&data_hash, &end);
        let mut path = Vec::from(data_hash);
        path.extend_from_slice(&end);

        let data = validate_data_path(
            &root,
            body.len() as u128,
            0,
            MERKLE_REBASE_SUPPORT_THRESHOLD,
            &path,
        )
        .unwrap();
        assert_eq!((data.start, data.end), (0, body.len() as u128));
        assert_eq!(data.data_hash, data_hash);

        path[0] ^= 1;
        assert!(validate_data_path(&root, body.len() as u128, 0, 0, &path).is_err());
    }

    #[test]
    fn rejects_corrupt_chunk_proofs_and_geometry() {
        let body = br#"{"hello":"arweave"}"#;
        let data_hash = sha256(&[body]);
        let data_end = note(body.len() as u128);
        let data_root = hash_leaf(&data_hash, &data_end);
        let data_path = [data_hash.as_slice(), data_end.as_slice()].concat();
        let tx_end = note(body.len() as u128);
        let tx_root = hash_leaf(&data_root, &tx_end);
        let tx_path = [data_root.as_slice(), tx_end.as_slice()].concat();
        let chunk = || JsonChunk {
            chunk: URL_SAFE_NO_PAD.encode(body),
            data_path: URL_SAFE_NO_PAD.encode(&data_path),
            tx_path: URL_SAFE_NO_PAD.encode(&tx_path),
        };
        let mut geometry = Geometry {
            tx_root,
            data_root,
            block_weave_size: 1_145,
            previous_weave_size: 1_000,
            first_offset: 1_001,
            end_offset: 1_019,
            data_size: body.len() as u128,
        };

        assert_eq!(verify_chunk(chunk(), 1_001, 0, &geometry).unwrap(), body);

        let mut corrupt_bytes = chunk();
        corrupt_bytes.chunk = URL_SAFE_NO_PAD.encode(b"corrupt");
        assert!(verify_chunk(corrupt_bytes, 1_001, 0, &geometry).is_err());

        let mut incomplete_data_path = chunk();
        incomplete_data_path.data_path.pop();
        assert!(verify_chunk(incomplete_data_path, 1_001, 0, &geometry).is_err());

        let mut incomplete_tx_path = chunk();
        incomplete_tx_path.tx_path.pop();
        assert!(verify_chunk(incomplete_tx_path, 1_001, 0, &geometry).is_err());

        geometry.data_root[0] ^= 1;
        assert!(verify_chunk(chunk(), 1_001, 0, &geometry).is_err());
        geometry.data_root[0] ^= 1;

        geometry.end_offset += 1;
        assert!(verify_chunk(chunk(), 1_001, 0, &geometry).is_err());
    }

    #[test]
    fn validates_transaction_geometry_and_rejects_wrong_root() {
        let data_root = [7; 32];
        let end = note(145);
        let root = hash_leaf(&data_root, &end);
        let mut path = Vec::from(data_root);
        path.extend_from_slice(&end);

        let transaction = validate_tx_path(&root, 1_001, 1_145, 1_000, &path).unwrap();
        assert_eq!(transaction.data_root, data_root);
        assert_eq!(transaction.start_bound, 1_000);
        assert_eq!(transaction.end_offset, 1_145);
        assert_eq!(transaction.size, 145);

        assert!(validate_tx_path(&[0; 32], 1_001, 1_145, 1_000, &path).is_err());
    }
}
