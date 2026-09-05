pub mod database;
pub mod indexer;
mod peers;
pub mod server;

use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::{
    RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
    signature::hazmat::PrehashVerifier,
};
use reqwest::{Client, RequestBuilder, Url, header::HeaderValue};
use rsa::{BigUint, Pss, RsaPublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha384};
use sha3::Keccak256;

const CONSENSUS_DEPTH: u64 = 50;
const FORK_2_5_HEIGHT: u64 = 812_970;
const FORK_2_6_HEIGHT: u64 = 1_132_210;
const FORK_2_7_HEIGHT: u64 = 1_275_480;
const FORK_2_8_HEIGHT: u64 = 1_547_120;
const FORK_2_9_HEIGHT: u64 = 1_602_350;
const HASH_SIZE: usize = 32;
const NOTE_SIZE: usize = 32;
const BRANCH_SIZE: usize = HASH_SIZE * 2 + NOTE_SIZE;
const LEAF_SIZE: usize = HASH_SIZE + NOTE_SIZE;
const MAX_CHUNK_SIZE: u128 = 256 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_PROOF_BYTES: usize = 64 * 1024;
const MAX_BLOCK_INDEX_BYTES: usize = 256 * 99;
const BUNDLE_ENTRY_SIZE: usize = 64;
const MAX_DATA_ITEM_TAGS: usize = 128;
const MAX_DATA_ITEM_TAG_BYTES: usize = 4096;
const STRICT_DATA_SPLIT_THRESHOLD: u128 = 30_607_159_107_830;
const MERKLE_REBASE_SUPPORT_THRESHOLD: u128 = 151_066_495_197_430;

#[derive(Clone, Debug)]
pub struct Config {
    pub trusted_node_url: String,
    pub archive_url: String,
    pub chunk_sources: Vec<String>,
    pub request_timeout: Duration,
    pub max_peer_attempts: usize,
    pub max_data_size: usize,
    pub cache_max_entries: usize,
    pub cache_max_bytes: usize,
}

impl Config {
    pub fn new(
        trusted_node_url: impl Into<String>,
        archive_url: impl Into<String>,
        chunk_sources: Vec<String>,
        request_timeout: Duration,
        max_peer_attempts: usize,
        max_data_size: usize,
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
        ensure!(max_data_size > 0, "maximum data size must be positive");
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
            max_data_size,
            cache_max_entries: 1024,
            cache_max_bytes: 512 * 1024 * 1024,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedData {
    #[serde(skip_serializing)]
    pub bytes: Arc<[u8]>,
    #[serde(skip_serializing)]
    pub cache_hit: bool,
    pub id: String,
    pub block_height: u64,
    pub content_type: String,
    pub content_length: usize,
    pub etag: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct VerifiedChunk {
    pub bytes: Vec<u8>,
    pub chunk: String,
    pub data_path: String,
    pub tx_path: String,
    pub data_root: String,
    pub data_size: u128,
    pub start_offset: u128,
    pub relative_start_offset: u128,
    pub read_offset: u128,
    pub tx_start_offset: u128,
    pub source_host: String,
}

type RetrievalResult = Option<std::result::Result<VerifiedData, String>>;

#[derive(Default)]
struct ContentCache {
    entries: HashMap<String, (VerifiedData, u128)>,
    inflight: HashMap<String, tokio::sync::watch::Sender<RetrievalResult>>,
    bytes: usize,
    clock: u128,
}

impl ContentCache {
    fn get(&mut self, id: &str) -> Option<VerifiedData> {
        let (data, accessed) = self.entries.get_mut(id)?;
        self.clock += 1;
        *accessed = self.clock;
        let mut data = data.clone();
        data.cache_hit = true;
        Some(data)
    }

    fn insert(&mut self, data: VerifiedData, max_entries: usize, max_bytes: usize) {
        let size = data.bytes.len();
        if max_entries == 0 || size > max_bytes || max_bytes == 0 {
            return;
        }
        if let Some((old, _)) = self.entries.remove(&data.id) {
            self.bytes -= old.bytes.len();
        }
        // ponytail: bounded O(n) eviction, use an ordered LRU if insertion throughput demands it.
        while self.entries.len() >= max_entries || self.bytes > max_bytes - size {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, (_, accessed))| *accessed)
                .map(|(id, _)| id.clone())
                .unwrap();
            self.bytes -= self.entries.remove(&victim).unwrap().0.bytes.len();
        }
        self.clock += 1;
        self.bytes += size;
        self.entries.insert(data.id.clone(), (data, self.clock));
    }
}

struct RetrievalLeader<'a> {
    cache: &'a Mutex<ContentCache>,
    id: &'a str,
    completed: bool,
}

impl Drop for RetrievalLeader<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(sender) = self.cache.lock().unwrap().inflight.remove(self.id) {
            sender.send_replace(Some(Err("verified retrieval canceled".to_owned())));
        }
    }
}

pub struct Gateway {
    config: Config,
    client: Client,
    cache: Mutex<ContentCache>,
    peers: peers::PeerState,
    block_store: Option<database::BlockStore>,
}

impl Gateway {
    pub fn new(config: Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .context("failed to build HTTP client")?;
        let peers = peers::PeerState::new(&config.trusted_node_url)?;
        Ok(Self {
            config,
            client,
            cache: Mutex::new(ContentCache::default()),
            peers,
            block_store: None,
        })
    }

    pub async fn with_database(mut self, url: &str) -> Result<Self> {
        let store = database::BlockStore::connect(url).await?;
        let state = store
            .state()
            .await?
            .context("block index has not been initialized")?;
        ensure!(
            state.source == self.config.trusted_node_url,
            "block index belongs to a different trusted node"
        );
        self.block_store = Some(store);
        Ok(self)
    }

    pub async fn retrieve(&self, id: &str) -> Result<VerifiedData> {
        decode_fixed::<32>(id, "data ID")?;
        self.retrieve_cached(id, async {
            match self.discover(id).await? {
                Some(hint) => self.retrieve_bundled_with_hint(id, hint).await,
                None => self.retrieve_direct(id).await,
            }
        })
        .await
    }

    async fn retrieve_cached(
        &self,
        id: &str,
        retrieve: impl Future<Output = Result<VerifiedData>>,
    ) -> Result<VerifiedData> {
        let (mut receiver, leader) = {
            let mut cache = self.cache.lock().unwrap();
            if let Some(data) = cache.get(id) {
                return Ok(data);
            }
            match cache.inflight.get(id) {
                Some(sender) => (sender.subscribe(), None),
                None => {
                    let (sender, receiver) = tokio::sync::watch::channel(None);
                    cache.inflight.insert(id.to_owned(), sender);
                    (
                        receiver,
                        Some(RetrievalLeader {
                            cache: &self.cache,
                            id,
                            completed: false,
                        }),
                    )
                }
            }
        };
        if let Some(mut leader) = leader {
            let result = tokio::time::timeout(self.config.request_timeout, retrieve)
                .await
                .context("verified retrieval timed out")
                .and_then(|result| result);
            {
                let mut cache = self.cache.lock().unwrap();
                if let Ok(data) = &result {
                    cache.insert(
                        data.clone(),
                        self.config.cache_max_entries,
                        self.config.cache_max_bytes,
                    );
                }
                if let Some(sender) = cache.inflight.remove(id) {
                    sender.send_replace(Some(match &result {
                        Ok(data) => Ok(data.clone()),
                        Err(error) => Err(format!("{error:#}")),
                    }));
                }
                leader.completed = true;
            }
            drop(leader);
            result
        } else {
            tokio::time::timeout(self.config.request_timeout, receiver.changed())
                .await
                .context("coalesced retrieval timed out")?
                .context("coalesced retrieval canceled")?;
            receiver
                .borrow_and_update()
                .as_ref()
                .context("coalesced retrieval returned no result")?
                .clone()
                .map_err(anyhow::Error::msg)
        }
    }

    pub async fn retrieve_direct(&self, id: &str) -> Result<VerifiedData> {
        let (verified, _) = self.retrieve_direct_with_tags(id).await?;
        Ok(verified)
    }

    pub async fn retrieve_bundled(&self, id: &str) -> Result<VerifiedData> {
        decode_fixed::<32>(id, "data item ID")?;
        let hint = self
            .discover(id)
            .await?
            .context("discovery returned an unbundled transaction")?;
        self.retrieve_bundled_with_hint(id, hint).await
    }

    pub async fn retrieve_chunk(&self, offset: u128) -> Result<Option<VerifiedChunk>> {
        match tokio::time::timeout(
            self.config.request_timeout,
            self.retrieve_chunk_inner(offset),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Ok(None),
        }
    }

    async fn retrieve_chunk_inner(&self, offset: u128) -> Result<Option<VerifiedChunk>> {
        let Some(geometry) = self.trusted_block_geometry(offset).await? else {
            return Ok(None);
        };
        let mut invalid = Vec::new();
        let discovered = self.peers.candidates(
            Some(offset),
            self.config.max_peer_attempts,
            &self.config.chunk_sources,
        );

        for source in self
            .config
            .chunk_sources
            .iter()
            .take(self.config.max_peer_attempts - usize::from(!discovered.is_empty()))
            .chain(discovered.iter())
            .take(self.config.max_peer_attempts)
        {
            let candidate: Option<JsonChunk> = match self
                .request_optional_json(self.source_request(
                    source,
                    &format!("chunk/{offset}"),
                    &discovered,
                ))
                .await
            {
                Ok(candidate) => candidate,
                Err(error) => {
                    self.peers.record_result(source, false);
                    invalid.push(format!("{source}: {error:#}"));
                    continue;
                }
            };
            let Some(candidate) = candidate else {
                self.peers.record_result(source, false);
                continue;
            };
            let proof = match verify_chunk_proof(candidate, offset, &geometry) {
                Ok(proof) => proof,
                Err(error) => {
                    self.peers.record_result(source, false);
                    invalid.push(format!("{source}: {error:#}"));
                    continue;
                }
            };
            let start_offset = proof
                .first_offset
                .checked_add(proof.data.start)
                .context("chunk start offset overflow")?;
            let read_offset = proof
                .relative_offset
                .checked_sub(proof.data.start)
                .context("chunk read offset underflow")?;
            let source_host = Url::parse(source)?
                .host_str()
                .context("chunk source has no host")?
                .to_owned();

            self.peers.record_result(source, true);
            return Ok(Some(VerifiedChunk {
                data_root: URL_SAFE_NO_PAD.encode(proof.transaction.data_root),
                data_size: proof.transaction.size,
                relative_start_offset: proof.data.start,
                tx_start_offset: proof.first_offset,
                bytes: proof.bytes,
                chunk: proof.chunk,
                data_path: proof.data_path,
                tx_path: proof.tx_path,
                start_offset,
                read_offset,
                source_host,
            }));
        }

        if invalid.is_empty() {
            Ok(None)
        } else {
            bail!(
                "all returned chunk proofs were invalid: {}",
                invalid.join("; ")
            )
        }
    }

    async fn trusted_block_geometry(&self, offset: u128) -> Result<Option<BlockGeometry>> {
        if offset == 0 {
            return Ok(None);
        }
        if let Some(store) = &self.block_store
            && let Some((previous, block)) = store.block_for_offset(offset).await?
        {
            ensure!(
                offset > previous.weave_size && offset <= block.weave_size,
                "stored block index returned inconsistent offset geometry"
            );
            return Ok(Some(BlockGeometry {
                tx_root: block
                    .tx_root
                    .as_slice()
                    .try_into()
                    .context("invalid stored tx_root")?,
                block_weave_size: block.weave_size,
                previous_weave_size: previous.weave_size,
            }));
        }
        let Some(info): Option<NodeInfo> = self
            .request_optional_json(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, "info")),
            )
            .await?
        else {
            return Ok(None);
        };
        let Some(stable_height) = info.height.checked_sub(CONSENSUS_DEPTH) else {
            return Ok(None);
        };
        let Some(tip) = self
            .trusted_block_index(stable_height, stable_height)
            .await?
        else {
            return Ok(None);
        };
        let tip_weave_size = tip[0].weave_size;
        if offset > tip_weave_size {
            return Ok(None);
        }

        let mut low = 0;
        let mut high = stable_height;
        while low < high {
            let height = low + (high - low) / 2;
            let Some(entry) = self.trusted_block_index(height, height).await? else {
                return Ok(None);
            };
            let weave_size = entry[0].weave_size;
            if offset <= weave_size {
                high = height;
            } else {
                low = height + 1;
            }
        }

        let (start, block_index) = if low == 0 { (0, 0) } else { (low - 1, 1) };
        let Some(entries) = self.trusted_block_index(start, low).await? else {
            return Ok(None);
        };
        let block = &entries[block_index];
        let block_weave_size = block.weave_size;
        let previous_weave_size = if low == 0 { 0 } else { entries[0].weave_size };
        ensure!(
            offset > previous_weave_size && offset <= block_weave_size,
            "trusted block index returned inconsistent offset geometry"
        );

        Ok(Some(BlockGeometry {
            tx_root: decode_fixed(&block.tx_root, "block tx_root")?,
            block_weave_size,
            previous_weave_size,
        }))
    }

    async fn trusted_block_index(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<TrustedBlockIndexEntry>>> {
        let expected = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .context("invalid block index range")?;
        ensure!(expected <= 256, "block index range exceeds 256 entries");
        let byte_limit = expected as usize * 99;
        let mut response = match self
            .client
            .get(endpoint(
                &self.config.trusted_node_url,
                &format!("block_index2/{start}/{end}"),
            ))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        if let Some(length) = response.content_length() {
            ensure!(
                length <= byte_limit.min(MAX_BLOCK_INDEX_BYTES) as u64,
                "trusted block index response exceeds size limit"
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("failed to read block index")?
        {
            ensure!(
                body.len().saturating_add(chunk.len()) <= byte_limit,
                "trusted block index response exceeds size limit"
            );
            body.extend_from_slice(&chunk);
        }
        let entries = decode_block_index(&body)?;
        let expected = expected as usize;
        ensure!(
            entries.len() == expected,
            "trusted block index returned incomplete geometry"
        );
        Ok(Some(entries))
    }

    async fn retrieve_bundled_with_hint(&self, id: &str, hint: BundleHint) -> Result<VerifiedData> {
        let hinted_size = checked_data_size(
            parse_u128(&hint.data_size, "discovered data item size")?,
            self.config.max_data_size,
        )?;
        let (parent, parent_tags) = self.retrieve_direct_with_tags(&hint.parent_id).await?;
        require_bundle_tags(&parent_tags)?;
        let item = verify_bundle_item(&parent.bytes, id)?;
        ensure!(
            item.data.len() == hinted_size,
            "discovered data item size does not match verified payload"
        );

        let bytes = item.data.to_vec();
        let body_hash = sha256(&[&bytes]);
        Ok(VerifiedData {
            content_length: bytes.len(),
            bytes: bytes.into(),
            cache_hit: false,
            id: id.to_owned(),
            block_height: parent.block_height,
            content_type: item.content_type,
            etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(body_hash)),
            sha256: hex(&body_hash),
        })
    }

    async fn discover(&self, id: &str) -> Result<Option<BundleHint>> {
        let response: GraphQlResponse = self
            .request_json(
                self.client
                    .post(endpoint(&self.config.archive_url, "graphql"))
                    .json(&serde_json::json!({
                        "query": "query($ids: [ID!]!) { transactions(ids: $ids, first: 2) { edges { node { id bundledIn { id } data { size } } } } }",
                        "variables": { "ids": [id] }
                    })),
            )
            .await
            .context("failed to discover data location")?;
        let mut edges = response.data.transactions.edges;
        ensure!(
            edges.len() == 1,
            "discovery did not return exactly one data item"
        );
        let node = edges.pop().unwrap().node;
        ensure!(node.id == id, "discovery returned the wrong data item");
        decode_fixed::<32>(&node.id, "discovered data item ID")?;
        let Some(parent) = node.bundled_in else {
            return Ok(None);
        };
        let parent_id = parent.id;
        decode_fixed::<32>(&parent_id, "discovered parent ID")?;
        ensure!(parent_id != id, "data item cannot be its own parent");
        Ok(Some(BundleHint {
            parent_id,
            data_size: node.data.size,
        }))
    }

    async fn retrieve_direct_with_tags(&self, id: &str) -> Result<(VerifiedData, Vec<Tag>)> {
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

        let indexed = match &self.block_store {
            Some(store) => store.block_pair(status.block_height).await?,
            None => None,
        };
        let entries: Vec<BlockIndexEntry> = if let Some((previous, block)) = indexed {
            [block, previous]
                .into_iter()
                .map(|entry| BlockIndexEntry {
                    hash: URL_SAFE_NO_PAD.encode(&entry.hash),
                    tx_root: URL_SAFE_NO_PAD.encode(&entry.tx_root),
                    weave_size: entry.weave_size.to_string(),
                })
                .collect()
        } else {
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
            self.request_json(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, &index_path))
                    .header("x-block-format", "1"),
            )
            .await
            .context("failed to fetch trusted block index")?
        };
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
        self.authenticate_block(block, status.block_height, id)
            .await?;

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

        let expected_len = checked_data_size(data_size, self.config.max_data_size)?;
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

        Ok((
            VerifiedData {
                bytes: bytes.into(),
                cache_hit: false,
                id: id.to_owned(),
                block_height: status.block_height,
                content_type,
                content_length: expected_len,
                etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(body_hash)),
                sha256: hex(&body_hash),
            },
            transaction.tags,
        ))
    }

    async fn authenticate_block(
        &self,
        entry: &BlockIndexEntry,
        height: u64,
        transaction_id: &str,
    ) -> Result<()> {
        let path = format!("block/hash/{}", entry.hash);
        let mut failures = Vec::new();

        match self
            .fetch_and_authenticate_block(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, &path)),
                entry,
                height,
                transaction_id,
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) => failures.push(format!("{}: {error:#}", self.config.trusted_node_url)),
        }

        let mut attempted = HashSet::new();
        let discovered = self.peers.candidates(
            None,
            self.config.max_peer_attempts,
            &self.config.chunk_sources,
        );
        for source in std::iter::once(&self.config.archive_url)
            .chain(self.config.chunk_sources.iter())
            .chain(discovered.iter())
        {
            if source == &self.config.trusted_node_url || attempted.contains(source.as_str()) {
                continue;
            }
            if attempted.len() >= self.config.max_peer_attempts {
                break;
            }
            if attempted.len()
                >= self.config.max_peer_attempts - usize::from(!discovered.is_empty())
                && !discovered.iter().any(|peer| peer == source)
            {
                continue;
            }
            attempted.insert(source.as_str());

            match self
                .fetch_and_authenticate_block(
                    self.source_request(source, &path, &discovered),
                    entry,
                    height,
                    transaction_id,
                )
                .await
            {
                Ok(()) => {
                    self.peers.record_result(source, true);
                    return Ok(());
                }
                Err(error) => {
                    self.peers.record_result(source, false);
                    failures.push(format!("{source}: {error:#}"));
                }
            }
        }

        bail!(
            "all bounded block header attempts failed: {}",
            failures.join("; ")
        )
    }

    async fn fetch_and_authenticate_block(
        &self,
        request: RequestBuilder,
        entry: &BlockIndexEntry,
        height: u64,
        transaction_id: &str,
    ) -> Result<()> {
        let block: BlockHeader = self.request_json(request).await?;
        verify_block_header(&block, entry, height, transaction_id)
    }

    fn source_request(&self, source: &str, path: &str, discovered: &[String]) -> RequestBuilder {
        let url = endpoint(source, path);
        if discovered.iter().any(|peer| peer == source) {
            self.peers.get(url)
        } else {
            self.client.get(url)
        }
    }

    async fn fetch_verified_chunk(
        &self,
        absolute_offset: u128,
        relative_offset: u128,
        geometry: &Geometry,
    ) -> Result<Vec<u8>> {
        let mut failures = Vec::new();
        let discovered = self.peers.candidates(
            Some(absolute_offset),
            self.config.max_peer_attempts,
            &self.config.chunk_sources,
        );
        let sources = self
            .config
            .chunk_sources
            .iter()
            .take(self.config.max_peer_attempts - usize::from(!discovered.is_empty()))
            .chain(discovered.iter())
            .take(self.config.max_peer_attempts);

        for source in sources {
            let result = async {
                let chunk: JsonChunk = self
                    .request_json(self.source_request(
                        source,
                        &format!("chunk/{absolute_offset}"),
                        &discovered,
                    ))
                    .await?;
                verify_chunk(chunk, absolute_offset, relative_offset, geometry)
            }
            .await;

            self.peers.record_result(source, result.is_ok());
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
        let response = request
            .send()
            .await
            .context("HTTP request failed")?
            .error_for_status()
            .context("HTTP source rejected request")?;
        read_json_response(response).await
    }

    async fn request_optional_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<Option<T>> {
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        Ok(Some(read_json_response(response).await?))
    }
}

async fn read_json_response<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T> {
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

#[derive(Deserialize)]
struct NodeInfo {
    height: u64,
}

#[derive(Deserialize)]
struct TxStatus {
    block_height: u64,
    block_indep_hash: String,
}

fn decode_block_index(bytes: &[u8]) -> Result<Vec<TrustedBlockIndexEntry>> {
    let mut cursor = 0;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let hash = URL_SAFE_NO_PAD.encode(take(bytes, &mut cursor, 48, "block hash")?);
        let weave_size_length =
            u16::from_be_bytes(take(bytes, &mut cursor, 2, "weave size length")?.try_into()?)
                as usize;
        ensure!(weave_size_length <= 16, "block weave size exceeds u128");
        let weave_size_bytes = take(bytes, &mut cursor, weave_size_length, "block weave size")?;
        let mut encoded_weave_size = [0; 16];
        encoded_weave_size[16 - weave_size_length..].copy_from_slice(weave_size_bytes);
        let weave_size = u128::from_be_bytes(encoded_weave_size);
        let tx_root_length = take(bytes, &mut cursor, 1, "tx_root length")?[0] as usize;
        ensure!(
            matches!(tx_root_length, 0 | 32),
            "invalid block tx_root length"
        );
        let tx_root =
            URL_SAFE_NO_PAD.encode(take(bytes, &mut cursor, tx_root_length, "block tx_root")?);
        entries.push(TrustedBlockIndexEntry {
            hash,
            tx_root,
            weave_size,
        });
    }
    Ok(entries)
}

struct TrustedBlockIndexEntry {
    hash: String,
    tx_root: String,
    weave_size: u128,
}

#[derive(Deserialize)]
struct BlockIndexEntry {
    tx_root: String,
    weave_size: String,
    hash: String,
}
#[derive(Deserialize, Default)]
struct BlockHeader {
    indep_hash: String,
    height: u64,
    previous_block: String,
    timestamp: u64,
    nonce: String,
    last_retarget: u64,
    diff: String,
    cumulative_diff: String,
    reward_pool: String,
    wallet_list: String,
    hash_list_merkle: String,
    hash: String,
    block_size: String,
    weave_size: String,
    tx_root: String,
    reward_addr: String,
    tags: Vec<String>,
    txs: Vec<String>,
    packing_2_5_threshold: String,
    strict_data_split_threshold: String,
    usd_to_ar_rate: [String; 2],
    scheduled_usd_to_ar_rate: [String; 2],
    poa: BlockPoa,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    reward: String,
    #[serde(default)]
    recall_byte: String,
    #[serde(default)]
    recall_byte2: String,
    #[serde(default)]
    hash_preimage: String,
    #[serde(default)]
    reward_key: String,
    #[serde(default)]
    partition_number: u64,
    #[serde(default)]
    nonce_limiter_info: NonceLimiterInfo,
    #[serde(default)]
    previous_solution_hash: String,
    #[serde(default)]
    price_per_gib_minute: String,
    #[serde(default)]
    scheduled_price_per_gib_minute: String,
    #[serde(default)]
    reward_history_hash: String,
    #[serde(default)]
    block_time_history_hash: String,
    #[serde(default)]
    debt_supply: String,
    #[serde(default)]
    kryder_plus_rate_multiplier: String,
    #[serde(default)]
    kryder_plus_rate_multiplier_latch: String,
    #[serde(default)]
    denomination: String,
    #[serde(default)]
    redenomination_height: u64,
    #[serde(default)]
    double_signing_proof: serde_json::Value,
    #[serde(default)]
    previous_cumulative_diff: String,
    #[serde(default)]
    merkle_rebase_support_threshold: String,
    #[serde(default)]
    poa2: BlockPoa,
    #[serde(default)]
    chunk_hash: String,
    #[serde(default)]
    chunk2_hash: String,
    #[serde(default)]
    packing_difficulty: u8,
    #[serde(default)]
    unpacked_chunk_hash: String,
    #[serde(default)]
    unpacked_chunk2_hash: String,
    #[serde(default)]
    replica_format: u8,
}

#[derive(Deserialize, Default)]
struct BlockPoa {
    #[serde(default)]
    option: String,
    #[serde(default)]
    tx_path: String,
    #[serde(default)]
    data_path: String,
    #[serde(default)]
    chunk: String,
}

#[derive(Deserialize, Default)]
struct NonceLimiterInfo {
    #[serde(default)]
    output: String,
    #[serde(default)]
    global_step_number: u64,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    next_seed: String,
    #[serde(default)]
    zone_upper_bound: u64,
    #[serde(default)]
    next_zone_upper_bound: u64,
    #[serde(default)]
    prev_output: String,
    #[serde(default)]
    checkpoints: Vec<String>,
    #[serde(default)]
    last_step_checkpoints: Vec<String>,
    #[serde(default)]
    vdf_difficulty: String,
    #[serde(default)]
    next_vdf_difficulty: String,
}

fn verify_block_header(
    block: &BlockHeader,
    entry: &BlockIndexEntry,
    height: u64,
    transaction_id: &str,
) -> Result<()> {
    ensure!(block.height == height, "block header height mismatch");
    let expected_hash = decode_fixed::<48>(&entry.hash, "trusted block hash")?;
    ensure!(
        decode_fixed::<48>(&block.indep_hash, "block indep_hash")? == expected_hash,
        "block header identifier mismatch"
    );
    ensure!(
        block_indep_hash(block)? == expected_hash,
        "block indep_hash verification failed"
    );
    ensure!(
        decode_fixed::<32>(&block.tx_root, "block tx_root")?
            == decode_fixed::<32>(&entry.tx_root, "trusted block tx_root")?,
        "block tx_root does not match trusted index"
    );
    ensure!(
        parse_u128(&block.weave_size, "block weave size")?
            == parse_u128(&entry.weave_size, "trusted block weave size")?,
        "block weave size does not match trusted index"
    );
    ensure!(
        block.txs.iter().any(|id| id == transaction_id),
        "transaction ID is absent from authenticated block"
    );
    Ok(())
}

fn block_indep_hash(block: &BlockHeader) -> Result<[u8; 48]> {
    if block.height >= FORK_2_6_HEIGHT {
        let signed_hash = post_2_6_signed_hash(block)?;
        let signature = decode_b64(&block.signature, "block signature")?;
        Ok(sha384(&[&signed_hash, &signature]))
    } else {
        pre_2_6_indep_hash(block)
    }
}

fn pre_2_6_indep_hash(block: &BlockHeader) -> Result<[u8; 48]> {
    ensure!(
        block.height >= FORK_2_5_HEIGHT,
        "block versions before fork 2.5 are unsupported"
    );

    let core = [
        deep_hash_decimal(&block.height.to_string(), "block height")?,
        deep_hash_blob(&decode_b64(&block.previous_block, "previous block")?),
        deep_hash_blob(&decode_b64(&block.tx_root, "block tx_root")?),
        deep_hash_b64_list(&block.txs, "block transaction ID")?,
        deep_hash_decimal(&block.block_size, "block size")?,
        deep_hash_decimal(&block.weave_size, "block weave size")?,
        deep_hash_blob(&reward_address(&block.reward_addr, false)?),
        deep_hash_b64_list(&block.tags, "block tag")?,
    ];
    let mut base = Vec::with_capacity(14);
    for (value, label) in [
        (&block.usd_to_ar_rate[0], "USD rate dividend"),
        (&block.usd_to_ar_rate[1], "USD rate divisor"),
        (
            &block.scheduled_usd_to_ar_rate[0],
            "scheduled USD rate dividend",
        ),
        (
            &block.scheduled_usd_to_ar_rate[1],
            "scheduled USD rate divisor",
        ),
        (&block.packing_2_5_threshold, "packing threshold"),
        (
            &block.strict_data_split_threshold,
            "strict data split threshold",
        ),
    ] {
        base.push(deep_hash_decimal(value, label)?);
    }
    base.extend_from_slice(&core);
    let base_hash = deep_hash_list(&base);
    let data_segment = deep_hash_list(&[
        deep_hash_blob(&base_hash),
        deep_hash_decimal(&block.timestamp.to_string(), "block timestamp")?,
        deep_hash_decimal(&block.last_retarget.to_string(), "last retarget")?,
        deep_hash_decimal(&block.diff, "block difficulty")?,
        deep_hash_decimal(&block.cumulative_diff, "cumulative difficulty")?,
        deep_hash_decimal(&block.reward_pool, "reward pool")?,
        deep_hash_blob(&decode_b64(&block.wallet_list, "wallet list")?),
        deep_hash_blob(&decode_b64(&block.hash_list_merkle, "hash_list_merkle")?),
    ]);
    let poa = deep_hash_list(&[
        deep_hash_decimal(&block.poa.option, "proof option")?,
        deep_hash_blob(&decode_b64(&block.poa.tx_path, "block tx_path")?),
        deep_hash_blob(&decode_b64(&block.poa.data_path, "block data_path")?),
        deep_hash_blob(&decode_b64(&block.poa.chunk, "block chunk")?),
    ]);

    Ok(deep_hash_list(&[
        deep_hash_blob(&data_segment),
        deep_hash_blob(&decode_b64(&block.hash, "block hash")?),
        deep_hash_blob(&decode_b64(&block.nonce, "block nonce")?),
        poa,
    ]))
}

fn post_2_6_signed_hash(block: &BlockHeader) -> Result<[u8; 32]> {
    let nonce = decode_b64(&block.nonce, "block nonce")?;
    ensure!(!nonce.is_empty(), "block nonce is empty");
    let nonce_start = nonce
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(nonce.len() - 1);
    let nonce = &nonce[nonce_start..];
    let nonce_info = &block.nonce_limiter_info;
    let mut segment = Vec::new();

    append_b64(&mut segment, &block.previous_block, 1, "previous block")?;
    append_u64(&mut segment, block.timestamp, 1)?;
    append_bytes(&mut segment, nonce, 2)?;
    append_u64(&mut segment, block.height, 1)?;
    append_decimal(&mut segment, &block.diff, 2, "block difficulty")?;
    append_decimal(
        &mut segment,
        &block.cumulative_diff,
        2,
        "cumulative difficulty",
    )?;
    append_u64(&mut segment, block.last_retarget, 1)?;
    append_b64(&mut segment, &block.hash, 1, "block hash")?;
    append_decimal(&mut segment, &block.block_size, 2, "block size")?;
    append_decimal(&mut segment, &block.weave_size, 2, "block weave size")?;
    append_bytes(&mut segment, &reward_address(&block.reward_addr, true)?, 1)?;
    append_b64(&mut segment, &block.tx_root, 1, "block tx_root")?;
    append_b64(&mut segment, &block.wallet_list, 1, "wallet list")?;
    append_b64(&mut segment, &block.hash_list_merkle, 1, "hash_list_merkle")?;
    append_decimal(&mut segment, &block.reward_pool, 1, "reward pool")?;
    append_decimal(
        &mut segment,
        &block.packing_2_5_threshold,
        1,
        "packing threshold",
    )?;
    append_decimal(
        &mut segment,
        &block.strict_data_split_threshold,
        1,
        "strict data split threshold",
    )?;
    append_decimal(
        &mut segment,
        &block.usd_to_ar_rate[0],
        1,
        "USD rate dividend",
    )?;
    append_decimal(
        &mut segment,
        &block.usd_to_ar_rate[1],
        1,
        "USD rate divisor",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_usd_to_ar_rate[0],
        1,
        "scheduled USD rate dividend",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_usd_to_ar_rate[1],
        1,
        "scheduled USD rate divisor",
    )?;
    append_b64_list(&mut segment, &block.tags, 2, 2, "block tag")?;
    append_b64_list(&mut segment, &block.txs, 2, 1, "block transaction ID")?;
    append_decimal(&mut segment, &block.reward, 1, "block reward")?;
    append_decimal(&mut segment, &block.recall_byte, 2, "recall byte")?;
    append_b64(&mut segment, &block.hash_preimage, 1, "hash preimage")?;
    append_optional_decimal(&mut segment, &block.recall_byte2, 2, "second recall byte")?;
    append_b64(&mut segment, &block.reward_key, 2, "reward key")?;
    append_u64(&mut segment, block.partition_number, 1)?;
    append_fixed_b64(&mut segment, &nonce_info.output, 32, "VDF output")?;
    append_fixed_u64(&mut segment, nonce_info.global_step_number, 8)?;
    append_fixed_b64(&mut segment, &nonce_info.seed, 48, "VDF seed")?;
    append_fixed_b64(&mut segment, &nonce_info.next_seed, 48, "next VDF seed")?;
    append_fixed_u64(&mut segment, nonce_info.zone_upper_bound, 32)?;
    append_fixed_u64(&mut segment, nonce_info.next_zone_upper_bound, 32)?;
    append_b64(
        &mut segment,
        &nonce_info.prev_output,
        1,
        "previous VDF output",
    )?;
    append_hashes(&mut segment, &nonce_info.checkpoints, "VDF checkpoint")?;
    append_hashes(
        &mut segment,
        &nonce_info.last_step_checkpoints,
        "last VDF checkpoint",
    )?;
    append_b64(
        &mut segment,
        &block.previous_solution_hash,
        1,
        "previous solution hash",
    )?;
    append_decimal(
        &mut segment,
        &block.price_per_gib_minute,
        1,
        "price per GiB minute",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_price_per_gib_minute,
        1,
        "scheduled price per GiB minute",
    )?;
    append_fixed_b64(
        &mut segment,
        &block.reward_history_hash,
        32,
        "reward history hash",
    )?;
    append_decimal(&mut segment, &block.debt_supply, 1, "debt supply")?;
    append_fixed_decimal(
        &mut segment,
        &block.kryder_plus_rate_multiplier,
        3,
        "Kryder+ rate multiplier",
    )?;
    append_fixed_decimal(
        &mut segment,
        &block.kryder_plus_rate_multiplier_latch,
        1,
        "Kryder+ rate multiplier latch",
    )?;
    append_fixed_decimal(&mut segment, &block.denomination, 3, "denomination")?;
    append_u64(&mut segment, block.redenomination_height, 1)?;
    append_double_signing_proof(&mut segment, &block.double_signing_proof)?;
    append_decimal(
        &mut segment,
        &block.previous_cumulative_diff,
        2,
        "previous cumulative difficulty",
    )?;

    if block.height >= FORK_2_7_HEIGHT {
        append_decimal(
            &mut segment,
            &block.merkle_rebase_support_threshold,
            2,
            "Merkle rebase threshold",
        )?;
        append_b64(&mut segment, &block.poa.data_path, 3, "block data_path")?;
        append_b64(&mut segment, &block.poa.tx_path, 3, "block tx_path")?;
        append_b64(
            &mut segment,
            &block.poa2.data_path,
            3,
            "second block data_path",
        )?;
        append_b64(&mut segment, &block.poa2.tx_path, 3, "second block tx_path")?;
        append_fixed_b64(&mut segment, &block.chunk_hash, 32, "chunk hash")?;
        append_optional_b64(&mut segment, &block.chunk2_hash, 1, "second chunk hash")?;
        append_fixed_b64(
            &mut segment,
            &block.block_time_history_hash,
            32,
            "block time history hash",
        )?;
        append_decimal(
            &mut segment,
            &nonce_info.vdf_difficulty,
            1,
            "VDF difficulty",
        )?;
        append_decimal(
            &mut segment,
            &nonce_info.next_vdf_difficulty,
            1,
            "next VDF difficulty",
        )?;
    }
    if block.height >= FORK_2_8_HEIGHT {
        segment.push(block.packing_difficulty);
        append_optional_b64(
            &mut segment,
            &block.unpacked_chunk_hash,
            1,
            "unpacked chunk hash",
        )?;
        append_optional_b64(
            &mut segment,
            &block.unpacked_chunk2_hash,
            1,
            "second unpacked chunk hash",
        )?;
    }
    if block.height >= FORK_2_9_HEIGHT {
        segment.push(block.replica_format);
    }

    Ok(sha256(&[&segment]))
}

fn append_size(output: &mut Vec<u8>, value: usize, bytes: usize) -> Result<()> {
    ensure!(
        bytes > 0 && bytes <= size_of::<u128>(),
        "invalid size prefix width"
    );
    let max = 1u128.checked_shl((bytes * 8) as u32).unwrap_or(u128::MAX);
    ensure!((value as u128) < max, "encoded size exceeds prefix width");
    let encoded = (value as u128).to_be_bytes();
    let prefix = &encoded[size_of::<u128>() - bytes..];
    output.extend_from_slice(prefix);
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8], size_bytes: usize) -> Result<()> {
    let max = 1u128
        .checked_shl((size_bytes * 8) as u32)
        .unwrap_or(u128::MAX);
    ensure!((value.len() as u128) < max, "value exceeds size prefix");
    append_size(output, value.len(), size_bytes)?;
    output.extend_from_slice(value);
    Ok(())
}

fn append_b64(output: &mut Vec<u8>, value: &str, size_bytes: usize, label: &str) -> Result<()> {
    append_bytes(output, &decode_b64(value, label)?, size_bytes)
}

fn append_optional_b64(
    output: &mut Vec<u8>,
    value: &str,
    size_bytes: usize,
    label: &str,
) -> Result<()> {
    if value.is_empty() {
        append_bytes(output, &[], size_bytes)
    } else {
        append_b64(output, value, size_bytes, label)
    }
}

fn append_decimal(output: &mut Vec<u8>, value: &str, size_bytes: usize, label: &str) -> Result<()> {
    let mut encoded = parse_biguint(value, label)?.to_bytes_be();
    if encoded.is_empty() {
        encoded.push(0);
    }
    append_bytes(output, &encoded, size_bytes)
}

fn append_optional_decimal(
    output: &mut Vec<u8>,
    value: &str,
    size_bytes: usize,
    label: &str,
) -> Result<()> {
    if value.is_empty() {
        append_bytes(output, &[], size_bytes)
    } else {
        append_decimal(output, value, size_bytes, label)
    }
}

fn append_u64(output: &mut Vec<u8>, value: u64, size_bytes: usize) -> Result<()> {
    append_decimal(output, &value.to_string(), size_bytes, "integer")
}

fn append_fixed_decimal(
    output: &mut Vec<u8>,
    value: &str,
    bytes: usize,
    label: &str,
) -> Result<()> {
    let encoded = parse_biguint(value, label)?.to_bytes_be();
    ensure!(encoded.len() <= bytes, "{label} exceeds fixed width");
    output.resize(output.len() + bytes - encoded.len(), 0);
    output.extend_from_slice(&encoded);
    Ok(())
}

fn append_fixed_u64(output: &mut Vec<u8>, value: u64, bytes: usize) -> Result<()> {
    append_fixed_decimal(output, &value.to_string(), bytes, "integer")
}

fn append_fixed_b64(output: &mut Vec<u8>, value: &str, bytes: usize, label: &str) -> Result<()> {
    let decoded = decode_b64(value, label)?;
    ensure!(decoded.len() == bytes, "invalid {label} length");
    output.extend_from_slice(&decoded);
    Ok(())
}

fn append_b64_list(
    output: &mut Vec<u8>,
    values: &[String],
    list_size_bytes: usize,
    element_size_bytes: usize,
    label: &str,
) -> Result<()> {
    append_size(output, values.len(), list_size_bytes)?;
    for value in values.iter().rev() {
        append_b64(output, value, element_size_bytes, label)?;
    }
    Ok(())
}

fn append_hashes(output: &mut Vec<u8>, values: &[String], label: &str) -> Result<()> {
    append_size(output, values.len(), 2)?;
    for value in values {
        append_fixed_b64(output, value, 32, label)?;
    }
    Ok(())
}

fn append_double_signing_proof(output: &mut Vec<u8>, proof: &serde_json::Value) -> Result<()> {
    match proof {
        serde_json::Value::Null => output.push(0),
        serde_json::Value::Object(fields) if fields.is_empty() => output.push(0),
        _ => bail!("non-empty double-signing proofs are unsupported"),
    }
    Ok(())
}

fn reward_address(value: &str, post_2_6: bool) -> Result<Vec<u8>> {
    if value == "unclaimed" {
        Ok(if post_2_6 {
            Vec::new()
        } else {
            b"unclaimed".to_vec()
        })
    } else {
        decode_b64(value, "reward address")
    }
}

fn parse_biguint(value: &str, label: &str) -> Result<BigUint> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid {label}: {value}"
    );
    BigUint::parse_bytes(value.as_bytes(), 10).with_context(|| format!("invalid {label}: {value}"))
}

fn deep_hash_decimal(value: &str, label: &str) -> Result<[u8; 48]> {
    Ok(deep_hash_blob(
        parse_biguint(value, label)?.to_str_radix(10).as_bytes(),
    ))
}

fn deep_hash_b64_list(values: &[String], label: &str) -> Result<[u8; 48]> {
    let hashes = values
        .iter()
        .map(|value| Ok(deep_hash_blob(&decode_b64(value, label)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(deep_hash_list(&hashes))
}

fn checked_data_size(data_size: u128, maximum: usize) -> Result<usize> {
    ensure!(
        data_size <= maximum as u128,
        "transaction exceeds configured data size limit"
    );
    usize::try_from(data_size).context("transaction is too large")
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
struct GraphQlResponse {
    data: GraphQlData,
}

#[derive(Deserialize)]
struct GraphQlData {
    transactions: GraphQlTransactions,
}

#[derive(Deserialize)]
struct GraphQlTransactions {
    edges: Vec<GraphQlEdge>,
}

#[derive(Deserialize)]
struct GraphQlEdge {
    node: GraphQlNode,
}

#[derive(Deserialize)]
struct GraphQlNode {
    id: String,
    #[serde(rename = "bundledIn")]
    bundled_in: Option<GraphQlBundledIn>,
    data: GraphQlNodeData,
}

#[derive(Deserialize)]
struct GraphQlBundledIn {
    id: String,
}

#[derive(Deserialize)]
struct GraphQlNodeData {
    size: String,
}

struct BundleHint {
    parent_id: String,
    data_size: String,
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

struct BlockGeometry {
    tx_root: [u8; 32],
    block_weave_size: u128,
    previous_weave_size: u128,
}

struct ProvenChunk {
    bytes: Vec<u8>,
    chunk: String,
    data_path: String,
    tx_path: String,
    transaction: TxPath,
    data: DataPath,
    relative_offset: u128,
    first_offset: u128,
}

fn verify_chunk(
    chunk: JsonChunk,
    absolute_offset: u128,
    relative_offset: u128,
    geometry: &Geometry,
) -> Result<Vec<u8>> {
    let proof = verify_chunk_proof(
        chunk,
        absolute_offset,
        &BlockGeometry {
            tx_root: geometry.tx_root,
            block_weave_size: geometry.block_weave_size,
            previous_weave_size: geometry.previous_weave_size,
        },
    )?;
    ensure!(
        proof.transaction.data_root == geometry.data_root,
        "tx_path data root mismatch"
    );
    ensure!(
        proof.transaction.end_offset == geometry.end_offset,
        "tx_path end offset mismatch"
    );
    ensure!(
        proof.transaction.size == geometry.data_size,
        "tx_path transaction size mismatch"
    );
    ensure!(
        proof.first_offset == geometry.first_offset,
        "tx_path start offset mismatch"
    );
    ensure!(
        proof.relative_offset == relative_offset,
        "tx_path relative offset mismatch"
    );
    ensure!(
        proof.data.start == relative_offset,
        "data_path does not start at requested offset"
    );
    Ok(proof.bytes)
}

fn verify_chunk_proof(
    chunk: JsonChunk,
    absolute_offset: u128,
    geometry: &BlockGeometry,
) -> Result<ProvenChunk> {
    let JsonChunk {
        chunk,
        data_path,
        tx_path,
    } = chunk;
    let bytes = decode_b64(&chunk, "chunk bytes")?;
    let data_path_bytes = decode_b64(&data_path, "data_path")?;
    let tx_path_bytes = decode_b64(&tx_path, "tx_path")?;
    ensure!(
        bytes.len() <= MAX_CHUNK_SIZE as usize,
        "chunk exceeds protocol limit"
    );
    ensure!(
        data_path_bytes.len() <= MAX_PROOF_BYTES,
        "data_path exceeds size limit"
    );
    ensure!(
        tx_path_bytes.len() <= MAX_PROOF_BYTES,
        "tx_path exceeds size limit"
    );

    let transaction = validate_tx_path(
        &geometry.tx_root,
        absolute_offset,
        geometry.block_weave_size,
        geometry.previous_weave_size,
        &tx_path_bytes,
    )?;
    let first_offset = transaction
        .start_bound
        .checked_add(1)
        .context("transaction start offset overflow")?;
    let relative_offset = absolute_offset
        .checked_sub(first_offset)
        .context("requested offset precedes transaction")?;
    let data = validate_data_path(
        &transaction.data_root,
        transaction.size,
        relative_offset,
        absolute_offset,
        &data_path_bytes,
    )?;
    ensure!(
        data.start <= relative_offset && relative_offset < data.end,
        "data_path does not contain requested offset"
    );
    ensure!(
        data.end <= transaction.size,
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

    Ok(ProvenChunk {
        bytes,
        chunk,
        data_path,
        tx_path,
        transaction,
        data,
        relative_offset,
        first_offset,
    })
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
    verify_rsa_pss(&owner, &signature, &signature_payload, "transaction")
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
            return Ok(response_content_type(value));
        }
    }
    Ok("application/octet-stream".to_owned())
}

fn response_content_type(value: String) -> String {
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let has_charset = parts.any(|parameter| {
        parameter
            .split_once('=')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("charset"))
    });

    if !has_charset
        && (media_type.starts_with("text/")
            || media_type == "application/json"
            || media_type.ends_with("+json"))
    {
        format!("{value}; charset=utf-8")
    } else {
        value
    }
}

fn require_bundle_tags(tags: &[Tag]) -> Result<()> {
    let mut format = false;
    let mut version = false;
    for tag in tags {
        let name = decode_b64(&tag.name, "tag name")?;
        let value = decode_b64(&tag.value, "tag value")?;
        format |= name == b"Bundle-Format" && value == b"binary";
        version |= name == b"Bundle-Version" && value == b"2.0.0";
    }
    ensure!(format, "parent is missing Bundle-Format: binary");
    ensure!(version, "parent is missing Bundle-Version: 2.0.0");
    Ok(())
}

struct VerifiedItem<'a> {
    data: &'a [u8],
    content_type: String,
}

struct ItemTag<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

fn verify_bundle_item<'a>(bundle: &'a [u8], expected_id: &str) -> Result<VerifiedItem<'a>> {
    let expected_id = decode_fixed::<32>(expected_id, "data item ID")?;
    let mut cursor = 0;
    let count = read_u256_usize(
        take(bundle, &mut cursor, 32, "bundle item count")?,
        "bundle item count",
    )?;
    ensure!(count > 0, "bundle is empty");
    ensure!(
        count <= (bundle.len() - cursor) / BUNDLE_ENTRY_SIZE,
        "bundle item table exceeds parent bounds"
    );
    let table_size = count
        .checked_mul(BUNDLE_ENTRY_SIZE)
        .context("bundle item table size overflow")?;
    let data_start = cursor
        .checked_add(table_size)
        .context("bundle item table offset overflow")?;
    let mut item_start = data_start;
    let mut found = None;

    for _ in 0..count {
        let size = read_u256_usize(
            take(bundle, &mut cursor, 32, "bundle item size")?,
            "bundle item size",
        )?;
        ensure!(size > 0, "bundle contains an empty item");
        let id = take(bundle, &mut cursor, 32, "bundle item ID")?;
        let item_end = item_start
            .checked_add(size)
            .context("bundle item offset overflow")?;
        ensure!(
            item_end <= bundle.len(),
            "bundle item exceeds parent bounds"
        );
        if id == expected_id.as_slice() {
            ensure!(found.is_none(), "bundle contains duplicate data item IDs");
            found = Some((item_start, item_end));
        }
        item_start = item_end;
    }

    ensure!(cursor == data_start, "bundle item table is malformed");
    ensure!(
        item_start == bundle.len(),
        "bundle item sizes do not consume the parent"
    );
    let (start, end) = found.context("data item is absent from verified parent")?;
    verify_data_item(&bundle[start..end], &expected_id)
}

fn data_item_signature_sizes(signature_type: u16) -> Result<(usize, usize)> {
    match signature_type {
        1 => Ok((512, 512)),
        2 => Ok((64, 32)),
        3 => Ok((65, 65)),
        4 | 5 => Ok((64, 32)),
        6 => Ok((2_052, 1_025)),
        7 => Ok((65, 42)),
        _ => bail!("unsupported ANS-104 signature type {signature_type}"),
    }
}

fn data_item_signature_payload(
    signature_type: u16,
    owner: &[u8],
    target: &[u8],
    anchor: &[u8],
    raw_tags: &[u8],
    data: &[u8],
) -> [u8; 48] {
    let signature_type = signature_type.to_string();
    deep_hash_list(&[
        deep_hash_blob(b"dataitem"),
        deep_hash_blob(b"1"),
        deep_hash_blob(signature_type.as_bytes()),
        deep_hash_blob(owner),
        deep_hash_blob(target),
        deep_hash_blob(anchor),
        deep_hash_blob(raw_tags),
        deep_hash_blob(data),
    ])
}

fn verify_data_item<'a>(item: &'a [u8], expected_id: &[u8; 32]) -> Result<VerifiedItem<'a>> {
    let mut cursor = 0;
    let signature_type = read_le_u16(item, &mut cursor, "data item signature type")?;
    let (signature_size, owner_size) = data_item_signature_sizes(signature_type)?;
    let signature = take(item, &mut cursor, signature_size, "data item signature")?;
    let owner = take(item, &mut cursor, owner_size, "data item owner")?;
    let target = read_optional_32(item, &mut cursor, "data item target")?;
    let anchor = read_optional_32(item, &mut cursor, "data item anchor")?;
    let tag_count = usize::try_from(read_le_u64(item, &mut cursor, "data item tag count")?)
        .context("data item tag count is too large")?;
    ensure!(
        tag_count <= MAX_DATA_ITEM_TAGS,
        "data item tag count exceeds limit"
    );
    let tag_bytes_len =
        usize::try_from(read_le_u64(item, &mut cursor, "data item tag byte length")?)
            .context("data item tag byte length is too large")?;
    ensure!(
        tag_bytes_len <= MAX_DATA_ITEM_TAG_BYTES,
        "data item tag bytes exceed limit"
    );
    let raw_tags = take(item, &mut cursor, tag_bytes_len, "data item tags")?;
    let tags = parse_avro_tags(raw_tags, tag_count)?;
    let data = &item[cursor..];

    ensure!(
        sha256(&[signature]) == *expected_id,
        "data item ID is not the signature hash"
    );
    let payload =
        data_item_signature_payload(signature_type, owner, target, anchor, raw_tags, data);
    verify_data_item_signature(signature_type, owner, signature, &payload)?;

    Ok(VerifiedItem {
        data,
        content_type: item_content_type(&tags)?,
    })
}

fn item_content_type(tags: &[ItemTag<'_>]) -> Result<String> {
    for tag in tags {
        if tag.name == b"Content-Type" {
            let value = HeaderValue::from_bytes(tag.value)
                .context("invalid Content-Type tag")?
                .to_str()
                .context("non-ASCII Content-Type tag")?
                .to_owned();
            return Ok(response_content_type(value));
        }
    }
    Ok("application/octet-stream".to_owned())
}

fn parse_avro_tags(bytes: &[u8], expected_count: usize) -> Result<Vec<ItemTag<'_>>> {
    let mut cursor = 0;
    let mut tags = Vec::with_capacity(expected_count);
    loop {
        let block_count = read_avro_long(bytes, &mut cursor)?;
        if block_count == 0 {
            break;
        }
        let count = block_count
            .checked_abs()
            .context("Avro tag block count overflow")?;
        let count = usize::try_from(count).context("Avro tag block count is too large")?;
        ensure!(
            tags.len().saturating_add(count) <= expected_count,
            "Avro tag count exceeds declared count"
        );
        let block_end = if block_count < 0 {
            let block_size = read_avro_long(bytes, &mut cursor)?;
            ensure!(block_size >= 0, "Avro tag block size is negative");
            let block_size =
                usize::try_from(block_size).context("Avro tag block size is too large")?;
            Some(
                cursor
                    .checked_add(block_size)
                    .context("Avro tag block size overflow")?,
            )
        } else {
            None
        };

        for _ in 0..count {
            let name_len = read_avro_length(bytes, &mut cursor, "Avro tag name")?;
            let name = take(bytes, &mut cursor, name_len, "Avro tag name")?;
            let value_len = read_avro_length(bytes, &mut cursor, "Avro tag value")?;
            let value = take(bytes, &mut cursor, value_len, "Avro tag value")?;
            tags.push(ItemTag { name, value });
        }
        if let Some(block_end) = block_end {
            ensure!(cursor == block_end, "Avro tag block size mismatch");
        }
    }
    ensure!(
        cursor == bytes.len(),
        "Avro tag bytes contain trailing data"
    );
    ensure!(
        tags.len() == expected_count,
        "Avro tag count does not match declared count"
    );
    Ok(tags)
}

fn read_avro_length(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<usize> {
    let length = read_avro_long(bytes, cursor)?;
    ensure!(length >= 0, "{label} length is negative");
    usize::try_from(length).with_context(|| format!("{label} length is too large"))
}

fn read_avro_long(bytes: &[u8], cursor: &mut usize) -> Result<i64> {
    let mut encoded = 0u64;
    for index in 0..10 {
        let byte = take(bytes, cursor, 1, "Avro long")?[0];
        if index == 9 {
            ensure!(byte <= 1, "Avro long overflows i64");
        }
        encoded |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(((encoded >> 1) as i64) ^ -((encoded & 1) as i64));
        }
    }
    bail!("Avro long is malformed")
}

fn read_optional_32<'a>(bytes: &'a [u8], cursor: &mut usize, label: &str) -> Result<&'a [u8]> {
    match take(bytes, cursor, 1, label)?[0] {
        0 => Ok(&[]),
        1 => take(bytes, cursor, 32, label),
        _ => bail!("{label} flag is invalid"),
    }
}

fn read_le_u16(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        take(bytes, cursor, 2, label)?.try_into().unwrap(),
    ))
}

fn read_le_u64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(
        take(bytes, cursor, 8, label)?.try_into().unwrap(),
    ))
}

fn read_u256_usize(bytes: &[u8], label: &str) -> Result<usize> {
    ensure!(bytes.len() == 32, "{label} has the wrong width");
    ensure!(
        bytes[8..].iter().all(|byte| *byte == 0),
        "{label} exceeds u64"
    );
    usize::try_from(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        .with_context(|| format!("{label} exceeds usize"))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize, label: &str) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .with_context(|| format!("{label} offset overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .with_context(|| format!("{label} is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn verify_data_item_signature(
    signature_type: u16,
    owner: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<()> {
    match signature_type {
        1 => verify_rsa_pss(owner, signature, payload, "data item"),
        2 => verify_ed25519(owner, signature, payload),
        3 => verify_ethereum(owner, signature, payload),
        4 => verify_ed25519(owner, signature, hex(payload).as_bytes()),
        5 => verify_ed25519(
            owner,
            signature,
            format!("APTOS\nmessage: {}\nnonce: bundlr", hex(payload)).as_bytes(),
        ),
        6 => verify_aptos_multisignature(owner, signature, payload),
        7 => verify_typed_ethereum(owner, signature, payload),
        _ => bail!("unsupported ANS-104 signature type {signature_type}"),
    }
}

fn verify_ed25519(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    let owner: &[u8; 32] = owner
        .try_into()
        .context("invalid Ed25519 data item owner length")?;
    let signature =
        Ed25519Signature::try_from(signature).context("invalid Ed25519 signature length")?;
    let key = Ed25519VerifyingKey::from_bytes(owner).context("invalid Ed25519 data item owner")?;
    key.verify_strict(message, &signature)
        .context("data item signature verification failed")
}

fn verify_ethereum(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(signature.len() == 65, "invalid Ethereum signature length");
    let key = Secp256k1VerifyingKey::from_sec1_bytes(owner)
        .context("invalid Ethereum data item owner")?;
    let signature = Secp256k1Signature::try_from(&signature[..64])
        .context("invalid Ethereum data item signature")?;
    key.verify_prehash(&ethereum_message_hash(message), &signature)
        .context("data item signature verification failed")
}

fn ethereum_message_hash(message: &[u8]) -> [u8; 32] {
    let length = message.len().to_string();
    keccak256(&[
        b"\x19Ethereum Signed Message:\n",
        length.as_bytes(),
        message,
    ])
}

fn verify_aptos_multisignature(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(owner.len() == 1_025, "invalid Aptos multisig owner length");
    ensure!(
        signature.len() == 2_052,
        "invalid Aptos multisig signature length"
    );
    let threshold = usize::from(owner[1_024]);
    ensure!(
        (1..=32).contains(&threshold),
        "invalid Aptos multisig threshold"
    );
    let bitmap = &signature[2_048..];
    let signature_count = bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
    ensure!(
        signature_count >= threshold,
        "Aptos multisig threshold is not met"
    );

    for index in 0..32 {
        if bitmap[index / 8] & (0x80 >> (index % 8)) != 0 {
            verify_ed25519(
                &owner[index * 32..(index + 1) * 32],
                &signature[index * 64..(index + 1) * 64],
                message,
            )?;
        }
    }
    Ok(())
}

fn verify_typed_ethereum(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(
        signature.len() == 65,
        "invalid typed Ethereum signature length"
    );
    let address = ethereum_address_from_owner(owner)?;
    let recovery_id = match signature[64] {
        value @ 0..=1 => value,
        value @ 27..=28 => value - 27,
        _ => bail!("invalid typed Ethereum recovery ID"),
    };
    let signature = Secp256k1Signature::try_from(&signature[..64])
        .context("invalid typed Ethereum data item signature")?;
    let key = Secp256k1VerifyingKey::recover_from_prehash(
        &typed_ethereum_message_hash(message, &address),
        &signature,
        RecoveryId::try_from(recovery_id).context("invalid typed Ethereum recovery ID")?,
    )
    .context("typed Ethereum data item signature recovery failed")?;
    let public_key = key.to_sec1_point(false);
    let recovered = keccak256(&[&public_key.as_bytes()[1..]]);
    ensure!(
        recovered[12..] == address,
        "data item signature verification failed"
    );
    Ok(())
}

fn typed_ethereum_message_hash(message: &[u8], address: &[u8; 20]) -> [u8; 32] {
    let domain_type = keccak256(&[b"EIP712Domain(string name,string version)"]);
    let domain_name = keccak256(&[b"Bundlr"]);
    let domain_version = keccak256(&[b"1"]);
    let domain = keccak256(&[&domain_type, &domain_name, &domain_version]);
    let message_type = keccak256(&[b"Bundlr(bytes Transaction hash, address address)"]);
    let transaction_hash = keccak256(&[message]);
    let mut encoded_address = [0; 32];
    encoded_address[12..].copy_from_slice(address);
    let value = keccak256(&[&message_type, &transaction_hash, &encoded_address]);
    keccak256(&[b"\x19\x01", &domain, &value])
}

fn ethereum_address_from_owner(owner: &[u8]) -> Result<[u8; 20]> {
    ensure!(
        owner.len() == 42 && owner[..2].eq_ignore_ascii_case(b"0x"),
        "invalid typed Ethereum data item owner"
    );
    let mut address = [0; 20];
    for (byte, encoded) in address.iter_mut().zip(owner[2..].chunks_exact(2)) {
        *byte = decode_hex_nibble(encoded[0])
            .and_then(|high| decode_hex_nibble(encoded[1]).map(|low| high << 4 | low))
            .context("invalid typed Ethereum data item owner")?;
    }
    Ok(address)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::default();
    for part in parts {
        sha3::Digest::update(&mut hasher, part);
    }
    sha3::Digest::finalize(hasher).into()
}

fn verify_rsa_pss(owner: &[u8], signature: &[u8], payload: &[u8], label: &str) -> Result<()> {
    let signature_digest = Sha256::digest(payload);
    let key = RsaPublicKey::new(BigUint::from_bytes_be(owner), BigUint::from(65_537u32))
        .with_context(|| format!("invalid RSA {label} owner"))?;
    let encoded_len = (key.n().bits().saturating_sub(1) as usize).div_ceil(8);
    let max_salt = encoded_len.saturating_sub(32 + 2);
    let valid = [0, 32, max_salt].into_iter().any(|salt_len| {
        key.verify(
            Pss::new_with_salt::<Sha256>(salt_len),
            &signature_digest,
            signature,
        )
        .is_ok()
    });
    ensure!(valid, "{label} signature verification failed");
    Ok(())
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
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use k256::ecdsa::SigningKey as Secp256k1SigningKey;

    fn note(value: u128) -> [u8; 32] {
        let mut note = [0; 32];
        note[16..].copy_from_slice(&value.to_be_bytes());
        note
    }

    fn encode_data_item(
        signature_type: u16,
        signature: &[u8],
        owner: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let mut item = Vec::new();
        item.extend_from_slice(&signature_type.to_le_bytes());
        item.extend_from_slice(signature);
        item.extend_from_slice(owner);
        item.extend_from_slice(&[0, 0]);
        item.extend_from_slice(&0u64.to_le_bytes());
        item.extend_from_slice(&1u64.to_le_bytes());
        item.push(0);
        item.extend_from_slice(data);
        item
    }

    fn check_data_item(
        signature_type: u16,
        owner: &[u8],
        signature: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let item = encode_data_item(signature_type, signature, owner, data);
        let expected_id = sha256(&[signature]);
        assert_eq!(verify_data_item(&item, &expected_id).unwrap().data, data);

        let (signature_size, _) = data_item_signature_sizes(signature_type).unwrap();
        let mut wrong_signature = item.clone();
        wrong_signature[2] ^= 1;
        let wrong_id = sha256(&[&wrong_signature[2..2 + signature_size]]);
        assert!(verify_data_item(&wrong_signature, &wrong_id).is_err());

        let mut wrong_owner = item.clone();
        wrong_owner[2 + signature_size] ^= 1;
        assert!(verify_data_item(&wrong_owner, &expected_id).is_err());

        let mut wrong_data = item.clone();
        *wrong_data.last_mut().unwrap() ^= 1;
        assert!(verify_data_item(&wrong_data, &expected_id).is_err());
        item
    }

    fn recoverable_signature(key: &Secp256k1SigningKey, digest: &[u8; 32]) -> Vec<u8> {
        let (signature, recovery_id) = key.sign_prehash_recoverable(digest);
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte() + 27);
        bytes
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
    fn decodes_binary_block_index() {
        let mut encoded = vec![7; 48];
        encoded.extend_from_slice(&2_u16.to_be_bytes());
        encoded.extend_from_slice(&1_145_u16.to_be_bytes());
        encoded.push(32);
        encoded.extend_from_slice(&[9; 32]);
        let entries = decode_block_index(&encoded).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash, URL_SAFE_NO_PAD.encode([7; 48]));
        assert_eq!(entries[0].weave_size, 1_145);
        assert_eq!(entries[0].tx_root, URL_SAFE_NO_PAD.encode([9; 32]));
        encoded.pop();
        assert!(decode_block_index(&encoded).is_err());
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
        let proof = verify_chunk_proof(
            chunk(),
            1_006,
            &BlockGeometry {
                tx_root,
                block_weave_size: 1_145,
                previous_weave_size: 1_000,
            },
        )
        .unwrap();
        assert_eq!(proof.relative_offset, 5);
        assert_eq!((proof.data.start, proof.data.end), (0, body.len() as u128));

        let mut corrupt_bytes = chunk();
        corrupt_bytes.chunk = URL_SAFE_NO_PAD.encode(b"corrupt");
        assert!(verify_chunk(corrupt_bytes, 1_001, 0, &geometry).is_err());

        let mut incomplete_data_path = chunk();
        incomplete_data_path.data_path = URL_SAFE_NO_PAD.encode(&data_path[..data_path.len() - 1]);
        assert!(verify_chunk(incomplete_data_path, 1_001, 0, &geometry).is_err());

        let mut incomplete_tx_path = chunk();
        incomplete_tx_path.tx_path = URL_SAFE_NO_PAD.encode(&tx_path[..tx_path.len() - 1]);
        assert!(verify_chunk(incomplete_tx_path, 1_001, 0, &geometry).is_err());

        geometry.data_root[0] ^= 1;
        assert!(verify_chunk(chunk(), 1_001, 0, &geometry).is_err());
        geometry.data_root[0] ^= 1;

        geometry.end_offset += 1;
        assert!(verify_chunk(chunk(), 1_001, 0, &geometry).is_err());
    }

    #[test]
    fn normalizes_content_type_and_bounds_data_size() {
        assert_eq!(
            response_content_type("Application/JSON".to_owned()),
            "Application/JSON; charset=utf-8"
        );
        assert_eq!(
            response_content_type("Text/Plain; Charset=ISO-8859-1".to_owned()),
            "Text/Plain; Charset=ISO-8859-1"
        );
        assert_eq!(response_content_type("image/png".to_owned()), "image/png");
        assert_eq!(checked_data_size(145, 1024).unwrap(), 145);
        assert!(checked_data_size(1025, 1024).is_err());
    }

    #[test]
    fn authenticates_block_metadata_and_transaction_ids() {
        let transaction_id = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let tx_root = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let mut block = BlockHeader {
            height: 1_000_000,
            previous_block: String::new(),
            timestamp: 1,
            nonce: URL_SAFE_NO_PAD.encode([1u8]),
            last_retarget: 1,
            diff: "1".to_owned(),
            cumulative_diff: "1".to_owned(),
            reward_pool: "0".to_owned(),
            wallet_list: String::new(),
            hash_list_merkle: String::new(),
            hash: String::new(),
            block_size: "1".to_owned(),
            weave_size: "1".to_owned(),
            tx_root: tx_root.clone(),
            reward_addr: "unclaimed".to_owned(),
            txs: vec![transaction_id.clone()],
            packing_2_5_threshold: "0".to_owned(),
            strict_data_split_threshold: "0".to_owned(),
            usd_to_ar_rate: ["1".to_owned(), "1".to_owned()],
            scheduled_usd_to_ar_rate: ["1".to_owned(), "1".to_owned()],
            poa: BlockPoa {
                option: "1".to_owned(),
                ..BlockPoa::default()
            },
            ..BlockHeader::default()
        };
        block.indep_hash = URL_SAFE_NO_PAD.encode(block_indep_hash(&block).unwrap());
        let entry = BlockIndexEntry {
            tx_root,
            weave_size: "1".to_owned(),
            hash: block.indep_hash.clone(),
        };

        verify_block_header(&block, &entry, block.height, &transaction_id).unwrap();
        let absent_id = URL_SAFE_NO_PAD.encode([4u8; 32]);
        assert!(verify_block_header(&block, &entry, block.height, &absent_id).is_err());

        block.txs[0] = absent_id;
        assert!(verify_block_header(&block, &entry, block.height, &transaction_id).is_err());
    }

    #[test]
    fn verifies_all_supported_ans104_signature_types() {
        const DATA: &[u8] = b"ANS-104 signature parity";
        const RAW_TAGS: &[u8] = &[0];

        let ed25519 = Ed25519SigningKey::from_bytes(&[2; 32]);
        let ed25519_owner = ed25519.verifying_key().to_bytes();
        let payload = data_item_signature_payload(2, &ed25519_owner, &[], &[], RAW_TAGS, DATA);
        let signature = ed25519.sign(&payload).to_bytes();
        check_data_item(2, &ed25519_owner, &signature, DATA);

        let secp256k1 = Secp256k1SigningKey::from_slice(&[3; 32]).unwrap();
        let ethereum_owner = secp256k1
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let payload = data_item_signature_payload(3, &ethereum_owner, &[], &[], RAW_TAGS, DATA);
        let signature = recoverable_signature(&secp256k1, &ethereum_message_hash(&payload));
        check_data_item(3, &ethereum_owner, &signature, DATA);

        let payload = data_item_signature_payload(4, &ed25519_owner, &[], &[], RAW_TAGS, DATA);
        let signature = ed25519.sign(hex(&payload).as_bytes()).to_bytes();
        check_data_item(4, &ed25519_owner, &signature, DATA);

        let payload = data_item_signature_payload(5, &ed25519_owner, &[], &[], RAW_TAGS, DATA);
        let message = format!("APTOS\nmessage: {}\nnonce: bundlr", hex(&payload));
        let signature = ed25519.sign(message.as_bytes()).to_bytes();
        check_data_item(5, &ed25519_owner, &signature, DATA);

        let second_ed25519 = Ed25519SigningKey::from_bytes(&[4; 32]);
        let mut multisig_owner = vec![0; 1_025];
        multisig_owner[..32].copy_from_slice(&ed25519_owner);
        multisig_owner[32..64].copy_from_slice(&second_ed25519.verifying_key().to_bytes());
        multisig_owner[1_024] = 2;
        let payload = data_item_signature_payload(6, &multisig_owner, &[], &[], RAW_TAGS, DATA);
        let mut multisignature = vec![0; 2_052];
        multisignature[..64].copy_from_slice(&ed25519.sign(&payload).to_bytes());
        multisignature[64..128].copy_from_slice(&second_ed25519.sign(&payload).to_bytes());
        multisignature[2_048] = 0b1100_0000;
        check_data_item(6, &multisig_owner, &multisignature, DATA);
        multisignature[2_048] = 0b1000_0000;
        let insufficient = encode_data_item(6, &multisignature, &multisig_owner, DATA);
        assert!(
            verify_data_item(&insufficient, &sha256(&[&multisignature])).is_err(),
            "Aptos multisignature must meet its owner threshold"
        );

        let public_key = secp256k1.verifying_key().to_sec1_point(false);
        let public_key_hash = keccak256(&[&public_key.as_bytes()[1..]]);
        let address: [u8; 20] = public_key_hash[12..].try_into().unwrap();
        let typed_owner = format!("0x{}", hex(&address)).into_bytes();
        let payload = data_item_signature_payload(7, &typed_owner, &[], &[], RAW_TAGS, DATA);
        let signature =
            recoverable_signature(&secp256k1, &typed_ethereum_message_hash(&payload, &address));
        check_data_item(7, &typed_owner, &signature, DATA);

        assert!(data_item_signature_sizes(8).is_err());
    }

    #[test]
    fn verifies_ans104_item_and_rejects_mutations() {
        const ID: &str = "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY";
        let item = include_bytes!("../tests/fixtures/lolcchekc-item.bin");
        let expected_id = decode_fixed::<32>(ID, "data item ID").unwrap();
        let verified = verify_data_item(item, &expected_id).unwrap();
        assert_eq!(verified.data.len(), 2_982);
        assert_eq!(
            hex(&sha256(&[verified.data])),
            "4d02c735657b171d1a3d3bc9ddd7ee396cdf5232e11d6adb06826637c3b9070c"
        );
        assert_eq!(verified.content_type, "text/html; charset=utf-8");

        let mut bundle = Vec::with_capacity(32 + BUNDLE_ENTRY_SIZE + item.len());
        bundle.extend_from_slice(&1u64.to_le_bytes());
        bundle.extend_from_slice(&[0; 24]);
        bundle.extend_from_slice(&(item.len() as u64).to_le_bytes());
        bundle.extend_from_slice(&[0; 24]);
        bundle.extend_from_slice(&expected_id);
        bundle.extend_from_slice(item);
        assert_eq!(verify_bundle_item(&bundle, ID).unwrap().data, verified.data);

        let mut wrong_id = bundle.clone();
        wrong_id[64] ^= 1;
        assert!(verify_bundle_item(&wrong_id, ID).is_err());

        let mut wrong_size = bundle.clone();
        wrong_size[32] ^= 1;
        assert!(verify_bundle_item(&wrong_size, ID).is_err());

        let mut truncated = bundle;
        truncated.pop();
        assert!(verify_bundle_item(&truncated, ID).is_err());

        let (signature_size, _) = data_item_signature_sizes(1).unwrap();
        let mut wrong_signature = item.to_vec();
        wrong_signature[2] ^= 1;
        let wrong_signature_id = sha256(&[&wrong_signature[2..2 + signature_size]]);
        assert!(verify_data_item(&wrong_signature, &wrong_signature_id).is_err());

        let mut wrong_owner = item.to_vec();
        wrong_owner[2 + signature_size] ^= 1;
        assert!(verify_data_item(&wrong_owner, &expected_id).is_err());

        let mut wrong_payload = item.to_vec();
        let payload_start = item.len() - verified.data.len();
        wrong_payload[payload_start] ^= 1;
        assert!(verify_data_item(&wrong_payload, &expected_id).is_err());

        assert!(verify_data_item(&item[..2 + signature_size], &expected_id).is_err());
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

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn data(id: &str) -> VerifiedData {
        VerifiedData {
            bytes: Arc::from(&b"hello"[..]),
            cache_hit: false,
            id: id.to_owned(),
            block_height: 1,
            content_type: "text/plain".to_owned(),
            content_length: 5,
            etag: String::new(),
            sha256: String::new(),
        }
    }

    fn gateway() -> Gateway {
        Gateway::new(
            Config::new(
                "http://127.0.0.1:1",
                "http://127.0.0.1:1",
                vec!["http://127.0.0.1:1".to_owned()],
                Duration::from_millis(50),
                1,
                1024,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn bounds_cache_and_retains_recently_used_content() {
        for (entries, bytes) in [(2, 100), (100, 10)] {
            let mut cache = ContentCache::default();
            cache.insert(data("a"), entries, bytes);
            cache.insert(data("b"), entries, bytes);
            assert!(cache.get("a").unwrap().cache_hit);
            cache.insert(data("c"), entries, bytes);
            assert!(cache.get("b").is_none());
            assert!(cache.get("a").is_some());
            assert!(cache.get("c").is_some());
            cache.insert(data("oversized"), entries, 4);
            assert!(cache.get("oversized").is_none());
        }
    }

    #[tokio::test]
    async fn shares_cold_results_and_only_caches_success() {
        let mut gateway = gateway();
        for limit in [1024, 4] {
            gateway.config.cache_max_bytes = limit;
            let id = limit.to_string();
            let (leader, follower) = tokio::join!(
                gateway.retrieve_cached(&id, async {
                    tokio::task::yield_now().await;
                    Ok(data(&id))
                }),
                gateway.retrieve_cached(&id, async { panic!("duplicate retrieval") })
            );
            let leader = leader.unwrap();
            let follower = follower.unwrap();
            assert!(!leader.cache_hit && !follower.cache_hit);
            assert!(Arc::ptr_eq(&leader.bytes, &follower.bytes));
            let next = gateway
                .retrieve_cached(&id, async { Ok(data(&id)) })
                .await
                .unwrap();
            assert_eq!(next.cache_hit, limit >= 5);
        }
        let (leader, follower) = tokio::join!(
            gateway.retrieve_cached("failure", async {
                tokio::task::yield_now().await;
                bail!("bad proof")
            }),
            gateway.retrieve_cached("failure", async { panic!("duplicate retrieval") })
        );
        assert!(leader.is_err() && follower.is_err());
        assert!(
            !gateway
                .retrieve_cached("failure", async { Ok(data("failure")) })
                .await
                .unwrap()
                .cache_hit
        );
    }

    #[tokio::test]
    async fn cancellation_and_deadlines_release_followers() {
        let gateway = gateway();
        let mut leader = Box::pin(gateway.retrieve_cached("cancel", std::future::pending()));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(leader.as_mut().poll(cx).is_pending())
            })
            .await
        );
        let mut follower =
            Box::pin(gateway.retrieve_cached("cancel", async { panic!("duplicate") }));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(follower.as_mut().poll(cx).is_pending())
            })
            .await
        );
        drop(leader);
        assert!(follower.await.unwrap_err().to_string().contains("canceled"));
        assert!(
            !gateway
                .retrieve_cached("cancel", async { Ok(data("cancel")) })
                .await
                .unwrap()
                .cache_hit
        );

        let mut leader = Box::pin(gateway.retrieve_cached("timeout", std::future::pending()));
        std::future::poll_fn(|cx| {
            assert!(leader.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let follower = gateway
            .retrieve_cached("timeout", async { panic!("duplicate") })
            .await;
        assert!(follower.unwrap_err().to_string().contains("timed out"));
        assert!(leader.await.unwrap_err().to_string().contains("timed out"));
        assert!(
            !gateway
                .retrieve_cached("timeout", async { Ok(data("timeout")) })
                .await
                .unwrap()
                .cache_hit
        );
    }
}
