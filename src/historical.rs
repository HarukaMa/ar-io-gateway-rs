use std::{io, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{
    Number, Value,
    ser::{CharEscape, CompactFormatter, Formatter},
};
use tokio::sync::OnceCell;

use super::{
    BlockHeader, BlockIndexEntry, FORK_2_5_HEIGHT, decode_b64, decode_fixed, deep_hash_b64_list,
    deep_hash_blob, deep_hash_decimal, deep_hash_list, parse_biguint, parse_u128, reward_address,
    sha256, sha384,
};

pub(super) const FORK_1_6_HEIGHT: u64 = 95_000;
pub(super) const FORK_2_0_HEIGHT: u64 = 422_250;
const FORK_2_4_HEIGHT: u64 = 633_720;

// Official client-verification auxiliary, not the original block-index hashes.
const LEGACY_HASH_LIST_URL: &str = "https://raw.githubusercontent.com/ArweaveTeam/arweave/50e47de6d054afefdee112fa124695eb8d0176fc/genesis_data/hash_list_1_0";
const LEGACY_HASH_LIST_BYTES: usize = 28_290_751;
const LEGACY_HASH_LIST_SHA256: [u8; 32] = [
    0xd1, 0x61, 0x50, 0x2a, 0x13, 0xe6, 0x4f, 0xa4, 0x9b, 0xcb, 0x24, 0x25, 0x42, 0x0b, 0xcd, 0xcd,
    0x6a, 0x44, 0x07, 0xe4, 0x88, 0xac, 0xa3, 0xe1, 0x4b, 0xa2, 0x54, 0xf1, 0x64, 0x18, 0xca, 0x6f,
];
static LEGACY_HASHES: OnceCell<Vec<[u8; 48]>> = OnceCell::const_new();

pub(super) async fn verify_legacy_header(
    mut block: BlockHeader,
    entry: BlockIndexEntry,
    client: &reqwest::Client,
) -> Result<BlockHeader> {
    let index = legacy_hash_index(block.height)?;
    let hashes = LEGACY_HASHES
        .get_or_try_init(|| download_legacy_hashes(client))
        .await?;
    let expected_h2 = hashes[index];
    super::cpu_work(move || {
        verify_legacy_header_hash(&mut block, &entry, &expected_h2)?;
        Ok(block)
    })
    .await
}

fn legacy_hash_index(height: u64) -> Result<usize> {
    (FORK_2_0_HEIGHT - 1)
        .checked_sub(height)
        .map(|index| index as usize)
        .context("not a pre-2.0 block")
}

async fn download_legacy_hashes(client: &reqwest::Client) -> Result<Vec<[u8; 48]>> {
    let mut response = client
        .get(LEGACY_HASH_LIST_URL)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .context("failed to download historical H2 table")?
        .error_for_status()
        .context("historical H2 table request failed")?;
    if let Some(length) = response.content_length() {
        ensure!(
            length == LEGACY_HASH_LIST_BYTES as u64,
            "historical H2 table length mismatch"
        );
    }
    let mut body = Vec::with_capacity(LEGACY_HASH_LIST_BYTES);
    while let Some(chunk) = response.chunk().await.context("failed to read H2 table")? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= LEGACY_HASH_LIST_BYTES,
            "historical H2 table exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    super::cpu_work(move || decode_legacy_hashes(&body)).await
}

fn decode_legacy_hashes(body: &[u8]) -> Result<Vec<[u8; 48]>> {
    ensure!(
        body.len() == LEGACY_HASH_LIST_BYTES,
        "historical H2 table length mismatch"
    );
    ensure!(
        sha256(&[body]) == LEGACY_HASH_LIST_SHA256,
        "historical H2 table checksum mismatch"
    );
    let encoded: Vec<&str> =
        serde_json::from_slice(body).context("invalid historical H2 table JSON")?;
    ensure!(
        encoded.len() == FORK_2_0_HEIGHT as usize,
        "historical H2 table entry count mismatch"
    );
    let mut hashes = Vec::with_capacity(encoded.len());
    for value in encoded {
        ensure!(value.len() == 64, "invalid historical H2 hash length");
        let mut hash = [0_u8; 48];
        URL_SAFE_NO_PAD
            .decode_slice(value, &mut hash)
            .context("invalid historical H2 hash")?;
        hashes.push(hash);
    }
    Ok(hashes)
}

// ar_header_sync replaces the old tx_root and sorts decoded IDs before hashing.
// The caller separately checks the requested height and transaction membership.
fn verify_legacy_header_hash(
    block: &mut BlockHeader,
    entry: &BlockIndexEntry,
    expected_h2: &[u8; 48],
) -> Result<()> {
    legacy_hash_index(block.height)?;
    ensure!(
        decode_fixed::<48>(&block.indep_hash, "block indep_hash")?
            == decode_fixed::<48>(&entry.hash, "trusted block hash")?,
        "block header identifier mismatch"
    );
    ensure!(
        parse_u128(&block.weave_size, "block weave size")?
            == parse_u128(&entry.weave_size, "trusted block weave size")?,
        "block weave size does not match trusted index"
    );
    ensure!(
        matches!(
            decode_b64(&entry.tx_root, "trusted block tx_root")?.len(),
            0 | 32
        ),
        "invalid trusted block tx_root length"
    );
    block.tx_root.clone_from(&entry.tx_root);
    let mut transactions = block
        .txs
        .iter()
        .map(|id| decode_fixed::<32>(id, "block transaction ID"))
        .collect::<Result<Vec<_>>>()?;
    transactions.sort_unstable();
    let transaction_hashes: Vec<_> = transactions.iter().map(|id| deep_hash_blob(id)).collect();
    ensure!(
        modern_indep_hash(block, deep_hash_list(&transaction_hashes))? == *expected_h2,
        "historical block H2 verification failed"
    );
    Ok(())
}

// The order and JSON field names here are the pre-1.6 consensus preimage,
// not the modern wallet-list endpoint's address/balance field names.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct LegacyWallet {
    #[serde(rename = "wallet", alias = "address")]
    address: String,
    #[serde(
        rename = "quantity",
        alias = "balance",
        deserialize_with = "wallet_balance"
    )]
    balance: Number,
    last_tx: String,
}

fn wallet_balance<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Number, D::Error> {
    let mut value = Value::deserialize(deserializer)?;
    normalize_decimal(&mut value, "wallet balance").map_err(serde::de::Error::custom)?;
    decimal_number(value.as_str().unwrap(), "wallet balance").map_err(serde::de::Error::custom)
}

pub(super) fn decode_wallets(value: Value) -> Result<Vec<LegacyWallet>> {
    serde_json::from_value(value).context("invalid historical full wallet list")
}

// Retain JSON integers as decimal text, never via f64/u64. The caller must
// enable serde_json arbitrary_precision and preserve_order before parsing.
fn normalize_decimal(value: &mut Value, label: &str) -> Result<()> {
    if let Value::Number(number) = value {
        *value = Value::String(number.to_string());
    }
    let text = value
        .as_str()
        .with_context(|| format!("invalid {label}: expected integer"))?;
    ensure!(
        !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid {label}: expected nonnegative integer"
    );
    Ok(())
}

pub(super) fn decode_header(mut value: Value) -> Result<BlockHeader> {
    let fields = value
        .as_object_mut()
        .context("block header must be a JSON object")?;
    let height = fields
        .get("height")
        .and_then(Value::as_u64)
        .context("invalid block height")?;
    if height >= FORK_2_5_HEIGHT {
        return serde_json::from_value(value).context("invalid block header");
    }

    // The official parser ignores these fields entirely before fork 1.6.
    if height < FORK_1_6_HEIGHT {
        fields.insert("cumulative_diff".into(), Value::String("0".into()));
        fields.insert("hash_list_merkle".into(), Value::String(String::new()));
    }
    if height < FORK_2_0_HEIGHT {
        fields
            .entry("tx_root")
            .or_insert(Value::String(String::new()));
        fields.entry("poa").or_insert_with(|| {
            serde_json::json!({
                "option": "1", "tx_path": "", "data_path": "", "chunk": ""
            })
        });
    }
    // The Erlang pre-2.5 record uses undefined for these later fields. Empty
    // string slots preserve that absence in the current model; never hash them.
    for name in ["packing_2_5_threshold", "strict_data_split_threshold"] {
        fields.entry(name).or_insert(Value::String(String::new()));
    }
    for name in ["usd_to_ar_rate", "scheduled_usd_to_ar_rate"] {
        fields
            .entry(name)
            .or_insert_with(|| serde_json::json!(["", ""]));
    }
    for name in [
        "diff",
        "cumulative_diff",
        "reward_pool",
        "block_size",
        "weave_size",
    ] {
        normalize_decimal(
            fields
                .get_mut(name)
                .with_context(|| format!("missing block {name}"))?,
            name,
        )?;
    }
    let poa = fields
        .get_mut("poa")
        .and_then(Value::as_object_mut)
        .context("missing block proof of access")?;
    normalize_decimal(
        poa.get_mut("option").context("missing proof option")?,
        "proof option",
    )?;
    for name in ["tx_path", "data_path", "chunk"] {
        ensure!(
            poa.get(name).is_some_and(Value::is_string),
            "missing or invalid proof {name}"
        );
    }

    let wallets = fields
        .get_mut("wallet_list")
        .context("missing block wallet list")?;
    let legacy_wallets = if wallets.is_array() {
        ensure!(
            height < FORK_2_0_HEIGHT,
            "block requires a wallet-list root, not a full list"
        );
        let full_list = wallets.take();
        // Only the ordered full list is an input below 2.0. This unused root
        // slot is not a substitute: indep_hash requires legacy_wallets = Some.
        *wallets = Value::String(String::new());
        Some(decode_wallets(full_list)?)
    } else {
        ensure!(wallets.is_string(), "invalid block wallet list");
        None
    };
    let transactions = fields
        .get_mut("txs")
        .and_then(Value::as_array_mut)
        .context("missing block transaction list")?;
    for transaction in transactions {
        if let Value::Object(transaction_fields) = transaction {
            *transaction = transaction_fields
                .remove("id")
                .context("missing block transaction ID")?;
        }
        ensure!(transaction.is_string(), "invalid block transaction ID");
    }
    let mut block: BlockHeader =
        serde_json::from_value(value).context("invalid historical block header")?;
    block.legacy_wallets = legacy_wallets;
    Ok(block)
}

// Historical source (includes the complete pre-1.6 ordered JSON object):
// https://github.com/ArweaveTeam/arweave/blob/de995bf9aec003ccf5f48ee47998a34c1ec36668/src/ar_weave.erl#L243-L327
// Fork-2.0/2.4 BDS and PoA placement:
// https://github.com/ArweaveTeam/arweave/blob/50e47de6d054afefdee112fa124695eb8d0176fc/apps/arweave/src/ar_block.erl#L474-L621
pub(super) fn indep_hash(block: &BlockHeader) -> Result<[u8; 48]> {
    ensure!(block.height < FORK_2_5_HEIGHT, "not a pre-2.5 block");
    if block.height < FORK_1_6_HEIGHT {
        return Ok(sha384(&[&canonical_preimage(block)?]));
    }

    // ar_tx:tags_to_list is [[Name, Value] || {Name, Value} <- Tags].
    // The historical HTTP parser keeps Jiffy's raw tags unchanged: JSON arrays
    // are Erlang lists and JSON objects are ONE-tuples containing proplists.
    // No JSON value is an Erlang two-tuple, so all entries are filtered out.
    // In particular, interpreting [name, value] as a tuple would change the ID.
    // https://github.com/ArweaveTeam/arweave/blob/master/apps/arweave/src/ar_serialize.erl#L1368-L1376
    // https://github.com/ArweaveTeam/arweave/blob/master/apps/arweave/src/ar_tx.erl#L137-L138
    if block.height < FORK_2_0_HEIGHT {
        let wallets = required_wallets(block)?;
        let wallet_hashes = wallets
            .iter()
            .map(|wallet| {
                Ok(deep_hash_list(&[
                    deep_hash_blob(&decode_b64(&wallet.address, "wallet address")?),
                    deep_hash_blob(wallet.balance.to_string().as_bytes()),
                    deep_hash_blob(&decode_b64(&wallet.last_tx, "wallet last_tx")?),
                ]))
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(deep_hash_list(&[
            deep_hash_blob(&decode_b64(&block.nonce, "block nonce")?),
            deep_hash_blob(&decode_b64(&block.previous_block, "previous block")?),
            deep_hash_blob(block.timestamp.to_string().as_bytes()),
            deep_hash_blob(block.last_retarget.to_string().as_bytes()),
            deep_hash_decimal(&block.diff, "block difficulty")?,
            deep_hash_decimal(&block.cumulative_diff, "cumulative difficulty")?,
            deep_hash_blob(block.height.to_string().as_bytes()),
            deep_hash_blob(&decode_b64(&block.hash, "block hash")?),
            deep_hash_blob(&decode_b64(&block.hash_list_merkle, "hash_list_merkle")?),
            deep_hash_b64_list(&block.txs, "block transaction ID")?,
            deep_hash_list(&wallet_hashes),
            deep_hash_blob(&reward_address(&block.reward_addr, false)?),
            deep_hash_list(&[]),
            deep_hash_decimal(&block.reward_pool, "reward pool")?,
            deep_hash_decimal(&block.weave_size, "block weave size")?,
            deep_hash_decimal(&block.block_size, "block size")?,
        ]));
    }

    modern_indep_hash(
        block,
        deep_hash_b64_list(&block.txs, "block transaction ID")?,
    )
}

fn modern_indep_hash(block: &BlockHeader, transaction_hash: [u8; 48]) -> Result<[u8; 48]> {
    let poa = deep_hash_list(&[
        deep_hash_decimal(&block.poa.option, "proof option")?,
        deep_hash_blob(&decode_b64(&block.poa.tx_path, "block tx_path")?),
        deep_hash_blob(&decode_b64(&block.poa.data_path, "block data_path")?),
        deep_hash_blob(&decode_b64(&block.poa.chunk, "block chunk")?),
    ]);
    let base = [
        deep_hash_blob(block.height.to_string().as_bytes()),
        deep_hash_blob(&decode_b64(&block.previous_block, "previous block")?),
        deep_hash_blob(&decode_b64(&block.tx_root, "block tx_root")?),
        transaction_hash,
        deep_hash_decimal(&block.block_size, "block size")?,
        deep_hash_decimal(&block.weave_size, "block weave size")?,
        deep_hash_blob(&reward_address(&block.reward_addr, false)?),
        deep_hash_list(&[]),
        poa,
    ];
    let base_hash = deep_hash_list(if block.height < FORK_2_4_HEIGHT {
        &base
    } else {
        &base[..8]
    });
    let data = deep_hash_list(&[
        deep_hash_blob(&base_hash),
        deep_hash_blob(block.timestamp.to_string().as_bytes()),
        deep_hash_blob(block.last_retarget.to_string().as_bytes()),
        deep_hash_decimal(&block.diff, "block difficulty")?,
        deep_hash_decimal(&block.cumulative_diff, "cumulative difficulty")?,
        deep_hash_decimal(&block.reward_pool, "reward pool")?,
        deep_hash_blob(&decode_b64(&block.wallet_list, "wallet-list root")?),
        deep_hash_blob(&decode_b64(&block.hash_list_merkle, "hash_list_merkle")?),
    ]);
    let independent = [
        deep_hash_blob(&data),
        deep_hash_blob(&decode_b64(&block.hash, "block hash")?),
        deep_hash_blob(&decode_b64(&block.nonce, "block nonce")?),
        poa,
    ];
    Ok(deep_hash_list(if block.height < FORK_2_4_HEIGHT {
        &independent[..3]
    } else {
        &independent
    }))
}

fn required_wallets(block: &BlockHeader) -> Result<&[LegacyWallet]> {
    block
        .legacy_wallets
        .as_deref()
        .context("missing full ordered historical wallet list")
}

fn decimal_number(value: &str, label: &str) -> Result<Number> {
    parse_biguint(value, label)?
        .to_str_radix(10)
        .parse()
        .with_context(|| format!("invalid {label}"))
}

#[derive(Serialize)]
struct CanonicalBlock<'a> {
    nonce: &'a str,
    previous_block: &'a str,
    timestamp: u64,
    last_retarget: u64,
    diff: Number,
    height: u64,
    hash: &'a str,
    indep_hash: &'a str,
    txs: &'a [String],
    hash_list: &'a [String],
    wallet_list: &'a [LegacyWallet],
    reward_addr: &'a str,
    tags: &'a [Value],
    reward_pool: Number,
    weave_size: Number,
    block_size: Number,
}

fn canonical_preimage(block: &BlockHeader) -> Result<Vec<u8>> {
    let wallets = required_wallets(block)?;
    ensure!(
        block.hash_list.len() as u64 == block.height,
        "missing or incomplete historical hash_list: expected every predecessor through H0"
    );
    if block.height == 0 {
        ensure!(block.previous_block.is_empty(), "genesis has a predecessor");
    } else {
        ensure!(
            block.hash_list.first() == Some(&block.previous_block),
            "historical hash_list must start with the previous block and end with H0"
        );
    }
    for hash in &block.hash_list {
        decode_fixed::<48>(hash, "historical predecessor hash")?;
    }
    for id in &block.txs {
        decode_fixed::<32>(id, "block transaction ID")?;
    }
    for wallet in wallets {
        decode_b64(&wallet.address, "wallet address")?;
        decode_b64(&wallet.last_tx, "wallet last_tx")?;
    }
    decode_b64(&block.nonce, "block nonce")?;
    // Historical PoW hashes/nonces are not constrained to modern sizes.
    decode_b64(&block.hash, "block hash")?;
    reward_address(&block.reward_addr, false)?;
    let canonical = CanonicalBlock {
        nonce: &block.nonce,
        previous_block: &block.previous_block,
        timestamp: block.timestamp,
        last_retarget: block.last_retarget,
        diff: decimal_number(&block.diff, "block difficulty")?,
        height: block.height,
        hash: &block.hash,
        indep_hash: "",
        txs: &block.txs,
        hash_list: &block.hash_list,
        wallet_list: wallets,
        reward_addr: &block.reward_addr,
        tags: &block.tags,
        reward_pool: decimal_number(&block.reward_pool, "reward pool")?,
        weave_size: decimal_number(&block.weave_size, "block weave size")?,
        block_size: decimal_number(&block.block_size, "block size")?,
    };
    let mut serializer = serde_json::Serializer::with_formatter(Vec::new(), JiffyFormatter);
    canonical
        .serialize(&mut serializer)
        .context("cannot represent historical Jiffy block preimage")?;
    Ok(serializer.into_inner())
}

// The Jiffy source vendored by the historical node uses uppercase hex for
// control escapes. Serde's other compact string escapes match: raw UTF-8, no
// slash escaping, and the short escapes for backspace/formfeed/newline/CR/tab.
// https://github.com/ArweaveTeam/arweave/blob/de995bf9aec003ccf5f48ee47998a34c1ec36668/lib/jiffy/c_src/encoder.c#L247-L400
// https://github.com/ArweaveTeam/arweave/blob/de995bf9aec003ccf5f48ee47998a34c1ec36668/lib/jiffy/c_src/utf8.c#L31-L67
struct JiffyFormatter;

impl Formatter for JiffyFormatter {
    fn write_char_escape<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        escape: CharEscape,
    ) -> io::Result<()> {
        if let CharEscape::AsciiControl(byte) = escape {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            writer.write_all(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(byte >> 4) as usize],
                HEX[(byte & 15) as usize],
            ])
        } else {
            CompactFormatter.write_char_escape(writer, escape)
        }
    }

    fn write_number_str<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        value: &str,
    ) -> io::Result<()> {
        let digits = value.strip_prefix('-').unwrap_or(value);
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            // Preserve arbitrary-size integers; Jiffy decodes integer -0 as 0.
            return writer.write_all(if value == "-0" {
                b"0"
            } else {
                value.as_bytes()
            });
        }
        let number = value
            .parse::<f64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.write_f64(writer, number)
    }

    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        if !value.is_finite() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-finite historical JSON number",
            ));
        }
        if value == 0.0 {
            return writer.write_all(b"0.0");
        }

        // Jiffy's vendored DoubleToStringConverter uses nearest-even shortest
        // digits, UNIQUE_ZERO, positive exponent signs, fixed notation for
        // exponents [-6,21), and trailing ".0" for fixed integral floats.
        // https://github.com/ArweaveTeam/arweave/blob/de995bf9aec003ccf5f48ee47998a34c1ec36668/lib/jiffy/c_src/doubles.cc
        // Its bignum-dtoa.cc L235-L260 and Serde's existing Zmij formatter both
        // select the nearest EVEN decimal on ties. Rust's standard shortest
        // formatting rounds ties away from zero, so is not interchangeable.
        let mut rendered = [0_u8; 32];
        let mut remaining = &mut rendered[..];
        CompactFormatter.write_f64(&mut remaining, value.abs())?;
        let length = 32 - remaining.len();
        let shortest = std::str::from_utf8(&rendered[..length]).unwrap();
        let (mantissa, exponent) = match shortest.split_once('e') {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i32>().unwrap()),
            None => (shortest, 0),
        };
        let point = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
        let mut digits = [0_u8; 32];
        let mut length = 0;
        for byte in mantissa.bytes().filter(|byte| *byte != b'.') {
            digits[length] = byte;
            length += 1;
        }
        let start = digits[..length]
            .iter()
            .position(|byte| *byte != b'0')
            .unwrap();
        let end = digits[..length]
            .iter()
            .rposition(|byte| *byte != b'0')
            .unwrap();
        let digits = &digits[start..=end];
        let point = point - start as i32;
        let exponent = point - 1;
        if value.is_sign_negative() {
            writer.write_all(b"-")?;
        }
        if !(-6..21).contains(&exponent) {
            writer.write_all(&digits[..1])?;
            if digits.len() > 1 {
                writer.write_all(b".")?;
                writer.write_all(&digits[1..])?;
            }
            write!(writer, "e{exponent:+}")
        } else if point <= 0 {
            writer.write_all(b"0.")?;
            writer.write_all(&[b'0'; 20][..(-point) as usize])?;
            writer.write_all(digits)
        } else if point as usize >= digits.len() {
            writer.write_all(digits)?;
            writer.write_all(&[b'0'; 20][..point as usize - digits.len()])?;
            writer.write_all(b".0")
        } else {
            writer.write_all(&digits[..point as usize])?;
            writer.write_all(b".")?;
            writer.write_all(&digits[point as usize..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_legacy_header_authenticates_real_300000_and_rejects_tampering() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/historical-block-300000.json"
        ))
        .unwrap();
        let expected_h2 = decode_fixed::<48>(fixture["h2"].as_str().unwrap(), "H2").unwrap();
        let entry: BlockIndexEntry = serde_json::from_value(fixture["index"].clone()).unwrap();
        let mut block = decode_header(fixture["block"].clone()).unwrap();
        verify_legacy_header_hash(&mut block, &entry, &expected_h2).unwrap();
        block.txs.reverse();
        verify_legacy_header_hash(&mut block, &entry, &expected_h2).unwrap();

        block.wallet_list = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        assert!(verify_legacy_header_hash(&mut block, &entry, &expected_h2).is_err());
        block = decode_header(fixture["block"].clone()).unwrap();
        block.txs[0] = URL_SAFE_NO_PAD.encode([0_u8; 32]);
        assert!(verify_legacy_header_hash(&mut block, &entry, &expected_h2).is_err());
        block = decode_header(fixture["block"].clone()).unwrap();
        block.indep_hash = URL_SAFE_NO_PAD.encode([0_u8; 48]);
        assert!(verify_legacy_header_hash(&mut block, &entry, &expected_h2).is_err());
        block = decode_header(fixture["block"].clone()).unwrap();
        block.weave_size = "0".into();
        assert!(verify_legacy_header_hash(&mut block, &entry, &expected_h2).is_err());
        block = decode_header(fixture["block"].clone()).unwrap();
        let altered_entry = BlockIndexEntry {
            tx_root: URL_SAFE_NO_PAD.encode([0_u8; 32]),
            ..entry
        };
        assert!(verify_legacy_header_hash(&mut block, &altered_entry, &expected_h2).is_err());
    }

    #[test]
    fn pre_1_6_h2_ignores_fields_absent_before_the_fork() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/historical-block-300000.json"
        ))
        .unwrap();
        let mut header = fixture["block"].clone();
        header["height"] = Value::from(FORK_1_6_HEIGHT - 1);
        let fields = header.as_object_mut().unwrap();
        fields.remove("cumulative_diff");
        fields.remove("hash_list_merkle");
        fields.remove("poa");
        let block = decode_header(header.clone()).unwrap();
        let transactions = deep_hash_b64_list(&block.txs, "transaction ID").unwrap();
        let expected = modern_indep_hash(&block, transactions).unwrap();

        header["cumulative_diff"] = serde_json::json!({"ignored": true});
        header["hash_list_merkle"] = Value::String("not base64".into());
        let block = decode_header(header.clone()).unwrap();
        assert_eq!(modern_indep_hash(&block, transactions).unwrap(), expected);
        header["height"] = Value::from(FORK_1_6_HEIGHT);
        assert!(decode_header(header).is_err());
    }

    #[test]
    fn legacy_table_rejects_truncation_overflow_and_checksum_changes() {
        let mut corrupt = vec![0; LEGACY_HASH_LIST_BYTES - 1];
        assert!(decode_legacy_hashes(&corrupt).is_err());
        corrupt.push(0);
        assert!(decode_legacy_hashes(&corrupt).is_err());
        corrupt.push(0);
        assert!(decode_legacy_hashes(&corrupt).is_err());
    }

    #[test]
    fn legacy_table_height_mapping_covers_both_boundaries() {
        assert_eq!(legacy_hash_index(0).unwrap(), 422_249);
        assert_eq!(legacy_hash_index(300_000).unwrap(), 122_249);
        assert_eq!(legacy_hash_index(422_249).unwrap(), 0);
        assert!(legacy_hash_index(FORK_2_0_HEIGHT).is_err());
        assert!(legacy_hash_index(u64::MAX).is_err());
    }

    #[test]
    fn jiffy_preimage_preserves_order_integers_and_raw_tags() {
        let block = decode_header(serde_json::from_str(r#"{
            "nonce":"AA","previous_block":"","timestamp":1,"last_retarget":2,
            "diff":340282366920938463463374607431768211456,"height":0,"hash":"AQ",
            "indep_hash":"ignored","txs":[],"hash_list":[],
            "wallet_list":[{"address":"Ag","balance":"340282366920938463463374607431768211457","last_tx":""}],
            "reward_addr":"unclaimed","tags":[{"z":-0,"a":"\u000e/\u00e9\u2028\ud83d\ude00\n"},[104,105]],
            "reward_pool":3,"weave_size":4,"block_size":5
        }"#).unwrap()).unwrap();
        let expected = concat!(
            "{\"nonce\":\"AA\",\"previous_block\":\"\",\"timestamp\":1,\"last_retarget\":2,",
            "\"diff\":340282366920938463463374607431768211456,\"height\":0,\"hash\":\"AQ\",",
            "\"indep_hash\":\"\",\"txs\":[],\"hash_list\":[],\"wallet_list\":[{\"wallet\":\"Ag\",",
            "\"quantity\":340282366920938463463374607431768211457,\"last_tx\":\"\"}],",
            "\"reward_addr\":\"unclaimed\",\"tags\":[{\"z\":0,\"a\":\"\\u000E/\u{e9}\u{2028}\u{1f600}\\n\"},[104,105]],",
            "\"reward_pool\":3,\"weave_size\":4,\"block_size\":5}"
        );
        assert_eq!(canonical_preimage(&block).unwrap(), expected.as_bytes());
        assert_eq!(indep_hash(&block).unwrap(), sha384(&[expected.as_bytes()]));
    }

    #[test]
    fn historical_preimages_require_wallets_and_all_predecessors() {
        let mut block = BlockHeader {
            diff: "1".into(),
            reward_pool: "0".into(),
            weave_size: "0".into(),
            block_size: "0".into(),
            reward_addr: "unclaimed".into(),
            ..BlockHeader::default()
        };
        assert!(indep_hash(&block).is_err());
        block.legacy_wallets = Some(Vec::new());
        let genesis_hash = indep_hash(&block).unwrap();
        block.height = 1;
        block.previous_block = URL_SAFE_NO_PAD.encode(genesis_hash);
        assert!(indep_hash(&block).is_err());
        block.hash_list.push(block.previous_block.clone());
        let first_hash = indep_hash(&block).unwrap();
        block.height = 2;
        block.previous_block = URL_SAFE_NO_PAD.encode(first_hash);
        block.hash_list.insert(0, block.previous_block.clone());
        let second_hash = indep_hash(&block).unwrap();
        block.hash_list.pop();
        assert!(indep_hash(&block).is_err());
        block.hash_list.push(URL_SAFE_NO_PAD.encode(genesis_hash));
        block.hash_list.reverse();
        assert!(indep_hash(&block).is_err());
        block.hash_list.reverse();
        assert_eq!(indep_hash(&block).unwrap(), second_hash);
    }

    #[test]
    fn legacy_json_arrays_are_not_erlang_tag_tuples() {
        let mut block = BlockHeader {
            diff: "1".into(),
            cumulative_diff: "1".into(),
            reward_pool: "0".into(),
            weave_size: "0".into(),
            block_size: "0".into(),
            reward_addr: "unclaimed".into(),
            legacy_wallets: Some(Vec::new()),
            ..BlockHeader::default()
        };
        block.poa.option = "1".into();
        // Jiffy decodes ["name","value"] to an Erlang LIST, not {Name,Value}.
        // ar_serialize does not adapt these raw block tags to transaction tags.
        for height in [FORK_1_6_HEIGHT, FORK_2_0_HEIGHT, FORK_2_4_HEIGHT] {
            block.height = height;
            block.tags = vec![
                serde_json::json!(["name", "value"]),
                serde_json::json!([104, 105]),
            ];
            let tagged = indep_hash(&block).unwrap();
            block.tags.clear();
            assert_eq!(indep_hash(&block).unwrap(), tagged);
        }
    }

    #[test]
    fn missing_fork_inputs_and_invalid_balances_fail_closed() {
        let mut header = serde_json::json!({
            "nonce":"", "previous_block":"", "timestamp":1, "last_retarget":1,
            "diff":1, "height":FORK_2_0_HEIGHT, "hash":"", "indep_hash":"",
            "txs":[], "wallet_list":"", "reward_addr":"unclaimed", "tags":[],
            "reward_pool":0, "weave_size":0, "block_size":0,
            "cumulative_diff":1, "hash_list_merkle":"", "tx_root":""
        });
        assert!(decode_header(header.clone()).is_err());
        header["poa"] = serde_json::json!({"option":"1", "tx_path":"", "data_path":""});
        assert!(decode_header(header).is_err());
        assert!(
            decode_wallets(serde_json::json!([{"wallet":"", "quantity":1.5, "last_tx":""}]))
                .is_err()
        );
    }

    #[test]
    fn jiffy_float_notation_and_nearest_even_ties() {
        // The boundary cases follow the vendored converter's ToShortest
        // examples plus the trailing-zero flags in doubles.cc.
        for (input, expected) in [
            ("1.0", "1.0"),
            ("-0.0", "0.0"),
            ("0.000001", "0.000001"),
            ("-0.0000001", "-1e-7"),
            ("1e20", "100000000000000000000.0"),
            ("1e21", "1e+21"),
            ("111111111111111111111.0", "111111111111111110000.0"),
            ("1111111111111111111111.0", "1.1111111111111111e+21"),
            ("1000000000000000.25", "1000000000000000.2"),
            ("1000000000000000.75", "1000000000000000.8"),
            ("5e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
        ] {
            let number: Value = serde_json::from_str(input).unwrap();
            let mut serializer = serde_json::Serializer::with_formatter(Vec::new(), JiffyFormatter);
            number.serialize(&mut serializer).unwrap();
            assert_eq!(serializer.into_inner(), expected.as_bytes(), "{input}");
        }
        let number: Value = serde_json::from_str("1e400").unwrap();
        let mut serializer = serde_json::Serializer::with_formatter(Vec::new(), JiffyFormatter);
        assert!(number.serialize(&mut serializer).is_err());
    }
}
