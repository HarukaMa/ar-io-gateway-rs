use anyhow::{Context, Result, ensure};
use rsa::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    BlockHeader, FORK_2_5_HEIGHT, FORK_2_6_HEIGHT, FORK_2_9_HEIGHT, MAX_BLOCK_TRANSACTIONS,
    MAX_CHUNK_SIZE, RecoveryId, Secp256k1Signature, Secp256k1VerifyingKey, Transaction,
    database::ObjectMetadata, decode_b64, decode_fixed, deep_hash_blob, deep_hash_list,
    hash_branch, hash_leaf, parse_u128, sha256,
};

const FORK_2_0_HEIGHT: u64 = 422_250;
const FORK_2_4_HEIGHT: u64 = 633_720;

// SHA-256 of the JSON tuples below, ordered by raw transaction ID, from
// ArweaveTeam/arweave@50e47de6d054afefdee112fa124695eb8d0176fc/genesis_data/genesis_txs.
const MAINNET_GENESIS_RECORDS_SHA256: [u8; 32] = [
    0x07, 0xbd, 0x8c, 0xce, 0x7d, 0x85, 0x65, 0x5e, 0x24, 0x86, 0x35, 0x42, 0xca, 0xba, 0xda, 0x99,
    0x98, 0x26, 0xd3, 0xc8, 0xb6, 0x78, 0x12, 0x22, 0xc4, 0xb1, 0x6c, 0x64, 0x13, 0x17, 0x98, 0xf8,
];

pub(super) struct VerifiedTransaction {
    pub(super) metadata: ObjectMetadata,
    pub(super) inline_data: Option<Vec<u8>>,
}

pub(super) fn decode_transaction(mut value: Value) -> Result<Transaction> {
    let fields = value
        .as_object_mut()
        .context("transaction is not an object")?;
    let format = match fields.get("format") {
        Some(value) => json_integer(value, "transaction format")?.parse::<u8>()?,
        None => 1,
    };
    ensure!(matches!(format, 1 | 2), "unsupported transaction format");
    fields.insert("format".into(), Value::from(format));
    for name in ["quantity", "reward"] {
        let value = fields
            .get(name)
            .with_context(|| format!("missing transaction {name}"))?;
        let number = json_integer(value, name)?;
        fields.insert(name.into(), Value::String(number));
    }
    if let Some(value) = fields.get("denomination") {
        let denomination = json_integer(value, "transaction denomination")?.parse::<u32>()?;
        ensure!(
            denomination > 0,
            "explicit transaction denomination must be positive"
        );
        fields.insert("denomination".into(), Value::from(denomination));
    }
    if let Some(value) = fields.get("data_size") {
        let number = json_integer(value, "transaction data size")?;
        fields.insert("data_size".into(), Value::String(number));
    }
    if format == 1 {
        let data = fields
            .get("data")
            .and_then(Value::as_str)
            .context("format-1 transaction is missing inline data")?;
        // ar_serialize:parse_data_size/4 ignores the unsigned v1 size field.
        let size = decode_b64(data, "transaction data")?.len();
        fields.insert("data_size".into(), Value::String(size.to_string()));
    } else {
        ensure!(
            fields.contains_key("data_size"),
            "missing transaction data size"
        );
    }
    fields
        .entry("tags")
        .or_insert_with(|| Value::Array(Vec::new()));
    serde_json::from_value(value).context("invalid transaction JSON")
}

fn json_integer(value: &Value, label: &str) -> Result<String> {
    match value {
        Value::String(value) => Ok(canonical_unsigned(value, label)?.to_owned()),
        Value::Number(value) => Ok(canonical_unsigned(&value.to_string(), label)?.to_owned()),
        _ => anyhow::bail!("invalid {label}: expected an integer"),
    }
}

fn canonical_unsigned<'a>(value: &'a str, label: &str) -> Result<&'a str> {
    let negative = value.starts_with('-');
    let digits = value
        .strip_prefix('+')
        .or_else(|| value.strip_prefix('-'))
        .unwrap_or(value);
    ensure!(
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid {label}"
    );
    let number = digits.trim_start_matches('0');
    ensure!(!negative || number.is_empty(), "negative {label}");
    Ok(if number.is_empty() { "0" } else { number })
}

pub(super) fn verify_transaction(
    transaction: &Transaction,
    expected_id: &str,
    height: u64,
) -> Result<VerifiedTransaction> {
    // ar_node_utils passes containing_height - 1 through ar_tx_replay_pool.
    // Signature/format gates use that parent height; denomination adds 1 back.
    let previous_height = height.saturating_sub(1);
    ensure!(
        matches!(transaction.format, 1 | 2),
        "unsupported transaction format"
    );
    ensure!(
        transaction.format == 1 || previous_height >= FORK_2_0_HEIGHT,
        "format-2 transaction before fork 2.0"
    );
    ensure!(
        transaction.denomination == 0 || height >= FORK_2_6_HEIGHT,
        "transaction denomination before fork 2.6"
    );
    let id = decode_fixed::<32>(&transaction.id, "transaction ID")?;
    ensure!(
        transaction.owner.len() <= 683 && transaction.signature.len() <= 683,
        "transaction key or signature exceeds protocol limit"
    );
    ensure!(
        id == decode_fixed::<32>(expected_id, "expected transaction ID")?,
        "transaction ID mismatch"
    );
    let signature = decode_b64(&transaction.signature, "transaction signature")?;
    ensure!(
        id == sha256(&[&signature]),
        "transaction ID is not the signature hash"
    );
    let mut owner = decode_b64(&transaction.owner, "transaction owner")?;
    ensure!(
        owner.len() <= 512 && signature.len() <= 512,
        "transaction key or signature exceeds protocol limit"
    );
    let ecdsa = owner.is_empty();
    ensure!(
        !ecdsa || (transaction.format == 2 && previous_height >= FORK_2_9_HEIGHT),
        "ECDSA transaction before fork 2.9 or in format 1"
    );
    let target = decode_b64(&transaction.target, "transaction target")?;
    let anchor = decode_b64(&transaction.last_tx, "transaction anchor")?;
    let quantity = canonical_unsigned(&transaction.quantity, "transaction quantity")?;
    let reward = canonical_unsigned(&transaction.reward, "transaction reward")?;
    let tags = transaction
        .tags
        .iter()
        .map(|tag| {
            Ok((
                decode_b64(&tag.name, "tag name")?,
                decode_b64(&tag.value, "tag value")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let data = decode_b64(&transaction.data, "transaction data")?;
    let supplied_root = decode_b64(&transaction.data_root, "transaction data root")?;
    let (data_size, data_root) = if transaction.format == 1 {
        // Neither v1 root nor size is signed. Recompute instead of accepting an
        // archival provider's advisory fields; even empty data has a tree leaf.
        (data.len() as u128, inline_data_root(&data).to_vec())
    } else {
        let size =
            canonical_unsigned(&transaction.data_size, "transaction data size")?.parse::<u128>()?;
        let root = supplied_root;
        ensure!(
            (size == 0) == root.is_empty() && root.len() <= 32,
            "transaction data size and root disagree"
        );
        ensure!(
            size != 0 || data.is_empty(),
            "empty transaction has nonempty inline data"
        );
        (size, root)
    };
    let digest = if transaction.format == 1 && transaction.denomination == 0 {
        // ar_tx:tags_to_binary/1 is raw ordered concatenation, NOT Avro.
        let mut digest = Sha256::new();
        for bytes in [
            owner.as_slice(),
            &target,
            &data,
            quantity.as_bytes(),
            reward.as_bytes(),
            &anchor,
        ] {
            digest.update(bytes);
        }
        for (name, value) in &tags {
            digest.update(name);
            digest.update(value);
        }
        digest.finalize().into()
    } else {
        let tag_hashes = tags
            .iter()
            .map(|(name, value)| deep_hash_list(&[deep_hash_blob(name), deep_hash_blob(value)]))
            .collect::<Vec<_>>();
        let mut fields = Vec::with_capacity(10);
        if transaction.denomination > 0 {
            fields.push(deep_hash_blob(
                transaction.denomination.to_string().as_bytes(),
            ));
        }
        if transaction.format == 2 {
            fields.push(deep_hash_blob(b"2"));
        }
        if !ecdsa {
            fields.push(deep_hash_blob(&owner));
        }
        fields.push(deep_hash_blob(&target));
        if transaction.format == 1 {
            fields.push(deep_hash_blob(&data));
        }
        fields.extend([
            deep_hash_blob(quantity.as_bytes()),
            deep_hash_blob(reward.as_bytes()),
            deep_hash_blob(&anchor),
            deep_hash_list(&tag_hashes),
        ]);
        if transaction.format == 2 {
            fields.push(deep_hash_blob(data_size.to_string().as_bytes()));
            fields.push(deep_hash_blob(&data_root));
        }
        sha256(&[&deep_hash_list(&fields)])
    };
    if ecdsa {
        ensure!(
            signature.len() == 65,
            "invalid ECDSA transaction signature length"
        );
        let recovery =
            RecoveryId::try_from(signature[64]).context("invalid ECDSA transaction recovery ID")?;
        let compact = Secp256k1Signature::try_from(&signature[..64])
            .context("invalid ECDSA transaction signature")?;
        // The official secp256k1 NIF verifies low-S and serializes COMPRESSED.
        ensure!(
            compact.normalize_s() == compact,
            "noncanonical ECDSA transaction signature"
        );
        let key = Secp256k1VerifyingKey::recover_from_prehash(&digest, &compact, recovery)
            .context("ECDSA transaction signature recovery failed")?;
        owner = key.to_sec1_point(true).as_bytes().to_vec();
    } else {
        verify_rsa_pss_digest(
            &owner,
            &signature,
            &digest,
            previous_height < FORK_2_4_HEIGHT,
            "transaction",
        )?;
    }
    let owner_address = if !ecdsa && owner.len() == 32 {
        owner.clone()
    } else {
        sha256(&[&owner]).to_vec()
    };
    let content_type = optional_text_tag(
        tags.iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice())),
        b"Content-Type",
    );
    let content_encoding = optional_text_tag(
        tags.iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice())),
        b"Content-Encoding",
    );
    Ok(VerifiedTransaction {
        metadata: ObjectMetadata {
            id: id.to_vec(),
            kind: 0,
            signature,
            anchor,
            owner_address,
            owner_public_key: owner,
            target,
            data_size,
            content_type,
            content_encoding,
            signature_type: if ecdsa { 2 } else { 1 },
            format: Some(i16::from(transaction.format)),
            quantity: Some(quantity.to_owned()),
            reward: Some(reward.to_owned()),
            denomination: Some(transaction.denomination),
            data_root: Some(data_root),
            tags,
        },
        inline_data: if transaction.format == 1 || data_size == 0 {
            Some(data)
        } else {
            None
        },
    })
}

pub(super) fn verify_block_data_root(
    block: &BlockHeader,
    objects: &mut [ObjectMetadata],
) -> Result<()> {
    ensure!(
        objects.len() == block.txs.len() && objects.len() <= MAX_BLOCK_TRANSACTIONS,
        "incomplete block transaction data"
    );
    let mut expected_ids = block
        .txs
        .iter()
        .map(|id| decode_fixed::<32>(id, "block transaction ID"))
        .collect::<Result<std::collections::HashSet<_>>>()?;
    ensure!(
        expected_ids.len() == block.txs.len(),
        "duplicate block transaction ID"
    );
    // Erlang sorts full #tx{} records: format precedes the raw ID in the tuple.
    objects.sort_unstable_by(|left, right| (left.format, &left.id).cmp(&(right.format, &right.id)));
    let mut genesis = (block.height == 0).then(Sha256::new);
    if genesis.is_some() {
        ensure!(
            objects.len() == 314
                && block.indep_hash
                    == "7wIU7KolICAjClMlcZ38LZzshhI7xGkm2tDCJR7Wvhe3ESUo2-Z4-y0x1uaglRJE"
                && parse_u128(&block.block_size, "block size")? == 0
                && parse_u128(&block.weave_size, "weave size")? == 0
                && block.tx_root == "P_OiqMNN1s4ltcaq0HXb9VFos_Zz6LFjM8ogUG0vJek",
            "unsupported genesis block"
        );
    }
    let mut row = Vec::with_capacity(if genesis.is_some() {
        0
    } else {
        objects.len() * 2
    });
    let mut end = 0u128;
    for object in objects {
        let id: [u8; 32] = object
            .id
            .as_slice()
            .try_into()
            .context("invalid transaction ID")?;
        ensure!(
            expected_ids.remove(&id),
            "transaction does not match authenticated block membership"
        );
        let root = object
            .data_root
            .as_deref()
            .context("missing transaction data root")?;
        if let Some(digest) = genesis.as_mut() {
            // Bind every source field, including the ambiguous v1 metadata boundaries.
            serde_json::to_writer(
                digest,
                &(
                    &object.id,
                    &object.signature,
                    &object.anchor,
                    &object.owner_public_key,
                    &object.target,
                    object.data_size,
                    &object.data_root,
                    object.format,
                    &object.quantity,
                    &object.reward,
                    object.denomination,
                    &object.tags,
                ),
            )?;
            continue;
        }
        end = end
            .checked_add(object.data_size)
            .context("block data size overflow")?;
        // Empty roots/sizes still produce leaves; padding has an empty data root.
        row.push((hash_leaf(root, &note(end)), end));
        if block.height >= FORK_2_5_HEIGHT {
            let padding = (MAX_CHUNK_SIZE - object.data_size % MAX_CHUNK_SIZE) % MAX_CHUNK_SIZE;
            if padding > 0 {
                end = end.checked_add(padding).context("block padding overflow")?;
                row.push((hash_leaf(&[], &note(end)), end));
            }
        }
    }
    if let Some(digest) = genesis {
        let actual: [u8; 32] = digest.finalize().into();
        ensure!(
            actual == MAINNET_GENESIS_RECORDS_SHA256,
            "genesis transaction records differ from the official snapshot"
        );
        return Ok(());
    }
    ensure!(
        end == parse_u128(&block.block_size, "block size")?,
        "transaction data does not match authenticated block size"
    );
    let root = merkle_root(row);
    ensure!(
        root.as_ref().map_or(&[][..], |root| root.as_slice())
            == decode_b64(&block.tx_root, "block tx_root")?,
        "transaction data does not match authenticated block tx_root"
    );
    Ok(())
}

pub(super) fn optional_text_tag<'a>(
    tags: impl Iterator<Item = (&'a [u8], &'a [u8])>,
    expected: &[u8],
) -> Option<String> {
    tags.filter(|(name, _)| name.eq_ignore_ascii_case(expected))
        .find_map(|(_, value)| {
            std::str::from_utf8(value)
                .ok()
                .filter(|value| !value.contains('\0'))
                .map(str::to_owned)
        })
}

fn inline_data_root(data: &[u8]) -> [u8; 32] {
    const CHUNK_SIZE: usize = 256 * 1024;
    let mut row = Vec::with_capacity(data.len() / CHUNK_SIZE + 1);
    // ar_tx:chunk_binary/2 uses a strict < base case, retaining a final empty
    // chunk for exact multiples (including an empty transaction).
    for start in (0..=data.len() / CHUNK_SIZE).map(|index| index * CHUNK_SIZE) {
        let end = (start + CHUNK_SIZE).min(data.len());
        row.push((
            hash_leaf(&sha256(&[&data[start..end]]), &note(end as u128)),
            end as u128,
        ));
    }
    merkle_root(row).expect("inline data always has a leaf")
}

fn merkle_root(mut row: Vec<([u8; 32], u128)>) -> Option<[u8; 32]> {
    while row.len() > 1 {
        let count = row.len();
        for index in 0..count.div_ceil(2) {
            let left = row[index * 2];
            row[index] = if index * 2 + 1 < count {
                let right = row[index * 2 + 1];
                (hash_branch(&left.0, &right.0, &note(left.1)), right.1)
            } else {
                left
            };
        }
        row.truncate(count.div_ceil(2));
    }
    row.first().map(|(root, _)| *root)
}

fn note(value: u128) -> [u8; 32] {
    let mut note = [0; 32];
    note[16..].copy_from_slice(&value.to_be_bytes());
    note
}

pub(super) fn verify_rsa_pss(
    owner: &[u8],
    signature: &[u8],
    payload: &[u8],
    label: &str,
) -> Result<()> {
    verify_rsa_pss_digest(owner, signature, &sha256(&[payload]), false, label)
}

fn verify_rsa_pss_digest(
    owner: &[u8],
    signature: &[u8],
    digest: &[u8; 32],
    legacy: bool,
    label: &str,
) -> Result<()> {
    ensure!(
        owner.len() <= 512 && signature.len() <= 512,
        "RSA {label} key or signature exceeds protocol limit"
    );
    let modulus = BigUint::from_bytes_be(owner);
    let bits = modulus.bits() as usize;
    let public_len = bits.div_ceil(8);
    let encoded_len = if legacy { bits / 8 } else { public_len };
    ensure!(
        encoded_len >= 34 && signature.len() == public_len,
        "invalid RSA {label} signature length"
    );
    let number = BigUint::from_bytes_be(signature);
    ensure!(number < modulus, "RSA {label} signature exceeds modulus");
    let recovered = number
        .modpow(&BigUint::from(65_537u32), &modulus)
        .to_bytes_be();
    ensure!(
        recovered.len() <= encoded_len,
        "RSA {label} encoded message exceeds historical width"
    );
    let mut encoded = vec![0; encoded_len];
    encoded[encoded_len - recovered.len()..].copy_from_slice(&recovered);
    ensure!(
        encoded[encoded_len - 1] == 0xbc,
        "invalid RSA {label} PSS trailer"
    );
    let db_len = encoded_len - 33;
    let (db, tail) = encoded.split_at_mut(db_len);
    let hash = &tail[..32];
    for (counter, block) in db.chunks_mut(32).enumerate() {
        let mask = sha256(&[hash, &(counter as u32).to_be_bytes()]);
        for (byte, mask) in block.iter_mut().zip(mask) {
            *byte ^= mask;
        }
    }
    // Match rsa_pss:normalize_to_key_size/2 exactly, including its 0 => 0xff
    // mask and historical floor/ceil byte widths. Salt length is discovered,
    // not guessed by retrying a handful of fixed-salt library verifiers.
    let significant = (bits - 1) & 7;
    if significant != 0 {
        db[0] &= 0xff >> (8 - significant);
    }
    let separator = db
        .iter()
        .position(|byte| *byte != 0)
        .context("RSA PSS salt separator missing")?;
    ensure!(db[separator] == 1, "invalid RSA {label} PSS padding");
    let expected = sha256(&[&[0; 8], digest, &db[separator + 1..]]);
    ensure!(hash == expected, "{label} signature verification failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn fixtures() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/protocol-transactions.json")).unwrap()
    }

    #[test]
    fn verifies_all_rsa_preimages_and_signed_metadata() {
        let fixtures = fixtures();
        for case in fixtures["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| !case["transaction"]["owner"].as_str().unwrap().is_empty())
        {
            let mut transaction = decode_transaction(case["transaction"].clone()).unwrap();
            let height = case["height"].as_u64().unwrap();
            let verified = verify_transaction(&transaction, &transaction.id, height).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD.encode(&verified.metadata.owner_address),
                case["owner_address"]
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(verified.metadata.data_root.as_ref().unwrap()),
                case["data_root"]
            );
            assert_eq!(verified.inline_data.is_some(), transaction.format == 1);
            if case["name"] == "format1-modern-width-boundary" {
                assert!(
                    verify_transaction(&transaction, &transaction.id, FORK_2_4_HEIGHT).is_err()
                );
            }
            if case["name"] == "format2-rsa-short-signed-root" {
                assert!(
                    verify_transaction(&transaction, &transaction.id, FORK_2_0_HEIGHT).is_err()
                );
            }
            if case["name"] == "format1-raw-variable-salt" {
                assert_eq!(
                    verified.metadata.quantity.as_deref(),
                    Some("9007199254740993")
                );
                assert_eq!(
                    verified.metadata.content_type.as_deref(),
                    Some("text/plain")
                );
                assert_eq!(verified.metadata.content_encoding.as_deref(), Some("gzip"));
                assert_eq!(
                    verified.metadata.tags[4],
                    (b"\0raw".to_vec(), b"\xff\0".to_vec())
                );
                assert_eq!(
                    verified.inline_data.as_deref(),
                    Some(b"historical inline data\n".as_slice())
                );
                transaction.tags.swap(0, 1);
                assert!(verify_transaction(&transaction, &transaction.id, height).is_err());
                transaction.tags.swap(0, 1);
            }
            if transaction.format == 1 {
                let old_data =
                    std::mem::replace(&mut transaction.data, URL_SAFE_NO_PAD.encode(b"changed"));
                assert!(verify_transaction(&transaction, &transaction.id, height).is_err());
                transaction.data = old_data;
            }
            if transaction.denomination > 0 {
                assert!(
                    verify_transaction(&transaction, &transaction.id, FORK_2_6_HEIGHT - 1).is_err()
                );
                let old = transaction.denomination;
                transaction.denomination = 0;
                assert!(verify_transaction(&transaction, &transaction.id, height).is_err());
                transaction.denomination = old;
            }
            transaction.reward = "999999".to_owned();
            assert!(verify_transaction(&transaction, &transaction.id, height).is_err());
        }
    }

    #[test]
    fn recovers_compressed_ecdsa_owner_and_rejects_noncanonical_signatures() {
        let fixtures = fixtures();
        for case in fixtures["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["transaction"]["owner"] == "")
        {
            let mut transaction = decode_transaction(case["transaction"].clone()).unwrap();
            let height = case["height"].as_u64().unwrap();
            let verified = verify_transaction(&transaction, &transaction.id, height).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD.encode(&verified.metadata.owner_public_key),
                "A6W_3e2WurFBBP-ZUIdsOpqxwVcnvNiJFG-xcQ_9odjl"
            );
            assert_eq!(
                URL_SAFE_NO_PAD.encode(&verified.metadata.owner_address),
                "Z7RxkVjLHgAniUGeEpjnaLuSYEK5RKk2Uij497DawmQ"
            );
            assert!(verify_transaction(&transaction, &transaction.id, FORK_2_9_HEIGHT).is_err());
            assert!(
                verify_transaction(&transaction, &URL_SAFE_NO_PAD.encode([0; 32]), height).is_err()
            );
            let signature = decode_b64(&transaction.signature, "signature").unwrap();
            let mut invalid = signature.clone();
            invalid[64] = 4;
            transaction.signature = URL_SAFE_NO_PAD.encode(&invalid);
            transaction.id = URL_SAFE_NO_PAD.encode(sha256(&[&invalid]));
            assert!(verify_transaction(&transaction, &transaction.id, height).is_err());

            let order = BigUint::parse_bytes(
                b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                16,
            )
            .unwrap();
            let high_s = (order - BigUint::from_bytes_be(&signature[32..64])).to_bytes_be();
            invalid.copy_from_slice(&signature);
            invalid[32..64].fill(0);
            invalid[64 - high_s.len()..64].copy_from_slice(&high_s);
            invalid[64] ^= 1;
            transaction.signature = URL_SAFE_NO_PAD.encode(&invalid);
            transaction.id = URL_SAFE_NO_PAD.encode(sha256(&[&invalid]));
            assert!(verify_transaction(&transaction, &transaction.id, height).is_err());

            // Recovery alone cannot bind the sender: an altered preimage can
            // recover another valid key. These records require trusted origin.
            transaction = decode_transaction(case["transaction"].clone()).unwrap();
            transaction.reward = "1".to_owned();
            let altered = verify_transaction(&transaction, &transaction.id, height).unwrap();
            assert_ne!(
                altered.metadata.owner_address,
                verified.metadata.owner_address
            );
        }
    }

    #[test]
    fn accepts_empty_data_without_accepting_inconsistent_format2_headers() {
        let value =
            serde_json::from_str(include_str!("../tests/fixtures/empty-transaction.json")).unwrap();
        let mut transaction = decode_transaction(value).unwrap();
        let verified = verify_transaction(&transaction, &transaction.id, FORK_2_6_HEIGHT).unwrap();
        assert_eq!(verified.inline_data, Some(Vec::new()));
        assert_eq!(verified.metadata.data_size, 0);
        assert_eq!(verified.metadata.data_root, Some(Vec::new()));
        transaction.data_root = URL_SAFE_NO_PAD.encode([1; 32]);
        assert!(verify_transaction(&transaction, &transaction.id, FORK_2_6_HEIGHT).is_err());
        transaction.data_root.clear();
        transaction.data_size = "1".to_owned();
        assert!(verify_transaction(&transaction, &transaction.id, FORK_2_6_HEIGHT).is_err());
        transaction.data_size = "0".to_owned();
        transaction.data = URL_SAFE_NO_PAD.encode(b"not empty");
        assert!(verify_transaction(&transaction, &transaction.id, FORK_2_6_HEIGHT).is_err());
    }

    #[test]
    fn preserves_official_chunk_splits_empty_leaf_and_odd_rows() {
        for case in fixtures()["chunk_roots"].as_array().unwrap() {
            let data = vec![b'x'; case["size"].as_u64().unwrap() as usize];
            assert_eq!(
                URL_SAFE_NO_PAD.encode(inline_data_root(&data)),
                case["root"]
            );
        }
    }

    #[test]
    fn mainnet_genesis_requires_pinned_records() {
        let snapshot: Vec<Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/mainnet-genesis-transactions.json"
        ))
        .unwrap();
        let mut objects: Vec<_> = snapshot
            .iter()
            .map(|value| {
                let transaction = decode_transaction(value.clone()).unwrap();
                verify_transaction(&transaction, &transaction.id, 0)
                    .unwrap()
                    .metadata
            })
            .collect();
        let mut block = BlockHeader {
            height: 0,
            indep_hash: "7wIU7KolICAjClMlcZ38LZzshhI7xGkm2tDCJR7Wvhe3ESUo2-Z4-y0x1uaglRJE"
                .to_owned(),
            txs: objects
                .iter()
                .map(|object| URL_SAFE_NO_PAD.encode(&object.id))
                .collect(),
            block_size: "0".to_owned(),
            weave_size: "0".to_owned(),
            tx_root: "P_OiqMNN1s4ltcaq0HXb9VFos_Zz6LFjM8ogUG0vJek".to_owned(),
            ..BlockHeader::default()
        };
        objects.reverse();
        verify_block_data_root(&block, &mut objects).unwrap();

        // Empty tag boundaries preserve the v1 signature but change indexed metadata.
        let original = objects[0].clone();
        let mut changed = snapshot[0].clone();
        changed
            .as_object_mut()
            .unwrap()
            .entry("tags")
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name": "", "value": ""}));
        let transaction = decode_transaction(changed).unwrap();
        objects[0] = verify_transaction(&transaction, &transaction.id, 0)
            .unwrap()
            .metadata;
        assert!(verify_block_data_root(&block, &mut objects).is_err());
        objects[0] = original;
        objects[0].data_root.as_mut().unwrap()[0] ^= 1;
        assert!(verify_block_data_root(&block, &mut objects).is_err());
        objects[0].data_root.as_mut().unwrap()[0] ^= 1;
        block.height = 1;
        assert!(verify_block_data_root(&block, &mut objects).is_err());
        block.height = 0;
        let genesis_hash = std::mem::take(&mut block.indep_hash);
        assert!(verify_block_data_root(&block, &mut objects).is_err());
        block.indep_hash = genesis_hash;
        objects.pop();
        block.txs.pop();
        assert!(verify_block_data_root(&block, &mut objects).is_err());
    }

    #[tokio::test]
    async fn block_reconstruction_overlaps_fetches_and_preserves_verification() {
        use axum::{Router, response::IntoResponse};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let cases = fixtures();
        let names = [
            "public-format1-height34",
            "format1-raw-variable-salt",
            "format1-modern-width-boundary",
            "format2-rsa-short-signed-root",
        ];
        let height = FORK_2_4_HEIGHT + 1;
        let mut responses = std::collections::HashMap::new();
        let mut objects = Vec::new();
        let mut ids = Vec::new();
        for name in names {
            let value = cases["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap()["transaction"]
                .clone();
            let transaction = decode_transaction(value.clone()).unwrap();
            objects.push(
                verify_transaction(&transaction, &transaction.id, height)
                    .unwrap()
                    .metadata,
            );
            ids.push(transaction.id.clone());
            responses.insert(format!("/tx/{}", transaction.id), value);
        }
        let first = objects[0].clone();
        objects.sort_unstable_by(|a, b| (a.format, &a.id).cmp(&(b.format, &b.id)));
        let mut size = 0;
        let leaves = objects
            .iter()
            .map(|object| {
                size += object.data_size;
                (
                    hash_leaf(object.data_root.as_deref().unwrap(), &note(size)),
                    size,
                )
            })
            .collect();
        let root = URL_SAFE_NO_PAD.encode(merkle_root(leaves).unwrap());
        let block = || BlockHeader {
            height,
            txs: ids.clone(),
            block_size: size.to_string(),
            tx_root: root.clone(),
            ..BlockHeader::default()
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mode = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&mode);
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let value = responses.get(uri.path()).cloned();
            let barrier = Arc::clone(&barrier);
            let mode = Arc::clone(&observed);
            async move {
                let Some(mut value) = value else {
                    return axum::http::StatusCode::NOT_FOUND.into_response();
                };
                barrier.wait().await;
                match mode.load(Ordering::Relaxed) {
                    1 => value["signature"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0; 512])),
                    2 => std::future::pending::<()>().await,
                    _ => {}
                }
                value.to_string().into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = crate::Gateway::new(
            crate::Config::new(
                &url,
                &url,
                vec![url.clone()],
                std::time::Duration::from_secs(2),
                1,
                2 * 1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let (_, actual) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            gateway.verify_block_transactions(block(), vec![first.clone()], 0, None),
        )
        .await
        .expect("transaction fetches did not overlap")
        .unwrap();
        assert_eq!(actual, objects);
        let mut wrong_root = block();
        wrong_root.tx_root = URL_SAFE_NO_PAD.encode([0; 32]);
        assert!(
            gateway
                .verify_block_transactions(wrong_root, vec![first.clone()], 0, None)
                .await
                .is_err()
        );
        mode.store(1, Ordering::Relaxed);
        assert!(
            gateway
                .verify_block_transactions(block(), vec![first.clone()], 0, None)
                .await
                .is_err()
        );
        mode.store(2, Ordering::Relaxed);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                gateway.verify_block_transactions(block(), vec![first], 0, None),
            )
            .await
            .is_err()
        );
        server.abort();
    }

    #[tokio::test]
    async fn concurrent_chunked_responses_share_one_byte_budget() {
        use axum::{
            Router,
            body::{Body, Bytes},
            response::Response,
        };
        use std::sync::atomic::AtomicUsize;

        let app = Router::new().fallback(|| async {
            Response::new(Body::from_stream(futures_util::stream::iter([Ok::<
                _,
                std::io::Error,
            >(
                Bytes::from_static(b"{}     "),
            )])))
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        for (limit, accepted) in [(14, 2), (13, 1)] {
            let budget = AtomicUsize::new(limit);
            let read = || async {
                let response = client.get(&url).send().await.unwrap();
                crate::read_json_response_with_limit::<Value>(response, 14, &budget, None).await
            };
            let (left, right) = tokio::join!(read(), read());
            assert_eq!(
                usize::from(left.is_ok()) + usize::from(right.is_ok()),
                accepted
            );
        }
        server.abort();
    }

    #[test]
    fn legacy_field_interpretation_cannot_change_authenticated_payload() {
        let fixtures = fixtures();
        let case = fixtures["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "format1-raw-variable-salt")
            .unwrap();
        let height = case["height"].as_u64().unwrap();
        let mut transaction = decode_transaction(case["transaction"].clone()).unwrap();
        let original = verify_transaction(&transaction, &transaction.id, height).unwrap();
        let mut block = BlockHeader {
            height,
            txs: vec![transaction.id.clone()],
            block_size: original.metadata.data_size.to_string(),
            tx_root: URL_SAFE_NO_PAD.encode(hash_leaf(
                original.metadata.data_root.as_deref().unwrap(),
                &note(original.metadata.data_size),
            )),
            ..BlockHeader::default()
        };
        let mut objects = [original.metadata];
        verify_block_data_root(&block, &mut objects).unwrap();

        // Re-split a tag name/value without changing the concatenated preimage.
        let tag = &mut transaction.tags[2];
        let mut name = decode_b64(&tag.name, "tag name").unwrap();
        let mut value = decode_b64(&tag.value, "tag value").unwrap();
        value.insert(0, name.pop().unwrap());
        tag.name = URL_SAFE_NO_PAD.encode(&name);
        tag.value = URL_SAFE_NO_PAD.encode(&value);
        let interpreted = verify_transaction(&transaction, &transaction.id, height).unwrap();
        assert_ne!(interpreted.metadata.tags, objects[0].tags);
        objects[0] = interpreted.metadata;
        verify_block_data_root(&block, &mut objects).unwrap();

        // Move "900" out of the canonical quantity into data. Signature and ID
        // still verify, but the payload boundary is no longer the block's.
        let mut data = decode_b64(&transaction.data, "data").unwrap();
        data.extend_from_slice(&transaction.quantity.as_bytes()[..3]);
        transaction.data = URL_SAFE_NO_PAD.encode(data);
        transaction.quantity = transaction.quantity[3..].to_owned();
        let substituted = verify_transaction(&transaction, &transaction.id, height).unwrap();
        assert_ne!(substituted.metadata.data_root, objects[0].data_root);
        objects[0] = substituted.metadata;
        assert!(verify_block_data_root(&block, &mut objects).is_err());
        // Matching the attacker's size is insufficient: the trusted root differs.
        block.block_size = objects[0].data_size.to_string();
        assert!(verify_block_data_root(&block, &mut objects).is_err());
    }

    #[test]
    fn block_roots_preserve_record_order_empty_leaves_and_fork_padding() {
        let fixtures = fixtures();
        let legacy = fixtures["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == "format1-modern-width-boundary")
            .unwrap();
        let legacy = decode_transaction(legacy["transaction"].clone()).unwrap();
        let empty = decode_transaction(
            serde_json::from_str(include_str!("../tests/fixtures/empty-transaction.json")).unwrap(),
        )
        .unwrap();
        for height in [FORK_2_5_HEIGHT - 1, FORK_2_5_HEIGHT] {
            let legacy = verify_transaction(&legacy, &legacy.id, height)
                .unwrap()
                .metadata;
            let empty = verify_transaction(&empty, &empty.id, height)
                .unwrap()
                .metadata;
            assert!(legacy.id > empty.id);
            let size = legacy.data_size;
            let leaf = hash_leaf(legacy.data_root.as_deref().unwrap(), &note(size));
            let (root, block_size) = if height < FORK_2_5_HEIGHT {
                (
                    hash_branch(&leaf, &hash_leaf(&[], &note(size)), &note(size)),
                    size,
                )
            } else {
                let padding = hash_leaf(&[], &note(MAX_CHUNK_SIZE));
                let left = hash_branch(&leaf, &padding, &note(size));
                (
                    hash_branch(&left, &padding, &note(MAX_CHUNK_SIZE)),
                    MAX_CHUNK_SIZE,
                )
            };
            let block = BlockHeader {
                height,
                txs: vec![
                    URL_SAFE_NO_PAD.encode(&empty.id),
                    URL_SAFE_NO_PAD.encode(&legacy.id),
                ],
                block_size: block_size.to_string(),
                tx_root: URL_SAFE_NO_PAD.encode(root),
                ..BlockHeader::default()
            };
            let mut objects = [empty, legacy];
            verify_block_data_root(&block, &mut objects).unwrap();
            // Membership and the set of roots are unchanged, but their ID
            // associations are swapped. A root-set-only check would miss this.
            let (left, right) = objects.split_at_mut(1);
            std::mem::swap(&mut left[0].data_root, &mut right[0].data_root);
            std::mem::swap(&mut left[0].data_size, &mut right[0].data_size);
            assert!(verify_block_data_root(&block, &mut objects).is_err());
        }
    }

    #[test]
    fn accepts_variable_pss_salt_and_respects_historical_width() {
        let fixture = &fixtures()["historical_pss"];
        let owner = decode_b64(fixture["owner"].as_str().unwrap(), "owner").unwrap();
        let signature = decode_b64(fixture["signature"].as_str().unwrap(), "signature").unwrap();
        let payload = decode_b64(fixture["payload"].as_str().unwrap(), "payload").unwrap();
        verify_rsa_pss(&owner, &signature, &payload, "fixture").unwrap();
        assert!(
            verify_rsa_pss_digest(&owner, &signature, &sha256(&[&payload]), true, "fixture")
                .is_err()
        );
        assert!(verify_rsa_pss(&owner, &signature, b"changed", "fixture").is_err());
        assert!(verify_rsa_pss(&owner, &owner, &payload, "fixture").is_err());
        assert!(verify_rsa_pss(&[1; 513], &signature, &payload, "fixture").is_err());
    }

    #[test]
    fn rejects_malformed_json_instead_of_coercing_or_dropping_fields() {
        let fixtures = fixtures();
        let value = fixtures["transactions"][1]["transaction"].clone();
        for bad in [
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!("-1"),
            serde_json::json!("1e3"),
        ] {
            let mut malformed = value.clone();
            malformed["quantity"] = bad;
            assert!(decode_transaction(malformed).is_err());
        }
        let mut malformed = value.clone();
        malformed["denomination"] = serde_json::json!("0");
        assert!(decode_transaction(malformed).is_err());
        let mut malformed = value.clone();
        malformed["tags"][0]["value"] = Value::Null;
        assert!(decode_transaction(malformed).is_err());
        let mut missing_data = value;
        missing_data.as_object_mut().unwrap().remove("data");
        assert!(decode_transaction(missing_data).is_err());
        let mut missing_size = fixtures["transactions"][3]["transaction"].clone();
        missing_size.as_object_mut().unwrap().remove("data_size");
        assert!(decode_transaction(missing_size).is_err());
    }
}
