use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use std::collections::HashMap;
use tokio::time::timeout;

use crate::{
    BundleItems, CONSENSUS_DEPTH, Gateway, MAX_BUNDLE_DEPTH, NodeInfo,
    database::{BlockStore, BundleLocation, Checkpoint, IndexBlock, ObjectMetadata},
    decode_b64, endpoint, parse_u128, require_bundle_tags, verify_data_item,
};

#[derive(Debug, Serialize)]
pub struct ImportSummary {
    pub start_height: u64,
    pub end_height: u64,
    pub imported_blocks: u64,
    pub imported_through: Option<u64>,
    pub checkpoint_height: u64,
    pub checkpoint_hash: String,
}

#[derive(Debug, Serialize)]
pub struct MetadataSummary {
    pub start_height: u64,
    pub end_height: u64,
    pub imported_blocks: u64,
    pub imported_transactions: u64,
}

#[derive(Debug, Serialize)]
pub struct BundleSummary {
    pub start_height: u64,
    pub end_height: u64,
    pub imported_roots: u64,
    pub imported_occurrences: u64,
}

pub async fn import_range(
    gateway: &Gateway,
    store: &mut BlockStore,
    start: u64,
    end: u64,
) -> Result<ImportSummary> {
    ensure!(start <= end, "invalid import range");
    let coverage_start = start.saturating_sub(1);
    let source = gateway.config.trusted_node_url.as_str();
    let deadline = gateway.config.request_timeout;
    let state = timeout(deadline, async {
        let existing = store.state().await?;
        if let Some(state) = &existing {
            ensure!(
                state.start_height == coverage_start,
                "import start does not match stored range"
            );
            ensure!(
                state.source == source,
                "trusted node source does not match stored import"
            );
        }
        let info: NodeInfo = gateway
            .request_optional_json(gateway.client.get(endpoint(source, "info")))
            .await?
            .context("trusted node info is unavailable")?;
        let stable_height = info
            .height
            .checked_sub(CONSENSUS_DEPTH)
            .context("trusted node has no stable block index")?;
        ensure!(
            end <= stable_height,
            "import end is inside the trusted node consensus window"
        );
        let checkpoint = match existing {
            Some(state) => {
                ensure!(
                    state.checkpoint.height <= stable_height,
                    "stored checkpoint is no longer stable at the trusted node"
                );
                verify_checkpoint(gateway, &state.checkpoint).await?;
                if end > state.checkpoint.height {
                    let next = read_checkpoint(gateway, stable_height).await?;
                    verify_checkpoint(gateway, &state.checkpoint).await?;
                    verify_checkpoint(gateway, &next).await?;
                    store
                        .advance_checkpoint(&state.checkpoint, &next, source)
                        .await?;
                    next
                } else {
                    state.checkpoint
                }
            }
            None => read_checkpoint(gateway, stable_height).await?,
        };
        store.initialize(coverage_start, &checkpoint, source).await
    })
    .await
    .context("import initialization timed out")??;

    let mut imported_through = state.imported_through;
    let mut imported_blocks = 0;
    let mut next_height = imported_through
        .map(|height| height.checked_add(1).context("import cursor overflow"))
        .transpose()?
        .unwrap_or(coverage_start);
    while next_height <= end {
        // One overlapping entry links a resumed batch, even for genesis-only coverage.
        let fetch_start = imported_through.unwrap_or(next_height);
        let fetch_end = end.min(fetch_start.saturating_add(255));
        let skip = usize::from(imported_through.is_some());
        let committed = timeout(deadline, async {
            verify_checkpoint(gateway, &state.checkpoint).await?;
            let entries = gateway
                .trusted_block_index(fetch_start, fetch_end)
                .await?
                .context("trusted block index batch is unavailable")?;
            ensure!(
                entries.len() as u64 == fetch_end - fetch_start + 1,
                "trusted block index returned an incomplete batch"
            );
            let mut blocks: Vec<IndexBlock> = Vec::with_capacity(entries.len());
            for (index, entry) in entries.into_iter().enumerate() {
                let hash = decode_b64(&entry.hash, "block hash")?;
                ensure!(hash.len() == 48, "invalid block hash length");
                let tx_root = decode_b64(&entry.tx_root, "block tx_root")?;
                ensure!(
                    matches!(tx_root.len(), 0 | 32),
                    "invalid block tx_root length"
                );
                if let Some(previous) = blocks.last() {
                    ensure!(
                        entry.weave_size >= previous.weave_size,
                        "trusted block index weave size decreased"
                    );
                }
                let height = fetch_start + index as u64;
                if height == state.checkpoint.height {
                    ensure!(
                        hash == state.checkpoint.hash,
                        "batch disagrees with the pinned checkpoint"
                    );
                }
                blocks.push(IndexBlock {
                    height,
                    hash,
                    previous_hash: blocks.last().map(|previous| previous.hash.clone()),
                    tx_root,
                    weave_size: entry.weave_size,
                });
            }
            verify_checkpoint(gateway, &state.checkpoint).await?;
            store
                .commit_batch(&blocks[skip..], &state.checkpoint, source)
                .await?;
            Ok::<_, anyhow::Error>((blocks.len() - skip) as u64)
        })
        .await
        .with_context(|| format!("block index batch {fetch_start}..={fetch_end} timed out"))??;
        imported_blocks += committed;
        imported_through = Some(fetch_end);
        next_height = fetch_end.checked_add(1).context("import cursor overflow")?;
    }

    Ok(ImportSummary {
        start_height: start,
        end_height: end,
        imported_blocks,
        imported_through,
        checkpoint_height: state.checkpoint.height,
        checkpoint_hash: URL_SAFE_NO_PAD.encode(&state.checkpoint.hash),
    })
}

pub async fn import_metadata(
    gateway: &Gateway,
    store: &mut BlockStore,
    start: u64,
    end: u64,
) -> Result<MetadataSummary> {
    ensure!(start <= end, "invalid metadata import range");
    let deadline = gateway.config.request_timeout;
    let state = timeout(deadline, store.state())
        .await
        .context("metadata import initialization timed out")??
        .context("block index is not initialized")?;
    ensure!(
        state.source == gateway.config.trusted_node_url,
        "trusted node source does not match stored import"
    );
    let imported_through = state
        .imported_through
        .context("block index has no imported canonical coverage")?;
    ensure!(
        start >= state.start_height && end <= imported_through,
        "metadata range {start}..={end} is outside imported block-index coverage {}..={imported_through}",
        state.start_height
    );

    let mut imported_blocks = 0;
    loop {
        let blocks = timeout(deadline, store.pending_metadata_blocks(start, end, 32))
            .await
            .context("pending block metadata query timed out")??;
        if blocks.is_empty() {
            break;
        }
        for block in blocks {
            timeout(deadline, async {
                let header = gateway.verified_block(&block).await?;
                let transaction_ids = header
                    .txs
                    .iter()
                    .map(|id| {
                        let id = decode_b64(id, "block transaction ID")?;
                        ensure!(id.len() == 32, "invalid block transaction ID length");
                        Ok(id)
                    })
                    .collect::<Result<Vec<_>>>()?;
                store
                    .record_block_metadata(&block, header.timestamp, &transaction_ids)
                    .await
            })
            .await
            .with_context(|| format!("block metadata at height {} timed out", block.height))?
            .with_context(|| format!("importing block metadata at height {}", block.height))?;
            imported_blocks += 1;
        }
    }

    let mut imported_transactions = 0;
    // Keep only one fully authenticated block, without inline payloads, across
    // resumable four-object commits. Partial root reconstructions never enter it.
    let mut authenticated_height = None;
    let mut authenticated_objects = HashMap::<Vec<u8>, ObjectMetadata>::new();
    loop {
        let pending = timeout(deadline, store.pending_transactions(start, end, 4))
            .await
            .context("pending transaction metadata query timed out")??;
        if pending.is_empty() {
            break;
        }
        let batch_count = pending.len() as u64;
        timeout(deadline, async {
            let mut pending = pending.into_iter();
            let fetch = |transaction: Option<(Vec<u8>, u64)>| {
                let cached = transaction.as_ref().is_some_and(|(id, height)| {
                    authenticated_height == Some(*height) && authenticated_objects.contains_key(id)
                });
                async move {
                    let Some((id, height)) = transaction else {
                        return Ok(None);
                    };
                    if cached {
                        return Ok(Some((id, height, None)));
                    }
                    let encoded_id = URL_SAFE_NO_PAD.encode(&id);
                    let mut remaining = usize::MAX;
                    let (_, verified) = gateway
                        .fetch_transaction(&encoded_id, height, &mut remaining)
                        .await
                        .with_context(|| format!("importing transaction metadata {encoded_id}"))?;
                    Ok::<_, anyhow::Error>(Some((
                        id,
                        height,
                        Some((verified.metadata, usize::MAX - remaining)),
                    )))
                }
            };
            // Inline futures are dropped together on errors, timeout, or cancellation.
            let (first, second, third, fourth) = tokio::try_join!(
                fetch(pending.next()),
                fetch(pending.next()),
                fetch(pending.next()),
                fetch(pending.next()),
            )?;
            let mut objects = Vec::with_capacity(4);
            for (id, height, fetched) in [first, second, third, fourth].into_iter().flatten() {
                if authenticated_height == Some(height)
                    && let Some(object) = authenticated_objects.remove(&id)
                {
                    objects.push(object);
                    continue;
                }
                let (object, fetched_bytes) =
                    fetched.context("verified block metadata is missing")?;
                if object.format != Some(1) || object.denomination != Some(0) {
                    objects.push(object);
                    continue;
                }
                let header = if let Some((previous, block)) = store.block_pair(height).await? {
                    let header = gateway.verified_block(&block).await?;
                    ensure!(
                        block.weave_size.checked_sub(previous.weave_size)
                            == Some(parse_u128(&header.block_size, "block size")?),
                        "block size does not match trusted weave geometry"
                    );
                    header
                } else {
                    // The coverage boundary/genesis may have no stored predecessor.
                    let entries = gateway
                        .trusted_block_index(height.saturating_sub(1), height)
                        .await?
                        .context("trusted transaction block index is unavailable")?;
                    let block = entries
                        .last()
                        .context("missing trusted transaction block")?;
                    let entry = crate::BlockIndexEntry {
                        hash: block.hash.clone(),
                        tx_root: block.tx_root.clone(),
                        weave_size: block.weave_size.to_string(),
                    };
                    let encoded_id = URL_SAFE_NO_PAD.encode(&id);
                    let header = gateway
                        .authenticate_block(&entry, height, Some(&encoded_id))
                        .await?;
                    let previous_size = if height == 0 {
                        0
                    } else {
                        entries[0].weave_size
                    };
                    ensure!(
                        block.weave_size.checked_sub(previous_size)
                            == Some(parse_u128(&header.block_size, "block size")?),
                        "block size does not match trusted weave geometry"
                    );
                    if height > 0 {
                        ensure!(
                            header.previous_block == entries[0].hash,
                            "block predecessor does not match trusted index"
                        );
                    }
                    header
                };
                let verified = gateway
                    .verify_block_transactions(&header, object, fetched_bytes)
                    .await?;
                authenticated_objects = verified
                    .into_iter()
                    .map(|object| (object.id.clone(), object))
                    .collect();
                authenticated_height = Some(height);
                objects.push(
                    authenticated_objects
                        .remove(&id)
                        .context("verified transaction is missing")?,
                );
            }
            store.record_objects(&objects).await
        })
        .await
        .context("transaction metadata batch timed out")??;
        imported_transactions += batch_count;
    }

    if imported_blocks > 0 || imported_transactions > 0 {
        timeout(deadline, store.analyze_metadata())
            .await
            .context("metadata statistics refresh timed out")??;
    }
    Ok(MetadataSummary {
        start_height: start,
        end_height: end,
        imported_blocks,
        imported_transactions,
    })
}

pub async fn import_bundles(
    gateway: &Gateway,
    store: &mut BlockStore,
    start: u64,
    end: u64,
) -> Result<BundleSummary> {
    ensure!(start <= end, "invalid bundle import range");
    let deadline = gateway.config.request_timeout;
    timeout(deadline, async {
        let state = store
            .state()
            .await?
            .context("block index is not initialized")?;
        ensure!(
            state.source == gateway.config.trusted_node_url,
            "trusted node source does not match stored import"
        );
        let imported_through = state
            .imported_through
            .context("block index has no imported canonical coverage")?;
        ensure!(
            start >= state.start_height && end <= imported_through,
            "bundle range is outside imported block-index coverage"
        );
        ensure!(
            store
                .pending_metadata_blocks(start, end, 1)
                .await?
                .is_empty()
                && store.pending_transactions(start, end, 1).await?.is_empty(),
            "bundle range has incomplete transaction metadata; import transactions first"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("bundle import initialization timed out")??;

    let mut summary = BundleSummary {
        start_height: start,
        end_height: end,
        imported_roots: 0,
        imported_occurrences: 0,
    };
    loop {
        let pending = timeout(deadline, store.pending_bundles(start, end, 1))
            .await
            .context("pending bundle query timed out")??;
        let Some((root_id, height)) = pending.into_iter().next() else {
            break;
        };
        let encoded_id = URL_SAFE_NO_PAD.encode(&root_id);
        let (root, tags) = timeout(deadline, gateway.retrieve_direct_with_tags(&encoded_id))
            .await
            .with_context(|| format!("retrieving bundle {encoded_id} timed out"))??;
        ensure!(
            root.block_height == height,
            "bundle root canonical height changed"
        );
        require_bundle_tags(&tags)?;
        let root_id = root_id
            .as_slice()
            .try_into()
            .context("invalid bundle root ID")?;
        let mut traversal = BundleTraversal::new(&root.bytes, root_id)?;
        loop {
            let (count, complete) = timeout(deadline, async {
                let mut objects = Vec::with_capacity(256);
                let mut locations = Vec::with_capacity(256);
                let mut complete = false;
                while locations.len() < 256 {
                    let Some((object, location)) = traversal.next().await? else {
                        complete = true;
                        break;
                    };
                    objects.push(object);
                    locations.push(location);
                }
                store
                    .commit_bundle_batch(root_id, &objects, &locations, complete)
                    .await?;
                Ok::<_, anyhow::Error>((locations.len() as u64, complete))
            })
            .await
            .with_context(|| format!("indexing bundle {encoded_id} batch timed out"))?
            .with_context(|| format!("indexing bundle {encoded_id}"))?;
            summary.imported_occurrences += count;
            if complete {
                break;
            }
        }
        summary.imported_roots += 1;
    }
    if summary.imported_roots > 0 {
        timeout(deadline, store.analyze_metadata())
            .await
            .context("bundle statistics refresh timed out")??;
    }
    Ok(summary)
}

struct BundleFrame<'a> {
    items: BundleItems<'a>,
    id: [u8; 32],
    item_offset: Option<u128>,
    payload_offset: u128,
    framing_checked: bool,
}

struct BundleTraversal<'a> {
    stack: Vec<BundleFrame<'a>>,
}

impl<'a> BundleTraversal<'a> {
    fn new(root: &'a [u8], root_id: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            stack: vec![BundleFrame {
                items: BundleItems::new(root)?,
                id: *root_id,
                item_offset: None,
                payload_offset: 0,
                framing_checked: false,
            }],
        })
    }

    async fn next(&mut self) -> Result<Option<(ObjectMetadata, BundleLocation)>> {
        while let Some(parent) = self.stack.last_mut() {
            if !parent.framing_checked {
                let mut table = BundleItems::new(parent.items.bundle)?;
                let mut checked = 0;
                while table.next()?.is_some() {
                    checked += 1;
                    if checked % 256 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                parent.framing_checked = true;
            }
            tokio::task::yield_now().await;
            let Some(entry) = parent.items.next()? else {
                self.stack.pop();
                continue;
            };
            let item = verify_data_item(entry.bytes, entry.id)?;
            let root_offset = parent
                .payload_offset
                .checked_add(entry.offset as u128)
                .context("bundle root offset overflow")?;
            let location = BundleLocation {
                id: entry.id.to_vec(),
                parent_id: parent.id.to_vec(),
                parent_offset: parent.item_offset,
                item_offset: entry.offset as u128,
                item_size: entry.bytes.len() as u128,
                data_offset: item.data_offset as u128,
                root_offset,
            };
            if item.is_bundle() {
                let items = BundleItems::new(item.data)?;
                if items.remaining > 0 {
                    ensure!(
                        self.stack.len() < MAX_BUNDLE_DEPTH,
                        "nested bundle exceeds maximum depth {MAX_BUNDLE_DEPTH}"
                    );
                    self.stack.push(BundleFrame {
                        items,
                        id: *entry.id,
                        item_offset: Some(root_offset),
                        payload_offset: root_offset
                            .checked_add(item.data_offset as u128)
                            .context("nested bundle payload offset overflow")?,
                        framing_checked: false,
                    });
                }
            }
            return Ok(Some((item.metadata(entry.id), location)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod bundle_tests {
    use super::*;
    use crate::{
        database::IndexedBundle,
        tests::{encode_bundle, signed_data_item},
        verify_bundle_item, verify_indexed_bundle,
    };

    const BUNDLE_TAGS: &[(&[u8], &[u8])] =
        &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];

    #[tokio::test]
    async fn nested_repeated_occurrences_authenticate_exact_stored_paths() {
        let root_id = [9; 32];
        let data = b"nested repeated payload";
        let (leaf, leaf_id) = signed_data_item(data, &[]);
        let nested_data = encode_bundle(&[&leaf, &leaf]);
        let (nested, nested_id) = signed_data_item(&nested_data, BUNDLE_TAGS);
        let root = encode_bundle(&[&nested, &nested]);
        let mut traversal = BundleTraversal::new(&root, &root_id).unwrap();
        let mut locations = Vec::new();
        while let Some((_, location)) = traversal.next().await.unwrap() {
            locations.push(location);
        }
        assert_eq!(
            locations
                .iter()
                .map(|location| location.id.as_slice())
                .collect::<Vec<_>>(),
            [nested_id, leaf_id, leaf_id, nested_id, leaf_id, leaf_id]
                .iter()
                .map(|id| id.as_slice())
                .collect::<Vec<_>>()
        );
        let payload_start = nested.len() - nested_data.len();
        let second_parent = 160 + nested.len();
        let second_leaf = second_parent + payload_start + 160 + leaf.len();
        assert_eq!(locations[5].root_offset, second_leaf as u128);
        assert_eq!(locations[5].parent_offset, Some(second_parent as u128));
        let indexed = || IndexedBundle {
            root_id: root_id.to_vec(),
            data_size: data.len() as u128,
            locations: vec![locations[3].clone(), locations[5].clone()],
        };
        assert_eq!(
            verify_indexed_bundle(&root, &leaf_id, &indexed())
                .await
                .unwrap()
                .data,
            data
        );
        for field in 0..8 {
            let mut hint = indexed();
            let location = &mut hint.locations[1];
            match field {
                0 => location.item_offset += 1,
                1 => location.root_offset += 1,
                2 => location.parent_offset = Some(0),
                3 => location.data_offset += 1,
                4 => location.item_size += 1,
                5 => location.parent_id[0] ^= 1,
                6 => location.id[0] ^= 1,
                7 => hint.data_size += 1,
                _ => unreachable!(),
            }
            assert!(verify_indexed_bundle(&root, &leaf_id, &hint).await.is_err());
        }
        let mut missing_ancestor = indexed();
        missing_ancestor.locations.remove(0);
        assert!(
            verify_indexed_bundle(&root, &leaf_id, &missing_ancestor)
                .await
                .is_err()
        );
        let mut corrupt_parent = root.clone();
        corrupt_parent[second_parent + 2] ^= 1;
        assert!(
            verify_indexed_bundle(&corrupt_parent, &leaf_id, &indexed())
                .await
                .is_err()
        );
        let mut corrupt_table = root.clone();
        corrupt_table[96] ^= 1;
        assert!(
            verify_indexed_bundle(&corrupt_table, &leaf_id, &indexed())
                .await
                .is_err()
        );

        let mut corrupt_leaf = leaf.clone();
        *corrupt_leaf.last_mut().unwrap() ^= 1;
        let repeated = encode_bundle(&[&corrupt_leaf, &leaf]);
        assert_eq!(
            verify_bundle_item(&repeated, &leaf_id, Some((160 + leaf.len()) as u128))
                .await
                .unwrap()
                .0
                .data,
            data
        );
        assert!(verify_bundle_item(&repeated, &leaf_id, None).await.is_err());
    }

    #[tokio::test]
    async fn valid_prefix_replays_after_a_later_signature_failure() {
        let (leaf, _) = signed_data_item(b"resumable", &[]);
        let mut corrupt = leaf.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut items = vec![leaf.as_slice(); 256];
        items.push(&corrupt);
        let root = encode_bundle(&items);
        let mut first = BundleTraversal::new(&root, &[9; 32]).unwrap();
        let mut replay = BundleTraversal::new(&root, &[9; 32]).unwrap();
        for index in 0..256 {
            let original = first.next().await.unwrap().unwrap();
            assert_eq!(original, replay.next().await.unwrap().unwrap());
            assert_eq!(
                original.1.root_offset,
                (32 + 257 * 64 + index * leaf.len()) as u128
            );
        }
        assert!(first.next().await.is_err());
        assert!(replay.next().await.is_err());
    }

    #[tokio::test]
    async fn malformed_tail_is_rejected_before_yielding_locations() {
        let (leaf, _) = signed_data_item(b"framing", &[]);
        let mut root = encode_bundle(&vec![leaf.as_slice(); 257]);
        root.push(0);
        let mut traversal = BundleTraversal::new(&root, &[9; 32]).unwrap();
        assert!(traversal.next().await.is_err());
    }

    #[tokio::test]
    async fn traversal_accepts_empty_bundles_and_enforces_table_and_depth_bounds() {
        let empty = encode_bundle(&[]);
        assert!(
            BundleTraversal::new(&empty, &[9; 32])
                .unwrap()
                .next()
                .await
                .unwrap()
                .is_none()
        );
        let mut trailing = empty.clone();
        trailing.push(0);
        assert!(BundleTraversal::new(&trailing, &[9; 32]).is_err());
        let mut oversized = empty;
        oversized[31] = 1;
        assert!(BundleTraversal::new(&oversized, &[9; 32]).is_err());

        let (leaf, _) = signed_data_item(b"deep", &[]);
        let mut root = encode_bundle(&[&leaf]);
        for _ in 1..MAX_BUNDLE_DEPTH {
            let (parent, _) = signed_data_item(&root, BUNDLE_TAGS);
            root = encode_bundle(&[&parent]);
        }
        let mut traversal = BundleTraversal::new(&root, &[9; 32]).unwrap();
        for _ in 0..MAX_BUNDLE_DEPTH {
            assert!(traversal.next().await.unwrap().is_some());
        }
        assert!(traversal.next().await.unwrap().is_none());
        let (parent, _) = signed_data_item(&root, BUNDLE_TAGS);
        let too_deep = encode_bundle(&[&parent]);
        let mut traversal = BundleTraversal::new(&too_deep, &[9; 32]).unwrap();
        for _ in 1..MAX_BUNDLE_DEPTH {
            traversal.next().await.unwrap().unwrap();
        }
        assert!(traversal.next().await.is_err());
    }
}

async fn read_checkpoint(gateway: &Gateway, height: u64) -> Result<Checkpoint> {
    let entries = gateway
        .trusted_block_index(height, height)
        .await?
        .context("trusted checkpoint is unavailable")?;
    ensure!(
        entries.len() == 1,
        "trusted checkpoint response is incomplete"
    );
    let hash = decode_b64(&entries[0].hash, "checkpoint block hash")?;
    ensure!(hash.len() == 48, "invalid checkpoint block hash length");
    Ok(Checkpoint { height, hash })
}

async fn verify_checkpoint(gateway: &Gateway, checkpoint: &Checkpoint) -> Result<()> {
    ensure!(
        read_checkpoint(gateway, checkpoint.height).await?.hash == checkpoint.hash,
        "trusted node disagrees with the pinned checkpoint"
    );
    Ok(())
}
