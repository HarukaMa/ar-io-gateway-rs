use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{StreamExt, stream};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time::timeout};

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

#[derive(Debug)]
pub(crate) struct RootFacts {
    pub(crate) block_hash: [u8; 48],
    pub(crate) timestamp: u64,
    pub(crate) transaction_ids: Vec<Vec<u8>>,
    pub(crate) object: ObjectMetadata,
}

impl RootFacts {
    pub(crate) fn heap_bytes(&self) -> usize {
        let ObjectMetadata {
            id,
            kind: _,
            signature,
            anchor,
            owner_address,
            owner_public_key,
            target,
            data_size: _,
            content_type,
            content_encoding,
            signature_type: _,
            format: _,
            quantity,
            reward,
            denomination: _,
            data_root,
            tags,
        } = &self.object;
        let mut bytes = self.transaction_ids.capacity() * std::mem::size_of::<Vec<u8>>();
        for id in &self.transaction_ids {
            bytes = bytes.saturating_add(id.capacity());
        }
        for value in [
            id,
            signature,
            anchor,
            owner_address,
            owner_public_key,
            target,
        ] {
            bytes = bytes.saturating_add(value.capacity());
        }
        for value in [content_type, content_encoding, quantity, reward]
            .into_iter()
            .flatten()
        {
            bytes = bytes.saturating_add(value.capacity());
        }
        bytes = bytes.saturating_add(data_root.as_ref().map_or(0, Vec::capacity));
        bytes = bytes.saturating_add(tags.capacity() * std::mem::size_of::<(Vec<u8>, Vec<u8>)>());
        for (name, value) in tags {
            bytes = bytes
                .saturating_add(name.capacity())
                .saturating_add(value.capacity());
        }
        bytes
    }
}

pub(crate) async fn follow_chain_step(gateway: &Gateway, store: &mut BlockStore) -> Result<bool> {
    let state = store.state().await?;
    ensure!(
        state.as_ref().is_none_or(|state| state.start_height == 0),
        "automatic full-chain indexing requires coverage starting at genesis"
    );
    let info: NodeInfo = gateway
        .get_json(&gateway.config.trusted_node_url, "info")
        .await?;
    let through = state.as_ref().and_then(|state| state.imported_through);
    let backlog = if let Some(through) = through {
        !store
            .pending_metadata_blocks(0, through, 1)
            .await?
            .is_empty()
            || !store.pending_transactions(0, through, 1).await?.is_empty()
    } else {
        false
    };
    let end = if backlog {
        through.unwrap()
    } else {
        through.map_or(255, |height| height.saturating_add(256))
    }
    .min(info.height);
    let summary = import_range(gateway, store, 0, end).await?;
    let pending = store.pending_metadata_blocks(0, end, 1).await?;
    let pending_transaction = store.pending_transactions(0, end, 1).await?;
    let height = pending
        .first()
        .map(|block| block.height)
        .into_iter()
        .chain(pending_transaction.first().map(|(_, height)| *height))
        .min();
    if let Some(height) = height {
        import_metadata(gateway, store, height, height.saturating_add(255).min(end)).await?;
    }
    Ok(summary.imported_blocks > 0 || height.is_some())
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
    let (state, tip) = timeout(deadline, async {
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
        ensure!(end <= info.height, "import end exceeds trusted node height");
        let tip = read_checkpoint(gateway, info.height).await?;
        let checkpoint = match existing {
            Some(state) => {
                ensure!(
                    state.checkpoint.height <= stable_height,
                    "stored checkpoint is no longer stable at the trusted node"
                );
                verify_checkpoint(gateway, &state.checkpoint).await?;
                if let Some(through) = state
                    .imported_through
                    .filter(|height| *height > state.checkpoint.height)
                {
                    let mut ancestor = through.min(info.height);
                    loop {
                        let remote = read_checkpoint(gateway, ancestor).await?;
                        if store.canonical_hash(ancestor).await?.as_deref()
                            == Some(remote.hash.as_slice())
                        {
                            break;
                        }
                        ensure!(
                            ancestor > state.checkpoint.height,
                            "reorg crosses protected checkpoint"
                        );
                        ancestor -= 1;
                    }
                    verify_checkpoint(gateway, &tip).await?;
                    if ancestor < through {
                        store.rewind(ancestor, &state.checkpoint, source).await?;
                    }
                }
                if stable_height > state.checkpoint.height {
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
        let state = store
            .initialize(coverage_start, &checkpoint, source)
            .await?;
        Ok::<_, anyhow::Error>((state, tip))
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
            verify_checkpoint(gateway, &tip).await?;
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

    let mut transaction_store = store.reconnect().await?;
    let (progress, mut updates) = tokio::sync::watch::channel(());
    let headers = Mutex::new(HashMap::new());
    let blocks = async {
        let mut imported = 0;
        loop {
            let blocks = timeout(deadline, store.pending_metadata_blocks(start, end, 256))
                .await
                .context("pending block metadata query timed out")??;
            if blocks.is_empty() {
                break;
            }
            let (sender, mut ready) = mpsc::channel(1);
            let produce = queue_metadata(block_metadata(gateway, blocks, &headers), sender);
            let consume = async {
                while let Some(batch) = ready.recv().await {
                    for header in batch {
                        let (block, timestamp, transaction_ids) = header?;
                        timeout(
                            deadline,
                            store.record_block_metadata(&block, timestamp, &transaction_ids),
                        )
                        .await
                        .with_context(|| {
                            format!("block metadata at height {} timed out", block.height)
                        })??;
                        imported += 1;
                        progress.send_replace(());
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(produce, consume)?;
        }
        drop(progress);
        Ok::<_, anyhow::Error>(imported)
    };
    let transactions = async {
        let mut imported = 0;
        loop {
            updates.borrow_and_update();
            imported +=
                import_pending_transactions(gateway, &mut transaction_store, start, end, &headers)
                    .await?;
            if updates.changed().await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(imported)
    };
    let (imported_blocks, imported_transactions) = tokio::try_join!(blocks, transactions)?;

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

async fn import_pending_transactions(
    gateway: &Gateway,
    store: &mut BlockStore,
    start: u64,
    end: u64,
    headers: &Mutex<HashMap<Vec<u8>, crate::BlockHeader>>,
) -> Result<u64> {
    let deadline = gateway.config.request_timeout;
    let mut imported_transactions = 0;
    let mut authenticated = (None, HashMap::<Vec<u8>, ObjectMetadata>::new());
    let slots = tokio::sync::Semaphore::new(32);
    loop {
        let pending = timeout(deadline, store.pending_transactions(start, end, 256))
            .await
            .context("pending transaction metadata query timed out")??;
        if pending.is_empty() {
            break;
        }
        let last_height = pending.last().unwrap().1;
        let mut groups = std::collections::BTreeMap::<_, Vec<_>>::new();
        for (id, height) in pending {
            groups.entry(height).or_default().push(id);
        }
        let mut jobs = Vec::with_capacity(groups.len());
        for (height, ids) in groups {
            let cached = if authenticated.0 == Some(height) {
                std::mem::take(&mut authenticated.1)
            } else {
                HashMap::new()
            };
            let anchor = timeout(deadline, store.block_pair(height)).await??;
            let anchor = anchor.map(|(previous, block)| {
                let header = headers.lock().unwrap().remove(&block.hash);
                (previous, block, header)
            });
            jobs.push((height, ids, anchor, cached));
        }
        let (sender, mut ready) = mpsc::channel(1);
        let fetched = stream::iter(jobs)
            .map(|(height, ids, anchor, cached)| {
                let slots = &slots;
                async move {
                    timeout(
                        deadline,
                        transaction_metadata(gateway, height, ids, anchor, cached, slots),
                    )
                    .await
                    .with_context(|| format!("transaction metadata at height {height} timed out"))?
                }
            })
            // Eight bounded block reconstructions share 32 HTTP fetch slots.
            .buffer_unordered(8);
        let produce = queue_metadata(fetched, sender);
        let consume = async {
            while let Some(batch) = ready.recv().await {
                let mut objects = Vec::with_capacity(32);
                for result in batch {
                    let (height, ids, mut verified) = result?;
                    for id in ids {
                        objects.push(
                            verified
                                .remove(&id)
                                .context("verified transaction is missing")?,
                        );
                        if objects.len() == 32 {
                            timeout(deadline, store.record_objects(&objects)).await??;
                            imported_transactions += objects.len() as u64;
                            objects.clear();
                        }
                    }
                    // Only the last selected height can straddle the 256-row window.
                    if height == last_height {
                        authenticated = (Some(height), verified);
                    }
                }
                if !objects.is_empty() {
                    timeout(deadline, store.record_objects(&objects)).await??;
                    imported_transactions += objects.len() as u64;
                }
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(produce, consume)?;
    }
    Ok(imported_transactions)
}

async fn queue_metadata<T>(
    entries: impl futures_util::Stream<Item = Result<T>>,
    sender: mpsc::Sender<Vec<Result<T>>>,
) -> Result<()> {
    let batches = entries.ready_chunks(32);
    tokio::pin!(batches);
    while let Some(batch) = batches.next().await {
        let failed = batch.iter().any(Result::is_err);
        if sender.send(batch).await.is_err() || failed {
            break;
        }
    }
    Ok(())
}

async fn transaction_metadata(
    gateway: &Gateway,
    height: u64,
    ids: Vec<Vec<u8>>,
    anchor: Option<(IndexBlock, IndexBlock, Option<crate::BlockHeader>)>,
    mut cached: HashMap<Vec<u8>, ObjectMetadata>,
    slots: &tokio::sync::Semaphore,
) -> Result<(u64, Vec<Vec<u8>>, HashMap<Vec<u8>, ObjectMetadata>)> {
    if ids.iter().all(|id| cached.contains_key(id)) {
        return Ok((height, ids, cached));
    }
    let remaining = std::sync::atomic::AtomicUsize::new(crate::MAX_BLOCK_TRANSACTION_BYTES);
    let fetch = |id: String| {
        let remaining = &remaining;
        async move {
            let _permit = slots
                .acquire()
                .await
                .context("metadata fetch admission closed")?;
            let (_, verified) = gateway.fetch_transaction(&id, height, remaining).await?;
            Ok::<_, anyhow::Error>(verified.metadata)
        }
    };
    let first = fetch(URL_SAFE_NO_PAD.encode(&ids[0])).await?;
    let mut objects = vec![first];
    if objects[0].format != Some(1) || objects[0].denomination != Some(0) {
        let fetched = stream::iter(ids.iter().skip(1))
            .map(|id| fetch(URL_SAFE_NO_PAD.encode(id)))
            .buffer_unordered(32);
        tokio::pin!(fetched);
        while let Some(object) = fetched.next().await {
            objects.push(object?);
        }
    }
    if objects
        .iter()
        .any(|object| object.format == Some(1) && object.denomination == Some(0))
    {
        let header = if let Some((previous, block, header)) = anchor {
            transaction_block(gateway, &previous, &block, header).await?
        } else {
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
            let encoded_id = URL_SAFE_NO_PAD.encode(&ids[0]);
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
        let fetched_bytes = crate::MAX_BLOCK_TRANSACTION_BYTES
            - remaining.load(std::sync::atomic::Ordering::Relaxed);
        let (_, verified) = gateway
            .verify_block_transactions(header, objects, fetched_bytes, Some((slots, &remaining)))
            .await?;
        cached = verified
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect();
    } else {
        cached = objects
            .into_iter()
            .map(|object| (object.id.clone(), object))
            .collect();
    }
    Ok((height, ids, cached))
}

async fn transaction_block(
    gateway: &Gateway,
    previous: &IndexBlock,
    block: &IndexBlock,
    header: Option<crate::BlockHeader>,
) -> Result<crate::BlockHeader> {
    let header = match header {
        Some(header) => header,
        None => gateway.verified_block(block).await?,
    };
    ensure!(
        block.weave_size.checked_sub(previous.weave_size)
            == Some(parse_u128(&header.block_size, "block size")?),
        "block size does not match trusted weave geometry"
    );
    Ok(header)
}

fn retain_transaction_header(
    headers: &Mutex<HashMap<Vec<u8>, crate::BlockHeader>>,
    hash: &[u8],
    header: crate::BlockHeader,
) {
    // Keep only fields used by transaction-root verification.
    let header = crate::BlockHeader {
        indep_hash: header.indep_hash,
        height: header.height,
        txs: header.txs,
        tx_root: header.tx_root,
        block_size: header.block_size,
        weave_size: header.weave_size,
        ..crate::BlockHeader::default()
    };
    let bytes = std::mem::size_of_val(&header)
        + hash.len()
        + header.txs.capacity() * std::mem::size_of::<String>()
        + header.txs.iter().map(String::capacity).sum::<usize>()
        + header.indep_hash.capacity()
        + header.tx_root.capacity()
        + header.block_size.capacity()
        + header.weave_size.capacity();
    if bytes <= 128 * 1024 {
        let mut headers = headers.lock().unwrap();
        if headers.len() < 256 {
            headers.insert(hash.to_vec(), header);
        }
    }
}

fn block_metadata<'a>(
    gateway: &'a Gateway,
    blocks: Vec<IndexBlock>,
    headers: &'a Mutex<HashMap<Vec<u8>, crate::BlockHeader>>,
) -> impl futures_util::Stream<Item = Result<(IndexBlock, u64, Vec<Vec<u8>>)>> + 'a {
    stream::iter(blocks)
        .map(move |block| async move {
            let metadata = timeout(gateway.config.request_timeout, async {
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
                let timestamp = header.timestamp;
                retain_transaction_header(headers, &block.hash, header);
                Ok::<_, anyhow::Error>((timestamp, transaction_ids))
            })
            .await
            .with_context(|| format!("block metadata at height {} timed out", block.height))?
            .with_context(|| format!("importing block metadata at height {}", block.height))?;
            Ok((block, metadata.0, metadata.1))
        })
        .buffer_unordered(32)
}

#[cfg(test)]
mod metadata_tests {
    #[tokio::test]
    async fn metadata_queue_flushes_partial_batch_and_terminates() {
        let (sender, mut ready) = mpsc::channel(1);
        let produce = queue_metadata(stream::iter((0..65).map(Ok)), sender);
        let consume = async {
            let mut received = Vec::new();
            let mut sizes = Vec::new();
            while let Some(batch) = ready.recv().await {
                sizes.push(batch.len());
                for entry in batch {
                    received.push(entry?);
                }
            }
            assert_eq!(sizes, [32, 32, 1]);
            assert_eq!(received, (0..65).collect::<Vec<_>>());
            Ok::<_, anyhow::Error>(())
        };
        timeout(Duration::from_secs(1), async {
            tokio::try_join!(produce, consume)
        })
        .await
        .expect("completed producer left its consumer waiting")
        .unwrap();
    }

    #[tokio::test]
    async fn metadata_queue_flushes_ready_items_before_stalled_tail() {
        let (sender, mut ready) = mpsc::channel(1);
        let entries = stream::iter([Ok(7)]).chain(stream::pending());
        let produce = queue_metadata(entries, sender);
        tokio::pin!(produce);
        timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = &mut produce => panic!("infinite producer finished: {result:?}"),
                batch = ready.recv() => {
                    let batch = batch.unwrap();
                    assert_eq!(batch.len(), 1);
                    assert_eq!(*batch[0].as_ref().unwrap(), 7);
                }
            }
        })
        .await
        .expect("ready metadata was held behind a stalled tail");
    }

    #[tokio::test]
    async fn legacy_block_reuses_fetched_headers_and_rejects_corruption() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let fixture: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../tests/fixtures/mainnet-genesis-transactions.json"
        ))
        .unwrap();
        let seeds: Vec<_> = fixture
            .iter()
            .take(32)
            .map(|value| {
                let tx = crate::transactions::decode_transaction(value.clone()).unwrap();
                crate::transactions::verify_transaction(&tx, &tx.id, 0)
                    .unwrap()
                    .metadata
            })
            .collect();
        let header = crate::BlockHeader {
            height: 0,
            indep_hash: "7wIU7KolICAjClMlcZ38LZzshhI7xGkm2tDCJR7Wvhe3ESUo2-Z4-y0x1uaglRJE"
                .to_owned(),
            txs: fixture
                .iter()
                .map(|value| value["id"].as_str().unwrap().to_owned())
                .collect(),
            block_size: "0".to_owned(),
            weave_size: "0".to_owned(),
            tx_root: "P_OiqMNN1s4ltcaq0HXb9VFos_Zz6LFjM8ogUG0vJek".to_owned(),
            ..crate::BlockHeader::default()
        };
        let responses: HashMap<_, _> = fixture
            .into_iter()
            .enumerate()
            .map(|(i, value)| (value["id"].as_str().unwrap().to_owned(), (i, value)))
            .collect();
        let responses = Arc::new(responses);
        let gate = Arc::new(Notify::new());
        let count = Arc::new(AtomicUsize::new(0));
        let corrupt = Arc::new(AtomicBool::new(false));
        let (requested, mut requests) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/tx/{id}",
            get({
                let gate = gate.clone();
                let count = count.clone();
                let corrupt = corrupt.clone();
                move |Path(id): Path<String>| {
                    let (index, mut value) = responses[&id].clone();
                    let gate = gate.clone();
                    let requested = requested.clone();
                    let corrupt = corrupt.load(Ordering::Relaxed);
                    count.fetch_add(1, Ordering::Relaxed);
                    async move {
                        requested.send(index).unwrap();
                        if index == 32 && !corrupt {
                            gate.notified().await;
                        }
                        if index == 64 && corrupt {
                            value["id"] = URL_SAFE_NO_PAD.encode([0u8; 32]).into();
                        }
                        ([("content-type", "application/json")], value.to_string())
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway::new(
            crate::Config::new(
                &url,
                &url,
                vec![url.clone()],
                Duration::from_secs(5),
                1,
                1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let slots = tokio::sync::Semaphore::new(4);
        let remaining = AtomicUsize::new(crate::MAX_BLOCK_TRANSACTION_BYTES);
        timeout(Duration::from_secs(10), async {
            let fetch = gateway.verify_block_transactions(header, seeds.clone(), 0, Some((&slots, &remaining)));
            tokio::pin!(fetch);
            for _ in 0..8 {
                tokio::select! {
                    _ = &mut fetch => panic!("finished before stalled header was released"),
                    index = requests.recv() => assert!(index.unwrap() >= 32, "seed was fetched twice"),
                }
            }
            gate.notify_one();
            let (header, objects) = fetch.await.unwrap();
            assert_eq!(count.load(Ordering::Relaxed), header.txs.len() - seeds.len());
            let cached: HashMap<_, _> = objects.into_iter().map(|o| (o.id.clone(), o)).collect();
            let ids = vec![seeds[0].id.clone(), seeds[1].id.clone()];
            let before = count.load(Ordering::Relaxed);
            let (_, returned, cached) = transaction_metadata(&gateway, 0, ids.clone(), None, cached, &slots).await.unwrap();
            assert_eq!(returned, ids);
            assert!(returned.iter().all(|id| cached.contains_key(id)));
            assert_eq!(count.load(Ordering::Relaxed), before);
            corrupt.store(true, Ordering::Relaxed);
            assert!(gateway.verify_block_transactions(header, seeds.clone(), 0, Some((&slots, &remaining))).await.is_err());
        }).await.unwrap();
        server.abort();
    }

    use super::*;
    use axum::{Router, extract::Path, routing::get};
    use std::sync::Arc;
    use tokio::{net::TcpListener, sync::Notify};

    #[tokio::test]
    async fn headers_refill_while_earlier_header_is_stalled() {
        let mut blocks = Vec::new();
        let mut responses = HashMap::new();
        for index in 0..64 {
            let mut value = serde_json::json!({
                "indep_hash": "", "height": 1_000_000 + index,
                "previous_block": "", "timestamp": index + 1,
                "nonce": "AQ", "last_retarget": 1, "diff": "1",
                "cumulative_diff": "1", "reward_pool": "0", "wallet_list": "",
                "hash_list_merkle": "", "hash": "", "block_size": "0",
                "weave_size": "0", "tx_root": "", "reward_addr": "unclaimed",
                "tags": [], "txs": [], "packing_2_5_threshold": "0",
                "strict_data_split_threshold": "0", "usd_to_ar_rate": ["1", "1"],
                "scheduled_usd_to_ar_rate": ["1", "1"],
                "poa": {"option": "1", "tx_path": "", "data_path": "", "chunk": ""}
            });
            let header = serde_json::from_value(value.clone()).unwrap();
            let hash = crate::block_indep_hash(&header).unwrap();
            let id = URL_SAFE_NO_PAD.encode(hash);
            value["indep_hash"] = id.clone().into();
            if index == 63 {
                value["timestamp"] = 999.into();
            }
            blocks.push(IndexBlock {
                height: 1_000_000 + index,
                hash: hash.to_vec(),
                previous_hash: None,
                tx_root: Vec::new(),
                weave_size: 0,
            });
            responses.insert(id, (index, value));
        }
        let responses = Arc::new(responses);
        let gate = Arc::new(Notify::new());
        let (requested, mut requests) = mpsc::unbounded_channel();
        let app = Router::new().route(
            "/block/hash/{id}",
            get({
                let gate = gate.clone();
                move |Path(id): Path<String>| {
                    let (index, value) = responses[&id].clone();
                    let gate = gate.clone();
                    let requested = requested.clone();
                    async move {
                        requested.send(index).unwrap();
                        if index == 0 {
                            gate.notified().await;
                        }
                        ([("content-type", "application/json")], value.to_string())
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = crate::Config::new(
            &url,
            &url,
            vec![url.clone()],
            Duration::from_secs(5),
            1,
            1024,
        )
        .unwrap();
        let gateway = Gateway::new(config).unwrap();
        let first_block = blocks[0].clone();
        let handoff = Mutex::new(HashMap::new());
        let headers = block_metadata(&gateway, blocks, &handoff);
        tokio::pin!(headers);
        timeout(Duration::from_secs(5), async {
            let mut heights = Vec::new();
            let mut rejected = false;
            loop {
                tokio::select! {
                    result = headers.next() => match result.unwrap() {
                        Ok((block, _, _)) => {
                            assert_ne!(block.height, 1_000_000);
                            heights.push(block.height);
                        }
                        Err(error) => {
                            assert!(format!("{error:#}").contains("block indep_hash verification failed"));
                            rejected = true;
                        }
                    },
                    index = requests.recv() => if index.unwrap() >= 32 { break; },
                }
            }
            gate.notify_one();
            while let Some(result) = headers.next().await {
                match result {
                    Ok((block, _, _)) => heights.push(block.height),
                    Err(error) => {
                        assert!(format!("{error:#}").contains("block indep_hash verification failed"));
                        rejected = true;
                    }
                }
            }
            heights.sort_unstable();
            assert_eq!(heights, (1_000_000..1_000_063).collect::<Vec<_>>());
            assert!(rejected);
            let cached = handoff.lock().unwrap().remove(&first_block.hash).unwrap();
            let mut previous = first_block.clone();
            previous.height -= 1;
            let header = transaction_block(&gateway, &previous, &first_block, Some(cached)).await.unwrap();
            assert_eq!(header.indep_hash, URL_SAFE_NO_PAD.encode(&first_block.hash));
            previous.weave_size = 1;
            assert!(transaction_block(&gateway, &previous, &first_block, Some(header)).await.is_err());
        })
        .await
        .unwrap();
        server.abort();
    }
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
    (summary.imported_roots, summary.imported_occurrences) =
        crate::background::import(gateway, store, start, end).await?;
    if summary.imported_roots > 0 {
        timeout(deadline, store.analyze_metadata())
            .await
            .context("bundle statistics refresh timed out")??;
    }
    Ok(summary)
}

pub(crate) async fn index_bundle_content(
    gateway: &Gateway,
    store: &mut BlockStore,
    bundle: std::sync::Arc<crate::VerifiedRoot>,
) -> Result<u64> {
    let crate::VerifiedRoot {
        data: root,
        tags,
        facts,
    } = bundle.as_ref();
    index_bundle_source(
        gateway,
        store,
        &root.id,
        root.bytes.clone(),
        root.block_height,
        root.cache_hit,
        tags,
        facts.as_ref(),
    )
    .await
}

pub(crate) async fn index_authenticated_bundle(
    gateway: &Gateway,
    store: &mut BlockStore,
    root: &crate::AuthenticatedRoot,
) -> Result<u64> {
    index_bundle_source(
        gateway,
        store,
        &root.id,
        root.bytes.with_gateway(gateway).await,
        root.block_height,
        false,
        &root.tags,
        root.facts.as_ref(),
    )
    .await
}

async fn index_bundle_source(
    gateway: &Gateway,
    store: &mut BlockStore,
    encoded_id: &str,
    content: crate::content::Content,
    block_height: u64,
    cache_hit: bool,
    tags: &[crate::Tag],
    facts: Option<&RootFacts>,
) -> Result<u64> {
    let reused_facts = facts.is_some();
    timeout(gateway.config.retrieval_timeout, async {
        let root_id = crate::decode_fixed::<32>(encoded_id, "bundle root ID")?;
        require_bundle_tags(tags)?;
        let deadline = gateway.config.request_timeout;
        let status = timeout(deadline, async {
            let state = store
                .state()
                .await?
                .context("block index is not initialized")?;
            ensure!(
                state.source == gateway.config.trusted_node_url,
                "trusted node source does not match stored import"
            );
            ensure!(
                block_height >= state.start_height
                    && state
                        .imported_through
                        .is_some_and(|through| block_height <= through),
                "bundle root is outside imported block-index coverage"
            );
            store.bundle_status(&root_id).await
        })
        .await
        .context("bundle metadata lookup timed out")??;
        if status.is_some_and(|(_, _, complete)| complete) {
            return Ok(0);
        }

        if let Some(facts) = facts {
            ensure!(
                facts.object.id.as_slice() == root_id
                    && facts.object.kind == 0
                    && facts.object.data_size == content.len() as u128,
                "authenticated bundle root metadata does not match verified content"
            );
            ensure!(
                facts.object.tags.len() == tags.len(),
                "authenticated bundle root tags differ"
            );
            for (tag, (name, value)) in tags.iter().zip(&facts.object.tags) {
                ensure!(
                    decode_b64(&tag.name, "tag name")? == *name
                        && decode_b64(&tag.value, "tag value")? == *value,
                    "authenticated bundle root tags differ"
                );
            }
            timeout(deadline, async {
                let (_, block) = store
                    .block_pair(block_height)
                    .await?
                    .context("bundle root has no imported canonical block pair")?;
                ensure!(
                    block.hash.as_slice() == facts.block_hash,
                    "authenticated bundle root block changed"
                );
                store
                    .record_bundle_root(
                        &block,
                        facts.timestamp,
                        &facts.transaction_ids,
                        &facts.object,
                        &gateway.config.trusted_node_url,
                    )
                    .await
            })
            .await
            .context("recording authenticated bundle root timed out")??;
        } else if status.is_none() {
            import_metadata(gateway, store, block_height, block_height).await?;
        }
        let (height, size, complete) = match status {
            Some(status) => status,
            None => timeout(deadline, store.bundle_status(&root_id))
                .await
                .context("bundle metadata lookup timed out")??
                .context("bundle root lacks completed canonical ANS-104 metadata")?,
        };
        ensure!(
            height == block_height && size == content.len() as u128,
            "canonical bundle root metadata does not match verified content"
        );
        if complete {
            return Ok(0);
        }

        persist_bundle(gateway, store, &root_id, content, cache_hit, reused_facts).await
    })
    .await
    .with_context(|| format!("indexing bundle {encoded_id} timed out"))?
}

pub(crate) async fn index_streamed_bundle(
    gateway: &Gateway,
    store: &mut BlockStore,
    id: &[u8; 32],
    height: u64,
) -> Result<u64> {
    let prepared = timeout(gateway.config.request_timeout, async {
        let state = store
            .state()
            .await?
            .context("block index is not initialized")?;
        ensure!(
            state.source == gateway.config.trusted_node_url,
            "trusted node source does not match stored import"
        );
        let status = store
            .bundle_status(id)
            .await?
            .context("bundle lacks canonical metadata")?;
        ensure!(status.0 == height, "bundle root canonical height changed");
        let data_root = store.bundle_data_root(id).await?;
        Ok::<_, anyhow::Error>((status, data_root))
    })
    .await
    .context("preparing streamed bundle timed out")??;
    let ((_, size, complete), data_root) = prepared;
    if complete {
        return Ok(0);
    }
    let encoded = URL_SAFE_NO_PAD.encode(id);
    let Some(data_root) = data_root.filter(|root| !root.is_empty()) else {
        let root = gateway.retrieve_direct_with_tags(&encoded).await?;
        return index_bundle_content(gateway, store, root).await;
    };
    let geometry = timeout(gateway.config.request_timeout, async {
        let (previous, block) = store
            .block_pair(height)
            .await?
            .context("bundle block anchors unavailable")?;
        let offset: crate::TxOffset = gateway
            .get_json(&gateway.config.archive_url, &format!("tx/{encoded}/offset"))
            .await?;
        ensure!(
            parse_u128(&offset.size, "offset data size")? == size,
            "transaction size and offset size differ"
        );
        let end_offset = parse_u128(&offset.offset, "transaction end offset")?;
        let first_offset = end_offset
            .checked_sub(size)
            .and_then(|start| start.checked_add(1))
            .context("transaction offset underflow")?;
        ensure!(
            first_offset > previous.weave_size && end_offset <= block.weave_size,
            "transaction offset outside anchored block"
        );
        Ok::<_, anyhow::Error>(crate::Geometry {
            tx_root: block
                .tx_root
                .as_slice()
                .try_into()
                .context("invalid anchored transaction root")?,
            data_root: data_root
                .as_slice()
                .try_into()
                .context("invalid signed data root")?,
            block_weave_size: block.weave_size,
            previous_weave_size: previous.weave_size,
            first_offset,
            end_offset,
            data_size: size,
        })
    })
    .await
    .context("preparing bundle chunk geometry timed out")??;
    let content = crate::content::Content::streamed(
        crate::streaming::ChunkSource::new(gateway, geometry),
        usize::try_from(size).context("bundle size exceeds addressable range")?,
    );
    persist_bundle(gateway, store, id, content, false, false).await
}

async fn persist_bundle(
    gateway: &Gateway,
    store: &mut BlockStore,
    root_id: &[u8; 32],
    content: crate::content::Content,
    cache_hit: bool,
    reused_facts: bool,
) -> Result<u64> {
    let encoded_id = URL_SAFE_NO_PAD.encode(root_id);
    let mut traversal = BundleTraversal::new(content, root_id).await?;
    let mut occurrences = 0;
    let mut verification_time = Duration::ZERO;
    let mut persistence_time = Duration::ZERO;
    loop {
        let started = Instant::now();
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
        verification_time += started.elapsed();
        let started = Instant::now();
        timeout(
            gateway.config.request_timeout,
            store.commit_bundle_batch(root_id, &objects, &locations, complete),
        )
        .await
        .context("committing bundle metadata timed out")??;
        persistence_time += started.elapsed();
        occurrences += locations.len() as u64;
        if complete {
            eprintln!(
                "indexed bundle {encoded_id}: occurrences={occurrences} cache_hit={cache_hit} reused_root_facts={reused_facts} item_verification_ms={} persistence_ms={}",
                verification_time.as_millis(),
                persistence_time.as_millis()
            );
            return Ok(occurrences);
        }
    }
}

struct BundleFrame {
    items: BundleItems,
    id: [u8; 32],
    item_offset: Option<u128>,
    payload_offset: u128,
    framing_checked: bool,
}

struct BundleTraversal {
    stack: Vec<BundleFrame>,
}

impl BundleTraversal {
    async fn new(root: crate::content::Content, root_id: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            stack: vec![BundleFrame {
                items: BundleItems::new(root).await?,
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
                let mut table = BundleItems::new(parent.items.bundle.clone()).await?;
                let mut checked = 0;
                while table.next().await?.is_some() {
                    checked += 1;
                    if checked % 256 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                parent.framing_checked = true;
            }
            tokio::task::yield_now().await;
            let Some(entry) = parent.items.next().await? else {
                self.stack.pop();
                continue;
            };
            let item_size = entry.bytes.len() as u128;
            let item = verify_data_item(entry.bytes, &entry.id).await?;
            let root_offset = parent
                .payload_offset
                .checked_add(entry.offset as u128)
                .context("bundle root offset overflow")?;
            let location = BundleLocation {
                id: entry.id.to_vec(),
                parent_id: parent.id.to_vec(),
                parent_offset: parent.item_offset,
                item_offset: entry.offset as u128,
                item_size,
                data_offset: item.data_offset as u128,
                root_offset,
            };
            let metadata = item.metadata(&entry.id);
            if item.is_bundle() {
                let items = BundleItems::new(item.data).await?;
                if items.remaining > 0 {
                    ensure!(
                        self.stack.len() < MAX_BUNDLE_DEPTH,
                        "nested bundle exceeds maximum depth {MAX_BUNDLE_DEPTH}"
                    );
                    self.stack.push(BundleFrame {
                        items,
                        id: entry.id,
                        item_offset: Some(root_offset),
                        payload_offset: root_offset
                            .checked_add(item.data_offset as u128)
                            .context("nested bundle payload offset overflow")?,
                        framing_checked: false,
                    });
                }
            }
            return Ok(Some((metadata, location)));
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
        let payload = vec![0xa5; 128 * 1024 + 17];
        let data = payload.as_slice();
        let (leaf, leaf_id) = signed_data_item(data, &[]);
        let nested_data = encode_bundle(&[&leaf, &leaf]);
        let (nested, nested_id) = signed_data_item(&nested_data, BUNDLE_TAGS);
        let root = encode_bundle(&[&nested, &nested]);
        let root_content = crate::tests::spooled_content(&root).await;
        let mut traversal = BundleTraversal::new(root_content.clone(), &root_id)
            .await
            .unwrap();
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
            content_type: None,
            locations: vec![locations[3].clone(), locations[5].clone()],
        };
        for content in [root.clone().into(), root_content] {
            let verified = verify_indexed_bundle(content, &leaf_id, &indexed(), None)
                .await
                .unwrap();
            assert_eq!(
                verified.data.read_all(data.len()).await.unwrap().as_ref(),
                data
            );
            assert_eq!(verified.body_hash, crate::sha256(&[data]));
        }
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
            assert!(
                verify_indexed_bundle(root.clone().into(), &leaf_id, &hint, None)
                    .await
                    .is_err()
            );
        }
        let mut missing_ancestor = indexed();
        missing_ancestor.locations.remove(0);
        assert!(
            verify_indexed_bundle(root.clone().into(), &leaf_id, &missing_ancestor, None)
                .await
                .is_err()
        );
        let mut corrupt_parent = root.clone();
        corrupt_parent[second_parent + 2] ^= 1;
        assert!(
            verify_indexed_bundle(corrupt_parent.into(), &leaf_id, &indexed(), None)
                .await
                .is_err()
        );
        let mut corrupt_table = root.clone();
        corrupt_table[96] ^= 1;
        assert!(
            verify_indexed_bundle(corrupt_table.into(), &leaf_id, &indexed(), None)
                .await
                .is_err()
        );

        let mut corrupt_leaf = leaf.clone();
        *corrupt_leaf.last_mut().unwrap() ^= 1;
        let repeated = encode_bundle(&[&corrupt_leaf, &leaf]);
        assert_eq!(
            verify_bundle_item(
                repeated.clone().into(),
                &leaf_id,
                Some((160 + leaf.len()) as u128),
                None,
            )
            .await
            .unwrap()
            .0
            .data
            .read_all(data.len())
            .await
            .unwrap()
            .as_ref(),
            data
        );
        assert!(
            verify_bundle_item(repeated.into(), &leaf_id, None, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn valid_prefix_replays_after_a_later_signature_failure() {
        let (leaf, _) = signed_data_item(b"resumable", &[]);
        let mut corrupt = leaf.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let mut items = vec![leaf.as_slice(); 256];
        items.push(&corrupt);
        let root = encode_bundle(&items);
        let mut first = BundleTraversal::new(root.clone().into(), &[9; 32])
            .await
            .unwrap();
        let mut replay = BundleTraversal::new(crate::tests::spooled_content(&root).await, &[9; 32])
            .await
            .unwrap();
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
        for content in [
            root.clone().into(),
            crate::tests::spooled_content(&root).await,
        ] {
            let mut traversal = BundleTraversal::new(content, &[9; 32]).await.unwrap();
            assert!(traversal.next().await.is_err());
        }
    }

    #[tokio::test]
    async fn traversal_accepts_empty_bundles_and_enforces_table_and_depth_bounds() {
        let empty = encode_bundle(&[]);
        assert!(
            BundleTraversal::new(empty.clone().into(), &[9; 32])
                .await
                .unwrap()
                .next()
                .await
                .unwrap()
                .is_none()
        );
        let mut trailing = empty.clone();
        trailing.push(0);
        assert!(
            BundleTraversal::new(trailing.into(), &[9; 32])
                .await
                .is_err()
        );
        let mut oversized = empty;
        oversized[31] = 1;
        assert!(
            BundleTraversal::new(oversized.into(), &[9; 32])
                .await
                .is_err()
        );

        let (leaf, _) = signed_data_item(b"deep", &[]);
        let mut root = encode_bundle(&[&leaf]);
        for _ in 1..MAX_BUNDLE_DEPTH {
            let (parent, _) = signed_data_item(&root, BUNDLE_TAGS);
            root = encode_bundle(&[&parent]);
        }
        let mut traversal = BundleTraversal::new(root.clone().into(), &[9; 32])
            .await
            .unwrap();
        for _ in 0..MAX_BUNDLE_DEPTH {
            assert!(traversal.next().await.unwrap().is_some());
        }
        assert!(traversal.next().await.unwrap().is_none());
        let (parent, _) = signed_data_item(&root, BUNDLE_TAGS);
        let too_deep = encode_bundle(&[&parent]);
        let mut traversal = BundleTraversal::new(too_deep.into(), &[9; 32])
            .await
            .unwrap();
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
