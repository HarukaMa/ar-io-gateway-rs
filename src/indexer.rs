use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use tokio::time::timeout;

use crate::{
    CONSENSUS_DEPTH, Gateway, NodeInfo,
    database::{BlockStore, Checkpoint, IndexBlock},
    decode_b64, endpoint,
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
                ensure!(
                    end <= state.checkpoint.height,
                    "import end exceeds the stored checkpoint"
                );
                verify_checkpoint(gateway, &state.checkpoint).await?;
                state.checkpoint
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
