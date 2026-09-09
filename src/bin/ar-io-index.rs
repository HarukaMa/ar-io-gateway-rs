use std::{env, time::Duration};

use anyhow::{Context, Result, ensure};
use ar_io_gateway::{
    Config, Gateway,
    database::BlockStore,
    indexer::{import_bundles, import_metadata, import_range},
};

const USAGE: &str = "usage: ar-io-index <blocks|transactions|bundles> <start-height> <end-height>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().context(USAGE)?;
    ensure!(
        matches!(command.as_str(), "blocks" | "transactions" | "bundles"),
        "{USAGE}"
    );
    let start: u64 = args
        .next()
        .context(USAGE)?
        .parse()
        .context("invalid start height")?;
    let end: u64 = args
        .next()
        .context(USAGE)?
        .parse()
        .context("invalid end height")?;
    ensure!(args.next().is_none(), "{USAGE}");
    ensure!(start <= end, "invalid import range");

    let database_url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
    let trusted_node =
        env::var("ARWEAVE_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:1984".to_owned());
    let timeout = Duration::from_secs(
        env::var("ARWEAVE_REQUEST_TIMEOUT_SECS")
            .unwrap_or_else(|_| "10".to_owned())
            .parse()
            .context("invalid ARWEAVE_REQUEST_TIMEOUT_SECS")?,
    );
    let archive =
        env::var("ARWEAVE_ARCHIVE_URL").unwrap_or_else(|_| "https://arweave.net".to_owned());
    let sources = env::var("ARWEAVE_CHUNK_SOURCES")
        .unwrap_or_else(|_| "https://arweave.net,https://tip-4.arweave.xyz".to_owned())
        .split(',')
        .filter(|source| !source.is_empty())
        .map(str::to_owned)
        .collect();
    let max_attempts = env::var("ARWEAVE_MAX_PEER_ATTEMPTS")
        .unwrap_or_else(|_| "3".to_owned())
        .parse()
        .context("invalid ARWEAVE_MAX_PEER_ATTEMPTS")?;
    let max_data_size = env::var("ARWEAVE_MAX_DATA_SIZE_BYTES")
        .unwrap_or_else(|_| (1024 * 1024 * 1024).to_string())
        .parse()
        .context("invalid ARWEAVE_MAX_DATA_SIZE_BYTES")?;
    let mut config = Config::new(
        trusted_node,
        archive,
        sources,
        timeout,
        max_attempts,
        max_data_size,
    )?;
    config.graphql_sources = env::var("ARWEAVE_GRAPHQL_URLS")
        .unwrap_or_else(|_| {
            format!(
                "{}/graphql,https://turbo-gateway.com/graphql",
                config.archive_url
            )
        })
        .split(',')
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .map(str::to_owned)
        .collect();
    config.max_memory_data_size = env::var("ARWEAVE_MAX_MEMORY_DATA_SIZE_BYTES")
        .unwrap_or_else(|_| config.max_memory_data_size.to_string())
        .parse()
        .context("invalid ARWEAVE_MAX_MEMORY_DATA_SIZE_BYTES")?;
    config.max_spool_bytes = env::var("ARWEAVE_MAX_SPOOL_BYTES")
        .unwrap_or_else(|_| config.max_spool_bytes.to_string())
        .parse()
        .context("invalid ARWEAVE_MAX_SPOOL_BYTES")?;
    config.index_downloads = env::var("AR_IO_INDEX_DOWNLOADS")
        .unwrap_or_else(|_| config.index_downloads.to_string())
        .parse()
        .context("invalid AR_IO_INDEX_DOWNLOADS")?;
    config.index_max_bytes = env::var("AR_IO_INDEX_MAX_BYTES")
        .unwrap_or_else(|_| config.index_max_bytes.to_string())
        .parse()
        .context("invalid AR_IO_INDEX_MAX_BYTES")?;
    config.retrieval_timeout = Duration::from_secs(
        env::var("ARWEAVE_RETRIEVAL_TIMEOUT_SECS")
            .unwrap_or_else(|_| config.retrieval_timeout.as_secs().to_string())
            .parse()
            .context("invalid ARWEAVE_RETRIEVAL_TIMEOUT_SECS")?,
    );
    config.stream_idle_timeout = Duration::from_secs(
        env::var("AR_IO_STREAM_IDLE_TIMEOUT_SECS")
            .unwrap_or_else(|_| config.stream_idle_timeout.as_secs().to_string())
            .parse()
            .context("invalid AR_IO_STREAM_IDLE_TIMEOUT_SECS")?,
    );
    config.stream_timeout = Duration::from_secs(
        env::var("AR_IO_STREAM_TIMEOUT_SECS")
            .unwrap_or_else(|_| config.stream_timeout.as_secs().to_string())
            .parse()
            .context("invalid AR_IO_STREAM_TIMEOUT_SECS")?,
    );
    config.cache_max_entries = env::var("AR_IO_CACHE_MAX_ENTRIES")
        .unwrap_or_else(|_| config.cache_max_entries.to_string())
        .parse()
        .context("invalid AR_IO_CACHE_MAX_ENTRIES")?;
    config.cache_max_bytes = env::var("AR_IO_CACHE_MAX_BYTES")
        .unwrap_or_else(|_| config.cache_max_bytes.to_string())
        .parse()
        .context("invalid AR_IO_CACHE_MAX_BYTES")?;
    let mut gateway = Gateway::new(config)?;
    let mut store = tokio::time::timeout(timeout, async {
        let mut store = BlockStore::connect(&database_url).await?;
        store.migrate().await?;
        Ok::<_, anyhow::Error>(store)
    })
    .await
    .context("database initialization timed out")??;
    if command == "bundles" {
        gateway = gateway.with_database(&database_url).await?;
        if let Err(error) = gateway.refresh_peers().await {
            eprintln!("Arweave peer discovery failed: {error:#}");
        }
        if let Some(path) = env::var_os("AR_IO_DISK_CACHE_DIR") {
            let min_free_bytes = env::var("AR_IO_DISK_CACHE_MIN_FREE_BYTES")
                .unwrap_or_else(|_| (50_u64 * 1024 * 1024 * 1024).to_string())
                .parse()
                .context("invalid AR_IO_DISK_CACHE_MIN_FREE_BYTES")?;
            gateway = gateway.with_disk_cache(path.into(), min_free_bytes).await?;
        }
    }
    let summary = match command.as_str() {
        "blocks" => serde_json::to_string(&import_range(&gateway, &mut store, start, end).await?)?,
        "transactions" => {
            serde_json::to_string(&import_metadata(&gateway, &mut store, start, end).await?)?
        }
        "bundles" => {
            serde_json::to_string(&import_bundles(&gateway, &mut store, start, end).await?)?
        }
        _ => unreachable!(),
    };
    println!("{summary}");
    Ok(())
}
