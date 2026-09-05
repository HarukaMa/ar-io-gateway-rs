use std::{env, time::Duration};

use anyhow::{Context, Result, ensure};
use ar_io_gateway::{
    Config, Gateway,
    database::BlockStore,
    indexer::{import_metadata, import_range},
};

const USAGE: &str = "usage: ar-io-index <blocks|transactions> <start-height> <end-height>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let command = args.next().context(USAGE)?;
    ensure!(
        matches!(command.as_str(), "blocks" | "transactions"),
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
        .unwrap_or_else(|_| (64 * 1024 * 1024).to_string())
        .parse()
        .context("invalid ARWEAVE_MAX_DATA_SIZE_BYTES")?;
    let gateway = Gateway::new(Config::new(
        trusted_node,
        archive,
        sources,
        timeout,
        max_attempts,
        max_data_size,
    )?)?;
    let mut store = tokio::time::timeout(timeout, async {
        let mut store = BlockStore::connect(&database_url).await?;
        store.migrate().await?;
        Ok::<_, anyhow::Error>(store)
    })
    .await
    .context("database initialization timed out")??;
    let summary = match command.as_str() {
        "blocks" => serde_json::to_string(&import_range(&gateway, &mut store, start, end).await?)?,
        "transactions" => {
            serde_json::to_string(&import_metadata(&gateway, &mut store, start, end).await?)?
        }
        _ => unreachable!(),
    };
    println!("{summary}");
    Ok(())
}
