use std::env;

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
    let config = Config::from_env()?;
    let timeout = config.request_timeout;
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
        "bundles" => serde_json::to_string(&import_bundles(gateway, store, start, end).await?)?,
        _ => unreachable!(),
    };
    println!("{summary}");
    Ok(())
}
