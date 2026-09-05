use std::{env, time::Duration};

use anyhow::{Context, Result, ensure};
use ar_io_gateway::{Config, Gateway, database::BlockStore, indexer::import_range};

const USAGE: &str = "usage: ar-io-index <start-height> <end-height>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
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
    let gateway = Gateway::new(Config::new(
        trusted_node.clone(),
        trusted_node.clone(),
        vec![trusted_node],
        timeout,
        1,
        1,
    )?)?;
    let mut store = tokio::time::timeout(timeout, async {
        let mut store = BlockStore::connect(&database_url).await?;
        store.migrate().await?;
        Ok::<_, anyhow::Error>(store)
    })
    .await
    .context("database initialization timed out")??;
    let summary = import_range(&gateway, &mut store, start, end).await?;
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}
