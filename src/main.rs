use std::{env, fs, time::Duration};

use anyhow::{Context, Result, bail};
use ar_io_gateway::{Config, Gateway};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        bail!("usage: ar-io-gateway fetch <transaction-id> <output-file>");
    };
    let Some(id) = args.next() else {
        bail!("usage: ar-io-gateway fetch <transaction-id> <output-file>");
    };
    let Some(output) = args.next() else {
        bail!("usage: ar-io-gateway fetch <transaction-id> <output-file>");
    };
    if command != "fetch" || args.next().is_some() {
        bail!("usage: ar-io-gateway fetch <transaction-id> <output-file>");
    }

    let trusted_node =
        env::var("ARWEAVE_NODE_URL").unwrap_or_else(|_| "http://127.0.0.1:1984".to_owned());
    let archive =
        env::var("ARWEAVE_ARCHIVE_URL").unwrap_or_else(|_| "https://arweave.net".to_owned());
    let sources = env::var("ARWEAVE_CHUNK_SOURCES")
        .unwrap_or_else(|_| "https://arweave.net,https://tip-4.arweave.xyz".to_owned())
        .split(',')
        .filter(|source| !source.is_empty())
        .map(str::to_owned)
        .collect();
    let timeout = env::var("ARWEAVE_REQUEST_TIMEOUT_SECS")
        .unwrap_or_else(|_| "10".to_owned())
        .parse()
        .context("invalid ARWEAVE_REQUEST_TIMEOUT_SECS")?;
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
        Duration::from_secs(timeout),
        max_attempts,
        max_data_size,
    )?)?;
    let verified = gateway.retrieve_direct(&id).await?;
    fs::write(&output, &verified.bytes)
        .with_context(|| format!("failed to write verified data to {output}"))?;
    println!("{}", serde_json::to_string(&verified)?);
    Ok(())
}
