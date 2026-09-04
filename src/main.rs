use std::{env, fs, time::Duration};

use anyhow::{Context, Result, bail};
use ar_io_gateway::{
    Config, Gateway,
    server::{self, ServerConfig},
};

const USAGE: &str =
    "usage: ar-io-gateway serve\n       ar-io-gateway <fetch|fetch-bundled> <id> <output-file>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        bail!("{USAGE}");
    };

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

    if command == "serve" {
        if args.next().is_some() {
            bail!("{USAGE}");
        }
        let max_concurrent_requests = env::var("AR_IO_MAX_CONCURRENT_REQUESTS")
            .unwrap_or_else(|_| "8".to_owned())
            .parse()
            .context("invalid AR_IO_MAX_CONCURRENT_REQUESTS")?;
        let config = ServerConfig::new(
            &env::var("AR_IO_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned()),
            &env::var("ARNS_ROOT_HOST").unwrap_or_else(|_| "ar.mrx.im".to_owned()),
            &env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_owned()),
            &env::var("ARIO_ARNS_PROGRAM_ID")
                .unwrap_or_else(|_| "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ".to_owned()),
            &env::var("ARIO_ANT_PROGRAM_ID")
                .unwrap_or_else(|_| "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5".to_owned()),
            max_concurrent_requests,
        )?;
        return server::serve(gateway, config).await;
    }

    let Some(id) = args.next() else {
        bail!("{USAGE}");
    };
    let Some(output) = args.next() else {
        bail!("{USAGE}");
    };
    if !matches!(command.as_str(), "fetch" | "fetch-bundled") || args.next().is_some() {
        bail!("{USAGE}");
    }
    let verified = match command.as_str() {
        "fetch" => gateway.retrieve_direct(&id).await?,
        "fetch-bundled" => gateway.retrieve_bundled(&id).await?,
        _ => unreachable!(),
    };
    fs::write(&output, &verified.bytes)
        .with_context(|| format!("failed to write verified data to {output}"))?;
    println!("{}", serde_json::to_string(&verified)?);
    Ok(())
}
