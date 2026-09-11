use std::{env, fs, io::Read, time::Duration};

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
        .unwrap_or_else(|_| (1024 * 1024 * 1024).to_string())
        .parse()
        .context("invalid ARWEAVE_MAX_DATA_SIZE_BYTES")?;
    let mut config = Config::new(
        trusted_node,
        archive,
        sources,
        Duration::from_secs(timeout),
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
    config.index_bundle_start_height = env::var("AR_IO_BUNDLE_START_HEIGHT")
        .unwrap_or_else(|_| config.index_bundle_start_height.to_string())
        .parse()
        .context("invalid AR_IO_BUNDLE_START_HEIGHT")?;
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
    let index_chain = env::var("AR_IO_INDEX_CHAIN")
        .unwrap_or_else(|_| "false".to_owned())
        .parse::<bool>()
        .context("invalid AR_IO_INDEX_CHAIN")?;
    config.index_chain = index_chain;
    let mut gateway = Gateway::new(config)?;
    if let Ok(url) = env::var("DATABASE_URL") {
        gateway = gateway.with_database(&url).await?;
    }
    if let Some(path) = env::var_os("AR_IO_DISK_CACHE_DIR") {
        let min_free_bytes = env::var("AR_IO_DISK_CACHE_MIN_FREE_BYTES")
            .unwrap_or_else(|_| (50_u64 * 1024 * 1024 * 1024).to_string())
            .parse()
            .context("invalid AR_IO_DISK_CACHE_MIN_FREE_BYTES")?;
        gateway = gateway.with_disk_cache(path.into(), min_free_bytes).await?;
    }

    if command == "serve" {
        if args.next().is_some() {
            bail!("{USAGE}");
        }
        let index_bundles = index_chain
            || env::var("AR_IO_INDEX_BUNDLES")
                .unwrap_or_else(|_| "false".to_owned())
                .parse::<bool>()
                .context("invalid AR_IO_INDEX_BUNDLES")?;
        for name in ["ANS104_UNBUNDLE_FILTER", "ANS104_INDEX_FILTER"] {
            if let Ok(value) = env::var(name) {
                let filter: serde_json::Value =
                    serde_json::from_str(&value).with_context(|| format!("invalid {name}"))?;
                let expected = if index_bundles {
                    serde_json::json!({"always": true})
                } else {
                    serde_json::json!({"never": true})
                };
                if filter != expected {
                    bail!(
                        "{name} must be {expected} when AR_IO_INDEX_BUNDLES={index_bundles}; selective filters are not supported"
                    );
                }
            }
        }
        let max_concurrent_requests = env::var("AR_IO_MAX_CONCURRENT_REQUESTS")
            .unwrap_or_else(|_| "128".to_owned())
            .parse()
            .context("invalid AR_IO_MAX_CONCURRENT_REQUESTS")?;
        let mut config = ServerConfig::new(
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
        config = config.with_routing(
            env::var("APEX_TX_ID")
                .ok()
                .filter(|value| !value.is_empty())
                .as_deref(),
            env::var("APEX_ARNS_NAME")
                .ok()
                .filter(|value| !value.is_empty())
                .as_deref(),
            env::var("CACHE_APEX_MAX_AGE")
                .unwrap_or_else(|_| "3600".to_owned())
                .parse()
                .context("invalid CACHE_APEX_MAX_AGE")?,
        )?;
        if let Some(path) = env::var("AR_IO_BLOCKLIST_PATH")
            .ok()
            .filter(|value| !value.is_empty())
        {
            let mut bytes = Vec::new();
            fs::File::open(path)
                .context("cannot open AR_IO_BLOCKLIST_PATH")?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .context("cannot read AR_IO_BLOCKLIST_PATH")?;
            config = config.with_blocklist(&bytes)?;
        }
        let wallet = env::var("AR_IO_WALLET")
            .ok()
            .filter(|value| !value.is_empty());
        let indexing_interval = env::var("MAX_EXPECTED_DATA_ITEM_INDEXING_INTERVAL_SECONDS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("invalid MAX_EXPECTED_DATA_ITEM_INDEXING_INTERVAL_SECONDS")?;
        config = config.with_info(
            env::var("ARIO_CORE_PROGRAM_ID").ok().as_deref(),
            env::var("ARIO_GAR_PROGRAM_ID").ok().as_deref(),
            env::var("BUNDLER_URLS").ok().as_deref(),
            wallet.as_deref(),
            indexing_interval,
        )?;
        let key_path = env::var("OBSERVER_KEYPAIR_PATH")
            .ok()
            .filter(|value| !value.is_empty());
        let private_key = env::var("OBSERVER_PRIVATE_KEY")
            .ok()
            .filter(|value| !value.is_empty());
        let signing_requested = wallet.is_some() || key_path.is_some() || private_key.is_some();
        let enabled = env::var("HTTPSIG_ENABLED")
            .unwrap_or_else(|_| signing_requested.to_string())
            .parse::<bool>()
            .context("invalid HTTPSIG_ENABLED")?;
        if enabled {
            let wallet = wallet.context("AR_IO_WALLET is required for signing")?;
            let mut keypair = match (key_path, private_key) {
                (Some(path), None) => {
                    let mut raw = fs::read(path).context("cannot read OBSERVER_KEYPAIR_PATH")?;
                    let result = serde_json::from_slice::<Vec<u8>>(&raw);
                    raw.fill(0);
                    let mut bytes = result
                        .map_err(|_| anyhow::anyhow!("invalid OBSERVER_KEYPAIR_PATH keypair"))?;
                    let keypair = <[u8; 64]>::try_from(bytes.as_slice());
                    bytes.fill(0);
                    keypair.context("OBSERVER_KEYPAIR_PATH must contain 64 bytes")?
                }
                (None, Some(encoded)) => {
                    let mut bytes = [0_u8; 64];
                    let result = bs58::decode(&encoded).onto(&mut bytes);
                    let mut encoded = encoded.into_bytes();
                    encoded.fill(0);
                    if !matches!(result, Ok(64)) {
                        bytes.fill(0);
                        bail!("invalid OBSERVER_PRIVATE_KEY keypair");
                    }
                    bytes
                }
                _ => bail!("set exactly one of OBSERVER_KEYPAIR_PATH or OBSERVER_PRIVATE_KEY"),
            };
            let bind_request = env::var("HTTPSIG_BIND_REQUEST")
                .unwrap_or_else(|_| "true".to_owned())
                .parse::<bool>()
                .context("invalid HTTPSIG_BIND_REQUEST")?;
            let result = config.with_signing(&wallet, &keypair, bind_request);
            keypair.fill(0);
            config = result?;
        }
        let worker = if index_bundles {
            let url = env::var("DATABASE_URL")
                .context("AR_IO_INDEX_BUNDLES=true requires DATABASE_URL")?;
            let (indexed_gateway, worker) = gateway.with_bundle_indexing(&url).await?;
            gateway = indexed_gateway;
            Some(worker)
        } else {
            None
        };
        let result = server::serve(gateway, config).await;
        let shutdown = match worker {
            Some(worker) => worker.shutdown().await,
            None => Ok(()),
        };
        return result.and(shutdown);
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
    verified
        .bytes
        .write_to(&output)
        .await
        .with_context(|| format!("failed to write verified data to {output}"))?;
    println!("{}", serde_json::to_string(&verified)?);
    Ok(())
}
