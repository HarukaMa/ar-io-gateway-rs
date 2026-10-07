use std::env;

use anyhow::{Context, Result, bail};
use ar_io_gateway::{
    Config, Gateway,
    server::{self, ServerConfig},
};

const USAGE: &str = "usage: ar-io-gateway serve\n       ar-io-gateway prepare-graphql-index\n       ar-io-gateway prepare-packed-tags\n       ar-io-gateway cache-cleanup\n       ar-io-gateway diagnose <url|arns-name|id>\n       ar-io-gateway <fetch|fetch-bundled> <id> <output-file>";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        bail!("{USAGE}");
    };
    if command == "cache-cleanup" && args.len() != 0 {
        bail!("{USAGE}");
    }
    if command == "prepare-graphql-index" || command == "prepare-packed-tags" {
        if args.next().is_some() {
            bail!("{USAGE}");
        }
        let url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        let mut store = ar_io_gateway::database::BlockStore::connect(&url).await?;
        if command == "prepare-packed-tags" {
            store.prepare_packed_tags().await?;
        } else {
            store.prepare_graphql_indexes().await?;
        }
        return Ok(());
    }
    if command == "serve" && env::var_os("AR_IO_BLOCKLIST_PATH").is_some() {
        bail!(
            "AR_IO_BLOCKLIST_PATH is no longer supported. Move its entries to \
             public.content_blocklist and remove the variable before starting."
        );
    }

    let mut config = Config::from_env()?;
    if command == "diagnose" {
        let input = args.next().context(USAGE)?;
        if args.next().is_some() {
            bail!("{USAGE}");
        }
        let database_url = env::var("DATABASE_URL").ok();
        let cache_directory = env::var_os("AR_IO_DISK_CACHE_DIR").map(std::path::PathBuf::from);
        let resolver = resolver_config(1, false)?;
        // Poll separately from the CLI's serving and indexing state machine.
        let report = tokio::spawn(async move {
            Box::pin(ar_io_gateway::diagnostics::diagnose(
                config,
                resolver,
                &input,
                database_url.as_deref(),
                cache_directory.as_deref(),
            ))
            .await
        })
        .await
        .context("diagnostic task failed")?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report["status"] != "passed" {
            bail!("diagnostic failed");
        }
        return Ok(());
    }
    config.index_bundle_start_height = env::var("AR_IO_BUNDLE_START_HEIGHT")
        .unwrap_or_else(|_| config.index_bundle_start_height.to_string())
        .parse()
        .context("invalid AR_IO_BUNDLE_START_HEIGHT")?;
    let index_chain = env::var("AR_IO_INDEX_CHAIN")
        .unwrap_or_else(|_| "false".to_owned())
        .parse::<bool>()
        .context("invalid AR_IO_INDEX_CHAIN")?;
    config.index_chain = index_chain;
    let mut gateway = Gateway::new(config)?;
    if let Ok(url) = env::var("DATABASE_URL") {
        if command == "serve" && args.len() == 0 {
            let mut store = ar_io_gateway::database::BlockStore::connect(&url).await?;
            store.migrate().await?;
            let filter_indexes_enabled = env::var("AR_IO_GRAPHQL_FILTER_INDEXES")
                .as_deref()
                .unwrap_or("false")
                .parse::<bool>()
                .context("invalid AR_IO_GRAPHQL_FILTER_INDEXES")?;
            if filter_indexes_enabled {
                store.require_graphql_indexes().await?;
            } else {
                store.pause_graphql_index_maintenance().await?;
            }
        }
        gateway = gateway.with_database(&url).await?;
    }
    if let Some(path) = env::var_os("AR_IO_DISK_CACHE_DIR") {
        let min_free_bytes = env::var("AR_IO_DISK_CACHE_MIN_FREE_BYTES")
            .unwrap_or_else(|_| (50_u64 * 1024 * 1024 * 1024).to_string())
            .parse()
            .context("invalid AR_IO_DISK_CACHE_MIN_FREE_BYTES")?;
        gateway = gateway.with_disk_cache(path.into(), min_free_bytes).await?;
    }
    if command == "cache-cleanup" {
        let removed = gateway.cleanup_content_cache().await?;
        println!("removed {removed} abandoned content cache files");
        return Ok(());
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
        let mut config = resolver_config(max_concurrent_requests, true)?;
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
        let indexing_interval = env::var("MAX_EXPECTED_DATA_ITEM_INDEXING_INTERVAL_SECONDS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("invalid MAX_EXPECTED_DATA_ITEM_INDEXING_INTERVAL_SECONDS")?;
        config = config.with_info(
            env::var("ARIO_CORE_PROGRAM_ID").ok().as_deref(),
            env::var("ARIO_GAR_PROGRAM_ID").ok().as_deref(),
            env::var("BUNDLER_URLS").ok().as_deref(),
            indexing_interval,
        )?;
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

fn resolver_config(max_concurrent_requests: usize, load_signing: bool) -> Result<ServerConfig> {
    let identities_path = env::var_os("AR_IO_IDENTITIES_FILE").filter(|value| !value.is_empty());
    let enabled = load_signing
        && env::var("HTTPSIG_ENABLED")
            .unwrap_or_else(|_| identities_path.is_some().to_string())
            .parse::<bool>()
            .context("invalid HTTPSIG_ENABLED")?;
    if load_signing && identities_path.is_none() {
        for name in [
            "AR_IO_WALLET",
            "OBSERVER_KEYPAIR_PATH",
            "OBSERVER_PRIVATE_KEY",
        ] {
            if env::var_os(name).is_some_and(|value| !value.is_empty()) {
                bail!(
                    "set AR_IO_IDENTITIES_FILE for gateway wallets and signing keys; \
                     global {name} is no longer a Rust serving input"
                );
            }
        }
        if enabled {
            bail!("HTTPSIG_ENABLED=true requires AR_IO_IDENTITIES_FILE");
        }
    }
    let roots = if identities_path.is_some() {
        String::new()
    } else {
        env::var("ARNS_ROOT_HOST").unwrap_or_else(|_| "ar.mrx.im".to_owned())
    };
    let config = ServerConfig::new(
        &env::var("AR_IO_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned()),
        &roots,
        &env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_owned()),
        &env::var("ARIO_ARNS_PROGRAM_ID")
            .unwrap_or_else(|_| "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ".to_owned()),
        &env::var("ARIO_ANT_PROGRAM_ID")
            .unwrap_or_else(|_| "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5".to_owned()),
        max_concurrent_requests,
    )?;
    if let Some(path) = identities_path {
        let bind_request = env::var("HTTPSIG_BIND_REQUEST")
            .unwrap_or_else(|_| "true".to_owned())
            .parse::<bool>()
            .context("invalid HTTPSIG_BIND_REQUEST")?;
        config.with_identities_file(std::path::Path::new(&path), enabled, bind_request)
    } else {
        Ok(config)
    }
}
