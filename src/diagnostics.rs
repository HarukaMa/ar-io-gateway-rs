use std::{cell::RefCell, future::Future, path::Path};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::FutureExt;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Config, Gateway, decode_fixed, server};

tokio::task_local! {
    static TRACE: RefCell<Trace>;
}

#[derive(Default, Serialize)]
struct Trace {
    steps: Vec<Step>,
    truncated: bool,
}

#[derive(Serialize)]
struct Step {
    stage: &'static str,
    id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}

impl Trace {
    fn push(&mut self, step: Step) -> Option<usize> {
        if self.steps.len() == 512 {
            self.truncated = true;
            return None;
        }
        let index = self.steps.len();
        self.steps.push(step);
        Some(index)
    }
}

pub(crate) fn check<T, F>(
    stage: &'static str,
    id: &str,
    operation: F,
) -> impl Future<Output = Result<T>> + use<T, F>
where
    F: Future<Output = Result<T>>,
{
    let index = TRACE
        .try_with(|trace| {
            trace.borrow_mut().push(Step {
                stage,
                id: id.to_owned(),
                status: "incomplete",
                error: None,
                parent_id: None,
                source: None,
            })
        })
        .ok()
        .flatten();
    operation.inspect(move |result| {
        if let Some(index) = index {
            let _ = TRACE.try_with(|trace| {
                let mut trace = trace.borrow_mut();
                let step = &mut trace.steps[index];
                step.status = if result.is_ok() { "passed" } else { "failed" };
                step.error = result.as_ref().err().map(|error| format!("{error:#}"));
            });
        }
    })
}

pub(crate) fn check_item<T, F>(
    id: &[u8],
    operation: F,
) -> impl Future<Output = Result<T>> + use<T, F>
where
    F: Future<Output = Result<T>>,
{
    let id = TRACE
        .try_with(|_| URL_SAFE_NO_PAD.encode(id))
        .unwrap_or_default();
    check("bundle_item_verification", &id, operation)
}

pub(crate) fn location(id: &str, parent: &str, source: &str) {
    let _ = TRACE.try_with(|trace| {
        trace.borrow_mut().push(Step {
            stage: "bundle_location",
            id: id.to_owned(),
            status: "discovered",
            error: None,
            parent_id: Some(parent.to_owned()),
            source: Some(source.to_owned()),
        });
    });
}

pub(crate) fn indexed_location(id: &[u8], parent: &[u8]) {
    let _ = TRACE.try_with(|_| {
        location(
            &URL_SAFE_NO_PAD.encode(id),
            &URL_SAFE_NO_PAD.encode(parent),
            "index",
        );
    });
}

/// Inspect local state and perform fresh verified retrieval without persistent writes.
/// Cache presence checks file type and size only. Retrieval bypasses persistent caches.
pub async fn diagnose(
    mut config: Config,
    resolver: server::ServerConfig,
    input: &str,
    database_url: Option<&str>,
    cache_directory: Option<&Path>,
) -> Value {
    config.index_chain = false;
    let deadline = config.retrieval_timeout;
    let setup = async {
        let mut gateway = Gateway::new(config)?;
        if let Some(url) = database_url {
            gateway = check("database_connection", input, gateway.with_database(url)).await?;
        }
        Ok(gateway)
    };
    run(setup, &resolver, input, cache_directory, deadline).await
}

pub(crate) async fn diagnose_public(
    serving: &Gateway,
    resolver: &server::ServerConfig,
    input: &str,
) -> Value {
    let mut config = serving.config.clone();
    config.index_chain = false;
    config.max_data_size = config.max_data_size.min(64 * 1024 * 1024);
    config.max_memory_data_size = config.max_memory_data_size.min(config.max_data_size);
    config.max_spool_bytes = config.max_spool_bytes.min(config.max_data_size);
    config.retrieval_timeout = config
        .retrieval_timeout
        .min(std::time::Duration::from_secs(60));
    let deadline = config.retrieval_timeout;
    let setup = async {
        let mut gateway = Gateway::new(config)?;
        gateway.spool_budget = serving.spool_budget.clone();
        gateway.peers = serving.peers.clone();
        if let Some(store) = &serving.block_store {
            gateway.block_store =
                Some(check("database_connection", input, store.reconnect()).await?);
        }
        Ok(gateway)
    };
    let mut report = run(
        setup,
        resolver,
        input,
        serving.disk_cache.as_ref().map(|cache| cache.directory()),
        deadline,
    )
    .await;
    // Public reports never include chained errors or configured upstream locations.
    if !report["error"].is_null() {
        report["error"] = json!("Diagnostic could not be completed. Check the stages below.");
    }
    for field in ["index", "cache"] {
        if let Some(error) = report[field].get_mut("error") {
            *error = json!("Inspection failed");
        }
    }
    if let Some(steps) = report["steps"].as_array_mut() {
        for step in steps {
            if let Some(error) = step.get_mut("error") {
                *error = json!("Stage failed");
            }
            if step.get("source").is_some_and(|source| source != "index") {
                step["source"] = json!("external");
            }
        }
    }
    report
}

async fn run(
    setup: impl Future<Output = Result<Gateway>>,
    resolver: &server::ServerConfig,
    input: &str,
    cache_directory: Option<&Path>,
    deadline: std::time::Duration,
) -> Value {
    TRACE.scope(RefCell::new(Trace::default()), async {
        let mut report = json!({
            "input": input,
            "resolved_id": null,
            "resolution": null,
            "index": {"state": "not_checked"},
            "cache": {"state": "not_checked", "integrity_checked": false},
            "retrieval_mode": "fresh",
            "content": null,
        });
        let preparation = tokio::time::timeout(deadline, async {
            let gateway = setup.await?;
            let id = if decode_fixed::<32>(input, "data ID").is_ok() {
                input.to_owned()
            } else {
                let resolution = check("name_resolution", input, async {
                    server::resolve_arns(&gateway, resolver, input.to_ascii_lowercase())
                        .await?
                        .context("ArNS name is missing or inactive")
                }).await?;
                let id = resolution.resolved_id.clone();
                report["resolution"] = serde_json::to_value(resolution)?;
                id
            };
            report["resolved_id"] = json!(id);
            anyhow::ensure!(resolver.diagnostic_allowed(&id), "Content is blocked");
            let key = decode_fixed::<32>(&id, "data ID")?;
            if let Some(store) = &gateway.block_store {
                match check("index_inspection", &id, store.diagnostic_object(&key)).await {
                    Ok(value) => report["index"] = value,
                    Err(error) => report["index"] = json!({"state": "error", "error": format!("{error:#}")}),
                }
                if let Some(directory) = cache_directory {
                    match check("cache_inspection", &id, inspect_cache(store, directory, &key)).await {
                        Ok(value) => report["cache"] = value,
                        Err(error) => report["cache"] = json!({"state": "error", "integrity_checked": false, "error": format!("{error:#}")}),
                    }
                } else {
                    report["cache"]["state"] = json!("not_configured");
                }
            } else {
                report["index"]["state"] = json!("not_configured");
                report["cache"]["state"] = json!(if cache_directory.is_some() {
                    "database_unavailable"
                } else {
                    "not_configured"
                });
            }
            Ok::<_, anyhow::Error>((gateway, id))
        }).await.context("diagnostic preparation timed out").and_then(|result| result);
        let result = match preparation {
            Ok((gateway, id)) => {
                match check("verified_retrieval", &id, gateway.retrieve(&id)).await {
                    Ok(data) => serde_json::to_value(data).map(|data| report["content"] = data)
                        .map_err(anyhow::Error::from),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        report["status"] = json!(if result.is_ok() { "passed" } else { "failed" });
        report["error"] = json!(result.err().map(|error| format!("{error:#}")));
        TRACE.with(|trace| {
            let trace = trace.borrow();
            report["steps"] = json!(trace.steps);
            report["trace_truncated"] = json!(trace.truncated);
        });
        report
    }).await
}

async fn inspect_cache(
    store: &crate::database::BlockStore,
    directory: &Path,
    id: &[u8; 32],
) -> Result<Value> {
    let Some((metadata, _)) = store.cached_content(id).await? else {
        return Ok(json!({"state": "absent", "integrity_checked": false}));
    };
    let entry: crate::CachedContent = serde_json::from_str(&metadata)?;
    let path = crate::disk_cache::blob_path(directory, entry.blob_hash);
    let state = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_file() && metadata.len() == entry.blob_size as u64 => "present",
        Ok(_) => "file_size_or_type_mismatch",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "file_missing",
        Err(error) => return Err(error.into()),
    };
    Ok(json!({"state": state, "integrity_checked": false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn timeout_preserves_incomplete_resolution_without_claiming_a_missing_name() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(|| async { std::future::pending::<String>().await });
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let mut config = Config::new(
            &url,
            &url,
            vec![url.clone()],
            Duration::from_secs(5),
            1,
            1024,
        )
        .unwrap();
        config.retrieval_timeout = Duration::from_millis(50);
        let resolver = server::ServerConfig::new(
            "127.0.0.1:0",
            "example.com",
            &url,
            "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ",
            "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5",
            1,
        )
        .unwrap();
        let report = diagnose(config, resolver, "example", None, None).await;
        assert_eq!(report["status"], "failed", "{report}");
        assert!(
            report["error"]
                .as_str()
                .unwrap()
                .starts_with("diagnostic preparation timed out:"),
            "{report}"
        );
        assert!(report["resolved_id"].is_null(), "{report}");
        assert!(report["content"].is_null(), "{report}");
        assert!(
            report["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["stage"] == "name_resolution"
                    && step["status"] == "incomplete"
                    && step.get("error").is_none()),
            "{report}"
        );
    }
}
