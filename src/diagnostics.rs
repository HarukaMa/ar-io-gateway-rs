use std::{cell::RefCell, future::Future, path::Path};

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::FutureExt;
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Config, Gateway, decode_fixed, server};

tokio::task_local! {
    static TRACE: RefCell<Trace>;
    static ATTEMPT_PARENT: String;
}

#[derive(Default, Serialize)]
struct Trace {
    steps: Vec<Step>,
    truncated: bool,
    #[serde(skip)]
    public_errors: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FailureDetail {
    label: &'static str,
    value: String,
    monospace: bool,
}

#[derive(Debug)]
pub(crate) struct Failure {
    context: &'static str,
    message: &'static str,
    details: Vec<FailureDetail>,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.context)?;
        for detail in &self.details {
            write!(formatter, ": {} = {}", detail.label, detail.value)?;
        }
        Ok(())
    }
}

impl std::error::Error for Failure {}

fn id_detail(label: &'static str, id: &str) -> FailureDetail {
    FailureDetail {
        label,
        value: decode_fixed::<32>(id, "ID")
            .map(|id| URL_SAFE_NO_PAD.encode(id))
            .unwrap_or_else(|_| "Invalid ID in discovery response".to_owned()),
        monospace: true,
    }
}

fn size_detail(label: &'static str, size: u128) -> FailureDetail {
    FailureDetail {
        label,
        value: format!("{size} bytes"),
        monospace: false,
    }
}

pub(crate) fn wrong_item(expected: &str, received: &str) -> Failure {
    Failure {
        context: "discovery returned the wrong data item",
        message: "The discovery response returned a different item from the one requested.",
        details: vec![
            id_detail("Requested item ID", expected),
            id_detail("Returned item ID", received),
        ],
    }
}

pub(crate) fn size_mismatch(
    context: &'static str,
    id: &[u8; 32],
    reported: u128,
    verified: u128,
) -> Failure {
    Failure {
        context,
        message: "The payload size reported by discovery differs from the verified item size.",
        details: vec![
            id_detail("Item ID", &URL_SAFE_NO_PAD.encode(id)),
            size_detail("Reported payload size", reported),
            size_detail("Verified payload size", verified),
        ],
    }
}

pub(crate) fn size_limit(size: u128, limit: usize) -> Failure {
    Failure {
        context: "transaction exceeds configured data size limit",
        message: "The content size exceeds this gateway's retrieval limit.",
        details: vec![
            size_detail("Content size", size),
            size_detail("Retrieval limit", limit as u128),
        ],
    }
}

fn error_details(error: &anyhow::Error) -> Vec<FailureDetail> {
    fn collect(error: &anyhow::Error, details: &mut Vec<FailureDetail>) {
        for cause in error.chain() {
            if let Some(failure) = cause.downcast_ref::<Failure>() {
                for detail in &failure.details {
                    if details.len() > 32 {
                        return;
                    }
                    if !details.contains(detail) {
                        details.push(detail.clone());
                    }
                }
            } else if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
                for error in &attempts.errors {
                    if details.len() > 32 {
                        return;
                    }
                    collect(error, details);
                }
            }
        }
    }
    let mut details = Vec::new();
    collect(error, &mut details);
    if details.len() > 32 {
        details.truncate(32);
        details.push(FailureDetail {
            label: "Additional details",
            value: "Further failure details were omitted to keep this report bounded.".to_owned(),
            monospace: false,
        });
    }
    details
}

fn error_text(error: &anyhow::Error, public: bool) -> String {
    if !public {
        return format!("{error:#}");
    }
    // Emit only known verifier messages and typed error fields. Raw causes can contain secrets.
    const SAFE_REASONS: &[&str] = &[
        "ArNS name is missing or inactive",
        "ArNS config account is missing",
        "Content is blocked",
        "diagnostic preparation timed out",
        "verified retrieval timed out",
        "verified bundle retrieval timed out",
        "chunk request timed out",
        "content spool budget exhausted",
        "transaction exceeds configured data size limit",
        "transaction exceeds configured size limit",
        "data item exceeds configured data size limit",
        "JSON item exceeds configured data size limit",
        "unsupported transaction format",
        "unsupported or ambiguous bundle format/version",
        "transaction ID mismatch",
        "transaction ID is not the signature hash",
        "transaction signature verification failed",
        "data item signature verification failed",
        "data item ID is not the signature hash",
        "JSON item signature hash differs from ID",
        "transaction data size and root disagree",
        "transaction status and verified size differ",
        "transaction block is above the trusted node tip",
        "archival status does not match the trusted block index",
        "trusted block index returned incomplete geometry",
        "transaction ID is absent from authenticated block",
        "block header height mismatch",
        "block header identifier mismatch",
        "block indep_hash verification failed",
        "block tx_root does not match trusted index",
        "block size does not match trusted weave geometry",
        "block predecessor does not match trusted block index",
        "content block changed during retrieval",
        "cyclic bundle ancestry",
        "bundle discovery path limit exceeded",
        "discovery response exceeds location limit",
        "discovered ancestor is not a supported bundle",
        "discovery returned the wrong data item",
        "a data item cannot be its own parent",
        "bundle item table exceeds parent bounds",
        "bundle item exceeds parent bounds",
        "valid data item is absent from verified parent at the expected offset",
        "tx_path data root mismatch",
        "tx_path is too short",
        "tx_path length is malformed",
        "chunk length does not match data_path",
        "chunk hash does not match data_path",
        "chunk exceeds protocol limit",
        "data_path exceeds size limit",
        "tx_path exceeds size limit",
        "invalid Content-Type tag",
        "invalid Content-Encoding tag",
        "invalid Solana account base64",
        "Solana account size mismatch",
        "Solana account exceeds size limit",
        "ANT record bump mismatch",
        "ANT root record mismatch",
        "ArNS config bump mismatch",
        "Solana RPC request failed",
        "Solana account owner mismatch",
        "Solana data account is executable",
        "unexpected Solana account encoding",
        "ArNS account name mismatch",
        "ArNS record bump mismatch",
        "ArNS name hash mismatch",
        "ANT mint mismatch",
        "ANT record PDA mismatch",
        "duplicate ANT record",
        "block index has not been initialized",
    ];
    let mut details = Vec::new();
    let mut add = |detail: String| {
        if details.len() < 6 && !details.contains(&detail) {
            details.push(detail);
        }
    };
    for cause in error.chain() {
        if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
            for error in &attempts.errors {
                add(error_text(error, true));
            }
            continue;
        }
        if let Some(failure) = cause.downcast_ref::<Failure>() {
            add(failure.message.to_owned());
            continue;
        }
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(status) = http.status() {
                add(format!("Upstream returned HTTP {status}"));
            } else if http.is_timeout() {
                add("Upstream request timed out".to_owned());
            } else if http.is_connect() {
                add("Could not connect to the upstream service".to_owned());
            } else if http.is_body() || http.is_decode() {
                add("Could not read the upstream response body".to_owned());
            }
        } else if cause.is::<tokio::time::error::Elapsed>() {
            add("The operation exceeded its time limit".to_owned());
        } else if let Some(json) = cause.downcast_ref::<serde_json::Error>() {
            add(format!(
                "Invalid JSON ({:?}, line {}, column {})",
                json.classify(),
                json.line(),
                json.column()
            ));
        } else if let Some(database) = cause.downcast_ref::<tokio_postgres::Error>() {
            add(match database.as_db_error() {
                Some(error) => {
                    format!("Database request failed (SQLSTATE {})", error.code().code())
                }
                None => "Database connection or communication failed".to_owned(),
            });
        } else if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            add(format!("I/O operation failed ({:?})", io.kind()));
        } else if cause.is::<crate::ContentNotFound>() {
            add("No L1 transaction was found for this ID".to_owned());
        }
        // Some retrieval paths aggregate attempt errors into a single context string.
        for part in cause.to_string().split([':', ';']).map(str::trim) {
            if SAFE_REASONS.contains(&part) {
                add(part.to_owned());
            } else if part.starts_with("unsupported ANS-104 signature type ") {
                add("The data item's signature type is unsupported".to_owned());
            } else if part.starts_with("nested bundle exceeds maximum depth ") {
                add("Bundle nesting exceeds the supported depth".to_owned());
            }
        }
    }
    if details.is_empty() {
        "The operation failed. Further details are available in the local CLI diagnostic."
            .to_owned()
    } else {
        details.join(". ")
    }
}

#[derive(Serialize)]
struct Step {
    stage: &'static str,
    id: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    details: Vec<FailureDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_parent_id: Option<String>,
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

pub(crate) async fn in_bundle<T>(parent: &[u8], operation: impl Future<Output = T>) -> T {
    if TRACE.try_with(|_| ()).is_err() {
        return operation.await;
    }
    ATTEMPT_PARENT
        .scope(URL_SAFE_NO_PAD.encode(parent), operation)
        .await
}

fn retrieval_unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            http.is_status() || http.is_connect() || http.is_timeout() || http.is_body()
        } else if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
            !attempts.errors.is_empty() && attempts.errors.iter().all(retrieval_unavailable)
        } else {
            cause.is::<tokio::time::error::Elapsed>()
        }
    })
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
                details: Vec::new(),
                message: None,
                parent_id: None,
                source: None,
                attempt_parent_id: ATTEMPT_PARENT.try_with(Clone::clone).ok(),
            })
        })
        .ok()
        .flatten();
    operation.inspect(move |result| {
        if let Some(index) = index {
            let _ = TRACE.try_with(|trace| {
                let mut trace = trace.borrow_mut();
                let public_errors = trace.public_errors;
                let step = &mut trace.steps[index];
                let error = result.as_ref().err();
                step.status = if error.is_none() { "passed" } else { "failed" };
                step.error = error.map(|error| error_text(error, public_errors));
                step.details = error.map(error_details).unwrap_or_default();
                if stage == "bundle_item_verification" && error.is_some_and(retrieval_unavailable) {
                    step.status = "unavailable";
                }
                if stage == "transaction_authentication"
                    && error.is_some_and(|error| error.is::<crate::ContentNotFound>())
                {
                    step.status = "not_found";
                    step.message = Some("No L1 transaction was found for this ID.");
                }
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
            details: Vec::new(),
            message: None,
            parent_id: Some(parent.to_owned()),
            source: Some(source.to_owned()),
            attempt_parent_id: None,
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

pub(crate) fn bundle_parent_fallback(id: &str) {
    let _ = TRACE.try_with(|trace| {
        if let Some(step) = trace.borrow_mut().steps.iter_mut().rev().find(|step| {
            step.stage == "transaction_authentication"
                && step.id == id
                && step.status == "not_found"
        }) {
            step.status = "fallback";
            step.message = Some(
                "No L1 transaction was found. Continuing through the discovered bundle parent.",
            );
        }
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
    run(setup, &resolver, input, cache_directory, deadline, false).await
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
        true,
    )
    .await;
    if let Some(steps) = report["steps"].as_array_mut() {
        for step in steps {
            if let Some(message) = step.get("message").cloned() {
                step["error"] = message;
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
    public_errors: bool,
) -> Value {
    TRACE.scope(RefCell::new(Trace { public_errors, ..Trace::default() }), async {
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
                    Err(error) => report["index"] = json!({"state": "error", "error": error_text(&error, public_errors)}),
                }
                if let Some(directory) = cache_directory {
                    match check("cache_inspection", &id, inspect_cache(store, directory, &key)).await {
                        Ok(value) => report["cache"] = value,
                        Err(error) => report["cache"] = json!({"state": "error", "integrity_checked": false, "error": error_text(&error, public_errors)}),
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
        report["error"] = json!(result.err().map(|error| error_text(&error, public_errors)));
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
    async fn concurrent_bundle_attempts_distinguish_unavailable_data_from_invalid_content() {
        TRACE
            .scope(
                RefCell::new(Trace {
                    public_errors: true,
                    ..Trace::default()
                }),
                async {
                    let unavailable = in_bundle(&[1; 32], async {
                        check_item(&[3; 32], async {
                            tokio::task::yield_now().await;
                            let response = reqwest::Response::from(
                                axum::http::Response::builder()
                                    .status(404)
                                    .body("")
                                    .unwrap(),
                            );
                            response.error_for_status()?;
                            Ok(())
                        })
                        .await
                    });
                    let invalid = in_bundle(&[2; 32], async {
                        tokio::task::yield_now().await;
                        check_item(&[3; 32], async {
                            anyhow::bail!("data item signature verification failed")
                        })
                        .await
                    });
                    let (unavailable, invalid): (Result<()>, Result<()>) =
                        tokio::join!(unavailable, invalid);
                    assert!(unavailable.is_err() && invalid.is_err());
                    let steps =
                        TRACE.with(|trace| serde_json::to_value(&trace.borrow().steps).unwrap());
                    let steps = steps.as_array().unwrap();
                    let missing = steps
                        .iter()
                        .find(|step| step["attempt_parent_id"] == URL_SAFE_NO_PAD.encode([1; 32]))
                        .unwrap();
                    assert_eq!(missing["status"], "unavailable");
                    assert_eq!(missing["error"], "Upstream returned HTTP 404 Not Found");
                    let rejected = steps
                        .iter()
                        .find(|step| step["attempt_parent_id"] == URL_SAFE_NO_PAD.encode([2; 32]))
                        .unwrap();
                    assert_eq!(rejected["status"], "failed");
                    assert_eq!(rejected["error"], "data item signature verification failed");
                    assert!(steps.iter().all(|step| step.get("parent_id").is_none()));
                },
            )
            .await;
    }

    #[test]
    fn failure_details_are_safe_deduplicated_and_bounded() {
        let error: anyhow::Error = wrong_item(
            &URL_SAFE_NO_PAD.encode([7; 32]),
            "https://user:secret@private.invalid/path",
        )
        .into();
        let details = serde_json::to_string(&error_details(&error)).unwrap();
        assert!(!details.contains("secret") && !details.contains("private.invalid"));
        assert!(details.contains("Invalid ID in discovery response"));
        let repeated: anyhow::Error = crate::AttemptFailures {
            context: "repeated attempts",
            errors: (0..100).map(|_| size_limit(100, 1).into()).collect(),
        }
        .into();
        assert_eq!(error_details(&repeated).len(), 2);
        let distinct: anyhow::Error = crate::AttemptFailures {
            context: "distinct attempts",
            errors: (100..200).map(|size| size_limit(size, 1).into()).collect(),
        }
        .into();
        let details = error_details(&distinct);
        assert_eq!(details.len(), 33);
        assert_eq!(details.last().unwrap().label, "Additional details");
    }

    #[test]
    fn public_errors_preserve_verifier_causes_without_exposing_private_context() {
        let error = anyhow::anyhow!("data item signature verification failed")
            .context("https://user:password@private.invalid/rpc?api-key=secret")
            .context("reading C:\\private\\cache\\content");
        assert_eq!(
            error_text(&error, true),
            "data item signature verification failed"
        );
        assert!(error_text(&error, false).contains("api-key=secret"));
        let aggregate = anyhow::anyhow!(
            "transaction metadata unavailable: https://private.invalid/key: transaction ID mismatch; https://private.invalid/other: transaction ID mismatch"
        );
        assert_eq!(error_text(&aggregate, true), "transaction ID mismatch");
        let unknown = anyhow::anyhow!("password=secret at /private/storage/file");
        let public = error_text(&unknown, true);
        assert!(!public.contains("secret") && !public.contains("/private"));
        assert!(public.contains("local CLI"));
    }

    #[tokio::test]
    async fn public_errors_explain_http_status_without_exposing_the_request_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private-key", listener.local_addr().unwrap());
        let app = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "private response body",
            )
        });
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let error = reqwest::get(url)
            .await
            .unwrap()
            .error_for_status()
            .unwrap_err();
        let error: anyhow::Error = crate::AttemptFailures {
            context: "all upstream attempts failed",
            errors: vec![anyhow::Error::from(error).context("https://private.invalid/secret")],
        }
        .into();
        assert_eq!(
            error_text(&error, true),
            "Upstream returned HTTP 429 Too Many Requests"
        );
    }

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
