use std::{cell::RefCell, future::Future, path::Path, time::Instant};

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
    #[serde(skip)]
    started: Option<Instant>,
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
    unavailable: bool,
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
        unavailable: false,
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
        unavailable: false,
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
        unavailable: false,
        details: vec![
            size_detail("Content size", size),
            size_detail("Retrieval limit", limit as u128),
        ],
    }
}

pub(crate) fn missing_chunk(offset: u128) -> Failure {
    Failure {
        context: "streaming chunk not found",
        message: "The required chunk is unavailable from upstream nodes.",
        unavailable: true,
        details: vec![FailureDetail {
            label: "Chunk offset",
            value: offset.to_string(),
            monospace: true,
        }],
    }
}

fn public_ipv4(address: std::net::Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && !address.is_documentation()
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 192 && b == 0 && c == 0)
        && !(a == 198 && (18..=19).contains(&b))
}

fn public_upstream(url: &reqwest::Url) -> Option<String> {
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_matches(['[', ']']);
    let public = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => public_ipv4(address),
        Ok(std::net::IpAddr::V6(address)) => {
            if let Some(address) = address.to_ipv4_mapped() {
                public_ipv4(address)
            } else {
                let segments = address.segments();
                segments[0] & 0xe000 == 0x2000
                    && segments[..2] != [0x2001, 0xdb8]
                    && !(segments[0] == 0x2001 && segments[1] < 0x200)
            }
        }
        Err(_) => {
            let host = host.trim_end_matches('.');
            host.contains('.')
                && ![
                    ".localhost",
                    ".local",
                    ".localdomain",
                    ".internal",
                    ".intranet",
                    ".lan",
                    ".home",
                    ".test",
                    ".invalid",
                    ".example",
                    ".onion",
                ]
                .iter()
                .any(|suffix| host.ends_with(suffix))
        }
    };
    // Endpoint paths and queries can contain credentials, even on public services.
    public.then(|| url.origin().ascii_serialization())
}

fn chunk_offset(url: &reqwest::Url) -> Option<u128> {
    let path = url
        .path()
        .strip_prefix("/chunk2/")
        .or_else(|| url.path().strip_prefix("/chunk/"))?;
    if !path.is_empty() && path.bytes().all(|byte| byte.is_ascii_digit()) {
        path.parse().ok()
    } else {
        None
    }
}

fn http_error_text(error: &reqwest::Error) -> String {
    if let Some(status) = error.status() {
        return format!("Upstream returned HTTP {status}");
    }
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if cause.to_string() == "connection closed before message completed" {
            return "Upstream connection closed before the response completed".to_owned();
        }
        source = cause.source();
    }
    if error.is_timeout() {
        "Upstream request timed out"
    } else if error.is_connect() {
        "Could not connect to the upstream service"
    } else if error.is_body() || error.is_decode() {
        "Could not read the upstream response body"
    } else if error.is_request() {
        "Could not send the upstream request or receive response headers"
    } else if error.is_redirect() {
        "Upstream redirect failed"
    } else if error.is_builder() {
        "Could not construct the upstream request"
    } else {
        "Upstream HTTP operation failed"
    }
    .to_owned()
}

fn error_details(error: &anyhow::Error) -> Vec<FailureDetail> {
    fn add(details: &mut Vec<FailureDetail>, detail: FailureDetail) {
        if details.len() <= 32 && !details.contains(&detail) {
            details.push(detail);
        }
    }
    fn collect(error: &anyhow::Error, details: &mut Vec<FailureDetail>, depth: usize) {
        if depth == 16 {
            add(
                details,
                FailureDetail {
                    label: "Additional details",
                    value: "Further nested causes were omitted.".to_owned(),
                    monospace: false,
                },
            );
            return;
        }
        for cause in error.chain() {
            if details.len() > 32 {
                return;
            }
            if let Some(failure) = cause.downcast_ref::<Failure>() {
                for detail in &failure.details {
                    add(details, detail.clone());
                }
            } else if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
                for error in &attempts.errors {
                    if details.len() > 32 {
                        return;
                    }
                    collect(error, details, depth + 1);
                }
            } else if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
                let reason = http_error_text(http);
                let upstream = http.url().and_then(public_upstream);
                add(
                    details,
                    FailureDetail {
                        label: "Upstream request",
                        value: match upstream {
                            Some(upstream) => format!("{upstream}: {reason}"),
                            None => reason,
                        },
                        monospace: false,
                    },
                );
                if let Some(offset) = http.url().and_then(chunk_offset) {
                    add(
                        details,
                        FailureDetail {
                            label: "Chunk offset",
                            value: offset.to_string(),
                            monospace: true,
                        },
                    );
                }
            }
        }
    }
    let mut details = Vec::new();
    collect(error, &mut details, 0);
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
        "ArNS undername exceeds the allowed limit",
        "Manifest path was not found",
        "manifest exceeds size limit",
        "manifest path exceeds size limit",
        "invalid manifest type",
        "unsupported manifest version",
        "invalid manifest JSON",
        "diagnostic preparation timed out",
        "verified retrieval timed out",
        "Could not read bundle header",
        "HTTP request failed",
        "HTTP source rejected request",
        "empty bundle contains trailing data",
        "bundle contains an empty item",
        "bundle item sizes do not consume the parent",
        "bundle item offset overflow",
        "invalid bundle item ID length",
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
        "data item content ID does not match its content",
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
        "discovery returned an invalid or empty parent bundle ID",
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
    fn collect(error: &anyhow::Error, details: &mut Vec<String>, depth: usize) {
        if depth == 16 || details.len() == 6 {
            return;
        }
        for cause in error.chain() {
            if details.len() == 6 {
                return;
            }
            if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
                for error in &attempts.errors {
                    collect(error, details, depth + 1);
                }
                continue;
            }
            let message = if let Some(failure) = cause.downcast_ref::<Failure>() {
                Some(failure.message.to_owned())
            } else if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
                Some(http_error_text(http))
            } else if cause.is::<tokio::time::error::Elapsed>() {
                Some("The operation exceeded its time limit".to_owned())
            } else if let Some(json) = cause.downcast_ref::<serde_json::Error>() {
                Some(format!(
                    "Invalid JSON ({:?}, line {}, column {})",
                    json.classify(),
                    json.line(),
                    json.column()
                ))
            } else if let Some(database) = cause.downcast_ref::<tokio_postgres::Error>() {
                Some(match database.as_db_error() {
                    Some(error) => {
                        format!("Database request failed (SQLSTATE {})", error.code().code())
                    }
                    None => "Database connection or communication failed".to_owned(),
                })
            } else if let Some(io) = cause.downcast_ref::<std::io::Error>() {
                Some(format!("I/O operation failed ({:?})", io.kind()))
            } else if cause.is::<crate::ContentNotFound>() {
                Some("No L1 transaction was found for this ID".to_owned())
            } else {
                None
            };
            if let Some(message) = message {
                if !details.contains(&message) {
                    details.push(message);
                }
                continue;
            }
            for part in cause.to_string().split([':', ';']).map(str::trim) {
                let message = if SAFE_REASONS.contains(&part) {
                    Some(part)
                } else if part.starts_with("unsupported ANS-104 signature type ") {
                    Some("The data item's signature type is unsupported")
                } else if part.starts_with("nested bundle exceeds maximum depth ") {
                    Some("Bundle nesting exceeds the supported depth")
                } else {
                    None
                };
                if let Some(message) = message {
                    if details.len() == 6 {
                        return;
                    }
                    if !details.iter().any(|detail| detail == message) {
                        details.push(message.to_owned());
                    }
                }
            }
        }
    }
    let mut details = Vec::new();
    collect(error, &mut details, 0);
    if details.is_empty() {
        "The operation failed. Further details are available in the local CLI diagnostic."
            .to_owned()
    } else {
        details.join(". ")
    }
}

pub(crate) fn public_error_text(error: &anyhow::Error) -> String {
    let mut text = error_text(error, true);
    for detail in error_details(error) {
        text.push('\n');
        text.push_str(detail.label);
        text.push_str(": ");
        text.push_str(&detail.value);
    }
    text
}

#[derive(Serialize)]
struct Step {
    stage: &'static str,
    id: String,
    status: &'static str,
    started_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_us: Option<u64>,
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

struct StepTimer {
    index: usize,
    started: Instant,
}

impl StepTimer {
    fn start(stage: &'static str, id: impl FnOnce() -> String) -> Option<Self> {
        TRACE
            .try_with(|trace| {
                let started = Instant::now();
                let mut trace = trace.borrow_mut();
                let started_us = started
                    .duration_since(*trace.started.get_or_insert(started))
                    .as_micros() as u64;
                trace
                    .push(Step {
                        stage,
                        id: id(),
                        status: "incomplete",
                        started_us,
                        elapsed_us: None,
                        error: None,
                        details: Vec::new(),
                        message: None,
                        parent_id: None,
                        source: None,
                        attempt_parent_id: ATTEMPT_PARENT.try_with(Clone::clone).ok(),
                    })
                    .map(|index| Self { index, started })
            })
            .ok()
            .flatten()
    }
}

impl Drop for StepTimer {
    fn drop(&mut self) {
        let _ = TRACE.try_with(|trace| {
            trace.borrow_mut().steps[self.index].elapsed_us =
                Some(self.started.elapsed().as_micros() as u64);
        });
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
            http.is_status()
                || http.is_connect()
                || http.is_timeout()
                || http.is_body()
                || http.is_request()
        } else if let Some(attempts) = cause.downcast_ref::<crate::AttemptFailures>() {
            !attempts.errors.is_empty() && attempts.errors.iter().all(retrieval_unavailable)
        } else if let Some(failure) = cause.downcast_ref::<Failure>() {
            failure.unavailable
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
    let timer = StepTimer::start(stage, || id.to_owned());
    operation.inspect(move |result| {
        if let Some(timer) = timer {
            let _ = TRACE.try_with(|trace| {
                let mut trace = trace.borrow_mut();
                let public_errors = trace.public_errors;
                let step = &mut trace.steps[timer.index];
                let error = result.as_ref().err();
                step.status = if error.is_none() { "passed" } else { "failed" };
                step.error = error.map(|error| error_text(error, public_errors));
                step.details = error.map(error_details).unwrap_or_default();
                if matches!(
                    stage,
                    "bundle_item_verification"
                        | "verified_retrieval"
                        | "content_proofs_and_hash"
                ) && error.is_some_and(retrieval_unavailable)
                {
                    step.status = "unavailable";
                }
                if stage == "transaction_authentication"
                    && error.is_some_and(|error| error.is::<crate::ContentNotFound>())
                {
                    step.status = "not_found";
                    step.message = Some("No L1 transaction was found for this ID.");
                }
            });
            drop(timer);
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

pub(crate) struct ChunkAttempt {
    timer: Option<StepTimer>,
}

impl ChunkAttempt {
    pub(crate) fn new(offset: u128, source: &str) -> Self {
        let attempt = Self {
            timer: StepTimer::start("chunk_retrieval", || offset.to_string()),
        };
        attempt.update(|step, public| {
            step.status = "downloading";
            let node = if public {
                reqwest::Url::parse(source)
                    .ok()
                    .and_then(|url| public_upstream(&url))
                    .unwrap_or_else(|| "Private upstream".to_owned())
            } else {
                source.to_owned()
            };
            step.details.push(FailureDetail {
                label: "Node",
                value: node,
                monospace: true,
            });
        });
        attempt
    }

    fn update(&self, operation: impl FnOnce(&mut Step, bool)) {
        if let Some(timer) = &self.timer {
            let _ = TRACE.try_with(|trace| {
                let mut trace = trace.borrow_mut();
                let public = trace.public_errors;
                operation(&mut trace.steps[timer.index], public);
            });
        }
    }

    pub(crate) fn downloaded(&self, packing: crate::packing::Packing, bytes: usize) {
        self.update(|step, _| {
            step.status = "downloaded";
            step.details.push(FailureDetail {
                label: "Packing",
                value: match packing {
                    crate::packing::Packing::Unpacked => "unpacked",
                    crate::packing::Packing::Replica29(_) => "replica_2_9",
                }
                .to_owned(),
                monospace: true,
            });
            step.details.push(FailureDetail {
                label: "Chunk bytes received",
                value: bytes.to_string(),
                monospace: false,
            });
        });
    }

    pub(crate) fn verifying(&self) {
        self.update(|step, _| step.status = "verifying");
    }

    pub(crate) fn verified(&self, bytes: usize) {
        self.update(|step, _| {
            step.status = "verified";
            step.details.push(FailureDetail {
                label: "Chunk verification",
                value: "Passed".to_owned(),
                monospace: false,
            });
            step.details.push(FailureDetail {
                label: "Verified bytes",
                value: bytes.to_string(),
                monospace: false,
            });
        });
    }

    pub(crate) fn failed(&self, error: &anyhow::Error) {
        self.update(|step, public| {
            step.status = if retrieval_unavailable(error) {
                "unavailable"
            } else {
                "failed"
            };
            step.error = Some(error_text(error, public));
            for detail in error_details(error) {
                if !step.details.contains(&detail) {
                    step.details.push(detail);
                }
            }
        });
    }

    pub(crate) fn selected(self) {
        self.update(|step, _| step.status = "selected");
    }
}

impl Drop for ChunkAttempt {
    fn drop(&mut self) {
        self.update(|step, _| {
            match step.status {
                "verified" => step.status = "unused",
                "downloading" | "downloaded" | "verifying" => {
                    step.details.push(FailureDetail {
                        label: "Stopped during",
                        value: match step.status {
                            "downloading" => "Download",
                            "downloaded" => "Waiting for verification",
                            _ => "Unpacking and verification",
                        }
                        .to_owned(),
                        monospace: false,
                    });
                    step.status = "cancelled";
                }
                _ => {}
            }
        });
    }
}

pub(crate) fn location(id: &str, parent: &str, source: &str) {
    let _ = TRACE.try_with(|trace| {
        let started = Instant::now();
        let mut trace = trace.borrow_mut();
        let started_us = started
            .duration_since(*trace.started.get_or_insert(started))
            .as_micros() as u64;
        trace.push(Step {
            stage: "bundle_location",
            id: id.to_owned(),
            status: "discovered",
            started_us,
            elapsed_us: Some(0),
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
            gateway.block_store = Some(std::sync::Arc::new(
                check("database_connection", input, store.reconnect()).await?,
            ));
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
            if let Some(source) = step.get("source").and_then(Value::as_str) {
                if source != "index" {
                    step["source"] = json!(
                        reqwest::Url::parse(source)
                            .ok()
                            .as_ref()
                            .and_then(public_upstream)
                            .unwrap_or_else(|| "external".to_owned())
                    );
                }
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
    let profile = crate::profiling::Profile::diagnostic();
    profile.phase(1);
    let mut report = crate::profiling::scope(Some(profile.clone()), TRACE.scope(RefCell::new(Trace {
        public_errors,
        started: Some(Instant::now()),
        ..Trace::default()
    }), async {
        let mut report = json!({
            "input": input,
            "resolved_id": null,
            "resolution": null,
            "root_id": null,
            "request_path": null,
            "manifest": null,
            "index": {"state": "not_checked"},
            "cache": {"state": "not_checked", "integrity_checked": false},
            "retrieval_mode": "fresh",
            "content": null,
        });
        let preparation = tokio::time::timeout(deadline, async {
            let (target, path) = check("input_resolution", input, async {
                resolver.diagnostic_target(input)
            }).await?;
            report["request_path"] = json!(path);
            let gateway = setup.await?;
            gateway.ensure_allowed(&target, None).await?;
            let mut id = if decode_fixed::<32>(&target, "data ID").is_ok() {
                target.clone()
            } else {
                let resolution = check("name_resolution", &target, async {
                    server::resolve_arns(&gateway, resolver, target.clone()).await?
                        .context("ArNS name is missing or inactive")
                }).await?;
                anyhow::ensure!(resolution.index <= usize::from(resolution.limit), "ArNS undername exceeds the allowed limit");
                let id = resolution.resolved_id.clone();
                report["resolution"] = serde_json::to_value(resolution)?;
                id
            };
            report["resolved_id"] = json!(id);
            gateway.ensure_allowed(&id, None).await?;
            report["root_id"] = json!(id);
            let mut retrieved = None;
            if let Some(path) = path {
                let root = check("verified_retrieval", &id, gateway.retrieve(&id)).await?;
                gateway.ensure_allowed(&root.id, Some(root.etag.trim_matches('"'))).await?;
                if server::is_manifest_content_type(&root.content_type) {
                    report["manifest"] = json!({"id": id, "path": path, "target_id": null});
                    let resolved = check("manifest_resolution", &id, async {
                        server::resolve_manifest_content(&root, &path).await?
                            .context("Manifest path was not found")
                    }).await?;
                    report["manifest"]["target_id"] = json!(resolved.id);
                    report["manifest"]["fallback"] = json!(resolved.fallback);
                    id = resolved.id;
                    report["resolved_id"] = json!(id);
                    gateway.ensure_allowed(&id, None).await?;
                } else {
                    retrieved = Some(root);
                }
            }
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
            Ok::<_, anyhow::Error>((gateway, id, retrieved))
        }).await.context("diagnostic preparation timed out").and_then(|result| result);
        let result = match preparation {
            Ok((gateway, id, retrieved)) => {
                let content = match retrieved {
                    Some(data) => Ok(data),
                    None => check("verified_retrieval", &id, gateway.retrieve(&id)).await,
                };
                async {
                    let data = content?;
                    gateway.ensure_allowed(&data.id, Some(data.etag.trim_matches('"'))).await?;
                    report["content"] = json!(data);
                    Ok(())
                }.await
            }
            Err(error) => Err(error),
        };
        let error = result.as_ref().err();
        report["status"] = json!(if error.is_some_and(retrieval_unavailable) {
            "unavailable"
        } else if error.is_some() {
            "failed"
        } else {
            "passed"
        });
        report["error"] = json!(error.map(|error| error_text(error, public_errors)));
        report["error_details"] = json!(error.map(error_details).unwrap_or_default());
        TRACE.with(|trace| {
            let trace = trace.borrow();
            report["steps"] = json!(trace.steps);
            report["trace_truncated"] = json!(trace.truncated);
        });
        report
    })).await;
    profile.finish(if report["status"] == "passed" {
        "passed"
    } else {
        "failed"
    });
    let mut snapshot = profile.snapshot("finished");
    let mut stages = snapshot["stages"].take();
    if public_errors && let Some(stages) = stages.as_object_mut() {
        stages.retain(|name, _| !name.starts_with("origin:"));
    }
    report["timings"] = json!({
        "elapsed_us": snapshot["elapsed_us"],
        "stages": stages,
    });
    report
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
    if entry.stream.is_some() {
        return Ok(json!({"state": "chunk_backed", "integrity_checked": false}));
    }
    let path = crate::disk_cache::blob_path(directory, entry.digest);
    let state = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_file() && metadata.len() == entry.length as u64 => "present",
        Ok(_) => "file_size_or_type_mismatch",
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "file_missing",
        Err(error) => return Err(error.into()),
    };
    Ok(json!({"state": state, "integrity_checked": false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;

    #[tokio::test]
    #[ignore = "requires ar_io_rust_test; inserts and removes blocking fixtures"]
    async fn site_diagnostics_resolve_manifest_paths_and_enforce_target_blocks() {
        let manifest_id = URL_SAFE_NO_PAD.encode([7; 32]);
        let asset_id = URL_SAFE_NO_PAD.encode([8; 32]);
        let make_gateway = |include_asset: bool| {
            let config = Config::new(
                "http://127.0.0.1:1",
                "http://127.0.0.1:1",
                vec!["http://127.0.0.1:1".into()],
                Duration::from_secs(1),
                1,
                65536,
            )
            .unwrap();
            let gateway = Gateway::new(config).unwrap();
            let manifest = serde_json::to_vec(&json!({
                "manifest": "arweave/paths", "version": "0.1.0",
                "index": {"path": "font file.woff"},
                "paths": {"font file.woff": {"id": asset_id}}
            }))
            .unwrap();
            for (id, bytes, content_type) in [
                (
                    manifest_id.clone(),
                    manifest,
                    "application/x.arweave-manifest+json",
                ),
                (asset_id.clone(), b"font payload".to_vec(), "font/woff"),
            ] {
                if id == asset_id && !include_asset {
                    continue;
                }
                let digest = Sha256::digest(&bytes);
                let data = crate::VerifiedData {
                    id,
                    content_length: bytes.len(),
                    bytes: bytes.into(),
                    cache_hit: false,
                    block_height: 1,
                    block_hash: None,
                    stable_anchor: true,
                    content_type: content_type.into(),
                    content_encoding: None,
                    etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(digest)),
                    sha256: crate::hex(&digest),
                    indexing_root: None,
                };
                gateway.cache.lock().unwrap().insert(data, 8, 65536);
            }
            gateway
        };
        let resolver = server::ServerConfig::new(
            "127.0.0.1:0",
            "example.com",
            "http://127.0.0.1:1",
            "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ",
            "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5",
            1,
        )
        .unwrap();
        let url = format!("https://foreign.invalid/{manifest_id}/font%20file.woff");
        let report = run(
            async { Ok(make_gateway(true)) },
            &resolver,
            &url,
            None,
            Duration::from_secs(2),
            true,
        )
        .await;
        assert_eq!(report["status"], "passed", "{report}");
        assert_eq!(report["root_id"], manifest_id);
        assert_eq!(report["resolved_id"], asset_id);
        assert_eq!(report["content"]["content_type"], "font/woff");
        assert_eq!(report["manifest"]["path"], "font file.woff");

        let missing = format!("https://foreign.invalid/{manifest_id}/missing.woff");
        let report = run(
            async { Ok(make_gateway(true)) },
            &resolver,
            &missing,
            None,
            Duration::from_secs(2),
            true,
        )
        .await;
        assert_eq!(report["error"], "Manifest path was not found");
        assert!(
            report["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["stage"] == "manifest_resolution" && step["status"] == "failed")
        );

        let report = run(
            async { Ok(make_gateway(false)) },
            &resolver,
            &url,
            None,
            Duration::from_secs(2),
            true,
        )
        .await;
        assert_eq!(report["status"], "failed");
        assert_eq!(report["resolved_id"], asset_id);
        assert!(
            report["steps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|step| step["stage"] == "verified_retrieval"
                    && step["id"] == asset_id
                    && step["status"] != "passed")
        );

        let database_url = std::env::var("DATABASE_URL").unwrap();
        let (policy, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let database: String = policy
            .query_one("SELECT current_database()", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(database, "ar_io_rust_test");
        let mut store = crate::database::BlockStore::connect(&database_url)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let store = std::sync::Arc::new(store);
        policy
            .execute(
                "INSERT INTO public.content_blocklist(kind,value) VALUES('id',$1)",
                &[&asset_id],
            )
            .await
            .unwrap();
        let mut gateway = make_gateway(true);
        gateway.block_store = Some(store.clone());
        let report = run(
            async { Ok(gateway) },
            &resolver,
            &url,
            None,
            Duration::from_secs(2),
            true,
        )
        .await;
        assert_eq!(report["status"], "failed");
        assert_eq!(report["error"], "Content is blocked");
        assert!(report["content"].is_null());

        policy
            .execute(
                "DELETE FROM public.content_blocklist WHERE kind='id' AND value=$1",
                &[&asset_id],
            )
            .await
            .unwrap();
        let mut gateway = make_gateway(true);
        gateway.block_store = Some(store);
        let hash = gateway
            .cache
            .lock()
            .unwrap()
            .get(&manifest_id)
            .unwrap()
            .etag
            .trim_matches('"')
            .to_owned();
        policy
            .execute(
                "INSERT INTO public.content_blocklist(kind,value) VALUES('hash',$1)",
                &[&hash],
            )
            .await
            .unwrap();
        let report = run(
            async { Ok(gateway) },
            &resolver,
            &url,
            None,
            Duration::from_secs(2),
            true,
        )
        .await;
        assert_eq!(report["error"], "Content is blocked");
        assert!(report["manifest"].is_null());
        assert!(report["content"].is_null());
        policy
            .execute(
                "DELETE FROM public.content_blocklist WHERE kind='hash' AND value=$1",
                &[&hash],
            )
            .await
            .unwrap();
    }

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
    fn public_upstream_details_remove_credentials_and_private_locations() {
        for (input, expected) in [
            (
                "http://38.29.227.75:1984/chunk2/123?key=secret",
                "http://38.29.227.75:1984",
            ),
            (
                "https://user:password@arweave.net/private-key?api-key=secret#secret",
                "https://arweave.net",
            ),
            ("https://arweave.net./rpc", "https://arweave.net."),
            (
                "https://[2606:4700:4700::1111]/private-key",
                "https://[2606:4700:4700::1111]",
            ),
        ] {
            let url = reqwest::Url::parse(input).unwrap();
            assert_eq!(public_upstream(&url).as_deref(), Some(expected), "{input}");
        }
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "192.0.2.1",
            "[::1]",
            "[fd00::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
            "[2001:db8::1]",
            "localhost",
            "private",
            "rpc.local",
            "rpc.internal",
            "private.invalid",
        ] {
            let url = reqwest::Url::parse(&format!("http://{host}/secret")).unwrap();
            assert!(public_upstream(&url).is_none(), "{host}");
        }
        for path in [
            "/chunk/123/secret",
            "/private-key",
            "/chunk2/secret",
            "/chunk2/+1",
        ] {
            let url = reqwest::Url::parse(&format!("https://arweave.net{path}")).unwrap();
            assert!(chunk_offset(&url).is_none(), "{path}");
        }
    }

    #[tokio::test]
    async fn missing_stream_chunk_reports_the_offset_and_upstream_404() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!(
            "http://user:password@arweave.net:{}/private-key",
            address.port()
        );
        let app = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::NOT_FOUND,
                "private upstream response",
            )
        });
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let mut gateway = Gateway::new(
            Config::new(
                &url,
                &url,
                vec![url.clone()],
                Duration::from_secs(2),
                1,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        gateway.client = reqwest::Client::builder()
            .no_proxy()
            .resolve("arweave.net", address)
            .build()
            .unwrap();
        let offset = 253736678629623;
        let source = crate::streaming::ChunkSource::new(
            &gateway,
            crate::Geometry {
                tx_root: [0; 32],
                data_root: [0; 32],
                block_weave_size: offset + 64,
                previous_weave_size: offset,
                first_offset: offset,
                end_offset: offset + 64,
                data_size: 64,
            },
        );
        let content = crate::content::Content::streamed(source, 64);
        TRACE
            .scope(
                RefCell::new(Trace {
                    public_errors: true,
                    ..Trace::default()
                }),
                async {
                    let result = in_bundle(
                        &[2; 32],
                        check_item(&[3; 32], async {
                            content
                                .read_at(0, 32)
                                .await
                                .context("Could not read bundle header")
                        }),
                    )
                    .await;
                    let error = result.unwrap_err();
                    let steps =
                        TRACE.with(|trace| serde_json::to_value(&trace.borrow().steps).unwrap());
                    let verification = steps
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|step| step["stage"] == "bundle_item_verification")
                        .unwrap();
                    assert_eq!(verification["status"], "unavailable");
                    assert!(
                        verification["error"]
                            .as_str()
                            .unwrap()
                            .contains("The required chunk is unavailable from upstream nodes")
                    );
                    assert!(
                        verification["details"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|detail| detail["label"] == "Chunk offset"
                                && detail["value"] == offset.to_string())
                    );
                    let fetch = steps
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|step| step["stage"] == "chunk_retrieval")
                        .unwrap();
                    assert_eq!(fetch["id"], offset.to_string());
                    assert_eq!(fetch["status"], "unavailable");
                    assert_eq!(fetch["error"], "Upstream returned HTTP 404 Not Found");
                    assert_eq!(fetch["attempt_parent_id"], URL_SAFE_NO_PAD.encode([2; 32]));
                    let upstream = format!(
                        "http://arweave.net:{}: Upstream returned HTTP 404 Not Found",
                        address.port()
                    );
                    assert!(
                        fetch["details"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|detail| detail["label"] == "Upstream request"
                                && detail["value"] == upstream)
                    );
                    let serialized = serde_json::to_string(&steps).unwrap();
                    assert!(
                        !serialized.contains("password")
                            && !serialized.contains("private-key")
                            && !serialized.contains("private upstream response")
                    );
                    let shared: anyhow::Error = crate::RetrievalFailure::from(error).into();
                    assert!(retrieval_unavailable(&shared));
                    let public = public_error_text(&shared);
                    assert!(public.contains(&format!("Chunk offset: {offset}")));
                    assert!(
                        !public.contains("127.0.0.1")
                            && !public.contains("private upstream response")
                    );
                },
            )
            .await;
    }

    #[tokio::test]
    async fn chunk_attempts_show_rejected_used_and_cancelled_responses() {
        use std::sync::Arc;
        let payload = b"verified chunk bytes";
        let mut end = [0; 32];
        end[16..].copy_from_slice(&(payload.len() as u128).to_be_bytes());
        let hash = crate::sha256(&[payload]);
        let data_root = crate::hash_leaf(&hash, &end);
        let tx_root = crate::hash_leaf(&data_root, &end);
        let response = |hash: [u8; 32]| {
            serde_json::to_vec(&json!({
                "chunk": crate::URL_SAFE_NO_PAD.encode(payload),
                "data_path": crate::URL_SAFE_NO_PAD.encode([hash.as_slice(), end.as_slice()].concat()),
                "tx_path": crate::URL_SAFE_NO_PAD.encode([data_root.as_slice(), end.as_slice()].concat()),
            })).unwrap()
        };
        let valid = response(hash);
        let invalid = response([0; 32]);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let valid = valid.clone();
            let invalid = invalid.clone();
            let barrier = Arc::clone(&barrier);
            async move {
                let host = request.headers().get("host").unwrap().to_str().unwrap().to_owned();
                barrier.wait().await;
                if host.starts_with("stalled.example.com") {
                    std::future::pending::<()>().await;
                }
                if host.starts_with("valid.example.com") {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    (axum::http::StatusCode::OK, valid)
                } else {
                    (axum::http::StatusCode::OK, invalid)
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let sources = vec![
            format!("http://user:password@invalid.example.com:{}/private-key?api-key=secret", address.port()),
            format!("http://valid.example.com:{}", address.port()),
            format!("http://stalled.example.com:{}", address.port()),
        ];
        let mut gateway = Gateway::new(Config::new(
            &sources[1], &sources[1], sources.clone(),
            std::time::Duration::from_secs(20), 3, 1024,
        ).unwrap()).unwrap();
        gateway.client = reqwest::Client::builder()
            .no_proxy()
            .resolve("invalid.example.com", address)
            .resolve("valid.example.com", address)
            .resolve("stalled.example.com", address)
            .build().unwrap();
        let geometry = crate::BlockGeometry {
            tx_root,
            block_weave_size: 1100,
            previous_weave_size: 1000,
        };
        TRACE.scope(RefCell::new(Trace {
            public_errors: true,
            ..Trace::default()
        }), async {
            let fetched = gateway.fetch_verified_chunk_inner(1001, geometry).await.unwrap().unwrap();
            assert_eq!(fetched.proof.bytes.as_ref(), payload);
            let steps = TRACE.with(|trace| serde_json::to_value(&trace.borrow().steps).unwrap());
            let attempt = |name: &str| {
                steps.as_array().unwrap().iter().find(|step| {
                    step["details"].as_array().unwrap().iter().any(|detail| {
                        detail["label"] == "Node" && detail["value"].as_str().unwrap().contains(name)
                    })
                }).unwrap()
            };
            assert_eq!(attempt("invalid.example.com")["status"], "failed");
            assert!(attempt("invalid.example.com")["details"].as_array().unwrap().iter()
                .any(|detail| detail["label"] == "Packing" && detail["value"] == "unpacked"));
            assert_eq!(attempt("valid.example.com")["status"], "selected");
            assert!(attempt("valid.example.com")["details"].as_array().unwrap().iter()
                .any(|detail| detail["label"] == "Verified bytes" && detail["value"] == payload.len().to_string()));
            assert_eq!(attempt("stalled.example.com")["status"], "cancelled");
            assert!(attempt("stalled.example.com")["details"].as_array().unwrap().iter()
                .any(|detail| detail["label"] == "Stopped during" && detail["value"] == "Download"));
            let serialized = serde_json::to_string(&steps).unwrap();
            assert!(!serialized.contains("password") && !serialized.contains("secret"));
            assert!(!serialized.contains("private-key"));
        }).await;
    }

    #[tokio::test]
    async fn incomplete_http_headers_report_the_public_node_and_unavailable_verification() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                tokio::io::AsyncReadExt::read(&mut socket, &mut request)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(
                    &mut socket,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n",
                )
                .await
                .unwrap();
                tokio::io::AsyncWriteExt::shutdown(&mut socket)
                    .await
                    .unwrap();
            }
        }));
        let http = reqwest::Client::new()
            .get(url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap_err();
        assert!(http.is_request(), "{http:?}");
        let http = http.with_url(
            reqwest::Url::parse(
                "http://user:password@38.29.227.75:1984/chunk2/253736678629623?api-key=secret",
            )
            .unwrap(),
        );
        let error: anyhow::Error = crate::AttemptFailures {
            context: "all chunk candidates failed",
            errors: vec![http.into()],
        }
        .into();
        let error: anyhow::Error = crate::RetrievalFailure::from(error).into();
        let error: anyhow::Error = crate::AttemptFailures {
            context: "all discovered bundle paths failed",
            errors: vec![error.context("Could not read bundle header")],
        }
        .into();
        let details = public_error_text(&error);
        assert!(
            details.contains("Could not read bundle header"),
            "{details}"
        );
        assert!(
            details.contains("Upstream connection closed before the response completed"),
            "{details}"
        );
        assert!(details.contains("http://38.29.227.75:1984"), "{details}");
        assert!(
            details.contains("Chunk offset: 253736678629623"),
            "{details}"
        );
        assert!(!details.contains("password") && !details.contains("secret"));
        assert!(!details.contains("127.0.0.1"));
        TRACE
            .scope(
                RefCell::new(Trace {
                    public_errors: true,
                    ..Trace::default()
                }),
                async {
                    let result: Result<()> = check_item(&[7; 32], async { Err(error) }).await;
                    let steps =
                        TRACE.with(|trace| serde_json::to_value(&trace.borrow().steps).unwrap());
                    assert_eq!(steps[0]["status"], "unavailable");
                    assert!(
                        steps[0]["details"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|detail| detail["label"] == "Chunk offset"
                                && detail["value"] == "253736678629623")
                    );
                    let mixed: anyhow::Error = crate::AttemptFailures {
                        context: "mixed bundle failures",
                        errors: vec![
                            result.unwrap_err(),
                            anyhow::anyhow!("data item signature verification failed"),
                        ],
                    }
                    .into();
                    assert!(!retrieval_unavailable(&mixed));
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
    async fn public_diagnostic_explains_missing_parent_location() {
        let id = URL_SAFE_NO_PAD.encode([7; 32]);
        let response = json!({"data": {"transactions": {"edges": [{
            "node": {"id": id, "bundledIn": {"id": ""}, "data": {"size": "12862"}}
        }]}}});
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/graphql/private-key",
            axum::routing::post(move || {
                let response = response.clone();
                async move { axum::Json(response) }
            }),
        );
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
        config.graphql_sources = vec![format!("{url}/graphql/private-key")];
        let gateway = Gateway::new(config).unwrap();
        let resolver = server::ServerConfig::new(
            "127.0.0.1:0",
            "example.com",
            &url,
            "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ",
            "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5",
            1,
        )
        .unwrap();
        let report = diagnose_public(&gateway, &resolver, &id).await;
        let reason = "discovery returned an invalid or empty parent bundle ID";
        assert_eq!(report["status"], "failed", "{report}");
        assert_eq!(report["error"], reason, "{report}");
        assert!(report["content"].is_null());
        let discovery = report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["stage"] == "bundle_discovery")
            .unwrap();
        assert_eq!(discovery["error"], reason);
        assert!(!report.to_string().contains("private-key"));
        assert!(!report.to_string().contains(&url));
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
        assert_eq!(report["status"], "unavailable", "{report}");
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
        let resolution = report["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["stage"] == "name_resolution")
            .unwrap();
        let started = resolution["started_us"].as_u64().unwrap();
        let elapsed = resolution["elapsed_us"].as_u64().unwrap();
        let remaining = 50_000_u64.saturating_sub(started);
        assert!(elapsed >= remaining.saturating_sub(10_000), "{report}");
        assert!(
            started + elapsed <= report["timings"]["elapsed_us"].as_u64().unwrap(),
            "{report}"
        );
    }
}
