use std::{
    collections::HashSet,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
        header::{CACHE_CONTROL, HOST},
        uri::Authority,
    },
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use parking_lot::Mutex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{Instant as StreamInstant, MissedTickBehavior, interval, sleep_until},
};
use tokio_util::io::ReaderStream;

use super::{
    Config, Gateway, VerifiedChunk, VerifiedData,
    content::{Content, ContentReader},
    decode_fixed,
};

const ARNS_CONFIG_DISCRIMINATOR: [u8; 8] = [117, 20, 158, 16, 49, 85, 82, 24];
const ARNS_RECORD_DISCRIMINATOR: [u8; 8] = [53, 158, 42, 125, 7, 132, 104, 188];
const ANT_RECORD_DISCRIMINATOR: [u8; 8] = [225, 94, 70, 240, 82, 45, 135, 81];
const ARNS_CONFIG_SEED: &[u8] = b"arns_config";
const ARNS_RECORD_SEED: &[u8] = b"arns_record";
const ANT_RECORD_SEED: &[u8] = b"ant_record";
const MAX_SOLANA_ACCOUNT_BYTES: usize = 4096;
const MAX_ANT_RECORDS: usize = 1024;
const MANIFEST_CONTENT_TYPE: &str = "application/x.arweave-manifest+json";
const MAX_MANIFEST_BYTES: usize = 10 * 1024 * 1024;
const MAX_MANIFEST_PATH_BYTES: usize = 4096;
const RESPONSE_CHUNK_BYTES: usize = 64 * 1024;
// ponytail: cap Range parsing and multipart bookkeeping; raise only for a measured client need.
const MAX_RANGE_HEADER_BYTES: usize = 8 * 1024;
const MAX_BYTE_RANGES: usize = 16;

pub struct ServerConfig {
    listen_addr: SocketAddr,
    arns_root_host: String,
    solana_rpc_url: Url,
    core_program_id: String,
    gar_program_id: String,
    arns_program_id: String,
    ant_program_id: String,
    max_concurrent_requests: usize,
    bundler_urls: Vec<String>,
    wallet: Option<String>,
    max_expected_data_item_indexing_interval_seconds: Option<u64>,
    signer: Option<HttpSigner>,
}

impl ServerConfig {
    pub fn new(
        listen_addr: &str,
        arns_root_host: &str,
        solana_rpc_url: &str,
        arns_program_id: &str,
        ant_program_id: &str,
        max_concurrent_requests: usize,
    ) -> Result<Self> {
        let listen_addr = listen_addr.parse().context("invalid AR_IO_LISTEN_ADDR")?;
        let arns_root_host = arns_root_host.trim_end_matches('.').to_ascii_lowercase();
        validate_host(&arns_root_host)?;
        let solana_rpc_url = Url::parse(solana_rpc_url).context("invalid SOLANA_RPC_URL")?;
        ensure!(
            matches!(solana_rpc_url.scheme(), "http" | "https"),
            "SOLANA_RPC_URL must use HTTP or HTTPS"
        );
        decode_pubkey(arns_program_id, "ArNS program ID")?;
        decode_pubkey(ant_program_id, "ANT program ID")?;
        ensure!(
            max_concurrent_requests > 0,
            "AR_IO_MAX_CONCURRENT_REQUESTS must be positive"
        );

        Ok(Self {
            listen_addr,
            arns_root_host,
            solana_rpc_url,
            core_program_id: "73YoECm6NKXpVRoe5f1Q9BcP5DJGPFUjnFy6AxBE5Nvh".to_owned(),
            gar_program_id: "89fNiiwgpFSPHKuqfNUkgYTYjtAJAhyqHjXmgXeppGpf".to_owned(),
            arns_program_id: arns_program_id.to_owned(),
            ant_program_id: ant_program_id.to_owned(),
            max_concurrent_requests,
            bundler_urls: vec!["https://turbo.ardrive.io/".to_owned()],
            wallet: None,
            max_expected_data_item_indexing_interval_seconds: None,
            signer: None,
        })
    }

    pub fn with_info(
        mut self,
        core_program_id: Option<&str>,
        gar_program_id: Option<&str>,
        bundler_urls: Option<&str>,
        wallet: Option<&str>,
        max_expected_data_item_indexing_interval_seconds: Option<u64>,
    ) -> Result<Self> {
        if let Some(program_id) = core_program_id {
            decode_pubkey(program_id, "ARIO_CORE_PROGRAM_ID")?;
            self.core_program_id = program_id.to_owned();
        }
        if let Some(program_id) = gar_program_id {
            decode_pubkey(program_id, "ARIO_GAR_PROGRAM_ID")?;
            self.gar_program_id = program_id.to_owned();
        }
        if let Some(urls) = bundler_urls {
            self.bundler_urls = urls
                .split(',')
                .map(|url| {
                    let url = url.trim();
                    let parsed = Url::parse(url).context("invalid URL in BUNDLER_URLS")?;
                    ensure!(
                        matches!(parsed.scheme(), "http" | "https"),
                        "BUNDLER_URLS must use HTTP or HTTPS"
                    );
                    ensure!(
                        parsed.username().is_empty()
                            && parsed.password().is_none()
                            && parsed.fragment().is_none(),
                        "BUNDLER_URLS must not contain credentials or fragments"
                    );
                    Ok(url.to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
        }
        if let Some(wallet) = wallet {
            decode_pubkey(wallet, "AR_IO_WALLET")?;
            ensure!(
                self.signer
                    .as_ref()
                    .is_none_or(|signer| signer.address == wallet),
                "AR_IO_WALLET does not match the signing wallet"
            );
            self.wallet = Some(wallet.to_owned());
        }
        self.max_expected_data_item_indexing_interval_seconds =
            max_expected_data_item_indexing_interval_seconds;
        Ok(self)
    }

    pub fn with_signing(
        mut self,
        wallet: &str,
        keypair: &[u8; 64],
        bind_request: bool,
    ) -> Result<Self> {
        let key = SigningKey::from_keypair_bytes(keypair).context("invalid signing keypair")?;
        let address = bs58::encode(key.verifying_key().as_bytes()).into_string();
        ensure!(address == wallet, "signing key does not match AR_IO_WALLET");
        let key_id = format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        );
        self.signer = Some(HttpSigner {
            key,
            address,
            key_id,
            bind_request,
        });
        self.wallet = Some(wallet.to_owned());
        Ok(self)
    }
}

struct AppState {
    gateway: Gateway,
    config: ServerConfig,
    request_permits: Arc<Semaphore>,
    started_at: Instant,
}

struct Resolution {
    name: String,
    basename: String,
    record: String,
    resolved_id: String,
    ttl: u32,
    ant_id: String,
    limit: u16,
    index: usize,
    resolved_at: u128,
}

#[derive(Deserialize)]
struct Manifest {
    manifest: String,
    version: String,
    #[serde(default)]
    index: serde_json::Value,
    #[serde(default)]
    fallback: serde_json::Value,
    #[serde(default)]
    paths: serde_json::Map<String, serde_json::Value>,
}

struct ManifestResolution {
    id: String,
    fallback: bool,
}

#[derive(Serialize)]
struct ChunkJsonResponse<'a> {
    chunk: &'a str,
    data_path: &'a str,
    tx_path: &'a str,
    packing: &'static str,
}

struct ArnsRecord<'a> {
    name: &'a str,
    ant: [u8; 32],
    undername_limit: u16,
    end_timestamp: Option<i64>,
    bump: u8,
}

struct AntRecord {
    undername: String,
    target: String,
    target_protocol: u8,
    ttl: u32,
    priority: Option<u32>,
    bump: u8,
}

pub async fn serve(gateway: Gateway, config: ServerConfig) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .context("failed to bind HTTP listener")?;
    println!("listening on http://{}", listener.local_addr()?);
    let state = Arc::new(AppState {
        request_permits: Arc::new(Semaphore::new(config.max_concurrent_requests)),
        started_at: Instant::now(),
        gateway,
        config,
    });
    let mut refresh_tasks = JoinSet::new();
    let node_state = state.clone();
    refresh_tasks.spawn(async move {
        let mut ticks = interval(Duration::from_secs(10 * 60));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            if let Err(error) = node_state.gateway.peers.refresh_arweave().await {
                eprintln!("Arweave peer refresh failed: {error:#}");
            }
        }
    });
    let gateway_state = state.clone();
    refresh_tasks.spawn(async move {
        let mut ticks = interval(Duration::from_secs(60 * 60));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticks.tick().await;
            if let Err(error) = gateway_state
                .gateway
                .peers
                .refresh_gateways(
                    &gateway_state.config.solana_rpc_url,
                    &gateway_state.config.gar_program_id,
                    gateway_state.config.wallet.as_deref(),
                )
                .await
            {
                eprintln!("Gateway peer refresh failed: {error:#}");
            }
        }
    });
    let app = Router::new()
        .route("/ar-io/info", get(serve_info))
        .route("/ar-io/healthcheck", get(serve_healthcheck))
        .route("/ar-io/peers", get(serve_peers))
        .route("/ar-io/resolver/{name}", get(serve_resolver))
        .route("/ar-io/offsets/{id}", get(serve_offsets))
        .route("/", get(serve_arns))
        .route("/chunk/{offset}", get(serve_chunk))
        .route("/chunk/{offset}/data", get(serve_chunk_data))
        .route("/raw/{id}", get(serve_raw))
        .route("/raw/{id}/", get(serve_raw))
        .route("/{*path}", get(serve_path))
        .layer(middleware::from_fn_with_state(state.clone(), sign_response))
        .layer(middleware::from_fn(cors_response))
        .with_state(state);
    let result = axum::serve(listener, app)
        .await
        .context("HTTP server failed");
    refresh_tasks.shutdown().await;
    result
}

async fn cors_response(request: Request<Body>, next: Next) -> Response {
    let mut response = if request.method() == Method::OPTIONS {
        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("content-length", "0")
            .header(
                "access-control-allow-methods",
                "GET,HEAD,PUT,PATCH,POST,DELETE",
            )
            .header("vary", "Access-Control-Request-Headers")
            .body(Body::empty())
            .unwrap();
        for value in request.headers().get_all("access-control-request-headers") {
            if !value.is_empty() {
                response
                    .headers_mut()
                    .append("access-control-allow-headers", value.clone());
            }
        }
        response
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert("access-control-allow-origin", HeaderValue::from_static("*"));
    response.headers_mut().insert(
        "access-control-expose-headers",
        HeaderValue::from_static("*"),
    );
    response
}
struct HttpSigner {
    key: SigningKey,
    address: String,
    key_id: String,
    bind_request: bool,
}

const SIGNATURE_TRIGGERS: &[&str] = &[
    "x-ar-io-data-id",
    "x-ar-io-verified",
    "x-ar-io-stable",
    "x-ar-io-trusted",
    "x-ar-io-root-transaction-id",
    "x-arweave-owner-address",
    "x-arweave-tags-truncated",
    "x-arns-name",
    "x-arns-resolved-id",
    "x-arns-ttl-seconds",
    "x-arns-ant-program-id",
    "x-arns-ant-id",
    "x-arweave-chunk-data-root",
    "x-arweave-chunk-tx-id",
    "x-ar-io-chunk-source-type",
];
const SIGNATURE_EXTRA_HEADERS: &[&str] = &[
    "content-type",
    "content-digest",
    "x-ar-io-root-data-item-offset",
    "x-ar-io-root-data-offset",
    "x-ar-io-root-item-offset",
    "x-ar-io-root-item-size",
    "x-ar-io-root-path",
];

impl HttpSigner {
    fn sign(&self, response: &mut Response, method: &Method, path: &str) -> Result<()> {
        response.headers_mut().remove("signature");
        response.headers_mut().remove("signature-input");
        if !SIGNATURE_TRIGGERS
            .iter()
            .any(|name| response.headers().contains_key(*name))
        {
            return Ok(());
        }
        let mut covered: Vec<&str> = response
            .headers()
            .keys()
            .map(|name| name.as_str())
            .filter(|name| {
                SIGNATURE_TRIGGERS.contains(name)
                    || SIGNATURE_EXTRA_HEADERS.contains(name)
                    || name.starts_with("x-arweave-tag-")
            })
            .collect();
        covered.sort_unstable();
        let mut components = vec!["\"@status\"".to_owned()];
        let mut base = format!("\"@status\": {}", response.status().as_u16()).into_bytes();
        for name in covered {
            components.push(format!("\"{name}\""));
            base.extend_from_slice(format!("\n\"{name}\": ").as_bytes());
            for (index, value) in response.headers().get_all(name).iter().enumerate() {
                if index != 0 {
                    base.extend_from_slice(b", ");
                }
                base.extend_from_slice(value.as_bytes());
            }
        }
        if self.bind_request {
            components.extend(["\"@method\";req".to_owned(), "\"@path\";req".to_owned()]);
            base.extend_from_slice(
                format!("\n\"@method\";req: {method}\n\"@path\";req: {path}").as_bytes(),
            );
        }
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs();
        let params = format!(
            "({});created={created};keyid=\"{}\";alg=\"ed25519\"",
            components.join(" "),
            self.key_id
        );
        base.extend_from_slice(format!("\n\"@signature-params\": {params}").as_bytes());
        let signature = self.key.sign(&base);
        response
            .headers_mut()
            .insert("signature-input", format!("sig1={params}").parse()?);
        response.headers_mut().insert(
            "signature",
            format!("sig1=:{}:", STANDARD.encode(signature.to_bytes())).parse()?,
        );
        Ok(())
    }
}

async fn sign_response(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if let Some(signer) = &state.config.signer {
        if let Err(error) = signer.sign(&mut response, &method, &path) {
            eprintln!("response signing failed: {error:#}");
            return empty_error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    response
}

async fn serve_info(State(state): State<Arc<AppState>>) -> Response {
    let filter = if state.gateway.bundle_indexer.is_some() {
        serde_json::json!({"always": true})
    } else {
        serde_json::json!({"never": true})
    };
    let mut info = serde_json::json!({
        "programIds": {
            "core": state.config.core_program_id,
            "gar": state.config.gar_program_id,
            "arns": state.config.arns_program_id,
            "ant": state.config.ant_program_id,
        },
        "ans104UnbundleFilter": filter,
        "ans104IndexFilter": filter,
        "supportedManifestVersions": ["0.1.0", "0.2.0"],
        "release": env!("CARGO_PKG_VERSION"),
        "services": {
            "bundlers": state.config.bundler_urls.iter()
                .map(|url| serde_json::json!({"url": url})).collect::<Vec<_>>(),
        },
    });
    if let Some(wallet) = &state.config.wallet {
        info["wallet"] = serde_json::json!(wallet);
    }
    if let Some(signer) = &state.config.signer {
        info["httpsig"] = serde_json::json!({
            "algorithm": "ed25519",
            "solanaAddress": signer.address,
        });
    }
    json_response(&info)
}

async fn serve_resolver(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    if split_arns_name(&name).is_err() {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    }
    let _permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let resolution = match tokio::time::timeout(
        state.gateway.config.retrieval_timeout,
        resolve_arns(&state, name),
    )
    .await
    {
        Ok(Ok(Some(resolution))) => resolution,
        Ok(Ok(None)) => return error_response(StatusCode::NOT_FOUND, "Not Found"),
        Ok(Err(error)) => {
            eprintln!("ArNS resolution failed: {error:#}");
            return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
        }
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway"),
    };
    let mut response = json_response(&serde_json::json!({
        "txId": resolution.resolved_id,
        "ttlSeconds": resolution.ttl,
        "antId": resolution.ant_id,
        "resolvedAt": resolution.resolved_at,
        "index": resolution.index,
        "limit": resolution.limit,
    }));
    for (name, value) in [
        ("x-arns-resolved-id", resolution.resolved_id),
        ("x-arns-ttl-seconds", resolution.ttl.to_string()),
        ("x-arns-ant-program-id", state.config.ant_program_id.clone()),
        ("x-arns-ant-id", resolution.ant_id),
        ("x-arns-resolved-at", resolution.resolved_at.to_string()),
        ("x-arns-record-index", resolution.index.to_string()),
        ("x-arns-undername-limit", resolution.limit.to_string()),
    ] {
        response.headers_mut().insert(
            name,
            HeaderValue::from_str(&value).expect("validated resolution header"),
        );
    }
    response
}

async fn serve_offsets(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let Ok(id) = decode_fixed::<32>(&id, "data ID") else {
        return error_response(StatusCode::BAD_REQUEST, "Must provide a valid data ID");
    };
    let _permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let lookup = async {
        let Some(store) = &state.gateway.block_store else {
            return Ok(None);
        };
        let Some(indexed) = store.bundle_location(&id).await? else {
            return Ok(None);
        };
        let target = indexed.locations.last().context("missing indexed target")?;
        let data_offset = target
            .root_offset
            .checked_add(target.data_offset)
            .context("indexed data offset overflow")?;
        let root_id = URL_SAFE_NO_PAD.encode(&indexed.root_id);
        let mut offsets = serde_json::json!({
            "rootTxId": root_id,
            "rootOffset": target.root_offset,
            "rootDataOffset": data_offset,
            "size": target.item_size,
            "dataSize": indexed.data_size,
        });
        if indexed.locations.len() == 1 {
            offsets["path"] = serde_json::json!([root_id]);
        }
        if let Some(content_type) = indexed.content_type {
            offsets["contentType"] = serde_json::json!(content_type);
        }
        Ok::<_, anyhow::Error>(Some(offsets))
    };
    match tokio::time::timeout(state.gateway.config.retrieval_timeout, lookup).await {
        Ok(Ok(Some(offsets))) => json_response(&offsets),
        Ok(Ok(None)) => {
            let mut response = error_response(StatusCode::NOT_FOUND, "Offsets not found");
            response.headers_mut().insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60, must-revalidate"),
            );
            response
        }
        result => {
            eprintln!("indexed offset lookup failed: {result:?}");
            let mut response = error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to resolve offsets",
            );
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
    }
}

async fn serve_healthcheck(State(state): State<Arc<AppState>>) -> Response {
    let now = SystemTime::now();
    let date = match iso_utc_date(now) {
        Ok(date) => date,
        Err(error) => {
            eprintln!("healthcheck date failed: {error:#}");
            return empty_error_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let mut health = serde_json::json!({
        "status": "ok",
        "uptime": state.started_at.elapsed().as_secs_f64(),
        "date": date,
    });
    let last_indexed_at = state
        .gateway
        .bundle_indexer
        .as_ref()
        .map_or(0, |indexer| indexer.last_indexed_at());
    if let Some(seconds) = state
        .config
        .max_expected_data_item_indexing_interval_seconds
        && now
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(last_indexed_at)
            > seconds
    {
        health["status"] = serde_json::json!("unhealthy");
        health["reasons"] = serde_json::json!([format!(
            "Last data item indexed more than {seconds} seconds ago."
        )]);
    }
    json_response(&health)
}

async fn serve_peers(State(state): State<Arc<AppState>>) -> Response {
    json_response(&state.gateway.peers.snapshot())
}

fn iso_utc_date(now: SystemTime) -> Result<String> {
    let elapsed = now
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    // Gregorian civil date from days since epoch, using 400-year eras.
    let days = elapsed.as_secs() / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    ensure!(year <= 9999, "system clock is outside the ISO date range");
    let seconds = elapsed.as_secs() % 86_400;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        elapsed.subsec_millis(),
    ))
}

fn json_response(value: &serde_json::Value) -> Response {
    let body = serde_json::to_vec(value).expect("response contains only JSON values");
    Response::builder()
        .header("content-type", "application/json; charset=utf-8")
        .header("content-length", body.len().to_string())
        .header("cache-control", "public, max-age=30")
        .body(Body::from(body))
        .unwrap()
}

fn request_permit(permits: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Response> {
    permits
        .clone()
        .try_acquire_owned()
        .map_err(|_| error_response(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable"))
}

async fn serve_chunk(
    State(state): State<Arc<AppState>>,
    Path(offset): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve_chunk_response(&state, &offset, &headers, false).await
}

async fn serve_chunk_data(
    State(state): State<Arc<AppState>>,
    Path(offset): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve_chunk_response(&state, &offset, &headers, true).await
}

async fn serve_chunk_response(
    state: &AppState,
    offset: &str,
    headers: &HeaderMap,
    raw: bool,
) -> Response {
    let permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    if offset.is_empty() || !offset.bytes().all(|byte| byte.is_ascii_digit()) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid offset");
    }
    let Ok(offset) = offset.parse::<u128>() else {
        return error_response(StatusCode::BAD_REQUEST, "Invalid offset");
    };
    match state.gateway.retrieve_chunk(offset).await {
        Ok(Some(chunk)) => chunk_response(chunk, raw, headers, &state.gateway.config, permit)
            .await
            .unwrap_or_else(|error| {
                eprintln!("chunk response construction failed: {error:#}");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Not Found"),
        Err(error) => {
            eprintln!("verified chunk retrieval failed: {error:#}");
            empty_error_response(StatusCode::BAD_GATEWAY)
        }
    }
}

async fn serve_arns(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if arns_name(&headers, &state.config.arns_root_host).is_none() {
        return serve_info(State(state)).await;
    }
    let permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    serve_arns_path(&state, &headers, "", permit).await
}

async fn serve_raw(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    if !is_data_id_shape(&id) {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    }
    if decode_fixed::<32>(&id, "data ID").is_err() {
        return error_response(StatusCode::BAD_REQUEST, "Invalid ID");
    }
    match state.gateway.retrieve(&id).await {
        Ok(verified) => verified_response(
            verified,
            None,
            &state.config,
            &headers,
            &state.gateway.config,
            permit,
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("response construction failed: {error:#}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        }),
        Err(error) => retrieval_error_response(error),
    }
}

async fn serve_path(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let permit = match request_permit(&state.request_permits) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let (id, manifest_path) = path.split_once('/').unwrap_or((&path, ""));
    if let Ok(decoded_id) = decode_fixed::<32>(id, "data ID") {
        let sandbox = sandbox_name(&decoded_id);
        let sandbox_host = format!("{sandbox}.{}", state.config.arns_root_host);
        if request_host(&headers).as_deref() != Some(sandbox_host.as_str()) {
            let location = format!(
                "https://{sandbox_host}{}?{}",
                uri.path(),
                uri.query().unwrap_or("")
            );
            return redirect_response(StatusCode::FOUND, location);
        }
        return retrieve_response(
            &state,
            id,
            manifest_path,
            manifest_path.is_empty() && !uri.path().ends_with('/'),
            uri.query(),
            None,
            &headers,
            permit,
        )
        .await;
    }
    if is_data_id_shape(id) {
        return error_response(StatusCode::BAD_REQUEST, "Invalid ID");
    }
    serve_arns_path(&state, &headers, &path, permit).await
}

async fn serve_arns_path(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    permit: OwnedSemaphorePermit,
) -> Response {
    let Some(name) = arns_name(headers, &state.config.arns_root_host) else {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    };
    let resolution = match resolve_arns(state, name).await {
        Ok(Some(resolution)) => resolution,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "Not Found"),
        Err(error) => {
            eprintln!("ArNS resolution failed: {error:#}");
            return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
        }
    };
    if resolution.index > usize::from(resolution.limit) {
        return error_response(StatusCode::PAYMENT_REQUIRED, "Payment Required");
    }
    retrieve_response(
        state,
        &resolution.resolved_id,
        path,
        false,
        None,
        Some(&resolution),
        headers,
        permit,
    )
    .await
}

async fn retrieve_response(
    state: &AppState,
    id: &str,
    manifest_path: &str,
    add_trailing_slash: bool,
    query: Option<&str>,
    resolution: Option<&Resolution>,
    headers: &HeaderMap,
    permit: OwnedSemaphorePermit,
) -> Response {
    let verified = match state.gateway.retrieve(id).await {
        Ok(verified) => verified,
        Err(error) => return retrieval_error_response(error),
    };
    if !is_manifest_content_type(&verified.content_type) {
        return verified_response(
            verified,
            resolution,
            &state.config,
            headers,
            &state.gateway.config,
            permit,
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("response construction failed: {error:#}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        });
    }

    let target = async {
        ensure!(
            verified.bytes.len() <= MAX_MANIFEST_BYTES,
            "manifest exceeds size limit"
        );
        let bytes = verified.bytes.read_all(MAX_MANIFEST_BYTES).await?;
        resolve_manifest(&bytes, manifest_path)
    }
    .await;
    let target = match target {
        Ok(Some(target)) => target,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "Not Found"),
        Err(error) => {
            eprintln!("manifest resolution failed: {error:#}");
            return error_response(StatusCode::BAD_GATEWAY, "Bad Gateway");
        }
    };
    if add_trailing_slash {
        let mut location = format!("/{}/", verified.id);
        if let Some(query) = query {
            location.push('?');
            location.push_str(query);
        }
        return redirect_response(StatusCode::MOVED_PERMANENTLY, location);
    }
    drop(verified);

    let fallback = target.fallback;
    let verified_target = match state.gateway.retrieve(&target.id).await {
        Ok(verified) => verified,
        Err(error) => return retrieval_error_response(error),
    };
    let mut response = verified_response(
        verified_target,
        resolution,
        &state.config,
        headers,
        &state.gateway.config,
        permit,
    )
    .await
    .unwrap_or_else(|error| {
        eprintln!("response construction failed: {error:#}");
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    });
    if fallback {
        response.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=60, must-revalidate"),
        );
    }
    response
}

fn is_manifest_content_type(value: &str) -> bool {
    value.split(';').next().is_some_and(|media_type| {
        media_type
            .trim()
            .eq_ignore_ascii_case(MANIFEST_CONTENT_TYPE)
    })
}

fn resolve_manifest(bytes: &[u8], path: &str) -> Result<Option<ManifestResolution>> {
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "manifest exceeds size limit"
    );
    ensure!(
        path.len() <= MAX_MANIFEST_PATH_BYTES,
        "manifest path exceeds size limit"
    );
    let manifest: Manifest = serde_json::from_slice(bytes).context("invalid manifest JSON")?;
    ensure!(
        manifest.manifest == "arweave/paths",
        "invalid manifest type"
    );
    ensure!(
        matches!(manifest.version.as_str(), "0.1.0" | "0.2.0"),
        "unsupported manifest version"
    );

    let path = path.trim_end_matches('/');
    let mut resolved = None;
    if path.is_empty() {
        if manifest.version == "0.2.0"
            && let Some(id) = manifest_field(&manifest.index, "id", "manifest index ID")?
        {
            resolved = Some((id, false));
        }
        if resolved.is_none()
            && let Some(index_path) =
                manifest_field(&manifest.index, "path", "manifest index path")?
            && let Some(target) = manifest.paths.get(index_path)
        {
            resolved = Some((
                required_manifest_id(target, "manifest index target")?,
                false,
            ));
        }
    } else if let Some((_, target)) = manifest
        .paths
        .iter()
        .find(|(manifest_path, _)| manifest_path.trim_end_matches('/') == path)
    {
        resolved = Some((required_manifest_id(target, "manifest path target")?, false));
    }

    if resolved.is_none() && manifest.version == "0.2.0" && !manifest.fallback.is_null() {
        resolved = Some((
            required_manifest_id(&manifest.fallback, "manifest fallback")?,
            true,
        ));
    }
    let Some((id, fallback)) = resolved else {
        return Ok(None);
    };
    decode_fixed::<32>(id, "manifest target ID")?;
    Ok(Some(ManifestResolution {
        id: id.to_owned(),
        fallback,
    }))
}

fn manifest_field<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<Option<&'a str>> {
    value
        .get(field)
        .map(|value| {
            value
                .as_str()
                .with_context(|| format!("{label} must be a string"))
        })
        .transpose()
}

fn required_manifest_id<'a>(value: &'a serde_json::Value, label: &str) -> Result<&'a str> {
    manifest_field(value, "id", label)?.with_context(|| format!("{label} is missing an ID"))
}

fn sandbox_name(id: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut encoded = String::with_capacity(52);
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in id {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            encoded.push(ALPHABET[usize::from((buffer >> bits) & 31)] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        encoded.push(ALPHABET[usize::from((buffer << (5 - bits)) & 31)] as char);
    }
    encoded
}

fn redirect_response(status: StatusCode, location: String) -> Response {
    Response::builder()
        .status(status)
        .header("location", location)
        .body(Body::empty())
        .unwrap()
}

async fn resolve_arns(state: &AppState, name: String) -> Result<Option<Resolution>> {
    let (basename, undername) = split_arns_name(&name)?;

    let name_hash: [u8; 32] = Sha256::digest(basename.as_bytes()).into();
    let (arns_address, arns_bump) = derive_pda(
        &state.config.arns_program_id,
        &[ARNS_RECORD_SEED, name_hash.as_slice()],
        "ArNS record",
    )?;
    let Some(arns_bytes) = account_info(
        &state.gateway,
        &state.config.solana_rpc_url,
        &arns_address,
        &state.config.arns_program_id,
    )
    .await?
    else {
        return Ok(None);
    };
    let arns = decode_arns_record(&arns_bytes)?;
    ensure!(arns.name == basename, "ArNS account name mismatch");
    ensure!(arns.bump == arns_bump, "ArNS record bump mismatch");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    if let Some(end_timestamp) = arns.end_timestamp
        && !arns_is_active(
            end_timestamp,
            arns_grace_period(state).await?,
            now.as_secs(),
        )?
    {
        return Ok(None);
    }

    let (index, record) = if undername == "@" {
        let undername_hash: [u8; 32] = Sha256::digest(b"@").into();
        let (ant_address, ant_bump) = derive_pda(
            &state.config.ant_program_id,
            &[
                ANT_RECORD_SEED,
                arns.ant.as_slice(),
                undername_hash.as_slice(),
            ],
            "ANT record",
        )?;
        let Some(ant_bytes) = account_info(
            &state.gateway,
            &state.config.solana_rpc_url,
            &ant_address,
            &state.config.ant_program_id,
        )
        .await?
        else {
            return Ok(None);
        };
        let record = decode_ant_record(&ant_bytes, &arns.ant)?;
        ensure!(record.bump == ant_bump, "ANT record bump mismatch");
        ensure!(record.undername == "@", "ANT root record mismatch");
        (0, record)
    } else {
        let Some(selected) = ant_undername(
            &state.gateway,
            &state.config.solana_rpc_url,
            &state.config.ant_program_id,
            &arns.ant,
            &undername,
        )
        .await?
        else {
            return Ok(None);
        };
        selected
    };
    ensure!(
        record.target_protocol == 0,
        "ANT record does not target Arweave"
    );
    decode_fixed::<32>(&record.target, "resolved data ID")?;

    Ok(Some(Resolution {
        name,
        basename,
        record: undername,
        resolved_id: record.target,
        ttl: record.ttl,
        ant_id: bs58::encode(arns.ant).into_string(),
        limit: arns.undername_limit,
        index,
        resolved_at: now.as_millis(),
    }))
}

async fn arns_grace_period(state: &AppState) -> Result<i64> {
    let (address, expected_bump) = derive_pda(
        &state.config.arns_program_id,
        &[ARNS_CONFIG_SEED],
        "ArNS config",
    )?;
    let bytes = account_info(
        &state.gateway,
        &state.config.solana_rpc_url,
        &address,
        &state.config.arns_program_id,
    )
    .await?
    .context("ArNS config account is missing")?;
    let (grace_period, bump) = decode_arns_config(&bytes)?;
    ensure!(bump == expected_bump, "ArNS config bump mismatch");
    Ok(grace_period)
}
fn arns_is_active(end_timestamp: i64, grace_period: i64, now: u64) -> Result<bool> {
    let expires_at = end_timestamp
        .checked_add(grace_period)
        .context("ArNS lease expiry overflow")?;
    Ok(i64::try_from(now).context("system time is too large")? < expires_at)
}

async fn account_info(
    gateway: &Gateway,
    rpc_url: &Url,
    address: &str,
    program_id: &str,
) -> Result<Option<Vec<u8>>> {
    let response: SolanaRpcResponse<AccountInfoResult> = gateway
        .request_json(
            gateway
                .client
                .post(rpc_url.clone())
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getAccountInfo",
                    "params": [address, {
                        "commitment": "finalized",
                        "encoding": "base64"
                    }]
                })),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Solana RPC request failed"))?;
    let Some(account) = response.into_result()?.value else {
        return Ok(None);
    };
    decode_program_account(account, program_id).map(Some)
}

async fn ant_undername(
    gateway: &Gateway,
    rpc_url: &Url,
    program_id: &str,
    mint: &[u8; 32],
    undername: &str,
) -> Result<Option<(usize, AntRecord)>> {
    // ponytail: one bounded per-ANT scan; index only if measured RPC cost warrants it.
    let response: SolanaRpcResponse<Vec<ProgramAccount>> = gateway
        .request_json(
            gateway
                .client
                .post(rpc_url.clone())
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "getProgramAccounts",
                    "params": [program_id, {
                        "commitment": "finalized",
                        "encoding": "base64",
                        "filters": [
                            {"memcmp": {
                                "offset": 0,
                                "bytes": bs58::encode(ANT_RECORD_DISCRIMINATOR).into_string(),
                                "encoding": "base58"
                            }},
                            {"memcmp": {
                                "offset": 8,
                                "bytes": bs58::encode(mint).into_string(),
                                "encoding": "base58"
                            }}
                        ]
                    }]
                })),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Solana RPC request failed"))?;
    select_ant_record(response.into_result()?, program_id, mint, undername)
}

fn decode_program_account(account: SolanaAccount, program_id: &str) -> Result<Vec<u8>> {
    ensure!(account.owner == program_id, "Solana account owner mismatch");
    ensure!(!account.executable, "Solana data account is executable");
    ensure!(
        account.data[1] == "base64",
        "unexpected Solana account encoding"
    );
    ensure!(
        account.space <= MAX_SOLANA_ACCOUNT_BYTES
            && account.data[0].len() <= MAX_SOLANA_ACCOUNT_BYTES.div_ceil(3) * 4,
        "Solana account exceeds size limit"
    );
    let data = STANDARD
        .decode(&account.data[0])
        .context("invalid Solana account base64")?;
    ensure!(data.len() == account.space, "Solana account size mismatch");
    Ok(data)
}
fn decode_arns_config(bytes: &[u8]) -> Result<(i64, u8)> {
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 8, "ArNS config discriminator")? == ARNS_CONFIG_DISCRIMINATOR,
        "invalid ArNS config discriminator"
    );
    take(bytes, &mut cursor, 96, "ArNS config addresses")?;
    let grace_period = read_i64(bytes, &mut cursor, "ArNS grace period")?;
    ensure!(grace_period >= 0, "invalid ArNS grace period");
    read_i64(bytes, &mut cursor, "ArNS return auction duration")?;
    read_u8(bytes, &mut cursor, "ArNS maximum lease length")?;
    read_u64(bytes, &mut cursor, "ArNS registered name count")?;
    read_i64(bytes, &mut cursor, "ArNS next record prune time")?;
    read_i64(bytes, &mut cursor, "ArNS next returned-name prune time")?;
    ensure!(
        read_u8(bytes, &mut cursor, "ArNS migration flag")? <= 1,
        "invalid ArNS migration flag"
    );
    take(bytes, &mut cursor, 32, "ArNS migration authority")?;
    let bump = read_u8(bytes, &mut cursor, "ArNS config bump")?;
    ensure!(
        take(bytes, &mut cursor, 3, "ArNS config schema version")? == [1, 0, 0],
        "unsupported ArNS config schema version"
    );
    ensure!(
        bytes[cursor..].iter().all(|byte| *byte == 0),
        "ArNS config contains trailing data"
    );
    Ok((grace_period, bump))
}

fn derive_pda(program_id: &str, seeds: &[&[u8]], label: &str) -> Result<(String, u8)> {
    let program_id = Pubkey::new_from_array(decode_pubkey(program_id, "Solana program ID")?);
    let (address, bump) = Pubkey::try_find_program_address(seeds, &program_id)
        .with_context(|| format!("failed to derive {label} PDA"))?;
    Ok((address.to_string(), bump))
}

fn decode_arns_record(bytes: &[u8]) -> Result<ArnsRecord<'_>> {
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 8, "ArNS discriminator")? == ARNS_RECORD_DISCRIMINATOR,
        "invalid ArNS record discriminator"
    );
    let name_hash = take(bytes, &mut cursor, 32, "ArNS name hash")?;
    take(bytes, &mut cursor, 32, "ArNS owner")?;
    let ant: [u8; 32] = take(bytes, &mut cursor, 32, "ArNS ANT ID")?
        .try_into()
        .unwrap();
    let purchase_type = read_u8(bytes, &mut cursor, "ArNS purchase type")?;
    read_i64(bytes, &mut cursor, "ArNS start timestamp")?;
    let end_timestamp = read_option_i64(bytes, &mut cursor, "ArNS end timestamp")?;
    ensure!(
        matches!((purchase_type, end_timestamp), (0, Some(_)) | (1, None)),
        "invalid ArNS purchase type or end timestamp"
    );
    let undername_limit = read_u16(bytes, &mut cursor, "ArNS undername limit")?;
    read_u64(bytes, &mut cursor, "ArNS purchase price")?;
    let bump = read_u8(bytes, &mut cursor, "ArNS bump")?;
    let name = read_string(bytes, &mut cursor, 64, "ArNS name")?;
    ensure!(
        Sha256::digest(name.as_bytes()).as_slice() == name_hash,
        "ArNS name hash mismatch"
    );
    ensure!(
        take(bytes, &mut cursor, 3, "ArNS schema version")? == [1, 0, 0],
        "unsupported ArNS schema version"
    );
    ensure!(
        bytes[cursor..].iter().all(|byte| *byte == 0),
        "ArNS account contains trailing data"
    );
    Ok(ArnsRecord {
        name,
        ant,
        undername_limit,
        end_timestamp,
        bump,
    })
}

fn decode_ant_record(bytes: &[u8], expected_mint: &[u8; 32]) -> Result<AntRecord> {
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 8, "ANT discriminator")? == ANT_RECORD_DISCRIMINATOR,
        "invalid ANT record discriminator"
    );
    ensure!(
        take(bytes, &mut cursor, 32, "ANT mint")? == expected_mint,
        "ANT mint mismatch"
    );
    let undername = read_string(bytes, &mut cursor, 64, "ANT undername")?.to_owned();
    let target = read_string(bytes, &mut cursor, 128, "ANT target")?.to_owned();
    let target_protocol = read_u8(bytes, &mut cursor, "ANT target protocol")?;
    let ttl = read_u32(bytes, &mut cursor, "ANT TTL")?;
    let priority = read_option_u32(bytes, &mut cursor, "ANT priority")?;
    read_option_bytes32(bytes, &mut cursor, "ANT owner")?;
    take(bytes, &mut cursor, 32, "ANT reconciled owner")?;
    let bump = read_u8(bytes, &mut cursor, "ANT bump")?;
    ensure!(
        take(bytes, &mut cursor, 3, "ANT schema version")? == [1, 0, 0],
        "unsupported ANT schema version"
    );
    ensure!(
        bytes[cursor..].iter().all(|byte| *byte == 0),
        "ANT account contains trailing data"
    );
    Ok(AntRecord {
        undername,
        target,
        target_protocol,
        ttl,
        priority,
        bump,
    })
}

fn select_ant_record(
    accounts: Vec<ProgramAccount>,
    program_id: &str,
    mint: &[u8; 32],
    undername: &str,
) -> Result<Option<(usize, AntRecord)>> {
    ensure!(
        accounts.len() <= MAX_ANT_RECORDS,
        "ANT record count exceeds limit"
    );
    let program = Pubkey::new_from_array(decode_pubkey(program_id, "ANT program ID")?);
    let mut addresses = HashSet::with_capacity(accounts.len());
    let mut records = Vec::with_capacity(accounts.len());
    for account in accounts {
        let address = decode_pubkey(&account.pubkey, "ANT record address")?;
        let data = decode_program_account(account.account, program_id)?;
        let mut record = decode_ant_record(&data, mint)?;
        record.undername.make_ascii_lowercase();
        if record.undername != "@" {
            split_arns_name(&format!("{}_x", record.undername))?;
        }
        let hash: [u8; 32] = Sha256::digest(record.undername.as_bytes()).into();
        let (expected, bump) =
            Pubkey::try_find_program_address(&[ANT_RECORD_SEED, mint, &hash], &program)
                .context("failed to derive ANT record PDA")?;
        ensure!(
            expected.to_bytes() == address && bump == record.bump,
            "ANT record PDA mismatch"
        );
        ensure!(addresses.insert(address), "duplicate ANT record");
        records.push(record);
    }
    records.sort_unstable_by(|a, b| {
        (
            a.undername != "@",
            a.priority.is_none(),
            a.priority,
            &a.undername,
        )
            .cmp(&(
                b.undername != "@",
                b.priority.is_none(),
                b.priority,
                &b.undername,
            ))
    });
    // Without the root, the first undername would incorrectly occupy the free slot.
    ensure!(
        records.first().is_none_or(|record| record.undername == "@"),
        "ANT response is missing root record"
    );
    Ok(records
        .into_iter()
        .enumerate()
        .find(|(_, record)| record.undername == undername))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByteRangeError {
    Malformed,
    Unsatisfiable,
}

fn parse_byte_ranges(
    value: &str,
    total: usize,
) -> std::result::Result<Vec<(usize, usize)>, ByteRangeError> {
    if value.len() > MAX_RANGE_HEADER_BYTES {
        return Err(ByteRangeError::Malformed);
    }
    let value = value
        .strip_prefix("bytes=")
        .ok_or(ByteRangeError::Malformed)?;
    let mut ranges = Vec::new();
    for (index, value) in value.split(',').enumerate() {
        if index == MAX_BYTE_RANGES {
            return Err(ByteRangeError::Unsatisfiable);
        }
        match parse_byte_range(value.trim(), total) {
            Ok(range) => ranges.push(range),
            Err(ByteRangeError::Unsatisfiable) => {}
            Err(error) => return Err(error),
        }
    }
    if ranges.is_empty() {
        return Err(ByteRangeError::Unsatisfiable);
    }
    Ok(ranges)
}

fn parse_byte_range(
    value: &str,
    total: usize,
) -> std::result::Result<(usize, usize), ByteRangeError> {
    let Some((start, end)) = value.split_once('-') else {
        return Err(ByteRangeError::Malformed);
    };

    if start.is_empty() {
        let suffix = end
            .parse::<usize>()
            .map_err(|_| ByteRangeError::Malformed)?;
        if suffix == 0 || total == 0 {
            return Err(ByteRangeError::Unsatisfiable);
        }
        return Ok((total.saturating_sub(suffix), total - 1));
    }

    let start = start
        .parse::<usize>()
        .map_err(|_| ByteRangeError::Malformed)?;
    let end = if end.is_empty() {
        total.saturating_sub(1)
    } else {
        end.parse::<usize>()
            .map_err(|_| ByteRangeError::Malformed)?
    };
    if total == 0 || start >= total || start > end {
        return Err(ByteRangeError::Unsatisfiable);
    }
    Ok((start, end.min(total - 1)))
}

fn multipart_content(
    content: &Content,
    ranges: &[(usize, usize)],
    content_type: &str,
    content_encoding: Option<&str>,
    boundary: &str,
) -> Result<(Vec<Content>, usize)> {
    HeaderValue::from_str(content_type).context("invalid multipart content type")?;
    let encoding_header = match content_encoding {
        Some(encoding) => {
            HeaderValue::from_str(encoding).context("invalid multipart content encoding")?;
            format!("Content-Encoding: {encoding}\r\n")
        }
        None => String::new(),
    };
    let mut parts = Vec::with_capacity(ranges.len() * 2 + 1);
    let mut length = 0_usize;
    let total = content.len();
    for (index, &(start, end)) in ranges.iter().enumerate() {
        let separator = if index == 0 { "" } else { "\r\n" };
        let header = format!(
            "{separator}--{boundary}\r\nContent-Type: {content_type}\r\n{encoding_header}Content-Range: bytes {start}-{end}/{total}\r\n\r\n"
        );
        let range = content.slice(start..end + 1)?;
        length = length
            .checked_add(header.len())
            .and_then(|length| length.checked_add(range.len()))
            .context("multipart response length overflow")?;
        parts.push(header.into_bytes().into());
        parts.push(range);
    }
    let closing = format!("\r\n--{boundary}--\r\n");
    length = length
        .checked_add(closing.len())
        .context("multipart response length overflow")?;
    parts.push(closing.into_bytes().into());
    Ok((parts, length))
}

struct SequentialReader {
    reader: Option<ContentReader>,
    remaining: std::vec::IntoIter<Content>,
    opening: Option<Pin<Box<dyn Future<Output = Result<ContentReader>> + Send>>>,
}

impl AsyncRead for SequentialReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(opening) = &mut this.opening {
                let reader = match opening.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(reader) => reader,
                };
                this.opening = None;
                match reader {
                    Ok(reader) => this.reader = Some(reader),
                    Err(error) => return Poll::Ready(Err(io::Error::other(error))),
                }
            }
            if let Some(reader) = &mut this.reader {
                let filled = output.filled().len();
                match Pin::new(reader).poll_read(cx, output) {
                    Poll::Ready(Ok(())) if output.filled().len() == filled => {
                        this.reader = None;
                    }
                    result => return result,
                }
            }
            let Some(content) = this.remaining.next() else {
                return Poll::Ready(Ok(()));
            };
            // Open one verified slice at a time; dropping the reader also drops unopened slices.
            this.opening = Some(Box::pin(async move { content.reader().await }));
        }
    }
}

struct ResponseStreamState {
    resources: Option<(SequentialReader, OwnedSemaphorePermit)>,
    expires_at: StreamInstant,
    total_deadline: StreamInstant,
    waker: Option<Waker>,
}

struct ResponseReader {
    state: Arc<Mutex<ResponseStreamState>>,
    idle_timeout: Duration,
    watchdog: JoinHandle<()>,
}

impl AsyncRead for ResponseReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut state = self.state.lock();
        let now = StreamInstant::now();
        if now >= state.expires_at {
            state.resources.take();
        }
        let Some((reader, _permit)) = &mut state.resources else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "verified response stream timed out",
            )));
        };
        let filled = buf.filled().len();
        let result = Pin::new(reader).poll_read(cx, buf);
        if result.is_pending() {
            state.waker = Some(cx.waker().clone());
        } else {
            state.waker = None;
            if buf.filled().len() > filled {
                // Idle measures body-read progress under backpressure, not remote acknowledgements.
                state.expires_at = now
                    .checked_add(self.idle_timeout)
                    .unwrap_or(state.total_deadline)
                    .min(state.total_deadline);
            }
        }
        result
    }
}

impl Drop for ResponseReader {
    fn drop(&mut self) {
        self.watchdog.abort();
    }
}

async fn content_body(
    content: Content,
    limits: &Config,
    permit: OwnedSemaphorePermit,
) -> Result<Body> {
    if content.is_empty() {
        return Ok(Body::empty());
    }
    response_body(content, Vec::new().into_iter(), limits, permit).await
}

async fn response_body(
    content: Content,
    remaining: std::vec::IntoIter<Content>,
    limits: &Config,
    permit: OwnedSemaphorePermit,
) -> Result<Body> {
    let now = StreamInstant::now();
    let total_deadline = now
        .checked_add(limits.stream_timeout)
        .context("stream timeout exceeds clock range")?;
    let expires_at = now
        .checked_add(limits.stream_idle_timeout)
        .unwrap_or(total_deadline)
        .min(total_deadline);
    let reader = tokio::time::timeout_at(expires_at, content.reader())
        .await
        .context("opening verified content timed out")??;
    let state = Arc::new(Mutex::new(ResponseStreamState {
        resources: Some((
            SequentialReader {
                reader: Some(reader),
                remaining,
                opening: None,
            },
            permit,
        )),
        expires_at,
        total_deadline,
        waker: None,
    }));
    let weak = Arc::downgrade(&state);
    // ponytail: a watchdog is necessary because a stalled client may stop polling the body.
    let watchdog = tokio::spawn(async move {
        let mut expires_at = expires_at;
        loop {
            sleep_until(expires_at).await;
            let Some(state) = weak.upgrade() else {
                return;
            };
            let waker = {
                let mut state = state.lock();
                if StreamInstant::now() < state.expires_at {
                    expires_at = state.expires_at;
                    continue;
                }
                state.resources.take();
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
            return;
        }
    });
    Ok(Body::from_stream(ReaderStream::with_capacity(
        ResponseReader {
            state,
            idle_timeout: limits.stream_idle_timeout,
            watchdog,
        },
        RESPONSE_CHUNK_BYTES,
    )))
}

async fn verified_response(
    verified: VerifiedData,
    resolution: Option<&Resolution>,
    config: &ServerConfig,
    request_headers: &HeaderMap,
    limits: &Config,
    permit: OwnedSemaphorePermit,
) -> Result<Response> {
    ensure!(
        verified.bytes.len() == verified.content_length,
        "verified content length mismatch"
    );
    let digest = verified
        .etag
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .context("verified ETag is malformed")?;
    let digest_bytes = URL_SAFE_NO_PAD
        .decode(digest)
        .context("verified ETag digest is malformed")?;
    ensure!(
        digest_bytes.len() == 32,
        "verified digest has the wrong size"
    );
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(digest_bytes));
    let mut builder = Response::builder()
        .header("accept-ranges", "bytes")
        .header("etag", verified.etag.as_str())
        .header("content-digest", content_digest)
        .header("x-ar-io-data-id", verified.id.as_str())
        .header("x-ar-io-digest", digest)
        .header("x-ar-io-stable", "true")
        .header("x-ar-io-verified", "true")
        .header("x-ar-io-trusted", "true")
        .header("x-cache", if verified.cache_hit { "HIT" } else { "MISS" })
        .header("x-ar-io-hops", "1");
    if let Some(resolution) = resolution {
        builder = builder
            .header(
                "cache-control",
                format!("public, max-age={}", resolution.ttl),
            )
            .header("x-arns-name", resolution.name.as_str())
            .header("x-arns-basename", resolution.basename.as_str())
            .header("x-arns-record", resolution.record.as_str())
            .header("x-arns-resolved-id", resolution.resolved_id.as_str())
            .header("x-arns-ttl-seconds", resolution.ttl.to_string())
            .header("x-arns-ant-program-id", config.ant_program_id.as_str())
            .header("x-arns-ant-id", resolution.ant_id.as_str())
            .header("x-arns-resolved-at", resolution.resolved_at.to_string())
            .header("x-arns-undername-limit", resolution.limit.to_string())
            .header("x-arns-record-index", resolution.index.to_string());
    } else {
        builder = builder.header(
            "cache-control",
            if verified.content_length > 100 * 1024 * 1024 {
                "private, max-age=2592000, immutable"
            } else {
                "public, max-age=2592000, immutable"
            },
        );
    }

    let range = request_headers
        .get("range")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ByteRangeError::Malformed)
                .and_then(|value| parse_byte_ranges(value, verified.content_length))
        })
        .transpose();
    let range = match range {
        Ok(range) => range,
        Err(error) => {
            let (status, message) = match error {
                ByteRangeError::Malformed => (StatusCode::BAD_REQUEST, "Malformed 'range' header"),
                ByteRangeError::Unsatisfiable => {
                    builder = builder.header(
                        "content-range",
                        format!("bytes */{}", verified.content_length),
                    );
                    (StatusCode::RANGE_NOT_SATISFIABLE, "Range not satisfiable")
                }
            };
            return builder
                .status(status)
                .header("content-type", "text/plain; charset=utf-8")
                .header("content-length", message.len().to_string())
                .body(Body::from(message))
                .context("failed to construct range error response");
        }
    };

    if request_headers
        .get("if-none-match")
        .is_some_and(|value| value.as_bytes() == verified.etag.as_bytes())
    {
        return builder
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .context("failed to construct not-modified response");
    }
    if let Some(ranges) = &range
        && ranges.len() > 1
    {
        let boundary = format!("ar-io-{digest}");
        let (parts, content_length) = multipart_content(
            &verified.bytes,
            ranges,
            &verified.content_type,
            verified.content_encoding.as_deref(),
            &boundary,
        )?;
        let mut parts = parts.into_iter();
        let first = parts.next().context("multipart response has no parts")?;
        // The envelope is not content-encoded; each part describes the encoded representation.
        return builder
            .status(StatusCode::PARTIAL_CONTENT)
            .header(
                "content-type",
                format!("multipart/byteranges; boundary={boundary}"),
            )
            .header("content-length", content_length.to_string())
            .body(response_body(first, parts, limits, permit).await?)
            .context("failed to construct multipart response");
    }
    if let Some(encoding) = &verified.content_encoding {
        builder = builder.header("content-encoding", encoding.as_str());
    }

    match range {
        Some(ranges) => {
            let (start, end) = ranges[0];
            let content_length = end - start + 1;
            builder
                .status(StatusCode::PARTIAL_CONTENT)
                .header("content-type", verified.content_type.as_str())
                .header("content-length", content_length.to_string())
                .header(
                    "content-range",
                    format!("bytes {start}-{end}/{}", verified.content_length),
                )
                .body(content_body(verified.bytes.slice(start..end + 1)?, limits, permit).await?)
                .context("failed to construct partial response")
        }
        None => builder
            .status(StatusCode::OK)
            .header("content-type", verified.content_type.as_str())
            .header("content-length", verified.content_length.to_string())
            .body(content_body(verified.bytes, limits, permit).await?)
            .context("failed to construct HTTP response"),
    }
}

async fn chunk_response(
    chunk: VerifiedChunk,
    raw: bool,
    request_headers: &HeaderMap,
    limits: &Config,
    permit: OwnedSemaphorePermit,
) -> Result<Response> {
    let VerifiedChunk {
        bytes,
        chunk,
        data_path,
        tx_path,
        data_root,
        data_size,
        start_offset,
        relative_start_offset,
        read_offset,
        tx_start_offset,
        source_host,
    } = chunk;
    let body = if raw {
        bytes
    } else {
        serde_json::to_vec(&ChunkJsonResponse {
            chunk: &chunk,
            data_path: &data_path,
            tx_path: &tx_path,
            packing: "unpacked",
        })
        .context("failed to encode chunk response")?
    };
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let digest_url = URL_SAFE_NO_PAD.encode(digest);
    let etag = format!("\"{digest_url}\"");
    let content_type = if raw {
        "application/octet-stream"
    } else {
        "application/json; charset=utf-8"
    };
    let mut builder = Response::builder()
        .header("etag", etag.as_str())
        .header(
            "content-digest",
            format!("sha-256=:{}:", STANDARD.encode(digest)),
        )
        .header("x-ar-io-chunk-source-type", "arweave-network")
        .header("x-ar-io-chunk-host", source_host)
        .header("x-cache", "MISS");
    if raw {
        builder = builder
            .header("x-arweave-chunk-data-path", data_path)
            .header("x-arweave-chunk-data-root", data_root)
            .header("x-arweave-chunk-start-offset", start_offset.to_string())
            .header(
                "x-arweave-chunk-relative-start-offset",
                relative_start_offset.to_string(),
            )
            .header("x-arweave-chunk-read-offset", read_offset.to_string())
            .header("x-arweave-chunk-tx-data-size", data_size.to_string())
            .header("x-arweave-chunk-tx-path", tx_path)
            .header(
                "x-arweave-chunk-tx-start-offset",
                tx_start_offset.to_string(),
            );
    }
    if request_headers
        .get("if-none-match")
        .is_some_and(|value| value.as_bytes() == etag.as_bytes())
    {
        return builder
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .context("failed to construct chunk not-modified response");
    }
    builder
        .status(StatusCode::OK)
        .header("content-type", content_type)
        .header("content-length", body.len().to_string())
        .header("cache-control", "public, max-age=30")
        .body(content_body(body.into(), limits, permit).await?)
        .context("failed to construct chunk response")
}

fn is_data_id_shape(id: &str) -> bool {
    id.len() == 43
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn retrieval_error_response(error: anyhow::Error) -> Response {
    if error.is::<crate::ContentNotFound>() {
        error_response(StatusCode::NOT_FOUND, "Not Found")
    } else {
        eprintln!("verified retrieval failed: {error:#}");
        error_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
    }
}

fn empty_error_response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header("content-length", "0")
        .body(Body::empty())
        .unwrap()
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("content-length", message.len().to_string())
        .body(Body::from(message))
        .unwrap()
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    let authority = headers
        .get(HOST)?
        .to_str()
        .ok()?
        .parse::<Authority>()
        .ok()?;
    Some(authority.host().trim_end_matches('.').to_ascii_lowercase())
}

fn arns_name(headers: &HeaderMap, root_host: &str) -> Option<String> {
    let host = request_host(headers)?;
    let name = host.strip_suffix(&format!(".{root_host}"))?;
    split_arns_name(name).ok()?;
    Some(name.to_owned())
}

fn split_arns_name(name: &str) -> Result<(String, String)> {
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "invalid ArNS name length"
    );
    ensure!(
        name.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'-' | b'_')),
        "invalid ArNS name characters"
    );
    ensure!(
        !matches!(name.as_bytes().first(), Some(b'-' | b'_'))
            && !matches!(name.as_bytes().last(), Some(b'-' | b'_')),
        "invalid ArNS name boundary"
    );
    let mut parts = name.split('_').collect::<Vec<_>>();
    ensure!(
        parts.iter().all(|part| !part.is_empty()),
        "invalid ArNS name"
    );
    let basename = parts.pop().unwrap().to_owned();
    let undername = if parts.is_empty() {
        "@".to_owned()
    } else {
        parts.join("_")
    };
    Ok((basename, undername))
}

fn validate_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty() && host.len() <= 253,
        "invalid ARNS_ROOT_HOST"
    );
    for label in host.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid ARNS_ROOT_HOST"
        );
        ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "invalid ARNS_ROOT_HOST"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "invalid ARNS_ROOT_HOST"
        );
    }
    Ok(())
}

fn decode_pubkey(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(value)
        .into_vec()
        .with_context(|| format!("invalid {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong size"))
}

fn read_string<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
    label: &str,
) -> Result<&'a str> {
    let length = usize::try_from(read_u32(bytes, cursor, label)?)
        .with_context(|| format!("{label} length is too large"))?;
    ensure!(length <= maximum, "{label} exceeds length limit");
    std::str::from_utf8(take(bytes, cursor, length, label)?)
        .with_context(|| format!("{label} is not UTF-8"))
}

fn read_option_i64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<Option<i64>> {
    match read_u8(bytes, cursor, label)? {
        0 => Ok(None),
        1 => Ok(Some(read_i64(bytes, cursor, label)?)),
        _ => bail!("{label} option is invalid"),
    }
}

fn read_option_u32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<Option<u32>> {
    match read_u8(bytes, cursor, label)? {
        0 => Ok(None),
        1 => Ok(Some(read_u32(bytes, cursor, label)?)),
        _ => bail!("{label} option is invalid"),
    }
}

fn read_option_bytes32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<()> {
    match read_u8(bytes, cursor, label)? {
        0 => Ok(()),
        1 => {
            take(bytes, cursor, 32, label)?;
            Ok(())
        }
        _ => bail!("{label} option is invalid"),
    }
}

fn read_u8(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u8> {
    Ok(take(bytes, cursor, 1, label)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        take(bytes, cursor, 2, label)?.try_into().unwrap(),
    ))
}

fn read_u32(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        take(bytes, cursor, 4, label)?.try_into().unwrap(),
    ))
}

fn read_u64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(
        take(bytes, cursor, 8, label)?.try_into().unwrap(),
    ))
}

fn read_i64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<i64> {
    Ok(i64::from_le_bytes(
        take(bytes, cursor, 8, label)?.try_into().unwrap(),
    ))
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize, label: &str) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .with_context(|| format!("{label} offset overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .with_context(|| format!("{label} is truncated"))?;
    *cursor = end;
    Ok(value)
}

#[derive(Deserialize)]
struct SolanaRpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

impl<T> SolanaRpcResponse<T> {
    fn into_result(self) -> Result<T> {
        ensure!(
            self.jsonrpc == "2.0" && self.id == 1,
            "invalid Solana RPC envelope"
        );
        if let Some(error) = self.error {
            bail!("Solana RPC rejected request (code {})", error.code);
        }
        self.result.context("Solana RPC omitted result")
    }
}

#[derive(Deserialize)]
struct AccountInfoResult {
    #[serde(deserialize_with = "Option::deserialize")]
    value: Option<SolanaAccount>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
}

#[derive(Deserialize)]
struct ProgramAccount {
    pubkey: String,
    account: SolanaAccount,
}

#[derive(Deserialize)]
struct SolanaAccount {
    data: [String; 2],
    owner: String,
    executable: bool,
    space: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentWriter, SpoolBudget};
    use axum::body::HttpBody as _;

    const ARNS_ACCOUNT: &str = "NZ4qfQeEaLwF6jmlT8XLNtBIvGDG/foSDuHpVUuCqaQ+a2p0ioe5aC2+lbeF1KeVB3WX89Ksp18jfWPgMFBF9tJsgtCTCP9M76AI6Wt+7PHPwtgIPrVmlgBd2KoBvC2lEcnNDTc0HywBgHC2ZwAAAAAAZAAAAAAAAAAAAP4JAAAAbG9sY2NoZWtjAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const ANT_ACCOUNT: &str = "4V5G8FIth1HvoAjpa37s8c/C2Ag+tWaWAF3YqgG8LaURyc0NNzQfLAEAAABAKwAAADNGX3lsZHFXX3p0NkNpXzQ3dy03Tzc2bFBwZWdwdTFyczdIMml5dWx0VlkAEA4AAAEAAAAAAC2+lbeF1KeVB3WX89Ksp18jfWPgMFBF9tJsgtCTCP9M/wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const ARNS_PROGRAM: &str = "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ";
    const ANT_PROGRAM: &str = "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5";

    #[test]
    fn formats_utc_milliseconds_across_leap_year_boundaries() {
        for (millis, expected) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (951_782_399_999, "2000-02-28T23:59:59.999Z"),
            (951_782_400_007, "2000-02-29T00:00:00.007Z"),
            (4_107_542_399_999, "2100-02-28T23:59:59.999Z"),
            (4_107_542_400_000, "2100-03-01T00:00:00.000Z"),
        ] {
            assert_eq!(
                iso_utc_date(UNIX_EPOCH + Duration::from_millis(millis)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn decodes_captured_arns_and_ant_accounts() {
        let arns_bytes = STANDARD.decode(ARNS_ACCOUNT).unwrap();
        let name_hash: [u8; 32] = Sha256::digest(b"lolcchekc").into();
        let arns = decode_arns_record(&arns_bytes).unwrap();
        assert_eq!(
            bs58::encode(arns.ant).into_string(),
            "H8Pya8AGbnt39Em7Zy5EHiXGY1MEuV5MpSM2JXzNYYY3"
        );
        assert_eq!(arns.undername_limit, 100);
        assert_eq!(arns.end_timestamp, None);
        assert_eq!(arns.bump, 254);
        let (arns_address, arns_bump) = derive_pda(
            ARNS_PROGRAM,
            &[ARNS_RECORD_SEED, name_hash.as_slice()],
            "ArNS record",
        )
        .unwrap();
        assert_eq!(arns_address, "E8Vm6GR2CDdsx5FRaxQ7iVoN832mTjufN8zuB2pvzpYn");
        assert_eq!(arns_bump, arns.bump);
        let mut lease_bytes = arns_bytes.clone();
        lease_bytes[104] = 0;
        lease_bytes[113] = 1;
        lease_bytes.splice(114..114, 100_i64.to_le_bytes());
        assert_eq!(
            decode_arns_record(&lease_bytes).unwrap().end_timestamp,
            Some(100)
        );

        let ant_bytes = STANDARD.decode(ANT_ACCOUNT).unwrap();
        let ant = decode_ant_record(&ant_bytes, &arns.ant).unwrap();
        assert_eq!(ant.undername, "@");
        assert_eq!(ant.target, "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY");
        assert_eq!(ant.target_protocol, 0);
        assert_eq!(ant.ttl, 3600);
        assert_eq!(ant.bump, 255);
        let undername_hash: [u8; 32] = Sha256::digest(b"@").into();
        let (ant_address, ant_bump) = derive_pda(
            ANT_PROGRAM,
            &[
                ANT_RECORD_SEED,
                arns.ant.as_slice(),
                undername_hash.as_slice(),
            ],
            "ANT record",
        )
        .unwrap();
        assert_eq!(ant_address, "3JEvMXaLmWvya2jtEX7pgzxHqZB5iiK2GQNdFXcjj26G");
        assert_eq!(ant_bump, ant.bump);

        assert!(decode_arns_record(&arns_bytes[..100]).is_err());
        assert!(decode_ant_record(&ant_bytes[..100], &arns.ant).is_err());
        let mut wrong_hash = arns_bytes.clone();
        wrong_hash[8] ^= 1;
        assert!(decode_arns_record(&wrong_hash).is_err());
    }

    fn ant_program_account(mint: &[u8; 32], name: &str, priority: Option<u32>) -> ProgramAccount {
        let hash: [u8; 32] = Sha256::digest(name.to_ascii_lowercase()).into();
        let (pubkey, bump) =
            derive_pda(ANT_PROGRAM, &[ANT_RECORD_SEED, mint, &hash], "ANT record").unwrap();
        let mut data = ANT_RECORD_DISCRIMINATOR.to_vec();
        data.extend_from_slice(mint);
        for value in [name, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
            data.extend_from_slice(&(value.len() as u32).to_le_bytes());
            data.extend_from_slice(value.as_bytes());
        }
        data.push(0);
        data.extend_from_slice(&3600_u32.to_le_bytes());
        data.push(u8::from(priority.is_some()));
        if let Some(priority) = priority {
            data.extend_from_slice(&priority.to_le_bytes());
        }
        data.push(0);
        data.extend_from_slice(&[0; 32]);
        data.extend_from_slice(&[bump, 1, 0, 0]);
        ProgramAccount {
            pubkey,
            account: SolanaAccount {
                data: [STANDARD.encode(&data), "base64".to_owned()],
                owner: ANT_PROGRAM.to_owned(),
                executable: false,
                space: data.len(),
            },
        }
    }

    #[test]
    fn selects_ant_records_in_deterministic_order() {
        let mint = [9; 32];
        let mut names = [
            ("z-unset", None),
            ("priority-z", Some(5)),
            ("a-unset", None),
            ("@", Some(u32::MAX)),
            ("priority-a", Some(5)),
            ("last-priority", Some(u32::MAX)),
            ("zero", Some(0)),
            ("MiXeD", Some(9)),
        ];
        for _ in 0..2 {
            for (expected_index, wanted) in [
                "@",
                "zero",
                "priority-a",
                "priority-z",
                "mixed",
                "last-priority",
                "a-unset",
                "z-unset",
            ]
            .into_iter()
            .enumerate()
            {
                let accounts = names
                    .iter()
                    .map(|(name, priority)| ant_program_account(&mint, name, *priority))
                    .collect();
                let (index, record) = select_ant_record(accounts, ANT_PROGRAM, &mint, wanted)
                    .unwrap()
                    .unwrap();
                assert_eq!(index, expected_index, "{wanted}");
                assert_eq!(record.undername, wanted);
            }
            names.reverse();
        }
        assert!(
            select_ant_record(
                vec![ant_program_account(&mint, "@", None)],
                ANT_PROGRAM,
                &mint,
                "missing"
            )
            .unwrap()
            .is_none()
        );
        assert!(
            select_ant_record(Vec::new(), ANT_PROGRAM, &mint, "missing")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_invalid_ant_record_sets() {
        let mint = [9; 32];
        let reject = |bad| {
            assert!(
                select_ant_record(
                    vec![
                        ant_program_account(&mint, "@", None),
                        ant_program_account(&mint, "valid", Some(0)),
                        bad,
                    ],
                    ANT_PROGRAM,
                    &mint,
                    "valid"
                )
                .is_err()
            );
        };
        let other = || ant_program_account(&mint, "other", None);
        let mut bad = other();
        bad.pubkey = bs58::encode([0; 32]).into_string();
        reject(bad);
        let mut bad = other();
        bad.account.owner = ARNS_PROGRAM.to_owned();
        reject(bad);
        let mut bad = other();
        bad.account.executable = true;
        reject(bad);
        let mut bad = other();
        bad.account.data[1] = "base58".to_owned();
        reject(bad);
        let mut bad = other();
        bad.account.data[0] = "!".to_owned();
        reject(bad);
        let mut bad = other();
        bad.account.space += 1;
        reject(bad);
        let mut bad = other();
        bad.account.space = MAX_SOLANA_ACCOUNT_BYTES + 1;
        reject(bad);
        reject(ant_program_account(&[8; 32], "other", None));
        reject(ant_program_account(&mint, "bad/name", None));
        reject(ant_program_account(&mint, "VaLiD", Some(99)));

        let data = STANDARD.decode(other().account.data[0].as_bytes()).unwrap();
        for offset in [0, data.len() - 4, data.len() - 1] {
            let mut bad = other();
            let mut corrupted = data.clone();
            corrupted[offset] ^= 1;
            bad.account.data[0] = STANDARD.encode(corrupted);
            reject(bad);
        }
        for corrupted in [data[..39].to_vec(), [data, vec![1]].concat()] {
            let mut bad = other();
            bad.account.space = corrupted.len();
            bad.account.data[0] = STANDARD.encode(corrupted);
            reject(bad);
        }
        assert!(
            select_ant_record(
                vec![ant_program_account(&mint, "valid", None)],
                ANT_PROGRAM,
                &mint,
                "valid"
            )
            .is_err()
        );
        let mut oversized = vec![ant_program_account(&mint, "@", None)];
        oversized.extend(
            (0..MAX_ANT_RECORDS)
                .map(|index| ant_program_account(&mint, &format!("record{index}"), None)),
        );
        assert!(select_ant_record(oversized, ANT_PROGRAM, &mint, "record0").is_err());
    }

    #[test]
    fn rejects_incomplete_rpc_envelopes_without_leaking_messages() {
        let result = |value| -> Result<Vec<ProgramAccount>> {
            serde_json::from_value::<SolanaRpcResponse<Vec<ProgramAccount>>>(value)?.into_result()
        };
        for value in [
            serde_json::json!({"jsonrpc": "2.0", "id": 1}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": null}),
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "result": []}),
            serde_json::json!({"jsonrpc": "1.0", "id": 1, "result": []}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"value": [], "paginationKey": "more"}}),
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": [{"pubkey": "missing-account"}]}),
        ] {
            assert!(result(value).is_err());
        }
        let error = result(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": [],
            "error": {"code": -32005, "message": "https://user:secret@rpc.test/?api-key=secret"}
        }))
        .err()
        .unwrap();
        assert!(!format!("{error:#}").contains("secret"));
        assert!(
            serde_json::from_value::<SolanaRpcResponse<AccountInfoResult>>(
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {}})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn enforces_undername_limit_at_serving_boundary() {
        let mut arns_bytes = STANDARD.decode(ARNS_ACCOUNT).unwrap();
        arns_bytes[114..116].copy_from_slice(&1_u16.to_le_bytes());
        let mint = decode_arns_record(&arns_bytes).unwrap().ant;
        let account_json = |account: SolanaAccount| {
            serde_json::json!({
                "data": account.data,
                "owner": account.owner,
                "executable": account.executable,
                "space": account.space,
            })
        };
        let root = ant_program_account(&mint, "@", None);
        let root_address = root.pubkey;
        let root = account_json(root.account);
        let records: Vec<_> = [("extra", None), ("@", None), ("paid", Some(7))]
            .into_iter()
            .map(|(name, priority)| {
                let account = ant_program_account(&mint, name, priority);
                serde_json::json!({
                    "pubkey": account.pubkey,
                    "account": account_json(account.account),
                })
            })
            .collect();
        let arns = serde_json::json!({
            "data": [STANDARD.encode(&arns_bytes), "base64"],
            "owner": ARNS_PROGRAM, "executable": false, "space": arns_bytes.len(),
        });
        let app = Router::new().route(
            "/",
            axum::routing::post(move |body: axum::body::Bytes| {
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let result = match request["method"].as_str() {
                    Some("getAccountInfo") => serde_json::json!({"value":
                        if request["params"][0] == "E8Vm6GR2CDdsx5FRaxQ7iVoN832mTjufN8zuB2pvzpYn" {
                            arns.clone()
                        } else if request["params"][0] == root_address {
                            root.clone()
                        } else {
                            serde_json::Value::Null
                        }
                    }),
                    Some("getProgramAccounts") => serde_json::json!(records),
                    _ => serde_json::Value::Null,
                };
                async move {
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway::new(stream_limits()).unwrap();
        let bytes = b"paid content".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        gateway.cache.lock().unwrap().insert(
            VerifiedData {
                content_length: bytes.len(),
                bytes: bytes.into(),
                cache_hit: false,
                id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                block_height: 1,
                content_type: "text/plain".to_owned(),
                content_encoding: None,
                etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(digest)),
                sha256: super::super::hex(&digest),
                indexing_root: None,
            },
            1,
            1024,
        );
        let state = AppState {
            gateway,
            config: ServerConfig::new(
                "127.0.0.1:0",
                "example.com",
                &rpc_url,
                ARNS_PROGRAM,
                ANT_PROGRAM,
                8,
            )
            .unwrap(),
            request_permits: Arc::new(Semaphore::new(8)),
            started_at: Instant::now(),
        };
        for (name, status, index) in [
            ("lolcchekc", StatusCode::OK, Some("0")),
            ("paid_lolcchekc", StatusCode::OK, Some("1")),
            ("extra_lolcchekc", StatusCode::PAYMENT_REQUIRED, None),
            ("missing_lolcchekc", StatusCode::NOT_FOUND, None),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, format!("{name}.example.com").parse().unwrap());
            let response = serve_arns_path(
                &state,
                &headers,
                "",
                request_permit(&state.request_permits).unwrap(),
            )
            .await;
            assert_eq!(response.status(), status, "{name}");
            if let Some(index) = index {
                assert_eq!(response.headers()["x-arns-record-index"], index);
                assert_eq!(response.headers()["x-arns-undername-limit"], "1");
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), 1024)
                        .await
                        .unwrap()
                        .as_ref(),
                    b"paid content"
                );
            }
        }
        server.abort();
    }

    #[test]
    fn checks_lease_expiry_and_config_pda() {
        assert!(arns_is_active(100, 10, 109).unwrap());
        assert!(!arns_is_active(100, 10, 110).unwrap());
        let mut config = vec![0; 182];
        config[..8].copy_from_slice(&ARNS_CONFIG_DISCRIMINATOR);
        config[104..112].copy_from_slice(&10_i64.to_le_bytes());
        config[178] = 255;
        config[179..].copy_from_slice(&[1, 0, 0]);
        assert_eq!(decode_arns_config(&config).unwrap(), (10, 255));
        let (config_address, config_bump) =
            derive_pda(ARNS_PROGRAM, &[ARNS_CONFIG_SEED], "ArNS config").unwrap();
        assert_eq!(
            config_address,
            "ENuQZZYp778k5cCAovtD4gS2JxHQ3jVd3fKmNmtcZqQ2"
        );
        assert_eq!(config_bump, 255);
        assert!(arns_is_active(i64::MAX, 1, 0).is_err());
    }

    #[test]
    fn rejects_saturated_requests_and_releases_permits() {
        let permits = Arc::new(Semaphore::new(1));
        let held = request_permit(&permits).unwrap();
        let response = request_permit(&permits).unwrap_err();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        drop(held);
        assert!(request_permit(&permits).is_ok());
        assert!(
            ServerConfig::new(
                "127.0.0.1:0",
                "ar.mrx.im",
                "http://127.0.0.1:1",
                ARNS_PROGRAM,
                ANT_PROGRAM,
                0,
            )
            .is_err()
        );
    }

    fn stream_limits() -> Config {
        Config::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            vec!["http://127.0.0.1:1".to_owned()],
            Duration::from_secs(1),
            1,
            RESPONSE_CHUNK_BYTES * 4,
        )
        .unwrap()
    }

    // gzip-compressed "hello", including its CRC32 and uncompressed length.
    const GZIP_HELLO: &[u8] = &[
        31, 139, 8, 0, 0, 0, 0, 0, 2, 3, 203, 72, 205, 201, 201, 7, 0, 134, 166, 16, 54, 5, 0, 0, 0,
    ];

    fn response_fixture(bytes: &[u8]) -> VerifiedData {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        VerifiedData {
            bytes: bytes.to_vec().into(),
            cache_hit: false,
            id: "fqheRv90pWZYwxcsNyVafsoT9tOipnSa_8tVMMX9b3s".to_owned(),
            block_height: 1_993_814,
            content_type: "text/plain; charset=utf-8".to_owned(),
            content_encoding: None,
            content_length: bytes.len(),
            etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(digest)),
            sha256: super::super::hex(&digest),
            indexing_root: None,
        }
    }

    #[tokio::test]
    async fn public_cors_encoding_head_and_invalid_ids() {
        let gateway = Gateway::new(stream_limits()).unwrap();
        let mut verified = response_fixture(GZIP_HELLO);
        verified.content_encoding = Some("gzip".to_owned());
        let id = verified.id.clone();
        let etag = verified.etag.clone();
        gateway.cache.lock().unwrap().insert(
            verified,
            gateway.config.cache_max_entries,
            gateway.config.cache_max_bytes,
        );
        let state = Arc::new(AppState {
            gateway,
            config: ServerConfig::new(
                "127.0.0.1:0",
                "example.com",
                "http://127.0.0.1:1",
                ARNS_PROGRAM,
                ANT_PROGRAM,
                1,
            )
            .unwrap(),
            request_permits: Arc::new(Semaphore::new(1)),
            started_at: Instant::now(),
        });
        let app = Router::new()
            .route("/raw/{id}", get(serve_raw))
            .route("/{*path}", get(serve_path))
            .layer(middleware::from_fn(cors_response))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let preflight = client
            .request(Method::OPTIONS, format!("{base}/unknown"))
            .header("origin", "https://example.test")
            .header("access-control-request-method", "GET")
            .header("access-control-request-headers", "Range, If-None-Match")
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(preflight.headers()["access-control-allow-origin"], "*");
        assert_eq!(preflight.headers()["access-control-expose-headers"], "*");
        assert_eq!(
            preflight.headers()["access-control-allow-methods"],
            "GET,HEAD,PUT,PATCH,POST,DELETE"
        );
        assert_eq!(
            preflight.headers()["access-control-allow-headers"],
            "Range, If-None-Match"
        );
        assert_eq!(
            preflight.headers()["vary"],
            "Access-Control-Request-Headers"
        );
        assert!(preflight.bytes().await.unwrap().is_empty());

        let invalid = format!("{}B", "A".repeat(42));
        for (method, path, status) in [
            (
                Method::POST,
                format!("/raw/{id}"),
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (Method::GET, "/unknown".to_owned(), StatusCode::NOT_FOUND),
            (Method::GET, "/raw/short".to_owned(), StatusCode::NOT_FOUND),
            (
                Method::GET,
                format!("/raw/{invalid}"),
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                format!("/{invalid}/path"),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = client
                .request(method, format!("{base}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
            assert_eq!(response.headers()["access-control-allow-origin"], "*");
            assert_eq!(response.headers()["access-control-expose-headers"], "*");
        }
        let response = client.get(format!("{base}/raw/{id}")).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-encoding"], "gzip");
        assert_eq!(
            response.headers()["content-length"],
            GZIP_HELLO.len().to_string()
        );
        assert_eq!(
            response.headers()["cache-control"],
            "public, max-age=2592000, immutable"
        );
        assert_eq!(
            response.headers()["content-digest"],
            format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(GZIP_HELLO)))
        );
        assert_eq!(response.bytes().await.unwrap().as_ref(), GZIP_HELLO);
        let head = client
            .head(format!("{base}/raw/{id}"))
            .header("range", "bytes=0-1,2-3")
            .send()
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::PARTIAL_CONTENT);
        assert!(
            head.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("multipart/byteranges; boundary=")
        );
        assert!(!head.headers().contains_key("content-encoding"));
        assert!(head.bytes().await.unwrap().is_empty());
        let conditional = client
            .get(format!("{base}/raw/{id}"))
            .header("if-none-match", etag)
            .send()
            .await
            .unwrap();
        assert_eq!(conditional.status(), StatusCode::NOT_MODIFIED);
        for header in [
            "content-type",
            "content-encoding",
            "content-range",
            "content-length",
        ] {
            assert!(!conditional.headers().contains_key(header), "{header}");
        }
        assert!(conditional.bytes().await.unwrap().is_empty());
        let _permit = request_permit(&state.request_permits).unwrap();
        server.abort();
    }

    #[test]
    fn keeps_verification_failures_distinct_from_missing_content() {
        let missing =
            anyhow::Error::new(crate::ContentNotFound).context("retrieving manifest target");
        assert_eq!(
            retrieval_error_response(missing).status(),
            StatusCode::NOT_FOUND
        );
        let invalid = anyhow::anyhow!("invalid chunk proof");
        assert_eq!(
            retrieval_error_response(invalid).status(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[tokio::test]
    async fn streams_encoded_multipart_and_releases_spool() {
        let mut limits = stream_limits();
        limits.stream_idle_timeout = Duration::from_secs(5);
        limits.stream_timeout = Duration::from_secs(30);
        let config = ServerConfig::new(
            "127.0.0.1:0",
            "example.com",
            "http://127.0.0.1:1",
            ARNS_PROGRAM,
            ANT_PROGRAM,
            1,
        )
        .unwrap();
        let permits = Arc::new(Semaphore::new(1));
        let budget = Arc::new(SpoolBudget::new(GZIP_HELLO.len()));
        for (consume, expire) in [(true, false), (false, false), (false, true)] {
            let mut writer = ContentWriter::new(GZIP_HELLO.len(), 1, budget.clone())
                .await
                .unwrap();
            writer.write(GZIP_HELLO).await.unwrap();
            let (content, _) = writer.finish().await.unwrap();
            let mut verified = response_fixture(GZIP_HELLO);
            verified.bytes = content;
            verified.content_encoding = Some("gzip".to_owned());
            let mut headers = HeaderMap::new();
            headers.insert("range", "bytes=23-24, 99-,0-1,1-2".parse().unwrap());
            let response = verified_response(
                verified,
                None,
                &config,
                &headers,
                &limits,
                request_permit(&permits).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert!(!response.headers().contains_key("content-range"));
            assert!(!response.headers().contains_key("content-encoding"));
            let boundary = response.headers()["content-type"]
                .to_str()
                .unwrap()
                .strip_prefix("multipart/byteranges; boundary=")
                .unwrap();
            let mut expected = Vec::new();
            for (start, end) in [(23, 24), (0, 1), (1, 2)] {
                expected.extend_from_slice(format!(
                    "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Range: bytes {start}-{end}/25\r\n\r\n"
                ).as_bytes());
                expected.extend_from_slice(&GZIP_HELLO[start..=end]);
                expected.extend_from_slice(b"\r\n");
            }
            expected.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            assert_eq!(
                response.headers()["content-length"],
                expected.len().to_string()
            );
            assert!(request_permit(&permits).is_err());
            assert!(
                ContentWriter::new(GZIP_HELLO.len(), 1, budget.clone())
                    .await
                    .is_err()
            );
            if consume {
                assert_eq!(
                    axum::body::to_bytes(response.into_body(), expected.len())
                        .await
                        .unwrap()
                        .as_ref(),
                    expected
                );
            } else if expire {
                tokio::time::pause();
                tokio::task::yield_now().await;
                tokio::time::advance(limits.stream_idle_timeout).await;
                tokio::task::yield_now().await;
                assert!(
                    axum::body::to_bytes(response.into_body(), expected.len())
                        .await
                        .is_err()
                );
                tokio::time::resume();
            } else {
                drop(response);
            }
            let _permit = request_permit(&permits).unwrap();
            drop(
                ContentWriter::new(GZIP_HELLO.len(), 1, budget.clone())
                    .await
                    .unwrap(),
            );
        }
    }

    #[tokio::test]
    async fn builds_verified_arns_response_headers() {
        let bytes = b"hello".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let digest_url = URL_SAFE_NO_PAD.encode(digest);
        let verified = VerifiedData {
            bytes: bytes.into(),
            cache_hit: false,
            id: "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY".to_owned(),
            block_height: 1_118_819,
            content_type: "text/html; charset=utf-8".to_owned(),
            content_encoding: None,
            content_length: 5,
            etag: format!("\"{digest_url}\""),
            sha256: super::super::hex(&digest),
            indexing_root: None,
        };
        let resolution = Resolution {
            name: "lolcchekc".to_owned(),
            basename: "lolcchekc".to_owned(),
            record: "@".to_owned(),
            resolved_id: verified.id.clone(),
            ttl: 3600,
            ant_id: "H8Pya8AGbnt39Em7Zy5EHiXGY1MEuV5MpSM2JXzNYYY3".to_owned(),
            limit: 100,
            index: 0,
            resolved_at: 1,
        };
        let config = ServerConfig::new(
            "127.0.0.1:0",
            "ar.mrx.im",
            "http://127.0.0.1:1",
            ARNS_PROGRAM,
            ANT_PROGRAM,
            8,
        )
        .unwrap();
        let response = verified_response(
            verified,
            Some(&resolution),
            &config,
            &HeaderMap::new(),
            &stream_limits(),
            request_permit(&Arc::new(Semaphore::new(1))).unwrap(),
        )
        .await
        .unwrap();
        let headers = response.headers();
        assert_eq!(headers["content-type"], "text/html; charset=utf-8");
        assert_eq!(headers["content-length"], "5");
        assert_eq!(headers["x-ar-io-verified"], "true");
        assert_eq!(headers["x-arns-name"], "lolcchekc");
        assert_eq!(headers["x-arns-record"], "@");
        assert_eq!(headers["x-arns-ttl-seconds"], "3600");
        assert_eq!(headers["cache-control"], "public, max-age=3600");

        let mut host_headers = HeaderMap::new();
        host_headers.insert(HOST, "lolcchekc.ar.mrx.im:3000".parse().unwrap());
        assert_eq!(arns_name(&host_headers, "ar.mrx.im").unwrap(), "lolcchekc");
    }

    #[test]
    fn resolves_manifests_and_encodes_sandbox_hosts() {
        const INDEX_ID: &str = "cG7Hdi_iTQPoEYgQJFqJ8NMpN4KoZ-vH_j7pG4iP7NI";
        const PATH_ID: &str = "fZ4d7bkCAUiXSfo3zFsPiQvpLVKVtXUKB6kiLNt2XVQ";
        const FALLBACK_ID: &str = "0543SMRGYuGKTaqLzmpOyK4AxAB96Fra2guHzYxjRGo";
        assert!(is_manifest_content_type(
            "application/x.arweave-manifest+json; charset=utf-8"
        ));
        let v1 = format!(
            r#"{{"manifest":"arweave/paths","version":"0.1.0","index":{{"path":"index.html"}},"paths":{{"index.html":{{"id":"{INDEX_ID}"}},"css/style.css":{{"id":"{PATH_ID}"}}}}}}"#
        );
        assert_eq!(
            resolve_manifest(v1.as_bytes(), "").unwrap().unwrap().id,
            INDEX_ID
        );
        assert_eq!(
            resolve_manifest(v1.as_bytes(), "css/style.css/")
                .unwrap()
                .unwrap()
                .id,
            PATH_ID
        );
        assert!(
            resolve_manifest(v1.as_bytes(), "missing")
                .unwrap()
                .is_none()
        );

        let v2 = format!(
            r#"{{"manifest":"arweave/paths","version":"0.2.0","index":{{"id":"{INDEX_ID}"}},"fallback":{{"id":"{FALLBACK_ID}"}},"paths":{{}}}}"#
        );
        assert_eq!(
            resolve_manifest(v2.as_bytes(), "").unwrap().unwrap().id,
            INDEX_ID
        );
        let fallback = resolve_manifest(v2.as_bytes(), "missing").unwrap().unwrap();
        assert_eq!(fallback.id, FALLBACK_ID);
        assert!(fallback.fallback);

        let missing_index = format!(
            r#"{{"manifest":"arweave/paths","version":"0.1.0","index":"0","paths":{{"0":{{"id":"{PATH_ID}"}}}}}}"#
        );
        assert!(
            resolve_manifest(missing_index.as_bytes(), "")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            resolve_manifest(missing_index.as_bytes(), "0")
                .unwrap()
                .unwrap()
                .id,
            PATH_ID
        );
        assert!(
            resolve_manifest(
                br#"{"manifest":"arweave/paths","version":"0.2.0","index":{"id":"bad"},"paths":{}}"#,
                ""
            )
            .is_err()
        );

        let id =
            decode_fixed::<32>("TB2wJyKrPnkAW79DAwlJYwpgdHKpijEJWQfcwX715Co", "data ID").unwrap();
        assert_eq!(
            sandbox_name(&id),
            "jqo3ajzcvm7hsac3x5bqgckjmmfga5dsvgfdcckza7omc7xv4qva"
        );
    }
    #[tokio::test]
    async fn serves_single_ranges_and_etag_conditionals() {
        let config = ServerConfig::new(
            "127.0.0.1:0",
            "ar.mrx.im",
            "http://127.0.0.1:1",
            ARNS_PROGRAM,
            ANT_PROGRAM,
            8,
        )
        .unwrap();
        let limits = stream_limits();
        let permits = Arc::new(Semaphore::new(1));
        let verified = || response_fixture(b"hello");

        let mut headers = HeaderMap::new();
        headers.insert("range", "bytes=1-3".parse().unwrap());
        let response = verified_response(
            verified(),
            None,
            &config,
            &headers,
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()["accept-ranges"], "bytes");
        assert_eq!(response.headers()["content-range"], "bytes 1-3/5");
        assert_eq!(response.headers()["content-length"], "3");
        assert_eq!(
            response.headers()["cache-control"],
            "public, max-age=2592000, immutable"
        );
        assert_eq!(
            &axum::body::to_bytes(response.into_body(), 3).await.unwrap()[..],
            b"ell"
        );

        headers.clear();
        headers.insert("if-none-match", verified().etag.parse().unwrap());
        let response = verified_response(
            verified(),
            None,
            &config,
            &headers,
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(!response.headers().contains_key("content-length"));
        assert!(!response.headers().contains_key("content-type"));
        assert!(
            axum::body::to_bytes(response.into_body(), 0)
                .await
                .unwrap()
                .is_empty()
        );

        headers.clear();
        headers.insert("range", "bytes=5-".parse().unwrap());
        let response = verified_response(
            verified(),
            None,
            &config,
            &headers,
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers()["content-range"], "bytes */5");

        assert_eq!(parse_byte_ranges("bytes=-2", 5), Ok(vec![(3, 4)]));
        assert_eq!(
            parse_byte_ranges("bytes=1-2,4-5", 5),
            Ok(vec![(1, 2), (4, 4)])
        );
        let maximum = format!("bytes={}", vec!["0-0"; MAX_BYTE_RANGES].join(","));
        assert_eq!(
            parse_byte_ranges(&maximum, 1).unwrap(),
            vec![(0, 0); MAX_BYTE_RANGES]
        );
        assert_eq!(
            parse_byte_ranges(&format!("{maximum},0-0"), 1),
            Err(ByteRangeError::Unsatisfiable)
        );
        assert_eq!(
            parse_byte_ranges(&" ".repeat(MAX_RANGE_HEADER_BYTES + 1), 1),
            Err(ByteRangeError::Malformed)
        );
    }

    #[tokio::test]
    async fn builds_chunk_json_raw_and_conditional_responses() {
        let limits = stream_limits();
        let permits = Arc::new(Semaphore::new(1));
        let verified = || VerifiedChunk {
            bytes: b"hello".to_vec(),
            chunk: "aGVsbG8".to_owned(),
            data_path: "data-path".to_owned(),
            tx_path: "tx-path".to_owned(),
            data_root: "data-root".to_owned(),
            data_size: 5,
            start_offset: 100,
            relative_start_offset: 2,
            read_offset: 102,
            tx_start_offset: 98,
            source_host: "arweave.net".to_owned(),
        };

        let response = chunk_response(
            verified(),
            false,
            &HeaderMap::new(),
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "public, max-age=30");
        assert_eq!(
            response.headers()["content-type"],
            "application/json; charset=utf-8"
        );
        assert_eq!(response.headers()["x-ar-io-chunk-host"], "arweave.net");
        let etag = response.headers()["etag"].clone();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            &body[..],
            br#"{"chunk":"aGVsbG8","data_path":"data-path","tx_path":"tx-path","packing":"unpacked"}"#
        );

        let response = chunk_response(
            verified(),
            true,
            &HeaderMap::new(),
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(response.headers()["x-arweave-chunk-data-path"], "data-path");
        assert_eq!(response.headers()["x-arweave-chunk-data-root"], "data-root");
        assert_eq!(response.headers()["x-arweave-chunk-start-offset"], "100");
        assert_eq!(
            response.headers()["x-arweave-chunk-relative-start-offset"],
            "2"
        );
        assert_eq!(response.headers()["x-arweave-chunk-read-offset"], "102");
        assert_eq!(response.headers()["x-arweave-chunk-tx-data-size"], "5");
        assert_eq!(response.headers()["x-arweave-chunk-tx-path"], "tx-path");
        assert_eq!(response.headers()["x-arweave-chunk-tx-start-offset"], "98");
        assert_eq!(
            &axum::body::to_bytes(response.into_body(), 5).await.unwrap()[..],
            b"hello"
        );

        let mut headers = HeaderMap::new();
        headers.insert("if-none-match", etag);
        let response = chunk_response(
            verified(),
            false,
            &headers,
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        for header in [
            "content-type",
            "content-encoding",
            "content-range",
            "content-length",
        ] {
            assert!(!response.headers().contains_key(header), "{header}");
        }
        assert!(!response.headers().contains_key("cache-control"));
        assert!(
            axum::body::to_bytes(response.into_body(), 0)
                .await
                .unwrap()
                .is_empty()
        );
    }

    async fn spooled_body(
        limits: &Config,
        permits: &Arc<Semaphore>,
        budget: Arc<SpoolBudget>,
    ) -> Body {
        let mut writer = ContentWriter::new(5, 1, budget).await.unwrap();
        writer.write(b"hello").await.unwrap();
        let (content, _) = writer.finish().await.unwrap();
        content_body(
            content.slice(1..4).unwrap(),
            limits,
            request_permit(permits).unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn spooled_response_releases_resources_on_drop_and_completion() {
        let limits = stream_limits();
        let permits = Arc::new(Semaphore::new(1));
        let budget = Arc::new(SpoolBudget::new(5));
        for cancel in [true, false] {
            let body = spooled_body(&limits, &permits, budget.clone()).await;
            assert_eq!(
                request_permit(&permits).unwrap_err().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(ContentWriter::new(5, 1, budget.clone()).await.is_err());
            if cancel {
                drop(body);
            } else {
                assert_eq!(&axum::body::to_bytes(body, 3).await.unwrap()[..], b"ell");
            }
            let _permit = request_permit(&permits).unwrap();
            drop(ContentWriter::new(5, 1, budget.clone()).await.unwrap());
        }
    }

    #[tokio::test]
    async fn idle_deadline_reclaims_unpolled_spooled_response() {
        let mut limits = stream_limits();
        limits.stream_idle_timeout = Duration::from_secs(5);
        limits.stream_timeout = Duration::from_secs(30);
        let permits = Arc::new(Semaphore::new(1));
        let budget = Arc::new(SpoolBudget::new(5));
        let body = spooled_body(&limits, &permits, budget.clone()).await;
        tokio::time::pause();
        tokio::task::yield_now().await;
        tokio::time::advance(limits.stream_idle_timeout).await;
        let _permit = tokio::time::timeout(
            Duration::from_millis(1),
            Arc::clone(&permits).acquire_owned(),
        )
        .await
        .unwrap()
        .unwrap();
        drop(ContentWriter::new(5, 1, budget).await.unwrap());
        assert!(axum::body::to_bytes(body, 3).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn active_body_reads_reset_idle_but_not_total_deadline() {
        let mut limits = stream_limits();
        limits.stream_idle_timeout = Duration::from_secs(5);
        limits.stream_timeout = Duration::from_secs(7);
        let permits = Arc::new(Semaphore::new(1));
        let mut body = content_body(
            vec![42; RESPONSE_CHUNK_BYTES * 3].into(),
            &limits,
            request_permit(&permits).unwrap(),
        )
        .await
        .unwrap();
        for elapsed in [0, 4] {
            tokio::time::advance(Duration::from_secs(elapsed)).await;
            let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                .await
                .unwrap()
                .unwrap();
            let chunk = frame.into_data().unwrap();
            assert!(chunk.len() <= RESPONSE_CHUNK_BYTES);
            assert!(chunk.iter().all(|byte| *byte == 42));
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(request_permit(&permits).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        let _permit = request_permit(&permits).unwrap();
        assert!(
            axum::body::to_bytes(body, RESPONSE_CHUNK_BYTES)
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;
    use ed25519_dalek::Signature;

    #[test]
    fn signs_response_and_request_components_and_rejects_tampering() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let signer = HttpSigner {
            address: bs58::encode(key.verifying_key().as_bytes()).into_string(),
            key_id: format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
            ),
            key,
            bind_request: true,
        };
        let mut response = Response::builder()
            .status(206)
            .header("content-digest", "sha-256=:YWJj:")
            .header("x-ar-io-verified", "true")
            .body(Body::empty())
            .unwrap();
        signer.sign(&mut response, &Method::GET, "/raw/id").unwrap();
        let params = response.headers()["signature-input"]
            .to_str()
            .unwrap()
            .strip_prefix("sig1=")
            .unwrap();
        let encoded = response.headers()["signature"]
            .to_str()
            .unwrap()
            .strip_prefix("sig1=:")
            .unwrap()
            .strip_suffix(':')
            .unwrap();
        let signature = Signature::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
        let base = format!(
            "\"@status\": 206\n\"content-digest\": sha-256=:YWJj:\n\"x-ar-io-verified\": true\n\"@method\";req: GET\n\"@path\";req: /raw/id\n\"@signature-params\": {params}"
        );
        let public = signer.key.verifying_key();
        public.verify_strict(base.as_bytes(), &signature).unwrap();
        for (before, after) in [
            ("206", "200"),
            ("YWJj", "YWJk"),
            ("true", "false"),
            ("GET", "HEAD"),
            ("/raw/id", "/raw/other"),
        ] {
            assert!(
                public
                    .verify_strict(base.replacen(before, after, 1).as_bytes(), &signature)
                    .is_err()
            );
        }
        let mut ordinary = Response::new(Body::empty());
        ordinary
            .headers_mut()
            .insert("signature", "untrusted".parse().unwrap());
        signer
            .sign(&mut ordinary, &Method::GET, "/ar-io/info")
            .unwrap();
        assert!(!ordinary.headers().contains_key("signature"));
        assert!(!ordinary.headers().contains_key("signature-input"));
    }

    #[test]
    fn rejects_mismatched_wallet_and_corrupted_keypair() {
        let config = || {
            ServerConfig::new(
                "127.0.0.1:0",
                "example.com",
                "http://127.0.0.1:1",
                "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ",
                "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5",
                1,
            )
            .unwrap()
        };
        let key = SigningKey::from_bytes(&[17; 32]);
        let wallet = bs58::encode(key.verifying_key().as_bytes()).into_string();
        let mut bytes = key.to_keypair_bytes();
        assert!(config().with_signing("wrong-wallet", &bytes, true).is_err());
        bytes[63] ^= 1;
        assert!(config().with_signing(&wallet, &bytes, true).is_err());
    }
}
