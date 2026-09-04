use std::{
    cmp::Ordering,
    collections::HashSet,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::HOST, uri::Authority},
    response::Response,
    routing::get,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

use super::{Gateway, VerifiedData, decode_fixed};

const ARNS_CONFIG_DISCRIMINATOR: [u8; 8] = [117, 20, 158, 16, 49, 85, 82, 24];
const ARNS_RECORD_DISCRIMINATOR: [u8; 8] = [53, 158, 42, 125, 7, 132, 104, 188];
const ANT_RECORD_DISCRIMINATOR: [u8; 8] = [225, 94, 70, 240, 82, 45, 135, 81];
const ARNS_CONFIG_SEED: &[u8] = b"arns_config";
const ARNS_RECORD_SEED: &[u8] = b"arns_record";
const ANT_RECORD_SEED: &[u8] = b"ant_record";
const MAX_SOLANA_ACCOUNT_BYTES: usize = 4096;
const MAX_SOLANA_ACCOUNTS: usize = 1024;

pub struct ServerConfig {
    listen_addr: SocketAddr,
    arns_root_host: String,
    solana_rpc_url: Url,
    arns_program_id: String,
    ant_program_id: String,
}

impl ServerConfig {
    pub fn new(
        listen_addr: &str,
        arns_root_host: &str,
        solana_rpc_url: &str,
        arns_program_id: &str,
        ant_program_id: &str,
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

        Ok(Self {
            listen_addr,
            arns_root_host,
            solana_rpc_url,
            arns_program_id: arns_program_id.to_owned(),
            ant_program_id: ant_program_id.to_owned(),
        })
    }
}

struct AppState {
    gateway: Gateway,
    config: ServerConfig,
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

struct ArnsRecord {
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

struct DecodedProgramAccount {
    pubkey: [u8; 32],
    data: Vec<u8>,
}
pub async fn serve(gateway: Gateway, config: ServerConfig) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .context("failed to bind HTTP listener")?;
    println!("listening on http://{}", listener.local_addr()?);
    let state = Arc::new(AppState { gateway, config });
    let app = Router::new()
        .route("/", get(serve_arns))
        .route("/{id}", get(serve_id))
        .with_state(state);
    axum::serve(listener, app)
        .await
        .context("HTTP server failed")
}

async fn serve_arns(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(name) = arns_name(&headers, &state.config.arns_root_host) else {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    };
    let resolution = match resolve_arns(&state, name).await {
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
    match state.gateway.retrieve(&resolution.resolved_id).await {
        Ok(verified) => verified_response(verified, Some(&resolution), &state.config)
            .unwrap_or_else(|error| {
                eprintln!("response construction failed: {error:#}");
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
            }),
        Err(error) => {
            eprintln!("verified retrieval failed: {error:#}");
            error_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
        }
    }
}

async fn serve_id(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    if decode_fixed::<32>(&id, "data ID").is_err() {
        return error_response(StatusCode::NOT_FOUND, "Not Found");
    }
    match state.gateway.retrieve(&id).await {
        Ok(verified) => verified_response(verified, None, &state.config).unwrap_or_else(|error| {
            eprintln!("response construction failed: {error:#}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
        }),
        Err(error) => {
            eprintln!("verified retrieval failed: {error:#}");
            error_response(StatusCode::BAD_GATEWAY, "Bad Gateway")
        }
    }
}

async fn resolve_arns(state: &AppState, name: String) -> Result<Option<Resolution>> {
    let (basename, undername) = split_arns_name(&name)?;
    let name_hash: [u8; 32] = Sha256::digest(basename.as_bytes()).into();
    let mut arns_filter = Vec::with_capacity(40);
    arns_filter.extend_from_slice(&ARNS_RECORD_DISCRIMINATOR);
    arns_filter.extend_from_slice(&name_hash);
    let arns_accounts = program_accounts(
        &state.gateway,
        &state.config.solana_rpc_url,
        &state.config.arns_program_id,
        &[(0, arns_filter)],
    )
    .await?;
    if arns_accounts.is_empty() {
        return Ok(None);
    }
    ensure!(
        arns_accounts.len() == 1,
        "ArNS lookup returned duplicate base names"
    );
    let arns_account = &arns_accounts[0];
    let arns = decode_arns_record(&arns_account.data, &basename, &name_hash)?;
    verify_pda(
        &arns_account.pubkey,
        &state.config.arns_program_id,
        &[ARNS_RECORD_SEED, name_hash.as_slice()],
        arns.bump,
        "ArNS record",
    )?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?;
    if let Some(end_timestamp) = arns.end_timestamp {
        ensure_arns_active(
            end_timestamp,
            arns_grace_period(state).await?,
            now.as_secs(),
        )?;
    }

    let ant_accounts = program_accounts(
        &state.gateway,
        &state.config.solana_rpc_url,
        &state.config.ant_program_id,
        &[
            (0, ANT_RECORD_DISCRIMINATOR.to_vec()),
            (8, arns.ant.to_vec()),
        ],
    )
    .await?;
    let mut seen = HashSet::new();
    let mut records = ant_accounts
        .iter()
        .map(|account| {
            ensure!(
                seen.insert(account.pubkey),
                "Solana RPC returned a duplicate ANT account"
            );
            let record = decode_ant_record(&account.data, &arns.ant)?;
            let undername_hash: [u8; 32] =
                Sha256::digest(record.undername.to_ascii_lowercase().as_bytes()).into();
            verify_pda(
                &account.pubkey,
                &state.config.ant_program_id,
                &[
                    ANT_RECORD_SEED,
                    arns.ant.as_slice(),
                    undername_hash.as_slice(),
                ],
                record.bump,
                "ANT record",
            )?;
            Ok(record)
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort_by(compare_ant_records);
    let Some((index, record)) = records
        .into_iter()
        .enumerate()
        .find(|(_, record)| record.undername == undername)
    else {
        return Ok(None);
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
    let accounts = program_accounts(
        &state.gateway,
        &state.config.solana_rpc_url,
        &state.config.arns_program_id,
        &[(0, ARNS_CONFIG_DISCRIMINATOR.to_vec())],
    )
    .await?;
    ensure!(
        accounts.len() == 1,
        "ArNS config lookup did not return exactly one account"
    );
    let account = &accounts[0];
    let (grace_period, bump) = decode_arns_config(&account.data)?;
    verify_pda(
        &account.pubkey,
        &state.config.arns_program_id,
        &[ARNS_CONFIG_SEED],
        bump,
        "ArNS config",
    )?;
    Ok(grace_period)
}
fn ensure_arns_active(end_timestamp: i64, grace_period: i64, now: u64) -> Result<()> {
    let expires_at = end_timestamp
        .checked_add(grace_period)
        .context("ArNS lease expiry overflow")?;
    ensure!(
        i64::try_from(now).context("system time is too large")? < expires_at,
        "ArNS lease has expired"
    );
    Ok(())
}

fn compare_ant_records(left: &AntRecord, right: &AntRecord) -> Ordering {
    match (left.undername == "@", right.undername == "@") {
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        _ => {}
    }
    match (left.priority, right.priority) {
        (Some(left_priority), Some(right_priority)) => left_priority
            .cmp(&right_priority)
            .then_with(|| left.undername.cmp(&right.undername)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.undername.cmp(&right.undername),
    }
}

async fn program_accounts(
    gateway: &Gateway,
    rpc_url: &Url,
    program_id: &str,
    filters: &[(usize, Vec<u8>)],
) -> Result<Vec<DecodedProgramAccount>> {
    let filters = filters
        .iter()
        .map(|(offset, bytes)| {
            serde_json::json!({
                "memcmp": {
                    "offset": offset,
                    "bytes": STANDARD.encode(bytes),
                    "encoding": "base64"
                }
            })
        })
        .collect::<Vec<_>>();
    let response: ProgramAccountsResponse = gateway
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
                        "filters": filters
                    }]
                })),
        )
        .await
        .context("Solana RPC request failed")?;
    if let Some(error) = response.error {
        bail!("Solana RPC rejected request: {}", error.message);
    }
    let accounts = response.result.context("Solana RPC omitted result")?;
    ensure!(
        accounts.len() <= MAX_SOLANA_ACCOUNTS,
        "Solana RPC returned too many accounts"
    );
    accounts
        .into_iter()
        .map(|account| decode_program_account(account, program_id))
        .collect()
}

fn decode_program_account(
    account: ProgramAccount,
    program_id: &str,
) -> Result<DecodedProgramAccount> {
    let pubkey = decode_pubkey(&account.pubkey, "Solana account ID")?;
    ensure!(
        account.account.owner == program_id,
        "Solana account owner mismatch"
    );
    ensure!(
        !account.account.executable,
        "Solana data account is executable"
    );
    ensure!(
        account.account.data[1] == "base64",
        "unexpected Solana account encoding"
    );
    let data = STANDARD
        .decode(&account.account.data[0])
        .context("invalid Solana account base64")?;
    ensure!(
        data.len() <= MAX_SOLANA_ACCOUNT_BYTES,
        "Solana account exceeds size limit"
    );
    ensure!(
        data.len() == account.account.space,
        "Solana account size mismatch"
    );
    Ok(DecodedProgramAccount { pubkey, data })
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

fn verify_pda(
    account: &[u8; 32],
    program_id: &str,
    seeds: &[&[u8]],
    bump: u8,
    label: &str,
) -> Result<()> {
    let program_id = Pubkey::new_from_array(decode_pubkey(program_id, "Solana program ID")?);
    let (expected, expected_bump) = Pubkey::try_find_program_address(seeds, &program_id)
        .with_context(|| format!("failed to derive {label} PDA"))?;
    ensure!(
        expected == Pubkey::new_from_array(*account),
        "{label} address is not its canonical PDA"
    );
    ensure!(bump == expected_bump, "{label} bump mismatch");
    Ok(())
}

fn decode_arns_record(
    bytes: &[u8],
    expected_name: &str,
    expected_hash: &[u8; 32],
) -> Result<ArnsRecord> {
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 8, "ArNS discriminator")? == ARNS_RECORD_DISCRIMINATOR,
        "invalid ArNS record discriminator"
    );
    ensure!(
        take(bytes, &mut cursor, 32, "ArNS name hash")? == expected_hash,
        "ArNS name hash mismatch"
    );
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
    ensure!(name == expected_name, "ArNS account name mismatch");
    ensure!(
        take(bytes, &mut cursor, 3, "ArNS schema version")? == [1, 0, 0],
        "unsupported ArNS schema version"
    );
    ensure!(
        bytes[cursor..].iter().all(|byte| *byte == 0),
        "ArNS account contains trailing data"
    );
    Ok(ArnsRecord {
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

fn verified_response(
    verified: VerifiedData,
    resolution: Option<&Resolution>,
    config: &ServerConfig,
) -> Result<Response> {
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
        .status(StatusCode::OK)
        .header("content-type", verified.content_type.as_str())
        .header("content-length", verified.content_length.to_string())
        .header("etag", verified.etag.as_str())
        .header("content-digest", content_digest)
        .header("x-ar-io-data-id", verified.id.as_str())
        .header("x-ar-io-digest", digest)
        .header("x-ar-io-stable", "true")
        .header("x-ar-io-verified", "true")
        .header("x-ar-io-trusted", "true")
        .header("x-cache", "MISS")
        .header("x-ar-io-hops", "1")
        .header("access-control-allow-origin", "*")
        .header("access-control-expose-headers", "*");
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
    }
    builder
        .body(Body::from(verified.bytes))
        .context("failed to construct HTTP response")
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("content-length", message.len().to_string())
        .header("access-control-allow-origin", "*")
        .header("access-control-expose-headers", "*")
        .body(Body::from(message))
        .unwrap()
}

fn arns_name(headers: &HeaderMap, root_host: &str) -> Option<String> {
    let authority = headers
        .get(HOST)?
        .to_str()
        .ok()?
        .parse::<Authority>()
        .ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
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
struct ProgramAccountsResponse {
    result: Option<Vec<ProgramAccount>>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
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

    const ARNS_ACCOUNT: &str = "NZ4qfQeEaLwF6jmlT8XLNtBIvGDG/foSDuHpVUuCqaQ+a2p0ioe5aC2+lbeF1KeVB3WX89Ksp18jfWPgMFBF9tJsgtCTCP9M76AI6Wt+7PHPwtgIPrVmlgBd2KoBvC2lEcnNDTc0HywBgHC2ZwAAAAAAZAAAAAAAAAAAAP4JAAAAbG9sY2NoZWtjAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const ANT_ACCOUNT: &str = "4V5G8FIth1HvoAjpa37s8c/C2Ag+tWaWAF3YqgG8LaURyc0NNzQfLAEAAABAKwAAADNGX3lsZHFXX3p0NkNpXzQ3dy03Tzc2bFBwZWdwdTFyczdIMml5dWx0VlkAEA4AAAEAAAAAAC2+lbeF1KeVB3WX89Ksp18jfWPgMFBF9tJsgtCTCP9M/wEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const ARNS_PROGRAM: &str = "2yCUx5edFvUrkibYaUa2ZXWyx9kuJkS8CwyzsgHPWdZZ";
    const ANT_PROGRAM: &str = "2MWexMHfMhGJwMHv9Qm9YAVCqjUFUJwDJAysW4oCUGk5";

    #[test]
    fn decodes_captured_arns_and_ant_accounts() {
        let arns_bytes = STANDARD.decode(ARNS_ACCOUNT).unwrap();
        let name_hash: [u8; 32] = Sha256::digest(b"lolcchekc").into();
        let arns = decode_arns_record(&arns_bytes, "lolcchekc", &name_hash).unwrap();
        assert_eq!(
            bs58::encode(arns.ant).into_string(),
            "H8Pya8AGbnt39Em7Zy5EHiXGY1MEuV5MpSM2JXzNYYY3"
        );
        assert_eq!(arns.undername_limit, 100);
        assert_eq!(arns.end_timestamp, None);
        assert_eq!(arns.bump, 254);
        let arns_pubkey =
            decode_pubkey("E8Vm6GR2CDdsx5FRaxQ7iVoN832mTjufN8zuB2pvzpYn", "fixture").unwrap();
        verify_pda(
            &arns_pubkey,
            ARNS_PROGRAM,
            &[ARNS_RECORD_SEED, name_hash.as_slice()],
            arns.bump,
            "ArNS record",
        )
        .unwrap();
        let mut lease_bytes = arns_bytes.clone();
        lease_bytes[104] = 0;
        lease_bytes[113] = 1;
        lease_bytes.splice(114..114, 100_i64.to_le_bytes());
        assert_eq!(
            decode_arns_record(&lease_bytes, "lolcchekc", &name_hash)
                .unwrap()
                .end_timestamp,
            Some(100)
        );

        let ant_bytes = STANDARD.decode(ANT_ACCOUNT).unwrap();
        let ant = decode_ant_record(&ant_bytes, &arns.ant).unwrap();
        assert_eq!(ant.undername, "@");
        assert_eq!(ant.target, "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY");
        assert_eq!(ant.target_protocol, 0);
        assert_eq!(ant.ttl, 3600);
        assert_eq!(ant.priority, Some(0));
        assert_eq!(ant.bump, 255);
        let ant_pubkey =
            decode_pubkey("3JEvMXaLmWvya2jtEX7pgzxHqZB5iiK2GQNdFXcjj26G", "fixture").unwrap();
        let undername_hash: [u8; 32] = Sha256::digest(b"@").into();
        verify_pda(
            &ant_pubkey,
            ANT_PROGRAM,
            &[
                ANT_RECORD_SEED,
                arns.ant.as_slice(),
                undername_hash.as_slice(),
            ],
            ant.bump,
            "ANT record",
        )
        .unwrap();
        let mut wrong_pubkey = ant_pubkey;
        wrong_pubkey[0] ^= 1;
        assert!(
            verify_pda(
                &wrong_pubkey,
                ANT_PROGRAM,
                &[
                    ANT_RECORD_SEED,
                    arns.ant.as_slice(),
                    undername_hash.as_slice(),
                ],
                ant.bump,
                "ANT record",
            )
            .is_err()
        );

        assert!(decode_arns_record(&arns_bytes[..100], "lolcchekc", &name_hash).is_err());
        assert!(decode_ant_record(&ant_bytes[..100], &arns.ant).is_err());
    }
    #[test]
    fn rejects_expired_leases_and_sorts_root_first() {
        assert!(ensure_arns_active(100, 10, 109).is_ok());
        assert!(ensure_arns_active(100, 10, 110).is_err());
        let mut config = vec![0; 182];
        config[..8].copy_from_slice(&ARNS_CONFIG_DISCRIMINATOR);
        config[104..112].copy_from_slice(&10_i64.to_le_bytes());
        config[178] = 255;
        config[179..].copy_from_slice(&[1, 0, 0]);
        assert_eq!(decode_arns_config(&config).unwrap(), (10, 255));
        let config_pubkey =
            decode_pubkey("ENuQZZYp778k5cCAovtD4gS2JxHQ3jVd3fKmNmtcZqQ2", "fixture").unwrap();
        verify_pda(
            &config_pubkey,
            ARNS_PROGRAM,
            &[ARNS_CONFIG_SEED],
            255,
            "ArNS config",
        )
        .unwrap();

        assert!(ensure_arns_active(i64::MAX, 1, 0).is_err());

        let record = |undername: &str, priority| AntRecord {
            undername: undername.to_owned(),
            target: String::new(),
            target_protocol: 0,
            ttl: 0,
            priority,
            bump: 0,
        };
        let mut records = vec![
            record("z", Some(0)),
            record("b", None),
            record("@", None),
            record("a", Some(0)),
        ];
        records.sort_by(compare_ant_records);
        assert_eq!(
            records
                .iter()
                .map(|record| record.undername.as_str())
                .collect::<Vec<_>>(),
            ["@", "a", "z", "b"]
        );
    }

    #[test]
    fn builds_verified_arns_response_headers() {
        let bytes = b"hello".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let digest_url = URL_SAFE_NO_PAD.encode(digest);
        let verified = VerifiedData {
            bytes,
            id: "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY".to_owned(),
            block_height: 1_118_819,
            content_type: "text/html; charset=utf-8".to_owned(),
            content_length: 5,
            etag: format!("\"{digest_url}\""),
            sha256: super::super::hex(&digest),
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
        )
        .unwrap();
        let response = verified_response(verified, Some(&resolution), &config).unwrap();
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
}
