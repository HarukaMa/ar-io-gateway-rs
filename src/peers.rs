use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Client, RequestBuilder, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use solana_pubkey::Pubkey;
use tokio::{
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

use crate::take;

const PEER_TIMEOUT: Duration = Duration::from_secs(5);
const NODE_REFRESH_TIMEOUT: Duration = Duration::from_secs(90);
const GATEWAY_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PEERS: usize = 256;
const MAX_ADVERTISED_PEERS: usize = 4096;
const PEER_CONCURRENCY: usize = 16;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_INFO_BYTES: usize = 64 * 1024;
const MAX_BUCKET_BYTES: usize = 2 * 1024 * 1024;
const MAX_BUCKETS: usize = 65_536;
const DEFAULT_BUCKET_SIZE: u64 = 10_000_000_000;
const MAX_GATEWAYS: usize = 3000;
const GATEWAY_BATCH_SIZE: usize = 100;
const REGISTRY_SIZE: usize = 168_056;
const GATEWAY_SIZE: usize = 964;
const REGISTRY_DISCRIMINATOR: [u8; 8] = [207, 115, 197, 33, 28, 106, 182, 209];
const GATEWAY_DISCRIMINATOR: [u8; 8] = [210, 132, 162, 254, 10, 224, 45, 86];

pub(crate) struct PeerState {
    client: Client,
    trusted_node_url: Url,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    gateways: BTreeMap<String, GatewayPeer>,
    nodes: BTreeMap<String, ArweavePeer>,
    selection: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPeer {
    url: String,
    data_weight: u8,
    chunk_weight: u8,
}

struct ArweavePeer {
    url: String,
    blocks: u64,
    height: u64,
    last_seen: u64,
    coverage: Option<Coverage>,
    weight: u8,
}

struct Coverage {
    bucket_size: u64,
    buckets: Vec<u64>,
    bucket_count: usize,
    updated: u64,
}

impl Coverage {
    fn covers(&self, offset: u128) -> bool {
        u64::try_from(offset / u128::from(self.bucket_size))
            .is_ok_and(|bucket| self.buckets.binary_search(&bucket).is_ok())
    }
}

impl PeerState {
    pub(crate) fn new(trusted_node_url: &str) -> Result<Self> {
        let trusted_node_url =
            Url::parse(trusted_node_url).context("invalid trusted peer source")?;
        ensure!(
            matches!(trusted_node_url.scheme(), "http" | "https"),
            "invalid trusted peer source scheme"
        );
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(PEER_TIMEOUT)
            .no_proxy()
            .build()
            .context("failed to initialize peer HTTP client")?;
        Ok(Self {
            client,
            trusted_node_url,
            state: Mutex::new(State::default()),
        })
    }

    pub(crate) fn get(&self, url: String) -> RequestBuilder {
        self.client.get(url)
    }

    pub(crate) async fn refresh_arweave(&self) -> Result<()> {
        timeout(NODE_REFRESH_TIMEOUT, self.refresh_nodes())
            .await
            .context("Arweave peer refresh deadline exceeded")?
    }

    async fn refresh_nodes(&self) -> Result<()> {
        let url = format!(
            "{}/peers",
            self.trusted_node_url.as_str().trim_end_matches('/')
        );
        let body = response_bytes(self.client.get(url), MAX_JSON_BYTES).await?;
        let advertised: Vec<String> =
            serde_json::from_slice(&body).context("invalid Arweave peer list")?;
        ensure!(
            advertised.len() <= MAX_ADVERTISED_PEERS,
            "Arweave peer list exceeds limit"
        );
        let mut addresses = BTreeSet::new();
        for host in &advertised {
            if let Some(address) = public_peer_address(host) {
                addresses.insert(address);
            }
        }
        ensure!(
            advertised.is_empty() || !addresses.is_empty(),
            "Arweave peer list contains no public numeric peers"
        );
        // ponytail: cap the maintained set at 256, raise the bound if wider discovery is needed.
        let addresses: Vec<_> = addresses.into_iter().take(MAX_PEERS).collect();
        let mut nodes = BTreeMap::new();
        for batch in addresses.chunks(PEER_CONCURRENCY) {
            let mut tasks = JoinSet::new();
            for address in batch {
                let address = *address;
                let client = self.client.clone();
                tasks.spawn(async move { observe_node(&client, address).await });
            }
            while let Some(result) = tasks.join_next().await {
                if let Ok((key, peer)) = result.context("Arweave peer task failed")? {
                    nodes.insert(key, peer);
                }
            }
        }
        ensure!(
            addresses.is_empty() || !nodes.is_empty(),
            "no Arweave peer answered with valid node information"
        );
        let mut state = self.state.lock().unwrap();
        for (key, node) in &mut nodes {
            if let Some(previous) = state.nodes.get(key) {
                node.weight = previous.weight;
            }
        }
        state.nodes = nodes;
        Ok(())
    }

    pub(crate) async fn refresh_gateways(
        &self,
        rpc_url: &Url,
        gar_program_id: &str,
        wallet: Option<&str>,
    ) -> Result<()> {
        timeout(
            GATEWAY_REFRESH_TIMEOUT,
            self.fetch_gateways(rpc_url, gar_program_id, wallet),
        )
        .await
        .context("gateway registry refresh deadline exceeded")?
    }

    async fn fetch_gateways(
        &self,
        rpc_url: &Url,
        gar_program_id: &str,
        wallet: Option<&str>,
    ) -> Result<()> {
        ensure!(
            matches!(rpc_url.scheme(), "http" | "https"),
            "invalid Solana RPC scheme"
        );
        let program: Pubkey = gar_program_id.parse().context("invalid GAR program ID")?;
        let (registry, _) = Pubkey::try_find_program_address(&[b"gateway_registry"], &program)
            .context("failed to derive gateway registry PDA")?;
        let registry_response = self
            .accounts(rpc_url, &[registry.to_string()], None)
            .await?;
        let registry_slot = registry_response.context.slot;
        let registry_account = registry_response
            .value
            .into_iter()
            .next()
            .flatten()
            .context("GAR gateway registry account is missing")?;
        let registry_data = decode_account(registry_account, gar_program_id, REGISTRY_SIZE)?;
        let operators = decode_registry(&registry_data)?;
        let operators: Vec<_> = operators
            .into_iter()
            .filter(|(_, operator)| {
                wallet != Some(Pubkey::new_from_array(*operator).to_string().as_str())
            })
            .collect();
        let mut gateways = BTreeMap::new();
        for batch in operators.chunks(GATEWAY_BATCH_SIZE) {
            let pdas: Vec<_> = batch
                .iter()
                .map(|(_, operator)| {
                    Pubkey::try_find_program_address(&[b"gateway", operator], &program)
                        .context("failed to derive gateway PDA")
                })
                .collect::<Result<_>>()?;
            let addresses: Vec<_> = pdas.iter().map(|(pda, _)| pda.to_string()).collect();
            let response = self
                .accounts(rpc_url, &addresses, Some(registry_slot))
                .await?;
            for ((account, (index, operator)), (_, bump)) in
                response.value.into_iter().zip(batch).zip(pdas)
            {
                // Finalized absence is possible when a leaving gateway's PDA has been closed.
                let Some(account) = account else { continue };
                let data = decode_account(account, gar_program_id, GATEWAY_SIZE)?;
                let (key, url) = decode_gateway(&data, operator, *index, bump)?;
                gateways.insert(
                    key,
                    GatewayPeer {
                        url,
                        data_weight: 50,
                        chunk_weight: 50,
                    },
                );
            }
        }
        let mut state = self.state.lock().unwrap();
        for (key, gateway) in &mut gateways {
            if let Some(previous) = state
                .gateways
                .get(key)
                .filter(|peer| peer.url == gateway.url)
            {
                gateway.data_weight = previous.data_weight;
                gateway.chunk_weight = previous.chunk_weight;
            }
        }
        state.gateways = gateways;
        Ok(())
    }

    async fn accounts(
        &self,
        rpc_url: &Url,
        addresses: &[String],
        min_slot: Option<u64>,
    ) -> Result<AccountResult> {
        ensure!(
            !addresses.is_empty() && addresses.len() <= GATEWAY_BATCH_SIZE,
            "invalid Solana account batch size"
        );
        let mut options = json!({ "encoding": "base64", "commitment": "finalized" });
        if let Some(slot) = min_slot {
            options["minContextSlot"] = json!(slot);
        }
        let body = response_bytes(
            self.client.post(rpc_url.clone()).json(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "getMultipleAccounts",
                "params": [addresses, options],
            })),
            MAX_JSON_BYTES,
        )
        .await?;
        let response: RpcResponse =
            serde_json::from_slice(&body).context("invalid Solana RPC response")?;
        ensure!(
            response.jsonrpc == "2.0" && response.id == 1,
            "invalid Solana RPC envelope"
        );
        if let Some(error) = response.error {
            bail!("Solana RPC rejected peer discovery: {error}");
        }
        let result = response
            .result
            .context("Solana RPC omitted peer discovery result")?;
        ensure!(
            result.value.len() == addresses.len(),
            "Solana RPC account batch length mismatch"
        );
        ensure!(
            min_slot.is_none_or(|slot| result.context.slot >= slot),
            "Solana RPC returned stale gateway accounts"
        );
        Ok(result)
    }

    pub(crate) fn snapshot(&self) -> Value {
        let state = self.state.lock().unwrap();
        let nodes: serde_json::Map<_, _> = state.nodes.iter().map(|(key, peer)| {
            let mut value = json!({
                "url": peer.url, "blocks": peer.blocks, "height": peer.height,
                "lastSeen": peer.last_seen,
                "bucketCount": peer.coverage.as_ref().map_or(0, |coverage| coverage.bucket_count),
            });
            if let Some(coverage) = &peer.coverage {
                value["bucketsLastUpdated"] = json!(coverage.updated);
            }
            (key.clone(), value)
        }).collect();
        json!({ "gateways": state.gateways, "arweaveNodes": nodes })
    }

    pub(crate) fn candidates(
        &self,
        offset: Option<u128>,
        limit: usize,
        exclude: &[String],
    ) -> Vec<String> {
        if limit == 0 {
            return Vec::new();
        }
        let mut state = self.state.lock().unwrap();
        let rotation = state.selection;
        state.selection = state.selection.wrapping_add(1);
        let mut ranked: Vec<_> = state
            .nodes
            .values()
            .filter(|peer| {
                !exclude
                    .iter()
                    .any(|url| url.trim_end_matches('/') == peer.url)
            })
            .map(|peer| {
                let covered = offset.is_some_and(|offset| {
                    peer.coverage
                        .as_ref()
                        .is_some_and(|coverage| coverage.covers(offset))
                });
                (covered, peer.weight, peer.url.as_str())
            })
            .collect();
        ranked.sort_unstable_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then(right.1.cmp(&left.1))
                .then(left.2.cmp(right.2))
        });
        let mut start = 0;
        while start < ranked.len() {
            let mut end = start + 1;
            while end < ranked.len()
                && (ranked[end].0, ranked[end].1) == (ranked[start].0, ranked[start].1)
            {
                end += 1;
            }
            ranked[start..end].rotate_left(rotation % (end - start));
            start = end;
        }
        ranked
            .into_iter()
            .take(limit)
            .map(|(_, _, url)| url.to_owned())
            .collect()
    }

    pub(crate) fn record_result(&self, url: &str, success: bool) {
        let mut state = self.state.lock().unwrap();
        if let Some(peer) = state
            .nodes
            .values_mut()
            .find(|peer| peer.url == url.trim_end_matches('/'))
        {
            peer.weight = if success {
                peer.weight.saturating_add(5).min(100)
            } else {
                peer.weight.saturating_sub(5).max(1)
            };
            if success {
                peer.last_seen = now_millis();
            }
        }
    }
}

async fn response_bytes(request: RequestBuilder, limit: usize) -> Result<Vec<u8>> {
    let mut response = request.send().await.context("peer request failed")?;
    ensure!(
        response.status().is_success(),
        "peer returned HTTP {}",
        response.status()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= limit as u64),
        "peer response exceeds size limit"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed to read peer response")?
    {
        ensure!(
            body.len().saturating_add(chunk.len()) <= limit,
            "peer response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn observe_node(client: &Client, address: SocketAddr) -> Result<(String, ArweavePeer)> {
    #[derive(Deserialize)]
    struct Info {
        blocks: u64,
        height: u64,
    }

    let deadline = Instant::now() + PEER_TIMEOUT;
    let url = format!("http://{address}");
    let info = timeout_at(
        deadline,
        response_bytes(client.get(format!("{url}/info")), MAX_INFO_BYTES),
    )
    .await
    .context("Arweave peer info deadline exceeded")??;
    let info: Info = serde_json::from_slice(&info).context("invalid Arweave peer info")?;
    let last_seen = now_millis();
    let coverage = timeout_at(deadline, async {
        let bytes =
            response_bytes(client.get(format!("{url}/sync_buckets")), MAX_BUCKET_BYTES).await?;
        decode_buckets(&bytes)
    })
    .await
    .ok()
    .and_then(Result::ok);
    Ok((
        address.to_string(),
        ArweavePeer {
            url,
            blocks: info.blocks,
            height: info.height,
            last_seen,
            coverage,
            weight: 50,
        },
    ))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn public_peer_address(value: &str) -> Option<SocketAddr> {
    if value.len() > 64 {
        return None;
    }
    let address: SocketAddr = value.parse().ok()?;
    if address.port() == 0 {
        return None;
    }
    let public = match address.ip() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                && !(a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    };
    public.then_some(address)
}

#[derive(Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    id: u8,
    result: Option<AccountResult>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct AccountResult {
    context: RpcContext,
    value: Vec<Option<SolanaAccount>>,
}

#[derive(Deserialize)]
struct RpcContext {
    slot: u64,
}

#[derive(Deserialize)]
struct SolanaAccount {
    owner: String,
    executable: bool,
    data: [String; 2],
    space: usize,
}

fn decode_account(account: SolanaAccount, program: &str, size: usize) -> Result<Vec<u8>> {
    ensure!(account.owner == program, "GAR account owner mismatch");
    ensure!(!account.executable, "GAR account is executable");
    ensure!(account.space == size, "GAR account allocation mismatch");
    ensure!(account.data[1] == "base64", "invalid GAR account encoding");
    ensure!(
        account.data[0].len() <= size.div_ceil(3) * 4,
        "GAR account exceeds size limit"
    );
    let bytes = STANDARD
        .decode(&account.data[0])
        .context("invalid GAR account base64")?;
    ensure!(bytes.len() == size, "GAR account length mismatch");
    Ok(bytes)
}

fn decode_registry(bytes: &[u8]) -> Result<Vec<(u32, [u8; 32])>> {
    ensure!(
        bytes.len() == REGISTRY_SIZE,
        "invalid gateway registry length"
    );
    ensure!(
        bytes[..8] == REGISTRY_DISCRIMINATOR,
        "invalid gateway registry discriminator"
    );
    ensure!(
        matches!(
            &bytes[REGISTRY_SIZE - 8..REGISTRY_SIZE - 5],
            [0, 0, 0] | [1, 0, 0]
        ),
        "unsupported gateway registry schema"
    );
    let count = u32::from_le_bytes(bytes[40..44].try_into().unwrap()) as usize;
    ensure!(
        count <= MAX_GATEWAYS,
        "gateway registry count exceeds capacity"
    );
    let mut operators = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    for index in 0..count {
        let slot = &bytes[48 + index * 56..48 + (index + 1) * 56];
        let operator: [u8; 32] = slot[..32].try_into().unwrap();
        if operator == [0; 32] {
            continue;
        }
        ensure!(
            slot[48] <= 2 && slot[49] <= 1,
            "invalid gateway registry slot state"
        );
        ensure!(seen.insert(operator), "duplicate gateway registry operator");
        operators.push((index as u32, operator));
    }
    Ok(operators)
}

fn decode_gateway(
    bytes: &[u8],
    operator: &[u8; 32],
    index: u32,
    bump: u8,
) -> Result<(String, String)> {
    ensure!(
        bytes.len() == GATEWAY_SIZE,
        "invalid gateway account length"
    );
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 8, "gateway discriminator")? == GATEWAY_DISCRIMINATOR,
        "invalid gateway discriminator"
    );
    ensure!(
        take(bytes, &mut cursor, 32, "gateway operator")? == operator,
        "gateway operator mismatch"
    );
    borsh_string(bytes, &mut cursor, 64)?;
    let fqdn = borsh_string(bytes, &mut cursor, 128)?;
    take(bytes, &mut cursor, 2, "gateway port")?;
    ensure!(
        read_byte(bytes, &mut cursor)? <= 1,
        "invalid gateway protocol"
    );
    borsh_string(bytes, &mut cursor, 256)?;
    borsh_string(bytes, &mut cursor, 256)?;
    take(bytes, &mut cursor, 16, "gateway stakes")?;
    ensure!(
        read_byte(bytes, &mut cursor)? <= 2,
        "invalid gateway status"
    );
    take(bytes, &mut cursor, 8, "gateway start timestamp")?;
    borsh_option(bytes, &mut cursor, 8)?;
    take(
        bytes,
        &mut cursor,
        8 + 22 + 56,
        "gateway duration, stats, and weights",
    )?;
    ensure!(
        read_byte(bytes, &mut cursor)? <= 1,
        "invalid gateway delegation flag"
    );
    take(bytes, &mut cursor, 2 + 8, "gateway delegation settings")?;
    ensure!(
        read_byte(bytes, &mut cursor)? <= 1,
        "invalid gateway allowlist flag"
    );
    borsh_option(bytes, &mut cursor, 2)?;
    borsh_option(bytes, &mut cursor, 8)?;
    ensure!(
        read_u32(bytes, &mut cursor)? == index,
        "gateway registry index mismatch"
    );
    take(
        bytes,
        &mut cursor,
        1 + 32 + 16,
        "gateway reserved byte, observer, and rewards",
    )?;
    ensure!(
        read_byte(bytes, &mut cursor)? == bump,
        "gateway PDA bump mismatch"
    );
    ensure!(
        take(bytes, &mut cursor, 3, "gateway schema")? == [1, 1, 0],
        "unsupported gateway schema"
    );
    // Anchor leaves the remainder of this fixed allocation unchanged after shorter updates.
    ensure!(
        fqdn.is_ascii()
            && !fqdn.is_empty()
            && fqdn
                .strip_suffix('.')
                .unwrap_or(fqdn)
                .split('.')
                .all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label.as_bytes()[0].is_ascii_alphanumeric()
                        && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }),
        "invalid gateway FQDN"
    );
    // Match the installed SDK's HTTPS projection and Node's omission of the stored port.
    let url = format!("https://{fqdn}");
    let parsed = Url::parse(&url).context("invalid gateway URL")?;
    let host = parsed.host_str().context("gateway URL lacks host")?;
    Ok((format!("{host}:443"), url))
}

fn read_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(take(bytes, cursor, 1, "peer protocol byte")?[0])
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        take(bytes, cursor, 4, "GAR integer")?.try_into().unwrap(),
    ))
}

fn borsh_string<'a>(bytes: &'a [u8], cursor: &mut usize, max: usize) -> Result<&'a str> {
    let length = read_u32(bytes, cursor)? as usize;
    ensure!(length <= max, "GAR string exceeds size limit");
    std::str::from_utf8(take(bytes, cursor, length, "GAR string")?)
        .context("invalid GAR string UTF-8")
}

fn borsh_option(bytes: &[u8], cursor: &mut usize, size: usize) -> Result<()> {
    match read_byte(bytes, cursor)? {
        0 => (),
        1 => {
            take(bytes, cursor, size, "GAR option")?;
        }
        _ => bail!("invalid GAR option tag"),
    }
    Ok(())
}

fn decode_buckets(bytes: &[u8]) -> Result<Coverage> {
    ensure!(
        bytes.len() <= MAX_BUCKET_BYTES,
        "sync buckets exceed size limit"
    );
    let mut cursor = 0;
    ensure!(
        take(bytes, &mut cursor, 3, "sync bucket tuple")? == [131, 104, 2],
        "invalid sync bucket ETF tuple"
    );
    let bucket_size = etf_integer(bytes, &mut cursor)?;
    ensure!(
        (DEFAULT_BUCKET_SIZE..=DEFAULT_BUCKET_SIZE * 4096).contains(&bucket_size),
        "invalid sync bucket size"
    );
    ensure!(
        read_byte(bytes, &mut cursor)? == 116,
        "sync buckets require an ETF map"
    );
    let count = u32::from_be_bytes(
        take(bytes, &mut cursor, 4, "sync bucket count")?
            .try_into()
            .unwrap(),
    ) as usize;
    ensure!(
        count <= MAX_BUCKETS && count <= (bytes.len() - cursor) / 4,
        "invalid sync bucket count"
    );
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let bucket = etf_integer(bytes, &mut cursor)?;
        let share = if bytes.get(cursor) == Some(&70) {
            cursor += 1;
            f64::from_be_bytes(
                take(bytes, &mut cursor, 8, "sync bucket share")?
                    .try_into()
                    .unwrap(),
            )
        } else {
            etf_integer(bytes, &mut cursor)? as f64
        };
        ensure!(
            share.is_finite() && (0.0..=1.0).contains(&share),
            "invalid sync bucket share"
        );
        entries.push((bucket, share > 0.0));
    }
    ensure!(cursor == bytes.len(), "trailing sync bucket ETF data");
    entries.sort_unstable_by_key(|entry| entry.0);
    ensure!(
        entries.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "duplicate sync bucket index"
    );
    Ok(Coverage {
        bucket_size,
        buckets: entries
            .into_iter()
            .filter_map(|(index, positive)| positive.then_some(index))
            .collect(),
        bucket_count: count,
        updated: now_millis(),
    })
}

fn etf_integer(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    match read_byte(bytes, cursor)? {
        97 => Ok(u64::from(read_byte(bytes, cursor)?)),
        98 => {
            let value =
                i32::from_be_bytes(take(bytes, cursor, 4, "ETF integer")?.try_into().unwrap());
            u64::try_from(value).context("negative ETF integer")
        }
        110 => {
            let size = usize::from(read_byte(bytes, cursor)?);
            ensure!(
                size <= 8 && read_byte(bytes, cursor)? == 0,
                "invalid ETF big integer"
            );
            let mut value = [0; 8];
            value[..size].copy_from_slice(take(bytes, cursor, size, "ETF big integer")?);
            Ok(u64::from_le_bytes(value))
        }
        _ => bail!("unsupported ETF integer tag"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket_frame(entries: &[(u8, f64)]) -> Vec<u8> {
        let mut bytes = vec![131, 104, 2, 110, 5, 0];
        bytes.extend_from_slice(&DEFAULT_BUCKET_SIZE.to_le_bytes()[..5]);
        bytes.push(116);
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        for (bucket, share) in entries {
            bytes.extend_from_slice(&[97, *bucket, 70]);
            bytes.extend_from_slice(&share.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn sync_bucket_boundaries_reject_corrupt_etf_and_preserve_advertised_size() {
        let bytes = bucket_frame(&[(2, 0.5), (1, 0.0)]);
        let coverage = decode_buckets(&bytes).unwrap();
        assert!(coverage.covers(u128::from(DEFAULT_BUCKET_SIZE) * 2));
        assert!(!coverage.covers(u128::from(DEFAULT_BUCKET_SIZE) * 2 - 1));
        assert_eq!(coverage.bucket_count, 2);
        for end in 0..bytes.len() {
            assert!(decode_buckets(&bytes[..end]).is_err());
        }
        for entries in [
            &[(1, f64::NAN)][..],
            &[(1, -0.5)],
            &[(1, 1.1)],
            &[(1, 1.0), (1, 0.5)],
        ] {
            assert!(decode_buckets(&bucket_frame(entries)).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_buckets(&trailing).is_err());
        let mut invalid_count = bytes.clone();
        invalid_count[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_buckets(&invalid_count).is_err());
        let mut negative_size = bytes;
        negative_size[5] = 1;
        assert!(decode_buckets(&negative_size).is_err());
    }

    #[test]
    fn discovered_addresses_cannot_probe_nonpublic_or_named_hosts() {
        assert_eq!(
            public_peer_address("8.8.8.8:1984").unwrap().to_string(),
            "8.8.8.8:1984"
        );
        assert!(public_peer_address("[2606:4700:4700::1111]:1984").is_some());
        for value in [
            "127.0.0.1:1984",
            "10.0.0.1:1984",
            "172.16.0.1:1984",
            "192.168.1.1:1984",
            "100.64.0.1:1984",
            "169.254.169.254:80",
            "0.0.0.0:1984",
            "224.0.0.1:1984",
            "192.0.2.1:1984",
            "198.18.0.1:1984",
            "[::1]:1984",
            "[::ffff:127.0.0.1]:1984",
            "[fc00::1]:1984",
            "[fe80::1]:1984",
            "[2001:db8::1]:1984",
            "[2002:7f00:1::]:1984",
            "localhost:1984",
            "8.8.8.8:0",
            "8.8.8.8:80/path",
            "8.8.8.8:80@127.0.0.1:80",
        ] {
            assert!(public_peer_address(value).is_none(), "{value}");
        }
    }

    #[test]
    fn registry_uses_full_slots_and_rejects_forged_account_boundaries() {
        let mut bytes = vec![0; REGISTRY_SIZE];
        bytes[..8].copy_from_slice(&REGISTRY_DISCRIMINATOR);
        bytes[40..44].copy_from_slice(&2_u32.to_le_bytes());
        bytes[48..80].fill(1);
        bytes[104..136].fill(2);
        // Match the zero version bytes in the deployed mainnet registry.
        assert_eq!(
            decode_registry(&bytes).unwrap(),
            vec![(0, [1; 32]), (1, [2; 32])]
        );
        let account = |owner: &str, executable: bool, space: usize| SolanaAccount {
            owner: owner.to_owned(),
            executable,
            data: [STANDARD.encode(&bytes), "base64".to_owned()],
            space,
        };
        assert!(
            decode_account(account("other", false, REGISTRY_SIZE), "gar", REGISTRY_SIZE).is_err()
        );
        assert!(decode_account(account("gar", true, REGISTRY_SIZE), "gar", REGISTRY_SIZE).is_err());
        assert!(
            decode_account(
                account("gar", false, REGISTRY_SIZE - 1),
                "gar",
                REGISTRY_SIZE
            )
            .is_err()
        );
        assert!(decode_registry(&bytes[..REGISTRY_SIZE - 1]).is_err());
        bytes[40..44].copy_from_slice(&3001_u32.to_le_bytes());
        assert!(decode_registry(&bytes).is_err());
        bytes[40..44].copy_from_slice(&2_u32.to_le_bytes());
        bytes[104..136].fill(1);
        assert!(decode_registry(&bytes).is_err());
    }

    #[test]
    fn gateway_decoder_binds_operator_index_and_pda_bump() {
        let operator = [7; 32];
        let program = Pubkey::new_from_array([8; 32]);
        let (_, bump) =
            Pubkey::try_find_program_address(&[b"gateway", &operator], &program).unwrap();
        let mut bytes = GATEWAY_DISCRIMINATOR.to_vec();
        bytes.extend_from_slice(&operator);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&11_u32.to_le_bytes());
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443_u16.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0; 8 + 16 + 1 + 8]);
        bytes.push(0);
        bytes.extend_from_slice(&[0; 8 + 22 + 56 + 1 + 2 + 8 + 1]);
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 1 + 32 + 16]);
        bytes.push(bump);
        bytes.extend_from_slice(&[1, 1, 0]);
        bytes.resize(GATEWAY_SIZE, 0xab);
        assert_eq!(
            decode_gateway(&bytes, &operator, 3, bump).unwrap(),
            (
                "example.com:443".to_owned(),
                "https://example.com".to_owned()
            )
        );
        assert!(decode_gateway(&bytes, &[6; 32], 3, bump).is_err());
        assert!(decode_gateway(&bytes, &operator, 4, bump).is_err());
        assert!(decode_gateway(&bytes, &operator, 3, bump.wrapping_add(1)).is_err());
        bytes[48] = b'/';
        assert!(decode_gateway(&bytes, &operator, 3, bump).is_err());
    }
}
