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

pub(crate) const CHUNK_ORIGIN_LIMIT: usize = 8;

pub(crate) fn chunk_slots(source: &str) -> Result<std::sync::Arc<tokio::sync::Semaphore>> {
    use std::sync::{Arc, LazyLock, Weak};
    static LIMITS: LazyLock<parking_lot::Mutex<BTreeMap<String, Weak<tokio::sync::Semaphore>>>> =
        LazyLock::new(Default::default);
    let origin = Url::parse(source)?.origin().ascii_serialization();
    let mut limits = LIMITS.lock();
    limits.retain(|_, slots| slots.strong_count() > 0);
    if let Some(slots) = limits.get(&origin).and_then(Weak::upgrade) {
        return Ok(slots);
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(CHUNK_ORIGIN_LIMIT));
    limits.insert(origin, Arc::downgrade(&slots));
    Ok(slots)
}

static CHUNK_FETCHES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(96);
static CHUNK_CAPACITY: tokio::sync::Notify = tokio::sync::Notify::const_new();

struct ChunkPermit {
    origin: Option<tokio::sync::OwnedSemaphorePermit>,
    global: Option<tokio::sync::SemaphorePermit<'static>>,
}

impl Drop for ChunkPermit {
    fn drop(&mut self) {
        self.origin.take();
        self.global.take();
        CHUNK_CAPACITY.notify_waiters();
    }
}

async fn admit_chunk(
    peers: &PeerState,
    offset: u128,
    configured: &[String],
    attempted: &BTreeSet<String>,
) -> Result<Option<(String, ChunkPermit)>> {
    loop {
        let changed = CHUNK_CAPACITY.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let global =
            crate::profiling::measure(crate::profiling::Stage::ChunkGlobalAdmission, async {
                CHUNK_FETCHES
                    .acquire()
                    .await
                    .context("chunk admission closed")
            })
            .await?;
        let mut remaining = false;
        for source in peers.chunk_candidates(offset, configured)? {
            if attempted.contains(&source) {
                continue;
            }
            remaining = true;
            if let Ok(origin) = chunk_slots(&source)?.try_acquire_owned() {
                return Ok(Some((
                    source,
                    ChunkPermit {
                        origin: Some(origin),
                        global: Some(global),
                    },
                )));
            }
        }
        drop(global);
        if !remaining {
            return Ok(None);
        }
        crate::profiling::measure(crate::profiling::Stage::ChunkOriginAdmission, async {
            changed.await;
            Ok(())
        })
        .await?;
    }
}

pub(crate) fn hedged_requests<'a, T, F, R>(
    peers: &'a PeerState,
    offset: u128,
    configured: &'a [String],
    request: &'a F,
    budget: Duration,
) -> impl futures_util::Stream<Item = (String, Result<T>)> + 'a
where
    F: Fn(String) -> R + 'a,
    R: Future<Output = Result<T>> + 'a,
    T: 'a,
{
    use futures_util::{StreamExt, stream::FuturesUnordered};
    futures_util::stream::unfold(
        (
            BTreeSet::new(),
            FuturesUnordered::new(),
            Instant::now(),
            false,
            budget,
            None::<Instant>,
        ),
        move |(
            mut attempted,
            mut active,
            mut launch_at,
            mut exhausted,
            mut remaining,
            mut deadline,
        )| async move {
            loop {
                if exhausted && active.is_empty() {
                    return None;
                }
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline.unwrap_or_else(Instant::now)),
                        if deadline.is_some() || remaining.is_zero() => {
                        active.clear();
                        return Some(((String::new(), Err(anyhow::anyhow!("chunk request timed out"))),
                            (attempted, active, launch_at, true, Duration::ZERO, None)));
                    }
                    result = active.next(), if !active.is_empty() => {
                        let result = result.unwrap();
                        if active.is_empty() {
                            remaining = deadline.take().unwrap().saturating_duration_since(Instant::now());
                        }
                        return Some((result, (attempted, active, Instant::now(), exhausted, remaining, deadline)));
                    }
                    admission = async {
                        tokio::time::sleep_until(launch_at).await;
                        admit_chunk(peers, offset, configured, &attempted).await
                    }, if active.len() < 3 && !exhausted => {
                        match admission {
                            Ok(Some((source, permit))) => {
                                // Only time with admitted requests consumes the chunk budget.
                                if active.is_empty() {
                                    deadline = Some(Instant::now() + remaining);
                                }
                                attempted.insert(source.clone());
                                active.push(async move {
                                    let _permit = permit;
                                    let timer = crate::profiling::start_origin(&source);
                                    let result = request(source.clone()).await;
                                    if let Some(timer) = timer { timer.finish(result.is_ok(), 0); }
                                    (source, result)
                                });
                                launch_at = Instant::now() + Duration::from_millis(150);
                            }
                            Ok(None) => exhausted = true,
                            Err(error) => return Some(((String::new(), Err(error)),
                                (attempted, active, launch_at, true, remaining, deadline))),
                        }
                    }
                }
            }
        },
    )
}

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
    chunk_stats: BTreeMap<String, ChunkStats>,
    chunk_selection: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayPeer {
    url: String,
    data_weight: u8,
    chunk_weight: u8,
}

struct ChunkStats {
    timing: Option<(f64, f64)>,
    weight: u8,
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
    buckets: Vec<(u64, f64)>,
    bucket_count: usize,
    updated: u64,
}

impl Coverage {
    fn share(&self, offset: u128) -> f64 {
        u64::try_from(offset / u128::from(self.bucket_size))
            .ok()
            .and_then(|bucket| {
                self.buckets
                    .binary_search_by_key(&bucket, |entry| entry.0)
                    .ok()
            })
            .map_or(0.0, |index| self.buckets[index].1)
    }

    fn covers(&self, offset: u128) -> bool {
        self.share(offset) > 0.0
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
            if let Some(previous) = state.nodes.get_mut(key) {
                node.weight = previous.weight;
                if node.coverage.is_none() {
                    node.coverage = previous.coverage.take();
                }
            }
        }
        // Keep a last-known snapshot for still-advertised peers that missed this refresh.
        for address in addresses {
            let key = address.to_string();
            if !nodes.contains_key(&key) {
                if let Some(previous) = state.nodes.remove(&key) {
                    nodes.insert(key, previous);
                }
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

    pub(crate) fn chunk_candidates(
        &self,
        offset: u128,
        configured: &[String],
    ) -> Result<Vec<String>> {
        let mut state = self.state.lock().unwrap();
        let mut pool: BTreeMap<String, Option<f64>> = configured
            .iter()
            .map(|url| (url.trim_end_matches('/').to_owned(), None))
            .collect();
        for peer in state.nodes.values() {
            if !peer
                .coverage
                .as_ref()
                .is_some_and(|coverage| coverage.covers(offset))
            {
                continue;
            }
            pool.insert(
                peer.url.clone(),
                peer.coverage.as_ref().map(|coverage| {
                    // After missed refreshes, converge toward the unknown-coverage prior.
                    let age = now_millis().saturating_sub(coverage.updated);
                    let confidence = 1.0 / (1.0 + age.saturating_sub(600_000) as f64 / 600_000.0);
                    confidence * coverage.share(offset) + (1.0 - confidence) * 0.5
                }),
            );
        }
        state.chunk_stats.retain(|url, _| pool.contains_key(url));
        let mut ranked = Vec::with_capacity(pool.len());
        for (url, share) in pool {
            let stats = state.chunk_stats.entry(url.clone()).or_insert(ChunkStats {
                timing: None,
                weight: 50,
            });
            let (latency, rate) = stats.timing.unwrap_or((1.0, 262_144.0));
            let cost = (latency + 262_144.0 / rate) * 50.0 / f64::from(stats.weight)
                + f64::from(50u8.saturating_sub(stats.weight)) / 5.0;
            let available = chunk_slots(&url)?.available_permits();
            let load = 1.0 + (CHUNK_ORIGIN_LIMIT - available) as f64 / CHUNK_ORIGIN_LIMIT as f64;
            ranked.push((
                available == 0,
                cost * load / share.unwrap_or(0.5).max(0.01),
                url,
            ));
        }
        ranked.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)).then(a.2.cmp(&b.2)));
        let selection = state.chunk_selection;
        state.chunk_selection = selection.wrapping_add(1);
        let mut start = 0;
        while start < ranked.len() {
            let mut end = start + 1;
            while end < ranked.len()
                && (ranked[end].0, ranked[end].1) == (ranked[start].0, ranked[start].1)
            {
                end += 1;
            }
            ranked[start..end].rotate_left(selection % (end - start));
            start = end;
        }
        let available = ranked.iter().take_while(|candidate| !candidate.0).count();
        if available > 0 && selection % 8 == 0 {
            let probe = available - 1 - (selection / 8) % available;
            ranked.swap(0, probe);
        }
        let sources = ranked.into_iter().map(|(_, _, url)| url).collect();
        Ok(sources)
    }

    pub(crate) fn record_chunk_result(
        &self,
        url: &str,
        sample: Option<(Duration, Duration, usize)>,
    ) {
        self.record_result(url, sample.is_some());
        let mut state = self.state.lock().unwrap();
        let Some(stats) = state.chunk_stats.get_mut(url.trim_end_matches('/')) else {
            return;
        };
        if let Some((headers, body, bytes)) = sample {
            crate::profiling::verified_chunk(url, bytes);
            stats.weight = stats.weight.saturating_add(5).min(100);
            let latency = headers.as_secs_f64();
            let rate = bytes as f64 / body.as_secs_f64().max(0.000_001);
            if bytes > 0 {
                stats.timing = Some(match stats.timing {
                    Some((old_latency, old_rate)) => (
                        old_latency * 0.75 + latency * 0.25,
                        old_rate * 0.75 + rate * 0.25,
                    ),
                    None => (latency, rate),
                });
            }
        } else {
            stats.weight = stats.weight.saturating_sub(5).max(1);
        }
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
        entries.push((bucket, share));
    }
    ensure!(cursor == bytes.len(), "trailing sync bucket ETF data");
    entries.sort_unstable_by_key(|entry| entry.0);
    ensure!(
        entries.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "duplicate sync bucket index"
    );
    Ok(Coverage {
        bucket_size,
        buckets: entries,
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

    #[tokio::test]
    async fn coverage_refresh_preserves_failed_snapshot_and_accepts_new_zero() -> Result<()> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let mode = Arc::new(AtomicUsize::new(0));
        let mode_in = Arc::clone(&mode);
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let mode = mode_in.load(Ordering::Relaxed);
            async move {
                let body = match request.uri().path() {
                    "/trusted/peers" => br#"["8.8.4.4:1984"]"#.to_vec(),
                    "/info" => br#"{"height":51,"blocks":51}"#.to_vec(),
                    "/sync_buckets" if mode == 1 => {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                    }
                    "/sync_buckets" => bucket_frame(&[(0, if mode == 0 { 0.25 } else { 0.0 })]),
                    _ => return (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                };
                (axum::http::StatusCode::OK, body)
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let mut peers = PeerState::new(&format!("{base}/trusted"))?;
        peers.client = Client::builder()
            .proxy(reqwest::Proxy::all(&base)?)
            .build()?;
        peers.refresh_arweave().await?;
        let initial = {
            let state = peers.state.lock().unwrap();
            let coverage = state.nodes["8.8.4.4:1984"].coverage.as_ref().unwrap();
            assert_eq!(coverage.share(1), 0.25);
            coverage.updated
        };
        mode.store(1, Ordering::Relaxed);
        peers.refresh_arweave().await?;
        {
            let state = peers.state.lock().unwrap();
            let coverage = state.nodes["8.8.4.4:1984"].coverage.as_ref().unwrap();
            assert_eq!(coverage.share(1), 0.25);
            assert_eq!(coverage.updated, initial);
        }
        mode.store(2, Ordering::Relaxed);
        peers.refresh_arweave().await?;
        assert_eq!(
            peers.state.lock().unwrap().nodes["8.8.4.4:1984"]
                .coverage
                .as_ref()
                .unwrap()
                .share(1),
            0.0
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_spreads_work_and_releases_cancelled_capacity() -> Result<()> {
        let peers = PeerState::new("http://127.0.0.1:1984")?;
        let sources = vec![
            "http://dispatch-a.test".to_owned(),
            "http://dispatch-b.test".to_owned(),
        ];
        let attempted = BTreeSet::new();
        let mut held = Vec::new();
        let mut counts = BTreeMap::new();
        for _ in 0..16 {
            let (source, permit) = timeout(
                Duration::from_secs(3),
                admit_chunk(&peers, 1, &sources, &attempted),
            )
            .await??
            .unwrap();
            *counts.entry(source.clone()).or_insert(0) += 1;
            held.push((source, permit));
        }
        assert_eq!(
            counts,
            BTreeMap::from([(sources[0].clone(), 8), (sources[1].clone(), 8)])
        );
        {
            let pending = admit_chunk(&peers, 1, &sources, &attempted);
            tokio::pin!(pending);
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            let (released, permit) = held.pop().unwrap();
            drop(permit);
            let (selected, _permit) = timeout(Duration::from_secs(1), pending).await??.unwrap();
            assert_eq!(selected, released);
        }
        held.clear();
        for source in &sources {
            let _all = chunk_slots(source)?.try_acquire_many_owned(8)?;
        }
        Ok(())
    }

    #[test]
    fn coverage_fraction_and_age_affect_ranking() -> Result<()> {
        let peers = PeerState::new("http://127.0.0.1:1984")?;
        let configured = vec!["http://unknown.test".to_owned()];
        for (url, share) in [
            ("http://full.test", Some(1.0)),
            ("http://partial.test", Some(0.1)),
            ("http://empty.test", Some(0.0)),
            ("http://unknown.test", None),
            ("http://unadvertised.test", None),
        ] {
            peers.state.lock().unwrap().nodes.insert(
                url.to_owned(),
                ArweavePeer {
                    url: url.to_owned(),
                    blocks: 1,
                    height: 1,
                    last_seen: now_millis(),
                    coverage: share
                        .map(|share| decode_buckets(&bucket_frame(&[(0, share)])))
                        .transpose()?,
                    weight: 50,
                },
            );
        }
        peers.state.lock().unwrap().chunk_selection = 1;
        assert_eq!(
            peers.chunk_candidates(1, &configured)?,
            vec![
                "http://full.test",
                "http://unknown.test",
                "http://partial.test",
            ]
        );
        {
            let mut state = peers.state.lock().unwrap();
            state
                .nodes
                .get_mut("http://empty.test")
                .unwrap()
                .coverage
                .as_mut()
                .unwrap()
                .updated = 0;
        }
        let ranked = peers.chunk_candidates(1, &configured)?;
        assert!(!ranked.iter().any(|url| url == "http://empty.test"));
        assert_eq!(
            peers.chunk_candidates(DEFAULT_BUCKET_SIZE.into(), &configured)?,
            configured
        );
        assert_eq!(
            peers
                .chunk_candidates(1, &["http://empty.test".to_owned()])?
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "http://full.test".to_owned(),
                "http://partial.test".to_owned(),
                "http://empty.test".to_owned(),
            ])
        );
        let explored: BTreeSet<_> = (0..64)
            .map(|_| peers.chunk_candidates(1, &configured).unwrap()[0].clone())
            .collect();
        assert_eq!(explored.len(), 3);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn chunk_backups_wait_for_slow_sources() -> Result<()> {
        use futures_util::StreamExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let peers = PeerState::new("http://127.0.0.1:1984")?;
        let sources = vec![
            "http://hedge-first.test".to_owned(),
            "http://hedge-backup.test".to_owned(),
        ];
        peers.chunk_candidates(1, &sources)?;
        peers.record_chunk_result(
            &sources[0],
            Some((Duration::from_millis(1), Duration::from_millis(1), 262_144)),
        );
        let calls = AtomicUsize::new(0);
        let fast = |_| async {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };
        let fetches = hedged_requests(&peers, 1, &sources, &fast, crate::CHUNK_DEADLINE);
        tokio::pin!(fetches);
        assert!(fetches.next().await.unwrap().1.is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        let slow = |source| async move {
            if source == "http://hedge-first.test" {
                std::future::pending::<()>().await;
            }
            Ok(())
        };
        let started = Instant::now();
        {
            let fetches = hedged_requests(&peers, 1, &sources, &slow, crate::CHUNK_DEADLINE);
            tokio::pin!(fetches);
            let (source, result) = fetches.next().await.unwrap();
            result?;
            assert_eq!(source, "http://hedge-backup.test");
            assert_eq!(started.elapsed(), Duration::from_millis(150));
        }
        for source in &sources {
            let _all = chunk_slots(source)?.try_acquire_many_owned(8)?;
        }
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn chunk_budget_pauses_during_admission_and_survives_retries() -> Result<()> {
        use futures_util::StreamExt;
        let peers = PeerState::new("http://127.0.0.1:1984")?;
        let sources = vec![
            "http://budget-first.test".to_owned(),
            "http://budget-second.test".to_owned(),
        ];
        let first = chunk_slots(&sources[0])?.try_acquire_many_owned(8)?;
        let second = chunk_slots(&sources[1])?.try_acquire_many_owned(8)?;
        let request = |source: String| async move {
            if source == "http://budget-first.test" {
                tokio::time::sleep(Duration::from_secs(4)).await;
                bail!("first request failed");
            }
            std::future::pending::<Result<()>>().await
        };
        let fetches = hedged_requests(&peers, 1, &sources, &request, Duration::from_secs(10));
        tokio::pin!(fetches);
        {
            let next = fetches.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            drop(first);
            let (source, result) = next.await.unwrap();
            assert_eq!(source, sources[0]);
            assert_eq!(result.unwrap_err().to_string(), "first request failed");
        }
        {
            let next = fetches.next();
            tokio::pin!(next);
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            tokio::time::advance(Duration::from_secs(30)).await;
            assert!(futures_util::poll!(next.as_mut()).is_pending());
            drop(second);
            let started = Instant::now();
            let (_, result) = next.await.unwrap();
            assert_eq!(result.unwrap_err().to_string(), "chunk request timed out");
            assert_eq!(started.elapsed(), Duration::from_secs(6));
        }
        assert!(fetches.next().await.is_none());
        for source in &sources {
            let _all = chunk_slots(source)?.try_acquire_many_owned(8)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn chunk_origin_limit_covers_url_aliases_and_releases_capacity() -> Result<()> {
        let slots = chunk_slots("http://origin-limit.test/path-a")?;
        let held = slots
            .clone()
            .try_acquire_many_owned(CHUNK_ORIGIN_LIMIT as u32)?;
        assert!(
            chunk_slots("http://origin-limit.test:80/path-b")?
                .try_acquire_owned()
                .is_err()
        );
        let other = chunk_slots("http://other-origin-limit.test")?.try_acquire_owned()?;
        drop(held);
        assert!(
            slots
                .try_acquire_many_owned(CHUNK_ORIGIN_LIMIT as u32)
                .is_ok()
        );
        drop(other);
        Ok(())
    }

    #[test]
    fn chunk_ranking_learns_speed_penalizes_failure_and_explores() -> Result<()> {
        let peers = PeerState::new("http://127.0.0.1:1984")?;
        let configured = vec!["https://slow".to_owned(), "https://new".to_owned()];
        let fast = "http://8.8.8.8:1984";
        for url in [configured[0].as_str(), configured[1].as_str(), fast] {
            peers.state.lock().unwrap().nodes.insert(
                url.to_owned(),
                ArweavePeer {
                    url: url.to_owned(),
                    blocks: 1,
                    height: 1,
                    last_seen: 0,
                    coverage: Some(decode_buckets(&bucket_frame(&[(0, 0.5)]))?),
                    weight: 50,
                },
            );
        }
        let candidates = peers.chunk_candidates(1, &configured)?;
        assert_eq!(
            candidates.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                fast.to_owned(),
                configured[0].clone(),
                configured[1].clone(),
            ])
        );
        peers.record_chunk_result(
            "https://slow",
            Some((Duration::from_secs(2), Duration::from_secs(2), 262_144)),
        );
        peers.record_chunk_result(
            fast,
            Some((
                Duration::from_millis(10),
                Duration::from_millis(10),
                262_144,
            )),
        );
        assert_eq!(peers.chunk_candidates(1, &configured)?[0], fast);
        for _ in 0..4 {
            peers.record_chunk_result(fast, None);
        }
        assert_ne!(peers.chunk_candidates(1, &configured)?[0], fast);
        peers.record_chunk_result(
            fast,
            Some((
                Duration::from_millis(10),
                Duration::from_millis(10),
                262_144,
            )),
        );
        assert!(
            (0..32).any(|_| peers.chunk_candidates(1, &configured).unwrap()[0] == "https://new")
        );
        let _saturated = chunk_slots(fast)?.try_acquire_many_owned(CHUNK_ORIGIN_LIMIT as u32)?;
        for _ in 0..16 {
            assert_ne!(peers.chunk_candidates(1, &configured)?[0], fast);
        }
        Ok(())
    }
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

    #[tokio::test]
    async fn discovered_chunks_remain_reachable_after_configured_failures() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let body = br#"{"hello":"arweave"}"#;
        let mut end = [0; 32];
        end[16..].copy_from_slice(&(body.len() as u128).to_be_bytes());
        let hash = crate::sha256(&[body]);
        let root = crate::hash_leaf(&hash, &end);
        let tx_root = crate::hash_leaf(&root, &end);
        let chunk = serde_json::to_vec(&json!({
            "chunk": crate::URL_SAFE_NO_PAD.encode(body),
            "data_path": crate::URL_SAFE_NO_PAD.encode([hash.as_slice(), end.as_slice()].concat()),
            "tx_path": crate::URL_SAFE_NO_PAD.encode([root.as_slice(), end.as_slice()].concat()),
        }))
        .unwrap();
        let index_entry = |weave: u128, root: [u8; 32]| {
            let mut bytes = vec![0; 48];
            bytes.extend_from_slice(&16_u16.to_be_bytes());
            bytes.extend_from_slice(&weave.to_be_bytes());
            bytes.push(32);
            bytes.extend_from_slice(&root);
            bytes
        };
        let previous = index_entry(1000, [0; 32]);
        let current = index_entry(1145, tx_root);
        let replies = Arc::new(BTreeMap::from([
            ("/trusted/peers", br#"["8.8.8.8:1984"]"#.to_vec()),
            ("/trusted/info", br#"{"height":51}"#.to_vec()),
            ("/info", br#"{"height":51,"blocks":51}"#.to_vec()),
            ("/sync_buckets", bucket_frame(&[(0, 1.0)])),
            ("/trusted/block_index2/0/0", previous.clone()),
            ("/trusted/block_index2/1/1", current.clone()),
            ("/trusted/block_index2/0/1", [previous, current].concat()),
            ("/chunk/1002", chunk.clone()),
            ("/chunk/1001", chunk),
        ]));
        let mode = Arc::new(AtomicUsize::new(0));
        let mode_in = Arc::clone(&mode);
        let chunk_requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&chunk_requests);
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let replies = replies.clone();
            let mode = Arc::clone(&mode_in);
            let counted = Arc::clone(&counted);
            async move {
                if request.uri().path().starts_with("/stalled") {
                    std::future::pending::<()>().await;
                }
                if mode.load(Ordering::Relaxed) == 5 && request.uri().path() == "/trusted/info" {
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Vec::new());
                }
                if request.uri().path().starts_with("/chunk/") {
                    counted.fetch_add(1, Ordering::Relaxed);
                    match mode.load(Ordering::Relaxed) {
                        1 => std::future::pending::<()>().await,
                        2 => return (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                        3 => {
                            return (
                                axum::http::StatusCode::OK,
                                br#"{"chunk":"AA","data_path":"","tx_path":""}"#.to_vec(),
                            );
                        }
                        _ => {}
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                if let Some(body) = replies.get(request.uri().path()) {
                    let mut body = body.clone();
                    if mode.load(Ordering::Relaxed) == 4
                        && request.uri().path().contains("block_index2")
                    {
                        *body.last_mut().unwrap() ^= 1;
                    }
                    (axum::http::StatusCode::OK, body)
                } else {
                    (axum::http::StatusCode::NOT_FOUND, Vec::new())
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = crate::Config::new(
            format!("{base}/trusted"),
            format!("{base}/archive"),
            std::iter::once(format!("{base}/stalled"))
                .chain((0..3).map(|index| format!("{base}/unavailable{index}")))
                .collect(),
            Duration::from_secs(5),
            3,
            1024,
        )
        .unwrap();
        let mut gateway = crate::Gateway::new(config).unwrap();
        let client = Client::builder()
            .proxy(reqwest::Proxy::all(&base).unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        gateway.client = client.clone();
        Arc::get_mut(&mut gateway.peers).unwrap().client = client;
        gateway.peers.refresh_arweave().await.unwrap();
        let geometry = crate::Geometry {
            tx_root,
            data_root: root,
            block_weave_size: 1145,
            previous_weave_size: 1000,
            first_offset: 1001,
            end_offset: 1019,
            data_size: body.len() as u128,
        };
        assert_eq!(
            crate::streaming::ChunkSource::new(&gateway, geometry)
                .read_at(0, body.len())
                .await
                .unwrap()
                .as_ref(),
            body
        );
        let calls = futures_util::future::join_all((0..32).map(|_| gateway.retrieve_chunk(1001)));
        let shared = tokio::time::timeout(Duration::from_millis(750), calls)
            .await
            .expect("stalled peer blocked the working peer");
        for result in shared {
            let (chunk, hit) = result.unwrap().unwrap();
            assert!(!hit);
            assert_eq!(
                chunk.bytes.read_all(body.len()).await.unwrap().as_ref(),
                body
            );
        }
        assert_eq!(
            chunk_requests.load(Ordering::Relaxed),
            2,
            "identical cold requests were duplicated"
        );
        mode.store(5, Ordering::Relaxed);
        let (nearby, hit) = gateway.retrieve_chunk(1002).await.unwrap().unwrap();
        assert!(!hit);
        assert_eq!(nearby.read_offset, 1);
        assert_eq!(
            nearby.bytes.read_all(body.len()).await.unwrap().as_ref(),
            body
        );
        mode.store(3, Ordering::Relaxed);
        assert!(gateway.retrieve_chunk(1001).await.unwrap().unwrap().1);
        assert_eq!(
            chunk_requests.load(Ordering::Relaxed),
            3,
            "cache hit fetched chunk content"
        );
        mode.store(4, Ordering::Relaxed);
        assert!(gateway.retrieve_chunk(1001).await.is_err());
        let mut config = gateway.config.clone();
        config.chunk_sources = vec![base.clone()];
        config.request_timeout = Duration::from_millis(200);
        config.cache_max_bytes = 1;
        let fresh = crate::Gateway::new(config).unwrap();
        mode.store(1, Ordering::Relaxed);
        assert!(
            fresh.retrieve_chunk(1001).await.is_err(),
            "timeout was reported as missing"
        );
        mode.store(2, Ordering::Relaxed);
        assert!(fresh.retrieve_chunk(1001).await.unwrap().is_none());
        mode.store(0, Ordering::Relaxed);
        let before = chunk_requests.load(Ordering::Relaxed);
        assert!(!fresh.retrieve_chunk(1001).await.unwrap().unwrap().1);
        assert!(!fresh.retrieve_chunk(1001).await.unwrap().unwrap().1);
        assert_eq!(
            chunk_requests.load(Ordering::Relaxed),
            before + 2,
            "over-budget chunk was retained"
        );
        assert_eq!(
            gateway
                .retrieve_chunk(1001)
                .await
                .unwrap()
                .unwrap()
                .0
                .bytes
                .read_all(body.len())
                .await
                .unwrap()
                .as_ref(),
            body
        );
        server.abort();
    }
}
