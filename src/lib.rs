pub mod background;
pub mod content;
pub mod database;
mod disk_cache;
mod historical;
pub mod indexer;
mod json_bundle;
mod peers;
mod profiling;
pub mod server;
mod streaming;
mod transactions;

use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use content::{Content, SpoolBudget};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use futures_util::{StreamExt, stream::FuturesUnordered};
use k256::ecdsa::{
    RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1VerifyingKey,
    signature::hazmat::PrehashVerifier,
};
use reqwest::{Client, RequestBuilder, Url, header::HeaderValue};
use rsa::BigUint;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256, Sha384};
use sha3::Keccak256;
use transactions::{verify_rsa_pss, verify_transaction};

const CONSENSUS_DEPTH: u64 = 50;
const FORK_2_5_HEIGHT: u64 = 812_970;
const FORK_2_6_HEIGHT: u64 = 1_132_210;
const FORK_2_7_HEIGHT: u64 = 1_275_480;
const FORK_2_8_HEIGHT: u64 = 1_547_120;
const FORK_2_9_HEIGHT: u64 = 1_602_350;
const HASH_SIZE: usize = 32;
const NOTE_SIZE: usize = 32;
const BRANCH_SIZE: usize = HASH_SIZE * 2 + NOTE_SIZE;
const LEAF_SIZE: usize = HASH_SIZE + NOTE_SIZE;
const MAX_CHUNK_SIZE: u128 = 256 * 1024;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_GRAPHQL_SOURCES: usize = 4;
const MAX_PROOF_BYTES: usize = 64 * 1024;
const MAX_BLOCK_INDEX_BYTES: usize = 256 * 99;
const MAX_BLOCK_TRANSACTIONS: usize = 1000;
const MAX_BLOCK_TRANSACTION_BYTES: usize = 64 * 1024 * 1024;
const BUNDLE_ENTRY_SIZE: usize = 64;
const MAX_DATA_ITEM_TAGS: usize = 128;
const MAX_DATA_ITEM_TAG_BYTES: usize = 4096;
// Type 6 has the largest signature/owner; flags, lengths and tags are bounded.
const MAX_DATA_ITEM_HEADER_BYTES: usize = 2 + 2_052 + 1_025 + 2 * 33 + 16 + MAX_DATA_ITEM_TAG_BYTES;
const MAX_BUNDLE_DEPTH: usize = 32;
const STRICT_DATA_SPLIT_THRESHOLD: u128 = 30_607_159_107_830;
const MERKLE_REBASE_SUPPORT_THRESHOLD: u128 = 151_066_495_197_430;

#[derive(Clone, Debug)]
pub struct Config {
    pub trusted_node_url: String,
    pub archive_url: String,
    pub chunk_sources: Vec<String>,
    /// Full GraphQL endpoint URLs used only for untrusted location hints.
    pub graphql_sources: Vec<String>,
    pub request_timeout: Duration,
    pub max_peer_attempts: usize,
    pub max_data_size: usize,
    pub max_memory_data_size: usize,
    pub max_spool_bytes: usize,
    /// Concurrent bundle downloads, configured by AR_IO_INDEX_DOWNLOADS.
    pub index_downloads: usize,
    /// Active and queued bundle bytes, configured by AR_IO_INDEX_MAX_BYTES.
    /// The serving worker reserves half for HTTP-discovered bundle handoffs.
    pub index_max_bytes: usize,
    /// Follow the trusted chain from genesis when AR_IO_INDEX_CHAIN is enabled.
    pub index_chain: bool,
    pub retrieval_timeout: Duration,
    pub stream_idle_timeout: Duration,
    pub stream_timeout: Duration,
    pub cache_max_entries: usize,
    pub cache_max_bytes: usize,
}

impl Config {
    pub fn new(
        trusted_node_url: impl Into<String>,
        archive_url: impl Into<String>,
        chunk_sources: Vec<String>,
        request_timeout: Duration,
        max_peer_attempts: usize,
        max_data_size: usize,
    ) -> Result<Self> {
        let trusted_node_url = normalize_base_url(&trusted_node_url.into())?;
        let archive_url = normalize_base_url(&archive_url.into())?;
        let chunk_sources = chunk_sources
            .into_iter()
            .map(|source| normalize_base_url(&source))
            .collect::<Result<Vec<_>>>()?;

        ensure!(
            !chunk_sources.is_empty(),
            "at least one chunk source is required"
        );
        ensure!(max_peer_attempts > 0, "max peer attempts must be positive");
        ensure!(max_data_size > 0, "maximum data size must be positive");
        ensure!(
            !request_timeout.is_zero(),
            "request timeout must be positive"
        );

        Ok(Self {
            trusted_node_url,
            graphql_sources: vec![endpoint(&archive_url, "graphql")],
            archive_url,
            chunk_sources,
            request_timeout,
            max_peer_attempts,
            max_data_size,
            max_memory_data_size: max_data_size.min(64 * 1024 * 1024),
            max_spool_bytes: 4 * 1024 * 1024 * 1024,
            index_downloads: 32,
            index_max_bytes: 8 * 1024 * 1024 * 1024,
            index_chain: false,
            retrieval_timeout: Duration::from_secs(30 * 60),
            stream_idle_timeout: Duration::from_secs(30),
            stream_timeout: Duration::from_secs(30 * 60),
            cache_max_entries: 1024,
            cache_max_bytes: 512 * 1024 * 1024,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedData {
    #[serde(skip_serializing)]
    pub bytes: Content,
    #[serde(skip_serializing)]
    pub cache_hit: bool,
    pub id: String,
    pub block_height: u64,
    #[serde(skip_serializing)]
    block_hash: Option<[u8; 48]>,
    #[serde(skip_serializing)]
    stable_anchor: bool,
    pub content_type: String,
    pub content_encoding: Option<String>,
    pub content_length: usize,
    pub etag: String,
    pub sha256: String,
    #[serde(skip_serializing)]
    indexing_root: Option<IndexingRoot>,
}

#[derive(Debug)]
pub(crate) struct VerifiedRoot {
    data: VerifiedData,
    tags: Vec<Tag>,
    facts: Option<indexer::RootFacts>,
}

#[derive(Clone, Debug)]
enum IndexingRoot {
    Complete(Arc<VerifiedRoot>),
    Partial(Arc<AuthenticatedRoot>),
}

#[derive(Debug)]
pub(crate) struct AuthenticatedRoot {
    id: String,
    bytes: Content,
    block_height: u64,
    block_hash: [u8; 48],
    stable_anchor: bool,
    tags: Vec<Tag>,
    content_encoding: Option<String>,
    facts: Option<indexer::RootFacts>,
}

impl AuthenticatedRoot {
    fn metadata_bytes(&self) -> usize {
        self.tags.iter().fold(
            std::mem::size_of::<Self>()
                .saturating_add(self.id.capacity())
                .saturating_add(self.content_encoding.as_ref().map_or(0, String::capacity))
                .saturating_add(self.tags.capacity() * std::mem::size_of::<Tag>())
                .saturating_add(self.facts.as_ref().map_or(0, |facts| facts.heap_bytes())),
            |bytes, tag| {
                bytes
                    .saturating_add(tag.name.capacity())
                    .saturating_add(tag.value.capacity())
            },
        )
    }
}

impl VerifiedRoot {
    fn verified(self: &Arc<Self>) -> VerifiedData {
        let mut data = self.data.clone();
        data.indexing_root = Some(IndexingRoot::Complete(Arc::clone(self)));
        data
    }

    fn metadata_bytes(&self) -> usize {
        self.tags.iter().fold(
            std::mem::size_of::<Self>()
                .saturating_add(self.data.string_bytes())
                .saturating_add(self.tags.capacity() * std::mem::size_of::<Tag>())
                .saturating_add(self.facts.as_ref().map_or(0, |facts| facts.heap_bytes())),
            |bytes, tag| {
                bytes
                    .saturating_add(tag.name.capacity())
                    .saturating_add(tag.value.capacity())
            },
        )
    }

    fn retained_bytes(&self) -> usize {
        self.metadata_bytes()
            .saturating_add(self.data.bytes.persistent_blob().map_or_else(
                || self.data.bytes.len().max(self.data.bytes.resident_len()),
                |(_, size, _)| size,
            ))
    }
}

impl VerifiedData {
    fn string_bytes(&self) -> usize {
        self.id
            .capacity()
            .saturating_add(self.content_type.capacity())
            .saturating_add(self.content_encoding.as_ref().map_or(0, String::capacity))
            .saturating_add(self.etag.capacity())
            .saturating_add(self.sha256.capacity())
    }

    fn cache_bytes(&self) -> usize {
        self.string_bytes()
            .saturating_add(match &self.indexing_root {
                Some(IndexingRoot::Complete(root)) => root.retained_bytes(),
                Some(IndexingRoot::Partial(root)) => self
                    .bytes
                    .resident_len()
                    .saturating_add(root.metadata_bytes())
                    .saturating_add(root.bytes.resident_len()),
                None => self.bytes.resident_len(),
            })
    }
}

tokio::task_local! {
    static BACKGROUND_CPU: ();
}

async fn cpu_work<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    static HTTP_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    static BACKGROUND_JOBS: tokio::sync::Semaphore =
        tokio::sync::Semaphore::const_new(background::CPU_JOBS);
    let jobs = if BACKGROUND_CPU.try_with(|()| ()).is_ok() {
        &BACKGROUND_JOBS
    } else {
        &HTTP_JOBS
    };
    let permit = profiling::measure(profiling::Stage::CpuAdmission, async {
        jobs.acquire().await.context("CPU work admission closed")
    })
    .await?;
    let profile = profiling::current();
    let dispatch = profiling::start(profiling::Stage::CpuDispatch);
    tokio::task::spawn_blocking(move || {
        if let Some(timer) = dispatch {
            timer.finish(true, 0);
        }
        let _permit = permit;
        let timer = profiling::start_for(&profile, profiling::Stage::CpuExecution);
        let result = work();
        if let Some(timer) = timer {
            timer.finish(result.is_ok(), 0);
        }
        result
    })
    .await
    .context("CPU verification task failed")?
}

#[derive(Serialize, Deserialize)]
struct CachedContent {
    id: String,
    block_height: u64,
    content_type: String,
    content_encoding: Option<String>,
    blob_hash: [u8; 32],
    blob_size: usize,
    offset: usize,
    length: usize,
    digest: [u8; 32],
    tags: Option<Vec<Tag>>,
}

#[derive(Debug)]
pub struct VerifiedChunk {
    pub bytes: Content,
    pub chunk: String,
    pub data_path: String,
    pub tx_path: String,
    pub data_root: String,
    pub data_size: u128,
    pub start_offset: u128,
    pub relative_start_offset: u128,
    pub read_offset: u128,
    pub tx_start_offset: u128,
    pub source_host: String,
}

impl VerifiedChunk {
    fn retained_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.bytes.resident_len()
            + self.chunk.capacity()
            + self.data_path.capacity()
            + self.tx_path.capacity()
            + self.data_root.capacity()
            + self.source_host.capacity()
    }
}

type ChunkResponse = Option<(Arc<VerifiedChunk>, bool)>;
type ChunkOutcome = Option<std::result::Result<ChunkResponse, RetrievalFailure>>;

#[derive(Default)]
struct ChunkCache {
    entries: HashMap<u128, (Arc<VerifiedChunk>, BlockGeometry, u64, Instant)>,
    inflight: HashMap<u128, tokio::sync::watch::Sender<ChunkOutcome>>,
    bytes: usize,
}

struct ChunkLeader<'a> {
    cache: &'a Mutex<ChunkCache>,
    offset: u128,
    completed: bool,
}

impl Drop for ChunkLeader<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.cache.lock().unwrap().inflight.remove(&self.offset);
    }
}

const CHUNK_DEADLINE: Duration = Duration::from_secs(20);
const CHUNK_PEER_DEADLINE: Duration = Duration::from_secs(3);
static CHUNK_FETCHES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);

#[derive(Debug)]
pub(crate) struct ContentNotFound;

impl std::fmt::Display for ContentNotFound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("content not found")
    }
}

impl std::error::Error for ContentNotFound {}

#[derive(Clone)]
enum RetrievalFailure {
    NotFound,
    Other(String),
}

type RetrievalResult = Option<std::result::Result<VerifiedData, RetrievalFailure>>;

#[derive(Default)]
struct ContentCache {
    entries: HashMap<String, (VerifiedData, u128)>,
    inflight: HashMap<String, tokio::sync::watch::Sender<RetrievalResult>>,
    bytes: usize,
    clock: u128,
}

impl ContentCache {
    fn get(&mut self, id: &str) -> Option<VerifiedData> {
        let (data, accessed) = self.entries.get_mut(id)?;
        self.clock += 1;
        *accessed = self.clock;
        let mut data = data.clone();
        data.cache_hit = true;
        Some(data)
    }

    fn insert(&mut self, data: VerifiedData, max_entries: usize, max_bytes: usize) {
        let size = data.cache_bytes();
        if !data.bytes.is_memory() || max_entries == 0 || size > max_bytes || max_bytes == 0 {
            return;
        }
        if let Some((old, _)) = self.entries.remove(&data.id) {
            self.bytes -= old.cache_bytes();
        }
        // ponytail: bounded O(n) eviction, use an ordered LRU if insertion throughput demands it.
        while self.entries.len() >= max_entries || self.bytes > max_bytes - size {
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, (_, accessed))| *accessed)
                .map(|(id, _)| id.clone())
                .unwrap();
            self.bytes -= self.entries.remove(&victim).unwrap().0.cache_bytes();
        }
        self.clock += 1;
        self.bytes += size;
        self.entries.insert(data.id.clone(), (data, self.clock));
    }
}

struct RetrievalLeader<'a> {
    cache: &'a Mutex<ContentCache>,
    id: &'a str,
    completed: bool,
}

impl Drop for RetrievalLeader<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(sender) = self.cache.lock().unwrap().inflight.remove(self.id) {
            sender.send_replace(Some(Err(RetrievalFailure::Other(
                "verified retrieval canceled".to_owned(),
            ))));
        }
    }
}

pub struct Gateway {
    config: Config,
    client: Client,
    cache: Mutex<ContentCache>,
    peers: Arc<peers::PeerState>,
    block_store: Option<database::BlockStore>,
    spool_budget: Arc<SpoolBudget>,
    disk_cache: Option<disk_cache::DiskCache>,
    direct_cache: Arc<Mutex<ContentCache>>,
    bundle_indexer: Option<background::BundleSubmitter>,
    chunk_cache: Mutex<ChunkCache>,
}

impl Gateway {
    pub fn new(mut config: Config) -> Result<Self> {
        ensure!(
            config.max_data_size > 0,
            "maximum data size must be positive"
        );
        ensure!(
            config.max_memory_data_size > 0 && config.max_spool_bytes > 0,
            "memory and temporary storage limits must be positive"
        );
        ensure!(
            (1..=256).contains(&config.index_downloads) && config.index_max_bytes > 0,
            "index downloads must be between 1 and 256 and the byte budget must be positive"
        );
        ensure!(
            !config.retrieval_timeout.is_zero()
                && !config.stream_idle_timeout.is_zero()
                && !config.stream_timeout.is_zero(),
            "retrieval and stream timeouts must be positive"
        );
        for source in &mut config.graphql_sources {
            *source = normalize_base_url(source.trim())?;
        }
        config.graphql_sources.sort();
        config.graphql_sources.dedup();
        ensure!(
            (1..=MAX_GRAPHQL_SOURCES).contains(&config.graphql_sources.len()),
            "between one and four GraphQL sources are required"
        );
        let client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .context("failed to build HTTP client")?;
        let peers = Arc::new(peers::PeerState::new(&config.trusted_node_url)?);
        Ok(Self {
            spool_budget: Arc::new(SpoolBudget::new(config.max_spool_bytes)),
            config,
            client,
            cache: Mutex::new(ContentCache::default()),
            chunk_cache: Mutex::new(ChunkCache::default()),
            peers,
            block_store: None,
            disk_cache: None,
            direct_cache: Arc::new(Mutex::new(ContentCache::default())),
            bundle_indexer: None,
        })
    }

    pub async fn with_database(mut self, url: &str) -> Result<Self> {
        let mut store = database::BlockStore::connect(url).await?;
        if self.config.index_chain && store.state().await?.is_none() {
            indexer::import_range(&self, &mut store, 0, 0).await?;
        }
        let state = store
            .state()
            .await?
            .context("block index has not been initialized")?;
        ensure!(
            state.source == self.config.trusted_node_url,
            "block index belongs to a different trusted node"
        );
        self.block_store = Some(store);
        Ok(self)
    }
    pub async fn with_disk_cache(mut self, path: PathBuf, min_free_bytes: u64) -> Result<Self> {
        let store = self
            .block_store
            .as_ref()
            .context("persistent caching requires DATABASE_URL and an initialized block index")?;
        store.require_content_cache().await?;
        let mut cache =
            disk_cache::DiskCache::new(path, min_free_bytes, self.config.max_spool_bytes).await?;
        let deadline = Instant::now() + self.config.retrieval_timeout;
        let removed = tokio::time::timeout_at(deadline.into(), cache.cleanup(store, deadline))
            .await
            .context("content cache startup cleanup timed out")??;
        if removed > 0 {
            eprintln!("removed {removed} abandoned content cache files");
        }
        self.disk_cache = Some(cache);
        Ok(self)
    }

    pub async fn with_bundle_indexing(
        mut self,
        database_url: &str,
    ) -> Result<(Self, background::BundleWorker)> {
        ensure!(
            self.block_store.is_some(),
            "bundle indexing requires an initialized database"
        );
        let (submitter, worker) = background::start(
            self.config.clone(),
            self.disk_cache.clone(),
            database_url.to_owned(),
            Arc::clone(&self.direct_cache),
            Arc::clone(&self.peers),
        )
        .await?;
        self.bundle_indexer = Some(submitter);
        Ok((self, worker))
    }

    async fn load_content_cache(
        &self,
        id: &str,
    ) -> Result<Option<(VerifiedData, Option<Vec<Tag>>)>> {
        let (Some(cache), Some(store)) = (&self.disk_cache, &self.block_store) else {
            return Ok(None);
        };
        let key = decode_fixed::<32>(id, "data ID")?;
        let Some((metadata, block_hash)) = store.cached_content(&key).await? else {
            return Ok(None);
        };
        let entry: CachedContent =
            serde_json::from_str(&metadata).context("invalid authenticated cache metadata")?;
        ensure!(entry.id == id, "cached content identity mismatch");
        ensure!(
            entry.length <= self.config.max_data_size,
            "cached content exceeds size limit"
        );
        let end = entry
            .offset
            .checked_add(entry.length)
            .context("cached content offset overflow")?;
        ensure!(end <= entry.blob_size, "cached content exceeds parent file");
        let Some(blob) = cache.load(entry.blob_hash, entry.blob_size).await? else {
            return Ok(None);
        };
        let bytes = blob.slice(entry.offset..end)?;
        let digest = if entry.offset == 0 && entry.length == entry.blob_size {
            entry.blob_hash
        } else {
            bytes.hashes().await?.0
        };
        ensure!(digest == entry.digest, "cached content digest mismatch");
        Ok(Some((
            VerifiedData {
                bytes,
                id: entry.id,
                block_height: entry.block_height,
                block_hash: Some(
                    block_hash
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid cached block hash"))?,
                ),
                stable_anchor: false,
                content_type: entry.content_type,
                content_encoding: entry.content_encoding,
                content_length: entry.length,
                etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(digest)),
                sha256: hex(&digest),
                cache_hit: true,
                indexing_root: None,
            },
            entry.tags,
        )))
    }

    async fn save_content_cache(
        &self,
        data: &mut VerifiedData,
        tags: Option<Vec<Tag>>,
    ) -> Result<()> {
        let (Some(cache), Some(store)) = (&self.disk_cache, &self.block_store) else {
            return Ok(());
        };
        let Some((_, block)) = store.block_pair(data.block_height).await? else {
            return Ok(());
        };
        ensure!(
            data.block_hash.as_ref().map(|hash| hash.as_slice()) == Some(block.hash.as_slice()),
            "verified content block changed before cache admission"
        );
        let digest = decode_fixed::<32>(data.etag.trim_matches('"'), "verified content digest")?;
        let bytes = if data.bytes.persistent_blob().is_some() {
            data.bytes.clone()
        } else {
            let Some(bytes) = cache.store(&data.bytes, digest).await? else {
                return Ok(());
            };
            bytes
        };
        let (blob_hash, blob_size, offset) = bytes
            .persistent_blob()
            .context("cache publication did not return persistent content")?;
        let entry = CachedContent {
            id: data.id.clone(),
            block_height: data.block_height,
            content_type: data.content_type.clone(),
            content_encoding: data.content_encoding.clone(),
            blob_hash,
            blob_size,
            offset,
            length: data.content_length,
            digest,
            tags,
        };
        let metadata = serde_json::to_string(&entry)?;
        if store
            .cache_content(
                &decode_fixed::<32>(&data.id, "data ID")?,
                data.block_height,
                &block.hash,
                &metadata,
            )
            .await?
        {
            data.bytes = bytes;
        }
        Ok(())
    }

    pub async fn retrieve(&self, id: &str) -> Result<VerifiedData> {
        decode_fixed::<32>(id, "data ID")?;
        // Keep the retrieval state machine off the Windows HTTP thread's stack.
        let data = Box::pin(self.retrieve_cached(&self.cache, id, true, async {
            if let Some((mut data, tags)) = self.load_content_cache(id).await? {
                if let Some(tags) = tags {
                    data = Arc::new(VerifiedRoot {
                        data,
                        tags,
                        facts: None,
                    })
                    .verified();
                }
                return Ok(data);
            }
            match self.retrieve_discovered(id).await {
                Ok(Some(data)) => Ok(data),
                Ok(None) => self.retrieve_direct(id).await,
                Err(discovery_error) => match self.retrieve_direct(id).await {
                    Ok(data) => Ok(data),
                    Err(error) if error.is::<ContentNotFound>() => Err(discovery_error),
                    Err(error) => Err(error),
                },
            }
        }))
        .await?;
        // Node's L1 content source returns 404 when there are no data chunks.
        if data.content_length == 0
            && matches!(&data.indexing_root, Some(IndexingRoot::Complete(root)) if root.data.id == data.id)
        {
            return Err(ContentNotFound.into());
        }
        if let (Some(indexer), Some(root)) = (&self.bundle_indexer, &data.indexing_root) {
            match root {
                IndexingRoot::Complete(root) => indexer.submit(root),
                IndexingRoot::Partial(root) => indexer.submit_partial(root),
            }
        }
        Ok(data)
    }

    async fn current_anchor(&self, data: &VerifiedData) -> Result<bool> {
        if data.stable_anchor {
            return Ok(true);
        }
        let expected = data
            .block_hash
            .context("verified content lacks a block hash")?;
        if let Some(store) = &self.block_store
            && let Some(hash) = store.stable_canonical_hash(data.block_height).await?
        {
            return Ok(hash.as_slice() == expected);
        }
        Ok(self
            .trusted_block_index(data.block_height, data.block_height)
            .await?
            .and_then(|entries| entries.into_iter().next())
            .is_some_and(|entry| entry.hash == URL_SAFE_NO_PAD.encode(expected)))
    }

    async fn retrieve_cached(
        &self,
        cache: &Mutex<ContentCache>,
        id: &str,
        cache_result: bool,
        retrieve: impl Future<Output = Result<VerifiedData>>,
    ) -> Result<VerifiedData> {
        let cached = { cache.lock().unwrap().get(id) };
        if let Some(data) = cached {
            if self.current_anchor(&data).await? {
                return Ok(data);
            }
            let mut state = cache.lock().unwrap();
            if let Some((old, _)) = state.entries.remove(id) {
                state.bytes -= old.cache_bytes();
            }
        }
        let (mut receiver, leader) = {
            let mut state = cache.lock().unwrap();
            match state.inflight.get(id) {
                Some(sender) => (sender.subscribe(), None),
                None => {
                    let (sender, receiver) = tokio::sync::watch::channel(None);
                    state.inflight.insert(id.to_owned(), sender);
                    (
                        receiver,
                        Some(RetrievalLeader {
                            cache,
                            id,
                            completed: false,
                        }),
                    )
                }
            }
        };
        if let Some(mut leader) = leader {
            let result = tokio::time::timeout(self.config.retrieval_timeout, async {
                let data = retrieve.await?;
                ensure!(
                    self.current_anchor(&data).await?,
                    "content block changed during retrieval"
                );
                Ok(data)
            })
            .await
            .context("verified retrieval timed out")
            .and_then(|result| result);
            {
                let mut cache = cache.lock().unwrap();
                if cache_result && let Ok(data) = &result {
                    cache.insert(
                        data.clone(),
                        self.config.cache_max_entries,
                        self.config.cache_max_bytes,
                    );
                }
                if let Some(sender) = cache.inflight.remove(id) {
                    sender.send_replace(Some(match &result {
                        Ok(data) => Ok(data.clone()),
                        Err(error) if error.is::<ContentNotFound>() => {
                            Err(RetrievalFailure::NotFound)
                        }
                        Err(error) => Err(RetrievalFailure::Other(format!("{error:#}"))),
                    }));
                }
                leader.completed = true;
            }
            drop(leader);
            result
        } else {
            tokio::time::timeout(self.config.retrieval_timeout, receiver.changed())
                .await
                .context("coalesced retrieval timed out")?
                .context("coalesced retrieval canceled")?;
            let data = receiver
                .borrow_and_update()
                .as_ref()
                .context("coalesced retrieval returned no result")?
                .clone()
                .map_err(|error| match error {
                    RetrievalFailure::NotFound => anyhow::Error::new(ContentNotFound),
                    RetrievalFailure::Other(message) => anyhow::Error::msg(message),
                })?;
            ensure!(
                self.current_anchor(&data).await?,
                "coalesced content block changed"
            );
            Ok(data)
        }
    }

    pub async fn retrieve_direct(&self, id: &str) -> Result<VerifiedData> {
        let root = tokio::time::timeout(
            self.config.retrieval_timeout,
            self.retrieve_direct_with_tags(id),
        )
        .await
        .context("verified retrieval timed out")??;
        Ok(root.verified())
    }

    pub async fn retrieve_bundled(&self, id: &str) -> Result<VerifiedData> {
        tokio::time::timeout(self.config.retrieval_timeout, async {
            decode_fixed::<32>(id, "data item ID")?;
            if let Some((data, None)) = self.load_content_cache(id).await? {
                ensure!(
                    self.current_anchor(&data).await?,
                    "cached content block changed"
                );
                return Ok(data);
            }
            self.retrieve_discovered(id)
                .await?
                .context("discovery returned an unbundled transaction")
        })
        .await
        .context("verified bundle retrieval timed out")?
    }

    pub async fn retrieve_chunk(&self, offset: u128) -> Result<ChunkResponse> {
        tokio::time::timeout(
            self.config.request_timeout.min(Duration::from_secs(60)),
            async {
                let (mut receiver, leader) = {
                    let mut cache = self.chunk_cache.lock().unwrap();
                    if let Some(sender) = cache.inflight.get(&offset) {
                        (sender.subscribe(), false)
                    } else {
                        let (sender, receiver) = tokio::sync::watch::channel(None);
                        cache.inflight.insert(offset, sender);
                        (receiver, true)
                    }
                };
                if !leader {
                    receiver
                        .changed()
                        .await
                        .context("coalesced chunk retrieval canceled")?;
                    return match receiver
                        .borrow()
                        .clone()
                        .context("missing chunk retrieval result")?
                    {
                        Ok(result) => Ok(result),
                        Err(RetrievalFailure::Other(message)) => bail!("{message}"),
                        Err(RetrievalFailure::NotFound) => Ok(None),
                    };
                }
                let mut leader = ChunkLeader {
                    cache: &self.chunk_cache,
                    offset,
                    completed: false,
                };
                let result = self.retrieve_cached_chunk(offset).await;
                if let Some(sender) = self.chunk_cache.lock().unwrap().inflight.remove(&offset) {
                    sender.send_replace(Some(match &result {
                        Ok(result) => Ok(result.clone()),
                        Err(error) => Err(RetrievalFailure::Other(format!("{error:#}"))),
                    }));
                }
                leader.completed = true;
                result
            },
        )
        .await
        .context("chunk retrieval timed out")?
    }

    async fn retrieve_cached_chunk(&self, offset: u128) -> Result<ChunkResponse> {
        let cached = {
            let mut cache = self.chunk_cache.lock().unwrap();
            cache
                .entries
                .get_mut(&offset)
                .map(|(chunk, geometry, height, used)| {
                    *used = Instant::now();
                    (Arc::clone(chunk), *geometry, *height)
                })
        };
        if let Some((chunk, geometry, height)) = cached {
            if self.chunk_anchor_matches(geometry, height).await? {
                return Ok(Some((chunk, true)));
            }
            let mut cache = self.chunk_cache.lock().unwrap();
            if let Some((old, _, _, _)) = cache.entries.remove(&offset) {
                cache.bytes -= old.retained_bytes();
            }
        }
        let nearby = {
            let cache = self.chunk_cache.lock().unwrap();
            cache
                .entries
                .values()
                .find(|(_, geometry, _, _)| {
                    offset > geometry.previous_weave_size && offset <= geometry.block_weave_size
                })
                .map(|(_, geometry, height, _)| (*geometry, *height))
        };
        let anchor = match nearby {
            Some((geometry, height)) if self.chunk_anchor_matches(geometry, height).await? => {
                Some((geometry, height))
            }
            _ => self.trusted_chunk_anchor(offset).await?,
        };
        let Some((geometry, height)) = anchor else {
            return Ok(None);
        };
        let Some(chunk) = tokio::time::timeout(
            self.config.request_timeout.min(CHUNK_DEADLINE),
            self.retrieve_chunk_inner(offset, geometry),
        )
        .await
        .context("chunk peer search timed out")??
        else {
            return Ok(None);
        };
        ensure!(
            self.chunk_anchor_matches(geometry, height).await?,
            "chunk block changed during retrieval"
        );
        let chunk = Arc::new(chunk);
        let size = chunk.retained_bytes();
        let max_bytes = self.config.cache_max_bytes.min(64 * 1024 * 1024);
        let max_entries = self.config.cache_max_entries.min(256);
        if max_entries > 0 && size <= max_bytes {
            let mut cache = self.chunk_cache.lock().unwrap();
            while cache.entries.len() >= max_entries || cache.bytes > max_bytes - size {
                let victim = *cache
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, _, _, used))| *used)
                    .unwrap()
                    .0;
                cache.bytes -= cache.entries.remove(&victim).unwrap().0.retained_bytes();
            }
            cache.entries.insert(
                offset,
                (Arc::clone(&chunk), geometry, height, Instant::now()),
            );
            cache.bytes += size;
        }
        Ok(Some((chunk, false)))
    }

    async fn chunk_anchor_matches(&self, geometry: BlockGeometry, height: u64) -> Result<bool> {
        if let Some(store) = &self.block_store
            && let Some((previous, block)) = store.block_pair(height).await?
        {
            return Ok(block.tx_root.as_slice() == geometry.tx_root
                && block.weave_size == geometry.block_weave_size
                && previous.weave_size == geometry.previous_weave_size);
        }
        let entries = self
            .trusted_block_index(height.saturating_sub(1), height)
            .await?
            .context("trusted chunk anchor is unavailable")?;
        let block = entries.last().context("trusted chunk anchor is empty")?;
        Ok(
            decode_fixed::<32>(&block.tx_root, "block tx_root")? == geometry.tx_root
                && block.weave_size == geometry.block_weave_size
                && (if height == 0 {
                    0
                } else {
                    entries[0].weave_size
                }) == geometry.previous_weave_size,
        )
    }

    async fn retrieve_chunk_inner(
        &self,
        offset: u128,
        geometry: BlockGeometry,
    ) -> Result<Option<VerifiedChunk>> {
        let mut invalid = Vec::new();
        let sources = self
            .peers
            .chunk_candidates(offset, &self.config.chunk_sources);

        let mut pending = sources.iter();
        let mut fetches = FuturesUnordered::new();
        loop {
            while fetches.len() < 3 {
                let Some(source) = pending.next() else { break };
                fetches.push(async move { (source, self.fetch_chunk(source, offset).await) });
            }
            let Some((source, result)) = fetches.next().await else {
                break;
            };
            let (candidate, headers, body) = match result {
                Ok(candidate) => candidate,
                Err(error) => {
                    self.peers.record_chunk_result(source, None);
                    if error
                        .downcast_ref::<reqwest::Error>()
                        .is_none_or(|error| error.status() != Some(reqwest::StatusCode::NOT_FOUND))
                    {
                        invalid.push(format!("{source}: {error:#}"));
                    }
                    continue;
                }
            };
            let proof =
                match cpu_work(move || verify_chunk_proof(candidate, offset, &geometry)).await {
                    Ok(proof) => proof,
                    Err(error) => {
                        self.peers.record_chunk_result(source, None);
                        invalid.push(format!("{source}: {error:#}"));
                        continue;
                    }
                };
            let start_offset = proof
                .first_offset
                .checked_add(proof.data.start)
                .context("chunk start offset overflow")?;
            let read_offset = proof
                .relative_offset
                .checked_sub(proof.data.start)
                .context("chunk read offset underflow")?;
            let source_host = Url::parse(source)?
                .host_str()
                .context("chunk source has no host")?
                .to_owned();

            self.peers
                .record_chunk_result(source, Some((headers, body, proof.bytes.len())));
            return Ok(Some(VerifiedChunk {
                data_root: URL_SAFE_NO_PAD.encode(proof.transaction.data_root),
                data_size: proof.transaction.size,
                relative_start_offset: proof.data.start,
                tx_start_offset: proof.first_offset,
                bytes: proof.bytes.into(),
                chunk: proof.chunk,
                data_path: proof.data_path,
                tx_path: proof.tx_path,
                start_offset,
                read_offset,
                source_host,
            }));
        }

        if invalid.is_empty() {
            Ok(None)
        } else {
            bail!("all chunk candidates failed: {}", invalid.join("; "))
        }
    }

    async fn trusted_chunk_anchor(&self, offset: u128) -> Result<Option<(BlockGeometry, u64)>> {
        if offset == 0 {
            return Ok(None);
        }
        if let Some(store) = &self.block_store
            && let Some((previous, block)) = store.block_for_offset(offset).await?
        {
            ensure!(
                offset > previous.weave_size && offset <= block.weave_size,
                "stored block index returned inconsistent offset geometry"
            );
            return Ok(Some((
                BlockGeometry {
                    tx_root: block
                        .tx_root
                        .as_slice()
                        .try_into()
                        .context("invalid stored tx_root")?,
                    block_weave_size: block.weave_size,
                    previous_weave_size: previous.weave_size,
                },
                block.height,
            )));
        }
        let info: NodeInfo = self.get_json(&self.config.trusted_node_url, "info").await?;
        let Some(stable_height) = info.height.checked_sub(CONSENSUS_DEPTH) else {
            return Ok(None);
        };
        let tip = self
            .trusted_block_index(stable_height, stable_height)
            .await?
            .context("trusted stable chunk anchor is unavailable")?;
        let tip_weave_size = tip[0].weave_size;
        if offset > tip_weave_size {
            return Ok(None);
        }

        let mut low = 0;
        let mut high = stable_height;
        while low < high {
            let height = low + (high - low) / 2;
            let entry = self
                .trusted_block_index(height, height)
                .await?
                .context("trusted chunk search anchor is unavailable")?;
            let weave_size = entry[0].weave_size;
            if offset <= weave_size {
                high = height;
            } else {
                low = height + 1;
            }
        }

        let (start, block_index) = if low == 0 { (0, 0) } else { (low - 1, 1) };
        let entries = self
            .trusted_block_index(start, low)
            .await?
            .context("trusted chunk anchor is unavailable")?;
        let block = &entries[block_index];
        let block_weave_size = block.weave_size;
        let previous_weave_size = if low == 0 { 0 } else { entries[0].weave_size };
        ensure!(
            offset > previous_weave_size && offset <= block_weave_size,
            "trusted block index returned inconsistent offset geometry"
        );

        Ok(Some((
            BlockGeometry {
                tx_root: decode_fixed(&block.tx_root, "block tx_root")?,
                block_weave_size,
                previous_weave_size,
            },
            low,
        )))
    }

    async fn trusted_block_index(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<Vec<TrustedBlockIndexEntry>>> {
        let expected = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .context("invalid block index range")?;
        ensure!(expected <= 256, "block index range exceeds 256 entries");
        let byte_limit = expected as usize * 99;
        let mut response = match self
            .client
            .get(endpoint(
                &self.config.trusted_node_url,
                &format!("block_index2/{start}/{end}"),
            ))
            .send()
            .await
        {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        if let Some(length) = response.content_length() {
            ensure!(
                length <= byte_limit.min(MAX_BLOCK_INDEX_BYTES) as u64,
                "trusted block index response exceeds size limit"
            );
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("failed to read block index")?
        {
            ensure!(
                body.len().saturating_add(chunk.len()) <= byte_limit,
                "trusted block index response exceeds size limit"
            );
            body.extend_from_slice(&chunk);
        }
        let entries = decode_block_index(&body)?;
        let expected = expected as usize;
        ensure!(
            entries.len() == expected,
            "trusted block index returned incomplete geometry"
        );
        Ok(Some(entries))
    }

    async fn retrieve_bundled_with_hint(&self, id: &str, hint: BundleHint) -> Result<VerifiedData> {
        let expected_id = decode_fixed::<32>(id, "data item ID")?;
        let (parent_id, size) = match &hint {
            BundleHint::Indexed(indexed) => {
                (URL_SAFE_NO_PAD.encode(&indexed.root_id), indexed.data_size)
            }
            BundleHint::External {
                parent_id,
                data_size,
            } => (
                parent_id.clone(),
                parse_u128(data_size, "discovered data item size")?,
            ),
        };
        let hinted_size = checked_data_size(size, self.config.max_data_size)?;
        let cached = self.load_content_cache(&parent_id).await?;
        let parent_root = if let Some((data, Some(tags))) = cached {
            IndexingRoot::Complete(Arc::new(VerifiedRoot {
                data,
                tags,
                facts: None,
            }))
        } else {
            IndexingRoot::Partial(Arc::new(self.authenticate_root(&parent_id).await.map_err(
                |error| {
                    if error.is::<ContentNotFound>() {
                        anyhow::anyhow!("bundle parent transaction {parent_id} was not found")
                    } else {
                        error
                    }
                },
            )?))
        };
        let (parent_bytes, block_height, block_hash, cache_hit, tags, stable_anchor) =
            match &parent_root {
                IndexingRoot::Complete(root) => (
                    &root.data.bytes,
                    root.data.block_height,
                    root.data.block_hash,
                    root.data.cache_hit,
                    &root.tags,
                    root.data.stable_anchor,
                ),
                IndexingRoot::Partial(root) => (
                    &root.bytes,
                    root.block_height,
                    Some(root.block_hash),
                    false,
                    &root.tags,
                    root.stable_anchor,
                ),
            };
        let format = require_bundle_tags(tags)?;
        let item = match &hint {
            BundleHint::Indexed(indexed) => {
                verify_indexed_bundle(
                    parent_bytes.clone(),
                    format,
                    &expected_id,
                    indexed,
                    Some(self),
                )
                .await?
            }
            BundleHint::External { .. } => {
                verify_bundle_item(parent_bytes.clone(), format, &expected_id, None, Some(self))
                    .await?
                    .0
            }
        };
        ensure!(
            item.data.len() == hinted_size,
            "discovered data item size does not match verified payload"
        );

        let content_encoding = response_content_encoding(item.text_tag(b"Content-Encoding"))?;
        let bytes = item.data;
        let body_hash = item.body_hash;
        let mut data = VerifiedData {
            content_length: bytes.len(),
            bytes,
            cache_hit,
            id: id.to_owned(),
            block_height,
            block_hash,
            stable_anchor,
            content_type: item_content_type(&item.tags)?,
            content_encoding,
            etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(body_hash)),
            sha256: hex(&body_hash),
            indexing_root: Some(parent_root),
        };
        if let Err(error) = self.save_content_cache(&mut data, None).await {
            eprintln!("content cache admission failed: {error:#}");
        }
        ensure!(
            self.current_anchor(&data).await?,
            "bundle block changed during retrieval"
        );
        Ok(data)
    }

    async fn retrieve_discovered(&self, id: &str) -> Result<Option<VerifiedData>> {
        if let Some(store) = &self.block_store {
            let item_id = decode_fixed::<32>(id, "data ID")?;
            if let Some(indexed) = store.bundle_location(&item_id).await? {
                return self
                    .retrieve_bundled_with_hint(id, BundleHint::Indexed(indexed))
                    .await
                    .map(Some);
            }
        }
        let mut seen = HashSet::new();
        let mut discoveries = FuturesUnordered::new();
        for source in &self.config.graphql_sources {
            discoveries.push(self.discover_from(id, source));
        }
        let mut candidates = FuturesUnordered::new();
        let mut failures = Vec::new();
        while !discoveries.is_empty() || !candidates.is_empty() {
            tokio::select! {
                Some(result) = discoveries.next(), if !discoveries.is_empty() => {
                    match result {
                        Ok(Some(hint)) => {
                            if let BundleHint::External { parent_id, data_size } = &hint
                                && !seen.insert((parent_id.clone(), data_size.clone()))
                            {
                                continue;
                            }
                            candidates.push(self.retrieve_bundled_with_hint(id, hint));
                        }
                        Ok(None) => {}
                        Err(error) => failures.push(format!("{error:#}")),
                    }
                }
                Some(result) = candidates.next(), if !candidates.is_empty() => {
                    match result {
                        Ok(data) => return Ok(Some(data)),
                        Err(error) => failures.push(format!("{error:#}")),
                    }
                }
            }
        }
        ensure!(
            failures.is_empty(),
            "bundle discovery failed: {}",
            failures.join("; ")
        );
        Ok(None)
    }

    async fn discover_from(&self, id: &str, source: &str) -> Result<Option<BundleHint>> {
        let response: GraphQlResponse = self
            .request_json(
                self.client
                    .post(source)
                    .json(&serde_json::json!({
                        "query": "query($ids: [ID!]!) { transactions(ids: $ids, first: 2) { edges { node { id bundledIn { id } data { size } } } } }",
                        "variables": { "ids": [id] }
                    })),
            )
            .await
            .context("failed to discover data location")?;
        let mut edges = response.data.transactions.edges;
        if edges.is_empty() {
            return Ok(None);
        }
        ensure!(
            edges.len() == 1,
            "discovery did not return exactly one data item"
        );
        let node = edges.pop().unwrap().node;
        ensure!(node.id == id, "discovery returned the wrong data item");
        decode_fixed::<32>(&node.id, "discovered data item ID")?;
        let Some(parent) = node.bundled_in else {
            return Ok(None);
        };
        let parent_id = parent.id;
        decode_fixed::<32>(&parent_id, "discovered parent ID")?;
        ensure!(parent_id != id, "data item cannot be its own parent");
        Ok(Some(BundleHint::External {
            parent_id,
            data_size: node.data.size,
        }))
    }

    pub async fn refresh_peers(&self) -> Result<()> {
        self.peers.refresh_arweave().await
    }

    async fn retrieve_direct_with_tags(&self, id: &str) -> Result<Arc<VerifiedRoot>> {
        let data = Box::pin(self.retrieve_cached(&self.direct_cache, id, false, async {
            let root = if let Some((data, Some(tags))) = self.load_content_cache(id).await? {
                VerifiedRoot {
                    data,
                    tags,
                    facts: None,
                }
            } else {
                let started = Instant::now();
                let (mut data, tags, facts) = self.fetch_direct_with_tags(id).await?;
                if facts.is_some() {
                    eprintln!(
                        "verified bundle root {id}: retrieval_ms={}",
                        started.elapsed().as_millis()
                    );
                }
                if let Err(error) = self.save_content_cache(&mut data, Some(tags.clone())).await {
                    eprintln!("content cache admission failed: {error:#}");
                }
                VerifiedRoot { data, tags, facts }
            };
            Ok(Arc::new(root).verified())
        }))
        .await?;
        let Some(IndexingRoot::Complete(root)) = data.indexing_root else {
            bail!("direct retrieval lacks complete root metadata");
        };
        ensure!(
            root.data.bytes.len() <= self.config.max_data_size,
            "shared root exceeds size limit"
        );
        if let Some(indexer) = &self.bundle_indexer {
            indexer.submit(&root);
        }
        Ok(root)
    }

    async fn fetch_direct_with_tags(
        &self,
        id: &str,
    ) -> Result<(VerifiedData, Vec<Tag>, Option<indexer::RootFacts>)> {
        let root = self.authenticate_root(id).await?;
        checked_data_size(root.bytes.len() as u128, self.config.max_data_size)?;
        let (bytes, body_hash) = root
            .bytes
            .materialize(
                self.config.max_memory_data_size,
                Arc::clone(&self.spool_budget),
            )
            .await?;
        Ok((
            VerifiedData {
                content_length: bytes.len(),
                bytes,
                cache_hit: false,
                id: root.id,
                block_height: root.block_height,
                block_hash: Some(root.block_hash),
                stable_anchor: root.stable_anchor,
                content_type: content_type(&root.tags)?,
                content_encoding: root.content_encoding,
                etag: format!("\"{}\"", URL_SAFE_NO_PAD.encode(body_hash)),
                sha256: hex(&body_hash),
                indexing_root: None,
            },
            root.tags,
            root.facts,
        ))
    }

    async fn authenticate_root(&self, id: &str) -> Result<AuthenticatedRoot> {
        decode_fixed::<32>(id, "transaction ID")?;

        let status_url = endpoint(&self.config.archive_url, &format!("tx/{id}/status"));
        let response = self
            .client
            .get(&status_url)
            .send()
            .await
            .context("failed to fetch transaction status")?;
        if response.status() == reqwest::StatusCode::NOT_FOUND
            && response.url().as_str() == status_url
        {
            return Err(ContentNotFound.into());
        }
        let status: TxStatus = read_json_response(
            response
                .error_for_status()
                .context("transaction status source rejected request")?,
        )
        .await?;
        decode_fixed::<48>(&status.block_indep_hash, "status block hash")?;

        let indexed = match &self.block_store {
            Some(store)
                if store
                    .stable_canonical_hash(status.block_height)
                    .await?
                    .is_some() =>
            {
                store.block_pair(status.block_height).await?
            }
            _ => None,
        };
        let stable_anchor;
        let entries: Vec<BlockIndexEntry> = if let Some((previous, block)) = indexed {
            stable_anchor = true;
            [block, previous]
                .into_iter()
                .map(|entry| BlockIndexEntry {
                    hash: URL_SAFE_NO_PAD.encode(&entry.hash),
                    tx_root: URL_SAFE_NO_PAD.encode(&entry.tx_root),
                    weave_size: entry.weave_size.to_string(),
                })
                .collect()
        } else {
            let info: NodeInfo = self
                .get_json(&self.config.trusted_node_url, "info")
                .await
                .context("failed to fetch trusted node height")?;
            ensure!(
                info.height >= status.block_height,
                "transaction block is above the trusted node tip"
            );
            stable_anchor = info.height - status.block_height >= CONSENSUS_DEPTH;
            let index_path = format!(
                "block_index/{}/{}",
                status.block_height.saturating_sub(1),
                status.block_height
            );
            self.request_json(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, &index_path))
                    .header("x-block-format", "1"),
            )
            .await
            .context("failed to fetch trusted block index")?
        };
        ensure!(
            entries.len() == if status.block_height == 0 { 1 } else { 2 },
            "trusted block index returned incomplete geometry"
        );
        let block = &entries[0];
        let previous_block = entries.get(1);
        ensure!(
            block.hash == status.block_indep_hash,
            "archival status does not match the trusted block index"
        );
        let mut header = self
            .authenticate_block(block, status.block_height, Some(id))
            .await?;

        let remaining = AtomicUsize::new(usize::MAX);
        let (transaction, mut verified) = self
            .fetch_transaction(id, status.block_height, &remaining)
            .await?;
        let root_metadata = (self.bundle_indexer.is_some()
            && require_bundle_tags(&transaction.tags).is_ok())
        .then(|| verified.metadata.clone());
        let data_size = verified.metadata.data_size;
        let content_encoding =
            response_content_encoding(verified.metadata.content_encoding.take())?;
        if transaction.format == 1 && transaction.denomination == 0 {
            let previous_size = previous_block
                .map(|previous| parse_u128(&previous.weave_size, "previous block weave size"))
                .transpose()?
                .unwrap_or(0);
            ensure!(
                parse_u128(&block.weave_size, "block weave size")?.checked_sub(previous_size)
                    == Some(parse_u128(&header.block_size, "block size")?),
                "block size does not match trusted weave geometry"
            );
            if let Some(previous) = previous_block {
                ensure!(
                    header.previous_block == previous.hash,
                    "block predecessor does not match trusted index"
                );
            }
            // Legacy signatures bind concatenated fields, not the data boundary.
            // Authenticate the ID-to-payload association before returning inline bytes.
            (header, _) = self
                .verify_block_transactions(
                    header,
                    vec![verified.metadata],
                    usize::MAX - remaining.load(Ordering::Relaxed),
                    None,
                )
                .await?;
        }
        let facts = root_metadata
            .map(|object| {
                Ok::<_, anyhow::Error>(indexer::RootFacts {
                    block_hash: decode_fixed::<48>(&block.hash, "bundle block hash")?,
                    timestamp: header.timestamp,
                    transaction_ids: header
                        .txs
                        .iter()
                        .map(|id| {
                            decode_fixed::<32>(id, "block transaction ID").map(|id| id.to_vec())
                        })
                        .collect::<Result<_>>()?,
                    object,
                })
            })
            .transpose()?;
        if let Some(bytes) = verified.inline_data {
            return Ok(AuthenticatedRoot {
                id: id.to_owned(),
                bytes: bytes.into(),
                block_height: status.block_height,
                block_hash: decode_fixed::<48>(&block.hash, "verified block hash")?,
                stable_anchor,
                tags: transaction.tags,
                content_encoding,
                facts,
            });
        }

        let offset: TxOffset = self
            .get_json(&self.config.archive_url, &format!("tx/{id}/offset"))
            .await
            .context("failed to fetch transaction offset")?;
        let offset_size = parse_u128(&offset.size, "offset data size")?;
        let end_offset = parse_u128(&offset.offset, "transaction end offset")?;
        ensure!(
            offset_size == data_size,
            "transaction size and offset size differ"
        );

        let block_weave_size = parse_u128(&block.weave_size, "block weave size")?;
        let previous_weave_size = previous_block
            .map(|previous| parse_u128(&previous.weave_size, "previous block weave size"))
            .transpose()?
            .unwrap_or(0);
        ensure!(
            block_weave_size > previous_weave_size,
            "invalid block weave geometry"
        );
        let first_offset = end_offset
            .checked_sub(data_size - 1)
            .context("transaction offset underflow")?;
        ensure!(
            first_offset > previous_weave_size,
            "transaction starts before its block"
        );
        ensure!(
            end_offset <= block_weave_size,
            "transaction ends after its block"
        );

        let geometry = Geometry {
            tx_root: decode_fixed(&block.tx_root, "block tx_root")?,
            data_root: decode_fixed(&transaction.data_root, "transaction data root")?,
            block_weave_size,
            previous_weave_size,
            first_offset,
            end_offset,
            data_size,
        };

        let expected_len =
            usize::try_from(data_size).context("parent size exceeds addressable range")?;
        Ok(AuthenticatedRoot {
            id: id.to_owned(),
            bytes: Content::streamed(streaming::ChunkSource::new(self, geometry), expected_len),
            block_height: status.block_height,
            block_hash: decode_fixed::<48>(&block.hash, "verified block hash")?,
            stable_anchor,
            tags: transaction.tags,
            content_encoding,
            facts,
        })
    }

    async fn verified_block(&self, block: &database::IndexBlock) -> Result<BlockHeader> {
        let entry = BlockIndexEntry {
            hash: URL_SAFE_NO_PAD.encode(&block.hash),
            tx_root: URL_SAFE_NO_PAD.encode(&block.tx_root),
            weave_size: block.weave_size.to_string(),
        };
        let header = self.authenticate_block(&entry, block.height, None).await?;
        if let Some(previous) = &block.previous_hash {
            ensure!(
                decode_b64(&header.previous_block, "previous block")? == *previous,
                "block predecessor does not match trusted index"
            );
        }
        Ok(header)
    }

    async fn fetch_transaction(
        &self,
        id: &str,
        height: u64,
        remaining_bytes: &AtomicUsize,
    ) -> Result<(Transaction, transactions::VerifiedTransaction)> {
        decode_fixed::<32>(id, "transaction ID")?;
        let limit = self
            .config
            .max_data_size
            .min(self.config.max_memory_data_size)
            .checked_mul(4)
            .and_then(|size| size.checked_div(3))
            .and_then(|size| size.checked_add(MAX_JSON_BYTES))
            .context("transaction response limit overflow")?;
        let mut failures = Vec::new();
        for (source, trusted) in [
            (&self.config.trusted_node_url, true),
            (&self.config.archive_url, false),
        ] {
            if !trusted && source == &self.config.trusted_node_url {
                continue;
            }
            let result = async {
                let transaction = profiling::measure(profiling::Stage::TransactionFetch, async {
                    let response = self
                        .client
                        .get(endpoint(source, &format!("tx/{id}")))
                        .send()
                        .await?
                        .error_for_status()?;
                    if trusted {
                        ensure!(
                            response.url().origin() == Url::parse(source)?.origin(),
                            "trusted transaction source redirected outside its origin"
                        );
                    }
                    let value =
                        read_json_response_with_limit(response, limit, remaining_bytes, None)
                            .await?;
                    transactions::decode_transaction(value)
                })
                .await?;
                ensure!(
                    trusted || !transaction.owner.is_empty(),
                    "ECDSA transactions require trusted node metadata"
                );
                let expected_id = id.to_owned();
                let (mut transaction, verified) = cpu_work(move || {
                    let verified = verify_transaction(&transaction, &expected_id, height)?;
                    Ok((transaction, verified))
                })
                .await?;
                ensure!(
                    verified
                        .inline_data
                        .as_ref()
                        .is_none_or(|data| data.len() <= self.config.max_data_size),
                    "transaction exceeds configured size limit"
                );
                transaction.data = String::new();
                Ok::<_, anyhow::Error>((transaction, verified))
            }
            .await;
            match result {
                Ok(verified) => return Ok(verified),
                Err(error) => failures.push(format!("{source}: {error:#}")),
            }
        }
        bail!("transaction metadata unavailable: {}", failures.join("; "))
    }

    async fn verify_block_transactions(
        &self,
        block: BlockHeader,
        mut objects: Vec<database::ObjectMetadata>,
        fetched_bytes: usize,
        admission: Option<(&tokio::sync::Semaphore, &AtomicUsize)>,
    ) -> Result<(BlockHeader, Vec<database::ObjectMetadata>)> {
        ensure!(
            block.txs.len() <= MAX_BLOCK_TRANSACTIONS,
            "block transaction count exceeds verification limit"
        );
        let remaining = AtomicUsize::new(
            MAX_BLOCK_TRANSACTION_BYTES
                .checked_sub(fetched_bytes)
                .context("block transactions exceed aggregate response limit")?,
        );
        let remaining = admission.map_or(&remaining, |(_, remaining)| remaining);
        let known: HashSet<_> = objects
            .iter()
            .map(|object| URL_SAFE_NO_PAD.encode(&object.id))
            .collect();
        ensure!(
            known.len() == objects.len() && known.iter().all(|id| block.txs.contains(id)),
            "transaction ID is absent from authenticated block or duplicated"
        );
        objects.reserve(block.txs.len().saturating_sub(objects.len()));
        {
            let mut pending = block.txs.iter();
            let mut fetches = FuturesUnordered::new();
            loop {
                while fetches.len() < 32 {
                    let Some(id) = pending.next() else { break };
                    if !known.contains(id) {
                        fetches.push(async move {
                            let _permit = match admission {
                                Some((slots, _)) => Some(
                                    profiling::measure(
                                        profiling::Stage::TransactionAdmission,
                                        async {
                                            slots
                                                .acquire()
                                                .await
                                                .context("metadata fetch admission closed")
                                        },
                                    )
                                    .await?,
                                ),
                                None => None,
                            };
                            self.fetch_transaction(id, block.height, remaining).await
                        });
                    }
                }
                let Some(result) = fetches.next().await else {
                    break;
                };
                let (_, verified) = result?;
                objects.push(verified.metadata);
            }
        }
        cpu_work(move || {
            transactions::verify_block_data_root(&block, &mut objects)?;
            Ok((block, objects))
        })
        .await
    }

    async fn authenticate_block(
        &self,
        entry: &BlockIndexEntry,
        height: u64,
        transaction_id: Option<&str>,
    ) -> Result<BlockHeader> {
        let path = format!("block/hash/{}", entry.hash);
        let mut failures = Vec::new();

        match self
            .fetch_and_authenticate_block(
                self.client
                    .get(endpoint(&self.config.trusted_node_url, &path)),
                entry,
                height,
                transaction_id,
            )
            .await
        {
            Ok(block) => return Ok(block),
            Err(error) => failures.push(format!("{}: {error:#}", self.config.trusted_node_url)),
        }

        let mut attempted = HashSet::new();
        let discovered = self.peers.candidates(
            None,
            self.config.max_peer_attempts,
            &self.config.chunk_sources,
        );
        for source in std::iter::once(&self.config.archive_url)
            .chain(self.config.chunk_sources.iter())
            .chain(discovered.iter())
        {
            if source == &self.config.trusted_node_url || attempted.contains(source.as_str()) {
                continue;
            }
            if attempted.len() >= self.config.max_peer_attempts {
                break;
            }
            if attempted.len()
                >= self.config.max_peer_attempts - usize::from(!discovered.is_empty())
                && !discovered.iter().any(|peer| peer == source)
            {
                continue;
            }
            attempted.insert(source.as_str());

            match self
                .fetch_and_authenticate_block(
                    self.source_request(source, &path, &discovered),
                    entry,
                    height,
                    transaction_id,
                )
                .await
            {
                Ok(block) => {
                    self.peers.record_result(source, true);
                    return Ok(block);
                }
                Err(error) => {
                    self.peers.record_result(source, false);
                    failures.push(format!("{source}: {error:#}"));
                }
            }
        }

        bail!(
            "all bounded block header attempts failed: {}",
            failures.join("; ")
        )
    }

    async fn fetch_and_authenticate_block(
        &self,
        request: RequestBuilder,
        entry: &BlockIndexEntry,
        height: u64,
        transaction_id: Option<&str>,
    ) -> Result<BlockHeader> {
        let value = self.request_json(request).await?;
        let mut block = historical::decode_header(value)?;
        ensure!(
            block.height == height && block.indep_hash == entry.hash,
            "block header identifier mismatch"
        );
        if height < 422_250 {
            block = historical::verify_legacy_header(block, entry.clone(), &self.client).await?;
            if let Some(transaction_id) = transaction_id {
                ensure!(
                    block.txs.iter().any(|id| id == transaction_id),
                    "transaction ID is absent from authenticated block"
                );
            }
        } else {
            let entry = entry.clone();
            let transaction_id = transaction_id.map(str::to_owned);
            block = cpu_work(move || {
                verify_block_header(&block, &entry, height, transaction_id.as_deref())?;
                Ok(block)
            })
            .await?;
        }
        Ok(block)
    }

    fn source_request(&self, source: &str, path: &str, discovered: &[String]) -> RequestBuilder {
        let url = endpoint(source, path);
        if discovered.iter().any(|peer| peer == source) {
            self.peers.get(url)
        } else {
            self.client.get(url)
        }
    }

    async fn fetch_chunk(
        &self,
        source: &str,
        offset: u128,
    ) -> Result<(JsonChunk, Duration, Duration)> {
        let _permit = profiling::measure(profiling::Stage::ChunkAdmission, async {
            CHUNK_FETCHES
                .acquire()
                .await
                .context("chunk fetch admission closed")
        })
        .await?;
        let url = endpoint(source, &format!("chunk/{offset}"));
        let request = if self
            .config
            .chunk_sources
            .iter()
            .any(|configured| configured.trim_end_matches('/') == source.trim_end_matches('/'))
        {
            self.client.get(url)
        } else {
            self.peers.get(url)
        };
        let started = Instant::now();
        // Reserve time for fallback within the shared chunk deadline.
        let response = profiling::measure(profiling::Stage::ChunkHeaders, async {
            Ok(request
                .timeout((self.config.request_timeout / 4).min(CHUNK_PEER_DEADLINE))
                .send()
                .await?
                .error_for_status()?)
        })
        .await?;
        let headers = started.elapsed();
        let started = Instant::now();
        let chunk = read_chunk_response(response).await?;
        Ok((chunk, headers, started.elapsed()))
    }

    async fn get_json<T: DeserializeOwned>(&self, base: &str, path: &str) -> Result<T> {
        self.request_json(self.client.get(endpoint(base, path)))
            .await
    }

    async fn request_json<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = request
            .send()
            .await
            .context("HTTP request failed")?
            .error_for_status()
            .context("HTTP source rejected request")?;
        read_json_response(response).await
    }

    async fn request_optional_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
    ) -> Result<Option<T>> {
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return Ok(None),
        };
        if !response.status().is_success() {
            return Ok(None);
        }
        Ok(Some(read_json_response(response).await?))
    }
}

async fn read_json_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let remaining = AtomicUsize::new(MAX_JSON_BYTES);
    read_json_response_with_limit(response, MAX_JSON_BYTES, &remaining, None).await
}

async fn read_chunk_response(response: reqwest::Response) -> Result<JsonChunk> {
    let timer = profiling::start(profiling::Stage::ChunkBody);
    let remaining = AtomicUsize::new(MAX_JSON_BYTES);
    let result =
        read_json_response_with_limit(response, MAX_JSON_BYTES, &remaining, timer.as_ref()).await;
    if let Some(timer) = timer {
        timer.finish(result.is_ok(), 0);
    }
    result
}

async fn read_json_response_with_limit<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
    remaining_bytes: &AtomicUsize,
    timer: Option<&profiling::Timer>,
) -> Result<T> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit.min(remaining_bytes.load(Ordering::Relaxed)) as u64,
            "JSON response exceeds size limit"
        );
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("failed to read HTTP body")? {
        if let Some(timer) = timer {
            timer.add_bytes(chunk.len() as u64);
        }
        let remaining = remaining_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                Some(remaining.saturating_sub(chunk.len()))
            })
            .unwrap();
        ensure!(
            chunk.len() <= remaining && body.len().saturating_add(chunk.len()) <= limit,
            "JSON response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).context("source returned malformed JSON")
}

#[derive(Deserialize)]
struct NodeInfo {
    height: u64,
}

#[derive(Deserialize)]
struct TxStatus {
    block_height: u64,
    block_indep_hash: String,
}

fn decode_block_index(bytes: &[u8]) -> Result<Vec<TrustedBlockIndexEntry>> {
    let mut cursor = 0;
    let mut entries = Vec::new();
    while cursor < bytes.len() {
        let hash = URL_SAFE_NO_PAD.encode(take(bytes, &mut cursor, 48, "block hash")?);
        let weave_size_length =
            u16::from_be_bytes(take(bytes, &mut cursor, 2, "weave size length")?.try_into()?)
                as usize;
        ensure!(weave_size_length <= 16, "block weave size exceeds u128");
        let weave_size_bytes = take(bytes, &mut cursor, weave_size_length, "block weave size")?;
        let mut encoded_weave_size = [0; 16];
        encoded_weave_size[16 - weave_size_length..].copy_from_slice(weave_size_bytes);
        let weave_size = u128::from_be_bytes(encoded_weave_size);
        let tx_root_length = take(bytes, &mut cursor, 1, "tx_root length")?[0] as usize;
        ensure!(
            matches!(tx_root_length, 0 | 32),
            "invalid block tx_root length"
        );
        let tx_root =
            URL_SAFE_NO_PAD.encode(take(bytes, &mut cursor, tx_root_length, "block tx_root")?);
        entries.push(TrustedBlockIndexEntry {
            hash,
            tx_root,
            weave_size,
        });
    }
    Ok(entries)
}

struct TrustedBlockIndexEntry {
    hash: String,
    tx_root: String,
    weave_size: u128,
}

#[derive(Clone, Deserialize)]
struct BlockIndexEntry {
    tx_root: String,
    weave_size: String,
    hash: String,
}
#[derive(Deserialize, Default)]
struct BlockHeader {
    indep_hash: String,
    height: u64,
    previous_block: String,
    timestamp: u64,
    nonce: String,
    last_retarget: u64,
    diff: String,
    cumulative_diff: String,
    reward_pool: String,
    wallet_list: String,
    #[serde(skip)]
    legacy_wallets: Option<Vec<historical::LegacyWallet>>,
    #[serde(default)]
    hash_list: Vec<String>,
    hash_list_merkle: String,
    hash: String,
    block_size: String,
    weave_size: String,
    tx_root: String,
    reward_addr: String,
    tags: Vec<serde_json::Value>,
    txs: Vec<String>,
    packing_2_5_threshold: String,
    strict_data_split_threshold: String,
    usd_to_ar_rate: [String; 2],
    scheduled_usd_to_ar_rate: [String; 2],
    poa: BlockPoa,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    reward: String,
    #[serde(default)]
    recall_byte: String,
    #[serde(default)]
    recall_byte2: String,
    #[serde(default)]
    hash_preimage: String,
    #[serde(default)]
    reward_key: String,
    #[serde(default)]
    partition_number: u64,
    #[serde(default)]
    nonce_limiter_info: NonceLimiterInfo,
    #[serde(default)]
    previous_solution_hash: String,
    #[serde(default)]
    price_per_gib_minute: String,
    #[serde(default)]
    scheduled_price_per_gib_minute: String,
    #[serde(default)]
    reward_history_hash: String,
    #[serde(default)]
    block_time_history_hash: String,
    #[serde(default)]
    debt_supply: String,
    #[serde(default)]
    kryder_plus_rate_multiplier: String,
    #[serde(default)]
    kryder_plus_rate_multiplier_latch: String,
    #[serde(default)]
    denomination: String,
    #[serde(default)]
    redenomination_height: u64,
    #[serde(default)]
    double_signing_proof: serde_json::Value,
    #[serde(default)]
    previous_cumulative_diff: String,
    #[serde(default)]
    merkle_rebase_support_threshold: String,
    #[serde(default)]
    poa2: BlockPoa,
    #[serde(default)]
    chunk_hash: String,
    #[serde(default)]
    chunk2_hash: String,
    #[serde(default)]
    packing_difficulty: u8,
    #[serde(default)]
    unpacked_chunk_hash: String,
    #[serde(default)]
    unpacked_chunk2_hash: String,
    #[serde(default)]
    replica_format: u8,
}

#[derive(Deserialize, Default)]
struct BlockPoa {
    #[serde(default)]
    option: String,
    #[serde(default)]
    tx_path: String,
    #[serde(default)]
    data_path: String,
    #[serde(default)]
    chunk: String,
}

#[derive(Deserialize, Default)]
struct NonceLimiterInfo {
    #[serde(default)]
    output: String,
    #[serde(default)]
    global_step_number: u64,
    #[serde(default)]
    seed: String,
    #[serde(default)]
    next_seed: String,
    #[serde(default)]
    zone_upper_bound: u64,
    #[serde(default)]
    next_zone_upper_bound: u64,
    #[serde(default)]
    prev_output: String,
    #[serde(default)]
    checkpoints: Vec<String>,
    #[serde(default)]
    last_step_checkpoints: Vec<String>,
    #[serde(default)]
    vdf_difficulty: String,
    #[serde(default)]
    next_vdf_difficulty: String,
}

fn verify_block_header(
    block: &BlockHeader,
    entry: &BlockIndexEntry,
    height: u64,
    transaction_id: Option<&str>,
) -> Result<()> {
    ensure!(block.height == height, "block header height mismatch");
    let expected_hash = decode_fixed::<48>(&entry.hash, "trusted block hash")?;
    ensure!(
        decode_fixed::<48>(&block.indep_hash, "block indep_hash")? == expected_hash,
        "block header identifier mismatch"
    );
    ensure!(
        block_indep_hash(block)? == expected_hash,
        "block indep_hash verification failed"
    );
    if height >= 422_250 {
        let tx_root = decode_b64(&block.tx_root, "block tx_root")?;
        ensure!(
            matches!(tx_root.len(), 0 | 32)
                && tx_root == decode_b64(&entry.tx_root, "trusted block tx_root")?,
            "block tx_root does not match trusted index"
        );
    }
    ensure!(
        parse_u128(&block.weave_size, "block weave size")?
            == parse_u128(&entry.weave_size, "trusted block weave size")?,
        "block weave size does not match trusted index"
    );
    if let Some(transaction_id) = transaction_id {
        ensure!(
            block.txs.iter().any(|id| id == transaction_id),
            "transaction ID is absent from authenticated block"
        );
    }
    Ok(())
}

fn block_indep_hash(block: &BlockHeader) -> Result<[u8; 48]> {
    if block.height >= FORK_2_6_HEIGHT {
        let signed_hash = post_2_6_signed_hash(block)?;
        let signature = decode_b64(&block.signature, "block signature")?;
        Ok(sha384(&[&signed_hash, &signature]))
    } else if block.height >= FORK_2_5_HEIGHT {
        pre_2_6_indep_hash(block)
    } else {
        historical::indep_hash(block)
    }
}

fn pre_2_6_indep_hash(block: &BlockHeader) -> Result<[u8; 48]> {
    let core = [
        deep_hash_decimal(&block.height.to_string(), "block height")?,
        deep_hash_blob(&decode_b64(&block.previous_block, "previous block")?),
        deep_hash_blob(&decode_b64(&block.tx_root, "block tx_root")?),
        deep_hash_b64_list(&block.txs, "block transaction ID")?,
        deep_hash_decimal(&block.block_size, "block size")?,
        deep_hash_decimal(&block.weave_size, "block weave size")?,
        deep_hash_blob(&reward_address(&block.reward_addr, false)?),
        deep_hash_list(
            &block
                .tags
                .iter()
                .map(|tag| {
                    Ok(deep_hash_blob(&decode_b64(
                        tag.as_str().context("invalid block tag")?,
                        "block tag",
                    )?))
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    ];
    let mut base = Vec::with_capacity(14);
    for (value, label) in [
        (&block.usd_to_ar_rate[0], "USD rate dividend"),
        (&block.usd_to_ar_rate[1], "USD rate divisor"),
        (
            &block.scheduled_usd_to_ar_rate[0],
            "scheduled USD rate dividend",
        ),
        (
            &block.scheduled_usd_to_ar_rate[1],
            "scheduled USD rate divisor",
        ),
        (&block.packing_2_5_threshold, "packing threshold"),
        (
            &block.strict_data_split_threshold,
            "strict data split threshold",
        ),
    ] {
        base.push(deep_hash_decimal(value, label)?);
    }
    base.extend_from_slice(&core);
    let base_hash = deep_hash_list(&base);
    let data_segment = deep_hash_list(&[
        deep_hash_blob(&base_hash),
        deep_hash_decimal(&block.timestamp.to_string(), "block timestamp")?,
        deep_hash_decimal(&block.last_retarget.to_string(), "last retarget")?,
        deep_hash_decimal(&block.diff, "block difficulty")?,
        deep_hash_decimal(&block.cumulative_diff, "cumulative difficulty")?,
        deep_hash_decimal(&block.reward_pool, "reward pool")?,
        deep_hash_blob(&decode_b64(&block.wallet_list, "wallet list")?),
        deep_hash_blob(&decode_b64(&block.hash_list_merkle, "hash_list_merkle")?),
    ]);
    let poa = deep_hash_list(&[
        deep_hash_decimal(&block.poa.option, "proof option")?,
        deep_hash_blob(&decode_b64(&block.poa.tx_path, "block tx_path")?),
        deep_hash_blob(&decode_b64(&block.poa.data_path, "block data_path")?),
        deep_hash_blob(&decode_b64(&block.poa.chunk, "block chunk")?),
    ]);

    Ok(deep_hash_list(&[
        deep_hash_blob(&data_segment),
        deep_hash_blob(&decode_b64(&block.hash, "block hash")?),
        deep_hash_blob(&decode_b64(&block.nonce, "block nonce")?),
        poa,
    ]))
}

fn post_2_6_signed_hash(block: &BlockHeader) -> Result<[u8; 32]> {
    let nonce = decode_b64(&block.nonce, "block nonce")?;
    ensure!(!nonce.is_empty(), "block nonce is empty");
    let nonce_start = nonce
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(nonce.len() - 1);
    let nonce = &nonce[nonce_start..];
    let nonce_info = &block.nonce_limiter_info;
    let mut segment = Vec::new();

    append_b64(&mut segment, &block.previous_block, 1, "previous block")?;
    append_u64(&mut segment, block.timestamp, 1)?;
    append_bytes(&mut segment, nonce, 2)?;
    append_u64(&mut segment, block.height, 1)?;
    append_decimal(&mut segment, &block.diff, 2, "block difficulty")?;
    append_decimal(
        &mut segment,
        &block.cumulative_diff,
        2,
        "cumulative difficulty",
    )?;
    append_u64(&mut segment, block.last_retarget, 1)?;
    append_b64(&mut segment, &block.hash, 1, "block hash")?;
    append_decimal(&mut segment, &block.block_size, 2, "block size")?;
    append_decimal(&mut segment, &block.weave_size, 2, "block weave size")?;
    append_bytes(&mut segment, &reward_address(&block.reward_addr, true)?, 1)?;
    append_b64(&mut segment, &block.tx_root, 1, "block tx_root")?;
    append_b64(&mut segment, &block.wallet_list, 1, "wallet list")?;
    append_b64(&mut segment, &block.hash_list_merkle, 1, "hash_list_merkle")?;
    append_decimal(&mut segment, &block.reward_pool, 1, "reward pool")?;
    append_decimal(
        &mut segment,
        &block.packing_2_5_threshold,
        1,
        "packing threshold",
    )?;
    append_decimal(
        &mut segment,
        &block.strict_data_split_threshold,
        1,
        "strict data split threshold",
    )?;
    append_decimal(
        &mut segment,
        &block.usd_to_ar_rate[0],
        1,
        "USD rate dividend",
    )?;
    append_decimal(
        &mut segment,
        &block.usd_to_ar_rate[1],
        1,
        "USD rate divisor",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_usd_to_ar_rate[0],
        1,
        "scheduled USD rate dividend",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_usd_to_ar_rate[1],
        1,
        "scheduled USD rate divisor",
    )?;
    append_size(&mut segment, block.tags.len(), 2)?;
    for tag in block.tags.iter().rev() {
        append_b64(
            &mut segment,
            tag.as_str().context("invalid block tag")?,
            2,
            "block tag",
        )?;
    }
    append_b64_list(&mut segment, &block.txs, 2, 1, "block transaction ID")?;
    append_decimal(&mut segment, &block.reward, 1, "block reward")?;
    append_decimal(&mut segment, &block.recall_byte, 2, "recall byte")?;
    append_b64(&mut segment, &block.hash_preimage, 1, "hash preimage")?;
    append_optional_decimal(&mut segment, &block.recall_byte2, 2, "second recall byte")?;
    append_b64(&mut segment, &block.reward_key, 2, "reward key")?;
    append_u64(&mut segment, block.partition_number, 1)?;
    append_fixed_b64(&mut segment, &nonce_info.output, 32, "VDF output")?;
    append_fixed_u64(&mut segment, nonce_info.global_step_number, 8)?;
    append_fixed_b64(&mut segment, &nonce_info.seed, 48, "VDF seed")?;
    append_fixed_b64(&mut segment, &nonce_info.next_seed, 48, "next VDF seed")?;
    append_fixed_u64(&mut segment, nonce_info.zone_upper_bound, 32)?;
    append_fixed_u64(&mut segment, nonce_info.next_zone_upper_bound, 32)?;
    append_b64(
        &mut segment,
        &nonce_info.prev_output,
        1,
        "previous VDF output",
    )?;
    append_hashes(&mut segment, &nonce_info.checkpoints, "VDF checkpoint")?;
    append_hashes(
        &mut segment,
        &nonce_info.last_step_checkpoints,
        "last VDF checkpoint",
    )?;
    append_b64(
        &mut segment,
        &block.previous_solution_hash,
        1,
        "previous solution hash",
    )?;
    append_decimal(
        &mut segment,
        &block.price_per_gib_minute,
        1,
        "price per GiB minute",
    )?;
    append_decimal(
        &mut segment,
        &block.scheduled_price_per_gib_minute,
        1,
        "scheduled price per GiB minute",
    )?;
    append_fixed_b64(
        &mut segment,
        &block.reward_history_hash,
        32,
        "reward history hash",
    )?;
    append_decimal(&mut segment, &block.debt_supply, 1, "debt supply")?;
    append_fixed_decimal(
        &mut segment,
        &block.kryder_plus_rate_multiplier,
        3,
        "Kryder+ rate multiplier",
    )?;
    append_fixed_decimal(
        &mut segment,
        &block.kryder_plus_rate_multiplier_latch,
        1,
        "Kryder+ rate multiplier latch",
    )?;
    append_fixed_decimal(&mut segment, &block.denomination, 3, "denomination")?;
    append_u64(&mut segment, block.redenomination_height, 1)?;
    append_double_signing_proof(&mut segment, &block.double_signing_proof)?;
    append_decimal(
        &mut segment,
        &block.previous_cumulative_diff,
        2,
        "previous cumulative difficulty",
    )?;

    if block.height >= FORK_2_7_HEIGHT {
        append_decimal(
            &mut segment,
            &block.merkle_rebase_support_threshold,
            2,
            "Merkle rebase threshold",
        )?;
        append_b64(&mut segment, &block.poa.data_path, 3, "block data_path")?;
        append_b64(&mut segment, &block.poa.tx_path, 3, "block tx_path")?;
        append_b64(
            &mut segment,
            &block.poa2.data_path,
            3,
            "second block data_path",
        )?;
        append_b64(&mut segment, &block.poa2.tx_path, 3, "second block tx_path")?;
        append_fixed_b64(&mut segment, &block.chunk_hash, 32, "chunk hash")?;
        append_optional_b64(&mut segment, &block.chunk2_hash, 1, "second chunk hash")?;
        append_fixed_b64(
            &mut segment,
            &block.block_time_history_hash,
            32,
            "block time history hash",
        )?;
        append_decimal(
            &mut segment,
            &nonce_info.vdf_difficulty,
            1,
            "VDF difficulty",
        )?;
        append_decimal(
            &mut segment,
            &nonce_info.next_vdf_difficulty,
            1,
            "next VDF difficulty",
        )?;
    }
    if block.height >= FORK_2_8_HEIGHT {
        segment.push(block.packing_difficulty);
        append_optional_b64(
            &mut segment,
            &block.unpacked_chunk_hash,
            1,
            "unpacked chunk hash",
        )?;
        append_optional_b64(
            &mut segment,
            &block.unpacked_chunk2_hash,
            1,
            "second unpacked chunk hash",
        )?;
    }
    if block.height >= FORK_2_9_HEIGHT {
        segment.push(block.replica_format);
    }

    Ok(sha256(&[&segment]))
}

fn append_size(output: &mut Vec<u8>, value: usize, bytes: usize) -> Result<()> {
    ensure!(
        bytes > 0 && bytes <= size_of::<u128>(),
        "invalid size prefix width"
    );
    let max = 1u128.checked_shl((bytes * 8) as u32).unwrap_or(u128::MAX);
    ensure!((value as u128) < max, "encoded size exceeds prefix width");
    let encoded = (value as u128).to_be_bytes();
    let prefix = &encoded[size_of::<u128>() - bytes..];
    output.extend_from_slice(prefix);
    Ok(())
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8], size_bytes: usize) -> Result<()> {
    let max = 1u128
        .checked_shl((size_bytes * 8) as u32)
        .unwrap_or(u128::MAX);
    ensure!((value.len() as u128) < max, "value exceeds size prefix");
    append_size(output, value.len(), size_bytes)?;
    output.extend_from_slice(value);
    Ok(())
}

fn append_b64(output: &mut Vec<u8>, value: &str, size_bytes: usize, label: &str) -> Result<()> {
    append_bytes(output, &decode_b64(value, label)?, size_bytes)
}

fn append_optional_b64(
    output: &mut Vec<u8>,
    value: &str,
    size_bytes: usize,
    label: &str,
) -> Result<()> {
    if value.is_empty() {
        append_bytes(output, &[], size_bytes)
    } else {
        append_b64(output, value, size_bytes, label)
    }
}

fn append_decimal(output: &mut Vec<u8>, value: &str, size_bytes: usize, label: &str) -> Result<()> {
    let mut encoded = parse_biguint(value, label)?.to_bytes_be();
    if encoded.is_empty() {
        encoded.push(0);
    }
    append_bytes(output, &encoded, size_bytes)
}

fn append_optional_decimal(
    output: &mut Vec<u8>,
    value: &str,
    size_bytes: usize,
    label: &str,
) -> Result<()> {
    if value.is_empty() {
        append_bytes(output, &[], size_bytes)
    } else {
        append_decimal(output, value, size_bytes, label)
    }
}

fn append_u64(output: &mut Vec<u8>, value: u64, size_bytes: usize) -> Result<()> {
    append_decimal(output, &value.to_string(), size_bytes, "integer")
}

fn append_fixed_decimal(
    output: &mut Vec<u8>,
    value: &str,
    bytes: usize,
    label: &str,
) -> Result<()> {
    let encoded = parse_biguint(value, label)?.to_bytes_be();
    ensure!(encoded.len() <= bytes, "{label} exceeds fixed width");
    output.resize(output.len() + bytes - encoded.len(), 0);
    output.extend_from_slice(&encoded);
    Ok(())
}

fn append_fixed_u64(output: &mut Vec<u8>, value: u64, bytes: usize) -> Result<()> {
    append_fixed_decimal(output, &value.to_string(), bytes, "integer")
}

fn append_fixed_b64(output: &mut Vec<u8>, value: &str, bytes: usize, label: &str) -> Result<()> {
    let decoded = decode_b64(value, label)?;
    ensure!(decoded.len() == bytes, "invalid {label} length");
    output.extend_from_slice(&decoded);
    Ok(())
}

fn append_b64_list(
    output: &mut Vec<u8>,
    values: &[String],
    list_size_bytes: usize,
    element_size_bytes: usize,
    label: &str,
) -> Result<()> {
    append_size(output, values.len(), list_size_bytes)?;
    for value in values.iter().rev() {
        append_b64(output, value, element_size_bytes, label)?;
    }
    Ok(())
}

fn append_hashes(output: &mut Vec<u8>, values: &[String], label: &str) -> Result<()> {
    append_size(output, values.len(), 2)?;
    for value in values {
        append_fixed_b64(output, value, 32, label)?;
    }
    Ok(())
}

fn append_double_signing_proof(output: &mut Vec<u8>, proof: &serde_json::Value) -> Result<()> {
    match proof {
        serde_json::Value::Null => output.push(0),
        serde_json::Value::Object(fields) if fields.is_empty() => output.push(0),
        _ => bail!("non-empty double-signing proofs are unsupported"),
    }
    Ok(())
}

fn reward_address(value: &str, post_2_6: bool) -> Result<Vec<u8>> {
    if value == "unclaimed" {
        Ok(if post_2_6 {
            Vec::new()
        } else {
            b"unclaimed".to_vec()
        })
    } else {
        decode_b64(value, "reward address")
    }
}

fn parse_biguint(value: &str, label: &str) -> Result<BigUint> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid {label}: {value}"
    );
    BigUint::parse_bytes(value.as_bytes(), 10).with_context(|| format!("invalid {label}: {value}"))
}

fn deep_hash_decimal(value: &str, label: &str) -> Result<[u8; 48]> {
    Ok(deep_hash_blob(
        parse_biguint(value, label)?.to_str_radix(10).as_bytes(),
    ))
}

fn deep_hash_b64_list(values: &[String], label: &str) -> Result<[u8; 48]> {
    let hashes = values
        .iter()
        .map(|value| Ok(deep_hash_blob(&decode_b64(value, label)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(deep_hash_list(&hashes))
}

fn checked_data_size(data_size: u128, maximum: usize) -> Result<usize> {
    ensure!(
        data_size <= maximum as u128,
        "transaction exceeds configured data size limit"
    );
    usize::try_from(data_size).context("transaction is too large")
}

#[derive(Deserialize)]
struct TxOffset {
    size: String,
    offset: String,
}

#[derive(Deserialize)]
struct Transaction {
    format: u8,
    id: String,
    last_tx: String,
    owner: String,
    tags: Vec<Tag>,
    target: String,
    quantity: String,
    #[serde(default)]
    data_size: String,
    #[serde(default)]
    data_root: String,
    reward: String,
    signature: String,
    #[serde(default)]
    data: String,
    #[serde(default)]
    denomination: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Tag {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct GraphQlResponse {
    data: GraphQlData,
}

#[derive(Deserialize)]
struct GraphQlData {
    transactions: GraphQlTransactions,
}

#[derive(Deserialize)]
struct GraphQlTransactions {
    edges: Vec<GraphQlEdge>,
}

#[derive(Deserialize)]
struct GraphQlEdge {
    node: GraphQlNode,
}

#[derive(Deserialize)]
struct GraphQlNode {
    id: String,
    #[serde(rename = "bundledIn")]
    bundled_in: Option<GraphQlBundledIn>,
    data: GraphQlNodeData,
}

#[derive(Deserialize)]
struct GraphQlBundledIn {
    id: String,
}

#[derive(Deserialize)]
struct GraphQlNodeData {
    size: String,
}

enum BundleHint {
    Indexed(database::IndexedBundle),
    External {
        parent_id: String,
        data_size: String,
    },
}

#[derive(Deserialize)]
struct JsonChunk {
    chunk: String,
    data_path: String,
    tx_path: String,
}

#[derive(Clone, Copy)]
struct Geometry {
    tx_root: [u8; 32],
    data_root: [u8; 32],
    block_weave_size: u128,
    previous_weave_size: u128,
    first_offset: u128,
    end_offset: u128,
    data_size: u128,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct BlockGeometry {
    tx_root: [u8; 32],
    block_weave_size: u128,
    previous_weave_size: u128,
}

struct ProvenChunk {
    bytes: Vec<u8>,
    chunk: String,
    data_path: String,
    tx_path: String,
    transaction: TxPath,
    data: DataPath,
    relative_offset: u128,
    first_offset: u128,
}

fn verify_chunk_range(
    chunk: JsonChunk,
    absolute_offset: u128,
    relative_offset: u128,
    geometry: &Geometry,
) -> Result<ProvenChunk> {
    let proof = verify_chunk_proof(
        chunk,
        absolute_offset,
        &BlockGeometry {
            tx_root: geometry.tx_root,
            block_weave_size: geometry.block_weave_size,
            previous_weave_size: geometry.previous_weave_size,
        },
    )?;
    ensure!(
        proof.transaction.data_root == geometry.data_root,
        "tx_path data root mismatch"
    );
    ensure!(
        proof.transaction.end_offset == geometry.end_offset,
        "tx_path end offset mismatch"
    );
    ensure!(
        proof.transaction.size == geometry.data_size,
        "tx_path transaction size mismatch"
    );
    ensure!(
        proof.first_offset == geometry.first_offset,
        "tx_path start offset mismatch"
    );
    ensure!(
        proof.relative_offset == relative_offset,
        "tx_path relative offset mismatch"
    );
    Ok(proof)
}

fn verify_chunk_proof(
    chunk: JsonChunk,
    absolute_offset: u128,
    geometry: &BlockGeometry,
) -> Result<ProvenChunk> {
    let JsonChunk {
        chunk,
        data_path,
        tx_path,
    } = chunk;
    let bytes = decode_b64(&chunk, "chunk bytes")?;
    let data_path_bytes = decode_b64(&data_path, "data_path")?;
    let tx_path_bytes = decode_b64(&tx_path, "tx_path")?;
    ensure!(
        bytes.len() <= MAX_CHUNK_SIZE as usize,
        "chunk exceeds protocol limit"
    );
    ensure!(
        data_path_bytes.len() <= MAX_PROOF_BYTES,
        "data_path exceeds size limit"
    );
    ensure!(
        tx_path_bytes.len() <= MAX_PROOF_BYTES,
        "tx_path exceeds size limit"
    );

    let transaction = validate_tx_path(
        &geometry.tx_root,
        absolute_offset,
        geometry.block_weave_size,
        geometry.previous_weave_size,
        &tx_path_bytes,
    )?;
    let first_offset = transaction
        .start_bound
        .checked_add(1)
        .context("transaction start offset overflow")?;
    let relative_offset = absolute_offset
        .checked_sub(first_offset)
        .context("requested offset precedes transaction")?;
    let data = validate_data_path(
        &transaction.data_root,
        transaction.size,
        relative_offset,
        absolute_offset,
        &data_path_bytes,
    )?;
    ensure!(
        data.start <= relative_offset && relative_offset < data.end,
        "data_path does not contain requested offset"
    );
    ensure!(
        data.end <= transaction.size,
        "data_path ends after transaction"
    );
    let proven_size = usize::try_from(data.end - data.start).context("chunk size overflow")?;
    ensure!(
        bytes.len() == proven_size,
        "chunk length does not match data_path"
    );
    ensure!(
        sha256(&[&bytes]) == data.data_hash,
        "chunk hash does not match data_path"
    );

    Ok(ProvenChunk {
        bytes,
        chunk,
        data_path,
        tx_path,
        transaction,
        data,
        relative_offset,
        first_offset,
    })
}

fn content_type(tags: &[Tag]) -> Result<String> {
    for tag in tags {
        if decode_b64(&tag.name, "tag name")? == b"Content-Type" {
            let value = decode_b64(&tag.value, "Content-Type tag")?;
            let value = HeaderValue::from_bytes(&value)
                .context("invalid Content-Type tag")?
                .to_str()
                .context("non-ASCII Content-Type tag")?
                .to_owned();
            return Ok(value);
        }
    }
    Ok("application/octet-stream".to_owned())
}

fn response_content_type(value: String) -> String {
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let has_charset = parts.any(|parameter| {
        parameter
            .split_once('=')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("charset"))
    });

    if !has_charset
        && (media_type.starts_with("text/")
            || media_type == "application/json"
            || media_type.ends_with("+json"))
    {
        format!("{value}; charset=utf-8")
    } else {
        value
    }
}

fn response_content_encoding(value: Option<String>) -> Result<Option<String>> {
    if let Some(value) = &value {
        HeaderValue::from_bytes(value.as_bytes())
            .context("invalid Content-Encoding tag")?
            .to_str()
            .context("non-ASCII Content-Encoding tag")?;
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BundleFormat {
    Binary,
    Json,
}

impl BundleFormat {
    fn from_pairs<'a>(tags: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> Result<Self> {
        let (mut binary, mut json, mut v1, mut v2) = (false, false, false, false);
        for (name, value) in tags {
            binary |= name == b"Bundle-Format" && value == b"binary";
            json |= name == b"Bundle-Format" && value == b"json";
            v1 |= name == b"Bundle-Version" && value == b"1.0.0";
            v2 |= name == b"Bundle-Version" && value == b"2.0.0";
        }
        match (binary && v2, json && v1) {
            (true, false) => Ok(Self::Binary),
            (false, true) => Ok(Self::Json),
            _ => bail!("unsupported or ambiguous bundle format/version"),
        }
    }
}

fn require_bundle_tags(tags: &[Tag]) -> Result<BundleFormat> {
    let decoded = tags
        .iter()
        .map(|tag| {
            Ok((
                decode_b64(&tag.name, "tag name")?,
                decode_b64(&tag.value, "tag value")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    BundleFormat::from_pairs(
        decoded
            .iter()
            .map(|(name, value)| (name.as_slice(), value.as_slice())),
    )
}

struct VerifiedItem {
    data: content::Content,
    data_offset: usize,
    item_size: usize,
    body_hash: [u8; 32],
    signature_type: u16,
    signature: axum::body::Bytes,
    owner: axum::body::Bytes,
    target: axum::body::Bytes,
    anchor: axum::body::Bytes,
    tags: Vec<ItemTag>,
}

impl VerifiedItem {
    fn text_tag(&self, name: &[u8]) -> Option<String> {
        transactions::optional_text_tag(
            self.tags
                .iter()
                .map(|tag| (tag.name.as_ref(), tag.value.as_ref())),
            name,
        )
    }

    fn bundle_format(&self) -> Option<BundleFormat> {
        BundleFormat::from_pairs(
            self.tags
                .iter()
                .map(|tag| (tag.name.as_ref(), tag.value.as_ref())),
        )
        .ok()
    }

    fn metadata(&self, id: &[u8; 32]) -> database::ObjectMetadata {
        let tags = self
            .tags
            .iter()
            .map(|tag| (tag.name.to_vec(), tag.value.to_vec()))
            .collect::<Vec<_>>();
        database::ObjectMetadata {
            id: id.to_vec(),
            kind: 1,
            signature: self.signature.to_vec(),
            anchor: self.anchor.to_vec(),
            owner_address: sha256(&[&self.owner]).to_vec(),
            owner_public_key: self.owner.to_vec(),
            target: self.target.to_vec(),
            data_size: self.data.len() as u128,
            content_type: self.text_tag(b"Content-Type"),
            content_encoding: self.text_tag(b"Content-Encoding"),
            signature_type: self.signature_type as i16,
            format: None,
            quantity: None,
            reward: None,
            denomination: None,
            data_root: None,
            tags,
        }
    }
}

struct ItemTag {
    name: axum::body::Bytes,
    value: axum::body::Bytes,
}

enum BundleEntry {
    Binary {
        id: [u8; 32],
        bytes: content::Content,
        offset: usize,
    },
    Json(json_bundle::JsonEntry),
}

impl BundleEntry {
    fn id(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Binary { id, .. } => Some(id),
            Self::Json(entry) => entry.id.as_ref(),
        }
    }

    fn offset(&self) -> usize {
        match self {
            Self::Binary { offset, .. } => *offset,
            Self::Json(entry) => entry.offset,
        }
    }

    fn is_json(&self) -> bool {
        matches!(self, Self::Json(_))
    }

    async fn verify(self, materialize: Option<&Gateway>) -> Result<Option<VerifiedItem>> {
        match self {
            Self::Binary { id, mut bytes, .. } => {
                if let Some(gateway) = materialize {
                    ensure!(
                        bytes.len()
                            <= gateway
                                .config
                                .max_data_size
                                .saturating_add(MAX_DATA_ITEM_HEADER_BYTES),
                        "data item exceeds configured data size limit"
                    );
                    bytes = bytes
                        .materialize(
                            gateway.config.max_memory_data_size,
                            Arc::clone(&gateway.spool_budget),
                        )
                        .await?
                        .0;
                }
                Ok(Some(verify_data_item(bytes, &id).await?))
            }
            Self::Json(entry) => {
                if let Some(gateway) = materialize {
                    ensure!(
                        entry.size
                            <= gateway
                                .config
                                .max_data_size
                                .saturating_mul(8)
                                .saturating_add(MAX_JSON_BYTES),
                        "JSON item exceeds configured data size limit"
                    );
                }
                let Some(mut item) = entry.verify().await? else {
                    return Ok(None);
                };
                if let Some(gateway) = materialize {
                    checked_data_size(item.data.len() as u128, gateway.config.max_data_size)?;
                    item.data = item
                        .data
                        .materialize(
                            gateway.config.max_memory_data_size,
                            Arc::clone(&gateway.spool_budget),
                        )
                        .await?
                        .0;
                }
                Ok(Some(item))
            }
        }
    }
}

enum BundleItems {
    Binary(BinaryBundleItems),
    Json(json_bundle::JsonBundle),
}

impl BundleItems {
    async fn new(bundle: content::Content, format: BundleFormat) -> Result<Self> {
        match format {
            BundleFormat::Binary => Ok(Self::Binary(BinaryBundleItems::new(bundle).await?)),
            BundleFormat::Json => Ok(Self::Json(json_bundle::JsonBundle::new(bundle).await?)),
        }
    }

    async fn checked(bundle: content::Content, format: BundleFormat) -> Result<Self> {
        let mut framing = Self::new(bundle.clone(), format).await?;
        let mut count = 0;
        while framing.next().await?.is_some() {
            count += 1;
            if count % 256 == 0 {
                tokio::task::yield_now().await;
            }
        }
        Self::new(bundle, format).await
    }

    async fn next(&mut self) -> Result<Option<BundleEntry>> {
        match self {
            Self::Binary(items) => items.next().await,
            Self::Json(items) => Ok(items.next().await?.map(BundleEntry::Json)),
        }
    }
}

struct BinaryBundleItems {
    bundle: content::Content,
    remaining: usize,
    cursor: usize,
    item_start: usize,
    table: axum::body::Bytes,
}

impl BinaryBundleItems {
    async fn new(bundle: content::Content) -> Result<Self> {
        let header = bundle
            .read_at(0, 32)
            .await
            .context("bundle item count is truncated")?;
        let count = read_u256_usize(&header, "bundle item count")?;
        let cursor = 32;
        ensure!(
            count <= (bundle.len() - cursor) / BUNDLE_ENTRY_SIZE,
            "bundle item table exceeds parent bounds"
        );
        let item_start = cursor + count * BUNDLE_ENTRY_SIZE;
        ensure!(
            count != 0 || item_start == bundle.len(),
            "empty bundle contains trailing data"
        );
        Ok(Self {
            bundle,
            remaining: count,
            cursor,
            item_start,
            table: axum::body::Bytes::new(),
        })
    }

    async fn next(&mut self) -> Result<Option<BundleEntry>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        if self.table.is_empty() {
            self.table = self
                .bundle
                .read_at(self.cursor, self.remaining.min(256) * BUNDLE_ENTRY_SIZE)
                .await?;
        }
        let header = self.table.split_to(BUNDLE_ENTRY_SIZE);
        self.cursor += BUNDLE_ENTRY_SIZE;
        let size = read_u256_usize(&header[..32], "bundle item size")?;
        ensure!(size > 0, "bundle contains an empty item");
        let id = header[32..]
            .try_into()
            .context("invalid bundle item ID length")?;
        let end = self
            .item_start
            .checked_add(size)
            .context("bundle item offset overflow")?;
        ensure!(
            end <= self.bundle.len(),
            "bundle item exceeds parent bounds"
        );
        self.remaining -= 1;
        if self.remaining == 0 {
            ensure!(
                end == self.bundle.len(),
                "bundle item sizes do not consume the parent"
            );
        }
        let entry = BundleEntry::Binary {
            id,
            bytes: self.bundle.slice(self.item_start..end)?,
            offset: self.item_start,
        };
        self.item_start = end;
        Ok(Some(entry))
    }
}

async fn verify_bundle_item(
    bundle: content::Content,
    format: BundleFormat,
    expected_id: &[u8; 32],
    expected_offset: Option<u128>,
    materialize: Option<&Gateway>,
) -> Result<(VerifiedItem, usize)> {
    let mut entries = BundleItems::new(bundle, format).await?;
    let mut found = None;
    let mut scanned = 0;
    while let Some(entry) = entries.next().await? {
        let offset = entry.offset();
        if entry.id() == Some(expected_id)
            && expected_offset.is_none_or(|expected| expected == offset as u128)
            && found.is_none()
        {
            // Invalid JSON occurrences do not hide a later valid copy of the same ID.
            found = entry.verify(materialize).await?.map(|item| (item, offset));
        }
        scanned += 1;
        if scanned % 256 == 0 {
            tokio::task::yield_now().await;
        }
    }
    found.context("valid data item is absent from verified parent at the expected offset")
}

async fn verify_indexed_bundle(
    root: content::Content,
    mut format: BundleFormat,
    expected_id: &[u8; 32],
    indexed: &database::IndexedBundle,
    materialize: Option<&Gateway>,
) -> Result<VerifiedItem> {
    ensure!(
        indexed.root_id.len() == 32 && (1..=MAX_BUNDLE_DEPTH).contains(&indexed.locations.len()),
        "invalid indexed bundle path"
    );
    let mut parent = root;
    let mut parent_id = indexed.root_id.as_slice();
    let mut path = Vec::with_capacity(indexed.locations.len());
    for (depth, location) in indexed.locations.iter().enumerate() {
        ensure!(
            location.parent_id == parent_id && location.json == (format == BundleFormat::Json),
            "indexed bundle parent or format does not match authenticated path"
        );
        let id = location
            .id
            .as_slice()
            .try_into()
            .context("invalid indexed item ID")?;
        let (item, offset) = verify_bundle_item(
            parent,
            format,
            id,
            Some(location.item_offset),
            materialize.filter(|_| depth + 1 == indexed.locations.len()),
        )
        .await?;
        path.push(offset as u128);
        ensure!(
            location.path == path
                && location.data_offset == item.data_offset as u128
                && location.item_size == item.item_size as u128,
            "indexed bundle path, offsets or size do not match authenticated item"
        );
        if depth + 1 == indexed.locations.len() {
            ensure!(id == expected_id, "indexed path ends at a different item");
            ensure!(
                item.data.len() as u128 == indexed.data_size,
                "indexed data size does not match authenticated payload"
            );
            return Ok(item);
        }
        format = item
            .bundle_format()
            .context("indexed ancestor is not a supported bundle")?;
        parent = item.data;
        parent_id = &location.id;
        tokio::task::yield_now().await;
    }
    bail!("indexed bundle path is empty")
}

fn data_item_signature_sizes(signature_type: u16) -> Result<(usize, usize)> {
    match signature_type {
        1 => Ok((512, 512)),
        2 => Ok((64, 32)),
        3 => Ok((65, 65)),
        4 | 5 => Ok((64, 32)),
        6 => Ok((2_052, 1_025)),
        7 => Ok((65, 42)),
        _ => bail!("unsupported ANS-104 signature type {signature_type}"),
    }
}

fn data_item_signature_payload(
    signature_type: u16,
    owner: &[u8],
    target: &[u8],
    anchor: &[u8],
    raw_tags: &[u8],
    data_hash: [u8; 48],
) -> [u8; 48] {
    let signature_type = signature_type.to_string();
    deep_hash_list(&[
        deep_hash_blob(b"dataitem"),
        deep_hash_blob(b"1"),
        deep_hash_blob(signature_type.as_bytes()),
        deep_hash_blob(owner),
        deep_hash_blob(target),
        deep_hash_blob(anchor),
        deep_hash_blob(raw_tags),
        data_hash,
    ])
}

async fn verify_data_item(item: content::Content, expected_id: &[u8; 32]) -> Result<VerifiedItem> {
    let item_size = item.len();
    let header = item
        .read_at(0, item.len().min(MAX_DATA_ITEM_HEADER_BYTES))
        .await?;
    // Early binary items omit the type prefix. The signature hash selects
    // their layout even when the first signature bytes resemble a modern type.
    let legacy = header
        .get(..512)
        .is_some_and(|signature| sha256(&[signature]) == *expected_id);
    let mut cursor = 0;
    let signature_type = if legacy {
        1
    } else {
        read_le_u16(&header, &mut cursor, "data item signature type")?
    };
    let (signature_size, owner_size) = data_item_signature_sizes(signature_type)?;
    let signature = take(&header, &mut cursor, signature_size, "data item signature")?;
    let owner = take(&header, &mut cursor, owner_size, "data item owner")?;
    let target = read_optional_32(&header, &mut cursor, "data item target")?;
    let anchor = read_optional_32(&header, &mut cursor, "data item anchor")?;
    let tag_count = usize::try_from(read_le_u64(&header, &mut cursor, "data item tag count")?)
        .context("data item tag count is too large")?;
    ensure!(
        tag_count <= MAX_DATA_ITEM_TAGS,
        "data item tag count exceeds limit"
    );
    let tag_bytes_len = usize::try_from(read_le_u64(
        &header,
        &mut cursor,
        "data item tag byte length",
    )?)
    .context("data item tag byte length is too large")?;
    ensure!(
        tag_bytes_len <= MAX_DATA_ITEM_TAG_BYTES,
        "data item tag bytes exceed limit"
    );
    let raw_tags = take(&header, &mut cursor, tag_bytes_len, "data item tags")?;
    let tags = parse_avro_tags(&header.slice_ref(raw_tags), tag_count)?;
    let data = item.slice(cursor..item.len())?;

    ensure!(
        sha256(&[signature]) == *expected_id,
        "data item ID is not the signature hash"
    );
    let (body_hash, body_sha384) = data.hashes().await?;
    let data_hash = sha384(&[
        &sha384(&[format!("blob{}", data.len()).as_bytes()]),
        &body_sha384,
    ]);
    let payload = if legacy {
        deep_hash_list(&[
            deep_hash_blob(b"dataitem"),
            deep_hash_blob(b"1"),
            deep_hash_blob(owner),
            deep_hash_blob(target),
            deep_hash_blob(anchor),
            deep_hash_blob(raw_tags),
            data_hash,
        ])
    } else {
        data_item_signature_payload(signature_type, owner, target, anchor, raw_tags, data_hash)
    };
    let signature_bytes = header.slice_ref(signature);
    let owner_bytes = header.slice_ref(owner);
    let target_bytes = header.slice_ref(target);
    let anchor_bytes = header.slice_ref(anchor);
    let (signature_bytes, owner_bytes) = cpu_work(move || {
        verify_data_item_signature(signature_type, &owner_bytes, &signature_bytes, &payload)?;
        Ok((signature_bytes, owner_bytes))
    })
    .await?;

    Ok(VerifiedItem {
        data,
        data_offset: cursor,
        item_size,
        body_hash,
        signature_type,
        signature: signature_bytes,
        owner: owner_bytes,
        target: target_bytes,
        anchor: anchor_bytes,
        tags,
    })
}

fn item_content_type(tags: &[ItemTag]) -> Result<String> {
    for tag in tags {
        if tag.name.as_ref() == b"Content-Type" {
            let value = HeaderValue::from_bytes(&tag.value)
                .context("invalid Content-Type tag")?
                .to_str()
                .context("non-ASCII Content-Type tag")?
                .to_owned();
            return Ok(value);
        }
    }
    Ok("application/octet-stream".to_owned())
}

fn parse_avro_tags(bytes: &axum::body::Bytes, expected_count: usize) -> Result<Vec<ItemTag>> {
    if bytes.is_empty() && expected_count == 0 {
        return Ok(Vec::new());
    }
    let mut cursor = 0;
    let mut tags = Vec::with_capacity(expected_count);
    loop {
        let block_count = read_avro_long(bytes, &mut cursor)?;
        if block_count == 0 {
            break;
        }
        let count = block_count
            .checked_abs()
            .context("Avro tag block count overflow")?;
        let count = usize::try_from(count).context("Avro tag block count is too large")?;
        ensure!(
            tags.len().saturating_add(count) <= expected_count,
            "Avro tag count exceeds declared count"
        );
        let block_end = if block_count < 0 {
            let block_size = read_avro_long(bytes, &mut cursor)?;
            ensure!(block_size >= 0, "Avro tag block size is negative");
            let block_size =
                usize::try_from(block_size).context("Avro tag block size is too large")?;
            Some(
                cursor
                    .checked_add(block_size)
                    .context("Avro tag block size overflow")?,
            )
        } else {
            None
        };

        for _ in 0..count {
            let name_len = read_avro_length(bytes, &mut cursor, "Avro tag name")?;
            let name = take(bytes, &mut cursor, name_len, "Avro tag name")?;
            let value_len = read_avro_length(bytes, &mut cursor, "Avro tag value")?;
            let value = take(bytes, &mut cursor, value_len, "Avro tag value")?;
            tags.push(ItemTag {
                name: bytes.slice_ref(name),
                value: bytes.slice_ref(value),
            });
        }
        if let Some(block_end) = block_end {
            ensure!(cursor == block_end, "Avro tag block size mismatch");
        }
    }
    ensure!(
        cursor == bytes.len(),
        "Avro tag bytes contain trailing data"
    );
    ensure!(
        tags.len() == expected_count,
        "Avro tag count does not match declared count"
    );
    Ok(tags)
}

fn read_avro_length(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<usize> {
    let length = read_avro_long(bytes, cursor)?;
    ensure!(length >= 0, "{label} length is negative");
    usize::try_from(length).with_context(|| format!("{label} length is too large"))
}

fn read_avro_long(bytes: &[u8], cursor: &mut usize) -> Result<i64> {
    let mut encoded = 0u64;
    for index in 0..10 {
        let byte = take(bytes, cursor, 1, "Avro long")?[0];
        if index == 9 {
            ensure!(byte <= 1, "Avro long overflows i64");
        }
        encoded |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(((encoded >> 1) as i64) ^ -((encoded & 1) as i64));
        }
    }
    bail!("Avro long is malformed")
}

fn read_optional_32<'a>(bytes: &'a [u8], cursor: &mut usize, label: &str) -> Result<&'a [u8]> {
    match take(bytes, cursor, 1, label)?[0] {
        0 => Ok(&[]),
        1 => take(bytes, cursor, 32, label),
        _ => bail!("{label} flag is invalid"),
    }
}

fn read_le_u16(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        take(bytes, cursor, 2, label)?.try_into().unwrap(),
    ))
}

fn read_le_u64(bytes: &[u8], cursor: &mut usize, label: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(
        take(bytes, cursor, 8, label)?.try_into().unwrap(),
    ))
}

fn read_u256_usize(bytes: &[u8], label: &str) -> Result<usize> {
    ensure!(bytes.len() == 32, "{label} has the wrong width");
    ensure!(
        bytes[8..].iter().all(|byte| *byte == 0),
        "{label} exceeds u64"
    );
    usize::try_from(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        .with_context(|| format!("{label} exceeds usize"))
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

fn verify_data_item_signature(
    signature_type: u16,
    owner: &[u8],
    signature: &[u8],
    payload: &[u8],
) -> Result<()> {
    match signature_type {
        1 => verify_rsa_pss(owner, signature, payload, "data item"),
        2 => verify_ed25519(owner, signature, payload),
        3 => verify_ethereum(owner, signature, payload),
        4 => verify_ed25519(owner, signature, hex(payload).as_bytes()),
        5 => verify_ed25519(
            owner,
            signature,
            format!("APTOS\nmessage: {}\nnonce: bundlr", hex(payload)).as_bytes(),
        ),
        6 => verify_aptos_multisignature(owner, signature, payload),
        7 => verify_typed_ethereum(owner, signature, payload),
        _ => bail!("unsupported ANS-104 signature type {signature_type}"),
    }
}

fn verify_ed25519(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    let owner: &[u8; 32] = owner
        .try_into()
        .context("invalid Ed25519 data item owner length")?;
    let signature =
        Ed25519Signature::try_from(signature).context("invalid Ed25519 signature length")?;
    let key = Ed25519VerifyingKey::from_bytes(owner).context("invalid Ed25519 data item owner")?;
    key.verify_strict(message, &signature)
        .context("data item signature verification failed")
}

fn verify_ethereum(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(signature.len() == 65, "invalid Ethereum signature length");
    let key = Secp256k1VerifyingKey::from_sec1_bytes(owner)
        .context("invalid Ethereum data item owner")?;
    let signature = Secp256k1Signature::try_from(&signature[..64])
        .context("invalid Ethereum data item signature")?;
    key.verify_prehash(&ethereum_message_hash(message), &signature)
        .context("data item signature verification failed")
}

fn ethereum_message_hash(message: &[u8]) -> [u8; 32] {
    let length = message.len().to_string();
    keccak256(&[
        b"\x19Ethereum Signed Message:\n",
        length.as_bytes(),
        message,
    ])
}

fn verify_aptos_multisignature(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(owner.len() == 1_025, "invalid Aptos multisig owner length");
    ensure!(
        signature.len() == 2_052,
        "invalid Aptos multisig signature length"
    );
    let threshold = usize::from(owner[1_024]);
    ensure!(
        (1..=32).contains(&threshold),
        "invalid Aptos multisig threshold"
    );
    let bitmap = &signature[2_048..];
    let signature_count = bitmap.iter().map(|byte| byte.count_ones()).sum::<u32>() as usize;
    ensure!(
        signature_count >= threshold,
        "Aptos multisig threshold is not met"
    );

    for index in 0..32 {
        if bitmap[index / 8] & (0x80 >> (index % 8)) != 0 {
            verify_ed25519(
                &owner[index * 32..(index + 1) * 32],
                &signature[index * 64..(index + 1) * 64],
                message,
            )?;
        }
    }
    Ok(())
}

fn verify_typed_ethereum(owner: &[u8], signature: &[u8], message: &[u8]) -> Result<()> {
    ensure!(
        signature.len() == 65,
        "invalid typed Ethereum signature length"
    );
    let address = ethereum_address_from_owner(owner)?;
    let recovery_id = match signature[64] {
        value @ 0..=1 => value,
        value @ 27..=28 => value - 27,
        _ => bail!("invalid typed Ethereum recovery ID"),
    };
    let signature = Secp256k1Signature::try_from(&signature[..64])
        .context("invalid typed Ethereum data item signature")?;
    let key = Secp256k1VerifyingKey::recover_from_prehash(
        &typed_ethereum_message_hash(message, &address),
        &signature,
        RecoveryId::try_from(recovery_id).context("invalid typed Ethereum recovery ID")?,
    )
    .context("typed Ethereum data item signature recovery failed")?;
    let public_key = key.to_sec1_point(false);
    let recovered = keccak256(&[&public_key.as_bytes()[1..]]);
    ensure!(
        recovered[12..] == address,
        "data item signature verification failed"
    );
    Ok(())
}

fn typed_ethereum_message_hash(message: &[u8], address: &[u8; 20]) -> [u8; 32] {
    let domain_type = keccak256(&[b"EIP712Domain(string name,string version)"]);
    let domain_name = keccak256(&[b"Bundlr"]);
    let domain_version = keccak256(&[b"1"]);
    let domain = keccak256(&[&domain_type, &domain_name, &domain_version]);
    let message_type = keccak256(&[b"Bundlr(bytes Transaction hash, address address)"]);
    let transaction_hash = keccak256(&[message]);
    let mut encoded_address = [0; 32];
    encoded_address[12..].copy_from_slice(address);
    let value = keccak256(&[&message_type, &transaction_hash, &encoded_address]);
    keccak256(&[b"\x19\x01", &domain, &value])
}

fn ethereum_address_from_owner(owner: &[u8]) -> Result<[u8; 20]> {
    ensure!(
        owner.len() == 42 && owner[..2].eq_ignore_ascii_case(b"0x"),
        "invalid typed Ethereum data item owner"
    );
    let mut address = [0; 20];
    for (byte, encoded) in address.iter_mut().zip(owner[2..].chunks_exact(2)) {
        *byte = decode_hex_nibble(encoded[0])
            .and_then(|high| decode_hex_nibble(encoded[1]).map(|low| high << 4 | low))
            .context("invalid typed Ethereum data item owner")?;
    }
    Ok(address)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::default();
    for part in parts {
        sha3::Digest::update(&mut hasher, part);
    }
    sha3::Digest::finalize(hasher).into()
}

struct TxPath {
    data_root: [u8; 32],
    start_bound: u128,
    end_offset: u128,
    size: u128,
}

fn validate_tx_path(
    tx_root: &[u8; 32],
    absolute_offset: u128,
    block_weave_size: u128,
    previous_weave_size: u128,
    path: &[u8],
) -> Result<TxPath> {
    ensure!(path.len() >= LEAF_SIZE, "tx_path is too short");
    ensure!(
        (path.len() - LEAF_SIZE).is_multiple_of(BRANCH_SIZE),
        "tx_path length is malformed"
    );
    ensure!(block_weave_size > previous_weave_size, "invalid block size");
    ensure!(
        absolute_offset > previous_weave_size && absolute_offset <= block_weave_size,
        "requested offset is outside block"
    );

    let block_size = block_weave_size - previous_weave_size;
    let target = absolute_offset - previous_weave_size - 1;
    let mut left_bound = 0u128;
    let mut right_bound = block_size;
    let mut current_hash = *tx_root;
    let mut cursor = 0usize;

    while path.len() - cursor > LEAF_SIZE {
        ensure!(
            cursor + BRANCH_SIZE <= path.len(),
            "truncated tx_path branch"
        );
        let left: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
        let right: [u8; 32] = path[cursor + HASH_SIZE..cursor + HASH_SIZE * 2]
            .try_into()
            .unwrap();
        let note = &path[cursor + HASH_SIZE * 2..cursor + BRANCH_SIZE];
        ensure!(
            hash_branch(&left, &right, note) == current_hash,
            "invalid tx_path branch"
        );
        let offset = note_to_u128(note)?;
        cursor += BRANCH_SIZE;

        if target < offset {
            current_hash = left;
            right_bound = right_bound.min(offset);
        } else {
            current_hash = right;
            left_bound = left_bound.max(offset);
        }
    }

    ensure!(cursor + LEAF_SIZE == path.len(), "truncated tx_path leaf");
    let data_root: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
    let note = &path[cursor + HASH_SIZE..cursor + LEAF_SIZE];
    ensure!(
        hash_leaf(&data_root, note) == current_hash,
        "invalid tx_path leaf"
    );
    let relative_end = note_to_u128(note)?;
    ensure!(
        relative_end > left_bound,
        "tx_path has an empty transaction"
    );
    ensure!(
        relative_end <= right_bound,
        "tx_path end exceeds its branch"
    );

    Ok(TxPath {
        data_root,
        start_bound: previous_weave_size + left_bound,
        end_offset: previous_weave_size + relative_end,
        size: relative_end - left_bound,
    })
}

#[derive(Clone, Copy)]
enum SplitCheck {
    None,
    Strict,
    Relaxed,
}

#[derive(Clone, Copy)]
struct DataContext {
    data_size: u128,
    is_rightmost: Option<bool>,
    left_shift: u128,
    check_borders: bool,
    check_split: SplitCheck,
    allow_rebase: bool,
    rebase_depth: u8,
}

struct DataPath {
    start: u128,
    end: u128,
    data_hash: [u8; 32],
}

fn validate_data_path(
    data_root: &[u8; 32],
    data_size: u128,
    relative_offset: u128,
    absolute_offset: u128,
    path: &[u8],
) -> Result<DataPath> {
    ensure!(data_size > 0, "data_path has zero data size");
    ensure!(
        relative_offset < data_size,
        "data_path offset is outside transaction"
    );
    ensure!(path.len() >= LEAF_SIZE, "data_path is too short");

    let (check_borders, check_split, allow_rebase) =
        if absolute_offset >= MERKLE_REBASE_SUPPORT_THRESHOLD {
            (true, SplitCheck::Relaxed, true)
        } else if absolute_offset >= STRICT_DATA_SPLIT_THRESHOLD {
            (true, SplitCheck::Strict, false)
        } else {
            (false, SplitCheck::None, false)
        };
    let context = DataContext {
        data_size,
        is_rightmost: None,
        left_shift: 0,
        check_borders,
        check_split,
        allow_rebase,
        rebase_depth: 0,
    };

    walk_rebased_data_path(
        Some(data_root),
        relative_offset,
        0,
        data_size,
        path,
        context,
    )
}

fn walk_rebased_data_path(
    root: Option<&[u8; 32]>,
    target: u128,
    left_bound: u128,
    right_bound: u128,
    path: &[u8],
    context: DataContext,
) -> Result<DataPath> {
    let rebased =
        context.allow_rebase && path.len() >= 128 && path[..32].iter().all(|byte| *byte == 0);
    if !rebased {
        return walk_data_path(
            root.context("missing data_path root")?,
            target,
            left_bound,
            right_bound,
            path,
            context,
        );
    }

    ensure!(
        context.rebase_depth < 64,
        "data_path rebasing depth exceeded"
    );
    let left: [u8; 32] = path[32..64].try_into().unwrap();
    let right: [u8; 32] = path[64..96].try_into().unwrap();
    let note = &path[96..128];
    if let Some(root) = root {
        ensure!(
            hash_branch(&left, &right, note) == *root,
            "invalid rebase branch"
        );
    }
    let boundary = note_to_u128(note)?;

    let (next_root, next_target, next_right, next_shift) = if target < boundary {
        let adjusted = right_bound.min(boundary);
        ensure!(adjusted >= left_bound, "invalid left rebase boundary");
        (
            left,
            target
                .checked_sub(left_bound)
                .context("rebase target underflow")?,
            adjusted - left_bound,
            context.left_shift + left_bound,
        )
    } else {
        let adjusted = left_bound.max(boundary);
        ensure!(right_bound >= adjusted, "invalid right rebase boundary");
        (
            right,
            target
                .checked_sub(adjusted)
                .context("rebase target underflow")?,
            right_bound - adjusted,
            context.left_shift + adjusted,
        )
    };
    let next_context = DataContext {
        left_shift: next_shift,
        is_rightmost: None,
        rebase_depth: context.rebase_depth + 1,
        ..context
    };

    walk_rebased_data_path(
        Some(&next_root),
        next_target,
        0,
        next_right,
        &path[128..],
        next_context,
    )
}

fn walk_data_path(
    root: &[u8; 32],
    target: u128,
    left_bound: u128,
    right_bound: u128,
    path: &[u8],
    context: DataContext,
) -> Result<DataPath> {
    ensure!(right_bound > 0, "data_path has empty bounds");
    let mut left = left_bound;
    let mut right = right_bound;
    let mut current_hash = *root;
    let mut cursor = 0usize;
    let mut is_rightmost = context.is_rightmost;

    while path.len() - cursor > LEAF_SIZE {
        ensure!(
            cursor + BRANCH_SIZE <= path.len(),
            "truncated data_path branch"
        );
        let left_hash: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
        let right_hash: [u8; 32] = path[cursor + HASH_SIZE..cursor + HASH_SIZE * 2]
            .try_into()
            .unwrap();
        let note = &path[cursor + HASH_SIZE * 2..cursor + BRANCH_SIZE];
        ensure!(
            hash_branch(&left_hash, &right_hash, note) == current_hash,
            "invalid data_path branch"
        );
        let boundary = note_to_u128(note)?;
        cursor += BRANCH_SIZE;

        if target < boundary {
            current_hash = left_hash;
            right = right.min(boundary);
            is_rightmost = Some(false);
        } else {
            current_hash = right_hash;
            left = left.max(boundary);
            if is_rightmost.is_none() {
                is_rightmost = Some(true);
            }
        }
    }

    ensure!(cursor + LEAF_SIZE == path.len(), "truncated data_path leaf");
    let data_hash: [u8; 32] = path[cursor..cursor + HASH_SIZE].try_into().unwrap();
    let note = &path[cursor + HASH_SIZE..cursor + LEAF_SIZE];
    let leaf_end = note_to_u128(note)?;
    ensure!(
        hash_leaf(&data_hash, note) == current_hash,
        "invalid data_path leaf"
    );

    if context.check_borders {
        ensure!(
            leaf_end.saturating_sub(left) <= MAX_CHUNK_SIZE
                && right.saturating_sub(left) <= MAX_CHUNK_SIZE,
            "data_path violates chunk borders"
        );
    }
    validate_split(leaf_end, left, right, is_rightmost, context)?;

    let start = context.left_shift + left;
    let end = context.left_shift + right.min(leaf_end).max(left + 1);
    ensure!(end > start, "data_path made no forward progress");

    Ok(DataPath {
        start,
        end,
        data_hash,
    })
}

fn validate_split(
    end: u128,
    left: u128,
    right: u128,
    is_rightmost: Option<bool>,
    context: DataContext,
) -> Result<()> {
    match context.check_split {
        SplitCheck::None => Ok(()),
        SplitCheck::Strict => {
            ensure!(end >= left, "invalid strict split bounds");
            let size = end - left;
            let valid = if size == MAX_CHUNK_SIZE {
                left.is_multiple_of(MAX_CHUNK_SIZE)
            } else if end == context.data_size {
                let border = (right / MAX_CHUNK_SIZE) * MAX_CHUNK_SIZE;
                !right.is_multiple_of(MAX_CHUNK_SIZE) && left <= border
            } else {
                left.is_multiple_of(MAX_CHUNK_SIZE)
                    && context.data_size.saturating_sub(left) > MAX_CHUNK_SIZE
                    && context.data_size.saturating_sub(left) < MAX_CHUNK_SIZE * 2
            };
            ensure!(valid, "data_path violates strict data split");
            Ok(())
        }
        SplitCheck::Relaxed => {
            let shifted_left = context.left_shift + left;
            let shifted_end = context.left_shift + end;
            let valid = if is_rightmost == Some(true) {
                shifted_left.is_multiple_of(MAX_CHUNK_SIZE)
                    || (shifted_left / MAX_CHUNK_SIZE + 1 == shifted_end / MAX_CHUNK_SIZE
                        && !shifted_end.is_multiple_of(MAX_CHUNK_SIZE))
            } else {
                shifted_left.is_multiple_of(MAX_CHUNK_SIZE)
            };
            ensure!(valid, "data_path violates relaxed data split");
            Ok(())
        }
    }
}

fn deep_hash_blob(bytes: &[u8]) -> [u8; 48] {
    let tag = Sha384::digest(format!("blob{}", bytes.len()).as_bytes());
    let data = Sha384::digest(bytes);
    sha384(&[&tag, &data])
}

fn deep_hash_list(items: &[[u8; 48]]) -> [u8; 48] {
    let mut accumulator: [u8; 48] =
        Sha384::digest(format!("list{}", items.len()).as_bytes()).into();
    for item in items {
        accumulator = sha384(&[&accumulator, item]);
    }
    accumulator
}

fn hash_branch(left: &[u8; 32], right: &[u8; 32], note: &[u8]) -> [u8; 32] {
    let left = sha256(&[left]);
    let right = sha256(&[right]);
    let note = sha256(&[note]);
    sha256(&[&left, &right, &note])
}

fn hash_leaf(data_hash: &[u8], note: &[u8]) -> [u8; 32] {
    let data_hash = sha256(&[data_hash]);
    let note = sha256(&[note]);
    sha256(&[&data_hash, &note])
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn note_to_u128(note: &[u8]) -> Result<u128> {
    ensure!(note.len() == NOTE_SIZE, "invalid Merkle note length");
    ensure!(
        note[..NOTE_SIZE - size_of::<u128>()]
            .iter()
            .all(|byte| *byte == 0),
        "Merkle note exceeds u128"
    );
    Ok(u128::from_be_bytes(
        note[NOTE_SIZE - size_of::<u128>()..].try_into().unwrap(),
    ))
}

fn decode_b64(value: &str, label: &str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("invalid base64url {label}"))?;
    ensure!(
        URL_SAFE_NO_PAD.encode(&decoded) == value,
        "non-canonical base64url {label}"
    );
    Ok(decoded)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    decode_b64(value, label)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("invalid {label} length: {}", bytes.len()))
}

fn parse_u128(value: &str, label: &str) -> Result<u128> {
    value
        .parse()
        .with_context(|| format!("invalid {label}: {value}"))
}

fn normalize_base_url(value: &str) -> Result<String> {
    let value = value.trim_end_matches('/');
    let url = Url::parse(value).context("invalid source URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "source URL must use HTTP(S)"
    );
    Ok(value.to_owned())
}

fn endpoint(base: &str, path: &str) -> String {
    format!("{base}/{}", path.trim_start_matches('/'))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").unwrap();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use k256::ecdsa::SigningKey as Secp256k1SigningKey;

    #[test]
    fn verifies_empty_transactions_and_rejects_size_root_mismatches() {
        let mut transaction: Transaction =
            serde_json::from_str(include_str!("../tests/fixtures/empty-transaction.json")).unwrap();
        verify_transaction(&transaction, &transaction.id, 1_000_000).unwrap();
        transaction.data_root = URL_SAFE_NO_PAD.encode([1; 32]);
        assert!(verify_transaction(&transaction, &transaction.id, 1_000_000).is_err());
        transaction.data_root.clear();
        transaction.data_size = "1".to_owned();
        assert!(verify_transaction(&transaction, &transaction.id, 1_000_000).is_err());
    }

    #[tokio::test]
    async fn only_ecdsa_metadata_requires_the_trusted_source() {
        use axum::{Router, http::StatusCode, response::IntoResponse};
        use std::sync::atomic::{AtomicBool, Ordering};
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/protocol-transactions.json"))
                .unwrap();
        for (name, requires_trusted) in [
            ("public-format1-height34", false),
            ("format2-ecdsa", true),
            ("format2-rsa-denomination", false),
        ] {
            let case = fixtures["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|case| case["name"] == name)
                .unwrap();
            let header = case["transaction"].clone();
            let id = header["id"].as_str().unwrap().to_owned();
            let height = case["height"].as_u64().unwrap();
            let available = Arc::new(AtomicBool::new(true));
            let mut servers = Vec::new();
            let mut urls = Vec::new();
            for trusted in [true, false] {
                let available = Arc::clone(&available);
                let header = header.clone();
                let router = Router::new().fallback(move || {
                    let header = header.clone();
                    let available = Arc::clone(&available);
                    async move {
                        if trusted && !available.load(Ordering::SeqCst) {
                            StatusCode::NOT_FOUND.into_response()
                        } else {
                            header.to_string().into_response()
                        }
                    }
                });
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                urls.push(format!("http://{}", listener.local_addr().unwrap()));
                servers.push(tokio::spawn(async move {
                    axum::serve(listener, router).await.unwrap();
                }));
            }
            let gateway = Gateway::new(
                Config::new(
                    &urls[0],
                    &urls[1],
                    vec![urls[1].clone()],
                    Duration::from_secs(2),
                    1,
                    1024 * 1024,
                )
                .unwrap(),
            )
            .unwrap();
            let remaining = AtomicUsize::new(usize::MAX);
            let verified = gateway
                .fetch_transaction(&id, height, &remaining)
                .await
                .unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD.encode(verified.1.metadata.owner_address),
                case["owner_address"]
            );
            available.store(false, Ordering::SeqCst);
            let fallback = gateway.fetch_transaction(&id, height, &remaining).await;
            assert_eq!(fallback.is_err(), requires_trusted, "{name}");
            for server in servers {
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn outbound_chunk_requests_share_a_global_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&active);
        let observed = Arc::clone(&peak);
        let app = axum::Router::new().fallback(move || {
            let active = Arc::clone(&counted);
            let peak = Arc::clone(&observed);
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(100)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                r#"{"chunk":"","data_path":"","tx_path":""}"#
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway::new(
            Config::new(
                &base,
                &base,
                vec![base.clone()],
                Duration::from_secs(10),
                1,
                1024,
            )
            .unwrap(),
        )
        .unwrap();
        let results = futures_util::future::join_all(
            (1..=128).map(|offset| gateway.fetch_chunk(&base, offset)),
        )
        .await;
        for result in results {
            result.unwrap();
        }
        assert!((2..=64).contains(&peak.load(Ordering::SeqCst)));
        server.abort();
    }

    fn note(value: u128) -> [u8; 32] {
        let mut note = [0; 32];
        note[16..].copy_from_slice(&value.to_be_bytes());
        note
    }

    fn encode_data_item(
        signature_type: u16,
        signature: &[u8],
        owner: &[u8],
        data: &[u8],
        raw_tags: &[u8],
        tag_count: u64,
    ) -> Vec<u8> {
        let mut item = Vec::new();
        item.extend_from_slice(&signature_type.to_le_bytes());
        item.extend_from_slice(signature);
        item.extend_from_slice(owner);
        item.extend_from_slice(&[0, 0]);
        item.extend_from_slice(&tag_count.to_le_bytes());
        item.extend_from_slice(&(raw_tags.len() as u64).to_le_bytes());
        item.extend_from_slice(raw_tags);
        item.extend_from_slice(data);
        item
    }

    pub(super) fn signed_data_item(data: &[u8], tags: &[(&[u8], &[u8])]) -> (Vec<u8>, [u8; 32]) {
        let mut raw_tags = Vec::new();
        let write_length = |bytes: &mut Vec<u8>, length: usize| {
            let mut value = (length as u64) << 1;
            while value >= 0x80 {
                bytes.push(value as u8 | 0x80);
                value >>= 7;
            }
            bytes.push(value as u8);
        };
        if !tags.is_empty() {
            write_length(&mut raw_tags, tags.len());
            for (name, value) in tags {
                write_length(&mut raw_tags, name.len());
                raw_tags.extend_from_slice(name);
                write_length(&mut raw_tags, value.len());
                raw_tags.extend_from_slice(value);
            }
        }
        raw_tags.push(0);
        let key = Ed25519SigningKey::from_bytes(&[2; 32]);
        let owner = key.verifying_key().to_bytes();
        let payload =
            data_item_signature_payload(2, &owner, &[], &[], &raw_tags, deep_hash_blob(data));
        let signature = key.sign(&payload).to_bytes();
        (
            encode_data_item(2, &signature, &owner, data, &raw_tags, tags.len() as u64),
            sha256(&[&signature]),
        )
    }

    pub(super) fn encode_bundle(items: &[&[u8]]) -> Vec<u8> {
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&(items.len() as u64).to_le_bytes());
        bundle.extend_from_slice(&[0; 24]);
        for item in items {
            bundle.extend_from_slice(&(item.len() as u64).to_le_bytes());
            bundle.extend_from_slice(&[0; 24]);
            let signature_type = u16::from_le_bytes(item[..2].try_into().unwrap());
            let (size, _) = data_item_signature_sizes(signature_type).unwrap();
            bundle.extend_from_slice(&sha256(&[&item[2..2 + size]]));
        }
        for item in items {
            bundle.extend_from_slice(item);
        }
        bundle
    }

    pub(super) async fn spooled_content(bytes: &[u8]) -> content::Content {
        let budget = Arc::new(content::SpoolBudget::new(bytes.len()));
        let mut writer = content::ContentWriter::new(bytes.len(), 1, budget)
            .await
            .unwrap();
        for chunk in bytes.chunks(64 * 1024) {
            writer.write(chunk).await.unwrap();
        }
        writer.finish().await.unwrap().0
    }

    #[tokio::test]
    async fn streamed_nested_items_verify_beyond_spool_and_payload_limits() {
        use std::sync::atomic::Ordering;
        let payload = vec![42; 128 * 1024];
        let (child, child_id) = signed_data_item(&payload, &[]);
        let inner = encode_bundle(&[&child]);
        let tags: &[(&[u8], &[u8])] =
            &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];
        let (parent, parent_id) = signed_data_item(&inner, tags);
        let bytes = encode_bundle(&[&parent]);
        let (mut gateway, _, corrupt, server, requests) =
            retrieval_fixture(&bytes, tags, None).await;
        gateway.config.max_data_size = 1;
        gateway.config.max_memory_data_size = 1;
        gateway.config.max_spool_bytes = 1;
        gateway.spool_budget = Arc::new(SpoolBudget::new(1));
        let end = note(bytes.len() as u128);
        let data_root = hash_leaf(&sha256(&[&bytes]), &end);
        let geometry = Geometry {
            tx_root: hash_leaf(&data_root, &end),
            data_root,
            block_weave_size: bytes.len() as u128,
            previous_weave_size: 0,
            first_offset: 1,
            end_offset: bytes.len() as u128,
            data_size: bytes.len() as u128,
        };
        let content =
            Content::streamed(streaming::ChunkSource::new(&gateway, geometry), bytes.len());
        let (verified_parent, _) =
            verify_bundle_item(content, crate::BundleFormat::Binary, &parent_id, None, None)
                .await
                .unwrap();
        let (verified_child, _) = verify_bundle_item(
            verified_parent.data,
            crate::BundleFormat::Binary,
            &child_id,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            verified_child
                .data
                .read_all(payload.len())
                .await
                .unwrap()
                .as_ref(),
            payload.as_slice()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        corrupt.store(true, Ordering::SeqCst);
        let content =
            Content::streamed(streaming::ChunkSource::new(&gateway, geometry), bytes.len());
        assert!(
            verify_bundle_item(content, BundleFormat::Binary, &parent_id, None, None)
                .await
                .is_err()
        );
        server.abort();
    }

    fn tree(chunks: &[&[u8]], start: usize) -> ([u8; 32], Vec<Vec<u8>>) {
        if chunks.len() == 1 {
            let hash = sha256(&[chunks[0]]);
            let end = note((start + chunks[0].len()) as u128);
            return (
                hash_leaf(&hash, &end),
                vec![[hash.as_slice(), &end].concat()],
            );
        }
        let mid = chunks.len() / 2;
        let boundary = start + chunks[..mid].iter().map(|chunk| chunk.len()).sum::<usize>();
        let (left, left_paths) = tree(&chunks[..mid], start);
        let (right, right_paths) = tree(&chunks[mid..], boundary);
        let boundary = note(boundary as u128);
        let branch = [left.as_slice(), &right, &boundary].concat();
        let paths = left_paths
            .into_iter()
            .chain(right_paths)
            .map(|path| [branch.as_slice(), &path].concat())
            .collect();
        (hash_branch(&left, &right, &boundary), paths)
    }
    #[tokio::test]
    async fn streamed_read_ahead_overlaps_fetches_and_preserves_verification() {
        use axum::{Router, extract::Path, routing::get};
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Default)]
        struct Requests {
            active: AtomicUsize,
            peak: AtomicUsize,
            fault: AtomicUsize,
            started: AtomicUsize,
            first_pair: tokio::sync::Notify,
        }
        let payload: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i / 8191) as u8).collect();
        let (item, id) = signed_data_item(&payload, &[]);
        let bytes = encode_bundle(&[&item]);
        // Uneven proof boundaries force read-ahead ranges to join multiple verified chunks.
        let chunks: Vec<_> = bytes.chunks(192 * 1024).collect();
        let (data_root, paths) = tree(&chunks, 0);
        let end = note(bytes.len() as u128);
        let tx_path = URL_SAFE_NO_PAD.encode([data_root.as_slice(), &end].concat());
        let replies: Vec<_> = chunks
            .iter()
            .zip(paths)
            .map(|(chunk, path)| {
                serde_json::json!({
                    "chunk": URL_SAFE_NO_PAD.encode(chunk),
                    "data_path": URL_SAFE_NO_PAD.encode(path),
                    "tx_path": tx_path,
                })
            })
            .collect();
        let requests = Arc::new(Requests::default());
        let observed = Arc::clone(&requests);
        let app = Router::new().route(
            "/chunk/{offset}",
            get(move |Path(offset): Path<usize>| {
                let index = (offset - 1) / (192 * 1024);
                let mut reply = replies[index].clone();
                let requests = Arc::clone(&observed);
                async move {
                    let active = requests.active.fetch_add(1, Ordering::SeqCst) + 1;
                    requests.peak.fetch_max(active, Ordering::SeqCst);
                    match requests.started.fetch_add(1, Ordering::SeqCst) {
                        0 => requests.first_pair.notified().await,
                        1 => requests.first_pair.notify_one(),
                        _ => {}
                    }
                    let fault = requests.fault.load(Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(if fault == 2 { 200 } else { 25 }))
                        .await;
                    requests.active.fetch_sub(1, Ordering::SeqCst);
                    if fault == 1 && index == 8 {
                        reply["chunk"] = serde_json::json!(URL_SAFE_NO_PAD.encode(b"corrupt"));
                    }
                    reply.to_string()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway::new(
            Config::new(&url, &url, vec![url.clone()], Duration::from_secs(5), 1, 1).unwrap(),
        )
        .unwrap();
        let geometry = Geometry {
            tx_root: hash_leaf(&data_root, &end),
            data_root,
            block_weave_size: bytes.len() as u128,
            previous_weave_size: 0,
            first_offset: 1,
            end_offset: bytes.len() as u128,
            data_size: bytes.len() as u128,
        };
        let fresh =
            || Content::streamed(streaming::ChunkSource::new(&gateway, geometry), bytes.len());
        let hashes = tokio::time::timeout(Duration::from_secs(10), fresh().hashes())
            .await
            .expect("streamed hashing stalled")
            .unwrap();
        assert_eq!(hashes, (sha256(&[&bytes]), sha384(&[&bytes])));
        let peak = requests.peak.load(Ordering::SeqCst);
        assert!((2..=8).contains(&peak), "peak in-flight requests: {peak}");
        let (verified, _) =
            verify_bundle_item(fresh(), crate::BundleFormat::Binary, &id, None, None)
                .await
                .unwrap();
        let mut reader = verified.data.reader().await.unwrap();
        let mut actual = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut actual)
            .await
            .unwrap();
        assert_eq!(actual, payload);
        requests.fault.store(1, Ordering::SeqCst);
        assert!(
            verify_bundle_item(fresh(), BundleFormat::Binary, &id, None, None)
                .await
                .is_err()
        );
        requests.fault.store(2, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fresh().hashes())
                .await
                .is_err()
        );
        server.abort();
    }

    async fn retrieval_fixture(
        data: &[u8],
        tags: &[(&[u8], &[u8])],
        bundled_item: Option<(&str, usize)>,
    ) -> (
        Gateway,
        String,
        Arc<std::sync::atomic::AtomicBool>,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use axum::{Router, http::StatusCode, response::IntoResponse};
        use std::sync::atomic::{AtomicBool, Ordering};

        let height = FORK_2_9_HEIGHT + 1;
        let end = note(data.len() as u128);
        let chunks: Vec<_> = data.chunks(MAX_CHUNK_SIZE as usize).collect();
        let (data_root, paths) = if chunks.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let (root, paths) = tree(&chunks, 0);
            (root.to_vec(), paths)
        };
        let tag_hashes = tags
            .iter()
            .map(|(name, value)| deep_hash_list(&[deep_hash_blob(name), deep_hash_blob(value)]))
            .collect::<Vec<_>>();
        let digest = sha256(&[&deep_hash_list(&[
            deep_hash_blob(b"2"),
            deep_hash_blob(b""),
            deep_hash_blob(b"0"),
            deep_hash_blob(b"0"),
            deep_hash_blob(b""),
            deep_hash_list(&tag_hashes),
            deep_hash_blob(data.len().to_string().as_bytes()),
            deep_hash_blob(&data_root),
        ])]);
        let key = Secp256k1SigningKey::from_slice(&[3; 32]).unwrap();
        let (signature, recovery_id) = key.sign_prehash_recoverable(&digest);
        let mut signature = signature.to_bytes().to_vec();
        signature.push(recovery_id.to_byte());
        let id = URL_SAFE_NO_PAD.encode(sha256(&[&signature]));
        let transaction = serde_json::json!({
            "format": 2, "id": id, "last_tx": "", "owner": "", "target": "",
            "quantity": "0", "reward": "0", "data": "", "data_size": data.len().to_string(),
            "data_root": URL_SAFE_NO_PAD.encode(&data_root),
            "signature": URL_SAFE_NO_PAD.encode(signature),
            "tags": tags.iter().map(|(name, value)| serde_json::json!({
                "name": URL_SAFE_NO_PAD.encode(name), "value": URL_SAFE_NO_PAD.encode(value),
            })).collect::<Vec<_>>(),
        });
        let zero32 = URL_SAFE_NO_PAD.encode([0; 32]);
        let zero48 = URL_SAFE_NO_PAD.encode([0; 48]);
        let tx_root = if data.is_empty() {
            String::new()
        } else {
            URL_SAFE_NO_PAD.encode(hash_leaf(&data_root, &end))
        };
        let mut block = serde_json::json!({
            "height": height, "timestamp": 0, "last_retarget": 0, "nonce": "AA",
            "previous_block": zero48, "reward_addr": zero32, "tx_root": tx_root,
            "tags": [], "txs": [id], "block_size": data.len().to_string(),
            "weave_size": data.len().to_string(), "usd_to_ar_rate": ["1", "1"],
            "scheduled_usd_to_ar_rate": ["1", "1"], "poa": {},
            "reward_history_hash": zero32, "block_time_history_hash": zero32,
            "chunk_hash": zero32,
            "nonce_limiter_info": {
                "output": zero32, "seed": zero48, "next_seed": zero48,
                "vdf_difficulty": "0", "next_vdf_difficulty": "0",
            },
        });
        for field in ["indep_hash", "wallet_list", "hash_list_merkle", "hash"] {
            block[field] = serde_json::json!("");
        }
        for field in [
            "diff",
            "cumulative_diff",
            "reward_pool",
            "packing_2_5_threshold",
            "strict_data_split_threshold",
            "reward",
            "recall_byte",
            "price_per_gib_minute",
            "scheduled_price_per_gib_minute",
            "debt_supply",
            "kryder_plus_rate_multiplier",
            "kryder_plus_rate_multiplier_latch",
            "denomination",
            "previous_cumulative_diff",
            "merkle_rebase_support_threshold",
        ] {
            block[field] = serde_json::json!("0");
        }
        let hash = URL_SAFE_NO_PAD
            .encode(block_indep_hash(&historical::decode_header(block.clone()).unwrap()).unwrap());
        block["indep_hash"] = serde_json::json!(hash);
        let edges = match bundled_item {
            Some((item_id, size)) => serde_json::json!([{
                "node": {"id": item_id, "bundledIn": {"id": id}, "data": {"size": size.to_string()}},
            }]),
            None => serde_json::json!([]),
        };
        let mut responses = HashMap::new();
        responses.insert(
            "/graphql".to_owned(),
            serde_json::json!({
                "data": {"transactions": {"edges": edges}},
            })
            .to_string(),
        );
        responses.insert(
            "/info".to_owned(),
            serde_json::json!({
                "height": height + CONSENSUS_DEPTH,
            })
            .to_string(),
        );
        responses.insert(
            format!("/tx/{id}/status"),
            serde_json::json!({
                "block_height": height, "block_indep_hash": hash,
            })
            .to_string(),
        );
        responses.insert(
            format!("/block_index/{}/{}", height - 1, height),
            serde_json::json!([
                {"hash": hash, "tx_root": tx_root, "weave_size": data.len().to_string()},
                {"hash": zero48, "tx_root": "", "weave_size": "0"},
            ])
            .to_string(),
        );
        responses.insert(format!("/block/hash/{hash}"), block.to_string());
        responses.insert(format!("/tx/{id}"), transaction.to_string());
        responses.insert(
            format!("/tx/{id}/offset"),
            serde_json::json!({
                "size": data.len().to_string(), "offset": data.len().to_string(),
            })
            .to_string(),
        );
        let chunk_replies: Vec<_> = chunks
            .iter()
            .zip(paths)
            .map(|(chunk, path)| {
                serde_json::json!({
                    "chunk": URL_SAFE_NO_PAD.encode(chunk),
                    "data_path": URL_SAFE_NO_PAD.encode(path),
                    "tx_path": URL_SAFE_NO_PAD.encode([data_root.as_slice(), &end].concat()),
                })
                .to_string()
            })
            .collect();
        let corrupt_chunk = Arc::new(AtomicBool::new(false));
        let corrupt = corrupt_chunk.clone();
        let chunk_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&chunk_requests);
        let anchor_path = format!("/block_index2/{height}/{height}");
        let mut anchor = decode_b64(&hash, "fixture hash").unwrap();
        anchor.extend_from_slice(&16u16.to_be_bytes());
        anchor.extend_from_slice(&(data.len() as u128).to_be_bytes());
        let encoded_root = decode_b64(&tx_root, "fixture tx root").unwrap();
        anchor.push(encoded_root.len() as u8);
        anchor.extend_from_slice(&encoded_root);
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let offset = uri
                .path()
                .strip_prefix("/chunk/")
                .and_then(|offset| offset.parse::<usize>().ok());
            if offset.is_some() {
                counted.fetch_add(1, Ordering::Relaxed);
            }
            let response = offset
                .and_then(|offset| offset.checked_sub(1))
                .and_then(|offset| chunk_replies.get(offset / MAX_CHUNK_SIZE as usize))
                .or_else(|| responses.get(uri.path()))
                .cloned();
            let corrupt = offset.is_some() && corrupt.load(Ordering::SeqCst);
            let anchor = (uri.path() == anchor_path).then(|| anchor.clone());
            async move {
                if let Some(anchor) = anchor {
                    return anchor.into_response();
                }
                match response {
                    Some(body) if corrupt => {
                        let mut chunk: serde_json::Value = serde_json::from_str(&body).unwrap();
                        chunk["chunk"] = serde_json::json!(URL_SAFE_NO_PAD.encode(b"corrupt"));
                        chunk.to_string().into_response()
                    }
                    Some(body) => body.into_response(),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let gateway = Gateway::new(
            Config::new(
                &url,
                &url,
                vec![url.clone()],
                Duration::from_secs(5),
                1,
                16 * 1024,
            )
            .unwrap(),
        )
        .unwrap();
        let requested = bundled_item.map_or(id, |(id, _)| id.to_owned());
        (gateway, requested, corrupt_chunk, server, chunk_requests)
    }

    #[tokio::test]
    async fn recent_confirmed_content_revalidates_cached_block_after_reorg() -> Result<()> {
        use axum::{Router, response::IntoResponse};
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        let payload = b"recent confirmed content";
        let (mut gateway, id, _, fixture, _) = retrieval_fixture(payload, &[], None).await;
        let _fixture = tokio_util::task::AbortOnDropHandle::new(fixture);
        let height = FORK_2_9_HEIGHT + 1;
        let tip = Arc::new(AtomicU64::new(height - 1));
        let reorg = Arc::new(AtomicBool::new(false));
        let source = gateway.config.trusted_node_url.clone();
        let client = gateway.client.clone();
        let node_tip = Arc::clone(&tip);
        let node_reorg = Arc::clone(&reorg);
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let client = client.clone();
            let url = endpoint(&source, uri.path().trim_start_matches('/'));
            let height = node_tip.load(Ordering::SeqCst);
            let reorg = node_reorg.load(Ordering::SeqCst);
            async move {
                if uri.path() == "/info" {
                    return serde_json::json!({"height": height})
                        .to_string()
                        .into_response();
                }
                if reorg && uri.path().starts_with("/block_index2/") {
                    return vec![0u8; 51].into_response();
                }
                let response = client.get(url).send().await.unwrap();
                (response.status(), response.bytes().await.unwrap()).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        gateway.config.trusted_node_url = format!("http://{}", listener.local_addr()?);
        let _node = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        ensure!(
            gateway.retrieve(&id).await.is_err(),
            "accepted an archival claim ahead of the trusted node"
        );
        tip.store(height, Ordering::SeqCst);
        let data = gateway.retrieve(&id).await?;
        ensure!(data.bytes.read_all(payload.len()).await?.as_ref() == payload);
        ensure!(
            gateway.retrieve(&id).await?.cache_hit,
            "content was not cached"
        );
        reorg.store(true, Ordering::SeqCst);
        ensure!(
            gateway.retrieve(&id).await.is_err(),
            "served a cached orphaned block"
        );
        Ok(())
    }

    #[tokio::test]
    async fn partial_retrieval_skips_unrelated_payload_and_rejects_invalid_items() {
        use std::sync::atomic::Ordering;

        let payload = vec![7; 49_247];
        let (item, item_id) = signed_data_item(&payload, &[]);
        let (other, _) = signed_data_item(&vec![3; 3 * 1024 * 1024], &[]);
        let bundle = encode_bundle(&[&other, &item]);
        let id = URL_SAFE_NO_PAD.encode(item_id);
        let tags: &[(&[u8], &[u8])] =
            &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];
        let (fixture, _, corrupt, server, requests) =
            retrieval_fixture(&bundle, tags, Some((&id, payload.len()))).await;
        let mut config = fixture.config.clone();
        config.max_data_size = payload.len();
        config.max_memory_data_size = 64 * 1024;
        let gateway = Gateway::new(config.clone()).unwrap();
        let data = gateway.retrieve(&id).await.unwrap();
        assert_eq!(data.sha256, hex(&sha256(&[&payload])));
        assert!(
            requests.load(Ordering::SeqCst) <= 3,
            "unrelated chunks were downloaded"
        );
        let Some(IndexingRoot::Partial(root)) = &data.indexing_root else {
            panic!("missing partial parent");
        };
        let fetched = requests.load(Ordering::SeqCst);
        assert!(gateway.retrieve_direct(&root.id).await.is_err());
        assert_eq!(
            requests.load(Ordering::SeqCst),
            fetched,
            "oversized direct root was downloaded"
        );
        corrupt.store(true, Ordering::SeqCst);
        assert!(Gateway::new(config).unwrap().retrieve(&id).await.is_err());
        server.abort();
        assert_eq!(
            data.bytes.read_all(payload.len()).await.unwrap().as_ref(),
            payload
        );
        assert_eq!(
            gateway
                .retrieve(&id)
                .await
                .unwrap()
                .bytes
                .read_all(payload.len())
                .await
                .unwrap()
                .as_ref(),
            payload
        );

        let (worker, _, _, worker_server, _) = retrieval_fixture(&bundle, tags, None).await;
        let Some(IndexingRoot::Partial(root)) = &data.indexing_root else {
            panic!("missing partial root handoff");
        };
        let rebound = root.bytes.with_gateway(&worker).await;
        assert_eq!(
            rebound.hashes().await.unwrap(),
            (sha256(&[&bundle]), sha384(&[&bundle]))
        );
        worker_server.abort();

        let mut invalid = encode_bundle(&[&item]);
        *invalid.last_mut().unwrap() ^= 1;
        let (fixture, _, _, server, _) =
            retrieval_fixture(&invalid, tags, Some((&id, payload.len()))).await;
        let mut config = fixture.config.clone();
        config.max_data_size = invalid.len();
        assert!(Gateway::new(config).unwrap().retrieve(&id).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn alternate_discovery_sources_require_verified_content() {
        use axum::{Router, response::IntoResponse};
        use std::sync::atomic::Ordering;

        let payload = b"verified through an alternate source";
        let (item, item_id) = signed_data_item(payload, &[]);
        let id = URL_SAFE_NO_PAD.encode(item_id);
        let bundle = encode_bundle(&[&item]);
        let tags: &[(&[u8], &[u8])] =
            &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];
        let (fixture, parent_id, corrupt, server, _) = retrieval_fixture(&bundle, tags, None).await;
        let valid = serde_json::json!({
            "data": {"transactions": {"edges": [{
                "node": {"id": id, "bundledIn": {"id": parent_id},
                         "data": {"size": payload.len().to_string()}}
            }]}}
        });
        let mut wrong = valid.clone();
        wrong["data"]["transactions"]["edges"][0]["node"]["data"]["size"] =
            serde_json::json!((payload.len() + 1).to_string());
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let wrong = wrong.to_string();
            let valid = valid.to_string();
            async move {
                match uri.path() {
                    "/stalled" => std::future::pending::<String>().await.into_response(),
                    "/wrong" => wrong.into_response(),
                    "/valid" => valid.into_response(),
                    _ => r#"{"data":{"transactions":{"edges":[]}}}"#.into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let sources = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = fixture.config.clone();
        config.request_timeout = Duration::from_secs(60);
        config.graphql_sources.extend([
            format!("{base}/stalled"),
            format!("{base}/wrong"),
            format!("{base}/valid"),
        ]);
        for bundled_only in [false, true] {
            let gateway = Gateway::new(config.clone()).unwrap();
            let data = tokio::time::timeout(Duration::from_secs(5), async {
                if bundled_only {
                    gateway.retrieve_bundled(&id).await
                } else {
                    gateway.retrieve(&id).await
                }
            })
            .await
            .expect("a stalled source blocked a verified result")
            .unwrap();
            assert_eq!(
                data.bytes.read_all(payload.len()).await.unwrap().as_ref(),
                payload
            );
        }

        config
            .graphql_sources
            .retain(|source| !source.ends_with("/stalled"));
        corrupt.store(true, Ordering::SeqCst);
        let error = Gateway::new(config)
            .unwrap()
            .retrieve(&id)
            .await
            .unwrap_err();
        assert!(!error.is::<ContentNotFound>(), "{error:#}");
        server.abort();

        let (direct, direct_id, _, direct_server, _) = retrieval_fixture(payload, &[], None).await;
        let mut config = direct.config.clone();
        config.graphql_sources = vec![format!("{base}/wrong")];
        let data = Gateway::new(config)
            .unwrap()
            .retrieve(&direct_id)
            .await
            .unwrap();
        assert_eq!(
            data.bytes.read_all(payload.len()).await.unwrap().as_ref(),
            payload
        );
        direct_server.abort();
        sources.abort();
    }

    #[tokio::test]
    async fn chunk_fallback_passes_stalled_and_missing_peers() {
        use axum::{Router, http::StatusCode, response::IntoResponse};

        let payload = b"verified after failed peers";
        let (fixture, id, _, fixture_server, _) = retrieval_fixture(payload, &[], None).await;
        let response = fixture
            .client
            .get(endpoint(&fixture.config.archive_url, "chunk/1"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let response = response.clone();
            async move {
                if uri.path().starts_with("/z-stall/") {
                    std::future::pending::<()>().await;
                }
                if uri.path().starts_with("/3-valid/") {
                    response.into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = fixture.config.clone();
        config.request_timeout = Duration::from_secs(1);
        config.chunk_sources = ["z-stall", "0-missing", "1-missing", "2-missing", "3-valid"]
            .map(|path| format!("{base}/{path}"))
            .to_vec();
        let gateway = Gateway::new(config.clone()).unwrap();
        let data = gateway.retrieve(&id).await.unwrap();
        assert_eq!(
            data.bytes.read_all(payload.len()).await.unwrap().as_ref(),
            payload
        );

        let size = payload.len() as u128;
        let end = note(size);
        let data_root = hash_leaf(&sha256(&[payload]), &end);
        let geometry = Geometry {
            tx_root: hash_leaf(&data_root, &end),
            data_root,
            block_weave_size: size,
            previous_weave_size: 0,
            first_offset: 1,
            end_offset: size,
            data_size: size,
        };
        let gateway = Gateway::new(config).unwrap();
        let source = streaming::ChunkSource::new(&gateway, geometry);
        assert_eq!(
            source.read_at(0, payload.len()).await.unwrap().as_ref(),
            payload
        );
        server.abort();
        fixture_server.abort();
    }

    #[tokio::test]
    async fn concurrent_gateways_share_verified_root_without_disk_cache() {
        let (gateway, id, corrupt, server, requests) =
            retrieval_fixture(b"shared root", &[], None).await;
        let mut worker = Gateway::new(gateway.config.clone()).unwrap();
        worker.direct_cache = Arc::clone(&gateway.direct_cache);
        let (requested, scheduled) = tokio::join!(
            gateway.retrieve_direct_with_tags(&id),
            worker.retrieve_direct_with_tags(&id),
        );
        for root in [requested.unwrap(), scheduled.unwrap()] {
            assert_eq!(
                root.data.bytes.read_all(11).await.unwrap().as_ref(),
                b"shared root"
            );
        }
        assert_eq!(requests.load(std::sync::atomic::Ordering::Relaxed), 1);
        corrupt.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(gateway.retrieve_direct_with_tags(&id).await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn preserves_verified_encoding_and_wire_bytes_through_retrieval() {
        use std::sync::atomic::Ordering;

        // gzip("encoded wire bytes"), including its unchanged trailer.
        const ENCODED: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 75, 205, 75, 206, 79, 73, 77, 81, 40, 207, 44, 74,
            85, 72, 170, 44, 73, 45, 6, 0, 226, 42, 8, 216, 18, 0, 0, 0,
        ];
        let tags: &[(&[u8], &[u8])] = &[
            (b"Content-Encoding", b"\xff"),
            (b"content-encoding", b"gzip"),
            (b"Content-Encoding", b"br"),
        ];
        for bundled in [false, true] {
            let (item, item_id) = signed_data_item(ENCODED, tags);
            let item_id = URL_SAFE_NO_PAD.encode(item_id);
            let bundle = encode_bundle(&[&item]);
            let parent_tags: &[(&[u8], &[u8])] =
                &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];
            let (gateway, id, corrupt_chunk, server, _) = if bundled {
                retrieval_fixture(&bundle, parent_tags, Some((&item_id, ENCODED.len()))).await
            } else {
                retrieval_fixture(ENCODED, tags, None).await
            };
            for cache_hit in [false, true] {
                let verified = gateway.retrieve(&id).await.unwrap();
                assert_eq!(verified.content_encoding.as_deref(), Some("gzip"));
                assert_eq!(
                    verified
                        .bytes
                        .read_all(ENCODED.len())
                        .await
                        .unwrap()
                        .as_ref(),
                    ENCODED
                );
                assert_eq!(verified.content_length, ENCODED.len());
                assert_eq!(verified.sha256, hex(&sha256(&[ENCODED])));
                assert_eq!(
                    verified.etag,
                    format!("\"{}\"", URL_SAFE_NO_PAD.encode(sha256(&[ENCODED])))
                );
                assert_eq!(verified.cache_hit, cache_hit);
            }
            corrupt_chunk.store(true, Ordering::SeqCst);
            let uncached = Gateway::new(gateway.config.clone()).unwrap();
            let (leader, follower) = tokio::join!(uncached.retrieve(&id), uncached.retrieve(&id));
            assert!(!leader.unwrap_err().is::<ContentNotFound>());
            assert!(!follower.unwrap_err().is::<ContentNotFound>());
            server.abort();
        }
        let (gateway, id, _, server, _) = retrieval_fixture(b"", tags, None).await;
        let verified = gateway.retrieve_direct(&id).await.unwrap();
        assert_eq!(verified.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(verified.content_length, 0);
        assert_eq!(verified.sha256, hex(&sha256(&[b""])));
        server.abort();
    }

    #[tokio::test]
    async fn rejects_empty_l1_content_but_serves_empty_bundle_items() {
        let (gateway, id, _, server, _) = retrieval_fixture(b"", &[], None).await;
        for _ in 0..2 {
            assert!(
                gateway
                    .retrieve(&id)
                    .await
                    .unwrap_err()
                    .is::<ContentNotFound>()
            );
        }
        server.abort();

        let (item, item_id) = signed_data_item(b"", &[]);
        let item_id = URL_SAFE_NO_PAD.encode(item_id);
        let bundle = encode_bundle(&[&item]);
        let tags: &[(&[u8], &[u8])] =
            &[(b"Bundle-Format", b"binary"), (b"Bundle-Version", b"2.0.0")];
        let (gateway, id, _, server, _) =
            retrieval_fixture(&bundle, tags, Some((&item_id, 0))).await;
        for _ in 0..2 {
            let data = gateway.retrieve(&id).await.unwrap();
            assert_eq!(data.content_length, 0);
            assert_eq!(data.sha256, hex(&sha256(&[b""])));
        }
        server.abort();
    }

    #[tokio::test]
    async fn rejects_signed_encoding_that_cannot_be_an_http_header() {
        let tags: &[(&[u8], &[u8])] = &[(b"Content-Encoding", b"gzip\r\nX-Injected: true")];
        let (gateway, id, _, server, _) = retrieval_fixture(b"wire bytes", tags, None).await;
        let error = gateway.retrieve(&id).await.unwrap_err();
        assert!(!error.is::<ContentNotFound>());
        server.abort();
    }

    #[tokio::test]
    async fn only_requested_transaction_absence_is_not_found_for_all_waiters() {
        use axum::{Router, http::StatusCode, response::IntoResponse};

        for failure in [
            "requested",
            "discovery-404",
            "malformed-discovery",
            "wrong-discovery",
            "malformed-status",
            "status-503",
            "missing-anchor",
            "missing-parent",
            "redirected-status",
        ] {
            let id = URL_SAFE_NO_PAD.encode([1; 32]);
            let parent = URL_SAFE_NO_PAD.encode([2; 32]);
            let edges = match failure {
                "missing-parent" => serde_json::json!([{
                    "node": {"id": id, "bundledIn": {"id": parent}, "data": {"size": "1"}},
                }]),
                "wrong-discovery" => serde_json::json!([{
                    "node": {"id": parent, "bundledIn": null, "data": {"size": "1"}},
                }]),
                _ => serde_json::json!([]),
            };
            let discovery = serde_json::json!({
                "data": {"transactions": {"edges": edges}},
            })
            .to_string();
            let status = serde_json::json!({
                "block_height": 1_000_000,
                "block_indep_hash": URL_SAFE_NO_PAD.encode([0; 48]),
            })
            .to_string();
            let app = Router::new().fallback(move |uri: axum::http::Uri| {
                let discovery = discovery.clone();
                let status = status.clone();
                async move {
                    if uri.path() == "/graphql" {
                        match failure {
                            "discovery-404" => StatusCode::NOT_FOUND.into_response(),
                            "malformed-discovery" => "{}".into_response(),
                            _ => discovery.into_response(),
                        }
                    } else if uri.path().starts_with("/tx/") && uri.path().ends_with("/status") {
                        match failure {
                            "requested" | "missing-parent" => StatusCode::NOT_FOUND.into_response(),
                            "malformed-status" => "{}".into_response(),
                            "status-503" => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                            "redirected-status" => (
                                StatusCode::FOUND,
                                [(axum::http::header::LOCATION, "/dependency")],
                            )
                                .into_response(),
                            _ => status.into_response(),
                        }
                    } else {
                        StatusCode::NOT_FOUND.into_response()
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let gateway = Gateway::new(
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
            let (leader, follower) = tokio::join!(gateway.retrieve(&id), gateway.retrieve(&id));
            for result in [leader, follower] {
                let error = result.unwrap_err();
                assert_eq!(
                    error.is::<ContentNotFound>(),
                    failure == "requested",
                    "{failure}: {error:#}",
                );
            }
            server.abort();
        }
    }

    async fn check_data_item(signature_type: u16, owner: &[u8], signature: &[u8], data: &[u8]) {
        let item = encode_data_item(signature_type, signature, owner, data, &[0], 0);
        let expected_id = sha256(&[signature]);
        for bytes in [item.clone().into(), spooled_content(&item).await] {
            let verified = verify_data_item(bytes, &expected_id).await.unwrap();
            assert_eq!(
                verified.data.read_all(data.len()).await.unwrap().as_ref(),
                data
            );
            assert_eq!(verified.body_hash, sha256(&[data]));
        }

        let (signature_size, _) = data_item_signature_sizes(signature_type).unwrap();
        let mut wrong_signature = item.clone();
        wrong_signature[2] ^= 1;
        let wrong_id = sha256(&[&wrong_signature[2..2 + signature_size]]);
        assert!(
            verify_data_item(wrong_signature.into(), &wrong_id)
                .await
                .is_err()
        );

        let mut wrong_owner = item.clone();
        wrong_owner[2 + signature_size] ^= 1;
        assert!(
            verify_data_item(wrong_owner.into(), &expected_id)
                .await
                .is_err()
        );

        let mut wrong_data = item;
        *wrong_data.last_mut().unwrap() ^= 1;
        assert!(
            verify_data_item(wrong_data.into(), &expected_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verifies_items_with_zero_tag_bytes() {
        let data = b"untagged";
        let key = Ed25519SigningKey::from_bytes(&[2; 32]);
        let owner = key.verifying_key().to_bytes();
        let payload = data_item_signature_payload(2, &owner, &[], &[], &[], deep_hash_blob(data));
        let signature = key.sign(&payload).to_bytes();
        let id = sha256(&[&signature]);
        let bytes = encode_data_item(2, &signature, &owner, data, &[], 0);
        let item = verify_data_item(bytes.into(), &id).await.unwrap();
        assert_eq!(item.data.read_all(data.len()).await.unwrap().as_ref(), data);
        assert!(item.metadata(&id).tags.is_empty());
        let inconsistent = encode_data_item(2, &signature, &owner, data, &[], 1);
        assert!(verify_data_item(inconsistent.into(), &id).await.is_err());
    }

    #[tokio::test]
    async fn verified_item_metadata_preserves_raw_tags_and_derives_only_valid_text() {
        let tags: &[(&[u8], &[u8])] = &[
            (b"Content-Type", b"\xff"),
            (b"content-type", b"text/plain"),
            (b"Content-Encoding", b"\0gzip"),
            (b"content-encoding", b"gzip"),
            (b"\0\xff", b"\xff\0"),
        ];
        let (encoded, id) = signed_data_item(b"raw tag payload", tags);
        let verified = verify_data_item(encoded.into(), &id).await.unwrap();
        let metadata = verified.metadata(&id);
        assert_eq!(
            metadata.tags,
            tags.iter()
                .map(|(name, value)| (name.to_vec(), value.to_vec()))
                .collect::<Vec<_>>()
        );
        assert_eq!(metadata.content_type.as_deref(), Some("text/plain"));
        assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
        assert_eq!(metadata.owner_address, sha256(&[&verified.owner]));
    }

    fn recoverable_signature(key: &Secp256k1SigningKey, digest: &[u8; 32]) -> Vec<u8> {
        let (signature, recovery_id) = key.sign_prehash_recoverable(digest);
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery_id.to_byte() + 27);
        bytes
    }

    #[test]
    fn validates_leaf_paths_and_rejects_corruption() {
        let body = br#"{"hello":"arweave"}"#;
        let data_hash = sha256(&[body]);
        let end = note(body.len() as u128);
        let root = hash_leaf(&data_hash, &end);
        let mut path = Vec::from(data_hash);

        path.extend_from_slice(&end);

        let data = validate_data_path(
            &root,
            body.len() as u128,
            0,
            MERKLE_REBASE_SUPPORT_THRESHOLD,
            &path,
        )
        .unwrap();
        assert_eq!((data.start, data.end), (0, body.len() as u128));
        assert_eq!(data.data_hash, data_hash);

        path[0] ^= 1;
        assert!(validate_data_path(&root, body.len() as u128, 0, 0, &path).is_err());
    }
    #[test]
    fn decodes_binary_block_index() {
        let mut encoded = vec![7; 48];
        encoded.extend_from_slice(&2_u16.to_be_bytes());
        encoded.extend_from_slice(&1_145_u16.to_be_bytes());
        encoded.push(32);
        encoded.extend_from_slice(&[9; 32]);
        let entries = decode_block_index(&encoded).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hash, URL_SAFE_NO_PAD.encode([7; 48]));
        assert_eq!(entries[0].weave_size, 1_145);
        assert_eq!(entries[0].tx_root, URL_SAFE_NO_PAD.encode([9; 32]));
        encoded.pop();
        assert!(decode_block_index(&encoded).is_err());
    }

    #[test]
    fn rejects_corrupt_chunk_proofs_and_geometry() {
        let body = br#"{"hello":"arweave"}"#;
        let data_hash = sha256(&[body]);
        let data_end = note(body.len() as u128);
        let data_root = hash_leaf(&data_hash, &data_end);
        let data_path = [data_hash.as_slice(), data_end.as_slice()].concat();
        let tx_end = note(body.len() as u128);
        let tx_root = hash_leaf(&data_root, &tx_end);
        let tx_path = [data_root.as_slice(), tx_end.as_slice()].concat();
        let chunk = || JsonChunk {
            chunk: URL_SAFE_NO_PAD.encode(body),
            data_path: URL_SAFE_NO_PAD.encode(&data_path),
            tx_path: URL_SAFE_NO_PAD.encode(&tx_path),
        };
        let mut geometry = Geometry {
            tx_root,
            data_root,
            block_weave_size: 1_145,
            previous_weave_size: 1_000,
            first_offset: 1_001,
            end_offset: 1_019,
            data_size: body.len() as u128,
        };

        assert_eq!(
            verify_chunk_range(chunk(), 1_001, 0, &geometry)
                .unwrap()
                .bytes,
            body
        );
        let proof = verify_chunk_proof(
            chunk(),
            1_006,
            &BlockGeometry {
                tx_root,
                block_weave_size: 1_145,
                previous_weave_size: 1_000,
            },
        )
        .unwrap();
        assert_eq!(proof.relative_offset, 5);
        assert_eq!((proof.data.start, proof.data.end), (0, body.len() as u128));

        let mut corrupt_bytes = chunk();
        corrupt_bytes.chunk = URL_SAFE_NO_PAD.encode(b"corrupt");
        assert!(verify_chunk_range(corrupt_bytes, 1_001, 0, &geometry).is_err());

        let mut incomplete_data_path = chunk();
        incomplete_data_path.data_path = URL_SAFE_NO_PAD.encode(&data_path[..data_path.len() - 1]);
        assert!(verify_chunk_range(incomplete_data_path, 1_001, 0, &geometry).is_err());

        let mut incomplete_tx_path = chunk();
        incomplete_tx_path.tx_path = URL_SAFE_NO_PAD.encode(&tx_path[..tx_path.len() - 1]);
        assert!(verify_chunk_range(incomplete_tx_path, 1_001, 0, &geometry).is_err());

        geometry.data_root[0] ^= 1;
        assert!(verify_chunk_range(chunk(), 1_001, 0, &geometry).is_err());
        geometry.data_root[0] ^= 1;

        geometry.end_offset += 1;
        assert!(verify_chunk_range(chunk(), 1_001, 0, &geometry).is_err());
    }

    #[test]
    fn normalizes_content_type_and_bounds_data_size() {
        assert_eq!(
            response_content_type("Application/JSON".to_owned()),
            "Application/JSON; charset=utf-8"
        );
        assert_eq!(
            response_content_type("Text/Plain; Charset=ISO-8859-1".to_owned()),
            "Text/Plain; Charset=ISO-8859-1"
        );
        assert_eq!(response_content_type("image/png".to_owned()), "image/png");
        assert_eq!(checked_data_size(145, 1024).unwrap(), 145);
        assert!(checked_data_size(1025, 1024).is_err());
    }

    #[test]
    fn authenticates_block_metadata_and_transaction_ids() {
        let transaction_id = URL_SAFE_NO_PAD.encode([3u8; 32]);
        let tx_root = URL_SAFE_NO_PAD.encode([2u8; 32]);
        let mut block = BlockHeader {
            height: 1_000_000,
            previous_block: String::new(),
            timestamp: 1,
            nonce: URL_SAFE_NO_PAD.encode([1u8]),
            last_retarget: 1,
            diff: "1".to_owned(),
            cumulative_diff: "1".to_owned(),
            reward_pool: "0".to_owned(),
            wallet_list: String::new(),
            hash_list_merkle: String::new(),
            hash: String::new(),
            block_size: "1".to_owned(),
            weave_size: "1".to_owned(),
            tx_root: tx_root.clone(),
            reward_addr: "unclaimed".to_owned(),
            txs: vec![transaction_id.clone()],
            packing_2_5_threshold: "0".to_owned(),
            strict_data_split_threshold: "0".to_owned(),
            usd_to_ar_rate: ["1".to_owned(), "1".to_owned()],
            scheduled_usd_to_ar_rate: ["1".to_owned(), "1".to_owned()],
            poa: BlockPoa {
                option: "1".to_owned(),
                ..BlockPoa::default()
            },
            ..BlockHeader::default()
        };
        block.indep_hash = URL_SAFE_NO_PAD.encode(block_indep_hash(&block).unwrap());
        let mut entry = BlockIndexEntry {
            tx_root,
            weave_size: "1".to_owned(),
            hash: block.indep_hash.clone(),
        };

        verify_block_header(&block, &entry, block.height, Some(&transaction_id)).unwrap();
        let absent_id = URL_SAFE_NO_PAD.encode([4u8; 32]);
        assert!(verify_block_header(&block, &entry, block.height, Some(&absent_id)).is_err());

        block.tx_root.clear();
        entry.tx_root.clear();
        block.indep_hash = URL_SAFE_NO_PAD.encode(block_indep_hash(&block).unwrap());
        entry.hash = block.indep_hash.clone();
        verify_block_header(&block, &entry, block.height, Some(&transaction_id)).unwrap();

        block.txs[0] = absent_id;
        assert!(verify_block_header(&block, &entry, block.height, Some(&transaction_id)).is_err());
    }

    #[tokio::test]
    async fn verifies_all_supported_ans104_signature_types() {
        const DATA: &[u8] = b"ANS-104 signature parity";
        const RAW_TAGS: &[u8] = &[0];

        let ed25519 = Ed25519SigningKey::from_bytes(&[2; 32]);
        let ed25519_owner = ed25519.verifying_key().to_bytes();
        let payload = data_item_signature_payload(
            2,
            &ed25519_owner,
            &[],
            &[],
            RAW_TAGS,
            deep_hash_blob(DATA),
        );
        let signature = ed25519.sign(&payload).to_bytes();
        check_data_item(2, &ed25519_owner, &signature, DATA).await;

        let secp256k1 = Secp256k1SigningKey::from_slice(&[3; 32]).unwrap();
        let ethereum_owner = secp256k1
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let payload = data_item_signature_payload(
            3,
            &ethereum_owner,
            &[],
            &[],
            RAW_TAGS,
            deep_hash_blob(DATA),
        );
        let signature = recoverable_signature(&secp256k1, &ethereum_message_hash(&payload));
        check_data_item(3, &ethereum_owner, &signature, DATA).await;

        let payload = data_item_signature_payload(
            4,
            &ed25519_owner,
            &[],
            &[],
            RAW_TAGS,
            deep_hash_blob(DATA),
        );
        let signature = ed25519.sign(hex(&payload).as_bytes()).to_bytes();
        check_data_item(4, &ed25519_owner, &signature, DATA).await;

        let payload = data_item_signature_payload(
            5,
            &ed25519_owner,
            &[],
            &[],
            RAW_TAGS,
            deep_hash_blob(DATA),
        );
        let message = format!("APTOS\nmessage: {}\nnonce: bundlr", hex(&payload));
        let signature = ed25519.sign(message.as_bytes()).to_bytes();
        check_data_item(5, &ed25519_owner, &signature, DATA).await;

        let second_ed25519 = Ed25519SigningKey::from_bytes(&[4; 32]);
        let mut multisig_owner = vec![0; 1_025];
        multisig_owner[..32].copy_from_slice(&ed25519_owner);
        multisig_owner[32..64].copy_from_slice(&second_ed25519.verifying_key().to_bytes());
        multisig_owner[1_024] = 2;
        let payload = data_item_signature_payload(
            6,
            &multisig_owner,
            &[],
            &[],
            RAW_TAGS,
            deep_hash_blob(DATA),
        );
        let mut multisignature = vec![0; 2_052];
        multisignature[..64].copy_from_slice(&ed25519.sign(&payload).to_bytes());
        multisignature[64..128].copy_from_slice(&second_ed25519.sign(&payload).to_bytes());
        multisignature[2_048] = 0b1100_0000;
        check_data_item(6, &multisig_owner, &multisignature, DATA).await;
        multisignature[2_048] = 0b1000_0000;
        let insufficient = encode_data_item(6, &multisignature, &multisig_owner, DATA, &[0], 0);
        assert!(
            verify_data_item(insufficient.into(), &sha256(&[&multisignature]))
                .await
                .is_err(),
            "Aptos multisignature must meet its owner threshold"
        );

        let public_key = secp256k1.verifying_key().to_sec1_point(false);
        let public_key_hash = keccak256(&[&public_key.as_bytes()[1..]]);
        let address: [u8; 20] = public_key_hash[12..].try_into().unwrap();
        let typed_owner = format!("0x{}", hex(&address)).into_bytes();
        let payload =
            data_item_signature_payload(7, &typed_owner, &[], &[], RAW_TAGS, deep_hash_blob(DATA));
        let signature =
            recoverable_signature(&secp256k1, &typed_ethereum_message_hash(&payload, &address));
        check_data_item(7, &typed_owner, &signature, DATA).await;

        assert!(data_item_signature_sizes(8).is_err());
    }

    #[tokio::test]
    async fn verifies_legacy_binary_item_and_rejects_mutations() {
        let bundle = include_bytes!("../tests/fixtures/legacy-bundle-752520.bin");
        let id = decode_fixed::<32>(
            "eATXzsBk9otMqBAxps_afQpjWd0C7rbPV8sB85S2Uvg",
            "data item ID",
        )
        .unwrap();
        let item = &bundle[96..];
        for bytes in [item.to_vec().into(), spooled_content(item).await] {
            let verified = verify_data_item(bytes, &id).await.unwrap();
            assert_eq!(verified.data.read_all(4).await.unwrap().as_ref(), b"test");
            assert_eq!(verified.body_hash, sha256(&[b"test"]));
        }
        for offset in [0, 512, 1024, 1042] {
            let mut corrupt = item.to_vec();
            corrupt[offset] ^= 1;
            let corrupt_id = sha256(&[&corrupt[..512]]);
            assert!(verify_data_item(corrupt.into(), &corrupt_id).await.is_err());
        }
        assert!(
            verify_data_item(item[..1042].to_vec().into(), &id)
                .await
                .is_err()
        );
        let mut prefixed = vec![1, 0];
        prefixed.extend_from_slice(item);
        assert!(verify_data_item(prefixed.into(), &id).await.is_err());
        let modern = include_bytes!("../tests/fixtures/lolcchekc-item.bin");
        let modern_id = sha256(&[&modern[2..514]]);
        assert!(
            verify_data_item(modern[2..].to_vec().into(), &modern_id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn legacy_binary_item_authenticates_tag_bytes() {
        let item = include_bytes!("../tests/fixtures/legacy-tagged-item-752923.bin");
        let id = decode_fixed::<32>(
            "-tlWxtdMmgp9B2MIY1AkBjmRkdVHERzVkbiVG5I370s",
            "data item ID",
        )
        .unwrap();
        let verified = verify_data_item(spooled_content(item).await, &id)
            .await
            .unwrap();
        assert_eq!(verified.tags[0].name.as_ref(), b"Content-Type");
        assert_eq!(verified.tags[0].value.as_ref(), b"text/plain");
        assert_eq!(
            hex(&verified.body_hash),
            "e963887bc1aff36d4066c783226da5a23757d7d5f288c90f6d0a38a0ba13bc97"
        );
        let mut corrupt = item.to_vec();
        let tag = corrupt
            .windows(b"text/plain".len())
            .position(|bytes| bytes == b"text/plain")
            .unwrap();
        corrupt[tag] = b'n';
        assert!(verify_data_item(corrupt.into(), &id).await.is_err());
    }

    #[tokio::test]
    async fn verifies_ans104_item_and_rejects_mutations() {
        const ID: &str = "3F_yldqW_zt6Ci_47w-7O76lPpegpu1rs7H2iyultVY";
        let item = include_bytes!("../tests/fixtures/lolcchekc-item.bin");
        let expected_id = decode_fixed::<32>(ID, "data item ID").unwrap();
        let verified = verify_data_item(spooled_content(item).await, &expected_id)
            .await
            .unwrap();
        assert_eq!(verified.data.len(), 2_982);
        assert_eq!(
            hex(&verified.body_hash),
            "4d02c735657b171d1a3d3bc9ddd7ee396cdf5232e11d6adb06826637c3b9070c"
        );
        assert_eq!(item_content_type(&verified.tags).unwrap(), "text/html");

        let mut bundle = Vec::with_capacity(32 + BUNDLE_ENTRY_SIZE + item.len());
        bundle.extend_from_slice(&1u64.to_le_bytes());
        bundle.extend_from_slice(&[0; 24]);
        bundle.extend_from_slice(&(item.len() as u64).to_le_bytes());
        bundle.extend_from_slice(&[0; 24]);
        bundle.extend_from_slice(&expected_id);
        bundle.extend_from_slice(item);
        assert_eq!(
            verify_bundle_item(
                bundle.clone().into(),
                BundleFormat::Binary,
                &expected_id,
                None,
                None
            )
            .await
            .unwrap()
            .0
            .data
            .read_all(2_982)
            .await
            .unwrap(),
            verified.data.read_all(2_982).await.unwrap()
        );

        let mut wrong_id = bundle.clone();
        wrong_id[64] ^= 1;
        assert!(
            verify_bundle_item(
                wrong_id.into(),
                BundleFormat::Binary,
                &expected_id,
                None,
                None
            )
            .await
            .is_err()
        );

        let mut wrong_size = bundle.clone();
        wrong_size[32] ^= 1;
        assert!(
            verify_bundle_item(
                wrong_size.into(),
                BundleFormat::Binary,
                &expected_id,
                None,
                None
            )
            .await
            .is_err()
        );

        let mut truncated = bundle;
        truncated.pop();
        assert!(
            verify_bundle_item(
                truncated.into(),
                BundleFormat::Binary,
                &expected_id,
                None,
                None
            )
            .await
            .is_err()
        );

        let (signature_size, _) = data_item_signature_sizes(1).unwrap();
        let mut wrong_signature = item.to_vec();
        wrong_signature[2] ^= 1;
        let wrong_signature_id = sha256(&[&wrong_signature[2..2 + signature_size]]);
        assert!(
            verify_data_item(wrong_signature.into(), &wrong_signature_id)
                .await
                .is_err()
        );

        let mut wrong_owner = item.to_vec();
        wrong_owner[2 + signature_size] ^= 1;
        assert!(
            verify_data_item(wrong_owner.into(), &expected_id)
                .await
                .is_err()
        );

        let mut wrong_payload = item.to_vec();
        let payload_start = item.len() - verified.data.len();
        wrong_payload[payload_start] ^= 1;
        assert!(
            verify_data_item(wrong_payload.into(), &expected_id)
                .await
                .is_err()
        );

        assert!(
            verify_data_item(item[..2 + signature_size].to_vec().into(), &expected_id)
                .await
                .is_err()
        );
    }

    #[test]
    fn validates_transaction_geometry_and_rejects_wrong_root() {
        let data_root = [7; 32];
        let end = note(145);
        let root = hash_leaf(&data_root, &end);
        let mut path = Vec::from(data_root);
        path.extend_from_slice(&end);

        let transaction = validate_tx_path(&root, 1_001, 1_145, 1_000, &path).unwrap();
        assert_eq!(transaction.data_root, data_root);
        assert_eq!(transaction.start_bound, 1_000);
        assert_eq!(transaction.end_offset, 1_145);
        assert_eq!(transaction.size, 145);

        assert!(validate_tx_path(&[0; 32], 1_001, 1_145, 1_000, &path).is_err());
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn data(id: &str) -> VerifiedData {
        VerifiedData {
            bytes: b"hello".to_vec().into(),
            cache_hit: false,
            id: id.to_owned(),
            block_height: 1,
            block_hash: None,
            stable_anchor: true,
            content_type: "text/plain".to_owned(),
            content_encoding: None,
            content_length: 5,
            etag: String::new(),
            sha256: String::new(),
            indexing_root: None,
        }
    }

    fn gateway() -> Gateway {
        let mut config = Config::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            vec!["http://127.0.0.1:1".to_owned()],
            Duration::from_millis(50),
            1,
            1024,
        )
        .unwrap();
        config.retrieval_timeout = Duration::from_millis(50);
        Gateway::new(config).unwrap()
    }

    #[test]
    fn bounds_cache_and_retains_recently_used_content() {
        for (entries, bytes) in [(2, 1024), (100, data("a").cache_bytes() * 2)] {
            let mut cache = ContentCache::default();
            cache.insert(data("a"), entries, bytes);
            cache.insert(data("b"), entries, bytes);
            assert!(cache.get("a").unwrap().cache_hit);
            cache.insert(data("c"), entries, bytes);
            assert!(cache.get("b").is_none());
            assert!(cache.get("a").is_some());
            assert!(cache.get("c").is_some());
            cache.insert(data("oversized"), entries, 4);
            assert!(cache.get("oversized").is_none());
        }
        let mut cache = ContentCache::default();
        let mut small_view = data("slice");
        small_view.bytes = Content::from(vec![0; 32]).slice(0..1).unwrap();
        small_view.content_length = 1;
        cache.insert(small_view, 2, 8);
        assert!(cache.get("slice").is_none());
    }

    #[tokio::test]
    async fn shares_cold_results_and_only_caches_success() {
        let mut gateway = gateway();
        for limit in [1024, 4] {
            gateway.config.cache_max_bytes = limit;
            let id = limit.to_string();
            let (leader, follower) = tokio::join!(
                gateway.retrieve_cached(&gateway.cache, &id, true, async {
                    tokio::task::yield_now().await;
                    Ok(data(&id))
                }),
                gateway.retrieve_cached(&gateway.cache, &id, true, async {
                    panic!("duplicate retrieval")
                })
            );
            let leader = leader.unwrap();
            let follower = follower.unwrap();
            assert!(!leader.cache_hit && !follower.cache_hit);
            let next = gateway
                .retrieve_cached(&gateway.cache, &id, true, async { Ok(data(&id)) })
                .await
                .unwrap();
            assert_eq!(next.cache_hit, limit >= 5);
        }
        let (leader, follower) = tokio::join!(
            gateway.retrieve_cached(&gateway.cache, "failure", true, async {
                tokio::task::yield_now().await;
                bail!("bad proof")
            }),
            gateway.retrieve_cached(&gateway.cache, "failure", true, async {
                panic!("duplicate retrieval")
            })
        );
        assert!(leader.is_err() && follower.is_err());
        assert!(
            !gateway
                .retrieve_cached(&gateway.cache, "failure", true, async {
                    Ok(data("failure"))
                })
                .await
                .unwrap()
                .cache_hit
        );
    }

    #[tokio::test]
    async fn cancellation_and_deadlines_release_followers() {
        let gateway = gateway();
        let mut leader = Box::pin(gateway.retrieve_cached(
            &gateway.cache,
            "cancel",
            true,
            std::future::pending(),
        ));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(leader.as_mut().poll(cx).is_pending())
            })
            .await
        );
        let mut follower = Box::pin(gateway.retrieve_cached(
            &gateway.cache,
            "cancel",
            true,
            async { panic!("duplicate") },
        ));
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(follower.as_mut().poll(cx).is_pending())
            })
            .await
        );
        drop(leader);
        assert!(follower.await.unwrap_err().to_string().contains("canceled"));
        assert!(
            !gateway
                .retrieve_cached(&gateway.cache, "cancel", true, async { Ok(data("cancel")) })
                .await
                .unwrap()
                .cache_hit
        );

        let mut leader = Box::pin(gateway.retrieve_cached(
            &gateway.cache,
            "timeout",
            true,
            std::future::pending(),
        ));
        std::future::poll_fn(|cx| {
            assert!(leader.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let follower = gateway
            .retrieve_cached(&gateway.cache, "timeout", true, async {
                panic!("duplicate")
            })
            .await;
        assert!(follower.unwrap_err().to_string().contains("timed out"));
        assert!(leader.await.unwrap_err().to_string().contains("timed out"));
        assert!(
            !gateway
                .retrieve_cached(&gateway.cache, "timeout", true, async {
                    Ok(data("timeout"))
                })
                .await
                .unwrap()
                .cache_hit
        );
    }

    #[tokio::test]
    async fn cpu_jobs_leave_runtime_responsive_and_keep_permits_until_completion() -> Result<()> {
        let mut jobs = Vec::new();
        let mut releases = Vec::new();
        for _ in 0..background::CPU_JOBS {
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            jobs.push(tokio::spawn(BACKGROUND_CPU.scope(
                (),
                cpu_work(move || {
                    let _ = started.send(());
                    wait.recv_timeout(Duration::from_secs(5))?;
                    Ok(())
                }),
            )));
            releases.push(release);
            ready.await?;
        }
        let http_result = tokio::time::timeout(Duration::from_secs(1), cpu_work(|| Ok(7))).await;
        let mut waiting = Box::pin(BACKGROUND_CPU.scope((), cpu_work(|| Ok(42))));
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        jobs[0].abort();
        assert!(jobs.remove(0).await.unwrap_err().is_cancelled());
        std::future::poll_fn(|cx| {
            assert!(waiting.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        releases.remove(0).send(())?;
        assert_eq!(waiting.await?, 42);
        for release in releases {
            release.send(())?;
        }
        for job in jobs {
            job.await??;
        }
        assert_eq!(http_result??, 7);
        Ok(())
    }
}
