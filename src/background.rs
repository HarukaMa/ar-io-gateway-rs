use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, sleep_until, timeout},
};

use crate::{
    Config, ContentCache, Gateway, MAX_JSON_BYTES, VerifiedRoot, database::BlockStore,
    disk_cache::DiskCache, indexer::index_bundle_content, require_bundle_tags,
};

use futures_util::{StreamExt, stream::FuturesUnordered};
const MAX_JOBS: usize = 8;
pub(crate) const INDEX_WORKERS: usize = 8;
pub(crate) const CPU_JOBS: usize = 8;
// Each root can retain an ancestor parser plus one being checked at the depth limit.
// Keep capacity for verification and file I/O beyond those blocked parsers.
pub(crate) const BLOCKING_THREADS: usize = INDEX_WORKERS * (crate::MAX_BUNDLE_DEPTH + 1) + CPU_JOBS;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

struct WorkerStatus {
    chain: &'static str,
    bundles: &'static str,
    last_failure: Option<serde_json::Value>,
}

struct Admission {
    state: Mutex<AdmissionState>,
    max_bytes: usize,
    max_jobs: usize,
    max_scheduled_jobs: usize,
    max_scheduled_bytes: usize,
    changed: tokio::sync::Notify,
    last_indexed_at: AtomicU64,
    status: Mutex<WorkerStatus>,
}

struct AdmissionState {
    ids: HashMap<[u8; 32], Arc<crate::profiling::Profile>>,
    bytes: usize,
    scheduled_bytes: usize,
    scheduled_jobs: usize,
    closed: bool,
}

impl Admission {
    fn new(max_bytes: usize, max_jobs: usize, request_headroom: bool) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(WorkerStatus {
                chain: "disabled",
                bundles: "idle",
                last_failure: None,
            }),
            state: Mutex::new(AdmissionState {
                ids: HashMap::with_capacity(max_jobs),
                bytes: 0,
                scheduled_bytes: 0,
                closed: false,
                scheduled_jobs: 0,
            }),
            max_bytes,
            max_jobs,
            max_scheduled_jobs: if request_headroom {
                max_jobs - MAX_JOBS
            } else {
                max_jobs
            },
            max_scheduled_bytes: if request_headroom {
                max_bytes / 2
            } else {
                max_bytes
            },
            changed: tokio::sync::Notify::new(),
            last_indexed_at: AtomicU64::new(0),
        })
    }

    fn reserve(self: &Arc<Self>, id: [u8; 32], bytes: usize) -> Option<Reservation> {
        self.reserve_inner(id, bytes, false)
    }

    fn reserve_inner(
        self: &Arc<Self>,
        id: [u8; 32],
        bytes: usize,
        scheduled: bool,
    ) -> Option<Reservation> {
        // Contention is backpressure too: HTTP never waits for the worker.
        let mut state = self.state.try_lock()?;
        if state.closed
            || state.ids.len() == self.max_jobs
            || state.ids.contains_key(&id)
            || bytes > self.max_bytes - state.bytes
            || (scheduled && bytes > self.max_scheduled_bytes - state.scheduled_bytes)
            || (scheduled && state.scheduled_jobs == self.max_scheduled_jobs)
        {
            return None;
        }
        let profile = crate::profiling::Profile::new(URL_SAFE_NO_PAD.encode(id));
        state.ids.insert(id, Arc::clone(&profile));
        state.bytes += bytes;
        if scheduled {
            state.scheduled_bytes += bytes;
            state.scheduled_jobs += 1;
        }
        Some(Reservation {
            admission: Arc::clone(self),
            id,
            bytes,
            scheduled,
            profile,
        })
    }

    fn reserve_scheduled(self: &Arc<Self>, id: [u8; 32], data_size: usize) -> Option<Reservation> {
        let bytes = data_size.checked_add(MAX_JSON_BYTES)?;
        self.reserve_inner(id, bytes, true)
    }

    fn indexed(&self, count: u64) {
        if count > 0 {
            if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
                self.last_indexed_at.store(now.as_secs(), Ordering::Relaxed);
            }
        }
    }

    fn failed(&self, message: &'static str) {
        self.status.lock().last_failure = Some(serde_json::json!({
            "message": message,
            "at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        }));
    }
}

struct Reservation {
    admission: Arc<Admission>,
    id: [u8; 32],
    bytes: usize,
    scheduled: bool,
    profile: Arc<crate::profiling::Profile>,
}

impl Reservation {
    fn shrink(&mut self, bytes: usize) -> Result<()> {
        ensure!(
            bytes <= self.bytes,
            "bundle exceeds retained-byte reservation"
        );
        let mut state = self.admission.state.lock();
        state.bytes -= self.bytes - bytes;
        if self.scheduled {
            state.scheduled_bytes -= self.bytes - bytes;
        }
        self.bytes = bytes;
        self.admission.changed.notify_one();
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.profile.finish("cancelled");
        let mut state = self.admission.state.lock();
        state.ids.remove(&self.id);
        state.bytes -= self.bytes;
        if self.scheduled {
            state.scheduled_bytes -= self.bytes;
            state.scheduled_jobs -= 1;
        }
        self.admission.changed.notify_one();
    }
}

enum JobContent {
    Complete(Arc<VerifiedRoot>),
    Streamed { height: u64 },
    Partial(Arc<crate::AuthenticatedRoot>),
}

struct Job {
    // Content and metadata are dropped before their admission is released.
    root: JobContent,
    reservation: Reservation,
}

pub(crate) struct BundleSubmitter {
    sender: mpsc::Sender<Job>,
    admission: Arc<Admission>,
}

impl BundleSubmitter {
    pub(crate) fn submit(&self, root: &Arc<VerifiedRoot>) {
        let mut id = [0; 32];
        if !matches!(URL_SAFE_NO_PAD.decode_slice(&root.data.id, &mut id), Ok(32))
            || root
                .metadata_bytes()
                .saturating_add(std::mem::size_of::<Job>())
                > MAX_JSON_BYTES
            || require_bundle_tags(&root.tags).is_err()
        {
            return;
        }
        let Some(reservation) = self.admission.reserve(id, job_bytes(root)) else {
            return;
        };
        let Ok(permit) = self.sender.try_reserve() else {
            return;
        };
        permit.send(Job {
            root: JobContent::Complete(Arc::clone(root)),
            reservation,
        });
    }

    pub(crate) fn submit_partial(&self, root: &Arc<crate::AuthenticatedRoot>) {
        let Ok(id) = crate::decode_fixed::<32>(&root.id, "bundle root ID") else {
            return;
        };
        let metadata = root
            .metadata_bytes()
            .saturating_add(std::mem::size_of::<Job>());
        if metadata > MAX_JSON_BYTES || require_bundle_tags(&root.tags).is_err() {
            return;
        }
        let Some(reservation) = self.admission.reserve(
            id,
            metadata.saturating_add(root.bytes.len().max(root.bytes.resident_len())),
        ) else {
            return;
        };
        let Ok(permit) = self.sender.try_reserve() else {
            return;
        };
        permit.send(Job {
            root: JobContent::Partial(Arc::clone(root)),
            reservation,
        });
    }

    pub(crate) fn last_indexed_at(&self) -> u64 {
        self.admission.last_indexed_at.load(Ordering::Relaxed)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    pub(crate) fn status(&self) -> serde_json::Value {
        let status = self.admission.status.lock();
        serde_json::json!({
            "running": !self.is_closed(),
            "chain": status.chain,
            "bundles": if status.bundles == "idle" && !self.admission.state.lock().ids.is_empty() {
                "fetching or queued"
            } else { status.bundles },
            "last_failure": status.last_failure,
        })
    }
}

fn job_bytes(root: &VerifiedRoot) -> usize {
    root.retained_bytes()
        .saturating_add(std::mem::size_of::<Job>())
}

pub struct BundleWorker {
    cancel: Option<oneshot::Sender<()>>,
    finished: Option<oneshot::Receiver<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
    admission: Arc<Admission>,
}

impl BundleWorker {
    fn cancel(&mut self) {
        self.admission.state.lock().closed = true;
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        self.cancel();
        if let Some(finished) = self.finished.take() {
            let _ = finished.await;
        }
        let thread = self.thread.take().expect("bundle worker thread");
        tokio::task::spawn_blocking(move || {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("bundle worker thread panicked"))?
        })
        .await
        .context("joining bundle worker")?
    }
}

impl Drop for BundleWorker {
    fn drop(&mut self) {
        self.cancel();
        // Do not block an HTTP runtime in Drop. The cancelled thread owns and drops
        // its runtime, receiver and DB drivers; no submitter is retained by that thread.
    }
}

pub(crate) async fn start(
    config: Config,
    disk_cache: Option<DiskCache>,
    database_url: String,
    direct_cache: Arc<std::sync::Mutex<ContentCache>>,
    peers: Arc<crate::peers::PeerState>,
) -> Result<(BundleSubmitter, BundleWorker)> {
    let admission = Admission::new(
        config.index_max_bytes,
        config.index_downloads + MAX_JOBS,
        true,
    );
    admission.status.lock().chain = if config.index_chain {
        "starting"
    } else {
        "disabled"
    };
    let (sender, receiver) = mpsc::channel(MAX_JOBS);
    let (cancel, mut cancelled) = oneshot::channel();
    let (ready, readiness) = oneshot::channel();
    let (finished, completion) = oneshot::channel();
    let worker_admission = Arc::clone(&admission);
    let thread = thread::Builder::new()
        .name("bundle-indexer".to_owned())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("bundle-worker")
                    .enable_all()
                    .max_blocking_threads(BLOCKING_THREADS)
                    .build()
                    .context("creating bundle worker runtime")?;
                let result = runtime.block_on(crate::BACKGROUND_CPU.scope((), async move {
                    let startup_timeout = config.request_timeout.saturating_mul(3);
                    let initialize = async {
                        let mut gateway = Gateway::new(config)?.with_database(&database_url).await?;
                        gateway.disk_cache = disk_cache;
                        gateway.direct_cache = direct_cache;
                        gateway.peers = peers;
                        let store = BlockStore::connect(&database_url).await?;
                        // Fail startup if the bundle schema is absent. Never migrate here.
                        store.require_bundle_schema().await?;
                        let chain_store = if gateway.config.index_chain {
                            Some(BlockStore::connect(&database_url).await?)
                        } else {
                            None
                        };
                        Ok::<_, anyhow::Error>((Arc::new(gateway), store, chain_store))
                    };
                    let (gateway, store, mut chain_store) = tokio::select! {
                        biased;
                        _ = &mut cancelled => return Ok(()),
                        result = timeout(startup_timeout, initialize) => {
                            result.context("initializing bundle worker timed out")??
                        }
                    };
                    if ready.send(()).is_err() {
                        return Ok(());
                    }
                    let follow_chain = async {
                        let Some(store) = chain_store.as_mut() else {
                            return std::future::pending::<Result<()>>().await;
                        };
                        loop {
                            worker_admission.status.lock().chain = "indexing";
                            match crate::indexer::follow_chain_step(&gateway, store).await {
                                Ok(true) => tokio::task::yield_now().await,
                                result => {
                                    worker_admission.status.lock().chain = if result.is_err() { "retrying" } else { "waiting" };
                                    if let Err(error) = result {
                                        eprintln!("following chain failed: {error:#}");
                                        worker_admission.failed("Chain indexing failed");
                                    }
                                    tokio::time::sleep(RETRY_INTERVAL).await;
                                }
                            }
                        }
                    };
                    tokio::select! {
                        biased;
                        _ = &mut cancelled => Ok(()),
                        result = run(Arc::clone(&gateway), store, Some(receiver), Arc::clone(&worker_admission), None) => result.map(|_| ()),
                        result = follow_chain => result,
                    }
                }));
                // Runtime shutdown (including blocking I/O) is on its owning OS thread.
                drop(runtime);
                result
            })();
            let _ = finished.send(());
            result
        })
        .context("starting bundle worker thread")?;
    let worker = BundleWorker {
        cancel: Some(cancel),
        finished: Some(completion),
        thread: Some(thread),
        admission: Arc::clone(&admission),
    };
    if readiness.await.is_err() {
        worker.shutdown().await?;
        bail!("bundle worker stopped before becoming ready");
    }
    Ok((BundleSubmitter { sender, admission }, worker))
}

pub(crate) async fn import(
    gateway: Gateway,
    store: BlockStore,
    start: u64,
    end: u64,
) -> Result<(u64, u64)> {
    let admission = Admission::new(
        gateway.config.index_max_bytes,
        gateway.config.index_downloads,
        false,
    );
    crate::BACKGROUND_CPU
        .scope(
            (),
            run(
                Arc::new(gateway),
                store,
                None,
                admission,
                Some((start, end)),
            ),
        )
        .await
}

async fn run(
    gateway: Arc<Gateway>,
    store: BlockStore,
    mut requests: Option<mpsc::Receiver<Job>>,
    admission: Arc<Admission>,
    range: Option<(u64, u64)>,
) -> Result<(u64, u64)> {
    let (sender, mut ready) = mpsc::channel(gateway.config.index_downloads);
    let mut stores = Vec::with_capacity(INDEX_WORKERS);
    for _ in 1..INDEX_WORKERS {
        stores.push(store.reconnect().await?);
    }
    stores.push(store);
    let produce = download_pending(&gateway, sender, &admission, range);
    let consume = async {
        let mut roots = 0;
        let mut occurrences = 0;
        let mut indexing = tokio::task::JoinSet::new();
        let mut downloads_finished = false;
        let mut snapshots = tokio::time::interval(Duration::from_secs(5));
        snapshots.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if downloads_finished && requests.is_none() && indexing.is_empty() {
                break;
            }
            let job = tokio::select! {
                _ = snapshots.tick() => {
                    let profiles: Vec<_> = admission.state.lock().ids.values().cloned().collect();
                    for profile in profiles {
                        eprintln!("bundle_profile {}", profile.snapshot("sample"));
                    }
                    continue;
                }
                Some(result) = indexing.join_next(), if !indexing.is_empty() => {
                    let (store, id, result) = result.context("bundle indexing task failed")?;
                    stores.push(store);
                    admission.status.lock().bundles = if indexing.is_empty() { "idle" } else { "indexing" };
                    match result {
                        Ok(count) => {
                            roots += 1;
                            occurrences += count;
                        }
                        Err(error) if range.is_some() => return Err(error),
                        Err(error) => {
                            admission.failed("Bundle indexing failed");
                            eprintln!("indexing bundle {id} failed: {error:#}");
                        }
                    }
                    continue;
                }
                job = async { requests.as_mut().unwrap().recv().await }, if requests.is_some() && !stores.is_empty() => {
                    match job {
                        Some(job) => job,
                        None => { requests = None; continue; }
                    }
                }
                job = ready.recv(), if !downloads_finished && !stores.is_empty() => {
                    match job {
                        Some(job) => job,
                        None => { downloads_finished = true; continue; }
                    }
                }
            };
            let id = URL_SAFE_NO_PAD.encode(job.reservation.id);
            admission.status.lock().bundles = "indexing";
            let mut store = stores.pop().expect("available bundle writer");
            let gateway = Arc::clone(&gateway);
            indexing.spawn(crate::BACKGROUND_CPU.scope((), async move {
                let result = process_job(&gateway, &mut store, job).await;
                (store, id, result)
            }));
        }
        Ok((roots, occurrences))
    };
    let (_, summary) = tokio::try_join!(produce, consume)?;
    Ok(summary)
}

async fn download_pending(
    gateway: &Gateway,
    sender: mpsc::Sender<Job>,
    admission: &Arc<Admission>,
    range: Option<(u64, u64)>,
) -> Result<()> {
    let discovery_store = gateway
        .block_store
        .as_ref()
        .context("bundle downloads require a database")?
        .bundle_discovery_reader()
        .await?;
    let store = &discovery_store;
    let discovery_range = range.or_else(|| {
        (gateway.config.index_bundle_start_height > 0)
            .then_some((gateway.config.index_bundle_start_height, i64::MAX as u64))
    });
    let mut downloads = FuturesUnordered::new();
    let mut cursor: Option<crate::database::BundleCursor> = None;
    let mut pending: Option<(Vec<u8>, u64, u128)> = None;
    let mut candidates = Vec::<(Vec<u8>, u64, u128)>::new().into_iter();
    let mut discovery = None;
    let mut exhausted = false;
    let mut next_poll = Instant::now();
    loop {
        if pending.is_none() && downloads.len() < gateway.config.index_downloads {
            pending = candidates.next();
        }
        if let Some((root_id, height, data_size)) = pending.take() {
            let id: [u8; 32] = root_id
                .as_slice()
                .try_into()
                .context("invalid pending bundle ID")?;
            let size = usize::try_from(data_size).context("bundle exceeds addressable range")?;
            let streamed = size > gateway.config.max_data_size
                || (size > gateway.config.max_memory_data_size
                    && size > gateway.config.max_spool_bytes)
                || size
                    .checked_add(MAX_JSON_BYTES)
                    .is_none_or(|bytes| bytes > admission.max_scheduled_bytes);
            // Streaming charges the bounded parser/hash working set, independent of payload length.
            let charge = if streamed { 16 * MAX_JSON_BYTES } else { size };
            ensure!(
                charge
                    .checked_add(MAX_JSON_BYTES)
                    .is_some_and(|bytes| bytes <= admission.max_scheduled_bytes),
                "indexing byte budget cannot hold the streaming working set"
            );
            if !admission.state.lock().ids.contains_key(&id) {
                let spool = if streamed || size <= gateway.config.max_memory_data_size {
                    Ok(None)
                } else {
                    gateway.spool_budget.reserve(size).map(Some)
                };
                let reserved = spool.ok().and_then(|spool| {
                    admission
                        .reserve_scheduled(id, charge)
                        .map(|reservation| (reservation, spool))
                });
                if let Some((mut reservation, spool)) = reserved {
                    downloads.push(async move {
                        let encoded = URL_SAFE_NO_PAD.encode(id);
                        if streamed {
                            return (
                                encoded,
                                Ok(Some(Job {
                                    root: JobContent::Streamed { height },
                                    reservation,
                                })),
                            );
                        }
                        let profile = Arc::clone(&reservation.profile);
                        profile.phase(1);
                        let result = crate::profiling::scope(
                            Some(Arc::clone(&profile)),
                            crate::content::DOWNLOAD_SPOOL.scope(
                                std::cell::RefCell::new(spool),
                                async {
                                    let root =
                                        fetch_scheduled(gateway, store, &id, &encoded, height)
                                            .await?;
                                    if let Some(root) = &root {
                                        ensure!(
                                            root.data.bytes.len() == size,
                                            "bundle size changed after admission"
                                        );
                                        reservation.shrink(job_bytes(root))?;
                                    }
                                    Ok::<_, anyhow::Error>(root)
                                },
                            ),
                        )
                        .await;
                        let result = match result {
                            Ok(Some(root)) => {
                                profile.phase(0);
                                Ok(Some(Job {
                                    root: JobContent::Complete(root),
                                    reservation,
                                }))
                            }
                            Ok(None) => {
                                profile.finish("skipped");
                                Ok(None)
                            }
                            Err(error) => {
                                profile.finish("failed");
                                Err(error)
                            }
                        };
                        (encoded, result)
                    });
                } else {
                    pending = Some((root_id, height, data_size));
                }
            }
        }
        if exhausted && downloads.is_empty() && range.is_some() {
            return Ok(());
        }
        if discovery.is_none()
            && pending.is_none()
            && candidates.len() == 0
            && downloads.len() < gateway.config.index_downloads
            && (!exhausted || range.is_none())
        {
            let after = cursor.clone();
            let poll_at = next_poll;
            // Keep this query alive across download completions and admission wakeups.
            discovery = Some(Box::pin(async move {
                sleep_until(poll_at).await;
                timeout(
                    Duration::from_secs(125),
                    store.pending_bundles_after(after.as_ref(), discovery_range),
                )
                .await
                .context("discovering pending bundles timed out")?
            }));
        }
        tokio::select! {
            result = downloads.next(), if !downloads.is_empty() => {
                let (id, result) = result.expect("nonempty downloads");
                match result {
                    Ok(Some(job)) => sender.send(job).await.map_err(|_| anyhow::anyhow!("bundle writer stopped"))?,
                    Ok(None) => {}
                    Err(error) if range.is_some() => return Err(error),
                    Err(error) => {
                        admission.failed("Bundle retrieval failed");
                        eprintln!("retrieving scheduled bundle {id} failed: {error:#}");
                    }
                }
            }
            _ = admission.changed.notified() => {}
            _ = gateway.spool_budget.released.notified(), if pending.is_some() => {}
            result = async { discovery.as_mut().expect("pending discovery").await }, if discovery.is_some() => {
                discovery = None;
                match result {
                    Ok(page) if page.after.is_some() => {
                        cursor = page.after;
                        candidates = page.roots.into_iter();
                        exhausted = false;
                        next_poll = Instant::now();
                    }
                    Ok(_) => {
                        exhausted = true;
                        cursor = None;
                        next_poll = Instant::now() + RETRY_INTERVAL;
                    }
                    Err(error) if range.is_some() => return Err(error),
                    Err(error) => {
                        eprintln!("discovering pending bundles failed: {error:#}");
                        admission.failed("Bundle discovery failed");
                        next_poll = Instant::now() + RETRY_INTERVAL;
                    }
                }
            }
            _ = std::future::ready(()), if pending.is_none()
                && candidates.len() > 0 && downloads.len() < gateway.config.index_downloads => {}
            _ = tokio::time::sleep(POLL_INTERVAL), if pending.is_some() => {}
        }
    }
}

async fn fetch_scheduled(
    gateway: &Gateway,
    store: &BlockStore,
    id: &[u8; 32],
    encoded: &str,
    height: u64,
) -> Result<Option<Arc<VerifiedRoot>>> {
    timeout(gateway.config.retrieval_timeout, async {
        if timeout(gateway.config.request_timeout, store.bundle_complete(id))
            .await
            .context("checking bundle completion timed out")??
        {
            return Ok(None);
        }
        let root = gateway.retrieve_direct_with_tags(encoded).await?;
        ensure!(
            root.data.block_height == height,
            "bundle root canonical height changed"
        );
        Ok(Some(root))
    })
    .await
    .context("retrieving scheduled bundle timed out")?
}

async fn process_job(gateway: &Gateway, store: &mut BlockStore, job: Job) -> Result<u64> {
    let Job { root, reservation } = job;
    let profile = Arc::clone(&reservation.profile);
    profile.phase(1);
    let result = crate::profiling::scope(Some(Arc::clone(&profile)), async {
        let root = match root {
            JobContent::Streamed { height } => {
                let count =
                    crate::indexer::index_streamed_bundle(gateway, store, &reservation.id, height)
                        .await?;
                reservation.admission.indexed(count);
                return Ok(count);
            }
            JobContent::Partial(root) => {
                let count =
                    crate::indexer::index_authenticated_bundle(gateway, store, &root).await?;
                reservation.admission.indexed(count);
                return Ok(count);
            }
            JobContent::Complete(root) => root,
        };
        timeout(gateway.config.retrieval_timeout, async {
            if timeout(
                gateway.config.request_timeout,
                store.bundle_complete(&reservation.id),
            )
            .await
            .context("checking bundle completion timed out")??
            {
                return Ok(0);
            }
            let count = index_bundle_content(gateway, store, root).await?;
            reservation.admission.indexed(count);
            Ok(count)
        })
        .await
        .context("indexing bundle timed out")?
    })
    .await;
    profile.finish(if result.is_ok() {
        "completed"
    } else {
        "failed"
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentWriter, SpoolBudget};
    use crate::{Tag, VerifiedData, content::Content};
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires ar_io_rust_test; takes a temporary bundle-progress table lock"]
    async fn bundle_jobs_overlap_with_bounded_admission_and_cancel_cleanly() -> Result<()> {
        let url = std::env::var("DATABASE_URL")?;
        let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(connection));
        let database: String = client
            .query_one("SELECT current_database()", &[])
            .await?
            .get(0);
        ensure!(
            database == "ar_io_rust_test",
            "requires the dedicated test database"
        );
        let source: String = client
            .query_one(
                "SELECT source FROM public.block_index_state WHERE singleton",
                &[],
            )
            .await?
            .get(0);
        let gateway = Gateway::new(Config::new(
            &source,
            "http://127.0.0.1:1",
            vec!["http://127.0.0.1:1".to_owned()],
            Duration::from_secs(10),
            1,
            1024,
        )?)?
        .with_database(&url)
        .await?;
        let store = BlockStore::connect(&url).await?;
        let (sender, receiver) = mpsc::channel(INDEX_WORKERS + 1);
        let submitter = BundleSubmitter {
            sender,
            admission: Admission::new(1024 * 1024, INDEX_WORKERS + 1, false),
        };
        for id in 0..=INDEX_WORKERS as u8 {
            submitter.submit(&root(id, vec![0; 64].into()));
        }
        let admission = Arc::clone(&submitter.admission);
        assert_eq!(admission.state.lock().ids.len(), INDEX_WORKERS + 1);
        drop(submitter);
        let transaction = client.transaction().await?;
        transaction.batch_execute(
            "SET LOCAL lock_timeout='1s'; LOCK TABLE public.bundle_progress IN ACCESS EXCLUSIVE MODE"
        ).await?;
        let pid: i32 = transaction
            .query_one("SELECT pg_backend_pid()", &[])
            .await?
            .get(0);
        let mut running = Box::pin(run(
            Arc::new(gateway),
            store,
            Some(receiver),
            Arc::clone(&admission),
            None,
        ));
        let observe = async {
            let mut settling = None;
            loop {
                transaction
                    .query_one("SELECT pg_stat_clear_snapshot()", &[])
                    .await?;
                let count: i64 = transaction
                    .query_one(
                        "SELECT count(*) FROM pg_stat_activity
                     WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%WITH bundle_tags%'",
                        &[&pid],
                    )
                    .await?
                    .get(0);
                ensure!(
                    count <= INDEX_WORKERS as i64,
                    "too many roots entered indexing"
                );
                if count == INDEX_WORKERS as i64 {
                    let start = settling.get_or_insert_with(Instant::now);
                    if start.elapsed() >= Duration::from_millis(50) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            result = &mut running => bail!("indexing exited while completion reads were blocked: {result:?}"),
            result = timeout(Duration::from_secs(3), observe) => result.context("bundle roots did not overlap")??,
        }
        assert_eq!(admission.state.lock().ids.len(), INDEX_WORKERS + 1);
        drop(running);
        timeout(Duration::from_secs(1), async {
            while !admission.state.lock().ids.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("cancelled indexing jobs retained admission")?;
        assert!(admission.state.lock().ids.is_empty());
        assert_eq!(admission.state.lock().bytes, 0);
        transaction.rollback().await?;
        Ok(())
    }

    #[test]
    fn scheduled_roots_keep_request_slots_free_until_they_are_released() {
        let admission = Admission::new(128 * MAX_JSON_BYTES, 40, true);
        let mut scheduled: Vec<_> = (0..32)
            .map(|id| admission.reserve_scheduled([id; 32], 0).unwrap())
            .collect();
        for reservation in &mut scheduled {
            reservation.shrink(0).unwrap();
        }
        assert!(admission.reserve_scheduled([32; 32], 0).is_none());
        let requests: Vec<_> = (32..40)
            .map(|id| admission.reserve([id; 32], 1).unwrap())
            .collect();
        assert!(admission.reserve([40; 32], 1).is_none());
        drop(scheduled.pop());
        assert!(admission.reserve_scheduled([40; 32], 0).is_some());
        drop(requests);
    }

    #[test]
    fn scheduled_bytes_preserve_aggregate_request_headroom() {
        let admission = Admission::new(8 * MAX_JSON_BYTES, 40, true);
        let first = admission
            .reserve_scheduled([1; 32], MAX_JSON_BYTES)
            .unwrap();
        let second = admission
            .reserve_scheduled([2; 32], MAX_JSON_BYTES)
            .unwrap();
        assert!(admission.reserve_scheduled([3; 32], 0).is_none());
        let request = admission.reserve([4; 32], 4 * MAX_JSON_BYTES).unwrap();
        assert!(admission.reserve([5; 32], 1).is_none());
        drop(first);
        let next = admission
            .reserve_scheduled([3; 32], MAX_JSON_BYTES)
            .unwrap();
        assert!(admission.reserve_scheduled([6; 32], 0).is_none());
        drop((second, request, next));
        assert!(admission.reserve([7; 32], 8 * MAX_JSON_BYTES).is_some());
    }

    fn submitter(bytes: usize) -> (BundleSubmitter, mpsc::Receiver<Job>) {
        let (sender, receiver) = mpsc::channel(MAX_JOBS);
        (
            BundleSubmitter {
                sender,
                admission: Admission::new(bytes, MAX_JOBS, false),
            },
            receiver,
        )
    }

    fn root(id: u8, bytes: Content) -> Arc<VerifiedRoot> {
        Arc::new(VerifiedRoot {
            data: VerifiedData {
                content_length: bytes.len(),
                bytes,
                cache_hit: false,
                id: URL_SAFE_NO_PAD.encode([id; 32]),
                block_height: 1,
                block_hash: None,
                stable_anchor: true,
                content_type: "application/octet-stream".to_owned(),
                content_encoding: None,
                etag: String::new(),
                sha256: String::new(),
                indexing_root: None,
            },
            tags: bundle_tags(),
            facts: None,
        })
    }

    fn bundle_tags() -> Vec<Tag> {
        [("Bundle-Format", "binary"), ("Bundle-Version", "2.0.0")]
            .into_iter()
            .map(|(name, value)| Tag {
                name: URL_SAFE_NO_PAD.encode(name),
                value: URL_SAFE_NO_PAD.encode(value),
            })
            .collect()
    }

    #[tokio::test]
    async fn healthcheck_reports_worker_exit_without_indexing_age_limit() -> Result<()> {
        let (submitter, receiver) = submitter(1024);
        let (stop, stopped) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = stopped.recv();
            drop(receiver);
        });
        let mut gateway = Gateway::new(Config::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            vec!["http://127.0.0.1:1".to_owned()],
            Duration::from_millis(50),
            1,
            1024,
        )?)?;
        gateway.bundle_indexer = Some(submitter);
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let config = crate::server::ServerConfig::new(
            &address.to_string(),
            "",
            "http://127.0.0.1:1",
            "11111111111111111111111111111111",
            "11111111111111111111111111111111",
            1,
        )?;
        drop(listener);
        let server = tokio::spawn(crate::server::serve(gateway, config));
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()?;
        let url = format!("http://{address}/ar-io/healthcheck");
        let ready = timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(response) = client.get(&url).send().await {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        assert_eq!(ready.status(), reqwest::StatusCode::OK);
        assert_eq!(ready.json::<serde_json::Value>().await?["status"], "ok");
        stop.send(())?;
        worker.join().expect("worker thread panicked");
        let response = client.get(&url).send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.json::<serde_json::Value>().await?["status"],
            "unhealthy"
        );
        server.abort();
        Ok(())
    }

    #[test]
    fn active_jobs_stay_deduplicated_and_count_toward_saturation() {
        let (submitter, mut receiver) = submitter(job_bytes(&root(0, vec![0].into())) * MAX_JOBS);
        submitter.submit(&root(0, vec![0].into()));
        let active = receiver.try_recv().unwrap();
        let JobContent::Complete(active_root) = &active.root else {
            panic!("request handoff was streamed")
        };
        submitter.submit(active_root);
        assert!(receiver.try_recv().is_err());
        for id in 1..MAX_JOBS as u8 {
            submitter.submit(&root(id, vec![0].into()));
        }
        submitter.submit(&root(8, vec![0].into()));
        assert_eq!(receiver.len(), MAX_JOBS - 1);
        drop(active);
        submitter.submit(&root(0, vec![0].into()));
        assert_eq!(receiver.len(), MAX_JOBS);
    }

    #[test]
    fn sliced_backing_and_scheduled_reservations_share_the_byte_ceiling() -> Result<()> {
        let memory = Content::from(vec![0; 8]);
        let first = root(0, memory.slice(0..1)?);
        let second = root(2, vec![0].into());
        let (submitter, mut receiver) = submitter(job_bytes(&first) + job_bytes(&second));
        submitter.submit(&first);
        let active = receiver.try_recv().unwrap();
        let mut scheduled = submitter.admission.reserve([1; 32], 2).unwrap();
        submitter.submit(&second);
        assert!(receiver.try_recv().is_err());
        scheduled.shrink(0)?;
        submitter.submit(&second);
        assert_eq!(receiver.len(), 1);
        drop(active);
        drop(scheduled);
        drop(receiver.try_recv().unwrap());

        let file = tempfile::tempfile()?;
        file.set_len(submitter.admission.max_bytes as u64)?;
        let persistent = Content::persistent(
            file,
            [0; 32],
            submitter.admission.max_bytes,
            Arc::new(tempfile::tempfile()?),
        );
        submitter.submit(&root(3, persistent.slice(0..1)?));
        assert!(receiver.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_receiver_releases_spooled_roots_and_rejects_late_submits() -> Result<()> {
        let (submitter, mut receiver) = submitter(16 * 1024);
        let budget = Arc::new(SpoolBudget::new(8));
        let mut writer = ContentWriter::new(8, 0, Arc::clone(&budget)).await?;
        writer.write(b"12345678").await?;
        let (content, _) = writer.finish().await?;
        let first = root(0, content);
        submitter.submit(&first);
        submitter.submit(&root(1, first.data.bytes.clone()));
        drop(first);
        assert!(ContentWriter::new(8, 0, Arc::clone(&budget)).await.is_err());
        let active = receiver.try_recv().unwrap();
        drop(receiver);
        assert!(ContentWriter::new(8, 0, Arc::clone(&budget)).await.is_err());
        drop(active);
        let writer = ContentWriter::new(8, 0, budget).await?;
        drop(writer);
        submitter.submit(&root(2, vec![0].into()));
        let reservation = submitter.admission.reserve([2; 32], 16).unwrap();
        drop(reservation);
        Ok(())
    }

    #[test]
    fn admission_charges_metadata_and_preserves_request_room() {
        let bundle = root(0, vec![0; 1024].into());
        let (too_small, mut rejected) = submitter(bundle.data.bytes.len());
        too_small.submit(&bundle);
        assert!(rejected.try_recv().is_err());

        let mut with_facts = root(1, vec![0; 1024].into());
        let capacity = job_bytes(&with_facts) + 4096;
        Arc::get_mut(&mut with_facts).unwrap().facts = Some(crate::indexer::RootFacts {
            block_hash: [0; 48],
            timestamp: 0,
            transaction_ids: vec![vec![0; 32]; 256],
            object: crate::database::ObjectMetadata {
                id: vec![1; 32],
                kind: 0,
                signature: Vec::new(),
                anchor: Vec::new(),
                owner_address: Vec::new(),
                owner_public_key: Vec::new(),
                target: Vec::new(),
                data_size: 1024,
                content_type: None,
                content_encoding: None,
                signature_type: 1,
                format: Some(2),
                quantity: None,
                reward: None,
                denomination: None,
                data_root: None,
                tags: Vec::new(),
            },
        });
        let (bounded, mut rejected) = submitter(capacity);
        bounded.submit(&with_facts);
        assert!(rejected.try_recv().is_err());

        let (submitter, mut receiver) = submitter(4 * MAX_JSON_BYTES);
        let scheduled = submitter
            .admission
            .reserve_scheduled([9; 32], MAX_JSON_BYTES)
            .unwrap();
        submitter.submit(&bundle);
        let requested = receiver
            .try_recv()
            .expect("scheduled fetch blocked a request handoff");
        let JobContent::Complete(requested_root) = &requested.root else {
            panic!("request handoff was streamed")
        };
        assert_eq!(
            requested_root.data.bytes.memory_bytes().unwrap().as_ref(),
            &[0; 1024]
        );
        assert!(
            submitter
                .admission
                .reserve([8; 32], 4 * MAX_JSON_BYTES)
                .is_none()
        );
        drop(requested);
        drop(scheduled);
    }

    #[tokio::test]
    async fn memory_cached_child_retries_a_rejected_parent_handoff() -> Result<()> {
        let parent = root(0, b"parent bytes".to_vec().into());
        let (submitter, mut receiver) = submitter(job_bytes(&parent));
        let occupied = submitter
            .admission
            .reserve([9; 32], submitter.admission.max_bytes)
            .unwrap();
        let mut gateway = Gateway::new(Config::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            vec!["http://127.0.0.1:1".to_owned()],
            Duration::from_millis(50),
            1,
            1024,
        )?)?;
        gateway.bundle_indexer = Some(submitter);
        let mut child = parent.verified();
        child.id = URL_SAFE_NO_PAD.encode([1; 32]);
        child.bytes = child.bytes.slice(0..6)?;
        child.content_length = 6;
        gateway
            .cache
            .lock()
            .unwrap()
            .insert(child.clone(), 1, child.cache_bytes());
        assert_eq!(
            gateway
                .retrieve(&child.id)
                .await?
                .bytes
                .read_all(6)
                .await?
                .as_ref(),
            b"parent"
        );
        assert!(receiver.try_recv().is_err());
        drop(occupied);
        assert!(gateway.retrieve(&child.id).await?.cache_hit);
        let job = receiver
            .try_recv()
            .expect("RAM cache hit did not retry its parent");
        let JobContent::Complete(root) = &job.root else {
            panic!("request handoff was streamed")
        };
        assert_eq!(root.data.id, parent.data.id);
        assert_eq!(
            root.data.bytes.read_all(12).await?.as_ref(),
            b"parent bytes"
        );
        Ok(())
    }
}
