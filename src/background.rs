use std::{
    collections::HashSet,
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
const POLL_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

struct Admission {
    state: Mutex<AdmissionState>,
    max_bytes: usize,
    max_jobs: usize,
    max_scheduled_jobs: usize,
    max_scheduled_bytes: usize,
    changed: tokio::sync::Notify,
    last_indexed_at: AtomicU64,
}

struct AdmissionState {
    ids: HashSet<[u8; 32]>,
    bytes: usize,
    scheduled_bytes: usize,
    scheduled_jobs: usize,
    closed: bool,
}

impl Admission {
    fn new(max_bytes: usize, max_jobs: usize, request_headroom: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(AdmissionState {
                ids: HashSet::with_capacity(max_jobs),
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
            || state.ids.contains(&id)
            || bytes > self.max_bytes - state.bytes
            || (scheduled && bytes > self.max_scheduled_bytes - state.scheduled_bytes)
            || (scheduled && state.scheduled_jobs == self.max_scheduled_jobs)
        {
            return None;
        }
        state.ids.insert(id);
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
}

struct Reservation {
    admission: Arc<Admission>,
    id: [u8; 32],
    bytes: usize,
    scheduled: bool,
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

struct Job {
    // Content and metadata are dropped before their admission is released.
    root: Arc<VerifiedRoot>,
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
            root: Arc::clone(root),
            reservation,
        });
    }

    pub(crate) fn last_indexed_at(&self) -> u64 {
        self.admission.last_indexed_at.load(Ordering::Relaxed)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.sender.is_closed()
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
    let (sender, receiver) = mpsc::channel(MAX_JOBS);
    let (cancel, mut cancelled) = oneshot::channel();
    let (ready, readiness) = oneshot::channel();
    let (finished, completion) = oneshot::channel();
    let worker_admission = Arc::clone(&admission);
    let thread = thread::Builder::new()
        .name("bundle-indexer".to_owned())
        .spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .max_blocking_threads(2)
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
                        store.pending_bundle_after(None, None).await?;
                        Ok::<_, anyhow::Error>((gateway, store))
                    };
                    let (gateway, mut store) = tokio::select! {
                        biased;
                        _ = &mut cancelled => return Ok(()),
                        result = timeout(startup_timeout, initialize) => {
                            result.context("initializing bundle worker timed out")??
                        }
                    };
                    if ready.send(()).is_err() {
                        return Ok(());
                    }
                    tokio::select! {
                        biased;
                        _ = &mut cancelled => Ok(()),
                        result = run(&gateway, &mut store, Some(receiver), worker_admission, None) => result.map(|_| ()),
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
    gateway: &Gateway,
    store: &mut BlockStore,
    start: u64,
    end: u64,
) -> Result<(u64, u64)> {
    let admission = Admission::new(
        gateway.config.index_max_bytes,
        gateway.config.index_downloads,
        false,
    );
    crate::BACKGROUND_CPU
        .scope((), run(gateway, store, None, admission, Some((start, end))))
        .await
}

async fn run(
    gateway: &Gateway,
    store: &mut BlockStore,
    mut requests: Option<mpsc::Receiver<Job>>,
    admission: Arc<Admission>,
    range: Option<(u64, u64)>,
) -> Result<(u64, u64)> {
    let (sender, mut ready) = mpsc::channel(gateway.config.index_downloads);
    let produce = download_pending(gateway, sender, &admission, range);
    let consume = async {
        let mut roots = 0;
        let mut occurrences = 0;
        let mut next_chain_poll = Instant::now();
        loop {
            let job = tokio::select! {
                _ = sleep_until(next_chain_poll), if range.is_none() && gateway.config.index_chain => {
                    match crate::indexer::follow_chain_step(gateway, store).await {
                        Ok(true) => next_chain_poll = Instant::now(),
                        Ok(false) => next_chain_poll = Instant::now() + RETRY_INTERVAL,
                        Err(error) => {
                            eprintln!("following chain failed: {error:#}");
                            next_chain_poll = Instant::now() + RETRY_INTERVAL;
                        }
                    }
                    continue;
                }
                job = async { requests.as_mut().unwrap().recv().await }, if requests.is_some() => {
                    match job {
                        Some(job) => job,
                        None => { requests = None; continue; }
                    }
                }
                job = ready.recv() => {
                    let Some(job) = job else { break; };
                    job
                }
            };
            let id = job.root.data.id.clone();
            match process_job(gateway, store, job).await {
                Ok(count) => {
                    roots += 1;
                    occurrences += count;
                }
                Err(error) if range.is_some() => return Err(error),
                Err(error) => eprintln!("indexing bundle {id} failed: {error:#}"),
            }
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
    let store = gateway
        .block_store
        .as_ref()
        .context("bundle downloads require a database")?;
    let mut downloads = FuturesUnordered::new();
    let mut cursor: Option<Vec<u8>> = None;
    let mut pending: Option<(Vec<u8>, u64, u128)> = None;
    let mut exhausted = false;
    let mut next_poll = Instant::now();
    loop {
        if let Some((root_id, height, data_size)) = pending.take() {
            let id: [u8; 32] = root_id
                .as_slice()
                .try_into()
                .context("invalid pending bundle ID")?;
            let size = usize::try_from(data_size).ok().filter(|size| {
                *size <= gateway.config.max_data_size
                    && (*size <= gateway.config.max_memory_data_size
                        || *size <= gateway.config.max_spool_bytes)
                    && size
                        .checked_add(MAX_JSON_BYTES)
                        .is_some_and(|bytes| bytes <= admission.max_scheduled_bytes)
            });
            if size.is_none() {
                let error = anyhow::anyhow!(
                    "bundle {} exceeds indexing byte limits",
                    URL_SAFE_NO_PAD.encode(id)
                );
                if range.is_some() {
                    return Err(error);
                }
                eprintln!("{error:#}");
                cursor = Some(root_id);
            } else if admission.state.lock().ids.contains(&id) {
                cursor = Some(root_id);
            } else {
                let size = size.unwrap();
                let spool = if size <= gateway.config.max_memory_data_size {
                    Ok(None)
                } else {
                    gateway.spool_budget.reserve(size).map(Some)
                };
                let reserved = spool.ok().and_then(|spool| {
                    admission
                        .reserve_scheduled(id, size)
                        .map(|reservation| (reservation, spool))
                });
                if let Some((mut reservation, spool)) = reserved {
                    cursor = Some(root_id);
                    downloads.push(async move {
                        let encoded = URL_SAFE_NO_PAD.encode(id);
                        let result = crate::content::DOWNLOAD_SPOOL
                            .scope(std::cell::RefCell::new(spool), async {
                                let Some(root) =
                                    fetch_scheduled(gateway, store, &id, &encoded, height).await?
                                else {
                                    return Ok(None);
                                };
                                ensure!(
                                    root.data.bytes.len() == size,
                                    "bundle size changed after admission"
                                );
                                reservation.shrink(job_bytes(&root))?;
                                Ok::<_, anyhow::Error>(Some(Job { root, reservation }))
                            })
                            .await;
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
        tokio::select! {
            result = downloads.next(), if !downloads.is_empty() => {
                let (id, result) = result.expect("nonempty downloads");
                match result {
                    Ok(Some(job)) => sender.send(job).await.map_err(|_| anyhow::anyhow!("bundle writer stopped"))?,
                    Ok(None) => {}
                    Err(error) if range.is_some() => return Err(error),
                    Err(error) => eprintln!("retrieving scheduled bundle {id} failed: {error:#}"),
                }
            }
            _ = admission.changed.notified() => {}
            _ = gateway.spool_budget.released.notified(), if pending.is_some() => {}
            result = async {
                sleep_until(next_poll).await;
                timeout(gateway.config.request_timeout, store.pending_bundle_after(cursor.as_deref(), range))
                    .await.context("discovering pending bundle timed out")?
            }, if pending.is_none() && downloads.len() < gateway.config.index_downloads && (!exhausted || range.is_none()) => {
                match result {
                    Ok(Some(root)) => { pending = Some(root); exhausted = false; next_poll = Instant::now(); }
                    Ok(None) => {
                        exhausted = true;
                        cursor = None;
                        next_poll = Instant::now() + RETRY_INTERVAL;
                    }
                    Err(error) if range.is_some() => return Err(error),
                    Err(error) => {
                        eprintln!("discovering pending bundles failed: {error:#}");
                        next_poll = Instant::now() + RETRY_INTERVAL;
                    }
                }
            }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentWriter, SpoolBudget};
    use crate::{Tag, VerifiedData, content::Content};

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
        submitter.submit(&active.root);
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
        assert_eq!(
            requested.root.data.bytes.memory_bytes().unwrap().as_ref(),
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
        assert_eq!(job.root.data.id, parent.data.id);
        assert_eq!(
            job.root.data.bytes.read_all(12).await?.as_ref(),
            b"parent bytes"
        );
        Ok(())
    }
}
