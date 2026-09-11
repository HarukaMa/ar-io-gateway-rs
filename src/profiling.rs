use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use serde_json::{Value, json};

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Stage {
    ChunkAdmission,
    ChunkHeaders,
    ChunkBody,
    CpuAdmission,
    CpuDispatch,
    CpuExecution,
    Traversal,
    Persistence,
    TransactionPending,
    TransactionAnchor,
    TransactionAdmission,
    TransactionFetch,
}
const STAGES: [&str; 12] = [
    "chunk_admission",
    "chunk_headers",
    "chunk_body",
    "cpu_admission",
    "cpu_dispatch",
    "cpu_execution",
    "traversal",
    "persistence",
    "transaction_pending",
    "transaction_anchor",
    "transaction_admission",
    "transaction_fetch",
];

#[derive(Default)]
struct Counter {
    elapsed: Duration,
    started: u64,
    completed: u64,
    failed: u64,
    cancelled: u64,
    active: u32,
    peak_active: u32,
    bytes: u64,
}

struct State {
    updated: Instant,
    phases: [Duration; 3],
    phase: usize,
    outcome: &'static str,
    counters: [Counter; STAGES.len()],
}

pub(crate) struct Profile {
    attempt: u64,
    started_at_us: u64,
    root: String,
    log_prefix: &'static str,
    state: Mutex<State>,
}

tokio::task_local! {
    static CURRENT: Arc<Profile>;
}

pub(crate) fn current() -> Option<Arc<Profile>> {
    CURRENT
        .try_with(Arc::clone)
        .ok()
        .filter(|profile| profile.state.lock().outcome == "running")
}

pub(crate) async fn scope<T>(profile: Option<Arc<Profile>>, future: impl Future<Output = T>) -> T {
    match profile {
        Some(profile) => CURRENT.scope(profile, future).await,
        None => future.await,
    }
}

impl State {
    fn update(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.updated);
        if self.outcome == "running" {
            self.phases[self.phase] += elapsed;
        }
        for counter in &mut self.counters {
            counter.elapsed += elapsed * counter.active;
        }
        self.updated = now;
    }
}

impl Profile {
    pub(crate) fn new(root: String) -> Arc<Self> {
        Self::with_prefix(root, "bundle_profile")
    }

    pub(crate) fn transaction_window(range: String) -> Arc<Self> {
        Self::with_prefix(range, "transaction_profile")
    }

    fn with_prefix(root: String, log_prefix: &'static str) -> Arc<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Arc::new(Self {
            attempt: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            started_at_us: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            root,
            log_prefix,
            state: Mutex::new(State {
                updated: Instant::now(),
                phases: [Duration::ZERO; 3],
                phase: 0,
                outcome: "running",
                counters: std::array::from_fn(|_| Counter::default()),
            }),
        })
    }

    pub(crate) fn phase(&self, phase: usize) {
        let mut state = self.state.lock();
        state.update();
        state.phase = phase;
    }

    pub(crate) fn finish(&self, outcome: &'static str) {
        let mut state = self.state.lock();
        state.update();
        if state.outcome == "running" {
            state.outcome = outcome;
        }
    }

    pub(crate) fn snapshot(&self, event: &str) -> Value {
        let mut state = self.state.lock();
        state.update();
        let stages: serde_json::Map<String, Value> = STAGES
            .iter()
            .zip(&state.counters)
            .map(|(name, c)| {
                (
                    (*name).to_owned(),
                    json!({"elapsed_us": c.elapsed.as_micros() as u64,
                "started": c.started, "completed": c.completed, "failed": c.failed,
                "cancelled": c.cancelled, "active": c.active, "peak_active": c.peak_active, "bytes": c.bytes}),
                )
            })
            .collect();
        json!({"attempt": self.attempt, "root": self.root, "event": event,
            "started_at_us": self.started_at_us,
            "at_us": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64,
            "elapsed_us": state.phases.iter().sum::<Duration>().as_micros() as u64,
            "phase": if state.outcome == "running" { ["queued", "preparing", "processing"][state.phase] } else { "finished" },
            "outcome": state.outcome,
            "phases_us": {"queued": state.phases[0].as_micros() as u64,
                "preparing": state.phases[1].as_micros() as u64, "processing": state.phases[2].as_micros() as u64},
            "stages": stages})
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        self.finish("cancelled");
        eprintln!("{} {}", self.log_prefix, self.snapshot("finished"));
    }
}

pub(crate) struct Timer {
    profile: Arc<Profile>,
    stage: Stage,
    outcome: Option<bool>,
    bytes: u64,
}

pub(crate) fn start(stage: Stage) -> Option<Timer> {
    start_for(&current(), stage)
}

// Already-dispatched blocking work can start after its root is cancelled.
pub(crate) fn start_for(profile: &Option<Arc<Profile>>, stage: Stage) -> Option<Timer> {
    let profile = profile.as_ref()?;
    {
        let mut state = profile.state.lock();
        state.update();
        let counter = &mut state.counters[stage as usize];
        counter.started += 1;
        counter.active += 1;
        counter.peak_active = counter.peak_active.max(counter.active);
    }
    Some(Timer {
        profile: Arc::clone(profile),
        stage,
        outcome: None,
        bytes: 0,
    })
}

impl Timer {
    pub(crate) fn add_bytes(&self, bytes: u64) {
        self.profile.state.lock().counters[self.stage as usize].bytes += bytes;
    }

    pub(crate) fn finish(mut self, success: bool, bytes: u64) {
        self.outcome = Some(success);
        self.bytes = bytes;
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let mut state = self.profile.state.lock();
        state.update();
        let counter = &mut state.counters[self.stage as usize];
        counter.active -= 1;
        counter.bytes += self.bytes;
        match self.outcome {
            Some(true) => counter.completed += 1,
            Some(false) => counter.failed += 1,
            None => counter.cancelled += 1,
        }
    }
}

pub(crate) async fn measure<T>(
    stage: Stage,
    future: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let timer = start(stage);
    let result = future.await;
    if let Some(timer) = timer {
        timer.finish(result.is_ok(), 0);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn failed_chunk_body_retains_received_bytes() -> anyhow::Result<()> {
        let app = axum::Router::new().fallback(|| async { "{bad}\r\n" });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let profile = Profile::new("body-failure-test".to_owned());
        scope(Some(Arc::clone(&profile)), async {
            let response = reqwest::Client::new().get(url).send().await?;
            assert!(crate::read_chunk_response(response).await.is_err());
            Ok::<_, anyhow::Error>(())
        })
        .await?;
        let sample = profile.snapshot("sample");
        assert_eq!(sample["stages"]["chunk_body"]["failed"], 1);
        assert_eq!(sample["stages"]["chunk_body"]["active"], 0);
        assert_eq!(sample["stages"]["chunk_body"]["bytes"], 7);
        Ok(())
    }

    #[tokio::test]
    async fn active_overlap_failures_and_cancelled_work_are_accounted() {
        let profile = Profile::new("timing-test".to_owned());
        scope(Some(Arc::clone(&profile)), async {
            let first = start(Stage::ChunkBody).unwrap();
            let second = start(Stage::ChunkBody).unwrap();
            profile.state.lock().updated -= Duration::from_secs(2);
            let snapshot = profile.snapshot("sample");
            assert!(
                snapshot["stages"]["chunk_body"]["elapsed_us"]
                    .as_u64()
                    .unwrap()
                    >= 4_000_000
            );
            assert_eq!(snapshot["stages"]["chunk_body"]["active"], 2);
            first.finish(true, 12);
            drop(second);
            assert!(
                measure::<()>(Stage::ChunkHeaders, async {
                    anyhow::bail!("source failed")
                })
                .await
                .is_err()
            );
            let pending = measure::<()>(Stage::Persistence, std::future::pending());
            let mut pending = Box::pin(pending);
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            drop(pending);
            assert_eq!(crate::cpu_work(|| Ok(7)).await.unwrap(), 7);
        })
        .await;
        profile.phase(1);
        profile.finish("failed");
        let snapshot = profile.snapshot("finished");
        assert_eq!(snapshot["stages"]["chunk_body"]["completed"], 1);
        assert_eq!(snapshot["stages"]["chunk_body"]["cancelled"], 1);
        assert_eq!(snapshot["stages"]["chunk_body"]["bytes"], 12);
        assert_eq!(snapshot["stages"]["chunk_body"]["active"], 0);
        assert_eq!(snapshot["stages"]["chunk_body"]["peak_active"], 2);
        assert_eq!(snapshot["stages"]["chunk_headers"]["failed"], 1);
        assert_eq!(snapshot["stages"]["persistence"]["cancelled"], 1);
        assert_eq!(snapshot["stages"]["cpu_execution"]["completed"], 1);
        assert_eq!(snapshot["stages"]["cpu_dispatch"]["completed"], 1);
        assert_eq!(snapshot["outcome"], "failed");
        scope(Some(profile), async {
            assert!(start(Stage::Traversal).is_none());
        })
        .await;
    }
}
