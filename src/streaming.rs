use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt, stream};
use reqwest::Client;
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    Geometry, cpu_work, endpoint, peers::PeerState, read_chunk_response, verify_chunk_range,
};

pub(crate) struct ChunkSource {
    client: Client,
    peers: Arc<PeerState>,
    sources: Vec<String>,
    timeout: Duration,
    geometry: Geometry,
    cached: Mutex<VecDeque<(usize, Bytes)>>,
    profile: Option<std::sync::Weak<crate::profiling::Profile>>,
}

impl std::fmt::Debug for ChunkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSource").finish_non_exhaustive()
    }
}

impl ChunkSource {
    pub(crate) fn new(gateway: &crate::Gateway, geometry: Geometry) -> Arc<Self> {
        Arc::new(Self {
            client: gateway.client.clone(),
            peers: gateway.peers.clone(),
            sources: gateway.config.chunk_sources.clone(),
            timeout: gateway.config.request_timeout.min(crate::CHUNK_DEADLINE),
            geometry,
            cached: Mutex::new(VecDeque::with_capacity(2)),
            profile: crate::profiling::current().as_ref().map(Arc::downgrade),
        })
    }

    pub(crate) async fn with_gateway(&self, gateway: &crate::Gateway) -> Arc<Self> {
        let cached = self.cached.lock().await.clone();
        let source = Self::new(gateway, self.geometry);
        *source.cached.lock().await = cached;
        source
    }

    pub(crate) fn read_ahead(
        self: Arc<Self>,
        offset: usize,
        length: usize,
    ) -> Result<impl Stream<Item = Result<Bytes>>> {
        let end = offset
            .checked_add(length)
            .context("stream range overflow")?;
        ensure!(
            end as u128 <= self.geometry.data_size,
            "stream range exceeds transaction"
        );
        let size = crate::MAX_CHUNK_SIZE as usize;
        let background = crate::BACKGROUND_CPU.try_with(|()| ()).is_ok();
        Ok(stream::iter((offset..end).step_by(size))
            .map(move |position| {
                let source = Arc::clone(&self);
                async move {
                    // Proof checks must progress while the consumer waits for the same CPU pool.
                    AbortOnDropHandle::new(tokio::spawn(async move {
                        let read = source.read_at(position, size.min(end - position));
                        if background {
                            crate::BACKGROUND_CPU.scope((), read).await
                        } else {
                            read.await
                        }
                    }))
                    .await
                    .context("stream read-ahead task failed")?
                }
            })
            .buffered(8))
    }

    pub(crate) async fn read_at(&self, offset: usize, length: usize) -> Result<Bytes> {
        let end = offset
            .checked_add(length)
            .context("stream range overflow")?;
        ensure!(
            end as u128 <= self.geometry.data_size,
            "stream range exceeds transaction"
        );
        let mut output = Vec::new();
        output.try_reserve_exact(length)?;
        let mut position = offset;
        while position < end {
            let hit = {
                let cached = self.cached.lock().await;
                cached
                    .iter()
                    .find(|(start, bytes)| *start <= position && position - start < bytes.len())
                    .cloned()
            };
            let (start, bytes) = match hit {
                Some(chunk) => chunk,
                None => self.fetch(position).await?,
            };
            {
                let mut cached = self.cached.lock().await;
                if let Some(index) = cached.iter().position(|(offset, _)| *offset == start) {
                    cached.remove(index);
                }
                if cached.len() == 2 {
                    cached.pop_back();
                }
                cached.push_front((start, bytes.clone()));
            }
            let within = position - start;
            let count = (end - position).min(bytes.len() - within);
            ensure!(count > 0, "verified stream made no progress");
            output.extend_from_slice(&bytes[within..within + count]);
            position += count;
        }
        Ok(Bytes::from(output))
    }

    async fn fetch(&self, position: usize) -> Result<(usize, Bytes)> {
        crate::profiling::scope(
            self.profile.as_ref().and_then(std::sync::Weak::upgrade),
            tokio::time::timeout(self.timeout, async {
                let absolute = self
                    .geometry
                    .first_offset
                    .checked_add(position as u128)
                    .context("stream chunk offset overflow")?;
                let request = |source: String| async move {
                    let path = format!("chunk/{absolute}");
                    let request = if self.sources.iter().any(|configured| configured == &source) {
                        self.client.get(endpoint(&source, &path))
                    } else {
                        self.peers.get(endpoint(&source, &path))
                    };
                    let started = Instant::now();
                    let response =
                        crate::profiling::measure(crate::profiling::Stage::ChunkHeaders, async {
                            Ok(request
                                .timeout((self.timeout / 4).min(crate::CHUNK_PEER_DEADLINE))
                                .send()
                                .await?
                                .error_for_status()?)
                        })
                        .await?;
                    let headers = started.elapsed();
                    let started = Instant::now();
                    let chunk = read_chunk_response(response).await?;
                    let body = started.elapsed();
                    let geometry = self.geometry;
                    let proof = cpu_work(move || {
                        verify_chunk_range(chunk, absolute, position as u128, &geometry)
                    })
                    .await?;
                    let offset = usize::try_from(proof.data.start)?;
                    Ok::<_, anyhow::Error>((offset, Bytes::from(proof.bytes), headers, body))
                };
                let fetches =
                    crate::peers::hedged_requests(&self.peers, absolute, &self.sources, &request);
                tokio::pin!(fetches);
                let mut failures = Vec::new();
                while let Some((source, result)) = fetches.next().await {
                    match result {
                        Ok((offset, bytes, headers, body)) => {
                            self.peers
                                .record_chunk_result(&source, Some((headers, body, bytes.len())));
                            return Ok((offset, bytes));
                        }
                        Err(error) => {
                            self.peers.record_chunk_result(&source, None);
                            failures.push(format!("{source}: {error:#}"));
                        }
                    }
                }
                anyhow::bail!(
                    "all streaming chunk candidates failed: {}",
                    failures.join("; ")
                )
            }),
        )
        .await
        .context("streaming chunk request timed out")?
    }
}
