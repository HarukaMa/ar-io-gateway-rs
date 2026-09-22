use std::{collections::VecDeque, sync::Arc};

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt, TryStreamExt, stream};
use tokio::sync::Mutex;
use tokio_util::task::AbortOnDropHandle;

use crate::Geometry;

pub(crate) struct ChunkSource {
    gateway: crate::Gateway,
    geometry: Geometry,
    cached: Mutex<VecDeque<(usize, Bytes, [u8; 32])>>,
    profile: Option<std::sync::Weak<crate::profiling::Profile>>,
}

impl std::fmt::Debug for ChunkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSource").finish_non_exhaustive()
    }
}

impl ChunkSource {
    pub(crate) fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub(crate) fn persistent(&self) -> bool {
        self.gateway.disk_cache.is_some()
    }
    pub(crate) fn new(gateway: &crate::Gateway, geometry: Geometry) -> Arc<Self> {
        let mut gateway = gateway.clone();
        gateway.bundle_indexer = None;
        Arc::new(Self {
            gateway,
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
        let read = move |position| {
            let source = Arc::clone(&self);
            async move {
                // Proof checks must progress while the consumer waits for the same CPU pool.
                AbortOnDropHandle::new(tokio::spawn(crate::shared::inherit(async move {
                    let read = source.chunk_at(position);
                    if background {
                        crate::BACKGROUND_CPU.scope((), read).await
                    } else {
                        read.await
                    }
                })))
                .await
                .context("stream read-ahead task failed")?
            }
        };
        // Positions a maximum chunk apart cannot select the same proof chunk.
        // Reserve one request slot for gaps left by smaller proof chunks.
        let pending = stream::iter((offset..end).step_by(size))
            .map(read.clone())
            .buffered(if background { 15 } else { 7 });
        Ok(stream::try_unfold(
            (Box::pin(pending), None::<(usize, Bytes)>, offset),
            move |(mut pending, mut next, position)| {
                let read = read.clone();
                async move {
                    if position == end {
                        return Ok(None);
                    }
                    if next.is_none() {
                        next = pending.try_next().await?;
                    }
                    let (start, bytes) = match &next {
                        Some((start, _)) if *start <= position => next.take().unwrap(),
                        _ => read(position).await?,
                    };
                    ensure!(
                        start <= position && position - start < bytes.len(),
                        "verified stream made no progress"
                    );
                    let within = position - start;
                    let count = (end - position).min(bytes.len() - within);
                    Ok(Some((
                        bytes.slice(within..within + count),
                        (pending, next, position + count),
                    )))
                }
            },
        ))
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
            let (start, bytes) = self.chunk_at(position).await?;
            let within = position - start;
            let count = (end - position).min(bytes.len() - within);
            ensure!(count > 0, "verified stream made no progress");
            output.extend_from_slice(&bytes[within..within + count]);
            position += count;
        }
        Ok(Bytes::from(output))
    }

    async fn chunk_at(&self, position: usize) -> Result<(usize, Bytes)> {
        let hit = {
            let cached = self.cached.lock().await;
            cached
                .iter()
                .find(|(start, bytes, _)| *start <= position && position - start < bytes.len())
                .cloned()
        };
        let (start, bytes, hash) = match hit {
            Some(chunk) => chunk,
            None => self.fetch(position).await?,
        };
        if let Some(cache) = &self.gateway.disk_cache {
            cache.touch(hash);
        }
        let mut cached = self.cached.lock().await;
        if let Some(index) = cached.iter().position(|(offset, _, _)| *offset == start) {
            cached.remove(index);
        }
        if cached.len() == 2 {
            cached.pop_back();
        }
        cached.push_front((start, bytes.clone(), hash));
        Ok((start, bytes))
    }

    async fn fetch(&self, position: usize) -> Result<(usize, Bytes, [u8; 32])> {
        crate::profiling::scope(
            self.profile.as_ref().and_then(std::sync::Weak::upgrade),
            async {
                let absolute = self
                    .geometry
                    .first_offset
                    .checked_add(position as u128)
                    .context("stream chunk offset overflow")?;
                let fetched = self
                    .gateway
                    .fetch_verified_chunk(
                        absolute,
                        crate::BlockGeometry {
                            tx_root: self.geometry.tx_root,
                            block_weave_size: self.geometry.block_weave_size,
                            previous_weave_size: self.geometry.previous_weave_size,
                        },
                    )
                    .await?
                    .context("streaming chunk not found")?;
                let proof = &fetched.proof;
                crate::check_chunk_geometry(proof, position as u128, &self.geometry)?;
                Ok((
                    usize::try_from(proof.data.start)?,
                    proof.bytes.clone(),
                    proof.data.data_hash,
                ))
            },
        )
        .await
    }
}
