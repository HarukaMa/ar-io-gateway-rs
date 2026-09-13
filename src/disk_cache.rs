use std::{
    fs::{self, File},
    io::{self, Read as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use tokio::task::spawn_blocking;

use crate::content::Content;

const IO_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct DiskCache(Arc<CacheDirectory>);

#[derive(Debug)]
struct CacheDirectory {
    path: PathBuf,
    lock: Arc<File>,
    min_free_bytes: u64,
    max_pending_bytes: usize,
    pending_bytes: AtomicUsize,
    publication: Arc<tokio::sync::RwLock<()>>,
    lookups: parking_lot::Mutex<[LookupStats; 2]>,
}

#[derive(Debug, Default)]
struct LookupStats {
    hits: u64,
    misses: u64,
    errors: u64,
}

impl LookupStats {
    fn snapshot(&self) -> serde_json::Value {
        let lookups = self.hits + self.misses + self.errors;
        serde_json::json!({
            "lookups": lookups,
            "hits": self.hits,
            "misses": self.misses,
            "errors": self.errors,
            "hit_rate": (lookups != 0).then(|| self.hits as f64 / lookups as f64),
        })
    }
}

struct PendingWrite {
    // Remove unfinished bytes before making their reservation available again.
    temp: NamedTempFile,
    reservation: Reservation,
}

struct Reservation {
    directory: Arc<CacheDirectory>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.directory
            .pending_bytes
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

struct CancelWrite(Arc<AtomicBool>);

impl Drop for CancelWrite {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl DiskCache {
    pub(crate) fn record_lookup<T>(&self, http: bool, result: &Result<Option<T>>) {
        let mut lookups = self.0.lookups.lock();
        let stats = &mut lookups[usize::from(!http)];
        match result {
            Ok(Some(_)) => stats.hits += 1,
            Ok(None) => stats.misses += 1,
            Err(_) => stats.errors += 1,
        }
    }

    pub(crate) fn stats(&self) -> serde_json::Value {
        let lookups = self.0.lookups.lock();
        serde_json::json!({
            "http": lookups[0].snapshot(),
            "background": lookups[1].snapshot(),
        })
    }

    pub(crate) fn publication_guard(&self) -> Option<tokio::sync::OwnedRwLockReadGuard<()>> {
        self.0.publication.clone().try_read_owned().ok()
    }

    pub(crate) async fn new(
        path: PathBuf,
        min_free_bytes: u64,
        max_pending_bytes: usize,
    ) -> Result<Self> {
        spawn_blocking(move || {
            fs::create_dir_all(&path).context("creating content cache directory")?;
            let path = fs::canonicalize(path).context("resolving content cache directory")?;
            let lock = Arc::new(
                fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path.join(".lock"))?,
            );
            lock.try_lock()
                .context("content cache directory is already in use")?;
            fs4::available_space(&path).context("checking content cache filesystem")?;
            Ok(Self(Arc::new(CacheDirectory {
                path,
                lock,
                min_free_bytes,
                max_pending_bytes,
                pending_bytes: AtomicUsize::new(0),
                publication: Arc::new(tokio::sync::RwLock::new(())),
                lookups: Default::default(),
            })))
        })
        .await
        .context("creating content cache task")?
    }

    pub(crate) async fn load(&self, hash: [u8; 32], size: usize) -> Result<Option<Content>> {
        let path = blob_path(&self.0.path, hash);
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelWrite(Arc::clone(&cancelled));
        let cache_lock = Arc::clone(&self.0.lock);
        spawn_blocking(move || {
            if !is_directory(path.parent().expect("cache shard"))? {
                return Ok(None);
            }
            verified_file(&path, hash, size, &cancelled)
                .map(|file| file.map(|file| Content::persistent(file, hash, size, cache_lock)))
        })
        .await
        .context("reading cached content task")
        .and_then(|result| result)
    }

    pub(crate) async fn store(&self, content: &Content, hash: [u8; 32]) -> Result<Option<Content>> {
        let Some(publication) = self.publication_guard() else {
            return Ok(None);
        };
        // Reserve before queueing any work or retaining another copy of the source.
        let Some(reservation) = self.0.reserve(content.len()) else {
            return Ok(None);
        };
        let directory = Arc::clone(&self.0);
        let content = content.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelWrite(Arc::clone(&cancelled));
        spawn_blocking(move || {
            let _publication = publication;
            ensure!(!cancelled.load(Ordering::Relaxed), "cache write cancelled");
            let path = blob_path(&directory.path, hash);
            let shard = path.parent().expect("cache shard");
            match fs::create_dir(shard) {
                Ok(()) => {
                    #[cfg(unix)]
                    File::open(&directory.path)?.sync_all()?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    ensure!(
                        is_directory(shard)?,
                        "cache shard is not a regular directory"
                    );
                }
                Err(error) => return Err(error).context("creating cache shard"),
            }
            let Some(mut pending) = directory.admit(reservation, shard)? else {
                return Ok(None);
            };
            content.copy_verified_to(pending.temp.as_file_mut(), hash, &cancelled)?;
            pending
                .temp
                .as_file()
                .sync_all()
                .context("syncing cached content")?;
            // Keep only a read-only handle after publication. Positional readers retain
            // this verified inode even if an external actor later replaces its path.
            let file =
                File::open(pending.temp.path()).context("opening completed cached content")?;
            file.lock_shared()
                .context("pinning published cache content")?;
            ensure!(!cancelled.load(Ordering::Relaxed), "cache write cancelled");
            let PendingWrite { temp, reservation } = pending;
            match temp.persist_noclobber(&path) {
                Ok(writer) => {
                    drop(writer);
                    #[cfg(unix)]
                    File::open(shard)?.sync_all()?;
                    drop(reservation);
                    Ok(Some(Content::persistent(
                        file,
                        hash,
                        content.len(),
                        Arc::clone(&directory.lock),
                    )))
                }
                Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                    let existing = if let Some(existing) =
                        verified_file(&path, hash, content.len(), &cancelled)?
                    {
                        existing
                    } else {
                        ensure!(
                            fs::symlink_metadata(&path)?.file_type().is_file(),
                            "cache repair requires a regular file"
                        );
                        ensure!(!cancelled.load(Ordering::Relaxed), "cache write cancelled");
                        drop(
                            error
                                .file
                                .persist(&path)
                                .context("repairing cached content")?,
                        );
                        #[cfg(unix)]
                        File::open(shard)?.sync_all()?;
                        file
                    };
                    drop(reservation);
                    Ok(Some(Content::persistent(
                        existing,
                        hash,
                        content.len(),
                        Arc::clone(&directory.lock),
                    )))
                }
                Err(error) => {
                    drop(file);
                    let tempfile::PersistError { error, file } = error;
                    drop(file);
                    Err(error).context("publishing cached content")
                }
            }
        })
        .await
        .context("writing content cache task")?
    }

    pub(crate) async fn cleanup(
        &mut self,
        store: &crate::database::BlockStore,
        deadline: Instant,
    ) -> Result<u64> {
        ensure!(
            Arc::strong_count(&self.0) == 1 && Arc::strong_count(&self.0.lock) == 1,
            "cache cleanup requires exclusive ownership without active readers or writers"
        );
        let cancelled = Arc::new(AtomicBool::new(false));
        let _cancel_on_drop = CancelWrite(Arc::clone(&cancelled));
        ensure!(Instant::now() < deadline, "cache cleanup timed out");
        let directory = Arc::clone(&self.0);
        let mut removed = 0;
        for prefix in 0..=u8::MAX {
            let shard = directory.path.join(format!("{prefix:02x}"));
            let worker_cancelled = Arc::clone(&cancelled);
            let entries = spawn_blocking(move || -> Result<_> {
                ensure!(
                    !worker_cancelled.load(Ordering::Relaxed),
                    "cache cleanup cancelled"
                );
                ensure!(Instant::now() < deadline, "cache cleanup timed out");
                if !is_directory(&shard)? {
                    return Ok(None);
                }
                fs::read_dir(shard).map(Some).context("reading cache shard")
            })
            .await??;
            let Some(mut entries) = entries else { continue };
            loop {
                let worker_cancelled = Arc::clone(&cancelled);
                let (next, seen, batch) = spawn_blocking(move || -> Result<_> {
                    let mut batch = Vec::with_capacity(128);
                    let mut seen = 0;
                    for _ in 0..128 {
                        ensure!(
                            !worker_cancelled.load(Ordering::Relaxed),
                            "cache cleanup cancelled"
                        );
                        ensure!(Instant::now() < deadline, "cache cleanup timed out");
                        let Some(entry) = entries.next() else { break };
                        seen += 1;
                        let entry = entry?;
                        if !entry.file_type()?.is_file() {
                            continue;
                        }
                        let name = entry.file_name();
                        let Some(name) = name.to_str() else { continue };
                        let hash = if name.len() == 64
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        {
                            let mut hash = [0; 32];
                            for (index, byte) in hash.iter_mut().enumerate() {
                                *byte = u8::from_str_radix(&name[index * 2..index * 2 + 2], 16)?;
                            }
                            if hash[0] != prefix {
                                continue;
                            }
                            Some(hash)
                        } else if name.strip_prefix(".pending-").is_some_and(|suffix| {
                            suffix.len() == 6 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
                        }) {
                            None
                        } else {
                            continue;
                        };
                        batch.push((entry.path(), hash));
                    }
                    Ok((entries, seen, batch))
                })
                .await??;
                entries = next;
                if seen == 0 {
                    break;
                }
                let hashes: Vec<_> = batch.iter().filter_map(|(_, hash)| *hash).collect();
                ensure!(Instant::now() < deadline, "cache cleanup timed out");
                let referenced = store.referenced_cache_blobs(&hashes).await?;
                let directory = Arc::clone(&self.0);
                let worker_cancelled = Arc::clone(&cancelled);
                removed += spawn_blocking(move || -> Result<u64> {
                    let _directory = directory;
                    let paths = batch.into_iter().filter_map(|(path, hash)| {
                        hash.is_none_or(|hash| !referenced.contains(&hash))
                            .then_some(path)
                    });
                    remove_abandoned_files(paths, &worker_cancelled, deadline)
                })
                .await??;
            }
        }
        Ok(removed)
    }
}

#[derive(Default)]
pub(crate) struct EvictionCursor {
    prefix: u8,
    entries: Option<fs::ReadDir>,
    reclaiming: bool,
}

struct EvictionCandidate {
    path: PathBuf,
    hash: [u8; 32],
    accessed: SystemTime,
}

impl DiskCache {
    pub(crate) async fn reclaim(
        &self,
        publisher: &crate::database::BlockStore,
        store: &crate::database::BlockStore,
        cursor: &mut EvictionCursor,
    ) -> Result<bool> {
        let directory = self.0.clone();
        let mut next = std::mem::take(cursor);
        let (next, candidates) = spawn_blocking(move || {
            let total = fs4::total_space(&directory.path)?;
            let available = fs4::available_space(&directory.path)?;
            let reserve = directory
                .min_free_bytes
                .saturating_add(directory.max_pending_bytes as u64);
            let trigger = (total / 10).max(reserve);
            let target = (total / 5).max(reserve.saturating_add(total / 20));
            next.reclaiming = available < if next.reclaiming { target } else { trigger };
            let candidates = if next.reclaiming {
                next.sample(&directory.path)?
            } else {
                Vec::new()
            };
            Ok::<_, anyhow::Error>((next, candidates))
        })
        .await??;
        *cursor = next;
        if candidates.is_empty() {
            return Ok(false);
        }

        let guard = self.0.publication.clone().write_owned().await;
        // Drain already-enqueued publications, including queries whose caller cancelled.
        publisher.cache_publication_barrier().await?;
        let pinned = spawn_blocking(move || -> Result<_> {
            let mut pinned = Vec::new();
            for candidate in candidates {
                let Ok(file) = File::open(&candidate.path) else {
                    continue;
                };
                if file.try_lock().is_err() {
                    continue;
                }
                let metadata = file.metadata()?;
                if !metadata.is_file() || metadata.accessed()? > candidate.accessed {
                    continue;
                }
                pinned.push((candidate, file));
                if pinned.len() == 64 {
                    break;
                }
            }
            Ok(pinned)
        })
        .await??;
        if pinned.is_empty() {
            return Ok(false);
        }
        let hashes: Vec<_> = pinned.iter().map(|(candidate, _)| candidate.hash).collect();
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.remove_cache_mappings(&hashes).await? != 0 {
            // Leave the files in place if metadata cleanup needs another pass.
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
        let removed = spawn_blocking(move || -> Result<u64> {
            let _guard = guard;
            let mut removed = 0;
            for (candidate, _pin) in pinned {
                match fs::remove_file(&candidate.path) {
                    Ok(()) => removed += 1,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("evicting cached blob"),
                }
            }
            Ok(removed)
        })
        .await??;
        if removed != 0 {
            eprintln!("Evicted {removed} cached blobs");
        }
        Ok(true)
    }
}

impl EvictionCursor {
    fn sample(&mut self, root: &Path) -> Result<Vec<EvictionCandidate>> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut candidates = Vec::new();
        let mut visited = 0;
        let mut seen = 0;
        while seen < 512 && visited < 256 && Instant::now() < deadline {
            if self.entries.is_none() {
                let shard = root.join(format!("{:02x}", self.prefix));
                if !is_directory(&shard)? {
                    self.prefix = self.prefix.wrapping_add(1);
                    visited += 1;
                    continue;
                }
                self.entries = Some(fs::read_dir(shard)?);
            }
            let Some(entry) = self.entries.as_mut().unwrap().next() else {
                self.entries = None;
                self.prefix = self.prefix.wrapping_add(1);
                visited += 1;
                continue;
            };
            seen += 1;
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                continue;
            }
            let hash = std::array::from_fn(|index| {
                u8::from_str_radix(&name[index * 2..index * 2 + 2], 16).unwrap()
            });
            if hash[0] != self.prefix {
                continue;
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_file() {
                candidates.push(EvictionCandidate {
                    path: entry.path(),
                    hash,
                    accessed: metadata.accessed()?,
                });
            }
        }
        candidates.sort_unstable_by_key(|candidate| candidate.accessed);
        Ok(candidates)
    }
}

impl CacheDirectory {
    fn reserve(self: &Arc<Self>, size: usize) -> Option<Reservation> {
        // Charge empty blobs too, so zero-byte writes cannot form an unbounded queue.
        let bytes = size.max(1);
        self.pending_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                pending
                    .checked_add(bytes)
                    .filter(|total| *total <= self.max_pending_bytes)
            })
            .ok()?;
        Some(Reservation {
            directory: Arc::clone(self),
            bytes,
        })
    }
    fn admit(
        self: &Arc<Self>,
        reservation: Reservation,
        shard: &Path,
    ) -> Result<Option<PendingWrite>> {
        // Snapshot reservations before querying free space: completion between the two
        // is conservatively double-counted, never omitted from both measurements.
        let total = self.pending_bytes.load(Ordering::Relaxed);
        let Some(required) = u64::try_from(total)
            .ok()
            .and_then(|total| self.min_free_bytes.checked_add(total))
        else {
            return Ok(None);
        };
        // ponytail: conservatively count all pending bytes, including bytes already written.
        // A single cache owner coordinates admission; unrelated disk users can still fill it.
        if fs4::available_space(&self.path).context("checking content cache free space")? < required
        {
            return Ok(None);
        }
        let temp = tempfile::Builder::new()
            .prefix(".pending-")
            .tempfile_in(shard)
            .context("creating content cache temporary file")?;
        Ok(Some(PendingWrite { temp, reservation }))
    }
}

fn blob_path(root: &Path, hash: [u8; 32]) -> PathBuf {
    let name = crate::hex(&hash);
    root.join(&name[..2]).join(name)
}

fn is_directory(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remove_abandoned_files(
    paths: impl IntoIterator<Item = PathBuf>,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> Result<u64> {
    let mut removed = 0;
    for path in paths {
        ensure!(
            !cancelled.load(Ordering::Relaxed),
            "cache cleanup cancelled"
        );
        ensure!(Instant::now() < deadline, "cache cleanup timed out");
        // A filesystem call already in progress must finish before cancellation takes effect.
        fs::remove_file(path).context("removing abandoned cache file")?;
        removed += 1;
    }
    Ok(removed)
}

fn verified_file(
    path: &Path,
    hash: [u8; 32],
    size: usize,
    cancelled: &AtomicBool,
) -> Result<Option<File>> {
    ensure!(!cancelled.load(Ordering::Relaxed), "cache read cancelled");
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspecting cached content"),
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("opening cached content"),
    };
    if file.try_lock_shared().is_err() {
        return Ok(None);
    }
    let expected_size = u64::try_from(size).context("cached content size exceeds file limits")?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Ok(None);
    }
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0; IO_CHUNK_SIZE.min(size.max(1))];
    let mut remaining = size;
    while remaining != 0 {
        ensure!(!cancelled.load(Ordering::Relaxed), "cache read cancelled");
        let length = remaining.min(buffer.len());
        if let Err(error) = file.read_exact(&mut buffer[..length]) {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(None);
            }
            return Err(error).context("reading cached content");
        }
        sha256.update(&buffer[..length]);
        remaining -= length;
    }
    if file.read(&mut buffer[..1])? != 0 || <[u8; 32]>::from(sha256.finalize()) != hash {
        return Ok(None);
    }
    Ok(Some(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{ContentWriter, SpoolBudget};
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn cleanup_timeout_stops_deleting_between_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = root.path().join("first");
        let second = root.path().join("second");
        fs::write(&first, b"first")?;
        fs::write(&second, b"second")?;
        let paths = [first.clone(), second.clone()];
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished, result) = tokio::sync::oneshot::channel();
        let mut cleanup = Box::pin(async move {
            let cancelled = Arc::new(AtomicBool::new(false));
            let _cancel_on_drop = CancelWrite(Arc::clone(&cancelled));
            spawn_blocking(move || {
                let mut started = Some(started);
                let paths = paths.into_iter().enumerate().map(|(index, path)| {
                    if index == 1 {
                        started.take().unwrap().send(()).unwrap();
                        released.recv().unwrap();
                    }
                    path
                });
                let outcome = remove_abandoned_files(
                    paths,
                    &cancelled,
                    Instant::now() + std::time::Duration::from_secs(60),
                );
                finished.send(outcome).unwrap();
            })
            .await
            .unwrap();
        });
        std::future::poll_fn(|cx| {
            assert!(cleanup.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready.await?;
        let timed_out = tokio::time::timeout(std::time::Duration::from_millis(1), cleanup).await;
        release.send(())?;
        let outcome = result.await?;
        assert!(timed_out.is_err());
        assert!(outcome.is_err());
        assert!(!first.exists());
        assert_eq!(fs::read(second)?, b"second");
        Ok(())
    }

    #[test]
    fn cleanup_expired_deadline_preserves_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("abandoned");
        fs::write(&path, b"keep")?;
        assert!(
            remove_abandoned_files([path.clone()], &AtomicBool::new(false), Instant::now(),)
                .is_err()
        );
        assert_eq!(fs::read(path)?, b"keep");
        Ok(())
    }

    #[tokio::test]
    async fn restart_load_preserves_parent_views_and_independent_readers() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cache = DiskCache::new(root.path().to_path_buf(), 0, 10).await?;
        let budget = Arc::new(SpoolBudget::new(10));
        let mut writer = ContentWriter::new(10, 0, Arc::clone(&budget)).await?;
        writer.write(b"0123456789").await?;
        let (source, hash) = writer.finish().await?;
        let stored = cache.store(&source, hash).await?.unwrap();
        drop(source);
        // Persistent bytes no longer retain the temporary spool reservation.
        drop(ContentWriter::new(10, 0, budget).await?);
        drop(stored);
        drop(cache);
        let cache = DiskCache::new(root.path().to_path_buf(), 0, 10).await?;
        let stored = cache.load(hash, 10).await?.unwrap();
        let view = stored.slice(1..9)?.slice(2..6)?;
        assert_eq!(view.persistent_blob(), Some((hash, 10, 3)));
        let mut left = view.reader().await?;
        let mut right = stored.slice(0..4)?.reader().await?;
        drop(view);
        drop(stored);
        drop(cache);
        assert!(
            DiskCache::new(root.path().to_path_buf(), 0, 10)
                .await
                .is_err()
        );
        let mut pair = [0; 2];
        left.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"34");
        right.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"01");
        left.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"56");
        right.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"23");
        assert_eq!(left.read(&mut pair).await?, 0);
        assert_eq!(right.read(&mut pair).await?, 0);
        drop(left);
        drop(right);
        let cache = DiskCache::new(root.path().to_path_buf(), 0, 10).await?;
        assert_eq!(
            cache.load(hash, 10).await?.unwrap().read_all(10).await?,
            b"0123456789"[..]
        );
        Ok(())
    }

    #[tokio::test]
    async fn verified_download_repairs_corrupt_and_truncated_cache_files() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cache = DiskCache::new(root.path().to_path_buf(), 0, 4).await?;
        let content = Content::from(b"data".to_vec());
        let hash = Sha256::digest(b"data").into();
        assert!(cache.load(hash, 4).await?.is_none());
        drop(cache.store(&content, hash).await?.unwrap());
        assert!(cache.load(hash, 3).await?.is_none());
        let name = crate::hex(&hash);
        let path = root.path().join(&name[..2]).join(&name);
        for corrupt in [b"evil".as_slice(), b"dat".as_slice()] {
            fs::write(&path, corrupt)?;
            assert!(cache.load(hash, 4).await?.is_none());
            let mut existing_reader = File::open(&path)?;
            #[cfg(windows)]
            {
                assert!(cache.store(&content, hash).await.is_err());
                assert_eq!(fs::read(&path)?, corrupt);
                let mut previous = Vec::new();
                existing_reader.read_to_end(&mut previous)?;
                assert_eq!(previous, corrupt);
                drop(existing_reader);
            }
            let repaired = cache.store(&content, hash).await?.unwrap();
            assert_eq!(repaired.read_all(4).await?.as_ref(), b"data");
            assert_eq!(
                cache
                    .load(hash, 4)
                    .await?
                    .unwrap()
                    .read_all(4)
                    .await?
                    .as_ref(),
                b"data"
            );
            #[cfg(not(windows))]
            {
                let mut previous = Vec::new();
                existing_reader.read_to_end(&mut previous)?;
                assert_eq!(previous, corrupt);
            }
        }
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        assert!(cache.store(&content, hash).await.is_err());
        assert!(path.is_dir());
        fs::remove_dir(&path)?;
        let shard = path.parent().unwrap();
        fs::remove_dir(shard)?;
        fs::write(shard, b"keep")?;
        assert!(cache.load(hash, 4).await?.is_none());
        assert!(cache.store(&content, hash).await.is_err());
        assert_eq!(fs::read(shard)?, b"keep");
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir()?;
            let outside_blob = outside.path().join(&name);
            fs::write(&outside_blob, b"data")?;
            fs::remove_file(shard)?;
            std::os::unix::fs::symlink(outside.path(), shard)?;
            assert!(cache.load(hash, 4).await?.is_none());
            assert!(cache.store(&content, hash).await.is_err());
            assert_eq!(fs::read(outside_blob)?, b"data");
        }
        Ok(())
    }

    #[tokio::test]
    async fn hash_failure_cleans_staging_and_admission_enforces_both_limits() -> Result<()> {
        let root = tempfile::tempdir()?;
        let content = Content::from(b"data".to_vec());
        let hash = Sha256::digest(b"data").into();
        let reserve = DiskCache::new(root.path().to_path_buf(), u64::MAX, 4).await?;
        assert!(reserve.store(&content, hash).await?.is_none());
        drop(reserve);
        let small = DiskCache::new(root.path().to_path_buf(), 0, 3).await?;
        assert!(small.store(&content, hash).await?.is_none());
        drop(small);
        let cache = DiskCache::new(root.path().to_path_buf(), 0, 4).await?;
        assert!(cache.store(&content, [0; 32]).await.is_err());
        drop(cache.store(&content, hash).await?.unwrap());
        // An identical publication race/repeat succeeds without replacing the root file.
        drop(cache.store(&content, hash).await?.unwrap());
        assert_eq!(
            cache.load(hash, 4).await?.unwrap().read_all(4).await?,
            b"data"[..]
        );
        Ok(())
    }

    #[test]
    fn cancelled_queued_store_does_not_publish_or_hold_admission() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .build()?;
        runtime.block_on(async {
            let root = tempfile::tempdir()?;
            let cache = DiskCache::new(root.path().to_path_buf(), 0, 4).await?;
            let (release, blocked) = std::sync::mpsc::channel();
            let blocker = spawn_blocking(move || blocked.recv().unwrap());
            let content = Content::from(b"data".to_vec());
            let hash = Sha256::digest(b"data").into();
            let mut write = Box::pin(cache.store(&content, hash));
            assert!(
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(write.as_mut().poll(cx).is_pending())
                })
                .await
            );
            assert!(cache.store(&content, hash).await?.is_none());
            drop(write);
            release.send(())?;
            blocker.await?;
            // This lookup is queued behind the cancelled worker on the same blocking pool.
            assert!(cache.load(hash, 4).await?.is_none());
            drop(cache.store(&content, hash).await?.unwrap());
            assert_eq!(
                cache.load(hash, 4).await?.unwrap().read_all(4).await?,
                b"data"[..]
            );
            Ok(())
        })
    }
}
