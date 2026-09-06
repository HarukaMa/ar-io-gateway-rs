use std::{
    future::Future,
    io::{self, Write as _},
    ops::Range,
    path::Path,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context as TaskContext, Poll},
};

use anyhow::{Context, Result, ensure};
use axum::body::Bytes;
use sha2::{Digest, Sha256, Sha384};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    task::{JoinHandle, spawn_blocking},
};

const IO_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct SpoolBudget {
    max_bytes: usize,
    used_bytes: AtomicUsize,
}

impl SpoolBudget {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            used_bytes: AtomicUsize::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Reservation> {
        self.used_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= self.max_bytes)
            })
            .map_err(|_| anyhow::anyhow!("content spool budget exhausted"))?;
        Ok(Reservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

#[derive(Debug)]
struct Reservation {
    budget: Arc<SpoolBudget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget
            .used_bytes
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct SpoolFile {
    // Drop the file (and unlink its name) before releasing the disk reservation.
    temp: NamedTempFile,
    _reservation: Reservation,
}

#[derive(Debug)]
enum ContentFile {
    Temporary(SpoolFile),
    Persistent {
        file: std::fs::File,
        hash: [u8; 32],
        len: usize,
    },
}

impl ContentFile {
    fn read_exact_at(&self, mut bytes: &mut [u8], mut offset: u64) -> io::Result<()> {
        let file = match self {
            Self::Temporary(file) => file.temp.as_file(),
            Self::Persistent { file, .. } => file,
        };
        while !bytes.is_empty() {
            // Never mix shared-handle cursor reads with positional reads on Windows.
            #[cfg(unix)]
            let read = std::os::unix::fs::FileExt::read_at(file, bytes, offset);
            #[cfg(windows)]
            let read = std::os::windows::fs::FileExt::seek_read(file, bytes, offset);
            match read {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(len) => {
                    offset += len as u64;
                    bytes = &mut bytes[len..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Content(Storage);

#[derive(Clone, Debug)]
enum Storage {
    Memory {
        bytes: Bytes,
        resident_len: usize,
    },
    File {
        file: Arc<ContentFile>,
        offset: usize,
        len: usize,
    },
}

impl From<Vec<u8>> for Content {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Storage::Memory {
            resident_len: bytes.capacity(),
            bytes: Bytes::from(bytes),
        })
    }
}

impl From<Bytes> for Content {
    fn from(bytes: Bytes) -> Self {
        // Vec recovers unique allocations and copies shared/opaque backing we cannot charge.
        Self::from(Vec::from(bytes))
    }
}

impl Content {
    // The caller must verify the entire file and provide a read-only handle.
    pub(crate) fn persistent(file: std::fs::File, hash: [u8; 32], len: usize) -> Self {
        Self(Storage::File {
            file: Arc::new(ContentFile::Persistent { file, hash, len }),
            offset: 0,
            len,
        })
    }

    pub(crate) fn persistent_blob(&self) -> Option<([u8; 32], usize, usize)> {
        let Storage::File { file, offset, .. } = &self.0 else {
            return None;
        };
        match file.as_ref() {
            ContentFile::Persistent { hash, len, .. } => Some((*hash, *len, *offset)),
            ContentFile::Temporary(_) => None,
        }
    }

    // Called only by the disk cache's blocking worker. Views copy only their own bytes.
    pub(crate) fn copy_verified_to(
        &self,
        output: &mut std::fs::File,
        expected_hash: [u8; 32],
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        let mut sha256 = Sha256::new();
        let mut buffer = Vec::new();
        if !self.is_memory() {
            buffer.resize(IO_CHUNK_SIZE.min(self.len()), 0);
        }
        for start in (0..self.len()).step_by(IO_CHUNK_SIZE) {
            ensure!(!cancelled.load(Ordering::Relaxed), "cache write cancelled");
            let end = self.len().min(start.saturating_add(IO_CHUNK_SIZE));
            let bytes = match &self.0 {
                Storage::Memory { bytes, .. } => &bytes[start..end],
                Storage::File { file, offset, .. } => {
                    let position = offset
                        .checked_add(start)
                        .context("content offset overflow")?;
                    file.read_exact_at(
                        &mut buffer[..end - start],
                        u64::try_from(position).context("content offset exceeds file limits")?,
                    )?;
                    &buffer[..end - start]
                }
            };
            sha256.update(bytes);
            output.write_all(bytes)?;
        }
        ensure!(
            <[u8; 32]>::from(sha256.finalize()) == expected_hash,
            "content does not match cache hash"
        );
        Ok(())
    }

    pub fn len(&self) -> usize {
        match &self.0 {
            Storage::Memory { bytes, .. } => bytes.len(),
            Storage::File { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_memory(&self) -> bool {
        matches!(&self.0, Storage::Memory { .. })
    }

    pub fn resident_len(&self) -> usize {
        match &self.0 {
            Storage::Memory { resident_len, .. } => *resident_len,
            Storage::File { .. } => 0,
        }
    }

    pub fn memory_bytes(&self) -> Option<&Bytes> {
        match &self.0 {
            Storage::Memory { bytes, .. } => Some(bytes),
            Storage::File { .. } => None,
        }
    }

    pub fn slice(&self, range: Range<usize>) -> Result<Self> {
        ensure!(
            range.start <= range.end && range.end <= self.len(),
            "content slice is out of bounds"
        );
        Ok(match &self.0 {
            Storage::Memory {
                bytes,
                resident_len,
            } => Self(Storage::Memory {
                bytes: bytes.slice(range),
                resident_len: *resident_len,
            }),
            Storage::File { file, offset, .. } => Self(Storage::File {
                file: Arc::clone(file),
                offset: offset
                    .checked_add(range.start)
                    .context("content slice offset overflow")?,
                len: range.end - range.start,
            }),
        })
    }

    pub async fn read_at(&self, offset: usize, length: usize) -> Result<Bytes> {
        let end = offset
            .checked_add(length)
            .context("content read offset overflow")?;
        let view = self.slice(offset..end)?;
        if let Some(bytes) = view.memory_bytes() {
            return Ok(bytes.clone());
        }
        if length == 0 {
            return Ok(Bytes::new());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length)?;
        bytes.resize(length, 0);
        view.reader()
            .await?
            .read_exact(&mut bytes)
            .await
            .context("reading content view")?;
        Ok(Bytes::from(bytes))
    }

    pub async fn read_all(&self, limit: usize) -> Result<Bytes> {
        ensure!(self.len() <= limit, "content exceeds read limit");
        self.read_at(0, self.len()).await
    }

    pub async fn hashes(&self) -> Result<([u8; 32], [u8; 48])> {
        let mut sha256 = Sha256::new();
        let mut sha384 = Sha384::new();
        if let Some(bytes) = self.memory_bytes() {
            for chunk in bytes.chunks(IO_CHUNK_SIZE) {
                sha256.update(chunk);
                sha384.update(chunk);
                tokio::task::coop::consume_budget().await;
            }
        } else {
            let mut reader = self.reader().await?;
            // An inline array inflates every enclosing retrieval future on Windows.
            let mut buffer = vec![0; IO_CHUNK_SIZE];
            loop {
                let length = reader.read(&mut buffer).await?;
                if length == 0 {
                    break;
                }
                sha256.update(&buffer[..length]);
                sha384.update(&buffer[..length]);
            }
        }
        Ok((sha256.finalize().into(), sha384.finalize().into()))
    }

    pub async fn reader(&self) -> Result<ContentReader> {
        let state = match &self.0 {
            Storage::Memory { bytes, .. } => ReadState::Memory(bytes.clone()),
            Storage::File { file, offset, .. } => ReadState::File(ReaderFile {
                storage: Arc::clone(file),
                offset: u64::try_from(*offset).context("content offset exceeds file limits")?,
                buffer: Vec::new(),
                consumed: 0,
            }),
        };
        Ok(ContentReader {
            state,
            remaining: self.len(),
        })
    }

    pub async fn write_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let mut reader = self.reader().await?;
        let mut output = tokio::fs::File::create(path).await?;
        output.set_max_buf_size(IO_CHUNK_SIZE);
        tokio::io::copy(&mut reader, &mut output).await?;
        output.flush().await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ContentReader {
    state: ReadState,
    remaining: usize,
}

#[derive(Debug)]
enum ReadState {
    Memory(Bytes),
    File(ReaderFile),
    Reading(JoinHandle<io::Result<ReaderFile>>),
    Failed,
}

#[derive(Debug)]
struct ReaderFile {
    storage: Arc<ContentFile>,
    offset: u64,
    buffer: Vec<u8>,
    consumed: usize,
}

impl AsyncRead for ContentReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match &mut this.state {
                ReadState::Memory(bytes) => {
                    let offset = bytes.len() - this.remaining;
                    let length = output.remaining().min(this.remaining);
                    output.put_slice(&bytes[offset..offset + length]);
                    this.remaining -= length;
                    return Poll::Ready(Ok(()));
                }
                ReadState::File(file) => {
                    if file.consumed < file.buffer.len() {
                        let length = output.remaining().min(file.buffer.len() - file.consumed);
                        output.put_slice(&file.buffer[file.consumed..file.consumed + length]);
                        file.consumed += length;
                        this.remaining -= length;
                        return Poll::Ready(Ok(()));
                    }
                    let ReadState::File(mut file) =
                        std::mem::replace(&mut this.state, ReadState::Failed)
                    else {
                        unreachable!();
                    };
                    let length = IO_CHUNK_SIZE.min(this.remaining).min(output.remaining());
                    // Each task owns the file and quota, even if its reader is cancelled.
                    this.state = ReadState::Reading(spawn_blocking(move || {
                        file.buffer.resize(length, 0);
                        file.consumed = 0;
                        file.storage.read_exact_at(&mut file.buffer, file.offset)?;
                        file.offset += length as u64;
                        Ok(file)
                    }));
                }
                ReadState::Reading(task) => {
                    let result = match Pin::new(task).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(result) => result,
                    };
                    this.state = ReadState::Failed;
                    match result {
                        Ok(Ok(file)) => this.state = ReadState::File(file),
                        Ok(Err(error)) => return Poll::Ready(Err(error)),
                        Err(error) => return Poll::Ready(Err(io::Error::other(error))),
                    }
                }
                ReadState::Failed => {
                    return Poll::Ready(Err(io::Error::other("content reader unavailable")));
                }
            }
        }
    }
}

pub(crate) struct ContentWriter {
    storage: WriteStorage,
    expected_len: usize,
    written: usize,
    sha256: Sha256,
}

enum WriteStorage {
    Memory(Vec<u8>),
    File(Option<WriterFile>),
}

struct WriterFile {
    file: SpoolFile,
    buffer: Vec<u8>,
}

impl ContentWriter {
    pub(crate) async fn new(
        expected_len: usize,
        memory_limit: usize,
        budget: Arc<SpoolBudget>,
    ) -> Result<Self> {
        let storage = if expected_len <= memory_limit {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(expected_len)?;
            WriteStorage::Memory(bytes)
        } else {
            let reservation = budget.reserve(expected_len)?;
            let file = spawn_blocking(move || -> io::Result<SpoolFile> {
                Ok(SpoolFile {
                    temp: NamedTempFile::new()?,
                    _reservation: reservation,
                })
            })
            .await
            .context("creating content spool task")??;
            WriteStorage::File(Some(WriterFile {
                file,
                buffer: Vec::new(),
            }))
        };
        Ok(Self {
            storage,
            expected_len,
            written: 0,
            sha256: Sha256::new(),
        })
    }

    pub(crate) async fn write(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= self.expected_len - self.written,
            "content exceeds expected length"
        );
        for chunk in bytes.chunks(IO_CHUNK_SIZE) {
            match &mut self.storage {
                WriteStorage::Memory(buffer) => buffer.extend_from_slice(chunk),
                WriteStorage::File(slot) => {
                    let mut file = slot.take().context("content writer unavailable")?;
                    file.buffer.clear();
                    file.buffer.extend_from_slice(chunk);
                    *slot = Some(
                        spawn_blocking(move || -> io::Result<WriterFile> {
                            file.file.temp.as_file_mut().write_all(&file.buffer)?;
                            Ok(file)
                        })
                        .await
                        .context("writing content spool task")??,
                    );
                }
            }
            self.sha256.update(chunk);
            self.written += chunk.len();
            tokio::task::coop::consume_budget().await;
        }
        Ok(())
    }

    pub(crate) async fn finish(self) -> Result<(Content, [u8; 32])> {
        ensure!(
            self.written == self.expected_len,
            "content is shorter than expected"
        );
        let content = match self.storage {
            WriteStorage::Memory(bytes) => Content::from(bytes),
            WriteStorage::File(file) => Content(Storage::File {
                file: Arc::new(ContentFile::Temporary(
                    file.context("content writer unavailable")?.file,
                )),
                offset: 0,
                len: self.expected_len,
            }),
        };
        Ok((content, self.sha256.finalize().into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_input_cannot_hide_retained_parent_memory() {
        let parent: Arc<[u8]> = Arc::from(&b"large parent"[..]);
        let parent_len = parent.len();
        let retained = Arc::downgrade(&parent);
        let content = Content::from(Bytes::from_owner(parent).slice(6..));
        assert_eq!(content.memory_bytes().unwrap().as_ref(), b"parent");
        assert!(retained.upgrade().is_none() || content.resident_len() >= parent_len);
    }

    #[tokio::test]
    async fn file_views_have_independent_read_cursors() -> Result<()> {
        let budget = Arc::new(SpoolBudget::new(10));
        let mut writer = ContentWriter::new(10, 1, budget).await?;
        writer.write(b"0123456789").await?;
        let (content, _) = writer.finish().await?;
        let mut left = content.slice(1..5)?.reader().await?;
        let mut right = content.slice(5..9)?.reader().await?;
        let mut pair = [0; 2];
        left.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"12");
        right.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"56");
        left.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"34");
        right.read_exact(&mut pair).await?;
        assert_eq!(&pair, b"78");
        assert_eq!(left.read(&mut pair).await?, 0);
        assert_eq!(right.read(&mut pair).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn spool_quota_lasts_until_the_final_view_or_reader_drops() -> Result<()> {
        let budget = Arc::new(SpoolBudget::new(4));
        let mut writer = ContentWriter::new(4, 1, Arc::clone(&budget)).await?;
        writer.write(b"data").await?;
        let (content, _) = writer.finish().await?;
        let view = content.slice(1..3)?;
        let reader = view.reader().await?;
        drop(content);
        assert!(ContentWriter::new(4, 1, Arc::clone(&budget)).await.is_err());
        drop(view);
        assert!(ContentWriter::new(4, 1, Arc::clone(&budget)).await.is_err());
        drop(reader);
        let replacement = ContentWriter::new(4, 1, Arc::clone(&budget)).await?;
        drop(replacement);
        let mut replacement = ContentWriter::new(4, 1, budget).await?;
        replacement.write(b"next").await?;
        assert_eq!(
            replacement.finish().await?.0.read_all(4).await?,
            b"next"[..]
        );
        Ok(())
    }
}
