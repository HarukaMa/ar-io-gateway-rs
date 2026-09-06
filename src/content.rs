use std::{
    future::Future,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
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

#[derive(Clone, Debug)]
pub struct Content(Storage);

#[derive(Clone, Debug)]
enum Storage {
    Memory {
        bytes: Bytes,
        resident_len: usize,
    },
    File {
        file: Arc<SpoolFile>,
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
            Storage::File { file, offset, .. } => {
                let storage = Arc::clone(file);
                let offset =
                    u64::try_from(*offset).context("content offset exceeds file limits")?;
                let file = spawn_blocking(move || -> io::Result<ReaderFile> {
                    // try_clone shares the cursor; reopen also checks the file's identity.
                    let mut file = storage.temp.reopen()?;
                    file.seek(SeekFrom::Start(offset))?;
                    Ok(ReaderFile {
                        file,
                        _storage: storage,
                        buffer: Vec::new(),
                        consumed: 0,
                    })
                })
                .await
                .context("opening content reader task")??;
                ReadState::File(file)
            }
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
    // Close this independent handle before dropping the last storage owner on Windows.
    file: std::fs::File,
    _storage: Arc<SpoolFile>,
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
                        file.file.read_exact(&mut file.buffer)?;
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
                file: Arc::new(file.context("content writer unavailable")?.file),
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
