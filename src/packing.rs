use std::{ffi::c_void, mem::MaybeUninit, ptr::NonNull, sync::Mutex};

use anyhow::{Context, Result, bail, ensure};
use axum::body::Bytes;
use serde::{Deserialize, Deserializer, de::Error as _};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio_util::sync::CancellationToken;

pub(crate) const MAX_PACKING_LEN: usize = 12 + 43;
const SUB_CHUNK_SIZE: usize = 8192;
const PARTITION_SIZE: u128 = 3_600_000_000_000;
const SECTOR_SIZE: u128 = 429_184 * SUB_CHUNK_SIZE as u128;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Packing {
    #[default]
    Unpacked,
    Replica29([u8; 32]),
}

impl Packing {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value == "unpacked" {
            return Ok(Self::Unpacked);
        }
        if let Some(address) = value.strip_prefix("replica_2_9_") {
            ensure!(
                value.len() == MAX_PACKING_LEN,
                "invalid replica packing address"
            );
            return Ok(Self::Replica29(crate::decode_fixed(
                address,
                "replica packing address",
            )?));
        }
        bail!("unsupported chunk packing format")
    }
}

impl<'de> Deserialize<'de> for Packing {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

pub(crate) struct Job {
    _permit: SemaphorePermit<'static>,
    background: bool,
    cancellation: CancellationToken,
}

impl Job {
    pub(crate) async fn acquire(cancellation: CancellationToken) -> Result<Self> {
        static HTTP: Semaphore = Semaphore::const_new(1);
        static BACKGROUND: Semaphore = Semaphore::const_new(1);
        let background = crate::BACKGROUND_CPU.try_with(|()| ()).is_ok();
        let semaphore = if background { &BACKGROUND } else { &HTTP };
        Ok(Self {
            _permit: semaphore
                .acquire()
                .await
                .context("replica unpacking admission closed")?,
            background,
            cancellation,
        })
    }

    fn check_cancelled(&self) -> Result<()> {
        ensure!(
            !self.cancellation.is_cancelled(),
            "replica unpacking cancelled"
        );
        Ok(())
    }
}

unsafe extern "C" {
    fn ar_io_replica_create() -> *mut c_void;
    fn ar_io_replica_destroy(state: *mut c_void);
    fn ar_io_replica_slice(
        state: *mut c_void,
        seeds: *const u8,
        index: usize,
        output: *mut u8,
    ) -> i32;
}

struct Decoder(NonNull<c_void>);
// Each decoder, including its native VMs, is exclusively accessed under its worker mutex.
unsafe impl Send for Decoder {}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe { ar_io_replica_destroy(self.0.as_ptr()) };
    }
}

pub(crate) fn unpack(
    bytes: &[u8],
    address: &[u8; 32],
    absolute_end: u128,
    size: usize,
    job: &Job,
) -> Result<Bytes> {
    ensure!(
        bytes.len() == crate::MAX_CHUNK_SIZE as usize,
        "invalid replica packed chunk size"
    );
    ensure!(
        size > 0 && size <= bytes.len(),
        "invalid replica unpacked chunk size"
    );
    ensure!(
        std::arch::is_x86_feature_detected!("sse4.2"),
        "replica unpacking requires SSE4.2"
    );
    job.check_cancelled()?;
    let (partition, first_entropy, slice_index) = position(absolute_end)?;
    static HTTP: Mutex<Option<Decoder>> = Mutex::new(None);
    static BACKGROUND: Mutex<Option<Decoder>> = Mutex::new(None);
    let worker = if job.background { &BACKGROUND } else { &HTTP };
    let mut state = worker
        .lock()
        .map_err(|_| anyhow::anyhow!("replica unpacking worker failed"))?;
    job.check_cancelled()?;
    if state.is_none() {
        *state = Some(Decoder(
            NonNull::new(unsafe { ar_io_replica_create() })
                .context("replica unpacking initialization failed")?,
        ));
    }
    let decoder = state.as_ref().unwrap();
    let mut output = Vec::with_capacity(size);
    let mut entropy = MaybeUninit::<[u8; SUB_CHUNK_SIZE]>::uninit();
    for (index, packed) in bytes.chunks_exact(SUB_CHUNK_SIZE).enumerate() {
        job.check_cancelled()?;
        let key = entropy_key(address, partition, first_entropy + index as u128);
        let seeds =
            std::array::from_fn::<_, 4, _>(|lane| crate::sha256(&[&key, &[lane as u8 + 1]]));
        let success = unsafe {
            ar_io_replica_slice(
                decoder.0.as_ptr(),
                seeds.as_ptr().cast(),
                slice_index,
                entropy.as_mut_ptr().cast(),
            )
        };
        ensure!(success == 1, "replica entropy generation failed");
        // A successful native call writes the complete 8 KiB slice.
        let entropy = unsafe { entropy.assume_init_ref() };
        job.check_cancelled()?;
        let used = size
            .saturating_sub(index * SUB_CHUNK_SIZE)
            .min(SUB_CHUNK_SIZE);
        output.extend((0..used).map(|offset| packed[offset] ^ entropy[offset]));
        ensure!(
            packed[used..]
                .iter()
                .zip(&entropy[used..])
                .all(|(byte, mask)| byte ^ mask == 0),
            "invalid packed chunk padding"
        );
    }
    Ok(output.into())
}

fn position(absolute_end: u128) -> Result<(u128, u128, usize)> {
    ensure!(absolute_end > 0, "invalid replica chunk end offset");
    let threshold = crate::STRICT_DATA_SPLIT_THRESHOLD;
    let chunk_size = crate::MAX_CHUNK_SIZE;
    let padded = if absolute_end > threshold {
        let buckets = (absolute_end - threshold - 1) / chunk_size + 1;
        buckets
            .checked_mul(chunk_size)
            .and_then(|value| threshold.checked_add(value))
            .context("replica chunk offset overflow")?
    } else {
        absolute_end
    };
    let bucket = padded.saturating_sub(chunk_size) / chunk_size * chunk_size;
    let partition = bucket / PARTITION_SIZE;
    let relative = bucket % PARTITION_SIZE;
    let slice_index = ((relative / SECTOR_SIZE) % 1024) as usize;
    let first_entropy = (relative % SECTOR_SIZE) / chunk_size * 32;
    Ok((partition, first_entropy, slice_index))
}

fn entropy_key(address: &[u8; 32], partition: u128, index: u128) -> [u8; 32] {
    let mut partition_note = [0; 32];
    partition_note[16..].copy_from_slice(&partition.to_be_bytes());
    let mut index_note = [0; 32];
    index_note[16..].copy_from_slice(&index.to_be_bytes());
    crate::sha256(&[&partition_note, &index_note, address])
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn replica_entropy_matches_verified_capture() {
        // This slice was part of the captured chunk whose complete payload matched its Merkle leaf.
        let address =
            crate::decode_fixed("9uWujM_SuXqXX1N02GoheYSXaCv9954aiZwWbW8zpZ0", "address").unwrap();
        let (partition, index, slice) = position(253_736_678_753_340).unwrap();
        assert_eq!((partition, index, slice), (70, 409184, 493));
        let key = entropy_key(&address, partition, index);
        let seeds =
            std::array::from_fn::<_, 4, _>(|lane| crate::sha256(&[&key, &[lane as u8 + 1]]));
        let decoder = Decoder(NonNull::new(unsafe { ar_io_replica_create() }).unwrap());
        let mut entropy = MaybeUninit::<[u8; SUB_CHUNK_SIZE]>::uninit();
        assert_eq!(
            unsafe {
                ar_io_replica_slice(
                    decoder.0.as_ptr(),
                    seeds.as_ptr().cast(),
                    slice,
                    entropy.as_mut_ptr().cast(),
                )
            },
            1
        );
        let digest = crate::sha256(&[unsafe { entropy.assume_init_ref() }]);
        assert_eq!(
            crate::URL_SAFE_NO_PAD.encode(digest),
            "danVgJSV2mE5UJh5H72QL0uyJiq1GVq1xxMC3lEbzS8"
        );
    }

    #[test]
    fn replica_bucket_boundaries_preserve_mapping() {
        assert_eq!(position(1).unwrap(), (0, 0, 0));
        assert_eq!(position(262144).unwrap(), (0, 0, 0));
        assert_eq!(position(524287).unwrap(), (0, 0, 0));
        assert_eq!(position(524288).unwrap(), (0, 32, 0));
        assert!(position(0).is_err());
        assert!(position(u128::MAX).is_err());
    }

    #[tokio::test]
    async fn cancelled_replica_job_cannot_produce_payload() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let job = Job::acquire(cancellation).await.unwrap();
        let error = unpack(
            &vec![0; crate::MAX_CHUNK_SIZE as usize],
            &[0; 32],
            1,
            1,
            &job,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "replica unpacking cancelled");
    }
}
