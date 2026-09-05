use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{task::JoinHandle, time::timeout};
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, Row, config::Host};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MIGRATION: &str = include_str!("../migrations/001_block_index.sql");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub hash: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexBlock {
    pub height: u64,
    pub hash: Vec<u8>,
    pub previous_hash: Option<Vec<u8>>,
    pub tx_root: Vec<u8>,
    pub weave_size: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportState {
    pub start_height: u64,
    pub imported_through: Option<u64>,
    pub checkpoint: Checkpoint,
    pub source: String,
}

pub struct BlockStore {
    client: Client,
    driver: JoinHandle<()>,
}

impl Drop for BlockStore {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl BlockStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let config = local_config(url)?;
        let (client, connection) = timeout(CONNECT_TIMEOUT, config.connect(NoTls))
            .await
            .context("PostgreSQL connection timed out")?
            .context("failed to connect to PostgreSQL")?;
        let driver = tokio::spawn(async move {
            // Connection errors are also returned by the client's pending requests.
            let _ = connection.await;
        });
        Ok(Self { client, driver })
    }

    pub async fn migrate(&mut self) -> Result<()> {
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended('ar-io-gateway:block-index:migrate', 0))",
                &[],
            )
            .await?;
        let installed: bool = transaction
            .query_one(
                "SELECT to_regclass('public.ar_io_schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get(0)?;
        if installed {
            let versions = transaction
                .query(
                    "SELECT version, name FROM public.ar_io_schema_migrations ORDER BY version LIMIT 2",
                    &[],
                )
                .await?;
            ensure!(
                versions.len() == 1
                    && versions[0].try_get::<_, i32>(0)? == 1
                    && versions[0].try_get::<_, String>(1)? == "001_block_index",
                "unsupported block-index schema version"
            );
        } else {
            // Plain CREATE statements reject pre-existing, unversioned tables atomically.
            transaction.batch_execute(MIGRATION).await.context(
                "block-index migration failed, existing unversioned tables cannot be adopted",
            )?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn state(&self) -> Result<Option<ImportState>> {
        self.client
            .query_opt(
                "SELECT start_height, imported_through, checkpoint_height, checkpoint_hash, source
                 FROM public.block_index_state WHERE singleton",
                &[],
            )
            .await?
            .as_ref()
            .map(state_from_row)
            .transpose()
    }

    pub(crate) async fn advance_checkpoint(
        &self,
        previous: &Checkpoint,
        next: &Checkpoint,
        source: &str,
    ) -> Result<()> {
        ensure!(next.height > previous.height, "checkpoint must advance");
        ensure!(next.hash.len() == 48, "checkpoint hash must be 48 bytes");
        let changed = self
            .client
            .execute(
                "UPDATE public.block_index_state
             SET checkpoint_height = $1, checkpoint_hash = $2
             WHERE singleton AND checkpoint_height = $3 AND checkpoint_hash = $4
               AND source = $5",
                &[
                    &sql_height(next.height)?,
                    &next.hash,
                    &sql_height(previous.height)?,
                    &previous.hash,
                    &source,
                ],
            )
            .await?;
        ensure!(changed == 1, "stored checkpoint or trusted source changed");
        Ok(())
    }

    /// The caller includes the requested interval's predecessor in start_height.
    pub async fn initialize(
        &mut self,
        start_height: u64,
        checkpoint: &Checkpoint,
        source: &str,
    ) -> Result<ImportState> {
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let start = sql_height(start_height)?;
        let checkpoint_height = sql_height(checkpoint.height)?;
        ensure!(
            start_height <= checkpoint.height,
            "start exceeds checkpoint"
        );
        ensure!(
            checkpoint.hash.len() == 48,
            "checkpoint hash must be 48 bytes"
        );
        ensure!(
            !source.is_empty() && !source.contains('\0'),
            "invalid block-index source"
        );
        transaction
            .execute(
                "INSERT INTO public.block_index_state
                     (start_height, checkpoint_height, checkpoint_hash, source)
                 VALUES ($1, $2, $3, $4) ON CONFLICT (singleton) DO NOTHING",
                &[&start, &checkpoint_height, &checkpoint.hash, &source],
            )
            .await?;
        let state = state_from_row(
            &transaction
                .query_one(
                    "SELECT start_height, imported_through, checkpoint_height, checkpoint_hash, source
                     FROM public.block_index_state WHERE singleton FOR UPDATE",
                    &[],
                )
                .await?,
        )?;
        ensure!(
            state.start_height == start_height,
            "block-index start height changed"
        );
        validate_pin(&state, checkpoint, source)?;
        transaction.commit().await?;
        Ok(state)
    }

    pub async fn commit_batch(
        &mut self,
        blocks: &[IndexBlock],
        checkpoint: &Checkpoint,
        source: &str,
    ) -> Result<()> {
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let state = state_from_row(
            &transaction
                .query_opt(
                    "SELECT start_height, imported_through, checkpoint_height, checkpoint_hash, source
                     FROM public.block_index_state WHERE singleton FOR UPDATE",
                    &[],
                )
                .await?
                .context("block index is not initialized")?,
        )?;
        validate_pin(&state, checkpoint, source)?;
        let predecessor = match state.imported_through {
            Some(height) => Some(block_from_row(
                &transaction
                    .query_one(
                        "SELECT b.height, b.hash, b.previous_hash, b.tx_root, b.weave_size::text
                         FROM public.canonical_blocks c
                         JOIN public.blocks b ON b.height = c.height AND b.hash = c.block_hash
                         WHERE c.height = $1",
                        &[&sql_height(height)?],
                    )
                    .await
                    .context("stored block-index predecessor is missing")?,
                0,
            )?),
            None => None,
        };
        validate_batch(blocks, &state, predecessor.as_ref())?;
        let mut heights = Vec::with_capacity(blocks.len());
        let mut hashes = Vec::with_capacity(blocks.len());
        let mut previous_hashes = Vec::with_capacity(blocks.len());
        let mut roots = Vec::with_capacity(blocks.len());
        let mut weave_sizes = Vec::with_capacity(blocks.len());
        for block in blocks {
            heights.push(sql_height(block.height)?);
            hashes.push(block.hash.as_slice());
            previous_hashes.push(block.previous_hash.as_deref());
            roots.push(block.tx_root.as_slice());
            weave_sizes.push(block.weave_size.to_string());
        }
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
            &[&heights, &hashes, &previous_hashes, &roots, &weave_sizes];
        transaction
            .execute(
                "INSERT INTO public.blocks (height, hash, previous_hash, tx_root, weave_size)
                 SELECT height, hash, previous_hash, tx_root, weave_size::public.uint128
                 FROM unnest($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[], $5::text[])
                      AS incoming(height, hash, previous_hash, tx_root, weave_size)
                 ON CONFLICT (hash) DO NOTHING",
                parameters,
            )
            .await?;
        let conflict = transaction
            .query_opt(
                "SELECT incoming.height
                 FROM unnest($1::bigint[], $2::bytea[], $3::bytea[], $4::bytea[], $5::text[])
                      AS incoming(height, hash, previous_hash, tx_root, weave_size)
                 JOIN public.blocks b ON b.hash = incoming.hash
                 WHERE ROW(b.height, b.previous_hash, b.tx_root, b.weave_size)
                     IS DISTINCT FROM
                       ROW(incoming.height, incoming.previous_hash, incoming.tx_root,
                           incoming.weave_size::numeric)
                 LIMIT 1",
                parameters,
            )
            .await?;
        if let Some(row) = conflict {
            anyhow::bail!(
                "conflicting immutable block at height {}",
                row.get::<_, i64>(0)
            );
        }
        transaction
            .execute(
                "INSERT INTO public.canonical_blocks (height, block_hash)
                 SELECT * FROM unnest($1::bigint[], $2::bytea[])",
                &[&heights, &hashes],
            )
            .await
            .context("conflicting canonical block in batch")?;
        let through = sql_height(blocks.last().context("empty block-index batch")?.height)?;
        transaction
            .execute(
                "UPDATE public.block_index_state SET imported_through = $1 WHERE singleton",
                &[&through],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn block_pair(&self, height: u64) -> Result<Option<(IndexBlock, IndexBlock)>> {
        if height == 0 {
            return Ok(None);
        }
        let row = self
            .client
            .query_opt(
                "SELECT p.height, p.hash, p.previous_hash, p.tx_root, p.weave_size::text,
                        b.height, b.hash, b.previous_hash, b.tx_root, b.weave_size::text
                 FROM public.block_index_state s
                 JOIN public.canonical_blocks c
                   ON c.height > s.start_height AND c.height <= s.imported_through
                 JOIN public.blocks b ON b.height = c.height AND b.hash = c.block_hash
                 JOIN public.canonical_blocks pc ON pc.height = c.height - 1
                 JOIN public.blocks p ON p.height = pc.height AND p.hash = pc.block_hash
                 WHERE s.singleton AND c.height = $1
                   AND b.previous_hash = p.hash AND b.weave_size >= p.weave_size",
                &[&sql_height(height)?],
            )
            .await?;
        row.as_ref().map(pair_from_row).transpose()
    }

    pub async fn block_for_offset(&self, offset: u128) -> Result<Option<(IndexBlock, IndexBlock)>> {
        if offset == 0 {
            return Ok(None);
        }
        let row = self
            .client
            .query_opt(
                "SELECT p.height, p.hash, p.previous_hash, p.tx_root, p.weave_size::text,
                        b.height, b.hash, b.previous_hash, b.tx_root, b.weave_size::text
                 FROM public.block_index_state s
                 JOIN public.canonical_blocks c
                   ON c.height > s.start_height AND c.height <= s.imported_through
                 JOIN public.blocks b ON b.height = c.height AND b.hash = c.block_hash
                 JOIN public.canonical_blocks pc ON pc.height = c.height - 1
                 JOIN public.blocks p ON p.height = pc.height AND p.hash = pc.block_hash
                 WHERE s.singleton AND b.previous_hash = p.hash
                   AND p.weave_size < $1::text::numeric AND b.weave_size >= $1::text::numeric
                 ORDER BY b.weave_size, c.height LIMIT 1",
                &[&offset.to_string()],
            )
            .await?;
        row.as_ref().map(pair_from_row).transpose()
    }
}

fn local_config(url: &str) -> Result<Config> {
    let mut config: Config = url
        .parse()
        .context("invalid PostgreSQL connection string")?;
    ensure!(
        config.get_hosts().len() <= 1 && config.get_hostaddrs().len() <= 1,
        "block storage requires one local PostgreSQL endpoint"
    );
    ensure!(
        !config.get_hosts().is_empty() || !config.get_hostaddrs().is_empty(),
        "PostgreSQL requires an explicit loopback host or Unix socket"
    );
    for address in config.get_hostaddrs() {
        ensure!(
            address.is_loopback(),
            "unencrypted PostgreSQL requires a loopback address"
        );
    }
    let address = match config.get_hosts().first() {
        Some(Host::Tcp(host)) => {
            let address: IpAddr = if host.eq_ignore_ascii_case("localhost") {
                IpAddr::from([127, 0, 0, 1])
            } else {
                host.parse()
                    .context("unencrypted PostgreSQL requires a loopback host")?
            };
            ensure!(
                address.is_loopback(),
                "unencrypted PostgreSQL requires a loopback host"
            );
            Some(address)
        }
        #[cfg(unix)]
        Some(Host::Unix(_)) => None,
        None => None,
    };
    if config.get_hostaddrs().is_empty() {
        if let Some(address) = address {
            // Pin localhost to a loopback address without relying on DNS configuration.
            config.hostaddr(address);
        }
    }
    config.connect_timeout(CONNECT_TIMEOUT);
    config.options(
        "-c statement_timeout=15000 -c lock_timeout=5000 \
         -c idle_in_transaction_session_timeout=30000 -c search_path=pg_catalog,public",
    );
    Ok(config)
}

fn sql_height(height: u64) -> Result<i64> {
    i64::try_from(height).context("block height exceeds PostgreSQL bigint")
}

fn validate_pin(state: &ImportState, checkpoint: &Checkpoint, source: &str) -> Result<()> {
    ensure!(
        state.checkpoint == *checkpoint,
        "block-index checkpoint changed"
    );
    ensure!(state.source == source, "block-index source changed");
    Ok(())
}

fn validate_batch<'a>(
    blocks: &'a [IndexBlock],
    state: &ImportState,
    mut predecessor: Option<&'a IndexBlock>,
) -> Result<()> {
    ensure!(
        !blocks.is_empty() && blocks.len() <= 256,
        "block-index batch must contain 1 to 256 blocks"
    );
    ensure!(
        predecessor.map(|block| block.height) == state.imported_through,
        "stored block-index predecessor does not match cursor"
    );
    let first_height = match state.imported_through {
        Some(height) => height.checked_add(1).context("block height overflow")?,
        None => state.start_height,
    };
    for (index, block) in blocks.iter().enumerate() {
        sql_height(block.height)?;
        ensure!(
            Some(block.height) == first_height.checked_add(index as u64),
            "block-index batch is not contiguous at height {}",
            block.height
        );
        ensure!(
            block.height <= state.checkpoint.height,
            "block exceeds pinned checkpoint"
        );
        ensure!(block.hash.len() == 48, "block hash must be 48 bytes");
        ensure!(
            block
                .previous_hash
                .as_ref()
                .is_none_or(|hash| hash.len() == 48),
            "previous block hash must be 48 bytes"
        );
        ensure!(
            matches!(block.tx_root.len(), 0 | 32),
            "transaction root must be empty or 32 bytes"
        );
        if block.height == state.checkpoint.height {
            ensure!(
                block.hash == state.checkpoint.hash,
                "block conflicts with pinned checkpoint"
            );
        }
        if let Some(previous) = predecessor {
            ensure!(
                block.previous_hash.as_deref() == Some(previous.hash.as_slice()),
                "block-index predecessor hash mismatch at height {}",
                block.height
            );
            ensure!(
                block.weave_size >= previous.weave_size,
                "block-index weave size decreased"
            );
        }
        predecessor = Some(block);
    }
    Ok(())
}

fn state_from_row(row: &Row) -> Result<ImportState> {
    Ok(ImportState {
        start_height: u64::try_from(row.try_get::<_, i64>(0)?)?,
        imported_through: row
            .try_get::<_, Option<i64>>(1)?
            .map(u64::try_from)
            .transpose()?,
        checkpoint: Checkpoint {
            height: u64::try_from(row.try_get::<_, i64>(2)?)?,
            hash: row.try_get(3)?,
        },
        source: row.try_get(4)?,
    })
}

fn block_from_row(row: &Row, offset: usize) -> Result<IndexBlock> {
    Ok(IndexBlock {
        height: u64::try_from(row.try_get::<_, i64>(offset)?)?,
        hash: row.try_get(offset + 1)?,
        previous_hash: row.try_get(offset + 2)?,
        tx_root: row.try_get(offset + 3)?,
        weave_size: row
            .try_get::<_, String>(offset + 4)?
            .parse()
            .context("invalid stored uint128 weave size")?,
    })
}

fn pair_from_row(row: &Row) -> Result<(IndexBlock, IndexBlock)> {
    Ok((block_from_row(row, 0)?, block_from_row(row, 5)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires DATABASE_URL for an initialized test block index"]
    async fn checkpoint_advance_rejects_stale_writers_and_preserves_coverage() {
        let store = BlockStore::connect(&std::env::var("DATABASE_URL").unwrap())
            .await
            .unwrap();
        store.client.batch_execute("BEGIN").await.unwrap();
        let original = store.state().await.unwrap().unwrap();
        let next = Checkpoint {
            height: original.checkpoint.height + 1,
            hash: vec![42; 48],
        };
        assert!(
            store
                .advance_checkpoint(&original.checkpoint, &next, "wrong-source")
                .await
                .is_err()
        );
        store
            .advance_checkpoint(&original.checkpoint, &next, &original.source)
            .await
            .unwrap();
        assert!(
            store
                .advance_checkpoint(&original.checkpoint, &next, &original.source)
                .await
                .is_err()
        );
        assert!(
            store
                .advance_checkpoint(&next, &original.checkpoint, &original.source)
                .await
                .is_err()
        );
        let changed = store.state().await.unwrap().unwrap();
        assert_eq!(changed.checkpoint, next);
        assert_eq!(changed.imported_through, original.imported_through);
        assert_eq!(changed.start_height, original.start_height);
        store.client.batch_execute("ROLLBACK").await.unwrap();
        assert_eq!(store.state().await.unwrap(), Some(original));
    }

    #[test]
    fn resumed_batches_preserve_linkage_and_allow_empty_blocks() {
        let previous = IndexBlock {
            height: 7,
            hash: vec![7; 48],
            previous_hash: None,
            tx_root: vec![1; 32],
            weave_size: u128::MAX,
        };
        let state = ImportState {
            start_height: 7,
            imported_through: Some(7),
            checkpoint: Checkpoint {
                height: 8,
                hash: vec![8; 48],
            },
            source: "http://localhost:1984".to_owned(),
        };
        let mut next = IndexBlock {
            height: 8,
            hash: state.checkpoint.hash.clone(),
            previous_hash: Some(previous.hash.clone()),
            tx_root: Vec::new(),
            weave_size: u128::MAX,
        };
        validate_batch(&[next.clone()], &state, Some(&previous)).unwrap();
        next.weave_size -= 1;
        assert!(validate_batch(&[next.clone()], &state, Some(&previous)).is_err());
        next.weave_size = u128::MAX;
        next.previous_hash = None;
        assert!(validate_batch(&[next.clone()], &state, Some(&previous)).is_err());
        next.previous_hash = Some(previous.hash.clone());
        next.hash[0] ^= 1;
        assert!(validate_batch(&[next], &state, Some(&previous)).is_err());
    }

    #[test]
    fn unencrypted_connections_cannot_escape_loopback() {
        for url in [
            "host=192.0.2.1 dbname=ar_io_rust_test",
            "host=localhost hostaddr=192.0.2.1 dbname=ar_io_rust_test",
            "host=example.org hostaddr=127.0.0.1 dbname=ar_io_rust_test",
        ] {
            assert!(local_config(url).is_err());
        }
        let config = local_config("host=localhost dbname=ar_io_rust_test").unwrap();
        assert_eq!(config.get_hostaddrs(), &[IpAddr::from([127, 0, 0, 1])]);
    }
}
