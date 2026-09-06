use std::{net::IpAddr, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{task::JoinHandle, time::timeout};
use tokio_postgres::{Client, Config, IsolationLevel, NoTls, Row, Transaction, config::Host};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_block_index",
        include_str!("../migrations/001_block_index.sql"),
    ),
    (
        "002_metadata",
        include_str!("../migrations/002_metadata.sql"),
    ),
    ("003_bundles", include_str!("../migrations/003_bundles.sql")),
    (
        "004_content_cache",
        include_str!("../migrations/004_content_cache.sql"),
    ),
];
const METADATA_BATCH_SIZE: usize = 256;
const ROW_BATCH_SIZE: usize = 1_000;

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ObjectMetadata {
    pub(crate) id: Vec<u8>,
    pub(crate) kind: i16,
    pub(crate) signature: Vec<u8>,
    pub(crate) anchor: Vec<u8>,
    pub(crate) owner_address: Vec<u8>,
    pub(crate) owner_public_key: Vec<u8>,
    pub(crate) target: Vec<u8>,
    pub(crate) data_size: u128,
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) signature_type: i16,
    pub(crate) format: Option<i16>,
    pub(crate) quantity: Option<String>,
    pub(crate) reward: Option<String>,
    pub(crate) denomination: Option<u32>,
    pub(crate) data_root: Option<Vec<u8>>,
    pub(crate) tags: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BundleLocation {
    pub(crate) id: Vec<u8>,
    pub(crate) parent_id: Vec<u8>,
    pub(crate) parent_offset: Option<u128>,
    pub(crate) item_offset: u128,
    pub(crate) item_size: u128,
    pub(crate) data_offset: u128,
    pub(crate) root_offset: u128,
}

#[derive(Debug)]
pub(crate) struct IndexedBundle {
    pub(crate) root_id: Vec<u8>,
    pub(crate) data_size: u128,
    pub(crate) content_type: Option<String>,
    pub(crate) locations: Vec<BundleLocation>,
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
        let applied = if installed {
            let versions = transaction
                .query(
                    "SELECT version, name FROM public.ar_io_schema_migrations
                     ORDER BY version LIMIT $1",
                    &[&i64::try_from(MIGRATIONS.len() + 1)?],
                )
                .await?;
            ensure!(
                !versions.is_empty() && versions.len() <= MIGRATIONS.len(),
                "unsupported block-index schema version"
            );
            for (index, version) in versions.iter().enumerate() {
                ensure!(
                    version.try_get::<_, i32>(0)? == i32::try_from(index + 1)?
                        && version.try_get::<_, String>(1)? == MIGRATIONS[index].0,
                    "unsupported or mismatched block-index schema version"
                );
            }
            versions.len()
        } else {
            0
        };
        for (name, migration) in &MIGRATIONS[applied..] {
            // Plain CREATE statements reject pre-existing, unversioned tables atomically.
            transaction
                .batch_execute(migration)
                .await
                .with_context(|| {
                    format!(
                        "migration {name} failed, existing unversioned tables cannot be adopted"
                    )
                })?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn require_content_cache(&self) -> Result<()> {
        let installed: bool = self
            .client
            .query_one(
                "SELECT to_regclass('public.content_cache') IS NOT NULL
                    AND to_regclass('public.ar_io_schema_migrations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get(0)?;
        let instruction = "disk cache requires schema migration 004_content_cache; apply \
            migrations/004_content_cache.sql through the approved migration workflow \
            before enabling disk cache";
        ensure!(installed, "{instruction}");
        let version: bool = self
            .client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM public.ar_io_schema_migrations
                 WHERE version = 4 AND name = '004_content_cache')",
                &[],
            )
            .await?
            .try_get(0)?;
        ensure!(version, "{instruction}");
        Ok(())
    }

    pub(crate) async fn cached_content(&self, id: &[u8; 32]) -> Result<Option<String>> {
        self.client
            .query_opt(
                "SELECT cached.metadata FROM public.content_cache cached
                 JOIN public.canonical_blocks c
                   ON c.height = cached.block_height AND c.block_hash = cached.block_hash
                 JOIN public.block_index_state s
                   ON s.singleton AND c.height > s.start_height
                   AND c.height <= s.imported_through
                 WHERE cached.id = $1 AND octet_length(cached.metadata) <= 1048576",
                &[&id.as_slice()],
            )
            .await?
            .map(|row| row.try_get(0).map_err(Into::into))
            .transpose()
    }

    pub(crate) async fn cache_content(
        &self,
        id: &[u8; 32],
        height: u64,
        block_hash: &[u8],
        metadata: &str,
    ) -> Result<bool> {
        ensure!(block_hash.len() == 48, "cache block hash must be 48 bytes");
        ensure!(metadata.len() <= 1_048_576, "cache metadata exceeds 1 MiB");
        let row = self
            .client
            .query_one(
                "WITH anchor AS MATERIALIZED (
                    SELECT c.height, c.block_hash FROM public.canonical_blocks c
                    JOIN public.block_index_state s
                      ON s.singleton AND c.height > s.start_height
                      AND c.height <= s.imported_through
                    WHERE c.height = $2 AND c.block_hash = $3
                 ), admitted AS (
                    INSERT INTO public.content_cache AS stored
                        (id, block_height, block_hash, metadata)
                    SELECT $1, height, block_hash, $4 FROM anchor WHERE true
                    ON CONFLICT (id) DO UPDATE SET id = stored.id
                    WHERE ROW(stored.block_height, stored.block_hash, stored.metadata)
                        = ROW(EXCLUDED.block_height, EXCLUDED.block_hash, EXCLUDED.metadata)
                    RETURNING id
                 )
                 SELECT EXISTS (SELECT 1 FROM anchor), EXISTS (SELECT 1 FROM admitted)",
                &[&id.as_slice(), &sql_height(height)?, &block_hash, &metadata],
            )
            .await?;
        let anchored: bool = row.try_get(0)?;
        let admitted: bool = row.try_get(1)?;
        ensure!(
            !anchored || admitted,
            "conflicting immutable cached content descriptor"
        );
        Ok(admitted)
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

    pub(crate) async fn pending_metadata_blocks(
        &self,
        start: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<IndexBlock>> {
        ensure!(start <= end, "metadata range is reversed");
        ensure!(
            (1..=METADATA_BATCH_SIZE).contains(&limit),
            "metadata query limit must be between 1 and 256"
        );
        self.client
            .query(
                "SELECT b.height, b.hash, b.previous_hash, b.tx_root, b.weave_size::text
                 FROM public.block_index_state s
                 JOIN public.canonical_blocks c
                   ON c.height >= s.start_height AND c.height <= s.imported_through
                 JOIN public.blocks b ON b.height = c.height AND b.hash = c.block_hash
                 WHERE s.singleton AND c.height BETWEEN $1 AND $2 AND b.timestamp IS NULL
                 ORDER BY c.height LIMIT $3",
                &[
                    &sql_height(start)?,
                    &sql_height(end)?,
                    &i64::try_from(limit)?,
                ],
            )
            .await?
            .iter()
            .map(|row| block_from_row(row, 0))
            .collect()
    }

    pub(crate) async fn record_block_metadata(
        &mut self,
        block: &IndexBlock,
        timestamp: u64,
        transaction_ids: &[Vec<u8>],
    ) -> Result<()> {
        let height = sql_height(block.height)?;
        let timestamp = i64::try_from(timestamp).context("timestamp exceeds PostgreSQL bigint")?;
        let count = i32::try_from(transaction_ids.len()).context("too many block transactions")?;
        ensure!(
            transaction_ids.iter().all(|id| id.len() == 32),
            "transaction ID must be 32 bytes"
        );
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let row = transaction
            .query_opt(
                "SELECT b.height, b.hash, b.previous_hash, b.tx_root, b.weave_size::text, b.timestamp
                 FROM public.block_index_state s
                 JOIN public.canonical_blocks c
                   ON c.height >= s.start_height AND c.height <= s.imported_through
                 JOIN public.blocks b ON b.height = c.height AND b.hash = c.block_hash
                 WHERE s.singleton AND c.height = $1 FOR UPDATE OF b",
                &[&height],
            )
            .await?
            .context("metadata block is outside the imported canonical index")?;
        ensure!(
            block_from_row(&row, 0)? == *block,
            "metadata block conflicts with the imported canonical index"
        );
        let stored_timestamp: Option<i64> = row.try_get(5)?;
        ensure!(
            stored_timestamp.is_none_or(|stored| stored == timestamp),
            "conflicting immutable block timestamp"
        );
        let mut identities: Vec<_> = transaction_ids.iter().map(Vec::as_slice).collect();
        identities.sort_unstable();
        identities.dedup();
        if stored_timestamp.is_none() {
            for ids in identities.chunks(ROW_BATCH_SIZE) {
                Self::lock_bundle_roots(&transaction, ids).await?;
            }
        }
        if stored_timestamp.is_none() {
            // Consistent identity order also bounds uniqueness-lock acquisition across writers.
            for ids in identities.chunks(ROW_BATCH_SIZE) {
                transaction
                    .execute(
                        "INSERT INTO public.objects (id, kind)
                         SELECT id, 0 FROM unnest($1::bytea[]) AS incoming(id) ORDER BY id
                         ON CONFLICT (id) DO NOTHING",
                        &[&ids],
                    )
                    .await?;
            }
        }
        for (batch, ids) in transaction_ids.chunks(ROW_BATCH_SIZE).enumerate() {
            let ids: Vec<_> = ids.iter().map(Vec::as_slice).collect();
            let offset = i64::try_from(batch * ROW_BATCH_SIZE)?;
            if stored_timestamp.is_none() {
                transaction
                    .execute(
                        "INSERT INTO public.block_transactions (block_hash, position, object_key)
                         SELECT $1, ($3 + incoming.ordinality - 1)::integer, o.key
                         FROM unnest($2::bytea[]) WITH ORDINALITY AS incoming(id, ordinality)
                         JOIN public.objects o ON o.id = incoming.id
                         ON CONFLICT (block_hash, position) DO NOTHING",
                        &[&block.hash, &ids, &offset],
                    )
                    .await?;
            }
            let conflict = transaction
                .query_opt(
                    "SELECT incoming.ordinality
                     FROM unnest($2::bytea[]) WITH ORDINALITY AS incoming(id, ordinality)
                     LEFT JOIN public.block_transactions bt
                       ON bt.block_hash = $1 AND bt.position = $3 + incoming.ordinality - 1
                     LEFT JOIN public.objects o ON o.key = bt.object_key
                     WHERE o.id IS DISTINCT FROM incoming.id OR o.kind IS DISTINCT FROM 0::smallint
                     LIMIT 1",
                    &[&block.hash, &ids, &offset],
                )
                .await?;
            ensure!(conflict.is_none(), "conflicting immutable block membership");
        }
        let stored_count: i64 = transaction
            .query_one(
                "SELECT count(*) FROM public.block_transactions WHERE block_hash = $1",
                &[&block.hash],
            )
            .await?
            .try_get(0)?;
        ensure!(
            stored_count == i64::from(count),
            "conflicting immutable block membership count"
        );
        if stored_timestamp.is_none() {
            for ids in identities.chunks(ROW_BATCH_SIZE) {
                transaction
                    .execute(
                        "INSERT INTO public.canonical_placements AS placement
                            (object_key, block_height, position, kind, id)
                         SELECT o.key, $3, min(bt.position), o.kind, o.id
                         FROM public.objects o
                         JOIN public.block_transactions bt ON bt.object_key = o.key
                         WHERE bt.block_hash = $1 AND o.id = ANY($2::bytea[])
                         GROUP BY o.key ORDER BY o.id
                         ON CONFLICT (object_key) DO UPDATE
                         SET block_height = EXCLUDED.block_height, position = EXCLUDED.position,
                             kind = EXCLUDED.kind, id = EXCLUDED.id
                         WHERE ROW(EXCLUDED.block_height, EXCLUDED.position)
                             < ROW(placement.block_height, placement.position)",
                        &[&block.hash, &ids, &height],
                    )
                    .await?;
            }
            transaction
                .execute(
                    "UPDATE public.blocks SET timestamp = $2 WHERE hash = $1",
                    &[&block.hash, &timestamp],
                )
                .await?;
            // A root can first be observed in a later block, then gain an earlier placement.
            let mut after = 0_i64;
            loop {
                let keys = transaction
                    .query(
                        "SELECT DISTINCT l.object_key
                     FROM public.block_transactions bt
                     JOIN public.item_locations l ON l.root_key=bt.object_key
                     WHERE bt.block_hash=$1 AND l.object_key>$2
                     ORDER BY l.object_key LIMIT 256",
                        &[&block.hash, &after],
                    )
                    .await?
                    .iter()
                    .map(|row| row.try_get(0))
                    .collect::<std::result::Result<Vec<i64>, _>>()?;
                let Some(&last) = keys.last() else {
                    break;
                };
                Self::refresh_item_placements(&transaction, &keys).await?;
                after = last;
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn pending_transactions(
        &self,
        start: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        ensure!(start <= end, "metadata range is reversed");
        ensure!(
            (1..=METADATA_BATCH_SIZE).contains(&limit),
            "metadata query limit must be between 1 and 256"
        );
        self.client
            .query(
                "SELECT o.id, p.block_height
                 FROM public.canonical_placements p
                 JOIN public.objects o ON o.key = p.object_key
                 WHERE o.kind = 0 AND NOT o.metadata_complete AND EXISTS (
                     SELECT 1 FROM public.block_index_state s
                     JOIN public.canonical_blocks c
                       ON c.height >= s.start_height AND c.height <= s.imported_through
                     JOIN public.block_transactions bt ON bt.block_hash = c.block_hash
                     WHERE s.singleton AND c.height BETWEEN $1 AND $2 AND bt.object_key = o.key
                 )
                 ORDER BY p.block_height, p.position, p.kind, p.id LIMIT $3",
                &[
                    &sql_height(start)?,
                    &sql_height(end)?,
                    &i64::try_from(limit)?,
                ],
            )
            .await?
            .iter()
            .map(|row| Ok((row.try_get(0)?, u64::try_from(row.try_get::<_, i64>(1)?)?)))
            .collect()
    }

    pub(crate) async fn pending_bundles(
        &self,
        start: u64,
        end: u64,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, u64)>> {
        ensure!(start <= end, "bundle range is reversed");
        ensure!(
            (1..=METADATA_BATCH_SIZE).contains(&limit),
            "bundle query limit must be between 1 and 256"
        );
        self.client.query(
            "SELECT o.id, p.block_height
             FROM public.canonical_placements p
             JOIN public.objects o ON o.key=p.object_key
             LEFT JOIN public.bundle_progress progress ON progress.root_key=o.key
             WHERE o.kind=0 AND o.metadata_complete AND NOT coalesce(progress.complete, false)
               AND p.block_height BETWEEN $1 AND $2
               AND EXISTS (
                   SELECT 1 FROM public.block_index_state s
                   JOIN public.canonical_blocks cb
                     ON cb.height > s.start_height AND cb.height <= s.imported_through
                   JOIN public.blocks b ON b.hash=cb.block_hash
                   JOIN public.block_transactions bt ON bt.block_hash=cb.block_hash
                   WHERE s.singleton AND cb.height=p.block_height AND bt.position=p.position
                     AND bt.object_key=o.key AND b.timestamp IS NOT NULL)
               AND EXISTS (
                   SELECT 1 FROM public.object_tags t
                   JOIN public.tag_names n ON n.key=t.name_key
                   JOIN public.tag_values v ON v.key=t.value_key
                   WHERE t.object_key=o.key AND n.value='Bundle-Format'::bytea AND v.value='binary'::bytea)
               AND EXISTS (
                   SELECT 1 FROM public.object_tags t
                   JOIN public.tag_names n ON n.key=t.name_key
                   JOIN public.tag_values v ON v.key=t.value_key
                   WHERE t.object_key=o.key AND n.value='Bundle-Version'::bytea AND v.value='2.0.0'::bytea)
             ORDER BY p.block_height, p.position, p.id LIMIT $3",
            &[&sql_height(start)?, &sql_height(end)?, &i64::try_from(limit)?],
        ).await?.iter().map(|row| Ok((row.try_get(0)?, u64::try_from(row.try_get::<_, i64>(1)?)?))).collect()
    }

    pub(crate) async fn commit_bundle_batch(
        &mut self,
        root_id: &[u8],
        objects: &[ObjectMetadata],
        locations: &[BundleLocation],
        complete: bool,
    ) -> Result<()> {
        ensure!(root_id.len() == 32, "bundle root ID must be 32 bytes");
        ensure!(
            locations.len() <= METADATA_BATCH_SIZE && objects.len() <= METADATA_BATCH_SIZE,
            "bundle batch exceeds 256 occurrences or objects"
        );
        let mut locations: Vec<_> = locations.iter().collect();
        locations.sort_unstable_by_key(|location| location.root_offset);
        ensure!(
            locations
                .windows(2)
                .all(|pair| pair[0].root_offset != pair[1].root_offset),
            "duplicate bundle offset in batch"
        );
        let metadata: std::collections::BTreeMap<_, _> = objects
            .iter()
            .map(|object| (object.id.as_slice(), object))
            .collect();
        for object in objects {
            ensure!(
                object.kind == 1
                    && object.id != root_id
                    && object.format.is_none()
                    && object.quantity.is_none()
                    && object.reward.is_none()
                    && object.denomination.is_none()
                    && object.data_root.is_none(),
                "bundle metadata must describe data items"
            );
            ensure!(
                locations.iter().any(|location| location.id == object.id),
                "bundle metadata has no occurrence"
            );
        }
        for location in &locations {
            ensure!(
                location.id.len() == 32 && location.parent_id.len() == 32,
                "bundle item and parent IDs must be 32 bytes"
            );
            let object = metadata
                .get(location.id.as_slice())
                .context("bundle occurrence lacks metadata")?;
            ensure!(
                location.item_offset >= 96
                    && location.data_offset > 0
                    && location.item_size.checked_sub(location.data_offset)
                        == Some(object.data_size),
                "invalid bundle item offsets or size"
            );
            match location.parent_offset {
                None => ensure!(
                    location.parent_id == root_id && location.root_offset == location.item_offset,
                    "direct bundle occurrence has an invalid parent or root offset"
                ),
                Some(parent) => ensure!(
                    parent < location.root_offset && location.parent_id != root_id,
                    "nested bundle occurrence has an invalid parent"
                ),
            }
        }
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        Self::lock_bundle_roots(&transaction, &[root_id]).await?;
        let root = transaction.query_opt(
            "SELECT o.key, o.data_size::text
             FROM public.objects o
             WHERE o.id=$1 AND o.kind=0 AND o.metadata_complete
               AND EXISTS (
                   SELECT 1 FROM public.block_index_state s
                   JOIN public.canonical_blocks cb
                     ON cb.height > s.start_height AND cb.height <= s.imported_through
                   JOIN public.blocks b ON b.hash=cb.block_hash
                   JOIN public.block_transactions bt ON bt.block_hash=cb.block_hash
                   WHERE s.singleton AND bt.object_key=o.key AND b.timestamp IS NOT NULL)
               AND EXISTS (
                   SELECT 1 FROM public.object_tags t
                   JOIN public.tag_names n ON n.key=t.name_key
                   JOIN public.tag_values v ON v.key=t.value_key
                   WHERE t.object_key=o.key AND n.value='Bundle-Format'::bytea AND v.value='binary'::bytea)
               AND EXISTS (
                   SELECT 1 FROM public.object_tags t
                   JOIN public.tag_names n ON n.key=t.name_key
                   JOIN public.tag_values v ON v.key=t.value_key
                   WHERE t.object_key=o.key AND n.value='Bundle-Version'::bytea AND v.value='2.0.0'::bytea)",
            &[&root_id],
        ).await?.context("bundle root lacks completed canonical ANS-104 metadata")?;
        let root_key: i64 = root.try_get(0)?;
        let root_size: u128 = root.try_get::<_, String>(1)?.parse()?;
        for location in &locations {
            ensure!(
                location
                    .root_offset
                    .checked_add(location.item_size)
                    .is_some_and(|end| end <= root_size),
                "bundle occurrence exceeds root payload"
            );
        }
        let was_complete: bool = transaction
            .query_one(
                "INSERT INTO public.bundle_progress AS stored (root_key) VALUES ($1)
             ON CONFLICT (root_key) DO UPDATE SET complete=stored.complete RETURNING complete",
                &[&root_key],
            )
            .await?
            .try_get(0)?;
        let keys = Self::write_objects(&transaction, objects).await?;
        let ids: Vec<_> = locations
            .iter()
            .map(|location| location.id.as_slice())
            .collect();
        let parents: Vec<_> = locations
            .iter()
            .map(|location| location.parent_id.as_slice())
            .collect();
        let parent_offsets: Vec<_> = locations
            .iter()
            .map(|location| location.parent_offset.map(|offset| offset.to_string()))
            .collect();
        let item_offsets: Vec<_> = locations
            .iter()
            .map(|location| location.item_offset.to_string())
            .collect();
        let item_sizes: Vec<_> = locations
            .iter()
            .map(|location| location.item_size.to_string())
            .collect();
        let data_offsets: Vec<_> = locations
            .iter()
            .map(|location| location.data_offset.to_string())
            .collect();
        let root_offsets: Vec<_> = locations
            .iter()
            .map(|location| location.root_offset.to_string())
            .collect();
        const INPUT: &str = "unnest($2::bytea[], $3::bytea[], $4::text[], $5::text[],
            $6::text[], $7::text[], $8::text[]) AS incoming(
            id, parent_id, parent_offset, item_offset, item_size, data_offset, root_offset)";
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &root_key,
            &ids,
            &parents,
            &parent_offsets,
            &item_offsets,
            &item_sizes,
            &data_offsets,
            &root_offsets,
        ];
        let inserted = transaction.query(&format!(
            "INSERT INTO public.item_locations
                (object_key, parent_key, root_key, parent_offset, item_offset, item_size, data_offset, root_offset)
             SELECT o.key, p.key, $1, incoming.parent_offset::public.uint128,
                incoming.item_offset::public.uint128, incoming.item_size::public.uint128,
                incoming.data_offset::public.uint128, incoming.root_offset::public.uint128
             FROM {INPUT}
             JOIN public.objects o ON o.id=incoming.id AND o.kind=1 AND o.metadata_complete
             JOIN public.objects p ON p.id=incoming.parent_id AND p.metadata_complete
             ORDER BY incoming.root_offset::numeric
             ON CONFLICT (root_key, root_offset) DO NOTHING RETURNING key"
        ), parameters).await?;
        ensure!(
            !was_complete || inserted.is_empty(),
            "completed bundle cannot acquire new occurrences"
        );
        let matched = transaction.query(&format!(
            "SELECT l.key FROM {INPUT}
             JOIN public.item_locations l ON l.root_key=$1 AND l.root_offset=incoming.root_offset::numeric
             JOIN public.objects o ON o.key=l.object_key
             JOIN public.objects p ON p.key=l.parent_key
             WHERE ROW(o.id, p.id, l.parent_offset, l.item_offset, l.item_size, l.data_offset)
                IS NOT DISTINCT FROM ROW(incoming.id, incoming.parent_id, incoming.parent_offset::numeric,
                    incoming.item_offset::numeric, incoming.item_size::numeric, incoming.data_offset::numeric)"
        ), parameters).await?;
        ensure!(
            matched.len() == locations.len(),
            "conflicting immutable bundle occurrence or missing parent"
        );
        let conflict = transaction.query_opt(
            "SELECT l.key FROM public.item_locations l
             LEFT JOIN public.item_locations p ON p.root_key=l.root_key AND p.root_offset=l.parent_offset
             WHERE l.root_key=$1 AND l.root_offset IN (SELECT unnest($2::text[])::numeric)
               AND l.parent_offset IS NOT NULL AND (
                   p.object_key IS DISTINCT FROM l.parent_key
                   OR l.root_offset <> p.root_offset + p.data_offset + l.item_offset
                   OR l.item_offset + l.item_size > p.item_size - p.data_offset
                   OR NOT EXISTS (
                       SELECT 1 FROM public.object_tags t
                       JOIN public.tag_names n ON n.key=t.name_key
                       JOIN public.tag_values v ON v.key=t.value_key
                       WHERE t.object_key=l.parent_key AND n.value='Bundle-Format'::bytea AND v.value='binary'::bytea)
                   OR NOT EXISTS (
                       SELECT 1 FROM public.object_tags t
                       JOIN public.tag_names n ON n.key=t.name_key
                       JOIN public.tag_values v ON v.key=t.value_key
                       WHERE t.object_key=l.parent_key AND n.value='Bundle-Version'::bytea AND v.value='2.0.0'::bytea))
             LIMIT 1",
            &[&root_key, &root_offsets],
        ).await?;
        ensure!(
            conflict.is_none(),
            "invalid nested bundle parent or offsets"
        );
        let conflict = transaction
            .query_opt(
                "SELECT l.key FROM public.item_locations l
             JOIN public.item_locations sibling ON sibling.root_key=l.root_key
               AND sibling.parent_offset IS NOT DISTINCT FROM l.parent_offset AND sibling.key<>l.key
               AND sibling.item_offset < l.item_offset + l.item_size
               AND l.item_offset < sibling.item_offset + sibling.item_size
             WHERE l.root_key=$1 AND l.root_offset IN (SELECT unnest($2::text[])::numeric) LIMIT 1",
                &[&root_key, &root_offsets],
            )
            .await?;
        ensure!(conflict.is_none(), "overlapping bundle siblings");
        let conflict = transaction.query_opt(
            "WITH RECURSIVE ancestors AS (
                SELECT root_offset AS target, parent_offset, 1 AS depth
                FROM public.item_locations
                WHERE root_key=$1 AND root_offset IN (SELECT unnest($2::text[])::numeric)
                UNION ALL
                SELECT a.target, p.parent_offset, a.depth+1
                FROM ancestors a JOIN public.item_locations p ON p.root_key=$1 AND p.root_offset=a.parent_offset
                WHERE a.depth < 32
             )
             SELECT target FROM ancestors GROUP BY target HAVING NOT bool_or(parent_offset IS NULL) LIMIT 1",
            &[&root_key, &root_offsets],
        ).await?;
        ensure!(
            conflict.is_none(),
            "bundle parent chain is missing or exceeds 32 levels"
        );
        Self::refresh_item_placements(&transaction, &keys).await?;
        if complete {
            transaction
                .execute(
                    "UPDATE public.bundle_progress SET complete=true WHERE root_key=$1",
                    &[&root_key],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    async fn refresh_item_placements(transaction: &Transaction<'_>, keys: &[i64]) -> Result<()> {
        transaction.execute(
            "INSERT INTO public.canonical_placements AS stored
                (object_key, block_height, position, location_key, kind, id)
             SELECT candidate.object_key, candidate.height, candidate.position, candidate.key, o.kind, o.id
             FROM (
                 SELECT DISTINCT ON (l.object_key) l.object_key, cb.height, bt.position, l.key
                 FROM public.item_locations l
                 JOIN public.block_transactions bt ON bt.object_key=l.root_key
                 JOIN public.canonical_blocks cb ON cb.block_hash=bt.block_hash
                 JOIN public.blocks b ON b.hash=cb.block_hash AND b.timestamp IS NOT NULL
                 JOIN public.block_index_state s
                   ON s.singleton AND cb.height > s.start_height AND cb.height <= s.imported_through
                 WHERE l.object_key=ANY($1::bigint[])
                 ORDER BY l.object_key, cb.height, bt.position, l.root_offset
             ) candidate JOIN public.objects o ON o.key=candidate.object_key
             ORDER BY o.id
             ON CONFLICT (object_key) DO UPDATE SET block_height=EXCLUDED.block_height,
                 position=EXCLUDED.position, location_key=EXCLUDED.location_key,
                 kind=EXCLUDED.kind, id=EXCLUDED.id
             WHERE ROW(EXCLUDED.block_height, EXCLUDED.position,
                       (SELECT root_offset FROM public.item_locations WHERE key=EXCLUDED.location_key))
                 < ROW(stored.block_height, stored.position,
                       (SELECT root_offset FROM public.item_locations WHERE key=stored.location_key))",
            &[&keys],
        ).await?;
        Ok(())
    }

    async fn lock_bundle_roots(transaction: &Transaction<'_>, ids: &[&[u8]]) -> Result<()> {
        // Serialize root membership changes with indexing, including roots with no progress row yet.
        transaction
            .query(
                "SELECT pg_advisory_xact_lock(hashtextextended(encode(id, 'hex'), 1))
             FROM (SELECT id FROM unnest($1::bytea[]) AS roots(id) ORDER BY id) ordered",
                &[&ids],
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn bundle_location(&self, id: &[u8]) -> Result<Option<IndexedBundle>> {
        ensure!(id.len() == 32, "bundle item ID must be 32 bytes");
        let installed: bool = self
            .client
            .query_one(
                "SELECT to_regclass('public.item_locations') IS NOT NULL",
                &[],
            )
            .await?
            .try_get(0)?;
        if !installed {
            return Ok(None);
        }
        // Read current membership, not just the cached placement, so stale hints fail closed.
        let rows = self.client.query(
            "WITH RECURSIVE selected AS (
                SELECT l.*, root.id AS root_id, root.data_size AS root_size, o.data_size AS target_size
                FROM public.objects o
                JOIN public.item_locations l ON l.object_key=o.key
                JOIN public.objects root ON root.key=l.root_key AND root.kind=0 AND root.metadata_complete
                JOIN public.block_transactions bt ON bt.object_key=l.root_key
                JOIN public.canonical_blocks cb ON cb.block_hash=bt.block_hash
                JOIN public.blocks b ON b.hash=cb.block_hash AND b.timestamp IS NOT NULL
                JOIN public.block_index_state s
                  ON s.singleton AND cb.height > s.start_height AND cb.height <= s.imported_through
                WHERE o.id=$1 AND o.kind=1 AND o.metadata_complete
                ORDER BY cb.height, bt.position, l.root_offset LIMIT 1
             ), path AS (
                SELECT selected.*, 1 AS depth FROM selected
                UNION ALL
                SELECT p.*, path.root_id, path.root_size, path.target_size, path.depth+1
                FROM path JOIN public.item_locations p
                  ON p.root_key=path.root_key AND p.root_offset=path.parent_offset
                WHERE path.depth < 32
             )
             SELECT o.id, parent.id, path.parent_offset::text, path.item_offset::text,
                path.item_size::text, path.data_offset::text, path.root_offset::text,
                path.root_id, path.root_size::text, path.target_size::text, o.content_type
             FROM path
             JOIN public.objects o ON o.key=path.object_key AND o.kind=1 AND o.metadata_complete
             JOIN public.objects parent ON parent.key=path.parent_key AND parent.metadata_complete
             ORDER BY path.depth DESC",
            &[&id],
        ).await?;
        let Some(first) = rows.first() else {
            return Ok(None);
        };
        let root_id: Vec<u8> = first.try_get(7)?;
        let root_size: u128 = first.try_get::<_, String>(8)?.parse()?;
        let data_size: u128 = first.try_get::<_, String>(9)?.parse()?;
        let content_type = rows
            .last()
            .context("missing stored bundle target")?
            .try_get(10)?;
        let mut locations: Vec<BundleLocation> = Vec::with_capacity(rows.len());
        for row in rows {
            let location = BundleLocation {
                id: row.try_get(0)?,
                parent_id: row.try_get(1)?,
                parent_offset: row
                    .try_get::<_, Option<String>>(2)?
                    .map(|offset| offset.parse())
                    .transpose()?,
                item_offset: row.try_get::<_, String>(3)?.parse()?,
                item_size: row.try_get::<_, String>(4)?.parse()?,
                data_offset: row.try_get::<_, String>(5)?.parse()?,
                root_offset: row.try_get::<_, String>(6)?.parse()?,
            };
            let (parent_id, parent_offset, payload_start, payload_size) = match locations.last() {
                Some(parent) => (
                    parent.id.as_slice(),
                    Some(parent.root_offset),
                    parent
                        .root_offset
                        .checked_add(parent.data_offset)
                        .context("bundle parent offset overflow")?,
                    parent.item_size - parent.data_offset,
                ),
                None => (root_id.as_slice(), None, 0, root_size),
            };
            ensure!(
                location.parent_id == parent_id
                    && location.parent_offset == parent_offset
                    && payload_start.checked_add(location.item_offset)
                        == Some(location.root_offset)
                    && location.item_offset >= 96
                    && location.data_offset > 0
                    && location.data_offset <= location.item_size
                    && location
                        .item_offset
                        .checked_add(location.item_size)
                        .is_some_and(|end| end <= payload_size),
                "invalid stored bundle parent chain or offsets"
            );
            locations.push(location);
        }
        let target = locations.last().context("missing stored bundle target")?;
        ensure!(
            target.id == id && target.item_size - target.data_offset == data_size,
            "invalid stored bundle target identity or size"
        );
        Ok(Some(IndexedBundle {
            root_id,
            data_size,
            content_type,
            locations,
        }))
    }

    pub(crate) async fn record_objects(&mut self, objects: &[ObjectMetadata]) -> Result<()> {
        let transaction = self
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        Self::write_objects(&transaction, objects).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn write_objects(
        transaction: &Transaction<'_>,
        objects: &[ObjectMetadata],
    ) -> Result<Vec<i64>> {
        ensure!(
            objects.len() <= METADATA_BATCH_SIZE,
            "metadata batch exceeds 256 objects"
        );
        if objects.is_empty() {
            return Ok(Vec::new());
        }
        let mut objects: Vec<_> = objects.iter().collect();
        objects.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        for pair in objects.windows(2) {
            ensure!(
                pair[0].id != pair[1].id || pair[0] == pair[1],
                "conflicting immutable object in metadata batch"
            );
        }
        objects.dedup_by(|a, b| a.id == b.id);
        let mut owners = std::collections::BTreeMap::new();
        for object in &objects {
            ensure!(object.id.len() == 32, "object ID must be 32 bytes");
            ensure!(matches!(object.kind, 0 | 1), "invalid object kind");
            i32::try_from(object.tags.len()).context("too many object tags")?;
            if let Some(previous) = owners.insert(
                object.owner_address.as_slice(),
                object.owner_public_key.as_slice(),
            ) {
                ensure!(
                    previous == object.owner_public_key.as_slice(),
                    "conflicting immutable owner in metadata batch"
                );
            }
        }
        let addresses: Vec<_> = owners.keys().copied().collect();
        let public_keys: Vec<_> = owners.values().copied().collect();
        transaction
            .execute(
                "INSERT INTO public.owners AS stored (address, public_key)
                 SELECT * FROM unnest($1::bytea[], $2::bytea[]) AS incoming(address, public_key)
                 ORDER BY address
                 ON CONFLICT (address) DO UPDATE SET public_key = EXCLUDED.public_key
                 WHERE stored.public_key IS NULL",
                &[&addresses, &public_keys],
            )
            .await?;
        let conflict = transaction
            .query_opt(
                "SELECT incoming.address
                 FROM unnest($1::bytea[], $2::bytea[]) AS incoming(address, public_key)
                 JOIN public.owners stored ON stored.address = incoming.address
                 WHERE stored.public_key IS DISTINCT FROM incoming.public_key LIMIT 1",
                &[&addresses, &public_keys],
            )
            .await?;
        ensure!(conflict.is_none(), "conflicting immutable owner public key");

        let ids: Vec<_> = objects.iter().map(|object| object.id.as_slice()).collect();
        let kinds: Vec<_> = objects.iter().map(|object| object.kind).collect();
        let signatures: Vec<_> = objects
            .iter()
            .map(|object| object.signature.as_slice())
            .collect();
        let anchors: Vec<_> = objects
            .iter()
            .map(|object| object.anchor.as_slice())
            .collect();
        let owner_addresses: Vec<_> = objects
            .iter()
            .map(|object| object.owner_address.as_slice())
            .collect();
        let targets: Vec<_> = objects
            .iter()
            .map(|object| object.target.as_slice())
            .collect();
        let data_sizes: Vec<_> = objects
            .iter()
            .map(|object| object.data_size.to_string())
            .collect();
        let content_types: Vec<_> = objects
            .iter()
            .map(|object| object.content_type.as_deref())
            .collect();
        let content_encodings: Vec<_> = objects
            .iter()
            .map(|object| object.content_encoding.as_deref())
            .collect();
        let signature_types: Vec<_> = objects.iter().map(|object| object.signature_type).collect();
        let formats: Vec<_> = objects.iter().map(|object| object.format).collect();
        let quantities: Vec<_> = objects
            .iter()
            .map(|object| object.quantity.as_deref())
            .collect();
        let rewards: Vec<_> = objects
            .iter()
            .map(|object| object.reward.as_deref())
            .collect();
        let denominations: Vec<_> = objects
            .iter()
            .map(|object| object.denomination.map(i64::from))
            .collect();
        let data_roots: Vec<_> = objects
            .iter()
            .map(|object| object.data_root.as_deref())
            .collect();
        let parameters: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &ids,
            &kinds,
            &signatures,
            &anchors,
            &owner_addresses,
            &targets,
            &data_sizes,
            &content_types,
            &content_encodings,
            &signature_types,
            &formats,
            &quantities,
            &rewards,
            &denominations,
            &data_roots,
        ];
        const INPUT: &str = "unnest(
            $1::bytea[], $2::smallint[], $3::bytea[], $4::bytea[], $5::bytea[], $6::bytea[],
            $7::text[], $8::text[], $9::text[], $10::smallint[], $11::smallint[],
            $12::text[], $13::text[], $14::bigint[], $15::bytea[]
        ) WITH ORDINALITY AS incoming(
            id, kind, signature, anchor, owner_address, target, data_size,
            content_type, content_encoding, signature_type, format, quantity,
            reward, denomination, data_root, ordinality
        )";
        let completed = transaction
            .query(
                &format!(
                    "INSERT INTO public.objects AS stored
                        (id, kind, signature, anchor, owner_address, target, data_size,
                         content_type, content_encoding, signature_type, format, quantity,
                         reward, denomination, data_root, metadata_complete, indexed_at)
                     SELECT id, kind, signature, anchor, owner_address, target, data_size::public.uint128,
                            content_type, content_encoding, signature_type, format, quantity::numeric,
                            reward::numeric, denomination, data_root, true,
                            extract(epoch FROM statement_timestamp())::bigint
                     FROM {INPUT} ORDER BY id
                     ON CONFLICT (id) DO UPDATE
                     SET signature = EXCLUDED.signature, anchor = EXCLUDED.anchor,
                         owner_address = EXCLUDED.owner_address, target = EXCLUDED.target,
                         data_size = EXCLUDED.data_size, content_type = EXCLUDED.content_type,
                         content_encoding = EXCLUDED.content_encoding, signature_type = EXCLUDED.signature_type,
                         format = EXCLUDED.format, quantity = EXCLUDED.quantity, reward = EXCLUDED.reward,
                         denomination = EXCLUDED.denomination, data_root = EXCLUDED.data_root,
                         metadata_complete = true, indexed_at = EXCLUDED.indexed_at
                     WHERE NOT stored.metadata_complete AND stored.kind = EXCLUDED.kind
                     RETURNING key"
                ),
                parameters,
            )
            .await?;
        let completed: Vec<i64> = completed
            .iter()
            .map(|row| row.try_get(0))
            .collect::<std::result::Result<_, _>>()?;
        let matched = transaction
            .query(
                &format!(
                    "SELECT stored.key FROM {INPUT}
                     JOIN public.objects stored ON stored.id = incoming.id
                     WHERE stored.metadata_complete AND
                         ROW(stored.kind, stored.signature, stored.anchor, stored.owner_address,
                             stored.target, stored.data_size, stored.content_type, stored.content_encoding,
                             stored.signature_type, stored.format, stored.quantity, stored.reward,
                             stored.denomination, stored.data_root)
                         IS NOT DISTINCT FROM
                         ROW(incoming.kind, incoming.signature, incoming.anchor, incoming.owner_address,
                             incoming.target, incoming.data_size::numeric, incoming.content_type,
                             incoming.content_encoding, incoming.signature_type, incoming.format,
                             incoming.quantity::numeric, incoming.reward::numeric,
                             incoming.denomination, incoming.data_root)
                     ORDER BY incoming.ordinality"
                ),
                parameters,
            )
            .await?;
        ensure!(
            matched.len() == objects.len(),
            "conflicting immutable object metadata"
        );
        let keys: Vec<i64> = matched
            .iter()
            .map(|row| row.try_get(0))
            .collect::<std::result::Result<_, _>>()?;

        let dictionaries = [("tag_names", false), ("tag_values", true)].map(|(table, values)| {
            let bytes: std::collections::BTreeSet<_> = objects
                .iter()
                .flat_map(|object| {
                    object.tags.iter().map(|(name, value)| {
                        if values {
                            value.as_slice()
                        } else {
                            name.as_slice()
                        }
                    })
                })
                .collect();
            let entries: Vec<_> = bytes
                .into_iter()
                .map(|value| {
                    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(value).into();
                    (value, digest)
                })
                .collect();
            (table, entries)
        });
        let mut lock_keys = Vec::new();
        for (_, entries) in &dictionaries {
            for entries in entries.chunks(ROW_BATCH_SIZE) {
                let digests: Vec<_> = entries
                    .iter()
                    .map(|(_, digest)| digest.as_slice())
                    .collect();
                for row in transaction
                    .query(
                        "SELECT DISTINCT hashtextextended(encode(digest, 'hex'), 0)
                         FROM unnest($1::bytea[]) AS incoming(digest)",
                        &[&digests],
                    )
                    .await?
                {
                    lock_keys.push(row.try_get::<_, i64>(0)?);
                }
            }
        }
        lock_keys.sort_unstable();
        lock_keys.dedup();
        // Acquire the complete cross-dictionary lock set before any dictionary INSERT.
        // A new read-committed statement then sees entries committed while locks were awaited.
        for locks in lock_keys.chunks(ROW_BATCH_SIZE) {
            transaction
                .query(
                    "SELECT pg_advisory_xact_lock(lock_key)
                     FROM (SELECT lock_key FROM unnest($1::bigint[]) AS locks(lock_key)
                           ORDER BY lock_key) ordered",
                    &[&locks],
                )
                .await?;
        }
        let mut dictionary_keys = [
            std::collections::BTreeMap::new(),
            std::collections::BTreeMap::new(),
        ];
        for ((table, entries), keys) in dictionaries.iter().zip(&mut dictionary_keys) {
            let insert = format!(
                "INSERT INTO public.{table} (digest, value)
                 SELECT digest, value
                 FROM unnest($1::bytea[], $2::bytea[]) AS incoming(digest, value)
                 WHERE NOT EXISTS (
                     SELECT 1 FROM public.{table} stored
                     WHERE stored.digest = incoming.digest AND stored.value = incoming.value
                 )"
            );
            let lookup = format!(
                "SELECT stored.key, incoming.ordinality
                 FROM unnest($1::bytea[], $2::bytea[]) WITH ORDINALITY AS incoming(digest, value, ordinality)
                 JOIN public.{table} stored
                   ON stored.digest = incoming.digest AND stored.value = incoming.value"
            );
            for entries in entries.chunks(ROW_BATCH_SIZE) {
                let digests: Vec<_> = entries
                    .iter()
                    .map(|(_, digest)| digest.as_slice())
                    .collect();
                let values: Vec<_> = entries.iter().map(|(value, _)| *value).collect();
                transaction.execute(&insert, &[&digests, &values]).await?;
                let rows = transaction.query(&lookup, &[&digests, &values]).await?;
                ensure!(
                    rows.len() == entries.len(),
                    "tag dictionary lookup is incomplete"
                );
                for row in rows {
                    let index = usize::try_from(row.try_get::<_, i64>(1)? - 1)?;
                    let (value, _) = entries
                        .get(index)
                        .context("invalid tag dictionary ordinal")?;
                    keys.insert(*value, row.try_get::<_, i64>(0)?);
                }
            }
        }
        let mut tags = objects.iter().zip(&keys).flat_map(|(object, key)| {
            object
                .tags
                .iter()
                .enumerate()
                .map(move |(ordinal, (name, value))| {
                    (*key, ordinal as i32, name.as_slice(), value.as_slice())
                })
        });
        loop {
            let batch: Vec<_> = tags.by_ref().take(ROW_BATCH_SIZE).collect();
            if batch.is_empty() {
                break;
            }
            let object_keys: Vec<_> = batch.iter().map(|tag| tag.0).collect();
            let ordinals: Vec<_> = batch.iter().map(|tag| tag.1).collect();
            let names: Vec<_> = batch
                .iter()
                .map(|tag| {
                    dictionary_keys[0]
                        .get(tag.2)
                        .copied()
                        .context("missing tag name")
                })
                .collect::<Result<_>>()?;
            let values: Vec<_> = batch
                .iter()
                .map(|tag| {
                    dictionary_keys[1]
                        .get(tag.3)
                        .copied()
                        .context("missing tag value")
                })
                .collect::<Result<_>>()?;
            transaction
                .execute(
                    "INSERT INTO public.object_tags (object_key, ordinal, name_key, value_key)
                     SELECT * FROM unnest($1::bigint[], $2::integer[], $3::bigint[], $4::bigint[])
                       AS incoming(object_key, ordinal, name_key, value_key)
                     WHERE object_key = ANY($5::bigint[])
                     ON CONFLICT (object_key, ordinal) DO NOTHING",
                    &[&object_keys, &ordinals, &names, &values, &completed],
                )
                .await?;
            let conflict = transaction
                .query_opt(
                    "SELECT incoming.object_key
                     FROM unnest($1::bigint[], $2::integer[], $3::bigint[], $4::bigint[])
                       AS incoming(object_key, ordinal, name_key, value_key)
                     LEFT JOIN public.object_tags stored
                       ON stored.object_key = incoming.object_key AND stored.ordinal = incoming.ordinal
                     WHERE ROW(stored.name_key, stored.value_key)
                         IS DISTINCT FROM ROW(incoming.name_key, incoming.value_key)
                     LIMIT 1",
                    &[&object_keys, &ordinals, &names, &values],
                )
                .await?;
            ensure!(conflict.is_none(), "conflicting immutable ordered tags");
        }
        let tag_counts: Vec<_> = objects
            .iter()
            .map(|object| object.tags.len() as i64)
            .collect();
        let conflict = transaction
            .query_opt(
                "SELECT incoming.object_key
                 FROM unnest($1::bigint[], $2::bigint[]) AS incoming(object_key, tag_count)
                 WHERE incoming.tag_count <> (
                     SELECT count(*) FROM public.object_tags tags WHERE tags.object_key = incoming.object_key
                 ) LIMIT 1",
                &[&keys, &tag_counts],
            )
            .await?;
        ensure!(conflict.is_none(), "conflicting immutable tag count");
        Ok(keys)
    }

    pub(crate) async fn analyze_metadata(&self) -> Result<()> {
        self.client
            .batch_execute(
                "ANALYZE public.objects;
                 ANALYZE public.object_tags;
                 ANALYZE public.canonical_placements;",
            )
            .await?;
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
    #[ignore = "requires migration 004 and imported blocks in ar_io_rust_test"]
    async fn content_cache_rejects_stale_anchors_and_conflicting_descriptors() -> Result<()> {
        use sha2::Digest;

        let store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
        let database: String = store
            .client
            .query_one("SELECT current_database()", &[])
            .await?
            .try_get(0)?;
        ensure!(
            database == "ar_io_rust_test",
            "requires the dedicated test database"
        );
        store.require_content_cache().await?;
        store.client.batch_execute("BEGIN").await?;
        let result = async {
            let row = store
                .client
                .query_one(
                    "SELECT c.height, c.block_hash FROM public.canonical_blocks c
                     JOIN public.block_index_state s
                       ON s.singleton AND c.height > s.start_height
                       AND c.height <= s.imported_through
                     ORDER BY c.height LIMIT 1 FOR UPDATE OF s",
                    &[],
                )
                .await?;
            let height = u64::try_from(row.try_get::<_, i64>(0)?)?;
            let hash: Vec<u8> = row.try_get(1)?;
            let id: [u8; 32] =
                sha2::Sha256::digest([b"content-cache-regression".as_slice(), &hash].concat())
                    .into();
            ensure!(
                store.cached_content(&id).await?.is_none(),
                "cache regression fixture already exists"
            );
            let metadata = r#"{"verified":"original"}"#;
            let mut wrong_hash = hash.clone();
            wrong_hash[0] ^= 1;
            ensure!(
                !store
                    .cache_content(&id, height, &wrong_hash, metadata)
                    .await?,
                "mismatched block anchor was admitted"
            );
            ensure!(store.cached_content(&id).await?.is_none());
            ensure!(store.cache_content(&id, height, &hash, metadata).await?);
            ensure!(store.cache_content(&id, height, &hash, metadata).await?);
            ensure!(
                store
                    .cache_content(&id, height, &hash, r#"{"verified":"conflict"}"#)
                    .await
                    .is_err(),
                "conflicting immutable descriptor was accepted"
            );
            ensure!(store.cached_content(&id).await?.as_deref() == Some(metadata));
            store
                .client
                .execute(
                    "UPDATE public.block_index_state SET start_height = $1 WHERE singleton",
                    &[&sql_height(height)?],
                )
                .await?;
            ensure!(
                store.cached_content(&id).await?.is_none(),
                "cache hit survived loss of imported coverage"
            );
            ensure!(
                !store.cache_content(&id, height, &hash, metadata).await?,
                "uncovered block anchor was admitted"
            );
            Ok(())
        }
        .await;
        store.client.batch_execute("ROLLBACK").await?;
        result
    }

    #[tokio::test]
    #[ignore = "requires indexed bundles in ar_io_rust_test"]
    async fn bundle_replay_and_conflicts_are_atomic() -> Result<()> {
        use sha2::Digest;
        let mut store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
        let database: String = store
            .client
            .query_one("SELECT current_database()", &[])
            .await?
            .try_get(0)?;
        ensure!(
            database == "ar_io_rust_test",
            "requires the dedicated test database"
        );
        let row = store
            .client
            .query_one(
                "SELECT o.id, o.signature, o.anchor, o.owner_address, w.public_key, o.target,
                o.data_size::text, o.content_type, o.content_encoding, o.signature_type, o.key,
                root.id, l.root_key, l.item_offset::text, l.item_size::text, l.data_offset::text
             FROM public.item_locations l
             JOIN public.objects o ON o.key=l.object_key AND o.metadata_complete
             JOIN public.owners w ON w.address=o.owner_address
             JOIN public.objects root ON root.key=l.root_key
             JOIN public.bundle_progress progress ON progress.root_key=l.root_key
             JOIN public.canonical_placements p ON p.object_key=root.key
             WHERE l.parent_offset IS NULL AND o.data_size>0 AND l.data_offset>1
             ORDER BY l.key LIMIT 1",
                &[],
            )
            .await?;
        let key: i64 = row.try_get(10)?;
        let tags = store
            .client
            .query(
                "SELECT n.value, v.value FROM public.object_tags t
             JOIN public.tag_names n ON n.key=t.name_key
             JOIN public.tag_values v ON v.key=t.value_key
             WHERE t.object_key=$1 ORDER BY t.ordinal",
                &[&key],
            )
            .await?
            .iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut object = ObjectMetadata {
            id: row.try_get(0)?,
            kind: 1,
            signature: row.try_get(1)?,
            anchor: row.try_get(2)?,
            owner_address: row.try_get(3)?,
            owner_public_key: row.try_get(4)?,
            target: row.try_get(5)?,
            data_size: row.try_get::<_, String>(6)?.parse()?,
            content_type: row.try_get(7)?,
            content_encoding: row.try_get(8)?,
            signature_type: row.try_get(9)?,
            format: None,
            quantity: None,
            reward: None,
            denomination: None,
            data_root: None,
            tags,
        };
        let root_id: Vec<u8> = row.try_get(11)?;
        let root_key: i64 = row.try_get(12)?;
        let item_offset = row.try_get::<_, String>(13)?.parse()?;
        let mut location = BundleLocation {
            id: object.id.clone(),
            parent_id: root_id.clone(),
            parent_offset: None,
            item_offset,
            item_size: row.try_get::<_, String>(14)?.parse()?,
            data_offset: row.try_get::<_, String>(15)?.parse()?,
            root_offset: item_offset,
        };
        let snapshot = "SELECT ARRAY[
            (SELECT count(*) FROM public.objects), (SELECT count(*) FROM public.owners),
            (SELECT count(*) FROM public.object_tags), (SELECT count(*) FROM public.tag_names),
            (SELECT count(*) FROM public.tag_values), (SELECT count(*) FROM public.item_locations),
            (SELECT count(*) FROM public.canonical_placements), (SELECT count(*) FROM public.bundle_progress)],
            (SELECT complete FROM public.bundle_progress WHERE root_key=$1)";
        let before = store.client.query_one(snapshot, &[&root_key]).await?;
        store
            .commit_bundle_batch(
                &root_id,
                std::slice::from_ref(&object),
                std::slice::from_ref(&location),
                false,
            )
            .await?;
        object.id = sha2::Sha256::digest([b"bundle-rollback-item".as_slice(), &object.id].concat())
            .to_vec();
        object.owner_address =
            sha2::Sha256::digest([b"bundle-rollback-owner".as_slice(), &object.id].concat())
                .to_vec();
        object.tags.push((
            [b"bundle-rollback-tag".as_slice(), &object.id].concat(),
            vec![0; 4096],
        ));
        location.id = object.id.clone();
        let mut new_occurrence = location.clone();
        new_occurrence.item_offset += 1;
        new_occurrence.root_offset += 1;
        new_occurrence.item_size -= 1;
        new_occurrence.data_offset -= 1;
        ensure!(
            store
                .commit_bundle_batch(&root_id, &[object], &[location, new_occurrence], true)
                .await
                .is_err(),
            "conflicting occurrence or completed bundle extension was accepted"
        );
        let after = store.client.query_one(snapshot, &[&root_key]).await?;
        ensure!(
            before.try_get::<_, Vec<i64>>(0)? == after.try_get::<_, Vec<i64>>(0)?
                && before.try_get::<_, bool>(1)? == after.try_get::<_, bool>(1)?,
            "failed bundle batch changed facts, tags, occurrences, placements, or progress"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires indexed transaction metadata in ar_io_rust_test"]
    async fn metadata_conflicts_roll_back_facts_and_ordered_tags() -> Result<()> {
        let mut store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
        let database: String = store
            .client
            .query_one("SELECT current_database()", &[])
            .await?
            .get(0);
        ensure!(
            database == "ar_io_rust_test",
            "requires the dedicated test database"
        );
        let row = store
            .client
            .query_one(
                "SELECT o.id, o.kind, o.signature, o.anchor, o.owner_address, w.public_key,
                    o.target, o.data_size::text, o.content_type, o.content_encoding,
                    o.signature_type, o.format, o.quantity::text, o.reward::text,
                    o.denomination, o.data_root, o.key
             FROM public.objects o JOIN public.owners w ON w.address=o.owner_address
             WHERE o.metadata_complete AND o.kind=0 ORDER BY o.key LIMIT 1",
                &[],
            )
            .await?;
        let key: i64 = row.try_get(16)?;
        let tags = store
            .client
            .query(
                "SELECT n.value, v.value FROM public.object_tags t
             JOIN public.tag_names n ON n.key=t.name_key
             JOIN public.tag_values v ON v.key=t.value_key
             WHERE t.object_key=$1 ORDER BY t.ordinal",
                &[&key],
            )
            .await?
            .iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut object = ObjectMetadata {
            id: row.try_get(0)?,
            kind: row.try_get(1)?,
            signature: row.try_get(2)?,
            anchor: row.try_get(3)?,
            owner_address: row.try_get(4)?,
            owner_public_key: row.try_get(5)?,
            target: row.try_get(6)?,
            data_size: row.try_get::<_, String>(7)?.parse()?,
            content_type: row.try_get(8)?,
            content_encoding: row.try_get(9)?,
            signature_type: row.try_get(10)?,
            format: row.try_get(11)?,
            quantity: row.try_get(12)?,
            reward: row.try_get(13)?,
            denomination: row
                .try_get::<_, Option<i64>>(14)?
                .map(u32::try_from)
                .transpose()?,
            data_root: row.try_get(15)?,
            tags,
        };
        let counts = "SELECT ARRAY[
            (SELECT count(*) FROM public.objects), (SELECT count(*) FROM public.owners),
            (SELECT count(*) FROM public.object_tags), (SELECT count(*) FROM public.tag_names),
            (SELECT count(*) FROM public.tag_values)]";
        let before: Vec<i64> = store.client.query_one(counts, &[]).await?.get(0);
        store.record_objects(std::slice::from_ref(&object)).await?;
        let original_size = object.data_size;
        object.data_size = original_size
            .checked_add(1)
            .context("fixture size overflow")?;
        ensure!(
            store
                .record_objects(std::slice::from_ref(&object))
                .await
                .is_err(),
            "conflicting immutable size was accepted"
        );
        object.data_size = original_size;
        object
            .tags
            .push((b"rollback-check".to_vec(), vec![0; 4096]));
        ensure!(
            store
                .record_objects(std::slice::from_ref(&object))
                .await
                .is_err(),
            "conflicting ordered tags were accepted"
        );
        object.tags.pop();
        store.record_objects(std::slice::from_ref(&object)).await?;
        let after: Vec<i64> = store.client.query_one(counts, &[]).await?.get(0);
        ensure!(before == after, "failed metadata write left rows behind");
        Ok(())
    }

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
