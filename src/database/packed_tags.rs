use super::*;

pub(super) const PREPARE: &str = include_str!("../../migrations/023_packed_tags_prepare.sql");

impl BlockStore {
    pub async fn prepare_packed_tags(&mut self) -> Result<()> {
        let batch_size = std::env::var("AR_IO_PACKED_TAG_BATCH_SIZE")
            .ok()
            .map(|value| value.parse::<i64>())
            .transpose()
            .context("invalid AR_IO_PACKED_TAG_BATCH_SIZE")?
            .unwrap_or(256);
        ensure!(
            (1..=16_384).contains(&batch_size),
            "AR_IO_PACKED_TAG_BATCH_SIZE must be between 1 and 16384"
        );
        self.migrate_schema(false).await?;
        self.client
            .batch_execute(
                "SET application_name='ar-io-packed-tags-prepare'; SET statement_timeout=0;
             SET transaction_timeout=0; SET lock_timeout='1s'; SET work_mem='16MB';
             SET max_parallel_workers_per_gather=0",
            )
            .await?;
        let bitmap_reads = std::env::var("AR_IO_PACKED_TAG_BITMAP_READS")
            .ok()
            .map(|value| value.parse::<bool>())
            .transpose()
            .context("invalid AR_IO_PACKED_TAG_BITMAP_READS")?
            .unwrap_or(false);
        let scans = if bitmap_reads {
            let settings = self
                .client
                .query_one(
                    "SELECT current_setting('enable_indexscan'),current_setting('enable_bitmapscan')",
                    &[],
                )
                .await?;
            Some((settings.get::<_, String>(0), settings.get::<_, String>(1)))
        } else {
            None
        };
        let locked: bool = self
            .client
            .query_one(
                "SELECT pg_try_advisory_lock(hashtextextended('ar-io-gateway:packed-tags',0))",
                &[],
            )
            .await?
            .get(0);
        ensure!(locked, "packed-tag preparation is already running");
        let transaction = self.client.transaction().await?;
        transaction.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended('ar-io-gateway:block-index:migrate',0))", &[]
        ).await?;
        let version: Option<i32> = transaction
            .query_one(
                "SELECT max(version) FROM public.ar_io_schema_migrations",
                &[],
            )
            .await?
            .get(0);
        ensure!(
            matches!(version, Some(21..=27)),
            "packed tags require schema 21 through 27"
        );
        if matches!(version, Some(23..=27)) {
            transaction.commit().await?;
            self.client
                .query_one(
                    "SELECT pg_advisory_unlock(hashtextextended('ar-io-gateway:packed-tags',0))",
                    &[],
                )
                .await?;
            eprintln!("Packed tags are already active");
            return Ok(());
        }
        let staged: bool = transaction
            .query_one(
                "SELECT to_regclass('public.packed_tag_preparation') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        if !staged {
            transaction.batch_execute(PREPARE).await?;
        }
        transaction.commit().await?;
        let mut reported = tokio::time::Instant::now();
        let mut reported_batches = 0_u64;
        let mut reported_objects = 0_usize;
        let mut reported_parent_time = Duration::ZERO;
        loop {
            let transaction = self.client.transaction().await?;
            let state = transaction.query_one(
                "SELECT after_key,high_key FROM public.packed_tag_preparation WHERE singleton FOR UPDATE", &[]
            ).await?;
            let after: i64 = state.get(0);
            let high: i64 = state.get(1);
            if after == high {
                transaction.commit().await?;
                break;
            }
            let keys: Vec<i64> = transaction
                .query(
                    "SELECT DISTINCT object_key FROM public.object_tags
                 WHERE object_key>$1 AND object_key<=$2 ORDER BY object_key LIMIT $3",
                    &[&after, &high, &batch_size],
                )
                .await?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            let parent_started = tokio::time::Instant::now();
            if bitmap_reads {
                transaction
                    .batch_execute("SET LOCAL enable_indexscan=off; SET LOCAL enable_bitmapscan=on")
                    .await?;
            }
            transaction
                .query(
                    "SELECT key FROM public.objects WHERE key=ANY($1) ORDER BY id FOR UPDATE",
                    &[&keys],
                )
                .await?;
            if let Some((indexscan, bitmapscan)) = &scans {
                transaction
                    .query_one(
                        "SELECT set_config('enable_indexscan',$1,true),set_config('enable_bitmapscan',$2,true)",
                        &[indexscan, bitmapscan],
                    )
                    .await?;
            }
            let parent_time = parent_started.elapsed();
            let gap = transaction.query_opt(
                "SELECT object_key FROM public.object_tags WHERE object_key=ANY($1)
                 GROUP BY object_key HAVING min(ordinal)<>0 OR max(ordinal)::bigint<>count(*)-1 LIMIT 1",
                &[&keys]
            ).await?;
            ensure!(gap.is_none(), "noncontiguous ordered tags");
            transaction.execute(
                "INSERT INTO public.packed_object_tags AS stored(object_key,refs)
                 SELECT object_key,string_agg(int8send(name_key)||int8send(value_key),''::bytea ORDER BY ordinal)
                 FROM public.object_tags WHERE object_key=ANY($1) GROUP BY object_key
                 ON CONFLICT(object_key) DO UPDATE SET refs=EXCLUDED.refs
                 WHERE stored.refs IS DISTINCT FROM EXCLUDED.refs", &[&keys]
            ).await?;
            let next = keys.last().copied().unwrap_or(high);
            transaction
                .execute(
                    "UPDATE public.packed_tag_preparation SET after_key=$1 WHERE singleton",
                    &[&next],
                )
                .await?;
            transaction.commit().await?;
            reported_batches += 1;
            reported_objects += keys.len();
            reported_parent_time += parent_time;
            if reported.elapsed() >= Duration::from_secs(5) || next == high {
                eprintln!(
                    "Packed-tag backfill: key {next}/{high}, bitmap={bitmap_reads}, batch_size={batch_size}, batches={reported_batches}, objects={reported_objects}, elapsed_ms={}, parent_ms={}",
                    reported.elapsed().as_millis(),
                    reported_parent_time.as_millis()
                );
                reported_batches = 0;
                reported_objects = 0;
                reported_parent_time = Duration::ZERO;
                reported = tokio::time::Instant::now();
            }
        }
        self.client
            .batch_execute("ANALYZE public.packed_object_tags")
            .await?;
        self.client
            .query_one(
                "SELECT pg_advisory_unlock(hashtextextended('ar-io-gateway:packed-tags',0))",
                &[],
            )
            .await?;
        eprintln!(
            "Packed tags are prepared; the current tag table remains active until schema cutover"
        );
        Ok(())
    }
}

pub(super) fn pack_refs(
    object: &ObjectMetadata,
    dictionaries: &[std::collections::BTreeMap<&[u8], i64>; 2],
) -> Result<Vec<u8>> {
    let mut refs = Vec::with_capacity(
        object
            .tags
            .len()
            .checked_mul(16)
            .context("tag references too large")?,
    );
    for (name, value) in &object.tags {
        let name = dictionaries[0]
            .get(name.as_slice())
            .context("missing tag name")?;
        let value = dictionaries[1]
            .get(value.as_slice())
            .context("missing tag value")?;
        refs.extend_from_slice(&name.to_be_bytes());
        refs.extend_from_slice(&value.to_be_bytes());
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires schema 23 in ar_io_rust_test; run serially"]
    async fn packed_tags_preserve_order_and_reject_conflicts_and_dangling_keys() -> Result<()> {
        let mut store = BlockStore::connect(&std::env::var("DATABASE_URL")?).await?;
        ensure!(
            store
                .client
                .query_one("SELECT current_database()", &[])
                .await?
                .get::<_, String>(0)
                == "ar_io_rust_test",
            "wrong database"
        );
        let id =
            crate::decode_fixed::<32>("z8dH98cY5MvVjBWm7DC6-NjuJOFMZxZeQjh_7hUuK54", "parent ID")?;
        let item = crate::verify_data_item(
            include_bytes!("../../tests/fixtures/ao-unsigned-parent.bin")
                .to_vec()
                .into(),
            &id,
        )
        .await?;
        let mut object = item.metadata(&crate::sha256(&[b"packed-tag-regression"]));
        object.tags = vec![
            (b"Bundle-Format".to_vec(), b"binary".to_vec()),
            (b"bundle-version".to_vec(), b"2.0.0".to_vec()),
            (b"X".to_vec(), vec![0, 255]),
            (b"X".to_vec(), vec![0, 255]),
            (Vec::new(), Vec::new()),
            (b"X".to_vec(), Vec::new()),
        ];
        let transaction = store
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        let keys = BlockStore::write_objects(&transaction, std::slice::from_ref(&object)).await?;
        let key = keys[0];
        let rows = transaction.query(
            "SELECT n.value,v.value FROM public.read_object_tags($1) t
             JOIN public.tag_names n ON n.key=t.name_key JOIN public.tag_values v ON v.key=t.value_key
             ORDER BY t.ordinal", &[&key]
        ).await?;
        let actual: Vec<(Vec<u8>, Vec<u8>)> = rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        ensure!(actual == object.tags, "ordered raw tags differ");
        ensure!(
            transaction
                .query_one("SELECT is_bundle FROM public.objects WHERE key=$1", &[&key])
                .await?
                .get::<_, bool>(0),
            "packed bundle classification was lost"
        );
        ensure!(
            BlockStore::write_objects(&transaction, std::slice::from_ref(&object)).await? == keys,
            "replay replaced the object identity"
        );
        let mut conflict = object.clone();
        conflict.tags.swap(0, 2);
        ensure!(
            BlockStore::write_objects(&transaction, &[conflict])
                .await
                .is_err(),
            "ordered tag conflict accepted"
        );
        let mut shortened = object.clone();
        shortened.tags.pop();
        ensure!(
            BlockStore::write_objects(&transaction, &[shortened])
                .await
                .is_err(),
            "tag-count conflict accepted"
        );
        let mut empty = object.clone();
        empty.id = crate::sha256(&[b"empty-packed-tag-regression"]).to_vec();
        empty.tags.clear();
        let empty_key = BlockStore::write_objects(&transaction, &[empty]).await?[0];
        ensure!(
            !transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM public.object_tags WHERE object_key=$1)",
                    &[&empty_key]
                )
                .await?
                .get::<_, bool>(0),
            "empty tags created a stored blob"
        );
        for (sql, code) in [
            (
                "UPDATE public.object_tags SET refs='\\x01'::bytea WHERE object_key=$1",
                "23514",
            ),
            (
                "UPDATE public.object_tags SET refs=int8send(-1::bigint)||int8send(-1::bigint) WHERE object_key=$1",
                "23503",
            ),
            (
                "DELETE FROM public.tag_names WHERE key=(SELECT name_key FROM public.read_object_tags($1) LIMIT 1)",
                "23503",
            ),
            (
                "DELETE FROM public.tag_values WHERE key=(SELECT value_key FROM public.read_object_tags($1) LIMIT 1)",
                "23503",
            ),
        ] {
            transaction.batch_execute("SAVEPOINT invalid_refs").await?;
            let error = transaction
                .execute(sql, &[&key])
                .await
                .expect_err("invalid dictionary reference accepted");
            ensure!(
                error.as_db_error().map(|e| e.code().code()) == Some(code),
                "wrong rejection: {error}"
            );
            transaction
                .batch_execute("ROLLBACK TO SAVEPOINT invalid_refs")
                .await?;
        }
        transaction.batch_execute("SAVEPOINT truncate_refs").await?;
        let error = transaction
            .batch_execute("TRUNCATE public.tag_names")
            .await
            .expect_err("referenced dictionary truncated");
        ensure!(
            error.as_db_error().map(|e| e.code().code()) == Some("23503"),
            "wrong truncate rejection: {error}"
        );
        transaction
            .batch_execute("ROLLBACK TO SAVEPOINT truncate_refs")
            .await?;
        let boundary=transaction.query_one(
            "SELECT name_key,value_key FROM public.decode_tag_refs(int8send($1::bigint)||int8send($2::bigint))",
            &[&i64::MAX,&(i64::MAX-1)]
        ).await?;
        ensure!(
            boundary.get::<_, i64>(0) == i64::MAX && boundary.get::<_, i64>(1) == i64::MAX - 1,
            "large dictionary keys were truncated"
        );
        transaction.rollback().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires ar_io_rust_test; run serially; briefly locks object_tags"]
    async fn batch_transactions_hold_no_dictionary_locks() -> Result<()> {
        let url = std::env::var("DATABASE_URL")?;
        let mut holder = BlockStore::connect(&url).await?;
        ensure!(
            holder
                .client
                .query_one("SELECT current_database()", &[])
                .await?
                .get::<_, String>(0)
                == "ar_io_rust_test",
            "wrong database"
        );
        let id =
            crate::decode_fixed::<32>("z8dH98cY5MvVjBWm7DC6-NjuJOFMZxZeQjh_7hUuK54", "parent ID")?;
        let item = crate::verify_data_item(
            include_bytes!("../../tests/fixtures/ao-unsigned-parent.bin")
                .to_vec()
                .into(),
            &id,
        )
        .await?;
        let mut object = item.metadata(&crate::sha256(&[b"interned-tag-regression"]));
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let value = format!("interned-tag-{}", nanos.as_nanos()).into_bytes();
        object.tags = vec![(b"timestamp".to_vec(), value.clone())];

        let mut writer = BlockStore::connect(&url).await?;
        let pid: i32 = writer
            .client
            .query_one("SELECT pg_backend_pid()", &[])
            .await?
            .get(0);
        let lock = holder.client.transaction().await?;
        lock.batch_execute(
            "SET LOCAL lock_timeout='5s'; LOCK TABLE public.object_tags IN SHARE MODE",
        )
        .await?;
        let batch_object = object.clone();
        let batch = tokio::spawn(async move {
            writer
                .record_objects(std::slice::from_ref(&batch_object))
                .await
        });
        let observer = BlockStore::connect(&url).await?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let blocked: bool = observer
                .client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1
                     AND wait_event_type='Lock' AND query LIKE 'INSERT INTO public.object_tags%')",
                    &[&pid],
                )
                .await?
                .get(0);
            if blocked {
                break;
            }
            ensure!(
                !batch.is_finished(),
                "batch finished before reaching tag writes"
            );
            ensure!(
                std::time::Instant::now() < deadline,
                "batch never reached tag writes"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let held: i64 = observer
            .client
            .query_one(
                "SELECT count(*) FROM pg_locks l,
                     (SELECT hashtextextended(encode(sha256($2::bytea),'hex'),0) AS k) d
                 WHERE l.pid=$1 AND l.locktype='advisory' AND l.granted AND l.objsubid=1
                   AND l.classid::bigint=((d.k>>32)&4294967295) AND l.objid::bigint=(d.k&4294967295)",
                &[&pid, &value],
            )
            .await?
            .get(0);
        batch.abort();
        let _ = batch.await;
        lock.rollback().await?;
        let removed = observer
            .client
            .execute("DELETE FROM public.tag_values WHERE value=$1", &[&value])
            .await?;
        ensure!(
            held == 0,
            "batch transaction held {held} dictionary advisory locks"
        );
        ensure!(
            removed == 1,
            "interned value was not committed before the batch"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires ar_io_rust_test; run serially; migrates it and briefly locks object_tags"]
    async fn tag_refs_skip_row_locks_and_racing_deletes_fail_closed() -> Result<()> {
        let url = std::env::var("DATABASE_URL")?;
        let mut setup = BlockStore::connect(&url).await?;
        ensure!(
            setup
                .client
                .query_one("SELECT current_database()", &[])
                .await?
                .get::<_, String>(0)
                == "ar_io_rust_test",
            "wrong database"
        );
        setup.migrate_schema(true).await?;
        let id =
            crate::decode_fixed::<32>("z8dH98cY5MvVjBWm7DC6-NjuJOFMZxZeQjh_7hUuK54", "parent ID")?;
        let item = crate::verify_data_item(
            include_bytes!("../../tests/fixtures/ao-unsigned-parent.bin")
                .to_vec()
                .into(),
            &id,
        )
        .await?;
        let mut object = item.metadata(&crate::sha256(&[b"tag-ref-validation-regression"]));
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let value = format!("tag-ref-validation-{}", nanos.as_nanos()).into_bytes();
        object.tags = vec![(b"timestamp".to_vec(), value.clone())];
        setup
            .client
            .execute("INSERT INTO public.tag_values(value) VALUES($1)", &[&value])
            .await?;

        let mut writer = BlockStore::connect(&url).await?;
        let transaction = writer
            .client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .await?;
        BlockStore::write_objects(&transaction, std::slice::from_ref(&object)).await?;
        let xmax: String = transaction
            .query_one(
                "SELECT xmax::text FROM public.tag_values WHERE value=$1",
                &[&value],
            )
            .await?
            .get(0);
        transaction.rollback().await?;

        let pid: i32 = writer
            .client
            .query_one("SELECT pg_backend_pid()", &[])
            .await?
            .get(0);
        let deleter = setup.client.transaction().await?;
        let deleted = deleter
            .execute("DELETE FROM public.tag_values WHERE value=$1", &[&value])
            .await?;
        let batch_object = object.clone();
        let batch = tokio::spawn(async move {
            let transaction = writer
                .client
                .build_transaction()
                .isolation_level(IsolationLevel::ReadCommitted)
                .start()
                .await?;
            BlockStore::write_objects(&transaction, std::slice::from_ref(&batch_object))
                .await
                .map(|_| ())
        });
        let observer = BlockStore::connect(&url).await?;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let blocked: bool = observer
                .client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1
                     AND wait_event_type='Lock' AND query LIKE 'INSERT INTO public.object_tags%')",
                    &[&pid],
                )
                .await?
                .get(0);
            if blocked {
                break;
            }
            ensure!(
                !batch.is_finished(),
                "tag write finished before the delete committed"
            );
            ensure!(
                std::time::Instant::now() < deadline,
                "tag write never waited for the delete"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        deleter.commit().await?;
        let error = batch
            .await?
            .expect_err("tag write referenced a deleted dictionary key");
        let code = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<tokio_postgres::Error>())
            .and_then(|error| error.code().map(|code| code.code().to_owned()));
        ensure!(
            xmax == "0",
            "tag write row-locked dictionary value (xmax {xmax})"
        );
        ensure!(
            deleted == 1,
            "unreferenced dictionary value was not deleted"
        );
        ensure!(
            code.as_deref() == Some("23503"),
            "racing delete was not rejected as a missing reference: {error:#}"
        );
        Ok(())
    }
}
