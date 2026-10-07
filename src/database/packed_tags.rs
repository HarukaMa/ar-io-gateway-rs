use super::*;

pub(super) const PREPARE: &str = include_str!("../../migrations/023_packed_tags_prepare.sql");

impl BlockStore {
    pub async fn prepare_packed_tags(&mut self) -> Result<()> {
        self.migrate_schema(false).await?;
        self.client
            .batch_execute(
                "SET application_name='ar-io-packed-tags-prepare'; SET statement_timeout=0;
             SET transaction_timeout=0; SET lock_timeout='1s'; SET work_mem='16MB';
             SET max_parallel_workers_per_gather=0",
            )
            .await?;
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
            matches!(version, Some(21 | 22 | 23 | 24)),
            "packed tags require schema 21 through 24"
        );
        if matches!(version, Some(23 | 24)) {
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
                 WHERE object_key>$1 AND object_key<=$2 ORDER BY object_key LIMIT 256",
                    &[&after, &high],
                )
                .await?
                .into_iter()
                .map(|row| row.get(0))
                .collect();
            transaction
                .query(
                    "SELECT key FROM public.objects WHERE key=ANY($1) ORDER BY id FOR UPDATE",
                    &[&keys],
                )
                .await?;
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
            if reported.elapsed() >= Duration::from_secs(5) || next == high {
                eprintln!("Packed-tag backfill: key {next}/{high}");
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
}
