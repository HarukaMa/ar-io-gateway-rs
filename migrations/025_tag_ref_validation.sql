SET LOCAL lock_timeout='1s';

-- Dictionary key removal takes a self-conflicting table lock on object_tags instead of
-- tag writers row-locking every referenced dictionary row.
CREATE OR REPLACE FUNCTION public.validate_tag_refs() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
BEGIN
    IF EXISTS(
        WITH refs AS MATERIALIZED (
            SELECT t.name_key,t.value_key
            FROM new_tags p CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t
        )
        SELECT 1 FROM (SELECT DISTINCT name_key FROM refs) k
        WHERE NOT EXISTS(SELECT 1 FROM public.tag_names n WHERE n.key=k.name_key)
        UNION ALL
        SELECT 1 FROM (SELECT DISTINCT value_key FROM refs) k
        WHERE NOT EXISTS(SELECT 1 FROM public.tag_values v WHERE v.key=k.value_key)
    ) THEN
        RAISE EXCEPTION 'Missing packed tag dictionary reference' USING ERRCODE='23503';
    END IF;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.protect_tag_dictionary_key() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
BEGIN
    IF TG_OP='UPDATE' AND NEW.key=OLD.key THEN RETURN NEW; END IF;
    -- The reference check below must see tag writes committed while this lock was awaited.
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Tag dictionary key removal requires read committed' USING ERRCODE='25000';
    END IF;
    LOCK TABLE public.object_tags IN SHARE ROW EXCLUSIVE MODE;
    IF TG_OP='TRUNCATE' THEN
        IF EXISTS(SELECT 1 FROM public.object_tags) THEN
            RAISE EXCEPTION 'Referenced packed tag dictionary' USING ERRCODE='23503';
        END IF;
        RETURN NULL;
    END IF;
    IF EXISTS(SELECT 1 FROM public.object_tags p CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t
        WHERE CASE WHEN TG_TABLE_NAME='tag_names' THEN t.name_key ELSE t.value_key END=OLD.key) THEN
        RAISE EXCEPTION 'Referenced packed tag dictionary key' USING ERRCODE='23503';
    END IF;
    RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END $$;

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(25,'025_tag_ref_validation');
