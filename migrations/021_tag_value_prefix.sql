DO $$
DECLARE
    candidate regclass := to_regclass('public.tag_values_digest_prefix_trial');
BEGIN
    IF candidate IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_index i
            JOIN pg_class c ON c.oid=i.indexrelid
            JOIN pg_am am ON am.oid=c.relam
            WHERE i.indexrelid=candidate AND i.indrelid='public.tag_values'::regclass
              AND i.indisvalid AND i.indisready AND i.indislive
              AND NOT i.indisunique AND NOT i.indisprimary
              AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indpred IS NULL
              AND am.amname='btree' AND i.indoption[0]=0
              AND i.indclass[0]=(SELECT oid FROM pg_opclass
                  WHERE opcnamespace='pg_catalog'::regnamespace AND opcname='int8_ops'
                    AND opcmethod=am.oid)
              AND pg_get_expr(i.indexprs,i.indrelid)='object_id_prefix(sha256(value))'
        ) THEN
            RAISE EXCEPTION 'Existing tag value prefix index has an unexpected definition or state';
        END IF;
        ALTER INDEX public.tag_values_digest_prefix_trial RENAME TO tag_values_digest_prefix;
    ELSE
        CREATE INDEX tag_values_digest_prefix ON public.tag_values
            (public.object_id_prefix(sha256(value)));
    END IF;
END $$;

CREATE FUNCTION public.lookup_tag_values(digests bytea[], raw_values bytea[])
RETURNS TABLE(key bigint, ordinality bigint, lock_key bigint)
LANGUAGE SQL STABLE STRICT SET search_path=pg_catalog,public
SET enable_indexscan=off SET enable_indexonlyscan=off SET enable_bitmapscan=on AS $$
    WITH candidates AS MATERIALIZED (
        SELECT stored.key,sha256(stored.value) AS digest,stored.value
        FROM public.tag_values stored
        WHERE public.object_id_prefix(sha256(stored.value))=ANY(
            ARRAY(SELECT public.object_id_prefix(digest) FROM unnest(digests) AS input(digest))
        )
    )
    SELECT stored.key,incoming.ordinality,
           CASE WHEN stored.key IS NULL
                THEN hashtextextended(encode(incoming.digest,'hex'),0) END
    FROM unnest(digests,raw_values) WITH ORDINALITY AS incoming(digest,value,ordinality)
    LEFT JOIN candidates stored ON stored.digest=incoming.digest AND stored.value=incoming.value
$$;

CREATE OR REPLACE FUNCTION public.unique_tag_bytes() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE
    digest bytea := sha256(NEW.value);
    duplicate boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Dictionary writes require read committed';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(encode(digest, 'hex'), 0));
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I WHERE %s AND value=$2 AND key<>$3)',
                   TG_TABLE_SCHEMA,TG_TABLE_NAME,
                   CASE WHEN TG_TABLE_NAME='tag_values'
                        THEN 'public.object_id_prefix(sha256(value))=public.object_id_prefix($1)'
                        ELSE 'sha256(value)=$1' END)
    INTO duplicate USING digest,NEW.value,NEW.key;
    IF duplicate THEN
        RAISE EXCEPTION 'Duplicate tag bytes' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.refresh_bundle_flags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
DECLARE
    ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        UPDATE public.objects SET is_bundle=false WHERE is_bundle;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT t.object_key) INTO ids
        FROM new_tags t JOIN public.tag_names n ON n.key=t.name_key
        WHERE translate(encode(n.value,'escape'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')
            IN ('bundle-format','bundle-version');
    ELSIF TG_OP='DELETE' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM old_tags;
    ELSE
        SELECT array_agg(object_key) INTO ids FROM (
            SELECT object_key FROM new_tags UNION SELECT object_key FROM old_tags
        ) changed;
    END IF;
    IF ids IS NULL THEN RETURN NULL; END IF;

    -- Tag pairs can arrive in separate statements, so recheck all stored tags.
    WITH bundle_tags AS MATERIALIZED (
        SELECT fn.key AS format_name, fv.key AS format_value,
               vn.key AS version_name, vv.key AS version_value, formats.json
        FROM (VALUES ('binary', '2.0.0', false), ('json', '1.0.0', true))
            AS formats(format, version, json)
        JOIN public.tag_names fn ON translate(encode(fn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-format'
        JOIN public.tag_values fv ON public.object_id_prefix(sha256(fv.value))=
            public.object_id_prefix(sha256(convert_to(formats.format, 'UTF8')))
            AND fv.value=convert_to(formats.format, 'UTF8')
        JOIN public.tag_names vn ON translate(encode(vn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-version'
        JOIN public.tag_values vv ON public.object_id_prefix(sha256(vv.value))=
            public.object_id_prefix(sha256(convert_to(formats.version, 'UTF8')))
            AND vv.value=convert_to(formats.version, 'UTF8')
    ), flags AS MATERIALIZED (
        SELECT requested.key, (
            WITH local_tags AS MATERIALIZED (
                SELECT name_key,value_key FROM public.object_tags WHERE object_key=requested.key
            )
            SELECT count(DISTINCT criteria.json)=1 FROM bundle_tags criteria WHERE
                (SELECT true FROM local_tags f WHERE f.name_key=criteria.format_name
                    AND f.value_key=criteria.format_value LIMIT 1) IS TRUE
                AND (SELECT true FROM local_tags v WHERE v.name_key=criteria.version_name
                    AND v.value_key=criteria.version_value LIMIT 1) IS TRUE
        ) AS recognized
        FROM public.objects requested WHERE requested.key=ANY(ids)
    )
    UPDATE public.objects o SET is_bundle=flags.recognized FROM flags
    WHERE o.key=flags.key AND o.is_bundle IS DISTINCT FROM flags.recognized;
    RETURN NULL;
END;
$$;

DROP INDEX IF EXISTS public.tag_values_digest_idx;
ANALYZE public.tag_values;
INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(21,'021_tag_value_prefix');
