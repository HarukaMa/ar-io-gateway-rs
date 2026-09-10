LOCK TABLE public.objects, public.object_tags, public.canonical_placements,
    public.bundle_progress IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE public.objects ADD COLUMN is_bundle boolean NOT NULL DEFAULT false;


    WITH bundle_tags AS MATERIALIZED (
        SELECT fn.key AS format_name, fv.key AS format_value,
               vn.key AS version_name, vv.key AS version_value, formats.json
        FROM (VALUES ('binary', '2.0.0', false), ('json', '1.0.0', true))
            AS formats(format, version, json)
        JOIN public.tag_names fn ON fn.digest=sha256('Bundle-Format'::bytea)
            AND fn.value='Bundle-Format'::bytea
        JOIN public.tag_values fv ON fv.digest=sha256(convert_to(formats.format, 'UTF8'))
            AND fv.value=convert_to(formats.format, 'UTF8')
        JOIN public.tag_names vn ON vn.digest=sha256('Bundle-Version'::bytea)
            AND vn.value='Bundle-Version'::bytea
        JOIN public.tag_values vv ON vv.digest=sha256(convert_to(formats.version, 'UTF8'))
            AND vv.value=convert_to(formats.version, 'UTF8')
    )
    , bundle_candidates AS MATERIALIZED (
        SELECT f.object_key, criteria.json FROM bundle_tags criteria
        JOIN public.object_tags f ON f.name_key=criteria.format_name AND f.value_key=criteria.format_value
        INTERSECT
        SELECT v.object_key, criteria.json FROM bundle_tags criteria
        JOIN public.object_tags v ON v.name_key=criteria.version_name AND v.value_key=criteria.version_value
    )
UPDATE public.objects o SET is_bundle=true
WHERE o.key IN (SELECT object_key FROM bundle_candidates);

CREATE TABLE public.bundle_totals (
    height bigint NOT NULL,
    writer integer NOT NULL,
    roots bigint NOT NULL,
    bytes numeric NOT NULL,
    completed bigint NOT NULL,
    completed_bytes numeric NOT NULL,
    nested bigint NOT NULL,
    PRIMARY KEY(height,writer)
);
INSERT INTO public.bundle_totals
SELECT p.block_height,0,
    count(*) FILTER (WHERE p.kind=0),
    coalesce(sum(o.data_size) FILTER (WHERE p.kind=0),0),
    count(*) FILTER (WHERE p.kind=0 AND coalesce(bp.complete,false)),
    coalesce(sum(o.data_size) FILTER (WHERE p.kind=0 AND coalesce(bp.complete,false)),0),
    count(*) FILTER (WHERE p.kind=1)
FROM public.canonical_placements p
JOIN public.objects o ON o.key=p.object_key AND o.metadata_complete AND o.is_bundle
LEFT JOIN public.bundle_progress bp ON bp.root_key=o.key
GROUP BY p.block_height;

-- Match the verified tag-pair semantics, including repeated tags and either supported format.
CREATE FUNCTION public.refresh_bundle_flags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE
    ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        UPDATE public.objects SET is_bundle=false WHERE is_bundle;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM new_tags;
    ELSIF TG_OP='DELETE' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM old_tags;
    ELSE
        SELECT array_agg(object_key) INTO ids FROM (
            SELECT object_key FROM new_tags UNION SELECT object_key FROM old_tags
        ) changed;
    END IF;
    IF ids IS NULL THEN RETURN NULL; END IF;

    WITH bundle_tags AS MATERIALIZED (
        SELECT fn.key AS format_name, fv.key AS format_value,
               vn.key AS version_name, vv.key AS version_value, formats.json
        FROM (VALUES ('binary', '2.0.0', false), ('json', '1.0.0', true))
            AS formats(format, version, json)
        JOIN public.tag_names fn ON fn.digest=sha256('Bundle-Format'::bytea)
            AND fn.value='Bundle-Format'::bytea
        JOIN public.tag_values fv ON fv.digest=sha256(convert_to(formats.format, 'UTF8'))
            AND fv.value=convert_to(formats.format, 'UTF8')
        JOIN public.tag_names vn ON vn.digest=sha256('Bundle-Version'::bytea)
            AND vn.value='Bundle-Version'::bytea
        JOIN public.tag_values vv ON vv.digest=sha256(convert_to(formats.version, 'UTF8'))
            AND vv.value=convert_to(formats.version, 'UTF8')
    )
    , flags AS MATERIALIZED (
        SELECT requested.key, EXISTS (SELECT 1 FROM bundle_tags criteria WHERE

    (SELECT true FROM public.object_tags f WHERE f.object_key=requested.key
        AND f.name_key=criteria.format_name AND f.value_key=criteria.format_value LIMIT 1) IS TRUE
    AND (SELECT true FROM public.object_tags v WHERE v.object_key=requested.key
        AND v.name_key=criteria.version_name AND v.value_key=criteria.version_value LIMIT 1) IS TRUE
        ) AS recognized
        FROM public.objects requested WHERE requested.key=ANY(ids)
    )
    UPDATE public.objects o SET is_bundle=flags.recognized FROM flags
    WHERE o.key=flags.key AND o.is_bundle IS DISTINCT FROM flags.recognized;
    RETURN NULL;
END;
$$;
CREATE TRIGGER bundle_flags_insert AFTER INSERT ON public.object_tags
REFERENCING NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_update AFTER UPDATE ON public.object_tags
REFERENCING OLD TABLE AS old_tags NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_delete AFTER DELETE ON public.object_tags
REFERENCING OLD TABLE AS old_tags FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_truncate AFTER TRUNCATE ON public.object_tags
FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();

-- Serialize new placements with metadata completion before the placement row exists.
CREATE FUNCTION public.lock_placement_metadata() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
    PERFORM 1 FROM public.objects WHERE key=NEW.object_key FOR SHARE;
    RETURN NEW;
END;
$$;
CREATE TRIGGER placement_metadata_lock BEFORE INSERT ON public.canonical_placements
FOR EACH ROW EXECUTE FUNCTION public.lock_placement_metadata();

-- Per-writer deltas avoid a shared counter lock across indexing connections.
CREATE FUNCTION public.update_bundle_totals() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE
    source text;
    changes text := '';
BEGIN
    IF TG_OP='TRUNCATE' THEN
        IF TG_TABLE_NAME='bundle_progress' THEN
            UPDATE public.bundle_totals SET completed=0,completed_bytes=0;
        ELSE
            TRUNCATE public.bundle_totals;
        END IF;
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME='bundle_progress' THEN
        source := 'SELECT p.block_height AS height,0 AS roots,0 AS bytes,
            1 AS completed,o.data_size AS completed_bytes,0 AS nested
            FROM %I bp JOIN public.objects o ON o.key=bp.root_key
            JOIN public.canonical_placements p ON p.object_key=o.key
            WHERE p.kind=0 AND o.metadata_complete AND o.is_bundle AND bp.complete';
    ELSE
        source := 'SELECT p.block_height AS height,(p.kind=0)::integer AS roots,
            CASE WHEN p.kind=0 THEN o.data_size ELSE 0 END AS bytes,
            (p.kind=0 AND coalesce(bp.complete,false))::integer AS completed,
            CASE WHEN p.kind=0 AND coalesce(bp.complete,false) THEN o.data_size ELSE 0 END AS completed_bytes,
            (p.kind=1)::integer AS nested FROM ';
        IF TG_TABLE_NAME='objects' THEN
            source := source || '%I o JOIN public.canonical_placements p ON p.object_key=o.key';
        ELSE
            source := source || '%I p JOIN public.objects o ON o.key=p.object_key';
        END IF;
        source := source || ' LEFT JOIN public.bundle_progress bp ON bp.root_key=o.key
            WHERE o.metadata_complete AND o.is_bundle';
    END IF;
    IF TG_OP<>'DELETE' THEN
        changes := 'SELECT 1 AS direction,c.* FROM (' || format(source,'new_rows') || ') c';
    END IF;
    IF TG_OP<>'INSERT' THEN
        IF changes<>'' THEN changes := changes || ' UNION ALL '; END IF;
        changes := changes || 'SELECT -1 AS direction,c.* FROM (' || format(source,'old_rows') || ') c';
    END IF;
    EXECUTE 'INSERT INTO public.bundle_totals AS stored
        SELECT height,pg_backend_pid(),sum(direction*roots),sum(direction*bytes),
            sum(direction*completed),sum(direction*completed_bytes),sum(direction*nested)
        FROM (' || changes || ') delta GROUP BY height
        HAVING sum(direction*roots)<>0 OR sum(direction*bytes)<>0
            OR sum(direction*completed)<>0 OR sum(direction*completed_bytes)<>0
            OR sum(direction*nested)<>0
        ORDER BY height
        ON CONFLICT(height,writer) DO UPDATE SET
            roots=stored.roots+EXCLUDED.roots,bytes=stored.bytes+EXCLUDED.bytes,
            completed=stored.completed+EXCLUDED.completed,
            completed_bytes=stored.completed_bytes+EXCLUDED.completed_bytes,
            nested=stored.nested+EXCLUDED.nested';
    RETURN NULL;
END;
$$;
CREATE TRIGGER bundle_totals_insert AFTER INSERT ON public.objects
REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_update AFTER UPDATE ON public.objects
REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_delete AFTER DELETE ON public.objects
REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_insert AFTER INSERT ON public.canonical_placements
REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_update AFTER UPDATE ON public.canonical_placements
REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_delete AFTER DELETE ON public.canonical_placements
REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_insert AFTER INSERT ON public.bundle_progress
REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_update AFTER UPDATE ON public.bundle_progress
REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_delete AFTER DELETE ON public.bundle_progress
REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_truncate AFTER TRUNCATE ON public.canonical_placements
FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();
CREATE TRIGGER bundle_totals_truncate AFTER TRUNCATE ON public.bundle_progress
FOR EACH STATEMENT EXECUTE FUNCTION public.update_bundle_totals();

ANALYZE public.bundle_totals;
INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(10,'010_bundle_totals');
