SET LOCAL lock_timeout='1s';
LOCK TABLE public.object_tags IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM public.packed_tag_preparation WHERE singleton AND after_key=high_key) THEN
        RAISE EXCEPTION 'Run prepare-packed-tags before schema cutover';
    END IF;
END $$;
DROP TABLE public.object_tags;
ALTER TABLE public.packed_object_tags RENAME TO object_tags;
ALTER TABLE public.object_tags RENAME CONSTRAINT packed_object_tags_pkey TO object_tags_pkey;
DROP FUNCTION public.mirror_packed_tags();
DROP TABLE public.packed_tag_preparation;

CREATE FUNCTION public.read_object_tags(wanted bigint)
RETURNS TABLE(object_key bigint, ordinal integer, name_key bigint, value_key bigint)
LANGUAGE sql STABLE STRICT PARALLEL SAFE AS $$
    SELECT p.object_key,t.* FROM public.object_tags p
    CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t WHERE p.object_key=wanted
$$;

CREATE FUNCTION public.validate_tag_refs() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
BEGIN
    PERFORM n.key FROM public.tag_names n JOIN (
        SELECT DISTINCT t.name_key FROM new_tags p CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t
    ) wanted ON wanted.name_key=n.key ORDER BY n.key FOR KEY SHARE OF n;
    PERFORM v.key FROM public.tag_values v JOIN (
        SELECT DISTINCT t.value_key FROM new_tags p CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t
    ) wanted ON wanted.value_key=v.key ORDER BY v.key FOR KEY SHARE OF v;
    IF EXISTS(SELECT 1 FROM new_tags p CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t
        LEFT JOIN public.tag_names n ON n.key=t.name_key LEFT JOIN public.tag_values v ON v.key=t.value_key
        WHERE n.key IS NULL OR v.key IS NULL) THEN
        RAISE EXCEPTION 'Missing packed tag dictionary reference' USING ERRCODE='23503';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER validate_refs_insert AFTER INSERT ON public.object_tags
    REFERENCING NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.validate_tag_refs();
CREATE TRIGGER validate_refs_update AFTER UPDATE ON public.object_tags
    REFERENCING NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.validate_tag_refs();

CREATE FUNCTION public.protect_tag_dictionary_key() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
BEGIN
    IF TG_OP='UPDATE' AND NEW.key=OLD.key THEN RETURN NEW; END IF;
    -- A new snapshot after waiting for the dictionary row lock must see committed tag references.
    IF current_setting('transaction_isolation')<>'read committed' THEN
        RAISE EXCEPTION 'Tag dictionary key removal requires read committed' USING ERRCODE='25000';
    END IF;
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
CREATE TRIGGER referenced_name_key BEFORE DELETE OR UPDATE OF key ON public.tag_names
    FOR EACH ROW EXECUTE FUNCTION public.protect_tag_dictionary_key();
CREATE TRIGGER referenced_value_key BEFORE DELETE OR UPDATE OF key ON public.tag_values
    FOR EACH ROW EXECUTE FUNCTION public.protect_tag_dictionary_key();
CREATE TRIGGER referenced_names_truncate BEFORE TRUNCATE ON public.tag_names
    FOR EACH STATEMENT EXECUTE FUNCTION public.protect_tag_dictionary_key();
CREATE TRIGGER referenced_values_truncate BEFORE TRUNCATE ON public.tag_values
    FOR EACH STATEMENT EXECUTE FUNCTION public.protect_tag_dictionary_key();

CREATE OR REPLACE FUNCTION public.refresh_bundle_flags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
DECLARE ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        UPDATE public.objects SET is_bundle=false WHERE is_bundle;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT p.object_key) INTO ids FROM new_tags p
        CROSS JOIN LATERAL public.decode_tag_refs(p.refs) t JOIN public.tag_names n ON n.key=t.name_key
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
    WITH bundle_tags AS MATERIALIZED (
        SELECT fn.key AS format_name,fv.key AS format_value,
               vn.key AS version_name,vv.key AS version_value,formats.json
        FROM (VALUES ('binary','2.0.0',false),('json','1.0.0',true)) formats(format,version,json)
        JOIN public.tag_names fn ON translate(encode(fn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-format'
        JOIN public.tag_values fv ON public.object_id_prefix(sha256(fv.value))=
            public.object_id_prefix(sha256(convert_to(formats.format,'UTF8')))
            AND fv.value=convert_to(formats.format,'UTF8')
        JOIN public.tag_names vn ON translate(encode(vn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-version'
        JOIN public.tag_values vv ON public.object_id_prefix(sha256(vv.value))=
            public.object_id_prefix(sha256(convert_to(formats.version,'UTF8')))
            AND vv.value=convert_to(formats.version,'UTF8')
    ), flags AS MATERIALIZED (
        SELECT requested.key,(
            WITH local_tags AS MATERIALIZED (
                SELECT name_key,value_key FROM public.read_object_tags(requested.key)
            ) SELECT count(DISTINCT criteria.json)=1 FROM bundle_tags criteria WHERE
                EXISTS(SELECT 1 FROM local_tags WHERE name_key=criteria.format_name AND value_key=criteria.format_value)
                AND EXISTS(SELECT 1 FROM local_tags WHERE name_key=criteria.version_name AND value_key=criteria.version_value)
        ) recognized FROM public.objects requested WHERE requested.key=ANY(ids)
    ) UPDATE public.objects o SET is_bundle=flags.recognized FROM flags
    WHERE o.key=flags.key AND o.is_bundle IS DISTINCT FROM flags.recognized;
    RETURN NULL;
END $$;
CREATE TRIGGER bundle_flags_insert AFTER INSERT ON public.object_tags
    REFERENCING NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_update AFTER UPDATE ON public.object_tags
    REFERENCING OLD TABLE AS old_tags NEW TABLE AS new_tags
    FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_delete AFTER DELETE ON public.object_tags
    REFERENCING OLD TABLE AS old_tags FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
CREATE TRIGGER bundle_flags_truncate AFTER TRUNCATE ON public.object_tags
    FOR EACH STATEMENT EXECUTE FUNCTION public.refresh_bundle_flags();
INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(23,'023_packed_tags');
