SET LOCAL lock_timeout='1s';
LOCK TABLE public.objects IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.object_tags IN SHARE ROW EXCLUSIVE MODE;

CREATE FUNCTION public.decode_tag_refs(refs bytea)
RETURNS TABLE(ordinal integer, name_key bigint, value_key bigint)
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT n, ('x'||encode(substring(refs FROM n*16+1 FOR 8),'hex'))::bit(64)::bigint,
              ('x'||encode(substring(refs FROM n*16+9 FOR 8),'hex'))::bit(64)::bigint
    FROM generate_series(0,octet_length(refs)/16-1) n
$$;

CREATE TABLE public.packed_object_tags (
    object_key bigint PRIMARY KEY REFERENCES public.objects,
    refs bytea NOT NULL CHECK (octet_length(refs)>0 AND octet_length(refs)%16=0)
);
CREATE TABLE public.packed_tag_preparation (
    singleton boolean PRIMARY KEY CHECK(singleton),
    high_key bigint NOT NULL,
    after_key bigint NOT NULL DEFAULT 0 CHECK(after_key>=0 AND after_key<=high_key)
);
INSERT INTO public.packed_tag_preparation(singleton,high_key)
SELECT true,coalesce(max(object_key),0) FROM public.object_tags;

CREATE FUNCTION public.mirror_packed_tags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
DECLARE ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        TRUNCATE public.packed_object_tags;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM new_tags;
    ELSIF TG_OP='DELETE' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM old_tags;
    ELSE
        SELECT array_agg(object_key) INTO ids FROM (
            SELECT object_key FROM old_tags UNION SELECT object_key FROM new_tags
        ) changed;
    END IF;
    IF ids IS NULL THEN RETURN NULL; END IF;
    PERFORM key FROM public.objects WHERE key=ANY(ids) ORDER BY id FOR UPDATE;
    IF EXISTS (SELECT 1 FROM public.object_tags WHERE object_key=ANY(ids)
        GROUP BY object_key HAVING min(ordinal)<>0 OR max(ordinal)::bigint<>count(*)-1) THEN
        RAISE EXCEPTION 'Noncontiguous ordered tags' USING ERRCODE='23514';
    END IF;
    INSERT INTO public.packed_object_tags AS stored(object_key,refs)
    SELECT object_key,string_agg(int8send(name_key)||int8send(value_key),''::bytea ORDER BY ordinal)
    FROM public.object_tags WHERE object_key=ANY(ids) GROUP BY object_key
    ON CONFLICT(object_key) DO UPDATE SET refs=EXCLUDED.refs
    WHERE stored.refs IS DISTINCT FROM EXCLUDED.refs;
    DELETE FROM public.packed_object_tags p WHERE p.object_key=ANY(ids)
        AND NOT EXISTS(SELECT 1 FROM public.object_tags t WHERE t.object_key=p.object_key);
    RETURN NULL;
END $$;
CREATE TRIGGER packed_tags_insert AFTER INSERT ON public.object_tags
    REFERENCING NEW TABLE AS new_tags FOR EACH STATEMENT EXECUTE FUNCTION public.mirror_packed_tags();
CREATE TRIGGER packed_tags_update AFTER UPDATE ON public.object_tags
    REFERENCING OLD TABLE AS old_tags NEW TABLE AS new_tags
    FOR EACH STATEMENT EXECUTE FUNCTION public.mirror_packed_tags();
CREATE TRIGGER packed_tags_delete AFTER DELETE ON public.object_tags
    REFERENCING OLD TABLE AS old_tags FOR EACH STATEMENT EXECUTE FUNCTION public.mirror_packed_tags();
CREATE TRIGGER packed_tags_truncate AFTER TRUNCATE ON public.object_tags
    FOR EACH STATEMENT EXECUTE FUNCTION public.mirror_packed_tags();
