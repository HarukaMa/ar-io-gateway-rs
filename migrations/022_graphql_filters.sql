SET LOCAL lock_timeout='1s';

ALTER TABLE public.canonical_placements
    ADD COLUMN owner_filter bigint,
    ADD COLUMN recipient_filter bigint;

CREATE FUNCTION public.graphql_filter(value bytea) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT public.object_id_prefix(sha256(value))
$$;

-- Admission writers serialize metadata and placements with the object-ID locks.
CREATE FUNCTION public.set_placement_filters() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    SELECT CASE WHEN metadata_complete THEN public.graphql_filter(owner_address) END,
           CASE WHEN metadata_complete AND target<>''::bytea THEN public.graphql_filter(target) END
    INTO NEW.owner_filter, NEW.recipient_filter
    FROM public.objects WHERE key=NEW.object_key;
    RETURN NEW;
END $$;
CREATE TRIGGER placement_filters BEFORE INSERT ON public.canonical_placements
    FOR EACH ROW EXECUTE FUNCTION public.set_placement_filters();

CREATE FUNCTION public.complete_placement_filters() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Match the placement writers' global ID lock order before updating a batch.
    PERFORM p.object_key FROM public.canonical_placements p
    JOIN new_objects n ON n.key=p.object_key JOIN old_objects o ON o.key=n.key
    WHERE ROW(n.metadata_complete,n.owner_address,n.target)
        IS DISTINCT FROM ROW(o.metadata_complete,o.owner_address,o.target)
    ORDER BY n.id FOR UPDATE OF p;

    UPDATE public.canonical_placements p
    SET owner_filter=CASE WHEN n.metadata_complete THEN public.graphql_filter(n.owner_address) END,
        recipient_filter=CASE WHEN n.metadata_complete AND n.target<>''::bytea
            THEN public.graphql_filter(n.target) END
    FROM new_objects n JOIN old_objects o ON o.key=n.key
    WHERE p.object_key=n.key AND ROW(n.metadata_complete,n.owner_address,n.target)
        IS DISTINCT FROM ROW(o.metadata_complete,o.owner_address,o.target);
    RETURN NULL;
END $$;
CREATE TRIGGER completed_placement_filters AFTER UPDATE ON public.objects
    REFERENCING OLD TABLE AS old_objects NEW TABLE AS new_objects
    FOR EACH STATEMENT EXECUTE FUNCTION public.complete_placement_filters();

-- The serving cutover records version 22 after both indexes are ready.
