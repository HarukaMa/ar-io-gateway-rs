SET LOCAL lock_timeout='1s';

-- One statement-level check per insert replaces a PL/pgSQL call per row. Rows are already
-- inserted, so the join also catches duplicates within the same statement.
CREATE FUNCTION public.unique_new_object_ids() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM new_objects) THEN
        RETURN NULL;
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Object writes require read committed';
    END IF;
    -- Sorted locks; the check below runs in a fresh snapshot taken after any wait.
    PERFORM pg_advisory_xact_lock((prefix >> 32)::integer, prefix::bit(32)::integer)
    FROM (SELECT DISTINCT public.object_id_prefix(id) AS prefix FROM new_objects ORDER BY 1) locks;
    IF EXISTS (
        SELECT 1 FROM new_objects n
        JOIN public.objects o ON public.object_id_prefix(o.id)=public.object_id_prefix(n.id)
          AND o.id=n.id AND o.key<>n.key
    ) THEN
        RAISE EXCEPTION 'Duplicate object ID' USING ERRCODE='23505';
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER unique_object_id ON public.objects;
-- No write path sets id, so the per-row update check stays and never fires in practice.
CREATE TRIGGER unique_object_id BEFORE UPDATE OF id ON public.objects
    FOR EACH ROW EXECUTE FUNCTION public.unique_object_id();
CREATE TRIGGER unique_new_object_ids AFTER INSERT ON public.objects
    REFERENCING NEW TABLE AS new_objects
    FOR EACH STATEMENT EXECUTE FUNCTION public.unique_new_object_ids();

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(27,'027_set_based_object_id_check');
