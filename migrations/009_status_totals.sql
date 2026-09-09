LOCK TABLE public.canonical_placements IN SHARE ROW EXCLUSIVE MODE;

-- Each writer owns its counter row, avoiding a shared write lock across indexers.
-- Retired connections remain in the sum; growth follows writer connections, not objects.
CREATE TABLE public.status_totals (
    writer integer PRIMARY KEY,
    transactions bigint NOT NULL,
    items bigint NOT NULL
);
INSERT INTO public.status_totals
SELECT 0, count(*) FILTER (WHERE kind=0), count(*) FILTER (WHERE kind=1)
FROM public.canonical_placements;

CREATE FUNCTION public.update_status_totals() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE
    tx bigint := 0;
    item_count bigint := 0;
    old_tx bigint;
    old_items bigint;
BEGIN
    IF TG_OP='TRUNCATE' THEN
        TRUNCATE public.status_totals;
        RETURN NULL;
    END IF;
    IF TG_OP<>'DELETE' THEN
        SELECT count(*) FILTER (WHERE kind=0), count(*) FILTER (WHERE kind=1)
        INTO tx, item_count FROM new_placements;
    END IF;
    IF TG_OP<>'INSERT' THEN
        SELECT count(*) FILTER (WHERE kind=0), count(*) FILTER (WHERE kind=1)
        INTO old_tx, old_items FROM old_placements;
        tx := tx-old_tx;
        item_count := item_count-old_items;
    END IF;
    IF tx<>0 OR item_count<>0 THEN
        INSERT INTO public.status_totals AS stored VALUES(pg_backend_pid(),tx,item_count)
        ON CONFLICT (writer) DO UPDATE SET transactions=stored.transactions+EXCLUDED.transactions,
            items=stored.items+EXCLUDED.items;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER status_placements_insert AFTER INSERT ON public.canonical_placements
REFERENCING NEW TABLE AS new_placements FOR EACH STATEMENT EXECUTE FUNCTION public.update_status_totals();
CREATE TRIGGER status_placements_update AFTER UPDATE ON public.canonical_placements
REFERENCING OLD TABLE AS old_placements NEW TABLE AS new_placements
FOR EACH STATEMENT EXECUTE FUNCTION public.update_status_totals();
CREATE TRIGGER status_placements_delete AFTER DELETE ON public.canonical_placements
REFERENCING OLD TABLE AS old_placements FOR EACH STATEMENT EXECUTE FUNCTION public.update_status_totals();
CREATE TRIGGER status_placements_truncate AFTER TRUNCATE ON public.canonical_placements
FOR EACH STATEMENT EXECUTE FUNCTION public.update_status_totals();

-- Completion counts subtract the small pending set, without duplicating metadata state.
CREATE INDEX objects_pending_status ON public.objects(kind,key) INCLUDE(id) WHERE NOT metadata_complete;
DROP INDEX public.objects_pending_l1;
CREATE INDEX pending_block_metadata ON public.canonical_blocks(height) WHERE NOT metadata_complete;
INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(9,'009_status_totals');
