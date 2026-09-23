LOCK TABLE public.objects IN ACCESS EXCLUSIVE MODE;

CREATE FUNCTION public.object_id_prefix(id bytea) RETURNS bigint
LANGUAGE SQL IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT ('x' || encode(substring(id FROM 1 FOR 8), 'hex'))::bit(64)::bigint
$$;

DO $$
DECLARE
    candidate regclass := to_regclass('public.objects_id_prefix_trial');
    placement text;
BEGIN
    IF candidate IS NOT NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM pg_index i
            JOIN pg_class c ON c.oid=i.indexrelid
            JOIN pg_am am ON am.oid=c.relam
            WHERE i.indexrelid=candidate AND i.indrelid='public.objects'::regclass
              AND i.indisvalid AND i.indisready AND i.indislive
              AND NOT i.indisunique AND NOT i.indisprimary
              AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indpred IS NULL
              AND am.amname='btree' AND i.indoption[0]=0
              AND i.indclass[0]=(SELECT oid FROM pg_opclass
                  WHERE opcnamespace='pg_catalog'::regnamespace AND opcname='int8_ops'
                    AND opcmethod=am.oid)
              AND pg_get_expr(i.indexprs,i.indrelid)=
                  '(((''x''::text || encode(SUBSTRING(id FROM 1 FOR 8), ''hex''::text)))::bit(64))::bigint'
        ) THEN
            RAISE EXCEPTION 'Existing object ID prefix index has an unexpected definition or state';
        END IF;
        ALTER INDEX public.objects_id_prefix_trial RENAME TO objects_id_prefix;
    ELSE
        SELECT t.spcname INTO placement FROM pg_class c
        JOIN pg_tablespace t ON t.oid=c.reltablespace
        WHERE c.oid='public.objects_id_key'::regclass;
        EXECUTE 'CREATE INDEX objects_id_prefix ON public.objects '
            || '((( ''x'' || encode(substring(id FROM 1 FOR 8), ''hex''))::bit(64)::bigint))'
            || CASE WHEN placement IS NULL THEN '' ELSE format(' TABLESPACE %I',placement) END;
    END IF;
END $$;

CREATE FUNCTION public.unique_object_id() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE prefix bigint := public.object_id_prefix(NEW.id);
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Object writes require read committed';
    END IF;
    PERFORM pg_advisory_xact_lock((prefix >> 32)::integer, prefix::bit(32)::integer);
    IF EXISTS (
        SELECT 1 FROM public.objects o
        WHERE public.object_id_prefix(o.id)=prefix AND o.id=NEW.id AND o.key<>NEW.key
    ) THEN
        RAISE EXCEPTION 'Duplicate object ID' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER unique_object_id BEFORE INSERT OR UPDATE OF id ON public.objects
    FOR EACH ROW EXECUTE FUNCTION public.unique_object_id();
ALTER TABLE public.objects DROP CONSTRAINT objects_id_key;

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(19,'019_object_id_prefix');
