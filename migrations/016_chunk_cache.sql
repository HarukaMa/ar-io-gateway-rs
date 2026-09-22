CREATE TABLE public.cache_blobs (
    hash bytea PRIMARY KEY CHECK (octet_length(hash) = 32),
    size bigint NOT NULL CHECK (size >= 0),
    last_access bigint NOT NULL
);
CREATE INDEX cache_blobs_access ON public.cache_blobs (last_access, hash);

CREATE TABLE public.cache_transactions (
    block_hash bytea NOT NULL,
    block_height bigint NOT NULL,
    tx_start public.uint128 NOT NULL,
    tx_end public.uint128 NOT NULL,
    tx_path bytea NOT NULL CHECK (octet_length(tx_path) <= 65536),
    PRIMARY KEY (block_hash, tx_start),
    FOREIGN KEY (block_height, block_hash) REFERENCES public.canonical_blocks (height, block_hash) ON DELETE CASCADE,
    CHECK (tx_end >= tx_start)
);
CREATE TABLE public.cache_chunks (
    block_hash bytea NOT NULL,
    tx_start public.uint128 NOT NULL,
    start_offset public.uint128 NOT NULL,
    end_offset public.uint128 NOT NULL,
    hash bytea NOT NULL REFERENCES public.cache_blobs ON DELETE CASCADE,
    data_path bytea NOT NULL CHECK (octet_length(data_path) <= 65536),
    source_host text NOT NULL CHECK (octet_length(source_host) <= 1024),
    PRIMARY KEY (block_hash, start_offset, end_offset, hash),
    FOREIGN KEY (block_hash, tx_start) REFERENCES public.cache_transactions ON DELETE CASCADE,
    CHECK (start_offset > 0 AND end_offset > start_offset AND end_offset - start_offset <= 262144)
);
CREATE INDEX cache_chunks_hash ON public.cache_chunks (hash);
CREATE INDEX cache_chunks_transaction ON public.cache_chunks (block_hash, tx_start);

CREATE TABLE public.cache_objects (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    block_height bigint NOT NULL,
    block_hash bytea NOT NULL,
    inline_hash bytea REFERENCES public.cache_blobs ON DELETE CASCADE,
    metadata text NOT NULL CHECK (octet_length(metadata) <= 1048576),
    last_access bigint NOT NULL DEFAULT extract(epoch FROM clock_timestamp())::bigint,
    FOREIGN KEY (block_height, block_hash) REFERENCES public.canonical_blocks (height, block_hash) ON DELETE CASCADE
);
CREATE INDEX cache_objects_inline_hash ON public.cache_objects (inline_hash) WHERE inline_hash IS NOT NULL;
CREATE INDEX cache_objects_access ON public.cache_objects (last_access DESC, id);

-- The volatile function takes a fresh snapshot after waiting for the budget lock.
CREATE FUNCTION public.prune_cache_objects(keep bytea, entries bigint, bytes bigint)
RETURNS bigint LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE removed bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Cache descriptor admission requires READ COMMITTED';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ar-io cache descriptor budget',0));
    WITH ranked AS (
        SELECT id,row_number() OVER w AS position,sum(octet_length(metadata)) OVER w AS total_bytes
        FROM public.cache_objects WHERE keep IS NULL OR id<>keep
        WINDOW w AS (ORDER BY last_access DESC,id ROWS UNBOUNDED PRECEDING)
    )
    DELETE FROM public.cache_objects o USING ranked r
    WHERE o.id=r.id AND (r.position>entries OR r.total_bytes>bytes);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (16, '016_chunk_cache');
