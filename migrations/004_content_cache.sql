CREATE TABLE public.content_cache (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 32),
    block_height bigint NOT NULL CHECK (block_height >= 0)
        REFERENCES public.canonical_blocks (height),
    block_hash bytea NOT NULL CHECK (octet_length(block_hash) = 48),
    metadata text NOT NULL CHECK (octet_length(metadata) <= 1048576),
    FOREIGN KEY (block_height, block_hash) REFERENCES public.blocks (height, hash)
);

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (4, '004_content_cache');
