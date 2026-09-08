ALTER TABLE public.block_index_state
    DROP CONSTRAINT block_index_state_check1,
    ADD CHECK (imported_through >= start_height);

ALTER TABLE public.canonical_blocks
    ADD UNIQUE (height, block_hash),
    ADD COLUMN metadata_complete boolean NOT NULL DEFAULT false;
UPDATE public.canonical_blocks c SET metadata_complete = true
FROM public.blocks b WHERE b.hash = c.block_hash AND b.timestamp IS NOT NULL;

ALTER TABLE public.canonical_placements
    ADD FOREIGN KEY (block_height) REFERENCES public.canonical_blocks (height) ON DELETE CASCADE;

ALTER TABLE public.content_cache
    DROP CONSTRAINT content_cache_block_height_fkey,
    DROP CONSTRAINT content_cache_block_height_block_hash_fkey,
    ADD FOREIGN KEY (block_height, block_hash)
        REFERENCES public.canonical_blocks (height, block_hash) ON DELETE CASCADE;

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (6, '006_chain_reorg');
