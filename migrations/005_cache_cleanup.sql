CREATE INDEX content_cache_blob_hash_idx
    ON public.content_cache ((metadata::jsonb -> 'blob_hash'));

INSERT INTO public.ar_io_schema_migrations (version, name)
    VALUES (5, '005_cache_cleanup');
