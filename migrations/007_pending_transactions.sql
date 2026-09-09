CREATE INDEX objects_pending_l1
    ON public.objects (key) INCLUDE (id)
    WHERE kind = 0 AND NOT metadata_complete;

INSERT INTO public.ar_io_schema_migrations (version, name)
VALUES (7, '007_pending_transactions');
