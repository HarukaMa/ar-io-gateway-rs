ALTER FUNCTION public.refresh_bundle_flags() SET jit = off;

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(14,'014_bundle_classification_jit');
