SET LOCAL lock_timeout='1s';

-- Not STRICT so the planner can inline it into callers; NULL input still yields no rows.
CREATE OR REPLACE FUNCTION public.decode_tag_refs(refs bytea)
RETURNS TABLE(ordinal integer, name_key bigint, value_key bigint)
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT n, substring(refs FROM n*16+1 FOR 8)::bigint, substring(refs FROM n*16+9 FOR 8)::bigint
    FROM generate_series(0,octet_length(refs)/16-1) n
$$;

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(26,'026_inline_tag_ref_decode');
