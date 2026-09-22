CREATE OR REPLACE FUNCTION public.refresh_bundle_flags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public SET jit=off AS $$
DECLARE
    ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        UPDATE public.objects SET is_bundle=false WHERE is_bundle;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT t.object_key) INTO ids
        FROM new_tags t JOIN public.tag_names n ON n.key=t.name_key
        WHERE translate(encode(n.value,'escape'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')
            IN ('bundle-format','bundle-version');
    ELSIF TG_OP='DELETE' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM old_tags;
    ELSE
        SELECT array_agg(object_key) INTO ids FROM (
            SELECT object_key FROM new_tags UNION SELECT object_key FROM old_tags
        ) changed;
    END IF;
    IF ids IS NULL THEN RETURN NULL; END IF;

    -- Tag pairs can arrive in separate statements, so recheck all stored tags.
    WITH bundle_tags AS MATERIALIZED (
        SELECT fn.key AS format_name, fv.key AS format_value,
               vn.key AS version_name, vv.key AS version_value, formats.json
        FROM (VALUES ('binary', '2.0.0', false), ('json', '1.0.0', true))
            AS formats(format, version, json)
        JOIN public.tag_names fn ON translate(encode(fn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-format'
        JOIN public.tag_values fv ON sha256(fv.value)=sha256(convert_to(formats.format, 'UTF8'))
            AND fv.value=convert_to(formats.format, 'UTF8')
        JOIN public.tag_names vn ON translate(encode(vn.value,'escape'),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='bundle-version'
        JOIN public.tag_values vv ON sha256(vv.value)=sha256(convert_to(formats.version, 'UTF8'))
            AND vv.value=convert_to(formats.version, 'UTF8')
    ), flags AS MATERIALIZED (
        SELECT requested.key, (SELECT count(DISTINCT criteria.json)=1 FROM bundle_tags criteria WHERE
            (SELECT true FROM public.object_tags f WHERE f.object_key=requested.key
                AND f.name_key=criteria.format_name AND f.value_key=criteria.format_value LIMIT 1) IS TRUE
            AND (SELECT true FROM public.object_tags v WHERE v.object_key=requested.key
                AND v.name_key=criteria.version_name AND v.value_key=criteria.version_value LIMIT 1) IS TRUE
        ) AS recognized
        FROM public.objects requested WHERE requested.key=ANY(ids)
    )
    UPDATE public.objects o SET is_bundle=flags.recognized FROM flags
    WHERE o.key=flags.key AND o.is_bundle IS DISTINCT FROM flags.recognized;
    RETURN NULL;
END;
$$;

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (17, '017_bundle_flag_candidates');
