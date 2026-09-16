LOCK TABLE public.objects, public.object_tags, public.canonical_placements,
    public.bundle_progress IN SHARE ROW EXCLUSIVE MODE;

-- Fold ASCII names without decoding arbitrary signed tag bytes as UTF-8.
CREATE INDEX tag_names_bundle_case ON public.tag_names (
    translate(encode(value,'escape'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')
) WHERE translate(encode(value,'escape'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')
    IN ('bundle-format','bundle-version');

CREATE OR REPLACE FUNCTION public.refresh_bundle_flags() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE
    ids bigint[];
BEGIN
    IF TG_OP='TRUNCATE' THEN
        UPDATE public.objects SET is_bundle=false WHERE is_bundle;
        RETURN NULL;
    ELSIF TG_OP='INSERT' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM new_tags;
    ELSIF TG_OP='DELETE' THEN
        SELECT array_agg(DISTINCT object_key) INTO ids FROM old_tags;
    ELSE
        SELECT array_agg(object_key) INTO ids FROM (
            SELECT object_key FROM new_tags UNION SELECT object_key FROM old_tags
        ) changed;
    END IF;
    IF ids IS NULL THEN RETURN NULL; END IF;

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
), affected_objects AS MATERIALIZED (
    SELECT DISTINCT t.object_key
    FROM public.tag_names n
    JOIN public.object_tags t ON t.name_key=n.key
    WHERE translate(encode(n.value,'escape'),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')
        IN ('bundle-format','bundle-version')
        AND n.value NOT IN ('Bundle-Format'::bytea,'Bundle-Version'::bytea)
), flags AS MATERIALIZED (
    SELECT requested.key, (SELECT count(DISTINCT criteria.json)=1 FROM bundle_tags criteria WHERE
        (SELECT true FROM public.object_tags f WHERE f.object_key=requested.key
            AND f.name_key=criteria.format_name AND f.value_key=criteria.format_value LIMIT 1) IS TRUE
        AND (SELECT true FROM public.object_tags v WHERE v.object_key=requested.key
            AND v.name_key=criteria.version_name AND v.value_key=criteria.version_value LIMIT 1) IS TRUE
    ) AS recognized
    FROM public.objects requested JOIN affected_objects a ON a.object_key=requested.key
)
UPDATE public.objects o SET is_bundle=flags.recognized FROM flags
WHERE o.key=flags.key AND o.is_bundle IS DISTINCT FROM flags.recognized;

INSERT INTO public.ar_io_schema_migrations(version,name) VALUES(13,'013_bundle_tag_casing');
