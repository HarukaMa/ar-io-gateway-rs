ALTER TABLE public.item_locations ADD COLUMN path numeric[];

WITH RECURSIVE paths AS (
    SELECT key, root_key, root_offset, ARRAY[item_offset::numeric] AS path
    FROM public.item_locations WHERE parent_offset IS NULL
    UNION ALL
    SELECT child.key, child.root_key, child.root_offset, parent.path || child.item_offset::numeric
    FROM public.item_locations child
    JOIN paths parent ON parent.root_key=child.root_key AND parent.root_offset=child.parent_offset
    WHERE cardinality(parent.path) < 32
)
UPDATE public.item_locations stored SET path=paths.path FROM paths WHERE paths.key=stored.key;

DROP INDEX public.item_lookup;
DROP INDEX public.container_children;
ALTER TABLE public.item_locations
    DROP CONSTRAINT item_locations_root_key_parent_offset_fkey,
    DROP CONSTRAINT item_locations_root_key_root_offset_key,
    DROP CONSTRAINT item_locations_check1,
    DROP CONSTRAINT item_locations_item_offset_check,
    DROP COLUMN parent_offset,
    DROP COLUMN root_offset,
    ALTER COLUMN path SET NOT NULL,
    ADD COLUMN json boolean NOT NULL DEFAULT false,
    ADD COLUMN parent_path numeric[] GENERATED ALWAYS AS (
        CASE WHEN cardinality(path) > 1 THEN path[1:cardinality(path)-1] END
    ) STORED,
    ADD CONSTRAINT item_path_bounds CHECK (
        array_ndims(path)=1 AND array_lower(path,1)=1 AND cardinality(path) BETWEEN 1 AND 32
        AND 0 <= ALL(path) AND 340282366920938463463374607431768211455 >= ALL(path)
        AND array_position(path, NULL) IS NULL AND path=path::public.uint128[]::numeric[]
        AND item_offset=path[cardinality(path)] AND item_offset > 0
    ),
    ADD CONSTRAINT item_binary_offset CHECK (json OR item_offset >= 96),
    ADD CONSTRAINT item_path_unique UNIQUE (root_key, path),
    ADD CONSTRAINT item_parent_path FOREIGN KEY (root_key, parent_path)
        REFERENCES public.item_locations (root_key, path),
    ADD CONSTRAINT item_parent_identity CHECK (
        (parent_path IS NULL AND parent_key=root_key)
        OR (parent_path IS NOT NULL AND parent_key<>root_key)
    );
CREATE INDEX item_lookup ON public.item_locations (object_key, root_key, path);
CREATE INDEX container_children ON public.item_locations (root_key, parent_path, item_offset);

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (8, '008_json_bundles');
