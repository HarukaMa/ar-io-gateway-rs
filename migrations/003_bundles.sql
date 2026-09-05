CREATE TABLE public.item_locations (
    key bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    object_key bigint NOT NULL REFERENCES public.objects,
    parent_key bigint NOT NULL REFERENCES public.objects,
    root_key bigint NOT NULL REFERENCES public.objects,
    parent_offset public.uint128,
    item_offset public.uint128 NOT NULL CHECK (item_offset >= 96),
    item_size public.uint128 NOT NULL,
    data_offset public.uint128 NOT NULL CHECK (data_offset > 0 AND data_offset <= item_size),
    root_offset public.uint128 NOT NULL,
    UNIQUE (root_key, root_offset),
    FOREIGN KEY (root_key, parent_offset) REFERENCES public.item_locations (root_key, root_offset),
    CHECK ((parent_offset IS NULL AND parent_key = root_key AND root_offset = item_offset)
        OR (parent_offset IS NOT NULL AND parent_offset < root_offset
            AND root_offset > parent_offset + item_offset))
);
CREATE INDEX item_lookup ON public.item_locations (object_key, root_key, root_offset);
CREATE INDEX container_children ON public.item_locations (root_key, parent_offset, item_offset);
CREATE INDEX root_items ON public.item_locations (root_key, object_key);

ALTER TABLE public.canonical_placements
    ADD COLUMN location_key bigint REFERENCES public.item_locations;

CREATE TABLE public.bundle_progress (
    root_key bigint PRIMARY KEY REFERENCES public.objects,
    complete boolean NOT NULL DEFAULT false
);

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (3, '003_bundles');
