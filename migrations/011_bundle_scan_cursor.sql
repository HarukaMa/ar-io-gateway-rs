ALTER TABLE public.block_index_state
    ADD COLUMN bundle_cursor_height bigint,
    ADD COLUMN bundle_cursor_position integer,
    ADD COLUMN bundle_cursor_kind smallint,
    ADD COLUMN bundle_cursor_id bytea,
    ADD CONSTRAINT valid_bundle_scan_cursor CHECK (
        num_nonnulls(bundle_cursor_height, bundle_cursor_position,
                     bundle_cursor_kind, bundle_cursor_id) IN (0, 4)
        AND (bundle_cursor_height IS NULL OR (
            bundle_cursor_height >= 0 AND bundle_cursor_position >= 0
            AND bundle_cursor_kind IN (0, 1) AND octet_length(bundle_cursor_id) = 32
        ))
    );

INSERT INTO public.ar_io_schema_migrations (version, name)
VALUES (11, '011_bundle_scan_cursor');
