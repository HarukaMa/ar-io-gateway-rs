ALTER TABLE public.block_index_state
    ADD COLUMN bundle_scan_boundary bigint,
    ADD COLUMN bundle_backfill_height bigint,
    ADD COLUMN bundle_backfill_position integer,
    ADD COLUMN bundle_backfill_kind smallint,
    ADD COLUMN bundle_backfill_id bytea,
    ADD CONSTRAINT valid_bundle_scan_boundary CHECK (bundle_scan_boundary >= 0),
    ADD CONSTRAINT valid_bundle_backfill_cursor CHECK (
        num_nonnulls(bundle_backfill_height, bundle_backfill_position,
                     bundle_backfill_kind, bundle_backfill_id) IN (0, 4)
        AND (bundle_backfill_height IS NULL OR (
            bundle_backfill_height >= 0 AND bundle_backfill_position >= 0
            AND bundle_backfill_kind IN (0, 1) AND octet_length(bundle_backfill_id) = 32
        ))
    );

INSERT INTO public.ar_io_schema_migrations (version, name)
VALUES (15, '015_bundle_scan_directions');
