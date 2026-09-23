CREATE TABLE public.content_blocklist (
    kind text NOT NULL CHECK (kind IN ('id', 'hash', 'name')),
    value text COLLATE "C" NOT NULL,
    reason text CHECK (octet_length(reason) <= 4096),
    PRIMARY KEY (kind, value),
    CHECK (
        (kind IN ('id', 'hash') AND value ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$')
        OR (kind = 'name' AND length(value) BETWEEN 1 AND 253
            AND value ~ '^[a-z0-9_-]+$')
    )
);

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (18, '018_content_blocklist');
