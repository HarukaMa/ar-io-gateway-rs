CREATE DOMAIN public.uint128 AS numeric(39,0)
CHECK (VALUE >= 0 AND VALUE <= 340282366920938463463374607431768211455);

CREATE TABLE public.blocks (
    height bigint NOT NULL CHECK (height >= 0),
    hash bytea PRIMARY KEY CHECK (octet_length(hash) = 48),
    previous_hash bytea CHECK (octet_length(previous_hash) = 48),
    tx_root bytea NOT NULL CHECK (octet_length(tx_root) IN (0, 32)),
    weave_size public.uint128 NOT NULL,
    timestamp bigint CHECK (timestamp >= 0),
    UNIQUE (height, hash)
);
CREATE INDEX blocks_weave ON public.blocks (weave_size, height);

CREATE TABLE public.canonical_blocks (
    height bigint PRIMARY KEY,
    block_hash bytea NOT NULL,
    FOREIGN KEY (height, block_hash) REFERENCES public.blocks (height, hash)
);

CREATE TABLE public.block_index_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    start_height bigint NOT NULL CHECK (start_height >= 0),
    imported_through bigint REFERENCES public.canonical_blocks (height),
    checkpoint_height bigint NOT NULL CHECK (checkpoint_height >= start_height),
    checkpoint_hash bytea NOT NULL CHECK (octet_length(checkpoint_hash) = 48),
    source text NOT NULL CHECK (source <> ''),
    CHECK (imported_through >= start_height AND imported_through <= checkpoint_height)
);

CREATE TABLE public.ar_io_schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    name text NOT NULL
);
INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (1, '001_block_index');
