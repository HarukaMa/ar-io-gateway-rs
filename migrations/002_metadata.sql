CREATE TABLE public.owners (
    address bytea PRIMARY KEY,
    public_key bytea
);

CREATE TABLE public.objects (
    key bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id bytea NOT NULL UNIQUE CHECK (octet_length(id) = 32),
    kind smallint NOT NULL CHECK (kind IN (0, 1)),
    metadata_complete boolean NOT NULL DEFAULT false,
    signature bytea,
    anchor bytea,
    owner_address bytea REFERENCES public.owners,
    target bytea,
    data_size public.uint128,
    content_type text,
    content_encoding text,
    signature_type smallint,
    format smallint,
    quantity numeric CHECK (quantity >= 0 AND scale(quantity) = 0),
    reward numeric CHECK (reward >= 0 AND scale(reward) = 0),
    denomination bigint CHECK (denomination BETWEEN 0 AND 4294967295),
    data_root bytea,
    indexed_at bigint,
    CHECK (NOT metadata_complete OR (
        signature IS NOT NULL AND anchor IS NOT NULL AND owner_address IS NOT NULL
        AND target IS NOT NULL AND data_size IS NOT NULL AND signature_type IS NOT NULL
        AND indexed_at IS NOT NULL
    ))
);
CREATE INDEX objects_owner ON public.objects (owner_address, key);
CREATE INDEX objects_target ON public.objects (target, key) WHERE target IS NOT NULL;

CREATE TABLE public.block_transactions (
    block_hash bytea NOT NULL REFERENCES public.blocks (hash),
    position integer NOT NULL CHECK (position >= 0),
    object_key bigint NOT NULL REFERENCES public.objects,
    end_offset public.uint128,
    PRIMARY KEY (block_hash, position)
);
CREATE INDEX transaction_membership ON public.block_transactions (object_key, block_hash, position);
CREATE INDEX transaction_end ON public.block_transactions (end_offset) WHERE end_offset IS NOT NULL;

CREATE TABLE public.canonical_placements (
    object_key bigint PRIMARY KEY REFERENCES public.objects,
    block_height bigint NOT NULL CHECK (block_height >= 0),
    position integer NOT NULL CHECK (position >= 0),
    kind smallint NOT NULL CHECK (kind IN (0, 1)),
    id bytea NOT NULL CHECK (octet_length(id) = 32)
);
CREATE INDEX placement_chronology
    ON public.canonical_placements (block_height, position, kind, id);

CREATE TABLE public.tag_names (
    key bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    value bytea NOT NULL CHECK (digest = sha256(value))
);
CREATE INDEX tag_names_digest ON public.tag_names (digest);
CREATE TABLE public.tag_values (LIKE public.tag_names INCLUDING ALL);

-- Raw bytes can exceed B-tree entry limits, and digest collisions remain distinct.
-- Writers acquire every batch's digest locks in sorted order before inserting.
CREATE FUNCTION public.unique_tag_bytes() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE duplicate boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'Dictionary writes require read committed';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(encode(NEW.digest, 'hex'), 0));
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I WHERE digest=$1 AND value=$2 AND key<>$3)',
                   TG_TABLE_SCHEMA, TG_TABLE_NAME)
        INTO duplicate USING NEW.digest, NEW.value, NEW.key;
    IF duplicate THEN
        RAISE EXCEPTION 'Duplicate tag bytes' USING ERRCODE='23505';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER unique_name_bytes BEFORE INSERT OR UPDATE ON public.tag_names
    FOR EACH ROW EXECUTE FUNCTION public.unique_tag_bytes();
CREATE TRIGGER unique_value_bytes BEFORE INSERT OR UPDATE ON public.tag_values
    FOR EACH ROW EXECUTE FUNCTION public.unique_tag_bytes();

CREATE TABLE public.object_tags (
    object_key bigint NOT NULL REFERENCES public.objects,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    name_key bigint NOT NULL REFERENCES public.tag_names,
    value_key bigint NOT NULL REFERENCES public.tag_values,
    PRIMARY KEY (object_key, ordinal)
);
CREATE INDEX tag_candidates ON public.object_tags (name_key, value_key, object_key);
CREATE STATISTICS public.tag_pair_statistics (mcv, dependencies)
    ON name_key, value_key FROM public.object_tags;
ALTER STATISTICS public.tag_pair_statistics SET STATISTICS 1000;

INSERT INTO public.ar_io_schema_migrations (version, name) VALUES (2, '002_metadata');
