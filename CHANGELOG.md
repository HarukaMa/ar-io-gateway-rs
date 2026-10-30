# Changelog

## 88-pre-rs

- Report `X-AR-IO-Stable` from the verified block's stability. Data within the fork depth of the trusted tip is labelled unstable and cached for 12 hours without `immutable`. Stable data keeps the 30-day `immutable` tier, including content restored from the disk cache.

## 85-rs

- Preserve resolved ArNS headers on content retrieval errors, including missing content and manifest paths.
- Preserve uploaded JSON Content-Type parameters without adding a charset.
- Accept case-insensitive byte ranges and ignore unknown range units.
- Use signed Repr-Digest headers for whole-item digests on range responses.
- Cache verified manifest path resolutions, including missing paths, with bounded memory. Revalidate the manifest anchor and content policy before cache lookup.
- Share bounded ArNS resolution caching across gateway roots until the ANT TTL or ArNS lease/grace expiry. Coalesce concurrent lookups, never retain zero-TTL or missing results, and fail closed when an expired entry cannot refresh. Content cache lifetimes use the remaining resolution TTL.
- Accept selective `ANS104_INDEX_FILTER` values for bundle items, using upstream filter syntax plus a `blockHeight` range. Skipped items are not written, nested bundles stay indexed, and gateway info reports the configured filter.
- Publish `cdb64-root-tx` bands over Index Sharing (publication protocol version 1). Set `AR_IO_INDEXES_DIR` to a directory of `<index>/<band>/` band directories, which must be writable for its `.state/` subdirectory. The first identity in `AR_IO_IDENTITIES_FILE` signs and serves `/ar-io/indexes`, the band files by name, digest and WebSeed with single-range support, deterministic hybrid torrents that match libtorrent, and an RSS feed per index. `/ar-io/info` advertises them. Documents are renewed halfway through their 24-hour lifetime. Without a torrent engine, BitTorrent clients download from the WebSeed.

Index Sharing subscriptions and CDB64 lookups remain outside the current release scope. Range requests retain full content verification before serving.
