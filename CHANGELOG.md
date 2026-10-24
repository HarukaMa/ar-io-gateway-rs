# Changelog

## 85-rs

- Preserve resolved ArNS headers on content retrieval errors, including missing content and manifest paths.
- Preserve uploaded JSON Content-Type parameters without adding a charset.
- Accept case-insensitive byte ranges and ignore unknown range units.
- Use signed Repr-Digest headers for whole-item digests on range responses.
- Cache verified manifest path resolutions, including missing paths, with bounded memory. Revalidate the manifest anchor and content policy before cache lookup.
- Share bounded ArNS resolution caching across gateway roots until the ANT TTL or ArNS lease/grace expiry. Coalesce concurrent lookups, never retain zero-TTL or missing results, and fail closed when an expired entry cannot refresh. Content cache lifetimes use the remaining resolution TTL.
- Accept selective `ANS104_INDEX_FILTER` values for bundle items, using upstream filter syntax plus a `blockHeight` range. Skipped items are not written, nested bundles stay indexed, and gateway info reports the configured filter.

Index Sharing remains outside the current release scope. Range requests retain full content verification before serving.
