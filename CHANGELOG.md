# Changelog

## 85-rs

- Preserve uploaded JSON Content-Type parameters without adding a charset.
- Accept case-insensitive byte ranges and ignore unknown range units.
- Use signed Repr-Digest headers for whole-item digests on range responses.
- Cache verified manifest path resolutions, including missing paths, with bounded memory. Revalidate the manifest anchor and content policy before cache lookup.

Index Sharing remains outside the current release scope. Range requests retain full content verification before serving.
