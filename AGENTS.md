# AR.IO Rust gateway

## Orientation and tracking

- Repository: `HarukaMa/ar-io-gateway-rs`. Primary branch: `slave`.
- GitHub Issues are the project tracker. Use umbrella #1, the existing phase issues, and detailed sub-issues for the active phase. Check existing issues before creating new ones.
- Keep implementation scope, acceptance criteria, blockers, and delivery evidence in the relevant GitHub issue. Session todos are temporary execution bookkeeping.
- Verify mutable operational facts before acting.
- Never publish credentials, private-network addresses, or live deployment identifiers in tracked files or GitHub issues.

## Architecture

- Build an independent Rust gateway in one Cargo package with one long-running process for serving and background operations. Avoid a generic SDK, provider framework, or database abstraction.
- Target feature parity, strong content verification, and usable baseline performance. Defer performance optimization until measurements demonstrate a problem.
- Keep the existing Node gateway unchanged as the production behavioral oracle and rollback deployment. Run Rust on a separate port with separate storage during development.
- Every Rust-owned request path runs end to end in Rust. Do not call legacy Node services or read live legacy SQLite databases.
- Isolate HTTP execution capacity from indexing, unbundling, repair, and maintenance within the same process. Keep CPU-heavy and blocking work off HTTP workers. Bound work, database concurrency, memory, queues, and request duration. Preserve cancellation and backpressure.
- Resolve ArNS and ANT state directly through the configured trusted Solana RPC. Validate account ownership, canonical PDAs, layouts, linkage, and name lifecycle rules. Permit per-ANT `getProgramAccounts` reads filtered by mint and record discriminator, with bounded response size, concurrency, and deadlines. Add ANT indexing only when measured resolution performance requires it.
- Keep resolver-side ArNS and ANT lookups uncached so each request queries current finalized state.

## Verification and trust

- Anchor chain history to the trusted Arweave node's consensus-validated stable block index. Pin synchronization to a stable checkpoint outside the node's consensus window.
- Treat archival providers and external location hints as untrusted. Authenticate block hashes and membership, transaction signatures and roots, chunk proofs, bundle offsets, and item signatures before serving or caching bytes.
- Legacy format-1 transactions without denomination may use archival field interpretations. Their signatures do not uniquely bind field boundaries. Verify signatures and canonical membership, then reconstruct the complete block transaction root and check block geometry before serving inline content or recording legacy metadata.
- ECDSA transactions still require metadata from the trusted node and its trusted transport. Fail closed when that header is unavailable.
- Pre-2.0 block shadows use the checksum-pinned official H2 auxiliary with the trusted block index. Treat that table as an additional client-verification anchor.
- Fail closed when required anchors or proofs are unavailable or invalid. Provider agreement does not establish authenticity.
- Preserve protocol compatibility. Identify unsupported formats and related compatibility gaps explicitly before claiming a request path or indexing range is complete.

## Storage

- PostgreSQL is the sole permanent write and indexing database. Rebuild its historical index through Rust's verified indexing pipeline. Do not migrate legacy SQLite rows or add interchangeable backends or a live legacy-database dependency. Keep Node and its SQLite databases intact for rollback.
- Store immutable metadata and ordered tags once. Keep canonical membership, bundle occurrences, progress, and the stable-chain watermark separate. Restrict fork rollback to unstable membership.
- Reuse the selected normalized tag dictionaries and canonical-placement layout. Search optimization requires evidence from the relevant workload.
- Use bounded bulk ingestion and safe write concurrency. Keep facts, membership, placement updates, and progress transactionally consistent. Reject conflicting immutable records and support resumability.
- Keep content bytes outside PostgreSQL. Future disk caching remains Rust-owned. Reusing Node cache files requires an explicit identity mapping and independent verification.

## Verification and delivery

- Reuse existing code and dependencies, enabling only required features. Keep code, comments, and documentation ASCII-only.
- Run `cargo fmt` and `cargo test` for implementation changes. Exercise the changed command or serving path with the smallest meaningful runtime check. Run database-specific checks explicitly when the normal suite excludes them.
- Use the dedicated local `ar_io_rust_test` database for indexing verification. Preserve existing data and leave databases belonging to other projects untouched. Production measurements require a separately approved bounded batch.
- Deliver coherent issue-sized commits. Each commit must be independently buildable and cryptographically signed with `git commit -S`.
- Include implementation, verification, signed commit, push, and issue updates in one concrete approval batch when publication is intended. Complete that approved delivery before moving to the next issue.
- Verify the published commit is remotely reachable before closing its issue. Local implementation, passing checks, or a local commit alone do not satisfy issue closure.
- Keep unrelated experiments and private operational files out of implementation commits. Published rollback requires separately approved signed reverts and corresponding issue updates.
