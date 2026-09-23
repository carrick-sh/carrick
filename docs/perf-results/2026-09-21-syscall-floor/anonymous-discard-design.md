# Private anonymous discard implementation boundary

Status: initial aligned-granule retirement is implemented with positive Node
measurements. Failure injection, partial-granule retirement, cross-backend checks
and full promotion remain open; see assessment.md and discard-retirement/.

Node trace measured about 806 MB explicitly cleared per app iteration. Whole-
range and subrange pristine bypasses failed warmed workload acceptance. The
remaining candidate is retiring materialized backing while preserving the VMA.

The kernel must select each covered segment by its own backing provenance and
permissions. The corrected MADV_DONTNEED branch now selects each private anonymous segment
independently; the prior aggregate writable/shared gate has been removed. Read-only anonymous pages still lose
old contents. A signed fixture now exercises this boundary, plus child-only
4-KiB discard with neighboring pages and a fork peer preserved.

Add an explicit private-anonymous discard operation to the current-MM memory
interface. Capability refusal before mutation may use the existing authenticated
scrub fallback. A partial publication failure must not be reported as a clean
unsupported result or ordinary ENOMEM; follow existing clean/indeterminate
publication error conventions. Do not implement it as unmap_range followed by
set_unmapped(false): unmap_range also publishes semantic protection metadata.

The shared AArch64 implementation can reuse stage-1 edit/TLBI and the HVF
prepare_process_alias_retirement / commit_process_alias_retirement mechanism.
Preparation reserves inventory changes without changing aliases; commit voids
old COW receipts, unregisters this MM's aliases, disarms only retired leases,
and preserves surviving compound fragments. Prepare before invalidation and
classify every failure after invalidation explicitly. Preserve the existing
runtime MM-exclusion order: MADV_DONTNEED already takes the page-table pause
before host-alias dispatch. Do not add a second independent quiescence order.

Only after old translations and authoritative lookup routes are unreachable
may exact-MM deferred anonymous state publish fresh-zero provenance. Keep
semantic VMA R/W/X, including executable V8 ranges. Future read/write/fault
paths must see zero through existing deferred materialization. Partial host
granules need separate proof: old backing must not reappear through a retained
neighbor, and fork peers must retain their old bytes. Unsupported backend and
non-anonymous ranges keep explicit fallback; a missing translation alone is
never proof of pristine bytes.

Contract acceptance must count actual guest-memory zero bytes and backing
allocations at scales 1/8/32/128, with separate complete-granule and boundary
cases. Include failure injection before and after stage-1 publication, repeated
discard, first read/write, fork, mixed VMA protections, holes, and executable
permission preservation. The signed fixture and same-source native ARM64
Docker differential precede full signed promotion. Production trace must show
material reduction in zeroed bytes, then warmed untraced Node ABBA must show a
repeatable runtime benefit. No gain is implied by this design.
