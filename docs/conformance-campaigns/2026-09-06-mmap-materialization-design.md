# Exact-MM memory materialization on macOS

Status: implementation direction for the mmap campaign; not a landing receipt.
Controller: `2026-09-04-ecosystem.md`. Preserve capstd-first ordering and the
file mmap <=10 us / anonymous mmap <=6 us acceptance contracts.

## Why this boundary needs to change

The signed fd2121d51 artifact has zero `write_guest_bytes` across 100 immutable
whole-file MAP_PRIVATE mappings, but isolated mmap costs remain 44.774958 us
file and 27.350042 us anonymous. These are measured failures of the targets.
Anonymous host-allocation census records one allocation per untouched mmap.
The current local sparse materializer combines allocation, stage-2 custody,
frame inventory, stage-1 changes, per-executor mappings and deferred protection
receipts. Foreign writes instead enter a COW transaction whose unarmed branch
requires an existing retained translation and owner. An untouched reservation
has neither. Duplicating the local transaction for foreign writes would
duplicate publication and rollback rules.

The local allocator also computes physical padding from the VA's 2 MiB offset,
even for a 4 KiB fault. This is a source-derived amplification hypothesis to
prove with a bounded allocation test and first-touch census, not a timing result.

## Alternatives and decision

1. Share the exact-MM materialization transaction across local and foreign
   callers. This preserves existing kernel authorities while removing the
   dependency on a guest executor for publication. Recommended.
2. Add a second foreign-only allocator. Smaller immediate edit, but it creates
   two implementations of ownership, page-table rollback and zero provenance.
3. Replace the entire VM subsystem. Not justified by the evidence and would
   obscure the measured regressions behind a much larger validation surface.

## State and authority

Reservation declares semantic address range, permissions and backing source.
It does not allocate private host memory. The exact-MM pristine state records
which explicitly reserved private anonymous pages can still supply zeros.
Logical read residency is distinct from physical backing and permissions.
Fork copies this state; DONTFORK removes it; WIPEONFORK clears inherited logical
residency without inventing pristine provenance for materialized child frames.
Exec binds a new state to the newly committed MM. Retirement revokes provenance
before the VA can identify another mapping.

Callers obtain their existing exact-MM mutation exclusion before entering the
shared transaction. Local faults/copies use frame-COW quiescence; foreign
writes use the already-held target-MM mutation authority. The transaction must
not acquire another quiesce guard. A non-cloneable scoped permit identifies
the MM, stage-1 binding and authority lifetime; a raw MM number is insufficient.
Lock ordering remains outer mutation exclusion, topology, then pristine-state
transition. Backend code must not call into runtime MM locks while holding the
pristine-state lock.

## Shared transaction

A common backend component owns the prepare/publish/rollback algorithm. It
accepts the authenticated permit, semantic extent, backing source and intended
permissions. Call-site adapters provide invalidation and retained-owner access;
they must not duplicate allocation or stage-1/inventory publication logic.

1. Revalidate exact binding, permissions, absence or current owner, and explicit
   pristine provenance under mutation exclusion. Preserve neighboring mappings.
2. Reserve inventory capacity and backing before making any guest leaf visible.
   Fault-sized anonymous requests use host-page congruence; use larger alignment
   only where it enables block mappings for the actual requested extent.
3. Journal stage-1 preimages and any structural arena publication. Register
   stage-2 ownership and stage the exact inventory mapping. Authenticate the
   live leaf output, attributes and owner generation before publication.
4. Publish with the exact-ASID invalidation and kernel inventory receipt. Only
   then consume pristine provenance and return the committed backing receipt.
5. Any pre-commit failure restores live/shadow tables, invalidates, and releases
   staged inventory/backing. Failure to prove rollback is fatal; returning an
   ordinary error must never leave a live translation to released memory.

Foreign callers refresh their retained snapshot/backing from the receipt, then
perform the normal prepared write. They must not fabricate an old COW frame.
Local callers update executor caches from that same receipt; these caches are
not the publication authority. Permission changes and residency accounting
remain explicit and must agree with the transaction's published attributes.

## Validation and integration order

First extract the existing transaction without enabling new behavior and prove
existing receipts. Then wire anonymous first-touch and both syscall-copy
directions, followed by foreign writes through that shared transaction. Keep
red tests for absent provenance, stale MM, read-only pages, exact neighboring
bytes, mixed pristine/backed spans, fork policies, and every rollback phase.
Validation queries must not allocate or change mincore residency.

The WIPEONFORK logical-residency test failed before the fix; the full serial
runtime suite after correction passes 2472 tests, 2 ignored, in
`target/conformance/deferred-fork-full-green.log` with run ID
`eco-deferred-fork-green-20260906a`. This validates the current in-progress
source, not a signed guest artifact or a main milestone.

Before mmap landing: signed first-touch/copy/fork/permission/reuse probes, whole
probe family, full serial runtime suite, Ubuntu shell true and Python print,
zero-copy trace and both isolated latency targets on one exact signed artifact.
Reconcile line-pinned inventories on clean committed source, commit, then lint.
Fast-forward only from the main checkout. Fresh quiet-host fork and complete
2127-row cached-oracle ledger follow that landing. Residual file mmap cost
requires separate attribution; lazy anonymous backing does not prove its target.
