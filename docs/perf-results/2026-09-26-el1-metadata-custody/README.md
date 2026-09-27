# Carrier-owned metadata aperture

Pre-change source fa557cc7d. Contract kernel.el1.metadata-allocation.
The red witness passes two different CarrierVmCustody objects through the
existing global aperture accessor: reserving slot zero in one makes it occupied
in the other (exit 101). The corrected accessor returns each custody's own
state. No process-global aperture or invented generation counter remains.

Live HVF vCPUs now carry their custody and captured VM generation into HVC #6.
Requests must match the current live generation. Grant receipts retain that
generation; wrong token/length/generation cannot unmap. Diagnostic reset changes
counters only, never backing. Successful raw VM destruction releases its
metadata backing; failed destruction preserves ownership and data.

Tests call the production return operation with injected unmap outcomes to
prove refusal retains bytes and reservations, retry releases exactly once,
and stale identities never call unmap. The former test-only reset operation
was removed once diagnostic reset stopped owning mappings.

Four metadata tests pass; all 48 existing carrier custody tests pass; HVF
all-target Clippy with -D warnings and formatting pass. No signed result is
claimed for this revision: the prior focused signed green belongs to c33e1d152.

Remaining ownership work: publish metadata mappings into the shared stage-2
record ledger with exact rollback/retirement, including publication failures.
The current per-carrier raw map/unmap path is not yet full stage-2 inventory
acceptance. Concurrent guest use, IRQ protocol, bounded-work/retention evidence
and control gating also remain. Then rerun signed allocation and proceed to
shared MMU/EL1 first-touch. All end-to-end goal stages remain required.
