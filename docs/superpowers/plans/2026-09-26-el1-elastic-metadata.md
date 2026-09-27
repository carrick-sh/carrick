# EL1 elastic metadata allocation: implementation brief

> For agentic workers: execute this brief under the existing EL1 controller.
> The director owns integration, native controls and signed acceptance.

**Goal:** Supply the neutral MMU with usable EL1-owned metadata storage that
reclaims freed allocations, grows through authenticated host extent grants,
and returns unused dynamic extents. Prove the allocator executes in the guest;
a host-only allocator or a relocated bump pointer does not satisfy this brief.

**Authority:** [accepted EL1 design](../specs/2026-09-24-el1-kernel.md),
[execution controller](2026-09-26-el1-completion.md), and
[metadata refusal prerequisite](2026-09-26-mmu-metadata-refusal.md).
This is a dependency within memory checkpoint 2, not checkpoint acceptance.

## Entry condition and current interfaces

- Finish the selected neutral MMU edit/publication/rollback refusal contract
  before enabling MMU allocations in EL1. The final worker review is pending;
  no current candidate is accepted by this brief.
- `crates/carrick-el1/src/alloc.rs::BumpAllocator` is dormant, starts exactly
  at the object table, and cannot free. There is no installed guest global
  allocator and no MMU dependency in the EL1 crate yet.
- `carrick-el1-abi` owns region reservations and `EL1_ABI_LAYOUT_HASH`.
  The compiled layout census finds an unassigned 9 MiB interval at offsets
  0x00700000..0x01000000. Treat this as a bootstrap candidate requiring an
  explicit ABI reservation, not a dynamic heap or a final fixed RAM pool.
  The nominal 48 MiB heap is largely assigned to other tables.
- `PageTableManager` contains Vec/hashbrown/Arc state. Its pointers and trait
  objects belong to the venue that constructed it. A host manager cannot be
  copied into guest memory and used there. `HostArenaResolver` is the current
  neutral table-access interface; a guest adapter must authenticate an IPA
  against guest-accessible backing and exact live ownership.
- The EL1 entry currently forwards faults after preserving their context.
  Existing HVC values have lifecycle/maintenance meanings. Inventory the
  shared decoder and both AArch64 engine implementations before assigning
  grant request/completion transport; do not alias an existing exit meaning.

## Required outcome and constraints

1. Replace the dormant bump allocator with reclaiming allocation over
   explicitly admitted extents. Handle Rust Layout size/alignment, checked
   arithmetic, exhaustion and reuse without corrupting adjacent reservations.
   Register bootstrap location and size in the ABI hash and layout checks.
2. Distinguish metadata storage from anonymous user frames and page-table
   frames. A metadata allocation returns a pointer valid in the executing
   venue. Extent receipts must distinguish guest VA, stage-1 IPA, host owner
   generation and the identity needed for exact return. Reject stale,
   overlapping or mismatched receipts before publication.
3. Grow through real host grants and return fully unused dynamic extents.
   Preserve a bounded bootstrap reserve only for initialization and servicing
   grant/return bookkeeping. No preallocated maximum guest RAM arena, fixed
   frame pool, or retained-ever-growing metadata list is the final result.
4. Do not request a host grant while holding a lock needed by completion or
   a host memory editor. Define the allocation/growth/publication protocol,
   including failure and cancellation, before installation. IRQ entry must
   not spin on a lock held by the interrupted EL1 path; any IRQ masking must
   be bounded and restored on every exit. No host wait while IRQs are masked.
5. Keep allocation refusal observable and recoverable through the existing
   typed transaction errors. List remaining infallible MMU lifecycle paths;
   make those actually reached by the new guest initialization/service path
   fallible before exposing them. Do not claim the whole lifecycle migrated.
6. Delete the superseded bump implementation when its replacement is active.
   Preserve the single neutral MMU algorithm and personality boundary. This
   task does not authorize a guest table algorithm beside a host shadow.

## Acceptance witnesses

- Register the precise metadata allocation contract before implementation.
  Preserve the existing raw overlap red. New red evidence must be a behavioral
  or work assertion, not failure to compile against a nonexistent API.
- VM-free: actual writes into independently owned backing, arbitrary valid
  alignments, fragmentation/reuse, refusal, double/stale extent admission,
  unchanged neighboring reservations, and repeated grow/free/return cycles.
  Test 1/8/32/128 extents with deterministic allocation, search, split/merge,
  requested-byte and retained-byte bounds derived from the chosen structure.
  Historical freed extents must not make later operations unbounded.
- Guest: allocate/write/verify/free repeatedly using the installed allocator;
  force growth beyond bootstrap, observe real host grant and return counters,
  and verify a denied grant leaves existing allocations usable and permits a
  subsequent successful request. Exercise concurrent users and pending host
  work without losing a wake or deadlocking. Preserve the exact signed image,
  test binary, negative entitlement control and run-scoped cleanup.
- Build the neutral MMU into the guest only after its selected allocation
  closure is safe. A host test of guest-shaped pointers is not guest execution.
- Run the applicable host checks and exact-artifact signed tests. Preserve the
  broader first-touch red until actual guest service makes it green; never
  reduce its <0.125 incremental host-exits/page requirement.

## Next dependency and completion limit

This deliverable supplies storage and extent lifetime, not anonymous mapping
semantics. Immediately follow it with the shared host/EL1 mutation protocol,
elastic page-frame grants and in-guest first-touch/permission handling. The
existing two-process first-touch witness is the next performance milestone.
Fork COW, memory syscalls, removal of the last host page-table writer/pause,
full promotion, paired workloads, later checkpoints and the per-workload 2x
native-arm64 Docker objective remain required by the original controller.
