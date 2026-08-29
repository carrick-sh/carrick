# MM Authority and Structural Lock Order Design

**Status:** Approved 2026-08-28

**Controlling audit:**
[`docs/runtime-abstraction-audit-2026-08-27.md`](../../runtime-abstraction-audit-2026-08-27.md)
Part 2 items 4 and 5

## Purpose

Carrick currently has one `GuestMemory` view: the address space bound to the
executor handling the syscall. That view cannot safely answer an address in a
different Linux `mm`. `process_vm_readv/writev`, ptrace PEEK/POKE, and
`/proc/<pid>/mem` therefore either stop at an honest error or risk addressing
the caller's bytes at the target's numeric VA.

HVPatch also enforces its page-table-pause and host-alias ordering only by
discipline. The existing `dispatch/lock_order.rs` validator is compiled out of
release artifacts and names almost none of the real acquisition sites. A
foreign write necessarily crosses both domains: it may break target COW under
page-table exclusion and then copy through the live host owner. Building MM
authority without structural lock ordering would reproduce the same ABBA
hazard behind a new API.

This design closes both audit items with one carrier-owned, per-MM authority.
It does not add a second VM, borrow a target executor, or make a current engine
pretend to be a foreign address space.

## Required invariants

1. A guest virtual address is unusable without an authenticated MM token.
2. Only the kernel graph can mint a live token; numeric PID, TID, `MmId`, ASID,
   TTBR, or VA values are not authority.
3. Current-MM and foreign-MM access are different types. There is no blanket
   implementation that turns any `GuestMemory` into foreign memory.
4. A token retains the exact `Arc<Mm>` incarnation and a coherent backend
   snapshot. PID reuse and exec cannot retarget it.
5. Backend, VMA, and frame-inventory revisions are distinct domains. They are
   recorded and validated independently, never compared to one another.
6. Foreign reads use the target's stage-1 root and live global-frame owner.
   They never consult the caller engine's VA mapping.
7. A foreign write cannot reach backing until a `CowBroken` witness for the
   same token, range, and post-COW generation exists.
8. Page-table exclusion is acquired before host-alias mutation. Only the
   outer guard can mint the permit needed to enter the inner phase.
9. Every partial transfer follows Linux iovec ordering: bytes completed before
   the first fault remain completed; a fault before any byte lowers to the
   syscall-specific errno.
10. The current-MM syscall hot path gains no dynamic dispatch, global lookup,
    allocation, or additional lock.

## Authority model

### Kernel-owned identity

`kernel/mm_access.rs` owns the safe authority types:

```rust
pub struct MmToken {
    task: TaskKey,
    mm: Arc<Mm>,
    snapshot: MmBackendSnapshot,
}

pub struct CurrentMm<'context> {
    token: MmToken,
    context: PhantomData<&'context KernelContext>,
}

pub struct ForeignMm {
    token: MmToken,
}
```

Fields and constructors are private. `KernelContext::current_mm()` mints
`CurrentMm` only after the context's exact task/thread binding and scheduler MM
identity agree. `Kernel::foreign_mm(caller, target: TaskKey)` performs an exact
registry lookup, retains that task's `Arc<Mm>`, snapshots its backend, and
returns one of:

```rust
pub enum MmRelation<'context> {
    Current(CurrentMm<'context>),
    Foreign(ForeignMm),
}
```

An `OtherGuest` task may share the caller's MM through `CLONE_VM`; comparison is
therefore by exact `Arc<Mm>`/`MmId`, not by task identity. Shared-MM targets
project as `Current` after permission and target-liveness checks.

`MmToken` is cloneable because its `Arc<Mm>` is the Linux open-file-style MM
reference required by `/proc/<pid>/mem`: an fd opened before target exec keeps
the old MM alive and never silently follows the replacement. It does not keep
the task alive. Operations that require a live task reauthenticate `TaskKey`;
operations whose Linux object is the retained MM use the retained token.

### Token-bound address ranges

Raw VAs enter through a token method and become access-specific ranges:

```rust
pub struct MmReadRange<'mm> { /* token borrow, GuestVa, NonZeroUsize */ }
pub struct MmWriteRange<'mm> { /* token borrow, GuestVa, NonZeroUsize */ }
```

Construction checks overflow and every covered VMA. Zero-length operations
remain a separate, allocation-free success path. The range retains a borrow of
the token, so it cannot be paired with another MM by safe code.

`VmaSummary` grows an explicit access value rather than a raw integer:

```rust
pub struct VmaAccess {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub kernel_visible: bool,
}
```

`dispatch::mem` projects this from the sole live VMA/protection authority.
`kernel_visible = false` carries secret-memory semantics needed by
`/proc/<pid>/mem`. Snapshot fixtures and adapters must name the value
explicitly; no permissive default is provided.

## Current and foreign memory interfaces

`carrick-guest-mem` keeps `GuestMemory` as the low-level byte primitive and
adds a current-MM marker with explicit implementations:

```rust
pub trait CurrentMmMemory: GuestMemory {}
```

There is deliberately no blanket `impl<T: GuestMemory> CurrentMmMemory for T`.
Every production engine and bounded test memory names its current-MM role.
Runtime dispatch generics migrate from `M: GuestMemory` to
`M: CurrentMmMemory` where guest pointers mean the caller's current MM. This is
a compile-time census, not a behavior change.

Foreign access is not implemented on the engine. `carrick-hal` defines only an
object-safe transport over already validated snapshots:

```rust
pub trait ForeignMmTransport: Send + Sync {
    fn read(&self, snapshot: &ForeignMmSnapshot, va: GuestVa, dst: &mut [u8])
        -> Result<ForeignMmReadReceipt, ForeignMmTransportError>;
    fn break_cow(&self, snapshot: &ForeignMmSnapshot, va: GuestVa, len: usize)
        -> Result<ForeignCowReceipt, ForeignMmTransportError>;
    fn write(&self, receipt: &ForeignCowReceipt, va: GuestVa, src: &[u8])
        -> Result<ForeignMmWriteReceipt, ForeignMmTransportError>;
}
```

The HAL values are transport data, not safe authority. A private runtime facade
stored in `hvpatch::ProcessContext` accepts only `ForeignMm` and token-bound
ranges, projects the transport snapshot, validates receipts, and returns Linux
typed errors. No dispatcher field exposes the raw transport.

The transport snapshot carries the exact domains the backend must validate:

```rust
pub struct ForeignMmSnapshot {
    pub mm: NonZeroU64,
    pub binding: MmBinding,
    pub backend_revision: ForeignBackendRevision,
    pub vma_revision: ForeignVmaRevision,
    pub frame_inventory_revision: ForeignFrameInventoryRevision,
    pub mapping_ids: Vec<MappingId>,
}
```

The three revision types are distinct `u64` newtypes in `carrick-hal`; none
implements cross-domain comparison or arithmetic. HVPatch refuses a snapshot
whose optional backend observations are absent; the kernel facade converts the
coherent `MmBackendSnapshot` only after matching its MM identity. Read and
write receipts repeat the MM identity and all post-operation revisions.
`ForeignCowReceipt` additionally carries the exact VA compound, new
mapping/frame IDs, physical extent, and owner generation needed to authenticate
the write. Receipt fields are readable for validation but constructible only
inside the HAL/backend transport modules.

Non-HVPatch backends do not install a transport. Their existing one-host-
process-per-guest behavior remains behind their current host mechanisms until a
backend supplies an equivalent explicit implementation.

## Carrier-owned per-MM access state

HVPatch implements `ForeignMmTransport` on one carrier-shared authority. The
per-MM entry contains only state that belongs to the MM, not a movable executor:

- stable stage-1 root/ASID generation and host-readable table backing;
- shared `PageTableManager` observer/editor;
- `MemoryProtections` and COW-armed ranges;
- frame-inventory authority and backend inventory ledger;
- global-frame owner lookup/copy operations;
- stage-1 invalidation for the exact ASID;
- structural mutation coordinator described below.

The implementation factors these pieces out of `HvfTaskState` into an
`Arc<MmAccessState>`. Movable task state retains only executor-local registers,
mailbox/vCPU data, and a clone of the per-MM authority. Sibling threads and
`CLONE_VM` processes share the same `Arc`; forked MMs receive a distinct one.

Foreign reads walk the snapshot's stage-1 root through owner-pinned table
backing, authenticate each leaf against the exact live global-frame owner, and
copy while the owner lock pins its mapping and generation. A missing or stale
owner is an error, never permission to dereference an old per-vCPU descriptor.

Each read validates the backend, VMA, and frame-inventory revisions before and
after the chunk. Concurrent change returns `Retry`; the runtime retries a
bounded number of times from a fresh kernel-minted snapshot and then lowers to
`EFAULT`/`EIO` according to the consumer. It never splices observations from
different generations.

## Foreign writes and `CowBroken`

The runtime facade accepts a token-bound `MmWriteRange` and asks the carrier
authority to break COW. The backend reuses the existing transactional COW
algorithm: reserve inventory, allocate/map the replacement frame, preserve the
complete page-table pre-image, publish and authenticate stage-1, invalidate the
exact ASID, commit kernel inventory, retire old stage-2 state, and authenticate
the new mapping. Any pre-commit error restores the old image; a failure after
irreversible kernel publication remains a carrier fault as today.

On success the runtime validates the receipt against the same MM token and
mints:

```rust
pub struct CowBroken<'mm> {
    range: MmWriteRange<'mm>,
    backend_revision: u64,
    vma_revision: VmaRevision,
    frame_inventory_revision: u64,
    owner_generation: u64,
}
```

Fields and constructors are private. `write_foreign` consumes the witness and
copies only through the newly authenticated live owner. A stale receipt, range
mismatch, revision change, or owner-generation change fails closed. Multi-page
writes produce and consume one witness per backend COW compound/chunk, which
preserves partial-transfer semantics without claiming an unbounded atomic
operation.

## Structural lock ordering

The real hierarchy needed by this work is small:

```text
MmMutationGuard (owns page-table exclusion)
    -> HostAliasPermit (minted only by MmMutationGuard)
        -> HostAliasGuard
```

`MmMutationCoordinator::begin` raises or records the existing page-table
exclusion and returns a non-cloneable `MmMutationGuard`. Its
`host_alias_permit()` method borrows the guard and returns a non-cloneable
permit. Every host-alias entry point that can coexist with stage-1 mutation
requires that permit. Constructors remain private to the owning modules.

The permit lifetime prevents dropping page-table exclusion while the alias
phase is live. There is no reverse constructor, no optional token, and no
runtime enum saying which level a caller claims. Callers that need only a
current-MM read acquire neither guard.

Existing `HostAliasDispatchGuard`, COW, mmap alias installation, rollback, and
cleanup paths migrate to the structural API. After the source gate proves no
untyped acquisition remains, `dispatch/lock_order.rs`, `LockLevel`, and their
debug-only calls are deleted.

This design does not serialize unrelated MMs globally. Each MM has its own
mutation coordinator; VM-global owner-map critical sections remain short and
inside the structural inner phase.

## Consumer semantics

### `process_vm_readv` and `process_vm_writev`

Permission and exact target lookup remain in the dispatcher. Local iovecs use
`CurrentMmMemory`; remote iovecs are token-bound target ranges. Shared-MM
targets use the current path. Foreign reads and writes stream in Linux iovec
order and return the completed byte count after a later fault. Foreign writes
require `CowBroken` for each affected chunk.

### ptrace PEEK/POKE

The existing kernel ptrace relationship remains the permission/liveness
authority. PEEK reads one target word through `ForeignMm`; POKE obtains and
consumes `CowBroken`. Invalid alignment/range keeps Linux's request-specific
`EIO`; absent targets remain `ESRCH`. HVPatch no longer returns `ENOSYS` for a
memory request it can authorize.

### `/proc/<pid>/mem`

Opening the file resolves an exact task and captures its `MmToken`. The open
description retains that token, access mode, and file offset. Reads and writes
operate on the retained MM even if the target later execs, matching Linux's MM
file reference rather than following a reused PID. Secret-memory ranges lower
to `EIO`. Existing self paths continue through the current-MM fast path.

## Errors and cancellation

Kernel minting has typed errors for missing task, retired/stale `TaskKey`,
missing backend authority, and snapshot timeout/churn. The runtime facade has
typed range-permission, translation, owner, revision, COW, and structural-lock
errors. Syscall consumers perform the final Linux mapping because the same
foreign fault is `EFAULT` for `process_vm_*` and commonly `EIO` for proc/ptrace.

Waits for page-table exclusion retain the existing bounded/cancellable policy.
No operation waits while holding the host-alias phase. Retry loops have an
explicit attempt/deadline budget and expose terminal churn rather than spinning.

## Mechanical enforcement

A monotone source checker wired into `just lint-domains` must fail on:

- direct construction or field access for `MmToken`, token-bound ranges, or
  `CowBroken` outside their owner modules;
- `GuestMemory`-only bounds in production syscall dispatch paths after the
  `CurrentMmMemory` migration;
- current-memory byte access inside foreign target arms;
- raw foreign target `(pid, mm, ttbr, va)` tuples crossing subsystem APIs;
- host-alias acquisition without a `HostAliasPermit`;
- any remaining `LockLevel`/debug validator use after deletion.

The checker has red/green fixtures, rejects stale baseline rows, and scans all
production Rust leaves. A broad `rg` census accompanies it but is not the gate.

## Verification strategy

Every behavior change is red-first:

1. Compile/source-contract tests first prove the missing token, trait split,
   COW witness, and structural permit.
2. Kernel unit tests cover exact task/MM incarnation, `CLONE_VM` relation,
   target exec, PID reuse, stale token, snapshot churn, and retained proc MM.
3. HAL/backend tests cover foreign stage-1 walks, stale table/owner generation,
   VMA permissions, multi-page partial reads, COW rollback at every phase,
   target-ASID invalidation, and stale `CowBroken` rejection.
4. Concurrency tests force target exit/exec, VMA mutation, COW, and alias cleanup
   at each validation boundary. A watchdog proves no `HostAlias -> PtPause`
   wait exists.
5. Existing and new embed probes are run red against the pre-fix signed binary
   and green against the exact post-fix artifact for `process_vm_*`, ptrace, and
   `/proc/<pid>/mem` read/write/COW cases.
6. Focused crate tests, `just lint-domains`, `just clippy`, `just doc`,
   `just test`, `just test-integration`, `just test-embed`, and the relevant
   conformance-probe filter gate each independently reviewed milestone.
7. The completion receipt records source HEAD, binary identity, cleanup, exact
   probe population, and any unchanged pre-existing host-authority drift.

## Milestones and delegation

1. **RED authority gate:** checker plus compile contracts.
2. **Kernel types:** `MmToken`, relation, ranges, VMA access, revisions.
3. **Current-MM census:** explicit `CurrentMmMemory` implementations and generic
   migration. This large mechanical chunk is suitable for Antigravity.
4. **Carrier read authority:** shared per-MM state, foreign walk/read receipts.
5. **Structural mutation authority:** `MmMutationGuard`, permit migration, and
   dead-validator deletion.
6. **Foreign COW/write authority:** transactional break-COW and `CowBroken`.
7. **Consumers:** delegate file-disjoint `process_vm_*`, ptrace, and proc-mem
   wiring to bounded Antigravity workers; Codex reviews and sends findings back
   to the same conversations before integration.
8. **Closure:** source census, repository gates, signed red/green probes,
   independent reviews, receipts, and fast-forward to local `main`.

Codex retains type architecture, COW/lock-order correctness, conflict
resolution, gate interpretation, and final integration. Worker results never
land directly on `main`.

## Rejected approaches

### Add foreign methods to the caller's engine

This keeps the original category error: a current executor remains the object
through which another MM is addressed. It also makes a target COW operate on
the caller's mutable engine state.

### Borrow or migrate onto a target executor

A target may be blocked, parked, exiting, or have no executor. Borrowing it
introduces scheduler liveness and lock cycles into a memory operation whose
authority belongs to the MM, not a vCPU.

### Raw snapshot helper functions

Passing `(MmId, TTBR, revision, VA)` tuples cannot prevent mixing generations
or applying a COW receipt to another MM. Safe authority must retain identity and
couple addresses and receipts to it.

### Keep the debug lock-order validator as a second gate

Two mechanisms drift. Once construction requires the structural permit, the
debug-only hierarchy is redundant and green-looking; it must be deleted.
