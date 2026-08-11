# HVPatch K1 kernel object model

**Status:** K1 implementation design  
**Parent:** [`hybrid.md`](../../../hybrid.md)  
**Prerequisite:** K0 memory-HAL GO at source commit `abe7bd74`

## Purpose and phase boundary

K1 gives Carrick typed, independently testable Linux object interfaces while
adapting the working one-HVF-VM prototype behind them. It establishes identity,
ownership, lock order, sharing rules, rollback contracts, coherent snapshots,
typed events, and executable gates.

K1 does **not** replace process banks, implement global frame allocation or
persistent page tables (K2), cut fork/clone/wait over to the kernel-native
transactions (K3), make exec transactional (K4), or replace scheduling and
synchronization (K5). The K1 model defines the contracts those phases consume.
The prototype remains the only implementation during K1; there is no second
compatibility path.

Each authority moves once. A temporary adapter may expose an existing authority
through a typed interface, but it cannot duplicate state or accept writes. When
an authority is extracted, its former field and adapter are deleted in the same
commit.

## Invariants

1. One `Kernel` object graph describes one HVPatch VM.
2. Linux TGIDs and TIDs share one reservation namespace.
3. Stable object identity is allocated, not derived from a pointer, host PID,
   fd, IPA, guest VA, or container index.
4. A syscall captures one coherent set of current object references.
5. Object-lock guards are never held across HVF, Mach, host I/O, thread
   creation, blocking waits, or callbacks into another subsystem.
6. K1 operations either leave the typed model equivalent to its pre-operation
   state or publish one typed outcome. No partial snapshot is success.
7. ASID/backing retirement requires a proof-bearing HAL interface; the current
   prototype's self-acknowledgement remains explicitly RED until K3 cuts over.
8. Debug records are sorted, pointer-free, versioned, bounded, and internally
   joinable by typed IDs.
9. Native and VMM retain their current execution paths. Shared syscall code
   receives the same kernel vocabulary from a one-task adapter, not an optional
   or untyped legacy context.
10. K1 does not claim K2–K5 correctness or performance.

## Linux identity domains

`crates/carrick-runtime/src/kernel/ids.rs` owns runtime object IDs:

```rust
pub struct TaskId(NonZeroI32);       // Linux TGID / process identity
pub struct LinuxTid(NonZeroI32);     // guest-visible schedulable task ID
pub struct TaskSerial(NonZeroU64);   // never reused by one Kernel
pub struct ThreadSerial(NonZeroU64);
pub struct MmId(NonZeroU64);
pub struct FileTableId(NonZeroU64);
pub struct FileDescriptionId(NonZeroU64);
pub struct FsContextId(NonZeroU64);
pub struct SighandId(NonZeroU64);
pub struct ProcessGroupId(NonZeroI32);
pub struct SessionId(NonZeroI32);
```

Cross-runtime/backend IDs live in the dependency-neutral
`carrick-hal::kernel` module so `carrick-runtime` and `carrick-vmm-hvf` cannot
form a dependency cycle:

```rust
pub struct FrameId(NonZeroU64);
pub struct MappingId(NonZeroU64);
pub struct KernelTransactionId(NonZeroU64);
```

The existing `carrick_hal::ThreadId` remains a process-local registry key. It is
not silently reinterpreted as `LinuxTid`; boundary code carries both until the
registry is migrated. `Asid` moves from the private HVPatch module into the
kernel vocabulary. New typed `Stage1Root` and `Ttbr0` wrappers validate address
alignment and ASID composition at construction.

`TaskId` and `LinuxTid` have allocator/ABI-specific constructors, not public
general `from_raw`. The root adapter preserves the prototype's observed PID via
`TaskId::for_root_bootstrap`; changing PID namespace policy is separate work.

One `IdRegistry` reserves leader TGIDs and non-leader TIDs. Reservations include
live, preparing, exiting, and zombie records. Numeric claims also remain held by
live `ProcessGroup` and `Session` objects after a leader exits or is reaped.
Wraparound cannot reuse a number still referenced in any of those domains.

## Object graph

The controlling concepts remain `hybrid.md`'s `Task` (Linux process) and
`Thread` (execution context):

```text
Kernel
 ├── Registry
 │    ├── live/exiting TaskRef
 │    ├── compact Zombie records
 │    ├── ProcessGroup and Session records
 │    └── preparing-operation reservations (not externally discoverable)
 ├── IdRegistry
 ├── FrameInventory
 └── DebugPublisher

Task
 ├── TaskKey { TaskId, TaskSerial }
 ├── parent/children, process group, session, exit/wait state
 ├── atomic Arc<TaskShared> { Mm, Sighand, task-pending signals }
 └── ThreadRef set

Thread
 ├── LinuxTid, existing registry ThreadId, ThreadSerial
 ├── weak TaskRef / stable TaskKey
 ├── Arc<ThreadResources> { FileTable, FsContext, Credentials }
 ├── mask, thread-pending signals, altstack, TLS/register/run state
 └── backend vCPU binding
```

Linux permits `CLONE_THREAD|CLONE_SIGHAND|CLONE_VM` without `CLONE_FILES` or
`CLONE_FS`, and credentials such as fsuid can differ per thread. Therefore files,
fs context, and credentials are referenced by `Thread`, not assumed uniform in
a thread group. A `Task` owns the mm/sighand association required by
`CLONE_THREAD`; separate tasks may still share those objects through legal
`CLONE_VM`/`CLONE_SIGHAND` combinations.

Parent/child links and thread/task back-links use stable keys or `Weak`, never
mutual strong `Arc`s. Epoll interest edges and pidfd targets use stable IDs plus
weak registry lookup; no `FileDescription -> FileDescription` or
`FileTable -> Task -> FileTable` strong cycle is allowed. Model tests cover
self/nested epoll rejection and pidfd teardown.

A zombie is a compact record containing task key, parent/group/session keys,
status, rusage, and diagnostic identity. It does not retain `TaskShared`,
threads, files, or signals. Detached task/mm objects are reclaimed only after
runners and in-flight kernel references drain.

## Kernel context

Shared syscall entry receives:

```rust
pub struct KernelContext {
    pub kernel: Arc<Kernel>,
    pub task: TaskRef,
    pub thread: ThreadRef,
    pub shared: Arc<TaskShared>,
    pub resources: Arc<ThreadResources>,
}
```

The references are captured once at dispatch entry. A handler cannot combine an
old mm with new files or credentials. Native and VMM construct a one-task object
graph using their existing process state; HVPatch constructs the multi-task
graph. `KernelContext` is mandatory, never `Option<...>`.

## Sharing rules

| Operation | Mm | Sighand | File table | File descriptions | Fs context | Credentials | Pending |
|---|---|---|---|---|---|---|---|
| plain fork | new logical mm, prototype snapshot | copied | copied | shared | copied | copied value | child queues clear |
| `CLONE_VM` | shared | shared only with legal flags | by `CLONE_FILES` | shared through slots | by `CLONE_FS` | copied then per-thread | new thread/task queues |
| `CLONE_THREAD` | shared | shared | independently selectable by flags | shared through slots | independently selectable | per-thread reference/value | task queue shared, thread queue new |
| exec contract | replacement at K4 commit | caught handlers reset at K4 | caller table with CLOEXEC staging at K4 | surviving descriptions retained | retained | changed only by Linux credential rules | Linux-prescribed preservation |

K1 characterizes the existing prototype against this matrix and exposes named
`CloneSharing` policies. K3 performs the production fork/clone cutover. K4
performs the exec commit; K1 keeps the current destructive exec explicitly RED.

## Memory and frame interfaces

K1 gives mm identity to the current bank mechanism without making banks part of
the public contract:

```rust
pub struct MmBinding {
    pub asid: Asid,
    pub stage1_root: Stage1Root,
    pub ttbr0: Ttbr0,
}

pub trait MmBackend: Send + Sync {
    fn binding(&self) -> MmBinding;
    fn vma_summaries(&self) -> Result<Vec<VmaSummary>, SnapshotError>;
    fn mapping_ids(&self) -> Result<Vec<MappingId>, SnapshotError>;
}
```

The sole HVPatch K1 implementation is `hvpatch/banked_mm.rs`. K2 replaces and
deletes it; there is no runtime selection enum or feature flag.

Frame observation requires a HAL-level inventory sink because authoritative
mappings live in `carrick-vmm-hvf`, not the dispatcher. The K1 adapter assigns
one stable `FrameId` to each exact sparse host-backing extent and one
`MappingId` to each logical stage-2 alias extent. A frame summary has zero or
more typed IPA aliases—it never assumes one backing has one IPA. `FrameLength`
carries the checked extent length; shared host backing plus offset reuses
`FrameId`, while a copied backing gets a new ID. Host addresses never cross the
sink.

This extent granularity is a deliberate K1 phase boundary. A current HVPatch
process bank is a sparse 40 GiB mapping: expanding it eagerly would create
2,621,440 16 KiB records and more than 5.2 million prepare/publish events per
birth, violating both the 262,144-event batch cap and the 16 MiB debug-response
cap while adding work proportional to sparse virtual extent. K2 remains RED for
replacing those sparse extents with demand-materialized 16 KiB compound-frame
records in the global `FrameTable`; K1 must neither pretend the sparse pages are
materialized nor pull that memory-mechanism replacement forward.

`carrick-hal::kernel` also defines the pointer-free `FrameInventoryEvent` and
owned `FrameInventoryBatch` contract. The backend records prepare, publish,
permission-change, unmap, and retire events into an operation-local batch while
holding backend locks. It performs no callback into runtime and touches no
kernel-object lock. After the topology/stage-2 lock is released, the engine
returns the batch with the operation result; runtime then validates and applies
it under the frame-inventory lock. A failed or rolled-back operation discards
its unpublished batch. Every event includes `KernelTransactionId` and mapping
generation so publication or rollback affects only that operation.

## File and I/O authority map

K1 does not delete the whole current `IoState` as one step. Its fields move as
follows:

- `FileTable`: open fd slots, next-fd cursor, bare-stdio descriptor state,
  fd-open paths, nofile limit, epoll table/index/wake registry, io_uring and AIO
  namespaces, splice pushback;
- `FsContext`: cwd and chroot root;
- `RuntimeIo`: stdout/stderr buffers and stream mode.

`FileTable` slots own `Arc<FileDescription>` with stable
`FileDescriptionId`. Plain fork copies slots/descriptor flags while sharing
descriptions; `CLONE_FILES` shares the table. Explicit logical reference counts
must match reachable slots after rollback and teardown.

Before extraction, table-driven tests characterize every `IoState::fork_clone`
field. `KernelContext` is threaded through all dispatch entry points before any
field moves. Each authority is then cut over and its old field deleted in the
same commit.

## Signal authority

The current signal state splits into:

- `Sighand`: dispositions;
- task-directed pending state;
- thread mask, pending state, altstack, and handler-frame state.

Fork copies dispositions and caller thread state but clears child pending
queues. Legal `CLONE_SIGHAND` shares dispositions. Exec behavior remains a K4
commit concern but is modeled now: ignored dispositions, masks, and pending
signals survive as Linux requires; caught handlers and old-image altstack/frame
state reset.

## Locking and operation reservations

Lock nesting order is registry, one task, then one leaf object. Two tasks order
by `TaskSerial`; two file descriptions order by `FileDescriptionId`. Registry
lookup clones a ref and releases the registry before ordinary task access.
Snapshot collection never nests leaf locks.

**Backend/topology locks are not in this order because they may never nest with
kernel-object locks.** A multi-stage operation uses:

1. lock task briefly, install a typed operation reservation and capture object
   revisions, then unlock;
2. prepare HVF/Mach/thread/host resources under backend locks only;
3. reacquire registry/task locks, validate reservation and revisions, perform a
   short in-memory publication or reject/retry;
4. release object locks before waking a child or invoking the backend.

A test-only rank checker detects object-lock inversion. Every snapshot lock uses
deadline-aware `try_lock`; no diagnostic worker can block indefinitely behind a
wedged guest.

## Rollback contracts and phase ownership

K1 defines and property-tests non-cloneable reservations and typestate results:

```text
ReservedOperation -> PreparedOperation -> PublishedOperation
                  \-> RolledBackOperation
LiveTask -> RetiringTask -> Zombie
```

An operation owns all reservations until publication. `Drop` rolls back only
unpublished model/HAL-preparation resources. Publication is an infallible
in-memory registry transition; host work and guest-memory copyout are not part
of it.

The production atomic fork protocol is K3. Its K1 contract requires:

- child-thread-owned copyouts complete on the child host thread before its
  readiness acknowledgement;
- parent copyout ranges are protected by the K3 generation/permission barrier;
- parent copyouts occur while the child remains undiscoverable, with original
  bytes retained for rollback;
- failure terminates the unpublished child and restores parent bytes before
  releasing the barrier;
- commit publishes registry/pidfd state and then opens the start gate, with no
  copyout or blocking wait.

K1 tests this protocol in the reference model and failpoint harness. It does not
claim the current `quiesce.rs` order has been replaced; K3 owns that cutover.

Retirement similarly defines a non-forgeable `TlbRetirementProof`, but the K1
prototype adapter may not use it to authorize ASID reuse until a signed
multi-vCPU qualification proves every participating vCPU acknowledgement. The
current self-acknowledging `publish_exit` remains a named K3 blocker.

## Coherent snapshots

`Kernel::snapshot(deadline)` returns owned `KernelSnapshotV1` tables for task,
thread, mm, VMA, frame/mapping, fd/description, fs, credentials, process group,
session, and signal state.

Every mutable object has a revision counter incremented with release ordering at
each publication. Registry epoch covers membership and zombie/group/session
changes. Draining objects remain explicitly classified until their last strong
reference disappears.

Algorithm:

1. acquire the registry with a bounded `try_read_until`, copy sorted refs and
   epoch, then unlock;
2. acquire at most one object with bounded `try_lock_until`, copy values and
   revision, then unlock;
3. reacquire the registry before the same deadline and verify epoch/membership;
4. verify all revisions, retry at most three times within the request deadline;
5. return `Busy`, `TimedOut`, or `InvariantViolation`, never partial data.

## Live debug protocol

The runtime publishes a Unix socket at
`$TMPDIR/carrick-kernel/<uid>/<sha256(CARRICK_RUN_ID)>/snapshot.sock`. Parent
directories are mode 0700, the socket is mode 0600, stale entries are rejected
unless their recorded owner PID is dead and run token differs, and paths never
contain raw run IDs.

The server accepts only a peer whose effective uid equals the runtime uid using
a new fallible `peer_credentials` host API. Best-effort zero credentials are
rejected. Requests are at most 4 KiB; canonical JSON responses are at most
16 MiB; both sides use a two-second deadline and length-prefix framing. The CLI
turns connect/read deadline expiry into a named timeout even when the runtime is
wedged.

`carrick debug hvpatch-kernel --run-id <id> [--table ...]` parses the shared
versioned DTO and fails on unknown schema, missing table, duplicate ID, broken
join, partial frame, or trailing bytes.

## Sequenced event ring and typed CTF

The ring is bounded history, not snapshot authority. Each slot uses an odd/even
generation protocol:

1. writer CAS-publishes a unique odd generation (busy/incomplete);
2. writer stores payload;
3. writer release-publishes the matching even generation (complete);
4. reader acquire-loads generation, rejects odd, reads payload, acquire-loads
   again, and accepts only equal even values matching the expected logical
   index.

A global monotonically increasing reservation index prevents two delayed writers
from publishing the same generation after wrap. Readers report overwrite, gap,
unknown kind, or torn/busy slot as errors.

Typed events in `carrick-observability` carry transaction ID, task key,
thread/TID, mm ID/ASID where applicable, phase, and outcome. Scalar USDT is only
the wire boundary. DTrace, Rust, CLI, and LLDB consumers update atomically.

A separate authenticated process-wide VM ledger records create attempt, create
success, stable VM serial, destroy, and terminal run identity. The K1 lifecycle
validator requires exactly one successful creation, no second attempt, matching
teardown, zero DTrace drops, zero ring gaps, and matching source/binary/program
provenance. A bounded ring alone is never the complete-workload authority.

## Migration sequence

1. Add typed IDs, group/session claims, reservations, and conversion tests.
2. Introduce mandatory `KernelContext` at shared dispatch entry for all three
   backends; replace `ProcessContext` with a `TaskRef` in the same HVPatch
   cutover, without extracting dispatcher fields yet.
3. Rename/refactor `ProcessTable` into the sole prototype registry and expose
   typed task/thread/mm/group/session snapshots; preserve runtime behavior.
4. Add operation/failure models, lock-rank tests, and direct regressions for
   TTBR mutation, ID reuse, resource-reference rollback, and snapshot joins.
5. Add the HAL frame-inventory sink and HVPatch implementation.
6. Extract `FsContext`, `FileTable`, credentials, and signal authorities one at
   a time after context access exists; delete each old field on cutover.
7. Add coherent snapshot DTO/server and `carrick debug` readers.
8. Replace the ring protocol and add typed CTF/VM ledger plus strict Rust
   lifecycle parser.
9. Run model/failpoint tests, a bounded live snapshot smoke, exact signed
   68/67/69 lifecycle capture, and `just ci`; publish K1 evidence.

K3 then replaces prototype fork/clone/wait/exit with the already-tested
transaction contracts. K4 replaces destructive exec with the candidate-mm
contract. No K1 evidence may claim those later gates.

## K1 gate

K1 is GO only when:

- generated model tests cover legal/illegal clone sharing, per-thread files/fs/
  credentials, signals, group/session lifetime, wait/zombie behavior, stable ID
  reservations, epoll/pidfd cycle prevention, and modeled exec identity;
- every K1 model/adapter failpoint returns resource/reference/ID counts to its
  pre-operation snapshot and emits rollback without a false commit;
- all shared dispatch paths carry mandatory coherent `KernelContext` objects;
- live debug reads task, thread, mm, VMA, frame/mapping, fd/description, fs,
  credential, group/session, and signal tables from one coherent snapshot and
  fails closed on timeout/corruption;
- the event ring rejects busy/torn slots, gaps, overwrite, and unknown kinds;
- the HAL frame inventory has no host addresses and all mappings join one frame
  and mm identity;
- a signed multi-vCPU retirement probe records the acknowledgement set needed
  for future `TlbRetirementProof` use (failure keeps the K3 retirement path RED);
- a bundled Rust-validated lifecycle profile binds canonical image digest,
  fixture argv/env, exact stdout bytes/hash, expected empty stderr hash, timeout,
  source/binary/program hashes, CLI/root exit status zero, zero drops, one VM,
  68 fork commits, 67 exec commits, and 69 unique births; every non-root birth
  has exactly one terminal exit, the root has exactly one successful run
  terminal, and the final live set is empty (or root-only immediately before
  that terminal);
- `just ci` passes on the exact implementation commit;
- durable K1 evidence reports both GO scope and remaining K2–K5 RED gates.

No performance claim is required for K1.
