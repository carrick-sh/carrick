# Kernel signal-authority atomic migration

**Status:** required for K1; implementation must replace dispatcher authority in
one cutover.

**Reason for existence:** `SyscallDispatcher::signal` currently owns Linux
signal semantics while Kernel `Sighand`, task pending, and thread signal
objects are lossy summaries. This plan moves the exact existing semantics into
typed Kernel objects without dual-writing or reconstructing an exact
`KernelContext`.

**Controlling context:** [`hybrid.md`](../../../hybrid.md),
[`2026-08-09-hvpatch-k1-kernel-object-model.md`](../specs/2026-08-09-hvpatch-k1-kernel-object-model.md).

## Non-negotiable semantics

- Dispositions are shared only through the exact `Arc<Sighand>` selected by
  clone rules.
- Process-directed pending remains task-owned and may be consumed by any
  eligible thread.
- Thread-directed pending never migrates to a sibling.
- Standard signals coalesce. Real-time signals retain count, FIFO order, and
  exact `siginfo` payload.
- Thread pending wins a same-signum tie with task pending; payload dequeue uses
  the same provenance decision.
- Masks, altstack, handler-frame nesting, restore mask, and action snapshots are
  per-thread.
- Exec preserves ignored dispositions, caller mask, and pending queues; it
  resets caught dispositions, altstack, frame, restore, and old-image action
  snapshots atomically with image commit.
- Host async handlers only publish transport records/hints and wake. Ordinary
  runtime context adopts them into Kernel queues.
- Native/VMM host-fork children consume immutable snapshots prepared before
  fork barriers; they never lock inherited mutable authority.

## Authoritative objects

```rust
Sighand {
    id: SighandId,
    actions: Mutex<ActionTable>,
    revision: ObjectRevision,
}

TaskPendingSignals {
    queue: Mutex<PendingQueue>,
    pending_hint: AtomicU64,
    revision: ObjectRevision,
}

ThreadSignalState {
    inner: Mutex<ThreadSignalInner>,
    pending_hint: AtomicU64,
    revision: ObjectRevision,
}

PendingQueue {
    present: SigSet,
    rt_counts: BTreeMap<LinuxSignal, NonZeroU32>,
    siginfos: BTreeMap<LinuxSignal, VecDeque<LinuxSiginfo>>,
}

ThreadSignalInner {
    blocked: SigSet,
    pending: PendingQueue,
    altstack: Option<LinuxSigaltstack>,
    handler_frames: Vec<HandlerFrameState>,
    armed_restore_mask: Option<SigSet>,
    pending_actions: BTreeMap<LinuxSignal, VecDeque<LinuxSigaction>>,
}
```

`LinuxSigaction` is the disposition authority. `Default`, `Ignore`, and
`Caught` are derived snapshot classes only. Queue APIs accept typed
`LinuxSignal`; raw `i32` appears only at ABI/host transport boundaries.

Hints live beside their queue. Queue mutation publishes the exact present bits
before unlocking. `false` proves empty; `true` requires lock and revalidation.
Hints never carry RT depth or payload and are never copied as semantic state.

## SignalAuthority operations

Construct the facade from one already captured `KernelContext`. It stores
exact refs to `Sighand`, `TaskPendingSignals`, and the current
`ThreadSignalState`.

Required closed operations:

- action lookup/install and ignored-mask derivation;
- mask read/update and temporary wait-mask arm/cancel;
- enqueue task/thread standard or RT signal with typed siginfo/action snapshot;
- choose and dequeue the lowest deliverable signal with task/thread provenance;
- synchronous wait/signalfd dequeue from an explicit set;
- altstack query/install and handler enter/return;
- fork/clone preparation;
- exec replacement preparation and commit;
- immutable host-fork/native-reexec snapshot and exact restore;
- coherent snapshot rows and invariant counters.

Do not expose queue locks, mutable maps, or a recapture-by-TID helper. Runtime
paths outside a syscall retain a `KernelContext`, `TaskRef`, or `ThreadRef` at
the scheduling boundary.

## Locking

Never hold registry/task locks while acquiring signal leaves. Capture refs
first. Canonical order for unavoidable nesting:

1. `SighandId` action state;
2. task pending;
3. thread signal state.

Task-vs-thread dequeue locks thread then task only long enough to choose and
remove one candidate with thread-first tie breaking. Do not hold signal locks
across guest-memory access, frame injection, host signal APIs, registry
enumeration, futex/kicker wake, or blocking waits.

Disposition host-glue changes use prepare/apply: commit `Sighand`, release its
lock, then update host transport. A host preparation failure rolls back or
terminates; it never leaves two visible answers.

## Atomic implementation waves

### Wave 1 — characterization

Add Kernel-object assertions and signed/Docker differentials for:

- process-directed blocked signal consumed by a sibling `sigtimedwait`;
- `tgkill` not consumable by a sibling;
- standard coalescing and RT FIFO/count/payload;
- signalfd provenance;
- pselect/ppoll/sigsuspend mask restoration;
- fork in handler with altstack/`SS_ONSTACK`;
- `CLONE_SIGHAND` share versus fork copy;
- exec ignored/caught reset and mask/pending survival.

### Wave 2 — typed leaf implementation

Implement queue/action/thread primitives and property tests in
`kernel/signals.rs`. This wave remains uncommitted with the later cutover; do
not populate it through a second writer.

### Wave 3 — production cutover

Move the concrete fields and methods from `dispatch/signal.rs` into Kernel
objects. Change syscall and delivery boundaries to build `SignalAuthority` from
the exact captured context. Delete in the same cutover:

- `SignalState`;
- `SyscallDispatcher::signal`;
- dispatcher pending hint atomics;
- raw backend-TID pending/mask/altstack maps;
- migrate/rekey/retire map-surgery helpers;
- count-only or disposition-only writable Kernel summaries.

### Wave 4 — lifecycle and fallback

Implement share/copy/new rules in Kernel clone transactions. Exec prepares
replacement `Sighand` and thread image state before commit and preserves task
and caller-thread pending queues. Child publication waits for exact signal
bindings.

Version native reexec state to carry ignored full actions, blocked mask, task
and thread pending queues including RT counts/siginfo, and transport identity.
Restore Kernel objects before dispatch starts.

Native/VMM host-fork paths prepare immutable signal snapshots before fork and
build child objects without inherited-lock access.

### Wave 5 — delivery, waits, and deletion

Adopt host/xsignal transport records into Kernel queues before semantic use.
Route delivery, signalfd, `rt_sigtimedwait`, sigsuspend, wait EINTR predicates,
and `/proc` masks through the facade. Publish hint before wake.

Make snapshots read only Kernel objects, sorted by typed IDs. Add typed events
for enqueue owner, dequeue owner, RT depth, handler entry/return, and fork/exec
transform.

## Verification

Structural gate:

```bash
rg -n 'struct SignalState|signal_tid_pending_hint|signal_process_pending_hint|\.signal\.lock|migrate_thread_signal_state|rekey_thread_signal_state|retire_sibling_thread_signal_state' crates/carrick-runtime/src
```

The command must return no production semantic authority outside Kernel signal
objects.

Correctness gates:

```bash
cargo test -p carrick-runtime kernel:: -- --test-threads=1
cargo test -p carrick-runtime signal --lib -- --test-threads=1
cargo test -p carrick-runtime --test integration -- --test-threads=1
just ci
git diff --check
```

Build/sign through `just build`. Run Carrick and Docker separately. Exercise
`sigwaitthread`, `forkaltstack`, `ppollunblock`, `maskfork`,
`sigtimedwaitintr`, `clone3signalflight`, `execpermitchurn`, and signalfd
probes under HVPatch, native, and VMM. The native reexec probe must block and
queue one standard plus two RT payloads, retain one ignored action, exec, then
consume all surviving state while proving caught action and altstack reset.

## Completion criteria

The cutover completes only when one Kernel object graph is the sole semantic
signal authority, exact contexts drive every operation, clone/fork/exec/reexec
matrices match Linux, host hints cannot hide queued work, coherent snapshots
and typed events contain provenance, signed fallback probes pass, and `just ci`
passes.
