# Native short-lock contention (#233, part of #236)

Base: GitHub main b97e124c17b4ce0dd9a60d2ed22f81e8fa6c86d1.
Contract: process.native.short-lock (docs/conformance-contracts.md).
Host: x86-w1, Linux x86_64, no Docker or HVF.

## Red-first evidence

The red commit is 6e21d50bc. Tests hold all 1024 buckets until the
wait-policy probe reaches 100000 contended acquisitions. The fixture uses
no elapsed-time lock-release deadline, random collision, load generator,
or guest retry. Completion/unwinding also releases fixture guards.

Commands (foreground):

- `cargo test -p carrick-el1 --lib bucket_contention -- --nocapture`
  exits 101: four failures. msgrcv and semtimedop return Err(-11);
  normal exit reports NativeQuarantined; signal exit returns Quarantined.
- `cargo test -p carrick-el1 --lib pending_default_stop_does_not_interrupt_wait4 -- --nocapture`
  exits 101: wait4 returns -11.
- An initial attempt exited 101 on a fixture Debug formatting compile
  error; it is not counted as red semantic evidence.

## Re-entry and wait ownership audit

x86 SYSCALL clears IF through SFMASK (carrick-hal/src/x8664_arch.rs).
Native IRQ gates retain masked IF until IRETQ (native_irq.rs).
Native execution's STI/HLT/CLI idle boundary follows enrollment and
guard release. The entry.rs STI terminal fault witness is fixture-only
and retains no scheduler bucket. Kernel user-copy faults use their
fixup; other kernel faults fail loud. These are not nested enrollment.
ARM El1IrqMode and vector tests keep IRQs masked throughout EL1,
including WFI (carrick-mem/src/memory.rs).

The x86 timer IRQ may inspect a scheduler wait, but its expiry path uses
bounded acquisition, retains the ticket, and rearms on contention.
That is an explicit deferred operation, not a guest error. It must not
be converted to an infallible wait that could interrupt its own holder.

Native entry paths release graph custody before bucket acquisition.
Enrollment drops the bucket before a scheduler switch. Wake publication
drops graph custody first. Cancellation runs after exit graph publication.

## BoundedSpin audit

Converted:

- native_process_runtime.rs: signal/child/IPC/pending-exit enrollment,
  committed wake publication and member cancellation use NativeBucketWait,
  an infallible ShortLockWait retaining the contention probe.
- carrick-core/src/entry.rs: authenticated retirement uses ShortLockSpin;
  genuine stale/ownership refusal remains distinct. Removed the obsolete
  spin-budget argument and updated callers.
- carrick-core/src/wait.rs: observe, park and notify object queue locks use
  ShortLockSpin; removed caller spin budgets. Queue generation, changed
  predicates and capacity failures remain meaningful errors.
- carrick-el1/src/sched.rs: futex bucket contention no longer refuses the
  syscall path into a host crossing.
- personality/ipc.rs EL1_WAIT: fd table and object-queue binding use the
  short-lock policy. FD backing allocation occurs outside table locks
  (carrick-fd-core SlotBacking contract), so these do not wait for a vCPU.
- carrick-el1/src/alloc.rs: metadata queue binding uses ShortLockSpin;
  contention cannot masquerade as failed metadata request admission.

Retained:

- personality/file_table.rs: both BoundedSpin uses are test setup only,
  with uncontended buckets; production uses FD_MAP_LOCK instead.
- native_process_runtime.rs: remaining BoundedSpin uses are fixture setup
  and deterministic probe thresholds only.
- personality/ipc.rs ObjectLockWait (not BoundedSpin): an EL1 object holder
  is waited for; a host object holder may wait for this vCPU to stop.
  Refusal preserves the owned IPC operation and crosses for settlement;
  it does not publish contention as guest EAGAIN. Keep the holder-aware
  policy. Its separate Finish wait settles an already retained backing.
- carrick-sched-core placement: optional peer-slot acquisition falls back
  to the waker's own queue; nonblocking placement retains wake ownership.
- carrick-sched-core migrate_queued: a busy destination retains/requeues
  the source record; it is an optional placement optimization.
- carrick-sched-core expire_timer: owns the ticket and rearms on a busy
  bucket; explicit IRQ deferral as described above.
- carrick-sched-core steal_from: a busy peer queue declines only that
  optional steal; ownership and queued work remain at the victim.

No crossing.rs rows or census host-fallback rows changed.

## Verification

Final commands and exit codes will be recorded after gates.

The director's #231 owner decision superseded the requested three local
KVM passes: KVM evidence now comes from the merge-queue lane.
A shell retained its old script inode and entered the first `just test-kvm`
compilation despite the cancellation edit. That exact runner and all of
its descendants were terminated with SIGTERM before guest tests executed.
The second and third passes did not start. No stability or NEW/FIXED
comparison against #236 is claimed here. The merge queue must supply that
receipt. Local `just accept --profile linux-portable` would start KVM and
is therefore not run under the revised owner policy.

The first standalone domain lint reached live compiler discovery but
exited 137 while duplicate lint compiler profiles overlapped. The older
duplicate and orphaned compiler trees were explicitly terminated (143).
This is infrastructure interruption, not a semantic red witness. CI runs
the same gate in isolation, without changing budgets or concurrency.
Signed HVF and Docker ratio measurements are unavailable on this host.
