# Futex example

Relative `FUTEX_WAIT` time belongs to the admitted operation, including time
spent obtaining the futex word's backing. The host syscall completion token
owns its guest-monotonic deadline through owner service and the zone's final
atomic recheck. Only the remaining duration is converted into host wait time;
scaled container clocks do not mix guest and host units. After the final
successful comparison and enrollment, the host transfers the remaining expiry
to the zone wait and retires the syscall token. Completion and cancellation
consume that token.

The EL1 adapter moves a typed relative-wait operation into the exact native
member's continuation state on a copy refusal. Service ACK leaves that custody
available for the original syscall's retry; synchronous `Redispatch` uses the
same owner without allocating a parked register save area. An admitted futex
wait transfers the expiry into its scheduler record. Terminal service failure,
a new unrelated or unserved syscall, signal-frame construction, and member or
process retirement discard the retained operation. Neither trap-frame scratch
nor user registers carry a deadline.

The two-live-thread binding
`threaded_futex_relative_deadline_survives_owner_redispatch` refuses either the
first or second atomic comparison, advances a deterministic clock one second,
and changes the original timespec. A five-second wait still has four seconds
remaining. A new completion token starts with no inherited deadline. The EL1
bindings require expiry tick 105 after admission at tick 100, whether owner
preparation parks or returns synchronous `Redispatch`. Separate episodes prove
that cancellation, unrelated syscalls and unserved futex operations release
custody before the next wait.
`futex_caught_signal_releases_owner_deadline_before_handler_wait` retains the
original post-ACK signal-frame cleanup witness without redispatching the futex
first. `futex_signal_during_owner_park_interrupts_then_starts_fresh_handler_wait` sends
SIGUSR1 from the live sibling while the original waiter is still parked on
owner service. After service ACK, the retained syscall must return errno 4
without spending its deadline. The production return checkpoint delivers the
handler, which receives a fresh five-second wait without an intervening
unrelated syscall. The host runtime binding
`serial_host_futex_deadline_survives_zone_word_recheck_owner_park` drives the
production dispatcher, refuses the final `zone_park` load, releases its owner
at virtual second one, and resumes the production job. Its resulting zone
continuation must expire four seconds later, rather than five.
Its cancellation companion sends SIGKILL while backing remains unavailable;
the production job must retire its completion token without another operand
load or guest return, and late owner release cannot requeue it.

Native admission captures a presence hint under its existing graph lock.
Ordinary syscalls with no retained futex do not acquire a second graph lock
just to discover absence; the operation itself remains solely in the member
row. Terminal service and lifecycle admission discard that owned state before
closing or retiring the member.

These VM-free witnesses establish continuation semantics and bounded work.
They do not supply signed execution or an end-to-end Docker timing ratio.

`kernel.futex.contention` is the first vertical contract. Its VM-free binding
checks exact wake cardinality, no lost wake, one continuation enrollment and
park per blocking episode, no redispatch while parked, and queue work
proportional to affected waiters rather than historical population. It runs at
1, 8, 32, and 128 waiters.

`recycled_owner_wait_record_resumes_a_completed_futex_without_an_owner_continuation`
adds an incarnation-reuse witness at the runtime residency boundary. An
owner-memory wait and a subsequent futex wait reuse the same zone record,
but only the owner wait retains a syscall continuation. Exactly one host
wake restores the futex's completed EL0 context without replay or refusal.
Allocation resets completion flags in constant work; previous owner flags
must not change the next Linux futex wait's result or require another wake.

Carrier shared-word keys compare the full `(st_dev, st_ino, file offset)` for
file mappings, or the exact host word address for direct and mirror mappings.
A hash may select a shard but cannot decide queue equality. The VM-free
`file_words_with_colliding_hints_have_distinct_carrier_queues` witness forces a
legacy hash collision and proves separate wake cardinality; the continuation
`two_live_owners_of_one_shared_word_receive_one_wake_each` witness proves that
two real waiters on one key each require their own counted wake. Key admission
uses one sharded map lookup per futex operation, with no live-waiter scan.
Shared bucket entries hold weak references and disappear when their final wait,
subscription, wake or requeue destination reference leaves. The VM-free
`ten_thousand_retired_shared_words_leave_no_live_keys_per_table` witness waits
and wakes 10,000 distinct direct and file words in each of two tables, then
requires zero live shared entries in both.

The shared table belongs to one kernel instance. Linux tasks in that kernel
must rendezvous on the same file word across fork, while two live kernels
must never consume each other's wakes even for identical `(dev, ino, offset)`
and host backing. The VM-free continuation witness
`two_kernels_with_the_same_file_word_do_not_share_wakes` enrolls B before A,
requires A's wake to reach only A, then requires zero additional waiter entries
in A while B remains enrolled. This is an exact zero cross-instance budget
under `kernel.futex.contention`, independent of timing or host process identity.
`two_shared_authorities_have_no_cross_instance_entries` exercises cloned
descendant authorities with fresh private tables at 1, 8, 32 and 128 file
words. Each table holds only its own live keys and returns to zero after
retirement. Embed host-buffer leases carry the carrier's same typed authority,
including leases minted before the first kernel root boots.

The signed binding reuses Carrick's futex probes to prove guest execution. A
separate uninstrumented release run compares the pinned futex distribution with
same-image Docker. The existing tests remain until the contract has demonstrated
equivalent or stronger failure detection.

## Futex word copy migration (#1703)

Futex operands require aligned atomic word access. The neutral `UserCopy`
interface therefore has `atomic_load_u32` and `atomic_compare_exchange_u32`,
both returning the existing `CopyOutcome`. Loads acquire; successful exchanges
acquire/release, while mismatches acquire and report the observed value as
`Done`. A refusal changes neither the output argument nor the futex word.
Byte-only providers defer atomic operands to the exact memory owner; they must
never synthesize a word from independent byte transfers.

`ValidatedCopy` implements these operations with permission checks and guarded
ISA instructions on ARM and x86. ARM exclusive accesses temporarily lower PAN
only around the guarded operand and restore it on success and fault. x86 uses
LOCK CMPXCHG with the existing task-local fixup and SMAP cleanup. Host-native
fixtures use Rust atomics, including the scheduler's hardware-word adapter.
The stopped-host x86 lane uses atomics on its retained eager aperture.

The ARM private WAIT/WAIT_BITSET path compares under the futex bucket lock.
A typed refusal releases that lock before entering the existing native
owner-memory wait. Resumption retains the original syscall arguments and
repeats comparison and enrollment under the bucket lock. Only a proven fault
may return errno 14. Address-only wakes acquire no word-read requirement.

`futex_unbacked_word_waits_for_owner_with_two_live_threads` adopts a sibling
through its first real native syscall, then withholds the waiter's physical
word once. The production dispatcher must suspend on the exact owner's Gate
notification rather than forward. After release, a changed word must fail the
original comparison with errno 11; a matching word enrolls once, one counted
sibling wake completes it with zero, and a second wake returns zero. The
fixture retains both live members throughout. The word remains unavailable until
the test explicitly supplies it after the owner refusal. Both sibling WAKE calls
also start with backing unavailable and must perform zero word reads. Physical
word availability and
the physical preparation refusal are controlled; the process graph, owner
notification, continuation and futex scheduler run their production code.
`atomic_copy_tests` additionally checks output preservation, mismatch and
successful exchange, and invalid ranges without touching an operand.

This is still a partial migration. Shared futex, host requeue and PI word
accesses remain on host dispatch and have not moved to this interface. The
stopped-host x86 lane still has no owner-memory suspension venue because its
aperture is eagerly provisioned. The futex copy-debt counter has not been
retired. Robust-futex updates remain outside this slice (#1697). Signed
execution, Docker comparison and the director's scoreboard rerun remain
required before the whole slice can be accepted.

The supplemental host-dispatch witness
`futex_wait_preserves_owner_memory_refusal_before_comparison` injects an exact
owner refusal through the production syscall entry. It was red at errno 14;
the helper now preserves the existing owner wait and redispatch compares the
available word, returning errno 11 for a mismatch. Host address-only operations
skip the unused read, while a separate shared mirror wake obtains a fresh word
before publication. The shared-pointer fallback uses an acquire atomic load.
This supplemental test proves refusal propagation, not atomicity of the direct
host read or scheduler enrollment; those remain incomplete in this slice.

### Host atomic admission boundary

The remaining host migration must retain both semantic and physical authority
through the atomic instruction. `GuestMemory::host_read` returns an optional
retained pointer, but absence does not distinguish an invalid address from an
owner that has not made backing available. `host_ptr_for_write` is only a
request: its pointer cannot be dereferenced without exact backing admission.
Neither optional pointer is sufficient to translate refusal into `CopyOutcome`.
Reading bytes first to diagnose pointer admission is also not an atomic load.

The owner-backed ARM transfer already has an authenticated effect callback.
`PreparedWrite::settle` runs `ticket.copy_requested` while the exact prepared
permit, current service loan and `TransferPin` remain live. An atomic operand
must execute inside that authorization interval, on the retained selected
backing. Extending only `PreparedGuestWrite::commit` with a byte buffer cannot
implement compare-exchange: a sibling may change the word between a prior load
and that commit. The read operand similarly needs read authority, without
requiring write permission or breaking COW merely to compare a WAIT value.

A host `UserCopy` adapter must return the existing `CopyOutcome` while retaining
any host owner receipt until the dispatch outcome takes it. `GuestCopyRequest`
identifies the requested user access; it does not replace the exact owner
incarnation, physical dependency or supply request needed by host redispatch.
The adapter must release permits and bucket locks before returning that wait.
A `NotYet` result must publish neither a loaded value nor a guest store.

PI ownership updates must compare-exchange the full observed word, including
its flag bits. Checking the masked TID and later committing bytes can overwrite
a concurrent owner or flag update. A failed exchange must re-evaluate the
observed ownership before returning success or waking a waiter. Mirror-backed
WAIT also needs separate treatment: Linux WAIT only reads its operand, so a
mandatory writeback must not introduce a write-permission requirement. These
constraints apply to the existing host paths; they do not justify a new
fallback, owner polling loop, outcome type, or an early debt-ceiling decrease.

### Neutral copy ownership (#1726 boundary repair)

The copy interface, `CopyOutcome`, `GuestCopyRequest`, and atomic refusal
helper live in `carrick_core::user_copy`. They describe neutral guest-memory
access and memory-owner preparation, rather than personality policy. Moving
the existing definitions (option b) preserves one outcome type for substrate,
Linux, ARM and x86 callers; a substrate-specific outcome would duplicate the
same protocol and require conversions. The old personality path has no
re-export shim. The existing substrate byte-copy trait remains unchanged.

This repair moves the definitions verbatim and updates imports and qualified
paths only. It changes no guest-visible semantics or work for
`kernel.futex.contention` or `kernel.memory.owner-wait`: Done completes, Fault
is authoritative, and NotYet retains the exact request for owner parking.
The boundary checker is unchanged. Existing futex refusal and atomic-copy
witnesses remain the behavioral checks.

The unchanged `check-personality-boundary --root . --metadata-file
target/cargo-metadata.json` reports 12 source violations with the original
EL1 file and scheduler sources restored, and exits 1. Restoring their neutral
copy paths makes the same checker exit 0 with 11 substrate crates clean.

### Typed record writes (#1703 debt retirement)

`UserCopy::write_val` now preserves the underlying `CopyOutcome`, including
an exact `NotYet` owner request. The helper no longer collapses refusal to a
boolean, and its bool-trait debt entry is deleted. The six existing System V
IPC consumers explicitly retain their previous `is_done` policy; this repair
does not claim to add owner suspension to those IPC operations. Their later
migration must retain operation state before waiting, especially a dequeued
message. The futex word paths and their owner-wait protocol are unchanged.
`typed_record_write_preserves_every_copy_outcome` checks the typed helper's
Done, Fault and exact NotYet propagation; the existing two-live-thread futex
witness remains the production-entry behavioral proof.

### Fork/exec successor refusal witness (#1721)

`serial_host_native_fork_exec_child_futex_retains_owner_refusal` extends the
native fork/exec fixture with a second live process. The parent waits through
production `wait4`; the child completes the exec service and uses the successor
MM. Its first private WAIT has a valid aligned address with a simulated unavailable
physical word. The dispatcher must retain the owner Gate wait, preserve the
original comparison arguments, and return errno 11 after backing becomes
available with a different value. It must never turn this refusal into errno 14
or forward the child to an unavailable host dispatcher. A subsequent raw clone
uses glibc's clone flags and native thread stock; a matching WAIT selects that
birth, whose first dispatched gettid must return its issued TID. The original
parent remains alive throughout.

This is a controlled memory-supply witness for the `UserCopy` correction carried
by prerequisite #1726. It does not execute glibc, identify the futex that caused
the reported `forkexecpthread` abort, or establish signed GNU/musl parity. The
exec reply, physical backing and owner refusal are controlled by the native
harness; the process graph, dispatcher, clone, wait queue and continuation are
production code. Actual child-futex capture and the signed census remain open.

The lifecycle order here is fork, exec, injected WAIT refusal, then raw clone.
The existing `conformance-probes/src/bin/forkexecpthread.rs` likewise execs
before creating its pthread: the fork child calls only execve or _exit, and
the replacement image calls pthread_create and pthread_join. The native
witness follows that order but does not execute pthread startup's libc futex
operations. A pass must not be reported as a `forkexecpthread` pass or as
red-first evidence for that abort. The typed-copy prerequisites are already
on the admitted main; that original witness alone adds no production correction.

To finish #1721, first run the original GNU and musl workload on current main.
If GNU still aborts, capture the child's actual in-ring futex variant, user
address, typed copy outcome and producing source location before selecting a
fix. Keep that capture distinct from the controlled `NotYet` above. Then run
the original probe through real guest execution and compare the signed census
on one identified artifact. A Linux x86_64 native fixture can
check the shared dispatcher protocol, but cannot establish that ARM/HVF result.

### Untimed realtime bitset admission in native exec children (#1721)

Node's [delayed task scheduler startup](https://github.com/nodejs/node/blob/v24.0.0/src/node_platform.cc)
waits on `uv_sem_wait`; modern glibc uses `sem_wait` through
[libuv's Unix semaphore implementation](https://github.com/libuv/libuv/blob/v1.x/src/unix/thread.c).
A bounded native Linux experiment with a live parent, exec successor and
semaphore-posting pthread observes operation 393:
`FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME`, timeout NULL and
`FUTEX_BITSET_MATCH_ANY`. A separate direct syscall in an exec successor
with word zero and expected value one returns errno 11. These experiments
use Linux libc as an oracle, without inspecting GPL implementation sources;
they are not a capture of the signed Node guest.

The [Linux futex contract](https://man7.org/linux/man-pages/man2/futex.2.html)
allows the realtime selector for WAIT_BITSET. With timeout NULL,
[WAIT_BITSET](https://man7.org/linux/man-pages/man2/FUTEX_WAIT_BITSET.2const.html)
waits indefinitely: there is no clock value to translate. The Linux policy
therefore admits this exact private variant to its existing wait owner.
It does not clear arbitrary operation flags, admit shared words under private
keys, or interpret an absolute timestamp as a relative duration.

`serial_host_native_fork_exec_child_realtime_bitset_futex_retains_owner_refusal`
extends the existing production native fork/exec witness at child-private VA
`0x40000000` in the exec successor's MM, while its parent remains alive.
The pre-fix dispatcher returned `Forward` before any `CopyOutcome` or
`MemoryError`: opcode admission rejected 393. The witness then runs production
`native_unstaged_exit`, deriving ForkChild lineage from the registered exec
successor. That final capture installs errno 38 (`ENOSYS`) with zero operand
reads. Restoring the corrected admission must eliminate that refusal.
After admission, unavailable
backing yields `CopyOutcome::NotYet` for a four-byte read and the exact owner's
Gate wait. Supply resumes the original comparison with errno 11, never errno
14. A matching wait subsequently enrolls and selects the successor's real
clone thread through its first gettid. The budget is one operand read before
owner transfer, one mismatching read on resume, and one read under the bucket lock for the
matching compare/enroll episode, with no polling or new wait ledger.

The opcode-128 witness is retained. Its context save was ported to the
scheduler's explicit `CpuExitCause::Svc` interface during rebase; its lifecycle
and copy-refusal assertions are unchanged. The earlier neutral-copy import
port is retained and the lane's evidence-only documentation remains applicable.

Shared operation 265 observed at native pthread_join, non-NULL absolute
WAIT_BITSET timeouts and PI variants remain outside this correction. Signed
Node startup and GNU/musl forkexecpthread must still run on the director's Mac;
passing this VM-free binding alone does not close the reported abort.

## EL1 wakes always finish in the ring (#1941)

Linux `FUTEX_WAKE` never fails for lack of a place to run a waiter: it wakes
up to `count` eligible waiters and returns how many it woke. EL1 used to
refuse a wake as a whole when one waiter could only run where EL1 could not
queue it (`Unplaceable`) or parked on several futexes (`MultiEntry`), and the
futex family then forwarded the call for the host to serve. A ring-owned fork
child has no host task, so the final capture answered that forward with a
counted ENOSYS. Guests ignore a wake's return value, so the waiter slept
forever: `el1_sched_two_processes_share_vcpus` hung 10 of 10.

`ZoneTables::wake_placed` now has no refusal. A waiter whose allowed CPUs are
all busy is queued on the least loaded of them with a reschedule SGI, the
choice the host's `place_in_guest` makes. A waiter no guest slot may run
(its only slot stopped at a host exit) is queued on the waker's own slot and
reported misplaced; the waker's host exit relocates it. A `futex_waitv`
waiter, which only the host parks, is claimed into a transfer, its woken entry
is unlinked under the bucket lock, and it goes to the carrier completion
chain; the host boundary the waker then owes unlinks its other entries and
hands it to its continuation with the index that fired. `wake_word` and the
Linux `FutexVenue::wake` return a `Served`, so a decline cannot be written.
The final capture treats a forward of an admitted private futex wake
(`FUTEX_WAKE_PRIVATE`, `FUTEX_WAKE_BITSET_PRIVATE`) from a task with no host
route as `EntryBindingFatalReason::OwnedFamilyForward`, never a counted
ENOSYS. Only wakes are guarded, because only a wake is guaranteed to finish
in ring. An admitted wait may still decline: a switched-in fork child's timed
`FUTEX_WAIT_PRIVATE` (timed waits are not admitted there) and an untimed wait
that finds the futex-entry pool exhausted both return no completion. Such a
decline, like an unported futex operation, keeps the counted ENOSYS, exactly
as on main.

Witnesses:

- `forked_child_futex_wake_reaches_a_waiter_pinned_to_a_busy_vcpu` (red on
  main `fa3f74317`: `exit Refused(Served), x0 -38`): a real root and fork
  child through `dispatch_arm_syscall_with_native_process` and
  `native_unstaged_exit`; the child's wake returns 1 and queues the pinned
  waiter on its busy vCPU with one SGI.
- `an_el1_futex_wake_always_finishes_in_ring`: busy pinned, stopped pinned and
  two-futex waiters, each served by `wake_word`.
- `native_fork_child_futex_wake_forward_is_an_invariant_break`: the typed
  fatal for admitted wakes; ENOSYS for an admitted wait's forward and for
  `FUTEX_REQUEUE`; the host route for a root.
- `forked_child_timed_futex_wait_decline_stays_a_counted_refusal` and
  `forked_child_futex_wait_on_an_exhausted_entry_pool_stays_a_counted_refusal`
  (red on `38fc414d5`: `OwnedFamilyForward`): a real fork child's declined
  waits through `dispatch_arm_syscall_with_native_process` and
  `native_unstaged_exit` stay `Refused(Served)` with one counted refusal.
- `carrick-sched-core`: `el1_queues_a_pinned_thread_on_its_busy_cpu`,
  `el1_honours_affinity_for_floating_threads`,
  `el1_hands_a_multi_entry_waiter_to_its_host_continuation` and
  `unplaceable_parent_is_woken_once_in_ring`.

A wake's placement reports what the waker still owes in `WakeEffects`:
reschedule kicks for busy slots that took a waiter, a queue stamp and slice
for a thread queued on its own slot, and a host boundary for a misplaced or
host-handed waiter. One ISA-neutral applier, `WakeEffects::apply` in
`carrick-sched-core`, consumes them for every waker. ISAs lend only their
mechanics through `WakeMechanics`. ARM's `Sched` lends an SGI by the slot's
target, the virtual counter, its slice timer and the task's host-work
doorbell. The x86 CPL0 lifecycle lane's `NativeLane` lends a reschedule IPI
by the slot's APIC route, the TSC and the same doorbell. x86 CPL0 has no
run-queue slice timer, so a thread queued on the waker's own slot gets a
reschedule kick to that slot, as the production process owner already does.
ARM's `Sched::wake_word`, `Sched::finish_object_wake`, x86
`NativeLane::wake_word` and the lane's child-exit `CHILD_WAIT_KEY` wake all
call it. The x86 lane used to drop its effects: a waiter queued on a busy
slot was never kicked, and a misplaced waiter owed the host nothing.

x86 witnesses (host tests of `PendingFamilies::futex` for `NativeLane`, red
on PR head `adb6aec667`):

- `native_futex_wake_queues_a_waiter_pinned_to_a_busy_cpu_in_ring`: the wake
  completes in ring, queues the waiter on its busy slot and sends one kick
  (`el1_sgis`, was 0).
- `native_futex_wake_of_a_waiter_on_a_stopped_cpu_owes_a_host_boundary`: the
  waiter's only CPU is stopped; it is queued misplaced on the waker's slot
  and the waker has pending host work (was false).

The lifecycle wait-channel wake crossing (`cross_wait_channel_wake`, HVC
`GRANT_OP_WAIT_CHANNEL_WAKE`) has no guest caller left; retiring its host
handler is follow-up work. The signed end-to-end check (the two-process test
from 0/10 to 10/10) is outstanding, and the separate `entry_binding` fatal at
`arm_signal_user_return` may still end some signed runs of that test.
