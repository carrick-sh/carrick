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
`futex_caught_signal_releases_owner_deadline_before_handler_wait` sends
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
