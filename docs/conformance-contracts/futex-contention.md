# Futex example

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
