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

## Futex word copy prerequisite (#1703)

The typed `carrick_core::personality::UserCopy` byte-transfer interface from
#1691 does not guarantee single-copy atomic word access. Its ARM adapter uses
`file::ValidatedCopy`, whose guarded transfers loop over individual bytes.
Those transfers cannot replace `HardwareUserWord::read_u32`, which uses one
guarded 32-bit load: another live thread may change the futex word concurrently.
Four independently loaded bytes can form a value that neither thread stored.

Before migrating futex words, the shared copy contract needs explicit aligned
32-bit atomic access returning the existing `CopyOutcome`. ARM and x86 must
retain their ISA word accesses; no second refusal type or byte-copy wrapper
can substitute for that guarantee. A `NotYet` result must leave the bucket
lock before entering the existing owner-memory wait, then repeat the value
comparison and enrollment together under that lock. Only a proven fault may
return errno 14. Address-only wake operations must not acquire a word-read
requirement.

The x86 stopped-host `NativeLane` currently treats `wait_guest_copy` as an
invariant failure because its aperture is eagerly provisioned. It needs an
owner-memory suspension adapter before it can accept `NotYet`. Shared futex,
requeue and PI word accesses also use host dispatch rather than the private
in-ring scheduler; migrating only that scheduler does not cover those calls
or retire the host futex copy-debt entry.

This prerequisite analysis supplies no red/green execution witness. The
two-live-thread, unbacked-word witness and signed acceptance remain required;
the futex word migration is not implemented by this note.
