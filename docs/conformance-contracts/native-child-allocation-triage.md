# Native child allocation triage (#1505)

The reported nineteen signed generic-probe allocation failures have not been
reproduced by the VM-free native suite on the admitted main. This note records
the limits of that result; it is not an allocation fix or acceptance evidence
for those probes.

## VM-free result

`just test-el1-native` completed with 725 passed, zero failed and one ignored.
In particular, these existing witnesses passed:

- `native_fork_child_first_allocation_and_thread_admission`
- `native_child_fixed_over_cow_preserves_parent_bytes_and_retires`
- `owner_munmap_then_mmap_null_places_outside_owed_return_in_ring`

The first witness forks through `arm_call_with_cpu`, selects the actual child,
and grows its break from 4096 to 5120 and reserves a 64 KiB anonymous mapping.
The parent's break remains 4096. Its allocation calls enter
`serve_delegated_anonymous` directly, rather than the entire syscall pipeline.
Consequently it proves the shared memory engine for that fixture, not a Rust
allocator running in a guest or the production entry's complete routing.

The ignored `anonymous_reservation_first_touch_service_budget` was also run
explicitly. It fails with 64/256/1024 backing requests for 64/256/1024
reservations, against the required incremental slope below 1/8. Its existing
ignore names #898. This is a structural-budget failure, not a reproduction of
the small-allocation refusal, and must not be represented as a green contract.

## Where to classify a reproduction

The applicable surface is `kernel.el1.anonymous-reservations`. Linux `brk(2)`
and `mmap(2)` define the allocation semantics. Carrick's invariant is exact-MM
reservation and backing authority, with bounded work and no host syscall
fallback for a ring-owned child.

`carrick-el1/src/memory.rs::serve_delegated_anonymous` counts its refusal before
returning `Forward`. Relevant classes are:

- `RootUnavailableMetadataRequired`: reservation metadata cannot be secured.
- `RootUnavailableBusy`: the reservation decision reports contention.
- `BackingHostOwnedLeaf`: a live leaf has no EL1-private tag.
- `BackingBlock`: the live walk reaches an L1/L2 block.
- `BackingRetired` and `JournalFull`: backing return or journal custody.

Other existing classes distinguish root admission/commit, descriptor editing,
malformed backing and multiple backing runs. The signed test helper
`anonymous_leaves_breakdown` already gives every class a readable name.
No counter observations from the nineteen failing probes were available in
this checkout; the list above is a classification guide, not their measured
failure population.

The public #1501 report names `accessx`, `acceptsock` and `fdceiling` as
examples, but does not enumerate all nineteen or include their anonymous-leave
counts. `accessx` and `acceptsock` allocate C strings without forking in their
own `main`. Their native identity can therefore come from the harness's
fork/exec, and a reduction must cover an exec successor as well as a fork-only
child. The passing first-allocation witness above does not exercise exec.
The shared successor planner already marks hidden heap backing lazy and leaves
it without reservation nodes until `brk` grows; its existence alone does not
prove the observed successor's actual descriptor graph.

The root and child differ at the final unclaimed-syscall boundary:
`carrick-el1-linux/src/dispatch.rs::unclaimed_native_syscall` retains the host
route for a root, but returns counted ENOSYS for a fork child, which has no
host task. Thus a memory engine refusal can become an allocation failure only
in the child while the root still has a serving venue. This explains the
authority distinction, but does not identify which refusal the reported
probes reached. Changing that boundary to forward child calls would violate
the ring-first contract.

## Remaining evidence

Resume with the nineteen probe names, fixture identities and both raw streams,
including anonymous-leave counts, from #1501. Reduce the first measured refusal
through the production-entry harness with the parent and child both alive.
Capture a red witness before changing reservation, descriptor or backing
authority. Then prove the correction on both ISAs and rerun the original
nineteen probes on one signed artifact. The Linux runner cannot supply the
macOS/HVF signed proof.
