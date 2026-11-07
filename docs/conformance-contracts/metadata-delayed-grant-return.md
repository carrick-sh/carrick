# Delayed metadata grant return (#1572)

The `kernel.el1.metadata-allocation` invariant includes grants that arrive
when their original allocation demand has disappeared. A carrier-wide mailbox
response can be consumed by another participant's deallocation or drain.
Admission creates an Active extent with zero live allocations. Previously,
only deallocation changed an extent to PendingReturn, so a grant that was
never allocated remained resident after drain reported no work. This explains
a missing return without a wrong-participant FREE or a lost host completion.
It is an ordering-dependent allocator lifetime defect; this reduction does
not establish which historical signed change first exposed it.

The first correction returned every empty Active dynamic extent during
ordinary mailbox servicing. That was too early: zero live allocations does
not mean the suspended allocation transaction has finished. Another
participant's deallocation, a small allocation served from bootstrap, or the
requester's own progress check can consume the grant before its large
allocation retries. Returning that capacity restarts the allocation/return
cycle instead of completing the transaction.

Ordinary return selection now handles only PendingReturn extents, which have
been completely deallocated. Fresh, unused grants stay allocatable through
ordinary mailbox progress. The explicit test-control drain retires unused
Active grants after allocation transactions finish, before publishing their
exact returns. The concurrent fixture already calls this drain after its
round-completion barrier; sequential fixtures call it after success. This is
an internal test-control operation, not an inferred global quiescence test.
Normal allocation paths may retain newly supplied capacity for later use.

Drain scans the fixed 128-descriptor table and unlinks each empty dynamic
extent's complete free block before changing it to PendingReturn. Bootstrap
and live extents remain resident. Mailbox contention retains the return for
the next ordinary boundary. Exact base, size, token and descriptor identity
still authenticate completion. No timeout, retry budget, concurrency or
parking assertion changes.

The production-path witness
`delayed_grant_consumed_by_last_deallocation_returns_both_extents` still
requires both tokens to return, now through the explicit drain. The new
`unrelated_deallocation_preserves_grant_for_waiting_allocation` witnesses a
capacity miss, host response, unrelated free and successful requesting retry.
`progress_check_and_small_allocation_preserve_waiting_capacity` additionally
checks response consumption by the production progress checker and a small
allocation from bootstrap. Both use real MetadataStorage entry points with
an injected mailbox; only zone mapping and pending-host-work marking are
omitted on the native host. Core witnesses still require exact-once return,
removal from allocatable bins, and preservation of bootstrap and live grants.

This VM-free reduction cannot prove vCPU parking, stage-2 unmapping or signed
fixture completion. Final acceptance still requires the original signed HVF
test and two consecutive main signed runs. There is no Docker comparison for
this internal allocator operation.

Signed run 41957513818's `signed-result-1`,
`steps/0f555702/el1-embed.log`, records 30-second watchdog failures for
`el1_metadata_allocator_delayed_owner_parks_participants`,
`el1_metadata_allocator_grows_and_returns_extents`, and
`el1_metadata_allocator_host_wait_requires_unmasked_irq` (also concurrent
growth). Each reports `kernel aborted: kernel abort requested for run` and
exit status 137, rather than a double-return assertion. The artifact does
not contain the referenced post-mortem directories, so it cannot establish
the precise signed blocked stacks. The native ordering witnesses are red on
the rejected head at `unrelated free returned a demanded grant` and
`progress check returned waiting capacity`. Both pass with the correction. This
attributes a real capacity-reclamation regression to the eager-return
correction; it does not establish that every NEW signed failure shares it.
The original historical attribution and two consecutive main signed passes
remain director-owned acceptance work.

The runtime host-park correction preserves the published lifecycle authority
when constructing futex, owner-memory and IPC records. The quantum borrows
its carrier's retained mapping owner and authenticates the complete parked
execution against its execution lease before resolving the exact control's
aliases. It never copies another slot's CurrentTask. The carrier keeps the
backing mappings through the lifetime of all its records. Lookup performs no
allocation, mapping, polling or wait and leaves allocator budgets unchanged.

The VM-free production owner-wait fixture checks the aliases before releasing
the editor that prevented completion. Its test-only provider retains the
real control backing at direct aliases; the host park, record allocation,
queue admission, continuation, release and reload are production operations.
This isolates alias loss at the host-park producer. It does not prove HVF
stage-2 publication, first-publication refusal handling, or the signed test's
pass population. Those remain separate from this deterministic reduction.
