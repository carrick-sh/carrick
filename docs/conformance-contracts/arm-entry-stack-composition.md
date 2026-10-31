# ARM entry stack composition

`kernel.el1.signal-delivery-owner` and `kernel.el1.thread-lifecycle` also bind
compiled ARM entry-chain stack envelopes. The image build includes the vector
record and nested descriptor, copy, notification and allocator frames in a
12 KiB budget on the unchanged 16 KiB per-CPU stack. Signal encoding borrows
and fills admitted storage; native contexts and retained aggregate results use
heap custody. See [the stack contract](../el1-stack-budget.md) for the exact scope
and remaining #369 work. The existing anonymous mapping retirement signed
witness remains the macOS integration binding.

## Carrier-wide MM identity composition

`kernel.el1.address-space-switch` and `core.lifecycle.publication` require MM
keys to be distinct across live roots, native children, reservations and later
host supply in one carrier. Linux `fork(2)` separates child address-space identity;
carrier address-space and occupancy tables cannot alias unrelated MMs.
`two_live_roots_keep_native_and_later_host_mm_keys_distinct` retained a real
production-bound RED: active keys `[1,2,3,5]`, later host keys `[3,4]`. The adapted
older baseline passed the same schedule, without proving universal baseline MM
safety. The repair routes both producers through a distinct typed zone MM word,
bound before issuance or under the actual stopped global MM allocation authority.
`two_live_roots_concurrently_publish_native_mms_before_host_supply` additionally
covers concurrent real graph forks, later host supply, unpublished rollback and
exhaustion without child publication. Existing kernel bootstrap/handoff/export
and retained physical-source controls cover the owner and revocation protocol.
No receiver authentication, wait4 behavior, work budget or graph-lock scope is
weakened. See the carrier issuer handoff for custody and per-ticket costs.

## First-entry claim custody under Closing

`kernel.el1.thread-lifecycle` has production-code loom bindings in
`carrick-sched-core::loom_models`. The scheduler's atomics (including run-queue
locks, incarnation, eligibility and kick debt) use loom storage in this test
build. A single usable index and slot bound the population, not the protocol;
ordinary tests keep the shared-memory layout and full-capacity bindings.
Object waits and address-space edits are outside these first-entry models.

The initial RED exploration at preemption bound 2 exposed these schedules:

- `release_races_closing_without_losing_custody`: producer reads
  `Placing(false)` for release; Closing CASes it to `Placing(true)` and
  returns Deferred; producer's release CAS fails and consumes the sole token.
  Both actors end with `Placing(true)` and no future owner.
- `requested_fallback_on_wfi_owes_a_kick`: producer admits placement; the
  previous slot enters WFI; Closing requests the placement and returns
  Deferred; producer cannot place, releases to Host, then requeues on the
  previous slot. The queue is nonempty but `take_resched` returns false.
- `mint_rejects_recycled_incarnation` and
  `placement_rejects_recycled_incarnation`: stale admission validates
  incarnation 1; an executor activates, retires and frees that birth; the
  allocator reuses the same index as incarnation 3; stale admission reads its
  Host claim and CASes it to Activating/Placing, returning an incarnation-1
  token for incarnation-3 storage.

Each focused RED test exited 101. These are assertions over the shipping
scheduler methods, not replicas of the transition function. The lifecycle
composition and competing-executor models additionally assert eligible or
terminal final ownership, one adapter delivery/adoption and retirement per
birth, rejection of the old token after reuse, and no queue links after free.
Graph-ledger adoption and physical interrupt delivery remain kernel/runtime
and signed integration bindings; the model counts their effects only under
real scheduler activation custody.

The final scheduler suite uses preemption bound 3 for focused race pairs and
bound 2 for the three composed producer/Closing/executor cases, with a 10,000
branch failure budget and no duration or permutation cap. These ownership
transfers use CAS and the WFI handshake uses a slot lock, not a Dekker pair.
`closing_producer_executor_sleep_and_reuse_preserve_delivery` counts returned
kick receipts and their consumption, while requiring every surviving queued
WFI record to have owed or delivered wakeup debt. The replacement-Closing
case also checks that stale admission cannot poison replacement custody. These
cases run through `just test-loom` and the existing CI loom job.

`current_handback_preserves_birth_incarnation_for_mint` covers non-cancelled
`OnCpu` and `OnCpuRequested` handback through the real `HostTransfer`
publication, racing a minter at bound 3. A generation-zero birth with lifecycle
and control storage returns to `FirstEntryHost` with the same incarnation;
an adopted thread returns to `Host` with its park sequence and refuses
first-entry mint. Born-in-zone entry completion does not supply a host adoption
generation, so it does not change that distinction. Publishing ordinary `Host`
for the birth would lose incarnation authentication at the acquisition CAS.

`stale_mint_cannot_consume_reused_service_head_delivery` adds a stronger P3
RED control. A stale incarnation-1 call is suspended until an executor retires
that birth, allocates incarnation 3 on the same index and queues it. The real
service-head take removes incarnation 3 and publishes Host. The stale caller
wins Host -> Activating, the legitimate executor fails to mint and returns no
delivery, and stale validation restores an unqueued Host record. There is no
remaining delivery event. This fails at focused bound 3 even with validation
under exclusive custody: eligibility alone is not delivery. The acquisition
CAS must reject a different incarnation without taking its ownership.

The repair encodes the full non-wrapping 60-bit incarnation in first-entry
claim words (`FirstEntryHost`, `Placing`/requested, `Activating`, `Retiring`).
Admission compares that exact word: a stale caller cannot acquire a new
birth even transiently. Ordinary parked and queued states retain their
slot/sequence encoding; the retained `last_seq` supplies that sequence when
first-entry custody queues a record. The ABI hash includes the claim protocol
version. Closing publishes a tagged intent, and the exclusive owner applies
its handback reason before release/publication; a delayed old requester
cannot overwrite a replacement's untagged handback. Placement release retains
custody across the single request-bit transition. Fallback publication and
its owed kick occur under the slot lock, returning a receipt to the adapter.

`delayed_closing_cannot_overwrite_replacement_handback` holds the old birth
in Placing while Closing reads its word and incarnation. The producer then
releases it, the executor retires it and a replacement reuses the index.
The old requester resumes its untagged Control write before its failed CAS,
overwriting the replacement's Service handback despite returning Stale.
This is RED on the under-custody repair at focused bound 3; publishing tagged
intent and applying payload only under exact owner custody preserves Service.
