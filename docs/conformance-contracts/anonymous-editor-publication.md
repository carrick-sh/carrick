# Anonymous editor publication during a host pause

The `kernel.el1.anonymous-permissions`, `kernel.el1.anonymous-munmap`
and `kernel.el1.anonymous-reservations` policies retain the exact-MM
`SpaceEditor` until descriptor mutation, local invalidation and publication
have completed. A host pause can raise the admission gate while waiting for
that editor. The admitted operation must publish through its existing guard;
requesting a fresh open-gate grant after mutation can turn contention into a
fatal binding error.

`admitted_mprotect_publishes_through_pause_then_next_edit_succeeds` drives
the production policy, raises the gate inside the admitted descriptor step,
and requires one publication before editor release and another successful
edit after the pause lowers. It was red at publication 0 versus expected 1.
Publication is one atomic increment per successful descriptor operation,
including the full-journal handback, with no new wait or retry.

The hardware editor still completes its local invalidation before policy
publication. Publication deliberately does not acknowledge slot coverage;
the next entry must consume the published generation through the existing
per-vCPU invalidation protocol. This conservative extra invalidation does
not establish synchronous completion on an already-running sibling vCPU.
That P1 review finding remains open, as does signed verification of the
changed head. The earlier signed population evidence belongs to its original
artifact and does not establish a result for this change.

`slot_cow_coverage_survives_rebinding_and_rejects_retired_asid_identity`
drives `ZoneTables::cover_cow` on two slots, resetting and rebinding a slot
to a replacement vCPU, switching that slot through a
second live MM, then retiring the first MM and publishing a new MM with the
same numeric root/ASID and publication generation. Coverage must remain
local to both the slot and MM identity. This is a scheduler lifecycle witness,
not proof of hardware ASID-retirement completion.

`scheduler_invalidates_cow_after_vcpu_slot_rebinding` and
`scheduler_invalidates_reused_asid_with_matching_publication_number` extend
that ledger witness through `Sched::run_ready`. The production installer
must call the CPU invalidator, install the target root and acknowledge only
the entering slot's exact MM. The CPU is modeled: these tests do not establish
hardware ASID retirement or synchronous sibling completion.
Restoring the pre-reset behavior (omitting the two coverage-clearing stores)
makes the rebinding test fail at the CPU call assertion: no invalidation is
issued, instead of the required single invalidation of the reused ASID.

A successful `reset_slot` clears local coverage together with the timer
cache because a new mailbox lease can name a different vCPU. The reset
witness was red (`None` instead of `Some(1)` owed) before clearing these
fields. A refused reset preserves the still-owned slot.

## Remaining completion obligation

The per-slot generation is an entry obligation, not a shootdown receipt.
`SpaceEditor` excludes another editor and host root retirement; it does not
exclude a sibling already executing user instructions. In particular, an
installer can capture generation `g`, the editor can invalidate, and that
installer can cross back into guest execution before the editor publishes
`g + 1`. Its previously captured grant does not observe the new obligation.
This is a protocol counterexample to a generation-only proof, not a newly
observed hardware failure or a core diagnosis.

Publishing before invalidation alone also leaves an installer that captured
`g` before publication. Completing this contract requires admission and
invalidation completion to cover both already-running siblings and siblings
crossing the host/guest boundary. An architectural broadcast claim must
establish that guarantee for the backend's virtual CPUs, including host
entry and exit. The failed stronger-barrier experiment in the population
report cannot supply that proof.

An alternative is an owned continuation using the existing paused-MM
descriptor transaction: retain the operation and its completion authority,
close admission, obtain exact sibling acknowledgments, and complete only
after invalidation. It must release execution capacity while awaiting those
acknowledgments. Neither synchronously waiting on a pool worker nor forwarding
after an untracked partial mutation is a valid implementation. Its witness
must hold one sibling across entry and another in user execution, delay an
acknowledgment, and prove that the edit cannot report completion early while
other runnable tasks still make progress. The final signed population must
then be collected on the resulting head; the historical population does not
discharge this obligation.

## Reviewed integration boundary for a retained pause

The host's existing pause is not an asynchronous acquisition interface.
`carrick-kernel::dispatch::mm_quiesce::pause_exact_mm` calls
`drain_exact_mm`, which waits for resident departures. Its test-only
`try_drain_exact_mm` does not provide production continuation custody.
Calling the synchronous pause from an anonymous service would occupy an
executor while waiting for guest tasks.

`carrick-runtime::vcpu_loop::binding::RetainedMemoryAction` is the existing
capacity-releasing owner to extend if acquisition is carried by the host.
It currently has no anonymous reservation operation or originating syscall
frame. The process-quiesce suspension beside it waits for a fork barrier's
release, not for the page-table coordinator's exact resident population to
drain. Neither API can be substituted without changing its ownership contract.

The proposed acquisition order, requiring a separate interface review before
implementation, is:

1. Capture the anonymous proposal and originating task generation before any
   descriptor effect. Release the reservation model borrow and guest editor
   before submitting pause acquisition. Keep the pending reservation owned;
   do not cancel it merely to recreate the syscall later.
2. Elect one exact-MM pause owner and close entry admission before observing
   residents. Retain that owner and an authenticated drain subscription in
   the capacity-releasing action. Enrollment must precede the final resident
   probe, covering a departure between observation and park publication.
3. Prompt both resident execution and concurrent installers through their
   existing host/guest admission handshake. A wake is a prompt to recheck
   the owned drain, not an acknowledgment inferred from elapsed time or a
   generation counter.
4. Once drained, lend the paused target's exact descriptor authority to the
   original operation. Reacquire its reservation model and maintenance editor
   only for the descriptor transaction; neither borrow crosses a park.
5. Settle descriptor invalidation, root metadata and backing receipts before
   releasing the pause and completing the original syscall. Cancellation
   before mutation refuses the proposal; cancellation after mutation retains
   settlement custody and suppresses only delivery to the departed origin.

The forbidden lock edge is guest editor → host pause acquisition: the host
raises the gate and waits for the same guest editor, producing a cycle. The
reverse transfer must therefore cross an owned, unmutated proposal, not a
borrowed editor or an applied but untracked edit. New request/receipt layouts
and the cross-crate lock order need the separate design review required by
AGENTS.md. This describes an integration boundary, not an implemented pause
protocol, and supplies no new runtime or signed acceptance evidence.

## Existing venues and the missing integration

`carrick-personality-linux::pending_anonymous::serve` currently has no owned
invalidation-wait result. `PermissionStep::Return` completes the syscall;
`CommitOwed` also installs success before handing metadata work to the carrier.
Neither can represent an edit awaiting sibling acknowledgments. Likewise,
`RetirementStep::Retired` describes an already applied edit. Reusing these
variants for a delayed shootdown would expose completion before its authority
exists.

The delegated path already captures the originating task generation, exact MM,
arguments and return address in `PendingReservationSyscall`, but
`serve_delegated_anonymous` consumes that custody within the synchronous call.
Its `PreparedConflict` park waits for a reservation producer, not for vCPU
invalidation. That notification cannot be substituted for an exact sibling
acknowledgment.

The HVF `ForeignEl1Publisher` is an existing example of authenticated descriptor
submission under a paused target. Its contract requires the caller to supply
the pause and lend a vCPU; `authenticate` does not obtain the pause itself.
Calling that publisher from a synchronous anonymous hook therefore does not
solve admission or release the waiting executor. It is also an HVF adapter,
not an appropriate home for neutral continuation ownership.

A correction needs a retained operation outcome through the native anonymous
entry owner, plus exact-MM pause custody established before descriptor mutation.
The owner must enroll on acknowledged release, surrender execution capacity,
and resume that same operation after siblings have left the old translation
state. Only after descriptor execution, invalidation and receipt settlement may
it install the Linux result or release retired backing. Cancellation must
distinguish an unmutated proposal from an applied transaction whose settlement
is still owed. These are changes to continuation custody and cross-crate lock
ordering, not another generation increment or a stronger DSB instruction.

The required deterministic schedule has three independently controlled actors:
the editor, a sibling holding a pre-edit install grant, and a sibling already
executing user code. It delays each sibling acknowledgment separately, requires
the edit to remain incomplete, and runs an unrelated runnable task with the
normal executor capacity. Releasing both acknowledgments must complete the
original edit once, without replaying it. This schedule and its production
continuation integration remain unimplemented; the existing tests do not
establish this property.

## What a red witness may conclude

The remaining P1 is a missing completion witness, not a demonstrated failure
of HVF's broadcast invalidation. `ThreadCpu::invalidate_asid` already requires
all-PE completion. Its AArch64 implementation issues `DSB ISHST`,
`TLBI ASIDE1IS`, `DSB ISH`, then `ISB`; the missing evidence concerns that
sequence's effect on virtual CPUs running or entering through HVF.

A VM-free editor that returns success after invalidating only its own modeled
CPU cannot disprove this backend guarantee: it has substituted a weaker
implementation. Likewise, an old per-slot coverage word after a broadcast is
not evidence that the hardware translation survived. Do not make either
assertion a red-first regression test for a guest-visible stale translation.
The existing generation tests establish entry obligations only.

There are two distinct admissible proof routes. A backend witness must retain
the real hardware editor, warm a sibling translation, control the sibling's
entry or continued user execution, and distinguish a denied access from a
timeout or an incidental scheduler re-entry. An explicit rendezvous instead
needs the production continuation schedule above, including delayed exact-MM
acknowledgments and progress by an unrelated task. Its red assertion concerns
premature syscall completion, not just a missing coverage counter. Neither
route has been executed for the current head on the Linux dispatch runner;
the signed population and core/event-ring acceptance remain outstanding.
