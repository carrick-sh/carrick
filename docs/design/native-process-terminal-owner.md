# Native process terminal ownership (design for #1579)

Status: proposed; independent design review is required before slice 1.
This round changes documentation only. It does not claim a lifecycle fix.

## Scope and evidence

The source anchors below describe admitted main
`04deeb00729d48ec881eec6ecac8716d64161492`. They are a review snapshot,
not a new machine-enforced line inventory; delete this snapshot when the
migration reaches zero. The authoritative inventory remains
`just xtask terminal-custody --list`, run with `just xtask lint-source`.
The scanner counts one function/rule pair, not individual expressions
(`crates/carrick-xtask/src/terminal_custody.rs:139`). Consequently two live
reads in one function cost one site, while import costs three sites.

The existing owner is substantial: `carrick-core/src/terminal.rs:702`
closes admission, orders the birth snapshot and selects the unique exit
owner; `:859` authenticates member receipts; `:893` checks the live and
claimed floors before settlement. Extend this implementation. Do not add a
second lifecycle state machine in Linux or in an ISA backend.

## Current decisions to remove

Paths below are under `crates/carrick-el1-linux/src/`. Each row identifies
the raw decision, its current purpose, and the proposed owner operation.

| File:line / function | Rule and decision | Owner operation |
|---|---|---|
| `native_process_runtime.rs:103` / `signal_record_exists` | live record or exact host-owned free record accepts signal control | authenticate recipient custody |
| `native_process_runtime.rs:191` / `owned_control` | Born/Published licenses a retained control pointer | borrow exact member control |
| `native_process_runtime.rs:281` / `run_failure_reason` | group-exit custody lowered to fatal reason | consume typed terminal disposition; retain diagnostic mapping only where truly invariant |
| `native_process_runtime.rs:2806` / `authorize_group` | live census bounds sibling adoption (two reads, one site) | admit member under registry guard |
| `native_process_runtime.rs:2882` / `live_pool_entry` | Born/Published selects a signal-capable pool incarnation | authenticate pool member |
| `native_process_runtime.rs:2981` / `live_signal_member` | live zone record validates recipient identity | borrow recipient |
| `native_process_runtime.rs:3188` / `imported_members` | EntryState filters imported members | import authenticated membership |
| `native_process_runtime.rs:3249` / `imported_members` | live count equals leader plus imports | validate import census |
| `native_process_runtime.rs:3249` / `imported_members` | zero claims required for import | validate import claims |
| `native_process_runtime.rs:3846` / `record_binding` | live record licenses saved context access | borrow execution binding |
| `native_process_runtime.rs:3874` / `resume_visible_pid` | live record resolves process for resume | authenticate resume identity |
| `native_process_runtime.rs:5904` / `begin_closing` | zero live census quarantines close admission | close admission verdict |
| `native_process_runtime.rs:6472` / `exit_with_status` | live member requires host cancellation | apply exact cancellation permit |
| `native_process_runtime.rs:6927` / `fork_publish` | child starts with one live member | admit fresh child |
| `native_process_runtime.rs:6932` / `fork_publish` | all pool entries Vacant before publication | admit fresh child stock |
| `lifecycle.rs:583` / `release_current` | absent zone record refuses retirement | consume existing ZoneRetirement capability |
| `dispatch.rs:277` / `dispatch_syscall` | live census feeds `arm_owner_must_serve` in the refusal closure: non-last-thread SYS_EXIT permits ordinary fallback when the process call is unserved; this does not choose initial routing | owner supplies refusal-policy capability preserving that distinction |
| `aarch64_process.rs:2595` / `retire_mm` | PendingRetirement authenticates terminal execution before crossing | consume phase-specific retirement capability |

These are all 18 live scanner sites. No ceiling increase or scanner exemption
is part of this proposal. The ARM retirement adapter is a client of the shared
owner; the corresponding x86 client must consume the same capability when
that interface changes, with only physical root mechanics left per ISA.

## Owner interface and state transitions

The following names are proposed API vocabulary, not implemented APIs.
`ProcessHandle` identifies an exact TaskKey generation and retained lifecycle
storage. It is a lookup capability, not proof that the process is running.
`MemberHandle` binds that process, thread serial, record incarnation and
control storage lifetime. Neither exposes a numeric live census or EntryState.
The neutral owner authenticates these handles against existing lifecycle and
scheduler authorities; it must not maintain a shadow census.

Preserve `TerminalCustody<Process, Closing>` and `<Process, Settled>` and
`TerminalCustody<Thread, Live/Exiting/Terminal>` (`terminal.rs:600`, `:961`,
`:1215`, `:1357`). Add opaque admission/borrow results around them:

- Birth reservation owns a pre-live obligation; publishing produces an exact
  member handle, rollback returns its existing obligation. Closing refuses
  fresh births but must account for births admitted before gate closure.
- Close admission returns either the unique closing custody, a participant
  capability joining that close, or an invariant error. A loser cannot consume
  the winner's membership or reset cancellation. Exit upgrades an outstanding
  exec using the existing pending-operation authority (`native_process_runtime.rs:5847`).
- Closing owns the caller, cancellation cause and exact member receipt set.
  A pending result retains this ownership and an existing release dependency;
  enrollment probes once and releases execution capacity. It is never a new
  errno or a fatal Busy. Settlement consumes completed exact receipts and
  produces Settled, as the current `settle` already does (`terminal.rs:903`).
- Settled authorizes address-space retirement and terminal publication;
  Published status is retained by the existing neutral process graph until
  one parent wait consumes it. Reaped handles cannot authenticate a recycled
  task. Do not conflate thread Terminal, process Settled and parent Reaped.

A borrowed binding or recipient is scoped to the existing graph/registry or
scheduler custody that protects the operation. It cannot survive a park as a
reference; retain an owned continuation with exact handles, then authenticate
on resume. No public `is_alive() -> bool` API: a boolean followed by mutation
would recreate the check/use race. Diagnostic snapshots cannot license work.
The owner returns operation-specific capabilities or Pending/Terminal verdicts.

Linux retains namespace PID translation, Linux wait-status encoding, signal
actions, credentials and service payloads. Neutral core owns lifecycle
eligibility; scheduler core continues to own record claim transitions. Neutral
code must not depend on the Linux crate or use Linux statuses as state tags.
Do not move pointer dereferences into neutral code without carrying their
existing retained storage lifetime and exact identity proof.

## How callers ask

Fork uses a birth reservation and consumes a fresh-child admission result
instead of inspecting pool state (`native_process_runtime.rs:6879`). Adopted
members join under the registry guard already held across close/snapshot
(`:5837`). Exec obtains close custody through the same owner and retains its
caller and service claim: its floor is one live and one claim, unlike exit's
zero/zero (`carrick-core/src/terminal.rs:893`). Cancellation of exec transfers
the prepared operation and receipt duties; it does not create a new process.

Signal ingress asks for an exact recipient borrow, including the host-owned
record case at `native_process_runtime.rs:103`; generation mismatch refuses
that recipient, while closing selects terminal handling. Signal policy stays
in `native_process_signals.rs`. Native service settlement asks whether this
exact member should resume, yield to a host requester, join a close, or await
a retained dependency. A closed gate alone cannot classify the member as
corrupt. `native_process_runtime/service.rs:1535` also has a distinct enrollment
lifetime check; the owner must compose with it rather than replacing it with
a census read.

## Composition and ordering

These are integration requirements, not claims that open branches have landed.
The #1653 review and #1589 body and patch were read on 2026-11-05; #1589
was still open. These are integration requirements, not runtime acceptance.
Recheck every prerequisite head, landing and witness before implementation.

| Lane | Interaction and prerequisite |
|---|---|
| #1569 | Exact observed scheduler claim and yield receipt fix. Land before slice 1; reuse its neutral host-request verdict. Do not restore a claim re-read after a successful requeue. |
| #1575 | Service exit Busy during group close. Land before slice 1 and preserve its production two-thread red witness; closing participant handling becomes an owner client, never a competing fatal/errno path. |
| #1576 / #1589 | Signal delivery binding around native birth/exit is an explicit prerequisite of slice 1, alongside #1569, #1575/#1585 and #1566. Preserve exact-incarnation first admission versus absence after unregister; exit changes the same member/graph lifetimes. Require the production signal witness and signed acceptance below before starting. |
| #1566 | Per-waiting-task continuations. Land before slice 1 so pending close/wait integration retains the calling task's continuation rather than a process-wide slot. |
| #1485 | Owed-return claims and linear retirement permits. Exit slice may land without completing its MM work, but must leave its existing retirement boundary intact. Any shared API overlap is resolved with that lane first; later MM retirement integration depends on its reviewed permits, never a duplicate return path. |

No lane should wait for this design to fix a current fatal. Rebase each slice,
map every affected fix as kept/ported/dropped, and re-prove its production red
witness after code moves. The director owns the final ordering and signed gate.

The #1589 prerequisite includes
`aarch64_process_tests::native_fault_supply_tests::native_child_thread_signal_at_first_user_return`
and core's `lifecycle::membership_tests::graph_registration_survives_final_reference_until_control_reset`.
The first must preserve newborn admission, once-only signal delivery and
rejection of newborn restoration after first admission; preserve the retained
`GRAPH_REGISTERED` distinction through final unregister until control reset.
The director must also complete repeated full signed `el1_sched` populations
with zero #1576 `EntryBinding at=1795` fatals, including the affected fork-COW,
two-process, spawn-slope, seccomp clone-filter and allocator witnesses.
VM-free results on #1589 do not satisfy that signed prerequisite. Current main
still authenticates signal return with `with_process_entry` and fails closed
at `dispatch.rs:1785` and `:1795`; the exit slice must preserve that boundary.

## First slice: exit and import

After fresh independent approval of this revision and accepted landing of
#1569, #1585 (for #1575), #1589 (for #1576) and #1566, move the eligibility
in `exit_with_status`,
`begin_closing` and `imported_members` behind the existing neutral owner.
The Linux adapter supplies retained member observations and applies returned
capabilities; core alone filters states and validates membership/claim floors.
Import must return authenticated membership before Linux constructs graph rows;
an absent or wrong-generation record must not become an unsafe pointer borrow.
Exit cancellation consumes an exact member cancellation capability rather than
checking zone.live and then claiming a possibly changed record.

Delete five function/rule sites: exit live, close live, import EntryState,
import live, import claimed_count. On this baseline the ratchet must go from
18 to 13, with no offsetting new site anywhere. Lower the ceiling in the same
slice. Later independently reviewable slices migrate fork/adoption, recipient
and execution binding, then remaining lifecycle adapters/diagnostic policy to
zero. Merely renaming a raw read or moving it to another non-owner crate does
not count. Delete the zero ceiling entry when the final client migrates.

### Retained receipt progress

Slice 1 also changes `PendingExit::{observations,readiness,ready_or_record,
completed_receipts}` and their `park_pending_exit` / `exit_with_status` callers.
On admitted main, `observations` (`native_process_runtime.rs:1039`) scans all
outstanding members; `readiness` (`:1093`) rebuilds both vectors each time.
Core's `observe_members_verdict` (`terminal.rs:786`) starts at pool member zero
and drops its completed prefix on the first missing receipt. Moving only the
five predicates leaves quadratic work under staggered completion and does not
meet this slice's acceptance criterion.

Propose a neutral, non-Clone `MemberReceiptProgress` in `carrick-core::terminal`,
minted once by Closing custody from its authenticated `MemberSet`. It owns the
boxed exact expected receipt sequence, a next-uncompleted cursor and the
already authenticated prefix. This evolves the existing member/receipt storage;
it is not a second census or lifecycle state machine. Linux `PendingExit` owns
this value alongside Closing custody and retained control-storage handles;
Linux cannot construct it, reset its cursor or mark a receipt complete.
The owner binds it to the exact process close operation and member-set identity.
Large storage remains boxed, outside the bounded EL1/CPL0 stack.

The proposed `advance` operation borrows only the next exact retained member
observation, authenticates the existing pool/adopted/host-born receipt, records
success once and advances. A Pending result returns an exact release dependency
for that cursor without discarding progress. `ready_or_record` reports this
cached verdict; `completed_receipts` consumes the finished progress into the
existing `CompletedMemberReceipts`, without another whole-set check. Evolve the
existing `observe_members_verdict` implementation into this protocol, replacing
its native close call path rather than keeping a parallel scanner. Final
`can_settle` still applies the owner's live/claimed floors; a floor wait retains
the completed proof and does not revisit members.

To park, enroll on the selected member's existing release notification under
its wait-bucket guard, then re-probe that same exact dependency once. If already
returned, cancel enrollment and advance; otherwise retain progress, dependency
and control lifetimes in the calling task's continuation and release execution
capacity. Wake resumes that cursor, never member zero. No borrowed observation,
registry guard or scheduler claim survives parking. Arm the existing process
membership-release dependency similarly when only the final floor remains.
This is enrollment against an authoritative receipt, not periodic polling.

Completion may arrive out of order: it remains in the existing member's durable
receipt storage until the cursor reaches it. An earlier pending member is the
only armed dependency; later completions need no separate wake or scan. When
the earlier member returns, the cursor consumes already-returned successors.
The post-enrollment re-probe closes the lost-wakeup window even if the next
member completed before enrollment. A spurious wake rechecks only the selected
dependency and cannot invalidate the authenticated prefix.

Close admission still orders the birth snapshot (`terminal.rs:723` and `:737`)
and holds the existing registry/graph admission boundary. Capture pre-live
obligations in that one bounded snapshot before sealing progress; late Born or
ExitedInZone publication completes the same reserved exact identity, not a
newly discovered member requiring a rescan. If capture is still pending, retain
its bounded traversal cursor and admission obligation before receipt advancement.
No success is minted until that snapshot is sealed. Retained control custody
prevents reset/reuse while its receipt is owed; authenticate record incarnation,
entry identity and host birth serial at each advancement. A mismatched recycled
record cannot satisfy the cursor. After authentication, the retained prefix
proves that exact old obligation even if storage is later reused; it does not
license access to the replacement record. Exec-to-exit upgrade transfers this
same progress and accounts once for exec's retained caller/service obligations;
it cannot restart the sequence or discard an owed receipt.

Require production-entry schedules at N = 2, 8 and 32 members, with both
one-at-a-time ordered completion and reverse/out-of-order completion, late
publication, reuse refusal and an enrollment race. Count snapshot slots S,
receipt observations R and pending dependency episodes W per close operation.
Assert one snapshot traversal, no observation of an authenticated prefix, and
`total_member_visits <= S + N + 2*W`: each successful receipt costs at most one
visit and each pending episode at most its initial check plus enrollment
re-probe. Count floor probes separately, at most one initial probe plus one per
floor release/enrollment event; they cannot traverse members. W counts only
actual selected-dependency episodes (including spurious wakes), is bounded by
the fixture schedule, and cannot be inflated by hidden full-set work. Total
member visits include R and snapshot/authentication work. Restoring whole-vector
rebuilding or resetting the cursor on wake must fail this assertion under
staggered completion at these scales.
Authenticate each member once, including exact cardinality at sealing; do not
use the current repeated per-element set searches in `MemberSet::completed`
(`terminal.rs:464`) as an uncounted quadratic final validation. Snapshot
deduplication and member lookup must also fit the bound; retain stable indexed
slots for exact obligations rather than nested identity searches. The red-first
work witness is required before slice 1 can claim this interface is implemented.

Before moving production code, extend production-entry native witnesses to
exercise two live threads, pre-live claims, late Born/ExitedInZone publication,
closing losers, host-reserved members, Busy once then success, recycled records,
exec-to-exit upgrade, and exact once-only parent status consumption. Mutation
of each migrated predicate must make its corresponding witness red. Existing
anchors include `exit_group_holds_terminal_custody_until_pre_live_claim_settles`
(`native_process_runtime.rs:12062`),
`clone_live_membership_blocks_exit_between_graph_unlock_and_enqueue` (`:12351`)
and `losing_exit_group_keeps_host_reserved_membership_and_live_record`
(`native_process_runtime/tests/terminal_park.rs:430`).

Run every native witness using `just test-el1-native` (including serial_host),
focused core regular/serial suites, source and base debt ratchets and contract
coverage. Compare started/completed test populations against the admitted base.
The director then runs signed smoke and all applicable native signed witnesses
on the exact artifact, with no missing binaries and NEW=[]; Docker differential
and promotion remain required where the changed contract binds them.

The semantic authority is Linux exit/wait ordering and once-only reap. Existing
contract `process.native.terminal-child` documents retained terminal identity
and parent handback (`docs/conformance-contracts/native-child-terminal.md:18`).
Before implementation, map every affected surface to its existing contract and
add any missing red-first binding. Structural acceptance forbids extra polling,
rescans per wake, duplicate census storage or additional host readiness objects.
Count member visits at three capacities and require one bounded snapshot plus
work proportional to actual member receipts, with no replay after suspension.
A semantic pass cannot excuse a work-budget failure.

**Kill criterion:** if slice 1 requires a parallel lifecycle path or deletes no
ratchet sites, stop the owner migration and continue fixing individual defects.
Do not expand the slice, add scanner exemptions, or increase a ceiling to save
this bet. Missing native witnesses or a red signed population blocks slice 1;
it does not justify claiming the architecture succeeded.
