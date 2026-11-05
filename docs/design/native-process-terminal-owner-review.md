# Independent review of the native process terminal owner

Reviewed `native-process-terminal-owner.md` against admitted main
`a35575eba8dd9e9d4ead76c119a379b6171fe7d1`, on 2026-11-05. This is a design
review only; it implements no lifecycle changes. The recommendation is
**request changes**: two P1 findings block slice 1. No P0 findings.

## P1: make signal binding a prerequisite of slice 1

The design's ordering table at `native-process-terminal-owner.md:129` allows
#1576 to land after the exit slice, requiring only recipient migration to wait.
The review brief instead requires #1576/#1589 before slice 1, alongside #1569,
#1575/#1585 and #1566. This is a substantive integration boundary: signal return
already calls `with_process_entry` and treats failed authentication as fatal
(`crates/carrick-el1-linux/src/dispatch.rs:1785` and `:1795`). Exit changes the
same retained member and graph lifetimes. PR #1589 distinguishes an exact
incarnation's first admission from absence after unregister; that distinction
must survive the owner migration.

Require #1589 before slice 1, name its first-admission/after-unregister witness,
and preserve the issue's signed requirement of zero `EntryBinding at=1795`
fatals. Do not infer acceptance from the PR's VM-free results. Public GitHub
reported #1569, #1585, #1589 and #1566 all open and unmerged when checked.

## P1: specify retained receipt progress for the promised work bound

The design forbids rescanning per wake and replay after suspension
(`native-process-terminal-owner.md:178`), but its proposed interface explains
only whole-set receipt authentication and Pending custody. The existing
implementation does not satisfy that bound:

- `PendingExit::observations` visits the whole outstanding set
  (`crates/carrick-el1-linux/src/native_process_runtime.rs:1039`).
- `readiness` rebuilds both observation vectors on each call (`:1093`),
  including from `ready_or_record` (`:1075`) and `completed_receipts` (`:1032`).
- `observe_members_verdict` restarts at the first pool member, discarding its
  partial completed vector on the first unreturned receipt
  (`crates/carrick-core/src/terminal.rs:793`).
- `park_pending_exit` invokes readiness under the wait bucket (`native_process_runtime.rs:5736`),
  and `exit_with_status` invokes receipt completion again (`:6325`).

With N members settling across N wakes, rebuilding all observations alone can
cost N squared visits. Moving the five counted predicates cannot remove that
work. This is a missing interface for the design's own structural claim, not
a request for adjacent performance optimization.

Before slice 1 starts, specify which neutral owned value retains authenticated
partial receipts or a progress cursor, how its next exact dependency is armed
and re-probed, and how it handles out-of-order completion, late publication and
record reuse without losing a wake. Include the affected PendingExit helpers
in the slice boundary. Name three scale points and a total-visit assertion
under staggered and out-of-order completion, with a mutation that restores
whole-set rebuilding and fails. Existing receipt storage can be evolved; a
second census or lifecycle path remains forbidden.

## P2: describe the dispatch decision precisely

The inventory row at `native-process-terminal-owner.md:46` describes choosing
whether SYS_EXIT stays in the thread path. At `dispatch.rs:277`, the census
actually feeds the refusal closure's `arm_owner_must_serve` call. That helper
at `dispatch.rs:510` decides whether an unserved process call must be refused;
for non-last-thread SYS_EXIT it permits the ordinary fallback path. Describe
this refusal-policy decision explicitly so a later migration does not change
initial routing by accident. This wording improvement does not block landing;
track it as a follow-up if it is not corrected with the P1 revisions.

## Verified design claims

`just xtask terminal-custody --list` reports exactly the 18 Linux function/rule
pairs already listed in the design. Its scanner uses a set per function/rule,
so the two adoption census expressions count once and import counts three
times. The design's source anchors still match admitted main. The first
slice's exit-live, close-live and three import predicates are five actual
sites; removing them without replacements yields 18 to 13. That is a scoped
acceptance target, not evidence that implementation already meets it.

The owner extension direction is sound. Core already closes admission and
orders birth publication (`terminal.rs:723`), reserves one exit caller
(`:742`), authenticates exact member receipts (`:879`), and distinguishes
exec's one-live/one-claim floor from exit's zero/zero floor (`:893`). Settlement
consumes Closing and yields Settled (`:903`); thread terminal retirement uses
the separate ZoneRetirement capability (`:1357`). The design correctly keeps
process settlement, thread terminal state and parent reaping distinct. Opaque
exact-generation handles, retained control storage, scoped borrows and
re-authentication after parking are appropriate requirements; they are proposed
interfaces, not existing guarantees.

Fork, exec, signal and native-service clients are addressed without a second
state machine. The registry/graph admission guard in `begin_closing`
(`native_process_runtime.rs:5837`) and exec-to-exit upgrade (`:5847`) must remain
part of the authority boundary. The signal-record exception really does allow
an exact host-owned Free record (`:102`). The service enrollment check
(`native_process_runtime/service.rs:1535`) is a distinct wait-lifetime check.
Linux policy and payloads remain outside neutral lifecycle eligibility.

The ordering table correctly requires #1569's observed-claim/yield fix,
#1575/#1585's closed-gate service retirement and #1566's per-task continuations
before slice 1. Public PR descriptions and changed-file lists confirm these
overlaps; their acceptance claims were not independently runtime-verified here.
#1485 remains an MM/owed-return integration dependency when its interface is
touched, rather than a blanket prerequisite of the five-predicate exit slice.
Preserving the current `aarch64_process.rs:2586` retirement boundary is
consistent with that separation. The eventual capability migration must cover
the x86 client as the design requires.

All three named native witness anchors exist at the cited locations. The
two-thread, pre-live-claim, late-publication, closing-loser, host-reserved,
Busy-once, reuse, exec-upgrade and once-only reap requirements are appropriate.
Their existence does not prove the new predicates or proposed work budget;
slice 1 still needs the specified production-entry mutation evidence and all
native test populations completed.

The kill criterion is explicit and matches the issue: stop if the first slice
needs a parallel lifecycle path or deletes no ratchet sites. No exemptions,
ceiling increase or missing signed population may rescue it.

## Start decision

Slice 1 cannot start merely because its prerequisite PRs land. First resolve
both P1 findings in the design and independently review those revisions. Then,
once #1569, #1585, #1589 and #1566 have landed with their required acceptance,
slice 1 can start. Rebase, classify each affected prerequisite fix as
kept/ported/dropped, and re-prove the production witnesses after movement.
The P2 wording issue does not independently block that start.
