# Stage-1-first retirement for #847

Spec: the latest design comment on issue #847.

## Constraints

- A current stage-1 leaf must always have live or publishing stage-2 authority.
- Stage-2 retirement requires a non-forgeable `Stage1Unpublished` witness.
- Whole-MM retirement unpublishes its stage-1 image through the Editor before
  returning physical retirement candidates.
- Host copies wait only for Reservations, Editor, or an active stage-2
  publication. A current unchanged leaf whose pin fails is a typed MM-fatal
  invariant event, not EFAULT and not a carrier failure.
- Publication/removal authority publishes readiness from RAII `Drop`, including
  rollback. Terminal refused retirement quarantines the IPA.
- Per-MM work is proportional to live state; no historical rewrite ledger.

## Task 1: Remove inferred rewrite producers

- Delete `OwedStage1Rewrite`, `PendingStage1Rewrite`, and their ABI/runtime
  handling.
- Carry the SELECT Editor receipt into physical retention. Return that exact
  Editor wait when a concurrent edit can explain a stale selection.
- Make producer-free Editor recheck a typed `Stage2AuthorityInvariant` and
  terminate only the affected MM with SIGKILL plus an event-ring record.
- Add production-path tests for immediate reselect, held-editor enrollment,
  publication commit/rollback, successor rebind, and invariant containment.

## Task 2: Make retirement stage-1-first by type

- Make `Stage1Unpublished` constructible only from a completed stage-1 edit
  receipt or a committed `Stage1UnpublishedMm`; identity alone is not proof.
- Require that capability at the final mutation APIs, including
  `retire_stage2_record_using`, terminal-record removal, and global-frame host
  owner retirement. Delete test-only proof constructors and drive tests through
  the production edit or inventory path.
- Close whole-MM exit/exec through an Editor-visible transition. A host copy
  holding the prior Editor revision must observe the close as changed, never as
  a stage-2 invariant violation.
- Before diagnosing a producer-free pin refusal as an invariant violation,
  revalidate the selected leaf against the authoritative stage-1 table. A
  host-side edit that changed or removed the leaf reselects and reaches the
  normal EL1 fault/EFAULT result; it never SIGKILLs the MM.
- Red first: capability-shape tests, whole-MM close racing a parked host copy,
  and a production host-side unmap+retire racing a held-revision copy.

## Task 3: Publication authority and quarantine

- Replace manual stage-2 availability publication with an RAII mutation guard
  for insert/remove/rebind/rollback paths.
- Preserve terminal retirement records and directory collision refusal so a
  quarantined IPA cannot be registered again.
- Replace the registration-wide overlap scan with a `BTreeMap` interval index;
  registration checks only predecessor and successor and all shared removal
  paths update the index under the same mutation authority.
- Make authority rollback/drop retire through a real teardown proof; no
  debug-only leak path remains.
- Add refused-retirement, rollback-wake, free-after-Editor-revision, real
  two-MM-by-N retirement/no-growth, and interval-neighbour witnesses.

## Task 4: End-to-end VM-free and gates

- Add real production-path witnesses for exit and exec racing a parked
  sibling host copy, and munmap racing a blocking read under an exhausted
  executor pool.
- Record the exact new-test list and distinguish new tests from strengthened
  pre-existing tests.
- Run focused crate tests, `just fmt-check`, `just clippy`,
  `just clippy-linux`, `just lint-domains`, and `just test-kernel`.
- Measure both EL1 images and record loaded size plus maximum checked stack.
- Commit evidence and update `/tmp/740-s2hw-handoff.md`; do not push.

## Execution rulings for review round 12

- The authoritative stage-1 revalidation is the safety backstop for every
  host-side edit. It avoids a second Editor observer while ensuring a sampled
  revision cannot justify SIGKILL after an edit outside the ring Editor path.
- Editor epoch changes are wake/reselection evidence, not forward progress for
  the bounded owner-copy driver; committed bytes remain the progress measure.
- The `kernel.memory.owner-wait` contract applies: a valid mapped buffer cannot
  become EFAULT or SIGKILL because a private stage-2 transition was observed,
  and registration/retirement work must remain proportional to live state.
