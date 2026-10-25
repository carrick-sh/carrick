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

- Add `Stage1Unpublished`, with constructors confined to Editor-release and
  whole-inventory commit paths.
- Require it at `request_stage2_record_retirement` and thread it through every
  production retirement driver.
- Convert whole-MM exit/exec inventory retirement into an Editor edit that
  unpublishes stage-1 before returning stage-2 candidates.
- Add a compile-shape/unit witness that a bare identity cannot request
  retirement and lifecycle tests for exit/exec racing host copy.

## Task 3: Publication authority and quarantine

- Replace manual stage-2 availability publication with an RAII mutation guard
  for insert/remove/rebind/rollback paths.
- Preserve terminal retirement records and directory collision refusal so a
  quarantined IPA cannot be registered again.
- Add refused-retirement, rollback-wake, free-after-Editor-revision, and
  two-MM bounded-state witnesses.

## Task 4: End-to-end VM-free and gates

- Add the exhausted-pool munmap/read race witness.
- Run focused crate tests, `just fmt-check`, `just clippy`,
  `just clippy-linux`, `just lint-domains`, and `just test-kernel`.
- Measure both EL1 images and record loaded size plus maximum checked stack.
- Commit evidence and update `/tmp/740-s2hw-handoff.md`; do not push.
