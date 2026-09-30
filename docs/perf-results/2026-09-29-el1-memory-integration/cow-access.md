# COW kernel, legacy, maintenance and private-file caller integration

Development on adapter parent 1b121731c. Contract: kernel.el1.stage1-publication.
No production admission, signed COW execution or checkpoint acceptance claimed.

CowRepoint protocol v4 carries typed access authority: EL1-recorded private
intent, backend user page-write decisions, or kernel-only access. Tagged leaves
always retain EL1 permission authority. Legacy pages preserve validity and all
non-address attributes except explicitly licensed write access; kernel pages use
the same EL1-only flags as the existing host kernel mapper. All pages remain one
compound transaction through the existing copy aliases and descriptor journal.

perform_frame_cow now submits kernel, legacy user and maintenance copies. After
verified completion it reads the exact maintenance leaf under retained MM/custody
exclusion and preserves the existing deferred protection-publication receipt.
The remaining blanket COW-shape refusal is removed; other writer entry points
remain fenced and admission is still disabled.

Private-file destination reuse keeps its existing owner pin. It authenticates
that published mapping through KernelFrameCowAuthority without a duplicate
grant, using one O(1) kernel row/revision query and an independently retained
physical owner. The backend checks returned MM, frame, mapping and generation.
Only fresh destinations use provisional-grant rollback. Existing destinations
are never retired by fresh-grant cleanup; the copy touches only the semantic
span, preserving already-private neighbors in the reused compound.

Evidence:
- Kernel/legacy operation witnesses failed NotCowArmed before implementation.
- An intermediate implementation incorrectly let the legacy mask suppress EL1
  write intent; the retained red control caught it, and the final shared tagged
  rule ignores the backend mask for these leaves.
- Wire round trips cover all access modes. MMU 163 and EL1 114 tests pass.
- Existing-destination runtime authority red failed Unsupported; green checks
  exact MM/IDs/revision/generation, wrong-IPA rejection and post-rollback refusal.
  This uses the real kernel inventory with the existing fixed-owner fixture,
  not hardware COW execution or carrier-owner recycling coverage.
- Kernel inventory 22, backend COW 11 and affected all-target Clippy pass.
  Hardware-image dependencies compile; no signed run is part of this slice.

Next: private/shared repoint publishers, replacement grants, retired reuse,
sparse replacement and foreign-MM publication, then engine/exec writer closure
and SharedReservations policy/lifecycle. A successful full perform_frame_cow
execution with real ownership and signed guest evidence remains required at the
connected memory milestone. Keep main unchanged and x86 deferred.
