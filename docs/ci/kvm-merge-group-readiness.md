# KVM merge-group gate: director integration review

PR [#1380](https://github.com/carrick-sh/carrick/pull/1380) remains a draft.
The existing implementation is worth preserving, but must not be deployed
from its stale head. Main still has no pre-landing KVM job. This audit adds
documentation and a durable workflow patch; it does not integrate main,
change controller code, deploy infrastructure, or establish live acceptance.

Review scope: issue [#1366](https://github.com/carrick-sh/carrick/issues/1366),
admitted PR head `1ccb0f74c09c6859f8ff089d9e656a93a5ab65f1`, fetched GitHub
main `a4750d355f9b4b5563cf71d0740d2a782fe4e4fb`, common ancestor
`6d664da7b16a92dd204bb172139b98b276c3f91b`. These identify the reviewed source,
not a runtime receipt. Refresh the comparison if main moves. GitHub confirmed
the PR is open, draft, and has that admitted head. The issue, PR comments and
decision log were read; they name this existing carrick-87 lane, with no
second #1366 implementation owner identified.

## Findings

**P0: none identified in this bounded source review.** This is not a security
review or a successful live merge-group run.

**P1 — current main has no KVM merge-group protection.** Its `ci.yml` has no
`kvm-tests` or `kvm-gate`; `kernel-runtime.yml` triggers on main push and
owner dispatch only. A green PR or hosted merge-group run cannot substitute
for pre-landing KVM evidence. The stale PR's AGENTS.md describes the proposed
state, not deployed coverage. Keep the director's queue hold until the pilot
below succeeds. The director already recorded the correction on
[#231](https://github.com/carrick-sh/carrick/issues/231#issuecomment-6621421888).

**P1 — the capability probe also blocks dispatch-agent clones.** In the PR's
`ci_scaler::live::boot_and_register`, `standing` matches both
`Admission::Standing` and `Admission::Agent`. The new capabilities probe is
inside that block. Current main's binary has no `Capabilities` subcommand,
so agent templates built from current main fail this probe too. Rebuilding
only KVM template 300, as the PR describes, leaves new dispatch clones
refused before registration with a misleading "rebuild template 300" error.
Existing clones are a separate population; their survival is not proof that
new dispatch admission works.

Required integration change: keep the existing `admit-job --controller`
qualification for both admissions, but perform the `merge-group-v1`
capability requirement for `Admission::Standing` only. Agent labels cannot
take a `willow-kvm` job. Preserve the agent-runner qualification and existing
mint/assignment checks. Prove this through the pre-registration production
path: an otherwise qualified agent with the old capabilities command must
reach registration, an old KVM clone must be refused before registration,
and a qualified new KVM clone must proceed. The current helper-only
`stale_template_admission_is_refused_before_minting_with_a_rebuild_reason`
test does not prove which lane calls the helper. This audit leaves the
production fix to the director's integration step.

**P1 — stale controller deployment would discard newer safety work.** Main
contains linked-clone qualification, typed agent-template selection and
retirement, JSON storage inventory, orphan-volume reservation and cleanup,
per-VMID PVE locks with a bounded poll, and the three-hour dispatch mint
budget assertion. The old PR predates these. Deploy only a newly built,
reviewed integration of current main plus this PR. Do not install the old
PR binary just because its KVM tests pass. Do not copy these authorities
into a second implementation or change authority ceilings.

**P1 — template rollout remains an explicit prerequisite.** The owner
[required the build-beside pattern for template 300 too](https://github.com/carrick-sh/carrick/issues/231#issuecomment-6565492134).
Current main's typed blue/green source selection is for **agent** templates
9000/9001; `Site::template` still returns 300 for KVM. It does not provide
a KVM source cutover merely because agent rotation is implemented. Before
rollout, the director must settle the KVM source-slot/cutover procedure and
prove linked-clone qualification with the current builder. Do not extend
agent VMIDs, reuse qualification slot 9501 for KVM, rebuild a referenced
source in place, or invent a parallel template selector in this lane.

**P2 — source merge conflict and incomplete integration evidence.** A
read-only `git merge-tree --write-tree` of the admitted head and reviewed
main reports one conflict, at the end of `tests/ci_scaler.rs`. Keep the
PR's `standing_admits_hosted_ci_main_merge_groups_only` and main's
`template_builder_refuses_existing_slot_and_accepts_the_other` plus
`template_cleanup_refuses_timeout_unfinished_and_failed_guest_exec` as separate
complete tests. Do not accept shared trailing braces or duplicate/misplaced
`#[test]` / Linux cfg attributes. Other overlapping files auto-merge; that
does not establish their semantic correctness.

**P2 — local wiring tests cannot close the live acceptance criterion.**
`merge_group_kvm_wiring_requires_receipted_hardware` checks text presence;
the closure test calls the classifier helper. The existing aggregate tests
exercise `just ci-results`, and receipt tests exercise grading separately.
They do not show GitHub scheduling, controller assignment and the required
check refusing a NEW failure as one chain. Require the live pilot below.

## Preservation inventory

Disposition describes the director's proposed integration. No production
fix has been dropped or ported in this audit commit.

| Existing change | Disposition and integration instruction |
| --- | --- |
| `ci_changes::collect_changed_paths` / `run` | **Kept:** cumulative merge-group base-to-head diff and `kvm` output; missing history must require hardware. Preserve current main's unrelated classification behavior. |
| `ci_changes::kvm_required` | **Kept:** Cargo-derived Linux closure, explicit x86/soft-CPU roots, canonical relative root, unknown-path fallback, fixture workspace coverage and innermost package ownership. Metadata/tree errors require KVM. |
| `tests/ci_changes.rs` | **Kept:** classifier, relative-root, fixture, merge-group wiring and aggregate skip/failure/break-glass witnesses. Re-prove against the final integrated workflow. |
| `ci.yml` KVM jobs / `changes` output / `ci-ok` dependencies | **Kept in patch:** merge groups only, shared lane, hosted trusted grader, restore-only cache, read-only checkout and aggregate dependencies. Director publishes protected edits. |
| `kernel-runtime.yml` KVM job | **Kept in patch:** main baseline producer uses the same lane definition; preserve all unrelated main hardware jobs and trigger guards. |
| `.github/actions/kvm-lane-receipt/action.yml` | **Kept in patch:** host verification, exact receipt/log upload, stale-output cleanup, one lane definition, caller-controlled cache publication. |
| `justfile::ci-results` | **Port onto main:** keep its newer test list and tooling changes, add only KVM aggregate and break-glass checks; do not replace the entire file from the PR. |
| `ci_scaler::Admission`, `JobPolicy`, `standing_workflow` | **Kept:** bind event to workflow and main queue namespace, preserve owner-only dispatch, deny unbound persistent merge-group policy. Keep main's template CLI additions. |
| `ci_scaler::github::workflow_runs` and tests | **Kept:** poll the two named workflow files and use the same admission for demand and actual assignment. No repository-wide run polling or replacement assignment path. |
| `ci_scaler::live` capability verdict | **Port:** retain probe/refusal semantics for KVM; narrow the call site as described above. Retain main's extracted readiness, provisioning and teardown authorities. |
| `tests/ci_scaler.rs` | **Port:** preserve both sides of the sole textual conflict; keep shared-action/pin/cache and admission tests alongside current main's builder/cleanup tests. |
| `tests/ci_cache.rs` | **Kept:** composite restore-only cache audit plus main's real-socket and concurrent compiler-cache fixtures. Both additions auto-merge. |
| `ci_receipt.rs` | **Kept:** the PR changes only its module description. Use current main's existing baseline selection, population comparison and retirement validation; do not add a second grader. |
| `AGENTS.md`, `docs/ci/contabo-kvm.md` | **Port:** preserve newer main instructions, accurately state implemented versus deployed coverage and the resolved template procedure. Correct dispatch-agent probe scope and use first-parent main baseline wording. |
| Exact `merge_group.base_sha` baseline from the earlier harvested design | **Dropped already by admitted PR:** preserve the nearest-receipted-main replacement; do not restore an exact-queue-base wait. |
| Duplicated KVM job steps from the first PR commit | **Dropped already by admitted PR:** preserve the composite action; do not restore a second lane definition. |

The full protected delta is preserved in
[`patches/kvm-merge-group.patch`](patches/kvm-merge-group.patch). It is the
binary-capable Git diff of the admitted PR against its common ancestor,
restricted to the three action/workflow files. It applies cleanly to the
reviewed main using an isolated index. It is a review artifact, not a
published workflow or a claim that the rest of the PR integrates cleanly.

## Gate and admission semantics to preserve

The candidate job produces a receipt and releases its hardware runner before
the hosted gate waits for a baseline. A failing test suite may still make
the producer job green if it wrote its receipt; the grader must then reject
NEW failures. Missing receipt/upload, setup failure or cancellation must not
turn into acceptance. The composite clears stale receipt/log directories.

The selector is built from trusted `refs/heads/main`. Starting with the
candidate's first parent, it finds the nearest shared **first-parent** main
ancestor. `ci-receipt select-baseline` walks back from there, at most 50
commits, to the nearest trusted KVM receipt. Trust requires this repository,
`kernel-runtime.yml`, main branch, exact SHA, and either a main push or an
owner-started/owner-triggered dispatch. A merge-group receipt is never a
baseline. The latest receipt-bearing run/attempt wins; an overall red
baseline can be valid differential evidence, not an absolute green result.

Missing completed runs can be covered as a range by an older receipt.
Pending runs share one bounded 90-minute wait; expiry, API/history errors,
no receipt or the walk limit refuse acceptance. Report the selected SHA and
covered range. The baseline's own lockfile and xtask do the comparison,
including missing started tests, unfinished binaries and retired-test
validation. No candidate code executes on the hosted grader as the grader.
The [recorded clarification](https://github.com/carrick-sh/carrick/issues/231#issuecomment-6564818794)
already authorizes this baseline meaning; no new exact-base exception is
needed. The base equals the selected receipt only when that base is on main
and has a suitable receipt. A queued predecessor is not a main baseline.

For a merge group with the lane enabled, `ci-results` requires both KVM jobs
successful unless `kvm` is exactly `false`. Missing/unknown output therefore
cannot excuse a skipped job. A failed `changes` job remains red regardless.
Outside the closure, PRs, or explicit break-glass require both jobs skipped.
The existing fallback treats absent KVM keys as skipped in those cases;
preserve the workflow dependency tests so removing a `needs` entry cannot
silently weaken wiring. Break-glass is `CARRICK_MERGE_GROUP_KVM=false`
(case-insensitive, matching Actions expressions), emits a warning, and is
explicitly **no KVM evidence**. `CARRICK_SELF_HOSTED_KVM=true` independently
controls main baseline production. An unset baseline producer can eventually
exhaust receipt retention/history even with a healthy candidate fleet.

Demand discovery must admit `ci.yml` only for `merge_group` on
`gh-readonly-queue/main/pr-*`; main push/owner dispatch stay bound to
`kernel-runtime.yml`. Repository, workflow ref, SHA, run and attempt must
agree again at actual assignment. A JIT registration is not a job binding:
GitHub can assign another matching-label job. Keep the existing assignment
rendezvous, controller re-vet, durable approval and row ownership. Persistent
unbound standing hooks must refuse merge groups. Keep the existing mint
exchange, per-scope budgets, revocation and registration authority untouched.
No new capability may mint dispatch credentials for a merge-group job.

## Current-main integration and rollout order

1. Director refreshes main and ownership on #231 and #1380; repeat the source
   conflict check if the tip changed. Keep the PR draft. No worker rebase or
   history rewrite is authorized for this round.
2. Integrate current main through the director-owned branch procedure.
   Resolve the single test conflict as above. Preserve main's cleanup and
   reservation sequence (`reservation_inventory`, JSON `image_inventory`,
   `clear_volumes` before closing teardown, PVE per-VMID locks and deadlines),
   typed agent template/retirement/qualification path, and mint lifetime
   assertion. Assignment authorities are unchanged between the reviewed
   ancestor and main; keep that path rather than recreating it.
3. Fix the cross-lane capabilities call site and add a production-path
   red-first pre-registration witness. Re-run focused xtask regular and
   `serial_host` suites, including `ci_changes`, `ci_receipt`, `ci_scaler`,
   `ci_scaler_hook`, `ci_cache`, and scaler library tests. Keep main's
   dispatch workflow coverage. Run actionlint, formatting, contract-change,
   source authority-debt and pre-push clippy. Re-prove classifier and NEW
   failure witnesses on the integrated head. No guest/ISA/HAL source change
   is proposed here; such additions would expand required gates.
4. Director obtains independent review of the resulting production diff
   and records the KVM template source/cutover procedure. Build the final
   integrated controller and qualified KVM template artifact with the current
   checked cleanup/graceful-shutdown builder. Qualify a real linked clone,
   including non-root KVM API 12, installed hook and capabilities output.
   Preserve the active agent source and existing linked disks.
5. Announce shared changes before deployment. Deploy only the integrated
   controller, using the existing deployment and assignment authorities;
   verify new dispatch admission and mint/cleanup behavior as well as KVM.
   Existing old KVM clones must not serve merge-group jobs with stale hooks.
   Record artifact identities and the source actually selected for new clones.
   Keep host leases per VM; take no hypervisor lease.
6. Verify/seed a trusted main KVM receipt through the existing owner dispatch
   path if necessary. Record selected baseline provenance and test population.
   Director publishes the protected workflow delta through the supported
   path, retains required `ci-ok`, and performs the pilot below. This PR's
   own workflow diff triggers KVM, so runner admission must work first.
7. Publish before/after observations on #231 and #1380, including how other
   sessions would detect breakage. Only after the pilot and exact-head gates
   may the director mark the draft ready and enqueue. A break-glass landing
   must be recorded as having no KVM evidence, not successful acceptance.

## Required live pilot and testable acceptance

- A real merge group touching `carrick-x86-cpl0` schedules both named KVM
  jobs on a Contabo clone. Capture event, cumulative base/head, closure
  output, run/attempt/SHA, actual assignment approval and runner identity.
- Capture a NEW KVM test failure in a real candidate receipt, and show the
  hosted gate and required `ci-ok` red for that exact candidate. A receipt
  fixture alone proves grading, not merge-queue refusal. Use a disposable
  director-controlled pilot that cannot land the intentional defect.
- Show a complete population with no NEW failures accepted on the same
  lane definition; missing receipt, setup failure, cancelled producer and
  missing baseline must refuse. Preserve logs even when the producer exits
  before any test starts. Do not retry a correctness failure until green.
- Test a second queued entry: the predecessor's queue SHA must not become
  baseline. Show selection of the nearest trusted main receipt and its
  covered-range notice. Exercise a pending and absent baseline in focused
  tests without extending the production wait budget.
- Verify docs-only outside-closure behavior, classifier failure, failed
  `changes`, default-on and explicit break-glass aggregate behavior. Confirm
  both required jobs remain in `ci-ok.needs` and required-check configuration.
- Refuse PR, wrong workflow, wrong queue target, unbound standing policy,
  stale SHA/attempt and stale KVM capabilities before workflow steps. Exercise
  cross-assignment, not only the job the clone was originally minted for.
- Finish with new dispatch and KVM clones cleaned through the existing
  ledger: no runner registration, orphan disk or stale reservation remains;
  do not remove another lane's clone. Confirm agent source, assignment,
  token mint/revocation and budgets were preserved.

## Local verification of the audit

All builds and test commands reused the dispatch job's VM-local gate lease
through `just lease gate`. No hypervisor custody was acquired.

- The protected patch applies to reviewed main in an isolated index and
  reproduces all three admitted action/workflow blobs exactly. The source
  merge simulation found only the test conflict documented above.
- Focused integration regular partition: `ci_cache` 13, `ci_changes` 17,
  `ci_receipt` 42, `ci_scaler` 48 passed. `ci_scaler_hook` passed 3 and failed
  `agent_auth_provisions_all_worker_credentials_and_only_agy_for_loop` at
  its `agent-runner cleanup` assertion. This audit changes no production or
  fixture code; the failure is unresolved, not excused as a passing gate.
- Focused integration `serial_host` partition: 23 passed (11 receipt,
  4 scaler, 8 hook); cache and changes have no tests in that partition.
- Scaler library regular partition: 104 passed. A single-thread library
  run selecting scaler and `serial_host` tests passed 130, with 2 ignored
  (existing runner-account and isolated-subreaper fixtures were not enabled).
- Formatting, source authority-debt ceilings and contract-change against
  reviewed main passed. The source-only debt command does not claim a
  range delta ratchet. Final pre-push clippy outcome is in the worker result.
- `just actionlint` could not run: actionlint is not installed (exit 127).
  No Docker executable is installed and HVF is unavailable on this Linux
  host. `/dev/kvm` exists; live KVM and merge-group scheduling were not run
  for this documentation audit. They remain director pilot work, not an
  unavailable-device skip.

No macOS-cfg, KVM/HAL or guest production source was changed in this audit,
so macOS cross-check, `just check-linux` and KVM crate checks were not added
to its scope. Whole-workspace domain/kernel gates remain with CI. None of
these local results establishes main integration or deployment acceptance.
