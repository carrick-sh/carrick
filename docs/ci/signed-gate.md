# Signed gate in the merge queue

`Signed gate` runs signed acceptance on every `checks_requested` merge group
for this repository's `main` queue. On one assigned Mac, under one host
lease, it builds, signs and accepts the event's **base_sha** and then the exact
group head, compares the two receipts, and posts `signed-gate` as a commit
status. The **Signed queue gate** check requires successful authorization, fixtures,
execution and verdict publication; skipped, cancelled or failed dependencies
fail it. Main's merge ruleset must require this GitHub Actions check. Its
PR-only placeholder permits enqueueing without a separate PR signed run.
There are no path filters that could leave a required group check missing.

Queue authorization is owner-approved by #1750 / #231. It requires this
repository, `checks_requested`, `base_ref=refs/heads/main`, a main queue ref
matching `GITHUB_REF`, and an exact `head_sha=GITHUB_SHA`. The event base must
be an ancestor of main. Manual gates still require `tjfontaine` as actor and
rerun actor; the agent-held `carrick-workers` App remains refused (#654).

## Paired base execution

A signed receipt depends on the Mac that ran it: a test can fail
deterministically on one gate Mac and pass on another. A base receipt from a
different host would report such a failure as NEW and eject every group
(#1884). The gate job therefore runs the merge base itself, before the
candidate, on the same Mac in the same job and under the same exclusive
`gate` lease. Both runs restore the candidate's same-run fixture bundle; when
the base checkout's fixture inputs differ from that bundle, execution is
refused instead of substituting another bundle. The receipts record the
execution host and fixture content identity, and publication compares the
candidate only with this paired base. A pair whose host or fixture evidence
still differs is reported as **INCOMPARABLE BASE — BLOCKED**, never as NEW.
No stored receipt from another run or host is downloaded.

A PR that changes fixture inputs cannot be paired this way and is blocked;
land such a change only after its fixture inputs are on main, or by owner
direction.

Every push to `main` still runs the signed phase, admits its receipt against
itself and uploads `signed-baseline-<sha>-<attempt>` (90-day retention) as
main's own evidence. Queue and PR requests do not consume it.

PRs in a batch receive the verdict comment, found through the comparison's
commits and their associated PRs. The group status and Actions summary also
link the itemized comparison and logs. A NEW failure fails **Signed queue
gate**, so the required check ejects the group instead of landing it.

## Optional PR gates and recovery

PR-time signed gates remain available on request, not as a landing
prerequisite. As the owner, apply (or remove and reapply) `gate:signed` to an
open PR targeting `main`, or dispatch the current exact head from main:

```sh
gh workflow run signed-gate.yml --ref main -f pr=123 -f sha=<40-character-sha>
```

Label authorization also checks the latest transition's actor through the
API. A stale label does not authorize a new head. A PR request executes its exact
merge base beside the head; its evidence belongs only to the requested head.
A main receipt can be regenerated, owner-only, with:

```sh
gh workflow run signed-gate.yml --ref main -f pr=main -f sha=<main-ancestor-sha>
```

## Rollout and director verification

Keep this change draft until #1668, #1572, #1736 and #1741 have their
required proofs; do not mask flipping tests. The host-read prerequisite #847
is closed, with its fix and signed population evidence on admitted main.
#1732 proposes a separate coalescing baseline dispatcher. This workflow
supplies automatic baselines directly from push events and replaces that
proposal's dispatch-token requirement. Do not enable both producers or
coalesce away a base the queue needs. Land the Rust support on trusted main
before activating the required queue check: authorization checks out main. The
director announces the shared CI change on #231 and adds **Signed queue gate**
to main's required checks (GitHub Actions source),
removing any mandatory per-PR `signed-gate` status requirement. The queue
check-response budget must cover the paired base and candidate runs.
Repo settings are not changed by this patch.

Validate on GitHub with an ARM-touching group that passes and lands, a group
whose NEW test failure is named in the PR comment and ejects it, and two
consecutive landings whose bases are supplied automatically. Linux fixtures
cover the control path; they cannot certify queue policy or live HVF runs.
The retired `gate.sh`, sweep prompt and D38 choreography are not present in
this repository; their external owners must remove that per-PR prerequisite.

## Runners and prerequisites

Register the director Mac and cloudmac with all these labels:

```text
self-hosted, macOS, ARM64, carrick-signed-gate
```

Each runner needs Apple Silicon macOS, the repository's pinned Rust toolchain
and cross targets, `cargo`, `just`, `git`, `codesign`, `dwarfdump`, `otool`,
and the same scoped sudo/cleanup configuration as the existing signed lane.
Keep Apple ld64 and debuginfo. The workflow neither installs runner software
nor changes host permissions. The runner pool serves whichever Mac is free.

The Linux ARM fixture job publishes an exact-SHA archive in the same run.
The Mac downloads that artifact and verifies both its producing SHA and fixture
input identity before restoration. No manually provisioned archive or Docker
is needed on the Mac.

GitHub assigns one job at a time to a runner. The Rust executor also holds
the machine's exclusive `gate` lease across both runs' fixture restore, `just
build`, `cargo run -p carrick-xtask -- accept --profile no-docker --phase
signed`, and independent artifact inspection. A paired job takes about twice
a single run (roughly 45-70 minutes; the job timeout is 240). Nested acceptance reuses that
lease. Both runners must share their local lease path with all other gate
participants on that host. A per-SHA Actions concurrency group with
`cancel-in-progress: false` queues duplicate requests. GitHub does not expose
`runner.name` when job concurrency is evaluated, so host serialization uses
the lease rather than an invalid runner-name expression (director ruling on
#634).

Authorization, comparison and status/comment publication
run on Ubuntu using trusted `main` code. The execution job has read-only
permissions, persists no checkout credential, and passes no GitHub token to
candidate commands. It fetches each admitted commit (base, then candidate)
into a fresh detached worktree and removes the worktree and its target
directory after copying logs. Runner operators must still treat approved PR code as code executing
on that machine.

## Evidence and verdict

`accept` performs its own signed build before testing and records the exact
artifact's SHA-256, CDHash, LC_UUID, hypervisor entitlement and
`__dof_carrick`. The executor verifies the post-gate artifact against that
receipt before releasing the lease. It independently reaps every recorded
run ID and requires an explicit zero remaining count, retaining `cleanup.json`
and per-reap logs. This avoids treating an older receipt's unknown-cleanup
zero as evidence. Missing fixture validation, required steps or scoped
cleanup counts fail receipt admission.

The trusted publication job uses the same Rust comparison as:

```sh
cargo run -p carrick-xtask -- ci-receipt signed-diff \
  --base base.json --candidate candidate.json --json diff.json
```

The CLI prints Markdown and exits nonzero for FAIL. Every step reports base
and candidate started-test counts, finished binaries, unfinished binaries,
unitemized failures, and itemized `failed_tests` NEW/FIXED sets. EL1
`failed_tests` and `unexpected_failures` are included separately. Keys come
from structured fields, never human `failures` strings. FIXED is an observed
set difference and is not proof that a killed binary recovered.

PASS requires no new itemized or unitemized failures, no newly unfinished
binary, no missing step, no smaller started-test or finished-binary
population, and no disappeared completed binary. New probe diffs or cleanup
failures also fail. The execution job must finish successfully and its receipt
must pass admission. Existing main test failures do not alone reject a PR.

Artifacts are `signed-request-<attempt>`, `signed-result-<attempt>` (candidate
receipt, identity and logs; the paired base's in `base/`), and `signed-verdict-<attempt>` (comparison JSON and PR
comment Markdown). Evidence is retained 30 days; main baselines 90 days.
The PR comments and Actions summary link the run and name NEW/FIXED tests.
A failed execution with no receipt still gets a failure status and an explanatory comment when the publication job runs.
An authorization failure cannot publish a verdict. A cancelled workflow can
prevent publication; inspect the Actions conclusion and dispatch again.

The first live signed run is the director's macOS validation. Linux tests
cover the receipt and Actions control logic; they cannot validate HVF,
codesigning, local fixture provisioning or runner registration.
