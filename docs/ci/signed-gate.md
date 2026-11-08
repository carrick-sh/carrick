# Signed gate in the merge queue

`Signed gate` runs signed acceptance on every `checks_requested` merge group
for this repository's `main` queue. On one assigned Mac, under one host
lease, it builds, signs and accepts the event's **base_sha** and then the exact
group head, compares the two receipts, and posts `signed-gate` as a commit
status. The **Signed queue gate** check requires successful authorization, the
trusted base fixture fetch, execution and verdict publication; skipped, cancelled or failed dependencies
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
`gate` lease. The receipts record the execution host and fixture content
identity, and publication compares the candidate only with this paired base.
A pair whose host or fixture evidence still differs is reported as
**INCOMPARABLE BASE — BLOCKED**, never as NEW. No stored receipt from another
run or host is downloaded.

**Fixture authority comes from main, never from the candidate** (#1889).
The `base-fixtures` job runs trusted `main` code that finds the
`kernel-runtime.yml` run which built exactly the merge base, and checks that
run's workflow path, `main` branch, head SHA, repository and event (a push,
or an owner dispatch). It downloads only that run's `signed-fixtures-<base>`
artifact, waiting up to 75 minutes while main's publisher may still upload
it, and fails when no such bundle exists. Both paired runs restore this one
bundle: the base checkout must match it exactly, and the candidate checkout
must have equal fixture inputs. Fixture builds are not bit-reproducible (two
main bundles with identical inputs differed in 19 of 1195 executables), so a
second, candidate-built bundle would never have equal `content_sha256`;
publication still requires equal content and input identity.

**An incomplete base blocks.** Completed tests with known failures stay
comparable, because the gate is differential. A base step that did not run
to completion (a killed or unfinished binary, a build failure, zero tests
selected), tests skipped after the binary budget expired, or a failing
acceptance exit that no completed failure explains is refused before any
comparison, in the executor and again at publication. A missing base result
can therefore never read as FIXED.

**The base evidence is sealed before candidate code runs.** Immediately after
the base run the executor records a SHA-256 inventory of every file under
`base/` in its own memory. After the candidate run and its cleanup it
re-inventories `base/` and refuses any changed, missing or added file; only
then does it write `base-seal.json`, replacing anything planted at that path.
Publication checks that record against the base evidence it loads. This
protects the baseline against candidate-phase writes, including accidental
ones; a candidate process that outlives its run and rewrites both the
evidence and the record before upload would need process or storage
isolation, which this lane does not provide.

### Owner exception: PRs that change fixture inputs

A PR that changes fixture inputs (probe sources, fixture lockfiles, the
compiler pin or build policy) cannot pass this gate: main has no bundle for
its inputs, and comparability is never relaxed for it. Do not retry, rebuild
the bundle from candidate code inside the gate, or edit the comparison. Land
such a change only through this owner-approved exception:

1. Keep the fixture-input change in its own small PR, with no unrelated
   runtime changes, so the unverified surface is only the fixtures.
2. The owner records the exception on the PR and in the decision log (#231),
   naming the exact head SHA.
3. Independent fixture evidence: publish a bundle for that exact head on a
   trusted Linux ARM host (`just fixtures-publish <sha>`), restore and verify
   it on a gate Mac (`just fixtures-restore`, `just fixtures-verify`), and
   attach the bundle's manifest and content SHA-256 to the PR.
4. Exact-head signed validation on that Mac with that bundle:
   `just accept --profile no-docker --phase signed` on a detached checkout of
   the head, with every step finished (no `NotRun`, no unfinished binary)
   and its itemized failures reviewed by the owner against main's latest
   signed results from the same Mac. This is owner review, not a gate PASS.
5. The owner lands the PR by explicit admin direction (the AGENTS.md
   admin-merge rules apply). The landing push makes main publish its own
   bundle for the new inputs.
6. Post-landing queue validation: the next merge group's **Signed queue
   gate** must pass on the new base with main's new bundle. If it does not,
   fix forward on main before landing anything else.

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

The conventional scratch mount `/Volumes/carrick` is automatically considered
only when cached mount metadata identifies a local filesystem and public
volume properties identify internal, non-removable storage (#1727). External
USB storage is skipped without creating the case-probe file there. Unknown
or timed-out classification also falls through to the existing scratch default.
On cloudmac, set `CARRICK_HOME` to an internal case-sensitive directory so
`$CARRICK_HOME/scratch` is usable; explicitly configured roots are not classified.

main's Linux ARM fixture job (`kernel-runtime.yml`) publishes an exact-SHA
archive on every push to main. The `base-fixtures` job fetches the merge
base's archive from that authenticated run; the Mac verifies its producing
SHA and each checkout's fixture input identity before restoration. No
manually provisioned archive or Docker is needed on the Mac.

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
must pass admission, and the paired base must be complete and match its
seal. Existing main test failures do not alone reject a PR.

Artifacts are `signed-request-<attempt>`, `signed-base-fixtures-<attempt>`
(the trusted base bundle and its `provenance.json`), `signed-result-<attempt>`
(candidate receipt, identity and logs; the paired base's in `base/`, sealed by
`base-seal.json`), and `signed-verdict-<attempt>` (comparison JSON and PR
comment Markdown). Evidence is retained 30 days; main baselines 90 days.
The PR comments and Actions summary link the run and name NEW/FIXED tests.
A failed execution with no receipt still gets a failure status and an explanatory comment when the publication job runs.
An authorization failure cannot publish a verdict. A cancelled workflow can
prevent publication; inspect the Actions conclusion and dispatch again.

The first live signed run is the director's macOS validation. Linux tests
cover the receipt and Actions control logic; they cannot validate HVF,
codesigning, local fixture provisioning or runner registration.

## Disk admission and build leases (#1693)

Disk admission now takes exclusive host custody before measuring free space.
Shared builds drain before the floor is checked; a shortage on the admitted
host still fails with free GiB and floor GiB. The HVF checkout bootstrap and
PR bootstrap use the installed `/usr/local/bin/carrick-xtask` supervisor;
install it before enabling this workflow on a gate host. The HVF checkout
xtask lives in `target/lease-tools` so the debug-tree prune cannot remove it.

See [build admission and remaining direct-script limits](../host-lease-containment-follow-up.md#disk-admission-and-build-leases-1693)
for the lock order, standalone build admission, and the direct signed-script
bootstrap gap still requiring closure before cloudmac returns to the pool.
