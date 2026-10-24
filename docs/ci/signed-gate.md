# On-demand signed gate

The `Signed gate` workflow runs the macOS signed acceptance phase for an exact
PR head and posts a `signed-gate` commit status, a PR comment, and downloadable
receipts and logs. It survives the director session. This is step 1 of
[#634](https://github.com/carrick-sh/carrick/issues/634); it does not enqueue or
merge the PR.

Only `tjfontaine` may trigger or rerun it. The `carrick-workers` App is held
by agents and worker VMs, so admitting it would let agent-written code run on
a gate runner at the agent's own request (#654). Other actors fail
authorization on Ubuntu before reaching a self-hosted runner.
For `gate:signed`, authorization also checks the latest label transition's
actor through the GitHub API. A label left over from a previous head does not
authorize a changed head.

## Trigger a PR gate

Apply `gate:signed` to an open PR targeting `main`, as the owner or App.
Remove and reapply the label to request another run. Alternatively dispatch
from the **main** workflow ref, supplying the PR's current full head SHA:

```sh
gh workflow run signed-gate.yml --ref main -f pr=123 -f sha=<40-character-sha>
```

The authorization job verifies the SHA against the current PR head. A head
change during authorization requires a new request. A subsequent head change
does not retarget an admitted run: its status and receipt belong to the
original SHA.

## Seed the merge-base baseline

A PR compares against the newest nonexpired `signed-baseline-<sha>-<attempt>`
artifact for its **exact merge-base with main**, from an authorized completed
`Signed gate` dispatch on `main`. Baselines from other workflows, branches,
SHAs, actors or unauthorized reruns are refused. Itemized test failures,
unfinished binaries and unitemized failures on main
remain in the baseline; the candidate must preserve its populations and may
not add to those failure sets. Missing required suite populations cannot
seed a baseline.

If no baseline exists, authorization fails with an instruction to seed it:

```sh
gh workflow run signed-gate.yml --ref main -f pr=main -f sha=<merge-base-sha>
```

`pr=main` accepts only a main ancestor, runs the same signed phase and uploads
the admitted baseline (90-day retention). Rerun the PR request afterward.
There is no fallback to a nearby SHA or stored failure-name list. Main can be
seeded on demand; this workflow does not install a nightly schedule.

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

Fixtures are built per run. The `fixtures` job runs `just fixtures-publish
<sha>` for the authorized SHA on a hosted, ephemeral `ubuntu-24.04-arm` runner
with no secrets, and uploads the archive as `signed-fixtures-<sha>-<attempt>`.
The Mac gate job downloads it, checks its transport digest
(`scripts/ci/download-fixture-bundle.sh verify`) and passes its path as
`CARRICK_SIGNED_FIXTURE_BUNDLE`. Restore then re-verifies the archive's
fixture **input identity** against the candidate tree in a fresh worktree; it
never uses Docker. No static per-Mac bundle is needed, so fixture-input
changes no longer require manual provisioning.

GitHub assigns one job at a time to a runner. The Rust executor also holds
the physical host's exclusive `gate` lease across fixture restore, `just
build`, `cargo run -p carrick-xtask -- accept --profile no-docker --phase
signed`, and independent artifact inspection. Nested acceptance reuses that
lease. Both runners must share their local lease path with all other gate
participants on that host. A per-SHA Actions concurrency group with
`cancel-in-progress: false` queues duplicate requests. GitHub does not expose
`runner.name` when job concurrency is evaluated, so host serialization uses
the lease rather than an invalid runner-name expression (director ruling on
#634).

Authorization, baseline download, comparison and status/comment publication
run on Ubuntu using trusted `main` code. The execution job has read-only
permissions, persists no checkout credential, and passes no GitHub token to
candidate commands. It fetches the admitted commit into a fresh detached
worktree and removes the worktree and its target directory after copying
logs. Runner operators must still treat approved PR code as code executing
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

Artifacts are `signed-request-<attempt>`, `signed-result-<attempt>` (receipt,
identity and logs), and `signed-verdict-<attempt>` (comparison JSON and PR
comment Markdown). Evidence is retained 30 days; main baselines 90 days.
The PR comment links the run. A failed execution with no receipt still gets
a failure status and an explanatory comment when the publication job runs.
An authorization failure cannot publish a verdict. A cancelled workflow can
prevent publication; inspect the Actions conclusion and dispatch again.

The first live signed run is the director's macOS validation. Linux tests
cover the receipt and Actions control logic; they cannot validate HVF,
codesigning, local fixture provisioning or runner registration.
