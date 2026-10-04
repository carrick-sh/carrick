# PR and merge queue migration

Status: proposed; owner approval and director configuration required. This change
adds workflow code and a plan only. It does not protect `main`, register runners,
configure environments, enqueue a PR, or change repository settings.

## Workflow and evidence

Extend `.github/workflows/ci.yml`. Replacing its existing native ARM job and
augmenting its existing x86 cross-check avoids a second workflow repeating those
runner setups and kernel suites. Existing macOS source, license and cross-platform
checks remain. The Mac jobs share setup, cleanup and artifact upload through a YAML anchor,
with literal `macos-host` and `signed` check names even when skipped on PRs.
GitHub supports [workflow anchors and aliases](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations). `kernel-runtime.yml` remains a separate
scheduled diagnostic workflow, not merge-queue acceptance.

`pull_request` and `merge_group: checks_requested` targeting `main` run hosted
checks against the event's checkout SHA. There are no path filters. Native
`ubuntu-24.04-arm` runs `just accept --profile linux-portable` (including
`just fmt-check` and `just test-kernel`), plus `just clippy`, `just test`,
`just lint-domains` and `just doc`. The x86 `ubuntu-24.04` job opens `/dev/kvm`,
checks API version 12, builds `carrick-x86-cpl0` for `x86_64-unknown-none`
and the static musl hello fixture, and runs the x86
engine library and `carrier_cpu`, `cpl0_entry`, `live_vcpu_x86`, `sentinel_decode`
KVM suites. Missing hardware, inaccessible devices, missing fixtures or a reported
`SKIP:` fail the job. ARM hosted checks do not claim ARM KVM execution.

`macos-host` and `signed` run `just accept --phase host` and
`just accept --phase signed`, respectively, only for merge groups and authorized
manual runs. Both need the hosted ARM and KVM jobs to pass first. Manual dispatch
is limited to `refs/heads/main`; a hosted job checks both the initiating actor
and rerun actor for repository `maintain` or `admin` roles. An API error denies
execution. The permission endpoint needs only repository metadata read, implicit
in the read-only GitHub installation token. No PAT is supplied to the jobs.

The Mac jobs use `[self-hosted, macOS, ARM64, carrick-signed]`; the host job
also requires `macos-host`. The signed job follows the host job. Cross-run Mac
concurrency never cancels an active job. Before signed execution,
`just lease docker just land-provision all` builds fresh native ARM Linux fixtures
and probes under an exclusive lease. Provisioning uses Docker to build artifacts,
not to execute the oracle. Then accept holds its own exclusive gate lease across
build, signing, tests, cleanup and receipt publication. Never wrap accept in a
shared `just lease carrick` lease: that would require an unsupported upgrade.
Additional guest diagnostics, if added later, must use `just lease carrick`.
Docker oracle runs remain a separate director-owned, sequential phase.

`CARRICK_RUN_ID` includes Actions run ID, attempt and job/phase. Accept currently
assigns its own per-step `accept-<timestamp>-<step>` IDs. The always-run cleanup
extracts those exact IDs from the complete console log and calls
`scripts/sudo/kill.sh <run-id>` for each, including `-cli` children and the outer
Actions ID. It records failures and counts; it never uses `pkill`. This also
covers cancellation before accept publishes a receipt. A machine crash can
prevent any `always()` step: the director must inspect/reap recorded IDs before
returning that host to service.

Artifacts named `<check>-<event-sha>-<attempt>` retain the entire
`target/el1-gate/` tree (including `<short-sha>/receipt.json` and every step log),
console/provision/cleanup logs and signed artifact manifests, for 30 days.
Logs are not truncated and uploads run even after failure. Each accept job
asserts a clean PASS receipt for its exact checkout SHA and profile/phase. Separate Mac jobs
upload separate artifacts so their receipts do not overwrite each other.
The directory uses Git's abbreviated SHA; the receipt records the full HEAD.
Receipts are evidence for that checkout/artifact, not transferable to another
merge group or to a re-signed binary.

## Ruleset for the director to apply after approval

Create an active repository branch ruleset named `main-merge-queue`, targeting
exactly `refs/heads/main`. First verify merge queue is available for this
repository/account; GitHub documents availability for public organization-owned
repositories. A public personal repository alone does not establish eligibility.
If unavailable, stop activation and ask the owner about organization ownership;
do not silently replace the queue with auto-merge or direct pushes.

Require a PR, at least one independent approving review, dismissal of stale
approvals, approval of the latest reviewable push and resolution of review
conversations. Require code-owner review once the owner supplies the director's
actual GitHub user/team and a reviewed CODEOWNERS file (especially for
`.github/`, `scripts/`, `justfile`, toolchain files and acceptance policy).
Workers must not approve/enqueue their own changes. Do not require the PR branch
to be up to date before enqueueing: the queue tests the combined SHA.
Block deletion and force pushes; require linear history and the merge queue.
No direct push to `main` is part of the normal flow.

Required checks, bound to the **GitHub Actions** app, by exact job/check name:

| Check | PR | Merge group |
| --- | --- | --- |
| `host-linux-arm64` | success | success |
| `host-linux-x86-kvm` | success | success |
| `macos-host` | intentionally skipped | success |
| `signed` | intentionally skipped | success |
| `merge-queue` | success | success |

`merge-queue` is an always-run hosted aggregate. It also requires the retained
macOS source, license, FreeBSD and NetBSD checks, and authorization, to succeed.
On merge groups it requires the both Mac jobs to succeed; a skipped,
failed, cancelled or unauthorized Mac tier is a failure. GitHub accepts skipped
required jobs, so requiring just `signed` would allow a skipped dependency to
look green. Never remove the aggregate from required checks. Confirm the names
and GitHub Actions app IDs in a real PR and merge-group check run before enforcing
them; neither a workflow title nor a step name is a check context.

Queue settings:

- Merge method: **squash**, retaining Why/What/Verified and agent trailers in the
  resulting commit. Keep rebase available for owner-directed exceptional use;
  both preserve linear history, but the queue uses squash consistently.
- Maximum merge batch: **4 PRs**. Minimum: **4**, with a **5 minute** wait for that
  population, after which smaller batches may merge. These are merge limits,
  not a promise that four PRs share one CI build.
- Build concurrency: **1 merge group**, initially, because the two Macs and the
  host lease are the scarce resource. The Mac jobs also share a concurrency group. Do not
  increase concurrency or shorten evidence to hide a capacity problem.
- Status-check timeout: **360 minutes**. Hosted prerequisites, two Mac phases
  (each capped at 240 minutes), and environment approval can exhaust this;
  observe actual gate duration before activation. If normal duration cannot
  fit the chosen queue timeout, resolve capacity/gate cost before enabling;
  do not turn a timeout into a skip or retry-until-green policy.
- Require every queued PR's checks to pass ("only merge non-failing pull
  requests" on). Do not accept a failed PR just because a later group is green.
- Bypass: **owner only**, using a named emergency identity, never workers,
  general write collaborators, GitHub Actions or all administrators. Use
  PR-only bypass where supported. Record the incident and the exact acceptance
  receipt before any emergency merge. Routine director merges use the queue.

GitHub's [merge queue documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue)
distinguishes merge limits, build concurrency and status-check timeout. The queue
rebuilds groups after a failure or reorder; earlier PR receipts do not substitute
for acceptance of the new combined SHA.

## Public repository security and activation order

Treat queued source as privileged code: Rust build scripts, tests, scripts and
workflow steps all execute arbitrary code as the runner account. Carrick is
experimental and is not a hardened boundary for hostile guests. Code review
before enqueueing is the trust decision, even when the PR originated in a fork.
`contents: read`, SHA-pinned actions, credential-free checkout, no self-hosted
PR caches, event guards and hosted permission checks reduce exposure; they do
not sandbox the host. Artifact uploads contain public logs: supply no secrets
that a test could print.

The explicit event guard ensures this committed workflow never routes a
`pull_request` to a Mac. **A PR can edit that guard or add another workflow.**
Repo-scoped runner labels are routing metadata, not an access-control boundary.
Protected environments can also be omitted by malicious YAML. Do not assert
that these alone make self-hosted public-repository runners safe. GitHub
[warns about persistent compromise of public self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use).

Before any runner is online, the director, after owner approval, must:

1. Review and land this bootstrap workflow through a PR using the existing
   acceptance procedure; until that happens `main` remains unprotected.
2. Set fork-workflow approval to **all outside collaborators**, and prohibit
   approving a fork run until reviewing its workflow changes, local actions,
   invoked scripts and build inputs. Reject any PR execution targeting a
   self-hosted label or attempting another privileged event. First-time-only
   approval is insufficient. Do not add `pull_request_target` execution of
   PR code or a `workflow_run` bridge to self-hosted machines.
3. Configure `carrick-trusted` with required director/owner environment reviewers,
   no secrets and no administrator bypass. Allow `main` and
   `gh-readonly-queue/main/*` refs; verify approval of a merge group before
   enabling the ruleset. These are job approval gates, not VM isolation.
4. Install CODEOWNERS with the owner's approved identity and enforce the review
   rules above. Audit *all* repository workflows and write-capable collaborators.
   Do not give workers enqueue rights beyond the reviewed operating procedure.
5. Isolate the runner accounts and obtain explicit owner acceptance of residual
   risk. With repo-scoped runners there is no enforced selected-workflow
   allowlist. If the owner needs that guarantee, use a separately approved
   architecture such as organization runner groups restricted to trusted
   workflows, or externally gated isolated machines; do not activate this plan
   on the director's everyday account and call it secure.
6. Keep the old `carrick-hvf`/`carrick-kvm` labels off these new registrations.
   Disable old scheduled hardware execution on a shared gate host before
   cutover (the director manages existing variables/registrations), or move it
   to separate hosts. `kernel-runtime.yml` predates this full gate lease flow;
   its bare host/build work must not compete with queue acceptance.
7. Test hosted PR checks, unauthorized manual dispatch, an authorized manual
   gate, failure/skip/cancellation propagation, full logs and scoped cleanup.
   Bring up the ruleset, enqueue a reviewed test PR and confirm the exact
   merge-group receipt/artifact identity. Enable ordinary queue landings only
   after that end-to-end exercise; this Linux validation cannot prove it.

## Runner installation: cloudmac and the director's Mac

These are instructions for the director, not actions taken by this change.
Use one dedicated non-admin macOS account and **one runner process per physical
Mac**, repo-scoped to the owner's actual GitHub `OWNER/REPO`. Keep source review,
SSH identities, signing certificates, personal keychains and unrelated work out
of that account. Ad-hoc Carrick signing needs no private signing key. Preserve
only narrowly approved sudo diagnostics; no general passwordless sudo. Both
machines need real Apple Silicon HVF capability, Apple ld64/Xcode tools, a
sufficient hard file limit for `ulimit -n 65536`, native ARM Docker for provisioning,
Rust 1.96.0 with `rust-toolchain.toml` targets/components, just, cargo-deny,
Semgrep, jq, Python and existing signing/debug tools. Never use lld for Mach-O.

Use **non-ephemeral registration initially**: there is no authorized automation
here to reimage/re-register physical Macs after each job, and losing registration
after a host job would strand its signed partner. Persistent registration is a
maintenance choice, not a security claim. Ephemeral registration alone does not
clean a host. A future ephemeral lane needs automated replacement of the entire
machine/account plus external log retention before it can replace this service.
Rebuild fixtures/probes each signed job, retain no public-PR caches, and reset the
account/machine after suspected compromise.

For each machine, download the current **macOS ARM64** runner tarball and verify
the SHA-256 displayed by the repository's Settings → Actions → Runners → New
self-hosted runner page. Extract to a dedicated account-owned directory, e.g.
`~/actions-runner-carrick`. Use a short-lived **repository registration token**
obtained by the director; never store a PAT in the runner service. In a terminal
logged in as that account, use the page's token interactively:

```sh
cd ~/actions-runner-carrick
# Built-in default labels are self-hosted, macOS, ARM64; retain them.
# Substitute cloudmac-carrick or director-mac-carrick as appropriate.
./config.sh --url https://github.com/OWNER/REPO \
  --name cloudmac-carrick --labels carrick-signed,macos-host --work _work
./svc.sh install
./svc.sh start
./svc.sh status
```

Do **not** pass `--ephemeral`, `--no-default-labels`, `--replace` or an
organization URL. Never use `sudo ./svc.sh` or a system LaunchDaemon. GitHub's
[macOS service implementation](https://github.com/actions/runner/blob/main/src/Misc/layoutbin/darwin.svc.sh.template)
installs under `~/Library/LaunchAgents` and rejects root. Ensure the account's
user launchd session exists; test startup after logout/reboot and document the
login/session procedure on a headless cloudmac. Configure the service PATH to
include the approved tool locations (`~/.cargo/bin`, Homebrew, Semgrep), then
restart and confirm its environment with a maintainer dispatch. User services
are not a promise of pre-login availability.

Both accounts and all local gate/Docker processes must use the same absolute
`CARRICK_HOST_LEASE_PATH` **on each physical host** and have permissions to that
same lock file. Do not give each checkout/account a private lease path. Export
it in the user service environment and the director's local shells. Never unlink
a live lease file. Accept inherits an exclusive descriptor into signed scripts;
there is no shared-to-exclusive upgrade. Keep one runner per host even if labels
match both jobs. Do not share the remote-accept worktree: Actions
uses its own checkout, while the lease coordinates physical host access.

## Worker/director flow and retained tools

Workers finish scoped changes, run local gates, commit with agent trailers,
push their feature branch and use `gh pr create --base main --head <branch>`
with Why/What/Verified and evidence links. They never push `main`, create
`land/batchN`, or merge their own work. The director reviews the diff and
hosted checks, then enqueues the reviewed PR in the GitHub UI or with
`gh pr merge <number> --auto` (without `--admin`). The queue determines the
combined tree and runs fresh acceptance; a failed group returns to review.
Squash messages must preserve authorship trailers and validation limits.

`land/batchN` integration branches and routine per-worker `remote-accept`
landing receipts are replaced by PRs plus merge-group artifacts. Keep
`just accept` for local feedback, reproductions and emergency gates;
`just accept --profile linux-portable` remains Linux worker feedback.
Keep `remote-recapture` for compiler-authoritative inventory patches from
cloudmac, applied and committed locally before pushing a PR. Keep `remote-accept`
available for diagnosis/bootstrap/rollback, not a substitute for a queued check.
The director still owns oracle runs and runtime diagnosis.

Proposed concise AGENTS.md amendment (apply at cutover, not before):

```diff
@@ Directing workers is reviewing diffs, not reading reports
-- Linux workers run `just accept --profile linux-portable`, then `just remote-accept --ref <their commit> --phase host` before reporting review-ready; macOS/ARM changes also require `--phase signed` coordinated with the director. Include both verdicts and receipt paths. macOS workers run `just accept`.
+- Workers run local `just accept` (Linux: `--profile linux-portable`), push a feature branch, and open a PR with `gh pr create`; include receipts and platform limits. No `land/batchN` or direct main pushes.
+- The director reviews diffs and hosted checks, then enqueues the PR. Merge-group host/signed artifacts are landing evidence for the combined SHA; skipped signed jobs never authorize a landing. `remote-recapture` remains available; `remote-accept` is diagnostic/bootstrap/rollback only.
@@ Commits, hooks & CI
+- Land through the main merge queue after director review; never push main or use `--admin` for routine work. Preserve Why/What/Verified and agent trailers in squash commits.
+- Require `host-linux-arm64`, `host-linux-x86-kvm`, `macos-host`, `signed`, and `merge-queue`; the aggregate requires real Mac success on merge groups. Run local `just ci` before feature-branch pushes; never bypass hooks.
```

## Rollback

Freeze enqueueing and remove affected PRs from the queue. Stop both user services
with `./svc.sh stop` before editing trusted workflow guards. Collect complete
Actions artifacts and acceptance run IDs, reap only those IDs, inspect the Macs,
and reset compromised runner accounts/machines before restart. Do not delete a
live host lease or kill unrelated Carrick processes.

The director restores the recorded pre-cutover ruleset/settings and legacy
hardware scheduling only after owner approval. Prefer keeping PR review and
hosted required checks while disabling the queue; use owner emergency PR bypass
plus director `just accept`/`just remote-accept` on the exact proposed landing.
If direct landings are explicitly reinstated, restore `land/batchN` and the old
AGENTS wording together with their acceptance procedure. Revert the workflow via
a reviewed PR, retain receipts, and do not treat a rollback as permission for
workers to push main. To retire registrations, stop/uninstall the user services
and remove the repo runners using a fresh removal token; no system service exists.

## Local verification record

The development VM is Linux x86_64. Native ARM hosted execution, Apple Silicon
HVF/signing, GitHub check contexts, merge groups, environments and user services
require the director's activation exercise. No Docker oracle run is authorized
on this VM. Local command results and receipt paths belong in the commit/work contract;
a cross-compile is not native ARM execution.

Local checks completed while preparing the workflow:

- Actionlint 1.7.12 validates all workflows with `.github/actionlint.yaml`
  registering only the known custom labels for validation.
- Extracted workflow scripts pass nine aggregate-result scenarios, maintainer
  dispatch/denial scenarios, a missing-device KVM scenario and exact cleanup
  ID extraction. These are local simulations, not GitHub execution.
- `/dev/kvm` opens on this VM and reports API version 12; this preflight
  creates no VM and does not claim a KVM guest suite pass. Both required x86
  images also build locally; the first portable gate exposed the missing CPL0
  image, which is now built explicitly before hosted KVM execution.
- `just ci` reaches `just doc`, then fails on existing rustdoc issues in
  `carrick-mmu-core/src/aarch64.rs` (unresolved links) and
  `carrick-signal-core/src/{policy,timer,wait}.rs` (bare URLs). The strict
  documentation gate remains in the workflow. The director confirmed main
  already has CI failures and assigned their repair separately.
- Portable acceptance and remaining host-suite results are recorded in the
  worker report with their exact SHA and receipt/log paths. No signed/HVF
  gate or Docker oracle execution was performed on this VM.
