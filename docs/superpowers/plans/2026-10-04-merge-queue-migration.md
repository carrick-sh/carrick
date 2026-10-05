# Hosted CI and merge queue migration

Status: workflow implementation for the owner-approved runner-first direction
in [PR #4](https://github.com/carrick-sh/carrick/pull/4). This supersedes the
workflow proposal in [PR #2](https://github.com/carrick-sh/carrick/pull/2).
Repository settings and runner registration are owner/director actions, not
changes made by this PR. Full runtime acceptance remains with the director
until the hardware lanes are qualified.

## Parallel hosted checks

All `run` steps in `ci.yml` call `just` recipes. Toolchain setup reads
`rust-toolchain.toml`, including its components and targets; YAML carries no
second Rust version. Actions retain PR #2's immutable pins and read-only token;
checkout does not persist credentials. Every job has a timeout: 60 minutes on
macOS, 30 on Linux, and 5 for filtering/aggregation.

| Job | Recipes / evidence |
| --- | --- |
| `lint` (Ubuntu) | `fmt-check`, one `deny`, `check-matrix`, `check-layering`, PR `check-contract-change`, `lint-domains-source` (including contract registry on every event) |
| `portable` (Ubuntu x86_64) | `check-kernel-portable` for aarch64 Linux, native `test-kernel-semantics` |
| `linux-doc` (Ubuntu) | `doc` for the Linux crate set, including Linux host/KVM documentation hidden from the macOS build |
| `cross-check-linux` (Ubuntu) | `check-linux`, `test-host-linux` |
| `kernel-linux-native` (Ubuntu ARM64) | Existing native `test-kernel-semantics`; no hardware virtualization needed |
| `cross-check-freebsd` (Ubuntu) | Existing `check-freebsd` CLI/runtime/tests closure, permanent-archive sysroot |
| `cross-check-netbsd` (Ubuntu) | Existing `check-netbsd` NVMM/tests closure |
| `macos-clippy` (`macos-15`) | `clippy`, `lint-domains-host` live compiler census |
| `macos-build` (`macos-15`) | `check --workspace`, `doc`, `check-fuzz` |
| `macos-unit` (`macos-15`) | `test` with existing fd-limit setup |
| `macos-integration` (`macos-15`) | `test-integration` with existing fd-limit setup |

The four Mac jobs use the same rust-cache `shared-key`, so they can reuse a
compatible dependency cache without serial dependencies between jobs. Cold jobs
still compile independently; the cache is an optimization, never evidence.
`if: !cancelled()` on check steps allows independent checks to report after an
earlier failure in the same job, without `continue-on-error`. A recipe's own
internal prerequisite ordering remains intact. Setup failures also remain red.
The Linux doc job does not claim rustdoc coverage of FreeBSD/NetBSD-only cfgs;
those platforms retain their existing compile checks.

The baseline [run 37248340573](https://github.com/carrick-sh/carrick/actions/runs/37248340573)
spent about 29 minutes in one serial macOS job. The new critical path is the
longest parallel job plus filter, aggregate and queue/setup time. Hosted run
links and observed durations belong in the PR verification record, with cold
cache and unrelated source failures distinguished from a green timing result.

## Events, docs fast path and the one required check

Events are `pull_request`, `merge_group: checks_requested`, push to `main`,
manual dispatch and the existing 07:00 UTC nightly schedule. Each checks out
its event SHA, including the combined queue SHA. Concurrency groups include
event and ref. Only superseded PR runs are cancelled; main and merge groups
never cancel an active run.

The `changes` job diffs a PR base against its checked-out merge result. Only a
nonempty diff containing exclusively `docs/**` or Markdown files (`*.md` at any
depth) skips heavy jobs. Deleted paths count, and rename detection is disabled
so moving source into documentation cannot hide a source deletion. Invalid or
missing bases fail the filter; empty diffs conservatively run all checks.
Non-PR events always run everything, including docs-only merge groups.
There is no workflow-level paths filter that could leave a required check pending.

**The only required check name is `ci-ok`, bound to the GitHub Actions app.**
Its job has `if: always()` and explicitly needs `changes` and every check job.
`just ci-results` verifies the full needs-result object:

- A successful filter with `heavy=true` requires every check to succeed.
- A successful PR filter with `heavy=false` requires every heavy job to be
  skipped. This is the only accepted skip.
- A failed/cancelled filter, missing/invalid output, failed/cancelled check, or
  unexpected skipped check fails the aggregate. Cancellation of the aggregate
  itself cannot authorize a merge.

Requiring only individual jobs is insufficient because GitHub accepts skipped
required jobs. Do not require the old `check`, `deny`, `merge-queue`,
`host-linux-arm64`, `host-linux-x86-kvm`, `macos-host` or `signed` names from PR #2.
Do not require the workflow title `Hosted CI`; it is not the check name.

## Owner-applied ruleset

After observing real checks and reviewing the diff, the owner configures a
branch ruleset `main-merge-queue` targeting exactly `refs/heads/main`:

1. Require pull requests, at least one independent approving review, dismissal
   of stale approvals, approval of the latest reviewable push, and resolution
   of review conversations. Require code-owner review once the owner supplies
   the actual review identity and reviewed CODEOWNERS file. Workers never
   approve, enqueue or merge their own changes.
2. Require **`ci-ok`** from **GitHub Actions**. Confirm its exact context and app
   on a live PR and a controlled merge-group run. Remove superseded required
   check names as part of the same settings change. Do not require an up-to-date
   PR branch: the queue checks the combined tree.
3. Require the merge queue, linear history, and block force pushes/deletion.
   No direct worker pushes to `main`. Confirm queue availability for the
   repository/account before activation; lack of queue support is not license
   to substitute direct pushes or ordinary auto-merge.
4. Queue merge method **squash**; retain Why/What/Verified and authorship trailers.
   Start with build concurrency **1** merge group, maximum merge batch **4**,
   minimum **4**, and a **5 minute** wait before allowing smaller batches.
   Enable **Only merge non-failing pull requests**. Merge limits do not combine
   builds; do not assume four PRs share one CI run.
5. Use a **90 minute** hosted status-check timeout initially (60-minute Mac
   job budget plus setup/aggregation/queue headroom). Measure actual run and
   queue times before activation; revisit capacity if normal work cannot fit.
   Reassess this limit when hardware acceptance is integrated.
6. Limit emergency bypass to the owner's named identity, PR-only where
   supported, with an incident record and exact acceptance evidence. No worker,
   general collaborator, Actions-app or blanket administrator bypass.

These controls follow GitHub's [merge queue documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).
The workflow itself neither creates nor activates this ruleset.
Before ordinary queue landings, exercise success, docs-only PR skips, failed
checks, cancellation and a fresh merge group. Keep ordinary enqueueing paused
where the runner-first plan still lacks required hardware acceptance. Hosted
`ci-ok` is source/host evidence, not signed HVF or real KVM acceptance.

## Hardware hook-in and PR #2 carryover

`kernel-runtime.yml` stays byte-for-byte unchanged. Adding `merge_group` now
is unsafe: there is no available hardware runner. With `CARRICK_SELF_HOSTED`
false, its jobs skip and prove nothing; if enabled prematurely, physical-runner
jobs queue indefinitely. A job timeout does not provide a bounded runner wait.
Those jobs are not dependencies of `ci-ok` and are not required ruleset checks
at this stage. The existing scheduled/manual/push diagnostics remain gated.

PR #2's valid pieces carried here are the merge-group event, event/ref
concurrency with PR-only cancellation, read-only permissions, credential-free
checkout, action pins, a fail-closed aggregate, and actionlint custom-label
configuration. The latter lists only labels actually used by existing workflows
and suppresses only the pre-existing SC2016 warning in `kernel-runtime.yml`:
its single-quoted `bash -c` script must expand in the child shell.

PR #2's persistent cloudmac registration, direct Docker provisioning there,
hosted x86 KVM assumption, new full per-worker acceptance, trusted-event jobs
and old five-check ruleset are superseded by the owner-approved runner-first
plan. Future hardware integration needs qualified willow/KVM and cloudmac JIT
runners, an explicit trust boundary (merge groups/owner dispatch only for
signed HVF), external fixture provisioning and director-owned Docker oracles.
Do not route public PR code to self-hosted runners. Review workflows, scripts
and build inputs before enqueueing; labels and environment guards alone are
not a security boundary. The director's Mac remains local, without a runner.

When those lanes are qualified, extend the aggregate to require their real
success for merge groups and update the ruleset rollout evidence in the same
reviewed change. Never turn an unavailable runner or a skipped signed test into
acceptance. Exact-SHA runtime receipts and artifact identity do not carry across
queue rebuilds, reorderings or re-signing.

## Worker flow and rollback

Workers run focused checks, push feature branches and open draft PRs; runners
supply hosted feedback and the director reviews diffs and coordinates the batch
gate during rollout. No per-worker `accept`/`remote-accept` is introduced here.
Keep those tools for diagnosis and director-owned bootstrap/rollback, and keep
`remote-recapture` for authoritative inventory patches. This PR does not change
AGENTS.md or install runner services.

If activation fails, freeze enqueueing, retain run logs, and restore the recorded
pre-cutover ruleset through the owner. Prefer retaining PR review and hosted
checks while disabling the queue. Revert workflows through a reviewed PR;
rollback does not authorize workers to push `main` or use `--admin` merges.
