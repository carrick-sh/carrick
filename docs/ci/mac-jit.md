# cloudmac HVF JIT runners

`kernel-runtime.yml`'s signed jobs (`hvf-kernel`, and `hvf-closure` on an
owner dispatch) run on cloudmac, the owner's Apple Silicon gate Mac, as **one
JIT ephemeral runner per job**. No runner is registered persistently and no
GitHub credential is ever written on cloudmac.

```
director's Mac                               cloudmac (rentamac)
--------------                               -------------------
carrick-xtask ci-scaler mac-jit
  gh api: queued jobs, exact labels,
  Admission::Standing run filter
  gh api: generate-jitconfig (one-use) --ssh stdin--> carrick-xtask ci-scaler mac-run-once
  ledger: ~/.carrick-ci/mac-jit                        state: run/<name>/{policy,admission.lock,admit-job.sh}
                                                       setsid run.sh --jitconfig  (fresh session)
                                                       job-start hook: admit-job, else kill -KILL 0
```

## What is admitted

Demand and the job-start hook share one policy, `Admission::Standing`
(`crates/carrick-xtask/src/ci_scaler.rs`):

- repository `carrick-sh/carrick` (run and head repository);
- workflow file `.github/workflows/kernel-runtime.yml`, read at the very ref
  being run (`GITHUB_WORKFLOW_REF == <repo>/<file>@GITHUB_REF`);
- event `merge_group` on `refs/heads/gh-readonly-queue/main/*`, or `push` /
  `workflow_dispatch` on `refs/heads/main`;
- job labels exactly `HVF_LABELS` = `self-hosted, macOS, ARM64, carrick-hvf`
  (`kernel-runtime.yml` uses exactly these; a test keeps them identical).

`pull_request`, `pull_request_target`, `schedule`, other branches, other
workflows and forks are never served, and a runner that GitHub assigns such a
job kills its own session in the hook before any step (including `always()`
and `failure()` steps) runs. The hook is `scripts/ci/admit-job.sh`, the same
script Willow clones use; `mac-run-once` substitutes only the xtask, policy and
state paths.

## One-time cloudmac preparation (director, live)

Not performed by the repository change. Run on cloudmac as the owner:

1. **Runner binary.** Download the macOS ARM64 runner from the official
   release page, <https://github.com/actions/runner/releases>, choosing a
   current release (the Willow pilot qualified v2.337.0). Verify the SHA-256
   published in that release's notes before extracting; do not run
   `config.sh` (JIT runners need no configuration):

   ```sh
   VERSION=2.xxx.y                       # the chosen release
   EXPECTED=<sha256 from the release notes for actions-runner-osx-arm64-$VERSION.tar.gz>
   mkdir -p /Volumes/carrick-build/actions-runner && cd /Volumes/carrick-build/actions-runner
   curl --disable -fsSLO "https://github.com/actions/runner/releases/download/v$VERSION/actions-runner-osx-arm64-$VERSION.tar.gz"
   echo "$EXPECTED  actions-runner-osx-arm64-$VERSION.tar.gz" | shasum -a 256 -c -
   tar xzf "actions-runner-osx-arm64-$VERSION.tar.gz"
   ```

2. **Hook binary.** Build `carrick-xtask` from the reviewed commit and install
   it **root-owned**; `mac-run-once` refuses an xtask that the runner user (and
   therefore a job) could replace:

   ```sh
   cargo build --locked --release -p carrick-xtask
   sudo install -d -o root -g wheel -m 755 /Volumes/carrick-build/carrick-ci/bin
   sudo install -o root -g wheel -m 755 target/release/carrick-xtask /Volumes/carrick-build/carrick-ci/bin/carrick-xtask
   install -d -m 700 /Volumes/carrick-build/carrick-ci/run
   ```

3. **Job prerequisites** that `hvf-kernel` already assumed: Rust via rustup,
   `just`, `gh` (for the merge-queue baseline gate, authenticated only by the
   job's `GITHUB_TOKEN`), passwordless `sudo` for `scripts/sudo/kill.sh` as in
   local gate runs, and the HVF entitlement signing toolchain.

## Running the controller (director's Mac)

`gh` must be authenticated on the director's Mac with rights to call
`repos/carrick-sh/carrick/actions/runners/generate-jitconfig` (repository
administration). The controller uses that credential locally; only the
encoded JIT config travels over SSH stdin:

```sh
cargo run --locked --release -p carrick-xtask -- ci-scaler mac-jit \
  --state-dir "$HOME/.carrick-ci/mac-jit" --runner-group-id 1
```

Defaults: `--host rentamac@cloudmac`,
`--remote-xtask /Volumes/carrick-build/carrick-ci/bin/carrick-xtask`,
`--remote-state-root /Volumes/carrick-build/carrick-ci/run`. `--one-job` exits
after one cleaned-up lifecycle (for qualification). The controller holds a
flock on its ledger directory; a second instance refuses to start.

## Lifecycle and recovery

- **One runner at a time.** The ledger (`mac-ledger.json`, 0600, fsynced)
  records `Registering` before the JIT request, `Launched` after it, and
  `Done` after registration removal. Rows are kept: a job key (run, attempt,
  job) is served once; a re-run is a new attempt.
- **Launch.** `mac-run-once` creates `run/<name>` with `mkdir` (a replayed
  name fails), writes the `standing` policy, the hook lock and the hook, reads
  one base64 JIT line from stdin, and starts `run.sh --jitconfig` in a new
  session (`setsid`). The JIT is passed in argv to the runner exactly as on
  Willow and is never written to disk. Runner output goes to
  `run/<name>/runner.log` on cloudmac only.
- **Unassigned runner.** After 15 minutes without a job the controller runs
  `ci-scaler quiesce` on cloudmac under the hook's flock. If no job started,
  further job starts are refused (and killed), the controller rechecks the
  assignment, removes the registration, and `mac-run-once` kills the runner's
  session when it sees the drain marker.
- **Completion.** After the runner process exits, a completed, unknown or
  never-assigned registration is removed if it still exists and is not busy.
- **Restart.** A `Registering` row is closed by removing any registration of
  that exact name. A `Launched` row is reconciled from GitHub's assignment; a
  busy runner is never removed.
- **Bounds.** Every `gh` and `ssh` call runs in its own process group with a
  deadline (the SSH-held runner lifecycle is bounded at five hours, above the
  180-minute job timeout) and its output is parsed, never logged.

## Not claimed

This is trusted-workflow infrastructure, not an isolation boundary. Admitted
jobs are code already on main or in the merge queue; they run as the same
cloudmac user as the runner and can modify the runner directory and later
state directories. The hook binary is root-owned so the admission decision
itself cannot be replaced by a job. See
[the security review](willow-pilot-security-review.md#standing-admission-surface).
