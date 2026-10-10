# cloudmac HVF JIT runners

`kernel-runtime.yml`'s `hvf-kernel` job runs on cloudmac, the owner's Apple
Silicon gate Mac, as **one JIT ephemeral runner per job**, bound to the one
workflow run the controller vetted. No runner is registered persistently, no
GitHub credential is ever written on cloudmac, and jobs run as an
unprivileged account that owns nothing the next launch trusts.

```
director's Mac                                cloudmac
--------------                                --------
carrick-xtask ci-scaler mac-jit               rentamac (SSH login, no privileges beyond:)
  gh: queued jobs of kernel-runtime.yml         sudo -n carrick-xtask ci-scaler mac-run-once ...   (root)
      with exactly HVF_LABELS                     verify runner tree == pinned manifest
  gh: re-vet the run; merge group PR heads        write root-owned run/<name>/{policy,admit-job.sh}
      must all be carrick-sh/carrick              policy = "standing run=R attempt=A sha=S"
  gh: generate-jitconfig (one-use) --stdin-->     setsid; drop to carrick-ci; run.sh
  ledger: ~/.carrick-ci/mac-jit                   JIT via ACTIONS_RUNNER_INPUT_JITCONFIG (never argv)
                                                  hook: admit-job (bound run), else kill -KILL 0
                                                  after exit: kill every carrick-ci process
```

## What is admitted

Demand (`Admission::Standing`, `crates/carrick-xtask/src/ci_scaler.rs`):

- runs of `.github/workflows/kernel-runtime.yml` in `carrick-sh/carrick`
  (run and head repository), listed through the workflow's own runs
  endpoint;
- event `merge_group` on `gh-readonly-queue/main/*`, or `push` /
  `workflow_dispatch` on `main`;
- job labels exactly `HVF_LABELS` = `self-hosted, macOS, ARM64, carrick-hvf`.
  The closure job uses `HVF_CLOSURE_LABELS` (`carrick-hvf-closure`) and is
  never served by `mac-jit`, so it cannot occupy the merge-queue runner.

Before minting a runner the controller re-reads the run (`Github::vet`): same
admission, same attempt, and for a merge group every pull request in the
group (its queue entry and every entry ahead of it, from the GraphQL
`mergeQueue` listing) must have its head repository equal to
`carrick-sh/carrick`. A group with a fork pull request is refused.

The runner is then bound (`JobPolicy::Bound`) to that run id, attempt and
SHA in a root-owned policy file. The job-start hook
(`scripts/ci/admit-job.sh`, shared with Willow) admits only a job whose
`GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT` and `GITHUB_SHA` match and which also
passes every standing check (repository, workflow file at the ref being run,
event and ref). Anything else kills the runner's session before any step,
including `always()` and `failure()` steps.

## One-time cloudmac preparation (owner, live)

Not performed by the repository change.

1. **Runner account.** Create an unprivileged, non-admin user `carrick-ci`
   (no sudo rights, its own home, e.g. via System Settings or `sysadminctl
   -addUser carrick-ci`). Install the job toolchain in its home: rustup,
   `just`, `gh` (used only by the merge-queue gate with the job's
   `GITHUB_TOKEN`). No `sudo` entry is needed for jobs: scoped reaping
   (`scripts/sudo/kill.sh <run-id>`) only signals the runner user's own
   processes, and `mac-run-once` kills every `carrick-ci` process after each
   job as that user.

2. **Runner tree, root-owned.** Download the macOS ARM64 runner from
   <https://github.com/actions/runner/releases>, verify the SHA-256 from that
   release's notes, extract as root, and give only `_work` and `_diag` to the
   runner account. Do not run `config.sh`:

   ```sh
   VERSION=2.xxx.y
   EXPECTED=<sha256 for actions-runner-osx-arm64-$VERSION.tar.gz from the release notes>
   curl --disable -fsSLO "https://github.com/actions/runner/releases/download/v$VERSION/actions-runner-osx-arm64-$VERSION.tar.gz"
   echo "$EXPECTED  actions-runner-osx-arm64-$VERSION.tar.gz" | shasum -a 256 -c -
   sudo install -d -o root -g wheel -m 755 /Volumes/carrick-build/actions-runner
   sudo tar -xzf "actions-runner-osx-arm64-$VERSION.tar.gz" -C /Volumes/carrick-build/actions-runner
   sudo chown -R root:wheel /Volumes/carrick-build/actions-runner
   sudo chmod -R go-w /Volumes/carrick-build/actions-runner
   sudo install -d -o carrick-ci -m 700 /Volumes/carrick-build/actions-runner/_work /Volumes/carrick-build/actions-runner/_diag
   ```

   A root-owned tree cannot self-update; to move to a new runner release,
   repeat this step and regenerate the manifest and pin.

3. **Hook xtask, root-owned.** Build from the reviewed commit and install:

   ```sh
   cargo build --locked --release -p carrick-xtask
   sudo install -d -o root -g wheel -m 755 /Volumes/carrick-build/carrick-ci/bin /Volumes/carrick-build/carrick-ci/run
   sudo install -o root -g wheel -m 755 target/release/carrick-xtask /Volumes/carrick-build/carrick-ci/bin/carrick-xtask
   ```

4. **Manifest and pin.** Generate the manifest of the root-owned tree as root
   and record its SHA-256; that digest is the controller's
   `--runner-manifest-sha256`:

   ```sh
   sudo /Volumes/carrick-build/carrick-ci/bin/carrick-xtask ci-scaler mac-runner-manifest \
     | sudo tee /Volumes/carrick-build/carrick-ci/runner-manifest.txt >/dev/null
   sudo chmod 644 /Volumes/carrick-build/carrick-ci/runner-manifest.txt
   shasum -a 256 /Volumes/carrick-build/carrick-ci/runner-manifest.txt
   ```

   Every launch re-lists the tree (file contents, permission bits, symlink
   targets, root ownership, no group/other write; `_work`/`_diag` excluded)
   and refuses to start if it differs from the manifest, or the manifest
   differs from the pin.

5. **One sudoers entry** (`sudo visudo -f /etc/sudoers.d/carrick-ci`) for the
   SSH login account, naming only the root-owned binary and its two
   subcommands:

   ```
   rentamac ALL=(root) NOPASSWD: /Volumes/carrick-build/carrick-ci/bin/carrick-xtask ci-scaler mac-run-once *, /Volumes/carrick-build/carrick-ci/bin/carrick-xtask ci-scaler mac-quiesce *
   ```

   As root, `mac-run-once` accepts only the runner name, the run binding and
   the manifest pin; every path and the runner account are compiled in.

## Running the controller (director's Mac)

`gh` on the director's Mac must be able to call
`repos/carrick-sh/carrick/actions/runners/generate-jitconfig` (repository
Administration). Only the encoded JIT config travels over SSH stdin:

```sh
cargo run --locked --release -p carrick-xtask -- ci-scaler mac-jit \
  --state-dir "$HOME/.carrick-ci/mac-jit" --runner-group-id 1 \
  --runner-manifest-sha256 <digest from step 4>
```

`--host` defaults to `rentamac@cloudmac`; `--one-job` exits after one cleaned
up lifecycle (for qualification). A second instance on the same ledger
refuses to start. GitHub, SSH and parse failures back off (30 s doubling to
10 min) and the loop continues.

## Seeding baselines

The merge-queue gate compares each group's receipt with the receipt of the
group's base SHA (`ci-receipt gate`). Baselines are published by push-to-main,
merge-group and owner `workflow_dispatch`-on-main runs. Before making the
check required, and whenever a main push failed to upload its receipt, seed
main's tip:

```sh
gh workflow run kernel-runtime.yml --repo carrick-sh/carrick --ref main
```

If the base SHA's run is still in progress (queue depth above one), the gate
waits for its receipt for up to 90 minutes (`--wait-minutes`, polled every 60
s). A base run that finished without a receipt fails closed and names this
reseed command.

## Lifecycle and recovery

- **One runner at a time.** The ledger (`mac-ledger.json`, 0600, fsynced)
  records `Registering` before vetting and the JIT request, `Launched` after
  it, and `Done` after registration removal.
- **Re-serve.** A job key is served again when its runner closed without
  running it (failed vet or launch, drained, killed by the hook), at most
  three reservations per key; a key whose runner ran it is never re-served.
- **Assignment** is read from the reserved job and the runner list only;
  the controller never lists every run per poll.
- **Unassigned runner.** After 15 minutes without a job the controller runs
  `mac-quiesce` under the hook's flock. If no job started, further job starts
  are refused (and killed), the registration is removed, and `mac-run-once`
  kills the runner's session.
- **Completion.** After `mac-run-once` returns (runner exited, its session and
  every `carrick-ci` process killed), the registration is removed if it
  still exists and is not busy.
- **Bounds.** Every `gh` and `ssh` call has a deadline and its output is
  parsed, never logged. Runner output stays in the root-owned
  `run/<name>/runner.log` on cloudmac.

## Not claimed

This is trusted-workflow infrastructure, not an adversarial isolation
boundary. Admitted jobs are code on main or in the merge queue from this
repository's branches. They run as `carrick-ci`, which cannot write the
runner tree, the hook binary, the policy or the hook script, but can write
its home, `_work` and `_diag` (toolchains and caches persist across jobs).
The JIT config is passed in the runner's environment; whether the runner
removes it before starting job steps is the runner's behaviour, not a
property this repository verifies. See
[the security review](willow-pilot-security-review.md#standing-admission-surface).
