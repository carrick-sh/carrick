# cloudmac persistent HVF runner

`kernel-runtime.yml`'s `hvf-kernel` job (`runs-on: [self-hosted, macOS, ARM64, carrick-hvf]`)
runs on `cloudmac`, the owner's Apple Silicon gate Mac, as a **persistent GitHub Actions
self-hosted runner** managed by `launchd` (`sh.carrick.hvf-runner`) on its own dedicated
internal APFS volume (`/Volumes/carrick-hvf`) under a dedicated non-admin `carrick-hvf`
account (#1225).

It replaces per-job `ci-scaler mac-jit` provisioning ([`mac-jit.md`](mac-jit.md), retained
during cutover as rollback until three consecutive `main` runs finish green).

```
GitHub Actions (kernel-runtime.yml@refs/heads/main)
  runner group restriction: only carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main
  job concurrency:          { group: hvf-kernel-${{ github.event_name }}, cancel-in-progress: false }
        |
        v
cloudmac (/Library/LaunchDaemons/sh.carrick.hvf-runner.plist, KeepAlive=true, UserName=carrick-hvf)
  /Volumes/carrick-hvf/runner/     root:wheel 0755 (--disableupdate; root-owned .env, run.sh, bin/, externals/)
  ACTIONS_RUNNER_HOOK_JOB_STARTED  /usr/local/libexec/carrick-ci/hvf-job-started.sh (root:wheel 0755)
    -> verifies root-owned /usr/local/bin/carrick-xtask and /etc/carrick-ci/policy ("standing")
    -> runs `carrick-xtask ci-scaler admit-job` (push or owner workflow_dispatch on refs/heads/main)
    -> on any policy/path failure: `kill -KILL 0` (kills worker + listener; launchd KeepAlive respawns clean)
    -> reclaims stale $GITHUB_WORKSPACE/target
  step 0 (`Disk admission`)        60 GiB floor via `df -Pk "$RUNNER_WORKSPACE"` before checkout (::error::)
  build + signed gates             exclusive `just lease gate` on `/tmp/carrick-host-lease.lock`
  post-host-gate prune + check     rm -rf host-gate target subdirs, then `CARRICK_DISK_FLOOR_GIB=35 just check-disk`
  ACTIONS_RUNNER_HOOK_JOB_COMPLETED /usr/local/libexec/carrick-ci/hvf-job-completed.sh (root:wheel 0755)
    -> prunes $GITHUB_WORKSPACE/target and clears $RUNNER_TEMP contents immediately
```

## Storage plan

Measured on cloudmac with `diskutil apfs list` (2026-10-31): `mac-jit` builds each run
under `/Volumes/carrick-build/carrick-ci/run/<id>`. That volume has a **100 GB APFS quota**
and was 94.7% full, beside `carrick-gate` (70 GB quota), `carrick-ci` (the
`carrick-macos-ci` PR runner, 35 GB quota) and about 45 GB of director data (`sccache`,
fixtures, evidence) in the same internal container. Signed HVF runs on `main` failed
mid-build with `ENOSPC` there (#1225). The similar #994 was a different host, carrick-m4.

Hot Cargo builds and signed guest images stay on internal NVMe APFS; cold/cached director
artifacts move to the external USB volume (`/Volumes/carrick`, 233 GB total):

1. **Move cold and cached `rentamac` data to external USB (`/Volumes/carrick`):**
   - `rentamac` compiler cache at `/Volumes/carrick/dev/.sccache` (already the default on
     `cloudmac` in `scripts/lib/build-env.sh`; remove any stale `/Volumes/carrick-build`
     cache tree);
   - director fixture archives and retained gate evidence/home archives under
     `/Volumes/carrick/dev/`;
   - reclaims ~45 GB in the internal APFS container for active CI and gate worktrees.
2. **Raise the 35 GB quota on `/Volumes/carrick-ci`:**
   - Check it with `diskutil apfs list`, then raise it so `carrick-macos-ci` PR shards
     don't fail at the quota, e.g.
     `sudo diskutil apfs setQuota <carrick-ci volume disk id> 60g`. Record the before
     and after `diskutil apfs list` lines on #1225.
3. **Create a dedicated internal APFS volume `/Volumes/carrick-hvf`:**
   - Add an internal APFS volume `carrick-hvf` in the internal NVMe container with a
     reserve, so other volumes cannot starve it:
     `sudo diskutil apfs addVolume <internal container disk id> "Case-sensitive APFS" carrick-hvf -reserve 80g -quota 150g`.
     The reserve covers the 60 GiB admission floor. The HVF builds
     get NVMe link/test throughput while keeping filesystem ownership isolated from
     `/Volumes/carrick-gate` (director gates), `/Volumes/carrick-ci` (`ci` PR user), and
     `/Volumes/carrick/dev` (`rentamac`).
   - Enable ownership (`sudo diskutil enableOwnership /Volumes/carrick-hvf`), set root
     directory `/Volumes/carrick-hvf` to `root:wheel` `0755`, and keep each user's home/work
     directories `0700` so `carrick-hvf` has zero read or write access to director volumes
     or `ci`'s volume (matching #650 / #1169).

## Host setup and #1232 binding security requirements

Performed by the owner on `cloudmac` before enabling `sh.carrick.hvf-runner`:

1. **Dedicated non-admin runner account (`carrick-hvf`).**
   Create an unprivileged, non-admin account with home `/Volumes/carrick-hvf/home` (`0700`),
   no `sudo` rights, and no group membership granting access to `rentamac` or `ci` paths:

   ```sh
   sudo install -d -o root -g wheel -m 755 /Volumes/carrick-hvf
   sudo sysadminctl -addUser carrick-hvf -home /Volumes/carrick-hvf/home
   sudo install -d -o carrick-hvf -g staff -m 700 \
     /Volumes/carrick-hvf/home \
     /Volumes/carrick-hvf/sccache \
     /Volumes/carrick-hvf/temp
   echo carrick-hvf | sudo tee -a /usr/lib/cron/cron.deny /usr/lib/cron/at.deny >/dev/null
   ```

   Scoped guest cleanup (`scripts/sudo/kill.sh "$CARRICK_RUN_ID"`) only signals processes
   owned by `carrick-hvf`, so no `sudoers` rule is granted to `carrick-hvf`.

2. **Read-only toolchain and read-only fixture relay token.**
   Provision `rustup` and `sccache` as `root:wheel` (`go-w`) under
   `/Volumes/carrick-hvf/toolchain/{rustup,cargo}` with every component and target pinned
   by `rust-toolchain.toml` (`Verify the read-only toolchain` enforces `test ! -w "$RUSTUP_HOME"`).
   Provision the download-only `carrick-gate-relay` bearer token as `root:wheel` `0444`:

   ```sh
   sudo install -d -o root -g wheel -m 755 /etc/carrick-ci
   sudo install -o root -g wheel -m 444 /Volumes/carrick/.relay-token /etc/carrick-ci/relay-token
   sudo -u carrick-hvf test -r /etc/carrick-ci/relay-token
   sudo -u carrick-hvf test ! -w /etc/carrick-ci/relay-token
   ```

   `scripts/ci/download-fixture-bundle.sh` reads `CARRICK_RELAY_TOKEN_FILE` and refuses
   symlinks, non-root ownership, or any mode other than `0444`.

3. **Root-owned `carrick-xtask`, `/etc/carrick-ci/policy`, and runner hooks (#1232).**
   `scripts/ci/hvf-job-started.sh` hardcodes `/usr/local/bin/carrick-xtask` and
   `/etc/carrick-ci/policy` (ignoring environment overrides) and verifies before execution
   that both are non-symlink regular files owned by `uid 0` without group/other write bits
   (`mode & 022 == 0`). Install them and both hook scripts as `root:wheel`:

   ```sh
   cargo build --locked --release -p carrick-xtask
   sudo install -d -o root -g wheel -m 755 /usr/local/bin /usr/local/libexec/carrick-ci /etc/carrick-ci
   sudo install -o root -g wheel -m 755 target/release/carrick-xtask /usr/local/bin/carrick-xtask
   sudo install -o root -g wheel -m 755 \
     scripts/ci/hvf-job-started.sh \
     scripts/ci/hvf-job-completed.sh \
     /usr/local/libexec/carrick-ci/
   printf 'standing\n' | sudo tee /etc/carrick-ci/policy >/dev/null
   sudo chown root:wheel /etc/carrick-ci/policy
   sudo chmod 644 /etc/carrick-ci/policy
   ```

4. **GitHub runner group restricted to `kernel-runtime.yml@refs/heads/main` (#1232).**
   Create (or configure) a dedicated organization/repository runner group for HVF:
   - **Repository access:** only `carrick-sh/carrick` (never public PRs or forks);
   - **Workflow access ("Selected workflows"):** restricted to
     `carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main`.

   GitHub blocks any other workflow or ref before job assignment; `hvf-job-started.sh` and
   `Admission::Standing` (`push` or owner `workflow_dispatch` on `refs/heads/main`) enforce
   the same invariant locally before steps run.

5. **Root-owned runner tree with `--disableupdate` (#1232).**
   Download the official `actions-runner-osx-arm64-<version>.tar.gz` release, verify its
   published SHA-256, extract into `/Volumes/carrick-hvf/runner`, register once with
   `--disableupdate` and labels `self-hosted, macOS, ARM64, carrick-hvf`, write `.env`, and
   lock the runner root, `.env`, `run.sh`, `bin/`, and `externals/` to `root:wheel` (`go-w`)
   so an admitted job cannot modify runner binaries, hooks, or `.env` across runs:

   ```sh
   sudo install -d -o carrick-hvf -g staff -m 755 /Volumes/carrick-hvf/runner
   sudo -u carrick-hvf tar -xzf "actions-runner-osx-arm64-$VERSION.tar.gz" -C /Volumes/carrick-hvf/runner
   # The registration token never goes in argv (visible to every user in `ps`).
   # Save it to a 0600 file owned by carrick-hvf, pass it through the runner's
   # ACTIONS_RUNNER_INPUT_TOKEN input variable, then delete the file.
   sudo -u carrick-hvf env ACTIONS_RUNNER_INPUT_TOKEN="$(sudo cat /Volumes/carrick-hvf/registration-token)" \
     /Volumes/carrick-hvf/runner/config.sh \
     --unattended \
     --url https://github.com/carrick-sh/carrick \
     --runnergroup carrick-hvf \
     --name cloudmac-hvf \
     --labels carrick-hvf \
     --work _work \
     --disableupdate

   cat <<'EOF' | sudo tee /Volumes/carrick-hvf/runner/.env >/dev/null
   ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/carrick-ci/hvf-job-started.sh
   ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/libexec/carrick-ci/hvf-job-completed.sh
   RUSTUP_HOME=/Volumes/carrick-hvf/toolchain/rustup
   CARGO_HOME=/Volumes/carrick-hvf/home/.cargo
   SCCACHE_DIR=/Volumes/carrick-hvf/sccache
   SCCACHE_CACHE_SIZE=8G
   SCCACHE_SERVER_UDS=/Volumes/carrick-hvf/home/sccache.sock
   CARRICK_RELAY_TOKEN_FILE=/etc/carrick-ci/relay-token
   EOF

   sudo install -d -o carrick-hvf -g staff -m 700 \
     /Volumes/carrick-hvf/runner/_work \
     /Volumes/carrick-hvf/runner/_diag
   sudo chown -R root:wheel \
     /Volumes/carrick-hvf/runner \
     /Volumes/carrick-hvf/runner/.env \
     /Volumes/carrick-hvf/runner/run.sh \
     /Volumes/carrick-hvf/runner/bin \
     /Volumes/carrick-hvf/runner/externals
   sudo chmod -R go-w \
     /Volumes/carrick-hvf/runner \
     /Volumes/carrick-hvf/runner/.env \
     /Volumes/carrick-hvf/runner/run.sh \
     /Volumes/carrick-hvf/runner/bin \
     /Volumes/carrick-hvf/runner/externals
   # Re-grant only _work and _diag to carrick-hvf. Every local macOS user's
   # primary group is `staff`, including `ci`, which runs same-repo PR code on
   # this host, so nothing here may be group- or world-readable through staff.
   sudo chown -R carrick-hvf:carrick-hvf \
     /Volumes/carrick-hvf/runner/_work \
     /Volumes/carrick-hvf/runner/_diag
   # The runner identity (.runner, .credentials, .credentials_rsaparams) is
   # readable by carrick-hvf alone: anyone who can read it can pose as
   # cloudmac-hvf, take trusted main jobs and upload receipts.
   sudo chown carrick-hvf:carrick-hvf \
     /Volumes/carrick-hvf/runner/.runner /Volumes/carrick-hvf/runner/.credentials*
   sudo chmod 0400 /Volumes/carrick-hvf/runner/.runner /Volumes/carrick-hvf/runner/.credentials*
   ```

   Negative check (must print nothing and exit 0). The PR-job user `ci` and
   the director user `rentamac` cannot read any runner identity file:

   ```sh
   for u in ci rentamac; do
     for f in /Volumes/carrick-hvf/runner/.runner /Volumes/carrick-hvf/runner/.credentials*; do
       sudo -u "$u" test -r "$f" && echo "READABLE by $u: $f"
     done
   done; true
   ```

   Record its empty output on #1225 before the runner is registered for jobs.
   Re-run it after every runner upgrade.

   With `--disableupdate` and `root:wheel` ownership on the runner root, `.env`, `run.sh`,
   and `bin/`, the runner never attempts self-updates and jobs cannot tamper with `.env` or
   hook wiring. To upgrade the runner version, boot out the daemon, replace `bin/` and
   `externals/` from a SHA-256-verified release archive as root, and bootstrap the daemon.

6. **`launchd` service with `KeepAlive` and process-group `SIGKILL` recovery (#1232).**
   Unlike `mac-jit` (`setsid` per one-shot launch), a persistent `launchd` runner executes
   `Runner.Listener` and `Runner.Worker` in one process group without per-job `setsid`.
   Because a nonzero `ACTIONS_RUNNER_HOOK_JOB_STARTED` exit still allows conditional
   (`always()`, `failure()`, `!cancelled()`) workflow steps to run, `hvf-job-started.sh`
   executes `kill -KILL 0` on any policy or path guard failure. That terminates both
   `Runner.Worker` and `Runner.Listener` before any step runs; `KeepAlive = true` in
   `/Library/LaunchDaemons/sh.carrick.hvf-runner.plist` immediately respawns a clean
   `Runner.Listener` from the root-owned tree:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key>
     <string>sh.carrick.hvf-runner</string>
     <key>UserName</key>
     <string>carrick-hvf</string>
     <key>GroupName</key>
     <string>staff</string>
     <key>WorkingDirectory</key>
     <string>/Volumes/carrick-hvf/runner</string>
     <key>ProgramArguments</key>
     <array>
       <string>/Volumes/carrick-hvf/runner/run.sh</string>
     </array>
     <key>EnvironmentVariables</key>
     <dict>
       <key>HOME</key>
       <string>/Volumes/carrick-hvf/home</string>
       <key>RUNNER_TEMP</key>
       <string>/Volumes/carrick-hvf/temp</string>
       <key>PATH</key>
       <string>/Volumes/carrick-hvf/toolchain/cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
     </dict>
     <key>KeepAlive</key>
     <true/>
     <key>ThrottleInterval</key>
     <integer>10</integer>
     <key>StandardOutPath</key>
     <string>/Volumes/carrick-hvf/runner/_diag/launchd.out.log</string>
     <key>StandardErrorPath</key>
     <string>/Volumes/carrick-hvf/runner/_diag/launchd.err.log</string>
   </dict>
   </plist>
   ```

   Install as `root:wheel` `0644` and load with
   `sudo launchctl bootstrap system /Library/LaunchDaemons/sh.carrick.hvf-runner.plist`.

## Signing prerequisites, concurrency, and host-lease serialization

- **Codesigning and USDT prerequisites:** Apple Command Line Tools (`codesign`, `otool`,
  Apple `ld64`) must be present on `cloudmac`. Ad-hoc signing (`scripts/build-signed.sh`,
  `scripts/test-signed.sh`) applies `com.apple.security.hypervisor` without a Keychain
  certificate, and `hvf-kernel` verifies both `com.apple.security.hypervisor` and
  `__dof_carrick` on `target/release/carrick`.
- **Newest-push coalescing:** `hvf-kernel` declares job-level
  `concurrency: { group: hvf-kernel-${{ github.event_name }}, cancel-in-progress: false }`.
  While one `hvf-kernel` job is running, GitHub keeps at most one pending `push` job (the
  newest `main` push, superseding older queued pushes) without cancelling the running job
  and without letting an owner `workflow_dispatch` cancel or replace a pending `push`.
- **Host-lease serialization (`/tmp/carrick-host-lease.lock`):**
  - `hvf-kernel` acquires an **exclusive** `just lease gate` across `Host-only source gate`,
    fixture restoration, `just accept --phase signed`, and `Signed embedded guest tests`.
  - Director gates (`just accept`, `just remote-accept` on `/Volumes/carrick-gate`) also
    acquire exclusive `gate` mode.
  - `ci.yml`'s `carrick-macos-ci` PR jobs (`macos-clippy`, `macos-build`, `macos-unit-a`,
    `macos-unit-b`, `macos-integration`) prebuild `carrick-xtask` (`just ci-prebuild-xtask`)
    and run every compile, lint, rustdoc, and test step under **shared** `just lease carrick`.
    Multiple PR shards share `cloudmac` concurrently with one another, but automatically block
    while an exclusive `gate` step (`hvf-kernel` or director `accept`) holds the machine, and
    an incoming `gate` step waits (up to `HOST_LEASE_WAIT_LIMIT` = 1 hour) for in-flight PR
    steps to finish.
  - Every participant on `cloudmac` (`rentamac`, `ci`, `carrick-hvf`) must use the default
    `/tmp/carrick-host-lease.lock` (`0666`); never set `CARRICK_HOST_LEASE_PATH` to a private
    file in production or unlink a live lock file.

## Disk admission and `target/` cleanup

Disk exhaustion fails up front with a clear GitHub annotation rather than mid-build:

1. **Pre-job hook (`hvf-job-started.sh`):** removes any leftover `$GITHUB_WORKSPACE/target`
   from an interrupted prior run (refusing symlinks and handling read-only subdirectories).
2. **Pre-checkout `Disk admission` (`steps[0]` in `hvf-kernel`):** runs `df -Pk "$RUNNER_WORKSPACE"`
   against `HVF_DISK_FLOOR_GIB: "60"` before `actions/checkout@v4`. Below 60 GiB free, it
   emits `::error title=HVF disk admission failed::...` and exits `1`; post-gate
   `!cancelled()` steps require `steps.host-gate-setup.outcome == 'success'`, so the rest of
   the job skips cleanly without touching stale workspace state.
3. **Mid-job pruning and 35 GiB signed-build guard:** `Prune host-only gate build artifacts`
   deletes ~28.3 GiB of host-gate outputs (`target/debug`, `target/doc`,
   `target/aarch64-unknown-linux-gnu`, `target/host-authority-census`,
   `target/host-authority-escape-syntax`), then `Check disk headroom before signed acceptance`
   (`id: signed-disk`) runs `CARRICK_DISK_FLOOR_GIB=35 just check-disk`. `Signed acceptance receipt`
   requires `steps.signed-disk.outcome == 'success'`, so `< 35 GiB` free aborts before the
   ~27.9 GiB release + `.dSYM` build even when `Host-only source gate` was red.
4. **Post-job hook (`hvf-job-completed.sh`):** deletes `$GITHUB_WORKSPACE/target` and clears
   all entries inside `$RUNNER_TEMP` immediately after every job outcome.

## Cutover and rollback

1. **Announce before and after on `#231`** (shared CI infrastructure change).
2. **Cutover sequence:**
   - Move `rentamac`'s `sccache`, fixtures, and evidence archives off `/Volumes/carrick-build`
     to `/Volumes/carrick`, raise `carrick-ci`'s 35 GB APFS quota, and create
     `/Volumes/carrick-hvf`.
   - Install `/usr/local/bin/carrick-xtask`, `/etc/carrick-ci/policy`, `/etc/carrick-ci/relay-token`,
     `/usr/local/libexec/carrick-ci/hvf-job-{started,completed}.sh`, and the root-owned
     `/Volumes/carrick-hvf/runner` tree (`--disableupdate`), and restrict the `carrick-hvf`
     GitHub runner group to `carrick-sh/carrick/.github/workflows/kernel-runtime.yml@refs/heads/main`.
   - Stop `carrick-ci-mac-jit.service` on `carrick-ctb` (`sudo systemctl stop carrick-ci-mac-jit.service`
     without deleting its unit, ledger, or `/Volumes/carrick-build/carrick-ci`).
   - Load `/Library/LaunchDaemons/sh.carrick.hvf-runner.plist` on `cloudmac` and verify
     `cloudmac-hvf` appears `Idle` in GitHub Actions.
   - **Negative control (admission failure):** place temporary ballast on `/Volumes/carrick-hvf`
     so free space drops below 60 GiB, dispatch `kernel-runtime.yml` on `main`, confirm step 0
     (`Disk admission`) fails immediately with `::error title=HVF disk admission failed::`,
     and remove the ballast.
   - Dispatch or push on `main` and confirm `hvf-kernel` runs on `cloudmac-hvf`, uploads
     `receipt-hvf-<sha>-<attempt>`, and prunes `target/` on completion.
3. **Retiring `mac-jit`:** keep `carrick-ci-mac-jit.service` (stopped, not deleted),
   `/Volumes/carrick-build/carrick-ci`, and `crates/carrick-xtask/src/ci_scaler/mac.rs`
   in place until **three consecutive `main` runs** complete green on `cloudmac-hvf`, where green
   means `Trusted hardware OK` succeeded with `HVF · receipt gate` reporting `NEW=[]`
   (`hvf-kernel` itself stays red on main by design, so its own result is not the test). The
   cutover also needs #1238's probe check (the #1196/#1119 probes MATCH on the new runner). Only
   then disable `carrick-ci-mac-jit.service` (`sudo systemctl disable carrick-ci-mac-jit.service`)
   and retire the legacy tree, posting the post-cutover note on `#231`.
4. **Rollback (if `cloudmac-hvf` misbehaves before retirement):**
   - Announce rollback on `#231`.
   - Boot out the persistent daemon on `cloudmac`:
     `sudo launchctl bootout system /Library/LaunchDaemons/sh.carrick.hvf-runner.plist`
     and deregister it so queued jobs don't wait on the offline registration
     (GitHub has no per-runner disable switch):
     `sudo -u carrick-hvf env ACTIONS_RUNNER_INPUT_TOKEN="$(sudo cat /Volumes/carrick-hvf/removal-token)" /Volumes/carrick-hvf/runner/config.sh remove`.
   - Rollback needs space on `/Volumes/carrick-build`: cutover step 1 must already have moved
     the director data to USB, or `mac-jit`'s own 60 GiB disk admission refuses the job.
   - Start `carrick-ci-mac-jit.service` on `carrick-ctb`:
     `sudo systemctl start carrick-ci-mac-jit.service` (it serves the identical
     `[self-hosted, macOS, ARM64, carrick-hvf]` labels using the existing
     `/Volumes/carrick-build/carrick-ci` tree, now with the 45 GB freed in the internal
     APFS container).

## Seeding baselines

`kernel-runtime.yml` runs the HVF lane and selected KVM backend once per
main push event on `push` to `main`, subject to queued-push coalescing. A
single push can land several commits. Owner `workflow_dispatch` on `main` also
runs both lanes to seed receipts. Neither pull requests, merge groups nor
schedules run this workflow. The optional full-conformance `hvf-closure` job
runs only on owner dispatch with its enable variable and dedicated runner.
`ci.yml` retains its own PR, merge-group, schedule and dispatch
triggers; only `ci-ok` is a merge requirement. The director owns pre-merge
hardware evidence; the hardware run after landing is the backstop.

On push, hosted `hvf-gate` and `kvm-gate` build the selector xtask from the
trusted `github.event.before` commit, using its own checkout and lockfile.
`ci-receipt select-baseline` rejects zero/malformed `before` values and any
`before` outside the pushed SHA's first-parent ancestry (force pushes).
Starting at `before`, it checks at most 50 first-parent commits and selects
the nearest one with a trusted receipt for that lane. Pending or cancelled
runs without a receipt do not prevent using an older receipted ancestor.

The selector writes the exact baseline SHA and every intervening landed
commit without its own receipt to the step summary and a notice annotation:
**covered as a range, not individually**. This covers multi-commit PRs,
stack landings and gaps in the hardware backlog. The pushed SHA has its own
candidate receipt and is excluded from the uncovered list. Trust remains
exact SHA, kernel-runtime workflow path, repository/head repository,
push/dispatch event and main branch. Failed receipts remain usable baselines.

The comparison builds the selected baseline's xtask in a separate clean
checkout with that commit's lockfile; only candidate receipt data is graded.
When `before` supplies the receipt, reuse its existing checkout/build. The
candidate's Rust code is never built to grade itself. Hardware jobs never
wait for a baseline. A missing baseline before the first-parent root fails
as **No baseline**; exhausting 50 commits while older ancestry remains fails
as **Baseline walk limit**. Both have explicit error annotations and summaries
and neither is reported as a NEW regression.

At initial rollout the trusted `before` may predate `select-baseline`. That
push fails visibly as **Baseline selector unavailable**; seed current main
with an owner dispatch. Subsequent pushes can use the new selector. The
workflow never falls back to executing the candidate's selector code.

Owner dispatch seeds the current main tip without comparing it to a parent:

```sh
gh workflow run kernel-runtime.yml --repo carrick-sh/carrick --ref main
```

After a gap, this supplies a baseline for subsequent pushes; it does not
accumulate or retroactively turn an earlier No baseline outcome into a comparison.
`Trusted hardware OK` requires both hardware lanes, and on push also both
receipt comparisons. It remains visible after landing and does not gate
merging.

### Retiring or renaming gated tests (`.github/retired-tests.toml`)

When a PR legitimately renames or retires a passing test in an HVF or KVM
receipt lane, the candidate commit may include a PR-scoped
`.github/retired-tests.toml` with `[[retired]]` entries naming
`test = "<bin>::<test>"`, `reason`, `pr`, and optional
`replaced_by = "<bin>::<test>"`. The binary and every test-path segment must
match `[A-Za-z_][A-Za-z0-9_]*`; receipt matches always include the binary.
Hosted `hvf-gate` and `kvm-gate` build the comparison xtask from the
selected receipted ancestor; `ci-receipt gate` fetches `--candidate-sha` from `origin`
and inspects the candidate tree's `.github/retired-tests.toml` alongside the
parent main commit's tree. A declaration drops `missing:` only when the
retired test did not fail in the applicable receipt lane, is absent from the
candidate's test sources, still existed in the base's test sources, and (when
`replaced_by` is given) the replacement test started without failing in the
candidate receipt. A replacement on another lane need not start unless the
retired test actually started in this baseline receipt. Lane declarations
accept strings and `{ lane = "..." }` tables, including wildcards; missing
metadata means the `host` lane, and `manual` targets have no automated lane.
An observed start remains authoritative even if metadata says another lane.

The source check parses every Rust source file in each owning crate, including
integration targets, `src/bin/` and explicit binary targets such as `carrick`.
Only functions with test attributes (`#[test]`, `#[tokio::test]`, etc.) establish
test presence; an ignored test still exists. Retirement is refused if a file
cannot parse or the crate contains unresolved item macros (including
`macro_rules!` generators), `#[path]` modules, `include!`, or explicit
`[[test]] path` targets outside `tests/`. Explicit test, binary and library
source paths must be Rust files inside the crate. Same-named tests in other
modules conservatively prevent retirement.
Symlink files and directories are skipped, including manifests and declarations.

Stale entries (already absent in base source) are inert: they
excuse nothing and appear as non-blocking `WARNING` lines in the gate summary.
Remove these entries once `main`'s baseline receipt rolls past the rename;
delete the file when no entries remain. Empty declaration files fail the gate.
Selector changes take effect when they reach trusted event.before.
Comparison changes take effect when that commit supplies the chosen receipt.
