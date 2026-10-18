# cloudmac HVF JIT runners

`kernel-runtime.yml`'s `hvf-kernel` job runs on cloudmac, the owner's Apple
Silicon gate Mac, as **one JIT ephemeral runner per job**, admitted to trusted runs of
`kernel-runtime.yml`, re-vetted at assignment. No runner is registered
persistently, no long-lived GitHub or Cloudflare upload credential is ever
written on cloudmac, and jobs run as an unprivileged account that owns
nothing the next launch trusts.

```
director's Mac                                cloudmac
--------------                                --------
carrick-xtask ci-scaler mac-jit               rentamac (SSH login, no privileges beyond:)
  gh: queued jobs of kernel-runtime.yml         sudo -n carrick-xtask ci-scaler mac-run-once ...   (root)
      with exactly HVF_LABELS                     verify runner tree == pinned manifest
  gh: re-vet main push or owner dispatch         write root-owned run/<name>/{policy,admit-job.sh}
                                                 reservation = "standing run=R attempt=A sha=S"
  gh: generate-jitconfig (one-use) --stdin-->     setsid; drop to carrick-ci; Runner.Listener run
  ledger: ~/.carrick-ci/mac-jit                   JIT via ACTIONS_RUNNER_INPUT_JITCONFIG (never argv)
                                                  hook: request actual run; await controller approval
                                                  else kill -KILL 0
                                                  after exit: kill every carrick-ci process
```

## What is admitted

Demand (`Admission::Standing`, `crates/carrick-xtask/src/ci_scaler.rs`):

- runs of `.github/workflows/kernel-runtime.yml` in `carrick-sh/carrick`
  (run and head repository), listed through the workflow's own runs
  endpoint;
- event `push` or owner `workflow_dispatch` on `main` (both `actor` and
  `triggering_actor` must be `tjfontaine` for dispatch); merge groups,
  pull requests and schedules are refused;
- job labels exactly `HVF_LABELS` = `self-hosted, macOS, ARM64, carrick-hvf`.
  The closure job uses `HVF_CLOSURE_LABELS` (`carrick-hvf-closure`) and is
  never served by `mac-jit`, so it cannot occupy the main-push runner.
  **Nothing serves that label today:** an owner-started dedicated runner
  with exactly those labels is required, and until one exists a dispatched
  closure job stays queued (GitHub cancels it after 24 hours).

Before minting a runner the controller re-reads the run (`Github::vet`):
same trusted main admission, same attempt and exact SHA. Both controllers
serve the **newest queued main push first**, then owner dispatches. They
coalesce queued pushes on every poll, including while busy. Before cancelling
an older run, each controller fsyncs a supersession entry in its own ledger
and logs `superseded by <newer sha>`. That run is permanently ineligible for
local JIT minting and hook approval, including reruns. Its commits remain
visible through the receipt gate's range report.

Supersession and hook approval share the controller's admission lock. Approval
is durable before the hook is released; an already approved local run cannot
be superseded. Every assignment, including the reserved job, must rendezvous.
The cancellation POST is cleanup outside that lock: a fresh all-lane jobs GET
must show the target queued, no in-progress job and no started hardware job
(HVF, standing KVM or hosted GCP KVM). Observed started work prevents the POST. The controllers
have separate authorities; there is no cross-controller acknowledgement.
**A superseded job never starts through our admission; a raced cancellation
can only affect a superseded run.** Another controller can start that run
between GET and POST; scoped cleanup uses its run ID. This does not guarantee
that running work can never be cancelled in that window.

Per-job refusals are logged and recorded durably, then the controller considers
the next job in the same pass. API failures back off and leave supersession
intents durable for restart/retry. Refused assignment keys are attempt-specific;
superseded runs remain refused across attempts.

GitHub does not bind a JIT registration to the reserved job: a compatible
job from another run may be assigned. The mac hook therefore re-vets the
**actual assignment** through a credential-free rendezvous with the controller:

1. Before steps, the hook validates standing repository/workflow/event/ref
   checks and writes its run id, attempt and SHA into the pre-created
   `assignment.json`, under the admission flock. It waits at most four minutes
   for approval; missing approval fails closed and kills the runner session.
2. Through the existing root-only `mac-quiesce --assignment` command, the
   controller reads that request. It finds the unique job in that run/attempt
   assigned to this runner id, checks exact HVF labels, and re-vets the actual
   run with `Github::vet`, including main push or owner dispatch admission.
3. The controller fsyncs the true job id and full run/attempt/job key into its
   ledger, including the approval decision, **before** publishing
   `approved-policy` through
   `mac-quiesce --assignment --approve`. That root-owned policy binds approval
   to the actual run/attempt/SHA. The hook verifies it and marks job-started
   under the same flock before returning to the runner.

No GitHub credential reaches cloudmac. The runner user can request admission,
but cannot write approval. Drain and approval share the admission flock;
restart can republish the same approval but cannot replace it with another
run. Once approval exists, reconciliation does not re-vet a completed run. An actual job B is deduplicated
while the unserved reservation A remains eligible for another runner; a
runner assigned another job neither holds A nor consumes one of A's serves.
A refused actual assignment is recorded once and never approved.
The decision (`serve_assignment` in `ci_scaler/assignment.rs`) is shared with
the standing KVM controller ([willow-pilot.md](willow-pilot.md#standing-mode-main-pushes-and-owner-dispatch),
#333); only the transport differs. The historical pilot remains bound.

This is Option A for [#256](https://github.com/carrick-sh/carrick/issues/256).
A hook rejection fails the assigned job; it is not a release-to-queue API.
Re-vetting before steps serves trusted reassignment while preserving refusal
of pull requests, forks, other workflows and other repositories.

## One-time cloudmac preparation (owner, live)

Not performed by the repository change.

1. **Runner account.** Create an unprivileged, non-admin user `carrick-ci`
   with home `/Volumes/carrick-build/carrick-ci/job-home` (`mac-run-once`
   refuses any other home), no sudo rights, e.g.
   `sudo sysadminctl -addUser carrick-ci -home /Volumes/carrick-build/carrick-ci/job-home`.
   Deny it cron and at (live configuration; `mac-run-once` refuses to launch
   unless both lists name it):

   ```sh
   echo carrick-ci | sudo tee -a /usr/lib/cron/cron.deny /usr/lib/cron/at.deny >/dev/null
   ```

   Create the root-owned skeleton the job home is rebuilt from (dotfiles
   only, no toolchains): `sudo install -d -o root -g wheel -m 755
   /Volumes/carrick-build/carrick-ci/skel`.

   No `sudo` entry is needed for jobs: scoped reaping
   (`scripts/sudo/kill.sh <run-id>`) only signals the runner user's own
   processes, and `mac-run-once` kills every `carrick-ci` process before and
   after each job as that user.

   **Toolchain, root-owned and read-only.** Install rustup as root into
   `/Volumes/carrick-build/carrick-ci/toolchain/{rustup,cargo}` with the
   toolchain pinned by `rust-toolchain.toml` (components, targets) plus
   `sccache` in `cargo/bin`, then `sudo chown -R root:wheel` and
   `sudo chmod -R go-w` it. Jobs get `RUSTUP_HOME=.../toolchain/rustup`
   (read-only) and a fresh writable `CARGO_HOME` in the job home; tools a
   workflow installs (`just`, `cargo-deny`) land there and are wiped.

   The host-authority census preserves this `RUSTUP_HOME` while isolating
   Cargo configuration and selecting the checked toolchain channel. Its
   subprocesses disable automatic toolchain installation; a missing pinned
   toolchain must be fixed during owner provisioning, not inside the job.

   **Private sccache per run.** `mac-run-once` sets `SCCACHE_SERVER_UDS` to a
   socket in the wiped job home, `SCCACHE_DIR` to
   `/Volumes/carrick-build/carrick-ci/sccache` (owned by `carrick-ci`, 0700)
   and `SCCACHE_CACHE_SIZE=8G`. Without it the client used the default TCP
   server on `127.0.0.1:4226`, which was another local user's sccache: it
   tried to spawn rustc inside the 0700 job home (`Permission denied`) and
   would have run CI compiles as that user against its cache. The server
   dies with the run (`kill_all_as` reaps every `carrick-ci` process).

   **Toolchain bumps need the owner first.** Jobs cannot install a
   toolchain, so a change to `rust-toolchain.toml` (version, component or
   target) fails `hvf-kernel` until the owner has installed the new
   toolchain into this read-only directory on cloudmac. Install it before
   the bump lands (both versions can coexist). Automating this from a
   reviewed commit is an open follow-up.

   **Fixture relay token (director, one time before #318 lands).** The
   existing `/Volumes/carrick/.relay-token` belongs to `rentamac` (0600),
   so jobs cannot read it. Copy it into the provisioned toolchain without
   printing its contents:

   ```sh
   sudo install -o root -g wheel -m 444 /Volumes/carrick/.relay-token \
     /Volumes/carrick-build/carrick-ci/toolchain/relay-token
   stat -f '%Su:%Sg %Lp' /Volumes/carrick-build/carrick-ci/toolchain/relay-token
   sudo -u carrick-ci test -r /Volumes/carrick-build/carrick-ci/toolchain/relay-token
   sudo -u carrick-ci test ! -w /Volumes/carrick-build/carrick-ci/toolchain/relay-token
   ```

   The containing toolchain directories must remain root-owned and 0755,
   with no group/other write permission. The downloader refuses a symlink,
   non-root ownership or a mode other than 0444. Repeat the copy after owner
   rotation of the source token. This read-only relay bearer token is the
   sole persistent credential deliberately readable by admitted jobs; it
   must authorize **only downloads** through `carrick-gate-relay`, never R2
   writes or GitHub access. Do not put it in GitHub secrets, job outputs or
   the writable skeleton/home. Jobs can read it, so this retains the existing
   trusted-workflow assumption; it does not isolate the token from admitted
   code or other local readers. A previous job cannot change the provisioned
   token for a later job.

   The hosted `signed-fixtures` publisher alone receives the R2 upload token
   and account id, scoped to its upload step. It uses pinned Wrangler 4.76.0
   to publish at most 256 MiB per object at
   `carrick-gate-images/bundles/<sha>/<archive-sha256>.part00`, `.part01`, etc.
   The existing GitHub artifact upload is retained. The archive filename
   names its manifest hash, so the publisher separately records the actual
   archive SHA-256, filename and part count as job outputs. The Mac never
   trusts digest metadata from the relay. It sends the bearer header to the
   fixed HTTPS Worker endpoint via curl's stdin configuration (no token in
   argv, output or a workspace file), concatenates parts in order, and
   verifies the archive digest before publishing the download. A relay
   attempt has a 45-second network budget; any failure, including missing
   provisioning or digest mismatch, selects `actions/download-artifact`.
   Both paths then pass the same mandatory archive digest check and the
   existing checkout-aware fixture manifest/object verification at restore.

2. **Runner tree, root-owned.** Download the macOS ARM64 runner from
   <https://github.com/actions/runner/releases>, verify the SHA-256 from that
   release's notes, extract as root. The tree is never run directly or written by the runner
   account: every run gets a private APFS clone (below). Do not run
   `config.sh`:

   ```sh
   VERSION=2.xxx.y
   EXPECTED=<sha256 for actions-runner-osx-arm64-$VERSION.tar.gz from the release notes>
   curl --disable -fsSLO "https://github.com/actions/runner/releases/download/v$VERSION/actions-runner-osx-arm64-$VERSION.tar.gz"
   echo "$EXPECTED  actions-runner-osx-arm64-$VERSION.tar.gz" | shasum -a 256 -c -
   sudo install -d -o root -g wheel -m 755 /Volumes/carrick-build/actions-runner
   sudo tar -xzf "actions-runner-osx-arm64-$VERSION.tar.gz" -C /Volumes/carrick-build/actions-runner
   sudo chown -R root:wheel /Volumes/carrick-build/actions-runner
   sudo chmod -R go-w /Volumes/carrick-build/actions-runner
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
Administration). Only the encoded JIT config travels over SSH stdin.

Stale-run cancellation uses the existing classic/OAuth `repo` scope. A
fine-grained token needs **Actions: write** for
[workflow-run cancellation](https://docs.github.com/en/rest/actions/workflow-runs#cancel-a-workflow-run);
a token without that permission cannot complete coalescing cleanup. The
controller logs the failure, retains the pending intent and withholds local
admission for the superseded run; it does not silently skip cancellation.

Start the controller with the runner-tree pin:

```sh
cargo run --locked --release -p carrick-xtask -- ci-scaler mac-jit \
  --state-dir "$HOME/.carrick-ci/mac-jit" --runner-group-id 1 \
  --runner-manifest-sha256 <digest from step 4>
```

`--host` defaults to `rentamac@cloudmac`; `--one-job` exits after one cleaned
up lifecycle (for qualification). A second instance on the same ledger
refuses to start. GitHub, SSH and parse failures back off (30 s doubling to
10 min) and the loop continues. Per-job admission refusals do not grow the backoff. Cancellation failures
are logged and pending intents are retried on subsequent coalescing passes. An actual-assignment
refusal is recorded once and approval is withheld; the existing hook
deadline kills the rejected runner session before any workflow step. A dedicated
assignment worker continues serving while the lifecycle loop backs off or
waits on provisioning and cleanup. It uses a one-second timer between passes
and publishes through a short-held ledger mutex, preserving both lifecycle
transitions and authenticated assignment decisions. Refusal history retains
at most 4096 job keys; eviction never bypasses vetting.

## Seeding baselines

`kernel-runtime.yml` runs the HVF lane and selected KVM backend once per
main push event on `push` to `main`, subject to queued-push coalescing. A
single push can land several commits. Owner `workflow_dispatch` on `main` also
runs both lanes to seed receipts. Neither pull requests, merge groups nor
schedules run this workflow. The optional full-conformance `hvf-closure` job
runs only on owner dispatch with its enable variable and dedicated runner.
`ci.yml` retains its own PR, merge-group, push, schedule and dispatch
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
retroactively turn an earlier No baseline outcome into a comparison.
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

## Lifecycle and recovery

- **One runner at a time.** The ledger (`mac-ledger.json`, 0600, fsynced)
  records `Registering` after vetting and before the JIT request, `Launched` after
  it, and `Done` after registration removal.
- **Re-serve.** A job key is served again when its runner closed without
  running it (failed launch, drained, killed by the hook), at most
  three reservations per key; a key whose runner ran it is never re-served.
  A refused key is skipped until a new workflow attempt.
- **Assignment** is read from the hook rendezvous and the actual run/attempt
  jobs, authenticated by runner id. Once recorded, reconciliation reads that
  job and the runner list; it never lists every run per poll.
- **Unassigned runner.** After 15 minutes without a job the controller runs
  `mac-quiesce` under the hook's flock. If no job started, further job starts
  are refused (and killed), the registration is removed, and `mac-run-once`
  kills the runner's session.
- **Launchd agents.** launchd starts per-user Apple agents for any uid
  with processes and respawns them when killed (observed: `/usr/sbin/distnoted
  agent`, ppid 1, under `carrick-ci`), so "no runner-account process left"
  is unattainable on macOS. The reap exempts only processes whose real
  executable path (kernel `proc_pidpath`, never argv) is exactly on
  `EXEMPT_AGENTS`, whose parent is launchd, and whose binary is root-owned
  and not writable; every other `carrick-ci` process is still SIGKILLed and
  any survivor still refuses the launch. A job cannot qualify by renaming
  its argv or copying a binary to a look-alike path. Booting out the
  account's launchd user domain is not relied on.
- **Per-job reset.** Before every launch `mac-run-once` kills every
  `carrick-ci` process, then deletes and recreates the job home from the
  skeleton (symlinks are removed, never followed). Nothing a previous job wrote (caches, launch agents, rc files,
  cargo installs) reaches the next job.
- **Per-run runner root.** The listener writes its registration files
  (`.runner`, `.credentials`, ...) into its root directory, so
  `mac-run-once` clones the pinned tree (`clonefile`, copy-on-write) to
  `run/<name>/runner`, re-verifies the clone against the manifest, hands only
  the clone's root directory plus fresh `_work` and `_diag` to `carrick-ci`
  (`bin/` and `externals/` stay root-owned), and runs the listener from it.
  The clone is deleted on every exit path, without following symlinks.
- **Completion.** After `mac-run-once` returns (runner exited, its session and
  every `carrick-ci` process killed), the registration is removed if it
  still exists and is not busy.
- **Bounds.** Every `gh` and `ssh` call has a deadline and its output is
  parsed, never logged. Runner output stays in the root-owned
  `run/<name>/runner.log` on cloudmac.

## Host test authorities

The runner account has no sudo rights. Production target pruning requires an
all-user `lsof` census and preserves artifacts when that census is denied.
Its unit fixtures instead query real `lsof` as the invoking user: they own
the private target directory and every process opening its files. This
fixture scope exists only under `cfg(test)`; the CLI cannot select it.

The listener starts through `setsid` and `setuid`, without a login into the
runner user's launchd bootstrap session. Detached remote-accept jobs inherit
an ignored SIGHUP from their spawning shell. They do not invoke Darwin's
`nohup`, which additionally requires a launchd console-session detach before
executing the requested command. Job startup errors go to the accept log;
lock joining and exit publication still determine the lock's lifetime.

## Not claimed

This is trusted-workflow infrastructure, not an adversarial isolation
boundary. Admitted jobs are code landed on this repository's main branch. They run as `carrick-ci`, which cannot write the
runner tree, the toolchain, the hook binary, the policy or the hook script;
its home and per-run runner root are recreated before every job.
The JIT config is passed in the runner's environment; whether the runner
removes it before starting job steps is the runner's behaviour, not a
property this repository verifies. See
[the security review](willow-pilot-security-review.md#standing-admission-surface).
