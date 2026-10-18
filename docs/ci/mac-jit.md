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
  gh: re-vet the run; merge group PR heads        write root-owned run/<name>/{policy,admit-job.sh}
      must all be carrick-sh/carrick              reservation = "standing run=R attempt=A sha=S"
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
- event `merge_group` on `gh-readonly-queue/main/*`, or `push` /
  `workflow_dispatch` on `main`;
- job labels exactly `HVF_LABELS` = `self-hosted, macOS, ARM64, carrick-hvf`.
  The closure job uses `HVF_CLOSURE_LABELS` (`carrick-hvf-closure`) and is
  never served by `mac-jit`, so it cannot occupy the merge-queue runner.
  **Nothing serves that label today:** an owner-started dedicated runner
  with exactly those labels is required, and until one exists a dispatched
  closure job stays queued (GitHub cancels it after 24 hours).

Before minting a runner the controller re-reads the run (`Github::vet`): same
admission, same attempt, and for a merge group every pull request in the
group (its queue entry and every entry ahead of it, from the GraphQL
`mergeQueue` listing) must have its head repository equal to
`carrick-sh/carrick`. A group with a fork pull request is refused.

Demand is served in priority order: a pending main push needed for a group's
missing base receipt, admitted live merge groups, then the newest pending
main push when no group is pending, then owner `workflow_dispatch` runs on main.
While a merge-group HVF job is pending, a main-push job is offered a runner
only when its head SHA is the group's `base_sha` and that push run has not
published an HVF receipt. The group's hosted `hvf-gate` waits for that base
receipt; its producer runs before the group, even when a newer main push is
queued. The controller obtains the base from `baseCommit.oid` in the existing
merge-queue GraphQL observation and reuses that observation when vetting the
group. Other main pushes are deferred while groups are pending. A newer main
push temporarily supersedes older pending pushes unless an older push is a
group's missing base-receipt producer. These skips do not cancel a run or
enter the durable refusal ledger: a push becomes eligible again when the
higher-priority demand leaves the queue. A per-job refusal never aborts the
pass: the controller records and logs it once per
run/attempt/job key, then considers the next job in the same pass. Refusals
survive restarts; a re-run's new attempt is vetted afresh. Vetting happens
before reserving a runner, so a refused job cannot occupy cloudmac's budget.

When a merge group's SHA is absent from two consecutive complete, successful queue
listings, the controller also requests cancellation of its workflow run.
A truncated queue listing is retried without a durable refusal.
A fork-head refusal, truncated queue listing or API/parse failure does not
trigger cancellation. Cancellation is best effort and attempted once for
the refused job: a denied or failed cancellation leaves the job ignored
and does not prevent serving live demand.

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
   run with `Github::vet`, including same-repository merge-group PR heads.
3. The controller fsyncs the true job id and full run/attempt/job key into its
   ledger **before** publishing `approved-policy` through
   `mac-quiesce --assignment --approve`. That root-owned policy binds approval
   to the actual run/attempt/SHA. The hook verifies it and marks job-started
   under the same flock before returning to the runner.

No GitHub credential reaches cloudmac. The runner user can request admission,
but cannot write approval. Drain and approval share the admission flock;
restart can republish the same approval but cannot replace it with another
run. Once approval exists, reconciliation does not re-vet a completed merge
group that may already have left the queue. An actual job B is deduplicated
while the unserved reservation A remains eligible for another runner; a
runner assigned another job neither holds A nor consumes one of A's serves.
A refused actual assignment is recorded once (a stale merge group is also
cancelled, as for demand) and never approved.
The decision (`serve_assignment` in `ci_scaler/assignment.rs`) is shared with
the standing KVM controller ([willow-pilot.md](willow-pilot.md#standing-mode-merge-queue),
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
an Actions-read-only token still skips and ignores refused jobs, without
expanding its permissions.

Start the controller with the runner-tree pin:

```sh
cargo run --locked --release -p carrick-xtask -- ci-scaler mac-jit \
  --state-dir "$HOME/.carrick-ci/mac-jit" --runner-group-id 1 \
  --runner-manifest-sha256 <digest from step 4>
```

`--host` defaults to `rentamac@cloudmac`; `--one-job` exits after one cleaned
up lifecycle (for qualification). A second instance on the same ledger
refuses to start. GitHub, SSH and parse failures back off (30 s doubling to
10 min) and the loop continues. Per-job admission refusals and failed
stale-run cancellation do not grow the backoff. An actual-assignment
refusal is recorded once and approval is withheld; the existing hook
deadline kills the rejected runner session before any workflow step. A dedicated
assignment worker continues serving while the lifecycle loop backs off or
waits on provisioning and cleanup. It uses a one-second timer between passes
and publishes through a short-held ledger mutex, preserving both lifecycle
transitions and authenticated assignment decisions. Refusal history retains
at most 4096 job keys; eviction never bypasses vetting.

## Seeding baselines

The merge-queue gate compares each group's receipt with the nearest published
receipt on its base chain (`ci-receipt gate`). A superseded shallower group may
have no receipt, so the gate follows that queue entry's base, repeating until
it finds a published receipt. It reports the selected ancestor SHA and its
recorded failure state; a failed ancestor receipt is compared, not silently
skipped. Baselines are published by push-to-main, merge-group and owner
`workflow_dispatch`-on-main runs. Before making the
check required, and whenever a main push failed to upload its receipt, seed
main's tip:

```sh
gh workflow run kernel-runtime.yml --repo carrick-sh/carrick --ref main
```

The comparison runs in the hosted `hvf-gate`/`kvm-gate` jobs, never on the
trusted hardware: a lane job only produces and uploads its receipt. The gate
uses the live merge-queue base links, not commit parents, for the chain. It
waits up to 90 minutes only when the terminal receipt-producing ancestor's
run is still in progress (polled every 60 s; job timeout 110 min). A missing
queue link for an unreceipted merge-group ancestor fails immediately. A
terminal ancestor that finished without a receipt fails closed and names this
reseed command.

Merge groups always run in full: every hardware and hosted job executes
unconditionally with no docs-only or hardware skip. The docs-only fast path
is restricted to `pull_request` CI runs (where only unreferenced prose changed),
and draft PRs skip expensive jobs while keeping cheap Linux checks.

### Retiring or renaming gated tests (`.github/retired-tests.toml`)

When a PR legitimately renames or retires a passing test in an HVF or KVM
receipt lane, the candidate commit may include a PR-scoped
`.github/retired-tests.toml` with `[[retired]]` entries naming
`test = "<bin>::<test>"`, `reason`, `pr`, and optional
`replaced_by = "<bin>::<test>"`. Hosted `hvf-gate` and `kvm-gate` check out
`github.event.merge_group.base_sha` so the gate binary itself always runs
trusted base code; `ci-receipt gate` fetches `--candidate-sha` from `origin`
and inspects the candidate tree's `.github/retired-tests.toml` alongside the
selected baseline ancestor's tree. A declaration drops `missing:` only when the
retired test did not fail in base or candidate, is absent from the candidate's
test sources, still existed in the base's test sources, and (when `replaced_by`
is given) the replacement test started without failing in the candidate
receipt. Stale entries (already absent in base source) and empty
`.github/retired-tests.toml` files fail the gate so the file stays
delete-at-zero once `main`'s baseline receipt rolls past the rename. Because
the hosted gate builds `carrick-xtask` from `base_sha`, any change to
`ci-receipt gate` rolls out as soon as it lands on `main` and becomes the
`base_sha` of subsequent merge groups.

### Cumulative merge groups (#402)

Both controllers check supersession in the shared `Github::vet` path,
for reservations. Actual assignments retain ordinary admission checks and
serve normally regardless of queue depth: withholding approval would make
the job-start hook fail at its deadline. A shallower merge group is skipped
while a deeper queued group contains it, or that successor's workflow passed.
The proof requires a complete merge-queue listing, trusted heads, a pending
or successful latest workflow run, and a GitHub comparison whose merge base
is exactly the shallower SHA. The extra observation uses one page of at most
100 workflow runs and at most five comparisons per vet. Missing, partial,
failed or ambiguous depth observations preserve ordinary group service. Main
pushes retain their per-SHA baseline receipts; only an unreceipted base
producer is served while a group is pending.

Superseded demand does not enter the durable refusal ledger: if the successor
fails or leaves the queue, the shallower group can be served again. If a
Contabo reservation becomes superseded during provisioning, its pre-JIT clone
is released through the existing owned teardown path; registered or assigned
runners retain their normal lifecycle. Supersession never cancels a workflow
run or records a durable refusal, including during provisioning. Superseded
provisioning returns normally without backoff or freezing. Cancelled deeper
runs, rebuilt queues without a qualifying successor, and partial queue
listings preserve ordinary service.

The director must qualify HEADGREEN on the first live batch after deployment:
a skipped group must resume when its successor fails, is cancelled or leaves
the queue, and the deepest group's gate must reach a published ancestor
receipt through skipped shallower groups.

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
boundary. Admitted jobs are code on main or in the merge queue from this
repository's branches. They run as `carrick-ci`, which cannot write the
runner tree, the toolchain, the hook binary, the policy or the hook script;
its home and per-run runner root are recreated before every job.
The JIT config is passed in the runner's environment; whether the runner
removes it before starting job steps is the runner's behaviour, not a
property this repository verifies. See
[the security review](willow-pilot-security-review.md#standing-admission-surface).
