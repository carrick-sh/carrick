# PR #18 security review regressions

All five findings have a red-first regression and a separate fix commit.
This review used local tests and mock APIs. No Willow SSH/API operation,
deployment, clone, registration or workflow dispatch was performed. The
[historical live receipt](willow-pilot-evidence.md) belongs to its recorded
older controller artifact; it does not confer live qualification on these
fixes. Any subsequent live run must retain the pool, VMID, admission and
one-clone limits.

## Terminal authorization rejection

Commit `4f8104783` isolates the runner listener/worker/hook with `setsid --wait`.
A failed admission execs the trusted absolute `/bin/kill -KILL 0`, killing
that group before the worker can schedule a workflow-controlled continuation.
The controller qualifies `setsid` and `kill` before JIT registration; future
templates explicitly install their guest packages.

[Workflow fixture](../../crates/carrick-xtask/tests/fixtures/ci-scaler/rejected-job.yml)
contains both `if: always()` and `if: failure()` commands. Its local native
process harness uses the actual hook wrapper with only the authorization
decision substituted. Existing policy tests cover real repository/event/ref/
SHA decisions. This is a local process-death proof, not a live GitHub dispatch.

| Case | always command | failure command | Listener continuation |
|---|---|---|---|
| Ordinary failed hook control | Executed | Executed | Executed |
| Pre-fix hook, rejected decision (red) | Executed | Executed | Executed |
| Fixed hook, rejected decision | Absent | Absent | Absent; SIGKILL |
| Fixed hook, admitted decision | Executed | Absent | Executed |

The fixture is bounded to five seconds and owns a fresh process group.
The pinned [runner process invoker](https://github.com/actions/runner/blob/v2.337.0/src/Runner.Sdk/ProcessInvoker.cs)
uses ordinary child processes; [.NET documents CreateNoWindow as ignored on Unix](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.createnowindow?view=net-10.0#remarks).
The group boundary is established before the listener can accept a job.

## Authenticated curl configuration

Commit `055a06c56` passes `--disable` first in every authenticated controller
and template curl call. [Curl requires this position to disable default configuration](https://curl.se/docs/manpage.html#-q).
Both actual callers were tested with a synthetic credential, a private
ambient `.curlrc` containing `trace-ascii`, and a local HTTP fixture.

The control reconstructed the synthetic Authorization credential from the
trace. Both callers failed red by writing a trace. Controller GET/POST/PUT/
DELETE calls and the isolated actual template helper now write no trace file;
the synthetic Authorization header still reaches the intended fixture.
TLS verification and stdin-only credential delivery are retained. No real
PVE credential was accessed, copied or logged.

## Interrupted teardown

Commit `514c90931` makes `Reaping` a durable license granted after assignment
and drain checks. The continuation fsyncs that license before side effects,
then stops/deletes the owned VM and verifies absence before registration
removal. Restart does not query job assignment for licensed reaping.
Failed or ambiguous preparation/JIT delivery preserves its actual phase;
it does not grant teardown authority.

The previous policy failed red: an unknown assignment kept `Reaping`, and
absence without a saved delete task was quarantined. Mock APIs now exercise
the actual production continuation with no recorded assignment:

- Interruption immediately after physical VM stop, before its task-ID save.
- Interruption immediately after runner removal, before ledger completion.
- The previous removed-registration/present-VM state, running or stopped.
- VM absence before delete-task persistence.
- Wrong VMID, pool, identity or template flag; no mutation is attempted.
- Failed license publication; no external mutation is attempted.

Each restart finishes `Destroyed` without duplicate stop/delete/removal.
The one-clone budget, dedupe records and ownership guards remain enforced.

## Minor findings

Commit `974c6e9fe` applies the controller's inclusive 80% projected CPU ceiling
to template boot. The actual isolated awk policy failed red by admitting
80.1%; it now admits 79% and 80%, and refuses 80.1% and 84%.

Commit `6d65a5173` requires at least one exact allowlisted deprecation for
cloud-init exit 2. Empty map and empty `DEPRECATED` list failed red and now
reject. Known deprecations still qualify, clean exit 0 still qualifies, and
unknown warnings, errors, running state and other exits remain rejected.

## Verification

`cargo test -p carrick-xtask`, scoped clippy with `-D warnings`, `just fmt-check`,
all three script syntax checks and `just lint-domains` passed on the five fix
commits. The xtask library passed 80 tests with one pre-existing ignored test;
controller policy tests passed 18, and terminal-hook fixture tests passed 2.
Other xtask integration suites also passed.

Lint-domain compiler evidence covers the available macOS profiles; its
receipt explicitly leaves other host profiles pending. Batch acceptance
remains with the director. Full `just ci` retains the separately disclosed
inherited MMU/signal/EL1 rustdoc red owned by PR #3. Local red and green logs
are in `/tmp/willow-pilot-review/`.

## Standing admission surface

The pilot admitted one workflow (`willow-pilot.yml`, `workflow_dispatch`,
`work/willow-pilot`, one approved SHA). The merge-queue gate adds a bounded
standing policy for Willow (`ci-scaler standing`) and cloudmac
(`ci-scaler mac-jit`). Demand uses `Admission::Standing`; each runner is then
bound by `JobPolicy::Bound` to the one run the controller re-vetted. Both are
in `crates/carrick-xtask/src/ci_scaler.rs`; there is no second copy.

| Check | Pilot | Standing |
|---|---|---|
| Repository (run and head repository) | `carrick-sh/carrick` | `carrick-sh/carrick` |
| Workflow file | `willow-pilot.yml` | `kernel-runtime.yml`, at the ref being run |
| Events and refs | `workflow_dispatch` on `work/willow-pilot` | `merge_group` on `gh-readonly-queue/main/*`; `push` or `workflow_dispatch` on `main` |
| Merge group content | n/a | every PR in the group has its head in `carrick-sh/carrick` (GraphQL `mergeQueue`, vetted before minting) |
| Hook binding | one approved SHA | the vetted run id, attempt and SHA |
| Labels | `ci_scaler::LABELS` | `LABELS` (Willow), `HVF_LABELS` (cloudmac); closure uses `HVF_CLOSURE_LABELS`, never served |
| Concurrency | one clone | Willow 1 by default, `--max-concurrency 2` at most; cloudmac 1 |

Not admitted, by test (`tests/ci_scaler.rs`): `pull_request` (including one
claiming `refs/heads/main`), `pull_request_target`, `schedule`, other branches
and tags, an empty or foreign merge-queue prefix, a foreign workflow file, a
workflow file read at another ref, a fork repository, a short SHA, a merge
group containing (or queued behind) a fork pull request, and, for a bound
runner, any other run id, attempt or SHA. `kernel-runtime.yml` has no
`pull_request` trigger; a test fails if one is added.

Retained properties:

- **JIT one-use registration**, never in a ledger, log, disk file or argv:
  Willow and cloudmac runners read it from `ACTIONS_RUNNER_INPUT_JITCONFIG`.
- **Willow budget**: clone range 308-349 (typed `CloneId`), pool
  `carrick-ci`, the protected-VM census, the 80% projected CPU ceiling,
  10 GiB memory, 150 GiB thin-pool data and metadata below 80% before every
  clone. With two clones every non-template pool member must be an active
  ledger clone; any unknown object, reconcile error or ambiguous clone
  freezes admission. A clone whose registration is gone and whose reserved
  job never ran on it is destroyed only after its guest reports the
  runner's exit file.
- **Job-start hook**: rejection runs `exec /bin/kill -KILL 0` on the
  runner's own session; `tests/ci_scaler_hook.rs` proves process death for
  both hook variants. The policy file must be root-owned, a regular file, not
  group/other writable; the hook reads no job-settable environment.
- **Secrets**: the PVE token stays on Willow; the standing controller's
  GitHub credential is a fine-grained, single-repository token with
  Administration (runner registration) and Actions read only
  ([creation steps](willow-pilot.md#github-credential-for-standing-mode)),
  forwarded through SSH stdin. cloudmac receives only JIT material.
- **Bounded API use**: demand lists one workflow's runs; assignment reads
  the reserved job and the runner list; transient failures back off and
  never end either controller loop.

cloudmac isolation (`docs/ci/mac-jit.md`): the SSH login runs only
`mac-run-once`/`mac-quiesce` of one root-owned binary through sudoers; the
runner tree is root-owned and verified against a manifest pinned by the
controller before every launch; jobs run as the unprivileged `carrick-ci`
account, which cannot write the tree, the binary, the policy or the hook;
reaping needs no sudo target a job could write.

Merge-queue gate integrity: the comparison runs in hosted `hvf-gate` and
`kvm-gate` jobs. Each checks out the merge group's **base** commit cleanly,
builds and runs the base's `carrick-xtask` in that checkout (its own
`.cargo` config, lockfile and working directory) and downloads only the
candidate's receipt artifact; no candidate code executes there. The hardware
lane jobs only produce receipts and never wait, so a deep queue cannot
deadlock on the single runner.

**Write access to this repository means trusted.** A merge group runs the
candidate's own workflow file and the candidate's `xtask accept`, which
writes the receipt the gate judges. A pull request that rewrote either could
skip or falsify its receipt. The gate protects against accidental
regressions, not against a malicious writer; review of `.github/` and
`crates/carrick-xtask` changes, and who holds write access, are the
controls.

cloudmac cross-job persistence: before every launch `mac-run-once` kills
every `carrick-ci` process, recreates the job home from a root-owned
skeleton and empties `_work`/`_diag` (no symlink following); it refuses to
launch unless `cron.deny` and `at.deny` name the account (configured live),
and the toolchain is root-owned and read-only with a per-job `CARGO_HOME`.
Processes are killed again after the job.

Residual risk, stated plainly: standing mode admits commits from this
repository's branches that reach main or the merge queue, i.e. trusted code.
Within one job, a job can still use whatever `carrick-ci` and the network
allow; a killed process cannot persist, but a cloudmac kernel or setuid
vulnerability is out of scope. No live
Willow, cloudmac or GitHub operation was performed for this review; the
director qualifies it live.

## Contabo standing credential

The standing controller also runs on the dedicated Contabo host (issue #287,
[contabo-kvm.md](contabo-kvm.md)). Admission, JIT handling, the job-start
hook and teardown are the same code. Site placement comes from the typed
table in `ci_scaler/site.rs`, which fails closed on an unknown host. The
protected-VM proof covers every VM in the site's list (Contabo: the agent
workers 101-104 and their template 9000), and Willow's row is pinned to its
previous constants by test.

Departures from the Willow procedure, and their reasons:

- **The GitHub token is stored on the host.** A standing service must
  survive reboots, which a token forwarded over SSH stdin cannot. It is a
  systemd encrypted credential (`/etc/credstore.encrypted/carrick-ci-gh-token`,
  root 0600), loaded with `LoadCredentialEncrypted=` into the unit's private
  credential directory and exported only into the controller's environment.
  Contabo has no TPM, so the credential is encrypted with the host key
  (`/var/lib/systemd/credential.secret`) alone, on unencrypted media; root
  on the host can decrypt it. The token is the owner's existing one rather
  than the minimal fine-grained token described in willow-pilot.md. Replace
  it with that token (Administration read/write and Actions read on
  `carrick-sh/carrick` only) when convenient; the unit needs no other change.
- **Clones use static addresses on a private NAT bridge shared with the
  agent workers.** The host runs no DHCP or DNS service for them and opens no
  host firewall port. Besides the guest firewall, which a job with root in
  the clone could undo, template 300 carries a PVE VM firewall on `net0`:
  default deny in and out, `ipfilter` on, SSH in from the gateway only,
  and out to public IPv4 only (all private and link-local ranges dropped
  first; no IPv6). Clones inherit it. The controller fails closed: it checks
  the exact options and ordered rules on the template and on each clone
  before boot, and that the datacenter firewall is enabled.
- **The host is shared with four agent-worker VMs.** They are outside the
  `carrick-ci` pool, so the scoped token has no rights over them, and the
  controller verifies that before serving.
