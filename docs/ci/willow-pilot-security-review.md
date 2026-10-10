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
`work/willow-pilot`, one approved SHA). The merge-queue gate adds a second,
bounded policy for Willow (`ci-scaler standing`) and cloudmac
(`ci-scaler mac-jit`). Both are one `Admission::Standing` value in
`crates/carrick-xtask/src/ci_scaler.rs`, used for demand detection and in the
job-start hook; there is no second copy of the rules.

| Check | Pilot | Standing |
|---|---|---|
| Repository (run and head repository) | `carrick-sh/carrick` | `carrick-sh/carrick` |
| Workflow file | `willow-pilot.yml` | `kernel-runtime.yml`, at the ref being run |
| Events and refs | `workflow_dispatch` on `work/willow-pilot` | `merge_group` on `gh-readonly-queue/main/*`; `push` or `workflow_dispatch` on `main` |
| SHA | one approved SHA | any full SHA reachable by those refs |
| Labels | `ci_scaler::LABELS` | `LABELS` (Willow), `HVF_LABELS` (cloudmac) |
| Concurrency | one clone | Willow 1 by default, `--max-concurrency 2` at most; cloudmac 1 |

Not admitted, by test (`tests/ci_scaler.rs`): `pull_request` (including a
`pull_request` event claiming `refs/heads/main`), `pull_request_target`,
`schedule`, other branches and tags, an empty or foreign merge-queue prefix,
a foreign workflow file (`ci.yml`, `willow-pilot.yml`), a workflow file read
at a different ref, a fork repository, and a short SHA. The pilot policy and
the standing policy do not admit each other's runs or jobs.
`kernel-runtime.yml` has no `pull_request` trigger; a test fails if one is
added.

Unchanged properties, retained by construction and tests:

- **JIT one-use registration.** Each runner is minted by
  `generate-jitconfig` for one ledger name; Willow runners consume a
  `mkdir` marker in the guest, cloudmac runners a `mkdir`'d per-name state
  directory. The JIT never enters a ledger, log or disk file.
- **Willow budget.** Clone range 308-349 (typed `CloneId`), pool
  `carrick-ci`, the protected-VM permission census, the 80% projected CPU
  ceiling, 10 GiB available memory, 150 GiB thin-pool data headroom and
  metadata below 80% apply before every clone. With two clones, every
  non-template pool member must be an active ledger clone; any unknown object
  blocks all admission. A reconcile error or ambiguous clone freezes new
  admission until a clean pass; the CPU ceiling still stops the controller.
- **Job-start hook.** Repository, event, workflow file and ref are verified
  before any step; rejection runs `exec /bin/kill -KILL 0` on the runner's
  dedicated session (`setsid --wait` on Willow, `setsid()` in
  `mac-run-once`). `tests/ci_scaler_hook.rs` proves process death for both
  hook variants against `always()`/`failure()` steps. The policy is read from
  a controller-written file that must be a regular file writable only by its
  owner (`/etc/carrick-ci/policy`, root 0644, on Willow; `run/<name>/policy`,
  0600, on cloudmac); the hook reads no environment variable a workflow could
  set.
- **Secrets.** The PVE token stays in `/root/carrick-ci-token.json` on Willow.
  The GitHub credential stays in `gh` on the director's Mac for cloudmac and
  is forwarded over SSH stdin to the Willow controller's memory as before;
  cloudmac receives only JIT material. External command output is parsed in
  memory and never logged (`ScalerError::External` carries static text only).

Residual risk, stated plainly: standing mode admits any commit that reaches
main or the merge queue. Those jobs run as the runner user; on cloudmac that
user persists between jobs and can modify the runner directory and future
state directories, so an admitted job is trusted code. The cloudmac hook
binary must be root-owned (`mac-run-once` refuses otherwise) so the admission
decision cannot be replaced from a job. No live Willow, cloudmac or GitHub
operation was performed for this review; the director qualifies it live.
