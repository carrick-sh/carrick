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
