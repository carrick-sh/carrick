# Repeated signed-test capture

`just xtask stress-capture` repeats an **already signed test executable** on
macOS and stops at the first selected hang, stderr expression, terminating
signal, or exit code. It replaces the manual loops described in #978, #1007,
and #1008 (Part of #1018). Execution is refused on other hosts; orchestration
and classification tests run on Linux.

This is an xtask because it owns repository test artifacts and reuses the
existing host-lease supervisor, load check, and scoped cleanup script. It does
not add build-tool dependencies to the shipped CLI or guest services. Build
and sign the test first through `scripts/test-signed.sh`; no build or re-sign
happens during stress. Use the exact executable emitted by that script.

```sh
just xtask stress-capture \
  --executable /absolute/checkout/target/release/deps/el1_files-<hash> \
  --test el1_files_exit_group_stress \
  --iterations 30 --timeout-seconds 60 --hang-seconds 20 \
  --stderr-regex 'carrick fatal|panicked at' --exit-codes 134,139 \
  --capture bt,ring,core --capture-seconds 120 --ring-records 8192 \
  --output target/stress-exit-group --run-id-prefix exit-group
```

The example uses a 20-second hang threshold to capture before the embedded
30-second watchdog in `el1_files_exit_group_stress`.

Use the full libtest name, including module prefixes. A bounded `--list`
preflight rejects names that select zero tests. The output directory must not
already exist. Codesign verification and entitlement inspection precede the
loop. Preserve the executable and its debug symbols beside any saved cores;
`summary.json` records its SHA-256.

The runner holds shared `carrick` admission on the normal host lease through
capture and cleanup, including when admission is inherited from a gate. It
uses the same load refusal and `CARRICK_ALLOW_LOAD=1` override as signed tests;
the summary records the load report. It never starts Docker. Host-specific CI
admission (such as refusing a gate while Runner.Worker is active on carrick-m4)
still belongs to the host's gate launcher.

Each test receives a unique `CARRICK_RUN_ID`, a new session/process group,
null stdin and file-backed stdout/stderr before executing. LLDB also runs in a
separate session with null stdin, through noninteractive sudo. No terminal is
inherited. Fatal paths are held for the shared capture deadline plus ten seconds.
At a live trigger the runner captures the root test and exact run-id-labelled
carrier/helper processes. The positive PID parsed from a fatal hold notice is
captured first if it belongs to that process census. All PIDs share one
`--capture-seconds` budget, beginning when observation ends; tracer shutdown
and process census also consume that budget. The runner records budget
exhaustion rather than giving every PID a fresh timeout. Each LLDB session
imports this checkout's plugin,
captures selected stacks/rings and a `modified-memory` core, then detaches.
Exited processes cannot be attached: signal/exit triggers preserve logs and
any trace already collected, without promising a post-exit LLDB core.

Optional tracing is armed **before** the test execs:

```sh
just xtask stress-capture \
  --executable /absolute/path/to/signed-test --test exact_test_name \
  --probe 'carrick*:::hvpatch-executor-load-failure' --trace-seconds 15 \
  --output target/stress-load-failure
```

Probe descriptions are restricted to Carrick USDT selectors, with a predicate
covering the test PID and its descendants. Probe arguments are uninterpreted
integers, not assumed pointer layouts. DTrace uses `-Z`, an internal tick
limit, and an independent runner deadline. A startup gate prevents the test
from outrunning probe admission. A trace with zero scoped events is explicitly
inconclusive; a successful iteration may have no failure-probe events. Do not
interpret that as proof that an operation did not happen. Tracing and debugger
attachment perturb scheduling; compare only equally instrumented runs.

Every iteration invokes `sudo -n scripts/sudo/kill.sh <run-id>` and kills its
owned test process group, including after monitoring/capture errors. The
owned group is killed before `kill.sh`; an EPERM from a zombie-only group is
accepted only after `waitid(WNOWAIT)` confirms that the owned leader exited.

LLDB and DTrace stop by sending TERM to their sudo leader, allowing sudo to
relay it and DTrace to flush its END clause. After a bounded wait, surviving
argv are reaped by `sudo -n scripts/sudo/kill-capture.sh <run-directory>`.
The helper matches the literal run directory with a suffix boundary, requires
the iteration marker, and never kills by tool name or by a supplied PID. Each
LLDB invocation uses a command file inside that directory, even for bt-only
captures. The runner verifies no scoped argv remain and reaps the launcher.
There is no privileged `/bin/kill` dependency. Noninteractive sudo permission
is needed for the two cleanup scripts, LLDB and DTrace; denied cleanup is an
error, never a skipped capture.
SIGINT, SIGTERM and SIGHUP request cleanup. SIGKILL, host failure, or a denied
privileged cleanup can still require manual scoped recovery; errors remain in
the summary.

`summary.json` and `summary.txt` are rewritten after each cleaned iteration.
They contain counts, the stopping run, timings, the parsed fatal PID,
artifact paths, and capture or cleanup errors. Each iteration produces a
record even if setup, startup admission, trace inspection or monitoring fails.
Unexpected Drop cleanup failures are also appended to `cleanup-error.txt`;
normal cleanup errors appear in the summary. The table is also printed.
An unselected ordinary test failure
is counted and iteration continues; selected triggers or capture/cleanup errors
stop immediately. Any observed failure yields a nonzero command result. Regex
matching is incremental with a 64 KiB overlap; expressions requiring a match
longer than that are unsupported. Per-run timeout ends the observation phase;
`--hang-seconds`, when present, is an earlier observation deadline and thus
wins over `--timeout-seconds`. Capture and cleanup have separate hard bounds;
the timeout flag is not a total wall-clock limit for those phases.

Fatal capture in signed embed tests requires the harness from this change:
`common::guest_lock()` calls the same
`carrick_fatal::arm_debugger_hold_from_env` function as the CLI before guest
work. Both the environment policy and hold-notice PID parser live in
`carrick-fatal`. Unset, zero, invalid or out-of-range values leave the hold disabled, matching the CLI.
The runner supplies a positive hold of `--capture-seconds + 10` (capped at
`u32::MAX`) on every run, including custom stderr-trigger runs.

A fatal message can arrive before its hold notice. The runner waits for
`carrick fatal: holding … s for a debugger (pid …)` before treating a live
fatal as ready for capture. The hold notice itself triggers capture even
with a custom stderr regex. Generic stderr matches still trigger immediately;
a fatal that exits before announcing a hold is recorded without live artifacts.
The normal run/hang deadlines remain in force while waiting for the notice.
The embed test's own watchdog also remains active, so choose a hang threshold
below that watchdog and allow for its deadline when sizing live captures.

Portable tests cover the shared environment arming policy, hold PID parsing,
TERM/END flushing, scoped escalation with sibling-prefix isolation, WNOWAIT
custody, and recorded setup failures. Fake children announce a hold, exit
before one, or remain alive without one; terminating fixtures use a 30-second
observation deadline while intentional hangs use a short deadline.
Live fatal and hang capture still require the director's Mac verification.
