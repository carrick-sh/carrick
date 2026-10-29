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
inherited. Fatal paths are held for the capture deadline plus ten seconds.
At a live trigger the runner captures the root test and exact run-id-labelled
carrier/helper processes. Each LLDB session imports this checkout's plugin,
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
owned test process group, including after monitoring/capture errors. DTrace
gets a scoped group interrupt, then bounded kill escalation if necessary.
This requires noninteractive permission for the cleanup script, LLDB, DTrace,
and scoped `/bin/kill`; denied permission is an error, never a skipped capture.
SIGINT, SIGTERM and SIGHUP request cleanup. SIGKILL, host failure, or a denied
privileged cleanup can still require manual scoped recovery; errors remain in
the summary.

`summary.json` and `summary.txt` are rewritten after each cleaned iteration.
They contain counts, the stopping run, timings, artifact paths, and capture or
cleanup errors. The table is also printed. An unselected ordinary test failure
is counted and iteration continues; selected triggers or capture/cleanup errors
stop immediately. Any observed failure yields a nonzero command result. Regex
matching is incremental with a 64 KiB overlap; expressions requiring a match
longer than that are unsupported. Per-run timeout ends the observation phase;
capture and cleanup have their own separate hard bounds.
