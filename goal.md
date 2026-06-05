# Process-control conformance goal

## Goal

Make process-control conformance boring.

Carrick should agree with Linux for the process-control behaviors that real
language runtimes depend on: traced child stops, exec/wait status, process group
changes, signal interruption and restart, stopped/continued children, and
parent/child cleanup under fork-heavy workloads. LTP remains the discovery
oracle, but every runtime fix must land with a carrick-owned deterministic
probe or focused unit test before we claim the behavior is done.

## Ambitious autonomous target

Drive the current process-control cluster from classified NEW rows to owned,
boring behavior without weakening the gate. The near-term push is to finish the
remaining ptrace signal/death semantics, then use that sharper process-state
model to make the Go `os/exec` and CPython process-pool rows produce comparable
summaries instead of disappearing mid-workload.

This is autonomous because every step has a current raw row, a Linux oracle, and
a reducer path. We do not need to bless, quarantine, or invent broad ptrace
debugger support to make measurable progress.

## Current baseline

Baseline date: 2026-06-05.

Command:

```sh
just conformance
```

Result:

```text
1222 rows
1155 MATCH
67 NEW
0 regressions
0 timeouts
```

The previous blocking rows are cleared:

- `node-libuv`: `MATCH`, carrick failure matches oracle failure.
- `go-runtime`: `MATCH`, 52/52 on carrick and oracle.

This goal starts from a green regression gate. The target is to reduce NEW rows
by fixing verified process-control gaps, not by blessing, quarantining, or
weakening the gate.

Current targeted ptrace rerun after the `ptracesigdeath` reducer:

```text
ltp-ptrace05  carrick 806/1184, oracle 63/63, run conf-27543-c00
ltp-ptrace06  carrick no parseable summary, oracle 48/48, run conf-27543-c01
```

## Primary target rows

These are the first rows to investigate because they share process-control,
wait-status, stop-state, or signal-interruption behavior:

| Row | Ecosystem | Current carrick | Oracle | Why it belongs here |
| --- | --- | --- | --- | --- |
| `ltp-ptrace05` | LTP | 806/1184 after `ptracesigdeath` | 63/63 | `PTRACE_TRACEME` and traced self-`SIGKILL` are no longer the blocker; remaining failures are broader signal-delivery stop semantics (`ptrace05.c:149`). |
| `ltp-ptrace06` | LTP | no parseable summary after `ptracesigdeath` | 48/48 | Same tracee-state surface, likely exec-stop or unimplemented ptrace request/state hiding the LTP summary. |
| `go-os_exec` | Go | 0/0 | 86/86 | Process execution test suite stalls or exits before classified Go assertions. |
| `go-syscall` | Go | 0/0 | 34/34 | Broad syscall package fallout; inspect for process/wait/signal cases first. |
| `cpython-subprocess` | CPython | 280/280 | 278/278 | Count inversion needs assertion-level audit; do not treat as a win without proof. |
| `cpython-concurrent_futures` | CPython | 0/0 | 20/20 | Process-pool/forkserver behavior currently fails to produce a comparable result. |
| `ltp-setpgid01` | LTP | 2/2 | 1/2 | Inversion risk: may be under-enforcement rather than better behavior. |
| `ltp-pause02` | LTP | 0/3 | 1/1 | Signal interruption/restart behavior around sleeping processes. |
| `ltp-kill10` / `ltp-kill12` | LTP | 1/1 | 1/1 | Count match but assertion identity must be checked before relying on it. |
| `go-os_signal` | Go | 28/30 | 29/30 | Adjacent signal/process-control surface. |
| `ltp-sigaction01` | LTP | 3/4 | 4/4 | Adjacent signal ABI row; only include fixes that affect this goal's process-control path. |

Rows outside this cluster can be fixed opportunistically if a reducer proves the
same root cause, but they are not part of this goal's success criteria.

## Acceptance rules

1. No quarantine-only changes.
2. No baseline blessing as a substitute for a runtime fix.
3. No count-only MATCH claims for LTP or language-runtime rows. Diff the actual
   assertion lines or reduce the behavior to a deterministic probe.
4. Every behavior fix gets an owning probe or focused unit test before the
   runtime change is considered complete.
5. Every wait in a new probe must be bounded. A broken runtime path should print
   a deterministic false/errno/status line, not hang the harness.
6. Prefer Linux/Darwin first principles over in-memory shadow state when a host
   kernel primitive can be used faithfully.
7. Keep commits logical: probe/reducer, runtime fix, docs/coverage, and harness
   changes should be split when they are independently meaningful.

## Probe backlog

Add probes under `conformance-probes/src/bin/` for the smallest behavior that
explains each row. These names are suggestions; rename them if the reducer
points to a sharper invariant.

| Probe | Invariant |
| --- | --- |
| `ptracetraceme` | Child calls `ptrace(PTRACE_TRACEME)`, raises/stops, parent observes the Linux wait status, then continues/reaps it. |
| `ptracesigdeath` | A traced child receiving `SIGKILL` dies with a signaled wait status, while ordinary delivered signals report the Linux ptrace stop expected by `ptrace05`. |
| `traceexecstop` | A traced child that execs reports the expected stop/exec wait status rather than disappearing or running through silently. |
| `stoppedwaitstatus` | Parent observes stopped, continued, signaled, and exited states with Linux-compatible `waitpid`/`waitid` status encoding. |
| `setpgidrules` | `setpgid` validates session/process-group constraints, races, and self/child cases like Linux. |
| `pauseinterrupt2` | A sleeping child interrupted by the relevant signal returns `EINTR` or restarts exactly when Linux does. |
| `subprocesspipes` | Fork/exec with stdio pipes closes, EOFs, and reaps consistently under parent-side waits. |

Each probe must be validated with:

```sh
scripts/run-probe.sh <probe>
just conformance-probes
```

If a behavior is better expressed as a Rust unit/integration test, update
`docs/conformance-coverage.md` with the owning test instead of forcing it into a
guest probe.

## Implementation milestones

### Milestone 1: Classify the process-control rows

For each primary target row:

- Locate the raw output under `target/conformance/raw/`.
- Compare carrick output against the cached Docker/oracle assertion lines.
- Mark the row as one of:
  - missing syscall,
  - wrong errno/validation order,
  - wrong wait/status encoding,
  - signal interruption/restart bug,
  - harness/oracle mismatch,
  - unrelated to this process-control goal.
- Record the classification in this file before fixing the row.

Exit criteria: every primary row has a one-line classification and a chosen
first reducer/probe.

### Milestone 2: Own ptrace stop and signal-death semantics

Start with `ltp-ptrace05` and `ltp-ptrace06`.

Initial fact: syscall 117 was wired in `dispatch/proc.rs` but returned
`ENOSYS`. Current fact: the canonical `PTRACE_TRACEME` child-stop path is owned
by `ptracetraceme`, and the next gap is tracee signal delivery. `ltp-ptrace05`
now reports `SIGKILL` stopping instead of killing the tracee and several signal
cases that do not stop when Linux expects a ptrace stop. `ltp-ptrace06` still
produces no parseable stdout summary.

The next useful behavior is not full debugger support; it is enough tracee
signal/death and exec-stop state for the canonical LTP rows to reach assertion
parity or expose a separate, named blocker.

Exit criteria:

- `ptracetraceme` probe exists and fails on the pre-fix carrick.
- Runtime implements the minimal Linux-compatible tracee state needed by the
  probe.
- Probe matches Docker Linux. Landed 2026-06-05: `PTRACE_TRACEME`/`PTRACE_CONT`
  are probe-owned, positive ptrace pids are translated through the pid
  namespace, and self-target `SIGSTOP` stops directly instead of being
  delivered twice through the pending-signal path.
- `ptracesigdeath` exists and fails on the current carrick before the runtime
  change.
- Runtime implements traced self-`SIGKILL` as signal death rather than a
  ptrace-visible stop, and routes at least one default-ignored traced self-signal
  through a ptrace stop before `PTRACE_CONT`.
- Probe matches Docker Linux. Landed 2026-06-05: `ptracesigdeath` owns traced
  self-`SIGKILL` wait status and default-ignored `SIGCHLD` stop/continue.
- `ltp-ptrace05` improves beyond 82/103 and no longer reports the
  `ptrace05.c:139` SIGKILL-stop failure; remaining `ptrace05.c:149` cases must
  be split into their own reducer.
- `ltp-ptrace06` produces a parseable summary, improves, or is reclassified with
  an exact exec-stop blocker.

### Milestone 3: Stabilize exec/wait/subprocess semantics

Use `go-os_exec`, `cpython-subprocess`, and `cpython-concurrent_futures` as the
workload pressure tests.

Exit criteria:

- At least one owned probe captures the root cause before the runtime fix.
- The target language row changes from NEW to MATCH, or the remaining NEW
  difference is proven to be a separate assertion with its own follow-up.
- `just conformance-probes` stays green.

### Milestone 4: Process groups and signal interruption

Use `ltp-setpgid01`, `ltp-pause02`, `go-os_signal`, and adjacent kill/sigaction
rows to close the process-group and interruption rules exposed by the first two
milestones.

Exit criteria:

- `setpgidrules` or a focused unit test owns the process-group invariant.
- `pauseinterrupt2` or an existing signal probe owns the interruption invariant.
- Count inversions are fixed unless assertion-level evidence proves a LinuxKit
  oracle weakness; proven oracle weaknesses must be documented as non-goal
  evidence, not used to hide an unimplemented carrick behavior.

## Final success criteria

This goal is complete when all of the following are true:

- `just conformance` has zero regressions and zero timeouts.
- The total NEW count drops from 67 to 45 or lower, or every remaining
  process-control NEW row is proven to be a distinct non-process-control gap.
- `ltp-ptrace05` and `ltp-ptrace06` no longer fail because `ptrace` returns
  `ENOSYS`, because `SIGKILL` is reported as a stop, or because tracee exec-stop
  state is absent.
- `go-os_exec` no longer reports `0/0` against an 86/86 oracle.
- `cpython-concurrent_futures` no longer reports `0/0` against a 20/20 oracle,
  unless the exact remaining assertion is documented and owned by a follow-up.
- `docs/conformance-coverage.md` maps every new invariant to its owning probe or
  unit test.
- All committed changes have focused validation in the commit body.

## Non-goals

- Full debugger-grade ptrace support.
- Implementing unrelated missing syscall families such as POSIX mqueue, POSIX
  AIO, mount APIs, pkeys, Landlock, or NUMA policy.
- Chasing all 67 NEW rows.
- Treating a count-based MATCH as proof without assertion-level evidence.
- Changing the conformance harness to hide slow or failing rows.

## Working notes

Keep this section current as classifications and fixes land.

| Row | Classification | Owner/probe | Status |
| --- | --- | --- | --- |
| `ltp-ptrace05` | missing syscall plus wrong traced-child stop/status path: raw `conf-42088-c1010` shows `ptrace(PTRACE_TRACEME)` returning `ENOSYS`, then repeated "Didn't stop as expected" and live child cleanup. After `ptracetraceme`, targeted rerun `conf-24123-c00` improves to 82/103 vs oracle 63/63. After `ptracesigdeath`, targeted rerun `conf-27543-c00` improves to 806/1184; `SIGKILL` now reports "Killed with SIGKILL, as expected" and the old `ptrace05.c:139` signature is gone, while remaining failures are `ptrace05.c:149` signal-delivery stop cases. | `ptracetraceme` and `ptracesigdeath` landed; next reducer should own the remaining nonfatal/stop-signal delivery cases before `traceexecstop` | TRACEME stop/continue and traced self-`SIGKILL` death owned; remaining signal-specific ptrace stop semantics |
| `ltp-ptrace06` | same ptrace tracee-state surface: raw `conf-42088-c1011` has `PTRACE_TRACEME failed` and `child status not stopped: 0x100`. After `ptracetraceme`, targeted rerun `conf-24123-c01` still emits no parseable stdout summary, only the root-user warning on stderr. After `ptracesigdeath`, targeted rerun `conf-27543-c01` still emits no parseable stdout summary, only the root-user warning on stderr. | `traceexecstop` plus remaining ptrace signal-stop reducer | minimal `PTRACE_TRACEME` stop/continue and traced self-`SIGKILL` death owned; still no LTP summary |
| `go-os_exec` | process/wait workload does useful work but exits without a parseable suite summary in `conf-42088-c593`; tail ends after `TestIgnorePipeErrorOnSuccess`, and live observation saw an `os_exec.test` child stopped. | `stoppedwaitstatus` before broader `subprocesspipes` | classified; reduce the stopped/waited child path |
| `go-syscall` | mixed process-control and unrelated syscall fallout: raw `conf-42088-c615` includes `TestExec` runtime `netpoll failed` after `epollwait on fd 3 failed with 9`, plus namespace/capability/file-mode failures. | `subprocesspipes` only for `TestExec`; split non-process rows out | classified; process-control subset only |
| `cpython-subprocess` | harness/oracle assertion mismatch, not a failure: carrick passes `test_no_leaking` in both poll modes while cached oracle marks both skipped. | oracle refresh/assertion audit | classified; do not bless count inversion as proof |
| `cpython-concurrent_futures` | process-pool/forkserver run starts and passes fork/forkserver cases, then stops mid-`ProcessPoolForkserverProcessPoolExecutorTest.test_max_tasks_early_shutdown` without a regrtest summary. | `subprocesspipes` / process-pool reducer | classified; reduce forkserver shutdown/harness exit |
| `ltp-setpgid01` | inversion risk: carrick reports both `setpgid(1, 1)` and `setpgid(0, 0)` pass, while cached oracle has one failure. This needs the Docker assertion refreshed before treating carrick as better or worse. | `setpgidrules` plus `--refresh-oracle --suite ltp-setpgid01` | classified; oracle assertion required before fix |
| `ltp-pause02` | signal interruption/restart bug: raw `conf-42088-c959` reports unexpected `SIGINT`, then `pause was interrupted but the retval and/or errno was wrong`. | `pauseinterrupt2` | classified; runtime signal interruption path |
| `ltp-kill10` | harness/oracle identity mismatch: carrick raw `conf-42088-c857` has `TPASS`, cached oracle has totals but no `summary` id, yielding `summary ok` vs absent. | LTP parser/oracle-cache audit | classified; non-runtime until parser/oracle evidence changes |
| `ltp-kill12` | harness/oracle identity mismatch: carrick raw `conf-42088-c859` has `TPASS`, cached oracle has totals but no `summary` id, yielding `summary ok` vs absent. | LTP parser/oracle-cache audit | classified; non-runtime until parser/oracle evidence changes |
| `go-os_signal` | signal delivery/status mismatch: raw `conf-42088-c595` shows `TestAtomicStop` failing because one iteration exits status 2 where Docker expects `SIGINT`; `TestTerminalSignal` is an existing oracle-matching fail. | `pauseinterrupt2` or new `atomicstop` reducer | classified; adjacent signal runtime path |
| `ltp-sigaction01` | signal ABI bug: raw `conf-42088-c1123` says `SA_RESETHAND should not cause SA_SIGINFO to be cleared, but it was`. | focused signal-action unit/probe | classified; adjacent, lower priority than pause/ptrace |

## Next autonomous slice

1. Add a `ptracesignalstop` reducer that enumerates the remaining
   `ptrace05.c:149` failures, including Linux stop signals and real-time signal
   numbers that Darwin cannot faithfully raise as host signals.
2. Replace the traced-child nonfatal self-signal path's host-raise shortcut with
   a deterministic Linux wait-status model only as far as the probe requires.
3. Validate with `scripts/run-probe.sh ptracesignalstop`,
   `scripts/run-probe.sh ptracesigdeath`, `just conformance-probes`, and targeted
   `just conformance full --suite ltp-ptrace05 --suite ltp-ptrace06 --no-image-refresh`.
4. Update this file and `docs/conformance-coverage.md`, then land a logical
   commit with the validation commands in the body.
