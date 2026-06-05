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
boring behavior without weakening the gate. The near-term push is to close the
CPython forkserver/process-pool hang by reducing it to a deterministic
process-wait, fd-readiness, or futex invariant, then use that sharper model to
keep the Go `os/exec`, CPython subprocess, and signal-interruption rows as
comparable pressure workloads instead of letting them disappear mid-workload.

This is autonomous because every step has a current raw row, a Linux oracle, a
focused reducer path, and a first-principles kernel primitive to compare against.
We do not need to bless, quarantine, or invent broad ptrace debugger support to
make measurable progress.

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

Current targeted ptrace rerun after the `ptraceinvaliderrno` reducer:

```text
ltp-ptrace05  MATCH, carrick 63/63, oracle 63/63, run conf-51453-c00
ltp-ptrace06  MATCH, carrick 48/48, oracle 48/48, run conf-51453-c01
```

Latest live refresh note: a full conformance refresh later stopped in
`cpython-concurrent_futures` run `conf-42207-c75`, hanging in
`ProcessPoolForkserverProcessPoolExecutorTest.test_max_tasks_early_shutdown`.
The exact single test passes under carrick, but the full forkserver class still
times out. A two-test sequence that had reproduced intermittently passed 5/5
after the wake-pipe drain guard below, while the full class still timed out in
run `procgoal-cf-class-narrow-48477` with 10 leaked semaphores. The
`futexsharedalias` diagnostic probe now MATCHes Linux, so same-page shared
futex word aliasing is ruled out as the root cause. Recent targeted
`ltp-pause02` attempts are currently quiet, so pause/signal interruption
remains pressure coverage rather than the next reducer until it produces a
fresh deterministic RED.

## Primary target rows

These are the first rows to investigate because they share process-control,
wait-status, stop-state, or signal-interruption behavior:

| Row | Ecosystem | Current carrick | Oracle | Why it belongs here |
| --- | --- | --- | --- | --- |
| `ltp-ptrace05` | LTP | MATCH 63/63 after `ptracesignalstop` | 63/63 | `PTRACE_TRACEME`, traced self-`SIGKILL`, `SIGCONT`, and Linux RT signal-delivery stops are now owned. |
| `ltp-ptrace06` | LTP | MATCH 48/48 after `ptraceinvaliderrno` | 48/48 | Exec-stop setup and invalid PEEK/POKE request errno are now owned without claiming full debugger memory/register access. |
| `go-os_exec` | Go | MATCH 86/86 in targeted rerun `conf-93241-c156` | 86/86 | Previously 0/0; current evidence shows process execution suite parity, so keep watching it as pressure coverage rather than the next reducer. |
| `go-syscall` | Go | 0/0 | 34/34 | Broad syscall package fallout; inspect for process/wait/signal cases first. |
| `cpython-subprocess` | CPython | 280/280 | 278/278 | Count inversion needs assertion-level audit; do not treat as a win without proof. |
| `cpython-concurrent_futures` | CPython | hangs in `test_max_tasks_early_shutdown` during forkserver class run | 20/20 | Process-pool/forkserver shutdown currently fails to produce a comparable result. Shared futex word aliasing is now probe-ruled-out; continue on process wait/fd readiness/forkserver cleanup. |
| `ltp-setpgid01` | LTP | 2/2 | 1/2 | Inversion risk: may be under-enforcement rather than better behavior. |
| `ltp-pause02` | LTP | unstable historically; latest targeted attempts currently MATCH | 1/1 | Signal interruption/restart behavior around sleeping processes; keep as pressure coverage until it produces a fresh RED. |
| `ltp-kill10` / `ltp-kill12` | LTP | 1/1 | 1/1 | Count match but assertion identity must be checked before relying on it. |
| `go-os_signal` | Go | unstable pressure row: NEW 28/30 in `conf-71289-c00`, MATCH 29/30 in `conf-18439-c00` | 29/30 | Adjacent signal/process-control surface; `TestAtomicStop` flips, while `TestTerminalSignal` still fails on both carrick and oracle. |
| `ltp-sigaction01` | LTP | MATCH 4/4 after `sigactionresetinfo`, latest targeted rerun `conf-18439-c02` | 4/4 | Adjacent signal ABI row; SA_RESETHAND + SA_SIGINFO old-state preservation is now owned. |

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
| `ptraceinvaliderrno` | Invalid PEEK/POKE TEXT/DATA/USER ptrace requests against a stopped tracee return Linux-compatible `EIO`/`EFAULT` rather than `ENOSYS`. |
| `stoppedwaitstatus` | Parent observes stopped, continued, signaled, and exited states with Linux-compatible `waitpid`/`waitid` status encoding. |
| `setpgidrules` | `setpgid` validates session/process-group constraints, races, and self/child cases like Linux. |
| `pauseinterrupt2` | A sleeping child interrupted by the relevant signal returns `EINTR` or restarts exactly when Linux does. |
| `subprocesspipes` | Fork/exec with stdio pipes closes, EOFs, and reaps consistently under parent-side waits. |
| `futexsharedalias` | Two distinct futex words in the same `MAP_SHARED` page remain distinct host wait keys; waking word A cannot consume the waiter for word B. |

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
- `ptracesignalstop` exists and fails on the current carrick before the runtime
  change for Linux `SIGCONT` and real-time self-signals.
- Runtime routes traced self-`SIGCONT` and Linux RT self-signals through a
  ptrace-visible stop carrier instead of letting them fall through to normal
  exit.
- Probe matches Docker Linux. Landed 2026-06-05: `ptracesignalstop` owns
  `SIGTERM`, `SIGSTOP`, `SIGCONT`, `SIGRTMIN`, and `SIGRTMAX` stop/continue.
- `ltp-ptrace05` matches the cached Docker oracle: 63/63 vs 63/63 in
  `conf-7738-c00`.
- `traceexecstop` exists and fails on the current carrick before the runtime
  change.
- Runtime reports a traced execve as a SIGTRAP stop before the new image runs,
  releasing any vfork-suspended parent before stopping the child.
- Probe matches Docker Linux. Landed 2026-06-05: `traceexecstop` owns the
  ptrace06 exec-stop setup leg.
- `ltp-ptrace06` now produces a parseable summary and improves from none to
  0/48 vs oracle 48/48 in `conf-31128-c01`; the remaining blocker is invalid
  PEEK/POKE request errno.
- `ptraceinvaliderrno` exists and fails on the current carrick before the
  runtime change for invalid TEXT/DATA/USER PEEK/POKE request errno.
- Runtime maps only the invalid PEEK/POKE address cases that Linux definitively
  answers with `EIO`, leaving non-invalid debugger memory/register access
  unsupported.
- Probe matches Docker Linux. Landed 2026-06-05: `ptraceinvaliderrno` owns the
  ptrace06 invalid request errno matrix.
- `ltp-ptrace06` matches the cached Docker oracle: 48/48 vs 48/48 in
  `conf-51453-c01`.

### Milestone 3: Stabilize exec/wait/subprocess semantics

Use `go-os_exec`, `cpython-subprocess`, and `cpython-concurrent_futures` as the
workload pressure tests. The current live target is
`cpython-concurrent_futures`: CPython's forkserver process pool churns through
semaphores, worker exits, epoll/select waits, and parent-side fd cleanup. The
first-principles path is to keep shrinking that class hang until a bounded
probe or focused unit test owns the exact host-wait/futex/fd invariant.

Exit criteria:

- At least one owned probe captures the root cause before the runtime fix.
- `futexsharedalias` proves that two shared futex words on one mapped page use
  distinct host wait keys. It MATCHes Linux on current carrick, so it is
  diagnostic coverage and not the forkserver root cause.
- `host_signal::tests::drain_fd_forces_empty_pipe_nonblocking` owns the
  host-side invariant that draining an internal wake pipe must never turn into
  an unbounded blocking read if fd flags are disturbed by fork/fd churn.
- The target language row changes from NEW to MATCH, or the remaining NEW
  difference is proven to be a separate assertion with its own follow-up.
- `just conformance-probes` stays green.

### Milestone 4: Process groups and signal interruption

Use `ltp-setpgid01`, `ltp-pause02`, `go-os_signal`, and adjacent kill/sigaction
rows to close the process-group and interruption rules exposed by the first two
milestones.

Exit criteria:

- `setpgidrules` or a focused unit test owns the process-group invariant.
- `pauseinterrupt2` or a sharper focused reducer owns the unstable
  `ltp-pause02` interruption invariant, and `sigactionresetinfo` owns the
  adjacent SA_RESETHAND + SA_SIGINFO reset-state rule that moved
  `ltp-sigaction01` to MATCH.
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
| `ltp-ptrace05` | missing syscall plus wrong traced-child stop/status path: raw `conf-42088-c1010` shows `ptrace(PTRACE_TRACEME)` returning `ENOSYS`, then repeated "Didn't stop as expected" and live child cleanup. After `ptracetraceme`, targeted rerun `conf-24123-c00` improves to 82/103 vs oracle 63/63. After `ptracesigdeath`, targeted rerun `conf-27543-c00` improves to 806/1184; `SIGKILL` now reports "Killed with SIGKILL, as expected". After `ptracesignalstop`, targeted rerun `conf-7738-c00` matches 63/63 vs oracle 63/63. | `ptracetraceme`, `ptracesigdeath`, and `ptracesignalstop` | MATCH; ptrace05 signal-death and signal-delivery stop matrix owned |
| `ltp-ptrace06` | same ptrace tracee-state surface: raw `conf-42088-c1011` has `PTRACE_TRACEME failed` and `child status not stopped: 0x100`. After `ptracetraceme`, targeted rerun `conf-24123-c01` still emits no parseable stdout summary, only the root-user warning on stderr. After `ptracesigdeath` and `ptracesignalstop`, targeted rerun `conf-7738-c01` still emits no parseable stdout summary. After `traceexecstop`, targeted rerun `conf-31128-c01` emits 48 TFAIL lines, all `ENOSYS` where Linux expects `EIO` or `EFAULT` for invalid PEEK/POKE requests. After `ptraceinvaliderrno`, targeted rerun `conf-51453-c01` matches 48/48 vs oracle 48/48. | `traceexecstop` and `ptraceinvaliderrno` | MATCH; exec-stop setup and invalid ptrace request errno owned |
| `go-os_exec` | previously process/wait workload exited without a parseable suite summary in `conf-42088-c593`; targeted rerun `conf-93241-c156` now matches 86/86 vs oracle 86/86 with assertion ids aligned. | keep as process-control pressure coverage; no reducer needed unless it regresses | MATCH |
| `go-syscall` | mixed process-control and unrelated syscall fallout: raw `conf-42088-c615` includes `TestExec` runtime `netpoll failed` after `epollwait on fd 3 failed with 9`, plus namespace/capability/file-mode failures. | `subprocesspipes` only for `TestExec`; split non-process rows out | classified; process-control subset only |
| `cpython-subprocess` | harness/oracle assertion mismatch, not a failure: carrick passes `test_no_leaking` in both poll modes while cached oracle marks both skipped. | oracle refresh/assertion audit | classified; do not bless count inversion as proof |
| `cpython-concurrent_futures` | process-pool/forkserver run starts and passes fork/forkserver cases, then stops mid-`ProcessPoolForkserverProcessPoolExecutorTest.test_max_tasks_early_shutdown` without a regrtest summary. Docker exact single test passes and carrick exact single test passes. The two-test reducer passed 5/5 after `drain_fd` was hardened against blocking on a disturbed wake pipe, but the full forkserver class still times out (`procgoal-cf-class-narrow-48477`, 10 leaked semaphores). `futexsharedalias` MATCHes Linux, so same-page shared futex word aliasing is no longer the leading fault. | `futexsharedalias`, `host_signal::tests::drain_fd_forces_empty_pipe_nonblocking`, then sharper CPython forkserver class reducer | current live RED target |
| `ltp-setpgid01` | inversion risk: carrick reports both `setpgid(1, 1)` and `setpgid(0, 0)` pass, while cached oracle has one failure. This needs the Docker assertion refreshed before treating carrick as better or worse. | `setpgidrules` plus `--refresh-oracle --suite ltp-setpgid01` | classified; oracle assertion required before fix |
| `ltp-pause02` | signal interruption/restart bug when it reproduces: raw `conf-42088-c959` reported unexpected `SIGINT`, then `pause was interrupted but the retval and/or errno was wrong`; rerun `conf-71289-c01` matched, and later `conf-18439-c01` reproduced the same signature, but latest focused attempts and `pauseinterrupt2` are currently MATCH. | `pauseinterrupt2` or sharper interruption reducer if the row turns RED again | pressure coverage; no runtime fix without fresh RED |
| `ltp-kill10` | harness/oracle identity mismatch: carrick raw `conf-42088-c857` has `TPASS`, cached oracle has totals but no `summary` id, yielding `summary ok` vs absent. | LTP parser/oracle-cache audit | classified; non-runtime until parser/oracle evidence changes |
| `ltp-kill12` | harness/oracle identity mismatch: carrick raw `conf-42088-c859` has `TPASS`, cached oracle has totals but no `summary` id, yielding `summary ok` vs absent. | LTP parser/oracle-cache audit | classified; non-runtime until parser/oracle evidence changes |
| `go-os_signal` | adjacent signal delivery/status mismatch: raw `conf-42088-c595` showed `TestAtomicStop` failing because one iteration exited status 2 where Docker expected `SIGINT`; rerun `conf-71289-c00` is NEW with `TestAtomicStop` failing at iteration 3, while latest rerun `conf-18439-c00` happens to match 29/30. `TestTerminalSignal` remains an oracle-matching fail. | `atomicstop` pressure reducer if pause reduction does not explain it | unstable pressure coverage |
| `ltp-sigaction01` | signal ABI bug: raw `conf-42088-c1123` says `SA_RESETHAND should not cause SA_SIGINFO to be cleared, but it was`; fixed by preserving SA_SIGINFO metadata in the reset SIG_DFL action for in-handler `sigaction(SIG, NULL, &old)`. | `sigactionresetinfo` + `signal::tests::sa_resethand_resets_disposition_to_default_on_handler_entry` | MATCH 4/4 vs oracle 4/4 in `conf-18439-c02` |

### Probe-gate pressure

2026-06-05: `just conformance-probes` had become the immediate blocker after
the ptrace rows were fixed. `waitexitstorm` was correctness-MATCH only with a
long timeout: a carrick-only long run completed in 69.06s real / 66.20s sys,
and the default probe gate timed out. A focused `carrick trace` showed per-fork
parent waiter churn (`kqueue`, wake pipes, fd close/fcntl traffic) dominating
host kernel time.

Runtime fix: keep the parent's existing `ThreadWaiter` across fork in both
single-threaded and threaded paths. A single-thread fork child can start with a
process-only waiter and upgrade before its first blocking syscall; the threaded
fork child keeps a full waiter because the `itimer` fork-child busy-wait probe
depends on immediate signal-pump wake registration.

Validation after the fix:

```text
scripts/run-probe.sh itimer              MATCH
scripts/run-probe.sh waitexitstorm       MATCH
/usr/bin/time -lp scripts/run-probe.sh waitexitstorm
  real 39.93
  sys  37.30
target/release/carrick run-elf .../itimer          exit 0
target/release/carrick run-elf .../waitexitstorm   exit 0
just conformance-probes
  test result: ok. 4 passed; 0 failed; finished in 219.94s
```

2026-06-05 follow-up: a later final-tree probe gate reproduced the
`waitexitstorm` timeout (`arm64:waitexitstorm` hit the 45s harness deadline, and
`scripts/run-probe.sh waitexitstorm` exceeded its 60s helper timeout). A bare
`run-elf` measurement showed the hot path had regressed to 64.72s real /
61.58s sys. `wait_proc_exit` now peeks `waitid(WNOWAIT|WNOHANG)` before arming
an EVFILT_PROC watch, so immediate-exit children skip per-child kqueue
add/delete bookkeeping. New validation:

```text
target/release/carrick run-elf .../waitexitstorm
  all_reaped=true, real 41.74, sys 39.07
/usr/bin/time -lp scripts/run-probe.sh waitexitstorm
  MATCH, real 45.56, sys 42.76
just conformance-probes
  test result: ok. 4 passed; 0 failed; finished in 255.84s
```

## Next autonomous slice

1. Keep `futexsharedalias` as landed diagnostic coverage: it creates two futex
   words in one `MAP_SHARED` page, starts the word-B waiter first, starts the
   word-A waiter second, wakes only word A once, and MATCHes Linux by leaving B
   blocked until explicit cleanup.
2. Trace the remaining full forkserver class hang around
   `test_max_tasks_early_shutdown`, focusing on epoll/select waits, wake-pipe
   drain/fd lifetime, worker reap status, and semaphore cleanup rather than the
   ruled-out same-page futex alias.
3. Add the next bounded probe or focused unit test for the exact invariant that
   explains the full-class hang before changing the runtime again.
4. Validate the owned probe plus existing futex/process probes, then rerun the
   CPython two-test forkserver reducer, the full forkserver process-pool class,
   and `just conformance full --suite cpython-concurrent_futures --no-image-refresh`.
5. Keep `ltp-pause02` and `go-os_signal` as adjacent pressure rows. Do not fix
   them from memory or stale output; wait for a fresh deterministic RED and then
   split a separate `pauseinterrupt2` or `atomicstop` reducer if needed.
6. Update this file and `docs/conformance-coverage.md`, then land a logical
   commit with the validation commands in the body.
