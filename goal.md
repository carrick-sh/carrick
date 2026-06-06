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
boring behavior without weakening the gate. The near-term push cleared
`cpython-concurrent_futures` from runtime hangs and then from its stale
oracle-cache classification problem: forkserver max-task shutdown and the later
`test_deadlock` big-data crash case are both owned by focused tests, and the
suite now MATCHes the refreshed Docker oracle. Use each sharper model to keep
the Go `os/exec`, CPython subprocess, process-group, and signal-interruption
rows as comparable pressure workloads instead of letting them disappear
mid-workload.

This is autonomous because every step has a current raw row, a Linux oracle, a
focused reducer path, and a first-principles kernel primitive to compare against.
We do not need to bless, quarantine, or invent broad ptrace debugger support to
make measurable progress.

## Current baseline

Latest full-sweep refresh: 2026-06-06.

Command:

```sh
just conformance full --workers 8 --cpython-workers 4
```

Result:

```text
1222 rows
1168 MATCH
54 NEW
0 regressions
0 timeouts
```

The previous blocking rows are cleared:

- `node-libuv`: `MATCH`, carrick failure matches oracle failure.
- `go-runtime`: `MATCH`, 52/52 on carrick and oracle.
- `ltp-kill02`: targeted rerun now `MATCH`, carrick 2/2 vs oracle 2/2
  after allowing namespace init's idempotent `setpgrp()` while preserving
  explicit session-leader `setpgid(1, 1)` as `EPERM`.
- `ltp-clone303`: targeted rerun now `MATCH`, carrick skipped 1 vs oracle
  skipped 1 after exposing `/proc/self/mounts` as the per-process alias for
  the synthetic mount table. The owned `clone3args` probe already covered the
  clone3 validation surface; this row was blocked in LTP cgroup setup.
- `ltp-kill10` / `ltp-kill12`: full rerun now `MATCH`, carrick 1/1 vs oracle
  1/1, after refreshing stale oracle-cache entries that had totals but no
  `summary` id. The current rows pair `summary` as `ok`/`ok`.

This goal starts from a green regression gate. The target is to reduce NEW rows
by fixing verified process-control gaps, not by blessing, quarantining, or
weakening the gate.

Current targeted ptrace rerun after the `ptraceinvaliderrno` reducer and the
blocking ptrace signal-stop wakeup fix:

```text
ltp-ptrace05  MATCH, carrick 63/63, oracle 63/63, run conf-43208-c00
ltp-ptrace06  MATCH, carrick 48/48, oracle 48/48, run conf-51453-c01
```

Latest smoke refresh after the profiler and subprocess oracle fixes:

```text
just conformance-quick
23 rows
23 MATCH
0 NEW
0 regressions
```

Earlier live refresh note: a full conformance refresh later stopped in
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

Update after EOF wake-pipe tracing: the forkserver class exposed a real host
sys-time bug where a forked child repeatedly woke on an internal wake-pipe EOF
and spun through `fcntl(F_GETFL)` plus `read(...)=0`. That behavior is now
owned by `io_wait::tests::wake_pipe_at_eof_does_not_refire` and
`host_signal::tests::drain_fd_reports_dead_on_eof`: EOF drains mark the waiter's
wake channel dead, remove the kqueue read filter, and fall back to bounded poll
slices. The full forkserver class still timed out in `procgoal-cf-eof-97926`
at `test_max_tasks_early_shutdown`, but samples no longer show the high-CPU EOF
loop; they show a quiescent wait graph with the parent supervisor parked in
`kevent`, forkserver threads in futex/kqueue waits, one worker in `wait_poll`,
and one worker in `shared_futex_wait`. The next reducer should target that
blocked wait/reap/futex state, not the already-owned EOF spin.

Update after missed child-exit watch handling: the exact early-shutdown reducer
that previously timed out now completes five forkserver churn iterations under
carrick, and the full
`ProcessPoolForkserverProcessPoolExecutorTest` class passes 21 tests in
15.723s (1 Windows-only skip). The root cause was a fast-exit child reaching
the forkserver parent before Carrick successfully armed the pump's
`EVFILT_PROC` watch; if `kevent` reports the child is already gone, Carrick now
publishes the requested guest exit signal immediately instead of losing the
only wakeup that makes CPython scan `waitpid(-1, WNOHANG)`. The focused unit
owners are
`host_signal::tests::missed_child_exit_watch_publishes_exit_signal_once` and
`host_signal::tests::missed_child_exit_watch_honors_zero_exit_signal`.

Update after large host-pipe write handling: CPython's
`test_deadlock.ProcessPoolForkExecutorDeadlockTest.test_crash_big_data` hung
with the queue feeder blocked in `_send`, the executor manager closing the
broken call queue, and the main thread waiting in `ProcessPoolExecutor.shutdown`.
The reducer now prints `broken`, the exact two-test sequence passes, and the
full `ProcessPoolForkExecutorDeadlockTest` class passes 16 tests in 5.338s.
The owning unit test is
`dispatch::overlay_dispatch_tests::large_blocking_host_pipe_write_hands_off_after_partial_progress`,
with `blockingpipewrite` preserving the Linux oracle that the guest-visible
short count appears only after a signal interrupts the blocked write.

Latest `just` harness refresh: `just conformance full --suite
cpython-concurrent_futures --refresh-oracle --no-image-refresh` rewrote the
stale Docker oracle cache entry that had totals but no per-test ids. The
current `target/conformance/results.jsonl` row has
`carrick_run_id=conf-35590-c00`, `docker_run_id=<cached>`, and reports `MATCH`
with carrick 20/20 vs oracle 20/20, 239 paired assertion ids, and no new or
known diffs. The refresh evidence was `conf-28227-c00` vs Docker
`conf-28227-d00`; the raw output proves the runtime result: all eight CPython
submodules completed with `== Tests result: SUCCESS ==`, `All 8 tests OK`, and
`run=255 skipped=18`.

Latest `cpython-subprocess` harness refresh: `just conformance full --suite
cpython-subprocess --refresh-oracle --no-image-refresh` now reports `MATCH`
with carrick `280/280` vs Docker `280/280` in `conf-82809-c00` /
`conf-82809-d00`. The previous count inversion was not a Carrick false pass:
Docker's default nofile limit was so high that CPython never reached EMFILE and
skipped both `test_no_leaking` assertions. The suite now caps Docker to
`nofile=1024:1024`, matching Carrick's EMFILE path and preserving assertion
coverage instead of marking the diff known.

Latest full conformance refresh after fast-forwarding the mmap/lazy-zero branch,
refreshing stale kill-test oracle ids, and running the harness with bounded
CPython suite concurrency completed all 1222 rows with `OK: no regressions`:
1168 `MATCH`, 54 `NEW`, and a fully cached oracle phase (`conf-63608-*`).
`cpython-concurrent_futures`, `cpython-subprocess`, `cpython-multiprocessing_fork`,
`go-os_exec`, `go-os_signal`, `go-runtime_pprof`, `ltp-kill02`,
`ltp-kill10`, `ltp-kill12`, `ltp-ptrace05`, `ltp-ptrace06`,
`ltp-setpgid01`, `ltp-pause02`, and `ltp-sigaction01` are all `MATCH` in that
run. Current remaining process-control-shaped NEW rows are `go-os`,
`go-syscall`, `cpython-multiprocessing_forkserver`,
`cpython-multiprocessing_spawn`, and `cpython-signal`; prior evidence still
separates `go-syscall`'s remaining diffs into namespace, chmod/flock, prlimit,
and socket credential fallout rather than the prior process-control timeout.

A later targeted `go-syscall` rerun now completes instead of timing out:
`conf-4038-c00` reports `NEW` with carrick 31/43 vs oracle 34/34. The
process-control-shaped hang in `TestSetuidEtc` is fixed and passes in the
direct reducer after preserving `SI_TKILL` siginfo for thread-directed setxid
signals and rendering live uid/gid/group state in `/proc/self/status`; the
remaining row differences are namespace, chmod/flock, prlimit, and socket
credential fallout rather than the prior no-summary stop. `ltp-kill02` was then
reduced with `CARRICK_TRACE_SYSCALLS=1`:
the LTP parent calls `setpgrp()` before forking, and Carrick returned `EPERM`
because namespace init was treated as a session leader even for the idempotent
self-group operation. Linux/Docker lets this no-op succeed; with the fix,
`just conformance full --suite ltp-kill02 --no-image-refresh` reports `MATCH`
with carrick 2/2 vs oracle 2/2.

`ltp-clone303` was then classified as a procfs/cgroup setup blocker rather
than clone3 syscall fallout: Carrick had TBROKed on
`/proc/self/mounts: ENOENT`, while Docker opened the mount table and skipped
because `/sys/fs/cgroup/ltp` is read-only. Exposing `/proc/self/mounts` as the
same synthetic table as `/proc/mounts` moves the targeted row to `MATCH` in
`conf-53261-c00`, with carrick skipped 1 vs cached oracle skipped 1.

`go-runtime_pprof` then reduced to three independent roots. The first is
`ITIMER_PROF` CPU-time accounting: Carrick's wall-timer delivery incorrectly
ticked while the process was idle in a blocking sleep. The new
`itimerprofidle` reducer now MATCHes Linux, and the existing `itimer` busy
delivery probe still MATCHes after switching CPU timers to guest-CPU based
one-shot rechecks that include in-flight `hv_vcpu_run` time. The second was
the `TestMapping` toolchain crash surface: Go's build driver touched more than
eight distinct registered `MAP_SHARED` file aliases before another syscall,
and an exec'd Go tool could inherit stale active signal-frame bookkeeping that
made its first `sigaltstack()` reconfigure return `EPERM`. The final profiler
magnitude gap was POSIX timer fallout: Go's Linux per-M profiler tries
`timer_create(CLOCK_THREAD_CPUTIME_ID, SIGEV_THREAD_ID, SIGPROF)`, and Carrick
had accepted that unsupported per-thread CPU timer as a wall-clock process
signal source. The dispatcher now rejects that exact combination so Go falls
back to the process `ITIMER_PROF` path Carrick owns. Current targeted harness
evidence is `conf-39285-c00`: `go-runtime_pprof` is `MATCH`, carrick 93/93 vs
cached oracle 93/93. Post-fix validation also passed `just conformance-probes`
and `just conformance-quick`; the smoke gate reported no regressions, with the
known `cpython-subprocess` count inversion still classified as `NEW`.

## Primary target rows

These are the first rows to investigate because they share process-control,
wait-status, stop-state, or signal-interruption behavior:

| Row | Ecosystem | Current carrick | Oracle | Why it belongs here |
| --- | --- | --- | --- | --- |
| `ltp-ptrace05` | LTP | MATCH 63/63 after `ptracesignalstop` blocking-wait coverage | 63/63 | `PTRACE_TRACEME`, traced self-`SIGKILL`, `SIGCONT`, Linux RT signal-delivery stops, and parent waits that park before the tracee stop is published are now owned. |
| `ltp-ptrace06` | LTP | MATCH 48/48 after `ptraceinvaliderrno` | 48/48 | Exec-stop setup and invalid PEEK/POKE request errno are now owned without claiming full debugger memory/register access. |
| `go-os_exec` | Go | MATCH 86/86 in targeted rerun `conf-93241-c156` | 86/86 | Previously 0/0; current evidence shows process execution suite parity, so keep watching it as pressure coverage rather than the next reducer. |
| `go-runtime_pprof` | Go | MATCH 93/93 in targeted rerun `conf-39285-c00` | 93/93 | CPU profiler pressure coverage. Idle `ITIMER_PROF`, `TestMapping` alias/sigaltstack, and unsupported per-thread CPU timer over-sampling are now owned. |
| `go-syscall` | Go | NEW 31/43 in `conf-4038-c00`; direct `TestSetuidEtc` now passes | 34/34 | Process-control `TestExec` and setxid/thread-signal blockers are fixed and owned. The row now completes; remaining diffs are split into namespace setup (`whoami`/`id`, unshare/userns), `Fchmodat`, `FcntlFlock`, `Prlimit*`, and `SCMCredentials` fallout rather than a process-control timeout. |
| `cpython-subprocess` | CPython | MATCH 280/280 in `conf-82809-c00` | 280/280 in refreshed Docker run `conf-82809-d00` | The old count inversion was a Docker oracle environment issue: Docker's default nofile limit was too high, so CPython skipped both `test_no_leaking` cases instead of exercising the EMFILE leak path Carrick already ran. The suite now caps Docker to `nofile=1024:1024` and assertion ids align. |
| `cpython-concurrent_futures` | CPython | MATCH 20/20 in cache-backed `conf-35590-c00`; raw output shows all 8 CPython submodules succeeded | 20/20 in refreshed Docker oracle `conf-28227-d00` | Runtime hangs and the stale oracle-id cache mismatch are cleared. |
| `ltp-kill02` | LTP | MATCH 2/2 in targeted rerun after namespace-init `setpgrp()` fix | 2/2 | The parent process must be allowed to form its guest-visible process group before `kill(0, SIGUSR1)` broadcasts to child 1 and child A; explicit session-leader `setpgid(1, 1)` remains `EPERM`. |
| `ltp-clone303` | LTP | MATCH skipped 1 in `conf-53261-c00` | skipped 1 | Non-process setup blocker cleared: LTP's cgroup helper needs `/proc/self/mounts`; clone3 validation itself remains owned by `clone3args`. |
| `ltp-setpgid01` | LTP | MATCH 1/2 in `conf-3259-c00` | 1/2 | PID-namespace session-leader rule is now owned; `setpgid(1, 1)` fails EPERM like Docker Linux while forked non-leader `setpgid(0, 0)` still succeeds. |
| `ltp-pause02` | LTP | unstable historically; latest targeted attempts currently MATCH | 1/1 | Signal interruption/restart behavior around sleeping processes; keep as pressure coverage until it produces a fresh RED. |
| `ltp-kill10` / `ltp-kill12` | LTP | MATCH 1/1 in `conf-63608-c857` / `conf-63608-c859` | 1/1 | Stale oracle-cache ids are refreshed; both rows now pair `summary` as `ok`/`ok`. |
| `go-os_signal` | Go | MATCH 29/30 in fresh targeted rerun `conf-41403-c00` after the vfork identity, lazy signal-pump, and self-`tgkill` fixes | 29/30 | `TestDetectNohup` used vfork/exec and left the parent's fast-path getpid stamped with the child ns-pid, breaking later `kill(getpid(), sig)` delivery; fixed and owned by `vforkpid`. The later `TestAtomicStop` new diff is also cleared by keeping self-`tgkill` thread-directed; `TestTerminalSignal` still fails on both carrick and oracle. |
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
| `execthreads` | `execve` from a multithreaded process terminates sibling threads before the VM/address-space replacement and starts the new image single-threaded. |
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
- Follow-up 2026-06-06: `ptracesignalstop` also owns blocking parent
  `waitpid(pid, 0)` cases, including a delayed child that publishes the traced
  signal stop only after the parent has already parked.
- `ltp-ptrace05` matches the cached Docker oracle: 63/63 vs 63/63 in
  `conf-43208-c00`.
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
`cpython-concurrent_futures`: CPython's process-pool and deadlock tests churn
through semaphores, worker exits, pipe/socket transfer, epoll/select waits, and
parent-side fd cleanup. The forkserver max-task race and the big-data
process-pool cleanup deadlock are now owned, and the refreshed oracle cache
makes the row MATCH. Keep it as pressure coverage while moving active runtime
work to the next process-control row.

Exit criteria:

- At least one owned probe captures the root cause before the runtime fix.
- `futexsharedalias` proves that two shared futex words on one mapped page use
  distinct host wait keys. It MATCHes Linux on current carrick, so it is
  diagnostic coverage and not the forkserver root cause.
- `host_signal::tests::drain_fd_forces_empty_pipe_nonblocking` owns the
  host-side invariant that draining an internal wake pipe must never turn into
  an unbounded blocking read if fd flags are disturbed by fork/fd churn.
- `host_signal::tests::missed_child_exit_watch_publishes_exit_signal_once` owns
  the fast-exit child race where a missed `EVFILT_PROC` watch must still publish
  the requested guest exit signal. The zero-exit-signal companion test keeps
  `clone(0)` semantics from gaining a spurious SIGCHLD.
- `dispatch::overlay_dispatch_tests::large_blocking_host_pipe_write_hands_off_after_partial_progress`
  owns the big-data broken process-pool cleanup path where a large host-pipe
  write must hand off a pinned continuation after filling the pipe instead of
  parking inside the dispatcher and blocking sibling fd cleanup.
- `execthreads` owns the Go `syscall.TestExec` shape: one thread execs while
  sibling runtime threads are live, and the new image must start with
  `Threads: 1`.
- The target language row changes from NEW to MATCH. Landed 2026-06-05:
  refreshing the stale CPython Docker oracle entry records 239 per-test ids and
  makes `cpython-concurrent_futures` MATCH 20/20 vs 20/20 without blessing a
  baseline.
- `just conformance-probes` stays green.

### Milestone 4: Process groups and signal interruption

Use `ltp-setpgid01`, `ltp-pause02`, `go-os_signal`, and adjacent kill/sigaction
rows to close the process-group and interruption rules exposed by the first two
milestones.

Exit criteria:

- `dispatch::proc::setpgid_tests::namespace_init_setpgid_is_eperm_when_host_sid_differs_from_pgid`
  owns the PID-namespace session-leader rule for `setpgid`, with
  `setpgidparentgroup` and `proclife` preserving child process-group joins and
  ordinary self-group behavior.
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
- The total NEW count drops to 45 or lower, or every remaining
  process-control NEW row is proven to be a distinct non-process-control gap.
- `ltp-ptrace05` and `ltp-ptrace06` no longer fail because `ptrace` returns
  `ENOSYS`, because `SIGKILL` is reported as a stop, or because tracee exec-stop
  state is absent.
- `go-os_exec` no longer reports `0/0` against an 86/86 oracle.
- `cpython-concurrent_futures` no longer reports `0/0` against a 20/20 oracle,
  and any remaining `NEW` classification is proven at assertion/cache level
  rather than by a runtime hang.
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
| `ltp-ptrace05` | missing syscall plus wrong traced-child stop/status path: raw `conf-42088-c1010` shows `ptrace(PTRACE_TRACEME)` returning `ENOSYS`, then repeated "Didn't stop as expected" and live child cleanup. After `ptracetraceme`, targeted rerun `conf-24123-c00` improves to 82/103 vs oracle 63/63. After `ptracesigdeath`, targeted rerun `conf-27543-c00` improves to 806/1184; `SIGKILL` now reports "Killed with SIGKILL, as expected". After `ptracesignalstop`, targeted rerun `conf-7738-c00` matches 63/63 vs oracle 63/63. A later blocking-wait regression showed that a parent parked in `waitpid(pid, 0)` could sleep past a traced signal-delivery stop; the shared child metadata wakeup now keeps targeted `conf-43208-c00` at 63/63 vs oracle 63/63. | `ptracetraceme`, `ptracesigdeath`, and `ptracesignalstop`; `guest_cpu::tests::child_ptrace_stop_marker_lives_until_report_or_reap` | MATCH; ptrace05 signal-death, signal-delivery stop matrix, and blocking wait readiness owned |
| `ltp-ptrace06` | same ptrace tracee-state surface: raw `conf-42088-c1011` has `PTRACE_TRACEME failed` and `child status not stopped: 0x100`. After `ptracetraceme`, targeted rerun `conf-24123-c01` still emits no parseable stdout summary, only the root-user warning on stderr. After `ptracesigdeath` and `ptracesignalstop`, targeted rerun `conf-7738-c01` still emits no parseable stdout summary. After `traceexecstop`, targeted rerun `conf-31128-c01` emits 48 TFAIL lines, all `ENOSYS` where Linux expects `EIO` or `EFAULT` for invalid PEEK/POKE requests. After `ptraceinvaliderrno`, targeted rerun `conf-51453-c01` matches 48/48 vs oracle 48/48. | `traceexecstop` and `ptraceinvaliderrno` | MATCH; exec-stop setup and invalid ptrace request errno owned |
| `go-os_exec` | previously process/wait workload exited without a parseable suite summary in `conf-42088-c593`; targeted rerun `conf-93241-c156` now matches 86/86 vs oracle 86/86 with assertion ids aligned. | keep as process-control pressure coverage; no reducer needed unless it regresses | MATCH |
| `go-syscall` | mixed process-control and unrelated syscall fallout: raw `conf-39099-c00` reproduced the old `TestExec` runtime `netpoll failed` after `epollwait on fd 3 failed with 9`, caused by `execve` rebuilding the HVF VM while sibling guest threads from the old thread group were still live. Docker passed isolated `TestExec`; Carrick now passes the same isolated filter, and `execthreads` proves the new image starts with `Threads: 1`. The later full row timed out in `TestSetuidEtc` because glibc's cgo setxid path sent RT signal 33 with `tgkill`, but Carrick delivered it with synthesized `SI_USER` siginfo; after fixing `SI_TKILL` delivery and `/proc/self/status` credential rendering, direct `TestSetuidEtc` passes and the full row completes as `NEW` 31/43 vs oracle 34/34 in `conf-4038-c00`. | `execthreads`, `thread::tests::remove_all_except_keeps_exec_owner_live`, `syscall_thread::tgkill_to_sibling_queues_si_tkill_siginfo`, `vfs::proc::tests::self_status_reflects_live_credentials_and_groups`; non-process rows split out | process-control subset fixed; full row still has non-process syscall fallout (`SCMCredentials`, userns/unshare helper paths, `Fchmodat`, `FcntlFlock`, `Prlimit*`) |
| `cpython-subprocess` | fixed harness/oracle environment mismatch: Carrick opened until EMFILE around fd 1021 and passed both `test_no_leaking` poll modes, while Docker's default `RLIMIT_NOFILE=1048576` made CPython skip those assertions with `failed to reach the file descriptor limit (tried 1026)`. The suite now gives Docker `--ulimit nofile=1024:1024`, which forces the same EMFILE path and refreshed oracle ids. | `scripts/conformance/suites.toml` Docker nofile cap; generator keeps the stanza reproducible | MATCH 280/280 vs oracle 280/280 in `conf-82809-c00` / `conf-82809-d00`; no known gap or quarantine |
| `cpython-concurrent_futures` | runtime hangs are fixed: the exact five-iteration early-shutdown reducer completes, `ProcessPoolForkserverProcessPoolExecutorTest` passes 21 tests, `ProcessPoolForkExecutorDeadlockTest` passes 16 tests, and refreshed harness run `conf-28227-c00` matches Docker oracle run `conf-28227-d00` at 20/20 with 239 paired assertion ids. The previous `conf-98558-c00` row was `NEW` only because the committed oracle cache had totals but no Docker per-test ids. | `futexsharedalias`, wake-pipe drain tests, `host_signal::tests::missed_child_exit_watch_*`, `blockingpipewrite`, `dispatch::overlay_dispatch_tests::large_blocking_host_pipe_write_hands_off_after_partial_progress`, refreshed oracle-cache entry | MATCH; keep as pressure coverage |
| `ltp-setpgid01` | real under-enforcement after oracle refresh: Docker `conf-43101-d00` fails `setpgid(1, 1)` with `EPERM` and passes the forked-child `setpgid(0, 0)` leg. Carrick had reported both as TPASS because the harness starts Carrick in a fresh host process group but the same host session; PID namespace mapping recorded only the init host PGID, so guest `getsid(0)` / session-leader checks missed host SID values that differ from PGID. | `dispatch::proc::setpgid_tests::namespace_init_setpgid_is_eperm_when_host_sid_differs_from_pgid`, `setpgidparentgroup`, `proclife` | MATCH 1/2 vs oracle 1/2 in `conf-3259-c00`; process-group session-leader rule owned |
| `ltp-clone303` | procfs/cgroup setup blocker, not clone3 syscall behavior: targeted run before the fix TBROKed on `/proc/self/mounts: ENOENT`, while Docker opened the mount table and TCONF-skipped because `/sys/fs/cgroup/ltp` is read-only. `clone3args` already proved Carrick's clone3 validation behavior matches the Linux/seccomp oracle shape. | `syscall_fs::synthetic_proc_surface_serves_common_process_and_system_files`; `clone3args` for clone3 validation | MATCH skipped 1 vs oracle skipped 1 in `conf-53261-c00`; setup blocker cleared |
| `ltp-pause02` | signal interruption/restart bug when it reproduces: raw `conf-42088-c959` reported unexpected `SIGINT`, then `pause was interrupted but the retval and/or errno was wrong`; rerun `conf-71289-c01` matched, and later `conf-18439-c01` reproduced the same signature, but latest focused attempts and `pauseinterrupt2` are currently MATCH. | `pauseinterrupt2` or sharper interruption reducer if the row turns RED again | pressure coverage; no runtime fix without fresh RED |
| `ltp-kill10` | harness/oracle identity mismatch: carrick raw `conf-42088-c857` had `TPASS`, while the cached oracle had totals but no `summary` id, yielding `summary ok` vs absent. Refreshing the Docker oracle cache records `summary: ok`, and the full run now pairs `summary` as `ok`/`ok`. | refreshed `scripts/conformance/oracle-cache.jsonl` entry | MATCH 1/1 vs oracle 1/1 in `conf-63608-c857`; non-runtime oracle-cache fix |
| `ltp-kill12` | harness/oracle identity mismatch: carrick raw `conf-42088-c859` had `TPASS`, while the cached oracle had totals but no `summary` id, yielding `summary ok` vs absent. Refreshing the Docker oracle cache records `summary: ok`, and the full run now pairs `summary` as `ok`/`ok`. | refreshed `scripts/conformance/oracle-cache.jsonl` entry | MATCH 1/1 vs oracle 1/1 in `conf-63608-c859`; non-runtime oracle-cache fix |
| `go-os_signal` | adjacent signal delivery/status mismatch split into three roots. Fresh runs `conf-30698-c00`/`conf-41653-c00` failed `TestStop`, `TestSIGCONT`, and `TestSignalTrace` because `TestDetectNohup`'s vfork/exec child stamped the shared EL1 identity page with the child ns-pid; later parent `kill(getpid(), sig)` used pid 4 and returned `ESRCH`. `vforkpid` owns that fix. Full row later improved to `conf-87864-c00` at 28/30 with only `TestAtomicStop` new vs oracle, then matched after default, unblocked child-exit SIGCHLD stopped forcing signal-pump/watch churn. `TestAtomicStop` was a self-`tgkill` contract bug: Carrick routed the signal through the process-directed pending slot, letting another Go thread consume it. Fresh targeted rerun `conf-41403-c00` remains MATCH at 29/30 after preserving self-`tgkill` as thread-directed. `TestTerminalSignal` remains an oracle-matching fail. | `vforkpid`; `signal::tests::child_exit_signal_pump_predicate_tracks_observable_dispositions`; `syscall_thread::tgkill_to_self_raises_locally`; `sigchld` / `cloneexitsig` | MATCH; keep as pressure coverage |
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

2026-06-05 second follow-up: the final signed threaded probe path still had
`waitexitstorm` close enough to the 60s helper deadline that host load could
trip it again. A host syscall profile showed the process was not wedged; it was
paying repeated signal-pump stop/start and child `EVFILT_PROC` watch setup for
default, unblocked `SIGCHLD` children whose notification is guest-inert and
whose reap is owned by the blocking wait path. The fork coordinator now carries
whether a pump existed through `PreparedHostFork`, the threaded runtime starts
non-interactive command runs pump-free, and fork restarts/registers the pump
only when the exit signal is caught, blocked for sigwait/sigtimedwait, or has a
non-ignored default disposition. Installing a real guest signal handler requests
the pump before guest userspace resumes, preserving busy-wait signal delivery.

Validation after the lazy-pump fix:

```text
/usr/bin/time -p scripts/run-probe.sh waitexitstorm
  MATCH, real 51.84, sys 48.10
scripts/run-probe.sh sigchld       MATCH
scripts/run-probe.sh cloneexitsig  MATCH
scripts/run-probe.sh killgroup     MATCH
scripts/run-probe.sh itimer        MATCH
just conformance-probes
  test result: ok. 4 passed; 0 failed; finished in 346.86s
```

2026-06-06 ptrace follow-up: the ptrace05 runtime fix extended
`ptracesignalstop` with blocking `waitpid(pid, 0)` cases. The final probe gate
still passed after the shared child ptrace-stop metadata and wait-readiness
changes:

```text
just conformance-probes
  test result: ok. 4 passed; 0 failed; finished in 165.69s
```

## Next autonomous slice

2026-06-06 stop checkpoint: after recording the full-run artifacts and landing
the logical commits for the oracle refresh and harness scheduler change, stop
this goal instead of continuing into another autonomous reducer slice.

If this goal is resumed later, keep `go-syscall` as a non-process follow-up
only if the scope expands: `TestExec` is now fixed and owned, while the full row
still stops around namespace/chroot fallout after user namespace, unshare,
capability, and fd-flag failures. Keep `go-os_signal` as pressure coverage; the
latest full run still matches 29/30 vs oracle, with only `TestTerminalSignal`
failing on both sides.
