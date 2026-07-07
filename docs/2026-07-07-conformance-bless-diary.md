# 2026-07-07 conformance bless diary

## clone08 regression

Hypothesis:
`ltp-clone08` is a real runtime clone-semantics bug, not load or timing. The
process-like clone path drops `CLONE_PARENT`, `CLONE_PARENT_SETTID`, and
`CLONE_CHILD_SETTID` before the runtime fork code can model them. Separately,
the thread path classifies only Carrick's `THREAD_MASK` superset as a thread,
so a Linux-valid `CLONE_THREAD|CLONE_VM|CLONE_SIGHAND|CLONE_CHILD_CLEARTID`
shape falls through to a real process fork.

Tests:
- Focused Carrick run:
  `target/conformance/logs/ltp-clone08-focus-013314.carrick.log`
- Focused Docker oracle:
  `target/conformance/logs/ltp-clone08-focus-013314.docker.log`
- Carrick trace:
  `target/conformance/logs/clone08-trace-013656.trace`

Outcome:
Docker passes all five clone08 assertions. Carrick fails all five. The trace
shows the `CLONE_THREAD` subtest issuing `clone` with flags `0x210911`, then
Carrick records a new process pid and a private-futex wait instead of an
in-process thread exit clear/wake. Code inspection confirmed fork-like clone
outcomes carried only pidfd, signal, stack, and vfork metadata.

Fix under test:
Classify any valid `CLONE_THREAD` request as `CloneThread` after the existing
`THREAD => SIGHAND => VM` validation. Preserve process-clone parent/TID
metadata through `DispatchOutcome::Fork`, write `pid_t` values in the parent
and child fork arms, and register `CLONE_PARENT` children through the
fork-coherent adopted-child table.

Follow-up:
The first patched focused run improved Carrick from 0/5 to 3/5 and reduced the
raw run from about 6s to about 1s, but `CLONE_PARENT_SETTID` still failed. A
second trace showed the failing shape was `CLONE_PARENT_SETTID|CLONE_VM`; the
LTP child checks `ptid` after clone. Because Carrick models this as a CoW fork
rather than a shared-VM process clone, the Linux-visible store must be mirrored
into the child branch too, not only the parent branch.

Second follow-up:
The next focused run returned success but only produced 4 TPASS lines. Carrick's
thread subtest changed `ctid` to the thread id instead of clearing it to 0,
which let the parent observe `EWOULDBLOCK` and exit before the child thread's
own assertion ran. Root cause: the thread outcome conflated
`CLONE_CHILD_SETTID` and `CLONE_CHILD_CLEARTID`. These are distinct Linux
effects: set-tid writes at clone return, clear-tid registers an exit-time clear
and futex wake.

Third follow-up:
After splitting set-tid and clear-tid, the thread child actually ran and crashed
with SIGSEGV. The next root cause is the TLS handoff: Carrick encoded "no
`CLONE_SETTLS`" as `tls = 0`, but still installed `Some(0)` in the sibling vCPU.
For clone08's thread case, Linux preserves the caller's TLS because SETTLS is
absent. The runtime outcome now carries `tls: Option<u64>` so no-SETTLS clones
leave the child TLS register alone.

Verified:
- Focused raw run `ltp-clone08-fix4-020037`: Carrick 5/5 in 969ms, Docker 5/5
  in 477ms. This is about 2.03x for the focused command, down from the
  full-harness failure's 14.89x outlier.
- Harness run:
  `target/release/carrick-conformance --suite ltp-clone08 --jsonl target/conformance/clone08-fix.jsonl`
  reported `MATCH carrick[5/5] oracle[5/5]`.

## munmap04 performance outlier

Hypothesis:
The full bless reported `ltp-munmap04` as `MATCH` but with a 77.42x timing
outlier: Carrick 31,121ms vs cached Docker oracle 402ms. This is not acceptable
as a blessed state even though the verdict matches. The first suspicion was
that the shell-wrapped LTP process left a child alive or waited on the wrong
process.

Tests:
- Direct binary run without `/bin/sh -c`:
  `target/conformance/logs/munmap04-focus-020704.carrick.log`
- Exact harness argv with `/bin/sh -c`:
  `target/conformance/logs/munmap04-exact-020811.carrick.log`
- Docker oracle refresh:
  `target/conformance/logs/munmap04-docker-020916.docker.log`
- DTrace profile:
  `target/conformance/logs/munmap04-profile-020857.trace`
- lldb deadline captures:
  `target/conformance/logs/lldb-runs/munmap04-lldborder-021849.lldb.txt`

Outcome:
The direct no-shell run returned in 415ms, but the exact harness argv took
30,332ms. Docker's exact argv returned in 505ms with the same LTP `SIGSEGV`
TBROK verdict. The DTrace profile showed the active child was not blocked: it
made about 39k guest `mmap` syscalls in six seconds. A first VMA metadata patch
removed full-vector sort/linear overlap work from `dynamic_maps`, but the exact
run still took 30,843ms.

The original lldb runner attached parents first and missed the hot leaf process.
After freezing the scoped process set and attaching leaf-first, lldb caught the
worker in `carrick_guest_mem::protections::RangeSet::set` from the PROT_NONE
`mmap` path. That range set was also doing full sort/merge scans on every
mapping, plus full scans for no-op clears.

Fix under test:
Keep the existing `Vec`-backed metadata representation, but update sorted ranges
locally with `partition_point`:
- `dynamic_maps` now does binary overlap checks and ordered insertions without
  resorting the whole vector for non-overlapping fixed mappings.
- `MemoryProtections::RangeSet` now merges or removes only the affected local
  slice instead of sorting/merging every stored range on each `set_no_access`.
- `carrick debug lldb-run` now freezes the scoped process set and attaches
  leaf-first so fork-heavy diagnostics capture the active guest process.

Verified:
- Raw exact Carrick argv after the range-set fix:
  `target/conformance/logs/munmap04-rangeset-022035.carrick.log`, rc 2,
  elapsed 1,151ms. This is about 2.28x vs the 505ms fresh Docker run, down from
  the 30s timeout class and below the 10x outlier threshold.
- Harness run:
  `target/release/carrick-conformance --suite ltp-munmap04 --jsonl target/conformance/munmap04-harness-fixed-022052.jsonl`
  reported `MATCH carrick[0/1] oracle[0/1]` with no performance outlier.

## kill12 sleep/signal performance outlier

Hypothesis:
The full bless reported `ltp-kill12` as a clean `MATCH`, but with a 32.63x
timing outlier: Carrick 13,181ms vs cached Docker oracle 404ms. The LTP test
loops over signals 1..13 and uses `sleep(1)` while waiting for a child
`SIGCHLD` readiness/exit notification. A one-second-per-signal total means the
signal eventually arrives, but it is not interrupting the guest sleep promptly.

Tests:
- Focused exact Carrick argv:
  `target/conformance/logs/kill12-focus-022859.carrick.log`, elapsed 12.44s.
- Bounded DTrace script:
  `scripts/dtrace/sleep-signal-wakeup.d`.
- DTrace run:
  `target/conformance/logs/kill12-wakeup-023042.trace`.
- Focused re-run before the fix:
  `target/conformance/logs/kill12-refocus-023429.carrick.log`, elapsed 12.57s.

Outcome:
The trace showed parent child-exit `SIGCHLD` wakes often returned
`io-wait-end result=2` (`Interrupted`), but the child's guest-sent `SIGCHLD`
path could sit behind `clock_nanosleep` and only deliver after a timeout. The
common shape is an xsignal-ring entry that exists outside the host pending
bitmasks until the dispatcher drains it. Sleep waits were only checking the
host-signal waiter's predicate while parked; unlike poll/proc-exit waits, they
did not explicitly service dispatcher-owned pending state before and during
the wait.

Fix under test:
For `WaitOnSleep` in both the threaded and single-vCPU loops, drain xsignals
for the current tid and check dispatcher pending state before parking. Then
wait in the same 50ms internal slice granularity used by `io_wait`, so each
slice has a dispatcher-pending recheck instead of letting a guest sleep absorb
the full one-second deadline.

Verified:
- Focused exact Carrick argv after the fix:
  `target/conformance/logs/kill12-sleepfix-023709.carrick.log`, rc 0,
  elapsed 0.64s.
- Harness run:
  `target/release/carrick-conformance --suite ltp-kill12 --jsonl target/conformance/kill12-sleepfix.jsonl`
  reported `MATCH carrick[1/1] oracle[1/1]`, with Carrick 496ms vs oracle
  404ms (1.23x).

## getpid01 wait-any performance outlier

Hypothesis:
The full bless reported `ltp-getpid01` as a semantic `MATCH` but with a 36.18x
timing outlier: Carrick 14,617ms vs cached Docker oracle 404ms. Reading the LTP
source reframed this as a fork/wait-any benchmark, not a raw `getpid` hot loop:
the test forks 100 children serially, and each child calls `getpid()`.

Tests:
- Focused exact Carrick argv before the fix:
  `target/conformance/logs/getpid01-focus-024803-1.carrick.log`,
  `target/conformance/logs/getpid01-focus-024811-2.carrick.log`, and
  `target/conformance/logs/getpid01-focus-024820-3.carrick.log`, elapsed
  8,271ms, 8,269ms, and 8,308ms.
- Fresh Docker timings:
  `target/conformance/logs/docker-getpid01-focus-024836-1.docker.log`,
  `target/conformance/logs/docker-getpid01-focus-024837-2.docker.log`, and
  `target/conformance/logs/docker-getpid01-focus-024837-3.docker.log`, elapsed
  503ms, 273ms, and 256ms.
- lldb deadline capture:
  `target/conformance/logs/lldb-runs/getpid01-lldb-025050.lldb.txt`.

Outcome:
The lldb runner froze the live process tree mid-test. The active LTP worker was
blocked in `ThreadWaiter::wait_proc_exit_fallback(pid=-1)`, not in guest
`getpid()`. Carrick already used kqueue `EVFILT_PROC` for concrete
`wait4(pid)`, but `wait4(-1)` fell back to a 50ms `waitid(P_ALL, WNOHANG)` poll
because Darwin has no single "any child" kqueue sentinel. In a serial fork loop
that made every child reap pay a sleep/re-poll penalty.

Fix under test:
Use Carrick's fork-shared child table as the missing structure for the probe:
snapshot this process's direct, non-adopted children, arm one `EVFILT_PROC`
watch per child on the per-thread kqueue, and re-dispatch `wait4(-1)` when any
child exit fires. Adopted children stay on the existing adopted-child table path,
and the old polling fallback remains for no-child/unusable-kqueue cases.

Verified:
- Focused exact Carrick argv after the fix:
  `target/conformance/logs/getpid01-anykq-025352-1.carrick.log`,
  `target/conformance/logs/getpid01-anykq-025355-2.carrick.log`, and
  `target/conformance/logs/getpid01-anykq-025358-3.carrick.log`, elapsed
  2,836ms, 2,674ms, and 2,699ms.
- Harness run:
  `target/release/carrick-conformance --suite ltp-getpid01 --jsonl target/conformance/getpid01-anykq.jsonl`
  reported `MATCH carrick[100/100] oracle[100/100]`, with Carrick 2,965ms vs
  cached oracle 404ms (7.34x), below the conformance 10x outlier threshold.

Follow-up after full bless:
The next full `--bless` run still reported `ltp-getpid01` as the top timing
outlier under worker load:
`target/conformance/logs/conformance-bless-20260707-025522.log` failed fast
after 55 cached-oracle gating verdicts, with `ltp-getpid01` still a semantic
match but 16,115ms vs 404ms (39.89x). A focused exact re-run immediately after
the full run took 4,729ms, and the harness run
`target/conformance/getpid01-postfull.jsonl` reported 4,889ms vs 404ms
(12.10x). The wait-any kqueue fix therefore removed the original 50ms
poll/reap cliff, but did not make the fork-heavy case robust under load.

Second lldb capture:
`target/conformance/logs/lldb-runs/getpid01-lldb2-030336.lldb.txt` caught the
active LTP worker in `HvfVmState::fork_rebuild` while creating a fresh HVF VM
for the fork child. The parent was waiting on the concrete child with
`wait_proc_exit_kqueue`, and the shell was on the new `wait_proc_exit_any_kqueue`
path, so the remaining hot state is no longer the wait-any fallback.

Host-HVF comparison:
Checked-in `hvf_fork_probe` isolates raw Hypervisor.framework create/destroy
from Carrick's guest rebuild work. After codesigning the probe binary, the
host-only recreate loop showed VM+vCPU creation usually in tens of microseconds,
and the fork churn probe showed child `hv_vm_create` around 300-700us:
`target/conformance/logs/hvf-probes/recreate-loop-20260707-030531.log` and
`target/conformance/logs/hvf-probes/fork-churn-20260707-030531.log`. That makes
plain `hv_vm_create` too small to explain the 4-5s focused LTP cost by itself.

Raw fork oracle:
The untracked local `perf_fork` probe timed a steady-state loop of
`fork()+_exit(0)+waitpid()` with no child work. Carrick:
`target/conformance/logs/perf-probes/perf_fork-carrick-20260707-030639.log`
reported `fork_p50_us=40988.625`, `fork_p95_us=42627.084`, and
`fork_min_us=38328.250` over 300 iterations. Docker:
`target/conformance/logs/perf-probes/perf_fork-docker-20260707-030639.log`
reported `fork_p50_us=47.666`, `fork_p95_us=578.083`, and
`fork_min_us=32.875`. This is the current first-principles explanation for
`getpid01`: the test is a 100-fork loop, so Carrick's steady-state fork
primitive alone accounts for roughly four seconds, while Docker's is effectively
sub-millisecond at this scale. The next question is architectural: whether the
HVF fork model can avoid rebuilding a full VM for simple child-exit forks, or
whether the conformance harness should classify this as an acknowledged
performance gap rather than a transient wait bug.

## short finite wait timer regressions

Hypothesis:
The latest full bless left several timer-threshold regressions that all had the
same shape: Carrick slept about 2.5-3.5ms past the requested finite timeout.
`ltp-epoll_wait02` failed as 4/7 or 5/7 against a 7/7 Docker oracle, and a
focused rerun before the fix showed the 10ms, 25ms, and 100ms cases failing
with "slept too long":
`target/conformance/epoll_wait02-focus-030948.jsonl` and
`target/conformance/raw/conf-93040-c00.err`. The dispatcher handed empty
`epoll_wait` to `WaitOnFds`, and the vCPU loop reclaimed/rebound the HVF vCPU
before every fd/poll timeout and every sleep wait, so short finite waits were
paying timer latency plus vCPU lifecycle overhead.

Test:
Added a pure policy helper in `crates/carrick-runtime/src/vcpu_loop/mod.rs`:
short finite timed waits keep the current vCPU lease, while indefinite waits and
finite waits above 250ms still release the lease. The sleep path applies that
policy to the full remaining deadline, not the internal 50ms xsignal slice, so a
long sleep still releases the vCPU for most of its duration and only keeps it
for the final short tail.

Outcome:
- `cargo fmt --check`
- `cargo test -p carrick-runtime timed_wait_reclaim --lib`
- `just build -p carrick-cli`
- `target/release/carrick-conformance --suite ltp-epoll_wait02 --suite ltp-epoll_pwait03 --suite ltp-kill12 --suite ltp-nanosleep01 --jsonl target/conformance/timedwait-reclaim-focused.jsonl`
  matched all four suites:
  - `ltp-epoll_wait02`: 7/7 vs 7/7, 1.11x
  - `ltp-epoll_pwait03`: 14/14 vs 14/14, 1.03x
  - `ltp-kill12`: 1/1 vs 1/1, 5.86x
  - `ltp-nanosleep01`: 7/7 vs 7/7, 1.02x
- The same fix cleared the adjacent full-bless regressions:
  `target/release/carrick-conformance --suite ltp-poll02 --suite ltp-pselect01 --suite ltp-pselect01_64 --suite ltp-prctl09 --jsonl target/conformance/timedwait-reclaim-poll-select.jsonl`
  matched all four suites at 7/7 vs 7/7.

## ptrace06 timeout

Hypothesis:
The `ltp-ptrace06` regression was a real wait/ptrace bug, not a slow test to
bless. Docker completes the matrix in about 412ms with 48/48 TPASS lines, while
Carrick timed out at about 30.5s before printing any TPASS. The LTP source first
forks a `PTRACE_TRACEME` child, the child uses `raise(SIGSTOP)`, and the parent
uses a plain blocking `wait()`; Linux reports this as a ptrace stop even without
`WUNTRACED`.

Tests:
- Docker oracle:
  `docker run --rm --platform linux/arm64 localhost:5050/ltp:arm64 /bin/sh -c /opt/ltp/testcases/bin/ptrace06`
  printed 48 TPASS lines.
- `carrick trace`:
  `target/conformance/logs/ptrace06-trace-current-040615.dtrace.txt` showed the
  LTP worker parked in wait-any after its tracee called `ptrace(TRACEME)`.
- `carrick debug lldb-run`:
  `target/conformance/logs/lldb-runs/ptrace06-post-race-041227.lldb.txt`
  caught the worker in `wait_proc_exit_any_kqueue` with a stopped tracee child.
- New focused probe:
  `conformance-probes/src/bin/ptracestop.rs` reproduces the exact setup with a
  bounded blocking wait and `raise(SIGSTOP)`.

Outcome:
The first reducer using `kill(getpid(), SIGSTOP)` passed, which disproved the
generic "SIGSTOP stop is invisible" theory. Changing the reducer to
`raise(SIGSTOP)` made it red on Carrick: the blocking wait timed out and was
interrupted by the probe alarm. The first runtime fix taught all self-directed
ptraced signal paths, including tkill/tgkill self-raise, to publish a Linux
ptrace-stop marker before applying the host stop carrier. That fixed the
reducer but not LTP.

The remaining root cause was in the fork-shared child metadata. The child can
self-register and publish the ptrace-stop marker before, or after, the parent
registers fork ancestry. Existing-slot registration was not stable: parent-side
registration could clear a published marker, and child self-registration could
erase `parent_pid`. Wait-any then stopped considering the tracee a direct child,
so the 50ms kqueue retry loop still missed it. The fix preserves live
`ptrace_stop_signal` and parent ancestry across metadata-free self-registration
and late parent registration.

Verified:
- `cargo fmt --check`
- `cargo test -p carrick-host guest_cpu::tests --lib`
- `cargo test -p carrick-runtime timed_wait_reclaim --lib`
- `cargo test -p carrick-vmm-hvf child_status_ready_observes_ptrace_trap_stop --lib`
- `just build -p carrick-cli`
- Focused probes:
  - `ptracestop` under Carrick OCI and `run-elf` now reports
    `blocking_wait_reaped_stop=true` and `blocking_wait_alarm_fired=false`.
  - the cross-process diagnostic `ptracesignal` passes in focused OCI and
    `run-elf` runs, but it is not being committed as a durable gate because the
    full loaded `just conformance-probes` run observed a `SIGPIPE` stop in that
    diagnostic probe.
- Focused LTP harness:
  `target/release/carrick-conformance --suite ltp-ptrace06 --jsonl target/conformance/ptrace06-ancestry-fix.jsonl`
  reported `MATCH carrick[48/48] oracle[48/48]`.

Probe-gate note:
`just conformance-probes` is not green on this tree. It hit the existing bridge
UDP timeout and existing arm64 musl gaps such as `childsubreaper`,
`epollforkeventfd`, `execthreads`, `keydeny`, `mlock2`, `ptyforkreopen`,
`rlimitroundtrip`, `sotimeo`, and `syscallregpreserve`. The new stable
`ptracestop` probe passed in that run.

## 2026-07-07 04:xx - Full bless after ptrace06

Command:

```sh
target/release/carrick-conformance --tier full --bless \
  --jsonl target/conformance/bless-after-ptrace.jsonl
```

Outcome:

- The run stopped in Carrick phase 1/3 at the harness fail-fast limit:
  51 cached-oracle gating verdicts exceeded the default maximum of 50.
- No bless artifacts were left staged or modified.
- The ptrace06 fix held under the larger run:
  `ltp-ptrace06` reported `MATCH carrick[48/48] oracle[48/48]` with
  `716ms/412ms` (`1.74x`).

Important regressions/timing signals:

- `ltp-ptrace11` is a nearby ptrace regression but not a timing outlier:
  `broken/ok`, `717ms/606ms`.
- `ltp-pipe07` is both a gating regression and a pathological timing case:
  `broken/fail`, `31353ms/1027ms` (`30.53x`).
- Related pipe/wait timing signals cluster around the same 30s Carrick runtime:
  `ltp-pipe06` (`19.34x`, both broken), `ltp-pipe11` (`24.73x`, match),
  and `ltp-epoll-ltp` (`23.41x`, match).
- Largest observed ratio was `ltp-rt_sigqueueinfo02` at `66.30x`, but that is
  also a new signal-semantics diff (`broken/ok`), so it is not the first pipe
  wait/backpressure reducer.

Hypothesis:

The immediate next target should be `ltp-pipe07`, not a blanket baseline bless.
It is narrow enough to reproduce alone, it is a gating regression, and its
runtime matches the broader pipe/epoll/fcntl slow-wait cluster. If the focused
run keeps the 30s shape, trace pipe/fd syscalls first; if tracing perturbs the
failure, run the same command through `carrick debug lldb-run` so event-ring and
thread dumps are captured by the deadline handler instead of relying on an
external sleep/retry loop.

## 2026-07-07 04:37 - pipe07 graceful-failure reducer

Hypothesis:

`ltp-pipe07` is not a pipe readiness/kqueue problem. It is an fd-fill/resource
contract problem: Carrick advertised Linux's 1M `RLIMIT_NOFILE`, then backed
each anonymous pipe with real macOS pipe fds until the host refused more pipe
resources. The old behavior returned a Darwin-shaped failure (`EBADF`) after
122864 pipe fds and then timed out during LTP cleanup.

Tests:

- Focused pre-fix harness:
  `target/release/carrick-conformance --suite ltp-pipe07 --jsonl target/conformance/pipe07-focused-1.jsonl`
  reproduced the 30s failure: `carrick[0/3] oracle[0/2]`,
  `30472ms/1027ms`, with raw Carrick output:
  - `TFAIL: errno (9) != EMFILE (24)`
  - `TFAIL: exp_num_pipes (1048572) != num_pipe_fds (122864)`
  - `TBROK: Test killed! (timeout?)`
- Live Docker oracle, run alone after Carrick stopped, contradicted the stale
  cache and passed:
  - `TPASS: errno == EMFILE (24)`
  - `TPASS: exp_num_pipes == num_pipe_fds (1048572)`
- Added a focused integration gate,
  `pipe2_fd_fill_fails_fast_with_emfile`, that opens 2048 host-backed pipes
  through the real `pipe2` dispatcher path, asserts the next `pipe2` returns
  Linux `EMFILE`, then closes every fd it opened.

Change:

Added `HOST_PIPE_FD_PRESSURE` at 4096 guest fd-table entries, mirroring the
existing path-open pressure cap. `pipe2` now returns Linux `EMFILE` before
allocating more host pipes past that threshold, and any raw host `pipe(2)`
failure is normalized to `EMFILE` because the guest pointer is Carrick-owned and
a failure there means host pipe/fd resources are exhausted for this emulation
path.

Outcome:

- `cargo fmt --check` passed.
- `cargo test -p carrick-runtime --test integration pipe2_fd_fill_fails_fast_with_emfile`
  passed.
- `just build -p carrick-cli` passed and re-signed `target/release/carrick`.
- Refreshed focused harness:
  `target/release/carrick-conformance --suite ltp-pipe07 --refresh-oracle --jsonl target/conformance/pipe07-fast-emfile.jsonl`
  now finishes quickly: `carrick[1/2] oracle[2/2]`,
  `1112ms/822ms` (`1.35x`), with no timeout/TBROK. Carrick now passes the
  `EMFILE` assertion and fails only the real missing-capacity assertion:
  `exp_num_pipes (1048572) != num_pipe_fds (4096)`.

Conclusion:

This is a good logical checkpoint to commit as graceful failure and stale-oracle
repair, not a complete `pipe07` conformance fix. Passing `pipe07` requires a
larger architectural answer for million-scale anonymous pipes: synthetic/pooled
pipe storage, or a coherent lower guest-visible `RLIMIT_NOFILE` and `/proc`
surface. The former is closer to Linux semantics; the latter would deliberately
diverge from the Docker oracle.
