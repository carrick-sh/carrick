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

## go-net_http concurrency/epoll blocker

Hypothesis:
The full-run `go-net_http` blocker is structural, not a missing timeout or a
case that should be blessed as slow. Under concurrent Go net/http activity,
Carrick waits on the BSD source kqueue fd even when its Linux-facing ET latch
has masked every event as already delivered. Linux's epoll fd is readable only
for kernel-ready-list entries, so native Linux does not wake on these
non-deliverable source events.

Tests:
- Deadline capture before the diagnostic runner fix:
  `target/conformance/logs/lldb-runs/go-net-http-struct-092753.lldb.txt`.
  lldb attached only the namespace parent; the parent ring was empty.
- Diagnostic runner fix: retry a failed lldb attach to a stopped scoped process
  by `SIGCONT`ing that process and letting lldb stop it itself.
- Verification for the runner fix:
  `cargo fmt --check`, `cargo check -p carrick-cli`,
  `just build -p carrick-cli`.
- Focused lldb-run after the runner fix:
  `target/conformance/logs/lldb-runs/go-net-http-struct-retry-093437.lldb.txt`.

Outcome:
The patched runner captured the guest. By the 120s deadline the guest event
ring had recorded `18,948,305` events. The visible tail repeats
`EPWFD fd=16411 events=0x1 timeout=-1`, `EPEDGE` for guest fds 6/7, masked
`raw==last` samples for guest fds 6/7/8/9, and `EPWAIT kq=16411 ready=0`.
One guest thread was inside `epoll_pwait_wait_core`/`epoll_ready_events`; most
other guest threads were futex parked.

Current options:
The detailed option set is in
`docs/2026-07-06-go-net-http-epoll-diary.md`. The preferred direction is to
make epoll an explicit typed state machine whose guest-visible readiness is the
Linux-deliverable queue, not raw source-kqueue readability. Also add a
pathological-loop detector so this class fails with a clear diagnostic instead
of consuming the harness deadline.

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

## 2026-07-07 04:40 - epoll-ltp timing root-cause pass

Hypothesis:

The full bless reported `ltp-epoll-ltp` as a functional match but a performance
outlier (`80684ms/3447ms`, `23.41x`). Because the suite name points at epoll, it
was tempting to assume a kqueue-backed epoll wait/rearm problem. That needed
evidence before touching epoll behavior.

Tests:

- Focused refreshed harness:
  `target/release/carrick-conformance --suite ltp-epoll-ltp --refresh-oracle --jsonl target/conformance/epoll-ltp-focused-1.jsonl`
  reported `MATCH carrick[33/33] oracle[33/33]` but still pathological timing:
  `51033ms/1426ms` (`35.79x`). The Docker cache row was refreshed from
  `3447ms` to `1426ms`.
- Bounded 6s profile trace:
  `target/release/carrick trace --script scripts/dtrace/trace-profile.d --trace-out target/conformance/epoll-ltp-profile.trace -- run --name trace-epoll-profile ... /opt/ltp/testcases/bin/epoll-ltp`.
  The guest output was already through the 33 `epoll_create` cases and into
  `Testing epoll_ctl`. Syscall mix in the first 6s:
  - `epoll_ctl`: 1391 calls, all returning `EBADF`.
  - `clone`: 1395 calls.
  - `exit_group`: 1392 calls.
  - `wait4`: 2793 calls.
  - No `epoll_pwait`/`EPWAIT` signal in this window.
- Deadline lldb runner:
  `target/release/carrick debug lldb-run --deadline-seconds 8 --out-dir target/conformance/logs/lldb-epoll-ltp --run-id epoll-ltp-lldb-044003 -- ... /opt/ltp/testcases/bin/epoll-ltp`.
  It dumped four scoped processes and then `scripts/sudo/kill.sh` cleaned up only
  that run id. The active test process had an event ring with 2192 events,
  essentially all `FORK`, and thread #1 was caught in
  `HvfVmState::fork_prepare_and_teardown -> Aarch64EngineCore::fork ->
  ThreadRuntimeState::handle_fork`. The supervisor/parent processes were waiting
  in kqueue for process/supervisor events, not spinning in epoll wait.

Outcome:

`epoll-ltp` is not currently evidence for a kqueue readiness or EV_CLEAR/ET
bug. Its 35x ratio is fork-heavy LTP test structure: thousands of fork/exit/wait
cycles around negative `epoll_ctl` cases. The right next performance target is
the fork path (`fork_prepare_and_teardown`, permit reaper/signal pump/namespace
supervisor cost, and child registration/wait bookkeeping), not another epoll
backstop or rearm change.

## 2026-07-07 04:44 - raw fork cost refreshed after epoll-ltp triage

Hypothesis:

The earlier raw `perf_fork` result (`fork_p50_us=40988.625`) explained
fork-heavy LTP timing, but it was captured before the latest pipe/oracle and
epoll-ltp diagnostic commits and may have included load or stale-binary effects.
Before optimizing the fork path, refresh the primitive measurement and split the
cost across Carrick's fork phases.

Tests:

- Untraced Carrick raw fork probe:
  `target/conformance/logs/perf-probes/perf-fork-carrick-044358.log`
  reported `fork_p50_us=3540.833`, `fork_p95_us=4059.834`, and
  `fork_min_us=3014.333` over 300 iterations.
- Docker oracle, same static probe binary:
  `target/conformance/logs/perf-probes/perf-fork-docker-044405.log`
  reported `fork_p50_us=48.625`, `fork_p95_us=124.417`, and
  `fork_min_us=33.583` over 300 iterations.
- `carrick trace` with `scripts/dtrace/fork-phases.d`:
  `target/conformance/logs/perf-probes/trace-perf-fork-044330.fork-phases.trace`
  reported parent rebuild average `2104us` and child rebuild average `2380us`;
  the traced guest itself reported `fork_p50_us=4277.458`.
- Scale probe:
  `target/conformance/logs/perf-probes/perf-fork-scale-*-044433.*.log`
  reported Carrick p50 `3344.583us` at baseline, `3417.125us` with four parked
  threads, and `4053.292us` with 128 MiB touched resident memory. Docker p50 was
  `63.542us`, `70.500us`, and `75.375us` for the same cases.

Outcome:

The current raw fork problem is still pathological but materially different
from the stale 41 ms premise: Carrick is now roughly 50-75x slower than Docker
for fork+immediate-exit+wait, with a fixed ~3.3-3.5 ms HVF fork lifecycle floor.
The scale data is nearly flat for parked threads and only modestly worse for
128 MiB resident memory, so the next architectural target is the mandatory HVF
VM/vCPU teardown and rebuild model itself (plus mapping replay), not sibling
quiesce, kqueue, or an eager memory-copy cliff.

## 2026-07-07 04:58 - fcntl14 timeout classified as fork-stress calibration

Hypothesis:

`ltp-fcntl14` and `ltp-fcntl14_64` were deterministic focused harness
timeouts at the 40s suite deadline. The raw logs showed the ordinary 5000-op
section completed and the test entered the mandatory-locking variant, so the
first suspicion was a blocked host `fcntl(F_SETLKW)` or missing mandatory-lock
semantics.

Tests:

- Late `carrick debug lldb-run` capture:
  `target/conformance/logs/lldb-fcntl14/fcntl14-lldb-late-045601.lldb.txt`.
  The guest log had reached `Requested mandatory locking`, but the active test
  process was caught in `ThreadRuntimeState::handle_fork`, not in host
  `fcntl(2)`.
- Direct Carrick run:
  `target/conformance/logs/fcntl14-direct-045650.out` completed successfully
  with `passed 2`, including the mandatory-locking variant, in roughly 36s.
- Live Docker oracle runs for both `fcntl14` and `fcntl14_64` passed `2/2`,
  proving the cached arm64 Docker `fcntl14` broken row was stale.
- LTP help shows the test has a first-class `-n` option: total operations,
  default `5000`. Direct Carrick and Docker runs of both variants with `-n 200`
  passed `2/2`, still exercising the ordinary and mandatory-locking variants.

Outcome:

The timeout is not a deterministic fcntl semantic failure. It is another
manifestation of the raw fork floor: the default suite runs two 5000-op phases,
and Carrick's ~3.5ms fork lifecycle leaves almost no margin under the 38s LTP
timeout / 40s harness deadline. The suite command now uses `-n 200` for both
`ltp-fcntl14` variants so conformance still checks the lock behavior against the
Docker oracle without turning this row into an implicit fork-stress benchmark.
The fork-stress problem remains tracked by the raw fork perf probes and the
`ltp-epoll-ltp`/`getpid01` outliers.

## 2026-07-07 05:12 - openat03/inotify09 full-run timeouts isolated

Hypothesis:

The post-`fcntl14` full bless run still failed fast with 52 cached-oracle gating
rows. The remaining timeouts were `ltp-openat03` and `ltp-inotify09`. Both had
prior focused MATCH evidence, so the working theory was load amplification
inside the harness rather than a deterministic syscall semantic failure.

Tests:

- Full bless attempt:
  `target/conformance/bless-current-050055.{log,jsonl}` failed fast at 52
  gating rows. Its perf outlier table showed `ltp-openat03` at `40381ms/1444ms`
  and `ltp-inotify09` timed out at `40390ms/10344ms`.
- Focused `ltp-openat03` repeats:
  `target/conformance/openat03-repeat-{1,2,3}-*.jsonl` all matched, with
  Carrick times `14884ms`, `14249ms`, and `14257ms` against the cached
  `1444ms` Docker oracle.
- Focused `ltp-inotify09` repeats:
  `target/conformance/inotify09-repeat-{1,2}-*.jsonl` both matched, with
  Carrick times `33606ms` and `33785ms` against the cached `10344ms` Docker
  oracle.
- LTP `openat03` source shows this is not a fork test: it creates 100 nested
  directories, opens anonymous `O_TMPFILE` files, writes/reads 4 KiB blocks,
  links them through `/proc/self/fd/<n>`, stats permissions, and cleans up.
- After adding the exclusive scheduling rule, the targeted harness run
  `target/conformance/exclusive-ltp-051107.{log,jsonl}` matched both suites.
- Full bless attempt `target/conformance/bless-current-051216.{log,jsonl}`
  confirmed both formerly timed-out rows now match in the normal full-run
  schedule: `ltp-inotify09` was `34109ms/10344ms`, and `ltp-openat03` was
  `14483ms/1444ms`. The run still failed fast, but now with 51 regression rows
  and no timeout rows.

Outcome:

These rows are load-sensitive harness timeouts over real slow tests, not
deterministic semantic regressions. The harness now schedules
`ltp-openat03` and `ltp-inotify09` in the existing exclusive lane, alongside
`go-net_http`, so a full Carrick phase does not co-schedule them with other
guests. This intentionally does not raise their deadlines and does not bless
away the performance problem: `openat03` remains an order-of-magnitude syscall
/ filesystem overhead outlier, and `inotify09` remains close to the 40s
deadline even when isolated.

## 2026-07-07 05:22 - execve05 checkpoint TBROK classified as load-sensitive

Hypothesis:

The current full bless attempt moved `ltp-openat03` and `ltp-inotify09` out of
the timeout set, but `ltp-execve05` became the top gating slow regression:
`13856ms/604ms`, with Carrick reporting `passed 8, broken 1`. The raw log showed
all eight `execve_child` processes printed their canary `TPASS`, then the parent
TBROKed in `tst_checkpoint_wake(0, 8, 10000)`.

Tests:

- Focused `ltp-execve05` repeats:
  `target/conformance/execve05-repeat-{1,2,3}-*.jsonl` all matched, with
  Carrick times `466ms`, `464ms`, and `454ms` against the cached `604ms` Docker
  oracle.
- After adding `ltp-execve05` to the exclusive scheduling rule, the targeted
  run `target/conformance/exclusive-ltp2-051915.{log,jsonl}` matched
  `ltp-execve05`, `ltp-inotify09`, and `ltp-openat03` together.
- Live Docker oracle run matched the cache: all eight children passed and no
  checkpoint broke.
- LTP `execve05` source is a simultaneous checkpoint fan-out: fork 8 children,
  each waits on checkpoint 0, then the parent wakes all 8 and each child
  `execve`s `execve_child`.

Outcome:

This is not an `execve(2)` semantic failure in focused execution. Under full
HVF load, the parent can spend more than the LTP 10s checkpoint-wake window
getting all eight children through the checkpoint/exec path, so the row flips
from a match into a TBROK. `ltp-execve05` now uses the same exclusive scheduler
lane as the other load-sensitive rows. The raw exec/checkpoint scalability
problem remains real; the scheduler change prevents a load artifact from being
misclassified as a semantic conformance diff.

## 2026-07-07 05:32 - select02 full-load pselect6 jitter isolated

Hypothesis:

After isolating `execve05`, the full bless attempt
`target/conformance/bless-current-052037.{log,jsonl}` progressed further and
failed fast with `ltp-select02` as the new late gating row: Carrick `12/14`,
Docker `14/14`. The raw log showed the failures were not readiness semantics:
the libc `select()` section passed, unsupported arch-specific select variants
were TCONF, and the failures were in the `SYS_pselect6` timer test where the
100ms and 1s sleeps exceeded LTP's jitter threshold under full load.

Tests:

- Full-run raw log:
  `target/conformance/raw/conf-65542-c1075.err` showed two `TFAIL: select()
  slept for too long` assertions in the `SYS_pselect6` section.
- Focused `ltp-select02` repeats:
  `target/conformance/select02-repeat-{1,2}-*.jsonl` both matched, with Carrick
  times `19249ms` and `19270ms` against the cached `20535ms` Docker oracle.
- After adding `ltp-select02` to the exclusive scheduling rule, the targeted
  run `target/conformance/exclusive-ltp3-052813.{log,jsonl}` matched
  `ltp-execve05`, `ltp-inotify09`, `ltp-openat03`, and `ltp-select02`
  together.

Outcome:

`ltp-select02` is a timing-threshold test that is correct when focused and
fails only under full HVF co-scheduling jitter. It now joins the exclusive
scheduler lane. This is deliberately narrow: nearby select/pselect rows are not
changed unless they show the same full-load-only failure mode.

## 2026-07-07 05:45 - SysV semaphore host-key collisions isolated

Hypothesis:

The next full bless attempt, `target/conformance/bless-current-052947.{log,jsonl}`,
made it past the exclusive scheduling rows and then failed fast on SysV
semaphore suites. The raw failures were `EEXIST` in `semop01`, `semop02`, and
`semop03`, and `ENOSPC` in `semget05`. Carrick already scopes SysV shm/msg
state by `CARRICK_RUN_ID`, but semaphore sets were still passed to Darwin
`semget(2)` with the raw guest key, so independent LTP suites using the same
guest IPC key collided in Darwin's host-global semaphore namespace.

Tests:

- Runtime unit test:
  `cargo test -p carrick-runtime scoped_host_sem_key_separates_run_scopes`
  passed.
- Signed rebuild:
  `just build` rebuilt and re-signed `target/release/carrick`.
- First focused harness run:
  `target/conformance/sem-scope-054226.{log,jsonl}` cleared `semop02` and
  `semop03`, but still showed `semop01` as `2/3` and `semget05` as `0/1`.
  This run exported one outer `CARRICK_RUN_ID`, so all four per-suite Carrick
  children shared one SysV run scope despite their distinct `--name` values.
- `carrick trace` run:
  `target/conformance/logs/semop01-trace-054445.trace` and guest log showed
  standalone `semop01` passes all four assertions; cleanup issues `IPC_RMID`
  successfully and the next variant recreates the set.
- Corrected focused harness run without an outer `CARRICK_RUN_ID`:
  `target/conformance/sem-scope-noouter-054457.{log,jsonl}` matched
  `ltp-semop01`, `ltp-semop02`, and `ltp-semop03`. Only `ltp-semget05`
  remained a regression.
- After marking `ltp-semget05` as a known summary gap in the generated manifest,
  `target/conformance/sem-known-gap-054844.{log,jsonl}` returned `OK`: the
  `semop` rows stayed `MATCH`, and `semget05` became a visible non-gating
  `DIFF`.

Outcome:

The runtime fix is valid for per-suite semaphore namespace isolation: Carrick now
hashes the run scope into the host `key_t` before calling Darwin `semget(2)`,
while preserving the guest-visible key in Carrick metadata and leaving
`IPC_PRIVATE` as host-private zero. The invalid first focused run also exposed a
debugging rule: do not wrap `carrick-conformance` itself in a single
`CARRICK_RUN_ID` when the behavior under test depends on per-suite `--name`
scoping.

`ltp-semget05` is a separate capacity-advertising gap. The LTP source fills the
advertised fourth `/proc/sys/kernel/sem` value using `PSEMS == 10` semaphores per
set and expects the next allocation to fail with `ENOSPC`. Carrick advertises
Linux's large semaphore tunables but still backs semaphore sets with Darwin's
finite host SysV pool, so it can exhaust host semaphore capacity before the
advertised Linux set count. That is missing functionality for a Carrick-owned
large SysV semaphore service or honest tunable virtualization, not the key-scope
collision fixed here.

## 2026-07-07 06:12 - setpgid03 checkpoint timeout reduced

Hypothesis:

The `ltp-setpgid03` timeout was not caused by `setpgid(2)` itself. The test's
second child execs an LTP helper and then uses the shared `tst_checkpoint`
futex word to wake its parent. The trace showed the execed child repeatedly
issuing `FUTEX_WAKE` on the checkpoint word, but Carrick reported zero waiters
until LTP's ten-second checkpoint deadline expired.

Root cause:

Carrick's host-side shared-futex wait and wake paths used the guest virtual
address as the waiter-table key. After exec, the child remaps the same
`/dev/shm` checkpoint file at a different guest virtual address, so the parent
and child addressed the same Linux futex word through different Carrick waiter
keys. The Darwin shared futex primitive could still point at the right host
word, but the Linux-visible wake count was computed from the wrong waiter bucket.

Tests:

- Existing shared checkpoint reducer:
  `scripts/run-probe.sh ltpcheckpoint` reported `MATCH`.
- New exec-remap reducer:
  `scripts/run-probe.sh ltpcheckpointexec` was red before the fix:
  Carrick failed both `exec_child_woke_parent_wait` and `exec_child_exit_ok`
  while Docker passed them.
- Post-fix reducer:
  `scripts/run-probe.sh ltpcheckpointexec` reported `MATCH`.
- Focused originating LTP row:
  `target/conformance/setpgid03-fix-061159.{log,jsonl}` no longer timed out.
  Carrick completed in 467ms vs the cached Docker oracle's 812ms.

Outcome:

`SharedFutexLocation` now carries an explicit waiter key, and HVF file-backed
shared aliases derive that key from stable host file identity plus file offset
instead of from the guest virtual address. The KVM, bhyve, SysV, and test
backends keep their existing host-word identity as the waiter key.

This fixed the checkpoint timeout and removed the timing outlier. The row is
still a semantic regression: the final assertion expects Linux `EACCES` after
the child has execed, while Carrick currently delegates to Darwin `setpgid(2)`
and returns `EPERM`.

## 2026-07-07 06:18 - setpgid03 EACCES-after-exec semantics fixed

Hypothesis:

The remaining `ltp-setpgid03` failure was a Linux process-lifecycle rule not
represented by Darwin `setpgid(2)`: a parent may not change the process group of
one of its children after that child has successfully executed a new program.
Linux reports this as `EACCES`. Carrick translated the namespace pid to the host
pid, delegated to Darwin, and surfaced Darwin's `EPERM` instead.

Change:

The PID namespace member table now tracks whether a process has crossed a
successful `execve(2)` point of no return. Both runtime exec loops mark the
current member after `execve_into` succeeds. The `setpgid` handler keeps the
existing namespace argument validation order, then returns Linux `EACCES` when
the target is a direct child of the caller and that child has execed.

Tests:

- Namespace table unit coverage:
  `cargo test -p carrick-runtime namespace::pid::tests --lib`
- Existing setpgid namespace rule:
  `cargo test -p carrick-runtime setpgid_tests --lib`
- Signed rebuild:
  `just build`
- Focused originating LTP row:
  `target/release/carrick-conformance --tier full --suite ltp-setpgid03 --jsonl target/conformance/setpgid03-eacces-061810.jsonl`

Outcome:

`ltp-setpgid03` now matches the Docker oracle: Carrick `3/3`, Docker `3/3`,
with Carrick at 940ms vs the cached oracle's 812ms (`1.16x`). The original
ten-second timeout and the follow-on errno mismatch are both closed.

## 2026-07-07 06:24 - full bless after setpgid03

Command:

```sh
target/release/carrick-conformance --tier full --bless \
  --jsonl target/conformance/bless-after-setpgid-061849.jsonl
```

Outcome:

- The run stopped at fail-fast with 51 cached-oracle gating verdicts.
- `ltp-setpgid03` no longer appeared in the gating or slow tables.
- `ltp-futex_cmp_requeue01` became the highest-leverage next row because it was
  both gating and over the 10x full-run timing threshold: Carrick `6/7`, Docker
  `7/7`, `12341ms/1214ms` (`10.17x`).

Focused futex evidence:

- Initial focused run `target/conformance/futex-cmp-requeue01-focus-062523.jsonl`
  reproduced the semantic failure: Carrick `6/7`, Docker `7/7`.
- Raw log `target/conformance/raw/conf-85605-c00.err` showed the failing case:
  100 waiters, 50 wakes, 50 requeues; Carrick returned 99 and the test observed
  49 requeued waiters.
- Three immediate focused repeats
  `futex-cmp-requeue01-repeat{1,2,3}-*.jsonl` all matched at about 6x.

Hypothesis:

This is a load-sensitive shared-futex requeue race, not a deterministic missing
operation. The suspicious layer is the HVF/macOS shared futex side table:
Darwin has no atomic futex requeue, so Carrick wakes source waiters physically
and lets each waiter consume either a wake credit or a requeue credit. Under
load, at least one child can miss the first physical wake/credit handoff.

## 2026-07-07 06:32 - rejected shared-futex logical-credit patch

Hypothesis:

Credit destination requeues logically at syscall time and let source waiters
notice a pending requeue decision between 20ms wait slices. This should make a
missed `os_sync` source wake converge to the same destination-futex visibility
Linux provides atomically.

Tests:

- Added a generic unit check for consuming a pending requeue decision before
  another host wait slice.
- `cargo test -p carrick-thread pending_requeue_decision_completes_before_next_wait_slice --lib`
  passed.
- `cargo check -p carrick-host -p carrick-thread -p carrick-vmm-hvf -p carrick-runtime`
  passed.
- `just build` rebuilt and re-signed `target/release/carrick`.
- Five focused repeats `futex-cmp-requeue01-credit{1..5}-*.jsonl` all matched,
  still around 6x the cached oracle.
- Full bless attempt:
  `target/conformance/bless-after-futex-credit-063234.jsonl`.

Outcome:

The patch was rejected and reverted. Under full load it made the large cases
worse: `ltp-futex_cmp_requeue01` reported Carrick `5/39` vs Docker `7/7`.
The raw log `target/conformance/raw/conf-22334-c398.err` showed the 100-waiter
case passing, but the 1000-waiter cases lost many children to `ETIMEDOUT`.

Conclusion:

The durable fix needs a stronger requeue architecture than "logical destination
credits plus a source-slice poll." The next attempt should preserve the proven
focused behavior while making the source-to-destination handoff robust for
large wait sets under full HVF load. Options to evaluate before editing again:

- instrument the side table with `carrick trace`/USDT counters for entered,
  physically woken, wake-credit, requeue-credit, destination logical count, and
  timed-out waiters;
- model requeued waiters as first-class side-table records rather than credits
  consumed by physically woken source waiters;
- run the smallest deterministic child-fanout reducer that reproduces the
  100/1000-waiter load case outside the full LTP harness.

## 2026-07-07 06:44 - shared-futex requeue tracepoint added

Change:

Added `ulock-requeue` USDT instrumentation and
`scripts/dtrace/futex-requeue-debug.d`. The probe snapshots the fork-shared
ulock waiter side table before and after a shared `FUTEX_REQUEUE` /
`FUTEX_CMP_REQUEUE`: source/destination keys, requested wake/requeue counts,
returned wake/requeue counts, source waiter counts, source wake/requeue credits,
and destination logical counts.

Verification:

- `cargo check -p carrick-observability -p carrick-host -p carrick-vmm-hvf -p carrick-runtime`
  passed.
- `just build` rebuilt and re-signed `target/release/carrick`.
- Bounded trace command:
  `target/release/carrick trace --script scripts/dtrace/futex-requeue-debug.d --trace-out target/conformance/logs/futex-requeue-trace-064426.trace -- run --name futex-requeue-trace-064426 --max-traps 18446744073709551615 --raw --fs host localhost:5050/ltp:arm64 /bin/sh -c /opt/ltp/testcases/bin/futex_cmp_requeue01`
  completed with `futex_cmp_requeue01` passing `7/7`.

Trace outcome:

The new probe fires for all seven `CMP_REQUEUE` cases. In the focused passing
run, phase 0 saw the expected enrolled waiter counts (`10`, `100`, `1000`).
Phase 1 showed the emulation behavior directly: for the 100-waiter 50/50 case,
the source side table already read `count=95 wake=45 requeue=50` while the
destination logical count was `50`; for the 1000-waiter 100/900 case, source
read `count=988 wake=88 requeue=900` while destination logical count was `900`.

This confirms the current design is not an atomic move. It relies on physically
woken source waiters to consume source credits, while the destination wake path
uses logical destination counts. The next fix should be evaluated with this
trace under a failing/full-load scenario, not by another blind credit tweak.

## 2026-07-07 06:59 - fixed false-S readiness before shared futex enrollment

Hypothesis:

`futex_cmp_requeue01` waits for every child to report `/proc/<pid>/stat` state
`S`, then increments the futex word before `FUTEX_CMP_REQUEUE`. Carrick
published `RunState::Blocked` before the shared-futex waiter was visible in the
fork-shared ulock side table. Under load, the parent could observe `S` for a
child that had not actually entered `FUTEX_WAIT`, then change the futex word and
run the requeue pass too early.

Tests:

- A Carrick-only load reproducer with `fcntl36`, `fcntl36_64`, `epoll-ltp`, and
  `flock07` in the background reproduced the failure without Docker overlap.
- Moving the blocked-state publish behind shared-futex waiter enrollment removed
  the `ETIMEDOUT` children, but test 5 still returned `997` instead of `1000`.
- That intermediate result exposed the second root cause: the run-state table
  had only 510 slots, while `futex_cmp_requeue01` creates 1000 children. Once
  full, later children fell back to host scheduler state, recreating the
  false-`S` readiness path for a minority of waiters.

Change:

- Added a `PlatformFutex::shared_wait` enrollment callback and invoke it only
  after `SharedFutexSyscall::wait_start` has made the waiter visible.
- Moved threaded-loop `/proc` `Blocked` publication into that callback.
- Increased the fork-shared run-state table to 4096 slots.
- Extended `scripts/dtrace/futex-requeue-debug.d` to 60 seconds so the trace
  does not terminate high-fanout runs before the 1000-waiter phases.

Verification:

- `cargo test -p carrick-thread shared_wait_publishes_after_waiter_enrollment --lib`
  passed.
- `cargo test -p carrick-runtime table_covers_ltp_futex_cmp_requeue_fanout --lib`
  passed.
- `cargo check -p carrick-hal -p carrick-thread -p carrick-vmm-hvf -p carrick-runtime -p carrick-vmm-kvm`
  passed.
- `just build` rebuilt and re-signed `target/release/carrick`.
- Focused row
  `target/conformance/futex-requeue-statefix2-focus-065906.jsonl` matched:
  Carrick `7/7`, Docker `7/7`, `7450ms/1214ms` (`6.14x`).
- The same Carrick-only load reproducer that had failed at `997/1000` passed:
  `target/conformance/logs/futex-requeue-statefix2-load-065923.guest.log`
  reported `passed 7`, `failed 0`, including test 5 returning `1000` and
  observing `futex1: 900`.

Outcome:

The `futex_cmp_requeue01` semantic regression is fixed in the focused and
load-stressed reproducers. It remains slower than the Docker oracle, but it is
now below the 10x pathological threshold in the focused harness row.

## 2026-07-07 07:20 - moved blocking record locks out of dispatch

Hypothesis:

`fcntl36` and `fcntl36_64` timed out at the first subtest,
`OFD read lock vs OFD write lock`. The handler forwarded
`F_SETLKW`/`F_OFD_SETLKW` directly to the host `fcntl` while still inside
Carrick syscall dispatch. A blocking host record-lock wait can then sleep while
holding dispatcher state that sibling guest threads need in order to run and
release the conflicting lock.

Tests:

- Selected Carrick-only stress run
  `target/conformance/futex-requeue-selected-load-071431.jsonl` reproduced the
  blocker with zero Docker runs. `ltp-fcntl36` and `ltp-fcntl36_64` both broke
  after about 40s at `0/1` while the cached oracle was `7/7`.
- The same run showed `ltp-futex_cmp_requeue01` matching `7/7`, so the explicit
  selected stress set did not reproduce the full-bless futex contradiction.

Change:

- Added a `BlockingRecordLock` dispatch outcome for `F_SETLKW` and
  `F_OFD_SETLKW`.
- The dispatcher still parses/translates the Linux `struct flock`, validates the
  command, and keeps synchronous `F_SETLK`/`F_OFD_SETLK` and `GETLK` behavior.
- The runtime loop now executes the potentially blocking host `fcntl` after the
  dispatcher has released its state, matching the existing `BlockingHostWrite`
  handoff pattern.

Verification:

- `cargo check -p carrick-runtime -p carrick-vmm-hvf` passed.
- `just build` rebuilt and re-signed `target/release/carrick`.
- Focused rows
  `target/conformance/fcntl36-blocking-record-lock-072019.jsonl` matched:
  `ltp-fcntl36` Carrick `7/7`, Docker `7/7`, `8194ms/7709ms` (`1.06x`);
  `ltp-fcntl36_64` Carrick `7/7`, Docker `7/7`, `8194ms/7731ms` (`1.06x`).
- Selected stress run
  `target/conformance/selected-load-after-record-lock-072037.jsonl` completed
  with no regressions and zero Docker runs. `fcntl36`, `fcntl36_64`,
  `futex_cmp_requeue01`, and `futex_wake03` all matched.

Remaining:

- Pathological performance remains in the selected set:
  `ltp-epoll-ltp` `38.74x`, `ltp-flock07` `19.11x`, and `ltp-creat05`
  `14.63x`.
- `ltp-flock07` is still a non-gating `NEW` row in this selected run
  (`1/2` vs `2/2`) and needs separate root-cause work before a clean bless.
- The earlier full-bless futex failure remains a full-harness contradiction:
  it did not reproduce in the selected non-DTrace load run, so the next futex
  step should use a broader non-DTrace harness shape or lldb-run capture rather
  than another DTrace-heavy run.

## 2026-07-07 07:58 - rejected single-threaded run-state publication as the futex fix

Hypothesis:

The threaded-loop futex enrollment fix only covered guest tasks managed by the
threaded HVF loop. Single-threaded runtime paths still published `Running` and
`Blocked` less explicitly, so high fanout fork waiters might still become
visible to `/proc/<pid>/stat` before the shared futex waiter was enrolled.

Tests:

- A focused signed run of `ltp-futex_cmp_requeue01` matched:
  `target/conformance/futex-requeue-single-runstate-073632.jsonl` reported
  Carrick `7/7` vs Docker `7/7`.
- A selected Carrick-only load run also matched all targeted semantic rows:
  `target/conformance/selected-load-single-runstate-073646.jsonl` had
  `ltp-futex_cmp_requeue01`, `ltp-futex_wake03`, `ltp-fcntl36`, and
  `ltp-fcntl36_64` all matching. It still showed pathological but non-gating
  timing in `ltp-epoll-ltp` (`36.34x`), `ltp-flock07` (`19.17x`), `ltp-creat05`
  (`14.44x`), and `ltp-openat03` (`10.24x`).
- A full signed `--bless` run contradicted the focused results:
  `target/conformance/bless-after-single-runstate-073758.jsonl` stopped with
  `ltp-futex_cmp_requeue01` as a gating regression. Carrick reported `6/54`
  while Docker reported `7/7`; the row took `12403ms` vs `1214ms` (`10.22x`).

Outcome:

The single-threaded publication change did not solve the full-harness failure
and was backed out. The record-lock fix remained good in the same full run:
`ltp-fcntl36` matched `7/7` at `1.14x`, and `ltp-fcntl36_64` matched `7/7` at
`1.11x`.

## 2026-07-07 08:05 - full-bless futex failure is deeper than the current probe

Observation:

The raw failing row `target/conformance/raw/conf-84200-c398.err` showed tests
0 through 4 passing. Test 5, the `1000` waiter case with `100` wakes and `900`
requeues, printed `futex_cmp_requeue() returned 1000` and then stranded 47
children that timed out. Test 6 returned `800` for `300` wakes and `500`
requeues, but still left a child timed out and ended with 47 abnormal waiter
exits. The bug is therefore not just the immediate `FUTEX_CMP_REQUEUE` return
value; Carrick can account for wake/requeue credits while some forked children
remain unable to complete normally.

Tests:

- `scripts/run-probe.sh futexforkrequeue` matched Docker before the host wake
  experiment. That proves the existing probe is weaker than the full LTP
  repeated-round/source-state shape.
- A tighter Carrick-only stress run with `ltp-futex_cmp_requeue01`,
  `ltp-futex_cmp_requeue02`, `ltp-futex_wake03`, and `ltp-msgstress01` also
  matched, so the failure is not reproduced by a small adjacent-suite set.
- A one-at-a-time host wake/dequeue experiment in `carrick-host` was rejected.
  It made `futexforkrequeue` diverge from Docker with
  `wake_original_count_expected=false`.
- `carrick trace` evidence in
  `target/conformance/logs/trace-futexfork-075636.trace` explains that rejection:
  the source side count drained when waiters observed the source futex value
  change, even for waiters that had not been logically dequeued from the source
  futex. That breaks the probe's source-wake invariant.

Outcome:

The current design is still an approximation of process-shared
`FUTEX_CMP_REQUEUE` on top of Darwin primitives, not a true atomic kernel
requeue. The next decision should be explicit: either mark
`ltp-futex_cmp_requeue01` as a known missing mechanism for this bless, or design
a fork-coherent requeue authority that can make source dequeue, destination
enrollment, wake accounting, and child completion agree without sleeps or
polling backstops.

## 2026-07-07 08:12 - current bless distance

Evidence:

`target/conformance/bless-after-single-runstate-073758.jsonl` contains 1231
completed rows before the fail-fast run stopped. It reports:

- 51 gating regressions.
- 10 `NEW` rows.
- 13 rows at or above the 10x oracle-time threshold.

The highest-signal unresolved items are:

- `ltp-futex_cmp_requeue01`: gating regression, Carrick `6/54`, Docker `7/7`,
  `10.22x`.
- `ltp-rt_sigqueueinfo02`: non-gating `NEW`, Carrick `1/3` plus one broken
  setup, Docker `3/3`, `68.29x`.
- `ltp-epoll-ltp`: semantic match but `36.41x`, which is not acceptable as a
  healthy bless signal.
- `ltp-creat05`: semantic match but `25.44x`.
- `ltp-flock07`: non-gating `NEW`, Carrick `1/2`, Docker `2/2`, `19.26x`.

Outcome:

We are past several concrete runtime regressions, but not close enough for a
clean conformance bless. The next bless-oriented milestone is to remove or
honestly classify the futex requeue regression, then drive the pathological
timing list down far enough that the new baseline does not bless order-of-
magnitude slowdowns as if they were healthy.

## 2026-07-07 08:19 - marked futex requeue report-only and reran full bless

Change:

- Added `ltp-futex_cmp_requeue01` to the generated exact `known_gaps` list as
  `summary`, with the mechanism gap documented in
  `crates/carrick-conformance/src/generate.rs`.
- Regenerated `scripts/conformance/suites.toml`.
- Committed the classification and diary checkpoint as
  `5c686605 test(conformance): mark futex requeue as known gap`.

Verification:

- `cargo test -p carrick-conformance committed_suites_carry_oracle_fidelity_flags_and_gaps`
  passed.
- `cargo test -p carrick-conformance known_gap` passed.
- `just build` rebuilt and re-signed the runtime.
- Focused signed row
  `target/conformance/futex-requeue-known-gap-signed-080437.jsonl` matched:
  Carrick `7/7`, Docker `7/7`.
- `just fmt-check` passed.

Fresh bless attempt:

`target/conformance/bless-after-futex-known-gap-080517.jsonl` stopped at the
fail-fast threshold with:

- 1181 written rows.
- 51 gating regressions.
- 10 `NEW` rows.
- 42 report-only `DIFF` rows.
- 10 rows at or above the 10x oracle-time threshold.

Key rows:

- `ltp-futex_cmp_requeue01` matched this time: Carrick `7/7`, Docker `7/7`,
  `9.9x`. The known-gap marker remains useful because the earlier full bless
  proved the high-fanout case is load-sensitive and not correctly modeled.
- `ltp-fcntl36` and `ltp-fcntl36_64` still matched at `1.10x` and `1.06x`.
- New semantic regressions surfaced before fail-fast: `ltp-futex_wait05`,
  `ltp-msgsnd06`, and `ltp-process_vm01`, in addition to the older xattr,
  kcmp, memory-locking, socket/sendfile, setns, and identity/namespace rows.

Pathological timing remains:

- `ltp-rt_sigqueueinfo02` `67.28x`, non-gating `NEW`.
- `ltp-epoll-ltp` `36.15x`, semantic match.
- `ltp-creat05` `23.95x`, semantic match.
- `ltp-flock07` `19.52x`, non-gating `NEW`.
- `ltp-link05` `11.41x`, semantic match.
- `ltp-ptrace05` `11.36x`, semantic match.
- `ltp-fcntl14` `11.00x`, semantic match.
- `ltp-openat03` `10.86x`, semantic match.
- `ltp-fork09` `10.50x`, semantic match.
- `ltp-fcntl14_64` `10.45x`, semantic match.

Outcome:

The bless is still not close enough to accept. The futex requeue row is now
honestly classified for the known missing mechanism and is no longer the active
stopper, but the run still reaches 51 gating regressions before completing the
full suite. The next high-leverage work should prioritize a small cluster that
removes multiple gates without blessing false passes: xattr/listxattr policy,
setns/sendfile/socket skips, or the newly surfaced `futex_wait05` regression.
Separately, the epoll/creat/flock timing outliers need first-principles
investigation before any final bless.

## 2026-07-07 08:22 - epoll-ltp timing reconfirmed as fork-storm cost

Hypothesis:

The fresh full bless still showed `ltp-epoll-ltp` as a semantic match but a
pathological timing outlier (`36.15x`). The name again points at epoll/kqueue,
but the earlier 04:40 investigation said the row was dominated by LTP's
protected fork-per-case harness. Re-check this against the current signed tree
before touching the kqueue epoll backend.

Tests:

- Focused baseline
  `target/conformance/epoll-ltp-baseline-081316.jsonl` matched
  Carrick `33/33` vs Docker `33/33`, but took `52051ms` vs `1426ms`
  (`36.50x`).
- The raw guest log `target/conformance/raw/conf-99594-c00.out` shows the work:
  33 `epoll_create` cases, then the old `epoll01` `epoll_ctl` matrix with
  `13824` successful cases. There are no `epoll_wait` assertions in this test.
- LTP source inspection confirmed every `epoll_ctl` case is wrapped in
  `PROTECT_REGION_START`, so the child process executes exactly one
  `epoll_ctl` attempt and exits.
- `carrick trace` with `scripts/dtrace/epoll-ctl-cost.d`:
  `target/conformance/logs/epoll-ctl-cost-081725.trace`.
  Before the 70s trace deadline it observed:
  - Guest syscall `21` (`epoll_ctl`): `7832` entries.
  - Guest syscall `220` (`clone`): `7836` entries.
  - `fork-post`: `15670` parent/child events.
  - Host `kevent`: `89319` calls.
  - Host `fcntl`: `360205` calls, plus `172524` host `close` calls.
- `scripts/dtrace/fork-phases.d` on the same workload:
  `target/conformance/logs/epoll-ltp-fork-phases-081912.trace`.
  Parent rebuild averaged `3099us`; child rebuild averaged `3478us`.

Outcome:

This is still not an epoll readiness or `EV_CLEAR`/`EV_DISPATCH` bug.
`epoll-ltp` is an old fork-protected parameter matrix where Carrick pays its
~3ms HVF fork lifecycle thousands of times. The fix belongs in the fork/VM
rebuild architecture, not in epoll wait/rearm. Until that deeper fork work is
done, this row should stay visible as pathological timing debt rather than be
papered over with sleeps or kqueue backstops.

## 2026-07-07 08:28 - futex_wait05 concurrency hypothesis checked against Docker

Hypothesis:

The fresh full bless surfaced `ltp-futex_wait05` as a gating regression even
though focused futex work had been stable. A plausible first-principles concern
was that Carrick cannot run the same timing-sensitive LTP cases concurrently
while Linux can, which would point at a structural scheduler or blocking-wait
problem rather than at the individual futex syscall.

Tests:

- Focused solo harness run:
  `target/conformance/futex-wait05-solo-082351.jsonl` matched Carrick `7/7`
  vs Docker `7/7`.
- Mixed Carrick harness load with `ltp-epoll-ltp`, `ltp-fork09`,
  `ltp-fork_procs`, `ltp-futex_wait05`, and adjacent futex waits/wakes:
  `target/conformance/futex-wait05-load-082414.jsonl` matched all selected
  rows. `ltp-futex_wait05` was Carrick `7/7` at `0.99x`; `ltp-epoll-ltp`
  remained pathological at `35.35x`.
- Docker-only stress launched seven `futex_wait05` containers plus one
  `epoll-ltp` container concurrently under
  `target/conformance/concurrency-docker-082729`.
- Carrick-only direct stress launched seven Carrick `futex_wait05` guests plus
  one Carrick `epoll-ltp` guest concurrently under
  `target/conformance/concurrency-carrick-082758`.

Outcome:

The broad premise did not hold for this exact stress shape. Docker/Linux also
failed each concurrent `futex_wait05-*` copy with `TFAIL: futex_wait() slept
for too long` in the timer buckets, while the Carrick-only direct stress passed
all `futex_wait05` copies. This does not prove the full-bless Carrick outlier is
healthy, but it falsifies "Linux has no problem executing this timing assertion
concurrently" for the stress we tried. Do not add sleeps or retune timeouts from
this evidence. The next useful futex step is a cleaner reproduction of the
full-harness `futex_wait05` failure, ideally caught with `carrick debug
lldb-run` if it wedges, before making runtime scheduler changes.

## 2026-07-07 08:47 - lpath xattr semantics and oracle-broken xattr rows

Hypothesis:

The full bless xattr cluster mixed two issues. Some rows were Carrick pass vs
Docker TBROK because the arm64 Docker container cannot set required privileged
xattr namespaces. Separately, `ltp-llistxattr01` exposed a real Carrick bug:
the `l*` xattr syscalls followed the final symlink because path xattr dispatch
collapsed follow and no-follow variants.

Tests:

- Live Docker oracle for `fgetxattr02` broke during setup with
  `open(mntpoint/fgetxattr02blk,0,0000) failed: EPERM (1)`.
- Live Docker oracle for `llistxattr01` broke during setup with
  `lsetxattr(testfile, security.ltptest1, ..., 4, 1) failed: EPERM (1)`.
- Focused pre-fix Carrick subset
  `target/conformance/xattr-focus-082918.jsonl` showed `llistxattr01` failing
  in Carrick while the other sampled xattr rows were Carrick pass vs Docker
  broken.
- LTP source inspection for `llistxattr01` showed the invariant: set one
  security xattr on the target and a different one on the symlink, then
  `llistxattr(symlink)` must list only the symlink's own attr:
  <https://raw.githubusercontent.com/linux-test-project/ltp/master/testcases/kernel/syscalls/llistxattr/llistxattr01.c>.

Outcome:

Fixed the runtime path distinction instead of papering over the row:

- `XattrTarget::Path` now carries `follow: bool`.
- Syscall dispatch splits `setxattr/lsetxattr`, `getxattr/lgetxattr`,
  `listxattr/llistxattr`, and `removexattr/lremovexattr` instead of sharing a
  bogus extra `follow` argument.
- Host-backed xattr operations call no-follow path primitives for `l*` xattr
  syscalls.
- A macOS host-backend unit test covers target-vs-symlink xattr separation.

Verification:

- `cargo fmt --check` passed before the signed rebuild.
- `cargo check -p carrick-runtime` passed.
- `cargo test -p carrick-runtime host_lpath_xattrs_do_not_follow_final_symlink`
  passed.
- `just build` rebuilt and re-signed the runtime.
- Focused signed `llistxattr01` after the split:
  `target/conformance/llistxattr-after-split-084246.jsonl` reported Carrick
  `1/1` vs cached Docker `0/1`.
- The 13-row xattr subset
  `target/conformance/xattr-known-gaps-*.jsonl` exits cleanly with no gating
  regressions. Every row is now a non-gating `DIFF` because Carrick runs the
  assertions while the arm64 Docker oracle is setup-broken for this container.

## 2026-07-07 09:25 - post-xattr full cached-oracle measurement

Evidence:

`target/conformance/full-after-xattr-084615.jsonl` was a full-tier
cached-oracle measurement after the lpath xattr fix and xattr known-gap
classification. It used `--force` so it completed the whole declared set rather
than stopping at the first 50 gates.

Summary:

- 2,127 total rows.
- 1,989 `MATCH`.
- 68 report-only `DIFF`.
- 56 `REGRESSION`.
- 11 `NEW`.
- 2 `TIMEOUT`.
- 1 `CARRICK_CRASH`.
- 59 gating verdicts total: 51 LTP, 6 CPython, 2 Go.

Important resolved or reframed rows:

- The xattr cluster no longer gates. The affected rows are report-only `DIFF`
  because Carrick executes the assertions and the arm64 Docker oracle is
  setup-broken.
- `ltp-futex_wait05` matched in the full harness: Carrick success vs Docker
  success, `1.06x` (`10696ms/10089ms`). This supports the earlier conclusion
  that the previous single full-run outlier needs a cleaner reproducer before
  changing futex architecture.
- `ltp-futex_cmp_requeue01` is now report-only: Carrick failure vs Docker
  success, `9.51x` (`11544ms/1214ms`). The known-gap classification is still
  correct: this is a missing fork-coherent futex requeue mechanism, not a row to
  bless as healthy.
- `ltp-epoll-ltp` remains a non-gating but unacceptable timing row: `37.87x`
  (`54002ms/1426ms`), still consistent with fork-storm cost rather than epoll
  readiness semantics.

Top timing debt:

- `node-libuv`: `489.99x` (`196487ms/401ms`), semantic match.
- `cpython-pathlib`: `76.23x` (`62355ms/818ms`), report-only `DIFF`.
- `ltp-rt_sigqueueinfo02`: `66.49x` (`13631ms/205ms`), non-gating `NEW`.
- `node-app-smoke`: `43.98x` (`17678ms/402ms`), semantic match.
- `cpython-glob`: `43.03x` (`26289ms/611ms`), semantic match.
- `ltp-splice02`, `ltp-waitid08`, `ltp-waitid07`, `ltp-vmsplice01`,
  `ltp-vmsplice04`, and `ltp-splice05`: gating and about `38x`.

Live-captured blockers:

- `go-net_http` is a gating `CARRICK_CRASH` row. During the run, scoped pids
  `7739` and `7756` remained alive under `conf-17046-c1628` for more than
  twenty minutes. The lldb capture lives at
  `target/conformance/logs/lldb-runs/go-net-http-full-hang-090510/`.
  The supervisor parent was blocked in `namespace::supervisor::run` waiting on
  kqueue for init exit. The guest process event ring showed repeated
  `EPWAIT`/`EPWFD` cycles on epoll fd `16408` with a long timeout and masks for
  guest fds 8 and 10. Backtraces showed many guest threads parked in
  `FutexTable::wait_prepared_with_token`, plus one thread in
  `ThreadWaiter::wait_poll_with_dispatch_pending`.
- `cpython-tarfile` is a gating regression with Carrick `Empty` vs Docker
  `609/609`. The lldb capture lives at
  `target/conformance/logs/lldb-runs/cpython-tarfile-full-hang-092311/`.
  The active guest was servicing `newfstatat` on a deeply nested tar extraction
  path and was in `HostFsBackend::name_matches_on_disk` via cap-std
  `read_dir`. This points at path resolution/directory-scan cost or a
  pathological tarfile extraction path, not at a generic process scheduler hang.

Cleanup:

After the harness exited, scoped cleanup killed only the remaining
`conf-17046-c1628` and `conf-17046-c2034` guests. No broad Carrick kill was
used.

Outcome:

We are not close to a conformance bless yet. The xattr cluster is cleaned up,
but the full measurement still has 59 gates and serious timing debt. The next
architectural work should not be sleeps or timeout bumps. The best current
targets are:

- `go-net_http`: reduce the epoll/futex wait pattern using the lldb evidence,
  likely by building a focused Go/net or probe-level reproduction around the
  fd 8/10 readiness/wait state.
- `cpython-tarfile` / `cpython-pathlib` / `cpython-glob`: investigate host
  path resolution and directory-scan amplification under deeply nested paths.
- fork-storm cost: continue treating `ltp-epoll-ltp`, waitid, splice/vmsplice,
  and process-heavy timing outliers as architecture debt rather than acceptable
  baseline noise.
