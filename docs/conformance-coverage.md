# carrick conformance coverage map

**Goal:** every syscall-ABI invariant that matters is gated by a *carrick-owned*
deterministic test — a `conformance-probes/` probe (line-exact carrick-vs-Linux,
run by `cargo test --test conformance`) or a lib unit test — NOT by re-running
LTP. LTP-in-Docker is the **discovery oracle** (slow, count-based, VM-jitter
flaky, needs a registry); it tells us *where to dig*. A probe nails the specific
behavior down so it can never silently regress.

**The rule:** every gap-fix ships with its owning probe/lib-test. The probe is
the deliverable; the LTP MATCH is just confirmation. When you fix something,
add its row here.

**Headline metric:** # of owned invariant tests, and which curated-MATCH LTP
behaviors are still LTP-only (the backlog below).

Legend: ✅ owned by a probe · 🧪 owned by a lib unit test · ⬜ LTP-only (no
carrick test yet — backlog).

## Signals & process control

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| rt_sigaction: install/restore, bad addr→EFAULT, bad sigsetsize→EINVAL, SIGKILL/STOP→EINVAL | ✅ `signals` | rt_sigaction01/02/03, sigaction01/02 |
| rt_sigprocmask block/unblock/read; sigpending membership | ✅ `signals` | rt_sigprocmask01/02, sigpending02 |
| rt_sigtimedwait dequeues an already-pending signal | ✅ `signals` | sigtimedwait01 |
| rt_sigtimedwait with timeout=NULL blocks until a waited signal arrives; fills siginfo; consumes without handler delivery | ✅ `sigwaitblock` | sigwait01, sigwaitinfo01, sigtimedwait01, rt_sigtimedwait01 |
| Self-`raise()` of a caught signal runs the handler before returning | ✅ `selfraise` | signal01–06, kill03 |
| SIGCHLD delivered to a parent handler on child exit; reap still works; SIG_IGN auto-reaps | ✅ `sigchld` | (framework heartbeat; wait4) |
| Cross-process signal (child→parent SIGUSR1) runs handler, not default; Linux↔macOS signum xlate | ✅ `xsignal` | tgkill01, tkill01/02, kill09 |
| Cross-thread signal to a thread blocked in futex/join runs handler | ✅ `xthreadsig` | (Go async-preempt class) |
| Per-thread `sigaltstack` storage (not clobbered across threads) | ✅ `altstacktid` | sigaltstack01 |
| SA_ONSTACK delivery on the alt stack | ✅ `signals`/`altstacktid` | sigaltstack01/02 |
| **SA_RESTART restarts wait4; non-SA_RESTART EINTRs; awaited-child exit never spurious-EINTRs** | ✅ `waitrestart` | (reap blocker — whole tst_test suite) |
| **execve resets caught handlers→SIG_DFL, keeps SIG_IGN, preserves mask + pending; sigaltstack is preserved (empirically, despite man-page wording)** | ✅ `execvereset` + 🧪 `signal::tests::execve_resets_…` | (shell-wrapped tests; pause/kill) |
| **fork: child inherits blocked mask; child pending cleared; parent pending survives** | ✅ `maskfork` | (fork signal semantics) |
| **death-by-signal → wait4 WIFSIGNALED/WTERMSIG; clean exit → WIFEXITED** | ✅ `signalexit` | kill03/06/09 |
| **Pending on unblock: standard coalesces to 1, real-time queues N** | ✅ `pendingunblock` + 🧪 `rt_signals_queue_…` | (RT vs standard delivery) |
| ppoll: blocked signal raised mid-wait does NOT interrupt | ✅ `ppollsig` | ppoll01 |
| **pause(): unblocked signal mid-wait → handler runs, returns -1/EINTR** | ✅ `pauseeintr` | pause01 |
| **sigsuspend(empty): pending blocked sig delivered, handler runs, returns -1/EINTR, original mask restored, pending consumed** | ✅ `pauseeintr` | sigsuspend01 |
| sigprocmask BLOCK/UNBLOCK round-trip (sighold/sigrelse equivalent) | ✅ `pauseeintr` + `signals` | sighold02, sigrelse01 |
| Interval timers (SIGALRM/SIGVTALRM/SIGPROF) fire incl. busy-wait + forked child | ✅ `itimer` | setitimer01/02, getitimer01/02, alarm02–07 |

### Signals — backlog (LTP-only, no carrick probe yet)
- ⬜ `rt_sigqueueinfo01` — self-queue+deliver (ENOSYS stub).
- ⬜ process-group kill: `kill10/11/12` (TIMEOUT), `kill02` self-kill wait-status, `kill05/07`.
- ⬜ `tgkill02/03` invalid-tgid-with-valid-tid; `abort01`.

## fork / clone / process & procfs

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| fork memory isolation (COW) across .data/.bss/heap/mmap | ✅ `forkcow` | (fork correctness) |
| MAP_SHARED coherence across multi-level fork, both directions | ✅ `forkshared` | (tst_checkpoint shared mem) |
| fork+wait4+SIGCHLD/SIGUSR1 + list-walk leaves heap intact; wait status correct | ✅ `forksigwalk` | (shell/framework fork+reap) |
| `/proc/<pid>/{stat,status,cmdline,comm}` + `task/` for descendants; paused child→'S' | ✅ `procstat` | pause02/03, futex_wait03 |
| getpid/getppid/gettid identity | ✅ `procid`, `ppid` | gettid02, getpid* |
| process lifecycle / exit codes / WIFSIGNALED | ✅ `proclife` | (wait4 status) |
| clone basic + thread flags | (LTP) | clone01–09 (mostly MATCH) |

### fork/clone — backlog
- ⬜ `clone301/302/303` clone3 arg validation; `clone05/08`.

## futex / sched

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| Cross-process futex WAIT/WAKE on MAP_SHARED word (`__ulock`) | ✅ `futexshare` | futex_wait02/03, futex_wake02/03 |
| sched affinity / getcpu / hw cpu count | ✅ `cpucount` | sched_getaffinity01, getcpu01/02 |

### sched — backlog (the big ENOSYS cluster)
- ⬜ **POSIX timers** `timer_create/settime/gettime/delete/getoverrun` — all `carrick passed 0` (unregistered). Register → ~7 tests.
- ⬜ **`sched_*`** `get_priority_max/min`, `getparam`, `getscheduler`, `rr_get_interval`, `setparam`, `setscheduler` — all `carrick passed 0` (unregistered). Register → ~7 tests.
- ⬜ `futex_cmp_requeue01` (accepted host limitation), `futex_wake04`, `futex_wait_bitset01`.

## epoll / poll / select / pipe / eventfd

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| epoll_ctl arg validation (EPERM/EINVAL/EBADF), epoll_pwait sigmask/maxevents | ✅ `epollpwait` | epoll_ctl01/02/03/04, epoll_pwait04 |
| epoll readiness/edge/level events | ✅ `pollevent`, `netpoll` | epoll_wait01/04, eventfd01/02/03 |
| eventfd read/write/poll + semaphore mode | ✅ `pollevent` | eventfd01–06, eventfd2_* |
| pipe create/rw/O_NONBLOCK/F_GETPIPE_SZ | ✅ `splicepipe`, `fdio` | pipe01/03/05/06/09/10/11/14 |

### epoll/poll/select — backlog
- ⬜ `epoll_ctl05` EPOLLEXCLUSIVE; `epoll_wait05/06/07`, `epoll_pwait01/02/05`.
- ⬜ `select01/02/03` (TIMEOUT — select-with-timeout wait path), `pselect02`.
- ⬜ `pipe07/08/12/13`, `pipe2_*`.

## fs / mm / time / misc
(Existing probes: `accessx`, `dirops`, `fsmeta`, `fsx`, `linkstat`, `fdstat`,
`fcntlstdio`, `mem`, `memmap`, `mmaprecl`, `hugepage`, `timeclock`, `sysinfo`,
`accounting`, `iouring`, `net`, `netlink_route`, `icmp`, `ptypair`. Map these
to their LTP areas as those areas are swept.)

### time — backlog
- ⬜ `clock_gettime01` (TIMEOUT), `gettimeofday02`/`times03` (TIMEOUT), `clock_settime02`/`clock_adjtime01/02` (need caps; partly fail on Docker too).
