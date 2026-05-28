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

**Currently exposed gaps** (probes whose carrick-vs-Linux diff is non-empty,
listed in `KNOWN_PROBE_GAPS` so the harness stays green while the gap is
tracked here; a probe leaving this list = the gap got fixed):

_None — all four gap-exposing probes added this session have been driven to
zero. The list is intentionally kept around for future gaps._

**Fixed this session** (probes that flipped from gap → MATCH because the
underlying gap got fixed):

| Probe | Fix |
|---|---|
| `schedparam` | Registered sysno 118–121, 125–127 with Linux-conformant constants (proc.rs). |
| `pauseeintr` | Bounded `wait_kqueue` retry to 50 ms even with a signal pipe (io_wait.rs); added Linux's `set_restore_sigmask` analogue to rt_sigsuspend so a pending blocked signal is actually delivered when the temp mask unblocks it. |
| `rtsigqueueinfo` | Read the caller's siginfo in `rt_sigqueueinfo`, queue it via `record_pending_siginfo`, and thread an `Option<LinuxSiginfo>` through `inject_signal` so the SA_SIGINFO handler sees the real `si_value` payload instead of a synthesised SI_USER. |
| `posixtimers` | New `crate::posix_timer` module (per-process timer registry with fallback-thread delivery); wired sysnos 107–111 (`timer_create`/`_gettime`/`_getoverrun`/`_settime`/`_delete`) in dispatch. SIGEV_SIGNAL only; SIGEV_THREAD returns ENOTSUP. |

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
| kill targeting: self / -pgid / 0 broadcasts to current pgrp; kill(bogus,0)→ESRCH; tkill/tgkill arg validation | ✅ `killtarget` | kill02/10/11/12, tkill02, tgkill02/03 |
| Cross-thread signal to a thread blocked in futex/join runs handler | ✅ `xthreadsig` | (Go async-preempt class) |
| Per-thread `sigaltstack` storage (not clobbered across threads) | ✅ `altstacktid` | sigaltstack01 |
| SA_ONSTACK delivery on the alt stack | ✅ `signals`/`altstacktid` | sigaltstack01/02 |
| **SA_RESTART restarts wait4; non-SA_RESTART EINTRs; awaited-child exit never spurious-EINTRs** | ✅ `waitrestart` | (reap blocker — whole tst_test suite) |
| **execve resets caught handlers→SIG_DFL, keeps SIG_IGN, preserves mask + pending; sigaltstack is preserved (empirically, despite man-page wording)** | ✅ `execvereset` + 🧪 `signal::tests::execve_resets_…` | (shell-wrapped tests; pause/kill) |
| **fork: child inherits blocked mask; child pending cleared; parent pending survives** | ✅ `maskfork` | (fork signal semantics) |
| **death-by-signal → wait4 WIFSIGNALED/WTERMSIG; clean exit → WIFEXITED** | ✅ `signalexit` | kill03/06/09 |
| **Pending on unblock: standard coalesces to 1, real-time queues N** | ✅ `pendingunblock` + 🧪 `rt_signals_queue_…` | (RT vs standard delivery) |
| ppoll: blocked signal raised mid-wait does NOT interrupt | ✅ `ppollsig` | ppoll01 |
| **pause(): unblocked signal mid-wait → handler runs, returns -1/EINTR** *(carrick gap exposed: pause() doesn't wake on a setitimer-delivered SIGALRM — TIMEOUT)* | ✅ `pauseeintr` | pause01 |
| **sigsuspend(empty): pending blocked sig delivered, handler runs, returns -1/EINTR, original mask restored, pending consumed** | ✅ `pauseeintr` | sigsuspend01 |
| sigprocmask BLOCK/UNBLOCK round-trip (sighold/sigrelse equivalent) | ✅ `pauseeintr` + `signals` | sighold02, sigrelse01 |
| **rt_sigqueueinfo: queue delivers, handler runs; SA_SIGINFO si_value.sival_int payload reaches the handler** | ✅ `rtsigqueueinfo` | rt_sigqueueinfo01, sigqueue01 |
| Interval timers (SIGALRM/SIGVTALRM/SIGPROF) fire incl. busy-wait + forked child | ✅ `itimer` | setitimer01/02, getitimer01/02, alarm02–07 |

### Signals — backlog (LTP-only, no carrick probe yet)
- ⬜ `kill05/07` (remaining kill-family tests), `abort01`.

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
| POSIX timers: create/settime/gettime remaining/getoverrun/delete + stale-id EINVAL; SIGEV_SIGNAL delivers SIGUSR1 | ✅ `posixtimers` | timer_create01–07, timer_settime01/02, timer_gettime01, timer_delete01, timer_getoverrun01 |
| sched_* invariants: get_priority_{max,min} for OTHER/FIFO/RR; getscheduler→SCHED_OTHER; getparam priority=0; rr_get_interval non-neg | ✅ `schedparam` | sched_get_priority_max01, sched_get_priority_min01, sched_getparam01, sched_getscheduler01, sched_rr_get_interval01, sched_setparam01, sched_setscheduler01 |

### sched — backlog (the big ENOSYS cluster)
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

## fs / metadata / dir

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| access/faccessat/faccessat2 edges under guest-uid=0 (root bypasses rwx; F_OK/R_OK/W_OK/X_OK; AT_EACCESS) | ✅ `accessx` | access01–04, faccessat01/02, faccessat2_* |
| mkdir/rmdir, nested dirs, readdir ordering + content, hard/sym/relative links, dir rename, unlink, getdents-on-cwd | ✅ `dirops` | mkdir01–09, rmdir01–03, readdir01/2, link01–08, symlink01–05, rename01–14, unlink01–08, getdents01/02 |
| stat / lstat / fstat / access / readlink / getcwd-family | ✅ `fsmeta` | stat01–06, lstat01/02, fstat01–05, readlink01–04, getcwd01–04 |
| `fstat(fd) == fstatat(path) == statx(fd, AT_EMPTY_PATH)` (size/mtime/mode/inode all agree — apt-cache regression gate) | ✅ `fdstat` | (apt cross-check; statx vs fstat consistency) |
| readlinkat edge cases + fstat st_mode TYPE bits (regular/dir/symlink/fifo/sock) | ✅ `linkstat` | readlinkat01/02, fstat *_isreg/dir/lnk |
| statfs / fstatfs, utimensat, fadvise64, fallocate, sync/syncfs/fsync/fdatasync, xattr family, faccessat2, readlinkat, chdir+getcwd, mknod/mknodat | ✅ `fsx` | statfs01–03, fstatfs01/02, utimensat01–04, fadvise64_01, fallocate01–06, sync01, syncfs01, fsync01–04, fdatasync01–03, lsetxattr/getxattr/listxattr01, mknod01–09 |
| fcntl(F_GETFL/F_SETFL/F_GETFD/F_SETFD) on stdio (0/1/2) returns the right errnos (the dpkg `fcntl(0, F_SETFL, O_NONBLOCK)→EBADF` regression gate) | ✅ `fcntlstdio` | fcntl01–35, dup01–06 |

## mm (memory management)

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| mmap/mprotect/munmap/mremap/brk/sbrk/madvise/mlock/munlock/msync | ✅ `mem` | mmap01–18, mprotect01–05, munmap01–03, mremap01–05, brk01, madvise01–11, mlock01–05, msync01–04 |
| MAP_SHARED file coherence + mremap-grow preservation (apt DynamicMMap path) | ✅ `memmap` | mmap-shared + apt DynamicMMap |
| Multi-page MAP_SHARED-file alias mappings (16 KiB / 32 KiB) succeed where single-page does (HV_ERROR isolation) | ✅ `aliassize` | (carrick-specific: live file alias HV_ERROR repro) |
| Post-boot `hv_vm_map` via the MapHostAlias high-VA path works in a forked child (>= 1 TiB MAP_FIXED) | ✅ `forkhighva` | (carrick-specific: post-fork high-VA hv_vm_map) |
| `mmap` arena reclaim — touch+free 800 × 64 MiB succeeds without exhausting the 32 GiB arena; reused regions read back zero | ✅ `mmaprecl` | (Go-heap-style arena reuse) |
| MADV_HUGEPAGE / MADV_NOHUGEPAGE return 0 (advisory; allocators must not treat the hint as an error) | ✅ `hugepage` | madvise/THP-hint conformance |

## time (clocks + nanosleep + accounting)

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| clock_gettime/clock_getres/nanosleep/clock_nanosleep/gettimeofday/times/getrusage/time on all supported clocks | ✅ `timeclock` | clock_gettime01–03, clock_getres01, nanosleep01–04, clock_nanosleep01/02, gettimeofday01, times01/02, getrusage01–04, time01 |
| CPU-time + memory accounting non-zero after burning measurable work (getrusage / times / `/proc/self/statm` / `/proc/self/status`) | ✅ `accounting` | (Darwin-sourced rusage/task_info plumbing) |

## process / sys-info / misc

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| uname/sysinfo/getrlimit/prlimit64/prctl/getrandom/sched_getaffinity/sched_yield/getpriority/gettid/umask/getcpu/capget | ✅ `sysinfo` | uname01–04, sysinfo01–03, getrlimit01–03, prlimit64_01–02, prctl01–08, getrandom01–05, sched_getaffinity01, sched_yield01, getpriority01/02, gettid01, umask01–03, getcpu01/02, capget01/02 |

## net / sockets / netlink / pty

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| socket/socketpair/bind/listen/connect/accept/getsockname/setsockopt/getsockopt across AF_UNIX/INET/INET6/NETLINK | ✅ `net` | socket01/02, socketpair01–04, bind01/06, listen01, connect01/02, accept01/04, getsockname01, setsockopt01–10, getsockopt01–07 |
| rtnetlink `RTM_GETROUTE` dump: at least one `RTM_NEWROUTE` followed by `NLMSG_DONE` | ✅ `netlink_route` | (rtnetlink shape conformance) |
| Unprivileged `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` ping socket sends an echo request to loopback | ✅ `icmp` | (unprivileged ICMP / ping_group_range path) |
| pty pair round-trip: posix_openpt → grantpt → unlockpt → ptsname → open slave → write master/read slave (+ reverse) | ✅ `ptypair` | openpt01, grantpt01, ptsname01, posix_openpt01 |

## io_uring

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| Raw io_uring_setup → mmap rings → submit (NOP + WRITE + READ + READV) → io_uring_enter → reap CQEs end-to-end | ✅ `iouring` | (io_uring data path; WS-H4-B1) |
