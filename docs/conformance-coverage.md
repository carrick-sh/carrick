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

**Headline metric** (run `python3 scripts/coverage-metric.py` to recompute —
it parses this doc + the probe binaries on disk and fails CI if the doc cites
a probe that doesn't exist):

```
Owned invariant probes (on disk):  73
Invariant rows with an owning test: 77/77 (100%)
Distinct curated LTP tests owned:   432/432 (100%)
```

This is the number the project tracks INSTEAD of "LTP MATCH count": the probe
suite is the authoritative ABI gate (`cargo test --release --test conformance
conformance_probes`), and the metric answers "how complete is that gate?".
Every curated invariant row and every LTP test it stands in for now has an
owning probe or lib test. New gap-fixes MUST keep this at 100% — the probe is
the deliverable; the LTP MATCH is just confirmation.

Known LTP tests NOT in the curated map (out of scope, tracked in handoff, not
counted above): rt_sigtimedwait01 / sched_getparam01-syscall-variant (LTP
test-variant-switching framework hang), shmat01 (alias-VA reuse semantics),
epoll_pwait2 (syscall 441), clone08 (CLONE_VM-child-stack thread shape).
`futex_cmp_requeue01`: the requeue PRIMITIVE is implemented + probe-owned for
PRIVATE futexes (`futexrequeue` below); the LTP test uses FORKED-CHILD
(cross-process, MAP_SHARED) waiters to test the kernel MECHANISM (are the
requeued waiters actually parked on uaddr2?). carrick's shared/cross-process
path degrades CMP_REQUEUE to wake-all — program-correct (the futex contract
permits spurious wakes; a woken guest re-checks + re-waits) but not
mechanism-exact, so `futex_wake(uaddr2)` finds 0 and the test's
requeue-location assertion fails. A mechanism-exact cross-process requeue
needs a carrick-managed shared redirect registry keyed on the futex word's
stable physical-page identity (each process maps the shared page at a
different host VA, so the per-process `__ulock` host address can't be the
key) — a tracked follow-up, NOT an accepted limitation of the primitive. A
guest-thread RESPAWN bug is also tracked: a Rust guest that spawns a batch of
threads, joins them, then spawns a SECOND batch aborts the second batch with
"current thread handle already set during thread spawn" (Rust std detecting a
new thread's `#[thread_local] CURRENT` is already populated). Minimal repro:
`batch(3); batch(3)` — batch 1 runs, batch 2 aborts. `carrick trace` shows
batch-2 threads get FRESH, distinct TLS addresses (0x…208b78 vs batch-1's
0x…207b78), so it is NOT literal same-address TLS reuse; the recycled TLS
block's `.tbss` (where CURRENT lives) isn't reaching the new thread zeroed,
or the child runs with a stale tpidr_el0. A deep guest-TLS-lifecycle /
CLONE_VM-thread-teardown investigation — tracked, not yet fixed (the
`futexrequeue` probe sidesteps it with a single threaded round).

Legend: ✅ owned by a probe · 🧪 owned by a lib unit test · ⬜ LTP-only (no
carrick test yet — backlog).

**Currently exposed gaps** (probes whose carrick-vs-Linux diff is non-empty,
listed in `KNOWN_PROBE_GAPS` so the harness stays green while the gap is
tracked here; a probe leaving this list = the gap got fixed):

_None — all four gap-exposing probes added this session have been driven to
zero. The list is intentionally kept around for future gaps._

**Backfilled** (probes added to gate previously-landed-but-unguarded fixes):

| Probe | Gates |
|---|---|
| `sysvshm` | SysV shared memory: shmget(IPC_PRIVATE,…) → shmid; shmat returns a mapped address; r/w roundtrip; cross-process coherence after fork; shmdt returns 0; shmctl(IPC_RMID) returns 0. Backed by host files under `/tmp/carrick-shm/` so forked guests see the same inode (LTP `kill07` MATCH; `kill05` advances past the prior `shmget ENOSYS` TBROK). |
| `killuidperm` | `kill(2)` permission model: root → other-uid is allowed; non-root cross-uid returns -1/EPERM; non-root same-uid is allowed. Backed by per-process `/tmp/carrick-cred-<host_pid>` so a peer carrick process publishes the euid the kill check reads (LTP `kill05` MATCH 1/1). |
| `rtsigqueueinfoxthread` | rt_sigqueueinfo(sibling_tid, SIGUSR1, &info) delivers the signal to the sibling thread's SA_SIGINFO handler and propagates si_value — the LTP `rt_sigqueueinfo01` shape (now MATCHing 2/2 assertions after route_thread_signal routing in rt_sigqueueinfo). |
| `futexwakecount` | `FUTEX_WAKE(INT_MAX)` returns EXACTLY N when N waiters are parked on a MAP_SHARED word — the `sched_yield` between `__ulock_wake_any` iterations invariant from commit 3c6c711 (and the no-phantom-counts invariant from commit e0dd202). Stands in for LTP `futex_wake03`. |
| `coredumpbit` | `WCOREDUMP(status)` is TRUE for the Linux core-dumping signal set (SIGABRT/SIGSEGV/SIGQUIT/…) and FALSE for non-core signals (SIGTERM/SIGKILL). Synthesizes the 0x80 bit even though macOS's default RLIMIT_CORE=0 suppresses it on the host wait status — commit 0b55501. Stands in for LTP `abort01`. |
| `unlinkatbindmount` | `unlinkat(AT_FDCWD, "/dev/shm/<f>", 0)` removes a file created via the same bind-mounted path. Mirrors openat's vfs_mounts.resolve routing for unlink/unlinkat (commit 063ccf4) — without this, every `tst_checkpoint`-using LTP test TBROKs at setup_ipc. |
| `reparenttoinit` | Double-fork orphans a grandchild; after the intermediate parent exits, `getppid()` in the orphan returns 1 (the PID-namespace init). Process-tree mirror must reparent on the macOS host the same way Linux does in its PID namespace. Stands in for LTP `getpid01`. |
| `prctldumpable` | `PR_SET_DUMPABLE`/`PR_GET_DUMPABLE` round-trip: initial=1, set 0→get 0, set 1→get 1, set 2 returns OBSERVED rc/errno (newer kernels reject with EINVAL — probe records the tuple), set 99→EINVAL. Stands in for LTP `prctl04`/`prctl08`. |
| `waitidspec` | `waitid(2)` siginfo encoding: CLD_EXITED+si_status, CLD_KILLED+si_status==SIGKILL, WNOWAIT peek-then-reap leaves the zombie, P_ALL+WNOHANG→ECHILD with no children. Distinct ABI from wait4 (covered by `proclife`/`waitrestart`). Stands in for LTP `waitid01`/`waitid02`/`waitid03`. |

**Fixed this session** (probes that flipped from gap → MATCH because the
underlying gap got fixed):

| Probe | Fix |
|---|---|
| `schedparam` | Registered sysno 118–121, 125–127 with Linux-conformant constants (proc.rs). |
| `pauseeintr` | Bounded `wait_kqueue` retry to 50 ms even with a signal pipe (io_wait.rs); added Linux's `set_restore_sigmask` analogue to rt_sigsuspend so a pending blocked signal is actually delivered when the temp mask unblocks it. |
| `rtsigqueueinfo` | Read the caller's siginfo in `rt_sigqueueinfo`, queue it via `record_pending_siginfo`, and thread an `Option<LinuxSiginfo>` through `inject_signal` so the SA_SIGINFO handler sees the real `si_value` payload instead of a synthesised SI_USER. |
| `posixtimers` | New `crate::posix_timer` module (per-process timer registry with fallback-thread delivery); wired sysnos 107–111 (`timer_create`/`_gettime`/`_getoverrun`/`_settime`/`_delete`) in dispatch. SIGEV_SIGNAL only; SIGEV_THREAD returns ENOTSUP. |
| `selecttimeout` | pselect6 empty-fds path now goes through `WaitOnFds` instead of a raw `libc::nanosleep` so SIGALRM EINTRs the wait; added Linux's `sigset_argpack` decode + a `block_signals` bitmask so the sigmask arg actually gates which signals interrupt the wait. |
| `clone3args` | Strict arg validation in `dispatch::SyscallDispatcher::clone3`: `args_size` must be one of CLONE_ARGS_SIZE_VER0/1/2 (64/80/88); unknown flag bits (outside the 0x100..0x4_0000_0000 range) → EINVAL; mismatched `stack`/`stack_size` pair → EINVAL. Before: any bogus clone3 silently forked, creating an exponential fork-bomb in the rest of the probe. |
| `epollexclusive` | (1) Detect "kqueue drained but all events filtered out by user mask" and switch to a signal-pipe-only sleep so polling kq_fd doesn't tight-loop. (2) Honor an empty interest set: `epoll_pwait(epfd, …, timeout)` with no fds added now sleeps the timeout (interruptible by signals) instead of returning 0 immediately. (3) Implement EPOLLONESHOT: after the first delivery the interest is disarmed (events cleared, host kqueue filter removed) until `EPOLL_CTL_MOD` re-arms it. Added the LINUX_EPOLLONESHOT / LINUX_EPOLLEXCLUSIVE constants. |
| `pipeextra` | (1) `pipe2(O_DIRECT)` accepted as a no-op flag (Darwin pipes don't have packet mode but the regular-pipe write-then-read subset matches; aarch64 O_DIRECT is 0o200000, NOT the asm-generic 0o40000 — checking the wrong value silently rejected every probe). (2) `ioctl(FIONREAD)` on a HostPipe / HostSocket forwards to the host fd so the guest sees the kernel's actual queued-byte count (was hardcoded 0). |

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
| **A blocking `waitpid(A)` is NOT interrupted by a sibling child B's default-ignore SIGCHLD (no handler → delivered-and-dropped → no EINTR); a SIGCHLD HANDLER without SA_RESTART DOES interrupt (EINTR). The dispatcher folds blocked + effectively-ignored signals into the wait's no-interrupt mask** | ✅ `waitsiblingsigchld` | futex_cmp_requeue01 / any multi-child SAFE_WAITPID reap |
| **execve resets caught handlers→SIG_DFL, keeps SIG_IGN, preserves mask + pending; sigaltstack is preserved (empirically, despite man-page wording)** | ✅ `execvereset` + 🧪 `signal::tests::execve_resets_…` | (shell-wrapped tests; pause/kill) |
| **fork: child inherits blocked mask; child pending cleared; parent pending survives** | ✅ `maskfork` | (fork signal semantics) |
| **death-by-signal → wait4 WIFSIGNALED/WTERMSIG; clean exit → WIFEXITED** | ✅ `signalexit` | kill03/06/09 |
| **Pending on unblock: standard coalesces to 1, real-time queues N** | ✅ `pendingunblock` + 🧪 `rt_signals_queue_…` | (RT vs standard delivery) |
| ppoll: blocked signal raised mid-wait does NOT interrupt | ✅ `ppollsig` | ppoll01 |
| **pause(): unblocked signal mid-wait → handler runs, returns -1/EINTR** *(carrick gap exposed: pause() doesn't wake on a setitimer-delivered SIGALRM — TIMEOUT)* | ✅ `pauseeintr` | pause01 |
| **sigsuspend(empty): pending blocked sig delivered, handler runs, returns -1/EINTR, original mask restored, pending consumed** | ✅ `pauseeintr` | sigsuspend01 |
| sigprocmask BLOCK/UNBLOCK round-trip (sighold/sigrelse equivalent) | ✅ `pauseeintr` + `signals` | sighold02, sigrelse01 |
| **rt_sigqueueinfo: queue delivers, handler runs; SA_SIGINFO si_value.sival_int payload reaches the handler** | ✅ `rtsigqueueinfo` | rt_sigqueueinfo01, sigqueue01 |
| **rt_sigqueueinfo(sibling_tid, …): routes to a sibling thread of the same process (not just self/peer-pid); the sibling's SA_SIGINFO handler runs and the si_value payload propagates** | ✅ `rtsigqueueinfoxthread` | rt_sigqueueinfo01 (the canonical thread-target shape) |
| **rt_tgsigqueueinfo (syscall 240, was ENOSYS): queue a signal with a caller siginfo to a specific (tgid, tid); the target's SA_SIGINFO handler runs and the si_value payload propagates — same delivery machinery as rt_sigqueueinfo but keyed on the explicit tid** | ✅ `tgsigqueue` | rt_tgsigqueueinfo01 (self / sibling / parent-thread legs) |
| **get_robust_list (syscall 100, was ENOSYS) + set_robust_list len validation: set_robust_list rejects len != sizeof(robust_list_head)=24 → EINVAL; get_robust_list gives EFAULT on NULL head/len ptr, ESRCH for a nonexistent pid, EPERM for another live task, and succeeds for self (carrick has no robust-futex death cleanup, so the head is reported empty — errno/return contract only)** | ✅ `robustlist` | set_robust_list01, get_robust_list01 (EPERM leg gated by the LTP test, not the probe — see probe note) |
| Interval timers (SIGALRM/SIGVTALRM/SIGPROF) fire incl. busy-wait + forked child | ✅ `itimer` | setitimer01/02, getitimer01/02, alarm02–07 |
| **Default-disposition death-by-signal: SIGTERM/SIGKILL kill child→WIFSIGNALED/WTERMSIG; abort() resets SIGABRT→SIG_DFL and re-raises** | ✅ `abortdeath` | kill05, kill07, abort01 |
| **`WCOREDUMP(status)` set for core-dumping signals (SIGABRT/SIGSEGV/SIGQUIT/SIGILL/SIGTRAP/SIGBUS/SIGFPE/SIGXCPU/SIGXFSZ/SIGSYS), unset for non-core signals (SIGTERM/SIGKILL) — 0x80 bit synthesized through macOS's default RLIMIT_CORE=0** | ✅ `coredumpbit` | abort01 |
| **signalfd4 (syscall 74, emulated — macOS has no signalfd): SFD_CLOEXEC→FD_CLOEXEC, SFD_NONBLOCK→O_NONBLOCK on the returned fd, unknown flag bit→EINVAL (fd-flag surface only; signal-read delivery is a tracked follow-up)** | ✅ `signalfd4` | signalfd4_01, signalfd4_02 |

### Signals — backlog (LTP-only, no carrick probe yet)
- _(none — all signals-backlog rows are owned by probes)_

## fork / clone / process & procfs

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| **/proc/self/status Pid/Tgid agree with getpid()/gettid() (carrick hardcoded Pid:1 while getpid returned process::id())** | ✅ `procselfpid` | gettid01 |
| **waitpid error edges: pid<-1 naming a nonexistent process group → ESRCH (carrick forwarded to the host which gives EINVAL); invalid options → EINVAL; no children → ECHILD** | ✅ `waitpgid` | waitpid04 |
| fork memory isolation (COW) across .data/.bss/heap/mmap | ✅ `forkcow` | (fork correctness) |
| MAP_SHARED coherence across multi-level fork, both directions | ✅ `forkshared` | (tst_checkpoint shared mem) |
| fork+wait4+SIGCHLD/SIGUSR1 + list-walk leaves heap intact; wait status correct | ✅ `forksigwalk` | (shell/framework fork+reap) |
| `/proc/<pid>/{stat,status,cmdline,comm}` + `task/` for descendants; paused child→'S' | ✅ `procstat` | pause02/03, futex_wait03 |
| getpid/getppid/gettid identity | ✅ `procid`, `ppid` | gettid02, getpid* |
| **Orphan child (double-fork) is reparented to PID 1 in its PID namespace; orphan's `getppid()` returns 1** | ✅ `reparenttoinit` | getpid01 (orphan-reparent), classical daemonize idiom |
| process lifecycle / exit codes / WIFSIGNALED | ✅ `proclife` | (wait4 status) |
| **`waitid(2)` siginfo encoding: CLD_EXITED/CLD_KILLED + si_status; WNOWAIT peek-then-reap; P_ALL+WNOHANG→ECHILD when no children** | ✅ `waitidspec` | waitid01, waitid02, waitid03 |
| **clone basic + thread-flag validation: `clone(SIGCHLD)` forks (positive pid parent / 0 child / clean reap); `clone(CLONE_THREAD)` without CLONE_VM\|CLONE_SIGHAND → EINVAL (kernel flag-consistency: THREAD→SIGHAND→VM)** | ✅ `clonebasic` | clone01–04, clone06, clone08 (negative shape) |
| **clone3 arg validation: happy path returns child pid + clean reap; truncated `size`, unknown flag bit, inconsistent stack/stack_size pair each rejected (EINVAL on real Linux, ENOSYS under Docker default seccomp)** | ✅ `clone3args` | clone301, clone302, clone303, clone05, clone08 |

### fork/clone — backlog
- _(none — clone3 arg-validation backlog is owned by `clone3args`)_

## futex / sched

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| Cross-process futex WAIT/WAKE on MAP_SHARED word (`__ulock`) | ✅ `futexshare` | futex_wait02/03, futex_wake02/03 |
| **`FUTEX_WAKE(INT_MAX)` returns exactly N when N waiters are parked on a MAP_SHARED word — `__ulock_wake_any` lock-structure zombie window neutralised by sched_yield between iterations** | ✅ `futexwakecount` | futex_wake03 |
| **Diagnostic: `FUTEX_WAKE` on a fresh MAP_SHARED page with no waiters returns 0 (no phantom counts)** | ✅ `futexghost` | (no LTP equiv — repro for e0dd202) |
| sched affinity / getcpu / hw cpu count | ✅ `cpucount` | sched_getaffinity01, getcpu01/02 |
| POSIX timers: create/settime/gettime remaining/getoverrun/delete + stale-id EINVAL; SIGEV_SIGNAL delivers SIGUSR1 | ✅ `posixtimers` | timer_create01–07, timer_settime01/02, timer_gettime01, timer_delete01, timer_getoverrun01 |
| sched_* invariants: get_priority_{max,min} for OTHER/FIFO/RR; getscheduler→SCHED_OTHER; getparam priority=0; rr_get_interval non-neg | ✅ `schedparam` | sched_get_priority_max01, sched_get_priority_min01, sched_getparam01, sched_getscheduler01, sched_rr_get_interval01, sched_setparam01, sched_setscheduler01 |
| **sched_get/setparam/rr_get_interval accept ANY live pid (not just self): the calling process can query any task's params, mirroring Linux's task-wide read access (via the sched_pid_exists kill(pid,0) check)** | ✅ `schedparam` | sched_setparam01 (MATCH), sched_getparam01 libc variant (4/4 PASS) |
| **sched_{getscheduler,getparam,setparam,setscheduler} negative-pid→EINVAL; sched_setscheduler bad-param-ptr→EFAULT (before priority validation); getpriority bad-which→EINVAL; get/setpriority negative-who→ESRCH (all PRIO_* classes)** | ✅ `schedprio` | sched_getparam03, sched_setparam04, sched_setscheduler01, getpriority02 (setpriority02 negative-who half; its EACCES/EPERM cases need a fuller priority/uid model — follow-up) |
| **nice value model: setpriority(PRIO_PROCESS, self) persists a per-process nice CLAMPED to [-20,19] (out-of-range is clamped, NOT EINVAL — glibc nice() relies on this); getpriority reflects it as `20 - nice`; a non-root euid lowering nice below current → EPERM** | ✅ `nicepriority` | nice02 (clamp), nice03 (persist), nice04 (non-root EPERM — gated by the LTP test, which drops to nobody; the probe runs privileged) |

| FUTEX_WAIT / FUTEX_WAIT_BITSET on mismatched expected → EAGAIN; FUTEX_WAKE with no waiters → 0; cross-thread wait/wake round-trip on a private futex | ✅ `futexextra` | futex_wait02 (mismatch), futex_wake04, futex_wait_bitset01 |
| **FUTEX_CMP_REQUEUE / FUTEX_REQUEUE on a private futex: CMP_REQUEUE(nr_wake=1, INT_MAX) over N waiters wakes 1 + requeues N-1 (returns N); a WAKE(uaddr1) after drains to 0 (the rest really left); a WAKE(uaddr2) reaches the N-1 requeued; val3 mismatch → EAGAIN; negative count → EINVAL; empty REQUEUE → 0. Implemented over `parking_lot_core::unpark_requeue` (the primitive Darwin `__ulock` lacks); shared/cross-process futexes degrade to wake-all (correct per the spurious-wake-tolerant futex contract)** | ✅ `futexrequeue` | futex_cmp_requeue01 (requeue primitive — returns the correct 3+7=10; the test's residual TBROK is an unrelated waitpid-EINTR-restart gap) |

### sched — backlog (the big ENOSYS cluster)
- _(none — FUTEX_(CMP_)REQUEUE is now implemented + owned by `futexrequeue`)_

## epoll / poll / select / pipe / eventfd

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| epoll_ctl arg validation (EPERM/EINVAL/EBADF), epoll_pwait sigmask/maxevents | ✅ `epollpwait` | epoll_ctl01/02/03/04, epoll_pwait04 |
| epoll readiness/edge/level events | ✅ `pollevent`, `netpoll` | epoll_wait01/04, eventfd01/02/03 |
| TCP urgent data registered through epoll wakes as `EPOLLPRI` and remains readable via `recv(MSG_OOB)` | ✅ `epollpri` | libuv `poll_oob` |
| eventfd read/write/poll + semaphore mode | ✅ `pollevent` | eventfd01–06, eventfd2_* |
| pipe create/rw/O_NONBLOCK/F_GETPIPE_SZ | ✅ `splicepipe`, `fdio` | pipe01/03/05/06/09/10/11/14 |
| **select/pselect timeout & wakeup: bare-timeout rc==0, ready-pipe rc==1 with bit set, not-ready rc==0; pselect sigmask blocks→signal stays pending and times out; sigmask=NULL→alarm interrupts with EINTR** | ✅ `selecttimeout` | select01, select02, select03, pselect02 |
| **select/pselect6 argument validation: `nfds < 0` → EINVAL (validated FIRST, before the empty-fd-set NULL-timeout path that previously blocked the caller forever); an invalid `timeout` timespec (negative sec/nsec, or nsec ≥ 1e9) → EINVAL (was clamped to 0). Fixes the pselect02 child hang that the tst_test watchdog SIGALRM-killed → TBROK.** | ✅ `selectnfds` | pselect02 (+_64), select03 (negative-nfds + invalid-timeout legs) |
| **epoll edge/oneshot/exclusive + pwait sigmask: EPOLL_CLOEXEC create, EPOLLEXCLUSIVE add, double-ADD→EEXIST, ADD events=0 silent until MOD, EPOLLET fires-once-per-edge, EPOLLONESHOT disarms until MOD rearm, pwait sigmask blocks SIGALRM through wait, NULL mask EINTRs** | ✅ `epollexclusive` | epoll_ctl05, epoll_wait05, epoll_wait06, epoll_wait07, epoll_pwait01, epoll_pwait02, epoll_pwait05 |
| **pipe / pipe2 edges: pipe2(O_NONBLOCK / O_CLOEXEC / O_DIRECT) propagate to both fds; FIONREAD matches written bytes; non-blocking write past capacity → EAGAIN; closed-write-end read → 0 (EOF); closed-read-end write → -1/EPIPE (SIGPIPE caught)** | ✅ `pipeextra` | pipe07, pipe08, pipe12, pipe13, pipe2_01, pipe2_02, pipe2_03 |

### epoll/poll/select — backlog
- _(none — all pipe / epoll / pwait backlog rows are owned by probes)_

## fs / metadata / dir

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| **directory-modify DAC: an unprivileged guest (euid≠0) can mkdir/rmdir/unlink an entry only in a dir it has write+search on (else EACCES); a sticky (S_ISVTX) dir additionally requires owning the entry or the dir to remove (else EPERM). Root (CAP_DAC_OVERRIDE) bypasses — the default root guest + demos are unaffected** | ✅ `dirdac` | mkdir04, rmdir03, unlink08, symlink03 |
| access/faccessat/faccessat2 edges under guest-uid=0 (root bypasses rwx; F_OK/R_OK/W_OK/X_OK; AT_EACCESS) | ✅ `accessx` | access01–04, faccessat01/02, faccessat2_* |
| **O_DIRECTORY on a non-directory → ENOTDIR; on a directory → success; O_RDWR on a directory → EISDIR. Fixed the swapped aarch64 fcntl constants (O_DIRECTORY=0o40000 not 0o200000=O_DIRECT; O_NOFOLLOW=0o100000 not 0o400000) — O_DIRECTORY had never triggered the must-be-a-dir check** | ✅ `odirectory` | open08 (O_NOFOLLOW→ELOOP enforcement is a tracked follow-up; the constant is now correct so the flag is detected) |
| **preadv on a write-only (O_WRONLY) fd → EBADF (reads the fd, so it must be open for reading); a readable fd returns the bytes** | ✅ `preadvwronly` | preadv02/preadv02_64/preadv202/preadv202_64 (the "not open for reading" case) |
| **read(2) on a regular file opened write-only (O_WRONLY) → EBADF; a readable fd returns the bytes (only regular-file descriptions carry O_ACCMODE — pipes/sockets/eventfds keep their per-branch rules)** | ✅ `readwronly` | open09, creat01 |
| **fchmod on a directory fd persists the mode so a subsequent fstat on the same fd reflects it (sticky/setgid/plain). carrick reported a Directory fd's cached open-time mode; fchmod now refreshes the open description's cached metadata (HostFile already re-reads the live xattr)** | ✅ `fchmoddir` | fchmod04, fchmod05 |
| **A relative path resolved against a dirfd that is a valid but non-directory fd (e.g. stdout) → ENOTDIR; a genuinely-invalid dirfd → EBADF. carrick gave EBADF for a valid stdio dirfd (not in its open-file table); resolve_at_path now returns ENOTDIR when the fd is valid-but-non-dir** | ✅ `dirfdnotdir` | statx03 |
| **write to a broken pipe (read end closed) → EPIPE AND raises SIGPIPE on the writer (handler runs once; SIG_DFL terminates; SIG_IGN → just EPIPE, no handler). carrick returned EPIPE without the signal** | ✅ `sigpipewrite` | write05 (HostPipe; the socket-EPIPE→SIGPIPE leg is a tracked follow-up to avoid demo risk) |
| **chmod setgid-clear: an unprivileged owner whose egid ≠ the file's group cannot set S_ISGID (chmod succeeds, bit stripped); fchmodat2 (nr 452) rejects an unknown flag bit with EINVAL (plain fchmodat nr 53 ignores the flags register — apt relies on it)** | ✅ `chmodsetgid` | chmod05, fchmodat02, fchmodat2_02 (fchmod04/05 fd-on-dir mode persistence + mkdir02/04 gid inheritance remain) |
| mkdir/rmdir, nested dirs, readdir ordering + content, hard/sym/relative links, dir rename, unlink, getdents-on-cwd | ✅ `dirops` | mkdir01–09, rmdir01–03, readdir01/2, link01–08, symlink01–05, rename01–14, unlink01–08, getdents01/02 |
| **setgid-directory inheritance: a dir created in an S_ISGID parent inherits the parent's GID and itself gets S_ISGID (carrick used the creator's egid and dropped S_ISGID)** | ✅ `mkdirsetgid` | mkdir02 (mkdir04 = mkdir-in-non-writable-parent→EACCES, the deferred DAC/guest-root class) |
| **`unlinkat(AT_FDCWD, "/dev/shm/<f>", 0)` removes a file created via the same bind-mounted path; both unlinkat and libc::unlink route through `vfs_mounts.resolve` (parallels openat) — the LTP `tst_checkpoint` setup_ipc unblocker** | ✅ `unlinkatbindmount` | (tst_test setup_ipc; ~10 SIGNALS-area tests) |
| stat / lstat / fstat / access / readlink / getcwd-family | ✅ `fsmeta` | stat01–06, lstat01/02, fstat01–05, readlink01–04, getcwd01–04 |
| `fstat(fd) == fstatat(path) == statx(fd, AT_EMPTY_PATH)` (size/mtime/mode/inode all agree — apt-cache regression gate) | ✅ `fdstat` | (apt cross-check; statx vs fstat consistency) |
| readlinkat edge cases + fstat st_mode TYPE bits (regular/dir/symlink/fifo/sock) | ✅ `linkstat` | readlinkat01/02, fstat *_isreg/dir/lnk |
| statfs / fstatfs, utimensat, fadvise64, fallocate, sync/syncfs/fsync/fdatasync, xattr family (incl. **removexattr** round-trip: remove→0, get-after-remove/remove-absent→ENODATA, remove-nonexistent-path→ENOENT), faccessat2, readlinkat, chdir+getcwd, mknod/mknodat | ✅ `fsx` | statfs01–03, fstatfs01/02, utimensat01–04, fadvise64_01, fallocate01–06, sync01, syncfs01, fsync01–04, fdatasync01–03, lsetxattr/getxattr/listxattr01, removexattr01/02, mknod01–09 |
| **flock(2) real advisory locking: an exclusive lock on one fd makes a second independent fd's LOCK_NB exclusive request EAGAIN, reacquirable after LOCK_UN; bad fd→EBADF (host-forwarded so cross-process/fork-shared conflicts are real). Bad-operation→EINVAL matches mainline Linux but the Docker LinuxKit kernel disagrees, so it's carrick-correct but not probe-asserted.** | ✅ `flocklock` | flock04, flock06 |
| fcntl(F_GETFL/F_SETFL/F_GETFD/F_SETFD) on stdio (0/1/2) returns the right errnos (the dpkg `fcntl(0, F_SETFL, O_NONBLOCK)→EBADF` regression gate) | ✅ `fcntlstdio` | fcntl01–35, dup01–06 |
| **pidfd_open sets FD_CLOEXEC; posix_fadvise out-of-range advice→EINVAL + pipe(FIFO)→ESPIPE; ftruncate read-only fd→EINVAL (not EBADF); a freshly `O_RDONLY\|O_CREAT`'d file is a non-writable fd (guest writability follows the access mode, not O_CREAT); fsync/fdatasync on a pipe/socket/char-device→EINVAL (dir/regular unaffected)** | ✅ `cluster10errno` | pidfd_open01, posix_fadvise03, posix_fadvise04, ftruncate03, fdatasync01/02 |
| **fcntl file leases (F_SETLEASE/F_GETLEASE, recorded per open-file-description): O_RDONLY read-lease round-trip RDLCK↔UNLCK; bad lease type→EINVAL; F_RDLCK on a write-capable fd→EAGAIN (fcntl32 cross-process F_WRLCK conflict deferred — needs inode-wide opener count)** | ✅ `fcntllease` | fcntl23–27 (+_64) |
| **F_GETLK with no conflicting lock leaves the caller's `struct flock` UNCHANGED except `l_type = F_UNLCK` — `l_pid`/`l_whence`/`l_start`/`l_len` keep the caller's input (was rewriting the whole struct from the macOS flock, zeroing `l_pid`)** | ✅ `fcntlgetlk` | fcntl05 (+_64) (fcntl13/15/17 F_SETLK-conflict + cross-process locking deferred) |
| **positional/vector read on a special fd: pread on a pipe→ESPIPE, pread/readv on a directory→EISDIR (was EINVAL); pread on a regular file unaffected** | ✅ `preadspecial` | pread02 (+_64), readv02 (preadv02/202 negative-offset/iovec residual deferred) |
| **zero-length write never accesses the buffer: `write`/`pwrite(fd, NULL, 0)`→0 (not EFAULT); a `{NULL, 0}` iovec segment in `pwritev` is a permitted no-op. carrick was validating the guest buffer regardless of length (`read_bytes(NULL,0)`→EFAULT); now skips the read when len==0** | ✅ `zerolenio` | pwrite03 (+_64), pwritev01 (+_64), pwritev201 (+_64), write02 (pwrite04 O_APPEND-offset + write05 residual deferred) |
| **sendfile access-mode validation: a write-only (O_WRONLY) in_fd → EBADF (sendfile READS the source); read-only out_fd → EBADF; valid O_RDONLY→O_WRONLY transfer returns the byte count. carrick read the source regardless of the guest in_fd access mode** | ✅ `sendfilebadf` | sendfile03 (+_64) (sendfile04/06/09 data-transfer/offset assertions deferred) |
| **`memfd_create(name, flags)` (nr 279, was ENOSYS→TCONF): creates an anonymous in-memory writable file (O_TMPFILE shape); MFD_CLOEXEC→FD_CLOEXEC, MFD_ALLOW_SEALING accepted; flag/name validation — unknown flag bit→EINVAL, NULL name→EFAULT, name>249 (MFD_NAME_MAX_LEN)→EINVAL** | ✅ `memfdcreate` | memfd_create02 (memfd_create01 needs fcntl F_ADD_SEALS file sealing — deferred) |
| **`sync_file_range(fd, offset, nbytes, flags)` (nr 84, was ENOSYS): validating advisory range flush — unknown flags / negative offset / negative nbytes (or offset+nbytes overflow) → EINVAL; bad fd → EBADF; pipe/socket/anon fd → ESPIPE; regular file → best-effort host flush, return 0** | ✅ `syncfilerange` | sync_file_range01 |
| **`cachestat(fd, range, cstat, flags)` (nr 451, was ENOSYS): reports in-range in-file pages as nr_cache (rest 0) — satisfies LTP cachestat02's `nr_cache+nr_evicted==num_pages` invariant; flags≠0→EINVAL, bad/non-cache fd→EBADF, bad ptr→EFAULT. Probe asserts only the oracle-agreed validation (the page-count sum is Docker-LinuxKit-fs-sensitive, gated by the LTP test)** | ✅ `cachestatpages` | cachestat02 |
| **openat2 open_how validation: normal O_RDWR\|O_CREAT open succeeds (flags+mode passed through, no longer whitelisted); mode-without-O_CREAT / mode>0o7777 / unknown-resolve-bits / size<sizeof → EINVAL; size>sizeof zero-pad accepted, nonzero-pad→E2BIG; bad dirfd→EBADF** | ✅ `openat2valid` | openat201, openat203 (openat202 RESOLVE_* path enforcement deferred) |
| **functional FIFO (named pipe): `mknod(S_IFIFO)` creates a real `mkfifoat` node that stats as `S_IFIFO` with the umask-adjusted mode; opening it (RDONLY/WRONLY/RDWR) opens the host FIFO NON-BLOCKING and wraps it as a `HostPipe` so a writer-less open can't wedge the single dispatcher (guest blocking routes through the kqueue `WaitOnFds` park); an `O_RDWR` FIFO is bidirectional (new `HostPipe.bidirectional`); select reports writable-when-empty + readable-after-write; `mknod(S_IFMT)`→EINVAL, device/socket type→EPERM. All FIFO metadata reads (`real_stat`/`metadata`/`get_owner`/`set_mode`) are path-based (fstatat/fchmodat) — never open the node, since an O_RDONLY open of a writer-less FIFO blocks.** | ✅ `fifonode` | select01–04, pselect01–03 (FIFO leg), mknod01–09, mknodat01/02 |

## mm (memory management)

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| mmap/mprotect/munmap/mremap/brk/sbrk/madvise/mlock/munlock/msync | ✅ `mem` | mmap01–18, mprotect01–05, munmap01–03, mremap01–05, brk01, madvise01–11, mlock01–05, msync01–04 |
| MAP_SHARED file coherence + mremap-grow preservation (apt DynamicMMap path) | ✅ `memmap` | mmap-shared + apt DynamicMMap |
| Multi-page MAP_SHARED-file alias mappings (16 KiB / 32 KiB) succeed where single-page does (HV_ERROR isolation) | ✅ `aliassize` | (carrick-specific: live file alias HV_ERROR repro) |
| Post-boot `hv_vm_map` via the MapHostAlias high-VA path works in a forked child (>= 1 TiB MAP_FIXED) | ✅ `forkhighva` | (carrick-specific: post-fork high-VA hv_vm_map) |
| `mmap` arena reclaim — touch+free 800 × 64 MiB succeeds without exhausting the 32 GiB arena; reused regions read back zero | ✅ `mmaprecl` | (Go-heap-style arena reuse) |
| MADV_HUGEPAGE / MADV_NOHUGEPAGE return 0 (advisory; allocators must not treat the hint as an error) | ✅ `hugepage` | madvise/THP-hint conformance |
| **mmap/munmap errno ordering + behavior: a file mapping on a bad fd → EBADF even when length is also invalid (Linux `fget` precedes `do_mmap`, so EBADF beats EINVAL); munmap of a MAP_SHARED-file mapping (a high-VA alias) succeeds; munmap requires a page-aligned address (else EINVAL) and rejects out-of-address-space ranges with EINVAL** | ✅ `mmapmunmap` | mmap08 (len-0 bad-fd→EBADF), munmap01/02 (unmap a valid MAP_SHARED/MAP_PRIVATE file region), munmap03 (unaligned addr / len 0 / out-of-range → EINVAL) |

## time (clocks + nanosleep + accounting)

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| clock_gettime/clock_getres/nanosleep/clock_nanosleep/gettimeofday/times/getrusage/time on all supported clocks | ✅ `timeclock` | clock_gettime01–03, clock_getres01, nanosleep01–04, clock_nanosleep01/02, gettimeofday01, times01/02, getrusage01–04, time01 |
| CPU-time + memory accounting non-zero after burning measurable work (getrusage / times / `/proc/self/statm` / `/proc/self/status`) | ✅ `accounting` | (Darwin-sourced rusage/task_info plumbing) |
| **clock_gettime/getres positivity + monotonic nondecreasing across a busy-wait; gettimeofday/times nonneg; unprivileged clock_settime/clock_adjtime → EPERM (no CAP_SYS_TIME)** | ✅ `timeextra` | clock_gettime01 (TIMEOUT), gettimeofday02, times03, clock_settime02, clock_adjtime01/02 |

## process / sys-info / misc

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| uname/sysinfo/getrlimit/prlimit64/prctl/getrandom/sched_getaffinity/sched_yield/getpriority/gettid/umask/getcpu/capget | ✅ `sysinfo` | uname01–04, sysinfo01–03, getrlimit01–03, prlimit64_01–02, prctl01–08, getrandom01–05, sched_getaffinity01, sched_yield01, getpriority01/02, gettid01, umask01–03, getcpu01/02, capget01/02 |
| **`PR_SET_DUMPABLE`/`PR_GET_DUMPABLE` tri-state round-trip (0↔1↔2) + EINVAL on bogus values** | ✅ `prctldumpable` | prctl04, prctl08 |
| **setfsuid/setfsgid fs-id model: a tracked fsuid/fsgid (default = euid/egid, reset by every set*uid/set*gid) that setfs*id RETURNS (the previous value) and updates when privileged or the arg matches r/e/s/fs; `(uid_t)-1` is a query** | ✅ `setfsid` | setfsuid01/03, setfsgid01/02 (setfsuid04 = fs-id DAC open() enforcement, the host-backed guest-root class — deferred) |
| **`sched_getattr(pid, attr, size, flags)` (nr 275, was ENOSYS): pid 0/self → success with a zeroed SCHED_OTHER sched_attr (size field set); flags≠0 / size<SCHED_ATTR_SIZE_VER0(48) / NULL attr → EINVAL; non-existent pid → ESRCH** | ✅ `schedgetattr` | sched_getattr02 |
| **prlimit64/getrlimit/setrlimit reject an invalid resource (>= RLIM_NLIMITS=16) with EINVAL before any limit read/write (was treating unknown resources as RLIM_INFINITY and succeeding); valid resources 0..15 unaffected** | ✅ `rlimitresource` | getrlimit02 (getrlimit03 per-resource default VALUES + setrlimit02/03 EPERM-raise-hard-limit deferred) |

## net / sockets / netlink / pty

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| **getsockname output-pointer validation: NULL addr or NULL addrlen → EFAULT; a negative input *addrlen → EINVAL; valid → success** | ✅ `getsocknameval` | getsockname01, getpeername01 |
| **recv/recvfrom with MSG_ERRQUEUE on a socket with no queued error → EAGAIN (carrick has no error queue, so it returned 0 / a normal recv)** | ✅ `recverrqueue` | recv01 (recvfrom01's invalid-addrlen leg remains) |
| socket/socketpair/bind/listen/connect/accept/getsockname/setsockopt/getsockopt across AF_UNIX/INET/INET6/NETLINK | ✅ `net` | socket01/02, socketpair01–04, bind01/06, listen01, connect01/02, accept01/04, getsockname01, setsockopt01–10, getsockopt01–07 |
| rtnetlink `RTM_GETROUTE` dump: at least one `RTM_NEWROUTE` followed by `NLMSG_DONE` | ✅ `netlink_route` | (rtnetlink shape conformance) |
| Unprivileged `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` ping socket sends an echo request to loopback | ✅ `icmp` | (unprivileged ICMP / ping_group_range path) |
| pty pair round-trip: posix_openpt → grantpt → unlockpt → ptsname → open slave → write master/read slave (+ reverse) | ✅ `ptypair` | openpt01, grantpt01, ptsname01, posix_openpt01 |

## io_uring

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| Raw io_uring_setup → mmap rings → submit (NOP + WRITE + READ + READV) → io_uring_enter → reap CQEs end-to-end | ✅ `iouring` | (io_uring data path; WS-H4-B1) |
| `io_uring_setup(IORING_SETUP_SQPOLL)` is rejected/unavailable unless a real SQ polling worker exists; a successful setup without SQPOLL servicing can wedge libuv's `_iouring` tests | ✅ `iouringsqpoll` | (io_uring SQPOLL fallback contract; libuv fs `_iouring` path) |

## LTP framework primitives

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| `tst_test` setup_ipc reduction: `/dev/shm` exists, open(O_CREAT\|O_EXCL), chmod 0666, ftruncate, mmap MAP_SHARED, close-then-write coherence, fork-coherent shared word, BOTH directions of cross-process FUTEX_WAIT/WAKE on the shared word | ✅ `ltpcheckpoint` | (`tst_checkpoint`-using tests: pause01, sigwaitinfo01, sigtimedwait01, sighold02, sigrelse01, rt_sigtimedwait01, kill05, tgkill02, …) |

## SysV IPC

| Invariant | Owned by | Stands in for (LTP) |
|---|---|---|
| **semctl(SETVAL)/SETALL value-range: a semaphore value must be in [0, SEMVMX(32767)]; negative or too-large → ERANGE (macOS doesn't enforce the Linux bound)** | ✅ `semctlrange` | semctl05 |
| **`shmget` + `shmat` + `shmdt` + `shmctl(IPC_RMID/IPC_STAT/SHM_STAT/SHM_INFO)` round-trip; per-segment `shm_nattch` / `shm_ctime` / `shm_atime`; cross-process coherence after fork via host-file-backed `/tmp/carrick-shm/<key>` (inode = shmid)** | ✅ `sysvshm` | kill07 (MATCH), kill05 (advances past TBROK), shmctl01 (6/12 → bumped from 0/12), shmat01 (1/4 → bumped from 0/4), shmget/shmdt LTP families |
| **`msgctl(IPC_STAT)` fills the ipc64_perm (key @0, mode @20) in the returned msqid64_ds — was leaving them zero (only the msg_* fields were translated); owner ids from the guest creds, key/mode/seq from the host stat** | ✅ `msgctlstat` | msgctl01 |
| **`semget(key, nsems, flg)` with nsems > Linux SEMMSL (32000) → EINVAL (was forwarding to macOS semget, which returns ENOSPC for its far-smaller limit)** | ✅ `semgetnsems` | semget02 (nsems-too-large leg; semget02's nsems>existing-set→EINVAL-before-EACCES ordering + semget05 deferred — an errno-order vs macOS perm-gate mismatch) |
| **`kill(2)` permission model across peer guest processes: root → any allowed; non-root cross-uid → EPERM; non-root same-uid → allowed. Cred propagation via per-process `/tmp/carrick-cred-<host_pid>` updated on every setuid/setreuid/setresuid** | ✅ `killuidperm` | kill05 (MATCH 1/1) |

---

## Language-runtime conformance snapshot — 2026-06-02

A *different* axis from the probe map above: end-to-end differential runs of real
language test suites under `carrick run` vs the **Docker linux/arm64 oracle**
(same image, same args; outcome-category diff). These are discovery runs, not the
owned-probe gate — every confirmed gap below should eventually graduate to a probe
row. Method notes that cost time (don't repeat): run each suite **solo** (concurrent
heavy suites starve each other and produce false TIMEOUT/n=0); cpython-parity.py
`--jsonl` *appends* (dedupe last-wins per module); carrick needs the **registry**
image ref `localhost:5050/cpython-test:3.12.13` (a bare docker-daemon ref → carrick
can't pull → every module `n=0`, looks like a mass regression but isn't).

| Ecosystem (suite) | Result vs oracle |
|---|---|
| Go (std test bins: sync, atomic, context, time, os/signal, os/exec, runtime, net, cgo) | ~876/880 pass; 4 carrick-only, all known/env-gated |
| Node.js (node-core, full plan) | 5301/5304 pass (99.9%); 3 cosmetic stderr-snapshot only |
| libuv (full suite, solo, as uid 65534) | 498/507 pass (98.2%); 9 carrick-only gaps |
| CPython 3.12.13 (regrtest, 492 modules) | 425 MATCH / 18 DIFF (86.4%) |

**Go — at parity.** sync/atomic/context/time/os-signal/runtime/cgo 100%. Carrick-only:
`os/exec` TestExplicitPWD (cross-mount symlink/$PWD); `net` TestInterfaceMulticastAddrs,
TestIPConnRemoteName, TestIPConnSpecificMethods (raw-IP sockets / multicast iface —
need CAP_NET_RAW/sudo).

**Node.js node-core — at parity.** Only `test-node-output-{v8-warning,eval,errors}`
fail — exact-stderr snapshot comparisons (cosmetic); the Docker oracle also fails
`v8-warning` and in fact hung mid-suite, so carrick was the side that completed.

**libuv — 9 carrick-only gaps.** Carrick *passes* all 14 tests the LinuxKit/root
Docker oracle fails (`fs_*`, `pipe_*` EOPNOTSUPP, iouring). The 9: `kill`,
`spawn_exercise_sigchld_issue` (signal), `tcp_reuseport`/`udp_reuseport` (SO_REUSEPORT),
`udp_multicast_interface6`, `udp_recvmsg_unreachable_error`(+`6`) (UDP/ICMP),
`tty_pty_partial`, `platform_output` (uv_cpu_info cosmetic). (`eintr_handling` is a
contention false-positive — passes solo.)

**CPython — 425/492 MATCH.** DIFF clusters: multiprocessing (8 modules — a
DETERMINISTIC guest SIGSEGV at `test_async_timeout`'s `Pool(3)` creation; the
campaign's #1 deep blocker, NOT a syscall gap); asyncio (events/subprocess);
`test_socket` (40 SCTP skips — macOS lacks SCTP, out of scope); + small punch-list
gaps (test_posix/test_shutil/test_zipfile/test_subprocess/test_cmd_line_script/test_ssl).
Per-module verdicts in `docs/cpython-baseline/`.

**Incidental carrick gaps found during the runs:** `/dev/fd/N` process substitution
(FIXED, commit 8b7b5c4); `diff <(...)` aborts on the `/proc/self/fd/N` magic-symlink
`st_size=0`; `--user <name>` resolution (numeric uid only); `setpriv` capability-prctl
EINVAL.
