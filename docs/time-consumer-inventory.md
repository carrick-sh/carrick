# Linux-Visible Time Consumer Inventory

**Phase F — Clock Domains and Virtual-Time Scheduler**  
**Date:** 2026-08-26  
**Status:** Baseline Inventory for Phase F Verification

---

## 1. Overview and Accounting

This inventory accounts for every time consumer and time source across the Carrick codebase, categorizing each as:
- **Domain-routed**: Linux-visible time consumers that must adhere to the container's [`ClockDomain`](crates/carrick-runtime/src/kernel/container.rs) (`TimeControl::{System, Offset, Frozen, Scaled, Deterministic}`).
- **Deliberately host-only**: Host safety deadlines, watchdog threads, internal resource reclamation timeouts, and observability timestamps that MUST remain tied to real wall-clock time and must never be frozen, scaled, or blocked by guest time control.

---

## 2. Linux-Visible Time Consumers (Domain-Routed)

| Category | Syscall / Interface | Location (`file:line`) | Routing & Mechanism |
|---|---|---|---|
| **Clock Reads** | `clock_gettime` (113) | `crates/carrick-runtime/src/dispatch/time.rs:282` | `linux_clock_duration(clock, clock_id)` (`dispatch/mod.rs:7713`) |
| **Clock Reads** | `gettimeofday` (169) | `crates/carrick-runtime/src/dispatch/time.rs:1367` | `cx.kernel.task().container().clock().realtime_now()` |
| **Clock Reads** | `time` (x86 private) | `crates/carrick-runtime/src/dispatch/time.rs:1301` | `cx.kernel.task().container().clock().realtime_now()` |
| **Clock Reads** | `adjtimex` (171) | `crates/carrick-runtime/src/dispatch/time.rs:1435` | `adjtimex_bootstrap` (`dispatch/mod.rs:7839`) via `clock.realtime_now()` |
| **Clock Reads** | `clock_adjtime` (266) | `crates/carrick-runtime/src/dispatch/time.rs:1492` | `adjtimex_bootstrap` via `clock.realtime_now()` |
| **Clock Reads** | `clock_getres` (114) | `crates/carrick-runtime/src/dispatch/time.rs:526` | `linux_clock_getres_nsec` (`dispatch/mod.rs:7781`) |
| **Clock Control** | `clock_settime` (112) | `crates/carrick-runtime/src/dispatch/time.rs:247` | Updates `ClockDomain` offset + bumps epoch (or returns `EPERM` if controlled) |
| **Clock Control** | `settimeofday` (170) | `crates/carrick-runtime/src/dispatch/time.rs:1415` | Returns `EPERM` or shifts `ClockDomain` realtime offset |
| **Sleeps** | `nanosleep` (101) | `crates/carrick-runtime/src/dispatch/time.rs:219` | Relative sleep via `ClockDomain` / scheduler wait |
| **Sleeps** | `clock_nanosleep` (115) | `crates/carrick-runtime/src/dispatch/time.rs:570` | Relative/absolute sleep via `ClockDomain` / scheduler wait |
| **Interval Timers** | `getitimer` (102) | `crates/carrick-runtime/src/dispatch/time.rs:232` | `ProcState::itimers` (`carrick-timer-core/src/itimer.rs`) |
| **Interval Timers** | `setitimer` (103) | `crates/carrick-runtime/src/dispatch/time.rs:239` | `ProcState::itimers` arm/disarm with `ClockDomain` due times |
| **Interval Timers** | `alarm` (x86 private) | `crates/carrick-runtime/src/dispatch/time.rs:1290` | `setitimer(ITIMER_REAL, ...)` via `ProcState::itimers` |
| **POSIX Timers** | `timer_create` (107) | `crates/carrick-runtime/src/dispatch/time.rs:608` | `PosixTimerTable` (`carrick-timer-core/src/posix.rs`) bound to clock id |
| **POSIX Timers** | `timer_gettime` (108) | `crates/carrick-runtime/src/dispatch/time.rs:634` | Computes remaining duration using `ClockDomain` |
| **POSIX Timers** | `timer_getoverrun` (109) | `crates/carrick-runtime/src/dispatch/time.rs:677` | Overrun count calculation via `carrick-timer-core/src/posix.rs` |
| **POSIX Timers** | `timer_settime` (110) | `crates/carrick-runtime/src/dispatch/time.rs:704` | Arms timer relative/absolute with `ClockDomain` |
| **POSIX Timers** | `timer_delete` (111) | `crates/carrick-runtime/src/dispatch/time.rs:778` | Disarms and releases `PosixTimer` |
| **Timerfd** | `timerfd_create` (85) | `crates/carrick-runtime/src/dispatch/time.rs:153` | `TimerFdState` bound to `Arc<ClockDomain>` |
| **Timerfd** | `timerfd_settime` (86) | `crates/carrick-runtime/src/dispatch/time.rs:167` | Arms timerfd with relative or `TFD_TIMER_ABSTIME` against domain clock |
| **Timerfd** | `timerfd_gettime` (87) | `crates/carrick-runtime/src/dispatch/time.rs:207` | Computes remaining duration via `timerfd_itimerspec` (`dispatch/mod.rs:8624`) |
| **Futex Timeouts** | `futex` (98) (`FUTEX_WAIT`, `FUTEX_WAIT_BITSET`, `FUTEX_LOCK_PI`, `FUTEX_WAIT_REQUEUE_PI`) | `crates/carrick-runtime/src/dispatch/mod.rs:7251`, `crates/carrick-runtime/src/dispatch/proc.rs:2230` | `relative_from_absolute_timespec` (`dispatch/mod.rs:6974`) routes `CLOCK_REALTIME` via `ClockDomain::realtime_now()` |
| **I/O Multiplexing** | `pselect6` (72) | `crates/carrick-runtime/src/dispatch/epoll_shim.rs:430` | Relative `timespec` timeout converted to domain duration |
| **I/O Multiplexing** | `ppoll` (73) | `crates/carrick-runtime/src/dispatch/epoll_shim.rs:460` | Relative `timespec` timeout converted to domain duration |
| **I/O Multiplexing** | `epoll_wait` (22) / `epoll_pwait` (281) | `crates/carrick-runtime/src/dispatch/epoll_shim.rs:400` | Millisecond timeout converted to domain duration |
| **I/O Multiplexing** | `epoll_pwait2` (441) | `crates/carrick-runtime/src/dispatch/epoll_shim.rs:415` | Nanosecond `timespec` timeout converted to domain duration |
| **Socket Timeouts** | `setsockopt` / `getsockopt` (`SO_RCVTIMEO`, `SO_SNDTIMEO`) | `crates/carrick-runtime/src/dispatch/net.rs:2550` | Sets/gets socket read/write timeouts |
| **Signal Timers** | `rt_sigtimedwait` (137) | `crates/carrick-runtime/src/dispatch/signal.rs:320` | Timespec timeout for signal delivery |
| **File Timestamps** | `utimensat` (88) / `futimens` | `crates/carrick-runtime/src/dispatch/fs.rs:8871` | `UTIME_NOW` interprets timestamp as `ClockDomain::realtime_now()` |
| **File Timestamps** | `statx` (291) / `newfstatat` (79) | `crates/carrick-runtime/src/dispatch/fs/stat.rs:100-300` | File mtime/atime/ctime reported in guest format |
| **File Timestamps** | In-memory files (`InMemoryFileVfs`, `devpts`) | `crates/carrick-runtime/src/fs_backend.rs:2022,6205` | Synthetic file modification stamps using `ClockDomain::realtime_now()` |
| **CPU Accounting** | `times` (153) | `crates/carrick-runtime/src/dispatch/time.rs:1310` | Reports user/system CPU ticks and elapsed ticks |
| **CPU Accounting** | `getrusage` (165) | `crates/carrick-runtime/src/dispatch/time.rs:1340` | Reports `ru_utime`, `ru_stime` |
| **CPU Clocks** | `CLOCK_PROCESS_CPUTIME_ID` / `CLOCK_THREAD_CPUTIME_ID` / dynamic CPU clocks | `crates/carrick-runtime/src/dispatch/mod.rs:7730` | `DynamicCpuClock` CPU duration accounting |
| **Procfs** | `/proc/uptime` | `crates/carrick-runtime/src/vfs/proc.rs:416` | Field 1 derived from container `boottime_duration()` |
| **Procfs** | `/proc/stat` `btime` | `crates/carrick-runtime/src/vfs/proc.rs:423` | Derived from container boottime and realtime |
| **Procfs** | `/proc/[pid]/stat` `starttime` | `crates/carrick-runtime/src/vfs/proc.rs:3337` | Clock ticks since container boot |
| **SysV IPC** | `semtimedop` (193) | `crates/carrick-runtime/src/dispatch/sysv.rs:5379` | Timespec timeout for semaphore operations |
| **SysV IPC** | `msgctl` / `shmctl` / `semctl` | `crates/carrick-runtime/src/dispatch/sysv.rs:3000-5000` | Stamps `msg_stime`, `shm_atime`, `sem_otime` using `ClockDomain::realtime_now()` |
| **POSIX Mqueue** | `mq_timedsend` (182) / `mq_timedreceive` (183) | `crates/carrick-runtime/src/dispatch/mqueue.rs:1090,2591` | Absolute `CLOCK_REALTIME` timespec timeout against `ClockDomain::realtime_now()` |
| **vDSO Fast Path** | `VVAR_OFF_REALTIME_OFF_NS` & mode word | `crates/carrick-mem/src/vdso.rs:55`, `crates/carrick-runtime/src/kernel/container.rs:319` | Per-container vvar seqlock publication; `CNTKCTL_EL1.EL0VCTEN` control for non-System modes |

---

## 3. Deliberately Host-Only Infrastructure Sources (Real Time)

The following time sources and deadlines are deliberately excluded from guest domain virtualization to prevent hangs, watchdog starvation, and host resource leaks:

1. **Deadlock Watchdog** (`crates/carrick-runtime/src/deadlock_watchdog.rs:1-120`):
   Uses host real time (`Instant::now` / `thread::sleep`) to detect deadlocks in the carrier. Must never be delayed by guest time control.
2. **Trap Limit Safety** (`crates/carrick-runtime/src/runtime.rs:DEFAULT_MAX_TRAPS`, `crates/carrick-vmm-hvf/src/trap.rs`):
   Enforces maximum trap count and host runtime bounds.
3. **vCPU Lease Acquisition & Quiesce Barriers** (`crates/carrick-vmm-hvf/src/fork_quiesce.rs`, `crates/carrick-vmm-hvf/src/host_signal.rs:1392`):
   Thread parking and synchronization timeouts on host primitives use real `Instant::now() + timeout`.
4. **Kernel Lock Acquisition Timeouts** (`crates/carrick-kernel/src/arena.rs:307`, `crates/carrick-kernel/src/lock.rs:74`, `crates/carrick-kernel/src/wait.rs:35`):
   Robust lock recovery and kernel arena allocation safety bounds use real host deadlines.
5. **Host Storage & Memory Cache Pruning** (`crates/carrick-runtime/src/layer_cache.rs:229`, `crates/carrick-native-darwin/src/aot_cache.rs:1512`):
   Disk and AOT cache TTL evaluation on the host.
6. **Observability & Perf Tracing Baseline** (`crates/carrick-runtime/src/dispatch/perf.rs:147` `BASE: OnceLock<Instant>`):
   DTrace / USDT / perf probe wall-clock timestamps for host telemetry.
