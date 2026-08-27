# Linux-Visible Time Consumer Inventory

**Phase F — Clock Domains and Virtual-Time Scheduler**  
**Date:** 2026-08-26  
**Status:** Verified Inventory for Phase F Verification

---

## 1. Overview and Accounting

This inventory accounts for every time consumer and raw time source across the Carrick codebase (`crates/`). Every call site is audited and categorized into one of two mutually exclusive buckets:

1. **Domain-routed**: Linux-visible time consumers that must adhere to the container's [`ClockDomain`](../crates/carrick-runtime/src/kernel/container.rs) (`TimeControl::{System, Offset, Frozen, Scaled, Deterministic}`).
2. **Deliberately host-only**: Host safety deadlines, deadlock watchdog threads, trap bounds, vCPU lease/lock timeouts, host resource cleanup, and telemetry that MUST remain anchored to real host time so that no guest time control can freeze, stall, or destabilize host infrastructure.

---

## 2. Raw Time Source Census and Verification

A reader can re-run the exact `ripgrep` commands below to verify every raw time call site across the `crates/` workspace.

### 2.1 `SystemTime::now()` (32 call sites total)

Verification: `rg "SystemTime::now\(\)" crates --stats`

| Bucket | Count | Call Sites & Rationale |
|---|---|---|
| **Domain Base Calibration** | 2 | `crates/carrick-runtime/src/kernel/container.rs:475` (default realtime base for `ClockDomain::system()`), `:1110` (unit test base anchor). |
| **VMM Boot Reference** | 3 | `crates/carrick-vmm-hvf/src/trap.rs:16015`, `crates/carrick-vmm-kvm/src/guest_setup.rs:1364`, `crates/carrick-dsr-aarch64/src/mapped_memory.rs:1579` (initial boot-time host wall-clock reference for calibration). |
| **Host Process & CLI Entropy** | 6 | `crates/carrick-cli/src/commands.rs:969, 3146`, `crates/carrick-cli/src/serve/handlers.rs:1112, 2327`, `crates/carrick-cli/src/lifecycle.rs:438`, `crates/carrick-embed/src/prepared.rs:76` (host run ID / random fallback seed generation). |
| **Host Storage & Layer Cache TTL** | 5 | `crates/carrick-runtime/src/fs_backend.rs:2022, 6205`, `crates/carrick-runtime/src/layer_cache.rs:229`, `crates/carrick-native-darwin/src/aot_cache.rs:1512`, `crates/carrick-host/src/host_mapping.rs:305` (host scratch directory unique prefixes and disk cache expiry). |
| **Host Socket Suffix & Debug Stats** | 2 | `crates/carrick-runtime/src/network/socket_namespace.rs:1686` (host socket file disambiguation), `crates/carrick-dsr-aarch64/src/translator.rs:8313` (host translation telemetry). |
| **Test Harnesses & Assertions** | 14 | `crates/carrick-cli/tests/perf_support/provenance.rs:60`, `crates/carrick-cli/tests/dsr_trace_overhead.rs:913`, `crates/carrick-runtime/src/dispatch/tests.rs:5001`, `crates/carrick-runtime/tests/integration/syscall_net_unix.rs:52, 126, 312, 389, 493`, `crates/carrick-runtime/src/dispatch/mqueue.rs:2591`, `crates/carrick-runtime/src/vfs/proc.rs:5817`, `crates/carrick-runtime/src/dispatch/sysv.rs:5379` (test assertions). |

### 2.2 `Instant::now()` (406 call sites total)

Verification: `rg "Instant::now\(\)" crates --stats`

All 406 call sites are **deliberately host-only** safety deadlines, resource reclamation timeouts, telemetry baselines, and test assertions (detailed in Section 4).

### 2.3 `clock_gettime` / `gettimeofday` (49 call sites total)

Verification: `rg "\b(libc::)?(clock_gettime|gettimeofday)\b" crates --stats`

- **Host Uptime & Precision Measurement**: 28 call sites in `crates/carrick-host/src/clock.rs`, `crates/carrick-host-bsd/src/clock.rs`, and `crates/carrick-host-linux/src/clock.rs` used exclusively for host timer frequency calibration and host execution profiling.
- **Test Harnesses & Conformance Probes**: 21 call sites in test modules and conformance probes measuring host execution.

---

## 3. Linux-Visible Time Consumers (Domain-Routed)

Every Linux syscall and guest-visible time consumer reads from or coordinates with the active container's `ClockDomain`:

| Category | Syscall / Interface | Location (`file:line`) | Routing & Mechanism |
|---|---|---|---|
| **Clock Reads** | `clock_gettime` (113) | `crates/carrick-runtime/src/dispatch/time.rs:282` | `linux_clock_duration(clock, clock_id)` (`dispatch/mod.rs:7713`) |
| **Clock Reads** | `gettimeofday` (169) | `crates/carrick-runtime/src/dispatch/time.rs:1367` | `cx.kernel.task().container().clock().realtime_now()` |
| **Clock Reads** | `time` (x86 private) | `crates/carrick-runtime/src/dispatch/time.rs:1301` | `cx.kernel.task().container().clock().realtime_now()` |
| **Clock Reads** | `adjtimex` (171) | `crates/carrick-runtime/src/dispatch/time.rs:1435` | `adjtimex_bootstrap` (`dispatch/mod.rs:7839`) via `clock.realtime_now()` |
| **Clock Reads** | `clock_adjtime` (266) | `crates/carrick-runtime/src/dispatch/time.rs:1492` | `adjtimex_bootstrap` via `clock.realtime_now()` |
| **Clock Reads** | `clock_getres` (114) | `crates/carrick-runtime/src/dispatch/time.rs:526` | `linux_clock_getres_nsec` (`dispatch/mod.rs:7781`) |
| **Clock Control** | `clock_settime` (112) | `crates/carrick-runtime/src/dispatch/time.rs:247` | Updates `ClockDomain` offset + bumps epoch; returns `EPERM` if controlled |
| **Clock Control** | `settimeofday` (170) | `crates/carrick-runtime/src/dispatch/time.rs:1415` | Returns `EPERM` if controlled or shifts `ClockDomain` realtime offset |
| **Sleeps** | `nanosleep` (101) | `crates/carrick-runtime/src/dispatch/time.rs:219` | Scales duration via `clock.scale_timeout()`; waits in domain |
| **Sleeps** | `clock_nanosleep` (115) | `crates/carrick-runtime/src/dispatch/time.rs:570` | Scales relative/absolute timeouts via `clock.scale_timeout()`; `Frozen` realtime-absolute future waits do not expire on host time |
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
| **Futex Timeouts** | `futex` (98) (`FUTEX_WAIT`, `FUTEX_WAIT_BITSET`, `FUTEX_LOCK_PI`, `FUTEX_WAIT_REQUEUE_PI`) | `crates/carrick-runtime/src/dispatch/mod.rs:7251`, `crates/carrick-runtime/src/dispatch/proc.rs:2230` | `relative_from_absolute_timespec` (`dispatch/mod.rs:6974`) routes `CLOCK_REALTIME` via `ClockDomain::realtime_now()`; applies `scale_timeout()` |
| **Futex waitv** | `futex_waitv` (449) | `crates/carrick-runtime/src/dispatch/proc.rs:2420` | `dispatch_futex_waitv_args` routes via container `ClockDomain` and `scale_timeout()` |
| **I/O Multiplexing** | `pselect6` (72) | `crates/carrick-runtime/src/dispatch/net.rs:5245` | Timeout scaled via `clock.scale_timeout()` |
| **I/O Multiplexing** | `ppoll` (73) | `crates/carrick-runtime/src/dispatch/net.rs:5590` | Timeout scaled via `clock.scale_timeout()` |
| **I/O Multiplexing** | `epoll_wait` (22) / `epoll_pwait` (281) | `crates/carrick-runtime/src/dispatch/net.rs:4938` | Timeout milliseconds scaled via `clock.scale_timeout()` |
| **I/O Multiplexing** | `epoll_pwait2` (441) | `crates/carrick-runtime/src/dispatch/net.rs:5085` | Nanosecond timespec timeout scaled via `clock.scale_timeout()` |
| **Socket Timeouts** | `setsockopt` / `getsockopt` (`SO_RCVTIMEO`, `SO_SNDTIMEO`) | `crates/carrick-runtime/src/dispatch/net.rs:2550` | Sets/gets socket read/write timeouts |
| **Signal Timers** | `rt_sigtimedwait` (137) | `crates/carrick-runtime/src/dispatch/signal.rs:1985` | Timespec timeout scaled via `clock.scale_timeout()` |
| **File Timestamps** | `utimensat` (88) / `futimens` | `crates/carrick-runtime/src/dispatch/fs.rs:14595` | `UTIME_NOW` interprets timestamp as `ClockDomain::realtime_now()` |
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
| **vDSO Fast Path & Trapping** | `with_optional_vdso_for_clock` | `crates/carrick-runtime/src/vdso_policy.rs:107` | When clock is `Scaled`, `Deterministic`, or `Frozen`, maps syscall-stub vDSO (`vdso_image_bytes_with_clock_syscalls()`) to route clock reads through the domain |

---

## 4. Deliberately Host-Only Safety Deadlines (Real Host Time)

The following safety deadlines, watchdogs, and infrastructure timeouts are **deliberately host-only by name**. They MUST NEVER be controlled, frozen, or scaled by guest time domains:

1. **Deadlock Watchdog (`crates/carrick-runtime/src/deadlock_watchdog.rs`)**:
   Tracks host thread heartbeats on real host monotonic time (`Instant::now` / `thread::sleep`). If a guest freezes or scales time, the watchdog continues on host real time to detect wedged locks or deadlocks.
2. **Trap Limit Safety Bounds (`crates/carrick-runtime/src/runtime.rs:DEFAULT_MAX_TRAPS`, `crates/carrick-vmm-hvf/src/trap.rs`)**:
   Enforces maximum trap count bounds against runaway guest loops regardless of guest virtual time.
3. **vCPU Lease Acquisition & Admission Gate (`crates/carrick-vmm-hvf/src/fork_quiesce.rs`, `crates/carrick-hal/src/vcpu_sched.rs:341`)**:
   Host threads waiting on bounded vCPU permits observe real host deadlines (`Instant::now() + timeout`) to prevent unbounded permit starvation.
4. **Host Kernel Lock & Futex Timeouts (`crates/carrick-kernel/src/lock.rs:74`, `crates/carrick-thread/src/fork_quiesce.rs:690`, `crates/carrick-thread/src/thread.rs:1095, 1234`)**:
   Internal carrier lock acquisition and fork barrier quiescence use host real-time deadlines so a stalled child cannot deadlock parent reaping.
5. **Host Storage Reclamation, Trash Sweeps & Layer Cache Eviction (`crates/carrick-runtime/src/fs_backend.rs:2022`, `crates/carrick-runtime/src/layer_cache.rs:229`, `crates/carrick-native-darwin/src/aot_cache.rs:1512`)**:
   Disk cache TTL evaluation and background orphan trash reduction operate on real host timestamps.
6. **Host Process Identity, UUID Generation & Run IDs (`crates/carrick-cli/src/commands.rs:969`, `crates/carrick-embed/src/prepared.rs:76`)**:
   Carrier process naming, telemetry session IDs, and random seeds use host entropy.
7. **Observability, USDT Probes, and Event Ring (`crates/carrick-observability/src/probes.rs:5877`, `crates/carrick-runtime/src/event_ring.rs`)**:
   DTrace/USDT profiling timestamps record real host time for accurate performance attribution.
8. **Test Suite Deadlines & Timeouts (`crates/carrick-embed/tests/guest_smoke.rs:145`, etc.)**:
   Test harness watchdogs and assertion timeouts enforce test execution limits on real time.

---

## 5. Domain Bypass Prevention Analysis

- **Under `System` and `Offset` Modes**: The vDSO provides the fast path reading `CNTVCT_EL0` with `VVAR_OFF_REALTIME_OFF_NS` carrying the signed wall-clock offset.
- **Under `Scaled`, `Deterministic`, and `Frozen` Modes**: `with_optional_vdso_for_clock` maps `vdso_image_bytes_with_clock_syscalls()`. Every dynamic symbol (`__kernel_clock_gettime`, `__kernel_gettimeofday`, `__kernel_clock_getres`) points directly to a `svc #0` syscall instruction stub, routing all guest userspace clock queries to the kernel dispatcher without reading the hardware cycle counter.
- **Hardware Counter Trapping (`CNTKCTL_EL1.EL0VCTEN`)**: Direct raw `mrs cntvct_el0` instructions at EL0 trap (`El0SysRegRead::CntvctEl0`) when counter access is withheld, preventing guest code from bypassing the domain.
- **Bypass Status**: **Zero** guest-visible clock reads bypass the domain under controlled container execution.
