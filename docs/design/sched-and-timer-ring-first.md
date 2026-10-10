# Ring-First Scheduling, Timers, and Refusal Alignment

- **Status:** In-Ring (Priority Boundaries & RR Slice); Unported / Counted-ENOSYS (Timers, Affinity, Clocks, Priority/Policy Get/Set)
- **Date:** 2026-10-10
- **Scope:** `crates/carrick-personality-linux`, `crates/carrick-el1`, `crates/carrick-syscall-abi`, `crates/carrick-abi`

---

## 1. Overview and Ring-First Census Policy

Under Carrick's ring-first architecture (`origin/main` cb835a712):
- **AArch64 EL1:** Syscalls without a wired in-ring handler remain `Family::Unported` and are refused as `Counted-ENOSYS` under strict ring-first. Wired family handlers returning `Forward` are tagged `ForwardReason::FamilyFallback` and reach the host uncounted, which would bypass the strict census in `docs/design/arm-ring-first-flip.tsv`.
- **x86_64 CPL0:** Operates in strict mode where any forwarding outside `HostCrossingSet::X86` (`crates/carrick-personality-linux/src/crossing.rs`) is refused as `ENOSYS`.

Because uncounted host forwarding is not permitted for unported scheduling, timer, and clock operations, and adding rows to `crossing.rs` requires explicit owner sign-off, this family is strictly partitioned into:
1. **In-Ring Served Exactly:** Pure, deterministic syscalls that require no foreign state or stateful guest-task mutations.
2. **Unported per Census:** All remaining operations remain unrouted (`Family::Unported`) and return `-ENOSYS`.

---

## 2. Syscall Classification

| Subsystem / Syscalls | Route | Behavior |
|---|---|---|
| `sched_get_priority_max` (canonical 125, x86 146) | `Family::Sched(SchedCall::GetPriorityMax)` | Returns 0 for `SCHED_OTHER`, `BATCH`, `IDLE`, `DEADLINE`; 99 for `FIFO`, `RR`; `-EINVAL` otherwise. |
| `sched_get_priority_min` (canonical 126, x86 147) | `Family::Sched(SchedCall::GetPriorityMin)` | Returns 0 for `SCHED_OTHER`, `BATCH`, `IDLE`, `DEADLINE`; 1 for `FIFO`, `RR`; `-EINVAL` otherwise. |
| `sched_rr_get_interval` (canonical 127, x86 148) | `Family::Sched(SchedCall::RrGetInterval)` | Returns CFS/EEVDF slice (`tv_sec = 0, tv_nsec = 2_000_000`, 2 ms); negative pid -> `-EINVAL`; NULL pointer -> `-EFAULT`; foreign pid -> `-ESRCH`. |
| `sched_setparam`, `sched_getparam`, `sched_setscheduler`, `sched_getscheduler`, `sched_setattr`, `sched_getattr` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. No partial state storage in `GuestTask`. |
| `sched_setaffinity`, `sched_getaffinity`, `getcpu`, `sched_yield` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. Live vCPU topology and affinity enforcement await scheduler ring integration. |
| `setpriority`, `getpriority`, `ioprio_set`, `ioprio_get` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. Nice and I/O priority await process owner integration. |
| `getitimer`, `setitimer`, `alarm` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. Awaits shared indexed timer authority. |
| `timer_create`, `timer_settime`, `timer_gettime`, `timer_getoverrun`, `timer_delete` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. No stub timer tables in task state. |
| `clock_settime`, `settimeofday`, `adjtimex`, `clock_adjtime` | `Family::Unported` | Counted-ENOSYS / x86 ENOSYS. Host clock isolation per container policy. |

---

## 3. In-Ring Implementation Details

### 3.1 Priority Limits (`sched_get_priority_min` / `sched_get_priority_max`)
- Evaluated via `sched_priority_min(policy)` and `sched_priority_max(policy)`.
- Valid policies: `LINUX_SCHED_OTHER` (0), `LINUX_SCHED_BATCH` (3), `LINUX_SCHED_IDLE` (5), `LINUX_SCHED_DEADLINE` (6) return min 0, max 0.
- Real-time policies: `LINUX_SCHED_FIFO` (1), `LINUX_SCHED_RR` (2) return min 1, max 99.
- Invalid or unknown policies return `Err(LINUX_EINVAL)` (`-22`).

### 3.2 Round-Robin Interval (`sched_rr_get_interval`)
- Parameter validation order matches Linux:
  1. Negative pid (`pid < 0`) returns `-EINVAL` (`-22`), checked prior to pointer validation.
  2. Null or unmapped pointer (`interval == 0`) returns `-EFAULT` (`-14`).
  3. Non-self PID (`pid != 0 && pid != self_pid`) returns `-ESRCH` (`-3`).
- Valid calls copy the 16-byte timespec `LINUX_SCHED_OTHER_SLICE` (`tv_sec = 0`, `tv_nsec = 2_000_000`) into guest user memory using `venue.copy_out`.
- If memory copy fails, `-EFAULT` (`-14`) is returned.

---

## 4. Open Work

The following work items remain open for future migration into the ring-first kernel:

1. **Shared In-Ring Timer Authority:**
   - Integrate with the indexed per-waiter timer authority landing in a companion lane.
   - Schedule true timer expirations and deliver `SIGALRM`, `SIGVTALRM`, and `SIGPROF` via the shared signal owner.
   - Support POSIX timers (`timer_create`, `timer_settime`, etc.) with real clock IDs (`CLOCK_MONOTONIC`, `CLOCK_REALTIME`), overrun accounting, and `sigevent` delivery (including `SIGEV_THREAD_ID`).

2. **vCPU Topology and Thread Affinity:**
   - Map `sched_setaffinity` and `sched_getaffinity` to live guest vCPU topologies from the carrier rather than fixed bitmasks.
   - Honor affinity masks during vCPU scheduling dispatch; reject impossible or empty masks with `-EINVAL`.
   - Implement `getcpu` to report the executing carrier vCPU index.

3. **Task Priority, Policy, and Nice Levels:**
   - Implement a unified task scheduling authority for policy (`SCHED_OTHER`, `SCHED_FIFO`, `SCHED_RR`, etc.), static priorities, and nice levels (`-20..=19`).
   - Implement credentials and capability verification (`CAP_SYS_NICE`) for raising priority or changing other processes' policies.
   - Enforce policy inheritance across `fork`/`clone`.

4. **Clock Setters and Container Isolation:**
   - Differentiate read-only queries (e.g. `adjtimex` with `modes == 0`) from clock-modifying operations.
   - Enforce container isolation: callers without `CAP_SYS_TIME` receive `-EPERM`, preventing guest processes from modifying the host system clock.
