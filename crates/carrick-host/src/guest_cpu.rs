//! Guest CPU-time accounting via the Darwin hypervisor's per-vCPU execution
//! clock (`hv_vcpu_get_exec_time`).
//!
//! HVF guest execution does NOT accrue to the host thread's
//! rusage/`thread_info` — `proc_pid_rusage` drastically under-reports a guest's
//! CPU burn (measured: a loop that costs 275 ms on real Linux shows ~6 ms of
//! host CPU under carrick, because the cycles run in the hypervisor, not the
//! carrick thread). The hypervisor exposes the *true* cumulative per-vCPU run
//! time instead, which is the source of truth for the guest's user-mode CPU
//! time (`getrusage`/`times`/`/proc/<pid>/stat`).
//!
//! Each vCPU run accumulates the wall time it spent inside `hv_vcpu_run` (where
//! the vCPU thread is on-CPU executing guest code — blocking guest syscalls
//! trap OUT of `run` and wait in carrick host code, so `run` time tracks actual
//! guest execution, not idle waiting). `hv_vcpu_get_exec_time` was measured to
//! under-report this ~40×, so it is not used. Readers take the process-wide sum
//! across vCPUs. State is per-process — a forked guest is a separate host
//! process with its own table (`reset` clears the inherited parent entries in
//! the child) — so each process reports only its own guest threads, matching
//! Linux's per-process CPU accounting.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

/// Per-vCPU accumulated guest execution nanoseconds, one atomic slot per vCPU
/// thread. `add` is called on EVERY vCPU run (every guest syscall), so it must
/// be lock-free — a global lock here serialized all vCPU threads on every
/// syscall and throttled multi-threaded guests (e.g. Go's netpoller +
/// goroutine M's). Each thread claims a slot once and `fetch_add`s into it;
/// readers sum the array. Slots are intentionally not recycled: the value in a
/// departed thread's slot remains part of process-total CPU time, and recycling
/// through TLS destructors would complicate fork reset semantics. 512 slots
/// covers realistic active-lifetime vCPU thread counts; overflow shares the
/// last slot, which preserves total accounting because updates are atomic.
const MAX_VCPUS: usize = 512;
#[allow(clippy::declare_interior_mutable_const)]
static EXEC_SLOTS: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(0) }; MAX_VCPUS];
static ACTIVE_START_NS: [AtomicU64; MAX_VCPUS] = [const { AtomicU64::new(0) }; MAX_VCPUS];
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// This vCPU thread's slot index, claimed once. Capped at the last slot if
    /// somehow exceeded (degrades to shared accounting rather than UB).
    static MY_SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed).min(MAX_VCPUS - 1);
}

fn monotonic_ns() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

/// Mark this vCPU thread as actively executing guest code. Called immediately
/// before `hv_vcpu_run` so readers can include the in-flight run before it traps
/// back and is committed to `EXEC_SLOTS`.
pub fn begin_active() {
    MY_SLOT.with(|&slot| {
        ACTIVE_START_NS[slot].store(monotonic_ns().max(1), Ordering::Release);
    });
}

/// Add `delta_ns` of guest execution to this vCPU's running total. Called from
/// the trap engine after each `hv_vcpu_run`; lock-free (a thread-local read +
/// one relaxed `fetch_add`).
pub fn add(delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    MY_SLOT.with(|&slot| {
        EXEC_SLOTS[slot].fetch_add(delta_ns, Ordering::Relaxed);
    });
}

/// Commit a completed `hv_vcpu_run` and clear this thread's in-flight marker.
pub fn finish_active(delta_ns: u64) {
    add(delta_ns);
    MY_SLOT.with(|&slot| {
        ACTIVE_START_NS[slot].store(0, Ordering::Release);
    });
}

/// Process-wide guest CPU time (nanoseconds): the sum across all vCPU slots.
pub fn total_ns() -> u64 {
    EXEC_SLOTS.iter().map(|s| s.load(Ordering::Relaxed)).sum()
}

/// Process-wide guest CPU time including active `hv_vcpu_run` calls that have
/// not trapped back to the runtime yet.
pub fn total_ns_including_active() -> u64 {
    let now = monotonic_ns();
    EXEC_SLOTS
        .iter()
        .zip(ACTIVE_START_NS.iter())
        .map(|(total, active_start)| {
            let committed = total.load(Ordering::Relaxed);
            let start = active_start.load(Ordering::Acquire);
            if start == 0 {
                committed
            } else {
                committed.saturating_add(now.saturating_sub(start))
            }
        })
        .sum()
}

/// Number of vCPU threads currently inside `hv_vcpu_run`.
pub fn active_count() -> usize {
    ACTIVE_START_NS
        .iter()
        .filter(|start| start.load(Ordering::Acquire) != 0)
        .count()
}

/// Process-wide guest CPU time in microseconds (the unit accounting surfaces
/// use), including in-flight vCPU runs. Saturating.
pub fn total_us() -> u64 {
    total_ns_including_active() / 1000
}

/// Clear per-process state in a freshly `fork`ed child: its vCPU starts a new
/// exec clock at zero and it has not waited any children of its own. (The
/// shared child-exit table is process-shared and intentionally NOT cleared.)
pub fn reset() {
    for slot in &EXEC_SLOTS {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in &ACTIVE_START_NS {
        slot.store(0, Ordering::Relaxed);
    }
    CHILD_USER_US.store(0, Ordering::Relaxed);
    CHILD_SYS_US.store(0, Ordering::Relaxed);
}

// ---- Child metadata and CPU accounting (getrusage RUSAGE_CHILDREN, times cutime) ----
//
// A guest's child runs as a separate host process, so its guest CPU time lives
// in the child's own `EXEC_NS` table and dies with it. Linux rolls a reaped
// child's CPU into the parent's child-time totals; to match, an exiting child
// publishes its guest CPU into a process-SHARED table (created before any fork
// so the MAP_SHARED region is inherited), and the parent drains it at `wait4`
// into its per-process child accumulators below. The same live-child row also
// carries low-volume wait metadata that the parent must observe before terminal
// reap, such as pending ptrace signal-delivery stops. The host-side child CPU
// comes from Darwin's own `wait4` rusage out-param (added by the caller).

/// Per-process accumulated child CPU (microseconds), summed over reaped
/// children. NOT shared across fork — each process tracks the children IT
/// reaped, and `reset()` zeroes them in a forked child.
static CHILD_USER_US: AtomicU64 = AtomicU64::new(0);
static CHILD_SYS_US: AtomicU64 = AtomicU64::new(0);

/// Shared (across fork) table mapping an exiting child's pid → its guest CPU
/// nanoseconds. `AtomicPtr` to a `MAP_SHARED|MAP_ANON` slot array; null until
/// `init_child_table` runs (in the root guest, before any fork).
static CHILD_TABLE: AtomicPtr<ChildSlot> = AtomicPtr::new(std::ptr::null_mut());
const CHILD_SLOTS: usize = 256;

#[repr(C)]
struct ChildSlot {
    /// Child pid, or 0 for a free slot. Cross-process atomic (shared page).
    pid: AtomicU64,
    /// The child's total guest CPU nanoseconds.
    guest_ns: AtomicU64,
    /// Non-zero while this child has an unreported ptrace signal-delivery stop.
    ptrace_stop_pending: AtomicU64,
}

/// Create the shared child-exit table. MUST be called in the root guest before
/// any `fork`, so every descendant inherits the same `MAP_SHARED` region.
/// Idempotent; a mapping failure leaves child accounting as a no-op.
pub fn init_child_table() {
    if !CHILD_TABLE.load(Ordering::Acquire).is_null() {
        return;
    }
    let bytes = CHILD_SLOTS * std::mem::size_of::<ChildSlot>();
    // SAFETY: standard anonymous shared mapping; zero-initialised by the kernel,
    // which is the valid "all slots free" state (pid 0).
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return;
    }
    CHILD_TABLE.store(p as *mut ChildSlot, Ordering::Release);
}

fn child_slots() -> Option<&'static [ChildSlot]> {
    let p = CHILD_TABLE.load(Ordering::Acquire);
    if p.is_null() {
        return None;
    }
    // SAFETY: `p` points at `CHILD_SLOTS` zero-initialised ChildSlots that live
    // for the process's lifetime (never unmapped); the region is shared but each
    // field is accessed only through atomics.
    Some(unsafe { std::slice::from_raw_parts(p, CHILD_SLOTS) })
}

/// Register a live child so descendants can publish metadata before exit.
pub fn register_child(pid: u32) {
    let Some(slots) = child_slots() else { return };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            return;
        }
    }
    for slot in slots {
        if slot
            .pid
            .compare_exchange(0, pid as u64, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.guest_ns.store(0, Ordering::Relaxed);
            slot.ptrace_stop_pending.store(0, Ordering::Release);
            return;
        }
    }
}

/// Mark the current process as having an unreported ptrace signal stop.
pub fn mark_self_ptrace_stop_pending() {
    let pid = std::process::id();
    register_child(pid);
    let Some(slots) = child_slots() else { return };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            slot.ptrace_stop_pending.store(1, Ordering::Release);
            return;
        }
    }
}

/// Clear the pending ptrace signal-stop marker once wait4 reports it.
pub fn clear_child_ptrace_stop_pending(pid: u32) {
    let Some(slots) = child_slots() else { return };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            slot.ptrace_stop_pending.store(0, Ordering::Release);
            return;
        }
    }
}

/// Whether `pid` has an unreported ptrace signal-delivery stop.
pub fn child_has_ptrace_stop_pending(pid: u32) -> bool {
    let Some(slots) = child_slots() else {
        return false;
    };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            return slot.ptrace_stop_pending.load(Ordering::Acquire) != 0;
        }
    }
    false
}

/// Publish an exiting child's total guest CPU (nanoseconds) for its parent to
/// reap. Called from the forked-child exit path.
pub fn record_child_exit(pid: u32, guest_ns: u64) {
    let Some(slots) = child_slots() else { return };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            slot.guest_ns.store(guest_ns, Ordering::Release);
            return;
        }
    }
    for slot in slots {
        if slot
            .pid
            .compare_exchange(0, pid as u64, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.guest_ns.store(guest_ns, Ordering::Release);
            slot.ptrace_stop_pending.store(0, Ordering::Release);
            return;
        }
    }
    // Table full: drop (worst case, this child's CPU is omitted from cutime).
}

/// Drain a reaped child's published guest CPU nanoseconds (0 if none), freeing
/// the slot. Called from the parent's `wait4` after a successful reap.
pub fn reap_child_guest_ns(pid: u32) -> u64 {
    let Some(slots) = child_slots() else { return 0 };
    for slot in slots {
        if slot.pid.load(Ordering::Acquire) == pid as u64 {
            let ns = slot.guest_ns.load(Ordering::Acquire);
            slot.guest_ns.store(0, Ordering::Relaxed);
            slot.ptrace_stop_pending.store(0, Ordering::Release);
            slot.pid.store(0, Ordering::Release);
            return ns;
        }
    }
    0
}

/// Accumulate a reaped child's CPU (microseconds) into this process's
/// child-time totals.
pub fn add_reaped_child(user_us: u64, system_us: u64) {
    CHILD_USER_US.fetch_add(user_us, Ordering::Relaxed);
    CHILD_SYS_US.fetch_add(system_us, Ordering::Relaxed);
}

/// This process's accumulated reaped-child user / system CPU (microseconds).
pub fn child_user_us() -> u64 {
    CHILD_USER_US.load(Ordering::Relaxed)
}
pub fn child_system_us() -> u64 {
    CHILD_SYS_US.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn add_then_sum_accumulates() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset();
        add(1_000_000); // +1 ms
        add(2_000_000); // +2 ms (same test thread → same slot, accumulates)
        assert_eq!(total_ns(), 3_000_000);
        assert_eq!(total_us(), 3000);
        reset();
        assert_eq!(total_ns(), 0);
    }

    #[test]
    fn active_run_is_visible_before_commit() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        reset();
        begin_active();
        assert_eq!(active_count(), 1);
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(total_ns_including_active() > total_ns());
        assert!(total_us() > 0);
        finish_active(1_000_000);
        assert_eq!(active_count(), 0);
        assert_eq!(total_ns(), 1_000_000);
        reset();
    }

    #[test]
    fn child_ptrace_stop_marker_lives_until_report_or_reap() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        init_child_table();
        let pid = 424_242;

        let _ = reap_child_guest_ns(pid);
        register_child(pid);
        assert!(!child_has_ptrace_stop_pending(pid));

        let slots = child_slots().unwrap();
        for slot in slots {
            if slot.pid.load(Ordering::Acquire) == pid as u64 {
                slot.ptrace_stop_pending.store(1, Ordering::Release);
                break;
            }
        }
        assert!(child_has_ptrace_stop_pending(pid));

        clear_child_ptrace_stop_pending(pid);
        assert!(!child_has_ptrace_stop_pending(pid));

        for slot in child_slots().unwrap() {
            if slot.pid.load(Ordering::Acquire) == pid as u64 {
                slot.ptrace_stop_pending.store(1, Ordering::Release);
                break;
            }
        }

        record_child_exit(pid, 1234);
        assert!(child_has_ptrace_stop_pending(pid));
        assert_eq!(reap_child_guest_ns(pid), 1234);
        assert!(!child_has_ptrace_stop_pending(pid));
    }
}
