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

use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

/// vCPU key (its host mach thread port) → accumulated guest execution
/// nanoseconds. One entry per vCPU; grows monotonically.
static EXEC_NS: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

/// Add `delta_ns` of guest execution to a vCPU's running total. Called from the
/// trap engine after each vCPU run with the time spent inside `hv_vcpu_run`;
/// cheap (one lock + map update).
pub fn add(vcpu_key: u64, delta_ns: u64) {
    if delta_ns == 0 {
        return;
    }
    let mut guard = EXEC_NS.lock().unwrap_or_else(|e| e.into_inner());
    let entry = guard.get_or_insert_with(HashMap::new).entry(vcpu_key).or_insert(0);
    *entry = entry.saturating_add(delta_ns);
}

/// Process-wide guest CPU time (nanoseconds): the sum of every vCPU's latest
/// cumulative execution time.
pub fn total_ns() -> u64 {
    let guard = EXEC_NS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(|m| m.values().copied().sum())
        .unwrap_or(0)
}

/// Process-wide guest CPU time in microseconds (the unit accounting surfaces
/// use). Saturating.
pub fn total_us() -> u64 {
    total_ns() / 1000
}

/// Clear per-process state in a freshly `fork`ed child: its vCPU starts a new
/// exec clock at zero and it has not waited any children of its own. (The
/// shared child-exit table is process-shared and intentionally NOT cleared.)
pub fn reset() {
    let mut guard = EXEC_NS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = guard.as_mut() {
        m.clear();
    }
    CHILD_USER_US.store(0, Ordering::Relaxed);
    CHILD_SYS_US.store(0, Ordering::Relaxed);
}

// ---- Reaped-child CPU accounting (getrusage RUSAGE_CHILDREN, times cutime) ----
//
// A guest's child runs as a separate host process, so its guest CPU time lives
// in the child's own `EXEC_NS` table and dies with it. Linux rolls a reaped
// child's CPU into the parent's child-time totals; to match, an exiting child
// publishes its guest CPU into a process-SHARED table (created before any fork
// so the MAP_SHARED region is inherited), and the parent drains it at `wait4`
// into its per-process child accumulators below. The host-side child CPU comes
// from Darwin's own `wait4` rusage out-param (added by the caller).

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

/// Publish an exiting child's total guest CPU (nanoseconds) for its parent to
/// reap. Called from the forked-child exit path.
pub fn record_child_exit(pid: u32, guest_ns: u64) {
    let Some(slots) = child_slots() else { return };
    for slot in slots {
        if slot
            .pid
            .compare_exchange(0, pid as u64, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.guest_ns.store(guest_ns, Ordering::Release);
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

    #[test]
    fn add_then_sum_across_vcpus() {
        reset();
        add(11, 1_000_000); // vCPU 1: +1 ms
        add(22, 2_000_000); // vCPU 2: +2 ms
        add(11, 500_000); // vCPU 1 accumulates → 1.5 ms
        assert_eq!(total_ns(), 1_500_000 + 2_000_000);
        assert_eq!(total_us(), 3500);
        reset();
        assert_eq!(total_ns(), 0);
    }
}
