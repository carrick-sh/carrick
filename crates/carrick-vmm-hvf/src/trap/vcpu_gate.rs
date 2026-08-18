//! # vCPU Gate & Admission
//!
//! Hypervisor.framework caps the number of vCPUs that may exist CONCURRENTLY in
//! a VM (`hv_vm_get_max_vcpu_count`, 64 on this class of host). Carrick also
//! should not ask the bounded M:N scheduler to run more HVF vCPU handles than
//! there are physical host cores: extra runnable guest threads should queue in
//! the scheduler, not oversubscribe HVF and turn conformance into host-kernel
//! contention.
//!
//! Linux has no such cap: those 100 threads just run. To preserve that observable
//! behavior we DON'T fail clone; instead the bounded scheduler parks excess
//! guest threads until a vCPU slot frees. The guest thread is created eagerly
//! (clone succeeds, matching Linux); it simply may not get scheduled onto a real
//! vCPU until the live count drops below budget. Threads that decouple through a
//! queue (producers exit → free slots → queued consumers admitted) therefore
//! complete instead of deadlocking.

use std::sync::{Condvar, Mutex, OnceLock};

/// Slots we keep in reserve below the raw HVF cap so a multithreaded fork can
/// always rebuild its quiesced siblings' vCPUs (each sibling releases then
/// recreates one) and the forker has headroom, even while the gate is full.
const RESERVE: i64 = 4;

static BUDGET: OnceLock<usize> = OnceLock::new();
static GATE_CV: Condvar = Condvar::new();

/// HVF concurrent-vCPU budget for SIBLING threads, capped by both the
/// usable HVF ceiling (cap − reserve) and physical host cores. Queried once.
/// This is the `Aarch64Vmm::vcpu_budget()` the bounded scheduler installs.
///
/// NOTE: the old blocking `acquire()` admission gate is RETIRED — the bounded
/// carrick-hal scheduler (installed for `vcpu_budget()`) does admission in the
/// shared spawn path, and HVF's `wait_for_vcpu_slot` is now a no-op. `notify`
/// is still poked on every vCPU destroy in case a future waiter parks on the
/// condvar.
pub(crate) fn budget() -> usize {
    *BUDGET.get_or_init(|| {
        budget_from_limits(
            hvf_cap_budget(),
            carrick_host::host_facts::physical_cpu_count(),
        )
    })
}

pub(crate) fn hvf_cap_budget() -> usize {
    let mut max: u32 = 0;
    let rc = unsafe { applevisor_sys::hv_vm_get_max_vcpu_count(&mut max) };
    let cap = if rc == 0 && max > 0 {
        i64::from(max)
    } else {
        64
    };
    (cap - RESERVE).max(1) as usize
}

/// The M:N admission budget is the HYPERVISOR's ceiling, not the host's core
/// count.
///
/// Clamping to physical cores treated a correctness-critical admission
/// resource as a throughput knob. carrick binds one vCPU per guest thread, so
/// the budget is the number of guest threads that may be simultaneously
/// admitted -- and a guest whose runnable threads exceed it can deadlock:
/// slots end up held by threads that only release when some other thread makes
/// progress, and the thread that would make it is the one queued for a slot.
/// Oversubscribing vCPUs to cores is what a host scheduler is for; refusing to
/// admit them is what wedges a guest.
///
/// Measured 2026-08-18 on `go-os_exec` `TestConcurrentExec`, canonical host
/// (10 physical cores, HVF ceiling 63): with the clamp, 23 clone children pass
/// the vCPU gate, only 17 ever get a scheduler slot, and the 6 that do not make
/// their parents' 10 s start gate expire into `std::process::abort()` -- 4 runs
/// out of 4. `CARRICK_HVF_VCPU_RECLAIM=0`, which admits one live HVF vCPU per
/// guest thread and so removes the bound entirely, passes the same test in
/// under a second.
///
/// Reclaim still matters above this ceiling: HVF caps concurrent vCPUs, and
/// guests do exceed it (CPython `test_queue.test_many_threads` spawns 100).
pub(crate) fn budget_from_limits(hvf_budget: usize, physical_cores: usize) -> usize {
    let _ = physical_cores;
    hvf_budget.max(1)
}

/// A vCPU was destroyed; wake any thread parked on the gate condvar.
pub fn notify() {
    GATE_CV.notify_all();
}

/// Park until a vCPU slot may have freed (a `notify()` from a sibling's
/// `vcpu_destroyed`) or `timeout` elapses — whichever first. Used by the
/// `HV_NO_RESOURCES` backpressure retry so a creation that hit the true hard
/// limit waits for capacity instead of failing. The timeout is the backstop
/// for the cross-process case: a slot freed by a DIFFERENT process's teardown
/// can't reach this process's condvar, so the bounded wait drives the retry.
/// A missed notify is harmless — the timeout retries anyway.
pub(crate) fn park_for_slot(timeout: std::time::Duration) {
    static GATE_MUTEX: Mutex<()> = Mutex::new(());
    let guard = GATE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let _ = GATE_CV.wait_timeout(guard, timeout);
}
