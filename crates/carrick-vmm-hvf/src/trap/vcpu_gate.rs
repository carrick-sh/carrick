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

pub(crate) fn budget_from_limits(hvf_budget: usize, physical_cores: usize) -> usize {
    hvf_budget.max(1).min(physical_cores.max(1))
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
