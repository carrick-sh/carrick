//! Backend-neutral, generation-isolated explicit diagnostic observations.
//! Only the execution owner reads hardware state. Remote capture requests
//! enroll on a condition variable; ordinary exits perform no diagnostic read.
use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub use carrick_guest_arch::GuestIsa;
use carrick_mmu_core::live_descriptor_words::{DescriptorDiagnostic, DescriptorPlanRefusalSite};

/// Request refusal observations on the existing grant receipt. The full
/// residency census runs only on failed publication in an opted-in grant.
pub fn trace_grant_refusals() -> bool {
    static TRACE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TRACE
        .get_or_init(|| std::env::var_os("CARRICK_TRACE_GRANT_REFUSALS").is_some_and(|v| v == "1"))
}

pub fn trace_descriptor_diagnostic(isa: GuestIsa, event: DescriptorDiagnostic) {
    use carrick_observability::probes;
    match event {
        DescriptorDiagnostic::PlanRefused {
            site,
            reason,
            op_kind,
            live_stores,
            table_grants,
        } => {
            let isa = match isa {
                GuestIsa::Aarch64 => 1,
                GuestIsa::X86_64 => 2,
            };
            let (stores, grants) = (live_stores as u64, table_grants as u64);
            if site == DescriptorPlanRefusalSite::JournalReserve {
                probes::descriptor_journal_reserve_failed(isa, op_kind, stores, grants);
            }
            probes::descriptor_plan_refused(
                isa,
                site as u64,
                op_kind,
                stores,
                grants,
                reason as u64,
            );
        }
        DescriptorDiagnostic::ResidencyRefused {
            mm_key,
            va,
            len,
            slots_used,
            slots_total,
        } => {
            probes::frame_grant_residency_refused(
                mm_key,
                va,
                len,
                slots_used as u64,
                slots_total as u64,
            );
        }
        DescriptorDiagnostic::ResidencyPublishedBeforeRefusal => {}
    }
}

pub struct CaptureSlot<T: Copy> {
    requested: AtomicU64,
    completed: AtomicU64,
    sample: Mutex<Option<(u64, T)>>,
    ready: Condvar,
}
impl<T: Copy> CaptureSlot<T> {
    /// Fixed storage; no allocation is needed to publish an observation.
    pub const fn new() -> Self {
        Self {
            requested: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            sample: Mutex::new(None),
            ready: Condvar::new(),
        }
    }
    /// Start one fresh generation. The caller serializes capture requests.
    pub fn request(&self) -> Option<CaptureRequest<'_, T>> {
        let previous = self
            .requested
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                old.checked_add(1)
            })
            .ok()?;
        Some(CaptureRequest {
            slot: self,
            generation: previous.checked_add(1)?,
        })
    }
    /// Called only by the execution owner; reads nothing without a request.
    pub fn observe(&self, read: impl FnOnce() -> T) {
        let generation = self.requested.load(Ordering::Acquire);
        if generation == self.completed.load(Ordering::Acquire) {
            return;
        }
        let registers = read();
        let mut sample = self.sample.lock();
        *sample = Some((generation, registers));
        self.completed.store(generation, Ordering::Release);
        self.ready.notify_all();
    }
    /// Await exactly this request until the shared collection deadline.
    fn wait(&self, generation: u64, deadline: Instant) -> Option<T> {
        let mut sample = self.sample.try_lock_until(deadline)?;
        loop {
            if let Some((observed, registers)) = *sample
                && observed == generation
            {
                return Some(registers);
            }
            if Instant::now() >= deadline {
                return None;
            }
            self.ready.wait_until(&mut sample, deadline);
        }
    }
}

/// A request bound to its exact observation slot. A generation from another
/// slot cannot accidentally satisfy this request.
#[derive(Clone, Copy)]
pub struct CaptureRequest<'a, T: Copy> {
    slot: &'a CaptureSlot<T>,
    generation: u64,
}
impl<T: Copy> CaptureRequest<'_, T> {
    pub fn wait(self, deadline: Instant) -> Option<T> {
        self.slot.wait(self.generation, deadline)
    }
}
impl<T: Copy> core::fmt::Display for CaptureRequest<'_, T> {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.generation, out)
    }
}

impl<T: Copy> Default for CaptureSlot<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "diagnostic_capture_tests.rs"]
mod tests;
