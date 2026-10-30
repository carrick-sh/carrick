//! Backend-neutral, generation-isolated explicit diagnostic observations.
//! Only the execution owner reads hardware state. Remote capture requests
//! enroll on a condition variable; ordinary exits perform no diagnostic read.
use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

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
