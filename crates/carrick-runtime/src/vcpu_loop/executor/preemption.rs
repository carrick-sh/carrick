//! Production deadline-driven preemption driver for the persistent executor pool.

use std::sync::Arc;
use std::thread::JoinHandle;

use carrick_kernel::kernel::{PreemptionDriverError, PreemptionWork, Scheduler};

/// Carrier-owned scheduling-deadline driver.
///
/// Drives preemption deadlines for an active [`Scheduler`]. Exactly one driver
/// is attached to a scheduler at a time. The driver thread blocks on the kernel's
/// wait predicate until a deadline expires or scheduler state changes; no periodic
/// sleep or scanning tick is performed.
#[derive(Debug)]
pub struct PreemptionDriver {
    thread: Option<JoinHandle<()>>,
    scheduler: Arc<Scheduler>,
    enabled: bool,
    attached: bool,
}

impl PreemptionDriver {
    /// Start the preemption driver for the given scheduler.
    ///
    /// If `CARRICK_FAIR_PREEMPTION=0` is set in the environment, the driver is
    /// disabled (no background thread is spawned) and `thread` is `None`.
    pub fn start(scheduler: Arc<Scheduler>) -> Result<Self, PreemptionDriverError> {
        scheduler.attach_preemption_driver()?;

        let enabled = match std::env::var("CARRICK_FAIR_PREEMPTION") {
            Ok(raw) => raw.trim() != "0",
            Err(_) => true,
        };

        if !enabled {
            return Ok(Self {
                thread: None,
                scheduler,
                enabled: false,
                attached: true,
            });
        }

        let driver_sched = Arc::clone(&scheduler);
        let thread = match std::thread::Builder::new()
            .name("carrick-preemption-driver".to_string())
            .spawn(move || {
                while let PreemptionWork::Due(requests) = driver_sched.wait_preemption_work() {
                    for req in requests {
                        driver_sched.deliver_preemption(req);
                    }
                }
            }) {
            Ok(thread) => thread,
            Err(e) => {
                scheduler.detach_preemption_driver();
                return Err(PreemptionDriverError::SpawnFailed(e.to_string()));
            }
        };

        Ok(Self {
            thread: Some(thread),
            scheduler,
            enabled: true,
            attached: true,
        })
    }

    /// Whether the preemption driver thread is enabled and running.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Stop the driver and join its helper thread.
    pub fn shutdown(&mut self) {
        if self.attached {
            self.scheduler.stop_preemption_driver();
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            self.scheduler.detach_preemption_driver();
            self.attached = false;
        }
    }
}

impl Drop for PreemptionDriver {
    fn drop(&mut self) {
        self.shutdown();
    }
}
