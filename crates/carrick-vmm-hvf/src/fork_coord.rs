//! HVF's kqueue signal pump behind the shared start-only control seam.
//!
//! The pump remains lazy: a non-interactive guest never creates it, while a tty
//! or pending observable signal request starts it idempotently. Guest process
//! lifecycle stays inside the HVPatch kernel and is not represented here.

use std::sync::Arc;

use parking_lot::Mutex;

use carrick_hal::{HostSignalPump, PlatformFutex, SignalPumpController, VcpuRegistry};

use crate::vcpu_kick::SignalPump;

/// HVF's kqueue async host-signal pump primitive. Owns the lazily-spawned pump
/// thread behind a `Mutex<Option<SignalPump>>`.
#[derive(Default)]
pub struct KqueuePump {
    signal_pump: Mutex<Option<SignalPump>>,
}

impl KqueuePump {
    #[cfg(test)]
    pub fn has_signal_pump_for_tests(&self) -> bool {
        self.signal_pump.lock().is_some()
    }
}

impl HostSignalPump for KqueuePump {
    fn ensure_handler(&self) {
        // No-op: HVF's vCPU kick is `hv_vcpus_exit` (not a signal), and its
        // cross-process signal handlers are installed once via
        // `host_signal::install_default_handlers` at run start — there is no
        // per-fork kick-handler / xsig-ring install to re-assert.
    }

    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        let mut pump = self.signal_pump.lock();
        if pump.is_none() {
            *pump = Some(crate::vcpu_kick::spawn_signal_pump(
                Arc::clone(registry),
                Arc::clone(futex),
            ));
        }
    }
}

/// HVF's start-only signal-pump control.
pub type HvfSignalPumpControl = SignalPumpController<KqueuePump>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thread::FutexTable;
    use crate::threaded_impl::hvf_futex;
    use crate::vcpu_kick::VcpuKicker;
    use carrick_hal::SignalPumpControl;

    fn dyn_context() -> (Arc<dyn VcpuRegistry>, Arc<dyn PlatformFutex>) {
        let registry: Arc<dyn VcpuRegistry> = Arc::new(VcpuKicker::new());
        let futex: Arc<dyn PlatformFutex> = Arc::new(hvf_futex(Arc::new(FutexTable::new())));
        (registry, futex)
    }

    #[test]
    fn start_signal_pump_is_idempotent() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let controller = HvfSignalPumpControl::new();
        let (registry, futex) = dyn_context();

        controller.start_signal_pump(&registry, &futex);
        controller.start_signal_pump(&registry, &futex);
        assert!(
            controller.pump().has_signal_pump_for_tests(),
            "start-only control keeps exactly one live pump"
        );
    }
}
