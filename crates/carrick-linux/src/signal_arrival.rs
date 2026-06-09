//! KVM's [`SignalArrival`]: the one neutral wake hook the generic loop drives.
//! `wake_all_waiters` kicks every live vCPU out of `KVM_RUN` (the kicker) and
//! nudges the futex so parked threads re-check pending state — used at fork/exec
//! quiesce points and on process-directed signal arrival.
//!
//! Everything else (the async host-signal pump, re-armed on fork by
//! `KvmForkCoordinator` / `kvm_signal_pump`; cross-process delivery via the
//! shared `carrick_signal_core::xsig` ring + `kvm_xsig`) is reached by the
//! dispatcher through `carrick_runtime::host_signal::*` directly, NOT through
//! this trait.
use std::sync::Arc;

use carrick_hal::{PlatformFutex, SignalArrival, VcpuRegistry};

pub struct KvmSignalArrival {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub futex: Arc<dyn PlatformFutex>,
}

impl SignalArrival for KvmSignalArrival {
    fn wake_all_waiters(&self) {
        self.kicker.kick_all();
        self.futex.notify_signal_pending();
    }
}
