//! KVM's SignalArrival: wakes a target vCPU via the kicker + futex. The async
//! host-signal pump is implemented separately (`kvm_signal_pump`, re-armed on
//! fork by `KvmForkCoordinator`), and cross-process signal delivery is wired
//! through the shared `carrick_signal_core::xsig` ring + `kvm_xsig`. The
//! dispatcher drives those via `carrick_runtime::host_signal::xsig_*` directly,
//! so the `xsig_*` methods on this value stay unused delegation stubs (false /
//! empty); only the kicker + futex wake path here is live.
use std::sync::Arc;

use carrick_hal::{PlatformFutex, SignalArrival, ThreadId, VcpuRegistry};

pub struct KvmSignalArrival {
    pub kicker: Arc<dyn VcpuRegistry>,
    pub futex: Arc<dyn PlatformFutex>,
}

impl SignalArrival for KvmSignalArrival {
    fn install_handlers(&self) {}
    fn on_signal_arrived(&self, tid: ThreadId) {
        self.kicker.kick(tid);
        self.futex.notify_signal_pending();
    }
    fn wake_all_waiters(&self) {
        self.kicker.kick_all();
        self.futex.notify_signal_pending();
    }
    fn record_sender(&self, _signum: i32, _host_pid: i32) {}
    fn register_child_exit_watch(&self, _child: i32, _parent: i32, _sig: i32) {}
    fn xsig_enqueue(&self, _t: i32, _s: i32, _ns: i32, _u: u32, _v: i64) -> bool {
        false
    }
    fn xsig_nudge(&self, _t: i32) {}
    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, u32, i64)> {
        Vec::new()
    }
    fn xsig_has_pending(&self) -> bool {
        false
    }
    fn reinit_after_fork(&self) {}
}
