//! KVM's SignalArrival: wakes via the kicker + futex. The async host-signal pump
//! is Task 7; native rt_sigqueueinfo cross-process is Task 8 — those methods are
//! inert here, matching today's KVM behavior (guest-issued sends already carry
//! identity via the dispatcher's siginfo queue).
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
