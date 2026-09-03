//! Carrier-local relay-to-kernel terminal signal routing.

use std::sync::{Arc, OnceLock, Weak};

use parking_lot::Mutex;

use super::{ContainerId, Kernel, LinuxSignal};

#[derive(Default)]
struct DeliveryState {
    kernel: Option<Weak<Kernel>>,
    /// The one container whose interactive relay is currently attached.
    /// `ContainerId` is never a guest pid and is never reused.
    container: Option<ContainerId>,
    acknowledged: bool,
    /// Standard Linux signals coalesce while pending. Bit `signum - 1` mirrors
    /// that rule and gives the pre-route channel a fixed memory bound.
    pending: u64,
}

fn slot() -> &'static Mutex<DeliveryState> {
    static SLOT: OnceLock<Mutex<DeliveryState>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(DeliveryState::default()))
}

/// Begin a new interactive carrier session before the relay thread can observe
/// input. This removes any route or pending signals left by a prior run.
pub(crate) fn prepare() {
    *slot().lock() = DeliveryState::default();
}

pub(crate) fn install(kernel: &Arc<Kernel>) {
    let mut state = slot().lock();
    state.kernel = Some(Arc::downgrade(kernel));
    state.container = None;
    state.acknowledged = false;
}

/// Acknowledge that the installed kernel has an exact controlling terminal and
/// foreground process group, then flush the coalesced pre-route signal set.
pub(super) fn acknowledge_ready(expected_kernel: &Kernel, container: ContainerId) {
    let (kernel, pending) = {
        let mut state = slot().lock();
        let Some(kernel) = state.kernel.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        if !std::ptr::eq(kernel.as_ref(), expected_kernel) {
            return;
        }
        state.container = Some(container);
        state.acknowledged = true;
        let pending = std::mem::take(&mut state.pending);
        (kernel, pending)
    };
    for signum in 1..=64 {
        if pending & (1_u64 << (signum - 1)) == 0 {
            continue;
        }
        if let Ok(signal) = LinuxSignal::for_signal_number(signum) {
            kernel.post_signal_to_tty_foreground(container, signal);
        }
    }
}

pub(crate) fn route_foreground_signal(signum: i32) {
    let Ok(signal) = LinuxSignal::for_signal_number(signum) else {
        return;
    };
    let route = {
        let mut state = slot().lock();
        if !state.acknowledged {
            state.pending |= 1_u64 << (signum - 1);
            return;
        }
        state
            .kernel
            .as_ref()
            .and_then(Weak::upgrade)
            .zip(state.container)
    };
    let Some((kernel, container)) = route else {
        return;
    };
    kernel.post_signal_to_tty_foreground(container, signal);
}
