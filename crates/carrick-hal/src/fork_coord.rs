//! The kick+futex backends' self-pipe signal pump, generic over the backend's
//! [`HostSignalGlue`](carrick_signal_core::HostSignalGlue). HVPatch does not host
//! fork guest tasks, so this module exposes startup control only.

#![cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]

use std::marker::PhantomData;
use std::sync::Arc;

use carrick_signal_core::HostSignalGlue;

use crate::pump_fork_coord::{HostSignalPump, SignalPumpController};
use crate::{PlatformFutex, VcpuRegistry};

/// The self-pipe async host-signal pump for a kick+futex backend `G`. Owns no
/// per-instance state — the pump thread + self-pipe + install flag are all
/// process-global (`crate::signal_pump` + `SIGNAL_PUMP_INSTALLED`); `G` is used
/// only through associated fns.
pub struct SelfPipePump<G: HostSignalGlue>(PhantomData<fn() -> G>);

impl<G: HostSignalGlue> Default for SelfPipePump<G> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<G: HostSignalGlue> HostSignalPump for SelfPipePump<G> {
    fn ensure_handler(&self) {
        // ORDERING IS LOAD-BEARING: first runs at STARTUP (pre-fork, via
        // `start_signal_pump`) so the `MAP_SHARED` xsig ring is created BEFORE
        // `libc::fork` and inherited by every child. In `reinit_child` it re-runs
        // where `init_xsig` is idempotent (no-ops on the inherited ring) and only
        // the nudge handler is re-asserted.
        G::install_kick_handler();
        carrick_signal_core::host_glue::init_xsig::<G>();
    }

    fn start(&self, registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
        crate::signal_pump::start_pump::<G>(registry, futex);
    }
}

/// Shared startup controller for a kick+futex backend `G`.
pub type GenericSignalPumpControl<G> = SignalPumpController<SelfPipePump<G>>;
