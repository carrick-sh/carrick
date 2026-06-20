//! bhyve async host-signal pump — now a thin forwarder to the SHARED
//! [`carrick_hal::signal_pump`], parameterized by [`crate::BhyveGlue`]. The pump
//! logic is byte-identical across KVM/bhyve/NVMM and lives in carrick-hal; this
//! module keeps bhyve's call-site API stable. (The runtime calls the shared pump
//! directly after the #6 cfg-flip.)

use std::sync::Arc;

use carrick_hal::signal_pump as pump;
use carrick_hal::{PlatformFutex, VcpuRegistry};

use crate::BhyveGlue;

/// Wake the pump thread (async-signal-safe).
pub fn poke() {
    pump::poke();
}

/// Block host-pumped signals on the thread about to `fork(2)`.
pub fn block_pump_signals_for_fork() {
    pump::block_pump_signals_for_fork();
}

/// Restore the mask saved by [`block_pump_signals_for_fork`].
pub fn restore_pump_signals_after_fork() {
    pump::restore_pump_signals_after_fork();
}

/// Stop + join the pump thread before `libc::fork`. Returns whether one ran.
pub fn stop_pump_for_fork() -> bool {
    pump::stop_pump_for_fork()
}

/// Start the async host-signal pump (idempotent), installing `BhyveGlue` handlers.
pub fn start_pump(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    pump::start_pump::<BhyveGlue>(registry, futex);
}

/// Re-arm the pump in a freshly forked child.
pub fn reinit_after_fork(registry: &Arc<dyn VcpuRegistry>, futex: &Arc<dyn PlatformFutex>) {
    pump::reinit_after_fork::<BhyveGlue>(registry, futex);
}

/// Reset the pump guards in a supervisor-fork child WITHOUT respawning.
pub fn reset_state_for_supervisor_fork() {
    pump::reset_state_for_supervisor_fork();
}
