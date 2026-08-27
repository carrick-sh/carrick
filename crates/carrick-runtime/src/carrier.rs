//! Carrier-lifetime infrastructure.
//!
//! A carrier is ONE host process hosting ONE HVF VM, ONE `KernelArena`, and any
//! number of containers — sequentially or at once. Everything in the table is
//! installed once per carrier, is idempotent on re-entry, and is torn down only
//! by [`shutdown`], never by a container's run terminal. None of it may alias a
//! container: every `KernelContext` reaches its container through its task,
//! not through one of these statics.
//!
//! | Facility | Install site | Re-entry | Torn down by |
//! |---|---|---|---|
//! | HVF VM, five control mappings, mailbox allocator | first `HvfVmState::new_with_plan` (`carrick-vmm-hvf::trap::persistent_carrier_cell`) | later roots boot inside it | [`shutdown`] → `destroy_persistent_vm_at_carrier_exit` |
//! | `KernelArena` (pid regions live inside it, per container) | `KernelArena::global` (`OnceLock`, carrick-kernel/src/arena.rs) | first wins | process exit |
//! | Host signal dispositions: SIGINT, xsig nudge, pending self-pipe, xsig ring, FASYNC table | `host_signal::install_default_handlers` (`INSTALLED` CAS guard) | guarded | process exit |
//! | Signal-pump dispositions (`PUMP_SIGNALS`, SIGCHLD) | `signal_pump::install_handlers` / `install_sigchld_handler` (`SIGCHLD_INSTALLED`) | re-install is a no-op by effect | process exit |
//! | SIGWINCH self-pipe (`pty_relay::WINCH_PIPE_WRITE`) | `PtyRelay::start_with_pair_and_winsize` (tty runs only) | one relay at a time; endpoints stay open for the process lifetime by design | relay drop restores the disposition |
//! | Deadlock watchdog thread | `deadlock_watchdog::arm` (`ARMED` swap) | guarded | process exit |
//! | vCPU admission scheduler | `vcpu_sched::install_for_budget` (`OnceLock`) | first wins | process exit |
//! | `TimerDelivery` handle | `timer_delivery::register_delivery` (`OnceLock`; `HvfTimerDelivery` is a unit struct) | first wins | process exit |
//! | `RLIMIT_NOFILE` soft raise | `carrick-cli/main.rs` at startup; `dispatch/time.rs::raise_host_nofile_backing` | only ever raises | process exit |
//! | VM lifecycle ledger terminal + artifact | [`shutdown`] | single terminal per carrier | — |
//!
//! Per-container state (pid namespace root and region, rootfs + mount table,
//! UTS hostname, netns membership, clock domain, granted caps, executor pool,
//! kernel process tree) is owned by `crate::kernel::container::Container` and
//! retired by [`retire_container`].

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::kernel::container::{Container, ContainerId};
use crate::run_result::RuntimeError;
use crate::vm_lifecycle::VmRunTerminalOutcome;

static LIVE_CONTAINERS: AtomicUsize = AtomicUsize::new(0);
static LAST_CONTAINER_TERMINAL: parking_lot::Mutex<Option<VmRunTerminalOutcome>> =
    parking_lot::Mutex::new(None);
static SHUTDOWN_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Number of containers currently booted in this carrier.
pub fn live_container_count() -> usize {
    LIVE_CONTAINERS.load(Ordering::Acquire)
}

/// RAII admission of one container into the carrier census. Dropped by
/// [`retire_container`] (or by unwinding, so a failed boot never leaks a seat).
#[must_use = "dropping the admission immediately un-counts the container"]
pub(crate) struct ContainerAdmission {
    id: ContainerId,
}

pub(crate) fn admit_container(id: ContainerId) -> ContainerAdmission {
    LIVE_CONTAINERS.fetch_add(1, Ordering::AcqRel);
    ContainerAdmission { id }
}

impl ContainerAdmission {
    pub(crate) fn id(&self) -> ContainerId {
        self.id
    }
}

impl Drop for ContainerAdmission {
    fn drop(&mut self) {
        LIVE_CONTAINERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Receipt of one container's teardown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerTeardown {
    pub id: ContainerId,
    pub tasks_reaped: usize,
    pub mounts_dropped: usize,
    pub pid_region_released: bool,
}

/// Retire a container whose run loop has returned: reap every remaining task
/// of its process tree, drop its mount table, release its pid region. The VM
/// and the arena stay for the next container.
pub(crate) fn retire_container(
    container: Arc<Container>,
    admission: ContainerAdmission,
) -> Result<ContainerTeardown, RuntimeError> {
    debug_assert_eq!(container.id(), admission.id());
    let receipt = container.retire()?;
    drop(admission);
    Ok(receipt)
}

/// Remember the most recent container's terminal outcome for the carrier
/// ledger. The lifecycle ledger accepts ONE run terminal per carrier, so it is
/// written at [`shutdown`], not per container.
pub(crate) fn record_container_terminal(outcome: VmRunTerminalOutcome) {
    *LAST_CONTAINER_TERMINAL.lock() = Some(outcome);
}

#[cfg(feature = "platform-macos")]
fn destroy_vm() -> Result<(), RuntimeError> {
    crate::trap::destroy_persistent_vm_at_carrier_exit().map_err(RuntimeError::from)
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn destroy_vm() -> Result<(), RuntimeError> {
    Ok(())
}

/// Whether this carrier ever ATTEMPTED a VM create. A failed create still
/// leaves a `LogicalCreateAttempt` in the ledger, and such a carrier records a
/// `RuntimeError` terminal (the shape `setup_failure_has_one_vm_teardown_and_
/// runtime_error_artifact` pins for the helper).
#[cfg(feature = "platform-macos")]
fn ledger_has_events() -> bool {
    !crate::vm_lifecycle::process_snapshot().events.is_empty()
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn ledger_has_events() -> bool {
    false
}

/// Tear the carrier down: destroy the persistent VM, record the ledger
/// terminal (the last container's outcome, or `RuntimeError` if a VM create
/// was attempted but no container completed), and publish the lifecycle
/// artifact when `CARRICK_HVPATCH_VM_LEDGER_PATH` names one. Idempotent; a
/// carrier whose ledger is empty records nothing.
pub fn shutdown() -> Result<(), RuntimeError> {
    if SHUTDOWN_DONE.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    if live_container_count() != 0 {
        return Err(RuntimeError::Configuration(format!(
            "carrier shutdown with {} live container(s)",
            live_container_count()
        )));
    }
    let attempted = ledger_has_events();
    destroy_vm()?;
    if !attempted {
        return Ok(());
    }
    let terminal = LAST_CONTAINER_TERMINAL
        .lock()
        .take()
        .unwrap_or(VmRunTerminalOutcome::RuntimeError);
    crate::vm_lifecycle::record_process_terminal(terminal);
    if let Some(path) = std::env::var_os(crate::vm_lifecycle::VM_LIFECYCLE_ARTIFACT_PATH_ENV) {
        crate::vm_lifecycle::write_completed_process_artifact(std::path::Path::new(&path))
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "HVPatch VM lifecycle artifact publication failed at carrier exit: {error}"
                ))
            })?;
    }
    Ok(())
}

/// The CLI's one exit funnel: shut the carrier down, then exit with `status`.
/// A shutdown failure is reported on stderr and turns a successful status into
/// 125 (infrastructure failure), never the other way round.
pub fn exit_carrier(status: i32) -> ! {
    let status = match shutdown() {
        Ok(()) => status,
        Err(error) => {
            eprintln!("carrick: carrier shutdown failed: {error:#}");
            if status == 0 { 125 } else { status }
        }
    };
    std::process::exit(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_without_a_booted_container_records_no_terminal() {
        assert_eq!(live_container_count(), 0);
        shutdown().expect("shutdown without a VM is a no-op");
        assert!(crate::vm_lifecycle::process_snapshot().terminal.is_none());
        // Idempotent.
        shutdown().expect("second shutdown is a no-op");
    }

    #[test]
    fn sequential_containers_admit_and_retire_in_one_carrier() {
        assert_eq!(live_container_count(), 0);
        let alpha = Arc::new(Container::for_reference_model());
        let alpha_admission = admit_container(alpha.id());
        assert_eq!(live_container_count(), 1);
        let alpha_teardown =
            retire_container(alpha, alpha_admission).expect("alpha container retire must succeed");
        assert_eq!(live_container_count(), 0);

        let beta = Arc::new(Container::for_reference_model());
        let beta_admission = admit_container(beta.id());
        assert_eq!(live_container_count(), 1);
        let beta_teardown =
            retire_container(beta, beta_admission).expect("beta container retire must succeed");
        assert_eq!(live_container_count(), 0);

        assert_ne!(alpha_teardown.id, beta_teardown.id);
        shutdown().expect("carrier shutdown after container retirement should succeed");
    }

    #[test]
    fn concurrent_containers_admit_and_retire_in_one_carrier() {
        assert_eq!(live_container_count(), 0);
        let start_barrier = Arc::new(std::sync::Barrier::new(3));
        let alpha_barrier = Arc::clone(&start_barrier);
        let beta_barrier = Arc::clone(&start_barrier);

        let alpha_handle = std::thread::spawn(move || {
            alpha_barrier.wait();
            let alpha = Arc::new(Container::for_reference_model());
            let alpha_admission = admit_container(alpha.id());
            retire_container(alpha, alpha_admission).expect("alpha container retire must succeed")
        });

        let beta_handle = std::thread::spawn(move || {
            beta_barrier.wait();
            let beta = Arc::new(Container::for_reference_model());
            let beta_admission = admit_container(beta.id());
            retire_container(beta, beta_admission).expect("beta container retire must succeed")
        });

        start_barrier.wait();
        let alpha_teardown = alpha_handle.join().expect("alpha thread join");
        let beta_teardown = beta_handle.join().expect("beta thread join");

        assert_ne!(alpha_teardown.id, beta_teardown.id);
        assert_eq!(live_container_count(), 0);
        shutdown().expect("carrier shutdown after concurrent container retirement should succeed");
    }
}
