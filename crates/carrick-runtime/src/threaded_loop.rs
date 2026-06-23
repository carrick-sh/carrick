//! The platform-NEUTRAL shared threaded vCPU run loop + its `HostBackend` host
//! seam. Extracted from the Linux-only inline `runtime` module (F3) so BOTH the
//! kick+futex backends (KVM/bhyve/NVMM) and the macOS/HVF backend drive the SAME
//! loop — each plugs in a `HostBackend` impl, never a copied loop.

use crate::dispatch::SyscallDispatcher;
use crate::run_result::{RunResult, RuntimeError};

/// The host-OS seam for the shared threaded vCPU loop ([`run_threaded_loop`]).
///
/// The KVM and bhyve loops were ~85-line near-verbatim clones: identical
/// scaffold (thread registry, root-pid + child-CPU-table init, `KernelState`,
/// `run_vcpu_until_exit`, result assembly) differing only in the four host
/// trait objects each backend plugs in. `HostBackend` is that seam — a backend
/// is now one ~25-line impl, NOT a copied loop. Each method supplies the host's
/// BEST primitive (its own futex, fork coordinator, kicker, timer delivery) —
/// never a lowest-common-denominator.
///
/// The kicker is `Arc<dyn VcpuRegistry>` and the engine's `KickHandle` is
/// type-erased into `Box<dyn VcpuKickDyn>` at registration (`register_vcpu`),
/// so `run_threaded_loop` is generic over any `E: ThreadedEngine` with NO
/// `KickHandle =` binding to thread through — the backend↔engine pair agree via
/// the type-erased registry, not a generic associated-type clause.
///
/// The signal-arrival mechanism is the shared
/// [`carrick_hal::GenericSignalArrival`] (kicker + futex wake) for every
/// `HostBackend` host; HVF's kqueue-pump wake is a different mechanism, so HVF
/// keeps its own loop (`runtime.rs`) — it is migrated last / deferrable.
pub trait HostBackend: Send + Sync + 'static {
    /// Wrap a process-private `FutexTable` as this host's `PlatformFutex`
    /// (its shared-page futex shim — Linux `SYS_futex` / FreeBSD `_umtx_op`).
    fn make_futex(
        &self,
        table: std::sync::Arc<crate::thread::FutexTable>,
    ) -> std::sync::Arc<dyn carrick_hal::PlatformFutex>;

    /// This host's fork coordinator (signal-pump stop/join across `libc::fork`,
    /// kick-handler + xsig-ring install). Boxed object-safe for `KernelState`.
    fn make_fork_coordinator(&self) -> Box<dyn carrick_hal::HostForkCoordinator>;

    /// The live-vCPU kick registry. Both current backends use the neutral
    /// `GenericVcpuRegistry`; a host may override (e.g. a bulk-kick primitive).
    fn make_kicker(&self) -> std::sync::Arc<dyn carrick_hal::VcpuRegistry> {
        std::sync::Arc::new(carrick_hal::GenericVcpuRegistry::new())
    }

    /// This host's wall-clock/POSIX timer delivery (itimer/posix arm/disarm).
    fn make_timer_delivery(
        &self,
        kicker: std::sync::Arc<dyn carrick_hal::VcpuRegistry>,
        main_tid: crate::thread::ThreadId,
    ) -> std::sync::Arc<dyn carrick_hal::TimerDelivery>;

    /// The signal ARRIVAL/wake mechanism. Default = the shared
    /// [`carrick_hal::GenericSignalArrival`] (kick every live vCPU + nudge the
    /// futex so parked threads re-check pending). HVF overrides with its
    /// kqueue-pump wake (`HvfSignalArrival`).
    fn make_signal_arrival(
        &self,
        kicker: &std::sync::Arc<dyn carrick_hal::VcpuRegistry>,
        platform_futex: &std::sync::Arc<dyn carrick_hal::PlatformFutex>,
    ) -> std::sync::Arc<dyn carrick_hal::SignalArrival> {
        std::sync::Arc::new(carrick_hal::GenericSignalArrival {
            kicker: std::sync::Arc::clone(kicker),
            futex: std::sync::Arc::clone(platform_futex),
        })
    }

    /// Host-specific pre-loop setup, run ONCE at the top of the loop; the returned
    /// guard is held for the loop's lifetime. Default no-op. HVF installs its
    /// default cross-process signal handlers + a `TermiosRestoreGuard` here.
    fn pre_loop_setup(&self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    /// Whether to start the signal pump EAGERLY at loop start. Default `true`
    /// (kick+futex backends keep the pump always-on). HVF overrides to gate on a
    /// tty — its pump is lazy, so a non-interactive guest starts pump-free and
    /// requests one only when a guest installs a handler / forks a caught-exit
    /// child.
    fn start_pump_eagerly(&self) -> bool {
        true
    }

    /// Wire the kicker for this host's process-directed POSIX-timer fallback. The
    /// kick+futex backends register the kicker for the wall-clock `deliver` thread;
    /// macOS HVF uses a kqueue `EVFILT_TIMER` instead (no kicker wiring), so this
    /// is a no-op there. cfg'd default — no backend overrides it.
    fn register_process_timer_kicker(
        &self,
        kicker: &std::sync::Arc<dyn carrick_hal::VcpuRegistry>,
        main_tid: crate::thread::ThreadId,
    ) {
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        crate::timer_delivery::register(std::sync::Arc::clone(kicker), main_tid);
        #[cfg(feature = "platform-macos")]
        {
            let _ = (kicker, main_tid);
        }
    }
}

/// The ONE threaded vCPU run loop, parameterized over the host seam
/// [`HostBackend`]. Replaces `run_threaded_kvm_loop` / `run_threaded_bhyve_loop`
/// (and any future kick+futex backend's): builds the shared scaffold + the
/// host's four trait objects, installs the kick handler / pump via the
/// coordinator, wires timer delivery, and drives the generic
/// `vcpu_loop::run_vcpu_until_exit`. `handle_fork` (real `libc::fork` + child VM
/// rebuild), `spawn_clone_thread` (sibling vCPUs), and the private/shared futex
/// paths all flow through the shared loop.
pub fn run_threaded_loop<E, H>(
    engine: E,
    dispatcher: SyscallDispatcher,
    host: H,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    E: carrick_hal::ThreadedEngine + 'static,
    E::SiblingSpec: 'static,
    H: HostBackend,
{
    use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
    use crate::vcpu_loop::{
        KernelState, PlatformFutexFactory, VcpuLoopOutcome, run_vcpu_until_exit,
    };
    use std::sync::Arc;

    // Host-specific pre-loop setup (HVF: install default cross-process signal
    // handlers + a termios-restore guard); the guard is held for the loop.
    let _loop_guard = host.pre_loop_setup();

    let main_tid: ThreadId = std::process::id() as ThreadId;
    let registry = Arc::new(ThreadRegistry::new(main_tid));
    // Publish for /proc/<tid>/stat + /proc/<pid>/task/ synthesis.
    crate::thread::set_current_registry(Arc::clone(&registry));
    // Root guest pid (before any fork) so /proc/<pid>/ can tell a guest
    // descendant from a host process.
    crate::host_proc::set_root_guest_pid(std::process::id());
    // PID-namespace launch-placement fallback (container path only; a no-op when
    // not requested → kick+futex backends unaffected): if the ns supervisor fork
    // was skipped, identity-init so getpid()==1 still holds.
    if crate::namespace::pid::requested() && !crate::namespace::pid::enabled() {
        let _ = crate::namespace::pid::init(std::process::id());
    }
    // Shared reaped-child CPU table, allocated before any fork so every guest
    // descendant inherits the same MAP_SHARED region.
    crate::guest_cpu::init_child_table();
    // Shared published-run-state table (same MAP_SHARED-before-fork pattern), so
    // a sibling's /proc/<pid>/stat reads the guest's TRUE run-state instead of
    // the host vCPU-thread scheduler state (a booting child parked in the host's
    // internal boot ppoll is `R`, not `S`). Publish this (root) process as
    // Booting until its vCPU first resumes guest code.
    crate::run_state::init_table();
    crate::run_state::publish(crate::run_state::RunState::Booting);

    // Install the M:N admission scheduler for this backend's concurrent-vCPU
    // budget: a bounded HostCondvarScheduler for the finite-cap reclaiming
    // backends (bhyve's hw.vmm.maxcpu, KVM's KVM_CAP_MAX_VCPUS) so >budget
    // guest threads time-share the vCPU pool instead of failing vCPU creation;
    // a Noop for an unbounded backend (vcpu_budget == usize::MAX). Once, before
    // any guest thread can spawn.
    carrick_hal::vcpu_sched::install_for_budget(E::vcpu_budget());
    // Reserve slot 0 for the MAIN thread (its vCPU is id 0), so siblings draw
    // 1..N-1 and never collide with the main vCPU. Held for the process's life
    // (released implicitly by `_exit`).
    carrick_hal::vcpu_sched::set_current_lease(
        carrick_hal::vcpu_sched::global().acquire(main_tid as u64),
    );

    // The CONCRETE process-private futex table, threaded UNCHANGED through the
    // dispatch + complete_futex_wait path (the generation-snapshot lost-wake
    // protocol stays byte-identical). The host's object-safe `PlatformFutex`
    // wraps the SAME table for the SHARED-futex / notify-signal-pending ops;
    // the factory rebuilds that pairing over a fresh table on the fork CHILD
    // side (`vcpu_loop::handle_fork`).
    let futex = Arc::new(FutexTable::new());
    let platform_futex: Arc<dyn carrick_hal::PlatformFutex> = host.make_futex(Arc::clone(&futex));
    let host_for_factory = std::sync::Arc::new(host);
    let factory_host = Arc::clone(&host_for_factory);
    let platform_futex_factory: PlatformFutexFactory = Arc::new(
        move |table: Arc<FutexTable>| -> Arc<dyn carrick_hal::PlatformFutex> {
            factory_host.make_futex(table)
        },
    );
    let fork_coordinator: Box<dyn carrick_hal::HostForkCoordinator> =
        host_for_factory.make_fork_coordinator();
    // The live-vCPU registry. Constructing the kicker installs the kick-signal
    // handler (idempotent) so a cross-thread `pthread_kill` forces a target
    // vCPU out of its run ioctl. Built before the kernel so the signal-arrival
    // wake can reach a target vCPU via it.
    let kicker: Arc<dyn carrick_hal::VcpuRegistry> = host_for_factory.make_kicker();
    // The signal ARRIVAL/wake mechanism. Default kick+futex hosts kick every live
    // vCPU + nudge the futex; HVF supplies its kqueue-pump wake.
    let signal_arrival: Arc<dyn carrick_hal::SignalArrival> =
        host_for_factory.make_signal_arrival(&kicker, &platform_futex);
    let kernel = Arc::new(KernelState::new(
        dispatcher,
        fork_coordinator,
        signal_arrival,
    ));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight; joined after the main thread finishes.
    let threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(parking_lot::Mutex::new(Vec::new()));
    // Install the kick handler / start the host's signal pump up front via the
    // coordinator, so a process-directed signal is observable regardless of
    // whether a guest has forked yet. HVF gates this on a tty (lazy pump).
    if host_for_factory.start_pump_eagerly() {
        kernel.fork.start_signal_pump(&kicker, &platform_futex);
    }

    // Wire wall-clock timer signals (setitimer/alarm/timer_settime): the
    // firing thread publishes the timer signal then kicks through this registry.
    // (No-op on HVF, which uses a kqueue EVFILT_TIMER.)
    host_for_factory.register_process_timer_kicker(&kicker, main_tid);
    // Install the backend `TimerDelivery` the dispatch arm reaches through the
    // process-global (`dispatch/time.rs` has no KernelState ref).
    crate::timer_delivery::register_delivery(
        host_for_factory.make_timer_delivery(Arc::clone(&kicker), main_tid),
    );

    let outcome = run_vcpu_until_exit(
        Arc::clone(&kernel),
        engine,
        Arc::clone(&registry),
        Arc::clone(&futex),
        Arc::clone(&platform_futex),
        Arc::clone(&platform_futex_factory),
        main_tid,
        Arc::clone(&threads),
        Arc::clone(&kicker),
        max_traps,
    )?;

    let result = match outcome {
        VcpuLoopOutcome::ProcessExit(r) | VcpuLoopOutcome::TrapLimit(r) => *r,
        VcpuLoopOutcome::ThreadDone => {
            // The main thread ran exit(2) while siblings were alive. Assemble
            // a result from the shared kernel buffers (run-to-completion CLI).
            let report = kernel.reporter.snapshot();
            RunResult {
                exit_code: 0,
                stdout: kernel.dispatcher.stdout(),
                stderr: kernel.dispatcher.stderr(),
                traps: 0,
                report,
                trap_limit_hit: false,
            }
        }
    };

    Ok(result)
}
