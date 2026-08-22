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
fn publish_initial_frame_inventory<Inventory>(
    context: Option<&crate::kernel::KernelContext>,
    extent_count: usize,
    inventory: Inventory,
) -> Result<(), RuntimeError>
where
    Inventory: FnOnce(
        carrick_hal::FrameInventoryReservation,
    ) -> Result<carrick_hal::FrameInventoryCommit<()>, carrick_hal::TrapError>,
{
    let Some(context) = context else {
        return Ok(());
    };
    let event_count = extent_count
        .checked_mul(2)
        .ok_or(crate::kernel::FrameInventoryReserveError::CandidateCountExceedsEvents)?;
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(event_count)
        .map_err(crate::kernel::FrameInventoryReserveError::from)?;
    let reservation =
        context
            .kernel()
            .reserve_frame_inventory(extent_count, extent_count, capacity)?;
    let transaction = reservation.transaction();
    let commit = match inventory(reservation) {
        Ok(commit) => commit,
        Err(error) => {
            let abandoned = context.kernel().frame_inventory().abandon(transaction);
            debug_assert!(abandoned);
            return Err(error.into());
        }
    };
    // These mappings already exist in HVF. A missing/rejected authoritative
    // publication cannot be recovered without running with two truths.
    if context
        .kernel()
        .frame_inventory()
        .apply(context.shared().mm().id(), commit)
        .is_err()
    {
        std::process::abort();
    }
    Ok(())
}

fn resolve_hvpatch_setup<T, Retire>(
    setup: Result<T, RuntimeError>,
    retire_vcpu: Retire,
) -> Result<T, RuntimeError>
where
    Retire: FnOnce(),
{
    if setup.is_err() {
        retire_vcpu();
    }
    setup
}

/// HVPatch is the only execution path, so the root registry identity is always
/// the Linux bootstrap pid. It was previously selected against the backend, with
/// the host pid as the retired lanes' answer.
fn main_registry_id() -> crate::thread::ThreadId {
    crate::thread::ThreadId::from_guest_supplied_tid(carrick_abi::LINUX_BOOTSTRAP_PID as i32)
}

pub fn run_threaded_loop<E, H>(
    mut engine: E,
    dispatcher: SyscallDispatcher,
    host: H,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    E: carrick_hal::ThreadedEngine + 'static,
    E::SiblingSpec: 'static,
    H: HostBackend,
{
    dispatcher.activate_file_authority().map_err(|error| {
        RuntimeError::Configuration(format!("activate per-run FileAuthority: {error}"))
    })?;
    use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
    use crate::vcpu_loop::{KernelState, PlatformFutexFactory, VcpuLoopOutcome};
    use std::sync::Arc;

    // Host-specific pre-loop setup (HVF: install default cross-process signal
    // handlers + a termios-restore guard); the guard is held for the loop.
    let _loop_guard = host.pre_loop_setup();

    let main_tid: ThreadId = main_registry_id();
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
        carrick_hal::vcpu_sched::global().acquire(main_tid.raw() as u64),
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
    let fork_coordinator: Arc<dyn carrick_hal::HostForkCoordinator> =
        Arc::from(host_for_factory.make_fork_coordinator());
    // The live-vCPU registry. Constructing the kicker installs the kick-signal
    // handler (idempotent) so a cross-thread `pthread_kill` forces a target
    // vCPU out of its run ioctl. Built before the kernel so the signal-arrival
    // wake can reach a target vCPU via it.
    let kicker: Arc<dyn carrick_hal::VcpuRegistry> = host_for_factory.make_kicker();
    // The signal ARRIVAL/wake mechanism. Default kick+futex hosts kick every live
    // vCPU + nudge the futex; HVF supplies its kqueue-pump wake.
    let signal_arrival: Arc<dyn carrick_hal::SignalArrival> =
        host_for_factory.make_signal_arrival(&kicker, &platform_futex);
    let setup = crate::hvpatch::initialize_root_process(&mut engine, &dispatcher);
    let hvpatch_process = resolve_hvpatch_setup(setup, || {
        // The outer HVPatch owner destroys the VM and records the terminal.
        // Retire only this already-created vCPU so teardown has one owner.
        engine.destroy_vcpu_on_thread_exit();
    })?;
    if hvpatch_process.is_none() {
        // Container VMM runs construct the dispatcher before the namespace
        // supervisor fork. Rebind the one-task adapter to this guest-init host
        // process before its first syscall; HVPatch installs its authoritative
        // process binding in `initialize_root_process` above.
        let inherited_context = dispatcher.capture_one_task_context().map_err(|error| {
            RuntimeError::Configuration(format!(
                "capture mature VMM bootstrap Kernel context: {error}"
            ))
        })?;
        dispatcher
            .reset_one_task_kernel_binding_for_current_process(&inherited_context, main_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "rebind mature VMM one-task Kernel identity: {error}"
                ))
            })?;
        drop(inherited_context);
    }
    let root_linux_tid = if let Some(process) = hvpatch_process.as_ref() {
        crate::kernel::LinuxTid::for_task_leader(process.task_id())
    } else {
        // Read the root's leader tid from the kernel binding rather than
        // recomputing it from the host pid: the two agree today only because
        // the kernel's root task id is seeded from that same host pid, which is
        // a coincidence this must not depend on.
        dispatcher.root_leader_linux_tid()
    };
    let kernel = Arc::new(KernelState::new(
        dispatcher,
        fork_coordinator,
        signal_arrival,
        hvpatch_process,
        None,
        None,
    ));
    if kernel.hvpatch_process.is_some() {
        let context = kernel
            .dispatcher
            .capture_kernel_context(root_linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "capture initial HVPatch frame inventory context: {error}"
                ))
            })?;
        let extent_count = engine.frame_inventory_extent_count();
        publish_initial_frame_inventory(Some(&context), extent_count, |reservation| {
            engine.inventory_initial_mappings(reservation)
        })?;
    }
    kernel.register_hvpatch_runtime_endpoint(Arc::clone(&futex), Arc::clone(&kicker));
    debug_assert!(kernel.hvpatch_process.as_ref().is_none_or(|process| {
        process.pid() == carrick_abi::LINUX_BOOTSTRAP_PID as i32
            && process.live_process_count() == 1
    }));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight; joined after the main thread finishes.
    let threads: Arc<parking_lot::Mutex<Vec<crate::vcpu_loop::VcpuThreadHandle>>> =
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

    let outcome = crate::vcpu_loop::launch_vcpu_until_exit(
        Arc::clone(&kernel),
        engine,
        Arc::clone(&registry),
        Arc::clone(&futex),
        Arc::clone(&platform_futex),
        Arc::clone(&platform_futex_factory),
        root_linux_tid,
        main_tid,
        Arc::clone(&threads),
        Arc::clone(&kicker),
        // The main guest thread's lifetime in-guest handshake flag.
        carrick_hal::InGuestFlag::for_guest_thread(),
        max_traps,
    )
    .wait();
    // Process children are not Linux thread-group siblings of their creator.
    // The outer root run, which owns the shared HVPatch VM lifetime, joins the
    // global process topology after its own terminal loop even when that loop
    // reports an error, so no shared-VM execution owner is detached.
    let process_join = kernel.join_hvpatch_process_threads();
    let outcome = outcome?;
    process_join?;

    let result = match kernel.take_process_terminal()? {
        Some(Ok(result)) => result,
        Some(Err(())) => {
            return Err(RuntimeError::Unsupported(
                "HVPatch sibling-owned process termination failed".to_owned(),
            ));
        }
        None => match outcome {
            VcpuLoopOutcome::ProcessExit(r) | VcpuLoopOutcome::TrapLimit(r) => *r,
            VcpuLoopOutcome::ThreadDone => {
                // Ordinary main-thread exit(2) with surviving siblings keeps the
                // historical synthesized success. HVPatch exit_group/fatal
                // ownership publishes an exact result above instead.
                let report = kernel.reporter.snapshot();
                RunResult {
                    exit_code: 0,
                    terminating_signal: None,
                    stdout: kernel.dispatcher.stdout(),
                    stderr: kernel.dispatcher.stderr(),
                    traps: 0,
                    report,
                    trap_limit_hit: false,
                }
            }
        },
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::num::NonZeroU64;

    #[test]
    fn hvpatch_main_registry_id_is_linux_init() {
        assert_eq!(
            main_registry_id().raw(),
            carrick_abi::LINUX_BOOTSTRAP_PID as i32,
        );
    }

    fn root_context(pid: i32) -> crate::kernel::KernelContext {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            pid,
            crate::thread::ThreadId::synthetic_for_tests(pid),
            "inventory-root".to_owned(),
        )
        .expect("root bootstrap");
        crate::kernel::Kernel::bootstrap_root(bootstrap)
            .expect("root kernel")
            .1
    }

    fn one_mapping_commit(
        mut reservation: carrick_hal::FrameInventoryReservation,
    ) -> carrick_hal::FrameInventoryCommit<()> {
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().expect("frame candidate");
        let mapping = reservation.claim_mapping().expect("mapping candidate");
        let generation = carrick_hal::MappingGeneration::from_backend_counter(
            NonZeroU64::new(1).expect("generation"),
        );
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: carrick_guest_mem::Gpa(0x4000),
                length: carrick_hal::FrameLength::from_mapping_extent(
                    NonZeroU64::new(0x4000).expect("length"),
                ),
                permissions: carrick_hal::MemPerms {
                    read: true,
                    write: true,
                    exec: false,
                },
            })
            .expect("prepare event");
        reservation
            .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                transaction,
                mapping,
                generation,
            })
            .expect("publish event");
        reservation.commit(())
    }

    #[test]
    fn initial_inventory_is_hvpatch_only_and_publishes_once_to_exact_mm() {
        let mature_called = Cell::new(false);
        publish_initial_frame_inventory(None, 1, |reservation| {
            mature_called.set(true);
            Ok(one_mapping_commit(reservation))
        })
        .expect("non-HVPatch no-op");
        assert!(!mature_called.get());

        let context = root_context(67_101);
        let exact_mm = context.shared().mm().id();
        let calls = Cell::new(0);
        publish_initial_frame_inventory(Some(&context), 1, |reservation| {
            calls.set(calls.get() + 1);
            Ok(one_mapping_commit(reservation))
        })
        .expect("initial publication");

        assert_eq!(calls.get(), 1);
        let snapshot = context.kernel().frame_inventory().snapshot_for_mm(exact_mm);
        assert_eq!(snapshot.frames.len(), 1);
        assert_eq!(snapshot.mappings.len(), 1);
        assert_eq!(snapshot.mappings[0].mm, exact_mm);
    }

    #[test]
    fn initial_inventory_abandons_reservation_when_backend_staging_fails() {
        let context = root_context(67_102);
        let transaction = RefCell::new(None);
        let error = publish_initial_frame_inventory(Some(&context), 1, |reservation| {
            transaction.replace(Some(reservation.transaction()));
            Err(carrick_hal::TrapError::Hypervisor(
                "mock initial inventory failure".to_owned(),
            ))
        })
        .expect_err("staging must fail");
        assert!(matches!(error, RuntimeError::Trap(_)));
        assert!(
            !context
                .kernel()
                .frame_inventory()
                .abandon(transaction.into_inner().expect("captured transaction"))
        );
    }

    #[test]
    fn hvpatch_setup_failure_retires_only_the_created_vcpu_once() {
        let retire_count = std::cell::Cell::new(0_u32);
        let result = resolve_hvpatch_setup::<(), _>(
            Err(RuntimeError::Unsupported(
                "deterministic post-vCPU setup failure".to_owned(),
            )),
            || retire_count.set(retire_count.get() + 1),
        );
        assert!(result.is_err());
        assert_eq!(retire_count.get(), 1);
    }
}
