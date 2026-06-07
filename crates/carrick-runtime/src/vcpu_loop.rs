//! The multi-threaded vCPU run loop, hoisted out of the macOS-only `runtime`
//! module and made generic over [`carrick_hal::ThreadedEngine`].
//!
//! # One host thread + one vCPU per guest thread
//!
//! Carrick binds one host thread and one engine vCPU to each guest thread, all
//! sharing ONE process VM (stage-2 mappings are visible to every vCPU). The MAIN
//! guest thread enters [`run_vcpu_until_exit`]; a thread-creating `clone(2)`
//! spawns a sibling host thread that builds its own vCPU in the same VM and runs
//! the same function ([`ThreadRuntimeState::spawn_clone_thread`]).
//!
//! Shared kernel-half state lives behind [`KernelState`] (an `Arc`, each
//! subsystem internally synchronised). The engine-specific lifecycle — kick,
//! fork/exec VM surgery, per-thread materialisation, the private/shared futex
//! backend — is reached only through the [`carrick_hal`] traits
//! ([`ThreadedEngine`], [`VcpuRegistry`], [`PlatformFutex`],
//! [`HostForkCoordinator`]), so this module names no concrete backend.
//!
//! # The two futex paths (the key seam)
//!
//! The loop threads BOTH a CONCRETE `Arc<carrick_thread::thread::FutexTable>`
//! (the process-private futex table, used UNCHANGED by `dispatch_threaded` and
//! [`ThreadRuntimeState::complete_futex_wait`] so the generation-snapshot
//! lost-wake handshake stays byte-identical) AND an object-safe
//! `Arc<dyn PlatformFutex>` (used only for the SHARED-futex ops and the
//! signal-pending notifications, which differ HVF-ulock vs KVM-`SYS_futex`). On
//! HVF the `PlatformFutex` wraps the SAME `FutexTable`, so they stay consistent.
//!
//! # Fork / page-table-edit stop-the-world
//!
//! See the original prose in `runtime.rs`: a guest `fork(2)` from a
//! multithreaded guest quiesces every other live vCPU at its lock-safe run-loop
//! top ([`ThreadRuntimeState::handle_fork`]); a stage-1 page-table edit is a
//! lighter Pause-Modify-Resume that keeps every vCPU alive
//! ([`ThreadRuntimeState::pt_pause`]). The `in_guest` ↔ `quiescing` Dekker
//! handshake (SeqCst on both sides) is preserved verbatim in
//! [`run_vcpu_until_exit`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use carrick_hal::{HostForkCoordinator, PlatformFutex, ThreadedEngine, VcpuRegistry};

use crate::compat::CompatReporter;
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, ProcMapsEntry,
    SyscallDispatcher, SyscallRequest,
};
use crate::memory::AddressSpace;
use crate::run_result::{RunResult, RuntimeError};
use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::trap::{SyscallTrap, TrapError};

const SIGNAL_WAIT_SLICE: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// macOS-only, NON-engine helpers the generic loop calls.
//
// These build/redirect the HVF AddressSpace (`load_execve_image`) or run the
// no-unwind forked-child death paths; they touch only cross-platform types in
// their SIGNATURES but their BODIES are macOS-coupled (HVF page tables, host
// signals), so they live in `crate::runtime::exec` (macOS) and the generic loop
// reaches them through this thin shim. On Linux the generic `run_vcpu_until_exit`
// is never instantiated (the KVM run path is single-threaded in
// `crate::runtime`), so the Linux arm is `unreachable!()` — present only so the
// unconditional module name-resolves. Same pattern as the `host_signal` /
// `probes` Linux stubs in lib.rs.
// ---------------------------------------------------------------------------
#[cfg(feature = "platform-macos")]
use crate::runtime::exec::{
    forked_child_die_by_signal, forked_child_exit, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
};
#[cfg(feature = "platform-macos")]
use crate::runtime::hardware_tso_for_debug;

#[cfg(not(feature = "platform-macos"))]
#[allow(unused_variables, clippy::needless_pass_by_value)]
mod macos_helper_stubs {
    use super::{AddressSpace, SyscallDispatcher};

    pub(super) fn load_execve_image(
        _dispatcher: &SyscallDispatcher,
        _path: &str,
        _argv: Vec<Vec<u8>>,
        _env: Vec<Vec<u8>>,
    ) -> Result<AddressSpace, i32> {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
    pub(super) fn forked_child_exit(
        _code: i32,
        _stdout_buf: impl AsRef<[u8]>,
        _stderr_buf: impl AsRef<[u8]>,
    ) -> ! {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
    pub(super) fn forked_child_die_by_signal(
        _signum: i32,
        _stdout_buf: impl AsRef<[u8]>,
        _stderr_buf: impl AsRef<[u8]>,
    ) -> ! {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
    pub(super) fn stop_by_signal(_signum: i32) {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
    pub(super) fn stop_after_traced_exec(_dispatcher: &SyscallDispatcher) {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
    pub(super) fn hardware_tso_for_debug(_requested: bool) -> bool {
        unreachable!("threaded vcpu_loop is not instantiated on the KVM backend")
    }
}
#[cfg(not(feature = "platform-macos"))]
use macos_helper_stubs::{
    forked_child_die_by_signal, forked_child_exit, hardware_tso_for_debug, load_execve_image,
    stop_after_traced_exec, stop_by_signal,
};

/// Process-wide fork quiesce barrier (defined in `fork_quiesce` so the blocking
/// wait predicates can reach the same instance).
fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    crate::fork_quiesce::barrier()
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
fn pt_barrier() -> &'static crate::fork_quiesce::PtQuiesce {
    crate::fork_quiesce::pt_barrier()
}

// ===================================================================
// Cross-platform kernel-half state.
// ===================================================================

/// Shared kernel-half state for the threaded loop: the syscall dispatcher, the
/// compat reporter, and the host-fork coordinator (held object-safe so this is
/// cross-platform). Built by the macOS setup wrapper with the boxed HVF
/// `ForkCoordinator`.
pub(crate) struct KernelState {
    pub(crate) dispatcher: SyscallDispatcher,
    pub(crate) reporter: CompatReporter,
    pub(crate) fork: Box<dyn HostForkCoordinator>,
}

impl KernelState {
    pub(crate) fn new(dispatcher: SyscallDispatcher, fork: Box<dyn HostForkCoordinator>) -> Self {
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            fork,
        }
    }

    fn begin_exec_replacement(&self, owner: ThreadId) {
        crate::fork_quiesce::begin_exec_replacement(owner);
    }

    fn end_exec_replacement(&self) {
        crate::fork_quiesce::end_exec_replacement();
    }

    fn exec_replacing_other_thread(&self, tid: ThreadId) -> bool {
        crate::fork_quiesce::exec_replacing_other_thread(tid)
    }
}

pub(crate) type Kernel = Arc<KernelState>;

/// What a single vCPU loop did when it stopped.
pub(crate) enum VcpuLoopOutcome {
    /// Whole-process exit (last thread, exit_group, or fatal signal). Carries
    /// the assembled RunResult so the main thread can return it.
    ProcessExit(Box<RunResult>),
    /// Just this thread finished (`exit(2)` with siblings still alive). The
    /// host thread returns; its vCPU is left to the kernel at process exit.
    ThreadDone,
    /// Trap limit hit without exit (used for the main thread's RunResult).
    TrapLimit(Box<RunResult>),
}

pub(crate) fn signal_wait_slice(deadline: &mut Option<Instant>, timeout: Option<Duration>) -> Option<Duration> {
    if let Some(timeout) = timeout {
        let target = deadline.get_or_insert_with(|| Instant::now() + timeout);
        let now = Instant::now();
        if now >= *target {
            return None;
        }
        Some((*target - now).min(SIGNAL_WAIT_SLICE))
    } else {
        *deadline = None;
        Some(SIGNAL_WAIT_SLICE)
    }
}

pub(crate) fn signal_wait_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|target| Instant::now() >= target)
}

// ===================================================================
// Cross-platform syscall-dispatch backstops + image proc-state stamps.
// (Moved from runtime.rs; the macOS single-threaded loop now calls these
// same generic fns.)
// ===================================================================

pub(crate) fn dispatch_with_panic_backstop(
    syscall_nr: u64,
    tid: ThreadId,
    run: impl FnOnce() -> Result<DispatchOutcome, DispatchError>,
) -> Result<DispatchOutcome, DispatchError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(result) => result,
        Err(_) => {
            eprintln!(
                "carrick: FATAL — panic in syscall {syscall_nr} handler on vCPU tid {tid}; \
                 aborting guest (subsystem state may be torn, cannot safely resume)"
            );
            std::process::abort();
        }
    }
}

pub(crate) fn raise_sigpipe_for_blocking_write(
    dispatcher: &SyscallDispatcher,
    write: &crate::dispatch::BlockingHostWrite,
    outcome: DispatchOutcome,
) -> DispatchOutcome {
    if write.sigpipe_on_epipe()
        && matches!(
            &outcome,
            DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EPIPE
            }
        )
        && !dispatcher.signal_is_ignored(crate::linux_abi::LINUX_SIGPIPE)
    {
        dispatcher.mark_signal_pending(write.tid(), crate::linux_abi::LINUX_SIGPIPE);
    }
    outcome
}

pub(crate) fn partial_write_interrupt_outcome(
    write: &crate::dispatch::BlockingHostWrite,
) -> DispatchOutcome {
    if write.offset() > 0 {
        DispatchOutcome::Returned {
            value: write.offset() as i64,
        }
    } else {
        DispatchOutcome::Errno {
            errno: crate::linux_abi::LINUX_EINTR,
        }
    }
}

/// Hand the dispatcher the loaded image's region list + auxv so /proc/self/maps
/// and /proc/self/auxv reflect it (refreshed on each execve).
pub(crate) fn apply_image_proc_state(dispatcher: &SyscallDispatcher, image: &AddressSpace) {
    dispatcher.set_address_space_regions(proc_maps_from_address_space(image));
    dispatcher.set_auxv_image(image.linux_auxv_image().to_vec());
}

/// Stamp the per-process identity page the EL1 syscall shim reads (no-op unless
/// the shim is enabled). Must run before the guest issues any intercepted
/// syscall: at boot, and again in a forked child / after execve, since the
/// child's pid and the new image's identity differ.
pub(crate) fn stamp_identity_page<M: GuestMemory>(memory: &mut M, dispatcher: &SyscallDispatcher) {
    if !crate::syscall_shim_enabled() {
        return;
    }
    let id = dispatcher.identity_snapshot();
    let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
    for (off, val) in [
        (crate::memory::IDENTITY_OFF_PID, id.pid),
        (crate::memory::IDENTITY_OFF_UID, id.uid),
        (crate::memory::IDENTITY_OFF_EUID, id.euid),
        (crate::memory::IDENTITY_OFF_GID, id.gid),
        (crate::memory::IDENTITY_OFF_EGID, id.egid),
    ] {
        // Best-effort: the page is only absent when the shim is off (handled
        // above) or on a non-HVF stub; a stamp failure can't corrupt the guest.
        let _ = memory.write_bytes(base + off, &val.to_le_bytes());
    }
}

/// Stamp the running guest thread's guest-visible tid into the vCPU's TPIDR_EL1,
/// which the EL1 shim returns for `gettid` without a VM exit (no-op unless the
/// shim is enabled). Must run whenever the vCPU is (re)created — boot, clone,
/// fork, exec — since TPIDR_EL1 resets.
pub(crate) fn stamp_guest_tid<E: ThreadedEngine>(
    engine: &E,
    this_tid: ThreadId,
    registry: &ThreadRegistry,
) {
    if !crate::syscall_shim_enabled() {
        return;
    }
    if let Some(tid) = crate::dispatch::guest_visible_tid(this_tid, registry) {
        let _ = engine.set_guest_thread_id(u64::from(tid));
    }
}

fn proc_maps_from_address_space(image: &AddressSpace) -> Vec<ProcMapsEntry> {
    image
        .regions()
        .iter()
        .map(|region| ProcMapsEntry {
            start: region.start,
            end: region.end,
            read: region.perms.read,
            write: region.perms.write,
            execute: region.perms.execute,
            path: String::new(),
        })
        .collect()
}

// ===================================================================
// EL0 synchronous-fault translation (moved from runtime/fault.rs; the
// classifier fns are pure and the delivery fn is generic over the engine).
// ===================================================================

/// Map an EL0 synchronous-fault `ESR_EL1` to the Linux `(signum, si_code)` the
/// kernel would deliver, or `None` for a class we don't translate (kept fatal).
pub(crate) fn el0_fault_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let segv_code = if (0x0c..=0x0f).contains(&dfsc) {
        SEGV_ACCERR
    } else {
        SEGV_MAPERR
    };
    match ec {
        0x20 | 0x21 => Some((SIGSEGV, segv_code)), // instruction abort
        0x24 | 0x25 => {
            if dfsc == 0x21 {
                Some((SIGBUS, BUS_ADRALN)) // alignment fault
            } else {
                Some((SIGSEGV, segv_code))
            }
        }
        _ => None,
    }
}

/// Map an EL0 synchronous *debug* exception `ESR_EL1` to the Linux
/// `(SIGTRAP, si_code)` the kernel would deliver, or `None` if it isn't a debug
/// class (leaving it to `el0_fault_signal`).
pub(crate) fn el0_debug_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1; // software breakpoint (BRK)
    const TRAP_TRACE: i32 = 2; // process trace trap (single-step)
    const TRAP_HWBKPT: i32 = 4; // hardware breakpoint/watchpoint
    let ec = (esr >> 26) & 0x3f;
    match ec {
        0x3c => Some((SIGTRAP, TRAP_BRKPT)),         // BRK (AArch64)
        0x32 | 0x33 => Some((SIGTRAP, TRAP_TRACE)),  // software step
        0x30 | 0x31 => Some((SIGTRAP, TRAP_HWBKPT)), // HW breakpoint
        0x34 | 0x35 => Some((SIGTRAP, TRAP_HWBKPT)), // watchpoint
        _ => None,
    }
}

/// Deliver a synchronous guest EL0 fault as a Linux signal, exactly as the
/// kernel does. Returns `Some(outcome)` to terminate, `None` to resume into the
/// injected handler. `elr` is the faulting instruction's PC.
#[allow(clippy::too_many_arguments)]
fn deliver_fault_signal<E: ThreadedEngine>(
    kernel: &Kernel,
    engine: &mut E,
    this_tid: ThreadId,
    esr: u64,
    elr: u64,
    far: u64,
    from_el0_direct: bool,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    let dispatcher = &kernel.dispatcher;
    // Capture the forked-child flag up front so the `terminate` closure does not
    // borrow `engine` — it is now also called in the inject-failure arm below,
    // after a &mut engine use, and a closure-held &engine would conflict. (M1b)
    let is_forked_child = engine.is_forked_child();
    let terminate = |signum: i32| -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        if is_forked_child || kernel.dispatcher.is_forked_guest_process() {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            forked_child_die_by_signal(signum, &out, &err);
        }
        let result = assemble_run_result(kernel, 128 + signum, traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    let (signum, si_code, si_addr) = if let Some((signum, si_code)) = el0_debug_signal(esr) {
        (signum, si_code, elr)
    } else if let Some((signum, si_code)) = el0_fault_signal(esr) {
        (signum, si_code, far)
    } else {
        return terminate(11);
    };
    if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
        eprintln!(
            "[FAULTDBG tid={this_tid:?}] esr={esr:#x} ec={:#x} elr={elr:#x} far={far:#x} signum={signum} si_addr={si_addr:#x}",
            (esr >> 26) & 0x3f
        );
    }
    crate::probes::signal_deliver(this_tid, signum);

    // A synchronous fault with the signal blocked, or no handler installed,
    // forces the default action (terminate) on Linux.
    let action = dispatcher.registered_signal_handler(signum);
    if dispatcher.signal_blocked(this_tid, signum) || action.is_none() {
        return terminate(signum);
    }
    // INVARIANT: the `action.is_none()` arm above returned, so this is `Some`.
    #[allow(clippy::unwrap_used)]
    let action = action.unwrap();
    let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
        dispatcher.signal_altstack(this_tid)
    } else {
        None
    };
    let saved_sigmask = dispatcher.enter_signal_handler(this_tid, signum, action);
    let interrupted_pc = if from_el0_direct { Some(elr) } else { None };
    let injected = engine.inject_signal(
        signum,
        action.sa_handler,
        restorer,
        None,
        interrupted_pc,
        altstack,
        saved_sigmask,
        Some((si_code, si_addr)),
        None,  // a synchronous fault never carries a queued (rt_sigqueueinfo) siginfo
        false, // a synchronous fault re-runs the faulting instruction, never a syscall restart
    );
    match injected {
        Ok(()) => Ok(None),
        // Linux force_sigsegv: the handler frame couldn't be written to the
        // user stack -> the thread-group dies by SIGSEGV (exit 139).
        Err(TrapError::SignalDeliveryFault) => terminate(11), // SIGSEGV
        Err(e) => Err(e.into()),
    }
}

// ===================================================================
// Per-thread vCPU runtime state, generic over the engine.
// ===================================================================

/// Builds a `PlatformFutex` over a given concrete private-futex table. Lets the
/// generic loop rebuild the child-side futex pair (concrete table + matching
/// `PlatformFutex`) without naming the backend's concrete `HvfFutex`.
pub(crate) type PlatformFutexFactory =
    Arc<dyn Fn(Arc<FutexTable>) -> Arc<dyn PlatformFutex> + Send + Sync>;

pub(crate) struct ThreadRuntimeState<E: ThreadedEngine> {
    registry: Arc<ThreadRegistry>,
    /// The CONCRETE process-private futex table — used UNCHANGED by
    /// `dispatch_threaded` + `complete_futex_wait` (the generation-snapshot
    /// lost-wake protocol stays byte-identical). Do NOT abstract this.
    futex: Arc<FutexTable>,
    /// The object-safe platform futex — used ONLY for SHARED-futex ops +
    /// signal-pending notifications. On HVF this wraps the SAME `FutexTable`.
    platform_futex: Arc<dyn PlatformFutex>,
    /// Rebuilds a `PlatformFutex` over a FRESH concrete `FutexTable` for the
    /// CHILD side of a guest `fork(2)` (`libc::fork` replicated only this thread,
    /// so the child drops the parent's table + waiters and starts over). Built
    /// ONCE by the macOS setup wrapper (where naming the concrete `HvfFutex` is
    /// fine) and threaded through, so the loop keeps `self.futex` and
    /// `self.platform_futex` wrapping the SAME table without ever naming the
    /// backend — see `handle_fork`'s Child arm.
    platform_futex_factory: PlatformFutexFactory,
    this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    /// The object-safe vCPU registry (the kicker). The shared loop never names
    /// the concrete `VcpuKicker`.
    kicker: Arc<dyn VcpuRegistry>,
    /// This vCPU's "currently in `next_syscall`" flag, shared with the kicker so
    /// a page-table-edit coordinator can tell whether this thread is walking
    /// guest memory. Set true around `next_syscall`, false otherwise.
    in_guest: Arc<std::sync::atomic::AtomicBool>,
    waiter: crate::io_wait::ThreadWaiter,
    max_traps: usize,
    trace: bool,
    /// Set on a vfork (`CLONE_VM|CLONE_VFORK`) CHILD: the write end of the pipe
    /// whose read end the suspended PARENT blocks on. `None` on the parent and on
    /// ordinary (non-vfork) children.
    vfork_release_fd: Option<i32>,
    /// The engine is passed as `&mut E` to each method, so no field owns it; this
    /// pins the generic parameter to the struct.
    _engine: std::marker::PhantomData<fn() -> E>,
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        registry: Arc<ThreadRegistry>,
        futex: Arc<FutexTable>,
        platform_futex: Arc<dyn PlatformFutex>,
        platform_futex_factory: PlatformFutexFactory,
        this_tid: ThreadId,
        threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
        kicker: Arc<dyn VcpuRegistry>,
        max_traps: usize,
    ) -> Self {
        let in_guest = kicker.register_in_guest(this_tid);
        Self {
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            this_tid,
            threads,
            kicker,
            in_guest,
            waiter: crate::io_wait::ThreadWaiter::new(this_tid),
            max_traps,
            trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),
            vfork_release_fd: None,
            _engine: std::marker::PhantomData,
        }
    }

    fn register_vcpu(&self, engine: &E) {
        let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
        self.kicker.register(self.this_tid, handle);
        self.registry
            .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
    }

    /// Pause sibling vCPUs for a stage-1 page-table edit (mmap/mprotect/munmap),
    /// returning an RAII guard that resumes them on drop.
    fn pt_pause(&self) -> crate::fork_quiesce::PtPauseGuard {
        let b = pt_barrier();
        // Serialize editors: at most one stop-the-world at a time. A loser parks
        // (if the winner has raised quiescing) or yields (tiny pre-flag window),
        // then retries.
        loop {
            if b.try_become_coordinator() {
                break;
            }
            if b.is_quiescing() {
                b.park();
            } else {
                std::thread::yield_now();
            }
        }
        b.set_quiescing();
        let tid = self.this_tid;
        crate::probes::pt_pause_begin(
            tid,
            i32::from(self.kicker.any_other_in_guest(self.this_tid)),
            self.kicker.count() as i32,
        );
        // Force in-guest siblings out so they reach the run-loop-top park, then
        // wait until none is walking the tables. Re-kick each spin in case a
        // vCPU was between runs when the first kick landed.
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_millis(500);
        let mut spins: i32 = 0;
        while self.kicker.any_other_in_guest(self.this_tid) {
            self.kicker.kick_all_except(self.this_tid);
            if std::time::Instant::now() >= deadline {
                crate::probes::pt_pause_timeout(tid, start.elapsed().as_micros() as i64);
                break;
            }
            spins = spins.saturating_add(1);
            std::thread::yield_now();
        }
        crate::probes::pt_pause_ready(tid, spins, start.elapsed().as_micros() as i64);
        b.pause_guard(tid)
    }

    fn release_and_park_vcpu_for_fork(&self, engine: &mut E) -> Result<(), RuntimeError> {
        engine.release_vcpu_for_fork()?;
        // Drop out of the kicker the instant the vCPU is gone: while parked we
        // have no live vCPU, so another fork must not count us in `others` nor
        // try to kick a destroyed vCPU.
        self.kicker.unregister(self.this_tid);
        fork_barrier().park_if_quiescing();
        // Recreate the vCPU under the topology lock so vcpu_create cannot race
        // another fork's hv_vm_destroy/create. Register only after it exists.
        {
            let _topo = crate::fork_quiesce::topology_lock()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            engine.rebuild_vcpu_after_fork()?;
            self.register_vcpu(engine);
        }
        Ok(())
    }

    fn trace_syscall(&self, traps: usize, frame: Aarch64SyscallFrame) {
        if !self.trace {
            return;
        }
        let name = crate::syscall::lookup_aarch64(frame.x8)
            .map(|s| s.name)
            .unwrap_or("<unknown>");
        eprintln!(
            "tid#{} trap#{}: x8={} ({name}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x}",
            self.this_tid, traps, frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4
        );
    }

    /// Return-side companion to [`Self::trace_syscall`].
    fn trace_syscall_return(&self, traps: usize, ret: Option<i64>) {
        if !self.trace {
            return;
        }
        let Some(ret) = ret else { return };
        if (-4095..0).contains(&ret) {
            let e = (-ret) as u32;
            let ename = crate::linux_abi::errno_name(e).unwrap_or("?");
            eprintln!("tid#{} trap#{traps}:   -> errno={e} ({ename})", self.this_tid);
        } else {
            eprintln!("tid#{} trap#{traps}:   -> ret={ret:#x} ({ret})", self.this_tid);
        }
    }

    fn service_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        frame: Aarch64SyscallFrame,
    ) -> Result<DispatchOutcome, RuntimeError> {
        // Stage-1 page-table editors — munmap(215), mremap(216), mmap(222),
        // mprotect(226) — mutate the shared guest descriptors from the host.
        // With sibling vCPUs live, Pause-Modify-Resume them so none walks a
        // half-edited descriptor tree.
        let _pt_pause = match frame.x8 {
            215 | 216 | 222 | 226 if self.kicker.count() > 1 => Some(self.pt_pause()),
            _ => None,
        };
        let mut signal_wait_deadline = None;
        // Monotonic deadline for a WaitOnSleep, established on first dispatch and
        // preserved across quiesce-park re-dispatch so the sleep isn't restarted.
        let mut sleep_deadline: Option<Instant> = None;
        loop {
            let request = SyscallRequest::from_aarch64_frame(frame);
            let outcome = dispatch_with_panic_backstop(request.number, self.this_tid, || {
                kernel.dispatcher.dispatch_threaded(
                    request,
                    engine,
                    &kernel.reporter,
                    self.this_tid,
                    &self.registry,
                    &self.futex,
                )
            })?;
            match outcome {
                DispatchOutcome::BlockingHostWrite(mut write) => {
                    self.waiter.ensure_full();
                    loop {
                        if crate::fork_quiesce::is_quiescing() {
                            self.release_and_park_vcpu_for_fork(engine)?;
                            continue;
                        }
                        match crate::dispatch::drive_blocking_host_write(&mut write) {
                            crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                                return Ok(raise_sigpipe_for_blocking_write(
                                    &kernel.dispatcher,
                                    &write,
                                    outcome,
                                ));
                            }
                            crate::dispatch::BlockingHostWriteStep::Wait => {
                                match self.waiter.wait(
                                    &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                    None,
                                    0,
                                ) {
                                    crate::io_wait::WaitResult::Ready => continue,
                                    crate::io_wait::WaitResult::Interrupted => {
                                        if crate::fork_quiesce::is_quiescing() {
                                            self.release_and_park_vcpu_for_fork(engine)?;
                                            continue;
                                        }
                                        return Ok(partial_write_interrupt_outcome(&write));
                                    }
                                    crate::io_wait::WaitResult::TimedOut => {
                                        return Ok(DispatchOutcome::Returned {
                                            value: write.offset() as i64,
                                        });
                                    }
                                    crate::io_wait::WaitResult::Errno(errno) => {
                                        if write.offset() > 0 {
                                            return Ok(DispatchOutcome::Returned {
                                                value: write.offset() as i64,
                                            });
                                        }
                                        return Ok(DispatchOutcome::Errno { errno });
                                    }
                                }
                            }
                        }
                    }
                }
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait(&fds, timeout, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnFdsSelect {
                    fds,
                    timeout,
                    block_signals,
                    clear_on_timeout,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait(&fds, timeout, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            for (addr, len) in &clear_on_timeout {
                                let zeros = vec![0u8; *len];
                                let _ = engine.write_bytes(*addr, &zeros);
                            }
                            break Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait_poll(&fds, timeout, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait_proc_exit(pid, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSignals { wait_set, timeout } => {
                    let slice = match signal_wait_slice(&mut signal_wait_deadline, timeout) {
                        Some(slice) => slice,
                        None => {
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EAGAIN,
                            });
                        }
                    };
                    self.waiter.ensure_full();
                    match self.waiter.wait(&[], Some(slice), !wait_set) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            if signal_wait_expired(signal_wait_deadline) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EAGAIN,
                                });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                            }
                            if crate::fork_quiesce::exec_replacing_other_thread(self.this_tid) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EINTR,
                                });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSleep { duration } => {
                    // The fix for the multithreaded-fork deadlock: sleep via the
                    // waiter (NOT a blocking host nanosleep in the dispatcher) so
                    // a sleeping sibling reaches here, observes the fork-quiesce,
                    // and PARKS. The deadline is preserved across the park.
                    let deadline = *sleep_deadline.get_or_insert_with(|| Instant::now() + duration);
                    let now = Instant::now();
                    if now >= deadline {
                        break Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    self.waiter.ensure_full();
                    match self.waiter.wait(&[], Some(deadline - now), 0) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            if Instant::now() >= deadline {
                                break Ok(DispatchOutcome::Returned { value: 0 });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                other => break Ok(other),
            }
        }
    }

    fn complete_returned(&self, engine: &mut E, value: i64) -> Result<i64, RuntimeError> {
        engine.complete_syscall(value)?;
        Ok(value)
    }

    fn complete_errno(&self, engine: &mut E, errno: i32) -> Result<i64, RuntimeError> {
        self.complete_returned(engine, -(errno as i64))
    }

    fn complete_futex_wait(
        &self,
        engine: &mut E,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        use crate::thread::FutexWaitOutcome;

        let retval: i64 = loop {
            let outcome =
                match self
                    .futex
                    .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                        crate::host_signal::has_pending_for(self.this_tid)
                            || crate::fork_quiesce::is_quiescing()
                            || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
                    }) {
                    FutexWaitOutcome::Woken => 0,
                    FutexWaitOutcome::TimedOut => -(crate::linux_abi::LINUX_ETIMEDOUT as i64),
                    FutexWaitOutcome::Interrupted if crate::fork_quiesce::is_quiescing() => {
                        self.release_and_park_vcpu_for_fork(engine)?;
                        continue;
                    }
                    FutexWaitOutcome::Interrupted => -(crate::linux_abi::LINUX_EINTR as i64),
                };
            break outcome;
        };
        self.complete_returned(engine, retval)
    }

    fn complete_shared_futex_wait(
        &self,
        engine: &mut E,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        let interrupted = || {
            crate::host_signal::has_pending_for(self.this_tid)
                || crate::fork_quiesce::is_quiescing()
                || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
        };
        let retval = loop {
            let retval =
                self.platform_futex
                    .shared_wait(host_addr, value, timeout, &interrupted);
            if retval == -(crate::linux_abi::LINUX_EINTR as i64)
                && crate::fork_quiesce::is_quiescing()
            {
                self.release_and_park_vcpu_for_fork(engine)?;
                continue;
            }
            break retval;
        };
        self.complete_returned(engine, retval)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_clone_thread(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        stack: u64,
        tls: u64,
        parent_tid_addr: u64,
        child_tid_addr: u64,
    ) -> Result<ThreadId, RuntimeError> {
        let clear_addr = if child_tid_addr != 0 {
            child_tid_addr
        } else {
            0
        };
        let tid = self.registry.register_child(clear_addr);
        let tid_bytes = tid.to_le_bytes();
        if parent_tid_addr != 0 {
            let _ = engine.write_bytes(parent_tid_addr, &tid_bytes);
        }
        if child_tid_addr != 0 {
            let _ = engine.write_bytes(child_tid_addr, &tid_bytes);
        }

        let spec = engine.build_sibling_spec(stack, tls)?;
        let child_kernel = Arc::clone(kernel);
        let child_registry = Arc::clone(&self.registry);
        let child_futex = Arc::clone(&self.futex);
        let child_platform_futex = Arc::clone(&self.platform_futex);
        let child_platform_futex_factory = Arc::clone(&self.platform_futex_factory);
        let child_threads = Arc::clone(&self.threads);
        let child_kicker = Arc::clone(&self.kicker);
        // Cleanup handles kept past the move into run_vcpu_until_exit: if the
        // sibling loop returns Err, its normal thread-exit cleanup never ran, so
        // we MUST still drop it from the registry + kicker here. Otherwise it
        // lingers as a phantom live thread.
        let cleanup_registry = Arc::clone(&self.registry);
        let cleanup_kicker = Arc::clone(&self.kicker);
        let cleanup_kernel = Arc::clone(kernel);
        let max_traps = self.max_traps;
        let trace = self.trace;
        let handle = std::thread::Builder::new()
            .name(format!("guest-tid-{tid}"))
            .spawn(move || {
                if trace {
                    eprintln!("[sibling tid#{tid}] thread started, building vCPU");
                }
                // Wait (if necessary) for room under the HVF concurrent-vCPU cap
                // BEFORE taking the topology lock. carrick binds one vCPU per
                // guest thread for its whole lifetime; HVF caps concurrent vCPUs
                // (64 on this host), so a guest with more live threads than the
                // cap (CPython test_queue.test_many_threads spawns 100) would
                // otherwise hit HV_NO_RESOURCES here. Done OUTSIDE the topology
                // lock so a fork in flight isn't stalled behind a full gate.
                E::wait_for_vcpu_slot();
                // Build the vCPU + register it in the kicker UNDER the topology
                // lock, so this is atomic w.r.t. a fork's VM teardown.
                let topo = crate::fork_quiesce::topology_lock()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !child_registry.is_live(tid) {
                    drop(topo);
                    child_kicker.unregister(tid);
                    crate::host_signal::forget_thread(tid);
                    child_kernel.dispatcher.forget_thread_signal_state(tid);
                    return;
                }
                match E::materialize_sibling(spec) {
                    Ok(child_engine) => {
                        let handle: Box<dyn carrick_hal::VcpuKickDyn> =
                            Box::new(child_engine.kick_handle());
                        child_kicker.register(tid, handle);
                        drop(topo);
                        if trace {
                            let pc = child_engine.program_counter().unwrap_or(0);
                            eprintln!("[sibling tid#{tid}] vCPU built, pc={pc:#x}, entering loop");
                        }
                        let r = run_vcpu_until_exit(
                            child_kernel,
                            child_engine,
                            child_registry,
                            child_futex,
                            child_platform_futex,
                            child_platform_futex_factory,
                            tid,
                            child_threads,
                            child_kicker,
                            max_traps,
                        );
                        match r {
                            Ok(VcpuLoopOutcome::ProcessExit(result)) => {
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                let _ = unsafe {
                                    libc::write(
                                        1,
                                        result.stdout.as_ptr() as *const _,
                                        result.stdout.len(),
                                    )
                                };
                                let _ = unsafe {
                                    libc::write(
                                        2,
                                        result.stderr.as_ptr() as *const _,
                                        result.stderr.len(),
                                    )
                                };
                                unsafe { libc::_exit(result.exit_code) };
                            }
                            Ok(VcpuLoopOutcome::TrapLimit(_)) | Ok(VcpuLoopOutcome::ThreadDone) => {}
                            Err(e) => {
                                tracing::error!(tid, error = %e, "thread sibling vCPU loop failed");
                                cleanup_registry.exit(tid);
                                cleanup_kicker.unregister(tid);
                                crate::host_signal::forget_thread(tid);
                                cleanup_kernel.dispatcher.forget_thread_signal_state(tid);
                            }
                        }
                    }
                    Err(e) => {
                        drop(topo);
                        tracing::error!(tid, error = %e, "thread sibling vCPU failed to start");
                        child_registry.exit(tid);
                    }
                }
            })
            .map_err(|e| {
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn guest thread failed: {e}"
                )))
            })?;
        self.threads.lock().push(handle);
        Ok(tid)
    }

    fn complete_signal_thread(
        &self,
        engine: &mut E,
        target: ThreadId,
        signum: i32,
    ) -> Result<i64, RuntimeError> {
        let retval: i64 = if self.registry.is_live(target) {
            crate::host_signal::publish_pending_for(target, signum);
            self.kicker.kick(target);
            0
        } else {
            -(crate::linux_abi::LINUX_ESRCH as i64)
        };
        self.complete_returned(engine, retval)
    }

    fn handle_thread_exit(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        code: i32,
        traps: usize,
    ) -> VcpuLoopOutcome {
        if let Some(addr) = self.registry.clear_child_tid(self.this_tid)
            && addr != 0
        {
            let _ = engine.write_bytes(addr, &0i32.to_le_bytes());
            self.futex.wake(addr, 1);
        }
        let last = self.registry.exit(self.this_tid);
        self.kicker.unregister(self.this_tid);
        crate::host_signal::forget_thread(self.this_tid);
        kernel.dispatcher.forget_thread_signal_state(self.this_tid);
        if last {
            let result = assemble_run_result(kernel, code, traps, false);
            VcpuLoopOutcome::ProcessExit(Box::new(result))
        } else {
            // A sibling thread is going away but the process lives on: destroy
            // its vCPU now (the no-op Drop won't), else it leaks live and a
            // later fork's hv_vm_destroy hits HV_BUSY on the dead thread's vCPU.
            engine.destroy_vcpu_on_thread_exit();
            VcpuLoopOutcome::ThreadDone
        }
    }

    fn terminate_siblings_for_exec(
        &self,
        kernel: &Kernel,
        _engine: &mut E,
    ) -> Result<(), RuntimeError> {
        // Linux execve replaces the whole thread group. Carrick's execve path
        // destroys and recreates the process-wide HVF VM, so every sibling vCPU
        // must be gone before `execve_into` runs.
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        kernel.begin_exec_replacement(self.this_tid);
        self.kicker.kick_all_except(self.this_tid);
        self.platform_futex.notify_signal_pending();
        crate::host_signal::wake_all_waiters();

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    kernel.end_exec_replacement();
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "execve thread-group teardown timed out: vcpu_live={} kicker={}",
                        crate::trap::VCPU_LIVE.load(SeqCst),
                        self.kicker.count()
                    ))));
                }
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }

        let removed = self.registry.remove_all_except(self.this_tid);
        for tid in removed {
            self.kicker.unregister(tid);
            crate::host_signal::forget_thread(tid);
            kernel.dispatcher.forget_thread_signal_state(tid);
        }
        kernel.end_exec_replacement();
        Ok(())
    }

    fn handle_execve(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        crate::probes::execve_argv(&path, &argv);
        // The proctitle / /proc/self/cmdline identity is display text; lossily
        // decode the byte argv (a genuinely non-UTF-8 argv is rare).
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let base = path.rsplit('/').next().unwrap_or(&path).to_owned();
        crate::dispatch::set_host_process_name(base.as_bytes());
        let proc_env = env.clone();
        match load_execve_image(&kernel.dispatcher, &path, argv, env) {
            Ok(img) => {
                crate::probes::execve_loaded(
                    &path,
                    img.entry(),
                    img.initial_stack_pointer().unwrap_or(0),
                    img.regions().len() as u64,
                );
                kernel
                    .dispatcher
                    .set_executable_identity(path.clone(), proc_argv, proc_env);
                // Refresh /proc/self/maps + /proc/self/auxv for the new image.
                apply_image_proc_state(&kernel.dispatcher, &img);
                kernel.dispatcher.close_cloexec_fds();
                if self.registry.live_count() > 1 {
                    self.terminate_siblings_for_exec(kernel, engine)?;
                }
                engine.execve_into(&img)?;
                // execve_into rebuilt a fresh vCPU: re-stamp the identity page
                // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
                // vfork: the execve SUCCEEDED and we now have our own private VM.
                // Release the suspended parent by writing one byte to the
                // inherited pipe, then close it. A FAILED execve returns above via
                // `?` WITHOUT releasing — the child then `_exit`s and the parent's
                // `read()` gets EOF instead.
                if let Some(fd) = self.vfork_release_fd.take() {
                    let _ = unsafe { libc::write(fd, [0u8; 1].as_ptr().cast(), 1) };
                    unsafe { libc::close(fd) };
                }
                stop_after_traced_exec(&kernel.dispatcher);
                Ok(())
            }
            Err(errno) => {
                let retval = -(errno as i64);
                engine.complete_syscall(retval)?;
                Ok(())
            }
        }
    }

    fn handle_fork(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        pidfd_out: Option<u64>,
        exit_signal: u32,
        vfork: Option<u64>,
    ) -> Result<Option<i64>, RuntimeError> {
        // vfork (CLONE_VM|CLONE_VFORK): the child SHARES the parent's guest RAM
        // (engine.fork_vfork() below) and the parent vCPU is SUSPENDED here until
        // the child execve's or exits (Parent arm below). An ordinary fork keeps
        // the CoW snapshot and does not suspend.
        // Serialize forks: at most one quiesce/fork in flight. When another fork
        // already holds the token, BLOCK rather than surfacing EAGAIN. Park at the
        // in-flight fork's barrier so it can count this thread as quiesced and
        // complete, then retry the token.
        while !fork_barrier().try_begin_fork() {
            if fork_barrier().is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        // Serialize VM topology against sibling vCPU creation for the whole fork.
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Clear any VM published by a previous fork so siblings that release their
        // vCPUs this round see only THIS fork's republished VM.
        crate::trap::clear_rebuilt_vm_for_fork();
        // Stop-the-world: a multithreaded guest can fork only if every OTHER guest
        // vCPU thread is first paused at its lock-safe run-loop top.
        let mut others = self.kicker.count().saturating_sub(1);
        crate::probes::fork_quiesce(0, others as i64, self.kicker.count() as i64, self.this_tid);
        let mut quiesced = false;
        if others > 0 {
            let barrier = fork_barrier();
            barrier.set_quiescing();
            // Wake every other thread so it reaches the barrier: kick in-guest
            // vCPUs, and nudge blocked futex / io_wait waiters. The flag is set
            // FIRST so a woken thread observes `is_quiescing()` and parks.
            self.kicker.kick_all_except(self.this_tid);
            self.platform_futex.notify_signal_pending();
            crate::host_signal::wake_all_waiters();
            loop {
                // Re-read the LIVE sibling count each iteration. A vCPU that EXITS
                // mid-quiesce drops out of the kicker, so an `others` captured ONCE
                // goes stale-HIGH and wait_quiesced waits for a parker that no
                // longer exists → spins forever (the multithreaded-fork wedge).
                others = self.kicker.count().saturating_sub(1);
                if barrier.wait_quiesced(others, Duration::from_millis(50)) {
                    break;
                }
                crate::probes::fork_quiesce(
                    1,
                    others as i64,
                    barrier.paused_count() as i64,
                    self.this_tid,
                );
                // Do not surface EAGAIN to the guest here. Keep nudging every wait
                // class until all live vCPUs reach the barrier.
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
            }
            quiesced = true;
        }

        // INVARIANT before tearing down the VM: no OTHER guest vCPU is live
        // besides this forker's (VCPU_LIVE == 1). Give the kicked siblings a
        // BOUNDED window (sleeping, NOT spinning) to finish releasing; if it still
        // doesn't hold, ABORT LOUDLY rather than proceed into a corrupting
        // hv_vm_destroy (HV_BUSY).
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        vcpu_live = crate::trap::VCPU_LIVE.load(SeqCst),
                        kicker = self.kicker.count(),
                        others,
                        pid = std::process::id(),
                        "fork quiesce failed to release sibling vCPUs in 5s; aborting \
                         to avoid HV_BUSY VM corruption"
                    );
                    std::process::abort();
                }
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }

        // Publish the arena high-water so the child snapshot's mincore scan is
        // bounded to the guest's used prefix, not all 32 GiB.
        crate::trap::set_guest_arena_high_water(kernel.dispatcher.mmap_arena_high_water());
        // vfork: an inherited pipe to SUSPEND the parent until the child
        // execve/_exit. Created BEFORE the fork so BOTH processes inherit BOTH
        // ends; these are host fds (NOT in the guest fd table). On a pipe() failure
        // degrade to a non-suspending shared fork (vfork_pipe = None).
        let vfork_pipe: Option<(i32, i32)> = if vfork.is_some() {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                }
                Some((fds[0], fds[1]))
            } else {
                None
            }
        } else {
            None
        };
        let prepared_fork = kernel.fork.prepare_host_fork();
        // vfork shares the parent's guest RAM (CLONE_VM); an ordinary fork takes a
        // private CoW snapshot. CRITICAL: gate the SHARE on the suspend pipe
        // existing, NOT on vfork.is_some() — if pipe() failed the parent CANNOT be
        // suspended, and sharing RAM with a running parent silently corrupts guest
        // memory. So a pipe() failure degrades to a plain CoW fork.
        let fork_result = if vfork_pipe.is_some() {
            engine.fork_vfork()
        } else {
            engine.fork()
        };
        let fork_outcome = match fork_result {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                kernel
                    .fork
                    .restart_after_fork_error(prepared_fork, &self.kicker, &self.platform_futex);
                return Err(RuntimeError::Trap(error));
            }
        };

        let retval = match fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
                // Publish the rebuilt VM so quiesced siblings recreate their vCPUs
                // in it, THEN resume them.
                if quiesced {
                    engine.publish_vm_for_siblings()?;
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                let child_exit_needs_signal_pump = kernel
                    .dispatcher
                    .child_exit_signal_needs_pump(self.this_tid, exit_signal);
                kernel.fork.restart_after_parent_fork(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                    child_exit_needs_signal_pump,
                );
                // engine.fork() rebuilt this thread's own vCPU, so its old kicker
                // handle is stale. Re-register the new one (under the topology lock
                // we still hold).
                self.register_vcpu(engine);
                if child_exit_needs_signal_pump {
                    // Watch the child's exit (EVFILT_PROC/NOTE_EXIT) so the signal
                    // pump delivers the requested signal to this (parent) tid when
                    // it exits.
                    crate::host_signal::register_child_exit_watch(
                        child_pid,
                        self.this_tid,
                        i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                    );
                }
                crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                crate::guest_cpu::register_child(child_pid as u32);
                // CLONE_PIDFD: allocate a pidfd for the new child and write its fd
                // to the guest pidfd-out pointer.
                if let Some(addr) = pidfd_out {
                    let fd = kernel
                        .dispatcher
                        .install_child_pidfd(child_pid)
                        .unwrap_or(-1);
                    let _ = engine.write_bytes(addr, &fd.to_le_bytes());
                }
                // PID namespace: allocate the child's ns-pid + record the mapping,
                // and return the ns-pid as the fork retval. Identity when off.
                let retval = i64::from(crate::namespace::pid::register_child(
                    child_pid as u32,
                    std::process::id(),
                ));
                // vfork: SUSPEND this (parent) vCPU thread until the child execve's
                // (it writes one byte) or exits (the OS closes the child's write
                // end → our read() returns EOF). We still hold `_topology`, so no
                // concurrent fork can quiesce us. Retry on EINTR.
                if let Some((vf_read, _vf_write)) = vfork_pipe {
                    unsafe { libc::close(_vf_write) }; // parent only reads
                    // Bounded suspend: the child should execve/_exit within ms, but
                    // a pathological guest must NOT wedge the parent forever — we
                    // still hold topology_lock here. Poll with a deadline; on expiry
                    // resume the parent DEGRADED with a loud diagnostic.
                    const VFORK_SUSPEND_TIMEOUT: Duration = Duration::from_secs(60);
                    let deadline = std::time::Instant::now() + VFORK_SUSPEND_TIMEOUT;
                    let mut byte = [0u8; 1];
                    loop {
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            tracing::error!(
                                child_pid,
                                "vfork parent-suspend timed out (60s) waiting for child \
                                 execve/_exit; resuming parent degraded"
                            );
                            break;
                        }
                        let remaining_ms =
                            (deadline - now).as_millis().min(i32::MAX as u128) as i32;
                        let mut pfd = libc::pollfd {
                            fd: vf_read,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let r = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
                        if r > 0 {
                            // Readable: a byte (child execve'd) or EOF (child exited).
                            let _ = unsafe { libc::read(vf_read, byte.as_mut_ptr().cast(), 1) };
                            break;
                        }
                        if r == 0 {
                            continue; // deadline re-checked at loop top
                        }
                        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                            break; // unexpected poll error — stop waiting
                        }
                        // EINTR → re-poll on the remaining budget.
                    }
                    unsafe { libc::close(vf_read) };
                    // The vfork child shared the parent's guest RAM until it
                    // execve'd or exited. Its child-side identity stamp therefore
                    // overwrote the shared EL1 shim identity page; restore the
                    // parent's getpid/get*id fast-path values before resuming it.
                    stamp_identity_page(engine, &kernel.dispatcher);
                }
                retval
            }
            crate::trap::ForkOutcome::Child => {
                kernel.dispatcher.clear_output_buffers();
                // A forked child must NOT inherit its PARENT's vfork suspend-pipe
                // write end (copied across libc::fork). Drop the inherited copy so
                // only the genuine vfork child holds the writer.
                if let Some(stale) = self.vfork_release_fd.take() {
                    unsafe { libc::close(stale) };
                }
                // vfork: keep the WRITE end of OUR suspend pipe (close the read end
                // the parent owns).
                if let Some((vf_read, vf_write)) = vfork_pipe {
                    unsafe { libc::close(vf_read) };
                    self.vfork_release_fd = Some(vf_write);
                }
                // vfork with an explicit child_stack (clone's stack arg != 0): run
                // the child on it.
                if let Some(child_stack) = vfork
                    && child_stack != 0
                    && let Err(e) = engine.set_guest_sp_el0(child_stack)
                {
                    tracing::warn!(?e, "vfork: failed to set child SP_EL0");
                }
                // Don't inherit the parent's accumulated guest CPU time.
                crate::guest_cpu::reset();
                let parent_tid = self.this_tid;
                self.this_tid = std::process::id() as ThreadId;
                // The child inherits the parent's blocked mask + alternate signal
                // stack (POSIX) but has a NEW tid; re-key the dispatcher's per-tid
                // signal state.
                kernel
                    .dispatcher
                    .migrate_thread_signal_state(parent_tid, self.this_tid);
                self.registry = Arc::new(ThreadRegistry::new(self.this_tid));
                crate::thread::set_current_registry(Arc::clone(&self.registry));
                // The other guest threads do not exist in the child (libc::fork
                // replicated only the calling thread). Drop their stale bookkeeping:
                // a fresh futex table (no phantom waiters), a fresh kicker (only
                // this vCPU is registered below), and an empty thread-handle vec.
                // The fresh kicker comes from `fresh_fork_kicker()` (object-safe,
                // so the loop never names the concrete kicker); the fresh concrete
                // private-futex table is built here and the matching `PlatformFutex`
                // is derived from it via the threaded-through factory, so the two
                // stay over the SAME table (the notify-signal-pending consistency
                // invariant) without naming the backend.
                let fresh_kicker = engine.fresh_fork_kicker();
                self.kicker = fresh_kicker;
                self.futex = Arc::new(crate::thread::FutexTable::new());
                self.platform_futex = (self.platform_futex_factory)(Arc::clone(&self.futex));
                self.threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
                // Clear the quiesce + fork flags the child inherited (copied) from
                // the parent so the child's single-threaded run loop runs.
                fork_barrier().end_quiesce();
                fork_barrier().end_fork();
                crate::event_ring::reinit_after_fork();
                crate::host_signal::reinit_after_fork();
                // PID namespace: block until the parent registered our ns-pid
                // before any guest code runs. No-op when ns off.
                crate::namespace::pid::await_self_registration();
                // Re-stamp identity + tid: the child's pid changed and the vCPU was
                // rebuilt.
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
                self.waiter = crate::io_wait::ThreadWaiter::new(self.this_tid);
                let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
                self.kicker.register(self.this_tid, handle);
                self.registry
                    .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
                kernel
                    .fork
                    .restart_after_child_fork(prepared_fork, &self.kicker, &self.platform_futex);
                0
            }
        };
        Ok(Some(retval))
    }
}

/// Run one vCPU (one guest thread) until it exits the process, finishes its own
/// thread, or hits the trap limit. Holds NO lock during the vCPU run; takes the
/// dispatcher lock only to dispatch + complete each syscall.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_vcpu_until_exit<E: ThreadedEngine + 'static>(
    kernel: Kernel,
    mut engine: E,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    platform_futex_factory: PlatformFutexFactory,
    this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    kicker: Arc<dyn VcpuRegistry>,
    max_traps: usize,
) -> Result<VcpuLoopOutcome, RuntimeError>
where
    E::SiblingSpec: 'static,
{
    let mut state = ThreadRuntimeState::new(
        registry,
        futex,
        platform_futex,
        platform_futex_factory,
        this_tid,
        threads,
        kicker,
        max_traps,
    );
    state.register_vcpu(&engine);
    // Stamp this thread's tid into TPIDR_EL1 for the EL1 gettid fast path (main
    // thread at boot; each worker at spawn). Re-stamped after fork/exec below.
    stamp_guest_tid(&engine, state.this_tid, &state.registry);
    // Run the vCPU loop in a closure so we can run vCPU cleanup on EVERY exit
    // path — `?` errors, early returns, and the trap-limit fall-through alike.
    let result: Result<VcpuLoopOutcome, RuntimeError> = (|| {
        for traps in 1..=state.max_traps {
            if kernel.exec_replacing_other_thread(state.this_tid) {
                return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
            }
            // Lock-safe point: no carrick lock is held here. If another thread is
            // forking a multithreaded guest, release this vCPU (so the forker can
            // hv_vm_destroy), park until the fork completes, then recreate the vCPU
            // in the parent's rebuilt VM and resume.
            if fork_barrier().is_quiescing() {
                state.release_and_park_vcpu_for_fork(&mut engine)?;
            }
            // Page-table-edit Pause-Modify-Resume: if a sibling vCPU is editing the
            // shared stage-1 tables from the host, park here (KEEPING this vCPU —
            // unlike fork) until it finishes.
            if pt_barrier().is_quiescing() {
                pt_barrier().park();
            }
            // Publish that we are about to enter the guest (and may walk page
            // tables). The store here and the re-check below form a Dekker
            // handshake with the edit coordinator, which sets `quiescing` then
            // reads `in_guest`: SeqCst guarantees at least one side observes the
            // other, so this vCPU never enters guest concurrently with an edit.
            state
                .in_guest
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if pt_barrier().is_quiescing() {
                state
                    .in_guest
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                pt_barrier().park();
                continue;
            }
            // ---- vCPU run: NO dispatcher lock held ----
            let next = engine.next_syscall();
            // Out of guest now (in host): a coordinator may proceed past us.
            state
                .in_guest
                .store(false, std::sync::atomic::Ordering::SeqCst);
            let frame = match next {
                Ok(Some(f)) => f,
                Ok(None) => {
                    // The vCPU was forced out of the guest by a cross-thread kick
                    // (hv_vcpus_exit) with no syscall pending — deliver a signal at
                    // the interrupted PC, then resume.
                    let pc = engine.current_pc()?;
                    if let Some(outcome) = service_signals_threaded(
                        &kernel,
                        &mut engine,
                        state.this_tid,
                        None,
                        Some(pc),
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                    continue;
                }
                Err(TrapError::EL0Fault {
                    syndrome,
                    elr,
                    far,
                    from_el0_direct,
                    ..
                }) => {
                    // A synchronous guest EL0 fault (nil deref, bad access). Deliver
                    // it to the guest as SIGSEGV/SIGBUS (Linux semantics).
                    if let Some(outcome) = deliver_fault_signal(
                        &kernel,
                        &mut engine,
                        state.this_tid,
                        syndrome,
                        elr,
                        far,
                        from_el0_direct,
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            state.trace_syscall(traps, frame);

            // ---- syscall service: no dispatcher-wide lock held ----
            let outcome = state.service_threaded_syscall(&kernel, &mut engine, frame)?;

            let mut last_syscall_retval: Option<i64> = None;

            match outcome {
                DispatchOutcome::WaitOnFds { .. }
                | DispatchOutcome::BlockingHostWrite(_)
                | DispatchOutcome::WaitOnFdsSelect { .. }
                | DispatchOutcome::WaitOnPollFds { .. }
                | DispatchOutcome::WaitOnProcExit { .. }
                | DispatchOutcome::WaitOnSignals { .. }
                | DispatchOutcome::WaitOnSleep { .. } => {
                    last_syscall_retval =
                        Some(state.complete_errno(&mut engine, crate::linux_abi::LINUX_EINTR)?);
                }
                DispatchOutcome::Exit { code } => {
                    crate::trap::dump_kick_stats();
                    // A forked child process (real macOS fork) exits via _exit so
                    // the rebuilt HVF context doesn't run the panicky Drops.
                    if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                        crate::probes::guest_exit(code);
                        forked_child_exit(
                            code,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    // exit_group, or exit(2) as the last live thread. Tear the whole
                    // process down.
                    let last = state.registry.exit(state.this_tid);
                    if !last {
                        // exit_group(94) or fatal process termination: flush shared
                        // buffers and terminate the entire host process.
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        let out = kernel.dispatcher.stdout();
                        let err = kernel.dispatcher.stderr();
                        let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                        let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                        unsafe { libc::_exit(code) };
                    }
                    let result = assemble_run_result(&kernel, code, traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
                DispatchOutcome::SignalDeath { signum } => {
                    crate::trap::dump_kick_stats();
                    if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                        forked_child_die_by_signal(
                            signum,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    let code = 128 + signum;
                    let last = state.registry.exit(state.this_tid);
                    if !last {
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        let out = kernel.dispatcher.stdout();
                        let err = kernel.dispatcher.stderr();
                        let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                        let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                        unsafe { libc::_exit(code) };
                    }
                    let result = assemble_run_result(&kernel, code, traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
                DispatchOutcome::Returned { value } => {
                    last_syscall_retval = Some(state.complete_returned(&mut engine, value)?);
                }
                DispatchOutcome::Errno { errno } => {
                    last_syscall_retval = Some(state.complete_errno(&mut engine, errno)?);
                }
                DispatchOutcome::FutexWait { wait, timeout } => {
                    // Block with the dispatcher lock RELEASED so a sibling FUTEX_WAKE
                    // can run.
                    last_syscall_retval =
                        Some(state.complete_futex_wait(&mut engine, wait, timeout)?);
                }
                DispatchOutcome::SharedFutexWait {
                    host_addr,
                    value,
                    timeout,
                } => {
                    // Cross-process futex (MAP_SHARED): block on the host __ulock
                    // keyed by the shared physical page, with the dispatcher lock
                    // released. Interruptible by a signal deliverable to this thread.
                    last_syscall_retval = Some(state.complete_shared_futex_wait(
                        &mut engine,
                        host_addr,
                        value,
                        timeout,
                    )?);
                }
                DispatchOutcome::CloneThread {
                    stack,
                    tls,
                    flags: _,
                    parent_tid_addr,
                    child_tid_addr,
                } => {
                    let tid = state.spawn_clone_thread(
                        &kernel,
                        &mut engine,
                        stack,
                        tls,
                        parent_tid_addr,
                        child_tid_addr,
                    )?;
                    state.complete_returned(&mut engine, tid as i64)?;
                }
                DispatchOutcome::ThreadExit { code } => {
                    return Ok(state.handle_thread_exit(&kernel, &mut engine, code, traps));
                }
                DispatchOutcome::SignalThread {
                    tid: target,
                    signum,
                } => {
                    last_syscall_retval =
                        Some(state.complete_signal_thread(&mut engine, target, signum)?);
                }
                DispatchOutcome::Execve { path, argv, env } => {
                    crate::event_ring::rec(crate::event_ring::EXEC, 1, 0, 0);
                    state.handle_execve(&kernel, &mut engine, path, argv, env)?;
                }
                DispatchOutcome::SigReturn => {
                    let restored_sigmask = engine.restore_from_sigframe()?;
                    kernel
                        .dispatcher
                        .restore_signal_mask(state.this_tid, restored_sigmask);
                    // Deliver the next pending signal (if any) before resuming.
                }
                DispatchOutcome::Fork {
                    pidfd_out,
                    exit_signal,
                    vfork,
                } => {
                    if let Some(retval) =
                        state.handle_fork(&kernel, &mut engine, pidfd_out, exit_signal, vfork)?
                    {
                        last_syscall_retval = Some(state.complete_returned(&mut engine, retval)?);
                    }
                }
                DispatchOutcome::SetMemoryModel { tso } => {
                    // Rosetta requested hardware x86_64 TSO on this vCPU.
                    engine.set_memory_model(hardware_tso_for_debug(tso))?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, 0)?);
                }
                DispatchOutcome::MapHostAlias {
                    va,
                    ipa,
                    len,
                    payload,
                    file,
                } => {
                    engine.map_host_alias(va, ipa, len, &payload, file)?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, va as i64)?);
                }
            }

            if kernel.dispatcher.take_signal_pump_request() {
                kernel
                    .fork
                    .start_signal_pump(&state.kicker, &state.platform_futex);
            }

            state.trace_syscall_return(traps, last_syscall_retval);

            // Signal delivery. A signal targeted at THIS tid (guest tgkill/tkill)
            // takes priority; otherwise a process-directed signal in the global
            // slot is deliverable by any thread.
            if let Some(outcome) = service_signals_threaded(
                &kernel,
                &mut engine,
                state.this_tid,
                last_syscall_retval,
                None,
                traps,
            )? {
                return Ok(outcome);
            }
        }

        let result = assemble_run_result(&kernel, -1, state.max_traps, true);
        Ok(VcpuLoopOutcome::TrapLimit(Box::new(result)))
    })();
    // This thread is leaving its vCPU loop. The engine's Drop is a no-op, so
    // destroy the vCPU here on every path EXCEPT ProcessExit (the whole process
    // is exiting) and ThreadDone (handle_thread_exit already destroyed it).
    if !matches!(
        &result,
        Ok(VcpuLoopOutcome::ProcessExit(_)) | Ok(VcpuLoopOutcome::ThreadDone)
    ) {
        engine.destroy_vcpu_on_thread_exit();
    }
    result
}

/// Snapshot the shared kernel buffers + reporter into a RunResult. Called on
/// whole-process exit / trap limit.
pub(crate) fn assemble_run_result(
    kernel: &Kernel,
    exit_code: i32,
    traps: usize,
    trap_limit_hit: bool,
) -> RunResult {
    crate::probes::guest_exit(exit_code);
    let report = kernel.reporter.snapshot();
    RunResult {
        exit_code,
        stdout: kernel.dispatcher.stdout(),
        stderr: kernel.dispatcher.stderr(),
        traps,
        report,
        trap_limit_hit,
    }
}

/// Outcome of `deliver_pending_signal`.
pub(crate) struct PendingSignalAction {
    pub(crate) term_signal: Option<i32>,
    pub(crate) stop_signal: Option<i32>,
}

impl PendingSignalAction {
    fn ignored() -> Self {
        Self {
            term_signal: None,
            stop_signal: None,
        }
    }

    fn terminate(signum: i32) -> Self {
        Self {
            term_signal: Some(signum),
            stop_signal: None,
        }
    }

    fn stop(signum: i32) -> Self {
        Self {
            term_signal: None,
            stop_signal: Some(signum),
        }
    }
}

/// Drain whatever signal is sitting in the host pending slot and dispatch it to
/// the guest. Returns `Ok(None)` when nothing was pending.
pub(crate) fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    // Drain the cross-process explicit-signal ring into pending state, so the
    // normal delivery below runs each with the sender's identity.
    dispatcher.drain_xsignals_for_tid(tid);

    let pending = crate::host_signal::take_pending_for(tid);
    let pending = if pending == 0 {
        // Nothing newly arrived in the host slot. Deliver the next signal that was
        // raised while blocked and has since been unblocked.
        match dispatcher.take_deliverable_pending(tid) {
            Some(s) => s,
            None => return Ok(None),
        }
    } else {
        pending
    };
    crate::probes::signal_deliver(tid, pending);
    // A blocked signal must not be delivered — hold it pending until the guest
    // unblocks it.
    if dispatcher.signal_blocked(tid, pending) {
        dispatcher.mark_signal_pending(tid, pending);
        return Ok(Some(PendingSignalAction::ignored()));
    }
    if dispatcher.signal_is_ignored(pending) {
        return Ok(Some(PendingSignalAction::ignored()));
    }
    match dispatcher.registered_signal_handler(pending) {
        Some(action) => {
            // Block the signal (+ its sa_mask) for the duration of the handler, as
            // the kernel does — restored by rt_sigreturn.
            let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
                action.sa_restorer
            } else {
                0
            };
            // SA_ONSTACK: run the handler on the alternate signal stack if one is
            // installed.
            let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
                dispatcher.signal_altstack(tid)
            } else {
                None
            };
            // SA_RESTART: if this handler interrupted a blocking, restartable
            // syscall that returned EINTR, restart it instead of surfacing the
            // EINTR.
            let restart_syscall = interrupted_pc.is_none()
                && last_syscall_retval == Some(-(crate::linux_abi::LINUX_EINTR as i64))
                && action.sa_flags & crate::linux_abi::LINUX_SA_RESTART != 0
                && trap.last_syscall_nr().is_some_and(is_restartable_syscall);
            let saved_sigmask = dispatcher.enter_signal_handler(tid, pending, action);
            // If rt_sigqueueinfo queued a caller-supplied siginfo for this (tid,
            // signum), pop it now and hand it to inject_signal. Failing that,
            // synthesise an SI_USER siginfo with the sender's ns-pid.
            let queued_siginfo = dispatcher.take_pending_siginfo(tid, pending).or_else(|| {
                let sender_host = crate::host_signal::last_sender_for(pending);
                (sender_host > 0).then(|| {
                    let ns_pid =
                        crate::namespace::pid::host_to_ns_or_self(sender_host as u32) as i32;
                    let uid = crate::cred_ipc::read_target(sender_host).unwrap_or(0);
                    crate::linux_abi::LinuxSiginfo::kill(
                        pending,
                        crate::linux_abi::LINUX_SI_USER,
                        ns_pid,
                        uid,
                    )
                })
            });
            match trap.inject_signal(
                pending,
                action.sa_handler,
                restorer,
                last_syscall_retval,
                interrupted_pc,
                altstack,
                saved_sigmask,
                None, // SI_USER-shaped (tkill/sysmon); faults use deliver_fault_signal
                queued_siginfo,
                restart_syscall,
            ) {
                Ok(()) => Ok(Some(PendingSignalAction::ignored())),
                // Linux force_sigsegv: the signal frame couldn't be written to the
                // user stack. Terminate the whole thread-group by SIGSEGV (exit
                // 139).
                Err(TrapError::SignalDeliveryFault) => {
                    Ok(Some(PendingSignalAction::terminate(11))) // SIGSEGV
                }
                Err(e) => Err(e.into()),
            }
        }
        // No registered handler → the kernel takes the signal's DEFAULT action.
        None if is_default_ignore_signal(pending) => Ok(Some(PendingSignalAction::ignored())),
        None if is_default_stop_signal(pending) => Ok(Some(PendingSignalAction::stop(pending))),
        None => Ok(Some(PendingSignalAction::terminate(pending))),
    }
}

/// Linux aarch64 syscall numbers that auto-restart when interrupted by an
/// SA_RESTART handler (the kernel's `ERESTARTSYS` set).
fn is_restartable_syscall(nr: u64) -> bool {
    matches!(
        nr,
        95  // waitid
        | 260 // wait4
    )
}

/// Signals whose DEFAULT disposition is "ignore" (Linux `Ign`).
fn is_default_ignore_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGCHLD
            | crate::linux_abi::LINUX_SIGURG
            | crate::linux_abi::LINUX_SIGWINCH
    )
}

fn is_default_stop_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGSTOP
            | crate::linux_abi::LINUX_SIGTSTP
            | crate::linux_abi::LINUX_SIGTTIN
            | crate::linux_abi::LINUX_SIGTTOU
    )
}

/// Run signal delivery for one iteration of the multi-threaded vCPU loop. Returns
/// `Some(outcome)` when a default-action (terminate) signal fires and the process
/// should end; `None` to keep running.
fn service_signals_threaded<E: ThreadedEngine>(
    kernel: &Kernel,
    engine: &mut E,
    this_tid: ThreadId,
    last_syscall_retval: Option<i64>,
    interrupted_pc: Option<u64>,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    {
        if let Some(action) = deliver_pending_signal(
            engine,
            &kernel.dispatcher,
            last_syscall_retval,
            this_tid,
            interrupted_pc,
        )? {
            if let Some(signum) = action.stop_signal {
                stop_by_signal(signum);
                return Ok(None);
            }
            if let Some(signum) = action.term_signal {
                if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                    let out = kernel.dispatcher.stdout();
                    let err = kernel.dispatcher.stderr();
                    forked_child_die_by_signal(signum, &out, &err);
                }
                let result = assemble_run_result(kernel, 128 + signum, traps, false);
                return Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ignore_signals_are_not_terminating() {
        // SIGCHLD/SIGURG/SIGWINCH default to Ign — a no-handler instance is
        // dropped, not terminated. SIGURG=23 is the one that made `go build`
        // flaky (raise(SIGURG) is a host no-op → _exit(128+23)=151).
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGURG));
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGCHLD));
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGWINCH));
        // Genuinely-terminating defaults must NOT be treated as ignore.
        assert!(!is_default_ignore_signal(crate::linux_abi::LINUX_SIGINT)); // 2
        assert!(!is_default_ignore_signal(crate::linux_abi::LINUX_SIGTERM)); // 15
        assert!(!is_default_ignore_signal(13)); // SIGPIPE: default IS terminate
        assert!(!is_default_ignore_signal(11)); // SIGSEGV
    }

    // Linux asm-generic/siginfo.h SIGTRAP si_codes.
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1;
    const TRAP_TRACE: i32 = 2;
    const TRAP_HWBKPT: i32 = 4;

    fn esr(ec: u64) -> u64 {
        ec << 26
    }

    #[test]
    fn brk_aarch64_maps_to_sigtrap_brkpt() {
        // EC=0x3c is `BRK #imm` from AArch64 — the in-guest software breakpoint
        // Go's debug-call protocol hits. Linux delivers SIGTRAP/TRAP_BRKPT.
        assert_eq!(el0_debug_signal(esr(0x3c)), Some((SIGTRAP, TRAP_BRKPT)));
    }

    #[test]
    fn software_step_maps_to_sigtrap_trace() {
        // EC=0x32/0x33 software-step exception → SIGTRAP/TRAP_TRACE (PTRACE_SINGLESTEP).
        assert_eq!(el0_debug_signal(esr(0x32)), Some((SIGTRAP, TRAP_TRACE)));
        assert_eq!(el0_debug_signal(esr(0x33)), Some((SIGTRAP, TRAP_TRACE)));
    }

    #[test]
    fn hw_breakpoint_and_watchpoint_map_to_sigtrap_hwbkpt() {
        // EC=0x30/0x31 HW breakpoint, 0x34/0x35 watchpoint → SIGTRAP/TRAP_HWBKPT.
        assert_eq!(el0_debug_signal(esr(0x30)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x31)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x34)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x35)), Some((SIGTRAP, TRAP_HWBKPT)));
    }

    #[test]
    fn non_debug_faults_are_not_debug_signals() {
        // Aborts and unknown classes are NOT debug exceptions — they stay on the
        // SIGSEGV/SIGBUS path (`el0_fault_signal`), so the classifier returns None.
        assert_eq!(el0_debug_signal(esr(0x20)), None); // instruction abort
        assert_eq!(el0_debug_signal(esr(0x24)), None); // data abort
        assert_eq!(el0_debug_signal(esr(0x00)), None); // unknown
    }}
