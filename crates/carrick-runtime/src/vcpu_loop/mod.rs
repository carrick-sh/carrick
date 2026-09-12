//! The multi-threaded vCPU run loop, hoisted out of the macOS-only `runtime`
//! module and made generic over [`carrick_hal::ThreadedEngine`].
//!
//! # One host thread + one vCPU per guest thread
//!
//! Carrick binds one host thread and one engine vCPU to each guest thread, all
//! sharing ONE process VM (stage-2 mappings are visible to every vCPU). The MAIN
//! guest thread enters `run_vcpu_until_exit`; a thread-creating `clone(2)`
//! spawns a sibling host thread that builds its own vCPU in the same VM and runs
//! the same function (`ThreadRuntimeState::spawn_clone_thread`).
//!
//! Shared kernel-half state lives behind [`KernelState`] (an `Arc`, each
//! subsystem internally synchronised). The engine-specific lifecycle — kick,
//! fork/exec VM surgery, per-thread materialisation, the private/shared futex
//! backend — is reached only through the [`carrick_hal`] traits
//! ([`ThreadedEngine`], [`VcpuRegistry`], [`PlatformFutex`],
//! [`SignalPumpControl`]), so this module names no concrete backend.
//!
//! # The two futex paths (the key seam)
//!
//! The loop threads BOTH a CONCRETE `Arc<carrick_thread::thread::FutexTable>`
//! (the process-private futex table, used UNCHANGED by `dispatch_threaded` and
//! `ThreadRuntimeState::complete_futex_wait` so the generation-snapshot
//! lost-wake handshake stays byte-identical) AND an object-safe
//! `Arc<dyn PlatformFutex>` (used only for the SHARED-futex ops and the
//! signal-pending notifications, which differ HVF-ulock vs KVM-`SYS_futex`). On
//! HVF the `PlatformFutex` wraps the SAME `FutexTable`, so they stay consistent.
//!
//! # Fork / page-table-edit stop-the-world
//!
//! See the original prose in `runtime.rs`: a guest `fork(2)` from a
//! multithreaded guest quiesces every other live vCPU at its lock-safe run-loop
//! top (`ThreadRuntimeState::handle_fork`); a stage-1 page-table edit is a
//! lighter Pause-Modify-Resume that keeps every vCPU alive
//! (`ThreadRuntimeState::pt_pause`). The `in_guest` ↔ `quiescing` Dekker
//! handshake (SeqCst on both sides) is preserved verbatim in
//! `run_vcpu_until_exit`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_fatal::carrick_fatal;
use parking_lot::{Condvar, Mutex};

use carrick_hal::{PlatformFutex, SignalPumpControl, ThreadedEngine, VcpuRegistry};

use crate::compat::CompatReporter;
use crate::dispatch::routing::{MutationDispatchRoute, OrdinaryDispatchRoute};
use crate::dispatch::{
    CurrentMmMemory, DispatchError, DispatchOutcome, PreparedDispatch, PreparedSyscall,
    SyscallCompletionToken, SyscallDispatcher, SyscallRequest, ThreadCtx,
};
use crate::linux_abi::LinuxErrno;
use crate::memory::AddressSpace;
use crate::run_result::{RunResult, RuntimeError};
use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::trap::{SyscallTrap, TrapError};

pub mod continuation;
pub mod executor;

const SIGNAL_WAIT_SLICE: Duration = Duration::from_millis(50);

/// vCPU reclaim census.
///
/// The M:N scheduler design removes the destroy/recreate reclaim path
/// entirely, and the rule is that the win must be measured before the path is
/// deleted rather than assumed. A cutoff sweep only bounds the reclaims the
/// 250 ms cutoff currently SUPPRESSES (measured at ~+9% CPU); it cannot say
/// what today's reclaims actually cost. These counters can.
///
/// Three relaxed atomics on a path that already destroys and recreates an HVF
/// vCPU are not measurable overhead.
pub(crate) static VCPU_RECLAIMS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(crate) static VCPU_RECLAIM_PARK_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
pub(crate) static VCPU_RECLAIM_RESUME_NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Totals for this process: (reclaims, park ns, resume ns).
pub(crate) fn vcpu_reclaim_census() -> (u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        VCPU_RECLAIMS.load(Relaxed),
        VCPU_RECLAIM_PARK_NS.load(Relaxed),
        VCPU_RECLAIM_RESUME_NS.load(Relaxed),
    )
}

pub(crate) mod memory;
pub(crate) use memory::{
    KernelForeignCowProof, KernelFrameCowAuthority, apply_alias_frame_inventory,
    apply_exec_image_proc_state, apply_image_proc_state, ns_visible_guest_tid,
    refuse_alias_install, requires_no_unwind_host_exit, stamp_identity_page,
    stamp_identity_page_at, stamp_identity_values, stamp_ns_visible_guest_tid,
    syscall_takes_pre_dispatch_pt_pause, with_foreign_mm_mutation_guard, with_sole_mm_stage1,
};
#[cfg(test)]
pub(crate) use memory::{
    fixed_frame_cow_owner_inventory_for_test, kernel_frame_cow_authority_for_test,
    with_real_pt_pause_for_test,
};

// ---------------------------------------------------------------------------
// NON-engine helpers the generic loop calls.
//
// On macOS these live in `crate::runtime::exec`: `load_execve_image` builds the
// HVF AddressSpace, and the no-unwind forked-child death paths flush stdio +
// `_exit`/`raise`. The generic loop reaches them through this thin shim.
//
// On the non-macOS (Linux/KVM) build the generic `run_vcpu_until_exit` IS now
// instantiated (`run_threaded_kvm_loop`, Task 7), so the child-shutdown /
// signal-death helpers below are REAL portable-libc implementations — NOT
// `unreachable!()`. Only `load_execve_image` (HVF image builder) and
// `hardware_tso_for_debug` (Apple TSO) remain macOS-only stubs.
// ---------------------------------------------------------------------------
#[cfg(feature = "platform-macos")]
use crate::runtime::exec::{
    forked_child_die_by_signal, load_execve_image, stop_after_traced_exec, stop_by_signal,
};
#[cfg(feature = "platform-macos")]
use crate::runtime::hardware_tso_for_debug;

/// Attach the architecture-appropriate VMM vDSO after sealing the live
/// dispatcher's fast-path visibility. Carrick has no x86_64 no-fastpaths vDSO
/// image yet, so the fail-closed x86 choice is to omit AT_SYSINFO_EHDR and the
/// mapping entirely; libc then uses ordinary syscalls. AArch64 retains the
/// existing no-fastpaths image because it still provides rt_sigreturn.
#[cfg(any(
    test,
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn with_vmm_vdso_for_dispatcher<A: carrick_hal::GuestArch>(
    image: AddressSpace,
    dispatcher: &SyscallDispatcher,
    requires_syscall_traps: bool,
) -> Result<AddressSpace, carrick_mem::memory::AddressSpaceError> {
    let requires_syscall_traps = requires_syscall_traps || dispatcher.requires_syscall_traps();
    if requires_syscall_traps && A::linux_guest_abi() == carrick_abi::LinuxGuestAbi::X86_64 {
        return Ok(image.with_vdso_auxv(false));
    }
    crate::vdso_policy::with_optional_vdso_for_clock_with_visibility::<A>(
        image,
        dispatcher.container().clock(),
        requires_syscall_traps,
    )
}

// On the non-macOS (Linux/KVM) build the generic `run_vcpu_until_exit` IS now
// instantiated — `run_threaded_kvm_loop` (Phase 2 Task 7) drives it for
// fork/execve/threads/futex guests. So the forked-child shutdown and
// default-signal-death helpers must be REAL here, not `unreachable!()`: their
// bodies are portable libc (`_exit`, `raise`, `sigprocmask`) plus the
// cross-platform `crate::guest_cpu` / `crate::host_signal` shims, identical to
// the macOS versions in `crate::runtime::exec`. Without them a forked child that
// runs `exit_group`/dies-by-signal panics instead of `_exit`ing with the guest's
// code (the `shared-futex-fork` exit-5 bug: the child reached `_exit(7)` but the
// stub panicked, so the parent's `wait4` saw the wrong status).
//
// `load_execve_image` (HVF AddressSpace builder) and `hardware_tso_for_debug`
// (Apple TSO) stay genuinely macOS-only stubs — the KVM execve path builds its
// own image (Task 7d) and KVM has no Rosetta TSO toggle.
#[cfg(any(
    test,
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
#[cfg_attr(
    all(test, feature = "platform-macos"),
    allow(dead_code, unused_imports)
)]
#[allow(unused_variables, clippy::needless_pass_by_value)]
mod macos_helper_stubs {
    use super::{AddressSpace, SyscallDispatcher};

    fn execve_trace_filter() -> Option<Option<String>> {
        static FILTER: std::sync::OnceLock<Option<Option<String>>> = std::sync::OnceLock::new();
        FILTER
            .get_or_init(|| {
                std::env::var_os("CARRICK_EXECVE_TRACE").map(|value| {
                    let value = value.to_string_lossy();
                    if value.is_empty() || value == "1" {
                        None
                    } else {
                        Some(value.into_owned())
                    }
                })
            })
            .clone()
    }

    fn trace_execve(path: &str, args: std::fmt::Arguments<'_>) {
        let Some(filter) = execve_trace_filter() else {
            return;
        };
        if filter.as_ref().is_none_or(|needle| path.contains(needle)) {
            eprintln!("[EXECVE] {args}");
        }
    }

    /// KVM execve image builder — the Linux twin of `crate::runtime::exec::
    /// load_execve_image`. It resolves the target through the dispatcher's
    /// exec-file reader (overlay/rootfs first, then the host fs) and shebangs,
    /// then builds a KVM-flavored `AddressSpace`: ELF segments + vdso/auxv +
    /// the Linux initial stack, but NO syscall shim, NO Rosetta redirect, and NO
    /// EL0 trampoline / stage-1 tables / EL1 vectors (KVM's `execve_into` →
    /// `GuestRam::build_for_image` adds the sentinel-vector bring-up pages
    /// itself, mirroring `run_elf_real_dispatch`'s boot image). Returns `-errno`
    /// (as a positive `i32` Linux errno) on any load failure, exactly like the
    /// macOS twin, so the dispatcher reports the same execve(2) error to the guest.
    pub(super) fn load_execve_image(
        dispatcher: &SyscallDispatcher,
        path: &str,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
        requires_syscall_traps: bool,
    ) -> Result<AddressSpace, crate::linux_abi::LinuxErrno> {
        use crate::linux_abi::LINUX_ENOENT;
        let argv = if argv.is_empty() {
            vec![path.as_bytes().to_vec()]
        } else {
            argv
        };
        // Absolutize a relative target against the guest cwd, then resolve any
        // `#!` shebang to its interpreter via the shared cross-platform helper.
        let named_target = dispatcher.resolve_exec_path(path);
        // fanotify FAN_OPEN_EXEC, kept in step with the macOS twin in
        // `crate::runtime::exec::load_execve_image` so the two lanes report the
        // same events. (This lane has no `check_exec_target` gate, so the event
        // precedes validation here; a load failure below still aborts the exec.)
        dispatcher.fanotify_notify_exec(&named_target);
        let (path, argv) =
            crate::exec_helpers::resolve_shebang(dispatcher, named_target.clone(), argv)?;
        if path != named_target {
            dispatcher.fanotify_notify_exec(&path);
        }
        trace_execve(&path, format_args!("load path={path}"));
        // Read the binary overlay-first. Fall back to the literal host fs ONLY
        // for a bare run-elf boot (host-staged target, no container fs). In a
        // container run the fallback is OFF, so a target absent from the rootfs
        // ENOENTs instead of silently loading the matching HOST binary (the
        // containment hole that loaded host glibc `/usr/bin/echo` into a musl
        // rootfs mid-execvp PATH search).
        let host_fallback = dispatcher.exec_host_fs_fallback();
        let host_read = |p: &str| -> Option<Vec<u8>> {
            if host_fallback {
                std::fs::read(p).ok()
            } else {
                None
            }
        };
        let raw_bytes = match dispatcher
            .read_exec_file(&path)
            .or_else(|| host_read(&path))
        {
            Some(bytes) => {
                trace_execve(
                    &path,
                    format_args!("main path={path} bytes={}", bytes.len()),
                );
                bytes
            }
            None => {
                trace_execve(&path, format_args!("main path={path} missing"));
                return Err(LINUX_ENOENT);
            }
        };
        // The ELF machine this lane accepts. The byte-based loader otherwise
        // defaults to EM_AARCH64 (the aarch64 KVM lane); the x86_64 lanes
        // (KVM-x86, bhyve) MUST pass EM_X86_64 or an x86_64 execve target is
        // rejected as a machine mismatch → the dispatcher would ENOENT the
        // execve (trap-confirmed on the bhyve lane: a static-musl x86_64 execd
        // failed to load until the machine was threaded through). Resolve it from
        // the build target arch (the engine's GuestArch::elf_machine()).
        #[cfg(target_arch = "x86_64")]
        let machine = {
            use carrick_hal::guest_arch::GuestArch as _;
            carrick_hal::x8664_arch::X8664GuestArch::elf_machine()
        };
        #[cfg(not(target_arch = "x86_64"))]
        let machine = goblin::elf::header::EM_AARCH64;
        // Load the ELF, resolving a dynamic interpreter through the same reader.
        let raw = match AddressSpace::load_elf_bytes_with_reader_for(
            &raw_bytes,
            &|p| {
                let bytes = dispatcher.read_exec_file(p).or_else(|| host_read(p));
                match bytes.as_ref() {
                    Some(found) => {
                        trace_execve(&path, format_args!("interp path={p} bytes={}", found.len()));
                    }
                    None => trace_execve(&path, format_args!("interp path={p} missing")),
                }
                bytes
            },
            machine,
        ) {
            Ok(raw) => raw.with_main_file_path(path.clone()),
            Err(err) => {
                trace_execve(&path, format_args!("elf-load path={path} err={err:?}"));
                return Err(LINUX_ENOENT);
            }
        };
        // KVM boot-image shape: vdso (so AT_SYSINFO_EHDR resolves) + the Linux
        // initial stack (argc/argv/envp/auxv). `build_for_image` adds the
        // trampoline / page-tables / sentinel vectors. Matches the boot chain in
        // `run_elf_real_dispatch`. Per-ISA vDSO bytes come from the engine's
        // GuestArch; the x86_64 lanes now materialize the shared x86 clock vDSO
        // as well, so execve children do not fall back to real clock syscalls.
        #[cfg(all(feature = "platform-linux", target_arch = "aarch64"))]
        let image = {
            type KvmArch = <carrick_vmm_kvm::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch;
            let linux_page_size = dispatcher.linux_page_size();
            match super::with_vmm_vdso_for_dispatcher::<KvmArch>(
                raw,
                dispatcher,
                requires_syscall_traps,
            )
            .and_then(|a| a.with_linux_initial_stack_page_size(argv, env, linux_page_size))
            {
                Ok(image) => image,
                Err(err) => {
                    trace_execve(&path, format_args!("image-build path={path} err={err:?}"));
                    return Err(LINUX_ENOENT);
                }
            }
        };
        #[cfg(target_arch = "x86_64")]
        let image =
            {
                let linux_page_size = dispatcher.linux_page_size();
                match super::with_vmm_vdso_for_dispatcher::<
                carrick_hal::x8664_arch::X8664GuestArch,
            >(raw, dispatcher, requires_syscall_traps)
                .and_then(|a| a.with_linux_initial_stack_page_size(argv, env, linux_page_size))
            {
                Ok(image) => image,
                Err(err) => {
                    trace_execve(&path, format_args!("image-build path={path} err={err:?}"));
                    return Err(LINUX_ENOENT);
                }
            }
            };
        #[cfg(all(
            not(target_arch = "x86_64"),
            not(all(feature = "platform-linux", target_arch = "aarch64"))
        ))]
        let image = raw
            .with_vdso_auxv(false)
            .with_linux_initial_stack_page_size(argv, env, dispatcher.linux_page_size())
            .map_err(|_| LINUX_ENOENT)?;
        Ok(image)
    }

    // The 5 forked-child/signal-stop helpers and the shebang pair are now in the
    // cross-platform `exec_helpers` module. Re-export them here under `pub(super)`
    // so the `use macos_helper_stubs::{…}` import at the bottom of this module
    // (line ~281) continues to resolve without change.
    pub(super) use crate::exec_helpers::{
        forked_child_die_by_signal, stop_after_traced_exec, stop_by_signal,
    };

    pub(super) fn hardware_tso_for_debug(_requested: bool) -> bool {
        unreachable!("Apple-Silicon hardware TSO toggle is HVF-only; KVM has no Rosetta TSO")
    }
}
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use macos_helper_stubs::{
    forked_child_die_by_signal, hardware_tso_for_debug, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
};

// ===================================================================
// Ownership-aligned submodules (Task A2). Each concern owns a disjoint file so
// the THREAD / SIGNAL / MEM / PROC agents do not collide. These are pure code
// moves: the `impl ThreadRuntimeState` methods and free fns below live in the
// submodules, re-exported here so every external `crate::vcpu_loop::X` path keeps
// resolving unchanged.
// ===================================================================
pub(crate) mod exec;
pub(crate) use exec::{
    AuthenticatedExecCompletionOrigin, ExecCompletionOrigin, PendingExecCompletionOwnership,
    SyscallCompletionOwnership,
};
pub(crate) mod quiesce;
mod signal;
mod threads;
#[cfg(test)]
pub(crate) use threads::enroll_persistent_process_member;
pub(crate) use threads::{
    PersistentProcessMemberPublication, VcpuThreadHandle, VcpuThreadRegistry,
};

// Re-export the free fns that moved into submodules so the in-crate callers
// (`crate::runtime`, this module's own code) keep naming them as
// `crate::vcpu_loop::X` / bare `X`.
// The threaded loop owns its backend-specific fault resolution. Native Darwin
// reuses the architecture lowering and Linux signal-frame half below.
pub(crate) use signal::is_default_ignore_signal;
// Production reaches this through `signal::upgrade_protection_si_code` directly
// (`poll_with_engine`); only `dispatch::mem`'s tests need it re-exported, so the
// re-export is test-only rather than an unused import in the lib build.
#[cfg(test)]
pub(crate) use signal::upgrade_protection_si_code;
use signal::{
    deliver_fault_signal, deliver_pending_signal_with_restart,
    deliver_reserved_signal_with_restart, lower_el0_fault,
};
pub(crate) use signal::{
    deliver_pending_signal, partial_write_interrupt_outcome, raise_sigpipe_for_blocking_write,
    signal_progress_count, signal_wait_expired, signal_wait_slice,
};
pub(crate) use signal::{
    reset_signal_progress_for_executor_boundary, signal_progress_is_zero_for_executor_boundary,
};
// Test-only consumer since the DSR translator (the lib-side caller) moved to
// the arch crate; the ESR decode itself lives in carrick_aarch64::esr and
// signal.rs re-exports it.
#[cfg(test)]
use signal::el0_debug_signal;

pub(crate) mod wait_wake;
pub(crate) use wait_wake::{
    ContainerJobReservation, HvpatchRuntimeDirectory, HvpatchTaskWaker, ProcessPhysicalRetirement,
};

pub(crate) mod terminal;
#[cfg(test)]
pub(crate) use terminal::ProcessExitClaim;
pub(crate) use terminal::{
    CloneAdmissionChangeSubscription, CloneAdmissionGate, CloneAdmissionPermit, CloneEnrollment,
    ExecCloneAdmission, ExecTerminalHandoff, FatalSignalAuthority, FatalSignalRecord,
    ForkCloneAdmission, ProcessExitClaimReceipt, VcpuLoopOutcome, core_note_resume_pair,
    try_claim_persistent_process_exit_with,
};

pub(crate) mod outcome;
pub(crate) use outcome::{
    HvpatchExternalTerminalSettlement, HvpatchLoopResult, KernelAbortRecord, LIVENESS_CONFIRM,
    LIVENESS_POLL, ProcessGraphLiveness, assemble_run_result,
};
#[cfg(test)]
pub(crate) use outcome::{HvpatchLoopPoll, HvpatchLoopSuspension};

pub(crate) mod crash;
#[cfg(test)]
use crash::CrashLeaseDrainBudget;
pub(crate) mod lifecycle;
pub(crate) use lifecycle::ProcessChildBootstrap;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) use lifecycle::bootstrap_hvpatch_process_child;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) use lifecycle::install_hvpatch_process_failpoint;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(in crate::vcpu_loop) use lifecycle::{
    HvpatchCloneBackendOps, HvpatchCloneThreadRequest, PersistentHvpatchCloneAttempt,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use lifecycle::{
    HvpatchProcessBackendOps, HvpatchProcessFailpoint, HvpatchProcessInventoryPreparation,
    check_hvpatch_process_failpoint,
};

pub(crate) use crash::PreparedCorePublication;

/// Shared kernel-half state for the threaded loop: the syscall dispatcher, the
/// compat reporter, and the start-only signal-pump controller (held object-safe
/// so this is cross-platform).
pub(crate) struct KernelState {
    pub(crate) dispatcher: SyscallDispatcher,
    pub(crate) reporter: CompatReporter,
    pub(crate) signal_pump: Arc<dyn SignalPumpControl>,
    /// Per-backend signal ARRIVAL / wake mechanism (kicker+futex on KVM, the
    /// kqueue pump / self-pipe / xsig ring on HVF). The neutral pending STORE is
    /// carrick-signal-core; this is only how an async signal physically wakes a
    /// waiter. Held object-safe so the loop never names the concrete impl.
    pub(crate) signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
    /// Present only for hvpatch: binds this kernel/dispatcher to one Linux
    /// process in the shared in-process process table.
    pub(crate) hvpatch_process: Option<crate::hvpatch::ProcessContext>,
    /// Process-local terminal teardown latch.  Unlike the legacy exec/fork
    /// globals, each hvpatch child owns a distinct `KernelState`, so this can
    /// stop clone admission without disturbing another process in the VM.
    process_exiting: std::sync::atomic::AtomicBool,
    /// Per-Linux-process fork pause for the shared-VM backend. The legacy
    /// barrier is host-process-global because it assumed one process per VM.
    process_fork_barrier: Option<Arc<crate::fork_quiesce::QuiesceBarrier>>,
    /// Issues crash-capture generations and broadcasts the one currently
    /// collecting. Sibling loops read it at their quiesce safe point.
    crash_capture: Option<Arc<crate::kernel::CrashCaptureAuthority>>,
    /// Cross-layer thread-clone admission spans Kernel reservation through
    /// runtime registration, handle visibility, and child start.
    clone_admission: Arc<CloneAdmissionGate>,
    /// Runtime-only task-generation to wake-endpoint directory shared by every
    /// Linux process multiplexed in one HVPatch host process.
    hvpatch_runtime: Option<Arc<HvpatchRuntimeDirectory>>,
    /// Signal requested by this process's creating clone/fork operation.
    /// Parent selection itself is resolved from the Kernel graph at exit.
    child_exit_signal: Option<i32>,
    /// Terminal result published by whichever HVPatch thread owns process
    /// teardown. The main loop consumes it after sibling-driven exit_group.
    process_terminal: Mutex<Option<Result<RunResult, ()>>>,
    process_terminal_ready: Condvar,
    /// Exact physical completions for every logical thread enrolled when
    /// terminal clone admission closed. Outer process owners wait this receipt
    /// after logical publication, never from a persistent executor worker.
    process_physical_retirement: ProcessPhysicalRetirement,
    fatal_signal: FatalSignalAuthority,
    control_exec: Mutex<Option<crate::kernel::control::ExecRuntime>>,
    external_exec: Mutex<Option<crate::kernel::control::ExecWork>>,
}

impl KernelState {
    pub(crate) fn new(
        dispatcher: SyscallDispatcher,
        signal_pump: Arc<dyn SignalPumpControl>,
        signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
        hvpatch_process: Option<crate::hvpatch::ProcessContext>,
        inherited_hvpatch_runtime: Option<Arc<HvpatchRuntimeDirectory>>,
        child_exit_signal: Option<i32>,
    ) -> Self {
        let process_fork_barrier = hvpatch_process
            .as_ref()
            .map(|_| Arc::new(crate::fork_quiesce::QuiesceBarrier::new()));
        let crash_capture = hvpatch_process
            .as_ref()
            .map(|_| Arc::new(crate::kernel::CrashCaptureAuthority::default()));
        let hvpatch_runtime = hvpatch_process.as_ref().map(|_| {
            inherited_hvpatch_runtime
                .unwrap_or_else(|| Arc::new(HvpatchRuntimeDirectory::default()))
        });
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            signal_pump,
            signal_arrival,
            hvpatch_process,
            process_exiting: std::sync::atomic::AtomicBool::new(false),
            process_fork_barrier,
            crash_capture,
            clone_admission: Arc::new(CloneAdmissionGate::default()),
            hvpatch_runtime,
            child_exit_signal,
            process_terminal: Mutex::new(None),
            process_terminal_ready: Condvar::new(),
            process_physical_retirement: ProcessPhysicalRetirement::default(),
            fatal_signal: FatalSignalAuthority::default(),
            control_exec: Mutex::new(None),
            external_exec: Mutex::new(None),
        }
    }

    pub(crate) fn pt_quiesce(&self) -> Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        self.dispatcher.pt_quiesce()
    }

    pub(crate) fn install_control_exec_runtime(
        &self,
        runtime: crate::kernel::control::ExecRuntime,
    ) -> Result<(), RuntimeError> {
        let mut installed = self.control_exec.lock();
        if installed.is_some() {
            return Err(RuntimeError::Configuration(
                "carrier logical exec runtime already installed".to_owned(),
            ));
        }
        *installed = Some(runtime);
        Ok(())
    }

    pub(crate) fn install_control_exec_waker(
        &self,
        runtime: &crate::kernel::control::ExecRuntime,
        linux_tid: crate::kernel::LinuxTid,
    ) -> Result<(), RuntimeError> {
        let process = self.hvpatch_process.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec wake route has no HVPatch process".to_owned(),
            )
        })?;
        let directory = self.hvpatch_runtime.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec wake route has no runtime directory".to_owned(),
            )
        })?;
        let context = self
            .dispatcher
            .capture_kernel_context(linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "capture carrier logical exec wake target: {error}"
                ))
            })?;
        let thread = context.thread().key();
        let scheduler = directory.continuation_services(process.kernel_graph()).0;
        runtime
            .install_waker(Arc::new(move || {
                let _ = scheduler.wake_control(thread);
            }))
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "install carrier logical exec wake route: {error}"
                ))
            })
    }

    fn try_take_control_exec(&self) -> Option<crate::kernel::control::ExecWork> {
        self.control_exec.lock().as_ref()?.try_take()
    }

    fn install_external_exec_work(
        &self,
        work: crate::kernel::control::ExecWork,
    ) -> Result<(), RuntimeError> {
        let mut installed = self.external_exec.lock();
        if installed.is_some() {
            return Err(RuntimeError::Configuration(
                "logical process already has external exec work".to_owned(),
            ));
        }
        *installed = Some(work);
        Ok(())
    }

    fn take_external_exec_work(&self) -> Option<crate::kernel::control::ExecWork> {
        self.external_exec.lock().take()
    }

    fn admit_external_exec(&self, task: crate::kernel::TaskKey) -> Result<(), RuntimeError> {
        let mut external = self.external_exec.lock();
        let Some(work) = external.as_mut() else {
            return Ok(());
        };
        if work.admit(task.into()) {
            Ok(())
        } else {
            Err(RuntimeError::Configuration(
                "logical exec request expired before exact task admission".to_owned(),
            ))
        }
    }

    fn record_fatal_signal(&self, record: FatalSignalRecord) {
        let _ = self.fatal_signal.record(record);
    }

    pub(crate) fn register_hvpatch_runtime_endpoint(
        self: &Arc<Self>,
        futex: Arc<FutexTable>,
        kicker: Arc<dyn VcpuRegistry>,
    ) {
        let (Some(process), Some(directory)) =
            (self.hvpatch_process.as_ref(), self.hvpatch_runtime.as_ref())
        else {
            return;
        };
        let binding = process.task_binding();
        let leader = crate::kernel::LinuxTid::for_task_leader(binding.task_id());
        let signal_context = binding.capture(leader).unwrap_or_else(|error| {
            tracing::error!(%error, "cannot retain HVPatch runtime endpoint context");
            carrick_fatal!(
                "kernel::runtime_binding",
                "cannot retain HVPatch runtime endpoint context: {error}"
            );
        });
        // The kernel wakes a task through this; cross-process signal delivery
        // reaches a PARKED guest only because of it.
        signal_context.task().set_waker(Arc::new(HvpatchTaskWaker {
            futex,
            kicker,
            signal_arrival: Arc::clone(&self.signal_arrival),
        }));
        directory.register_endpoint(process.task_key(), Arc::downgrade(self), binding);
        // Give the signal pump's process-directed reconcile a route to parked
        // continuations: the ONE shared directory enumerates live tasks at
        // invocation time, so first-install-wins semantics are correct across
        // per-process endpoint registrations.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            let weak_directory = Arc::downgrade(directory);
            crate::host_signal::set_process_signal_wake_hook(Box::new(move || {
                if let Some(directory) = weak_directory.upgrade() {
                    directory.wake_all_tasks_for_process_signal();
                }
            }));
        }
    }

    fn reserve_hvpatch_persistent_process_job(
        &self,
    ) -> Result<ContainerJobReservation, RuntimeError> {
        let process = self.hvpatch_process.as_ref().ok_or_else(|| {
            RuntimeError::CarrierFailed(
                "cannot reserve HVPatch process job without process identity".to_owned(),
            )
        })?;
        let runtime = self.hvpatch_runtime.as_ref().ok_or_else(|| {
            RuntimeError::CarrierFailed(
                "cannot reserve HVPatch process job without runtime directory".to_owned(),
            )
        })?;
        let container_id = process.container_id();
        runtime.container_job_group(container_id).reserve()
    }

    pub(crate) fn join_hvpatch_process_threads(&self) -> Result<(), RuntimeError> {
        let (Some(process), Some(directory)) =
            (self.hvpatch_process.as_ref(), self.hvpatch_runtime.as_ref())
        else {
            return Ok(());
        };
        let container_id = process.container_id();
        directory
            .container_job_group(container_id)
            .join()
            .map(|_| ())
    }

    fn notify_hvpatch_parent_exit(&self, parent: Option<crate::kernel::TaskKey>) {
        match (parent, self.hvpatch_runtime.as_ref()) {
            (Some(parent), Some(directory)) => {
                directory.notify_child_exit(parent, self.child_exit_signal);
            }
            (Some(parent), None) => tracing::error!(
                parent = ?parent,
                "child exit notification dropped: no HVPatch runtime directory"
            ),
            (None, _) => {}
        }
    }

    fn unregister_hvpatch_runtime_endpoint(&self) {
        if let (Some(process), Some(directory)) =
            (self.hvpatch_process.as_ref(), self.hvpatch_runtime.as_ref())
        {
            directory.remove(process.task_key());
        }
    }

    fn begin_process_exit(&self) {
        self.process_exiting
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.process_physical_retirement.begin_process_exit();
    }

    fn try_claim_persistent_process_exit(
        &self,
        owner: ThreadId,
    ) -> Result<ProcessExitClaimReceipt, RuntimeError> {
        try_claim_persistent_process_exit_with(&self.clone_admission, owner)
    }

    pub(crate) fn process_exiting(&self) -> bool {
        self.process_exiting
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn enroll_thread_clone(&self) -> CloneEnrollment {
        self.clone_admission.enroll_thread_clone()
    }

    fn close_clone_admission_for_exec(
        &self,
        owner: ThreadId,
    ) -> Result<ExecCloneAdmission, RuntimeError> {
        self.clone_admission.close_for_exec(owner)
    }

    fn publish_process_terminal(&self, terminal: Result<RunResult, ()>) {
        let mut published = self.process_terminal.lock();
        if published.is_none() {
            *published = Some(terminal);
            self.process_terminal_ready.notify_all();
        }
    }

    pub(crate) fn take_process_terminal(
        &self,
    ) -> Result<Option<Result<RunResult, ()>>, RuntimeError> {
        let mut published = self.process_terminal.lock();
        if published.is_none() && self.process_exiting() {
            let wait = self
                .process_terminal_ready
                .wait_for(&mut published, std::time::Duration::from_secs(5));
            if wait.timed_out() && published.is_none() {
                return Err(RuntimeError::Unsupported(
                    "HVPatch terminal owner did not complete teardown".to_owned(),
                ));
            }
        }
        Ok(published.take())
    }
}

pub(crate) type Kernel = Arc<KernelState>;

fn thread_should_finish_for_exec_replacement(registry: &ThreadRegistry, tid: ThreadId) -> bool {
    // `exec_replacing_other_thread` is transient. A sibling that reclaimed its
    // vCPU can still be waking from a host wait after the execing thread has
    // removed it from the registry and cleared the flag; the registry removal is
    // the durable signal that it must not recreate a vCPU in the replaced VM.
    crate::fork_quiesce::exec_replacing_other_thread(tid) || !registry.is_live(tid)
}

fn trace_hvpatch_thread_teardown(kernel: &Kernel, tid: ThreadId, phase: i32) {
    if let Some(process) = kernel.hvpatch_process.as_ref() {
        crate::event_ring::rec_hvpatch_thread_teardown(process.pid(), tid.raw(), phase);
    }
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
            carrick_fatal!(
                "vcpu_loop::panic_backstop",
                "panic in syscall handler on vCPU: subsystem state may be torn"
            );
        }
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

pub(crate) mod binding;

pub(crate) use binding::{
    ExecutionLeaseCell, HvpatchBlockInput, HvpatchContinuationInput, HvpatchLogicalJobInput,
    HvpatchSyscallServiceGuard, launch_persistent_hvpatch_job, prepare_hvpatch_logical_job,
};

#[cfg(test)]
pub(in crate::vcpu_loop) use binding::{
    HvpatchLoopJob, HvpatchProductionPhase, PersistentTerminalRuntimeState,
    ProductionHvpatchLoopJob, ProductionHvpatchLoopPoll, ScriptedHvpatchLoopEngine,
};

pub(crate) struct ThreadRuntimeState<E: ThreadedEngine> {
    pub(super) registry: Arc<ThreadRegistry>,
    /// The CONCRETE process-private futex table — used UNCHANGED by
    /// `dispatch_threaded` + `complete_futex_wait` (the generation-snapshot
    /// lost-wake protocol stays byte-identical). Do NOT abstract this.
    pub(super) futex: Arc<FutexTable>,
    /// The object-safe platform futex — used ONLY for SHARED-futex ops +
    /// signal-pending notifications. On HVF this wraps the SAME `FutexTable`.
    pub(super) platform_futex: Arc<dyn PlatformFutex>,
    /// Rebuilds a `PlatformFutex` over a FRESH concrete `FutexTable` for the
    /// CHILD side of a guest `fork(2)` (`libc::fork` replicated only this thread,
    /// so the child drops the parent's table + waiters and starts over). Built
    /// ONCE by the macOS setup wrapper (where naming the concrete `HvfFutex` is
    /// fine) and threaded through, so the loop keeps `self.futex` and
    /// `self.platform_futex` wrapping the SAME table without ever naming the
    /// backend — see `handle_fork`'s Child arm.
    pub(super) platform_futex_factory: PlatformFutexFactory,
    /// `Some` only for a process multiplexed in the shared HvPatch VM.
    pub(super) process_fork_barrier: Option<Arc<crate::fork_quiesce::QuiesceBarrier>>,
    pub(super) crash_capture: Option<Arc<crate::kernel::CrashCaptureAuthority>>,
    #[cfg(test)]
    pub(super) crash_lease_drain_budget: CrashLeaseDrainBudget,
    pub(super) kernel_thread: Option<crate::kernel::ThreadRef>,
    pub(super) guest_execution: Option<crate::dispatch::MmExecutorParticipation>,
    /// Exact Task 1 execution authority while this logical thread is running.
    /// Empty only before its first reclaim snapshot and while blocked.
    pub(super) execution_lease: ExecutionLeaseCell,
    pub(super) pending_exec_replacement: Option<executor::PendingExecReplacement>,
    /// Authoritative Linux TGID for a task multiplexed by HVPatch. `None` on
    /// the one-host-process-per-task native/VMM lanes.
    pub(super) hvpatch_task_pid: Option<i32>,
    /// Guest-visible identity allocated in the kernel namespace. It is never
    /// inferred from the backend-local thread registry key.
    pub(super) linux_tid: crate::kernel::LinuxTid,
    /// Image generation that owns fatal-signal publication for this loop. It
    /// changes only after a successful exec has crossed every fallible edge.
    pub(super) fatal_image_generation: u64,
    /// Exact authority captured at the current syscall boundary. Lifecycle
    /// outcomes consume it rather than recapturing a newer registry generation.
    pub(super) service_kernel_context: Option<crate::kernel::KernelContext>,
    #[cfg(test)]
    pub(in crate::vcpu_loop) exec_terminal_context_failpoint:
        Option<exec::ExecTerminalContextFailpoint>,
    #[cfg(test)]
    pub(super) committed_exec_context_for_test: Option<crate::kernel::KernelContext>,
    pub(super) syscall_completion: SyscallCompletionOwnership,
    pub(super) continuation_restart: Option<continuation::RestartDecision>,
    /// Consecutive identical (FAR, ESR) COW faults "successfully" resolved.
    /// A resolution that does not change the faulting translation refaults
    /// forever inside one quantum, starving this executor's command channel
    /// and wedging every peer waiting in `consume_invalidation_acks` — seen
    /// live on `futexforkrequeue` (core: ffr-livelock-76407). Fail closed
    /// with a named clause instead of spinning.
    pub(super) cow_refault_watch: Option<(u64, u64, Option<u64>, u32)>,
    pub(super) reserved_signal: Option<continuation::ReservedSignal>,
    pub(super) this_tid: ThreadId,
    pub(super) threads: VcpuThreadRegistry,
    /// The object-safe vCPU registry (the kicker). The shared loop never names
    /// the concrete `VcpuKicker`.
    pub(super) kicker: Arc<dyn VcpuRegistry>,
    /// This guest thread's ONE "currently in `next_syscall`" flag, created when
    /// the guest thread is born and held for its whole life, so a
    /// page-table-edit coordinator can tell whether this thread is walking
    /// guest memory. Set true around `next_syscall`, false otherwise. Every
    /// (re-)registration of this thread hands the kicker THIS flag — see
    /// [`carrick_hal::InGuestFlag`], whose whole point is that the two halves
    /// of a registration cannot drift apart.
    pub(super) in_guest: carrick_hal::InGuestFlag,
    pub(super) max_traps: usize,
    pub(super) trace: bool,
    /// Set on a vfork (`CLONE_VM|CLONE_VFORK`) CHILD: the write end of the pipe
    /// whose read end the suspended PARENT blocks on. `None` on the parent and on
    /// ordinary (non-vfork) children.
    pub(super) vfork_release_fd: Option<i32>,
    /// The one-shot runtime-withdrawal memo for
    /// `handle_persistent_thread_exit` Busy retries (see
    /// `PersistentThreadExitDisposition`).
    pub(super) thread_exit_withdrawn: bool,
    /// Live reservation-change subscription while a thread exit is parked
    /// on `PersistentThreadExitDisposition::Busy`; dropped when the retry
    /// runs.
    pub(super) thread_exit_retry_subscription: Option<crate::kernel::ReservationChangeSubscription>,
    /// The engine is passed as `&mut E` to each method, so no field owns it; this
    /// pins the generic parameter to the struct.
    pub(super) _engine: std::marker::PhantomData<fn() -> E>,
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
        process_fork_barrier: Option<Arc<crate::fork_quiesce::QuiesceBarrier>>,
        crash_capture: Option<Arc<crate::kernel::CrashCaptureAuthority>>,
        kernel_thread: Option<crate::kernel::ThreadRef>,
        hvpatch_task_pid: Option<i32>,
        linux_tid: crate::kernel::LinuxTid,
        fatal_image_generation: u64,
        this_tid: ThreadId,
        threads: impl Into<VcpuThreadRegistry>,
        kicker: Arc<dyn VcpuRegistry>,
        in_guest: carrick_hal::InGuestFlag,
        max_traps: usize,
    ) -> Self {
        Self {
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            process_fork_barrier,
            crash_capture,
            kernel_thread,
            guest_execution: None,
            execution_lease: ExecutionLeaseCell::owned(),
            pending_exec_replacement: None,
            hvpatch_task_pid,
            linux_tid,
            fatal_image_generation,
            service_kernel_context: None,
            #[cfg(test)]
            exec_terminal_context_failpoint: None,
            #[cfg(test)]
            committed_exec_context_for_test: None,
            syscall_completion: SyscallCompletionOwnership::Idle,
            continuation_restart: None,
            cow_refault_watch: None,
            reserved_signal: None,
            this_tid,
            threads: threads.into(),
            kicker,
            in_guest,
            max_traps,
            trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),
            #[cfg(test)]
            crash_lease_drain_budget: CrashLeaseDrainBudget::DEFAULT,
            vfork_release_fd: None,
            thread_exit_withdrawn: false,
            thread_exit_retry_subscription: None,
            _engine: std::marker::PhantomData,
        }
    }

    #[cfg(test)]
    fn install_exec_terminal_context_failpoint_for_test(
        &mut self,
        point: exec::ExecTerminalContextFailpoint,
    ) {
        self.exec_terminal_context_failpoint = Some(point);
        self.committed_exec_context_for_test = None;
    }

    #[cfg(test)]
    fn fail_exec_terminal_context_for_test(
        &self,
        point: exec::ExecTerminalContextFailpoint,
    ) -> Result<(), RuntimeError> {
        if self.exec_terminal_context_failpoint == Some(point) {
            return Err(RuntimeError::Configuration(format!(
                "injected exec terminal context failure at {point:?}"
            )));
        }
        Ok(())
    }

    /// Publish this runtime thread's process-visible state without confusing
    /// HVPatch's shared Darwin pid for the Linux task id.
    fn publish_process_run_state(&self, state: crate::run_state::RunState) {
        if let Some(task_pid) = self.hvpatch_task_pid {
            crate::run_state::publish_task_thread(task_pid, self.linux_tid.raw(), state);
        } else {
            crate::run_state::publish(state);
        }
    }

    /// Mark this thread's guest as BLOCKED for as long as the guard lives, and
    /// restore `Running` when it drops.
    ///
    /// The run-loop top publishes `Running` on EVERY iteration, so a guest that
    /// blocks keeps reading `R` unless the blocking site says otherwise. That
    /// used to be hand-written at each site, and it was missing from most of
    /// them: `grep RunState::Blocked` found exactly two non-test publishers in
    /// the whole runtime, both futex paths, so `read` on a pipe, `nanosleep`,
    /// `poll` and `wait4` all reported `R` while genuinely parked. Measured
    /// against the Docker oracle, all four read `S` there and `R` here.
    ///
    /// That is not cosmetic. LTP's `TST_PROCESS_STATE_WAIT(pid,'S',0)` polls
    /// this character every 1 ms with NO timeout, so a parent waiting for a
    /// child to sleep waits forever — the mechanism behind
    /// `ltp-futex_cmp_requeue01`'s 989 diverging rows.
    ///
    /// The run-loop comment claimed a `block_guard` already did this "for the
    /// duration of the park". No such thing existed; the identifier appeared
    /// only in that comment. This is it, made RAII so a blocking site cannot
    /// return early or `?` out and silently leave the guest marked runnable.
    /// Publish both process-visible and per-thread state at the points that
    /// already maintain the thread registry on mature lanes.
    /// Record one "successfully resolved" COW fault and fail closed if the
    /// IDENTICAL (FAR, ESR, resolved-translation) triple keeps recurring: a
    /// correct resolution must change the faulting translation, so a repeat
    /// that lands on the SAME output proves the resolver made no progress,
    /// and the historical behaviour was a silent 100% CPU refault loop that
    /// also starved `InvalidateAsid` servicing. (FAR, ESR) alone is NOT
    /// evidence: a fork loop legitimately re-COWs the same VA once per
    /// iteration — fork re-arms the parent's span and the wait loop rewrites
    /// the same stack slot — with a FRESH frame every time (waitexitstorm,
    /// futexwakeexact and forkstackstorm all tripped the old pair-keyed
    /// detector on exactly that shape, at ~4 forks per run).
    /// The threshold of 4 is pure paranoia headroom over "impossible twice".
    pub(super) fn note_cow_resolution(
        &mut self,
        far: u64,
        syndrome: u64,
        translation: Option<u64>,
    ) -> Result<(), RuntimeError> {
        const COW_REFAULT_LIMIT: u32 = 4;
        match &mut self.cow_refault_watch {
            Some((last_far, last_esr, last_translation, count))
                if *last_far == far
                    && *last_esr == syndrome
                    && *last_translation == translation =>
            {
                *count += 1;
                if *count >= COW_REFAULT_LIMIT {
                    return Err(RuntimeError::Configuration(format!(
                        "HVPatch COW resolution did not satisfy the faulting access: \
                         identical fault recurred {count} times with unchanged resolution \
                         (far={far:#x} esr={syndrome:#x} translation={translation:?} tid={}) \
                         — refault livelock",
                        self.this_tid
                    )));
                }
            }
            _ => self.cow_refault_watch = Some((far, syndrome, translation, 1)),
        }
        Ok(())
    }

    fn publish_thread_run_state(&self, state: crate::run_state::RunState, stat: char) {
        self.publish_process_run_state(state);
        // This hot path already owns the exact per-process registry. Using it
        // directly avoids a carrier endpoint-directory lock on every
        // block/wake transition.
        self.registry.set_thread_state(self.this_tid, stat);
        if self.hvpatch_task_pid.is_none() {
            crate::run_state::publish_guest_tid(self.this_tid.raw(), state);
        }
    }

    pub(super) fn trace_syscall(&self, traps: usize, frame: carrick_hal::RawSyscall) {
        if !self.trace {
            return;
        }
        // The frame carries the RAW per-ISA number, so the name comes from this
        // engine's per-ISA table (Phase 1 T8), not the canonical aarch64 table.
        let name = <<E::Arch as carrick_hal::GuestArch>::Table as carrick_hal::SyscallTable>::name(
            frame.number.raw(),
        )
        .unwrap_or("<unknown>");
        let a = frame.args;
        eprintln!(
            "tid#{} trap#{}: nr={} ({name}) a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x}",
            self.this_tid,
            traps,
            frame.number.raw(),
            a[0],
            a[1],
            a[2],
            a[3],
            a[4]
        );
    }

    pub(super) fn trace_hvpatch_thread_terminal(
        &self,
        reason: carrick_observability::probes::HvpatchThreadTerminalReason,
        detail: i32,
    ) {
        let Some(pid) = self.hvpatch_task_pid else {
            return;
        };
        crate::probes::hvpatch_thread_terminal(
            pid,
            self.linux_tid.raw(),
            self.this_tid.raw(),
            reason,
            detail,
        );
    }

    /// Return-side companion to [`Self::trace_syscall`].
    pub(super) fn trace_syscall_return(&self, traps: usize, ret: Option<i64>) {
        if !self.trace {
            return;
        }
        let Some(ret) = ret else { return };
        if let Some(e) = LinuxErrno::from_guest_retval(ret) {
            let ename = crate::linux_abi::errno_name(e).unwrap_or("?");
            let e = e.get();
            eprintln!(
                "tid#{} trap#{traps}:   -> errno={e} ({ename})",
                self.this_tid
            );
        } else {
            eprintln!(
                "tid#{} trap#{traps}:   -> ret={ret:#x} ({ret})",
                self.this_tid
            );
        }
    }

    fn prepare_hvpatch_continuation(
        &self,
        kernel: &Kernel,
        lease: &crate::kernel::objects::ThreadExecutionLease,
        request: SyscallRequest,
        input: HvpatchContinuationInput,
    ) -> Result<continuation::BlockedContinuation, RuntimeError> {
        let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch blocking continuation has no shared runtime directory".to_owned(),
            )
        })?;
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch blocking continuation lost syscall Kernel context".to_owned(),
            )
        })?;
        let (_scheduler, _service) = directory.continuation_services(context.kernel());

        let capture = continuation::ContinuationCapture::from_lease(
            context,
            lease,
            request,
            if is_restartable_syscall(request.number.raw()) {
                continuation::RestartClass::RestartSyscall
            } else {
                continuation::RestartClass::Never
            },
            continuation::ContinuationBackend::Hvpatch,
        )
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let mut continuation = match input {
            HvpatchContinuationInput::Dispatch(outcome) => {
                continuation::BlockedContinuation::from_dispatch_outcome(outcome, capture)
            }
            HvpatchContinuationInput::Vfork { child, wait } => {
                continuation::BlockedContinuation::from_vfork_parent(capture, child, wait)
            }
        }
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        continuation.bind_product_futex(&self.futex);
        continuation.install_temporary_signal_mask(context);
        Ok(continuation)
    }

    pub(super) fn persistent_block_exit(
        &self,
        kernel: &Kernel,
        lease: &crate::kernel::objects::ThreadExecutionLease,
        request: SyscallRequest,
        input: HvpatchBlockInput,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let native_syscall_number = request.native_number.raw();
        let block_args = [
            request.arg(0),
            request.arg(1),
            request.arg(2),
            request.arg(3),
        ];
        let (continuation_input, vfork_activation) = match input {
            HvpatchBlockInput::Dispatch(outcome) => {
                (HvpatchContinuationInput::Dispatch(outcome), None)
            }
            HvpatchBlockInput::Vfork {
                child,
                wait,
                activation,
            } => (
                HvpatchContinuationInput::Vfork { child, wait },
                Some(activation),
            ),
        };
        let continuation =
            self.prepare_hvpatch_continuation(kernel, lease, request, continuation_input)?;
        if let Some(pid) = self.hvpatch_task_pid
            && pid == self.linux_tid.raw()
        {
            crate::event_ring::rec_hvpatch_blocked_continuation(
                pid,
                self.linux_tid.raw(),
                native_syscall_number,
                continuation.family().event_code(),
                block_args,
            );
        }
        Ok(executor::ExecutorExit::BlockedContinuation {
            continuation: Box::new(continuation),
            vfork_activation,
        })
    }

    pub(super) fn resume_persistent_continuation(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        lease: &mut crate::kernel::objects::ThreadExecutionLease,
    ) -> Result<Option<DispatchOutcome>, RuntimeError> {
        let event = lease
            .blocked_continuation()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent resume lost its Kernel-owned continuation".to_owned(),
                )
            })?
            .ready_event()
            .map_err(|error| {
                RuntimeError::Configuration(format!("continuation event: {error:?}"))
            })?;
        let context = self.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent continuation resume lost exact Kernel context".to_owned(),
            )
        })?;
        let fresh = context
            .task_binding()
            .capture(self.linux_tid)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let mut result = match continuation::resume_continuation(lease, event, &fresh) {
            Ok(result) => result,
            Err(continuation::ContinuationResumeError::StaleFileSlot) => {
                return Ok(Some(DispatchOutcome::Errno {
                    errno: crate::linux_abi::LINUX_EBADF,
                }));
            }
            Err(error) => {
                return Err(RuntimeError::Configuration(format!(
                    "resume persistent continuation: {error:?}"
                )));
            }
        };
        // A restart decision is only MEANINGFUL when this resume itself
        // evaluated a signal (the Signal/ReservedSignal event path, which
        // weighs SA_RESTART against the continuation's family and progress).
        // A Ready->Redispatch resume carries the default NoRestart, and
        // stashing that as Some(..) VETOED the syscall-boundary restart
        // predicates for whatever the REDISPATCHED syscall did next: wait4
        // re-dispatched after a task wake, hit the pre-park deliverable-signal
        // gate, returned EINTR — and the stale Some(NoRestart) overrode the
        // all-true SA_RESTART predicates, surfacing EINTR to a guest whose
        // handler asked for restart (waitrestart scenario A).
        self.continuation_restart = match result.completion {
            continuation::ContinuationCompletion::Redispatch
            | continuation::ContinuationCompletion::RedispatchWithPartial(_) => None,
            _ => Some(result.restart()),
        };
        self.reserved_signal = result.take_reserved_signal();

        use continuation::ContinuationCompletion as Completion;
        Ok(match result.completion {
            Completion::Return(value) => Some(DispatchOutcome::Returned { value }),
            Completion::Errno(errno) => Some(DispatchOutcome::Errno { errno }),
            Completion::Redispatch => None,
            Completion::RedispatchWithPartial(value) => Some(DispatchOutcome::Returned { value }),
            Completion::ReturnWithGuestWrites(value, writes) => {
                for range in writes {
                    engine
                        .zero_guest_range(range.start().raw(), range.len())
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
                }
                Some(DispatchOutcome::Returned { value })
            }
            Completion::ErrnoWithGuestWrites(errno, writes) => {
                for range in writes {
                    engine
                        .zero_guest_range(range.start().raw(), range.len())
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
                }
                Some(DispatchOutcome::Errno { errno })
            }
            Completion::BlockingWrite { write, outcome } => {
                let outcome = match outcome {
                    continuation::BlockingWriteOutcome::Return(value) => {
                        DispatchOutcome::Returned { value }
                    }
                    continuation::BlockingWriteOutcome::Errno(errno) => {
                        DispatchOutcome::Errno { errno }
                    }
                };
                Some(raise_sigpipe_for_blocking_write(
                    &kernel.dispatcher,
                    context,
                    &write,
                    outcome,
                ))
            }
            Completion::InterruptedSleep { remaining } => {
                Some(crate::dispatch::complete_interrupted_sleep(
                    engine,
                    remaining.map(|(range, _)| crate::dispatch::GuestPtr(range.start().raw())),
                    remaining.map_or(Duration::ZERO, |(_, duration)| duration),
                ))
            }
        })
    }

    fn with_mm_mutation_authority<T>(
        &mut self,
        kernel: &Kernel,
        run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> Result<T, RuntimeError> {
        let mut executor = self.guest_execution.take().ok_or_else(|| {
            RuntimeError::Configuration("MM mutation lacks executor participation".to_owned())
        })?;
        let result = self.with_mm_mutation_authority_for_executor(kernel, &mut executor, run);
        self.guest_execution = Some(executor);
        result
    }

    fn with_mm_mutation_authority_for_executor<T>(
        &mut self,
        kernel: &Kernel,
        executor: &mut crate::dispatch::MmExecutorParticipation,
        run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> Result<T, RuntimeError> {
        let context = kernel
            .dispatcher
            .capture_kernel_context(self.linux_tid)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let coordinator = kernel.dispatcher.mm_mutation_coordinator();
        let mm = context.shared().mm().id();
        let mut authority = quiesce::acquire_mm_stage1_authority(
            executor,
            self.this_tid,
            quiesce::PtPauseBudget::DEFAULT,
        )
        .map_err(|error| {
            RuntimeError::Configuration(format!(
                "fault page-table pause failed before mutation: {error:?}"
            ))
        })?;
        let mut mutation = match &mut authority {
            quiesce::MmStage1Authority::Sole(sole) => {
                crate::dispatch::mm_mutation::from_sole_executor(sole, coordinator, mm)
            }
            quiesce::MmStage1Authority::Paused(pause) => {
                crate::dispatch::mm_mutation::from_pt_pause(pause)
            }
        };
        Ok(run(&mut mutation))
    }

    fn service_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        frame: carrick_hal::RawSyscall,
    ) -> Result<DispatchOutcome, RuntimeError> {
        let mut executor = self.guest_execution.take().ok_or_else(|| {
            RuntimeError::Configuration(
                "syscall service lacks MM executor participation".to_owned(),
            )
        })?;
        let result =
            self.service_threaded_syscall_for_executor(kernel, engine, frame, &mut executor);
        self.guest_execution = Some(executor);
        result
    }

    fn service_threaded_syscall_for_executor(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        frame: carrick_hal::RawSyscall,
        mm_executor: &mut crate::dispatch::MmExecutorParticipation,
    ) -> Result<DispatchOutcome, RuntimeError> {
        self.service_kernel_context = None;
        if !self.syscall_completion.is_idle() {
            return Err(RuntimeError::Configuration(
                "new syscall trapped while a completion token is still live".to_owned(),
            ));
        }
        let kernel_context = kernel
            .dispatcher
            .capture_kernel_context(self.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "capture mandatory syscall kernel context: {error}"
                ))
            })?;
        self.service_kernel_context = Some(kernel_context.retain_exact());
        let request = SyscallRequest::from_raw(frame)
            .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi())
            .with_current_guest_sp(engine.get_reg(carrick_hal::Reg::Sp).ok());
        let (syscall, prepared_outcome) =
            match kernel
                .dispatcher
                .prepare_syscall(&kernel_context, request, &kernel.reporter)?
            {
                PreparedDispatch::Invoke(syscall) => (syscall, None),
                PreparedDispatch::Complete { syscall, outcome } => (syscall, Some(outcome)),
            };
        self.syscall_completion = SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
            syscall,
            kernel_context.retain_exact(),
            kernel.dispatcher.observers().cloned(),
        ));
        if let Some(outcome) = prepared_outcome {
            return Ok(outcome);
        }
        self.redispatch_threaded_syscall_for_executor(kernel, engine, syscall, mm_executor)
    }

    fn redispatch_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
    ) -> Result<DispatchOutcome, RuntimeError> {
        let mut executor = self.guest_execution.take().ok_or_else(|| {
            RuntimeError::Configuration(
                "syscall redispatch lacks MM executor participation".to_owned(),
            )
        })?;
        let syscall = self
            .syscall_completion
            .guest("syscall redispatch lost completion token")?
            .syscall();
        let result =
            self.redispatch_threaded_syscall_for_executor(kernel, engine, syscall, &mut executor);
        self.guest_execution = Some(executor);
        result
    }

    fn redispatch_threaded_syscall_for_executor(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        syscall: PreparedSyscall,
        mm_executor: &mut crate::dispatch::MmExecutorParticipation,
    ) -> Result<DispatchOutcome, RuntimeError> {
        let kernel_context = self
            .service_kernel_context
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "syscall redispatch lost exact Kernel context".to_owned(),
                )
            })?
            .retain_exact();
        let request = syscall.request;
        let _syscall_guard = kernel.hvpatch_process.as_ref().and_then(|proc| {
            let (pid, asid) = proc.syscall_trace_identity()?;
            HvpatchSyscallServiceGuard::begin(
                pid,
                self.linux_tid.raw(),
                asid,
                request.number.raw(),
                request.args.0,
            )
        });
        // Stage-1 page-table editors — munmap(215), mremap(216), mmap(222),
        // mprotect(226) — mutate the shared guest descriptors from the host.
        // With sibling vCPUs live, Pause-Modify-Resume them so none walks a
        // half-edited descriptor tree.
        //
        // `MADV_DONTNEED` madvise(233) joins them, and the reason is a LOCK
        // ORDER, not a descriptor edit of its own. Two process-wide serializers
        // are in play: this page-table pause (P) and the dispatcher's
        // `HostAliasTransactions` phase (A, `dispatch/mod.rs`). The four
        // editors above take P here and A inside their handler. `madvise`
        // takes A in its handler (`begin_host_alias_dispatch`) and then reaches
        // P lazily and cross-thread, because `MADV_DONTNEED` calls
        // `zero_backing` -> `ensure_frame_cow_write` ->
        // `materialize_sparse_mmap_extent` -> `FrameCowAuthority::quiesce`.
        // That is A-then-P against the editors' P-then-A: a live ABBA. Captured
        // in a core of a wedged carrier (`bt all` + `PtQuiesce` bytes
        // `coordinator=1 quiescing=1` with NO thread in the drain): a munmap
        // thread held P and slept in `begin_dispatch` for A while a madvise
        // thread held A and slept in `acquire_pt_pause`'s coordinator election
        // for P. Every other guest thread then parked at the run-loop top on
        // `quiescing`, so the whole guest stopped at ~0% CPU.
        //
        // Taking P here makes the order uniformly P-then-A. The nested
        // acquisition inside the backend then borrows this pause for free —
        // `KernelFrameCowAuthority::quiesce` short-circuits on
        // `current_thread_holds_pt_pause()` — so the only new cost is a pause
        // on a `MADV_DONTNEED` whose backing needed no COW. The advice check
        // keeps it off every other advice, which never reaches `zero_backing`.
        // The population this decision needs is active or admitted guest
        // execution, NOT current vCPU lease publication — see
        // `KernelState::has_peer_guest_executor`. Registration can be
        // transiently absent while an admitted loop acquires or rebinds its
        // lease, so census participation is published first. A sibling
        // suspended in `epoll_wait` has dropped participation and is absent
        // from this page-table RAISE population; fork/crash use durable task
        // membership for their distinct barriers.
        // Claim stage-1 exclusivity for the whole dispatch of any syscall that
        // edits stage-1 descriptors. Both arms below are exclusive, for
        // different reasons, and the backend page-table manager needs to know
        // that so it can reclaim the spare sub-tables an alias teardown empties
        // (`carrick_hal::stage1_exclusive` documents what leaks when it cannot).
        enum SyscallMmPhase<'executor> {
            Ordinary(&'executor mut crate::dispatch::MmExecutorParticipation),
            Mutation(quiesce::MmStage1Authority<'executor>),
        }

        let edits_stage1 =
            syscall_takes_pre_dispatch_pt_pause(request.number.raw(), request.args.0[2], true);
        let mut mm_phase = if edits_stage1 {
            match quiesce::acquire_mm_stage1_authority(
                mm_executor,
                self.this_tid,
                quiesce::PtPauseBudget::DEFAULT,
            ) {
                Ok(authority) => SyscallMmPhase::Mutation(authority),
                Err(
                    quiesce::PtPauseError::TimedOut | quiesce::PtPauseError::UnkickableExecutor,
                ) => {
                    // No dispatcher/backend mapping call has started yet. Return
                    // a clean Linux allocation failure after pt_pause rolled the
                    // request back and resumed already-parked siblings. This is
                    // still a completed syscall boundary, so retain the exact
                    // context required by errno completion and signal service.
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ENOMEM));
                }
            }
        } else {
            SyscallMmPhase::Ordinary(mm_executor)
        };
        // The parked-slice, sleep/poll deadline and child-wait trace state that
        // used to live here belonged to the in-loop compatibility wait arms.
        // Every blocking outcome now escapes to the executor's continuation
        // before the match, so this function owns no wait state at all.
        let sync_shared_file_aliases = engine.needs_shared_file_alias_sync();
        'service: {
            if sync_shared_file_aliases && !matches!(request.number.raw(), 260 | 95) {
                engine.sync_shared_file_aliases()?;
            }
            let outcome =
                dispatch_with_panic_backstop(request.number.raw(), self.this_tid, || {
                    let lease_guard = if crate::dispatch::syscall_requires_execution_lease(
                        request.number.raw(),
                        request.args,
                    ) {
                        Some(self.execution_lease.lock())
                    } else {
                        None
                    };
                    let lease = lease_guard.as_deref().and_then(|g| g.as_ref());
                    if crate::dispatch::syscall_requires_mm_mutation(
                        request.number.raw(),
                        request.args,
                    ) {
                        let coordinator = kernel.dispatcher.mm_mutation_coordinator();
                        let stage1_authority = match &mut mm_phase {
                            SyscallMmPhase::Mutation(authority) => authority,
                            SyscallMmPhase::Ordinary(_) => {
                                tracing::error!("mutation dispatch lacks outer stage-1 authority");
                                carrick_fatal!(
                                    "vcpu_loop::mm_stage1_authority",
                                    "mutation dispatch lacks outer stage-1 authority"
                                )
                            }
                        };
                        match stage1_authority {
                            quiesce::MmStage1Authority::Sole(authority) => {
                                let mut mutation = crate::dispatch::mm_mutation::from_sole_executor(
                                    authority,
                                    coordinator,
                                    kernel_context.shared().mm().id(),
                                );
                                kernel
                                    .dispatcher
                                    .dispatch_threaded_prepared_mutation_with_lease(
                                        &kernel_context,
                                        syscall,
                                        engine,
                                        &kernel.reporter,
                                        ThreadCtx::new(self.this_tid, &self.registry, &self.futex),
                                        MutationDispatchRoute {
                                            guard: &mut mutation,
                                            lease,
                                        },
                                    )
                            }
                            quiesce::MmStage1Authority::Paused(authority) => {
                                let mut mutation =
                                    crate::dispatch::mm_mutation::from_pt_pause(authority);
                                kernel
                                    .dispatcher
                                    .dispatch_threaded_prepared_mutation_with_lease(
                                        &kernel_context,
                                        syscall,
                                        engine,
                                        &kernel.reporter,
                                        ThreadCtx::new(self.this_tid, &self.registry, &self.futex),
                                        MutationDispatchRoute {
                                            guard: &mut mutation,
                                            lease,
                                        },
                                    )
                            }
                        }
                    } else {
                        let mm_executor = match &mut mm_phase {
                            SyscallMmPhase::Ordinary(executor) => &mut **executor,
                            SyscallMmPhase::Mutation(_) => {
                                tracing::error!(
                                    "ordinary dispatch unexpectedly owns stage-1 authority"
                                );
                                carrick_fatal!(
                                    "vcpu_loop::mm_stage1_authority",
                                    "ordinary dispatch unexpectedly owns stage-1 authority"
                                )
                            }
                        };
                        kernel
                            .dispatcher
                            .dispatch_threaded_prepared_with_mm_executor_and_lease(
                                &kernel_context,
                                syscall,
                                engine,
                                &kernel.reporter,
                                ThreadCtx::new(self.this_tid, &self.registry, &self.futex),
                                OrdinaryDispatchRoute {
                                    lease,
                                    mm_executor: Some(mm_executor),
                                },
                            )
                    }
                })?;
            if continuation::is_blocking_dispatch_outcome(&outcome) {
                // The persistent executor converts this exact owned outcome into
                // a continuation at its quantum boundary. This is the ONLY exit
                // for a blocking outcome; the arm below only fails closed.
                return Ok(outcome);
            }
            match outcome {
                // Every blocking outcome escaped above, into the executor's
                // continuation. Reaching this arm would mean the escape and
                // `is_blocking_dispatch_outcome` had drifted apart, so it fails
                // closed rather than re-entering a host wait: the retired lanes
                // parked a host thread here through `CompatibilityThreadWaiter`,
                // which is exactly the authority HVPatch must not take.
                blocking @ (DispatchOutcome::BlockingHostWrite(_)
                | DispatchOutcome::BlockingRecordLock(_)
                | DispatchOutcome::WaitOnFds { .. }
                | DispatchOutcome::WaitOnProcExit { .. }
                | DispatchOutcome::WaitOnProcState { .. }
                | DispatchOutcome::WaitOnHvpatchChild { .. }
                | DispatchOutcome::WaitOnSignals { .. }
                | DispatchOutcome::WaitOnSleep { .. }
                | DispatchOutcome::WaitOnSharedWord { .. }) => {
                    break 'service Err(RuntimeError::Configuration(format!(
                        "blocking dispatch outcome reached the syscall service tail: {blocking:?}"
                    )));
                }
                DispatchOutcome::MapHostAlias {
                    success_retval,
                    transaction,
                    va,
                    ipa,
                    len,
                    payload,
                    backing,
                    prot,
                    prot_none,
                } if kernel.hvpatch_process.is_some() => {
                    let shared = backing.is_shared();
                    let coordinator = kernel.dispatcher.mm_mutation_coordinator();
                    let install_alias = |permit: &crate::dispatch::mm_mutation::HostAliasPermit<
                        '_,
                    >| {
                        let Some(install) = transaction.claim(permit) else {
                            drop(backing);
                            return Ok(DispatchOutcome::Returned {
                                value: crate::linux_abi::LINUX_ENOMEM.guest_retval(),
                            });
                        };

                        // The dispatch transaction is exclusively claimed, but no
                        // backend mutation has started. Allocate every ID and event
                        // slot before arming the backend's topology-locked staging.
                        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2)
                            .map_err(crate::kernel::FrameInventoryReserveError::from)?;
                        let reservation = kernel_context
                            .kernel()
                            .reserve_frame_inventory(1, 1, capacity)?;
                        let inventory_transaction = reservation.transaction();
                        let process = kernel.hvpatch_process.as_ref().ok_or_else(|| {
                            RuntimeError::Configuration(
                                "HVPatch alias inventory has no process context".to_owned(),
                            )
                        })?;
                        let registry = crate::fork_quiesce::FrameRegistryGuard::new(
                            crate::fork_quiesce::frame_registry_lock().lock(),
                        );
                        if let Err(error) = engine.begin_alias_inventory(reservation) {
                            let abandoned = kernel_context
                                .kernel()
                                .frame_inventory()
                                .abandon(inventory_transaction);
                            debug_assert!(abandoned);
                            return Err(error.into());
                        }

                        if let Err(error) = engine.map_host_alias(va, ipa, len, &payload, backing) {
                            // A failed alias install is guest-argument-reachable
                            // (an oversized/awkwardly-placed mmap can exhaust the
                            // global frame IPA arena or fail hv_vm_map), so it must
                            // lower to a guest errno, never abort the VM carrier —
                            // one Linux process's bad mmap would otherwise kill
                            // EVERY process multiplexed into this carrier.
                            //
                            // Stage-1/stage-2 unwind is the backend's own (RAII host
                            // mappings and global-frame IPA leases); this arm rolls
                            // back the two publications it armed itself: the
                            // backend's alias staging — without which the NEXT guest
                            // mmap fails as an "overlapping HVPatch alias inventory
                            // transaction" — and the kernel's frame-inventory
                            // transaction. `install` is dropped unclaimed, which
                            // aborts the dispatcher's pending VMA commit and wakes
                            // blocked sibling mapping syscalls.
                            engine.abandon_alias_inventory();
                            let abandoned = kernel_context
                                .kernel()
                                .frame_inventory()
                                .abandon(inventory_transaction);
                            debug_assert!(abandoned);
                            drop(registry);
                            drop(install);
                            tracing::error!(
                                va = format_args!("{:#x}", va.raw()),
                                len = format_args!("{len:#x}"),
                                shared,
                                %error,
                                "HVPatch alias install failed; guest mmap lowered to ENOMEM"
                            );
                            return Ok(DispatchOutcome::Returned {
                                value: crate::linux_abi::LINUX_ENOMEM.guest_retval(),
                            });
                        }
                        use crate::kernel::debug::HvpatchAliasInstallSite as Site;
                        let guest_pid = process.pid();
                        let guest_tid = self.this_tid.raw();
                        let refuse = |site: Site, error: String, frame| {
                            refuse_alias_install(
                                kernel,
                                &kernel_context,
                                site,
                                guest_pid,
                                guest_tid,
                                va.raw(),
                                len,
                                prot,
                                shared,
                                prot_none,
                                error,
                                frame,
                            )
                        };
                        let Some(commit) = engine.take_alias_inventory() else {
                            return Err(refuse(
                                Site::InventoryCommitMissing,
                                "backend staged no alias inventory commit".to_owned(),
                                None,
                            ));
                        };
                        // Publish to the kernel frame-inventory authority BEFORE
                        // releasing the registry guard. Staging above made a fresh
                        // shared-file frame visible to every later installer of the
                        // same file through the backend's shared-frame registry
                        // (`stage_mapping_in`: `frames.shared.entry(backing)`), and
                        // a reuser's batch names that frame WITHOUT reserving it —
                        // the authority accepts it only if the frame is already
                        // live. Publishing after the release (d913972c2) let a
                        // sibling stage its reuse and publish first, and its apply
                        // was refused with `UnreservedFrame`: the silent rc=134
                        // carrier abort of 2026-09-08 (go-build reducer, and the
                        // MAP_SHARED two-process reducer 4/4). Holding the
                        // guard across the apply makes publication order equal to
                        // staging order, as the registry reuse relies on. Lock order
                        // is unchanged: the authority mutex is a leaf
                        // (`frame_inventory.rs` never calls out while holding it).
                        let published = apply_alias_frame_inventory(&kernel_context, commit);
                        drop(registry);
                        if let Err(error) = published {
                            return Err(refuse(
                                Site::InventoryPublish,
                                error.to_string(),
                                error.frame(),
                            ));
                        }

                        let Ok(len_bytes) = usize::try_from(len) else {
                            return Err(refuse(
                                Site::LenOverflow,
                                "range length does not fit usize".to_owned(),
                                None,
                            ));
                        };
                        if prot_none
                            && let Err(error) = engine.protect_range(va.raw(), len_bytes, 0)
                        {
                            return Err(refuse(Site::ProtectNone, error.to_string(), None));
                        }
                        engine.set_mapping_protection_and_sharing(
                            va.raw(),
                            len_bytes,
                            prot_none,
                            !carrick_abi::LinuxProtFlags::from_bits_truncate(prot)
                                .contains(carrick_abi::LinuxProtFlags::WRITE),
                            if shared {
                                carrick_guest_mem::MappingSharing::Shared
                            } else {
                                carrick_guest_mem::MappingSharing::Private
                            },
                        );
                        if let Some((bus_start, bus_len)) = install.bus_fault_range() {
                            let Ok(bus_len) = usize::try_from(bus_len) else {
                                return Err(refuse(
                                    Site::BusFaultLenOverflow,
                                    format!(
                                        "bus-fault tail length {bus_len:#x} does not fit usize"
                                    ),
                                    None,
                                ));
                            };
                            if let Err(error) = engine.protect_range(bus_start, bus_len, 0) {
                                return Err(refuse(
                                    Site::BusFaultProtect,
                                    format!("bus-fault tail {bus_start:#x}+{bus_len:#x}: {error}"),
                                    None,
                                ));
                            }
                            engine.set_no_access(bus_start, bus_len, true);
                        }
                        if let Err(error) = kernel.dispatcher.commit_host_alias_install(install) {
                            return Err(refuse(Site::DispatcherCommit, format!("{error:?}"), None));
                        }
                        Ok(DispatchOutcome::Returned {
                            value: success_retval,
                        })
                    };
                    let stage1_authority = match &mut mm_phase {
                        SyscallMmPhase::Mutation(authority) => authority,
                        SyscallMmPhase::Ordinary(_) => {
                            tracing::error!("host-alias install lacks outer stage-1 authority");
                            carrick_fatal!(
                                "vcpu_loop::mm_stage1_authority",
                                "host-alias install lacks outer stage-1 authority"
                            )
                        }
                    };
                    let installed = match stage1_authority {
                        quiesce::MmStage1Authority::Sole(authority) => {
                            let mutation = crate::dispatch::mm_mutation::from_sole_executor(
                                authority,
                                coordinator,
                                kernel_context.shared().mm().id(),
                            );
                            let permit = mutation.host_alias_permit();
                            install_alias(&permit)
                        }
                        quiesce::MmStage1Authority::Paused(authority) => {
                            let mutation = crate::dispatch::mm_mutation::from_pt_pause(authority);
                            let permit = mutation.host_alias_permit();
                            install_alias(&permit)
                        }
                    };
                    break 'service installed;
                }
                other => break 'service Ok(other),
            }
        }
    }

    pub(super) fn complete_returned(
        &mut self,
        engine: &mut E,
        reporter: &CompatReporter,
        value: i64,
    ) -> Result<i64, RuntimeError> {
        if !matches!(
            self.syscall_completion,
            SyscallCompletionOwnership::Guest(_)
        ) {
            return Err(RuntimeError::Configuration(
                "threaded syscall completed without guest completion ownership".to_owned(),
            ));
        }
        engine.complete_syscall(value)?;
        let SyscallCompletionOwnership::Guest(completion) = std::mem::replace(
            &mut self.syscall_completion,
            SyscallCompletionOwnership::Idle,
        ) else {
            unreachable!("guest completion ownership checked before engine completion")
        };
        completion.publish_return(reporter, value);
        Ok(value)
    }

    pub(super) fn complete_errno(
        &mut self,
        engine: &mut E,
        reporter: &CompatReporter,
        errno: LinuxErrno,
    ) -> Result<i64, RuntimeError> {
        self.complete_returned(engine, reporter, errno.guest_retval())
    }

    pub(super) fn retire_syscall(&mut self) -> Result<(), RuntimeError> {
        match std::mem::replace(
            &mut self.syscall_completion,
            SyscallCompletionOwnership::Idle,
        ) {
            SyscallCompletionOwnership::Guest(_) => Ok(()),
            other => {
                self.syscall_completion = other;
                Err(RuntimeError::Configuration(
                    "threaded syscall retired without guest completion ownership".to_owned(),
                ))
            }
        }
    }

    fn complete_precompleted_child(
        &mut self,
        reporter: &CompatReporter,
        value: i64,
    ) -> Result<(), RuntimeError> {
        let completion = match std::mem::replace(
            &mut self.syscall_completion,
            SyscallCompletionOwnership::Idle,
        ) {
            SyscallCompletionOwnership::Guest(completion) => completion,
            other => {
                self.syscall_completion = other;
                return Err(RuntimeError::Configuration(
                    "child syscall completion lacks guest ownership".to_owned(),
                ));
            }
        };
        completion.publish_return(reporter, value);
        Ok(())
    }
}

pub(crate) struct PendingSignalAction {
    pub(crate) term_signal: Option<i32>,
    pub(crate) stop_signal: Option<i32>,
    pub(crate) stop_generation: Option<crate::kernel::JobControlStopInvalidationGeneration>,
}

impl PendingSignalAction {
    pub(super) fn ignored() -> Self {
        Self {
            term_signal: None,
            stop_signal: None,
            stop_generation: None,
        }
    }

    pub(super) fn terminate(signum: i32) -> Self {
        Self {
            term_signal: Some(signum),
            stop_signal: None,
            stop_generation: None,
        }
    }

    pub(super) fn stop(
        signum: i32,
        generation: Option<crate::kernel::JobControlStopInvalidationGeneration>,
    ) -> Self {
        Self {
            term_signal: None,
            stop_signal: Some(signum),
            stop_generation: generation,
        }
    }
}

/// Linux aarch64 syscall numbers that auto-restart when interrupted by an
/// SA_RESTART handler (the kernel's `ERESTARTSYS` set), per `signal(7)`
/// "Interruption of system calls and library functions by signal handlers".
///
/// This listed only `waitid`/`wait4` for a long time, which meant EVERY other
/// blocking call surfaced `EINTR` to a guest that had explicitly asked, via
/// `SA_RESTART`, not to see it. libuv's `eintr_handling` is the reduced case:
/// a thread `kill(getpid(), SIGUSR1)`s while the main thread is blocked in a
/// synchronous `read(2)` on an empty pipe, and libuv installs its signal
/// handlers with `SA_RESTART`, so Linux resumes the read and returns the 13
/// bytes. Carrick returned `-EINTR` (the test reports `-4 == 13`).
///
/// The `signal(7)` "never restarted" list is deliberately EXCLUDED, so those
/// keep surfacing `EINTR` as Linux does: `poll`/`ppoll`, `select`/`pselect6`,
/// `epoll_wait`/`epoll_pwait`, `nanosleep`/`clock_nanosleep`, `io_getevents`,
/// `msgrcv`/`msgsnd`, `semop`/`semtimedop`, and the `sigsuspend`/
/// `rt_sigtimedwait` family.
///
/// Socket calls (`accept`, `connect`, the `recv`/`send` families) are also
/// absent, and that is a KNOWN REMAINING GAP rather than a judgement that they
/// do not restart — they do, but only when the socket carries no
/// `SO_RCVTIMEO`/`SO_SNDTIMEO`. This decision point sees only the syscall
/// NUMBER, not the fd, so honouring that exclusion needs the timeout plumbed
/// through first; restarting unconditionally would re-block a timeout socket
/// that Linux would have failed with `EINTR`.
pub(super) fn is_restartable_syscall(nr: u64) -> bool {
    matches!(
        nr,
        // Reads and writes on "slow" devices — pipes, terminals, sockets. On a
        // regular file these never return EINTR, so listing them is harmless.
        63  // read
        | 64  // write
        | 65  // readv
        | 66  // writev
        | 67  // pread64
        | 68  // pwrite64
        | 69  // preadv
        | 70  // pwritev
        | 286 // preadv2
        | 287 // pwritev2
        | 29  // ioctl (on a slow device)
        | 56  // openat (blocks opening a FIFO)
        // Advisory file locking: flock, and fcntl's F_SETLKW. fcntl is listed
        // whole because the blocking lock commands are the only ones that can
        // return EINTR.
        | 32  // flock
        | 25  // fcntl
        // POSIX message queues.
        | 182 // mq_timedsend
        | 183 // mq_timedreceive
        | 278 // getrandom
        // Waits.
        | 95  // waitid
        | 260 // wait4
    )
}
pub(super) fn is_default_stop_signal(signum: i32) -> bool {
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
#[allow(clippy::too_many_arguments)]
pub(super) fn service_signals_threaded<E: ThreadedEngine>(
    kernel: &Kernel,
    context: &crate::kernel::KernelContext,
    engine: &mut E,
    this_tid: ThreadId,
    fatal_image_generation: u64,
    last_syscall_retval: Option<i64>,
    interrupted_pc: Option<u64>,
    continuation_restart: Option<continuation::RestartDecision>,
    reserved_signal: Option<continuation::ReservedSignal>,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    {
        let restart =
            continuation_restart.map(|decision| decision == continuation::RestartDecision::Restart);
        let action = match reserved_signal {
            Some(reserved) => deliver_reserved_signal_with_restart(
                engine,
                &kernel.dispatcher,
                context,
                last_syscall_retval,
                this_tid,
                interrupted_pc,
                restart,
                reserved,
            )?,
            None => deliver_pending_signal_with_restart(
                engine,
                &kernel.dispatcher,
                context,
                last_syscall_retval,
                this_tid,
                interrupted_pc,
                restart,
            )?,
        };
        if let Some(action) = action {
            if let Some(signum) = action.stop_signal {
                if kernel.hvpatch_process.is_some() {
                    let signal = crate::kernel::LinuxSignal::for_signal_number(signum)
                        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
                    if !context.kernel().stop_task_for_job_control(
                        context.task().key().id,
                        signal,
                        action.stop_generation,
                    ) {
                        return Err(RuntimeError::Configuration(format!(
                            "HVPatch default-stop lost live task {}",
                            context.task().key().id.raw()
                        )));
                    }
                } else {
                    stop_by_signal(signum);
                }
                return Ok(None);
            }
            if let Some(signum) = action.term_signal {
                if requires_no_unwind_host_exit(kernel, engine.is_forked_child()) {
                    // Destroy a name-bound child VM (bhyve) before _exit — KVM/HVF
                    // is a no-op (fd-lifetime-bound VM). Fail before terminal
                    // publication if copied shared-file writeback is incomplete.
                    engine.process_exit_cleanup()?;
                    let out = kernel.dispatcher.stdout();
                    let err = kernel.dispatcher.stderr();
                    forked_child_die_by_signal(signum, &out, &err);
                }
                kernel.record_fatal_signal(FatalSignalRecord {
                    image_generation: fatal_image_generation,
                    tid: context.thread().key().tid,
                    signo: signum,
                    code: 0,
                    addr: 0,
                });
                let result = assemble_run_result(kernel, 128 + signum, Some(signum), traps, false);
                return Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::binding::*;
    use super::signal::{lower_el0_fault, upgrade_protection_si_code};
    use super::*;
    use carrick_guest_mem::GuestMemory;
    use std::time::{Duration, Instant};

    struct ContinueInterceptor;

    impl crate::observe::SyscallInterceptor for ContinueInterceptor {
        fn intercept(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::InterceptedSyscall<'_>,
        ) -> crate::observe::InterceptAction {
            crate::observe::InterceptAction::Continue
        }
    }

    pub(super) fn synthetic_elf(machine: u16) -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const PT_LOAD: u32 = 1;
        let mut elf = vec![0_u8; 0x1000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000_u64.to_le_bytes());
        let len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&len.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf
    }

    fn production_shaped_image(machine: u16) -> AddressSpace {
        AddressSpace::load_elf_bytes_with_reader_for(&synthetic_elf(machine), &|_| None, machine)
            .expect("production-shaped ELF image")
    }

    fn serialize_auxv(image: AddressSpace) -> AddressSpace {
        image
            .with_linux_initial_stack_page_size(
                [b"/fixture".as_slice()],
                std::iter::empty::<&[u8]>(),
                crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
            )
            .expect("serialize production-shaped auxv")
    }

    fn advertises_vdso(image: &AddressSpace) -> bool {
        image.linux_auxv_image().chunks_exact(16).any(|entry| {
            u64::from_le_bytes(entry[..8].try_into().expect("auxv type word"))
                == carrick_abi::LINUX_AT_SYSINFO_EHDR
        })
    }

    fn maps_vdso(image: &AddressSpace) -> bool {
        image
            .regions()
            .iter()
            .any(|region| region.start == carrick_mem::vdso::LINUX_VDSO_BASE)
    }

    #[test]
    fn vmm_image_policy_restricts_aarch64_and_x8664_fastpaths_production_shaped_vmm_vdso_auxv_coherence()
     {
        use carrick_hal::GuestArch as _;
        use carrick_hal::aarch64_arch::Aarch64GuestArch;
        use carrick_hal::x8664_arch::X8664GuestArch;

        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_interceptor(Arc::new(ContinueInterceptor));

        let aarch64_disabled =
            crate::vdso_policy::with_optional_vdso_for_clock_at_with_mode::<Aarch64GuestArch>(
                production_shaped_image(Aarch64GuestArch::elf_machine()),
                dispatcher.container().clock(),
                carrick_mem::vdso::LINUX_VVAR_BASE,
                carrick_mem::vdso::LINUX_VDSO_BASE,
                false,
                crate::vdso_policy::VdsoDebugMode::Disabled,
            )
            .expect("disabled aarch64 VMM image");
        let aarch64_disabled = serialize_auxv(aarch64_disabled);
        assert!(!maps_vdso(&aarch64_disabled));
        assert!(!advertises_vdso(&aarch64_disabled));

        let aarch64_restricted = with_vmm_vdso_for_dispatcher::<Aarch64GuestArch>(
            production_shaped_image(Aarch64GuestArch::elf_machine()),
            &dispatcher,
            false,
        )
        .expect("restricted aarch64 VMM image");
        let vdso = aarch64_restricted
            .regions()
            .iter()
            .find(|region| region.start == carrick_mem::vdso::LINUX_VDSO_BASE)
            .expect("aarch64 no-fastpaths vDSO")
            .bytes();
        let no_fastpaths = carrick_mem::vdso::vdso_image_bytes_without_fastpaths();
        assert_eq!(&vdso[..no_fastpaths.len()], no_fastpaths.as_slice());
        let aarch64_restricted = serialize_auxv(aarch64_restricted);
        assert!(maps_vdso(&aarch64_restricted));
        assert!(advertises_vdso(&aarch64_restricted));

        let x8664_restricted = with_vmm_vdso_for_dispatcher::<X8664GuestArch>(
            production_shaped_image(X8664GuestArch::elf_machine()),
            &dispatcher,
            false,
        )
        .expect("restricted x86_64 VMM image");
        let x8664_restricted = serialize_auxv(x8664_restricted);
        assert!(!maps_vdso(&x8664_restricted));
        assert!(!advertises_vdso(&x8664_restricted));

        let unrestricted = with_vmm_vdso_for_dispatcher::<Aarch64GuestArch>(
            production_shaped_image(Aarch64GuestArch::elf_machine()),
            &SyscallDispatcher::new(),
            false,
        )
        .expect("unrestricted aarch64 VMM image");
        let unrestricted = serialize_auxv(unrestricted);
        assert!(maps_vdso(&unrestricted));
        assert!(advertises_vdso(&unrestricted));
    }

    #[test]
    fn non_macos_exec_loader_accepts_visibility_contract() {
        type Loader = fn(
            &SyscallDispatcher,
            &str,
            Vec<Vec<u8>>,
            Vec<Vec<u8>>,
            bool,
        ) -> Result<AddressSpace, crate::linux_abi::LinuxErrno>;

        let loader: Loader = macos_helper_stubs::load_execve_image;
        let _ = loader;
    }

    /// `SA_RESTART` must resume the calls `signal(7)` says it resumes, and must
    /// NOT resume the ones it says always fail with `EINTR`.
    ///
    /// The set used to be just `waitid`/`wait4`, so every other blocking call
    /// surfaced `EINTR` to a guest that had explicitly asked not to see it —
    /// libuv's `eintr_handling` failed because a synchronous `read(2)` on a
    /// pipe, interrupted by a `SA_RESTART` SIGUSR1, returned `-EINTR` instead
    /// of the 13 bytes. The negative half matters just as much: restarting
    /// `poll` or `nanosleep` would be its own divergence, silently turning a
    /// guest's interruptible wait into an uninterruptible one.
    #[test]
    fn sa_restart_restarts_exactly_the_documented_syscalls() {
        // Restarted (signal(7)): slow-device I/O, blocking open, file locks,
        // POSIX mqueues, getrandom, waits.
        for (nr, name) in [
            (63u64, "read"),
            (64, "write"),
            (65, "readv"),
            (66, "writev"),
            (67, "pread64"),
            (68, "pwrite64"),
            (69, "preadv"),
            (70, "pwritev"),
            (286, "preadv2"),
            (287, "pwritev2"),
            (29, "ioctl"),
            (56, "openat"),
            (32, "flock"),
            (25, "fcntl"),
            (182, "mq_timedsend"),
            (183, "mq_timedreceive"),
            (278, "getrandom"),
            (95, "waitid"),
            (260, "wait4"),
        ] {
            assert!(
                is_restartable_syscall(nr),
                "{name} ({nr}) is restarted under SA_RESTART"
            );
        }

        // NEVER restarted, regardless of SA_RESTART (signal(7)).
        for (nr, name) in [
            (73u64, "ppoll"),
            (72, "pselect6"),
            (22, "epoll_pwait"),
            (101, "nanosleep"),
            (115, "clock_nanosleep"),
            (188, "msgrcv"),
            (189, "msgsnd"),
            (193, "semop"),
            (192, "semtimedop"),
            (133, "rt_sigsuspend"),
            (137, "rt_sigtimedwait"),
            (4, "io_getevents"),
        ] {
            assert!(
                !is_restartable_syscall(nr),
                "{name} ({nr}) always fails with EINTR, even under SA_RESTART"
            );
        }
    }

    struct ProtectionOnlyMemory {
        protections: carrick_guest_mem::protections::MemoryProtections,
    }

    impl carrick_guest_mem::GuestMemory for ProtectionOnlyMemory {
        fn protections(&self) -> Option<&carrick_guest_mem::protections::MemoryProtections> {
            Some(&self.protections)
        }

        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            Err(carrick_guest_mem::MemoryError::OutOfBounds { address, length })
        }

        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            Err(carrick_guest_mem::MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })
        }
    }

    impl CurrentMmMemory for ProtectionOnlyMemory {}

    pub(crate) struct EndpointTestSignalPump;

    impl SignalPumpControl for EndpointTestSignalPump {
        fn start_signal_pump(
            &self,
            _registry: &Arc<dyn VcpuRegistry>,
            _futex: &Arc<dyn PlatformFutex>,
        ) {
        }
    }

    pub(crate) struct EndpointTestSignalArrival;

    impl carrick_hal::SignalArrival for EndpointTestSignalArrival {
        fn wake_all_waiters(&self) {}
    }

    #[derive(Debug, Default)]
    pub(crate) struct EndpointRecordingWaker(pub(crate) std::sync::atomic::AtomicUsize);

    impl crate::kernel::TaskWaker for EndpointRecordingWaker {
        fn wake_task(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    pub(crate) struct Memory(std::collections::BTreeMap<u64, Vec<u8>>);
    impl carrick_guest_mem::GuestMemory for Memory {
        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.0
                .get(&address)
                .filter(|bytes| bytes.len() == length)
                .cloned()
                .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length })
        }

        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.0.insert(address, bytes.to_vec());
            Ok(())
        }
    }

    impl CurrentMmMemory for Memory {}

    impl threads::CloneTidMemory for Memory {
        fn read_clone_tid_bytes(
            &self,
            address: u64,
            len: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            self.read_bytes_raw(address, len)
        }

        fn write_clone_tid_bytes(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.write_bytes_raw(address, bytes)
        }
    }

    pub(crate) struct DynamicCloneBackendOps;

    impl HvpatchCloneBackendOps<Memory> for DynamicCloneBackendOps {
        type Prepared = (u64, u64);
        type Backend = ();

        fn prepare(
            &mut self,
            _memory: &Memory,
            _identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
            _entry: carrick_hal::GuestEntryRegs,
            mm_generation: u64,
            asid_generation: u64,
        ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError> {
            Ok((
                (mm_generation, asid_generation),
                carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                    carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                        gprs: [0; 31],
                        pc: 0x1000,
                        pstate: 0,
                        trap_pc: 0,
                        trap_pstate: 0,
                        sp_el0: 0x8000,
                        elr_el1: 0,
                        spsr_el1: 0,
                        ttbr0: 0,
                        ttbr1: 0,
                        tcr: 0,
                        sctlr_el1: 0,
                        mair_el1: 0,
                        vbar_el1: 0,
                        cpacr_el1: 0,
                        cntkctl_el1: 0,
                        tpidr_el1: 0,
                        actlr_el1: 0,
                        tpidr_el0: 0,
                        tpidrro_el0: 0,
                        contextidr_el1: 0,
                        vregs: [0; 32],
                        fpsr: 0,
                        fpcr: 0,
                        pending_resume_pc: None,
                        last_syscall_nr: None,
                        last_syscall_orig_x0: 0,
                        last_fault_esr: 0,
                        last_exit_class: 0,
                        is_forked_child: false,
                        syscall_continuation: None,
                        mm_generation,
                        asid_generation,
                    },
                ),
            ))
        }

        fn abort(&mut self, _prepared: Self::Prepared) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn commit(
            &mut self,
            _prepared: Self::Prepared,
            _directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
        ) -> Result<Self::Backend, RuntimeError> {
            Ok(())
        }

        fn bind_child_kernel(
            &mut self,
            _backend: &mut Self::Backend,
            _token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
        ) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn frame_cow_owner_inventory(
            &self,
            _backend: &Self::Backend,
        ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
            fixed_frame_cow_owner_inventory_for_test(
                carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    std::num::NonZeroU64::new(1).unwrap(),
                ),
            )
        }

        fn activate_child(&mut self, _backend: &mut Self::Backend) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn make_binding_state(
            &mut self,
            _backend: Self::Backend,
        ) -> executor::HvpatchTaskEngineBindingState {
            executor::HvpatchTaskEngineBindingState::test_only()
        }
    }

    #[derive(Default)]
    pub(super) struct FakeBackendOps {
        parent_commits: usize,
        parent_rollbacks: usize,
        backend_prepare_rollbacks: usize,
        aborts: usize,
        fail_stops: usize,
        child_kernel_bound: bool,
        copied_preparations: usize,
        shared_preparations: usize,
        inventory_applies: usize,
        prepare_fails: bool,
        abort_fails: bool,
        on_prepare: Option<Arc<dyn Fn() + Send + Sync>>,
        request_parent_mm: Option<u64>,
        request_child_mm: Option<u64>,
    }

    impl<E: ThreadedEngine> HvpatchProcessBackendOps<E, Memory> for FakeBackendOps {
        type Prepared = ();
        type Backend = ();

        fn prepare(
            &mut self,
            _memory: &mut Memory,
            inventory: HvpatchProcessInventoryPreparation<'_>,
            request: carrick_hal::ProcessForkRequest,
            _identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
            mm_generation: u64,
            asid_generation: u64,
        ) -> Result<
            (
                Self::Prepared,
                carrick_hal::threaded::GuestCpuState,
                Arc<dyn VcpuRegistry>,
            ),
            RuntimeError,
        > {
            self.request_parent_mm = Some(request.plan.parent_mm());
            self.request_child_mm = Some(request.plan.child_mm());
            if self.prepare_fails {
                self.backend_prepare_rollbacks += 1;
                return Err(RuntimeError::Trap(
                    carrick_vmm_hvf::trap::TrapError::Hypervisor(
                        "simulated backend prepare error".to_owned(),
                    ),
                ));
            }
            if let Some(hook) = &self.on_prepare {
                hook();
            }
            match inventory {
                HvpatchProcessInventoryPreparation::Copied(_) => {
                    self.copied_preparations += 1;
                }
                HvpatchProcessInventoryPreparation::SharedMm { .. } => {
                    self.shared_preparations += 1;
                }
            }
            Ok((
                (),
                carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                    carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                        gprs: [0; 31],
                        pc: 0x1000,
                        pstate: 0,
                        trap_pc: 0,
                        trap_pstate: 0,
                        sp_el0: 0x8000,
                        elr_el1: 0,
                        spsr_el1: 0,
                        ttbr0: 0,
                        ttbr1: 0,
                        tcr: 0,
                        sctlr_el1: 0,
                        mair_el1: 0,
                        vbar_el1: 0,
                        cpacr_el1: 0,
                        cntkctl_el1: 0,
                        tpidr_el1: 0,
                        actlr_el1: 0,
                        tpidr_el0: 0,
                        tpidrro_el0: 0,
                        contextidr_el1: 0,
                        vregs: [0; 32],
                        fpsr: 0,
                        fpcr: 0,
                        pending_resume_pc: None,
                        last_syscall_nr: None,
                        last_syscall_orig_x0: 0,
                        last_fault_esr: 0,
                        last_exit_class: 0,
                        is_forked_child: true,
                        syscall_continuation: None,
                        mm_generation,
                        asid_generation,
                    },
                ),
                Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            ))
        }

        fn abort(&mut self, _prepared: Self::Prepared) -> Result<(), RuntimeError> {
            self.aborts += 1;
            if self.abort_fails {
                return Err(RuntimeError::Configuration(
                    "simulated backend abort failure".to_owned(),
                ));
            }
            Ok(())
        }

        fn commit_parent(&mut self, _memory: &mut Memory) -> Result<(), RuntimeError> {
            self.parent_commits += 1;
            Ok(())
        }

        fn rollback_parent(&mut self, _memory: &mut Memory) -> Result<(), RuntimeError> {
            self.parent_rollbacks += 1;
            Ok(())
        }

        fn commit(
            &mut self,
            _prepared: Self::Prepared,
            _directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
        ) -> Result<Self::Backend, RuntimeError> {
            Ok(())
        }

        fn apply_inventory(
            &mut self,
            _backend: &Self::Backend,
            _kernel: &Arc<crate::kernel::Kernel>,
            _mm: crate::kernel::MmId,
        ) -> Result<(), RuntimeError> {
            assert!(
                self.child_kernel_bound,
                "inventory must follow exact child Kernel/MM binding"
            );
            self.inventory_applies += 1;
            Ok(())
        }

        fn bind_child_kernel(
            &mut self,
            _backend: &mut Self::Backend,
            _token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
        ) -> Result<(), RuntimeError> {
            self.child_kernel_bound = true;
            Ok(())
        }

        fn frame_cow_owner_inventory(
            &self,
            _backend: &Self::Backend,
        ) -> Arc<dyn carrick_hal::FrameCowOwnerInventory> {
            fixed_frame_cow_owner_inventory_for_test(
                carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    std::num::NonZeroU64::new(1).unwrap(),
                ),
            )
        }

        fn activate_child(&mut self, _backend: &mut Self::Backend) -> Result<(), RuntimeError> {
            Ok(())
        }

        fn make_binding_state(
            &mut self,
            _backend: Self::Backend,
        ) -> executor::HvpatchTaskEngineBindingState {
            executor::HvpatchTaskEngineBindingState::test_only()
        }

        fn guest_sp(&self, _memory: &Memory) -> Option<u64> {
            Some(0x8000)
        }

        fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError {
            self.fail_stops += 1;
            error
        }
    }

    pub(crate) struct NoopPlatformFutex;
    impl PlatformFutex for NoopPlatformFutex {
        fn private_wait(
            &self,
            _addr: u64,
            _val: u32,
            _tid: ThreadId,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
        ) -> carrick_hal::FutexOutcome {
            carrick_hal::FutexOutcome::Interrupted
        }
        fn private_wake(&self, _addr: u64, _n: u32) -> u32 {
            0
        }
        fn shared_wait(
            &self,
            _location: carrick_guest_mem::SharedFutexLocation,
            _val: u32,
            _tid: ThreadId,
            _timeout: Option<Duration>,
            _interrupted: &dyn Fn() -> bool,
            _wait_enrolled: &dyn Fn(),
        ) -> i64 {
            -1
        }
        fn shared_wake(
            &self,
            _location: carrick_guest_mem::SharedFutexLocation,
            _waiter_key: usize,
            _n: u32,
        ) -> i64 {
            0
        }
        fn requeue(&self, _from: u64, _to: u64, _wake: u32, _requeue: u32) -> (u32, u32) {
            (0, 0)
        }
        fn notify_signal_pending(&self) {}
        fn notify_signal_pending_for(&self, _tid: ThreadId) {}
    }

    struct RegistrationTestKick;

    impl carrick_hal::VcpuKickDyn for RegistrationTestKick {
        fn kick(&self) {}
    }

    pub(crate) fn registration_test_handle() -> Box<dyn carrick_hal::VcpuKickDyn> {
        Box::new(RegistrationTestKick)
    }

    #[derive(Debug, Default)]
    pub(crate) struct RuntimeTestExecutorKick(Mutex<Option<crate::kernel::ExecutorBinding>>);

    impl crate::kernel::ExecutorKick for RuntimeTestExecutorKick {
        fn try_bind(&self, binding: crate::kernel::ExecutorBinding) -> bool {
            let mut current = self.0.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: crate::kernel::ExecutorBinding) {
            let mut current = self.0.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn rebind_exact_with(
            &self,
            predecessor: crate::kernel::ExecutorBinding,
            successor: crate::kernel::ExecutorBinding,
            publish: &mut dyn FnMut() -> bool,
        ) -> bool {
            let mut current = self.0.lock();
            if *current != Some(predecessor) || !publish() {
                return false;
            }
            *current = Some(successor);
            true
        }

        fn deliver_exact(&self, token: crate::kernel::ExecutorKickToken) -> bool {
            self.0.lock().is_some_and(|binding| {
                binding.executor() == token.executor()
                    && binding.executor_epoch() == token.executor_epoch()
                    && binding.thread() == token.thread()
                    && binding.generation() == token.generation()
            })
        }

        fn current_binding(&self) -> Option<crate::kernel::ExecutorBinding> {
            *self.0.lock()
        }
    }

    #[derive(Clone)]
    pub(crate) struct CrashCaptureTestKick;

    impl carrick_hal::VcpuKick for CrashCaptureTestKick {
        fn kick(&self) {}
    }

    pub(crate) type CrashReadTracker = Arc<Mutex<Vec<(u64, usize)>>>;

    #[derive(Default)]
    pub(crate) struct CrashCaptureTestEngine {
        pub(crate) next_syscall: Option<carrick_hal::RawSyscall>,
        pub(crate) completed_syscalls: Vec<i64>,
        pub(crate) completion_events: Option<Arc<Mutex<Vec<&'static str>>>>,
        pub(crate) execve_installs: usize,
        pub(crate) exec_inventory_arms: usize,
        pub(crate) retirement_inventory: Option<carrick_hal::FrameInventoryReservation>,
        pub(crate) exec_inventory: Option<(
            Option<carrick_hal::FrameInventoryReservation>,
            carrick_hal::FrameInventoryReservation,
        )>,
        pub(crate) exec_support: bool,
        pub(crate) snapshot_cpu: Option<carrick_hal::threaded::GuestCpuState>,
        pub(crate) frame_cow_owner_inventory: Option<Arc<dyn carrick_hal::FrameCowOwnerInventory>>,
        pub(crate) installed_table_arena_sources: usize,
        pub(crate) guest_memory: std::collections::BTreeMap<u64, Vec<u8>>,
        pub(crate) read_tracker: Option<CrashReadTracker>,
        pub(crate) fail_read_at: Option<u64>,
    }

    impl carrick_guest_mem::GuestMemory for CrashCaptureTestEngine {
        fn read_bytes_raw(
            &self,
            address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            if self.fail_read_at == Some(address) {
                return Err(carrick_guest_mem::MemoryError::OutOfBounds { address, length });
            }
            if let Some(tracker) = &self.read_tracker {
                tracker.lock().push((address, length));
            }
            Ok(self
                .guest_memory
                .get(&address)
                .filter(|bytes| bytes.len() == length)
                .cloned()
                .unwrap_or_else(|| vec![0; length]))
        }

        fn write_bytes_raw(
            &mut self,
            address: u64,
            bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            self.guest_memory.insert(address, bytes.to_vec());
            Ok(())
        }
    }

    impl carrick_guest_mem::CurrentMmMemory for CrashCaptureTestEngine {}

    impl carrick_hal::RegAccess for CrashCaptureTestEngine {
        fn get_reg(&self, _register: carrick_hal::Reg) -> Result<u64, carrick_hal::OsError> {
            Ok(0)
        }

        fn set_reg(
            &mut self,
            _register: carrick_hal::Reg,
            _value: u64,
        ) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }

        fn get_sys_reg(&self, _register: carrick_hal::SysReg) -> Result<u64, carrick_hal::OsError> {
            Ok(0)
        }

        fn set_sys_reg(
            &mut self,
            _register: carrick_hal::SysReg,
            _value: u64,
        ) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }

        fn get_vreg(&self, _register: u32) -> Result<u128, carrick_hal::OsError> {
            Ok(0)
        }

        fn set_vreg(&mut self, _register: u32, _value: u128) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }

        fn get_fpcr(&self) -> Result<u64, carrick_hal::OsError> {
            Ok(0)
        }

        fn set_fpcr(&mut self, _value: u64) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }

        fn get_fpsr(&self) -> Result<u64, carrick_hal::OsError> {
            Ok(0)
        }

        fn set_fpsr(&mut self, _value: u64) -> Result<(), carrick_hal::OsError> {
            Ok(())
        }
    }

    impl carrick_hal::SyscallTrap for CrashCaptureTestEngine {
        fn next_syscall(&mut self) -> Result<Option<carrick_hal::RawSyscall>, TrapError> {
            Ok(self.next_syscall.take())
        }

        fn current_pc(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
            self.completed_syscalls.push(return_value);
            if let Some(events) = &self.completion_events {
                events.lock().push("engine");
            }
            Ok(())
        }

        fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
            self.execve_installs += 1;
            Ok(())
        }

        fn begin_exec_inventory(
            &mut self,
            retired: Option<carrick_hal::FrameInventoryReservation>,
            replacement: carrick_hal::FrameInventoryReservation,
        ) -> Result<(), TrapError> {
            self.exec_inventory_arms += 1;
            if self.exec_support {
                self.exec_inventory = Some((retired, replacement));
            } else {
                drop((retired, replacement));
            }
            Ok(())
        }

        fn take_exec_inventory(&mut self) -> Option<carrick_hal::ExecInventoryCommits> {
            let (retired, mut replacement) = self.exec_inventory.take()?;
            drop(retired);
            let transaction = replacement.transaction();
            let frame = replacement
                .claim_frame()
                .expect("test exec frame candidate");
            let mapping = replacement
                .claim_mapping()
                .expect("test exec mapping candidate");
            let generation = carrick_hal::MappingGeneration::from_backend_counter(
                std::num::NonZeroU64::new(1).unwrap(),
            );
            replacement
                .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                    transaction,
                    frame,
                    mapping,
                    generation,
                    gpa: carrick_guest_mem::Gpa(0x4000),
                    length: carrick_hal::FrameLength::from_mapping_extent(
                        std::num::NonZeroU64::new(0x4000).unwrap(),
                    ),
                    permissions: carrick_hal::MemPerms {
                        read: true,
                        write: true,
                        exec: false,
                    },
                })
                .expect("test exec prepare mapping");
            replacement
                .push(carrick_hal::FrameInventoryEvent::PublishMapping {
                    transaction,
                    mapping,
                    generation,
                })
                .expect("test exec publish mapping");
            Some((None, Some(replacement.commit(()))))
        }

        fn frame_inventory_exec_extent_counts(&self, _new_image: &AddressSpace) -> (usize, usize) {
            if self.exec_support { (0, 1) } else { (0, 0) }
        }

        fn inject_signal(
            &mut self,
            _signal: carrick_hal::SignalInjection,
        ) -> Result<(), TrapError> {
            Ok(())
        }

        fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
            Ok(0)
        }
    }

    impl ThreadedEngine for CrashCaptureTestEngine {
        type Arch = carrick_hal::Aarch64GuestArch;
        type KickHandle = CrashCaptureTestKick;
        type SiblingSpec = ();
        type ProcessSpec = ();

        fn install_stage1_table_arena_source(
            &mut self,
            _source: Box<dyn carrick_mem::page_table::TableArenaSource>,
        ) -> Result<(), TrapError> {
            self.installed_table_arena_sources += 1;
            Ok(())
        }

        fn take_guest_run_receipt_ns(&mut self) -> u64 {
            0
        }

        fn frame_cow_owner_inventory(
            &self,
        ) -> Option<Arc<dyn carrick_hal::FrameCowOwnerInventory>> {
            self.frame_cow_owner_inventory.as_ref().map(Arc::clone)
        }

        fn prepare_exec_address_space(
            &mut self,
            _root_slot_base: u64,
            _root_slot_size: u64,
            _asid: u16,
        ) -> Result<(), TrapError> {
            if self.exec_support {
                Ok(())
            } else {
                Err(TrapError::Hypervisor(
                    "crash timeout test does not prepare exec address spaces".to_owned(),
                ))
            }
        }

        fn complete_task_load_barrier(&mut self) -> Result<(), TrapError> {
            if self.exec_support {
                Ok(())
            } else {
                Err(TrapError::Hypervisor(
                    "crash timeout test does not complete task-load barriers".to_owned(),
                ))
            }
        }

        fn bind_task_snapshot_identity(&mut self, mm_generation: u64, asid_generation: u64) {
            if let Some(carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu)) =
                self.snapshot_cpu.as_mut()
            {
                let cpu = Arc::make_mut(cpu);
                cpu.mm_generation = mm_generation;
                cpu.asid_generation = asid_generation;
            }
        }

        fn begin_retirement_inventory(
            &mut self,
            reservation: carrick_hal::FrameInventoryReservation,
        ) -> Result<(), TrapError> {
            if self.retirement_inventory.replace(reservation).is_some() {
                return Err(TrapError::Hypervisor(
                    "test engine received overlapping retirement inventory".to_owned(),
                ));
            }
            Ok(())
        }

        fn snapshot_guest_state_for_publication(
            &mut self,
        ) -> Result<carrick_hal::threaded::GuestCpuState, TrapError> {
            if self.exec_support {
                return self.snapshot_cpu.clone().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "exec-capable crash test engine lost snapshot template".to_owned(),
                    )
                });
            }
            Err(TrapError::Hypervisor(
                "crash timeout test does not snapshot executor state".to_owned(),
            ))
        }

        fn aarch64_core_registers(
            &self,
        ) -> Result<Option<carrick_hal::Aarch64CoreRegisters>, TrapError> {
            Ok(Some(carrick_hal::Aarch64CoreRegisters::default()))
        }

        fn kick_handle(&self) -> Self::KickHandle {
            CrashCaptureTestKick
        }

        fn wait_for_vcpu_slot() {}

        fn build_sibling_spec(
            &self,
            _entry: carrick_hal::GuestEntryRegs,
        ) -> Result<Self::SiblingSpec, TrapError> {
            Ok(())
        }

        fn materialize_sibling(_spec: Self::SiblingSpec) -> Result<Self, TrapError> {
            Ok(Self::default())
        }

        fn program_counter(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn set_guest_sp_el0(&self, _sp: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
            Ok(())
        }

        fn fresh_fork_kicker(&self) -> Arc<dyn VcpuRegistry> {
            Arc::new(carrick_hal::GenericVcpuRegistry::new())
        }
    }

    pub(super) fn suffix_failure_test_job(
        kernel: &Kernel,
        state: ThreadRuntimeState<CrashCaptureTestEngine>,
        phase: HvpatchProductionPhase,
        external_exec: Option<crate::kernel::control::ExecWork>,
    ) -> ProductionHvpatchLoopJob<CrashCaptureTestEngine> {
        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        ProductionHvpatchLoopJob {
            kernel: Arc::clone(kernel),
            state,
            phase,
            registration_wait: None,
            terminal_settlement: HvpatchExternalTerminalSettlement::new(result, completion.clone()),
            terminal_result: None,
            completion,
            traps: 0,
            budget_floor: 0,
            seen_signal_progress: signal_progress_count(),
            last_signal_progress: Instant::now(),
            terminal_runtime: PersistentTerminalRuntimeState::Resident,
            pending_terminal_retirement: None,
            pending_terminal_inventory: None,
            external_exec,
        }
    }

    macro_rules! test_carrier_graph_with_dispatcher {
        ($pid:expr, $dispatcher:expr) => {{
            let (process, root) = crate::hvpatch::process_context_for_tests($pid);
            $dispatcher.bind_hvpatch_process(process.clone());
            let kernel = Arc::new(KernelState::new(
                $dispatcher,
                Arc::new(EndpointTestSignalPump),
                Arc::new(EndpointTestSignalArrival),
                Some(process.clone()),
                None,
                None,
            ));
            let runtime = Arc::clone(kernel.hvpatch_runtime.as_ref().unwrap());
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 500);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding = executor::tests::hvpatch_test_binding(&root, &root_state, 600);
            let dormant = runtime
                .persistent_bindings()
                .prepare_submission(
                    &scheduler,
                    executor::HvpatchSubmissionShape::Root,
                    None,
                    Arc::clone(root.thread()),
                    root_generation,
                    Arc::clone(&root_binding),
                )
                .unwrap();
            executor::tests::activate_hvpatch_test_submission(
                dormant,
                &scheduler,
                &root,
                &root_state,
                root_generation,
                root_binding.as_ref(),
            );
            (runtime, scheduler, kernel, root, process, root_generation)
        }};
    }
    pub(crate) use test_carrier_graph_with_dispatcher;

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
    }

    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;

    #[test]
    fn tracked_live_protections_upgrade_maperr_but_unmapped_does_not() {
        let address = 0x9000_0000;
        let memory = ProtectionOnlyMemory {
            protections: carrick_guest_mem::protections::MemoryProtections::default(),
        };
        memory.protections.set_no_write(address, 0x4000, true);

        assert_eq!(
            upgrade_protection_si_code(&memory, SIGSEGV, SEGV_MAPERR, address),
            SEGV_ACCERR,
            "a tracked read-only VMA exists, so Linux reports permission denial"
        );
        assert_eq!(
            upgrade_protection_si_code(&memory, SIGSEGV, SEGV_MAPERR, address + 0x4000),
            SEGV_MAPERR,
            "an address outside tracked mappings remains an unmapped fault"
        );

        memory.protections.set_no_write(address, 0x4000, false);
        memory.protections.set_no_access(address, 0x4000, true);
        assert_eq!(
            upgrade_protection_si_code(&memory, SIGSEGV, SEGV_MAPERR, address),
            SEGV_ACCERR,
            "a live PROT_NONE VMA is also a Linux permission fault"
        );

        memory.protections.set_unmapped(address, 0x4000, true);
        assert_eq!(
            upgrade_protection_si_code(&memory, SIGSEGV, SEGV_MAPERR, address),
            SEGV_MAPERR,
            "munmap removes the VMA, so a later translation fault stays MAPERR"
        );
    }

    #[test]
    fn lower_el0_fault_covers_both_debug_and_abort_arms() {
        // The Stage-0 lowering MUST be identity w.r.t. the historical
        // EL0Fault→deliver_fault_signal resolution: debug classes win first and
        // carry `elr` as si_addr; abort classes carry `far` as si_addr.
        let elr = 0xDEAD_BEEF;
        let far = 0xCAFE_F00D;

        // BRK (debug) → SIGTRAP/TRAP_BRKPT, si_addr = elr (the faulting PC).
        assert_eq!(
            lower_el0_fault(esr(0x3c), elr, far),
            Some((SIGTRAP, TRAP_BRKPT, elr)),
            "BRK must lower to SIGTRAP carrying the PC — regressing this breaks ptrace/Go debug-call"
        );
        // Single-step (debug) → SIGTRAP/TRAP_TRACE, si_addr = elr.
        assert_eq!(
            lower_el0_fault(esr(0x32), elr, far),
            Some((SIGTRAP, TRAP_TRACE, elr))
        );

        // Data abort (fault) → SIGSEGV/SEGV_MAPERR, si_addr = far (the bad VA).
        assert_eq!(
            lower_el0_fault(esr(0x24), elr, far),
            Some((SIGSEGV, SEGV_MAPERR, far))
        );
        // Instruction abort (fault) → SIGSEGV, si_addr = far.
        assert_eq!(
            lower_el0_fault(esr(0x20), elr, far),
            Some((SIGSEGV, SEGV_MAPERR, far))
        );
        // Alignment fault (DFSC=0x21 under a data abort) → SIGBUS/BUS_ADRALN.
        assert_eq!(
            lower_el0_fault(esr(0x24) | 0x21, elr, far),
            Some((SIGBUS, BUS_ADRALN, far))
        );

        // Unclassified → None (caller terminates by SIGSEGV).
        assert_eq!(lower_el0_fault(esr(0x00), elr, far), None);
    }
}
