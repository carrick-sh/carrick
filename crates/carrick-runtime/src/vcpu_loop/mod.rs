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
use crate::dispatch::{
    CurrentMmMemory, DispatchError, DispatchOutcome, PreparedDispatch, PreparedSyscall,
    SyscallCompletionToken, SyscallDispatcher, SyscallRequest,
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
    PendingExecTerminal, PendingExecTerminalError, ProductionHvpatchPollError,
    SyscallCompletionOwnership,
};
pub(crate) mod quiesce;
mod signal;
mod threads;
#[cfg(test)]
pub(crate) use threads::finish_persistent_process_handles;
pub(crate) use threads::{
    PersistentProcessMemberPublication, VcpuThreadHandle, VcpuThreadRegistry,
    enroll_persistent_process_member, publish_unexpected_executor_failure_retirement,
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
    ContainerJobReservation, HvpatchRuntimeDirectory, HvpatchTaskWaker,
    PHYSICAL_JOB_RETIREMENT_TIMEOUT, PreparedPersistentServices, ProcessPhysicalRetirement,
    shared_futex_wake, trace_shared_futex_requeue, wait_for_physical_job_retirement,
};

pub(crate) mod terminal;
pub(crate) use terminal::{
    CloneAdmissionChangeSubscription, CloneAdmissionGate, CloneAdmissionPermit, CloneEnrollment,
    ExecCloneAdmission, ExecTerminalHandoff, FatalSignalAuthority, FatalSignalRecord,
    ForkCloneAdmission, ProcessExitClaim, ProcessExitClaimReceipt, VcpuLoopOutcome,
    core_note_resume_pair, fatal_for_terminal_owner, try_claim_persistent_process_exit_with,
};

pub(crate) mod outcome;
pub(crate) use outcome::{
    HvpatchExternalTerminalSettlement, HvpatchLoopResult, HvpatchLoopSuspension, KernelAbortRecord,
    LIVENESS_CONFIRM, LIVENESS_POLL, ProcessGraphLiveness, assemble_run_result,
};
#[cfg(test)]
pub(crate) use outcome::{
    HvpatchLoopPoll, HvpatchTerminalSettlementRole, terminal_result_for_publication,
};

pub(crate) mod crash;
#[cfg(test)]
use crash::CrashLeaseDrainBudget;
pub(crate) mod lifecycle;
pub(crate) use lifecycle::ProcessChildBootstrap;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) use lifecycle::install_hvpatch_process_failpoint;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use lifecycle::{
    CloneRetrySubscription, HvpatchCloneBackendOps, HvpatchCloneFailpoint,
    HvpatchCloneThreadRequest, HvpatchProcessBackendOps, HvpatchProcessInventoryPreparation,
    PersistentHvpatchCloneAttempt,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use lifecycle::{
    HvpatchProcessFailpoint, ProductionHvpatchCloneBackendOps, ProductionHvpatchProcessBackendOps,
    bootstrap_hvpatch_process_child, check_hvpatch_clone_failpoint,
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
        let receipt = try_claim_persistent_process_exit_with(&self.clone_admission, owner)?;
        if receipt.claim == ProcessExitClaim::Owner {
            self.begin_process_exit();
        }
        Ok(receipt)
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

/// Exact execution authority is task-local in the compatibility loop and is
/// lent by the Task 4 worker in the persistent loop. Both modes expose the
/// same narrow slot API so exec/continuation helpers cannot accidentally grow
/// a second scheduler-specific implementation.
enum ExecutionLeaseCell {
    Owned(Mutex<Option<crate::kernel::objects::ThreadExecutionLease>>),
    Injected(Arc<InjectedExecutionLeaseSlot>),
}

struct InjectedExecutionLeaseSlot {
    slot: std::sync::atomic::AtomicPtr<Option<crate::kernel::objects::ThreadExecutionLease>>,
}

impl InjectedExecutionLeaseSlot {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: std::sync::atomic::AtomicPtr::new(std::ptr::null_mut()),
        })
    }

    fn install(
        self: &Arc<Self>,
        slot: *mut Option<crate::kernel::objects::ThreadExecutionLease>,
    ) -> InjectedExecutionLeasePublication<'_> {
        if self
            .slot
            .compare_exchange(
                std::ptr::null_mut(),
                slot,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_err()
        {
            carrick_fatal!(
                "vcpu_loop::runtime_context",
                "Duplicate installation of thread-local VcpuRuntimeContext"
            );
        }
        InjectedExecutionLeasePublication { owner: self }
    }
}

struct InjectedExecutionLeasePublication<'a> {
    owner: &'a Arc<InjectedExecutionLeaseSlot>,
}

impl Drop for InjectedExecutionLeasePublication<'_> {
    fn drop(&mut self) {
        let previous = self
            .owner
            .slot
            .swap(std::ptr::null_mut(), std::sync::atomic::Ordering::AcqRel);
        if previous.is_null() {
            carrick_fatal!(
                "vcpu_loop::runtime_context",
                "Thread-local VcpuRuntimeContext missing on teardown"
            );
        }
    }
}

enum ExecutionLeaseGuard<'a> {
    Owned(parking_lot::MutexGuard<'a, Option<crate::kernel::objects::ThreadExecutionLease>>),
    Injected(&'a mut Option<crate::kernel::objects::ThreadExecutionLease>),
}

impl std::ops::Deref for ExecutionLeaseGuard<'_> {
    type Target = Option<crate::kernel::objects::ThreadExecutionLease>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(slot) => slot,
            Self::Injected(slot) => slot,
        }
    }
}

impl std::ops::DerefMut for ExecutionLeaseGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(slot) => slot,
            Self::Injected(slot) => slot,
        }
    }
}

impl ExecutionLeaseCell {
    fn owned() -> Self {
        Self::Owned(Mutex::new(None))
    }

    fn injected() -> (Self, Arc<InjectedExecutionLeaseSlot>) {
        let slot = InjectedExecutionLeaseSlot::new();
        (Self::Injected(Arc::clone(&slot)), slot)
    }

    fn lock(&self) -> ExecutionLeaseGuard<'_> {
        match self {
            Self::Owned(slot) => ExecutionLeaseGuard::Owned(slot.lock()),
            Self::Injected(slot) => {
                let pointer = slot.slot.load(std::sync::atomic::Ordering::Acquire);
                if pointer.is_null() {
                    carrick_fatal!(
                        "vcpu_loop::runtime_context",
                        "Thread-local VcpuRuntimeContext missing when entering direct dispatch lock"
                    );
                }
                // SAFETY: the persistent worker installs the unique mutable
                // lease slot for the duration of this poll and clears it before
                // returning the physical engine. A logical job is polled by at
                // most one worker at a time under HvpatchTaskQuantum's mutex.
                ExecutionLeaseGuard::Injected(unsafe { &mut *pointer })
            }
        }
    }
}

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
    /// `Some` only for a process multiplexed in the shared HvPatch VM.
    process_fork_barrier: Option<Arc<crate::fork_quiesce::QuiesceBarrier>>,
    crash_capture: Option<Arc<crate::kernel::CrashCaptureAuthority>>,
    #[cfg(test)]
    crash_lease_drain_budget: CrashLeaseDrainBudget,
    kernel_thread: Option<crate::kernel::ThreadRef>,
    guest_execution: Option<crate::dispatch::MmExecutorParticipation>,
    /// Exact Task 1 execution authority while this logical thread is running.
    /// Empty only before its first reclaim snapshot and while blocked.
    execution_lease: ExecutionLeaseCell,
    pending_exec_replacement: Option<executor::PendingExecReplacement>,
    /// Authoritative Linux TGID for a task multiplexed by HVPatch. `None` on
    /// the one-host-process-per-task native/VMM lanes.
    hvpatch_task_pid: Option<i32>,
    /// Guest-visible identity allocated in the kernel namespace. It is never
    /// inferred from the backend-local thread registry key.
    linux_tid: crate::kernel::LinuxTid,
    /// Image generation that owns fatal-signal publication for this loop. It
    /// changes only after a successful exec has crossed every fallible edge.
    fatal_image_generation: u64,
    /// Exact authority captured at the current syscall boundary. Lifecycle
    /// outcomes consume it rather than recapturing a newer registry generation.
    service_kernel_context: Option<crate::kernel::KernelContext>,
    #[cfg(test)]
    exec_terminal_context_failpoint: Option<exec::ExecTerminalContextFailpoint>,
    #[cfg(test)]
    committed_exec_context_for_test: Option<crate::kernel::KernelContext>,
    pub(super) syscall_completion: SyscallCompletionOwnership,
    continuation_restart: Option<continuation::RestartDecision>,
    /// Consecutive identical (FAR, ESR) COW faults "successfully" resolved.
    /// A resolution that does not change the faulting translation refaults
    /// forever inside one quantum, starving this executor's command channel
    /// and wedging every peer waiting in `consume_invalidation_acks` — seen
    /// live on `futexforkrequeue` (core: ffr-livelock-76407). Fail closed
    /// with a named clause instead of spinning.
    cow_refault_watch: Option<(u64, u64, Option<u64>, u32)>,
    reserved_signal: Option<continuation::ReservedSignal>,
    this_tid: ThreadId,
    threads: VcpuThreadRegistry,
    /// The object-safe vCPU registry (the kicker). The shared loop never names
    /// the concrete `VcpuKicker`.
    kicker: Arc<dyn VcpuRegistry>,
    /// This guest thread's ONE "currently in `next_syscall`" flag, created when
    /// the guest thread is born and held for its whole life, so a
    /// page-table-edit coordinator can tell whether this thread is walking
    /// guest memory. Set true around `next_syscall`, false otherwise. Every
    /// (re-)registration of this thread hands the kicker THIS flag — see
    /// [`carrick_hal::InGuestFlag`], whose whole point is that the two halves
    /// of a registration cannot drift apart.
    in_guest: carrick_hal::InGuestFlag,
    max_traps: usize,
    trace: bool,
    /// Set on a vfork (`CLONE_VM|CLONE_VFORK`) CHILD: the write end of the pipe
    /// whose read end the suspended PARENT blocks on. `None` on the parent and on
    /// ordinary (non-vfork) children.
    vfork_release_fd: Option<i32>,
    /// The one-shot runtime-withdrawal memo for
    /// `handle_persistent_thread_exit` Busy retries (see
    /// `PersistentThreadExitDisposition`).
    thread_exit_withdrawn: bool,
    /// Live reservation-change subscription while a thread exit is parked
    /// on `PersistentThreadExitDisposition::Busy`; dropped when the retry
    /// runs.
    thread_exit_retry_subscription: Option<crate::kernel::ReservationChangeSubscription>,
    /// The engine is passed as `&mut E` to each method, so no field owns it; this
    /// pins the generic parameter to the struct.
    _engine: std::marker::PhantomData<fn() -> E>,
}

enum HvpatchBlockInput {
    Dispatch(DispatchOutcome),
    Vfork {
        child: crate::kernel::TaskKey,
        wait: crate::kernel::VforkParentWait,
        activation: executor::PreparedVforkChildActivation,
    },
}

enum HvpatchContinuationInput {
    Dispatch(DispatchOutcome),
    Vfork {
        child: crate::kernel::TaskKey,
        wait: crate::kernel::VforkParentWait,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DeferredResumeBlocked {
    frame: carrick_hal::RawSyscall,
    vfork_child_pid: Option<i32>,
    original_blocked_reason: Option<crate::kernel::objects::BlockedReason>,
}

impl DeferredResumeBlocked {
    fn capture(
        phase: &HvpatchProductionPhase,
        original_blocked_reason: Option<crate::kernel::objects::BlockedReason>,
    ) -> Option<Self> {
        match phase {
            HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid,
            } => Some(Self {
                frame: *frame,
                vfork_child_pid: *vfork_child_pid,
                original_blocked_reason,
            }),
            _ => None,
        }
    }

    fn restore(self, phase: &mut HvpatchProductionPhase) {
        *phase = HvpatchProductionPhase::ResumeBlocked {
            frame: self.frame,
            vfork_child_pid: self.vfork_child_pid,
        };
    }
}

enum HvpatchProductionPhase {
    Resident,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    BootstrapProcessChild(ProcessChildBootstrap),
    BootstrapThreadChild,
    ResumeForkQuiesce {
        _subscription: carrick_thread::fork_quiesce::QuiesceSubscription,
    },
    ResumeJobControlStop {
        _subscription: crate::kernel::objects::TaskWakeSubscription,
    },
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    RetryProcessFork {
        frame: Option<carrick_hal::RawSyscall>,
        request: quiesce::ForkRequest,
        coordinator: Option<quiesce::ProcessForkCoordinator>,
        external_exec: Option<crate::kernel::control::ExecWork>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
        _subscription: quiesce::ProcessForkRetrySubscription,
    },
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    RetryCloneThread {
        frame: carrick_hal::RawSyscall,
        request: HvpatchCloneThreadRequest,
        prepared: Option<crate::kernel::PreparedThreadClone>,
        _subscription: CloneRetrySubscription,
    },
    /// A guest thread exit found the kernel task reservation held
    /// (`ProcessThreadExit::Busy`). The job parked with a
    /// reservation-change subscription (stored on the runtime state) and
    /// re-runs the exit with this code on resume. The executor stays free
    /// to service peer commands in between — blocking it in the exit wait
    /// deadlocked against an exec survivor's ASID-ack collection.
    RetryThreadExit {
        code: i32,
    },
    ResumeBlocked {
        frame: carrick_hal::RawSyscall,
        vfork_child_pid: Option<i32>,
    },
    ExecSiblingDrain {
        context: crate::kernel::KernelContext,
        owner: exec::PreparedExecveDrain,
    },
    TerminalProcessDrain {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        drain: continuation::ProcessDrain,
    },
    TerminalClaimRetry {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        _subscription: Option<CloneAdmissionChangeSubscription>,
    },
    TerminalRetireRetry {
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        _subscription: TerminalRetireSubscription,
    },
    Complete,
}

/// What a parked process terminal waits on before retrying its retirement.
enum TerminalRetireSubscription {
    /// The carrier-wide topology lock (another fork/exec/exit mid-edit).
    Topology {
        _subscription: carrick_thread::fork_quiesce::TopologyReleaseSubscription,
    },
    /// A sibling's exec reservation owns this process's MM generation; the
    /// exit's owner-set edit is admitted once it settles.
    ExecSettlement {
        _subscription: crate::hvpatch::ExecSettlementSubscription,
    },
}

#[cfg(test)]
fn enter_guest_executor_then_register<F>(
    census: &Arc<crate::kernel::GuestExecutorCensus>,
    thread: Option<crate::kernel::ThreadRef>,
    register: F,
) -> Result<
    (
        crate::kernel::GuestExecutorParticipation,
        carrick_hal::VcpuRegistrationEnrollment,
    ),
    crate::kernel::GuestExecutorCensusError,
>
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = census.enter(thread)?;
    let enrollment = register();
    Ok((participation, enrollment))
}

fn enter_mm_executor_then_register<F>(
    dispatcher: &crate::dispatch::SyscallDispatcher,
    thread: Option<crate::kernel::ThreadRef>,
    registry: Arc<dyn carrick_hal::VcpuRegistry>,
    tid: ThreadId,
    register: F,
) -> Result<
    (
        crate::dispatch::MmExecutorParticipation,
        carrick_hal::VcpuRegistrationEnrollment,
    ),
    crate::kernel::GuestExecutorCensusError,
>
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = dispatcher.enter_mm_executor_for_thread(thread, registry, tid)?;
    let enrollment = register();
    Ok((participation, enrollment))
}

fn registration_wake_uses_control(
    phase: &HvpatchProductionPhase,
    pending_control_quantum: bool,
) -> bool {
    if pending_control_quantum {
        return true;
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        matches!(
            phase,
            HvpatchProductionPhase::RetryProcessFork {
                external_exec: Some(_),
                ..
            }
        )
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = phase;
        false
    }
}

fn registration_wake_callback(
    scheduler: Arc<crate::kernel::Scheduler>,
    thread: crate::kernel::ThreadKey,
    use_control: bool,
) -> Arc<dyn Fn() + Send + Sync + 'static> {
    Arc::new(move || {
        let _ = if use_control {
            scheduler.wake_control(thread)
        } else {
            scheduler.wake(thread)
        };
    })
}

impl HvpatchProductionPhase {
    fn is_terminal_transition(&self) -> bool {
        matches!(
            self,
            Self::ExecSiblingDrain { .. }
                | Self::TerminalProcessDrain { .. }
                | Self::TerminalClaimRetry { .. }
                | Self::TerminalRetireRetry { .. }
        )
    }

    /// Stable ordinal for the `hvpatch-thread-terminal` probe's `detail`
    /// (reason `ExternallySettledWithoutResult`): which phase a job was
    /// parked in when the executor settled its terminal for it.
    const fn probe_ordinal(&self) -> i32 {
        match self {
            Self::Resident => 0,
            Self::BootstrapProcessChild { .. } => 1,
            Self::ResumeForkQuiesce { .. } => 2,
            Self::ResumeJobControlStop { .. } => 3,
            Self::RetryProcessFork { .. } => 4,
            Self::RetryCloneThread { .. } => 5,
            Self::RetryThreadExit { .. } => 6,
            Self::ResumeBlocked { .. } => 7,
            Self::ExecSiblingDrain { .. } => 8,
            Self::TerminalProcessDrain { .. } => 9,
            Self::TerminalClaimRetry { .. } => 10,
            Self::TerminalRetireRetry { .. } => 11,
            Self::Complete => 12,
            Self::BootstrapThreadChild => 13,
        }
    }
}

#[cfg(test)]
#[test]
fn bootstrap_thread_child_probe_ordinal_is_append_only() {
    assert_eq!(
        HvpatchProductionPhase::BootstrapThreadChild.probe_ordinal(),
        13
    );
}

enum PersistentTerminal {
    Outcome {
        outcome: VcpuLoopOutcome,
        prepared_core: Option<Box<PreparedCorePublication>>,
    },
    Error(RuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentTerminalRuntimeState {
    Resident,
    Withdrawn,
}

impl PersistentTerminal {
    fn from_outcome(outcome: VcpuLoopOutcome) -> Self {
        Self::Outcome {
            outcome,
            prepared_core: None,
        }
    }

    fn into_result(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        match self {
            Self::Outcome { outcome, .. } => Ok(outcome),
            Self::Error(error) => Err(error),
        }
    }
}

struct ProductionHvpatchLoopJob<E: ThreadedEngine> {
    kernel: Kernel,
    state: ThreadRuntimeState<E>,
    phase: HvpatchProductionPhase,
    registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>,
    terminal_settlement: HvpatchExternalTerminalSettlement,
    terminal_result: Option<Result<VcpuLoopOutcome, RuntimeError>>,
    completion: continuation::LogicalJobCompletion,
    traps: usize,
    budget_floor: usize,
    seen_signal_progress: u64,
    last_signal_progress: Instant,
    terminal_runtime: PersistentTerminalRuntimeState,
    pending_terminal_retirement: Option<crate::hvpatch::PendingAddressSpaceRetirement>,
    pending_terminal_inventory: Option<(Arc<crate::kernel::Kernel>, crate::kernel::MmId)>,
    external_exec: Option<crate::kernel::control::ExecWork>,
}

trait ProductionHvpatchLoopPoll: Send {
    fn pt_quiesce(&self) -> Arc<crate::fork_quiesce::PtQuiesce>;

    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit;

    fn after_terminal_settlement(&mut self);

    /// The scheduler settled this thread against a target the kernel graph
    /// says is TERMINAL: no successor exists, so nothing will run this job
    /// again and no other publisher is left for it.
    fn after_reaped_settlement(&mut self);

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement;

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement>;

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError>;

    /// The same publication, returning the authenticated receipt a published
    /// `HvpatchTaskMmAuthority` needs to leave its `Active` phase.
    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError>;
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    fn external_exec_failure(&mut self, engine: &mut E, code: i32) -> executor::ExecutorExit {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during external exec failure transition"))
            .retain_exact();
        let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
            &self.kernel,
            code,
            None,
            self.traps,
            false,
        )));
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::from_outcome(outcome),
            context,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn start_external_exec(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let request = self
            .external_exec
            .as_mut()
            .ok_or_else(|| {
                RuntimeError::Configuration("external exec work disappeared".to_owned())
            })?
            .take_request()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "external exec lost exact child Kernel context".to_owned(),
                )
            })?
            .retain_exact();
        let user = request.user.map(|user| {
            let supplementary = user
                .supplementary_gids
                .into_iter()
                .map(carrick_abi::NsGid::new)
                .collect();
            (
                carrick_abi::NsUid::new(user.uid),
                carrick_abi::NsGid::new(user.gid),
                supplementary,
            )
        });
        let context = match self.kernel.dispatcher.configure_logical_exec_context(
            &context,
            request.workdir.as_deref(),
            user,
        ) {
            Ok(context) => context,
            Err(_) => {
                self.state.finish_internal_control_exec()?;
                return Ok(self.external_exec_failure(engine, 126));
            }
        };
        let kernel = Arc::clone(&self.kernel);
        let setup = kernel.dispatcher.with_kernel_resources(&context, || {
            let requested_path = request.argv[0].clone();
            let argv = request.argv.into_iter().map(String::into_bytes).collect();
            let mut env = self.kernel.dispatcher.current_exec_env();
            for variable in request.env {
                let prefix = format!("{}=", variable.key).into_bytes();
                env.retain(|entry| !entry.starts_with(&prefix));
                let mut entry = prefix;
                entry.extend_from_slice(variable.value.as_bytes());
                env.push(entry);
            }
            let path = if requested_path.contains('/') {
                Ok(requested_path)
            } else {
                let search = env
                    .iter()
                    .rev()
                    .find_map(|entry| entry.strip_prefix(b"PATH="))
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
                self.kernel
                    .dispatcher
                    .resolve_execvp_path(&requested_path, search)
            };
            path.map(|path| (path, argv, env))
        });
        let (path, argv, env) = match setup {
            Ok(setup) => setup,
            Err(errno) => {
                let exit_code = if errno == crate::linux_abi::LINUX_ENOENT {
                    127
                } else {
                    126
                };
                self.state.finish_internal_control_exec()?;
                return Ok(self.external_exec_failure(engine, exit_code));
            }
        };
        match self.state.prepare_execve(
            &self.kernel,
            &context,
            engine,
            path,
            argv,
            env,
            ExecCompletionOrigin::InternalControl,
        )? {
            exec::ExecvePreparation::Complete(Some(outcome)) => {
                self.state.finish_internal_control_exec()?;
                Ok(self.enter_terminal_with_outcome(engine, outcome))
            }
            exec::ExecvePreparation::Complete(None) => Ok(self.external_exec_failure(engine, 126)),
            exec::ExecvePreparation::TerminalFailure(failure) => {
                Err(ProductionHvpatchPollError::from_exec_failure(failure))
            }
            exec::ExecvePreparation::Prepared(prepared) => {
                let prepared = *prepared;
                let owner = match self.state.begin_prepared_execve_drain(
                    &self.kernel,
                    self.completion.id(),
                    prepared,
                ) {
                    Ok(owner) => owner,
                    Err(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                };
                if owner.is_ready() {
                    let finished = match self.state.finish_prepared_execve_drain(
                        &self.kernel,
                        engine,
                        &self.completion,
                        owner,
                    ) {
                        Ok(finished) => finished,
                        Err(failure) => {
                            return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                        }
                    };
                    self.finish_exec_suffix(engine, control, finished)
                } else {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                    Ok(self.suspend(
                        HvpatchLoopSuspension::ExecSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ))
                }
            }
        }
    }

    fn take_terminal_inventory_authority(
        &mut self,
    ) -> Result<(Arc<crate::kernel::Kernel>, crate::kernel::MmId), TrapError> {
        self.pending_terminal_inventory.take().ok_or_else(|| {
            TrapError::Hypervisor(
                "detached terminal cleanup lost its exact Kernel/MM authority".to_owned(),
            )
        })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn control_quantum(
        &self,
    ) -> Result<Option<crate::kernel::objects::SchedulerControlQuantum>, RuntimeError> {
        let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec lost exact root Kernel context".to_owned(),
            )
        })?;
        let thread = context.thread();
        thread
            .scheduler_control_quantum(thread.key())
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "inspect carrier logical exec control quantum: {error}"
                ))
            })
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn finish_control_quantum(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "carrier logical exec lost exact root Kernel context".to_owned(),
            )
        })?;
        let thread = context.thread();
        let quantum = thread
            .finish_scheduler_control_quantum(thread.key())
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "finish carrier logical exec control quantum: {error}"
                ))
            })?;
        // Clear-then-recheck closes coalesced admission races. Every request
        // queued before the clear remains visible here. A request queued after
        // this check observes no marker, so its waker creates a fresh control
        // edge. If the next request is already visible, restore the displaced
        // continuation token and service it in this same owner quantum.
        if let Some(work) = self.kernel.try_take_control_exec() {
            thread
                .restore_scheduler_control_quantum(thread.key(), quantum)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "continue carrier logical exec control quantum: {error}"
                    ))
                })?;
            return self.begin_control_exec_fork(engine, control, work, deferred_resume_blocked);
        }
        let Some(deferred) = deferred_resume_blocked else {
            if quantum.blocked_reason.is_some() {
                return Err(RuntimeError::Configuration(
                    "carrier logical exec lost its deferred blocked continuation".to_owned(),
                ));
            }
            return Ok(executor::ExecutorExit::Syscall);
        };
        if quantum.blocked_reason != deferred.original_blocked_reason {
            return Err(RuntimeError::Configuration(
                "carrier logical exec changed the deferred blocked reason".to_owned(),
            ));
        }
        let continuation_ready = control
            .execution_lease_mut()
            .map_err(RuntimeError::Trap)?
            .blocked_continuation()
            .is_some_and(|continuation| continuation.ready_event().is_ok());
        let original_blocked_reason = deferred.original_blocked_reason;
        deferred.restore(&mut self.phase);
        match (original_blocked_reason, continuation_ready) {
            // A real producer won while the control quantum was runnable. Let
            // ResumeBlocked consume that exact event in this same lease.
            (_, true) | (None, _) => Ok(executor::ExecutorExit::Syscall),
            (Some(reason), false) => Ok(self.suspend(
                HvpatchLoopSuspension::BlockedContinuation,
                executor::ExecutorExit::Blocked(reason),
            )),
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn begin_control_exec_fork(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        work: crate::kernel::control::ExecWork,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "carrier logical exec lost exact root Kernel context".to_owned(),
                )
            })?
            .retain_exact();
        let prepared = self.state.prepare_in_process_fork(
            &self.kernel,
            &context,
            engine,
            control,
            &mut ProductionHvpatchProcessBackendOps,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: 0,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: Some(work),
            },
        )?;
        self.complete_persistent_process_fork(
            engine,
            control,
            None,
            deferred_resume_blocked,
            prepared,
        )
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn complete_persistent_process_fork(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: Option<carrick_hal::RawSyscall>,
        deferred_resume_blocked: Option<DeferredResumeBlocked>,
        prepared: quiesce::PreparedInProcessFork,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        match prepared {
            quiesce::PreparedInProcessFork::Complete(Some(value)) => {
                if frame.is_some() {
                    self.state
                        .complete_returned(engine, &self.kernel.reporter, value)?;
                }
                if frame.is_none() {
                    return self.finish_control_quantum(engine, control, deferred_resume_blocked);
                }
                Ok(executor::ExecutorExit::Syscall)
            }
            quiesce::PreparedInProcessFork::Complete(None) => {
                if deferred_resume_blocked.is_some() {
                    return Err(RuntimeError::Configuration(
                        "external logical exec retired the blocked init process".to_owned(),
                    ));
                }
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during persistent fork completion"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    0,
                    None,
                    self.traps,
                    false,
                )));
                Ok(self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                ))
            }
            quiesce::PreparedInProcessFork::SuspendVfork(suspension) => {
                let frame = frame.ok_or_else(|| {
                    RuntimeError::Configuration(
                        "external logical exec unexpectedly requested vfork suspension".to_owned(),
                    )
                })?;
                let request = suspension.request;
                let child_pid = suspension.child_pid;
                let exit = self.state.persistent_block_exit(
                    &self.kernel,
                    control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                    request,
                    HvpatchBlockInput::Vfork {
                        child: suspension.child,
                        wait: suspension.wait,
                        activation: suspension.activation,
                    },
                )?;
                self.phase = HvpatchProductionPhase::ResumeBlocked {
                    frame,
                    vfork_child_pid: Some(child_pid),
                };
                Ok(self.suspend(HvpatchLoopSuspension::VforkParent, exit))
            }
            quiesce::PreparedInProcessFork::Retry {
                request,
                coordinator,
                external_exec,
                _subscription,
            } => {
                self.phase = HvpatchProductionPhase::RetryProcessFork {
                    frame,
                    request,
                    coordinator,
                    external_exec,
                    deferred_resume_blocked,
                    _subscription,
                };
                Ok(self.suspend(
                    HvpatchLoopSuspension::BlockedContinuation,
                    executor::ExecutorExit::Blocked(
                        crate::kernel::objects::BlockedReason::HostWait,
                    ),
                ))
            }
        }
    }

    fn finalize_persistent_process_terminal(
        &mut self,
        engine: &mut E,
        terminal_context: crate::kernel::KernelContext,
        terminal: PersistentTerminal,
    ) -> executor::ExecutorExit {
        let process = self.kernel.hvpatch_process.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::terminal_settlement",
                "Terminal process missing execution context during terminal finalization"
            )
        });
        let wake_scheduler = || {
            self.kernel
                .hvpatch_runtime
                .as_ref()
                .unwrap_or_else(|| carrick_fatal!("hvpatch::task_backend_lifecycle", "Missing HVPatch runtime reference when constructing the terminal-retire wake callback"))
                .continuation_services(terminal_context.kernel())
                .0
        };
        // Close the process's fds FIRST — before the owner-set hold and the
        // retirement topology lock — matching Linux `exit_files` preceding
        // `exit_notify`, and the fork path's lock order (subsystem
        // authorities, then topology). Closing takes per-description locks;
        // a sibling mid-`read(2)` holds one of those while its copy-in
        // faults a copy-on-write page, which needs the topology lock. Taking
        // the topology lock first and closing fds under it was an ABBA that
        // wedged `ltp-fork07` at its ninth child (`forkreadexitcow`).
        // Idempotent on a `TerminalRetireRetry` re-entry: the table
        // generation is already drained and its close events consumed.
        self.kernel
            .dispatcher
            .retire_hvpatch_process_fds(&terminal_context);
        // Retiring this process's MM edge is an owner-set edit on its
        // generation. A vfork sibling mid-exec has that generation reserved
        // and its owner set frozen; admit the edit against the reservation
        // here, where a refusal is a parkable wait, rather than at
        // `begin_address_space_retirement` after the kernel exit
        // publication, where it is only an abort. The hold itself is taken
        // before the topology lock and never held across a park.
        let owner_set_edit = loop {
            let settlement = process.mm_resources().exec_settlement_epoch();
            match process
                .mm_resources()
                .hold_owner_set_edit(terminal_context.task().key())
            {
                Ok(hold) => break Some(hold),
                Err(crate::hvpatch::MmResourcesError::UnknownTask(_)) => break None,
                Err(crate::hvpatch::MmResourcesError::ExecReservationConflict(conflict)) => {
                    let scheduler = wake_scheduler();
                    let thread = terminal_context.thread().key();
                    match process.mm_resources().subscribe_exec_settlement(
                        settlement,
                        Arc::new(move |_| {
                            let _ = scheduler.wake(thread);
                        }),
                    ) {
                        crate::hvpatch::ExecSettlementEnrollment::Ready => continue,
                        crate::hvpatch::ExecSettlementEnrollment::Subscribed(subscription) => {
                            tracing::debug!(
                                ?conflict,
                                "process exit deferred behind a sibling's exec reservation"
                            );
                            self.phase = HvpatchProductionPhase::TerminalRetireRetry {
                                terminal,
                                context: terminal_context,
                                _subscription: TerminalRetireSubscription::ExecSettlement {
                                    _subscription: subscription,
                                },
                            };
                            return self.suspend(
                                HvpatchLoopSuspension::TerminalSiblingDrain,
                                executor::ExecutorExit::Blocked(
                                    crate::kernel::objects::BlockedReason::HostWait,
                                ),
                            );
                        }
                    }
                }
                Err(failure) => {
                    tracing::error!(%failure, "admit persistent terminal MM retirement");
                    carrick_fatal!(
                        "hvpatch::mm_reservation",
                        "admit persistent terminal MM retirement failed: {failure}"
                    );
                }
            }
        };
        let topology = loop {
            let observed = crate::fork_quiesce::topology_release_generation();
            if let Some(topology) = crate::fork_quiesce::try_acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                process.pid(),
                self.state.this_tid.raw(),
            ) {
                break topology;
            }
            let scheduler = wake_scheduler();
            let thread = terminal_context.thread().key();
            match crate::fork_quiesce::subscribe_topology_release(
                observed,
                Arc::new(move |_| {
                    let _ = scheduler.wake(thread);
                }),
            ) {
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::TopologyReleaseEnrollment::Subscribed(
                    subscription,
                ) => {
                    // Release the admission while parked: the topology
                    // holder may be the exec'er this hold is excluding.
                    drop(owner_set_edit);
                    self.phase = HvpatchProductionPhase::TerminalRetireRetry {
                        terminal,
                        context: terminal_context,
                        _subscription: TerminalRetireSubscription::Topology {
                            _subscription: subscription,
                        },
                    };
                    return self.suspend(
                        HvpatchLoopSuspension::TerminalSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    );
                }
            }
        };
        let terminal_mm = terminal_context.shared().mm().id();
        let owns_final_mm = process
            .owns_final_mm_edge(terminal_context.task().key())
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "classify persistent terminal MM ownership");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "classify persistent terminal MM ownership failed: {failure}"
                );
            });
        if owns_final_mm {
            let capacity = carrick_hal::FrameEventCapacity::for_event_count(
                carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            )
            .unwrap_or_else(|_| {
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "Missing sibling execution context during terminal settlement"
                )
            });
            let reservation = terminal_context
                .kernel()
                .reserve_frame_inventory(0, 0, capacity)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "reserve persistent failure inventory");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "reserve persistent failure inventory failed: {failure}"
                    );
                });
            let transaction = reservation.transaction();
            engine
                .begin_retirement_inventory(reservation)
                .unwrap_or_else(|failure| {
                    terminal_context
                        .kernel()
                        .frame_inventory()
                        .abandon(transaction);
                    tracing::error!(%failure, "arm persistent failure inventory");
                    carrick_fatal!(
                        "kernel::container_scope",
                        "arm persistent failure inventory failed: {failure}"
                    );
                });
        }
        let prepared_core = match &terminal {
            PersistentTerminal::Outcome { prepared_core, .. } => prepared_core.as_deref(),
            _ => None,
        };
        let core_publication = match prepared_core {
            Some(prepared) => {
                match self.kernel.dispatcher.publish_core_atomic(
                    &prepared.snapshot,
                    prepared.generation,
                    prepared.payload.clone(),
                ) {
                    Ok(publ) => {
                        crate::probes::hvpatch_core_lifecycle(
                            4,
                            process.pid(),
                            prepared.fatal_tid,
                            publ.generation,
                            0,
                        );
                        tracing::debug!(
                            path = %publ.path,
                            bytes = publ.bytes,
                            "published guest core file"
                        );
                        Some(publ)
                    }
                    Err(error) => {
                        tracing::warn!(%error, "publish core atomic");
                        crate::probes::hvpatch_core_lifecycle(
                            6,
                            process.pid(),
                            prepared.fatal_tid,
                            prepared.generation,
                            1,
                        );
                        None
                    }
                }
            }
            None => None,
        };
        let core_dumped = core_publication.is_some();
        let (exit_code, wait_encoding, terminal_publication) = match &terminal {
            PersistentTerminal::Outcome {
                outcome: VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run),
                ..
            } => (
                run.exit_code,
                run.wait_status_encoding(core_dumped),
                Ok((**run).clone()),
            ),
            PersistentTerminal::Error(error) => {
                // The owner's failure would otherwise vanish: its sibling job
                // result is not the launch result, so this arm's Err(()) was
                // the only externally visible trace ("sibling-owned process
                // termination failed" with no cause). Name the cause here.
                //
                // The guest pid belongs in the line for the same reason: a
                // `cpython-importlib` wedge left one zombie at `127 << 8` and
                // an unattributable error on stderr, so which Linux process
                // carrick killed had to be inferred from the wait status.
                tracing::error!(
                    guest_pid = process.pid(),
                    %error,
                    "HVPatch terminal owner publishes failure"
                );
                (127, 127 << 8, Err(()))
            }
            PersistentTerminal::Outcome {
                outcome: VcpuLoopOutcome::ThreadDone,
                ..
            } => carrick_fatal!(
                "kernel::terminal_settlement",
                "Unexpected terminal settlement disposition encountered during process teardown"
            ),
        };
        let process_exit_event = process.record_process_exit_begin(exit_code, self.state.this_tid);
        let child = process.is_child();
        if let Some(work) = self.external_exec.take() {
            let out = self.kernel.dispatcher.stdout();
            let err = self.kernel.dispatcher.stderr();
            let terminating_signal = match &terminal {
                PersistentTerminal::Outcome {
                    outcome: VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run),
                    ..
                } => run.terminating_signal,
                PersistentTerminal::Error(_) => None,
                PersistentTerminal::Outcome {
                    outcome: VcpuLoopOutcome::ThreadDone,
                    ..
                } => None,
            };
            if let Err(error) = work.complete(crate::kernel::control::ExecResult {
                exit_code,
                terminating_signal,
                stdout: out,
                stderr: err,
                output_truncated: false,
            }) {
                tracing::error!(%error, "publish logical exec terminal result failed");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "publish logical exec terminal result failed: {error}"
                );
            }
        }
        let status = crate::kernel::LinuxWaitStatus::from_wait_encoding(wait_encoding);
        let orphan_adopter = self.kernel.dispatcher.hvpatch_orphan_adopter();
        let publish_result = process.publish_exit_status(status, orphan_adopter, |parent| {
            if child {
                self.kernel.notify_hvpatch_parent_exit(parent);
            } else if let Some(parent) = parent {
                tracing::error!(
                    parent = ?parent,
                    "child exit notification dropped: is_child() said no parent but the exit transaction named one"
                );
            }
        });
        if publish_result.is_ok() {
            if let Some(chain) = self.kernel.dispatcher.observers() {
                let p = crate::observe::ProcessInfo::new(&terminal_context);
                chain.on_process_exit(&p, crate::observe::ExitStatus::from_wait_status(status));
            }
        }
        if let Err(failure) = publish_result {
            if let Some(publ) = &core_publication {
                let _ = self.kernel.dispatcher.rollback_core_publication(publ);
            }
            if let Some(prepared) = prepared_core {
                crate::probes::hvpatch_core_lifecycle(
                    6,
                    process.pid(),
                    prepared.fatal_tid,
                    prepared.generation,
                    1,
                );
            }
            tracing::error!(%failure, "publish persistent failure Kernel exit");
            carrick_fatal!(
                "kernel::terminal_settlement",
                "publish persistent failure Kernel exit failed: {failure}"
            );
        }
        // The logical process is no longer runnable. Drop its carrier-wide
        // run-state publication now; run-state-only records are reclaimed here,
        // while namespace-owned records retain their zombie metadata until a
        // consuming wait reaps them.
        crate::run_state::clear_guest_process(process.pid());
        if let Some(prepared) = prepared_core {
            if core_dumped {
                crate::probes::hvpatch_core_lifecycle(
                    5,
                    process.pid(),
                    prepared.fatal_tid,
                    prepared.generation,
                    0,
                );
            }
        }
        self.kernel.unregister_hvpatch_runtime_endpoint();
        if owns_final_mm {
            if self
                .pending_terminal_inventory
                .replace((Arc::clone(terminal_context.kernel()), terminal_mm))
                .is_some()
            {
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "Failed to claim persistent process terminal owner role"
                );
            }
        }
        self.pending_terminal_retirement = Some(
            process
                .begin_address_space_retirement(exit_code, self.state.this_tid, process_exit_event)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "retire persistent failure MM/ASID");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "retire persistent failure MM/ASID failed: {failure}"
                    );
                }),
        );
        drop(owner_set_edit);
        drop(topology);
        self.kernel.publish_process_terminal(terminal_publication);
        self.finish(terminal.into_result())
    }

    /// Complete or park a guest thread's logical exit. `Busy` parks the
    /// job with a reservation-change subscription and schedules a retry
    /// through `HvpatchProductionPhase::RetryThreadExit` — the executor
    /// must NOT block in the exit wait, because the reservation holder (an
    /// exec survivor's terminal path) may be waiting for this exact
    /// executor's ASID acknowledgement (the execfromthread ABBA wedge).
    fn settle_persistent_thread_exit(
        &mut self,
        engine: &mut E,
        code: i32,
        context: crate::kernel::KernelContext,
        disposition: threads::PersistentThreadExitDisposition,
    ) -> executor::ExecutorExit {
        match disposition {
            threads::PersistentThreadExitDisposition::Done(VcpuLoopOutcome::ThreadDone) => {
                self.finish(Ok(VcpuLoopOutcome::ThreadDone))
            }
            threads::PersistentThreadExitDisposition::Done(
                outcome @ VcpuLoopOutcome::ProcessExit(_),
            ) => {
                self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            threads::PersistentThreadExitDisposition::Done(VcpuLoopOutcome::TrapLimit(_)) => {
                carrick_fatal!(
                    "kernel::thread_settlement",
                    "Unhandled thread exit disposition during persistent thread settlement"
                )
            }
            threads::PersistentThreadExitDisposition::Busy { observed_epoch } => {
                if self.kernel.process_exiting()
                    || thread_should_finish_for_exec_replacement(
                        &self.state.registry,
                        self.state.this_tid,
                    )
                {
                    // Ownership passed (see the drain gate): the process
                    // terminal or an exec replacement retires this thread's
                    // row; parking would strand past retirement.
                    self.state.trace_hvpatch_thread_terminal(
                        carrick_observability::probes::HvpatchThreadTerminalReason::ProcessTerminalLoser,
                        1,
                    );
                    return self.finish(Ok(VcpuLoopOutcome::ThreadDone));
                }
                self.park_thread_exit_retry(
                    &context,
                    observed_epoch,
                    HvpatchProductionPhase::RetryThreadExit { code },
                )
            }
        }
    }

    /// Park a Busy thread exit as a Blocked job subscribed to the kernel
    /// reservation-change epoch, retrying through `retry_phase`. The wake
    /// is the plain key-addressed `Scheduler::wake`: while the task is
    /// LIVE it rolls the submission authority correctly, and the drain
    /// invariant (the terminal owner's sibling drain waits for member jobs
    /// and wakes removed members BEFORE the task exit commits) guarantees
    /// the task is live whenever this park still needs a wake. A wake that
    /// races retirement anyway fails with UnknownThread and is discarded —
    /// never an abort (only a generation-observer bypass can abort, which
    /// this path does not do).
    fn park_thread_exit_retry(
        &mut self,
        context: &crate::kernel::KernelContext,
        observed_epoch: u64,
        retry_phase: HvpatchProductionPhase,
    ) -> executor::ExecutorExit {
        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during thread exit retry park"))
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();
        let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
            let woke = scheduler.wake(thread);
            tracing::info!(?thread, ?woke, "thread-exit retry wake");
        });
        // A `None` subscription means the epoch already moved and the
        // callback (wake) already fired — parking is still correct: the
        // pending wake resumes the retry immediately.
        self.state.thread_exit_retry_subscription = context
            .kernel()
            .subscribe_reservation_change(observed_epoch, callback);
        tracing::info!(
            thread = ?context.thread().key(),
            observed_epoch,
            "thread-exit retry parks"
        );
        self.phase = retry_phase;
        self.suspend(
            HvpatchLoopSuspension::TerminalSiblingDrain,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
        )
    }

    fn begin_persistent_process_terminal(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
    ) -> executor::ExecutorExit {
        let receipt = self
            .kernel
            .try_claim_persistent_process_exit(self.state.this_tid)
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "claim persistent process terminal owner");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "claim persistent process terminal owner failed: {failure}"
                );
            });
        self.begin_persistent_process_terminal_with_claim(engine, terminal, context, receipt)
    }

    fn begin_persistent_process_terminal_from_exec(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        pending: PendingExecTerminal,
    ) -> executor::ExecutorExit {
        let PendingExecTerminal { context, handoff } = pending;
        let receipt = handoff.claim_process_exit().unwrap_or_else(|failure| {
            match &terminal {
                PersistentTerminal::Error(original) => {
                    tracing::error!(%original, %failure, "claim exec terminal handoff owner");
                }
                PersistentTerminal::Outcome { .. } => {
                    tracing::error!(%failure, "claim exec terminal handoff owner");
                }
            }
            carrick_fatal!(
                "hvpatch::exec_terminal",
                "claim exec terminal handoff owner failed: {failure}"
            );
        });
        self.state.service_kernel_context = Some(context.retain_exact());
        self.state.kernel_thread = Some(Arc::clone(context.thread()));
        if receipt.claim == ProcessExitClaim::Owner {
            self.kernel.begin_process_exit();
        }
        self.begin_persistent_process_terminal_with_claim(engine, terminal, context, receipt)
    }

    fn begin_persistent_process_terminal_with_claim(
        &mut self,
        engine: &mut E,
        terminal: PersistentTerminal,
        context: crate::kernel::KernelContext,
        receipt: ProcessExitClaimReceipt,
    ) -> executor::ExecutorExit {
        match receipt.claim {
            ProcessExitClaim::LostToExec | ProcessExitClaim::AlreadyOwned => {
                self.state.trace_hvpatch_thread_terminal(
                    carrick_observability::probes::HvpatchThreadTerminalReason::ProcessTerminalLoser,
                    2,
                );
                if self.terminal_runtime == PersistentTerminalRuntimeState::Resident {
                    let _ = self.state.handle_persistent_thread_exit(
                        &self.kernel,
                        engine,
                        127,
                        self.traps,
                    );
                    self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
                }
                return self.finish(Ok(VcpuLoopOutcome::ThreadDone));
            }
            ProcessExitClaim::Pending => {
                tracing::info!(tid = ?self.state.this_tid, "process-terminal claim PENDING parks");
                let scheduler = self
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("kernel::runtime_binding", "A pending terminal claim cannot subscribe its exact thread without the Kernel HVPatch runtime"))
                    .continuation_services(context.kernel())
                    .0;
                let thread = context.thread().key();
                let subscription = self.kernel.clone_admission.subscribe_change(
                    receipt.change_epoch,
                    Arc::new(move || {
                        let _ = scheduler.wake(thread);
                    }),
                );
                self.phase = HvpatchProductionPhase::TerminalClaimRetry {
                    terminal,
                    context,
                    _subscription: subscription,
                };
                return self.suspend(
                    HvpatchLoopSuspension::TerminalSiblingDrain,
                    executor::ExecutorExit::Blocked(
                        crate::kernel::objects::BlockedReason::ChildState,
                    ),
                );
            }
            ProcessExitClaim::Owner => {
                self.terminal_settlement
                    .arm_process_owner()
                    .unwrap_or_else(|failure| {
                        tracing::error!(%failure, "arm persistent terminal result owner");
                        carrick_fatal!(
                            "kernel::terminal_settlement",
                            "arm persistent terminal result owner failed: {failure}"
                        );
                    });
            }
        }
        let mut terminal = terminal;
        if let PersistentTerminal::Outcome {
            ref outcome,
            ref mut prepared_core,
        } = terminal
        {
            let terminating_signal = match outcome {
                VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run) => {
                    run.terminating_signal
                }
                VcpuLoopOutcome::ThreadDone => None,
            };
            if let Some(fatal) = fatal_for_terminal_owner(
                self.kernel
                    .fatal_signal
                    .recorded_for(self.state.fatal_image_generation),
                self.state.fatal_image_generation,
                self.state.linux_tid,
                terminating_signal,
            ) {
                *prepared_core =
                    match self
                        .state
                        .capture_core_for_publication(&self.kernel, engine, fatal)
                    {
                        Ok(p) => p.map(Box::new),
                        Err(error) => {
                            tracing::warn!(%error, "capture core for publication");
                            None
                        }
                    };
            }
        }
        // Withdraw runtime execution immediately, but retain the exact Kernel
        // thread/generation through drain and topology retries. Their callbacks
        // wake this owner by that key; retiring it here loses the only wake.
        if self.terminal_runtime == PersistentTerminalRuntimeState::Resident {
            self.state
                .withdraw_persistent_terminal_owner_runtime(&self.kernel, engine);
            self.terminal_runtime = PersistentTerminalRuntimeState::Withdrawn;
        }
        drop(self.state.guest_execution.take());
        let drain = self
            .state
            .begin_persistent_exit_sibling_drain(&self.kernel, self.completion.id())
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "begin persistent failure sibling drain");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "begin persistent failure sibling drain failed: {failure}"
                );
            });
        if drain.is_ready() {
            let completions = self
                .state
                .finish_persistent_sibling_drain(&self.completion)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "finish persistent failure sibling drain");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "finish persistent failure sibling drain failed: {failure}"
                    );
                });
            self.kernel
                .process_physical_retirement
                .publish(completions)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "publish persistent process physical retirement");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "publish persistent process physical retirement failed: {failure}"
                    );
                });
            return self.finalize_persistent_process_terminal(engine, context, terminal);
        }
        self.phase = HvpatchProductionPhase::TerminalProcessDrain {
            terminal,
            context,
            drain,
        };
        self.suspend(
            HvpatchLoopSuspension::TerminalSiblingDrain,
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
        )
    }

    fn suspend_for_process_quiesce(
        &mut self,
        engine: &E,
        _control: &executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<Option<executor::ExecutorExit>, RuntimeError> {
        let Some(barrier) = self.state.process_fork_barrier.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        if !barrier.is_quiescing() {
            return Ok(None);
        }
        let _ = self.state.stash_parked_registers(engine);
        if self
            .state
            .publish_crash_registers_if_requested(engine)
            .is_err()
        {
            self.state.withdraw_from_crash_capture();
        }
        let context = match self.state.service_kernel_context.as_ref() {
            Some(context) => context.retain_exact(),
            None => self
                .kernel
                .dispatcher
                .capture_kernel_context(self.state.linux_tid)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "quiescing HVPatch task lost Kernel context: {error}"
                    ))
                })?,
        };
        self.state.service_kernel_context = Some(context.retain_exact());
        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::quiesce_barrier",
                    "Missing quiesce barrier reference when suspending for process quiesce"
                )
            })
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();
        loop {
            let observed = barrier.publication_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            let enrollment = barrier.subscribe_quiesce(
                observed,
                Arc::new(move |event| {
                    if event.kind == carrick_thread::fork_quiesce::QuiesceEventKind::Released {
                        let _ = wake_scheduler.wake(thread);
                    }
                }),
            );
            match enrollment {
                carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(event)
                    if event.kind == carrick_thread::fork_quiesce::QuiesceEventKind::Released =>
                {
                    return Ok(None);
                }
                carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(_) => continue,
                carrick_thread::fork_quiesce::QuiesceEnrollment::Subscribed(subscription) => {
                    self.phase = HvpatchProductionPhase::ResumeForkQuiesce {
                        _subscription: subscription,
                    };
                    let exit = self.suspend(
                        HvpatchLoopSuspension::InitialAdmission,
                        executor::ExecutorExit::Quiesced,
                    );
                    barrier.notify_quiesced_progress();
                    return Ok(Some(exit));
                }
            }
        }
    }

    fn suspend_for_job_control(
        &mut self,
        engine: &mut E,
        _control: &executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<Option<executor::ExecutorExit>, RuntimeError> {
        let context = match self.state.service_kernel_context.as_ref() {
            Some(context) => context.retain_exact(),
            None => {
                let context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture kernel context for job control: {error}"
                        ))
                    })?;
                self.state.service_kernel_context = Some(context.retain_exact());
                context
            }
        };
        let task = context.task();
        let ptrace_stop_settled = match context.kernel().settle_task_ptrace_stop(task.key().id) {
            crate::kernel::objects::PtraceStopSettlement::NotPtraceStopped => false,
            crate::kernel::objects::PtraceStopSettlement::Stopped
            | crate::kernel::objects::PtraceStopSettlement::Resumed { .. } => true,
        };
        if !task.is_job_control_stopped() && !ptrace_stop_settled {
            return Ok(None);
        }
        self.state.withdraw_from_crash_capture();
        self.state
            .publish_thread_run_state(crate::run_state::RunState::Blocked, 'T');

        let scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during job control suspension"))
            .continuation_services(context.kernel())
            .0;
        let thread = context.thread().key();

        while task.is_job_control_stopped() {
            let observed = task.wake_generation();
            let wake_scheduler = Arc::clone(&scheduler);
            let enrollment = task.subscribe_wake(
                observed,
                Arc::new(move |_| {
                    let _ = wake_scheduler.wake(thread);
                }),
            );
            match enrollment {
                crate::kernel::objects::TaskWakeEnrollment::Ready(_) => {
                    if !task.is_job_control_stopped() {
                        break;
                    }
                    continue;
                }
                crate::kernel::objects::TaskWakeEnrollment::Subscribed(subscription) => {
                    if !task.is_job_control_stopped() {
                        break;
                    }
                    self.phase = HvpatchProductionPhase::ResumeJobControlStop {
                        _subscription: subscription,
                    };
                    let exit = self.suspend(
                        HvpatchLoopSuspension::BlockedContinuation,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    );
                    return Ok(Some(exit));
                }
            }
        }
        if let Some(fault) = context.kernel().take_ptrace_resume_fault(task.key().id) {
            if let Some(outcome) = deliver_fault_signal(
                &self.kernel,
                &context,
                engine,
                self.state.this_tid,
                self.state.fatal_image_generation,
                fault.signal.raw(),
                fault.si_code,
                fault.si_addr,
                fault.interrupted_pc,
                self.traps,
            )? {
                return Ok(Some(self.enter_terminal_with_outcome(engine, outcome)));
            }
            return Ok(None);
        }
        if ptrace_stop_settled
            && let Some(outcome) = service_signals_threaded(
                &self.kernel,
                &context,
                engine,
                self.state.this_tid,
                self.state.fatal_image_generation,
                None,
                None,
                None,
                None,
                self.traps,
            )?
        {
            return Ok(Some(self.enter_terminal_with_outcome(engine, outcome)));
        }
        Ok(None)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[allow(clippy::too_many_arguments)]
    fn rollback_published_hvpatch_clone<M: threads::CloneTidMemory>(
        &self,
        memory: &mut M,
        context: &crate::kernel::KernelContext,
        generation: crate::kernel::objects::ExecutionGeneration,
        tid: ThreadId,
        tid_outputs: &threads::CloneTidOutputTransaction,
        logical: Option<PreparedHvpatchLogicalJob>,
        registry_installed: bool,
    ) {
        let completion = logical.as_ref().map(|logical| logical.completion.clone());
        // Dropping the logical job first retires its exact task backend/carrier
        // registration. No scheduler or Kernel row can be retired while a live
        // backend still has authority to mutate the child MM.
        drop(logical);
        let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "Missing parent execution context during clone publication rollback"
            )
        });
        let process = self.kernel.hvpatch_process.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "Missing HVPatch runtime binding on KernelState during clone rollback"
            )
        });
        let scheduler = runtime.continuation_services(context.kernel()).0;
        executor::retire_failed_hvpatch_clone_authority(
            &scheduler,
            process.kernel_graph(),
            context,
            generation,
            |thread, generation| runtime.persistent_bindings().retire(thread, generation),
        )
        .map(|retirement| {
            // A child that settled terminally before the rollback reached it
            // is not a rollback failure. This used to abort the carrier: an
            // executor claimed the child's pre-activation generation, could
            // not resolve its binding, settled it
            // `Failed { SnapshotRestoreFailed }`, and this rollback then
            // found that Failed generation and killed every Linux process in
            // the carrier. The claim itself is now unrepresentable (the
            // thread's pre-publication reservation outlives the authority
            // this rollback drops), and the outcome of reaching this state by
            // any other route is a guest-visible clone failure, not a dead
            // carrier.
            if let executor::FailedCloneRetirement::AlreadySettled(state) = retirement {
                tracing::error!(
                    thread = ?context.thread().key(),
                    ?generation,
                    ?state,
                    "HVPatch clone rollback found its child already settled; failing the clone"
                );
            }
        })
        .unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: authoritative HVPatch clone rollback: {error}");
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "authoritative HVPatch clone rollback failed: {error}"
            );
        });
        if registry_installed {
            self.state.registry.exit(tid);
        }
        tid_outputs.rollback(memory).unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: restore published HVPatch clone TID outputs: {error}");
            carrick_fatal!(
                "hvpatch::clone_rollback",
                "restore published HVPatch clone TID outputs failed: {error}"
            );
        });
        if let Some(completion) = completion {
            let id = completion.id();
            let _ = self.state.threads.take_by_id(id);
            // Completion is the final irrevocable publication. Every backend,
            // binding, scheduler, Kernel, registry, handle, and copyout owner
            // above is gone before a waiter can observe it.
            completion.publish();
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn spawn_persistent_hvpatch_clone_thread<M, O>(
        &mut self,
        memory: &mut M,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        parent_context: &crate::kernel::KernelContext,
        request: HvpatchCloneThreadRequest,
        retry_prepared: Option<crate::kernel::PreparedThreadClone>,
        ops: &mut O,
    ) -> Result<PersistentHvpatchCloneAttempt, RuntimeError>
    where
        M: threads::CloneTidMemory + 'static,
        O: HvpatchCloneBackendOps<M>,
    {
        let HvpatchCloneThreadRequest {
            stack,
            tls,
            flags,
            parent_tid_addr,
            child_tid_addr,
            clear_child_tid_addr,
        } = request;

        let clone_permit = match self.kernel.enroll_thread_clone() {
            CloneEnrollment::Admitted(permit) => permit,
            CloneEnrollment::Deferred { observed_epoch } => {
                // A sibling's process fork has admission closed while it
                // publishes its child. Linux serializes the two; park until
                // that close lifts and enroll again, keeping any prepared
                // clone state for the retry.
                let scheduler = self
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("kernel::runtime_binding", "Missing HVPatch runtime reference when constructing the clone-admission deferral wake callback"))
                    .continuation_services(parent_context.kernel())
                    .0;
                let thread = parent_context.thread().key();
                let subscription = self.kernel.clone_admission.subscribe_change(
                    observed_epoch,
                    Arc::new(move || {
                        let _ = scheduler.wake(thread);
                    }),
                );
                tracing::debug!("thread clone deferred behind a sibling fork's admission close");
                return Ok(PersistentHvpatchCloneAttempt::Wait {
                    prepared: retry_prepared,
                    subscription: CloneRetrySubscription::Admission {
                        _subscription: subscription,
                    },
                });
            }
            CloneEnrollment::Refused => {
                // A guest-visible resource failure must never be silent: EAGAIN
                // from thread admission under NO real pressure has meant a leaked
                // permit/lease before, and the guest's own report ("failed to
                // spawn thread") cannot say which side refused.
                tracing::warn!("thread clone admission refused; clone(2) = EAGAIN");
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN),
                ));
            }
        };
        if self.kernel.process_exiting() || clone_permit.is_cancelled() {
            tracing::warn!(
                exiting = self.kernel.process_exiting(),
                "thread clone raced exec/exit cancellation; clone(2) = EAGAIN"
            );
            return Ok(PersistentHvpatchCloneAttempt::Complete(
                threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN),
            ));
        }
        let plan = match crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::from_bits_retain(flags),
        ) {
            Ok(plan) => plan,
            Err(_) => {
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EINVAL),
                ));
            }
        };
        let process = self.kernel.hvpatch_process.as_ref().ok_or_else(|| {
            RuntimeError::Configuration("persistent thread clone has no HVPatch process".to_owned())
        })?;
        let wait_for_change = |observed, prepared| {
            let runtime = self
                .kernel
                .hvpatch_runtime
                .as_ref()
                .unwrap_or_else(|| carrick_fatal!("hvpatch::task_backend_lifecycle", "Missing HVPatch runtime reference when constructing the reservation-change wake callback for a deferred thread clone"));
            let scheduler = runtime.continuation_services(parent_context.kernel()).0;
            let thread = parent_context.thread().key();
            let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || {
                let _ = scheduler.wake(thread);
            });
            let subscription = process
                .kernel_graph()
                .subscribe_reservation_change(observed, callback);
            PersistentHvpatchCloneAttempt::Wait {
                prepared,
                subscription: CloneRetrySubscription::Reservation {
                    _subscription: subscription,
                },
            }
        };
        let prepared = if let Some(prepared) = retry_prepared {
            prepared
        } else {
            let observed = process.kernel_graph().reservation_epoch();
            let reservation =
                match process
                    .kernel_graph()
                    .reserve_thread_clone(parent_context, plan, None)
                {
                    Ok(reservation) => reservation,
                    Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                        return Ok(wait_for_change(observed, None));
                    }
                    Err(error) => {
                        return Err(RuntimeError::Configuration(format!(
                            "reserve persistent HVPatch thread clone: {error}"
                        )));
                    }
                };
            let linux_tid = reservation.tid();
            let tid = ThreadId::from_guest_supplied_tid(linux_tid.raw());
            reservation.prepare(tid).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "prepare persistent HVPatch thread clone: {error}"
                ))
            })?
        };
        let observed = process.kernel_graph().reservation_epoch();
        let prepared = match prepared.try_reserve_publication().map_err(|error| {
            RuntimeError::Configuration(format!(
                "reserve persistent HVPatch thread publication: {error}"
            ))
        })? {
            crate::kernel::ThreadPublicationReservationAttempt::Reserved(prepared) => prepared,
            crate::kernel::ThreadPublicationReservationAttempt::Busy(prepared) => {
                return Ok(wait_for_change(observed, Some(prepared)));
            }
        };
        let linux_tid = prepared.tid();
        let visible_tid = prepared.visible_tid();
        let tid = ThreadId::from_guest_supplied_tid(linux_tid.raw());
        let tid_outputs = match threads::CloneTidOutputTransaction::capture(
            memory,
            parent_tid_addr,
            child_tid_addr,
        ) {
            Ok(outputs) => outputs,
            Err(errno) => {
                return Ok(PersistentHvpatchCloneAttempt::Complete(
                    threads::CloneThreadSpawn::Errno(errno),
                ));
            }
        };
        let (task_key, thread_key, mm, expected_generation) =
            prepared.prepared_execution_identity();
        let mm_binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration(
                "persistent HVPatch clone has no MM/ASID binding".to_owned(),
            )
        })?;
        let asid_generation = process.asid_generation();
        let carrier_identity = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity {
            task_serial: task_key.serial.raw(),
            thread_serial: thread_key.serial.raw(),
            execution_generation: expected_generation.raw(),
            linux_pid: process.pid(),
            linux_tid: linux_tid.raw(),
            asid: mm_binding.asid.raw(),
        };
        let (prepared_backend, cpu) = ops.prepare(
            memory,
            carrier_identity,
            carrick_hal::GuestEntryRegs {
                return_value: 0,
                stack: Some(stack),
                tls,
            },
            mm.raw(),
            asid_generation,
        )?;
        if !tid_outputs.publish(memory, visible_tid, tid) {
            tid_outputs.rollback(memory).map_err(|error| {
                RuntimeError::Configuration(format!(
                    "restore failed HVPatch clone TID copyout: {error}"
                ))
            })?;
            ops.abort(prepared_backend)?;
            return Ok(PersistentHvpatchCloneAttempt::Complete(
                threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT),
            ));
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::TidCopyout) {
            tid_outputs.rollback(memory).map_err(|rollback| {
                RuntimeError::Configuration(format!(
                    "restore failpoint HVPatch clone TID outputs: {rollback}"
                ))
            })?;
            ops.abort(prepared_backend)?;
            return Err(error);
        }
        let published = match prepared.commit() {
            Ok(published) => published,
            Err(error) => {
                tid_outputs.rollback(memory).map_err(|rollback| {
                    RuntimeError::Configuration(format!(
                        "restore unpublished HVPatch clone TID outputs: {rollback}"
                    ))
                })?;
                ops.abort(prepared_backend)?;
                return Err(RuntimeError::Configuration(format!(
                    "publish persistent HVPatch thread: {error}"
                )));
            }
        };
        let child_context = published
            .context()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "published HVPatch thread has no closed-gate context".to_owned(),
                )
            })?
            .retain_exact();
        let task_state = crate::kernel::objects::MigratableTaskState {
            cpu,
            mm,
            asid_generation,
        };
        // The gate must stand BEFORE the child is Kernel-runnable: from here
        // a producer can wake it, and its submission is not admitted for
        // another few hundred lines. See
        // `Scheduler::publish_initial_task_state_gated`.
        let publishing_scheduler = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent HVPatch clone has no runtime directory".to_owned(),
                )
            })?
            .continuation_services(child_context.kernel())
            .0;
        let generation = match publishing_scheduler
            .publish_initial_task_state_gated(child_context.thread(), task_state.clone())
        {
            Ok(generation) if generation == expected_generation => generation,
            Ok(generation) => {
                ops.abort(prepared_backend).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: abort generation-drifted clone backend: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "abort generation-drifted clone backend failed: {error}"
                    );
                });
                let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
                    carrick_fatal!(
                        "kernel::runtime_binding",
                        "Missing HVPatch runtime binding during generation drift clone retirement"
                    )
                });
                let scheduler = runtime.continuation_services(child_context.kernel()).0;
                executor::retire_failed_hvpatch_clone_authority(
                    &scheduler,
                    process.kernel_graph(),
                    &child_context,
                    generation,
                    |_, _| {},
                )
                .map(|_| ())
                .unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: retire generation-drifted clone: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "retire generation-drifted clone failed: {error}"
                    );
                });
                tid_outputs.rollback(memory).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: restore generation-drifted clone TIDs: {error}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore generation-drifted clone TIDs failed: {error}"
                    );
                });
                return Err(RuntimeError::Configuration(
                    "persistent HVPatch child execution generation drifted".to_owned(),
                ));
            }
            Err(error) => {
                ops.abort(prepared_backend).unwrap_or_else(|abort| {
                    eprintln!("carrick: FATAL: abort unpublished clone backend: {abort}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "abort unpublished clone backend failed: {abort}"
                    );
                });
                process
                    .kernel_graph()
                    .exit_thread(&child_context, None)
                    .unwrap_or_else(|retire| {
                        eprintln!("carrick: FATAL: retire unpublished clone: {retire}");
                        carrick_fatal!(
                            "hvpatch::clone_lifecycle",
                            "retire unpublished clone failed: {retire}"
                        );
                    });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore published clone TIDs: {rollback}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore published clone TIDs failed: {rollback}"
                    );
                });
                return Err(RuntimeError::Configuration(format!(
                    "publish persistent HVPatch child execution state: {error}"
                )));
            }
        };
        let runtime = self.kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "Missing HVPatch runtime binding when committing clone task backend"
            )
        });
        let mut task_backend = match ops.commit(
            prepared_backend,
            runtime.carrier_tasks(child_context.kernel()),
        ) {
            Ok(state) => state,
            Err(error) => {
                let scheduler = runtime.continuation_services(child_context.kernel()).0;
                executor::retire_failed_hvpatch_clone_authority(
                    &scheduler,
                    process.kernel_graph(),
                    &child_context,
                    generation,
                    |_, _| {},
                )
                .map(|_| ())
                .unwrap_or_else(|retire| {
                    eprintln!("carrick: FATAL: retire carrier-commit clone: {retire}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "retire carrier-commit clone failed: {retire}"
                    );
                });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore carrier-commit clone TIDs: {rollback}");
                    carrick_fatal!(
                        "hvpatch::clone_lifecycle",
                        "restore carrier-commit clone TIDs failed: {rollback}"
                    );
                });
                return Err(error);
            }
        };
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::BackendCommit) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        let cow_identity = carrick_hal::FrameCowIdentity {
            linux_pid: process.pid(),
            linux_tid: linux_tid.raw(),
            mm: mm.raw(),
            asid: mm_binding.asid.raw(),
        };
        let cow_authority = Arc::new(KernelFrameCowAuthority {
            deferred_anonymous: self.kernel.dispatcher.deferred_anonymous_state(mm),
            kernel: Arc::clone(child_context.kernel()),
            mm,
            owner_inventory: ops.frame_cow_owner_inventory(&task_backend),
            guest_executors: self.kernel.dispatcher.mm_executor_census(),
            tid,
            identity: cow_identity,
            pt_quiesce: self.kernel.dispatcher.pt_quiesce(),
        });
        let child_token = match Arc::clone(&cow_authority).issue_hvpatch_child_token(&child_context)
        {
            Ok(token) => token,
            Err(error) => {
                drop(task_backend);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    None,
                    false,
                );
                return Err(RuntimeError::Configuration(error));
            }
        };
        if let Err(error) = ops.bind_child_kernel(&mut task_backend, child_token) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::TokenBind) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }
        if let Err(error) = ops.activate_child(&mut task_backend) {
            drop(task_backend);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                None,
                false,
            );
            return Err(error);
        }

        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let mut child_state = ThreadRuntimeState::<E>::new(
            Arc::clone(&self.state.registry),
            Arc::clone(&self.state.futex),
            Arc::clone(&self.state.platform_futex),
            Arc::clone(&self.state.platform_futex_factory),
            self.kernel.process_fork_barrier.clone(),
            self.kernel.crash_capture.clone(),
            Some(Arc::clone(child_context.thread())),
            Some(process.pid()),
            linux_tid,
            self.kernel.fatal_signal.current_generation(),
            tid,
            self.state.threads.clone(),
            Arc::clone(&self.state.kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            self.state.max_traps,
        );
        child_state.execution_lease = execution_lease;
        child_state.service_kernel_context = Some(child_context.retain_exact());
        let child_syscall = self
            .state
            .syscall_completion
            .guest("clone child publication lost parent completion token")?
            .syscall();
        child_state.syscall_completion =
            SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                child_syscall,
                child_context.retain_exact(),
                self.kernel.dispatcher.observers().cloned(),
            ));
        let mut logical = match prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&self.kernel),
            state: child_state,
            task_backend: ops.make_binding_state(task_backend),
            context: child_context.retain_exact(),
            cpu: task_state,
            generation,
            injected_lease,
            bootstrap_process_child: None,
            bootstrap_thread_child: true,
        }) {
            Ok(logical) => logical,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    None,
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        let (grant_thread, grant_generation) = match control.current_submission_key() {
            Ok(key) => key,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        let dormant = match control.prepare_hvpatch_submission(
            runtime.persistent_bindings(),
            executor::HvpatchSubmissionShape::SameTaskSibling {
                grant: (grant_thread, grant_generation),
            },
            Arc::clone(child_context.thread()),
            generation,
            Arc::clone(&logical.binding),
        ) {
            Ok(dormant) => dormant,
            Err(error) => {
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    false,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        self.state
            .registry
            .register_child_with_tid(tid, clear_child_tid_addr);
        enroll_persistent_process_member(&self.state.threads, &logical.terminal_settlement);
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::RegistryHandle) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        let started = match published.start_thread() {
            Ok(started) => started,
            Err(error) => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Configuration(format!(
                    "open persistent HVPatch child start gate: {error}"
                )));
            }
        };
        let start_gate = match started
            .context()
            .thread()
            .take_opened_start_gate(generation)
        {
            Some(gate) => gate,
            None => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Configuration(
                    "persistent HVPatch child lost opened start proof".to_owned(),
                ));
            }
        };
        if let Err(error) = logical.install_start_gate(start_gate) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(RuntimeError::Trap(error));
        }
        let proof = match logical.activation_proof() {
            Ok(proof) => proof,
            Err(error) => {
                drop(dormant);
                self.rollback_published_hvpatch_clone(
                    memory,
                    &child_context,
                    generation,
                    tid,
                    &tid_outputs,
                    Some(logical),
                    true,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::StartProof) {
            drop(dormant);
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        if let Err(error) = dormant.activate(
            &runtime.continuation_services(child_context.kernel()).0,
            Arc::clone(child_context.thread()),
            proof,
        ) {
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(RuntimeError::Trap(error));
        }
        if let Err(error) = check_hvpatch_clone_failpoint(HvpatchCloneFailpoint::Activation) {
            self.rollback_published_hvpatch_clone(
                memory,
                &child_context,
                generation,
                tid,
                &tid_outputs,
                Some(logical),
                true,
            );
            return Err(error);
        }
        drop(clone_permit);
        Ok(PersistentHvpatchCloneAttempt::Complete(
            threads::CloneThreadSpawn::Started {
                internal: linux_tid,
                visible: visible_tid,
            },
        ))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn complete_persistent_hvpatch_clone(
        &mut self,
        engine: &mut E,
        spawned: threads::CloneThreadSpawn,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let (completed_internal_tid, completed_visible_tid, completed_errno) = match spawned {
            threads::CloneThreadSpawn::Started { internal, visible } => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, i64::from(visible))?;
                (internal.raw(), visible, 0)
            }
            threads::CloneThreadSpawn::Errno(errno) => {
                self.state.complete_returned(
                    engine,
                    &self.kernel.reporter,
                    errno.guest_retval(),
                )?;
                (
                    self.state.this_tid.raw(),
                    self.state.this_tid.raw(),
                    errno.get(),
                )
            }
        };
        crate::event_ring::rec(
            crate::event_ring::CLONESPAWN,
            self.state.this_tid.raw(),
            completed_internal_tid,
            completed_errno,
        );
        crate::probes::mn_clone_outcome(
            completed_visible_tid,
            carrick_observability::probes::HvpatchCloneThreadPhase::Completed,
            completed_errno,
        );
        Ok(executor::ExecutorExit::Syscall)
    }

    fn leave_executor(&mut self) {
        self.state.kicker.unregister(self.state.this_tid);
        drop(self.state.guest_execution.take());
    }

    fn finish(&mut self, outcome: Result<VcpuLoopOutcome, RuntimeError>) -> executor::ExecutorExit {
        self.leave_executor();
        if self.terminal_result.replace(outcome).is_some() {
            carrick_fatal!(
                "vcpu_loop::lifecycle",
                "Duplicate terminal outcome recorded on completed thread run loop"
            );
        }
        self.phase = HvpatchProductionPhase::Complete;
        executor::ExecutorExit::Exited
    }

    fn publish_terminal_result(&mut self) {
        if self.terminal_result.is_none() && !self.terminal_settlement.is_published() {
            self.state.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::ExternallySettledWithoutResult,
                self.phase.probe_ordinal(),
            );
        }
        self.terminal_settlement
            .publish_terminal(self.terminal_result.take());
    }

    /// Publish the terminal result of a job that lost the process-exit claim.
    ///
    /// Such a job carries no outcome of its own: another thread of the same
    /// process owns the exit, so Linux terminated this thread. That is the same
    /// `ThreadDone` the owner's member drain publishes through
    /// `publish_member`, and publishing it here keeps the job's own settlement
    /// the sole owner of its publication instead of a member list this job may
    /// already have left.
    fn publish_lost_claim_terminal_result(&mut self) {
        if self.terminal_result.is_none() {
            self.terminal_result = Some(Ok(VcpuLoopOutcome::ThreadDone));
        }
        self.publish_terminal_result();
    }

    fn suspend(
        &mut self,
        suspension: HvpatchLoopSuspension,
        exit: executor::ExecutorExit,
    ) -> executor::ExecutorExit {
        self.leave_executor();
        match suspension {
            HvpatchLoopSuspension::BlockedContinuation | HvpatchLoopSuspension::VforkParent => {
                let is_stopped = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .is_some_and(|cx| cx.task().is_job_control_stopped());
                if is_stopped {
                    self.state
                        .publish_thread_run_state(crate::run_state::RunState::Blocked, 'T');
                } else {
                    self.state
                        .publish_thread_run_state(crate::run_state::RunState::Blocked, 'S');
                }
            }
            _ => {}
        }
        exit
    }

    fn publish_exec_replacement(
        &mut self,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<bool, RuntimeError> {
        if let Some(replacement) = self.state.pending_exec_replacement.take() {
            control
                .publish_exec_replacement(replacement)
                .map_err(RuntimeError::Trap)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn finish_exec_suffix(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        finished: exec::FinishedPreparedExecve,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let (outcome, context, handoff) = finished.into_parts();
        let replaced = match self.publish_exec_replacement(control) {
            Ok(replaced) => replaced,
            Err(error) => {
                return Err(ProductionHvpatchPollError::from_exec_error(
                    error, context, handoff,
                ));
            }
        };
        let pending = PendingExecTerminal { context, handoff };
        if let Some(outcome) = outcome {
            return Ok(self.begin_persistent_process_terminal_from_exec(
                engine,
                PersistentTerminal::from_outcome(outcome),
                pending,
            ));
        }

        // Successful replacement is the only non-terminal path that may
        // reopen clone admission. Every fallible operation after the close,
        // including executor replacement publication, has completed first.
        drop(pending);
        Ok(if replaced {
            self.suspend(
                HvpatchLoopSuspension::Preemption,
                executor::ExecutorExit::Preempted,
            )
        } else {
            executor::ExecutorExit::Syscall
        })
    }

    fn service_outcome(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: carrick_hal::RawSyscall,
        outcome: DispatchOutcome,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        if continuation::is_blocking_dispatch_outcome(&outcome) {
            let _ = self.state.stash_parked_registers(engine);
            let request = self
                .state
                .syscall_completion
                .guest("blocking syscall lost its prepared completion token")?
                .syscall()
                .request;
            let exit = self.state.persistent_block_exit(
                &self.kernel,
                control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                request,
                HvpatchBlockInput::Dispatch(outcome),
            )?;
            self.phase = HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid: None,
            };
            return Ok(self.suspend(HvpatchLoopSuspension::BlockedContinuation, exit));
        }

        Ok(match outcome {
            DispatchOutcome::Returned { value } => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                // Self-directed signals (e.g. raise(SIGABRT)) posted during syscall handling must be serviced before returning to guest EL0, otherwise the thread resumes execution and runs subsequent instructions (like _exit(99)) before any asynchronous kick can arrive.
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::Errno { errno } => {
                let value = self
                    .state
                    .complete_errno(engine, &self.kernel.reporter, errno)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SchedulerYield => {
                self.state
                    .complete_returned(engine, &self.kernel.reporter, 0)?;
                // Linux delivers pending signals on the return-to-user edge of
                // EVERY syscall — sched_yield included. This arm skipped the
                // service, so a thread looping on sched_yield NEVER took a
                // pending unblocked signal: musl's __synccall broadcast
                // (SIGSYNCCALL, rt signal 34) sat pending on a yield-storming
                // sibling forever and set*id hung for its full 45 s budget
                // (setidthreadchurn — kernel snapshot showed the pending
                // signal on a Running thread across ~200k yield quanta).
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(0),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                self.suspend(
                    HvpatchLoopSuspension::SchedulerYield,
                    executor::ExecutorExit::Yielded,
                )
            }
            DispatchOutcome::ThreadExit { code } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                let disposition = self.state.handle_persistent_thread_exit(
                    &self.kernel,
                    engine,
                    code,
                    self.traps,
                );
                self.settle_persistent_thread_exit(engine, code, context, disposition)
            }
            DispatchOutcome::Exit { code } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    code,
                    None,
                    self.traps,
                    false,
                )));
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            DispatchOutcome::Execve { path, argv, env } => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent exec lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let preparation = self.state.prepare_execve(
                    &self.kernel,
                    &context,
                    engine,
                    path,
                    argv,
                    env,
                    ExecCompletionOrigin::GuestSyscall,
                )?;
                match preparation {
                    exec::ExecvePreparation::Complete(Some(outcome)) => {
                        self.state.retire_syscall()?;
                        self.finish(Ok(outcome))
                    }
                    exec::ExecvePreparation::Complete(None) => executor::ExecutorExit::Syscall,
                    exec::ExecvePreparation::TerminalFailure(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                    exec::ExecvePreparation::Prepared(prepared) => {
                        let prepared = *prepared;
                        let owner = match self.state.begin_prepared_execve_drain(
                            &self.kernel,
                            self.completion.id(),
                            prepared,
                        ) {
                            Ok(owner) => owner,
                            Err(failure) => {
                                return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                            }
                        };
                        if owner.is_ready() {
                            let finished = match self.state.finish_prepared_execve_drain(
                                &self.kernel,
                                engine,
                                &self.completion,
                                owner,
                            ) {
                                Ok(finished) => finished,
                                Err(failure) => {
                                    return Err(ProductionHvpatchPollError::from_exec_failure(
                                        failure,
                                    ));
                                }
                            };
                            return self.finish_exec_suffix(engine, control, finished);
                        }
                        self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                        self.suspend(
                            HvpatchLoopSuspension::ExecSiblingDrain,
                            executor::ExecutorExit::Blocked(
                                crate::kernel::objects::BlockedReason::ChildState,
                            ),
                        )
                    }
                }
            }
            DispatchOutcome::Fork {
                flags,
                pidfd_out,
                clone_parent,
                parent_tid_addr,
                child_tid_addr,
                exit_signal,
                child_stack,
                vfork,
            } if engine.supports_in_process_fork() => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent fork lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let prepared = self.state.prepare_in_process_fork(
                    &self.kernel,
                    &context,
                    engine,
                    control,
                    &mut ProductionHvpatchProcessBackendOps,
                    quiesce::ProcessForkAttempt {
                        request: quiesce::ForkRequest {
                            flags,
                            pidfd_out,
                            clone_parent,
                            parent_tid_addr,
                            child_tid_addr,
                            exit_signal,
                            child_stack,
                            vfork,
                        },
                        coordinator: None,
                        external_exec: None,
                    },
                )?;
                return Ok(self.complete_persistent_process_fork(
                    engine,
                    control,
                    Some(frame),
                    None,
                    prepared,
                )?);
            }
            DispatchOutcome::CloneThread {
                stack,
                tls,
                flags,
                parent_tid_addr,
                child_tid_addr,
                clear_child_tid_addr,
            } => {
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                let spawned = {
                    let context = self
                        .state
                        .service_kernel_context
                        .as_ref()
                        .ok_or_else(|| {
                            RuntimeError::Configuration(
                                "persistent clone-thread lost exact Kernel context".to_owned(),
                            )
                        })?
                        .retain_exact();
                    let request = HvpatchCloneThreadRequest {
                        stack,
                        tls,
                        flags,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                    };
                    match self.spawn_persistent_hvpatch_clone_thread(
                        engine,
                        control,
                        &context,
                        request,
                        None,
                        &mut ProductionHvpatchCloneBackendOps,
                    )? {
                        PersistentHvpatchCloneAttempt::Complete(spawned) => spawned,
                        PersistentHvpatchCloneAttempt::Wait {
                            prepared,
                            subscription,
                        } => {
                            self.phase = HvpatchProductionPhase::RetryCloneThread {
                                frame,
                                request,
                                prepared,
                                _subscription: subscription,
                            };
                            return Ok(self.suspend(
                                HvpatchLoopSuspension::BlockedContinuation,
                                executor::ExecutorExit::Blocked(
                                    crate::kernel::objects::BlockedReason::HostWait,
                                ),
                            ));
                        }
                    }
                };
                #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
                let spawned = threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN);
                let (completed_internal_tid, completed_visible_tid, completed_errno) = match spawned
                {
                    threads::CloneThreadSpawn::Started { internal, visible } => {
                        self.state.complete_returned(
                            engine,
                            &self.kernel.reporter,
                            i64::from(visible),
                        )?;
                        (internal.raw(), visible, 0)
                    }
                    threads::CloneThreadSpawn::Errno(errno) => {
                        self.state.complete_returned(
                            engine,
                            &self.kernel.reporter,
                            errno.guest_retval(),
                        )?;
                        (
                            self.state.this_tid.raw(),
                            self.state.this_tid.raw(),
                            errno.get(),
                        )
                    }
                };
                crate::event_ring::rec(
                    crate::event_ring::CLONESPAWN,
                    self.state.this_tid.raw(),
                    completed_internal_tid,
                    completed_errno,
                );
                crate::probes::mn_clone_outcome(
                    completed_visible_tid,
                    carrick_observability::probes::HvpatchCloneThreadPhase::Completed,
                    completed_errno,
                );
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SignalThread {
                tid,
                signum,
                kernel_target,
            } => {
                // `tkill`/`tgkill`/`pthread_kill` at a sibling thread. This
                // existed only in the welded loop; without it the outcome fell
                // through to the catch-all below, which returns `InvalidState`
                // and hangs the guest — `xthreadsig` timed out at
                // `SignalThread { signum: 10 }`.
                let value = self.state.complete_signal_thread(
                    &self.kernel,
                    engine,
                    tid,
                    signum,
                    kernel_target,
                )?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SetMemoryModel { tso } => {
                engine
                    .set_memory_model(hardware_tso_for_debug(tso))
                    .map_err(RuntimeError::Trap)?;
                let value = self
                    .state
                    .complete_returned(engine, &self.kernel.reporter, 0)?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SigReturn => {
                // `rt_sigreturn`. This existed only in the welded loop, so on the
                // persistent path it fell through to the unlowered-outcome arm —
                // invisible until forced-exit signal service started actually
                // delivering signals, at which point every guest that RETURNED
                // from a handler produced one of these.
                let restored_sigmask = match engine.restore_from_sigframe() {
                    Ok(mask) => mask,
                    // A guest-reachable bad `rt_sigreturn` frame (bad SP, or a
                    // corrupt/forged frame) is `force_sigsegv` on Linux: kill
                    // THIS process by SIGSEGV, never abort the carrier. Mirrors
                    // the unclassified-EL0-fault path.
                    Err(TrapError::SignalDeliveryFault) => {
                        self.state.retire_syscall()?;
                        let result = assemble_run_result(
                            &self.kernel,
                            128 + 11,
                            Some(crate::linux_abi::LINUX_SIGSEGV),
                            self.traps,
                            false,
                        );
                        return Ok(self.enter_terminal_with_outcome(
                            engine,
                            VcpuLoopOutcome::ProcessExit(Box::new(result)),
                        ));
                    }
                    Err(error) => return Err(RuntimeError::Trap(error).into()),
                };
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "sigreturn lost its exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                self.kernel.dispatcher.restore_signal_mask(
                    &context,
                    self.state.this_tid,
                    carrick_abi::SigSet::from_raw(restored_sigmask),
                );
                self.state.retire_syscall()?;
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                // The guest resumes at the just-restored user PC. Do NOT complete
                // a syscall return here: `rt_sigreturn` has no return value, and
                // on x86 the frame restores RCX as an ordinary caller-clobbered
                // register that a syscall-boundary completion would mistake for
                // the resume address.
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SharedFutexWake { target, count } => {
                let value =
                    shared_futex_wake(target.location.wait_addr().raw(), target.waiter_key, count);
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SharedFutexRequeue {
                from,
                to,
                wake,
                requeue,
            } => {
                trace_shared_futex_requeue(0, from.waiter_key, to.waiter_key, wake, requeue, 0, 0);
                let (carrier_woken, carrier_requeued) =
                    carrick_thread::platform_futex::carrier_shared_futex_table().requeue(
                        from.waiter_key as u64,
                        to.waiter_key as u64,
                        wake,
                        requeue,
                    );
                let (ulock_woken, ulock_requeued) = crate::ulock::requeue_counted(
                    from.location.wait_addr().raw(),
                    from.waiter_key,
                    to.location.wait_addr().raw(),
                    to.waiter_key,
                    wake,
                    requeue,
                );
                let woken = carrier_woken.max(ulock_woken);
                let requeued = carrier_requeued.max(ulock_requeued);
                trace_shared_futex_requeue(
                    1,
                    from.waiter_key,
                    to.waiter_key,
                    wake,
                    requeue,
                    woken,
                    requeued,
                );
                let value = i64::from(woken + requeued);
                self.state
                    .complete_returned(engine, &self.kernel.reporter, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    Some(value),
                    None,
                    self.state.continuation_restart.take(),
                    self.state.reserved_signal.take(),
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                executor::ExecutorExit::Syscall
            }
            DispatchOutcome::SignalDeath { signum } => {
                self.state.retire_syscall()?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context during run-loop outcome servicing"))
                    .retain_exact();
                self.kernel.record_fatal_signal(FatalSignalRecord {
                    image_generation: self.state.fatal_image_generation,
                    tid: context.thread().key().tid,
                    signo: signum,
                    code: 0,
                    addr: 0,
                });
                let outcome = VcpuLoopOutcome::ProcessExit(Box::new(assemble_run_result(
                    &self.kernel,
                    128 + signum,
                    Some(signum),
                    self.traps,
                    false,
                )));
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                )
            }
            other => {
                tracing::error!(
                    ?other,
                    "persistent HVPatch loop reached an unlowered outcome"
                );
                executor::ExecutorExit::InvalidState
            }
        })
    }

    /// Route a terminal outcome produced outside `service_outcome` — a fault
    /// signal that killed the process, or a forced-exit signal service — into
    /// the persistent terminal, the same way the trap watchdog does.
    fn enter_terminal_with_outcome(
        &mut self,
        engine: &mut E,
        outcome: VcpuLoopOutcome,
    ) -> executor::ExecutorExit {
        let context = self
            .state
            .service_kernel_context
            .as_ref()
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "vcpu_loop::service_context",
                    "ThreadRuntimeState missing service_kernel_context when entering terminal state"
                )
            })
            .retain_exact();
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::from_outcome(outcome),
            context,
        )
    }

    fn step_trap_watchdog<C, W>(&mut self, clock: C, max_wall: W) -> TrapWatchdog
    where
        C: FnOnce(&Instant) -> Duration,
        W: FnOnce() -> Duration,
    {
        let signal_progress = signal_progress_count();
        if signal_progress != self.seen_signal_progress {
            self.seen_signal_progress = signal_progress;
            self.budget_floor = self.traps;
            self.last_signal_progress = Instant::now();
        }
        let decision = trap_watchdog_decision(
            self.traps.saturating_sub(self.budget_floor),
            self.state.max_traps,
            || clock(&self.last_signal_progress),
            max_wall,
        );
        if decision == TrapWatchdog::ResetBudget {
            self.budget_floor = self.traps;
            self.last_signal_progress = Instant::now();
        }
        decision
    }

    fn poll_with_engine(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        if self.terminal_settlement.is_published()
            || matches!(self.phase, HvpatchProductionPhase::Complete)
        {
            self.phase = HvpatchProductionPhase::Complete;
            return Ok(executor::ExecutorExit::Exited);
        }
        if self.state.guest_execution.is_none() {
            drop(self.registration_wait.take());
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let pending_control_quantum = self.control_quantum()?.is_some();
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            let pending_control_quantum = false;
            let registration_wake_mode =
                registration_wake_uses_control(&self.phase, pending_control_quantum);
            let context = self.state.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent registration admission lost exact Kernel context".to_owned(),
                )
            })?;
            let runtime = self.kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent registration admission lost shared scheduler".to_owned(),
                )
            })?;
            let scheduler = runtime.continuation_services(context.kernel()).0;
            let wake_registration = registration_wake_callback(
                scheduler,
                context.thread().key(),
                registration_wake_mode,
            );
            let (participation, enrollment) = enter_mm_executor_then_register(
                &self.kernel.dispatcher,
                self.state.kernel_thread.as_ref().map(Arc::clone),
                Arc::clone(&self.state.kicker),
                self.state.this_tid,
                || {
                    self.state
                        .subscribe_register_vcpu(engine, wake_registration)
                },
            )
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            self.state.guest_execution = Some(participation);
            match enrollment {
                carrick_hal::VcpuRegistrationEnrollment::Registered => {}
                carrick_hal::VcpuRegistrationEnrollment::Waiting { subscription, .. } => {
                    self.registration_wait = Some(subscription);
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::InitialAdmission,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::HostWait,
                        ),
                    ));
                }
            }
        }

        // Exec/exit can force a blocked vfork parent runnable solely so it can
        // retire its exact logical result. Do not resume the old continuation
        // or touch guest state after that terminal ownership transition.
        let exec_finish =
            thread_should_finish_for_exec_replacement(&self.state.registry, self.state.this_tid);
        if !self.phase.is_terminal_transition() && (self.kernel.process_exiting() || exec_finish) {
            self.state.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAtLoopTop,
                i32::from(self.kernel.process_exiting()),
            );
            match self
                .state
                .handle_persistent_thread_exit(&self.kernel, engine, 0, self.traps)
            {
                // The drain path always finishes ThreadDone: the terminal
                // owner or exec survivor owns the task's end, so a
                // registry-derived process-exit claim is discarded here
                // exactly as it always was.
                threads::PersistentThreadExitDisposition::Done(_) => {
                    return Ok(self.finish(Ok(VcpuLoopOutcome::ThreadDone)));
                }
                threads::PersistentThreadExitDisposition::Busy { observed_epoch } => {
                    // Ownership passed: on this drain path the thread is
                    // here BECAUSE an exec replacement or the process
                    // terminal is retiring it — the Busy holder is (or is
                    // superseded by) the very transaction that retires this
                    // thread's kernel row. Its own exit_thread is redundant,
                    // and parking for the holder STRANDS: the retirement
                    // makes every registry-addressed wake UnknownThread
                    // (measured live — parks at observed_epoch with three
                    // later publishes, final wake Err(UnknownThread), 10/12
                    // teardown hangs). Finish; the owner retires the row.
                    let _ = observed_epoch;
                    return Ok(self.finish(Ok(VcpuLoopOutcome::ThreadDone)));
                }
            }
        }

        self.state
            .publish_thread_run_state(crate::run_state::RunState::Running, 'R');

        // A control exec is a peer-root operation, not completion of the
        // init's blocked syscall. Service it at this scheduler safe point
        // before ResumeBlocked consumes and re-parks the continuation. The
        // typed token survives a fork retry and restores the exact frame and
        // vfork identity after publication.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Some(quantum) = self.control_quantum()?
            && let Some(deferred_resume_blocked) =
                DeferredResumeBlocked::capture(&self.phase, quantum.blocked_reason)
        {
            if let Some(work) = self.kernel.try_take_control_exec() {
                return Ok(self.begin_control_exec_fork(
                    engine,
                    control,
                    work,
                    Some(deferred_resume_blocked),
                )?);
            }
            // Admission may have been cancelled before the owner claimed it.
            // Consume only the control edge and put the untouched continuation
            // back; never turn this into guest readiness.
            return Ok(self.finish_control_quantum(
                engine,
                control,
                Some(deferred_resume_blocked),
            )?);
        }

        let phase = std::mem::replace(&mut self.phase, HvpatchProductionPhase::Resident);
        match phase {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::BootstrapProcessChild(bootstrap) => {
                bootstrap_hvpatch_process_child(&self.kernel, &mut self.state, engine, bootstrap)?;
                if let Some(work) = self.kernel.take_external_exec_work() {
                    self.external_exec = Some(work);
                    return self.start_external_exec(engine, control);
                }
            }
            HvpatchProductionPhase::BootstrapThreadChild => {
                self.state
                    .complete_precompleted_child(&self.kernel.reporter, 0)?;
            }
            HvpatchProductionPhase::ResumeForkQuiesce { _subscription } => {
                drop(_subscription);
            }
            HvpatchProductionPhase::ResumeJobControlStop { _subscription } => {
                drop(_subscription);
                let context = match self.state.service_kernel_context.as_ref() {
                    Some(context) => context.retain_exact(),
                    None => self
                        .kernel
                        .dispatcher
                        .capture_kernel_context(self.state.linux_tid)
                        .map_err(|error| {
                            RuntimeError::Configuration(format!(
                                "resume from job control stop lost Kernel context: {error}"
                            ))
                        })?,
                };
                self.state.service_kernel_context = Some(context.retain_exact());
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    None,
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::RetryProcessFork {
                frame,
                request,
                coordinator,
                external_exec,
                deferred_resume_blocked,
                _subscription,
            } => {
                drop(_subscription);
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent fork retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let prepared = self.state.prepare_in_process_fork(
                    &self.kernel,
                    &context,
                    engine,
                    control,
                    &mut ProductionHvpatchProcessBackendOps,
                    quiesce::ProcessForkAttempt {
                        request,
                        coordinator,
                        external_exec,
                    },
                )?;
                return Ok(self.complete_persistent_process_fork(
                    engine,
                    control,
                    frame,
                    deferred_resume_blocked,
                    prepared,
                )?);
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::RetryCloneThread {
                frame,
                request,
                prepared,
                _subscription,
            } => {
                drop(_subscription);
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent clone retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                return match self.spawn_persistent_hvpatch_clone_thread(
                    engine,
                    control,
                    &context,
                    request,
                    prepared,
                    &mut ProductionHvpatchCloneBackendOps,
                )? {
                    PersistentHvpatchCloneAttempt::Complete(spawned) => {
                        Ok(self.complete_persistent_hvpatch_clone(engine, spawned)?)
                    }
                    PersistentHvpatchCloneAttempt::Wait {
                        prepared,
                        subscription,
                    } => {
                        self.phase = HvpatchProductionPhase::RetryCloneThread {
                            frame,
                            request,
                            prepared,
                            _subscription: subscription,
                        };
                        Ok(self.suspend(
                            HvpatchLoopSuspension::BlockedContinuation,
                            executor::ExecutorExit::Blocked(
                                crate::kernel::objects::BlockedReason::HostWait,
                            ),
                        ))
                    }
                };
            }
            HvpatchProductionPhase::RetryThreadExit { code } => {
                // Drop the reservation subscription for this attempt; a
                // fresh one is installed if the retry parks again.
                self.state.thread_exit_retry_subscription = None;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent thread-exit retry lost exact Kernel context".to_owned(),
                        )
                    })?
                    .retain_exact();
                let disposition = self.state.handle_persistent_thread_exit(
                    &self.kernel,
                    engine,
                    code,
                    self.traps,
                );
                return Ok(self.settle_persistent_thread_exit(engine, code, context, disposition));
            }
            HvpatchProductionPhase::ResumeBlocked {
                frame,
                vfork_child_pid,
            } => {
                let resumed = self.state.resume_persistent_continuation(
                    &self.kernel,
                    engine,
                    control.execution_lease_mut().map_err(RuntimeError::Trap)?,
                )?;
                if vfork_child_pid.is_some()
                    && matches!(&resumed, Some(DispatchOutcome::Returned { .. }))
                {
                    let parent_context =
                        self.state.service_kernel_context.as_ref().ok_or_else(|| {
                            RuntimeError::Configuration(
                                "vfork parent identity restore lost Kernel context".to_owned(),
                            )
                        })?;
                    stamp_identity_page(engine, &self.kernel.dispatcher, parent_context).map_err(
                        |error| {
                            RuntimeError::Trap(TrapError::Hypervisor(format!(
                                "restore vfork parent identity page: {error}"
                            )))
                        },
                    )?;
                }
                let outcome = match (vfork_child_pid, resumed) {
                    (Some(child_pid), Some(DispatchOutcome::Returned { .. })) => {
                        DispatchOutcome::Returned {
                            value: i64::from(child_pid),
                        }
                    }
                    (Some(_), Some(DispatchOutcome::ThreadExit { code })) => {
                        DispatchOutcome::ThreadExit { code }
                    }
                    (Some(_), _) => {
                        return Err(RuntimeError::Configuration(
                            "vfork parent resumed without release completion".to_owned(),
                        )
                        .into());
                    }
                    (None, Some(outcome)) => outcome,
                    (None, None) => self
                        .state
                        .redispatch_threaded_syscall(&self.kernel, engine)?,
                };
                if self.kernel.dispatcher.take_signal_pump_request() {
                    self.kernel
                        .signal_pump
                        .start_signal_pump(&self.state.kicker, &self.state.platform_futex);
                }
                return self.service_outcome(engine, control, frame, outcome);
            }
            HvpatchProductionPhase::ExecSiblingDrain { context, owner } => {
                if !owner.is_ready() {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain { context, owner };
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::ExecSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ));
                }
                let finished = match self.state.finish_prepared_execve_drain(
                    &self.kernel,
                    engine,
                    &self.completion,
                    owner,
                ) {
                    Ok(finished) => finished,
                    Err(failure) => {
                        return Err(ProductionHvpatchPollError::from_exec_failure(failure));
                    }
                };
                return self.finish_exec_suffix(engine, control, finished);
            }
            HvpatchProductionPhase::TerminalProcessDrain {
                terminal,
                context,
                drain,
            } => {
                if !drain.is_ready() {
                    self.phase = HvpatchProductionPhase::TerminalProcessDrain {
                        terminal,
                        context,
                        drain,
                    };
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::TerminalSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ));
                }
                let completions = self
                    .state
                    .finish_persistent_sibling_drain(&self.completion)?;
                self.kernel
                    .process_physical_retirement
                    .publish(completions)?;
                return Ok(self.finalize_persistent_process_terminal(engine, context, terminal));
            }
            HvpatchProductionPhase::TerminalClaimRetry {
                terminal,
                context,
                _subscription,
            } => {
                drop(_subscription);
                return Ok(self.begin_persistent_process_terminal(engine, terminal, context));
            }
            HvpatchProductionPhase::TerminalRetireRetry {
                terminal,
                context,
                _subscription,
            } => {
                drop(_subscription);
                return Ok(self.finalize_persistent_process_terminal(engine, context, terminal));
            }
            HvpatchProductionPhase::Resident => {}
            HvpatchProductionPhase::Complete => return Ok(executor::ExecutorExit::Exited),
        }

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if self.control_quantum()?.is_some() {
            if let Some(work) = self.kernel.try_take_control_exec() {
                return Ok(self.begin_control_exec_fork(engine, control, work, None)?);
            }
            return Ok(self.finish_control_quantum(engine, control, None)?);
        }

        if let Some(exit) = self.suspend_for_process_quiesce(engine, control)? {
            return Ok(exit);
        }

        if let Some(exit) = self.suspend_for_job_control(engine, control)? {
            return Ok(exit);
        }

        if control.need_resched() {
            return Ok(self.suspend(
                HvpatchLoopSuspension::Preemption,
                executor::ExecutorExit::Preempted,
            ));
        }
        match self.step_trap_watchdog(Instant::elapsed, trap_watchdog_wall_window) {
            TrapWatchdog::KeepRunning | TrapWatchdog::ResetBudget => {}
            TrapWatchdog::Trip => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context on trap limit outcome assembly"))
                    .retain_exact();
                let outcome = VcpuLoopOutcome::TrapLimit(Box::new(assemble_run_result(
                    &self.kernel,
                    -1,
                    None,
                    self.state.max_traps,
                    true,
                )));
                return Ok(self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::from_outcome(outcome),
                    context,
                ));
            }
        }
        self.traps = self.traps.saturating_add(1);
        let pt_quiesce = self.kernel.pt_quiesce();
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let entered_guest = quiesce::enter_hvpatch_guest_or_service_invalidation(
            &self.state.in_guest,
            &pt_quiesce,
            self.state.this_tid,
            engine,
            control,
        )?;
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let entered_guest = quiesce::enter_guest_or_park(&self.state.in_guest, &pt_quiesce);
        if !entered_guest {
            return Ok(executor::ExecutorExit::Syscall);
        }
        self.state
            .publish_thread_run_state(crate::run_state::RunState::Running, 'R');
        if let Some(thread) = self.state.kernel_thread.as_ref() {
            thread.begin_guest_run();
        }
        let next = engine.next_syscall();
        if let Some(thread) = self.state.kernel_thread.as_ref() {
            thread.charge_user_ns(engine.take_guest_run_receipt_ns());
        }
        self.state.in_guest.leave_guest();
        // Every guest boundary that is NOT a syscall arrives here: a forced exit
        // with no pending syscall, a stage-1 COW fault, and — the one that
        // matters most — a synchronous EL0 fault. This handling used to live
        // ONLY in the welded `run_vcpu_until_exit_inner`, which
        // `launch_vcpu_until_exit` made unreachable at its first statement, so
        // the persistent executor turned every guest fault into a runtime error
        // and killed the process instead of delivering SIGSEGV/SIGBUS/SIGTRAP.
        // `ExecutorExit::Syscall` is this loop's "poll me again", i.e. the
        // welded loop's `continue`.
        let frame = match next {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                // The vCPU was forced out of the guest by a cross-thread kick
                // (hv_vcpus_exit) with no syscall pending — deliver a signal at
                // the interrupted PC, then resume.
                let pc = engine.current_pc()?;
                let signal_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture forced-exit signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = service_signals_threaded(
                    &self.kernel,
                    &signal_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    None,
                    Some(pc),
                    None,
                    None,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                if let Some(exit) = self.suspend_for_process_quiesce(engine, control)? {
                    return Ok(exit);
                }
                if let Some(exit) = self.suspend_for_job_control(engine, control)? {
                    return Ok(exit);
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(TrapError::Stage1CowFault {
                syndrome,
                far,
                elr,
                spsr,
            }) => {
                // The engine's single COW resolver emits the exact TTBR +
                // descriptor pair immediately before its typed trigger. Do not
                // duplicate that pair here: the structural consumer joins and
                // consumes one sequence per attempted fault.
                if let carrick_hal::CowFaultResolution::Resolved { translation } =
                    engine.resolve_frame_cow_fault(syndrome, far)?
                {
                    self.state.note_cow_resolution(far, syndrome, translation)?;
                    return Ok(executor::ExecutorExit::Syscall);
                }
                return Err(RuntimeError::Trap(TrapError::GuestAtEl1 {
                    esr_el1: syndrome,
                    elr_el1: elr,
                    far_el1: far,
                    spsr_el1: spsr,
                })
                .into());
            }
            Err(TrapError::EL0Fault {
                syndrome,
                elr,
                far,
                from_el0_direct,
                ..
            }) => {
                if let carrick_hal::CowFaultResolution::Resolved { translation } =
                    engine.resolve_frame_cow_fault(syndrome, far)?
                {
                    self.state.note_cow_resolution(far, syndrome, translation)?;
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // The fault probes are load-bearing instruments, not debug
                // spam: `carrick trace` profiles and `scripts/dtrace/*.d` join
                // on them, and a probe that never fires reads as "the fault did
                // not happen". They were part of this handling before it was
                // ported off the welded loop and stay part of it.
                // Both probes take their arguments LAZILY: the instruction
                // fetch (a guest read, two heap allocations) and the register
                // reads run only when a D script is attached. This branch is
                // taken on every data abort, so eager decoding here was a
                // per-fault allocation on the happy path.
                crate::probes::vcpu_fault_regs_with(|| {
                    let instruction = engine
                        .read_bytes(elr, 4)
                        .ok()
                        .and_then(|bytes| bytes.try_into().ok())
                        .map(u32::from_le_bytes);
                    let (base_register, base_value) = instruction.map_or((u32::MAX, 0), |word| {
                        let index = (word >> 5) & 0x1f;
                        let value = (index < 31)
                            .then(|| engine.get_reg(carrick_hal::Reg::X(index)).ok())
                            .flatten()
                            .unwrap_or(0);
                        (index, value)
                    });
                    (
                        syndrome,
                        elr,
                        far,
                        instruction.map_or(u64::MAX, u64::from),
                        base_register,
                        base_value,
                    )
                });
                crate::probes::vcpu_fault_gprs_with(|| {
                    let x = |n: u32| engine.get_reg(carrick_hal::Reg::X(n)).unwrap_or(0);
                    (x(0), x(1), x(2), x(3), x(4), x(5))
                });
                // Same lazy-argument contract as the two probes above, and for
                // the same reason: the stage-1 walk is a `TTBR0_EL1` sysreg
                // read, a backend lookup for the table root and four
                // descriptor reads, and it was running on EVERY data abort to
                // feed two probes that are a no-op with no D script attached.
                crate::probes::pt_fault_with(far, || engine.diagnostic_fault_page_tables(far));
                if let Some(process) = self.kernel.hvpatch_process.as_ref() {
                    process.trace_fault(syndrome, elr, far, self.state.this_tid);
                }
                // A synchronous guest EL0 fault (nil deref, bad access, BRK,
                // single-step). Lower the raw aarch64 ESR to the ISA-neutral
                // (signum, si_code, fault_addr) triple — covering BOTH the abort
                // classes (SIGSEGV/SIGBUS) AND the debug classes (BRK /
                // single-step → SIGTRAP) — then deliver via the shared
                // GuestFault path. `from_el0_direct` selects whether the sigframe
                // records the faulting PC as the resume target.
                let Some((signum, si_code, si_addr)) = lower_el0_fault(syndrome, elr, far) else {
                    // Unclassified EL0 fault: Linux forces the default action
                    // (terminate by SIGSEGV).
                    self.kernel.record_fatal_signal(FatalSignalRecord {
                        image_generation: self.state.fatal_image_generation,
                        tid: self.state.linux_tid,
                        signo: crate::linux_abi::LINUX_SIGSEGV,
                        code: 0,
                        addr: far,
                    });
                    let result = assemble_run_result(
                        &self.kernel,
                        128 + 11,
                        Some(crate::linux_abi::LINUX_SIGSEGV),
                        self.traps,
                        false,
                    );
                    return Ok(self.enter_terminal_with_outcome(
                        engine,
                        VcpuLoopOutcome::ProcessExit(Box::new(result)),
                    ));
                };
                // Raw hardware/host faults can decode as MAPERR even when
                // Carrick tracks a live VMA denying the access. Upgrade from the
                // shared protection metadata (LTP mmap05 / roprotect probe).
                let si_code =
                    signal::upgrade_protection_si_code(&*engine, signum, si_code, si_addr);
                let interrupted_pc = from_el0_direct.then_some(elr);
                let faulting_tid = self.state.linux_tid;
                if self.kernel.dispatcher.fault_requires_mm_mutation(si_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                si_addr,
                                signal::el0_fault_access(syndrome),
                                faulting_tid,
                                mutation,
                            )
                        })?
                        .map_err(RuntimeError::Trap)?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // Captured only now: a first touch resolved above never
                // delivers a signal, and this capture is an `RwLock` read plus
                // a kernel-graph snapshot that only `deliver_fault_signal`
                // consumes. Hoisting it out of the resolved path takes it off
                // the hot arm of every anonymous first-touch fault.
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture synchronous-fault signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = deliver_fault_signal(
                    &self.kernel,
                    &fault_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    signum,
                    si_code,
                    si_addr,
                    interrupted_pc,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(TrapError::GuestFault {
                signum,
                si_code,
                fault_addr,
            }) => {
                // The ISA-neutral structured fault path: an x86 backend emits
                // this directly (fault_addr = CR2). The backend restores the
                // interrupted user context before surfacing the fault, so the
                // live PC is the faulting instruction.
                let si_code =
                    signal::upgrade_protection_si_code(&*engine, signum, si_code, fault_addr);
                let interrupted_pc = Some(engine.current_pc()?);
                let faulting_tid = self.state.linux_tid;
                if self
                    .kernel
                    .dispatcher
                    .fault_requires_mm_mutation(fault_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            // The ISA-neutral triple carries no syndrome, so
                            // the access class is unknown here: a stale fault
                            // on this arm is delivered rather than retried.
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                fault_addr,
                                None,
                                faulting_tid,
                                mutation,
                            )
                        })?
                        .map_err(RuntimeError::Trap)?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
                // Same hoist as the aarch64 arm above: only the delivered
                // path needs the captured kernel context.
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture guest-fault signal context: {error}"
                        ))
                    })?;
                if let Some(outcome) = deliver_fault_signal(
                    &self.kernel,
                    &fault_context,
                    engine,
                    self.state.this_tid,
                    self.state.fatal_image_generation,
                    signum,
                    si_code,
                    fault_addr,
                    interrupted_pc,
                    self.traps,
                )? {
                    return Ok(self.enter_terminal_with_outcome(engine, outcome));
                }
                return Ok(executor::ExecutorExit::Syscall);
            }
            Err(error) => return Err(RuntimeError::Trap(error).into()),
        };
        self.state.trace_syscall(self.traps, frame);
        let outcome = self
            .state
            .service_threaded_syscall(&self.kernel, engine, frame)?;
        if self.kernel.dispatcher.take_signal_pump_request() {
            self.kernel
                .signal_pump
                .start_signal_pump(&self.state.kicker, &self.state.platform_futex);
        }
        self.service_outcome(engine, control, frame, outcome)
    }

    fn poll_with_engine_typed(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, ProductionHvpatchPollError> {
        let _current_mm =
            carrick_thread::fork_quiesce::bind_current_mm_quiesce(self.kernel.pt_quiesce());
        match self.poll_with_engine(engine, control) {
            Err(ProductionHvpatchPollError::Runtime(error)) => {
                match self.take_pending_exec_terminal() {
                    Some(pending) => Err(ProductionHvpatchPollError::Exec(Box::new(
                        PendingExecTerminalError { error, pending },
                    ))),
                    None => Err(ProductionHvpatchPollError::Runtime(error)),
                }
            }
            result => result,
        }
    }

    /// Extract a suspended exec's exact context and terminal authority without
    /// reopening clone admission. This is the sole error-boundary extraction
    /// for failures before the main phase dispatch (control lookup,
    /// exact-context recovery, or vCPU/MM re-admission).
    fn take_pending_exec_terminal(&mut self) -> Option<PendingExecTerminal> {
        let phase = std::mem::replace(&mut self.phase, HvpatchProductionPhase::Resident);
        match phase {
            HvpatchProductionPhase::ExecSiblingDrain { context, owner } => {
                let (terminal_context, handoff) = owner.into_terminal_authority();
                drop(context);
                Some(PendingExecTerminal {
                    context: terminal_context,
                    handoff,
                })
            }
            other => {
                self.phase = other;
                None
            }
        }
    }
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll for ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    fn pt_quiesce(&self) -> Arc<crate::fork_quiesce::PtQuiesce> {
        self.kernel.pt_quiesce()
    }

    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(engine) = engine.downcast_mut::<E>() else {
            return executor::ExecutorExit::InvalidState;
        };
        match self.poll_with_engine_typed(engine, control) {
            Ok(exit) => exit,
            Err(ProductionHvpatchPollError::Exec(pending)) => {
                let PendingExecTerminalError { error, pending } = *pending;
                self.begin_persistent_process_terminal_from_exec(
                    engine,
                    PersistentTerminal::Error(error),
                    pending,
                )
            }
            Err(ProductionHvpatchPollError::Runtime(error)) => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| carrick_fatal!("vcpu_loop::service_context", "ThreadRuntimeState missing service_kernel_context on engine error terminal transition"))
                    .retain_exact();
                self.begin_persistent_process_terminal(
                    engine,
                    PersistentTerminal::Error(error),
                    context,
                )
            }
        }
    }

    fn after_terminal_settlement(&mut self) {
        self.publish_terminal_result();
    }

    fn after_reaped_settlement(&mut self) {
        // Same publication the lost-process-exit-claim path makes, for the
        // same reason: this thread is terminated and carries no outcome of its
        // own, so the `ThreadDone` its owner's member drain would have
        // published is published from the settlement that owns it. Without
        // this the job's `HvpatchLoopResult` was never filled and its
        // container process job waited on it forever (`go_types`).
        self.publish_lost_claim_terminal_result();
    }

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement {
        if self.terminal_settlement.is_published() {
            return continuation::ExecutorFailureSettlement::AlreadyPublished;
        }
        if self.terminal_result.is_some() {
            self.publish_terminal_result();
            return continuation::ExecutorFailureSettlement::PublishCurrent;
        }

        let receipt = match self.take_pending_exec_terminal() {
            Some(PendingExecTerminal { context, handoff }) => {
                let receipt = handoff.claim_process_exit().unwrap_or_else(|failure| {
                    tracing::error!(%failure, "claim unexpected executor-failure exec handoff");
                    carrick_fatal!(
                        "hvpatch::exec_terminal",
                        "claim unexpected executor-failure exec handoff failed: {failure}"
                    );
                });
                self.state.service_kernel_context = Some(context.retain_exact());
                self.state.kernel_thread = Some(Arc::clone(context.thread()));
                if receipt.claim == ProcessExitClaim::Owner {
                    self.kernel.begin_process_exit();
                }
                receipt
            }
            None => self
                .kernel
                .try_claim_persistent_process_exit(self.state.this_tid)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "claim unexpected executor-failure process exit");
                    carrick_fatal!(
                        "kernel::terminal_settlement",
                        "claim unexpected executor-failure process exit failed: {failure}"
                    );
                }),
        };
        match receipt.claim {
            ProcessExitClaim::LostToExec | ProcessExitClaim::AlreadyOwned => {
                // Losing the claim used to defer publication to the process
                // terminal owner. That owner only ever publishes the members
                // its drain snapshot holds, and an `execve` survivor is removed
                // from the member list by `finish_persistent_process_handles`
                // and never re-enrolled -- so a lost-claim survivor's result was
                // published by nobody. Its container process job then waited on
                // an `HvpatchLoopResult` forever, with every Kernel task retired
                // and every executor idle (the `go build` / `go_types` exit
                // wedge). The outcome is not in doubt here: another thread owns
                // the process exit, so Linux has terminated this one, which is
                // exactly the `ThreadDone` the owner's member drain would have
                // published. Publish it from the settlement that owns it.
                self.publish_lost_claim_terminal_result();
                return continuation::ExecutorFailureSettlement::PublishCurrent;
            }
            ProcessExitClaim::Owner | ProcessExitClaim::Pending => {}
        }

        if receipt.claim == ProcessExitClaim::Pending {
            // The failed worker cannot block on a clone permit held by another
            // executor. Arm the fail-closed root wait first, stop every known
            // sibling, then let a failure-only coordinator publish the exact
            // member snapshot after clone admission reaches zero.
            self.kernel.begin_process_exit();
        }
        let sibling_stop = self
            .state
            .persistent_sibling_stop_authority()
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "retain unexpected executor-failure sibling stop");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "retain unexpected executor-failure sibling stop failed: {failure}"
                );
            });
        sibling_stop
            .publish(&self.kernel)
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "stop siblings after unexpected executor failure");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "stop siblings after unexpected executor failure failed: {failure}"
                );
            });

        if receipt.claim == ProcessExitClaim::Owner {
            publish_unexpected_executor_failure_retirement(
                &self.kernel,
                &self.state.threads,
                &self.completion,
            )
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "publish unexpected executor-failure retirement");
                carrick_fatal!(
                    "kernel::terminal_settlement",
                    "publish unexpected executor-failure retirement failed: {failure}"
                );
            });
        } else {
            let kernel = Arc::clone(&self.kernel);
            let threads = self.state.threads.clone();
            let current = self.completion.clone();
            let owner = self.state.this_tid;
            if let Err(failure) = std::thread::Builder::new()
                .name("carrick-exit-failure-drain".to_owned())
                .spawn(move || {
                    if let Err(failure) = kernel
                        .clone_admission
                        .wait_for_claimed_process_exit_clone_drain(
                            owner,
                            PHYSICAL_JOB_RETIREMENT_TIMEOUT,
                        )
                        .and_then(|()| sibling_stop.publish(&kernel))
                        .and_then(|()| {
                            publish_unexpected_executor_failure_retirement(
                                &kernel, &threads, &current,
                            )
                        })
                    {
                        // `begin_process_exit` already armed the root's bounded
                        // publication wait. Leaving the receipt absent is the
                        // fail-closed outcome; never synthesize an incomplete
                        // member list after a clone-drain failure.
                        tracing::error!(%failure, "unexpected executor-failure retirement coordinator failed");
                    }
                })
            {
                tracing::error!(%failure, "spawn unexpected executor-failure retirement coordinator");
            }
        }

        self.publish_terminal_result();
        continuation::ExecutorFailureSettlement::PublishCurrent
    }

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.pending_terminal_retirement.take()
    }

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        let (kernel, mm) = self.take_terminal_inventory_authority()?;
        kernel
            .frame_inventory()
            .apply(mm, commit)
            .map(|_| ())
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "publish detached terminal inventory retirement: {error}"
                ))
            })
    }

    /// The same publication, but returning the authenticated receipt a published
    /// `HvpatchTaskMmAuthority` needs to leave its `Active` phase.
    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError> {
        let (kernel, mm) = self.take_terminal_inventory_authority()?;
        kernel
            .frame_inventory()
            .apply_retirement_with_receipt(mm, commit)
            .map(|(_, receipt)| receipt)
            .map_err(|error| {
                TrapError::Hypervisor(format!(
                    "publish detached terminal inventory retirement receipt: {error}"
                ))
            })
    }
}

/// Engine-free logical state for the HVPatch vCPU loop.  The backend engine is
/// lent to `poll_quantum_with_engine` by its persistent owner pthread and is
/// never stored here.  Production logical/runtime fields are moved into this
/// object as the seven async suspension arms are lowered to the typed states
/// above.
pub(crate) struct HvpatchLoopJob<E> {
    suspended: Option<HvpatchLoopSuspension>,
    injected_lease: Option<Arc<InjectedExecutionLeaseSlot>>,
    production: Option<Box<dyn ProductionHvpatchLoopPoll>>,
    poller: fn(
        &mut HvpatchLoopJob<E>,
        &mut E,
        &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit,
    #[cfg(test)]
    scripted: std::collections::VecDeque<HvpatchLoopSuspension>,
    #[cfg(test)]
    resumed: Vec<HvpatchLoopSuspension>,
    _marker: std::marker::PhantomData<fn(&mut E)>,
}

#[cfg(test)]
pub(crate) trait ScriptedHvpatchLoopEngine {
    fn record_injected_resume(&mut self, resumed: &[HvpatchLoopSuspension]);
}

#[cfg(test)]
impl<E: ScriptedHvpatchLoopEngine> HvpatchLoopJob<E> {
    fn scripted_for_test(boundaries: impl IntoIterator<Item = HvpatchLoopSuspension>) -> Self {
        Self {
            suspended: None,
            injected_lease: None,
            production: None,
            poller: Self::poll_scripted_for_test,
            scripted: boundaries.into_iter().collect(),
            resumed: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    fn poll_scripted_for_test(
        job: &mut Self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let need_resched = control.need_resched();
        match job.poll_quantum_with_engine(engine, need_resched) {
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::BlockedContinuation) => {
                executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::HostWait)
            }
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::SchedulerYield) => {
                executor::ExecutorExit::Yielded
            }
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::Preemption) => {
                executor::ExecutorExit::Preempted
            }
            HvpatchLoopPoll::Suspended(
                HvpatchLoopSuspension::ExecSiblingDrain
                | HvpatchLoopSuspension::VforkParent
                | HvpatchLoopSuspension::TerminalSiblingDrain,
            ) => executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState),
            HvpatchLoopPoll::Suspended(HvpatchLoopSuspension::InitialAdmission) => {
                executor::ExecutorExit::Quiesced
            }
            HvpatchLoopPoll::Exited => executor::ExecutorExit::Exited,
        }
    }

    fn poll_quantum_with_engine(&mut self, engine: &mut E, _need_resched: bool) -> HvpatchLoopPoll {
        let Some(boundary) = self.scripted.pop_front() else {
            self.suspended = None;
            engine.record_injected_resume(&self.resumed);
            return HvpatchLoopPoll::Exited;
        };
        self.resumed.push(boundary);
        engine.record_injected_resume(&self.resumed);
        self.suspended = Some(boundary);
        HvpatchLoopPoll::Suspended(boundary)
    }

    const fn suspended_at(&self) -> Option<HvpatchLoopSuspension> {
        self.suspended
    }
}

impl<E: 'static> HvpatchLoopJob<E> {
    fn production(
        job: ProductionHvpatchLoopJob<E>,
        injected_lease: Arc<InjectedExecutionLeaseSlot>,
    ) -> Self
    where
        E: ThreadedEngine,
        E::SiblingSpec: 'static,
    {
        Self {
            suspended: Some(HvpatchLoopSuspension::InitialAdmission),
            injected_lease: Some(injected_lease),
            production: Some(Box::new(job)),
            poller: Self::poll_production,
            #[cfg(test)]
            scripted: std::collections::VecDeque::new(),
            #[cfg(test)]
            resumed: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    fn poll_production(
        job: &mut Self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(production) = job.production.as_mut() else {
            return executor::ExecutorExit::InvalidState;
        };
        let _current_mm =
            carrick_thread::fork_quiesce::bind_current_mm_quiesce(production.pt_quiesce());
        let exit = production.poll(engine, control);
        job.suspended = match exit {
            executor::ExecutorExit::BlockedContinuation { .. }
            | executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::HostWait) => {
                Some(HvpatchLoopSuspension::BlockedContinuation)
            }
            executor::ExecutorExit::Blocked(crate::kernel::objects::BlockedReason::ChildState) => {
                match job.suspended {
                    Some(HvpatchLoopSuspension::ExecSiblingDrain) => {
                        Some(HvpatchLoopSuspension::ExecSiblingDrain)
                    }
                    Some(HvpatchLoopSuspension::VforkParent) => {
                        Some(HvpatchLoopSuspension::VforkParent)
                    }
                    _ => Some(HvpatchLoopSuspension::TerminalSiblingDrain),
                }
            }
            executor::ExecutorExit::Yielded => Some(HvpatchLoopSuspension::SchedulerYield),
            executor::ExecutorExit::Preempted => Some(HvpatchLoopSuspension::Preemption),
            executor::ExecutorExit::Exited | executor::ExecutorExit::InvalidState => None,
            _ => None,
        };
        exit
    }
}

impl<E: 'static> continuation::PersistentQuantumJob for HvpatchLoopJob<E> {
    fn poll_quantum_with_engine(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(engine) = engine.downcast_mut::<E>() else {
            return executor::ExecutorExit::InvalidState;
        };
        let lease_slot = control.execution_lease_slot_mut() as *mut _;
        let injected_lease = self.injected_lease.clone();
        let _lease_publication = injected_lease.as_ref().map(|slot| slot.install(lease_slot));
        (self.poller)(self, engine, control)
    }

    fn after_terminal_settlement(&mut self) {
        if let Some(production) = self.production.as_mut() {
            production.after_terminal_settlement();
        }
    }

    fn after_reaped_settlement(&mut self) {
        if let Some(production) = self.production.as_mut() {
            production.after_reaped_settlement();
        }
    }

    fn after_executor_failure_settlement(&mut self) -> continuation::ExecutorFailureSettlement {
        match self.production.as_mut() {
            Some(production) => production.after_executor_failure_settlement(),
            None => continuation::ExecutorFailureSettlement::PublishCurrent,
        }
    }

    fn take_address_space_retirement(
        &mut self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.production
            .as_mut()
            .and_then(|production| production.take_address_space_retirement())
    }

    fn apply_detached_address_space_retirement(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), TrapError> {
        self.production
            .as_mut()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "scripted HVPatch job has no detached address-space authority".to_owned(),
                )
            })?
            .apply_detached_address_space_retirement(commit)
    }

    fn apply_detached_address_space_retirement_with_receipt(
        &mut self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<carrick_hal::FrameInventoryRetirementReceipt, TrapError> {
        self.production
            .as_mut()
            .ok_or_else(|| {
                TrapError::Hypervisor(
                    "scripted HVPatch job has no detached address-space authority".to_owned(),
                )
            })?
            .apply_detached_address_space_retirement_with_receipt(commit)
    }
}

/// RAII-timed completion record for Linux syscalls multiplexed inside the
/// one-VM hvpatch host process. Keeping publication in `Drop` covers every
/// returned, blocking, fork/exec, exit, and error path that unwinds normally,
/// without changing control flow. A terminal `_exit` cannot run destructors and
/// is intentionally absent from the completed population.
struct HvpatchSyscallServiceGuard {
    pid: i32,
    tid: i32,
    asid: u32,
    number: u64,
    started: std::time::Instant,
}

impl HvpatchSyscallServiceGuard {
    fn begin(pid: i32, tid: i32, asid: u32, number: u64, args: [u64; 6]) -> Option<Self> {
        // The wrapper materializes the clock only inside the USDT enabled
        // closure. With no consumer this returns `None`, preserving the probe
        // surface's predicted-not-taken-branch cost contract.
        let event =
            carrick_observability::probes::HvpatchSyscallService::new(pid, tid, asid, number, 0)
                .ok()?;
        let started = crate::probes::hvpatch_syscall_service_begin(event, args)?;
        Some(Self {
            pid,
            tid,
            asid,
            number,
            started,
        })
    }
}

impl Drop for HvpatchSyscallServiceGuard {
    fn drop(&mut self) {
        use carrick_observability::probes::HvpatchSyscallService;

        let duration_ns = u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        if let Ok(event) =
            HvpatchSyscallService::new(self.pid, self.tid, self.asid, self.number, duration_ns)
        {
            crate::probes::hvpatch_syscall_service(event);
            crate::probes::hvpatch_syscall_service_clear(event);
        }
    }
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
    fn note_cow_resolution(
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

    fn trace_syscall(&self, traps: usize, frame: carrick_hal::RawSyscall) {
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

    fn trace_hvpatch_thread_terminal(
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
    fn trace_syscall_return(&self, traps: usize, ret: Option<i64>) {
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

    fn persistent_block_exit(
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

    fn resume_persistent_continuation(
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
                                        self.this_tid,
                                        &self.registry,
                                        &self.futex,
                                        &mut mutation,
                                        lease,
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
                                        self.this_tid,
                                        &self.registry,
                                        &self.futex,
                                        &mut mutation,
                                        lease,
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
                                mm_executor,
                                &kernel_context,
                                syscall,
                                engine,
                                &kernel.reporter,
                                self.this_tid,
                                &self.registry,
                                &self.futex,
                                lease,
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
                        let topology = crate::fork_quiesce::acquire_topology_lock(
                            carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
                            process.pid(),
                            self.this_tid.raw(),
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
                            drop(topology);
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
                        // releasing the topology lock. Staging above made a fresh
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
                        // lock across the apply makes publication order equal to
                        // staging order, which is the invariant the registry
                        // reuse relies on. Lock order is unchanged: the AliasUnmap
                        // retirement already publishes under this lock, and the
                        // authority mutex is a leaf (`frame_inventory.rs` never
                        // calls out while holding it).
                        let published = apply_alias_frame_inventory(&kernel_context, commit);
                        drop(topology);
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

/// Wall-clock budget for the trap watchdog: a guest that keeps trapping but makes
/// NO signal-handler progress for this long is treated as genuinely wedged. The
/// default (30s) is comfortably above any legitimate syscall-bound burst (e.g. a
/// 10s SIGALRM-bounded `gettimeofday` loop) yet below the conformance harness's
/// outer per-run timeout (~40s), so a real wedge aborts cleanly here rather than
/// via the harness SIGKILL. Override with `CARRICK_MAX_WALL_MS`.
fn trap_watchdog_wall_window() -> std::time::Duration {
    // Read once: this sits on the watchdog checkpoint that every trap
    // quantum passes through, and a `getenv` per checkpoint was measurable
    // (0.6% of the arena-churn profile) for a value that never changes.
    static WINDOW: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *WINDOW.get_or_init(|| {
        let ms = std::env::var("CARRICK_MAX_WALL_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30_000);
        std::time::Duration::from_millis(ms)
    })
}

/// One progress-aware trap-watchdog checkpoint decision.
#[derive(Debug, PartialEq, Eq)]
enum TrapWatchdog {
    /// Under the count pre-filter — keep running (the cheap hot-path case).
    KeepRunning,
    /// Over the count pre-filter, but the guest made wall-clock progress within
    /// `max_wall` (a syscall-bound-but-progressing loop) — reset the count budget
    /// and keep running, do NOT abort.
    ResetBudget,
    /// Over the count pre-filter AND no signal-handler progress for `max_wall`
    /// (a genuine wedge) — abort the vCPU loop.
    Trip,
}

pub(crate) enum VcpuLoopLaunch {
    Direct(Result<VcpuLoopOutcome, RuntimeError>),
    Persistent {
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
        process_retirement: ProcessPhysicalRetirement,
        /// The always-on runner invariant, carried so the CONTAINER ROOT's own
        /// wait is supervised too. The exit wedge parked here as readily as in
        /// `ContainerJobGroup::join`: this is the main thread's wait for the
        /// root process job, and an unsupervised wait here would leave the
        /// wedge in place for exactly the run every other lane goes through.
        liveness: ProcessGraphLiveness,
    },
}

impl VcpuLoopLaunch {
    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }

    /// Wait for this container root's main-thread job. Carrier-global pool
    /// shutdown belongs exclusively to the carrier terminal finalizer.
    pub(crate) fn wait(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        match self {
            Self::Direct(result) => result,
            Self::Persistent {
                result,
                completion,
                process_retirement,
                liveness,
            } => {
                let outcome = result.wait_supervised(&liveness);
                // An aborted kernel's executor bindings are not going to
                // retire: the abort exists precisely because the graph will
                // not progress, and its guest threads are still loaded. Waiting
                // for retirement here reported "logical HVPatch job N published
                // before its executor binding retired" and MASKED the abort,
                // turning the one answer the caller needs into a generic
                // carrier failure.
                if matches!(outcome, Err(RuntimeError::KernelAborted { .. })) {
                    return outcome;
                }
                wait_for_physical_job_retirement(&completion)?;
                match &outcome {
                    Ok(_) => process_retirement.wait()?,
                    Err(_) => process_retirement.wait_if_exit_started_or_published()?,
                }
                tracing::info!(
                    outcome = match &outcome {
                        Ok(VcpuLoopOutcome::ProcessExit(_)) => "process-exit",
                        Ok(VcpuLoopOutcome::ThreadDone) => "thread-done",
                        Ok(_) => "other-ok",
                        Err(_) => "error",
                    },
                    "HVPatch root launch wait returned"
                );
                outcome
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PreparedHvpatchLogicalJob {
    binding: Arc<continuation::HvpatchTaskBinding>,
    result: HvpatchLoopResult,
    completion: continuation::LogicalJobCompletion,
    process_retirement: ProcessPhysicalRetirement,
    terminal_settlement: HvpatchExternalTerminalSettlement,
    context: crate::kernel::KernelContext,
    cpu: crate::kernel::objects::MigratableTaskState,
    generation: crate::kernel::objects::ExecutionGeneration,
    start_gate: Option<crate::kernel::objects::OpenedStartGate>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl PreparedHvpatchLogicalJob {
    fn install_start_gate(
        &mut self,
        start_gate: crate::kernel::objects::OpenedStartGate,
    ) -> Result<(), TrapError> {
        if self.start_gate.replace(start_gate).is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch logical job received duplicate start-gate proof".to_owned(),
            ));
        }
        Ok(())
    }

    fn activation_proof(&mut self) -> Result<executor::HvpatchActivationProof, TrapError> {
        let start_gate = self.start_gate.take().ok_or_else(|| {
            TrapError::Hypervisor("HVPatch start-gate proof was already consumed".to_owned())
        })?;
        executor::HvpatchActivationProof::validate(
            &self.context,
            &self.cpu,
            self.generation,
            self.binding.identity(),
            start_gate,
        )
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvpatchLogicalJobInput<E: ThreadedEngine> {
    kernel: Kernel,
    state: ThreadRuntimeState<E>,
    task_backend: executor::HvpatchTaskEngineBindingState,
    context: crate::kernel::KernelContext,
    cpu: crate::kernel::objects::MigratableTaskState,
    generation: crate::kernel::objects::ExecutionGeneration,
    injected_lease: Arc<InjectedExecutionLeaseSlot>,
    bootstrap_process_child: Option<ProcessChildBootstrap>,
    bootstrap_thread_child: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepare_hvpatch_logical_job<E: ThreadedEngine + 'static>(
    input: HvpatchLogicalJobInput<E>,
) -> Result<PreparedHvpatchLogicalJob, TrapError>
where
    E::SiblingSpec: 'static,
{
    let HvpatchLogicalJobInput {
        kernel,
        state,
        task_backend,
        context,
        cpu,
        generation,
        injected_lease,
        bootstrap_process_child,
        bootstrap_thread_child,
    } = input;
    if context.thread().key()
        != state
            .kernel_thread
            .as_ref()
            .ok_or_else(|| {
                TrapError::Hypervisor("prepared HVPatch job has no exact Kernel thread".to_owned())
            })?
            .key()
        || context.shared().mm().id() != cpu.mm
    {
        return Err(TrapError::Hypervisor(
            "prepared HVPatch logical job rejected Kernel/CPU/MM identity".to_owned(),
        ));
    }
    let result = HvpatchLoopResult::pending();
    let completion = continuation::LogicalJobCompletion::pending();
    let terminal_settlement =
        HvpatchExternalTerminalSettlement::new(result.clone(), completion.clone());
    let process_retirement = kernel.process_physical_retirement.clone();
    let identity = executor::TaskLoadIdentity {
        abi: cpu.cpu.guest_abi(),
        version: cpu.cpu.version(),
        mm: cpu.mm,
        asid_generation: cpu.asid_generation,
    };
    let process = kernel
        .hvpatch_process
        .as_ref()
        .ok_or_else(|| TrapError::Hypervisor("HVPatch logical job has no process MM".to_owned()))?;
    let stage1_mm = process
        .stage1_mm_lease()
        .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
    let production = ProductionHvpatchLoopJob {
        kernel,
        state,
        phase: if bootstrap_thread_child {
            HvpatchProductionPhase::BootstrapThreadChild
        } else {
            bootstrap_process_child.map_or(
                HvpatchProductionPhase::Resident,
                HvpatchProductionPhase::BootstrapProcessChild,
            )
        },
        registration_wait: None,
        terminal_settlement: terminal_settlement.clone(),
        terminal_result: None,
        completion: completion.clone(),
        traps: 0,
        budget_floor: 0,
        seen_signal_progress: signal_progress_count(),
        last_signal_progress: Instant::now(),
        terminal_runtime: PersistentTerminalRuntimeState::Resident,
        pending_terminal_retirement: None,
        pending_terminal_inventory: None,
        external_exec: None,
    };
    let job = HvpatchLoopJob::production(production, injected_lease);
    let quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
        Box::new(job),
        completion.clone(),
    ));
    let binding = Arc::new(continuation::HvpatchTaskBinding::new_with_stage1_mm(
        identity,
        quantum,
        Box::new(task_backend),
        stage1_mm,
    )?);
    Ok(PreparedHvpatchLogicalJob {
        binding,
        result,
        completion,
        process_retirement,
        terminal_settlement,
        context: context.retain_exact(),
        cpu,
        generation,
        start_gate: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn launch_persistent_hvpatch_job<E: ThreadedEngine + 'static>(
    kernel: Kernel,
    mut engine: E,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    platform_futex_factory: PlatformFutexFactory,
    linux_tid: crate::kernel::LinuxTid,
    this_tid: ThreadId,
    threads: impl Into<VcpuThreadRegistry>,
    kicker: Arc<dyn VcpuRegistry>,
    in_guest: carrick_hal::InGuestFlag,
    max_traps: usize,
) -> VcpuLoopLaunch
where
    E::SiblingSpec: 'static,
{
    let threads = threads.into();
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (
            kernel,
            engine,
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            linux_tid,
            this_tid,
            threads,
            kicker,
            in_guest,
            max_traps,
        );
        return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
            "HVPatch persistent executors require macOS/aarch64 HVF".to_owned(),
        )));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;

        let mut prepared = match prepare_initial_runner_handoff(
            &kernel,
            &mut engine,
            &kicker,
            linux_tid,
            this_tid,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return VcpuLoopLaunch::Direct(Err(error)),
        };
        let prepared_task = prepared.task.take().unwrap_or_else(|| {
            carrick_fatal!(
                "vcpu_loop::job_launch",
                "Prepared persistent job missing task context during job launch"
            )
        });
        let context = prepared_task.context;
        let exact_cpu = prepared_task.cpu;
        let start_gate = prepared_task.start_gate;
        let thread = Arc::clone(context.thread());

        // Initial-runner park has stopped/destroyed its vCPU. Only now may the
        // factory take the four owning carrier mappings: every failure below
        // can drop them without unmapping stage-2 under a live bootstrap vCPU.
        let authority = match (&mut engine as &mut dyn std::any::Any).downcast_mut::<HvfEngine>() {
            Some(engine) => {
                match carrick_vmm_hvf::hvf_aarch64_engine::persistent_executor_factory_authority(
                    engine,
                ) {
                    Ok(authority) => authority,
                    Err(error) => {
                        prepared.fail_exact();
                        return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
                    }
                }
            }
            None => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
                    "HVPatch launch rejected a non-HVF engine".to_owned(),
                )));
            }
        };

        let boxed: Box<dyn std::any::Any> = Box::new(engine);
        let hvf_engine = match boxed.downcast::<HvfEngine>() {
            Ok(engine) => *engine,
            Err(_) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(
                    "HVPatch engine changed type during persistent handoff".to_owned(),
                )));
            }
        };
        let (task_backend, parked_vcpu) =
            carrick_vmm_hvf::hvf_aarch64_engine::split_initial_task_engine(hvf_engine);
        drop(parked_vcpu);

        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let process_members = threads.clone();
        let mut state = ThreadRuntimeState::<HvfEngine>::new(
            registry,
            futex,
            platform_futex,
            platform_futex_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(&thread)),
            kernel.hvpatch_process.as_ref().map(|process| process.pid()),
            linux_tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            threads,
            kicker,
            in_guest,
            max_traps,
        );
        state.execution_lease = execution_lease;
        state.service_kernel_context = Some(context.retain_exact());

        let mut logical = match prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&kernel),
            state,
            task_backend: executor::HvpatchTaskEngineBindingState::initial(task_backend),
            context,
            cpu: exact_cpu,
            generation: prepared.generation,
            injected_lease,
            bootstrap_process_child: None,
            bootstrap_thread_child: false,
        }) {
            Ok(logical) => logical,
            Err(error) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        if let Err(error) = logical.install_start_gate(start_gate) {
            prepared.fail_exact();
            return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
        }
        let directory = kernel.hvpatch_runtime.as_ref().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::runtime_binding",
                "KernelState missing HVPatch runtime reference during persistent job launch"
            )
        });
        let dormant = match directory.persistent_bindings().prepare_submission(
            &prepared.scheduler,
            executor::HvpatchSubmissionShape::Root,
            None,
            Arc::clone(&thread),
            prepared.generation,
            Arc::clone(&logical.binding),
        ) {
            Ok(dormant) => dormant,
            Err(error) => {
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        let proof = match logical.activation_proof() {
            Ok(proof) => proof,
            Err(error) => {
                drop(dormant);
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
            }
        };
        let member_publication =
            PersistentProcessMemberPublication::new(process_members, &logical.terminal_settlement);
        let started_pool = match directory.start_persistent_pool(
            authority,
            <HvfEngine as ThreadedEngine>::vcpu_budget(),
            &PreparedPersistentServices {
                scheduler: Arc::clone(&prepared.scheduler),
                wait_service: Arc::clone(&prepared.wait_service),
            },
        ) {
            Ok(started) => started,
            Err(error) => {
                drop(dormant);
                prepared.fail_exact();
                return VcpuLoopLaunch::Direct(Err(error));
            }
        };
        if let Err(error) = dormant.activate(&prepared.scheduler, Arc::clone(&thread), proof) {
            // The job was never exposed. Remove its process-local drain handle
            // before closing a newly-created pool, or shutdown would wait on a
            // completion no scheduler row can ever publish.
            drop(member_publication);
            prepared.fail_exact();
            if started_pool && let Err(shutdown) = directory.shutdown_persistent_pool() {
                return VcpuLoopLaunch::Direct(Err(RuntimeError::Configuration(format!(
                    "HVPatch root activation failed: {error}; newly started pool rollback failed: {shutdown}"
                ))));
            }
            return VcpuLoopLaunch::Direct(Err(RuntimeError::Trap(error)));
        }
        member_publication.commit();
        prepared.disarm();
        VcpuLoopLaunch::Persistent {
            result: logical.result,
            completion: logical.completion,
            process_retirement: logical.process_retirement,
            liveness: directory.process_graph_liveness(),
        }
    }
}

struct PreparedInitialRunnerTask {
    context: crate::kernel::KernelContext,
    cpu: crate::kernel::objects::MigratableTaskState,
    start_gate: crate::kernel::objects::OpenedStartGate,
}

struct PreparedInitialHandoff {
    task: Option<PreparedInitialRunnerTask>,
    scheduler: Arc<crate::kernel::Scheduler>,
    wait_service: Arc<continuation::CarrierWaitService>,
    thread: crate::kernel::ThreadRef,
    generation: crate::kernel::objects::ExecutionGeneration,
    armed: bool,
}

impl PreparedInitialHandoff {
    fn fail_exact(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self.scheduler.fail_runnable_exact(
            self.thread.key(),
            self.generation,
            crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
        );
        self.armed = false;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PreparedInitialHandoff {
    fn drop(&mut self) {
        self.fail_exact();
    }
}

fn prepare_initial_runner_handoff<E: ThreadedEngine + 'static>(
    kernel: &Kernel,
    engine: &mut E,
    kicker: &Arc<dyn VcpuRegistry>,
    linux_tid: crate::kernel::LinuxTid,
    this_tid: ThreadId,
) -> Result<PreparedInitialHandoff, RuntimeError> {
    let context = kernel
        .dispatcher
        .capture_kernel_context(linux_tid)
        .map_err(|error| {
            RuntimeError::Configuration(format!("capture initial runner task authority: {error}"))
        })?;
    let mm = context.shared().mm().id();
    let asid_generation = kernel
        .hvpatch_process
        .as_ref()
        .map_or(mm.raw(), crate::hvpatch::ProcessContext::asid_generation);
    engine.bind_task_snapshot_identity(mm.raw(), asid_generation);
    if let Some(process) = kernel.hvpatch_process.as_ref() {
        let owner_inventory = engine.frame_cow_owner_inventory().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch initial runner has no carrier host-owner inventory".to_owned(),
            )
        })?;
        let binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch initial runner task has no ASID".to_owned())
        })?;
        engine.bind_frame_cow(
            Arc::new(KernelFrameCowAuthority {
                deferred_anonymous: kernel.dispatcher.deferred_anonymous_state(mm),
                kernel: Arc::clone(context.kernel()),
                mm,
                owner_inventory,
                guest_executors: kernel.dispatcher.mm_executor_census(),
                tid: this_tid,
                identity: carrick_hal::FrameCowIdentity {
                    linux_pid: process.pid(),
                    linux_tid: this_tid.raw(),
                    mm: mm.raw(),
                    asid: binding.asid.raw(),
                },
                pt_quiesce: kernel.dispatcher.pt_quiesce(),
            }),
            carrick_hal::FrameCowIdentity {
                linux_pid: process.pid(),
                linux_tid: this_tid.raw(),
                mm: mm.raw(),
                asid: binding.asid.raw(),
            },
        );
    }
    if !kernel.dispatcher.bind_deferred_anonymous_state(engine, mm) {
        return Err(RuntimeError::Configuration(
            "initial runner anonymous authority MM mismatch".to_owned(),
        ));
    }
    let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
        RuntimeError::Configuration("initial runner task has no runtime directory".to_owned())
    })?;
    let services = directory.prepare_persistent_services(context.kernel());
    let scheduler = Arc::clone(&services.scheduler);
    let cpu = engine
        .save_initial_runner_state()
        .map_err(RuntimeError::Trap)?;
    let state = crate::kernel::objects::MigratableTaskState {
        cpu,
        mm,
        asid_generation,
    };
    let retained_cpu = state.clone();
    // Gated for the same reason the clone child is: the initial runner is
    // Kernel-runnable here, and its submission is admitted later.
    let generation = scheduler
        .publish_initial_task_state_gated(context.thread(), state)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .ok_or_else(|| {
            RuntimeError::Configuration(
                "initial HVPatch runner has no exact opened Kernel start gate".to_owned(),
            )
        })?;
    let thread = Arc::clone(context.thread());
    let prepared = PreparedInitialHandoff {
        task: Some(PreparedInitialRunnerTask {
            context,
            cpu: retained_cpu,
            start_gate,
        }),
        scheduler,
        wait_service: services.wait_service,
        thread,
        generation,
        armed: true,
    };
    kicker.unregister(this_tid);
    if let Some(lease) = carrick_hal::vcpu_sched::take_current_lease() {
        carrick_hal::vcpu_sched::global().release(lease, carrick_hal::Yield::Blocked);
    }
    engine
        .audit_executor_boundary()
        .map_err(RuntimeError::Trap)?;
    Ok(prepared)
}

/// Decide what the progress-aware trap watchdog should do at one checkpoint.
///
/// The watchdog trips on a WALL-TIME stall, not on raw syscall count:
/// `traps_since_signal` exceeding `max_traps` is only a cheap pre-filter (it
/// gates the comparatively expensive wall-clock read at the call site). Once the
/// pre-filter fires, the guest is aborted only if there has ALSO been no
/// delivered-signal progress for `elapsed >= max_wall`; otherwise the count
/// budget is reset and the guest keeps running. Pure so the trip / no-trip
/// boundaries are unit-testable without a live vCPU.
fn trap_watchdog_decision<E, W>(
    traps_since_signal: usize,
    max_traps: usize,
    elapsed: E,
    max_wall: W,
) -> TrapWatchdog
where
    E: FnOnce() -> std::time::Duration,
    W: FnOnce() -> std::time::Duration,
{
    if traps_since_signal <= max_traps {
        TrapWatchdog::KeepRunning
    } else if elapsed() >= max_wall() {
        TrapWatchdog::Trip
    } else {
        TrapWatchdog::ResetBudget
    }
}

#[cfg(test)]
fn write_hvpatch_child_output(fd: i32, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written > 0 {
            bytes = &bytes[written as usize..];
            continue;
        }
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "host output descriptor made no progress",
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
    Ok(())
}

/// Outcome of `deliver_pending_signal`.
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
fn service_signals_threaded<E: ThreadedEngine>(
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
mod tests {
    use super::signal::{lower_el0_fault, upgrade_protection_si_code};
    use super::*;
    use carrick_guest_mem::GuestMemory;
    use std::num::NonZeroU64;
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

    #[test]
    fn guest_run_accounting_uses_non_aliasing_engine_receipts() {
        let source = include_str!("mod.rs");
        assert!(!source.contains(concat!("this_thread_", "slot")));
        assert!(!source.contains(concat!("slot_", "us(")));
        assert!(source.contains(concat!("take_guest_run_", "receipt_ns")));
    }

    #[test]
    fn initial_execution_authority_precedes_registration_and_guest_run() {
        let source = include_str!("mod.rs");
        // The welded loop published the initial execution authority inline and
        // then registered the vCPU and ran the guest in the same function. The
        // persistent path publishes it in `prepare_initial_runner_handoff`,
        // whose start gate the executor must have claimed before any guest run,
        // so the ordering is asserted where it now lives.
        let handoff = source
            .split("fn prepare_initial_runner_handoff")
            .nth(1)
            .and_then(|tail| tail.split("fn trap_watchdog_decision").next())
            .expect("initial runner handoff body");
        let publish = handoff
            .find(concat!(
                "publish_initial_",
                "task_state_gated(context.thread(), state)"
            ))
            .expect("initial task state must be published through its claimability gate");
        let gate = handoff
            .find("take_opened_start_gate(generation)")
            .expect("claimed start gate");
        assert!(
            publish < gate,
            "the start gate is claimed only after the initial task state is published"
        );
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

    fn alias_context(pid: i32) -> crate::kernel::KernelContext {
        let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "alias-inventory".to_owned(),
        )
        .expect("root bootstrap");
        crate::kernel::Kernel::bootstrap_root(bootstrap)
            .expect("root kernel")
            .1
    }

    fn mock_alias_commit(
        context: &crate::kernel::KernelContext,
    ) -> carrick_hal::FrameInventoryCommit<()> {
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).expect("capacity");
        let mut reservation = context
            .kernel()
            .reserve_frame_inventory(1, 1, capacity)
            .expect("reservation");
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
                gpa: carrick_guest_mem::Gpa(0x8000),
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

    /// The backend's shared-frame registry makes a freshly staged shared-file
    /// frame reusable by the next installer of the same file from staging
    /// time, and a reuser's batch does not reserve that frame; the authority
    /// accepts the reuse only if the frame is already published. So the
    /// install arm must publish while it still holds the AliasMap topology
    /// lock. Publishing after the release produced the 2026-09-08 silent
    /// `UnreservedFrame` carrier abort under concurrent MAP_SHARED installs.
    #[test]
    fn alias_install_publishes_inventory_before_releasing_the_topology_lock() {
        let source = include_str!("mod.rs");
        let arm = source
            .split("DispatchOutcome::MapHostAlias {")
            .nth(1)
            .expect("the alias-install arm exists");
        let arm = arm
            .split("break 'service installed;")
            .next()
            .expect("the alias-install arm ends by breaking with its result");
        // Anchor after the backend commit is taken: the failed-install
        // rollback above it drops the lock too, and must not satisfy this.
        let tail = arm
            .split("engine.take_alias_inventory()")
            .nth(1)
            .expect("the arm takes the backend alias commit");
        let publish = tail
            .find("apply_alias_frame_inventory(&kernel_context, commit)")
            .expect("the arm publishes the alias inventory");
        let release = tail
            .find("drop(topology);")
            .expect("the arm releases the topology lock after the commit is taken");
        assert!(
            publish < release,
            "alias inventory publication must complete under the AliasMap topology lock"
        );
    }

    #[test]
    fn alias_inventory_applies_to_the_syscall_context_mm() {
        let context = alias_context(67_103);
        let exact_mm = context.shared().mm().id();
        let commit = mock_alias_commit(&context);

        apply_alias_frame_inventory(&context, commit).expect("alias publication");

        let snapshot = context.kernel().frame_inventory().snapshot_for_mm(exact_mm);
        assert_eq!(snapshot.mappings.len(), 1);
        assert_eq!(snapshot.mappings[0].mm, exact_mm);
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

    pub(super) struct EndpointTestSignalPump;

    impl SignalPumpControl for EndpointTestSignalPump {
        fn start_signal_pump(
            &self,
            _registry: &Arc<dyn VcpuRegistry>,
            _futex: &Arc<dyn PlatformFutex>,
        ) {
        }
    }

    pub(super) struct EndpointTestSignalArrival;

    impl carrick_hal::SignalArrival for EndpointTestSignalArrival {
        fn wake_all_waiters(&self) {}
    }

    #[derive(Debug, Default)]
    struct EndpointRecordingWaker(std::sync::atomic::AtomicUsize);

    impl crate::kernel::TaskWaker for EndpointRecordingWaker {
        fn wake_task(&self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn hvpatch_migration_endpoint_routes_task_wake_to_exact_scheduler_generation() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let mm = context.shared().mm().id();
        context
            .thread()
            .publish_initial_task_state(crate::kernel::objects::MigratableTaskState {
                cpu: carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                    carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                        gprs: [0; 31],
                        pc: 0x1000,
                        pstate: 0,
                        trap_pc: 0,
                        trap_pstate: 0,
                        sp_el0: 0x2000,
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
                        mm_generation: mm.raw(),
                        asid_generation: mm.raw(),
                    },
                ),
                mm,
                asid_generation: mm.raw(),
            })
            .expect("initial scheduler state");
        let scheduler = Arc::new(crate::kernel::scheduler::Scheduler::new(Arc::clone(
            context.kernel(),
        )));
        let directory = HvpatchRuntimeDirectory::default();
        directory
            .install_scheduler(Arc::clone(&scheduler))
            .expect("install packaged scheduler route");
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register_endpoint(
            context.task().key(),
            Arc::downgrade(&kernel),
            context.task_binding(),
        );
        let compatibility_wake = Arc::new(EndpointRecordingWaker::default());
        context.task().set_waker(compatibility_wake.clone());

        directory.notify_child_exit(context.task().key(), None);
        assert_eq!(scheduler.queued_len(), 1);
        assert_eq!(
            compatibility_wake
                .0
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "exact scheduler publication must not also invoke the broad compatibility waker"
        );
        assert!(matches!(
            context.thread().execution_state(),
            crate::kernel::objects::ThreadExecutionState::Runnable { .. }
        ));
    }

    #[test]
    fn installed_scheduler_rejection_never_falls_back_to_broad_task_wake_authority() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let scheduler = Arc::new(crate::kernel::scheduler::Scheduler::new(Arc::clone(
            context.kernel(),
        )));
        let directory = HvpatchRuntimeDirectory::default();
        directory
            .install_scheduler(scheduler)
            .expect("install packaged scheduler route");
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register_endpoint(
            context.task().key(),
            Arc::downgrade(&kernel),
            context.task_binding(),
        );
        let compatibility_wake = Arc::new(EndpointRecordingWaker::default());
        context.task().set_waker(compatibility_wake.clone());

        directory.notify_child_exit(context.task().key(), None);

        assert_eq!(
            compatibility_wake
                .0
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a broad compatibility nudge cannot replace rejected scheduler authority"
        );
    }

    #[derive(Default)]
    pub(super) struct Memory(std::collections::BTreeMap<u64, Vec<u8>>);
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

    pub(super) struct DynamicCloneBackendOps;

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

    pub(super) struct NoopPlatformFutex;
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
    pub(super) use test_carrier_graph_with_dispatcher;

    #[test]
    fn persistent_root_waits_for_physical_retirement_after_error_result() {
        struct NeverPolled;
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        let quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            completion.clone(),
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: result.clone(),
            completion: completion.clone(),
            process_retirement: ProcessPhysicalRetirement::default(),
        };
        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        result.publish(Err(RuntimeError::Unsupported(
            "injected root failure".to_owned(),
        )));
        completion.publish();
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "root error must not outrun physical binding retirement"
        );
        drop(quantum);
        match wait_rx.recv().expect("root wait result") {
            Err(error) => assert!(error.to_string().contains("injected root failure")),
            Ok(_) => panic!("injected root failure unexpectedly succeeded"),
        }
        waiter.join().expect("root waiter");
    }

    #[test]
    fn persistent_error_after_exit_starts_waits_for_process_physical_retirement() {
        struct NeverPolled;
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            root_completion.clone(),
        ));
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled),
            sibling_completion.clone(),
        ));
        let process_retirement = ProcessPhysicalRetirement::default();
        process_retirement.begin_process_exit();
        process_retirement
            .publish(vec![root_completion.clone(), sibling_completion.clone()])
            .unwrap();
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: result.clone(),
            completion: root_completion.clone(),
            process_retirement,
        };

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        result.publish(Err(RuntimeError::Unsupported(
            "injected terminal failure".to_owned(),
        )));
        root_completion.publish();
        sibling_completion.publish();
        drop(root_quantum);

        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "terminal error must not outrun sibling physical retirement"
        );
        drop(sibling_quantum);
        match wait_rx.recv().expect("root wait result") {
            Err(error) => assert!(error.to_string().contains("injected terminal failure")),
            Ok(_) => panic!("injected terminal failure unexpectedly succeeded"),
        }
        waiter.join().expect("root waiter");
    }

    #[test]
    fn pre_exit_executor_failure_reaps_late_clone_before_physical_retirement() {
        struct NeverPolled {
            _mount_owner: Option<Box<dyn Send>>,
        }

        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only sibling job must not run")
            }
        }

        let dispatcher = SyscallDispatcher::new();
        let mut mounts = dispatcher.prepare_mount_retirement();
        let sibling_mount_owner: Box<dyn Send> = Box::new(dispatcher.archive_authority());
        drop(dispatcher);

        let (runtime, scheduler, kernel, root, process, generation) =
            test_carrier_graph_with_dispatcher!(72_430, SyscallDispatcher::new());
        let pending_clone = kernel
            .enroll_thread_clone()
            .admitted()
            .expect("hold one in-flight clone admission");
        let executor = scheduler
            .register_executor(Arc::new(RuntimeTestExecutorKick::default()))
            .expect("register failing executor");
        let running = scheduler.take(&executor).expect("take failing root job");
        runtime
            .persistent_bindings()
            .retire(root.thread().key(), generation);

        let threads = VcpuThreadRegistry::default();
        let root_result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let root_settlement =
            HvpatchExternalTerminalSettlement::new(root_result.clone(), root_completion.clone());
        let sibling_result = HvpatchLoopResult::pending();
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_settlement =
            HvpatchExternalTerminalSettlement::new(sibling_result, sibling_completion.clone());
        enroll_persistent_process_member(&threads, &root_settlement);
        enroll_persistent_process_member(&threads, &sibling_settlement);

        let this_tid = ThreadId::synthetic_for_tests(72_430);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::clone(&registry),
            futex,
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            threads.clone(),
            kicker,
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        let production = ProductionHvpatchLoopJob {
            kernel: Arc::clone(&kernel),
            state,
            phase: HvpatchProductionPhase::Resident,
            registration_wait: None,
            terminal_settlement: root_settlement,
            terminal_result: None,
            completion: root_completion.clone(),
            traps: 0,
            budget_floor: 0,
            seen_signal_progress: signal_progress_count(),
            last_signal_progress: Instant::now(),
            terminal_runtime: PersistentTerminalRuntimeState::Resident,
            pending_terminal_retirement: None,
            pending_terminal_inventory: None,
            external_exec: None,
        };
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(HvpatchLoopJob::production(
                production,
                InjectedExecutionLeaseSlot::new(),
            )),
            root_completion.clone(),
        ));
        let root_binding = Arc::new(continuation::HvpatchTaskBinding::new(
            executor::TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: root.shared().mm().id(),
                asid_generation: process.asid_generation(),
            },
            Arc::clone(&root_quantum),
            Box::new(72_430_u64),
        ));
        runtime
            .persistent_bindings()
            .publish(root.thread().key(), generation, Arc::clone(&root_binding))
            .expect("publish production failure binding");
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled {
                _mount_owner: Some(sibling_mount_owner),
            }),
            sibling_completion,
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: root_result,
            completion: root_completion,
            process_retirement: kernel.process_physical_retirement.clone(),
        };

        assert!(
            executor::fail_running_and_retire_for_test::<continuation::HvpatchTaskBinding, _>(
                runtime.persistent_bindings().as_ref(),
                &scheduler,
                running,
                crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
            )
            .is_none(),
            "exact failure settlement itself must succeed",
        );
        drop(root_binding);
        drop(root_quantum);

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "pre-exit executor failure must not outrun sibling physical retirement"
        );
        assert!(
            mounts.prepare().is_err(),
            "the live sibling quantum still owns the exact mount table"
        );

        let late_tid = registry.register_child(0);
        let late_result = HvpatchLoopResult::pending();
        let late_completion = continuation::LogicalJobCompletion::pending();
        let late_settlement =
            HvpatchExternalTerminalSettlement::new(late_result, late_completion.clone());
        enroll_persistent_process_member(&threads, &late_settlement);
        let late_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled { _mount_owner: None }),
            late_completion.clone(),
        ));

        drop(pending_clone);
        let late_settlement_deadline = Instant::now() + Duration::from_secs(1);
        while !late_completion.is_finished() && Instant::now() < late_settlement_deadline {
            std::thread::yield_now();
        }
        assert!(
            late_completion.is_finished(),
            "post-stop admitted clone must be included in the exact member snapshot"
        );
        assert!(
            !registry.is_live(late_tid),
            "post-stop admitted clone must be removed by a repeated sibling stop"
        );
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "clone-drain completion must publish a receipt that still waits for the sibling"
        );
        drop(sibling_quantum);
        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "the exact receipt must retain the late child's physical quantum"
        );
        drop(late_quantum);
        assert!(matches!(
            wait_rx.recv().expect("root wait result"),
            Err(RuntimeError::CarrierFailed(_))
        ));
        waiter.join().expect("root waiter");
        mounts.prepare().expect("all physical mount owners retired");
        scheduler
            .unregister_executor(&executor)
            .expect("unregister failing executor");
        scheduler.close();
        scheduler.wait_closed();
    }

    #[test]
    fn persistent_root_wait_does_not_outrun_sibling_terminal_mount_owner() {
        struct NeverPolled {
            _mount_owner: Option<Box<dyn Send>>,
        }
        impl continuation::PersistentQuantumJob for NeverPolled {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut executor::HvpatchQuantumControl<'_, '_>,
            ) -> executor::ExecutorExit {
                unreachable!("retirement-only test job must not run")
            }
        }

        let dispatcher = SyscallDispatcher::new();
        let mut mounts = dispatcher.prepare_mount_retirement();
        let sibling_mount_owner: Box<dyn Send> = Box::new(dispatcher.archive_authority());
        drop(dispatcher);

        let root_result = HvpatchLoopResult::pending();
        let root_completion = continuation::LogicalJobCompletion::pending();
        let root_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled { _mount_owner: None }),
            root_completion.clone(),
        ));
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_quantum = Arc::new(continuation::HvpatchTaskQuantum::new(
            Box::new(NeverPolled {
                _mount_owner: Some(sibling_mount_owner),
            }),
            sibling_completion.clone(),
        ));
        let launch = VcpuLoopLaunch::Persistent {
            liveness: ProcessGraphLiveness::unbound(),
            result: root_result.clone(),
            completion: root_completion.clone(),
            process_retirement: {
                let retirement = ProcessPhysicalRetirement::default();
                retirement
                    .publish(vec![root_completion.clone(), sibling_completion.clone()])
                    .unwrap();
                retirement
            },
        };

        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            wait_tx.send(launch.wait()).expect("report root wait");
        });
        root_result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        root_completion.publish();
        sibling_completion.publish();
        drop(root_quantum);

        assert!(
            wait_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "root process wait must retain the sibling owner's physical completion"
        );
        assert!(
            mounts.prepare().is_err(),
            "the live sibling quantum still owns the exact mount table"
        );

        drop(sibling_quantum);
        assert!(matches!(
            wait_rx.recv().expect("root wait result"),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        waiter.join().expect("root waiter");
        mounts.prepare().expect("all physical mount owners retired");
    }

    #[test]
    fn exec_replacement_treats_removed_sibling_as_done_after_flag_clears() {
        let owner = ThreadId::synthetic_for_tests(1000);
        let registry = ThreadRegistry::new(owner);
        let sibling = registry.register_child(0);

        let removed = registry.remove_all_except(owner);
        assert!(removed.contains(&sibling));
        crate::fork_quiesce::end_exec_replacement();

        assert!(thread_should_finish_for_exec_replacement(
            &registry, sibling
        ));
    }

    #[test]
    fn trap_watchdog_keeps_running_below_count_prefilter() {
        // Below the count pre-filter, the wall clock is irrelevant — never trip,
        // even after a long elapsed window.
        assert_eq!(
            trap_watchdog_decision(
                100,
                1000,
                || Duration::from_secs(60),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::KeepRunning
        );
        // Exactly AT the count threshold is still under (the guard uses `>`).
        assert_eq!(
            trap_watchdog_decision(
                1000,
                1000,
                || Duration::from_secs(60),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::KeepRunning
        );
    }

    #[test]
    fn trap_watchdog_resets_budget_when_count_exceeded_but_wall_intact() {
        // Over the count pre-filter but the guest made wall-clock progress
        // recently (a syscall-bound-but-progressing loop) → reset, do not abort.
        assert_eq!(
            trap_watchdog_decision(
                1001,
                1000,
                || Duration::from_millis(100),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::ResetBudget
        );
        // Just under the wall window is still a reset (the trip uses `>=`).
        assert_eq!(
            trap_watchdog_decision(
                2_000_000,
                1000,
                || Duration::from_millis(29_999),
                || Duration::from_millis(30_000)
            ),
            TrapWatchdog::ResetBudget
        );
    }

    #[test]
    fn trap_watchdog_trips_on_count_and_wall_stall() {
        // Over the count pre-filter AND no progress for >= max_wall → abort.
        // The boundary is inclusive (`>=`): exactly max_wall trips.
        assert_eq!(
            trap_watchdog_decision(
                1001,
                1000,
                || Duration::from_secs(30),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::Trip
        );
        assert_eq!(
            trap_watchdog_decision(
                1_000_000,
                1000,
                || Duration::from_secs(45),
                || Duration::from_secs(30)
            ),
            TrapWatchdog::Trip
        );
    }

    #[test]
    fn trap_watchdog_decision_gates_clock_and_window_reads() {
        use std::cell::Cell;

        let clock_reads = Cell::new(0_usize);
        let window_reads = Cell::new(0_usize);
        let clock = || {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_secs(10)
        };
        let window = || {
            window_reads.set(window_reads.get() + 1);
            Duration::from_secs(30)
        };

        // 1. Below threshold: zero clock/window reads.
        let decision = trap_watchdog_decision(500, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "below count prefilter must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "below count prefilter must perform 0 window reads"
        );

        // 2. Exactly at threshold: zero clock/window reads.
        let decision = trap_watchdog_decision(1000, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "exact count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "exact count threshold must perform 0 window reads"
        );

        // 3. usize::MAX threshold (ecosystem invocation): zero clock/window reads.
        let decision = trap_watchdog_decision(10_000_000, usize::MAX, clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "usize::MAX threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "usize::MAX threshold must perform 0 window reads"
        );

        // 4. Above threshold: exactly 1 clock read and 1 window read.
        let decision = trap_watchdog_decision(1001, 1000, clock, window);
        assert_eq!(decision, TrapWatchdog::ResetBudget);
        assert_eq!(
            clock_reads.get(),
            1,
            "above count threshold must perform 1 clock read"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "above count threshold must perform 1 window read"
        );
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

    #[test]
    fn trap_watchdog_step_seam_proves_call_path_zero_reads_and_signal_reset() {
        use std::cell::Cell;

        let (process, root) = crate::hvpatch::process_context_for_tests(70_222);
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process.clone());
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            Some(process.clone()),
            None,
            None,
        ));
        let this_tid = ThreadId::synthetic_for_tests(70_222);
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(this_tid)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            this_tid,
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            1_000,
        );
        state.service_kernel_context = Some(root.retain_exact());
        let mut job =
            suffix_failure_test_job(&kernel, state, HvpatchProductionPhase::Resident, None);

        let clock_reads = Cell::new(0_usize);
        let window_reads = Cell::new(0_usize);
        let clock = |_last: &Instant| {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_millis(100)
        };
        let window = || {
            window_reads.set(window_reads.get() + 1);
            Duration::from_secs(30)
        };

        // Below threshold (traps = 500, max_traps = 1000): 0 clock reads, 0 window reads.
        job.traps = 500;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "call path below count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "call path below count threshold must perform 0 window reads"
        );

        // Exactly at threshold (traps = 1000, max_traps = 1000): 0 clock reads, 0 window reads.
        job.traps = 1000;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            0,
            "call path at exact count threshold must perform 0 clock reads"
        );
        assert_eq!(
            window_reads.get(),
            0,
            "call path at exact count threshold must perform 0 window reads"
        );

        // Above threshold (traps = 1001, max_traps = 1000): 1 clock read, 1 window read -> ResetBudget.
        job.traps = 1001;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::ResetBudget);
        assert_eq!(
            clock_reads.get(),
            1,
            "call path above count threshold must read clock"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "call path above count threshold must read window"
        );
        assert_eq!(
            job.budget_floor, 1001,
            "budget floor must reset to current traps on ResetBudget"
        );

        // Next step after budget reset (traps = 1002, budget_floor = 1001, delta = 1 <= 1000): 0 reads.
        job.traps = 1002;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            1,
            "call path after budget reset must perform 0 new clock reads"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "call path after budget reset must perform 0 new window reads"
        );

        // Now test max_traps = usize::MAX (ecosystem workload pattern)
        job.state.max_traps = usize::MAX;
        job.traps = 50_000_000;
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            clock_reads.get(),
            1,
            "usize::MAX max_traps must perform 0 new clock reads"
        );
        assert_eq!(
            window_reads.get(),
            1,
            "usize::MAX max_traps must perform 0 new window reads"
        );

        // Now test signal progress independently resets budget floor without reading clock
        job.state.max_traps = 1000;
        job.traps = 2000; // traps_since_signal would be 2000 - 1001 = 999 <= 1000
        // Simulate a new signal progress event by modifying seen_signal_progress
        job.seen_signal_progress = signal_progress_count().wrapping_sub(1);
        let decision = job.step_trap_watchdog(clock, window);
        assert_eq!(decision, TrapWatchdog::KeepRunning);
        assert_eq!(
            job.budget_floor, 2000,
            "signal progress must update budget floor to traps"
        );
        assert_eq!(job.seen_signal_progress, signal_progress_count());
        assert_eq!(
            clock_reads.get(),
            1,
            "signal progress reset must not require clock read if delta <= max_traps"
        );

        // Now test Trip condition: traps above threshold and elapsed >= max_wall
        job.traps = 3500; // delta = 3500 - 2000 = 1500 > 1000
        let trip_clock = |_last: &Instant| {
            clock_reads.set(clock_reads.get() + 1);
            Duration::from_secs(35)
        };
        let decision = job.step_trap_watchdog(trip_clock, window);
        assert_eq!(decision, TrapWatchdog::Trip);
        assert_eq!(clock_reads.get(), 2);
        assert_eq!(window_reads.get(), 2);
    }

    #[test]
    fn hvpatch_child_output_writer_drains_payload_larger_than_a_pipe() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload: Vec<u8> = (0..(256 * 1024)).map(|index| (index % 251) as u8).collect();
        let reader = std::thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                let read = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
                if read > 0 {
                    output.extend_from_slice(&buffer[..read as usize]);
                } else {
                    break;
                }
            }
            unsafe { libc::close(fds[0]) };
            output
        });
        write_hvpatch_child_output(fds[1], &payload).expect("complete pipe write");
        unsafe { libc::close(fds[1]) };
        assert_eq!(reader.join().expect("pipe reader"), payload);
    }

    #[test]
    fn post_close_exec_failures_reach_production_poll_as_typed_authority() {
        let source = include_str!("mod.rs");
        let exec_source = include_str!("exec.rs");

        assert!(
            exec_source.contains("enum ProductionHvpatchPollError"),
            "production polling must distinguish ordinary errors from exact post-close exec errors"
        );
        assert!(
            (source.contains("ProductionHvpatchPollError::Exec")
                || exec_source.contains("ProductionHvpatchPollError::Exec")),
            "the production wrapper must consume the typed exec-terminal error arm"
        );
        assert!(
            exec_source.contains("struct ExecTerminalFailure"),
            "fallible prepared-drain and suffix operations must return the retained handoff"
        );
        assert!(
            exec_source.contains("struct FinishedPreparedExecve"),
            "the handoff must remain live through fallible post-suffix publication"
        );
    }

    #[test]
    fn persistent_terminal_owner_withdrawal_clears_child_tid_and_wakes_joiner() {
        let owner = ThreadId::synthetic_for_tests(70_302);
        let clear_address = 0x2_000;
        let registry = ThreadRegistry::new(owner);
        registry.set_clear_child_tid(owner, clear_address);
        let futex = FutexTable::new();
        let wait = futex.prepare_wait(clear_address);
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let enrollment = futex.subscribe_generation(
            wait,
            Arc::new(move |_| {
                wake_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        let mut memory =
            crate::dispatch::LinearMemory::new(clear_address, owner.raw().to_le_bytes().to_vec());

        threads::clear_persistent_child_tid_and_wake(&mut memory, &registry, &futex, owner);

        assert_eq!(
            memory.read_bytes(clear_address, std::mem::size_of::<i32>()),
            Ok(0_i32.to_le_bytes().to_vec())
        );
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(enrollment);
    }

    /// The production thread-clone path must park a `Deferred` enrollment
    /// on the gate's change epoch rather than lower it to `EAGAIN`.
    /// A process exit retires its MM edge; that is an owner-set edit and
    /// must be admitted against a sibling's exec reservation exactly as a
    /// shared fork is — before the topology lock, and long before the
    /// kernel exit publication after which a refusal is only an abort.
    #[test]
    fn process_exit_admits_its_retirement_against_exec_reservations() {
        let source = include_str!("mod.rs");
        let finalize = source
            .split("fn finalize_persistent_process_terminal(")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n    fn ")
            .next()
            .unwrap_or_else(|| std::process::abort());
        let hold_at = finalize
            .find(".hold_owner_set_edit(terminal_context.task().key())")
            .expect("exit admits its owner-set edit");
        let topology_at = finalize
            .find("try_acquire_topology_lock(")
            .expect("exit takes the topology lock");
        let publish_at = finalize
            .find(".publish_exit_status(")
            .expect("exit publishes into the kernel graph");
        let retire_at = finalize
            .find(".begin_address_space_retirement(")
            .expect("exit retires its MM edge");
        assert!(
            hold_at < topology_at,
            "admission precedes the topology lock"
        );
        assert!(
            hold_at < publish_at,
            "admission precedes kernel publication"
        );
        assert!(finalize.contains("TerminalRetireSubscription::ExecSettlement"));
        assert!(finalize.contains(".subscribe_exec_settlement("));
        // The hold is also dropped when parking on the topology lock; the
        // final release follows the retirement.
        let release_at = finalize
            .rfind("drop(owner_set_edit);")
            .expect("the hold is released explicitly after retirement");
        assert!(retire_at < release_at);
        let park_release_at = finalize
            .find("drop(owner_set_edit);")
            .expect("the hold is dropped before parking on topology");
        assert!(
            park_release_at
                < topology_at
                    + finalize[topology_at..]
                        .find("return self.suspend(")
                        .unwrap()
        );
    }

    #[test]
    fn deferred_thread_clone_parks_on_the_admission_epoch() {
        let source = include_str!("mod.rs");
        let spawn = source
            .split("fn spawn_persistent_hvpatch_clone_thread")
            .nth(1)
            .unwrap_or_else(|| std::process::abort())
            .split("\n#[cfg(test)]")
            .next()
            .unwrap_or_else(|| std::process::abort());
        let deferred_at = spawn
            .find("CloneEnrollment::Deferred { observed_epoch }")
            .expect("thread clone handles a deferred enrollment");
        let refused_at = spawn
            .find("CloneEnrollment::Refused")
            .expect("thread clone handles a refused enrollment");
        let eagain_at = spawn
            .find("thread clone admission refused; clone(2) = EAGAIN")
            .expect("refusal is the only EAGAIN");
        assert!(deferred_at < refused_at && refused_at < eagain_at);
        assert!(spawn[deferred_at..refused_at].contains("CloneRetrySubscription::Admission"));
        assert!(spawn[deferred_at..refused_at].contains("clone_admission.subscribe_change("));
        assert!(!spawn[deferred_at..refused_at].contains("LINUX_EAGAIN"));
    }

    #[test]
    fn fork_barrier_raise_uses_durable_threads_when_sibling_owns_no_executor() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_100);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .unwrap();
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(70_101))
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context();
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process);
        let runtime = KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        );
        assert_eq!(
            runtime
                .dispatcher
                .mm_executor_census()
                .participant_count_for_probe(),
            0
        );
        assert_eq!(root.task().threads().len(), 2);
        assert_eq!(sibling.task().key(), root.task().key());
        assert!(
            include_str!("quiesce.rs")
                .contains("fork_barrier_participants(parent_context.thread().key())")
        );
    }

    #[test]
    fn persistent_exec_drain_retains_leader_result_until_exact_completion() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_102);
        let directory = HvpatchRuntimeDirectory::default();
        let (scheduler, _) = directory.continuation_services(context.kernel());
        let handles = VcpuThreadRegistry::default();
        let leader_result = HvpatchLoopResult::pending();
        let leader_completion = continuation::LogicalJobCompletion::pending();
        let exec_result = HvpatchLoopResult::pending();
        let exec_completion = continuation::LogicalJobCompletion::pending();
        let leader_settlement = HvpatchExternalTerminalSettlement::new(
            leader_result.clone(),
            leader_completion.clone(),
        );
        let exec_settlement =
            HvpatchExternalTerminalSettlement::new(exec_result, exec_completion.clone());

        enroll_persistent_process_member(&handles, &leader_settlement);
        enroll_persistent_process_member(&handles, &exec_settlement);
        let drain = continuation::ProcessDrain::for_scheduler(
            context.thread().key(),
            &scheduler,
            exec_completion.id(),
            handles.completions(),
        );
        assert!(!drain.is_ready(), "exec must wait for the suspended leader");

        leader_settlement
            .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
            .unwrap();
        assert!(drain.is_ready());
        let (published, _) = finish_persistent_process_handles(&handles, &exec_completion)
            .expect("drain exact leader result without synthesizing one");
        assert_eq!(published, 0, "the leader settled its own job");
    }

    #[test]
    fn persistent_worker_drain_never_waits_for_a_removed_logical_job() {
        let source = include_str!("mod.rs");
        let threads_source = include_str!("threads.rs");
        let finish = threads_source
            .split("fn finish_completed(self, current")
            .nth(1)
            .and_then(|tail| tail.split("fn enroll_persistent_process_member").next())
            .expect("persistent handle settlement body");
        assert!(
            !finish.contains("result.wait()"),
            "an executor worker must externally settle a removed persistent job, never wait"
        );
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
                    .next()
            })
            .expect("production job poll");
        assert!(
            poll.find("terminal_settlement.is_published()").unwrap()
                < poll.find("guest_execution.is_none()").unwrap(),
            "a late queued poll must observe external terminal settlement before re-entry"
        );
        let publication = source
            .split("fn publish_terminal_result(&mut self)")
            .nth(1)
            .and_then(|tail| tail.split("fn suspend(").next())
            .expect("production terminal result publication");
        assert!(
            publication.contains("publish_terminal(self.terminal_result.take())"),
            "scheduler terminal settlement must consume the typed role/result pair"
        );
        assert!(
            source.contains("ProcessExitClaim::Owner => {")
                && source.contains("arm_process_owner()"),
            "the exact terminal CAS winner must arm owner-result authority"
        );
    }

    #[test]
    fn production_registration_keeps_census_before_registry_publication() {
        let source = include_str!("mod.rs");
        let poll = source.split("fn poll_with_engine(").nth(1).unwrap();
        assert!(
            poll.find("enter_mm_executor_then_register").unwrap()
                < poll.find("subscribe_register_vcpu").unwrap()
        );
    }

    #[test]
    fn registration_wait_is_sidecar_not_hvpatch_phase() {
        let source = include_str!("mod.rs");
        let job = source
            .split("struct ProductionHvpatchLoopJob")
            .nth(1)
            .unwrap();
        assert!(
            job.contains("registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>")
        );
        let phases = source
            .split("enum HvpatchProductionPhase")
            .nth(1)
            .unwrap()
            .split("impl HvpatchProductionPhase")
            .next()
            .unwrap();
        assert!(!phases.contains("RegistrationWait"));
    }

    #[test]
    fn production_registration_has_no_barrier_precheck_or_phase_replacement() {
        let source = include_str!("mod.rs");
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .expect("production poll body");
        let registration = poll
            .split("if self.state.guest_execution.is_none()")
            .nth(1)
            .expect("registration admission block")
            .split("// Exec/exit can force")
            .next()
            .expect("bounded registration admission block");
        assert!(registration.contains("enter_mm_executor_then_register"));
        assert!(!registration.contains("is_quiescing"));
        assert!(!registration.contains("try_begin_fork"));
        assert!(!registration.contains("self.phase ="));
    }

    struct RegistrationTestKick;

    impl carrick_hal::VcpuKickDyn for RegistrationTestKick {
        fn kick(&self) {}
    }

    pub(super) fn registration_test_handle() -> Box<dyn carrick_hal::VcpuKickDyn> {
        Box::new(RegistrationTestKick)
    }

    #[derive(Debug, Default)]
    pub(super) struct RuntimeTestExecutorKick(Mutex<Option<crate::kernel::ExecutorBinding>>);

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
    pub(super) struct CrashCaptureTestKick;

    impl carrick_hal::VcpuKick for CrashCaptureTestKick {
        fn kick(&self) {}
    }

    pub(super) type CrashReadTracker = Arc<Mutex<Vec<(u64, usize)>>>;

    #[derive(Default)]
    pub(super) struct CrashCaptureTestEngine {
        pub(super) next_syscall: Option<carrick_hal::RawSyscall>,
        pub(super) completed_syscalls: Vec<i64>,
        pub(super) completion_events: Option<Arc<Mutex<Vec<&'static str>>>>,
        pub(super) execve_installs: usize,
        pub(super) exec_inventory_arms: usize,
        pub(super) retirement_inventory: Option<carrick_hal::FrameInventoryReservation>,
        pub(super) exec_inventory: Option<(
            Option<carrick_hal::FrameInventoryReservation>,
            carrick_hal::FrameInventoryReservation,
        )>,
        pub(super) exec_support: bool,
        pub(super) snapshot_cpu: Option<carrick_hal::threaded::GuestCpuState>,
        pub(super) frame_cow_owner_inventory: Option<Arc<dyn carrick_hal::FrameCowOwnerInventory>>,
        pub(super) installed_table_arena_sources: usize,
        pub(super) guest_memory: std::collections::BTreeMap<u64, Vec<u8>>,
        pub(super) read_tracker: Option<CrashReadTracker>,
        pub(super) fail_read_at: Option<u64>,
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

        #[allow(clippy::too_many_arguments)]
        fn inject_signal(
            &mut self,
            _signum: i32,
            _handler: u64,
            _sa_restorer: u64,
            _pending_syscall_retval: Option<i64>,
            _interrupted_pc: Option<u64>,
            _altstack: Option<(u64, u64)>,
            _saved_sigmask: u64,
            _fault_siginfo: Option<(i32, u64)>,
            _queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
            _restart_syscall: bool,
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_test_exec_work() -> crate::kernel::control::ExecWork {
        use crate::kernel::control::{
            CarrierExecAdmission, ControlNonce, ControlTaskKey, ExecAttach, ExecCapability,
            ExecRequest, ExecRuntime, ExecStatus,
        };

        let runtime = ExecRuntime::new(1);
        let capability = ExecCapability::from(ControlNonce::fresh().expect("control nonce"));
        let submit = runtime.clone();
        let request = ExecRequest {
            argv: vec!["/bin/true".to_owned()],
            env: Vec::new(),
            workdir: None,
            user: None,
            tty: false,
            attach: ExecAttach::Capture,
        };
        let submitter = std::thread::spawn(move || submit.admit(capability, request));
        while runtime.query(capability) != ExecStatus::Pending {
            std::thread::yield_now();
        }
        let mut work = loop {
            if let Some(work) = runtime.try_take() {
                break work;
            }
            std::thread::yield_now();
        };
        assert!(work.begin_publication());
        assert!(work.admit(ControlTaskKey {
            pid: 70_204,
            serial: 1,
        }));
        assert_eq!(submitter.join().expect("exec submitter"), Ok(capability));
        work
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_test_retry_phase(
        external_exec: Option<crate::kernel::control::ExecWork>,
    ) -> HvpatchProductionPhase {
        HvpatchProductionPhase::RetryProcessFork {
            frame: None,
            request: quiesce::ForkRequest {
                flags: 0,
                pidfd_out: None,
                clone_parent: false,
                parent_tid_addr: None,
                child_tid_addr: None,
                exit_signal: 0,
                child_stack: 0,
                vfork: None,
            },
            coordinator: None,
            external_exec,
            deferred_resume_blocked: None,
            _subscription: quiesce::ProcessForkRetrySubscription::Reservation {
                _subscription: None,
            },
        }
    }

    #[test]
    fn census_admission_precedes_registry_publication() {
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let first = ThreadId::synthetic_for_tests(70_201);
        let second = ThreadId::synthetic_for_tests(70_202);
        let _first_participation = census.enter(None).expect("first participation");
        let freeze = match registry.subscribe_lease_drain(first, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("first thread must freeze an empty sibling lease set"),
        };
        let second_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let (second_participation, attempt) =
            enter_guest_executor_then_register(&census, Some(thread.clone()), || {
                assert!(
                    census.has_peer_executor(),
                    "census admission must precede registry publication"
                );
                assert!(
                    thread.is_crash_safe_point_participant(),
                    "crash participation must precede registry publication"
                );
                registry.subscribe_register(
                    second,
                    registration_test_handle(),
                    &second_in_guest,
                    Arc::new(|| {}),
                )
            })
            .expect("second participation");

        assert!(census.has_peer_executor());
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        assert_eq!(
            registry.poll_lease_drain(first),
            carrick_hal::VcpuLeaseDrainPoll::Complete
        );
        drop(second_participation);
        assert_eq!(census.participant_count_for_probe(), 1);
        drop(attempt);
        drop(freeze);
    }

    #[test]
    fn failed_crash_admission_suppresses_registry_publication() {
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let _outside = thread
            .enter_crash_safe_point_participation()
            .expect("outside crash participation");
        let register_called = std::sync::atomic::AtomicBool::new(false);

        assert!(matches!(
            enter_guest_executor_then_register(&census, Some(thread.clone()), || {
                register_called.store(true, std::sync::atomic::Ordering::Release);
                panic!("failed admission must not invoke registry publication")
            }),
            Err(crate::kernel::GuestExecutorCensusError::CrashParticipationAlreadyActive {
                thread: rejected
            }) if rejected == thread.key()
        ));
        assert!(!register_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(census.participant_count_for_probe(), 0);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn fork_owner_registration_ignores_raised_barrier_and_preserves_phase() {
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let census = Arc::new(crate::kernel::GuestExecutorCensus::default());
        let owner = ThreadId::synthetic_for_tests(70_203);
        let barrier = Arc::new(crate::fork_quiesce::QuiesceBarrier::new());
        assert!(barrier.try_begin_fork());
        barrier.set_quiescing();
        let phase = registration_test_retry_phase(None);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let (participation, enrollment) = enter_guest_executor_then_register(&census, None, || {
            registry.subscribe_register(
                owner,
                registration_test_handle(),
                &owner_in_guest,
                Arc::new(|| {}),
            )
        })
        .expect("owner participation");

        assert!(matches!(
            enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        assert!(matches!(
            phase,
            HvpatchProductionPhase::RetryProcessFork { .. }
        ));
        assert!(barrier.is_quiescing());
        registry.unregister(owner);
        drop(participation);
        barrier.end_quiesce();
        barrier.end_fork();
        drop(freeze);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn registration_thaw_wakes_external_exec_control_quantum() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_204);
        context
            .thread()
            .publish_initial_task_state(executor::tests::task_state(&context, 204))
            .expect("publish test task state");
        let scheduler = Arc::new(crate::kernel::Scheduler::new(Arc::clone(context.kernel())));
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue test thread");
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let owner = ThreadId::synthetic_for_tests(70_205);
        let waiter = ThreadId::synthetic_for_tests(70_204);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let mut phase = registration_test_retry_phase(Some(registration_test_exec_work()));
        let wake_mode = registration_wake_uses_control(&phase, false);
        let wake_registration =
            registration_wake_callback(Arc::clone(&scheduler), context.thread().key(), wake_mode);
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let attempt = registry.subscribe_register(
            waiter,
            registration_test_handle(),
            &waiter_in_guest,
            wake_registration,
        );
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("inspect control quantum")
                .is_none()
        );

        phase = HvpatchProductionPhase::Resident;
        assert!(matches!(phase, HvpatchProductionPhase::Resident));
        drop(freeze);

        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("registration thaw control quantum")
                .is_some()
        );
        assert_eq!(scheduler.queued_len(), 1);
        drop(attempt);
    }

    #[test]
    fn registration_thaw_wakes_pending_control_quantum_before_phase_transition() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_206);
        context
            .thread()
            .publish_initial_task_state(executor::tests::task_state(&context, 206))
            .expect("publish test task state");
        let scheduler = Arc::new(crate::kernel::Scheduler::new(Arc::clone(context.kernel())));
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue test thread");
        scheduler
            .wake_control(context.thread().key())
            .expect("publish pending scheduler control quantum");
        let pending_control_quantum = context
            .thread()
            .scheduler_control_quantum(context.thread().key())
            .expect("inspect pending control quantum")
            .is_some();
        let phase = HvpatchProductionPhase::Resident;
        let wake_mode = registration_wake_uses_control(&phase, pending_control_quantum);
        let wake_registration =
            registration_wake_callback(Arc::clone(&scheduler), context.thread().key(), wake_mode);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let owner = ThreadId::synthetic_for_tests(70_207);
        let waiter = ThreadId::synthetic_for_tests(70_206);
        let freeze = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("owner must freeze an empty sibling lease set"),
        };
        let waiter_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let attempt = registry.subscribe_register(
            waiter,
            registration_test_handle(),
            &waiter_in_guest,
            wake_registration,
        );
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        context
            .thread()
            .finish_scheduler_control_quantum(context.thread().key())
            .expect("simulate phase transition after captured wake mode");
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("control quantum consumed for transition")
                .is_none()
        );

        drop(freeze);

        assert!(matches!(phase, HvpatchProductionPhase::Resident));
        assert!(
            context
                .thread()
                .scheduler_control_quantum(context.thread().key())
                .expect("registration thaw restores control quantum")
                .is_some()
        );
        assert_eq!(scheduler.queued_len(), 1);
        drop(attempt);
    }

    #[test]
    fn removed_persistent_job_is_settled_once_without_repoll_or_binding_cycle() {
        let (_process, context) = crate::hvpatch::process_context_for_tests(70_104);
        let task_state = executor::tests::task_state(&context, 104);
        let binding = executor::tests::hvpatch_test_binding(&context, &task_state, 104);
        let quantum_strong_before = Arc::strong_count(binding.quantum());
        let handles = VcpuThreadRegistry::default();
        let removed_result = HvpatchLoopResult::pending();
        let removed_completion = continuation::LogicalJobCompletion::pending();
        let removed = HvpatchExternalTerminalSettlement::new(
            removed_result.clone(),
            removed_completion.clone(),
        );
        let owner = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            continuation::LogicalJobCompletion::pending(),
        );
        enroll_persistent_process_member(&handles, &removed);
        enroll_persistent_process_member(&handles, &owner);
        assert_eq!(
            Arc::strong_count(binding.quantum()),
            quantum_strong_before,
            "process-member retention must not point back to binding/quantum/job"
        );

        let (published, _) = finish_persistent_process_handles(&handles, &owner.completion())
            .expect("removed Kernel thread settles without a job repoll");
        assert_eq!(published, 1);
        assert!(handles.is_empty());
        assert!(removed.result_is_ready());
        assert!(removed_completion.is_finished());
        assert!(matches!(
            removed_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        assert!(
            !removed
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .unwrap(),
            "external result authority is one-shot"
        );
        assert!(
            !owner.is_published(),
            "the exact current owner retains its separate outcome authority"
        );

        let consumed_result = HvpatchLoopResult::pending();
        let consumed = HvpatchExternalTerminalSettlement::new(
            consumed_result.clone(),
            continuation::LogicalJobCompletion::pending(),
        );
        consumed
            .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
            .unwrap();
        assert!(matches!(
            consumed_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));
        let consumed_handles = VcpuThreadRegistry::default();
        enroll_persistent_process_member(&consumed_handles, &consumed);
        enroll_persistent_process_member(&consumed_handles, &owner);
        let (published, _) =
            finish_persistent_process_handles(&consumed_handles, &owner.completion())
                .expect("already-consumed result retains durable settlement proof");
        assert_eq!(
            published, 0,
            "an already-consumed member is not republished"
        );
    }

    #[test]
    fn terminal_physical_retirement_includes_a_sole_current_member() {
        let handles = VcpuThreadRegistry::default();
        let current = continuation::LogicalJobCompletion::pending();

        let (published, completions) =
            finish_persistent_process_handles(&handles, &current).unwrap();

        assert_eq!(published, 0);
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].id(), current.id());

        let current_settlement =
            HvpatchExternalTerminalSettlement::new(HvpatchLoopResult::pending(), current.clone());
        let sibling_completion = continuation::LogicalJobCompletion::pending();
        let sibling_settlement = HvpatchExternalTerminalSettlement::new(
            HvpatchLoopResult::pending(),
            sibling_completion.clone(),
        );
        enroll_persistent_process_member(&handles, &current_settlement);
        enroll_persistent_process_member(&handles, &sibling_settlement);

        let (published, completions) =
            finish_persistent_process_handles(&handles, &current).unwrap();
        assert_eq!(published, 1);
        assert_eq!(
            completions
                .iter()
                .filter(|completion| completion.id() == current.id())
                .count(),
            1,
            "the terminal owner must occur exactly once even when still enrolled"
        );
        assert!(
            completions
                .iter()
                .any(|completion| completion.id() == sibling_completion.id()),
            "every sibling physical completion must remain in the receipt"
        );
    }

    #[test]
    fn missing_terminal_publication_fails_but_an_externally_settled_sibling_stays_thread_done() {
        assert!(matches!(
            terminal_result_for_publication(None, HvpatchTerminalSettlementRole::Member),
            Err(RuntimeError::CarrierFailed(_))
        ));
        assert!(matches!(
            terminal_result_for_publication(None, HvpatchTerminalSettlementRole::ProcessOwner),
            Err(RuntimeError::Configuration(_))
        ));
        assert!(matches!(
            terminal_result_for_publication(
                Some(Ok(VcpuLoopOutcome::ThreadDone)),
                HvpatchTerminalSettlementRole::ProcessOwner
            ),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));

        let member_result = HvpatchLoopResult::pending();
        let member_completion = continuation::LogicalJobCompletion::pending();
        let member = HvpatchExternalTerminalSettlement::new(
            member_result.clone(),
            member_completion.clone(),
        );
        assert!(
            member
                .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
                .unwrap()
        );
        assert!(
            !member.publish_terminal(None),
            "the executor callback must not replace an exact external sibling settlement"
        );
        assert!(member_completion.is_finished());
        assert!(matches!(
            member_result.wait(),
            Ok(VcpuLoopOutcome::ThreadDone)
        ));

        let owner_result = HvpatchLoopResult::pending();
        let owner_completion = continuation::LogicalJobCompletion::pending();
        let owner =
            HvpatchExternalTerminalSettlement::new(owner_result.clone(), owner_completion.clone());
        owner.arm_process_owner().unwrap();
        assert!(owner.publish_terminal(None));
        assert!(owner_completion.is_finished());
        assert!(matches!(
            owner_result.wait(),
            Err(RuntimeError::Configuration(_))
        ));
    }

    #[test]
    fn persistent_exec_terminal_check_precedes_blocked_vfork_resume() {
        let source = include_str!("mod.rs");
        let poll = source
            .split("fn poll_with_engine(")
            .nth(1)
            .and_then(|tail| {
                tail.split("impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll")
                    .next()
            })
            .expect("production poll body");
        let terminal = poll
            .find("thread_should_finish_for_exec_replacement")
            .expect("top-of-quantum exec terminal check");
        let phase = poll
            .find("let phase = std::mem::replace")
            .expect("phase dispatch");
        assert!(
            terminal < phase,
            "a forced vfork wake must exit before ResumeBlocked"
        );
    }

    #[test]
    fn persistent_terminal_transition_phases_are_not_aborted_by_process_exiting() {
        let context = alias_context(70_105);
        assert!(
            HvpatchProductionPhase::TerminalClaimRetry {
                terminal: PersistentTerminal::from_outcome(VcpuLoopOutcome::ThreadDone),
                context: context.retain_exact(),
                _subscription: None,
            }
            .is_terminal_transition()
        );
        assert!(
            HvpatchProductionPhase::TerminalProcessDrain {
                terminal: PersistentTerminal::from_outcome(VcpuLoopOutcome::ThreadDone),
                context: context.retain_exact(),
                drain: continuation::ProcessDrain::excluding(
                    continuation::LogicalJobCompletion::pending(),
                    Vec::new(),
                ),
            }
            .is_terminal_transition()
        );
        assert!(!HvpatchProductionPhase::Resident.is_terminal_transition());
        assert!(
            !HvpatchProductionPhase::ResumeBlocked {
                frame: carrick_hal::RawSyscall {
                    number: carrick_abi::CanonicalNr(0),
                    args: [0; 6],
                    guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
                    native_number: carrick_abi::NativeNr(0),
                },
                vfork_child_pid: None,
            }
            .is_terminal_transition()
        );
    }

    fn deferred_frame() -> carrick_hal::RawSyscall {
        carrick_hal::RawSyscall {
            number: carrick_abi::CanonicalNr(101),
            args: [1, 2, 3, 4, 5, 6],
            guest_abi: carrick_abi::LinuxGuestAbi::Aarch64,
            native_number: carrick_abi::NativeNr(202),
        }
    }

    fn assert_deferred_resume_exact(
        phase: &HvpatchProductionPhase,
        expected_frame: carrick_hal::RawSyscall,
        expected_vfork_child: Option<i32>,
    ) {
        let HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid,
        } = phase
        else {
            panic!("deferred phase was not restored to ResumeBlocked");
        };
        assert_eq!(*frame, expected_frame);
        assert_eq!(*vfork_child_pid, expected_vfork_child);
    }

    #[test]
    fn control_exec_complete_restores_exact_blocked_frame_and_vfork_identity() {
        let frame = deferred_frame();
        let original = HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid: Some(70_106),
        };
        let deferred = DeferredResumeBlocked::capture(
            &original,
            Some(crate::kernel::objects::BlockedReason::HostWait),
        )
        .expect("capture ResumeBlocked");
        let mut after_peer_publication = HvpatchProductionPhase::Resident;
        deferred.restore(&mut after_peer_publication);
        assert_deferred_resume_exact(&after_peer_publication, frame, Some(70_106));
    }

    #[test]
    fn control_exec_retry_carries_exact_blocked_frame_and_vfork_identity() {
        fn carry_retry_token(token: DeferredResumeBlocked) -> Option<DeferredResumeBlocked> {
            Some(token)
        }

        let frame = deferred_frame();
        let original = HvpatchProductionPhase::ResumeBlocked {
            frame,
            vfork_child_pid: Some(70_107),
        };
        let retry_token = carry_retry_token(
            DeferredResumeBlocked::capture(
                &original,
                Some(crate::kernel::objects::BlockedReason::HostWait),
            )
            .expect("capture ResumeBlocked"),
        );
        let mut after_retry = HvpatchProductionPhase::Resident;
        retry_token
            .expect("RetryProcessFork carries deferred token")
            .restore(&mut after_retry);
        assert_deferred_resume_exact(&after_retry, frame, Some(70_107));
    }

    #[test]
    fn control_exec_completion_clear_then_rechecks_coalesced_queue() {
        let source = include_str!("mod.rs");
        let finish = source
            .split_once("fn finish_control_quantum(")
            .expect("control completion helper")
            .1
            .split_once("fn begin_control_exec_fork(")
            .expect("end control completion helper")
            .0;
        let clear = finish
            .find("finish_scheduler_control_quantum")
            .expect("atomically clear current marker");
        let recheck = finish
            .find("try_take_control_exec")
            .expect("recheck queued work");
        let restore = finish
            .find("restore_scheduler_control_quantum")
            .expect("restore displaced continuation for next work");
        let continue_work = finish
            .find("begin_control_exec_fork")
            .expect("service next work in same root quantum");
        assert!(clear < recheck && recheck < restore && restore < continue_work);
    }

    #[test]
    fn persistent_exec_stop_control_wakes_unreleased_vfork_parent_without_guest_readiness() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_103);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let sibling_tid = ThreadId::synthetic_for_tests(70_104);
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve sibling")
            .prepare(sibling_tid)
            .expect("prepare sibling")
            .commit()
            .expect("publish sibling")
            .start_thread()
            .expect("start sibling")
            .into_context();
        let root_state = executor::tests::task_state(&root, 710);
        let sibling_state = executor::tests::task_state(&sibling, 711);
        root.thread()
            .publish_initial_task_state(root_state)
            .expect("publish root state");
        sibling
            .thread()
            .publish_initial_task_state(sibling_state)
            .expect("publish sibling state");
        let executor = crate::kernel::objects::ExecutorId::for_transitional_thread(
            ThreadId::synthetic_for_tests(71),
        )
        .expect("test executor");
        let lease = root
            .thread()
            .claim_runnable(executor)
            .expect("claim leader");
        let published = process
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::VFORK | carrick_abi::LinuxCloneFlags::VM,
                )
                .expect("vfork plan"),
                "persistent exec-stop vfork parent".to_owned(),
                None,
            )
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(70_105))
            .expect("prepare vfork child")
            .commit()
            .expect("publish vfork child");
        let (vfork_child, vfork_wait) = published.into_parts().expect("start vfork child");
        let current = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("recapture vfork parent");
        let continuation = continuation::BlockedContinuation::from_vfork_parent(
            continuation::ContinuationCapture::from_lease(
                &current,
                &lease,
                SyscallRequest::new(220, crate::compat::SyscallArgs([0; 6])),
                continuation::RestartClass::RestartSyscall,
                continuation::ContinuationBackend::Hvpatch,
            )
            .expect("capture vfork parent"),
            vfork_child.task().key(),
            vfork_wait.expect("vfork parent wait"),
        )
        .expect("construct vfork parent continuation");
        root.thread()
            .scheduler_park_continuation_from_executor(
                lease,
                crate::kernel::objects::BlockedReason::ChildState,
                continuation,
            )
            .map_err(|(error, _)| error)
            .expect("block vfork leader");
        let directory = HvpatchRuntimeDirectory::default();
        let (scheduler, _) = directory.continuation_services(root.kernel());

        threads::wake_removed_persistent_sibling_threads(
            &sibling,
            &scheduler,
            &[ThreadId::synthetic_for_tests(root.thread().key().tid.raw())],
        )
        .expect("wake exact removed leader");

        assert!(matches!(
            root.thread().execution_state(),
            crate::kernel::objects::ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(scheduler.queued_len(), 1);
        let claimed = root
            .thread()
            .claim_runnable(executor)
            .expect("claim control-woken vfork parent");
        assert!(
            claimed
                .blocked_continuation()
                .expect("preserved vfork continuation")
                .ready_event()
                .is_err(),
            "terminal control wake must not manufacture guest vfork readiness",
        );
        root.thread()
            .exit_from_executor(claimed)
            .expect("retire control-woken vfork parent");
    }

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
