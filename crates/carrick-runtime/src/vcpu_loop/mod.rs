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
//! ([`ThreadRuntimeState::pt_pause`]). The `in_guest` ↔ `quiescing` Dekker
//! handshake (SeqCst on both sides) is preserved verbatim in
//! `run_vcpu_until_exit`.

use std::collections::BTreeMap;
use std::os::fd::IntoRawFd;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use carrick_hal::{PlatformFutex, SignalPumpControl, ThreadedEngine, VcpuRegistry};

use crate::compat::CompatReporter;
use crate::dispatch::{
    CurrentMmMemory, DispatchError, DispatchOutcome, ProcMapSharing, ProcMapsEntry,
    SyscallDispatcher, SyscallRequest,
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

/// Whether this syscall must take the process-wide page-table pause BEFORE the
/// dispatcher runs — see the call site in `service_threaded_syscall` for the
/// lock-order argument. `arg2` is the third syscall argument (madvise's
/// `advice`); it is ignored for every other number.
fn syscall_takes_pre_dispatch_pt_pause(number: u64, arg2: u64, multi_vcpu: bool) -> bool {
    if !multi_vcpu {
        return false;
    }
    syscall_edits_stage1(number, arg2)
}

/// Whether this syscall edits stage-1 descriptors at all, independent of how
/// many threads exist. Split out from the pause predicate because the two
/// answers are used for different things: a peer executor decides whether a
/// PAUSE is needed, while editing stage-1 at all decides whether this thread
/// should claim stage-1 EXCLUSIVITY for the dispatch — which it holds either
/// way, since with no peer executor there is nobody to be exclusive against.
fn syscall_edits_stage1(number: u64, arg2: u64) -> bool {
    crate::dispatch::syscall_requires_mm_mutation(
        number,
        crate::compat::SyscallArgs::from([0, 0, arg2, 0, 0, 0]),
    )
}

/// Restores the guest-visible `Running` state when a guest-blocking wait ends.
///
/// Deliberately owns no borrow of the run state: the blocking arms it wraps
/// need `&mut self` for `complete_errno`/`complete_returned`, so a guard
/// holding `&self` could not coexist with them. It carries the identity it
/// publishes under instead, which is fixed for the life of the thread.
fn apply_alias_frame_inventory(
    context: &crate::kernel::KernelContext,
    commit: carrick_hal::FrameInventoryCommit<()>,
) -> Result<(), crate::kernel::FrameInventoryError> {
    context
        .kernel()
        .frame_inventory()
        .apply(context.shared().mm().id(), commit)
        .map(|_| ())
}

struct KernelFrameCowAuthority {
    kernel: Arc<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
    /// Exact-MM admission plus every participant's opaque pause endpoint.
    guest_executors: Arc<crate::kernel::GuestExecutorCensus>,
    tid: carrick_hal::ThreadId,
    identity: carrick_hal::FrameCowIdentity,
}

impl KernelFrameCowAuthority {
    #[allow(dead_code)] // consumed by the HVPatch child publication slice
    fn issue_hvpatch_child_token(
        self: Arc<Self>,
        context: &crate::kernel::KernelContext,
    ) -> Result<carrick_hal::HvpatchChildKernelToken, String> {
        if self.identity.linux_tid != self.tid.raw()
            || self.identity.mm != self.mm.raw()
            || self.identity.asid == 0
        {
            return Err("child token identity does not match Kernel COW authority".to_owned());
        }
        static NEXT_AUTHORITY_ID: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let raw = NEXT_AUTHORITY_ID
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| current.checked_add(1),
            )
            .map_err(|_| "child COW authority identity exhausted".to_owned())?;
        let authority_identity = std::num::NonZeroU64::new(raw)
            .ok_or_else(|| "child COW authority identity is zero".to_owned())?;
        let identity = self.identity;
        let authority: Arc<dyn carrick_hal::FrameCowAuthority> = self;
        context
            .issue_hvpatch_child_token(authority, identity, authority_identity)
            .map_err(|error| format!("issue exact HVPatch child token: {error}"))
    }
}

impl carrick_hal::FrameCowAuthority for KernelFrameCowAuthority {
    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        quiesce::acquire_frame_cow_quiesce(
            quiesce::pt_barrier(),
            self.mm,
            &self.guest_executors,
            self.tid,
            quiesce::PtPauseBudget::DEFAULT,
        )
        .map(|guard| Box::new(guard) as Box<dyn carrick_hal::FrameCowQuiesce>)
        .map_err(|error| {
            Box::new(std::io::Error::other(format!(
                "HVPatch frame-COW vCPU quiesce failed: {error:?}"
            ))) as Box<dyn std::error::Error + Send + Sync>
        })
    }

    fn reserve(
        &self,
        frame_candidates: usize,
        mapping_candidates: usize,
        event_count: usize,
    ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
    {
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(event_count)?;
        self.kernel
            .reserve_frame_inventory(frame_candidates, mapping_candidates, capacity)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn apply(
        &self,
        commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.kernel
            .frame_inventory()
            .apply(self.mm, commit)
            .map(|_| ())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    fn mapping_is_live(
        &self,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let inventory = self.kernel.frame_inventory();
        if inventory.mapping_is_live_exact(self.mm, mapping, frame, gpa, length) {
            return Ok(true);
        }
        let candidates: Vec<_> = inventory
            .snapshot()
            .mappings
            .into_iter()
            .filter(|row| {
                row.mapping == mapping
                    || row.frame == frame
                    || (row.gpa == gpa && row.length == length)
            })
            .take(16)
            .collect();
        Err(Box::new(std::io::Error::other(format!(
            "frame mapping is not exact-live: expected mm={:?} mapping={mapping:?} frame={frame:?} gpa={gpa:?} length={} candidates={candidates:?}",
            self.mm,
            length.raw(),
        ))))
    }

    fn frame_mapping_count(
        &self,
        frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.kernel.frame_inventory().frame_mapping_count(frame))
    }
}

/// HVPatch multiplexes every Linux process inside one carrier, so no guest exit
/// is ever a host-process exit: the terminal owner always unwinds. This was
/// true only for the retired host-fork lanes, where a forked child had to
/// `_exit` without running Drop over its parent's inherited fd table.
pub(super) fn requires_no_unwind_host_exit(kernel: &Kernel, engine_is_forked_child: bool) -> bool {
    let _ = (kernel, engine_is_forked_child);
    false
}

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
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
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
            use carrick_hal::GuestArch as _;
            type KvmArch = <carrick_vmm_kvm::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch;
            let linux_page_size = dispatcher.linux_page_size();
            match raw
                .with_vdso_bytes(KvmArch::vdso_bytes())
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
        let image = {
            use carrick_hal::GuestArch as _;
            let linux_page_size = dispatcher.linux_page_size();
            match raw
                .with_vdso_bytes(carrick_hal::x8664_arch::X8664GuestArch::vdso_bytes())
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
mod exec;
pub(crate) mod quiesce;
mod signal;
mod threads;

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
// the arch crate; the ESR decode itself lives in carrick_dsr_aarch64::esr and
// signal.rs re-exports it.
#[cfg(test)]
use signal::el0_debug_signal;

// ===================================================================
// Cross-platform kernel-half state.
// ===================================================================

/// Runtime-only delivery endpoint for one live HVPatch task generation.
/// Linux parentage remains authoritative in `Kernel`; this table only turns
/// the parent key selected there into the host wake objects needed to deliver
/// the configured child-exit signal.
#[derive(Clone)]
struct HvpatchRuntimeEndpoint {
    kernel: Weak<KernelState>,
    /// Exact parent task generation retained at endpoint publication. Each
    /// notification recaptures one CURRENT live thread through this binding so
    /// exec's replacement Sighand is observed without accepting PID reuse.
    task_binding: crate::kernel::KernelTaskBinding,
    /// Migration-only exact scheduler endpoint. While absent, the welded
    /// runner below remains the explicitly transitional fallback. When
    /// present, exact-generation scheduler wake is authoritative and the
    /// legacy wake vehicles are compatibility nudges only.
    scheduler: Option<Arc<crate::kernel::scheduler::Scheduler>>,
}

impl HvpatchRuntimeEndpoint {
    fn wake_scheduler_exact(
        &self,
        snapshot: &crate::kernel::core::KernelTaskSignalSnapshot,
    ) -> Result<bool, crate::kernel::scheduler::SchedulerError> {
        let Some(scheduler) = self.scheduler.as_ref() else {
            return Ok(false);
        };
        let mut delivered = false;
        for thread in snapshot.threads() {
            match scheduler.wake(thread.key()) {
                Ok(_) => delivered = true,
                Err(
                    crate::kernel::scheduler::SchedulerError::Thread(
                        crate::kernel::objects::ThreadExecutionError::InvalidTransition { .. },
                    )
                    | crate::kernel::scheduler::SchedulerError::UnknownThread,
                ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(delivered)
    }
}

/// The kernel lane's [`TaskWaker`](crate::kernel::TaskWaker): the three vehicles a guest task on this
/// lane can be parked on, kicked together.
///
/// A parked guest is waiting on one of them and the kernel cannot tell which,
/// so all three fire. Each is a hint — the woken thread re-reads the
/// authoritative pending queue — which is what makes kicking all three safe
/// rather than merely wasteful.
///
/// These are the SAME objects child-exit notification has always used; routing
/// both through one waker is what keeps a single answer to "how is a task on
/// this lane woken".
struct HvpatchTaskWaker {
    /// Unparks a `FUTEX_WAIT`, and the futex-backed waits layered on it.
    futex: Arc<FutexTable>,
    /// Forces the vCPU out of `hv_vcpu_run` so a RUNNING guest reaches a
    /// boundary where it polls. Process-scoped, which is correct here: the
    /// waker is registered per Linux process with that process's own kicker.
    kicker: Arc<dyn VcpuRegistry>,
    /// Writes the wake pipes every parked `ThreadWaiter` kqueue watches.
    signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
}

impl std::fmt::Debug for HvpatchTaskWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HvpatchTaskWaker")
    }
}

impl crate::kernel::TaskWaker for HvpatchTaskWaker {
    fn wake_task(&self) {
        self.futex.notify_signal_pending();
        // Shared (`MAP_SHARED`) futex waiters park in the CARRIER-wide table,
        // not this process's — a wake that only pokes `self.futex` leaves a
        // shared waiter asleep until its timeout. Concretely: `tgkill` posts
        // the signal and comes through here; before this line, a target parked
        // in `tst_checkpoint_wait` never noticed the pending signal and the
        // sender's delivery handshake stalled its full 10 s (`tgkill01`).
        carrick_thread::platform_futex::carrier_shared_futex_table().notify_signal_pending();
        self.signal_arrival.wake_all_waiters();
        self.kicker.kick_all();
    }
}

#[derive(Default)]
pub(crate) struct HvpatchRuntimeDirectory {
    endpoints: Mutex<BTreeMap<crate::kernel::TaskKey, HvpatchRuntimeEndpoint>>,
    continuation_wait_service: Mutex<Option<Arc<continuation::CarrierWaitService>>>,
    scheduler: Mutex<Option<Arc<crate::kernel::scheduler::Scheduler>>>,
    persistent_bindings: Arc<executor::HvpatchTaskBindingDirectory>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    carrier_tasks:
        Mutex<Option<Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>>>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    persistent_pool: Mutex<
        Option<
            executor::ExecutorPool<
                executor::HvpatchPersistentExecutorFactory,
                executor::HvpatchTaskBindingDirectory,
            >,
        >,
    >,
    /// Carrier-owned logical process jobs. No process child owns a host thread;
    /// the root waits these exact completions before shutting the shared pool.
    process_jobs: Mutex<Vec<HvpatchProcessJobHandle>>,
}

enum HvpatchProcessJobHandle {
    Persistent {
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
    },
}

impl HvpatchRuntimeDirectory {
    fn persistent_bindings(&self) -> &Arc<executor::HvpatchTaskBindingDirectory> {
        &self.persistent_bindings
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn carrier_tasks(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory> {
        let mut installed = self.carrier_tasks.lock();
        Arc::clone(installed.get_or_insert_with(|| {
            static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 =
                std::sync::atomic::AtomicU64::new(1);
            let raw = NEXT_DIRECTORY
                .fetch_update(
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                    |current| current.checked_add(1),
                )
                .unwrap_or_else(|_| std::process::abort());
            let instance = std::num::NonZeroU64::new(raw).unwrap_or_else(|| std::process::abort());
            Arc::new(
                carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory::new(
                    instance,
                    kernel.hvpatch_child_token_verifier(),
                ),
            )
        }))
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn start_persistent_pool(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        authority: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPersistentExecutorFactoryAuthority,
        vcpu_ceiling: usize,
    ) -> Result<bool, RuntimeError> {
        let mut pool = self.persistent_pool.lock();
        if pool.is_some() {
            return Ok(false);
        }
        let (scheduler, _service) = self.continuation_services(kernel);
        self.persistent_bindings
            .install_scheduler(&scheduler)
            .map_err(RuntimeError::Trap)?;
        let physical_cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        let factory = Arc::new(executor::HvpatchPersistentExecutorFactory::new(authority));
        let started = executor::ExecutorPool::start(
            executor::ExecutorPoolConfig {
                physical_cores,
                vcpu_ceiling,
                reserve: 0,
            },
            scheduler,
            factory,
            Arc::clone(&self.persistent_bindings),
            executor::ExecutorBoundaryAudit,
        )
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        *pool = Some(started);
        Ok(true)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn shutdown_persistent_pool(&self) -> Result<(), RuntimeError> {
        let Some(pool) = self.persistent_pool.lock().take() else {
            return Ok(());
        };
        tracing::info!("HVPatch persistent pool shutdown begins (run queue will close)");
        pool.shutdown()
            .map(|_| ())
            .map_err(|error| RuntimeError::Configuration(error.to_string()))
    }

    fn continuation_services(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
    ) -> (
        Arc<crate::kernel::Scheduler>,
        Arc<continuation::CarrierWaitService>,
    ) {
        let scheduler =
            {
                let mut slot = self.scheduler.lock();
                Arc::clone(slot.get_or_insert_with(|| {
                    Arc::new(crate::kernel::Scheduler::new(Arc::clone(kernel)))
                }))
            };
        for endpoint in self.endpoints.lock().values_mut() {
            if endpoint.scheduler.is_none() {
                endpoint.scheduler = Some(Arc::clone(&scheduler));
            }
        }
        let service = {
            let mut slot = self.continuation_wait_service.lock();
            Arc::clone(slot.get_or_insert_with(|| {
                Arc::new(continuation::CarrierWaitService::new(Arc::clone(
                    &scheduler,
                )))
            }))
        };
        (scheduler, service)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Task 4 installs the persistent executor scheduler through this packaged seam"
        )
    )]
    pub(crate) fn install_scheduler(
        &self,
        scheduler: Arc<crate::kernel::scheduler::Scheduler>,
    ) -> Result<(), RuntimeError> {
        let mut installed = self.scheduler.lock();
        if installed.is_some() || !self.endpoints.lock().is_empty() {
            return Err(RuntimeError::Unsupported(
                "HVPatch scheduler must be installed exactly once before endpoint publication"
                    .to_owned(),
            ));
        }
        *installed = Some(scheduler);
        Ok(())
    }

    fn register_endpoint(
        &self,
        task: crate::kernel::TaskKey,
        kernel: Weak<KernelState>,
        task_binding: crate::kernel::KernelTaskBinding,
    ) {
        let scheduler = self.scheduler.lock().clone();
        self.register(
            task,
            HvpatchRuntimeEndpoint {
                kernel,
                task_binding,
                scheduler,
            },
        );
    }

    fn register(&self, task: crate::kernel::TaskKey, endpoint: HvpatchRuntimeEndpoint) {
        self.endpoints.lock().insert(task, endpoint);
    }

    /// Wake every registered task's parked vehicles so they re-check pending
    /// signal state. The process-directed signal lane's host publication
    /// (`PROC_PENDING`) carries no task identity, so arrival is a carrier
    /// broadcast; `task.wake()` is a hint and spurious wakes are harmless.
    /// Without this, a thread parked in a non-futex continuation (wait4's
    /// `WaitOnHvpatchChild`) never observed a process-directed SIGALRM: the
    /// pump's `kick_all` reaches only live vCPU leases and its futex notify
    /// only enrolled futex waiters (the `waitrestart` hang).
    fn wake_all_tasks_for_process_signal(&self) {
        let debug = std::env::var_os("CARRICK_SIG_DEBUG").is_some();
        let endpoints: Vec<HvpatchRuntimeEndpoint> =
            self.endpoints.lock().values().cloned().collect();
        if debug {
            eprintln!(
                "SIGDBG process-wake broadcast: endpoints={}",
                endpoints.len()
            );
        }
        for endpoint in endpoints {
            if endpoint.kernel.upgrade().is_none() {
                continue;
            }
            let Ok(snapshot) = endpoint.task_binding.capture_signal_snapshot() else {
                if debug {
                    eprintln!("SIGDBG process-wake broadcast: stale binding skipped");
                }
                continue;
            };
            let woken = snapshot.context().task().wake();
            if debug {
                eprintln!(
                    "SIGDBG process-wake broadcast: task={:?} subscribed_wake={}",
                    snapshot.context().task().key(),
                    woken
                );
            }
        }
    }

    fn remove(&self, task: crate::kernel::TaskKey) {
        self.endpoints.lock().remove(&task);
    }

    fn enroll_persistent_process_job(
        &self,
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
    ) {
        self.process_jobs
            .lock()
            .push(HvpatchProcessJobHandle::Persistent { result, completion });
    }

    fn join_process_threads(&self) -> Result<(), RuntimeError> {
        // Carry the joined children's actual failure payloads into the
        // terminal clause: the bare "HVPatch process child panicked" summary
        // hid the root cause behind a generic string (14 gate-14 rows were
        // indistinguishable until their stderr tails were exhumed one by
        // one), and a 2-line stderr tail can cut the tracing line that held
        // the detail.
        let mut child_errors: Vec<String> = Vec::new();
        loop {
            let jobs = std::mem::take(&mut *self.process_jobs.lock());
            if jobs.is_empty() {
                return match child_errors.first() {
                    Some(first) => Err(RuntimeError::Unsupported(format!(
                        "HVPatch process child panicked ({} failed): first: {first}",
                        child_errors.len()
                    ))),
                    None => Ok(()),
                };
            }
            for job in jobs {
                let result = match job {
                    HvpatchProcessJobHandle::Persistent { result, completion } => {
                        let _completion_identity = completion.id();
                        result.wait()
                    }
                };
                if let Err(error) = result {
                    tracing::error!(%error, "HVPatch process job failed");
                    child_errors.push(error.to_string());
                }
            }
            // A joined child may have forked another process before it left.
            // Drain repeatedly until the shared topology census is empty, even
            // after a panic, so no remaining shared-VM owner is detached.
        }
    }

    fn notify_child_exit(&self, parent: crate::kernel::TaskKey, signal: Option<i32>) {
        let Some(endpoint) = self.endpoints.lock().get(&parent).cloned() else {
            return;
        };
        let Some(parent_kernel) = endpoint.kernel.upgrade() else {
            return;
        };
        let Ok(signal_snapshot) = endpoint.task_binding.capture_signal_snapshot() else {
            return;
        };
        let signal_context = signal_snapshot.context();
        if let Some(signal) = signal
            && parent_kernel
                .dispatcher
                .child_exit_signal_snapshot_needs_pump(&signal_snapshot, signal as u32)
        {
            parent_kernel
                .dispatcher
                .mark_in_process_signal_pending(signal_context, signal);
        }
        // Child waitability is independent of SIGCHLD disposition. The Kernel
        // zombie is durable, but a parent can be between its initial wait query
        // and host-wait enrollment when publication occurs; always nudge every
        // wait vehicle so it rechecks the authoritative graph even when SIGCHLD
        // is ignored or blocked.
        let _ = signal_context.task().publish_wake_subscriptions();
        if let Err(error) = endpoint.wake_scheduler_exact(&signal_snapshot) {
            tracing::error!(parent = ?parent, %error, "authoritative scheduler wake rejected");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloneAdmissionClose {
    Exec { owner: ThreadId, generation: u64 },
    Fork { owner: ThreadId, generation: u64 },
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloneAdmissionKind {
    ThreadClone,
    ProcessFork { owner: ThreadId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessExitClaim {
    Owner,
    LostToExec,
    AlreadyOwned,
    Pending,
}

type CloneAdmissionListener = Arc<dyn Fn() + Send + Sync + 'static>;
type CloneAdmissionListeners = BTreeMap<u64, (u64, CloneAdmissionListener)>;

#[derive(Default)]
struct CloneAdmissionState {
    in_flight: usize,
    generation: u64,
    closing: Option<CloneAdmissionClose>,
    change_epoch: u64,
    next_listener: u64,
    listeners: CloneAdmissionListeners,
}

#[derive(Default)]
struct CloneAdmissionGate {
    state: Mutex<CloneAdmissionState>,
    changed: Condvar,
}

struct CloneAdmissionChangeSubscription {
    gate: Weak<CloneAdmissionGate>,
    id: u64,
    expected_epoch: u64,
}

impl Drop for CloneAdmissionChangeSubscription {
    fn drop(&mut self) {
        let Some(gate) = self.gate.upgrade() else {
            return;
        };
        let mut state = gate.state.lock();
        if state
            .listeners
            .get(&self.id)
            .is_some_and(|(epoch, _)| *epoch == self.expected_epoch)
        {
            state.listeners.remove(&self.id);
        }
    }
}

impl CloneAdmissionGate {
    fn change_epoch(&self) -> u64 {
        self.state.lock().change_epoch
    }

    fn subscribe_change(
        self: &Arc<Self>,
        expected_epoch: u64,
        callback: Arc<dyn Fn() + Send + Sync + 'static>,
    ) -> Option<CloneAdmissionChangeSubscription> {
        let mut state = self.state.lock();
        if state.change_epoch != expected_epoch {
            drop(state);
            callback();
            return None;
        }
        state.next_listener = state
            .next_listener
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let id = state.next_listener;
        state.listeners.insert(id, (expected_epoch, callback));
        Some(CloneAdmissionChangeSubscription {
            gate: Arc::downgrade(self),
            id,
            expected_epoch,
        })
    }

    fn try_enroll_kind(self: &Arc<Self>, kind: CloneAdmissionKind) -> Option<CloneAdmissionPermit> {
        let mut state = self.state.lock();
        if state.closing.is_some() {
            return None;
        }
        state.in_flight = state.in_flight.checked_add(1)?;
        Some(CloneAdmissionPermit {
            gate: Arc::clone(self),
            generation: state.generation,
            kind,
            active: true,
        })
    }

    fn try_enroll_thread_clone(self: &Arc<Self>) -> Option<CloneAdmissionPermit> {
        self.try_enroll_kind(CloneAdmissionKind::ThreadClone)
    }

    pub(crate) fn try_enroll_process_fork(
        self: &Arc<Self>,
        owner: ThreadId,
    ) -> Option<CloneAdmissionPermit> {
        self.try_enroll_kind(CloneAdmissionKind::ProcessFork { owner })
    }

    fn close_for_exec(
        self: &Arc<Self>,
        owner: ThreadId,
    ) -> Result<ExecCloneAdmission, RuntimeError> {
        let mut state = self.state.lock();
        let generation = state.generation;
        match state.closing {
            None | Some(CloneAdmissionClose::Fork { .. }) => {
                // Exec is destructive and wins a race with an ordinary fork.
                // Promoting the close reason makes the fork permit observe
                // cancellation and drain itself before exec proceeds.
                state.closing = Some(CloneAdmissionClose::Exec { owner, generation });
            }
            Some(reason) => {
                return Err(RuntimeError::Unsupported(format!(
                    "cannot begin exec while clone admission is closing: {reason:?}"
                )));
            }
        }
        self.changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.in_flight != 0 {
            let now = Instant::now();
            if now >= deadline {
                state.closing = None;
                state.generation = state.generation.wrapping_add(1);
                self.changed.notify_all();
                return Err(RuntimeError::Unsupported(format!(
                    "exec clone-admission drain timed out: in_flight={}",
                    state.in_flight
                )));
            }
            self.changed
                .wait_for(&mut state, (deadline - now).min(Duration::from_millis(50)));
        }
        Ok(ExecCloneAdmission {
            gate: Arc::clone(self),
            owner,
            generation,
        })
    }

    fn try_close_for_fork(
        self: &Arc<Self>,
        owner: ThreadId,
        generation: u64,
    ) -> Result<Option<ForkCloneAdmission>, RuntimeError> {
        let mut state = self.state.lock();
        let close = CloneAdmissionClose::Fork { owner, generation };
        if state.generation != generation || state.closing.is_some_and(|current| current != close) {
            return Err(RuntimeError::Unsupported(
                "cannot begin fork while clone admission is closing".to_owned(),
            ));
        }
        state.closing = Some(close);
        self.changed.notify_all();
        // The caller's own process-fork permit remains enrolled. Every other
        // permit belongs to a thread clone admitted before the fork close and
        // must finish normally before the task snapshot can be reserved.
        if state.in_flight != 1 {
            return Ok(None);
        }
        Ok(Some(ForkCloneAdmission {
            gate: Arc::clone(self),
            owner,
            generation,
        }))
    }

    fn try_claim_process_exit(&self) -> Result<ProcessExitClaim, RuntimeError> {
        let mut state = self.state.lock();
        match state.closing {
            Some(CloneAdmissionClose::Exec { .. }) => return Ok(ProcessExitClaim::LostToExec),
            Some(CloneAdmissionClose::Fork { .. }) => {
                state.closing = Some(CloneAdmissionClose::Exit);
            }
            Some(CloneAdmissionClose::Exit) => {}
            None => state.closing = Some(CloneAdmissionClose::Exit),
        }
        self.changed.notify_all();
        if state.in_flight == 0 {
            Ok(ProcessExitClaim::Owner)
        } else {
            Ok(ProcessExitClaim::Pending)
        }
    }
}

struct CloneAdmissionPermit {
    gate: Arc<CloneAdmissionGate>,
    generation: u64,
    kind: CloneAdmissionKind,
    active: bool,
}

impl CloneAdmissionPermit {
    fn is_cancelled(&self) -> bool {
        let state = self.gate.state.lock();
        if state.generation != self.generation {
            return true;
        }
        match state.closing {
            Some(CloneAdmissionClose::Exec { .. } | CloneAdmissionClose::Exit) => true,
            Some(CloneAdmissionClose::Fork { owner, generation }) => match self.kind {
                CloneAdmissionKind::ThreadClone => false,
                CloneAdmissionKind::ProcessFork {
                    owner: permit_owner,
                } => permit_owner != owner || self.generation != generation,
            },
            None => false,
        }
    }

    fn try_close_for_fork(
        &self,
        owner: ThreadId,
    ) -> Result<Option<ForkCloneAdmission>, RuntimeError> {
        if self.kind != (CloneAdmissionKind::ProcessFork { owner }) {
            return Err(RuntimeError::Unsupported(
                "fork close requires the matching process-fork permit".to_owned(),
            ));
        }
        self.gate.try_close_for_fork(owner, self.generation)
    }
}

impl Drop for CloneAdmissionPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.gate.state.lock();
        let Some(in_flight) = state.in_flight.checked_sub(1) else {
            std::process::abort();
        };
        state.in_flight = in_flight;
        self.active = false;
        state.change_epoch = state
            .change_epoch
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let callbacks = std::mem::take(&mut state.listeners)
            .into_values()
            .map(|(_, callback)| callback)
            .collect::<Vec<_>>();
        if state.in_flight == 0 || state.closing.is_some() {
            self.gate.changed.notify_all();
        }
        drop(state);
        for callback in callbacks {
            callback();
        }
    }
}

struct ForkCloneAdmission {
    gate: Arc<CloneAdmissionGate>,
    owner: ThreadId,
    generation: u64,
}

impl Drop for ForkCloneAdmission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        if state.closing
            == Some(CloneAdmissionClose::Fork {
                owner: self.owner,
                generation: self.generation,
            })
        {
            state.closing = None;
            self.gate.changed.notify_all();
        }
    }
}

struct ExecCloneAdmission {
    gate: Arc<CloneAdmissionGate>,
    owner: ThreadId,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FatalSignalRecord {
    image_generation: u64,
    tid: crate::kernel::LinuxTid,
    signo: i32,
    code: i32,
    addr: u64,
}

fn core_note_resume_pair(
    registers: &carrick_hal::Aarch64CoreRegisters,
    synchronous_fatal_owner: bool,
) -> (u64, u64) {
    if synchronous_fatal_owner {
        (registers.elr_el1, registers.spsr_el1)
    } else {
        (registers.resume_pc, registers.resume_pstate)
    }
}

#[derive(Debug)]
struct FatalSignalState {
    image_generation: u64,
    recorded: Option<FatalSignalRecord>,
}

impl Default for FatalSignalState {
    fn default() -> Self {
        Self {
            image_generation: 1,
            recorded: None,
        }
    }
}

#[derive(Debug, Default)]
struct FatalSignalAuthority(Mutex<FatalSignalState>);

impl FatalSignalAuthority {
    fn current_generation(&self) -> u64 {
        self.0.lock().image_generation
    }

    /// Rebind write-once fatal authority to the replacement exec image.  The
    /// expected generation prevents a stale exec owner from clearing a newer
    /// image's fatal record.
    fn rebind_after_exec(&self, expected_generation: u64) -> Option<u64> {
        let mut state = self.0.lock();
        if state.image_generation != expected_generation {
            return None;
        }
        let next = state.image_generation.checked_add(1)?;
        state.image_generation = next;
        state.recorded = None;
        Some(next)
    }

    /// Publish at most one fatal record for the image generation that produced
    /// it. A pre-exec loser that arrives after the replacement is committed is
    /// rejected rather than poisoning the new image's later crash authority.
    fn record(&self, record: FatalSignalRecord) -> bool {
        let mut state = self.0.lock();
        if state.image_generation != record.image_generation || state.recorded.is_some() {
            return false;
        }
        state.recorded = Some(record);
        true
    }

    fn recorded_for(&self, image_generation: u64) -> Option<FatalSignalRecord> {
        let state = self.0.lock();
        (state.image_generation == image_generation)
            .then_some(state.recorded)
            .flatten()
    }
}

fn fatal_for_terminal_owner(
    recorded: Option<FatalSignalRecord>,
    image_generation: u64,
    owner: crate::kernel::LinuxTid,
    terminating_signal: Option<i32>,
) -> Option<FatalSignalRecord> {
    recorded.filter(|fatal| {
        fatal.image_generation == image_generation
            && fatal.tid == owner
            && terminating_signal == Some(fatal.signo)
    })
}

impl Drop for ExecCloneAdmission {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        if state.closing
            == Some(CloneAdmissionClose::Exec {
                owner: self.owner,
                generation: self.generation,
            })
        {
            state.closing = None;
            state.generation = state.generation.wrapping_add(1);
            self.gate.changed.notify_all();
        }
    }
}

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
    persistent_exit_owner: std::sync::atomic::AtomicI32,
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
            persistent_exit_owner: std::sync::atomic::AtomicI32::new(0),
            process_fork_barrier,
            crash_capture,
            clone_admission: Arc::new(CloneAdmissionGate::default()),
            hvpatch_runtime,
            child_exit_signal,
            process_terminal: Mutex::new(None),
            process_terminal_ready: Condvar::new(),
            fatal_signal: FatalSignalAuthority::default(),
            control_exec: Mutex::new(None),
            external_exec: Mutex::new(None),
        }
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
            std::process::abort();
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

    fn enroll_hvpatch_persistent_process_job(
        &self,
        result: HvpatchLoopResult,
        completion: continuation::LogicalJobCompletion,
    ) {
        if let Some(runtime) = &self.hvpatch_runtime {
            runtime.enroll_persistent_process_job(result, completion);
        }
    }

    pub(crate) fn join_hvpatch_process_threads(&self) -> Result<(), RuntimeError> {
        match self.hvpatch_runtime.as_ref() {
            Some(directory) => directory.join_process_threads(),
            None => Ok(()),
        }
    }

    fn notify_hvpatch_parent_exit(&self, parent: Option<crate::kernel::TaskKey>) {
        if let (Some(parent), Some(directory)) = (parent, self.hvpatch_runtime.as_ref()) {
            directory.notify_child_exit(parent, self.child_exit_signal);
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
    }

    fn try_claim_persistent_process_exit(
        &self,
        owner: ThreadId,
    ) -> Result<ProcessExitClaim, RuntimeError> {
        let owner_raw = owner.raw();
        match self.persistent_exit_owner.compare_exchange(
            0,
            owner_raw,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(current) if current == owner_raw => {}
            Err(_) => return Ok(ProcessExitClaim::AlreadyOwned),
        }
        let claim = self.clone_admission.try_claim_process_exit()?;
        if claim == ProcessExitClaim::Owner {
            self.begin_process_exit();
        }
        Ok(claim)
    }

    pub(crate) fn process_exiting(&self) -> bool {
        self.process_exiting
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn try_enroll_thread_clone(&self) -> Option<CloneAdmissionPermit> {
        self.clone_admission.try_enroll_thread_clone()
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
            std::process::abort();
        }
    }
}

/// Enter sole-executor stage-1 authority only from an exact-MM census token.
/// Normalized handlers receive no such token.
pub(crate) fn with_sole_mm_stage1<T>(
    participation: &mut crate::dispatch::MmExecutorParticipation,
    run: impl FnOnce(&mut quiesce::SoleMmStage1<'_>) -> T,
) -> Option<T> {
    let mut authority = quiesce::SoleMmStage1::claim(participation)?;
    Some(run(&mut authority))
}

#[cfg(test)]
pub(crate) fn with_real_pt_pause_for_test<T>(
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    run: impl FnOnce(&mut quiesce::PtPauseGuard<'_>) -> T,
) -> T {
    quiesce::with_real_mutation_pause_for_test(coordinator, run)
}

#[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
pub(crate) fn with_foreign_mm_mutation_guard<T>(
    mm: crate::kernel::MmId,
    coordinator: Arc<crate::dispatch::mm_mutation::MmMutationCoordinator>,
    census: &crate::kernel::GuestExecutorCensus,
    stage1: Arc<crate::hvpatch::Stage1MmLease>,
    tid: carrick_hal::ThreadId,
    run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
) -> Result<T, crate::dispatch::mm_mutation::ForeignMmMutationError> {
    let mut authority = quiesce::acquire_foreign_mm_mutation_quiesce(
        quiesce::pt_barrier(),
        mm,
        census,
        coordinator,
        stage1,
        tid,
        quiesce::PtPauseBudget::DEFAULT,
    )
    .map_err(|error| match error {
        quiesce::PtPauseError::TimedOut => {
            crate::dispatch::mm_mutation::ForeignMmMutationError::TimedOut
        }
        quiesce::PtPauseError::UnkickableExecutor => {
            crate::dispatch::mm_mutation::ForeignMmMutationError::UnkickableExecutor
        }
    })?;
    let mut mutation = crate::dispatch::mm_mutation::from_frame_cow(&mut authority);
    Ok(run(&mut mutation))
}

/// Hand the dispatcher the loaded image's region list + auxv so /proc/self/maps
/// and /proc/self/auxv reflect it (refreshed on each execve).
pub(crate) fn apply_image_proc_state(
    dispatcher: &mut SyscallDispatcher,
    image: &AddressSpace,
) -> Result<(), DispatchError> {
    dispatcher.publish_initial_image_state(
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
    )
}

/// Publish a successful exec image as one dispatcher VMA generation.
pub(crate) fn apply_exec_image_proc_state(
    dispatcher: &SyscallDispatcher,
    replacement_mm_id: crate::kernel::MmId,
    image: &AddressSpace,
) -> crate::dispatch::PreparedDispatchMmExec {
    dispatcher.publish_exec_image_state(
        replacement_mm_id,
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
    )
}

fn core_file_mappings_from_address_space(
    image: &AddressSpace,
) -> Vec<crate::core_dump::FileMapping> {
    image
        .file_mappings()
        .iter()
        .filter(|mapping| !mapping.path.is_empty())
        .map(|mapping| crate::core_dump::FileMapping {
            start: mapping.start,
            end: mapping.end,
            file_page_offset: mapping.file_page_offset,
            path: mapping.path.clone(),
        })
        .collect()
}

/// Stamp the per-process identity page the EL1 syscall shim reads (no-op unless
/// the shim is enabled). Must run before the guest issues any intercepted
/// syscall: at boot, and again in a forked child / after execve, since the
/// child's pid and the new image's identity differ.
pub(crate) fn stamp_identity_page<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
) -> Result<(), carrick_guest_mem::MemoryError> {
    stamp_identity_page_at(
        memory,
        dispatcher,
        kernel_context,
        crate::memory::LINUX_IDENTITY_PAGE_BASE,
    )
}

fn stamp_identity_page_at<M: CurrentMmMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    base: u64,
) -> Result<(), carrick_guest_mem::MemoryError> {
    if !crate::syscall_shim_enabled() {
        return Ok(());
    }
    let id = dispatcher.identity_snapshot(kernel_context);
    // FAIL CLOSED on an unpublishable identity.
    //
    // `getpid()` never returns 0 on Linux, so a zero here means the identity
    // is not knowable yet rather than that it is zero — a pid-namespace
    // translation that has not been registered resolves to 0 through the
    // `unwrap_or(0)` in `identity_pid`. Opening the fast-path gate over that
    // publishes a pid no Linux process has, and the guest reads it in
    // userspace with NO vm exit, so nothing ever re-checks it. Observed as a
    // container's init reporting `getpid=0`.
    //
    // Leaving the gate SHUT costs only speed: the guest traps and the
    // dispatcher answers correctly. A later stamp re-opens it once the
    // identity is real.
    let shim_enabled = identity_gate_word(dispatcher.identity_fast_path_enabled(), id.pid);
    stamp_identity_values(memory, base, id.pid, shim_enabled)
}

/// The value to publish in the identity page's shim gate.
///
/// Non-zero opens the userspace fast path, so it must only ever be opened over
/// a pid a guest could legitimately observe. `getpid()` never returns 0 on
/// Linux: a zero here means the identity is not knowable YET — an unregistered
/// pid-namespace translation resolves to 0 through the `unwrap_or(0)` in
/// `identity_pid` — not that the pid is zero. Publishing it would let a guest
/// read a pid no process has, with no vm exit and nothing to re-check it.
///
/// Shutting the gate costs only speed: the guest traps and the dispatcher
/// answers correctly, and a later stamp opens it once the identity is real.
fn identity_gate_word(fast_path_enabled: bool, pid: u32) -> u32 {
    u32::from(fast_path_enabled && pid != 0)
}

fn stamp_identity_values<M: CurrentMmMemory>(
    memory: &mut M,
    base: u64,
    pid: u32,
    shim_enabled: u32,
) -> Result<(), carrick_guest_mem::MemoryError> {
    // Disable the fast path FIRST, then publish the identity, then re-enable.
    //
    // The shim word is the gate: while it is non-zero the guest answers
    // getpid/gettid from this page in userspace with NO vm exit, so nothing
    // re-checks the value it reads. Writing the pid before the gate is only
    // safe if the gate is known to be closed, and on a carrier VM it is not —
    // the identity page's backing is recycled between containers, so a
    // container can begin life with a predecessor's `1` still in the gate
    // while its own pid slot reads zero. The guest then reports pid 0, which
    // no Linux process ever sees. It is rare because the window is short, and
    // it widens under load, which is precisely why it must be closed rather
    // than tolerated.
    //
    // Closing the gate first costs nothing: a guest that reads it mid-stamp
    // takes the trap path and gets the correct answer from the dispatcher.
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &0_u32.to_le_bytes(),
    )?;
    // Pair for the release below: the CLOSE must be observable before the
    // identity it protects starts changing, or a guest can see the old gate
    // open over a half-written pid.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(base + crate::memory::IDENTITY_OFF_PID, &pid.to_le_bytes())?;
    // A fresh stamp starts a fresh serviced-syscall ledger: a forked child
    // COWs its parent's identity page and must not inherit the parent's
    // counter (Linux children start rusage at zero), and an exec'd image
    // keeps its task ledger but not the page. (The exec re-stamp drops any
    // pre-exec counted-but-unfolded syscalls — a µs-scale undercount.)
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
        &0_u64.to_le_bytes(),
    )?;
    // RELEASE the identity before opening the gate.
    //
    // Ordering the stores in program order is necessary but NOT sufficient.
    // The guest reads this page from another vCPU, and AArch64 lets plain
    // stores be observed out of order: without a barrier a guest can see the
    // gate word already non-zero while the pid store is not yet visible, and
    // report pid 0 through a fast path that never traps. That is the whole
    // failure — intermittent, wider under load, and closed by anything that
    // slows the writer down (which is why logging or a debug build hides it).
    //
    // The gate is a publication flag, so it needs release semantics: every
    // store above must be observable before the store that opens it.
    std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
    memory.write_bytes(
        base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
        &shim_enabled.to_le_bytes(),
    )?;
    Ok(())
}

pub(crate) fn stamp_guest_tid_checked<E: ThreadedEngine>(
    engine: &E,
    _this_tid: ThreadId,
    _registry: &ThreadRegistry,
    hvpatch_linux_tid: Option<crate::kernel::LinuxTid>,
) -> Result<(), TrapError> {
    stamp_guest_tid_with(crate::syscall_shim_enabled(), hvpatch_linux_tid, |tid| {
        engine.set_guest_thread_id(tid)
    })
}

fn stamp_guest_tid_with(
    shim_enabled: bool,
    hvpatch_linux_tid: Option<crate::kernel::LinuxTid>,
    set: impl FnOnce(u64) -> Result<(), TrapError>,
) -> Result<(), TrapError> {
    if !shim_enabled {
        return Ok(());
    }
    if let Some(tid) = hvpatch_linux_tid.and_then(|tid| u32::try_from(tid.raw()).ok()) {
        set(u64::from(tid))?;
    }
    Ok(())
}

fn proc_maps_from_address_space(image: &AddressSpace) -> Vec<ProcMapsEntry> {
    // Linux reserves RLIMIT_STACK as the maximum grow-down extent, but the
    // initial [stack] VMA covers only the argument/environment tail plus the
    // kernel's 128 KiB pre-expansion. Musl's pthread_getattr_np reads that VMA;
    // projecting the full Carrick backing falsely reports an already-grown
    // 8 MiB mapping. The backing remains the full RLIMIT-sized region so deep
    // recursion still has the same capacity as Linux.
    const INITIAL_STACK_VMA_EXPANSION: u64 = 128 * 1024;
    let stack_backing_start = crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE;
    let initial_stack_vma_start = image.initial_stack_pointer().map(|stack_pointer| {
        stack_pointer
            .saturating_sub(INITIAL_STACK_VMA_EXPANSION)
            .max(stack_backing_start)
            & !(crate::linux_abi::LINUX_PAGE_SIZE - 1)
    });
    image
        .regions()
        .iter()
        .map(|region| {
            let is_initial_stack =
                region.start == stack_backing_start && region.end == crate::memory::LINUX_STACK_TOP;
            ProcMapsEntry {
                start: if is_initial_stack {
                    initial_stack_vma_start.unwrap_or(region.start)
                } else {
                    region.start
                },
                end: region.end,
                read: region.perms.read,
                write: region.perms.write,
                execute: region.perms.execute,
                sharing: ProcMapSharing::Private,
                path: if is_initial_stack {
                    "[stack]".to_owned()
                } else {
                    String::new()
                },
            }
        })
        .collect()
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
            std::process::abort();
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
            std::process::abort();
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
                    std::process::abort();
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
    current_syscall_request: Option<crate::dispatch::SyscallRequest>,
    observers: Option<Arc<crate::observe::ObserverChain>>,
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
    threads: Arc<Mutex<Vec<VcpuThreadHandle>>>,
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

struct PreparedCorePublication {
    snapshot: crate::dispatch::CoreProcessSnapshot,
    bytes: Vec<u8>,
    generation: u64,
    fatal_tid: i32,
}

/// The only points at which the HVPatch logical loop may give its physical
/// executor back to the pool.  Keeping the list typed makes additions
/// fail-closed: a new suspension site must acquire an explicit save/detach and
/// resume case instead of becoming an implicit async-frame borrow of a vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HvpatchLoopSuspension {
    InitialAdmission,
    BlockedContinuation,
    SchedulerYield,
    ExecSiblingDrain,
    VforkParent,
    Preemption,
    TerminalSiblingDrain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) enum HvpatchLoopPoll {
    Suspended(HvpatchLoopSuspension),
    Exited,
}

struct HvpatchLoopResultState {
    result: Mutex<Option<Result<VcpuLoopOutcome, RuntimeError>>>,
    ready: Condvar,
}

#[derive(Clone)]
pub(crate) struct HvpatchLoopResult {
    state: Arc<HvpatchLoopResultState>,
}

impl HvpatchLoopResult {
    fn pending() -> Self {
        Self {
            state: Arc::new(HvpatchLoopResultState {
                result: Mutex::new(None),
                ready: Condvar::new(),
            }),
        }
    }

    fn publish(&self, result: Result<VcpuLoopOutcome, RuntimeError>) {
        let mut slot = self.state.result.lock();
        if slot.is_some() {
            std::process::abort();
        }
        *slot = Some(result);
        self.state.ready.notify_all();
    }

    #[cfg(test)]
    fn is_ready(&self) -> bool {
        self.state.result.lock().is_some()
    }

    fn wait(self) -> Result<VcpuLoopOutcome, RuntimeError> {
        let mut slot = self.state.result.lock();
        while slot.is_none() {
            self.state.ready.wait(&mut slot);
        }
        slot.take().unwrap_or_else(|| std::process::abort())
    }
}

struct HvpatchExternalTerminalState {
    published: bool,
    role: HvpatchTerminalSettlementRole,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HvpatchTerminalSettlementRole {
    Member,
    ProcessOwner,
}

/// Acyclic one-shot result authority retained by a process-member handle.
///
/// The logical job and the handle both retain this cell, but it never points
/// back to the binding, quantum, job, or process `threads` vector. Publishing
/// the result and then completion under one mutex makes the ordering exact
/// without creating `handle -> binding -> job -> handles` retention.
#[derive(Clone)]
pub(crate) struct HvpatchExternalTerminalSettlement {
    result: HvpatchLoopResult,
    completion: continuation::LogicalJobCompletion,
    state: Arc<Mutex<HvpatchExternalTerminalState>>,
}

impl HvpatchExternalTerminalSettlement {
    fn new(result: HvpatchLoopResult, completion: continuation::LogicalJobCompletion) -> Self {
        Self {
            result,
            completion,
            state: Arc::new(Mutex::new(HvpatchExternalTerminalState {
                published: false,
                role: HvpatchTerminalSettlementRole::Member,
            })),
        }
    }

    fn is_published(&self) -> bool {
        self.state.lock().published
    }

    fn arm_process_owner(&self) -> Result<(), RuntimeError> {
        let mut state = self.state.lock();
        if state.published {
            return Err(RuntimeError::Configuration(
                "terminal owner armed after logical result publication".to_owned(),
            ));
        }
        state.role = HvpatchTerminalSettlementRole::ProcessOwner;
        Ok(())
    }

    fn publish_member(
        &self,
        outcome: Result<VcpuLoopOutcome, RuntimeError>,
    ) -> Result<bool, RuntimeError> {
        let mut state = self.state.lock();
        if state.published {
            return Ok(false);
        }
        if state.role != HvpatchTerminalSettlementRole::Member {
            return Err(RuntimeError::Configuration(
                "drained-member settlement attempted to replace process-owner outcome".to_owned(),
            ));
        }
        self.result.publish(outcome);
        state.published = true;
        drop(state);
        self.completion.publish();
        Ok(true)
    }

    fn publish_terminal(&self, terminal: Option<Result<VcpuLoopOutcome, RuntimeError>>) -> bool {
        let mut state = self.state.lock();
        if state.published {
            return false;
        }
        let outcome = terminal_result_for_publication(terminal, state.role);
        self.result.publish(outcome);
        state.published = true;
        drop(state);
        self.completion.publish();
        true
    }

    fn completion(&self) -> continuation::LogicalJobCompletion {
        self.completion.clone()
    }

    #[cfg(test)]
    fn result_is_ready(&self) -> bool {
        self.result.is_ready()
    }
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
    BootstrapProcessChild {
        shares_mm: bool,
        child_settid: Option<(u64, i32)>,
    },
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
        _subscription: Option<crate::kernel::ReservationChangeSubscription>,
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
        prepared: exec::PreparedExecve,
        drain: continuation::ProcessDrain,
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
        _subscription: carrick_thread::fork_quiesce::TopologyReleaseSubscription,
    },
    Complete,
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
}

enum PersistentTerminal {
    Outcome {
        outcome: VcpuLoopOutcome,
        prepared_core: Option<PreparedCorePublication>,
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

fn terminal_result_for_publication(
    terminal: Option<Result<VcpuLoopOutcome, RuntimeError>>,
    role: HvpatchTerminalSettlementRole,
) -> Result<VcpuLoopOutcome, RuntimeError> {
    match (role, terminal) {
        (_, Some(result)) => result,
        (HvpatchTerminalSettlementRole::Member, None) => Ok(VcpuLoopOutcome::ThreadDone),
        (HvpatchTerminalSettlementRole::ProcessOwner, None) => Err(RuntimeError::Configuration(
            "persistent terminal settlement had no logical result".to_owned(),
        )),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
struct HvpatchCloneThreadRequest {
    stack: u64,
    tls: Option<u64>,
    flags: u64,
    parent_tid_addr: u64,
    child_tid_addr: u64,
    clear_child_tid_addr: u64,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum PersistentHvpatchCloneAttempt {
    Complete(threads::CloneThreadSpawn),
    Wait {
        prepared: Option<crate::kernel::PreparedThreadClone>,
        subscription: Option<crate::kernel::ReservationChangeSubscription>,
    },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
trait HvpatchCloneBackendOps<M: threads::CloneTidMemory> {
    type Prepared;
    type Backend;

    fn prepare(
        &mut self,
        memory: &M,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        entry: carrick_hal::GuestEntryRegs,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError>;
    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError>;
    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError>;
    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError>;
    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError>;
    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type HvpatchProcessPreparation<P> = (
    P,
    carrick_hal::threaded::GuestCpuState,
    Arc<dyn VcpuRegistry>,
);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum HvpatchProcessInventoryPreparation<'a> {
    /// A plain fork owns a new MM and must publish its staged frame inventory.
    Copied(
        &'a mut dyn FnMut(
            usize,
            usize,
            carrick_hal::FrameEventCapacity,
        ) -> Result<carrick_hal::FrameInventoryReservation, RuntimeError>,
    ),
    /// `CLONE_VM`/vfork retains the parent's exact MM/inventory authority.  No
    /// process inventory transaction exists for the child edge.
    SharedMm { kernel_mm: u64 },
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn validate_hvpatch_process_prepare_boundary(
    inventory: &HvpatchProcessInventoryPreparation<'_>,
    request: &carrick_hal::ProcessForkRequest,
    mm_generation: u64,
) -> Result<(), RuntimeError> {
    carrick_hal::validate_fork_projection(request.plan.ranges()).map_err(|error| {
        RuntimeError::Configuration(format!("invalid HVPatch fork projection: {error}"))
    })?;
    match (inventory, &request.plan) {
        (
            HvpatchProcessInventoryPreparation::Copied(_),
            carrick_hal::ForkProjectionPlan::Copied {
                parent_mm,
                child_mm,
                ..
            },
        ) if *child_mm == mm_generation && parent_mm != child_mm => Ok(()),
        (
            HvpatchProcessInventoryPreparation::SharedMm { kernel_mm },
            carrick_hal::ForkProjectionPlan::Shared { parent_mm, .. },
        ) if *parent_mm == *kernel_mm
            && request.plan.child_mm() == *kernel_mm
            && mm_generation == *kernel_mm =>
        {
            Ok(())
        }
        (HvpatchProcessInventoryPreparation::Copied(_), _) => Err(RuntimeError::Configuration(
            "copied HVPatch inventory requires a distinct-parent Copied projection bound to the child MM generation"
                .to_owned(),
        )),
        (HvpatchProcessInventoryPreparation::SharedMm { .. }, _) => {
            Err(RuntimeError::Configuration(
                "shared HVPatch inventory requires a Shared projection bound to the kernel MM"
                    .to_owned(),
            ))
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn cleanup_failed_hvpatch_initial_cpu<T>(
    abort: impl FnOnce() -> Result<(), RuntimeError>,
    context: &mut T,
    cancel_inventory: impl FnOnce(&mut T) -> Result<(), RuntimeError>,
    rollback_parent: impl FnOnce(&mut T) -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    let abort_error = abort().err();
    let _cancel_error = cancel_inventory(context).err();
    let rollback_error = rollback_parent(context).err();
    match (abort_error, rollback_error) {
        (None, None) => Ok(()),
        (Some(abort), None) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to abort child: {abort}"
        ))),
        (None, Some(rollback)) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to rollback parent: {rollback}"
        ))),
        (Some(abort), Some(rollback)) => Err(RuntimeError::Configuration(format!(
            "HVPatch initial CPU cleanup failed to abort child ({abort}) and rollback parent ({rollback})"
        ))),
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
trait HvpatchProcessBackendOps<E: ThreadedEngine, M: CurrentMmMemory> {
    type Prepared;
    type Backend;

    fn prepare(
        &mut self,
        memory: &mut M,
        inventory: HvpatchProcessInventoryPreparation<'_>,
        request: carrick_hal::ProcessForkRequest,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<HvpatchProcessPreparation<Self::Prepared>, RuntimeError>;
    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError>;
    fn commit_parent(&mut self, memory: &mut M) -> Result<(), RuntimeError>;
    fn rollback_parent(&mut self, memory: &mut M) -> Result<(), RuntimeError>;
    fn abort_and_rollback_prepared(
        &mut self,
        prepared: Self::Prepared,
        memory: &mut M,
        rollback_parent: bool,
    ) -> Result<(), RuntimeError> {
        let abort_error = self.abort(prepared).err();
        let rollback_error = rollback_parent
            .then(|| self.rollback_parent(memory).err())
            .flatten();
        match (abort_error, rollback_error) {
            (None, None) => Ok(()),
            (Some(abort), None) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to abort child: {abort}"
            ))),
            (None, Some(rollback)) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to rollback parent: {rollback}"
            ))),
            (Some(abort), Some(rollback)) => Err(RuntimeError::Configuration(format!(
                "HVPatch prepared unwind failed to abort child ({abort}) and rollback parent ({rollback})"
            ))),
        }
    }
    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError>;
    fn apply_inventory(
        &mut self,
        backend: &Self::Backend,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) -> Result<(), RuntimeError>;
    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError>;
    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError>;
    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState;
    fn guest_sp(&self, memory: &M) -> Option<u64>;
    fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ProductionHvpatchProcessBackendOps;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<E: ThreadedEngine + 'static> HvpatchProcessBackendOps<E, E>
    for ProductionHvpatchProcessBackendOps
where
    E::ProcessSpec: 'static,
{
    type Prepared = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPreparedTaskOnlyEngineState;
    type Backend = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState;

    fn prepare(
        &mut self,
        memory: &mut E,
        inventory: HvpatchProcessInventoryPreparation<'_>,
        request: carrick_hal::ProcessForkRequest,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<HvpatchProcessPreparation<Self::Prepared>, RuntimeError> {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        validate_hvpatch_process_prepare_boundary(&inventory, &request, mm_generation)?;
        let prepared = match inventory {
            HvpatchProcessInventoryPreparation::Copied(reserve) => {
                let spec = match memory.build_process_spec(request) {
                    Ok(spec) => spec,
                    Err(error) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Trap(error));
                    }
                };
                let spec = match (Box::new(spec) as Box<dyn std::any::Any>)
                    .downcast::<<HvfEngine as ThreadedEngine>::ProcessSpec>()
                {
                    Ok(spec) => spec,
                    Err(_) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Configuration(
                            "persistent HVPatch fork rejected non-HVF process spec".to_owned(),
                        ));
                    }
                };
                match carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_process_without_vcpu_with_reservation(
                    identity,
                    *spec,
                    |frames, mappings, capacity| {
                        reserve(frames, mappings, capacity)
                            .map_err(|error| carrick_hal::TrapError::Hypervisor(error.to_string()))
                    },
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = memory.cancel_process_inventory();
                        memory.rollback_process_fork().map_err(RuntimeError::Trap)?;
                        return Err(RuntimeError::Trap(error));
                    }
                }
            }
            HvpatchProcessInventoryPreparation::SharedMm { kernel_mm } => {
                if !request.shares_mm() {
                    return Err(RuntimeError::Configuration(
                        "shared HVPatch process preparation requires CLONE_VM".to_owned(),
                    ));
                }
                let engine = (memory as &dyn std::any::Any)
                    .downcast_ref::<HvfEngine>()
                    .ok_or_else(|| {
                        RuntimeError::Configuration(
                            "persistent HVPatch shared process rejected non-HVF engine".to_owned(),
                        )
                    })?;
                let spec = <HvfEngine as ThreadedEngine>::build_sibling_spec(engine, request.entry)
                    .map_err(RuntimeError::Trap)?;
                carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_shared_process_without_vcpu(
                    identity,
                    kernel_mm,
                    spec,
                )
                .map_err(RuntimeError::Trap)?
            }
        };
        let cpu = match prepared.initial_cpu_state(mm_generation, asid_generation) {
            Ok(cpu) => cpu,
            Err(error) => {
                if let Err(cleanup_error) = cleanup_failed_hvpatch_initial_cpu(
                    || prepared.abort().map_err(RuntimeError::Trap),
                    memory,
                    |memory| {
                        let _cancelled = memory.cancel_process_inventory();
                        Ok(())
                    },
                    |memory| memory.rollback_process_fork().map_err(RuntimeError::Trap),
                ) {
                    return Err(<Self as HvpatchProcessBackendOps<E, E>>::fail_stop(
                        self,
                        cleanup_error,
                    ));
                }
                return Err(RuntimeError::Trap(error));
            }
        };
        Ok((prepared, cpu, memory.fresh_fork_kicker()))
    }

    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError> {
        prepared.abort().map_err(RuntimeError::Trap)
    }

    fn commit_parent(&mut self, memory: &mut E) -> Result<(), RuntimeError> {
        memory.commit_process_fork().map_err(RuntimeError::Trap)
    }

    fn rollback_parent(&mut self, memory: &mut E) -> Result<(), RuntimeError> {
        let _ = memory.cancel_process_inventory();
        memory.rollback_process_fork().map_err(RuntimeError::Trap)
    }

    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError> {
        prepared.commit(directory).map_err(RuntimeError::Trap)
    }

    fn apply_inventory(
        &mut self,
        backend: &Self::Backend,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) -> Result<(), RuntimeError> {
        backend
            .apply_inventory(|commit| {
                kernel
                    .frame_inventory()
                    .apply_with_receipt(mm, commit)
                    .map(|(_, receipt)| receipt)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))
            })
            .map_err(RuntimeError::Trap)
    }

    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError> {
        backend.bind_child_kernel(token).map_err(RuntimeError::Trap)
    }

    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError> {
        backend.activate_child().map_err(RuntimeError::Trap)
    }

    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState {
        executor::HvpatchTaskEngineBindingState::task_only(backend)
    }

    fn guest_sp(&self, memory: &E) -> Option<u64> {
        memory.get_reg(carrick_hal::Reg::Sp).ok()
    }

    fn fail_stop(&mut self, error: RuntimeError) -> RuntimeError {
        eprintln!("carrick: FATAL: HVPatch process publication failure: {error}");
        std::process::abort();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ProductionHvpatchCloneBackendOps;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl<M: threads::CloneTidMemory + 'static> HvpatchCloneBackendOps<M>
    for ProductionHvpatchCloneBackendOps
{
    type Prepared = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchPreparedTaskOnlyEngineState;
    type Backend = carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState;

    fn prepare(
        &mut self,
        memory: &M,
        identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
        entry: carrick_hal::GuestEntryRegs,
        mm_generation: u64,
        asid_generation: u64,
    ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError> {
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        let engine = (memory as &dyn std::any::Any)
            .downcast_ref::<HvfEngine>()
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "persistent HVPatch clone rejected non-HVF engine".to_owned(),
                )
            })?;
        let spec = <HvfEngine as ThreadedEngine>::build_sibling_spec(engine, entry)
            .map_err(RuntimeError::Trap)?;
        let prepared =
            carrick_vmm_hvf::hvf_aarch64_engine::materialize_hvpatch_sibling_without_vcpu(
                identity, spec,
            )
            .map_err(RuntimeError::Trap)?;
        let cpu = prepared
            .initial_cpu_state(mm_generation, asid_generation)
            .map_err(RuntimeError::Trap)?;
        Ok((prepared, cpu))
    }

    fn abort(&mut self, prepared: Self::Prepared) -> Result<(), RuntimeError> {
        prepared.abort().map_err(RuntimeError::Trap)
    }

    fn commit(
        &mut self,
        prepared: Self::Prepared,
        directory: Arc<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory>,
    ) -> Result<Self::Backend, RuntimeError> {
        prepared.commit(directory).map_err(RuntimeError::Trap)
    }

    fn bind_child_kernel(
        &mut self,
        backend: &mut Self::Backend,
        token: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchChildKernelBinding,
    ) -> Result<(), RuntimeError> {
        backend.bind_child_kernel(token).map_err(RuntimeError::Trap)
    }

    fn activate_child(&mut self, backend: &mut Self::Backend) -> Result<(), RuntimeError> {
        backend.activate_child().map_err(RuntimeError::Trap)
    }

    fn make_binding_state(
        &mut self,
        backend: Self::Backend,
    ) -> executor::HvpatchTaskEngineBindingState {
        executor::HvpatchTaskEngineBindingState::task_only(backend)
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum HvpatchCloneFailpoint {
    TidCopyout = 1,
    BackendCommit = 2,
    TokenBind = 3,
    RegistryHandle = 4,
    StartProof = 5,
    Activation = 6,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum HvpatchProcessFailpoint {
    ParentCopyout = 1,
    BackendCommit = 2,
    KernelCommit = 3,
    TokenBind = 4,
    DormantHandle = 5,
    StartProof = 6,
    Activation = 7,
    ChildSettidBootstrap = 8,
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static HVPATCH_CLONE_FAILPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
static HVPATCH_PROCESS_FAILPOINT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
fn install_hvpatch_clone_failpoint(phase: HvpatchCloneFailpoint) {
    HVPATCH_CLONE_FAILPOINT.store(phase as u8, std::sync::atomic::Ordering::Release);
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn install_hvpatch_process_failpoint(phase: HvpatchProcessFailpoint) {
    HVPATCH_PROCESS_FAILPOINT.store(phase as u8, std::sync::atomic::Ordering::Release);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn check_hvpatch_clone_failpoint(phase: HvpatchCloneFailpoint) -> Result<(), RuntimeError> {
    #[cfg(test)]
    if HVPATCH_CLONE_FAILPOINT
        .compare_exchange(
            phase as u8,
            0,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        return Err(RuntimeError::Configuration(format!(
            "injected production HVPatch clone failpoint: {phase:?}"
        )));
    }
    #[cfg(not(test))]
    let _ = phase;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) fn check_hvpatch_process_failpoint(
    phase: HvpatchProcessFailpoint,
) -> Result<(), RuntimeError> {
    #[cfg(test)]
    if HVPATCH_PROCESS_FAILPOINT
        .compare_exchange(
            phase as u8,
            0,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
    {
        return Err(RuntimeError::Configuration(format!(
            "injected production HVPatch process failpoint: {phase:?}"
        )));
    }
    #[cfg(not(test))]
    let _ = phase;
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn bootstrap_hvpatch_process_child<E: ThreadedEngine>(
    kernel: &Kernel,
    state: &ThreadRuntimeState<E>,
    engine: &mut E,
    shares_mm: bool,
    child_settid: Option<(u64, i32)>,
) -> Result<(), RuntimeError> {
    if !shares_mm {
        engine
            .refresh_fork_process_state()
            .map_err(RuntimeError::Trap)?;
    }
    let context = state.service_kernel_context.as_ref().ok_or_else(|| {
        RuntimeError::Configuration("process child bootstrap lost Kernel context".to_owned())
    })?;
    bootstrap_hvpatch_process_child_identity(engine, &kernel.dispatcher, context, shares_mm)?;
    stamp_guest_tid_checked(
        engine,
        state.this_tid,
        &state.registry,
        Some(state.linux_tid),
    )
    .map_err(RuntimeError::Trap)?;
    if let Some((address, tid)) = child_settid {
        bootstrap_hvpatch_process_child_tid(engine, address, tid)?;
    }
    Ok(())
}

fn bootstrap_hvpatch_process_child_identity(
    memory: &mut impl CurrentMmMemory,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    shares_mm: bool,
) -> Result<(), RuntimeError> {
    bootstrap_hvpatch_process_child_identity_with(
        memory,
        dispatcher,
        kernel_context,
        shares_mm,
        crate::syscall_shim_enabled(),
    )
}

fn bootstrap_hvpatch_process_child_identity_with(
    memory: &mut impl CurrentMmMemory,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    shares_mm: bool,
    shim_enabled: bool,
) -> Result<(), RuntimeError> {
    if !shim_enabled {
        return Ok(());
    }
    let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
    let res = if shares_mm {
        memory.write_bytes(
            base + crate::memory::IDENTITY_OFF_SHIM_ENABLED,
            &0_u32.to_le_bytes(),
        )
    } else {
        let id = dispatcher.identity_snapshot(kernel_context);
        stamp_identity_values(
            memory,
            base,
            id.pid,
            u32::from(dispatcher.identity_fast_path_enabled()),
        )
    };
    res.map_err(|error| {
        RuntimeError::Trap(TrapError::Hypervisor(format!(
            "process child identity bootstrap: {error}"
        )))
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn bootstrap_hvpatch_process_child_tid(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    tid: i32,
) -> Result<(), RuntimeError> {
    check_hvpatch_process_failpoint(HvpatchProcessFailpoint::ChildSettidBootstrap)?;
    memory
        .write_bytes(address, &tid.to_le_bytes())
        .map_err(|error| {
            RuntimeError::Trap(TrapError::Hypervisor(format!(
                "process child TID bootstrap copyout: {error}"
            )))
        })
}

trait ProductionHvpatchLoopPoll: Send {
    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit;

    fn after_terminal_settlement(&mut self);

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
            .unwrap_or_else(|| std::process::abort())
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
    ) -> Result<executor::ExecutorExit, RuntimeError> {
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
            Err(_) => return Ok(self.external_exec_failure(engine, 126)),
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
                return Ok(self.external_exec_failure(engine, exit_code));
            }
        };
        match self
            .state
            .prepare_execve(&self.kernel, &context, engine, path, argv, env)?
        {
            exec::ExecvePreparation::Complete(Some(outcome)) => {
                Ok(self.enter_terminal_with_outcome(engine, outcome))
            }
            exec::ExecvePreparation::Complete(None) => Ok(self.external_exec_failure(engine, 126)),
            exec::ExecvePreparation::Prepared(prepared) => {
                let prepared = *prepared;
                let drain = self
                    .state
                    .begin_persistent_exec_sibling_drain(&self.kernel, self.completion.id())?;
                if drain.is_ready() {
                    self.state
                        .finish_persistent_sibling_drain(self.completion.id())?;
                    let finished = self.state.finish_prepared_execve(
                        &self.kernel,
                        &context,
                        engine,
                        prepared,
                    )?;
                    let replaced = self.publish_exec_replacement(control)?;
                    Ok(match (finished, replaced) {
                        (Some(outcome), _) => self.enter_terminal_with_outcome(engine, outcome),
                        (None, true) => self.suspend(
                            HvpatchLoopSuspension::Preemption,
                            executor::ExecutorExit::Preempted,
                        ),
                        (None, false) => executor::ExecutorExit::Syscall,
                    })
                } else {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain {
                        context,
                        prepared,
                        drain,
                    };
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
                    self.state.complete_returned(engine, value)?;
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
                    .unwrap_or_else(|| std::process::abort())
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
        let process = self
            .kernel
            .hvpatch_process
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        let topology = loop {
            let observed = crate::fork_quiesce::topology_release_generation();
            if let Some(topology) = crate::fork_quiesce::try_acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                process.pid(),
                self.state.this_tid.raw(),
            ) {
                break topology;
            }
            let scheduler = self
                .kernel
                .hvpatch_runtime
                .as_ref()
                .unwrap_or_else(|| std::process::abort())
                .continuation_services(terminal_context.kernel())
                .0;
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
                    self.phase = HvpatchProductionPhase::TerminalRetireRetry {
                        terminal,
                        context: terminal_context,
                        _subscription: subscription,
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
                std::process::abort();
            });
        if owns_final_mm {
            let capacity = carrick_hal::FrameEventCapacity::for_event_count(
                carrick_hal::MAX_FRAME_INVENTORY_EVENTS_PER_BATCH,
            )
            .unwrap_or_else(|_| std::process::abort());
            let reservation = terminal_context
                .kernel()
                .reserve_frame_inventory(0, 0, capacity)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "reserve persistent failure inventory");
                    std::process::abort();
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
                    std::process::abort();
                });
        }
        let prepared_core = match &terminal {
            PersistentTerminal::Outcome { prepared_core, .. } => prepared_core.as_ref(),
            _ => None,
        };
        let core_publication = match prepared_core {
            Some(prepared) => {
                match self.kernel.dispatcher.publish_core_atomic(
                    &prepared.snapshot,
                    prepared.generation,
                    prepared.bytes.clone(),
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
                tracing::error!(%error, "HVPatch terminal owner publishes failure");
                (127, 127 << 8, Err(()))
            }
            PersistentTerminal::Outcome {
                outcome: VcpuLoopOutcome::ThreadDone,
                ..
            } => std::process::abort(),
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
                std::process::abort();
            }
        }
        let status = crate::kernel::LinuxWaitStatus::from_wait_encoding(wait_encoding);
        let orphan_adopter = self.kernel.dispatcher.hvpatch_orphan_adopter();
        let publish_result = process.publish_exit_status(status, orphan_adopter, |parent| {
            self.kernel
                .dispatcher
                .retire_hvpatch_process_fds(&terminal_context);
            if child {
                self.kernel.notify_hvpatch_parent_exit(parent);
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
            std::process::abort();
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
                std::process::abort();
            }
        }
        self.pending_terminal_retirement = Some(
            process
                .begin_address_space_retirement(exit_code, self.state.this_tid, process_exit_event)
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "retire persistent failure MM/ASID");
                    std::process::abort();
                }),
        );
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
                std::process::abort()
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
            .unwrap_or_else(|| std::process::abort())
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
        let observed = self.kernel.clone_admission.change_epoch();
        match self
            .kernel
            .try_claim_persistent_process_exit(self.state.this_tid)
            .unwrap_or_else(|failure| {
                tracing::error!(%failure, "claim persistent process terminal owner");
                std::process::abort();
            }) {
            ProcessExitClaim::LostToExec | ProcessExitClaim::AlreadyOwned => {
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
                    .unwrap_or_else(|| std::process::abort())
                    .continuation_services(context.kernel())
                    .0;
                let thread = context.thread().key();
                let subscription = self.kernel.clone_admission.subscribe_change(
                    observed,
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
                        std::process::abort();
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
                        Ok(p) => p,
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
                std::process::abort();
            });
        if drain.is_ready() {
            self.state
                .finish_persistent_sibling_drain(self.completion.id())
                .unwrap_or_else(|failure| {
                    tracing::error!(%failure, "finish persistent failure sibling drain");
                    std::process::abort();
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
            .unwrap_or_else(|| std::process::abort())
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
            .unwrap_or_else(|| std::process::abort())
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
        let runtime = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        let process = self
            .kernel
            .hvpatch_process
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        let scheduler = runtime.continuation_services(context.kernel()).0;
        executor::retire_failed_hvpatch_clone_authority(
            &scheduler,
            process.kernel_graph(),
            context,
            generation,
            |thread, generation| runtime.persistent_bindings().retire(thread, generation),
        )
        .unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: authoritative HVPatch clone rollback: {error}");
            std::process::abort();
        });
        if registry_installed {
            self.state.registry.exit(tid);
        }
        tid_outputs.rollback(memory).unwrap_or_else(|error| {
            eprintln!("carrick: FATAL: restore published HVPatch clone TID outputs: {error}");
            std::process::abort();
        });
        if let Some(completion) = completion {
            let id = completion.id();
            self.state
                .threads
                .lock()
                .retain(|handle| handle.completion().id() != id);
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
        type HvfEngine = carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine;
        let HvpatchCloneThreadRequest {
            stack,
            tls,
            flags,
            parent_tid_addr,
            child_tid_addr,
            clear_child_tid_addr,
        } = request;

        let Some(clone_permit) = self.kernel.try_enroll_thread_clone() else {
            return Ok(PersistentHvpatchCloneAttempt::Complete(
                threads::CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN),
            ));
        };
        if self.kernel.process_exiting() || clone_permit.is_cancelled() {
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
                .unwrap_or_else(|| std::process::abort());
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
                subscription,
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
        if !tid_outputs.publish(memory, linux_tid, tid) {
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
        let generation = match child_context
            .thread()
            .publish_initial_task_state(task_state.clone())
        {
            Ok(generation) if generation == expected_generation => generation,
            Ok(generation) => {
                ops.abort(prepared_backend).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: abort generation-drifted clone backend: {error}");
                    std::process::abort();
                });
                let runtime = self
                    .kernel
                    .hvpatch_runtime
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort());
                let scheduler = runtime.continuation_services(child_context.kernel()).0;
                executor::retire_failed_hvpatch_clone_authority(
                    &scheduler,
                    process.kernel_graph(),
                    &child_context,
                    generation,
                    |_, _| {},
                )
                .unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: retire generation-drifted clone: {error}");
                    std::process::abort();
                });
                tid_outputs.rollback(memory).unwrap_or_else(|error| {
                    eprintln!("carrick: FATAL: restore generation-drifted clone TIDs: {error}");
                    std::process::abort();
                });
                return Err(RuntimeError::Configuration(
                    "persistent HVPatch child execution generation drifted".to_owned(),
                ));
            }
            Err(error) => {
                ops.abort(prepared_backend).unwrap_or_else(|abort| {
                    eprintln!("carrick: FATAL: abort unpublished clone backend: {abort}");
                    std::process::abort();
                });
                process
                    .kernel_graph()
                    .exit_thread(&child_context, None)
                    .unwrap_or_else(|retire| {
                        eprintln!("carrick: FATAL: retire unpublished clone: {retire}");
                        std::process::abort();
                    });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore published clone TIDs: {rollback}");
                    std::process::abort();
                });
                return Err(RuntimeError::Configuration(format!(
                    "publish persistent HVPatch child execution state: {error}"
                )));
            }
        };
        let runtime = self
            .kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
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
                .unwrap_or_else(|retire| {
                    eprintln!("carrick: FATAL: retire carrier-commit clone: {retire}");
                    std::process::abort();
                });
                tid_outputs.rollback(memory).unwrap_or_else(|rollback| {
                    eprintln!("carrick: FATAL: restore carrier-commit clone TIDs: {rollback}");
                    std::process::abort();
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
            kernel: Arc::clone(child_context.kernel()),
            mm,
            guest_executors: self.kernel.dispatcher.mm_executor_census(),
            tid,
            identity: cow_identity,
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
        let mut child_state = ThreadRuntimeState::<HvfEngine>::new(
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
            Arc::clone(&self.state.threads),
            Arc::clone(&self.state.kicker),
            carrick_hal::InGuestFlag::for_guest_thread(),
            self.state.max_traps,
        );
        child_state.execution_lease = execution_lease;
        child_state.service_kernel_context = Some(child_context.retain_exact());
        let mut logical = match prepare_hvpatch_logical_job(HvpatchLogicalJobInput {
            kernel: Arc::clone(&self.kernel),
            state: child_state,
            task_backend: ops.make_binding_state(task_backend),
            context: child_context.retain_exact(),
            cpu: task_state,
            generation,
            injected_lease,
            bootstrap_process_child: None,
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
            threads::CloneThreadSpawn::Started(linux_tid),
        ))
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn complete_persistent_hvpatch_clone(
        &mut self,
        engine: &mut E,
        spawned: threads::CloneThreadSpawn,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        let (completed_tid, completed_errno) = match spawned {
            threads::CloneThreadSpawn::Started(tid) => {
                self.state.complete_returned(engine, i64::from(tid.raw()))?;
                (tid.raw(), 0)
            }
            threads::CloneThreadSpawn::Errno(errno) => {
                self.state.complete_returned(engine, errno.guest_retval())?;
                (self.state.this_tid.raw(), errno.get())
            }
        };
        crate::event_ring::rec(
            crate::event_ring::CLONESPAWN,
            self.state.this_tid.raw(),
            completed_tid,
            completed_errno,
        );
        crate::probes::mn_clone_outcome(
            completed_tid,
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
            std::process::abort();
        }
        self.phase = HvpatchProductionPhase::Complete;
        executor::ExecutorExit::Exited
    }

    fn publish_terminal_result(&mut self) {
        self.terminal_settlement
            .publish_terminal(self.terminal_result.take());
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

    fn service_outcome(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
        frame: carrick_hal::RawSyscall,
        outcome: DispatchOutcome,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
        if continuation::is_blocking_dispatch_outcome(&outcome) {
            let _ = self.state.stash_parked_registers(engine);
            let request = SyscallRequest::from_raw(frame)
                .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi())
                .with_current_guest_sp(engine.get_reg(carrick_hal::Reg::Sp).ok());
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
                self.state.complete_returned(engine, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                // Self-directed signals (e.g. raise(SIGABRT)) posted during syscall handling must be serviced before returning to guest EL0, otherwise the thread resumes execution and runs subsequent instructions (like _exit(99)) before any asynchronous kick can arrive.
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                let value = self.state.complete_errno(engine, errno)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                self.state.complete_returned(engine, 0)?;
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
                    .unwrap_or_else(|| std::process::abort())
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
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                let preparation =
                    self.state
                        .prepare_execve(&self.kernel, &context, engine, path, argv, env)?;
                if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
                    eprintln!(
                        "SIGDBG execve-arm tid={:?} prepared={}",
                        self.state.this_tid,
                        matches!(preparation, exec::ExecvePreparation::Prepared(_)),
                    );
                }
                match preparation {
                    exec::ExecvePreparation::Complete(Some(outcome)) => self.finish(Ok(outcome)),
                    exec::ExecvePreparation::Complete(None) => executor::ExecutorExit::Syscall,
                    exec::ExecvePreparation::Prepared(prepared) => {
                        let prepared = *prepared;
                        let drain = self.state.begin_persistent_exec_sibling_drain(
                            &self.kernel,
                            self.completion.id(),
                        )?;
                        if drain.is_ready() {
                            self.state
                                .finish_persistent_sibling_drain(self.completion.id())?;
                            let finished = self.state.finish_prepared_execve(
                                &self.kernel,
                                &context,
                                engine,
                                prepared,
                            )?;
                            let replaced = self.publish_exec_replacement(control)?;
                            return Ok(match (finished, replaced) {
                                (Some(outcome), _) => self.finish(Ok(outcome)),
                                (None, true) => self.suspend(
                                    HvpatchLoopSuspension::Preemption,
                                    executor::ExecutorExit::Preempted,
                                ),
                                (None, false) => executor::ExecutorExit::Syscall,
                            });
                        }
                        self.phase = HvpatchProductionPhase::ExecSiblingDrain {
                            context,
                            prepared,
                            drain,
                        };
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
                return self.complete_persistent_process_fork(
                    engine,
                    control,
                    Some(frame),
                    None,
                    prepared,
                );
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
                let (completed_tid, completed_errno) = match spawned {
                    threads::CloneThreadSpawn::Started(tid) => {
                        self.state.complete_returned(engine, i64::from(tid.raw()))?;
                        (tid.raw(), 0)
                    }
                    threads::CloneThreadSpawn::Errno(errno) => {
                        self.state.complete_returned(engine, errno.guest_retval())?;
                        (self.state.this_tid.raw(), errno.get())
                    }
                };
                crate::event_ring::rec(
                    crate::event_ring::CLONESPAWN,
                    self.state.this_tid.raw(),
                    completed_tid,
                    completed_errno,
                );
                crate::probes::mn_clone_outcome(
                    completed_tid,
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
                    .unwrap_or_else(|| std::process::abort())
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
                engine.set_memory_model(hardware_tso_for_debug(tso))?;
                let value = self.state.complete_returned(engine, 0)?;
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                    Err(error) => return Err(error.into()),
                };
                let signal_context =
                    self.state.service_kernel_context.as_ref().ok_or_else(|| {
                        RuntimeError::Configuration(
                            "sigreturn lost its exact Kernel context".to_owned(),
                        )
                    })?;
                self.kernel.dispatcher.restore_signal_mask(
                    signal_context,
                    self.state.this_tid,
                    carrick_abi::SigSet::from_raw(restored_sigmask),
                );
                let context = signal_context.retain_exact();
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
            DispatchOutcome::SharedFutexWake {
                location,
                waiter_key,
                count,
            } => {
                let value = shared_futex_wake(location.wait_addr().raw(), waiter_key, count);
                self.state.complete_returned(engine, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                from_key,
                to,
                to_key,
                wake,
                requeue,
            } => {
                trace_shared_futex_requeue(0, from_key, to_key, wake, requeue, 0, 0);
                let (carrier_woken, carrier_requeued) =
                    carrick_thread::platform_futex::carrier_shared_futex_table().requeue(
                        from_key as u64,
                        to_key as u64,
                        wake,
                        requeue,
                    );
                let (ulock_woken, ulock_requeued) = crate::ulock::requeue_counted(
                    from.wait_addr().raw(),
                    from_key,
                    to.wait_addr().raw(),
                    to_key,
                    wake,
                    requeue,
                );
                let woken = carrier_woken.max(ulock_woken);
                let requeued = carrier_requeued.max(ulock_requeued);
                trace_shared_futex_requeue(1, from_key, to_key, wake, requeue, woken, requeued);
                let value = i64::from(woken + requeued);
                self.state.complete_returned(engine, value)?;
                self.state.trace_syscall_return(self.traps, Some(value));
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
            .unwrap_or_else(|| std::process::abort())
            .retain_exact();
        self.begin_persistent_process_terminal(
            engine,
            PersistentTerminal::from_outcome(outcome),
            context,
        )
    }

    fn poll_with_engine(
        &mut self,
        engine: &mut E,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> Result<executor::ExecutorExit, RuntimeError> {
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
        if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
            eprintln!(
                "SIGDBG quantum-check registry={:p} tid={:?} live={} finish={exec_finish} terminal={}",
                std::sync::Arc::as_ptr(&self.state.registry),
                self.state.this_tid,
                self.state.registry.is_live(self.state.this_tid),
                self.phase.is_terminal_transition(),
            );
        }
        if !self.phase.is_terminal_transition() && (self.kernel.process_exiting() || exec_finish) {
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
                return self.begin_control_exec_fork(
                    engine,
                    control,
                    work,
                    Some(deferred_resume_blocked),
                );
            }
            // Admission may have been cancelled before the owner claimed it.
            // Consume only the control edge and put the untouched continuation
            // back; never turn this into guest readiness.
            return self.finish_control_quantum(engine, control, Some(deferred_resume_blocked));
        }

        let phase = std::mem::replace(&mut self.phase, HvpatchProductionPhase::Resident);
        match phase {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            HvpatchProductionPhase::BootstrapProcessChild {
                shares_mm,
                child_settid,
            } => {
                bootstrap_hvpatch_process_child(
                    &self.kernel,
                    &self.state,
                    engine,
                    shares_mm,
                    child_settid,
                )?;
                if let Some(work) = self.kernel.take_external_exec_work() {
                    self.external_exec = Some(work);
                    return self.start_external_exec(engine, control);
                }
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
                return self.complete_persistent_process_fork(
                    engine,
                    control,
                    frame,
                    deferred_resume_blocked,
                    prepared,
                );
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
                        self.complete_persistent_hvpatch_clone(engine, spawned)
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
                        ));
                    }
                    (None, Some(outcome)) => outcome,
                    (None, None) => {
                        self.state
                            .service_threaded_syscall(&self.kernel, engine, frame)?
                    }
                };
                if self.kernel.dispatcher.take_signal_pump_request() {
                    self.kernel
                        .signal_pump
                        .start_signal_pump(&self.state.kicker, &self.state.platform_futex);
                }
                return self.service_outcome(engine, control, frame, outcome);
            }
            HvpatchProductionPhase::ExecSiblingDrain {
                context,
                prepared,
                drain,
            } => {
                if !drain.is_ready() {
                    self.phase = HvpatchProductionPhase::ExecSiblingDrain {
                        context,
                        prepared,
                        drain,
                    };
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::ExecSiblingDrain,
                        executor::ExecutorExit::Blocked(
                            crate::kernel::objects::BlockedReason::ChildState,
                        ),
                    ));
                }
                self.state
                    .finish_persistent_sibling_drain(self.completion.id())?;
                let finished =
                    self.state
                        .finish_prepared_execve(&self.kernel, &context, engine, prepared)?;
                let replaced = self.publish_exec_replacement(control)?;
                if let Some(outcome) = finished {
                    return Ok(self.finish(Ok(outcome)));
                }
                if replaced {
                    return Ok(self.suspend(
                        HvpatchLoopSuspension::Preemption,
                        executor::ExecutorExit::Preempted,
                    ));
                }
                return Ok(executor::ExecutorExit::Syscall);
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
                self.state
                    .finish_persistent_sibling_drain(self.completion.id())?;
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
                return self.begin_control_exec_fork(engine, control, work, None);
            }
            return self.finish_control_quantum(engine, control, None);
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
        let signal_progress = signal_progress_count();
        if signal_progress != self.seen_signal_progress {
            self.seen_signal_progress = signal_progress;
            self.budget_floor = self.traps;
            self.last_signal_progress = Instant::now();
        }
        match trap_watchdog_decision(
            self.traps.saturating_sub(self.budget_floor),
            self.state.max_traps,
            self.last_signal_progress.elapsed(),
            trap_watchdog_wall_window(),
        ) {
            TrapWatchdog::KeepRunning => {}
            TrapWatchdog::ResetBudget => {
                self.budget_floor = self.traps;
                self.last_signal_progress = Instant::now();
            }
            TrapWatchdog::Trip => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        let entered_guest = quiesce::enter_hvpatch_guest_or_service_invalidation(
            &self.state.in_guest,
            quiesce::pt_barrier(),
            self.state.this_tid,
            engine,
            control,
        )?;
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        let entered_guest =
            quiesce::enter_guest_or_park(&self.state.in_guest, quiesce::pt_barrier());
        if !entered_guest {
            return Ok(executor::ExecutorExit::Syscall);
        }
        self.state
            .publish_thread_run_state(crate::run_state::RunState::Running, 'R');
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
                }));
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
                crate::probes::vcpu_fault_regs(
                    syndrome,
                    elr,
                    far,
                    instruction.map_or(u64::MAX, u64::from),
                    base_register,
                    base_value,
                );
                crate::probes::vcpu_fault_gprs(
                    engine.get_reg(carrick_hal::Reg::X(0)).unwrap_or(0),
                    engine.get_reg(carrick_hal::Reg::X(1)).unwrap_or(0),
                    engine.get_reg(carrick_hal::Reg::X(2)).unwrap_or(0),
                    engine.get_reg(carrick_hal::Reg::X(3)).unwrap_or(0),
                    engine.get_reg(carrick_hal::Reg::X(4)).unwrap_or(0),
                    engine.get_reg(carrick_hal::Reg::X(5)).unwrap_or(0),
                );
                if let Some((ttbr, descriptors)) = engine.diagnostic_fault_page_tables(far) {
                    crate::probes::pt_fault_walk(
                        far,
                        descriptors[0],
                        descriptors[1],
                        descriptors[2],
                        descriptors[3],
                    );
                    crate::probes::pt_fault_ttbr(far, ttbr);
                }
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
                    if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                        eprintln!(
                            "[FAULTDBG tid={:?}] UNCLASSIFIED EL0 fault esr={syndrome:#x} ec={:#x} elr={elr:#x} far={far:#x} -> SIGSEGV terminate",
                            self.state.this_tid,
                            (syndrome >> 26) & 0x3f
                        );
                    }
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
                if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                    let base =
                        (base_register < 31).then(|| format!("x{base_register}={base_value:#x}"));
                    let regs: Vec<_> = (0..=12)
                        .map(|index| {
                            engine
                                .get_reg(carrick_hal::Reg::X(index))
                                .map_or_else(|_| "?".to_owned(), |value| format!("{value:#x}"))
                        })
                        .collect();
                    eprintln!(
                        "[FAULTDBG tid={:?}] classified EL0 fault esr={syndrome:#x} ec={:#x} elr={elr:#x} far={far:#x} direct={from_el0_direct} last_syscall={:?} insn={instruction:?} base={base:?} x0..x12={regs:?}",
                        self.state.this_tid,
                        (syndrome >> 26) & 0x3f,
                        engine.last_syscall_nr()
                    );
                }
                // Raw hardware/host faults can decode as MAPERR even when
                // Carrick tracks a live VMA denying the access. Upgrade from the
                // shared protection metadata (LTP mmap05 / roprotect probe).
                let si_code =
                    signal::upgrade_protection_si_code(&*engine, signum, si_code, si_addr);
                let interrupted_pc = from_el0_direct.then_some(elr);
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture synchronous-fault signal context: {error}"
                        ))
                    })?;
                if self.kernel.dispatcher.fault_requires_mm_mutation(si_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                si_addr,
                                mutation,
                            )
                        })?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
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
                let fault_context = self
                    .kernel
                    .dispatcher
                    .capture_kernel_context(self.state.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture guest-fault signal context: {error}"
                        ))
                    })?;
                if self
                    .kernel
                    .dispatcher
                    .fault_requires_mm_mutation(fault_addr)
                    && self
                        .state
                        .with_mm_mutation_authority(&self.kernel, |mutation| {
                            signal::resolve_mutating_fault(
                                &self.kernel.dispatcher,
                                engine,
                                fault_addr,
                                mutation,
                            )
                        })?
                {
                    return Ok(executor::ExecutorExit::Syscall);
                }
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
            Err(error) => return Err(RuntimeError::Trap(error)),
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
}

impl<E: ThreadedEngine + 'static> ProductionHvpatchLoopPoll for ProductionHvpatchLoopJob<E>
where
    E::SiblingSpec: 'static,
{
    fn poll(
        &mut self,
        engine: &mut dyn std::any::Any,
        control: &mut executor::HvpatchQuantumControl<'_, '_>,
    ) -> executor::ExecutorExit {
        let Some(engine) = engine.downcast_mut::<E>() else {
            return executor::ExecutorExit::InvalidState;
        };
        match self.poll_with_engine(engine, control) {
            Ok(exit) => exit,
            Err(error) => {
                let context = self
                    .state
                    .service_kernel_context
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort())
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

#[derive(Clone, Copy, Debug)]
struct CrashLeaseDrainBudget {
    timeout: Duration,
    poll_interval: Duration,
}

impl CrashLeaseDrainBudget {
    const DEFAULT: Self = Self {
        timeout: Duration::from_secs(10),
        poll_interval: Duration::from_micros(200),
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrashLeaseDrainTimeout {
    Waiting(ThreadId),
    Busy(ThreadId),
}

impl std::fmt::Display for CrashLeaseDrainTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waiting(tid) => write!(
                formatter,
                "HVPatch crash lease drain timed out waiting for sibling vCPU tid {}",
                tid.raw()
            ),
            Self::Busy(owner) => write!(
                formatter,
                "HVPatch crash lease drain timed out behind freeze owner tid {}",
                owner.raw()
            ),
        }
    }
}

fn crash_lease_drain_park_duration(poll_interval: Duration, remaining: Duration) -> Duration {
    poll_interval.min(remaining)
}

fn acquire_crash_lease_drain<N>(
    registry: &dyn VcpuRegistry,
    owner: ThreadId,
    budget: CrashLeaseDrainBudget,
    mut nudge: N,
) -> Result<carrick_hal::VcpuLeaseDrainGuard, CrashLeaseDrainTimeout>
where
    N: FnMut(),
{
    let deadline = Instant::now() + budget.timeout;
    let waiter = std::thread::current();
    let callback: Arc<dyn Fn() + Send + Sync + 'static> = Arc::new(move || waiter.unpark());

    loop {
        let subscription = match registry.subscribe_lease_drain(owner, Arc::clone(&callback)) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => return Ok(guard),
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { subscription, .. }
            | carrick_hal::VcpuLeaseDrainEnrollment::Busy { subscription, .. } => subscription,
        };

        nudge();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            std::thread::park_timeout(crash_lease_drain_park_duration(
                budget.poll_interval,
                remaining,
            ));
            drop(subscription);
            if Instant::now() < deadline {
                continue;
            }
        } else {
            drop(subscription);
        }

        return match registry.subscribe_lease_drain(owner, Arc::clone(&callback)) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => Ok(guard),
            carrick_hal::VcpuLeaseDrainEnrollment::Waiting { tid, .. } => {
                Err(CrashLeaseDrainTimeout::Waiting(tid))
            }
            carrick_hal::VcpuLeaseDrainEnrollment::Busy { owner, .. } => {
                Err(CrashLeaseDrainTimeout::Busy(owner))
            }
        };
    }
}

fn finish_crash_collection<T>(
    authority: &crate::kernel::CrashCaptureAuthority,
    barrier: &crate::fork_quiesce::QuiesceBarrier,
    quiesced: bool,
    lease_drain_guard: Option<carrick_hal::VcpuLeaseDrainGuard>,
    result: Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    authority.stop_collecting();
    if quiesced {
        barrier.end_quiesce();
    }
    barrier.end_fork();
    drop(lease_drain_guard);
    result
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
        threads: Arc<Mutex<Vec<VcpuThreadHandle>>>,
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
            current_syscall_request: None,
            observers: None,
            continuation_restart: None,
            cow_refault_watch: None,
            reserved_signal: None,
            this_tid,
            threads,
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
    fn install_crash_lease_drain_budget_for_test(&mut self, budget: CrashLeaseDrainBudget) {
        self.crash_lease_drain_budget = budget;
    }

    fn crash_lease_drain_budget(&self) -> CrashLeaseDrainBudget {
        #[cfg(test)]
        {
            self.crash_lease_drain_budget
        }
        #[cfg(not(test))]
        {
            CrashLeaseDrainBudget::DEFAULT
        }
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
        crate::thread::set_current_thread_state(self.this_tid, stat);
        if self.hvpatch_task_pid.is_none() {
            crate::run_state::publish_guest_tid(self.this_tid.raw(), state);
        }
    }

    /// The crash generation this thread's safe point should answer, if a fatal
    /// sibling is collecting one right now.
    fn collecting_crash_generation(&self) -> Option<crate::kernel::CrashCaptureGeneration> {
        self.crash_capture
            .as_ref()
            .and_then(|authority| authority.collecting())
    }

    fn stash_parked_registers(&self, engine: &E) -> Result<(), RuntimeError> {
        if let Ok(Some(registers)) = engine.aarch64_core_registers() {
            if let Some(thread) = self.kernel_thread.as_ref() {
                thread.stash_parked_registers(registers);
            }
        }
        Ok(())
    }

    fn publish_crash_registers_if_requested(&self, engine: &E) -> Result<(), RuntimeError> {
        let Some(mut generation) = self.collecting_crash_generation() else {
            return Ok(());
        };
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "register-generation")
        {
            generation = generation.skewed_for_failpoint();
        }
        let registers = engine.aarch64_core_registers()?.ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks complete AArch64 register authority".to_owned(),
            )
        })?;
        let thread = self.kernel_thread.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks authoritative Kernel thread".to_owned(),
            )
        })?;
        thread.publish_crash_registers(generation, registers);
        Ok(())
    }

    /// Answer a collecting fatal sibling with "I cannot publish".
    ///
    /// Every park that reaches the task-local quiesce barrier WITHOUT a
    /// readable register file must call this before blocking. Such a thread
    /// (waiting for a vCPU lease, or for a sibling to materialise) does not
    /// resume until the barrier drops, so it can never publish for this
    /// generation — and a collector that kept waiting for it burned its full
    /// ten-second deadline and then published no core at all.
    fn withdraw_from_crash_capture(&self) {
        let (Some(generation), Some(thread)) = (
            self.collecting_crash_generation(),
            self.kernel_thread.as_ref(),
        ) else {
            return;
        };
        thread.withdraw_from_crash_capture(generation);
    }

    fn capture_core_for_publication(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        fatal: FatalSignalRecord,
    ) -> Result<Option<PreparedCorePublication>, RuntimeError> {
        // Linux default actions that carry a core. Other fatal signals still
        // publish a signal wait status, but never set WCOREDUMP.
        if !matches!(fatal.signo, 3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31) {
            return Ok(None);
        }
        let context = kernel
            .dispatcher
            .capture_kernel_context(self.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!("capture core Kernel context: {error}"))
            })?;
        let process_pid = kernel
            .hvpatch_process
            .as_ref()
            .map(crate::hvpatch::ProcessContext::pid)
            .ok_or_else(|| {
                RuntimeError::Configuration(
                    "HVPatch crash capture lacks process identity authority".to_owned(),
                )
            })?;
        let barrier = kernel.process_fork_barrier.as_ref().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch crash capture lacks task-local barrier".to_owned())
        })?;
        let authority = kernel.crash_capture.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks generation authority".to_owned(),
            )
        })?;
        let generation = authority
            .issue()
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
        let lifecycle = |phase, outcome| {
            crate::probes::hvpatch_core_lifecycle(
                phase,
                process_pid,
                fatal.tid.raw(),
                generation.get(),
                outcome,
            );
        };
        lifecycle(0, 0);
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "capture-timeout")
        {
            lifecycle(6, 1);
            return Err(RuntimeError::Configuration(
                "core publication failpoint capture-timeout".to_owned(),
            ));
        }
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "capture-interrupted")
        {
            lifecycle(6, 1);
            return Err(RuntimeError::Configuration(
                "core publication failpoint capture-interrupted".to_owned(),
            ));
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !barrier.try_begin_fork() {
            if std::time::Instant::now() >= deadline {
                lifecycle(6, 1);
                return Err(RuntimeError::Configuration(
                    "HVPatch crash capture timed out behind fork/exec quiesce".to_owned(),
                ));
            }
            std::thread::yield_now();
        }
        // Advertise BEFORE the barrier rises: a thread that parked without
        // seeing the generation would owe a register file it can never publish.
        authority.advertise(generation);
        let mut quiesced = false;
        let mut lease_drain_guard = None;
        let result = (|| {
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "capture-registers")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint capture-registers".to_owned(),
                ));
            }
            self.publish_crash_registers_if_requested(engine)?;
            // Raise the barrier whenever this task has a sibling at all. A
            // sibling parked in a futex has already released its vCPU lease,
            // so registry membership cannot decide whether the barrier is
            // needed. The identity-aware enrollment below answers its own
            // narrower question and freezes the empty sibling lease set through
            // the complete live-memory snapshot. CrashQuorum remains the sole
            // register-collection predicate.
            let crash_participants = context
                .task()
                .crash_barrier_participants(context.thread().key())
                .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
            if crash_participants.requires_quiesce() {
                barrier.set_quiescing();
                quiesced = true;
            }
            lease_drain_guard = Some(
                acquire_crash_lease_drain(
                    &*self.kicker,
                    self.this_tid,
                    self.crash_lease_drain_budget(),
                    || {
                        self.kicker.kick_all_except(self.this_tid);
                        self.futex.notify_signal_pending();
                        self.platform_futex.notify_signal_pending();
                        kernel.signal_arrival.wake_all_waiters();
                    },
                )
                .map_err(|timeout| RuntimeError::Configuration(timeout.to_string()))?,
            );
            lifecycle(1, 0);

            engine.prepare_core_snapshot().map_err(|error| {
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "prepare coherent core memory snapshot: {error}"
                )))
            })?;

            // Identity, auxv, VMAs, file provenance, cwd and RLIMIT belong to
            // the same all-thread safe point as the register files. Taking
            // this before raising the barrier would admit a concurrent
            // mmap/exec mutation between the two halves of the core.
            let process = kernel
                .dispatcher
                .core_process_snapshot(&context)
                .map_err(|error| {
                    RuntimeError::FsBackend(anyhow::anyhow!(
                        "capture quiesced core process state: {error}"
                    ))
                })?;
            if !process.dumpable || process.rlimit_core == 0 {
                return Ok(None);
            }

            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "missing-thread")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint missing-thread".to_owned(),
                ));
            }
            // The quorum is the ONLY register-collection predicate, and it
            // re-reads the task's live membership on every poll. Three
            // populations used to be conflated here: the task's thread count,
            // the live vCPU-lease count, and a one-shot membership snapshot.
            // Each over-counted, and every over-count cost the full deadline
            // and then published no core: a thread retiring mid-collection, a
            // thread whose host loop had already returned (a terminal-claim
            // loser after `exit_group`), a thread admitted into the graph whose
            // host loop was cancelled before it ever ran, and a live thread
            // parked at the barrier from a path with no readable register file.
            let quorum =
                crate::kernel::CrashQuorum::open(std::sync::Arc::clone(context.task()), generation);
            let collect_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut threads = loop {
                match quorum.poll() {
                    crate::kernel::CrashQuorumPoll::Complete(files) => {
                        break files
                            .into_iter()
                            .map(|file| {
                                let registers = file.registers;
                                let mut gregs = [0_u64; crate::core_dump::AARCH64_GREGS];
                                gregs[..31].copy_from_slice(&registers.gprs);
                                gregs[31] = registers.sp_el0;
                                // The engine selects live PC/PSTATE for a vCPU
                                // force-exited directly from EL0, or saved
                                // ELR/SPSR while a syscall is parked in EL1. A
                                // synchronous fatal owner is independently
                                // identified by its positive kernel si_code and
                                // uses the raw exception ELR/SPSR pair. Raw
                                // pairs remain in Kernel authority.
                                let synchronous_fatal_owner =
                                    file.tid == fatal.tid && fatal.code > 0;
                                let (resume_pc, resume_pstate) =
                                    core_note_resume_pair(&registers, synchronous_fatal_owner);
                                gregs[32] = resume_pc;
                                gregs[33] = resume_pstate;
                                crate::core_dump::ThreadState {
                                    tid: file.tid.raw(),
                                    registers: crate::core_dump::ThreadRegisters {
                                        gregs,
                                        tpidr_el0: registers.tpidr_el0,
                                        vregs: registers.vregs,
                                        fpsr: registers.fpsr,
                                        fpcr: registers.fpcr,
                                    },
                                    current_signal: if file.tid == fatal.tid {
                                        fatal.signo
                                    } else {
                                        0
                                    },
                                }
                            })
                            .collect::<Vec<_>>();
                    }
                    crate::kernel::CrashQuorumPoll::Waiting(tid) => {
                        if std::time::Instant::now() >= collect_deadline {
                            return Err(RuntimeError::Configuration(format!(
                                "core generation {} missing registers for tid {}",
                                generation.get(),
                                tid.raw()
                            )));
                        }
                    }
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            };
            threads.sort_by_key(|thread| (thread.tid != fatal.tid.raw(), thread.tid));
            if std::env::var_os("CARRICK_CORE_FAILPOINT").is_some_and(|value| value == "capture-mm")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint capture-mm".to_owned(),
                ));
            }
            if process.auxv.is_empty()
                || std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "missing-auxv")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing authoritative auxv".to_owned(),
                ));
            }
            if process.maps.is_empty()
                || std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "missing-vma")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing authoritative VMA state".to_owned(),
                ));
            }
            let readable_bytes = process
                .maps
                .iter()
                .filter(|map| map.read)
                .try_fold(0_u64, |total, map| {
                    total.checked_add(map.end.saturating_sub(map.start))
                })
                .ok_or_else(|| {
                    RuntimeError::Configuration(
                        "core readable-region byte count overflowed".to_owned(),
                    )
                })?;
            // No pre-emptive refusal on size: core(5) truncates an oversized
            // dump rather than suppressing it, and `to_bytes_bounded` applies
            // RLIMIT_CORE at serialisation. Failing closed here published NO
            // core and therefore cleared WCOREDUMP for any process whose
            // readable regions merely exceeded the limit.
            let _ = readable_bytes;
            let mut region_bytes = Vec::with_capacity(process.maps.len());
            for map in &process.maps {
                if !map.read {
                    region_bytes.push(Vec::new());
                    continue;
                }
                // Linux's default coredump filter omits the CONTENTS of
                // executable file-backed mappings (program/library text): the
                // oracle core lists them as PT_LOAD with p_filesz = 0 while
                // still dumping readable data/RELRO file mappings in full.
                // The `coredumpfile` probe pins this — its in-core instruction
                // lookup at the thread PCs must FAIL exactly as it does
                // against a Linux core. Overlap (not containment) match: the
                // loader's image VMA runs past the file extent (bss tail).
                // Known approximation: carrick's main/interp images are one
                // merged VMA (text+data+bss), so their DATA drops out of the
                // core alongside the text where Linux, with split VMAs, keeps
                // it; no conformance row observes that today.
                let file_backed = process
                    .file_mappings
                    .iter()
                    .any(|fm| fm.start < map.end && map.start < fm.end);
                if file_backed && map.execute {
                    region_bytes.push(Vec::new());
                    continue;
                }
                if std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "memory-read")
                {
                    return Err(RuntimeError::Configuration(
                        "core publication failpoint memory-read".to_owned(),
                    ));
                }
                let length = usize::try_from(map.end.saturating_sub(map.start)).map_err(|_| {
                    RuntimeError::Configuration(format!(
                        "core region length does not fit host usize at {:#x}",
                        map.start
                    ))
                })?;
                region_bytes.push(engine.read_core_bytes(map.start, length).map_err(|error| {
                    RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "read core region {:#x}..{:#x}: {error}",
                        map.start, map.end
                    )))
                })?);
            }
            let regions = process
                .maps
                .iter()
                .zip(&region_bytes)
                .map(|(map, bytes)| crate::core_dump::MemoryRegion {
                    start: map.start,
                    flags: crate::core_dump::region_flags(map.read, map.write, map.execute),
                    bytes: bytes.as_slice(),
                    size: map.end.saturating_sub(map.start),
                })
                .collect::<Vec<_>>();
            let mappings = process.file_mappings.clone();
            // How many `NT_PRSTATUS` notes Linux would have written, versus how
            // many carrick actually collected. They differ exactly when a live
            // thread WITHDREW from the quorum — parked where its register file
            // is unreadable — which is a real, bounded fidelity gap and is
            // reported rather than hidden behind a failed-closed core.
            let required_threads = context
                .task()
                .core_note_participants()
                .required_note_count_for_probe();
            let thread_count = u64::try_from(threads.len()).unwrap_or(u64::MAX);
            let mapping_count = u64::try_from(mappings.len()).unwrap_or(u64::MAX);
            let region_count = u64::try_from(regions.len()).unwrap_or(u64::MAX);
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "missing-file-identity")
            {
                return Err(RuntimeError::Configuration(
                    "core capture missing file mapping identity".to_owned(),
                ));
            }
            let mm = context.shared().mm().id().raw();
            let asid = kernel
                .hvpatch_process
                .as_ref()
                .and_then(crate::hvpatch::ProcessContext::mm_binding)
                .map(|binding| u32::from(binding.asid.raw()))
                .ok_or_else(|| {
                    RuntimeError::Configuration(
                        "core capture missing HVPatch ASID authority".to_owned(),
                    )
                })?;
            crate::probes::hvpatch_core_context(
                generation.get(),
                mm,
                asid,
                required_threads,
                thread_count,
            );
            lifecycle(2, 0);
            let dump = crate::core_dump::CoreDump {
                identity: process.identity.clone(),
                signal: crate::core_dump::SignalInfo {
                    signo: fatal.signo,
                    code: fatal.code,
                    errno: 0,
                    addr: fatal.addr,
                },
                threads,
                auxv: process.auxv.clone(),
                mappings,
                regions,
            };
            let bytes = dump
                .to_bytes_bounded(process.rlimit_core)
                .map_err(|error| {
                    RuntimeError::FsBackend(anyhow::anyhow!("serialise bounded core: {error}"))
                })?;
            if std::env::var_os("CARRICK_CORE_FAILPOINT").is_some_and(|value| value == "validator")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint validator".to_owned(),
                ));
            }
            use sha2::Digest as _;
            let digest: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            let mut hash_words = [0_u64; 4];
            for (word, octets) in hash_words.iter_mut().zip(digest.chunks_exact(8)) {
                let mut octet_array = [0_u8; 8];
                octet_array.copy_from_slice(octets);
                *word = u64::from_be_bytes(octet_array);
            }
            crate::probes::hvpatch_core_census(
                generation.get(),
                mapping_count,
                4_u64.saturating_add(thread_count.saturating_mul(3)),
                region_count,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            );
            crate::probes::hvpatch_core_hash(generation.get(), hash_words);
            lifecycle(3, 0);
            Ok(Some(PreparedCorePublication {
                snapshot: process,
                bytes,
                // Wire boundary: the publication path and its probes carry the
                // raw generation number.
                generation: generation.get(),
                fatal_tid: fatal.tid.raw(),
            }))
        })();
        if result.is_err() || matches!(&result, Ok(None)) {
            lifecycle(6, if result.is_err() { 1 } else { 2 });
        }
        finish_crash_collection(authority, barrier, quiesced, lease_drain_guard, result)
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
        let edits_stage1 =
            syscall_takes_pre_dispatch_pt_pause(frame.number.raw(), frame.args[2], true);
        let mut stage1_authority = if edits_stage1 {
            match quiesce::acquire_mm_stage1_authority(
                mm_executor,
                self.this_tid,
                quiesce::PtPauseBudget::DEFAULT,
            ) {
                Ok(authority) => Some(authority),
                Err(
                    quiesce::PtPauseError::TimedOut | quiesce::PtPauseError::UnkickableExecutor,
                ) => {
                    // No dispatcher/backend mapping call has started yet. Return
                    // a clean Linux allocation failure after pt_pause rolled the
                    // request back and resumed already-parked siblings. This is
                    // still a completed syscall boundary, so retain the exact
                    // context required by errno completion and signal service.
                    let kernel_context = kernel
                        .dispatcher
                        .capture_kernel_context(self.linux_tid)
                        .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture timed-out page-table pause kernel context: {error}"
                        ))
                    })?;
                    self.service_kernel_context = Some(kernel_context.retain_exact());
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ENOMEM));
                }
            }
        } else {
            None
        };
        // The parked-slice, sleep/poll deadline and child-wait trace state that
        // used to live here belonged to the in-loop compatibility wait arms.
        // Every blocking outcome now escapes to the executor's continuation
        // before the match, so this function owns no wait state at all.
        let kernel_context = kernel
            .dispatcher
            .capture_kernel_context(self.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!(
                    "capture mandatory syscall kernel context: {error}"
                ))
            })?;
        // Retain the exact entry generation across every blocking continuation
        // and the post-syscall signal-delivery boundary. Lifecycle outcomes
        // consume this slot through `take_service_kernel_context`; ordinary
        // outcomes leave it available to signal delivery below.
        self.service_kernel_context = Some(kernel_context.retain_exact());
        self.observers = kernel.dispatcher.observers().cloned();
        let _syscall_guard = kernel.hvpatch_process.as_ref().and_then(|proc| {
            let (pid, asid) = proc.syscall_trace_identity()?;
            HvpatchSyscallServiceGuard::begin(
                pid,
                self.linux_tid.raw(),
                asid,
                frame.number.raw(),
                frame.args,
            )
        });
        let sync_shared_file_aliases = engine.needs_shared_file_alias_sync();
        'service: {
            if sync_shared_file_aliases && !matches!(frame.number.raw(), 260 | 95) {
                engine.sync_shared_file_aliases()?;
            }
            let request = SyscallRequest::from_raw(frame)
                .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi())
                .with_current_guest_sp(engine.get_reg(carrick_hal::Reg::Sp).ok());
            self.current_syscall_request = Some(request);
            let outcome =
                dispatch_with_panic_backstop(request.number.raw(), self.this_tid, || {
                    if crate::dispatch::syscall_requires_mm_mutation(
                        request.number.raw(),
                        request.args,
                    ) {
                        let coordinator = kernel.dispatcher.mm_mutation_coordinator();
                        match stage1_authority.as_mut().unwrap_or_else(|| {
                            tracing::error!("mutation dispatch lacks outer stage-1 authority");
                            std::process::abort();
                        }) {
                            quiesce::MmStage1Authority::Sole(authority) => {
                                let mut mutation = crate::dispatch::mm_mutation::from_sole_executor(
                                    authority,
                                    coordinator,
                                    kernel_context.shared().mm().id(),
                                );
                                kernel.dispatcher.dispatch_threaded_mutation(
                                    &kernel_context,
                                    request,
                                    engine,
                                    &kernel.reporter,
                                    self.this_tid,
                                    &self.registry,
                                    &self.futex,
                                    &mut mutation,
                                )
                            }
                            quiesce::MmStage1Authority::Paused(authority) => {
                                let mut mutation =
                                    crate::dispatch::mm_mutation::from_pt_pause(authority);
                                kernel.dispatcher.dispatch_threaded_mutation(
                                    &kernel_context,
                                    request,
                                    engine,
                                    &kernel.reporter,
                                    self.this_tid,
                                    &self.registry,
                                    &self.futex,
                                    &mut mutation,
                                )
                            }
                        }
                    } else {
                        kernel.dispatcher.dispatch_threaded(
                            &kernel_context,
                            request,
                            engine,
                            &kernel.reporter,
                            self.this_tid,
                            &self.registry,
                            &self.futex,
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
                | DispatchOutcome::WaitOnFdsSelect { .. }
                | DispatchOutcome::WaitOnPollFds { .. }
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
                    file,
                    shared,
                    prot,
                    prot_none,
                } if kernel.hvpatch_process.is_some() => {
                    let file = file.map(|(fd, offset, prot)| (fd.into_owned_fd(), offset, prot));
                    let coordinator = kernel.dispatcher.mm_mutation_coordinator();
                    let install_alias =
                        |permit: &crate::dispatch::mm_mutation::HostAliasPermit<'_>| {
                            let Some(install) = transaction.claim(permit) else {
                                drop(file);
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

                            if let Err(error) = engine.map_host_alias_with_sharing(
                                va,
                                ipa,
                                len,
                                &payload,
                                file.map(|(fd, offset, prot)| (fd.into_raw_fd(), offset, prot)),
                                shared,
                            ) {
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
                            let Some(commit) = engine.take_alias_inventory() else {
                                std::process::abort();
                            };
                            // Serialize both the reservation slot and raw HVF topology
                            // mutation. Authority publication takes its own lock only
                            // after the topology lock and backend locks are released.
                            drop(topology);
                            if apply_alias_frame_inventory(&kernel_context, commit).is_err() {
                                std::process::abort();
                            }

                            let Ok(len) = usize::try_from(len) else {
                                std::process::abort();
                            };
                            if prot_none && engine.protect_range(va.raw(), len, 0).is_err() {
                                std::process::abort();
                            }
                            engine.set_mapping_protection_and_sharing(
                                va.raw(),
                                len,
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
                                    std::process::abort();
                                };
                                if engine.protect_range(bus_start, bus_len, 0).is_err() {
                                    std::process::abort();
                                }
                                engine.set_no_access(bus_start, bus_len, true);
                            }
                            if kernel
                                .dispatcher
                                .commit_host_alias_install(install)
                                .is_err()
                            {
                                std::process::abort();
                            }
                            Ok(DispatchOutcome::Returned {
                                value: success_retval,
                            })
                        };
                    let installed = match stage1_authority.as_mut().unwrap_or_else(|| {
                        tracing::error!("host-alias install lacks outer stage-1 authority");
                        std::process::abort();
                    }) {
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
        &self,
        engine: &mut E,
        value: i64,
    ) -> Result<i64, RuntimeError> {
        engine.complete_syscall(value)?;
        if let (Some(context), Some(request), Some(chain)) = (
            &self.service_kernel_context,
            &self.current_syscall_request,
            &self.observers,
        ) {
            let p = crate::observe::ProcessInfo::new(context);
            let s = crate::observe::SyscallInfo::new(request);
            let o = crate::observe::SyscallOutcome::from_retval(value);
            chain.on_syscall_return(&p, &s, &o);
        }
        Ok(value)
    }

    pub(super) fn complete_errno(
        &self,
        engine: &mut E,
        errno: LinuxErrno,
    ) -> Result<i64, RuntimeError> {
        self.complete_returned(engine, errno.guest_retval())
    }
}

/// Wall-clock budget for the trap watchdog: a guest that keeps trapping but makes
/// NO signal-handler progress for this long is treated as genuinely wedged. The
/// default (30s) is comfortably above any legitimate syscall-bound burst (e.g. a
/// 10s SIGALRM-bounded `gettimeofday` loop) yet below the conformance harness's
/// outer per-run timeout (~40s), so a real wedge aborts cleanly here rather than
/// via the harness SIGKILL. Override with `CARRICK_MAX_WALL_MS`.
fn trap_watchdog_wall_window() -> std::time::Duration {
    let ms = std::env::var("CARRICK_MAX_WALL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(30_000);
    std::time::Duration::from_millis(ms)
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
        directory: Arc<HvpatchRuntimeDirectory>,
        shutdown_on_wait: bool,
    },
}

/// The call that installed the shared carrier pool owns its one terminal
/// shutdown. Logical guest parentage and host launch topology are unrelated:
/// a DTrace-created root is still the pool creator, while a descendant that
/// reuses the inherited directory is not.
const fn persistent_pool_shutdown_on_wait(started_pool: bool) -> bool {
    started_pool
}

/// A guest thread's handle in the process-private thread list. The retired
/// `Job` variant carried a transitional-runner task receipt, which nothing on
/// the persistent path ever produced.
pub(crate) enum VcpuThreadHandle {
    Persistent {
        terminal_settlement: HvpatchExternalTerminalSettlement,
    },
}

impl VcpuThreadHandle {
    fn completion(&self) -> continuation::LogicalJobCompletion {
        match self {
            Self::Persistent {
                terminal_settlement,
            } => terminal_settlement.completion(),
        }
    }

    fn finish_completed(self, current: continuation::JobId) -> Result<(), RuntimeError> {
        match self {
            Self::Persistent {
                terminal_settlement,
            } if terminal_settlement.completion().id() == current => Ok(()),
            Self::Persistent {
                terminal_settlement,
            } => {
                terminal_settlement.publish_member(Ok(VcpuLoopOutcome::ThreadDone))?;
                if !terminal_settlement.is_published()
                    || !terminal_settlement.completion().is_finished()
                {
                    return Err(RuntimeError::Configuration(
                        "external persistent terminal settlement violated result-before-completion"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

fn enroll_persistent_process_member(
    threads: &Arc<Mutex<Vec<VcpuThreadHandle>>>,
    terminal_settlement: &HvpatchExternalTerminalSettlement,
) {
    let mut handles = threads.lock();
    if handles
        .iter()
        .any(|handle| handle.completion().id() == terminal_settlement.completion().id())
    {
        std::process::abort();
    }
    handles.push(VcpuThreadHandle::Persistent {
        terminal_settlement: terminal_settlement.clone(),
    });
}

fn remove_persistent_process_member(
    threads: &Arc<Mutex<Vec<VcpuThreadHandle>>>,
    completion: continuation::JobId,
) {
    threads
        .lock()
        .retain(|handle| handle.completion().id() != completion);
}

fn finish_persistent_process_handles(
    threads: &Arc<Mutex<Vec<VcpuThreadHandle>>>,
    current: continuation::JobId,
) -> Result<(), RuntimeError> {
    let handles = std::mem::take(&mut *threads.lock());
    for handle in handles {
        handle.finish_completed(current)?;
    }
    Ok(())
}

pub(crate) struct PersistentProcessMemberPublication {
    threads: Arc<Mutex<Vec<VcpuThreadHandle>>>,
    completion: continuation::JobId,
    armed: bool,
}

impl PersistentProcessMemberPublication {
    pub(crate) fn new(
        threads: Arc<Mutex<Vec<VcpuThreadHandle>>>,
        terminal_settlement: &HvpatchExternalTerminalSettlement,
    ) -> Self {
        enroll_persistent_process_member(&threads, terminal_settlement);
        Self {
            threads,
            completion: terminal_settlement.completion().id(),
            armed: true,
        }
    }

    pub(crate) fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for PersistentProcessMemberPublication {
    fn drop(&mut self) {
        if self.armed {
            remove_persistent_process_member(&self.threads, self.completion);
        }
    }
}

/// The root launch's deferred pool-shutdown obligation. The root main
/// thread's job can complete (even as a terminal-claim LOSER, with
/// `ThreadDone`) while the winning sibling OWNER is still running process
/// teardown on the persistent pool — so the pool must not close until the
/// caller has waited for the owner's terminal publication. Shutting down
/// inside `wait()` stranded the owner mid-teardown: its wakes hit "run
/// queue is closed" and every fork-storm exit died on "HVPatch terminal
/// owner did not complete teardown" (reducer: `forkstackstorm`).
pub(crate) struct PersistentPoolShutdown {
    directory: Arc<HvpatchRuntimeDirectory>,
}

impl PersistentPoolShutdown {
    pub(crate) fn shutdown(self) -> Result<(), RuntimeError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.directory.shutdown_persistent_pool()
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            let _ = &self.directory;
            Ok(())
        }
    }
}

impl VcpuLoopLaunch {
    /// Wait for the root main-thread job. Pool shutdown is NOT performed
    /// here: the caller must first drain the process topology and the
    /// terminal owner's publication, then consume the returned
    /// [`PersistentPoolShutdown`]. See its doc for the ordering defect this
    /// prevents.
    pub(crate) fn wait_deferring_pool_shutdown(
        self,
    ) -> (
        Result<VcpuLoopOutcome, RuntimeError>,
        Option<PersistentPoolShutdown>,
    ) {
        match self {
            Self::Direct(result) => (result, None),
            Self::Persistent {
                result,
                directory,
                shutdown_on_wait,
                ..
            } => {
                let outcome = result.wait();
                tracing::info!(
                    shutdown_on_wait,
                    outcome = match &outcome {
                        Ok(VcpuLoopOutcome::ProcessExit(_)) => "process-exit",
                        Ok(VcpuLoopOutcome::ThreadDone) => "thread-done",
                        Ok(_) => "other-ok",
                        Err(_) => "error",
                    },
                    "HVPatch root launch wait returned"
                );
                let shutdown = shutdown_on_wait.then_some(PersistentPoolShutdown { directory });
                (outcome, shutdown)
            }
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct PreparedHvpatchLogicalJob {
    binding: Arc<continuation::HvpatchTaskBinding>,
    result: HvpatchLoopResult,
    completion: continuation::LogicalJobCompletion,
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
struct HvpatchLogicalJobInput {
    kernel: Kernel,
    state: ThreadRuntimeState<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>,
    task_backend: executor::HvpatchTaskEngineBindingState,
    context: crate::kernel::KernelContext,
    cpu: crate::kernel::objects::MigratableTaskState,
    generation: crate::kernel::objects::ExecutionGeneration,
    injected_lease: Arc<InjectedExecutionLeaseSlot>,
    bootstrap_process_child: Option<(bool, Option<(u64, i32)>)>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn prepare_hvpatch_logical_job(
    input: HvpatchLogicalJobInput,
) -> Result<PreparedHvpatchLogicalJob, TrapError> {
    let HvpatchLogicalJobInput {
        kernel,
        state,
        task_backend,
        context,
        cpu,
        generation,
        injected_lease,
        bootstrap_process_child,
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
    let identity = executor::TaskLoadIdentity {
        abi: cpu.cpu.guest_abi(),
        version: cpu.cpu.version(),
        mm: cpu.mm,
        asid_generation: cpu.asid_generation,
    };
    let stage1_mm = kernel
        .hvpatch_process
        .as_ref()
        .ok_or_else(|| TrapError::Hypervisor("HVPatch logical job has no process MM".to_owned()))?
        .stage1_mm_lease()
        .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
    let production = ProductionHvpatchLoopJob {
        kernel,
        state,
        phase: bootstrap_process_child.map_or(
            HvpatchProductionPhase::Resident,
            |(shares_mm, child_settid)| HvpatchProductionPhase::BootstrapProcessChild {
                shares_mm,
                child_settid,
            },
        ),
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
    threads: Arc<Mutex<Vec<VcpuThreadHandle>>>,
    kicker: Arc<dyn VcpuRegistry>,
    in_guest: carrick_hal::InGuestFlag,
    max_traps: usize,
) -> VcpuLoopLaunch
where
    E::SiblingSpec: 'static,
{
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
        let prepared_task = prepared
            .task
            .take()
            .unwrap_or_else(|| std::process::abort());
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
        let process_members = Arc::clone(&threads);
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
        let directory = kernel
            .hvpatch_runtime
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
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
            logical.context.kernel(),
            authority,
            <HvfEngine as ThreadedEngine>::vcpu_budget(),
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
            directory: Arc::clone(directory),
            shutdown_on_wait: persistent_pool_shutdown_on_wait(started_pool),
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
        let binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch initial runner task has no ASID".to_owned())
        })?;
        engine.bind_frame_cow(
            Arc::new(KernelFrameCowAuthority {
                kernel: Arc::clone(context.kernel()),
                mm,
                guest_executors: kernel.dispatcher.mm_executor_census(),
                tid: this_tid,
                identity: carrick_hal::FrameCowIdentity {
                    linux_pid: process.pid(),
                    linux_tid: this_tid.raw(),
                    mm: mm.raw(),
                    asid: binding.asid.raw(),
                },
            }),
            carrick_hal::FrameCowIdentity {
                linux_pid: process.pid(),
                linux_tid: this_tid.raw(),
                mm: mm.raw(),
                asid: binding.asid.raw(),
            },
        );
    }
    let directory = kernel.hvpatch_runtime.as_ref().ok_or_else(|| {
        RuntimeError::Configuration("initial runner task has no runtime directory".to_owned())
    })?;
    let (scheduler, _service) = directory.continuation_services(context.kernel());
    let cpu = engine
        .save_initial_runner_state()
        .map_err(RuntimeError::Trap)?;
    let state = crate::kernel::objects::MigratableTaskState {
        cpu,
        mm,
        asid_generation,
    };
    let retained_cpu = state.clone();
    let generation = context
        .thread()
        .publish_initial_task_state(state)
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
fn trap_watchdog_decision(
    traps_since_signal: usize,
    max_traps: usize,
    elapsed: std::time::Duration,
    max_wall: std::time::Duration,
) -> TrapWatchdog {
    if traps_since_signal <= max_traps {
        TrapWatchdog::KeepRunning
    } else if elapsed >= max_wall {
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

/// Snapshot the shared kernel buffers + reporter into a RunResult. Called on
/// whole-process exit / trap limit.
pub(crate) fn assemble_run_result(
    kernel: &Kernel,
    exit_code: i32,
    terminating_signal: Option<i32>,
    traps: usize,
    trap_limit_hit: bool,
) -> RunResult {
    crate::probes::guest_exit(exit_code);
    kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
    let report = kernel.reporter.snapshot();
    let terminal_reason = if trap_limit_hit {
        Some(crate::runtime::TerminalReason::TrapLimit)
    } else {
        None
    };
    RunResult {
        exit_code,
        terminating_signal,
        stdout: kernel.dispatcher.stdout(),
        stderr: kernel.dispatcher.stderr(),
        traps,
        report,
        trap_limit_hit,
        terminal_reason,
    }
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

fn shared_futex_wake(host_addr: usize, waiter_key: usize, count: u32) -> i64 {
    let carrier_woken =
        carrick_thread::platform_futex::carrier_shared_futex_table().wake(waiter_key as u64, count);
    let ulock_woken = crate::ulock::wake_counted(host_addr, waiter_key, count);
    crate::probes::ulock_wake(host_addr as u64, 0, ulock_woken);
    i64::from(carrier_woken).max(ulock_woken.max(0))
}

fn trace_shared_futex_requeue(
    phase: u32,
    from_key: usize,
    to_key: usize,
    wake_req: u32,
    requeue_req: u32,
    wake_ret: u32,
    requeue_ret: u32,
) {
    let from = crate::ulock::waiter_debug_counts(from_key);
    let to = crate::ulock::waiter_debug_counts(to_key);
    crate::probes::ulock_requeue(crate::probes::UlockRequeueProbe {
        phase,
        from_key: from_key as u64,
        to_key: to_key as u64,
        wake_req,
        requeue_req,
        wake_ret,
        requeue_ret,
        from_count: from.count,
        from_requeue_wake: from.requeue_wake,
        from_requeue_count: from.requeue_count,
        from_logical_requeued: from.logical_requeued,
        from_logical_wake: from.logical_wake,
        to_count: to.count,
        to_requeue_wake: to.requeue_wake,
        to_requeue_count: to.requeue_count,
        to_logical_requeued: to.logical_requeued,
        to_logical_wake: to.logical_wake,
    });
}

#[cfg(test)]
mod tests {
    use super::signal::{lower_el0_fault, upgrade_protection_si_code};
    use super::*;
    use crate::vcpu_loop::executor::TaskBindingResolver;
    use carrick_guest_mem::GuestMemory;
    use std::cell::RefCell;
    use std::num::NonZeroU64;
    use std::time::Duration;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn fork_request(plan: carrick_hal::ForkProjectionPlan) -> carrick_hal::ProcessForkRequest {
        carrick_hal::ProcessForkRequest {
            entry: carrick_hal::GuestEntryRegs::default(),
            child_ttbr0: 0,
            root_slot_base: 0,
            root_slot_size: 0,
            plan,
            child_tid: carrick_hal::ThreadId::NONE,
            forking_tid: carrick_hal::ThreadId::NONE,
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn projection_ranges() -> Arc<[carrick_hal::ForkProjectionRange]> {
        Arc::from([carrick_hal::ForkProjectionRange {
            va: 0x1000,
            len: 0x1000,
            disposition: carrick_hal::ForkLeafDisposition::Preserve,
        }])
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn backend_fork_boundary_rejects_wrong_inventory_mode_and_mm_identity() {
        let mut reserve = |_, _, _| {
            Err(RuntimeError::Configuration(
                "validation test must not reserve inventory".to_owned(),
            ))
        };
        let copied_inventory = HvpatchProcessInventoryPreparation::Copied(&mut reserve);
        let shared = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 7,
            ranges: projection_ranges(),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&copied_inventory, &shared, 8).is_err());

        let wrong_child = fork_request(carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 7,
            child_mm: 9,
            ranges: projection_ranges(),
        });
        assert!(
            validate_hvpatch_process_prepare_boundary(&copied_inventory, &wrong_child, 8).is_err()
        );

        let shared_inventory = HvpatchProcessInventoryPreparation::SharedMm { kernel_mm: 7 };
        let copied = fork_request(carrick_hal::ForkProjectionPlan::Copied {
            parent_mm: 7,
            child_mm: 8,
            ranges: projection_ranges(),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&shared_inventory, &copied, 8).is_err());
        let wrong_shared_mm = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 8,
            ranges: projection_ranges(),
        });
        assert!(
            validate_hvpatch_process_prepare_boundary(&shared_inventory, &wrong_shared_mm, 8)
                .is_err()
        );
        let right_shared_mm_wrong_generation =
            fork_request(carrick_hal::ForkProjectionPlan::Shared {
                parent_mm: 7,
                ranges: projection_ranges(),
            });
        assert!(
            validate_hvpatch_process_prepare_boundary(
                &shared_inventory,
                &right_shared_mm_wrong_generation,
                8,
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn backend_fork_boundary_rejects_invalid_projection_before_prepare() {
        let inventory = HvpatchProcessInventoryPreparation::SharedMm { kernel_mm: 7 };
        let request = fork_request(carrick_hal::ForkProjectionPlan::Shared {
            parent_mm: 7,
            ranges: Arc::from([carrick_hal::ForkProjectionRange {
                va: 0x1001,
                len: 0x1000,
                disposition: carrick_hal::ForkLeafDisposition::Preserve,
            }]),
        });
        assert!(validate_hvpatch_process_prepare_boundary(&inventory, &request, 7).is_err());
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn initial_cpu_cleanup_attempts_cancel_and_rollback_after_abort_failure() {
        let calls = RefCell::new(Vec::new());
        let result = cleanup_failed_hvpatch_initial_cpu(
            || {
                calls.borrow_mut().push("abort");
                Err(RuntimeError::Configuration("abort failed".to_owned()))
            },
            &mut (),
            |_| {
                calls.borrow_mut().push("cancel");
                Err(RuntimeError::Configuration("cancel failed".to_owned()))
            },
            |_| {
                calls.borrow_mut().push("rollback");
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(*calls.borrow(), ["abort", "cancel", "rollback"]);
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn prepared_unwind_attempts_parent_rollback_after_abort_failure() {
        let mut ops = FakeBackendOps {
            abort_fails: true,
            ..Default::default()
        };
        let mut memory = Memory::default();
        let result = ops.abort_and_rollback_prepared((), &mut memory, true);
        assert!(result.is_err());
        assert_eq!(ops.aborts, 1);
        assert_eq!(ops.parent_rollbacks, 1);
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
            .find(concat!("publish_initial_", "task_state(state)"))
            .expect("initial task state must be published");
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

    #[test]
    fn proc_maps_projects_linux_initial_stack_vma_not_full_rlimit_backing() {
        let image = crate::memory::AddressSpace::from_regions(0x1_0000, Vec::new())
            .expect("empty image")
            .with_linux_initial_stack([b"tool".as_slice()], [b"KEY=value".as_slice()])
            .expect("initial stack");
        let initial_sp = image.initial_stack_pointer().expect("initial SP");
        let maps = proc_maps_from_address_space(&image);
        let stack = maps
            .iter()
            .find(|mapping| mapping.path == "[stack]")
            .expect("Linux-visible stack VMA");
        let expected_start =
            initial_sp.saturating_sub(128 * 1024) & !(crate::linux_abi::LINUX_PAGE_SIZE - 1);

        assert_eq!(stack.start, expected_start);
        assert_eq!(stack.end, crate::memory::LINUX_STACK_TOP);
        assert!(
            stack.start > crate::memory::LINUX_STACK_TOP - crate::memory::LINUX_STACK_SIZE,
            "the full RLIMIT-sized backing is not the initially grown Linux VMA"
        );
    }

    #[test]
    fn identity_gate_stays_shut_over_an_unpublishable_pid() {
        // `getpid()` never returns 0 on Linux, so a zero identity means "not
        // knowable yet", not "zero" — an unregistered pid-namespace
        // translation resolves to 0 via `unwrap_or(0)` in `identity_pid`.
        // Opening the fast path over it publishes a pid no process has, and
        // the guest reads it with NO vm exit, so nothing re-checks it. Seen as
        // a container's init reporting `getpid=0`.
        //
        // Drop the `pid != 0` term and the first assertion fails.
        assert_eq!(
            identity_gate_word(true, 0),
            0,
            "an unpublishable identity must leave the fast path SHUT"
        );
        assert_eq!(
            identity_gate_word(true, 1),
            1,
            "a real pid still opens the fast path"
        );
        assert_eq!(
            identity_gate_word(false, 1),
            0,
            "a caller that disabled the fast path still wins"
        );
    }

    #[test]
    fn identity_stamp_closes_the_shim_gate_before_publishing_a_new_pid() {
        // The shim word gates a userspace read with NO vm exit, so the guest
        // may look at this page at any instant. Starting from a page that a
        // previous container left ENABLED with a stale pid, the stamp must
        // never leave the gate open over a pid it has not written yet —
        // otherwise the guest reads a pid that belongs to no one (observed as
        // `getpid=0` from a container's init, which no Linux process reports).
        //
        // Records the exact write order and asserts the gate is shut before the
        // pid moves and reopened only after. Under the old order (pid, then
        // gate) the first recorded write is the pid, and this fails.
        #[derive(Default)]
        struct RecordingMemory {
            base: u64,
            page: Vec<u8>,
            order: Vec<(u64, u64)>,
        }
        impl carrick_guest_mem::GuestMemory for RecordingMemory {
            fn read_bytes_raw(
                &self,
                addr: u64,
                len: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                Ok(self.page[off..off + len].to_vec())
            }
            fn write_bytes_raw(
                &mut self,
                addr: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                let off = (addr - self.base) as usize;
                self.page[off..off + bytes.len()].copy_from_slice(bytes);
                let mut word = [0u8; 8];
                let n = bytes.len().min(8);
                word[..n].copy_from_slice(&bytes[..n]);
                self.order
                    .push((addr - self.base, u64::from_le_bytes(word)));
                Ok(())
            }
        }
        impl carrick_guest_mem::CurrentMmMemory for RecordingMemory {}

        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = RecordingMemory {
            base,
            page: vec![0; 4096],
            order: Vec::new(),
        };
        // The predecessor's residue: gate open, someone else's pid.
        memory.page[crate::memory::IDENTITY_OFF_SHIM_ENABLED as usize] = 1;
        memory.page[crate::memory::IDENTITY_OFF_PID as usize] = 7;

        stamp_identity_values(&mut memory, base, 1, 1).expect("stamp");

        let gate = crate::memory::IDENTITY_OFF_SHIM_ENABLED;
        let pid_off = crate::memory::IDENTITY_OFF_PID;
        let first_gate_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == gate)
            .expect("the gate must be written");
        let pid_write = memory
            .order
            .iter()
            .position(|(off, _)| *off == pid_off)
            .expect("the pid must be written");
        assert!(
            first_gate_write < pid_write,
            "the shim gate must be CLOSED before the pid moves; write order was {:?}",
            memory.order
        );
        assert_eq!(
            memory.order[first_gate_write].1, 0,
            "the first gate write must shut it, not re-open it"
        );
        assert_eq!(
            memory.order.last().map(|(off, val)| (*off, *val)),
            Some((gate, 1)),
            "the gate must be re-opened LAST, after pid and ledger are published"
        );
    }

    #[test]
    fn identity_page_stamp_surfaces_guest_memory_write_failure() {
        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let mut memory = crate::dispatch::LinearMemory::new(base, vec![0; 4]);
        let error = stamp_identity_values(&mut memory, base, 123, 1)
            .expect_err("second identity word is outside the backing");
        assert!(matches!(
            error,
            carrick_guest_mem::MemoryError::OutOfBounds { .. }
        ));
    }

    #[test]
    fn mandatory_child_contextidr_stamp_propagates_injected_failure() {
        let (_, context) = crate::hvpatch::process_context_for_tests(70_200);
        let tid = context.thread().key().tid;
        let error = stamp_guest_tid_with(true, Some(tid), |_| {
            Err(TrapError::Hypervisor(
                "injected CONTEXTIDR failure".to_owned(),
            ))
        })
        .unwrap_err();
        assert!(error.to_string().contains("CONTEXTIDR"));
    }

    #[test]
    fn hvpatch_process_child_identity_bootstrap_handles_shared_and_copied_mm() {
        let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
        let read_state = |m: &crate::dispatch::LinearMemory| {
            let pid = u32::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_PID, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let enabled = u32::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_SHIM_ENABLED, 4)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            let syscalls = u64::from_le_bytes(
                m.read_bytes_raw(base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS, 8)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            );
            (pid, enabled, syscalls)
        };

        let mut memory = crate::dispatch::LinearMemory::new(base, vec![0; 4096]);
        let (parent_pid, parent_counter): (u32, u64) = (70_301, 127);
        stamp_identity_values(&mut memory, base, parent_pid, 1).unwrap();
        memory
            .write_bytes(
                base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
                &parent_counter.to_le_bytes(),
            )
            .unwrap();

        let (_child_process, child_context) = crate::hvpatch::process_context_for_tests(70_302);
        let dispatcher = SyscallDispatcher::new();
        let child_pid = dispatcher.identity_snapshot(&child_context).pid;
        assert_ne!(child_pid, parent_pid);

        // 1. Shared-MM: preserves parent PID and counter, clears enabled word.
        bootstrap_hvpatch_process_child_identity_with(
            &mut memory,
            &dispatcher,
            &child_context,
            true,
            true,
        )
        .unwrap();
        assert_eq!(read_state(&memory), (parent_pid, 0, parent_counter));

        // 2. Copied-MM: stamps child PID and enabled state, resets counter.
        let mut child_memory = crate::dispatch::LinearMemory::new(base, vec![0; 4096]);
        stamp_identity_values(&mut child_memory, base, parent_pid, 1).unwrap();
        child_memory
            .write_bytes(
                base + crate::memory::IDENTITY_OFF_SHIM_SYSCALLS,
                &parent_counter.to_le_bytes(),
            )
            .unwrap();

        bootstrap_hvpatch_process_child_identity_with(
            &mut child_memory,
            &dispatcher,
            &child_context,
            false,
            true,
        )
        .unwrap();
        assert_eq!(read_state(&child_memory), (child_pid, 1, 0));
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

    #[test]
    fn fatal_core_authority_belongs_only_to_the_matching_terminal_owner() {
        let context = alias_context(67_104);
        let owner = context.thread().key().tid;
        let fatal = FatalSignalRecord {
            image_generation: 1,
            tid: owner,
            signo: 11,
            code: 1,
            addr: 0,
        };
        assert_eq!(
            fatal_for_terminal_owner(Some(fatal), 1, owner, Some(11)),
            Some(fatal)
        );
        assert_eq!(fatal_for_terminal_owner(Some(fatal), 1, owner, None), None);

        let other = alias_context(67_105).thread().key().tid;
        assert_eq!(
            fatal_for_terminal_owner(Some(fatal), 1, other, Some(11)),
            None,
            "a losing fatal thread cannot core-dump the winning owner"
        );
    }

    #[test]
    fn core_note_uses_exception_pair_only_for_synchronous_fatal_owner() {
        let registers = carrick_hal::Aarch64CoreRegisters {
            resume_pc: 0x1111,
            resume_pstate: 0x2222,
            elr_el1: 0x3333,
            spsr_el1: 0x4444,
            ..carrick_hal::Aarch64CoreRegisters::default()
        };
        assert_eq!(
            core_note_resume_pair(&registers, false),
            (0x1111, 0x2222),
            "running and syscall-blocked siblings use the engine-selected EL0 pair"
        );
        assert_eq!(
            core_note_resume_pair(&registers, true),
            (0x3333, 0x4444),
            "a positive si_code binds the fatal owner to the synchronous exception pair"
        );
    }

    #[test]
    fn fatal_core_authority_rebinds_at_exec_and_rejects_late_old_image_signal() {
        let context = alias_context(67_106);
        let owner = context.thread().key().tid;
        let authority = Arc::new(FatalSignalAuthority::default());
        let old_image = authority.current_generation();
        let old_fatal = FatalSignalRecord {
            image_generation: old_image,
            tid: owner,
            signo: 11,
            code: 1,
            addr: 0xfeed,
        };
        assert!(authority.record(old_fatal));

        let fatal_loser_release = Arc::new(std::sync::Barrier::new(2));
        let replacement_image = std::thread::scope(|scope| {
            let losing_authority = authority.clone();
            let losing_release = fatal_loser_release.clone();
            let losing_fatal = scope.spawn(move || {
                losing_release.wait();
                losing_authority.record(old_fatal)
            });
            let replacement_image = authority
                .rebind_after_exec(old_image)
                .expect("current exec generation rebinds");
            fatal_loser_release.wait();
            assert!(
                !losing_fatal.join().expect("fatal race participant"),
                "the pre-exec fatal participant released after exec must lose deterministically"
            );
            replacement_image
        });
        assert_ne!(replacement_image, old_image);
        assert_eq!(authority.recorded_for(replacement_image), None);

        let replacement_fatal = FatalSignalRecord {
            image_generation: replacement_image,
            tid: owner,
            signo: 6,
            code: 0,
            addr: 0,
        };
        assert!(authority.record(replacement_fatal));
        assert_eq!(
            fatal_for_terminal_owner(
                authority.recorded_for(replacement_image),
                replacement_image,
                owner,
                Some(6),
            ),
            Some(replacement_fatal)
        );
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

    struct EndpointTestSignalPump;

    impl SignalPumpControl for EndpointTestSignalPump {
        fn start_signal_pump(
            &self,
            _registry: &Arc<dyn VcpuRegistry>,
            _futex: &Arc<dyn PlatformFutex>,
        ) {
        }
    }

    struct EndpointTestSignalArrival;

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

    #[test]
    fn production_clone_failpoints_are_exact_and_consumed_once() {
        #[derive(Default)]
        struct Memory(std::collections::BTreeMap<u64, Vec<u8>>);
        impl threads::CloneTidMemory for Memory {
            fn read_clone_tid_bytes(
                &self,
                address: u64,
                _len: usize,
            ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
                self.0
                    .get(&address)
                    .cloned()
                    .ok_or(carrick_guest_mem::MemoryError::OutOfBounds { address, length: 4 })
            }

            fn write_clone_tid_bytes(
                &mut self,
                address: u64,
                bytes: &[u8],
            ) -> Result<(), carrick_guest_mem::MemoryError> {
                self.0.insert(address, bytes.to_vec());
                Ok(())
            }
        }

        struct FakeBackendOps;
        impl HvpatchCloneBackendOps<Memory> for FakeBackendOps {
            type Prepared = ();
            type Backend = ();

            fn prepare(
                &mut self,
                _memory: &Memory,
                _identity: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity,
                _entry: carrick_hal::GuestEntryRegs,
                mm_generation: u64,
                asid_generation: u64,
            ) -> Result<(Self::Prepared, carrick_hal::threaded::GuestCpuState), RuntimeError>
            {
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
                _directory: Arc<
                    carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskStateDirectory,
                >,
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

        struct NoopPlatformFutex;
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

        let request = HvpatchCloneThreadRequest {
            stack: 0x9000,
            tls: None,
            flags: (carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM)
                .bits(),
            parent_tid_addr: 0x1000,
            child_tid_addr: 0x2000,
            clear_child_tid_addr: 0,
        };
        for (case, phase) in [
            HvpatchCloneFailpoint::TidCopyout,
            HvpatchCloneFailpoint::BackendCommit,
            HvpatchCloneFailpoint::TokenBind,
            HvpatchCloneFailpoint::RegistryHandle,
            HvpatchCloneFailpoint::StartProof,
            HvpatchCloneFailpoint::Activation,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 68_000 + case as i32;
            let (process, root) = crate::hvpatch::process_context_for_tests(pid);
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
            let runtime = kernel.hvpatch_runtime.as_ref().unwrap();
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 100 + case as u64);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding =
                executor::tests::hvpatch_test_binding(&root, &root_state, 200 + case as u64);
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
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .unwrap();
            let this_tid = ThreadId::synthetic_for_tests(pid);
            let registry = Arc::new(ThreadRegistry::new(this_tid));
            let futex = Arc::new(FutexTable::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let threads = Arc::new(Mutex::new(Vec::new()));
            let mut state =
                ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                    Arc::clone(&threads),
                    kicker,
                    carrick_hal::InGuestFlag::for_guest_thread(),
                    1_000,
                );
            state.service_kernel_context = Some(root.retain_exact());
            let job_result = HvpatchLoopResult::pending();
            let job_completion = continuation::LogicalJobCompletion::pending();
            let mut job = ProductionHvpatchLoopJob {
                kernel: Arc::clone(&kernel),
                state,
                phase: HvpatchProductionPhase::Resident,
                registration_wait: None,
                terminal_settlement: HvpatchExternalTerminalSettlement::new(
                    job_result,
                    job_completion.clone(),
                ),
                terminal_result: None,
                completion: job_completion,
                traps: 0,
                budget_floor: 0,
                seen_signal_progress: signal_progress_count(),
                last_signal_progress: Instant::now(),
                terminal_runtime: PersistentTerminalRuntimeState::Resident,
                pending_terminal_retirement: None,
                pending_terminal_inventory: None,
                external_exec: None,
            };
            let mut memory = Memory::default();
            memory.0.insert(0x1000, 11_i32.to_le_bytes().to_vec());
            memory.0.insert(0x2000, 22_i32.to_le_bytes().to_vec());
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            install_hvpatch_clone_failpoint(phase);
            assert!(
                job.spawn_persistent_hvpatch_clone_thread(
                    &mut memory,
                    &mut control,
                    &root,
                    request,
                    None,
                    &mut FakeBackendOps,
                )
                .is_err()
            );
            assert!(check_hvpatch_clone_failpoint(phase).is_ok());
            assert_eq!(memory.0[&0x1000], 11_i32.to_le_bytes());
            assert_eq!(memory.0[&0x2000], 22_i32.to_le_bytes());
            assert_eq!(root.task().threads().len(), 1);
            assert_eq!(registry.live_count(), 1);
            assert!(threads.lock().is_empty());
            assert_eq!(scheduler.queued_len(), 1);
            runtime
                .persistent_bindings()
                .restore_submission_authority(root_authority)
                .unwrap();
        }
    }

    #[derive(Default)]
    struct Memory(std::collections::BTreeMap<u64, Vec<u8>>);
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

    #[derive(Default)]
    struct FakeBackendOps {
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

    impl HvpatchProcessBackendOps<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine, Memory>
        for FakeBackendOps
    {
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

    struct NoopPlatformFutex;
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

    #[test]
    fn production_process_failpoints_run_the_real_kernel_copyout_and_publication_body() {
        for (case, phase) in [
            Some(HvpatchProcessFailpoint::ParentCopyout),
            Some(HvpatchProcessFailpoint::BackendCommit),
            Some(HvpatchProcessFailpoint::KernelCommit),
            Some(HvpatchProcessFailpoint::TokenBind),
            Some(HvpatchProcessFailpoint::DormantHandle),
            Some(HvpatchProcessFailpoint::StartProof),
            Some(HvpatchProcessFailpoint::Activation),
            None,
        ]
        .into_iter()
        .enumerate()
        {
            let pid = 69_000 + case as i32;
            let (process, root) = crate::hvpatch::process_context_for_tests(pid);
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
            let runtime = kernel.hvpatch_runtime.as_ref().unwrap();
            let (scheduler, _) = runtime.continuation_services(root.kernel());
            runtime
                .persistent_bindings()
                .install_scheduler(&scheduler)
                .unwrap();
            let mut root_state = executor::tests::task_state(&root, 500 + case as u64);
            root_state.asid_generation = process.asid_generation();
            let carrick_hal::threaded::GuestCpuState::Aarch64V1(cpu) = &mut root_state.cpu else {
                unreachable!()
            };
            Arc::make_mut(cpu).asid_generation = process.asid_generation();
            let root_generation = root
                .thread()
                .publish_initial_task_state(root_state.clone())
                .unwrap();
            let root_binding =
                executor::tests::hvpatch_test_binding(&root, &root_state, 600 + case as u64);
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
            let root_authority = runtime
                .persistent_bindings()
                .take_submission_authority(root.thread().key(), root_generation)
                .unwrap();
            let this_tid = ThreadId::synthetic_for_tests(pid);
            let registry = Arc::new(ThreadRegistry::new(this_tid));
            let futex = Arc::new(FutexTable::new());
            let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
            let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
            let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
            let mut state =
                ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                    Arc::new(Mutex::new(Vec::new())),
                    kicker,
                    carrick_hal::InGuestFlag::for_guest_thread(),
                    1_000,
                );
            state.service_kernel_context = Some(root.retain_exact());
            let mut memory = Memory::default();
            memory.0.insert(0x1000, 11_i32.to_le_bytes().to_vec());
            memory.0.insert(0x2000, 22_i32.to_le_bytes().to_vec());
            let need_resched = std::sync::atomic::AtomicBool::new(false);
            let mut submission = executor::ExecutorSubmissionContext {
                scheduler: &scheduler,
                publish_test_descendant: &|_, _| unreachable!(),
                current: Some(&root_authority),
                lease: None,
                exec_replacement: None,
            };
            let mut control =
                executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
            let mut ops = FakeBackendOps::default();
            if let Some(phase) = phase {
                install_hvpatch_process_failpoint(phase);
            }
            let result = state.prepare_in_process_fork(
                &kernel,
                &root,
                &mut memory,
                &mut control,
                &mut ops,
                quiesce::ProcessForkAttempt {
                    request: quiesce::ForkRequest {
                        flags: if phase.is_none() {
                            carrick_abi::LinuxCloneFlags::VM.bits()
                        } else {
                            0
                        },
                        pidfd_out: None,
                        clone_parent: false,
                        parent_tid_addr: Some(0x1000),
                        child_tid_addr: Some(0x2000),
                        exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                        child_stack: 0,
                        vfork: None,
                    },
                    coordinator: None,
                    external_exec: None,
                },
            );
            let Some(phase) = phase else {
                assert!(matches!(
                    result,
                    Ok(quiesce::PreparedInProcessFork::Complete(Some(_)))
                ));
                assert_eq!(ops.shared_preparations, 1);
                assert_eq!(ops.copied_preparations, 0);
                assert_eq!(ops.parent_commits, 0);
                assert_eq!(ops.parent_rollbacks, 0);
                assert_eq!(ops.inventory_applies, 0);
                assert_eq!(root.kernel().registry().task_count(), 2);
                continue;
            };
            assert!(result.is_err());
            assert!(check_hvpatch_process_failpoint(phase).is_ok());
            assert_eq!(ops.copied_preparations, 1);
            assert_eq!(ops.shared_preparations, 0);
            if matches!(
                phase,
                HvpatchProcessFailpoint::ParentCopyout
                    | HvpatchProcessFailpoint::BackendCommit
                    | HvpatchProcessFailpoint::KernelCommit
            ) {
                assert_eq!(memory.0[&0x1000], 11_i32.to_le_bytes());
                assert_eq!(ops.parent_rollbacks, 1);
                assert_eq!(ops.fail_stops, 0);
                assert_eq!(root.kernel().registry().task_count(), 1);
            } else {
                assert_eq!(ops.parent_commits, 1);
                assert_eq!(ops.fail_stops, 1);
                assert_eq!(root.kernel().registry().task_count(), 2);
            }
        }

        let mut bootstrap = Memory::default();
        bootstrap.0.insert(0x3000, 33_i32.to_le_bytes().to_vec());
        install_hvpatch_process_failpoint(HvpatchProcessFailpoint::ChildSettidBootstrap);
        assert!(bootstrap_hvpatch_process_child_tid(&mut bootstrap, 0x3000, 44).is_err());
        assert_eq!(bootstrap.0[&0x3000], 33_i32.to_le_bytes());
        bootstrap_hvpatch_process_child_tid(&mut bootstrap, 0x3000, 44).unwrap();
        assert_eq!(bootstrap.0[&0x3000], 44_i32.to_le_bytes());
    }

    #[test]
    fn backend_prepare_error_does_not_double_rollback() {
        let pid = 42;
        let dispatcher = SyscallDispatcher::new();
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(pid, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state =
            ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                Arc::new(Mutex::new(Vec::new())),
                kicker,
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
        state.service_kernel_context = Some(root.retain_exact());
        let mut memory = Memory::default();
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);
        let mut ops = FakeBackendOps {
            prepare_fails: true,
            ..Default::default()
        };
        let result = state.prepare_in_process_fork(
            &kernel,
            &root,
            &mut memory,
            &mut control,
            &mut ops,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: None,
            },
        );
        assert!(result.is_err());
        // Backend prepare handles its own rollback on error; caller must not roll back again.
        assert_eq!(ops.backend_prepare_rollbacks, 1);
        assert_eq!(ops.parent_rollbacks, 0);
        assert_eq!(ops.aborts, 0);
    }

    #[test]
    fn backend_staleness_after_successful_prepare_aborts_and_rolls_copied_parent_back_exactly_once()
    {
        let pid = 43;
        let dispatcher = SyscallDispatcher::new();
        let parent_context = dispatcher.capture_one_task_context().unwrap();
        let (runtime, scheduler, kernel, root, process, root_generation) =
            test_carrier_graph_with_dispatcher!(pid, dispatcher);
        let root_authority = runtime
            .persistent_bindings()
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();
        let this_tid = ThreadId::synthetic_for_tests(pid);
        let registry = Arc::new(ThreadRegistry::new(this_tid));
        let futex = Arc::new(FutexTable::new());
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let kicker: Arc<dyn VcpuRegistry> = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let mut state =
            ThreadRuntimeState::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine>::new(
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
                Arc::new(Mutex::new(Vec::new())),
                kicker,
                carrick_hal::InGuestFlag::for_guest_thread(),
                1_000,
            );
        state.service_kernel_context = Some(root.retain_exact());
        let mut memory = Memory::default();
        let need_resched = std::sync::atomic::AtomicBool::new(false);
        let mut submission = executor::ExecutorSubmissionContext {
            scheduler: &scheduler,
            publish_test_descendant: &|_, _| unreachable!(),
            current: Some(&root_authority),
            lease: None,
            exec_replacement: None,
        };
        let mut control = executor::HvpatchQuantumControl::for_test(&need_resched, &mut submission);

        let kernel_clone = Arc::clone(&kernel);
        let mut ops = FakeBackendOps {
            on_prepare: Some(Arc::new(move || {
                // Simulate an authority swap / revision change during prepare
                let replacement = Arc::new(
                    crate::dispatch::DispatchMmAuthority::new_for_test_with_revision(
                        crate::kernel::VmaRevision::from_authority_raw(999),
                    ),
                );
                kernel_clone
                    .dispatcher
                    .replace_current_mm_for_test(replacement);
            })),
            ..Default::default()
        };

        let result = state.prepare_in_process_fork(
            &kernel,
            &root,
            &mut memory,
            &mut control,
            &mut ops,
            quiesce::ProcessForkAttempt {
                request: quiesce::ForkRequest {
                    flags: 0,
                    pidfd_out: None,
                    clone_parent: false,
                    parent_tid_addr: None,
                    child_tid_addr: None,
                    exit_signal: crate::linux_abi::LINUX_SIGCHLD as u32,
                    child_stack: 0,
                    vfork: None,
                },
                coordinator: None,
                external_exec: None,
            },
        );
        assert!(matches!(
            result,
            Ok(quiesce::PreparedInProcessFork::Complete(Some(_)))
        ));
        // Fork lowered to EAGAIN and rolled back copied parent exactly once.
        assert_eq!(ops.aborts, 1);
        assert_eq!(ops.parent_rollbacks, 1);
        assert_eq!(ops.parent_commits, 0);
        assert_eq!(
            ops.request_parent_mm,
            Some(parent_context.shared().mm().id().raw())
        );
        assert!(ops.request_child_mm.is_some());
        assert_ne!(ops.request_parent_mm, ops.request_child_mm);
    }

    #[test]
    fn carrier_retains_and_retires_exact_persistent_process_completion() {
        let directory = HvpatchRuntimeDirectory::default();
        let result = HvpatchLoopResult::pending();
        let completion = continuation::LogicalJobCompletion::pending();
        directory.enroll_persistent_process_job(result.clone(), completion.clone());
        assert_eq!(directory.process_jobs.lock().len(), 1);
        result.publish(Ok(VcpuLoopOutcome::ThreadDone));
        completion.publish();
        directory.join_process_threads().unwrap();
        assert!(directory.process_jobs.lock().is_empty());
    }

    #[test]
    fn hvpatch_child_exit_reads_the_post_exec_sighand_generation() {
        let dispatcher = SyscallDispatcher::new();
        let pre_exec = dispatcher
            .capture_one_task_context()
            .expect("pre-exec context");
        let task = pre_exec.task().key();
        let directory = HvpatchRuntimeDirectory::default();
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        ));
        directory.register(
            task,
            HvpatchRuntimeEndpoint {
                kernel: Arc::downgrade(&kernel),
                task_binding: pre_exec.task_binding(),
                scheduler: None,
            },
        );

        let prepared = kernel
            .dispatcher
            .prepare_one_task_kernel_exec(&pre_exec)
            .expect("prepare exec");
        let post_exec = kernel
            .dispatcher
            .commit_one_task_kernel_exec(prepared)
            .expect("commit exec");
        let chld = crate::linux_abi::LINUX_SIGCHLD;
        let signal = crate::kernel::LinuxSignal::for_signal_number(chld).expect("SIGCHLD");
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        post_exec.shared().sighand().install_action(signal, caught);

        assert_eq!(pre_exec.task().key(), post_exec.task().key());
        assert_ne!(pre_exec.revision(), post_exec.revision());
        assert_ne!(pre_exec.thread().key(), post_exec.thread().key());
        assert_ne!(
            pre_exec.shared().sighand().id(),
            post_exec.shared().sighand().id()
        );
        let post_exec_snapshot = pre_exec
            .task_binding()
            .capture_signal_snapshot()
            .expect("post-exec signal snapshot");
        assert_eq!(
            post_exec_snapshot.context().revision(),
            post_exec.revision()
        );
        assert_eq!(
            post_exec_snapshot.context().thread().key(),
            post_exec.thread().key()
        );
        assert_eq!(post_exec_snapshot.threads().len(), 1);
        assert_eq!(
            post_exec_snapshot.threads()[0].key(),
            post_exec.thread().key()
        );
        assert_eq!(
            post_exec.shared().sighand().disposition(signal),
            crate::kernel::SignalDisposition::Caught
        );
        directory.notify_child_exit(task, Some(chld));
        assert!(
            post_exec
                .shared()
                .pending_signals()
                .present()
                .contains(chld)
        );
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
            trap_watchdog_decision(100, 1000, Duration::from_secs(60), Duration::from_secs(30)),
            TrapWatchdog::KeepRunning
        );
        // Exactly AT the count threshold is still under (the guard uses `>`).
        assert_eq!(
            trap_watchdog_decision(1000, 1000, Duration::from_secs(60), Duration::from_secs(30)),
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
                Duration::from_millis(100),
                Duration::from_secs(30)
            ),
            TrapWatchdog::ResetBudget
        );
        // Just under the wall window is still a reset (the trip uses `>=`).
        assert_eq!(
            trap_watchdog_decision(
                2_000_000,
                1000,
                Duration::from_millis(29_999),
                Duration::from_millis(30_000)
            ),
            TrapWatchdog::ResetBudget
        );
    }

    #[test]
    fn trap_watchdog_trips_on_count_and_wall_stall() {
        // Over the count pre-filter AND no progress for >= max_wall → abort.
        // The boundary is inclusive (`>=`): exactly max_wall trips.
        assert_eq!(
            trap_watchdog_decision(1001, 1000, Duration::from_secs(30), Duration::from_secs(30)),
            TrapWatchdog::Trip
        );
        assert_eq!(
            trap_watchdog_decision(
                1_000_000,
                1000,
                Duration::from_secs(45),
                Duration::from_secs(30)
            ),
            TrapWatchdog::Trip
        );
    }

    /// Editing stage-1 and NEEDING A PAUSE are different questions, and the
    /// page-table manager keys table reclaim on the first. A sole guest
    /// executor takes no pause precisely because it is already exclusive, so if
    /// exclusivity were derived from pause ownership it would read as "shared"
    /// there — which is the shape that leaked one stage-1 table per
    /// `mmap(MAP_SHARED, fd)` until the pool hit `OutOfTables`.
    #[test]
    fn stage1_editors_are_claimed_regardless_of_peers() {
        for &editor in crate::dispatch::MM_MUTATION_SYSCALLS {
            assert!(
                syscall_edits_stage1(editor, 0),
                "{editor} edits stage-1 whether or not a peer exists"
            );
            assert_eq!(
                syscall_takes_pre_dispatch_pt_pause(editor, 0, true),
                syscall_edits_stage1(editor, 0)
            );
        }
        assert!(!syscall_edits_stage1(63, 0), "read edits no descriptors");
    }

    /// The pre-dispatch page-table pause exists to keep ONE global lock order
    /// (pause, then the dispatcher's host-alias phase). `MADV_DONTNEED` is in
    /// the set because it is the one host-alias-taking syscall that reaches the
    /// backend's self-quiescing `zero_backing` path; without it the two orders
    /// crossed and deadlocked a whole guest at ~0% CPU.
    #[test]
    fn pre_dispatch_pt_pause_covers_madvise_dontneed() {
        for &editor in crate::dispatch::MM_MUTATION_SYSCALLS {
            assert!(syscall_takes_pre_dispatch_pt_pause(editor, 0, true));
            assert!(
                !syscall_takes_pre_dispatch_pt_pause(editor, 0, false),
                "a single-vCPU process has no sibling to pause"
            );
        }
        assert!(!syscall_takes_pre_dispatch_pt_pause(63, 0, true));
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
    fn persistent_terminal_claim_has_one_owner_and_retries_without_blocking() {
        let kernel = KernelState::new(
            SyscallDispatcher::new(),
            Arc::new(EndpointTestSignalPump),
            Arc::new(EndpointTestSignalArrival),
            None,
            None,
            None,
        );
        let clone = kernel
            .clone_admission
            .try_enroll_thread_clone()
            .expect("model admitted clone");
        let owner = ThreadId::synthetic_for_tests(70_300);
        assert_eq!(
            kernel.try_claim_persistent_process_exit(owner).unwrap(),
            ProcessExitClaim::Pending
        );
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_301))
                .unwrap(),
            ProcessExitClaim::AlreadyOwned
        );
        let wakes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let wake_count = Arc::clone(&wakes);
        let subscription = kernel.clone_admission.subscribe_change(
            kernel.clone_admission.change_epoch(),
            Arc::new(move || {
                wake_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }),
        );
        drop(clone);
        assert_eq!(wakes.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(subscription);
        assert_eq!(
            kernel.try_claim_persistent_process_exit(owner).unwrap(),
            ProcessExitClaim::Owner
        );
        assert_eq!(
            kernel
                .try_claim_persistent_process_exit(ThreadId::synthetic_for_tests(70_301))
                .unwrap(),
            ProcessExitClaim::AlreadyOwned
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

    #[test]
    fn clone_admission_cancels_enrolled_process_fork_before_exec_drain() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(1003);
        let process_fork = gate
            .try_enroll_process_fork(owner)
            .expect("process fork admission");

        std::thread::scope(|scope| {
            let exec = scope.spawn(|| gate.close_for_exec(owner));
            while !process_fork.is_cancelled() {
                std::thread::yield_now();
            }
            assert!(
                gate.try_enroll_thread_clone().is_none(),
                "new process forks must be rejected after exec closes admission"
            );
            drop(process_fork);
            drop(
                exec.join()
                    .expect("exec closer")
                    .expect("exec admission drain"),
            );
        });
        assert!(gate.try_enroll_thread_clone().is_some());
    }

    #[test]
    fn fork_admission_drains_existing_clones_without_cancelling_them() {
        let gate = Arc::new(CloneAdmissionGate::default());
        let owner = ThreadId::synthetic_for_tests(1004);
        let process_fork = gate
            .try_enroll_process_fork(owner)
            .expect("process fork admission");
        let existing_clone = gate
            .try_enroll_thread_clone()
            .expect("existing clone admission");

        assert!(
            process_fork.try_close_for_fork(owner).unwrap().is_none(),
            "fork close must yield while an admitted clone publishes"
        );
        assert!(
            gate.try_enroll_thread_clone().is_none(),
            "new clones wait behind fork"
        );
        assert!(
            !existing_clone.is_cancelled(),
            "a clone admitted before fork must finish, not leak EAGAIN"
        );
        drop(existing_clone);
        let fork = process_fork
            .try_close_for_fork(owner)
            .expect("retry fork close")
            .expect("fork admission drain");
        assert!(!process_fork.is_cancelled());
        drop(fork);

        drop(process_fork);
        assert!(gate.try_enroll_thread_clone().is_some());
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
        let handles = Arc::new(Mutex::new(Vec::new()));
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
            handles
                .lock()
                .iter()
                .map(VcpuThreadHandle::completion)
                .collect(),
        );
        assert!(!drain.is_ready(), "exec must wait for the suspended leader");

        leader_settlement
            .publish_member(Ok(VcpuLoopOutcome::ThreadDone))
            .unwrap();
        assert!(drain.is_ready());
        finish_persistent_process_handles(&handles, exec_completion.id())
            .expect("drain exact leader result without synthesizing one");
    }

    #[test]
    fn persistent_worker_drain_never_waits_for_a_removed_logical_job() {
        let source = include_str!("mod.rs");
        let finish = source
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

    fn registration_test_handle() -> Box<dyn carrick_hal::VcpuKickDyn> {
        Box::new(RegistrationTestKick)
    }

    fn register_crash_test_vcpu(
        registry: &dyn VcpuRegistry,
        tid: ThreadId,
        in_guest: &carrick_hal::InGuestFlag,
    ) {
        assert!(matches!(
            registry
                .subscribe_register(tid, registration_test_handle(), in_guest, Arc::new(|| {}),),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
    }

    #[derive(Clone)]
    struct CrashCaptureTestKick;

    impl carrick_hal::VcpuKick for CrashCaptureTestKick {
        fn kick(&self) {}
    }

    struct CrashCaptureTestEngine;

    impl carrick_guest_mem::GuestMemory for CrashCaptureTestEngine {
        fn read_bytes_raw(
            &self,
            _address: u64,
            length: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            Ok(vec![0; length])
        }

        fn write_bytes_raw(
            &mut self,
            _address: u64,
            _bytes: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
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
            Ok(None)
        }

        fn current_pc(&self) -> Result<u64, TrapError> {
            Ok(0)
        }

        fn complete_syscall(&mut self, _return_value: i64) -> Result<(), TrapError> {
            Ok(())
        }

        fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
            Ok(())
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

        fn take_guest_run_receipt_ns(&mut self) -> u64 {
            0
        }

        fn snapshot_guest_state_for_publication(
            &mut self,
        ) -> Result<carrick_hal::threaded::GuestCpuState, TrapError> {
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
            Ok(Self)
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

    struct CrashCallbackRegistry {
        inner: carrick_hal::GenericVcpuRegistry,
        callback_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CrashCallbackRegistry {
        fn new(callback_calls: Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self {
                inner: carrick_hal::GenericVcpuRegistry::new(),
                callback_calls,
            }
        }
    }

    impl VcpuRegistry for CrashCallbackRegistry {
        fn poll_lease_drain(&self, except: ThreadId) -> carrick_hal::VcpuLeaseDrainPoll {
            self.inner.poll_lease_drain(except)
        }

        fn subscribe_lease_drain(
            &self,
            except: ThreadId,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> carrick_hal::VcpuLeaseDrainEnrollment {
            let callback_calls = Arc::clone(&self.callback_calls);
            self.inner.subscribe_lease_drain(
                except,
                Arc::new(move || {
                    callback_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    callback();
                }),
            )
        }

        fn subscribe_register(
            &self,
            tid: ThreadId,
            handle: Box<dyn carrick_hal::VcpuKickDyn>,
            in_guest: &carrick_hal::InGuestFlag,
            callback: Arc<dyn Fn() + Send + Sync + 'static>,
        ) -> carrick_hal::VcpuRegistrationEnrollment {
            self.inner
                .subscribe_register(tid, handle, in_guest, callback)
        }

        fn unregister(&self, tid: ThreadId) {
            self.inner.unregister(tid);
        }

        fn kick(&self, tid: ThreadId) {
            self.inner.kick(tid);
        }

        fn kick_if_in_guest(&self, tid: ThreadId) -> bool {
            self.inner.kick_if_in_guest(tid)
        }

        fn kick_all(&self) {
            self.inner.kick_all();
        }

        fn kick_all_in_guest(&self) -> bool {
            self.inner.kick_all_in_guest()
        }

        fn kick_all_except(&self, except: ThreadId) {
            self.inner.kick_all_except(except);
        }

        fn any_other_in_guest(&self, except: ThreadId) -> bool {
            self.inner.any_other_in_guest(except)
        }

        fn is_in_guest(&self, tid: ThreadId) -> bool {
            self.inner.is_in_guest(tid)
        }

        fn debug_registered_vcpus(&self) -> Vec<(ThreadId, bool)> {
            self.inner.debug_registered_vcpus()
        }
    }

    #[test]
    fn crash_lease_drain_short_budget_reports_exact_waiting_tid() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_221);
        let sibling = ThreadId::synthetic_for_tests(70_222);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(&registry, owner, &owner_in_guest);
        register_crash_test_vcpu(&registry, sibling, &sibling_in_guest);

        let timeout = match acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        ) {
            Ok(_) => panic!("a live sibling must exhaust the zero crash-drain budget"),
            Err(timeout) => timeout,
        };

        assert!(matches!(
            timeout,
            CrashLeaseDrainTimeout::Waiting(tid) if tid == sibling
        ));
    }

    #[test]
    fn crash_lease_drain_short_budget_reports_busy_owner() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let freeze_owner = ThreadId::synthetic_for_tests(70_223);
        let competing_owner = ThreadId::synthetic_for_tests(70_224);
        let freeze = match registry.subscribe_lease_drain(freeze_owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("first crash owner must acquire the unique drain freeze"),
        };

        let timeout = match acquire_crash_lease_drain(
            &registry,
            competing_owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        ) {
            Ok(_) => panic!("a competing freeze must exhaust the zero crash-drain budget"),
            Err(timeout) => timeout,
        };

        assert!(matches!(
            timeout,
            CrashLeaseDrainTimeout::Busy(owner) if owner == freeze_owner
        ));
        drop(freeze);
    }

    #[test]
    fn crash_lease_drain_freezes_late_registration() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_225);
        let late = ThreadId::synthetic_for_tests(70_226);
        let guard = acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {},
        )
        .expect("an empty sibling set must freeze atomically");
        let late_in_guest = carrick_hal::InGuestFlag::for_guest_thread();

        let enrollment = registry.subscribe_register(
            late,
            registration_test_handle(),
            &late_in_guest,
            Arc::new(|| {}),
        );
        assert!(matches!(
            &enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Waiting {
                owner: waiting_owner,
                ..
            } if *waiting_owner == owner
        ));
        assert_eq!(
            registry.poll_lease_drain(owner),
            carrick_hal::VcpuLeaseDrainPoll::Complete
        );
        drop(enrollment);
        drop(guard);
    }

    #[test]
    fn crash_guard_source_spans_quorum_and_read_core_bytes() {
        let source = include_str!("mod.rs");
        let capture = source
            .split("fn capture_core_for_publication(")
            .nth(1)
            .and_then(|tail| tail.split("fn trace_syscall(").next())
            .expect("bounded crash publication body");
        let barrier_acquire = capture.find("while !barrier.try_begin_fork()").unwrap();
        let advertise = capture.find("authority.advertise(generation)").unwrap();
        let envelope = capture.find("let result = (|| {").unwrap();
        let envelope_end = capture
            .rfind("})();")
            .expect("exact protected crash publication closure end")
            + "})();".len();
        let finish = capture.rfind("finish_crash_collection(").unwrap();
        assert!(envelope < envelope_end);
        assert!(envelope_end < finish);
        assert!(barrier_acquire < advertise);
        assert!(advertise < envelope);

        let protected = &capture[envelope..envelope_end];
        let barrier_raise = protected.find("barrier.set_quiescing()").unwrap();
        let acquire = protected.find("acquire_crash_lease_drain(").unwrap();
        let prepare = protected.find("engine.prepare_core_snapshot()").unwrap();
        let quorum = protected.find("quorum.poll()").unwrap();
        let read = protected.find("engine.read_core_bytes").unwrap();
        let serialize = protected.find(".to_bytes_bounded(").unwrap();
        let publication = protected.find("PreparedCorePublication {").unwrap();
        assert!(barrier_raise < acquire);
        assert!(acquire < prepare);
        assert!(prepare < quorum);
        assert!(quorum < read);
        assert!(read < serialize);
        assert!(serialize < publication);
        assert_eq!(
            protected.matches("engine.read_core_bytes").count(),
            capture.matches("engine.read_core_bytes").count(),
            "every live engine read must remain inside the drain-guard closure"
        );
        assert!(
            protected
                .contains(".map_err(|timeout| RuntimeError::Configuration(timeout.to_string()))?")
        );
        assert!(!protected.contains("finish_crash_collection("));
        assert!(!capture[..finish].contains("drop(lease_drain_guard)"));
        assert!(!capture.contains("kicker.count()"));

        let cleanup = source
            .split("fn finish_crash_collection")
            .nth(1)
            .and_then(|tail| tail.split("impl<E: ThreadedEngine + 'static>").next())
            .expect("bounded common crash cleanup helper");
        let stop = cleanup.find("authority.stop_collecting()").unwrap();
        let end_quiesce = cleanup.find("barrier.end_quiesce()").unwrap();
        let end_fork = cleanup.find("barrier.end_fork()").unwrap();
        let drop_guard = cleanup.find("drop(lease_drain_guard)").unwrap();
        assert!(stop < end_quiesce);
        assert!(end_quiesce < end_fork);
        assert!(end_fork < drop_guard);
    }

    #[test]
    fn crash_teardown_releases_barrier_before_guard() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let barrier = Arc::new(crate::fork_quiesce::QuiesceBarrier::new());
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let generation = authority.issue().expect("test crash generation");
        authority.advertise(generation);
        assert!(barrier.try_begin_fork());
        barrier.set_quiescing();
        let owner = ThreadId::synthetic_for_tests(70_227);
        let late = ThreadId::synthetic_for_tests(70_228);
        let guard = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("crash owner must freeze the empty sibling set"),
        };
        let saw_quiescing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let observed = Arc::clone(&saw_quiescing);
        let callback_barrier = Arc::clone(&barrier);
        let late_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let enrollment = registry.subscribe_register(
            late,
            registration_test_handle(),
            &late_in_guest,
            Arc::new(move || {
                observed.store(
                    callback_barrier.is_quiescing(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }),
        );
        assert!(matches!(
            &enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));

        finish_crash_collection(
            &authority,
            &barrier,
            true,
            Some(guard),
            Ok::<_, RuntimeError>(()),
        )
        .expect("crash cleanup must preserve the successful result");

        assert!(!saw_quiescing.load(std::sync::atomic::Ordering::SeqCst));
        drop(enrollment);
    }

    #[test]
    fn crash_lease_drain_timeout_releases_collection_and_barriers() {
        let (process, root) = crate::hvpatch::process_context_for_tests(70_229);
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::THREAD
                | carrick_abi::LinuxCloneFlags::SIGHAND
                | carrick_abi::LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve crash sibling")
            .prepare(ThreadId::synthetic_for_tests(70_230))
            .expect("prepare crash sibling")
            .commit()
            .expect("publish crash sibling")
            .start_thread()
            .expect("start crash sibling")
            .into_context();
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
        let barrier = kernel
            .process_fork_barrier
            .clone()
            .expect("HVPatch crash barrier");
        let authority = kernel
            .crash_capture
            .clone()
            .expect("HVPatch crash authority");
        let owner = ThreadId::synthetic_for_tests(70_229);
        let sibling_tid = ThreadId::synthetic_for_tests(70_230);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let kicker = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        register_crash_test_vcpu(kicker.as_ref(), owner, &owner_in_guest);
        register_crash_test_vcpu(kicker.as_ref(), sibling_tid, &sibling_in_guest);
        let kicker: Arc<dyn VcpuRegistry> = kicker;
        let platform: Arc<dyn PlatformFutex> = Arc::new(NoopPlatformFutex);
        let platform_factory: PlatformFutexFactory = Arc::new(|_| Arc::new(NoopPlatformFutex));
        let mut state = ThreadRuntimeState::<CrashCaptureTestEngine>::new(
            Arc::new(ThreadRegistry::new(owner)),
            Arc::new(FutexTable::new()),
            platform,
            platform_factory,
            Some(Arc::clone(&barrier)),
            Some(Arc::clone(&authority)),
            Some(Arc::clone(root.thread())),
            Some(process.pid()),
            root.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            owner,
            Arc::new(Mutex::new(Vec::new())),
            kicker,
            owner_in_guest,
            1_000,
        );
        state.install_crash_lease_drain_budget_for_test(CrashLeaseDrainBudget {
            timeout: Duration::ZERO,
            poll_interval: Duration::from_micros(1),
        });
        let mut engine = CrashCaptureTestEngine;

        let result = state.capture_core_for_publication(
            &kernel,
            &mut engine,
            FatalSignalRecord {
                image_generation: kernel.fatal_signal.current_generation(),
                tid: root.thread().key().tid,
                signo: 11,
                code: 1,
                addr: 0xdead,
            },
        );

        let error = match result {
            Ok(_) => panic!("a live waiting lease must time out real crash capture"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(&sibling_tid.raw().to_string()),
            "timeout must report the exact waiting sibling: {error}"
        );
        assert_eq!(root.task().key(), sibling.task().key());
        assert!(authority.collecting().is_none());
        assert!(!barrier.is_quiescing());
        assert!(barrier.try_begin_fork());
        barrier.end_fork();
    }

    #[test]
    fn crash_lease_drain_callback_before_park_completes_without_poll_interval() {
        let callback_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let registry = Arc::new(CrashCallbackRegistry::new(Arc::clone(&callback_calls)));
        let owner = ThreadId::synthetic_for_tests(70_233);
        let sibling = ThreadId::synthetic_for_tests(70_234);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(registry.as_ref(), owner, &owner_in_guest);
        register_crash_test_vcpu(registry.as_ref(), sibling, &sibling_in_guest);
        let nudge_entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release_nudge = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        let worker_registry = Arc::clone(&registry);
        let worker_nudge_entered = Arc::clone(&nudge_entered);
        let worker_release_nudge = Arc::clone(&release_nudge);
        let worker = std::thread::spawn(move || {
            let result = acquire_crash_lease_drain(
                worker_registry.as_ref(),
                owner,
                CrashLeaseDrainBudget {
                    timeout: Duration::from_secs(2),
                    poll_interval: Duration::from_secs(1),
                },
                || {
                    worker_nudge_entered.store(true, std::sync::atomic::Ordering::SeqCst);
                    while !worker_release_nudge.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::yield_now();
                    }
                },
            )
            .map(drop);
            done_tx.send(result).expect("publish drain result");
        });

        let nudge_deadline = Instant::now() + Duration::from_secs(1);
        while !nudge_entered.load(std::sync::atomic::Ordering::SeqCst) {
            assert!(
                Instant::now() < nudge_deadline,
                "worker must subscribe before parking"
            );
            std::thread::yield_now();
        }
        registry.unregister(sibling);
        assert_eq!(
            callback_calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "membership change must exercise the subscribed unpark callback"
        );
        release_nudge.store(true, std::sync::atomic::Ordering::SeqCst);
        done_rx
            .recv_timeout(Duration::from_millis(250))
            .expect("an unpark token published before park must avoid the one-second poll")
            .expect("membership removal must complete acquisition");
        worker.join().expect("crash-drain worker");
    }

    #[test]
    fn crash_lease_drain_deadline_reenrolls_after_waiting_member_leaves() {
        let registry = carrick_hal::GenericVcpuRegistry::new();
        let owner = ThreadId::synthetic_for_tests(70_231);
        let sibling = ThreadId::synthetic_for_tests(70_232);
        let owner_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        register_crash_test_vcpu(&registry, owner, &owner_in_guest);
        register_crash_test_vcpu(&registry, sibling, &sibling_in_guest);
        let mut nudged = false;

        let guard = acquire_crash_lease_drain(
            &registry,
            owner,
            CrashLeaseDrainBudget {
                timeout: Duration::ZERO,
                poll_interval: Duration::from_secs(1),
            },
            || {
                assert!(
                    !nudged,
                    "the zero-budget path must perform one final enrollment"
                );
                nudged = true;
                registry.unregister(sibling);
            },
        )
        .expect("the final atomic enrollment must observe the sibling removal");

        assert!(nudged);
        drop(guard);
    }

    #[test]
    fn crash_lease_drain_park_caps_to_remaining_budget() {
        assert_eq!(
            crash_lease_drain_park_duration(Duration::from_secs(1), Duration::from_millis(7)),
            Duration::from_millis(7)
        );
        assert_eq!(
            crash_lease_drain_park_duration(Duration::from_micros(200), Duration::from_secs(1)),
            Duration::from_micros(200)
        );
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
        let handles = Arc::new(Mutex::new(Vec::new()));
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

        finish_persistent_process_handles(&handles, owner.completion().id())
            .expect("removed Kernel thread settles without a job repoll");
        assert!(handles.lock().is_empty());
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
        let consumed_handles = Arc::new(Mutex::new(Vec::new()));
        enroll_persistent_process_member(&consumed_handles, &consumed);
        enroll_persistent_process_member(&consumed_handles, &owner);
        finish_persistent_process_handles(&consumed_handles, owner.completion().id())
            .expect("already-consumed result retains durable settlement proof");
    }

    #[test]
    fn terminal_publication_synthesizes_thread_done_only_for_an_exact_removed_sibling() {
        assert!(matches!(
            terminal_result_for_publication(None, HvpatchTerminalSettlementRole::Member),
            Ok(VcpuLoopOutcome::ThreadDone)
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
