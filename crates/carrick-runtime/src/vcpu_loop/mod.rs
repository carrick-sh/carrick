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

use std::collections::BTreeMap;
use std::os::fd::IntoRawFd;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use carrick_hal::{HostForkCoordinator, PlatformFutex, ThreadedEngine, VcpuRegistry};

use crate::compat::CompatReporter;
use crate::dispatch::{
    CorePublicationError, DispatchError, DispatchOutcome, GuestMemory, ProcMapSharing,
    ProcMapsEntry, SyscallDispatcher, SyscallRequest,
};
use crate::linux_abi::LinuxErrno;
use crate::memory::AddressSpace;
use crate::run_result::{RunResult, RuntimeError};
use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::trap::{SyscallTrap, TrapError};

const SIGNAL_WAIT_SLICE: Duration = Duration::from_millis(50);
const SHORT_TIMED_WAIT_RECLAIM_CUTOFF: Duration = Duration::from_millis(250);

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

/// Accumulates resume time on every exit path, including the early return
/// when there was no reclaim (which contributes zero and costs one branch).
struct ResumeCensusGuard(std::time::Instant);

impl Drop for ResumeCensusGuard {
    fn drop(&mut self) {
        VCPU_RECLAIM_RESUME_NS.fetch_add(
            u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Totals for this process: (reclaims, park ns, resume ns).
pub(crate) fn vcpu_reclaim_census() -> (u64, u64, u64) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        VCPU_RECLAIMS.load(Relaxed),
        VCPU_RECLAIM_PARK_NS.load(Relaxed),
        VCPU_RECLAIM_RESUME_NS.load(Relaxed),
    )
}

fn should_reclaim_vcpu_for_timed_wait(timeout: Option<Duration>) -> bool {
    match timeout {
        None => true,
        Some(timeout) => timeout > SHORT_TIMED_WAIT_RECLAIM_CUTOFF,
    }
}

fn should_keep_vcpu_for_blocking_wait(
    force_reclaim: bool,
    has_spare_capacity: bool,
    has_waiters: bool,
) -> bool {
    !force_reclaim && has_spare_capacity && !has_waiters
}

fn threaded_fd_wait_should_interrupt(fork_quiescing: bool, dispatch_pending: bool) -> bool {
    // Internal stop-the-world edges outrank guest-visible fd readiness. An
    // always-ready host fd can otherwise make the wait return Ready forever,
    // starving the run-loop-top quiesce check (captured in a go-build core as
    // the sole still-registered vCPU while every sibling was barrier-parked).
    fork_quiescing || dispatch_pending
}

fn should_destroy_departing_vcpu(process_exit: bool, thread_done: bool) -> bool {
    !process_exit && !thread_done
}

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
    kicker: Arc<dyn carrick_hal::VcpuRegistry>,
    tid: carrick_hal::ThreadId,
}

impl carrick_hal::FrameCowAuthority for KernelFrameCowAuthority {
    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        if self.kicker.count() <= 1 || quiesce::current_thread_holds_pt_pause() {
            return Ok(Box::new(()));
        }
        quiesce::acquire_pt_pause(
            quiesce::pt_barrier(),
            &*self.kicker,
            self.tid,
            Duration::from_millis(500),
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
        Ok(self
            .kernel
            .frame_inventory()
            .snapshot_for_mm(self.mm)
            .mappings
            .iter()
            .any(|row| {
                row.mapping == mapping
                    && row.frame == frame
                    && row.gpa == gpa
                    && row.length == length
            }))
    }
}

pub(super) fn requires_no_unwind_host_exit(kernel: &Kernel, engine_is_forked_child: bool) -> bool {
    !kernel.is_hvpatch_child()
        && kernel.dispatcher.execution_backend() != crate::page_profile::ExecutionBackend::HvPatch
        && (engine_is_forked_child || kernel.dispatcher.is_forked_guest_process())
}

/// MT whole-VM residency lease (E4 Track 3): when every thread of a
/// multi-threaded process has been parked for a while, release the whole VM
/// like single-threaded parks already do, so >127 blocked MT processes don't
/// exhaust the per-VM slot budget. The release is DEFERRED — never taken on
/// the common park path (hot blocking waits must not pay the release+rebuild
/// round trip); a SLICING wait arm upgrades a vCPU-only park to a whole-VM
/// release on its second ≥1 s parked slice
/// (`try_upgrade_vm_release_on_slice_tick`).
/// `CARRICK_MT_VM_LEASE=0` disables the MT upgrade for bisection.
///
/// Lock ordering (process-wide rule): `fork_quiesce::topology_lock` →
/// registry lock is PERMITTED — the wake path claims the rebuild
/// (`unpark_vcpu`) under the topology lock, and the MT release path re-checks
/// the registry under a topology TRY-lock. Registry → topology is FORBIDDEN
/// (no registry lock is ever held while acquiring the topology lock; the
/// registry's own methods are self-contained critical sections). The park
/// path never runs under an already-held `topology_lock` (its callers are the
/// blocking-wait arms of the dispatch loop, which hold neither lock).
fn mt_vm_lease_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("CARRICK_MT_VM_LEASE")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// TEST-ONLY: `CARRICK_MT_VM_LEASE_FDBACKED=1` swaps `try_release_vm_mt`'s
/// re-check from the shipped class-aware `all_other_parked_release_safe`
/// (fd-backed parks veto the release) to the class-blind `all_other_parked`
/// — the reproducible form of the veto-neutered mutation that surfaced
/// cluster B (b01e18e2). Default OFF (false); truthy only on the literal
/// value `"1"`, mirroring `mt_vm_lease_enabled` above. This does not ship —
/// it exists so the `procladder_epollmgr` probe can drive the same
/// release-under-fd-waiters shape the cluster-B cores showed, without
/// deleting the shipping veto.
fn mt_vm_lease_fdbacked_release_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("CARRICK_MT_VM_LEASE_FDBACKED").is_some_and(|v| v == "1"))
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
    forked_child_die_by_signal, forked_child_exit, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
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
        let (path, argv) = crate::exec_helpers::resolve_shebang(
            dispatcher,
            dispatcher.resolve_exec_path(path),
            argv,
        )?;
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
        forked_child_die_by_signal, forked_child_exit, stop_after_traced_exec, stop_by_signal,
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
    forked_child_die_by_signal, forked_child_exit, hardware_tso_for_debug, load_execve_image,
    stop_after_traced_exec, stop_by_signal,
};

// ===================================================================
// Ownership-aligned submodules (Task A2). Each concern owns a disjoint file so
// the THREAD / SIGNAL / MEM / PROC agents do not collide. These are pure code
// moves: the `impl ThreadRuntimeState` methods and free fns below live in the
// submodules, re-exported here so every external `crate::vcpu_loop::X` path keeps
// resolving unchanged.
// ===================================================================
mod exec;
mod quiesce;
mod signal;
mod threads;

// Re-export the free fns that moved into submodules so the in-crate callers
// (`crate::runtime`, this module's own code) keep naming them as
// `crate::vcpu_loop::X` / bare `X`.
pub(crate) use quiesce::{fork_barrier, pt_barrier};
// The threaded loop owns its backend-specific fault resolution. Native Darwin
// reuses the architecture lowering and Linux signal-frame half below.
use signal::deliver_fault_signal;
pub(crate) use signal::is_default_ignore_signal;
#[cfg(test)]
pub(crate) use signal::upgrade_protection_si_code;
pub(crate) use signal::{
    deliver_pending_signal, lower_el0_fault, partial_write_interrupt_outcome,
    raise_sigpipe_for_blocking_write, signal_progress_count, signal_wait_expired,
    signal_wait_remaining, signal_wait_slice,
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
struct HvpatchRuntimeEndpoint {
    kernel: Weak<KernelState>,
    /// Exact parent task generation retained at endpoint publication. Child
    /// exit notification must not recapture a newer registry association.
    signal_context: crate::kernel::KernelContext,
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
        self.signal_arrival.wake_all_waiters();
        self.kicker.kick_all();
    }
}

#[derive(Default)]
pub(crate) struct HvpatchRuntimeDirectory {
    endpoints: Mutex<BTreeMap<crate::kernel::TaskKey, HvpatchRuntimeEndpoint>>,
    /// Process-child host threads are shared-VM topology, not members of the
    /// creating process's Linux thread group. The outer root run owns their
    /// eventual joins; per-process finalizers must never treat them as sibling
    /// vCPUs or wait for children that Linux has reparented.
    process_threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl HvpatchRuntimeDirectory {
    fn register(&self, task: crate::kernel::TaskKey, endpoint: HvpatchRuntimeEndpoint) {
        self.endpoints.lock().insert(task, endpoint);
    }

    fn remove(&self, task: crate::kernel::TaskKey) {
        self.endpoints.lock().remove(&task);
    }

    fn enroll_process_thread(&self, handle: std::thread::JoinHandle<()>) {
        self.process_threads.lock().push(handle);
    }

    fn join_process_threads(&self) -> Result<(), RuntimeError> {
        let mut child_panicked = false;
        loop {
            let handles = std::mem::take(&mut *self.process_threads.lock());
            if handles.is_empty() {
                return if child_panicked {
                    Err(RuntimeError::Unsupported(
                        "HVPatch process child panicked".to_owned(),
                    ))
                } else {
                    Ok(())
                };
            }
            for handle in handles {
                if handle.join().is_err() {
                    child_panicked = true;
                }
            }
            // A joined child may have forked another process before it left.
            // Drain repeatedly until the shared topology census is empty, even
            // after a panic, so no remaining shared-VM owner is detached.
        }
    }

    fn notify_child_exit(&self, parent: crate::kernel::TaskKey, signal: Option<i32>) {
        let endpoints = self.endpoints.lock();
        let Some(endpoint) = endpoints.get(&parent) else {
            return;
        };
        let Some(parent_kernel) = endpoint.kernel.upgrade() else {
            return;
        };
        if let Some(signal) = signal
            && parent_kernel
                .dispatcher
                .child_exit_signal_needs_process_pump(&endpoint.signal_context, signal as u32)
        {
            parent_kernel
                .dispatcher
                .mark_in_process_signal_pending(&endpoint.signal_context, signal);
        }
        // Child waitability is independent of SIGCHLD disposition. The Kernel
        // zombie is durable, but a parent can be between its initial wait query
        // and host-wait enrollment when publication occurs; always nudge every
        // wait vehicle so it rechecks the authoritative graph even when SIGCHLD
        // is ignored or blocked.
        endpoint.signal_context.task().wake();
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
}

#[derive(Debug, Default)]
struct CloneAdmissionState {
    in_flight: usize,
    generation: u64,
    closing: Option<CloneAdmissionClose>,
}

#[derive(Debug, Default)]
struct CloneAdmissionGate {
    state: Mutex<CloneAdmissionState>,
    changed: Condvar,
}

impl CloneAdmissionGate {
    fn try_enroll_kind(&self, kind: CloneAdmissionKind) -> Option<CloneAdmissionPermit<'_>> {
        let mut state = self.state.lock();
        if state.closing.is_some() {
            return None;
        }
        state.in_flight = state.in_flight.checked_add(1)?;
        Some(CloneAdmissionPermit {
            gate: self,
            generation: state.generation,
            kind,
            active: true,
        })
    }

    fn try_enroll_thread_clone(&self) -> Option<CloneAdmissionPermit<'_>> {
        self.try_enroll_kind(CloneAdmissionKind::ThreadClone)
    }

    fn try_enroll_process_fork(&self, owner: ThreadId) -> Option<CloneAdmissionPermit<'_>> {
        self.try_enroll_kind(CloneAdmissionKind::ProcessFork { owner })
    }

    fn is_closing(&self) -> bool {
        self.state.lock().closing.is_some()
    }

    fn is_terminal_closing(&self) -> bool {
        matches!(
            self.state.lock().closing,
            Some(CloneAdmissionClose::Exec { .. } | CloneAdmissionClose::Exit)
        )
    }

    fn close_for_exec(&self, owner: ThreadId) -> Result<ExecCloneAdmission<'_>, RuntimeError> {
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
            gate: self,
            owner,
            generation,
        })
    }

    fn close_for_fork(
        &self,
        owner: ThreadId,
        generation: u64,
    ) -> Result<ForkCloneAdmission<'_>, RuntimeError> {
        let mut state = self.state.lock();
        if state.generation != generation || state.closing.is_some() {
            return Err(RuntimeError::Unsupported(
                "cannot begin fork while clone admission is closing".to_owned(),
            ));
        }
        let close = CloneAdmissionClose::Fork { owner, generation };
        state.closing = Some(close);
        self.changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(5);
        // The caller's own process-fork permit remains enrolled. Every other
        // permit belongs to a thread clone admitted before the fork close and
        // must finish normally before the task snapshot can be reserved.
        while state.in_flight != 1 {
            if state.closing != Some(close) {
                return Err(RuntimeError::Unsupported(
                    "fork clone-admission close was superseded".to_owned(),
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                state.closing = None;
                self.changed.notify_all();
                return Err(RuntimeError::Unsupported(format!(
                    "fork clone-admission drain timed out: in_flight={}",
                    state.in_flight
                )));
            }
            self.changed
                .wait_for(&mut state, (deadline - now).min(Duration::from_millis(50)));
        }
        Ok(ForkCloneAdmission {
            gate: self,
            owner,
            generation,
        })
    }

    fn claim_process_exit(&self) -> Result<ProcessExitClaim, RuntimeError> {
        let mut state = self.state.lock();
        match state.closing {
            Some(CloneAdmissionClose::Exec { .. }) => return Ok(ProcessExitClaim::LostToExec),
            Some(CloneAdmissionClose::Fork { .. }) => {
                // Whole-process exit wins an ordinary fork. The fork permit
                // observes Exit as cancellation and drains before teardown.
                state.closing = Some(CloneAdmissionClose::Exit);
            }
            Some(CloneAdmissionClose::Exit) => return Ok(ProcessExitClaim::AlreadyOwned),
            None => state.closing = Some(CloneAdmissionClose::Exit),
        }
        self.changed.notify_all();
        let deadline = Instant::now() + Duration::from_secs(5);
        while state.in_flight != 0 {
            let now = Instant::now();
            if now >= deadline {
                return Err(RuntimeError::Unsupported(format!(
                    "process-exit clone-admission drain timed out: in_flight={}",
                    state.in_flight
                )));
            }
            self.changed
                .wait_for(&mut state, (deadline - now).min(Duration::from_millis(50)));
        }
        Ok(ProcessExitClaim::Owner)
    }
}

struct CloneAdmissionPermit<'a> {
    gate: &'a CloneAdmissionGate,
    generation: u64,
    kind: CloneAdmissionKind,
    active: bool,
}

impl CloneAdmissionPermit<'_> {
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

    fn close_for_fork(&self, owner: ThreadId) -> Result<ForkCloneAdmission<'_>, RuntimeError> {
        if self.kind != (CloneAdmissionKind::ProcessFork { owner }) {
            return Err(RuntimeError::Unsupported(
                "fork close requires the matching process-fork permit".to_owned(),
            ));
        }
        self.gate.close_for_fork(owner, self.generation)
    }
}

impl Drop for CloneAdmissionPermit<'_> {
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
        if state.in_flight == 0 || state.closing.is_some() {
            self.gate.changed.notify_all();
        }
    }
}

struct ForkCloneAdmission<'a> {
    gate: &'a CloneAdmissionGate,
    owner: ThreadId,
    generation: u64,
}

impl Drop for ForkCloneAdmission<'_> {
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

struct ExecCloneAdmission<'a> {
    gate: &'a CloneAdmissionGate,
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

impl Drop for ExecCloneAdmission<'_> {
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
/// compat reporter, and the host-fork coordinator (held object-safe so this is
/// cross-platform). Built by the macOS setup wrapper with the boxed HVF
/// `ForkCoordinator`.
pub(crate) struct KernelState {
    pub(crate) dispatcher: SyscallDispatcher,
    pub(crate) reporter: CompatReporter,
    pub(crate) fork: Arc<dyn HostForkCoordinator>,
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
    /// Non-zero while a fatal owner is collecting one task-local register
    /// generation. Sibling loops observe it at their quiesce safe point.
    crash_capture_generation: Option<Arc<std::sync::atomic::AtomicU64>>,
    next_crash_capture_generation: std::sync::atomic::AtomicU64,
    /// Number of host vCPU loops still alive for this Linux process.
    process_vcpu_live: std::sync::atomic::AtomicUsize,
    /// Cross-layer thread-clone admission spans Kernel reservation through
    /// runtime registration, handle visibility, and child start.
    clone_admission: CloneAdmissionGate,
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
}

impl KernelState {
    pub(crate) fn new(
        dispatcher: SyscallDispatcher,
        fork: Arc<dyn HostForkCoordinator>,
        signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
        hvpatch_process: Option<crate::hvpatch::ProcessContext>,
        inherited_hvpatch_runtime: Option<Arc<HvpatchRuntimeDirectory>>,
        child_exit_signal: Option<i32>,
    ) -> Self {
        let process_fork_barrier = hvpatch_process
            .as_ref()
            .map(|_| Arc::new(crate::fork_quiesce::QuiesceBarrier::new()));
        let crash_capture_generation = hvpatch_process
            .as_ref()
            .map(|_| Arc::new(std::sync::atomic::AtomicU64::new(0)));
        let hvpatch_runtime = hvpatch_process.as_ref().map(|_| {
            inherited_hvpatch_runtime
                .unwrap_or_else(|| Arc::new(HvpatchRuntimeDirectory::default()))
        });
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            fork,
            signal_arrival,
            hvpatch_process,
            process_exiting: std::sync::atomic::AtomicBool::new(false),
            process_fork_barrier,
            crash_capture_generation,
            next_crash_capture_generation: std::sync::atomic::AtomicU64::new(0),
            process_vcpu_live: std::sync::atomic::AtomicUsize::new(0),
            clone_admission: CloneAdmissionGate::default(),
            hvpatch_runtime,
            child_exit_signal,
            process_terminal: Mutex::new(None),
            process_terminal_ready: Condvar::new(),
            fatal_signal: FatalSignalAuthority::default(),
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
        directory.register(
            process.task_key(),
            HvpatchRuntimeEndpoint {
                kernel: Arc::downgrade(self),
                signal_context,
            },
        );
    }

    fn enroll_hvpatch_process_thread(&self, handle: std::thread::JoinHandle<()>) {
        let Some(directory) = self.hvpatch_runtime.as_ref() else {
            std::process::abort();
        };
        directory.enroll_process_thread(handle);
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

    fn begin_exec_replacement(&self, owner: ThreadId) {
        crate::fork_quiesce::begin_exec_replacement(owner);
    }

    fn end_exec_replacement(&self) {
        crate::fork_quiesce::end_exec_replacement();
    }

    /// True for a Linux child process multiplexed inside the current host
    /// process.  These children must return a `ProcessExit` to the lifecycle
    /// owner; the legacy fork-child paths below must never call host `_exit`.
    fn is_hvpatch_child(&self) -> bool {
        self.hvpatch_process
            .as_ref()
            .is_some_and(crate::hvpatch::ProcessContext::is_child)
    }

    fn begin_process_exit(&self) {
        self.process_exiting
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Arbitrate exec and whole-process exit under the same admission lock.
    /// An exec owner drains terminal siblings as ordinary thread losers; an
    /// exit owner permanently closes admission and becomes the sole process
    /// finalizer. This prevents mutually waiting terminal drains.
    fn claim_process_exit(&self) -> Result<ProcessExitClaim, RuntimeError> {
        let claim = self.clone_admission.claim_process_exit()?;
        if claim == ProcessExitClaim::Owner {
            self.begin_process_exit();
        }
        Ok(claim)
    }

    pub(crate) fn process_exiting(&self) -> bool {
        self.process_exiting
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn try_enroll_thread_clone(&self) -> Option<CloneAdmissionPermit<'_>> {
        self.clone_admission.try_enroll_thread_clone()
    }

    fn clone_admission_cancelled(&self) -> bool {
        self.clone_admission.is_closing()
    }

    fn clone_admission_terminal_cancelled(&self) -> bool {
        self.clone_admission.is_terminal_closing()
    }

    fn close_clone_admission_for_exec(
        &self,
        owner: ThreadId,
    ) -> Result<ExecCloneAdmission<'_>, RuntimeError> {
        self.clone_admission.close_for_exec(owner)
    }

    fn process_vcpu_live(&self) -> usize {
        self.process_vcpu_live
            .load(std::sync::atomic::Ordering::SeqCst)
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

pub(super) enum BlockingWaitCompletion {
    Retval(i64),
    ExecReplacedThread,
}

pub(super) enum SharedWordWaitCompletion {
    Changed,
    Interrupted,
    ExecReplacedThread,
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

fn trace_hvpatch_wait_begin<E: ThreadedEngine>(
    kernel: &Kernel,
    tid: ThreadId,
    wait_class: u8,
    fds: &[crate::io_wait::WaitFd],
    engine: &E,
) -> Option<u32> {
    let process = kernel.hvpatch_process.as_ref()?;
    let Some(registers) = engine.diagnostic_wait_registers() else {
        crate::event_ring::rec_hvpatch_wait(process.pid(), tid.raw(), wait_class, 1, fds.len());
        return None;
    };
    Some(crate::event_ring::rec_hvpatch_wait_begin(
        process.pid(),
        tid.raw(),
        wait_class,
        fds.len(),
        fds.first().map(|fd| (fd.fd(), fd.events())),
        crate::event_ring::HvpatchWaitRegisters {
            pc: registers.pc,
            sp: registers.sp,
            lr: registers.lr,
        },
    ))
}

fn trace_hvpatch_wait_end(
    kernel: &Kernel,
    tid: ThreadId,
    wait_class: u8,
    phase: u8,
    fd_count: usize,
    id: Option<u32>,
) {
    if let Some(process) = kernel.hvpatch_process.as_ref() {
        if let Some(id) = id {
            crate::event_ring::rec_hvpatch_wait_end(
                process.pid(),
                tid.raw(),
                wait_class,
                phase,
                fd_count,
                id,
            );
        } else {
            crate::event_ring::rec_hvpatch_wait(
                process.pid(),
                tid.raw(),
                wait_class,
                phase,
                fd_count,
            );
        }
    }
}

fn hvpatch_wait_result_phase(result: &crate::io_wait::WaitResult) -> u8 {
    match result {
        crate::io_wait::WaitResult::Ready => 2,
        crate::io_wait::WaitResult::TimedOut => 3,
        crate::io_wait::WaitResult::Interrupted => 4,
        crate::io_wait::WaitResult::Errno(_) => 5,
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

/// Hand the dispatcher the loaded image's region list + auxv so /proc/self/maps
/// and /proc/self/auxv reflect it (refreshed on each execve).
pub(crate) fn apply_image_proc_state(dispatcher: &SyscallDispatcher, image: &AddressSpace) {
    dispatcher.set_address_space_regions(proc_maps_from_address_space(image));
    dispatcher.set_address_space_file_mappings(core_file_mappings_from_address_space(image));
    dispatcher.set_auxv_image(image.linux_auxv_image().to_vec());
}

/// Publish a successful exec image as one dispatcher VMA generation.
pub(crate) fn apply_exec_image_proc_state(dispatcher: &SyscallDispatcher, image: &AddressSpace) {
    dispatcher.publish_exec_image_state(
        proc_maps_from_address_space(image),
        image.linux_auxv_image().to_vec(),
        core_file_mappings_from_address_space(image),
    );
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
pub(crate) fn stamp_identity_page<M: GuestMemory>(
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

fn stamp_identity_page_at<M: GuestMemory>(
    memory: &mut M,
    dispatcher: &SyscallDispatcher,
    kernel_context: &crate::kernel::KernelContext,
    base: u64,
) -> Result<(), carrick_guest_mem::MemoryError> {
    if !crate::syscall_shim_enabled() {
        return Ok(());
    }
    let id = dispatcher.identity_snapshot(kernel_context);
    stamp_identity_values(
        memory,
        base,
        id.pid,
        u32::from(dispatcher.identity_fast_path_enabled()),
    )
}

fn stamp_identity_values<M: GuestMemory>(
    memory: &mut M,
    base: u64,
    pid: u32,
    shim_enabled: u32,
) -> Result<(), carrick_guest_mem::MemoryError> {
    for (off, val) in [
        (crate::memory::IDENTITY_OFF_PID, pid),
        (crate::memory::IDENTITY_OFF_SHIM_ENABLED, shim_enabled),
    ] {
        memory.write_bytes(base + off, &val.to_le_bytes())?;
    }
    Ok(())
}

/// Stamp the running guest thread's guest-visible tid into the vCPU sysreg that
/// the EL1 shim returns for `gettid` without a VM exit (no-op unless the shim is
/// enabled). Must run whenever the vCPU is (re)created — boot, clone, fork,
/// exec — since vCPU sysregs reset.
pub(crate) fn stamp_guest_tid<E: ThreadedEngine>(
    engine: &E,
    _this_tid: ThreadId,
    _registry: &ThreadRegistry,
    hvpatch_linux_tid: Option<crate::kernel::LinuxTid>,
) {
    if !crate::syscall_shim_enabled() {
        return;
    }
    let tid = hvpatch_linux_tid.and_then(|tid| u32::try_from(tid.raw()).ok());
    if let Some(tid) = tid {
        let _ = engine.set_guest_thread_id(u64::from(tid));
    }
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
    crash_capture_generation: Option<Arc<std::sync::atomic::AtomicU64>>,
    kernel_thread: Option<crate::kernel::ThreadRef>,
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
    /// Last task-wake generation reconciled at a safe guest boundary. Lane
    /// kicks remain the prompt path; this closes the host-side/rebind interval
    /// where no vCPU run exists yet to consume one.
    observed_task_wake_generation: u64,
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

struct BlockingWaitReclaim {
    state: Vec<u8>,
    old_slot: Option<carrick_hal::SlotId>,
    single_threaded_process: bool,
}

struct PreparedCorePublication {
    snapshot: crate::dispatch::CoreProcessSnapshot,
    bytes: Vec<u8>,
    generation: u64,
    fatal_tid: i32,
}

/// Return whichever bounded-scheduler slot this host thread owns when its
/// guest vCPU loop ends.  Process-leader threads created by hvpatch fork do
/// not necessarily hold a lease at startup, but can acquire one later when a
/// blocking wait resumes.  Keeping this guard at the loop boundary covers
/// that late-acquire case as well as ordinary main and clone threads, on every
/// return/error path.
struct VcpuLeaseGuard;

impl Drop for VcpuLeaseGuard {
    fn drop(&mut self) {
        if let Some(lease) = carrick_hal::vcpu_sched::take_current_lease() {
            carrick_hal::vcpu_sched::global()
                .release(lease, carrick_hal::vcpu_sched::Yield::Exited);
        }
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

struct ProcessVcpuLiveGuard<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for ProcessVcpuLiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
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
        crash_capture_generation: Option<Arc<std::sync::atomic::AtomicU64>>,
        kernel_thread: Option<crate::kernel::ThreadRef>,
        hvpatch_task_pid: Option<i32>,
        linux_tid: crate::kernel::LinuxTid,
        fatal_image_generation: u64,
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
            process_fork_barrier,
            crash_capture_generation,
            kernel_thread,
            hvpatch_task_pid,
            linux_tid,
            fatal_image_generation,
            service_kernel_context: None,
            observed_task_wake_generation: 0,
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

    fn fork_is_quiescing(&self) -> bool {
        self.process_fork_barrier
            .as_ref()
            .map_or_else(crate::fork_quiesce::is_quiescing, |barrier| {
                barrier.is_quiescing()
            })
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

    /// Publish both process-visible and per-thread state at the points that
    /// already maintain the thread registry on mature lanes.
    fn publish_thread_run_state(&self, state: crate::run_state::RunState, stat: char) {
        self.publish_process_run_state(state);
        crate::thread::set_current_thread_state(self.this_tid, stat);
        if self.hvpatch_task_pid.is_none() {
            crate::run_state::publish_guest_tid(self.this_tid.raw(), state);
        }
    }

    fn publish_crash_registers_if_requested(&self, engine: &E) -> Result<(), RuntimeError> {
        let Some(generation) = self.crash_capture_generation.as_ref() else {
            return Ok(());
        };
        let mut generation = generation.load(std::sync::atomic::Ordering::Acquire);
        if generation == 0 {
            return Ok(());
        }
        if std::env::var_os("CARRICK_CORE_FAILPOINT")
            .is_some_and(|value| value == "register-generation")
        {
            generation = generation.saturating_add(1);
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
        let advertised = kernel.crash_capture_generation.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "HVPatch crash capture lacks generation authority".to_owned(),
            )
        })?;
        let generation = kernel
            .next_crash_capture_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .checked_add(1)
            .ok_or_else(|| {
                RuntimeError::Configuration("HVPatch crash generation exhausted".to_owned())
            })?;
        let lifecycle = |phase, outcome| {
            crate::probes::hvpatch_core_lifecycle(
                phase,
                process_pid,
                fatal.tid.raw(),
                generation,
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
        advertised.store(generation, std::sync::atomic::Ordering::Release);
        let mut quiesced = false;
        let result = (|| {
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "capture-registers")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint capture-registers".to_owned(),
                ));
            }
            self.publish_crash_registers_if_requested(engine)?;
            if self.kicker.count() > 1 {
                barrier.set_quiescing();
                quiesced = true;
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while self.kicker.count() > 1 {
                    if std::time::Instant::now() >= deadline {
                        return Err(RuntimeError::Configuration(format!(
                            "HVPatch crash generation {generation} timed out: {} sibling vCPUs remain",
                            self.kicker.count().saturating_sub(1)
                        )));
                    }
                    self.kicker.kick_all_except(self.this_tid);
                    self.futex.notify_signal_pending();
                    self.platform_futex.notify_signal_pending();
                    kernel.signal_arrival.wake_all_waiters();
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            }
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

            let task_threads = context.task().threads();
            let required_threads = u64::try_from(task_threads.len()).unwrap_or(u64::MAX);
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "missing-thread")
            {
                return Err(RuntimeError::Configuration(
                    "core publication failpoint missing-thread".to_owned(),
                ));
            }
            let collect_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut threads = loop {
                let mut collected = Vec::with_capacity(task_threads.len());
                let mut missing_tid = None;
                for thread in &task_threads {
                    let Some(registers) = thread.crash_registers(generation) else {
                        missing_tid = Some(thread.key().tid.raw());
                        break;
                    };
                    let mut gregs = [0_u64; crate::core_dump::AARCH64_GREGS];
                    gregs[..31].copy_from_slice(&registers.gprs);
                    gregs[31] = registers.sp_el0;
                    // The engine selects live PC/PSTATE for a vCPU force-exited
                    // directly from EL0, or saved ELR/SPSR while a syscall is
                    // parked in EL1. A synchronous fatal owner is independently
                    // identified by its positive kernel si_code and uses the raw
                    // exception ELR/SPSR pair. Raw pairs remain in Kernel authority.
                    let synchronous_fatal_owner = thread.key().tid == fatal.tid && fatal.code > 0;
                    let (resume_pc, resume_pstate) =
                        core_note_resume_pair(&registers, synchronous_fatal_owner);
                    gregs[32] = resume_pc;
                    gregs[33] = resume_pstate;
                    collected.push(crate::core_dump::ThreadState {
                        tid: thread.key().tid.raw(),
                        registers: crate::core_dump::ThreadRegisters {
                            gregs,
                            tpidr_el0: registers.tpidr_el0,
                            vregs: registers.vregs,
                            fpsr: registers.fpsr,
                            fpcr: registers.fpcr,
                        },
                        current_signal: if thread.key().tid == fatal.tid {
                            fatal.signo
                        } else {
                            0
                        },
                    });
                }
                if missing_tid.is_none() {
                    break collected;
                }
                if std::time::Instant::now() >= collect_deadline {
                    return Err(RuntimeError::Configuration(format!(
                        "core generation {generation} missing registers for tid {}",
                        missing_tid.unwrap_or_default()
                    )));
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
                generation,
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
                generation,
                mapping_count,
                4_u64.saturating_add(thread_count.saturating_mul(3)),
                region_count,
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            );
            crate::probes::hvpatch_core_hash(generation, hash_words);
            lifecycle(3, 0);
            Ok(Some(PreparedCorePublication {
                snapshot: process,
                bytes,
                generation,
                fatal_tid: fatal.tid.raw(),
            }))
        })();
        if result.is_err() || matches!(&result, Ok(None)) {
            lifecycle(6, if result.is_err() { 1 } else { 2 });
        }
        advertised.store(0, std::sync::atomic::Ordering::Release);
        if quiesced {
            barrier.end_quiesce();
        }
        barrier.end_fork();
        result
    }

    fn park_if_fork_quiescing(&self) {
        if let Some(barrier) = &self.process_fork_barrier {
            barrier.park_if_quiescing();
        } else {
            fork_barrier().park_if_quiescing();
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

    fn park_vcpu_for_blocking_wait(
        &self,
        engine: &mut E,
        park_class: crate::thread::VcpuParkClass,
    ) -> Option<BlockingWaitReclaim> {
        self.park_vcpu_for_blocking_wait_with_policy(engine, park_class, false)
    }

    fn park_vcpu_for_blocking_wait_with_policy(
        &self,
        engine: &mut E,
        park_class: crate::thread::VcpuParkClass,
        force_reclaim: bool,
    ) -> Option<BlockingWaitReclaim> {
        if !engine.reclaims() {
            return None;
        }
        // KEEP the vCPU when the pool is uncontended, unless the caller has
        // already classified this wait as long enough to yield proactively.
        //
        // `has_waiters`/`has_spare_capacity` were written for exactly this and
        // then never called from anywhere in the workspace, so every blocking
        // wait paid a full HVF destroy/recreate even with the pool almost
        // entirely free. Wiring them makes the common case the no-reclaim path,
        // which an ABBA measured as CPU-neutral and 13x more consistent
        // run-to-run (`2026-08-13-hvpatch-noreclaim-abba.md`), while keeping
        // reclaim as the safety valve under real contention.
        //
        // Both conditions are needed and the asymmetry is deliberate. Keeping
        // the vCPU requires a slot to be FREE, not merely that nobody is
        // waiting yet: a thread parked at a barrier it can only leave once some
        // future waiter runs would otherwise deadlock that waiter. And an
        // existing waiter means release now, spare capacity or not.
        let scheduler = carrick_hal::vcpu_sched::global();
        if should_keep_vcpu_for_blocking_wait(
            force_reclaim,
            scheduler.has_spare_capacity(),
            scheduler.has_waiters(),
        ) {
            return None;
        }
        let park_started = std::time::Instant::now();
        // A one-thread Linux process does not necessarily own the VM: hvpatch
        // multiplexes several process registries in one persistent HVF VM.
        // Whole-VM park/rebuild is therefore legal only on the legacy
        // one-process-per-VM path. Hvpatch always destroys/recreates this
        // thread's vCPU alone while other processes continue running.
        let single_threaded_process =
            self.registry.live_count() == 1 && self.process_fork_barrier.is_none();
        let state = if single_threaded_process {
            // Single-threaded: this thread IS the whole process — no sibling
            // can race the teardown, so release unconditionally via the
            // combined vCPU+VM park (the historical pre-lease path, kept
            // byte-identical; the class is recorded but nothing consults it
            // for ST). The registry bookkeeping is harmless here (one
            // thread, no contention) and keeps one claim protocol; the flag
            // is claimed back by this same thread's own `unpark_vcpu` on wake.
            let _ = self
                .registry
                .park_vcpu_classified(self.this_tid, park_class);
            let st = engine.save_shared_wait_state();
            self.registry.set_vm_released(true);
            st
        } else {
            // MT: vCPU-only park. Destroy this thread's OWN vCPU FIRST
            // (reclaim_park shape — snapshot stashed, compatible with the
            // shared-wait resume), and only THEN set the registry "parked"
            // mark — so `vcpu_parked` truthfully means "vCPU actually
            // destroyed". The mark carries the wait's wake-path CLASS: a
            // parked FD-BACKED wait vetoes any sibling's whole-VM release
            // (the fd-wait wake path under a released VM has an
            // un-root-caused gap — attribution cluster B). The whole-VM
            // release is deliberately NOT taken here: an eager last-unparked
            // release on this common park path made every hot MT blocking
            // wait pay a full VM release+rebuild (wait_pipe_pingpong p50
            // 41.9µs → 354µs, +867% — see
            // .superpowers/sdd/task-6-regression-attribution.md, cluster A1)
            // and wedged the CPython forkserver suite (cluster B). The
            // release is DEFERRED to the slicing wait arms' second parked
            // full slice — see `try_upgrade_vm_release_on_slice_tick`.
            let st = engine.save_guest_state();
            let _ = self
                .registry
                .park_vcpu_classified(self.this_tid, park_class);
            st
        };
        let old_slot = carrick_hal::vcpu_sched::current_slot();
        if let Some(lease) = carrick_hal::vcpu_sched::take_current_lease() {
            carrick_hal::vcpu_sched::global()
                .release(lease, carrick_hal::vcpu_sched::Yield::Blocked);
        }
        if engine.reclaim_refreshes_kicker() {
            self.kicker.unregister(self.this_tid);
        }
        {
            use std::sync::atomic::Ordering::Relaxed;
            VCPU_RECLAIMS.fetch_add(1, Relaxed);
            VCPU_RECLAIM_PARK_NS.fetch_add(
                u64::try_from(park_started.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Relaxed,
            );
        }
        Some(BlockingWaitReclaim {
            state,
            old_slot,
            single_threaded_process,
        })
    }

    /// Deferred MT whole-VM release — the SLICE-TICK UPGRADE. Called only
    /// from the SLICING wait arms (WaitOnSignals, WaitOnSleep — the arms
    /// that re-dispatch on ≥1 s parked service slices), on a tick where this
    /// thread has ALREADY completed at least one full parked slice AND the
    /// CURRENT tick is itself a full ≥1 s slice (both counted/checked by the
    /// caller — a finite wait's final <1 s window uses short slices and must
    /// not churn releases at slice rate). At that point this thread's own
    /// vCPU is already destroyed by the slice's vCPU-only park, so an idle
    /// fully-parked MT process converges to holding zero HVF VMs within ~1 s
    /// — while hot blocking paths (pipe/futex pingpongs, which park and wake
    /// in microseconds) never reach a second slice and never pay the
    /// release+rebuild round trip (the +867% wait_pipe regression the eager
    /// design caused — task-6-regression-attribution.md, cluster A1).
    /// Post-release ticks stretch progressively (2s→4s→8s, caller-managed)
    /// so a long-idle process converges to ~1 rebuild per 8 s. The better
    /// endpoint — SKIP the resume/re-park round trip entirely on an idle
    /// TimedOut tick — is now IMPLEMENTED: both slicing arms wrap the wait in
    /// an inner re-wait loop, so a fully-idle parked process re-arms without
    /// resuming/re-parking (deadline + EINTR bookkeeping stays inside the
    /// loop; a finite deadline expiry, a real wake, or a non-parked short
    /// wait still breaks out to the single resume). A long-idle MT process
    /// therefore holds zero HVF VMs and issues ~1 rebuild for the whole idle
    /// span (the boot + final wake), not one per stretched tick.
    ///
    /// Returns true iff the process VM is released when this returns (this
    /// call released it, or it was already released) — the caller uses it to
    /// drive the post-release slice-stretch progression.
    ///
    /// INVARIANT (enforced, not just documented): a parked FD-BACKED wait
    /// anywhere in the process VETOES the release
    /// (`all_other_parked_release_safe`) — fd-backed waits never have the VM
    /// released from under them until the fd-wait wake gap is root-caused
    /// (the CPython forkserver wedge: attribution report cluster B, retained
    /// cores cr-attr-fs.38232 et al. — an fd-wait manager parked and made no
    /// progress). Consequently a process whose blocked threads are ALL in
    /// fd-backed waits never releases its VM; a mixed process releases only
    /// while every parked sibling is wake-safe (signal/timer/futex-driven,
    /// or an empty-fd-set poll like `ppoll(NULL)`).
    fn try_upgrade_vm_release_on_slice_tick(&self, engine: &mut E) -> bool {
        if self.process_fork_barrier.is_some()
            || !mt_vm_lease_enabled()
            || self.registry.live_count() == 1
        {
            // ST processes already released eagerly at park
            // (save_shared_wait_state); the upgrade is MT-only.
            // Hvpatch never releases the shared VM from a process-local wait.
            return false;
        }
        self.try_release_vm_mt(engine)
    }

    /// MT whole-VM release machinery (used only by the slice-tick upgrade
    /// above): this thread — whose own vCPU is ALREADY destroyed by its
    /// vCPU-only park — releases the remaining whole-VM state so a fleet of
    /// fully-blocked MT processes holds zero HVF VM slots.
    ///
    /// The re-check + teardown + `set_vm_released` run under the topology
    /// lock so they are ATOMIC against a waking sibling's claim + rebind
    /// (which hold the same lock in `resume_vcpu_after_blocking_wait`):
    /// without it, a sibling waking between the all-parked re-check and the
    /// teardown could claim FALSE (flag not yet set) and re-create its vCPU
    /// in the VM we are destroying. TRY-lock, not lock: on a NON-refresh
    /// (pool-swap) backend this thread is still kicker-registered while
    /// parked, so blocking on a forker-held topology lock would deadlock the
    /// quiesce drain; on HVF (kicker already unregistered by the park) the
    /// try-lock still holds — a contended lock means a fork/exec is
    /// rebuilding the VM topology anyway, so releasing now would be wasted
    /// work at best. A held lock simply skips the release (the park stays
    /// vCPU-only); so does an unparked sibling (the re-check), a parked
    /// FD-BACKED sibling (the release-safe veto), or an already-set flag
    /// (VM already dead — reported as released).
    ///
    /// `vm_released` is set ONLY when the engine reports a successful
    /// whole-VM release (`Ok(true)`). On `Err` — e.g. HV_BUSY from a vCPU in
    /// a teardown window the registry no longer tracks (a thread mid-exit) —
    /// the VM is still alive and setting the flag would poison an innocent
    /// sibling's wake with a rebuild against a live VM; instead the park
    /// stays vCPU-only, with a gated diagnostic.
    ///
    /// Returns true iff the VM stands released on return.
    fn try_release_vm_mt(&self, engine: &mut E) -> bool {
        let Some(_topo) = crate::fork_quiesce::try_acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::VmRelease,
            0,
            self.this_tid.raw(),
        ) else {
            return false;
        };
        if self.registry.vm_released() {
            // A slicing sibling already released this tick cycle and no
            // waker has claimed yet: the VM is already gone.
            return true;
        }
        let release_safe = if mt_vm_lease_fdbacked_release_enabled() {
            // TEST-ONLY (CARRICK_MT_VM_LEASE_FDBACKED=1): treat fd-backed
            // parks as release-safe — the reproducible form of the
            // procladder_mixed mutation check (b01e18e2). The veto stays the
            // shipping default until cluster B is root-caused (the recorded
            // reviewer condition).
            self.registry.all_other_parked(self.this_tid)
        } else {
            self.registry.all_other_parked_release_safe(self.this_tid)
        };
        if !release_safe {
            // A sibling woke (its unpark cleared its mark) — it is about to
            // re-create its vCPU — or (default veto) a parked sibling is in
            // an FD-BACKED wait, whose wake path must never see the VM
            // released from under it (attribution cluster B). The VM stays.
            return false;
        }
        match engine.release_vm_after_reclaim_park() {
            Ok(true) => {
                self.registry.set_vm_released(true);
                true
            }
            // Backend has no whole-VM state to release (pool-swap): nothing
            // to flag; the wake side's rebind_to_slot is already correct.
            Ok(false) => false,
            Err(error) => {
                tracing::warn!(
                    tid = self.this_tid.raw(),
                    %error,
                    "MT whole-VM release failed; keeping the park vCPU-only \
                     (vm_released NOT set)"
                );
                false
            }
        }
    }

    fn park_vcpu_for_timed_wait(
        &self,
        engine: &mut E,
        timeout: Option<Duration>,
        park_class: crate::thread::VcpuParkClass,
    ) -> Option<BlockingWaitReclaim> {
        if should_reclaim_vcpu_for_timed_wait(timeout) {
            self.park_vcpu_for_blocking_wait_with_policy(engine, park_class, true)
        } else {
            None
        }
    }

    fn resume_vcpu_after_blocking_wait(
        &self,
        engine: &mut E,
        reclaim: Option<BlockingWaitReclaim>,
    ) -> Result<(), RuntimeError> {
        // Timed from entry so the census captures the whole resume, including
        // any wait for a free slot — which is exactly the cost the executor
        // model removes, since an executor never gives its vCPU up.
        let resume_started = std::time::Instant::now();
        let _resume_census = ResumeCensusGuard(resume_started);
        let Some(reclaim) = reclaim else {
            return Ok(());
        };
        let mut kicker_dropped = engine.reclaim_refreshes_kicker();
        let new_lease = loop {
            if let Some(lease) = carrick_hal::vcpu_sched::global().acquire_timeout(
                self.this_tid.raw() as u64,
                reclaim.old_slot,
                Duration::from_millis(50),
            ) {
                break lease;
            }
            if self.fork_is_quiescing() {
                if !kicker_dropped {
                    self.kicker.unregister(self.this_tid);
                    kicker_dropped = true;
                }
                self.park_if_fork_quiescing();
            }
        };
        carrick_hal::vcpu_sched::set_current_lease(new_lease);
        if engine.reclaim_refreshes_kicker() {
            let _topo = crate::fork_quiesce::acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::VcpuRebind,
                0,
                self.this_tid.raw(),
            );
            // Claim the whole-VM rebuild INSIDE the topology lock — the same
            // lock the park-side teardown and every rebind hold — so a
            // claim-FALSE result proves the claimer's rebuild (or the
            // teardown's downgrade) already completed: a claim-false waker
            // can never reach `rebind_to_slot` against a dead VM. Exactly one
            // of any set of simultaneous wakers claims true (registry mutex).
            // `unpark_vcpu` is ALWAYS called (the mark must clear); the MT
            // claim is honored only with the lease enabled, so
            // CARRICK_MT_VM_LEASE=0 is a true zero (no MT release can have
            // set the flag with the lease off, so ignoring a claim is safe).
            let claimed = self.registry.unpark_vcpu(self.this_tid);
            let rebuild_vm = reclaim.single_threaded_process || (mt_vm_lease_enabled() && claimed);
            if rebuild_vm {
                if reclaim.single_threaded_process {
                    engine
                        .rebind_shared_wait_state(new_lease.slot, &reclaim.state)
                        .map_err(RuntimeError::Trap)?;
                } else {
                    // MT first waker: rebuild the process VM on behalf of the
                    // still-parked siblings — the mapping replay must carry
                    // the UNION of every thread's dynamic mappings, not just
                    // this thread's per-thread list.
                    engine
                        .rebind_shared_wait_state_mt(new_lease.slot, &reclaim.state)
                        .map_err(RuntimeError::Trap)?;
                }
            } else {
                engine
                    .rebind_to_slot(new_lease.slot, &reclaim.state)
                    .map_err(RuntimeError::Trap)?;
            }
            let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
            self.kicker.register(self.this_tid, handle);
        } else {
            if self.fork_is_quiescing() {
                if !kicker_dropped {
                    self.kicker.unregister(self.this_tid);
                    kicker_dropped = true;
                }
                self.park_if_fork_quiescing();
            }
            if kicker_dropped {
                self.register_vcpu(engine);
            }
            // Non-refresh (pool-swap: KVM x86 / bhyve) branch: no backend in
            // this branch tears down per-process VM state on a shared-wait
            // park (`save_shared_wait_state` defaults to the vCPU pool-swap),
            // so there is no dead-VM window and the claim needs no topology
            // lock. Taking it here would deadlock a concurrent fork quiesce:
            // this thread stays kicker-REGISTERED on pool-swap backends, so
            // the forker (holding the topology lock) would wait on our park
            // while we wait on its lock. Same lease gating as the refresh
            // branch: unpark always, honor an MT claim only with the lease on.
            let claimed = self.registry.unpark_vcpu(self.this_tid);
            let rebuild_vm = reclaim.single_threaded_process || (mt_vm_lease_enabled() && claimed);
            if rebuild_vm {
                if reclaim.single_threaded_process {
                    engine
                        .rebind_shared_wait_state(new_lease.slot, &reclaim.state)
                        .map_err(RuntimeError::Trap)?;
                } else {
                    engine
                        .rebind_shared_wait_state_mt(new_lease.slot, &reclaim.state)
                        .map_err(RuntimeError::Trap)?;
                }
            } else {
                engine
                    .rebind_to_slot(new_lease.slot, &reclaim.state)
                    .map_err(RuntimeError::Trap)?;
            }
        }
        let prev = reclaim.old_slot.unwrap_or(new_lease.slot);
        crate::probes::mn_reclaim(
            self.this_tid.raw(),
            prev,
            new_lease.slot,
            if new_lease.slot == prev { 1 } else { 2 },
        );
        Ok(())
    }

    fn exec_replaced_thread_exit(&self) -> Option<DispatchOutcome> {
        if thread_should_finish_for_exec_replacement(&self.registry, self.this_tid) {
            Some(DispatchOutcome::ThreadExit { code: 0 })
        } else {
            None
        }
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

    fn service_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        frame: carrick_hal::RawSyscall,
    ) -> Result<DispatchOutcome, RuntimeError> {
        self.service_kernel_context = None;
        // Stage-1 page-table editors — munmap(215), mremap(216), mmap(222),
        // mprotect(226) — mutate the shared guest descriptors from the host.
        // With sibling vCPUs live, Pause-Modify-Resume them so none walks a
        // half-edited descriptor tree.
        let _pt_pause = match frame.number.raw() {
            215 | 216 | 222 | 226 if self.kicker.count() > 1 => match self.pt_pause() {
                Ok(guard) => Some(guard),
                Err(quiesce::PtPauseError::TimedOut) => {
                    // No dispatcher/backend mapping call has started yet. Return
                    // a clean Linux allocation failure after pt_pause rolled the
                    // request back and resumed already-parked siblings.
                    return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ENOMEM));
                }
            },
            _ => None,
        };
        let mut signal_wait_deadline = None;
        // Completed FULL (≥1 s) parked service slices in this syscall's
        // slicing wait arms (WaitOnSignals / WaitOnSleep). Drives the
        // deferred MT whole-VM upgrade: the FIRST parked slice is always
        // vCPU-only; from the second FULL tick on (≈1 s parked, provably
        // idle) the arm attempts `try_upgrade_vm_release_on_slice_tick`.
        // Resets naturally with each new syscall dispatch (deliberately NOT
        // on a Ready wake — see the WaitOnSignals arm's comment).
        let mut parked_full_slices: u32 = 0;
        // Parked-slice stretch target for the slicing arms: 1 s until a
        // whole-VM release succeeds, then 2s→4s→8s (reset to 1 s on any
        // real wake) so a long-idle released process converges to ~1
        // rebuild per 8 s. The better endpoint — skip the resume/re-park
        // round trip entirely on an idle TimedOut tick — is now implemented:
        // each slicing arm's inner re-wait loop re-arms an idle parked tick
        // without resuming, so a long-idle process pays ~1 rebuild for the
        // whole idle span instead of one per stretched tick.
        let mut parked_slice_stretch: Duration = Duration::from_secs(1);
        // Monotonic deadline for a WaitOnSleep, established on first dispatch and
        // preserved across quiesce-park re-dispatch so the sleep isn't restarted.
        let mut sleep_deadline: Option<Instant> = None;
        // Monotonic deadline for WaitOnPollFds, preserved across internal
        // readiness re-sample retries so a finite guest epoll/pidfd wait is not
        // restarted by the kqueue backstop.
        let mut poll_deadline: Option<Instant> = None;
        // One record spans the whole internally-polled HvPatch child wait.
        // Recording every 10 ms retry both perturbs the cold path and can evict
        // the child's earlier exit history from the always-on ring before a
        // post-mortem attach. Keep the selector even when register capture is
        // unavailable so the uncorrelated fallback is also emitted only once.
        let mut hvpatch_child_wait_trace: Option<(Option<i32>, Option<u32>)> = None;
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
        let sync_shared_file_aliases = engine.needs_shared_file_alias_sync();
        loop {
            if sync_shared_file_aliases && !matches!(frame.number.raw(), 260 | 95) {
                engine.sync_shared_file_aliases()?;
            }
            let request = SyscallRequest::from_raw(frame)
                .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi())
                .with_current_guest_sp(engine.get_reg(carrick_hal::Reg::Sp).ok());
            let outcome =
                dispatch_with_panic_backstop(request.number.raw(), self.this_tid, || {
                    kernel.dispatcher.dispatch_threaded(
                        &kernel_context,
                        request,
                        engine,
                        &kernel.reporter,
                        self.this_tid,
                        &self.registry,
                        &self.futex,
                    )
                })?;
            if !matches!(&outcome, DispatchOutcome::WaitOnHvpatchChild { .. }) {
                if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                    trace_hvpatch_wait_end(kernel, self.this_tid, 6, 2, 0, trace);
                }
            }
            match outcome {
                DispatchOutcome::BlockingHostWrite(mut write) => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    loop {
                        if self.fork_is_quiescing() {
                            self.release_and_park_vcpu_for_fork(engine)?;
                            continue;
                        }
                        match crate::dispatch::drive_blocking_host_write(&mut write) {
                            crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                                return Ok(raise_sigpipe_for_blocking_write(
                                    &kernel.dispatcher,
                                    &kernel_context,
                                    &write,
                                    outcome,
                                ));
                            }
                            crate::dispatch::BlockingHostWriteStep::Wait => {
                                match self.waiter.wait_with_dispatch_pending(
                                    &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                    None,
                                    carrick_abi::SigBlockMask::NONE,
                                    || {
                                        kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                            &kernel_context,
                                            self.this_tid,
                                            carrick_abi::WaitSigMask::NONE,
                                        )
                                    },
                                ) {
                                    crate::io_wait::WaitResult::Ready => continue,
                                    crate::io_wait::WaitResult::Interrupted => {
                                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                                            return Ok(outcome);
                                        }
                                        if self.fork_is_quiescing() {
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
                DispatchOutcome::BlockingRecordLock(lock) => {
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // FdBacked (conservative): the record-lock wake is a host
                    // blocking fcntl, unproven under a released VM.
                    let reclaim = self.park_vcpu_for_blocking_wait(
                        engine,
                        crate::thread::VcpuParkClass::FdBacked,
                    );
                    let outcome = crate::dispatch::drive_blocking_record_lock(&lock);
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    break Ok(outcome);
                }
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    sig_mask,
                } => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // A NON-EMPTY fd set is fd-backed (kqueue readiness wake —
                    // vetoes whole-VM release; attribution cluster B); an
                    // EMPTY set (pure signal/timeout wait, e.g. ppoll(NULL))
                    // wakes like a signal wait and is release-safe.
                    let park_class = if fds.is_empty() {
                        crate::thread::VcpuParkClass::ReleaseSafe
                    } else {
                        crate::thread::VcpuParkClass::FdBacked
                    };
                    let wait_trace =
                        trace_hvpatch_wait_begin(kernel, self.this_tid, 1, &fds, engine);
                    let reclaim = self.park_vcpu_for_timed_wait(engine, timeout, park_class);
                    let wait_result = self.waiter.wait_with_dispatch_pending(
                        &fds,
                        timeout,
                        sig_mask.block_mask(),
                        || {
                            threaded_fd_wait_should_interrupt(
                                self.fork_is_quiescing(),
                                kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                    &kernel_context,
                                    self.this_tid,
                                    sig_mask,
                                ),
                            )
                        },
                    );
                    trace_hvpatch_wait_end(
                        kernel,
                        self.this_tid,
                        1,
                        hvpatch_wait_result_phase(&wait_result),
                        fds.len(),
                        wait_trace,
                    );
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        return Ok(outcome);
                    }
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if self.fork_is_quiescing() {
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
                    sig_mask,
                    clear_on_timeout,
                } => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // fd-class rule: see the WaitOnFds arm.
                    let park_class = if fds.is_empty() {
                        crate::thread::VcpuParkClass::ReleaseSafe
                    } else {
                        crate::thread::VcpuParkClass::FdBacked
                    };
                    let wait_trace =
                        trace_hvpatch_wait_begin(kernel, self.this_tid, 2, &fds, engine);
                    let reclaim = self.park_vcpu_for_timed_wait(engine, timeout, park_class);
                    let wait_result = self.waiter.wait_with_dispatch_pending(
                        &fds,
                        timeout,
                        sig_mask.block_mask(),
                        || {
                            threaded_fd_wait_should_interrupt(
                                self.fork_is_quiescing(),
                                kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                    &kernel_context,
                                    self.this_tid,
                                    sig_mask,
                                ),
                            )
                        },
                    );
                    trace_hvpatch_wait_end(
                        kernel,
                        self.this_tid,
                        2,
                        hvpatch_wait_result_phase(&wait_result),
                        fds.len(),
                        wait_trace,
                    );
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        return Ok(outcome);
                    }
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            for (addr, len) in &clear_on_timeout {
                                let _ = engine.zero_guest_range(*addr, *len);
                            }
                            break Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if self.fork_is_quiescing() {
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
                    sig_mask,
                } => {
                    self.waiter.ensure_full();
                    let timeout = match timeout {
                        Some(duration) => {
                            let deadline =
                                *poll_deadline.get_or_insert_with(|| Instant::now() + duration);
                            let now = Instant::now();
                            if now >= deadline {
                                break Ok(DispatchOutcome::Returned { value: on_timeout });
                            }
                            Some(deadline - now)
                        }
                        None => {
                            poll_deadline = None;
                            None
                        }
                    };
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // fd-class rule: see the WaitOnFds arm. An empty poll set
                    // (ppoll(NULL) — pure signal/timeout wait, e.g.
                    // procladder_mt's pause() sibling) is release-safe.
                    let park_class = if fds.is_empty() {
                        crate::thread::VcpuParkClass::ReleaseSafe
                    } else {
                        crate::thread::VcpuParkClass::FdBacked
                    };
                    let wait_trace =
                        trace_hvpatch_wait_begin(kernel, self.this_tid, 3, &fds, engine);
                    let reclaim = self.park_vcpu_for_timed_wait(engine, timeout, park_class);
                    let wait_result = self.waiter.wait_poll_with_dispatch_pending(
                        &fds,
                        timeout,
                        sig_mask.block_mask(),
                        || {
                            threaded_fd_wait_should_interrupt(
                                self.fork_is_quiescing(),
                                kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                    &kernel_context,
                                    self.this_tid,
                                    sig_mask,
                                ),
                            )
                        },
                    );
                    trace_hvpatch_wait_end(
                        kernel,
                        self.this_tid,
                        3,
                        hvpatch_wait_result_phase(&wait_result),
                        fds.len(),
                        wait_trace,
                    );
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        return Ok(outcome);
                    }
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if self.fork_is_quiescing() {
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
                DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // FdBacked (conservative): the wake is kqueue
                    // EVFILT_PROC readiness — same kqueue-wake family as the
                    // un-root-caused fd gap (attribution cluster B).
                    let reclaim = self.park_vcpu_for_blocking_wait(
                        engine,
                        crate::thread::VcpuParkClass::FdBacked,
                    );
                    let wait_result = self.waiter.wait_proc_exit_with_dispatch_pending(
                        pid,
                        sig_mask.block_mask(),
                        || {
                            // waitpid carries WaitSigMask::Additive: its set is
                            // `non_interrupting_signal_mask` (a persistent-mask
                            // superset), so the persistent-mask union is a no-op.
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                &kernel_context,
                                self.this_tid,
                                sig_mask,
                            )
                        },
                    );
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        return Ok(outcome);
                    }
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            if self.fork_is_quiescing() {
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
                DispatchOutcome::WaitOnProcState { sig_mask, .. } => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    let reclaim = self.park_vcpu_for_blocking_wait(
                        engine,
                        crate::thread::VcpuParkClass::FdBacked,
                    );
                    let wait_result = self.waiter.wait_proc_state_with_dispatch_pending(
                        sig_mask.block_mask(),
                        || {
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                &kernel_context,
                                self.this_tid,
                                sig_mask,
                            )
                        },
                    );
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        return Ok(outcome);
                    }
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready
                        | crate::io_wait::WaitResult::TimedOut => continue,
                        crate::io_wait::WaitResult::Interrupted => {
                            if self.fork_is_quiescing() {
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
                DispatchOutcome::WaitOnHvpatchChild { target, sig_mask } => {
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    if hvpatch_child_wait_trace
                        .as_ref()
                        .is_none_or(|(traced_target, _)| *traced_target != target)
                    {
                        if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                            trace_hvpatch_wait_end(kernel, self.this_tid, 6, 2, 0, trace);
                        }
                        let trace = trace_hvpatch_wait_begin(kernel, self.this_tid, 6, &[], engine);
                        if let Some(id) = trace {
                            crate::event_ring::rec_hvpatch_wait_target(id, target);
                        }
                        hvpatch_child_wait_trace = Some((target, trace));
                    }
                    // Release this thread's vCPU slot for the duration of the
                    // guest's wait.
                    //
                    // `wait4` is an INDEFINITE guest block that merely happens
                    // to be implemented as a 10 ms poll loop, so the slice
                    // length must not decide reclaim: `park_vcpu_for_timed_wait`
                    // would consult `should_reclaim_vcpu_for_timed_wait`, see
                    // 10 ms < the 250 ms cutoff, and keep the slot forever.
                    //
                    // Holding it deadlocked the VM. The scheduler pool is TEN
                    // slots for the whole host process, shared by every guest
                    // process hvpatch multiplexes, and this arm was the only
                    // blocking outcome in this loop with no park at all. A
                    // wedged cold `go build` core showed four `wait4` threads
                    // pinning slots while awaiting children whose sibling
                    // materializers were simultaneously starving for those very
                    // slots — a closed cycle with no runnable slot holder, which
                    // is why raising the start-gate bound to 120 s produced
                    // 121 s aborts rather than passes.
                    let wait_reclaim = self.park_vcpu_for_blocking_wait(
                        engine,
                        crate::thread::VcpuParkClass::ReleaseSafe,
                    );
                    let wait_result = self.waiter.wait_with_dispatch_pending(
                        &[],
                        Some(Duration::from_millis(10)),
                        sig_mask.block_mask(),
                        || {
                            self.fork_is_quiescing()
                                || !self.registry.is_live(self.this_tid)
                                || kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                    &kernel_context,
                                    self.this_tid,
                                    sig_mask,
                                )
                        },
                    );
                    self.resume_vcpu_after_blocking_wait(engine, wait_reclaim)?;
                    if let Some(outcome) = self.exec_replaced_thread_exit() {
                        if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                            trace_hvpatch_wait_end(kernel, self.this_tid, 6, 4, 0, trace);
                        }
                        return Ok(outcome);
                    }
                    match wait_result {
                        crate::io_wait::WaitResult::TimedOut => continue,
                        crate::io_wait::WaitResult::Ready => {
                            if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                                trace_hvpatch_wait_end(kernel, self.this_tid, 6, 2, 0, trace);
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                                trace_hvpatch_wait_end(kernel, self.this_tid, 6, 4, 0, trace);
                            }
                            if self.fork_is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            if let Some((_, trace)) = hvpatch_child_wait_trace.take() {
                                trace_hvpatch_wait_end(kernel, self.this_tid, 6, 5, 0, trace);
                            }
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSignals {
                    wait_set,
                    block_mask,
                    timeout,
                } => {
                    let slice = match signal_wait_slice(&mut signal_wait_deadline, timeout) {
                        Some(slice) => slice,
                        None => {
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EAGAIN,
                            });
                        }
                    };
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // Park for reclaim-eligible waits, judged by the GUEST's
                    // overall timeout (None = indefinite sigwait), not the
                    // 50 ms service slice — otherwise signal-wait threads hold
                    // vCPU + permit + (via never becoming "parked") the whole
                    // VM forever: the sigwait-shaped procladder_mt red's
                    // silent fork-storm stall. While parked, stretch the slice
                    // to 1 s: real wakes arrive via the per-thread waiter kick
                    // (`publish_pending_for` → `wake_thread_waiter`) in
                    // microseconds; the slice is only the lost-kick safety
                    // net, and 20 park/resume VM-rebuild cycles per second per
                    // blocked thread would be pointless churn. A stretched
                    // slice may overshoot a FINITE guest deadline by up to
                    // 1 s, so only stretch when the guest wait is indefinite
                    // or has more than 1 s left, capped at the remainder (the
                    // TimedOut arm's `signal_wait_expired` bookkeeping is
                    // unchanged).
                    let guest_remaining = signal_wait_remaining(signal_wait_deadline, timeout);
                    // Signal-driven wake (the per-thread waiter pipe) —
                    // release-safe: proven to wake and rebuild with the VM
                    // released (procladder_mt's sigwait children).
                    let reclaim = self.park_vcpu_for_timed_wait(
                        engine,
                        guest_remaining,
                        crate::thread::VcpuParkClass::ReleaseSafe,
                    );
                    // Lost-kick safety net for skip-resume signal waits. A
                    // sibling can drain the xsig ring and publish a
                    // process-directed signal into dispatcher state while its
                    // own mask prevents delivery; a ring-only or host-slot-only
                    // peek then sees nothing and the sigwait thread can strand.
                    // Draining here and checking dispatcher-owned pending state
                    // lets a wait-set signal re-dispatch into
                    // `rt_sigtimedwait`, while an out-of-set caught signal
                    // still exits as EINTR. Blocked/ignored non-set signals do
                    // not return true, so the inner loop does not spin.
                    let signals_interrupt_pending = || {
                        kernel
                            .dispatcher
                            .drain_xsignals_process_directed(&kernel_context);
                        kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                            &kernel_context,
                            self.this_tid,
                            carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(
                                block_mask.raw(),
                            )),
                        ) || kernel.dispatcher.signal_wait_should_eintr(
                            &kernel_context,
                            self.this_tid,
                            wait_set,
                            block_mask,
                        )
                    };
                    // Inner re-wait loop: an idle parked TimedOut tick re-arms
                    // the wait WITHOUT the resume/re-park round trip (the
                    // "skip-resume-on-idle-TimedOut" endpoint named by the
                    // 2026-07-09 evidence doc). Every tick still: re-checks
                    // the finite guest deadline, advances the full-slice
                    // count, and may attempt the deferred whole-VM upgrade.
                    // Any non-TimedOut result (or a deadline expiry, or a
                    // non-parked wait) breaks out to the single resume below.
                    //
                    // While parked, stretch the service slice: 1 s by
                    // default; after a successful whole-VM release the
                    // progression below widens it 2s→4s→8s so a long-idle
                    // process converges to ~1 rebuild per 8 s instead of one
                    // per second. Only when the guest wait is indefinite or
                    // has >1 s left, capped at the remainder — a finite
                    // wait's final <1 s window keeps 50 ms slices (and, via
                    // the full-slice gate below, never attempts an upgrade
                    // at that rate).
                    let wait_result = loop {
                        let guest_remaining = signal_wait_remaining(signal_wait_deadline, timeout);
                        let slice_eff = match (reclaim.is_some(), guest_remaining) {
                            (true, None) => slice.max(parked_slice_stretch),
                            (true, Some(remaining)) if remaining > Duration::from_secs(1) => {
                                slice.max(parked_slice_stretch).min(remaining)
                            }
                            _ => slice,
                        };
                        let was_parked_full_slice =
                            reclaim.is_some() && slice_eff >= Duration::from_secs(1);
                        // Deferred MT whole-VM upgrade: only from the SECOND
                        // parked full slice on (≈1 s provably idle), and only
                        // when the CURRENT tick is itself a full ≥1 s slice —
                        // the first tick and any short-slice tick stay
                        // vCPU-only, so hot signal waits and finite-wait tail
                        // windows never pay the release+rebuild round trip.
                        let released = was_parked_full_slice
                            && parked_full_slices >= 1
                            && self.try_upgrade_vm_release_on_slice_tick(engine);
                        let result = self.waiter.wait_with_dispatch_pending(
                            &[],
                            Some(slice_eff),
                            block_mask,
                            signals_interrupt_pending,
                        );
                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                            return Ok(outcome);
                        }
                        match result {
                            crate::io_wait::WaitResult::TimedOut => {
                                if was_parked_full_slice {
                                    parked_full_slices = parked_full_slices.saturating_add(1);
                                    if released {
                                        // Post-release progression: 2s→4s→8s.
                                        parked_slice_stretch = (parked_slice_stretch * 2)
                                            .clamp(Duration::from_secs(2), Duration::from_secs(8));
                                    }
                                }
                                if signal_wait_expired(signal_wait_deadline) {
                                    break result; // finite deadline: resume, then EAGAIN below
                                }
                                if reclaim.is_none() {
                                    break result; // vCPU live (short-wait class): keep the old re-dispatch cadence
                                }
                                // Idle parked tick: skip the resume/re-park
                                // round trip entirely and re-arm the wait
                                // (`signals_interrupt_pending` above is the
                                // lost-kick safety net for this skip).
                                continue;
                            }
                            other => break other,
                        }
                    };
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => {
                            // Real wake: reset the post-release stretch
                            // progression. `parked_full_slices` deliberately
                            // does NOT reset — the thread already proved ≥1 s
                            // idle once within this syscall, and the upgrade
                            // stays gated on the CURRENT tick being a full
                            // slice, so a hot wait (which never completes
                            // full slices) is unaffected either way.
                            parked_slice_stretch = Duration::from_secs(1);
                            continue;
                        }
                        crate::io_wait::WaitResult::TimedOut => {
                            if signal_wait_expired(signal_wait_deadline) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EAGAIN,
                                });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            parked_slice_stretch = Duration::from_secs(1);
                            if let Some(outcome) = self.exec_replaced_thread_exit() {
                                break Ok(outcome);
                            }
                            if self.fork_is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                            }
                            if crate::fork_quiesce::exec_replacing_other_thread(self.this_tid) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EINTR,
                                });
                            }
                            // An unblocked pending signal OUTSIDE the wait set:
                            // EINTR so the loop tail delivers its handler.
                            // Re-dispatching instead would find nothing in
                            // `wait_set` and re-park forever.
                            if kernel.dispatcher.signal_wait_should_eintr(
                                &kernel_context,
                                self.this_tid,
                                wait_set,
                                block_mask,
                            ) {
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
                DispatchOutcome::WaitOnSleep {
                    duration,
                    remaining,
                } => {
                    // The fix for the multithreaded-fork deadlock: sleep via the
                    // waiter (NOT a blocking host nanosleep in the dispatcher) so
                    // a sleeping sibling reaches here, observes the fork-quiesce,
                    // and PARKS. The deadline is preserved across the park.
                    let deadline = *sleep_deadline.get_or_insert_with(|| Instant::now() + duration);
                    let now = Instant::now();
                    if now >= deadline {
                        break Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let sleep_interrupt_pending = || {
                        kernel
                            .dispatcher
                            .drain_xsignals_process_directed(&kernel_context);
                        kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                            &kernel_context,
                            self.this_tid,
                            carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::EMPTY),
                        )
                    };
                    if sleep_interrupt_pending() {
                        break Ok(crate::dispatch::complete_interrupted_sleep(
                            engine,
                            remaining,
                            deadline.saturating_duration_since(Instant::now()),
                        ));
                    }
                    self.waiter.ensure_full();
                    self.publish_process_run_state(crate::run_state::RunState::Blocked);
                    // Xsignals live in a fork-shared ring, not an fd. Bound the
                    // sleep wait at the same internal slice as `io_wait` so each
                    // slice services dispatcher-owned pending state.
                    let remaining_until_deadline = deadline - now;
                    // Timer-driven wake — release-safe.
                    let reclaim = self.park_vcpu_for_timed_wait(
                        engine,
                        Some(remaining_until_deadline),
                        crate::thread::VcpuParkClass::ReleaseSafe,
                    );
                    // Inner re-wait loop (see the WaitOnSignals arm): an idle
                    // parked TimedOut tick re-arms the wait WITHOUT the
                    // resume/re-park round trip. Every tick re-checks the
                    // sleep deadline, advances the full-slice count, and may
                    // attempt the deferred whole-VM upgrade. Any non-TimedOut
                    // result (or the deadline elapsing, or a non-parked wait)
                    // breaks out to the single resume below.
                    //
                    // While PARKED, stretch the 50 ms service slice (same
                    // capped rule + post-release 2s→4s→8s progression as the
                    // WaitOnSignals arm): interrupts arrive via the waiter
                    // kick in microseconds, and a fully-parked MT process in
                    // a long nanosleep would otherwise churn ~20 VM
                    // park/resume cycles per second. Only when >1 s remains,
                    // capped at the remainder, so the deadline check below
                    // is unaffected.
                    let wait_result = loop {
                        let now = Instant::now();
                        if now >= deadline {
                            break crate::io_wait::WaitResult::TimedOut;
                        }
                        let remaining_until_deadline = deadline - now;
                        let wait_for = if reclaim.is_some()
                            && remaining_until_deadline > Duration::from_secs(1)
                        {
                            remaining_until_deadline.min(parked_slice_stretch)
                        } else {
                            remaining_until_deadline.min(Duration::from_millis(50))
                        };
                        let was_parked_full_slice =
                            reclaim.is_some() && wait_for >= Duration::from_secs(1);
                        // Deferred MT whole-VM upgrade: second+ parked full slice
                        // only, and only when the CURRENT tick is a full slice
                        // (see the WaitOnSignals arm).
                        let released = was_parked_full_slice
                            && parked_full_slices >= 1
                            && self.try_upgrade_vm_release_on_slice_tick(engine);
                        let result = self.waiter.wait_with_dispatch_pending(
                            &[],
                            Some(wait_for),
                            carrick_abi::SigBlockMask::NONE,
                            sleep_interrupt_pending,
                        );
                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                            return Ok(outcome);
                        }
                        match result {
                            crate::io_wait::WaitResult::TimedOut => {
                                if was_parked_full_slice {
                                    parked_full_slices = parked_full_slices.saturating_add(1);
                                    if released {
                                        parked_slice_stretch = (parked_slice_stretch * 2)
                                            .clamp(Duration::from_secs(2), Duration::from_secs(8));
                                    }
                                }
                                if Instant::now() >= deadline {
                                    break result; // deadline elapsed: resume, then Returned{0} below
                                }
                                if reclaim.is_none() {
                                    break result; // vCPU live (short-wait class): keep the old 50 ms cadence
                                }
                                // Idle parked tick: skip the resume/re-park
                                // round trip entirely and re-arm the wait.
                                continue;
                            }
                            other => break other,
                        }
                    };
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
                        crate::io_wait::WaitResult::Ready => {
                            parked_slice_stretch = Duration::from_secs(1);
                            continue;
                        }
                        crate::io_wait::WaitResult::TimedOut => {
                            if Instant::now() >= deadline {
                                break Ok(DispatchOutcome::Returned { value: 0 });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            parked_slice_stretch = Duration::from_secs(1);
                            if self.fork_is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(crate::dispatch::complete_interrupted_sleep(
                                engine,
                                remaining,
                                deadline.saturating_duration_since(Instant::now()),
                            ));
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSharedWord {
                    location,
                    waiter_key,
                    value,
                } => match self.wait_on_shared_word(engine, location, waiter_key, value)? {
                    SharedWordWaitCompletion::Changed => continue,
                    SharedWordWaitCompletion::Interrupted => {
                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                            break Ok(outcome);
                        }
                        if self.fork_is_quiescing() {
                            self.release_and_park_vcpu_for_fork(engine)?;
                            continue;
                        }
                        break Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    SharedWordWaitCompletion::ExecReplacedThread => {
                        break Ok(DispatchOutcome::ThreadExit { code: 0 });
                    }
                },
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
                    let Some(install) = transaction.claim() else {
                        drop(file);
                        break Ok(DispatchOutcome::Returned {
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
                        break Ok(DispatchOutcome::Returned {
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
                        prot & crate::linux_abi::LINUX_PROT_WRITE == 0,
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
                    break Ok(DispatchOutcome::Returned {
                        value: success_retval,
                    });
                }
                other => break Ok(other),
            }
        }
    }

    pub(super) fn complete_returned(
        &self,
        engine: &mut E,
        value: i64,
    ) -> Result<i64, RuntimeError> {
        engine.complete_syscall(value)?;
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
    linux_tid: crate::kernel::LinuxTid,
    this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    kicker: Arc<dyn VcpuRegistry>,
    max_traps: usize,
) -> Result<VcpuLoopOutcome, RuntimeError>
where
    E::SiblingSpec: 'static,
{
    // This must wrap the whole run, not only clone-thread closures: an
    // hvpatch process leader may begin without a lease, park, acquire one on
    // wake, and then exit.  Before this guard those late leases leaked until
    // the global pool was exhausted during a cold Go build.
    let _vcpu_lease_guard = VcpuLeaseGuard;
    let _process_vcpu_live_guard = kernel.hvpatch_process.as_ref().map(|_| {
        kernel
            .process_vcpu_live
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ProcessVcpuLiveGuard(&kernel.process_vcpu_live)
    });
    let kernel_thread = if kernel.hvpatch_process.is_some() {
        Some(Arc::clone(
            kernel
                .dispatcher
                .capture_kernel_context(linux_tid)
                .map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "bind HVPatch crash-register authority: {error}"
                    ))
                })?
                .thread(),
        ))
    } else {
        None
    };
    let mut state = ThreadRuntimeState::new(
        registry,
        futex,
        platform_futex,
        platform_futex_factory,
        kernel.process_fork_barrier.clone(),
        kernel.crash_capture_generation.clone(),
        kernel_thread,
        kernel.hvpatch_process.as_ref().map(|process| process.pid()),
        linux_tid,
        kernel.fatal_signal.current_generation(),
        this_tid,
        threads,
        kicker,
        max_traps,
    );
    if let Some(process) = kernel.hvpatch_process.as_ref() {
        let context = kernel
            .dispatcher
            .capture_kernel_context(state.linux_tid)
            .map_err(|error| {
                RuntimeError::Configuration(format!("bind HVPatch frame-COW authority: {error}"))
            })?;
        let binding = process.mm_binding().ok_or_else(|| {
            RuntimeError::Configuration("HVPatch task has no mm binding for frame COW".to_owned())
        })?;
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: process.pid(),
            linux_tid: state.this_tid.raw(),
            mm: context.shared().mm().id().raw(),
            asid: binding.asid.raw(),
        };
        let authority: Arc<dyn carrick_hal::FrameCowAuthority> =
            Arc::new(KernelFrameCowAuthority {
                kernel: Arc::clone(context.kernel()),
                mm: context.shared().mm().id(),
                kicker: Arc::clone(&state.kicker),
                tid: state.this_tid,
            });
        engine.bind_frame_cow(authority, identity);
    }
    state.register_vcpu(&engine);
    // Stamp this thread's tid into TPIDR_EL1 for the EL1 gettid fast path (main
    // thread at boot; each worker at spawn). Re-stamped after fork/exec below.
    stamp_guest_tid(
        &engine,
        state.this_tid,
        &state.registry,
        kernel.hvpatch_process.as_ref().map(|_| state.linux_tid),
    );
    // Run the vCPU loop in a closure so we can run vCPU cleanup on EVERY exit
    // path — `?` errors, early returns, and the trap-limit fall-through alike.
    let mut result: Result<VcpuLoopOutcome, RuntimeError> = (|| {
        // Progress-aware trap watchdog: bound the traps SINCE THE LAST DELIVERED
        // SIGNAL HANDLER, not the lifetime total. A guest legitimately spinning
        // while it waits for a signal (CPython test_io's reentrant-write tests
        // busy-loop ~1s for a SIGALRM, ~600k syscalls per cycle) is responsive,
        // not hung — each handler delivery resets the budget. A genuinely stuck
        // guest delivers no handlers and still trips the limit.
        let mut budget_floor = 0usize;
        let mut seen_signal_progress = signal_progress_count();
        let mut last_progress = std::time::Instant::now();
        let max_wall = trap_watchdog_wall_window();
        // Retain the just-completed syscall value until the vCPU actually
        // leaves Carrick's EL1 return trampoline. A durable task wake can be
        // observed in that host-side interval; signal injection must then use
        // the saved EL0 resume pair, exactly like the ordinary post-syscall
        // boundary, rather than treating the live EL1 `eret` PC as guest code.
        let mut guest_entry_syscall_retval: Option<i64> = None;
        for traps in 1.. {
            let progress = signal_progress_count();
            if progress != seen_signal_progress {
                seen_signal_progress = progress;
                budget_floor = traps - 1;
                last_progress = std::time::Instant::now();
            }
            if traps - budget_floor > state.max_traps {
                // `max_traps` is now a cheap pre-filter interval, NOT a hard
                // ceiling: tripping it means the guest issued that many syscalls
                // since the last delivered signal handler. That is not a hang if
                // it is still doing real work — a syscall-bound loop bounded by a
                // SIGALRM (LTP gettimeofday02 issues ~1M raw __NR_gettimeofday in a
                // 10s alarm window) makes forward progress, and the conformance
                // harness already wraps every run in an outer wall-clock timeout.
                // Abort ONLY if there has been NO wall-clock progress (no delivered
                // handler) for `max_wall` — a genuinely wedged guest; otherwise
                // reset the count budget and keep running. `last_progress` is
                // re-sampled rarely (handler delivery + this pre-filter), so the
                // hot per-syscall path takes no Instant::now(). The outer count
                // guard guarantees we are past the pre-filter, so the decision is
                // only ever `Trip` or `ResetBudget` here.
                match trap_watchdog_decision(
                    traps - budget_floor,
                    state.max_traps,
                    last_progress.elapsed(),
                    max_wall,
                ) {
                    TrapWatchdog::Trip => break,
                    TrapWatchdog::ResetBudget => budget_floor = traps,
                    TrapWatchdog::KeepRunning => {}
                }
            }
            if thread_should_finish_for_exec_replacement(&state.registry, state.this_tid) {
                state.trace_hvpatch_thread_terminal(
                    carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAtLoopTop,
                    i32::from(!state.registry.is_live(state.this_tid)),
                );
                return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
            }
            // HVPatch hosts every Linux task as threads of one Darwin process,
            // so guest job control must park only this kernel task. SIGCONT or
            // SIGKILL clears the task state and notifies this wait before its
            // pending action is delivered.
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                if process.wait_until_job_control_resumed() {
                    // A ptrace resume may inject a signal (PTRACE_KILL is
                    // SIGKILL). Service it before re-entering the guest: the
                    // instruction after the stopped syscall may itself be
                    // exit_group, and Linux guarantees the injected fatal
                    // action wins that race.
                    let signal_context =
                        state.service_kernel_context.as_ref().ok_or_else(|| {
                            RuntimeError::Configuration(
                                "HVPatch resume lost its exact Kernel context".to_owned(),
                            )
                        })?;
                    let interrupted_pc = engine.current_pc()?;
                    if let Some(outcome) = service_signals_threaded(
                        &kernel,
                        signal_context,
                        &mut engine,
                        state.this_tid,
                        state.fatal_image_generation,
                        None,
                        Some(interrupted_pc),
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                }
            }
            // Lock-safe point: no carrick lock is held here. If another thread is
            // forking a multithreaded guest, release this vCPU (so the forker can
            // hv_vm_destroy), park until the fork completes, then recreate the vCPU
            // in the parent's rebuilt VM and resume.
            if state.fork_is_quiescing() {
                state.release_and_park_vcpu_for_fork(&mut engine)?;
            }
            // Page-table-edit Pause-Modify-Resume: if a sibling vCPU is editing the
            // shared stage-1 tables from the host, park here (KEEPING this vCPU —
            // unlike fork) until it finishes.
            if pt_barrier().is_quiescing() {
                pt_barrier().park();
            }
            // A lane wake has a durable Kernel generation as well as its
            // immediate host kick. Reconcile it before guest entry: a child can
            // publish SIGCHLD after the post-syscall drain but while this vCPU
            // is still host-side, and a reclaimed vCPU may have no registered
            // kick handle at all. `hv_vcpus_exit` remains the prompt path once
            // guest execution begins; this branch runs only when a new wake is
            // observed, not on the steady-state entry path.
            if state.hvpatch_task_pid.is_some()
                && let Some(signal_context) = state.service_kernel_context.as_ref()
            {
                let wake_generation = signal_context.task().wake_generation();
                if wake_generation != state.observed_task_wake_generation {
                    let signal_progress_before = signal_progress_count();
                    if let Some(outcome) = service_signals_threaded(
                        &kernel,
                        signal_context,
                        &mut engine,
                        state.this_tid,
                        state.fatal_image_generation,
                        guest_entry_syscall_retval,
                        None,
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                    if signal_progress_count() != signal_progress_before {
                        // A handler frame is now the live resume boundary. If a
                        // second publication raced this drain, its nested frame
                        // must preserve the first handler's x0, not reapply the
                        // syscall return value underneath it.
                        guest_entry_syscall_retval = None;
                    }
                    state.observed_task_wake_generation = wake_generation;
                    // Re-read on the next iteration. A second publication may
                    // have raced this drain; acknowledging only the generation
                    // captured before it ensures that edge is not hidden.
                    continue;
                }
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
            // Publish that this guest is RUNNING (executing guest code). This is
            // the single point that means "guest code is live now": it clears the
            // post-fork `Booting` state and any prior `Blocked`, so a sibling's
            // /proc/<pid>/stat reads `R`. A genuine guest-blocking wait re-publishes
            // `Blocked` below for the duration of the park (see `block_guard`).
            state.publish_thread_run_state(crate::run_state::RunState::Running, 'R');
            let next = engine.next_syscall();
            // Any exit surfaced by the engine is past its internal EL1-vector
            // kick swallow: either guest EL0 ran or a real guest boundary was
            // reached. The prior syscall resume pair is no longer live.
            guest_entry_syscall_retval = None;
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
                    let signal_context = kernel
                        .dispatcher
                        .capture_kernel_context(state.linux_tid)
                        .map_err(|error| {
                            RuntimeError::Configuration(format!(
                                "capture forced-exit signal context: {error}"
                            ))
                        })?;
                    if let Some(outcome) = service_signals_threaded(
                        &kernel,
                        &signal_context,
                        &mut engine,
                        state.this_tid,
                        state.fatal_image_generation,
                        None,
                        Some(pc),
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                    continue;
                }
                Err(TrapError::Stage1CowFault {
                    syndrome,
                    far,
                    elr,
                    spsr,
                }) => {
                    // The engine's single COW resolver emits the exact TTBR +
                    // descriptor pair immediately before its typed trigger.
                    // Do not duplicate that pair here: the structural consumer
                    // joins and consumes one sequence per attempted fault.
                    if engine.resolve_frame_cow_fault(syndrome, far)? {
                        continue;
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
                    if engine.resolve_frame_cow_fault(syndrome, far)? {
                        continue;
                    }
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
                    let fault_x0 = engine.get_reg(carrick_hal::Reg::X(0)).unwrap_or(0);
                    crate::probes::vcpu_fault_gprs(
                        fault_x0,
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
                    if let Some(process) = kernel.hvpatch_process.as_ref() {
                        process.trace_fault(syndrome, elr, far, state.this_tid);
                    }
                    // A synchronous guest EL0 fault (nil deref, bad access, BRK,
                    // single-step). Lower the raw aarch64 ESR to the ISA-neutral
                    // (signum, si_code, fault_addr) triple — covering BOTH the
                    // abort classes (SIGSEGV/SIGBUS) AND the debug classes
                    // (BRK/single-step → SIGTRAP) — then deliver via the shared
                    // GuestFault path. `from_el0_direct` selects whether the
                    // sigframe records the faulting PC as the resume target.
                    if let Some((signum, si_code, si_addr)) = lower_el0_fault(syndrome, elr, far) {
                        if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                            let base = (base_register < 31)
                                .then(|| format!("x{base_register}={base_value:#x}"));
                            let regs: Vec<_> = (0..=12)
                                .map(|index| {
                                    engine.get_reg(carrick_hal::Reg::X(index)).map_or_else(
                                        |_| "?".to_owned(),
                                        |value| format!("{value:#x}"),
                                    )
                                })
                                .collect();
                            eprintln!(
                                "[FAULTDBG tid={:?}] classified EL0 fault esr={syndrome:#x} ec={:#x} elr={elr:#x} far={far:#x} direct={from_el0_direct} last_syscall={:?} insn={instruction:?} base={base:?} x0..x12={regs:?}",
                                state.this_tid,
                                (syndrome >> 26) & 0x3f,
                                engine.last_syscall_nr()
                            );
                        }
                        // Raw hardware/host faults can decode as MAPERR even
                        // when Carrick tracks a live VMA denying the access.
                        // Upgrade from the shared protection metadata (LTP
                        // mmap05 / roprotect probe).
                        let si_code =
                            signal::upgrade_protection_si_code(&engine, signum, si_code, si_addr);
                        let interrupted_pc = if from_el0_direct { Some(elr) } else { None };
                        let fault_context = kernel
                            .dispatcher
                            .capture_kernel_context(state.linux_tid)
                            .map_err(|error| {
                                RuntimeError::Configuration(format!(
                                    "capture synchronous-fault signal context: {error}"
                                ))
                            })?;
                        if let Some(outcome) = deliver_fault_signal(
                            &kernel,
                            &fault_context,
                            &mut engine,
                            state.this_tid,
                            state.fatal_image_generation,
                            signum,
                            si_code,
                            si_addr,
                            interrupted_pc,
                            traps,
                        )? {
                            return Ok(outcome);
                        }
                    } else {
                        // Unclassified EL0 fault: Linux forces the default action
                        // (terminate by SIGSEGV).
                        if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                            eprintln!(
                                "[FAULTDBG tid={:?}] UNCLASSIFIED EL0 fault esr={syndrome:#x} ec={:#x} elr={elr:#x} far={far:#x} -> SIGSEGV terminate",
                                state.this_tid,
                                (syndrome >> 26) & 0x3f
                            );
                        }
                        if requires_no_unwind_host_exit(&kernel, engine.is_forked_child()) {
                            let out = kernel.dispatcher.stdout();
                            let err = kernel.dispatcher.stderr();
                            kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                            forked_child_die_by_signal(11, &out, &err);
                        }
                        kernel.record_fatal_signal(FatalSignalRecord {
                            image_generation: state.fatal_image_generation,
                            tid: state.linux_tid,
                            signo: crate::linux_abi::LINUX_SIGSEGV,
                            code: 0,
                            addr: far,
                        });
                        let result = assemble_run_result(
                            &kernel,
                            128 + 11,
                            Some(crate::linux_abi::LINUX_SIGSEGV),
                            traps,
                            false,
                        );
                        return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                    }
                    continue;
                }
                Err(TrapError::GuestFault {
                    signum,
                    si_code,
                    fault_addr,
                }) => {
                    // The ISA-neutral structured fault path: an x86 backend emits
                    // this directly (fault_addr = CR2). The backend restores the
                    // interrupted user context before surfacing the fault, so the
                    // live PC is the faulting instruction, not a syscall-return
                    // RCX path.
                    // A backend can surface MAPERR even when Carrick tracks a
                    // live VMA denying the access. Upgrade from the shared
                    // protection metadata (LTP mmap05 / roprotect probe).
                    let si_code =
                        signal::upgrade_protection_si_code(&engine, signum, si_code, fault_addr);
                    let interrupted_pc = Some(engine.current_pc()?);
                    let fault_context = kernel
                        .dispatcher
                        .capture_kernel_context(state.linux_tid)
                        .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture guest-fault signal context: {error}"
                        ))
                    })?;
                    if let Some(outcome) = deliver_fault_signal(
                        &kernel,
                        &fault_context,
                        &mut engine,
                        state.this_tid,
                        state.fatal_image_generation,
                        signum,
                        si_code,
                        fault_addr,
                        interrupted_pc,
                        traps,
                    )? {
                        return Ok(outcome);
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            state.trace_syscall(traps, frame);

            let _hvpatch_syscall_service = kernel
                .hvpatch_process
                .as_ref()
                .and_then(crate::hvpatch::ProcessContext::syscall_trace_identity)
                .and_then(|(pid, asid)| {
                    HvpatchSyscallServiceGuard::begin(
                        pid,
                        state.this_tid.raw(),
                        asid,
                        frame.number.raw(),
                        frame.args,
                    )
                });

            // ---- syscall service: no dispatcher-wide lock held ----
            let outcome = state.service_threaded_syscall(&kernel, &mut engine, frame)?;

            let mut last_syscall_retval: Option<i64> = None;
            let mut signal_interrupted_pc: Option<u64> = None;

            match outcome {
                DispatchOutcome::WaitOnFds { .. }
                | DispatchOutcome::BlockingHostWrite(_)
                | DispatchOutcome::BlockingRecordLock(_)
                | DispatchOutcome::WaitOnFdsSelect { .. }
                | DispatchOutcome::WaitOnPollFds { .. }
                | DispatchOutcome::WaitOnProcExit { .. }
                | DispatchOutcome::WaitOnProcState { .. }
                | DispatchOutcome::WaitOnHvpatchChild { .. }
                | DispatchOutcome::WaitOnSignals { .. }
                | DispatchOutcome::WaitOnSleep { .. } => {
                    last_syscall_retval =
                        Some(state.complete_errno(&mut engine, crate::linux_abi::LINUX_EINTR)?);
                }
                DispatchOutcome::Exit { code } => {
                    if code != 0 && std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                        eprintln!(
                            "[FAULTDBG tid={}] guest requested process exit code={code}",
                            state.this_tid.raw()
                        );
                    }
                    tracing::trace!(
                        tid = state.this_tid.raw(),
                        code,
                        "guest requested process exit"
                    );
                    crate::trap::dump_kick_stats();
                    // Mature real-fork children keep the historical no-unwind
                    // `_exit` path. A namespace-forked HVPatch root was created
                    // after that fork, so it returns through typed process
                    // teardown and publishes the complete VM ledger instead.
                    if requires_no_unwind_host_exit(&kernel, engine.is_forked_child()) {
                        crate::probes::guest_exit(code);
                        engine.process_exit_cleanup()?;
                        kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                        forked_child_exit(
                            code,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    // exit_group, or exit(2) as the last live thread. Tear the whole
                    // process down.
                    let last = if kernel.is_hvpatch_child()
                        || kernel.dispatcher.execution_backend()
                            == crate::page_profile::ExecutionBackend::HvPatch
                    {
                        // HVPatch process cleanup first drains every sibling
                        // vCPU, then removes this owner and unmaps its bank.
                        // Removing the owner here would permit a second retire.
                        true
                    } else {
                        state.registry.exit(state.this_tid)
                    };
                    if !last {
                        // exit_group(94) or fatal process termination: flush shared
                        // buffers and terminate the entire host process.
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        let out = kernel.dispatcher.stdout();
                        let err = kernel.dispatcher.stderr();
                        let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                        let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                        kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                        unsafe { libc::_exit(code) };
                    }
                    let result = assemble_run_result(&kernel, code, None, traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
                DispatchOutcome::SignalDeath { signum } => {
                    if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
                        eprintln!(
                            "[FAULTDBG tid={}] guest process terminated by signal={signum}",
                            state.this_tid.raw()
                        );
                    }
                    tracing::trace!(
                        tid = state.this_tid.raw(),
                        signum,
                        "guest process terminated by signal"
                    );
                    crate::trap::dump_kick_stats();
                    if requires_no_unwind_host_exit(&kernel, engine.is_forked_child()) {
                        engine.process_exit_cleanup()?;
                        kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                        forked_child_die_by_signal(
                            signum,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    let code = 128 + signum;
                    let last = if kernel.is_hvpatch_child()
                        || kernel.dispatcher.execution_backend()
                            == crate::page_profile::ExecutionBackend::HvPatch
                    {
                        true
                    } else {
                        state.registry.exit(state.this_tid)
                    };
                    if !last {
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        let out = kernel.dispatcher.stdout();
                        let err = kernel.dispatcher.stderr();
                        let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                        let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                        kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                        unsafe { libc::_exit(code) };
                    }
                    kernel.record_fatal_signal(FatalSignalRecord {
                        image_generation: state.fatal_image_generation,
                        tid: state.linux_tid,
                        signo: signum,
                        code: 0,
                        addr: 0,
                    });
                    let result = assemble_run_result(&kernel, code, Some(signum), traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
                DispatchOutcome::Returned { value } => {
                    last_syscall_retval = Some(state.complete_returned(&mut engine, value)?);
                }
                DispatchOutcome::SchedulerYield => {
                    // Preserve Linux's runnable-thread semantics under a
                    // bounded M:N backend: surrender the scarce vCPU lease to
                    // an already-queued guest before competing to reacquire it.
                    // `park_vcpu_for_blocking_wait` is a no-op for unbounded
                    // backends, retaining their historical host-only yield.
                    let reclaim = state.park_vcpu_for_blocking_wait(
                        &mut engine,
                        crate::thread::VcpuParkClass::ReleaseSafe,
                    );
                    std::thread::yield_now();
                    state.resume_vcpu_after_blocking_wait(&mut engine, reclaim)?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, 0)?);
                }
                DispatchOutcome::Errno { errno } => {
                    last_syscall_retval = Some(state.complete_errno(&mut engine, errno)?);
                }
                DispatchOutcome::FutexWait { wait, timeout } => {
                    // Block with the dispatcher lock RELEASED so a sibling FUTEX_WAKE
                    // can run.
                    match state.complete_futex_wait(&kernel, &mut engine, wait, timeout)? {
                        BlockingWaitCompletion::Retval(retval) => {
                            last_syscall_retval = Some(retval);
                        }
                        BlockingWaitCompletion::ExecReplacedThread => {
                            state.trace_hvpatch_thread_terminal(
                                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAfterBlockingWait,
                                i32::from(!state.registry.is_live(state.this_tid)),
                            );
                            return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
                        }
                    }
                }
                DispatchOutcome::FutexWaitv {
                    wait,
                    timeout,
                    index,
                } => {
                    match state.complete_futex_waitv(&kernel, &mut engine, wait, timeout, index)? {
                        BlockingWaitCompletion::Retval(retval) => {
                            last_syscall_retval = Some(retval);
                        }
                        BlockingWaitCompletion::ExecReplacedThread => {
                            state.trace_hvpatch_thread_terminal(
                                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAfterBlockingWait,
                                i32::from(!state.registry.is_live(state.this_tid)),
                            );
                            return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
                        }
                    }
                }
                DispatchOutcome::SharedFutexWait {
                    location,
                    waiter_key,
                    value,
                    timeout,
                } => {
                    // Cross-process futex (MAP_SHARED): block on the host __ulock
                    // keyed by the shared physical page, with the dispatcher lock
                    // released. Interruptible by a signal deliverable to this thread.
                    match state.complete_shared_futex_wait(
                        &mut engine,
                        location,
                        waiter_key,
                        value,
                        timeout,
                    )? {
                        BlockingWaitCompletion::Retval(retval) => {
                            last_syscall_retval = Some(retval);
                        }
                        BlockingWaitCompletion::ExecReplacedThread => {
                            state.trace_hvpatch_thread_terminal(
                                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAfterBlockingWait,
                                i32::from(!state.registry.is_live(state.this_tid)),
                            );
                            return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
                        }
                    }
                }
                DispatchOutcome::SharedFutexWaitv {
                    location,
                    waiter_key,
                    value,
                    timeout,
                    index,
                } => {
                    match state.complete_shared_futex_waitv(
                        &mut engine,
                        location,
                        waiter_key,
                        value,
                        timeout,
                        index,
                    )? {
                        BlockingWaitCompletion::Retval(retval) => {
                            last_syscall_retval = Some(retval);
                        }
                        BlockingWaitCompletion::ExecReplacedThread => {
                            state.trace_hvpatch_thread_terminal(
                                carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAfterBlockingWait,
                                i32::from(!state.registry.is_live(state.this_tid)),
                            );
                            return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
                        }
                    }
                }
                DispatchOutcome::SharedFutexWake {
                    location,
                    waiter_key,
                    count,
                } => {
                    // Cross-process futex wake (MAP_SHARED): route through the
                    // SAME `PlatformFutex` the wait side uses so the wake reaches
                    // a waiter parked in another carrick process. Non-blocking, so
                    // we complete the syscall inline with the count woken (clamped
                    // to non-negative; a negative kernel return surfaces as 0
                    // woken, matching the prior inline ulock loop's `break`).
                    let woke = state
                        .platform_futex
                        .shared_wake(location, waiter_key, count);
                    last_syscall_retval = Some(state.complete_returned(&mut engine, woke.max(0))?);
                }
                DispatchOutcome::SharedFutexRequeue {
                    from,
                    from_key,
                    to,
                    to_key,
                    wake,
                    requeue,
                } => {
                    let (woken, requeued) = state
                        .platform_futex
                        .shared_requeue(from, from_key, to, to_key, wake, requeue);
                    last_syscall_retval =
                        Some(state.complete_returned(&mut engine, i64::from(woken + requeued))?);
                }
                DispatchOutcome::WaitOnSharedWord {
                    location: _,
                    waiter_key: _,
                    value: _,
                } => {
                    return Err(RuntimeError::Unsupported(
                        "WaitOnSharedWord escaped threaded syscall service".to_string(),
                    ));
                }
                DispatchOutcome::CloneThread {
                    stack,
                    tls,
                    flags,
                    parent_tid_addr,
                    child_tid_addr,
                    clear_child_tid_addr,
                } => {
                    let kernel_context = state
                        .service_kernel_context
                        .as_ref()
                        .ok_or_else(|| {
                            RuntimeError::Configuration(
                                "clone-thread lost its exact Kernel context".to_owned(),
                            )
                        })?
                        .retain_exact();
                    let tid = state.spawn_clone_thread(
                        &kernel,
                        &kernel_context,
                        &mut engine,
                        stack,
                        tls,
                        flags,
                        parent_tid_addr,
                        child_tid_addr,
                        clear_child_tid_addr,
                    )?;
                    let (completed_tid, completed_errno) = match tid {
                        threads::CloneThreadSpawn::Started(tid) => {
                            state.complete_returned(&mut engine, i64::from(tid.raw()))?;
                            (tid.raw(), 0)
                        }
                        threads::CloneThreadSpawn::Errno(errno) => {
                            state.complete_returned(&mut engine, errno.guest_retval())?;
                            (state.this_tid.raw(), errno.get())
                        }
                    };
                    crate::probes::mn_clone_outcome(
                        completed_tid,
                        carrick_observability::probes::HvpatchCloneThreadPhase::Completed,
                        completed_errno,
                    );
                }
                DispatchOutcome::ThreadExit { code } => {
                    let reason = if frame.number.raw() == 93 {
                        carrick_observability::probes::HvpatchThreadTerminalReason::GuestThreadExit
                    } else {
                        carrick_observability::probes::HvpatchThreadTerminalReason::ExecRegistryGoneAfterBlockingWait
                    };
                    state.trace_hvpatch_thread_terminal(reason, code);
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
                    let kernel_context = state
                        .service_kernel_context
                        .as_ref()
                        .ok_or_else(|| {
                            RuntimeError::Configuration(
                                "execve lost its exact Kernel context".to_owned(),
                            )
                        })?
                        .retain_exact();
                    // `Some` means the exec failed past its point of no return
                    // and this Linux process is terminating; it must NOT be
                    // discarded, or the loop would run on with a destroyed
                    // thread group.
                    if let Some(outcome) = state.handle_execve(
                        &kernel,
                        &kernel_context,
                        &mut engine,
                        path,
                        argv,
                        env,
                    )? {
                        return Ok(outcome);
                    }
                }
                DispatchOutcome::SigReturn => {
                    let restored_sigmask = match engine.restore_from_sigframe() {
                        Ok(mask) => mask,
                        // A guest-reachable bad rt_sigreturn frame (bad SP, or a
                        // corrupt/forged frame) is force_sigsegv on Linux: kill
                        // THIS process by SIGSEGV (exit 139), never abort the whole
                        // carrick runtime. Mirrors the unclassified-EL0-fault path.
                        Err(TrapError::SignalDeliveryFault) => {
                            if requires_no_unwind_host_exit(&kernel, engine.is_forked_child()) {
                                let out = kernel.dispatcher.stdout();
                                let err = kernel.dispatcher.stderr();
                                kernel.dispatcher.cleanup_sysv_ipc_on_process_exit();
                                forked_child_die_by_signal(11, &out, &err);
                            }
                            let result = assemble_run_result(
                                &kernel,
                                128 + 11,
                                Some(crate::linux_abi::LINUX_SIGSEGV),
                                traps,
                                false,
                            );
                            return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                        }
                        Err(e) => return Err(e.into()),
                    };
                    let signal_context =
                        state.service_kernel_context.as_ref().ok_or_else(|| {
                            RuntimeError::Configuration(
                                "sigreturn lost its exact Kernel context".to_owned(),
                            )
                        })?;
                    kernel.dispatcher.restore_signal_mask(
                        signal_context,
                        state.this_tid,
                        carrick_abi::SigSet::from_raw(restored_sigmask),
                    );
                    // Deliver the next pending signal (if any) before resuming,
                    // but at the just-restored user PC, not as another
                    // syscall-boundary signal. On x86, `rt_sigreturn` restores
                    // RCX as an ordinary caller-clobbered register; treating this
                    // as a syscall boundary would use that RCX as the resume RIP.
                    signal_interrupted_pc = Some(engine.current_pc()?);
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
                } => {
                    let kernel_context = state
                        .service_kernel_context
                        .as_ref()
                        .ok_or_else(|| {
                            RuntimeError::Configuration(
                                "fork lost its exact Kernel context".to_owned(),
                            )
                        })?
                        .retain_exact();
                    match state.handle_fork(
                        &kernel,
                        &kernel_context,
                        &mut engine,
                        quiesce::ForkRequest {
                            flags,
                            pidfd_out,
                            clone_parent,
                            parent_tid_addr,
                            child_tid_addr,
                            exit_signal,
                            child_stack,
                            vfork,
                        },
                    )? {
                        Some(retval) => {
                            last_syscall_retval =
                                Some(state.complete_returned(&mut engine, retval)?);
                        }
                        None => {
                            state.trace_hvpatch_thread_terminal(
                                carrick_observability::probes::HvpatchThreadTerminalReason::VforkParentTerminalCancellation,
                                0,
                            );
                            return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
                        }
                    }
                }
                DispatchOutcome::SetMemoryModel { tso } => {
                    // Rosetta requested hardware x86_64 TSO on this vCPU.
                    engine.set_memory_model(hardware_tso_for_debug(tso))?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, 0)?);
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
                } => {
                    let file = file.map(|(fd, offset, prot)| (fd.into_owned_fd(), offset, prot));
                    let retval = match transaction.claim() {
                        None => {
                            drop(file);
                            crate::linux_abi::LINUX_ENOMEM.guest_retval()
                        }
                        Some(install) => 'install: {
                            if let Err(error) = engine.map_host_alias_with_sharing(
                                va,
                                ipa,
                                len,
                                &payload,
                                file.map(|(fd, offset, prot)| (fd.into_raw_fd(), offset, prot)),
                                shared,
                            ) {
                                // Same guest-argument-reachable class as the
                                // HVPatch arm above: a failed backend alias
                                // install (arena exhaustion, a rejected GPA, a
                                // failed host mmap) is an out-of-memory answer
                                // to one guest `mmap`, not an invariant
                                // violation, so it lowers to ENOMEM. `install`
                                // drops unclaimed, which aborts the
                                // dispatcher's pending VMA commit and wakes
                                // blocked sibling mapping syscalls.
                                drop(install);
                                tracing::error!(
                                    va = format_args!("{:#x}", va.raw()),
                                    len = format_args!("{len:#x}"),
                                    shared,
                                    %error,
                                    "alias install failed; guest mmap lowered to ENOMEM"
                                );
                                break 'install crate::linux_abi::LINUX_ENOMEM.guest_retval();
                            }
                            let Ok(len) = usize::try_from(len) else {
                                std::process::abort();
                            };
                            if prot_none && engine.protect_range(va.raw(), len, 0).is_err() {
                                std::process::abort();
                            }
                            // The backend install and requested leaf protection
                            // are live. Atomically publish the dispatcher's full
                            // Linux protection + sharing classification before
                            // any sibling or the current vCPU can resume.
                            engine.set_mapping_protection_and_sharing(
                                va.raw(),
                                len,
                                prot_none,
                                prot & crate::linux_abi::LINUX_PROT_WRITE == 0,
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
                            success_retval
                        }
                    };
                    last_syscall_retval = Some(state.complete_returned(&mut engine, retval)?);
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
            let signal_context = state.service_kernel_context.as_ref().ok_or_else(|| {
                RuntimeError::Configuration(
                    "post-syscall signal delivery lost its exact Kernel context".to_owned(),
                )
            })?;
            if let Some(outcome) = service_signals_threaded(
                &kernel,
                signal_context,
                &mut engine,
                state.this_tid,
                state.fatal_image_generation,
                last_syscall_retval,
                signal_interrupted_pc,
                traps,
            )? {
                return Ok(outcome);
            }
            guest_entry_syscall_retval = last_syscall_retval;
        }

        let result = assemble_run_result(&kernel, -1, None, state.max_traps, true);
        Ok(VcpuLoopOutcome::TrapLimit(Box::new(result)))
    })();
    // Every terminal HVPatch process transition (root or in-process child)
    // has one owner and one ordering point. Output and process-fd lifetime are
    // finalized before Linux exit publication; only after the zombie/pidfd and
    // current-parent signal are visible may the owner retire backend mappings,
    // bank, ASID, and current vCPU under the global topology lock.
    let terminal_hvpatch_process = kernel.dispatcher.execution_backend()
        == crate::page_profile::ExecutionBackend::HvPatch
        && matches!(
            &result,
            Ok(VcpuLoopOutcome::ProcessExit(_) | VcpuLoopOutcome::TrapLimit(_)) | Err(_)
        );
    let mut vcpu_retired_by_hvpatch_cleanup = false;
    if terminal_hvpatch_process {
        if let Err(error) = &result {
            tracing::error!(%error, "terminal HVPatch vCPU loop failure");
        }
        let exit_claim = match kernel.claim_process_exit() {
            Ok(claim) => claim,
            Err(error) => {
                tracing::error!(%error, "terminal owner could not close clone admission");
                std::process::abort();
            }
        };
        if exit_claim == ProcessExitClaim::Owner {
            let published_exit_code = match &result {
                Ok(VcpuLoopOutcome::ProcessExit(run)) => run.exit_code,
                Ok(VcpuLoopOutcome::TrapLimit(_)) | Err(_) => 127,
                Ok(VcpuLoopOutcome::ThreadDone) => unreachable!("non-terminal outcome"),
            };

            // A losing fatal thread may race another terminal transition up to
            // clone-admission close. Never attach its crash authority to the
            // winning owner's normal exit (or to a different fatal owner): an
            // ambiguous race is an honest no-core outcome.
            let terminating_signal = match &result {
                Ok(VcpuLoopOutcome::ProcessExit(run)) => run.terminating_signal,
                Ok(VcpuLoopOutcome::TrapLimit(_) | VcpuLoopOutcome::ThreadDone) | Err(_) => None,
            };
            let fatal_signal = fatal_for_terminal_owner(
                kernel
                    .fatal_signal
                    .recorded_for(state.fatal_image_generation),
                state.fatal_image_generation,
                state.linux_tid,
                terminating_signal,
            );
            let mut prepared_core = match fatal_signal {
                Some(fatal) => {
                    match state.capture_core_for_publication(&kernel, &mut engine, fatal) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            // Core preparation is fail-closed but cannot turn a
                            // guest signal death into a host/runtime abort. The
                            // parent receives the original signal with WCOREDUMP
                            // clear, and no final-path artifact survives.
                            tracing::warn!(
                                pid = kernel
                                    .hvpatch_process
                                    .as_ref()
                                    .map_or(0, crate::hvpatch::ProcessContext::pid),
                                %error,
                                "HVPatch core publication failed closed"
                            );
                            None
                        }
                    }
                }
                None => None,
            };

            if let Err(error) = state.terminate_siblings_for_process_exit(&kernel) {
                tracing::error!(%error, "terminal owner could not drain sibling vCPUs");
                std::process::abort();
            }
            if std::env::var_os("CARRICK_CORE_FAILPOINT")
                .is_some_and(|value| value == "sibling-drain")
                && let Some(prepared) = prepared_core.take()
            {
                crate::probes::hvpatch_core_lifecycle(
                    6,
                    prepared.snapshot.identity.pid,
                    prepared.fatal_tid,
                    prepared.generation,
                    1,
                );
            }

            // The terminal loop outcome may have snapshotted output before a
            // sibling completed an already-admitted write. Refresh the buffers
            // only after every sibling loop has drained, while preserving the
            // original exit/trap metadata.
            let mut final_result = match &result {
                Ok(VcpuLoopOutcome::ProcessExit(run) | VcpuLoopOutcome::TrapLimit(run)) => {
                    (**run).clone()
                }
                Err(_) => assemble_run_result(&kernel, 127, None, 0, false),
                Ok(VcpuLoopOutcome::ThreadDone) => unreachable!("non-terminal outcome"),
            };
            final_result.stdout = kernel.dispatcher.stdout();
            final_result.stderr = kernel.dispatcher.stderr();
            let terminal_publication = match &result {
                Ok(VcpuLoopOutcome::ProcessExit(_) | VcpuLoopOutcome::TrapLimit(_)) => {
                    Ok(final_result.clone())
                }
                Err(_) => Err(()),
                Ok(VcpuLoopOutcome::ThreadDone) => unreachable!("non-terminal outcome"),
            };

            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 1);
            state.registry.exit(state.this_tid);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 2);
            state.kicker.unregister(state.this_tid);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 3);
            crate::run_state::clear_guest_tid(state.this_tid.raw());
            crate::host_signal::forget_thread(state.this_tid.raw());
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 4);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 5);

            if let Some(process) = kernel.hvpatch_process.as_ref() {
                let terminal_context = match process.context_for_linux_tid(state.linux_tid) {
                    Ok(context) => context,
                    Err(error) => {
                        tracing::error!(pid = process.pid(), %error, "capture terminal frame inventory mm");
                        std::process::abort();
                    }
                };
                let terminal_mm = terminal_context.shared().mm().id();
                let extent_count = engine.frame_inventory_extent_count();
                if extent_count > 0 {
                    let event_count = match extent_count.checked_mul(2) {
                        Some(count) => count,
                        None => std::process::abort(),
                    };
                    let capacity =
                        match carrick_hal::FrameEventCapacity::for_event_count(event_count) {
                            Ok(capacity) => capacity,
                            Err(_) => std::process::abort(),
                        };
                    let reservation = match terminal_context
                        .kernel()
                        .reserve_frame_inventory(0, 0, capacity)
                    {
                        Ok(reservation) => reservation,
                        Err(error) => {
                            tracing::error!(pid = process.pid(), %error, "reserve terminal frame inventory");
                            std::process::abort();
                        }
                    };
                    let transaction = reservation.transaction();
                    if let Err(error) = engine.begin_retirement_inventory(reservation) {
                        terminal_context
                            .kernel()
                            .frame_inventory()
                            .abandon(transaction);
                        tracing::error!(pid = process.pid(), %error, "arm terminal frame inventory");
                        std::process::abort();
                    }
                }
                let process_exit_event =
                    process.record_process_exit_begin(published_exit_code, state.this_tid);
                let child = process.is_child();
                if child {
                    for (fd, stream, bytes) in [
                        (1, "stdout", final_result.stdout.as_slice()),
                        (2, "stderr", final_result.stderr.as_slice()),
                    ] {
                        if let Err(error) = write_hvpatch_child_output(fd, bytes) {
                            tracing::error!(
                                pid = process.pid(),
                                stream,
                                %error,
                                "flush HVPatch child output before exit publication failed"
                            );
                        }
                    }
                }
                // Rename is deliberately after sibling drain and every
                // fallible terminal-inventory edge. Rollback ownership remains
                // live until authoritative wait-status commit; no observer can
                // receive WCOREDUMP for an artifact that was later removed.
                let mut core_publication = match prepared_core.take() {
                    Some(prepared) => match kernel.dispatcher.publish_core_atomic(
                        &prepared.snapshot,
                        prepared.generation,
                        prepared.bytes,
                    ) {
                        Ok(publication) => {
                            crate::probes::hvpatch_core_lifecycle(
                                4,
                                process.pid(),
                                prepared.fatal_tid,
                                prepared.generation,
                                0,
                            );
                            Some(publication)
                        }
                        Err(error) => {
                            crate::probes::hvpatch_core_lifecycle(
                                6,
                                process.pid(),
                                prepared.fatal_tid,
                                prepared.generation,
                                1,
                            );
                            if matches!(error, CorePublicationError::Cleanup { .. }) {
                                tracing::error!(pid = process.pid(), %error, "HVPatch core cleanup failed; refusing authoritative terminal publication");
                                std::process::abort();
                            }
                            tracing::warn!(pid = process.pid(), %error, "HVPatch core publication failed closed");
                            None
                        }
                    },
                    None => None,
                };
                if std::env::var_os("CARRICK_CORE_FAILPOINT")
                    .is_some_and(|value| value == "wait-commit")
                    && let Some(publication) = core_publication.take()
                {
                    if let Err(error) = kernel.dispatcher.rollback_core_publication(&publication) {
                        tracing::error!(pid = process.pid(), %error, "HVPatch core rollback failed; refusing authoritative terminal publication");
                        std::process::abort();
                    }
                    crate::probes::hvpatch_core_lifecycle(
                        6,
                        process.pid(),
                        fatal_signal.map_or(state.this_tid.raw(), |fatal| fatal.tid.raw()),
                        publication.generation,
                        1,
                    );
                }
                let core_dumped = core_publication.is_some();
                let published_status = crate::kernel::LinuxWaitStatus::from_wait_encoding(
                    final_result.wait_status_encoding(core_dumped),
                );
                let orphan_adopter = kernel.dispatcher.hvpatch_orphan_adopter();
                let current_parent =
                    match process.publish_exit_status(published_status, orphan_adopter, |parent| {
                        // Linux has already closed every child descriptor when
                        // SIGCHLD or wait(2) makes exit observable. HVPatch
                        // multiplexes processes in one host, so `_exit` cannot
                        // supply that ordering for us. The Kernel invokes this
                        // callback after removing the exact task generation but
                        // before releasing its exit reservation: retire the
                        // table here, then wake the parent. Retiring afterward
                        // lets an interrupted edge-triggered epoll resample the
                        // pipe before its last writer disappears and lose HUP.
                        kernel
                            .dispatcher
                            .retire_hvpatch_process_fds(&terminal_context);
                        if child {
                            kernel.notify_hvpatch_parent_exit(parent);
                        }
                    }) {
                        Ok(parent) => parent,
                        Err(error) => {
                            if let Some(publication) = &core_publication {
                                if let Err(cleanup_error) =
                                    kernel.dispatcher.rollback_core_publication(publication)
                                {
                                    tracing::error!(
                                        pid = process.pid(),
                                        %cleanup_error,
                                        "HVPatch core rollback also failed during terminal abort"
                                    );
                                }
                            }
                            tracing::error!(
                                pid = process.pid(),
                                %error,
                                "terminal owner could not publish authoritative Kernel exit"
                            );
                            std::process::abort();
                        }
                    };
                if let Some(publication) = &core_publication {
                    crate::probes::hvpatch_core_lifecycle(
                        5,
                        process.pid(),
                        fatal_signal.map_or(state.this_tid.raw(), |fatal| fatal.tid.raw()),
                        publication.generation,
                        0,
                    );
                    tracing::info!(
                        pid = process.pid(),
                        path = %publication.path,
                        bytes = publication.bytes,
                        "published HVPatch Linux core"
                    );
                }
                tracing::trace!(
                    pid = process.pid(),
                    exit_code = published_exit_code,
                    child,
                    parent = ?current_parent,
                    "finalizing authoritative HVPatch process"
                );
                kernel.unregister_hvpatch_runtime_endpoint();

                let topology = crate::fork_quiesce::acquire_topology_lock(
                    carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                    process.pid(),
                    state.this_tid.raw(),
                );
                if let Err(error) = engine.retire_in_process_address_space() {
                    tracing::error!(
                        pid = process.pid(),
                        %error,
                        "terminal owner could not retire HVPatch engine address space"
                    );
                    std::process::abort();
                }
                let retirement_commit = (extent_count > 0).then(|| {
                    engine.take_retirement_inventory().unwrap_or_else(|| {
                        tracing::error!(
                            pid = process.pid(),
                            "terminal HVPatch frame inventory commit is missing"
                        );
                        std::process::abort();
                    })
                });
                drop(topology);

                if let Some(commit) = retirement_commit
                    && let Err(error) = terminal_context
                        .kernel()
                        .frame_inventory()
                        .apply(terminal_mm, commit)
                {
                    let snapshot = terminal_context
                        .kernel()
                        .frame_inventory()
                        .snapshot_for_mm(terminal_mm);
                    tracing::error!(
                        pid = process.pid(),
                        %error,
                        live_mappings = ?snapshot.mappings,
                        "terminal HVPatch frame inventory publication failed"
                    );
                    std::process::abort();
                }

                let topology = crate::fork_quiesce::acquire_topology_lock(
                    carrick_observability::probes::HvpatchTopologyOperation::ProcessRetire,
                    process.pid(),
                    state.this_tid.raw(),
                );
                if let Err(error) =
                    process.retire_address_space(published_exit_code, state.this_tid)
                {
                    tracing::error!(
                        pid = process.pid(),
                        %error,
                        "terminal owner could not retire HVPatch bank/ASID"
                    );
                    std::process::abort();
                }
                drop(topology);
                process.record_process_exit_commit(process_exit_event);
            } else {
                tracing::error!("terminal HVPatch process lacks authoritative process context");
                std::process::abort();
            }
            vcpu_retired_by_hvpatch_cleanup = true;
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 6);
            // Publication is the completion barrier: the main owner may destroy
            // the process-wide VM only after lifecycle and backend finalization.
            kernel.publish_process_terminal(terminal_publication);
        } else {
            state.trace_hvpatch_thread_terminal(
                carrick_observability::probes::HvpatchThreadTerminalReason::ProcessTerminalLoser,
                match exit_claim {
                    ProcessExitClaim::LostToExec => 1,
                    ProcessExitClaim::AlreadyOwned => 2,
                    ProcessExitClaim::Owner => 0,
                },
            );
            // An exec that claimed admission first owns the replacement. Its
            // terminal sibling must retire its exact old Kernel thread before
            // disappearing so the exec owner can finish the runtime drain and
            // prepare against a one-thread graph. A competing exit owner, in
            // contrast, will retire the whole task and needs only runtime drain.
            if exit_claim == ProcessExitClaim::LostToExec
                && let Some(process) = kernel.hvpatch_process.as_ref()
            {
                match process.exit_thread(state.linux_tid) {
                    Ok(crate::hvpatch::ProcessThreadExit::Retired) => {}
                    Ok(crate::hvpatch::ProcessThreadExit::LastThread) | Err(_) => {
                        tracing::error!(
                            pid = process.pid(),
                            tid = state.linux_tid.raw(),
                            "exec-loser could not retire its authoritative Kernel thread"
                        );
                        std::process::abort();
                    }
                }
            }
            // Another terminal operation owns this process transition. Retire
            // only this vCPU/thread and suppress a second ProcessExit.
            let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 1);
            state.registry.exit(state.this_tid);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 2);
            state.kicker.unregister(state.this_tid);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 3);
            crate::run_state::clear_guest_tid(state.this_tid.raw());
            crate::host_signal::forget_thread(state.this_tid.raw());
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 4);
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 5);
            engine.destroy_vcpu_on_thread_exit();
            trace_hvpatch_thread_teardown(&kernel, state.this_tid, 6);
            result = Ok(VcpuLoopOutcome::ThreadDone);
        }
    }
    // This thread is leaving its vCPU loop. The engine's Drop is a no-op.
    // HVPatch ProcessExit retires its vCPU in the process cleanup above;
    // mature VMM ProcessExit keeps its historical process-death teardown.
    if !vcpu_retired_by_hvpatch_cleanup
        && should_destroy_departing_vcpu(
            matches!(&result, Ok(VcpuLoopOutcome::ProcessExit(_))),
            matches!(&result, Ok(VcpuLoopOutcome::ThreadDone)),
        )
    {
        engine.destroy_vcpu_on_thread_exit();
    }
    trace_hvpatch_thread_teardown(&kernel, state.this_tid, 7);
    result
}

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
    RunResult {
        exit_code,
        terminating_signal,
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
/// SA_RESTART handler (the kernel's `ERESTARTSYS` set).
pub(super) fn is_restartable_syscall(nr: u64) -> bool {
    matches!(
        nr,
        95  // waitid
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
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    {
        if let Some(action) = deliver_pending_signal(
            engine,
            &kernel.dispatcher,
            context,
            last_syscall_retval,
            this_tid,
            interrupted_pc,
        )? {
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
    use std::num::NonZeroU64;
    use std::time::Duration;

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

    impl GuestMemory for ProtectionOnlyMemory {
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

    #[test]
    fn process_topology_handles_are_not_thread_group_siblings_and_drain_descendants() {
        let directory = Arc::new(HvpatchRuntimeDirectory::default());
        let sibling_threads = Mutex::new(Vec::<std::thread::JoinHandle<()>>::new());
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let child_directory = Arc::clone(&directory);
        let child_completed = Arc::clone(&completed);
        let child = std::thread::spawn(move || {
            let grandchild_completed = Arc::clone(&child_completed);
            child_directory.enroll_process_thread(std::thread::spawn(move || {
                grandchild_completed.fetch_add(1, std::sync::atomic::Ordering::Release);
            }));
            child_completed.fetch_add(1, std::sync::atomic::Ordering::Release);
        });
        directory.enroll_process_thread(child);

        assert!(sibling_threads.lock().is_empty());
        assert!(directory.join_process_threads().is_ok());
        assert_eq!(completed.load(std::sync::atomic::Ordering::Acquire), 2);
        assert!(directory.process_threads.lock().is_empty());
    }

    #[test]
    fn process_topology_join_drains_every_owner_after_a_child_panic() {
        let directory = HvpatchRuntimeDirectory::default();
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        directory.enroll_process_thread(std::thread::spawn(|| {
            panic!("deliberate process-child panic");
        }));
        let surviving_completed = Arc::clone(&completed);
        directory.enroll_process_thread(std::thread::spawn(move || {
            surviving_completed.store(true, std::sync::atomic::Ordering::Release);
        }));

        assert!(directory.join_process_threads().is_err());
        assert!(completed.load(std::sync::atomic::Ordering::Acquire));
        assert!(directory.process_threads.lock().is_empty());
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

    #[test]
    fn departing_vcpu_is_destroyed_unless_terminal_cleanup_already_owns_it() {
        assert!(!should_destroy_departing_vcpu(true, false));
        assert!(!should_destroy_departing_vcpu(false, true));
        assert!(should_destroy_departing_vcpu(false, false));
    }

    #[test]
    fn timed_wait_reclaim_keeps_vcpu_for_short_finite_timeouts() {
        assert!(!should_reclaim_vcpu_for_timed_wait(Some(
            SHORT_TIMED_WAIT_RECLAIM_CUTOFF
        )));
        assert!(!should_reclaim_vcpu_for_timed_wait(Some(
            SHORT_TIMED_WAIT_RECLAIM_CUTOFF - Duration::from_millis(1)
        )));
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
    fn clone_admission_exit_waits_for_in_flight_and_stays_closed() {
        let gate = CloneAdmissionGate::default();
        let permit = gate
            .try_enroll_thread_clone()
            .expect("initial clone permit");
        std::thread::scope(|scope| {
            let closer = scope.spawn(|| gate.claim_process_exit());
            while !permit.is_cancelled() {
                std::thread::yield_now();
            }
            assert!(gate.try_enroll_thread_clone().is_none());
            drop(permit);
            assert_eq!(
                closer
                    .join()
                    .expect("exit closer thread")
                    .expect("exit admission drain"),
                ProcessExitClaim::Owner
            );
        });
        assert!(gate.try_enroll_thread_clone().is_none());
    }

    #[test]
    fn clone_admission_arbitrates_exec_before_exit_without_mutual_drain() {
        let gate = CloneAdmissionGate::default();
        let owner = ThreadId::synthetic_for_tests(1002);
        let exec = gate.close_for_exec(owner).expect("exec admission close");
        assert!(gate.try_enroll_thread_clone().is_none());
        assert_eq!(
            gate.claim_process_exit().expect("exit arbitration"),
            ProcessExitClaim::LostToExec
        );
        drop(exec);
        assert!(gate.try_enroll_thread_clone().is_some());

        // Once exec releases, exit can claim permanent ownership and a later
        // exec cannot establish a competing terminal drain.
        assert_eq!(
            gate.claim_process_exit().expect("exit owns admission"),
            ProcessExitClaim::Owner
        );
        assert!(gate.close_for_exec(owner).is_err());
        assert!(gate.try_enroll_thread_clone().is_none());
    }

    #[test]
    fn clone_admission_cancels_enrolled_process_fork_before_exec_drain() {
        let gate = CloneAdmissionGate::default();
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
        let gate = CloneAdmissionGate::default();
        let owner = ThreadId::synthetic_for_tests(1004);
        let process_fork = gate
            .try_enroll_process_fork(owner)
            .expect("process fork admission");
        let existing_clone = gate
            .try_enroll_thread_clone()
            .expect("existing clone admission");

        std::thread::scope(|scope| {
            let closer = scope.spawn(|| process_fork.close_for_fork(owner));
            while !gate.is_closing() {
                std::thread::yield_now();
            }
            assert!(
                gate.try_enroll_thread_clone().is_none(),
                "new clones wait behind fork"
            );
            assert!(
                !existing_clone.is_cancelled(),
                "a clone admitted before fork must finish, not leak EAGAIN"
            );
            drop(existing_clone);
            let fork = closer
                .join()
                .expect("fork closer")
                .expect("fork admission drain");
            assert!(!process_fork.is_cancelled());
            drop(fork);
        });

        drop(process_fork);
        assert!(gate.try_enroll_thread_clone().is_some());
    }

    #[test]
    fn concurrent_fork_close_does_not_retire_a_vfork_parent() {
        let gate = CloneAdmissionGate::default();
        let owner = ThreadId::synthetic_for_tests(1005);
        let process_fork = gate
            .try_enroll_process_fork(owner)
            .expect("process fork admission");
        let fork = process_fork
            .close_for_fork(owner)
            .expect("fork admission close");

        assert!(gate.is_closing(), "ordinary fork must close new admission");
        assert!(
            !gate.is_terminal_closing(),
            "an unrelated fork close must not retire a suspended vfork parent"
        );

        drop(fork);
        drop(process_fork);
        let exec = gate.close_for_exec(owner).expect("exec admission close");
        assert!(
            gate.is_terminal_closing(),
            "exec replacement must retire a suspended vfork parent"
        );
        drop(exec);
        assert_eq!(
            gate.claim_process_exit().expect("process exit close"),
            ProcessExitClaim::Owner
        );
        assert!(
            gate.is_terminal_closing(),
            "process exit must retire a suspended vfork parent"
        );
    }

    #[test]
    fn timed_wait_reclaim_releases_vcpu_for_long_or_indefinite_waits() {
        assert!(should_reclaim_vcpu_for_timed_wait(None));
        assert!(should_reclaim_vcpu_for_timed_wait(Some(
            SHORT_TIMED_WAIT_RECLAIM_CUTOFF + Duration::from_millis(1)
        )));
        assert!(should_keep_vcpu_for_blocking_wait(false, true, false));
        assert!(!should_keep_vcpu_for_blocking_wait(false, false, false));
        assert!(!should_keep_vcpu_for_blocking_wait(false, true, true));
        assert!(
            !should_keep_vcpu_for_blocking_wait(true, true, false),
            "a selected long wait must release its slot before future admissions queue"
        );
    }

    #[test]
    fn threaded_fd_wait_interrupts_for_internal_fork_quiesce() {
        assert!(threaded_fd_wait_should_interrupt(true, false));
        assert!(threaded_fd_wait_should_interrupt(false, true));
        assert!(!threaded_fd_wait_should_interrupt(false, false));
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
