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
    DispatchError, DispatchOutcome, GuestMemory, ProcMapsEntry, SyscallDispatcher, SyscallRequest,
};
use crate::memory::AddressSpace;
use crate::run_result::{RunResult, RuntimeError};
use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::trap::{SyscallTrap, TrapError};

const SIGNAL_WAIT_SLICE: Duration = Duration::from_millis(50);

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
    ) -> Result<AddressSpace, i32> {
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
            Ok(raw) => raw,
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
            match raw
                .with_vdso_bytes(KvmArch::vdso_bytes())
                .and_then(|a| a.with_linux_initial_stack(argv, env))
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
            match raw
                .with_vdso_bytes(carrick_hal::x8664_arch::X8664GuestArch::vdso_bytes())
                .and_then(|a| a.with_linux_initial_stack(argv, env))
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
            .with_linux_initial_stack(argv, env)
            .map_err(|_| LINUX_ENOENT)?;
        // execve point of no return: reset CAUGHT handlers to SIG_DFL (the kernel
        // does this; SIG_IGN/mask/pending are preserved).
        dispatcher.reset_memory_state_on_execve();
        dispatcher.reset_signal_handlers_on_execve();
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
// `lower_el0_fault` / `deliver_fault_signal`: only callers are in this module's
// run-loop body. `pub(super)` in signal.rs limits them to vcpu_loop scope.
use signal::{deliver_fault_signal, lower_el0_fault};
pub(crate) use signal::{
    deliver_pending_signal, partial_write_interrupt_outcome, raise_sigpipe_for_blocking_write,
    signal_progress_count, signal_wait_expired, signal_wait_slice,
};
// Test-only re-exports: the `tests` module below names these (via `use super::*`)
// but no non-test in-crate caller does, so gate them to avoid an unused-import
// warning on the normal build.
#[cfg(test)]
pub(super) use signal::el0_debug_signal;
pub(crate) use signal::is_default_ignore_signal;

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
    /// Per-backend signal ARRIVAL / wake mechanism (kicker+futex on KVM, the
    /// kqueue pump / self-pipe / xsig ring on HVF). The neutral pending STORE is
    /// carrick-signal-core; this is only how an async signal physically wakes a
    /// waiter. Held object-safe so the loop never names the concrete impl.
    pub(crate) signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
}

impl KernelState {
    pub(crate) fn new(
        dispatcher: SyscallDispatcher,
        fork: Box<dyn HostForkCoordinator>,
        signal_arrival: Arc<dyn carrick_hal::SignalArrival>,
    ) -> Self {
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            fork,
            signal_arrival,
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

    fn trace_syscall(&self, traps: usize, frame: carrick_hal::RawSyscall) {
        if !self.trace {
            return;
        }
        // The frame carries the RAW per-ISA number, so the name comes from this
        // engine's per-ISA table (Phase 1 T8), not the canonical aarch64 table.
        let name = <<E::Arch as carrick_hal::GuestArch>::Table as carrick_hal::SyscallTable>::name(
            frame.number,
        )
        .unwrap_or("<unknown>");
        let a = frame.args;
        eprintln!(
            "tid#{} trap#{}: nr={} ({name}) a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x}",
            self.this_tid, traps, frame.number, a[0], a[1], a[2], a[3], a[4]
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
        // Stage-1 page-table editors — munmap(215), mremap(216), mmap(222),
        // mprotect(226) — mutate the shared guest descriptors from the host.
        // With sibling vCPUs live, Pause-Modify-Resume them so none walks a
        // half-edited descriptor tree.
        let _pt_pause = match frame.number {
            215 | 216 | 222 | 226 if self.kicker.count() > 1 => Some(self.pt_pause()),
            _ => None,
        };
        let mut signal_wait_deadline = None;
        // Monotonic deadline for a WaitOnSleep, established on first dispatch and
        // preserved across quiesce-park re-dispatch so the sleep isn't restarted.
        let mut sleep_deadline: Option<Instant> = None;
        // Monotonic deadline for WaitOnPollFds, preserved across internal
        // readiness re-sample retries so a finite guest epoll/pidfd wait is not
        // restarted by the kqueue backstop.
        let mut poll_deadline: Option<Instant> = None;
        loop {
            let request = SyscallRequest::from_raw(frame)
                .with_guest_abi(<E::Arch as carrick_hal::GuestArch>::linux_guest_abi());
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
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
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
                    mask_replaces,
                } => {
                    self.waiter.ensure_full();
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
                    match self.waiter.wait_with_dispatch_pending(
                        &fds,
                        timeout,
                        block_signals,
                        || {
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                self.this_tid,
                                block_signals,
                                mask_replaces,
                            )
                        },
                    ) {
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
                    mask_replaces,
                    clear_on_timeout,
                } => {
                    self.waiter.ensure_full();
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
                    match self.waiter.wait_with_dispatch_pending(
                        &fds,
                        timeout,
                        block_signals,
                        || {
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                self.this_tid,
                                block_signals,
                                mask_replaces,
                            )
                        },
                    ) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            for (addr, len) in &clear_on_timeout {
                                let _ = engine.zero_guest_range(*addr, *len);
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
                    mask_replaces,
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
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
                    match self.waiter.wait_poll_with_dispatch_pending(
                        &fds,
                        timeout,
                        block_signals,
                        || {
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                self.this_tid,
                                block_signals,
                                mask_replaces,
                            )
                        },
                    ) {
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
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
                    match self.waiter.wait_proc_exit_with_dispatch_pending(
                        pid,
                        block_signals,
                        || {
                            // waitpid is additive: block_signals is
                            // `non_interrupting_signal_mask` (a persistent-mask
                            // superset), so the persistent-mask union is a no-op.
                            kernel.dispatcher.has_deliverable_dispatch_pending_for_wait(
                                self.this_tid,
                                block_signals,
                                false,
                            )
                        },
                    ) {
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
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
                    match self.waiter.wait(&[], Some(slice), block_mask) {
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
                            // An unblocked pending signal OUTSIDE the wait set:
                            // EINTR so the loop tail delivers its handler.
                            // Re-dispatching instead would find nothing in
                            // `wait_set` and re-park forever.
                            if kernel.dispatcher.signal_wait_should_eintr(
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
                    crate::run_state::publish(crate::run_state::RunState::Blocked);
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

    pub(super) fn complete_returned(
        &self,
        engine: &mut E,
        value: i64,
    ) -> Result<i64, RuntimeError> {
        engine.complete_syscall(value)?;
        Ok(value)
    }

    pub(super) fn complete_errno(&self, engine: &mut E, errno: i32) -> Result<i64, RuntimeError> {
        self.complete_returned(engine, -(errno as i64))
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
            // Publish that this guest is RUNNING (executing guest code). This is
            // the single point that means "guest code is live now": it clears the
            // post-fork `Booting` state and any prior `Blocked`, so a sibling's
            // /proc/<pid>/stat reads `R`. A genuine guest-blocking wait re-publishes
            // `Blocked` below for the duration of the park (see `block_guard`).
            crate::run_state::publish(crate::run_state::RunState::Running);
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
                    // A synchronous guest EL0 fault (nil deref, bad access, BRK,
                    // single-step). Lower the raw aarch64 ESR to the ISA-neutral
                    // (signum, si_code, fault_addr) triple — covering BOTH the
                    // abort classes (SIGSEGV/SIGBUS) AND the debug classes
                    // (BRK/single-step → SIGTRAP) — then deliver via the shared
                    // GuestFault path. `from_el0_direct` selects whether the
                    // sigframe records the faulting PC as the resume target.
                    if let Some((signum, si_code, si_addr)) = lower_el0_fault(syndrome, elr, far) {
                        let interrupted_pc = if from_el0_direct { Some(elr) } else { None };
                        if let Some(outcome) = deliver_fault_signal(
                            &kernel,
                            &mut engine,
                            state.this_tid,
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
                        if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                            let out = kernel.dispatcher.stdout();
                            let err = kernel.dispatcher.stderr();
                            forked_child_die_by_signal(11, &out, &err);
                        }
                        let result = assemble_run_result(&kernel, 128 + 11, traps, false);
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
                    let interrupted_pc = Some(engine.current_pc()?);
                    if let Some(outcome) = deliver_fault_signal(
                        &kernel,
                        &mut engine,
                        state.this_tid,
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

            // ---- syscall service: no dispatcher-wide lock held ----
            let outcome = state.service_threaded_syscall(&kernel, &mut engine, frame)?;

            let mut last_syscall_retval: Option<i64> = None;
            let mut signal_interrupted_pc: Option<u64> = None;

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
                        // Destroy a name-bound child VM (bhyve) before _exit — KVM/HVF
                        // is a no-op (fd-lifetime-bound VM). _exit skips every Drop.
                        engine.process_exit_cleanup();
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
                        // Destroy a name-bound child VM (bhyve) before _exit — KVM/HVF
                        // is a no-op (fd-lifetime-bound VM). _exit skips every Drop.
                        engine.process_exit_cleanup();
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
                DispatchOutcome::SharedFutexWake { host_addr, count } => {
                    // Cross-process futex wake (MAP_SHARED): route through the
                    // SAME `PlatformFutex` the wait side uses so the wake reaches
                    // a waiter parked in another carrick process. Non-blocking, so
                    // we complete the syscall inline with the count woken (clamped
                    // to non-negative; a negative kernel return surfaces as 0
                    // woken, matching the prior inline ulock loop's `break`).
                    let woke = state.platform_futex.shared_wake(host_addr, count);
                    last_syscall_retval = Some(state.complete_returned(&mut engine, woke.max(0))?);
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
                    let restored_sigmask = match engine.restore_from_sigframe() {
                        Ok(mask) => mask,
                        // A guest-reachable bad rt_sigreturn frame (bad SP, or a
                        // corrupt/forged frame) is force_sigsegv on Linux: kill
                        // THIS process by SIGSEGV (exit 139), never abort the whole
                        // carrick runtime. Mirrors the unclassified-EL0-fault path.
                        Err(TrapError::SignalDeliveryFault) => {
                            if engine.is_forked_child()
                                || kernel.dispatcher.is_forked_guest_process()
                            {
                                let out = kernel.dispatcher.stdout();
                                let err = kernel.dispatcher.stderr();
                                forked_child_die_by_signal(11, &out, &err);
                            }
                            let result = assemble_run_result(&kernel, 128 + 11, traps, false);
                            return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                        }
                        Err(e) => return Err(e.into()),
                    };
                    kernel
                        .dispatcher
                        .restore_signal_mask(state.this_tid, restored_sigmask);
                    // Deliver the next pending signal (if any) before resuming,
                    // but at the just-restored user PC, not as another
                    // syscall-boundary signal. On x86, `rt_sigreturn` restores
                    // RCX as an ordinary caller-clobbered register; treating this
                    // as a syscall boundary would use that RCX as the resume RIP.
                    signal_interrupted_pc = Some(engine.current_pc()?);
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
                signal_interrupted_pc,
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
    pub(super) fn ignored() -> Self {
        Self {
            term_signal: None,
            stop_signal: None,
        }
    }

    pub(super) fn terminate(signum: i32) -> Self {
        Self {
            term_signal: Some(signum),
            stop_signal: None,
        }
    }

    pub(super) fn stop(signum: i32) -> Self {
        Self {
            term_signal: None,
            stop_signal: Some(signum),
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
                    // Destroy a name-bound child VM (bhyve) before _exit — KVM/HVF
                    // is a no-op (fd-lifetime-bound VM). _exit skips every Drop.
                    engine.process_exit_cleanup();
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
    use super::signal::lower_el0_fault;
    use super::*;
    use std::time::Duration;

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
    const BUS_ADRALN: i32 = 1;

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
