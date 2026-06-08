#![allow(
    clippy::unusual_byte_groupings,
    clippy::collapsible_if,
    clippy::manual_dangling_ptr,
    clippy::items_after_test_module
)]
// Several cross-platform casts (e.g. `mode_t`, fd ints) target a libc type that
// is ALREADY the destination width on non-macOS targets, so clippy flags them as
// `unnecessary_cast` only there. On macOS the source type differs (the cast is
// load-bearing), so we keep the lint STRICT on the macOS build and only relax it
// off-macOS where the casts are genuinely redundant.
#![cfg_attr(not(target_os = "macos"), allow(clippy::unnecessary_cast))]
// Same shape story for `CompatReporter::default()`: the reporter is a real
// fielded struct on macOS (carrick-hvf) but a unit struct in the non-macOS
// fallback, so `default_constructed_unit_structs` fires only off-macOS. Keep it
// STRICT on macOS.
#![cfg_attr(
    not(target_os = "macos"),
    allow(clippy::default_constructed_unit_structs)
)]

//! Carrick runtime — the core that runs an unmodified Linux ELF binary as a
//! native macOS process.
//!
//! # Theory of operation
//!
//! Carrick has **no guest Linux kernel**. A Linux ELF is loaded into a guest
//! address space, executed at EL0 under Apple's Hypervisor.framework (HVF), and
//! every `svc #0` (the AArch64 syscall instruction) traps back to the host. The
//! trapped syscall is then *emulated* — translated to Darwin host primitives
//! (real file descriptors, `kqueue`, `__ulock`, `posix_spawn`, `fork`) — and the
//! result is written back into the guest registers before resuming. To the
//! Linux process it is running on Linux; there is no VM image, no init, no guest
//! ring-0 code. carrick is simultaneously the VMM *and* the kernel the guest
//! thinks it is talking to.
//!
//! This crate is the union of those two roles. The split between them is
//! reflected in the module layout:
//!
//! - **The exec engine** (the leaf crate `carrick-hvf`, re-exported below under
//!   `crate::trap`, `crate::thread`, `crate::io_wait`, …): the HVF trap engine
//!   that owns the vCPUs, fork/exec address-space surgery, the SIMD/FP restore
//!   shim, cross-thread vCPU coordination (the kicker, the fork/page-table
//!   quiesce barriers), the Darwin `kqueue` wrapper, and host-signal capture.
//!   This is the "VMM half".
//! - **The kernel half** (this crate proper): [`dispatch`] — the syscall
//!   dispatcher and its subsystems — plus [`vfs`]/[`rootfs`]/[`overlay`]/
//!   [`fs_backend`] (the filesystem the guest sees), [`namespace`] (UID/GID +
//!   PID namespace emulation), [`container`] (docker-style run state), and the
//!   `/proc` and signal machinery. None of these touch HVF directly; they
//!   answer syscalls.
//! - **The lifecycle** ([`runtime`], [`execute`]): the glue that wires the two
//!   halves together. It loads the image, installs the EL0 trampoline / EL1
//!   vectors / stage-1 page tables, then drives the trap → dispatch → complete
//!   loop until the guest exits. It also owns the fork/clone model
//!   (`libc::fork` for guest processes, one host thread + one HVF vCPU per guest
//!   thread), fault-to-signal translation, the interactive pty bridge
//!   ([`pty_relay`]/[`interactive_supervisor`]), and the namespace supervisor
//!   ([`namespace::supervisor`]). Start reading at [`runtime`].
//!
//! # The leaf-crate re-exports
//!
//! Several subsystems were lifted out of this crate into leaf crates to cut the
//! build-graph fan-out (a ~40k-line monolith re-linking on every edit). They are
//! re-exported below under their *original* `crate::<module>` paths, so every
//! call site across the runtime — and every `carrick_runtime::<module>` path the
//! CLI/engine crates use — is unchanged. When you see `crate::trap::…` or
//! `crate::memory::…` in this crate, the code physically lives in `carrick-hvf`
//! / `carrick-mem` / `carrick-host` / `carrick-abi`; the boundary is a build
//! optimisation, not a semantic one.
//!
//! # Sharp edges (read before touching the lifecycle)
//!
//! - **HVF is not fork-safe.** A VM live in the parent at `libc::fork(2)` makes
//!   the child's `hv_vm_create` return `HV_BUSY`. Every fork in carrick is
//!   therefore choreographed: the namespace supervisor forks *before* any VM
//!   exists, and a guest `fork(2)` from a multithreaded guest first quiesces all
//!   sibling vCPUs, tears the VM down, forks, and rebuilds. See [`runtime`].
//! - **A forked child must `_exit`, never unwind.** It shares the parent's fd
//!   table; dropping an fd-owning value on the way out double-closes an inherited
//!   fd and trips std's IO-safety abort (`SIGABRT`). The lifecycle code branches
//!   on "am I a forked child" on every exit path for exactly this reason.
//! - **One vCPU per guest thread, one process VM.** Stage-2 mappings are shared
//!   across all vCPUs, but stage-1 page-table edits (mmap/mprotect/munmap) and
//!   forks are stop-the-world events coordinated through the quiesce barriers in
//!   `carrick-hvf::fork_quiesce`.

// carrick-runtime is an INTERNAL crate (consumed only by carrick-engine and
// carrick-cli), and its rustdoc is built with `--document-private-items` so the
// Big Theory Statements above and on each module can cross-link the internal
// run-loop / lifecycle items they describe (`run_vcpu_until_exit`,
// `maybe_fork_ns_supervisor`, `SupervisorRole`, `ThreadRuntimeState::handle_fork`,
// …). Those items are deliberately NOT public API; allow the internal doc links
// rather than widen the public surface just to satisfy rustdoc.
#![allow(rustdoc::private_intra_doc_links)]

#[cfg(target_os = "macos")]
pub mod apfs;
/// Linux/non-macOS `apfs` shim. The real `apfs` module (macOS-only, above) drives
/// APFS volume management via `diskutil`; that does not apply on Linux. But the
/// CLI + engine consult `default_writable_backend_kind` to pick the default fs
/// backend, and on Linux the host filesystem (cap-std passthrough) is always the
/// fork-coherent writable source of truth. The `*_carrick_volume` functions are
/// genuinely macOS-only — the `carrick volume` subcommand is gated off on Linux.
/// Gated as the exact complement of the real module's `target_os = "macos"` so the
/// two can never both exist.
#[cfg(not(target_os = "macos"))]
pub mod apfs {
    pub fn default_writable_backend_kind() -> carrick_spec::FsBackendKind {
        carrick_spec::FsBackendKind::Host
    }
}
pub mod binfmt;
pub mod container;
pub mod cred_ipc;
// Cross-platform forked-child exit helpers and shebang resolution, hoisted out
// of the per-platform copies in `runtime/exec.rs` (macOS) and
// `vcpu_loop::macos_helper_stubs` (Linux). No cfg gate: the functions are
// portable libc + `crate::...` path helpers that resolve per-platform.
#[cfg(target_os = "macos")]
pub(crate) mod darwin_fs;
pub mod deadlock_watchdog;
pub mod dispatch;
#[cfg(target_os = "macos")]
pub mod dtrace_consumer;
pub mod event_ring;
pub(crate) mod exec_helpers;
pub mod fs_backend;
pub mod host_tty;
pub(crate) mod inotify;
pub mod interactive_supervisor;
pub mod layer_cache;
pub mod namespace;
// `linux_abi` was lifted into the leaf crate `carrick-abi` (build-graph split,
// docs/archive/build-decomposition-design.md §3.A-A1). Re-exported under the original
// path so every `crate::linux_abi::…` / `carrick_runtime::linux_abi::…` site is
// unchanged.
pub use carrick_abi as linux_abi;
// elf/memory/page_table/vdso were lifted into the leaf crate `carrick-mem`
// (build-graph A3). Re-exported under their original paths so every
// `crate::memory::…` / `crate::elf::…` / `crate::page_table::…` / `crate::vdso::…`
// site (and the `carrick_runtime::*` ones) is unchanged.
pub use carrick_mem::{elf, memory, page_table, vdso};
// guest_cpu/host_facts/host_mapping/host_proc/ulock were lifted into the leaf
// crate `carrick-host` (Darwin host primitives — machine facts, __ulock, host
// shared mappings, CPU accounting, libproc introspection; no dispatch/trap/VFS
// deps). Re-exported under their original paths so every `crate::host_proc::…`
// / `crate::guest_cpu::…` / `crate::ulock::…` site is unchanged.
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
// The dispatch-free vCPU / exec-engine cluster was lifted into the leaf crate
// `carrick-hvf` (report item #1): the HVF trap engine (`trap`, incl. the
// `SyscallTrap` contract + SIMD/FP C shim), cross-thread vCPU coordination
// (`thread`/`vcpu_kick`/`io_wait`/`itimer`/`fork_quiesce`/`fork_coord`), the
// shared-aperture allocator, the Darwin `kqueue` wrapper, host-signal capture,
// the USDT probe provider (`probes`), compat-reporting (`compat`), and static
// syscall metadata (`syscall`). None depend on dispatch/VFS. Re-exported under
// their original `crate::trap::…` / `crate::thread::…` / … paths so every call
// site across the runtime is unchanged.
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub use carrick_hvf::darwin_kqueue;
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::{
    compat, fork_coord, host_signal, io_wait, itimer, posix_timer, probes, shared_aperture,
    syscall, threaded_impl, trap, vcpu_kick,
};
// thread (ThreadRegistry/FutexTable) + fork_quiesce barriers are
// hypervisor-agnostic; both backends use the real carrick-thread impls.
pub use carrick_thread::{fork_quiesce, thread};
// `current_thread_states` queries the kernel for per-thread run-state via the
// Mach port recorded by each vCPU thread. On macOS the real implementation
// (in carrick-hvf::thread) issues `thread_info`; on Linux there are no Mach
// ports, so we return every registered thread with state 'R' (running).
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::thread::current_thread_states;
#[cfg(not(feature = "platform-macos"))]
pub fn current_thread_states() -> Vec<(thread::ThreadId, char)> {
    thread::current_thread_ports()
        .into_iter()
        .map(|(tid, _port)| (tid, 'R'))
        .collect()
}

// Under platform-linux there is no carrick-hvf to re-export `trap` from; the
// SyscallTrap/TrapError/ForkOutcome contract lives in carrick-hal (section
// HAL). Re-export a `trap` shim so `crate::trap::{SyscallTrap, …}` resolves on
// both platforms. The concrete engine (HvfTrapEngine / KvmTrapEngine) is
// selected by the run-loop, which is itself platform-gated.
#[cfg(not(feature = "platform-macos"))]
pub mod trap {
    pub use carrick_hal::{ForkOutcome, SyscallTrap, TrapError};
    pub const HVF_PAGE_SIZE: u64 = 0x4000;

    // Cross-process VM-topology bookkeeping the shared threaded loop references
    // around a guest fork. On HVF these coordinate the stop-the-world VM
    // teardown/rebuild (carrick-hvf::trap); the Linux KVM backend has no such
    // host-side VM surgery, so they are inert stubs — same no-op pattern as the
    // `host_signal` / `probes` Linux stubs below. The vcpu_loop fork path that
    // uses them is itself gated to the HVF run loop, so these are never hit on
    // Linux; they exist only so the unconditional `vcpu_loop` module compiles.

    /// Count of live vCPUs — the fork/exec quiesce invariant on HVF. Always 0 on
    /// Linux (the fork quiesce is HVF-only).
    pub static VCPU_LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

    /// Clear any VM republished by a previous fork. No-op on Linux.
    pub fn clear_rebuilt_vm_for_fork() {}

    /// Publish the guest arena high-water so a child snapshot's mincore scan is
    /// bounded. No-op on Linux (no host-side CoW snapshot).
    pub fn set_guest_arena_high_water(_addr: u64) {}

    /// Dump cross-thread kick statistics at process exit. No-op on Linux.
    pub fn dump_kick_stats() {}
}
pub mod overlay;
pub mod pathcodec;

// Cross-platform run-loop result/error + kernel-half state. Single home for
// `RunResult` / `RuntimeError` / `KernelState` / `Kernel` / `VcpuLoopOutcome`,
// shared by the HVF threaded loop (`vcpu_loop`) and the KVM single-threaded
// loop (the Linux `runtime` module below).
pub mod run_result;

// The multi-threaded vCPU run loop, generic over `carrick_hal::ThreadedEngine`.
// Unconditional (compiles on both platforms); the generic `run_vcpu_until_exit`
// is instantiated only by the macOS HVF setup wrapper in `runtime`, so on Linux
// the whole module is dead code (the KVM run path is the single-threaded loop in
// the `runtime` shim below) — allow `dead_code` there so the Linux cross-check
// stays warning-clean without `#[allow]` peppered on every item.
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
pub mod vcpu_loop;

#[cfg(feature = "platform-macos")]
pub mod execute;
pub mod pty_relay;
pub mod rootfs;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub(crate) mod seccomp;
pub mod vfs;
#[cfg(feature = "platform-macos")]
pub use execute::Runtime;

#[cfg(not(feature = "platform-macos"))]
pub mod execute {
    pub fn guest_hostname() -> &'static str {
        "carrick"
    }

    /// Linux mirror of the macOS `execute::Runtime`. The CLI's run seam
    /// (`carrick_runtime::Runtime::execute(&spec)`, carrick-cli `commands.rs`) is
    /// platform-agnostic: on macOS it drives the HVF run loop, on Linux it drives
    /// the KVM OCI path. Both consume the SAME `carrick_spec::RunSpec` the engine
    /// already resolved and return the SAME `Result<RunResult, RuntimeError>`, so
    /// the CLI call site is byte-identical across platforms — only symbol
    /// resolution flips per feature. Mirrors how `runtime::run_oci` already mirrors
    /// the macOS `Runtime::execute` shape.
    pub struct Runtime;

    impl Runtime {
        pub fn execute(
            spec: &carrick_spec::RunSpec,
        ) -> Result<crate::run_result::RunResult, crate::run_result::RuntimeError> {
            crate::runtime::run_oci(spec)
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub use execute::Runtime;

#[cfg(not(feature = "platform-macos"))]
pub mod runtime {
    //! Linux (KVM) run path. The full macOS run loop lives in `runtime.rs`
    //! (`cfg(platform-macos)`); on Linux we drive `carrick_linux::KvmTrapEngine`
    //! through the REAL `SyscallDispatcher` with a single-threaded loop that
    //! mirrors the macOS loop's non-blocking outcome handling
    //! (`Returned`/`Errno`/`Exit`). Blocking I/O (the epoll waiter), futex, and
    //! fork/exec/signal-injection are the full-backend spec's Phase C/D work and
    //! deliberately surface here as `RuntimeError::Unsupported` for now.
    use carrick_guest_mem::GuestMemory;
    use carrick_hal::SyscallTrap;

    use crate::compat::CompatReporter;
    use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
    // The run-loop result/error types are now cross-platform (unified with the
    // macOS HVF loop) so both backends return the same `Result<RunResult, _>`.
    pub use crate::run_result::{RunResult, RuntimeError};

    pub const DEFAULT_MAX_TRAPS: usize = 1_000_000;
    pub(crate) const ROSETTA_INTERPRETER: &str =
        "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";
    pub(crate) fn rosetta_license_blob() -> Option<&'static [u8]> {
        None
    }

    /// Single-threaded real-dispatch loop for the KVM backend. Generic over the
    /// engine, which must be BOTH the guest memory (`GuestMemory`) and the trap
    /// vehicle (`SyscallTrap`) — `KvmTrapEngine` is both, so there is no
    /// `SplitView`. `next_syscall`, `dispatch`, and `complete_syscall` are
    /// called sequentially, so the single `&mut runtime` is never aliased.
    pub fn run_combined_syscall_loop_linux<R>(
        runtime: &mut R,
        mut dispatcher: SyscallDispatcher,
        max_traps: usize,
    ) -> Result<RunResult, RuntimeError>
    where
        R: GuestMemory + SyscallTrap,
    {
        let reporter = CompatReporter::default();
        let mut waiter =
            crate::io_wait::ThreadWaiter::new(std::process::id() as crate::thread::ThreadId);
        let trace_traps = std::env::var_os("CARRICK_TRACE_TRAPS").is_some();
        for traps in 1..=max_traps {
            // `next_syscall` returns `TrapError`, which the unified RuntimeError
            // absorbs via `#[from]` — so `?` carries it through directly.
            let frame = match runtime.next_syscall()? {
                Some(f) => f,
                // A bare kick/halt with no pending syscall. Phase B has no
                // process-directed signals, so there is nothing to deliver.
                None => continue,
            };
            if trace_traps {
                eprintln!(
                    "trap#{traps}: x8={} x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x}",
                    frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5
                );
            }
            // Dispatch, servicing any blocking-I/O wait inline (ppoll) and
            // re-dispatching on readiness, so the returned outcome is terminal.
            let outcome = service_syscall(
                &mut dispatcher,
                SyscallRequest::from_aarch64_frame(frame),
                runtime,
                &reporter,
                &mut waiter,
            )?;
            match outcome {
                DispatchOutcome::Returned { value } => {
                    runtime.complete_syscall(value)?;
                }
                DispatchOutcome::Errno { errno } => {
                    runtime.complete_syscall(-(errno as i64))?;
                }
                DispatchOutcome::Exit { code } => {
                    return Ok(RunResult {
                        exit_code: code,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                        report: reporter.snapshot(),
                        trap_limit_hit: false,
                    });
                }
                other => {
                    // Blocking I/O / futex / fork / clone-thread / signals:
                    // Phase C/D. Surface clearly rather than silently mis-handle.
                    return Err(RuntimeError::Unsupported(format!("{other:?}")));
                }
            }
        }
        Err(RuntimeError::TrapLimitExceeded { max_traps })
    }

    /// Multi-threaded KVM run loop (Phase 2 Task 7) — the Linux analog of the
    /// macOS `run_threaded_hvf_loop` (`runtime.rs`). Constructs the KVM trait
    /// objects (the concrete private `FutexTable`, the `KvmFutex` as
    /// `Arc<dyn PlatformFutex>`, the `PlatformFutexFactory` that rebuilds that
    /// pairing on the fork-child side, the `KvmKicker` as `Arc<dyn VcpuRegistry>`,
    /// and the `KvmForkCoordinator` as `Box<dyn HostForkCoordinator>`) and drives
    /// the generic `vcpu_loop::run_vcpu_until_exit::<KvmTrapEngine>`. THIS is what
    /// makes the KVM backend multi-process / multi-threaded: `handle_fork` (real
    /// `libc::fork` + child VM rebuild), `spawn_clone_thread` (sibling vCPUs on
    /// the same VM), and the private/shared futex paths all flow through here,
    /// byte-matching Docker.
    ///
    /// Unlike HVF, KVM needs NO signal-pump daemon thread: a host signal
    /// delivered to a vCPU thread blocked in `KVM_RUN` returns `EINTR` natively
    /// (`VcpuExit::Kicked`), so async process-directed signals interrupt the
    /// in-guest vCPU without a pump. The coordinator installs only the
    /// kick-signal handler (idempotently). The blocking-I/O / proc-exit / sleep /
    /// signal-wait arms use the `ppoll`/`waitid`-backed Linux `ThreadWaiter`
    /// (`crate::io_wait`, the same one the single-threaded loop used).
    #[cfg(feature = "platform-linux")]
    pub fn run_threaded_kvm_loop(
        engine: carrick_linux::KvmTrapEngine,
        dispatcher: SyscallDispatcher,
        max_traps: usize,
    ) -> Result<RunResult, RuntimeError> {
        use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
        use crate::vcpu_loop::{
            KernelState, PlatformFutexFactory, VcpuLoopOutcome, run_vcpu_until_exit,
        };
        use std::sync::Arc;

        let main_tid: ThreadId = std::process::id() as ThreadId;
        let registry = Arc::new(ThreadRegistry::new(main_tid));
        // Publish for /proc/<tid>/stat + /proc/<pid>/task/ synthesis (no-op on
        // the bare run-elf path, but kept parallel to HVF for the container path).
        crate::thread::set_current_registry(Arc::clone(&registry));
        // Root guest pid (before any fork) so /proc/<pid>/ can tell a guest
        // descendant from a host process.
        crate::host_proc::set_root_guest_pid(std::process::id());
        // Shared reaped-child CPU table, allocated before any fork so every guest
        // descendant inherits the same MAP_SHARED region.
        crate::guest_cpu::init_child_table();

        // The CONCRETE process-private futex table, threaded UNCHANGED through the
        // dispatch + complete_futex_wait path (the generation-snapshot lost-wake
        // protocol stays byte-identical). The object-safe `KvmFutex` wraps the
        // SAME table for the SHARED-futex / notify-signal-pending ops; the factory
        // rebuilds that pairing over a fresh table on the fork CHILD side
        // (`vcpu_loop::handle_fork`) without the generic loop naming `KvmFutex`.
        let futex = Arc::new(FutexTable::new());
        let platform_futex: Arc<dyn carrick_hal::PlatformFutex> =
            Arc::new(carrick_linux::KvmFutex(Arc::clone(&futex)));
        let platform_futex_factory: PlatformFutexFactory = Arc::new(
            |table: Arc<FutexTable>| -> Arc<dyn carrick_hal::PlatformFutex> {
                Arc::new(carrick_linux::KvmFutex(table))
            },
        );
        // The KVM host-fork coordinator (lean — no pump thread), boxed object-safe.
        let fork_coordinator: Box<dyn carrick_hal::HostForkCoordinator> =
            Box::new(carrick_linux::KvmForkCoordinator::new());
        let kernel = Arc::new(KernelState::new(dispatcher, fork_coordinator));
        // Track spawned sibling threads so the process doesn't tear down while a
        // worker is mid-flight; joined after the main thread finishes.
        let threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        // The KVM kicker (registry of live vCPUs). Held object-safe as the
        // `VcpuRegistry` the generic loop drives. Constructing it installs the
        // kick-signal handler (idempotent) so a cross-thread `pthread_kill` forces
        // a target vCPU out of `KVM_RUN` (→ `EINTR` → `VcpuExit::Kicked`).
        let kicker: Arc<dyn carrick_hal::VcpuRegistry> = Arc::new(carrick_linux::KvmKicker::new());
        // Install the kick-signal handler up front via the coordinator, so a
        // process-directed signal turns an in-flight `KVM_RUN` into `EINTR`
        // regardless of whether a guest has forked yet. (KvmKicker::new already
        // installs it; this makes the dependency explicit and matches the HVF
        // wrapper's `start_signal_pump` call site.)
        kernel.fork.start_signal_pump(&kicker, &platform_futex);

        // Wire wall-clock timer signals (setitimer/alarm/timer_settime): a
        // fallback timer thread publishes the timer signal to `main_tid` and
        // kicks it through this same `VcpuRegistry`.
        crate::timer_delivery::register(Arc::clone(&kicker), main_tid);

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

    /// Dispatch one syscall, servicing any blocking-I/O outcome inline via the
    /// `ppoll` waiter (then re-dispatching the SAME syscall on readiness), and
    /// return the TERMINAL outcome. Mirrors the macOS `dispatch_single_threaded_
    /// syscall` for the fd-wait / select / poll / sleep / blocking-write arms.
    /// Signal-wait, proc-exit, futex, fork, and clone-thread outcomes are not
    /// serviced here yet (later slices) — they fall through to the caller, which
    /// surfaces `RuntimeError::Unsupported`.
    fn service_syscall<M: GuestMemory>(
        dispatcher: &mut SyscallDispatcher,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        waiter: &mut crate::io_wait::ThreadWaiter,
    ) -> Result<DispatchOutcome, RuntimeError> {
        use crate::io_wait::{WaitFd, WaitResult};
        const EINTR: i32 = crate::linux_abi::LINUX_EINTR;
        loop {
            // `dispatch` returns `DispatchError`, absorbed via `#[from]`.
            let outcome = dispatcher.dispatch(request, memory, reporter)?;
            match outcome {
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait(&fds, timeout, block_signals) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                },
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait_poll(&fds, timeout, block_signals) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                },
                DispatchOutcome::WaitOnFdsSelect {
                    fds,
                    timeout,
                    block_signals,
                    clear_on_timeout,
                } => match waiter.wait(&fds, timeout, block_signals) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        // select returns 0 with the fd-sets zeroed; the handler
                        // left them intact, so zero them here.
                        for (addr, len) in &clear_on_timeout {
                            let _ = memory.write_bytes(*addr, &vec![0u8; *len]);
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno { errno: EINTR });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                },
                DispatchOutcome::WaitOnSleep { duration } => {
                    match waiter.wait(&[], Some(duration), 0) {
                        // Empty fd set: only TimedOut (sleep elapsed) is expected.
                        WaitResult::Ready | WaitResult::TimedOut => {
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        WaitResult::Interrupted => {
                            return Ok(DispatchOutcome::Errno { errno: EINTR });
                        }
                        WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    }
                }
                DispatchOutcome::BlockingHostWrite(mut write) => loop {
                    match crate::dispatch::drive_blocking_host_write(&mut write) {
                        // (SIGPIPE-on-EPIPE raise is deferred with signal delivery.)
                        crate::dispatch::BlockingHostWriteStep::Done(o) => return Ok(o),
                        crate::dispatch::BlockingHostWriteStep::Wait => {
                            match waiter.wait(
                                &[WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                None,
                                0,
                            ) {
                                WaitResult::Ready => continue,
                                WaitResult::Interrupted | WaitResult::TimedOut => {
                                    return Ok(DispatchOutcome::Returned {
                                        value: write.offset() as i64,
                                    });
                                }
                                WaitResult::Errno(errno) => {
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
                },
                DispatchOutcome::WaitOnSignals { wait_set, timeout } => {
                    // rt_sigtimedwait/sigwait blocking: a signal already pending
                    // in wait_set was dequeued before this outcome, so we reach
                    // here only to wait. Sleep for the timeout, re-dispatching on
                    // wake to re-check pending (a host signal mapped to the guest,
                    // or — once cross-process signals land — another process's
                    // kill). A finite timeout with nothing pending → EAGAIN, the
                    // sigtimedwait timeout return. Single-threaded: no in-process
                    // async source, so a finite timeout is deterministic.
                    match waiter.wait(&[], timeout, !wait_set) {
                        WaitResult::Ready | WaitResult::Interrupted => continue,
                        WaitResult::TimedOut => {
                            return Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EAGAIN,
                            });
                        }
                        WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    }
                }
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    // wait4/waitid on a child. The single-vCPU backend has no
                    // guest children yet (fork/clone is Phase D), so this is a
                    // clean ECHILD rather than a hang.
                    match waiter.wait_proc_exit(pid, block_signals) {
                        WaitResult::Ready => continue,
                        WaitResult::Interrupted | WaitResult::TimedOut => {
                            return Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_ECHILD,
                            });
                        }
                        WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                    }
                }
                // Terminal (Returned/Errno/Exit/...) and not-yet-serviced
                // (futex/fork/clone-thread/...) outcomes.
                terminal => return Ok(terminal),
            }
        }
    }

    /// Phase B entry: boot a freestanding/static aarch64 ELF under KVM and run
    /// it through the REAL dispatcher — the `cfg(platform-linux)` sibling of the
    /// macOS `HvfTrapEngine` run path. `KvmTrapEngine` satisfies the loop's
    /// `GuestMemory + SyscallTrap` bound directly.
    #[cfg(feature = "platform-linux")]
    pub fn run_elf_real_dispatch(path: &std::path::Path) -> Result<RunResult, RuntimeError> {
        // Build the full guest image WITH a Linux initial stack: argc/argv/envp
        // and the auxv (AT_RANDOM/AT_PLATFORM/AT_EXECFN) a real binary's CRT
        // reads before main. A freestanding fixture that ignores SP is
        // unaffected; a libc binary needs it. argv[0] is the path; a minimal
        // env keeps the CRT happy.
        let argv0 = path.to_string_lossy().into_owned();
        // `AddressSpaceError` and `TrapError` are absorbed by the unified
        // RuntimeError via `#[from]`, so `?` carries each through directly.
        let image = crate::memory::AddressSpace::load_elf(path)?
            // load_elf sets AT_SYSINFO_EHDR in the auxv, so a libc CRT reads the
            // vdso ELF header at LINUX_VDSO_BASE. Materialise the vdso (+ vvar)
            // regions — bring_up backs them as their own slots — or that read
            // faults. Mirrors the macOS boot chain. Must precede the stack build
            // (which serialises the auxv). The vDSO clock fast path reads
            // `cntvct_el0` at EL0; bring_up enables it (CNTKCTL_EL1) + fills the
            // vvar so the read is correct.
            .with_vdso()?
            .with_linux_initial_stack(
                [argv0.as_bytes()],
                [
                    b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".as_slice(),
                    b"HOME=/".as_slice(),
                    b"TERM=dumb".as_slice(),
                ],
            )?;
        let mut engine = carrick_linux::KvmTrapEngine::new(&image)?;
        // Phase 2 Task 7: drive the generic MULTI-THREADED loop by default so
        // fork/execve/threads/futex guests run (handle_fork, sibling vCPUs, the
        // private/shared futex paths). The single-threaded thin loop
        // (`run_combined_syscall_loop_linux`) stays reachable as a `--no-threads`
        // fallback via `CARRICK_NO_THREADS` for A/B debugging — it surfaces
        // `Unsupported` on any fork/clone/futex outcome, so it is only useful for
        // the simple write+exit cases the MVP validated.
        if std::env::var_os("CARRICK_NO_THREADS").is_some() {
            return run_combined_syscall_loop_linux(
                &mut engine,
                make_linux_dispatcher(),
                DEFAULT_MAX_TRAPS,
            );
        }
        run_threaded_kvm_loop(engine, make_linux_dispatcher(), DEFAULT_MAX_TRAPS)
    }

    /// Build the dispatcher for the bare KVM ELF runner with a real, writable
    /// guest filesystem. A bare ELF has no OCI rootfs, so a fresh
    /// `SyscallDispatcher` has an empty VFS and every guest `open` fails. We root
    /// the guest at a private, cap-std-sandboxed scratch directory
    /// (`HostFsBackend`) — so `open`/`read`/`write` flow to real host syscalls —
    /// and seed a minimal Linux baseline (`/tmp`, `/etc/{passwd,group,hosts,…}`),
    /// mirroring carrick-cli's `--fs host`. If the backend can't be created the
    /// guest simply has no filesystem (the runner still works for fs-free code).
    #[cfg(feature = "platform-linux")]
    fn make_linux_dispatcher() -> SyscallDispatcher {
        use crate::fs_backend::{FsBackend, HostFsBackend};

        let mut dispatcher = SyscallDispatcher::new();
        let scratch_root = std::env::temp_dir().join("carrick-kvm-scratch");
        match HostFsBackend::new_in(&scratch_root) {
            Ok(host) => {
                let mut backend: Box<dyn FsBackend> = Box::new(host);
                seed_linux_baseline(&mut *backend);
                let _ = dispatcher.set_fs_backend(backend);
            }
            Err(e) => {
                eprintln!(
                    "carrick-kvm: host fs backend unavailable ({e}); guest filesystem is empty"
                );
            }
        }
        dispatcher
    }

    /// Pre-create the standard Linux directories and a few `/etc` databases a
    /// raw static binary assumes exist (it has no OCI rootfs to supply them).
    #[cfg(feature = "platform-linux")]
    fn seed_linux_baseline(backend: &mut dyn crate::fs_backend::FsBackend) {
        for dir in [
            "/tmp",
            "/var",
            "/var/tmp",
            "/root",
            "/etc",
            "/dev",
            "/run",
            "/bin",
            "/sbin",
            "/usr",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local",
            "/usr/local/bin",
            "/usr/local/sbin",
        ] {
            let _ = backend.make_dir(dir);
        }
        let _ = backend.set_mode("/tmp", 0o1777);
        let _ = backend.set_mode("/var/tmp", 0o1777);
        let _ = backend.set_file_contents(
            "/etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                .to_vec(),
        );
        let _ = backend.set_file_contents("/etc/group", b"root:x:0:\nnogroup:x:65534:\n".to_vec());
        let _ = backend.set_file_contents(
            "/etc/nsswitch.conf",
            b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
        );
        let host = crate::execute::guest_hostname();
        let hosts = format!(
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t{host}\n"
        );
        let _ = backend.set_file_contents("/etc/hosts", hosts.into_bytes());
        let _ = backend.set_file_contents("/etc/hostname", format!("{host}\n").into_bytes());
    }

    /// Like [`seed_linux_baseline`] but GAP-FILLING: only create dirs (harmless
    /// if the image already has them) and write an `/etc` file when the extracted
    /// rootfs did NOT provide one. A container image owns its own `/etc/passwd`,
    /// `PATH`, etc.; clobbering them (as `seed_linux_baseline` does for the bare
    /// run-elf runner) would silently override the image. Mirrors the macOS
    /// `seed_guest_baseline` + `set_baseline_file_if_missing` (execute.rs).
    #[cfg(feature = "platform-linux")]
    fn seed_linux_baseline_gaps(backend: &mut dyn crate::fs_backend::FsBackend) {
        for dir in [
            "/tmp",
            "/var",
            "/var/tmp",
            "/root",
            "/etc",
            "/dev",
            "/proc",
            "/sys",
            "/run",
            "/bin",
            "/sbin",
            "/usr",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local",
            "/usr/local/bin",
            "/usr/local/sbin",
        ] {
            let _ = backend.make_dir(dir);
        }
        let _ = backend.set_mode("/tmp", 0o1777);
        let _ = backend.set_mode("/var/tmp", 0o1777);
        let fill = |path: &str, contents: Vec<u8>| {
            if backend.metadata(path).is_none() {
                let _ = backend.set_file_contents(path, contents);
            }
        };
        fill(
            "/etc/passwd",
            b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n".to_vec(),
        );
        fill("/etc/group", b"root:x:0:\nnogroup:x:65534:\n".to_vec());
        fill(
            "/etc/nsswitch.conf",
            b"passwd: files\ngroup: files\nhosts: files dns\n".to_vec(),
        );
        let host = crate::execute::guest_hostname();
        let hosts = format!(
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t{host}\n"
        );
        fill("/etc/hosts", hosts.into_bytes());
        fill("/etc/hostname", format!("{host}\n").into_bytes());
    }

    /// Phase 5 entry: run an OCI container under KVM. The macOS sibling of this is
    /// `Runtime::execute`'s `FsBackendKind::Host` path (execute.rs): extract the
    /// image layers onto a scratch rootfs, root the dispatcher there, set
    /// cwd/uid/gid, load the entrypoint FROM the rootfs, and run it with the OCI
    /// argv/env. The only divergence is the run-loop entry: this drives
    /// `KvmTrapEngine` through `run_threaded_kvm_loop` instead of the HVF loop.
    ///
    /// NOTE: the entrypoint must be a FULL-PATH ELF (`/bin/echo`). PATH-resolution
    /// of a bare command and `#!`-shebang resolution live in the macOS-gated
    /// `resolve_entrypoint_program`; sharing them is a follow-up.
    #[cfg(feature = "platform-linux")]
    pub fn run_oci(spec: &carrick_spec::RunSpec) -> Result<RunResult, RuntimeError> {
        use crate::fs_backend::HostFsBackend;
        use std::path::PathBuf;

        // 1. Extract the OCI layers onto a fresh cap-std scratch rootfs.
        let mut host = HostFsBackend::new()
            .map_err(|e| RuntimeError::FsBackend(anyhow::anyhow!("scratch dir: {e}")))?;
        let layer_paths: Vec<PathBuf> = spec
            .rootfs_layers
            .iter()
            .map(|p| PathBuf::from(p.as_std_path()))
            .collect();
        host.extract_layers(&layer_paths)
            .map_err(|e| RuntimeError::FsBackend(anyhow::anyhow!("extract OCI layers: {e}")))?;
        seed_linux_baseline_gaps(&mut host);

        // 2. Build the dispatcher rooted at the extracted rootfs. This is a
        //    sandboxed container fs (extracted OCI layers on a cap-std overlay):
        //    forbid the execve host-fs fallback so a target absent from the
        //    rootfs ENOENTs instead of escaping to the host binary.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.sandbox_exec_to_container();
        dispatcher.set_executable_path(spec.executable.clone());
        if let Some(cwd) = &spec.cwd {
            dispatcher.set_cwd(cwd.as_str());
        }
        dispatcher.set_credentials(spec.uid, spec.gid);
        for mount in &spec.mounts {
            let host_path = PathBuf::from(mount.source.as_std_path());
            let target_path = PathBuf::from(mount.target.as_std_path());
            let bind =
                crate::vfs::bind::BindVfs::new(mount.target.as_str(), host_path, mount.readonly);
            dispatcher.register_mount(target_path, Box::new(bind));
        }
        let _ = dispatcher.set_fs_backend(Box::new(host));

        // 3. Resolve + load the entrypoint FROM the rootfs via the SHARED helpers
        //    (identical to the macOS run path): PATH-resolve a bare command,
        //    resolve `#!` scripts, read the ELF (+ its PT_INTERP/loader) through
        //    the rootfs reader, and assemble the image. The only platform fork is
        //    step 4 (the run-loop entry). at_base=None: Rosetta amd64 redirection
        //    is not wired on Linux yet (the build_run_image at_base param supports
        //    it the day a Linux Rosetta interpreter is located).
        let argv_bytes: Vec<Vec<u8>> = spec.argv.iter().map(|s| s.as_bytes().to_vec()).collect();
        let (resolved, argv) = crate::exec_helpers::resolve_entrypoint_program(
            &spec.executable,
            &spec.envp,
            argv_bytes,
            &dispatcher,
        )
        .map_err(|_| {
            RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                spec.executable.clone(),
            )))
        })?;
        dispatcher.set_executable_identity(
            resolved.clone(),
            spec.argv.clone(),
            spec.envp.iter().map(|s| s.as_bytes().to_vec()).collect(),
        );
        let bytes = dispatcher.read_exec_file(&resolved).ok_or_else(|| {
            RuntimeError::AddressSpace(crate::memory::AddressSpaceError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                resolved.clone(),
            )))
        })?;
        let image = crate::exec_helpers::build_run_image(
            &bytes,
            argv,
            &spec.envp,
            &dispatcher,
            true,
            None,
        )?;
        // Materialise the vvar+vDSO regions so the auxv's AT_SYSINFO_EHDR
        // (= LINUX_VDSO_BASE, set by load_elf and kept by build_run_image's
        // with_vdso_auxv(true)) resolves to real KVM-backed slots. A STATIC CRT
        // can skip AT_SYSINFO_EHDR, but a DYNAMIC loader (ld-musl/ld-linux)
        // ALWAYS dereferences it to bind vDSO symbols — without the region that
        // read stage-2-faults to KVM_EXIT_MMIO at LINUX_VDSO_BASE (the busybox
        // MmioRead at 0x2E_0001_0020). `build_for_image` backs each high region
        // as its own slot. The macOS/HVF run path adds these regions later in
        // `finish_and_run_image`; the KVM run-elf/execve paths add them inline
        // (lib.rs:601, vcpu_loop.rs:144) — run_oci was the last KVM path missing
        // it. `with_vdso` preserves the already-serialised stack + auxv image, so
        // adding it after `with_linux_initial_stack` is equivalent to the run-elf
        // vdso-then-stack order. The vDSO clock fast path reads `cntvct_el0` at
        // EL0; `bring_up` enables that (CNTKCTL_EL1) and fills the vvar with the
        // freq + realtime offset so the read is correct (see `populate_vdso_vvar`).
        let image = image.with_vdso()?;

        // 4. Run on KVM through the same generic threaded loop as run-elf.
        let engine = carrick_linux::KvmTrapEngine::new(&image)?;
        run_threaded_kvm_loop(engine, dispatcher, spec.max_traps)
    }
}

/// Whether the EL1 guest-side syscall shim (the register-only identity fast
/// path: getpid/get*id/gettid) is compiled in. Gated by the `syscall-shim`
/// Cargo feature. carrick-cli enables it by default; build the binary with
/// `--no-default-features` for the legacy trap-only path.
pub(crate) const fn syscall_shim_enabled() -> bool {
    cfg!(feature = "syscall-shim")
}

#[cfg(feature = "platform-macos")]
pub use carrick_bsd::bsd_to_linux_errno as host_to_linux_errno;

#[cfg(not(feature = "platform-macos"))]
pub fn host_to_linux_errno(host: i32) -> i32 {
    host
}

// Fallbacks for the configured-out carrick-hvf re-exports when platform-macos is disabled.
#[cfg(not(feature = "platform-macos"))]
pub mod darwin_kqueue {
    pub const EVFILT_EXCEPT: i16 = -15;
    pub const NOTE_OOB: u32 = 0x0000_0002;

    pub fn trigger_user(_kq: i32, _ident: usize) -> Result<(), i32> {
        Ok(())
    }
    pub fn apply_changes(_kq: i32, _changes: &[Kevent]) -> Result<(), i32> {
        Ok(())
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Kevent;
    impl Kevent {
        pub fn empty() -> Self {
            Self
        }
        pub fn read(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn write(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn oob(_fd: i32, _flags: u16) -> Self {
            Self
        }
        pub fn vnode(_fd: i32, _note: u32) -> Self {
            Self
        }
        pub fn vnode_delete(_fd: i32) -> Self {
            Self
        }
        pub fn proc_exit(_pid: i32) -> Self {
            Self
        }
        pub fn with_udata(self, _udata: i32) -> Self {
            Self
        }
        pub fn user(_ident: usize, _flags: u16) -> Self {
            Self
        }
        pub fn timer(_ident: usize, _flags: u16, _interval_ns: i64) -> Self {
            Self
        }
        pub fn udata_i32(&self) -> i32 {
            0
        }
        pub fn vnode_ident(&self) -> i32 {
            -1
        }

        pub fn is_proc_exit(&self) -> bool {
            false
        }
        pub fn is_read_for_fd(&self, _fd: i32) -> bool {
            false
        }
        pub fn filter(&self) -> i16 {
            0
        }
        pub fn flags(&self) -> u16 {
            0
        }
        pub fn fflags(&self) -> u32 {
            0
        }
        pub fn data(&self) -> i64 {
            0
        }
        pub fn ident(&self) -> usize {
            0
        }
        pub fn proc_exit_ident(&self) -> Option<i32> {
            None
        }
        pub fn proc_exit_status(&self) -> i32 {
            0
        }
    }

    #[derive(Debug)]
    pub struct Kqueue;
    impl Kqueue {
        pub fn new_internal() -> Option<Self> {
            None
        }
        /// A do-nothing kqueue for the Linux epoll instance. Linux `epoll_pwait`
        /// computes readiness directly from the interest map and blocks via
        /// `ppoll` (see net.rs), so the kqueue is never driven — but the
        /// `OpenDescription::Epoll` struct still needs one to construct.
        pub fn dummy() -> Self {
            Self
        }
        pub fn apply(&self, _changes: &[Kevent]) -> Result<(), i32> {
            Ok(())
        }
        pub fn raw_fd(&self) -> i32 {
            -1
        }
        pub fn wait(
            &self,
            _changes: &[Kevent],
            _events: &mut [Kevent],
            _timeout: Option<&libc::timespec>,
        ) -> Result<usize, i32> {
            Ok(0)
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod host_signal {
    pub const NO_PENDING_SIGNAL: i32 = 0;

    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    // Per-guest-thread pending UNBLOCKED-signal bitmask (bit `signum-1`),
    // mirroring the macOS `THREAD_PENDING`. A guest `tgkill`/`tkill` (raise,
    // pthread_kill) or a sibling-directed send of an UNBLOCKED signal is
    // published here by `publish_pending_for`; the TARGET thread's run loop
    // consumes it via `take_pending_for` (in `vcpu_loop::deliver_pending_signal`)
    // and injects the handler. BLOCKED signals do NOT come here — they go to the
    // dispatcher's own per-thread pending set (`mark_signal_pending`, the
    // sigwait/sigtimedwait path), which is why blocked-signal delivery already
    // worked while this module was stubbed. Linux has no host-signal pump, so
    // there is no process-directed `PROC_PENDING` analogue: a guest
    // process-directed send is already routed to a concrete thread (or to the
    // dispatcher's shared pending set) before it would reach here.
    fn thread_pending() -> &'static Mutex<HashMap<i32, u64>> {
        static T: OnceLock<Mutex<HashMap<i32, u64>>> = OnceLock::new();
        T.get_or_init(|| Mutex::new(HashMap::new()))
    }
    /// Lock the pending table, recovering the guard if a panicking thread
    /// poisoned the mutex (the contents are a plain bitmask, never left in a
    /// half-updated state — and a poisoned signal table must not crash delivery).
    fn lock_pending() -> std::sync::MutexGuard<'static, HashMap<i32, u64>> {
        thread_pending()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// `THREAD_PENDING` bit for `signum` (bit `signum-1`), or 0 if out of range.
    fn pending_bit(signum: i32) -> u64 {
        if (1..=64).contains(&signum) {
            1u64 << (signum - 1)
        } else {
            0
        }
    }

    pub fn relocate_internal_fd(fd: i32) -> i32 {
        fd
    }
    pub fn reset_after_supervisor_fork() {}
    /// Is a deliverable (unblocked) signal pending for `tid`? A signal whose bit
    /// is in `block_mask` does not count (it stays pending until unblocked), but
    /// SIGKILL/SIGSTOP always count. Used by a blocking wait (ppoll/epoll_pwait)
    /// to decide whether to break so the loop can run delivery.
    pub fn has_unblocked_pending_for(tid: i32, block_mask: u64) -> bool {
        let always = pending_bit(crate::linux_abi::LINUX_SIGKILL)
            | pending_bit(crate::linux_abi::LINUX_SIGSTOP);
        lock_pending()
            .get(&tid)
            .is_some_and(|&mask| mask & (!block_mask | always) != 0)
    }
    pub fn linux_to_host_signum(sig: i32) -> i32 {
        sig
    }
    pub fn host_to_linux_signum(sig: i32) -> i32 {
        sig
    }
    pub fn has_process_pending() -> bool {
        false
    }
    pub fn take_child_exit_parent(_child_pid: i32) -> Option<(i32, i32)> {
        None
    }
    pub fn reset_routed_handlers_after_execve(_ignored_mask: u64) {}
    pub fn xsig_has_pending() -> bool {
        false
    }
    pub fn xsig_drain_for_self() -> Vec<(i32, i32, u32, i64)> {
        Vec::new()
    }
    pub fn raise_for_self(_sig: i32) {}
    /// Publish an UNBLOCKED thread-directed signal at guest `tid`. The target's
    /// run loop consumes it via `take_pending_for` and injects the handler. The
    /// caller is responsible for any cross-thread wakeup (the runtime kicks the
    /// target vCPU right after, for the sibling path); for a self-raise the
    /// publishing thread reaches `deliver_pending_signal` itself on the next
    /// loop iteration.
    pub fn publish_pending_for(tid: i32, sig: i32) {
        let bit = pending_bit(sig);
        if bit != 0 {
            *lock_pending().entry(tid).or_insert(0) |= bit;
        }
    }
    pub fn take_pending() -> i32 {
        0
    }
    pub fn ensure_host_handler(_sig: i32) {}
    pub fn set_host_ignore(_sig: i32) {}
    pub fn set_host_default(_linux_signum: i32) {}
    /// Drain a pending signal for `tid` that intersects `wait_set` (bit
    /// `signum-1`), clearing only the lowest matching bit and leaving the rest
    /// pending. Consulted by `rt_sigtimedwait`/`sigwait` (`dispatch/signal.rs`)
    /// after the dispatcher's own pending store: an UNBLOCKED async-published
    /// signal (e.g. a wall-clock timer's SIGALRM that the program also blocks +
    /// awaits synchronously) lands in this per-thread table, not the dispatcher's,
    /// so the synchronous wait must look here too. Returns `NO_PENDING_SIGNAL`
    /// (0) if nothing in the table matches `wait_set`.
    pub fn take_pending_in_for(tid: i32, wait_set: u64) -> i32 {
        let mut guard = lock_pending();
        if let Some(mask) = guard.get_mut(&tid) {
            let in_set = *mask & wait_set;
            if in_set != 0 {
                let signum = in_set.trailing_zeros() as i32 + 1;
                *mask &= !pending_bit(signum);
                if *mask == 0 {
                    guard.remove(&tid);
                }
                return signum;
            }
        }
        NO_PENDING_SIGNAL
    }
    pub fn xsig_enqueue(
        _target_host: i32,
        _sig: i32,
        _sender_ns: i32,
        _sender_uid: u32,
        _value: i64,
    ) -> bool {
        false
    }
    pub fn xsig_nudge(_target_host: i32) {}
    /// No kqueue signal pump on Linux. Returning -1 makes the `setitimer`
    /// dispatch path (the only caller) skip the EVFILT_TIMER arming and use the
    /// wall-clock fallback timer thread (`itimer::spawn_fallback_timer`) instead.
    pub fn pump_kqueue() -> i32 {
        -1
    }
    // The generic threaded loop IS instantiated on the KVM backend
    // (`run_threaded_kvm_loop` -> `run_vcpu_until_exit::<KvmTrapEngine>`), so the
    // per-thread signal-pending functions below (`forget_thread`,
    // `has_pending_for`, `take_pending_for`) are REAL — they back the unblocked
    // async-signal-delivery path (Phase 4). The few still-stubbed names below
    // (`last_sender_for`, `register_child_exit_watch`, `reinit_after_fork`,
    // `take_pending_in_for`, ...) are macOS host-signal-pump mechanisms with no
    // Linux analogue, or paths the dispatcher already covers; they remain inert.
    pub fn forget_thread(tid: i32) {
        lock_pending().remove(&tid);
    }
    pub fn has_pending_for(tid: i32) -> bool {
        lock_pending().get(&tid).is_some_and(|&mask| mask != 0)
    }
    pub fn last_sender_for(_signum: i32) -> i32 {
        0
    }
    pub fn register_child_exit_watch(_child_pid: i32, _parent_tid: i32, _exit_signal: i32) {}
    pub fn reinit_after_fork() {}
    /// Pop the lowest-numbered pending signal for `tid` (clearing its bit), or
    /// `0` if none. The single point of consumption in
    /// `vcpu_loop::deliver_pending_signal`.
    pub fn take_pending_for(tid: i32) -> i32 {
        let mut guard = lock_pending();
        if let Some(mask) = guard.get_mut(&tid)
            && *mask != 0
        {
            let signum = mask.trailing_zeros() as i32 + 1;
            *mask &= *mask - 1; // clear the lowest set bit
            if *mask == 0 {
                guard.remove(&tid);
            }
            return signum;
        }
        NO_PENDING_SIGNAL
    }
    pub fn wake_all_waiters() {}
}

#[cfg(not(feature = "platform-macos"))]
pub mod io_wait {
    use std::os::fd::RawFd;
    use std::time::{Duration, Instant};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WaitFd {
        fd: RawFd,
        events: i16,
        anchored: bool,
    }

    impl WaitFd {
        pub fn raw(fd: RawFd, events: i16) -> Self {
            Self {
                fd,
                events,
                anchored: false,
            }
        }
        pub fn anchored(fd: RawFd, events: i16) -> Self {
            Self {
                fd,
                events,
                anchored: true,
            }
        }
        pub fn fd(&self) -> RawFd {
            self.fd
        }
        pub fn events(&self) -> i16 {
            self.events
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WaitResult {
        Ready,
        TimedOut,
        Interrupted,
        Errno(i32),
    }

    /// The Linux per-thread blocking-I/O waiter (Phase C). Where the macOS
    /// waiter owns a kqueue, the Linux waiter is a stateless `ppoll(2)`: the run
    /// loop hands it the host fds the dispatcher wants to block on (plus an
    /// optional timeout), and it polls them in one call. That matches the
    /// run-loop contract exactly — wait, then re-dispatch the same syscall on
    /// readiness — without persistent fd registration (a persistent epoll is for
    /// guest *epoll-fd emulation*, a later slice).
    ///
    /// `block_mask` (the guest's atomically-blocked sigmask for ppoll/pselect)
    /// is ignored for now: carrick does not yet deliver guest signals as host
    /// signals, so there is nothing to block. Spurious HOST signals are absorbed
    /// by retrying `ppoll` for the remaining time (no guest `EINTR` is fabricated
    /// — real signal delivery is the later signal slice).
    pub struct ThreadWaiter;

    impl ThreadWaiter {
        pub fn new(_tid: crate::thread::ThreadId) -> Self {
            Self
        }

        /// No-op: `ppoll` needs no per-wait setup (the macOS waiter lazily
        /// creates its kqueue here).
        pub fn ensure_full(&mut self) {}

        pub fn wait(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: u64,
        ) -> WaitResult {
            ppoll_wait(fds, timeout, block_mask)
        }

        /// `poll(2)`-flavoured wait. On Linux this is the same `ppoll` as
        /// [`wait`](Self::wait) — both take pollfd-style (fd, events) pairs.
        pub fn wait_poll(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: u64,
        ) -> WaitResult {
            ppoll_wait(fds, timeout, block_mask)
        }

        /// Wait for a guest child process to become reapable (Phase 2 Task 7).
        ///
        /// carrick's guest children are REAL host processes (the generic loop's
        /// `handle_fork` runs `libc::fork`), so the parent's blocking `wait4` /
        /// `waitid` parks here until the host child exits, then the run loop
        /// re-dispatches the wait to reap it. We poll the child with
        /// `waitid(WEXITED | WNOWAIT | WNOHANG)` — `WNOWAIT` PEEKS and leaves the
        /// zombie reapable for the caller's re-dispatched `wait4` to consume —
        /// sleeping between polls in an interruptible `ppoll` slice so a pending
        /// host signal (a kick) or a fork quiesce surfaces promptly as
        /// `Interrupted` rather than wedging the parent. `pid > 0` watches that
        /// specific child; `pid <= 0` watches ANY child (`P_ALL`), matching the
        /// guest `wait4(-1, …)` / `wait4(0, …)` "any child" forms.
        pub fn wait_proc_exit(&self, pid: i32, _block_mask: u64) -> WaitResult {
            loop {
                if child_status_ready(pid) {
                    return WaitResult::Ready;
                }
                // Still running. Park briefly (≤50 ms) in an empty `ppoll` so a
                // delivered signal returns `Interrupted` (the loop maps that to
                // EINTR / a fork-quiesce park), then re-poll the child. Not a busy
                // spin — each idle slice sleeps in `ppoll`.
                // TimedOut (slice elapsed) or a spurious Ready: re-poll the
                // child at the loop top; only an Interrupted bails out.
                if let WaitResult::Interrupted = ppoll_wait(&[], Some(Duration::from_millis(50)), 0)
                {
                    return WaitResult::Interrupted;
                }
            }
        }
    }

    /// True when `pid` is a terminally-exited (CLD_EXITED/KILLED/DUMPED)
    /// reapable child, WITHOUT consuming it (`WNOWAIT` leaves the zombie for the
    /// caller's re-dispatched `wait4`/`waitid` to reap). `pid > 0` probes that
    /// child (`P_PID`); `pid <= 0` probes any child (`P_ALL`). On `ECHILD` (the
    /// child was already reaped, or is not ours) we report ready so the caller
    /// surfaces the real status / `ECHILD` exactly as it would without this
    /// backstop.
    fn child_status_ready(pid: i32) -> bool {
        let (idtype, id) = if pid > 0 {
            (libc::P_PID, pid as libc::id_t)
        } else {
            (libc::P_ALL, 0 as libc::id_t)
        };
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                idtype,
                id,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if rc == 0 {
            // si_signo/si_code are zeroed by us before the call; a real reapable
            // child sets si_pid != 0 and a terminal CLD_* code. (WNOHANG with no
            // ready child returns 0 with si_pid == 0 on Linux.)
            const CLD_EXITED: i32 = 1;
            const CLD_KILLED: i32 = 2;
            const CLD_DUMPED: i32 = 3;
            let si_pid = carrick_portable::si_pid(&info);
            si_pid != 0 && matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED)
        } else {
            // ECHILD: already reaped (or never ours) → ready, so the caller's
            // re-dispatched wait surfaces the real status/ECHILD. Any other errno
            // (EINVAL etc.) → not ready, re-poll.
            std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
        }
    }

    fn ppoll_wait(fds: &[WaitFd], timeout: Option<Duration>, _block_mask: u64) -> WaitResult {
        let mut pollfds: Vec<libc::pollfd> = fds
            .iter()
            .map(|w| libc::pollfd {
                fd: w.fd(),
                events: w.events(),
                revents: 0,
            })
            .collect();
        // Re-arm with the REMAINING time across spurious host-EINTR so a signal
        // storm can't extend the wait past the deadline.
        let deadline = timeout.map(|d| Instant::now() + d);
        loop {
            let ts = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return WaitResult::TimedOut;
                    }
                    let rem = dl - now;
                    Some(libc::timespec {
                        tv_sec: rem.as_secs().min(i64::MAX as u64) as libc::time_t,
                        tv_nsec: rem.subsec_nanos() as libc::c_long,
                    })
                }
                None => None,
            };
            let tsp = ts
                .as_ref()
                .map_or(std::ptr::null(), |t| t as *const libc::timespec);
            // SAFETY: `pollfds` is a valid array of `pollfds.len()` entries; `tsp`
            // is NULL or a valid timespec; NULL sigmask (no atomic mask swap).
            let n = unsafe {
                libc::ppoll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    tsp,
                    std::ptr::null(),
                )
            };
            if n > 0 {
                return WaitResult::Ready;
            }
            if n == 0 {
                return WaitResult::TimedOut;
            }
            let err = unsafe { *libc::__errno_location() };
            if err == libc::EINTR {
                // Spurious host signal; no guest signal delivery yet — retry.
                continue;
            }
            return WaitResult::Errno(crate::host_to_linux_errno(err));
        }
    }
}

// Wall-clock timer-signal delivery for the non-macOS (KVM/Linux) backend. Where
// macOS arms an EVFILT_TIMER on the kqueue signal pump, the Linux backend has no
// pump: a fallback timer THREAD (spawned by `itimer`/`posix_timer` below) sleeps
// to the deadline and then PUBLISHES the timer signal into the per-thread pending
// table and KICKS the target vCPU so the generic loop runs delivery. The target
// is registered once when the run loop starts (`register`).
#[cfg(not(feature = "platform-macos"))]
pub mod timer_delivery {
    use crate::thread::ThreadId;
    use std::sync::{Arc, Mutex, OnceLock};

    struct Delivery {
        kicker: Arc<dyn carrick_hal::VcpuRegistry>,
        // Wall-clock interval timers are process-directed; deliver to the main
        // thread (the common single-threaded timer case). A blocked-main /
        // multi-thread fan-out is a future refinement.
        main_tid: ThreadId,
    }

    fn cell() -> &'static Mutex<Option<Delivery>> {
        static C: OnceLock<Mutex<Option<Delivery>>> = OnceLock::new();
        C.get_or_init(|| Mutex::new(None))
    }
    fn lock() -> std::sync::MutexGuard<'static, Option<Delivery>> {
        cell()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Install the kicker + target tid. Called once at run-loop startup.
    pub fn register(kicker: Arc<dyn carrick_hal::VcpuRegistry>, main_tid: ThreadId) {
        *lock() = Some(Delivery { kicker, main_tid });
    }

    /// Publish `signum` to the target thread and kick its vCPU. No-op if no run
    /// loop has registered (e.g. a unit test exercising arm/disarm only).
    pub fn deliver(signum: i32) {
        if let Some(d) = lock().as_ref() {
            crate::host_signal::publish_pending_for(d.main_tid, signum);
            d.kicker.kick(d.main_tid);
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod itimer {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    struct Slot {
        generation: AtomicU64,
        interval_ns: AtomicU64,
        armed: AtomicBool,
    }
    impl Slot {
        fn new() -> Self {
            Self {
                generation: AtomicU64::new(0),
                interval_ns: AtomicU64::new(0),
                armed: AtomicBool::new(false),
            }
        }
    }
    // ITIMER_REAL / ITIMER_VIRTUAL / ITIMER_PROF.
    fn slots() -> &'static [Slot; 3] {
        static S: OnceLock<[Slot; 3]> = OnceLock::new();
        S.get_or_init(|| [Slot::new(), Slot::new(), Slot::new()])
    }

    pub fn ident_for(which: usize) -> usize {
        which
    }
    pub fn which_for_ident(ident: usize) -> Option<usize> {
        (ident < 3).then_some(ident)
    }
    pub fn signum_for(which: usize) -> i32 {
        match which {
            1 => crate::linux_abi::LINUX_SIGVTALRM, // ITIMER_VIRTUAL
            2 => crate::linux_abi::LINUX_SIGPROF,   // ITIMER_PROF
            _ => crate::linux_abi::LINUX_SIGALRM,   // ITIMER_REAL
        }
    }
    /// ITIMER_VIRTUAL/ITIMER_PROF measure GUEST CPU time, which carrick does not
    /// account here — they are tracked (getitimer reports them) but NOT fired.
    pub fn is_cpu_timer(which: usize) -> bool {
        which == 1 || which == 2
    }
    pub fn arm(which: usize, _value_ns: u64, interval_ns: u64, _needs_periodic: bool) -> u64 {
        match slots().get(which) {
            Some(slot) => {
                let generation = slot
                    .generation
                    .fetch_add(1, Ordering::SeqCst)
                    .wrapping_add(1);
                slot.interval_ns.store(interval_ns, Ordering::SeqCst);
                slot.armed.store(true, Ordering::SeqCst);
                generation
            }
            None => 0,
        }
    }
    pub fn disarm(which: usize) {
        if let Some(slot) = slots().get(which) {
            slot.generation.fetch_add(1, Ordering::SeqCst);
            slot.armed.store(false, Ordering::SeqCst);
            slot.interval_ns.store(0, Ordering::SeqCst);
        }
    }
    pub fn is_armed(which: usize) -> bool {
        slots()
            .get(which)
            .is_some_and(|s| s.armed.load(Ordering::SeqCst))
    }
    pub fn interval_ns(which: usize) -> u64 {
        slots()
            .get(which)
            .map_or(0, |s| s.interval_ns.load(Ordering::SeqCst))
    }
    pub fn cpu_timer_recheck_delay_ns(remaining_cpu_ns: u64) -> u64 {
        remaining_cpu_ns
    }
    fn generation_matches(which: usize, generation: u64) -> bool {
        slots()
            .get(which)
            .is_some_and(|s| s.generation.load(Ordering::SeqCst) == generation)
    }

    /// Spawn the wall-clock fallback timer thread for `which`. It sleeps to the
    /// first deadline, then (if still armed with this `generation`) publishes the
    /// signal + kicks via `timer_delivery`, repeating every `interval` until the
    /// timer is disarmed or re-armed (generation bump). CPU-time timers are not
    /// fired (no guest-CPU accounting). At most one thread per `which` is live —
    /// a disarm/re-arm bumps the generation so the old thread exits.
    pub fn spawn_fallback_timer(
        which: usize,
        generation: u64,
        value: Duration,
        interval: Duration,
    ) {
        if is_cpu_timer(which) {
            return;
        }
        let signum = signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                std::thread::sleep(value);
                if !generation_matches(which, generation) {
                    return;
                }
                crate::timer_delivery::deliver(signum);
                if interval.is_zero() {
                    return;
                }
                loop {
                    std::thread::sleep(interval);
                    if !generation_matches(which, generation) {
                        return;
                    }
                    crate::timer_delivery::deliver(signum);
                }
            });
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod posix_timer {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TimerSpec {
        pub signum: i32,
        pub value_ns: u64,
        pub interval_ns: u64,
    }

    struct Slot {
        clock_id: i32,
        signum: i32,
        generation: u64,
        value_ns: u64,
        interval_ns: u64,
        armed_at: Option<Instant>,
    }

    fn timers() -> &'static Mutex<HashMap<i32, Slot>> {
        static T: OnceLock<Mutex<HashMap<i32, Slot>>> = OnceLock::new();
        T.get_or_init(|| Mutex::new(HashMap::new()))
    }
    fn lock() -> std::sync::MutexGuard<'static, HashMap<i32, Slot>> {
        timers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn next_id() -> i32 {
        static N: AtomicI32 = AtomicI32::new(1);
        N.fetch_add(1, Ordering::SeqCst)
    }

    pub fn create(clock_id: i32, signum: i32) -> i32 {
        let id = next_id();
        lock().insert(
            id,
            Slot {
                clock_id,
                signum,
                generation: 0,
                value_ns: 0,
                interval_ns: 0,
                armed_at: None,
            },
        );
        id
    }

    /// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
    /// old_value). A `value_ns == 0` disarms. A non-zero value spawns a wall-clock
    /// firing thread that delivers `signum` after `value` then every `interval`,
    /// until the timer is re-armed or deleted (generation bump).
    pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<TimerSpec> {
        let (prev, generation, signum) = {
            let mut g = lock();
            let slot = g.get_mut(&id)?;
            let prev = TimerSpec {
                signum: slot.signum,
                value_ns: slot.value_ns,
                interval_ns: slot.interval_ns,
            };
            slot.generation = slot.generation.wrapping_add(1);
            slot.value_ns = value_ns;
            slot.interval_ns = interval_ns;
            slot.armed_at = (value_ns > 0).then(Instant::now);
            (prev, slot.generation, slot.signum)
        };
        if value_ns > 0 {
            spawn_timer(
                id,
                generation,
                signum,
                Duration::from_nanos(value_ns),
                Duration::from_nanos(interval_ns),
            );
        }
        Some(prev)
    }

    fn generation_matches(id: i32, generation: u64) -> bool {
        lock().get(&id).is_some_and(|s| s.generation == generation)
    }

    fn spawn_timer(id: i32, generation: u64, signum: i32, value: Duration, interval: Duration) {
        let _ = std::thread::Builder::new()
            .name(format!("carrick-ptimer-{id}"))
            .spawn(move || {
                std::thread::sleep(value);
                if !generation_matches(id, generation) {
                    return;
                }
                crate::timer_delivery::deliver(signum);
                if interval.is_zero() {
                    return;
                }
                loop {
                    std::thread::sleep(interval);
                    if !generation_matches(id, generation) {
                        return;
                    }
                    crate::timer_delivery::deliver(signum);
                }
            });
    }

    /// `timer_gettime`: time until the next expiration + the reload interval.
    /// One-shot remaining counts down from arm; an already-fired one-shot is 0.
    pub fn remaining(id: i32) -> Option<(u64, u64)> {
        let g = lock();
        let slot = g.get(&id)?;
        let value = match (slot.armed_at, slot.value_ns) {
            (Some(at), v) if v > 0 => {
                let elapsed = u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX);
                if elapsed >= v && slot.interval_ns == 0 {
                    0
                } else if slot.interval_ns > 0 {
                    // After the first fire, the next expiry is `interval` phased.
                    let into = elapsed.saturating_sub(v) % slot.interval_ns;
                    if elapsed < v {
                        v - elapsed
                    } else {
                        slot.interval_ns - into
                    }
                } else {
                    v - elapsed
                }
            }
            _ => 0,
        };
        Some((value, slot.interval_ns))
    }

    pub fn delete(id: i32) -> bool {
        // Removing the slot makes `generation_matches` false, so any live firing
        // thread exits at its next deadline.
        lock().remove(&id).is_some()
    }
    pub fn getoverrun(id: i32) -> Option<u32> {
        lock().contains_key(&id).then_some(0)
    }
    pub fn exists(id: i32) -> bool {
        lock().contains_key(&id)
    }
    pub fn clock_id(id: i32) -> i32 {
        lock().get(&id).map_or(0, |s| s.clock_id)
    }
    pub fn clear() {
        lock().clear();
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod shared_aperture {
    use crate::memory::{LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE};
    use carrick_abi::align_up_u64;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BackingObject {
        SharedAnon,
        SharedFile { host_fd: i32, offset: u64 },
        PrivateAnon,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct SharedAlloc {
        pub guest_addr: u64,
        pub len: u64,
        pub backing: BackingObject,
        pub source: Option<u64>,
    }

    #[derive(Debug, Clone)]
    pub struct SharedAperture {
        base: u64,
        size: u64,
        next: u64,
        free: Vec<(u64, u64)>,
        live: Vec<SharedAlloc>,
    }

    const GRANULE: u64 = 0x4000;

    impl Default for SharedAperture {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SharedAperture {
        pub fn new() -> Self {
            Self::with_window(LINUX_SHARED_FILE_BASE, LINUX_SHARED_FILE_SIZE)
        }

        pub fn with_window(base: u64, size: u64) -> Self {
            Self {
                base,
                size,
                next: base,
                free: Vec::new(),
                live: Vec::new(),
            }
        }

        fn window_end(&self) -> u64 {
            self.base + self.size
        }

        pub fn alloc(&mut self, len: u64, backing: BackingObject) -> Option<u64> {
            self.alloc_sourced_with_reuse(len, backing, None)
                .map(|(addr, _reused)| addr)
        }

        pub fn alloc_sourced(
            &mut self,
            len: u64,
            backing: BackingObject,
            source: Option<u64>,
        ) -> Option<u64> {
            self.alloc_sourced_with_reuse(len, backing, source)
                .map(|(addr, _reused)| addr)
        }

        pub fn alloc_sourced_with_reuse(
            &mut self,
            len: u64,
            backing: BackingObject,
            source: Option<u64>,
        ) -> Option<(u64, bool)> {
            if len == 0 {
                return None;
            }
            let len = align_up_u64(len, GRANULE)?;
            if let Some(pos) = self.free.iter().position(|&(_, l)| l >= len) {
                let (s, l) = self.free[pos];
                if l == len {
                    self.free.remove(pos);
                } else {
                    self.free[pos] = (s + len, l - len);
                }
                self.live.push(SharedAlloc {
                    guest_addr: s,
                    len,
                    backing,
                    source,
                });
                return Some((s, true));
            }
            let addr = align_up_u64(self.next, GRANULE)?;
            let end = addr.checked_add(len)?;
            if end > self.window_end() {
                return None;
            }
            self.next = end;
            self.live.push(SharedAlloc {
                guest_addr: addr,
                len,
                backing,
                source,
            });
            Some((addr, false))
        }

        pub fn find_by_source(&self, source: u64) -> Option<u64> {
            self.live
                .iter()
                .find(|a| a.source == Some(source))
                .map(|a| a.guest_addr)
        }

        pub fn free(&mut self, guest_addr: u64) -> Option<SharedAlloc> {
            let pos = self.live.iter().position(|a| a.guest_addr == guest_addr)?;
            let alloc = self.live.remove(pos);
            free_insert(&mut self.free, alloc.guest_addr, alloc.len);
            Some(alloc)
        }

        pub fn live(&self) -> &[SharedAlloc] {
            &self.live
        }
    }

    fn free_insert(regions: &mut Vec<(u64, u64)>, addr: u64, len: u64) {
        let mut start = addr;
        let mut end = addr.saturating_add(len);
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(regions.len() + 1);
        let mut inserted = false;
        for &(s, l) in regions.iter() {
            let e = s.saturating_add(l);
            if e < start || s > end {
                if !inserted && s > end {
                    out.push((start, end - start));
                    inserted = true;
                }
                out.push((s, l));
            } else {
                start = start.min(s);
                end = end.max(e);
            }
        }
        if !inserted {
            out.push((start, end - start));
        }
        out.sort_by_key(|&(s, _)| s);
        *regions = out;
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod compat {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SyscallArgs(pub [u64; 6]);

    impl From<[u64; 6]> for SyscallArgs {
        fn from(args: [u64; 6]) -> Self {
            Self(args)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GuestRegs {
        pub pc: u64,
        pub sp: u64,
        pub fp: u64,
        pub lr: u64,
        pub x8: u64,
        pub x0: u64,
        pub stack_guest_base: u64,
        pub stack_host_base: u64,
        pub stack_guest_end: u64,
    }

    pub struct CompatReporter;
    impl CompatReporter {
        pub fn record(&self, _event: CompatEvent) {}
        /// Snapshot the (empty) compat report. The KVM MVP loop builds a
        /// `RunResult` with this; full compat reporting is a later slice.
        pub fn snapshot(&self) -> CompatReport {
            CompatReport::default()
        }
        /// Consume the reporter and produce the (empty, scaffolded) report — the
        /// Linux mirror of the macOS `CompatReporter::finish`. Compat reporting is
        /// scaffolded on BOTH backends (the CLI warns and emits an empty report),
        /// so this keeps `carrick dispatch-syscall` working on Linux. The richer
        /// `compat-report --format` (which needs the HVF `CompatReportFormat`
        /// renderer) stays macOS-only.
        pub fn finish(self) -> CompatReport {
            self.snapshot()
        }
    }
    impl Default for CompatReporter {
        fn default() -> Self {
            Self
        }
    }

    /// JSON-serialisable compatibility report. The macOS reporter records guest
    /// syscall coverage; the Linux KVM MVP carries an empty report so the
    /// cross-platform `RunResult` has a single shape on both backends.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CompatReport {
        pub events: Vec<CompatEvent>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum CompatEvent {
        SyscallEntry {
            number: u64,
            name: std::borrow::Cow<'static, str>,
            args: SyscallArgs,
        },
        SyscallReturn {
            number: u64,
            name: std::borrow::Cow<'static, str>,
            retval: i64,
            errno: Option<i32>,
        },
        UnhandledSyscall {
            number: u64,
            name: String,
            args: SyscallArgs,
        },
        PartialSyscall {
            number: u64,
            name: String,
            args: SyscallArgs,
            reason: String,
        },
        UnhandledIoctl {
            fd: i32,
            request: u64,
            arg: u64,
        },
        ProcReadUnimplemented {
            path: String,
        },
        SysReadUnimplemented {
            path: String,
        },
        SignalUnsupported {
            signum: i32,
            reason: String,
        },
        UnknownSyscallFlags {
            number: u64,
            name: String,
            argument: u32,
            unknown_bits: u64,
        },
    }
    impl CompatEvent {
        pub fn unhandled_syscall(number: u64, name: impl Into<String>, args: SyscallArgs) -> Self {
            Self::UnhandledSyscall {
                number,
                name: name.into(),
                args,
            }
        }
        pub fn partial_syscall(
            number: u64,
            name: impl Into<String>,
            args: SyscallArgs,
            reason: impl Into<String>,
        ) -> Self {
            Self::PartialSyscall {
                number,
                name: name.into(),
                args,
                reason: reason.into(),
            }
        }
        pub fn unhandled_ioctl(fd: i32, request: u64, arg: u64) -> Self {
            Self::UnhandledIoctl { fd, request, arg }
        }
        pub fn proc_read_unimplemented(path: impl Into<String>) -> Self {
            Self::ProcReadUnimplemented { path: path.into() }
        }
        pub fn sys_read_unimplemented(path: impl Into<String>) -> Self {
            Self::SysReadUnimplemented { path: path.into() }
        }
        pub fn unknown_syscall_flags(
            number: u64,
            name: impl Into<String>,
            argument: u32,
            unknown_bits: u64,
        ) -> Self {
            Self::UnknownSyscallFlags {
                number,
                name: name.into(),
                argument,
                unknown_bits,
            }
        }
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod syscall {
    /// `Serialize` so the CLI's `carrick syscalls <n>` per-number lookup works on
    /// Linux (the macOS `carrick_hvf::syscall::Syscall` is serializable too). The
    /// full-table dump (`aarch64_table`) stays macOS-only.
    #[derive(serde::Serialize)]
    pub struct Syscall {
        pub name: &'static str,
    }
    pub fn lookup_aarch64(_number: u64) -> Option<&'static Syscall> {
        None
    }
}

#[cfg(not(feature = "platform-macos"))]
pub mod probes {
    macro_rules! stub {
        ($name:ident($($param:ident: $ty:ty),* $(,)?)) => {
            #[allow(dead_code, unused_variables)]
            #[inline(always)]
            pub fn $name($($param: $ty),*) {}
        };
    }

    stub!(fork_pre(pc: u64, elr: u64, cpsr: u64));
    stub!(path_open(path: &str, result_size: u64, errno: i32));
    stub!(itimer_fire(signum: i32, generation: u64));
    stub!(futex_route(addr: u64, op: i32, shared: i32, host_addr: u64));
    stub!(ulock_wait(host_addr: u64, value: u32, timeout_us: u32, phase: i32, rc: i64));
    stub!(ulock_wake(host_addr: u64, iter: i32, rc: i64));
    stub!(guest_exit(code: i32));
    stub!(lifecycle(phase: u32));
    stub!(execve_argv(path: &str, argv: &[Vec<u8>]));
    stub!(fs_op(op: &str, path: &str, errno: i32));
    stub!(host_pipe_io(host_fd: i32, dir: i32, n: i64));
    stub!(epoll_ctl(epfd: i32, op: u64, fd: i32, events: u32, data: u64, errno: i32));
    stub!(epoll_interest(epfd: i32, fd: i32, requested: u32, raw_ready: u32, last_ready: u32, ready: u32));
    stub!(epoll_wait_fd(epfd: i32, fd: i32, host_fd: i32, poll_events: i32, timeout_ms: i32));
    stub!(epoll_result(epfd: i32, ready_count: i32, wait_count: i32, timeout_ms: i32, kind: i32));
    stub!(io_wait_begin(tid: i32, fd_count: i32, timeout_ms: i64, fd0: i32, events0: i32, fd1: i32));
    stub!(io_wait_end(tid: i32, result: i32, fd_count: i32, fd0: i32, fd1: i32, fd2: i32));
    stub!(fork_quiesce(phase: i32, a: i64, b: i64, tid: i32));
    stub!(fork_post(pid: i32, pc: u64, elr: u64));
    stub!(signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64));
    stub!(signal_restore(saved_pc: u64, sp: u64, magic: u64));
    stub!(kick_in_kernel(pc: u64, el: u32));
    stub!(kick_stats(el1_resumed: u64, kick_inject: u64, inject_at_el1: u64));
    stub!(mem_watch(syscall_nr: u64, addr: u64, value: u64));
    stub!(sigaction_read(signum: i32, w0: u64, w1: u64, w2: u64, w3: u64));
    stub!(supervisor_fork(child_pid: i32));
    stub!(supervisor_child_ready(runtime_pid: i32));
    stub!(supervisor_foreground_pgrp(pgid: i32, errno: i32));
    stub!(supervisor_child_exit(pid: i32, status: i32));
    stub!(pt_pause_begin(tid: i32, others_in_guest: i32, count: i32));
    stub!(pt_pause_ready(tid: i32, spins: i32, wait_us: i64));
    stub!(pt_pause_timeout(tid: i32, wait_us: i64));
    stub!(pt_pause_end(tid: i32));
    stub!(pt_pool(in_use: u32, free_list: u32, capacity: u32, changed: i32));
    stub!(pt_fault_walk(far: u64, l0: u64, l1: u64, l2: u64, l3: u64));
    stub!(guest_mem_bytes(direction: u32, address: u64, bytes: &[u8]));
    stub!(vcpu_trap(regs: &crate::compat::GuestRegs));
    stub!(execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64));
    stub!(execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64));
    stub!(vcpu_fault(esr: u64, elr: u64, far: u64, x30: u64, sp: u64, tid: i32));
    stub!(vcpu_fault_regs(esr: u64, elr: u64, far: u64, insn: u64, rn: u32, xrn: u64));
    stub!(pt_alias_walk(va: u64, descs: [u64; 4], flag: i32));
    stub!(hv_vm_map_alias(va: u64, ipa: u64, size: u64, rc: i32, forked: i32));
    stub!(signal_publish(target_tid: i32, signum: i32, kind: i32));
    stub!(signal_deliver(tid: i32, pending: i32));
    stub!(fire(event: &crate::compat::CompatEvent));

    #[allow(dead_code)]
    pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
        Ok(())
    }
}
