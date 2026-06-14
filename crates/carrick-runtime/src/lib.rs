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
pub mod event_mux;
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
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::{
    fork_coord, host_signal, io_wait, itimer, posix_timer, probes, signal_arrival, threaded_impl,
    trap, vcpu_kick,
};
// The HVF `TimerDelivery` impl. Re-exported under `timer_delivery_impl` (the
// `timer_delivery` name is the runtime's own register/deliver module above), so
// the macOS run-loop startup can name `HvfTimerDelivery`.
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::timer_delivery as timer_delivery_impl;
// The syscall-compat reporter is platform-neutral; it lives in
// carrick-observability so every backend shares the REAL recorder (the Linux/KVM
// arm was a no-op unit-struct stub; bhyve would have inherited it). DTrace
// backends install the per-event probe-fire hook via `compat::set_probe_hook` in
// their probe registration; Linux/bhyve leave it unset. Re-exported at
// `crate::compat` so all call sites are unchanged.
pub use carrick_observability::compat;
// AArch64 syscall metadata is platform-neutral ABI data, hoisted to carrick-abi
// so every backend shares ONE table (the Linux/KVM arm was a `lookup → None`
// stub; bhyve would have inherited it). Re-exported at `crate::syscall` so the
// dispatcher / CLI / compat reporter call sites are unchanged on both platforms.
pub use carrick_abi::syscall;
// The shared-aperture sub-allocator is platform-NEUTRAL host-memory bookkeeping
// (the stage-2 REGISTRATION of the window is the per-backend glue, not this
// carver). It lives in carrick-mem so every backend — HVF, KVM, and bhyve —
// consumes ONE allocator instead of the old cfg split (HVF re-export vs a Linux
// inline reimplementation). Re-exported at `crate::shared_aperture` so
// dispatch/mem.rs is unchanged.
pub use carrick_mem::shared_aperture;
// thread (ThreadRegistry/FutexTable) + fork_quiesce barriers are
// hypervisor-agnostic; both backends use the real carrick-thread impls.
pub use carrick_thread::{fork_quiesce, thread};
// `current_thread_states` queries the kernel for per-thread run-state via the
// Mach port recorded by each vCPU thread. On macOS the real implementation
// (in carrick-hvf::thread) issues `thread_info`; on Linux there are no Mach
// ports, so we return every registered thread with state 'R' (running).
#[cfg(feature = "platform-macos")]
pub use carrick_hvf::thread::current_thread_states;
#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
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
#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod trap {
    pub use carrick_hal::{ForkOutcome, RawSyscall, SyscallTrap, TrapError};
    pub const HVF_PAGE_SIZE: u64 = 0x4000;

    // Cross-process VM-topology bookkeeping the shared threaded loop references
    // around a guest fork/exec. The shared `vcpu_loop` fork/exec paths RUN on
    // Linux (the generic threaded loop drives them on both backends since the
    // Phase 2 KVM bring-up); what differs is how much host-side VM surgery
    // each backend needs. On HVF these hooks coordinate the stop-the-world VM
    // teardown/rebuild (carrick-hvf::trap); KVM forks by rebuilding a fresh VM
    // in the CHILD only, so the HVF-specific hooks below stay inert no-ops —
    // same pattern as the `host_signal` / `probes` Linux stubs below.

    /// Count of live vCPUs — the execve thread-group drain invariant on BOTH
    /// backends (`terminate_siblings_for_exec` spin-waits for `<= 1` after
    /// kicking siblings, so the exec teardown can't free guest RAM under a
    /// still-running sibling). On platform-linux this is the REAL counter
    /// maintained by the KVM engine (vcpu construction / sibling-spec tickets
    /// / KvmVcpu::drop); only non-linux scaffolding (bhyve) gets an inert
    /// always-0 stub (no drain) until it implements the same contract.
    #[cfg(feature = "platform-linux")]
    pub use carrick_linux::kvm::VCPU_LIVE;
    #[cfg(not(feature = "platform-linux"))]
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
// shared by the generic threaded `vcpu_loop` on BOTH backends — the HVF setup
// wrapper on macOS and `run_threaded_kvm_loop` on Linux (the `runtime` modules
// below).
pub mod run_result;

// The multi-threaded vCPU run loop, generic over `carrick_hal::ThreadedEngine`.
// Unconditional (compiles on both platforms) and the SHARED threaded run path on
// BOTH backends: the generic `run_vcpu_until_exit` is instantiated on macOS by
// the HVF setup wrapper in `runtime`, and on Linux by `run_threaded_kvm_loop`
// (which `runtime::run_oci` / `run_elf_real_dispatch` drive over `KvmTrapEngine`).
// So the module is live on Linux too — NOT dead code — and carries no `#[allow]`.
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

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod execute {
    // Shared on the non-macOS lane (used by /proc + uname on every backend).
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
    // Linux-lane run entry (drives the KVM OCI path via run_oci); the BSD/bhyve
    // run entry is wired in #1. guest_hostname above stays shared.
    #[cfg(feature = "platform-linux")]
    pub struct Runtime;

    #[cfg(feature = "platform-linux")]
    impl Runtime {
        pub fn execute(
            spec: &carrick_spec::RunSpec,
        ) -> Result<crate::run_result::RunResult, crate::run_result::RuntimeError> {
            crate::runtime::run_oci(spec)
        }
    }
}

#[cfg(feature = "platform-linux")]
pub use execute::Runtime;

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod runtime {
    //! Linux (KVM) run path. The full macOS run loop lives in `runtime.rs`
    //! (`cfg(platform-macos)`); on Linux we drive `carrick_linux::KvmTrapEngine`
    //! through the REAL `SyscallDispatcher` on the SAME generic threaded
    //! `vcpu_loop` the HVF backend uses, via `run_threaded_kvm_loop` (which
    //! `run_oci` / `run_elf_real_dispatch` invoke). It mirrors the macOS loop's
    //! non-blocking outcome handling (`Returned`/`Errno`/`Exit`); blocking I/O,
    //! futex, and fork/exec/threads/signal-injection are all wired through the
    //! shared loop (Phase 2 + Phase 4 complete), not stubbed `Unsupported`.
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
                let a = frame.args;
                eprintln!(
                    "trap#{traps}: nr={} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                    frame.number, a[0], a[1], a[2], a[3], a[4], a[5]
                );
            }
            // Dispatch, servicing any blocking-I/O wait inline (ppoll) and
            // re-dispatching on readiness, so the returned outcome is terminal.
            let outcome = service_syscall(
                &mut dispatcher,
                SyscallRequest::from_raw(frame),
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
    /// (`crate::io_wait`).
    #[cfg(feature = "platform-linux")]
    pub fn run_threaded_kvm_loop<E>(
        engine: E,
        dispatcher: SyscallDispatcher,
        max_traps: usize,
    ) -> Result<RunResult, RuntimeError>
    where
        E: carrick_hal::ThreadedEngine<KickHandle = carrick_linux::KvmKickHandle> + 'static,
        E::SiblingSpec: 'static,
    {
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
        // The KVM kicker (registry of live vCPUs). Held object-safe as the
        // `VcpuRegistry` the generic loop drives. Constructing it installs the
        // kick-signal handler (idempotent) so a cross-thread `pthread_kill` forces
        // a target vCPU out of `KVM_RUN` (→ `EINTR` → `VcpuExit::Kicked`). Built
        // before the kernel so `KvmSignalArrival` can wake a target vCPU via it.
        let kicker: Arc<dyn carrick_hal::VcpuRegistry> = Arc::new(carrick_linux::KvmKicker::new());
        // The KVM signal ARRIVAL/wake mechanism: kicker + futex. The async
        // host-signal pump is now implemented via `KvmForkCoordinator` /
        // `kvm_signal_pump`, and cross-process signal delivery via the shared
        // `carrick_signal_core::xsig` ring + `kvm_xsig` (the dispatcher reaches
        // these through `crate::host_signal::xsig_*`, so this `SignalArrival`
        // value only carries the kicker + futex wake path). Held object-safe in
        // `KernelState`.
        let signal_arrival: Arc<dyn carrick_hal::SignalArrival> =
            Arc::new(carrick_linux::KvmSignalArrival {
                kicker: Arc::clone(&kicker),
                futex: Arc::clone(&platform_futex),
            });
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            fork_coordinator,
            signal_arrival,
        ));
        // Track spawned sibling threads so the process doesn't tear down while a
        // worker is mid-flight; joined after the main thread finishes.
        let threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
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
        // Install the backend `TimerDelivery` the dispatch arm reaches through
        // the process-global (`dispatch/time.rs` has no KernelState ref). KVM's
        // `arm_itimer` returns false → the dispatch arm spawns the shared
        // fallback thread; `arm_posix` spawns the POSIX firing thread here.
        crate::timer_delivery::register_delivery(Arc::new(carrick_linux::KvmTimerDelivery {
            kicker: Arc::clone(&kicker),
            main_tid,
        }));

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

    /// The FreeBSD/bhyve analogue of `run_threaded_kvm_loop` (M2 Tier 1).
    ///
    /// A near-verbatim clone of the KVM lane: it wires carrick-bhyve's newtypes
    /// (`Bhyve{Futex,ForkCoordinator,Kicker,SignalArrival,TimerDelivery}`) into the
    /// SHARED `run_vcpu_until_exit` loop, so x86_64 bhyve guests run through the same
    /// canonical dispatcher/fork/futex/timer plumbing as KVM and HVF. Lives here in
    /// carrick-runtime (where `KernelState` / `run_vcpu_until_exit` are pub(crate));
    /// carrick-bhyve stays a leaf crate.
    #[cfg(feature = "platform-freebsd")]
    pub fn run_threaded_bhyve_loop<E>(
        engine: E,
        dispatcher: SyscallDispatcher,
        max_traps: usize,
    ) -> Result<RunResult, RuntimeError>
    where
        E: carrick_hal::ThreadedEngine<KickHandle = carrick_bhyve::BhyveKickHandle> + 'static,
        E::SiblingSpec: 'static,
    {
        use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
        use crate::vcpu_loop::{
            KernelState, PlatformFutexFactory, VcpuLoopOutcome, run_vcpu_until_exit,
        };
        use std::sync::Arc;

        let main_tid: ThreadId = std::process::id() as ThreadId;
        let registry = Arc::new(ThreadRegistry::new(main_tid));
        crate::thread::set_current_registry(Arc::clone(&registry));
        crate::host_proc::set_root_guest_pid(std::process::id());
        crate::guest_cpu::init_child_table();

        let futex = Arc::new(FutexTable::new());
        let platform_futex: Arc<dyn carrick_hal::PlatformFutex> =
            Arc::new(carrick_bhyve::BhyveFutex(Arc::clone(&futex)));
        let platform_futex_factory: PlatformFutexFactory = Arc::new(
            |table: Arc<FutexTable>| -> Arc<dyn carrick_hal::PlatformFutex> {
                Arc::new(carrick_bhyve::BhyveFutex(table))
            },
        );
        let fork_coordinator: Box<dyn carrick_hal::HostForkCoordinator> =
            Box::new(carrick_bhyve::BhyveForkCoordinator::new());
        let kicker: Arc<dyn carrick_hal::VcpuRegistry> =
            Arc::new(carrick_bhyve::BhyveKicker::new());
        let signal_arrival: Arc<dyn carrick_hal::SignalArrival> =
            Arc::new(carrick_bhyve::BhyveSignalArrival {
                kicker: Arc::clone(&kicker),
                futex: Arc::clone(&platform_futex),
            });
        let kernel = Arc::new(KernelState::new(
            dispatcher,
            fork_coordinator,
            signal_arrival,
        ));
        let threads: Arc<parking_lot::Mutex<Vec<std::thread::JoinHandle<()>>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));

        kernel.fork.start_signal_pump(&kicker, &platform_futex);

        crate::timer_delivery::register(Arc::clone(&kicker), main_tid);
        crate::timer_delivery::register_delivery(Arc::new(carrick_bhyve::BhyveTimerDelivery {
            kicker: Arc::clone(&kicker),
            main_tid,
        }));

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

    /// x86_64 bhyve run through the FULL `SyscallDispatcher` on the canonical loop
    /// (M2 Tier 1). Mirrors the x86_64 arm of `run_elf_real_dispatch`: build a
    /// `BhyveTrapEngine` via `carrick_bhyve::run_elf::build_x86_engine` and drive it
    /// through `run_threaded_bhyve_loop`. `CARRICK_NO_THREADS` falls back to the M1
    /// single-threaded `carrick_bhyve::run_elf::run_elf_bhyve` (which writes guest
    /// stdout/stderr straight to the host — hence empty buffers in the RunResult).
    /// The carrick-bhyve helpers return `Result<_, String>`; map those to
    /// `RuntimeError::Unsupported` (the variant the codebase uses for opaque
    /// backend messages).
    #[cfg(feature = "platform-freebsd")]
    pub fn run_elf_bhyve_dispatch(path: &std::path::Path) -> Result<RunResult, RuntimeError> {
        if std::env::var_os("CARRICK_NO_THREADS").is_some() {
            let code = carrick_bhyve::run_elf::run_elf_bhyve(path)
                .map_err(|e| RuntimeError::Unsupported(format!("run_elf_bhyve: {e}")))?;
            return Ok(RunResult {
                exit_code: code,
                stdout: Vec::new(),
                stderr: Vec::new(),
                traps: 0,
                report: crate::compat::CompatReport::default(),
                trap_limit_hit: false,
            });
        }
        let engine = carrick_bhyve::run_elf::build_x86_engine(path)
            .map_err(|e| RuntimeError::Unsupported(format!("build_x86_engine: {e}")))?;
        run_threaded_bhyve_loop(engine, make_linux_dispatcher(), DEFAULT_MAX_TRAPS)
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
    #[cfg(all(feature = "platform-linux", target_arch = "aarch64"))]
    pub fn run_elf_real_dispatch(path: &std::path::Path) -> Result<RunResult, RuntimeError> {
        // Build the full guest image WITH a Linux initial stack: argc/argv/envp
        // and the auxv (AT_RANDOM/AT_PLATFORM/AT_EXECFN) a real binary's CRT
        // reads before main. A freestanding fixture that ignores SP is
        // unaffected; a libc binary needs it. argv[0] is the path; a minimal
        // env keeps the CRT happy.
        let argv0 = path.to_string_lossy().into_owned();
        // Per-ISA vDSO bytes come from the engine's GuestArch (the x86_64
        // seam); this is the Linux/KVM path. Free function, so name the engine
        // explicitly (same idiom as `guest_setup::program_sysregs`).
        use carrick_hal::GuestArch as _;
        let vdso_bytes =
            <carrick_linux::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch::vdso_bytes();
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
            .with_vdso_bytes(vdso_bytes)?
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

    /// x86_64 KVM run through the FULL `SyscallDispatcher` (audit #1, M1).
    ///
    /// KVM runs same-arch guests, so the HOST arch selects the engine: on an
    /// x86_64 host this is `KvmX86TrapEngine`. That engine already satisfies
    /// `GuestMemory + SyscallTrap` — the only bounds `run_combined_syscall_loop_linux`
    /// requires — so this needs NO new trait impls. It drives the single-threaded
    /// combined loop through the real ~209-handler dispatcher (vs the standalone
    /// ~15-syscall `run_elf_kvm_x86` loop). fork/clone/futex/signal outcomes
    /// surface `Unsupported` here; full multithreading is M3 (`ThreadedEngine`).
    /// No vDSO on x86 yet (musl falls back to real `SYSCALL`; mirrors
    /// `run_elf_kvm_x86`'s `with_vdso_auxv(false)`).
    #[cfg(all(feature = "platform-linux", target_arch = "x86_64"))]
    pub fn run_elf_real_dispatch(path: &std::path::Path) -> Result<RunResult, RuntimeError> {
        use carrick_hal::GuestArch as _;
        let argv0 = path.to_string_lossy().into_owned();
        // Mirror run_elf_kvm_x86's image build EXACTLY (empty env) — a non-empty
        // env is a separate variable to introduce only once the bare path is proven.
        let image = crate::memory::AddressSpace::load_elf_for(
            path,
            carrick_hal::X8664GuestArch::elf_machine(),
        )?
        .with_linux_initial_stack([argv0.as_bytes()], std::iter::empty::<&[u8]>())?
        .with_vdso_auxv(false);
        let mut engine = carrick_linux::KvmX86TrapEngine::new(&image)?;
        // Default: the canonical multi-threaded loop, now SHARED with aarch64-KVM
        // and HVF (M3). `CARRICK_NO_THREADS` keeps the M1 single-threaded combined
        // loop reachable as an A/B fallback (mirrors the aarch64 arm). fork/clone/
        // futex/signal outcomes still surface Unsupported until M3c/M3d.
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
    #[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
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
    #[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
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
    // Used by the OCI run_oci path (aarch64-KVM); x86-KVM's run_oci is a stub until
    // OCI-x86 lands, so this is unused only on the x86_64 platform-linux build.
    #[cfg_attr(
        all(feature = "platform-linux", target_arch = "x86_64"),
        allow(dead_code)
    )]
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
    #[cfg(all(feature = "platform-linux", target_arch = "aarch64"))]
    pub fn run_oci(spec: &carrick_spec::RunSpec) -> Result<RunResult, RuntimeError> {
        use crate::fs_backend::HostFsBackend;
        use std::path::PathBuf;

        // 0. Docker's container init is a SESSION LEADER (runc setsid()s before
        //    exec'ing the entrypoint): a leader's own setpgid() is EPERM
        //    (ltp-setpgid01 case 1), getsid(0) == getpid(), and there is no
        //    controlling tty unless one is allocated. The macOS path gets this
        //    guest-visible state from the PID-namespace layer (ns-pid 1 +
        //    init_host_sid seeding → translate_setpgid_args EPERM); on Linux the
        //    HOST kernel is the source of truth for the passthrough process
        //    model, so make the guest init a REAL session leader. Best-effort:
        //    setsid(2) fails (EPERM) only when this process is already a
        //    process-group leader, in which case it keeps its current group —
        //    none of the CLI / conformance spawn shapes hit that.
        // SAFETY: setsid takes no arguments; on failure it changes nothing.
        unsafe {
            libc::setsid();
        }

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

        // Stream guest stdio straight to the inherited host fds, mirroring the
        // macOS `setup_interactive_stdio` raw arm (execute.rs) — the engine
        // resolves EVERY container run with `raw: true`. Without this the
        // KVM lane buffered bare-stdio writes in `io.stdout`/`io.stderr`
        // (flushed only at exit via the CLI's `emit_raw`) while a fd dup2'd
        // OVER stdio (an `open_files` entry wrapping a host dup) wrote LIVE —
        // so output interleaving broke, and when carrick's stdout was a
        // regular file the exit-time flush landed at the dup-shared kernel
        // offset, OVERWRITING earlier live bytes (cpython test_subprocess
        // test_close_fd_1's save/close/restore of fd 1 scrambled the suite
        // log). A forked child also drops its buffered copy on exit (only the
        // exit code crosses waitpid), so any buffered child output simply
        // vanished. `tty` has no pty supervisor on Linux yet; degrade it to
        // raw streaming rather than silently buffering.
        if spec.raw || spec.tty {
            dispatcher.set_stream_stdio(true);
        }

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
        // Per-ISA vDSO bytes come from the engine's GuestArch (the x86_64 seam);
        // this is the Linux/KVM path.
        use carrick_hal::GuestArch as _;
        let image = image.with_vdso_bytes(
            <carrick_linux::KvmTrapEngine as carrick_hal::ThreadedEngine>::Arch::vdso_bytes(),
        )?;

        // 4. Run on KVM through the same generic threaded loop as run-elf.
        let engine = carrick_linux::KvmTrapEngine::new(&image)?;
        run_threaded_kvm_loop(engine, dispatcher, spec.max_traps)
    }

    /// OCI container run on x86_64 is not yet wired: audit #1 M1 covers bare-ELF
    /// `run-elf` through the dispatcher; the OCI rootfs/entrypoint path on x86
    /// follows. Exists so the `carrick-kvm` bin compiles on an x86_64 host.
    #[cfg(all(feature = "platform-linux", target_arch = "x86_64"))]
    pub fn run_oci(_spec: &carrick_spec::RunSpec) -> Result<RunResult, RuntimeError> {
        Err(RuntimeError::Unsupported(
            "OCI run on x86_64 is not yet wired (M1 = bare-ELF run-elf through the dispatcher)"
                .to_string(),
        ))
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

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub fn host_to_linux_errno(host: i32) -> i32 {
    host
}

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod host_signal {
    // The platform-NEUTRAL pending bookkeeping (the THREAD_PENDING/PROC_PENDING
    // store, SENDER_PID, and their pure operations) lives in
    // `carrick-signal-core`, shared verbatim with the HVF backend. The KVM
    // backend has no host-signal pump, self-pipe, or xsignal ring, so its
    // `publish_pending_for`/`has_pending_for`/`take_pending_for`/... are EXACTLY
    // the core's pure forms — re-export them directly. A guest `tgkill`/`tkill`
    // (raise, pthread_kill) or a sibling-directed send of an UNBLOCKED signal is
    // published via `publish_pending_for`; the TARGET thread's run loop consumes
    // it via `take_pending_for` (in `vcpu_loop::deliver_pending_signal`) and
    // injects the handler. BLOCKED signals do NOT come here — they go to the
    // dispatcher's own per-thread pending set (`mark_signal_pending`, the
    // sigwait/sigtimedwait path). The caller is responsible for any cross-thread
    // wakeup (the runtime kicks the target vCPU right after, for the sibling
    // path); for a self-raise the publishing thread reaches
    // `deliver_pending_signal` itself on the next loop iteration.
    pub use carrick_signal_core::{
        NO_PENDING_SIGNAL, forget_thread, has_process_pending, last_sender_for,
        publish_pending_for, take_pending_for, take_pending_in_for,
    };

    // `has_pending_for` / `has_unblocked_pending_for` are NOT pure re-exports on
    // KVM: a cross-process guest signal may be sitting in the shared xsignal ring
    // (see `carrick_linux::kvm_xsig`), so a waiter must also peek the ring. These
    // wrappers fold the ring check over the neutral-core pending check, mirroring
    // the HVF backend's `host_signal::has_pending_for` / `has_unblocked_pending_for`.

    /// Is a signal deliverable to `tid` pending? True for a thread-directed signal
    /// for this tid, any process-directed signal, OR an unblocked self-targeted
    /// entry in the shared xsignal ring. Used by a parked thread to decide whether
    /// to break its wait so the loop can deliver.
    pub fn has_pending_for(tid: i32) -> bool {
        if carrick_signal_core::xsig::xsig_has_unblocked_for_self(0) {
            return true;
        }
        carrick_signal_core::has_pending_for(tid)
    }

    /// Like [`has_pending_for`], but a signal blocked by `block_mask` (bit
    /// `signum-1`) does NOT count as deliverable-for-waking. A queued cross-process
    /// signal in the xsignal ring is peeked WITHOUT consuming it so a temporary
    /// ppoll/epoll_pwait mask keeps genuinely blocked signals pending until the
    /// syscall returns. `block_mask == 0` is identical to [`has_pending_for`].
    pub fn has_unblocked_pending_for(tid: i32, block_mask: u64) -> bool {
        if carrick_signal_core::xsig::xsig_has_unblocked_for_self(block_mask) {
            return true;
        }
        carrick_signal_core::has_unblocked_pending_for(tid, block_mask)
    }

    // ---- KVM-arm-only glue stubs (no carrick-signal-core equivalent) ----
    // These are macOS host-signal-pump / cross-process-xsignal mechanisms with no
    // Linux analogue, or paths the dispatcher already covers. A later task moves
    // the platform-specific surface to a trait; for now they remain inert so the
    // KVM backend keeps compiling and behaving exactly as before.
    /// Move a carrick-internal fd above the high floor (and close the original)
    /// so it can never alias a low host fd handed to a guest under `--fs host`.
    /// Real POSIX impl shared with HVF (via carrick-host), no longer an identity
    /// stub that left internal fds at low, collision-prone numbers.
    pub use carrick_host::internal_fd::{duplicate_internal_fd, relocate_internal_fd};
    /// Reset inherited host-signal state in the runtime child after the
    /// interactive-`--tty` session supervisor forks (called from
    /// `interactive_supervisor::adopt_stdio`, in the freshly-forked child BEFORE
    /// it runs the normal runtime setup). The child must NOT inherit the
    /// supervisor's stale pending signals, mirrored host dispositions, child-exit
    /// watches, or its now-defunct signal-pump bookkeeping — it re-derives all of
    /// them from scratch as it boots its own guest.
    ///
    /// NEUTRAL vs GLUE (mirrors the HVF arm's rationale,
    /// `carrick_hvf::host_signal::reset_after_supervisor_fork`). The load-bearing
    /// CORRECTNESS clears are the platform-NEUTRAL `carrick-signal-core` state —
    /// the same pending / disposition / child-watch the HVF arm clears — so the
    /// child starts with an empty pending set and re-derives its own host
    /// dispositions. The PUMP re-arm is KVM GLUE: where HVF reopens its self-pipe
    /// here, KVM resets the inherited pump guards (`PUMP_STARTED` /
    /// `SIGCHLD_INSTALLED` / the stale `SELF_PIPE_W`) so the child's subsequent
    /// `start_signal_pump` (the normal runtime setup, lib.rs:477 / runtime.rs:1500)
    /// actually re-spawns a fresh pump instead of no-opping on the inherited
    /// `PUMP_STARTED == true` guard and leaving a dead pump.
    pub fn reset_after_supervisor_fork() {
        // ---- NEUTRAL (shared with HVF): drop inherited pending / disposition /
        // child-watch state so the child does not act on the supervisor's. ----
        carrick_signal_core::clear_thread_pending();
        carrick_signal_core::clear_proc_pending();
        // The mirrored host-disposition install mask (Task 6's shared
        // INSTALLED_MASK): clear it so the child re-derives its own host
        // dispositions as the guest re-installs handlers, instead of believing the
        // supervisor's mirrors are already in place.
        carrick_signal_core::host_disposition::clear_all();
        // The supervisor's child-exit watches belong to ITS children; the runtime
        // child must not reap or deliver their exit signals.
        carrick_signal_core::child_watch::clear();
        // NOTE: there is no KVM thread-waiter registry of HVF's `THREAD_WAITERS`
        // shape (per-thread self-pipes for thread-directed wakes) — the Linux
        // waiter is a stateless `ppoll` woken by the kick's EINTR (see
        // `io_wait::ThreadWaiter`), so there is nothing analogous to
        // `clear_thread_waiters()` to call here.
        //
        // ---- GLUE (KVM-specific pump re-arm): reset the inherited signal-pump
        // guards + stale self-pipe so the child's later `start_signal_pump`
        // re-arms a working pump (spawn-free — the spawn is the caller's
        // subsequent `start_signal_pump`). ----
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_signal_pump::reset_state_for_supervisor_fork();
        // BSD lane: bhyve signal-pump glue is wired in #1.
    }
    pub fn linux_to_host_signum(sig: i32) -> i32 {
        sig
    }
    pub fn host_to_linux_signum(sig: i32) -> i32 {
        sig
    }
    /// Resolve + REMOVE a child's `(parent_tid, exit_signal)` watch. Called by
    /// the dispatcher's synchronous terminal-reap path to CANCEL the async
    /// child-exit watch when the guest reaps the child itself (the double-delivery
    /// guard: the pump's reaper then finds nothing to publish). Delegates to the
    /// neutral child-watch registry.
    pub fn take_child_exit_parent(child_pid: i32) -> Option<(i32, i32)> {
        carrick_signal_core::child_watch::take(child_pid)
    }
    /// True iff `child_pid` is a tracked guest child (without consuming the
    /// mapping). Delegates to the neutral child-watch registry.
    pub fn is_tracked_child(child_pid: i32) -> bool {
        carrick_signal_core::child_watch::is_tracked(child_pid)
    }
    /// Guest `execve`: reset every mirrored host disposition to default, except
    /// the signals the new image keeps ignored (the bits set in `ignored_mask`,
    /// indexed by bit `signum` — the dispatcher's caller ABI). Because carrick
    /// does not host-exec, the host process would otherwise keep catching/ignoring
    /// those signals after the emulated disposition was replaced. Delegates to the
    /// carrick-linux glue (parallels HVF's reset).
    pub fn reset_routed_handlers_after_execve(ignored_mask: u64) {
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_disposition::reset_routed_handlers_after_execve(ignored_mask);
        #[cfg(not(feature = "platform-linux"))]
        let _ = ignored_mask; // BSD lane: bhyve disposition glue wired in #1.
    }
    /// Did a cross-process nudge arrive since the last drain? Delegates to the
    /// neutral ring core (the nudge handler in `carrick_linux::kvm_xsig` set the
    /// dirty flag).
    pub fn xsig_has_pending() -> bool {
        carrick_signal_core::xsig::xsig_has_pending()
    }
    /// Drain every xsignal-ring entry targeting THIS process, clearing the dirty
    /// flag. Called in dispatch context; the consumer rebuilds siginfo (preserving
    /// `si_value` for RT signals) and marks each signal pending.
    pub fn xsig_drain_for_self() -> Vec<(i32, i32, u32, i64)> {
        carrick_signal_core::xsig::xsig_drain_for_self()
    }
    /// Self-directed `kill(getpid(), sig)` for an UNBLOCKED signal: publish it
    /// into the process-directed pending mask so the generic vCPU loop injects
    /// the handler on the next pending check (the KVM analogue of HVF's
    /// `publish_pending` — no host pump, the same-thread syscall return re-checks
    /// pending). Without this the signal was dropped (the old inert stub), so a
    /// self-kill with a handler never ran. The sender siginfo (si_pid) is queued
    /// separately by the `kill` dispatcher arm and consumed by the loop.
    pub fn raise_for_self(sig: i32) {
        carrick_signal_core::publish_process_signal(sig);
    }
    /// Drain the lowest process-directed pending signum (`0` if none). Bridges a
    /// host-PUMPED process-directed signal (SIGTERM/SIGINT — the KVM pump sets
    /// `carrick_signal_core::PROC_PENDING` via `proc_pending_fetch_or`) into the
    /// post-EINTR delivery cycle so a `sigsuspend`-blocked thread wakes promptly
    /// instead of only via the 5s safety belt. Delegates to the neutral core —
    /// the same `take_process_pending` HVF's `take_pending` uses.
    pub fn take_pending() -> i32 {
        carrick_signal_core::take_process_pending()
    }
    /// Mirror a guest-installed handler onto a real HOST routed handler so a
    /// sibling guest process's host `kill` of this STANDARD catchable signal (the
    /// non-namespaced host-kill path) RUNS the guest handler instead of taking the
    /// host default action and TERMINATING the receiver (CPython
    /// test_interprocess_signal / LTP kill02). Idempotent; no-op for non-routable
    /// or KVM-claimed (pump/kick/nudge/SIGCHLD) signals. Delegates to the
    /// carrick-linux glue, whose policy is the shared neutral host_disposition.
    pub fn ensure_host_handler(sig: i32) {
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_disposition::ensure_host_handler(sig);
        #[cfg(not(feature = "platform-linux"))]
        let _ = sig; // BSD lane: bhyve disposition glue wired in #1.
    }
    /// Mirror a guest `SIG_IGN` onto the HOST disposition so a sibling guest
    /// process's host `kill` is DROPPED (honoring the guest's ignore) instead of
    /// host-default-terminating us. No-op for non-routable / KVM-claimed signals.
    pub fn set_host_ignore(sig: i32) {
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_disposition::set_host_ignore(sig);
        #[cfg(not(feature = "platform-linux"))]
        let _ = sig; // BSD lane: bhyve disposition glue wired in #1.
    }
    /// Reset a mirrored signal's HOST disposition to `SIG_DFL` (the guest reset it
    /// to default): clear any host SIG_IGN / routed handler mirrored earlier and
    /// possibly INHERITED across fork, so the host no longer swallows the signal.
    pub fn set_host_default(linux_signum: i32) {
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_disposition::set_host_default(linux_signum);
        #[cfg(not(feature = "platform-linux"))]
        let _ = linux_signum; // BSD lane: bhyve disposition glue wired in #1.
    }
    /// Enqueue a cross-process guest signal into the shared `MAP_SHARED` xsignal
    /// ring (inherited across `fork`, so every carrick process shares ONE ring).
    /// Delegates to the neutral ring core; false = no ring or ring full.
    pub fn xsig_enqueue(
        target_host: i32,
        sig: i32,
        sender_ns: i32,
        sender_uid: u32,
        value: i64,
    ) -> bool {
        carrick_signal_core::xsig::xsig_enqueue(target_host, sig, sender_ns, sender_uid, value)
    }
    /// Nudge `target_host` (a sibling carrick process) to drain its xsignal ring
    /// — host `SIGRTMIN+1`, a pure wakeup whose handler marks the ring dirty +
    /// kicks the target's vCPUs out of `KVM_RUN` (see `carrick_linux::kvm_xsig`).
    pub fn xsig_nudge(target_host: i32) {
        #[cfg(feature = "platform-linux")]
        carrick_linux::kvm_xsig::xsig_nudge(target_host);
        #[cfg(not(feature = "platform-linux"))]
        let _ = target_host; // BSD lane: bhyve xsignal-nudge glue wired in #1.
    }
    /// No kqueue signal pump on Linux. Returning -1 makes the `setitimer`
    /// dispatch path (the only caller) skip the EVFILT_TIMER arming and use the
    /// wall-clock fallback timer thread (`itimer::spawn_fallback_timer`) instead.
    pub fn pump_kqueue() -> i32 {
        -1
    }
    /// Record that guest tid `parent_tid` forked child `child_pid`, which should
    /// receive `exit_signal` when it exits, so the KVM signal pump's reaper
    /// publishes that signal to `parent_tid` the instant the child exits. The
    /// neutral child-watch core does the sanitize + insert; the KVM glue (the
    /// separate SIGCHLD `sigaction` + the pump-thread reaper) is installed by
    /// `kvm_signal_pump::start_pump` (called at startup via `start_signal_pump`,
    /// lib.rs ~477, BEFORE any guest fork), so the SIGCHLD disposition is already
    /// live by the time any watch registers — no per-register install needed.
    /// Without this watch a guest that reaps from its SIGCHLD handler (no blocking
    /// wait4) hung forever on KVM (the headline gap).
    pub fn register_child_exit_watch(child_pid: i32, parent_tid: i32, exit_signal: i32) {
        carrick_signal_core::child_watch::register(child_pid, parent_tid, exit_signal);
    }
    pub fn reinit_after_fork() {
        // A forked child inherits the parent's process-global timer + signal-pending
        // state (these live in carrick-timer-core / carrick-signal-core statics, copied
        // across libc::fork), but POSIX gives a fork child NO inherited timers and an
        // EMPTY pending-signal set. The parent's interval/POSIX-timer fallback THREADS
        // do not survive fork (only the forking thread does), so an inherited armed
        // slot has no backing thread; clear the registries so the child does not see
        // the parent's timer ids (EINVAL, not stale state) and a re-arm starts fresh.
        // Mirrors the HVF host_signal::reinit_after_fork neutral clears (its self-pipe/
        // kqueue/CHILD_WATCHES bits are HVF glue; the KVM pump re-inits separately in
        // kvm_signal_pump::reinit_after_fork).
        crate::posix_timer::clear();
        crate::itimer::clear();
        carrick_signal_core::clear_thread_pending();
        carrick_signal_core::clear_proc_pending();
        // The inherited child-exit watches belong to the PARENT's children (this
        // child's siblings); the freshly-forked child must not deliver their exit
        // signals. Cleared here alongside the other neutral fork-clears for
        // consistency with the HVF arm; `kvm_signal_pump::reinit_after_fork` also
        // clears it (idempotent) when the fork coordinator re-arms the child pump.
        carrick_signal_core::child_watch::clear();
        // The mirrored host DISPOSITIONS (the routed handlers / SIG_IGN installed
        // by kvm_disposition + their shared INSTALLED_MASK) are INTENTIONALLY left
        // intact across a guest fork — exactly as HVF's reinit_after_fork leaves
        // them. `libc::fork` inherits both the host sigactions AND the guest
        // sigaction table consistently, so the child's mirrored host dispositions
        // still match its inherited guest dispositions; clearing them here would
        // wrongly strip a handler the child still has installed. (The
        // supervisor-fork path — Task 7 — is the one that resets them, because
        // there the runtime re-installs from scratch.)
    }
    pub fn wake_all_waiters() {}
}

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
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
    pub struct ThreadWaiter {
        /// The guest tid this waiter parks on behalf of. Used by the `ppoll`
        /// EINTR-recheck so a THREAD-directed pending signal (e.g. an async
        /// child-exit signal the pump reaper published to this tid, or a
        /// `tgkill`) breaks the wait — not just a process-directed one. The
        /// macOS waiter wakes via a self-pipe + `has_pending`; the Linux waiter
        /// has no pipe in a `pause()` (empty-fd `ppoll`), so the kick's EINTR is
        /// the only wake and the recheck must see thread-pending too.
        tid: crate::thread::ThreadId,
    }

    impl ThreadWaiter {
        pub fn new(tid: crate::thread::ThreadId) -> Self {
            Self { tid }
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
            ppoll_wait(self.tid, fds, timeout, block_mask)
        }

        /// `poll(2)`-flavoured wait. On Linux this is the same `ppoll` as
        /// [`wait`](Self::wait) — both take pollfd-style (fd, events) pairs.
        pub fn wait_poll(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: u64,
        ) -> WaitResult {
            ppoll_wait(self.tid, fds, timeout, block_mask)
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
        pub fn wait_proc_exit(&self, pid: i32, block_mask: u64) -> WaitResult {
            loop {
                if child_status_ready(pid) {
                    return WaitResult::Ready;
                }
                // A ptraced child (PTRACE_TRACEME, then a delivered signal) is in
                // a signal-delivery STOP, not an exit — the WEXITED-only probe
                // above never reports it and the park would wedge forever (LTP
                // ptrace05 on the KVM lane). Probe the trap-stop separately:
                //   * a guest-meaningful stop signal → Ready, so the re-dispatched
                //     wait4's WNOHANG pre-check / blocking host wait observes the
                //     WIFSTOPPED status (Linux reports tracee stops to wait4 even
                //     without WUNTRACED);
                //   * a carrick-INTERNAL signal (the SIGRTMIN vCPU kick / the
                //     SIGRTMIN+1 xsignal nudge) → transparently PTRACE_CONT with
                //     the signal re-injected (its handler still runs) and keep
                //     waiting. The guest never asked for those; on HVF they don't
                //     exist as host signals (`hv_vcpus_exit` kicks), so a traced
                //     HVF child only ever stops for guest-raised signals.
                match tracee_trap_stop(pid) {
                    TraceeTrapStop::GuestSignal => return WaitResult::Ready,
                    TraceeTrapStop::InternalSignal(sig) => {
                        continue_tracee_with(pid, sig);
                        continue;
                    }
                    TraceeTrapStop::None => {}
                }
                // Still running. Park briefly (≤50 ms) in an empty `ppoll` so a
                // delivered signal returns `Interrupted` (the loop maps that to
                // EINTR / a fork-quiesce park), then re-poll the child. Not a busy
                // spin — each idle slice sleeps in `ppoll`.
                // TimedOut (slice elapsed) or a spurious Ready: re-poll the
                // child at the loop top; only an Interrupted bails out.
                //
                // CRITICAL: pass `block_mask` (the caller's non-interrupting mask
                // — blocked signals + default-ignored unblocked SIGCHLD/SIGURG/
                // SIGWINCH) so a carrick-internal vCPU kick (SIGRTMIN, e.g. the
                // signal pump's `kick_all` after a fork) or a default-ignored
                // SIGCHLD does NOT spuriously surface as `Interrupted` → EINTR.
                // A handler-less guest `wait4` is not interruptible by those on
                // real Linux; without the mask, a parent whose `wait4` parks
                // before the child exits gets a bogus EINTR (x86 fork race — the
                // child exited during the park; aarch64 reaps before parking so
                // it never bit). `ppoll_wait` retries on a masked interrupt and
                // re-polls the child, so the wait restarts transparently.
                if let WaitResult::Interrupted =
                    ppoll_wait(self.tid, &[], Some(Duration::from_millis(50)), block_mask)
                {
                    return WaitResult::Interrupted;
                }
            }
        }
    }

    /// What a `WSTOPPED` peek of a specific child found.
    enum TraceeTrapStop {
        /// Not stopped (or `pid <= 0`, or not a ptrace trap stop).
        None,
        /// Stopped in a ptrace signal-delivery stop for a signal the guest can
        /// legitimately observe (it raised it, or a sibling killed it).
        GuestSignal,
        /// Stopped on a carrick-internal host signal that the guest knows
        /// nothing about; carries the signal so the caller can re-inject it.
        InternalSignal(i32),
    }

    /// Signals carrick reserves for its own cross-thread/cross-process plumbing
    /// on the Linux lane: the vCPU kick (`carrick-linux`'s
    /// `kvm_kicker::kick_signal()` = `SIGRTMIN`) and the xsignal-ring nudge
    /// (`kvm_xsig::xsig_nudge_signal()` = `SIGRTMIN+1`). Guest signals never
    /// travel as these host numbers (guest RT signals ride the xsig ring; the
    /// shared kill path raises a host `SIGSTOP` carrier for RT/SIGCONT), so a
    /// traced child stopped on one of these is ALWAYS an implementation
    /// artifact, never guest-visible state. Mirrored by an equality test in
    /// `carrick-linux` (`kvm_disposition`'s claimed-signal tests).
    pub fn is_internal_kick_signal(signum: i32) -> bool {
        #[cfg(feature = "platform-linux")]
        {
            signum == libc::SIGRTMIN() || signum == libc::SIGRTMIN() + 1
        }
        // BSD lane: bhyve's kick-signal reservation is wired in #1; nothing is
        // reserved yet, so no host signum is carrick-internal.
        #[cfg(not(feature = "platform-linux"))]
        {
            let _ = signum;
            false
        }
    }

    /// Peek (`WNOWAIT`) whether child `pid` sits in a ptrace signal-delivery
    /// stop (`CLD_TRAPPED`), without consuming any state. Only meaningful for a
    /// specific child; `pid <= 0` reports `None`.
    fn tracee_trap_stop(pid: i32) -> TraceeTrapStop {
        if pid <= 0 {
            return TraceeTrapStop::None;
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if rc != 0 {
            return TraceeTrapStop::None;
        }
        // A group-stop of an untraced child is CLD_STOPPED and is NOT ours to
        // surface here (wait4 without WUNTRACED ignores it); only the ptrace
        // trap stop (CLD_TRAPPED) keeps the WEXITED park from ever resolving.
        const CLD_TRAPPED: i32 = 4;
        if carrick_portable::si_pid(&info) == 0 || info.si_code != CLD_TRAPPED {
            return TraceeTrapStop::None;
        }
        let sig = carrick_portable::si_status(&info);
        if is_internal_kick_signal(sig) {
            TraceeTrapStop::InternalSignal(sig)
        } else {
            TraceeTrapStop::GuestSignal
        }
    }

    /// `PTRACE_CONT` a trap-stopped tracee, re-injecting `sig` so its handler
    /// (the kick no-op / the nudge ring-drain) still runs. Failure is benign
    /// (e.g. the tracee died meanwhile): the caller re-polls.
    fn continue_tracee_with(pid: i32, sig: i32) {
        // SAFETY: PT_CONTINUE with addr 1 ("resume where stopped") and the
        // signal to re-inject; same shape as the dispatch ptrace(PTRACE_CONT).
        unsafe {
            libc::ptrace(
                carrick_portable::PT_CONTINUE,
                pid,
                std::ptr::without_provenance_mut::<libc::c_char>(1),
                sig,
            );
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
        // A ptraced child that published a pending signal-delivery stop (the
        // shared kill path marks the slot BEFORE raising) is waitable NOW: the
        // re-dispatched wait4 skips the park and its blocking host wait observes
        // the WIFSTOPPED status. Mirrors the HVF waiter's identical pre-check
        // (carrick-hvf io_wait::child_status_ready).
        if pid > 0 && crate::guest_cpu::child_has_ptrace_stop_pending(pid as u32) {
            return true;
        }
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

    fn ppoll_wait(
        tid: crate::thread::ThreadId,
        fds: &[WaitFd],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
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
            let err = carrick_portable::errno();
            if err == libc::EINTR {
                // A host signal interrupted the wait. If it carried a now-pending
                // PROCESS-directed guest signal (the async host-signal pump's
                // SIGTERM/INT/HUP/QUIT, or a process-directed timer/kill fan-out),
                // surface `Interrupted` so the caller returns EINTR and the
                // generic loop's `deliver_pending_signal` drains PROC_PENDING and
                // runs the guest handler. Without this an infinite `pause()`
                // (ppoll with NULL fds + NULL timeout) wedged forever: the kick's
                // EINTR was treated as spurious and re-entered the same wait, so
                // the handler never ran. A spurious kick with nothing pending
                // (e.g. a fork-quiesce nudge, handled by the caller) still falls
                // through to the re-arm retry below.
                // A cross-process guest signal may instead be sitting in the
                // shared xsignal ring (a SIGRTMIN+1 nudge marked it dirty — see
                // `carrick_linux::kvm_xsig`): peek the ring (without consuming) so
                // an `Interrupted` lets `deliver_pending_signal` drain it and
                // re-inject the guest signal with the sender's siginfo. The
                // `block_mask` keeps a genuinely-blocked ring signal parked.
                // `has_unblocked_pending_for(tid, block_mask)` covers BOTH a
                // process-directed pending signal (the host-signal pump's
                // SIGTERM/INT/HUP/QUIT, a process-directed timer/kill fan-out) AND
                // a THREAD-directed one published to THIS tid — notably the async
                // child-exit signal the SIGCHLD pump reaper publishes to the
                // recorded parent tid (`publish_pending_for`). Using only
                // `has_process_pending()` here wedged a `pause()`-blocked parent
                // forever: the reaper's thread-directed publish + kick EINTR'd the
                // ppoll, but the recheck saw no process-pending and treated the
                // kick as spurious, re-entering the same wait. The `block_mask`
                // keeps a genuinely-blocked signal parked (sigwait/ppoll mask).
                // A FORK-QUIESCE (or execve thread-group replacement) nudge must
                // ALSO surface as Interrupted: the forker now waits for the
                // kicker count to drain to 1, and a ppoll-parked waiter that
                // swallows the nudge as "spurious" never reaches
                // `release_and_park_vcpu_for_fork` — with `wait_proc_exit`'s
                // re-poll loop that deadlocked the whole guest (forker waiting
                // on the waiter; the waiter's awaited CHILD un-runnable behind
                // the stopped world; captured live in gdb under go-os_exec
                // TestConcurrentExec). The Interrupted callers all re-check
                // `is_quiescing()` themselves, so a nudge with no quiesce by the
                // time they look is surfaced as a harmless EINTR exactly as any
                // other interrupted slice. Mirrors the futex-wait predicate
                // (`is_quiescing || exec_replacing_other_thread`).
                if crate::fork_quiesce::is_quiescing()
                    || crate::fork_quiesce::exec_replacing_other_thread(tid)
                {
                    return WaitResult::Interrupted;
                }
                if crate::host_signal::has_unblocked_pending_for(tid, block_mask)
                    || carrick_signal_core::xsig::xsig_has_unblocked_for_self(block_mask)
                {
                    return WaitResult::Interrupted;
                }
                // Spurious host signal; no guest signal delivery yet — retry.
                continue;
            }
            return WaitResult::Errno(crate::host_to_linux_errno(err));
        }
    }

    /// Parity guard: the internal-signal whitelist must track exactly the RT
    /// signals the KVM backend reserves. Drift in either direction is a bug —
    /// an unlisted internal signal wedges a traced child in an unobserved
    /// ptrace stop; an over-listed one swallows a guest-visible stop.
    #[cfg(all(test, feature = "platform-linux", target_os = "linux"))]
    mod internal_signal_parity_tests {
        #[test]
        fn whitelist_matches_kvm_reserved_signals() {
            assert!(super::is_internal_kick_signal(
                carrick_linux::kvm_kicker::kick_signal()
            ));
            assert!(super::is_internal_kick_signal(
                carrick_linux::kvm_xsig::nudge_signum()
            ));
            // Every standard signal (incl. the SIGSTOP RT/SIGCONT carrier the
            // shared kill path raises) stays guest-visible.
            for s in 1..=31 {
                assert!(!super::is_internal_kick_signal(s), "signal {s}");
            }
        }
    }
}

// Wall-clock timer-signal delivery for the non-macOS (KVM/Linux) backend. Where
// macOS arms an EVFILT_TIMER on the kqueue signal pump, the Linux backend has no
// pump: a fallback timer THREAD (spawned by `itimer`/`posix_timer` below) sleeps
// to the deadline and then PUBLISHES the timer signal into the per-thread pending
// table and KICKS the target vCPU so the generic loop runs delivery. The target
// is registered once when the run loop starts (`register`).
#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod timer_delivery {
    use crate::thread::ThreadId;
    use std::sync::{Arc, Mutex, OnceLock};

    struct Delivery {
        kicker: Arc<dyn carrick_hal::VcpuRegistry>,
        // Wall-clock interval/POSIX timer signals (SIGALRM/SIGVTALRM/SIGPROF) are
        // PROCESS-directed: Linux delivers them to the thread group, runnable by
        // any thread that does not block the signal. `main_tid` is retained only
        // as the kick target for the legacy single-threaded path; `deliver` now
        // publishes into the SHARED process-directed mask and kicks ALL vCPUs so
        // a blocked-main / multi-thread guest still gets the timer (matching the
        // dispatcher's process-directed routing).
        #[allow(dead_code)]
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

    /// Publish a PROCESS-directed timer `signum` into the shared process-directed
    /// pending mask and kick EVERY vCPU so any unblocked thread re-checks pending
    /// at its safe point and delivers (a blocked main thread does not drop the
    /// timer). No-op if no run loop has registered (e.g. a unit test exercising
    /// arm/disarm only).
    pub fn deliver(signum: i32) {
        if let Some(d) = lock().as_ref() {
            carrick_signal_core::publish_process_signal(signum);
            d.kicker.kick_all();
        }
    }

    // The process-global `TimerDelivery` backend handle. This is the SAME
    // OnceLock seam as `register`/`deliver` above, extended so the dispatch
    // arm (`dispatch/time.rs`) can reach the backend's arm/disarm without
    // KernelState (the dispatch handlers don't carry a KernelState ref). The
    // run-loop startup registers the concrete backend (KVM `KvmTimerDelivery`).
    static DELIVERY: OnceLock<Arc<dyn carrick_hal::TimerDelivery>> = OnceLock::new();

    /// Install the backend `TimerDelivery`. Called once at run-loop startup
    /// (the same site as `register`). Subsequent calls are ignored.
    pub fn register_delivery(delivery: Arc<dyn carrick_hal::TimerDelivery>) {
        let _ = DELIVERY.set(delivery);
    }

    /// The registered backend `TimerDelivery`, or `None` if no run loop has
    /// registered one (e.g. a unit test exercising the dispatcher without a
    /// backing run loop). Every real run-loop entry registers a backend before
    /// the dispatcher can run a `setitimer`/`timer_settime`, so the `None` arm
    /// only matters for tests, where the caller falls back to the shared
    /// wall-clock timer thread (the pre-trait `kq < 0` behavior).
    pub fn delivery() -> Option<Arc<dyn carrick_hal::TimerDelivery>> {
        DELIVERY.get().map(Arc::clone)
    }
}

// The process-global `TimerDelivery` handle for the macOS/HVF backend. macOS has
// no kicker-based wall-clock `timer_delivery` (it arms EVFILT_TIMER on the pump
// kqueue), so this module is ONLY the `register_delivery`/`delivery` seam the
// dispatch arm consumes — mirroring the Linux module's extension above.
#[cfg(feature = "platform-macos")]
pub mod timer_delivery {
    use std::sync::{Arc, OnceLock};

    static DELIVERY: OnceLock<Arc<dyn carrick_hal::TimerDelivery>> = OnceLock::new();

    /// Install the backend `TimerDelivery` (HVF `HvfTimerDelivery`). Called once
    /// at run-loop startup. Subsequent calls are ignored.
    pub fn register_delivery(delivery: Arc<dyn carrick_hal::TimerDelivery>) {
        let _ = DELIVERY.set(delivery);
    }

    /// The registered backend `TimerDelivery`, or `None` if no run loop has
    /// registered one (e.g. a unit test exercising the dispatcher without a
    /// backing run loop). Every real run-loop entry registers a backend before
    /// the dispatcher can run a `setitimer`/`timer_settime`, so the `None` arm
    /// only matters for tests, where the caller falls back to the shared
    /// wall-clock timer thread (the pre-trait `kq < 0` behavior).
    pub fn delivery() -> Option<Arc<dyn carrick_hal::TimerDelivery>> {
        DELIVERY.get().map(Arc::clone)
    }
}

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod itimer {
    //! KVM/Linux interval-timer glue. The neutral per-`which` slot state, the
    //! CPU-due math, the ident/signum mapping, and the fallback-thread timing
    //! loop now live in [`carrick_timer_core::itimer`]; this module re-exports
    //! them and keeps only the KVM-specific wall-clock fallback thread spawn,
    //! which delivers via `timer_delivery` (publish + kick the target vCPU).

    pub use carrick_timer_core::itimer::*;

    use std::time::Duration;

    /// Spawn the fallback timer thread for `which`. The timing-loop body is
    /// shared (`carrick_timer_core::itimer::run_fallback`); the per-fire action
    /// delivers via `timer_delivery` (publish the signal + kick the target
    /// vCPU). For wall-time `ITIMER_REAL` the shared loop sleeps to the
    /// deadline; for CPU-time `ITIMER_VIRTUAL`/`ITIMER_PROF` it POLLS the core's
    /// `cpu_timer_decision` against the live aggregate guest CPU total — so CPU
    /// itimers fire off real guest CPU time (Task 3 wired the source) and never
    /// while the guest is idle. At most one thread per `which` is live — a
    /// disarm/re-arm bumps the generation so the old thread exits.
    pub fn spawn_fallback_timer(
        which: usize,
        generation: u64,
        value: Duration,
        interval: Duration,
    ) {
        let value_ns = u64::try_from(value.as_nanos()).unwrap_or(u64::MAX);
        let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
        let signum = signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                run_fallback(which, generation, value_ns, interval_ns, || {
                    crate::timer_delivery::deliver(signum);
                });
            });
    }
}

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
pub mod posix_timer {
    //! KVM/Linux POSIX per-process timer glue. The neutral spec/registry
    //! bookkeeping + remaining math now live in [`carrick_timer_core::posix`];
    //! this module re-exports them and keeps only the KVM-specific firing thread
    //! (spawn + deliver via `timer_delivery` on each expiry).

    pub use carrick_timer_core::posix::{
        PosixTimerSlot, PosixTimerSpec, clear, clock_id, create, delete, exists, getoverrun,
        remaining,
    };

    use std::time::Duration;

    /// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
    /// old_value). A `value_ns == 0` disarms. A non-zero value spawns a
    /// wall-clock firing thread that delivers `signum` after `value` then every
    /// `interval`, until the timer is re-armed or deleted (generation bump).
    pub fn arm(id: i32, value_ns: u64, interval_ns: u64) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, value_ns, interval_ns)?;
        if value_ns > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    std::thread::sleep(Duration::from_nanos(value_ns));
                    if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                        return;
                    }
                    crate::timer_delivery::deliver(signum);
                    if interval_ns == 0 {
                        return;
                    }
                    loop {
                        std::thread::sleep(Duration::from_nanos(interval_ns));
                        if !carrick_timer_core::posix::generation_matches(&slot, generation) {
                            return;
                        }
                        carrick_timer_core::posix::record_overrun(&slot);
                        crate::timer_delivery::deliver(signum);
                    }
                });
        }
        Some(armed.old)
    }
}

#[cfg(any(feature = "platform-linux", feature = "platform-freebsd"))]
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
