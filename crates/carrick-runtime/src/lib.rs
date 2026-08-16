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
// fielded struct on macOS (carrick-vmm-hvf) but a unit struct in the non-macOS
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
//! - **The exec engine** (the leaf crate `carrick-vmm-hvf`, re-exported below under
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
//! `crate::memory::…` in this crate, the code physically lives in `carrick-vmm-hvf`
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
//!   `carrick-vmm-hvf::fork_quiesce`.

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
pub mod core_dump;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_fs;
pub mod deadlock_watchdog;

pub mod dispatch;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod dtrace_consumer;
#[cfg(target_os = "macos")]
pub mod dtrace_symbols;
pub mod event_mux;
pub mod event_ring;
pub(crate) mod eventfd_shm;
pub(crate) mod exec_helpers;
pub(crate) mod fanotify;
pub mod fs_backend;
pub mod fs_resolve_cache;
pub mod host_tty;
pub(crate) mod inotify;
pub mod interactive_supervisor;
// The Linux kernel keyring subsystem behind `add_key`/`request_key`/`keyctl`.
// The key objects are VM-wide (one service on `kernel::Kernel`); the
// per-thread, per-process and per-uid keyring POINTERS live in the kernel
// graph, never in a host-process global. Rendered docs live in the module
// itself so its intra-doc links resolve in its own scope.
pub(crate) mod keyring;
pub mod layer_cache;
pub mod namespace;

pub mod network;
pub mod page_profile;
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
// Versioned native-x86 context layout consumed by the live profiler. The
// matching carrick binary is the authority; scripts must never duplicate the
// offset because gateway state (notably XSAVE) changes its size.
pub use carrick_dsr_x86::{X86DsrProfilerLayout, x86_dsr_profiler_layout};
// The translation-redundancy census file model. The WRITER lives beside the
// translator that produces the records; `carrick debug xlat-census` aggregates
// them and must parse them with the SAME definition, so the format is exported
// here rather than re-implemented in the CLI (which cannot depend on
// carrick-dsr-aarch64 directly). Unconditional: carrick-dsr-aarch64 compiles on
// every host, and reading a census captured on a Darwin/aarch64 rig is a
// perfectly reasonable thing to do elsewhere.
pub use carrick_dsr_aarch64::translator::xlat_census;
// Allocation-owner census records are rendered by the AArch64 translator-side
// diagnostic and parsed by the portable CLI. Re-export the single typed wire
// authority so the CLI does not acquire a direct guest-ISA dependency.
#[cfg(feature = "alloc-owner-census")]
pub use carrick_dsr_aarch64::alloc_owner_census;
pub use carrick_dsr_aarch64::alloc_owner_wire;
// The biased-lowering host-bias candidate set. The native-fault partition in
// the CLI classifies fault pages against `guest_va + bias`, and the bias is
// selected per process at boot from exactly this list — re-exported (the
// `xlat_census` precedent) so the parser reads the runtime's authority instead
// of duplicating four load-bearing constants.
pub use carrick_dsr::address::BIAS_CANDIDATES as NATIVE_HOST_BIAS_CANDIDATES;
// The guest-virtual address domain the census records are keyed on. Exported
// beside `xlat_census` so an out-of-crate aggregator keys its sets on the typed
// address instead of degrading them to `u64` at the crate boundary.
pub use carrick_guest_mem::{GuestVa, GuestVaRange};
// guest_cpu/host_facts/host_mapping/host_proc/ulock were lifted into the leaf
// crate `carrick-host` (Darwin host primitives — machine facts, __ulock, host
// shared mappings, CPU accounting, libproc introspection; no dispatch/trap/VFS
// deps). Re-exported under their original paths so every `crate::host_proc::…`
// / `crate::guest_cpu::…` / `crate::ulock::…` site is unchanged.
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
// The dispatch-free vCPU / exec-engine cluster was lifted into the leaf crate
// `carrick-vmm-hvf` (report item #1): the HVF trap engine (`trap`, incl. the
// `SyscallTrap` contract + SIMD/FP C shim), cross-thread vCPU coordination
// (`thread`/`vcpu_kick`/`io_wait`/`itimer`/`fork_quiesce`/`fork_coord`), the
// shared-aperture allocator, the Darwin `kqueue` wrapper, host-signal capture,
// the USDT probe provider (`probes`), compat-reporting (`compat`), and static
// syscall metadata (`syscall`). None depend on dispatch/VFS. Re-exported under
// their original `crate::trap::…` / `crate::thread::…` / … paths so every call
// site across the runtime is unchanged.
#[cfg(feature = "platform-macos")]
pub use carrick_vmm_hvf::{
    fork_coord, host_signal, io_wait, itimer, posix_timer, signal_arrival, threaded_impl, trap,
    vcpu_kick,
};
// The HVF `TimerDelivery` impl. Re-exported under `timer_delivery_impl` (the
// `timer_delivery` name is the runtime's own register/deliver module above), so
// the macOS run-loop startup can name `HvfTimerDelivery`.
#[cfg(feature = "platform-macos")]
pub use carrick_vmm_hvf::timer_delivery as timer_delivery_impl;
// The syscall-compat reporter is platform-neutral; it lives in
// carrick-observability so every backend shares the REAL recorder (the Linux/KVM
// arm was a no-op unit-struct stub; bhyve would have inherited it). DTrace
// backends install the per-event probe-fire hook via `compat::set_probe_hook` in
// their probe registration; Linux/bhyve leave it unset. Re-exported at
// `crate::compat` so all call sites are unchanged.
pub use carrick_observability::compat;
// The USDT (DTrace) probe provider is likewise platform-neutral now: it lives in
// carrick-observability so macOS AND FreeBSD fire the REAL `usdt` provider, while
// Linux/NetBSD link a no-op stub with identical signatures (replacing the old
// inline `pub mod probes` stub that lived here, and the macOS-only
// carrick-vmm-hvf re-export). Re-exported at `crate::probes` on EVERY platform so
// the dispatcher's call sites are unchanged.
pub use carrick_observability::probes;
pub use carrick_observability::vm_lifecycle;
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
// (in carrick-vmm-hvf::thread) issues `thread_info`; on Linux there are no Mach
// ports, so we return every registered thread with state 'R' (running).
#[cfg(feature = "platform-macos")]
pub use carrick_vmm_hvf::thread::current_thread_states;
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub fn current_thread_states() -> Vec<(thread::ThreadId, char)> {
    thread::current_thread_state_chars()
}

// Under platform-linux there is no carrick-vmm-hvf to re-export `trap` from; the
// SyscallTrap/TrapError/ForkOutcome contract lives in carrick-hal (section
// HAL). Re-export a `trap` shim so `crate::trap::{SyscallTrap, …}` resolves on
// both platforms. The concrete engine (HvfTrapEngine / KvmTrapEngine) is
// selected by the run-loop, which is itself platform-gated.
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod trap {
    pub use carrick_hal::{ForkOutcome, RawSyscall, SyscallTrap, TrapError};
    // Portable helpers the native (DSR) backend shares with the HVF trap
    // layer; real impls for every host OS live in carrick-host (the HVF trap
    // module re-exports the same symbols on macOS, so `crate::trap::…`
    // resolves identically on both platform arms).
    pub use carrick_host::clock::host_clock_uptime_ns;
    pub use carrick_host::futex_key::{shared_file_key_base, shared_futex_waiter_key};
    pub const HVF_PAGE_SIZE: u64 = 0x4000;

    // Cross-process VM-topology bookkeeping the shared threaded loop references
    // around a guest fork/exec. The shared `vcpu_loop` fork/exec paths RUN on
    // Linux (the generic threaded loop drives them on both backends since the
    // Phase 2 KVM bring-up); what differs is how much host-side VM surgery
    // each backend needs. On HVF these hooks coordinate the stop-the-world VM
    // teardown/rebuild (carrick-vmm-hvf::trap); KVM forks by rebuilding a fresh VM
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
    pub use carrick_vmm_kvm::kvm::VCPU_LIVE;
    #[cfg(not(feature = "platform-linux"))]
    pub static VCPU_LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

    /// Clear any VM republished by a previous fork. No-op on Linux.
    pub fn clear_rebuilt_vm_for_fork() {}

    /// Reset the per-fork sibling-mapping registry. No-op on Linux (the KVM fork
    /// rebuilds a fresh VM in the child only; no shared-VM union to collect).
    pub fn clear_sibling_fork_mappings() {}

    /// Dump cross-thread kick statistics at process exit. No-op on Linux.
    pub fn dump_kick_stats() {}
}

pub mod overlay;
pub mod pathcodec;
pub mod run_state;

/// Typed object identities and reservation contracts for the backend-neutral
/// kernel model.
pub mod kernel;

// Cross-platform run-loop result/error + kernel-half state. Single home for
// `RunResult` / `RuntimeError` / `KernelState` / `Kernel` / `VcpuLoopOutcome`,
// shared by the generic threaded `vcpu_loop` on BOTH backends — the HVF setup
// wrapper on macOS and `run_threaded_kvm_loop` on Linux (the `runtime` modules
// below).
pub mod run_result;

pub(crate) mod container_policy;
pub mod threaded_loop;
pub mod vcpu_loop;
// Platform-NEUTRAL debug-state snapshot + vDSO attach policy (moved out of the
// macOS `runtime.rs` arm; both `runtime` arms re-export them so the original
// `crate::runtime::…` call-site paths resolve on every platform).
pub mod debug_state;
pub mod exec_stamps;
#[cfg(feature = "platform-macos")]
pub mod execute;
pub(crate) mod hvpatch;
pub mod pty_relay;
pub mod rootfs;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub(crate) mod seccomp;
pub(crate) mod vdso_policy;
pub mod vfs;
#[cfg(feature = "platform-macos")]
pub use execute::Runtime;

/// Absolute host path to Apple's Rosetta 2 Linux interpreter that carrick probes
/// (and, on macOS, redirects x86_64 ELF loads to). Resolution order, so the same
/// probe is correct on every Apple-Silicon host regardless of OS:
///   1. `CARRICK_ROSETTA_PATH` — explicit override for non-standard layouts.
///   2. The `interpreter` recorded in the kernel's binfmt_misc `rosetta`
///      registration (`/proc/sys/fs/binfmt_misc/rosetta`). This is how an
///      Apple-Silicon Linux guest under Virtualization.framework (e.g. a lima VM
///      with `rosetta.enabled: true`) exposes Apple's Rosetta-for-Linux, and it
///      names wherever the guest mounted it. The read simply fails (and is
///      skipped) on macOS and on hosts without Rosetta.
///   3. Apple's fixed macOS location.
pub fn rosetta_interpreter_path() -> String {
    const APPLE_DEFAULT: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";
    if let Some(p) = std::env::var_os("CARRICK_ROSETTA_PATH") {
        return p.to_string_lossy().into_owned();
    }
    if let Ok(reg) = std::fs::read_to_string("/proc/sys/fs/binfmt_misc/rosetta") {
        if let Some(path) = parse_binfmt_interpreter(&reg) {
            return path.to_string();
        }
    }
    APPLE_DEFAULT.to_string()
}

/// Extract the `interpreter <path>` value from a binfmt_misc registration dump
/// (the body of `/proc/sys/fs/binfmt_misc/rosetta`). Pure, so the lima-discovery
/// path is unit-testable without a real `/proc`.
fn parse_binfmt_interpreter(reg: &str) -> Option<&str> {
    reg.lines()
        .find_map(|l| l.strip_prefix("interpreter "))
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

/// Whether Apple Rosetta 2 for Linux is accessible on this host — the gate for
/// running x86_64 (`linux/amd64`) guests on an aarch64 host. Probes the
/// interpreter file (see [`rosetta_interpreter_path`]) for read access: a cheap
/// `access(2)` check, not a full read, and host-agnostic so it is correct on
/// macOS AND on an Apple-Silicon Linux guest (e.g. lima) that mounts
/// Rosetta-for-Linux. On an x86_64 host, amd64 is the native ISA and this is
/// never consulted.
///
/// NOTE: this reports interpreter *presence*, which is what the engine's
/// [pre-run gate](../carrick_engine/fn.check_platform_runnable.html) needs. The
/// x86→Rosetta ELF-load *redirect* is currently wired only on the macOS/HVF load
/// path (`runtime::maybe_redirect_to_rosetta`); the Linux/KVM load path does not
/// yet redirect, so on a lima guest a `true` here gates the request in but the
/// execute-side bring-up is still in progress.
pub fn rosetta_available() -> bool {
    match std::ffi::CString::new(rosetta_interpreter_path()) {
        Ok(c) => unsafe { libc::access(c.as_ptr(), libc::R_OK) == 0 },
        Err(_) => false,
    }
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
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
    // Non-macOS run entry: Linux drives the KVM OCI path; FreeBSD drives the
    // bhyve OCI path. guest_hostname above stays shared.
    #[cfg(any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub struct Runtime;

    #[cfg(any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    impl Runtime {
        pub fn execute(
            spec: &carrick_spec::RunSpec,
        ) -> Result<crate::run_result::RunResult, crate::run_result::RuntimeError> {
            crate::runtime::run_oci(spec)
        }
    }
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub use execute::Runtime;

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod runtime {
    pub use crate::debug_state::{DebugRegionSnapshot, DebugStateSnapshot, maybe_dump_debug_state};
    pub use crate::run_result::{RunResult, RuntimeError};

    pub const DEFAULT_MAX_TRAPS: usize = usize::MAX;
    pub(crate) const ROSETTA_INTERPRETER: &str =
        "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";
    pub(crate) fn rosetta_license_blob() -> Option<&'static [u8]> {
        None
    }

    pub fn run_oci(_spec: &carrick_spec::RunSpec) -> Result<RunResult, RuntimeError> {
        Err(RuntimeError::Unsupported(
            "Pending port to hvpatch VM carrier model".to_string(),
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

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub use carrick_host_bsd::bsd_to_linux_errno as host_to_linux_errno;

#[cfg(feature = "platform-linux")]
pub fn host_to_linux_errno(host: i32) -> carrick_abi::LinuxErrno {
    // On a Linux host the host errno space already IS the Linux errno space —
    // the identity translation just enters the typed domain.
    carrick_abi::LinuxErrno::new(host)
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
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
        publish_pending_for, publish_process_signal, take_pending_for, take_pending_in_for,
        take_process_pending,
    };

    /// Who owns the vCPU kick after a pending-signal publish (mirrors the HVF
    /// module's enum so publication call sites compile on every platform).
    /// These lanes have no HVF signal pump: publication is the neutral core's
    /// and the caller always manages its own kick (the ActiveGlue kick path),
    /// so both variants degrade to a plain publish. The FreeBSD NATIVE lane
    /// will replace this with the real thread-waiter wake registry when the
    /// native backend's wake plumbing moves to a neutral home.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PublicationWake {
        SignalPump,
        CallerManaged,
    }

    /// Publish a thread-directed signal with an explicit wake owner. See
    /// [`PublicationWake`]: no pump exists here, so the wake mode does not
    /// change behaviour — the caller's own kick closes the lost-wakeup window.
    pub fn publish_pending_for_with_wake(tid: i32, signum: i32, _wake: PublicationWake) {
        carrick_signal_core::publish_pending_for(tid, signum);
    }

    /// Publish a process-directed signal with an explicit wake owner (mirrors
    /// the HVF `publish_process_signal_with_wake`: pending-bit publish + waiter
    /// wake + optional pump nudge). The load-bearing pending store IS the
    /// neutral core's (`publish_process_signal` sets the process-directed
    /// pending bit); like [`publish_pending_for_with_wake`] there is no HVF
    /// signal pump on these lanes, so the wake mode does not change behaviour.
    /// The native backend's only caller today uses `CallerManaged` and performs
    /// its own ordered kick-all right after this returns, which faithfully
    /// reproduces the HVF caller-managed contract. CORRECTNESS NOTE for the
    /// future FreeBSD native lane (M1): a `SignalPump`-owned publication here
    /// silently loses the pump wake — a guest thread busy in native code with
    /// no parked waiter is only interrupted at its next syscall/trap boundary.
    /// The native lane's real wake pump replaces this degrade in M1.
    pub fn publish_process_signal_with_wake(signum: i32, _wake: PublicationWake) {
        carrick_signal_core::publish_process_signal(signum);
    }

    /// Install the host-level default signal handlers (the HVF original wires
    /// host SIGINT → guest pending publish, opens the self-pipe, and installs
    /// the cross-process xsignal SIGINFO nudge handler). On these lanes the
    /// kick-backend signal pump (`carrick_hal::signal_pump::start_pump`,
    /// started by the fork coordinator's `start_signal_pump`) owns the host
    /// handler installs, so there is nothing left for this entry point to do —
    /// except keep the shared xsignal/FASYNC rings mapped, which is idempotent
    /// and matches the tail of the HVF install. CORRECTNESS NOTE for the future
    /// FreeBSD native lane (M1): the native run loop calls this WITHOUT
    /// starting a kick-backend pump, so until the native lane grows its own
    /// handler install, a host-delivered SIGINT takes the host default action
    /// (terminating carrick) instead of routing to the guest, and a sibling's
    /// xsignal nudge is only drained at the next dispatch boundary. The native
    /// lane replaces this in M1.
    pub fn install_default_handlers() {
        carrick_signal_core::xsig::xsig_init();
        carrick_signal_core::fasync::fasync_init();
    }

    /// ATFORK-PREPARE bundle for a guest `fork` (mirrors HVF's
    /// `SignalForkLocks`): every fork-shared signal-static mutex a NON-forking
    /// auxiliary thread can hold while publishing — the child-watch tables and
    /// the THREAD_PENDING store. Both guards are the platform-NEUTRAL
    /// `carrick-signal-core` ones, i.e. the REAL locks these lanes use. Native
    /// FreeBSD also includes the timer-delivery mutex because its unregistered
    /// helper nests pending publication and kicker/futex registry access under
    /// that mutex. The HVF `THREAD_WAITERS` self-pipe registry has no analogue
    /// here (these lanes use a stateless `ppoll` waiter).
    pub struct SignalForkLocks {
        _child_watch: carrick_signal_core::child_watch::ChildWatchForkGuard,
        _thread_pending: carrick_signal_core::ThreadPendingForkGuard,
        /// Freezes the unregistered timer helper across its complete
        /// publish+kicker+futex critical section on the native FreeBSD lane.
        #[cfg(all(
            any(target_os = "freebsd", target_os = "netbsd"),
            target_arch = "x86_64"
        ))]
        _timer_delivery: crate::timer_delivery::TimerForkGuard,
    }

    /// Acquire the atfork-prepare bundle (see [`SignalForkLocks`]). Call
    /// immediately before `libc::fork()`; drop immediately after in both
    /// processes, strictly before any child-side signal reinit.
    pub fn hold_signal_locks_for_fork() -> SignalForkLocks {
        #[cfg(all(
            any(target_os = "freebsd", target_os = "netbsd"),
            target_arch = "x86_64"
        ))]
        loop {
            // Match the helper's real nesting: timer delivery owns its mutex
            // before pending publication and kicker/futex registry access.
            if let Some(timer_delivery) = crate::timer_delivery::try_hold_for_fork()
                && let Some(child_watch) = carrick_signal_core::child_watch::try_hold_for_fork()
                && let Some(thread_pending) =
                    carrick_signal_core::try_hold_thread_pending_for_fork()
            {
                return SignalForkLocks {
                    _child_watch: child_watch,
                    _thread_pending: thread_pending,
                    _timer_delivery: timer_delivery,
                };
            }
            std::thread::yield_now();
        }

        #[cfg(not(all(
            any(target_os = "freebsd", target_os = "netbsd"),
            target_arch = "x86_64"
        )))]
        {
            let child_watch = carrick_signal_core::child_watch::hold_for_fork();
            let thread_pending = carrick_signal_core::hold_thread_pending_for_fork();
            SignalForkLocks {
                _child_watch: child_watch,
                _thread_pending: thread_pending,
            }
        }
    }

    /// Acquire the complete signal-static fork bundle without an unbounded
    /// mutex wait. This is fork-path-only retry work; ordinary signal and
    /// syscall paths retain their existing single-lock fast path.
    #[cfg(all(
        any(target_os = "freebsd", target_os = "netbsd"),
        target_arch = "x86_64"
    ))]
    pub fn try_hold_signal_locks_for_fork_until(
        deadline: std::time::Instant,
    ) -> Option<SignalForkLocks> {
        loop {
            // All acquisitions are nonblocking so a failed inner lock drops
            // the timer guard before retrying, preserving timer->signal order.
            if let Some(timer_delivery) = crate::timer_delivery::try_hold_for_fork()
                && let Some(child_watch) = carrick_signal_core::child_watch::try_hold_for_fork()
                && let Some(thread_pending) =
                    carrick_signal_core::try_hold_thread_pending_for_fork()
            {
                return Some(SignalForkLocks {
                    _child_watch: child_watch,
                    _thread_pending: thread_pending,
                    _timer_delivery: timer_delivery,
                });
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }

    // The active backend's host-signal glue (Review-P1 #6 seam). One cfg-selected
    // type alias replaces the per-function backend fanout below: every signal op
    // is now ONE generic call through the shared `carrick_signal_core::host_glue`
    // / `carrick_hal::signal_pump`, parameterized here. A new kick backend adds one
    // line + a `HostSignalGlue` impl and inherits the whole shared driver.
    //
    // UNLIKE the VMM entry points, this alias cannot simply be arch-gated away
    // on the aarch64 BSD lanes: every guest-facing signal operation in this
    // module is a generic call through `ActiveGlue`, and those are reached from
    // the arch-neutral dispatcher on every host. So the two BSD arms are
    // arch-SPLIT rather than arch-gated — x86_64 keeps the VMM crate's glue
    // byte-for-byte, and a BSD build with no VMM crate (aarch64) resolves to
    // `carrick_host_bsd::native_glue::BsdNativeGlue`, which expresses the same
    // per-OS policy from the same single-source `carrick_host_bsd::signum`
    // table. `bhyve_signal_backend` / `nvmm_signal_backend` carry the test that
    // asserts the two agree on every signal number.
    #[cfg(feature = "platform-linux")]
    pub(crate) type ActiveGlue = carrick_vmm_kvm::KvmGlue;
    #[cfg(all(feature = "platform-freebsd", target_arch = "x86_64"))]
    pub(crate) type ActiveGlue = carrick_vmm_bhyve::BhyveGlue;
    #[cfg(all(feature = "platform-netbsd", target_arch = "x86_64"))]
    pub(crate) type ActiveGlue = carrick_vmm_nvmm::NvmmGlue;
    #[cfg(all(
        any(feature = "platform-freebsd", feature = "platform-netbsd"),
        not(target_arch = "x86_64")
    ))]
    pub(crate) type ActiveGlue = carrick_host_bsd::native_glue::BsdNativeGlue;

    // `has_pending_for` / `has_unblocked_pending_for` are NOT pure re-exports on
    // KVM: a cross-process guest signal may be sitting in the shared xsignal ring
    // (see `carrick_vmm_kvm::kvm_xsig`), so a waiter must also peek the ring. These
    // wrappers fold the ring check over the neutral-core pending check, mirroring
    // the HVF backend's `host_signal::has_pending_for` / `has_unblocked_pending_for`.

    /// Is a signal deliverable to `tid` pending? True for a thread-directed signal
    /// for this tid, any process-directed signal, OR an unblocked self-targeted
    /// entry in the shared xsignal ring. Used by a parked thread to decide whether
    /// to break its wait so the loop can deliver.
    pub fn has_pending_for(tid: i32) -> bool {
        if carrick_signal_core::xsig::xsig_has_unblocked_for_self(carrick_abi::SigBlockMask::NONE) {
            return true;
        }
        carrick_signal_core::has_pending_for(tid)
    }

    /// Like [`has_pending_for`], but a signal blocked by `block_mask` does NOT
    /// count as deliverable-for-waking. A queued cross-process signal in the
    /// xsignal ring is peeked WITHOUT consuming it so a temporary
    /// ppoll/epoll_pwait mask keeps genuinely blocked signals pending until the
    /// syscall returns. `SigBlockMask::NONE` is identical to
    /// [`has_pending_for`].
    pub fn has_unblocked_pending_for(tid: i32, block_mask: carrick_abi::SigBlockMask) -> bool {
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
    /// `carrick_vmm_hvf::host_signal::reset_after_supervisor_fork`). The load-bearing
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
        carrick_signal_core::xsig::xsig_refresh_self_host_pid();
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
        carrick_hal::signal_pump::reset_state_for_supervisor_fork();
    }
    /// Translate a Linux (guest) signal number to the host kernel's number. On a
    /// Linux host this is identity (the numbers match); on a FreeBSD host the BSD
    /// numbering differs for several signals (SIGUSR1/2, SIGCHLD, SIGCONT/STOP/TSTP,
    /// SIGBUS, SIGURG, SIGIO, SIGSYS) so it routes through the bhyve table.
    pub fn linux_to_host_signum(sig: i32) -> i32 {
        carrick_signal_core::host_glue::glue_linux_to_host::<ActiveGlue>(sig)
    }
    /// Translate a host kernel signal number back to its Linux (guest) number.
    /// Identity on a Linux host; the inverse BSD table on FreeBSD.
    pub fn host_to_linux_signum(sig: i32) -> i32 {
        carrick_signal_core::host_glue::glue_host_to_linux::<ActiveGlue>(sig)
    }
    /// Resolve + REMOVE a child's `(parent_tid, exit_signal)` watch. Called by
    /// the dispatcher's synchronous terminal-reap path to CANCEL the async
    /// child-exit watch when the guest reaps the child itself (the double-delivery
    /// guard: the pump's reaper then finds nothing to publish). Delegates to the
    /// neutral child-watch registry.
    pub fn take_child_exit_parent(child_pid: i32) -> Option<(i32, i32)> {
        carrick_signal_core::child_watch::take(child_pid)
    }
    /// Pop a backend-recorded child-exit `waitid` payload for the next delivery
    /// of `exit_signal` to `parent_tid`. The runtime converts host pid/status
    /// into the guest namespace and Linux signal numbering when building the
    /// final `siginfo_t`.
    pub fn take_child_exit_siginfo(
        parent_tid: i32,
        exit_signal: i32,
    ) -> Option<carrick_signal_core::child_watch::ChildExitSiginfo> {
        carrick_signal_core::child_watch::take_siginfo(parent_tid, exit_signal)
    }
    /// True iff `child_pid` is a tracked guest child (without consuming the
    /// mapping). Delegates to the neutral child-watch registry.
    pub fn is_tracked_child(child_pid: i32) -> bool {
        carrick_signal_core::child_watch::is_tracked(child_pid)
    }
    /// Guest `execve`: reset every mirrored host disposition to default, except
    /// the signals the new image keeps ignored (`ignored`). Because carrick
    /// does not host-exec, the host process would otherwise keep catching/ignoring
    /// those signals after the emulated disposition was replaced. Delegates to the
    /// carrick-vmm-kvm glue (parallels HVF's reset).
    pub fn reset_routed_handlers_after_execve(ignored: carrick_abi::SigSet) {
        carrick_signal_core::host_glue::reset_routed_handlers_after_execve::<ActiveGlue>(ignored);
    }
    /// Did a cross-process nudge arrive since the last drain? Delegates to the
    /// neutral ring core (the nudge handler in `carrick_vmm_kvm::kvm_xsig` set the
    /// dirty flag).
    pub fn xsig_has_pending() -> bool {
        carrick_signal_core::xsig::xsig_has_pending()
    }
    /// Drain every xsignal-ring entry targeting THIS process, clearing the dirty
    /// flag. Called in dispatch context; the consumer rebuilds siginfo (preserving
    /// `si_value` for RT signals) and marks each signal pending. The trailing
    /// `target_ns_tid` is 0 for a process-directed send (kill/rt_sigqueueinfo/
    /// pidfd) or the guest ns tid of a thread-directed one (tkill/tgkill/
    /// rt_tgsigqueueinfo).
    pub fn xsig_drain_for_self() -> Vec<(i32, i32, i32, u32, i64, i32)> {
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
    /// carrick-vmm-kvm glue, whose policy is the shared neutral host_disposition.
    pub fn ensure_host_handler(sig: i32) {
        carrick_signal_core::host_glue::ensure_host_handler::<ActiveGlue>(sig);
    }
    /// Mirror a guest `SIG_IGN` onto the HOST disposition so a sibling guest
    /// process's host `kill` is DROPPED (honoring the guest's ignore) instead of
    /// host-default-terminating us. No-op for non-routable / KVM-claimed signals.
    pub fn set_host_ignore(sig: i32) {
        carrick_signal_core::host_glue::set_host_ignore::<ActiveGlue>(sig);
    }
    /// Reset a mirrored signal's HOST disposition to `SIG_DFL` (the guest reset it
    /// to default): clear any host SIG_IGN / routed handler mirrored earlier and
    /// possibly INHERITED across fork, so the host no longer swallows the signal.
    pub fn set_host_default(linux_signum: i32) {
        carrick_signal_core::host_glue::set_host_default::<ActiveGlue>(linux_signum);
    }
    /// Enqueue a cross-process guest signal into the shared `MAP_SHARED` xsignal
    /// ring (inherited across `fork`, so every carrick process shares ONE ring).
    /// Delegates to the neutral ring core; false = no ring or ring full.
    /// `target_ns_tid` is 0 for a process-directed send, or the target's guest
    /// ns tid for a thread-directed one (tkill/tgkill/rt_tgsigqueueinfo).
    pub fn xsig_enqueue(
        target_host: i32,
        sig: i32,
        code: i32,
        sender_ns: i32,
        sender_uid: u32,
        value: i64,
        target_ns_tid: i32,
    ) -> bool {
        carrick_signal_core::xsig::xsig_enqueue(
            target_host,
            sig,
            code,
            sender_ns,
            sender_uid,
            value,
            target_ns_tid,
        )
    }
    /// Nudge `target_host` (a sibling carrick process) to drain its xsignal ring
    /// — host `SIGRTMIN+1`, a pure wakeup whose handler marks the ring dirty +
    /// kicks the target's vCPUs out of `KVM_RUN` (see `carrick_vmm_kvm::kvm_xsig`).
    pub fn xsig_nudge(target_host: i32) {
        carrick_signal_core::host_glue::xsig_nudge::<ActiveGlue>(target_host);
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
        carrick_signal_core::xsig::xsig_refresh_self_host_pid();
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

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod io_wait {
    use carrick_abi::{LinuxErrno, SigBlockMask};
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
        Errno(LinuxErrno),
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

        /// The guest tid this waiter parks on behalf of.
        pub fn tid(&self) -> crate::thread::ThreadId {
            self.tid
        }

        /// Permanently follow a nonleader exec survivor onto the process main
        /// tid. All subsequent pending-signal checks must use the rekeyed
        /// registry identity, including after the replacement image clones.
        pub fn rekey_after_exec(&mut self, tid: crate::thread::ThreadId) {
            self.tid = tid;
        }

        pub fn wait(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: SigBlockMask,
        ) -> WaitResult {
            ppoll_wait(self.tid, fds, timeout, block_mask, || false)
        }

        pub fn wait_with_dispatch_pending<F>(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: SigBlockMask,
            should_interrupt: F,
        ) -> WaitResult
        where
            F: Fn() -> bool,
        {
            ppoll_wait(self.tid, fds, timeout, block_mask, should_interrupt)
        }

        /// Wait for a child stop/continue notification (mirrors the macOS
        /// waiter's kqueue-less arm): an empty-fd park whose 50 ms timeout is
        /// the lost-edge backstop; a kick/pending-signal edge prompts
        /// immediate re-dispatch via `should_interrupt`.
        pub fn wait_proc_state_with_dispatch_pending<F>(
            &self,
            block_mask: SigBlockMask,
            should_interrupt: F,
        ) -> WaitResult
        where
            F: Fn() -> bool,
        {
            ppoll_wait(
                self.tid,
                &[],
                Some(Duration::from_millis(50)),
                block_mask,
                should_interrupt,
            )
        }

        /// `poll(2)`-flavoured wait. On Linux this is the same `ppoll` as
        /// [`wait`](Self::wait) — both take pollfd-style (fd, events) pairs.
        pub fn wait_poll(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: SigBlockMask,
        ) -> WaitResult {
            ppoll_wait_poll(self.tid, fds, timeout, block_mask, || false)
        }

        pub fn wait_poll_with_dispatch_pending<F>(
            &self,
            fds: &[WaitFd],
            timeout: Option<Duration>,
            block_mask: SigBlockMask,
            should_interrupt: F,
        ) -> WaitResult
        where
            F: Fn() -> bool,
        {
            ppoll_wait_poll(self.tid, fds, timeout, block_mask, should_interrupt)
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
        pub fn wait_proc_exit(&self, pid: i32, block_mask: SigBlockMask) -> WaitResult {
            self.wait_proc_exit_with_dispatch_pending(pid, block_mask, || false)
        }

        pub fn wait_proc_exit_with_dispatch_pending<F>(
            &self,
            pid: i32,
            block_mask: SigBlockMask,
            should_interrupt: F,
        ) -> WaitResult
        where
            F: Fn() -> bool,
        {
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
                if let WaitResult::Interrupted = ppoll_wait_recheck_on_masked_interrupt(
                    self.tid,
                    &[],
                    Some(Duration::from_millis(50)),
                    block_mask,
                    &should_interrupt,
                ) {
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

    /// Signals carrick reserves for its own cross-thread/cross-process plumbing.
    /// A traced child can stop on these host carriers before the carrier handler
    /// runs. Surface none of them to the guest tracer; re-inject and keep waiting
    /// so the handler can publish the real guest-visible state.
    pub fn is_internal_kick_signal(signum: i32) -> bool {
        #[cfg(feature = "platform-macos")]
        {
            if crate::host_signal::is_xsig_nudge(signum) {
                return true;
            }
        }
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        {
            use crate::host_signal::ActiveGlue;
            use carrick_signal_core::HostSignalGlue;
            return signum == ActiveGlue::kick_signal() || signum == ActiveGlue::nudge_signum();
        }
        #[allow(unreachable_code)]
        false
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
            carrick_portable::ptrace(carrick_portable::PT_CONTINUE, pid, 1, sig);
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
        // (carrick-vmm-hvf io_wait::child_status_ready).
        if pid > 0 && crate::guest_cpu::child_has_ptrace_stop_pending(pid as u32) {
            return true;
        }
        if pid <= 0 && crate::guest_cpu::direct_child_ptrace_stop_pending(std::process::id()) {
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
        block_mask: SigBlockMask,
        should_interrupt: impl Fn() -> bool,
    ) -> WaitResult {
        ppoll_wait_inner(
            tid,
            fds,
            timeout,
            block_mask,
            should_interrupt,
            false,
            false,
        )
    }

    fn ppoll_wait_poll(
        tid: crate::thread::ThreadId,
        fds: &[WaitFd],
        timeout: Option<Duration>,
        block_mask: SigBlockMask,
        should_interrupt: impl Fn() -> bool,
    ) -> WaitResult {
        ppoll_wait_inner(tid, fds, timeout, block_mask, should_interrupt, false, true)
    }

    fn ppoll_wait_recheck_on_masked_interrupt(
        tid: crate::thread::ThreadId,
        fds: &[WaitFd],
        timeout: Option<Duration>,
        block_mask: SigBlockMask,
        should_interrupt: impl Fn() -> bool,
    ) -> WaitResult {
        ppoll_wait_inner(tid, fds, timeout, block_mask, should_interrupt, true, false)
    }

    fn ppoll_wait_inner(
        tid: crate::thread::ThreadId,
        fds: &[WaitFd],
        timeout: Option<Duration>,
        block_mask: SigBlockMask,
        should_interrupt: impl Fn() -> bool,
        recheck_on_masked_interrupt: bool,
        retry_poll_slice: bool,
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
        // Backstop for an UNBOUNDED wait (`timeout == None`, e.g. a guest
        // `pause()` = empty-fd ppoll with a NULL timeout). On the Linux/KVM lane
        // such a wait blocks SOLELY on the kick signal (SIGRTMIN, sent by
        // `kvm_signal_pump`'s `kick_all` after publishing a process-directed
        // signal): there is no fd in the set to ready it and no self-pipe in the
        // pollfds. If that single wake EDGE is LOST — the kick fired in the
        // window between this thread publishing `WaitOnFds`/`WaitOnProcExit` and
        // actually entering `ppoll`, or the pump's poke landed on a stale pipe
        // mid fork-reinit — a NULL-timeout ppoll would wedge the thread FOREVER:
        // PROC_PENDING already holds the signal, but the recheck below only runs
        // on an EINTR that never arrives. A parent's `kill(child, SIG)` + the
        // child's `pause()` deadlocked exactly here on KVM (the child stuck in
        // `poll_schedule_timeout`, the parent's `wait4` park never firing —
        // `signalexit`/`waitexitstorm` HANG). Cap an unbounded slice at a short
        // backstop so a lost edge re-checks the pending state within bounded
        // latency, then re-blocks — mirroring the bounded re-poll the sibling
        // `wait_proc_exit`/`rt_sigsuspend` loops already use. A real wake (kick
        // EINTR or an fd readying) still returns immediately; this only changes
        // how long a LOST edge can hide.
        const UNBOUNDED_BACKSTOP: Duration = Duration::from_millis(50);
        loop {
            if should_interrupt() {
                return WaitResult::Interrupted;
            }
            let ts = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return WaitResult::TimedOut;
                    }
                    let rem = (dl - now).min(UNBOUNDED_BACKSTOP);
                    Some(libc::timespec {
                        tv_sec: rem.as_secs().min(i64::MAX as u64) as libc::time_t,
                        tv_nsec: rem.subsec_nanos() as libc::c_long,
                    })
                }
                // Unbounded wait: block in a bounded backstop slice instead of a
                // NULL timeout so a lost kick edge cannot wedge the thread.
                None => Some(libc::timespec {
                    tv_sec: UNBOUNDED_BACKSTOP.as_secs() as libc::time_t,
                    tv_nsec: UNBOUNDED_BACKSTOP.subsec_nanos() as libc::c_long,
                }),
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
                // ppoll slice elapsed. For a BOUNDED wait, only return TimedOut
                // once the REAL deadline is reached — a slice truncated by the
                // unbounded backstop cap above must re-block for the remainder
                // (the loop top recomputes the remaining time and returns
                // TimedOut when `now >= dl`). For an UNBOUNDED wait (`deadline
                // == None`, a `pause()`), a slice elapsing is the backstop: it
                // must NEVER surface as TimedOut (the guest asked to block
                // forever); instead re-check whether a wake edge was LOST while
                // we were blocked — a now-deliverable pending/ring signal that
                // never EINTR'd us — and surface `Interrupted` so the caller's
                // `deliver_pending_signal` runs, else re-block.
                match deadline {
                    Some(dl) if Instant::now() >= dl => return WaitResult::TimedOut,
                    Some(_) if retry_poll_slice && !fds.is_empty() => return WaitResult::Ready,
                    Some(_) => continue,
                    None => {
                        if crate::fork_quiesce::is_quiescing()
                            || crate::fork_quiesce::exec_replacing_other_thread(tid)
                            || crate::host_signal::has_unblocked_pending_for(tid.raw(), block_mask)
                            || carrick_signal_core::xsig::xsig_has_unblocked_for_self(block_mask)
                            || should_interrupt()
                        {
                            return WaitResult::Interrupted;
                        }
                        if retry_poll_slice && !fds.is_empty() {
                            return WaitResult::Ready;
                        }
                        continue;
                    }
                }
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
                // `carrick_vmm_kvm::kvm_xsig`): peek the ring (without consuming) so
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
                if crate::host_signal::has_unblocked_pending_for(tid.raw(), block_mask)
                    || carrick_signal_core::xsig::xsig_has_unblocked_for_self(block_mask)
                    || should_interrupt()
                {
                    return WaitResult::Interrupted;
                }
                // Spurious or masked host signal. Normal fd waits retry the
                // remaining deadline. A proc-exit wait instead returns to its
                // outer child-status probe so a SIGCHLD/kick cannot burn the
                // full 50 ms backstop while a zombie is already reapable.
                if recheck_on_masked_interrupt {
                    return WaitResult::TimedOut;
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
                carrick_vmm_kvm::kvm_kicker::kick_signal()
            ));
            assert!(super::is_internal_kick_signal(
                carrick_vmm_kvm::kvm_xsig::nudge_signum()
            ));
            // Every standard signal (incl. the SIGSTOP RT/SIGCONT carrier the
            // shared kill path raises) stays guest-visible.
            for s in 1..=31 {
                assert!(!super::is_internal_kick_signal(s), "signal {s}");
            }
        }
    }

    #[cfg(all(test, feature = "platform-linux", target_os = "linux"))]
    mod ppoll_backstop_tests {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[test]
        fn unbounded_wait_checks_dispatch_pending_after_backstop_slice() {
            let checks = AtomicUsize::new(0);

            let result = super::ppoll_wait(
                crate::thread::ThreadId::synthetic_for_tests(7),
                &[],
                None,
                carrick_abi::SigBlockMask::NONE,
                || checks.fetch_add(1, Ordering::SeqCst) > 0,
            );

            assert_eq!(result, super::WaitResult::Interrupted);
            assert!(
                checks.load(Ordering::SeqCst) >= 2,
                "predicate must be checked before and after the backstop slice"
            );
        }
    }
}

// Wall-clock timer-signal delivery for the non-macOS (KVM/Linux) backend. Where
// macOS arms an EVFILT_TIMER on the kqueue signal pump, the Linux backend has no
// pump: a fallback timer THREAD (spawned by `itimer`/`posix_timer` below) sleeps
// to the deadline and then PUBLISHES the timer signal into the per-thread pending
// table and KICKS the target vCPU so the generic loop runs delivery. The target
// is registered once when the run loop starts (`register`).
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
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

    /// Opaque atfork guard for the real timer-delivery helper mutex. Holding it
    /// proves no unregistered timer thread can be inside the pending-signal,
    /// kicker-registry, or current-futex operations nested under `deliver`.
    #[cfg(all(
        any(target_os = "freebsd", target_os = "netbsd"),
        target_arch = "x86_64"
    ))]
    pub struct TimerForkGuard {
        _delivery: std::sync::MutexGuard<'static, Option<Delivery>>,
    }

    /// Try-acquire the timer helper's complete critical section. The fork
    /// bundle acquires this outer guard first, then try-acquires signal guards;
    /// any miss drops everything before retrying, matching `deliver`'s
    /// timer->pending lock order without an unbounded wait.
    #[cfg(all(
        any(target_os = "freebsd", target_os = "netbsd"),
        target_arch = "x86_64"
    ))]
    pub fn try_hold_for_fork() -> Option<TimerForkGuard> {
        match cell().try_lock() {
            Ok(delivery) => Some(TimerForkGuard {
                _delivery: delivery,
            }),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => Some(TimerForkGuard {
                _delivery: poisoned.into_inner(),
            }),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    /// Replace the inherited parent kicker after a native fork child installs
    /// its fresh current registry and futex table.
    #[cfg(all(
        any(target_os = "freebsd", target_os = "netbsd"),
        target_arch = "x86_64"
    ))]
    pub fn reset_after_fork_child(kicker: Arc<dyn carrick_hal::VcpuRegistry>, main_tid: ThreadId) {
        *lock() = Some(Delivery { kicker, main_tid });
    }

    #[cfg(all(test, target_os = "freebsd", target_arch = "x86_64"))]
    pub(crate) fn hold_critical_section_for_native_fork_test(
        on_locked: impl FnOnce(),
        release: impl FnOnce(),
    ) {
        let _delivery = lock();
        on_locked();
        release();
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
            crate::thread::notify_current_futex_signal_pending();
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

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod itimer {
    //! KVM/Linux interval-timer glue. The neutral per-`which` slot state, the
    //! CPU-due math, the ident/signum mapping, and the fallback-thread timing
    //! loop now live in [`carrick_timer_core::itimer`]; this module re-exports
    //! them and keeps only the KVM-specific wall-clock fallback thread spawn,
    //! which delivers via `timer_delivery` (publish + kick the target vCPU).

    pub use carrick_timer_core::itimer::*;

    use carrick_timer_core::TimerSpecNs;

    /// Spawn the fallback timer thread for `which`. The timing-loop body is
    /// shared (`carrick_timer_core::itimer::run_fallback`); the per-fire action
    /// delivers via `timer_delivery` (publish the signal + kick the target
    /// vCPU). For wall-time `ITIMER_REAL` the shared loop sleeps to the
    /// deadline; for CPU-time `ITIMER_VIRTUAL`/`ITIMER_PROF` it POLLS the core's
    /// `cpu_timer_decision` against the live aggregate guest CPU total — so CPU
    /// itimers fire off real guest CPU time (Task 3 wired the source) and never
    /// while the guest is idle. At most one thread per `which` is live — a
    /// disarm/re-arm bumps the generation so the old thread exits.
    pub fn spawn_fallback_timer(which: usize, generation: u64, spec: TimerSpecNs) {
        let signum = signum_for(which);
        let _ = std::thread::Builder::new()
            .name(format!("carrick-itimer-{which}"))
            .spawn(move || {
                run_fallback(which, generation, spec, || {
                    crate::timer_delivery::deliver(signum);
                });
            });
    }
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod posix_timer {
    //! KVM/Linux POSIX per-process timer glue. The neutral spec/registry
    //! bookkeeping + remaining math now live in [`carrick_timer_core::posix`];
    //! this module re-exports them and keeps only the KVM-specific firing thread
    //! (spawn + deliver via `timer_delivery` on each expiry).

    pub use carrick_timer_core::posix::{
        PosixTimerSlot, PosixTimerSpec, clear, clock_id, create, delete, exists, getoverrun,
        remaining, seed_overrun,
    };

    /// (Re-)arm timer `id`. Returns the PREVIOUS spec (for `timer_settime`'s
    /// old_value). A `spec.value == 0` disarms. A non-zero value spawns a
    /// firing thread (the shared timer-core loop) that delivers `signum` after
    /// `spec.value` then every `spec.interval`, until the timer is re-armed or
    /// deleted (generation bump).
    pub fn arm(id: i32, spec: carrick_timer_core::TimerSpecNs) -> Option<PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let on_fire = move || {
                crate::timer_delivery::deliver(signum);
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback(slot, generation, spec, on_fire);
                });
        }
        Some(armed.old)
    }
}

#[cfg(test)]
mod rosetta_detection_tests {
    use super::parse_binfmt_interpreter;

    #[test]
    fn parses_rosetta_binfmt_interpreter_path() {
        // Shape of a real /proc/sys/fs/binfmt_misc/rosetta dump on a lima guest.
        let reg = "enabled\ninterpreter /mnt/lima-rosetta/rosetta\nflags: POCF\noffset 0\nmagic 7f454c46\n";
        assert_eq!(
            parse_binfmt_interpreter(reg),
            Some("/mnt/lima-rosetta/rosetta")
        );
    }

    #[test]
    fn binfmt_without_interpreter_line_is_none() {
        assert_eq!(parse_binfmt_interpreter("enabled\noffset 0\n"), None);
        // A bare `interpreter ` with no path is rejected (not an empty path).
        assert_eq!(parse_binfmt_interpreter("interpreter   \n"), None);
        assert_eq!(parse_binfmt_interpreter(""), None);
    }
}

pub(crate) mod file_authority;
