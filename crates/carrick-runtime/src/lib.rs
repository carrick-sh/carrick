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
//! trapped syscall is then *emulated* — translated to carrier-local kernel
//! state and bounded Darwin host primitives (real file descriptors, `kqueue`,
//! `__ulock`) — and the
//! result is written back into the guest registers before resuming. To the
//! Linux process it is running on Linux; there is no VM image, no init, no guest
//! ring-0 code. carrick is simultaneously the VMM *and* the kernel the guest
//! thinks it is talking to.
//!
//! This crate is now the **execution lane** of that pair, not the union of
//! both:
//!
//! - **The exec engine** (the leaf crate `carrick-vmm-hvf`, re-exported below under
//!   `crate::trap`, `crate::thread`, `crate::vcpu_kick`, …): the HVF trap engine
//!   that owns the vCPUs, process/exec address-space projection, the SIMD/FP
//!   restore shim, cross-thread vCPU coordination (the kicker and page-table
//!   quiesce barriers), the Darwin `kqueue` wrapper, and host-signal capture.
//!   This is the "VMM half".
//! - **The kernel half is `carrick-kernel`**: the kernel object graph, the
//!   syscall dispatcher and its subsystems, the namespaces, the in-zone
//!   network, the kernel-view filesystems and the container/run state. It
//!   names no carrier and no VMM module, so an execution backend other than
//!   this carrier can reuse it. Consumers import `carrick_kernel::…` directly;
//!   this crate re-exports none of it.
//! - **The lifecycle and the carrier** (this crate proper — [`runtime`],
//!   [`execute`], [`prepare`], `carrier`, `hvpatch`, `vcpu_loop`,
//!   `threaded_loop`): the glue that wires the two halves together. It loads
//!   the image, installs the EL0 trampoline / EL1 vectors / stage-1 page
//!   tables, then drives the trap → dispatch → complete loop until the guest
//!   exits. It also owns the fork/clone model (logical Carrick-kernel tasks for
//!   guest processes, one host thread per guest thread), fault-to-signal
//!   translation, and the interactive pty bridge
//!   ([`interactive_supervisor`]). It implements the `carrick-hal` bridges the
//!   kernel consumes ([`bridges`]). Start reading at [`runtime`].
//!
//! # The leaf-crate re-exports
//!
//! Several subsystems were lifted out of this crate into leaf crates to cut the
//! build-graph fan-out (a ~40k-line monolith re-linking on every edit). They are
//! re-exported below under their *original* `crate::<module>` paths, so every
//! call site across the carrier — and every `carrick_runtime::<module>` path the
//! CLI/engine crates use — is unchanged. When you see `crate::trap::…` or
//! `crate::memory::…` in this crate, the code physically lives in `carrick-vmm-hvf`
//! / `carrick-mem` / `carrick-host` / `carrick-abi`; the boundary is a build
//! optimisation, not a semantic one. `carrick-kernel` is the one split that is
//! NOT re-exported: it is a semantic boundary, so its paths are spelled
//! `carrick_kernel::…` at every call site.
//!
//! # Sharp edges (read before touching the lifecycle)
//!
//! - **The carrier must never fork for a guest task.** Guest `fork(2)` creates a
//!   logical Carrick-kernel task and a distinct MM projection inside the existing
//!   carrier. Host process creation is reserved for the typed CLI carrier-launch
//!   boundary.
//! - **One vCPU per guest thread, one process VM.** Stage-2 mappings are shared
//!   across all vCPUs, but stage-1 page-table edits (mmap/mprotect/munmap) and
//!   process-MM changes are coordinated through the quiesce barriers in
//!   `carrick-vmm-hvf::fork_quiesce`.

// carrick-runtime is an INTERNAL crate (consumed only by carrick-engine and
// carrick-cli), and its rustdoc is built with `--document-private-items` so the
// Big Theory Statements above and on each module can cross-link the internal
// run-loop / lifecycle items they describe (`run_vcpu_until_exit`,
// `run_vcpu_until_exit`, `ThreadRuntimeState`, …). Those items are deliberately
// NOT public API; allow the internal doc links
// rather than widen the public surface just to satisfy rustdoc.
#![allow(rustdoc::private_intra_doc_links)]

pub mod binfmt;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod dtrace_consumer;
#[cfg(target_os = "macos")]
pub mod dtrace_symbols;
pub mod host_process;
pub mod interactive_supervisor;
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
// (`thread`/`vcpu_kick`/`fork_quiesce`/`fork_coord`), the
// shared-aperture allocator, the Darwin `kqueue` wrapper, host-signal capture,
// the USDT probe provider (`probes`), compat-reporting (`compat`), and static
// syscall metadata (`syscall`). None depend on dispatch/VFS. Re-exported under
// their original `crate::trap::…` / `crate::thread::…` / … paths so every call
// site across the runtime is unchanged.
#[cfg(feature = "platform-macos")]
pub use carrick_vmm_hvf::{fork_coord, signal_arrival, threaded_impl, trap, vcpu_kick};
// The host-signal and guest-timer seams are NOT re-exported: dispatch and the
// kernel reach them only through the carrier's `CarrierBridges`
// (`carrick_hal::{HostSignalBridge, GuestTimerBridge}`), selected per lane in
// `bridges`; the macOS carrier names `carrick_vmm_hvf::{host_signal, io_wait,
// timer_delivery}` directly where it needs the HVF glue itself.
pub mod bridges;
pub use bridges::platform_bridges;
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
// Under platform-linux there is no carrick-vmm-hvf to re-export `trap` from; the
// SyscallTrap/TrapError contract lives in carrick-hal (section
// HAL). Re-export a `trap` shim so `crate::trap::{SyscallTrap, …}` resolves on
// both platforms. The concrete engine (HvfTrapEngine / KvmTrapEngine) is
// selected by the run-loop, which is itself platform-gated.
#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub mod trap {
    pub use carrick_hal::{RawSyscall, SyscallTrap, TrapError};
    // Portable helpers the native (DSR) backend shares with the HVF trap
    // layer; real impls for every host OS live in carrick-host (the HVF trap
    // module re-exports the same symbols on macOS, so `crate::trap::…`
    // resolves identically on both platform arms).
    pub use carrick_host::clock::host_clock_uptime_ns;
    pub use carrick_host::futex_key::{shared_file_key_base, shared_futex_waiter_key};
    pub const HVF_PAGE_SIZE: u64 = carrick_guest_mem::HOST_PAGE_GRANULE;

    // Cross-process VM-topology bookkeeping the shared threaded loop references
    // around a guest fork/exec. The shared `vcpu_loop` fork/exec paths RUN on
    // Linux (the generic threaded loop drives them on both backends since the
    // Phase 2 KVM bring-up); what differs is how much host-side VM surgery
    // each backend needs. On HVF these hooks coordinate the stop-the-world VM
    // teardown/rebuild (carrick-vmm-hvf::trap); KVM forks by rebuilding a fresh VM
    // in the CHILD only, so the HVF-specific hooks below stay inert no-ops —
    // same pattern as the `probes` Linux stub.

    /// Dump cross-thread kick statistics at process exit. No-op on Linux.
    pub fn dump_kick_stats() {}
}

pub mod carrier;
pub use carrier::{
    CarrierAdmissionState, CarrierLease, CarrierRuntime, CarrierSnapshot, ContainerInitSnapshot,
};
pub mod threaded_loop;
pub mod vcpu_loop;
// Platform-NEUTRAL debug-state snapshot + vDSO attach policy (moved out of the
// macOS `runtime.rs` arm; both `runtime` arms re-export them so the original
// `crate::runtime::…` call-site paths resolve on every platform).
pub mod debug_state;
#[cfg(feature = "platform-macos")]
pub mod execute;
pub(crate) mod hvpatch;
pub mod prepare;
#[cfg(feature = "platform-macos")]
pub mod runtime;
pub use prepare::{
    ExecutionPlan, PreparedRun, Runtime, RuntimeExtensions, prepare_on, resolve_plan,
};

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use carrick_vmm_hvf::{read_el1_counters, reset_el1_counters};

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn read_el1_counters() -> Option<carrick_el1_abi::Counters> {
    None
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn reset_el1_counters() {}

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
///   3. Apple's fixed macOS location
///      (`dispatch::rosetta::ROSETTA_INTERPRETER`).
pub fn rosetta_interpreter_path() -> String {
    if let Some(p) = std::env::var_os("CARRICK_ROSETTA_PATH") {
        return p.to_string_lossy().into_owned();
    }
    if let Ok(reg) = std::fs::read_to_string("/proc/sys/fs/binfmt_misc/rosetta") {
        if let Some(path) = parse_binfmt_interpreter(&reg) {
            return path.to_string();
        }
    }
    carrick_kernel::dispatch::rosetta::ROSETTA_INTERPRETER.to_string()
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
pub mod runtime {
    pub use crate::debug_state::{DebugRegionSnapshot, DebugStateSnapshot, maybe_dump_debug_state};
    // Private: `RunResult`/`RuntimeError` are kernel types and the carrier does
    // not re-export them. The `run_oci` signature below names them; callers name
    // `carrick_kernel::run_result::…`.
    use carrick_kernel::run_result::{RunResult, RuntimeError};

    pub fn run_oci(_spec: &carrick_spec::RunSpec) -> Result<RunResult, RuntimeError> {
        Err(RuntimeError::Unsupported(
            "Pending port to hvpatch VM carrier model".to_string(),
        ))
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
