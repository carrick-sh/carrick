#![allow(
    clippy::collapsible_if,
    clippy::manual_is_multiple_of,
    rustdoc::broken_intra_doc_links
)]

//! HVF vCPU / exec-engine leaf crate for the carrick runtime.
//!
//! This crate holds the dispatch-free vCPU cluster: the Hypervisor.framework
//! trap engine (`trap`, with its `SyscallTrap` contract, `TrapError`,
//! `HvfTrapEngine`, fork/exec address-space management and the SIMD/FP C shim),
//! cross-thread vCPU coordination (`thread`, `vcpu_kick`, `io_wait`, `itimer`,
//! `fork_quiesce`, `fork_coord`), the shared-aperture allocator, the Darwin
//! `kqueue` wrapper, host-signal capture, the USDT probe provider (`probes`),
//! the compat-reporting primitives (`compat`), and static syscall metadata
//! (`syscall`).
//!
//! None of these modules depend on the runtime's dispatcher/VFS layers, so they
//! live in their own crate to keep edits to the vCPU/exec engine from
//! recompiling the ~40k-line runtime (and vice versa). `carrick-runtime`
//! re-exports every module here under its original `crate::<module>` path so
//! all call sites are unchanged.
//!
//! The modules reference the other leaf crates through the same re-export
//! aliases the runtime uses (`crate::linux_abi`, `crate::memory`,
//! `crate::host_mapping`, …); those aliases are re-declared below so the moved
//! code resolves identically inside this crate.

// Leaf-crate re-exports mirroring carrick-runtime's lib.rs, so the moved
// modules' `crate::linux_abi::…` / `crate::memory::…` / `crate::host_mapping::…`
// paths resolve unchanged inside carrick-vmm-hvf.
pub use carrick_abi as linux_abi;
pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock};
pub use carrick_mem::{elf, memory, page_table, vdso};

// The syscall-compat reporter is platform-neutral; it lives in carrick-observability
// (every backend shares it instead of the old HVF-impl-vs-Linux-stub cfg split).
// Re-exported as `crate::compat` so call sites are unchanged. The macOS probe-fire
// hook is installed in `probes::register_dtrace_probes`.
pub use carrick_observability::compat;
// The USDT (DTrace) probe provider was hoisted into carrick-observability too, so
// the FreeBSD/bhyve build gets the REAL provider (Linux/NetBSD get the no-op stub).
// Re-exported as `crate::probes` so the HVF trap engine's `crate::probes::…` call
// sites are unchanged on macOS.
pub use carrick_observability::probes;
#[cfg(target_os = "macos")]
pub mod darwin_kqueue;
pub mod fork_coord;
pub mod fork_quiesce;
pub mod host_signal;
pub mod io_wait;
pub mod itimer;
pub mod posix_timer;
// AArch64 syscall metadata is platform-neutral ABI data — hoisted to carrick-abi
// (shared by KVM/bhyve, which used to get a `lookup → None` stub). Re-exported as
// `crate::syscall` so HVF's compat reporter + the probes provider are unchanged.
pub use carrick_abi::syscall;
pub mod signal_arrival;
pub mod syscall_mailbox;
pub mod thread;
pub mod threaded_impl;
pub mod timer_delivery;
pub mod trap;
pub mod vcpu_kick;
// The HVF aarch64 backend on the shared `carrick-aarch64` scaffold (F7 step 4/5):
// the thin `Aarch64Vmm`/`Aarch64Vcpu` trait pair the generic `Aarch64EngineCore`
// is parameterized over. `crate::trap::HvfTrapEngine` aliases the specialization.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod hvf_aarch64_engine;
// Root death-reclaim supervisor for the flag-gated atomic vCPU permit: one
// EVFILT_PROC kqueue that frees a dead owner's generation-stamped slots. Started
// from `HvfHostBackend::pre_loop_setup` via `trap::start_vcpu_permit_reaper`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod vcpu_permit_reaper;

/// Serializes tests that fork REAL child processes. The test binary is one
/// process, so any-child wait paths under test (`wait4(-1)`,
/// `waitid(P_ALL)`, `child_status_ready(-1)`) see EVERY test's children:
/// a concurrent forking test's child gets stolen - or outright reaped - by
/// a sibling's any-child wait, failing both tests (the recurring `just ci`
/// carrick-vmm-hvf flake). Every test that forks holds this for its whole
/// fork-to-wait-to-reap lifetime.
#[cfg(test)]
pub(crate) fn fork_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
