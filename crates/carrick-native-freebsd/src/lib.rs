//! `carrick-native-freebsd` — the FreeBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! Two rungs of the seams design
//! (docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md)
//! live here: the dual-mapped W^X JIT backend (M0.7) and the guest-fault
//! shim ([`fault`]) that turns SIGSEGV/SIGBUS/SIGFPE/SIGILL inside the code
//! cache into typed gateway `Signal` exits. The SIGPIPE kick plumbing lands
//! with the runtime thread loop.
//!
//! The whole crate is FreeBSD-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-host-bsd`).

#![cfg(target_os = "freebsd")]

pub mod fault;
pub mod jit;

pub use jit::FreebsdHostJit;

/// The process-wide host-JIT instance handed to
/// `carrick_dsr_aarch64::translator::install_host_jit`-style installers by
/// the runtime's lane wiring (M0.8).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: FreebsdHostJit = FreebsdHostJit;
    &JIT
}
