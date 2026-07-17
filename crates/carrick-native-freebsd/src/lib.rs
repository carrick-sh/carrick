//! `carrick-native-freebsd` — the FreeBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! First rung (M0.7 of the seams design,
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md):
//! the REAL dual-mapped W^X JIT backend. The trap transport (sigaction shim
//! reading the amd64 `mcontext_t`), the SIGPIPE kick plumbing, and the
//! fsbase-swap discipline land with M1 once the x86 gateway design exists to
//! consume them; nothing here speculates their shapes.
//!
//! The whole crate is FreeBSD-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-host-bsd`).

#![cfg(target_os = "freebsd")]

pub mod jit;

pub use jit::FreebsdHostJit;

/// The process-wide host-JIT instance handed to
/// `carrick_dsr_aarch64::translator::install_host_jit`-style installers by
/// the runtime's lane wiring (M0.8).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: FreebsdHostJit = FreebsdHostJit;
    &JIT
}
