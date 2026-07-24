//! `carrick-native-freebsd` — the FreeBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! Two rungs of the seams design
//! (docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md)
//! live here: the dual-mapped W^X JIT backend (M0.7) and the guest-fault
//! shim (`fault`) that turns SIGSEGV/SIGBUS/SIGFPE/SIGILL inside the code
//! cache into typed gateway `Signal` exits. The SIGPIPE kick plumbing lands
//! with the runtime thread loop.
//!
//! `fault` (like every other item below) only exists when this crate's whole
//! body is compiled in on `target_os = "freebsd"`; the module doc above uses
//! a plain code span rather than an intra-doc link so `cargo doc` does not
//! try (and fail) to resolve it on other hosts, where the `#![cfg]` below
//! leaves this crate empty.
//!
//! The whole crate is FreeBSD-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-host-bsd`).

#![cfg(target_os = "freebsd")]

pub mod fault;
pub mod futex;
pub mod jit;
mod waiter_key;

pub use jit::FreebsdHostJit;

/// The process-wide host-JIT instance handed to
/// `carrick_dsr_aarch64::translator::install_host_jit`-style installers by
/// the runtime's lane wiring (M0.8).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: FreebsdHostJit = FreebsdHostJit;
    &JIT
}

/// The FreeBSD half of a native lane (`carrick_dsr::lane::NativeHost`):
/// hands the lane wiring this crate's JIT authority. Mirrors
/// `carrick-native-darwin`'s `DarwinHost`.
pub struct FreebsdHost;

impl carrick_dsr::lane::NativeHost for FreebsdHost {
    const NAME: &'static str = "freebsd";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }

    fn shared_futex_waiter_key(host_addr: usize) -> Option<usize> {
        waiter_key::shared_waiter_key(host_addr)
    }

    fn exclusive_fixed_map_flag() -> i32 {
        libc::MAP_EXCL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn freebsd_host_name_and_jit_are_wired() {
        assert_eq!(FreebsdHost::NAME, "freebsd");
        FreebsdHost::active_jit().supported().expect("supported");
    }
}
