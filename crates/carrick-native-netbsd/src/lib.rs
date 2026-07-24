//! `carrick-native-netbsd` — the NetBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! Task 1 of the NetBSD native-lane plan lands the dual-mapped W^X JIT backend
//! here (`jit`), built on the Task-0 grounding
//! (docs/superpowers/specs/2026-07-25-netbsd-primitives-grounding.md): NetBSD
//! has no `SHM_ANON`, so the anonymous backing object is a uniquely-named
//! `shm_open` that is `shm_unlink`ed immediately, then mapped twice (RX + RW).
//! The guest-fault shim (`fault`) and cross-process futex (`futex`/
//! `waiter_key`) join in Tasks 2 and 3.
//!
//! The whole crate is NetBSD-only by construction (same `#![cfg]` pattern as
//! `carrick-native-freebsd`); other targets compile it to nothing, so the
//! module doc above uses a plain code span rather than an intra-doc link that
//! `cargo doc` could not resolve off-NetBSD.

#![cfg(target_os = "netbsd")]

pub mod jit;

pub use jit::NetbsdHostJit;

/// The process-wide host-JIT instance handed to the runtime's lane wiring
/// (mirrors `carrick-native-freebsd::active_host_jit`).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: NetbsdHostJit = NetbsdHostJit;
    &JIT
}

/// The NetBSD half of a native lane (`carrick_dsr::lane::NativeHost`): hands
/// the lane wiring this crate's JIT authority. Mirrors `FreebsdHost`.
///
/// Unlike FreeBSD, NetBSD needs neither seam override (Task-0 grounding):
/// there is no `MAP_EXCL` (so `exclusive_fixed_map_flag` keeps the default 0,
/// overlap protection staying in `NativeMappingTransaction`), and the kernel
/// keys shared futexes by their backing object, so `shared_futex_waiter_key`
/// keeps the default `None` (finalized in Task 3) rather than a
/// `kern.proc.vmmap`-style derivation.
pub struct NetbsdHost;

impl carrick_dsr::lane::NativeHost for NetbsdHost {
    const NAME: &'static str = "netbsd";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn netbsd_host_name_and_jit_are_wired() {
        assert_eq!(NetbsdHost::NAME, "netbsd");
        NetbsdHost::active_jit().supported().expect("supported");
    }
}
