//! Native-lane abstraction: (guest ISA, host OS) pairings for the DSR backend.
//!
//! A native lane is a concrete combination of:
//! - A **guest ISA** (AArch64, x86_64): defines user VA space bounds and page size.
//! - A **host OS** (Darwin, FreeBSD): provides JIT authority and syscall transport.
//!
//! Phase 1 carries only what shared slices consume; gateway/emit surfaces
//! join in Phase 2 (spec §traits).

use crate::host::NativeHostJit;

/// Guest-ISA half of a native lane. Phase 1 carries only what the shared
/// slices consume; gateway/emit surfaces join in Phase 2 (spec §traits).
pub trait GuestIsa: 'static + Send + Sync {
    const NAME: &'static str; // "aarch64" | "x86_64"

    /// Exclusive end of canonical user VA (x86_64: 1<<47; aarch64: 1<<48).
    const USER_VA_END_EXCLUSIVE: u64;

    /// Native guest page size the ISA lane translates for.
    const GUEST_PAGE_SIZE: usize;
}

/// Host-OS half of a native lane. Phase 1: JIT authority only.
pub trait NativeHost: 'static + Send + Sync {
    const NAME: &'static str; // "darwin" | "freebsd"

    fn active_jit() -> &'static dyn NativeHostJit;
}

/// A concrete (ISA, Host) pairing. Native lanes are same-ISA by definition.
pub trait NativeLane: 'static + Send + Sync {
    type Isa: GuestIsa;
    type Host: NativeHost;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Dummy host JIT for testing (fail-closed pattern from darwin_jit.rs)
    struct TestHostJit;

    impl NativeHostJit for TestHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Err("test stub")
        }

        fn map_code_cache(&self, _capacity: usize) -> std::io::Result<crate::host::JitRegion> {
            Err(std::io::Error::other("test stub"))
        }

        unsafe fn unmap(&self, _region: &crate::host::JitRegion) {}

        fn begin_thread_write(&self) {}

        fn end_thread_write(&self) {}

        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}

        fn after_fork_child(&self) {}

        fn remap_for_fork_child(
            &self,
            _prior: &crate::host::JitRegion,
        ) -> std::io::Result<crate::host::ForkChildJit> {
            Err(std::io::Error::other("test stub"))
        }
    }

    static TEST_HOST_JIT: TestHostJit = TestHostJit;

    // Dummy test host for trait composition
    struct TestHost;

    impl NativeHost for TestHost {
        const NAME: &'static str = "test";

        fn active_jit() -> &'static dyn NativeHostJit {
            &TEST_HOST_JIT
        }
    }

    // Dummy test ISA for trait composition
    struct TestIsa;

    impl GuestIsa for TestIsa {
        const NAME: &'static str = "test";
        const USER_VA_END_EXCLUSIVE: u64 = 1u64 << 48;
        const GUEST_PAGE_SIZE: usize = 4096;
    }

    // Dummy test lane for trait composition
    struct TestLane;

    impl NativeLane for TestLane {
        type Isa = TestIsa;
        type Host = TestHost;
    }

    /// Compile-check test: verify trait bundle composes correctly.
    fn assert_lane<L: NativeLane>() {}

    #[test]
    fn lane_traits_compose() {
        assert_lane::<TestLane>();
    }
}
