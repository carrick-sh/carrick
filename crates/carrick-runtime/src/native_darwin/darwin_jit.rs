//! Shim: the `carrick_dsr::host::NativeHostJit` seam is now provided by the
//! per-host native-lane crates (M0.6/M0.7 of the seams design) —
//! `carrick-native-darwin` for macOS (Apple-Silicon MAP_JIT; a fail-closed
//! stub on any other macOS arch) and `carrick-native-freebsd` for FreeBSD
//! (dual-mapped W^X SHM). This file re-exports whichever one applies so
//! every existing `darwin_jit::active_host_jit()` call site in this crate
//! resolves unchanged.

// The real Darwin host JIT (MAP_JIT single mapping on aarch64, fail-closed
// off Apple Silicon — both arms live in carrick-native-darwin itself).
#[cfg(target_os = "macos")]
pub(crate) use carrick_native_darwin::active_host_jit;

// The real FreeBSD host JIT (dual-mapped RW/RX SHM object; see
// carrick-native-freebsd for the design incl. the fork-sharing hazard that
// gates guest execution until M1's region-remap hook).
#[cfg(target_os = "freebsd")]
pub(crate) use carrick_native_freebsd::active_host_jit;

/// Fail-closed placeholder for hosts with no native-lane crate at all yet
/// (e.g. Linux, under `platform-linux`): the capability probe rejects, so
/// `TranslationCache::new` returns a typed cache policy error instead of
/// ever mapping code.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
mod unsupported {
    use carrick_dsr::host::{JitRegion, NativeHostJit};

    pub(crate) struct UnsupportedHostJit;

    impl NativeHostJit for UnsupportedHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Err("no native host JIT implementation for this target yet")
        }

        fn map_code_cache(&self, _capacity: usize) -> std::io::Result<JitRegion> {
            Err(std::io::Error::other(
                "no native host JIT implementation for this target yet",
            ))
        }

        unsafe fn unmap(&self, _region: &JitRegion) {}

        fn begin_thread_write(&self) {}

        fn end_thread_write(&self) {}

        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}

        fn after_fork_child(&self) {}
    }

    static UNSUPPORTED_HOST_JIT: UnsupportedHostJit = UnsupportedHostJit;

    pub(crate) fn active_host_jit() -> &'static dyn NativeHostJit {
        &UNSUPPORTED_HOST_JIT
    }
}

#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
pub(crate) use unsupported::active_host_jit;
