//! Darwin's `carrick_dsr::host::NativeHostJit` seam: the MAP_JIT /
//! `pthread_jit_write_protect_np` / sys-icache plumbing that lived inline in
//! the pre-extraction `native_darwin/dsr/cache.rs`, then in the transitional
//! `carrick-runtime/src/native_darwin/darwin_jit.rs` shim, and now lives here
//! (M0.6 of the seams design) — the real host-crate home, moved byte-for-byte.
//!
//! `DarwinHostJit` (and the `carrick_native_clear_icache` C shim it calls,
//! compiled by this crate's `build.rs` from `csrc/native_darwin.c`) is
//! genuinely Apple-Silicon-only: MAP_JIT's per-thread write-protect toggle is
//! an aarch64 hardware feature. On any other macOS arch this crate still
//! provides `active_host_jit()` (the crate's whole-`target_os = "macos"` gate
//! covers both arches), but it resolves to a fail-closed stub so
//! `TranslationCache::new` gets a typed cache-policy error instead of ever
//! mapping code — mirroring the "unsupported" fallback the runtime shim used
//! to carry for this exact case.

#[cfg(target_arch = "aarch64")]
mod darwin {
    use std::ptr::NonNull;

    use carrick_dsr::host::{JitRegion, NativeHostJit};

    pub struct DarwinHostJit;

    // The C trap/kick shim (`csrc/native_darwin.c`) is genuinely Darwin+
    // aarch64: x18 guest-ABI switching, `__darwin_mcontext64` snapshots, and
    // the MAP_JIT cache bounds all live there, and `build.rs` only compiles
    // it for that target.
    unsafe extern "C" {
        fn carrick_native_clear_icache(start: *mut libc::c_void, len: usize);
    }

    impl NativeHostJit for DarwinHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            if unsafe { libc::pthread_jit_write_protect_supported_np() } == 0 {
                return Err("pthread JIT write protection is unavailable");
            }
            Ok(())
        }

        fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion> {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = NonNull::new(mapped.cast::<u8>())
                .ok_or_else(|| std::io::Error::other("MAP_JIT returned a null mapping"))?;
            // MAP_JIT: writability is a per-thread hardware toggle, so the
            // write pointer IS the exec pointer.
            Ok(JitRegion {
                exec_base: base,
                write_base: base,
                capacity,
            })
        }

        unsafe fn unmap(&self, region: &JitRegion) {
            let _ = unsafe { libc::munmap(region.exec_base.as_ptr().cast(), region.capacity) };
        }

        fn begin_thread_write(&self) {
            unsafe { libc::pthread_jit_write_protect_np(0) };
        }

        fn end_thread_write(&self) {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }

        fn flush_icache(&self, exec_ptr: *const u8, len: usize) {
            unsafe { carrick_native_clear_icache(exec_ptr as *mut libc::c_void, len) };
        }

        fn after_fork_child(&self) {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }
    }

    static DARWIN_HOST_JIT: DarwinHostJit = DarwinHostJit;

    /// The process-wide host-JIT instance handed to
    /// `carrick_dsr_aarch64::translator::install_host_jit`-style installers
    /// by the runtime's lane wiring (M0.8).
    pub fn active_host_jit() -> &'static dyn NativeHostJit {
        &DARWIN_HOST_JIT
    }
}

#[cfg(target_arch = "aarch64")]
pub use darwin::{DarwinHostJit, active_host_jit};

/// Fail-closed placeholder for a macOS host that isn't Apple Silicon: the
/// capability probe rejects, so `TranslationCache::new` returns a typed cache
/// policy error instead of ever mapping code. Same contract as the runtime
/// shim's own `unsupported` module (which still covers non-macOS,
/// non-FreeBSD hosts) — this arm exists because THIS crate's gate is
/// `target_os = "macos"` for both arches, while the real `DarwinHostJit`
/// above needs aarch64.
#[cfg(not(target_arch = "aarch64"))]
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

    /// Same signature as [`super::darwin::active_host_jit`] so callers never
    /// see a cfg seam: whichever arm compiles, `active_host_jit()` exists.
    pub fn active_host_jit() -> &'static dyn NativeHostJit {
        &UNSUPPORTED_HOST_JIT
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub use unsupported::active_host_jit;

#[cfg(test)]
mod tests {
    use super::*;

    const CAPACITY: usize = 64 * 1024;

    #[test]
    fn supported_reports_a_typed_result() {
        // On aarch64 hardware this is `Ok`; on the non-aarch64 fallback arm
        // it fails closed. Either way it must not panic.
        let jit = active_host_jit();
        let _ = jit.supported();
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn map_code_cache_round_trips_on_apple_silicon() {
        let jit = active_host_jit();
        jit.supported().expect("MAP_JIT must be supported here");
        let region = jit.map_code_cache(CAPACITY).expect("map");
        assert_eq!(
            region.exec_base, region.write_base,
            "MAP_JIT: the write pointer IS the exec pointer"
        );
        assert_eq!(region.capacity, CAPACITY);
        unsafe { jit.unmap(&region) };
    }

    #[test]
    #[cfg(not(target_arch = "aarch64"))]
    fn map_code_cache_fails_closed_off_apple_silicon() {
        let jit = active_host_jit();
        assert!(jit.supported().is_err());
        assert!(jit.map_code_cache(CAPACITY).is_err());
    }
}
