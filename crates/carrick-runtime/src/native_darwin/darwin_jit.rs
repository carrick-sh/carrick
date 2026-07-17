//! Transitional Darwin implementation of the `carrick_dsr::host::NativeHostJit`
//! seam: exactly the MAP_JIT / `pthread_jit_write_protect_np` / sys-icache
//! plumbing that lived inline in the pre-extraction
//! `native_darwin/dsr/cache.rs`. This impl migrates to the
//! `carrick-native-darwin` host crate in a later slice (M0.6 of the seams
//! design); it lives here so this slice keeps the runtime's behavior
//! byte-identical while the cache itself moves to `carrick-dsr`.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod darwin {
    use std::ptr::NonNull;

    use carrick_dsr::host::{JitRegion, NativeHostJit};

    pub(crate) struct DarwinHostJit;

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
            unsafe {
                super::super::carrick_native_clear_icache(exec_ptr as *mut libc::c_void, len)
            };
        }

        fn after_fork_child(&self) {
            unsafe { libc::pthread_jit_write_protect_np(1) };
        }
    }

    static DARWIN_HOST_JIT: DarwinHostJit = DarwinHostJit;

    pub(crate) fn active_host_jit() -> &'static dyn NativeHostJit {
        &DARWIN_HOST_JIT
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use darwin::active_host_jit;

/// Fail-closed placeholder for targets without a native host JIT yet: the
/// capability probe rejects, so `TranslationCache::new` returns a typed cache
/// policy error instead of ever mapping code. The real FreeBSD host lands
/// with `carrick-native-freebsd` (M0.7 of the seams design).
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
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

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub(crate) use unsupported::active_host_jit;
