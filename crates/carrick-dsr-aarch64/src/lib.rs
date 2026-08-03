//! `carrick-dsr-aarch64` — the AArch64 guest-ISA half of the native (DSR)
//! execution backend: bad64 decode/classification, block planning (including
//! exclusive-region fusion analysis), dynasmrt emission, the gateway context
//! and its `gateway_aarch64.S` entry/exit surface, the CNTVCT/Apple-timebase
//! counter plan, and the per-block artifact-spike store.
//!
//! The whole crate compiles on every host (bad64/dynasmrt are pure Rust);
//! only the gateway's assembled half is target-gated — one
//! `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]` boundary in
//! `gateway`, mirrored by this crate's `build.rs`. Off that lane the gateway
//! entry points fail closed with `DsrError::Gateway`.
//!
//! Extracted verbatim from `carrick-runtime/src/native_darwin/dsr` (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! while the extraction is staged the runtime re-exports these modules under
//! their old paths so call sites are unchanged. The live-execution oracle
//! (`dsr/oracle.rs`) stays in the runtime: every one of its tests drives the
//! Darwin JIT, the assembled gateway, or the C trap shim, none of which link
//! from this crate before the host-seam slice (M0.6) lands.

pub mod artifact_spike;
pub mod block;
pub mod counter;
pub mod decode;
pub mod direct_binding;
pub mod emit;
pub mod emulate;
pub mod esr;
pub mod gateway;
pub mod mapped_memory;
pub mod pending_augmentation;
pub mod prot_ranges;
// The prepared-image schema moved to `carrick-dsr` (the platform-neutral
// crate) as part of the staged native-backend extraction: it is ISA-free
// (Task 6, docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
// Re-exported under its old path so every `carrick_dsr_aarch64::prepared_image::…`
// call site (notably `carrick-runtime`'s `native_prepared_image.rs` shim) is
// unchanged.
pub use carrick_dsr::prepared_image;
pub mod shared_cache;
pub mod snapshot;
pub mod translator;
pub mod types;

/// AArch64 guest ISA implementation for the DSR lane seam.
pub struct Aarch64Isa;

impl carrick_dsr::lane::GuestIsa for Aarch64Isa {
    const NAME: &'static str = "aarch64";
    const USER_VA_END_EXCLUSIVE: u64 = 1u64 << 48;
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::GuestIsa;

    #[test]
    fn aarch64_isa_constants() {
        assert_eq!(Aarch64Isa::NAME, "aarch64");
        assert_eq!(Aarch64Isa::USER_VA_END_EXCLUSIVE, 1u64 << 48);
    }
}

#[cfg(test)]
mod direct_binding_tests {
    use super::direct_binding::PrivateJitEpoch;
    use std::sync::Arc;

    #[test]
    fn private_epoch_reports_live_descriptor_leases() {
        let epoch = PrivateJitEpoch::process_owner();
        assert_eq!(Arc::strong_count(&epoch), 1);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 0);

        let lease = Arc::clone(&epoch);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 1);
        drop(lease);
        assert_eq!(Arc::strong_count(&epoch), 1);
        assert_eq!(PrivateJitEpoch::live_descriptor_leases(&epoch), 0);
    }
}

/// Plain-mmap host JIT + cache constructor for this crate's unit tests: the
/// emitted bytes are never executed by these tests, so no `MAP_JIT` or
/// icache maintenance is needed.
#[cfg(test)]
pub(crate) mod test_jit {
    use carrick_dsr::cache::TranslationCache;
    use carrick_dsr::host::{ForkChildJit, JitRegion, NativeHostJit};
    use std::ptr::NonNull;

    struct TestHostJit;

    static TEST_HOST_JIT: TestHostJit = TestHostJit;

    impl NativeHostJit for TestHostJit {
        fn supported(&self) -> Result<(), &'static str> {
            Ok(())
        }

        fn map_code_cache(&self, capacity: usize) -> std::io::Result<JitRegion> {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error());
            }
            let base = NonNull::new(mapped.cast::<u8>())
                .ok_or_else(|| std::io::Error::other("mmap returned null"))?;
            Ok(JitRegion {
                exec_base: base,
                write_base: base,
                capacity,
            })
        }

        unsafe fn unmap(&self, region: &JitRegion) {
            let _ = unsafe { libc::munmap(region.exec_base.as_ptr().cast(), region.capacity) };
        }

        fn begin_thread_write(&self) {}

        fn end_thread_write(&self) {}

        fn flush_icache(&self, _exec_ptr: *const u8, _len: usize) {}

        fn remap_for_fork_child(&self, _prior: &JitRegion) -> std::io::Result<ForkChildJit> {
            Ok(ForkChildJit::Inherited)
        }
    }

    pub(crate) fn test_cache(capacity: usize) -> TranslationCache {
        TranslationCache::new(capacity, &TEST_HOST_JIT).expect("allocate test translation cache")
    }
}
