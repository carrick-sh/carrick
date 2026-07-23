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
pub mod emit;
pub mod emulate;
pub mod esr;
pub mod gateway;
pub mod mapped_memory;
pub mod prepared_image;
pub mod snapshot;
pub mod translator;
pub mod types;

/// AArch64 guest ISA implementation for the DSR lane seam.
pub struct Aarch64Isa;

impl carrick_dsr::lane::GuestIsa for Aarch64Isa {
    const NAME: &'static str = "aarch64";
    const USER_VA_END_EXCLUSIVE: u64 = 1u64 << 48;
    const GUEST_PAGE_SIZE: usize = 16384; // Darwin lane value today
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::GuestIsa;

    #[test]
    fn aarch64_isa_constants() {
        assert_eq!(Aarch64Isa::NAME, "aarch64");
        assert_eq!(Aarch64Isa::USER_VA_END_EXCLUSIVE, 1u64 << 48);
        assert_eq!(Aarch64Isa::GUEST_PAGE_SIZE, 16384);
    }
}
