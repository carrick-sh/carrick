//! `carrick-native-darwin` — the macOS host layer for the native (DSR)
//! backend.
//!
//! The single-mapping MAP_JIT W^X JIT backend (M0.6) lives here: [`jit`]
//! provides `DarwinHostJit` (the real Apple-Silicon MAP_JIT /
//! `pthread_jit_write_protect_np` implementation) plus [`active_host_jit`],
//! moved byte-for-byte out of the transitional
//! `carrick-runtime/src/native_darwin/darwin_jit.rs` shim (which becomes a
//! thin re-export of this crate). The C trap/kick shim
//! (`csrc/native_darwin.c`) moved with it — `build.rs` compiles it under the
//! same target gate it always used.
//!
//! The whole crate is macOS-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-native-freebsd`). Within
//! that macOS gate, [`jit`] narrows further to aarch64 for the real
//! implementation — Apple Silicon is the only hardware `MAP_JIT`'s
//! per-thread write-protect toggle exists on — with a fail-closed fallback
//! for any other macOS arch, mirroring the runtime shim's own "unsupported"
//! arm.

#![cfg(target_os = "macos")]

pub mod aot;
pub mod aot_cache;
/// Tier D: run guest code directly, patching only `svc`/x18/`tpidr_el0`.
/// aarch64-only — the whole premise is same-ISA execution.
#[cfg(target_arch = "aarch64")]
pub mod direct;
pub mod jit;

#[cfg(target_arch = "aarch64")]
pub use jit::DarwinHostJit;
pub use jit::active_host_jit;

/// The Darwin half of a native lane (`carrick_dsr::lane::NativeHost`):
/// hands the lane wiring this crate's JIT authority.
pub struct DarwinHost;

impl carrick_dsr::lane::NativeHost for DarwinHost {
    const NAME: &'static str = "darwin";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn darwin_host_name_and_jit_are_wired() {
        assert_eq!(DarwinHost::NAME, "darwin");
        // Must not panic regardless of arch (aarch64 real impl vs the
        // fail-closed fallback on any other macOS arch).
        let _ = DarwinHost::active_jit().supported();
    }
}
