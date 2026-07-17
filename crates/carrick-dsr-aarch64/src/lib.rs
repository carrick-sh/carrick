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
pub mod gateway;
pub mod snapshot;
pub mod types;
