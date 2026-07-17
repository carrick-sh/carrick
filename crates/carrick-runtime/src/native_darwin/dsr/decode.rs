//! Shim: the AArch64 DSR decoder moved verbatim to
//! `carrick_dsr_aarch64::decode` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::decode::*` call paths resolve unchanged.

// `allow(unused_imports)`: on the platform-freebsd check the runtime
// consumers of this shim do not typecheck yet (they still reference bad64
// directly until the M0.4-completing slice), so the re-export reports as
// unused there; the macOS lane uses it.
#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr_aarch64::decode::*;
