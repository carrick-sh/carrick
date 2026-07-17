//! Moved verbatim (modulo the `NativeHostJit` host seam and the typed
//! `CacheError`) to `carrick_dsr::cache` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::cache::*` call paths resolve unchanged.

pub(in crate::native_darwin) use carrick_dsr::cache::*;
