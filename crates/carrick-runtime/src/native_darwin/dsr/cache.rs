//! Moved verbatim (modulo the `NativeHostJit` host seam and the typed
//! `CacheError`) to `carrick_dsr::cache` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::cache::*` call paths resolve unchanged.

// `allow(unused_imports)`: the runtime LIB no longer names `dsr::cache::*`
// since the translator orchestration moved to the arch crate; the re-export
// stays for the oracle and the JIT-entangled test suites.
#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr::cache::*;
