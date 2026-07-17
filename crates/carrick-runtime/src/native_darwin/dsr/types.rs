//! Shim: the AArch64 DSR plan/exit vocabulary moved verbatim to
//! `carrick_dsr_aarch64::types` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::types::*` call paths resolve unchanged.
//!
//! The USDT probe projections (`probe_fields`/`probe_outcome`) moved to
//! `carrick_dsr_aarch64::translator` with their only consumers (the
//! translator orchestration), retargeted onto `carrick_dsr::probes`'
//! ordinal-exact mirrored enums — the runtime's probe forwarder maps those
//! onto the real `carrick-observability` USDT enums at the sink edge.

pub(in crate::native_darwin) use carrick_dsr_aarch64::types::*;
