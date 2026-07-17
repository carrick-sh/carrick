//! Moved verbatim to `carrick_dsr::address` as part of the staged
//! native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `address::*` / `super::super::address::*` call
//! paths resolve unchanged. The `NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE` /
//! `NATIVE_DARWIN_HARD_PAGEZERO_END` layout constants moved along with it.

pub(in crate::native_darwin) use carrick_dsr::address::*;
