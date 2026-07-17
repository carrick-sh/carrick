//! Shim: the native prepared-image schema (regions/spans/relocations record,
//! validation, and the copy-window helper) moved wholesale to
//! `carrick_dsr_aarch64::prepared_image` as part of the staged
//! native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `crate::native_prepared_image::*` call paths
//! resolve unchanged.
//!
//! The re-export is UNCONDITIONAL on purpose, preserving the schema
//! contract this module always had: the arch crate compiles on every
//! target, so the prepared-image schema keeps compiling on every target
//! (`native_cfg_topology_tests` in lib.rs asserts exactly this).

pub(crate) use carrick_dsr_aarch64::prepared_image::*;
