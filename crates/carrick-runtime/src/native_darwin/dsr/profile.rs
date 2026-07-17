//! Shim: the DSR profiling census moved verbatim to `carrick_dsr::profile` as
//! part of the staged native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
//! This re-export keeps every existing `dsr::profile::*` call path in the
//! runtime resolving unchanged until the extraction completes.

pub(in crate::native_darwin) use carrick_dsr::profile::*;
