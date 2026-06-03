//! Shared helpers for the perf benchmark gate (`tests/perf_runner.rs`).
//! Lives in a subdirectory so cargo does NOT compile it as its own test binary;
//! it is pulled in via `mod perf_support;` from perf_runner.rs.
pub mod stats;
pub mod metric;
pub mod provenance;
pub mod invoke;
