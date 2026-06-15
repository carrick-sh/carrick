//! carrick-observability: platform-NEUTRAL observability shared by every backend.
//!
//! Currently the syscall-compatibility reporter ([`compat`]) — the recorder that
//! aggregates unhandled/partial syscalls, ioctls, and coverage against the static
//! [`carrick_abi::syscall`] table and renders a JSON/text report. It was
//! carrick-vmm-hvf-private (re-exported on macOS, a no-op unit-struct STUB on the
//! Linux/KVM arm), so neither Linux nor bhyve produced a real compat report;
//! hoisting it here gives every backend the real reporter.
//!
//! The DTrace `probes` provider is NOT here — it is genuine per-backend usdt glue
//! (macOS/FreeBSD fire real probes, Linux is a no-op). compat is decoupled from it
//! via a probe-fire HOOK ([`compat::set_probe_hook`]) the dtrace backends install,
//! so this crate carries no usdt dependency.

pub mod compat;
