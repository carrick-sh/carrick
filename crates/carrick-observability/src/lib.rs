//! carrick-observability: platform-NEUTRAL observability shared by every backend.
//!
//! Currently the syscall-compatibility reporter ([`compat`]) — the recorder that
//! aggregates unhandled/partial syscalls, ioctls, and coverage against the static
//! [`carrick_abi::syscall`] table and renders a JSON/text report. It was
//! carrick-vmm-hvf-private (re-exported on macOS, a no-op unit-struct STUB on the
//! Linux/KVM arm), so neither Linux nor bhyve produced a real compat report;
//! hoisting it here gives every backend the real reporter.
//!
//! The DTrace [`probes`] provider also lives here now (hoisted out of the
//! macOS-only carrick-vmm-hvf crate): macOS/FreeBSD compile the REAL `usdt`
//! provider, Linux/NetBSD a no-op stub with identical signatures. Sharing it
//! here is what lets the FreeBSD/bhyve build fire genuine probes too. compat
//! stays decoupled from the provider via a probe-fire HOOK
//! ([`compat::set_probe_hook`]) the dtrace backends install in
//! [`probes::register_dtrace_probes`].

pub mod compat;
pub mod probes;
