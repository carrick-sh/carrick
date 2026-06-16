//! NetBSD `linux <-> host` signal-number translation.
//!
//! NetBSD uses the BSD signal numbering already captured in
//! `carrick-host-bsd`; keep this thin module so NVMM call sites have a VMM-local
//! path matching the KVM/bhyve glue.

pub use carrick_host_bsd::signum::{host_to_linux_signum, linux_to_host_signum};
