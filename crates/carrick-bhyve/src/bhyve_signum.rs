//! FreeBSD `linux <-> host` signal-number translation (SP4.2).
//!
//! This is now a thin re-export of the ONE BSD-family table in
//! [`carrick_bsd::signum`]. FreeBSD shares BSD signal numbering with macOS, so
//! the table that was previously copied here entry-for-entry (and a third time
//! in `carrick_hvf::host_signal`) lives once in `carrick-bsd`. See
//! `carrick_bsd::signum` for the table, the rationale, and the round-trip tests.
//!
//! Kept as a module path so the bhyve call sites
//! (`bhyve_disposition`/`bhyve_signal_pump`) need no churn.

pub use carrick_bsd::signum::{host_to_linux_signum, linux_to_host_signum};
