//! macOS/FreeBSD host-primitive implementations of the `carrick-hal` traits.
//!
//! Gated `cfg(any(target_os = "macos", target_os = "freebsd"))`. This crate
//! holds the BSD-family implementations lifted out of `carrick-runtime`
//! (errno translation here; kqueue/sendfile/futex added in the BSDIO section).
#![cfg(any(target_os = "macos", target_os = "freebsd"))]

pub mod errno;
pub use errno::bsd_to_linux_errno;

// Filled by the BSDIO section (EventMultiplexer / Sendfile / CrossProcessFutex):
// pub mod kqueue;
// pub mod sendfile;
// pub mod futex;
