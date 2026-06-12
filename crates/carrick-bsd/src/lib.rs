//! macOS/FreeBSD host-primitive implementations of the `carrick-hal` traits.
//!
//! Gated `cfg(any(target_os = "macos", target_os = "freebsd"))`. This crate
//! holds the BSD-family implementations lifted out of `carrick-runtime`
//! (errno translation here; kqueue/sendfile/futex added in the BSDIO section).
#![cfg(any(target_os = "macos", target_os = "freebsd"))]

pub mod errno;
pub use errno::bsd_to_linux_errno;

pub mod kqueue;
pub use kqueue::{Kevent, Kqueue, duplicate_internal_fd, relocate_internal_fd};
pub mod multiplexer;
pub use multiplexer::KqueueMultiplexer;

pub mod futex;
pub use futex::BsdFutex;
