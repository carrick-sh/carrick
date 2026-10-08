//! Shared owner algorithms; hardware and Linux lowering stay with clients.
#![no_std]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
extern crate alloc;
pub mod lifecycle;
pub mod mm;
#[cfg(target_os = "macos")]
mod n1_diagnostics;
pub mod wait;

#[cfg(any(test, target_os = "macos"))]
extern crate std;
