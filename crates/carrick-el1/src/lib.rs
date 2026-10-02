//! Carrick guest EL1 image: neutral mechanisms and Linux personality.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;
pub mod alloc;
pub mod cow;
pub mod fault;
pub mod lock;
pub mod memory;
pub mod personality;
pub mod substrate;
pub use fault::dispatch_fault;
pub use personality::dispatch::*;
pub use personality::{file, inotify, sched};

#[cfg(test)]
#[path = "personality/native_ownership_tests.rs"]
mod native_ownership_tests;
