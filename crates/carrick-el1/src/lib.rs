//! Carrick guest EL1 image: neutral mechanisms and Linux personality.
//!
//! ISA selection: the AArch64 EL1 image and host builds compile every
//! module. The x86_64 CPL0 image (`target_os = "none"`, `x86_64`) also
//! compiles the ISA-neutral lock and frame-independent personality modules;
//! the remaining modules still embed AArch64 frames or system registers.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
extern crate alloc as rust_alloc;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod alloc;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod cow;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod fault;
pub mod lock;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod memory;
pub mod personality;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod substrate;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub use fault::dispatch_fault;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub use personality::dispatch::*;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub use personality::{file, inotify, sched};

#[cfg(test)]
#[path = "personality/native_ownership_tests.rs"]
mod native_ownership_tests;
