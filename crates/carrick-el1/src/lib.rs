//! Carrick guest EL1 image: neutral mechanisms and Linux personality.
//!
//! ISA selection: the AArch64 EL1 image and host builds compile every
//! module. The x86_64 CPL0 image (`target_os = "none"`, `x86_64`) compiles
//! only the frame-independent personality modules; the others still embed
//! AArch64 frames, system registers or the EL1 allocator.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
extern crate alloc as rust_alloc;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod alloc;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod cow;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod fault;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
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
mod native_ownership_tests;
