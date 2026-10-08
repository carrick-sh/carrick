//! Carrick guest EL1 image: neutral mechanisms and Linux personality.
//!
//! One kernel body is compiled into the AArch64 EL1 and x86_64 CPL0 images.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;
pub mod alloc;
pub mod cow;
pub mod fault;
pub mod isa;
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
#[cfg(test)]
#[path = "isa/x86/context_words.rs"]
mod x86_context_words_tests;
#[cfg(test)]
#[path = "isa/x86/initial_mm.rs"]
mod x86_initial_mm_tests;
#[cfg(test)]
#[path = "isa/x86/interrupts.rs"]
#[allow(dead_code)]
mod x86_interrupt_timer_tests;

#[cfg(test)]
#[path = "isa/x86/user_tables.rs"]
mod x86_user_tables_tests;
