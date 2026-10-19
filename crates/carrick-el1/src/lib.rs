//! Carrick guest EL1 runtime: neutral mechanisms. The Linux personality
//! client and the image binary live in `carrick-el1-linux`.
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
pub mod substrate;

#[cfg(test)]
#[path = "isa/x86/context_resume.rs"]
mod x86_context_resume_tests;
#[cfg(test)]
#[path = "isa/x86/context_words.rs"]
mod x86_context_words_tests;
#[cfg(test)]
#[path = "isa/x86/interrupts.rs"]
#[allow(dead_code)]
mod x86_interrupt_timer_tests;
