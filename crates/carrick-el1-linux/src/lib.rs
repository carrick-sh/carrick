//! Linux personality client of the neutral `carrick-el1` runtime: Linux ABI
//! decoding and result mapping, and the EL1 image binary (`entry.rs`).
//!
//! The same modules compile into both guest images; native operations are
//! supplied by the selected architecture backend.
#![cfg_attr(target_os = "none", no_std)]
#[cfg(target_os = "none")]
extern crate alloc as rust_alloc;
pub mod aarch64_process;
#[cfg(any(test, feature = "host-test"))]
pub mod aarch64_process_tests;
pub mod common_entry;
pub mod cow_resolver;
pub mod dispatch;
pub mod file;
pub mod file_table;
pub mod fork_loan;
pub mod inotify;
pub mod ipc;
pub mod lifecycle;
pub mod mm_portal;
pub mod native_fork_refusal;
pub mod native_process_custody;
pub mod native_process_entry;
pub mod native_process_runtime;
pub mod native_process_signals;
pub mod native_run_failure;
pub mod process_owner;
pub mod retired_spaces;
pub mod sched;
pub mod signal_delivery;
pub mod thread_setup;

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub mod arm_signal;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub mod x86_signal;

#[cfg(test)]
#[path = "reservation_decoder_tests.rs"]
mod decoder_tests;
#[cfg(test)]
mod native_ownership_tests;
