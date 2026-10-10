//! Linux ABI decoding and result mapping; depends on neutral substrate.
//!
//! The same modules compile into both guest images; native operations are
//! supplied by the selected architecture backend.
pub mod aarch64_process;
#[cfg(test)]
mod aarch64_process_tests;
pub mod common_entry;
pub mod dispatch;
pub mod file;
pub mod inotify;
pub mod ipc;
pub mod lifecycle;
pub mod mm_portal;
pub mod native_process_custody;
pub mod native_process_entry;
pub mod native_process_runtime;
pub mod native_process_signals;
pub mod native_run_failure;
pub mod process_owner;
pub mod sched;
pub mod thread_setup;

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
mod arm_signal;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod x86_signal;
