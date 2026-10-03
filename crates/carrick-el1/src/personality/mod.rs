//! Linux ABI decoding and result mapping; depends on neutral substrate.
//!
//! The x86_64 CPL0 image compiles only the frame-independent modules: the
//! normalized common entry and the thread-setup bodies it routes to. The
//! remaining modules still carry AArch64 frames or hardware hooks.
pub mod common_entry;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod dispatch;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod file;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod inotify;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod ipc;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod lifecycle;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod mm_portal;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub mod sched;
pub mod thread_setup;
