//! Carrick runtime crate.
//!
//! This crate hosts the Linux ABI translation layer, guest address-space
//! management, syscall dispatcher, rootfs/VFS support, signal/thread handling,
//! and HVF trap engine used by the CLI and engine crates.

#[cfg(target_os = "macos")]
pub mod apfs;
pub mod compat;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_fs;
#[cfg(target_os = "macos")]
pub(crate) mod darwin_kqueue;
pub mod dispatch;
#[cfg(target_os = "macos")]
pub mod dtrace_consumer;
pub mod elf;
pub(crate) mod fork_coord;
pub(crate) mod fork_quiesce;
pub mod fs_backend;
pub mod guest_cpu;
pub mod host_facts;
#[cfg(target_os = "macos")]
pub(crate) mod host_mapping;
pub mod host_proc;
pub mod host_signal;
pub mod host_tty;
pub mod interactive_supervisor;
pub mod io_wait;
pub(crate) mod itimer;
pub mod linux_abi;
pub mod memory;
pub mod overlay;
pub(crate) mod page_table;

pub mod execute;
pub mod probes;
pub mod pty_relay;
pub mod rootfs;
pub mod runtime;
pub(crate) mod shared_aperture;
pub mod syscall;
pub mod thread;
pub mod trap;
pub mod ulock;
pub mod vcpu_kick;
pub mod vdso;
pub mod vfs;
pub use execute::Runtime;
