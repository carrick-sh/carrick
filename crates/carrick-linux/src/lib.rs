//! carrick-linux: the KVM aarch64 MVP backend.
//!
//! Proves the `carrick-hal` seam end-to-end on real hardware KVM by booting a
//! freestanding aarch64 ELF, servicing its syscalls through the existing
//! `carrick-runtime` dispatch via the MMIO-sentinel trap vehicle, and exiting
//! cleanly. All hypervisor code is `cfg(target_os = "linux")`; on any other
//! host this crate is intentionally empty.
#![cfg(target_os = "linux")]

pub mod errno;

#[cfg(target_os = "linux")]
pub mod guest_setup;
#[cfg(target_os = "linux")]
pub mod kvm;
#[cfg(target_os = "linux")]
pub mod trap_engine;

#[cfg(target_os = "linux")]
pub use kvm::{KvmVcpu, KvmVm};
#[cfg(target_os = "linux")]
pub use trap_engine::KvmTrapEngine;
