//! carrick-linux: the KVM aarch64 MVP backend.
//!
//! Proves the `carrick-hal` seam end-to-end on real hardware KVM by booting a
//! freestanding aarch64 ELF, servicing its syscalls via the MMIO-sentinel trap
//! vehicle, and exiting cleanly. For the MVP the syscalls (`write`/`writev`,
//! `exit`/`exit_group`) are serviced directly in the `run_elf` module — reusing the full
//! `carrick-runtime` dispatch on Linux is the full-backend spec's job (it needs
//! ~200 macOS-isms ported out of the dispatch layer). All hypervisor code is
//! `cfg(target_os = "linux")`; on any other host this crate is intentionally
//! empty.
#![cfg(target_os = "linux")]

pub mod errno;
pub mod guest_setup;
pub mod kvm;
pub mod run_elf;
pub mod trap_engine;

pub use kvm::{KvmVcpu, KvmVm};
pub use run_elf::run_elf_kvm;
pub use trap_engine::KvmTrapEngine;
