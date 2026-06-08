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
pub mod fork;
pub mod guest_setup;
pub mod kvm;
pub mod kvm_fork_coord;
pub mod kvm_futex;
pub mod kvm_kicker;
pub mod kvm_signal_pump;
pub mod run_elf;
pub mod signal_arrival;
pub mod timer_delivery;
pub mod trap_engine;

pub use kvm::{KvmVcpu, KvmVm};
pub use signal_arrival::KvmSignalArrival;
pub use timer_delivery::KvmTimerDelivery;
pub use kvm_fork_coord::KvmForkCoordinator;
pub use kvm_futex::KvmFutex;
pub use kvm_kicker::{KvmKickHandle, KvmKicker, install_kvm_kick_handler};
pub use run_elf::run_elf_kvm;
pub use trap_engine::KvmTrapEngine;
