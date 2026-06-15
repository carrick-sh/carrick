//! carrick-vmm-kvm: the Linux/KVM VMM backend.
//!
//! Proves the `carrick-hal` seam end-to-end on real hardware KVM by booting a
//! freestanding aarch64 ELF, servicing its syscalls via the MMIO-sentinel trap
//! vehicle, and exiting cleanly. For the MVP the syscalls (`write`/`writev`,
//! `exit`/`exit_group`) are serviced directly in the `run_elf` module — reusing the full
//! `carrick-runtime` dispatch on Linux is the full-backend spec's job (it needs
//! ~200 macOS-isms ported out of the dispatch layer). All hypervisor code is
//! `cfg(target_os = "linux")`; on any other host this crate is intentionally
//! empty.
//!
//! The Linux host-OS glue that used to live here (the native epoll
//! `EventMultiplexer` and the `host_to_linux_errno` identity hook) was split
//! out into the VMM-agnostic `carrick-host-linux` crate; carrick-runtime wires
//! both together under the `platform-linux` feature.
#![cfg(target_os = "linux")]

pub mod guest_setup;
pub mod kvm;
pub mod kvm_disposition;
pub mod kvm_fork_coord;
pub mod kvm_futex;
pub mod kvm_kicker;
pub mod kvm_signal_pump;
pub mod kvm_xsig;
// `KvmSignalArrival` was byte-identical to bhyve's; both collapsed into the
// shared `carrick_hal::GenericSignalArrival` (kicker + futex wake). The KVM run
// loop constructs that directly, so this backend has no SignalArrival module.
pub mod timer_delivery;

// aarch64-only modules: fork snapshot/restore, the MMIO-sentinel trap engine,
// and the aarch64 standalone run-elf loop all use ARM-specific KVM APIs
// (KVM_GET/SET_ONE_REG, ARM sysregs, EL1 vector, vDSO vvar) that do not exist
// on x86_64.  The x86_64 analogues live in the cfg(x86_64) stubs below.
#[cfg(target_arch = "aarch64")]
pub mod fork;
#[cfg(target_arch = "aarch64")]
pub mod run_elf;
#[cfg(target_arch = "aarch64")]
pub mod trap_engine;

pub use kvm::{KvmVcpu, KvmVm};
pub use kvm_fork_coord::KvmForkCoordinator;
pub use kvm_futex::{KvmFutex, make_kvm_futex};
pub use kvm_kicker::{KvmKickHandle, KvmKicker, install_kvm_kick_handler};
pub use timer_delivery::KvmTimerDelivery;

#[cfg(target_arch = "aarch64")]
pub use run_elf::run_elf_kvm;
#[cfg(target_arch = "aarch64")]
pub use trap_engine::KvmTrapEngine;

// x86_64 KVM backend modules.
// Compiled only on Linux x86_64 — invisible to the aarch64 build.
#[cfg(target_arch = "x86_64")]
pub mod guest_setup_x86;
// The KVM x86 lane on the shared `carrick-x86` scaffold (portability S4-KVM):
// `KvmVmm`/`impl X86Vcpu for KvmVcpu` + `bring_up` → `X86EngineCore<KvmVmm>`.
// Replaces the hand-rolled `KvmX86TrapEngine`.
#[cfg(target_arch = "x86_64")]
pub mod kvm_x86_engine;
#[cfg(target_arch = "x86_64")]
pub mod run_elf_x86;
