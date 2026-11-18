//! `carrick-vmm-soft` — the VM-free soft x86 carrier (#671).
//!
//! M1-0 bring-up probe: boots the production CPL0 ring image on
//! [`carrick_softcpu_x86::SoftMachine`] from the neutral
//! [`carrick_x86_cpl0_host::cpl0_boot::prepare_boot`] value and the shared
//! [`carrick_x86_cpl0_host::cpl0_boot::BootCpuState`], then reports how far
//! it gets. It is not yet a `CarrierCpuBackend` and is not wired to the
//! runtime; see `docs/design/soft-x86-cpl0-bringup.md` ("Follow-up soft slice").

#![cfg(target_arch = "x86_64")]

pub mod cpu;
pub mod memory;
pub mod probe;

pub use cpu::{SoftBootVcpu, apply_boot_cpu_state};
pub use memory::SoftBootMemory;
pub use probe::{BootExit, BootReport, ProbeImage, boot_probe};
