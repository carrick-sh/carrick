//! `carrick-vmm-soft` — the VM-free soft x86 carrier (#671).
//!
//! [`SoftCarrier`] boots the CPL0 ring image on
//! [`carrick_softcpu_x86::SoftMachine`] through the same neutral boot the KVM
//! carrier uses: [`carrick_x86_cpl0_host::cpl0_boot::prepare_boot`],
//! [`carrick_x86_cpl0_host::cpl0_boot::install_boot_memory`] over the soft
//! [`SoftVm`] slot table, the shared
//! [`carrick_x86_cpl0_host::cpl0_boot::BootCpuState`] and
//! `BootstrapCustody`, and admits the initial guest MM through the shared
//! [`carrick_x86_cpl0_host::cpl0_boot::load_guest_mm`]. [`boot_probe`]
//! reports how far a ring image gets. It is not yet a `CarrierCpuBackend`
//! and is not wired to the runtime; see
//! `docs/design/soft-x86-cpl0-bringup.md` ("Follow-up soft slice").

#![cfg(target_arch = "x86_64")]

pub mod carrier;
pub mod cpu;
pub mod memory;
pub mod probe;

pub use carrier::{SoftBootImage, SoftCarrier, SoftRunTrace, SoftStop};
pub use cpu::{SoftBootVcpu, apply_boot_cpu_state};
pub use memory::{SoftCarrierMemory, SoftVm};
pub use probe::{BootExit, BootReport, ProbeBind, ProbeImage, boot_probe};
