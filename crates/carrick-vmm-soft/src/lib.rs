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
//! reports how far a ring image gets. [`SoftCarrier::into_worker_parts`]
//! hands its CPUs, as [`SoftCpuBackend`]s behind the shared
//! `CarrierCpuBackend` seam, to the shared production worker custody. It is
//! not wired to the runtime; see
//! `docs/design/soft-x86-cpl0-bringup.md` ("Follow-up soft slice").

#![cfg(target_arch = "x86_64")]

pub mod backend;
pub mod carrier;
pub mod cpu;
pub mod memory;
pub mod probe;

pub use backend::{SoftCpuBackend, SoftKick, SoftRunContext, SoftWatchdog};
pub use carrier::{
    SoftBootImage, SoftCarrier, SoftCpuIo, SoftRunTrace, SoftRunner, SoftStop, SoftWorkerParts,
    soft_cpuid,
};
pub use cpu::{SoftBootVcpu, SoftCpuView, apply_boot_cpu_state};
pub use memory::{SoftCarrierMemory, SoftVm, publish_worker_backings};
pub use probe::{BootExit, BootReport, ProbeBind, ProbeImage, boot_probe};
