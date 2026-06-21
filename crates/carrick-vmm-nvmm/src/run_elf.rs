//! `run_elf_nvmm` — the M1 thin static-ELF run path (mirrors
//! `carrick_vmm_kvm::run_elf_kvm_x86`, NOT copied from carrick-vmm-bhyve).
//!
//! Loads a static x86_64 Linux ELF, brings up the generic
//! [`carrick_x86::X86EngineCore`]`<`[`crate::nvmm_x86_engine::NvmmVmm`]`>` over
//! NVMM, and runs the shared [`carrick_x86::run_elf_service_loop`] (the M2
//! startup syscall set lives once in carrick-x86) to exit.

use std::path::Path;

use carrick_mem::memory::AddressSpace;

type NvmmX86Engine = carrick_x86::X86EngineCore<crate::nvmm_x86_engine::NvmmVmm>;

/// Build a fully brought-up x86_64 NVMM engine from an already prepared Linux
/// address space. The runtime OCI path owns ELF/argv/env/rootfs construction;
/// NVMM only consumes the finalized image and materializes it in the VMM.
pub fn build_x86_engine_from_image(image: &AddressSpace) -> Result<NvmmX86Engine, String> {
    crate::nvmm_x86_engine::bring_up(image).map_err(|e| format!("nvmm-x86 bring-up: {e}"))
}

/// Build a fully brought-up x86_64 NVMM engine on the shared `carrick-x86`
/// scaffold.
pub fn build_x86_engine_shared(path: impl AsRef<Path>) -> Result<NvmmX86Engine, String> {
    let path = path.as_ref();

    let image = carrick_x86::load_x86_elf_image(path)?;

    build_x86_engine_from_image(&image)
}

/// Boot the static x86_64 ELF at `path` under NVMM and run it to exit. Returns
/// the guest's exit code on success, or a diagnostic string on failure.
pub fn run_elf_nvmm(path: impl AsRef<Path>) -> Result<i32, String> {
    let path = path.as_ref();

    // The map + vDSO/vvar + Linux initial-stack idiom is shared across every x86
    // run-elf path (KVM/bhyve/NVMM).
    let image = carrick_x86::load_x86_elf_image(path)?;

    let mut engine = build_x86_engine_from_image(&image)?;

    carrick_x86::run_elf_service_loop(&mut engine).map_err(|e| format!("run-elf: {e}"))
}
