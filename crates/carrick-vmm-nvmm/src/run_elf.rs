//! `run_elf_nvmm` — the M1 thin static-ELF run path (mirrors
//! `carrick_vmm_kvm::run_elf_kvm_x86`, NOT copied from carrick-vmm-bhyve).
//!
//! Loads a static x86_64 Linux ELF, brings up the generic
//! [`carrick_x86::X86EngineCore`]`<`[`crate::nvmm_x86_engine::NvmmVmm`]`>` over
//! NVMM, and runs the shared [`carrick_x86::run_elf_service_loop`] (the M2
//! startup syscall set lives once in carrick-x86) to exit.

use std::path::Path;

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
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

    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_x86: {e}"))?
        .with_vdso_bytes(X8664GuestArch::vdso_bytes())
        .map_err(|e| format!("with_vdso_bytes: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?;

    build_x86_engine_from_image(&image)
}

/// Boot the static x86_64 ELF at `path` under NVMM and run it to exit. Returns
/// the guest's exit code on success, or a diagnostic string on failure.
pub fn run_elf_nvmm(path: impl AsRef<Path>) -> Result<i32, String> {
    let path = path.as_ref();

    // `with_vdso_bytes`: materializes the shared x86_64 vDSO/vvar. Backends
    // without vvar calibration leave frequency zero, so the vDSO clock code
    // falls back to the real syscall path.
    // `with_linux_initial_stack`: argc/argv/envp/auxv on the guest stack.
    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_x86: {e}"))?
        .with_vdso_bytes(X8664GuestArch::vdso_bytes())
        .map_err(|e| format!("with_vdso_bytes: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?;

    let mut engine = build_x86_engine_from_image(&image)?;

    carrick_x86::run_elf_service_loop(&mut engine).map_err(|e| format!("run-elf: {e}"))
}
