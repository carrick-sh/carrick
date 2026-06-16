//! `run_elf_bhyve` — the thin static-ELF runner for the shared x86 engine.
//!
//! This crate stays cycle-free: it loads a static x86_64 Linux ELF, builds a
//! `X86EngineCore<BhyveVmm>`, and drives the shared `carrick-x86`
//! startup-syscall service loop. The full dispatcher path still lives in
//! `carrick-runtime::runtime::run_elf_bhyve_dispatch`.

#![cfg(target_arch = "x86_64")]

use std::path::Path;

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::AddressSpace;

use crate::guest_setup_x86::bring_up_x86_elf;

type BhyveX86Engine = carrick_x86::X86EngineCore<crate::bhyve_x86_engine::BhyveVmm>;

/// Build a fully brought-up x86_64 bhyve engine from an already prepared Linux
/// address space. The runtime OCI path owns ELF/argv/env/rootfs construction;
/// bhyve only consumes the finalized image and materializes it in the VMM.
pub fn build_x86_engine_from_image(image: &AddressSpace) -> Result<BhyveX86Engine, String> {
    let entry_rip = image.entry();
    let initial_rsp = image
        .initial_stack_pointer()
        .ok_or_else(|| "no initial stack pointer (with_linux_initial_stack failed?)".to_string())?;

    let bux = bring_up_x86_elf(image, entry_rip, initial_rsp)
        .map_err(|e| format!("bring_up_x86_elf: {e}"))?;
    Ok(crate::bhyve_x86_engine::engine_from_brought_up(bux))
}

/// Build a fully brought-up x86_64 bhyve engine on the shared `carrick-x86`
/// scaffold (`X86EngineCore<BhyveVmm>`).
pub fn build_x86_engine_shared(path: impl AsRef<Path>) -> Result<BhyveX86Engine, String> {
    let path = path.as_ref();
    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_for: {e}"))?
        .with_vdso_bytes(X8664GuestArch::vdso_bytes())
        .map_err(|e| format!("with_vdso_bytes: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?;

    build_x86_engine_from_image(&image)
}

/// Boot the static x86_64 ELF at `path` under bhyve and run the shared M2
/// startup-syscall service loop to exit.
pub fn run_elf_bhyve(path: impl AsRef<Path>) -> Result<i32, String> {
    let mut engine = build_x86_engine_shared(path)?;
    carrick_x86::run_elf_service_loop(&mut engine).map_err(|e| format!("run-elf: {e}"))
}
