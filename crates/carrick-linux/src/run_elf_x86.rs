//! Thin MVP run path: boot a static x86_64 Linux ELF under KVM on Linux x86_64
//! and service its syscalls via the shared [`carrick_x86::run_elf_service_loop`].
//!
//! Mirrors `run_elf_bhyve` (carrick-bhyve) in structure: no `carrick-runtime`
//! dependency — keeps the crate cycle-free and container-104-compilable.
//!
//! Since portability Stage 4-KVM the KVM lane is the generic
//! [`carrick_x86::X86EngineCore`]`<`[`KvmVmm`]`>`, and the M2 startup syscall set
//! lives once in `carrick-x86`; this file is the KVM-specific ELF-load + bring-up
//! wrapper around it.
//!
//! [`KvmVmm`]: crate::kvm_x86_engine::KvmVmm

use std::path::Path;

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::AddressSpace;

/// Boot the static x86_64 ELF at `path` under KVM and run it to exit.
///
/// Returns the guest's exit code on success, or a diagnostic string on failure.
pub fn run_elf_kvm_x86(path: impl AsRef<Path>) -> Result<i32, String> {
    let path = path.as_ref();

    // ── Load the ELF ─────────────────────────────────────────────────────────
    //
    // `with_linux_initial_stack`: builds argc/argv/envp/auxv on the guest stack.
    // `with_vdso_auxv(false)`: strips `AT_SYSINFO_EHDR` (no vDSO in Phase 2;
    //   musl falls back to real SYSCALL instructions).
    let image = AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_x86: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()], // argv[0] = ELF path
            std::iter::empty::<&[u8]>(),           // no env vars
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))?
        .with_vdso_auxv(false);

    // ── Bring up the generic engine over the KVM backend pair ────────────────
    let mut engine =
        crate::kvm_x86_engine::bring_up(&image).map_err(|e| format!("kvm-x86 bring-up: {e}"))?;

    // ── Run the shared M2 service loop ───────────────────────────────────────
    carrick_x86::run_elf_service_loop(&mut engine).map_err(|e| format!("run-elf: {e}"))
}
