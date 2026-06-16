//! Long-mode doorbell diagnostic (NetBSD/NVMM, runs as root).
//!
//! This isolates NVMM M1's first `nvmm_vcpu_run`: keep the full shared x86
//! long-mode bring-up, but overwrite the ring-0 entry stub with a local
//! `out %al,$0xC5; hlt` doorbell.
//!
//! Keep this ignored until the nested-SVM blocker is fixed. Under a hypervisor
//! `kvm_amd`, this currently pauses QEMU with `internal-error` before
//! NetBSD/NVMM returns from `nvmm_vcpu_run`; see the 2026-06-15 monitor-capture
//! note under `docs/superpowers/notes/`.
#![cfg(target_os = "netbsd")]
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::AddressSpace;
use carrick_x86::{X86Exit, X86Reg, X86Vcpu, X86Vmm};

const ENTRY_STUB_OFF: u64 = 0x100;
const LONG_MODE_DOORBELL: &[u8] = &[0xb0, 0xc5, 0xe6, 0xc5, 0xf4];

fn fixture(env: &str) -> Option<PathBuf> {
    std::env::var_os(env)
        .map(PathBuf::from)
        .filter(|p| p.exists())
}

fn fixture_image(path: &PathBuf) -> AddressSpace {
    AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .expect("load fixture x86_64 ELF")
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .expect("build fixture initial stack")
        .with_vdso_auxv(false)
}

#[test]
#[ignore = "nested NetBSD/NVMM currently pauses QEMU with internal-error in svm_vmrun"]
fn long_mode_ring0_doorbell_reaches_io_exit() {
    let Some(path) = fixture("CARRICK_NVMM_FIXTURE") else {
        eprintln!("skip: set CARRICK_NVMM_FIXTURE to a static x86_64 ELF");
        return;
    };

    let image = fixture_image(&path);
    let mut engine = carrick_vmm_nvmm::bring_up(&image).expect("nvmm long-mode bring-up");
    let stub_gpa = carrick_vmm_nvmm::NVMM_X86_LAYOUT.trampoline_base + ENTRY_STUB_OFF;
    engine
        .vm()
        .write_gpa(stub_gpa, LONG_MODE_DOORBELL)
        .expect("overwrite ring-0 entry stub with doorbell");
    engine
        .vcpu_mut()
        .set_gpr(X86Reg::Rip, stub_gpa)
        .expect("point RIP at diagnostic stub");

    let exit = engine.vcpu_mut().run().expect("run diagnostic stub");
    let X86Exit::Syscall { frame, resume_pc } = exit else {
        panic!("expected syscall doorbell IO exit, got {exit:?}");
    };
    assert_eq!(
        frame.rax & 0xFF,
        0xC5,
        "diagnostic stub should load AL with the doorbell marker"
    );
    assert_eq!(
        resume_pc,
        stub_gpa + 4,
        "NVMM should return the next PC after OUT"
    );

    engine
        .vcpu_mut()
        .set_gpr(X86Reg::Rip, resume_pc)
        .expect("resume at HLT after doorbell");
    assert!(
        matches!(
            engine.vcpu_mut().run().expect("run HLT after doorbell"),
            X86Exit::Halt
        ),
        "diagnostic stub should halt after the doorbell"
    );
}
