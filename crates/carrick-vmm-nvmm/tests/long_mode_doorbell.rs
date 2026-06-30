//! Long-mode doorbell diagnostic (NetBSD/NVMM, runs as root).
//!
//! This isolates NVMM M1's first `nvmm_vcpu_run`: keep the full shared x86
//! long-mode bring-up, but overwrite the ring-0 entry stub with a local
//! `out %al,$0xC5; hlt` doorbell.
//!
//! Box-capability gated. On stock NetBSD/NVMM under nested KVM (`kvm_amd`), the
//! first `nvmm_vcpu_run` of a long-mode guest pauses QEMU with `internal-error`
//! before the kernel returns (lazy GPA faults under nested SVM). A box with
//! the eager-fault `nvmm.kmod` faults every mapped GPA
//! page up front and runs this path cleanly — verified 2026-06-19: the live
//! `hello_runs_to_zero` acceptance test exercises the same long-mode IO-exit
//! path to completion. So this test is gated on `CARRICK_NVMM_EAGER_FAULT=1`
//! (opt-in, set on eager-fault boxes) rather than unconditionally `#[ignore]`d,
//! so the capable box actually asserts the ring-0 → IO-exit baseline while
//! stock boxes still skip it. Same env-gate pattern as `CARRICK_NVMM_FIXTURE`.
#![cfg(target_os = "netbsd")]
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use carrick_hal::GuestVmBackend;
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_mem::memory::AddressSpace;
use carrick_mem::pml4::{Pml4Manager, walk_descriptors};
use carrick_x86::{X86_PML4_CAPACITY, X86Exit, X86Reg, X86Vcpu};

const ENTRY_STUB_OFF: u64 = 0x100;
const LONG_MODE_DOORBELL: &[u8] = &[0xb0, 0xc5, 0xe6, 0xc5, 0xf4];
const FIRST_OBSERVED_NPF_GPA: u64 = 0x1000_4400;

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

fn read_u64(bytes: &[u8], off: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[off..off + 8]);
    u64::from_le_bytes(word)
}

#[test]
fn pml4_region_covers_observed_nested_fault_gpa_before_first_run() {
    let Some(path) = fixture("CARRICK_NVMM_FIXTURE") else {
        eprintln!("skip: set CARRICK_NVMM_FIXTURE to a static x86_64 ELF");
        return;
    };

    let image = fixture_image(&path);
    let engine = carrick_vmm_nvmm::bring_up(&image).expect("nvmm long-mode bring-up");
    let layout = carrick_vmm_nvmm::NVMM_X86_LAYOUT;
    let pml4_len = X86_PML4_CAPACITY as usize;
    let observed_off = (FIRST_OBSERVED_NPF_GPA - layout.pml4_base) as usize;

    assert!(
        FIRST_OBSERVED_NPF_GPA >= layout.pml4_base && observed_off + 8 <= pml4_len,
        "observed nested-fault GPA must sit inside the NVMM PML4 region"
    );
    assert!(
        engine.vm().host_ptr(FIRST_OBSERVED_NPF_GPA, 8).is_some(),
        "NVMM userspace region table must cover observed nested-fault GPA {FIRST_OBSERVED_NPF_GPA:#x}"
    );

    let pml4_ptr = engine
        .vm()
        .host_ptr(layout.pml4_base, pml4_len)
        .expect("PML4 region must be mapped in NVMM userspace table");
    // SAFETY: `host_ptr` proved the full PML4 range is backed by one live region.
    let pml4_bytes = unsafe { std::slice::from_raw_parts(pml4_ptr, pml4_len) }.to_vec();
    let observed_word = read_u64(&pml4_bytes, observed_off);
    assert_ne!(
        observed_word, 0,
        "observed nested-fault GPA points at a zero PML4 byte word"
    );

    let pml4 = Pml4Manager::new(pml4_bytes.clone(), layout.pml4_base);
    assert_eq!(
        pml4.translate(FIRST_OBSERVED_NPF_GPA),
        Some(FIRST_OBSERVED_NPF_GPA),
        "PML4 bytes should self-map the page-table memory"
    );
    assert_eq!(
        pml4.translate(layout.trampoline_base + ENTRY_STUB_OFF),
        Some(layout.trampoline_base + ENTRY_STUB_OFF),
        "PML4 bytes should map the ring-0 entry stub"
    );
    assert!(
        pml4.translate(image.entry()).is_some(),
        "PML4 bytes should map the fixture entry point"
    );

    let walk = walk_descriptors(&pml4_bytes, layout.pml4_base, FIRST_OBSERVED_NPF_GPA);
    assert!(
        walk.iter().all(|desc| *desc != 0),
        "self-map walk for observed nested-fault GPA must stay present: {walk:#x?}"
    );
}

#[test]
fn long_mode_ring0_doorbell_reaches_io_exit() {
    // Gated on the eager-fault nvmm.kmod (opt-in via env): the first long-mode
    // `nvmm_vcpu_run` deadlocks QEMU on stock NetBSD/NVMM under nested SVM, so
    // only run where the box advertises the eager-fault module.
    if std::env::var_os("CARRICK_NVMM_EAGER_FAULT").is_none() {
        eprintln!("skip: set CARRICK_NVMM_EAGER_FAULT=1 on a box with the eager-fault nvmm.kmod");
        return;
    }
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
