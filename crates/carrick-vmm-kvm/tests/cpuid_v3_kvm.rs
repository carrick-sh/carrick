//! Live KVM guest `CPUID` + `XGETBV` + `x86-64-v3` ISA conformance fixtures (#667 / #578).
//!
//! Proves on both x86 KVM execution paths (`Cpl0Carrier` 2-vCPU ring-3 carrier and
//! `carrick-vmm-kvm run-elf`) that:
//! 1. Every `CPUID` leaf observed by ring-3 guest `CPUID` instructions matches
//!    `carrick_x86::GuestCpuidView` (`x86-64-v3` + CPL0 `SMEP`/`SMAP`, per-vCPU `APIC ID`,
//!    host-clamped `MAXPHYADDR`, calibrated `CPUID.15H`).
//! 2. Zero features outside `x86-64-v3` (no `AVX-512`, `AMX`, `SHA`, `AES`, `PCLMULQDQ`,
//!    `RDRAND`, `RDSEED`, `ADX`, `FSGSBASE`, `PKU`, `LA57`, `UMIP`, `XSAVEOPT`/`XSAVEC`/`XSAVES`,
//!    `TSC_DEADLINE`, `HYPERVISOR`, `0x4000_0000`, `RDTSCP`, `PDPE1GB`, or AMD SEV leaves)
//!    leak through to the guest.
//! 3. `XGETBV(0)` returns `0x7` (`x87 | SSE | AVX`) and `AVX2` (`vpcmpeqd ymm0` / `vpmovmskb`),
//!    `BMI1` (`blsi`), `BMI2` (`pdep`), `LZCNT`, `POPCNT`, and `MOVBE` execute natively.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/physical_inventory.rs"]
mod physical_inventory;

use std::path::PathBuf;
use std::process::Command;

use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;
use carrick_x86::cpl0_entry::OBSERVE_NATIVE;
use carrick_x86::cpuid::{
    CPUID_1_ECX_HYPERVISOR, CPUID_1_ECX_X86_64_V3, CPUID_1_EDX_X86_64_V3, CPUID_7_0_EBX_PINNED,
    CPUID_8000_0001_ECX_X86_64_V3, CPUID_8000_0001_EDX_X86_64_V3, CPUID_8000_0007_EDX_INVTSC,
};
use carrick_x86::{CpuidRegs, GuestCpuidView, XCR0_X86_64_V3_MASK};
use physical_inventory::physical_inventory;

const PROBED_LEAVES: &[(u32, u32)] = &[
    (0x0000_0000, 0),
    (0x0000_0001, 0),
    (0x0000_0002, 0),
    (0x0000_0006, 0),
    (0x0000_0007, 0),
    (0x0000_0007, 1),
    (0x0000_0007, 2),
    (0x0000_000b, 0),
    (0x0000_000d, 0),
    (0x0000_000d, 1),
    (0x0000_000d, 2),
    (0x0000_000d, 5),
    (0x0000_0015, 0),
    (0x0000_0015, 1),
    (0x0000_0016, 0),
    (0x0000_0017, 0),
    (0x0000_001f, 0),
    (0x4000_0000, 0),
    (0x4000_0001, 0),
    (0x8000_0000, 0),
    (0x8000_0001, 0),
    (0x8000_0002, 0),
    (0x8000_0007, 0),
    (0x8000_0008, 0),
    (0x8000_001f, 0),
];

/// Expected packed witness `(popcnt(32) << 24) | (lzcnt(11) << 16) | (blsi(8) << 8) | pdep(0x50)`.
const EXPECTED_V3_ISA_WITNESS: u32 = 0x200b_0850;
const EXPECTED_MOVBE_WITNESS: u32 = 0x7856_3412;

fn image() -> PathBuf {
    PathBuf::from(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"))
}

fn emit_observe_rax(code: &mut Vec<u8>) {
    code.extend_from_slice(&[0x48, 0x89, 0xc7]); // mov rdi, rax
    code.extend_from_slice(&[0x48, 0xb8]); // movabs rax, OBSERVE_NATIVE
    code.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x05]); // syscall
}

/// Emit `AVX2` + `POPCNT` + `LZCNT` + `BMI1` + `BMI2` calculation leaving `EXPECTED_V3_ISA_WITNESS` in `eax`.
fn emit_v3_isa_witness_into_eax(code: &mut Vec<u8>) {
    code.extend_from_slice(&[
        0xc5, 0xfd, 0x76, 0xc0, // vpcmpeqd ymm0, ymm0, ymm0   (AVX2 -> all 1s)
        0xc5, 0xfd, 0xd7, 0xc0, // vpmovmskb eax, ymm0         (AVX2 -> 0xffff_ffff)
        0xf3, 0x0f, 0xb8, 0xc8, // popcnt ecx, eax             (POPCNT -> 32)
        0xb8, 0x00, 0x00, 0x10, 0x00, // mov eax, 0x0010_0000
        0xf3, 0x0f, 0xbd, 0xd0, // lzcnt edx, eax              (LZCNT -> 11)
        0x41, 0x89, 0xd0, // mov r8d, edx
        0xb8, 0x28, 0x00, 0x00, 0x00, // mov eax, 0x28
        0xc4, 0xe2, 0x78, 0xf3, 0xd8, // blsi eax, eax         (BMI1 -> 8)
        0xba, 0xf0, 0x0f, 0x00, 0x00, // mov edx, 0x0ff0
        0xbe, 0x05, 0x00, 0x00, 0x00, // mov esi, 5
        0xc4, 0xe2, 0x4b, 0xf5, 0xf2, // pdep esi, esi, edx    (BMI2 -> 0x50)
        0xc5, 0xf8, 0x77, // vzeroupper                        (AVX)
        0xc1, 0xe1, 0x18, // shl ecx, 24
        0x41, 0xc1, 0xe0, 0x10, // shl r8d, 16
        0xc1, 0xe0, 0x08, // shl eax, 8
        0x09, 0xc8, // or eax, ecx
        0x44, 0x09, 0xc0, // or eax, r8d
        0x09, 0xf0, // or eax, esi
    ]);
}

fn cpl0_cpuid_probe_program() -> Vec<u8> {
    let mut code = Vec::new();
    for &(leaf, subleaf) in PROBED_LEAVES {
        // Word 0: (ebx << 32) | eax
        code.push(0xb8);
        code.extend_from_slice(&leaf.to_le_bytes());
        code.push(0xb9);
        code.extend_from_slice(&subleaf.to_le_bytes());
        code.extend_from_slice(&[
            0x0f, 0xa2, // cpuid
            0x48, 0xc1, 0xe3, 0x20, // shl rbx, 32
            0x89, 0xc0, // mov eax, eax
            0x48, 0x09, 0xd8, // or rax, rbx
        ]);
        emit_observe_rax(&mut code);

        // Word 1: (edx << 32) | ecx
        code.push(0xb8);
        code.extend_from_slice(&leaf.to_le_bytes());
        code.push(0xb9);
        code.extend_from_slice(&subleaf.to_le_bytes());
        code.extend_from_slice(&[
            0x0f, 0xa2, // cpuid
            0x48, 0xc1, 0xe2, 0x20, // shl rdx, 32
            0x89, 0xc8, // mov eax, ecx
            0x48, 0x09, 0xd0, // or rax, rdx
        ]);
        emit_observe_rax(&mut code);
    }

    // XGETBV(0) -> (edx << 32) | eax
    code.extend_from_slice(&[
        0x31, 0xc9, // xor ecx, ecx
        0x0f, 0x01, 0xd0, // xgetbv
        0x48, 0xc1, 0xe2, 0x20, // shl rdx, 32
        0x89, 0xc0, // mov eax, eax
        0x48, 0x09, 0xd0, // or rax, rdx
    ]);
    emit_observe_rax(&mut code);

    // Execute real AVX2 / BMI1 / BMI2 / LZCNT / POPCNT instructions in ring 3.
    emit_v3_isa_witness_into_eax(&mut code);
    emit_observe_rax(&mut code);

    code.extend_from_slice(&[0x0f, 0x0b]); // ud2 sentinel after all observations
    assert!(
        code.len() <= 4096,
        "CPL0 CPUID probe program ({}) must fit in one 4 KiB code page",
        code.len()
    );
    code
}

fn assert_observed_leaves_are_strictly_v3(
    observed: &[((u32, u32), CpuidRegs)],
    expected_view: GuestCpuidView,
) {
    for &((leaf, subleaf), got) in observed {
        let want = expected_view.cpuid(leaf, subleaf);
        assert_eq!(
            got,
            want,
            "guest CPUID({leaf:#x}, {subleaf:#x}) diverged from GuestCpuidView \
             (apic_id={}): got={got:?} want={want:?}",
            expected_view.apic_id()
        );
    }

    let find = |leaf: u32, subleaf: u32| -> CpuidRegs {
        observed
            .iter()
            .find(|&&((l, s), _)| l == leaf && s == subleaf)
            .map(|&(_, r)| r)
            .expect("probed leaf present")
    };

    let l1 = find(1, 0);
    assert_eq!(
        l1.ecx & !CPUID_1_ECX_X86_64_V3,
        0,
        "non-v3 1.ECX bits leaked"
    );
    assert_eq!(l1.ecx & CPUID_1_ECX_HYPERVISOR, 0, "hypervisor bit leaked");
    assert_eq!(
        l1.edx & !CPUID_1_EDX_X86_64_V3,
        0,
        "non-v3 1.EDX bits leaked"
    );

    let l7_0 = find(7, 0);
    assert_eq!(l7_0, CpuidRegs::new(0, CPUID_7_0_EBX_PINNED, 0, 0));
    assert_eq!(find(7, 1), CpuidRegs::ZERO);
    assert_eq!(find(7, 2), CpuidRegs::ZERO);
    assert_eq!(find(0x0d, 1), CpuidRegs::ZERO);
    assert_eq!(find(0x0d, 5), CpuidRegs::ZERO);
    assert_eq!(find(0x4000_0000, 0), CpuidRegs::ZERO);
    assert_eq!(find(0x4000_0001, 0), CpuidRegs::ZERO);
    assert_eq!(
        find(0x8000_0001, 0),
        CpuidRegs::new(
            0,
            0,
            CPUID_8000_0001_ECX_X86_64_V3,
            CPUID_8000_0001_EDX_X86_64_V3,
        )
    );
    assert_eq!(
        find(0x8000_0007, 0),
        CpuidRegs::new(0, 0, 0, CPUID_8000_0007_EDX_INVTSC)
    );
    assert_eq!(find(0x8000_001f, 0), CpuidRegs::ZERO);
}

fn host_qualified_v3_view() -> GuestCpuidView {
    use carrick_hal::HvVm;
    let mut vm = carrick_vmm_kvm::KvmVm::create_empty().expect("create reference KvmVm");
    let _vcpu0 = vm.add_vcpu().expect("create vCPU 0 to calibrate KVM TSC");
    vm.cpuid_view()
}

#[test]
fn kvm_cpl0_guest_sees_pinned_x86_64_v3_cpuid_and_no_non_v3_features() {
    let base_view = host_qualified_v3_view();
    let prog = cpl0_cpuid_probe_program();
    let mut carrier =
        Cpl0Carrier::boot_with_interrupts(physical_inventory(), &image(), [&prog, &prog])
            .expect("real KVM + CPL0 carrier");

    let expected_views = [base_view.with_apic_id(0), base_view.with_apic_id(1)];
    assert_eq!(expected_views[0].apic_id(), 0);
    assert_eq!(expected_views[1].apic_id(), 1);
    assert!(
        !carrier.has_tsc_deadline(0).expect("CPU 0 tsc_deadline"),
        "TSC_DEADLINE is outside x86-64-v3 and must not be advertised"
    );

    for (slot, &expected_view) in expected_views.iter().enumerate() {
        let mut observed = Vec::with_capacity(PROBED_LEAVES.len());
        for &(leaf, subleaf) in PROBED_LEAVES {
            let lo = carrier.observe(slot).expect("observe ebx:eax").result as u64;
            let hi = carrier.observe(slot).expect("observe edx:ecx").result as u64;
            let regs = CpuidRegs::new(lo as u32, (lo >> 32) as u32, hi as u32, (hi >> 32) as u32);
            observed.push(((leaf, subleaf), regs));
        }
        assert_observed_leaves_are_strictly_v3(&observed, expected_view);

        let xcr0 = carrier.observe(slot).expect("observe XGETBV(0)").result as u64;
        assert_eq!(
            xcr0,
            u64::from(XCR0_X86_64_V3_MASK),
            "CPU {slot} XGETBV(0) must report pinned XCR0=0x7"
        );

        let isa_witness = carrier.observe(slot).expect("observe v3 ISA").result as u64;
        assert_eq!(
            isa_witness,
            u64::from(EXPECTED_V3_ISA_WITNESS),
            "CPU {slot} x86-64-v3 AVX2/BMI1/BMI2/LZCNT/POPCNT witness mismatch"
        );
    }
}

fn make_two_page_x86_elf(blob: &[u8], load_va: u64) -> Vec<u8> {
    let file_offset: u64 = 0x78;
    let filesz = blob.len() as u64;
    let memsz: u64 = 0x2000;
    assert!(filesz <= 0x1000, "code blob must fit in first 4 KiB page");

    let mut buf = Vec::with_capacity(0x78 + blob.len());
    buf.extend_from_slice(b"\x7fELF");
    buf.extend_from_slice(&[2, 1, 1, 0]);
    buf.extend_from_slice(&[0u8; 8]);
    buf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&load_va.to_le_bytes());
    buf.extend_from_slice(&64u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&64u16.to_le_bytes());
    buf.extend_from_slice(&56u16.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&64u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    buf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    buf.extend_from_slice(&7u32.to_le_bytes()); // PF_R | PF_W | PF_X
    buf.extend_from_slice(&file_offset.to_le_bytes());
    buf.extend_from_slice(&load_va.to_le_bytes());
    buf.extend_from_slice(&load_va.to_le_bytes());
    buf.extend_from_slice(&filesz.to_le_bytes());
    buf.extend_from_slice(&memsz.to_le_bytes());
    buf.extend_from_slice(&0x1000u64.to_le_bytes());
    buf.extend_from_slice(blob);
    buf
}

fn run_elf_cpuid_probe_blob(buf_va: u64) -> (Vec<u8>, usize) {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0xbd]); // movabs rbp, buf_va
    code.extend_from_slice(&buf_va.to_le_bytes());

    for &(leaf, subleaf) in PROBED_LEAVES {
        code.push(0xb8);
        code.extend_from_slice(&leaf.to_le_bytes());
        code.push(0xb9);
        code.extend_from_slice(&subleaf.to_le_bytes());
        code.extend_from_slice(&[
            0x0f, 0xa2, // cpuid
            0x89, 0x45, 0x00, // mov [rbp+0], eax
            0x89, 0x5d, 0x04, // mov [rbp+4], ebx
            0x89, 0x4d, 0x08, // mov [rbp+8], ecx
            0x89, 0x55, 0x0c, // mov [rbp+12], edx
            0x48, 0x83, 0xc5, 0x10, // add rbp, 16
        ]);
    }

    // XGETBV(0) -> 8 bytes at [rbp+0..8]
    code.extend_from_slice(&[
        0x31, 0xc9, // xor ecx, ecx
        0x0f, 0x01, 0xd0, // xgetbv
        0x89, 0x45, 0x00, // mov [rbp+0], eax
        0x89, 0x55, 0x04, // mov [rbp+4], edx
        0x48, 0x83, 0xc5, 0x08, // add rbp, 8
    ]);

    // AVX2 / BMI1 / BMI2 / LZCNT / POPCNT + MOVBE -> 8 bytes at [rbp+0..8]
    emit_v3_isa_witness_into_eax(&mut code);
    code.extend_from_slice(&[
        0xc7, 0x45, 0x04, 0x78, 0x56, 0x34, 0x12, // mov dword ptr [rbp+4], 0x12345678
        0x0f, 0x38, 0xf0, 0x7d, 0x04, // movbe edi, dword ptr [rbp+4]
        0x89, 0x45, 0x00, // mov [rbp+0], eax
        0x89, 0x7d, 0x04, // mov [rbp+4], edi
        0x48, 0x83, 0xc5, 0x08, // add rbp, 8
    ]);

    let total_bytes = PROBED_LEAVES.len() * 16 + 16;

    // write(1, buf_va, total_bytes)
    code.extend_from_slice(&[0xbf, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
    code.extend_from_slice(&[0x48, 0xbe]); // movabs rsi, buf_va
    code.extend_from_slice(&buf_va.to_le_bytes());
    code.push(0xba); // mov edx, total_bytes
    code.extend_from_slice(&(total_bytes as u32).to_le_bytes());
    code.extend_from_slice(&[
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, SYS_write (1)
        0x0f, 0x05, // syscall
        0x31, 0xff, // xor edi, edi
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax, SYS_exit_group (231)
        0x0f, 0x05, // syscall
    ]);

    (code, total_bytes)
}

#[test]
fn kvm_run_elf_guest_sees_pinned_x86_64_v3_cpuid_and_executes_v3_isa() {
    let expected_view = host_qualified_v3_view().with_apic_id(0);

    let load_va: u64 = 0x40_0000;
    let buf_va: u64 = load_va + 0x1000;
    let (blob, expected_bytes) = run_elf_cpuid_probe_blob(buf_va);
    let elf = make_two_page_x86_elf(&blob, load_va);

    let tmp = tempfile::Builder::new()
        .prefix("carrick_cpuid_v3_")
        .suffix(".elf")
        .tempfile()
        .expect("create temp ELF");
    std::fs::write(tmp.path(), &elf).expect("write temp ELF");

    let bin = env!("CARGO_BIN_EXE_carrick-vmm-kvm");
    // A guest fault must fail this witness rather than leave the KVM lane
    // waiting indefinitely for the subprocess to flush its observations.
    let out = Command::new("timeout")
        .args(["--signal=KILL", "10s", bin])
        .arg("run-elf")
        .arg(tmp.path())
        .output()
        .expect("spawn carrick-vmm-kvm run-elf");

    assert!(
        out.status.success(),
        "run-elf failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout.len(), expected_bytes, "unexpected output size");

    let mut observed = Vec::with_capacity(PROBED_LEAVES.len());
    for (idx, &(leaf, subleaf)) in PROBED_LEAVES.iter().enumerate() {
        let base = idx * 16;
        let regs = CpuidRegs::new(
            u32::from_le_bytes(out.stdout[base..base + 4].try_into().unwrap()),
            u32::from_le_bytes(out.stdout[base + 4..base + 8].try_into().unwrap()),
            u32::from_le_bytes(out.stdout[base + 8..base + 12].try_into().unwrap()),
            u32::from_le_bytes(out.stdout[base + 12..base + 16].try_into().unwrap()),
        );
        observed.push(((leaf, subleaf), regs));
    }
    assert_observed_leaves_are_strictly_v3(&observed, expected_view);

    let tail = PROBED_LEAVES.len() * 16;
    let xcr0 = u64::from_le_bytes(out.stdout[tail..tail + 8].try_into().unwrap());
    assert_eq!(xcr0, u64::from(XCR0_X86_64_V3_MASK), "run-elf XGETBV(0)");

    let isa_witness = u32::from_le_bytes(out.stdout[tail + 8..tail + 12].try_into().unwrap());
    let movbe_witness = u32::from_le_bytes(out.stdout[tail + 12..tail + 16].try_into().unwrap());
    assert_eq!(
        isa_witness, EXPECTED_V3_ISA_WITNESS,
        "run-elf v3 ISA witness"
    );
    assert_eq!(
        movbe_witness, EXPECTED_MOVBE_WITNESS,
        "run-elf MOVBE witness"
    );
}
