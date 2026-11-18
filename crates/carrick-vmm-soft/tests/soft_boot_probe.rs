//! M1 boot probe (#671): boot the production CPL0 ring image, and its
//! fixture sibling, on the VM-free `SoftMachine` through the neutral boot
//! KVM also uses (`prepare_boot`, `install_boot_memory`, `BootCpuState`,
//! `BootstrapCustody`, `load_guest_mm`) and report how far each gets.
//! Hosted-CI shaped: no /dev/kvm and no host privileges.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use carrick_vmm_soft::{BootExit, BootReport, ProbeImage, boot_probe};

const PRODUCTION: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_IMAGE"));
const FIXTURE: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"));
/// The initial guest-MM extent the KVM production boot witnesses use.
const INITIAL_EXTENT: usize = 0x20_000;
const MAX_BLOCKS: u64 = 1_000_000;

/// `mov edi, 7; mov eax, 231 (exit_group); syscall; ud2`.
const EXIT_SEVEN: &[u8] = &[
    0xbf, 7, 0, 0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
];

/// A static x86-64 `ET_EXEC` whose one `R+X` `PT_LOAD` maps its own
/// headers and `code` at `0x40_0000`, entering at `code`.
fn static_elf(code: &[u8]) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    const HEADERS: u64 = 64 + 56;
    let size = HEADERS + code.len() as u64;
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7fELF");
    elf.extend_from_slice(&[2, 1, 1, 0]); // ELFCLASS64, little-endian, v1, SysV
    elf.extend_from_slice(&[0; 8]);
    elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&(BASE + HEADERS).to_le_bytes()); // e_entry
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    elf.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&[0; 6]); // e_shentsize, e_shnum, e_shstrndx
    elf.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf.extend_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_vaddr
    elf.extend_from_slice(&BASE.to_le_bytes()); // p_paddr
    elf.extend_from_slice(&size.to_le_bytes()); // p_filesz
    elf.extend_from_slice(&size.to_le_bytes()); // p_memsz
    elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    elf.extend_from_slice(code);
    elf
}

fn inventory() -> Arc<dyn carrick_hal::PhysicalFrameInventory> {
    Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new())
        .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()))
}

fn probe(image: ProbeImage<'_>) -> BootReport {
    let report = boot_probe(inventory(), image, MAX_BLOCKS);
    println!("{report}");
    report
}

/// The carrier protocol's first serviced exit: port I/O or `HLT`, or a
/// complete fault-doorbell record for a CPL3 fault. A ring-0 fault record
/// is a carrier failure on KVM too (`fault_exit_from_record`). A ring fatal
/// is admitted only where the stopped carrier lacks what the ring requires.
fn reached_host_exit(report: &BootReport, ring_fatal_admitted: bool) -> bool {
    match &report.outcome {
        BootExit::HostExit(_) => report.fatal_payload.is_none() || ring_fatal_admitted,
        BootExit::FaultDoorbell(record) => record.cs & 3 == 3,
        _ => false,
    }
}

#[test]
fn production_ring_image_boots_to_first_carrier_exit_on_soft_cpu() {
    let exit_seven = static_elf(EXIT_SEVEN);
    let reports = [
        (
            false,
            probe(ProbeImage {
                name: "production, stopped boot",
                elf: PRODUCTION,
                programs: [&[], &[]],
                initial_extent_bytes: Some(INITIAL_EXTENT),
                fixture_image: false,
                user_elf: None,
            }),
        ),
        // The initial MM is admitted through the shared `load_guest_mm`, as
        // the KVM witnesses admit one through `run_pool_fixture`.
        (
            false,
            probe(ProbeImage {
                name: "production, admitted exit_group(7) ELF",
                elf: PRODUCTION,
                programs: [&[], &[]],
                initial_extent_bytes: None,
                fixture_image: false,
                user_elf: Some(&exit_seven),
            }),
        ),
        (
            false,
            probe(ProbeImage {
                name: "fixture, exit_group(7) syscall",
                elf: FIXTURE,
                programs: [EXIT_SEVEN, EXIT_SEVEN],
                initial_extent_bytes: None,
                fixture_image: true,
                user_elf: None,
            }),
        ),
    ];
    let failed: Vec<_> = reports
        .iter()
        .filter(|(fatal, report)| !reached_host_exit(report, *fatal))
        .map(|(_, report)| format!("[{}] {}", report.image, report.summary))
        .collect();
    assert!(failed.is_empty(), "soft boot probe:\n{}", failed.join("\n"));
}
