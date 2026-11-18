//! M1-0 boot probe (#671): boot the production CPL0 ring image, and its
//! fixture sibling, on the VM-free `SoftMachine` through only neutral code
//! (`prepare_boot`, `BootCpuState`) and report how far each gets.
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

fn inventory() -> Arc<dyn carrick_hal::PhysicalFrameInventory> {
    Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new())
        .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new()))
}

fn probe(image: ProbeImage<'_>) -> BootReport {
    let report = boot_probe(&*inventory(), image, MAX_BLOCKS);
    println!("{report}");
    report
}

/// The carrier protocol's first serviced exit: port I/O or `HLT`, or a
/// complete fault-doorbell record for a CPL3 fault. A ring-0 fault record
/// is a carrier failure on KVM too (`fault_exit_from_record`).
fn reached_host_exit(report: &BootReport) -> bool {
    match &report.exit {
        BootExit::HostExit(_) => true,
        BootExit::FaultDoorbell(record) => record.cs & 3 == 3,
        _ => false,
    }
}

#[test]
fn production_ring_image_boots_to_first_carrier_exit_on_soft_cpu() {
    let reports = [
        probe(ProbeImage {
            name: "production, stopped boot",
            elf: PRODUCTION,
            programs: [&[], &[]],
            initial_extent_bytes: Some(INITIAL_EXTENT),
            fixture_image: false,
        }),
        probe(ProbeImage {
            name: "production, exit_group(7) syscall",
            elf: PRODUCTION,
            programs: [EXIT_SEVEN, &[]],
            initial_extent_bytes: Some(INITIAL_EXTENT),
            fixture_image: false,
        }),
        probe(ProbeImage {
            name: "fixture, exit_group(7) syscall",
            elf: FIXTURE,
            programs: [EXIT_SEVEN, EXIT_SEVEN],
            initial_extent_bytes: None,
            fixture_image: true,
        }),
    ];
    let failed: Vec<_> = reports
        .iter()
        .filter(|report| !reached_host_exit(report))
        .map(|report| format!("[{}] {}", report.image, report.summary))
        .collect();
    assert!(failed.is_empty(), "soft boot probe:\n{}", failed.join("\n"));
}
