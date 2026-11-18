//! M1 boot probe (#671): boot the production CPL0 ring image, and its
//! fixture sibling, on the VM-free `SoftMachine` through the neutral boot
//! KVM also uses (`prepare_boot`, `install_boot_memory`, `BootCpuState`,
//! `BootstrapCustody`, `load_guest_mm`) and report how far each gets.
//! Hosted-CI shaped: no /dev/kvm and no host privileges.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_vmm_soft::{BootExit, BootReport, ProbeImage, SoftCarrier, boot_probe};

mod common;
use common::{bind_issued_root, inventory, static_elf};

const PRODUCTION: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_IMAGE"));
const FIXTURE: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE"));
/// The initial guest-MM extent the KVM production boot witnesses use.
const INITIAL_EXTENT: usize = 0x20_000;
const MAX_BLOCKS: u64 = 1_000_000;

/// `mov edi, 7; mov eax, 231 (exit_group); syscall; ud2`.
const EXIT_SEVEN: &[u8] = &[
    0xbf, 7, 0, 0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
];

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
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let ipc = carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher);
    let root = dispatcher.capture_one_task_context().expect("issued root");
    let bind = |carrier: &mut SoftCarrier| bind_issued_root(carrier, &root);
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
                ipc: None,
                bind: None,
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
                ipc,
                bind: Some(&bind),
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
                ipc: None,
                bind: None,
            }),
        ),
    ];
    let failed: Vec<_> = reports
        .iter()
        .filter(|(fatal, report)| {
            !reached_host_exit(report, *fatal)
                || (report.image.contains("admitted") && !report.admitted)
        })
        .map(|(_, report)| format!("[{}] {}", report.image, report.summary))
        .collect();
    assert!(failed.is_empty(), "soft boot probe:\n{}", failed.join("\n"));
}
