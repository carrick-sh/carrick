//! M1 boot probe (#671): boot the production CPL0 ring image, and its
//! fixture sibling, on the VM-free `SoftMachine` through the neutral boot
//! KVM also uses (`prepare_boot`, `install_boot_memory`, `BootCpuState`,
//! `BootstrapCustody`, `load_guest_mm`) and report how far each gets.
//! Hosted-CI shaped: no /dev/kvm and no host privileges.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_softcpu_x86::SoftMachineExit;
use carrick_vmm_soft::{BootExit, BootReport, ProbeImage, SoftCarrier, boot_probe};
use carrick_x86::cpl0_entry::{FORWARD_PORT, WORK_PORT};
use carrick_x86_cpl0_host::cpl0_boot::USER_CODE;

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

/// The exit one probe row must reach. Each row names its own: a CPL3
/// fault record standing in for a port exit (or the reverse) is a failure.
#[derive(Clone, Copy, Debug)]
enum Expected {
    /// The stopped production ring enters CPL3 at `USER_CODE` with no
    /// program mapped: the ring's IDT stub reports that instruction-fetch
    /// `#PF` to the carrier.
    UserFetchFault,
    /// A carrier host exit `OUT` on this port, with no ring fatal.
    Out(u16),
}

/// `Ok` when `report` reached exactly `expected`.
fn check(report: &BootReport, expected: Expected) -> Result<(), String> {
    let reached = match (expected, &report.outcome) {
        (Expected::UserFetchFault, BootExit::FaultDoorbell(record)) => {
            record.vector == 14
                && record.cs & 3 == 3
                // #PF error code: user-mode instruction fetch, not present.
                && record.error_code == 0x14
                && record.rip == USER_CODE
                && record.cr2 == USER_CODE
        }
        (Expected::Out(port), BootExit::HostExit(SoftMachineExit::IoOut { port: out, .. })) => {
            *out == port && report.fatal_payload.is_none()
        }
        _ => false,
    };
    if reached {
        Ok(())
    } else {
        Err(format!(
            "[{}] expected {expected:?}: {}",
            report.image, report.summary
        ))
    }
}

/// Row 2's shape: the production ring admits `elf` as the initial MM of
/// the kernel's issued root.
fn admitted_row(name: &'static str, elf: &[u8]) -> BootReport {
    let dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let ipc = carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher);
    let root = dispatcher.capture_one_task_context().expect("issued root");
    let bind = |carrier: &mut SoftCarrier| bind_issued_root(carrier, &root);
    let report = probe(ProbeImage {
        name,
        elf: PRODUCTION,
        programs: [&[], &[]],
        initial_extent_bytes: None,
        fixture_image: false,
        user_elf: Some(elf),
        ipc,
        bind: Some(&bind),
    });
    assert!(report.admitted, "[{name}] initial MM not admitted");
    report
}

#[test]
fn production_ring_image_boots_to_first_carrier_exit_on_soft_cpu() {
    let reports = [
        (
            Expected::UserFetchFault,
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
        // the KVM witnesses admit one through `run_pool_fixture`; its
        // `exit_group` reaches the carrier as root work.
        (
            Expected::Out(WORK_PORT),
            admitted_row(
                "production, admitted exit_group(7) ELF",
                &static_elf(EXIT_SEVEN),
            ),
        ),
        // The fixture ring forwards its CPL3 `exit_group` to the host.
        (
            Expected::Out(FORWARD_PORT),
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
        .filter_map(|(expected, report)| check(report, *expected).err())
        .collect();
    assert!(failed.is_empty(), "soft boot probe:\n{}", failed.join("\n"));
}

/// Mutation witness for the per-row expectation: an admitted root that
/// faults at CPL3 (`ud2`) reaches a complete CPL3 fault-doorbell record,
/// which the old shared predicate accepted for every row. Row 2 expects
/// `WORK_PORT` and must refuse it.
#[test]
fn a_user_fault_does_not_pass_for_the_admitted_root_work_exit() {
    let report = admitted_row("production, admitted ud2 ELF", &static_elf(&[0x0f, 0x0b]));
    assert!(
        matches!(&report.outcome, BootExit::FaultDoorbell(record) if record.cs & 3 == 3),
        "the mutation must reach a CPL3 fault record: {}",
        report.summary
    );
    assert!(check(&report, Expected::Out(WORK_PORT)).is_err());
}
