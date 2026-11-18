//! M1 (#671): the production CPL0 ring image runs a static hello on the
//! VM-free `SoftMachine` to its exit. The stopped carrier is booted, bound
//! and admitted through the shared neutral boot, then handed to the shared
//! production worker custody (`ProductionWorkerParts`,
//! `ProductionCpuFactory`, `CarrierCpu` over the soft `CarrierCpuBackend`);
//! the root lease's doorbells and forwards are served by the same shared
//! lease services the KVM stopped-worker witnesses drive. Hosted-CI shaped:
//! no /dev/kvm and no host privileges.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_guest_mem::GuestMemory as _;
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_kernel::dispatch::DispatchOutcome;
use carrick_vmm_soft::{SoftBootImage, SoftCarrier};
use carrick_x86_cpl0_host::carrier_cpu::CarrierRunExit;
use carrick_x86_cpl0_host::cpl0_boot::{
    InitialReservationLimits, PhysicalProcessExit, initial_extent_bytes_for, load_guest_mm,
};

mod common;
use common::{bind_issued_root, inventory, static_elf};

const PRODUCTION: &[u8] = include_bytes!(env!("CARRICK_X86_CPL0_IMAGE"));
/// Soft blocks one run may retire before it is a hang.
const MAX_BLOCKS: u64 = 4_000_000;
/// Carrier exits the root lease may take before the run is a hang.
const MAX_EXITS: usize = 256;

/// `write(1, "hello\n", 6); exit_group(0); ud2`, as the KVM M0/M1 hello.
const HELLO: &[u8] = &[
    0xbf, 1, 0, 0, 0, // mov edi, 1
    0x48, 0x8d, 0x35, 0x17, 0, 0, 0, // lea rsi, [rip + message]
    0xba, 6, 0, 0, 0, // mov edx, 6
    0xb8, 1, 0, 0, 0, // mov eax, 1 (write)
    0x0f, 0x05, // syscall
    0x31, 0xff, // xor edi, edi
    0xb8, 0xe7, 0, 0, 0, // mov eax, 231 (exit_group)
    0x0f, 0x05, // syscall
    0x0f, 0x0b, // ud2
    b'h', b'e', b'l', b'l', b'o', b'\n',
];

/// What the soft root lease did, and how far it got.
#[derive(Debug)]
struct HelloRun {
    stdout: Vec<u8>,
    exit: Option<i32>,
    exits: Vec<String>,
    failure: Option<String>,
}

impl HelloRun {
    fn summary(&self) -> String {
        let path = self.exits.join(" -> ");
        match (&self.failure, self.exit) {
            (Some(failure), _) => format!(
                "boots to [{path}] / fails at {failure} (stdout {:?})",
                String::from_utf8_lossy(&self.stdout)
            ),
            (None, Some(code)) => format!(
                "boots to exit {code} with stdout {:?} via [{path}]",
                String::from_utf8_lossy(&self.stdout)
            ),
            (None, None) => format!("boots to [{path}] / fails at exit budget"),
        }
    }
}

fn run_hello(elf: &[u8]) -> HelloRun {
    let mut run = HelloRun {
        stdout: Vec::new(),
        exit: None,
        exits: Vec::new(),
        failure: None,
    };
    if let Err(failure) = drive(elf, &mut run) {
        run.failure = Some(failure);
    }
    run
}

fn drive(elf: &[u8], run: &mut HelloRun) -> Result<(), String> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None)
        .map_err(|error| format!("setup: user ELF {error:?}"))?;
    let image = carrick_mem::x86_initial_image::prepare_x86_elf(&program)
        .map_err(|error| format!("setup: user ELF image {error:?}"))?;
    let extent = initial_extent_bytes_for(&image, &[], &[]).map_err(|error| error.to_string())?;
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    let reporter = carrick_kernel::compat::CompatReporter::default();
    let ipc = carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher);
    let mut carrier = SoftCarrier::boot(
        inventory(),
        SoftBootImage {
            elf: PRODUCTION,
            programs: [&[], &[]],
            initial_extent_bytes: Some(extent),
            fixture_image: false,
            ipc,
        },
        MAX_BLOCKS,
    )
    .map_err(|error| format!("setup: {error}"))?;
    let root = dispatcher
        .capture_one_task_context()
        .map_err(|error| format!("setup: issued root {error:?}"))?;
    bind_issued_root(&mut carrier, &root).map_err(|error| format!("setup: {error}"))?;
    load_guest_mm(
        &mut carrier,
        &image,
        &[],
        &[],
        InitialReservationLimits::UNLIMITED,
    )
    .map_err(|error| format!("initial-MM admission: {error}"))?;
    run.exits.push("initial-MM admission".to_owned());
    let parts = carrier
        .into_worker_parts()
        .map_err(|error| format!("worker hand-off: {error}"))?;
    let (root_state, factory) = parts.into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let mut lease = factory
        .claim(0)
        .map_err(|error| format!("root CPU claim: {error}"))?;
    let task = root_state.binding().task();
    lease
        .cpu_mut()
        .load(root_state)
        .map_err(|error| format!("root load: {error}"))?;
    run.exits.push("root loaded".to_owned());
    for _ in 0..MAX_EXITS {
        let stopped = lease
            .fixture_run_loaded(task)
            .map_err(|error| format!("run: {error}"))?;
        match stopped.exit {
            CarrierRunExit::SyscallTrap => {
                let (value, token) = lease
                    .capture_forward(task, |venue, frame| {
                        if frame.rax == carrick_el1_abi::HostObjectWriteCrossing::NUMBER
                            && frame.rcx == carrick_el1_abi::HostObjectWriteCrossing::FRAME_TAG
                        {
                            let object =
                                carrick_el1_abi::HostObjectBinding::from_encoded(frame.rdi as u32)
                                    .and_then(carrick_el1_abi::HostObjectBinding::stdio_fd)
                                    .filter(|fd| *fd == 1 || *fd == 2)
                                    .ok_or_else(|| {
                                        carrick_x86_cpl0_host::cpl0_boot::fail(format!(
                                            "unserved host object write {:#x}",
                                            frame.rdi
                                        ))
                                    })?;
                            let bytes = venue
                                .read_bytes_prefix(frame.rsi, frame.rdx as usize)
                                .map_err(|error| {
                                    carrick_x86_cpl0_host::cpl0_boot::fail(error.to_string())
                                })?;
                            return Ok(Ok(dispatcher.forward_stdio_bytes(object, &bytes)));
                        }
                        // A plain forwarded call takes the runtime executor's
                        // host route: normalize, then dispatch under the root.
                        let syscall = carrick_guest_mem::X8664SyscallFrame {
                            rax: frame.rax,
                            rdi: frame.rdi,
                            rsi: frame.rsi,
                            rdx: frame.rdx,
                            r10: frame.r10,
                            r8: frame.r8,
                            r9: frame.r9,
                        };
                        let SyscallNorm::Plain(raw) = X8664GuestArch::normalize_syscall(&syscall)
                        else {
                            return Ok(Err(format!("unserved arch_prctl forward {frame:?}")));
                        };
                        let request = carrick_kernel::dispatch::SyscallRequest::from_raw(raw)
                            .with_current_guest_sp(Some(frame.rsp));
                        let outcome = dispatcher
                            .dispatch(&root, request, venue, &reporter)
                            .map_err(|error| {
                                carrick_x86_cpl0_host::cpl0_boot::fail(error.to_string())
                            })?;
                        Ok(match outcome {
                            DispatchOutcome::Returned { value } => Ok(value),
                            DispatchOutcome::Errno { errno } => Ok(errno.guest_retval()),
                            other => Err(format!(
                                "unserved forward outcome {other:?} for native {}",
                                raw.native_number.0
                            )),
                        })
                    })
                    .map_err(|error| format!("forward capture: {error}"))?;
                let value = value?;
                lease
                    .complete_forward(task, token, value)
                    .map_err(|error| format!("forward completion: {error}"))?;
                run.exits.push(format!("forward={value}"));
            }
            CarrierRunExit::PhysicalDoorbell { port, .. } => {
                let kernel = root.kernel();
                let status = lease
                    .service_physical_doorbell(task, &stopped.exit, |served, doorbell| {
                        carrick_kernel::el1_delegation::settle_host_work_boundary(
                            kernel, served, doorbell,
                        );
                    })
                    .map_err(|error| format!("doorbell {port:#x}: {error}"))?;
                run.exits.push(format!("doorbell {port:#x}"));
                match status {
                    None => {}
                    Some(PhysicalProcessExit::Exited(status)) => {
                        if status.kind() != carrick_sched_core::process::TerminationKind::Exited {
                            return Err(format!("terminated by signal {}", status.code()));
                        }
                        run.exit = Some(status.code() as i32);
                        run.stdout = dispatcher.stdout();
                        return Ok(());
                    }
                    Some(PhysicalProcessExit::RunFailed(reason)) => {
                        return Err(format!("run failed {}", reason.as_str()));
                    }
                }
            }
            CarrierRunExit::Kick => run.exits.push("kick".to_owned()),
            CarrierRunExit::FaultDoorbellWord(first) => {
                let record = lease
                    .capture_fault_record(task, first)
                    .map_err(|error| format!("fault record: {error}"))?;
                return Err(format!("guest fault {record:?}"));
            }
            other => return Err(format!("unexpected carrier exit {other:?}")),
        }
        run.stdout = dispatcher.stdout();
    }
    Ok(())
}

#[test]
fn production_ring_runs_static_hello_to_exit_on_soft_cpu() {
    let run = run_hello(&static_elf(HELLO));
    println!("[production, static hello] {}", run.summary());
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(run.stdout, b"hello\n", "{}", run.summary());
    assert_eq!(run.exit, Some(0), "{}", run.summary());
}
