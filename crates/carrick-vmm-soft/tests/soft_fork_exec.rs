//! M1 (#671): a glibc parent forks and reaps an exec'd static successor
//! through the x86 production CPL0 image and the soft carrier.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

mod common;
#[path = "../../carrick-cli/tests/fixtures/x86_process_entry.rs"]
mod x86_process_entry;

use carrick_guest_mem::GuestMemory as _;
use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_kernel::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use carrick_mem::elf::ElfProgram;
use carrick_vmm_soft::{SoftBootImage, SoftCarrier, publish_worker_backings};
use carrick_x86_cpl0_host::carrier_cpu::CarrierRunExit;
use carrick_x86_cpl0_host::cpl0_boot::{
    InitialReservationLimits, PhysicalProcessExit, exec_service::X86ExecImage, fail,
    initial_extent_bytes_for, load_guest_mm,
};

const MAX_BLOCKS: u64 = 4_000_000;
const MAX_EXITS: usize = 256;
const SUCCESSOR_PATH: &[u8] = b"/fork-exec-child";

fn compile_fixture(name: &str, flags: &[&str]) -> Vec<u8> {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output =
        std::path::Path::new(env!("OUT_DIR")).join(format!("soft-{name}-{}", std::process::id()));
    x86_process_entry::compile_static_fixture(&source, &output, flags);
    let elf = std::fs::read(&output).expect("read fixture ELF");
    std::fs::remove_file(output).expect("remove compiled fixture");
    elf
}

#[test]
fn production_ring_runs_glibc_fork_exec_wait_on_soft_cpu() {
    let parent = compile_fixture("x86_glibc_fork_exec.c", &[]);
    let successor = compile_fixture("x86_fork_exec_child.S", &["-nostdlib"]);
    let mut boundaries = Vec::new();
    let outcome = run_fork_exec(&parent, &successor, &mut boundaries);
    let (status, stdout) = outcome.unwrap_or_else(|error| panic!("{error}; {boundaries:?}"));
    assert_eq!(status, 0, "stdout {stdout:?}; {boundaries:?}");
    assert_eq!(stdout, b"child ran after exec\nparent reaped exit 7\n");
}

fn run_fork_exec(
    parent: &[u8],
    successor: &[u8],
    boundaries: &mut Vec<String>,
) -> Result<(i32, Vec<u8>), String> {
    let mut dispatcher = SyscallDispatcher::default();
    let reporter = carrick_kernel::compat::CompatReporter::default();
    let root = dispatcher
        .capture_one_task_context()
        .map_err(|error| format!("issued root {error:?}"))?;
    let parent =
        ElfProgram::load(parent, 62, &|_| None).map_err(|error| format!("parent ELF {error:?}"))?;
    let image = carrick_mem::x86_initial_image::prepare_x86_elf(&parent)
        .map_err(|error| format!("parent image {error:?}"))?;
    let successor = ElfProgram::load(successor, 62, &|_| None)
        .map_err(|error| format!("successor ELF {error:?}"))?;
    let extent = initial_extent_bytes_for(&image, &[], &[]).map_err(|error| error.to_string())?;
    let mut carrier = SoftCarrier::boot(
        common::inventory(),
        SoftBootImage {
            elf: include_bytes!(env!("CARRICK_X86_CPL0_IMAGE")),
            programs: [&[], &[]],
            initial_extent_bytes: Some(extent),
            fixture_image: false,
            ipc: carrick_kernel::kernel::continuation::ipc::host_window_backing(&dispatcher),
        },
        MAX_BLOCKS,
    )
    .map_err(|error| error.to_string())?;
    common::bind_issued_root(&mut carrier, &root)?;
    load_guest_mm(
        &mut carrier,
        &image,
        &[],
        &[],
        InitialReservationLimits::UNLIMITED,
    )
    .map_err(|error| error.to_string())?;
    let (state, factory) = carrier
        .into_worker_parts()
        .map_err(|error| error.to_string())?
        .into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let task = state.binding().task();
    let mut lease = factory.claim(0).map_err(|error| error.to_string())?;
    lease
        .cpu_mut()
        .load(state)
        .map_err(|error| error.to_string())?;

    for _ in 0..MAX_EXITS {
        let stopped = lease
            .fixture_run_loaded(task)
            .map_err(|error| error.to_string())?;
        match stopped.exit {
            CarrierRunExit::SyscallTrap => {
                let ((number, value), token) = lease
                    .capture_forward(task, |venue, frame| {
                        if frame.rax == carrick_el1_abi::HostObjectWriteCrossing::NUMBER
                            && frame.rcx == carrick_el1_abi::HostObjectWriteCrossing::FRAME_TAG
                        {
                            let object =
                                carrick_el1_abi::HostObjectBinding::from_encoded(frame.rdi as u32)
                                    .and_then(carrick_el1_abi::HostObjectBinding::stdio_fd)
                                    .filter(|fd| *fd == 1 || *fd == 2)
                                    .ok_or_else(|| fail("expected a stdio write binding"))?;
                            let bytes = venue
                                .read_bytes_prefix(frame.rsi, frame.rdx as usize)
                                .map_err(|error| fail(error.to_string()))?;
                            return Ok((frame.rax, dispatcher.forward_stdio_bytes(object, &bytes)));
                        }
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
                            return Err(fail(format!("unexpected forward {frame:?}")));
                        };
                        let request =
                            SyscallRequest::from_raw(raw).with_current_guest_sp(Some(frame.rsp));
                        let outcome = dispatcher
                            .dispatch(&root, request, venue, &reporter)
                            .map_err(|error| fail(error.to_string()))?;
                        match outcome {
                            DispatchOutcome::Returned { value } => Ok((frame.rax, value)),
                            DispatchOutcome::Errno { errno } => {
                                Ok((frame.rax, errno.guest_retval()))
                            }
                            other => Err(fail(format!("forward {:#x}: {other:?}", frame.rax))),
                        }
                    })
                    .map_err(|error| error.to_string())?;
                boundaries.push(format!("forward {number:#x}={value}"));
                lease
                    .complete_forward(task, token, value)
                    .map_err(|error| error.to_string())?;
            }
            CarrierRunExit::PhysicalDoorbell { port, .. } => {
                boundaries.push(format!("port {port:#x}"));
                let status = lease
                    .service_physical_doorbell_with_host_file(
                        task,
                        &stopped.exit,
                        |served, doorbell| {
                            carrick_kernel::el1_delegation::settle_host_work_boundary(
                                root.kernel(),
                                served,
                                doorbell,
                            );
                        },
                        &mut |_, requester, record| {
                            dispatcher
                                .serve_native_host_file_for(record, None, requester)
                                .map(|reply| reply.into_reply())
                                .map_err(|_| carrick_hal::fork_stock::NativeHostFileRefused)
                        },
                        // The only file in this fixture's exec service is the
                        // compiled successor. KVM exercises filesystem lookup.
                        &mut |_| {
                            X86ExecImage::from_program(
                                &successor,
                                vec![SUCCESSOR_PATH.to_vec()],
                                vec![],
                            )
                        },
                    )
                    .map_err(|error| error.to_string())?;
                match status {
                    None => publish_worker_backings(&factory).map_err(|error| error.to_string())?,
                    Some(PhysicalProcessExit::Exited(status)) => {
                        if status.kind() != carrick_sched_core::process::TerminationKind::Exited {
                            return Err(format!("terminated by signal {}", status.code()));
                        }
                        return Ok((status.code() as i32, dispatcher.stdout()));
                    }
                    Some(PhysicalProcessExit::RunFailed(reason)) => {
                        return Err(format!("run failed {}", reason.as_str()));
                    }
                }
            }
            CarrierRunExit::Kick => boundaries.push("kick".to_owned()),
            CarrierRunExit::FaultDoorbellWord(first) => {
                let record = lease
                    .capture_fault_record(task, first)
                    .map_err(|error| error.to_string())?;
                return Err(format!("guest fault {record:?}"));
            }
            other => return Err(format!("unexpected carrier exit {other:?}")),
        }
    }
    Err("carrier exit budget exhausted".to_owned())
}
