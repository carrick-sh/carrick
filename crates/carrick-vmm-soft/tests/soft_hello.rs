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
use carrick_kernel::dispatch::{DispatchOutcome, StdioReadiness, SyscallDispatcher};
use carrick_kernel::kernel::KernelContext;
use carrick_vmm_soft::{SoftBootImage, SoftCarrier, publish_worker_backings};
use carrick_x86_cpl0_host::carrier_cpu::CarrierRunExit;
use carrick_x86_cpl0_host::cpl0_boot::{
    InitialReservationLimits, PhysicalProcessExit, initial_extent_bytes_for, load_guest_mm,
};

use carrick_x86_cpl0_host::host_readiness::{
    BoundHostFds, HostReadinessStep, ReadinessCrossing, ReadinessWait, StdioBinding,
    sample_host_readiness,
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

/// mmap one anonymous page, write through its first fault, and print the
/// bytes from that page. Exit 1 if mmap fails.
const ANONYMOUS_HELLO: &[u8] = &[
    0x31, 0xff, // xor edi, edi
    0xbe, 0, 0x10, 0, 0, // mov esi, 4096
    0xba, 3, 0, 0, 0, // mov edx, PROT_READ | PROT_WRITE
    0x41, 0xba, 0x22, 0, 0, 0, // mov r10d, MAP_PRIVATE | MAP_ANONYMOUS
    0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, // mov r8d, -1
    0x45, 0x31, 0xc9, // xor r9d, r9d
    0xb8, 9, 0, 0, 0, // mov eax, 9 (mmap)
    0x0f, 0x05, // syscall
    0x48, 0x85, 0xc0, // test rax, rax
    0xbf, 1, 0, 0, 0, // mov edi, 1
    0x78, 0x1d, // js exit_group
    0x48, 0x89, 0xc6, // mov rsi, rax
    0xc7, 0x06, b'h', b'e', b'l', b'l', // mov dword ptr [rsi], "hell"
    0x66, 0xc7, 0x46, 4, b'o', b'\n', // mov word ptr [rsi+4], "o\n"
    0xba, 6, 0, 0, 0, // mov edx, 6
    0xb8, 1, 0, 0, 0, // mov eax, 1 (write)
    0x0f, 0x05, // syscall
    0x31, 0xff, // xor edi, edi
    0xb8, 0xe7, 0, 0, 0, // mov eax, 231 (exit_group)
    0x0f, 0x05, // syscall
    0x0f, 0x0b, // ud2
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
    run_with_stdout_patch(elf, None)
}

fn run_with_stdout_patch(elf: &[u8], patch: Option<u8>) -> HelloRun {
    let mut run = HelloRun {
        stdout: Vec::new(),
        exit: None,
        exits: Vec::new(),
        failure: None,
    };
    if let Err(failure) = drive(elf, &mut run, patch) {
        run.failure = Some(failure);
    }
    run
}

fn boot_initial_mm(
    elf: &[u8],
    dispatcher: &SyscallDispatcher,
    root: &KernelContext,
) -> Result<SoftCarrier, String> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None)
        .map_err(|error| format!("setup: user ELF {error:?}"))?;
    let image = carrick_mem::x86_initial_image::prepare_x86_elf(&program)
        .map_err(|error| format!("setup: user ELF image {error:?}"))?;
    let extent = initial_extent_bytes_for(&image, &[], &[]).map_err(|error| error.to_string())?;
    let ipc = carrick_kernel::kernel::continuation::ipc::host_window_backing(dispatcher);
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
    bind_issued_root(&mut carrier, root).map_err(|error| format!("setup: {error}"))?;
    load_guest_mm(
        &mut carrier,
        &image,
        &[],
        &[],
        InitialReservationLimits::UNLIMITED,
    )
    .map_err(|error| format!("initial-MM admission: {error}"))?;
    Ok(carrier)
}

fn drive(elf: &[u8], run: &mut HelloRun, patch: Option<u8>) -> Result<(), String> {
    let mut dispatcher = SyscallDispatcher::default();
    let reporter = carrick_kernel::compat::CompatReporter::default();
    let root = dispatcher
        .capture_one_task_context()
        .map_err(|error| format!("setup: issued root {error:?}"))?;
    let carrier = boot_initial_mm(elf, &dispatcher, &root)?;
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
    // The run's stdio readiness authority, as the runtime executor binds it.
    let host_fds = BoundHostFds::from_stdio([0, 1, 2].map(|fd| {
        dispatcher
            .stdio_readiness(fd)
            .map(|readiness| match readiness {
                StdioReadiness::AlwaysWritable => StdioBinding::AlwaysWritable,
                StdioReadiness::Host(fd) => StdioBinding::Host(fd),
            })
    }))
    .map_err(|error| format!("setup: stdio readiness {error}"))?;
    for _ in 0..MAX_EXITS {
        let stopped = lease
            .fixture_run_loaded(task)
            .map_err(|error| format!("run: {error}"))?;
        match stopped.exit {
            CarrierRunExit::SyscallTrap => {
                let (value, token) = lease
                    .capture_forward(task, |venue, frame| {
                        // Host-bound poll readiness (std's startup probe of
                        // fds 0-2) through the shared carrier service.
                        let now = std::time::Instant::now();
                        match ReadinessCrossing::decode(frame, || now)? {
                            ReadinessCrossing::Other => {}
                            ReadinessCrossing::Refused(errno) => {
                                return Ok(Ok((frame.rax, errno.guest_retval())));
                            }
                            ReadinessCrossing::Request(request) => {
                                return Ok(
                                    match sample_host_readiness(venue, &request, &host_fds)? {
                                        HostReadinessStep::Ready(value) => Ok((frame.rax, value)),
                                        HostReadinessStep::Wait(_) => match request.wait(now) {
                                            ReadinessWait::Expired => Ok((frame.rax, 0)),
                                            ReadinessWait::Until(timeout) => Err(format!(
                                                "unserved host readiness wait {timeout:?}: \
                                                 parking needs an execution lease"
                                            )),
                                        },
                                    },
                                );
                            }
                        }
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
                            if let Some(patch) = patch {
                                venue
                                    .write_bytes_raw(frame.rsi, &[patch])
                                    .map_err(|error| {
                                        carrick_x86_cpl0_host::cpl0_boot::fail(error.to_string())
                                    })?;
                            }
                            return Ok(Ok((
                                frame.rax,
                                dispatcher.forward_stdio_bytes(object, &bytes),
                            )));
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
                        // Some root stdio writes are forwarded as the plain
                        // Linux syscall. Patch only after dispatch copied the
                        // original byte to stdout.
                        if let (Some(patch), DispatchOutcome::Returned { value: 1 }) =
                            (patch, &outcome)
                            && frame.rax == 1
                            && frame.rdi == 1
                            && frame.rdx == 1
                        {
                            venue
                                .write_bytes_raw(frame.rsi, &[patch])
                                .map_err(|error| {
                                    carrick_x86_cpl0_host::cpl0_boot::fail(error.to_string())
                                })?;
                        }
                        Ok(match outcome {
                            DispatchOutcome::Returned { value } => Ok((frame.rax, value)),
                            DispatchOutcome::Errno { errno } => {
                                Ok((frame.rax, errno.guest_retval()))
                            }
                            other => Err(format!(
                                "unserved forward outcome {other:?} for native {}",
                                raw.native_number.0
                            )),
                        })
                    })
                    .map_err(|error| format!("forward capture: {error}"))?;
                let (number, value) = value?;
                lease
                    .complete_forward(task, token, value)
                    .map_err(|error| format!("forward completion: {error}"))?;
                run.exits.push(format!("forward {number:#x}={value}"));
            }
            CarrierRunExit::PhysicalDoorbell { port, .. } => {
                let kernel = root.kernel();
                let status = lease
                    .service_physical_doorbell_with_host_file(
                        task,
                        &stopped.exit,
                        |served, doorbell| {
                            carrick_kernel::el1_delegation::settle_host_work_boundary(
                                kernel, served, doorbell,
                            );
                        },
                        // The fork fixture's native host-file record is the
                        // child's stdout write. Use the dispatcher that owns
                        // the requesting ring task's retained file resources.
                        &mut |_, requester, record| {
                            dispatcher
                                .serve_native_host_file_for(record, None, requester)
                                .map(|reply| reply.into_reply())
                                .map_err(|_| carrick_hal::fork_stock::NativeHostFileRefused)
                        },
                        &mut |_| Err(carrick_abi::LINUX_ENOSYS),
                    )
                    .map_err(|error| format!("doorbell {port:#x}: {error}"))?;
                run.exits.push(format!("doorbell {port:#x}"));
                match status {
                    None => publish_worker_backings(&factory).map_err(|error| {
                        format!("slot publication after doorbell {port:#x}: {error}")
                    })?,
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

#[test]
fn production_soft_worker_refuses_peer_entry() {
    let dispatcher = SyscallDispatcher::default();
    let root = dispatcher.capture_one_task_context().expect("issued root");
    let carrier = boot_initial_mm(&static_elf(HELLO), &dispatcher, &root).expect("initial MM");
    let (_, factory) = carrier
        .into_worker_parts()
        .expect("worker hand-off")
        .into_factory(carrick_kernel::dispatch::serve_native_entropy);
    let mut peer = factory.claim(1).expect("peer lease");
    let entry = peer.run_idle_peer();
    assert!(
        matches!(entry, Err(carrick_hal::TrapError::UnsupportedPlatform)),
        "the unconfigured soft peer reached guest entry: {entry:?}"
    );
}

#[test]
fn production_ring_xgetbv_matches_the_x86_64_v3_contract() {
    // xor ecx, ecx; xgetbv; mov edi, eax; mov eax, 231; syscall; ud2.
    let code = [
        0x31, 0xc9, 0x0f, 0x01, 0xd0, 0x89, 0xc7, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ];
    let run = run_hello(&static_elf(&code));
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(
        run.exit,
        Some(carrick_x86::XCR0_X86_64_V3_MASK as i32),
        "{}",
        run.summary()
    );
}

#[test]
fn production_ring_retranslates_a_code_page_written_through_forward_venue() {
    // Call the same leaf before and after the host writes to its immediate.
    // The stdout crossing records the original byte; exit_group uses the
    // value loaded by the second call to the translated leaf.
    let code = [
        0xe8, 0x28, 0, 0, 0, // call leaf
        0xbf, 1, 0, 0, 0, // mov edi, 1 (stdout)
        0x48, 0x8d, 0x35, 0x1d, 0, 0, 0, // lea rsi, [rip + leaf + 1]
        0xba, 1, 0, 0, 0, // mov edx, 1
        0xb8, 1, 0, 0, 0, // mov eax, 1 (write)
        0x0f, 0x05, // syscall
        0xe8, 0x0b, 0, 0, 0, // call leaf
        0x89, 0xc7, // mov edi, eax
        0xb8, 0xe7, 0, 0, 0, // mov eax, 231 (exit_group)
        0x0f, 0x05, // syscall
        0x0f, 0x0b, // ud2
        0xb8, 7, 0, 0, 0, 0xc3, // leaf: mov eax, 7; ret
    ];
    let mut elf = static_elf(&code);
    // PT_LOAD p_flags: user code is deliberately writable for this test.
    elf[68..72].copy_from_slice(&7u32.to_le_bytes());
    let run = run_with_stdout_patch(&elf, Some(9));
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(run.stdout, [7], "{}", run.summary());
    assert_eq!(run.exit, Some(9), "{}", run.summary());
}

#[test]
fn production_ring_resumes_after_runtime_slot_install() {
    let run = run_hello(&static_elf(ANONYMOUS_HELLO));
    println!("[production, anonymous hello] {}", run.summary());
    assert!(
        run.exits.iter().any(|exit| exit == "doorbell 0xd1"),
        "{}",
        run.summary()
    );
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(run.stdout, b"hello\n", "{}", run.summary());
    assert_eq!(run.exit, Some(0), "{}", run.summary());
}

/// The bhyve/KVM M2 static musl hello exercises stdio readiness and the
/// runtime slot refresh through the production soft ring.
#[test]
#[ignore = "requires the separately built musl hello fixture from just test-kvm"]
fn production_ring_runs_musl_hello_to_exit_on_soft_cpu() {
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../carrick-vmm-bhyve/fixtures/hello-x86_64/target/x86_64-unknown-linux-musl/release/carrick-hello-x86_64"
    ))
    .expect("musl hello fixture");
    let run = run_hello(&elf);
    println!("[production, musl hello] {}", run.summary());
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(run.stdout, b"hello, x86_64 world\n", "{}", run.summary());
    assert_eq!(run.exit, Some(0), "{}", run.summary());
}

fn assemble_static_fixture(name: &str, source: &str, flags: &[&str]) -> Vec<u8> {
    let output =
        std::path::Path::new(env!("OUT_DIR")).join(format!("soft-{name}-{}", std::process::id()));
    let assembled = std::process::Command::new("timeout")
        .args([
            "10",
            "cc",
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
        ])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(&output)
        .output()
        .expect("assemble static fixture");
    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let elf = std::fs::read(&output).expect("read assembled static fixture");
    std::fs::remove_file(output).expect("remove assembled static fixture");
    elf
}

#[test]
fn production_ring_forked_child_writes_and_is_reaped() {
    let elf = assemble_static_fixture(
        "fork",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-cli/tests/fixtures/x86_forked_child_stdout.S"
        ),
        &[],
    );
    let run = run_hello(&elf);
    assert!(run.failure.is_none(), "{}", run.summary());
    assert_eq!(run.stdout, b"E", "{}", run.summary());
    assert_eq!(run.exit, Some(7), "{}", run.summary());
}

#[test]
fn production_ring_non_last_threads_raw_exit() {
    let elf = assemble_static_fixture(
        "raw-exit",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../carrick-vmm-kvm/tests/fixtures/native_robust_raw_exit.S"
        ),
        &["-DTWO_LIVE"],
    );
    let run = run_hello(&elf);
    assert!(run.failure.is_none(), "{}", run.summary());
    assert!(run.stdout.is_empty(), "{}", run.summary());
    assert_eq!(run.exit, Some(0), "{}", run.summary());
}
