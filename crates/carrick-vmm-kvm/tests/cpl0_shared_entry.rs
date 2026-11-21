//! Real KVM proof that production CPL0 dispatches a Linux lifecycle call
//! inside the shared family before its physical root-exit notification.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

#[path = "common/kvm_pool_fixture.rs"]
mod kvm_pool_fixture;
use carrick_vmm_kvm::cpl0_boot::PhysicalCrossingFamily;
use kvm_pool_fixture::run_pool_fixture;

fn tiny_elf(code: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0xb0 + code.len()];
    let file_size = bytes.len() as u64;
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R|X
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0xb0..].copy_from_slice(code);
    bytes
}

#[test]
fn production_file_region_stdio_dup_parity() {
    let code = [
        0xbf, 1, 0, 0, 0, // mov edi,1: stdout
        0xb8, 32, 0, 0, 0, 0x0f, 0x05, // dup(stdout)
        0x48, 0x89, 0xc7, // mov rdi,rax: return the new descriptor as status
        0xb8, 231, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b, // exit_group; ud2
    ];
    let run = run_pool_fixture(&tiny_elf(&code), 4).run;
    assert_eq!(run.exit_code, 3);
    let witness = run
        .report
        .execution_witness
        .expect("production region witness");
    assert_eq!(witness.physical_crossing_families.len(), 1);
    assert_eq!(witness.physical_crossing_families[0].family, "root_exit");
    assert_eq!(witness.physical_crossing_families[0].count, 1);
}

#[test]
fn production_sigprocmask_uses_shared_lifecycle_family() {
    let code = [
        // NULL set and oldset need no guest memory or host resource. The old
        // CommonFamilies lifecycle path still forwarded this valid call.
        0x31, 0xf6, // xor esi,esi: no new set
        0x31, 0xff, // xor edi,edi: SIG_BLOCK
        0x31, 0xd2, // xor edx,edx: no old set
        0x49, 0xc7, 0xc2, 0x08, 0x00, 0x00, 0x00, // mov r10,8
        0xb8, 0x0e, 0x00, 0x00, 0x00, // mov eax,14: rt_sigprocmask
        0x0f, 0x05, // syscall
        0x48, 0x85, 0xc0, // test rax,rax
        0xbf, 0x07, 0x00, 0x00, 0x00, // mov edi,7: success exit
        0x74, 0x05, // jz exit_group
        0xbf, 0x09, 0x00, 0x00, 0x00, // mov edi,9: failure exit
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,231: exit_group
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ];
    let elf = tiny_elf(&code);
    let run = run_pool_fixture(&elf, 4).run;
    assert_eq!(run.exit_code, 7);
    let witness = run.report.execution_witness.expect("CPL0 witness");
    assert_eq!(witness.physical_crossing_families.len(), 1);
    assert_eq!(witness.physical_crossing_families[0].family, "root_exit");
    assert_eq!(witness.physical_crossing_families[0].count, 1);
}

#[test]
fn production_cpl0_refuses_non_allowlisted_forwards_with_enosys() {
    // Both ordinals map to guest process policy and are absent from the
    // production physical host-forward allowlist. Anonymous mmap is served
    // by the native MM owner and cannot be used as a refusal witness.
    let mut code = Vec::new();
    let mut branches = Vec::new();
    for native in [101u32, 103u32] {
        // ptrace, syslog
        code.extend_from_slice(&[0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2]);
        code.push(0xb8);
        code.extend_from_slice(&native.to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x48, 0x83, 0xf8, 0xda]);
        branches.push(code.len());
        code.extend_from_slice(&[0x75, 0]); // jne failure
    }
    code.extend_from_slice(&[
        0xbf, 42, 0, 0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    let failure = code.len();
    code.extend_from_slice(&[
        0xbf, 1, 0, 0, 0, 0xb8, 0xe7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    for branch in branches {
        code[branch + 1] = u8::try_from(failure - (branch + 2)).expect("bounded branch");
    }
    let elf = tiny_elf(&code);
    let outcome = run_pool_fixture(&elf, 8);
    assert_eq!(outcome.run.exit_code, 42);
    assert_eq!(outcome.physical.initial_execution_witness().unwrap().1, 0);
    assert_eq!(
        outcome.physical.physical_crossing_counts().unwrap(),
        [
            (PhysicalCrossingFamily::OwnerGrant, 0),
            (PhysicalCrossingFamily::RootExit, 1),
            (PhysicalCrossingFamily::ChildRetire, 0),
            (PhysicalCrossingFamily::RunFailure, 0),
            (PhysicalCrossingFamily::ReturnSettlement, 0),
        ]
    );
    assert_eq!(
        outcome
            .physical
            .refusal_count(carrick_abi::NativeNr(101))
            .unwrap(),
        1
    );
    assert_eq!(
        outcome
            .physical
            .refusal_count(carrick_abi::NativeNr(103))
            .unwrap(),
        1
    );
    assert_eq!(outcome.physical.refusal_overflow_count().unwrap(), 0);
    let counters = outcome.physical.syscall_counters().expect("mapped census");
    for nr in [101, 103] {
        assert_eq!(
            counters.refused[nr].load(core::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            counters.refused_child[nr].load(core::sync::atomic::Ordering::Relaxed),
            0,
            "the initial process is the graph root even when its visible PID is not 1"
        );
    }
}

#[test]
fn native_child_select_timeval_wakes_on_sibling_pipe_write() {
    native_child_select_wake(&["-DUSE_SELECT_TIMEVAL"], default_dispatcher());
}

/// #2588: apt's shape. A fork child selects with no timeout on a pipe its
/// live parent writes only after the host observes the child's enrollment.
#[test]
fn native_child_pselect6_wakes_on_parent_pipe_write() {
    native_child_select_wake(&["-DPARENT_WRITES"], default_dispatcher());
}

/// #2588: the writer is a fork child that makes the pipe its stdout and
/// execs a static successor, as apt's fetch methods do.
#[test]
fn native_child_pselect6_wakes_on_exec_successor_write() {
    let directory = tempfile::tempdir().expect("successor directory");
    let successor = directory.path().join("successor");
    let marker = kvm_pool_fixture::assemble_fixture("native_exec_marker.S", &[]);
    carrick_test_support::executable::write_executable_mode(&successor, &marker, 0o700);
    let define = format!("-DSUCCESSOR_PATH=\"{}\"", successor.display());
    let mut dispatcher = default_dispatcher();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    native_child_select_wake(&["-DEXEC_WRITER", &define], dispatcher);
}

/// #2588: the reader itself is an exec'd successor whose stdin is the zone
/// pipe; it parks in `pselect6` until its live parent writes after enrollment,
/// sees the pipe readable, reads the byte, and exits 0.
#[test]
fn native_exec_child_pselect6_wakes_on_parent_pipe_write() {
    let directory = tempfile::tempdir().expect("successor directory");
    let successor = directory.path().join("pselect_successor");
    let poller_elf = kvm_pool_fixture::assemble_fixture(
        "native_pipe_poll_wake.S",
        &[
            "-DUSE_PSELECT",
            "-DEXEC_POLLER_SUCCESSOR",
            "-DSELECT_GATE_PORT=0",
        ],
    );
    carrick_test_support::executable::write_executable_mode(&successor, &poller_elf, 0o700);
    let define = format!("-DSUCCESSOR_PATH=\"{}\"", successor.display());
    let mut dispatcher = default_dispatcher();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/"))
            .expect("host filesystem"),
    ));
    native_child_select_wake(&["-DPARENT_WRITES", "-DEXEC_POLLER", &define], dispatcher);
}

/// #2588: two fork children park simultaneously in `pselect6` on separate zone
/// pipes on the default 2-vCPU KVM pool. Both vCPUs must be released so their
/// live parent can run, observe both enrollments, write to both pipes, and reap
/// both children exiting 0.
#[test]
fn native_two_children_pselect6_release_default_pool_capacity() {
    use carrick_sched_core::{RecordId, ZONE_RECORDS};
    use std::time::{Duration, Instant};

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("select gate peer");
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set the gate socket deadline");
    let port = format!(
        "-DSELECT_GATE_PORT={}",
        peer.local_addr()
            .expect("gate socket address")
            .port()
            .swap_bytes()
    );
    let elf = kvm_pool_fixture::assemble_fixture(
        "native_pipe_poll_wake.S",
        &["-DUSE_PSELECT", "-DTWO_POLLERS", &port],
    );
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("two-poller fixture");
    let mut sender = None;
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        512,
        kvm_pool_fixture::ROOT_AFFINITY_ANY,
        |carrier| {
            let zone = carrier.carrier_zone_wake().expect("carrier wake domain");
            sender = Some(std::thread::spawn(move || {
                let mut pids = [0u8; 8];
                let (count, client) = peer.recv_from(&mut pids).expect("parent gate");
                assert_eq!(count, pids.len());
                let tid1 = u64::from(u32::from_ne_bytes(pids[..4].try_into().unwrap()));
                let tid2 = u64::from(u32::from_ne_bytes(pids[4..].try_into().unwrap()));
                let deadline = Instant::now() + Duration::from_secs(4);
                let both_parked = loop {
                    let is_enrolled = |tid| {
                        (1..ZONE_RECORDS as u32)
                            .filter_map(RecordId::from_raw)
                            .any(|id| {
                                let record = zone.zone().record(id);
                                record.identity().tid == tid
                                    && record.has_adapter_operation()
                                    && record
                                        .object_wait_census()
                                        .is_some_and(|wait| wait.queue != 0)
                            })
                    };
                    let ready = is_enrolled(tid1) && is_enrolled(tid2);
                    if ready || Instant::now() >= deadline {
                        break ready;
                    }
                    std::thread::yield_now();
                };
                assert_eq!(peer.send_to(b"w", client).expect("release parent"), 1);
                both_parked
            }));
        },
        default_dispatcher(),
    )
    .expect("two-poller pselect6 run");
    assert_eq!(
        outcome.run.exit_code, 7,
        "two-poller select: {:?}",
        outcome.run
    );
    assert!(
        sender
            .expect("gate sender")
            .join()
            .expect("join gate sender"),
        "both pselect6 children must be simultaneously enrolled on the 2-vCPU pool"
    );
}

/// #2588: pselect6's temporary mask blocks SIGUSR1 for the wait only. The
/// writer signals the parked reader before writing: the wait reports the
/// pipe rather than EINTR, the persistent mask comes back, and the pending
/// signal's handler runs after the call.
#[test]
fn native_child_pselect6_sigmask_holds_a_signal_until_the_wait_ends() {
    native_child_select_wake(&["-DSELECT_SIGMASK"], default_dispatcher());
}

fn default_dispatcher() -> carrick_kernel::dispatch::SyscallDispatcher {
    carrick_kernel::dispatch::SyscallDispatcher::default()
}

#[test]
fn native_child_pselect6_times_out_then_reports_eof() {
    let elf = kvm_pool_fixture::assemble_fixture(
        "native_pipe_poll_wake.S",
        &[
            "-DUSE_PSELECT",
            "-DSELECT_TIMEOUT_EOF",
            "-DSELECT_GATE_PORT=0",
        ],
    );
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("timed select fixture");
    let outcome = kvm_pool_fixture::try_run_program_with_root_affinity_typed(
        &program,
        256,
        kvm_pool_fixture::ROOT_AFFINITY_ANY,
        |_| {},
    )
    .unwrap_or_else(|failure| panic!("timed select: {}", failure.error));
    assert_eq!(outcome.run.exit_code, 7, "timed select: {:?}", outcome.run);
}

fn native_child_select_wake(
    variant: &[&str],
    dispatcher: carrick_kernel::dispatch::SyscallDispatcher,
) {
    use carrick_sched_core::{RecordId, ZONE_RECORDS};
    use std::time::{Duration, Instant};

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("select gate peer");
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set the gate socket deadline");
    let port = format!(
        "-DSELECT_GATE_PORT={}",
        peer.local_addr()
            .expect("gate socket address")
            .port()
            .swap_bytes()
    );
    let mut flags = vec!["-DUSE_PSELECT", "-DCHILD_POLLS", port.as_str()];
    flags.extend_from_slice(variant);
    let elf = kvm_pool_fixture::assemble_fixture("native_pipe_poll_wake.S", &flags);
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("pselect6 fixture");
    let mut sender = None;
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        256,
        kvm_pool_fixture::ROOT_AFFINITY_ANY,
        |carrier| {
            let zone = carrier.carrier_zone_wake().expect("carrier wake domain");
            sender = Some(std::thread::spawn(move || {
                let mut pid = [0; 4];
                let (count, client) = peer.recv_from(&mut pid).expect("sibling writer");
                assert_eq!(count, pid.len());
                let tid = u64::from(u32::from_ne_bytes(pid));
                let deadline = Instant::now() + Duration::from_secs(4);
                let parked = loop {
                    let enrolled =
                        (1..ZONE_RECORDS as u32)
                            .filter_map(RecordId::from_raw)
                            .any(|id| {
                                let record = zone.zone().record(id);
                                record.identity().tid == tid
                                    && record.has_adapter_operation()
                                    && record
                                        .object_wait_census()
                                        .is_some_and(|wait| wait.queue != 0)
                            });
                    if enrolled || Instant::now() >= deadline {
                        break enrolled;
                    }
                    std::thread::yield_now();
                };
                assert_eq!(peer.send_to(b"w", client).expect("release gate writer"), 1);
                parked
            }));
        },
        dispatcher,
    )
    .expect("pselect6 run");
    assert_eq!(outcome.run.exit_code, 7, "child select: {:?}", outcome.run);
    assert!(
        sender
            .expect("gate sender")
            .join()
            .expect("join gate sender"),
        "child pselect6 never enrolled"
    );
}
