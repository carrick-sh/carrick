//! Refusal-injection witnesses for the typed copyout families (#711).
//!
//! Each test dispatches one syscall against an admitted-owner memory whose
//! first prepare is refused with an Editor `OwnerWait`. The refusal must
//! surface as `OwnerMemoryWait` with nothing written and no side effect, and
//! the runtime's redispatch must then complete cleanly. Before migration each
//! of these returned `Errno { errno: 14 }` (EFAULT) on a valid pointer.

use super::copyout::owner_fixture::OwnerRefusingMemory;
use super::*;
use crate::compat::CompatReporter;
use carrick_abi::syscall::nr;
use carrick_abi::{
    LINUX_AF_INET, LINUX_AF_UNIX, LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LINUX_SOCK_STREAM,
};
use carrick_guest_mem::GuestMemory;

const BASE: u64 = 0x4000_0000;
const LEN: usize = 0x4000;
const FILL: u8 = 0xa5;
const OUT: u64 = BASE + 0x100;
const OUT2: u64 = BASE + 0x800;
const LEN_ADDR: u64 = BASE + 0x40;
const PATH: u64 = BASE + 0x2000;

fn running_lease(
    context: &crate::kernel::KernelContext,
) -> crate::kernel::objects::ThreadExecutionLease {
    let mm = context.shared().mm().id();
    context
        .thread()
        .publish_initial_task_state(crate::kernel::objects::MigratableTaskState {
            cpu: carrick_hal::threaded::GuestCpuState::from_aarch64_v1(
                carrick_hal::threaded::Aarch64TaskCpuStateV1 {
                    gprs: [0; 31],
                    pc: 0,
                    pstate: 0,
                    trap_pc: 0,
                    trap_pstate: 0,
                    sp_el0: 0,
                    elr_el1: 0,
                    spsr_el1: 0,
                    ttbr0: 0,
                    ttbr1: 0,
                    tcr: 0,
                    sctlr_el1: 0,
                    mair_el1: 0,
                    vbar_el1: 0,
                    cpacr_el1: 0,
                    cntkctl_el1: 0,
                    tpidr_el1: 0,
                    actlr_el1: 0,
                    tpidr_el0: 0,
                    tpidrro_el0: 0,
                    contextidr_el1: 0,
                    vregs: [0; 32],
                    fpsr: 0,
                    fpcr: 0,
                    pending_resume_pc: None,
                    last_syscall_nr: Some(271),
                    last_syscall_orig_x0: 0,
                    last_fault_esr: 0,
                    last_exit_class: 0,
                    is_forked_child: false,
                    syscall_continuation: None,
                    mm_generation: mm.raw(),
                    asid_generation: 41,
                },
            ),
            mm,
            asid_generation: 41,
        })
        .expect("publish task state");
    context
        .thread()
        .claim_runnable(
            crate::kernel::objects::ExecutorId::for_transitional_thread(
                carrick_hal::ThreadId::synthetic_for_tests(41),
            )
            .expect("transitional executor"),
        )
        .expect("claim running lease")
}

struct Guest {
    dispatcher: SyscallDispatcher,
    reporter: CompatReporter,
    memory: OwnerRefusingMemory,
    lease: Option<crate::kernel::objects::ThreadExecutionLease>,
}

impl Guest {
    fn new() -> Self {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let lease = running_lease(&context);
        Self {
            dispatcher,
            lease: Some(lease),
            reporter: CompatReporter::default(),
            memory: OwnerRefusingMemory::new(BASE, LEN, FILL),
        }
    }

    fn call(&mut self, number: u64, args: [u64; 6]) -> DispatchOutcome {
        let context = self.dispatcher.capture_one_task_context().unwrap();
        self.dispatcher
            .dispatch_with_lease(
                &context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                &mut self.memory,
                &self.reporter,
                self.lease.as_ref(),
            )
            .expect("dispatch")
    }

    fn ok(&mut self, number: u64, args: [u64; 6]) -> i64 {
        match self.call(number, args) {
            DispatchOutcome::Returned { value } => value,
            other => panic!("syscall {number} failed: {other:?}"),
        }
    }

    /// Dispatch once with the first prepare refused, assert the wait and an
    /// untouched output, and return the retried outcome.
    fn refused_then_retried(
        &mut self,
        number: u64,
        args: [u64; 6],
        untouched: &[(u64, usize)],
    ) -> DispatchOutcome {
        let wait = self.memory.refuse_next();
        let refused = self.call(number, args);
        assert_eq!(
            refused,
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
            "syscall {number}: a transient owner refusal is a wait, not EFAULT",
        );
        for &(address, len) in untouched {
            assert_eq!(
                self.memory.read_bytes(address, len).unwrap(),
                vec![FILL; len],
                "syscall {number}: nothing is written before the retry",
            );
        }
        self.call(number, args)
    }

    fn pipe(&mut self) -> (i32, i32) {
        assert_eq!(self.ok(nr::PIPE2.raw(), [OUT2, 0, 0, 0, 0, 0]), 0);
        let pair = self.memory.read_bytes(OUT2, 8).unwrap();
        self.memory.seed(OUT2, &[FILL; 8]);
        (
            i32::from_ne_bytes(pair[..4].try_into().unwrap()),
            i32::from_ne_bytes(pair[4..].try_into().unwrap()),
        )
    }

    fn stream_pair(&self) -> (i32, i32) {
        let creds = super::net::unix_pure::LinuxUcred {
            pid: 100,
            uid: 1000,
            gid: 1000,
        };
        let (left, right) =
            super::net::unix_pure::PureSocketInner::pair(LINUX_SOCK_STREAM, creds, creds);
        let install = |socket| {
            self.dispatcher
                .install_fd_at_or_above(
                    3,
                    OpenFile::from_open_description_with_status_flags(
                        Arc::new(parking_lot::RwLock::new(OpenDescription::InMemorySocket {
                            base: OpenDescriptionBase::new(0),
                            socket,
                        })),
                        LINUX_O_RDWR,
                        0,
                    ),
                )
                .unwrap()
        };
        (install(left), install(right))
    }

    fn seed_path(&mut self, path: &str) {
        self.memory.seed(PATH, format!("{path}\0").as_bytes());
    }
}

#[test]
fn pipe2_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let wait = g.memory.refuse_next();
    assert_eq!(
        g.call(nr::PIPE2.raw(), [OUT, 0, 0, 0, 0, 0]),
        DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
    );
    assert!(
        g.dispatcher.open_file(3).is_none() && g.dispatcher.open_file(4).is_none(),
        "no pipe end is installed before the output is prepared",
    );
    assert_eq!(g.memory.read_bytes(OUT, 8).unwrap(), [FILL; 8]);
    assert_eq!(g.ok(nr::PIPE2.raw(), [OUT, 0, 0, 0, 0, 0]), 0);
    let pair = g.memory.read_bytes(OUT, 8).unwrap();
    assert_eq!(pair[..4], 3i32.to_ne_bytes());
    assert_eq!(pair[4..], 4i32.to_ne_bytes());
    assert!(g.dispatcher.open_file(3).is_some() && g.dispatcher.open_file(4).is_some());
}

#[test]
fn fstat_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let (read_fd, _) = g.pipe();
    let size = <carrick_abi::LinuxStat as carrick_abi::KernelAbi>::ABI_SIZE;
    let retried = g.refused_then_retried(
        nr::FSTAT.raw(),
        [read_fd as u64, OUT, 0, 0, 0, 0],
        &[(OUT, size)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    let mode = u32::from_ne_bytes(
        g.memory
            .read_bytes(OUT + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & carrick_abi::LINUX_S_IFMT, carrick_abi::LINUX_S_IFIFO);
}

#[test]
fn newfstatat_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    g.seed_path("/");
    let size = <carrick_abi::LinuxStat as carrick_abi::KernelAbi>::ABI_SIZE;
    let retried = g.refused_then_retried(
        nr::NEWFSTATAT.raw(),
        [LINUX_AT_FDCWD, PATH, OUT, 0, 0, 0],
        &[(OUT, size)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    let mode = u32::from_ne_bytes(
        g.memory
            .read_bytes(OUT + 16, 4)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(mode & carrick_abi::LINUX_S_IFMT, carrick_abi::LINUX_S_IFDIR);
}

#[test]
fn statx_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let (read_fd, _) = g.pipe();
    g.seed_path("");
    let size = <carrick_abi::LinuxStatx as carrick_abi::KernelAbi>::ABI_SIZE;
    let retried = g.refused_then_retried(
        nr::STATX.raw(),
        [read_fd as u64, PATH, LINUX_AT_EMPTY_PATH, 0, OUT, 0],
        &[(OUT, size)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    let mode = u16::from_ne_bytes(
        g.memory
            .read_bytes(OUT + 28, 2)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        u32::from(mode) & carrick_abi::LINUX_S_IFMT,
        carrick_abi::LINUX_S_IFIFO
    );
}

#[test]
fn clock_gettime_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let retried = g.refused_then_retried(
        nr::CLOCK_GETTIME.raw(),
        [carrick_abi::LINUX_CLOCK_MONOTONIC, OUT, 0, 0, 0, 0],
        &[(OUT, 16)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    assert_ne!(g.memory.read_bytes(OUT, 16).unwrap(), [FILL; 16]);
}

#[test]
fn gettimeofday_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let retried = g.refused_then_retried(
        nr::GETTIMEOFDAY.raw(),
        [OUT, OUT2, 0, 0, 0, 0],
        &[(OUT, 16), (OUT2, 8)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    assert_ne!(g.memory.read_bytes(OUT, 16).unwrap(), [FILL; 16]);
    assert_eq!(
        g.memory.read_bytes(OUT2, 8).unwrap(),
        [0; 8],
        "UTC timezone"
    );
}
fn socketpair(g: &mut Guest) -> (i32, i32) {
    assert_eq!(
        g.ok(
            nr::SOCKETPAIR.raw(),
            [
                LINUX_AF_UNIX as u64,
                LINUX_SOCK_STREAM as u64,
                0,
                OUT2,
                0,
                0
            ],
        ),
        0
    );
    let pair = g.memory.read_bytes(OUT2, 8).unwrap();
    g.memory.seed(OUT2, &[FILL; 8]);
    (
        i32::from_ne_bytes(pair[..4].try_into().unwrap()),
        i32::from_ne_bytes(pair[4..].try_into().unwrap()),
    )
}

/// #695 control at 4559f21b0: 3 of 20 signed runs of
/// `sock-pingpong-stepper` got `socketpair` EFAULT on the main thread's valid
/// stack array while a sibling thread of the same MM ran host-served socket
/// operations. It must prepare its output before creating anything, report
/// the wait, and install nothing until the retry.
#[test]
fn socketpair_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let args = [LINUX_AF_UNIX as u64, LINUX_SOCK_STREAM as u64, 0, OUT, 0, 0];
    let wait = g.memory.refuse_next();
    assert_eq!(
        g.call(nr::SOCKETPAIR.raw(), args),
        DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
    );
    assert!(
        g.dispatcher.host_fd_for_poll(3).is_none() && g.dispatcher.host_fd_for_poll(4).is_none(),
        "nothing is installed before the output is prepared",
    );
    assert_eq!(g.memory.read_bytes(OUT, 8).unwrap(), [FILL; 8]);
    assert_eq!(g.ok(nr::SOCKETPAIR.raw(), args), 0);
    let pair = g.memory.read_bytes(OUT, 8).unwrap();
    for chunk in pair.chunks_exact(4) {
        let guest_fd = i32::from_ne_bytes(chunk.try_into().unwrap());
        assert!(g.dispatcher.host_fd_for_poll(guest_fd).is_some());
    }
}

#[test]
fn getsockname_and_getpeername_wait_for_an_owner_refused_copyout() {
    let mut g = Guest::new();
    let (left, _) = socketpair(&mut g);
    for number in [nr::GETSOCKNAME.raw(), nr::GETPEERNAME.raw()] {
        g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
        g.memory.seed(OUT, &[FILL; 16]);
        let retried =
            g.refused_then_retried(number, [left as u64, OUT, LEN_ADDR, 0, 0, 0], &[(OUT, 16)]);
        assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
        let family = u16::from_ne_bytes(g.memory.read_bytes(OUT, 2).unwrap().try_into().unwrap());
        assert_eq!(family, LINUX_AF_UNIX as u16, "syscall {number}");
    }
}

#[test]
fn sockaddr_addrlen_read_suspension_waits_before_copyout() {
    let mut g = Guest::new();
    let (left, _) = socketpair(&mut g);
    for number in [nr::GETSOCKNAME.raw(), nr::GETPEERNAME.raw()] {
        g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
        g.memory.seed(OUT, &[FILL; 16]);
        let wait = g.memory.refuse_next_read();
        assert_eq!(
            g.call(number, [left as u64, OUT, LEN_ADDR, 0, 0, 0]),
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
            "syscall {number}: addrlen read suspension must retain its owner wait",
        );
        assert_eq!(g.memory.read_bytes(OUT, 16).unwrap(), [FILL; 16]);
        assert_eq!(
            g.call(number, [left as u64, OUT, LEN_ADDR, 0, 0, 0]),
            DispatchOutcome::Returned { value: 0 },
        );
    }
}
#[test]
fn time_and_resource_records_wait_for_an_owner_refused_copyout() {
    let mut g = Guest::new();
    for (number, args, len, value) in [
        (nr::TIMES.raw(), [OUT, 0, 0, 0, 0, 0], 32, None),
        (nr::GETRUSAGE.raw(), [0, OUT, 0, 0, 0, 0], 144, Some(0)),
        (nr::GETRLIMIT.raw(), [7, OUT, 0, 0, 0, 0], 16, Some(0)),
        (nr::SYSINFO.raw(), [OUT, 0, 0, 0, 0, 0], 112, Some(0)),
        (
            nr::CLOCK_GETRES.raw(),
            [carrick_abi::LINUX_CLOCK_MONOTONIC, OUT, 0, 0, 0, 0],
            16,
            Some(0),
        ),
        (nr::GETITIMER.raw(), [0, OUT, 0, 0, 0, 0], 32, Some(0)),
    ] {
        g.memory.seed(OUT, &[FILL; 144]);
        let retried = g.refused_then_retried(number, args, &[(OUT, len)]);
        let DispatchOutcome::Returned { value: returned } = retried else {
            panic!("syscall {number} retry: {retried:?}");
        };
        if let Some(value) = value {
            assert_eq!(returned, value, "syscall {number}");
        }
        assert_ne!(
            g.memory.read_bytes(OUT, len).unwrap(),
            vec![FILL; len],
            "syscall {number} wrote its record on the retry",
        );
    }
}

#[test]
fn later_invalid_output_retains_valid_prefix_in_gettimeofday_and_sockaddr() {
    let mut g = Guest::new();
    let unmapped = BASE + (LEN as u64) + 0x100;

    // 1. gettimeofday(valid tv, invalid tz) -> EFAULT after writing tv.
    g.memory.seed(OUT, &[FILL; 16]);
    assert_eq!(
        g.call(nr::GETTIMEOFDAY.raw(), [OUT, unmapped, 0, 0, 0, 0]),
        DispatchOutcome::errno(carrick_abi::LINUX_EFAULT),
    );
    assert_ne!(
        g.memory.read_bytes(OUT, 16).unwrap(),
        [FILL; 16],
        "gettimeofday must commit valid tv before reporting EFAULT on tz",
    );

    // 2. getsockname(valid addr, readonly addrlen) -> EFAULT after writing addr.
    let (left, _) = socketpair(&mut g);
    let ro_len_addr = BASE + 0x900;
    g.memory.seed(ro_len_addr, &16u32.to_ne_bytes());
    g.memory.protect_readonly(ro_len_addr, 4);
    g.memory.seed(OUT, &[FILL; 16]);
    assert_eq!(
        g.call(
            nr::GETSOCKNAME.raw(),
            [left as u64, OUT, ro_len_addr, 0, 0, 0]
        ),
        DispatchOutcome::errno(carrick_abi::LINUX_EFAULT),
    );
    let family = u16::from_ne_bytes(g.memory.read_bytes(OUT, 2).unwrap().try_into().unwrap());
    assert_eq!(
        family, LINUX_AF_UNIX as u16,
        "getsockname must commit valid addr before reporting EFAULT on readonly addrlen",
    );
}

#[test]
fn sockaddr_at_page_end_with_storage_addrlen_prepares_only_actual_bytes() {
    let mut g = Guest::new();
    let v4_sock = g.ok(
        nr::SOCKET.raw(),
        [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    );
    let sockaddr_v4 = |port: u16| {
        let mut sa = Vec::with_capacity(16);
        sa.extend_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sa.extend_from_slice(&port.to_be_bytes());
        sa.extend_from_slice(&[127, 0, 0, 1]);
        sa.extend_from_slice(&[0u8; 8]);
        sa
    };
    g.memory.seed(OUT, &sockaddr_v4(0));
    assert_eq!(g.ok(nr::BIND.raw(), [v4_sock as u64, OUT, 16, 0, 0, 0]), 0);
    assert_eq!(g.ok(nr::LISTEN.raw(), [v4_sock as u64, 16, 0, 0, 0, 0]), 0);

    // Final 16 writable bytes before the unmapped boundary at `BASE + LEN`,
    // with supplied `*addrlen = 128` (`sizeof(sockaddr_storage)`).
    let tail_v4 = BASE + (LEN as u64) - 16;
    g.memory.seed(tail_v4, &[FILL; 16]);
    g.memory.seed(LEN_ADDR, &128u32.to_ne_bytes());
    assert_eq!(
        g.call(
            nr::GETSOCKNAME.raw(),
            [v4_sock as u64, tail_v4, LEN_ADDR, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
        "getsockname must prepare only the 16 actual AF_INET bytes, not 128",
    );
    assert_eq!(
        g.memory.read_bytes(LEN_ADDR, 4).unwrap(),
        16u32.to_ne_bytes()
    );
    // Final 28 writable bytes for AF_INET6 with `*addrlen = 128`.
    let v6_sock = g.ok(
        nr::SOCKET.raw(),
        [
            carrick_abi::LINUX_AF_INET6 as u64,
            LINUX_SOCK_STREAM as u64,
            0,
            0,
            0,
            0,
        ],
    );
    let mut sa6 = vec![0u8; 28];
    sa6[0..2].copy_from_slice(&(carrick_abi::LINUX_AF_INET6 as u16).to_ne_bytes());
    sa6[23] = 1; // ::1
    g.memory.seed(OUT, &sa6);
    assert_eq!(g.ok(nr::BIND.raw(), [v6_sock as u64, OUT, 28, 0, 0, 0]), 0);
    let tail_v6 = BASE + (LEN as u64) - 28;
    g.memory.seed(tail_v6, &[FILL; 28]);
    g.memory.seed(LEN_ADDR, &128u32.to_ne_bytes());
    assert_eq!(
        g.call(
            nr::GETSOCKNAME.raw(),
            [v6_sock as u64, tail_v6, LEN_ADDR, 0, 0, 0]
        ),
        DispatchOutcome::Returned { value: 0 },
        "getsockname must prepare only the 28 actual AF_INET6 bytes, not 128",
    );
    assert_eq!(
        g.memory.read_bytes(LEN_ADDR, 4).unwrap(),
        28u32.to_ne_bytes()
    );
}
#[test]
fn zero_output_gettimeofday_makes_zero_owner_prepares() {
    let mut g = Guest::new();
    let before = g.memory.prepares;
    let _wait = g.memory.refuse_next();
    assert_eq!(
        g.call(nr::GETTIMEOFDAY.raw(), [0, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 },
        "gettimeofday(NULL, NULL) must not suspend on an armed owner refusal",
    );
    assert_eq!(
        g.memory.prepares, before,
        "gettimeofday(NULL, NULL) must make zero prepare_write calls",
    );
}

#[test]
fn recvfrom_owner_defers_addrlen_fault_until_data() {
    for addrlen in [0, BASE + LEN as u64 + 1, LEN_ADDR] {
        let mut g = Guest::new();
        let (left, right) = g.stream_pair();
        if addrlen == LEN_ADDR {
            g.memory.seed(LEN_ADDR, &0u32.to_ne_bytes());
            g.memory.protect_readonly(LEN_ADDR, 4);
        }
        let args = [
            left as u64,
            OUT,
            4,
            LinuxMsgFlags::DONTWAIT.bits() as u64,
            OUT2,
            addrlen,
        ];
        assert_eq!(
            g.call(nr::RECVFROM.raw(), args),
            DispatchOutcome::errno(LINUX_EAGAIN),
            "empty nonblocking socket: errno 11 must precede addrlen errno 14"
        );
        let mut blocking = args;
        blocking[3] = 0;
        assert!(
            matches!(
                g.call(nr::RECVFROM.raw(), blocking),
                DispatchOutcome::WaitOnFds { .. }
            ),
            "empty blocking socket must wait, not return errno 14"
        );
        g.memory.seed(PATH, b"data");
        assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
        assert_eq!(
            g.call(nr::RECVFROM.raw(), blocking),
            DispatchOutcome::errno(LINUX_EFAULT),
            "data available: invalid addrlen returns errno 14"
        );
        assert_eq!(
            g.memory.read_bytes(OUT, 4).unwrap(),
            b"data",
            "Linux copies payload before the address fault"
        );
        assert_eq!(
            g.call(nr::RECVFROM.raw(), args),
            DispatchOutcome::errno(LINUX_EAGAIN),
            "the faulting receive consumed the payload"
        );
    }
}

#[test]
fn recvfrom_owner_reads_aliased_addrlen_after_payload() {
    for peek in [false, true] {
        for (initial, payload, expected) in [
            (u32::MAX, 0u32, DispatchOutcome::Returned { value: 4 }),
            (0, u32::MAX, DispatchOutcome::errno(LINUX_EINVAL)),
        ] {
            let mut g = Guest::new();
            let (left, right) = g.stream_pair();
            g.memory.seed(OUT, &initial.to_ne_bytes());
            g.memory.seed(PATH, &payload.to_ne_bytes());
            assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
            let flags = LinuxMsgFlags::DONTWAIT
                | if peek {
                    LinuxMsgFlags::PEEK
                } else {
                    LinuxMsgFlags::empty()
                };
            let prepares = g.memory.prepares;
            assert_eq!(
                g.call(
                    nr::RECVFROM.raw(),
                    [left as u64, OUT, 4, flags.bits() as u64, OUT2, OUT]
                ),
                expected,
                "peek={peek}: use post-copyout addrlen, zero succeeds and 0xffffffff returns errno 22"
            );
            assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), payload.to_ne_bytes());
            assert_eq!(
                g.memory.prepares - prepares,
                if payload == 0 { 2 } else { 1 },
                "one payload prepare, plus one metadata prepare only after validation"
            );
            assert_eq!(
                g.call(
                    nr::RECVFROM.raw(),
                    [
                        left as u64,
                        OUT,
                        4,
                        LinuxMsgFlags::DONTWAIT.bits() as u64,
                        0,
                        0
                    ]
                ),
                if peek {
                    DispatchOutcome::Returned { value: 4 }
                } else {
                    DispatchOutcome::errno(LINUX_EAGAIN)
                },
                "MSG_PEEK retains payload; normal receive consumes it (errno 11)"
            );
        }
    }
}

#[test]
fn recvfrom_owner_resumes_address_without_replaying_payload() {
    for peek in [false, true] {
        let mut g = Guest::new();
        let (left, right) = g.stream_pair();
        g.memory.seed(PATH, &[0; 4]);
        assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
        g.memory.seed(OUT, &u32::MAX.to_ne_bytes());
        let wait = g.memory.refuse_next_read();
        let flags = LinuxMsgFlags::DONTWAIT
            | if peek {
                LinuxMsgFlags::PEEK
            } else {
                LinuxMsgFlags::empty()
            };
        let first = g.call(
            nr::RECVFROM.raw(),
            [left as u64, OUT, 4, flags.bits() as u64, OUT2, OUT],
        );
        let DispatchOutcome::OutputSuspended(first) = first else {
            panic!("address read must suspend after receiving: {first:?}");
        };
        assert_eq!(
            first.wait(),
            &carrick_guest_mem::MemoryReadWait::Owner(wait)
        );
        assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), [0; 4]);
        // Distinct queued bytes make a replay observable even for MSG_PEEK.
        g.memory.seed(PATH, b"next");
        assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
        let context = g.dispatcher.capture_one_task_context().unwrap();
        // Retain the read continuation across another read suspension.
        let wait = g.memory.refuse_next_read();
        let DispatchOutcome::OutputSuspended(second) = first
            .resume(
                &context,
                &mut g.memory,
                g.lease.as_ref().unwrap().task_state_authority().unwrap(),
            )
            .unwrap()
        else {
            panic!("address read must retain its continuation");
        };
        assert_eq!(
            second.wait(),
            &carrick_guest_mem::MemoryReadWait::Owner(wait)
        );
        let wait = g.memory.refuse_next();
        let DispatchOutcome::OutputSuspended(third) = second
            .resume(
                &context,
                &mut g.memory,
                g.lease.as_ref().unwrap().task_state_authority().unwrap(),
            )
            .unwrap()
        else {
            panic!("validated address write must retain its own phase");
        };
        assert_eq!(
            third.wait(),
            &carrick_guest_mem::MemoryReadWait::Owner(wait)
        );
        // Once validated, a write wait must not read the edited length again.
        g.memory.seed(OUT, &u32::MAX.to_ne_bytes());
        assert_eq!(
            third
                .resume(
                    &context,
                    &mut g.memory,
                    g.lease.as_ref().unwrap().task_state_authority().unwrap()
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), [0; 4]);
        let receive = [
            left as u64,
            OUT,
            4,
            LinuxMsgFlags::DONTWAIT.bits() as u64,
            0,
            0,
        ];
        if peek {
            assert_eq!(g.ok(nr::RECVFROM.raw(), receive), 4);
            assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), [0; 4]);
        }
        assert_eq!(g.ok(nr::RECVFROM.raw(), receive), 4);
        assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), b"next");
        assert_eq!(
            g.call(nr::RECVFROM.raw(), receive),
            DispatchOutcome::errno(LINUX_EAGAIN)
        );
    }
}

#[test]
fn readv_pipe_retains_intra_iovec_progress_and_bounds_preparation() {
    for length in [1usize, 4096, 8192] {
        let mut guest = Guest::new();
        let (reader, writer) = guest.pipe();
        let bytes: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        guest.memory.seed(PATH, &bytes);
        assert_eq!(
            guest.ok(
                nr::WRITE.raw(),
                [writer as u64, PATH, length as u64, 0, 0, 0]
            ),
            length as i64
        );
        let mut vector = OUT.to_ne_bytes().to_vec();
        vector.extend_from_slice(&(length as u64).to_ne_bytes());
        guest.memory.seed(LEN_ADDR, &vector);
        let before = guest.memory.prepares;
        let wait = guest
            .memory
            .refuse_after_prepares(if length > 4096 { 1 } else { 0 });
        let outcome = guest.call(nr::READV.raw(), [reader as u64, LEN_ADDR, 1, 0, 0, 0]);
        let DispatchOutcome::PipeReadSuspended(pending) = outcome else {
            panic!("retained read expected: {outcome:?}");
        };
        assert_eq!(
            pending.wait(),
            &carrick_guest_mem::MemoryReadWait::Owner(wait)
        );
        let context = guest.dispatcher.capture_one_task_context().unwrap();
        assert_eq!(
            pending.resume(&context, &mut guest.memory).unwrap(),
            DispatchOutcome::Returned {
                value: length as i64
            }
        );
        assert_eq!(guest.memory.read_bytes(OUT, length).unwrap(), bytes);
        assert_eq!(
            guest.memory.prepares - before,
            length.div_ceil(4096) + 1,
            "one preparation per bounded window plus the refused admission"
        );
    }
}

#[test]
fn recvfrom_address_completion_rejects_wrong_task_before_memory_access() {
    let mut g = Guest::new();
    let (left, right) = g.stream_pair();
    g.memory.seed(PATH, b"data");
    assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    g.memory.refuse_after_prepares(1);
    let first = g.call(nr::RECVFROM.raw(), [left as u64, OUT, 4, 0, OUT2, LEN_ADDR]);
    let DispatchOutcome::OutputSuspended(pending) = first else {
        panic!("metadata must suspend: {first:?}");
    };
    assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), b"data");
    let mut successor = Guest::new();
    successor.memory.seed(LEN_ADDR, &[0xa5; 4]);
    let context = successor.dispatcher.capture_one_task_context().unwrap();
    let before = successor.memory.prepares;
    let reads = successor.memory.reads.get();
    let resumes = successor.memory.resumes.get();
    let commits = successor.memory.commits.len();
    let result = pending.resume(
        &context,
        &mut successor.memory,
        successor
            .lease
            .as_ref()
            .unwrap()
            .task_state_authority()
            .unwrap(),
    );
    let successor_addrlen = successor.memory.inner.read_bytes(LEN_ADDR, 4).unwrap();
    assert_eq!(
        successor_addrlen, [0xa5; 4],
        "stale recvfrom completion wrote another task's addrlen"
    );
    assert_eq!(successor.memory.prepares, before);
    assert_eq!(successor.memory.reads.get(), reads);
    assert_eq!(successor.memory.resumes.get(), resumes);
    assert_eq!(successor.memory.commits.len(), commits);
    assert!(result.is_err());
}

impl Drop for Guest {
    fn drop(&mut self) {
        let context = self.dispatcher.capture_one_task_context().unwrap();
        if let Some(lease) = self.lease.take() {
            context.thread().yield_from_executor(lease).unwrap();
        }
    }
}

fn suspended_address(
    g: &mut Guest,
    read_phase: bool,
    address: u64,
) -> Box<crate::kernel::continuation::output::SuspendedOutputCompletion> {
    let (left, right) = g.stream_pair();
    g.memory.seed(PATH, b"data");
    assert_eq!(g.ok(nr::WRITE.raw(), [right as u64, PATH, 4, 0, 0, 0]), 4);
    g.memory.seed(address, &4u32.to_ne_bytes());
    if read_phase {
        g.memory.refuse_next_read();
    } else {
        g.memory.refuse_after_prepares(1);
    }
    let outcome = g.call(nr::RECVFROM.raw(), [left as u64, OUT, 4, 0, OUT2, address]);
    let DispatchOutcome::OutputSuspended(pending) = outcome else {
        panic!("address completion must suspend: {outcome:?}")
    };
    assert_eq!(g.memory.inner.read_bytes(OUT, 4).unwrap(), b"data");
    pending
}

#[test]
fn recvfrom_address_stale_read_write_and_cancellation_access_no_memory() {
    use crate::kernel::continuation::CompletionFoldError;
    for read_phase in [false, true] {
        for failure in 0..4 {
            let mut g = Guest::new();
            let pending = suspended_address(&mut g, read_phase, LEN_ADDR);
            let context = g.dispatcher.capture_one_task_context().unwrap();
            let mut other = Guest::new();
            let other_context = other.dispatcher.capture_one_task_context().unwrap();
            let mm = g.lease.as_ref().unwrap().task_state_authority().unwrap();
            if failure >= 2 {
                use carrick_el1_abi::Lifecycle;
                context
                    .lifecycle_page()
                    .process_exit_custody()
                    .cancellation_authority()
                    .publish(
                        if failure == 2 {
                            carrick_core::cancellation::ProcessCancellation::GroupExit
                        } else {
                            carrick_core::cancellation::ProcessCancellation::FatalSignal
                        },
                        || panic!("no output effects across suspension"),
                    );
            }
            let (target, memory, identity) = if failure == 0 {
                (
                    &other_context,
                    &mut other.memory,
                    other
                        .lease
                        .as_ref()
                        .unwrap()
                        .task_state_authority()
                        .unwrap(),
                )
            } else {
                (
                    &context,
                    &mut g.memory,
                    if failure == 1 { (mm.0, mm.1 + 1) } else { mm },
                )
            };
            let before = (
                memory.reads.get(),
                memory.resumes.get(),
                memory.prepares,
                memory.commits.len(),
            );
            let bytes = memory.inner.read_bytes(LEN_ADDR, 4).unwrap();
            let result = pending.resume(target, memory, identity);
            assert_eq!(memory.inner.read_bytes(LEN_ADDR, 4).unwrap(), bytes);
            assert_eq!(
                (
                    memory.reads.get(),
                    memory.resumes.get(),
                    memory.prepares,
                    memory.commits.len()
                ),
                before,
                "read_phase={read_phase}, failure={failure}: rejection cannot touch memory"
            );
            match failure {
                0 => assert!(result.is_err()),
                1 => assert_eq!(result.unwrap_err(), CompletionFoldError::AddressSpace),
                _ => assert!(matches!(
                    result.unwrap(),
                    DispatchOutcome::OwnerCancelled(_)
                )),
            }
        }
    }
}

#[test]
fn recvfrom_address_write_is_one_unit_even_across_page_boundary() {
    for address in [LEN_ADDR, BASE + 0xfff] {
        let mut g = Guest::new();
        let pending = suspended_address(&mut g, false, address);
        assert_eq!(g.memory.prepares, 2, "payload and refused metadata");
        assert_eq!(g.memory.commits, [(OUT, b"data".to_vec())]);
        let before_reads = g.memory.reads.get();
        // Validation is frozen; retry must not inspect a subsequent negative edit.
        g.memory.seed(address, &u32::MAX.to_ne_bytes());
        let context = g.dispatcher.capture_one_task_context().unwrap();
        assert_eq!(
            pending
                .resume(
                    &context,
                    &mut g.memory,
                    g.lease.as_ref().unwrap().task_state_authority().unwrap()
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 4 }
        );
        assert_eq!(g.memory.prepares, 3);
        assert_eq!(g.memory.reads.get(), before_reads);
        assert_eq!(
            g.memory.commits,
            [(OUT, b"data".to_vec()), (address, vec![0; 4])]
        );
    }
}

#[test]
fn recvfrom_retained_output_requires_lease_and_leaves_sendto_unchanged() {
    let args = SyscallArgs::from([0; 6]);
    assert!(syscall_requires_execution_lease(nr::RECVFROM.raw(), args));
    assert!(!syscall_requires_execution_lease(nr::SENDTO.raw(), args));
}
