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
    LINUX_AF_INET, LINUX_AF_UNIX, LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LINUX_O_DIRECTORY,
    LINUX_SO_TYPE, LINUX_SOCK_STREAM, LINUX_SOL_SOCKET,
};
use carrick_guest_mem::GuestMemory;

const BASE: u64 = 0x4000_0000;
const LEN: usize = 0x4000;
const FILL: u8 = 0xa5;
const OUT: u64 = BASE + 0x100;
const OUT2: u64 = BASE + 0x800;
const LEN_ADDR: u64 = BASE + 0x40;
const PATH: u64 = BASE + 0x2000;

struct Guest {
    dispatcher: SyscallDispatcher,
    reporter: CompatReporter,
    memory: OwnerRefusingMemory,
}

impl Guest {
    fn new() -> Self {
        Self {
            dispatcher: SyscallDispatcher::new(),
            reporter: CompatReporter::default(),
            memory: OwnerRefusingMemory::new(BASE, LEN, FILL),
        }
    }

    fn call(&mut self, number: u64, args: [u64; 6]) -> DispatchOutcome {
        let context = self.dispatcher.capture_one_task_context().unwrap();
        self.dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                &mut self.memory,
                &self.reporter,
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
        let request = SyscallRequest::new(number, SyscallArgs::from(args));
        let refused = self.call(number, args);
        let retained = if let DispatchOutcome::CopyoutSuspended(pending) = refused {
            let (refused, operation) = (*pending).into_parts();
            assert_eq!(
                refused,
                DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
                "syscall {number}: retained copyout has the exact owner wait",
            );
            Some(operation)
        } else {
            assert_eq!(
                refused,
                DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
                "syscall {number}: a transient owner refusal is a wait, not EFAULT",
            );
            None
        };
        for &(address, len) in untouched {
            assert_eq!(
                self.memory.read_bytes(address, len).unwrap(),
                vec![FILL; len],
                "syscall {number}: nothing is written before the retry",
            );
        }
        if let Some(operation) = retained {
            let context = self.dispatcher.capture_one_task_context().unwrap();
            self.dispatcher
                .resume_owned_copyout(&context, request, operation, &mut self.memory)
                .expect("resume retained copyout")
        } else {
            self.call(number, args)
        }
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

    fn seed_path(&mut self, path: &str) {
        self.memory.seed(PATH, format!("{path}\0").as_bytes());
    }

    fn retained_refusal(
        &mut self,
        number: u64,
        args: [u64; 6],
        wait: carrick_el1_abi::PortalOwnerWait,
    ) -> OwnedCopyoutOperation {
        let DispatchOutcome::CopyoutSuspended(pending) = self.call(number, args) else {
            panic!("syscall {number} did not retain its copyout");
        };
        let (outcome, operation) = (*pending).into_parts();
        assert_eq!(
            outcome,
            DispatchOutcome::OwnerMemoryWait { wait, committed: 0 }
        );
        operation
    }

    fn resume_retained(
        &mut self,
        number: u64,
        args: [u64; 6],
        operation: OwnedCopyoutOperation,
    ) -> DispatchOutcome {
        let context = self.dispatcher.capture_one_task_context().unwrap();
        self.dispatcher
            .resume_owned_copyout(
                &context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                operation,
                &mut self.memory,
            )
            .unwrap()
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

#[test]
fn getdents64_waits_for_an_owner_refused_copyout_without_consuming_entries() {
    let mut g = Guest::new();
    g.seed_path("/proc/self/fd");
    let dir = g.ok(
        nr::OPENAT.raw(),
        [LINUX_AT_FDCWD, PATH, LINUX_O_DIRECTORY, 0, 0, 0],
    );
    let retried = g.refused_then_retried(
        nr::GETDENTS64.raw(),
        [dir as u64, OUT, 0x1000, 0, 0, 0],
        &[(OUT, 0x40)],
    );
    let DispatchOutcome::Returned { value } = retried else {
        panic!("getdents64 retry: {retried:?}");
    };
    assert!(value > 0, "the refused attempt consumed no entries");
    // The first record of the retried batch is still ".": the refusal did
    // not advance the directory offset.
    let first = g.memory.read_bytes(OUT, 24).unwrap();
    assert_eq!(&first[19..21], b".\0");
}

#[test]
fn getdents64_retained_copyout_ignores_numeric_fd_reuse() {
    let mut g = Guest::new();
    let root = g.dispatcher.capture_one_task_context().unwrap();
    let sibling = root
        .kernel()
        .clone_thread(
            &root,
            crate::kernel::ClonePlan::from_flags(
                carrick_abi::LinuxCloneFlags::VM
                    | carrick_abi::LinuxCloneFlags::SIGHAND
                    | carrick_abi::LinuxCloneFlags::FILES
                    | carrick_abi::LinuxCloneFlags::THREAD,
            )
            .unwrap(),
            carrick_hal::ThreadId::synthetic_for_tests(71_102),
            None,
        )
        .unwrap();
    assert!(root.exact_thread_is_live() && sibling.exact_thread_is_live());
    g.seed_path("/proc/self/fd");
    let dir = g.ok(
        nr::OPENAT.raw(),
        [LINUX_AT_FDCWD, PATH, LINUX_O_DIRECTORY, 0, 0, 0],
    );
    let args = [dir as u64, OUT, 0x1000, 0, 0, 0];
    let wait = g.memory.refuse_next();
    let operation = g.retained_refusal(nr::GETDENTS64.raw(), args, wait);
    let close = g
        .dispatcher
        .dispatch(
            &sibling,
            SyscallRequest::new(
                nr::CLOSE.raw(),
                SyscallArgs::from([dir as u64, 0, 0, 0, 0, 0]),
            ),
            &mut g.memory,
            &g.reporter,
        )
        .unwrap();
    assert_eq!(close, DispatchOutcome::Returned { value: 0 });
    g.seed_path("/proc/self/fdinfo");
    let DispatchOutcome::Returned { value: replacement } = g
        .dispatcher
        .dispatch(
            &sibling,
            SyscallRequest::new(
                nr::OPENAT.raw(),
                SyscallArgs::from([LINUX_AT_FDCWD, PATH, LINUX_O_DIRECTORY, 0, 0, 0]),
            ),
            &mut g.memory,
            &g.reporter,
        )
        .unwrap()
    else {
        panic!("sibling replacement open failed");
    };
    assert_eq!(replacement, dir, "the sibling action really reused the fd");
    let DispatchOutcome::Returned { value } =
        g.resume_retained(nr::GETDENTS64.raw(), args, operation)
    else {
        panic!("retained getdents did not complete");
    };
    assert!(value > 0);
    assert_eq!(&g.memory.read_bytes(OUT, 21).unwrap()[19..21], b".\0");

    g.memory.seed(OUT, &[FILL; 64]);
    let replacement_read = g.call(nr::GETDENTS64.raw(), args);
    assert!(matches!(replacement_read, DispatchOutcome::Returned { value } if value > 0));
    assert_eq!(
        &g.memory.read_bytes(OUT, 21).unwrap()[19..21],
        b".\0",
        "the retained operation did not advance the replacement description"
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
fn getsockopt_waits_for_an_owner_refused_copyout_instead_of_efault() {
    let mut g = Guest::new();
    let (left, _) = socketpair(&mut g);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    let retried = g.refused_then_retried(
        nr::GETSOCKOPT.raw(),
        [
            left as u64,
            LINUX_SOL_SOCKET as u64,
            LINUX_SO_TYPE as u64,
            OUT,
            LEN_ADDR,
            0,
        ],
        &[(OUT, 4)],
    );
    assert_eq!(retried, DispatchOutcome::Returned { value: 0 });
    assert_eq!(
        g.memory.read_bytes(OUT, 4).unwrap(),
        (LINUX_SOCK_STREAM as i32).to_ne_bytes()
    );
    assert_eq!(
        g.memory.read_bytes(LEN_ADDR, 4).unwrap(),
        4u32.to_ne_bytes()
    );
}

#[test]
fn accept_owns_the_dequeued_connection_across_an_owner_refusal() {
    let mut g = Guest::new();
    let socket = |g: &mut Guest| {
        g.ok(
            nr::SOCKET.raw(),
            [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
        )
    };
    let sockaddr = |port: u16| {
        let mut sa = Vec::with_capacity(16);
        sa.extend_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sa.extend_from_slice(&port.to_be_bytes());
        sa.extend_from_slice(&[127, 0, 0, 1]);
        sa.extend_from_slice(&[0u8; 8]);
        sa
    };
    let listener = socket(&mut g);
    g.memory.seed(OUT, &sockaddr(0));
    assert_eq!(g.ok(nr::BIND.raw(), [listener as u64, OUT, 16, 0, 0, 0]), 0);
    assert_eq!(g.ok(nr::LISTEN.raw(), [listener as u64, 16, 0, 0, 0, 0]), 0);
    g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
    assert_eq!(
        g.ok(
            nr::GETSOCKNAME.raw(),
            [listener as u64, OUT, LEN_ADDR, 0, 0, 0]
        ),
        0
    );
    let port = u16::from_be_bytes(g.memory.read_bytes(OUT + 2, 2).unwrap().try_into().unwrap());
    let client = socket(&mut g);
    g.memory.seed(OUT, &sockaddr(port));
    assert_eq!(
        g.ok(nr::CONNECT.raw(), [client as u64, OUT, 16, 0, 0, 0]),
        0
    );

    g.memory.seed(OUT, &[FILL; 16]);
    g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
    let next_fd = client + 1;
    let wait = g.memory.refuse_next();
    let args = [listener as u64, OUT, LEN_ADDR, 0, 0, 0];
    let operation = g.retained_refusal(nr::ACCEPT.raw(), args, wait);
    assert!(
        g.dispatcher.open_file(next_fd as i32).is_none(),
        "the refused accept installs nothing",
    );
    assert_eq!(g.memory.read_bytes(OUT, 16).unwrap(), [FILL; 16]);
    let DispatchOutcome::Returned { value: accepted } =
        g.resume_retained(nr::ACCEPT.raw(), args, operation)
    else {
        panic!("retained accept did not complete");
    };
    assert_eq!(
        accepted, next_fd,
        "the queued connection survived the refusal"
    );
    let family = u16::from_ne_bytes(g.memory.read_bytes(OUT, 2).unwrap().try_into().unwrap());
    assert_eq!(family, LINUX_AF_INET as u16);
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

/// A guest-sized getdents64 `count` (u32::MAX) over a listing larger than one
/// owner permit must return a batch on both venues, never reach the permit
/// bound's fatal: the legacy venue has no permit bound, and the owner venue
/// returns a short batch.
fn getdents_with_huge_count<M: carrick_guest_mem::CurrentMmMemory>(memory: &mut M) -> usize {
    let mut dispatcher = SyscallDispatcher::new();
    let reporter = CompatReporter::default();
    let call = |dispatcher: &mut SyscallDispatcher, memory: &mut M, number: u64, args| {
        let context = dispatcher.capture_one_task_context().unwrap();
        match dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                memory,
                &reporter,
            )
            .expect("dispatch")
        {
            DispatchOutcome::Returned { value } => value,
            other => panic!("syscall {number}: {other:?}"),
        }
    };
    // 400 pipes list 800+ `/proc/self/fd` entries: well over one 4 KiB permit.
    for _ in 0..400 {
        assert_eq!(
            call(
                &mut dispatcher,
                memory,
                nr::PIPE2.raw(),
                [OUT2, 0, 0, 0, 0, 0]
            ),
            0
        );
    }
    memory.write_bytes(PATH, b"/proc/self/fd\0").unwrap();
    let dir = call(
        &mut dispatcher,
        memory,
        nr::OPENAT.raw(),
        [LINUX_AT_FDCWD, PATH, LINUX_O_DIRECTORY, 0, 0, 0],
    );
    let returned = call(
        &mut dispatcher,
        memory,
        nr::GETDENTS64.raw(),
        [dir as u64, BASE, u64::from(u32::MAX), 0, 0, 0],
    );
    usize::try_from(returned).unwrap()
}

#[test]
fn getdents64_with_a_guest_sized_count_never_reaches_the_permit_fatal() {
    let mut legacy = LinearMemory::new(BASE, vec![0; 0x10_0000]);
    let legacy_batch = getdents_with_huge_count(&mut legacy);
    assert!(
        legacy_batch > super::copyout::COPYOUT_MAX_BYTES,
        "legacy keeps the caller's length: {legacy_batch}"
    );
    let mut owner = OwnerRefusingMemory::new(BASE, 0x10_0000, 0);
    let owner_batch = getdents_with_huge_count(&mut owner);
    assert!(
        owner_batch > 0 && owner_batch <= super::copyout::COPYOUT_MAX_BYTES,
        "owner returns a short batch: {owner_batch}"
    );
}

#[test]
fn later_invalid_output_retains_valid_prefix_in_gettimeofday_sockaddr_and_getsockopt() {
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

    // 3. getsockopt(valid optval, readonly optlen) -> EFAULT after writing optval
    // via `support::write_sockopt_value` (`SO_DOMAIN`), and also retains the
    // prefix write on `copyout_fixed_sockopt` (`SO_TYPE`).
    let ro_optlen_addr = BASE + 0x910;
    g.memory.seed(ro_optlen_addr, &4u32.to_ne_bytes());
    g.memory.protect_readonly(ro_optlen_addr, 4);
    g.memory.seed(OUT, &[FILL; 4]);
    assert_eq!(
        g.call(
            nr::GETSOCKOPT.raw(),
            [
                left as u64,
                LINUX_SOL_SOCKET as u64,
                carrick_abi::LINUX_SO_DOMAIN as u64,
                OUT,
                ro_optlen_addr,
                0,
            ],
        ),
        DispatchOutcome::errno(carrick_abi::LINUX_EFAULT),
    );
    assert_eq!(
        g.memory.read_bytes(OUT, 4).unwrap(),
        (LINUX_AF_UNIX as i32).to_ne_bytes(),
        "getsockopt(SO_DOMAIN) must commit valid optval before reporting EFAULT on readonly optlen",
    );
    g.memory.seed(OUT, &[FILL; 4]);
    assert_eq!(
        g.call(
            nr::GETSOCKOPT.raw(),
            [
                left as u64,
                LINUX_SOL_SOCKET as u64,
                LINUX_SO_TYPE as u64,
                OUT,
                ro_optlen_addr,
                0,
            ],
        ),
        DispatchOutcome::Returned { value: 0 },
    );
    assert_eq!(
        g.memory.read_bytes(OUT, 4).unwrap(),
        (LINUX_SOCK_STREAM as i32).to_ne_bytes(),
        "getsockopt(SO_TYPE) must still commit valid optval when optlen faults",
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
    let port = u16::from_be_bytes(
        g.memory
            .read_bytes(tail_v4 + 2, 2)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    // Connect and accept with the destination at the final 16 writable bytes
    // and `*addrlen = 128`.
    let client = g.ok(
        nr::SOCKET.raw(),
        [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    );
    g.memory.seed(OUT, &sockaddr_v4(port));
    assert_eq!(
        g.ok(nr::CONNECT.raw(), [client as u64, OUT, 16, 0, 0, 0]),
        0
    );
    g.memory.seed(tail_v4, &[FILL; 16]);
    g.memory.seed(LEN_ADDR, &128u32.to_ne_bytes());
    let accepted = g.ok(
        nr::ACCEPT.raw(),
        [v4_sock as u64, tail_v4, LEN_ADDR, 0, 0, 0],
    );
    assert!(accepted > client);
    assert_eq!(
        g.memory.read_bytes(LEN_ADDR, 4).unwrap(),
        16u32.to_ne_bytes()
    );
    let family = u16::from_ne_bytes(g.memory.read_bytes(tail_v4, 2).unwrap().try_into().unwrap());
    assert_eq!(family, LINUX_AF_INET as u16);

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
fn accept_and_getsockopt_preserve_read_suspension_on_length_pointer() {
    let mut g = Guest::new();
    let socket = |g: &mut Guest| {
        g.ok(
            nr::SOCKET.raw(),
            [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
        )
    };
    let sockaddr = |port: u16| {
        let mut sa = Vec::with_capacity(16);
        sa.extend_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sa.extend_from_slice(&port.to_be_bytes());
        sa.extend_from_slice(&[127, 0, 0, 1]);
        sa.extend_from_slice(&[0u8; 8]);
        sa
    };
    let listener = socket(&mut g);
    g.memory.seed(OUT, &sockaddr(0));
    assert_eq!(g.ok(nr::BIND.raw(), [listener as u64, OUT, 16, 0, 0, 0]), 0);
    assert_eq!(g.ok(nr::LISTEN.raw(), [listener as u64, 16, 0, 0, 0, 0]), 0);
    g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
    assert_eq!(
        g.ok(
            nr::GETSOCKNAME.raw(),
            [listener as u64, OUT, LEN_ADDR, 0, 0, 0]
        ),
        0
    );
    let port = u16::from_be_bytes(g.memory.read_bytes(OUT + 2, 2).unwrap().try_into().unwrap());
    let client = socket(&mut g);
    g.memory.seed(OUT, &sockaddr(port));
    assert_eq!(
        g.ok(nr::CONNECT.raw(), [client as u64, OUT, 16, 0, 0, 0]),
        0
    );

    // 1. Read suspension on `addrlen` before `accept` must park without dequeuing.
    g.memory.seed(OUT, &[FILL; 16]);
    g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
    let next_fd = client + 1;
    let wait = g.memory.refuse_next_read();
    let accept_args = [listener as u64, OUT, LEN_ADDR, 0, 0, 0];
    let operation = g.retained_refusal(nr::ACCEPT.raw(), accept_args, wait);
    assert!(
        g.dispatcher.open_file(next_fd as i32).is_none(),
        "read-suspended accept must not install an fd",
    );
    let DispatchOutcome::Returned { value: accepted } =
        g.resume_retained(nr::ACCEPT.raw(), accept_args, operation)
    else {
        panic!("retained accept did not complete");
    };
    assert_eq!(accepted, next_fd);

    // 2. Read suspension on `optlen` in `getsockopt` (`write_sockopt_value`) must park and retry cleanly.
    g.memory.seed(OUT, &[FILL; 4]);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    let wait = g.memory.refuse_next_read();
    assert_eq!(
        g.call(
            nr::GETSOCKOPT.raw(),
            [
                listener as u64,
                LINUX_SOL_SOCKET as u64,
                carrick_abi::LINUX_SO_DOMAIN as u64,
                OUT,
                LEN_ADDR,
                0,
            ],
        ),
        DispatchOutcome::OwnerMemoryWait { wait, committed: 0 },
        "read suspension on optlen must return OwnerMemoryWait, not EFAULT",
    );
    assert_eq!(
        g.ok(
            nr::GETSOCKOPT.raw(),
            [
                listener as u64,
                LINUX_SOL_SOCKET as u64,
                carrick_abi::LINUX_SO_DOMAIN as u64,
                OUT,
                LEN_ADDR,
                0,
            ],
        ),
        0
    );
    assert_eq!(
        g.memory.read_bytes(OUT, 4).unwrap(),
        (LINUX_AF_INET as i32).to_ne_bytes()
    );
}

#[test]
fn getsockopt_so_error_retains_pending_error_across_owner_refusal() {
    let mut g = Guest::new();
    let (host_sock, _) = socketpair(&mut g);

    // 1. HostSocket pending error (`take_socket_pending_error`) survives both
    //    read refusal on `optlen` and write refusal on `optval`/`optlen`.
    {
        let open_file = g.dispatcher.open_file(host_sock).unwrap();
        let mut desc =
            crate::kernel::FileDescription::write_for_io(&open_file.description).unwrap();
        let crate::dispatch::fd_table::OpenDescription::HostSocket { base, .. } = &mut *desc else {
            panic!("expected HostSocket");
        };
        base.set_pending_socket_error(carrick_abi::LINUX_ECONNREFUSED.get());
    }
    g.memory.seed(OUT, &[FILL; 4]);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    let args = [
        host_sock as u64,
        LINUX_SOL_SOCKET as u64,
        carrick_abi::LINUX_SO_ERROR as u64,
        OUT,
        LEN_ADDR,
        0,
    ];
    let wait = g.memory.refuse_next();
    let operation = g.retained_refusal(nr::GETSOCKOPT.raw(), args, wait);
    assert_eq!(g.memory.read_bytes(OUT, 4).unwrap(), [FILL; 4]);
    assert_eq!(
        g.resume_retained(nr::GETSOCKOPT.raw(), args, operation),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        carrick_abi::LINUX_ECONNREFUSED.get(),
        "SO_ERROR must survive transient refusals and be returned on the retry",
    );
    // Re-seed and also verify read suspension on `optlen` preserves SO_ERROR.
    {
        let open_file = g.dispatcher.open_file(host_sock).unwrap();
        let mut desc =
            crate::kernel::FileDescription::write_for_io(&open_file.description).unwrap();
        let crate::dispatch::fd_table::OpenDescription::HostSocket { base, .. } = &mut *desc else {
            panic!("expected HostSocket");
        };
        base.set_pending_socket_error(carrick_abi::LINUX_ECONNREFUSED.get());
    }
    g.memory.seed(OUT, &[FILL; 4]);
    let wait = g.memory.refuse_next_read();
    let operation = g.retained_refusal(nr::GETSOCKOPT.raw(), args, wait);
    assert_eq!(
        g.resume_retained(nr::GETSOCKOPT.raw(), args, operation),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        carrick_abi::LINUX_ECONNREFUSED.get(),
        "SO_ERROR must survive read suspension on optlen and be returned on the retry",
    );
    // Consumed once on completion: a subsequent read reports 0.
    assert_eq!(g.ok(nr::GETSOCKOPT.raw(), args), 0);
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        0,
    );

    // 2. InMemorySocket pending error (`socket.take_so_error()`) survives refusal too.
    let listener = g.ok(
        nr::SOCKET.raw(),
        [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    );
    let mut sa = vec![0u8; 16];
    sa[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    g.memory.seed(OUT, &sa);
    assert_eq!(g.ok(nr::BIND.raw(), [listener as u64, OUT, 16, 0, 0, 0]), 0);
    assert_eq!(g.ok(nr::LISTEN.raw(), [listener as u64, 16, 0, 0, 0, 0]), 0);
    g.memory.seed(LEN_ADDR, &16u32.to_ne_bytes());
    assert_eq!(
        g.ok(
            nr::GETSOCKNAME.raw(),
            [listener as u64, OUT, LEN_ADDR, 0, 0, 0]
        ),
        0
    );
    let port = u16::from_be_bytes(g.memory.read_bytes(OUT + 2, 2).unwrap().try_into().unwrap());
    let inmem_client = g.ok(
        nr::SOCKET.raw(),
        [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
    );
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    g.memory.seed(OUT, &sa);
    assert_eq!(
        g.ok(nr::CONNECT.raw(), [inmem_client as u64, OUT, 16, 0, 0, 0]),
        0
    );
    {
        let open_file = g.dispatcher.open_file(inmem_client as i32).unwrap();
        let desc = crate::kernel::FileDescription::inspect(&open_file.description).unwrap();
        let crate::dispatch::fd_table::OpenDescription::InMemorySocket { socket, .. } = &*desc
        else {
            panic!("expected InMemorySocket");
        };
        socket.set_so_error(carrick_abi::LINUX_EPIPE.get());
    }
    g.memory.seed(OUT, &[FILL; 4]);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    let inmem_args = [
        inmem_client as u64,
        LINUX_SOL_SOCKET as u64,
        carrick_abi::LINUX_SO_ERROR as u64,
        OUT,
        LEN_ADDR,
        0,
    ];
    let wait = g.memory.refuse_next();
    let operation = g.retained_refusal(nr::GETSOCKOPT.raw(), inmem_args, wait);
    assert_eq!(
        g.resume_retained(nr::GETSOCKOPT.raw(), inmem_args, operation),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        carrick_abi::LINUX_EPIPE.get(),
        "in-memory SO_ERROR must survive owner refusal and be returned on retry",
    );
    assert_eq!(g.ok(nr::GETSOCKOPT.raw(), inmem_args), 0);
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        0,
    );
}

#[test]
fn getsockopt_so_error_retained_copyout_ignores_numeric_fd_reuse() {
    let mut g = Guest::new();
    let (socket, peer) = socketpair(&mut g);
    let open_file = g.dispatcher.open_file(socket).unwrap();
    let mut desc = crate::kernel::FileDescription::write_for_io(&open_file.description).unwrap();
    let crate::dispatch::fd_table::OpenDescription::HostSocket { base, .. } = &mut *desc else {
        panic!("expected HostSocket");
    };
    base.set_pending_socket_error(carrick_abi::LINUX_ECONNREFUSED.get());
    drop(desc);
    g.memory.seed(OUT, &[FILL; 4]);
    g.memory.seed(LEN_ADDR, &4u32.to_ne_bytes());
    let args = [
        socket as u64,
        LINUX_SOL_SOCKET as u64,
        carrick_abi::LINUX_SO_ERROR as u64,
        OUT,
        LEN_ADDR,
        0,
    ];
    let wait = g.memory.refuse_next();
    let operation = g.retained_refusal(nr::GETSOCKOPT.raw(), args, wait);
    assert_eq!(g.ok(nr::CLOSE.raw(), [socket as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(g.ok(nr::CLOSE.raw(), [peer as u64, 0, 0, 0, 0, 0]), 0);
    let (replacement, _) = g.pipe();
    assert_eq!(replacement, socket, "the fd number was genuinely reused");
    assert_eq!(
        g.resume_retained(nr::GETSOCKOPT.raw(), args, operation),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        i32::from_ne_bytes(g.memory.read_bytes(OUT, 4).unwrap().try_into().unwrap()),
        carrick_abi::LINUX_ECONNREFUSED.get(),
    );
    assert!(g.dispatcher.open_file(replacement).is_some());
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
