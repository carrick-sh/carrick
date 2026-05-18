use carrick::compat::{CompatReporter, SyscallArgs};
use carrick::dispatch::{
    Aarch64SyscallFrame, DispatchOutcome, GuestMemory, LinearMemory, SyscallDispatcher,
    SyscallRequest,
};
use carrick::elf::SegmentPerms;
use carrick::linux_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_REG, LINUX_S_IFDIR, LINUX_S_IFMT, LINUX_S_IFREG,
    LinuxCapabilityData, LinuxCapabilityHeader, LinuxDirent64Header, LinuxEpollEvent,
    LinuxEventfdValue, LinuxFdPair, LinuxIovec, LinuxItimerspec, LinuxPollFd, LinuxRlimit,
    LinuxStat, LinuxStatfs, LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimezone,
    LinuxUtsname, LinuxWinsize,
};
use carrick::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE};
use carrick::rootfs::{LayerSource, RootFs};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use zerocopy::{FromBytes, IntoBytes};

const LINUX_F_DUPFD: u64 = 0;
const LINUX_F_GETFD: u64 = 1;
const LINUX_F_SETFD: u64 = 2;
const LINUX_F_GETFL: u64 = 3;
const LINUX_FD_CLOEXEC: u64 = 1;
const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
const LINUX_F_GETPIPE_SZ: u64 = 1032;
const LINUX_O_CLOEXEC: u64 = 0o2000000;
const LINUX_O_NONBLOCK: u64 = 0o4000;
const LINUX_OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_EPOLL_CTL_ADD: u64 = 1;
const LINUX_EPOLLIN: u32 = 0x001;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
const LINUX_ADDR_NO_RANDOMIZE: u64 = 0x0040_0000;
const LINUX_POLLIN: i16 = 0x0001;
const LINUX_POLLOUT: i16 = 0x0004;
const LINUX_POLLNVAL: i16 = 0x0020;
const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_TIOCGWINSZ: u64 = 0x5413;

#[test]
fn write_syscall_reads_guest_memory_and_writes_stdout() {
    let mut memory = LinearMemory::new(0x4000, b"hello from linux\n".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 17 });
    assert_eq!(dispatcher.stdout(), b"hello from linux\n");
    assert!(dispatcher.stderr().is_empty());

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
}

#[test]
fn write_syscall_rejects_bad_guest_pointer_with_efault() {
    let mut memory = LinearMemory::new(0x4000, b"short".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x5000, 5, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 14 });
    assert!(dispatcher.stdout().is_empty());
}

#[test]
fn exit_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(93, SyscallArgs::from([42, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 42 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn exit_group_syscall_requests_process_exit() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(94, SyscallArgs::from([7, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Exit { code: 7 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn unknown_syscall_returns_enosys_and_records_report_entry() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(9999, SyscallArgs::from([1, 2, 3, 4, 5, 6])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 38 });
    let report = reporter.finish();
    assert_eq!(report.unhandled_syscalls[0].number, 9999);
    assert_eq!(report.unhandled_syscalls[0].name, "unknown");
    assert_eq!(report.unhandled_syscalls[0].count, 1);
}

#[test]
fn ioctl_writes_packed_winsize_and_reports_unknown_requests() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([1, LINUX_TIOCGWINSZ, 0x4000, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let winsize = read_winsize(&memory, 0x4000);
    let rows = winsize.ws_row;
    let cols = winsize.ws_col;
    assert_eq!(rows, 24);
    assert_eq!(cols, 80);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, 0xdead_beef, 0x4040, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.unhandled_ioctls[0].request, 0xdead_beef);
    assert_eq!(report.unhandled_ioctls[0].count, 1);
}

#[test]
fn eventfd2_read_write_round_trip_uses_packed_counter() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([7, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let value = read_eventfd_value(&memory, 0x4000).value;
    assert_eq!(value, 7);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    memory
        .write_bytes(0x4010, LinuxEventfdValue { value: 5 }.as_bytes())
        .unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4010, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4020, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let value = read_eventfd_value(&memory, 0x4020).value;
    assert_eq!(value, 5);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pipe2_writes_packed_fd_pair_and_round_trips_bytes() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    let write_fd = pair.write_fd as u64;
    assert_eq!(read_fd, 3);
    assert_eq!(write_fd, 4);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([read_fd, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([read_fd, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_O_NONBLOCK as i64
        }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    memory.write_bytes(0x4040, b"pipe data").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([write_fd, 0x4040, 9, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 32, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(memory.read_bytes(0x4080, 9).unwrap(), b"pipe data");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pipe2_duplicate_writer_keeps_pipe_open_until_all_writers_close() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    let read_fd = pair.read_fd as u64;
    let write_fd = pair.write_fd as u64;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(23, SyscallArgs::from([write_fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([write_fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([5, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_getpipe_size_reports_bootstrap_pipe_capacity() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([pair.read_fd as u64, LINUX_F_GETPIPE_SZ, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 65536 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_settime_read_round_trip_uses_packed_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_O_NONBLOCK as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );

    let one_shot = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    memory.write_bytes(0x4000, one_shot.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4000, 0x4080, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let old = read_itimerspec(&memory, 0x4080);
    let old_value_sec = old.it_value.tv_sec;
    let old_value_nsec = old.it_value.tv_nsec;
    assert_eq!(old_value_sec, 0);
    assert_eq!(old_value_nsec, 0);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    let expirations = read_timerfd_expirations(&memory, 0x4100).expirations;
    assert!(expirations >= 1);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_gettime_writes_packed_itimerspec_for_armed_timer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    let armed = LinuxItimerspec {
        it_interval: LinuxTimespec::new(2, 0),
        it_value: LinuxTimespec::new(5, 0),
    };
    memory.write_bytes(0x4000, armed.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4000, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(87, SyscallArgs::from([3, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let current = read_itimerspec(&memory, 0x4080);
    let interval_sec = current.it_interval.tv_sec;
    let remaining_sec = current.it_value.tv_sec;
    assert_eq!(interval_sec, 2);
    assert!((0..=5).contains(&remaining_sec));
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_reports_timerfd_readiness_with_packed_event() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        data: 0x544d,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let one_shot = LinuxItimerspec {
        it_interval: LinuxTimespec::new(0, 0),
        it_value: LinuxTimespec::new(0, 1),
    };
    memory.write_bytes(0x4040, one_shot.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(86, SyscallArgs::from([3, 0, 0x4040, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let ready = read_epoll_event(&memory, 0x4100);
    let data = ready.data;
    assert_eq!(data, 0x544d);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_reports_eventfd_readiness_with_packed_events() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let wanted = LinuxEpollEvent {
        events: LINUX_EPOLLIN,
        data: 0xabc,
    };
    memory.write_bytes(0x4000, wanted.as_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([4, LINUX_EPOLL_CTL_ADD, 3, 0x4000, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    let ready = read_epoll_event(&memory, 0x4100);
    let events = ready.events;
    let data = ready.data;
    assert_eq!(events & LINUX_EPOLLIN, LINUX_EPOLLIN);
    assert_eq!(data, 0xabc);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ppoll_reports_eventfd_pipe_and_invalid_fd_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    memory.write_bytes(0x4080, b"x").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([pair.write_fd as u64, 0x4080, 1, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    write_pollfds(
        &mut memory,
        0x4100,
        [
            LinuxPollFd {
                fd: 3,
                events: LINUX_POLLIN,
                revents: 0,
            },
            LinuxPollFd {
                fd: pair.read_fd,
                events: LINUX_POLLIN,
                revents: 0,
            },
            LinuxPollFd {
                fd: pair.write_fd,
                events: LINUX_POLLOUT,
                revents: 0,
            },
            LinuxPollFd {
                fd: 99,
                events: LINUX_POLLIN,
                revents: 0,
            },
        ],
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(73, SyscallArgs::from([0x4100, 4, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );

    let pollfds = read_pollfds(&memory, 0x4100, 4);
    assert_eq!(pollfds[0].2 & LINUX_POLLIN, LINUX_POLLIN);
    assert_eq!(pollfds[1].2 & LINUX_POLLIN, LINUX_POLLIN);
    assert_eq!(pollfds[2].2 & LINUX_POLLOUT, LINUX_POLLOUT);
    assert_eq!(pollfds[3].2, LINUX_POLLNVAL);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pselect6_reports_eventfd_pipe_and_write_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4000);
    memory.write_bytes(0x4080, b"x").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    64,
                    SyscallArgs::from([pair.write_fd as u64, 0x4080, 1, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );

    let nfds = (pair.write_fd + 1) as usize;
    write_fd_set(&mut memory, 0x4100, nfds, [3, pair.read_fd]);
    write_fd_set(&mut memory, 0x4200, nfds, [pair.write_fd]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    72,
                    SyscallArgs::from([nfds as u64, 0x4100, 0x4200, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    assert_eq!(read_fd_set(&memory, 0x4100, nfds), vec![3, pair.read_fd]);
    assert_eq!(read_fd_set(&memory, 0x4200, nfds), vec![pair.write_fd]);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn pselect6_invalid_fd_returns_ebadf() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    write_fd_set(&mut memory, 0x4100, 100, [99]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(72, SyscallArgs::from([100, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn syscall_request_can_be_built_from_aarch64_register_frame() {
    let frame = Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 17,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    };

    assert_eq!(
        SyscallRequest::from_aarch64_frame(frame),
        SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 17, 0, 0, 0]))
    );
}

#[test]
fn linear_memory_bounds_reads() {
    let mut memory = LinearMemory::new(0x1000, b"abcdef".to_vec());

    assert_eq!(memory.read_bytes(0x1002, 3).unwrap(), b"cde");
    assert!(memory.read_bytes(0x1004, 3).is_err());
    memory.write_bytes(0x1001, b"XY").unwrap();
    assert_eq!(memory.read_bytes(0x1000, 4).unwrap(), b"aXYd");
    assert!(memory.write_bytes(0x1005, b"YZ").is_err());
}

#[test]
fn openat_read_close_round_trip_through_rootfs_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(opened, DispatchOutcome::Returned { value: 3 });

    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 18 });
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    let closed = dispatcher
        .dispatch(
            SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_missing_rootfs_file_returns_enoent() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, b"/missing\0".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn cwd_and_access_syscalls_use_rootfs_state() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    memory.write_bytes(0x4010, b"motd\0").unwrap();
    memory.write_bytes(0x4020, b"/\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0x4100 }
    );
    assert_eq!(memory.read_bytes(0x4100, 2).unwrap(), b"/\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(17, SyscallArgs::from([0x4100, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0x4100 }
    );
    assert_eq!(memory.read_bytes(0x4100, 5).unwrap(), b"/etc\0");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 4, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    48,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 2, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 13 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4010, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 64, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 18 }
    );
    assert_eq!(
        memory.read_bytes(0x4200, 18).unwrap(),
        b"rootfs says hello\n"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(49, SyscallArgs::from([0x4020, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(50, SyscallArgs::from([4, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(dispatcher.cwd(), "/etc");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn statfs_writes_packed_linux_statfs_for_rootfs_path() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(43, SyscallArgs::from([0x4000, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let block_size = statfs.f_bsize;
    let name_len = statfs.f_namelen;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert_eq!(block_size, 4096);
    assert!(name_len >= 255);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fstatfs_writes_packed_linux_statfs_for_open_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(44, SyscallArgs::from([3, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let statfs = read_statfs(&memory, 0x4100);
    let fs_type = statfs.f_type;
    let free_blocks = statfs.f_bfree;
    assert_eq!(fs_type, LINUX_OVERLAYFS_SUPER_MAGIC);
    assert!(free_blocks > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn lseek_repositions_rootfs_file_reads() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(62, SyscallArgs::from([3, 7, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 7 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"says");
}

#[test]
fn pread64_reads_from_offset_without_changing_file_offset() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(67, SyscallArgs::from([3, 0x4100, 4, 7, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"says");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"root");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sendfile_copies_rootfs_file_to_stdout_and_updates_offset_pointer() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_u64(&mut memory, 0x4100, 7);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(71, SyscallArgs::from([1, 3, 0x4100, 4, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(dispatcher.stdout(), b"says");
    assert_eq!(read_u64(&memory, 0x4100), 11);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"root");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn sendfile_without_offset_pointer_advances_file_offset_and_writes_pipe() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4100, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let pair = read_fd_pair(&memory, 0x4100);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(71, SyscallArgs::from([pair.write_fd as u64, 3, 0, 6, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 6 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    63,
                    SyscallArgs::from([pair.read_fd as u64, 0x4200, 6, 0, 0, 0])
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 6 }
    );
    assert_eq!(memory.read_bytes(0x4200, 6).unwrap(), b"rootfs");
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4300, 1, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(memory.read_bytes(0x4300, 1).unwrap(), b" ");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readv_reads_file_across_packed_iovecs() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 6), LinuxIovec::new(0x4300, 4)],
    );
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(65, SyscallArgs::from([3, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 10 }
    );
    assert_eq!(memory.read_bytes(0x4200, 6).unwrap(), b"rootfs");
    assert_eq!(memory.read_bytes(0x4300, 4).unwrap(), b" say");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn dup_shares_rootfs_file_offset_with_original_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(23, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([4, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"root");
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"fs s");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn dup3_installs_requested_fd_and_cloexec_is_per_descriptor() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(24, SyscallArgs::from([3, 9, LINUX_O_CLOEXEC, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([9, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_gets_and_sets_descriptor_and_status_flags() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_O_CLOEXEC, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_SETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([3, LINUX_F_DUPFD_CLOEXEC, 8, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([8, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_DUPFD, 8, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn writev_writes_stdout_from_packed_iovecs() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4200, b"hello ").unwrap();
    memory.write_bytes(0x4300, b"linux\n").unwrap();
    write_iovecs(
        &mut memory,
        0x4100,
        [LinuxIovec::new(0x4200, 6), LinuxIovec::new(0x4300, 6)],
    );
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(66, SyscallArgs::from([1, 0x4100, 2, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 12 }
    );
    assert_eq!(dispatcher.stdout(), b"hello linux\n");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readlinkat_reads_rootfs_symlink_target_without_nul() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar_with_links(
        [("lib/ld-musl-aarch64.so.1", b"loader".as_slice())],
        [("lib/ld-linux-aarch64.so.1", "ld-musl-aarch64.so.1")],
    ))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory
        .write_bytes(0x4000, b"/lib/ld-linux-aarch64.so.1\0")
        .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    let target = b"ld-musl-aarch64.so.1";
    assert_eq!(
        outcome,
        DispatchOutcome::Returned {
            value: target.len() as i64
        }
    );
    assert_eq!(memory.read_bytes(0x4100, target.len()).unwrap(), target);
    assert_eq!(
        memory.read_bytes(0x4100 + target.len() as u64, 1).unwrap(),
        [0xff]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn readlinkat_reports_synthetic_proc_self_exe() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "bin/app",
        b"app".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    memory.write_bytes(0x4000, b"/proc/self/exe\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs_and_executable(rootfs, "/bin/app");

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                78,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 64, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Returned { value: 8 });
    assert_eq!(memory.read_bytes(0x4100, 8).unwrap(), b"/bin/app");
    assert_eq!(memory.read_bytes(0x4108, 1).unwrap(), [0xff]);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_reads_synthetic_proc_maps_and_cpuinfo() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/self/maps\0").unwrap();
    memory.write_bytes(0x4040, b"/proc/cpuinfo\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    let maps_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 0x400, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: maps_len } = maps_read else {
        panic!("expected /proc/self/maps read success, got {maps_read:?}");
    };
    let maps = String::from_utf8(memory.read_bytes(0x4100, maps_len as usize).unwrap()).unwrap();
    assert!(maps.contains(" r-xp "));
    assert!(maps.contains("/proc/self/exe"));
    assert!(maps.contains("[heap]"));
    assert!(maps.ends_with('\n'));

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    let cpuinfo_read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([4, 0x4500, 0x200, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value: cpuinfo_len } = cpuinfo_read else {
        panic!("expected /proc/cpuinfo read success, got {cpuinfo_read:?}");
    };
    let cpuinfo =
        String::from_utf8(memory.read_bytes(0x4500, cpuinfo_len as usize).unwrap()).unwrap();
    assert!(cpuinfo.contains("processor\t: 0"));
    assert!(cpuinfo.contains("CPU architecture\t: 8"));
    assert!(cpuinfo.contains("Features\t:"));

    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert!(report.proc_read_unimplemented.is_empty());
}

#[test]
fn synthetic_proc_files_write_regular_packed_stat_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x1000]);
    memory.write_bytes(0x4000, b"/proc/cpuinfo\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode & 0o777, 0o444);
    assert!(size > 0);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let fd_stat = read_stat(&memory, 0x4200);
    let fd_mode = fd_stat.st_mode;
    let fd_size = fd_stat.st_size;
    assert_eq!(fd_mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(fd_mode & 0o777, 0o444);
    assert_eq!(fd_size, size);

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn missing_proc_file_records_compat_report_entry() {
    let mut memory = LinearMemory::new(0x4000, b"/proc/self/status\0".to_vec());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.proc_read_unimplemented[0].path, "/proc/self/status");
    assert_eq!(report.proc_read_unimplemented[0].count, 1);
}

#[test]
fn newfstatat_and_fstat_write_typed_linux_stat() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4100, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4100);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(mode & 0o777, 0o644);
    assert_eq!(size, 18);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(80, SyscallArgs::from([3, 0x4200, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4200);
    let mode = stat.st_mode;
    let size = stat.st_size;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFREG);
    assert_eq!(size, 18);

    memory.write_bytes(0x4300, b"/etc\0").unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    79,
                    SyscallArgs::from([(-100_i64) as u64, 0x4300, 0x4400, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let stat = read_stat(&memory, 0x4400);
    let mode = stat.st_mode;
    assert_eq!(mode & LINUX_S_IFMT, LINUX_S_IFDIR);
}

#[test]
fn getdents64_lists_rootfs_directory_entries() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x500]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
            &mut memory,
            &mut reporter,
        )
        .unwrap();
    let DispatchOutcome::Returned { value } = outcome else {
        panic!("expected getdents64 success, got {outcome:?}");
    };
    assert!(value as usize >= LINUX_DIRENT64_HEADER_SIZE + "motd".len() + 1);

    let dirent = memory.read_bytes(0x4100, value as usize).unwrap();
    let (header, _) = LinuxDirent64Header::read_from_prefix(&dirent).unwrap();
    let reclen = header.d_reclen;
    let dtype = header.d_type;
    assert_eq!(reclen as usize, value as usize);
    assert_eq!(dtype, LINUX_DT_REG);
    let name_start = LINUX_DIRENT64_HEADER_SIZE;
    let name_end = dirent[name_start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| name_start + offset)
        .unwrap();
    assert_eq!(&dirent[name_start..name_end], b"motd");

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(61, SyscallArgs::from([3, 0x4100, 0x100, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
}

#[test]
fn brk_tracks_heap_within_runtime_arena() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(214, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_HEAP_BASE as i64
        }
    );

    let next = LINUX_HEAP_BASE + 0x1000;
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(214, SyscallArgs::from([next, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: next as i64 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    214,
                    SyscallArgs::from([LINUX_HEAP_BASE + LINUX_HEAP_SIZE + 1, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: next as i64 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn process_identity_syscalls_return_bootstrap_ids() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    for (number, expected) in [
        (172, pid),
        (173, 1),
        (174, 0),
        (175, 0),
        (176, 0),
        (177, 0),
        (178, pid),
    ] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &mut reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: expected }
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn capget_writes_empty_bootstrap_capability_sets() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    write_capability_header(&mut memory, 0x4000, LINUX_CAPABILITY_VERSION_3, 0);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(90, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        read_capability_data(&memory, 0x4080, 2),
        vec![(0, 0, 0), (0, 0, 0)]
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn capset_accepts_empty_sets_and_rejects_nonempty_sets() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    write_capability_header(&mut memory, 0x4000, LINUX_CAPABILITY_VERSION_3, 0);
    write_capability_data(&mut memory, 0x4080, [(0, 0, 0), (0, 0, 0)]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(91, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    write_capability_data(&mut memory, 0x4080, [(1, 0, 0), (0, 0, 0)]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(91, SyscallArgs::from([0x4000, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 1 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn personality_query_and_set_round_trip_bootstrap_flags() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_PERSONALITY_QUERY, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_ADDR_NO_RANDOMIZE, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    92,
                    SyscallArgs::from([LINUX_PERSONALITY_QUERY, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_ADDR_NO_RANDOMIZE as i64
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn set_tid_address_and_robust_list_are_bootstrap_successes() {
    let mut memory = LinearMemory::new(0x4000, Vec::new());
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let pid = std::process::id() as i64;

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(96, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: pid }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(99, SyscallArgs::from([0x4000, 24, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn clock_gettime_writes_packed_linux_timespec() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxTimespec>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(113, SyscallArgs::from([0, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timespec = read_timespec(&memory, 0x4000);
    let sec = timespec.tv_sec;
    let nsec = timespec.tv_nsec;
    assert!(sec > 0);
    assert!((0..1_000_000_000).contains(&nsec));
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn clock_getres_writes_packed_linux_timespec() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxTimespec>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(114, SyscallArgs::from([1, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timespec = read_timespec(&memory, 0x4000);
    let sec = timespec.tv_sec;
    assert_eq!(sec, 0);
    let nsec = timespec.tv_nsec;
    assert!(nsec > 0);
    assert!(nsec < 1_000_000_000);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn gettimeofday_writes_packed_linux_timeval_and_timezone() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(169, SyscallArgs::from([0x4000, 0x4020, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let timeval = read_timeval(&memory, 0x4000);
    let sec = timeval.tv_sec;
    let usec = timeval.tv_usec;
    assert!(sec > 0);
    assert!((0..1_000_000).contains(&usec));
    let timezone = read_timezone(&memory, 0x4020);
    let minuteswest = timezone.tz_minuteswest;
    let dsttime = timezone.tz_dsttime;
    assert_eq!(minuteswest, 0);
    assert_eq!(dsttime, 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn uname_writes_packed_linux_utsname() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxUtsname>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(160, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let utsname = read_utsname(&memory, 0x4000);
    assert_eq!(linux_c_string(utsname.sysname), "Linux");
    assert_eq!(linux_c_string(utsname.machine), "aarch64");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn prlimit64_writes_packed_rlimit() {
    let mut memory = LinearMemory::new(0x4000, vec![0; core::mem::size_of::<LinuxRlimit>()]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(261, SyscallArgs::from([0, 3, 0, 0x4000, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    let rlimit = read_rlimit(&memory, 0x4000);
    let current = rlimit.rlim_cur;
    let maximum = rlimit.rlim_max;
    assert_eq!(current, maximum);
    assert!(current > 0);
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn getrandom_fills_guest_buffer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 32]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(278, SyscallArgs::from([0x4000, 16, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 16 }
    );
    assert!(
        memory
            .read_bytes(0x4000, 16)
            .unwrap()
            .iter()
            .any(|byte| *byte != 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn rt_signal_stubs_zero_old_state() {
    let mut memory = LinearMemory::new(0x4000, vec![0xff; 0x200]);
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(135, SyscallArgs::from([0, 0, 0x4000, 8, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(memory.read_bytes(0x4000, 8).unwrap(), [0; 8]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(134, SyscallArgs::from([2, 0, 0x4010, 8, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(
        memory
            .read_bytes(0x4010, 32)
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_maps_file_bytes_into_guest_memory_arena() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "lib/libc.so",
        b"0123456789abcdef".as_slice(),
    )]))])
    .unwrap();
    let mut memory = AddressSpace::from_segments(
        0,
        [
            (0x4000, rw_perms(), b"/lib/libc.so\0".to_vec(), 0x100),
            (LINUX_MMAP_BASE, rwx_perms(), Vec::new(), 0x4000),
        ],
    )
    .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(222, SyscallArgs::from([0, 4, 1, 0x02, 3, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );
    assert_eq!(memory.read_bytes(LINUX_MMAP_BASE, 4).unwrap(), b"0123");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn mmap_anonymous_fixed_mapping_zeroes_guest_memory_and_mprotect_munmap_are_noops() {
    let mut memory = AddressSpace::from_segments(
        0,
        [(LINUX_MMAP_BASE, rwx_perms(), b"dirty".to_vec(), 0x4000)],
    )
    .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([LINUX_MMAP_BASE, 5, 3, 0x12 | 0x20, (-1_i64) as u64, 0]),
                ),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_MMAP_BASE as i64
        }
    );
    assert_eq!(
        memory.read_bytes(LINUX_MMAP_BASE, 5).unwrap(),
        b"\0\0\0\0\0"
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(226, SyscallArgs::from([LINUX_MMAP_BASE, 5, 1, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(215, SyscallArgs::from([LINUX_MMAP_BASE, 5, 0, 0, 0, 0])),
                &mut memory,
                &mut reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

fn read_stat(memory: &impl GuestMemory, address: u64) -> LinuxStat {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStat>())
        .unwrap();
    let (stat, _) = LinuxStat::read_from_prefix(&bytes).unwrap();
    stat
}

fn read_statfs(memory: &impl GuestMemory, address: u64) -> LinuxStatfs {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStatfs>())
        .unwrap();
    let (statfs, _) = LinuxStatfs::read_from_prefix(&bytes).unwrap();
    statfs
}

fn read_winsize(memory: &impl GuestMemory, address: u64) -> LinuxWinsize {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxWinsize>())
        .unwrap();
    LinuxWinsize::read_from_bytes(&bytes).unwrap()
}

fn read_fd_pair(memory: &impl GuestMemory, address: u64) -> LinuxFdPair {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxFdPair>())
        .unwrap();
    LinuxFdPair::read_from_bytes(&bytes).unwrap()
}

fn read_itimerspec(memory: &impl GuestMemory, address: u64) -> LinuxItimerspec {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxItimerspec>())
        .unwrap();
    LinuxItimerspec::read_from_bytes(&bytes).unwrap()
}

fn read_timerfd_expirations(memory: &impl GuestMemory, address: u64) -> LinuxTimerfdExpirations {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimerfdExpirations>())
        .unwrap();
    LinuxTimerfdExpirations::read_from_bytes(&bytes).unwrap()
}

fn read_eventfd_value(memory: &impl GuestMemory, address: u64) -> LinuxEventfdValue {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxEventfdValue>())
        .unwrap();
    LinuxEventfdValue::read_from_bytes(&bytes).unwrap()
}

fn read_epoll_event(memory: &impl GuestMemory, address: u64) -> LinuxEpollEvent {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxEpollEvent>())
        .unwrap();
    LinuxEpollEvent::read_from_bytes(&bytes).unwrap()
}

fn read_utsname(memory: &impl GuestMemory, address: u64) -> LinuxUtsname {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxUtsname>())
        .unwrap();
    let (utsname, _) = LinuxUtsname::read_from_prefix(&bytes).unwrap();
    utsname
}

fn read_rlimit(memory: &impl GuestMemory, address: u64) -> LinuxRlimit {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxRlimit>())
        .unwrap();
    let (rlimit, _) = LinuxRlimit::read_from_prefix(&bytes).unwrap();
    rlimit
}

fn read_timespec(memory: &impl GuestMemory, address: u64) -> LinuxTimespec {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimespec>())
        .unwrap();
    let (timespec, _) = LinuxTimespec::read_from_prefix(&bytes).unwrap();
    timespec
}

fn read_timeval(memory: &impl GuestMemory, address: u64) -> LinuxTimeval {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimeval>())
        .unwrap();
    let (timeval, _) = LinuxTimeval::read_from_prefix(&bytes).unwrap();
    timeval
}

fn read_timezone(memory: &impl GuestMemory, address: u64) -> LinuxTimezone {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimezone>())
        .unwrap();
    let (timezone, _) = LinuxTimezone::read_from_prefix(&bytes).unwrap();
    timezone
}

fn linux_c_string<const N: usize>(field: [u8; N]) -> String {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(N);
    String::from_utf8(field[..end].to_vec()).unwrap()
}

fn write_iovecs<const N: usize>(
    memory: &mut impl GuestMemory,
    address: u64,
    iovecs: [LinuxIovec; N],
) {
    let mut bytes = Vec::new();
    for iovec in iovecs {
        bytes.extend_from_slice(iovec.as_bytes());
    }
    memory.write_bytes(address, &bytes).unwrap();
}

fn write_pollfds<const N: usize>(
    memory: &mut impl GuestMemory,
    address: u64,
    pollfds: [LinuxPollFd; N],
) {
    let mut bytes = Vec::new();
    for pollfd in pollfds {
        bytes.extend_from_slice(pollfd.as_bytes());
    }
    memory.write_bytes(address, &bytes).unwrap();
}

fn read_pollfds(memory: &impl GuestMemory, address: u64, count: usize) -> Vec<(i32, i16, i16)> {
    let bytes = memory
        .read_bytes(address, count * std::mem::size_of::<LinuxPollFd>())
        .unwrap();
    bytes
        .chunks_exact(std::mem::size_of::<LinuxPollFd>())
        .map(|pollfd| {
            let pollfd = LinuxPollFd::read_from_bytes(pollfd).unwrap();
            let fd = pollfd.fd;
            let events = pollfd.events;
            let revents = pollfd.revents;
            (fd, events, revents)
        })
        .collect()
}

fn write_fd_set<const N: usize>(
    memory: &mut impl GuestMemory,
    address: u64,
    nfds: usize,
    fds: [i32; N],
) {
    let mut bytes = vec![0; linux_fd_set_len(nfds)];
    for fd in fds {
        let fd = usize::try_from(fd).unwrap();
        bytes[fd / 8] |= 1 << (fd % 8);
    }
    memory.write_bytes(address, &bytes).unwrap();
}

fn read_fd_set(memory: &impl GuestMemory, address: u64, nfds: usize) -> Vec<i32> {
    let bytes = memory.read_bytes(address, linux_fd_set_len(nfds)).unwrap();
    (0..nfds)
        .filter(|fd| bytes[*fd / 8] & (1 << (*fd % 8)) != 0)
        .map(|fd| i32::try_from(fd).unwrap())
        .collect()
}

fn linux_fd_set_len(nfds: usize) -> usize {
    nfds.div_ceil(64) * 8
}

fn write_capability_header(memory: &mut impl GuestMemory, address: u64, version: u32, pid: i32) {
    memory
        .write_bytes(address, LinuxCapabilityHeader { version, pid }.as_bytes())
        .unwrap();
}

fn write_capability_data<const N: usize>(
    memory: &mut impl GuestMemory,
    address: u64,
    data: [(u32, u32, u32); N],
) {
    let mut bytes = Vec::new();
    for (effective, permitted, inheritable) in data {
        bytes.extend_from_slice(
            LinuxCapabilityData {
                effective,
                permitted,
                inheritable,
            }
            .as_bytes(),
        );
    }
    memory.write_bytes(address, &bytes).unwrap();
}

fn read_capability_data(
    memory: &impl GuestMemory,
    address: u64,
    count: usize,
) -> Vec<(u32, u32, u32)> {
    let bytes = memory.read_bytes(address, count * 12).unwrap();
    bytes
        .chunks_exact(12)
        .map(|data| {
            let data = LinuxCapabilityData::read_from_bytes(data).unwrap();
            let effective = data.effective;
            let permitted = data.permitted;
            let inheritable = data.inheritable;
            (effective, permitted, inheritable)
        })
        .collect()
}

fn write_u64(memory: &mut impl GuestMemory, address: u64, value: u64) {
    memory.write_bytes(address, &value.to_ne_bytes()).unwrap();
}

fn read_u64(memory: &impl GuestMemory, address: u64) -> u64 {
    let bytes = memory.read_bytes(address, 8).unwrap();
    u64::from_ne_bytes(bytes.try_into().unwrap())
}

fn rw_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: false,
    }
}

fn rwx_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: true,
    }
}

fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

fn gzip_tar_with_links<const N: usize, const M: usize>(
    files: [(&str, &[u8]); N],
    links: [(&str, &str); M],
) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        for (path, target) in links {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_cksum();
            builder.append_link(&mut header, path, target).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}
