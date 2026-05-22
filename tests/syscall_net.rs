//! Networking / I/O multiplexing syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

#[path = "common/syscall_support.rs"]
mod support;

use support::*;

#[test]
fn fionread_and_fionbio_bootstrap_succeed_for_valid_fds() {
    let mut memory = LinearMemory::new(0x4000, vec![0xee; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // FIONREAD on stdio writes 0.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_FIONREAD, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4000), 0);

    // FIONBIO on stdio with enable=1 → 0.
    memory.write_bytes(0x4010, &1_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, LINUX_FIONBIO, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // FIONBIO on fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_FIONBIO, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // FIONREAD on unknown fd 99 → EBADF too.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_FIONREAD, 0x4020, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

#[test]
fn eventfd2_read_write_round_trip_uses_packed_counter() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([7, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4000, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4020, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 32, 0, 0, 0])),
                &mut memory,
                &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    59,
                    SyscallArgs::from([0x4000, LINUX_O_NONBLOCK, 0, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([write_fd, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(57, SyscallArgs::from([5, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([read_fd, 0x4080, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_getpipe_size_reports_bootstrap_pipe_capacity() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(59, SyscallArgs::from([0x4000, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 65536 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_settime_read_round_trip_uses_packed_records() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 11 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn timerfd_gettime_writes_packed_itimerspec_for_armed_timer() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(87, SyscallArgs::from([3, 0x4080, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(85, SyscallArgs::from([1, LINUX_TFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn epoll_reports_eventfd_readiness_with_packed_events() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(22, SyscallArgs::from([4, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ppoll_reports_eventfd_pipe_and_invalid_fd_readiness() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x800]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(19, SyscallArgs::from([1, LINUX_EFD_NONBLOCK, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
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
                &reporter,
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
                &reporter,
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
                &reporter,
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
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    write_fd_set(&mut memory, 0x4100, 100, [99]);
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(72, SyscallArgs::from([100, 0x4100, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn socket_syscalls_dispatch_to_real_host_handlers() {
    // Now that the BSD socket family is wired through to libc, syscall
    // numbers 198..=212 / 242 must NOT come back as ENOSYS. We don't
    // care which specific errno the all-zero argument vector produces —
    // we only require that the dispatcher answered itself rather than
    // falling through to the "unhandled syscall" branch (which would
    // set ENOSYS and record an entry in `unhandled_syscalls`).
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let numbers: &[u64] = &[
        198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 242,
    ];

    for number in numbers {
        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(*number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        if let DispatchOutcome::Errno { errno } = outcome {
            assert_ne!(
                errno, 38,
                "socket syscall {number} returned ENOSYS — handler not installed"
            );
        }
    }

    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn signalfd4_vmsplice_tee_bootstrap_return_enosys() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x80]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    for number in [74_u64, 75, 77] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(number, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 38 },
            "syscall {number} should return ENOSYS"
        );
    }
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
