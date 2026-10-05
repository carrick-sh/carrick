//! Standalone x86 poll contract: normalize the real ABI, then serve it.
use super::*;
use carrick_abi::{
    LINUX_EFAULT, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LinuxPollFd,
};
use carrick_guest_mem::X8664SyscallFrame;
use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_hal::x8664_arch::SyscallNorm;
use carrick_hal::{RawSyscall, SignalInjection, SyscallTrap};
use std::cell::Cell;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use zerocopy::{FromBytes, IntoBytes};

struct PollGuest {
    request: Option<RawSyscall>,
    memory: Vec<u8>,
    results: Vec<i64>,
    read_bytes: Cell<usize>,
    written_bytes: usize,
}

impl PollGuest {
    fn new(fds: &[LinuxPollFd], address: u64) -> Self {
        let frame = X8664SyscallFrame {
            rax: 7,
            rdi: address,
            rsi: fds.len() as u64,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
        };
        let SyscallNorm::Plain(request) = X8664GuestArch::normalize_syscall(&frame) else {
            panic!("poll must normalize to an ordinary syscall");
        };
        Self {
            request: Some(request),
            memory: fds.as_bytes().to_vec(),
            results: Vec::new(),
            read_bytes: Cell::new(0),
            written_bytes: 0,
        }
    }
}

impl GuestMemory for PollGuest {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let bytes = usize::try_from(address)
            .ok()
            .and_then(|start| start.checked_add(length).map(|end| (start, end)))
            .and_then(|(start, end)| self.memory.get(start..end))
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        self.read_bytes.set(self.read_bytes.get() + length);
        Ok(bytes.to_vec())
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let dst = usize::try_from(address)
            .ok()
            .and_then(|start| start.checked_add(length).map(|end| (start, end)))
            .and_then(|(start, end)| self.memory.get_mut(start..end))
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        dst.copy_from_slice(bytes);
        self.written_bytes += length;
        Ok(())
    }
}

impl SyscallTrap for PollGuest {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        Ok(self.request.take())
    }
    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(0)
    }
    fn complete_syscall(&mut self, result: i64) -> Result<(), TrapError> {
        self.results.push(result);
        Ok(())
    }
    fn execve_into(&mut self, _: &AddressSpace) -> Result<(), TrapError> {
        panic!("unexpected exec")
    }
    fn inject_signal(&mut self, _: SignalInjection) -> Result<(), TrapError> {
        panic!("unexpected signal")
    }
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        panic!("unexpected sigreturn")
    }
}

#[test]
fn normalized_poll_reports_readiness_and_linear_guest_copy_work() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(b"ready").unwrap();
    for count in [1, 8, 32] {
        let fds = vec![
            LinuxPollFd {
                fd: reader.as_raw_fd(),
                events: LINUX_POLLIN,
                revents: -1
            };
            count
        ];
        let mut guest = PollGuest::new(&fds, 0);
        assert_eq!(run_elf_service_loop(&mut guest).unwrap(), 0);
        assert_eq!(guest.results, [count as i64]);
        for bytes in guest.memory.chunks_exact(8) {
            let fd = LinuxPollFd::read_from_bytes(bytes).unwrap();
            let revents = fd.revents;
            assert_eq!(revents, LINUX_POLLIN);
        }
        assert_eq!(guest.read_bytes.get(), count * size_of::<LinuxPollFd>());
        assert_eq!(guest.written_bytes, count * size_of::<i16>());
    }
}

#[test]
fn normalized_poll_keeps_distinct_ready_descriptors() {
    for count in [1, 8, 32] {
        let pairs: Vec<_> = (0..count)
            .map(|_| {
                let (reader, mut writer) = UnixStream::pair().unwrap();
                writer.write_all(b"ready").unwrap();
                (reader, writer)
            })
            .collect();
        let fds: Vec<_> = pairs
            .iter()
            .map(|(reader, _)| LinuxPollFd {
                fd: reader.as_raw_fd(),
                events: LINUX_POLLIN,
                revents: -1,
            })
            .collect();
        let mut guest = PollGuest::new(&fds, 0);
        run_elf_service_loop(&mut guest).unwrap();
        assert_eq!(guest.results, [count as i64]);
        for bytes in guest.memory.chunks_exact(8) {
            let revents = LinuxPollFd::read_from_bytes(bytes).unwrap().revents;
            assert_eq!(revents, LINUX_POLLIN);
        }
        assert_eq!(guest.read_bytes.get(), count * size_of::<LinuxPollFd>());
        assert_eq!(guest.written_bytes, count * size_of::<i16>());
    }
}

#[test]
fn normalized_poll_clears_stale_events_and_reports_invalid_descriptors() {
    let (reader, _writer) = UnixStream::pair().unwrap();
    let fds = [
        LinuxPollFd {
            fd: reader.as_raw_fd(),
            events: LINUX_POLLIN,
            revents: -1,
        },
        LinuxPollFd {
            fd: -1,
            events: LINUX_POLLIN,
            revents: -1,
        },
        LinuxPollFd {
            fd: i32::MAX,
            events: 0,
            revents: -1,
        },
    ];
    let mut guest = PollGuest::new(&fds, 0);
    assert_eq!(run_elf_service_loop(&mut guest).unwrap(), 0);
    assert_eq!(guest.results, [1]);
    let revents: Vec<_> = guest
        .memory
        .chunks_exact(8)
        .map(|bytes| LinuxPollFd::read_from_bytes(bytes).unwrap().revents)
        .collect();
    assert_eq!(revents, [0, 0, LINUX_POLLNVAL]);
}

#[test]
fn normalized_poll_preserves_each_duplicate_interest_and_unrequested_hangup() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(b"ready").unwrap();
    let fds: Vec<_> = [LINUX_POLLIN, 0, LINUX_POLLOUT, LINUX_POLLIN]
        .into_iter()
        .map(|events| LinuxPollFd {
            fd: reader.as_raw_fd(),
            events,
            revents: -1,
        })
        .collect();
    let mut guest = PollGuest::new(&fds, 0);
    run_elf_service_loop(&mut guest).unwrap();
    assert_eq!(guest.results, [3]);
    let revents: Vec<_> = guest
        .memory
        .chunks_exact(8)
        .map(|bytes| LinuxPollFd::read_from_bytes(bytes).unwrap().revents)
        .collect();
    assert_eq!(revents, [LINUX_POLLIN, 0, LINUX_POLLOUT, LINUX_POLLIN]);

    drop(writer);
    let mut hung_up = PollGuest::new(&[fds[1]], 0);
    run_elf_service_loop(&mut hung_up).unwrap();
    assert_eq!(hung_up.results, [1]);
    let revents = LinuxPollFd::read_from_bytes(&hung_up.memory)
        .unwrap()
        .revents;
    assert_eq!(revents, LINUX_POLLHUP);
}

#[test]
fn normalized_poll_validates_memory_but_ignores_pointer_for_empty_set() {
    let mut empty = PollGuest::new(&[], u64::MAX);
    run_elf_service_loop(&mut empty).unwrap();
    assert_eq!(empty.results, [0]);
    assert_eq!(empty.read_bytes.get(), 0);
    assert_eq!(empty.written_bytes, 0);

    let mut bad = PollGuest::new(
        &[LinuxPollFd {
            fd: -1,
            events: 0,
            revents: 0,
        }],
        u64::MAX,
    );
    run_elf_service_loop(&mut bad).unwrap();
    assert_eq!(bad.results, [LINUX_EFAULT.guest_retval()]);
}

#[test]
fn poll_normalizes_every_negative_timeout_at_the_native_boundary() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(b"ready").unwrap();
    for timeout in [-2, i32::MIN] {
        let mut guest = PollGuest::new(
            &[LinuxPollFd {
                fd: reader.as_raw_fd(),
                events: LINUX_POLLIN,
                revents: -1,
            }],
            0,
        );
        let result = sys_poll(
            StandaloneHostFds,
            &mut guest,
            carrick_guest_mem::GuestVa(0),
            1,
            timeout,
            |fds, native_timeout| {
                // FreeBSD rejects values below -1 even when a fd is ready.
                assert_eq!(native_timeout, -1);
                poll_host_fds(fds, native_timeout)
            },
        );
        assert_eq!(result, 1);
        let revents = LinuxPollFd::read_from_bytes(&guest.memory).unwrap().revents;
        assert_eq!(revents, LINUX_POLLIN);
    }
}

#[test]
fn poll_invalid_descriptor_overrides_an_infinite_timeout() {
    let mut guest = PollGuest::new(
        &[LinuxPollFd {
            fd: i32::MAX,
            events: 0,
            revents: -1,
        }],
        0,
    );
    let result = sys_poll(
        StandaloneHostFds,
        &mut guest,
        carrick_guest_mem::GuestVa(0),
        1,
        i32::MIN,
        |fds, timeout| {
            assert_eq!(timeout, 0);
            poll_host_fds(fds, timeout)
        },
    );
    assert_eq!(result, 1);
    let revents = LinuxPollFd::read_from_bytes(&guest.memory).unwrap().revents;
    assert_eq!(revents, LINUX_POLLNVAL);
}

#[test]
fn normalized_poll_broken_pipe_writer_reports_error_for_every_zero_interest_entry() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let fds = [LinuxPollFd {
        fd: writer.as_raw_fd(),
        events: 0,
        revents: -1,
    }; 2];
    let mut guest = PollGuest::new(&fds, 0);
    run_elf_service_loop(&mut guest).unwrap();
    assert_eq!(guest.results, [2]);
    for bytes in guest.memory.chunks_exact(8) {
        let revents = LinuxPollFd::read_from_bytes(bytes).unwrap().revents;
        assert_eq!(revents, carrick_abi::LINUX_POLLERR);
    }
    assert_eq!(guest.read_bytes.get(), 16);
    assert_eq!(guest.written_bytes, 4);
}

#[test]
fn normalized_poll_pipe_reader_keeps_unrequested_hangup() {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(writer);
    let mut guest = PollGuest::new(
        &[LinuxPollFd {
            fd: reader.as_raw_fd(),
            events: 0,
            revents: -1,
        }],
        0,
    );
    run_elf_service_loop(&mut guest).unwrap();
    assert_eq!(guest.results, [1]);
    let revents = LinuxPollFd::read_from_bytes(&guest.memory).unwrap().revents;
    assert_eq!(revents, LINUX_POLLHUP);
}

#[test]
fn poll_positive_wait_completes_when_a_producer_makes_the_fd_ready() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let (start, receive) = std::sync::mpsc::channel();
    let producer = std::thread::spawn(move || {
        receive
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        writer.write_all(b"ready").unwrap();
        writer
    });
    let mut guest = PollGuest::new(
        &[LinuxPollFd {
            fd: reader.as_raw_fd(),
            events: LINUX_POLLIN,
            revents: -1,
        }],
        0,
    );
    let result = sys_poll(
        StandaloneHostFds,
        &mut guest,
        carrick_guest_mem::GuestVa(0),
        1,
        5_000,
        |fds, timeout| {
            assert_eq!(timeout, 5_000);
            // The fd is initially unready. Release the producer at the native
            // wait boundary; either scheduler order must complete correctly.
            start.send(()).unwrap();
            poll_host_fds(fds, timeout)
        },
    );
    let _writer = producer.join().unwrap();
    assert_eq!(result, 1);
    let revents = LinuxPollFd::read_from_bytes(&guest.memory).unwrap().revents;
    assert_eq!(revents, LINUX_POLLIN);
}

#[test]
fn poll_native_interruption_returns_linux_eintr_without_copyout_or_retry() {
    let (reader, _writer) = UnixStream::pair().unwrap();
    let mut guest = PollGuest::new(
        &[LinuxPollFd {
            fd: reader.as_raw_fd(),
            events: LINUX_POLLIN,
            revents: -1,
        }],
        0,
    );
    let original = guest.memory.clone();
    let mut calls = 0;
    let result = sys_poll(
        StandaloneHostFds,
        &mut guest,
        carrick_guest_mem::GuestVa(0),
        1,
        5_000,
        |_, _| {
            // Inject at the native boundary, avoiding process-wide signal
            // disposition changes and timing-dependent signal delivery.
            calls += 1;
            Err(std::io::Error::from_raw_os_error(libc::EINTR))
        },
    );
    assert_eq!(result, carrick_abi::LINUX_EINTR.guest_retval());
    assert_eq!(calls, 1);
    assert_eq!(guest.memory, original);
    assert_eq!(guest.written_bytes, 0);
}

#[test]
fn poll_rejects_nfds_above_the_limit_before_guest_access_or_native_wait() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit points to writable storage for the returned host limit.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    let limit = u32::try_from(limit.rlim_cur).unwrap();
    assert!(limit > 0);
    let mut guest = PollGuest::new(&[], 0);
    for (count, errno) in [
        (limit, LINUX_EFAULT),
        (limit.checked_add(1).unwrap(), carrick_abi::LINUX_EINVAL),
    ] {
        let result = sys_poll(
            StandaloneHostFds,
            &mut guest,
            carrick_guest_mem::GuestVa(0),
            count,
            0,
            |_, _| panic!("invalid request must not reach the native wait"),
        );
        assert_eq!(result, errno.guest_retval());
        assert_eq!(guest.read_bytes.get(), 0);
        assert_eq!(guest.written_bytes, 0);
    }
}
