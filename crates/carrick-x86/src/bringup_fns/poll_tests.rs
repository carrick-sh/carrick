//! Standalone x86 poll contract: normalize the real ABI, then serve it.
use super::*;
use carrick_abi::{LINUX_EFAULT, LINUX_POLLIN, LINUX_POLLNVAL, LinuxPollFd};
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
