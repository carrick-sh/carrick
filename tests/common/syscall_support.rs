//! Shared support for the syscall-dispatch test suite.
//!
//! Extracted verbatim from the former tests/syscall_dispatch.rs monolith so that
//! per-subsystem test files can include it via
//! `#[path = "common/syscall_support.rs"] mod support;`. Items are re-exported `pub`
//! so each test file can `use support::*;`. Not every file uses every helper, hence
//! the broad allow below.
#![allow(dead_code, unused_imports)]
// This is test-support code: helpers are plain `pub fn`s (not `#[test]`/`#[cfg(test)]`),
// so clippy's `allow-unwrap-in-tests`/`allow-expect-in-tests` heuristic does not exempt
// them. Allow unwrap/expect here explicitly — the no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub use carrick::compat::{CompatReporter, SyscallArgs};
pub use carrick::dispatch::{
    Aarch64SyscallFrame, DispatchOutcome, GuestMemory, LinearMemory, SyscallDispatcher,
    SyscallRequest,
};
pub use carrick::elf::SegmentPerms;
pub use carrick::linux_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_REG, LINUX_S_IFDIR, LINUX_S_IFLNK, LINUX_S_IFMT,
    LINUX_S_IFREG, LINUX_TIOCGPTN, LINUX_TIOCSPTLCK, LinuxCapabilityData, LinuxCapabilityHeader,
    LinuxDirent64Header, LinuxEpollEvent, LinuxEventfdValue, LinuxFdPair, LinuxIovec,
    LinuxItimerspec, LinuxItimerval, LinuxPollFd, LinuxRlimit, LinuxRusage, LinuxSigaltstack,
    LinuxStat, LinuxStatfs, LinuxStatx, LinuxTermios, LinuxTimerfdExpirations, LinuxTimespec,
    LinuxTimeval, LinuxTimezone, LinuxTms, LinuxUtsname, LinuxWinsize,
};
pub use carrick::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE};
pub use carrick::rootfs::{LayerSource, RootFs};
pub use flate2::Compression;
pub use flate2::write::GzEncoder;
pub use std::io::Write;
pub use zerocopy::{FromBytes, IntoBytes};

pub const LINUX_F_DUPFD: u64 = 0;
pub const LINUX_F_GETFD: u64 = 1;
pub const LINUX_F_SETFD: u64 = 2;
pub const LINUX_F_GETFL: u64 = 3;
pub const LINUX_FD_CLOEXEC: u64 = 1;
pub const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
pub const LINUX_F_GETPIPE_SZ: u64 = 1032;
pub const LINUX_O_WRONLY: u64 = 1;
pub const LINUX_LOCK_SH: u64 = 1;
pub const LINUX_LOCK_NB: u64 = 4;
pub const LINUX_LOCK_UN: u64 = 8;
pub const LINUX_MADV_WILLNEED: u64 = 3;
pub const LINUX_MADV_DONTNEED: u64 = 4;
pub const LINUX_MEMBARRIER_CMD_QUERY: u64 = 0;
pub const LINUX_MEMBARRIER_CMD_GLOBAL: u64 = 1;
pub const LINUX_MEMBARRIER_CMD_FLAG_CPU: u64 = 1;
pub const LINUX_O_CLOEXEC: u64 = 0o2000000;
pub const LINUX_O_NONBLOCK: u64 = 0o4000;
pub const LINUX_OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
pub const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
pub const LINUX_EPOLL_CTL_ADD: u64 = 1;
pub const LINUX_EPOLLIN: u32 = 0x001;
pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
pub const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
pub const LINUX_ADDR_NO_RANDOMIZE: u64 = 0x0040_0000;
pub const LINUX_BOOTSTRAP_AFFINITY_BYTES: usize = 8;
pub const LINUX_FUTEX_WAIT: u64 = 0;
pub const LINUX_FUTEX_WAKE: u64 = 1;
pub const LINUX_FUTEX_PRIVATE_FLAG: u64 = 128;
pub const LINUX_POLLIN: i16 = 0x0001;
pub const LINUX_POLLOUT: i16 = 0x0004;
pub const LINUX_POLLNVAL: i16 = 0x0020;
pub const LINUX_PR_GET_DUMPABLE: u64 = 3;
pub const LINUX_PR_SET_DUMPABLE: u64 = 4;
pub const LINUX_PR_SET_NAME: u64 = 15;
pub const LINUX_PR_GET_NAME: u64 = 16;
pub const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
pub const LINUX_TIMER_ABSTIME: u64 = 0x1;
pub const LINUX_CLOCK_MONOTONIC: u64 = 1;
pub const LINUX_TCGETS: u64 = 0x5401;
pub const LINUX_TCSETS: u64 = 0x5402;
pub const LINUX_TIOCSCTTY: u64 = 0x540E;
pub const LINUX_TIOCGPGRP: u64 = 0x540F;
pub const LINUX_TIOCSPGRP: u64 = 0x5410;
pub const LINUX_TIOCGWINSZ: u64 = 0x5413;
pub const LINUX_FIONREAD: u64 = 0x541B;
pub const LINUX_FIONBIO: u64 = 0x5421;
pub const LINUX_TIOCNOTTY: u64 = 0x5422;
pub const LINUX_TIOCGSID: u64 = 0x5429;
pub const LINUX_R_OK: u64 = 4;
pub const LINUX_W_OK: u64 = 2;
pub const LINUX_X_OK: u64 = 1;
pub const LINUX_AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const LINUX_AT_EACCESS: u64 = 0x200;
pub const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub const LINUX_STATX_BASIC_STATS: u32 = 0x7ff;
pub const LINUX_STATX_RESERVED: u64 = 0x8000_0000;
pub const LINUX_SPLICE_F_MORE: u64 = 4;

pub fn read_stat(memory: &impl GuestMemory, address: u64) -> LinuxStat {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStat>())
        .unwrap();
    let (stat, _) = LinuxStat::read_from_prefix(&bytes).unwrap();
    stat
}

pub fn read_statx(memory: &impl GuestMemory, address: u64) -> LinuxStatx {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStatx>())
        .unwrap();
    let (statx, _) = LinuxStatx::read_from_prefix(&bytes).unwrap();
    statx
}

pub fn read_statfs(memory: &impl GuestMemory, address: u64) -> LinuxStatfs {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxStatfs>())
        .unwrap();
    let (statfs, _) = LinuxStatfs::read_from_prefix(&bytes).unwrap();
    statfs
}

pub fn read_i32_le(memory: &impl GuestMemory, address: u64) -> i32 {
    let bytes = memory.read_bytes(address, 4).unwrap();
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes);
    i32::from_le_bytes(buf)
}

pub fn read_winsize(memory: &impl GuestMemory, address: u64) -> LinuxWinsize {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxWinsize>())
        .unwrap();
    LinuxWinsize::read_from_bytes(&bytes).unwrap()
}

pub fn read_termios(memory: &impl GuestMemory, address: u64) -> LinuxTermios {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTermios>())
        .unwrap();
    LinuxTermios::read_from_bytes(&bytes).unwrap()
}

pub fn read_fd_pair(memory: &impl GuestMemory, address: u64) -> LinuxFdPair {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxFdPair>())
        .unwrap();
    LinuxFdPair::read_from_bytes(&bytes).unwrap()
}

pub fn read_itimerspec(memory: &impl GuestMemory, address: u64) -> LinuxItimerspec {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxItimerspec>())
        .unwrap();
    LinuxItimerspec::read_from_bytes(&bytes).unwrap()
}

pub fn read_itimerval(memory: &impl GuestMemory, address: u64) -> LinuxItimerval {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxItimerval>())
        .unwrap();
    LinuxItimerval::read_from_bytes(&bytes).unwrap()
}

pub fn read_timerfd_expirations(
    memory: &impl GuestMemory,
    address: u64,
) -> LinuxTimerfdExpirations {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimerfdExpirations>())
        .unwrap();
    LinuxTimerfdExpirations::read_from_bytes(&bytes).unwrap()
}

pub fn read_eventfd_value(memory: &impl GuestMemory, address: u64) -> LinuxEventfdValue {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxEventfdValue>())
        .unwrap();
    LinuxEventfdValue::read_from_bytes(&bytes).unwrap()
}

pub fn read_epoll_event(memory: &impl GuestMemory, address: u64) -> LinuxEpollEvent {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxEpollEvent>())
        .unwrap();
    LinuxEpollEvent::read_from_bytes(&bytes).unwrap()
}

pub fn read_utsname(memory: &impl GuestMemory, address: u64) -> LinuxUtsname {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxUtsname>())
        .unwrap();
    let (utsname, _) = LinuxUtsname::read_from_prefix(&bytes).unwrap();
    utsname
}

pub fn read_rlimit(memory: &impl GuestMemory, address: u64) -> LinuxRlimit {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxRlimit>())
        .unwrap();
    let (rlimit, _) = LinuxRlimit::read_from_prefix(&bytes).unwrap();
    rlimit
}

pub fn read_tms(memory: &impl GuestMemory, address: u64) -> LinuxTms {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTms>())
        .unwrap();
    let (tms, _) = LinuxTms::read_from_prefix(&bytes).unwrap();
    tms
}

pub fn read_rusage(memory: &impl GuestMemory, address: u64) -> LinuxRusage {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxRusage>())
        .unwrap();
    let (rusage, _) = LinuxRusage::read_from_prefix(&bytes).unwrap();
    rusage
}

pub fn read_timespec(memory: &impl GuestMemory, address: u64) -> LinuxTimespec {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimespec>())
        .unwrap();
    let (timespec, _) = LinuxTimespec::read_from_prefix(&bytes).unwrap();
    timespec
}

pub fn read_timeval(memory: &impl GuestMemory, address: u64) -> LinuxTimeval {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimeval>())
        .unwrap();
    let (timeval, _) = LinuxTimeval::read_from_prefix(&bytes).unwrap();
    timeval
}

pub fn read_timezone(memory: &impl GuestMemory, address: u64) -> LinuxTimezone {
    let bytes = memory
        .read_bytes(address, std::mem::size_of::<LinuxTimezone>())
        .unwrap();
    let (timezone, _) = LinuxTimezone::read_from_prefix(&bytes).unwrap();
    timezone
}

pub fn linux_c_string<const N: usize>(field: [u8; N]) -> String {
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(N);
    String::from_utf8(field[..end].to_vec()).unwrap()
}

pub fn write_iovecs<const N: usize>(
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

pub fn write_pollfds<const N: usize>(
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

pub fn read_pollfds(memory: &impl GuestMemory, address: u64, count: usize) -> Vec<(i32, i16, i16)> {
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

pub fn write_fd_set<const N: usize>(
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

pub fn read_fd_set(memory: &impl GuestMemory, address: u64, nfds: usize) -> Vec<i32> {
    let bytes = memory.read_bytes(address, linux_fd_set_len(nfds)).unwrap();
    (0..nfds)
        .filter(|fd| bytes[*fd / 8] & (1 << (*fd % 8)) != 0)
        .map(|fd| i32::try_from(fd).unwrap())
        .collect()
}

pub fn linux_fd_set_len(nfds: usize) -> usize {
    nfds.div_ceil(64) * 8
}

pub fn write_capability_header(
    memory: &mut impl GuestMemory,
    address: u64,
    version: u32,
    pid: i32,
) {
    memory
        .write_bytes(address, LinuxCapabilityHeader { version, pid }.as_bytes())
        .unwrap();
}

pub fn write_capability_data<const N: usize>(
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

pub fn read_capability_data(
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

pub fn write_linux_timespec(
    memory: &mut impl GuestMemory,
    address: u64,
    tv_sec: i64,
    tv_nsec: i64,
) {
    let timespec = LinuxTimespec::new(tv_sec, tv_nsec);
    memory.write_bytes(address, timespec.as_bytes()).unwrap();
}

pub fn write_u64(memory: &mut impl GuestMemory, address: u64, value: u64) {
    memory.write_bytes(address, &value.to_ne_bytes()).unwrap();
}

pub fn write_open_how(
    memory: &mut impl GuestMemory,
    address: u64,
    flags: u64,
    mode: u64,
    resolve: u64,
) {
    write_u64(memory, address, flags);
    write_u64(memory, address + 8, mode);
    write_u64(memory, address + 16, resolve);
}

pub fn read_u64(memory: &impl GuestMemory, address: u64) -> u64 {
    let bytes = memory.read_bytes(address, 8).unwrap();
    u64::from_ne_bytes(bytes.try_into().unwrap())
}

pub fn rw_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: false,
    }
}

pub fn rwx_perms() -> SegmentPerms {
    SegmentPerms {
        read: true,
        write: true,
        execute: true,
    }
}

pub fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
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

pub fn gzip_tar_with_links<const N: usize, const M: usize>(
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
