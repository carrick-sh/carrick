use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::linux_abi::{
    LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_DIR, LINUX_DT_LNK, LINUX_DT_REG, LINUX_PAGE_SIZE,
    LINUX_S_IFDIR, LINUX_S_IFLNK, LINUX_S_IFREG, LinuxCapabilityData, LinuxCapabilityHeader,
    LinuxDirent64Header, LinuxEpollEvent, LinuxEventfdValue, LinuxFdPair, LinuxIovec,
    LinuxItimerspec, LinuxPollFd, LinuxRlimit, LinuxSigaction, LinuxStat, LinuxStatfs,
    LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimezone, LinuxUtsname,
    LinuxWinsize,
};
use crate::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE, LINUX_MMAP_SIZE};
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
use crate::syscall::lookup_aarch64;
use serde::Serialize;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

pub const LINUX_EPERM: i32 = 1;
pub const LINUX_ENOENT: i32 = 2;
pub const LINUX_ESRCH: i32 = 3;
pub const LINUX_EBADF: i32 = 9;
pub const LINUX_EAGAIN: i32 = 11;
pub const LINUX_ENOMEM: i32 = 12;
pub const LINUX_EACCES: i32 = 13;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_EEXIST: i32 = 17;
pub const LINUX_EPIPE: i32 = 32;
pub const LINUX_ENOTDIR: i32 = 20;
pub const LINUX_EISDIR: i32 = 21;
pub const LINUX_EINVAL: i32 = 22;
pub const LINUX_ENOTTY: i32 = 25;
pub const LINUX_ERANGE: i32 = 34;
pub const LINUX_ENAMETOOLONG: i32 = 36;
pub const LINUX_ENOSYS: i32 = 38;
pub const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
pub const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub const LINUX_R_OK: u64 = 4;
pub const LINUX_W_OK: u64 = 2;
pub const LINUX_X_OK: u64 = 1;
pub const LINUX_F_DUPFD: u64 = 0;
pub const LINUX_F_GETFD: u64 = 1;
pub const LINUX_F_SETFD: u64 = 2;
pub const LINUX_F_GETFL: u64 = 3;
pub const LINUX_F_SETFL: u64 = 4;
pub const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
pub const LINUX_F_GETPIPE_SZ: u64 = 1032;
pub const LINUX_FD_CLOEXEC: u64 = 1;
pub const LINUX_SEEK_SET: u64 = 0;
pub const LINUX_SEEK_CUR: u64 = 1;
pub const LINUX_SEEK_END: u64 = 2;
pub const LINUX_O_ACCMODE: u64 = 0b11;
pub const LINUX_O_NONBLOCK: u64 = 0o4000;
pub const LINUX_O_CLOEXEC: u64 = 0o2000000;
pub const LINUX_PROT_READ: u64 = 0x1;
pub const LINUX_PROT_WRITE: u64 = 0x2;
pub const LINUX_PROT_EXEC: u64 = 0x4;
pub const LINUX_MAP_PRIVATE: u64 = 0x02;
pub const LINUX_MAP_FIXED: u64 = 0x10;
pub const LINUX_MAP_ANONYMOUS: u64 = 0x20;
pub const LINUX_RLIM_INFINITY: u64 = u64::MAX;
pub const LINUX_OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
const LINUX_EFD_SEMAPHORE: u64 = 0x1;
const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_EFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_EPOLL_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_EPOLL_CTL_ADD: u64 = 1;
const LINUX_EPOLL_CTL_DEL: u64 = 2;
const LINUX_EPOLL_CTL_MOD: u64 = 3;
const LINUX_EPOLLIN: u32 = 0x001;
const LINUX_POLLIN: i16 = 0x0001;
const LINUX_POLLOUT: i16 = 0x0004;
const LINUX_POLLERR: i16 = 0x0008;
const LINUX_POLLHUP: i16 = 0x0010;
const LINUX_POLLNVAL: i16 = 0x0020;
const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_TFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_TIMER_ABSTIME: u64 = 0x1;
const LINUX_TIOCGWINSZ: u64 = 0x5413;
const LINUX_PIPE_BUF_SIZE: i64 = 65_536;
const LINUX_RT_SIGSET_SIZE: u64 = 8;
const LINUX_CLOCK_REALTIME: u64 = 0;
const LINUX_CLOCK_MONOTONIC: u64 = 1;
const LINUX_CLOCK_MONOTONIC_RAW: u64 = 4;
const LINUX_CLOCK_REALTIME_COARSE: u64 = 5;
const LINUX_CLOCK_MONOTONIC_COARSE: u64 = 6;
const LINUX_CLOCK_BOOTTIME: u64 = 7;
const LINUX_CLOCK_RESOLUTION_NSEC: i64 = 1_000_000;
const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
const MAX_GUEST_PATH: usize = 4096;
const LINUX_IOV_MAX: usize = 1024;

static MONOTONIC_START: OnceLock<Instant> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: SyscallArgs,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Aarch64SyscallFrame {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x8: u64,
}

impl SyscallRequest {
    pub fn new(number: u64, args: SyscallArgs) -> Self {
        Self { number, args }
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.args.0[index]
    }

    pub fn from_aarch64_frame(frame: Aarch64SyscallFrame) -> Self {
        Self {
            number: frame.x8,
            args: SyscallArgs::from([frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Returned { value: i64 },
    Errno { errno: i32 },
    Exit { code: i32 },
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match *self {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => (-(errno as i64), Some(errno)),
            DispatchOutcome::Exit { code } => (code as i64, None),
        }
    }
}

pub trait GuestMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMemory {
    base: u64,
    bytes: Vec<u8>,
}

impl LinearMemory {
    pub fn new(base: u64, bytes: Vec<u8>) -> Self {
        Self { base, bytes }
    }
}

impl GuestMemory for LinearMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset =
            usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds { address, length })?;
        let end = offset
            .checked_add(length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        Ok(self.bytes[offset..end].to_vec())
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let offset = address
            .checked_sub(self.base)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        let offset = usize::try_from(offset).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        if end > self.bytes.len() {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MemoryError {
    #[error("guest memory read is out of bounds at 0x{address:x} for {length} bytes")]
    OutOfBounds { address: u64, length: usize },
}

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("guest memory read length does not fit this host: {0}")]
    LengthTooLarge(u64),
}

pub struct SyscallDispatcher {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    rootfs: Option<RootFs>,
    open_files: HashMap<i32, OpenFile>,
    next_fd: i32,
    cwd: String,
    brk_current: u64,
    mmap_next: u64,
    executable_path: String,
    personality: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenDescription {
    File {
        path: String,
        metadata: RootFsMetadata,
        contents: Vec<u8>,
        offset: usize,
        status_flags: u64,
    },
    Directory {
        path: String,
        metadata: RootFsMetadata,
        entries: Vec<RootFsDirEntry>,
        offset: usize,
        status_flags: u64,
    },
    SyntheticFile {
        path: String,
        contents: Vec<u8>,
        offset: usize,
        status_flags: u64,
    },
    EventFd {
        counter: u64,
        semaphore: bool,
        status_flags: u64,
    },
    TimerFd {
        clock_id: u64,
        interval: Option<Duration>,
        deadline: Option<Duration>,
        expirations: u64,
        status_flags: u64,
    },
    Epoll {
        interest: HashMap<i32, LinuxEpollEvent>,
        status_flags: u64,
    },
    PipeReader {
        pipe: Rc<RefCell<PipeState>>,
        status_flags: u64,
    },
    PipeWriter {
        pipe: Rc<RefCell<PipeState>>,
        status_flags: u64,
    },
}

#[derive(Debug, Clone)]
struct OpenFile {
    description: Rc<RefCell<OpenDescription>>,
    fd_flags: u64,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct PipeState {
    buffer: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollInterest {
    Read,
    Write,
    Except,
}

impl PollInterest {
    fn poll_events(self) -> i16 {
        match self {
            Self::Read => LINUX_POLLIN,
            Self::Write => LINUX_POLLOUT,
            Self::Except => LINUX_POLLERR,
        }
    }
}

impl OpenDescription {
    fn status_flags(&self) -> u64 {
        match self {
            OpenDescription::File { status_flags, .. }
            | OpenDescription::Directory { status_flags, .. }
            | OpenDescription::SyntheticFile { status_flags, .. }
            | OpenDescription::EventFd { status_flags, .. }
            | OpenDescription::TimerFd { status_flags, .. }
            | OpenDescription::Epoll { status_flags, .. }
            | OpenDescription::PipeReader { status_flags, .. }
            | OpenDescription::PipeWriter { status_flags, .. } => *status_flags,
        }
    }

    fn set_status_flags(&mut self, next: u64) {
        match self {
            OpenDescription::File { status_flags, .. }
            | OpenDescription::Directory { status_flags, .. }
            | OpenDescription::SyntheticFile { status_flags, .. }
            | OpenDescription::EventFd { status_flags, .. }
            | OpenDescription::TimerFd { status_flags, .. }
            | OpenDescription::Epoll { status_flags, .. }
            | OpenDescription::PipeReader { status_flags, .. }
            | OpenDescription::PipeWriter { status_flags, .. } => *status_flags = next,
        }
    }
}

impl Default for SyscallDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallDispatcher {
    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            rootfs: None,
            open_files: HashMap::new(),
            next_fd: 3,
            cwd: "/".to_owned(),
            brk_current: LINUX_HEAP_BASE,
            mmap_next: LINUX_MMAP_BASE,
            executable_path: "/proc/self/exe".to_owned(),
            personality: 0,
        }
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        Self {
            rootfs: Some(rootfs),
            ..Self::new()
        }
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        Self {
            rootfs: Some(rootfs),
            executable_path: executable_path.into(),
            ..Self::new()
        }
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: name.to_owned(),
            args: request.args,
        });

        let outcome = match request.number {
            17 => self.getcwd(request, memory)?,
            19 => self.eventfd2(request),
            20 => self.epoll_create1(request),
            21 => self.epoll_ctl(request, memory)?,
            22 => self.epoll_pwait(request, memory)?,
            23 => self.dup(request),
            24 => self.dup3(request),
            25 => self.fcntl(request),
            29 => self.ioctl(request, memory, reporter),
            43 => self.statfs(request, memory)?,
            44 => self.fstatfs(request, memory),
            48 => self.faccessat(request, memory)?,
            49 => self.chdir(request, memory)?,
            50 => self.fchdir(request),
            56 => self.openat(request, memory, reporter)?,
            57 => self.close(request),
            59 => self.pipe2(request, memory),
            61 => self.getdents64(request, memory)?,
            62 => self.lseek(request),
            63 => self.read(request, memory)?,
            64 => self.write(request, memory)?,
            65 => self.readv(request, memory)?,
            66 => self.writev(request, memory)?,
            67 => self.pread64(request, memory)?,
            71 => self.sendfile(request, memory)?,
            72 => self.pselect6(request, memory)?,
            73 => self.ppoll(request, memory)?,
            78 => self.readlinkat(request, memory)?,
            79 => self.newfstatat(request, memory)?,
            80 => self.fstat(request, memory),
            85 => self.timerfd_create(request),
            86 => self.timerfd_settime(request, memory),
            87 => self.timerfd_gettime(request, memory),
            90 => self.capget(request, memory),
            91 => self.capset(request, memory),
            92 => self.personality(request),
            93 => self.exit(request),
            94 => self.exit(request),
            96 => self.set_tid_address(),
            99 => self.set_robust_list(request),
            113 => self.clock_gettime(request, memory),
            114 => self.clock_getres(request, memory),
            134 => self.rt_sigaction(request, memory),
            135 => self.rt_sigprocmask(request, memory)?,
            160 => self.uname(request, memory),
            169 => self.gettimeofday(request, memory),
            172 => self.getpid(),
            173 => DispatchOutcome::Returned { value: 1 },
            174..=177 => DispatchOutcome::Returned { value: 0 },
            178 => self.getpid(),
            214 => self.brk(request),
            215 => self.munmap(request),
            222 => self.mmap(request, memory)?,
            226 => self.mprotect(request, memory),
            261 => self.prlimit64(request, memory),
            278 => self.getrandom(request, memory)?,
            _ => {
                reporter.record(CompatEvent::unhandled_syscall(
                    request.number,
                    name,
                    request.args,
                ));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS,
                }
            }
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: name.to_owned(),
            retval,
            errno,
        });

        Ok(outcome)
    }

    fn getcwd(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = request.arg(0);
        let size = usize::try_from(request.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(1)))?;
        let mut bytes = self.cwd.as_bytes().to_vec();
        bytes.push(0);
        if bytes.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: address as i64,
        })
    }

    fn faccessat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let mode = request.arg(2);
        let flags = request.arg(3);
        if mode & !(LINUX_R_OK | LINUX_W_OK | LINUX_X_OK) != 0 || flags != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(outcome) = self.synthetic_access(&path, mode) {
            return Ok(outcome);
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };

        if mode & LINUX_W_OK != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }
        if mode & LINUX_R_OK != 0
            && metadata.kind == RootFsEntryKind::File
            && metadata.mode & 0o444 == 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }
        if mode & LINUX_X_OK != 0
            && metadata.kind == RootFsEntryKind::File
            && metadata.mode & 0o111 == 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            });
        }

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn chdir(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };
        if metadata.kind != RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            });
        }
        self.cwd = display_rootfs_path(&metadata.path);
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fchdir(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::Directory { metadata, .. } => {
                self.cwd = display_rootfs_path(&metadata.path);
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            },
        }
    }

    fn synthetic_access(&self, path: &str, mode: u64) -> Option<DispatchOutcome> {
        if synthetic_proc_file(path, &self.executable_path).is_none() {
            return None;
        }
        if mode & LINUX_W_OK != 0 {
            Some(DispatchOutcome::Errno {
                errno: LINUX_EACCES,
            })
        } else {
            Some(DispatchOutcome::Returned { value: 0 })
        }
    }

    fn record_unimplemented_virtual_file(
        reporter: &mut CompatReporter,
        path: &str,
    ) -> Option<DispatchOutcome> {
        if path.starts_with("/proc/") {
            reporter.record(CompatEvent::proc_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            })
        } else if path.starts_with("/sys/") {
            reporter.record(CompatEvent::sys_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            })
        } else {
            None
        }
    }

    fn eventfd2(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let initial_value = request.arg(0);
        let flags = request.arg(1);
        if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let description = OpenDescription::EventFd {
            counter: initial_value,
            semaphore: flags & LINUX_EFD_SEMAPHORE != 0,
            status_flags: flags & LINUX_EFD_NONBLOCK,
        };
        self.install_fd(description, linux_fd_flags_from_open_flags(flags))
    }

    fn timerfd_create(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let flags = request.arg(1);
        if linux_clock_duration(clock_id).is_none()
            || flags & !(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC) != 0
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let description = OpenDescription::TimerFd {
            clock_id,
            interval: None,
            deadline: None,
            expirations: 0,
            status_flags: flags & LINUX_TFD_NONBLOCK,
        };
        self.install_fd(description, linux_fd_flags_from_open_flags(flags))
    }

    fn timerfd_settime(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let flags = request.arg(1);
        let new_value = request.arg(2);
        let old_value = request.arg(3);
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let spec = match read_itimerspec(memory, new_value) {
            Ok(spec) => spec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let (next_interval, next_value) = match itimerspec_durations(spec) {
            Ok(value) => value,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::TimerFd {
            clock_id,
            interval,
            deadline,
            expirations,
            ..
        } = &mut *open
        else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };

        if old_value != 0 {
            let previous = timerfd_itimerspec(*clock_id, *interval, *deadline);
            if memory.write_bytes(old_value, previous.as_bytes()).is_err() {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        }

        let now = linux_clock_duration(*clock_id).unwrap_or(Duration::ZERO);
        *interval = next_interval;
        *deadline = next_value.map(|value| {
            if flags & LINUX_TIMER_ABSTIME != 0 {
                value
            } else {
                now.saturating_add(value)
            }
        });
        *expirations = 0;
        DispatchOutcome::Returned { value: 0 }
    }

    fn timerfd_gettime(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let current_value = request.arg(1);
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let OpenDescription::TimerFd {
            clock_id,
            interval,
            deadline,
            ..
        } = &*open
        else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let current = timerfd_itimerspec(*clock_id, *interval, *deadline);
        write_packed(memory, current_value, current.as_bytes())
    }

    fn epoll_create1(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let flags = request.arg(0);
        if flags & !LINUX_EPOLL_CLOEXEC != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let description = OpenDescription::Epoll {
            interest: HashMap::new(),
            status_flags: 0,
        };
        self.install_fd(description, linux_fd_flags_from_open_flags(flags))
    }

    fn epoll_ctl(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let epfd = request.arg(0) as i32;
        let operation = request.arg(1);
        let fd = request.arg(2) as i32;
        let event_address = request.arg(3);
        if epfd == fd || !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        let Some(open_file) = self.open_files.get(&epfd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::Epoll { interest, .. } = &mut *open else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };

        match operation {
            LINUX_EPOLL_CTL_ADD => {
                let event = match read_epoll_event(memory, event_address) {
                    Ok(event) => event,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                if interest.contains_key(&fd) {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                interest.insert(fd, event);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_EPOLL_CTL_MOD => {
                let event = match read_epoll_event(memory, event_address) {
                    Ok(event) => event,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                let Some(slot) = interest.get_mut(&fd) else {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOENT,
                    });
                };
                *slot = event;
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            LINUX_EPOLL_CTL_DEL => {
                if interest.remove(&fd).is_some() {
                    Ok(DispatchOutcome::Returned { value: 0 })
                } else {
                    Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOENT,
                    })
                }
            }
            _ => Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            }),
        }
    }

    fn epoll_pwait(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let epfd = request.arg(0) as i32;
        let events_address = request.arg(1);
        let max_events = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        if max_events == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let Some(open_file) = self.open_files.get(&epfd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let interests = {
            let open = open_file.description.borrow();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            };
            interest
                .iter()
                .map(|(fd, event)| (*fd, *event))
                .collect::<Vec<_>>()
        };

        let mut ready = Vec::new();
        for (fd, event) in interests {
            let requested_events = event.events;
            let ready_events = self.epoll_ready_events(fd, requested_events);
            if ready_events != 0 {
                ready.push(LinuxEpollEvent {
                    events: ready_events,
                    data: event.data,
                });
                if ready.len() == max_events {
                    break;
                }
            }
        }

        let event_size = core::mem::size_of::<LinuxEpollEvent>();
        for (index, event) in ready.iter().enumerate() {
            let offset = index
                .checked_mul(event_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let address = events_address.checked_add(offset).ok_or(LINUX_EFAULT);
            let Ok(address) = address else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            };
            if memory.write_bytes(address, event.as_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }

        Ok(DispatchOutcome::Returned {
            value: ready.len() as i64,
        })
    }

    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_files.get(&fd) else {
            return 0;
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::EventFd { counter, .. }
                if *counter > 0 && requested_events & LINUX_EPOLLIN != 0 =>
            {
                LINUX_EPOLLIN
            }
            OpenDescription::PipeReader { pipe, .. } if requested_events & LINUX_EPOLLIN != 0 => {
                let pipe = pipe.borrow();
                if !pipe.buffer.is_empty() || pipe.writers == 0 {
                    LINUX_EPOLLIN
                } else {
                    0
                }
            }
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                ..
            } if requested_events & LINUX_EPOLLIN != 0
                && timerfd_expirations(*clock_id, *interval, *deadline, *expirations).0 > 0 =>
            {
                LINUX_EPOLLIN
            }
            _ => 0,
        }
    }

    fn pselect6(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nfds = usize::try_from(request.arg(0))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(0)))?;
        let readfds = request.arg(1);
        let writefds = request.arg(2);
        let exceptfds = request.arg(3);
        let read = match self.filter_fd_set(memory, readfds, nfds, PollInterest::Read)? {
            Ok(count) => count,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let write = match self.filter_fd_set(memory, writefds, nfds, PollInterest::Write)? {
            Ok(count) => count,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let except = match self.filter_fd_set(memory, exceptfds, nfds, PollInterest::Except)? {
            Ok(count) => count,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        Ok(DispatchOutcome::Returned {
            value: (read + write + except) as i64,
        })
    }

    fn filter_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
        interest: PollInterest,
    ) -> Result<Result<usize, i32>, DispatchError> {
        if address == 0 {
            return Ok(Ok(0));
        }
        let mut fd_set = match read_fd_set(memory, address, nfds) {
            Ok(fd_set) => fd_set,
            Err(errno) => return Ok(Err(errno)),
        };
        let mut ready_count = 0usize;
        for fd in 0..nfds {
            if !fd_set_contains(&fd_set, fd) {
                continue;
            }
            let fd = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
            if !self.fd_is_valid(fd) {
                return Ok(Err(LINUX_EBADF));
            }
            if self.poll_ready_events(fd, interest.poll_events()) & interest.poll_events() == 0 {
                fd_set_clear(&mut fd_set, fd as usize);
            } else {
                ready_count += 1;
            }
        }
        if memory.write_bytes(address, &fd_set).is_err() {
            return Ok(Err(LINUX_EFAULT));
        }
        Ok(Ok(ready_count))
    }

    fn ppoll(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pollfds_address = request.arg(0);
        let nfds = usize::try_from(request.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(1)))?;

        let mut ready = 0i64;
        let pollfd_size = core::mem::size_of::<LinuxPollFd>();
        for index in 0..nfds {
            let offset = index
                .checked_mul(pollfd_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let address = match pollfds_address.checked_add(offset) {
                Some(address) => address,
                None => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let mut pollfd = match read_pollfd(memory, address) {
                Ok(pollfd) => pollfd,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            pollfd.revents = self.poll_ready_events(pollfd.fd, pollfd.events);
            if pollfd.revents != 0 {
                ready += 1;
            }
            if memory.write_bytes(address, pollfd.as_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }

        Ok(DispatchOutcome::Returned { value: ready })
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return if is_stdio_fd(fd) {
                requested_events & LINUX_POLLOUT
            } else {
                LINUX_POLLNVAL
            };
        };
        let open = open_file.description.borrow();
        let mut ready = 0;
        match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            OpenDescription::Directory { .. } => {}
            OpenDescription::EventFd { counter, .. } => {
                if requested_events & LINUX_POLLIN != 0 && *counter > 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                ..
            } => {
                if requested_events & LINUX_POLLIN != 0
                    && timerfd_expirations(*clock_id, *interval, *deadline, *expirations).0 > 0
                {
                    ready |= LINUX_POLLIN;
                }
            }
            OpenDescription::Epoll { .. } => {}
            OpenDescription::PipeReader { pipe, .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    let pipe = pipe.borrow();
                    if !pipe.buffer.is_empty() {
                        ready |= LINUX_POLLIN;
                    }
                    if pipe.writers == 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let pipe = pipe.borrow();
                if pipe.readers == 0 {
                    ready |= LINUX_POLLERR;
                } else if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
        }
        ready
    }

    fn pipe2(&mut self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let flags = request.arg(1);
        if flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }

        let Some(read_fd) = self.allocate_fd(3) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if memory.write_bytes(address, pair.as_bytes()).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }

        let pipe = Rc::new(RefCell::new(PipeState::default()));
        let status_flags = flags & LINUX_O_NONBLOCK;
        let fd_flags = linux_fd_flags_from_open_flags(flags);
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::PipeReader {
                    pipe: Rc::clone(&pipe),
                    status_flags,
                })),
                fd_flags,
            },
        );
        self.insert_open_file(
            write_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::PipeWriter {
                    pipe,
                    status_flags,
                })),
                fd_flags,
            },
        );

        DispatchOutcome::Returned { value: 0 }
    }

    fn dup(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let old_fd = request.arg(0) as i32;
        self.duplicate_fd(old_fd, 3, 0)
    }

    fn dup3(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let old_fd = request.arg(0) as i32;
        let new_fd = request.arg(1) as i32;
        let flags = request.arg(2);
        if old_fd == new_fd || flags & !LINUX_O_CLOEXEC != 0 || new_fd < 3 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let Some(open_file) = self.open_files.get(&old_fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let description = Rc::clone(&open_file.description);
        if let Some(replaced) = self.open_files.remove(&new_fd) {
            close_open_file(&replaced);
        }
        retain_open_file(&description);
        self.open_files.insert(
            new_fd,
            OpenFile {
                description,
                fd_flags: linux_fd_flags_from_open_flags(flags),
            },
        );
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    fn fcntl(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let command = request.arg(1);
        let arg = request.arg(2);
        match command {
            LINUX_F_DUPFD => match linux_min_fd(arg) {
                Ok(min_fd) => self.duplicate_fd(fd, min_fd, 0),
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_F_DUPFD_CLOEXEC => match linux_min_fd(arg) {
                Ok(min_fd) => self.duplicate_fd(fd, min_fd, LINUX_FD_CLOEXEC),
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_F_GETPIPE_SZ => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                match &*open_file.description.borrow() {
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
                        DispatchOutcome::Returned {
                            value: LINUX_PIPE_BUF_SIZE,
                        }
                    }
                    _ => DispatchOutcome::Errno { errno: LINUX_EBADF },
                }
            }
            LINUX_F_GETFD => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                DispatchOutcome::Returned {
                    value: open_file.fd_flags as i64,
                }
            }
            LINUX_F_SETFD => {
                let Some(open_file) = self.open_files.get_mut(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                open_file.fd_flags = arg & LINUX_FD_CLOEXEC;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_F_GETFL => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                let open = open_file.description.borrow();
                DispatchOutcome::Returned {
                    value: open.status_flags() as i64,
                }
            }
            LINUX_F_SETFL => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                open_file
                    .description
                    .borrow_mut()
                    .set_status_flags(arg & !LINUX_O_CLOEXEC);
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        }
    }

    fn ioctl(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let ioctl_request = request.arg(1);
        let arg = request.arg(2);
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }

        match ioctl_request {
            LINUX_TIOCGWINSZ if is_stdio_fd(fd) => {
                let winsize = LinuxWinsize::terminal_80x24();
                write_packed(memory, arg, winsize.as_bytes())
            }
            LINUX_TIOCGWINSZ => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            _ => {
                reporter.record(CompatEvent::unhandled_ioctl(fd, ioctl_request, arg));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                }
            }
        }
    }

    fn fd_is_valid(&self, fd: i32) -> bool {
        is_stdio_fd(fd) || self.open_files.contains_key(&fd)
    }

    fn statfs(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let buffer = request.arg(1);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        if let Err(errno) = rootfs.metadata(path) {
            return Ok(DispatchOutcome::Errno {
                errno: rootfs_errno(errno),
            });
        }
        Ok(write_statfs(memory, buffer))
    }

    fn fstatfs(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.open_files.contains_key(&fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        write_statfs(memory, request.arg(1))
    }

    fn capget(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let header_address = request.arg(0);
        let data_address = request.arg(1);
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        if !linux_capability_version_is_supported(header.version) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if header.pid < 0 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        if data_address == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let words = linux_capability_data_words(header.version);
        let empty = vec![LinuxCapabilityData::empty(); words];
        if memory
            .write_bytes(data_address, capability_data_bytes(&empty).as_slice())
            .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn capset(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let header_address = request.arg(0);
        let data_address = request.arg(1);
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        if !linux_capability_version_is_supported(header.version) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if header.pid < 0 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        let words = linux_capability_data_words(header.version);
        let data = match read_capability_data(memory, data_address, words) {
            Ok(data) => data,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        if data.iter().any(|word| !word.is_empty()) {
            return DispatchOutcome::Errno { errno: LINUX_EPERM };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn personality(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let requested = request.arg(0);
        let previous = self.personality;
        if requested != LINUX_PERSONALITY_QUERY {
            self.personality = requested;
        }
        DispatchOutcome::Returned {
            value: previous as i64,
        }
    }

    fn set_tid_address(&self) -> DispatchOutcome {
        self.getpid()
    }

    fn set_robust_list(&self, request: SyscallRequest) -> DispatchOutcome {
        let len = request.arg(1);
        if len == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn clock_gettime(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let address = request.arg(1);
        let Some(duration) = linux_clock_duration(clock_id) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let timespec = linux_timespec_from_duration(duration);
        write_packed(memory, address, timespec.as_bytes())
    }

    fn clock_getres(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let address = request.arg(1);
        if linux_clock_duration(clock_id).is_none() {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if address == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        write_packed(
            memory,
            address,
            LinuxTimespec::new(0, LINUX_CLOCK_RESOLUTION_NSEC).as_bytes(),
        )
    }

    fn rt_sigaction(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let signum = request.arg(0);
        let old_action = request.arg(2);
        let sigset_size = request.arg(3);
        if signum == 0 || sigset_size != LINUX_RT_SIGSET_SIZE {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if old_action != 0
            && memory
                .write_bytes(old_action, LinuxSigaction::empty().as_bytes())
                .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn rt_sigprocmask(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_set = request.arg(2);
        let sigset_size = request.arg(3);
        if sigset_size == 0 || sigset_size > 128 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if old_set != 0 {
            let len = usize::try_from(sigset_size)
                .map_err(|_| DispatchError::LengthTooLarge(sigset_size))?;
            if memory.write_bytes(old_set, &vec![0; len]).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn uname(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        if memory
            .write_bytes(address, LinuxUtsname::carrick_aarch64().as_bytes())
            .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn gettimeofday(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let timeval = request.arg(0);
        let timezone = request.arg(1);
        let now = realtime_duration();
        if timeval != 0 {
            let timeval = linux_timeval_from_duration(now);
            if memory
                .write_bytes(request.arg(0), timeval.as_bytes())
                .is_err()
            {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        }
        if timezone != 0
            && memory
                .write_bytes(timezone, LinuxTimezone::utc().as_bytes())
                .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn getpid(&self) -> DispatchOutcome {
        DispatchOutcome::Returned {
            value: std::process::id() as i64,
        }
    }

    fn openat(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(2);
        if flags & LINUX_O_ACCMODE != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let description = if let Some(contents) = synthetic_proc_file(&path, &self.executable_path)
        {
            OpenDescription::SyntheticFile {
                path,
                contents,
                offset: 0,
                status_flags: flags & !LINUX_O_CLOEXEC,
            }
        } else {
            if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
                return Ok(outcome);
            }
            let Some(rootfs) = &self.rootfs else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            };
            let metadata = match rootfs.metadata(&path) {
                Ok(metadata) => metadata,
                Err(errno) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(errno),
                    });
                }
            };

            match metadata.kind {
                RootFsEntryKind::File => {
                    let contents = match rootfs.read(&path) {
                        Ok(contents) => contents,
                        Err(errno) => {
                            return Ok(DispatchOutcome::Errno {
                                errno: rootfs_errno(errno),
                            });
                        }
                    };
                    OpenDescription::File {
                        path,
                        metadata,
                        contents,
                        offset: 0,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                    }
                }
                RootFsEntryKind::Directory => {
                    let entries = match rootfs.directory_entries(&path) {
                        Ok(entries) => entries,
                        Err(errno) => {
                            return Ok(DispatchOutcome::Errno {
                                errno: rootfs_errno(errno),
                            });
                        }
                    };
                    OpenDescription::Directory {
                        path,
                        metadata,
                        entries,
                        offset: 0,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                    }
                }
                RootFsEntryKind::Symlink => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
            }
        };

        let Some(fd) = self.allocate_fd(3) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        self.insert_open_file(
            fd,
            OpenFile {
                description: Rc::new(RefCell::new(description)),
                fd_flags: linux_fd_flags_from_open_flags(flags),
            },
        );
        Ok(DispatchOutcome::Returned { value: fd as i64 })
    }

    fn close(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if let Some(open_file) = self.open_files.remove(&fd) {
            close_open_file(&open_file);
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::Errno { errno: LINUX_EBADF }
        }
    }

    fn duplicate_fd(&mut self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&old_fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let description = Rc::clone(&open_file.description);
        let Some(new_fd) = self.allocate_fd(min_fd) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        retain_open_file(&description);
        self.open_files.insert(
            new_fd,
            OpenFile {
                description,
                fd_flags,
            },
        );
        DispatchOutcome::Returned {
            value: new_fd as i64,
        }
    }

    fn allocate_fd(&mut self, min_fd: i32) -> Option<i32> {
        let mut fd = min_fd.max(3);
        while self.open_files.contains_key(&fd) {
            fd = fd.checked_add(1)?;
        }
        self.next_fd = self.next_fd.max(fd.saturating_add(1));
        Some(fd)
    }

    fn insert_open_file(&mut self, fd: i32, open_file: OpenFile) {
        retain_open_file(&open_file.description);
        if let Some(replaced) = self.open_files.insert(fd, open_file) {
            close_open_file(&replaced);
        }
    }

    fn install_fd(&mut self, description: OpenDescription, fd_flags: u64) -> DispatchOutcome {
        let Some(fd) = self.allocate_fd(3) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        self.insert_open_file(
            fd,
            OpenFile {
                description: Rc::new(RefCell::new(description)),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: fd as i64 }
    }

    fn getdents64(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let OpenDescription::Directory {
            entries, offset, ..
        } = &mut *open
        else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };

        let mut out = Vec::new();
        while *offset < entries.len() {
            let record = dirent64_record(&entries[*offset], *offset + 1);
            if record.len() > length {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if out.len() + record.len() > length {
                break;
            }
            out.extend_from_slice(&record);
            *offset += 1;
        }

        if memory.write_bytes(address, &out).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned {
            value: out.len() as i64,
        })
    }

    fn lseek(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let offset = request.arg(1) as i64;
        let whence = request.arg(2);
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let mut open = open_file.description.borrow_mut();

        let (current, end) = match &*open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (*offset as i64, contents.len() as i64),
            OpenDescription::Directory {
                entries, offset, ..
            } => (*offset as i64, entries.len() as i64),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        let next = match whence {
            LINUX_SEEK_SET => offset,
            LINUX_SEEK_CUR => current.saturating_add(offset),
            LINUX_SEEK_END => end.saturating_add(offset),
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        if next < 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }

        match &mut *open {
            OpenDescription::File { offset, .. }
            | OpenDescription::Directory { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => *offset = next as usize,
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => {}
        }
        DispatchOutcome::Returned { value: next }
    }

    fn brk(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let requested = request.arg(0);
        if requested == 0 {
            return DispatchOutcome::Returned {
                value: self.brk_current as i64,
            };
        }

        if range_within(requested, 0, LINUX_HEAP_BASE, LINUX_HEAP_SIZE) {
            self.brk_current = requested;
        }
        DispatchOutcome::Returned {
            value: self.brk_current as i64,
        }
    }

    fn mmap(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = request.arg(0);
        let length = request.arg(1);
        let prot = request.arg(2);
        let flags = request.arg(3);
        let fd = request.arg(4) as i32;
        let offset = request.arg(5);

        if length == 0
            || prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0
            || flags & LINUX_MAP_PRIVATE == 0
            || (flags & LINUX_MAP_ANONYMOUS == 0 && offset % LINUX_PAGE_SIZE != 0)
            || (flags & LINUX_MAP_FIXED != 0 && requested % LINUX_PAGE_SIZE != 0)
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let length = match align_up_u64(length, LINUX_PAGE_SIZE) {
            Some(length) => length,
            None => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            }
        };
        let address = match self.next_mmap_address(requested, length, flags) {
            Some(address) => address,
            None => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            }
        };

        let length_usize =
            usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;
        let mut bytes = vec![0; length_usize];
        if flags & LINUX_MAP_ANONYMOUS == 0 {
            let Some(open_file) = self.open_files.get(&fd) else {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            };
            let open = open_file.description.borrow();
            let contents = match &*open {
                OpenDescription::File { contents, .. }
                | OpenDescription::SyntheticFile { contents, .. } => contents,
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
            };
            let offset =
                usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
            if offset < contents.len() {
                let available = &contents[offset..];
                let copy_len = available.len().min(length_usize);
                bytes[..copy_len].copy_from_slice(&available[..copy_len]);
            }
        }

        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: address as i64,
        })
    }

    fn next_mmap_address(&mut self, requested: u64, length: u64, flags: u64) -> Option<u64> {
        if flags & LINUX_MAP_FIXED != 0 {
            if requested == 0 || !range_within(requested, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE)
            {
                return None;
            }
            return Some(requested);
        }

        let address = align_up_u64(self.mmap_next, LINUX_PAGE_SIZE)?;
        if !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return None;
        }
        self.mmap_next = address.checked_add(length)?;
        Some(address)
    }

    fn munmap(&self, request: SyscallRequest) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        if length == 0 || !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn mprotect(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        let prot = request.arg(2);
        if prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if length == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let Ok(length) = usize::try_from(length) else {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        };
        let Some(last_address) = address.checked_add(length as u64 - 1) else {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        };
        if memory.read_bytes(address, 1).is_err() || memory.read_bytes(last_address, 1).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn prlimit64(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let new_limit = request.arg(2);
        let old_limit = request.arg(3);
        if new_limit != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if old_limit != 0 {
            let limit = LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY);
            if memory.write_bytes(old_limit, limit.as_bytes()).is_err() {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn getrandom(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = request.arg(0);
        let length = usize::try_from(request.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(1)))?;
        let mut bytes = vec![0; length];
        if getrandom::fill(&mut bytes).is_err() {
            fill_deterministic_bootstrap_random(&mut bytes);
        }
        if memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn read(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let (contents, offset) = match &mut *open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (contents, offset),
            OpenDescription::EventFd {
                counter, semaphore, ..
            } => return Ok(read_eventfd(memory, address, length, counter, *semaphore)),
            OpenDescription::TimerFd {
                clock_id,
                interval,
                deadline,
                expirations,
                ..
            } => {
                return Ok(read_timerfd(
                    memory,
                    address,
                    length,
                    *clock_id,
                    interval,
                    deadline,
                    expirations,
                ));
            }
            OpenDescription::PipeReader { pipe, status_flags } => {
                return Ok(read_pipe(memory, address, length, pipe, *status_flags));
            }
            OpenDescription::Directory { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EISDIR,
                });
            }
            OpenDescription::Epoll { .. } | OpenDescription::PipeWriter { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let remaining = &contents[*offset..];
        let read_len = remaining.len().min(length);
        let bytes = &remaining[..read_len];
        if memory.write_bytes(address, bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        *offset += read_len;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    fn readv(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let iov = request.arg(1);
        let iovcnt = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        let (contents, offset) = match &mut *open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (contents, offset),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let read_len = read_from_contents_at(memory, contents, *offset, &iovecs)?;
        *offset += read_len;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    fn pread64(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let buffer = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let offset = usize::try_from(request.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(3)))?;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };

        let read_len = if offset < contents.len() {
            let bytes = &contents[offset..][..contents[offset..].len().min(length)];
            if memory.write_bytes(buffer, bytes).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
            bytes.len()
        } else {
            0
        };
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    fn sendfile(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let out_fd = request.arg(0) as i32;
        let in_fd = request.arg(1) as i32;
        let offset_address = request.arg(2);
        let count = usize::try_from(request.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(3)))?;
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let mut offset = match self.sendfile_offset(in_fd, offset_address, memory)? {
            Ok(offset) => offset,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match self.sendfile_bytes(in_fd, offset, count) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let outcome = self.write_output_fd(out_fd, &bytes);
        let DispatchOutcome::Returned { value } = outcome else {
            return Ok(outcome);
        };
        let written = usize::try_from(value).unwrap_or(0);
        offset = offset.saturating_add(written);
        if offset_address == 0 {
            if let Some(open_file) = self.open_files.get(&in_fd) {
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::File {
                        offset: current, ..
                    }
                    | OpenDescription::SyntheticFile {
                        offset: current, ..
                    } => *current = offset,
                    _ => {}
                }
            }
        } else if memory
            .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned { value })
    }

    fn sendfile_offset(
        &self,
        in_fd: i32,
        offset_address: u64,
        memory: &impl GuestMemory,
    ) -> Result<Result<usize, i32>, DispatchError> {
        if offset_address != 0 {
            return match read_u64(memory, offset_address) {
                Ok(offset) => {
                    Ok(Ok(usize::try_from(offset)
                        .map_err(|_| DispatchError::LengthTooLarge(offset))?))
                }
                Err(errno) => Ok(Err(errno)),
            };
        }
        let Some(in_file) = self.open_files.get(&in_fd) else {
            return Ok(Err(LINUX_EBADF));
        };
        let open = in_file.description.borrow();
        match &*open {
            OpenDescription::File { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => Ok(Ok(*offset)),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => Ok(Err(LINUX_EINVAL)),
        }
    }

    fn sendfile_bytes(&self, in_fd: i32, offset: usize, count: usize) -> Result<Vec<u8>, i32> {
        let Some(in_file) = self.open_files.get(&in_fd) else {
            return Err(LINUX_EBADF);
        };
        let open = in_file.description.borrow();
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. } => return Err(LINUX_EINVAL),
        };
        let available = contents.get(offset..).unwrap_or_default();
        let write_len = available.len().min(count);
        Ok(available[..write_len].to_vec())
    }

    fn write(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0);
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let bytes = match memory.read_bytes(address, length) {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        };

        match fd {
            1 => self.stdout.extend_from_slice(&bytes),
            2 => self.stderr.extend_from_slice(&bytes),
            _ => {
                let Some(open_file) = self.open_files.get(&(fd as i32)) else {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                };
                let mut open = open_file.description.borrow_mut();
                match &mut *open {
                    OpenDescription::EventFd { counter, .. } => {
                        return Ok(write_eventfd(&bytes, counter));
                    }
                    OpenDescription::PipeWriter { pipe, .. } => {
                        return Ok(write_pipe(&bytes, pipe));
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                }
            }
        }

        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn write_output_fd(&mut self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        match fd {
            1 => self.stdout.extend_from_slice(bytes),
            2 => self.stderr.extend_from_slice(bytes),
            _ => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                let mut open = open_file.description.borrow_mut();
                let OpenDescription::PipeWriter { pipe, .. } = &mut *open else {
                    return DispatchOutcome::Errno { errno: LINUX_EBADF };
                };
                return write_pipe(bytes, pipe);
            }
        }
        DispatchOutcome::Returned {
            value: bytes.len() as i64,
        }
    }

    fn writev(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0);
        let iov = request.arg(1);
        let iovcnt = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let mut total = 0usize;
        for iovec in iovecs {
            let iov_base = iovec.iov_base;
            let iov_len = usize::try_from(iovec.iov_len)
                .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
            let bytes = match memory.read_bytes(iov_base, iov_len) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            match fd {
                1 => self.stdout.extend_from_slice(&bytes),
                2 => self.stderr.extend_from_slice(&bytes),
                _ => {
                    let Some(open_file) = self.open_files.get(&(fd as i32)) else {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    };
                    let mut open = open_file.description.borrow_mut();
                    let OpenDescription::PipeWriter { pipe, .. } = &mut *open else {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    };
                    let outcome = write_pipe(&bytes, pipe);
                    let DispatchOutcome::Returned { value } = outcome else {
                        return Ok(outcome);
                    };
                    total = total
                        .checked_add(value as usize)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    continue;
                }
            }
            total = total
                .checked_add(bytes.len())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        }

        Ok(DispatchOutcome::Returned {
            value: total as i64,
        })
    }

    fn readlinkat(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let buffer = request.arg(2);
        let buffer_size = usize::try_from(request.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(3)))?;
        if buffer_size == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let target = if path == "/proc/self/exe" || path == "/proc/curproc/exe" {
            self.executable_path.clone()
        } else {
            let Some(rootfs) = &self.rootfs else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            };
            match rootfs.read_link(&path) {
                Ok(target) => target,
                Err(errno) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(errno),
                    });
                }
            }
        };

        let bytes = target.as_bytes();
        let written = bytes.len().min(buffer_size);
        if memory.write_bytes(buffer, &bytes[..written]).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
    }

    fn newfstatat(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let statbuf = request.arg(2);
        let flags = request.arg(3);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        if path.is_empty() && flags & LINUX_AT_EMPTY_PATH != 0 {
            return Ok(self.write_fd_stat(dirfd as i32, statbuf, memory));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(contents) = synthetic_proc_file(&path, &self.executable_path) {
            return Ok(write_synthetic_stat(memory, statbuf, &path, contents.len()));
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = match rootfs.metadata(path) {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };
        Ok(write_stat(memory, statbuf, &metadata))
    }

    fn fstat(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        self.write_fd_stat(request.arg(0) as i32, request.arg(1), memory)
    }

    fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let metadata = match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => metadata,
            OpenDescription::SyntheticFile { path, contents, .. } => {
                return write_synthetic_stat(memory, statbuf, path, contents.len());
            }
            OpenDescription::EventFd { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[eventfd]", 0);
            }
            OpenDescription::TimerFd { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[timerfd]", 0);
            }
            OpenDescription::Epoll { .. } => {
                return write_synthetic_stat(memory, statbuf, "anon_inode:[eventpoll]", 0);
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
                return write_synthetic_stat(memory, statbuf, "pipe:[carrick]", 0);
            }
        };
        write_stat(memory, statbuf, metadata)
    }

    fn exit(&self, request: SyscallRequest) -> DispatchOutcome {
        DispatchOutcome::Exit {
            code: request.arg(0) as i32,
        }
    }

    fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, i32> {
        if path.is_empty() || Path::new(path).is_absolute() {
            return Ok(path.to_owned());
        }
        if dirfd == LINUX_AT_FDCWD {
            return Ok(join_rootfs_path(&self.cwd, path));
        }

        match self.open_files.get(&(dirfd as i32)) {
            Some(open_file) => match &*open_file.description.borrow() {
                OpenDescription::Directory { path: dir, .. } => Ok(join_rootfs_path(dir, path)),
                OpenDescription::File { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. } => Err(LINUX_ENOTDIR),
            },
            None => Err(LINUX_EBADF),
        }
    }
}

fn write_packed(memory: &mut impl GuestMemory, address: u64, bytes: &[u8]) -> DispatchOutcome {
    if memory.write_bytes(address, bytes).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

fn write_statfs(memory: &mut impl GuestMemory, statfsbuf: u64) -> DispatchOutcome {
    let blocks = 1_048_576;
    let statfs = LinuxStatfs {
        f_type: LINUX_OVERLAYFS_SUPER_MAGIC,
        f_bsize: LINUX_PAGE_SIZE as i64,
        f_blocks: blocks,
        f_bfree: blocks / 2,
        f_bavail: blocks / 2,
        f_files: 1_048_576,
        f_ffree: 1_048_576,
        f_fsid: [0, 0],
        f_namelen: 255,
        f_frsize: LINUX_PAGE_SIZE as i64,
        f_flags: 0,
        f_spare: [0; 4],
    };
    write_packed(memory, statfsbuf, statfs.as_bytes())
}

fn linux_fd_flags_from_open_flags(flags: u64) -> u64 {
    if flags & LINUX_O_CLOEXEC != 0 {
        LINUX_FD_CLOEXEC
    } else {
        0
    }
}

fn is_stdio_fd(fd: i32) -> bool {
    matches!(fd, 0..=2)
}

fn retain_open_file(description: &Rc<RefCell<OpenDescription>>) {
    match &*description.borrow() {
        OpenDescription::PipeReader { pipe, .. } => {
            let mut pipe = pipe.borrow_mut();
            pipe.readers = pipe.readers.saturating_add(1);
        }
        OpenDescription::PipeWriter { pipe, .. } => {
            let mut pipe = pipe.borrow_mut();
            pipe.writers = pipe.writers.saturating_add(1);
        }
        _ => {}
    }
}

fn close_open_file(open_file: &OpenFile) {
    match &*open_file.description.borrow() {
        OpenDescription::PipeReader { pipe, .. } => {
            let mut pipe = pipe.borrow_mut();
            pipe.readers = pipe.readers.saturating_sub(1);
        }
        OpenDescription::PipeWriter { pipe, .. } => {
            let mut pipe = pipe.borrow_mut();
            pipe.writers = pipe.writers.saturating_sub(1);
        }
        _ => {}
    }
}

fn linux_min_fd(value: u64) -> Result<i32, i32> {
    i32::try_from(value).map_err(|_| LINUX_EINVAL)
}

fn linux_clock_duration(clock_id: u64) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_COARSE => Some(realtime_duration()),
        LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_MONOTONIC_COARSE
        | LINUX_CLOCK_BOOTTIME => Some(monotonic_duration()),
        _ => None,
    }
}

fn realtime_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

fn monotonic_duration() -> Duration {
    MONOTONIC_START.get_or_init(Instant::now).elapsed()
}

fn linux_timespec_from_duration(duration: Duration) -> LinuxTimespec {
    LinuxTimespec::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_nanos()),
    )
}

fn linux_timeval_from_duration(duration: Duration) -> LinuxTimeval {
    LinuxTimeval::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_micros()),
    )
}

fn write_stat(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: inode_for_path(&metadata.path),
        st_mode: linux_mode(metadata),
        st_nlink: if metadata.kind == RootFsEntryKind::Directory {
            2
        } else {
            1
        },
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: metadata.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks_512(metadata.size),
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
        __unused4: 0,
        __unused5: 0,
    };

    if memory.write_bytes(statbuf, stat.as_bytes()).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

fn write_synthetic_stat(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    path: &str,
    size: usize,
) -> DispatchOutcome {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: inode_for_path(Path::new(path)),
        st_mode: LINUX_S_IFREG | 0o444,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        __pad1: 0,
        st_size: size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks_512(size),
        st_atime: 0,
        st_atime_nsec: 0,
        st_mtime: 0,
        st_mtime_nsec: 0,
        st_ctime: 0,
        st_ctime_nsec: 0,
        __unused4: 0,
        __unused5: 0,
    };
    write_packed(memory, statbuf, stat.as_bytes())
}

fn synthetic_proc_file(path: &str, executable_path: &str) -> Option<Vec<u8>> {
    match path {
        "/proc/self/maps" => Some(synthetic_proc_maps(executable_path).into_bytes()),
        "/proc/cpuinfo" => Some(synthetic_proc_cpuinfo().to_vec()),
        _ => None,
    }
}

fn synthetic_proc_maps(executable_path: &str) -> String {
    format!(
        "0000000000400000-0000000000410000 r-xp 00000000 00:00 0 {executable_path}\n\
         {heap_base:016x}-{heap_end:016x} rw-p 00000000 00:00 0 [heap]\n\
         {mmap_base:016x}-{mmap_end:016x} rwxp 00000000 00:00 0 [carrick-mmap]\n\
         0000007fffe00000-0000008000000000 rw-p 00000000 00:00 0 [stack]\n",
        heap_base = LINUX_HEAP_BASE,
        heap_end = LINUX_HEAP_BASE + LINUX_HEAP_SIZE,
        mmap_base = LINUX_MMAP_BASE,
        mmap_end = LINUX_MMAP_BASE + LINUX_MMAP_SIZE,
    )
}

fn synthetic_proc_cpuinfo() -> &'static [u8] {
    b"processor\t: 0\n\
BogoMIPS\t: 48.00\n\
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n\
CPU implementer\t: 0x61\n\
CPU architecture\t: 8\n\
CPU variant\t: 0x0\n\
CPU part\t: 0x000\n\
CPU revision\t: 0\n\
\n\
Hardware\t: Carrick\n"
}

fn read_eventfd(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    counter: &mut u64,
    semaphore: bool,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxEventfdValue>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    if *counter == 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        };
    }
    let value = if semaphore { 1 } else { *counter };
    let eventfd_value = LinuxEventfdValue { value };
    if memory
        .write_bytes(address, eventfd_value.as_bytes())
        .is_err()
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    if semaphore {
        *counter -= 1;
    } else {
        *counter = 0;
    }
    DispatchOutcome::Returned {
        value: core::mem::size_of::<LinuxEventfdValue>() as i64,
    }
}

fn write_eventfd(bytes: &[u8], counter: &mut u64) -> DispatchOutcome {
    if bytes.len() != core::mem::size_of::<LinuxEventfdValue>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let Ok(value) = LinuxEventfdValue::read_from_bytes(bytes) else {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    };
    let increment = value.value;
    if increment == u64::MAX {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let Some(next) = counter.checked_add(increment) else {
        return DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        };
    };
    *counter = next;
    DispatchOutcome::Returned {
        value: core::mem::size_of::<LinuxEventfdValue>() as i64,
    }
}

fn read_timerfd(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    clock_id: u64,
    interval: &Option<Duration>,
    deadline: &mut Option<Duration>,
    expirations: &mut u64,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxTimerfdExpirations>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let (ready, next_deadline) = timerfd_expirations(clock_id, *interval, *deadline, *expirations);
    *deadline = next_deadline;
    *expirations = ready;
    if *expirations == 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        };
    }
    let value = LinuxTimerfdExpirations {
        expirations: *expirations,
    };
    if memory.write_bytes(address, value.as_bytes()).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    *expirations = 0;
    DispatchOutcome::Returned {
        value: core::mem::size_of::<LinuxTimerfdExpirations>() as i64,
    }
}

fn timerfd_itimerspec(
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
) -> LinuxItimerspec {
    let now = linux_clock_duration(clock_id).unwrap_or(Duration::ZERO);
    let remaining = deadline.map(|deadline| deadline.saturating_sub(now));
    LinuxItimerspec::new(
        linux_timespec_from_optional_duration(interval),
        linux_timespec_from_optional_duration(remaining),
    )
}

fn timerfd_expirations(
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = linux_clock_duration(clock_id) else {
        return (expirations, Some(deadline));
    };
    if now < deadline {
        return (expirations, Some(deadline));
    }
    let Some(interval) = interval else {
        return (expirations.saturating_add(1), None);
    };
    if interval.is_zero() {
        return (expirations.saturating_add(1), None);
    }

    let now_nanos = duration_to_nanos(now);
    let deadline_nanos = duration_to_nanos(deadline);
    let interval_nanos = duration_to_nanos(interval);
    let elapsed_periods = ((now_nanos - deadline_nanos) / interval_nanos).saturating_add(1);
    let count = u64::try_from(elapsed_periods).unwrap_or(u64::MAX);
    let next_deadline_nanos =
        deadline_nanos.saturating_add(interval_nanos.saturating_mul(elapsed_periods));
    (
        expirations.saturating_add(count),
        Some(duration_from_nanos_saturating(next_deadline_nanos)),
    )
}

fn itimerspec_durations(
    spec: LinuxItimerspec,
) -> Result<(Option<Duration>, Option<Duration>), i32> {
    let interval = spec.it_interval;
    let value = spec.it_value;
    Ok((
        duration_from_linux_timespec(interval)?,
        duration_from_linux_timespec(value)?,
    ))
}

fn duration_from_linux_timespec(timespec: LinuxTimespec) -> Result<Option<Duration>, i32> {
    let seconds = timespec.tv_sec;
    let nanoseconds = timespec.tv_nsec;
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return Err(LINUX_EINVAL);
    }
    if seconds == 0 && nanoseconds == 0 {
        return Ok(None);
    }
    Ok(Some(Duration::new(seconds as u64, nanoseconds as u32)))
}

fn linux_timespec_from_optional_duration(duration: Option<Duration>) -> LinuxTimespec {
    duration.map_or(LinuxTimespec::new(0, 0), linux_timespec_from_duration)
}

fn duration_to_nanos(duration: Duration) -> u128 {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    u128::from(duration.as_secs()) * NANOS_PER_SEC + u128::from(duration.subsec_nanos())
}

fn duration_from_nanos_saturating(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let seconds = nanos / NANOS_PER_SEC;
    if seconds > u128::from(u64::MAX) {
        return Duration::new(u64::MAX, 999_999_999);
    }
    Duration::new(seconds as u64, (nanos % NANOS_PER_SEC) as u32)
}

fn read_pipe(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    pipe: &Rc<RefCell<PipeState>>,
    _status_flags: u64,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let mut pipe = pipe.borrow_mut();
    if pipe.buffer.is_empty() {
        if pipe.writers == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        return DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        };
    }

    let read_len = pipe.buffer.len().min(length);
    let bytes = pipe
        .buffer
        .iter()
        .take(read_len)
        .copied()
        .collect::<Vec<_>>();
    if memory.write_bytes(address, &bytes).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    pipe.buffer.drain(..read_len);
    DispatchOutcome::Returned {
        value: read_len as i64,
    }
}

fn write_pipe(bytes: &[u8], pipe: &Rc<RefCell<PipeState>>) -> DispatchOutcome {
    let mut pipe = pipe.borrow_mut();
    if pipe.readers == 0 {
        return DispatchOutcome::Errno { errno: LINUX_EPIPE };
    }
    pipe.buffer.extend(bytes.iter().copied());
    DispatchOutcome::Returned {
        value: bytes.len() as i64,
    }
}

fn read_epoll_event(memory: &impl GuestMemory, address: u64) -> Result<LinuxEpollEvent, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxEpollEvent>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxEpollEvent::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_pollfd(memory: &impl GuestMemory, address: u64) -> Result<LinuxPollFd, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxPollFd>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxPollFd::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_capability_header(
    memory: &impl GuestMemory,
    address: u64,
) -> Result<LinuxCapabilityHeader, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxCapabilityHeader>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxCapabilityHeader::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_capability_data(
    memory: &impl GuestMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxCapabilityData>, i32> {
    let size = core::mem::size_of::<LinuxCapabilityData>();
    let length = count.checked_mul(size).ok_or(LINUX_EINVAL)?;
    let bytes = memory
        .read_bytes(address, length)
        .map_err(|_| LINUX_EFAULT)?;
    bytes
        .chunks_exact(size)
        .map(|chunk| LinuxCapabilityData::read_from_bytes(chunk).map_err(|_| LINUX_EFAULT))
        .collect()
}

fn read_u64(memory: &impl GuestMemory, address: u64) -> Result<u64, i32> {
    let bytes = memory.read_bytes(address, 8).map_err(|_| LINUX_EFAULT)?;
    Ok(u64::from_ne_bytes(
        bytes.as_slice().try_into().map_err(|_| LINUX_EFAULT)?,
    ))
}

fn capability_data_bytes(data: &[LinuxCapabilityData]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(data.len() * core::mem::size_of::<LinuxCapabilityData>());
    for word in data {
        bytes.extend_from_slice(word.as_bytes());
    }
    bytes
}

fn linux_capability_version_is_supported(version: u32) -> bool {
    matches!(
        version,
        LINUX_CAPABILITY_VERSION_1 | LINUX_CAPABILITY_VERSION_2 | LINUX_CAPABILITY_VERSION_3
    )
}

fn linux_capability_data_words(version: u32) -> usize {
    if version == LINUX_CAPABILITY_VERSION_1 {
        1
    } else {
        2
    }
}

fn read_fd_set(memory: &impl GuestMemory, address: u64, nfds: usize) -> Result<Vec<u8>, i32> {
    let length = linux_fd_set_len(nfds).ok_or(LINUX_EINVAL)?;
    memory.read_bytes(address, length).map_err(|_| LINUX_EFAULT)
}

fn fd_set_contains(fd_set: &[u8], fd: usize) -> bool {
    fd_set
        .get(fd / 8)
        .is_some_and(|byte| byte & (1 << (fd % 8)) != 0)
}

fn fd_set_clear(fd_set: &mut [u8], fd: usize) {
    if let Some(byte) = fd_set.get_mut(fd / 8) {
        *byte &= !(1 << (fd % 8));
    }
}

fn linux_fd_set_len(nfds: usize) -> Option<usize> {
    nfds.checked_add(63)?.checked_div(64)?.checked_mul(8)
}

fn read_itimerspec(memory: &impl GuestMemory, address: u64) -> Result<LinuxItimerspec, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxItimerspec>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxItimerspec::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_iovecs(
    memory: &impl GuestMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, i32> {
    if count > LINUX_IOV_MAX {
        return Err(LINUX_EINVAL);
    }

    let mut iovecs = Vec::with_capacity(count);
    let size = core::mem::size_of::<LinuxIovec>();
    for index in 0..count {
        let offset = index
            .checked_mul(size)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(LINUX_EINVAL)?;
        let iovec_address = address.checked_add(offset).ok_or(LINUX_EFAULT)?;
        let bytes = memory
            .read_bytes(iovec_address, size)
            .map_err(|_| LINUX_EFAULT)?;
        iovecs.push(LinuxIovec::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)?);
    }
    Ok(iovecs)
}

fn read_from_contents_at(
    memory: &mut impl GuestMemory,
    contents: &[u8],
    mut offset: usize,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        let remaining = contents.get(offset..).unwrap_or_default();
        let read_len = remaining.len().min(iov_len);
        if read_len == 0 {
            break;
        }
        if memory
            .write_bytes(iov_base, &remaining[..read_len])
            .is_err()
        {
            return Ok(total);
        }
        offset += read_len;
        total = total
            .checked_add(read_len)
            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
        if read_len < iov_len {
            break;
        }
    }
    Ok(total)
}

fn linux_mode(metadata: &RootFsMetadata) -> u32 {
    let kind = match metadata.kind {
        RootFsEntryKind::File => LINUX_S_IFREG,
        RootFsEntryKind::Directory => LINUX_S_IFDIR,
        RootFsEntryKind::Symlink => LINUX_S_IFLNK,
    };
    kind | (metadata.mode & 0o7777)
}

fn blocks_512(size: usize) -> i64 {
    if size == 0 {
        0
    } else {
        size.div_ceil(512) as i64
    }
}

fn dirent64_record(entry: &RootFsDirEntry, next_offset: usize) -> Vec<u8> {
    let name = entry.name.as_bytes();
    let record_len = align_to(LINUX_DIRENT64_HEADER_SIZE + name.len() + 1, 8);
    let header = LinuxDirent64Header {
        d_ino: inode_for_path(&entry.metadata.path),
        d_off: next_offset as i64,
        d_reclen: record_len as u16,
        d_type: linux_dirent_type(entry.metadata.kind),
    };

    let mut out = vec![0; record_len];
    out[..LINUX_DIRENT64_HEADER_SIZE].copy_from_slice(header.as_bytes());
    out[LINUX_DIRENT64_HEADER_SIZE..LINUX_DIRENT64_HEADER_SIZE + name.len()].copy_from_slice(name);
    out
}

fn linux_dirent_type(kind: RootFsEntryKind) -> u8 {
    match kind {
        RootFsEntryKind::File => LINUX_DT_REG,
        RootFsEntryKind::Directory => LINUX_DT_DIR,
        RootFsEntryKind::Symlink => LINUX_DT_LNK,
    }
}

fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    Some(value.div_ceil(alignment).checked_mul(alignment)?)
}

fn range_within(address: u64, length: u64, base: u64, size: u64) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    let Some(limit) = base.checked_add(size) else {
        return false;
    };
    address >= base && end <= limit
}

fn fill_deterministic_bootstrap_random(bytes: &mut [u8]) {
    let mut state = 0xca22_1c_u64;
    for byte in bytes {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        *byte = state as u8;
    }
}

fn inode_for_path(path: &Path) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in path.as_os_str().as_encoded_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash.max(1)
}

fn join_rootfs_path(base: &str, path: &str) -> String {
    if base == "/" {
        format!("/{path}")
    } else {
        format!("{}/{path}", base.trim_end_matches('/'))
    }
}

fn display_rootfs_path(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path.display())
    }
}

fn rootfs_errno(error: RootFsError) -> i32 {
    match error {
        RootFsError::NotFound(_) => LINUX_ENOENT,
        RootFsError::UnsafePath(_) | RootFsError::Utf8(_) | RootFsError::TooManySymlinks(_) => {
            LINUX_EINVAL
        }
        RootFsError::Io(_) => LINUX_EINVAL,
    }
}

fn read_guest_c_string(memory: &impl GuestMemory, address: u64) -> Result<String, i32> {
    let mut bytes = Vec::new();
    for offset in 0..MAX_GUEST_PATH {
        let address = address
            .checked_add(offset as u64)
            .ok_or(LINUX_ENAMETOOLONG)?;
        let byte = memory
            .read_bytes(address, 1)
            .map_err(|_| LINUX_EFAULT)?
            .into_iter()
            .next()
            .ok_or(LINUX_EFAULT)?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| LINUX_EINVAL);
        }
        bytes.push(byte);
    }
    Err(LINUX_ENAMETOOLONG)
}
