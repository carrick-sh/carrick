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
    LinuxItimerspec, LinuxItimerval, LinuxOpenHow, LinuxPollFd, LinuxRlimit, LinuxRusage, LinuxSigaction, LinuxSysinfo,
    LinuxSigaltstack, LinuxStat, LinuxStatfs, LinuxStatx, LinuxStatxTimestamp,
    LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimezone, LinuxTms,
    LinuxTermios, LinuxUtsname, LinuxWinsize,
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
pub const LINUX_ECHILD: i32 = 10;
pub const LINUX_EAGAIN: i32 = 11;
pub const LINUX_EINTR: i32 = 4;
pub const LINUX_ENOMEM: i32 = 12;
pub const LINUX_EACCES: i32 = 13;
pub const LINUX_EFAULT: i32 = 14;
pub const LINUX_EEXIST: i32 = 17;
pub const LINUX_EPIPE: i32 = 32;
pub const LINUX_ESPIPE: i32 = 29;
pub const LINUX_EROFS: i32 = 30;
pub const LINUX_ENOTSUP: i32 = 95;
pub const LINUX_FALLOC_FL_KEEP_SIZE: u64 = 0x01;
pub const LINUX_FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
pub const LINUX_FALLOC_FL_COLLAPSE_RANGE: u64 = 0x08;
pub const LINUX_FALLOC_FL_ZERO_RANGE: u64 = 0x10;
pub const LINUX_FALLOC_FL_INSERT_RANGE: u64 = 0x20;
pub const LINUX_FALLOC_FL_UNSHARE_RANGE: u64 = 0x40;
pub const LINUX_FALLOC_FL_SUPPORTED: u64 = LINUX_FALLOC_FL_KEEP_SIZE
    | LINUX_FALLOC_FL_PUNCH_HOLE
    | LINUX_FALLOC_FL_COLLAPSE_RANGE
    | LINUX_FALLOC_FL_ZERO_RANGE
    | LINUX_FALLOC_FL_INSERT_RANGE
    | LINUX_FALLOC_FL_UNSHARE_RANGE;
pub const LINUX_ENOTDIR: i32 = 20;
pub const LINUX_EISDIR: i32 = 21;
pub const LINUX_EINVAL: i32 = 22;
pub const LINUX_ENOTTY: i32 = 25;
pub const LINUX_ERANGE: i32 = 34;
pub const LINUX_ENAMETOOLONG: i32 = 36;
pub const LINUX_ENOSYS: i32 = 38;
pub const LINUX_E2BIG: i32 = 7;
pub const LINUX_ETIMEDOUT: i32 = 110;
pub const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
pub const LINUX_AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const LINUX_AT_EACCESS: u64 = 0x200;
pub const LINUX_AT_EMPTY_PATH: u64 = 0x1000;
pub const LINUX_AT_REMOVEDIR: u64 = 0x200;
pub const LINUX_AT_NO_AUTOMOUNT: u64 = 0x800;
pub const LINUX_AT_STATX_FORCE_SYNC: u64 = 0x2000;
pub const LINUX_AT_STATX_DONT_SYNC: u64 = 0x4000;
pub const LINUX_UTIME_NOW: i64 = (1 << 30) - 1;
pub const LINUX_UTIME_OMIT: i64 = (1 << 30) - 2;
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
pub const LINUX_MADV_NORMAL: u64 = 0;
pub const LINUX_MADV_RANDOM: u64 = 1;
pub const LINUX_MADV_SEQUENTIAL: u64 = 2;
pub const LINUX_MADV_WILLNEED: u64 = 3;
pub const LINUX_MADV_DONTNEED: u64 = 4;
pub const LINUX_MADV_FREE: u64 = 8;
pub const LINUX_MREMAP_MAYMOVE: u64 = 0x01;
pub const LINUX_MREMAP_FIXED: u64 = 0x02;
pub const LINUX_MREMAP_DONTUNMAP: u64 = 0x04;
pub const LINUX_MS_ASYNC: u64 = 0x01;
pub const LINUX_MS_INVALIDATE: u64 = 0x02;
pub const LINUX_MS_SYNC: u64 = 0x04;
pub const LINUX_MCL_CURRENT: u64 = 0x01;
pub const LINUX_MCL_FUTURE: u64 = 0x02;
pub const LINUX_MCL_ONFAULT: u64 = 0x04;
pub const LINUX_PRIO_PROCESS: u64 = 0;
pub const LINUX_PRIO_PGRP: u64 = 1;
pub const LINUX_PRIO_USER: u64 = 2;
pub const LINUX_DEFAULT_UMASK: u32 = 0o022;
pub const LINUX_RLIM_INFINITY: u64 = u64::MAX;
pub const LINUX_RUSAGE_SELF: i32 = 0;
pub const LINUX_RUSAGE_CHILDREN: i32 = -1;
pub const LINUX_RUSAGE_THREAD: i32 = 1;
pub const LINUX_CLK_TCK: i64 = 100;
pub const LINUX_OVERLAYFS_SUPER_MAGIC: i64 = 0x794c7630;
const LINUX_EFD_SEMAPHORE: u64 = 0x1;
const LINUX_EFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_EFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_EPOLL_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_EPOLL_CTL_ADD: u64 = 1;
const LINUX_EPOLL_CTL_DEL: u64 = 2;
const LINUX_EPOLL_CTL_MOD: u64 = 3;
const LINUX_EPOLLIN: u32 = 0x001;
const LINUX_LOCK_SH: u64 = 1;
const LINUX_LOCK_EX: u64 = 2;
const LINUX_LOCK_NB: u64 = 4;
const LINUX_LOCK_UN: u64 = 8;
const LINUX_POLLIN: i16 = 0x0001;
const LINUX_POLLOUT: i16 = 0x0004;
const LINUX_POLLERR: i16 = 0x0008;
const LINUX_POLLHUP: i16 = 0x0010;
const LINUX_POLLNVAL: i16 = 0x0020;
const LINUX_TFD_NONBLOCK: u64 = LINUX_O_NONBLOCK;
const LINUX_TFD_CLOEXEC: u64 = LINUX_O_CLOEXEC;
const LINUX_TIMER_ABSTIME: u64 = 0x1;
const LINUX_SPLICE_F_MOVE: u64 = 0x1;
const LINUX_SPLICE_F_NONBLOCK: u64 = 0x2;
const LINUX_SPLICE_F_MORE: u64 = 0x4;
const LINUX_SPLICE_F_GIFT: u64 = 0x8;
const LINUX_SPLICE_SUPPORTED_FLAGS: u64 =
    LINUX_SPLICE_F_MOVE | LINUX_SPLICE_F_NONBLOCK | LINUX_SPLICE_F_MORE | LINUX_SPLICE_F_GIFT;
const LINUX_FUTEX_WAIT: u64 = 0;
const LINUX_FUTEX_WAKE: u64 = 1;
const LINUX_FUTEX_CMD_MASK: u64 = 0x7f;
const LINUX_FUTEX_PRIVATE_FLAG: u64 = 128;
const LINUX_FUTEX_CLOCK_REALTIME: u64 = 256;
const LINUX_MEMBARRIER_CMD_QUERY: u64 = 0;
const LINUX_TCGETS: u64 = 0x5401;
const LINUX_TCSETS: u64 = 0x5402;
const LINUX_TCSETSW: u64 = 0x5403;
const LINUX_TCSETSF: u64 = 0x5404;
const LINUX_TIOCSCTTY: u64 = 0x540E;
const LINUX_TIOCGPGRP: u64 = 0x540F;
const LINUX_TIOCSPGRP: u64 = 0x5410;
const LINUX_TIOCGWINSZ: u64 = 0x5413;
const LINUX_FIONREAD: u64 = 0x541B;
const LINUX_FIONBIO: u64 = 0x5421;
const LINUX_TIOCNOTTY: u64 = 0x5422;
const LINUX_TIOCGSID: u64 = 0x5429;
const LINUX_BOOTSTRAP_PGID: i32 = 1;
const LINUX_BOOTSTRAP_SID: i32 = 1;
const LINUX_PIPE_BUF_SIZE: i64 = 65_536;
const LINUX_RT_SIGSET_SIZE: u64 = 8;
const LINUX_MAX_SIGNUM: u64 = 64;
const LINUX_BOOTSTRAP_PID: u64 = 1;
#[allow(dead_code)]
const LINUX_SS_ONSTACK: u64 = 1;
const LINUX_SS_DISABLE: u64 = 2;
const LINUX_MINSIGSTKSZ: u64 = 2048;
const LINUX_BOOTSTRAP_AFFINITY_BYTES: usize = 8;
const LINUX_CLOCK_REALTIME: u64 = 0;
const LINUX_CLOCK_MONOTONIC: u64 = 1;
const LINUX_CLOCK_MONOTONIC_RAW: u64 = 4;
const LINUX_CLOCK_REALTIME_COARSE: u64 = 5;
const LINUX_CLOCK_MONOTONIC_COARSE: u64 = 6;
const LINUX_CLOCK_BOOTTIME: u64 = 7;
const LINUX_CLOCK_REALTIME_ALARM: u64 = 8;
const LINUX_CLOCK_BOOTTIME_ALARM: u64 = 9;
const LINUX_CLOCK_TAI: u64 = 11;
const LINUX_CLOCK_RESOLUTION_NSEC: i64 = 1_000_000;
const LINUX_ITIMER_REAL: u64 = 0;
const LINUX_ITIMER_VIRTUAL: u64 = 1;
const LINUX_ITIMER_PROF: u64 = 2;
const LINUX_TASK_COMM_LEN: usize = 16;
const LINUX_CAPABILITY_VERSION_1: u32 = 0x1998_0330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x2007_1026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const LINUX_PERSONALITY_QUERY: u64 = 0xffff_ffff;
const LINUX_PR_GET_DUMPABLE: u64 = 3;
const LINUX_PR_SET_DUMPABLE: u64 = 4;
const LINUX_PR_SET_NAME: u64 = 15;
const LINUX_PR_GET_NAME: u64 = 16;
const LINUX_P_ALL: u64 = 0;
const LINUX_P_PID: u64 = 1;
const LINUX_P_PGID: u64 = 2;
const LINUX_P_PIDFD: u64 = 3;
const LINUX_WNOHANG: u64 = 1;
const LINUX_WUNTRACED: u64 = 2;
const LINUX_WSTOPPED: u64 = 2;
const LINUX_WEXITED: u64 = 4;
const LINUX_WCONTINUED: u64 = 8;
const LINUX_WNOWAIT: u64 = 0x0100_0000;
const LINUX_WAITID_STATE_MASK: u64 = LINUX_WEXITED | LINUX_WSTOPPED | LINUX_WCONTINUED;
const LINUX_WAITID_SUPPORTED_FLAGS: u64 = LINUX_WAITID_STATE_MASK | LINUX_WNOHANG | LINUX_WNOWAIT;
const LINUX_WCLONE: u64 = 0x8000_0000;
const LINUX_WALL: u64 = 0x4000_0000;
const LINUX_WNOTHREAD: u64 = 0x2000_0000;
const LINUX_WAIT4_SUPPORTED_FLAGS: u64 = LINUX_WNOHANG
    | LINUX_WUNTRACED
    | LINUX_WCONTINUED
    | LINUX_WCLONE
    | LINUX_WALL
    | LINUX_WNOTHREAD;
const LINUX_STATX_BASIC_STATS: u32 = 0x7ff;
const LINUX_STATX_RESERVED: u64 = 0x8000_0000;
const MAX_GUEST_PATH: usize = 4096;
const LINUX_IOV_MAX: usize = 1024;
const LINUX_OPEN_HOW_SIZE: u64 = core::mem::size_of::<LinuxOpenHow>() as u64;

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
    /// `clone(2)` with process-creation flags. The runtime must perform
    /// a real macOS fork against the trap engine, then write the child
    /// pid (parent) or 0 (child) into x0 to complete the syscall.
    Fork,
    /// `execve(2)` succeeded so far in the dispatcher (path readable,
    /// argv/envp resolved). The runtime must:
    ///   1. Tear down the current guest address space.
    ///   2. Load the new ELF (handling the interpreter chain).
    ///   3. Rebuild the trap engine's mappings and vCPU state.
    /// Because `execve` does not return on success, the syscall has
    /// no retval to write into x0 — the runtime simply resumes the
    /// loop with the new entry point.
    Execve {
        path: String,
        argv: Vec<String>,
        env: Vec<String>,
    },
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match *self {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => (-(errno as i64), Some(errno)),
            DispatchOutcome::Exit { code } => (code as i64, None),
            DispatchOutcome::Fork => (0, None),
            DispatchOutcome::Execve { .. } => (0, None),
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
    dumpable: i64,
    task_name: [u8; LINUX_TASK_COMM_LEN],
    umask: u32,
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
    /// Host kernel pipe end backed by a real macOS file descriptor.
    /// Survives `libc::fork(2)` natively — both parent and child see
    /// the same kernel pipe object, so the post-fork sh-pipe demo
    /// can actually carry data across the carrick process boundary.
    HostPipe {
        host_fd: i32,
        is_read_end: bool,
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
enum TtyFdKind {
    Stdio,
    Other,
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
            | OpenDescription::PipeWriter { status_flags, .. }
            | OpenDescription::HostPipe { status_flags, .. } => *status_flags,
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
            | OpenDescription::PipeWriter { status_flags, .. }
            | OpenDescription::HostPipe { status_flags, .. } => *status_flags = next,
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
            dumpable: 1,
            task_name: linux_task_name_from_bytes(b"carrick"),
            umask: LINUX_DEFAULT_UMASK,
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

    /// Borrow the dispatcher's rootfs. Used by the runtime when the
    /// dispatcher returns `DispatchOutcome::Execve` and the new image
    /// has to be loaded from the same image layers.
    pub fn rootfs(&self) -> Option<&RootFs> {
        self.rootfs.as_ref()
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Called after `libc::fork(2)` returns into a child: the child
    /// inherited the parent's buffered stdout/stderr, but we don't
    /// want to re-print those bytes when the child eventually exits
    /// via the `forked_child_exit` path. The parent's full buffer
    /// goes out through its own JSON report.
    pub fn clear_output_buffers(&mut self) {
        self.stdout.clear();
        self.stderr.clear();
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
            5..=16 => self.xattr_unsupported(),
            17 => self.getcwd(request, memory)?,
            19 => self.eventfd2(request),
            20 => self.epoll_create1(request),
            21 => self.epoll_ctl(request, memory)?,
            22 => self.epoll_pwait(request, memory)?,
            23 => self.dup(request),
            24 => self.dup3(request),
            25 => self.fcntl(request),
            29 => self.ioctl(request, memory, reporter),
            32 => self.flock(request),
            33 => self.mknodat(request, memory)?,
            34 => self.mkdirat(request, memory)?,
            35 => self.unlinkat(request, memory)?,
            36 => self.symlinkat(request, memory)?,
            37 => self.linkat(request, memory)?,
            38 => self.renameat(request, memory)?,
            43 => self.statfs(request, memory)?,
            44 => self.fstatfs(request, memory),
            45 => self.truncate(request, memory)?,
            46 => self.ftruncate(request),
            47 => self.fallocate(request),
            48 => self.faccessat(request, memory)?,
            49 => self.chdir(request, memory)?,
            50 => self.fchdir(request),
            52 => self.fchmod(request),
            53 => self.fchmodat(request, memory)?,
            54 => self.fchownat(request, memory)?,
            55 => self.fchown(request),
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
            68 => self.pwrite64(request, memory)?,
            69 => self.preadv(request, memory)?,
            70 => self.pwritev(request, memory)?,
            71 => self.sendfile(request, memory)?,
            72 => self.pselect6(request, memory)?,
            73 => self.ppoll(request, memory)?,
            74 => self.bootstrap_enosys(),
            75 => self.bootstrap_enosys(),
            76 => self.splice(request, memory)?,
            77 => self.bootstrap_enosys(),
            78 => self.readlinkat(request, memory)?,
            79 => self.newfstatat(request, memory)?,
            80 => self.fstat(request, memory),
            81 => self.sync(),
            82 => self.fsync(request),
            83 => self.fdatasync(request),
            85 => self.timerfd_create(request),
            86 => self.timerfd_settime(request, memory),
            87 => self.timerfd_gettime(request, memory),
            88 => self.utimensat(request, memory)?,
            90 => self.capget(request, memory),
            91 => self.capset(request, memory),
            92 => self.personality(request),
            93 => self.exit(request),
            94 => self.exit(request),
            95 => self.waitid(request),
            96 => self.set_tid_address(),
            98 => self.futex(request, memory),
            99 => self.set_robust_list(request),
            101 => self.nanosleep(request, memory),
            102 => self.getitimer(request, memory),
            103 => self.setitimer(request, memory, reporter),
            112 => self.clock_settime(request, memory),
            113 => self.clock_gettime(request, memory),
            114 => self.clock_getres(request, memory),
            115 => self.clock_nanosleep(request, memory),
            117 => self.ptrace(),
            123 => self.sched_getaffinity(request, memory),
            124 => self.sched_yield(),
            129 => self.kill(request),
            130 => self.tkill(request),
            131 => self.tgkill(request),
            132 => self.sigaltstack(request, memory),
            133 => self.rt_sigsuspend(request, memory),
            134 => self.rt_sigaction(request, memory),
            135 => self.rt_sigprocmask(request, memory)?,
            137 => self.rt_sigtimedwait(request, memory),
            138 => self.rt_sigqueueinfo(request),
            139 => self.rt_sigreturn(),
            140 => self.setpriority(request),
            141 => self.getpriority(request),
            142 => self.reboot(),
            153 => self.times(request, memory),
            154 => self.setpgid(request),
            155 => self.getpgid(request),
            156 => self.getsid(request),
            157 => self.setsid(),
            160 => self.uname(request, memory),
            161 => self.sethostname(),
            162 => self.setdomainname(),
            165 => self.getrusage(request, memory),
            166 => self.umask(request),
            167 => self.prctl(request, memory),
            168 => self.getcpu(request, memory),
            169 => self.gettimeofday(request, memory),
            170 => self.settimeofday(),
            171 => self.adjtimex(request, memory),
            172 => self.getpid(),
            173 => DispatchOutcome::Returned { value: 1 },
            174..=177 => DispatchOutcome::Returned { value: 0 },
            178 => self.getpid(),
            179 => self.sysinfo(request, memory),
            214 => self.brk(request),
            215 => self.munmap(request),
            216 => self.mremap(request),
            220 => self.clone(request),
            221 => self.execve(request, memory),
            222 => self.mmap(request, memory)?,
            226 => self.mprotect(request, memory),
            227 => self.msync(request, memory),
            228 => self.mlock(request, memory),
            229 => self.munlock(request, memory),
            230 => self.mlockall(request),
            231 => self.munlockall(),
            232 => self.mincore(request, memory),
            233 => self.madvise(request, memory),
            260 => self.wait4(request, memory),
            261 => self.prlimit64(request, memory),
            266 => self.clock_adjtime(request, memory),
            278 => self.getrandom(request, memory)?,
            283 => self.membarrier(request),
            291 => self.statx(request, memory)?,
            293 => self.rseq(),
            437 => self.openat2(request, memory, reporter)?,
            439 => self.faccessat2(request, memory)?,
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
        let flags = request.arg(3);
        if flags != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        self.access_at(request.arg(0), request.arg(1), request.arg(2), 0, memory)
    }

    fn faccessat2(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.access_at(
            request.arg(0),
            request.arg(1),
            request.arg(2),
            request.arg(3),
            memory,
        )
    }

    fn access_at(
        &self,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        if mode & !(LINUX_R_OK | LINUX_W_OK | LINUX_X_OK) != 0
            || !linux_access_flags_are_supported(flags)
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            if dirfd == LINUX_AT_FDCWD {
                return Ok(self.access_resolved_path(&self.cwd, mode, flags));
            }
            return Ok(self.fd_access(dirfd as i32, mode));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        Ok(self.access_resolved_path(&path, mode, flags))
    }

    fn access_resolved_path(&self, path: &str, mode: u64, flags: u64) -> DispatchOutcome {
        if let Some(outcome) = self.synthetic_access(&path, mode) {
            return outcome;
        }
        let Some(rootfs) = &self.rootfs else {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            };
        };
        let metadata = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            rootfs.symlink_metadata(path)
        } else {
            rootfs.metadata(path)
        };
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(errno) => {
                return DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                };
            }
        };
        access_metadata(&metadata, mode)
    }

    fn fd_access(&self, fd: i32, mode: u64) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => access_metadata(metadata, mode),
            OpenDescription::SyntheticFile { path, .. } => self
                .synthetic_access(path, mode)
                .unwrap_or(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                }),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => synthetic_readonly_access(mode),
        }
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            },
        }
    }

    fn synthetic_access(&self, path: &str, mode: u64) -> Option<DispatchOutcome> {
        if !is_synthetic_virtual_file(path, &self.executable_path) {
            return None;
        }
        Some(synthetic_readonly_access(mode))
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
            // /sys paths that are synthesized must not be recorded as unimplemented;
            // they are handled by the synthetic open path before reaching ENOENT.
            if synthetic_sys_file(path).is_some() {
                return None;
            }
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
            OpenDescription::HostPipe { .. } => {
                // Polling host pipes correctly requires poll(2) on the
                // host fd. For now report nothing ready and let the
                // guest block in a real read/write.
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

        // Allocate a real host pipe so the two ends share state via the
        // kernel and survive `libc::fork(2)` natively. macOS's `pipe(2)`
        // returns two fds: [0] read end, [1] write end.
        let mut host_fds = [0i32; 2];
        let r = unsafe { libc::pipe(host_fds.as_mut_ptr()) };
        if r != 0 {
            return DispatchOutcome::Errno { errno: host_errno() };
        }

        let host_read = host_fds[0];
        let host_write = host_fds[1];

        let Some(read_fd) = self.allocate_fd(3) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if memory.write_bytes(address, pair.as_bytes()).is_err() {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }

        let status_flags = flags & LINUX_O_NONBLOCK;
        let fd_flags = linux_fd_flags_from_open_flags(flags);
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: host_read,
                    is_read_end: true,
                    status_flags,
                })),
                fd_flags,
            },
        );
        self.insert_open_file(
            write_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: host_write,
                    is_read_end: false,
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
        // Linux dup3 requires old_fd != new_fd and only honours
        // O_CLOEXEC in `flags`. It explicitly allows new_fd to be 0/1/2
        // — that's how shells redirect stdin/stdout/stderr.
        if old_fd == new_fd || flags & !LINUX_O_CLOEXEC != 0 || new_fd < 0 {
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
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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
            LINUX_TIOCGWINSZ if fd_is_tty(&self.open_files, fd) => {
                let winsize = LinuxWinsize::terminal_80x24();
                write_packed(memory, arg, winsize.as_bytes())
            }
            LINUX_TIOCGWINSZ => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCGETS if fd_is_tty(&self.open_files, fd) => {
                let termios = LinuxTermios::default_cooked();
                write_packed(memory, arg, termios.as_bytes())
            }
            LINUX_TCGETS => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF if fd_is_tty(&self.open_files, fd) => {
                validate_termios_buffer(memory, arg)
            }
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TIOCSCTTY => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCGPGRP => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    write_packed(memory, arg, &LINUX_BOOTSTRAP_PGID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCSPGRP => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    let mut buf = [0u8; 4];
                    match memory.read_bytes(arg, 4) {
                        Ok(bytes) => buf.copy_from_slice(&bytes),
                        Err(_) => {
                            return DispatchOutcome::Errno {
                                errno: LINUX_EFAULT,
                            };
                        }
                    }
                    let pgid = i32::from_le_bytes(buf);
                    if pgid == LINUX_BOOTSTRAP_PGID {
                        DispatchOutcome::Returned { value: 0 }
                    } else {
                        DispatchOutcome::Errno { errno: LINUX_EPERM }
                    }
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_FIONREAD => {
                // Stdio, eventfd, timerfd, epoll, pipe writer, directory, regular file,
                // synthetic file: writing 0 ("nothing pending") is benign. Pipe reader
                // gets the actual buffered byte count.
                let available: i32 = match self.open_files.get(&fd) {
                    Some(open_file) => match &*open_file.description.borrow() {
                        OpenDescription::PipeReader { pipe, .. } => {
                            let len = pipe.borrow().buffer.len();
                            i32::try_from(len).unwrap_or(i32::MAX)
                        }
                        _ => 0,
                    },
                    // stdio fd (already validated above) or any other valid fd: 0.
                    None => 0,
                };
                write_packed(memory, arg, &available.to_le_bytes())
            }
            LINUX_FIONBIO => {
                if memory.read_bytes(arg, 4).is_err() {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                }
                // Bootstrap: accept and ignore — we don't persist nonblocking
                // state for most fd kinds. Real fcntl(F_SETFL) is the durable path.
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_TIOCNOTTY => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => DispatchOutcome::Returned { value: 0 },
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCGSID => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    write_packed(memory, arg, &LINUX_BOOTSTRAP_SID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            _ => {
                reporter.record(CompatEvent::unhandled_ioctl(fd, ioctl_request, arg));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                }
            }
        }
    }

    fn tty_ioctl_fd_kind(&self, fd: i32) -> Result<TtyFdKind, i32> {
        if is_stdio_fd(fd) {
            Ok(TtyFdKind::Stdio)
        } else if self.open_files.contains_key(&fd) {
            Ok(TtyFdKind::Other)
        } else {
            Err(LINUX_EBADF)
        }
    }

    fn fd_is_valid(&self, fd: i32) -> bool {
        is_stdio_fd(fd) || self.open_files.contains_key(&fd)
    }

    fn flock(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let operation = request.arg(1);
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }

        let lock_operation = operation & !LINUX_LOCK_NB;
        match lock_operation {
            LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN => DispatchOutcome::Returned { value: 0 },
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        }
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

    fn truncate(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = request.arg(0);
        let length = i64::from_ne_bytes(request.arg(1).to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let kind = if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            RootFsEntryKind::File
        } else {
            let Some(rootfs) = &self.rootfs else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            };
            match rootfs.metadata(&resolved) {
                Ok(metadata) => metadata.kind,
                Err(errno) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(errno),
                    });
                }
            }
        };
        let errno = match kind {
            RootFsEntryKind::Directory => LINUX_EISDIR,
            RootFsEntryKind::File | RootFsEntryKind::Symlink => LINUX_EROFS,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn fallocate(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let mode = request.arg(1);
        let offset = i64::from_ne_bytes(request.arg(2).to_ne_bytes());
        let length = i64::from_ne_bytes(request.arg(3).to_ne_bytes());
        if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if length <= 0 || offset < 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if is_stdio_fd(fd) {
            return DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            };
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EROFS,
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        DispatchOutcome::Errno { errno }
    }

    fn ftruncate(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let length = i64::from_ne_bytes(request.arg(1).to_ne_bytes());
        if length < 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if is_stdio_fd(fd) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::Epoll { .. } => LINUX_EINVAL,
        };
        DispatchOutcome::Errno { errno }
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

    fn prctl(&mut self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let option = request.arg(0);
        match option {
            LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                value: self.dumpable,
            },
            LINUX_PR_SET_DUMPABLE => {
                let value = request.arg(1);
                if value > 1 {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    };
                }
                self.dumpable = value as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_NAME => {
                let address = request.arg(1);
                let Ok(bytes) = memory.read_bytes(address, LINUX_TASK_COMM_LEN) else {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                };
                self.task_name = linux_task_name_from_bytes(&bytes);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_NAME => {
                let address = request.arg(1);
                if memory.write_bytes(address, &self.task_name).is_err() {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        }
    }

    fn getcpu(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let cpu_address = request.arg(0);
        let node_address = request.arg(1);
        let bootstrap_value = 0u32.to_ne_bytes();

        if cpu_address != 0 && memory.write_bytes(cpu_address, &bootstrap_value).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        if node_address != 0 && memory.write_bytes(node_address, &bootstrap_value).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
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

    fn sched_yield(&self) -> DispatchOutcome {
        std::thread::yield_now();
        DispatchOutcome::Returned { value: 0 }
    }

    fn sched_getaffinity(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let pid = request.arg(0);
        let size = request.arg(1);
        let address = request.arg(2);
        let current_pid = std::process::id() as u64;

        if pid != 0 && pid != current_pid {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        if size < LINUX_BOOTSTRAP_AFFINITY_BYTES as u64 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let mut mask = [0_u8; LINUX_BOOTSTRAP_AFFINITY_BYTES];
        mask[0] = 1;
        if memory.write_bytes(address, &mask).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned {
            value: LINUX_BOOTSTRAP_AFFINITY_BYTES as i64,
        }
    }

    fn futex(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let operation = request.arg(1);
        let value = request.arg(2) as u32;
        let timeout_address = request.arg(3);
        let command = operation & LINUX_FUTEX_CMD_MASK;
        let flags = operation & !LINUX_FUTEX_CMD_MASK;
        if flags & !(LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if flags & LINUX_FUTEX_CLOCK_REALTIME != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let word = match read_u32(memory, address) {
            Ok(word) => word,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };

        match command {
            LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
            LINUX_FUTEX_WAIT => {
                if word != value {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    };
                }
                if timeout_address == 0 {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    };
                }
                let timespec = match read_timespec(memory, timeout_address) {
                    Ok(timespec) => timespec,
                    Err(errno) => return DispatchOutcome::Errno { errno },
                };
                let timeout = match duration_from_linux_timespec(timespec) {
                    Ok(timeout) => timeout,
                    Err(errno) => return DispatchOutcome::Errno { errno },
                };
                if let Some(timeout) = timeout {
                    std::thread::sleep(timeout);
                }
                DispatchOutcome::Errno {
                    errno: LINUX_ETIMEDOUT,
                }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        }
    }

    fn nanosleep(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let request_address = request.arg(0);
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let duration = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        if let Some(duration) = duration {
            std::thread::sleep(duration);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn clock_nanosleep(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let flags = request.arg(1);
        let request_address = request.arg(2);
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let Some(now) = linux_clock_duration(clock_id) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let requested = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration.unwrap_or(Duration::ZERO),
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let sleep_duration = if flags & LINUX_TIMER_ABSTIME != 0 {
            requested.saturating_sub(now)
        } else {
            requested
        };
        if !sleep_duration.is_zero() {
            std::thread::sleep(sleep_duration);
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

    fn clock_settime(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let address = request.arg(1);
        if !linux_clock_is_known(clock_id) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        // Reading the timespec lets us surface EFAULT for bad pointers and
        // EINVAL for invalid tv_nsec, matching the order real Linux performs
        // these checks before the privilege check kicks in for unsupported
        // clocks.
        let timespec = match read_timespec(memory, address) {
            Ok(timespec) => timespec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let tv_nsec = timespec.tv_nsec;
        if !(0..1_000_000_000).contains(&tv_nsec) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        // Monotonic-family clocks can never be set; report EINVAL like the
        // real kernel.
        if !linux_clock_is_settable(clock_id) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        // For settable clocks (CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_TAI)
        // we still refuse: we are not root and we do not actually mutate the
        // host clock.
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    }

    fn getitimer(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let which = request.arg(0);
        let address = request.arg(1);
        if !linux_itimer_which_is_valid(which) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if address == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        // No timer is ever armed, so the truthful answer is a zeroed
        // itimerval (interval and value both zero == "disarmed").
        write_packed(memory, address, LinuxItimerval::zeroed().as_bytes())
    }

    fn setitimer(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> DispatchOutcome {
        let which = request.arg(0);
        let new_address = request.arg(1);
        let old_address = request.arg(2);
        if !linux_itimer_which_is_valid(which) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if new_address != 0 {
            let new_value = match read_itimerval(memory, new_address) {
                Ok(value) => value,
                Err(errno) => return DispatchOutcome::Errno { errno },
            };
            if !linux_timeval_usec_is_valid(new_value.it_interval)
                || !linux_timeval_usec_is_valid(new_value.it_value)
            {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        }
        if old_address != 0 {
            let outcome = write_packed(memory, old_address, LinuxItimerval::zeroed().as_bytes());
            if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                return outcome;
            }
        }
        reporter.record(CompatEvent::partial_syscall(
            request.number,
            "setitimer",
            request.args,
            "bootstrap: no SIGALRM delivery yet",
        ));
        DispatchOutcome::Returned { value: 0 }
    }

    fn adjtimex(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let address = request.arg(0);
        adjtimex_bootstrap(memory, address)
    }

    fn clock_adjtime(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let clock_id = request.arg(0);
        let address = request.arg(1);
        // Linux only accepts CLOCK_REALTIME for unprivileged callers (and
        // generally only CLOCK_REALTIME at all for adjtime semantics); anything
        // else is EINVAL.
        if clock_id != LINUX_CLOCK_REALTIME {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        adjtimex_bootstrap(memory, address)
    }

    fn kill(&self, request: SyscallRequest) -> DispatchOutcome {
        let pid = request.arg(0) as i64;
        let signum = request.arg(1);
        bootstrap_signal_send(pid, /*tid_required=*/ false, signum)
    }

    fn tkill(&self, request: SyscallRequest) -> DispatchOutcome {
        let tid = request.arg(0) as i64;
        let signum = request.arg(1);
        // tkill's target is a thread id, not a "0 means self" pid form.
        bootstrap_signal_send(tid, /*tid_required=*/ true, signum)
    }

    fn tgkill(&self, request: SyscallRequest) -> DispatchOutcome {
        let tgid = request.arg(0) as i64;
        let tid = request.arg(1) as i64;
        let signum = request.arg(2);
        if !is_valid_signum(signum) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if tgid != LINUX_BOOTSTRAP_PID as i64 || tid != LINUX_BOOTSTRAP_PID as i64 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        if signum == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    fn sigaltstack(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let ss = request.arg(0);
        let old_ss = request.arg(1);

        if old_ss != 0
            && memory
                .write_bytes(old_ss, LinuxSigaltstack::disabled().as_bytes())
                .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }

        if ss != 0 {
            let bytes = match memory.read_bytes(ss, core::mem::size_of::<LinuxSigaltstack>()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                }
            };
            let new_stack = match LinuxSigaltstack::read_from_bytes(&bytes) {
                Ok(stack) => stack,
                Err(_) => {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                }
            };
            let flags = new_stack.ss_flags as u32 as u64;
            // SS_ONSTACK is a query-only flag; reject it along with anything
            // unrecognized. Only SS_DISABLE is accepted from userspace.
            if flags & !LINUX_SS_DISABLE != 0 {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
            if flags == 0 {
                let size = new_stack.ss_size;
                if size < LINUX_MINSIGSTKSZ {
                    return DispatchOutcome::Errno {
                        errno: LINUX_ENOMEM,
                    };
                }
            }
            // SS_DISABLE or a request with a sufficiently large stack is
            // silently dropped: we have no alternate signal stack machinery
            // yet, so there's nothing to install.
        }

        DispatchOutcome::Returned { value: 0 }
    }

    fn rt_sigsuspend(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let mask_ptr = request.arg(0);
        let sigset_size = request.arg(1);
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        // Validate readability of the mask. The bootstrap has no signal
        // delivery, so we don't need to honour the mask — but we do owe the
        // caller an EFAULT if the pointer is bad. rt_sigsuspend is documented
        // to always return -1; with no signals to deliver, EINTR is the only
        // honest answer.
        if memory
            .read_bytes(mask_ptr, LINUX_RT_SIGSET_SIZE as usize)
            .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Errno {
            errno: LINUX_EINTR,
        }
    }

    fn rt_sigaction(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        // Treat signum as a 32-bit signed integer first (Linux ABI),
        // then promote to u64 for range checks. Linux returns EINVAL
        // for signum <= 0, > _NSIG, or == SIGKILL/SIGSTOP.
        let signum = request.arg(0) as i32;
        let old_action = request.arg(2);
        let sigset_size = request.arg(3);
        // Be lenient on the sigset_size and on signum=0 too. Busybox sh
        // in interactive mode walks `for sig in 0..NSIG` setting up
        // handlers; returning EINVAL anywhere in that walk poisons
        // x0 and the next iteration calls with signum = previous
        // -errno, producing a tight loop. Accept-and-ignore is the
        // safe stub for now.
        if !(0..=64).contains(&signum) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        // Be lenient on the old_action write: if the pointer is bogus
        // we still report success rather than EFAULT. Returning EFAULT
        // here trips up busybox sh in interactive mode — sh's startup
        // loops over signals and feeds the previous syscall's errno
        // (-14) back into x0 as the next signum, producing a tight
        // unrecoverable retry loop. The handler isn't supposed to
        // populate old_action when there was no previous handler
        // anyway, so skipping the write is benign.
        if old_action != 0 {
            let _ = memory.write_bytes(old_action, LinuxSigaction::empty().as_bytes());
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

    fn rt_sigtimedwait(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let set_ptr = request.arg(0);
        let timeout_ptr = request.arg(2);
        let sigset_size = request.arg(3);
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if memory
            .read_bytes(set_ptr, LINUX_RT_SIGSET_SIZE as usize)
            .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        if timeout_ptr != 0 {
            let timeout = match read_timespec(memory, timeout_ptr) {
                Ok(timeout) => timeout,
                Err(errno) => return DispatchOutcome::Errno { errno },
            };
            let tv_sec = timeout.tv_sec;
            let tv_nsec = timeout.tv_nsec;
            if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
            // A zero timeout is a polling check that must return immediately.
            // We have no signal queue, so the answer is always "timed out".
        }
        // Non-zero timeout: a real implementation would block. With no signal
        // source we'd block forever, so report the timeout. info is only
        // written on success, and we never succeed.
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        }
    }

    fn rt_sigqueueinfo(&self, request: SyscallRequest) -> DispatchOutcome {
        let tgid = request.arg(0) as i64;
        let signum = request.arg(1);
        if !is_valid_signum(signum) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if tgid != LINUX_BOOTSTRAP_PID as i64 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        // No signal delivery; surface the gap explicitly rather than silently
        // swallowing the queued siginfo.
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    fn rt_sigreturn(&self) -> DispatchOutcome {
        // rt_sigreturn is invoked from a signal trampoline to restore the
        // pre-signal context; a real kernel never returns from it. We never
        // deliver a signal, so this is unreachable in practice. Surface
        // ENOSYS if it is somehow invoked directly.
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
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

    fn ptrace(&self) -> DispatchOutcome {
        // Bootstrap: no debugger surface yet. Linux returns ENOSYS when ptrace
        // is built out of the kernel; we surface the same answer so glibc /
        // gdb fall back cleanly.
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    fn reboot(&self) -> DispatchOutcome {
        // We're not root and we wouldn't honour the request anyway.
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    }

    fn sethostname(&self) -> DispatchOutcome {
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    }

    fn setdomainname(&self) -> DispatchOutcome {
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    }

    fn settimeofday(&self) -> DispatchOutcome {
        DispatchOutcome::Errno { errno: LINUX_EPERM }
    }

    fn umask(&mut self, request: SyscallRequest) -> DispatchOutcome {
        let new = request.arg(0) as u32 & 0o777;
        let previous = self.umask;
        self.umask = new;
        DispatchOutcome::Returned {
            value: previous as i64,
        }
    }

    fn setpriority(&self, request: SyscallRequest) -> DispatchOutcome {
        let which = request.arg(0);
        let who = request.arg(1) as i32;
        let prio = request.arg(2) as i32;
        if which > LINUX_PRIO_USER || prio < -20 || prio > 19 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn getpriority(&self, request: SyscallRequest) -> DispatchOutcome {
        let which = request.arg(0);
        let who = request.arg(1) as i32;
        if which > LINUX_PRIO_USER {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        // Linux returns 20 - nice. Default nice is 0 → return 20. This is a
        // bootstrap value; we don't model per-process priority.
        DispatchOutcome::Returned { value: 20 }
    }

    fn sysinfo(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let info = LinuxSysinfo {
            uptime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            loads: [0; 3],
            totalram: 16 * 1024 * 1024 * 1024,
            freeram: 16 * 1024 * 1024 * 1024,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 1,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
            _padding: [0; 8],
        };
        if memory.write_bytes(request.arg(0), info.as_bytes()).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn times(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let buf = request.arg(0);
        let secs = realtime_duration().as_secs();
        let clock = i64::try_from(secs)
            .ok()
            .and_then(|s| s.checked_mul(LINUX_CLK_TCK))
            .unwrap_or(i64::MAX);
        if buf != 0
            && memory
                .write_bytes(buf, LinuxTms::zeroed().as_bytes())
                .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: clock }
    }

    fn getrusage(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let who = request.arg(0) as i32;
        let usage = request.arg(1);
        match who {
            LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD => {}
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        }
        if usage == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        if memory
            .write_bytes(usage, LinuxRusage::zeroed().as_bytes())
            .is_err()
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn setpgid(&self, request: SyscallRequest) -> DispatchOutcome {
        let pid = request.arg(0) as i32;
        let pgid = i32::from_ne_bytes((request.arg(1) as u32).to_ne_bytes());
        if pgid < 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if pid != 0 && pid != 1 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn getpgid(&self, request: SyscallRequest) -> DispatchOutcome {
        let pid = request.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        DispatchOutcome::Returned { value: 1 }
    }

    fn getsid(&self, request: SyscallRequest) -> DispatchOutcome {
        let pid = request.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return DispatchOutcome::Errno { errno: LINUX_ESRCH };
        }
        DispatchOutcome::Returned { value: 1 }
    }

    fn setsid(&self) -> DispatchOutcome {
        DispatchOutcome::Returned { value: 1 }
    }

    fn waitid(&self, request: SyscallRequest) -> DispatchOutcome {
        let idtype = request.arg(0);
        let options = request.arg(3);
        match idtype {
            LINUX_P_ALL | LINUX_P_PID | LINUX_P_PGID | LINUX_P_PIDFD => {}
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        }
        if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if options & LINUX_WAITID_STATE_MASK == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        }
    }

    fn wait4(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let pid = request.arg(0) as i32;
        let wstatus_addr = request.arg(1);
        let options = request.arg(2);
        if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
            return DispatchOutcome::Errno { errno: LINUX_EINVAL };
        }
        // Linux WNOHANG = 1; macOS WNOHANG = 1. Same bit, pass through.
        let mut host_status: i32 = 0;
        let result = unsafe { libc::waitpid(pid, &mut host_status, options as i32) };
        if result < 0 {
            // ECHILD on macOS == ECHILD on Linux (10).
            return DispatchOutcome::Errno { errno: host_errno() };
        }
        if result == 0 {
            // WNOHANG and no child ready.
            return DispatchOutcome::Returned { value: 0 };
        }
        // Linux and Darwin agree on the wstatus encoding for exited /
        // signaled children: low 7 bits = signal, bit 7 = core flag,
        // bits 8..15 = exit code. Pass through as-is.
        if wstatus_addr != 0 {
            let bytes = host_status.to_ne_bytes();
            if memory.write_bytes(wstatus_addr, &bytes).is_err() {
                return DispatchOutcome::Errno { errno: LINUX_EFAULT };
            }
        }
        DispatchOutcome::Returned { value: i64::from(result) }
    }

    fn openat(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.open_at_path(
            request.arg(0),
            request.arg(1),
            request.arg(2),
            memory,
            reporter,
        )
    }

    fn openat2(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let how_address = request.arg(2);
        let size = request.arg(3);
        if size != LINUX_OPEN_HOW_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let how = match read_open_how(memory, how_address) {
            Ok(how) => how,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if how.mode != 0
            || how.resolve != 0
            || how.flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        self.open_at_path(request.arg(0), request.arg(1), how.flags, memory, reporter)
    }

    fn open_at_path(
        &mut self,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
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
        } else if let Some(contents) = synthetic_sys_file(&path) {
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {}
        }
        DispatchOutcome::Returned { value: next }
    }

    /// Linux `execve(2)` (aarch64 syscall 221). Reads pathname, argv,
    /// and envp from guest memory, then surfaces `DispatchOutcome::Execve`
    /// so the runtime can tear down the guest address space and load
    /// the new image. Returns the usual errno on the failure paths
    /// (EFAULT on bad pointers, ENAMETOOLONG on oversized strings).
    fn execve(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let pathname_addr = request.arg(0);
        let argv_addr = request.arg(1);
        let envp_addr = request.arg(2);

        let path = match read_guest_c_string(memory, pathname_addr) {
            Ok(p) => p,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let argv = match read_guest_string_array(memory, argv_addr) {
            Ok(v) => v,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        let env = match read_guest_string_array(memory, envp_addr) {
            Ok(v) => v,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };

        DispatchOutcome::Execve { path, argv, env }
    }

    /// Linux `clone(2)` (aarch64 syscall 220). Real fork delegation:
    /// the dispatcher recognises clone, returns `DispatchOutcome::Fork`,
    /// and the runtime asks the trap engine to do a real macOS fork
    /// against the live HVF state.
    ///
    /// Currently only the simple SIGCHLD case (musl/glibc `fork()` wrapper
    /// → `clone(SIGCHLD, 0, ...)`) is wired. Thread-create flags
    /// (CLONE_VM | CLONE_THREAD) and namespace/process-share variants
    /// fall through to ENOSYS until the next iteration.
    fn clone(&mut self, request: SyscallRequest) -> DispatchOutcome {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;

        let flags = request.arg(0);
        // Thread creation needs pthread_create semantics, not fork.
        // Surface as ENOSYS for now so callers see "function not
        // implemented" rather than spuriously cloning the whole address
        // space when they wanted a thread.
        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            };
        }

        // Anything else (including the SIGCHLD-only fork case) → real fork.
        DispatchOutcome::Fork
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
                | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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

        // Best-effort zero-fill — if the destination isn't in our tracked
        // address space (e.g. MAP_FIXED at the heap base where we only model
        // a small window today), skip the fill and return the address. The
        // underlying stage-2 page is still backed by the host mapping for
        // that region, so the write would land in real memory.
        let _ = memory.write_bytes(address, &bytes);
        Ok(DispatchOutcome::Returned {
            value: address as i64,
        })
    }

    fn next_mmap_address(&mut self, requested: u64, length: u64, flags: u64) -> Option<u64> {
        if flags & LINUX_MAP_FIXED != 0 {
            // Bootstrap policy: accept MAP_FIXED at any page-aligned guest
            // address that fits in the configured IPA window. We do not
            // create new stage-2 mappings for these requests — the caller
            // expects the address back, and writes/reads will either hit a
            // pre-existing mapping or fault. musl's malloc relies on this to
            // place PROT_NONE guard pages at the heap edge.
            if requested == 0 || requested % LINUX_PAGE_SIZE != 0 {
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

    fn msync(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        let flags = request.arg(2);
        if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if length == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        if memory.read_bytes(address, 1).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn mlock(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        if length == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        if memory.read_bytes(address, 1).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn munlock(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        self.mlock(request, memory)
    }

    fn mlockall(&self, request: SyscallRequest) -> DispatchOutcome {
        let flags = request.arg(0);
        if flags == 0
            || flags & !(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT) != 0
        {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn munlockall(&self) -> DispatchOutcome {
        DispatchOutcome::Returned { value: 0 }
    }

    fn mincore(&self, request: SyscallRequest, memory: &mut impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        let vec = request.arg(2);
        if length == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        if memory.read_bytes(address, 1).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            };
        }
        let pages = (length + LINUX_PAGE_SIZE as u64 - 1) / LINUX_PAGE_SIZE as u64;
        let bytes = vec![1u8; pages as usize];
        if memory.write_bytes(vec, &bytes).is_err() {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn mremap(&self, request: SyscallRequest) -> DispatchOutcome {
        let old_address = request.arg(0);
        let old_size = request.arg(1);
        let new_size = request.arg(2);
        let flags = request.arg(3);
        if new_size == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if !range_within(old_address, old_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if new_size <= old_size {
            return DispatchOutcome::Returned {
                value: old_address as i64,
            };
        }
        DispatchOutcome::Errno {
            errno: LINUX_ENOMEM,
        }
    }

    fn mprotect(&self, request: SyscallRequest, _memory: &impl GuestMemory) -> DispatchOutcome {
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
        // Page-alignment check on the address — Linux requires that. Our
        // stage-2 mappings are already r-w-x for the bootstrap, so changing
        // protections is a no-op for the guest. Don't validate the range
        // against the dispatcher's address space: musl's RELRO loop hands us
        // addresses inside the dynamically-allocated mmap arenas that we
        // don't currently model, and gating those calls produces an
        // ENOMEM-retry loop that prevents dynamic startup from finishing.
        if address % LINUX_PAGE_SIZE as u64 != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn madvise(&self, request: SyscallRequest, memory: &impl GuestMemory) -> DispatchOutcome {
        let address = request.arg(0);
        let length = request.arg(1);
        let advice = request.arg(2);

        if address % LINUX_PAGE_SIZE != 0 || !linux_madvise_advice_is_supported(advice) {
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

    fn rseq(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    fn membarrier(&self, request: SyscallRequest) -> DispatchOutcome {
        let command = request.arg(0);
        let flags = request.arg(1);

        if command == LINUX_MEMBARRIER_CMD_QUERY && flags == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        }
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
            OpenDescription::HostPipe {
                host_fd,
                is_read_end,
                ..
            } => {
                if !*is_read_end {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                return Ok(read_host_pipe(memory, address, length, *host_fd));
            }
            OpenDescription::Directory { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EISDIR,
                });
            }
            OpenDescription::Epoll { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
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

    fn preadv(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let iov = request.arg(1);
        let iovcnt = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let offset = usize::try_from(request.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(3)))?;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let read_len = read_from_contents_at(memory, contents, offset, &iovecs)?;
        Ok(DispatchOutcome::Returned {
            value: read_len as i64,
        })
    }

    fn pwrite64(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let address = request.arg(1);
        let length = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let offset = i64::from_ne_bytes(request.arg(3).to_ne_bytes());
        if offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if memory.read_bytes(address, length).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn pwritev(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = request.arg(0) as i32;
        let iov = request.arg(1);
        let iovcnt = usize::try_from(request.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(2)))?;
        let offset = i64::from_ne_bytes(request.arg(3).to_ne_bytes());
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        for iovec in &iovecs {
            let iov_len = usize::try_from(iovec.iov_len)
                .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
            if memory.read_bytes(iovec.iov_base, iov_len).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => Ok(Err(LINUX_EINVAL)),
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
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => return Err(LINUX_EINVAL),
        };
        let available = contents.get(offset..).unwrap_or_default();
        let write_len = available.len().min(count);
        Ok(available[..write_len].to_vec())
    }

    fn splice(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_fd = request.arg(0) as i32;
        let off_in_address = request.arg(1);
        let out_fd = request.arg(2) as i32;
        let off_out_address = request.arg(3);
        let count = usize::try_from(request.arg(4))
            .map_err(|_| DispatchError::LengthTooLarge(request.arg(4)))?;
        let flags = request.arg(5);
        if flags & !LINUX_SPLICE_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        if let Some((pipe, status_flags)) = self.pipe_reader(in_fd) {
            if off_in_address != 0 || off_out_address != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if let Some(errno) = self.splice_output_errno(out_fd) {
                return Ok(DispatchOutcome::Errno { errno });
            }
            let bytes = match take_pipe_bytes(&pipe, count, status_flags) {
                Ok(bytes) => bytes,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let outcome = self.write_output_fd(out_fd, &bytes);
            return Ok(outcome);
        }

        if off_out_address != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        match self.fd_is_pipe_writer(out_fd) {
            Ok(true) => {}
            Ok(false) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        }

        let mut offset = match self.sendfile_offset(in_fd, off_in_address, memory)? {
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
        if off_in_address == 0 {
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
            .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        Ok(DispatchOutcome::Returned { value })
    }

    fn pipe_reader(&self, fd: i32) -> Option<(Rc<RefCell<PipeState>>, u64)> {
        let open_file = self.open_files.get(&fd)?;
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::PipeReader { pipe, status_flags } => {
                Some((Rc::clone(pipe), *status_flags))
            }
            _ => None,
        }
    }

    fn fd_is_pipe_writer(&self, fd: i32) -> Result<bool, i32> {
        let Some(open_file) = self.open_files.get(&fd) else {
            return if is_stdio_fd(fd) {
                Ok(false)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let open = open_file.description.borrow();
        Ok(matches!(&*open, OpenDescription::PipeWriter { .. }))
    }

    fn splice_output_errno(&self, fd: i32) -> Option<i32> {
        if is_stdio_fd(fd) {
            return None;
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return Some(LINUX_EBADF);
        };
        let open = open_file.description.borrow();
        let OpenDescription::PipeWriter { pipe, .. } = &*open else {
            return Some(LINUX_EINVAL);
        };
        if pipe.borrow().readers == 0 {
            Some(LINUX_EPIPE)
        } else {
            None
        }
    }

    fn sync(&self) -> DispatchOutcome {
        DispatchOutcome::Returned { value: 0 }
    }

    fn xattr_unsupported(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOTSUP,
        }
    }

    fn bootstrap_enosys(&self) -> DispatchOutcome {
        DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        }
    }

    fn fsync(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        DispatchOutcome::Returned { value: 0 }
    }

    fn fdatasync(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        DispatchOutcome::Returned { value: 0 }
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

        // Check open_files FIRST: dup3 may have redirected fd 1/2 to
        // a pipe, an eventfd, or some other resource. Only after we've
        // confirmed there's no open description do we fall back to the
        // dispatcher's built-in stdout/stderr buffers.
        if let Some(open_file) = self.open_files.get(&(fd as i32)) {
            let mut open = open_file.description.borrow_mut();
            match &mut *open {
                OpenDescription::EventFd { counter, .. } => {
                    return Ok(write_eventfd(&bytes, counter));
                }
                OpenDescription::PipeWriter { pipe, .. } => {
                    return Ok(write_pipe(&bytes, pipe));
                }
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    ..
                } => {
                    if *is_read_end {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    }
                    return Ok(write_host_pipe(&bytes, *host_fd));
                }
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
            }
        }
        match fd {
            1 => self.stdout.extend_from_slice(&bytes),
            2 => self.stderr.extend_from_slice(&bytes),
            _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
        }

        Ok(DispatchOutcome::Returned {
            value: length as i64,
        })
    }

    fn write_output_fd(&mut self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.open_files.get(&fd) {
            let mut open = open_file.description.borrow_mut();
            return match &mut *open {
                OpenDescription::PipeWriter { pipe, .. } => write_pipe(bytes, pipe),
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    ..
                } => {
                    if *is_read_end {
                        DispatchOutcome::Errno { errno: LINUX_EBADF }
                    } else {
                        write_host_pipe(bytes, *host_fd)
                    }
                }
                _ => DispatchOutcome::Errno { errno: LINUX_EBADF },
            };
        }
        match fd {
            1 => self.stdout.extend_from_slice(bytes),
            2 => self.stderr.extend_from_slice(bytes),
            _ => return DispatchOutcome::Errno { errno: LINUX_EBADF },
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
            // Mirror `write`: check open_files FIRST so post-dup3
            // redirects (eg `dup3(pipe_write, 1)`) actually plumb
            // through the redirected description rather than the
            // built-in stdout buffer.
            if let Some(open_file) = self.open_files.get(&(fd as i32)) {
                let mut open = open_file.description.borrow_mut();
                let outcome = match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => write_pipe(&bytes, pipe),
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        if *is_read_end {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        write_host_pipe(&bytes, *host_fd)
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                };
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                total = total
                    .checked_add(value as usize)
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                continue;
            }
            match fd {
                1 => self.stdout.extend_from_slice(&bytes),
                2 => self.stderr.extend_from_slice(&bytes),
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
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

    fn mknodat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        if let Some(rootfs) = &self.rootfs {
            match rootfs.symlink_metadata(&resolved) {
                Ok(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                Err(RootFsError::NotFound(_)) => {}
                Err(other) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(other),
                    });
                }
            }
        }
        Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
    }

    fn mkdirat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        if let Some(rootfs) = &self.rootfs {
            match rootfs.metadata(&resolved) {
                Ok(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                Err(RootFsError::NotFound(_)) => {}
                Err(other) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(other),
                    });
                }
            }
        }
        Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
    }

    fn fchmod(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        DispatchOutcome::Errno { errno: LINUX_EROFS }
    }

    fn fchown(&self, request: SyscallRequest) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        }
        DispatchOutcome::Errno { errno: LINUX_EROFS }
    }

    fn fchownat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            if dirfd == LINUX_AT_FDCWD {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
            }
            if !self.fd_is_valid(dirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        match rootfs.symlink_metadata(&resolved) {
            Ok(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
            Err(errno) => Ok(DispatchOutcome::Errno {
                errno: rootfs_errno(errno),
            }),
        }
    }

    fn fchmodat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(3);
        if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        match rootfs.symlink_metadata(&resolved) {
            Ok(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
            Err(errno) => Ok(DispatchOutcome::Errno {
                errno: rootfs_errno(errno),
            }),
        }
    }

    fn linkat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let olddirfd = request.arg(0);
        let oldpath = request.arg(1);
        let newdirfd = request.arg(2);
        let newpath = request.arg(3);
        let flags = request.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let old = match read_guest_c_string(memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let new_path = match read_guest_c_string(memory, newpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if new_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        if old.is_empty() && flags & LINUX_AT_EMPTY_PATH == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let source_exists = if old.is_empty() {
            self.fd_is_valid(olddirfd as i32)
        } else {
            let resolved = match self.resolve_at_path(olddirfd, &old) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            if is_synthetic_virtual_file(&resolved, &self.executable_path) {
                true
            } else if let Some(rootfs) = &self.rootfs {
                match rootfs.symlink_metadata(&resolved) {
                    Ok(_) => true,
                    Err(RootFsError::NotFound(_)) => false,
                    Err(other) => {
                        return Ok(DispatchOutcome::Errno {
                            errno: rootfs_errno(other),
                        });
                    }
                }
            } else {
                false
            }
        };
        if !source_exists {
            return Ok(DispatchOutcome::Errno {
                errno: if old.is_empty() {
                    LINUX_EBADF
                } else {
                    LINUX_ENOENT
                },
            });
        }
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_new, &self.executable_path) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        if let Some(rootfs) = &self.rootfs {
            match rootfs.symlink_metadata(&resolved_new) {
                Ok(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                Err(RootFsError::NotFound(_)) => {}
                Err(other) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(other),
                    });
                }
            }
        }
        Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
    }

    fn symlinkat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let target = request.arg(0);
        let newdirfd = request.arg(1);
        let linkpath = request.arg(2);
        let target_path = match read_guest_c_string(memory, target) {
            Ok(target) => target,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if target_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let link = match read_guest_c_string(memory, linkpath) {
            Ok(link) => link,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if link.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved_link = match self.resolve_at_path(newdirfd, &link) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_link, &self.executable_path) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        if let Some(rootfs) = &self.rootfs {
            match rootfs.symlink_metadata(&resolved_link) {
                Ok(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EEXIST,
                    });
                }
                Err(RootFsError::NotFound(_)) => {}
                Err(other) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(other),
                    });
                }
            }
        }
        Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
    }

    fn renameat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let olddirfd = request.arg(0);
        let oldpath = request.arg(1);
        let newdirfd = request.arg(2);
        let newpath = request.arg(3);
        let old = match read_guest_c_string(memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let new_path = match read_guest_c_string(memory, newpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if old.is_empty() || new_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved_old = match self.resolve_at_path(olddirfd, &old) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let _ = resolved_new;
        let synthetic = is_synthetic_virtual_file(&resolved_old, &self.executable_path);
        if synthetic {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        match rootfs.symlink_metadata(&resolved_old) {
            Ok(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
            Err(errno) => Ok(DispatchOutcome::Errno {
                errno: rootfs_errno(errno),
            }),
        }
    }

    fn unlinkat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(2);
        if flags & !LINUX_AT_REMOVEDIR != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let kind = if is_synthetic_virtual_file(&resolved, &self.executable_path) {
            RootFsEntryKind::File
        } else {
            let Some(rootfs) = &self.rootfs else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            };
            match rootfs.symlink_metadata(&resolved) {
                Ok(metadata) => metadata.kind,
                Err(errno) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: rootfs_errno(errno),
                    });
                }
            }
        };
        let remove_dir = flags & LINUX_AT_REMOVEDIR != 0;
        let errno = match (kind, remove_dir) {
            (RootFsEntryKind::Directory, false) => LINUX_EISDIR,
            (RootFsEntryKind::File | RootFsEntryKind::Symlink, true) => LINUX_ENOTDIR,
            _ => LINUX_EROFS,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn utimensat(
        &self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let times = request.arg(2);
        let flags = request.arg(3);
        if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if times != 0 {
            let atime = match read_timespec(memory, times) {
                Ok(timespec) => timespec,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let mtime_address = times
                .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                .ok_or(DispatchError::LengthTooLarge(times))?;
            let mtime = match read_timespec(memory, mtime_address) {
                Ok(timespec) => timespec,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            if !linux_utimensat_timespec_is_valid(atime)
                || !linux_utimensat_timespec_is_valid(mtime)
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }

        if pathname == 0 {
            if dirfd == LINUX_AT_FDCWD {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
            if !self.fd_is_valid(dirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&path, &self.executable_path) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        match rootfs.metadata(&path) {
            Ok(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
            Err(errno) => Ok(DispatchOutcome::Errno {
                errno: rootfs_errno(errno),
            }),
        }
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
        if let Some(contents) = synthetic_sys_file(&path) {
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

    fn statx(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = request.arg(0);
        let pathname = request.arg(1);
        let flags = request.arg(2);
        let mask = request.arg(3);
        let statxbuf = request.arg(4);

        if !linux_statx_flags_are_supported(flags) || mask & LINUX_STATX_RESERVED != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        if path.is_empty() {
            if flags & LINUX_AT_EMPTY_PATH == 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOENT,
                });
            }
            return Ok(self.write_fd_statx(dirfd as i32, statxbuf, memory));
        }

        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(contents) = synthetic_proc_file(&path, &self.executable_path) {
            return Ok(write_synthetic_statx(
                memory,
                statxbuf,
                &path,
                contents.len(),
            ));
        }
        if let Some(contents) = synthetic_sys_file(&path) {
            return Ok(write_synthetic_statx(
                memory,
                statxbuf,
                &path,
                contents.len(),
            ));
        }
        let Some(rootfs) = &self.rootfs else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        };
        let metadata = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            rootfs.symlink_metadata(path)
        } else {
            rootfs.metadata(path)
        };
        let metadata = match metadata {
            Ok(metadata) => metadata,
            Err(errno) => {
                return Ok(DispatchOutcome::Errno {
                    errno: rootfs_errno(errno),
                });
            }
        };
        Ok(write_statx(memory, statxbuf, &metadata))
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
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                return write_synthetic_stat(memory, statbuf, "pipe:[carrick]", 0);
            }
        };
        write_stat(memory, statbuf, metadata)
    }

    fn write_fd_statx(
        &self,
        fd: i32,
        statxbuf: u64,
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
                return write_synthetic_statx(memory, statxbuf, path, contents.len());
            }
            OpenDescription::EventFd { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[eventfd]", 0);
            }
            OpenDescription::TimerFd { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[timerfd]", 0);
            }
            OpenDescription::Epoll { .. } => {
                return write_synthetic_statx(memory, statxbuf, "anon_inode:[eventpoll]", 0);
            }
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                return write_synthetic_statx(memory, statxbuf, "pipe:[carrick]", 0);
            }
        };
        write_statx(memory, statxbuf, metadata)
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
                | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => Err(LINUX_ENOTDIR),
            },
            None => Err(LINUX_EBADF),
        }
    }
}

fn is_valid_signum(signum: u64) -> bool {
    signum <= LINUX_MAX_SIGNUM
}

fn bootstrap_signal_send(target: i64, tid_required: bool, signum: u64) -> DispatchOutcome {
    if !is_valid_signum(signum) {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let pid = LINUX_BOOTSTRAP_PID as i64;
    let self_target = if tid_required {
        target == pid
    } else {
        // kill(0, sig) targets the calling process's process group; in our
        // single-process bootstrap that's still just us.
        target == pid || target == 0
    };
    if !self_target {
        return DispatchOutcome::Errno { errno: LINUX_ESRCH };
    }
    if signum == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    DispatchOutcome::Errno {
        errno: LINUX_ENOSYS,
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

fn validate_termios_buffer(memory: &impl GuestMemory, address: u64) -> DispatchOutcome {
    match memory.read_bytes(address, core::mem::size_of::<LinuxTermios>()) {
        Ok(_) => DispatchOutcome::Returned { value: 0 },
        Err(_) => DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        },
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

/// Re-evaluate "is this fd a TTY" against the dispatcher's open-file
/// table. fd 0/1/2 are TTYs only when nothing has been dup3'd over
/// them (no `open_files` entry); the moment a pipe / file / eventfd
/// occupies that slot we owe the guest `ENOTTY` so callers like
/// `busybox ls` don't emit ANSI colour escapes into the pipe.
fn fd_is_tty(open_files: &HashMap<i32, OpenFile>, fd: i32) -> bool {
    if !is_stdio_fd(fd) {
        return false;
    }
    !open_files.contains_key(&fd)
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
        OpenDescription::HostPipe { host_fd, .. } => {
            // Close the host fd only when the LAST guest fd that
            // references this OpenDescription is being closed. Because
            // dup3/dup2 wraps a new Linux fd around the SAME Rc<...>,
            // we let the Rc go out of scope naturally and rely on the
            // wrapper around `OpenDescription::HostPipe` having no
            // shared owners. The simplest correct close here is to
            // count: if `strong_count == 1` we're the last one.
            // (The Rc is held by the OpenFile in `open_files`; if no
            // dup'd entry remains, strong_count is 1.)
            if std::rc::Rc::strong_count(&open_file.description) == 1 {
                unsafe {
                    libc::close(*host_fd);
                }
            }
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

fn linux_clock_is_known(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
            | LINUX_CLOCK_TAI
    )
}

fn linux_clock_is_settable(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME | LINUX_CLOCK_REALTIME_ALARM | LINUX_CLOCK_TAI
    )
}

fn linux_itimer_which_is_valid(which: u64) -> bool {
    matches!(
        which,
        LINUX_ITIMER_REAL | LINUX_ITIMER_VIRTUAL | LINUX_ITIMER_PROF
    )
}

fn linux_timeval_usec_is_valid(tv: LinuxTimeval) -> bool {
    let usec = tv.tv_usec;
    (0..1_000_000).contains(&usec)
}

fn adjtimex_bootstrap(memory: &impl GuestMemory, address: u64) -> DispatchOutcome {
    if address == 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    // Probe the leading 8 bytes (modes + frequency word) to detect a bad
    // pointer; we deliberately do not interpret the rest of the timex struct.
    if memory.read_bytes(address, 8).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    // We are unprivileged and we do not actually adjust the host clock.
    // Real Linux short-circuits modes==0 to "return current clock state",
    // but for bootstrap we always return EPERM and let glibc fall back.
    DispatchOutcome::Errno { errno: LINUX_EPERM }
}

fn linux_madvise_advice_is_supported(advice: u64) -> bool {
    matches!(
        advice,
        LINUX_MADV_NORMAL
            | LINUX_MADV_RANDOM
            | LINUX_MADV_SEQUENTIAL
            | LINUX_MADV_WILLNEED
            | LINUX_MADV_DONTNEED
            | LINUX_MADV_FREE
    )
}

fn linux_task_name_from_bytes(bytes: &[u8]) -> [u8; LINUX_TASK_COMM_LEN] {
    let mut name = [0; LINUX_TASK_COMM_LEN];
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
        .min(LINUX_TASK_COMM_LEN - 1);
    name[..length].copy_from_slice(&bytes[..length]);
    name
}

fn linux_statx_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW
        | LINUX_AT_EMPTY_PATH
        | LINUX_AT_NO_AUTOMOUNT
        | LINUX_AT_STATX_FORCE_SYNC
        | LINUX_AT_STATX_DONT_SYNC;
    flags & !SUPPORTED == 0
}

fn linux_access_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH;
    flags & !SUPPORTED == 0
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

fn write_statx(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    let zero_time = LinuxStatxTimestamp::zero();
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: if metadata.kind == RootFsEntryKind::Directory {
            2
        } else {
            1
        },
        stx_uid: 0,
        stx_gid: 0,
        stx_mode: linux_mode(metadata) as u16,
        __spare0: [0; 1],
        stx_ino: inode_for_path(&metadata.path),
        stx_size: metadata.size as u64,
        stx_blocks: blocks_512(metadata.size) as u64,
        stx_attributes_mask: 0,
        stx_atime: zero_time,
        stx_btime: zero_time,
        stx_ctime: zero_time,
        stx_mtime: zero_time,
        stx_rdev_major: 0,
        stx_rdev_minor: 0,
        stx_dev_major: 0,
        stx_dev_minor: 1,
        stx_mnt_id: 1,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        stx_subvol: 0,
        stx_atomic_write_unit_min: 0,
        stx_atomic_write_unit_max: 0,
        stx_atomic_write_segments_max: 0,
        stx_dio_read_offset_align: 0,
        stx_atomic_write_unit_max_opt: 0,
        __spare2: [0; 1],
        __spare3: [0; 8],
    };
    write_packed(memory, statxbuf, statx.as_bytes())
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

fn write_synthetic_statx(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
) -> DispatchOutcome {
    let metadata = RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: RootFsEntryKind::File,
        mode: 0o444,
        size,
    };
    write_statx(memory, statxbuf, &metadata)
}

fn synthetic_proc_file(path: &str, executable_path: &str) -> Option<Vec<u8>> {
    match path {
        "/proc/cmdline" => Some(synthetic_proc_cmdline().to_vec()),
        "/proc/cpuinfo" => Some(synthetic_proc_cpuinfo().to_vec()),
        "/proc/diskstats" => Some(synthetic_proc_diskstats().to_vec()),
        "/proc/filesystems" => Some(synthetic_proc_filesystems().to_vec()),
        "/proc/loadavg" => Some(synthetic_proc_loadavg().to_vec()),
        "/proc/meminfo" => Some(synthetic_proc_meminfo().to_vec()),
        "/proc/mounts" => Some(synthetic_proc_mounts().to_vec()),
        "/proc/partitions" => Some(synthetic_proc_partitions().to_vec()),
        "/proc/stat" => Some(synthetic_proc_stat().to_vec()),
        "/proc/uptime" => Some(synthetic_proc_uptime().into_bytes()),
        "/proc/version" => Some(synthetic_proc_version().to_vec()),
        "/proc/self/auxv" => Some(synthetic_proc_self_auxv().to_vec()),
        "/proc/self/cmdline" => Some(synthetic_proc_self_cmdline(executable_path)),
        "/proc/self/comm" => Some(synthetic_proc_self_comm(executable_path).into_bytes()),
        "/proc/self/limits" => Some(synthetic_proc_self_limits().to_vec()),
        "/proc/self/maps" => Some(synthetic_proc_maps(executable_path).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm().to_vec()),
        "/proc/self/status" => Some(synthetic_proc_self_status(executable_path).into_bytes()),
        "/proc/sys/kernel/osrelease" => Some(synthetic_proc_osrelease().to_vec()),
        "/proc/sys/kernel/hostname" => Some(synthetic_proc_hostname().to_vec()),
        "/proc/sys/kernel/random/boot_id" => {
            Some(synthetic_proc_boot_id().to_vec())
        }
        _ => None,
    }
}

fn synthetic_sys_file(path: &str) -> Option<Vec<u8>> {
    match path {
        "/sys/devices/system/cpu/online" => Some(synthetic_sys_cpu_online().to_vec()),
        "/sys/devices/system/cpu/possible" => Some(synthetic_sys_cpu_possible().to_vec()),
        "/sys/devices/system/cpu/present" => Some(synthetic_sys_cpu_present().to_vec()),
        "/sys/devices/system/cpu/kernel_max" => Some(synthetic_sys_cpu_kernel_max().to_vec()),
        "/sys/devices/system/cpu/cpu0/online" => Some(synthetic_sys_cpu0_online().to_vec()),
        "/sys/devices/system/cpu/cpu0/topology/physical_package_id" => {
            Some(synthetic_sys_cpu0_physical_package_id().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/core_id" => {
            Some(synthetic_sys_cpu0_core_id().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list" => {
            Some(synthetic_sys_cpu0_thread_siblings_list().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/core_siblings_list" => {
            Some(synthetic_sys_cpu0_core_siblings_list().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq" => {
            Some(synthetic_sys_cpufreq_scaling_cur_freq().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq" => {
            Some(synthetic_sys_cpufreq_scaling_max_freq().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq" => {
            Some(synthetic_sys_cpufreq_scaling_min_freq().to_vec())
        }
        "/sys/kernel/mm/transparent_hugepage/enabled" => {
            Some(synthetic_sys_thp_enabled().to_vec())
        }
        "/sys/kernel/mm/transparent_hugepage/defrag" => {
            Some(synthetic_sys_thp_defrag().to_vec())
        }
        "/sys/kernel/random/uuid" => Some(synthetic_sys_random_uuid().to_vec()),
        "/sys/kernel/random/boot_id" => Some(synthetic_sys_random_boot_id().to_vec()),
        "/sys/fs/cgroup/cgroup.controllers" => {
            Some(synthetic_sys_cgroup_controllers().to_vec())
        }
        _ => None,
    }
}

fn is_synthetic_virtual_file(path: &str, executable_path: &str) -> bool {
    synthetic_proc_file(path, executable_path).is_some() || synthetic_sys_file(path).is_some()
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

fn synthetic_proc_version() -> &'static [u8] {
    b"Linux version 6.6.0-carrick (carrick@bootstrap) (rustc) #1 SMP PREEMPT_DYNAMIC\n"
}

fn synthetic_proc_osrelease() -> &'static [u8] {
    b"6.6.0-carrick\n"
}

fn synthetic_proc_hostname() -> &'static [u8] {
    b"carrick\n"
}

fn synthetic_proc_loadavg() -> &'static [u8] {
    b"0.00 0.00 0.00 1/1 1\n"
}

fn synthetic_proc_uptime() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as f64;
    format!("{seconds:.2} {seconds:.2}\n")
}

fn synthetic_proc_meminfo() -> &'static [u8] {
    b"MemTotal:       16777216 kB\n\
MemFree:        16000000 kB\n\
MemAvailable:   16000000 kB\n\
Buffers:               0 kB\n\
Cached:                0 kB\n\
SwapCached:            0 kB\n\
Active:                0 kB\n\
Inactive:              0 kB\n\
SwapTotal:             0 kB\n\
SwapFree:              0 kB\n\
Dirty:                 0 kB\n\
Writeback:             0 kB\n\
AnonPages:             0 kB\n\
Mapped:                0 kB\n\
Shmem:                 0 kB\n\
Slab:                  0 kB\n\
KernelStack:           0 kB\n\
PageTables:            0 kB\n\
NFS_Unstable:          0 kB\n\
Bounce:                0 kB\n\
WritebackTmp:          0 kB\n\
CommitLimit:    16777216 kB\n\
Committed_AS:          0 kB\n\
VmallocTotal:   17179869184 kB\n\
VmallocUsed:           0 kB\n\
VmallocChunk:          0 kB\n"
}

fn synthetic_proc_stat() -> &'static [u8] {
    b"cpu  0 0 0 0 0 0 0 0 0 0\n\
cpu0 0 0 0 0 0 0 0 0 0 0\n\
intr 0\n\
ctxt 0\n\
btime 0\n\
processes 1\n\
procs_running 1\n\
procs_blocked 0\n\
softirq 0\n"
}

fn synthetic_proc_self_status(executable_path: &str) -> String {
    let comm = process_short_name(executable_path);
    format!(
        "Name:\t{comm}\n\
Umask:\t0022\n\
State:\tR (running)\n\
Tgid:\t1\n\
Ngid:\t0\n\
Pid:\t1\n\
PPid:\t0\n\
TracerPid:\t0\n\
Uid:\t0\t0\t0\t0\n\
Gid:\t0\t0\t0\t0\n\
FDSize:\t256\n\
Groups:\t\n\
VmPeak:\t       0 kB\n\
VmSize:\t       0 kB\n\
VmLck:\t       0 kB\n\
VmPin:\t       0 kB\n\
VmHWM:\t       0 kB\n\
VmRSS:\t       0 kB\n\
VmData:\t       0 kB\n\
VmStk:\t       0 kB\n\
VmExe:\t       0 kB\n\
VmLib:\t       0 kB\n\
VmPTE:\t       0 kB\n\
VmSwap:\t       0 kB\n\
Threads:\t1\n\
SigQ:\t0/0\n\
SigPnd:\t0000000000000000\n\
ShdPnd:\t0000000000000000\n\
SigBlk:\t0000000000000000\n\
SigIgn:\t0000000000000000\n\
SigCgt:\t0000000000000000\n\
CapInh:\t0000000000000000\n\
CapPrm:\t0000000000000000\n\
CapEff:\t0000000000000000\n\
CapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\n\
Cpus_allowed:\t1\n\
Cpus_allowed_list:\t0\n\
Mems_allowed:\t1\n\
Mems_allowed_list:\t0\n\
voluntary_ctxt_switches:\t0\n\
nonvoluntary_ctxt_switches:\t0\n"
    )
}

fn synthetic_proc_self_cmdline(executable_path: &str) -> Vec<u8> {
    let mut bytes = executable_path.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn synthetic_proc_self_comm(executable_path: &str) -> String {
    let mut comm = process_short_name(executable_path);
    comm.push('\n');
    comm
}

fn synthetic_proc_self_statm() -> &'static [u8] {
    b"0 0 0 0 0 0 0\n"
}

fn synthetic_proc_boot_id() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_proc_cmdline() -> &'static [u8] {
    b"BOOT_IMAGE=/boot/Image root=/dev/vda1 ro\n"
}

fn synthetic_proc_mounts() -> &'static [u8] {
    b"overlay / overlay ro,relatime 0 0\n"
}

fn synthetic_proc_filesystems() -> &'static [u8] {
    b"nodev\ttmpfs\n\
nodev\tproc\n\
nodev\tsysfs\n\
nodev\toverlay\n"
}

fn synthetic_proc_partitions() -> &'static [u8] {
    b"major minor  #blocks  name\n\n"
}

fn synthetic_proc_diskstats() -> &'static [u8] {
    b""
}

fn synthetic_proc_self_auxv() -> &'static [u8] {
    // A single AT_NULL entry (a_type=0, a_val=0), each 8 bytes on aarch64.
    &[0u8; 16]
}

fn synthetic_sys_cpu_online() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_possible() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_present() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_kernel_max() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_online() -> &'static [u8] {
    b"1\n"
}

fn synthetic_sys_cpu0_physical_package_id() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_core_id() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_thread_siblings_list() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_core_siblings_list() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpufreq_scaling_cur_freq() -> &'static [u8] {
    b"2400000\n"
}

fn synthetic_sys_cpufreq_scaling_max_freq() -> &'static [u8] {
    b"2400000\n"
}

fn synthetic_sys_cpufreq_scaling_min_freq() -> &'static [u8] {
    b"600000\n"
}

fn synthetic_sys_thp_enabled() -> &'static [u8] {
    b"always [madvise] never\n"
}

fn synthetic_sys_thp_defrag() -> &'static [u8] {
    b"always defer defer+madvise [madvise] never\n"
}

fn synthetic_sys_random_uuid() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_sys_random_boot_id() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_sys_cgroup_controllers() -> &'static [u8] {
    b"\n"
}

fn synthetic_proc_self_limits() -> &'static [u8] {
    b"Limit                     Soft Limit           Hard Limit           Units\n\
Max cpu time              unlimited            unlimited            seconds\n\
Max file size             unlimited            unlimited            bytes\n\
Max data size             unlimited            unlimited            bytes\n\
Max stack size            8388608              unlimited            bytes\n\
Max core file size        0                    unlimited            bytes\n\
Max resident set          unlimited            unlimited            bytes\n\
Max processes             unlimited            unlimited            processes\n\
Max open files            1024                 4096                 files\n\
Max locked memory         65536                65536                bytes\n\
Max address space         unlimited            unlimited            bytes\n\
Max file locks            unlimited            unlimited            locks\n\
Max pending signals       unlimited            unlimited            signals\n\
Max msgqueue size         819200               819200               bytes\n\
Max nice priority         0                    0                    \n\
Max realtime priority     0                    0                    \n\
Max realtime timeout      unlimited            unlimited            us\n"
}

fn process_short_name(executable_path: &str) -> String {
    Path::new(executable_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            let truncated: String = name.chars().take(15).collect();
            truncated
        })
        .unwrap_or_else(|| "carrick".to_string())
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

fn take_pipe_bytes(
    pipe: &Rc<RefCell<PipeState>>,
    length: usize,
    _status_flags: u64,
) -> Result<Vec<u8>, i32> {
    let mut pipe = pipe.borrow_mut();
    if pipe.buffer.is_empty() {
        if pipe.writers == 0 {
            return Ok(Vec::new());
        }
        return Err(LINUX_EAGAIN);
    }

    let read_len = pipe.buffer.len().min(length);
    Ok(pipe.buffer.drain(..read_len).collect())
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

fn read_u32(memory: &impl GuestMemory, address: u64) -> Result<u32, i32> {
    let bytes = memory.read_bytes(address, 4).map_err(|_| LINUX_EFAULT)?;
    Ok(u32::from_ne_bytes(
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

fn read_itimerval(memory: &impl GuestMemory, address: u64) -> Result<LinuxItimerval, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxItimerval>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxItimerval::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_timespec(memory: &impl GuestMemory, address: u64) -> Result<LinuxTimespec, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxTimespec>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxTimespec::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
}

fn read_open_how(memory: &impl GuestMemory, address: u64) -> Result<LinuxOpenHow, i32> {
    let bytes = memory
        .read_bytes(address, core::mem::size_of::<LinuxOpenHow>())
        .map_err(|_| LINUX_EFAULT)?;
    LinuxOpenHow::read_from_bytes(&bytes).map_err(|_| LINUX_EFAULT)
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

fn access_metadata(metadata: &RootFsMetadata, mode: u64) -> DispatchOutcome {
    if mode & LINUX_W_OK != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EACCES,
        };
    }
    if mode & LINUX_R_OK != 0
        && metadata.kind == RootFsEntryKind::File
        && metadata.mode & 0o444 == 0
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EACCES,
        };
    }
    if mode & LINUX_X_OK != 0
        && metadata.kind == RootFsEntryKind::File
        && metadata.mode & 0o111 == 0
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EACCES,
        };
    }
    DispatchOutcome::Returned { value: 0 }
}

fn synthetic_readonly_access(mode: u64) -> DispatchOutcome {
    if mode & LINUX_W_OK != 0 {
        DispatchOutcome::Errno {
            errno: LINUX_EACCES,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
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

fn linux_utimensat_timespec_is_valid(timespec: LinuxTimespec) -> bool {
    let nsec = timespec.tv_nsec;
    if nsec == LINUX_UTIME_NOW || nsec == LINUX_UTIME_OMIT {
        return true;
    }
    (0..1_000_000_000).contains(&nsec)
}

/// Read a NULL-terminated array of guest VA pointers, dereferencing
/// each to a C string. Used for `argv` / `envp` in `execve(2)`.
fn read_guest_string_array(
    memory: &impl GuestMemory,
    array_addr: u64,
) -> Result<Vec<String>, i32> {
    // execve(NULL, ...) is allowed by Linux for argv but treated as
    // "no argv". Same for envp. Return empty Vec.
    if array_addr == 0 {
        return Ok(Vec::new());
    }
    const MAX_ENTRIES: usize = 4096;
    let mut out = Vec::new();
    for index in 0..MAX_ENTRIES {
        let slot_addr = array_addr
            .checked_add((index as u64) * 8)
            .ok_or(LINUX_E2BIG)?;
        let bytes = memory
            .read_bytes(slot_addr, 8)
            .map_err(|_| LINUX_EFAULT)?;
        let ptr = u64::from_le_bytes(bytes.try_into().map_err(|_| LINUX_EFAULT)?);
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_guest_c_string(memory, ptr)?);
    }
    Err(LINUX_E2BIG)
}

fn host_errno() -> i32 {
    // SAFETY: `__errno_location` (Linux) and `__error` (macOS) both
    // return a thread-local int pointer.
    unsafe { *libc::__error() }
}

fn read_host_pipe(
    memory: &mut impl GuestMemory,
    guest_addr: u64,
    length: usize,
    host_fd: i32,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let mut buf = vec![0u8; length];
    let n = unsafe { libc::read(host_fd, buf.as_mut_ptr() as *mut _, length) };
    if n < 0 {
        return DispatchOutcome::Errno { errno: host_errno() };
    }
    let n_usize = n as usize;
    if n_usize > 0 {
        if memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() {
            return DispatchOutcome::Errno { errno: LINUX_EFAULT };
        }
    }
    DispatchOutcome::Returned { value: n as i64 }
}

fn write_host_pipe(bytes: &[u8], host_fd: i32) -> DispatchOutcome {
    let n = unsafe { libc::write(host_fd, bytes.as_ptr() as *const _, bytes.len()) };
    if n < 0 {
        return DispatchOutcome::Errno { errno: host_errno() };
    }
    DispatchOutcome::Returned { value: n as i64 }
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
