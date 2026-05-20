use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::linux_abi::{
    KernelAbi, LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_DIR, LINUX_DT_LNK, LINUX_DT_REG, LINUX_PAGE_SIZE,
    LINUX_S_IFDIR, LINUX_S_IFLNK, LINUX_S_IFREG, LINUX_TERMIOS_KERNEL_SIZE, LinuxCapabilityData, LinuxCapabilityHeader,
    LinuxDirent64Header, LinuxEpollEvent, LinuxEventfdValue, LinuxFdPair, LinuxIovec,
    LinuxItimerspec, LinuxItimerval, LinuxOpenHow, LinuxPollFd, LinuxRlimit, LinuxRusage, LinuxSigaction, LinuxSysinfo,
    LinuxSigaltstack, LinuxStat, LinuxStatfs, LinuxStatx, LinuxStatxTimestamp,
    LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimezone, LinuxTms,
    LinuxTermios, LinuxUtsname, LinuxWinsize,
};
use crate::memory::{
    LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_HEAP_BASE, LINUX_HEAP_SIZE,
    LINUX_MMAP_BASE, LINUX_MMAP_SIZE, LINUX_PAGE_TABLES_BASE, LINUX_STACK_SIZE, LINUX_STACK_TOP,
};
use crate::fs_backend::FsBackend;
use crate::overlay::OverlayEntry;
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
pub const LINUX_ENOTSOCK: i32 = 88;
pub const LINUX_ENOPROTOOPT: i32 = 92;
// Linux's `type & SOCK_NONBLOCK` and `& SOCK_CLOEXEC` bits sit in the
// type argument to socket(2)/socketpair(2)/accept4(2). macOS doesn't
// have these; we strip them before calling libc and apply the effect
// (O_NONBLOCK, FD_CLOEXEC) by hand.
pub const LINUX_SOCK_NONBLOCK: i32 = 0o4000;
pub const LINUX_SOCK_CLOEXEC: i32 = 0o2000000;
// Linux `sockaddr_storage` is 128 bytes. We use the same upper bound
// when round-tripping addresses through host syscalls.
pub const LINUX_SOCKADDR_STORAGE_SIZE: usize = 128;
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
pub const LINUX_F_GETLK: u64 = 5;
pub const LINUX_F_SETLK: u64 = 6;
pub const LINUX_F_SETLKW: u64 = 7;
pub const LINUX_F_OFD_GETLK: u64 = 36;
pub const LINUX_F_OFD_SETLK: u64 = 37;
pub const LINUX_F_OFD_SETLKW: u64 = 38;
pub const LINUX_F_DUPFD_CLOEXEC: u64 = 1030;
pub const LINUX_F_GETPIPE_SZ: u64 = 1032;
pub const LINUX_F_ADD_SEALS: u64 = 1033;
pub const LINUX_F_GET_SEALS: u64 = 1034;
pub const LINUX_FD_CLOEXEC: u64 = 1;
pub const LINUX_SEEK_SET: u64 = 0;
pub const LINUX_SEEK_CUR: u64 = 1;
pub const LINUX_SEEK_END: u64 = 2;
pub const LINUX_O_ACCMODE: u64 = 0b11;
pub const LINUX_O_RDONLY: u64 = 0;
pub const LINUX_O_WRONLY: u64 = 1;
#[allow(dead_code)]
pub const LINUX_O_RDWR: u64 = 2;
pub const LINUX_O_NONBLOCK: u64 = 0o4000;
pub const LINUX_O_CLOEXEC: u64 = 0o2000000;
pub const LINUX_O_CREAT: u64 = 0o100;
pub const LINUX_O_EXCL: u64 = 0o200;
pub const LINUX_O_TRUNC: u64 = 0o1000;
pub const LINUX_O_APPEND: u64 = 0o2000;
pub const LINUX_O_DIRECTORY: u64 = 0o200000;
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

/// Uniform context handed to every *normalized* syscall handler, so all
/// handlers share one signature and the dispatch arm is macro-generated.
/// Built transiently per dispatched syscall (a scoped borrow of guest memory
/// + the compat reporter), which lets migrated and legacy handlers coexist
/// while the macro migration proceeds subsystem by subsystem. See
/// [[plan-syscall-macro-split]].
pub struct SyscallCtx<'a, M: GuestMemory> {
    pub request: SyscallRequest,
    pub memory: &'a mut M,
    pub reporter: &'a mut CompatReporter,
}

impl<M: GuestMemory> SyscallCtx<'_, M> {
    #[inline]
    pub fn arg(&self, index: usize) -> u64 {
        self.request.arg(index)
    }
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
    /// Guest invoked `rt_sigreturn(2)` (syscall 139). The runtime must
    /// pop the Carrick sigframe at SP_EL0, restore the saved register
    /// state, and resume — without advancing PC the way a normal SVC
    /// completion would. There is no retval to write into x0; the
    /// restored x0 IS the return value.
    SigReturn,
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match *self {
            DispatchOutcome::Returned { value } => (value, None),
            DispatchOutcome::Errno { errno } => (-(errno as i64), Some(errno)),
            DispatchOutcome::Exit { code } => (code as i64, None),
            DispatchOutcome::Fork => (0, None),
            DispatchOutcome::Execve { .. } => (0, None),
            DispatchOutcome::SigReturn => (0, None),
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

/// One row of `/proc/self/maps`, captured from the guest's
/// `AddressSpace` at boot. Stored on the dispatcher so that a guest
/// `cat /proc/self/maps` (or Go runtime / glibc malloc introspection
/// / gdb) sees the real loaded ELF, runtime regions, mmap arena,
/// stack, and bootstrap pages — not the hard-coded four-line summary
/// we shipped before.
#[derive(Debug, Clone, PartialEq, Eq)]
/// Outcome of [`SyscallDispatcher::try_vfs_open`].
enum VfsOpenAttempt {
    Installed(i32),
    Errno(i32),
    FallThrough,
}

#[derive(Debug, Clone)]
pub struct ProcMapsEntry {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub path: String,
}

pub struct SyscallDispatcher {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// When true, writes to fd 1/2 stream directly to host fds 1/2
    /// instead of buffering into `stdout`/`stderr`. Set by `--raw`/the
    /// interactive runtime so the user sees the guest's prompt and
    /// output in real time, instead of after exit.
    stream_stdio: bool,
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
    /// Tracked (real, effective, saved) uid and gid. Carrick runs the
    /// guest as a single host identity, but tools like apt's _apt
    /// privsep drop to a non-root user via setresuid/setresgid and
    /// then VERIFY the new identity via getuid/geteuid/getresuid (and
    /// likewise for gid). Returning the host's identity unconditionally
    /// breaks the verification with "Could not switch group". We
    /// accept any setres*() the guest requests, record the values, and
    /// echo them back to the corresponding get*() calls.
    cred_ruid: u32,
    cred_euid: u32,
    cred_suid: u32,
    cred_rgid: u32,
    cred_egid: u32,
    cred_sgid: u32,
    /// Installed signal handlers per signum (1..=64). When the guest
    /// calls `rt_sigaction(signum, new, old, 8)` we record `new` here
    /// and return whatever was previously stored via `old`. Real
    /// signal delivery isn't wired yet, but tracking the handler
    /// state is what makes interactive `busybox sh`'s "is this signal
    /// owned?" introspection produce consistent answers.
    signal_handlers: HashMap<i32, LinuxSigaction>,
    /// Snapshot of the guest's `AddressSpace` regions, captured at
    /// boot via [`set_address_space_regions`]. When present,
    /// `/proc/self/maps` is rendered from this list (with the heap
    /// end tracking `brk_current` and the mmap arena end tracking
    /// `mmap_next`) instead of the hard-coded four-line summary.
    address_space_regions: Option<Vec<ProcMapsEntry>>,
    /// Swappable writable layer that sits on top of the read-only
    /// rootfs. Writes (mkdirat / openat O_CREAT / write / unlinkat /
    /// renameat) land here; reads consult this first and fall through
    /// to the rootfs when nothing is found. The backend's tombstones
    /// shadow rootfs-backed paths so unlink-then-stat behaves correctly.
    ///
    /// Two backends exist (see `src/fs_backend.rs`):
    ///   * [`MemoryBackend`]    — in-memory tmpfs, fast and ephemeral.
    ///   * [`HostFsBackend`]    — cap-std-sandboxed APFS scratch dir,
    ///                            durable, reflink-seeded.
    /// Unified VFS mount table. Holds DevVfs at /dev, ProcVfs at
    /// /proc, SysVfs at /sys. The dispatcher consults it first; any
    /// path no mount claims (or that a mount returns ENOSYS for)
    /// falls through to the legacy code path below, which reads the
    /// rootfs + overlay from [`Self::rootfs_vfs`].
    vfs_mounts: crate::vfs::VfsMounts,

    /// The `/` mount: immutable OCI rootfs + writable overlay
    /// ([`FsBackend`]). Held as a typed field rather than mounted in
    /// `vfs_mounts` because the dispatcher's existing fs syscalls
    /// reach into the overlay/rootfs state through ~50 call sites
    /// today. Routing those through `Vfs::method` calls is the
    /// follow-up mechanical migration; for step 4 of the plan we
    /// land the architectural ownership move (the state lives in
    /// `RootFsVfs`, exposed to callers via accessors) and the full
    /// Vfs trait impl (`RootFsVfs::open`, `unlink`, etc.) is
    /// independently tested.
    rootfs_vfs: crate::vfs::RootFsVfs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenDescription {
    File {
        path: String,
        metadata: RootFsMetadata,
        contents: Vec<u8>,
        offset: usize,
        status_flags: u64,
        /// True iff this fd targets the writable overlay. Writes
        /// to a writable=false File are still RO (return EROFS).
        writable: bool,
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
    /// Host BSD socket backed by a real macOS file descriptor.
    /// Survives `libc::fork(2)`; the `family`/`type_` fields capture
    /// the *Linux* AF_* / SOCK_* values the guest asked for so that
    /// subsequent socket syscalls (sockaddr translation, getsockopt
    /// SO_TYPE, etc.) can answer in Linux terms.
    HostSocket {
        host_fd: i32,
        family: i32,
        type_: i32,
        status_flags: u64,
    },
    /// A regular file backed by a REAL macOS file descriptor into the
    /// `--fs host` overlay scratch. Unlike `File` (which caches bytes
    /// in memory and so diverges across `libc::fork`), the kernel fd
    /// is shared by fork, so a forked child's writes are visible to
    /// the parent — which is what makes apt's verify-via-temp-file
    /// patterns work. read/write/lseek/fstat/mmap operate directly on
    /// `host_fd`; the kernel owns the offset.
    HostFile {
        host_fd: i32,
        metadata: RootFsMetadata,
        status_flags: u64,
        writable: bool,
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
            | OpenDescription::HostPipe { status_flags, .. }
            | OpenDescription::HostFile { status_flags, .. }
            | OpenDescription::HostSocket { status_flags, .. } => *status_flags,
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
            | OpenDescription::HostPipe { status_flags, .. }
            | OpenDescription::HostFile { status_flags, .. }
            | OpenDescription::HostSocket { status_flags, .. } => *status_flags = next,
        }
    }
}

impl Default for SyscallDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate `dispatch_normalized`, the single match over syscalls migrated
/// to the normalized `SyscallCtx` handler contract. Each entry maps a
/// syscall number to a handler method `fn(&mut self, &mut SyscallCtx<M>)
/// -> Result<DispatchOutcome, DispatchError>`. `dispatch()` tries this
/// first and falls through to the legacy match for not-yet-migrated
/// syscalls; the borrow of memory/reporter is scoped to the call so the
/// legacy arm can still use them. As subsystems migrate this list grows
/// and the legacy match shrinks. See [[plan-syscall-macro-split]].
macro_rules! normalized_dispatch {
    ( $( $num:pat => $handler:ident ),* $(,)? ) => {
        fn dispatch_normalized(
            &mut self,
            request: SyscallRequest,
            memory: &mut impl GuestMemory,
            reporter: &mut CompatReporter,
        ) -> Option<Result<DispatchOutcome, DispatchError>> {
            match request.number {
                $(
                    $num => {
                        let mut ctx = SyscallCtx { request, memory, reporter };
                        Some(self.$handler(&mut ctx))
                    }
                )*
                _ => None,
            }
        }
    };
}

impl SyscallDispatcher {
    normalized_dispatch! {
        17 => getcwd,
        19 => eventfd2,
        20 => epoll_create1,
        21 => epoll_ctl,
        22 => epoll_pwait,
        23 => dup,
        24 => dup3,
        25 => fcntl,
        29 => ioctl,
        32 => flock,
        33 => mknodat,
        46 => ftruncate,
        47 => fallocate,
        48 => faccessat,
        34 => mkdirat,
        35 => unlinkat,
        36 => symlinkat,
        37 => linkat,
        38 => renameat,
        49 => chdir,
        50 => fchdir,
        52 => fchmod,
        53 => fchmodat,
        54 => fchownat,
        55 => fchown,
        56 => openat,
        57 => close,
        59 => pipe2,
        61 => getdents64,
        62 => lseek,
        63 => read,
        64 => write,
        65 => readv,
        66 => writev,
        67 => pread64,
        68 => pwrite64,
        69 => preadv,
        70 => pwritev,
        71 => sendfile,
        72 => pselect6,
        73 => ppoll,
        76 => splice,
        78 => readlinkat,
        79 => newfstatat,
        80 => fstat,
        81 => sync,
        82 => fsync,
        83 => fdatasync,
        85 => timerfd_create,
        86 => timerfd_settime,
        87 => timerfd_gettime,
        88 => utimensat,
        90 => capget,
        91 => capset,
        92 => personality,
        95 => waitid,
        96 => set_tid_address,
        98 => futex,
        99 => set_robust_list,
        101 => nanosleep,
        102 => getitimer,
        103 => setitimer,
        112 => clock_settime,
        113 => clock_gettime,
        114 => clock_getres,
        115 => clock_nanosleep,
        117 => ptrace,
        123 => sched_getaffinity,
        124 => sched_yield,
        129 => kill,
        130 => tkill,
        131 => tgkill,
        132 => sigaltstack,
        133 => rt_sigsuspend,
        134 => rt_sigaction,
        135 => rt_sigprocmask,
        137 => rt_sigtimedwait,
        138 => rt_sigqueueinfo,
        139 => rt_sigreturn,
        140 => setpriority,
        141 => getpriority,
        142 => reboot,
        143 => setregid,
        144 => setgid,
        145 => setreuid,
        146 => setuid,
        147 => setresuid,
        148 => getresuid,
        149 => setresgid,
        150 => getresgid,
        153 => times,
        154 => setpgid,
        155 => getpgid,
        156 => getsid,
        157 => setsid,
        158 => getgroups,
        160 => uname,
        161 => sethostname,
        162 => setdomainname,
        165 => getrusage,
        166 => umask,
        167 => prctl,
        168 => getcpu,
        169 => gettimeofday,
        170 => settimeofday,
        171 => adjtimex,
        179 => sysinfo,
        198 => socket,
        199 => socketpair,
        200 => bind,
        201 => listen,
        202 => accept,
        203 => connect,
        204 => getsockname,
        205 => getpeername,
        206 => sendto,
        207 => recvfrom,
        208 => setsockopt,
        209 => getsockopt,
        210 => shutdown,
        211 => sendmsg,
        212 => recvmsg,
        214 => brk,
        215 => munmap,
        216 => mremap,
        220 => clone,
        221 => execve,
        222 => mmap,
        223 => fadvise64,
        226 => mprotect,
        227 => msync,
        228 => mlock,
        229 => munlock,
        230 => mlockall,
        231 => munlockall,
        232 => mincore,
        233 => madvise,
        242 => accept4,
        260 => wait4,
        261 => prlimit64,
        266 => clock_adjtime,
        276 => renameat2,
        278 => getrandom,
        285 => copy_file_range,
        291 => statx,
        436 => close_range,
        437 => openat2,
        439 => faccessat2,
    }

    pub fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            stream_stdio: false,
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
            // Default identity is root (uid 0, gid 0) — what `id` shows
            // in a typical container.
            cred_ruid: 0,
            cred_euid: 0,
            cred_suid: 0,
            cred_rgid: 0,
            cred_egid: 0,
            cred_sgid: 0,
            signal_handlers: HashMap::new(),
            address_space_regions: None,
            vfs_mounts: {
                let mut m = crate::vfs::VfsMounts::new();
                m.mount("/dev", Box::new(crate::vfs::DevVfs::new()));
                m.mount("/proc", Box::new(crate::vfs::ProcVfs::new()));
                m.mount("/sys", Box::new(crate::vfs::SysVfs::new()));
                m
            },
            rootfs_vfs: crate::vfs::RootFsVfs::new(),
        }
    }

    /// Capture the guest's `AddressSpace` region list so that
    /// `/proc/self/maps` reflects the real loaded layout (executable
    /// ELF segments, runtime regions, mmap arena, stack, EL0
    /// trampoline, EL1 vectors, page tables) instead of a fixed
    /// summary. Called once after `HvfTrapEngine::map_address_space`
    /// succeeds.
    pub fn set_address_space_regions(&mut self, regions: Vec<ProcMapsEntry>) {
        self.address_space_regions = Some(regions);
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        let mut s = Self::new();
        s.rootfs_vfs.rootfs = Some(rootfs);
        s
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.rootfs_vfs.rootfs = Some(rootfs);
        s.executable_path = executable_path.into();
        s
    }

    /// Swap the in-memory default for any other [`FsBackend`]. Used by
    /// the CLI's `--fs host` to switch to a cap-std-sandboxed scratch
    /// directory. Returns the previously-installed backend so the
    /// caller can decide what to do with it (normally just drop).
    pub fn set_fs_backend(&mut self, backend: Box<dyn FsBackend>) -> Box<dyn FsBackend> {
        self.rootfs_vfs.set_overlay(backend)
    }

    /// Name of the currently-installed backend (for logging / debug).
    pub fn fs_backend_name(&self) -> &'static str {
        self.rootfs_vfs.overlay.name()
    }

    /// Borrow the dispatcher's rootfs. Used by the runtime when the
    /// dispatcher returns `DispatchOutcome::Execve` and the new image
    /// has to be loaded from the same image layers.
    pub fn rootfs(&self) -> Option<&RootFs> {
        self.rootfs_vfs.rootfs.as_ref()
    }

    /// Read a regular file's bytes through the layered view (overlay
    /// first, then rootfs). Used by the runtime's execve path to
    /// detect `#!` shebang scripts and to load executables that the
    /// guest wrote into the overlay (which `load_elf_from_rootfs`
    /// alone would miss). Returns None if the path isn't a readable
    /// file in either layer.
    pub fn read_exec_file(&self, path: &str) -> Option<Vec<u8>> {
        if let Some(bytes) = self.rootfs_vfs.overlay.file_contents(path) {
            return Some(bytes);
        }
        self.rootfs_vfs.rootfs.as_ref()?.read(path).ok()
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Enable live passthrough for fd 1/2. After this, `write`/`writev`
    /// to the stdio fds go straight to host fd 1/2 via `libc::write`
    /// instead of accumulating in the in-memory buffers — required for
    /// interactive prompts (`/ # `, cursor-position queries, etc.) to
    /// reach the user's terminal before the guest exits.
    pub fn set_stream_stdio(&mut self, on: bool) {
        self.stream_stdio = on;
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

    /// Linux execve(2) closes every fd that had FD_CLOEXEC set. Our
    /// dispatcher previously preserved every fd across execve, which
    /// meant a forked-then-exec'd child kept holding read-end references
    /// to all of its parent's pipes — even ones it had marked CLOEXEC.
    /// apt's http method sets CLOEXEC on fd 3..1023, un-sets it on
    /// 0/1/2, then execve's, expecting the kernel to drop the inherited
    /// pipe ends. Without that drop, the host kernel pipe stays in a
    /// state where the parent's POLLIN never fires reliably.
    ///
    /// Walk open_files; for each fd whose fd_flags include FD_CLOEXEC,
    /// remove it and run close_open_file (which honours the Rc-count
    /// guard, so we don't close a host fd a sibling fd still aliases).
    pub fn close_cloexec_fds(&mut self) {
        let cloexec_fds: Vec<i32> = self
            .open_files
            .iter()
            .filter_map(|(fd, of)| {
                if of.fd_flags & LINUX_FD_CLOEXEC != 0 {
                    Some(*fd)
                } else {
                    None
                }
            })
            .collect();
        for fd in cloexec_fds {
            if let Some(open_file) = self.open_files.remove(&fd) {
                close_open_file(&open_file);
            }
        }
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Look up the currently-installed handler for `signum`. Returns
    /// `None` when no handler has been recorded via `rt_sigaction`, or
    /// when the recorded handler is `SIG_DFL` / `SIG_IGN`. The runtime
    /// uses this to decide whether to inject a guest frame (handler is
    /// `Some`) or apply the host-side default (handler is `None`).
    pub fn registered_signal_handler(&self, signum: i32) -> Option<LinuxSigaction> {
        let action = self.signal_handlers.get(&signum).copied()?;
        let handler = action.sa_handler;
        if handler == crate::linux_abi::LINUX_SIG_DFL
            || handler == crate::linux_abi::LINUX_SIG_IGN
        {
            None
        } else {
            Some(action)
        }
    }

    /// True iff the guest installed `SIG_IGN` for `signum`. Lets the
    /// runtime drop a pending signal without injecting it.
    pub fn signal_is_ignored(&self, signum: i32) -> bool {
        self.signal_handlers
            .get(&signum)
            .map(|a| a.sa_handler == crate::linux_abi::LINUX_SIG_IGN)
            .unwrap_or(false)
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

        // Systematic unknown-flag check. For each syscall whose flag
        // argument has a well-defined supported mask, validate the
        // bits BEFORE the handler runs. The handler still executes
        // (it makes its own EINVAL decisions); this just guarantees
        // a structured report entry whenever a bit drifts.
        for (nr, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *nr == request.number {
                let value = request.arg(*arg_index as usize);
                check_syscall_flags(
                    reporter,
                    request.number,
                    name,
                    *arg_index,
                    value,
                    *mask,
                );
            }
        }

        // Syscalls migrated to the normalized SyscallCtx handler contract are
        // dispatched here first; the borrow of memory/reporter is scoped to
        // the call, so the legacy match below can still use them for the rest.
        if let Some(result) = self.dispatch_normalized(request, memory, reporter) {
            let outcome = result?;
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number,
                name: name.to_owned(),
                retval,
                errno,
            });
            return Ok(outcome);
        }

        let outcome = match request.number {
            5..=16 => self.xattr_unsupported(),
            43 => self.statfs(request, memory)?,
            44 => self.fstatfs(request, memory),
            45 => self.truncate(request, memory)?,
            74 => self.bootstrap_enosys(),
            75 => self.bootstrap_enosys(),
            77 => self.bootstrap_enosys(),
            93 => self.exit(request),
            94 => self.exit(request),
            // setfsuid / setfsgid: Linux convention is to return the
            // PREVIOUS fsuid/fsgid (not 0/error). We treat fsuid as the
            // effective uid for tracking purposes.
            151 => DispatchOutcome::Returned {
                value: i64::from(self.cred_euid),
            },
            152 => DispatchOutcome::Returned {
                value: i64::from(self.cred_egid),
            },
            // getgroups(size, list): we belong to no supplementary groups.
            // size=0 means "tell me how many" — return 0. Otherwise write
            // nothing and return 0. setgroups: accept and ignore.
            159 => DispatchOutcome::Returned { value: 0 },
            172 => self.getpid(),
            173 => DispatchOutcome::Returned { value: 1 },
            174 => DispatchOutcome::Returned { value: i64::from(self.cred_ruid) },
            175 => DispatchOutcome::Returned { value: i64::from(self.cred_euid) },
            176 => DispatchOutcome::Returned { value: i64::from(self.cred_rgid) },
            177 => DispatchOutcome::Returned { value: i64::from(self.cred_egid) },
            178 => self.getpid(),
            243 => self.recvmmsg(request, memory),
            269 => self.sendmmsg(request, memory),
            435 => self.clone3(request, memory),
            283 => self.membarrier(request),
            293 => self.rseq(),
            _ => {
                reporter.record(CompatEvent::unhandled_syscall(
                    request.number,
                    name,
                    request.args,
                ));
                panic!(
                    "unimplemented syscall {} ({}) args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
                    request.number,
                    name,
                    request.arg(0),
                    request.arg(1),
                    request.arg(2),
                    request.arg(3),
                    request.arg(4),
                    request.arg(5),
                );
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

    fn getcwd<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let size = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let mut bytes = self.cwd.as_bytes().to_vec();
        bytes.push(0);
        if bytes.len() > size {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ERANGE,
            });
        }
        if ctx.memory.write_bytes(address, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        // Linux getcwd(2) returns the LENGTH of the buffer filled (including
        // the terminating NUL), not the buffer address. glibc tolerates a
        // positive non-length, but tools that use the return value as a
        // length (and the kernel ABI) require the real count.
        Ok(DispatchOutcome::Returned {
            value: bytes.len() as i64,
        })
    }

    fn faccessat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Linux's `faccessat` (syscall 48) takes only (dirfd, pathname, mode).
        // The 4-arg form with flags is `faccessat2` (syscall 439). We were
        // erroneously reading x3 as flags here, which is whatever uninit
        // register state the caller had — making glibc see EINVAL for normal
        // access(F_OK)-style calls and abort with "stack smashing detected".
        self.access_at(ctx.arg(0), ctx.arg(1), ctx.arg(2), 0, &*ctx.memory)
    }

    fn faccessat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.access_at(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            &*ctx.memory,
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
        // Synthetic /proc /sys paths bypass the rootfs/overlay
        // layered view: they have their own permission model.
        if let Some(outcome) = self.synthetic_access(path, mode) {
            return outcome;
        }
        // Layered overlay+rootfs lookup via RootFsVfs. AT_SYMLINK_NOFOLLOW
        // doesn't change the access mask (no chmod-on-link semantics
        // exposed in our compat layer), so we use the default lookup.
        let _ = flags; // AT_SYMLINK_NOFOLLOW is currently a no-op here
        use crate::vfs::Vfs as _;
        match self.rootfs_vfs.lookup(path) {
            Ok(md) => access_metadata(&vfs_md_to_rootfs_md(path, &md), mode),
            Err(errno) => DispatchOutcome::Errno { errno },
        }
    }

    fn fd_access(&self, fd: i32, mode: u64) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&fd) else {
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::HostFile { metadata, .. }
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
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => synthetic_readonly_access(mode),
        }
    }

    fn chdir<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname = ctx.arg(0);
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(LINUX_AT_FDCWD, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Use the LAYERED lookup (overlay/host backend first, then rootfs),
        // not just the immutable rootfs — otherwise a freshly mkdir'd
        // directory is invisible and chdir into it fails ENOENT (dpkg-deb
        // mkdir's its extraction dir then chdir's there).
        let metadata = match self.layered_metadata(&path) {
            Ok(metadata) => metadata,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if metadata.kind != RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            });
        }
        self.cwd = display_rootfs_path(&metadata.path);
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fchdir<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        Ok(match &*open {
            OpenDescription::Directory { metadata, .. } => {
                self.cwd = display_rootfs_path(&metadata.path);
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { .. }
            | OpenDescription::HostFile { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => DispatchOutcome::Errno {
                errno: LINUX_ENOTDIR,
            },
        })
    }

    fn synthetic_access(&self, path: &str, mode: u64) -> Option<DispatchOutcome> {
        if !is_synthetic_virtual_file(path, &self.synthetic_proc_context()) {
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

    fn eventfd2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let initial_value = ctx.arg(0);
        let flags = ctx.arg(1);
        if flags & !(LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::EventFd {
            counter: initial_value,
            semaphore: flags & LINUX_EFD_SEMAPHORE != 0,
            status_flags: flags & LINUX_EFD_NONBLOCK,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    fn timerfd_create<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let flags = ctx.arg(1);
        if linux_clock_duration(clock_id).is_none()
            || flags & !(LINUX_TFD_NONBLOCK | LINUX_TFD_CLOEXEC) != 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::TimerFd {
            clock_id,
            interval: None,
            deadline: None,
            expirations: 0,
            status_flags: flags & LINUX_TFD_NONBLOCK,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    fn timerfd_settime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let flags = ctx.arg(1);
        let new_value = ctx.arg(2);
        let old_value = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let spec = match read_itimerspec(memory, new_value) {
            Ok(spec) => spec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (next_interval, next_value) = match itimerspec_durations(spec) {
            Ok(value) => value,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };

        if old_value != 0 {
            let previous = timerfd_itimerspec(*clock_id, *interval, *deadline);
            if write_kernel_struct_raw(memory, old_value, &previous).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
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
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn timerfd_gettime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let current_value = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        let OpenDescription::TimerFd {
            clock_id,
            interval,
            deadline,
            ..
        } = &*open
        else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let current = timerfd_itimerspec(*clock_id, *interval, *deadline);
        Ok(write_kernel_struct(memory, current_value, &current))
    }

    fn epoll_create1<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(0);
        if flags & !LINUX_EPOLL_CLOEXEC != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = OpenDescription::Epoll {
            interest: HashMap::new(),
            status_flags: 0,
        };
        Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)))
    }

    fn epoll_ctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let epfd = ctx.arg(0) as i32;
        let operation = ctx.arg(1);
        let fd = ctx.arg(2) as i32;
        let event_address = ctx.arg(3);
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

    fn epoll_pwait<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let epfd = ctx.arg(0) as i32;
        let events_address = ctx.arg(1);
        let max_events = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
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
            if write_kernel_struct_raw(memory, address, event).is_err() {
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

    fn pselect6<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nfds = usize::try_from(ctx.arg(0))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(0)))?;
        let readfds_addr = ctx.arg(1);
        let writefds_addr = ctx.arg(2);
        let exceptfds_addr = ctx.arg(3);
        let timeout_addr = ctx.arg(4);
        let request = &ctx.request;
        let memory = &mut *ctx.memory;
        let reporter = &mut *ctx.reporter;

        // Decode timespec → millis for libc::poll. NULL = block forever (-1).
        let timeout_ms: i32 = if timeout_addr == 0 {
            -1
        } else {
            match memory.read_bytes(timeout_addr, 16) {
                Ok(b) if b.len() == 16 => {
                    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
                    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
                    let ms = sec
                        .saturating_mul(1000)
                        .saturating_add(nsec / 1_000_000);
                    if ms <= 0 {
                        0
                    } else if ms > i32::MAX as i64 {
                        i32::MAX
                    } else {
                        ms as i32
                    }
                }
                _ => 0,
            }
        };

        // Pull each fd_set into memory.
        let read_set = match self.read_optional_fd_set(memory, readfds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let write_set = match self.read_optional_fd_set(memory, writefds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let except_set = match self.read_optional_fd_set(memory, exceptfds_addr, nfds)? {
            Ok(s) => s,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        // Collect the union of the three sets into per-fd entries, and try to
        // map each guest fd to a real host fd. Then route exactly like ppoll:
        //   - all fds host-backed → one libc::poll (kernel blocks efficiently);
        //   - any fd synthetic (eventfd/timerfd/epoll/in-memory pipe) → the
        //     poll_ready_events readiness loop, which is correct for those.
        // The old code unwrap_or'd synthetic fds into the guest fd *number* and
        // polled that as a host fd — which blocks on carrick's own fds and
        // deadlocks. Each fd gets POLLIN/POLLOUT/POLLPRI per its set membership.
        let mut owners: Vec<(i32, i16)> = Vec::new(); // (fd, requested_mask)
        let mut events_list: Vec<i16> = Vec::new();
        let mut host_map: Vec<Option<i32>> = Vec::new();
        for fd in 0..nfds {
            let r = read_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            let w = write_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            let e = except_set.as_ref().map_or(false, |s| fd_set_contains(s, fd));
            if !(r || w || e) {
                continue;
            }
            let fd_i32 = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
            if !self.fd_is_valid(fd_i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let mut events: i16 = 0;
            if r { events |= libc::POLLIN; }
            if w { events |= libc::POLLOUT; }
            if e { events |= libc::POLLPRI; }
            let mut req_mask: i16 = 0;
            if r { req_mask |= 0x01; }
            if w { req_mask |= 0x02; }
            if e { req_mask |= 0x04; }
            owners.push((fd_i32, req_mask));
            events_list.push(events);
            host_map.push(self.host_fd_for_poll(fd_i32));
        }

        // revents per entry, filled by whichever path runs.
        let mut revents: Vec<i16> = vec![0; owners.len()];
        let all_host: Option<Vec<i32>> = host_map.iter().copied().collect();

        if owners.is_empty() {
            if timeout_ms > 0 {
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: (timeout_ms / 1000) as libc::time_t,
                        tv_nsec: ((timeout_ms % 1000) as i64 * 1_000_000) as libc::c_long,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
            }
        } else if let Some(host_fds) = all_host {
            let mut pollfds: Vec<libc::pollfd> = host_fds
                .iter()
                .zip(events_list.iter())
                .map(|(hf, ev)| libc::pollfd { fd: *hf, events: *ev, revents: 0 })
                .collect();
            let n = unsafe {
                libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, timeout_ms)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            for (slot, p) in revents.iter_mut().zip(pollfds.iter()) {
                *slot = p.revents;
            }
        } else {
            // Mixed/synthetic: per-fd readiness with nanosleep slicing.
            let mut deadline_attempts = 0u32;
            loop {
                let mut any = false;
                for (i, (fd, _)) in owners.iter().enumerate() {
                    let rev = self.poll_ready_events(*fd, events_list[i]);
                    revents[i] = rev;
                    if rev != 0 {
                        any = true;
                    }
                }
                if any || timeout_ms == 0 {
                    break;
                }
                const SLICE_MS: u32 = 10;
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: (SLICE_MS as i64) * 1_000_000,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
                deadline_attempts += 1;
                if timeout_ms > 0 {
                    if deadline_attempts.saturating_mul(SLICE_MS) as i32 >= timeout_ms {
                        break;
                    }
                } else if deadline_attempts > 6000 {
                    // Blocked ~60 s with no fd ever ready: almost certainly a
                    // missing readiness signal, not a real idle wait. Make it
                    // loud in `carrick trace` instead of silently returning 0.
                    reporter.record(CompatEvent::partial_syscall(
                        request.number,
                        "pselect6",
                        request.args,
                        "blocked ~60s with no fd ready (possible poll deadlock)",
                    ));
                    break;
                }
            }
        }

        // Adapter so the writeback below reads `p.revents` uniformly.
        let pollfds: Vec<libc::pollfd> = owners
            .iter()
            .zip(revents.iter())
            .map(|((fd, _), rev)| libc::pollfd { fd: *fd, events: 0, revents: *rev })
            .collect();

        // Write back ready bits. Start with fully-cleared sets and only
        // set bits for fds that fired.
        let mut new_read = read_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut new_write = write_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut new_except = except_set.clone().map(|mut s| { for b in &mut s { *b = 0 } s });
        let mut ready = 0i64;
        for ((fd, req_mask), p) in owners.iter().zip(pollfds.iter()) {
            let fd_usize = *fd as usize;
            let revs = p.revents;
            let mut fired = false;
            if (req_mask & 0x01) != 0 && (revs & (libc::POLLIN | libc::POLLHUP)) != 0 {
                if let Some(ref mut set) = new_read { fd_set_set(set, fd_usize); fired = true; }
            }
            if (req_mask & 0x02) != 0 && (revs & libc::POLLOUT) != 0 {
                if let Some(ref mut set) = new_write { fd_set_set(set, fd_usize); fired = true; }
            }
            if (req_mask & 0x04) != 0 && (revs & (libc::POLLPRI | libc::POLLERR)) != 0 {
                if let Some(ref mut set) = new_except { fd_set_set(set, fd_usize); fired = true; }
            }
            if fired { ready += 1; }
        }
        if let Some(s) = &new_read {
            if memory.write_bytes(readfds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if let Some(s) = &new_write {
            if memory.write_bytes(writefds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if let Some(s) = &new_except {
            if memory.write_bytes(exceptfds_addr, s).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: ready })
    }

    fn read_optional_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
    ) -> Result<Result<Option<Vec<u8>>, i32>, DispatchError> {
        if address == 0 {
            return Ok(Ok(None));
        }
        match read_fd_set(memory, address, nfds) {
            Ok(s) => Ok(Ok(Some(s))),
            Err(errno) => Ok(Err(errno)),
        }
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

    fn ppoll<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pollfds_address = ctx.arg(0);
        let nfds = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let timeout_address = ctx.arg(2);
        let request = &ctx.request;
        let memory = &mut *ctx.memory;
        let reporter = &mut *ctx.reporter;

        // Decode timeout. NULL pointer means block forever; non-NULL points
        // to a `struct timespec { i64 tv_sec; i64 tv_nsec; }`. We translate
        // to milliseconds for libc::poll (-1 = forever, 0 = immediate).
        let timeout_ms: i32 = if timeout_address == 0 {
            -1
        } else {
            match memory.read_bytes(timeout_address, 16) {
                Ok(b) if b.len() == 16 => {
                    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap_or([0; 8]));
                    let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap_or([0; 8]));
                    let ms = sec
                        .saturating_mul(1000)
                        .saturating_add(nsec / 1_000_000);
                    if ms <= 0 {
                        0
                    } else if ms > i32::MAX as i64 {
                        i32::MAX
                    } else {
                        ms as i32
                    }
                }
                _ => 0,
            }
        };

        // Read all the pollfds up front so we can route them. Fast path:
        // every fd in the set maps to a host fd (stdio bare, HostPipe, or
        // HostSocket) → call libc::poll once with the requested timeout
        // and let the kernel block efficiently instead of pseudo-polling
        // in a 10 ms-slice loop.
        let pollfd_size = core::mem::size_of::<LinuxPollFd>();
        let mut fds: Vec<LinuxPollFd> = Vec::with_capacity(nfds);
        let mut addresses: Vec<u64> = Vec::with_capacity(nfds);
        for index in 0..nfds {
            let offset = index
                .checked_mul(pollfd_size)
                .and_then(|offset| u64::try_from(offset).ok())
                .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
            let address = pollfds_address
                .checked_add(offset)
                .ok_or(LINUX_EFAULT);
            let address = match address {
                Ok(a) => a,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            };
            let pollfd = match read_pollfd(memory, address) {
                Ok(p) => p,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            fds.push(pollfd);
            addresses.push(address);
        }
        // Map guest fds → host fds where possible. Fast path requires
        // every fd be host-backed (stdio bare, HostPipe, HostSocket).
        let host_fds: Option<Vec<i32>> = fds
            .iter()
            .map(|p| self.host_fd_for_poll(p.fd))
            .collect();
        if let Some(host_fds) = host_fds {
            let mut sys_pollfds: Vec<libc::pollfd> = fds
                .iter()
                .zip(host_fds.iter())
                .map(|(p, hf)| libc::pollfd {
                    fd: *hf,
                    events: p.events as i16,
                    revents: 0,
                })
                .collect();
            let n = unsafe {
                libc::poll(
                    sys_pollfds.as_mut_ptr(),
                    sys_pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: host_errno(),
                });
            }
            let mut ready = 0i64;
            for (i, p) in sys_pollfds.iter().enumerate() {
                let mut pollfd = fds[i];
                pollfd.revents = p.revents as i16;
                if pollfd.revents != 0 {
                    ready += 1;
                }
                if write_kernel_struct_raw(memory, addresses[i], &pollfd).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            }
            return Ok(DispatchOutcome::Returned { value: ready });
        }

        // Mixed / synthetic fds: fall back to the per-fd readiness check
        // loop. Slow because of nanosleep slicing but correct.
        let mut ready = 0i64;
        let mut deadline_attempts = 0u32;
        loop {
            ready = 0;
            for (index, pollfd) in fds.iter_mut().enumerate() {
                pollfd.revents = self.poll_ready_events(pollfd.fd, pollfd.events);
                if pollfd.revents != 0 {
                    ready += 1;
                }
                if write_kernel_struct_raw(memory, addresses[index], pollfd).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            }
            if ready > 0 || timeout_ms == 0 {
                break;
            }
            const SLICE_MS: u32 = 10;
            unsafe {
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: (SLICE_MS as i64) * 1_000_000,
                };
                libc::nanosleep(&ts, std::ptr::null_mut());
            }
            deadline_attempts += 1;
            if timeout_ms > 0 {
                let elapsed_ms = deadline_attempts.saturating_mul(SLICE_MS);
                if elapsed_ms as i32 >= timeout_ms {
                    break;
                }
            } else if deadline_attempts > 6000 {
                // ~60 s ceiling for "block forever" callers. Reaching it means
                // no fd ever became ready — surface it loudly in carrick trace
                // rather than silently returning 0 (a likely poll deadlock).
                reporter.record(CompatEvent::partial_syscall(
                    request.number,
                    "ppoll",
                    request.args,
                    "blocked ~60s with no fd ready (possible poll deadlock)",
                ));
                break;
            }
        }

        Ok(DispatchOutcome::Returned { value: ready })
    }

    /// Return the host fd backing a guest fd for ppoll's fast path.
    /// `Some(host_fd)` means we can hand this off to libc::poll.
    /// `None` means it's synthetic (epoll/eventfd/timerfd/in-memory pipe)
    /// and ppoll has to fall back to the per-fd readiness loop.
    fn host_fd_for_poll(&self, fd: i32) -> Option<i32> {
        if fd < 0 {
            // Negative fd in a pollfd entry: libc::poll ignores it
            // (revents=0), which is the right semantic. Pass it through.
            return Some(fd);
        }
        if let Some(open_file) = self.open_files.get(&fd) {
            let open = open_file.description.borrow();
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
                _ => None,
            };
        }
        if is_stdio_fd(fd) {
            return Some(fd);
        }
        // Unknown fd: do NOT pass the guest fd number through as a host fd
        // (host fds 3,4,5… belong to carrick itself — the cap-std rootfs dir,
        // the HVF device, etc., so polling them blocks on the wrong object).
        // Route to the synthetic readiness path instead.
        None
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return if is_stdio_fd(fd) {
                // fd 1/2 are always writable (we either buffer or stream
                // straight to host write). For fd 0 we have to actually
                // poll the host because the guest's read(0,...) ultimately
                // calls libc::read(0,...); without a real readiness check,
                // ppoll would always return POLLOUT only and never POLLIN,
                // breaking interactive shells that ppoll(stdin) before
                // each prompt.
                let mut revents = requested_events & LINUX_POLLOUT;
                if fd == 0 && (requested_events & LINUX_POLLIN) != 0 {
                    let mut pfd = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let n = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                    if n > 0 {
                        if pfd.revents & libc::POLLIN != 0 {
                            revents |= LINUX_POLLIN;
                        }
                        if pfd.revents & libc::POLLHUP != 0 {
                            revents |= LINUX_POLLHUP;
                        }
                    }
                }
                revents
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
            // Regular files are always ready for read and write.
            OpenDescription::HostFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
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
            OpenDescription::HostSocket { host_fd, .. } => {
                // Poll the real host fd so the guest's poll loop reflects
                // actual kernel readiness for the socket.
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
        }
        ready
    }

    fn pipe2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let flags = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if flags & !(LINUX_O_CLOEXEC | LINUX_O_NONBLOCK) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        // Allocate a real host pipe so the two ends share state via the
        // kernel and survive `libc::fork(2)` natively. macOS's `pipe(2)`
        // returns two fds: [0] read end, [1] write end.
        let mut host_fds = [0i32; 2];
        let r = unsafe { libc::pipe(host_fds.as_mut_ptr()) };
        if r != 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }

        let host_read = host_fds[0];
        let host_write = host_fds[1];

        let Some(read_fd) = self.allocate_fd(3) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if write_kernel_struct_raw(memory, address, &pair).is_err() {
            unsafe {
                libc::close(host_read);
                libc::close(host_write);
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        // The access mode must be encoded per end so fcntl(F_GETFL) reports
        // it: the read end is O_RDONLY (0), the write end O_WRONLY. Without
        // this, glibc's fdopen(write_end, "w") sees O_RDONLY via F_GETFL and
        // fails with EINVAL ("Failed to open new FD - fdopen") — apt's dpkg
        // status pipe hit exactly that.
        let nonblock = flags & LINUX_O_NONBLOCK;
        let fd_flags = linux_fd_flags_from_open_flags(flags);
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: host_read,
                    is_read_end: true,
                    status_flags: LINUX_O_RDONLY | nonblock,
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
                    status_flags: LINUX_O_WRONLY | nonblock,
                })),
                fd_flags,
            },
        );

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn dup<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_fd = ctx.arg(0) as i32;
        Ok(self.duplicate_fd(old_fd, 3, 0))
    }

    fn dup3<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_fd = ctx.arg(0) as i32;
        let new_fd = ctx.arg(1) as i32;
        let flags = ctx.arg(2);
        // Linux dup3 requires old_fd != new_fd and only honours
        // O_CLOEXEC in `flags`. It explicitly allows new_fd to be 0/1/2
        // — that's how shells redirect stdin/stdout/stderr.
        if old_fd == new_fd || flags & !LINUX_O_CLOEXEC != 0 || new_fd < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let description = match self.open_files.get(&old_fd) {
            Some(open_file) => Rc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) => {
                // Shell `2>&1` style redirects: the source fd is the
                // process's real host fd 0/1/2 (no OpenDescription was
                // ever created for them — writes go straight through
                // stream_stdio). dup3 onto a different fd needs to
                // capture that host fd so future writes/reads also
                // reach the same host endpoint. Duplicate the host fd
                // and wrap it as a HostPipe so the write path picks it
                // up before the bare-stdio fallback.
                let duped = unsafe { libc::dup(old_fd) };
                if duped < 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: host_errno(),
                    });
                }
                Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: duped,
                    is_read_end: old_fd == 0,
                    status_flags: 0,
                }))
            }
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
        };
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
        Ok(DispatchOutcome::Returned {
            value: new_fd as i64,
        })
    }

    fn fcntl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let command = ctx.arg(1);
        let arg = ctx.arg(2);
        Ok(match command {
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
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                };
                match &*open_file.description.borrow() {
                    OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. } => {
                        DispatchOutcome::Returned {
                            value: LINUX_PIPE_BUF_SIZE,
                        }
                    }
                    OpenDescription::HostSocket { .. } => {
                        DispatchOutcome::Errno { errno: LINUX_EBADF }
                    }
                    _ => DispatchOutcome::Errno { errno: LINUX_EBADF },
                }
            }
            LINUX_F_GETFD => {
                if let Some(open_file) = self.open_files.get(&fd) {
                    return Ok(DispatchOutcome::Returned {
                        value: open_file.fd_flags as i64,
                    });
                }
                // stdio without an OpenDescription: not CLOEXEC by default
                // (Linux semantics: stdio survives exec). Return 0.
                if is_stdio_fd(fd) {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_SETFD => {
                if let Some(open_file) = self.open_files.get_mut(&fd) {
                    open_file.fd_flags = arg & LINUX_FD_CLOEXEC;
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                // apt's http method fcntl(fd, F_SETFD, FD_CLOEXEC)s its
                // inherited stdio fds on startup. Returning EBADF here
                // makes apt abort with "Could not set close on exec".
                // Carrick's exec inherits stdio via the host fd directly;
                // CLOEXEC is meaningless for our model (we don't exec
                // anything host-side after the syscall returns) but we
                // accept the call so the guest's bookkeeping succeeds.
                if is_stdio_fd(fd) {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_GETFL => {
                if let Some(open_file) = self.open_files.get(&fd) {
                    let open = open_file.description.borrow();
                    return Ok(DispatchOutcome::Returned {
                        value: open.status_flags() as i64,
                    });
                }
                // stdio without an OpenDescription: glibc cat/head/etc
                // probe `fcntl(1, F_GETFL)` on startup to decide whether
                // stdout is append-only. Returning O_RDWR (with the
                // appropriate direction for fd 0 vs 1/2) keeps them happy
                // instead of bailing with "Bad file descriptor".
                if is_stdio_fd(fd) {
                    let flags: u64 = if fd == 0 {
                        LINUX_O_RDONLY
                    } else {
                        LINUX_O_WRONLY
                    };
                    return Ok(DispatchOutcome::Returned { value: flags as i64 });
                }
                DispatchOutcome::Errno { errno: LINUX_EBADF }
            }
            LINUX_F_SETFL => {
                let Some(open_file) = self.open_files.get(&fd) else {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                };
                let next_flags = arg & !LINUX_O_CLOEXEC;
                // Propagate O_NONBLOCK to the underlying host fd when one
                // exists. Without this, our libc::read still blocks even
                // after the guest set O_NONBLOCK — apt's http method
                // depends on this for the pselect6 wait pattern.
                let open = open_file.description.borrow();
                if let Some(host_fd) = match &*open {
                    OpenDescription::HostPipe { host_fd, .. }
                    | OpenDescription::HostSocket { host_fd, .. } => Some(*host_fd),
                    _ => None,
                } {
                    let want_nonblock = next_flags & LINUX_O_NONBLOCK != 0;
                    unsafe {
                        let cur = libc::fcntl(host_fd, libc::F_GETFL, 0);
                        if cur >= 0 {
                            let next = if want_nonblock {
                                cur | libc::O_NONBLOCK
                            } else {
                                cur & !libc::O_NONBLOCK
                            };
                            if next != cur {
                                libc::fcntl(host_fd, libc::F_SETFL, next);
                            }
                        }
                    }
                }
                drop(open);
                open_file
                    .description
                    .borrow_mut()
                    .set_status_flags(next_flags);
                DispatchOutcome::Returned { value: 0 }
            }
            // Advisory record locks: apt uses fcntl(F_SETLK) on
            // /var/lib/apt/lists/lock as its inter-process lock. Carrick
            // runs the guest as a single-tenant VM (no real concurrent
            // apt invocations against the same overlay), so we treat the
            // whole F_*LK family as no-op success. Without this apt
            // reports "Could not get lock ... open (22: Invalid argument)"
            // because the F_SETLK that follows the openat is what
            // actually fails — apt's error message just blames open.
            LINUX_F_SETLK
            | LINUX_F_SETLKW
            | LINUX_F_OFD_SETLK
            | LINUX_F_OFD_SETLKW => {
                if !self.fd_is_valid(fd) {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_F_GETLK | LINUX_F_OFD_GETLK => {
                // Indicate "no lock present" by leaving the caller's
                // struct flock untouched and returning 0. apt only ever
                // probes after a successful SETLK so it doesn't
                // re-inspect the buffer.
                if !self.fd_is_valid(fd) {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    fn ioctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let ioctl_request = ctx.arg(1);
        let arg = ctx.arg(2);
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        Ok(match ioctl_request {
            LINUX_TIOCGWINSZ if fd_is_tty(&self.open_files, fd) => {
                // Prefer the live host window size when stdin/stdout/stderr
                // is a real macOS terminal; fall back to the 80x24 stub so
                // headless invocations (CI, redirected pipes that we still
                // synthesize a TTY for in tests) keep prior behaviour.
                let winsize = if crate::host_tty::host_isatty(fd) {
                    crate::host_tty::get_host_winsize(fd)
                        .unwrap_or_else(LinuxWinsize::terminal_80x24)
                } else {
                    LinuxWinsize::terminal_80x24()
                };
                write_kernel_struct(&mut *ctx.memory, arg, &winsize)
            }
            LINUX_TIOCGWINSZ => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCGETS if fd_is_tty(&self.open_files, fd) => {
                // Mirror the live host terminal modes when available so
                // `less`, `vi`, and an interactive shell see the actual
                // ICANON/ECHO state the user has configured.
                let termios = if crate::host_tty::host_isatty(fd) {
                    crate::host_tty::get_host_termios(fd)
                        .unwrap_or_else(LinuxTermios::default_cooked)
                } else {
                    LinuxTermios::default_cooked()
                };
                // KernelAbi for LinuxTermios pins this at 36 bytes —
                // the kernel-ABI termios size, NOT our 44-byte Rust
                // struct (which includes the termios2-only ispeed/ospeed
                // tail). Going past 36 here is what blew glibc's
                // tcgetattr canary and crashed ls/dpkg.
                write_kernel_struct(&mut *ctx.memory, arg, &termios)
            }
            LINUX_TCGETS => DispatchOutcome::Errno {
                errno: LINUX_ENOTTY,
            },
            LINUX_TCSETS | LINUX_TCSETSW | LINUX_TCSETSF if fd_is_tty(&self.open_files, fd) => {
                // Read 36 bytes (kernel termios), then pad to the
                // 44-byte zerocopy struct so we can parse it. The guest
                // only provided a 36-byte buffer; reading 44 would
                // EFAULT at the boundary of a stack-page allocation.
                match ctx.memory.read_bytes(arg, LINUX_TERMIOS_KERNEL_SIZE) {
                    Ok(bytes) => {
                        if crate::host_tty::host_isatty(fd) {
                            let mut padded =
                                [0u8; core::mem::size_of::<LinuxTermios>()];
                            padded[..LINUX_TERMIOS_KERNEL_SIZE]
                                .copy_from_slice(&bytes);
                            if let Ok(t) = LinuxTermios::read_from_bytes(&padded) {
                                let _ = crate::host_tty::set_host_termios_tracking(fd, &t);
                            }
                        }
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(_) => DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    },
                }
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
                    write_packed(&mut *ctx.memory, arg, &LINUX_BOOTSTRAP_PGID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            LINUX_TIOCSPGRP => match self.tty_ioctl_fd_kind(fd) {
                Ok(TtyFdKind::Stdio) => {
                    let mut buf = [0u8; 4];
                    match ctx.memory.read_bytes(arg, 4) {
                        Ok(bytes) => buf.copy_from_slice(&bytes),
                        Err(_) => {
                            return Ok(DispatchOutcome::Errno {
                                errno: LINUX_EFAULT,
                            });
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
                write_packed(&mut *ctx.memory, arg, &available.to_le_bytes())
            }
            LINUX_FIONBIO => {
                if ctx.memory.read_bytes(arg, 4).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
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
                    write_packed(&mut *ctx.memory, arg, &LINUX_BOOTSTRAP_SID.to_le_bytes())
                }
                Ok(TtyFdKind::Other) => DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                },
                Err(errno) => DispatchOutcome::Errno { errno },
            },
            _ => {
                ctx.reporter
                    .record(CompatEvent::unhandled_ioctl(fd, ioctl_request, arg));
                DispatchOutcome::Errno {
                    errno: LINUX_ENOTTY,
                }
            }
        })
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

    fn flock<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let operation = ctx.arg(1);
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }

        let lock_operation = operation & !LINUX_LOCK_NB;
        Ok(match lock_operation {
            LINUX_LOCK_SH | LINUX_LOCK_EX | LINUX_LOCK_UN => DispatchOutcome::Returned { value: 0 },
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
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
        // Consult the layered view (overlay/disk first, then rootfs) so
        // that files the guest created in the overlay are visible here
        // too — a rootfs-direct lookup would miss them.
        if let Err(errno) = self.layered_metadata(&path) {
            return Ok(DispatchOutcome::Errno { errno });
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
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        // Layered metadata (overlay/disk first, then rootfs) — not rootfs-only,
        // so guest-created files are seen too.
        let kind = match self.layered_metadata(&resolved) {
            Ok(md) => md.kind,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if kind == RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
        }
        // Disk-backed: open the real file and ftruncate it. The whole rootfs
        // is materialised on the cap-std scratch under --fs host, so this
        // works for both rootfs and guest-created files. MemoryBackend has no
        // raw fd → EROFS (path-based truncate stays unsupported in-memory).
        match self.rootfs_vfs.overlay.open_raw_fd(&resolved, true, false, false) {
            Some(host_fd) => {
                let rc = unsafe { libc::ftruncate(host_fd, length as libc::off_t) };
                let err = if rc < 0 { host_errno() } else { 0 };
                unsafe { libc::close(host_fd) };
                if err != 0 {
                    Ok(DispatchOutcome::Errno { errno: err })
                } else {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }
            None => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    fn fallocate<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let mode = ctx.arg(1);
        let offset = i64::from_ne_bytes(ctx.arg(2).to_ne_bytes());
        let length = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length <= 0 || offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
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
            OpenDescription::File { .. }
            | OpenDescription::HostFile { .. }
            | OpenDescription::SyntheticFile { .. } => LINUX_EROFS,
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn ftruncate<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let length = i64::from_ne_bytes(ctx.arg(1).to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(open_file) = self.open_files.get(&fd).cloned() else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        // Snapshot the path + new contents in a scope so the borrow drops
        // before we touch self.rootfs_vfs.overlay.
        let writeback: Option<(String, Vec<u8>)>;
        let outcome: DispatchOutcome;
        {
            let mut open = open_file.description.borrow_mut();
            match &mut *open {
                OpenDescription::File {
                    path,
                    contents,
                    offset,
                    writable,
                    metadata,
                    ..
                } => {
                    if !*writable {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    }
                    let new_len = length as usize;
                    if new_len > contents.len() {
                        contents.resize(new_len, 0);
                    } else {
                        contents.truncate(new_len);
                        if *offset > new_len {
                            *offset = new_len;
                        }
                    }
                    metadata.size = contents.len();
                    writeback = Some((path.clone(), contents.clone()));
                    outcome = DispatchOutcome::Returned { value: 0 };
                }
                OpenDescription::HostFile {
                    host_fd, writable, ..
                } => {
                    if !*writable {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                    }
                    // Real fd: ftruncate the kernel file directly (the
                    // change is visible across fork).
                    let r = unsafe { libc::ftruncate(*host_fd, length as libc::off_t) };
                    if r < 0 {
                        return Ok(DispatchOutcome::Errno { errno: host_errno() });
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                OpenDescription::SyntheticFile { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
                }
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
            }
        }
        if let Some((path, contents)) = writeback {
            let _ = self.rootfs_vfs.overlay.set_file_contents(&path, contents);
        }
        Ok(outcome)
    }

    fn capget<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let header_address = ctx.arg(0);
        let data_address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if !linux_capability_version_is_supported(header.version) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if header.pid < 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if data_address == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let words = linux_capability_data_words(header.version);
        let empty = vec![LinuxCapabilityData::empty(); words];
        if memory
            .write_bytes(data_address, capability_data_bytes(&empty).as_slice())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn capset<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let header_address = ctx.arg(0);
        let data_address = ctx.arg(1);
        let memory = &*ctx.memory;
        let header = match read_capability_header(memory, header_address) {
            Ok(header) => header,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if !linux_capability_version_is_supported(header.version) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if header.pid < 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        let words = linux_capability_data_words(header.version);
        let data = match read_capability_data(memory, data_address, words) {
            Ok(data) => data,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if data.iter().any(|word| !word.is_empty()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EPERM });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn personality<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let previous = self.personality;
        if requested != LINUX_PERSONALITY_QUERY {
            self.personality = requested;
        }
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    fn prctl<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let option = ctx.request.arg(0);
        Ok(match option {
            LINUX_PR_GET_DUMPABLE => DispatchOutcome::Returned {
                value: self.dumpable,
            },
            LINUX_PR_SET_DUMPABLE => {
                let value = ctx.request.arg(1);
                if value > 1 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    });
                }
                self.dumpable = value as i64;
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_SET_NAME => {
                let address = ctx.request.arg(1);
                let Ok(bytes) = memory.read_bytes(address, LINUX_TASK_COMM_LEN) else {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                };
                self.task_name = linux_task_name_from_bytes(&bytes);
                // Reflect the guest's chosen name into the host
                // process/thread name as `carrick: <name>`, so `ps -M`
                // / Activity Monitor / lldb show which guest each
                // carrick host process is running.
                set_host_process_name(&self.task_name);
                DispatchOutcome::Returned { value: 0 }
            }
            LINUX_PR_GET_NAME => {
                let address = ctx.request.arg(1);
                if memory.write_bytes(address, &self.task_name).is_err() {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
                DispatchOutcome::Returned { value: 0 }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
        })
    }

    fn getcpu<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let cpu_address = ctx.request.arg(0);
        let node_address = ctx.request.arg(1);
        let bootstrap_value = 0u32.to_ne_bytes();

        if cpu_address != 0 && memory.write_bytes(cpu_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if node_address != 0 && memory.write_bytes(node_address, &bootstrap_value).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn set_tid_address<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.getpid())
    }

    fn set_robust_list<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let len = ctx.arg(1);
        if len == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn sched_yield<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        std::thread::yield_now();
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn sched_getaffinity<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0);
        let size = ctx.arg(1);
        let address = ctx.arg(2);
        let memory = &mut *ctx.memory;
        let current_pid = std::process::id() as u64;

        if pid != 0 && pid != current_pid {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if size < LINUX_BOOTSTRAP_AFFINITY_BYTES as u64 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let mut mask = [0_u8; LINUX_BOOTSTRAP_AFFINITY_BYTES];
        mask[0] = 1;
        if memory.write_bytes(address, &mask).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: LINUX_BOOTSTRAP_AFFINITY_BYTES as i64,
        })
    }

    fn futex<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let operation = ctx.arg(1);
        let value = ctx.arg(2) as u32;
        let timeout_address = ctx.arg(3);
        let memory = &*ctx.memory;
        let command = operation & LINUX_FUTEX_CMD_MASK;
        let flags = operation & !LINUX_FUTEX_CMD_MASK;
        if flags & !(LINUX_FUTEX_PRIVATE_FLAG | LINUX_FUTEX_CLOCK_REALTIME) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & LINUX_FUTEX_CLOCK_REALTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let word = match read_u32(memory, address) {
            Ok(word) => word,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        Ok(match command {
            LINUX_FUTEX_WAKE => DispatchOutcome::Returned { value: 0 },
            LINUX_FUTEX_WAIT => {
                if word != value {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    });
                }
                if timeout_address == 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    });
                }
                let timespec = match read_timespec(memory, timeout_address) {
                    Ok(timespec) => timespec,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                };
                let timeout = match duration_from_linux_timespec(timespec) {
                    Ok(timeout) => timeout,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
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
        })
    }

    fn nanosleep<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request_address = ctx.arg(0);
        let memory = &*ctx.memory;
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let duration = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if let Some(duration) = duration {
            std::thread::sleep(duration);
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn clock_nanosleep<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let flags = ctx.arg(1);
        let request_address = ctx.arg(2);
        let memory = &*ctx.memory;
        if flags & !LINUX_TIMER_ABSTIME != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(now) = linux_clock_duration(clock_id) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let timespec = match read_timespec(memory, request_address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let requested = match duration_from_linux_timespec(timespec) {
            Ok(duration) => duration.unwrap_or(Duration::ZERO),
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let sleep_duration = if flags & LINUX_TIMER_ABSTIME != 0 {
            requested.saturating_sub(now)
        } else {
            requested
        };
        if !sleep_duration.is_zero() {
            std::thread::sleep(sleep_duration);
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn clock_gettime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        let Some(duration) = linux_clock_duration(clock_id) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        };
        let timespec = linux_timespec_from_duration(duration);
        Ok(write_kernel_struct(memory, address, &timespec))
    }

    fn clock_getres<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if linux_clock_duration(clock_id).is_none() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if address == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        Ok(write_packed(
            memory,
            address,
            LinuxTimespec::new(0, LINUX_CLOCK_RESOLUTION_NSEC).as_bytes(),
        ))
    }

    fn clock_settime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &*ctx.memory;
        if !linux_clock_is_known(clock_id) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Reading the timespec lets us surface EFAULT for bad pointers and
        // EINVAL for invalid tv_nsec, matching the order real Linux performs
        // these checks before the privilege check kicks in for unsupported
        // clocks.
        let timespec = match read_timespec(memory, address) {
            Ok(timespec) => timespec,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let tv_nsec = timespec.tv_nsec;
        if !(0..1_000_000_000).contains(&tv_nsec) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Monotonic-family clocks can never be set; report EINVAL like the
        // real kernel.
        if !linux_clock_is_settable(clock_id) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // For settable clocks (CLOCK_REALTIME, CLOCK_REALTIME_ALARM, CLOCK_TAI)
        // we still refuse: we are not root and we do not actually mutate the
        // host clock.
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    fn getitimer<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &mut *ctx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if address == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        // No timer is ever armed, so the truthful answer is a zeroed
        // itimerval (interval and value both zero == "disarmed").
        Ok(write_kernel_struct(memory, address, &LinuxItimerval::zeroed()))
    }

    fn setitimer<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let new_address = ctx.arg(1);
        let old_address = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if !linux_itimer_which_is_valid(which) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if new_address != 0 {
            let new_value = match read_itimerval(memory, new_address) {
                Ok(value) => value,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            if !linux_timeval_usec_is_valid(new_value.it_interval)
                || !linux_timeval_usec_is_valid(new_value.it_value)
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if old_address != 0 {
            let outcome = write_kernel_struct(memory, old_address, &LinuxItimerval::zeroed());
            if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                return Ok(outcome);
            }
        }
        ctx.reporter.record(CompatEvent::partial_syscall(
            ctx.request.number,
            "setitimer",
            ctx.request.args,
            "bootstrap: no SIGALRM delivery yet",
        ));
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn adjtimex<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        Ok(adjtimex_bootstrap(&*ctx.memory, address))
    }

    fn clock_adjtime<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let clock_id = ctx.arg(0);
        let address = ctx.arg(1);
        let memory = &*ctx.memory;
        // Linux only accepts CLOCK_REALTIME for unprivileged callers (and
        // generally only CLOCK_REALTIME at all for adjtime semantics); anything
        // else is EINVAL.
        if clock_id != LINUX_CLOCK_REALTIME {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(adjtimex_bootstrap(memory, address))
    }

    fn kill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        Ok(bootstrap_signal_send(pid, /*tid_required=*/ false, signum))
    }

    fn tkill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        // tkill's target is a thread id, not a "0 means self" pid form.
        Ok(bootstrap_signal_send(tid, /*tid_required=*/ true, signum))
    }

    fn tgkill<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tgid = ctx.arg(0) as i64;
        let tid = ctx.arg(1) as i64;
        let signum = ctx.arg(2);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let host_pid = std::process::id() as i64;
        let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
        let valid_self =
            (tgid == host_pid || tgid == bootstrap_pid)
                && (tid == host_pid || tid == bootstrap_pid);
        if !valid_self {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        if signum == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        crate::host_signal::raise_for_self(signum as i32);
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn sigaltstack<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let ss = ctx.arg(0);
        let old_ss = ctx.arg(1);
        let memory = &mut *ctx.memory;

        if old_ss != 0
            && memory
                .write_bytes(old_ss, LinuxSigaltstack::disabled().abi_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }

        if ss != 0 {
            let bytes = match memory.read_bytes(ss, core::mem::size_of::<LinuxSigaltstack>()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let new_stack = match LinuxSigaltstack::read_from_bytes(&bytes) {
                Ok(stack) => stack,
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            };
            let flags = new_stack.ss_flags as u32 as u64;
            // SS_ONSTACK is a query-only flag; reject it along with anything
            // unrecognized. Only SS_DISABLE is accepted from userspace.
            if flags & !LINUX_SS_DISABLE != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            if flags == 0 {
                let size = new_stack.ss_size;
                if size < LINUX_MINSIGSTKSZ {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_ENOMEM,
                    });
                }
            }
            // SS_DISABLE or a request with a sufficiently large stack is
            // silently dropped: we have no alternate signal stack machinery
            // yet, so there's nothing to install.
        }

        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn rt_sigsuspend<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let mask_ptr = ctx.arg(0);
        let sigset_size = ctx.arg(1);
        let memory = &*ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
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
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Errno {
            errno: LINUX_EINTR,
        })
    }

    fn rt_sigaction<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let signum = ctx.arg(0) as i32;
        let new_action = ctx.arg(1);
        let old_action = ctx.arg(2);
        let _sigset_size = ctx.arg(3);
        let memory = &mut *ctx.memory;
        // Linux returns EINVAL for signum <= 0 or > _NSIG (64 on
        // most arches). Reject these.
        if signum < 1 || signum > 64 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Write back the previously-installed handler (or zero if none).
        if old_action != 0 {
            let prev = self
                .signal_handlers
                .get(&signum)
                .copied()
                .unwrap_or_else(LinuxSigaction::empty);
            let _ = write_kernel_struct_raw(memory, old_action, &prev);
        }
        // Read and store the new handler. The kernel rejects attempts
        // to install handlers for SIGKILL (9) and SIGSTOP (19); leave
        // signum=0 in the lenient bucket for the interactive sh probe.
        if new_action != 0 && signum != 9 && signum != 19 {
            if let Ok(bytes) = memory.read_bytes(new_action, core::mem::size_of::<LinuxSigaction>()) {
                if let Ok(sa) = LinuxSigaction::ref_from_bytes(&bytes) {
                    self.signal_handlers.insert(signum, *sa);
                }
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn rt_sigprocmask<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let old_set = ctx.arg(2);
        let sigset_size = ctx.arg(3);
        let memory = &mut *ctx.memory;
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

    fn rt_sigtimedwait<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let set_ptr = ctx.arg(0);
        let timeout_ptr = ctx.arg(2);
        let sigset_size = ctx.arg(3);
        let memory = &*ctx.memory;
        if sigset_size != LINUX_RT_SIGSET_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if memory
            .read_bytes(set_ptr, LINUX_RT_SIGSET_SIZE as usize)
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if timeout_ptr != 0 {
            let timeout = match read_timespec(memory, timeout_ptr) {
                Ok(timeout) => timeout,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let tv_sec = timeout.tv_sec;
            let tv_nsec = timeout.tv_nsec;
            if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            // A zero timeout is a polling check that must return immediately.
            // We have no signal queue, so the answer is always "timed out".
        }
        // Non-zero timeout: a real implementation would block. With no signal
        // source we'd block forever, so report the timeout. info is only
        // written on success, and we never succeed.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        })
    }

    fn rt_sigqueueinfo<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let tgid = ctx.arg(0) as i64;
        let signum = ctx.arg(1);
        if !is_valid_signum(signum) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if tgid != LINUX_BOOTSTRAP_PID as i64 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        // No signal delivery; surface the gap explicitly rather than silently
        // swallowing the queued siginfo.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    fn rt_sigreturn<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // rt_sigreturn is invoked from a signal trampoline to restore the
        // pre-signal context. The dispatcher can't perform the restore
        // itself — only the trap engine has access to the vCPU register
        // file — so we signal `SigReturn` and let the runtime drive
        // `HvfTrapEngine::rt_sigreturn`. There is no x0 retval to write;
        // the restored x0 IS the value the guest sees.
        Ok(DispatchOutcome::SigReturn)
    }

    fn uname<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let address = ctx.request.arg(0);
        if memory
            .write_bytes(address, LinuxUtsname::carrick_aarch64().abi_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn gettimeofday<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let timeval = ctx.request.arg(0);
        let timezone = ctx.request.arg(1);
        let now = realtime_duration();
        if timeval != 0 {
            let timeval = linux_timeval_from_duration(now);
            if memory
                .write_bytes(ctx.request.arg(0), timeval.as_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        if timezone != 0
            && memory
                .write_bytes(timezone, LinuxTimezone::utc().abi_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn getpid(&self) -> DispatchOutcome {
        DispatchOutcome::Returned {
            value: std::process::id() as i64,
        }
    }

    fn ptrace<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Bootstrap: no debugger surface yet. Linux returns ENOSYS when ptrace
        // is built out of the kernel; we surface the same answer so glibc /
        // gdb fall back cleanly.
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    fn reboot<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // We're not root and we wouldn't honour the request anyway.
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    fn sethostname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    fn setdomainname<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    fn settimeofday<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Errno { errno: LINUX_EPERM })
    }

    fn umask<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let new = ctx.arg(0) as u32 & 0o777;
        let previous = self.umask;
        self.umask = new;
        Ok(DispatchOutcome::Returned {
            value: previous as i64,
        })
    }

    fn setpriority<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let who = ctx.arg(1) as i32;
        let prio = ctx.arg(2) as i32;
        if which > LINUX_PRIO_USER || prio < -20 || prio > 19 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn getpriority<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let which = ctx.arg(0);
        let who = ctx.arg(1) as i32;
        if which > LINUX_PRIO_USER {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if which == LINUX_PRIO_PROCESS && who != 0 && who != LINUX_BOOTSTRAP_PID as i32 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        // Linux returns 20 - nice. Default nice is 0 → return 20. This is a
        // bootstrap value; we don't model per-process priority.
        Ok(DispatchOutcome::Returned { value: 20 })
    }

    fn sysinfo<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
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
        if write_kernel_struct_raw(memory, ctx.request.arg(0), &info).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn times<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let buf = ctx.request.arg(0);
        let secs = realtime_duration().as_secs();
        let clock = i64::try_from(secs)
            .ok()
            .and_then(|s| s.checked_mul(LINUX_CLK_TCK))
            .unwrap_or(i64::MAX);
        if buf != 0
            && memory
                .write_bytes(buf, LinuxTms::zeroed().abi_bytes())
                .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: clock })
    }

    fn getrusage<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let who = ctx.request.arg(0) as i32;
        let usage = ctx.request.arg(1);
        match who {
            LINUX_RUSAGE_SELF | LINUX_RUSAGE_CHILDREN | LINUX_RUSAGE_THREAD => {}
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if usage == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        if memory
            .write_bytes(usage, LinuxRusage::zeroed().abi_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn setpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let pgid = i32::from_ne_bytes((ctx.arg(1) as u32).to_ne_bytes());
        if pgid < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `setresuid(ruid, euid, suid)`. -1 means "don't change". We record
    /// the new values; the guest gets to see them via getuid/geteuid/
    /// getresuid. Always succeeds — we're single-identity and tools
    /// can pretend to drop privileges as they like.
    fn setresuid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let s = ctx.arg(2);
        if r as i64 != -1 { self.cred_ruid = r as u32; }
        if e as i64 != -1 { self.cred_euid = e as u32; }
        if s as i64 != -1 { self.cred_suid = s as u32; }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn setresgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        let s = ctx.arg(2);
        if r as i64 != -1 { self.cred_rgid = r as u32; }
        if e as i64 != -1 { self.cred_egid = e as u32; }
        if s as i64 != -1 { self.cred_sgid = s as u32; }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `setreuid(ruid, euid)`: same as setresuid with suid=-1.
    fn setreuid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        if r as i64 != -1 {
            self.cred_ruid = r as u32;
        }
        if e as i64 != -1 {
            self.cred_euid = e as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn setregid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let r = ctx.arg(0);
        let e = ctx.arg(1);
        if r as i64 != -1 {
            self.cred_rgid = r as u32;
        }
        if e as i64 != -1 {
            self.cred_egid = e as u32;
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `setuid(uid)`: set effective uid and (if currently privileged)
    /// real + saved too. We always treat the caller as privileged so
    /// all three move together — matches what apt expects.
    fn setuid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let u = ctx.arg(0) as u32;
        self.cred_ruid = u;
        self.cred_euid = u;
        self.cred_suid = u;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn setgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let g = ctx.arg(0) as u32;
        self.cred_rgid = g;
        self.cred_egid = g;
        self.cred_sgid = g;
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `getresuid(*ruid, *euid, *suid)` — write our tracked tuple.
    fn getresuid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        for (i, value) in [self.cred_ruid, self.cred_euid, self.cred_suid]
            .iter()
            .enumerate()
        {
            let ptr = ctx.arg(i);
            if ptr == 0 {
                continue;
            }
            if ctx.memory.write_bytes(ptr, &value.to_le_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn getresgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        for (i, value) in [self.cred_rgid, self.cred_egid, self.cred_sgid]
            .iter()
            .enumerate()
        {
            let ptr = ctx.arg(i);
            if ptr == 0 {
                continue;
            }
            if ctx.memory.write_bytes(ptr, &value.to_le_bytes()).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// `getgroups(size, *list)`. Linux returns the number of
    /// supplementary groups; the carrick guest runs as root (uid/gid 0)
    /// and belongs to the single supplementary group gid 0, matching a
    /// fresh root shell in the container. With `size == 0` we report the
    /// count (1) without touching `list`; otherwise we write the one
    /// gid_t to the guest buffer and return the number written.
    fn getgroups<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // `size` is a Linux `int`; a negative value is invalid.
        let size = ctx.arg(0) as i32;
        if size < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Query mode: report the count without writing.
        if size == 0 {
            return Ok(DispatchOutcome::Returned { value: 1 });
        }
        // The buffer is too small to hold the supplementary group list.
        if size < 1 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        // Write the single supplementary group (gid 0) as a little-endian
        // gid_t (u32, 4 bytes).
        let list = ctx.arg(1);
        let gid: u32 = 0;
        if ctx.memory.write_bytes(list, &gid.to_le_bytes()).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    fn getpgid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    fn getsid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        if pid != 0 && pid != 1 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_ESRCH });
        }
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    fn setsid<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 1 })
    }

    fn waitid<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let idtype = ctx.arg(0);
        let options = ctx.arg(3);
        match idtype {
            LINUX_P_ALL | LINUX_P_PID | LINUX_P_PGID | LINUX_P_PIDFD => {}
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        }
        if options & !LINUX_WAITID_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if options & LINUX_WAITID_STATE_MASK == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ECHILD,
        })
    }

    fn wait4<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pid = ctx.arg(0) as i32;
        let wstatus_addr = ctx.arg(1);
        let options = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if options & !LINUX_WAIT4_SUPPORTED_FLAGS != 0 {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        }
        // Linux WNOHANG = 1; macOS WNOHANG = 1. Same bit, pass through.
        let mut host_status: i32 = 0;
        let result = unsafe { libc::waitpid(pid, &mut host_status, options as i32) };
        if result < 0 {
            // ECHILD on macOS == ECHILD on Linux (10).
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if result == 0 {
            // WNOHANG and no child ready.
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Linux and Darwin agree on the wstatus encoding for exited /
        // signaled children: low 7 bits = signal, bit 7 = core flag,
        // bits 8..15 = exit code. Pass through as-is.
        if wstatus_addr != 0 {
            let bytes = host_status.to_ne_bytes();
            if memory.write_bytes(wstatus_addr, &bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: i64::from(result) })
    }

    fn openat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        self.open_at_path(dirfd, pathname, flags, &*ctx.memory, ctx.reporter)
    }

    fn openat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let how_address = ctx.arg(2);
        let size = ctx.arg(3);
        let arg0 = ctx.arg(0);
        let arg1 = ctx.arg(1);
        if size != LINUX_OPEN_HOW_SIZE {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let how = match read_open_how(&*ctx.memory, how_address) {
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
        self.open_at_path(arg0, arg1, how.flags, &*ctx.memory, ctx.reporter)
    }

    fn open_at_path(
        &mut self,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        memory: &impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let access = flags & LINUX_O_ACCMODE;
        if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let writable_request = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        let want_create = flags & LINUX_O_CREAT != 0;
        let want_excl = flags & LINUX_O_EXCL != 0;
        let want_trunc = flags & LINUX_O_TRUNC != 0;

        let path = match read_guest_c_string(memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        // VFS-mount routing. DevVfs serves /dev/*, ProcVfs serves
        // /proc/*, SysVfs serves /sys/*. The dispatcher converts each
        // VfsHandle variant into the matching OpenDescription, then
        // falls back to the legacy synthetic-then-overlay-then-rootfs
        // chain for any path no mount claims (or that the mount
        // returns ENOSYS for).
        let vfs_outcome = self.try_vfs_open(&path, access, flags);
        match vfs_outcome {
            VfsOpenAttempt::Installed(fd) => {
                return Ok(DispatchOutcome::Returned { value: fd as i64 });
            }
            VfsOpenAttempt::Errno(errno) => {
                return Ok(DispatchOutcome::Errno { errno });
            }
            VfsOpenAttempt::FallThrough => {}
        }

        // /proc/* and /sys/* synthetic file opens now flow through
        // ProcVfs / SysVfs (mounted in `SyscallDispatcher::new`). Any
        // unknown /proc or /sys path returns ENOSYS from the mount
        // and falls through to the overlay+rootfs lookup below, which
        // handles directory entries like /proc itself.

        if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
            return Ok(outcome);
        }
        // Layered overlay+rootfs lookup with full openat semantics
        // (O_CREAT/O_EXCL/O_TRUNC, write-promotion of rootfs-only
        // files) lives in RootFsVfs::open_for_dispatch.
        let dispatch_result = self.rootfs_vfs.open_for_dispatch(
            &path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        );
        // USDT probe: every guest path-level open, with the resolved
        // path string and resulting size/errno. Lets dtrace operators
        // see exactly what bytes each forked carrick process is
        // serving for paths like /etc/hosts during the apt-resolver
        // run.
        match &dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File { contents, .. }) => {
                crate::probes::path_open(&path, contents.len() as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { .. }) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Err(errno) => {
                crate::probes::path_open(&path, 0, *errno);
            }
        }
        let description = match dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents,
                offset: 0,
                status_flags: flags & !LINUX_O_CLOEXEC,
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            }) => OpenDescription::HostFile {
                host_fd,
                metadata,
                status_flags: flags & !LINUX_O_CLOEXEC,
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { metadata, entries }) => {
                if writable_request {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EISDIR });
                }
                OpenDescription::Directory {
                    path,
                    metadata,
                    entries,
                    offset: 0,
                    status_flags: flags & !LINUX_O_CLOEXEC,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                // O_CREAT path: validate the parent directory exists,
                // create the empty overlay entry, return a writable
                // File description.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    if !self.path_is_directory(&parent_str) {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_ENOENT });
                    }
                }
                let metadata = RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o644,
                    size: 0,
                };
                // Disk-backed overlay (--fs host): create + open a real
                // host fd so the new file is fork-shareable. Falls back
                // to the in-memory File for MemoryBackend.
                if let Some(host_fd) =
                    self.rootfs_vfs.overlay.open_raw_fd(&path, true, true, want_trunc)
                {
                    OpenDescription::HostFile {
                        host_fd,
                        metadata,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                        writable: true,
                    }
                } else {
                    if self.rootfs_vfs.overlay.create_file(&path).is_err() {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
                    }
                    OpenDescription::File {
                        path,
                        metadata,
                        contents: Vec::new(),
                        offset: 0,
                        status_flags: flags & !LINUX_O_CLOEXEC,
                        writable: writable_request || want_create,
                    }
                }
            }
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
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

    /// Layered "is this a directory?" probe used by mkdirat / openat
    /// (O_CREAT) parent-existence checks. The synthetic /proc and
    /// /sys roots count as directories so that
    /// `mkdir("/proc/.tmp-XYZ")` can be detected as EEXIST rather
    /// than the wrong errno.
    fn path_is_directory(&self, path: &str) -> bool {
        if path == "/" || path.is_empty() {
            return true;
        }
        match self.rootfs_vfs.overlay.lookup(path) {
            Some(OverlayEntry::Dir) => return true,
            Some(OverlayEntry::Deleted) | Some(OverlayEntry::File(_)) => return false,
            None => {}
        }
        if let Some(rootfs) = &self.rootfs_vfs.rootfs {
            if let Ok(metadata) = rootfs.metadata(path) {
                return metadata.kind == RootFsEntryKind::Directory;
            }
        }
        false
    }

    /// Layered metadata probe. Mirrors the rootfs-or-synthetic chain
    /// used by stat / faccessat sites, but consults the overlay first
    /// and respects deletions.
    fn layered_metadata(&self, path: &str) -> Result<RootFsMetadata, i32> {
        use crate::vfs::Vfs as _;
        self.rootfs_vfs
            .lookup(path)
            .map(|md| vfs_md_to_rootfs_md(path, &md))
    }

    fn close<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        Ok(if let Some(open_file) = self.open_files.remove(&fd) {
            close_open_file(&open_file);
            DispatchOutcome::Returned { value: 0 }
        } else if is_stdio_fd(fd) {
            // Guest closing its own stdio at exit: there's nothing for
            // us to do (host fd stays open under stream_stdio so
            // sibling processes keep working), but reporting EBADF
            // here makes glibc print "write error: Bad file descriptor"
            // after the program's real output. Return success.
            DispatchOutcome::Returned { value: 0 }
        } else {
            DispatchOutcome::Errno { errno: LINUX_EBADF }
        })
    }

    /// `close_range(first, last, flags)` — close every fd in `[first, last]`
    /// (inclusive). Used by glibc's posix_spawn / apt's pre-fork cleanup
    /// to drop inherited fds in O(1) syscalls instead of an O(N) fcntl
    /// or close loop. Without this, apt walks fd 3..NR_OPEN issuing a
    /// fcntl per fd and burns 100k+ traps before exec.
    fn close_range<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let first = ctx.arg(0);
        let last = ctx.arg(1);
        let flags = ctx.arg(2);
        // CLOSE_RANGE_UNSHARE=2 is a no-op for us (single fd table);
        // CLOSE_RANGE_CLOEXEC=4 would mark fds CLOEXEC instead of
        // closing — accept the bit and apply CLOEXEC.
        const CLOSE_RANGE_UNSHARE: u64 = 2;
        const CLOSE_RANGE_CLOEXEC: u64 = 4;
        if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        }
        let cloexec_only = flags & CLOSE_RANGE_CLOEXEC != 0;
        // Drain matching fds out of the table so we don't iterate a
        // gigantic [first, last] (callers commonly pass last=u32::MAX).
        let fds: Vec<i32> = self
            .open_files
            .keys()
            .copied()
            .filter(|fd| (*fd as u64) >= first && (*fd as u64) <= last)
            .collect();
        for fd in fds {
            if cloexec_only {
                if let Some(open_file) = self.open_files.get_mut(&fd) {
                    open_file.fd_flags |= LINUX_FD_CLOEXEC;
                }
            } else if let Some(open_file) = self.open_files.remove(&fd) {
                close_open_file(&open_file);
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    // ------------------------------------------------------------------
    // BSD sockets.
    //
    // The host kernel does the heavy lifting: we allocate a real macOS
    // socket via `libc::socket(2)` and stash the host fd inside
    // `OpenDescription::HostSocket`. Subsequent socket syscalls translate
    // their Linux-flavoured arguments (sockaddr layouts, flag bits) into
    // BSD shape, dispatch to libc, and translate replies back. Files
    // mostly stay 1:1 — Linux and macOS BSD socket constants align for
    // AF_INET, AF_INET6, AF_UNIX and the common SOCK_* / MSG_* values.
    // The notable mismatches are:
    //   - SOCK_NONBLOCK / SOCK_CLOEXEC bits in `type`         (Linux-only)
    //   - sockaddr_in / sockaddr_un layout (BSD has sin_len)  (BSD-only)
    //   - many Linux-specific `SOL_*` levels                  (we ENOPROTOOPT)
    // ------------------------------------------------------------------

    fn socket<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let family = ctx.arg(0) as i32;
        let type_ = ctx.arg(1) as i32;
        let protocol = ctx.arg(2) as i32;
        Ok(self.host_socket_install(family, type_, protocol))
    }

    fn host_socket_install(
        &mut self,
        family: i32,
        type_: i32,
        protocol: i32,
    ) -> DispatchOutcome {
        // Strip the Linux-only SOCK_NONBLOCK / SOCK_CLOEXEC bits before
        // we hand the type to macOS, then set them on the resulting fd
        // by hand.
        let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
        let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
        let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
        let host_family = linux_to_host_af(family);
        let host_type = linux_to_host_socktype(base_type);
        let host_fd = unsafe { libc::socket(host_family, host_type, protocol) };
        if host_fd < 0 {
            return DispatchOutcome::Errno { errno: host_errno() };
        }
        if nonblock {
            unsafe {
                let flags = libc::fcntl(host_fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(host_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(linux_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(host_fd); }
            return DispatchOutcome::Errno { errno: LINUX_EINVAL };
        };
        self.insert_open_file(
            linux_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: linux_fd as i64 }
    }

    fn socketpair<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let family = ctx.request.arg(0) as i32;
        let type_ = ctx.request.arg(1) as i32;
        let protocol = ctx.request.arg(2) as i32;
        let sv_addr = ctx.request.arg(3);
        let nonblock = type_ & LINUX_SOCK_NONBLOCK != 0;
        let cloexec = type_ & LINUX_SOCK_CLOEXEC != 0;
        let base_type = type_ & !(LINUX_SOCK_NONBLOCK | LINUX_SOCK_CLOEXEC);
        let host_family = linux_to_host_af(family);
        let host_type = linux_to_host_socktype(base_type);

        let mut host_fds: [i32; 2] = [-1, -1];
        let rc = unsafe {
            libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr())
        };
        if rc != 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if nonblock {
            for fd in &host_fds {
                unsafe {
                    let flags = libc::fcntl(*fd, libc::F_GETFL);
                    if flags >= 0 {
                        libc::fcntl(*fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                    }
                }
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(read_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        };
        let Some(write_fd) = self.allocate_fd(read_fd.saturating_add(1)) else {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL });
        };
        let pair = LinuxFdPair { read_fd, write_fd };
        if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
            unsafe { libc::close(host_fds[0]); libc::close(host_fds[1]); }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        self.insert_open_file(
            read_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: host_fds[0],
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        self.insert_open_file(
            write_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: host_fds[1],
                    family,
                    type_: base_type,
                    status_flags,
                })),
                fd_flags,
            },
        );
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    /// Pull a (host_fd, family) pair out of the dispatcher's fd table.
    fn host_socket_lookup(&self, fd: i32) -> Result<(i32, i32), i32> {
        let Some(open_file) = self.open_files.get(&fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.borrow();
        match &*open {
            OpenDescription::HostSocket { host_fd, family, .. } => Ok((*host_fd, *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    fn bind<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen = ctx.request.arg(2) as u32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe {
            libc::bind(host_fd, host_addr.as_ptr() as *const _, host_addr.len() as u32)
        };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    fn listen<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let backlog = ctx.arg(1) as i32;
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe { libc::listen(host_fd, backlog) };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    fn accept<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request = ctx.request;
        Ok(self.accept_common(request, &mut *ctx.memory, 0))
    }

    fn accept4<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(3) as i32;
        let request = ctx.request;
        Ok(self.accept_common(request, &mut *ctx.memory, flags))
    }

    fn accept_common(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let addr_addr = request.arg(1);
        let addrlen_addr = request.arg(2);
        let (host_fd, family, type_) = {
            let Some(open_file) = self.open_files.get(&fd) else {
                return DispatchOutcome::Errno { errno: LINUX_EBADF };
            };
            match &*open_file.description.borrow() {
                OpenDescription::HostSocket { host_fd, family, type_, .. } => {
                    (*host_fd, *family, *type_)
                }
                _ => return DispatchOutcome::Errno { errno: LINUX_ENOTSOCK },
            }
        };
        let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
        let new_host = unsafe {
            libc::accept(
                host_fd,
                sa_storage.as_mut_ptr() as *mut _,
                &mut sa_len as *mut _,
            )
        };
        if new_host < 0 {
            return DispatchOutcome::Errno { errno: host_errno() };
        }
        let nonblock = accept4_flags & LINUX_SOCK_NONBLOCK as i32 != 0;
        let cloexec = accept4_flags & LINUX_SOCK_CLOEXEC as i32 != 0;
        if nonblock {
            unsafe {
                let flags = libc::fcntl(new_host, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(new_host, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        if addr_addr != 0 && addrlen_addr != 0 {
            let used = (sa_len as usize).min(sa_storage.len());
            let linux_bytes = host_to_linux_sockaddr(&sa_storage[..used], family);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                unsafe { libc::close(new_host); }
                return DispatchOutcome::Errno { errno: LINUX_EFAULT };
            }
        }
        let status_flags = if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let Some(linux_fd) = self.allocate_fd(3) else {
            unsafe { libc::close(new_host); }
            return DispatchOutcome::Errno { errno: LINUX_EINVAL };
        };
        self.insert_open_file(
            linux_fd,
            OpenFile {
                description: Rc::new(RefCell::new(OpenDescription::HostSocket {
                    host_fd: new_host,
                    family,
                    type_,
                    status_flags,
                })),
                fd_flags,
            },
        );
        DispatchOutcome::Returned { value: linux_fd as i64 }
    }

    fn connect<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen = ctx.request.arg(2) as u32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe {
            libc::connect(host_fd, host_addr.as_ptr() as *const _, host_addr.len() as u32)
        };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    fn getsockname<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen_addr = ctx.request.arg(2);
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockname(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _)
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (sa_len as usize).min(sa.len());
        let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn getpeername<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let addr_addr = ctx.request.arg(1);
        let addrlen_addr = ctx.request.arg(2);
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getpeername(host_fd, sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _)
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (sa_len as usize).min(sa.len());
        let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn sendto<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let buf_addr = ctx.request.arg(1);
        let len = ctx.request.arg(2) as usize;
        let flags = ctx.request.arg(3) as i32;
        let dest_addr = ctx.request.arg(4);
        let dest_len = ctx.request.arg(5) as u32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match memory.read_bytes(buf_addr, len) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        let host_flags = linux_to_host_msg_flags(flags);
        let n = if dest_addr == 0 {
            unsafe {
                libc::sendto(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    host_flags,
                    std::ptr::null(),
                    0,
                )
            }
        } else {
            let host_addr = match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                Ok(b) => b,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            unsafe {
                libc::sendto(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    host_flags,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            }
        };
        Ok(if n < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: n as i64 }
        })
    }

    fn recvfrom<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let buf_addr = ctx.request.arg(1);
        let len = ctx.request.arg(2) as usize;
        let flags = ctx.request.arg(3) as i32;
        let src_addr = ctx.request.arg(4);
        let src_len_addr = ctx.request.arg(5);
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let host_flags = linux_to_host_msg_flags(flags);
        let mut buf = vec![0u8; len];
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let (n, used_addr) = if src_addr == 0 {
            let n = unsafe {
                libc::recvfrom(
                    host_fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    host_flags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            (n, false)
        } else {
            let n = unsafe {
                libc::recvfrom(
                    host_fd,
                    buf.as_mut_ptr() as *mut _,
                    buf.len(),
                    host_flags,
                    sa.as_mut_ptr() as *mut _,
                    &mut sa_len as *mut _,
                )
            };
            (n, true)
        };
        if n < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        if n > 0 {
            let bytes = &buf[..n as usize];
            if memory.write_bytes(buf_addr, bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if used_addr && src_addr != 0 && src_len_addr != 0 {
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
            if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        Ok(DispatchOutcome::Returned { value: n as i64 })
    }

    fn setsockopt<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let level = ctx.request.arg(1) as i32;
        let optname = ctx.request.arg(2) as i32;
        let optval_addr = ctx.request.arg(3);
        let optlen = ctx.request.arg(4) as u32;
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
            Some(t) => t,
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_ENOPROTOOPT }),
        };
        let bytes = if optval_addr == 0 || optlen == 0 {
            Vec::new()
        } else {
            match memory.read_bytes(optval_addr, optlen as usize) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            }
        };
        let rc = unsafe {
            libc::setsockopt(
                host_fd,
                host_level,
                host_opt,
                if bytes.is_empty() {
                    std::ptr::null()
                } else {
                    bytes.as_ptr() as *const _
                },
                bytes.len() as u32,
            )
        };
        Ok(if rc < 0 {
            // Linux apps frequently set options that aren't supported on
            // macOS (eg IP_MTU_DISCOVER); swallow ENOPROTOOPT silently
            // when the equivalent option simply doesn't exist on macOS.
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    fn getsockopt<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let level = ctx.request.arg(1) as i32;
        let optname = ctx.request.arg(2) as i32;
        let optval_addr = ctx.request.arg(3);
        let optlen_addr = ctx.request.arg(4);
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
            Some(t) => t,
            None => return Ok(DispatchOutcome::Errno { errno: LINUX_ENOPROTOOPT }),
        };
        // Read the guest's reported optlen so we don't overflow.
        let optlen_bytes = match memory.read_bytes(optlen_addr, 4) {
            Ok(b) => b,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        let mut optlen = u32::from_ne_bytes([
            optlen_bytes[0], optlen_bytes[1], optlen_bytes[2], optlen_bytes[3],
        ]);
        let cap = optlen.min(256) as usize;
        let mut buf = vec![0u8; cap];
        let rc = unsafe {
            libc::getsockopt(
                host_fd,
                host_level,
                host_opt,
                buf.as_mut_ptr() as *mut _,
                &mut optlen as *mut _,
            )
        };
        if rc < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        let used = (optlen as usize).min(buf.len());
        if optval_addr != 0 && used > 0 {
            if memory.write_bytes(optval_addr, &buf[..used]).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        if memory.write_bytes(optlen_addr, &optlen.to_ne_bytes()).is_err() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn shutdown<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let how = ctx.arg(1) as i32;
        let (host_fd, _family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let rc = unsafe { libc::shutdown(host_fd, how) };
        Ok(if rc < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: 0 }
        })
    }

    fn sendmsg<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &*ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let msg_addr = ctx.request.arg(1);
        let flags = ctx.request.arg(3) as i32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Pack iovecs into a single contiguous send. Simple and avoids
        // having to keep guest pointers alive across the FFI call.
        let mut data = Vec::new();
        for iov in iovecs {
            let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                Ok(b) => b,
                Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
            };
            data.extend_from_slice(&chunk);
        }
        let host_flags = linux_to_host_msg_flags(flags);
        let n = if msg.name == 0 || msg.namelen == 0 {
            unsafe {
                libc::sendto(
                    host_fd,
                    data.as_ptr() as *const _,
                    data.len(),
                    host_flags,
                    std::ptr::null(),
                    0,
                )
            }
        } else {
            let host_addr = match read_linux_sockaddr(memory, msg.name, msg.namelen, family) {
                Ok(b) => b,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            unsafe {
                libc::sendto(
                    host_fd,
                    data.as_ptr() as *const _,
                    data.len(),
                    host_flags,
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            }
        };
        Ok(if n < 0 {
            DispatchOutcome::Errno { errno: host_errno() }
        } else {
            DispatchOutcome::Returned { value: n as i64 }
        })
    }

    fn recvmsg<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let fd = ctx.request.arg(0) as i32;
        let msg_addr = ctx.request.arg(1);
        let flags = ctx.request.arg(2) as i32;
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let msg = match read_linux_msghdr(memory, msg_addr) {
            Ok(m) => m,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let iovecs = match read_iovecs(memory, msg.iov, msg.iovlen as usize) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        let mut buf = vec![0u8; total];
        let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
        let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                host_fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                linux_to_host_msg_flags(flags),
                if msg.name == 0 { std::ptr::null_mut() } else { sa.as_mut_ptr() as *mut _ },
                if msg.name == 0 { std::ptr::null_mut() } else { &mut sa_len as *mut _ },
            )
        };
        if n < 0 {
            return Ok(DispatchOutcome::Errno { errno: host_errno() });
        }
        // Scatter the received bytes back into the guest's iovecs.
        let mut remaining = n as usize;
        let mut cursor = 0usize;
        for iov in iovecs {
            if remaining == 0 {
                break;
            }
            let chunk = remaining.min(iov.iov_len as usize);
            if chunk > 0 {
                if memory.write_bytes(iov.iov_base, &buf[cursor..cursor + chunk]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                cursor += chunk;
                remaining -= chunk;
            }
        }
        if msg.name != 0 && msg.namelen != 0 {
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family);
            // Write up to msg.namelen, then update the namelen field
            // inside the msghdr.
            let write_len = (linux_bytes.len() as u32).min(msg.namelen);
            if write_len > 0 {
                if memory.write_bytes(msg.name, &linux_bytes[..write_len as usize]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
            }
            // namelen lives at offset 8 (after the 8-byte name pointer).
            if memory
                .write_bytes(msg_addr + 8, &(linux_bytes.len() as u32).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
        }
        // We don't translate ancillary data; report controllen=0.
        if memory
            .write_bytes(msg_addr + 40, &0u64.to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        // msg_flags lives at offset 48 (just after controllen).
        if memory
            .write_bytes(msg_addr + 48, &0i32.to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }
        Ok(DispatchOutcome::Returned { value: n as i64 })
    }

    /// `sendmmsg(sockfd, msgvec, vlen, flags)` — Linux's batched
    /// sendmsg. glibc's getaddrinfo uses sendmmsg for DNS queries even
    /// when only a single message is sent; without this handler the
    /// guest sees ENOSYS and bails with "Temporary failure resolving".
    /// Implemented as a loop over single sendmsgs, writing each entry's
    /// msg_len field with the bytes-sent on success.
    fn sendmmsg(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let msgvec = request.arg(1);
        let vlen = request.arg(2) as u32;
        let flags = request.arg(3) as i32;
        // mmsghdr = msghdr (56 bytes) + msg_len:u32 (4) + pad (4) = 64.
        const MMSGHDR_SIZE: u64 = 64;
        const MSG_LEN_OFFSET: u64 = 56;
        let mut sent: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
            };
            // Build a synthetic sendmsg request that points at this
            // entry's msg_hdr (which is the first 56 bytes of the
            // mmsghdr). Reusing sendmsg keeps the iovec-pack + sockaddr-
            // translate logic in one place.
            let inner_req = SyscallRequest::new(
                211, // sendmsg
                SyscallArgs([fd as u64, entry, 0, flags as u64, 0, 0]),
            );
            let mut inner_reporter = CompatReporter::default();
            let outcome = {
                let mut inner_ctx = SyscallCtx {
                    request: inner_req,
                    memory: &mut *memory,
                    reporter: &mut inner_reporter,
                };
                match self.sendmsg(&mut inner_ctx) {
                    Ok(o) => o,
                    // sendmsg never produces a DispatchError; surface it
                    // as EFAULT to keep this helper's bare-outcome contract.
                    Err(_) => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::Errno { errno: LINUX_EFAULT };
                    }
                    sent += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if sent > 0 {
                        // At least one message went out — Linux returns
                        // the count of successful sends, and the errno
                        // surfaces on the next call.
                        return DispatchOutcome::Returned { value: sent as i64 };
                    }
                    return DispatchOutcome::Errno { errno };
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: sent as i64 }
    }

    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` — Linux's
    /// batched recvmsg. Same shape as sendmmsg: loop over entries,
    /// call single recvmsg for each, fill msg_len on success.
    /// The timeout argument is best-effort — we fall through to a
    /// single libc::poll up front if it's non-NULL and at least one
    /// message is wanted before blocking.
    fn recvmmsg(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = request.arg(0) as i32;
        let msgvec = request.arg(1);
        let vlen = request.arg(2) as u32;
        let flags = request.arg(3) as i32;
        const MMSGHDR_SIZE: u64 = 64;
        const MSG_LEN_OFFSET: u64 = 56;
        let mut received: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
            };
            // After the first successful recvmsg, switch to non-blocking
            // so we drain whatever else is in the queue without waiting.
            let entry_flags = if received > 0 {
                flags | (libc::MSG_DONTWAIT as i32)
            } else {
                flags
            };
            let inner_req = SyscallRequest::new(
                212, // recvmsg
                SyscallArgs([fd as u64, entry, entry_flags as u64, 0, 0, 0]),
            );
            let mut inner_reporter = CompatReporter::default();
            let outcome = {
                let mut inner_ctx = SyscallCtx {
                    request: inner_req,
                    memory: &mut *memory,
                    reporter: &mut inner_reporter,
                };
                match self.recvmsg(&mut inner_ctx) {
                    Ok(o) => o,
                    // recvmsg never produces a DispatchError; surface it
                    // as EFAULT to keep this helper's bare-outcome contract.
                    Err(_) => return DispatchOutcome::Errno { errno: LINUX_EFAULT },
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::Errno { errno: LINUX_EFAULT };
                    }
                    received += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if received > 0 {
                        return DispatchOutcome::Returned { value: received as i64 };
                    }
                    return DispatchOutcome::Errno { errno };
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: received as i64 }
    }

    fn duplicate_fd(&mut self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        let description = match self.open_files.get(&old_fd) {
            Some(open_file) => Rc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) => {
                // dup/fcntl(F_DUPFD) of the process's bare stdio fds:
                // mirror what dup3 does and grab the host fd into a
                // HostPipe so future reads/writes still hit the right
                // host endpoint (this is what dpkg-query needs at
                // startup to redirect its diagnostic fd, and what most
                // glibc fork+exec helpers expect to succeed).
                let duped = unsafe { libc::dup(old_fd) };
                if duped < 0 {
                    return DispatchOutcome::Errno {
                        errno: host_errno(),
                    };
                }
                Rc::new(RefCell::new(OpenDescription::HostPipe {
                    host_fd: duped,
                    is_read_end: old_fd == 0,
                    status_flags: 0,
                }))
            }
            None => return DispatchOutcome::Errno { errno: LINUX_EBADF },
        };
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

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    fn try_vfs_open(&mut self, path: &str, access: u64, flags: u64) -> VfsOpenAttempt {
        // Build the OpenContext from owned/copy data so the mut
        // borrow of `vfs_mounts` doesn't conflict with reads from
        // sibling fields.
        let exec_path = self.executable_path.clone();
        let addr_regions = self.address_space_regions.clone();
        let brk = self.brk_current;
        let mmap = self.mmap_next;
        let ctx = crate::vfs::OpenContext {
            executable_path: Some(exec_path.as_str()),
            address_space_regions: addr_regions.as_deref(),
            brk_current: brk,
            mmap_next: mmap,
        };
        let vfs_flags = crate::vfs::OpenFlags {
            read: matches!(access, LINUX_O_RDONLY | LINUX_O_RDWR),
            write: matches!(access, LINUX_O_WRONLY | LINUX_O_RDWR),
            nonblock: flags & LINUX_O_NONBLOCK != 0,
            cloexec: flags & LINUX_O_CLOEXEC != 0,
            append: flags & LINUX_O_APPEND != 0,
            trunc: flags & LINUX_O_TRUNC != 0,
            create: flags & LINUX_O_CREAT != 0,
            excl: flags & LINUX_O_EXCL != 0,
            directory: flags & LINUX_O_DIRECTORY != 0,
            nofollow: flags & 0o400000 != 0,
            mode: 0,
        };
        let handle = {
            let Some(mut m) = self.vfs_mounts.resolve_mut(path) else {
                return VfsOpenAttempt::FallThrough;
            };
            match m.vfs.open(&m.full_path, vfs_flags, &ctx) {
                Ok(h) => h,
                Err(errno) if errno == LINUX_ENOSYS => {
                    return VfsOpenAttempt::FallThrough;
                }
                Err(errno) => {
                    return VfsOpenAttempt::Errno(errno);
                }
            }
        };
        match handle {
            crate::vfs::VfsHandle::HostFd {
                host_fd,
                is_read_end,
                status_flags,
            } => {
                let new_fd = match self.allocate_fd(3) {
                    Some(fd) => fd,
                    None => {
                        unsafe { libc::close(host_fd) };
                        return VfsOpenAttempt::Errno(linux_errno::EMFILE);
                    }
                };
                self.insert_open_file(
                    new_fd,
                    OpenFile {
                        description: Rc::new(RefCell::new(OpenDescription::HostPipe {
                            host_fd,
                            is_read_end,
                            status_flags: status_flags as u64,
                        })),
                        fd_flags: linux_fd_flags_from_open_flags(flags),
                    },
                );
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Bytes {
                path,
                contents,
                status_flags,
            } => {
                let new_fd = match self.allocate_fd(3) {
                    Some(fd) => fd,
                    None => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                self.insert_open_file(
                    new_fd,
                    OpenFile {
                        description: Rc::new(RefCell::new(OpenDescription::SyntheticFile {
                            path,
                            contents,
                            offset: 0,
                            status_flags: ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC,
                        })),
                        fd_flags: linux_fd_flags_from_open_flags(flags),
                    },
                );
                VfsOpenAttempt::Installed(new_fd)
            }
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

    fn getdents64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
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

    fn lseek<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let offset = ctx.arg(1) as i64;
        let whence = ctx.arg(2);
        let Some(open_file) = self.open_files.get(&fd) else {
            // lseek on stdio with no OpenDescription is, on Linux, a
            // valid call on an unseekable pipe/tty — kernel returns
            // ESPIPE, not EBADF. Returning EBADF confuses glibc's
            // ftell/fclose path into reporting "write error: Bad
            // file descriptor" after every successful write.
            if is_stdio_fd(fd) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_ESPIPE });
            }
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();

        // HostFile: the kernel owns the offset — delegate straight to
        // libc::lseek on the real fd.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let host_whence = match whence {
                LINUX_SEEK_SET => libc::SEEK_SET,
                LINUX_SEEK_CUR => libc::SEEK_CUR,
                LINUX_SEEK_END => libc::SEEK_END,
                _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
            };
            let r = unsafe { libc::lseek(*host_fd, offset as libc::off_t, host_whence) };
            if r < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            return Ok(DispatchOutcome::Returned { value: r as i64 });
        }

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
            // Linux returns ESPIPE for lseek on a pipe / socket / tty
            // (the kernel's POSIX answer for "unseekable stream") and
            // EINVAL only for nonsensical arg combinations. Returning
            // EINVAL here made dpkg-query's ftell() retry-loop spin
            // forever because POSIX says "EINVAL is recoverable" while
            // ESPIPE means "give up, it's a stream".
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ESPIPE,
                });
            }
            // HostFile is handled by the early libc::lseek above.
            OpenDescription::HostFile { .. } => unreachable!("HostFile lseek handled above"),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. } => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        let next = match whence {
            LINUX_SEEK_SET => offset,
            LINUX_SEEK_CUR => current.saturating_add(offset),
            LINUX_SEEK_END => end.saturating_add(offset),
            _ => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
        };
        if next < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        match &mut *open {
            OpenDescription::File { offset, .. }
            | OpenDescription::Directory { offset, .. }
            | OpenDescription::SyntheticFile { offset, .. } => *offset = next as usize,
            OpenDescription::HostFile { .. } => unreachable!("HostFile lseek handled above"),
            OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => {}
        }
        Ok(DispatchOutcome::Returned { value: next })
    }

    /// Linux `execve(2)` (aarch64 syscall 221). Reads pathname, argv,
    /// and envp from guest memory, then surfaces `DispatchOutcome::Execve`
    /// so the runtime can tear down the guest address space and load
    /// the new image. Returns the usual errno on the failure paths
    /// (EFAULT on bad pointers, ENAMETOOLONG on oversized strings).
    fn execve<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let pathname_addr = ctx.arg(0);
        let argv_addr = ctx.arg(1);
        let envp_addr = ctx.arg(2);
        let memory = &*ctx.memory;

        let path = match read_guest_c_string(memory, pathname_addr) {
            Ok(p) => p,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let argv = match read_guest_string_array(memory, argv_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let env = match read_guest_string_array(memory, envp_addr) {
            Ok(v) => v,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        Ok(DispatchOutcome::Execve { path, argv, env })
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
    fn clone<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;

        let flags = ctx.arg(0);
        // Thread creation needs pthread_create semantics, not fork.
        // Surface as ENOSYS for now so callers see "function not
        // implemented" rather than spuriously cloning the whole address
        // space when they wanted a thread.
        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            });
        }

        // Anything else (including the SIGCHLD-only fork case) → real fork.
        Ok(DispatchOutcome::Fork)
    }

    /// clone3(2): like clone, but flags and the rest of the parameters live in
    /// a `struct clone_args` pointed to by arg0 (arg1 is its size). glibc's
    /// posix_spawn/fork now prefer clone3; without it apt-get's worker spawn
    /// silently failed and the parent deadlocked waiting on a child that never
    /// came up. We only need `flags` (the first u64) to decide thread-vs-fork.
    fn clone3(
        &mut self,
        request: SyscallRequest,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FS: u64 = 0x00000200;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_SIGHAND: u64 = 0x00000800;
        const CLONE_THREAD: u64 = 0x00010000;

        let args_ptr = request.arg(0);
        let args_size = request.arg(1);
        // clone_args is at least flags(8)+pidfd(8)+child_tid(8)+parent_tid(8)
        // +exit_signal(8) = 40 bytes; flags is the first field.
        if args_size < 8 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let flags = match memory.read_bytes(args_ptr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            Err(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        };

        let thread_mask =
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        if (flags & thread_mask) == thread_mask {
            return DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            };
        }

        // posix_spawn's CLONE_VM|CLONE_VFORK|SIGCHLD and plain SIGCHLD forks
        // both land here. A real fork is a valid implementation of vfork (the
        // child execs or _exits immediately), so route to the same path.
        DispatchOutcome::Fork
    }

    /// posix_fadvise(2): purely an advisory hint to the page cache. We have
    /// no readahead model, so honour it as a no-op — but validate the fd so a
    /// genuinely bad descriptor still reports EBADF. dpkg/apt/coreutils call
    /// this routinely; without it the unimplemented-syscall panic killed them.
    fn fadvise64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) && !is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn brk<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        if requested == 0 {
            return Ok(DispatchOutcome::Returned {
                value: self.brk_current as i64,
            });
        }

        if range_within(requested, 0, LINUX_HEAP_BASE, LINUX_HEAP_SIZE) {
            self.brk_current = requested;
        }
        Ok(DispatchOutcome::Returned {
            value: self.brk_current as i64,
        })
    }

    fn mmap<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let requested = ctx.arg(0);
        let length = ctx.arg(1);
        let prot = ctx.arg(2);
        let flags = ctx.arg(3);
        let fd = ctx.arg(4) as i32;
        let offset = ctx.arg(5);
        let memory = &mut *ctx.memory;

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
            let offset_usize =
                usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
            match &*open {
                OpenDescription::File { contents, .. }
                | OpenDescription::SyntheticFile { contents, .. } => {
                    if offset_usize < contents.len() {
                        let available = &contents[offset_usize..];
                        let copy_len = available.len().min(length_usize);
                        bytes[..copy_len].copy_from_slice(&available[..copy_len]);
                    }
                }
                // Real host file: pread the requested region directly.
                // MAP_PRIVATE snapshot semantics — we copy the bytes
                // into the guest mapping (we don't model live
                // MAP_SHARED file mappings).
                OpenDescription::HostFile { host_fd, .. } => {
                    let n = unsafe {
                        libc::pread(
                            *host_fd,
                            bytes.as_mut_ptr() as *mut _,
                            length_usize,
                            offset as libc::off_t,
                        )
                    };
                    // Short/zero reads just leave the tail zero-filled,
                    // matching mmap-past-EOF semantics. Negative = error
                    // but we still return the (zeroed) mapping rather
                    // than fail, mirroring the File path's leniency.
                    let _ = n;
                }
                OpenDescription::Directory { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. } => {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                }
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

    fn munmap<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        if length == 0 || !range_within(address, length, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn msync<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let flags = ctx.arg(2);
        let memory = &*ctx.memory;
        if flags & !(LINUX_MS_ASYNC | LINUX_MS_INVALIDATE | LINUX_MS_SYNC) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & LINUX_MS_ASYNC != 0 && flags & LINUX_MS_SYNC != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if memory.read_bytes(address, 1).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn mlock<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let memory = &*ctx.memory;
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if memory.read_bytes(address, 1).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn munlock<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.mlock(ctx)
    }

    fn mlockall<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let flags = ctx.arg(0);
        if flags == 0
            || flags & !(LINUX_MCL_CURRENT | LINUX_MCL_FUTURE | LINUX_MCL_ONFAULT) != 0
        {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn munlockall<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn mincore<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let vec = ctx.arg(2);
        let memory = &mut *ctx.memory;
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if memory.read_bytes(address, 1).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        let pages = (length + LINUX_PAGE_SIZE as u64 - 1) / LINUX_PAGE_SIZE as u64;
        let bytes = vec![1u8; pages as usize];
        if memory.write_bytes(vec, &bytes).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn mremap<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let memory = &mut *ctx.memory;
        let old_address = ctx.request.arg(0);
        let old_size = ctx.request.arg(1);
        let new_size_req = ctx.request.arg(2);
        let flags = ctx.request.arg(3);
        if new_size_req == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if flags & !(LINUX_MREMAP_MAYMOVE | LINUX_MREMAP_FIXED | LINUX_MREMAP_DONTUNMAP) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if !range_within(old_address, old_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let Some(new_size) = align_up_u64(new_size_req, LINUX_PAGE_SIZE) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        if new_size <= old_size {
            return Ok(DispatchOutcome::Returned {
                value: old_address as i64,
            });
        }

        // Grow in place when this mapping sits at the top of the bump
        // allocator: the tail bytes are fresh guest memory already backed by
        // the stage-2 mapping, so no copy is needed.
        if old_address.checked_add(old_size) == Some(self.mmap_next) {
            let Some(new_end) = old_address.checked_add(new_size) else {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            };
            if range_within(old_address, new_size, LINUX_MMAP_BASE, LINUX_MMAP_SIZE) {
                self.mmap_next = new_end;
                return Ok(DispatchOutcome::Returned {
                    value: old_address as i64,
                });
            }
        }

        // Otherwise the mapping can only grow by moving. Linux requires
        // MREMAP_MAYMOVE for that; without it the call fails.
        if flags & LINUX_MREMAP_MAYMOVE == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        let Some(new_address) = self.next_mmap_address(0, new_size, 0) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        let copy_len = match usize::try_from(old_size) {
            Ok(len) => len,
            Err(_) => {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_ENOMEM,
                });
            }
        };
        if copy_len > 0 {
            match memory.read_bytes(old_address, copy_len) {
                Ok(bytes) => {
                    let _ = memory.write_bytes(new_address, &bytes);
                }
                Err(_) => {
                    return Ok(DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    });
                }
            }
        }
        Ok(DispatchOutcome::Returned {
            value: new_address as i64,
        })
    }

    fn mprotect<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let prot = ctx.arg(2);
        if prot & !(LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        // Page-alignment check on the address — Linux requires that. Our
        // stage-2 mappings are already r-w-x for the bootstrap, so changing
        // protections is a no-op for the guest. Don't validate the range
        // against the dispatcher's address space: musl's RELRO loop hands us
        // addresses inside the dynamically-allocated mmap arenas that we
        // don't currently model, and gating those calls produces an
        // ENOMEM-retry loop that prevents dynamic startup from finishing.
        if address % LINUX_PAGE_SIZE as u64 != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn madvise<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = ctx.arg(1);
        let advice = ctx.arg(2);
        let memory = &*ctx.memory;

        if address % LINUX_PAGE_SIZE != 0 || !linux_madvise_advice_is_supported(advice) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if length == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let Ok(length) = usize::try_from(length) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        let Some(last_address) = address.checked_add(length as u64 - 1) else {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        };
        if memory.read_bytes(address, 1).is_err() || memory.read_bytes(last_address, 1).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOMEM,
            });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn prlimit64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let resource = ctx.arg(1);
        let new_limit = ctx.arg(2);
        let old_limit = ctx.arg(3);
        let memory = &mut *ctx.memory;
        if new_limit != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        if old_limit != 0 {
            // Per-resource values matched to a sensible Linux default.
            // Returning RLIM_INFINITY for ALL resources crashes apt:
            // its pre-fork "set CLOEXEC on every fd" loop iterates
            // 3..rlim_cur and so spins for u64::MAX cycles. RLIMIT_NOFILE
            // in particular needs a real bound.
            // Resource numbers from include/uapi/asm-generic/resource.h.
            const LINUX_RLIMIT_NOFILE: u64 = 7;
            const LINUX_RLIMIT_NPROC: u64 = 6;
            const LINUX_RLIMIT_STACK: u64 = 3;
            const LINUX_RLIMIT_AS: u64 = 9;
            const LINUX_RLIMIT_DATA: u64 = 2;
            let limit = match resource {
                LINUX_RLIMIT_NOFILE => LinuxRlimit::new(1024, 1024 * 1024),
                LINUX_RLIMIT_NPROC => LinuxRlimit::new(8192, 8192),
                LINUX_RLIMIT_STACK => LinuxRlimit::new(
                    crate::memory::LINUX_STACK_SIZE,
                    LINUX_RLIM_INFINITY,
                ),
                LINUX_RLIMIT_AS | LINUX_RLIMIT_DATA => {
                    LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
                }
                _ => LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY),
            };
            if write_kernel_struct_raw(memory, old_limit, &limit).is_err() {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                });
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn getrandom<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let address = ctx.arg(0);
        let length = usize::try_from(ctx.arg(1))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(1)))?;
        let memory = &mut *ctx.memory;
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

    fn read<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        // fd 0 with no explicit OpenDescription: read from host stdin.
        // This is what makes `read` against the guest's stdin pick up
        // input from the user's terminal (or whatever the carrick host
        // process's stdin is — file, pipe, or terminal).
        if fd == 0 && !self.open_files.contains_key(&0) {
            return Ok(read_host_pipe(memory, address, length, 0));
        }
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
            OpenDescription::HostSocket { host_fd, .. } => {
                return Ok(read_host_pipe(memory, address, length, *host_fd));
            }
            // Real host file: libc::read advances the kernel offset
            // (shared across fork). read_host_pipe is just a
            // memory-into-guest read(2) wrapper.
            OpenDescription::HostFile { host_fd, .. } => {
                return Ok(read_host_pipe(memory, address, length, *host_fd));
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

    fn readv<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &mut *ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let mut open = open_file.description.borrow_mut();
        // Real host file: readv via the kernel fd (advances the shared
        // offset). Fill each iovec sequentially.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let hfd = *host_fd;
            let mut total = 0i64;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                match read_host_pipe(memory, iov.iov_base, len, hfd) {
                    DispatchOutcome::Returned { value } => {
                        total += value;
                        if (value as usize) < len {
                            break;
                        }
                    }
                    other => return Ok(other),
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let (contents, offset) = match &mut *open {
            OpenDescription::File {
                contents, offset, ..
            }
            | OpenDescription::SyntheticFile {
                contents, offset, ..
            } => (contents, offset),
            OpenDescription::HostFile { .. } => unreachable!("HostFile readv handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => {
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

    fn pread64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let buffer = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional read via libc::pread (doesn't
        // disturb the shared kernel offset).
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let mut buf = vec![0u8; length];
            let n = unsafe {
                libc::pread(*host_fd, buf.as_mut_ptr() as *mut _, length, offset as libc::off_t)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            let n = n as usize;
            if n > 0 && memory.write_bytes(buffer, &buf[..n]).is_err() {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile pread handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => {
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

    fn preadv<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
        let iovecs = match read_iovecs(memory, iov, iovcnt) {
            Ok(iovecs) => iovecs,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional readv via libc::pread per iovec
        // (kernel offset untouched).
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let hfd = *host_fd;
            let mut total = 0i64;
            let mut cur = offset;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                let mut buf = vec![0u8; len];
                let n = unsafe {
                    libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, cur as libc::off_t)
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno { errno: host_errno() });
                }
                let n = n as usize;
                if n > 0 && memory.write_bytes(iov.iov_base, &buf[..n]).is_err() {
                    return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
                }
                total += n as i64;
                cur += n;
                if n < len {
                    break;
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile preadv handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => {
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

    fn pwrite64<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        if offset < 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let bytes = match (&*ctx.memory).read_bytes(address, length) {
            Ok(b) => b,
            Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
        };
        if is_stdio_fd(fd) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ESPIPE,
            });
        }
        let Some(open_file) = self.open_files.get(&fd) else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        };
        let open = open_file.description.borrow();
        // Real host file: positional write via libc::pwrite (visible
        // across fork; kernel offset untouched).
        if let OpenDescription::HostFile { host_fd, writable, .. } = &*open {
            if !*writable {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let n = unsafe {
                libc::pwrite(*host_fd, bytes.as_ptr() as *const _, length, offset as libc::off_t)
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::HostFile { .. } => unreachable!("handled above"),
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn pwritev<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let offset = i64::from_ne_bytes(ctx.arg(3).to_ne_bytes());
        let memory = &*ctx.memory;
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
        // Real host file: positional writev via libc::pwrite per iovec.
        if let OpenDescription::HostFile { host_fd, writable, .. } = &*open {
            if !*writable {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            let hfd = *host_fd;
            let mut total = 0i64;
            let mut cur = offset;
            for iov in &iovecs {
                let len = usize::try_from(iov.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                if len == 0 {
                    continue;
                }
                let buf = match memory.read_bytes(iov.iov_base, len) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT }),
                };
                let n = unsafe {
                    libc::pwrite(hfd, buf.as_ptr() as *const _, len, cur as libc::off_t)
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno { errno: host_errno() });
                }
                total += n as i64;
                cur += n as i64;
                if (n as usize) < len {
                    break;
                }
            }
            return Ok(DispatchOutcome::Returned { value: total });
        }
        let errno = match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
            OpenDescription::HostFile { .. } => unreachable!("handled above"),
            OpenDescription::Directory { .. } => LINUX_EISDIR,
            OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. }
            | OpenDescription::Epoll { .. } => LINUX_ESPIPE,
        };
        Ok(DispatchOutcome::Errno { errno })
    }

    fn sendfile<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let out_fd = ctx.arg(0) as i32;
        let in_fd = ctx.arg(1) as i32;
        let offset_address = ctx.arg(2);
        let count = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        let memory = &mut *ctx.memory;
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

    /// copy_file_range(2): like sendfile but file-to-file with independent
    /// in/out offset pointers. coreutils `cat`/`cp` and apt/dpkg use it for
    /// efficient copies; it was unimplemented and the panic-on-unknown guard
    /// turned that into a hard abort. We read from in_fd at its (pointer or
    /// current) offset and write to out_fd, reusing the sendfile machinery.
    fn copy_file_range<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_fd = ctx.arg(0) as i32;
        let off_in_addr = ctx.arg(1);
        let out_fd = ctx.arg(2) as i32;
        let off_out_addr = ctx.arg(3);
        // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
        // so cap each call to a bounded chunk rather than trying to allocate
        // a multi-exabyte buffer. A short return is legal for copy_file_range.
        let requested = usize::try_from(ctx.arg(4)).unwrap_or(usize::MAX);
        let memory = &mut *ctx.memory;
        let count = requested.min(8 * 1024 * 1024);
        if count == 0 {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        let in_offset = match self.sendfile_offset(in_fd, off_in_addr, memory)? {
            Ok(o) => o,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let bytes = match self.sendfile_bytes(in_fd, in_offset, count) {
            Ok(b) => b,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if bytes.is_empty() {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }

        // Write side. off_out == NULL → write at out_fd's current position
        // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
        // given offset on a real host fd and advance *off_out.
        let written = if off_out_addr == 0 {
            let outcome = self.write_output_fd(out_fd, &bytes);
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            usize::try_from(value).unwrap_or(0)
        } else {
            let out_off = match read_u64(memory, off_out_addr) {
                Ok(v) => v,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let host_fd = match self.open_files.get(&out_fd) {
                Some(of) => match &*of.description.borrow() {
                    OpenDescription::HostFile { host_fd, writable: true, .. } => *host_fd,
                    OpenDescription::HostFile { .. } => {
                        return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF })
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EINVAL }),
                },
                None => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
            };
            let n = unsafe {
                libc::pwrite(
                    host_fd,
                    bytes.as_ptr() as *const _,
                    bytes.len(),
                    out_off as libc::off_t,
                )
            };
            if n < 0 {
                return Ok(DispatchOutcome::Errno { errno: host_errno() });
            }
            let n = n as usize;
            if memory
                .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
            }
            n
        };

        // Advance the input offset (pointer or the fd's own position).
        let new_in = in_offset.saturating_add(written);
        if off_in_addr == 0 {
            if let Some(of) = self.open_files.get(&in_fd) {
                let mut open = of.description.borrow_mut();
                match &mut *open {
                    OpenDescription::File { offset, .. }
                    | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                    OpenDescription::HostFile { host_fd, .. } => {
                        unsafe { libc::lseek(*host_fd, new_in as libc::off_t, libc::SEEK_SET) };
                    }
                    _ => {}
                }
            }
        } else if memory
            .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
            .is_err()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EFAULT });
        }

        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
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
            // HostFile: current offset is the kernel's; query via lseek.
            OpenDescription::HostFile { host_fd, .. } => {
                let cur = unsafe { libc::lseek(*host_fd, 0, libc::SEEK_CUR) };
                if cur < 0 {
                    Ok(Err(host_errno()))
                } else {
                    Ok(Ok(cur as usize))
                }
            }
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => Ok(Err(LINUX_EINVAL)),
        }
    }

    fn sendfile_bytes(&self, in_fd: i32, offset: usize, count: usize) -> Result<Vec<u8>, i32> {
        let Some(in_file) = self.open_files.get(&in_fd) else {
            return Err(LINUX_EBADF);
        };
        let open = in_file.description.borrow();
        // HostFile: pread the requested window from the real fd.
        if let OpenDescription::HostFile { host_fd, .. } = &*open {
            let mut buf = vec![0u8; count];
            let n = unsafe {
                libc::pread(*host_fd, buf.as_mut_ptr() as *mut _, count, offset as libc::off_t)
            };
            if n < 0 {
                return Err(host_errno());
            }
            buf.truncate(n as usize);
            return Ok(buf);
        }
        let contents = match &*open {
            OpenDescription::File { contents, .. }
            | OpenDescription::SyntheticFile { contents, .. } => contents,
            OpenDescription::HostFile { .. } => unreachable!("HostFile sendfile handled above"),
            OpenDescription::Directory { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::Epoll { .. }
            | OpenDescription::PipeReader { .. }
            | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => return Err(LINUX_EINVAL),
        };
        let available = contents.get(offset..).unwrap_or_default();
        let write_len = available.len().min(count);
        Ok(available[..write_len].to_vec())
    }

    fn splice<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_fd = ctx.arg(0) as i32;
        let off_in_address = ctx.arg(1);
        let out_fd = ctx.arg(2) as i32;
        let off_out_address = ctx.arg(3);
        let count = usize::try_from(ctx.arg(4))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(4)))?;
        let flags = ctx.arg(5);
        let memory = &mut *ctx.memory;
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

    fn sync<M: GuestMemory>(
        &mut self,
        _ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
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

    fn fsync<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fdatasync<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn write<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0);
        let address = ctx.arg(1);
        let length = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let bytes = match (&*ctx.memory).read_bytes(address, length) {
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
        if let Some(open_file) = self.open_files.get(&(fd as i32)).cloned() {
            // Take an inner scope so the borrow on the description ends
            // before we touch self.rootfs_vfs.overlay (writable File path below).
            #[allow(dead_code)]
            enum FileWriteback {
                None,
                Update { path: String, contents: Vec<u8> },
            }
            let outcome: DispatchOutcome;
            let writeback: FileWriteback;
            {
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
                    OpenDescription::HostSocket { host_fd, .. } => {
                        // write(2) on a connected socket maps directly to a
                        // host write(2). Unconnected sockets will surface
                        // their own ENOTCONN via the host.
                        return Ok(write_host_pipe(&bytes, *host_fd));
                    }
                    OpenDescription::HostFile {
                        host_fd,
                        writable,
                        status_flags,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        // O_APPEND: seek to EOF before writing so `>>` and
                        // log appends don't overwrite from offset 0. (The
                        // host fd isn't opened O_APPEND, so we emulate the
                        // seek-then-write; single-writer, which covers the
                        // shell/dpkg append cases.)
                        if *status_flags & LINUX_O_APPEND != 0 {
                            unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                        }
                        // libc::write to the real fd: advances the
                        // kernel offset and is visible across fork.
                        return Ok(write_host_pipe(&bytes, *host_fd));
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                        }
                        write_into_file_contents(contents, offset, &bytes);
                        metadata.size = contents.len();
                        outcome = DispatchOutcome::Returned {
                            value: bytes.len() as i64,
                        };
                        writeback = FileWriteback::Update {
                            path: path.clone(),
                            contents: contents.clone(),
                        };
                    }
                    _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                }
            }
            if let FileWriteback::Update { path, contents } = writeback {
                let _ = self.rootfs_vfs.overlay.set_file_contents(&path, contents);
            }
            return Ok(outcome);
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
                OpenDescription::HostSocket { host_fd, .. } => {
                    write_host_pipe(bytes, *host_fd)
                }
                _ => DispatchOutcome::Errno { errno: LINUX_EBADF },
            };
        }
        if self.stream_stdio && (fd == 1 || fd == 2) {
            let n = unsafe {
                libc::write(fd, bytes.as_ptr() as *const _, bytes.len())
            };
            if n < 0 {
                let errno = unsafe { *libc::__error() };
                return DispatchOutcome::Errno {
                    errno: errno as i32,
                };
            }
            return DispatchOutcome::Returned { value: n as i64 };
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

    fn writev<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0);
        let iov = ctx.arg(1);
        let iovcnt = usize::try_from(ctx.arg(2))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(2)))?;
        let memory = &*ctx.memory;
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
            if let Some(open_file) = self.open_files.get(&(fd as i32)).cloned() {
                enum FileWriteback {
                    None,
                    Update { path: String, contents: Vec<u8> },
                }
                let outcome: DispatchOutcome;
                let writeback: FileWriteback;
                {
                    let mut open = open_file.description.borrow_mut();
                    match &mut *open {
                        OpenDescription::PipeWriter { pipe, .. } => {
                            outcome = write_pipe(&bytes, pipe);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostPipe {
                            host_fd,
                            is_read_end,
                            ..
                        } => {
                            if *is_read_end {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostSocket { host_fd, .. } => {
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::HostFile {
                            host_fd,
                            writable,
                            status_flags,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            // Mirror `write`(64): O_APPEND seeks to EOF, then
                            // libc::write to the real fd advances the shared
                            // kernel offset (visible across fork and to the
                            // readv that follows).
                            if *status_flags & LINUX_O_APPEND != 0 {
                                unsafe { libc::lseek(*host_fd, 0, libc::SEEK_END) };
                            }
                            outcome = write_host_pipe(&bytes, *host_fd);
                            writeback = FileWriteback::None;
                        }
                        OpenDescription::File {
                            path,
                            contents,
                            offset,
                            writable,
                            metadata,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
                            }
                            write_into_file_contents(contents, offset, &bytes);
                            metadata.size = contents.len();
                            outcome = DispatchOutcome::Returned {
                                value: bytes.len() as i64,
                            };
                            writeback = FileWriteback::Update {
                                path: path.clone(),
                                contents: contents.clone(),
                            };
                        }
                        _ => return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF }),
                    }
                }
                if let FileWriteback::Update { path, contents } = writeback {
                    let _ = self.rootfs_vfs.overlay.set_file_contents(&path, contents);
                }
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                total = total
                    .checked_add(value as usize)
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                continue;
            }
            if self.stream_stdio && (fd == 1 || fd == 2) {
                let n = unsafe {
                    libc::write(fd as i32, bytes.as_ptr() as *const _, bytes.len())
                };
                if n < 0 {
                    return Ok(DispatchOutcome::Errno {
                        errno: host_errno(),
                    });
                }
                total = total
                    .checked_add(n as usize)
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

    fn readlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let buffer = ctx.arg(2);
        let buffer_size = usize::try_from(ctx.arg(3))
            .map_err(|_| DispatchError::LengthTooLarge(ctx.arg(3)))?;
        if buffer_size == 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }

        let path = match read_guest_c_string(&*ctx.memory, pathname) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let path = match self.resolve_at_path(dirfd, &path) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };

        let target = if path == "/proc/self/exe" || path == "/proc/curproc/exe" {
            self.executable_path.clone()
        } else if let Some(t) = self.rootfs_vfs.overlay.read_link(&path) {
            // Symlink created in the writable backend (cap-std on --fs host).
            t
        } else {
            use crate::vfs::Vfs as _;
            match self.rootfs_vfs.readlink(&path) {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            }
        };

        let bytes = target.as_bytes();
        let written = bytes.len().min(buffer_size);
        if ctx.memory.write_bytes(buffer, &bytes[..written]).is_err() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            });
        }
        Ok(DispatchOutcome::Returned {
            value: written as i64,
        })
    }

    fn mknodat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
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
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // Existence check must consult the layered view (overlay/disk
        // first, then rootfs) — a rootfs-direct lookup would miss a file
        // the guest already created in the overlay and wrongly report
        // EROFS instead of EEXIST. Mirrors the linkat EEXIST check.
        if self.layered_metadata(&resolved).is_ok() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
    }

    fn mkdirat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
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
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // Layered existence + parent-exists checks live inside
        // RootFsVfs::mkdir; the dispatcher only handles synthetic
        // path shadowing.
        use crate::vfs::Vfs as _;
        match self.rootfs_vfs.mkdir(&resolved, 0) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn fchmod<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        // The overlay is a tmpfs that doesn't track owner/mode; accept
        // the call as a no-op so apt's chmod-the-directory-I-just-made
        // helpers don't fail with EROFS.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fchown<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        if !self.fd_is_valid(fd) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
        }
        // See `fchmod` above: tmpfs semantics, no-op success.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn fchownat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
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
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if !self.fd_is_valid(dirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        let resolved = match self.resolve_at_path(dirfd, &path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        // Layered presence check: overlay first (tombstones become ENOENT),
        // synthetic /proc and /sys are no-op success, rootfs is no-op
        // success (tmpfs semantics).
        match self.layered_metadata(&resolved) {
            Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => {
                if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
                    Ok(DispatchOutcome::Returned { value: 0 })
                } else {
                    Ok(DispatchOutcome::Errno { errno })
                }
            }
        }
    }

    fn fchmodat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(3);
        if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
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
        // Apply the mode to the writable backend (cap-std set_permissions on
        // --fs host). Synthetic /proc /sys paths and the in-memory backend
        // (Unsupported) accept it as a no-op as long as the path exists.
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if let Err(errno) = self.layered_metadata(&resolved) {
            return Ok(DispatchOutcome::Errno { errno });
        }
        let mode = (ctx.arg(2) & 0o7777) as u32;
        match self.rootfs_vfs.overlay.set_mode(&resolved, mode) {
            Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
        }
    }

    fn linkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let olddirfd = ctx.arg(0);
        let oldpath = ctx.arg(1);
        let newdirfd = ctx.arg(2);
        let newpath = ctx.arg(3);
        let flags = ctx.arg(4);
        if flags & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let old = match read_guest_c_string(&*ctx.memory, oldpath) {
            Ok(path) => path,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        let new_path = match read_guest_c_string(&*ctx.memory, newpath) {
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
        let resolved_old = if old.is_empty() {
            if !self.fd_is_valid(olddirfd as i32) {
                return Ok(DispatchOutcome::Errno { errno: LINUX_EBADF });
            }
            None
        } else {
            let resolved = match self.resolve_at_path(olddirfd, &old) {
                Ok(resolved) => resolved,
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            };
            let exists = is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context())
                || self.layered_metadata(&resolved).is_ok();
            if !exists {
                return Ok(DispatchOutcome::Errno { errno: LINUX_ENOENT });
            }
            Some(resolved)
        };
        let resolved_new = match self.resolve_at_path(newdirfd, &new_path) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if is_synthetic_virtual_file(&resolved_new, &self.synthetic_proc_context())
            || self.layered_metadata(&resolved_new).is_ok()
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EEXIST });
        }
        // Create a real hard link in the writable backend (cap-std
        // hard_link). dpkg link()s e.g. /var/lib/dpkg/status -> status-old.
        // AT_EMPTY_PATH (link by fd) isn't supported. MemoryBackend can't
        // hard-link an in-memory file, so it falls back to a content copy.
        let Some(src) = resolved_old else {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        };
        match self.rootfs_vfs.overlay.hard_link(&src, &resolved_new) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(crate::fs_backend::BackendError::Unsupported) => {
                // In-memory backend: emulate with a content copy (callers
                // like dpkg only need the data, not shared inodes).
                let contents = self
                    .rootfs_vfs
                    .overlay
                    .file_contents(&src)
                    .or_else(|| self.rootfs_vfs.rootfs.as_ref().and_then(|r| r.read(&src).ok()))
                    .unwrap_or_default();
                match self.rootfs_vfs.overlay.set_file_contents(&resolved_new, contents) {
                    Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
                }
            }
            Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    fn symlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let target = ctx.arg(0);
        let newdirfd = ctx.arg(1);
        let linkpath = ctx.arg(2);
        let target_path = match read_guest_c_string(&*ctx.memory, target) {
            Ok(target) => target,
            Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
        };
        if target_path.is_empty() {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_ENOENT,
            });
        }
        let link = match read_guest_c_string(&*ctx.memory, linkpath) {
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
        if is_synthetic_virtual_file(&resolved_link, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EEXIST,
            });
        }
        // If the link path already exists (anywhere in the layered
        // view), report EEXIST. Otherwise the overlay can't create
        // symlinks today, so we return EROFS.
        if self.layered_metadata(&resolved_link).is_ok() {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EEXIST });
        }
        // Create a real symlink in the writable backend (cap-std). The
        // target is stored verbatim, matching symlinkat(2). MemoryBackend
        // returns Unsupported → EROFS.
        match self.rootfs_vfs.overlay.symlink(&target_path, &resolved_link) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(crate::fs_backend::BackendError::Unsupported) => {
                Ok(DispatchOutcome::Errno { errno: LINUX_EROFS })
            }
            Err(_) => Ok(DispatchOutcome::Errno { errno: LINUX_EROFS }),
        }
    }

    fn renameat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.do_renameat(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            0,
            &*ctx.memory,
        )
    }

    fn renameat2<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // RENAME_NOREPLACE=1, RENAME_EXCHANGE=2, RENAME_WHITEOUT=4. We
        // implement the common subset (no flags or NOREPLACE). EXCHANGE
        // and WHITEOUT are not supported by overlayfs in our limited
        // mode either, so reject them.
        const RENAME_NOREPLACE: u64 = 1;
        const RENAME_EXCHANGE: u64 = 2;
        let flags = ctx.arg(4);
        if flags & !RENAME_NOREPLACE != 0 {
            if flags & RENAME_EXCHANGE != 0 {
                return Ok(DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                });
            }
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        self.do_renameat(
            ctx.arg(0),
            ctx.arg(1),
            ctx.arg(2),
            ctx.arg(3),
            flags,
            &*ctx.memory,
        )
    }

    fn do_renameat(
        &mut self,
        olddirfd: u64,
        oldpath: u64,
        newdirfd: u64,
        newpath: u64,
        flags: u64,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        const RENAME_NOREPLACE: u64 = 1;
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
        if is_synthetic_virtual_file(&resolved_old, &self.synthetic_proc_context())
            || is_synthetic_virtual_file(&resolved_new, &self.synthetic_proc_context())
        {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        let no_replace = flags & RENAME_NOREPLACE != 0;
        match self
            .rootfs_vfs
            .rename_with_flags(&resolved_old, &resolved_new, no_replace)
        {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn unlinkat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        if flags & !LINUX_AT_REMOVEDIR != 0 {
            return Ok(DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            });
        }
        let path = match read_guest_c_string(&*ctx.memory, pathname) {
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
        let remove_dir = flags & LINUX_AT_REMOVEDIR != 0;
        // Synthetic /proc /sys paths can't be unlinked.
        if is_synthetic_virtual_file(&resolved, &self.synthetic_proc_context()) {
            return Ok(DispatchOutcome::Errno { errno: LINUX_EROFS });
        }
        use crate::vfs::Vfs as _;
        let result = if remove_dir {
            self.rootfs_vfs.rmdir(&resolved)
        } else {
            self.rootfs_vfs.unlink(&resolved)
        };
        match result {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn utimensat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let times = ctx.arg(2);
        let flags = ctx.arg(3);
        let memory = &*ctx.memory;
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
            return Ok(DispatchOutcome::Returned { value: 0 });
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
        // The overlay doesn't track atime/mtime separately from the
        // underlying file. Accept the call as long as the path exists in
        // the layered view; mirror the rootfs view's NotFound otherwise.
        match self.layered_metadata(&path) {
            Ok(_) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => {
                if is_synthetic_virtual_file(&path, &self.synthetic_proc_context()) {
                    Ok(DispatchOutcome::Returned { value: 0 })
                } else {
                    Ok(DispatchOutcome::Errno { errno })
                }
            }
        }
    }

    fn newfstatat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let statbuf = ctx.arg(2);
        let flags = ctx.arg(3);
        let memory = &mut *ctx.memory;
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
        // Synthetic /proc /sys paths first.
        if let Some(contents) = synthetic_proc_file(&path, &self.synthetic_proc_context()) {
            return Ok(write_synthetic_stat(memory, statbuf, &path, contents.len()));
        }
        if let Some(contents) = synthetic_sys_file(&path) {
            return Ok(write_synthetic_stat(memory, statbuf, &path, contents.len()));
        }
        // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
        // so the type bits (S_IFLNK for a symlink) and st_nlink (a true
        // hard link reports >1) reflect what the kernel would report.
        // `AT_SYMLINK_NOFOLLOW` selects lstat (report the link) vs stat
        // (report the target) semantics.
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        if let Some(real) = self.rootfs_vfs.overlay.real_stat(&path, follow) {
            return Ok(write_stat_real(memory, statbuf, &path, &real));
        }
        // Layered overlay+rootfs lookup via RootFsVfs.
        use crate::vfs::Vfs as _;
        match self.rootfs_vfs.lookup(&path) {
            Ok(md) => Ok(write_stat(memory, statbuf, &vfs_md_to_rootfs_md(&path, &md))),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn statx<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let dirfd = ctx.arg(0);
        let pathname = ctx.arg(1);
        let flags = ctx.arg(2);
        let mask = ctx.arg(3);
        let statxbuf = ctx.arg(4);
        let memory = &mut *ctx.memory;

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
        if let Some(contents) = synthetic_proc_file(&path, &self.synthetic_proc_context()) {
            return Ok(write_synthetic_statx(memory, statxbuf, &path, contents.len()));
        }
        if let Some(contents) = synthetic_sys_file(&path) {
            return Ok(write_synthetic_statx(memory, statxbuf, &path, contents.len()));
        }
        // Disk-backed overlay (--fs host): prefer the REAL on-disk stat
        // (S_IFLNK + true st_nlink). `AT_SYMLINK_NOFOLLOW` selects lstat
        // (the link) vs stat (the target).
        let follow = flags & LINUX_AT_SYMLINK_NOFOLLOW == 0;
        if let Some(real) = self.rootfs_vfs.overlay.real_stat(&path, follow) {
            return Ok(write_statx_real(memory, statxbuf, &path, &real));
        }
        use crate::vfs::Vfs as _;
        match self.rootfs_vfs.lookup(&path) {
            Ok(md) => Ok(write_statx(memory, statxbuf, &vfs_md_to_rootfs_md(&path, &md))),
            Err(errno) => Ok(DispatchOutcome::Errno { errno }),
        }
    }

    fn fstat<M: GuestMemory>(
        &mut self,
        ctx: &mut SyscallCtx<M>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let fd = ctx.arg(0) as i32;
        let statbuf = ctx.arg(1);
        Ok(self.write_fd_stat(fd, statbuf, &mut *ctx.memory))
    }

    fn write_fd_stat(
        &self,
        fd: i32,
        statbuf: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_files.get(&fd) else {
            if is_stdio_fd(fd) {
                // Glibc cat/head/etc fstat stdout on startup to decide
                // whether they're talking to a regular file (use POSIX
                // sendfile fast path) or a TTY/pipe (default cooked
                // path). Synthesize a character-device stat so they
                // pick the right branch instead of bailing EBADF.
                let label = match fd {
                    0 => "/dev/stdin",
                    1 => "/dev/stdout",
                    _ => "/dev/stderr",
                };
                return write_synthetic_stat(memory, statbuf, label, 0);
            }
            return DispatchOutcome::Errno { errno: LINUX_EBADF };
        };
        let open = open_file.description.borrow();
        let metadata = match &*open {
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => metadata,
            // Real host file: fstat the fd for the LIVE size (it may
            // have grown since open, incl. from a forked child).
            OpenDescription::HostFile { host_fd, metadata, .. } => {
                let mut md = metadata.clone();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(*host_fd, &mut st) } == 0 {
                    md.size = st.st_size as usize;
                }
                return write_stat(memory, statbuf, &md);
            }
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
            OpenDescription::HostSocket { .. } => {
                return write_synthetic_stat(memory, statbuf, "socket:[carrick]", 0);
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
            OpenDescription::HostFile { host_fd, metadata, .. } => {
                let mut md = metadata.clone();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(*host_fd, &mut st) } == 0 {
                    md.size = st.st_size as usize;
                }
                return write_statx(memory, statxbuf, &md);
            }
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
            OpenDescription::HostSocket { .. } => {
                return write_synthetic_statx(memory, statxbuf, "socket:[carrick]", 0);
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
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
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
                | OpenDescription::HostFile { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
            | OpenDescription::HostPipe { .. }
            | OpenDescription::HostSocket { .. } => Err(LINUX_ENOTDIR),
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
    // getpid() exposes the host pid (std::process::id()) so glibc and
    // friends use that as the self-id when calling kill/tkill/tgkill.
    // Accept either that or LINUX_BOOTSTRAP_PID so existing callers
    // that hard-coded `1` keep working.
    let host_pid = std::process::id() as i64;
    let bootstrap_pid = LINUX_BOOTSTRAP_PID as i64;
    let self_target = if tid_required {
        target == host_pid || target == bootstrap_pid
    } else {
        // kill(0, sig) targets the calling process's process group; in our
        // single-process bootstrap that's still just us.
        target == host_pid || target == bootstrap_pid || target == 0
    };
    if self_target {
        if signum == 0 {
            // POSIX: signum 0 is the null-signal "is this pid alive" probe.
            return DispatchOutcome::Returned { value: 0 };
        }
        // Queue the signal for self-delivery. The runtime drains the pending
        // slot between vCPU iterations and either injects a handler frame or
        // applies the default action (terminate with 128 + signum).
        crate::host_signal::raise_for_self(signum as i32);
        return DispatchOutcome::Returned { value: 0 }
    }
    // Cross-process kill: target is some other host pid. After clone(),
    // child guests run as separate host processes — apt's parent
    // process uses kill(child_pid, SIGINT) as part of the AcquireMethod
    // shutdown protocol, and ESRCH here breaks the protocol with
    // "method did not start correctly". Defer to libc::kill on the host;
    // the host kernel knows whether `target` is one of our descendants
    // and returns ESRCH itself if not. Negative pids (process-group kill)
    // pass through too.
    if target == 0 || target < i32::MIN as i64 || target > i32::MAX as i64 {
        return DispatchOutcome::Errno { errno: LINUX_ESRCH };
    }
    let rc = unsafe { libc::kill(target as i32, signum as i32) };
    if rc < 0 {
        return DispatchOutcome::Errno { errno: host_errno() };
    }
    DispatchOutcome::Returned { value: 0 }
}

/// Untyped guest-memory write. Prefer [`write_kernel_struct`] over this
/// whenever the payload is a Linux UAPI struct: that path is bound to
/// `KernelAbi::ABI_SIZE` so it CAN'T accidentally over-write a caller's
/// stack buffer the way an ad-hoc `&[u8]` from `as_bytes()` can.
/// Apply `bytes` to a `Vec<u8>` file backing at `*offset`, growing the
/// vector (zero-filled if there's a gap) and advancing the cursor. This
/// is the in-memory mirror of `vfs_write`: it makes a writable
/// overlay-backed File behave like a real tmpfs.
fn write_into_file_contents(contents: &mut Vec<u8>, offset: &mut usize, bytes: &[u8]) {
    let end = *offset + bytes.len();
    if end > contents.len() {
        contents.resize(end, 0);
    }
    contents[*offset..end].copy_from_slice(bytes);
    *offset = end;
}

/// (syscall_number, arg_index, supported_mask) for every syscall that
/// takes a `flags`-style argument with a well-defined supported bit
/// set on aarch64 Linux. The dispatch entry point consults this table
/// BEFORE the handler runs, so any flag bit the guest sets that we
/// don't recognise produces a `UnknownSyscallFlags` event in the
/// compat report (and a `unknown-syscall-flags` USDT probe firing)
/// regardless of whether the individual handler validates flags
/// itself. Add entries here as new flag-bearing syscalls land.
const SYSCALL_FLAG_VALIDATORS: &[(u64, u32, u64)] = &[
    // eventfd2(initval, flags): EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC
    (19, 1, LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC),
    // epoll_create1(flags): EPOLL_CLOEXEC
    (20, 0, LINUX_EPOLL_CLOEXEC),
    // dup3(oldfd, newfd, flags): O_CLOEXEC
    (24, 2, LINUX_O_CLOEXEC),
    // unlinkat(dirfd, pathname, flags): AT_REMOVEDIR (0x200) plus the
    // AT_EMPTY_PATH/AT_SYMLINK_NOFOLLOW pair we accept elsewhere
    (35, 2, 0x200 | LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW),
    // renameat2(olddirfd, oldpath, newdirfd, newpath, flags):
    // RENAME_NOREPLACE(1)|EXCHANGE(2)|WHITEOUT(4)
    (276, 4, 0x1 | 0x2 | 0x4),
    // openat(dirfd, pathname, flags, mode): the open flags we recognise
    // — a superset that covers RDONLY/WRONLY/RDWR + the standard mods.
    // Bits are kept liberal because openat is the most-touched syscall.
    (
        56,
        2,
        // access mode bits 0..1 = O_RDONLY/O_WRONLY/O_RDWR
        0o3
        // common bit flags
        | 0o100      // O_CREAT
        | 0o200      // O_EXCL
        | 0o400      // O_NOCTTY
        | 0o1000     // O_TRUNC
        | 0o2000     // O_APPEND
        | LINUX_O_NONBLOCK
        | 0o10000    // O_DSYNC
        | 0o20000    // FASYNC
        | 0o40000    // O_DIRECT
        | 0o100000   // O_LARGEFILE
        | 0o200000   // O_DIRECTORY
        | 0o400000   // O_NOFOLLOW
        | 0o1000000  // O_NOATIME
        | LINUX_O_CLOEXEC
        | 0o4010000  // O_SYNC
        | 0o010000000 // O_PATH
        | 0o020000000 // O_TMPFILE
    ),
    // pipe2(pipefd, flags): O_CLOEXEC | O_NONBLOCK
    (59, 1, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK),
    // signalfd4(fd, mask, sizemask, flags): SFD_NONBLOCK | SFD_CLOEXEC
    (74, 3, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC),
    // timerfd_create(clockid, flags): TFD_NONBLOCK | TFD_CLOEXEC
    (85, 1, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC),
    // timerfd_settime(fd, flags, ...): TFD_TIMER_ABSTIME (1) | TFD_TIMER_CANCEL_ON_SET (2)
    (86, 1, 0x1 | 0x2),
    // utimensat(dirfd, pathname, times, flags): AT_SYMLINK_NOFOLLOW (0x100)
    (88, 3, LINUX_AT_SYMLINK_NOFOLLOW),
    // accept4(sockfd, addr, addrlen, flags): SOCK_NONBLOCK | SOCK_CLOEXEC
    (242, 3, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC),
    // close_range(first, last, flags): CLOSE_RANGE_UNSHARE(2) | CLOEXEC(4)
    (436, 2, 0x2 | 0x4),
    // openat2 — checked inside open_how, but the syscall flag arg is unused
    // statx(dirfd, pathname, flags, mask, statxbuf): AT_* flags
    (
        291,
        2,
        LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW | 0x1000 /* AT_NO_AUTOMOUNT */ | 0x800 /* AT_STATX_SYNC_AS_STAT */ | 0x4000 /* AT_STATX_FORCE_SYNC */ | 0x6000,
    ),
    // faccessat2(dirfd, pathname, mode, flags)
    (439, 3, LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW | 0x200 /* AT_EACCESS */),
];

/// Systematic unknown-flag detector for syscalls.
///
/// Every syscall that takes a "flags" argument knows which bits are
/// actually defined by the Linux ABI. If the guest passes a bit we
/// don't recognise, something has drifted — either the guest's libc
/// is newer than ours, or we forgot to wire a flag. Either way, it
/// shouldn't be silent. This helper records the unknown bits via the
/// reporter (so the JSON compat report aggregates them) and via the
/// `unknown-syscall-flags` USDT probe (so dtrace can fire on it
/// live), then returns the unknown bits so the caller can decide
/// whether to EINVAL or proceed.
///
/// Usage:
/// ```ignore
/// let unknown = check_syscall_flags(
///     reporter, /*nr=*/ 56, /*name=*/ "openat", /*arg_index=*/ 2,
///     flags, OPENAT_SUPPORTED_MASK,
/// );
/// if unknown != 0 {
///     return DispatchOutcome::Errno { errno: LINUX_EINVAL };
/// }
/// ```
pub fn check_syscall_flags(
    reporter: &mut CompatReporter,
    number: u64,
    name: &str,
    argument_index: u32,
    value: u64,
    supported_mask: u64,
) -> u64 {
    let unknown = value & !supported_mask;
    if unknown != 0 {
        reporter.record(CompatEvent::unknown_syscall_flags(
            number,
            name,
            argument_index,
            unknown,
        ));
    }
    unknown
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

/// Type-safe write for any Linux UAPI struct that implements
/// [`KernelAbi`]. Writes EXACTLY `T::ABI_SIZE` bytes — the size the
/// Linux kernel itself uses on the wire. The compiler refuses to pass
/// `T` here unless the trait is implemented, which forces every new
/// ABI struct to declare its kernel size up front and have a paired
/// const assert validating ABI_SIZE <= size_of::<T>().
fn write_kernel_struct<T: KernelAbi>(
    memory: &mut impl GuestMemory,
    address: u64,
    value: &T,
) -> DispatchOutcome {
    write_packed(memory, address, value.abi_bytes())
}

/// Lower-level form of [`write_kernel_struct`] for sites that already
/// handle `Result<(), MemoryError>` directly (typically because they
/// have post-write bookkeeping that the `DispatchOutcome::Errno` shape
/// would short-circuit). Same wire-size guarantee.
fn write_kernel_struct_raw<T: KernelAbi>(
    memory: &mut impl GuestMemory,
    address: u64,
    value: &T,
) -> Result<(), crate::dispatch::MemoryError> {
    memory.write_bytes(address, value.abi_bytes())
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
    write_kernel_struct(memory, statfsbuf, &statfs)
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
        OpenDescription::HostSocket { host_fd, .. }
        | OpenDescription::HostFile { host_fd, .. } => {
            // Same last-reference rule as HostPipe: only close the real
            // macOS fd when no other Linux fd still aliases the same
            // OpenDescription via dup3/dup2.
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

/// Set the host thread/process name to `carrick: <comm>` so external
/// tools (Activity Monitor, `ps -M`, `sample`, lldb) can tell which
/// guest a carrick host process is running — invaluable when a forked
/// child hangs. `comm` is the guest's NUL-padded task name. macOS's
/// `pthread_setname_np` sets the calling thread's name (capped at
/// MAXTHREADNAMESIZE=64), which for our single-vCPU-thread model is
/// the process's visible name.
#[cfg(target_os = "macos")]
pub fn set_host_process_name(comm: &[u8]) {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    let name = String::from_utf8_lossy(&comm[..end]);
    let label = format!("carrick: {}", name.trim());

    // (1) Thread name — shows in lldb / Instruments / sample / crash
    // reports. Capped at MAXTHREADNAMESIZE (64).
    let thread_label: String = label.chars().take(63).collect();
    if let Ok(cstr) = std::ffi::CString::new(thread_label) {
        unsafe {
            libc::pthread_setname_np(cstr.as_ptr());
        }
    }

    // (2) argv[0] in-place overwrite — what `ps` reads. macOS's `ps`
    // shows the argument vector; overwriting argv[0]'s bytes (bounded
    // by its original length so we never run past the contiguous
    // argv/env block) changes the visible command. This is the same
    // technique libuv/Node use for `process.title`. NUL-pad the
    // remainder so a shortened name doesn't leave stale trailing text.
    unsafe {
        let argv = libc::_NSGetArgv();
        if !argv.is_null() && !(*argv).is_null() {
            let arg0 = *(*argv);
            if !arg0.is_null() {
                let orig_len = libc::strlen(arg0);
                let bytes = label.as_bytes();
                let n = bytes.len().min(orig_len);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), arg0 as *mut u8, n);
                // Pad the rest of the original arg0 with NULs.
                for i in n..orig_len {
                    *arg0.add(i) = 0;
                }
            }
        }
    }

    // (3) Activity Monitor display name via private LaunchServices.
    // Best-effort; no-op on a non-GUI session.
    crate::host_proctitle::set_activity_monitor_name(&label);
}

#[cfg(not(target_os = "macos"))]
pub fn set_host_process_name(_comm: &[u8]) {}

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

    if write_kernel_struct_raw(memory, statbuf, &stat).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

/// Build and write a `stat` from REAL on-disk values ([`RealStat`]):
/// the true file type (so a symlink stat'd with `AT_SYMLINK_NOFOLLOW`
/// reports S_IFLNK) and the real `st_nlink` (a true hard link reports
/// >1). Type/mode bits come from a [`RootFsMetadata`] carrying the
/// real `kind`; `st_nlink` is overridden with the disk value.
fn write_stat_real(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    path: &str,
    real: &crate::fs_backend::RealStat,
) -> DispatchOutcome {
    let metadata = RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: real.kind,
        mode: real.mode,
        size: real.size as usize,
    };
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: inode_for_path(&metadata.path),
        st_mode: linux_mode(&metadata),
        st_nlink: real.nlink,
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
    if write_kernel_struct_raw(memory, statbuf, &stat).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

/// `statx` counterpart of [`write_stat_real`].
fn write_statx_real(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    path: &str,
    real: &crate::fs_backend::RealStat,
) -> DispatchOutcome {
    let metadata = RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: real.kind,
        mode: real.mode,
        size: real.size as usize,
    };
    let zero_time = LinuxStatxTimestamp::zero();
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: real.nlink,
        stx_uid: 0,
        stx_gid: 0,
        stx_mode: linux_mode(&metadata) as u16,
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
    write_kernel_struct(memory, statxbuf, &statx)
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
    write_kernel_struct(memory, statxbuf, &statx)
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
    write_kernel_struct(memory, statbuf, &stat)
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

/// Minimal view of the dispatcher needed by the synthetic /proc
/// renderers. Keeps the synthetic helpers as free functions while
/// letting them see live state (executable path, address-space
/// regions, current brk, next mmap address) without taking `&self`.
pub struct SyntheticProcContext<'a> {
    pub executable_path: &'a str,
    pub address_space_regions: Option<&'a [ProcMapsEntry]>,
    pub brk_current: u64,
    pub mmap_next: u64,
}

impl SyscallDispatcher {
    fn synthetic_proc_context(&self) -> SyntheticProcContext<'_> {
        SyntheticProcContext {
            executable_path: &self.executable_path,
            address_space_regions: self.address_space_regions.as_deref(),
            brk_current: self.brk_current,
            mmap_next: self.mmap_next,
        }
    }
}

pub fn synthetic_proc_file(path: &str, ctx: &SyntheticProcContext<'_>) -> Option<Vec<u8>> {
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
        "/proc/self/cmdline" => Some(synthetic_proc_self_cmdline(ctx.executable_path)),
        "/proc/self/comm" => Some(synthetic_proc_self_comm(ctx.executable_path).into_bytes()),
        "/proc/self/limits" => Some(synthetic_proc_self_limits().to_vec()),
        "/proc/self/maps" => Some(synthetic_proc_maps(ctx).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm().to_vec()),
        "/proc/self/status" => Some(synthetic_proc_self_status(ctx.executable_path).into_bytes()),
        "/proc/sys/kernel/osrelease" => Some(synthetic_proc_osrelease().to_vec()),
        "/proc/sys/kernel/hostname" => Some(synthetic_proc_hostname().to_vec()),
        "/proc/sys/kernel/random/boot_id" => {
            Some(synthetic_proc_boot_id().to_vec())
        }
        // glibc's `__check_pf` (called from getaddrinfo with
        // AI_ADDRCONFIG) queries the kernel via NETLINK_ROUTE for
        // interface families. macOS has no AF_NETLINK, so the socket
        // call fails and glibc falls back to reading
        // `/proc/net/if_inet6`. Without this file, glibc's fallback
        // path treats IPv6 as "available" by default, then apt's
        // resolver issues AAAA queries that never get answered and
        // returns EAI_AGAIN. Synthesise the file with only the
        // loopback `::1` entry so the kernel-PF check concludes "no
        // non-loopback IPv6" — AI_ADDRCONFIG then short-circuits to
        // IPv4 and apt's http method resolves on the first try.
        //
        // Format (per kernel docs):
        //   <16-byte hex IPv6 addr> <iface idx hex> <prefix len hex>
        //   <scope hex> <flags hex> <devname>
        "/proc/net/if_inet6" => Some(
            b"00000000000000000000000000000001 01 80 10 80       lo\n".to_vec(),
        ),
        _ => None,
    }
}

pub fn synthetic_sys_file(path: &str) -> Option<Vec<u8>> {
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

fn is_synthetic_virtual_file(path: &str, ctx: &SyntheticProcContext<'_>) -> bool {
    synthetic_proc_file(path, ctx).is_some() || synthetic_sys_file(path).is_some()
}

fn synthetic_proc_maps(ctx: &SyntheticProcContext<'_>) -> String {
    if let Some(regions) = ctx.address_space_regions {
        return render_proc_maps_from_regions(
            regions,
            ctx.executable_path,
            ctx.brk_current,
            ctx.mmap_next,
        );
    }
    // Fallback for callers that didn't plumb the live region list
    // (e.g. unit tests that drive the dispatcher in isolation). Mirrors
    // the historical hard-coded summary so existing assertions still
    // see r-xp / [heap] / a trailing newline.
    format!(
        "0000000000400000-0000000000410000 r-xp 00000000 00:00 0 {executable_path}\n\
         {heap_base:016x}-{heap_end:016x} rw-p 00000000 00:00 0 [heap]\n\
         {mmap_base:016x}-{mmap_end:016x} rwxp 00000000 00:00 0 [carrick-mmap]\n\
         0000007fffe00000-0000008000000000 rw-p 00000000 00:00 0 [stack]\n",
        executable_path = ctx.executable_path,
        heap_base = LINUX_HEAP_BASE,
        heap_end = LINUX_HEAP_BASE + LINUX_HEAP_SIZE,
        mmap_base = LINUX_MMAP_BASE,
        mmap_end = LINUX_MMAP_BASE + LINUX_MMAP_SIZE,
    )
}

/// Render `/proc/self/maps` from the real guest region list. Each
/// row matches the Linux kernel's `show_map_vma` format strictly:
/// `{start:x}-{end:x} {perms} {offset:08x} {dev:02x}:{dev:02x} {inode}    {path}`
/// where `perms` is `rwxp` (always private; we don't model MAP_SHARED).
/// The heap region's end is replaced with `brk_current` and the mmap
/// arena's end is replaced with `mmap_next`, both of which advance as
/// the guest runs.
fn render_proc_maps_from_regions(
    regions: &[ProcMapsEntry],
    executable_path: &str,
    brk_current: u64,
    mmap_next: u64,
) -> String {
    let mut sorted: Vec<&ProcMapsEntry> = regions.iter().collect();
    sorted.sort_by_key(|r| r.start);
    let mut out = String::new();
    for region in sorted {
        let (start, mut end, label) = label_for_region(region, executable_path);
        // Track live end pointers for heap and mmap so the guest sees
        // its own growth (brk(2) / mmap(2)) reflected in the map.
        match label.as_str() {
            "[heap]" => {
                if brk_current > start && brk_current <= region.end {
                    end = brk_current;
                }
            }
            "[carrick-mmap]" => {
                if mmap_next > start && mmap_next <= region.end {
                    end = mmap_next;
                }
            }
            _ => {}
        }
        let r = if region.read { 'r' } else { '-' };
        let w = if region.write { 'w' } else { '-' };
        let x = if region.execute { 'x' } else { '-' };
        // Always private (`p`); we don't model MAP_SHARED.
        out.push_str(&format!(
            "{start:016x}-{end:016x} {r}{w}{x}p 00000000 00:00 0                          {label}\n",
        ));
    }
    out
}

/// Pick a `/proc/self/maps` label for a region. Matches the kernel's
/// convention: `[heap]`, `[stack]`, anonymous-named tags like
/// `[carrick-mmap]` / `[carrick-vectors]` / `[carrick-trampoline]` /
/// `[carrick-pagetables]` for our bootstrap pages, the executable
/// path for the loaded ELF segments, and an empty path for everything
/// else.
fn label_for_region(region: &ProcMapsEntry, executable_path: &str) -> (u64, u64, String) {
    let start = region.start;
    let end = region.end;
    let label = if start == LINUX_HEAP_BASE {
        "[heap]".to_owned()
    } else if start == LINUX_MMAP_BASE {
        "[carrick-mmap]".to_owned()
    } else if start == LINUX_STACK_TOP.saturating_sub(LINUX_STACK_SIZE) {
        "[stack]".to_owned()
    } else if start == LINUX_EL0_TRAMPOLINE_BASE {
        "[carrick-trampoline]".to_owned()
    } else if start == LINUX_EL1_VECTORS_BASE {
        "[carrick-vectors]".to_owned()
    } else if start == LINUX_PAGE_TABLES_BASE {
        "[carrick-pagetables]".to_owned()
    } else if !region.path.is_empty() {
        region.path.clone()
    } else if region.execute {
        // Executable region with no other label and no explicit path
        // is almost certainly an ELF code segment from the loaded
        // executable image.
        executable_path.to_owned()
    } else {
        String::new()
    };
    (start, end, label)
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
    if write_kernel_struct_raw(memory, address, &value).is_err() {
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

fn fd_set_set(fd_set: &mut [u8], fd: usize) {
    if let Some(byte) = fd_set.get_mut(fd / 8) {
        *byte |= 1 << (fd % 8);
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
    // carrick runs the guest as uid 0 (root), and the overlay/host backend is
    // writable (read-only rootfs files copy up on write). Root bypasses DAC
    // read/write checks entirely, so R_OK and W_OK always succeed for an
    // existing path — previously W_OK returned EACCES unconditionally, which
    // made dpkg refuse /var/lib/dpkg ("required read/write access") even
    // though writes actually work. For execute, root still requires at least
    // one x bit on a regular file.
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
    // Idempotent: callers pass either a relative (normalised) path or an
    // already-absolute one. Strip leading slashes and prepend exactly one so
    // we never produce a double leading slash (getcwd returned "//tmp/...").
    let s = path.to_string_lossy();
    let trimmed = s.trim_start_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{trimmed}")
    }
}

pub fn rootfs_errno(error: RootFsError) -> i32 {
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

/// Adapter from the VFS-trait [`vfs::Metadata`] back to
/// [`RootFsMetadata`] for the dispatcher's existing stat/statx
/// writers, which still take the rootfs-shaped struct. Used by every
/// dispatcher fs syscall that's been migrated to consult
/// `RootFsVfs::lookup`.
fn vfs_md_to_rootfs_md(path: &str, md: &crate::vfs::Metadata) -> RootFsMetadata {
    RootFsMetadata {
        path: Path::new(path).to_path_buf(),
        kind: match md.kind {
            crate::vfs::EntryKind::File => RootFsEntryKind::File,
            crate::vfs::EntryKind::Directory => RootFsEntryKind::Directory,
            crate::vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
            crate::vfs::EntryKind::CharDevice => RootFsEntryKind::File,
        },
        mode: md.mode,
        size: md.size as usize,
    }
}

fn host_errno() -> i32 {
    // SAFETY: `__errno_location` (Linux) and `__error` (macOS) both
    // return a thread-local int pointer.
    let raw = unsafe { *libc::__error() };
    macos_to_linux_errno(raw)
}

/// Linux UAPI errno values. Sourced from
/// `linux/include/uapi/asm-generic/errno-base.h` and `errno.h`.
/// Hardcoded here so the translation is independent of whatever the
/// host's libc decided to name (or number) these — when we run on
/// macOS, `libc::EAGAIN` is 35, but Linux's EAGAIN is 11. We need
/// constant Linux numbers regardless of host.
#[allow(dead_code)]
pub mod linux_errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const ESRCH: i32 = 3;
    pub const EINTR: i32 = 4;
    pub const EIO: i32 = 5;
    pub const ENXIO: i32 = 6;
    pub const E2BIG: i32 = 7;
    pub const ENOEXEC: i32 = 8;
    pub const EBADF: i32 = 9;
    pub const ECHILD: i32 = 10;
    pub const EAGAIN: i32 = 11; // ≡ EWOULDBLOCK
    pub const ENOMEM: i32 = 12;
    pub const EACCES: i32 = 13;
    pub const EFAULT: i32 = 14;
    pub const ENOTBLK: i32 = 15;
    pub const EBUSY: i32 = 16;
    pub const EEXIST: i32 = 17;
    pub const EXDEV: i32 = 18;
    pub const ENODEV: i32 = 19;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    pub const ENOTTY: i32 = 25;
    pub const ETXTBSY: i32 = 26;
    pub const EFBIG: i32 = 27;
    pub const ENOSPC: i32 = 28;
    pub const ESPIPE: i32 = 29;
    pub const EROFS: i32 = 30;
    pub const EMLINK: i32 = 31;
    pub const EPIPE: i32 = 32;
    pub const EDOM: i32 = 33;
    pub const ERANGE: i32 = 34;
    // ----- Linux SysV-style codes start here; macOS diverges -----
    pub const EDEADLK: i32 = 35;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOLCK: i32 = 37;
    pub const ENOSYS: i32 = 38;
    pub const ENOTEMPTY: i32 = 39;
    pub const ELOOP: i32 = 40;
    pub const ENOMSG: i32 = 42;
    pub const EIDRM: i32 = 43;
    pub const ENOLINK: i32 = 67;
    pub const EBADMSG: i32 = 74;
    pub const EOVERFLOW: i32 = 75;
    pub const EILSEQ: i32 = 84;
    pub const ENOTSOCK: i32 = 88;
    pub const EDESTADDRREQ: i32 = 89;
    pub const EMSGSIZE: i32 = 90;
    pub const EPROTOTYPE: i32 = 91;
    pub const ENOPROTOOPT: i32 = 92;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const ESOCKTNOSUPPORT: i32 = 94;
    pub const EOPNOTSUPP: i32 = 95; // ≡ ENOTSUP
    pub const EPFNOSUPPORT: i32 = 96;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const EADDRINUSE: i32 = 98;
    pub const EADDRNOTAVAIL: i32 = 99;
    pub const ENETDOWN: i32 = 100;
    pub const ENETUNREACH: i32 = 101;
    pub const ENETRESET: i32 = 102;
    pub const ECONNABORTED: i32 = 103;
    pub const ECONNRESET: i32 = 104;
    pub const ENOBUFS: i32 = 105;
    pub const EISCONN: i32 = 106;
    pub const ENOTCONN: i32 = 107;
    pub const ESHUTDOWN: i32 = 108;
    pub const ETOOMANYREFS: i32 = 109;
    pub const ETIMEDOUT: i32 = 110;
    pub const ECONNREFUSED: i32 = 111;
    pub const EHOSTDOWN: i32 = 112;
    pub const EHOSTUNREACH: i32 = 113;
    pub const EALREADY: i32 = 114;
    pub const EINPROGRESS: i32 = 115;
    pub const ESTALE: i32 = 116;
    pub const EUCLEAN: i32 = 117;
    pub const EREMOTE: i32 = 121;
    pub const EDQUOT: i32 = 122;
    pub const ECANCELED: i32 = 125;
}

/// Robust, systematic macOS-errno → Linux-errno translation. Driven
/// off the host's `libc::E*` constants on the macOS side so we don't
/// hard-code macOS numeric values — if Apple ever renumbers something
/// (they won't, but defensive coding) we pick up the new value
/// automatically. Codes 1..=34 overlap between the two and pass
/// through unchanged. Sources:
/// - macOS: <sys/errno.h>
/// - Linux: asm-generic/errno-base.h + asm-generic/errno.h
pub fn macos_to_linux_errno(macos: i32) -> i32 {
    use linux_errno::*;
    #[cfg(target_os = "macos")]
    {
        match macos {
            x if x == libc::EAGAIN => EAGAIN,
            x if x == libc::EINPROGRESS => EINPROGRESS,
            x if x == libc::EALREADY => EALREADY,
            x if x == libc::ENOTSOCK => ENOTSOCK,
            x if x == libc::EDESTADDRREQ => EDESTADDRREQ,
            x if x == libc::EMSGSIZE => EMSGSIZE,
            x if x == libc::EPROTOTYPE => EPROTOTYPE,
            x if x == libc::ENOPROTOOPT => ENOPROTOOPT,
            x if x == libc::EPROTONOSUPPORT => EPROTONOSUPPORT,
            x if x == libc::ESOCKTNOSUPPORT => ESOCKTNOSUPPORT,
            x if x == libc::EOPNOTSUPP => EOPNOTSUPP,
            x if x == libc::EPFNOSUPPORT => EPFNOSUPPORT,
            x if x == libc::EAFNOSUPPORT => EAFNOSUPPORT,
            x if x == libc::EADDRINUSE => EADDRINUSE,
            x if x == libc::EADDRNOTAVAIL => EADDRNOTAVAIL,
            x if x == libc::ENETDOWN => ENETDOWN,
            x if x == libc::ENETUNREACH => ENETUNREACH,
            x if x == libc::ENETRESET => ENETRESET,
            x if x == libc::ECONNABORTED => ECONNABORTED,
            x if x == libc::ECONNRESET => ECONNRESET,
            x if x == libc::ENOBUFS => ENOBUFS,
            x if x == libc::EISCONN => EISCONN,
            x if x == libc::ENOTCONN => ENOTCONN,
            x if x == libc::ESHUTDOWN => ESHUTDOWN,
            x if x == libc::ETOOMANYREFS => ETOOMANYREFS,
            x if x == libc::ETIMEDOUT => ETIMEDOUT,
            x if x == libc::ECONNREFUSED => ECONNREFUSED,
            x if x == libc::ELOOP => ELOOP,
            x if x == libc::ENAMETOOLONG => ENAMETOOLONG,
            x if x == libc::EHOSTDOWN => EHOSTDOWN,
            x if x == libc::EHOSTUNREACH => EHOSTUNREACH,
            x if x == libc::ENOTEMPTY => ENOTEMPTY,
            x if x == libc::EDQUOT => EDQUOT,
            x if x == libc::ESTALE => ESTALE,
            x if x == libc::EREMOTE => EREMOTE,
            x if x == libc::ENOLCK => ENOLCK,
            x if x == libc::ENOSYS => ENOSYS,
            x if x == libc::EOVERFLOW => EOVERFLOW,
            x if x == libc::ECANCELED => ECANCELED,
            x if x == libc::EIDRM => EIDRM,
            x if x == libc::ENOMSG => ENOMSG,
            x if x == libc::EILSEQ => EILSEQ,
            x if x == libc::EBADMSG => EBADMSG,
            // Codes 1..=34 overlap; anything else falls through.
            other => other,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        macos
    }
}

// ----- BSD socket translation helpers ------------------------------------

/// Linux AF_* values for the families we support. Linux constants happen
/// to overlap with macOS's only for AF_UNSPEC / AF_UNIX / AF_INET — the
/// AF_INET6 numeric value differs (Linux: 10, macOS: 30).
const LINUX_AF_UNSPEC: i32 = 0;
const LINUX_AF_UNIX: i32 = 1;
const LINUX_AF_INET: i32 = 2;
const LINUX_AF_INET6: i32 = 10;
#[allow(dead_code)]
const LINUX_AF_NETLINK: i32 = 16;
#[allow(dead_code)]
const LINUX_AF_PACKET: i32 = 17;

const LINUX_SOCK_STREAM: i32 = 1;
const LINUX_SOCK_DGRAM: i32 = 2;
const LINUX_SOCK_RAW: i32 = 3;
const LINUX_SOCK_SEQPACKET: i32 = 5;

fn linux_to_host_af(family: i32) -> i32 {
    match family {
        LINUX_AF_UNSPEC => libc::AF_UNSPEC,
        LINUX_AF_UNIX => libc::AF_UNIX,
        LINUX_AF_INET => libc::AF_INET,
        LINUX_AF_INET6 => libc::AF_INET6,
        // Linux-only families. macOS doesn't have AF_NETLINK / AF_PACKET;
        // pass through whatever number was given so the host socket()
        // call returns EAFNOSUPPORT naturally.
        _ => family,
    }
}

fn host_to_linux_af(host_family: u16) -> u16 {
    match host_family as i32 {
        libc::AF_UNSPEC => LINUX_AF_UNSPEC as u16,
        libc::AF_UNIX => LINUX_AF_UNIX as u16,
        libc::AF_INET => LINUX_AF_INET as u16,
        libc::AF_INET6 => LINUX_AF_INET6 as u16,
        _ => host_family,
    }
}

fn linux_to_host_socktype(t: i32) -> i32 {
    // Linux and macOS agree on the numeric values for the BSD socket
    // types we care about (1=STREAM, 2=DGRAM, 3=RAW, 5=SEQPACKET).
    match t {
        LINUX_SOCK_STREAM => libc::SOCK_STREAM,
        LINUX_SOCK_DGRAM => libc::SOCK_DGRAM,
        LINUX_SOCK_RAW => libc::SOCK_RAW,
        LINUX_SOCK_SEQPACKET => libc::SOCK_SEQPACKET,
        _ => t,
    }
}

const LINUX_MSG_OOB: i32 = 0x0001;
const LINUX_MSG_PEEK: i32 = 0x0002;
const LINUX_MSG_DONTROUTE: i32 = 0x0004;
const LINUX_MSG_TRUNC: i32 = 0x0020;
const LINUX_MSG_DONTWAIT: i32 = 0x0040;
const LINUX_MSG_EOR: i32 = 0x0080;
const LINUX_MSG_WAITALL: i32 = 0x0100;
const LINUX_MSG_NOSIGNAL: i32 = 0x4000;
const LINUX_MSG_CMSG_CLOEXEC: i32 = 0x4000_0000_u32 as i32;

fn linux_to_host_msg_flags(flags: i32) -> i32 {
    let mut out = 0;
    if flags & LINUX_MSG_OOB != 0 { out |= libc::MSG_OOB; }
    if flags & LINUX_MSG_PEEK != 0 { out |= libc::MSG_PEEK; }
    if flags & LINUX_MSG_DONTROUTE != 0 { out |= libc::MSG_DONTROUTE; }
    if flags & LINUX_MSG_TRUNC != 0 { out |= libc::MSG_TRUNC; }
    if flags & LINUX_MSG_DONTWAIT != 0 { out |= libc::MSG_DONTWAIT; }
    if flags & LINUX_MSG_EOR != 0 { out |= libc::MSG_EOR; }
    if flags & LINUX_MSG_WAITALL != 0 { out |= libc::MSG_WAITALL; }
    // MSG_NOSIGNAL is Linux-only. macOS expresses the equivalent via
    // SO_NOSIGPIPE on the socket; ignoring the flag is the best we can
    // do here. Likewise MSG_CMSG_CLOEXEC has no macOS equivalent.
    let _ = (LINUX_MSG_NOSIGNAL, LINUX_MSG_CMSG_CLOEXEC);
    out
}

// Linux socket option levels and names. Linux numbers them as small
// integers (SOL_SOCKET=1) while macOS reuses the IPPROTO/SO scheme
// (SOL_SOCKET=0xffff). We translate explicitly for the most common
// options the guest will throw at us. Anything we don't recognise
// returns `None` and the caller surfaces ENOPROTOOPT.
const LINUX_SOL_SOCKET: i32 = 1;
const LINUX_SOL_IP: i32 = 0; // IPPROTO_IP
const LINUX_SOL_TCP: i32 = 6; // IPPROTO_TCP
const LINUX_SOL_UDP: i32 = 17; // IPPROTO_UDP
const LINUX_SOL_IPV6: i32 = 41; // IPPROTO_IPV6

const LINUX_SO_DEBUG: i32 = 1;
const LINUX_SO_REUSEADDR: i32 = 2;
const LINUX_SO_TYPE: i32 = 3;
const LINUX_SO_ERROR: i32 = 4;
const LINUX_SO_DONTROUTE: i32 = 5;
const LINUX_SO_BROADCAST: i32 = 6;
const LINUX_SO_SNDBUF: i32 = 7;
const LINUX_SO_RCVBUF: i32 = 8;
const LINUX_SO_KEEPALIVE: i32 = 9;
const LINUX_SO_OOBINLINE: i32 = 10;
const LINUX_SO_LINGER: i32 = 13;
const LINUX_SO_REUSEPORT: i32 = 15;
const LINUX_SO_RCVTIMEO: i32 = 20;
const LINUX_SO_SNDTIMEO: i32 = 21;
const LINUX_SO_ACCEPTCONN: i32 = 30;

fn linux_to_host_sockopt(level: i32, optname: i32) -> Option<(i32, i32)> {
    match level {
        LINUX_SOL_SOCKET => {
            let host_opt = match optname {
                LINUX_SO_DEBUG => libc::SO_DEBUG,
                LINUX_SO_REUSEADDR => libc::SO_REUSEADDR,
                LINUX_SO_TYPE => libc::SO_TYPE,
                LINUX_SO_ERROR => libc::SO_ERROR,
                LINUX_SO_DONTROUTE => libc::SO_DONTROUTE,
                LINUX_SO_BROADCAST => libc::SO_BROADCAST,
                LINUX_SO_SNDBUF => libc::SO_SNDBUF,
                LINUX_SO_RCVBUF => libc::SO_RCVBUF,
                LINUX_SO_KEEPALIVE => libc::SO_KEEPALIVE,
                LINUX_SO_OOBINLINE => libc::SO_OOBINLINE,
                LINUX_SO_LINGER => libc::SO_LINGER,
                LINUX_SO_REUSEPORT => libc::SO_REUSEPORT,
                LINUX_SO_RCVTIMEO => libc::SO_RCVTIMEO,
                LINUX_SO_SNDTIMEO => libc::SO_SNDTIMEO,
                LINUX_SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
                _ => return None,
            };
            Some((libc::SOL_SOCKET, host_opt))
        }
        LINUX_SOL_IP => Some((libc::IPPROTO_IP, optname)),
        LINUX_SOL_TCP => Some((libc::IPPROTO_TCP, optname)),
        LINUX_SOL_UDP => Some((libc::IPPROTO_UDP, optname)),
        LINUX_SOL_IPV6 => Some((libc::IPPROTO_IPV6, optname)),
        _ => None,
    }
}

/// Translate a Linux-formatted sockaddr (read from guest memory) into the
/// macOS BSD form. Returns the host-formatted bytes ready to hand to
/// libc::bind/connect/sendto.
fn read_linux_sockaddr(
    memory: &impl GuestMemory,
    addr: u64,
    addrlen: u32,
    _family_hint: i32,
) -> Result<Vec<u8>, i32> {
    if addr == 0 || addrlen < 2 {
        return Err(LINUX_EINVAL);
    }
    let len = addrlen as usize;
    let bytes = memory.read_bytes(addr, len).map_err(|_| LINUX_EFAULT)?;
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    match family {
        LINUX_AF_INET => {
            // sockaddr_in: family(2) port(2) addr(4) zero(8) = 16 bytes
            if len < 8 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 16];
            out[0] = 16; // sin_len
            out[1] = libc::AF_INET as u8; // sin_family
            out[2..4].copy_from_slice(&bytes[2..4]); // sin_port (network)
            out[4..8].copy_from_slice(&bytes[4..8]); // sin_addr
            Ok(out)
        }
        LINUX_AF_INET6 => {
            // sockaddr_in6: family(2) port(2) flowinfo(4) addr(16) scope(4) = 28
            if len < 24 {
                return Err(LINUX_EINVAL);
            }
            let mut out = vec![0u8; 28];
            out[0] = 28;
            out[1] = libc::AF_INET6 as u8;
            out[2..4].copy_from_slice(&bytes[2..4]); // port
            out[4..8].copy_from_slice(&bytes[4..8]); // flowinfo
            out[8..24].copy_from_slice(&bytes[8..24]); // addr
            if len >= 28 {
                out[24..28].copy_from_slice(&bytes[24..28]); // scope_id
            }
            Ok(out)
        }
        LINUX_AF_UNIX => {
            // sockaddr_un: family(2) path[108]
            if len < 2 {
                return Err(LINUX_EINVAL);
            }
            let path_len = len.saturating_sub(2);
            // macOS sockaddr_un is sun_len(1) sun_family(1) sun_path[104].
            let mut out = vec![0u8; 2 + path_len];
            out[0] = (2 + path_len).min(255) as u8;
            out[1] = libc::AF_UNIX as u8;
            out[2..].copy_from_slice(&bytes[2..2 + path_len]);
            Ok(out)
        }
        _ => Err(LINUX_EAFNOSUPPORT),
    }
}

/// Translate a macOS BSD sockaddr (as returned by accept/getsockname/...
/// into Linux-formatted bytes suitable for the guest to consume.
fn host_to_linux_sockaddr(bytes: &[u8], _family_hint: i32) -> Vec<u8> {
    if bytes.len() < 2 {
        return Vec::new();
    }
    // macOS layout: sa_len(1) sa_family(1) ...
    let host_family = bytes[1] as u16;
    let linux_family = host_to_linux_af(host_family);
    match host_family as i32 {
        libc::AF_INET => {
            // Linux sockaddr_in: family(2) port(2) addr(4) zero(8) = 16
            let mut out = vec![0u8; 16];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            if bytes.len() >= 8 {
                out[2..4].copy_from_slice(&bytes[2..4]); // port
                out[4..8].copy_from_slice(&bytes[4..8]); // addr
            }
            out
        }
        libc::AF_INET6 => {
            let mut out = vec![0u8; 28];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            let take = bytes.len().min(28);
            if take > 2 {
                out[2..take].copy_from_slice(&bytes[2..take]);
            }
            out
        }
        libc::AF_UNIX => {
            // Linux sockaddr_un is family(2) path[108]. macOS path starts
            // at offset 2; skip the host's sun_len byte at offset 0.
            let path_len = bytes.len().saturating_sub(2);
            let mut out = vec![0u8; 2 + path_len];
            out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            if path_len > 0 {
                out[2..].copy_from_slice(&bytes[2..2 + path_len]);
            }
            out
        }
        _ => {
            let mut out = bytes.to_vec();
            if out.len() >= 2 {
                out[0..2].copy_from_slice(&linux_family.to_ne_bytes());
            }
            out
        }
    }
}

/// Write a Linux-formatted sockaddr back into guest memory, respecting
/// the caller's `addrlen` (Linux truncates when the buffer is too small
/// and writes the full required length into `*addrlen_addr`).
fn write_linux_sockaddr(
    memory: &mut impl GuestMemory,
    addr: u64,
    addrlen_addr: u64,
    bytes: &[u8],
) -> Result<(), ()> {
    if addrlen_addr == 0 {
        return Err(());
    }
    let cur_bytes = memory.read_bytes(addrlen_addr, 4).map_err(|_| ())?;
    let cur = u32::from_ne_bytes([
        cur_bytes[0], cur_bytes[1], cur_bytes[2], cur_bytes[3],
    ]) as usize;
    let write_len = cur.min(bytes.len());
    if addr != 0 && write_len > 0 {
        memory.write_bytes(addr, &bytes[..write_len]).map_err(|_| ())?;
    }
    memory
        .write_bytes(addrlen_addr, &(bytes.len() as u32).to_ne_bytes())
        .map_err(|_| ())
}

#[derive(Debug, Clone, Copy)]
struct LinuxMsghdr {
    name: u64,
    namelen: u32,
    iov: u64,
    iovlen: u64,
}

fn read_linux_msghdr(memory: &impl GuestMemory, addr: u64) -> Result<LinuxMsghdr, i32> {
    if addr == 0 {
        return Err(LINUX_EFAULT);
    }
    // Linux msghdr (LP64): name(8) namelen(4) pad(4) iov(8) iovlen(8)
    //                      control(8) controllen(8) flags(4)
    let bytes = memory.read_bytes(addr, 56).map_err(|_| LINUX_EFAULT)?;
    let name = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let namelen = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    let iov = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
    let iovlen = u64::from_ne_bytes(bytes[24..32].try_into().unwrap());
    Ok(LinuxMsghdr { name, namelen, iov, iovlen })
}

pub const LINUX_EAFNOSUPPORT: i32 = 97;

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
    #[cfg(target_os = "macos")]
    crate::probes::host_pipe_io(host_fd, 0, n as i64);
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
    #[cfg(target_os = "macos")]
    crate::probes::host_pipe_io(host_fd, 1, n as i64);
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

#[cfg(test)]
mod overlay_dispatch_tests {
    //! End-to-end overlay tests that drive the public `dispatch` entry
    //! point. The fixture builds a tiny tar-backed RootFs holding one
    //! directory and one file, then exercises the syscall path the same
    //! way the runtime does (SyscallRequest + LinearMemory + compat
    //! reporter). The assertions are what `apt update` needs to keep
    //! working: writable mkdirat, openat O_CREAT + write + read,
    //! unlink-then-ENOENT, rename-moves-overlay-content.
    //!
    //! Keep these tests minimal — there's no need to exercise every
    //! flag combination here, just the four scenarios called out in the
    //! task spec.
    use super::*;
    use crate::compat::CompatReporter;
    use crate::rootfs::LayerSource;
    use tar::{Builder, EntryType, Header};
    const SYS_OPENAT: u64 = 56;
    const SYS_CLOSE: u64 = 57;
    const SYS_READ: u64 = 63;
    const SYS_WRITE: u64 = 64;
    const SYS_NEWFSTATAT: u64 = 79;
    const SYS_MKDIRAT: u64 = 34;
    const SYS_UNLINKAT: u64 = 35;
    const SYS_RENAMEAT: u64 = 38;
    const O_CREAT: u64 = 0o100;
    const O_WRONLY: u64 = 1;
    const O_RDONLY: u64 = 0;

    /// 16 KiB scratch buffer at virtual base 0x4000_0000. Tests pack
    /// pathnames + read/write buffers into this. The dispatcher itself
    /// only needs valid byte addresses for the syscalls under test —
    /// stat/statx writes a small fixed-size struct into the buffer.
    const MEM_BASE: u64 = 0x4000_0000;
    const MEM_LEN: usize = 16 * 1024;

    fn empty_rootfs() -> RootFs {
        // Bake a single layer containing /etc/motd and the directories
        // it lives under, so we can exercise both the rootfs-backed and
        // overlay-backed lookup paths.
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut builder = Builder::new(&mut buf);
            for dir in ["etc", "var", "var/lib", "var/lib/apt"] {
                let mut h = Header::new_gnu();
                h.set_path(format!("{}/", dir)).unwrap();
                h.set_entry_type(EntryType::Directory);
                h.set_size(0);
                h.set_mode(0o755);
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            }
            let body: &[u8] = b"hello, world\n";
            let mut h = Header::new_gnu();
            h.set_path("etc/motd").unwrap();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            builder.append(&h, body).unwrap();
            builder.finish().unwrap();
        }
        RootFs::from_layers(std::iter::once(LayerSource::Tar(buf))).unwrap()
    }

    struct Harness {
        dispatcher: SyscallDispatcher,
        memory: LinearMemory,
        reporter: CompatReporter,
        cursor: u64,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                dispatcher: SyscallDispatcher::with_rootfs(empty_rootfs()),
                memory: LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]),
                reporter: CompatReporter::default(),
                cursor: MEM_BASE + 4096, // leave the first page for stat bufs etc
            }
        }

        /// Copy `s` (NUL-terminated) into the guest scratch region and
        /// return its address.
        fn put_str(&mut self, s: &str) -> u64 {
            let addr = self.cursor;
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            self.memory.write_bytes(addr, &bytes).unwrap();
            self.cursor += bytes.len() as u64;
            // 8-byte align for the next allocation.
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn put_bytes(&mut self, b: &[u8]) -> u64 {
            let addr = self.cursor;
            self.memory.write_bytes(addr, b).unwrap();
            self.cursor += b.len() as u64;
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn reserve(&mut self, n: usize) -> u64 {
            let addr = self.cursor;
            self.cursor += n as u64;
            self.cursor = (self.cursor + 7) & !7;
            addr
        }

        fn call(&mut self, number: u64, args: [u64; 6]) -> DispatchOutcome {
            let request = SyscallRequest::new(number, SyscallArgs(args));
            self.dispatcher
                .dispatch(request, &mut self.memory, &mut self.reporter)
                .expect("dispatch must not surface a fatal error")
        }
    }

    fn returned(outcome: DispatchOutcome) -> i64 {
        match outcome {
            DispatchOutcome::Returned { value } => value,
            other => panic!("expected Returned, got {other:?}"),
        }
    }

    fn errno(outcome: DispatchOutcome) -> i32 {
        match outcome {
            DispatchOutcome::Errno { errno } => errno,
            other => panic!("expected Errno, got {other:?}"),
        }
    }

    const AT_FDCWD: u64 = (-100i64) as u64;

    #[test]
    fn mkdirat_creates_overlay_dir_and_fstatat_sees_it() {
        let mut h = Harness::new();
        let path = h.put_str("/var/lib/apt/lists");
        let outcome = h.call(SYS_MKDIRAT, [AT_FDCWD, path, 0o755, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // fstatat must succeed and report a directory. The Linux stat
        // layout puts st_mode at bytes 16..20; bit S_IFDIR=0o040000.
        let statbuf = h.reserve(160);
        let path2 = h.put_str("/var/lib/apt/lists");
        let outcome = h.call(SYS_NEWFSTATAT, [AT_FDCWD, path2, statbuf, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);
        let mode_bytes = h.memory.read_bytes(statbuf + 16, 4).unwrap();
        let mode = u32::from_le_bytes(mode_bytes.try_into().unwrap());
        assert_eq!(mode & 0o170000, 0o040000, "S_IFDIR not set in stat mode");
    }

    #[test]
    fn openat_o_creat_then_write_then_read_round_trips() {
        let mut h = Harness::new();
        // O_CREAT|O_WRONLY: writable, brand-new file inside an existing
        // rootfs directory.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(
            SYS_OPENAT,
            [AT_FDCWD, path, O_CREAT | O_WRONLY, 0o644, 0, 0],
        );
        let fd = returned(outcome) as u64;
        assert!(fd >= 3, "expected real fd, got {fd}");

        // Write four bytes.
        let payload = h.put_bytes(b"OKAY");
        let outcome = h.call(SYS_WRITE, [fd, payload, 4, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let outcome = h.call(SYS_CLOSE, [fd, 0, 0, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // Re-open O_RDONLY and read back.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        let fd = returned(outcome) as u64;
        let dest = h.reserve(16);
        let outcome = h.call(SYS_READ, [fd, dest, 16, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let bytes = h.memory.read_bytes(dest, 4).unwrap();
        assert_eq!(&bytes, b"OKAY");
    }

    #[test]
    fn unlinkat_on_rootfs_file_then_openat_returns_enoent() {
        let mut h = Harness::new();
        // /etc/motd lives in the rootfs.
        let path = h.put_str("/etc/motd");
        let outcome = h.call(SYS_UNLINKAT, [AT_FDCWD, path, 0, 0, 0, 0]);
        assert_eq!(returned(outcome), 0);

        let path = h.put_str("/etc/motd");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        assert_eq!(errno(outcome), LINUX_ENOENT);
    }

    #[test]
    fn renameat_moves_overlay_backed_file() {
        let mut h = Harness::new();
        // Create a file in the overlay first.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(
            SYS_OPENAT,
            [AT_FDCWD, path, O_CREAT | O_WRONLY, 0o644, 0, 0],
        );
        let fd = returned(outcome) as u64;
        let payload = h.put_bytes(b"DATA");
        let _ = h.call(SYS_WRITE, [fd, payload, 4, 0, 0, 0]);
        let _ = h.call(SYS_CLOSE, [fd, 0, 0, 0, 0, 0]);

        let from = h.put_str("/var/lib/apt/lock");
        let to = h.put_str("/var/lib/apt/lock.new");
        let outcome = h.call(SYS_RENAMEAT, [AT_FDCWD, from, AT_FDCWD, to, 0, 0]);
        assert_eq!(returned(outcome), 0);

        // Source must now ENOENT, destination must read back the data.
        let path = h.put_str("/var/lib/apt/lock");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        assert_eq!(errno(outcome), LINUX_ENOENT);

        let path = h.put_str("/var/lib/apt/lock.new");
        let outcome = h.call(SYS_OPENAT, [AT_FDCWD, path, O_RDONLY, 0, 0, 0]);
        let fd = returned(outcome) as u64;
        let dest = h.reserve(16);
        let outcome = h.call(SYS_READ, [fd, dest, 16, 0, 0, 0]);
        assert_eq!(returned(outcome), 4);
        let bytes = h.memory.read_bytes(dest, 4).unwrap();
        assert_eq!(&bytes, b"DATA");
    }

    /// Validates the systematic unknown-flag detector: when the guest
    /// passes a flag bit the dispatcher doesn't know about, the
    /// compat report must surface it as an `UnknownSyscallFlags`
    /// entry, regardless of whether the syscall ultimately returns
    /// success or EINVAL. The user explicitly asked for this loudness.
    #[test]
    fn unknown_pipe2_flag_is_recorded_in_compat_report() {
        let mut h = Harness::new();
        let buf = h.reserve(8);
        // Bit 0x80 (octal 0o200) is NOT one of O_CLOEXEC | O_NONBLOCK.
        // Send it through pipe2 — the handler returns EINVAL, and we
        // want the report to ALSO list the unknown bit so the operator
        // can fix it.
        const SYS_PIPE2: u64 = 59;
        let _ = h.call(SYS_PIPE2, [buf, 0x80, 0, 0, 0, 0]);

        // Finish the report and look for the entry.
        let report = std::mem::take(&mut h.reporter).finish();
        let entry = report
            .unknown_syscall_flags
            .iter()
            .find(|e| e.number == 59 && e.argument == 1)
            .expect("pipe2's unknown-flag bit 0x80 should appear in the report");
        assert!(entry.unknown_bits.contains("0x80"), "got {:?}", entry);
        assert_eq!(entry.count, 1);
        assert_eq!(entry.name, "pipe2");
    }

    /// Negative test: a syscall flag arg that has NO unknown bits set
    /// must NOT produce an UnknownSyscallFlags entry.
    #[test]
    fn known_pipe2_flag_is_silent() {
        let mut h = Harness::new();
        let buf = h.reserve(8);
        // O_CLOEXEC | O_NONBLOCK — both are in the supported mask.
        let _ = h.call(SYS_PIPE2, [buf, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0]);
        let report = std::mem::take(&mut h.reporter).finish();
        assert!(
            report.unknown_syscall_flags.is_empty(),
            "no unknown bits should be reported; got {:?}",
            report.unknown_syscall_flags
        );
    }

    const SYS_PIPE2: u64 = 59;

    /// Systematic errno translation tests. Verifies every code where
    /// macOS and Linux disagree maps correctly, plus that codes 1..=34
    /// pass through unchanged. Pins the contract so a future libc
    /// crate version that renumbers something fails CI rather than
    /// silently producing wrong errnos for guest binaries.
    #[cfg(target_os = "macos")]
    #[test]
    fn errno_translation_covers_every_divergent_code() {
        use crate::dispatch::{linux_errno, macos_to_linux_errno};
        // Overlap zone: 1..=34 must pass through.
        for code in 1..=34 {
            assert_eq!(
                macos_to_linux_errno(code),
                code,
                "code {} should be identity in overlap zone",
                code
            );
        }
        // The divergence cases that bit us — apt's connect saw macOS
        // EINPROGRESS=36 surface in the guest as ENAMETOOLONG=36.
        assert_eq!(macos_to_linux_errno(libc::EINPROGRESS), linux_errno::EINPROGRESS);
        assert_ne!(macos_to_linux_errno(libc::EINPROGRESS), 36, "EINPROGRESS != Linux ENAMETOOLONG");
        // Sample of network errnos that matter for apt's HTTP method.
        assert_eq!(macos_to_linux_errno(libc::EAGAIN), linux_errno::EAGAIN);
        assert_eq!(macos_to_linux_errno(libc::ECONNREFUSED), linux_errno::ECONNREFUSED);
        assert_eq!(macos_to_linux_errno(libc::EHOSTUNREACH), linux_errno::EHOSTUNREACH);
        assert_eq!(macos_to_linux_errno(libc::ETIMEDOUT), linux_errno::ETIMEDOUT);
        assert_eq!(macos_to_linux_errno(libc::ENOTCONN), linux_errno::ENOTCONN);
        assert_eq!(macos_to_linux_errno(libc::ECONNRESET), linux_errno::ECONNRESET);
        assert_eq!(macos_to_linux_errno(libc::EADDRINUSE), linux_errno::EADDRINUSE);
        assert_eq!(macos_to_linux_errno(libc::EAFNOSUPPORT), linux_errno::EAFNOSUPPORT);
        // Filesystem errnos that diverge.
        assert_eq!(macos_to_linux_errno(libc::ENAMETOOLONG), linux_errno::ENAMETOOLONG);
        assert_eq!(macos_to_linux_errno(libc::ENOTEMPTY), linux_errno::ENOTEMPTY);
        assert_eq!(macos_to_linux_errno(libc::ELOOP), linux_errno::ELOOP);
        assert_eq!(macos_to_linux_errno(libc::ENOSYS), linux_errno::ENOSYS);
        assert_eq!(macos_to_linux_errno(libc::ENOLCK), linux_errno::ENOLCK);
        // Misc.
        assert_eq!(macos_to_linux_errno(libc::EIDRM), linux_errno::EIDRM);
        assert_eq!(macos_to_linux_errno(libc::EILSEQ), linux_errno::EILSEQ);
        assert_eq!(macos_to_linux_errno(libc::ECANCELED), linux_errno::ECANCELED);
    }

    /// The Linux errno constants we publish must match the
    /// asm-generic kernel headers. Pinned values from
    /// linux/include/uapi/asm-generic/errno{,-base}.h.
    #[test]
    fn linux_errno_constants_match_kernel_uapi() {
        use crate::dispatch::linux_errno::*;
        assert_eq!(EPERM, 1);
        assert_eq!(ENOENT, 2);
        assert_eq!(EAGAIN, 11);
        assert_eq!(ENOMEM, 12);
        assert_eq!(EFAULT, 14);
        assert_eq!(EINVAL, 22);
        assert_eq!(ESPIPE, 29);
        assert_eq!(EDEADLK, 35);
        assert_eq!(ENAMETOOLONG, 36);
        assert_eq!(ENOSYS, 38);
        assert_eq!(EINPROGRESS, 115);
        assert_eq!(ETIMEDOUT, 110);
        assert_eq!(ECONNREFUSED, 111);
    }
}
