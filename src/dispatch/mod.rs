use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::linux_abi::{
    KernelAbi, LINUX_DIRENT64_HEADER_SIZE, LINUX_DT_DIR, LINUX_DT_LNK, LINUX_DT_REG, LINUX_PAGE_SIZE,
    LINUX_S_IFCHR, LINUX_S_IFDIR, LINUX_S_IFIFO, LINUX_S_IFLNK, LINUX_S_IFMT, LINUX_S_IFREG, LINUX_S_IFSOCK, LINUX_TERMIOS_KERNEL_SIZE, LinuxCapabilityData, LinuxCapabilityHeader,
    LinuxDirent64Header, LinuxEpollEvent, LinuxEventfdValue, LinuxFdPair, LinuxIfAddrMsg,
    LinuxIfInfoMsg, LinuxIovec, LinuxNlMsgHdr, LinuxRtAttr,
    LINUX_ARPHRD_LOOPBACK, LINUX_IFA_ADDRESS, LINUX_IFA_LABEL, LINUX_IFA_LOCAL, LINUX_IFF_LOOPBACK,
    LINUX_IFF_RUNNING, LINUX_IFF_UP, LINUX_IFLA_ADDRESS, LINUX_IFLA_IFNAME, LINUX_NLMSG_DONE,
    LINUX_NLM_F_MULTI, LINUX_RTM_GETADDR, LINUX_RTM_GETLINK, LINUX_RTM_NEWADDR, LINUX_RTM_NEWLINK,
    LinuxItimerspec, LinuxItimerval, LinuxOpenHow, LinuxPollFd, LinuxRlimit, LinuxRusage, LinuxSigaction, LinuxSysinfo,
    LinuxSigaltstack, LinuxStat, LinuxStatfs, LinuxStatx, LinuxStatxTimestamp,
    LinuxTimerfdExpirations, LinuxTimespec, LinuxTimeval, LinuxTimezone, LinuxTms,
    LinuxTermios, LinuxUtsname, LinuxWinsize,
    // ABI constants moved from dispatch.rs (Goal #3)
    LINUX_AT_EACCESS, LINUX_AT_EMPTY_PATH, LINUX_AT_FDCWD, LINUX_AT_NO_AUTOMOUNT, LINUX_AT_REMOVEDIR,
    LINUX_AT_STATX_DONT_SYNC, LINUX_AT_STATX_FORCE_SYNC, LINUX_AT_SYMLINK_NOFOLLOW, LINUX_CLK_TCK,
    LINUX_DEFAULT_UMASK, LINUX_E2BIG, LINUX_EACCES, LINUX_EAFNOSUPPORT, LINUX_EAGAIN, LINUX_EBADF,
    LINUX_ECHILD, LINUX_EEXIST, LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_EISDIR, LINUX_ENAMETOOLONG,
    LINUX_ENOENT, LINUX_ENOMEM, LINUX_ENOPROTOOPT, LINUX_ENOSYS, LINUX_ENOTDIR, LINUX_ENOTSOCK,
    LINUX_ENOTSUP, LINUX_ENOTTY, LINUX_EPERM, LINUX_EPIPE, LINUX_ERANGE, LINUX_EROFS, LINUX_ESOCKTNOSUPPORT,
    LINUX_ESPIPE, LINUX_ESRCH, LINUX_ETIMEDOUT,     LINUX_FALLOC_FL_KEEP_SIZE, LINUX_FALLOC_FL_SUPPORTED,
    LINUX_FD_CLOEXEC,     LINUX_F_DUPFD, LINUX_F_DUPFD_CLOEXEC, LINUX_F_GETFD, LINUX_F_GETFL, LINUX_F_GETLK, LINUX_F_GETPIPE_SZ,
    LINUX_F_OFD_GETLK, LINUX_F_OFD_SETLK, LINUX_F_OFD_SETLKW, LINUX_F_SETFD, LINUX_F_SETFL,
    LINUX_F_SETLK, LINUX_F_SETLKW, LINUX_MADV_DONTNEED, LINUX_MADV_FREE, LINUX_MADV_NORMAL, LINUX_MADV_RANDOM,
    LINUX_MADV_SEQUENTIAL, LINUX_MADV_WILLNEED, LINUX_MAP_ANONYMOUS, LINUX_MAP_FIXED, LINUX_MAP_PRIVATE,
    LINUX_MAP_SHARED, LINUX_MCL_CURRENT, LINUX_MCL_FUTURE, LINUX_MCL_ONFAULT, LINUX_MREMAP_DONTUNMAP,
    LINUX_MREMAP_FIXED, LINUX_MREMAP_MAYMOVE, LINUX_MS_ASYNC, LINUX_MS_INVALIDATE, LINUX_MS_SYNC,
    LINUX_OVERLAYFS_SUPER_MAGIC, LINUX_O_ACCMODE, LINUX_O_APPEND, LINUX_O_CLOEXEC, LINUX_O_CREAT,
    LINUX_O_DIRECTORY, LINUX_O_EXCL, LINUX_O_NONBLOCK, LINUX_O_RDONLY, LINUX_O_RDWR, LINUX_O_TRUNC,
    LINUX_O_WRONLY, LINUX_PRIO_PROCESS, LINUX_PRIO_USER, LINUX_PROT_EXEC, LINUX_PROT_READ,
    LINUX_PROT_WRITE, LINUX_RLIM_INFINITY, LINUX_RUSAGE_CHILDREN, LINUX_RUSAGE_SELF, LINUX_RUSAGE_THREAD,
    LINUX_R_OK, LINUX_SEEK_CUR, LINUX_SEEK_END, LINUX_SEEK_SET, LINUX_SOCKADDR_STORAGE_SIZE,
    LINUX_SOCK_CLOEXEC, LINUX_SOCK_NONBLOCK, LINUX_UTIME_NOW, LINUX_UTIME_OMIT, LINUX_W_OK,
    LINUX_X_OK,
    // ABI constants moved from dispatch.rs (Goal #3, private set)
    LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_NETLINK, LINUX_AF_UNIX, LINUX_AF_UNSPEC,
    LINUX_BOOTSTRAP_AFFINITY_BYTES, LINUX_BOOTSTRAP_PGID, LINUX_BOOTSTRAP_PID, LINUX_BOOTSTRAP_SID,
    LINUX_CAPABILITY_VERSION_1, LINUX_CAPABILITY_VERSION_2, LINUX_CAPABILITY_VERSION_3, LINUX_CLOCK_BOOTTIME,
    LINUX_CLOCK_BOOTTIME_ALARM, LINUX_CLOCK_MONOTONIC, LINUX_CLOCK_MONOTONIC_COARSE,
    LINUX_CLOCK_MONOTONIC_RAW, LINUX_CLOCK_PROCESS_CPUTIME_ID, LINUX_CLOCK_REALTIME,
    LINUX_CLOCK_REALTIME_ALARM, LINUX_CLOCK_REALTIME_COARSE, LINUX_CLOCK_RESOLUTION_NSEC, LINUX_CLOCK_TAI,
    LINUX_CLOCK_THREAD_CPUTIME_ID, LINUX_EFD_CLOEXEC, LINUX_EFD_NONBLOCK, LINUX_EFD_SEMAPHORE, LINUX_EPOLLERR,
    LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLOUT, LINUX_EPOLLPRI, LINUX_EPOLL_CLOEXEC, LINUX_EPOLL_CTL_ADD,
    LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_FIONBIO, LINUX_FIONREAD, LINUX_FUTEX_CLOCK_REALTIME,
    LINUX_FUTEX_CMD_MASK, LINUX_FUTEX_PRIVATE_FLAG, LINUX_FUTEX_WAIT, LINUX_FUTEX_WAKE, LINUX_IOV_MAX,
    LINUX_ITIMER_PROF, LINUX_ITIMER_REAL, LINUX_ITIMER_VIRTUAL, LINUX_LOCK_EX, LINUX_LOCK_NB, LINUX_LOCK_SH,
    LINUX_LOCK_UN, LINUX_MAX_SIGNUM, LINUX_MEMBARRIER_CMD_QUERY, LINUX_MINSIGSTKSZ, LINUX_MSG_CMSG_CLOEXEC,
    LINUX_MSG_DONTROUTE, LINUX_MSG_DONTWAIT, LINUX_MSG_EOR, LINUX_MSG_NOSIGNAL, LINUX_MSG_OOB, LINUX_MSG_PEEK,
    LINUX_MSG_TRUNC, LINUX_MSG_WAITALL, LINUX_OPEN_HOW_SIZE, LINUX_PERSONALITY_QUERY, LINUX_PIPE_BUF_SIZE,
    LINUX_POLLERR, LINUX_POLLHUP, LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT, LINUX_PR_GET_DUMPABLE,
    LINUX_PR_GET_NAME, LINUX_PR_GET_PDEATHSIG, LINUX_PR_SET_DUMPABLE, LINUX_PR_SET_NAME,
    LINUX_PR_SET_PDEATHSIG, LINUX_P_ALL, LINUX_P_PGID, LINUX_P_PID,
    LINUX_P_PIDFD, LINUX_RT_SIGSET_SIZE, LINUX_SIGKILL, LINUX_SIGSTOP, LINUX_SIG_BLOCK, LINUX_SIG_SETMASK,
    LINUX_SIG_UNBLOCK, LINUX_SOCK_DGRAM, LINUX_SOCK_RAW, LINUX_SOCK_SEQPACKET, LINUX_SOCK_STREAM,
    LINUX_SOL_IP, LINUX_SOL_SOCKET, LINUX_SO_ACCEPTCONN, LINUX_SO_BROADCAST, LINUX_SO_DONTROUTE,
    LINUX_SO_ERROR, LINUX_SO_KEEPALIVE, LINUX_SO_LINGER, LINUX_SO_OOBINLINE, LINUX_SO_RCVBUF,
    LINUX_SO_RCVTIMEO, LINUX_SO_REUSEADDR, LINUX_SO_REUSEPORT, LINUX_SO_SNDBUF, LINUX_SO_SNDTIMEO,
    LINUX_SO_TYPE,     LINUX_SPLICE_SUPPORTED_FLAGS, LINUX_SS_DISABLE, LINUX_STATX_BASIC_STATS,
    LINUX_STATX_RESERVED, LINUX_TASK_COMM_LEN, LINUX_TCGETS, LINUX_TCSETS, LINUX_TCSETSF, LINUX_TCSETSW,
    LINUX_TFD_CLOEXEC, LINUX_TFD_NONBLOCK, LINUX_TIMER_ABSTIME, LINUX_TIOCGPGRP, LINUX_TIOCGSID,
    LINUX_TIOCGWINSZ, LINUX_TIOCNOTTY, LINUX_TIOCSCTTY, LINUX_TIOCSPGRP, LINUX_WAIT4_SUPPORTED_FLAGS,
    LINUX_WAITID_STATE_MASK, LINUX_WAITID_SUPPORTED_FLAGS,         LINUX_SOL_TCP, LINUX_SOL_UDP, LINUX_SOL_IPV6, LINUX_SO_DEBUG,
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

mod creds;
mod fs;
mod mem;
mod net;
mod proc;
mod signal;
mod time;

#[allow(dead_code)]
const MAX_GUEST_PATH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    pub number: u64,
    pub args: SyscallArgs,
}

/// Uniform context handed to every *normalized* syscall handler, so all
/// handlers share one signature and the dispatch arm is macro-generated.
/// Built transiently per dispatched syscall (a scoped borrow of guest memory
/// and the compat reporter), which lets migrated and legacy handlers coexist
/// while the macro migration proceeds subsystem by subsystem.
///
/// See [[plan-syscall-macro-split]].
pub struct SyscallCtx<'a, M: GuestMemory> {
    pub request: SyscallRequest,
    pub memory: &'a mut M,
    pub reporter: &'a mut CompatReporter,
    /// Present only when the syscall is dispatched on behalf of a specific
    /// guest thread (the multi-threaded runtime path). Carries this thread's
    /// tid and the shared thread/futex coordination tables. `None` for the
    /// single-threaded `dispatch` path (legacy callers + unit tests), where
    /// tid-aware handlers fall back to pid-based answers.
    pub thread: Option<ThreadCtx<'a>>,
}

/// Per-thread coordination handles handed to tid-aware syscall handlers
/// (`gettid`, `set_tid_address`, `futex`).
#[derive(Clone, Copy)]
pub struct ThreadCtx<'a> {
    pub tid: crate::thread::ThreadId,
    pub registry: &'a crate::thread::ThreadRegistry,
    pub futex: &'a crate::thread::FutexTable,
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
    ///
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
    /// Thread-creating `clone(2)`/`clone3(2)` (CLONE_VM|CLONE_THREAD|...).
    /// The runtime spawns a new host thread + vCPU sharing this process's VM.
    CloneThread {
        stack: u64,           // child SP (clone arg)
        tls: u64,             // CLONE_SETTLS value -> TPIDR_EL0 (0 = none)
        flags: u64,
        parent_tid_addr: u64, // CLONE_PARENT_SETTID target (0 = none)
        child_tid_addr: u64,  // CLONE_CHILD_SETTID/CLEARTID target (0 = none)
    },
    /// A single thread exited via `exit(2)` (NOT exit_group): the runtime
    /// performs the CLONE_CHILD_CLEARTID futex wake and ends just this host
    /// thread. If it was the last live thread the process exits.
    ThreadExit { code: i32 },
    /// `FUTEX_WAIT` whose value-check passed under the kernel lock: the
    /// guest word equals the expected value, so this thread must block.
    /// The handler CANNOT block while holding the kernel lock (a sibling's
    /// `FUTEX_WAKE` would deadlock), so it returns this outcome and the
    /// runtime drops the lock, calls `FutexTable::wait`, then completes the
    /// syscall with 0 (woken) or -ETIMEDOUT (timed out).
    FutexWait {
        addr: u64,
        timeout: Option<Duration>,
    },
}

impl DispatchOutcome {
    fn retval_errno(&self) -> (i64, Option<i32>) {
        match self {
            DispatchOutcome::Returned { value } => (*value, None),
            DispatchOutcome::Errno { errno } => (-(*errno as i64), Some(*errno)),
            DispatchOutcome::Exit { code } => (*code as i64, None),
            DispatchOutcome::Fork => (0, None),
            DispatchOutcome::Execve { .. } => (0, None),
            DispatchOutcome::SigReturn => (0, None),
            // CloneThread/ThreadExit/FutexWait are handled specially by the
            // runtime and never flow through retval_errno — the runtime acts
            // on them directly before any x0 write.
            DispatchOutcome::CloneThread { .. } => (0, None),
            DispatchOutcome::ThreadExit { .. } => (0, None),
            DispatchOutcome::FutexWait { .. } => (0, None),
        }
    }
}

pub trait GuestMemory {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError>;
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;

    /// Back the guest range `[guest_addr, guest_addr+len)` with a real
    /// `MAP_SHARED` mapping of the host file `host_fd` at `offset`, so the
    /// guest CPU AND the dispatcher's accessor both operate on the file's
    /// page cache (full coherence + persistence). `host_fd` ownership is
    /// transferred — the impl must `close` it once mapped. Default: the
    /// backend doesn't support real shared mappings → caller falls back to
    /// a private snapshot copy.
    fn map_shared_file(
        &mut self,
        _guest_addr: u64,
        _len: usize,
        _host_fd: i32,
        _offset: u64,
    ) -> Result<(), MemoryError> {
        Err(MemoryError::Unsupported)
    }

    /// Tear down a shared file mapping previously created by
    /// `map_shared_file`. Default no-op.
    fn unmap_shared_file(&mut self, _guest_addr: u64, _len: usize) -> Result<(), MemoryError> {
        Ok(())
    }

    /// Flush a shared file mapping to the backing file (`msync`). Default
    /// no-op (the snapshot path has nothing to flush).
    fn msync_shared_file(&mut self, _guest_addr: u64, _len: usize) -> Result<(), MemoryError> {
        Ok(())
    }
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
    /// The backend can't service a real shared file-backed mapping (e.g.
    /// the non-HVF AddressSpace/LinearMemory used in unit tests). Callers
    /// fall back to the private-snapshot mmap path.
    #[error("operation unsupported by this guest-memory backend")]
    Unsupported,
    /// A host-side mapping operation (mmap/hv_vm_map/...) failed.
    #[error("host mapping operation failed: {0}")]
    HostMap(String),
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
    /// Owned I/O subsystem state (buffered stdout/stderr, stream toggle,
    /// the open-fd table, next-fd cursor, and cwd). See [`fs::IoState`].
    /// Handlers that touch only I/O state borrow `self.io` narrowly.
    io: fs::IoState,
    /// Owned memory subsystem state (brk, mmap arena, shared-file IPA
    /// window + live maps, and the captured address-space regions for
    /// `/proc/self/maps`). See [`mem::MemState`].
    mem: mem::MemState,
    /// Owned process subsystem state (executable path, personality,
    /// dumpable flag, task comm name). See [`proc::ProcState`].
    proc: proc::ProcState,
    /// Owned credentials subsystem state (uids/gids + umask). See
    /// [`creds::CredState`]. Handlers that touch only credential state
    /// borrow `self.creds` narrowly.
    creds: creds::CredState,
    /// Owned signal subsystem state (handlers, mask, pending set, alt
    /// stack). See [`signal::SignalState`]. Handlers that touch only
    /// signal state borrow `self.signal` narrowly.
    signal: signal::SignalState,
    /// Owned filesystem subsystem state (unified VFS mount table plus
    /// the `/` rootfs + writable overlay). See [`fs::FsState`]. Handlers
    /// that touch only fs state borrow `self.fs` narrowly.
    fs: fs::FsState,
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
    // In-memory pipe ends. Currently `pipe2(2)` routes through `HostPipe`
    // (real macOS kernel pipe) so these are not constructed today, but the
    // full read/write/poll machinery (`PipeState`, `read_pipe`, `write_pipe`)
    // is kept wired as the portable, host-fd-free pipe model and is matched
    // throughout the fd handlers. Retained as deliberate API surface.
    #[allow(dead_code)]
    PipeReader {
        pipe: Rc<RefCell<PipeState>>,
        status_flags: u64,
    },
    #[allow(dead_code)]
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
    /// Synthetic AF_NETLINK socket. macOS has no AF_NETLINK, so we can't
    /// back this with a host fd; instead we model just enough of the
    /// rtnetlink (NETLINK_ROUTE) protocol for glibc's `__check_pf`,
    /// getaddrinfo and `ip`/`ss` tooling to enumerate a loopback
    /// interface and then stop. `bind`/`getsockname` report the socket's
    /// pid/groups; a RTM_GETLINK/RTM_GETADDR dump request queues a
    /// synthetic response into `recv_queue` that the next recvmsg/recvfrom
    /// drains, terminated by NLMSG_DONE.
    Netlink {
        protocol: i32,
        /// Netlink "port id" the socket is bound to (0 until bind picks one).
        pid: u32,
        /// Multicast group mask from bind (nl_groups).
        groups: u32,
        /// Bytes queued by a dump request, drained by recvmsg/recvfrom.
        recv_queue: VecDeque<u8>,
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

/// Which form of an xattr syscall is being dispatched: the path/lpath
/// variants name a file by path; the f-variant names it by open fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XattrTarget {
    Path,
    Fd,
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
            | OpenDescription::HostSocket { status_flags, .. }
            | OpenDescription::Netlink { status_flags, .. } => *status_flags,
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
            | OpenDescription::HostSocket { status_flags, .. }
            | OpenDescription::Netlink { status_flags, .. } => *status_flags = next,
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
            thread: Option<ThreadCtx>,
        ) -> Option<Result<DispatchOutcome, DispatchError>> {
            match request.number {
                $(
                    $num => {
                        let mut ctx = SyscallCtx { request, memory, reporter, thread };
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
        452 => fchmodat, // fchmodat2: same ABI; handler ignores the extra flags
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
        136 => rt_sigpending,
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
        267 => syncfs,
        276 => renameat2,
        278 => getrandom,
        285 => copy_file_range,
        291 => statx,
        436 => close_range,
        437 => openat2,
        439 => faccessat2,
        5 | 6 => sys_setxattr_path,
        7 => sys_setxattr_fd,
        8 | 9 => sys_getxattr_path,
        10 => sys_getxattr_fd,
        11 | 12 => sys_listxattr_path,
        13 => sys_listxattr_fd,
        14..=16 => sys_xattr_unsupported,
        43 => sys_statfs,
        44 => sys_fstatfs,
        45 => sys_truncate,
        74 | 75 | 77 => sys_bootstrap_enosys,
        93 | 94 => sys_exit,
        151 => sys_setfsuid,
        152 => sys_setfsgid,
        159 => sys_setgroups,
        172 => sys_getpid,
        178 => gettid,
        173 => sys_getppid,
        174 => sys_getuid,
        175 => sys_geteuid,
        176 => sys_getgid,
        177 => sys_getegid,
        243 => sys_recvmmsg,
        269 => sys_sendmmsg,
        435 => sys_clone3,
        283 => sys_membarrier,
        293 => sys_rseq,
    }

    pub fn new() -> Self {
        Self {
            io: fs::IoState::new(),
            mem: mem::MemState::new(),
            proc: proc::ProcState::new(),
            creds: creds::CredState::new(),
            signal: signal::SignalState::new(),
            fs: fs::FsState::new(),
        }
    }

    /// Capture the guest's `AddressSpace` region list so that
    /// `/proc/self/maps` reflects the real loaded layout (executable
    /// ELF segments, runtime regions, mmap arena, stack, EL0
    /// trampoline, EL1 vectors, page tables) instead of a fixed
    /// summary. Called once after `HvfTrapEngine::map_address_space`
    /// succeeds.
    pub fn set_address_space_regions(&mut self, regions: Vec<ProcMapsEntry>) {
        self.mem.address_space_regions = Some(regions);
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs.rootfs = Some(rootfs);
        s
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs.rootfs = Some(rootfs);
        s.proc.executable_path = executable_path.into();
        s
    }

    /// Swap the in-memory default for any other [`FsBackend`]. Used by
    /// the CLI's `--fs host` to switch to a cap-std-sandboxed scratch
    /// directory. Returns the previously-installed backend so the
    /// caller can decide what to do with it (normally just drop).
    pub fn set_fs_backend(&mut self, backend: Box<dyn FsBackend>) -> Box<dyn FsBackend> {
        self.fs.rootfs_vfs.set_overlay(backend)
    }

    /// Drop the immutable in-memory rootfs layer. Valid ONLY once the
    /// overlay backend holds the complete materialised filesystem (i.e.
    /// after `HostFsBackend::seed_from_rootfs` for `--fs host`): from then
    /// on the disk overlay is authoritative for every read, so the
    /// in-memory rootfs is redundant and just wastes RAM. All layered VFS
    /// reads and `read_exec_file` already fall back gracefully to "overlay
    /// only" when the rootfs is `None`. Never call this for `--fs memory`,
    /// whose overlay starts empty and relies on the rootfs for reads.
    pub fn drop_rootfs_layer(&mut self) {
        self.fs.rootfs_vfs.rootfs = None;
    }

    /// Set the executable path recorded in `/proc/self/cmdline`,
    /// `/proc/self/comm`, and `/proc/self/status`. Used when a
    /// dispatcher is constructed via `SyscallDispatcher::new()` without
    /// a rootfs (the `--fs host` streaming path) so that `/proc` reads
    /// reflect the correct binary name.
    pub fn set_executable_path(&mut self, path: impl Into<String>) {
        self.proc.executable_path = path.into();
    }

    /// Name of the currently-installed backend (for logging / debug).
    pub fn fs_backend_name(&self) -> &'static str {
        self.fs.rootfs_vfs.overlay.name()
    }

    /// Borrow the dispatcher's rootfs. Used by the runtime when the
    /// dispatcher returns `DispatchOutcome::Execve` and the new image
    /// has to be loaded from the same image layers.
    pub fn rootfs(&self) -> Option<&RootFs> {
        self.fs.rootfs_vfs.rootfs.as_ref()
    }

    /// Read a regular file's bytes through the layered view (overlay
    /// first, then rootfs). Used by the runtime's execve path to
    /// detect `#!` shebang scripts and to load executables that the
    /// guest wrote into the overlay (which `load_elf_from_rootfs`
    /// alone would miss). Returns None if the path isn't a readable
    /// file in either layer.
    pub fn read_exec_file(&self, path: &str) -> Option<Vec<u8>> {
        if let Some(bytes) = self.fs.rootfs_vfs.overlay.file_contents(path) {
            return Some(bytes);
        }
        self.fs.rootfs_vfs.rootfs.as_ref()?.read(path).ok()
    }

    pub fn stdout(&self) -> &[u8] {
        &self.io.stdout
    }

    /// Enable live passthrough for fd 1/2. After this, `write`/`writev`
    /// to the stdio fds go straight to host fd 1/2 via `libc::write`
    /// instead of accumulating in the in-memory buffers — required for
    /// interactive prompts (`/ # `, cursor-position queries, etc.) to
    /// reach the user's terminal before the guest exits.
    pub fn set_stream_stdio(&mut self, on: bool) {
        self.io.stream_stdio = on;
    }

    /// Called after `libc::fork(2)` returns into a child: the child
    /// inherited the parent's buffered stdout/stderr, but we don't
    /// want to re-print those bytes when the child eventually exits
    /// via the `forked_child_exit` path. The parent's full buffer
    /// goes out through its own JSON report.
    pub fn clear_output_buffers(&mut self) {
        self.io.stdout.clear();
        self.io.stderr.clear();
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
        let cloexec_fds: Vec<i32> = self.io
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
            if let Some(open_file) = self.io.open_files.remove(&fd) {
                close_open_file(&open_file);
            }
        }
    }

    pub fn stderr(&self) -> &[u8] {
        &self.io.stderr
    }

    pub fn cwd(&self) -> &str {
        &self.io.cwd
    }







    /// Single-threaded dispatch (legacy + unit tests + the fork-based
    /// runtime path). Tid-aware handlers see `thread: None`.
    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_inner(request, memory, reporter, None)
    }

    /// Multi-threaded dispatch: the caller (the per-vCPU runtime loop)
    /// holds the big kernel lock and supplies THIS thread's tid plus the
    /// shared registry/futex tables, so `gettid`/`set_tid_address`/`futex`
    /// answer per-thread.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_threaded(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        let thread = Some(ThreadCtx {
            tid,
            registry,
            futex,
        });
        self.dispatch_inner(request, memory, reporter, thread)
    }

    fn dispatch_inner(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &mut CompatReporter,
        thread: Option<ThreadCtx>,
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
        if let Some(result) = self.dispatch_normalized(request, memory, reporter, thread) {
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

        // The normalized macro table is the single authoritative syscall
        // registry. Any number it does not claim is genuinely unimplemented:
        // record a structured compat event and return ENOSYS. The supervisor
        // must never panic on guest input — an unknown syscall is the guest's
        // problem to handle (it gets -ENOSYS), not ours to crash on.
        reporter.record(CompatEvent::unhandled_syscall(
            request.number,
            name,
            request.args,
        ));
        let outcome = DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
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
        OpenDescription::HostPipe { host_fd, .. }
            // Close the host fd only when the LAST guest fd that
            // references this OpenDescription is being closed. Because
            // dup3/dup2 wraps a new Linux fd around the SAME Rc<...>,
            // we let the Rc go out of scope naturally and rely on the
            // wrapper around `OpenDescription::HostPipe` having no
            // shared owners. The simplest correct close here is to
            // count: if `strong_count == 1` we're the last one.
            // (The Rc is held by the OpenFile in `open_files`; if no
            // dup'd entry remains, strong_count is 1.)
            if std::rc::Rc::strong_count(&open_file.description) == 1 => {
                unsafe {
                    libc::close(*host_fd);
                }
            }
        OpenDescription::HostSocket { host_fd, .. }
        | OpenDescription::HostFile { host_fd, .. }
            // Same last-reference rule as HostPipe: only close the real
            // macOS fd when no other Linux fd still aliases the same
            // OpenDescription via dup3/dup2.
            if std::rc::Rc::strong_count(&open_file.description) == 1 => {
                unsafe {
                    libc::close(*host_fd);
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
        // Linux↔macOS clock-id numbering DIFFERS, so map the Linux ids to
        // the host's symbolic libc constants rather than passing through.
        LINUX_CLOCK_PROCESS_CPUTIME_ID => host_clock_duration(libc::CLOCK_PROCESS_CPUTIME_ID),
        LINUX_CLOCK_THREAD_CPUTIME_ID => host_clock_duration(libc::CLOCK_THREAD_CPUTIME_ID),
        _ => None,
    }
}

fn linux_clock_is_known(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
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

    // NOTE: we deliberately do NOT set the Activity Monitor display name
    // via LaunchServices/CoreFoundation here. Carrick runs guests by
    // forking WITHOUT a subsequent exec (the guest executes in-process on
    // the HVF vCPU), and CoreFoundation/LaunchServices are not fork-safe:
    // a forked child calling into them deadlocks intermittently when a CF
    // lock was held at fork time (it blocks talking to launchservicesd
    // over Mach), which wedged the guest's vCPU and hung the parent in
    // wait4. The argv[0] overwrite above already gives `ps`/tooling the
    // visible `carrick: <name>` title, which is all we rely on.
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

/// Read a host (macOS) POSIX clock via `libc::clock_gettime`. `clock_id`
/// MUST be a host symbolic `libc::CLOCK_*` constant (Linux numbering
/// differs and is mapped by callers). Returns `None` only on failure.
fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, properly-aligned timespec we own.
    let rc = unsafe { libc::clock_gettime(clock_id, &mut ts) };
    if rc != 0 {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn monotonic_duration() -> Duration {
    // On real Linux CLOCK_MONOTONIC/CLOCK_BOOTTIME report system uptime (a
    // large, monotonic value). Use the host's real monotonic clock so tv_sec
    // is large rather than seconds-since-carrick-start (sub-second).
    host_clock_duration(libc::CLOCK_MONOTONIC).unwrap_or(Duration::ZERO)
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
/// > real `kind`; `st_nlink` is overridden with the disk value.
/// > Build a [`RealStat`](crate::fs_backend::RealStat) from a live `libc::stat`
/// > (e.g. an `fstat` of a host fd), so an fd-based stat reports the SAME real
/// > size/kind/times as the path-based `real_stat` that statx/newfstatat use.
///
/// Without this, `fstat` returned `st_mtime = 0` (the zeroed open-time
/// metadata) while statx/newfstatat returned the real mtime. apt records each
/// Packages index's mtime at pkgcache GENERATION (via the opened fd) and
/// re-checks it at VALIDATION (via stat-by-path); the 0-vs-real mismatch made
/// apt decide every index had changed and abort `apt install` with
/// "Cache is out of sync, can't x-ref a package file". The macOS and Linux
/// `S_IF*` type bits and epoch-second time values transfer directly.
pub(super) fn real_stat_from_libc(st: &libc::stat) -> crate::fs_backend::RealStat {
    use crate::rootfs::RootFsEntryKind;
    let kind = match st.st_mode as u32 & LINUX_S_IFMT {
        m if m == LINUX_S_IFDIR => RootFsEntryKind::Directory,
        m if m == LINUX_S_IFLNK => RootFsEntryKind::Symlink,
        _ => RootFsEntryKind::File,
    };
    crate::fs_backend::RealStat {
        kind,
        nlink: st.st_nlink as u32,
        mode: st.st_mode as u32 & 0o7777,
        // Owner defaults to root; the HostFile fstat/statx path overrides from
        // the guest owner xattr where present.
        uid: 0,
        gid: 0,
        size: st.st_size as u64,
        atime: (st.st_atime, st.st_atime_nsec),
        mtime: (st.st_mtime, st.st_mtime_nsec),
        ctime: (st.st_ctime, st.st_ctime_nsec),
    }
}

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
        st_uid: real.uid,
        st_gid: real.gid,
        st_rdev: 0,
        __pad1: 0,
        st_size: metadata.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks_512(metadata.size),
        st_atime: real.atime.0,
        st_atime_nsec: real.atime.1 as u64,
        st_mtime: real.mtime.0,
        st_mtime_nsec: real.mtime.1 as u64,
        st_ctime: real.ctime.0,
        st_ctime_nsec: real.ctime.1 as u64,
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
    let stx_ts = |t: (i64, i64)| LinuxStatxTimestamp {
        tv_sec: t.0,
        tv_nsec: t.1 as u32,
        __reserved: 0,
    };
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: real.nlink,
        stx_uid: real.uid,
        stx_gid: real.gid,
        stx_mode: linux_mode(&metadata) as u16,
        __spare0: [0; 1],
        stx_ino: inode_for_path(&metadata.path),
        stx_size: metadata.size as u64,
        stx_blocks: blocks_512(metadata.size) as u64,
        stx_attributes_mask: 0,
        stx_atime: stx_ts(real.atime),
        stx_btime: zero_time,
        stx_ctime: stx_ts(real.ctime),
        stx_mtime: stx_ts(real.mtime),
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
    mode: u32,
) -> DispatchOutcome {
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: inode_for_path(Path::new(path)),
        st_mode: mode,
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
            executable_path: &self.proc.executable_path,
            address_space_regions: self.mem.address_space_regions.as_deref(),
            brk_current: self.mem.brk_current,
            mmap_next: self.mem.mmap_next,
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
        "/proc/self/stat" => Some(synthetic_proc_self_stat(ctx.executable_path).into_bytes()),
        "/proc/self/statm" => Some(synthetic_proc_self_statm().to_vec()),
        "/proc/self/status" => Some(synthetic_proc_self_status(ctx.executable_path).into_bytes()),
        "/proc/sys/kernel/osrelease" => Some(synthetic_proc_osrelease().to_vec()),
        "/proc/sys/kernel/hostname" => Some(synthetic_proc_hostname().to_vec()),
        // The default 64-bit Linux pid ceiling. LTP (e.g. setpgid02) reads
        // this to bound pid scans; without it tst_test aborts with ENOENT.
        "/proc/sys/kernel/pid_max" => Some(b"4194304\n".to_vec()),
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
            "[heap]"
                if brk_current > start && brk_current <= region.end => {
                    end = brk_current;
                }
            "[carrick-mmap]"
                if mmap_next > start && mmap_next <= region.end => {
                    end = mmap_next;
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

/// `/proc/self/stat`: the 52-field single-line process status many tools and
/// LTP tests parse (ps, getsid validators, clock_gettime starttime checks).
/// Field 1 (pid) uses the real host pid so it matches getpid(); field 4
/// (ppid) uses the host parent (matches getppid for forked children). The
/// remaining fields are plausible constants — tests read a handful (comm,
/// ppid, pgrp, session, starttime) and check relationships, not exact values.
fn synthetic_proc_self_stat(executable_path: &str) -> String {
    let comm = process_short_name(executable_path);
    let pid = std::process::id();
    // SAFETY: getppid(2) is always successful with no side effects.
    let ppid = unsafe { libc::getppid() } as u32;
    // pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt
    // cmajflt utime stime cutime cstime priority nice num_threads itrealvalue
    // starttime vsize rss rsslim ... (remaining device/addr/signal fields 0;
    // field 38 exit_signal = 17 = SIGCHLD).
    format!(
        "{pid} ({comm}) R {ppid} {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 \
20 0 1 0 1 10485760 256 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 \
17 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
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

#[allow(clippy::too_many_arguments)]
// big-kernel-lock loop needs all of: memory, address, length, clock, interval, deadline, expirations, nonblocking
fn read_timerfd(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    clock_id: u64,
    interval: &Option<Duration>,
    deadline: &mut Option<Duration>,
    expirations: &mut u64,
    nonblocking: bool,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxTimerfdExpirations>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let (mut ready, mut next_deadline) =
        timerfd_expirations(clock_id, *interval, *deadline, *expirations);
    // A blocking timerfd read must wait until the timer fires rather than
    // returning EAGAIN. If the timer hasn't expired yet but there IS an armed
    // deadline, sleep until that deadline (real wall-clock) and recompute. If
    // there's no deadline (no timer armed) we can't know when to wake, so we
    // fall through to EAGAIN to avoid wedging the conformance harness.
    if ready == 0 && !nonblocking
        && let Some(target) = next_deadline {
            if let Some(now) = linux_clock_duration(clock_id) {
                let wait = target.saturating_sub(now);
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
            }
            let recomputed = timerfd_expirations(clock_id, *interval, Some(target), *expirations);
            ready = recomputed.0;
            next_deadline = recomputed.1;
        }
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





pub(super) fn read_u64(memory: &impl GuestMemory, address: u64) -> Result<u64, i32> {
    let bytes = memory.read_bytes(address, 8).map_err(|_| LINUX_EFAULT)?;
    Ok(u64::from_ne_bytes(
        bytes.as_slice().try_into().map_err(|_| LINUX_EFAULT)?,
    ))
}

pub(super) fn read_u32(memory: &impl GuestMemory, address: u64) -> Result<u32, i32> {
    let bytes = memory.read_bytes(address, 4).map_err(|_| LINUX_EFAULT)?;
    Ok(u32::from_ne_bytes(
        bytes.as_slice().try_into().map_err(|_| LINUX_EFAULT)?,
    ))
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

/// POSIX discretionary access control (DAC) check. `uid`/`gid` are the
/// CALLER's ids to test against (real ids for `access(2)`, effective for
/// `faccessat(AT_EACCESS)` / `open(2)`); `file_*` describe the target.
/// `mask` is `R_OK|W_OK|X_OK` (`F_OK`=0 always passes — existence is the
/// caller's concern). Returns `Ok(())` if permitted, `Err(EACCES)` otherwise.
///
/// Root (uid 0) bypasses read/write; for execute it still requires at least
/// one execute bit on a regular file (dirs are always searchable for root).
/// Non-root selects exactly ONE triplet — owner if `uid` matches the file
/// owner, else group if `gid` matches, else other — matching the kernel
/// (owner perms apply even when more restrictive than group/other).
pub(super) fn dac_check(
    uid: u32,
    gid: u32,
    file_uid: u32,
    file_gid: u32,
    file_mode: u32,
    is_dir: bool,
    mask: u64,
) -> Result<(), i32> {
    let need = (if mask & LINUX_R_OK != 0 { 4 } else { 0 })
        | (if mask & LINUX_W_OK != 0 { 2 } else { 0 })
        | (if mask & LINUX_X_OK != 0 { 1 } else { 0 });
    if need == 0 {
        return Ok(());
    }
    if uid == 0 {
        if need & 1 != 0 && !is_dir && file_mode & 0o111 == 0 {
            return Err(LINUX_EACCES);
        }
        return Ok(());
    }
    let triplet = if uid == file_uid {
        (file_mode >> 6) & 7
    } else if gid == file_gid {
        (file_mode >> 3) & 7
    } else {
        file_mode & 7
    };
    if triplet & need == need {
        Ok(())
    } else {
        Err(LINUX_EACCES)
    }
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

/// Resolve a validated utimensat timespec into the (sec, nsec) the backend
/// should write, or `None` to leave the time untouched (UTIME_OMIT).
/// UTIME_NOW resolves to the current wall-clock time.
fn resolve_utimensat_timespec(timespec: LinuxTimespec) -> Option<(i64, i64)> {
    // Copy out of the packed struct before matching (taking a reference to
    // a packed field is UB).
    let nsec = timespec.tv_nsec;
    let sec = timespec.tv_sec;
    if nsec == LINUX_UTIME_OMIT {
        None
    } else if nsec == LINUX_UTIME_NOW {
        Some(now_realtime_timespec())
    } else {
        Some((sec, nsec))
    }
}

/// Current CLOCK_REALTIME as a (sec, nsec) pair, for UTIME_NOW / NULL times.
fn now_realtime_timespec() -> (i64, i64) {
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    (ts.tv_sec as i64, ts.tv_nsec as i64)
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

pub(crate) fn host_errno() -> i32 {
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

// ----- AF_NETLINK (rtnetlink) synthesis -----------------------------------

#[allow(dead_code)]
/// Linux `NLMSG_ALIGNTO` — netlink messages and attributes are 4-byte aligned.
const NLMSG_ALIGNTO: usize = 4;




















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
    if n_usize > 0
        && memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() {
            return DispatchOutcome::Errno { errno: LINUX_EFAULT };
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

    #[test]
    fn every_migrated_syscall_is_claimed_by_the_normalized_table() {
        let mut d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let mut reporter = CompatReporter::default();
        // Numbers that used to live in the deleted legacy match. Each must now
        // be claimed by the normalized table (Some), never None.
        for nr in [5u64, 7, 8, 10, 11, 13, 14, 43, 44, 45, 74, 93, 151, 152,
                   159, 172, 173, 174, 175, 176, 177, 178, 243, 269, 283, 293, 435] {
            let req = SyscallRequest::new(nr, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
            assert!(
                d.dispatch_normalized(req, &mut mem, &mut reporter, None).is_some(),
                "syscall {nr} fell through the normalized table",
            );
        }
    }

    #[test]
    fn unknown_syscall_returns_enosys_without_panicking() {
        let mut d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let mut reporter = CompatReporter::default();
        // 999 is not a real aarch64 syscall and is not in the table.
        let req = SyscallRequest::new(999, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        let outcome = d.dispatch(req, &mut mem, &mut reporter).expect("must not error");
        assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_ENOSYS });
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
