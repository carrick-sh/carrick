//! Linux syscall dispatch core.
//!
//! This module owns guest ABI request decoding, descriptor state, wait
//! outcomes, and shared syscall helpers used by the per-domain handlers.

use std::collections::{HashMap, VecDeque};
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// LOCK ORDERING: dispatch handlers must not hold subsystem locks while entering
// guest-memory callbacks or blocking host waits. When multiple dispatcher
// locks are unavoidable, acquire fd/open-description state before filesystem
// overlay state, then pty_table, then proc/signal/thread registries. The
// EPOLL_INMEM_KQUEUES registry is independent and must not be held while
// acquiring dispatcher fd/open-description locks; in-memory wake broadcasts only
// trigger already-registered kqueues. Futex waits are prepared under dispatcher
// state and parked only after those locks have been released.

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::fs_backend::FsBackend;
use crate::linux_abi::{
    KernelAbi,
    // ABI constants moved from dispatch.rs (Goal #3, private set)
    LINUX_AF_INET,
    LINUX_AF_INET6,
    LINUX_AF_NETLINK,
    LINUX_AF_UNIX,
    LINUX_AF_UNSPEC,
    LINUX_ARPHRD_LOOPBACK,
    // ABI constants moved from dispatch.rs (Goal #3)
    LINUX_AT_EACCESS,
    LINUX_AT_EMPTY_PATH,
    LINUX_AT_FDCWD,
    LINUX_AT_NO_AUTOMOUNT,
    LINUX_AT_REMOVEDIR,
    LINUX_AT_STATX_DONT_SYNC,
    LINUX_AT_STATX_FORCE_SYNC,
    LINUX_AT_SYMLINK_FOLLOW,
    LINUX_AT_SYMLINK_NOFOLLOW,
    LINUX_BOOTSTRAP_PGID,
    LINUX_BOOTSTRAP_PID,
    LINUX_BOOTSTRAP_SID,
    LINUX_CAPABILITY_VERSION_1,
    LINUX_CAPABILITY_VERSION_2,
    LINUX_CAPABILITY_VERSION_3,
    LINUX_CLK_TCK,
    LINUX_CLOCK_BOOTTIME,
    LINUX_CLOCK_BOOTTIME_ALARM,
    LINUX_CLOCK_MONOTONIC,
    LINUX_CLOCK_MONOTONIC_COARSE,
    LINUX_CLOCK_MONOTONIC_RAW,
    LINUX_CLOCK_PROCESS_CPUTIME_ID,
    LINUX_CLOCK_REALTIME,
    LINUX_CLOCK_REALTIME_ALARM,
    LINUX_CLOCK_REALTIME_COARSE,
    LINUX_CLOCK_RESOLUTION_NSEC,
    LINUX_CLOCK_TAI,
    LINUX_CLOCK_THREAD_CPUTIME_ID,
    LINUX_CMSG_ALIGN,
    LINUX_CMSGHDR_LEN,
    LINUX_DEFAULT_UMASK,
    LINUX_DIRENT64_HEADER_SIZE,
    LINUX_DT_CHR,
    LINUX_DT_DIR,
    LINUX_DT_FIFO,
    LINUX_DT_LNK,
    LINUX_DT_REG,
    LINUX_DT_SOCK,
    LINUX_E2BIG,
    LINUX_EACCES,
    LINUX_EAFNOSUPPORT,
    LINUX_EAGAIN,
    LINUX_EALREADY,
    LINUX_EBADF,
    LINUX_EEXIST,
    LINUX_EFAULT,
    LINUX_EFBIG,
    LINUX_EFD_CLOEXEC,
    LINUX_EFD_NONBLOCK,
    LINUX_EFD_SEMAPHORE,
    LINUX_EINPROGRESS,
    LINUX_EINTR,
    LINUX_EINVAL,
    LINUX_EISCONN,
    LINUX_EISDIR,
    LINUX_ENAMETOOLONG,
    LINUX_ENOENT,
    LINUX_ENOMEM,
    LINUX_ENOPROTOOPT,
    LINUX_ENOSYS,
    LINUX_ENOTDIR,
    LINUX_ENOTSOCK,
    LINUX_ENOTSUP,
    LINUX_ENOTTY,
    LINUX_EPERM,
    LINUX_EPIPE,
    LINUX_EPOLL_CLOEXEC,
    LINUX_EPOLL_CTL_ADD,
    LINUX_EPOLL_CTL_DEL,
    LINUX_EPOLL_CTL_MOD,
    LINUX_EPOLLERR,
    LINUX_EPOLLET,
    LINUX_EPOLLHUP,
    LINUX_EPOLLIN,
    LINUX_EPOLLONESHOT,
    LINUX_EPOLLOUT,
    LINUX_EPOLLPRI,
    LINUX_EPOLLRDHUP,
    LINUX_ERANGE,
    LINUX_EROFS,
    LINUX_ESOCKTNOSUPPORT,
    LINUX_ESPIPE,
    LINUX_ESRCH,
    LINUX_ETIMEDOUT,
    LINUX_F_DUPFD,
    LINUX_F_DUPFD_CLOEXEC,
    LINUX_F_GETFD,
    LINUX_F_GETFL,
    LINUX_F_GETLEASE,
    LINUX_F_GETLK,
    LINUX_F_GETOWN,
    LINUX_F_GETOWN_EX,
    LINUX_F_GETPIPE_SZ,
    LINUX_F_GETSIG,
    LINUX_F_NOTIFY,
    LINUX_F_OFD_GETLK,
    LINUX_F_OFD_SETLK,
    LINUX_F_OFD_SETLKW,
    LINUX_F_OWNER_PGRP,
    LINUX_F_OWNER_PID,
    LINUX_F_OWNER_TID,
    LINUX_F_RDLCK,
    LINUX_F_SETFD,
    LINUX_F_SETFL,
    LINUX_F_SETLEASE,
    LINUX_F_SETLK,
    LINUX_F_SETLKW,
    LINUX_F_SETOWN,
    LINUX_F_SETOWN_EX,
    LINUX_F_SETPIPE_SZ,
    LINUX_F_SETSIG,
    LINUX_F_UNLCK,
    LINUX_F_WRLCK,
    LINUX_FALLOC_FL_KEEP_SIZE,
    LINUX_FALLOC_FL_SUPPORTED,
    LINUX_FD_CLOEXEC,
    LINUX_FIONBIO,
    LINUX_FIONREAD,
    LINUX_FUTEX_CMD_MASK,
    LINUX_FUTEX_CMP_REQUEUE,
    LINUX_FUTEX_REQUEUE,
    LINUX_FUTEX_WAIT,
    LINUX_FUTEX_WAKE,
    LINUX_IFA_ADDRESS,
    LINUX_IFA_LABEL,
    LINUX_IFA_LOCAL,
    LINUX_IFF_LOOPBACK,
    LINUX_IFF_RUNNING,
    LINUX_IFF_UP,
    LINUX_IFLA_ADDRESS,
    LINUX_IFLA_IFNAME,
    LINUX_IOV_MAX,
    LINUX_ITIMER_PROF,
    LINUX_ITIMER_REAL,
    LINUX_ITIMER_VIRTUAL,
    LINUX_LOCK_EX,
    LINUX_LOCK_NB,
    LINUX_LOCK_SH,
    LINUX_LOCK_UN,
    LINUX_MADV_COLLAPSE,
    LINUX_MADV_DONTNEED,
    LINUX_MADV_FREE,
    LINUX_MADV_HUGEPAGE,
    LINUX_MADV_NOHUGEPAGE,
    LINUX_MADV_NORMAL,
    LINUX_MADV_RANDOM,
    LINUX_MADV_SEQUENTIAL,
    LINUX_MADV_WILLNEED,
    LINUX_MAP_ANONYMOUS,
    LINUX_MAP_DROPPABLE,
    LINUX_MAP_FIXED,
    LINUX_MAP_FIXED_NOREPLACE,
    LINUX_MAP_PRIVATE,
    LINUX_MAP_SHARED,
    LINUX_MAX_SIGNUM,
    LINUX_MCL_CURRENT,
    LINUX_MCL_FUTURE,
    LINUX_MCL_ONFAULT,
    LINUX_MEMBARRIER_CMD_QUERY,
    LINUX_MINSIGSTKSZ,
    LINUX_MREMAP_DONTUNMAP,
    LINUX_MREMAP_FIXED,
    LINUX_MREMAP_MAYMOVE,
    LINUX_MS_ASYNC,
    LINUX_MS_INVALIDATE,
    LINUX_MS_SYNC,
    LINUX_MSG_CMSG_CLOEXEC,
    LINUX_MSG_CTRUNC,
    LINUX_MSG_DONTROUTE,
    LINUX_MSG_DONTWAIT,
    LINUX_MSG_EOR,
    LINUX_MSG_NOSIGNAL,
    LINUX_MSG_OOB,
    LINUX_MSG_PEEK,
    LINUX_MSG_TRUNC,
    LINUX_MSG_WAITALL,
    LINUX_NLM_F_MULTI,
    LINUX_NLMSG_DONE,
    LINUX_O_ACCMODE,
    LINUX_O_APPEND,
    LINUX_O_CLOEXEC,
    LINUX_O_CREAT,
    LINUX_O_DIRECTORY,
    LINUX_O_EXCL,
    LINUX_O_NONBLOCK,
    LINUX_O_RDONLY,
    LINUX_O_RDWR,
    LINUX_O_TRUNC,
    LINUX_O_WRONLY,
    LINUX_OPEN_HOW_SIZE,
    LINUX_OVERLAYFS_SUPER_MAGIC,
    LINUX_P_ALL,
    LINUX_P_PGID,
    LINUX_P_PID,
    LINUX_P_PIDFD,
    LINUX_PAGE_SIZE,
    LINUX_PERSONALITY_QUERY,
    LINUX_POLLERR,
    LINUX_POLLHUP,
    LINUX_POLLIN,
    LINUX_POLLNVAL,
    LINUX_POLLOUT,
    LINUX_PR_GET_DUMPABLE,
    LINUX_PR_GET_MEM_MODEL,
    LINUX_PR_GET_NAME,
    LINUX_PR_GET_PDEATHSIG,
    LINUX_PR_SET_DUMPABLE,
    LINUX_PR_SET_MEM_MODEL,
    LINUX_PR_SET_MEM_MODEL_DEFAULT,
    LINUX_PR_SET_MEM_MODEL_TSO,
    LINUX_PR_SET_NAME,
    LINUX_PR_SET_PDEATHSIG,
    LINUX_PRIO_PROCESS,
    LINUX_PRIO_USER,
    LINUX_PROT_EXEC,
    LINUX_PROT_READ,
    LINUX_PROT_WRITE,
    LINUX_R_OK,
    LINUX_RLIM_INFINITY,
    LINUX_RT_SIGSET_SIZE,
    LINUX_RTM_GETADDR,
    LINUX_RTM_GETLINK,
    LINUX_RTM_NEWADDR,
    LINUX_RTM_NEWLINK,
    LINUX_RUSAGE_CHILDREN,
    LINUX_RUSAGE_SELF,
    LINUX_RUSAGE_THREAD,
    LINUX_S_IFBLK,
    LINUX_S_IFCHR,
    LINUX_S_IFDIR,
    LINUX_S_IFIFO,
    LINUX_S_IFLNK,
    LINUX_S_IFMT,
    LINUX_S_IFREG,
    LINUX_S_IFSOCK,
    LINUX_SCHED_BATCH,
    LINUX_SCHED_DEADLINE,
    LINUX_SCHED_FIFO,
    LINUX_SCHED_IDLE,
    LINUX_SCHED_OTHER,
    LINUX_SCHED_RR,
    LINUX_SCM_RIGHTS,
    LINUX_SEEK_CUR,
    LINUX_SEEK_END,
    LINUX_SEEK_SET,
    LINUX_SIG_BLOCK,
    LINUX_SIG_SETMASK,
    LINUX_SIG_UNBLOCK,
    LINUX_SIGKILL,
    LINUX_SIGPIPE,
    LINUX_SIGSTOP,
    LINUX_SIGTTOU,
    LINUX_SO_ACCEPTCONN,
    LINUX_SO_BROADCAST,
    LINUX_SO_DEBUG,
    LINUX_SO_DONTROUTE,
    LINUX_SO_ERROR,
    LINUX_SO_KEEPALIVE,
    LINUX_SO_LINGER,
    LINUX_SO_OOBINLINE,
    LINUX_SO_RCVBUF,
    LINUX_SO_RCVTIMEO,
    LINUX_SO_REUSEADDR,
    LINUX_SO_REUSEPORT,
    LINUX_SO_SNDBUF,
    LINUX_SO_SNDTIMEO,
    LINUX_SO_TYPE,
    LINUX_SOCK_DGRAM,
    LINUX_SOCK_RAW,
    LINUX_SOCK_SEQPACKET,
    LINUX_SOCK_STREAM,
    LINUX_SOCKADDR_STORAGE_SIZE,
    LINUX_SOCKET_TYPE_SUPPORTED_MASK,
    LINUX_SOL_IP,
    LINUX_SOL_IPV6,
    LINUX_SOL_SOCKET,
    LINUX_SOL_TCP,
    LINUX_SOL_UDP,
    LINUX_SPLICE_SUPPORTED_FLAGS,
    LINUX_SS_DISABLE,
    LINUX_STATX_BASIC_STATS,
    LINUX_STATX_RESERVED,
    LINUX_TASK_COMM_LEN,
    LINUX_TCFLSH,
    LINUX_TCGETS,
    LINUX_TCP_CORK,
    LINUX_TCP_KEEPCNT,
    LINUX_TCP_KEEPIDLE,
    LINUX_TCP_KEEPINTVL,
    LINUX_TCP_MAXSEG,
    LINUX_TCP_NODELAY,
    LINUX_TCSBRK,
    LINUX_TCSBRKP,
    LINUX_TCSETS,
    LINUX_TCSETSF,
    LINUX_TCSETSW,
    LINUX_TCXONC,
    LINUX_TERMIOS_KERNEL_SIZE,
    LINUX_TFD_CLOEXEC,
    LINUX_TFD_NONBLOCK,
    LINUX_TIMER_ABSTIME,
    LINUX_TIOCGPGRP,
    LINUX_TIOCGPTN,
    LINUX_TIOCGSID,
    LINUX_TIOCGWINSZ,
    LINUX_TIOCNOTTY,
    LINUX_TIOCSCTTY,
    LINUX_TIOCSPGRP,
    LINUX_TIOCSPTLCK,
    LINUX_TIOCSWINSZ,
    LINUX_UTIME_NOW,
    LINUX_UTIME_OMIT,
    LINUX_W_OK,
    LINUX_WAIT4_SUPPORTED_FLAGS,
    LINUX_WAITID_STATE_MASK,
    LINUX_WAITID_SUPPORTED_FLAGS,
    LINUX_X_OK,
    LinuxAtFlags,
    LinuxCapabilityData,
    LinuxCapabilityHeader,
    LinuxCloneArgs,
    LinuxCloneFlags,
    LinuxDirent64Header,
    LinuxEpollEvent,
    LinuxEventfdValue,
    LinuxFdFlags,
    LinuxFdPair,
    LinuxFutexFlags,
    LinuxIfAddrMsg,
    LinuxIfInfoMsg,
    LinuxIovec,
    LinuxItimerspec,
    LinuxItimerval,
    LinuxMmapFlags,
    LinuxMmsghdr,
    LinuxMsghdr,
    LinuxNlMsgHdr,
    LinuxOpenFlags,
    LinuxOpenHow,
    LinuxPollFd,
    LinuxRlimit,
    LinuxRtAttr,
    LinuxRusage,
    LinuxSigaction,
    LinuxSigaltstack,
    LinuxSocketTypeFlags,
    LinuxStat,
    LinuxStatfs,
    LinuxStatx,
    LinuxStatxTimestamp,
    LinuxSysinfo,
    LinuxTermios,
    LinuxTimerfdExpirations,
    LinuxTimespec,
    LinuxTimeval,
    LinuxTimezone,
    LinuxTms,
    LinuxUtsname,
    LinuxWinsize,
};
use crate::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE};
use crate::overlay::OverlayEntry;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
use crate::syscall::lookup_aarch64;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes};

macro_rules! define_syscall {
    ( $(
        $(#[$meta:meta])*
        fn $name:ident ( $this:ident, $cx:ident $(, $arg:ident : $argty:ty )* $(,)? ) $body:block
    )* ) => {
        $(
            $(#[$meta])*
            #[allow(unused_variables)]
            pub(super) fn $name<M: GuestMemory>(
                &self,
                ctx: &mut SyscallCtx<M>,
            ) -> Result<DispatchOutcome, DispatchError> {
                // Alias the receiver and context to caller-named idents (macro
                // hygiene means a bare `self`/`ctx` in the body wouldn't bind).
                let $this = self;
                let $cx = ctx;
                let mut __arg_index = 0usize;
                $(
                    let $arg: $argty = $cx.typed_arg(__arg_index);
                    __arg_index += 1;
                )*
                let _ = __arg_index;
                $body
            }
        )*
    };
}

mod abi_args;
#[macro_use]
mod creds;
mod epoll_shim;
pub(crate) use epoll_shim::{notify_inmem_epoll, register_epoll_kqueue, unregister_epoll_kqueue};
mod fd_table;
mod ioring;
#[macro_use]
mod fs;
#[macro_use]
mod mem;
#[macro_use]
mod net;
#[macro_use]
mod proc;
mod proctitle;
#[macro_use]
mod signal;
mod sysv;
#[macro_use]
mod time;

pub use proctitle::{init as proctitle_init, set_host_process_name};

pub use crate::vfs::ProcMapsEntry;
pub use abi_args::{Fd, GuestLen, GuestPtr, Pid, Signal};
use fd_table::*;

#[allow(dead_code)]
const MAX_GUEST_PATH: usize = 4096;

fn threaded_independent_dispatch_supports(number: u64) -> bool {
    matches!(number, 96 | 98 | 99 | 124 | 178)
}

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
    pub reporter: &'a CompatReporter,
    /// Present only when the syscall is dispatched on behalf of a specific
    /// guest thread (the multi-threaded runtime path). Carries this thread's
    /// tid and the shared thread/futex coordination tables. `None` for the
    /// single-threaded `dispatch` path (legacy callers + unit tests), where
    /// tid-aware handlers fall back to pid-based answers.
    pub thread: Option<ThreadCtx<'a>>,
}

impl<M: GuestMemory> SyscallCtx<'_, M> {
    #[inline]
    pub fn number(&self) -> u64 {
        self.request.number
    }

    #[inline]
    pub fn raw_args(&self) -> SyscallArgs {
        self.request.args
    }
}

/// Per-thread coordination handles handed to tid-aware syscall handlers
/// (`gettid`, `set_tid_address`, `futex`).
#[derive(Clone, Copy)]
pub struct ThreadCtx<'a> {
    pub tid: crate::thread::ThreadId,
    pub registry: &'a crate::thread::ThreadRegistry,
    pub futex: &'a crate::thread::FutexTable,
}

// `Aarch64SyscallFrame`, `GuestMemory`, and `MemoryError` were lifted into the
// leaf crate `carrick-guest-mem` to break the `memory ↔ dispatch` cycle (see
// docs/build-decomposition-design.md §3.A-A2). Re-exported here so every
// `crate::dispatch::{…}` / `carrick_runtime::dispatch::{…}` site is unchanged.
pub use carrick_guest_mem::{Aarch64SyscallFrame, GuestMemory, MemoryError};

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
    Returned {
        value: i64,
    },
    Errno {
        errno: i32,
    },
    Exit {
        code: i32,
    },
    /// `clone(2)` with process-creation flags. The runtime must perform
    /// a real macOS fork against the trap engine, then write the child
    /// pid (parent) or 0 (child) into x0 to complete the syscall.
    ///
    /// `pidfd_out` is `Some(addr)` when `CLONE_PIDFD` was requested: the
    /// runtime allocates a pidfd for the new child and writes its (32-bit) fd
    /// to `addr` in the parent. Go's `os/exec` clones with `CLONE_PIDFD` and
    /// then waits on that fd.
    Fork {
        pidfd_out: Option<u64>,
        /// Guest-requested exit signal (low byte of clone flags / clone3
        /// `exit_signal`). Delivered to the parent on child exit instead of a
        /// hardcoded SIGCHLD. `0` means "no exit signal" (e.g. `clone(0)`).
        exit_signal: u32,
    },
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
        // argv/env are opaque BYTE strings (Linux ABI), not UTF-8 — a guest may
        // legitimately pass non-UTF-8 args/env (e.g. CPython regrtest's
        // PYTHONREGRTEST_UNICODE_GUARD). The executable `path` stays a String
        // (resolved against the String/Path fs layer).
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    },
    /// Guest requested a change to the vCPU memory-ordering model via
    /// `prctl(PR_SET_MEM_MODEL, …)`. Apple Rosetta 2 issues this at startup to
    /// turn on hardware x86_64 TSO ordering. The dispatcher has no access to the
    /// vCPU, so the runtime loop performs the `ACTLR_EL1.EnTSO` write on the
    /// active vCPU thread and then completes the syscall with 0.
    SetMemoryModel {
        tso: bool,
    },
    /// Back a dynamic high-VA `mmap` (a guest VA at/above 1 TiB that can't be
    /// identity-mapped — HVF's IPA is 40 bits). Apple Rosetta reserves its
    /// translation working set at ~240 TiB. The runtime `hv_vm_map`s anonymous
    /// memory at `ipa`, builds a VA→IPA stage-1 path for `[va, va+len)`, and
    /// completes the `mmap` with `va`. The dispatcher has already reserved `ipa`
    /// from the low alias arena (`crate::memory::LINUX_ALIAS_IPA_BASE`).
    MapHostAlias {
        va: u64,
        ipa: u64,
        len: u64,
        /// Bytes to copy into the freshly-mapped region at offset 0 (the file
        /// content for a file-backed mmap; empty for anonymous, which the host
        /// anon mapping already zeroes). Ignored when `file` is `Some` — a live
        /// `MAP_SHARED` file mapping is backed by the page cache directly.
        payload: Vec<u8>,
        /// `Some((fd, offset, host_prot))` for a live `MAP_SHARED` file mapping:
        /// the host memory at `ipa` is `mmap(host_prot, MAP_SHARED, fd, offset)`,
        /// so guest writes go to the file's page cache (coherent with other
        /// openers and across `fork`). `host_prot` is the guest's requested prot
        /// translated to `PROT_*` — it MUST match the fd's access mode (a
        /// `PROT_WRITE` MAP_SHARED of a read-only fd is EACCES). The fd is a dup
        /// the runtime owns and closes after mapping. `None` → anonymous (the
        /// high-VA / `payload`-snapshot path).
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
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
        stack: u64, // child SP (clone arg)
        tls: u64,   // CLONE_SETTLS value -> TPIDR_EL0 (0 = none)
        flags: u64,
        parent_tid_addr: u64, // CLONE_PARENT_SETTID target (0 = none)
        child_tid_addr: u64,  // CLONE_CHILD_SETTID/CLEARTID target (0 = none)
    },
    /// A single thread exited via `exit(2)` (NOT exit_group): the runtime
    /// performs the CLONE_CHILD_CLEARTID futex wake and ends just this host
    /// thread. If it was the last live thread the process exits.
    ThreadExit {
        code: i32,
    },
    /// Guest `tgkill`/`tkill` targeting a *sibling* thread (not self). The
    /// handler can't reach the target's vCPU, so the runtime publishes the
    /// signal for `tid` and forces that vCPU out of the guest (vcpu_kick) so it
    /// delivers promptly. Completes the calling syscall with 0, or -ESRCH if
    /// the target raced to exit. Only emitted on the multi-threaded path.
    SignalThread {
        tid: i32,
        signum: i32,
    },
    /// `FUTEX_WAIT` whose value-check passed under the dispatcher lock: the
    /// guest word equals the expected value, so this thread must block.
    /// The handler CANNOT block while holding the dispatcher lock (a sibling's
    /// `FUTEX_WAKE` would deadlock), so it returns this outcome and the
    /// runtime drops the lock, parks on the prepared futex token, then completes the
    /// syscall with 0 (woken) or -ETIMEDOUT (timed out).
    FutexWait {
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    },
    /// A `FUTEX_WAIT` on a genuine `MAP_SHARED` file mapping — an inter-PROCESS
    /// rendezvous (LTP `tst_checkpoint`). The in-process parking-lot table can't
    /// reach a waker in another carrick process, so the runtime blocks on the
    /// host `__ulock` keyed by the SHARED physical page (`host_addr` is the host
    /// VA of the futex word). Like `FutexWait` it must not block under the
    /// dispatcher lock; the runtime waits interruptibly and completes the
    /// syscall. `value` is the expected futex word (the kernel re-compares).
    SharedFutexWait {
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
    },
    /// A blocking-mode I/O syscall (ppoll/pselect/poll/select with no fd ready,
    /// or — later — recvfrom/accept/read that would block) needs to wait for
    /// host-fd readiness. Like `FutexWait`, the handler MUST NOT block while
    /// holding the dispatcher lock — that starves every sibling thread (CPython's
    /// GIL handoff, a server's worker threads, see the "dispatcher lock"). It
    /// returns this outcome; the runtime drops the lock, `libc::poll`s the host
    /// fds (signal-interruptible) up to `timeout`, then either completes the
    /// syscall (timeout → 0, signal → EINTR) or re-dispatches it (a fd became
    /// ready → the handler now finds it and returns the revents). The handler
    /// has already written zeroed revents into guest memory, so a timeout
    /// completion needs no further writes.
    WaitOnFds {
        /// (host_fd, poll events) pairs to wait on.
        fds: Vec<(i32, i16)>,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// Value to complete the syscall with if the wait times out: `0` for
        /// poll/select (a timeout means "no fds ready"), `-EAGAIN` for a
        /// blocking recv/accept with a finite SO_RCVTIMEO (a timeout means
        /// "would have blocked"). Only consulted when `timeout` is `Some`.
        on_timeout: i64,
        /// Signals (bit `signum-1`) this syscall temporarily blocks for the
        /// duration of the wait — an `epoll_pwait`/`ppoll`/`pselect6` sigmask. A
        /// signal blocked here does NOT interrupt the wait (it stays pending and
        /// is delivered after the syscall, per the persistent mask). `0` = none.
        block_signals: u64,
    },
    /// Like [`WaitOnFds`] but for `select`/`pselect6`, whose fd-set bitmaps are
    /// BOTH input and output (unlike `poll`'s separate `events`/`revents`).
    /// The handler therefore leaves the guest fd-sets UNMODIFIED across the
    /// wait, so:
    ///   - a `Ready` re-dispatch re-reads the original input sets and reports
    ///     the now-ready fds (a fd that becomes ready *during* the block — the
    ///     primary use of select — is found correctly), and
    ///   - an `Interrupted` (EINTR) return leaves the sets unmodified, exactly
    ///     as Linux specifies on signal interruption.
    /// Only `TimedOut` must present zeroed sets (select returns 0 with empty
    /// sets), which the runtime does by zeroing each `clear_on_timeout`
    /// `(guest_addr, byte_len)` range before completing the syscall with 0.
    /// `on_timeout` is implicitly 0 (a select timeout means "no fds ready").
    WaitOnFdsSelect {
        /// (host_fd, poll events) pairs to wait on.
        fds: Vec<(i32, i16)>,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// Temporarily-blocked sigmask for the wait (pselect6); `0` = none.
        block_signals: u64,
        /// Guest `(address, byte length)` of each present fd-set to zero if the
        /// wait times out. Empty when no fd-set was supplied.
        clear_on_timeout: Vec<(u64, usize)>,
    },
    /// Same contract as [`WaitOnFds`], but serviced by `poll(2)` instead of
    /// the runtime's per-thread kqueue. This is for epoll's backing kqueue fd:
    /// polling a kqueue fd observes pending epoll events without consuming
    /// them, so the runtime can re-dispatch `epoll_pwait` and let that call
    /// drain the epoll instance kqueue normally.
    WaitOnPollFds {
        /// (host_fd, poll events) pairs to wait on.
        fds: Vec<(i32, i16)>,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// Value to complete the syscall with if the wait times out.
        on_timeout: i64,
        /// Signals (bit `signum-1`) temporarily blocked for the wait.
        block_signals: u64,
    },
    /// A blocking `waitid(P_PID, pid, …)` whose target child hasn't changed
    /// state yet. The runtime parks the vCPU thread on the child's exit via the
    /// per-thread kqueue's `EVFILT_PROC`/`NOTE_EXIT` (interruptible by a signal
    /// or a fork quiesce — unlike a raw `libc::waitid`), then re-dispatches the
    /// waitid to reap. `block_signals` is the temporarily-blocked sigmask (0 for
    /// a plain waitid).
    WaitOnProcExit {
        pid: i32,
        block_signals: u64,
    },
    /// `rt_sigtimedwait` found no matching signal already pending and must wait
    /// until one of `wait_set` arrives, or until `timeout` elapses. The runtime
    /// parks without holding dispatcher locks, wakes only for matching signals,
    /// then re-dispatches the same syscall so the dispatcher can dequeue the
    /// signal and write `siginfo_t` through the original guest pointer.
    WaitOnSignals {
        wait_set: u64,
        timeout: Option<Duration>,
    },
    /// A relative sleep (`nanosleep`/`clock_nanosleep`). The run loop performs
    /// the timed wait via the per-thread waiter — NOT a blocking host nanosleep
    /// inside the dispatcher — so the sleep is interruptible by a guest signal
    /// (EINTR) AND, critically, can PARK for a fork-quiesce: a sibling stuck in
    /// a synchronous host nanosleep never reaches the run-loop top, so a
    /// multithreaded fork would otherwise deadlock waiting for it to quiesce.
    /// The run loop preserves the deadline across re-dispatch (quiesce-park),
    /// so the sleep is not restarted. `duration` is the (relative) remaining
    /// time; an ABSTIME clock_nanosleep is pre-converted by the handler.
    WaitOnSleep {
        duration: Duration,
    },
}

impl DispatchOutcome {
    /// Construct an errno outcome. The guest receives `-errno`.
    #[inline]
    pub fn errno(errno: i32) -> Self {
        DispatchOutcome::Errno { errno }
    }

    fn retval_errno(&self) -> (i64, Option<i32>) {
        match self {
            DispatchOutcome::Returned { value } => (*value, None),
            DispatchOutcome::Errno { errno } => (-(*errno as i64), Some(*errno)),
            DispatchOutcome::Exit { code } => (*code as i64, None),
            DispatchOutcome::Fork { .. } => (0, None),
            DispatchOutcome::Execve { .. } => (0, None),
            DispatchOutcome::SigReturn => (0, None),
            DispatchOutcome::SetMemoryModel { .. } => (0, None),
            DispatchOutcome::MapHostAlias { .. } => (0, None),
            // CloneThread/ThreadExit/FutexWait are handled specially by the
            // runtime and never flow through retval_errno — the runtime acts
            // on them directly before any x0 write.
            DispatchOutcome::CloneThread { .. } => (0, None),
            DispatchOutcome::ThreadExit { .. } => (0, None),
            DispatchOutcome::SignalThread { .. } => (0, None),
            DispatchOutcome::FutexWait { .. } => (0, None),
            DispatchOutcome::SharedFutexWait { .. } => (0, None),
            DispatchOutcome::WaitOnFds { .. } => (0, None),
            DispatchOutcome::WaitOnFdsSelect { .. } => (0, None),
            DispatchOutcome::WaitOnPollFds { .. } => (0, None),
            DispatchOutcome::WaitOnProcExit { .. } => (0, None),
            DispatchOutcome::WaitOnSignals { .. } => (0, None),
            DispatchOutcome::WaitOnSleep { .. } => (0, None),
        }
    }
}

impl From<i32> for DispatchOutcome {
    #[inline]
    fn from(errno: i32) -> Self {
        DispatchOutcome::Errno { errno }
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

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("guest memory read length does not fit this host: {0}")]
    LengthTooLarge(u64),
}

/// Outcome of [`SyscallDispatcher::try_vfs_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum VfsOpenAttempt {
    Installed(i32),
    Errno(i32),
    FallThrough,
}

pub struct SyscallDispatcher {
    /// Owned I/O subsystem state (buffered stdout/stderr, stream toggle,
    /// the open-fd table, next-fd cursor, and cwd). See [`fs::IoState`].
    /// Handlers that touch only I/O state borrow `self.io` narrowly.
    io: fs::IoState,
    /// Owned memory subsystem state (brk, mmap arena, shared-file IPA
    /// window + live maps, and the captured address-space regions for
    /// `/proc/self/maps`). See [`mem::MemState`].
    mem: Mutex<mem::MemState>,
    /// Owned process subsystem state (executable path, personality,
    /// dumpable flag, task comm name). See [`proc::ProcState`].
    proc: Mutex<proc::ProcState>,
    /// Owned credentials subsystem state (uids/gids + umask). See
    /// [`creds::CredState`]. This is internally locked so credential syscalls
    /// can run through shared threaded dispatch without the legacy dispatcher
    /// lock.
    creds: Mutex<creds::CredState>,
    /// Owned signal subsystem state (handlers, mask, pending set, alt
    /// stack). See [`signal::SignalState`]. This is internally locked so
    /// signal syscalls and runtime delivery can run through shared threaded
    /// dispatch without the legacy dispatcher lock.
    signal: Mutex<signal::SignalState>,
    /// Owned filesystem subsystem state (unified VFS mount table plus
    /// the `/` rootfs + writable overlay). See [`fs::FsState`]. Handlers
    /// that touch only fs state borrow `self.fs` narrowly.
    fs: fs::FsState,
    /// Installed seccomp(2) cBPF filters, checked before every syscall once
    /// active. Internally locked; `libc::fork` inherits the filters via the
    /// process memory copy and sibling threads share them (process-wide), which
    /// matches Linux's filter-inheritance semantics. See [`crate::seccomp`].
    seccomp: crate::seccomp::SeccompState,
    /// SysV shared-memory registry (per-process; host-file-backed so forked
    /// guests share segments by inode through `/tmp/carrick-shm/`).
    sysv: Mutex<sysv::SysvShmState>,
}

/// Owns an epoll instance's kqueue and keeps it in the in-memory-wake registry
/// for its lifetime (deregistered on drop). Derefs to the inner `Kqueue` so the
/// epoll handlers use it transparently.
#[derive(Debug)]
pub(crate) struct EpollKqueue {
    kq: crate::darwin_kqueue::Kqueue,
}

impl EpollKqueue {
    pub(crate) fn new(kq: crate::darwin_kqueue::Kqueue) -> Self {
        register_epoll_kqueue(kq.raw_fd());
        Self { kq }
    }
}

impl Drop for EpollKqueue {
    fn drop(&mut self) {
        unregister_epoll_kqueue(self.kq.raw_fd());
    }
}

impl std::ops::Deref for EpollKqueue {
    type Target = crate::darwin_kqueue::Kqueue;
    fn deref(&self) -> &Self::Target {
        &self.kq
    }
}

/// Normalize an already-absolute (leading-`/`) guest path: collapse `//`,
/// drop `.` components, and resolve `..` lexically (Linux `/proc/self/exe`
/// stores a resolved absolute path). Always returns a leading-`/` path.
fn normalize_abs_path(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    if out.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", out.join("/"))
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
            &self,
            request: SyscallRequest,
            memory: &mut impl GuestMemory,
            reporter: &CompatReporter,
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

        fn dispatch_normalized_known(number: u64) -> bool {
            matches!(number, $( $num )|*)
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
        26 => inotify_init1,
        27 => inotify_add_watch,
        28 => inotify_rm_watch,
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
        452 => fchmodat2, // validates the flags arg (nr 53 ignores it)
        54 => fchownat,
        55 => fchown,
        56 => openat,
        30 => ioprio_set,
        31 => ioprio_get,
        57 => close,
        58 => vhangup,
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
        74 => signalfd4,
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
        100 => get_robust_list,
        101 => nanosleep,
        102 => getitimer,
        103 => setitimer,
        107 => timer_create,
        108 => timer_gettime,
        109 => timer_getoverrun,
        110 => timer_settime,
        111 => timer_delete,
        112 => clock_settime,
        113 => clock_gettime,
        114 => clock_getres,
        115 => clock_nanosleep,
        117 => ptrace,
        118 => sched_setparam,
        119 => sched_setscheduler,
        120 => sched_getscheduler,
        121 => sched_getparam,
        122 => sched_setaffinity,
        123 => sched_getaffinity,
        124 => sched_yield,
        125 => sched_get_priority_max,
        126 => sched_get_priority_min,
        127 => sched_rr_get_interval,
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
        186 => msgget,
        187 => msgctl,
        188 => msgrcv,
        189 => msgsnd,
        190 => semget,
        191 => semctl,
        192 => semtimedop,
        193 => semop,
        194 => shmget,
        195 => shmctl,
        196 => shmat,
        197 => shmdt,
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
        240 => rt_tgsigqueueinfo,
        242 => accept4,
        260 => wait4,
        261 => prlimit64,
        266 => clock_adjtime,
        267 => syncfs,
        84 => sync_file_range,
        451 => cachestat,
        276 => renameat2,
        277 => sys_seccomp,
        275 => sched_getattr,
        278 => getrandom,
        279 => memfd_create,
        424 => pidfd_send_signal,
        425 => io_uring_setup,
        426 => io_uring_enter,
        427 => io_uring_register,
        434 => pidfd_open,
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
        14 | 15 => sys_removexattr_path,
        16 => sys_removexattr_fd,
        43 => sys_statfs,
        44 => sys_fstatfs,
        45 => sys_truncate,
        75 | 77 => sys_bootstrap_enosys,
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
            mem: Mutex::new(mem::MemState::new()),
            proc: Mutex::new(proc::ProcState::new()),
            creds: Mutex::new(creds::CredState::new()),
            signal: Mutex::new(signal::SignalState::new()),
            fs: fs::FsState::new(),
            seccomp: crate::seccomp::SeccompState::default(),
            sysv: Mutex::new(sysv::SysvShmState::new()),
        }
    }

    /// Capture the guest's `AddressSpace` region list so that
    /// `/proc/self/maps` reflects the real loaded layout (executable
    /// ELF segments, runtime regions, mmap arena, stack, EL0
    /// trampoline, EL1 vectors, page tables) instead of a fixed
    /// summary. Called once after `HvfTrapEngine::map_address_space`
    /// succeeds.
    pub fn set_address_space_regions(&mut self, regions: Vec<ProcMapsEntry>) {
        self.mem.lock().address_space_regions = Some(regions);
    }

    /// High-water mark (bump cursor) of the anonymous mmap arena: the guest has
    /// only ever touched `[LINUX_MMAP_BASE, this)` of the 32 GiB arena window.
    /// `HvfInner::fork` uses it to bound the per-fork resident-page `mincore`
    /// scan to the used prefix instead of all 2M pages of the full window — the
    /// difference between a ~470 ms and a sub-millisecond fork for a guest that
    /// has mmap'd only a sliver (i.e. essentially every guest).
    pub fn mmap_arena_high_water(&self) -> u64 {
        self.mem.lock().mmap_next
    }

    pub fn with_rootfs(rootfs: RootFs) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs.rootfs = Some(rootfs);
        s
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs.rootfs = Some(rootfs);
        s.set_executable_path(executable_path);
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
    pub fn set_executable_path(&self, path: impl Into<String>) {
        let path = path.into();
        let mut proc = self.proc.lock();
        proc.executable_path = path.clone();
        proc.argv = vec![path];
    }

    pub fn set_executable_identity(&self, path: impl Into<String>, argv: Vec<String>) {
        let path = path.into();
        // `/proc/self/exe` MUST resolve to an absolute path: the Linux kernel
        // always stores the absolute, resolved executable path regardless of how
        // execve was called. glibc's dynamic loader asserts this
        // (`_dl_get_origin`: `linkval[0] == '/'`) and aborts the process if the
        // readlink result is relative — which is exactly what happens when a
        // program execs itself by a RELATIVE path (e.g. Go's os/exec
        // TestCommandRelativeName). Absolutize a relative execve path against the
        // guest cwd so the stored identity matches kernel semantics.
        let abs = if path.starts_with('/') {
            normalize_abs_path(&path)
        } else {
            let cwd = self.cwd();
            normalize_abs_path(&format!("{}/{}", cwd.trim_end_matches('/'), path))
        };
        let mut proc = self.proc.lock();
        proc.executable_path = abs.clone();
        proc.argv = if argv.is_empty() { vec![abs] } else { argv };
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
        if let Some(bytes) = self
            .fs
            .rootfs_vfs
            .rootfs
            .as_ref()
            .and_then(|r| r.read(path).ok())
        {
            return Some(bytes);
        }
        // A docker `-v` bind mount can supply the executable itself (e.g.
        // `carrick run -v /host/bin:/gobin img /gobin/foo.test`). The overlay
        // and rootfs miss it, so consult the mount table. `read_file` takes the
        // absolute guest path; BindVfs strips its own mount point.
        self.fs
            .vfs_mounts
            .resolve(path)
            .and_then(|m| m.vfs.read_file(path).ok())
    }

    pub fn stdout(&self) -> Vec<u8> {
        self.io.stdout.lock().clone()
    }

    /// Enable live passthrough for fd 1/2. After this, `write`/`writev`
    /// to the stdio fds go straight to host fd 1/2 via `libc::write`
    /// instead of accumulating in the in-memory buffers — required for
    /// interactive prompts (`/ # `, cursor-position queries, etc.) to
    /// reach the user's terminal before the guest exits.
    pub fn set_stream_stdio(&self, on: bool) {
        *self.io.stream_stdio.lock() = on;
    }

    /// Called after `libc::fork(2)` returns into a child: the child
    /// inherited the parent's buffered stdout/stderr, but we don't
    /// want to re-print those bytes when the child eventually exits
    /// via the `forked_child_exit` path. The parent's full buffer
    /// goes out through its own JSON report.
    pub fn clear_output_buffers(&self) {
        self.io.stdout.lock().clear();
        self.io.stderr.lock().clear();
        // Interval timers are NOT inherited across fork(2) (setitimer(2)). The
        // child inherited the parent's armed interval timers through the copied
        // address space; clear them so the child's alarm()/getitimer() see
        // disarmed timers (LTP runs each test in a forked child whose alarm()
        // must return 0, not the framework's residual watchdog timeout).
        // Interval timers are NOT inherited across fork(2); the parent's timer
        // threads don't survive fork either, so just clear the state.
        self.proc.lock().itimers = [None, None, None];
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
    pub fn close_cloexec_fds(&self) {
        let removed: Vec<OpenFile> = {
            let mut table = self.io.open_files.write();
            let cloexec_fds: Vec<i32> = table
                .iter()
                .filter_map(|(fd, of)| {
                    if of.fd_flags & LINUX_FD_CLOEXEC != 0 {
                        Some(*fd)
                    } else {
                        None
                    }
                })
                .collect();

            cloexec_fds
                .into_iter()
                .filter_map(|fd| table.remove(&fd))
                .collect()
        };

        for open_file in removed {
            self.close_open_file_and_free_pty(&open_file);
        }
    }

    /// Close `open_file`'s backing host fd AND, if it was the last reference
    /// to a pty master this process owns, drop its `/dev/pts` entry. Use this
    /// on every fd-close path (close, close_range, exec CLOEXEC sweep) so the
    /// PtyTable never desyncs from the real fd lifetime.
    pub(in crate::dispatch) fn close_open_file_and_free_pty(&self, open_file: &OpenFile) {
        let pty_master_index = if Arc::strong_count(&open_file.description) == 1 {
            match &*open_file.description.read() {
                OpenDescription::HostPipe {
                    pty: Some(role), ..
                } if role.is_master => Some(role.index),
                _ => None,
            }
        } else {
            None
        };
        close_open_file(open_file);
        if let Some(index) = pty_master_index {
            self.pty_table()
                .lock()
                .free_if_owner(index, std::process::id());
        }
    }

    pub fn stderr(&self) -> Vec<u8> {
        self.io.stderr.lock().clone()
    }

    pub fn cwd(&self) -> String {
        self.io.cwd.read().clone()
    }

    /// Absolutize an `execve(2)` target path against the guest cwd, matching
    /// Linux semantics: a relative program path resolves against the calling
    /// process's working directory. carrick's overlay/rootfs/bind-mount layers
    /// all key on absolute guest paths, so a bare relative path (e.g. Go
    /// os/exec `TestCommandRelativeName`, which sets `cmd.Path = "dirBase/base"`
    /// with `cmd.Dir = "/"`) would miss every layer and fail ENOENT. argv[0] is
    /// left untouched by the caller (Linux preserves whatever the caller
    /// passed); only the path used to LOAD the image is absolutized.
    pub fn resolve_exec_path(&self, path: &str) -> String {
        if path.starts_with('/') {
            normalize_abs_path(path)
        } else {
            let cwd = self.cwd();
            normalize_abs_path(&format!("{}/{}", cwd.trim_end_matches('/'), path))
        }
    }

    /// Set the guest's initial working directory (docker `-w` / image
    /// `WorkingDir`), applied before the guest starts. `getcwd(2)` and relative
    /// path resolution observe it. The path is normalized to an absolute,
    /// no-trailing-slash form; non-absolute input is ignored (the default `/`
    /// stands). Existence is not enforced here — matching docker, which treats
    /// a missing workdir leniently — a later `chdir` validates if the guest
    /// makes one.
    pub fn set_cwd(&self, path: &str) {
        if !path.starts_with('/') {
            return;
        }
        let trimmed = path.trim_end_matches('/');
        *self.io.cwd.write() = if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        };
    }

    /// Shared pseudo-terminal table. Also held by the `/dev` (ptmx) and
    /// `/dev/pts` mounts — all three see the same Arc. Used by the ioctl
    /// (TIOCSPTLCK) and close (free-on-master-close) handlers.
    pub(super) fn pty_table(&self) -> &std::sync::Arc<parking_lot::Mutex<crate::vfs::PtyTable>> {
        &self.fs.pty_table
    }

    /// Register the host pty slave (e.g. `/dev/ttys003`) allocated by
    /// `carrick run -t` as the guest's controlling terminal. The slave is also
    /// the guest's fds 0/1/2. This makes `/dev/pts/N` exist, `/dev/tty` resolve
    /// to the controlling terminal, and `/proc/self/fd/{0,1,2}` readlink to
    /// `/dev/pts/N` so `ttyname(3)` works. Returns the allocated pts index N.
    pub fn register_controlling_pty(&self, host_slave_name: String) -> u32 {
        self.fs
            .pty_table
            .lock()
            .set_controlling(host_slave_name, std::process::id())
    }

    /// Single-threaded dispatch (legacy + unit tests + the fork-based
    /// runtime path). Tid-aware handlers see `thread: None`.
    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_inner(request, memory, reporter, None)
    }

    /// Evaluate installed seccomp filters against `request` before its handler
    /// runs. Returns `Some(outcome)` when a filter blocks the call (ERRNO →
    /// that errno; KILL/TRAP → terminate, fail-closed), or `None` to allow it.
    /// Fast path: no lock when no filter is installed.
    fn seccomp_precheck(&self, request: &SyscallRequest) -> Option<DispatchOutcome> {
        if !self.seccomp.is_active() {
            return None;
        }
        let data = crate::seccomp::SeccompData {
            nr: request.number as i32,
            arch: crate::seccomp::AUDIT_ARCH_AARCH64,
            instruction_pointer: 0,
            args: request.args.0,
        };
        let ret = self.seccomp.check(&data);
        match ret & crate::seccomp::SECCOMP_RET_ACTION_FULL {
            crate::seccomp::SECCOMP_RET_ALLOW
            | crate::seccomp::SECCOMP_RET_LOG
            | crate::seccomp::SECCOMP_RET_TRACE => None,
            crate::seccomp::SECCOMP_RET_ERRNO => {
                // RET_DATA is the errno, clamped to the kernel's 0..=4095 range.
                let errno = (ret & crate::seccomp::SECCOMP_RET_DATA).min(4095) as i32;
                Some(DispatchOutcome::Errno { errno })
            }
            // KILL_PROCESS / KILL_THREAD / TRAP (and any unmodelled action):
            // fail closed by terminating the guest with SIGSYS's wait status
            // (128 + SIGSYS). A *catchable* SIGSYS for RET_TRAP is a follow-up.
            crate::seccomp::SECCOMP_RET_KILL_PROCESS
            | crate::seccomp::SECCOMP_RET_KILL_THREAD
            | crate::seccomp::SECCOMP_RET_TRAP => Some(DispatchOutcome::Exit { code: 128 + 31 }),
            _ => Some(DispatchOutcome::Exit { code: 128 + 31 }),
        }
    }

    // (see `watch_addr` below)

    /// Multi-threaded dispatch through a shared dispatcher reference. Handlers
    /// that touch process-wide state must protect that state with subsystem
    /// locks; there is no dispatcher-wide fallback on this path.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_threaded(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        // seccomp veto applies on the multi-threaded path too (filters are
        // process-wide), before any handler — including the lockless hot path.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            return Ok(outcome);
        }
        if let Some(result) =
            self.dispatch_threaded_shared(request, memory, reporter, tid, registry, futex)
        {
            return result;
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let outcome = {
            reporter.record(CompatEvent::unhandled_syscall(
                request.number,
                name,
                request.args,
            ));
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            }
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            retval,
            errno,
        });

        Ok(outcome)
    }

    /// Shared threaded dispatch path for subsystems already moved behind
    /// interior locks.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_shared(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if let Some(result) =
            Self::dispatch_threaded_independent(request, memory, reporter, tid, registry, futex)
        {
            return Some(result);
        }

        if request.number == 64 && !self.write_shared_supported(request.args.0[0] as i32) {
            return None;
        }

        if !Self::dispatch_normalized_known(request.number) {
            return None;
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        for (nr, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *nr == request.number {
                let value = request.arg(*arg_index as usize);
                check_syscall_flags(reporter, request.number, name, *arg_index, value, *mask);
            }
        }

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number, addr, u64::from_le_bytes(le));
        }

        let thread = Some(ThreadCtx {
            tid,
            registry,
            futex,
        });

        let result = self.dispatch_normalized(request, memory, reporter, thread);
        let outcome = match result {
            Some(Ok(outcome)) => outcome,
            Some(Err(error)) => return Some(Err(error)),
            None => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            retval,
            errno,
        });

        Some(Ok(outcome))
    }

    /// Thread-local syscall subset that does not touch mutable dispatcher
    /// subsystem state. The runtime checks this before taking the serialized
    /// legacy dispatcher path so futex and tid coordination can proceed without
    /// the dispatcher-wide lock.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_independent(
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !threaded_independent_dispatch_supports(request.number) {
            return None;
        }
        match request.number {
            130 => {
                let target = request.arg(0) as crate::thread::ThreadId;
                let signum = request.arg(1);
                if signum <= LINUX_MAX_SIGNUM && (target == tid || !registry.is_live(target)) {
                    return None;
                }
            }
            131 => {
                let target = request.arg(1) as crate::thread::ThreadId;
                let signum = request.arg(2);
                if signum <= LINUX_MAX_SIGNUM && (target == tid || !registry.is_live(target)) {
                    return None;
                }
            }
            _ => {}
        }

        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let outcome = match request.number {
            96 => {
                let addr = request.arg(0);
                registry.set_clear_child_tid(tid, addr);
                DispatchOutcome::Returned { value: tid as i64 }
            }
            98 => dispatch_threaded_futex(request, memory, reporter, futex),
            99 => {
                // set_robust_list: len must equal sizeof(struct
                // robust_list_head) (24); anything else → EINVAL (matches the
                // serialized macro handler — LTP set_robust_list01).
                let len = request.arg(1);
                if len != 24 {
                    DispatchOutcome::Errno {
                        errno: LINUX_EINVAL,
                    }
                } else {
                    DispatchOutcome::Returned { value: 0 }
                }
            }
            124 => {
                std::thread::yield_now();
                DispatchOutcome::Returned { value: 0 }
            }
            130 => {
                let target = request.arg(0) as crate::thread::ThreadId;
                let signum = request.arg(1);
                dispatch_threaded_signal_route(tid, registry, target, signum)?
            }
            131 => {
                let target = request.arg(1) as crate::thread::ThreadId;
                let signum = request.arg(2);
                dispatch_threaded_signal_route(tid, registry, target, signum)?
            }
            178 => {
                if registry.live_count() > 1 {
                    DispatchOutcome::Returned { value: tid as i64 }
                } else {
                    DispatchOutcome::Returned {
                        value: std::process::id() as i64,
                    }
                }
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            retval,
            errno,
        });

        Some(Ok(outcome))
    }

    fn dispatch_inner(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number);
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number,
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        // seccomp: installed cBPF filters get to veto the syscall before its
        // handler runs (ERRNO / kill), mirroring the kernel's pre-syscall check.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number,
                name: ::std::borrow::Cow::Borrowed(name),
                retval,
                errno,
            });
            return Ok(outcome);
        }

        // Reusable guest-memory watchpoint (CARRICK_WATCH_ADDR=<hex>): fire a
        // probe with the current u64 at the watched address before each
        // syscall, so a trace can bracket which syscall changes it.
        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number, addr, u64::from_le_bytes(le));
        }

        // Systematic unknown-flag check. For each syscall whose flag
        // argument has a well-defined supported mask, validate the
        // bits BEFORE the handler runs. The handler still executes
        // (it makes its own EINVAL decisions); this just guarantees
        // a structured report entry whenever a bit drifts.
        for (nr, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *nr == request.number {
                let value = request.arg(*arg_index as usize);
                check_syscall_flags(reporter, request.number, name, *arg_index, value, *mask);
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
                name: ::std::borrow::Cow::Borrowed(name),
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
            name: ::std::borrow::Cow::Borrowed(name),
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
fn write_into_file_contents(
    contents: &mut Vec<u8>,
    offset: &mut usize,
    bytes: &[u8],
) -> Result<(), i32> {
    let end = (*offset).checked_add(bytes.len()).ok_or(LINUX_EFBIG)?;
    if end as u64 > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
        return Err(LINUX_EFBIG);
    }
    if end > contents.len() {
        contents.resize(end, 0);
    }
    contents[*offset..end].copy_from_slice(bytes);
    *offset = end;
    Ok(())
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
    (
        19,
        1,
        LINUX_EFD_SEMAPHORE | LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC,
    ),
    // epoll_create1(flags): EPOLL_CLOEXEC
    (20, 0, LINUX_EPOLL_CLOEXEC),
    // dup3(oldfd, newfd, flags): O_CLOEXEC
    (24, 2, LINUX_O_CLOEXEC),
    // unlinkat(dirfd, pathname, flags): AT_REMOVEDIR (0x200) plus the
    // AT_EMPTY_PATH/AT_SYMLINK_NOFOLLOW pair we accept elsewhere
    (
        35,
        2,
        0x200 | LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW,
    ),
    // renameat2(olddirfd, oldpath, newdirfd, newpath, flags):
    // RENAME_NOREPLACE(1)|EXCHANGE(2)|WHITEOUT(4)
    (276, 4, 0x1 | 0x2 | 0x4),
    // openat(dirfd, pathname, flags, mode): the open flags we recognise
    // — a superset that covers RDONLY/WRONLY/RDWR + the standard mods.
    // Bits are kept liberal because openat is the most-touched syscall.
    (56, 2, LinuxOpenFlags::SUPPORTED_MASK),
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
    // socket/socketpair type: low bits are a socket-kind enum, high bits are SOCK_* flags.
    (198, 1, LINUX_SOCKET_TYPE_SUPPORTED_MASK),
    (199, 1, LINUX_SOCKET_TYPE_SUPPORTED_MASK),
    // accept4(sockfd, addr, addrlen, flags): SOCK_NONBLOCK | SOCK_CLOEXEC
    (242, 3, LinuxSocketTypeFlags::SUPPORTED_MASK as u64),
    // close_range(first, last, flags): CLOSE_RANGE_UNSHARE(2) | CLOEXEC(4)
    (436, 2, 0x2 | 0x4),
    // openat2 — checked inside open_how, but the syscall flag arg is unused
    // statx(dirfd, pathname, flags, mask, statxbuf): AT_* flags
    (291, 2, LinuxAtFlags::STATX_SUPPORTED_MASK),
    // faccessat2(dirfd, pathname, mode, flags)
    (
        439,
        3,
        LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW | 0x200, /* AT_EACCESS */
    ),
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
    reporter: &CompatReporter,
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

/// Service Apple Rosetta 2's startup handshake ioctls. Returns `Some(outcome)`
/// when `request` is one of Rosetta's verification/info ioctls (so the ioctl
/// handler returns it), else `None` (continue normal ioctl handling).
///
/// See `dispatch::fs::ioctl` and `crate::runtime::rosetta_license_blob` for the
/// reverse-engineered details. The expected response bytes are sourced live
/// from the installed Rosetta binary rather than embedded here.
pub(super) fn rosetta_handshake_ioctl(
    memory: &mut impl GuestMemory,
    request: u64,
    arg: u64,
) -> Option<DispatchOutcome> {
    // Licensing ioctls whose result Rosetta `memcmp`s against its embedded blob.
    const ROSETTA_LICENSE_IOCTLS: [u64; 2] = [0x80456122, 0x80456125];
    // Info ioctl: only the (non-negative) return value matters to Rosetta.
    const ROSETTA_INFO_IOCTLS: [u64; 1] = [0x80806123];

    let is_license = ROSETTA_LICENSE_IOCTLS.contains(&request);
    let is_info = ROSETTA_INFO_IOCTLS.contains(&request);
    if !is_license && !is_info {
        return None;
    }

    // The response length is encoded in the ioctl request's size field [29:16].
    let size = ((request >> 16) & 0x3fff) as usize;
    let mut payload = vec![0u8; size];
    if is_license && let Some(blob) = crate::runtime::rosetta_license_blob() {
        let n = blob.len().min(size);
        payload[..n].copy_from_slice(&blob[..n]);
    }
    if memory.write_bytes(arg, &payload).is_err() {
        return Some(DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        });
    }
    Some(DispatchOutcome::Returned { value: 0 })
}

/// Convert an ABSOLUTE futex deadline (FUTEX_WAIT_BITSET) to the remaining
/// duration from now, on the host monotonic clock (or realtime when
/// FUTEX_CLOCK_REALTIME is set). Clamps to zero if already past — Linux then
/// returns ETIMEDOUT immediately.
fn relative_from_absolute_timespec(tv_sec: i64, tv_nsec: i64, realtime: bool) -> Duration {
    let abs_ns = (tv_sec as i128) * 1_000_000_000 + tv_nsec as i128;
    // The guest built `abs_ns` on ITS clock. For a non-FUTEX_CLOCK_REALTIME
    // futex that clock is Linux CLOCK_MONOTONIC, which carrick reports to the
    // guest as macOS CLOCK_UPTIME_RAW (see monotonic_duration: neither counts
    // suspend). "now" here MUST read the SAME base — macOS CLOCK_MONOTONIC is
    // mach_continuous_time (uptime + suspend), so using it makes abs_ns - now
    // off by the accumulated suspend time (hours on a laptop) → every absolute
    // deadline computes as already-past → instant spurious ETIMEDOUT (broke
    // CPython lock.acquire(timeout) / sem_timedwait / condvar timeouts; the
    // futexextra→deadline probe pins it).
    //
    // The FUTEX_CLOCK_REALTIME case reads the host wall clock here, which is
    // correct ONLY because the guest's vDSO CLOCK_REALTIME is calibrated to the
    // same wall clock (see HvfInner::populate_vdso_data_page, which derives the
    // vvar realtime offset from CLOCK_UPTIME_RAW — the guest's CNTVCT base — not
    // the suspend-counting raw cntvct MRS). Probe: futexrealtime.
    let clock = if realtime {
        libc::CLOCK_REALTIME
    } else {
        libc::CLOCK_UPTIME_RAW
    };
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: clock_gettime writes a timespec for a valid clock id.
    unsafe { libc::clock_gettime(clock, &mut now) };
    let now_ns = (now.tv_sec as i128) * 1_000_000_000 + now.tv_nsec as i128;
    let rel_ns = (abs_ns - now_ns).max(0);
    Duration::from_nanos(rel_ns.min(u64::MAX as i128) as u64)
}

fn dispatch_threaded_futex(
    request: SyscallRequest,
    memory: &impl GuestMemory,
    reporter: &CompatReporter,
    futex: &crate::thread::FutexTable,
) -> DispatchOutcome {
    let address = request.arg(0);
    let operation = request.arg(1);
    let value = request.arg(2) as u32;
    let timeout_address = request.arg(3);

    const LINUX_FUTEX_WAIT_BITSET: u64 = 9;
    const LINUX_FUTEX_WAKE_BITSET: u64 = 10;
    let raw_command = operation & LINUX_FUTEX_CMD_MASK;
    let command = match raw_command {
        LINUX_FUTEX_WAIT_BITSET => LINUX_FUTEX_WAIT,
        LINUX_FUTEX_WAKE_BITSET => LINUX_FUTEX_WAKE,
        other => other,
    };
    let flags = operation & !LINUX_FUTEX_CMD_MASK;
    let futex_flags = LinuxFutexFlags::from_bits_retain(flags);
    if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let word = match read_u32(memory, address) {
        Ok(word) => word,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };

    if !futex_flags.contains(LinuxFutexFlags::PRIVATE) {
        reporter.record(crate::compat::CompatEvent::partial_syscall(
            98,
            "futex",
            request.args,
            "non-private futex treated as private (shared address space)",
        ));
    }

    // A futex word that lives in a genuine MAP_SHARED file mapping is an
    // inter-process rendezvous: route it through the host __ulock keyed on the
    // shared physical page so a waker in another carrick process is reached.
    // Private/anon futexes stay in the in-process parking-lot table.
    let shared_host_addr = memory.shared_futex_host_addr(address);
    crate::probes::futex_route(
        address,
        command as i32,
        if shared_host_addr.is_some() { 1 } else { 0 },
        shared_host_addr.map(|h| h as u64).unwrap_or(0),
    );

    match command {
        LINUX_FUTEX_WAKE => {
            if let Some(host_addr) = shared_host_addr {
                // Linux FUTEX_WAKE wakes EXACTLY up to `value` waiters and
                // returns the count. __ulock_wake only does wake-one or
                // wake-all, so wake one at a time up to `value`, counting real
                // wakes until none remain (-ENOENT). (LTP futex_wake03 wakes
                // children incrementally and checks each count.)
                // Linux FUTEX_WAKE wakes up to `value` waiters and returns
                // the count actually woken. macOS wake_by_address_any wakes
                // ONE per call, returning 0/-ENOENT — but called in a tight
                // back-to-back loop on a SHARED address it has a quirk: the
                // kernel keeps the lock structure live for ~µs after a wake,
                // so the next call still finds it and reports success even
                // with no parked thread (we reproduced 7 wakes for 1 waiter
                // in pure libSystem C). A `sched_yield()` between iterations
                // lets the kernel invalidate the structure, after which a
                // second call correctly returns ENOENT — verified accurate
                // for N ∈ {1, 2, 5, 10} waiters. Required for LTP
                // futex_wake03 which checks `FUTEX_WAKE == nr_children`.
                let mut woke = 0i64;
                for i in 0..value {
                    let rc = crate::ulock::wake(host_addr, false);
                    crate::probes::ulock_wake(host_addr as u64, i as i32, rc);
                    if rc < 0 {
                        break;
                    }
                    woke += 1;
                    unsafe {
                        libc::sched_yield();
                    }
                }
                return DispatchOutcome::Returned { value: woke };
            }
            let n = futex.wake(address, value);
            DispatchOutcome::Returned {
                value: i64::from(n),
            }
        }
        LINUX_FUTEX_WAIT => {
            if word != value {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }
            let timeout = if timeout_address == 0 {
                None
            } else {
                let timespec = match read_timespec(memory, timeout_address) {
                    Ok(t) => t,
                    Err(errno) => return DispatchOutcome::Errno { errno },
                };
                // FUTEX_WAIT uses a RELATIVE timeout; FUTEX_WAIT_BITSET uses an
                // ABSOLUTE deadline (CLOCK_MONOTONIC, or CLOCK_REALTIME if
                // FUTEX_CLOCK_REALTIME) — convert it to the remaining duration,
                // else the wait would block until now+deadline ≈ forever.
                if raw_command == LINUX_FUTEX_WAIT_BITSET {
                    Some(relative_from_absolute_timespec(
                        timespec.tv_sec,
                        timespec.tv_nsec,
                        futex_flags.contains(LinuxFutexFlags::CLOCK_REALTIME),
                    ))
                } else {
                    match duration_from_linux_timespec(timespec) {
                        Ok(t) => t,
                        Err(errno) => return DispatchOutcome::Errno { errno },
                    }
                }
            };
            if let Some(host_addr) = shared_host_addr {
                // The shared path's compare-and-wait is atomic in the kernel
                // (__ulock UL_COMPARE_AND_WAIT re-checks the word), so no
                // generation snapshot is needed here.
                return DispatchOutcome::SharedFutexWait {
                    host_addr,
                    value,
                    timeout,
                };
            }
            // Private/anon futex: snapshot the wait generation BEFORE
            // re-validating the word, then re-read the word. This closes a
            // lost-wakeup race — capturing the generation only at park time
            // (i.e. after the value was read at the top of the handler) loses a
            // FUTEX_WAKE delivered in the window between that read and the
            // enqueue: the waker bumps the generation, the waiter then captures
            // the ALREADY-bumped value and sleeps forever. With the snapshot
            // first, a racing wake either advances the captured generation (the
            // wait returns Woken) or has already stored the new word value (the
            // re-read mismatches → EAGAIN, no stale park). High-frequency Go
            // scheduler M park/unpark hit this window and intermittently hung.
            let wait = futex.prepare_wait(address);
            match read_u32(memory, address) {
                Ok(reread) if reread != value => {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EAGAIN,
                    };
                }
                Ok(_) => {}
                Err(errno) => return DispatchOutcome::Errno { errno },
            }
            DispatchOutcome::FutexWait { wait, timeout }
        }
        LINUX_FUTEX_REQUEUE | LINUX_FUTEX_CMP_REQUEUE => {
            // FUTEX_(CMP_)REQUEUE: wake `nr_wake` waiters on uaddr1, then move
            // up to `nr_requeue` of the rest to uaddr2's queue. For this op the
            // futex(2) ABI REINTERPRETS the arg slots: arg3 (normally the
            // timeout pointer) is `nr_requeue`, arg4 is uaddr2, arg5 is val3
            // (the CMP_REQUEUE expected value).
            let nr_wake = value;
            // nr_wake and nr_requeue are signed ints in the kernel ABI; a
            // negative value (e.g. a guest passing ~0 as a "max" by mistake)
            // is EINVAL, checked BEFORE the val3 comparison.
            if (request.arg(2) as i32) < 0 || (request.arg(3) as i32) < 0 {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
            let nr_requeue = request.arg(3) as u32;
            let uaddr2 = request.arg(4);
            let val3 = request.arg(5) as u32;

            // CMP_REQUEUE atomically validates *uaddr1 == val3 before doing any
            // work (the race-free condvar handoff); plain REQUEUE skips it.
            if raw_command == LINUX_FUTEX_CMP_REQUEUE && word != val3 {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }

            // The shared (cross-process __ulock) path has no native requeue.
            // Requeue is an OPTIMISATION over wake (the futex contract permits
            // spurious wakeups, so waking a thread that "should" have been
            // requeued is still correct — the woken guest re-checks its word
            // and re-waits on uaddr2 itself). So for shared futexes we degrade
            // to waking nr_wake + nr_requeue waiters: correct, just without the
            // thundering-herd avoidance. Private/anon futexes — where glibc and
            // musl condvars and LTP futex_cmp_requeue01 actually live — take the
            // real parking-lot requeue below.
            if let Some(host_addr) = shared_host_addr {
                let total = (nr_wake as u64).saturating_add(nr_requeue as u64);
                let mut woke = 0i64;
                let mut i = 0u64;
                while i < total {
                    let rc = crate::ulock::wake(host_addr, false);
                    if rc < 0 {
                        break;
                    }
                    woke += 1;
                    unsafe { libc::sched_yield() };
                    i += 1;
                }
                return DispatchOutcome::Returned { value: woke };
            }

            // Private/anon: real requeue via parking_lot_core::unpark_requeue.
            let (woken, requeued) = futex.requeue(address, uaddr2, nr_wake, nr_requeue);
            // Linux returns the total number of waiters woken PLUS requeued.
            DispatchOutcome::Returned {
                value: i64::from(woken + requeued),
            }
        }
        _ => DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        },
    }
}

fn dispatch_threaded_signal_route(
    caller: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
    target: crate::thread::ThreadId,
    signum: u64,
) -> Option<DispatchOutcome> {
    if signum > LINUX_MAX_SIGNUM {
        return Some(DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        });
    }
    if caller == target {
        return None;
    }
    if registry.is_live(target) {
        return Some(DispatchOutcome::SignalThread {
            tid: target,
            signum: signum as i32,
        });
    }
    None
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

/// Type-safe read for Linux UAPI structs that implement [`KernelAbi`].
/// Reads exactly the Linux wire size, then zero-fills any Rust-only tail
/// bytes before returning the typed value.
fn read_kernel_struct<T>(memory: &impl GuestMemory, address: u64) -> Result<T, i32>
where
    T: KernelAbi + FromBytes,
{
    read_kernel_prefix(memory, address, T::ABI_SIZE)
}

/// Lower-level ABI read for variable-length structs such as clone_args.
/// `length` is the guest-provided prefix length and must fit inside the
/// Linux ABI size carried by the type.
fn read_kernel_prefix<T>(memory: &impl GuestMemory, address: u64, length: usize) -> Result<T, i32>
where
    T: KernelAbi + FromBytes,
{
    if address == 0 || length > T::ABI_SIZE {
        return Err(LINUX_EFAULT);
    }
    let bytes = memory
        .read_bytes(address, length)
        .map_err(|_| LINUX_EFAULT)?;
    let mut value = <T as zerocopy::FromZeros>::new_zeroed();
    value.as_mut_bytes()[..length].copy_from_slice(&bytes);
    Ok(value)
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
    let open_flags = LinuxOpenFlags::from_bits_retain(flags);
    if open_flags.contains(LinuxOpenFlags::CLOEXEC) {
        LinuxFdFlags::CLOEXEC.bits()
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
///
/// A bare stdio fd is the host's INHERITED fd 0/1/2, so its tty-ness is
/// exactly the host fd's tty-ness: `isatty(host_fd)`. Previously every bare
/// stdio fd was reported as a tty unconditionally, so `isatty(0)` returned
/// true even when carrick's stdin was a pipe or `/dev/null` — diverging from
/// Linux and making test_file.testStdin RUN (CPython skips it unless stdin is
/// a real TTY) instead of skip. Consulting the real host fd is the
/// Darwin-native ground truth and also fixes the interactive `-t` pty case
/// (the slave IS a tty) and the redirected case (a pipe/file is NOT).
fn fd_is_tty(open_files: &HashMap<i32, OpenFile>, fd: i32) -> bool {
    if !is_stdio_fd(fd) {
        return false;
    }
    !open_files.contains_key(&fd) && crate::host_tty::host_isatty(fd)
}

fn retain_open_file(description: &OpenDescriptionRef) {
    match &*description.read() {
        OpenDescription::PipeReader { pipe, .. } => {
            let mut pipe = pipe.lock();
            pipe.readers = pipe.readers.saturating_add(1);
        }
        OpenDescription::PipeWriter { pipe, .. } => {
            let mut pipe = pipe.lock();
            pipe.writers = pipe.writers.saturating_add(1);
        }
        _ => {}
    }
}

fn close_open_file(open_file: &OpenFile) {
    match &*open_file.description.read() {
        OpenDescription::PipeReader { pipe, .. } => {
            let mut pipe = pipe.lock();
            pipe.readers = pipe.readers.saturating_sub(1);
        }
        OpenDescription::PipeWriter { pipe, .. } => {
            let mut pipe = pipe.lock();
            pipe.writers = pipe.writers.saturating_sub(1);
        }
        _ => {}
    }
}

fn linux_min_fd(value: u64) -> Result<i32, i32> {
    i32::try_from(value).map_err(|_| LINUX_EINVAL)
}

/// A dynamic posix CPU-clock id (per-thread or per-process). These are NEGATIVE
/// (viewed as a signed 32-bit int) and encode a tid/pid; glibc/musl return them
/// from `clock_getcpuclockid`/`pthread_getcpuclockid`. CPython's
/// test_pthread_getcpuclockid does clock_gettime() on one — carrick rejected it.
enum DynamicCpuClock {
    /// Per-thread CPU clock → host CLOCK_THREAD_CPUTIME_ID (current thread).
    PerThread,
    /// Per-process CPU clock → host CLOCK_PROCESS_CPUTIME_ID (current process).
    PerProcess,
}

fn dynamic_cpu_clock(clock_id: u64) -> Option<DynamicCpuClock> {
    // clockid_t is a 32-bit `int`; the guest may zero- OR sign-extend it into
    // x0 (the vDSO __kernel_clock_gettime fast-path loads only w0, so a dynamic
    // id arrives as a LARGE positive u64, not sign-extended). Interpret as i32:
    // static CLOCK_* ids are small non-negative; dynamic per-task ids are
    // negative. Bit layout (clean-room from clock_getcpuclockid(3) + observed
    // Docker encodings): low 2 bits = clock type (SCHED=2), low 3 bits == 3 is
    // CPUCLOCK_FD (not a CPU clock), bit 2 (mask 4) = CPUCLOCK_PERTHREAD.
    if (clock_id as i32) >= 0 {
        return None;
    }
    if (clock_id & 0b11) as u8 == 3 {
        return None;
    }
    if clock_id & 0b100 != 0 {
        Some(DynamicCpuClock::PerThread)
    } else {
        Some(DynamicCpuClock::PerProcess)
    }
}

fn linux_clock_duration(clock_id: u64) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Some(realtime_duration()),
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW | LINUX_CLOCK_MONOTONIC_COARSE => {
            Some(monotonic_duration())
        }
        // BOOTTIME includes suspend time; on macOS that is CLOCK_MONOTONIC.
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => Some(boottime_duration()),
        // Linux↔macOS clock-id numbering DIFFERS, so map the Linux ids to
        // the host's symbolic libc constants rather than passing through.
        LINUX_CLOCK_PROCESS_CPUTIME_ID => host_clock_duration(libc::CLOCK_PROCESS_CPUTIME_ID),
        LINUX_CLOCK_THREAD_CPUTIME_ID => host_clock_duration(libc::CLOCK_THREAD_CPUTIME_ID),
        // A dynamic per-task CPU-clock id (negative) → best-effort current
        // thread/process CPU time (CLOCK_PROCESS_CPUTIME_ID may be unimplemented
        // on some hosts, so fall back to the thread clock).
        _ => match dynamic_cpu_clock(clock_id)? {
            DynamicCpuClock::PerThread => host_clock_duration(libc::CLOCK_THREAD_CPUTIME_ID),
            DynamicCpuClock::PerProcess => host_clock_duration(libc::CLOCK_PROCESS_CPUTIME_ID)
                .or_else(|| host_clock_duration(libc::CLOCK_THREAD_CPUTIME_ID)),
        },
    }
}

/// Linux clock_getres resolution in nanoseconds, selected per clock id.
///
/// The exact value is NOT a host-portable invariant: a CONFIG_HIGH_RES_TIMERS
/// kernel reports 1ns for the hrtimer-backed clocks, but a low-res kernel —
/// e.g. Docker Desktop's LinuxKit VM at CONFIG_HZ=1000 — reports TICK_NSEC =
/// 1ms for ALL of them (verified live: clock_getres on REALTIME/MONOTONIC/
/// MONOTONIC_RAW/BOOTTIME returns tv_nsec==1000000 under `gcc:13` linux/arm64).
/// carrick therefore reports the 1ms stand-in (LINUX_CLOCK_RESOLUTION_NSEC),
/// which matches the Docker oracle on these hosts. The clockgetres probe
/// asserts only the portable invariant (rc==0, tv_sec==0). The per-clock match
/// is retained so a future CONFIG_HZ/hrtimer-aware value can be wired in here
/// without re-plumbing the call site. Only clocks `linux_clock_duration`
/// returns Some for reach this (clock_getres rejects unknown ids with EINVAL
/// before the write).
fn linux_clock_getres_nsec(clock_id: u64) -> i64 {
    match clock_id {
        // hrtimer-backed hi-res clocks (1ns on a CONFIG_HIGH_RES_TIMERS
        // kernel) and the posix CPU clocks. The 1ms stand-in is what the
        // low-res Docker host kernels actually report; the value is not
        // probe-asserted, so this stays host-portable.
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_MONOTONIC
        | LINUX_CLOCK_MONOTONIC_RAW
        | LINUX_CLOCK_BOOTTIME
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_BOOTTIME_ALARM
        | LINUX_CLOCK_TAI
        | LINUX_CLOCK_PROCESS_CPUTIME_ID
        | LINUX_CLOCK_THREAD_CPUTIME_ID => LINUX_CLOCK_RESOLUTION_NSEC,
        // COARSE clocks report TICK_NSEC (CONFIG_HZ-dependent, NOT
        // host-portable). Same 1ms stand-in; not probe-asserted.
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE => LINUX_CLOCK_RESOLUTION_NSEC,
        _ => LINUX_CLOCK_RESOLUTION_NSEC,
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
    // Linux CLOCK_MONOTONIC does NOT advance while the system is suspended.
    // On macOS that is CLOCK_UPTIME_RAW (mach_absolute_time) — NOT macOS
    // CLOCK_MONOTONIC, which (unlike Linux) keeps counting through sleep and
    // therefore corresponds to Linux CLOCK_BOOTTIME (see `boottime_duration`).
    host_clock_duration(libc::CLOCK_UPTIME_RAW).unwrap_or(Duration::ZERO)
}

fn boottime_duration() -> Duration {
    // Linux CLOCK_BOOTTIME = CLOCK_MONOTONIC + time spent suspended. macOS
    // CLOCK_MONOTONIC (backed by mach_continuous_time) is exactly that: it
    // continues to advance while the system sleeps, so it is >= the
    // suspend-excluding `monotonic_duration` above.
    host_clock_duration(libc::CLOCK_MONOTONIC).unwrap_or_else(monotonic_duration)
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
    write_stat_record(memory, statbuf, &StatRecord::from_metadata(metadata))
}

fn write_stat_record(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: record.ino,
        st_mode: record.mode,
        st_nlink: record.nlink,
        st_uid: record.uid,
        st_gid: record.gid,
        st_rdev: 0,
        __pad1: 0,
        st_size: record.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks_512(size),
        st_atime: record.atime.0,
        st_atime_nsec: record.atime.1 as u64,
        st_mtime: record.mtime.0,
        st_mtime_nsec: record.mtime.1 as u64,
        st_ctime: record.ctime.0,
        st_ctime_nsec: record.ctime.1 as u64,
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
        ino: st.st_ino,
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
    write_stat_record(memory, statbuf, &StatRecord::from_real(path, real))
}

/// `statx` counterpart of [`write_stat_real`].
fn write_statx_real(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    path: &str,
    real: &crate::fs_backend::RealStat,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_real(path, real))
}

fn write_statx(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_metadata(metadata))
}

fn write_statx_record(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let zero_time = LinuxStatxTimestamp::zero();
    let stx_ts = |t: (i64, i64)| LinuxStatxTimestamp {
        tv_sec: t.0,
        tv_nsec: t.1 as u32,
        __reserved: 0,
    };
    let size = record.size_usize();
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: record.nlink,
        stx_uid: record.uid,
        stx_gid: record.gid,
        stx_mode: record.mode as u16,
        __spare0: [0; 1],
        stx_ino: record.ino,
        stx_size: record.size,
        stx_blocks: blocks_512(size) as u64,
        stx_attributes_mask: 0,
        stx_atime: stx_ts(record.atime),
        stx_btime: zero_time,
        stx_ctime: stx_ts(record.ctime),
        stx_mtime: stx_ts(record.mtime),
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
    write_stat_record(memory, statbuf, &StatRecord::synthetic(path, size, mode))
}

fn write_synthetic_statx(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
) -> DispatchOutcome {
    write_synthetic_statx_mode(memory, statxbuf, path, size, LINUX_S_IFREG | 0o444)
}

/// Like `write_synthetic_statx` but accepts an explicit `mode` word
/// (S_IF* type bits | permission bits) instead of deriving it from a
/// `RootFsEntryKind`. Used for fd types that don't map to a VFS kind,
/// such as pty character devices (S_IFCHR) and anonymous pipes (S_IFIFO).
fn write_synthetic_statx_mode(
    memory: &mut impl GuestMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
    mode: u32,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::synthetic(path, size, mode))
}

impl SyscallDispatcher {
    fn mem_snapshot(&self) -> mem::MemState {
        self.mem.lock().clone()
    }

    fn synthetic_proc_context(&self) -> crate::vfs::SyntheticProcContext {
        let proc = self.proc.lock();
        let mem = self.mem_snapshot();
        crate::vfs::SyntheticProcContext {
            executable_path: proc.executable_path.clone(),
            argv: proc.argv.clone(),
            address_space_regions: mem.address_space_regions,
            brk_current: mem.brk_current,
            mmap_next: mem.mmap_next,
        }
    }
}

fn read_eventfd(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    state: &EventFdState,
    semaphore: bool,
    nonblocking: bool,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxEventfdValue>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let mut counter = state.counter.lock();
    while *counter == 0 {
        if nonblocking {
            return DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            };
        }
        state.readable.wait(&mut counter);
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
    // Keep the host readiness pipe in sync (drains it when the counter hits 0,
    // so the read end stops being readable; EFD_SEMAPHORE keeps it readable
    // while the counter is still > 0).
    state.sync_readiness(*counter);
    DispatchOutcome::Returned {
        value: core::mem::size_of::<LinuxEventfdValue>() as i64,
    }
}

fn write_eventfd(bytes: &[u8], state: &EventFdState) -> DispatchOutcome {
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
    let mut counter = state.counter.lock();
    let Some(next) = (*counter).checked_add(increment) else {
        return DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        };
    };
    let was_zero = *counter == 0;
    *counter = next;
    // Mirror readiness onto the host pipe so the epoll instance kqueue sees it
    // natively (level-triggered, can't be lost) — the robust path for Go's
    // netpollBreak.
    state.sync_readiness(next);
    if was_zero && next > 0 {
        state.readable.notify_all();
        // Belt-and-suspenders for any epoll instance that (rarely) registered
        // the eventfd before its host fd was available: also poke the in-memory
        // wake broadcast. Redundant with the host-backed pipe above; harmless.
        drop(counter);
        notify_inmem_epoll();
    }
    DispatchOutcome::Returned {
        value: core::mem::size_of::<LinuxEventfdValue>() as i64,
    }
}

fn read_timerfd(
    memory: &mut impl GuestMemory,
    address: u64,
    length: usize,
    state: &TimerFdState,
    nonblocking: bool,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxTimerfdExpirations>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let mut timer = state.inner.lock();
    loop {
        let ready = refresh_timerfd_locked(&mut timer);
        if ready > 0 {
            let value = LinuxTimerfdExpirations {
                expirations: timer.expirations,
            };
            if write_kernel_struct_raw(memory, address, &value).is_err() {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
            timer.expirations = 0;
            return DispatchOutcome::Returned {
                value: core::mem::size_of::<LinuxTimerfdExpirations>() as i64,
            };
        }

        if nonblocking {
            return DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            };
        }

        let Some(deadline) = timer.deadline else {
            state.changed.wait(&mut timer);
            continue;
        };
        let Some(now) = linux_clock_duration(timer.clock_id) else {
            state.changed.wait(&mut timer);
            continue;
        };
        let wait = deadline.saturating_sub(now);
        if wait.is_zero() {
            continue;
        }
        state.changed.wait_for(&mut timer, wait);
    }
}

fn refresh_timerfd_locked(timer: &mut TimerFdInner) -> u64 {
    let (ready, next_deadline) = timerfd_expirations(
        timer.clock_id,
        timer.interval,
        timer.deadline,
        timer.expirations,
    );
    timer.expirations = ready;
    timer.deadline = next_deadline;
    ready
}

fn timerfd_ready_count(state: &TimerFdState) -> u64 {
    let mut timer = state.inner.lock();
    refresh_timerfd_locked(&mut timer)
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
    pipe: &PipeRef,
    _status_flags: u64,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    let mut pipe = pipe.lock();
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

fn take_pipe_bytes(pipe: &PipeRef, length: usize, _status_flags: u64) -> Result<Vec<u8>, i32> {
    let mut pipe = pipe.lock();
    if pipe.buffer.is_empty() {
        if pipe.writers == 0 {
            return Ok(Vec::new());
        }
        return Err(LINUX_EAGAIN);
    }

    let read_len = pipe.buffer.len().min(length);
    Ok(pipe.buffer.drain(..read_len).collect())
}

fn write_pipe(bytes: &[u8], pipe: &PipeRef) -> DispatchOutcome {
    let mut pipe = pipe.lock();
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
    read_kernel_struct(memory, address)
}

fn read_itimerval(memory: &impl GuestMemory, address: u64) -> Result<LinuxItimerval, i32> {
    read_kernel_struct(memory, address)
}

fn read_timespec(memory: &impl GuestMemory, address: u64) -> Result<LinuxTimespec, i32> {
    read_kernel_struct(memory, address)
}

fn read_open_how(memory: &impl GuestMemory, address: u64) -> Result<LinuxOpenHow, i32> {
    read_kernel_struct(memory, address)
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
    // Linux validates the iov array at syscall entry (rw_copy_check_uvector):
    // each iov_len and the running total must stay within SSIZE_MAX, else
    // EINVAL — NOT EFAULT. carrick previously let an oversized iov_len fall
    // through to a `read_bytes(base, huge)` that EFAULTed (LTP writev01).
    const SSIZE_MAX: u64 = i64::MAX as u64;
    let mut total: u64 = 0;
    for index in 0..count {
        let offset = index
            .checked_mul(size)
            .and_then(|offset| u64::try_from(offset).ok())
            .ok_or(LINUX_EINVAL)?;
        let iovec_address = address.checked_add(offset).ok_or(LINUX_EFAULT)?;
        let iovec: LinuxIovec = read_kernel_struct(memory, iovec_address)?;
        if iovec.iov_len > SSIZE_MAX {
            return Err(LINUX_EINVAL);
        }
        total = total.checked_add(iovec.iov_len).ok_or(LINUX_EINVAL)?;
        if total > SSIZE_MAX {
            return Err(LINUX_EINVAL);
        }
        iovecs.push(iovec);
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
        RootFsEntryKind::CharDevice => LINUX_S_IFCHR,
        RootFsEntryKind::Fifo => LINUX_S_IFIFO,
        RootFsEntryKind::Socket => LINUX_S_IFSOCK,
    };
    kind | (metadata.mode & 0o7777)
}

/// Parse `CARRICK_WATCH_ADDR` (hex, optional `0x`) once. `None` disables the
/// guest-memory watchpoint (the common, zero-cost case).
fn watch_addr() -> Option<u64> {
    static WATCH_ADDR: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *WATCH_ADDR.get_or_init(|| {
        std::env::var("CARRICK_WATCH_ADDR").ok().and_then(|s| {
            let s = s.trim();
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16).ok()
        })
    })
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
    // `entry.name` is in the VFS layer's reversible escape form; decode back to
    // the opaque directory-entry BYTES so an undecodable filename round-trips
    // through getdents (Linux d_name is raw bytes, not UTF-8). Valid-UTF-8
    // names decode to themselves.
    let name_bytes = crate::pathcodec::decode_to_bytes(&entry.name);
    let name = name_bytes.as_slice();
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
        RootFsEntryKind::CharDevice => LINUX_DT_CHR,
        RootFsEntryKind::Fifo => LINUX_DT_FIFO,
        RootFsEntryKind::Socket => LINUX_DT_SOCK,
    }
}

fn align_to(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn inode_for_path(path: &Path) -> u64 {
    // Inode numbers must reflect file *identity*, not the textual path used to
    // reach the file. stat("/a/b") and stat(".") from inside /a/b must agree,
    // or TOCTOU identity checks abort — dpkg-preconfigure stats a directory,
    // chdirs in, re-stats ".", and bails with "directory … changed before
    // chdir, expected ino=X, actual ino=Y". Normalise the path lexically
    // (collapse ".", "..", and "//") before hashing so every spelling of one
    // path maps to one inode. `normalize` returns None for paths that escape
    // the root ("/.."); fall back to the raw bytes there so we never panic.
    // Hash the RAW path bytes so an undecodable filename gets a stable,
    // distinct inode — to_string_lossy would collapse different undecodable
    // spellings to the same U+FFFD soup. The path may arrive in EITHER form:
    // the VFS layer's reversible escape (`&str`-derived, e.g. a synthetic
    // stat) OR already-raw bytes (a `normalize`-decoded PathBuf from getdents).
    // Canonicalise to raw bytes first so both spellings of one file agree.
    use std::os::unix::ffi::OsStrExt;
    let os_bytes = path.as_os_str().as_bytes();
    let decoded_owned;
    let canon_bytes: &[u8] = match std::str::from_utf8(os_bytes) {
        Ok(s) if crate::pathcodec::has_escaped_bytes(s) => {
            decoded_owned = crate::pathcodec::decode_to_bytes(s);
            &decoded_owned
        }
        _ => os_bytes,
    };
    let normalized =
        crate::fs_backend::normalize_raw(Path::new(std::ffi::OsStr::from_bytes(canon_bytes)));
    let key_os = normalized
        .as_ref()
        .map(|p| p.as_os_str().as_bytes())
        .unwrap_or(canon_bytes);
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in key_os {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash.max(1)
}

fn join_rootfs_path(base: &str, path: &str) -> String {
    let mut parts = Vec::new();
    for component in Path::new(base)
        .components()
        .chain(Path::new(path).components())
    {
        match component {
            Component::Prefix(_) => {}
            Component::RootDir => parts.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(name) => parts.push(name.to_string_lossy().into_owned()),
        }
    }
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
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

/// Read a NULL-terminated array of guest VA pointers, dereferencing each to a
/// C string as RAW BYTES — for `argv` / `envp` in `execve(2)`, which Linux
/// treats as opaque byte strings (NOT UTF-8). See [`read_guest_c_string_bytes`].
fn read_guest_string_array_bytes(
    memory: &impl GuestMemory,
    array_addr: u64,
) -> Result<Vec<Vec<u8>>, i32> {
    if array_addr == 0 {
        return Ok(Vec::new());
    }
    const MAX_ENTRIES: usize = 4096;
    let mut out = Vec::new();
    for index in 0..MAX_ENTRIES {
        let slot_addr = array_addr
            .checked_add((index as u64) * 8)
            .ok_or(LINUX_E2BIG)?;
        let bytes = memory.read_bytes(slot_addr, 8).map_err(|_| LINUX_EFAULT)?;
        let ptr = u64::from_le_bytes(bytes.try_into().map_err(|_| LINUX_EFAULT)?);
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_guest_c_string_bytes(memory, ptr)?);
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
            crate::vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
            crate::vfs::EntryKind::Fifo => RootFsEntryKind::Fifo,
            crate::vfs::EntryKind::Socket => RootFsEntryKind::Socket,
        },
        mode: md.mode,
        size: md.size as usize,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostSyscallError {
    raw_errno: i32,
    linux_errno: i32,
}

impl HostSyscallError {
    pub(crate) fn last() -> Self {
        // SAFETY: `__errno_location` (Linux) and `__error` (macOS) both
        // return a thread-local int pointer.
        let raw_errno = unsafe { *libc::__error() };
        Self {
            raw_errno,
            linux_errno: macos_to_linux_errno(raw_errno),
        }
    }

    #[cfg(test)]
    pub(crate) fn raw_errno(self) -> i32 {
        self.raw_errno
    }

    pub(crate) fn linux_errno(self) -> i32 {
        self.linux_errno
    }
}

pub(crate) trait HostSyscallResult: Sized {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError>;

    fn host_syscall_errno(self) -> Result<Self, i32> {
        self.host_syscall_result()
            .map_err(HostSyscallError::linux_errno)
    }
}

impl HostSyscallResult for i32 {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

impl HostSyscallResult for isize {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

impl HostSyscallResult for i64 {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError> {
        if self < 0 {
            Err(HostSyscallError::last())
        } else {
            Ok(self)
        }
    }
}

/// Linux UAPI errno values. Sourced from
/// `linux/include/uapi/asm-generic/errno-base.h` and `errno.h`.
/// Hardcoded here so the translation is independent of whatever the
/// host's libc decided to name (or number) these — when we run on
/// macOS, `libc::EAGAIN` is 35, but Linux's EAGAIN is 11. We need
/// constant Linux numbers regardless of host.
/// Linux UAPI errno values, re-exported under their bare names from the
/// canonical table in `crate::linux_abi`. Sourced originally from
/// `linux/include/uapi/asm-generic/errno-base.h` and `errno.h`. The Linux
/// numbers are hardcoded (in `linux_abi`) so the translation is independent
/// of whatever the host's libc decided to name (or number) these — on macOS
/// `libc::EAGAIN` is 35, but Linux's EAGAIN is 11. `macos_to_linux_errno`
/// and its tests refer to these as `linux_errno::EFAULT`; the numbers live
/// in exactly one place (linux_abi's `LINUX_E*`) so the two can't drift.
#[allow(dead_code)]
pub mod linux_errno {
    pub use crate::linux_abi::{
        LINUX_E2BIG as E2BIG, LINUX_EACCES as EACCES, LINUX_EADDRINUSE as EADDRINUSE,
        LINUX_EADDRNOTAVAIL as EADDRNOTAVAIL, LINUX_EAFNOSUPPORT as EAFNOSUPPORT,
        LINUX_EAGAIN as EAGAIN, LINUX_EALREADY as EALREADY, LINUX_EBADF as EBADF,
        LINUX_EBADMSG as EBADMSG, LINUX_EBUSY as EBUSY, LINUX_ECANCELED as ECANCELED,
        LINUX_ECHILD as ECHILD, LINUX_ECONNABORTED as ECONNABORTED,
        LINUX_ECONNREFUSED as ECONNREFUSED, LINUX_ECONNRESET as ECONNRESET,
        LINUX_EDEADLK as EDEADLK, LINUX_EDESTADDRREQ as EDESTADDRREQ, LINUX_EDOM as EDOM,
        LINUX_EDQUOT as EDQUOT, LINUX_EEXIST as EEXIST, LINUX_EFAULT as EFAULT,
        LINUX_EFBIG as EFBIG, LINUX_EHOSTDOWN as EHOSTDOWN, LINUX_EHOSTUNREACH as EHOSTUNREACH,
        LINUX_EIDRM as EIDRM, LINUX_EILSEQ as EILSEQ, LINUX_EINPROGRESS as EINPROGRESS,
        LINUX_EINTR as EINTR, LINUX_EINVAL as EINVAL, LINUX_EIO as EIO, LINUX_EISCONN as EISCONN,
        LINUX_EISDIR as EISDIR, LINUX_ELOOP as ELOOP, LINUX_EMFILE as EMFILE,
        LINUX_EMLINK as EMLINK, LINUX_EMSGSIZE as EMSGSIZE, LINUX_ENAMETOOLONG as ENAMETOOLONG,
        LINUX_ENETDOWN as ENETDOWN, LINUX_ENETRESET as ENETRESET, LINUX_ENETUNREACH as ENETUNREACH,
        LINUX_ENFILE as ENFILE, LINUX_ENOBUFS as ENOBUFS, LINUX_ENODEV as ENODEV,
        LINUX_ENOENT as ENOENT, LINUX_ENOEXEC as ENOEXEC, LINUX_ENOLCK as ENOLCK,
        LINUX_ENOLINK as ENOLINK, LINUX_ENOMEM as ENOMEM, LINUX_ENOMSG as ENOMSG,
        LINUX_ENOPROTOOPT as ENOPROTOOPT, LINUX_ENOSPC as ENOSPC, LINUX_ENOSYS as ENOSYS,
        LINUX_ENOTBLK as ENOTBLK, LINUX_ENOTCONN as ENOTCONN, LINUX_ENOTDIR as ENOTDIR,
        LINUX_ENOTEMPTY as ENOTEMPTY, LINUX_ENOTSOCK as ENOTSOCK, LINUX_ENOTTY as ENOTTY,
        LINUX_ENXIO as ENXIO, LINUX_EOPNOTSUPP as EOPNOTSUPP, LINUX_EOVERFLOW as EOVERFLOW,
        LINUX_EPERM as EPERM, LINUX_EPFNOSUPPORT as EPFNOSUPPORT, LINUX_EPIPE as EPIPE,
        LINUX_EPROTONOSUPPORT as EPROTONOSUPPORT, LINUX_EPROTOTYPE as EPROTOTYPE,
        LINUX_ERANGE as ERANGE, LINUX_EREMOTE as EREMOTE, LINUX_EROFS as EROFS,
        LINUX_ESHUTDOWN as ESHUTDOWN, LINUX_ESOCKTNOSUPPORT as ESOCKTNOSUPPORT,
        LINUX_ESPIPE as ESPIPE, LINUX_ESRCH as ESRCH, LINUX_ESTALE as ESTALE,
        LINUX_ETIMEDOUT as ETIMEDOUT, LINUX_ETOOMANYREFS as ETOOMANYREFS, LINUX_ETXTBSY as ETXTBSY,
        LINUX_EUCLEAN as EUCLEAN, LINUX_EXDEV as EXDEV,
    };
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
            // macOS ENOATTR ("attribute not found", 93) is Linux ENODATA (61) —
            // what getxattr/removexattr return for a missing xattr. Without
            // this it collapsed to EIO and LTP getxattr01/removexattr* failed
            // their ENODATA expectation.
            x if x == libc::ENOATTR => crate::linux_abi::LINUX_ENODATA,
            // Codes 1..=34 overlap; unmapped Darwin extension errnos above
            // that range are not Linux numbers, so collapse them to EIO
            // rather than leaking host-specific values to the guest.
            other if (1..=34).contains(&other) => other,
            _ => EIO,
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

/// Linux clamps a single read/recv/getrandom transfer to MAX_RW_COUNT (INT_MAX
/// rounded down to a page) and returns a short count; it never allocates the
/// caller's raw count. carrick stages guest reads into a host Vec, so without
/// this clamp a huge guest count is an immediate multi-terabyte allocation that
/// aborts the whole runtime (a one-syscall DoS). Probe: `bigread`.
pub(crate) const MAX_RW_COUNT: usize = 0x7fff_f000;

/// read(2) on a host-backed fd (pipe/socket/file). read has no per-call
/// non-blocking flag, so we put the host fd non-blocking (idempotent; immaterial
/// for files, which never block) and convert EAGAIN: a blocking-mode guest fd
/// hands off to the runtime's lockless kqueue wait via WaitOnFds; a non-blocking
/// guest fd gets EAGAIN. Never blocks under the dispatcher lock. `nonblocking` is
/// the guest's intended mode (status_flags / O_NONBLOCK).
fn read_host_pipe(
    memory: &mut impl GuestMemory,
    guest_addr: u64,
    length: usize,
    host_fd: i32,
    nonblocking: bool,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    // Clamp to Linux's MAX_RW_COUNT before staging a host buffer; a huge guest
    // count would otherwise be a one-syscall OOM-abort of the runtime.
    let length = length.min(MAX_RW_COUNT);
    crate::dispatch::net::set_host_nonblocking(host_fd);
    let mut buf = vec![0u8; length];
    let n = unsafe { libc::read(host_fd, buf.as_mut_ptr() as *mut _, length) };
    #[cfg(target_os = "macos")]
    crate::probes::host_pipe_io(host_fd, 0, n as i64);
    if let Err(e) = n.host_syscall_errno() {
        // EINTR: interrupted by a HOST signal. Don't surface it to the guest —
        // carrick's internal machinery raises frequent host signals (e.g. the
        // SIGURG vCPU kick), and leaking their EINTR spins the guest's read in
        // an infinite retry loop. Route through the readiness wait, which
        // retries transparently and only returns guest-EINTR when a deliverable
        // guest signal is actually pending (has_pending_for). Same discipline as
        // host_sleep_interruptible.
        if e == LINUX_EAGAIN || e == LINUX_EINTR {
            return would_block_outcome(host_fd, libc::POLLIN, nonblocking);
        }
        return DispatchOutcome::Errno { errno: e };
    }
    let n_usize = n as usize;
    if std::env::var_os("CARRICK_IO_DBG").is_some() && n_usize > 0 {
        eprintln!(
            "[IODBG] READ host_fd={host_fd} n={n_usize} bytes={:02x?}",
            &buf[..n_usize.min(64)]
        );
    }
    if n_usize > 0 && memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    DispatchOutcome::Returned { value: n as i64 }
}

/// write(2) on a host-backed fd. Same lockless discipline as `read_host_pipe`.
fn write_host_pipe(bytes: &[u8], host_fd: i32, nonblocking: bool) -> DispatchOutcome {
    const LINUX_PIPE_BUF: usize = 4096;
    if std::env::var_os("CARRICK_IO_DBG").is_some() && !bytes.is_empty() {
        eprintln!(
            "[IODBG] WRITE host_fd={host_fd} n={} bytes={:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(64)]
        );
    }
    crate::dispatch::net::set_host_nonblocking(host_fd);
    let complete_atomic_pipe_write = !nonblocking && bytes.len() <= LINUX_PIPE_BUF && {
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        (unsafe { libc::fstat(host_fd, &mut st) }) == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO
    };
    let mut offset = 0usize;
    loop {
        if std::env::var_os("CARRICK_TTY_DBG").is_some() && bytes.contains(&0x0a) {
            unsafe {
                let isatty = libc::isatty(host_fd);
                let mut t: libc::termios = core::mem::zeroed();
                let tg = libc::tcgetattr(host_fd, &mut t);
                let mut outq: libc::c_int = -1;
                libc::ioctl(host_fd, libc::TIOCOUTQ, &mut outq);
                let fl = libc::fcntl(host_fd, libc::F_GETFL);
                let mut st: libc::stat = core::mem::zeroed();
                libc::fstat(host_fd, &mut st);
                let oflag = t.c_oflag;
                let lflag = t.c_lflag;
                let rdev = st.st_rdev;
                let blen = bytes.len();
                eprintln!(
                    "[TTYDBG-PRE] host_fd={host_fd} isatty={isatty} tg={tg} oflag=0x{oflag:x} lflag=0x{lflag:x} outq={outq} flags=0x{fl:x} rdev={rdev} n={blen}"
                );
            }
        }
        let n = unsafe {
            libc::write(
                host_fd,
                bytes[offset..].as_ptr() as *const _,
                bytes.len() - offset,
            )
        };
        if std::env::var_os("CARRICK_TTY_DBG").is_some() && bytes.contains(&0x0a) {
            unsafe {
                let mut outq: libc::c_int = -1;
                libc::ioctl(host_fd, libc::TIOCOUTQ, &mut outq);
                eprintln!("[TTYDBG-POST] host_fd={host_fd} wrote={n} outq_after={outq}");
            }
        }
        #[cfg(target_os = "macos")]
        crate::probes::host_pipe_io(host_fd, 1, n as i64);
        if let Err(e) = n.host_syscall_errno() {
            // EINTR: interrupted by an internal host signal (e.g. SIGURG vCPU kick).
            // Route through the readiness wait rather than leaking it to the guest
            // (see read_host_pipe).
            if e == LINUX_EAGAIN || e == LINUX_EINTR {
                if complete_atomic_pipe_write && offset > 0 {
                    let mut pfd = libc::pollfd {
                        fd: host_fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe { libc::poll(&mut pfd, 1, -1) };
                    continue;
                }
                return would_block_outcome(host_fd, libc::POLLOUT, nonblocking);
            }
            return DispatchOutcome::Errno { errno: e };
        }
        if complete_atomic_pipe_write {
            offset += n as usize;
            if offset < bytes.len() {
                continue;
            }
            return DispatchOutcome::Returned {
                value: bytes.len() as i64,
            };
        }
        return DispatchOutcome::Returned { value: n as i64 };
    }
}

/// A host op returned EAGAIN: a non-blocking guest fd gets EAGAIN; a blocking
/// one gets a WaitOnFds hand-off so the runtime waits on readiness with the
/// dispatcher lock RELEASED (per-thread kqueue), then re-dispatches.
fn would_block_outcome(host_fd: i32, events: i16, nonblocking: bool) -> DispatchOutcome {
    if nonblocking {
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        }
    } else {
        DispatchOutcome::WaitOnFds {
            fds: vec![(host_fd, events)],
            timeout: None,
            on_timeout: -(LINUX_EAGAIN as i64),
            block_signals: 0,
        }
    }
}

/// Read a NUL-terminated C string from guest memory as RAW BYTES. Linux paths/
/// argv/env are OPAQUE byte strings, not UTF-8 — e.g. CPython's regrtest sets a
/// non-UTF-8 `PYTHONREGRTEST_UNICODE_GUARD` env var, which made an execve EINVAL
/// when carrick required UTF-8. The execve argv/env path keeps these bytes
/// verbatim; callers needing a Rust `String` (fs path lookup) use the wrapper.
fn read_guest_c_string_bytes(memory: &impl GuestMemory, address: u64) -> Result<Vec<u8>, i32> {
    const CHUNK: usize = 256;
    let mut bytes = Vec::new();
    let mut offset = 0usize;
    while offset < MAX_GUEST_PATH {
        let address = address
            .checked_add(offset as u64)
            .ok_or(LINUX_ENAMETOOLONG)?;
        let to_read = CHUNK.min(MAX_GUEST_PATH - offset);
        let chunk = match memory.read_bytes(address, to_read) {
            Ok(chunk) => chunk,
            Err(_) if to_read > 1 => memory.read_bytes(address, 1).map_err(|_| LINUX_EFAULT)?,
            Err(_) => return Err(LINUX_EFAULT),
        };
        if let Some(nul) = chunk.iter().position(|&byte| byte == 0) {
            bytes.extend_from_slice(&chunk[..nul]);
            return Ok(bytes);
        }
        offset += chunk.len();
        bytes.extend_from_slice(&chunk);
    }
    Err(LINUX_ENAMETOOLONG)
}

/// As [`read_guest_c_string_bytes`], carried into a Rust `String` for the paths
/// carrick resolves against its String/Path-based fs layer. Linux paths are
/// opaque BYTES; rather than reject a non-UTF-8 path with EINVAL, undecodable
/// bytes are carried through the `&str` layer with a reversible escape
/// (`crate::pathcodec`) — valid UTF-8 is byte-for-byte unchanged (fast path),
/// and the escape is decoded back to the raw bytes at the guest-facing read-back
/// boundaries (getdents/readlink/getcwd). The encoded form also doubles as the
/// durable host representation, since APFS rejects a raw non-UTF-8 name (EILSEQ).
/// argv/env use the bytes form and never reach here.
fn read_guest_c_string(memory: &impl GuestMemory, address: u64) -> Result<String, i32> {
    Ok(crate::pathcodec::encode_bytes(&read_guest_c_string_bytes(
        memory, address,
    )?))
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

    fn eventfd_open_file(counter: u64) -> OpenFile {
        OpenFile::new(
            Arc::new(RwLock::new(OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(counter)),
                semaphore: false,
                base: OpenDescriptionBase::new(0),
            })),
            0,
        )
    }

    #[test]
    fn fd_install_helpers_reserve_single_and_pair_slots_atomically() {
        let dispatcher = SyscallDispatcher::new();

        let first = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(1)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected first fd install to succeed"),
        };
        assert_eq!(first, 3);

        let pair = match dispatcher.install_fd_pair_at_or_above(
            3,
            eventfd_open_file(2),
            eventfd_open_file(3),
        ) {
            Ok(pair) => pair,
            Err(_) => panic!("expected pair install to succeed"),
        };
        assert_eq!(pair, (4, 5));

        let next = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(4)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected next fd install to succeed"),
        };
        assert_eq!(next, 6);
    }

    #[test]
    fn close_cloexec_fds_removes_marked_descriptors_only() {
        let dispatcher = SyscallDispatcher::new();
        let keep_fd = match dispatcher.install_fd_at_or_above(3, eventfd_open_file(1)) {
            Ok(fd) => fd,
            Err(_) => panic!("expected keep fd install to succeed"),
        };
        let cloexec_fd = match dispatcher.install_fd_at_or_above(
            3,
            OpenFile::new(
                Arc::new(RwLock::new(OpenDescription::EventFd {
                    state: Arc::new(EventFdState::new(2)),
                    semaphore: false,
                    base: OpenDescriptionBase::new(0),
                })),
                LINUX_FD_CLOEXEC,
            ),
        ) {
            Ok(fd) => fd,
            Err(_) => panic!("expected cloexec fd install to succeed"),
        };

        dispatcher.close_cloexec_fds();

        assert!(dispatcher.fd_is_valid(keep_fd));
        assert!(!dispatcher.fd_is_valid(cloexec_fd));
    }

    #[test]
    fn threaded_independent_dispatch_support_matches_handler_table() {
        let supported: Vec<u64> = crate::syscall::aarch64_table()
            .iter()
            .filter(|syscall| threaded_independent_dispatch_supports(syscall.number))
            .map(|syscall| syscall.number)
            .collect();
        assert_eq!(supported, vec![96, 98, 99, 124, 178]);

        for syscall in crate::syscall::aarch64_table() {
            if syscall.handler == crate::syscall::SyscallHandler::ThreadLocal {
                assert!(
                    threaded_independent_dispatch_supports(syscall.number),
                    "thread-local syscall {} ({}) must be handled without panicking",
                    syscall.number,
                    syscall.name
                );
            }
        }
    }

    #[test]
    fn join_rootfs_path_normalizes_relative_components() {
        assert_eq!(join_rootfs_path("/", "."), "/");
        assert_eq!(join_rootfs_path("/", ".."), "/");
        assert_eq!(join_rootfs_path("/tmp/work", ".."), "/tmp");
        assert_eq!(join_rootfs_path("/tmp/work", "../other/."), "/tmp/other");
        assert_eq!(join_rootfs_path("/tmp/work", "../../.."), "/");
    }

    #[test]
    fn inode_for_path_reflects_identity_not_textual_spelling() {
        // The same file reached via different textual spellings must map to
        // ONE inode, or TOCTOU identity checks abort: dpkg-preconfigure stats
        // a dir, chdirs in, re-stats ".", and aborts if the inode changed
        // ("directory /var/cache/debconf/tmp.ci changed before chdir").
        // "." after chdir resolves to "/dir/.", so that must hash the same as
        // "/dir".
        let canonical = inode_for_path(Path::new("/tmp/d"));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/.")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp//d")));
        assert_eq!(canonical, inode_for_path(Path::new("/tmp/d/sub/..")));
        // Distinct files still get distinct inodes.
        assert_ne!(canonical, inode_for_path(Path::new("/tmp/e")));
        // Never zero — some tools treat st_ino == 0 as "no such entry".
        assert_ne!(inode_for_path(Path::new("/")), 0);
        assert_ne!(inode_for_path(Path::new("/tmp/d")), 0);
    }

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
                .dispatch(request, &mut self.memory, &self.reporter)
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

    #[test]
    fn read_kernel_struct_accepts_unaligned_abi_reads_and_rejects_bad_pointers() {
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let address = MEM_BASE + 3;
        let expected = LinuxTimespec::new(12, 34);
        memory.write_bytes(address, expected.abi_bytes()).unwrap();

        let actual: LinuxTimespec = read_kernel_struct(&memory, address).unwrap();
        let tv_sec = actual.tv_sec;
        let tv_nsec = actual.tv_nsec;
        assert_eq!((tv_sec, tv_nsec), (12, 34));

        assert_eq!(
            read_kernel_struct::<LinuxTimespec>(&memory, 0),
            Err(LINUX_EFAULT)
        );
        assert_eq!(
            read_kernel_struct::<LinuxTimespec>(&memory, MEM_BASE + MEM_LEN as u64 - 1),
            Err(LINUX_EFAULT)
        );
    }

    #[test]
    fn read_kernel_prefix_zero_fills_truncated_clone_args_and_rejects_overlarge_reads() {
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
        let address = MEM_BASE + 5;
        let flags = LinuxCloneFlags::THREAD_MASK | LinuxCloneFlags::SETTLS.bits();
        memory.write_bytes(address, &flags.to_ne_bytes()).unwrap();

        let args: LinuxCloneArgs = read_kernel_prefix(&memory, address, 8).unwrap();
        let actual_flags = args.flags;
        let tls = args.tls;
        assert_eq!(actual_flags, flags);
        assert_eq!(tls, 0);

        assert_eq!(
            read_kernel_prefix::<LinuxCloneArgs>(
                &memory,
                address,
                <LinuxCloneArgs as KernelAbi>::ABI_SIZE + 1,
            ),
            Err(LINUX_EFAULT)
        );
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
        let _ = h.call(
            SYS_PIPE2,
            [buf, LINUX_O_CLOEXEC | LINUX_O_NONBLOCK, 0, 0, 0, 0],
        );
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
        assert_eq!(
            macos_to_linux_errno(libc::EINPROGRESS),
            linux_errno::EINPROGRESS
        );
        assert_ne!(
            macos_to_linux_errno(libc::EINPROGRESS),
            36,
            "EINPROGRESS != Linux ENAMETOOLONG"
        );
        // Sample of network errnos that matter for apt's HTTP method.
        assert_eq!(macos_to_linux_errno(libc::EAGAIN), linux_errno::EAGAIN);
        assert_eq!(
            macos_to_linux_errno(libc::ECONNREFUSED),
            linux_errno::ECONNREFUSED
        );
        assert_eq!(
            macos_to_linux_errno(libc::EHOSTUNREACH),
            linux_errno::EHOSTUNREACH
        );
        assert_eq!(
            macos_to_linux_errno(libc::ETIMEDOUT),
            linux_errno::ETIMEDOUT
        );
        assert_eq!(macos_to_linux_errno(libc::ENOTCONN), linux_errno::ENOTCONN);
        assert_eq!(
            macos_to_linux_errno(libc::ECONNRESET),
            linux_errno::ECONNRESET
        );
        assert_eq!(
            macos_to_linux_errno(libc::EADDRINUSE),
            linux_errno::EADDRINUSE
        );
        assert_eq!(
            macos_to_linux_errno(libc::EAFNOSUPPORT),
            linux_errno::EAFNOSUPPORT
        );
        // Filesystem errnos that diverge.
        assert_eq!(
            macos_to_linux_errno(libc::ENAMETOOLONG),
            linux_errno::ENAMETOOLONG
        );
        assert_eq!(
            macos_to_linux_errno(libc::ENOTEMPTY),
            linux_errno::ENOTEMPTY
        );
        assert_eq!(macos_to_linux_errno(libc::ELOOP), linux_errno::ELOOP);
        assert_eq!(macos_to_linux_errno(libc::ENOSYS), linux_errno::ENOSYS);
        assert_eq!(macos_to_linux_errno(libc::ENOLCK), linux_errno::ENOLCK);
        // Misc.
        assert_eq!(macos_to_linux_errno(libc::EIDRM), linux_errno::EIDRM);
        assert_eq!(macos_to_linux_errno(libc::EILSEQ), linux_errno::EILSEQ);
        assert_eq!(
            macos_to_linux_errno(libc::ECANCELED),
            linux_errno::ECANCELED
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn errno_translation_maps_unknown_darwin_extensions_to_eio() {
        use crate::dispatch::{linux_errno, macos_to_linux_errno};

        // ENOATTR ("attribute not found") maps to Linux ENODATA, the errno
        // getxattr/removexattr return for a missing xattr.
        assert_eq!(
            macos_to_linux_errno(libc::ENOATTR),
            crate::linux_abi::LINUX_ENODATA
        );
        assert_eq!(macos_to_linux_errno(999), linux_errno::EIO);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn host_syscall_result_translates_captured_host_errno() {
        use crate::dispatch::{HostSyscallResult, linux_errno};

        unsafe {
            *libc::__error() = libc::EINPROGRESS;
        }
        let err = (-1i32).host_syscall_result().unwrap_err();
        assert_eq!(err.raw_errno(), libc::EINPROGRESS);
        assert_eq!(err.linux_errno(), linux_errno::EINPROGRESS);
        assert_ne!(err.linux_errno(), libc::EINPROGRESS);

        unsafe {
            *libc::__error() = libc::EAGAIN;
        }
        assert_eq!(
            (-1isize).host_syscall_result().unwrap_err().linux_errno(),
            linux_errno::EAGAIN
        );

        unsafe {
            *libc::__error() = libc::ECONNREFUSED;
        }
        assert_eq!(
            (-1i64).host_syscall_errno().unwrap_err(),
            linux_errno::ECONNREFUSED
        );

        assert_eq!(0i32.host_syscall_result().unwrap(), 0);
    }

    struct CountingMemory {
        base: u64,
        bytes: Vec<u8>,
        reads: std::cell::Cell<usize>,
    }

    impl CountingMemory {
        fn new(base: u64, bytes: Vec<u8>) -> Self {
            Self {
                base,
                bytes,
                reads: std::cell::Cell::new(0),
            }
        }
    }

    impl GuestMemory for CountingMemory {
        fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.reads.set(self.reads.get() + 1);
            let offset = address
                .checked_sub(self.base)
                .ok_or(MemoryError::OutOfBounds { address, length })?;
            let offset = usize::try_from(offset)
                .map_err(|_| MemoryError::OutOfBounds { address, length })?;
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

    #[test]
    fn read_guest_c_string_reads_in_chunks_not_one_byte_at_a_time() {
        let mut bytes = vec![b'a'; 300];
        bytes.push(0);
        bytes.resize(512, 0);
        let memory = CountingMemory::new(0x4000, bytes);

        let value = read_guest_c_string(&memory, 0x4000).unwrap();

        assert_eq!(value.len(), 300);
        assert!(
            memory.reads.get() <= 3,
            "read_guest_c_string should chunk reads, not issue {} byte reads",
            memory.reads.get(),
        );
    }

    #[test]
    fn every_migrated_syscall_is_claimed_by_the_normalized_table() {
        let d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = CompatReporter::default();
        // Numbers that used to live in the deleted legacy match. Each must now
        // be claimed by the normalized table (Some), never None.
        for nr in [
            5u64, 7, 8, 10, 11, 13, 14, 43, 44, 45, 74, 93, 151, 152, 159, 172, 173, 174, 175, 176,
            177, 178, 243, 269, 283, 293, 435,
        ] {
            let req = SyscallRequest::new(nr, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
            assert!(
                d.dispatch_normalized(req, &mut mem, &reporter, None)
                    .is_some(),
                "syscall {nr} fell through the normalized table",
            );
        }
    }

    #[test]
    fn resolve_exec_path_absolutizes_relative_against_cwd() {
        let d = SyscallDispatcher::new();
        // Default cwd is "/": a relative exec path resolves against it. This is
        // the Go os/exec TestCommandRelativeName shape (cmd.Path="b/foo",
        // cmd.Dir="/").
        assert_eq!(d.resolve_exec_path("b/os_exec.test"), "/b/os_exec.test");
        // With a deeper cwd, the relative path joins onto it.
        d.set_cwd("/run/src/os/exec");
        assert_eq!(d.resolve_exec_path("./echo"), "/run/src/os/exec/echo");
        assert_eq!(d.resolve_exec_path("../x"), "/run/src/os/x");
        // Absolute paths are normalized but not cwd-joined.
        assert_eq!(d.resolve_exec_path("/bin/sh"), "/bin/sh");
        assert_eq!(d.resolve_exec_path("/bin/../bin/sh"), "/bin/sh");
    }

    #[test]
    fn unknown_syscall_returns_enosys_without_panicking() {
        let mut d = SyscallDispatcher::new();
        let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
        let reporter = CompatReporter::default();
        // 999 is not a real aarch64 syscall and is not in the table.
        let req = SyscallRequest::new(999, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        let outcome = d
            .dispatch(req, &mut mem, &reporter)
            .expect("must not error");
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS
            }
        );
    }

    /// The dispatcher's `pty_table()` accessor must return the same
    /// `Arc`-wrapped table that was cloned into the `/dev` and `/dev/pts`
    /// mounts. Because all three hold clones of the same `Arc`, mutations
    /// through one pointer are visible through any other.
    #[test]
    fn dispatcher_shares_pty_table_with_dev_mounts() {
        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        // A freshly constructed dispatcher has an empty pty table.
        assert!(
            dispatcher.pty_table().lock().live_indices().is_empty(),
            "pty table should start empty"
        );
        // Confirm the Arc is genuinely shared: insert an entry directly into
        // the table and verify the dispatcher sees it through its accessor.
        let index = dispatcher
            .pty_table()
            .lock()
            .insert("dummy-slave".to_string(), 1234);
        assert_eq!(
            dispatcher.pty_table().lock().live_indices(),
            vec![index],
            "inserted index must be visible through the dispatcher accessor"
        );
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

#[cfg(test)]
mod rosetta_handshake_tests {
    use super::*;

    const BASE: u64 = 0x4000;

    fn mem() -> LinearMemory {
        LinearMemory::new(BASE, vec![0xABu8; 256])
    }

    #[test]
    fn non_rosetta_ioctl_passes_through() {
        // A normal ioctl (e.g. TCGETS=0x5401) is not claimed by the handshake.
        let mut m = mem();
        assert!(rosetta_handshake_ioctl(&mut m, 0x5401, BASE).is_none());
    }

    #[test]
    fn info_ioctl_returns_zero_and_zeroes_buffer() {
        // 0x80806123: size field = 0x80 (128). Not memcmp'd; success + zeroed.
        let mut m = mem();
        let outcome =
            rosetta_handshake_ioctl(&mut m, 0x80806123, BASE).expect("info ioctl must be handled");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let buf = m.read_bytes(BASE, 128).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "info buffer must be zeroed");
    }

    #[test]
    fn license_ioctl_writes_blob_when_rosetta_present() {
        // 0x80456125: size field = 0x45 (69). When Rosetta is installed the
        // buffer is filled with its verification blob; either way it succeeds.
        let mut m = mem();
        let outcome = rosetta_handshake_ioctl(&mut m, 0x80456125, BASE)
            .expect("licence ioctl must be handled");
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        if crate::runtime::rosetta_license_blob().is_some() {
            let buf = m.read_bytes(BASE, 13).unwrap();
            assert_eq!(&buf, b"Our hard work");
        }
    }

    #[test]
    fn faulting_address_returns_efault() {
        // An out-of-bounds buffer address must surface EFAULT, not panic.
        let mut m = mem();
        let outcome = rosetta_handshake_ioctl(&mut m, 0x80806123, 0xDEAD_0000)
            .expect("info ioctl must be handled");
        assert_eq!(
            outcome,
            DispatchOutcome::Errno {
                errno: LINUX_EFAULT
            }
        );
    }
}
