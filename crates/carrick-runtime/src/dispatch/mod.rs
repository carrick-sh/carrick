//! Linux syscall dispatch core — theory of operation.
//!
//! # The problem
//!
//! A guest Linux process runs as a native macOS process. When it executes an
//! `svc #0`, HVF traps to the carrick runtime with the aarch64 syscall frame
//! (`x8` = number, `x0..x5` = args). There is no guest kernel: every Linux
//! syscall must be *re-implemented* against Darwin host primitives. This module
//! is where a decoded syscall request turns into an effect — and, crucially,
//! into a description of what the *run loop* must do next that the dispatcher
//! itself cannot (block, fork, exec, park a vCPU). It owns guest-ABI request
//! decoding, the open-descriptor / fd-table state, the wait-outcome protocol,
//! and the shared helpers the per-domain handler modules
//! (`fs`, `proc`, `net`, `mem`, `signal`, …) build on.
//!
//! # The dispatch table: one normalized contract, per-module routing
//!
//! Every handler has the *same* signature — a method on [`SyscallDispatcher`]
//! taking `&mut SyscallCtx<M>` and returning `Result<DispatchOutcome,
//! DispatchError>` — so a `number → handler` mapping is just a `match` returning
//! one [`SyscallHandler`] fn pointer. Each per-domain module (`fs`, `net`,
//! `mem`, `proc`, `signal`, `time`, `creds`, `sysv`, `mqueue`, `perf`) owns its
//! OWN routing table via the `syscall_table!` macro, which emits a
//! `dispatch_<area>(number) -> Option<SyscallHandler<M>>`. `resolve_handler`
//! chains those per-module tables;
//! `dispatch_normalized` (builds a [`SyscallCtx`] and invokes the resolved
//! handler) and `dispatch_normalized_known` (the membership test the threaded
//! path uses) both go through it, so they cannot drift. There is NO central
//! routing chokepoint: adding a syscall is a one-module edit, which lets many
//! agents grow their own module's syscall set without contending on a shared
//! file. The chained tables are the single authoritative syscall registry: any
//! number no module claims is genuinely unimplemented and returns `-ENOSYS` —
//! a structured compat event, never a panic. **The supervisor never panics on
//! guest input.**
//!
//! [`SyscallCtx`] is a *transient narrow borrow*: it bundles the request, a
//! scoped `&mut` of guest memory, the compat reporter, and (on the threaded
//! path) a [`ThreadCtx`] with this thread's tid plus the shared thread/futex
//! tables. It exists only for the duration of one dispatched syscall, so a
//! handler borrows exactly the guest memory and per-thread coordination it needs
//! and nothing else.
//!
//! # BKL-free: per-subsystem locks, two entry points
//!
//! Historically the dispatcher was guarded by one big lock (the "BKL"). It is
//! not anymore. [`SyscallDispatcher`] is shared as a plain `Arc` and each
//! subsystem owns its own interior lock — `io` (fd table / stdio / cwd),
//! `mem`, `proc`, `creds`, `signal`, `fs`, `seccomp`, `sysv`. A handler that
//! touches only one subsystem takes only that subsystem's lock; sibling threads
//! in other subsystems run concurrently. The two public entry points reflect the
//! two runtime models:
//!
//! - [`SyscallDispatcher::dispatch`] (`&mut self`) — the single-threaded /
//!   fork-based path and the unit tests. Tid-aware handlers see `thread: None`
//!   and fall back to pid-based answers.
//! - [`SyscallDispatcher::dispatch_threaded`] (`&self`) — the multi-threaded
//!   path. There is **no dispatcher-wide fallback** here: a handler that touches
//!   process-wide state MUST guard it with a subsystem lock. The threaded path
//!   first tries `dispatch_threaded_independent` (a
//!   lock-free hot subset: `gettid`, `sched_yield`, futex, thread-targeted
//!   `tgkill`/`tkill`, `set_tid_address`), then the normalized table; anything
//!   else is ENOSYS on this path.
//!
//! Both paths run the seccomp pre-check first (installed cBPF filters veto a
//! syscall before its handler — ERRNO or fail-closed kill, mirroring the kernel)
//! and bracket the call with `SyscallEntry`/`SyscallReturn` compat events.
//!
//! The **lock-ordering invariant** is load-bearing and stated in full in the
//! comment immediately below this doc block; the short version is: never hold a
//! subsystem lock across a guest-memory callback or a blocking host wait, and
//! acquire fd/open-description state before fs-overlay state before `pty_table`
//! before the proc/signal/thread registries.
//!
//! # `DispatchOutcome`: the handler↔run-loop protocol
//!
//! A handler runs to completion synchronously and returns a [`DispatchOutcome`].
//! Most outcomes are trivial — [`DispatchOutcome::Returned`] /
//! [`DispatchOutcome::Errno`] (the run loop writes the value or `-errno` into
//! `x0`) or [`DispatchOutcome::Exit`]. The interesting variants are *requests*:
//! the dispatcher reached a point it cannot finish in place — because finishing
//! would require blocking, forking, replacing the address space, or touching the
//! vCPU — so it hands the run loop (`runtime.rs`) a structured description of
//! what to do and (for the blocking cases) *re-dispatches the same syscall*
//! afterwards. The categories:
//!
//! - **Address-space / vCPU effects the dispatcher cannot perform.**
//!   [`DispatchOutcome::Fork`] (a logical kernel-graph fork inside the carrier;
//!   no host process is created),
//!   [`DispatchOutcome::Execve`] (tear down + reload the ELF; argv/env are raw
//!   *byte* strings, not UTF-8), [`DispatchOutcome::CloneThread`] (spawn a host
//!   thread + sibling vCPU sharing the VM), [`DispatchOutcome::ThreadExit`],
//!   [`DispatchOutcome::SigReturn`] (pop the sigframe, don't advance PC),
//!   [`DispatchOutcome::SetMemoryModel`] (Rosetta TSO via `ACTLR_EL1`),
//!   [`DispatchOutcome::MapHostAlias`] (back a high-VA / `MAP_SHARED` mapping),
//!   and [`DispatchOutcome::SignalThread`] (kick a sibling vCPU to deliver).
//!
//! - **Blocking that MUST NOT happen under a dispatcher lock.** A handler that
//!   blocks while holding a subsystem lock starves every sibling thread (a
//!   `FUTEX_WAKE`, a GIL handoff, a server's workers). So the value-check /
//!   readiness-check happens *under* the lock, and if the call must block the
//!   handler returns a wait outcome and the run loop drops all locks, parks
//!   interruptibly, then re-dispatches. These are [`DispatchOutcome::FutexWait`]
//!   / [`DispatchOutcome::SharedFutexWait`] (futex value matched → park on the
//!   parking-lot token or, for `MAP_SHARED` inter-process futexes, the host
//!   `__ulock`), [`DispatchOutcome::WaitOnFds`] with its [`FdWaitCompletion`]
//!   (poll/select/epoll-style fd readiness,
//!   serviced by the per-thread kqueue or `poll(2)`), [`DispatchOutcome::WaitOnProcExit`]
//!   (a blocking `waitid` parks on `EVFILT_PROC`/`NOTE_EXIT`),
//!   [`DispatchOutcome::WaitOnSignals`] (`rt_sigtimedwait` / `rt_sigsuspend`), and
//!   [`DispatchOutcome::WaitOnSleep`] (`nanosleep` via the per-thread waiter, so
//!   the sleep is interruptible AND can park for a fork-quiesce — a sibling stuck
//!   in a synchronous host nanosleep would deadlock a multithreaded fork).
//!
//! The re-dispatch contract is what makes the wait outcomes correct: a handler
//! writes nothing speculative, the run loop blocks, and on a *ready* wake it
//! calls the same syscall again — which now finds the fd ready / the signal
//! pending / the child reaped and completes normally. A *timeout* or *signal*
//! wake is completed by the run loop directly (`on_timeout` value, or `EINTR`).
//! See each variant's doc for its exact completion rule.
//!
//! # The fs subsystem
//!
//! The filesystem handlers (in `fs.rs` and `fs/`) route every path-bearing
//! syscall through the unified VFS mount table first (`FsState::vfs_mounts`
//! — `/dev`, `/proc`, `/sys`), falling through to the `/` mount: an immutable OCI
//! rootfs plus a writable overlay. Descriptors live in the fd table
//! (`fd_table`) as `OpenDescription` values — a per-open-file-description
//! union spanning in-memory `File`/`Directory`, host-fd-backed `HostFile` /
//! `HostSocket` / `HostPipe`, and the anonymous-inode fds (eventfd, epoll,
//! timerfd, signalfd, inotify, pidfd). The fd allocator is POSIX
//! lowest-free-descriptor, capped at the guest's soft `RLIMIT_NOFILE`.

use std::collections::{HashMap, VecDeque};
// Both traits are consumed only inside `snapshot_native_reexec_fd_table`
// (`OsStrExt::as_bytes`) and `restore_native_reexec_fd_table`

use std::path::{Component, Path};

pub use carrick_hal::{HostAliasBacking, HostAliasOwnedFd, HostAliasSharing};
use std::sync::Arc;
use std::time::Duration;

// LOCK ORDERING: dispatch handlers must not hold subsystem locks while entering
// guest-memory callbacks or blocking host waits. When multiple dispatcher
// locks are unavoidable, acquire fd/open-description state before filesystem
// overlay state, then pty_table, then proc/signal/thread registries. For paired
// SysV operations, the per-process attachment lock must precede the shared SysV
// namespace lock; this is structurally enforced via `SysvProcessGuard` and
// `SysvNamespacePermit`. The EPOLL_INMEM_KQUEUES registry is independent and must
// not be held while acquiring dispatcher fd/open-description locks; in-memory wake
// broadcasts only trigger already-registered kqueues. Futex waits are prepared under
// dispatcher state and parked only after those locks have been released.

use crate::compat::{CompatEvent, CompatReporter, SyscallArgs};
use crate::fs_backend::FsBackend;
#[cfg(test)]
use crate::linux_abi::LINUX_MAP_ANONYMOUS;
use crate::linux_abi::{
    KernelAbi,
    // ABI constants moved from dispatch.rs (Goal #3, private set)
    LINUX_AF_INET,
    LINUX_AF_INET6,
    LINUX_AF_NETLINK,
    LINUX_AF_UNIX,
    LINUX_AF_UNSPEC,
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
    LINUX_BOOTSTRAP_PID,
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
    LINUX_CLONE_NEWCGROUP,
    LINUX_CLONE_NEWIPC,
    LINUX_CLONE_NEWNET,
    LINUX_CLONE_NEWNS,
    LINUX_CLONE_NEWPID,
    LINUX_CLONE_NEWTIME,
    LINUX_CLONE_NEWUSER,
    LINUX_CLONE_NEWUTS,
    LINUX_CMSG_ALIGN,
    LINUX_CMSGHDR_LEN,
    LINUX_DEFAULT_TIMERSLACK_NS,
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
    LINUX_EBUSY,
    LINUX_EDEADLK,
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
    LINUX_ENODEV,
    LINUX_ENOENT,
    LINUX_ENOMEM,
    LINUX_ENOPROTOOPT,
    LINUX_ENOSYS,
    LINUX_ENOTCONN,
    LINUX_ENOTDIR,
    LINUX_ENOTSOCK,
    LINUX_ENOTSUP,
    LINUX_ENOTTY,
    LINUX_EOPNOTSUPP,
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
    LINUX_F_ADD_SEALS,
    LINUX_F_DUPFD,
    LINUX_F_DUPFD_CLOEXEC,
    LINUX_F_GET_SEALS,
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
    LINUX_FALLOC_FL_PUNCH_HOLE,
    LINUX_FALLOC_FL_SUPPORTED,
    LINUX_FD_CLOEXEC,
    LINUX_FICLONE,
    LINUX_FIONBIO,
    LINUX_FIONREAD,
    LINUX_FUTEX_32,
    LINUX_FUTEX_CMD_MASK,
    LINUX_FUTEX_CMP_REQUEUE,
    LINUX_FUTEX_LOCK_PI,
    LINUX_FUTEX_PRIVATE_FLAG,
    LINUX_FUTEX_REQUEUE,
    LINUX_FUTEX_TID_MASK,
    LINUX_FUTEX_TRYLOCK_PI,
    LINUX_FUTEX_UNLOCK_PI,
    LINUX_FUTEX_WAIT,
    LINUX_FUTEX_WAIT_BITSET,
    LINUX_FUTEX_WAITV_MAX,
    LINUX_FUTEX_WAKE,
    LINUX_FUTEX_WAKE_BITSET,
    LINUX_IFA_ADDRESS,
    LINUX_IFA_LABEL,
    LINUX_IFA_LOCAL,
    LINUX_IFLA_ADDRESS,
    LINUX_IFLA_IFNAME,
    LINUX_IFNAMSIZ,
    LINUX_IOV_MAX,
    LINUX_IPPROTO_SCTP,
    LINUX_IPPROTO_UDPLITE,
    LINUX_ITIMER_PROF,
    LINUX_ITIMER_REAL,
    LINUX_ITIMER_VIRTUAL,
    LINUX_LOCK_EX,
    LINUX_LOCK_NB,
    LINUX_LOCK_SH,
    LINUX_LOCK_UN,
    LINUX_MADV_COLLAPSE,
    LINUX_MADV_DODUMP,
    LINUX_MADV_DOFORK,
    LINUX_MADV_DONTDUMP,
    LINUX_MADV_DONTFORK,
    LINUX_MADV_DONTNEED,
    LINUX_MADV_FREE,
    LINUX_MADV_HUGEPAGE,
    LINUX_MADV_KEEPONFORK,
    LINUX_MADV_NOHUGEPAGE,
    LINUX_MADV_NORMAL,
    LINUX_MADV_RANDOM,
    LINUX_MADV_SEQUENTIAL,
    LINUX_MADV_WILLNEED,
    LINUX_MADV_WIPEONFORK,
    LINUX_MAP_FIXED,
    LINUX_MAP_FIXED_NOREPLACE,
    LINUX_MAX_SIGNUM,
    LINUX_MEMBARRIER_CMD_QUERY,
    LINUX_MFD_HUGETLB,
    LINUX_MINSIGSTKSZ,
    LINUX_MREMAP_DONTUNMAP,
    LINUX_MREMAP_FIXED,
    LINUX_MREMAP_MAYMOVE,
    LINUX_MS_ASYNC,
    LINUX_MS_INVALIDATE,
    LINUX_MS_SYNC,
    LINUX_MSG_CTRUNC,
    LINUX_MSG_EOR,
    LINUX_MSG_OOB,
    LINUX_MSG_TRUNC,
    LINUX_NLM_F_MULTI,
    LINUX_NLMSG_DONE,
    LINUX_NS_GET_NSTYPE,
    LINUX_NS_GET_OWNER_UID,
    LINUX_NS_GET_PARENT,
    LINUX_NS_GET_USERNS,
    LINUX_O_ACCMODE,
    LINUX_O_APPEND,
    LINUX_O_ASYNC,
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
    LINUX_PR_CAP_AMBIENT,
    LINUX_PR_CAP_AMBIENT_CLEAR_ALL,
    LINUX_PR_CAP_AMBIENT_IS_SET,
    LINUX_PR_CAP_AMBIENT_LOWER,
    LINUX_PR_CAP_AMBIENT_RAISE,
    LINUX_PR_CAPBSET_DROP,
    LINUX_PR_CAPBSET_READ,
    LINUX_PR_GET_CHILD_SUBREAPER,
    LINUX_PR_GET_DUMPABLE,
    LINUX_PR_GET_KEEPCAPS,
    LINUX_PR_GET_MEM_MODEL,
    LINUX_PR_GET_NAME,
    LINUX_PR_GET_NO_NEW_PRIVS,
    LINUX_PR_GET_PDEATHSIG,
    LINUX_PR_GET_SECCOMP,
    LINUX_PR_GET_SPECULATION_CTRL,
    LINUX_PR_GET_THP_DISABLE,
    LINUX_PR_GET_TIMERSLACK,
    LINUX_PR_SET_CHILD_SUBREAPER,
    LINUX_PR_SET_DUMPABLE,
    LINUX_PR_SET_KEEPCAPS,
    LINUX_PR_SET_MEM_MODEL,
    LINUX_PR_SET_MEM_MODEL_DEFAULT,
    LINUX_PR_SET_MEM_MODEL_TSO,
    LINUX_PR_SET_NAME,
    LINUX_PR_SET_NO_NEW_PRIVS,
    LINUX_PR_SET_PDEATHSIG,
    LINUX_PR_SET_SECCOMP,
    LINUX_PR_SET_SECUREBITS,
    LINUX_PR_SET_THP_DISABLE,
    LINUX_PR_SET_TIMERSLACK,
    LINUX_PR_SPEC_INDIRECT_BRANCH,
    LINUX_PR_SPEC_L1D_FLUSH,
    LINUX_PR_SPEC_STORE_BYPASS,
    LINUX_PRIO_PGRP,
    LINUX_PRIO_PROCESS,
    LINUX_PRIO_USER,
    LINUX_PROT_READ,
    LINUX_PROT_WRITE,
    LINUX_R_OK,
    LINUX_RLIM_INFINITY,
    LINUX_RLIM_NLIMITS,
    LINUX_RLIMIT_AS,
    LINUX_RLIMIT_DATA,
    LINUX_RLIMIT_MEMLOCK,
    LINUX_RNDGETENTCNT,
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
    LINUX_SCM_CREDENTIALS,
    LINUX_SCM_RIGHTS,
    LINUX_SECCOMP_MODE_FILTER,
    LINUX_SECCOMP_MODE_STRICT,
    LINUX_SEEK_CUR,
    LINUX_SEEK_END,
    LINUX_SEEK_SET,
    LINUX_SIG_BLOCK,
    LINUX_SIG_SETMASK,
    LINUX_SIG_UNBLOCK,
    LINUX_SIGIO,
    LINUX_SIGKILL,
    LINUX_SIGPIPE,
    LINUX_SIGSTOP,
    LINUX_SIGTTOU,
    LINUX_SIGXFSZ,
    LINUX_SIOCATMARK,
    LINUX_SIOCGIFADDR,
    LINUX_SIOCGIFBRDADDR,
    LINUX_SIOCGIFCONF,
    LINUX_SIOCGIFFLAGS,
    LINUX_SIOCGIFINDEX,
    LINUX_SIOCGIFMTU,
    LINUX_SIOCGIFNAME,
    LINUX_SIOCGIFNETMASK,
    LINUX_SIOCSIFFLAGS,
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
    LINUX_SS_DISABLE,
    LINUX_SS_ONSTACK,
    LINUX_STATX_BASIC_STATS,
    LINUX_STATX_RESERVED,
    LINUX_TASK_COMM_LEN,
    LINUX_TCFLSH,
    LINUX_TCGETA,
    LINUX_TCGETS,
    LINUX_TCGETS2,
    LINUX_TCP_CORK,
    LINUX_TCP_KEEPCNT,
    LINUX_TCP_KEEPIDLE,
    LINUX_TCP_KEEPINTVL,
    LINUX_TCP_MAXSEG,
    LINUX_TCP_NODELAY,
    LINUX_TCSBRK,
    LINUX_TCSBRKP,
    LINUX_TCSETS,
    LINUX_TCSETS2,
    LINUX_TCSETSF,
    LINUX_TCSETSF2,
    LINUX_TCSETSW,
    LINUX_TCSETSW2,
    LINUX_TCXONC,
    LINUX_TERMIO_SIZE,
    LINUX_TERMIOS_KERNEL_SIZE,
    LINUX_TERMIOS2_SIZE,
    LINUX_TFD_NONBLOCK,
    LINUX_TIME_DEL,
    LINUX_TIME_ERROR,
    LINUX_TIME_INS,
    LINUX_TIME_OK,
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
    LINUX_X_OK,
    LinuxAccessMode,
    LinuxAtFlags,
    LinuxCapabilityData,
    LinuxCapabilityHeader,
    LinuxCloneArgs,
    LinuxCloneFlags,
    LinuxDirent64Header,
    LinuxDnotifyMask,
    LinuxEfdFlags,
    LinuxEpollEvent,
    LinuxEpollEvents,
    LinuxEventfdValue,
    LinuxFOwnerEx,
    LinuxFanotifyEvents,
    LinuxFanotifyInitFlags,
    LinuxFanotifyMarkFlags,
    LinuxFdFlags,
    LinuxFdPair,
    LinuxFlock64,
    LinuxFutexFlags,
    LinuxGuestAbi,
    LinuxIfAddrMsg,
    LinuxIfInfoMsg,
    LinuxIfconf,
    LinuxIfreq,
    LinuxIocb,
    LinuxIovec,
    LinuxItimerspec,
    LinuxItimerval,
    LinuxMemfdFlags,
    LinuxMlock2Flags,
    LinuxMlockallFlags,
    LinuxMmapFlags,
    LinuxMmsghdr,
    LinuxMsgFlags,
    LinuxMsghdr,
    LinuxNlMsgHdr,
    LinuxOpenFlags,
    LinuxOpenHow,
    LinuxPipe2Flags,
    LinuxPollFd,
    LinuxProtFlags,
    LinuxRenameat2Flags,
    LinuxRlimit,
    LinuxRtAttr,
    LinuxRusage,
    LinuxSigaction,
    LinuxSigaltstack,
    LinuxSignalfdFlags,
    LinuxSigsetArgpack,
    LinuxSocketTypeFlags,
    LinuxSpliceFlags,
    LinuxStat,
    LinuxStatfs,
    LinuxStatx,
    LinuxStatxTimestamp,
    LinuxSysinfo,
    LinuxTermios,
    LinuxTfdFlags,
    LinuxTimerfdExpirations,
    LinuxTimespec,
    LinuxTimeval,
    LinuxTimex,
    LinuxTimexModes,
    LinuxTimexStatus,
    LinuxTimezone,
    LinuxTms,
    LinuxUtsname,
    LinuxWaitOptions,
    LinuxWinsize,
    LinuxX8664EpollEvent,
    LinuxX8664Stat,
    align_up_u64,
};
#[cfg(test)]
use crate::linux_abi::{LINUX_MAP_PRIVATE, LINUX_MAP_SHARED};
use crate::overlay::OverlayEntry;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
use carrick_fatal::carrick_fatal;
// Canonical-number lookups: carrick's canonical syscall numbering IS the
// aarch64 numbering. The dispatcher receives canonical numbers (a per-ISA
// table remaps raw numbers to canonical at the GuestArch seam — Phase 2 for
// x86_64), so its own metadata lookups stay aarch64-keyed by design; only
// raw-frame consumers (the vCPU-loop trace) use the per-ISA Arch::Table.
use crate::linux_abi::LinuxErrno;
use crate::syscall::lookup_aarch64;
use parking_lot::{Mutex, RwLock};
use zerocopy::{FromBytes, IntoBytes};

macro_rules! define_syscall_one {
    (mm_mutation $(#[$meta:meta])* fn $name:ident ( $this:ident, $cx:ident $(, $arg:ident : $argty:ty )* $(,)? ) $body:block) => {
            $(#[$meta])*
            #[allow(unused_variables)]
            pub(super) fn $name<M: CurrentMmMemory>(
                &self,
                ctx: &mut MutationSyscallCtx<M>,
            ) -> Result<DispatchOutcome, DispatchError> {
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
    };
    ($(#[$meta:meta])* fn $name:ident ( $this:ident, $cx:ident $(, $arg:ident : $argty:ty )* $(,)? ) $body:block) => {
            $(#[$meta])*
            #[allow(unused_variables)]
            pub(super) fn $name<M: CurrentMmMemory>(
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
    };
}

macro_rules! define_syscall {
    () => {};
    ($(#[$meta:meta])* mm_mutation fn $name:ident ( $this:ident, $cx:ident $(, $arg:ident : $argty:ty )* $(,)? ) $body:block $($rest:tt)*) => {
        define_syscall_one! { mm_mutation $(#[$meta])* fn $name($this, $cx $(, $arg: $argty)*) $body }
        define_syscall! { $($rest)* }
    };
    ($(#[$meta:meta])* fn $name:ident ( $this:ident, $cx:ident $(, $arg:ident : $argty:ty )* $(,)? ) $body:block $($rest:tt)*) => {
        define_syscall_one! { $(#[$meta])* fn $name($this, $cx $(, $arg: $argty)*) $body }
        define_syscall! { $($rest)* }
    };
}

/// Emit a `dispatch_<area>(number) -> Option<SyscallHandler<M>>` resolver from a
/// `number => handler` list. Each dispatch module invokes this once with the
/// arms it owns. The handler is returned as a fn pointer (the receiver and ctx
/// are bound later by `dispatch_normalized`), which is what makes the per-module
/// tables chainable without a shared `match` — adding a syscall is a one-module
/// edit (Task A1). Defined before the `mod` declarations so the child dispatch
/// modules can invoke it.
macro_rules! syscall_table {
    ( $(#[$meta:meta])* $vis:vis fn $name:ident ; $( $num:pat => $handler:ident ),* $(,)? ) => {
        $(#[$meta])*
        // An empty (or about-to-be-emptied) table is a `match` whose only arm
        // returns, making the `Some(..)` unreachable — that's expected for a
        // not-yet-populated module table, so allow it.
        #[allow(unreachable_code)]
        $vis fn $name<M: CurrentMmMemory>(number: u64) -> Option<SyscallHandler<M>> {
            Some(match number {
                $( $num => SyscallDispatcher::$handler, )*
                _ => return None,
            })
        }
    };
}

macro_rules! mutation_syscall_table {
    ( $(#[$meta:meta])* $vis:vis fn $name:ident ; $( $num:pat => $handler:ident ),* $(,)? ) => {
        $(#[$meta])*
        #[allow(unreachable_code)]
        $vis fn $name<M: CurrentMmMemory>(number: u64) -> Option<MutationSyscallHandler<M>> {
            Some(match number {
                $( $num => SyscallDispatcher::$handler, )*
                _ => return None,
            })
        }
    };
}

mod abi_args;
mod archive;
pub(crate) use archive::{
    ArchiveEntryMetadata, ArchiveFsAuthority, ArchiveFsError, MAX_ARCHIVE_BYTES,
};
mod pty_registry;
#[macro_use]
mod creds;
mod epoll_shim;
pub(crate) use epoll_shim::{
    EpollWakeRegistry, new_epoll_wake_registry, notify_inmem_epoll, register_epoll_kqueue,
    unregister_epoll_kqueue,
};
pub(crate) mod fd_table;
mod fifo_beacon;
pub(crate) mod ioring;
#[macro_use]
mod fs;
#[cfg(test)]
pub(crate) use fs::RecordLockContentionFixture;
pub use fs::StdioSink;
mod keys;
pub(crate) use fs::{LegacyAioContextId, MountRetirement, SplicePushback};
#[macro_use]
mod mem;
pub(crate) use mem::boot_private_file_backings;
#[macro_use]
pub(crate) mod net;
#[macro_use]
mod perf;
mod proc;
#[cfg(test)]
pub(crate) use proc::build_hvpatch_waitid_siginfo;
mod proctitle;
pub(crate) mod resources;
mod retval;
#[macro_use]
mod signal;
mod bpf;
pub mod mm_mutation;
mod mount_api;
mod mqueue;
mod syslog;
#[cfg(not(doctest))]
mod sysv;
#[cfg(doctest)]
pub mod sysv;
pub use sysv::SysvWaitState;
#[macro_use]
mod time;
pub use time::{
    HOST_FD_HEADROOM, guest_file_table_max, host_open_descriptor_count, raise_host_nofile_backing,
};

#[cfg(test)]
pub(crate) use proctitle::carrier_proc_label;
pub use proctitle::{init as proctitle_init, set_carrier_process_title, set_host_process_name};

pub use crate::vfs::{ProcMapSharing, ProcMapsEntry};
pub use abi_args::{Fd, GuestLen, GuestPtr, HostFd, HostPid, NsPid, Pid, Signal};
use fd_table::*;

pub mod wait_authority;
pub use wait_authority::WaitFds;
pub(crate) use wait_authority::{InternalWaitKind, WaitFdAuthority};

pub mod outcome;
pub use outcome::{
    BlockingHostWrite, BlockingRecordLock, DispatchError, DispatchOutcome, FdWaitCompletion,
    LinearMemory, SharedFutexTarget,
};
pub(crate) use outcome::{
    BlockingHostWriteStep, BlockingRecordLockStep, drive_blocking_host_write,
    drive_blocking_record_lock, lower_handler_result, try_drive_blocking_record_lock,
};

pub mod request;
pub use request::{MutationSyscallCtx, SyscallCtx, SyscallRequest, ThreadCtx};
pub(crate) use request::{
    PreparedDispatch, PreparedSyscall, SyscallCompletionToken, merge_policy_terminal,
    syscall_requires_execution_lease, threaded_independent_dispatch_supports,
};

pub mod host_alias;
pub use host_alias::HostAliasTransaction;
pub(crate) use host_alias::{HostAliasCommit, HostAliasDispatchGuard, HostAliasTransactions};

pub mod core_publication;
pub(crate) use core_publication::CoreProcessSnapshot;
#[allow(unused_imports)]
pub(crate) use core_publication::{CorePublication, CorePublicationError};

pub mod kernel_context;
#[allow(unused_imports)]
pub(crate) use kernel_context::GuestProcessTarget;
pub(crate) use kernel_context::bootstrap_one_task_binding;

pub mod dispatcher;
pub use dispatcher::SyscallDispatcher;
#[allow(unused_imports)]
pub(crate) use dispatcher::resolv_conf_contents_for_network;

// `GuestMemory` and `MemoryError` were lifted into the leaf crate
// `carrick-guest-mem` to break the `memory ↔ dispatch` cycle (see
// docs/archive/build-decomposition-design.md §3.A-A2). Re-exported here so every
// `crate::dispatch::{…}` / `carrick_runtime::dispatch::{…}` site is unchanged.
// (The `Aarch64SyscallFrame` re-export is gone: the dispatcher is ISA-neutral —
// backends decode raw frames behind `GuestArch` and hand over `RawSyscall`.)
pub use carrick_guest_mem::{CurrentMmMemory, Gpa, GuestMemory, GuestVa, HostVa, MemoryError};

const MAX_GUEST_PATH: usize = 4096;

/// Outcome of [`SyscallDispatcher::try_vfs_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum VfsOpenAttempt {
    Installed(i32),
    Errno(LinuxErrno),
    FallThrough,
}

/// Execution-backend owner of the vCPU wake after asynchronous signal
/// publication. This is run-scoped dispatcher state, not a host-platform or
/// process-global presence heuristic: macOS can execute the same container via
/// native translation or HVF, and only the selected backend knows who kicks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AsyncSignalWakeOwner {
    SignalPump,
}

impl AsyncSignalWakeOwner {
    #[allow(dead_code)]
    pub(crate) fn publish_process_signal(self, signum: i32) {
        #[cfg(feature = "platform-macos")]
        match self {
            Self::SignalPump => crate::host_signal::publish_process_signal(signum),
        }
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        {
            let _ = self;
            crate::timer_delivery::deliver(signum);
        }
    }
}

/// Dispatcher-side authority for one Linux MM.
///
/// Every dispatcher still owns process-private signal, fd, proc, and control
/// state. Only Linux memory metadata and the host-alias transaction boundary
/// travel together here: `CLONE_VM` selects the same authority while a copied
/// MM receives an exact fork-private authority.
pub(crate) struct DispatchMmAuthority {
    pub(crate) mm_id: crate::kernel::MmId,
    pub(crate) mem: Arc<mem::MemAuthority>,
    pub(crate) host_alias_transactions: Arc<HostAliasTransactions>,
    pub(crate) mutation_coordinator: Arc<mm_mutation::MmMutationCoordinator>,
    guest_executors: Arc<crate::kernel::GuestExecutorCensus>,
    pt_quiesce: Arc<carrick_thread::fork_quiesce::PtQuiesce>,
    /// The `guest_realtime_epoch()` under which THIS MM's vvar
    /// `VVAR_OFF_REALTIME_OFF_NS` word was last stamped by the dispatcher
    /// (`SyscallDispatcher::sync_vvar_realtime_offset`). The vvar page is per
    /// MM (it also carries the per-process RNG generation), so the stamp state
    /// is MM state. `u64::MAX` = never.
    ///
    /// While the global epoch is still 0 — no guest has moved the clock in
    /// this carrier — an MM is left at `u64::MAX` and never stamped, because
    /// the VMM stamper's boot-time word is already correct and a re-stamp
    /// would write the same bytes. The first `clock_settime` advances the
    /// epoch past 0, and each MM then re-stamps once on its next syscall (or
    /// at the post-exec identity stamp): a single 8-byte write (a fork child's
    /// vvar frame is already COW-split by the HVPatch RNG-generation
    /// re-stamp, `trap.rs:11281`).
    vvar_realtime_epoch: std::sync::atomic::AtomicU64,
}

impl DispatchMmAuthority {
    pub(in crate::dispatch) fn new(mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: Arc::new(mem::MemAuthority::new(mem::MemState::new())),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    fn fork_private(&self, mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: self.mem.fork_private(),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Re-key the prepared root dispatcher onto the MM identity committed by
    /// the carrier kernel graph.
    ///
    /// A dispatcher is assembled before carrier admission, so its mandatory
    /// one-task reference binding has an MM id from a throwaway kernel. The
    /// first carrier root happens to receive the same numeric id; later roots
    /// do not. Preserve the prepared VMA state, but mint every coordination
    /// object whose authority is defined by the exact committed MM.
    fn rebind_prepared_root(&self, mm_id: crate::kernel::MmId) -> Self {
        Self {
            mm_id,
            mem: Arc::clone(&self.mem),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(
                self.vvar_realtime_epoch
                    .load(std::sync::atomic::Ordering::Acquire),
            ),
        }
    }

    pub(in crate::dispatch) fn fork_private_with_policy(
        &self,
        mm_id: crate::kernel::MmId,
    ) -> Result<
        (
            Self,
            crate::kernel::VmaRevision,
            Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        let (forked_mem, revision, ranges) = self.mem.fork_private_with_policy()?;
        Ok((
            Self {
                mm_id,
                mem: Arc::new(forked_mem),
                host_alias_transactions: Arc::new(HostAliasTransactions::new()),
                mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
                guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
                pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
                // Never stamped: the child inherits the parent's vvar content
                // through the COW split, and re-stamps on its next syscall
                // only once a `clock_settime` has moved the global epoch.
                vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
            },
            revision,
            ranges,
        ))
    }

    pub(in crate::dispatch) fn fork_projection_with_revision(
        &self,
    ) -> Result<
        (
            crate::kernel::VmaRevision,
            Arc<[carrick_hal::ForkProjectionRange]>,
        ),
        carrick_hal::ForkProjectionError,
    > {
        self.mem.fork_projection_with_revision()
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, mem::MemState> {
        self.mem.lock()
    }

    fn revision_publisher(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.mem.revision_publisher()
    }

    pub(crate) fn vma_revision(&self) -> crate::kernel::VmaRevision {
        self.mem.vma_revision()
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_revision(revision: crate::kernel::VmaRevision) -> Self {
        let mm_id = crate::kernel::MmId::from_registry_allocation(std::num::NonZeroU64::MIN);
        Self {
            mm_id,
            mem: Arc::new(mem::MemAuthority::with_revision(
                mem::MemState::new(),
                revision,
            )),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            mutation_coordinator: Arc::new(mm_mutation::MmMutationCoordinator::new(mm_id)),
            guest_executors: Arc::new(crate::kernel::GuestExecutorCensus::default()),
            pt_quiesce: Arc::new(carrick_thread::fork_quiesce::PtQuiesce::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    /// Production-shape MM authority for cross-layer foreign-COW tests. This
    /// uses the real dispatch VMA authority, mutation coordinator, and executor
    /// census; only the single test VMA is synthetic.
    #[cfg(test)]
    pub(crate) fn foreign_cow_composition_for_test(
        mm_id: crate::kernel::MmId,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
        start: u64,
        end: u64,
    ) -> (Arc<Self>, mm_mutation::ForeignMmMutationAuthority) {
        let authority = Arc::new(Self::new(mm_id));
        {
            let mut mem = authority.mem.lock();
            mem.dynamic_maps.push(ProcMapsEntry {
                start,
                end,
                read: true,
                write: true,
                execute: false,
                sharing: ProcMapSharing::Private,
                path: "[foreign-cow-composition]".to_owned(),
            });
        }
        authority.mem.bump_revision();
        let mutation = mm_mutation::ForeignMmMutationAuthority::new(
            mm_id,
            Arc::clone(&authority.mutation_coordinator),
            Arc::clone(&authority.guest_executors),
            stage1,
            Arc::clone(&authority.pt_quiesce),
        );
        (authority, mutation)
    }

    pub(crate) fn pt_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        &self.pt_quiesce
    }

    #[cfg(test)]
    pub(crate) fn foreign_cow_executor_census_for_test(
        &self,
    ) -> Arc<crate::kernel::GuestExecutorCensus> {
        Arc::clone(&self.guest_executors)
    }

    #[cfg(test)]
    pub(crate) fn set_foreign_cow_vma_access_for_test(&self, access: crate::kernel::VmaAccess) {
        let mut mem = self.mem.lock();
        let vma = mem
            .dynamic_maps
            .iter_mut()
            .find(|vma| vma.path == "[foreign-cow-composition]")
            .expect("foreign COW composition VMA");
        vma.read = access.readable;
        vma.write = access.writable;
        vma.execute = access.executable;
        drop(mem);
        self.mem.bump_revision();
    }

    #[cfg(test)]
    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::kernel::OwnedVmaSnapshot, crate::kernel::SnapshotError> {
        self.mem.snapshot_until(deadline)
    }
}

/// Opaque participation in the executor census owned by one exact dispatch MM.
///
/// CLONE_VM dispatchers share the same [`DispatchMmAuthority`] and therefore
/// the same census. Holding this token says the caller may execute on that MM;
/// it does not itself grant mutation authority while a peer token exists.
pub struct MmExecutorParticipation {
    authority: Arc<DispatchMmAuthority>,
    admission: MmExecutorAdmissionRecipe,
    participation: Option<crate::kernel::GuestExecutorParticipation>,
}

#[derive(Clone)]
enum MmExecutorAdmissionRecipe {
    Anonymous,
    AnonymousWithPauseEndpoint {
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
    Thread {
        thread: crate::kernel::ThreadRef,
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    },
}

impl MmExecutorAdmissionRecipe {
    fn enter(
        &self,
        authority: &Arc<DispatchMmAuthority>,
    ) -> Result<crate::kernel::GuestExecutorParticipation, crate::kernel::GuestExecutorCensusError>
    {
        match self {
            Self::Anonymous => authority.guest_executors.enter(None),
            Self::AnonymousWithPauseEndpoint { registry, tid } => authority
                .guest_executors
                .enter_with_pause_endpoint(None, Arc::clone(registry), *tid),
            Self::Thread {
                thread,
                registry,
                tid,
            } => authority.guest_executors.enter_with_pause_endpoint(
                Some(thread.clone()),
                Arc::clone(registry),
                *tid,
            ),
        }
    }
}

impl MmExecutorParticipation {
    pub(crate) fn participation_mut(&mut self) -> &mut crate::kernel::GuestExecutorParticipation {
        self.participation.as_mut().unwrap_or_else(|| {
            tracing::error!("MM executor participation used while temporarily released");
            carrick_fatal!(
                "dispatch::mm_executor_participation",
                "MM executor participation used while temporarily released"
            )
        })
    }

    pub(crate) fn mm_id(&self) -> crate::kernel::MmId {
        self.authority.mm_id
    }

    pub(crate) fn mutation_coordinator(&self) -> Arc<mm_mutation::MmMutationCoordinator> {
        Arc::clone(&self.authority.mutation_coordinator)
    }

    pub(crate) fn pt_quiesce(&self) -> &Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        self.authority.pt_quiesce()
    }

    fn authorizes(&self, authority: &Arc<DispatchMmAuthority>) -> bool {
        Arc::ptr_eq(&self.authority, authority)
    }

    fn validates_thread_identity(&self, thread: &crate::kernel::ThreadRef) -> bool {
        match &self.admission {
            MmExecutorAdmissionRecipe::Anonymous
            | MmExecutorAdmissionRecipe::AnonymousWithPauseEndpoint { .. } => true,
            MmExecutorAdmissionRecipe::Thread {
                thread: admitted, ..
            } => Arc::ptr_eq(admitted, thread),
        }
    }

    fn leave_temporarily(&mut self) -> Result<(), DispatchError> {
        let participation = self
            .participation
            .take()
            .ok_or(DispatchError::MmExecutorParticipationUnavailable)?;
        drop(participation);
        Ok(())
    }

    fn reenter_exact(&mut self) -> Result<(), crate::kernel::GuestExecutorCensusError> {
        if self.participation.is_some() {
            tracing::error!("MM executor re-entry attempted while participation is present");
            carrick_fatal!(
                "dispatch::mm_executor_participation",
                "MM executor re-entry attempted while participation is present"
            );
        }
        self.participation = Some(self.admission.enter(&self.authority)?);
        Ok(())
    }
}

#[cfg(test)]
mod mm_executor_release_tests {
    use std::sync::Arc;

    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::*;
    use crate::kernel::objects::{ExecutorId, MigratableTaskState, ThreadExecutionLease};

    fn running_lease(context: &crate::kernel::KernelContext) -> ThreadExecutionLease {
        let mm = context.shared().mm().id();
        context
            .thread()
            .publish_initial_task_state(MigratableTaskState {
                cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                    gprs: [0; 31],
                    pc: 0,
                    pstate: 0,
                    trap_pc: 0,
                    trap_pstate: 0,
                    sp_el0: 0,
                    elr_el1: 0,
                    spsr_el1: 0,
                    ttbr0: 0,
                    ttbr1: 0,
                    tcr: 0,
                    sctlr_el1: 0,
                    mair_el1: 0,
                    vbar_el1: 0,
                    cpacr_el1: 0,
                    cntkctl_el1: 0,
                    tpidr_el1: 0,
                    actlr_el1: 0,
                    tpidr_el0: 0,
                    tpidrro_el0: 0,
                    contextidr_el1: 0,
                    vregs: [0; 32],
                    fpsr: 0,
                    fpcr: 0,
                    pending_resume_pc: None,
                    last_syscall_nr: Some(271),
                    last_syscall_orig_x0: 0,
                    last_fault_esr: 0,
                    last_exit_class: 0,
                    is_forked_child: false,
                    syscall_continuation: None,
                    mm_generation: mm.raw(),
                    asid_generation: mm.raw(),
                }),
                mm,
                asid_generation: mm.raw(),
            })
            .expect("publish task state");
        context
            .thread()
            .claim_runnable(
                ExecutorId::for_transitional_thread(carrick_hal::ThreadId::synthetic_for_tests(41))
                    .expect("transitional executor"),
            )
            .expect("claim running lease")
    }

    fn boundary_fixture() -> (
        SyscallDispatcher,
        crate::kernel::KernelContext,
        ThreadExecutionLease,
        MmExecutorParticipation,
        Arc<crate::kernel::GuestExecutorCensus>,
        carrick_hal::ThreadId,
    ) {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher
            .capture_one_task_context()
            .expect("capture dispatcher task");
        let lease = running_lease(&context);
        let tid = carrick_hal::ThreadId::synthetic_for_tests(41);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let endpoint: Arc<dyn carrick_hal::VcpuRegistry> = registry;
        let executor = dispatcher
            .enter_mm_executor_for_thread(Some(context.thread().clone()), endpoint, tid)
            .expect("admit exact MM executor");
        let census = dispatcher.mm_executor_census();
        (dispatcher, context, lease, executor, census, tid)
    }

    fn settle_fixture(
        context: &crate::kernel::KernelContext,
        lease: ThreadExecutionLease,
        executor: MmExecutorParticipation,
    ) {
        drop(executor);
        context
            .thread()
            .yield_from_executor(lease)
            .expect("settle execution lease");
    }

    #[test]
    fn caller_mm_executor_is_absent_during_operation_and_exact_identity_is_restored() {
        let (dispatcher, context, lease, mut executor, census, tid) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let value = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    0x5eed_u64
                })
                .expect("release and restore exact caller MM executor");
            assert_eq!(value, 0x5eed);
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        let exact = executor.participation_mut().lock_exact_mm();
        assert_eq!(exact.pause_endpoint_tids(), vec![tid]);
        drop(exact);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");

        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_is_restored_when_operation_returns_error() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let operation = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    Err::<(), LinuxErrno>(crate::linux_abi::LINUX_EFAULT)
                })
                .expect("boundary itself succeeds");
            assert_eq!(operation, Err(crate::linux_abi::LINUX_EFAULT));
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");
        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_is_restored_before_operation_panic_resumes() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = dispatcher.with_current_mm_executor_released(&mut syscall, || -> () {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    panic!("injected operation panic");
                });
            }));
            assert!(panic.is_err(), "operation panic must resume after re-entry");
        }
        assert_eq!(census.participant_count_for_probe(), 1);
        context
            .thread()
            .validate_running_execution_lease(&lease)
            .expect("same execution lease remains running");
        settle_fixture(&context, lease, executor);
    }

    #[test]
    fn caller_mm_executor_reports_dispatcher_binding_drift_after_reentry() {
        let (dispatcher, context, lease, mut executor, census, _) = boundary_fixture();
        let original = dispatcher.mm_binding.current.load_full();
        let replacement = Arc::new(DispatchMmAuthority::new_for_test_with_revision(
            original.vma_revision(),
        ));
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(0x1_0000, vec![0; 0x1000]);
        {
            let mut syscall = SyscallCtx {
                kernel: &context,
                request: SyscallRequest::new(271, SyscallArgs::from([0; 6])),
                memory: &mut memory,
                reporter: &reporter,
                thread: None,
                execution_lease: Some(&lease),
                mm_executor: Some(&mut executor),
            };

            let error = dispatcher
                .with_current_mm_executor_released(&mut syscall, || {
                    assert_eq!(census.participant_count_for_probe(), 0);
                    dispatcher.replace_current_mm_for_test(replacement);
                })
                .expect_err("post-operation dispatcher binding drift must fail typed");
            assert!(matches!(error, DispatchError::MmExecutorBindingDrift));
        }
        assert_eq!(census.participant_count_for_probe(), 1);

        dispatcher.replace_current_mm_for_test(original);
        settle_fixture(&context, lease, executor);
    }
}

pub(crate) struct PreparedDispatchMmFork {
    pub(crate) parent_mm_id: crate::kernel::MmId,
    pub(crate) child_mm_id: crate::kernel::MmId,
    pub(crate) parent_mm: Arc<DispatchMmAuthority>,
    pub(crate) parent_revision: crate::kernel::VmaRevision,
    pub(crate) mode: crate::kernel::CloneObjectMode,
    pub(crate) child_mm: Arc<DispatchMmAuthority>,
    pub(crate) backend_plan: Arc<[carrick_hal::ForkProjectionRange]>,
}

impl PreparedDispatchMmFork {
    pub(crate) fn fork_projection_plan(&self) -> carrick_hal::ForkProjectionPlan {
        match self.mode {
            crate::kernel::CloneObjectMode::Share => carrick_hal::ForkProjectionPlan::Shared {
                parent_mm: self.parent_mm_id.raw(),
                ranges: Arc::clone(&self.backend_plan),
            },
            crate::kernel::CloneObjectMode::Copy => carrick_hal::ForkProjectionPlan::Copied {
                parent_mm: self.parent_mm_id.raw(),
                child_mm: self.child_mm_id.raw(),
                ranges: Arc::clone(&self.backend_plan),
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrepareDispatchMmForkError {
    #[error(transparent)]
    Projection(#[from] carrick_hal::ForkProjectionError),
    #[error("shared MM preparation requires identical parent and child MM identities")]
    SharedIdentityMismatch,
    #[error("copied MM preparation requires distinct parent and child MM identities")]
    CopiedIdentityCollision,
}

pub(crate) struct DispatchMmBinding {
    current: arc_swap::ArcSwap<DispatchMmAuthority>,
    staged_exec: Mutex<Option<Arc<DispatchMmAuthority>>>,
}

impl DispatchMmBinding {
    pub(in crate::dispatch) fn new(current: Arc<DispatchMmAuthority>) -> Arc<Self> {
        Arc::new(Self {
            current: arc_swap::ArcSwap::new(current),
            staged_exec: Mutex::new(None),
        })
    }

    fn stage_private_exec(
        self: &Arc<Self>,
        replacement_mm_id: crate::kernel::MmId,
    ) -> PreparedDispatchMmExec {
        // The replacement stays private until promotion. Snapshot the current
        // authority; the exec transaction validates its source revision before
        // publication, so this read-only preparation is not host-alias work.
        let current = self.current.load_full();
        let staged = Arc::new(current.fork_private(replacement_mm_id));
        let mut slot = self.staged_exec.lock();
        if slot.is_some() {
            tracing::error!("dispatcher already has a staged exec MM authority");
            carrick_fatal!(
                "dispatch::mm_binding",
                "dispatcher already has a staged exec MM authority"
            );
        }
        *slot = Some(Arc::clone(&staged));
        PreparedDispatchMmExec {
            binding: Arc::clone(self),
            predecessor: current,
            staged,
            committed: false,
        }
    }

    fn rebind_prepared_root(&self, mm_id: crate::kernel::MmId) {
        let staged = self.staged_exec.lock();
        if staged.is_some() {
            tracing::error!("cannot rebind a prepared root with a staged exec MM");
            carrick_fatal!(
                "dispatch::mm_binding",
                "cannot rebind a prepared root with a staged exec MM"
            );
        }
        let current = self.current.load_full();
        if current.mm_id != mm_id {
            self.current
                .store(Arc::new(current.rebind_prepared_root(mm_id)));
        }
    }

    pub(crate) fn begin_dispatch<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
        marks_vma: bool,
    ) -> HostAliasDispatchGuard<'permit> {
        loop {
            let authority = self.current.load_full();
            let guard = authority
                .host_alias_transactions
                .begin_dispatch(permit, &authority.mutation_coordinator)
                .with_authority(Arc::clone(&authority));
            if Arc::ptr_eq(&self.current.load_full(), &authority) {
                return if marks_vma {
                    guard.with_vma_revision(authority.mem.revision_publisher())
                } else {
                    guard
                };
            }
            // Promotion won after selection but before exclusion. Releasing
            // the stale guard and retrying prevents an old transaction from
            // ever pairing with the new authority's memory.
            drop(guard);
        }
    }

    /// Begin a host-alias dispatch phase on `expected` only if it is still the
    /// live authority AND `permit` was minted for it.
    ///
    /// `begin_dispatch` retries against whatever authority is current, which is
    /// right for a syscall whose permit came from the same executor turn. A
    /// fork install is different: its permit and its prepared parent were
    /// captured BEFORE the copy phase, so an exec promotion racing the copy
    /// leaves both stale. `MmMutationCoordinator::begin_alias` treats a
    /// permit for another MM as a broken authority chain and aborts the
    /// carrier; here staleness is an ordinary outcome, so it is reported as
    /// `None` and the caller lowers it to a retryable failure.
    pub(in crate::dispatch) fn begin_dispatch_for<'permit>(
        &self,
        permit: &'permit mm_mutation::HostAliasPermit<'_>,
        expected: &Arc<DispatchMmAuthority>,
    ) -> Option<HostAliasDispatchGuard<'permit>> {
        if !permit.authorizes(&expected.mutation_coordinator, expected.mm_id) {
            return None;
        }
        if !Arc::ptr_eq(&self.current.load_full(), expected) {
            return None;
        }
        let guard = expected
            .host_alias_transactions
            .begin_dispatch(permit, &expected.mutation_coordinator)
            .with_authority(Arc::clone(expected));
        if Arc::ptr_eq(&self.current.load_full(), expected) {
            Some(guard)
        } else {
            // Promotion won between selection and exclusion; the caller's
            // observation is stale, not merely delayed.
            drop(guard);
            None
        }
    }
}

pub(crate) struct PreparedDispatchMmExec {
    binding: Arc<DispatchMmBinding>,
    predecessor: Arc<DispatchMmAuthority>,
    staged: Arc<DispatchMmAuthority>,
    committed: bool,
}

impl PreparedDispatchMmExec {
    pub(crate) fn vma_snapshot_source(&self) -> crate::kernel::SharedVmaSnapshotSource {
        self.staged.clone()
    }

    pub(crate) fn commit(mut self) {
        let mut staged = self.binding.staged_exec.lock();
        if !staged
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &self.staged))
        {
            tracing::error!("staged dispatcher exec MM authority changed before commit");
            carrick_fatal!(
                "dispatch::mm_exec_commit",
                "staged dispatcher exec MM authority changed before commit"
            );
        }
        let predecessor = self
            .predecessor
            .host_alias_transactions
            .with_non_dispatching_phase(|| {
                self.binding
                    .current
                    .compare_and_swap(&self.predecessor, Arc::clone(&self.staged))
            });
        if !Arc::ptr_eq(&predecessor, &self.predecessor) {
            tracing::error!("dispatcher exec MM predecessor changed before commit");
            carrick_fatal!(
                "dispatch::mm_exec_commit",
                "dispatcher exec MM predecessor changed before commit"
            );
        }
        *staged = None;
        self.committed = true;
    }
}

impl Drop for PreparedDispatchMmExec {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut staged = self.binding.staged_exec.lock();
        if staged
            .as_ref()
            .is_some_and(|candidate| Arc::ptr_eq(candidate, &self.staged))
        {
            *staged = None;
        }
    }
}

impl std::fmt::Debug for DispatchMmAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DispatchMmAuthority")
    }
}

impl crate::kernel::VmaSnapshotSource for DispatchMmAuthority {
    fn snapshot(
        &self,
        deadline: std::time::Instant,
    ) -> Result<crate::kernel::OwnedVmaSnapshot, crate::kernel::SnapshotError> {
        let _snapshot = self
            .mutation_coordinator
            .begin_snapshot_until(deadline)
            .ok_or_else(|| {
                if std::time::Instant::now() >= deadline {
                    crate::kernel::SnapshotError::TimedOut
                } else {
                    crate::kernel::SnapshotError::Busy
                }
            })?;
        self.mem.snapshot_until(deadline)
    }

    fn revision(&self) -> crate::kernel::VmaRevision {
        self.mem.vma_revision()
    }

    fn publish_if_revision(
        &self,
        expected: crate::kernel::VmaRevision,
        deadline: std::time::Instant,
        publish: &mut dyn FnMut() -> Result<(), crate::kernel::SnapshotError>,
    ) -> Result<(), crate::kernel::SnapshotError> {
        let _snapshot = self
            .mutation_coordinator
            .begin_snapshot_until(deadline)
            .ok_or_else(|| {
                if std::time::Instant::now() >= deadline {
                    crate::kernel::SnapshotError::TimedOut
                } else {
                    crate::kernel::SnapshotError::Busy
                }
            })?;
        if self.mem.vma_revision() != expected {
            return Err(crate::kernel::SnapshotError::ChangedDuringObservation);
        }
        publish()
    }
}

#[derive(Debug)]
pub(crate) enum AuthorityCallError {
    Rejected(crate::file_authority::AuthorityError),
    Fatal(crate::file_authority::AuthorityFatal),
}

/// Owns an epoll instance's kqueue and keeps it in the in-memory-wake registry
/// for its lifetime (deregistered on drop). Derefs to the inner `Kqueue` so the
/// epoll handlers use it transparently.
///
/// On the Linux lane it ALSO owns the instance's SELF-WAKE PIPE. The Linux
/// `epoll_pwait` emulation samples readiness once, then parks in a plain host
/// `ppoll` over the interest set's host fds — a snapshot the rest of the
/// process can invalidate while the waiter sleeps: a sibling's `read`/`splice`
/// drains the edge the park-set's ET exclusion was computed from (the go-os
/// TestSpliceFile deaf-park wedge), an `epoll_ctl` ADDs an fd the parked
/// `ppoll` doesn't watch, a `close` removes one. macOS doesn't have this
/// problem — the persistent kqueue is shared, so registrations and EV_CLEAR
/// re-arms reach a parked waiter natively. The wake pipe restores that
/// property: the park set always includes the read end, and every
/// snapshot-invalidating mutation (`epoll_rearm_after_io`, `epoll_ctl`,
/// `detach_fd_from_epolls`) writes a byte, forcing the parked waiter to
/// re-dispatch and rebuild from fresh state. The byte persists until the next
/// dispatch drains it, so a wake between sample and park is never lost.
/// An epoll instance's persistent readiness backend.
///
/// The backend is a boxed [`EventMultiplexer`](carrick_hal::event::EventMultiplexer):
/// kqueue-backed on macOS (`carrick_host_bsd::KqueueMultiplexer`), epoll-backed on
/// Linux (`carrick_host_linux::EpollMultiplexer`). `epoll_ctl` registers host-fd
/// interest through the trait and `epoll_pwait` drains it. The mux is wrapped in
/// a `Mutex` because the instance is shared via `Arc` (so a dup'd epoll fd refers
/// to the same backend) yet the trait's mutating methods need `&mut`; every call
/// site holds the lock only for a non-blocking change/drain (the blocking wait
/// happens on the `poll_fd` via the runtime's poll park, never under this lock).
/// `poll_fd` is cached so `Drop`/the wake registry/`host_fd_for_poll` read it
/// lock-free.
pub(crate) struct EpollKqueue {
    mux: std::sync::Mutex<Box<dyn carrick_hal::event::EventMultiplexer>>,
    /// Cached `mux.poll_fd()` (the kqueue/epoll fd) — stable for the instance's
    /// life, read lock-free by `Drop` and `host_fd_for_poll`.
    poll_fd: i32,
    /// The fd the in-memory wake registry pulses to pop a parked waiter on this
    /// instance: the user-wake `eventfd` on Linux (a separate fd) or the kqueue
    /// `poll_fd` on macOS (EVFILT_USER rides the kqueue fd). Stable for life;
    /// read lock-free by the registry and `Drop`.
    wake_fd: i32,
    wake_registry: EpollWakeRegistry,
}

impl EpollKqueue {
    /// Take ownership of a freshly-built multiplexer (its user-wake channel
    /// `register_user(0)` already armed) and record it in the in-memory wake
    /// registry so `notify_inmem_epoll`/`wake_parked` can reach this instance.
    pub(crate) fn new(
        mux: Box<dyn carrick_hal::event::EventMultiplexer>,
        wake_registry: EpollWakeRegistry,
    ) -> Self {
        let poll_fd = mux.poll_fd();
        // On Linux the user-wake is a separate eventfd; on macOS it rides the
        // kqueue fd, so fall back to poll_fd. The registry pulses this fd.
        let wake_fd = mux.user_wake_fd(0).unwrap_or(poll_fd);
        register_epoll_kqueue(&wake_registry, wake_fd);
        Self {
            mux: std::sync::Mutex::new(mux),
            poll_fd,
            wake_fd,
            wake_registry,
        }
    }

    /// The pollable fd readable when any registered event is ready. The runtime
    /// parks `WaitOnPollFds` on this; the wake registry and the epoll-fd
    /// readiness computation also read it.
    pub(crate) fn poll_fd(&self) -> i32 {
        self.poll_fd
    }

    /// Run a closure against the underlying multiplexer (locked for the call).
    /// Used by the epoll dispatch for non-blocking register/drain only.
    pub(crate) fn with_mux<R>(
        &self,
        f: impl FnOnce(&mut dyn carrick_hal::event::EventMultiplexer) -> R,
    ) -> R {
        let mut guard = self.mux.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut **guard)
    }

    /// Wake any waiter parked on this instance's `poll_fd` so it re-checks
    /// readiness. This fires the multiplexer's user-wake (`trigger_user(0)`),
    /// which makes the epoll `poll_fd` readable and pops the park; the parked
    /// thread re-samples and re-parks armed. The shared epoll set already
    /// auto-wakes on an ADD-of-ready-fd, so this covers readiness changes that
    /// don't ride a freshly-registered fd: ET re-arm, write-backpressure latch
    /// changes, and in-memory readiness broadcasts. Best-effort — a saturated
    /// user-wake is already a pending wake.
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn wake_parked(&self) {
        self.with_mux(|mux| {
            let _ = mux.trigger_user(0);
        });
    }
}

impl std::fmt::Debug for EpollKqueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `dyn EventMultiplexer` is not `Debug`; expose the stable poll fd only.
        f.debug_struct("EpollKqueue")
            .field("poll_fd", &self.poll_fd())
            .finish_non_exhaustive()
    }
}

impl Drop for EpollKqueue {
    fn drop(&mut self) {
        unregister_epoll_kqueue(&self.wake_registry, self.wake_fd);
    }
}

#[cfg(test)]
mod epoll_kqueue_tests {
    use super::*;

    #[test]
    fn wake_parked_makes_poll_fd_readable() {
        let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
        mux.register_user(0).expect("register user wake");
        let epoll = EpollKqueue::new(mux, new_epoll_wake_registry());

        epoll.wake_parked();

        let mut pfd = libc::pollfd {
            fd: epoll.poll_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
        assert_eq!(rc, 1, "epoll user wake must make poll_fd readable");
        assert_ne!(pfd.revents & libc::POLLIN, 0);
    }
}

/// Normalize an already-absolute (leading-`/`) guest path: collapse `//`,
/// drop `.` components, and resolve `..` lexically (Linux `/proc/self/exe`
/// stores a resolved absolute path). Always returns a leading-`/` path.
pub(in crate::dispatch) fn normalize_abs_path(path: &str) -> String {
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

/// A normalized syscall handler resolved to a bare function pointer: the
/// `define_syscall!`-generated `sys_*` methods all share this signature, so a
/// `number → handler` table is just a `match` returning one of these. Each
/// dispatch module owns a `dispatch_<area>(number) -> Option<SyscallHandler<M>>`
/// over the numbers IT implements; `dispatch_normalized` chains them. Adding a
/// syscall is then a one-module edit — no shared routing table to contend on
/// (Task A1). See [[plan-concurrent-fanout-lanes]] Part A.
pub(crate) type SyscallHandler<M> =
    fn(&SyscallDispatcher, &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>;
pub(crate) type MutationSyscallHandler<M> =
    fn(&SyscallDispatcher, &mut MutationSyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>;

/// Resolve a syscall number to its handler by chaining every dispatch module's
/// own routing table. This is the single source of truth for "is this number
/// claimed, and by which handler"; both `dispatch_normalized` (which builds the
/// ctx and invokes the handler) and `dispatch_normalized_known` (the membership
/// test) go through it. Each module owns its own arms, so a future agent adds a
/// syscall by editing ONE module's `dispatch_<area>` — never this function (the
/// central `dispatch()` chokepoint is gone). See [[plan-concurrent-fanout-lanes]].
fn resolve_handler<M: CurrentMmMemory>(number: u64) -> Option<SyscallHandler<M>> {
    fs::dispatch_fs(number)
        .or_else(|| net::dispatch_net(number))
        .or_else(|| mem::dispatch_mem(number))
        .or_else(|| proc::dispatch_proc(number))
        .or_else(|| keys::dispatch_keys(number))
        .or_else(|| signal::dispatch_signal(number))
        .or_else(|| time::dispatch_time(number))
        .or_else(|| creds::dispatch_creds(number))
        .or_else(|| sysv::dispatch_sysv(number))
        .or_else(|| mqueue::dispatch_mqueue(number))
        .or_else(|| bpf::dispatch_bpf(number))
        .or_else(|| perf::dispatch_perf(number))
        .or_else(|| mount_api::dispatch_mount_api(number))
        .or_else(|| syslog::dispatch_syslog(number))
}

fn resolve_mutation_handler<M: CurrentMmMemory>(number: u64) -> Option<MutationSyscallHandler<M>> {
    fs::dispatch_fs_mutation(number)
        .or_else(|| mem::dispatch_mem_mutation(number))
        .or_else(|| sysv::dispatch_sysv_mutation(number))
}

pub(crate) const MM_MUTATION_SYSCALLS: &[u64] = &[
    25, 196, 197, 214, 215, 216, 222, 226, 227, 228, 229, 230, 231, 232, 233, 234, 284,
];

pub(crate) fn syscall_requires_mm_mutation(number: u64, _args: SyscallArgs) -> bool {
    MM_MUTATION_SYSCALLS.contains(&number)
}

trait NormalizedDispatchRoute {
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        _kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>>;
}

struct OrdinaryDispatchRoute<'lease, 'executor> {
    lease: Option<&'lease crate::kernel::objects::ThreadExecutionLease>,
    mm_executor: Option<&'executor mut MmExecutorParticipation>,
}

impl NormalizedDispatchRoute for OrdinaryDispatchRoute<'_, '_> {
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        dispatcher.dispatch_normalized_with_lease(
            kernel,
            request,
            memory,
            reporter,
            thread,
            self.lease,
            self.mm_executor.take(),
        )
    }
}

struct MutationDispatchRoute<'guard, 'authority, 'lease> {
    guard: &'guard mut mm_mutation::MmMutationGuard<'authority>,
    lease: Option<&'lease crate::kernel::objects::ThreadExecutionLease>,
}

impl NormalizedDispatchRoute for MutationDispatchRoute<'_, '_, '_> {
    fn dispatch<M: CurrentMmMemory>(
        &mut self,
        dispatcher: &SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut M,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        dispatcher.dispatch_normalized_mutation(
            kernel, request, memory, reporter, thread, self.guard, self.lease,
        )
    }
}

/// True once the kernel lane's first process has bound. On that lane a Linux
/// process is a THREAD of this host process, so a guest pid is NOT a host pid
/// and must never be handed to a host call that takes one.
///
/// A process-global flag, following the precedent of
/// `guest_cpu::set_native_host_provider`: the free functions that need this
/// fact (the signal send path) hold no dispatcher, and threading one through
/// every caller would be a larger change than the fact warrants.
pub(crate) static HVPATCH_LANE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(crate) fn hvpatch_lane_active() -> bool {
    HVPATCH_LANE.load(std::sync::atomic::Ordering::Acquire)
}

/// Scoped override of the carrier-global HVPatch lane flag, for tests only.
///
/// `HVPATCH_LANE` describes the CARRIER: `bind_hvpatch_process` sets it once and
/// nothing ever clears it, which is correct for a run and wrong inside a test
/// binary, where every test after the first binding silently observes a
/// different lane than the one it was written against. That is the scope-domain
/// hazard `docs/identity-and-scope-domains.md` names: a `static` carrying no
/// mark saying what it describes. A test that asserts either side of the flag
/// takes this guard and gets a deterministic answer regardless of run order.
#[cfg(test)]
pub(crate) struct HvpatchLaneScope(bool);

#[cfg(test)]
impl HvpatchLaneScope {
    pub(crate) fn force(active: bool) -> Self {
        Self(HVPATCH_LANE.swap(active, std::sync::atomic::Ordering::AcqRel))
    }
}

#[cfg(test)]
impl Drop for HvpatchLaneScope {
    fn drop(&mut self) {
        HVPATCH_LANE.store(self.0, std::sync::atomic::Ordering::Release);
    }
}

impl SyscallDispatcher {
    fn mm_authority(&self) -> arc_swap::Guard<Arc<DispatchMmAuthority>> {
        self.mm_binding.current.load()
    }

    pub(crate) fn mem(&self) -> arc_swap::Guard<Arc<DispatchMmAuthority>> {
        self.mm_authority()
    }

    pub(crate) fn pt_quiesce(&self) -> Arc<carrick_thread::fork_quiesce::PtQuiesce> {
        Arc::clone(self.mm_authority().pt_quiesce())
    }

    #[cfg(test)]
    fn host_alias_transactions(&self) -> Arc<HostAliasTransactions> {
        Arc::clone(&self.mm_authority().host_alias_transactions)
    }

    pub(crate) fn vma_snapshot_source(&self) -> crate::kernel::SharedVmaSnapshotSource {
        self.mm_binding.current.load_full()
    }

    pub(crate) fn timer_delivery(&self) -> Option<Arc<dyn carrick_hal::TimerDelivery>> {
        self.timer_delivery
            .read()
            .clone()
            .or_else(crate::timer_delivery::delivery)
    }

    /// Dispatch a syscall through the chained per-module routing. Returns `None`
    /// for an unclaimed number (the caller ENOSYSes); otherwise builds the
    /// transient `SyscallCtx` and invokes the resolved handler.
    #[cfg(test)]
    fn dispatch_normalized(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        self.dispatch_normalized_with_lease(kernel, request, memory, reporter, thread, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_normalized_with_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
        execution_lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
        mm_executor: Option<&mut MmExecutorParticipation>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        let handler = resolve_handler(request.number.raw())?;
        let canonical_nr = request.number.raw();
        let mut ctx = SyscallCtx {
            kernel,
            request,
            memory,
            reporter,
            thread,
            execution_lease,
            mm_executor,
        };
        let outcome = resources::with_captured_resources(kernel, || handler(self, &mut ctx));
        // Single choke point for the fork-coherent resolve cache: a structural
        // namespace mutation (mkdirat/unlinkat/symlinkat/linkat/renameat/
        // renameat2/mknodat) can change how OTHER paths resolve, so bump the
        // shared generation that invalidates every process's cache. Every guest
        // syscall funnels through here exactly once; content writes are not in
        // the set, so a syscall-bound write/lseek loop keeps its cached resolves.
        if fs::is_structural_namespace_mutation(canonical_nr) {
            crate::fs_resolve_cache::bump_generation();
        }
        Some(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_normalized_mutation<'authority, 'lease>(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
        mm_mutation: &mut mm_mutation::MmMutationGuard<'authority>,
        execution_lease: Option<&'lease crate::kernel::objects::ThreadExecutionLease>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        let handler = resolve_mutation_handler(request.number.raw())?;
        let mut ctx = MutationSyscallCtx {
            kernel,
            request,
            memory,
            reporter,
            thread,
            mm_mutation,
            execution_lease,
        };
        Some(resources::with_captured_resources(kernel, || {
            handler(self, &mut ctx)
        }))
    }

    /// Focused unit-test boundary for mutation handlers. Production callers
    /// receive their guard from the exact-MM executor census; tests use the
    /// real page-table-pause issuer rather than falling back to the ordinary
    /// route (which intentionally cannot resolve mutation syscalls).
    #[cfg(test)]
    fn dispatch_normalized_mutation_for_test(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        mm_mutation::test_support::with_guard(self.mm_mutation_coordinator(), |guard| {
            self.dispatch_normalized_mutation(
                kernel, request, memory, reporter, thread, guard, None,
            )
        })
    }

    /// Membership test: is `number` claimed by some dispatch module? Mirrors
    /// `dispatch_normalized` exactly (both go through `resolve_handler`), so the
    /// two can never drift. Uses `LinearMemory` as the concrete memory type —
    /// the claimed set is independent of `M`.
    fn dispatch_normalized_known(number: u64) -> bool {
        resolve_handler::<LinearMemory>(number).is_some()
            || resolve_mutation_handler::<LinearMemory>(number).is_some()
    }

    /// Characterization seam for the per-module routing refactor (Task A1).
    ///
    /// Returns whether the (chained) normalized routing claims `number` — i.e.
    /// whether some dispatch module owns a handler for it. This is the single
    /// membership oracle the `routing_tests` characterization test pins against,
    /// so the refactor that moves arms out of the central table and into each
    /// module's `dispatch_<area>` cannot silently drop or re-route a number.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolves(&self, number: u64) -> bool {
        Self::dispatch_normalized_known(number)
    }

    /// Keep the CALLING MM's vvar `VVAR_OFF_REALTIME_OFF_NS` word coherent with
    /// the guest realtime offset, so the userspace vDSO `clock_gettime` and the
    /// trapping syscall agree after `clock_settime` / `settimeofday`.
    ///
    /// The vvar page is per MM, and a foreign MM has no stage-1 walker bound to
    /// it, so a change cannot be broadcast from the setter. Instead every MM
    /// re-stamps ITSELF at its next syscall entry when the global epoch has
    /// moved (and at the post-exec identity stamp, so an exec'd image reads
    /// the moved clock before its first syscall). Per-syscall cost when
    /// nothing changed: one Acquire load of the epoch, one `ArcSwap::load` of
    /// the current MM authority and one Acquire load — no write, no lock. One
    /// 8-byte carrick-internal write per MM per change. The setter's own MM is
    /// stamped inline by [`Self::set_guest_realtime`] before the syscall
    /// returns, so a vDSO read issued right after it already agrees.
    ///
    /// The VMM stampers publish the host calibration only; the guest delta
    /// enters the word here, through the single
    /// `carrick_mem::vdso::vvar_realtime_off_ns` computation.
    ///
    /// `write_bytes_unchecked` bypasses the guest-visible read-only permission
    /// of the vvar and splits a fork-shared frame (`PrivilegedInternal`), like
    /// the RNG-generation re-stamp. An MM with no vvar mapped at
    /// `LINUX_VVAR_BASE` (`CARRICK_DISABLE_VDSO=1`, the relocated native-lane
    /// vvar) has nothing to keep coherent: `OutOfBounds` at that fixed VA means
    /// exactly that (the aarch64 engine's `syscall_buffer_chunk` reports an
    /// unmapped VA as `OutOfBounds`) and is not an error. Any other failure is.
    pub(crate) fn sync_vvar_realtime_offset(
        &self,
        clock: &crate::kernel::container::ClockDomain,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<(), MemoryError> {
        let epoch = clock.epoch();
        // Epoch 0 means no guest has ever moved the clock in this container, so
        // every MM's vvar still holds exactly what the VMM stamper published
        // for it at boot (a fork child inherits that content, an exec'd MM is
        // stamped fresh) and no re-stamp can change a byte. Answering that
        // from ONE load of a domain atomic keeps the ArcSwap `mm_binding` load — the
        // expensive half of this check — off the syscall path entirely until
        // a `clock_settime` actually happens. This function runs on every
        // dispatched syscall, so the untaken case is the one that has to be
        // cheap.
        if epoch == 0 {
            return Ok(());
        }
        let authority = self.mm_binding.current.load();
        if authority
            .vvar_realtime_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            == epoch
        {
            return Ok(());
        }
        if let Some(host_off_ns) = crate::vdso::realtime_off_ns() {
            let word = crate::vdso::vvar_realtime_off_ns(host_off_ns, clock.realtime_offset_ns());
            match memory.write_bytes_unchecked(
                crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
                &word.to_le_bytes(),
            ) {
                Ok(()) | Err(MemoryError::OutOfBounds { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        authority
            .vvar_realtime_epoch
            .store(epoch, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// `clock_settime(CLOCK_REALTIME)` / `settimeofday`: move the guest wall
    /// clock so that "now" reads `target`, then stamp the caller's vvar at once.
    /// The delta is measured against the host-calibrated base, never against a
    /// transiently-zeroed offset, so concurrent readers never observe a
    /// momentary jump back to host time.
    pub(crate) fn set_guest_realtime(
        &self,
        clock: &crate::kernel::container::ClockDomain,
        memory: &mut impl CurrentMmMemory,
        target: Duration,
    ) -> Result<(), DispatchError> {
        if clock.is_controlled() {
            return Err(DispatchError::Errno(carrick_abi::LINUX_EPERM));
        }
        let base = clock.realtime_base_now();
        let delta_ns = if target >= base {
            i64::try_from((target - base).as_nanos()).unwrap_or(i64::MAX)
        } else {
            i64::try_from((base - target).as_nanos())
                .map(|n| -n)
                .unwrap_or(i64::MIN)
        };
        clock
            .try_set_realtime_offset_ns(delta_ns)
            .map_err(DispatchError::Errno)?;
        self.sync_vvar_realtime_offset(clock, memory)?;
        Ok(())
    }

    pub(crate) fn deferred_anonymous_state(
        &self,
        mm: crate::kernel::MmId,
    ) -> Option<Arc<carrick_guest_mem::DeferredAnonymousState>> {
        let authority = self.mm_authority();
        (authority.mm_id == mm).then(|| Arc::clone(&authority.lock().deferred_anonymous))
    }

    pub(crate) fn bind_deferred_anonymous_state(
        &self,
        memory: &mut impl carrick_guest_mem::CurrentMmMemory,
        mm: crate::kernel::MmId,
    ) -> bool {
        let authority = self.mm_authority();
        if authority.mm_id != mm {
            return false;
        }
        let state = Arc::clone(&authority.lock().deferred_anonymous);
        memory.bind_deferred_anonymous_state(state);
        true
    }

    pub(crate) fn mm_mutation_coordinator(&self) -> Arc<mm_mutation::MmMutationCoordinator> {
        Arc::clone(&self.mm_authority().mutation_coordinator)
    }

    pub(crate) fn foreign_mm_mutation_authority(
        &self,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
    ) -> mm_mutation::ForeignMmMutationAuthority {
        let authority = self.mm_authority();
        mm_mutation::ForeignMmMutationAuthority::new(
            authority.mm_id,
            Arc::clone(&authority.mutation_coordinator),
            Arc::clone(&authority.guest_executors),
            stage1,
            Arc::clone(&authority.pt_quiesce),
        )
    }

    pub(crate) fn mm_executor_census(&self) -> Arc<crate::kernel::GuestExecutorCensus> {
        Arc::clone(&self.mm_authority().guest_executors)
    }

    /// Enter the executor census owned by the exact current dispatch MM.
    ///
    /// A CLONE_VM dispatcher shares this census even though its dispatcher
    /// binding object is distinct. If exec promotion changes the selected MM
    /// during admission, the stale participation is dropped and selection is
    /// retried.
    pub fn enter_mm_executor(
        &self,
    ) -> Result<MmExecutorParticipation, crate::kernel::GuestExecutorCensusError> {
        self.enter_mm_executor_inner(None, None)
    }

    pub(crate) fn enter_mm_executor_for_thread(
        &self,
        thread: Option<crate::kernel::ThreadRef>,
        registry: Arc<dyn carrick_hal::VcpuRegistry>,
        tid: carrick_hal::ThreadId,
    ) -> Result<MmExecutorParticipation, crate::kernel::GuestExecutorCensusError> {
        self.enter_mm_executor_inner(thread, Some((registry, tid)))
    }

    fn enter_mm_executor_inner(
        &self,
        thread: Option<crate::kernel::ThreadRef>,
        pause_endpoint: Option<(Arc<dyn carrick_hal::VcpuRegistry>, carrick_hal::ThreadId)>,
    ) -> Result<MmExecutorParticipation, crate::kernel::GuestExecutorCensusError> {
        loop {
            let authority = self.mm_binding.current.load_full();
            let admission = match (&thread, &pause_endpoint) {
                (None, None) => MmExecutorAdmissionRecipe::Anonymous,
                (None, Some((registry, tid))) => {
                    MmExecutorAdmissionRecipe::AnonymousWithPauseEndpoint {
                        registry: Arc::clone(registry),
                        tid: *tid,
                    }
                }
                (Some(thread), Some((registry, tid))) => MmExecutorAdmissionRecipe::Thread {
                    thread: thread.clone(),
                    registry: Arc::clone(registry),
                    tid: *tid,
                },
                _ => {
                    tracing::error!(
                        "MM executor admission must be anonymous or carry an exact thread pause endpoint"
                    );
                    carrick_fatal!(
                        "dispatch::mm_executor_admission",
                        "MM executor admission must be anonymous or carry an exact thread pause endpoint"
                    )
                }
            };
            let participation = admission.enter(&authority)?;
            if Arc::ptr_eq(&self.mm_binding.current.load_full(), &authority) {
                return Ok(MmExecutorParticipation {
                    authority,
                    admission,
                    participation: Some(participation),
                });
            }
        }
    }

    fn validate_current_mm_executor(
        &self,
        executor: &MmExecutorParticipation,
        kernel: &crate::kernel::KernelContext,
        execution_lease: &crate::kernel::objects::ThreadExecutionLease,
    ) -> Result<(), DispatchError> {
        let current = self.mm_binding.current.load_full();
        if !executor.authorizes(&current) {
            return Err(DispatchError::MmExecutorBindingDrift);
        }
        let kernel_mm = kernel.shared().mm().id();
        if executor.mm_id() != kernel_mm {
            return Err(DispatchError::MmExecutorKernelMmMismatch {
                executor: executor.mm_id(),
                kernel: kernel_mm,
            });
        }
        if !executor.validates_thread_identity(kernel.thread()) {
            return Err(DispatchError::MmExecutorThreadIdentityMismatch);
        }
        kernel
            .thread()
            .validate_running_execution_lease(execution_lease)
            .map_err(DispatchError::MmExecutorExecutionLease)?;
        let (lease_mm, _) = kernel
            .thread()
            .authenticate_task_state_authority(execution_lease)
            .map_err(DispatchError::MmExecutorExecutionLease)?;
        if lease_mm != executor.mm_id() {
            return Err(DispatchError::MmExecutorExecutionMmMismatch {
                executor: executor.mm_id(),
                lease: lease_mm,
            });
        }
        Ok(())
    }

    /// Temporarily remove the caller from its exact MM's executor population,
    /// run `operation`, then re-enter with the same admission recipe.
    ///
    /// This is the narrow phase boundary needed by a foreign-MM operation:
    /// the target-MM pause must not count the caller as a target executor while
    /// the caller is synchronously performing that pause. The dispatcher/MM,
    /// exact thread identity, and running execution lease are authenticated on
    /// both sides. Re-entry failure is fatal because returning to guest code
    /// without census membership would make a later page-table pause unsound.
    pub(crate) fn with_current_mm_executor_released<M: CurrentMmMemory, T>(
        &self,
        syscall: &mut SyscallCtx<'_, M>,
        operation: impl FnOnce() -> T,
    ) -> Result<T, DispatchError> {
        let execution_lease = syscall
            .execution_lease
            .ok_or(DispatchError::MmExecutorExecutionLeaseUnavailable)?;
        let executor = syscall
            .mm_executor
            .as_deref_mut()
            .ok_or(DispatchError::MmExecutorParticipationUnavailable)?;
        self.validate_current_mm_executor(executor, syscall.kernel, execution_lease)?;
        executor.leave_temporarily()?;

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
        if let Err(error) = executor.reenter_exact() {
            tracing::error!(?error, "failed to re-enter exact caller-MM executor census");
            carrick_fatal!(
                "dispatch::mm_executor_reentry",
                "failed to re-enter exact caller-MM executor census"
            );
        }

        match result {
            Ok(value) => {
                self.validate_current_mm_executor(executor, syscall.kernel, execution_lease)?;
                Ok(value)
            }
            Err(payload) => {
                if let Err(error) =
                    self.validate_current_mm_executor(executor, syscall.kernel, execution_lease)
                {
                    tracing::error!(
                        ?error,
                        "caller-MM executor identity drifted while unwinding released operation"
                    );
                    carrick_fatal!(
                        "dispatch::mm_executor_reentry",
                        "caller-MM executor identity drifted while unwinding released operation"
                    );
                }
                std::panic::resume_unwind(payload)
            }
        }
    }

    pub(crate) fn activate_file_authority(
        &self,
        root_table: Arc<crate::kernel::FileTable>,
    ) -> Result<crate::file_authority::FileAuthorityBinding, crate::file_authority::AuthorityFatal>
    {
        let mut authority = self.file_authority.write();
        if let Some(active) = authority.as_ref() {
            if active.is_root_table(&root_table) {
                return Ok(active.binding());
            }
            return Err(crate::file_authority::AuthorityFatal::InvariantViolation(
                "FileAuthority root table mismatch across activations",
            ));
        }
        let run = crate::file_authority::FileAuthorityRun::launch(root_table)?;
        let binding = run.binding();
        *authority = Some(run);
        Ok(binding)
    }

    #[cfg(test)]
    pub(crate) fn file_authority_binding(
        &self,
    ) -> Option<crate::file_authority::FileAuthorityBinding> {
        self.file_authority
            .read()
            .as_ref()
            .map(|active| active.binding())
    }

    pub(crate) fn authority_call(
        &self,
        table: Arc<crate::kernel::FileTable>,
        slot: crate::kernel::objects::FileSlotAuthority,
        command: crate::file_authority::Command,
    ) -> Result<crate::file_authority::Outcome, AuthorityCallError> {
        let authority_guard = self.file_authority.read();
        let Some(active) = authority_guard.as_ref() else {
            return Err(AuthorityCallError::Fatal(
                crate::file_authority::AuthorityFatal::TransportUnavailable,
            ));
        };

        if slot.table() != table.id() {
            return Err(AuthorityCallError::Fatal(
                crate::file_authority::AuthorityFatal::InvariantViolation(
                    "slot table ID does not match target table ID",
                ),
            ));
        }

        let target = crate::file_authority::CanonicalAuthorityTarget { table, slot };
        let response = active
            .execute_canonical(target, command)
            .map_err(AuthorityCallError::Fatal)?;

        match response.outcome {
            crate::file_authority::Outcome::Rejected(error) => {
                Err(AuthorityCallError::Rejected(error))
            }
            outcome => Ok(outcome),
        }
    }

    pub(crate) fn notify_inmem_epoll(&self) {
        notify_inmem_epoll(self.captured_file_table().epoll_wake_registry());
    }

    /// Test-only publication boundary for synthetic boot layouts. Production
    /// publishes the complete initial image through
    /// `publish_initial_image_state`, under exact-MM mutation authority.
    #[cfg(test)]
    pub fn set_address_space_regions(&self, regions: Vec<ProcMapsEntry>) {
        mm_mutation::test_support::with_permit(self.mm_mutation_coordinator(), |permit| {
            let _vma_dispatch = self.begin_vma_dispatch(permit);
            self.replace_address_space_regions(regions);
        });
    }

    /// Publish a synthetic or externally prepared address-space layout under
    /// the same exact-MM mutation authority as production boot publication.
    pub fn publish_address_space_regions(
        &mut self,
        regions: Vec<ProcMapsEntry>,
    ) -> Result<(), DispatchError> {
        self.with_mm_executor_mutation(|dispatcher, mutation| {
            let permit = mutation.host_alias_permit();
            let _vma_dispatch = dispatcher.begin_vma_dispatch(&permit);
            dispatcher.replace_address_space_regions(regions);
        })
    }

    fn replace_address_space_regions(&self, regions: Vec<ProcMapsEntry>) {
        let mem_authority = self.mem();
        let mut mem = mem_authority.lock();
        let layout = mem.layout;
        let brk_current = mem.brk_current;
        let file_mappings = mem.core_file_mappings.clone();
        mem.semantic_vmas =
            mem::semantic_vmas_from_boot_regions(&regions, &file_mappings, layout, brk_current);
        mem.address_space_regions = Some(regions);
    }

    fn replace_address_space_file_mappings(&self, mappings: Vec<crate::core_dump::FileMapping>) {
        let mem_authority = self.mem();
        let mut mem = mem_authority.lock();
        let layout = mem.layout;
        let brk_current = mem.brk_current;
        if let Some(regions) = &mem.address_space_regions {
            mem.semantic_vmas =
                mem::semantic_vmas_from_boot_regions(regions, &mappings, layout, brk_current);
        }
        mem.core_file_mappings = mappings;
    }

    /// Publish the loaded boot image as one VMA generation before the first
    /// guest executor starts. The non-threaded outer boundary admits the exact
    /// MM into its executor census, mints real sole-stage-1 authority, and only
    /// then permits the host-alias/VMA transaction.
    pub(crate) fn publish_initial_image_state(
        &mut self,
        regions: Vec<ProcMapsEntry>,
        auxv: Vec<u8>,
        file_mappings: Vec<crate::core_dump::FileMapping>,
        private_file_backings: Vec<mem::PrivateFileMapEntry>,
    ) -> Result<(), DispatchError> {
        self.with_mm_executor_mutation(|dispatcher, mutation| {
            let permit = mutation.host_alias_permit();
            let _vma_dispatch = dispatcher.begin_vma_dispatch(&permit);
            dispatcher.replace_address_space_regions(regions);
            dispatcher.replace_address_space_file_mappings(file_mappings);
            dispatcher.mem().lock().private_file_maps = private_file_backings;
            dispatcher.set_auxv_image(auxv);
        })
    }

    /// Publish a replacement image's complete dispatcher memory generation.
    /// Reset, boot-region metadata and auxv become visible under one authority
    /// write, so K1 observers cannot see the destructive exec midpoint.
    pub(crate) fn publish_exec_image_state(
        &self,
        replacement_mm_id: crate::kernel::MmId,
        regions: Vec<ProcMapsEntry>,
        auxv: Vec<u8>,
        file_mappings: Vec<crate::core_dump::FileMapping>,
        private_file_backings: Vec<mem::PrivateFileMapEntry>,
    ) -> PreparedDispatchMmExec {
        // Always stage the replacement privately. This avoids asking a
        // racy owner-count question while another CLONE_VM dispatcher can be
        // created or dropped, and keeps even a currently-private exec out of
        // the live authority until the existing successful publication seam.
        let prepared = self.mm_binding.stage_private_exec(replacement_mm_id);
        let authority = Arc::clone(&prepared.staged);
        let mut mem = authority.mem.lock();
        mem.reset_for_execve();
        let layout = mem.layout;
        let brk_current = mem.brk_current;
        mem.semantic_vmas =
            mem::semantic_vmas_from_boot_regions(&regions, &file_mappings, layout, brk_current);
        mem.address_space_regions = Some(regions);
        mem.linux_auxv_image = auxv;
        mem.core_file_mappings = file_mappings;
        mem.private_file_maps = private_file_backings;
        drop(mem);
        prepared
    }

    /// Capture the guest's serialized ELF auxv image (from the loaded
    /// `AddressSpace`) so `/proc/self/auxv` can serve the byte-exact vector the
    /// guest received on its stack. Called alongside `set_address_space_regions`
    /// at boot and on each successful `execve`.
    pub fn set_auxv_image(&self, auxv: Vec<u8>) {
        self.mem().lock().linux_auxv_image = auxv;
    }

    /// High-water mark (bump cursor) of the anonymous mmap arena: the guest has
    /// only ever touched `[LINUX_MMAP_BASE, this)` of the 32 GiB arena window.
    /// `HvfInner::fork` uses it to bound the per-fork resident-page `mincore`
    /// scan to the used prefix instead of all 2M pages of the full window — the
    /// difference between a ~470 ms and a sub-millisecond fork for a guest that
    /// has mmap'd only a sliver (i.e. essentially every guest).
    pub fn mmap_arena_high_water(&self) -> u64 {
        self.mem().lock().mmap_next
    }

    /// Seed the guest's initial credentials (`docker run --user` / image `USER`).
    /// Applied once before the guest starts; defaults to (0, 0) = root.
    pub fn set_credentials(&self, uid: carrick_abi::NsUid, gid: carrick_abi::NsGid) {
        let context = self.capture_one_task_context().unwrap_or_else(|error| {
            tracing::error!(%error, "cannot capture launch credential context");
            carrick_fatal!(
                "dispatch::credentials",
                "cannot capture launch credential context"
            );
        });
        let credentials = self
            .update_credentials(&context, |credentials| {
                credentials.seed_identity(uid, gid);
            })
            .unwrap_or_else(|errno| {
                tracing::error!(errno = errno.get(), "publish launch Kernel credentials");
                carrick_fatal!("dispatch::credentials", "publish launch Kernel credentials");
            });
        self.publish_external_credential_projection(&context, &credentials);
    }

    pub(crate) fn configure_logical_exec_context(
        &self,
        context: &crate::kernel::KernelContext,
        workdir: Option<&str>,
        user: Option<(
            carrick_abi::NsUid,
            carrick_abi::NsGid,
            Vec<carrick_abi::NsGid>,
        )>,
    ) -> Result<crate::kernel::KernelContext, crate::linux_abi::LinuxErrno> {
        self.with_kernel_resources(context, || {
            self.configure_logical_exec_context_scoped(context, workdir, user)
        })
    }

    fn configure_logical_exec_context_scoped(
        &self,
        context: &crate::kernel::KernelContext,
        workdir: Option<&str>,
        user: Option<(
            carrick_abi::NsUid,
            carrick_abi::NsGid,
            Vec<carrick_abi::NsGid>,
        )>,
    ) -> Result<crate::kernel::KernelContext, crate::linux_abi::LinuxErrno> {
        let current = self.cred_snapshot();
        let (target_uid, target_gid) = user
            .as_ref()
            .map_or((current.fsuid, current.fsgid), |(uid, gid, _)| (*uid, *gid));
        let target_groups = user
            .as_ref()
            .map_or_else(|| self.current_groups(), |(_, _, groups)| groups.clone());
        let resolved_workdir = if let Some(path) = workdir {
            if !path.starts_with('/') {
                return Err(crate::linux_abi::LINUX_EINVAL);
            }
            Some(self.validate_directory_search_as(path, target_uid, target_gid, &target_groups)?)
        } else {
            None
        };
        let configured = if let Some((uid, gid, supplementary)) = user {
            let updated = self.update_credentials_context(context, |credentials| {
                credentials.seed_identity(uid, gid);
                credentials.set_supplementary_groups(supplementary);
            })?;
            self.publish_external_credential_projection(
                &updated,
                &updated.resources().credentials(),
            );
            updated
        } else {
            context.retain_exact()
        };
        if let Some(resolved) = resolved_workdir {
            let trimmed = resolved.trim_end_matches('/');
            configured
                .resources()
                .fs_context()
                .set_cwd(if trimmed.is_empty() {
                    "/".to_owned()
                } else {
                    trimmed.to_owned()
                });
        }
        Ok(configured)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn resolve_execvp_path(
        &self,
        command: &str,
        search: &str,
    ) -> Result<String, crate::linux_abi::LinuxErrno> {
        let mut access_denied = false;
        for directory in search.split(':') {
            let candidate = if directory.is_empty() {
                command.to_owned()
            } else {
                format!("{}/{}", directory.trim_end_matches('/'), command)
            };
            match self.check_exec_target(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(errno) if errno == crate::linux_abi::LINUX_EACCES => {
                    access_denied = true;
                }
                Err(errno)
                    if errno == crate::linux_abi::LINUX_ENOENT
                        || errno == crate::linux_abi::LINUX_ENOTDIR => {}
                Err(errno) => return Err(errno),
            }
        }
        Err(if access_denied {
            crate::linux_abi::LINUX_EACCES
        } else {
            crate::linux_abi::LINUX_ENOENT
        })
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
        self.read_exec_file_at(path).or_else(|| {
            let resolved = self.exec_symlink_resolved(path)?;
            self.read_exec_file_at(&resolved)
        })
    }

    /// Follow `path`'s trailing symlink chain through the LAYERED view, for the
    /// exec readers below.
    ///
    /// Each backend follows symlinks only WITHIN itself, so a link in the
    /// writable upper pointing at an executable that lives in the immutable
    /// image layers resolves in neither: the upper cannot see the target and
    /// the lower does not have the link. `execve(2)` has no `O_NOFOLLOW`, so
    /// such a link must be followed — CPython `test_posix.test_posix_spawnp`
    /// symlinks its temp-dir program name at `sys.executable` and spawns it,
    /// and carrick reported ENOENT. `None` when nothing moved, so the caller
    /// does not repeat an identical lookup.
    fn exec_symlink_resolved(&self, path: &str) -> Option<String> {
        let resolved = self.canonicalize_following(path).ok()?;
        (resolved != path).then_some(resolved)
    }

    fn read_exec_file_at(&self, path: &str) -> Option<Vec<u8>> {
        match self.fs.rootfs_vfs.overlay.lookup_kind(path) {
            Some(crate::fs_backend::OverlayEntryKind::File) => {
                // An owned upper entry shadows the lower even when it is not a
                // readable regular file (broken symlink/FIFO/etc.).
                return self.fs.rootfs_vfs.overlay.file_contents(path);
            }
            Some(crate::fs_backend::OverlayEntryKind::Dir)
            | Some(crate::fs_backend::OverlayEntryKind::Deleted) => return None,
            None => {}
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

    /// Return a run-local cache key for a real host-backed executable. The
    /// inode identity and nanosecond mutation timestamps make writes, replaces,
    /// and overlay shadows select a fresh entry; in-memory/bind targets bypass.
    /// This lets the default materialized host root share prepared tool images
    /// without assuming that its writable overlay is immutable.
    pub(crate) fn hvpatch_exec_cache_key(
        &self,
        path: &str,
        vdso: bool,
        requires_syscall_traps: bool,
        needs_at_base: bool,
    ) -> Option<String> {
        use std::os::unix::fs::MetadataExt as _;
        let file = self.open_exec_host_file(path)?;
        let metadata = file.metadata().ok()?;
        Some(format!(
            "{path}\0{}:{}:{}:{}:{}:{}:{}\0{}\0{}\0{}\0{}",
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
            self.linux_page_size(),
            u8::from(vdso),
            u8::from(requires_syscall_traps),
            u8::from(needs_at_base)
        ))
    }

    /// Get or construct one stack-independent HvPatch exec image. The lock is
    /// intentionally held through the first construction: concurrent Go tool
    /// launches otherwise stampede into four identical ELF reads and patch
    /// passes. The cache is bounded because retaining prepared binaries also
    /// retains their immutable region payloads.
    pub(crate) fn with_hvpatch_exec_cache<E>(
        &self,
        key: Option<String>,
        build: impl FnOnce() -> Result<crate::memory::AddressSpace, E>,
    ) -> Result<crate::memory::AddressSpace, E> {
        let Some(key) = key else {
            return build();
        };
        let mut cache = self.fs.hvpatch_exec_cache.lock();
        if let Some(image) = cache.get(&key) {
            return Ok(image.clone());
        }
        let image = build()?;
        const MAX_PREPARED_EXEC_IMAGES: usize = 16;
        if cache.len() >= MAX_PREPARED_EXEC_IMAGES
            && let Some(evicted) = cache.keys().next().cloned()
        {
            cache.remove(&evicted);
        }
        cache.insert(key, image.clone());
        Ok(image)
    }

    /// Bounded head of [`SyscallDispatcher::read_exec_file`]: at most `max`
    /// leading bytes through the same layered view, `None` exactly when the
    /// full read would be `None`. The execve path's existence check and `#!`
    /// shebang probe only need a head, and the full read walked a whole
    /// multi-MB tool binary per probe (twice per exec, before the loader's
    /// own read) on the cold `go build`.
    pub fn read_exec_file_head(&self, path: &str, max: usize) -> Option<Vec<u8>> {
        self.read_exec_file_head_at(path, max).or_else(|| {
            let resolved = self.exec_symlink_resolved(path)?;
            self.read_exec_file_head_at(&resolved, max)
        })
    }

    fn read_exec_file_head_at(&self, path: &str, max: usize) -> Option<Vec<u8>> {
        match self.fs.rootfs_vfs.overlay.lookup_kind(path) {
            Some(crate::fs_backend::OverlayEntryKind::File) => {
                return self.fs.rootfs_vfs.overlay.file_head(path, max);
            }
            Some(crate::fs_backend::OverlayEntryKind::Dir)
            | Some(crate::fs_backend::OverlayEntryKind::Deleted) => return None,
            None => {}
        }
        if let Some(bytes) = self
            .fs
            .rootfs_vfs
            .rootfs
            .as_ref()
            .and_then(|r| r.read_head(path, max).ok())
        {
            return Some(bytes);
        }
        self.fs
            .vfs_mounts
            .resolve(path)
            .and_then(|m| m.vfs.read_file(path).ok())
            .map(|mut bytes| {
                bytes.truncate(max);
                bytes
            })
    }

    /// Open the exec target as a REAL host fd when the overlay backend can
    /// serve one (`--fs host`; the only backend in a default build). The
    /// native execve path maps the image MAP_PRIVATE straight from this fd —
    /// same accept set and symlink policy as `read_exec_file`'s overlay layer,
    /// so a path this declines simply keeps the byte-materializing load. The
    /// overlay is consulted FIRST in `read_exec_file` too, so when both this
    /// and the layered read answer, they answer from the same inode.
    pub fn open_exec_host_file(&self, path: &str) -> Option<std::fs::File> {
        match self.fs.rootfs_vfs.overlay.lookup_kind(path) {
            Some(crate::fs_backend::OverlayEntryKind::File) => {
                self.fs.rootfs_vfs.overlay.open_file_readonly(path)
            }
            Some(crate::fs_backend::OverlayEntryKind::Dir)
            | Some(crate::fs_backend::OverlayEntryKind::Deleted) => None,
            None => self
                .fs
                .rootfs_vfs
                .rootfs
                .as_ref()
                .and_then(|rootfs| rootfs.open_file_readonly(path)),
        }
    }

    pub fn stdout(&self) -> Vec<u8> {
        self.io.stdout.lock().clone()
    }

    /// Choose where bare fd 1/2 writes go for this run (and every logical
    /// child forked from it). `Inherit` is required for interactive prompts
    /// (`/ # `, cursor-position queries) to reach the terminal before exit;
    /// `Captured` (the construction default) fills `RunResult`; `Piped` hands
    /// bytes to the embedder's writers. Set before boot.
    pub fn set_stdio_sink(&self, sink: StdioSink) {
        self.io.set_sink(sink);
    }

    pub(crate) fn init_external_exec_stdio(&mut self) {
        self.io = fs::RuntimeIo::new();
    }

    /// Close `open_file`'s backing host fd AND, if it was the last reference
    /// to a pty master this process owns, drop its `/dev/pts` entry. Use this
    /// on every fd-close path (including exec generation retirement) so the
    /// PtyTable never desyncs from the real fd lifetime.
    pub(in crate::dispatch) fn close_open_file_and_free_pty(&self, open_file: &OpenFile) {
        // Linux classic POSIX record locks are process-associated, and closing
        // any fd for the same file releases every classic lock this process
        // holds on that file. Carrick dup(2) aliases one HostFdRef in the shared
        // open description, so closing a guest dup would otherwise skip the host
        // close event and leave fcntl(F_SETLK) locks alive. Close a temporary
        // duplicate to trigger the host kernel's process-lock release without
        // shortening the shared description's actual fd lifetime. OFD locks are
        // tied to the open file description and survive a non-final dup close.
        // Only act when THIS is the last reference (the host fd is actually
        // closing) — a dup'd fd sharing the Arc keeps the writer/pty alive.
        let last_ref = open_file.description.fd_ref_count() == 1;
        if !last_ref {
            let classic_lock_release_fd = match open_file.description.read().as_deref() {
                Some(OpenDescription::HostFile { host_fd, .. }) => Some(host_fd.raw()),
                _ => None,
            };
            if let Some(host_fd) = classic_lock_release_fd {
                let duped = unsafe { libc::dup(host_fd) };
                if duped >= 0 {
                    unsafe {
                        libc::close(duped);
                    }
                }
            }
        }
        if last_ref
            && carrick_signal_core::fasync::any_armed()
            && let Some(pipe_id) = self.fasync_pipe_id_for_open_file(open_file)
        {
            // FASYNC is owned by the open file description, not by a numeric
            // fd alias. Exact registration matching prevents the other end of
            // a pipe (which shares the join key) from disarming this arm.
            carrick_signal_core::fasync::disarm(pipe_id, open_file.description.id().raw());
        }
        let mut pty_master_index = None;
        let mut fifo_writer_closed = false;
        let mut closing_inotify = None;
        let mut closing_fanotify = false;
        let mut closing_host_socket = false;
        if last_ref {
            if let Some(open) = open_file.description.read() {
                // A reuseport membership must never outlive its socket: host fds
                // are REUSED, so a stale entry would hand a later unrelated
                // socket's traffic to this group. Removal is by host fd and is a
                // no-op for a socket that never joined.
                if let OpenDescription::HostSocket { host_fd, .. } = &*open {
                    closing_host_socket = true;
                    crate::dispatch::net::reuseport_leave(host_fd.raw());
                    crate::dispatch::net::recverr_close(host_fd.raw());
                    // Drop this connection's SCTP message boundaries while the fd is
                    // still open — they are keyed by address pair, and a recycled
                    // pair must not inherit a dead connection's boundaries.
                    crate::dispatch::net::sctp_forget(host_fd.raw());
                    // Same rule, same reason: a recorded guest-visible address must
                    // not outlive its socket either. It used to, and a reused fd
                    // inherited the dead socket's address — glibc's `rfc3484_sort`
                    // closes an AF_INET probe socket and immediately opens an
                    // AF_INET6 one onto the same number, got the v4 sockaddr back
                    // from `getsockname`, and aborted the guest.
                    self.network.provider.forget_socket_addresses(
                        crate::network::SocketKey::for_host_fd(host_fd.raw()),
                    );
                }
                // A pty SLAVE is about to close. Darwin DESTROYS whatever is still
                // queued in the pty when the last slave fd goes away; Linux hands it
                // over and only then reports EOF. Rescue it onto the master's
                // staging queue, which the pipe read path already drains before it
                // touches the host fd and the readiness paths already count.
                let closing_slave = match &*open {
                    OpenDescription::HostPipe {
                        pty: Some(role), ..
                    } if !role.is_master => Some(role.index),
                    _ => None,
                };
                if let Some(index) = closing_slave {
                    self.rescue_pty_master_before_slave_close(index);
                }
                match &*open {
                    OpenDescription::HostPipe { pty, host_fd, .. } => {
                        // Unregister while the owned host descriptor is still
                        // alive. Waiting until after `close_open_file` would
                        // let another thread reuse the raw fd number and turn
                        // this removal into an ABA against the new owner.
                        fifo_writer_closed = crate::dispatch::fifo_beacon::register_close(host_fd);
                        if let Some(role) = pty
                            && role.is_master
                        {
                            pty_master_index = Some(role.index);
                        }
                    }
                    // The inotify fd is closing for good: drop every dispatch-registry
                    // entry it owned so stale watches don't keep firing (and so the
                    // registry doesn't pin the InotifyState alive via its Arc).
                    OpenDescription::Inotify { state, .. } => {
                        closing_inotify = Some(Arc::clone(state));
                    }
                    // A fanotify fd closing is NOT automatically the end of its
                    // group: a `dup`, or a guest fork that shared the description,
                    // may still hold it, and a forked child routinely closes its
                    // inherited fd while the parent keeps reading. So do not drop
                    // the marks here — just note that a reference went away and let
                    // the sweep below remove marks whose group actually died.
                    OpenDescription::Fanotify { .. } => {
                        closing_fanotify = true;
                    }
                    _ => {}
                }
            }
        }
        if let Some(state) = closing_inotify {
            self.fs.inotify_registry.unregister_all(&state);
        }
        let is_inmem_stream = matches!(
            open_file.description.read().as_deref(),
            Some(
                OpenDescription::PipeReader { .. }
                    | OpenDescription::PipeWriter { .. }
                    | OpenDescription::EventFd { .. }
                    | OpenDescription::TimerFd { .. }
            )
        );
        // Drop `open_file` first so the description — and with it the last
        // `Arc<FanotifyGroup>`, if this really was the last reference — is gone
        // before the sweep asks which groups are still alive.
        close_open_file(open_file);
        if is_inmem_stream {
            self.notify_inmem_epoll();
        }
        // The socket is gone, and with it any SCM_RIGHTS message still queued
        // on it: release the descriptions those messages carried in flight.
        if closing_host_socket {
            crate::dispatch::net::scm_rights_gc();
        }
        if closing_fanotify {
            self.fs.fanotify_registry.prune_dead_groups();
        }
        if let Some(index) = pty_master_index {
            crate::dispatch::pty_registry::unregister_master(index);
            self.pty_table()
                .lock()
                .free_if_owner(index, std::process::id());
        }
        // A FIFO write-end close drops a beacon writer — wake epoll/poll so FIFO
        // read-ends re-check the (kernel-decided) EOF (see dispatch::fifo_beacon).
        // No-op for non-FIFO host pipes.
        if fifo_writer_closed {
            self.notify_inmem_epoll();
        }
    }

    pub fn stderr(&self) -> Vec<u8> {
        self.io.stderr.lock().clone()
    }

    fn captured_mm(&self) -> Arc<crate::kernel::Mm> {
        if let Some(mm) = resources::mm() {
            return mm;
        }
        #[cfg(test)]
        {
            self.capture_one_task_context()
                .expect("test mm context")
                .shared()
                .mm()
        }
        #[cfg(not(test))]
        {
            tracing::error!("mm access escaped its captured KernelContext scope");
            carrick_fatal!(
                "dispatch::mm_authority",
                "mm access escaped its captured KernelContext scope"
            );
        }
    }

    fn captured_file_table(&self) -> Arc<crate::kernel::FileTable> {
        if let Some(files) = resources::files() {
            return files;
        }
        #[cfg(test)]
        {
            self.capture_one_task_context()
                .expect("test file-table context")
                .resources()
                .files()
        }
        #[cfg(not(test))]
        {
            tracing::error!("file-table access escaped its captured KernelContext scope");
            carrick_fatal!(
                "dispatch::file_authority",
                "file-table access escaped its captured KernelContext scope"
            );
        }
    }

    pub(in crate::dispatch) fn captured_slot_authority(
        &self,
        fd: i32,
    ) -> Option<crate::kernel::objects::FileSlotAuthority> {
        let number = crate::kernel::FileSlotNumber::for_open_fd(fd).ok()?;
        self.captured_file_table().capture_slot_authority(number)
    }

    pub(crate) fn file_table_for_context(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Arc<crate::kernel::FileTable> {
        context.resources().files()
    }

    fn captured_fs_context(&self) -> Arc<crate::kernel::FsContext> {
        if let Some(fs_context) = resources::fs_context() {
            return fs_context;
        }
        #[cfg(test)]
        {
            self.capture_one_task_context()
                .expect("test filesystem context")
                .resources()
                .fs_context()
        }
        #[cfg(not(test))]
        {
            tracing::error!("filesystem-context read escaped its captured KernelContext scope");
            carrick_fatal!(
                "dispatch::fs_context",
                "filesystem-context read escaped its captured KernelContext scope"
            );
        }
    }

    pub fn cwd(&self) -> String {
        if let Some(fs_context) = resources::fs_context() {
            return fs_context.cwd();
        }
        self.capture_one_task_context()
            .unwrap_or_else(|error| {
                tracing::error!(%error, "cannot capture initial filesystem context");
                carrick_fatal!(
                    "dispatch::fs_context",
                    "cannot capture initial filesystem context"
                );
            })
            .resources()
            .fs_context()
            .cwd()
    }

    /// Absolutize an `execve(2)` target path against the guest cwd, matching
    /// Linux semantics: a relative program path resolves against the calling
    /// process's working directory. carrick's overlay/rootfs/bind-mount layers
    /// all key on absolute guest paths, so a bare relative path (e.g. Go
    /// os/exec `TestCommandRelativeName`, which sets `cmd.Path = "dirBase/base"`
    /// with `cmd.Dir = "/"`) would miss every layer and fail ENOENT. `argv[0]` is
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
        let cwd = if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        };
        if let Some(fs_context) = resources::fs_context() {
            fs_context.set_cwd(cwd);
            return;
        }
        let context = self.capture_one_task_context().unwrap_or_else(|error| {
            tracing::error!(%error, "cannot capture initial filesystem context");
            carrick_fatal!(
                "dispatch::fs_context",
                "cannot capture initial filesystem context"
            );
        });
        context.resources().fs_context().set_cwd(cwd);
    }

    /// Shared pseudo-terminal table. Also held by the `/dev` (ptmx) and
    /// `/dev/pts` mounts — all three see the same Arc. Used by the ioctl
    /// (TIOCSPTLCK) and close (free-on-master-close) handlers.
    /// Move whatever is still queued in pty `index` onto the MASTER's staging
    /// queue, before the closing slave lets Darwin destroy it.
    ///
    /// Measured on macOS 27: write 1024 bytes to a pty slave, do not read the
    /// master, `close` the slave — the master then reads `0` and the bytes are
    /// gone. Linux delivers them first. Any reader even one buffer behind
    /// therefore loses the tail, which is exactly what libuv's
    /// `tty_pty_partial` sees: 64 slave writes of 1024 against 63 master reads,
    /// a constant 1024 bytes short of the 65536 it requires.
    ///
    /// Two constraints, both learned by getting them wrong:
    ///
    /// * the master is found through `dispatch::pty_registry`, NOT the file
    ///   table — reading the file table from inside this close path hangs
    ///   (`tty_pty` hung even when the rescue itself did nothing);
    /// * the amount is discovered by reading until EAGAIN under a byte cap, NOT
    ///   by `FIONREAD`, which reports 0 on a pty master even with data queued.
    fn rescue_pty_master_before_slave_close(&self, index: u32) {
        // Bounded so a still-live writer on the other end cannot keep this
        // draining — under the dispatcher lock — for as long as it produces.
        const CAP: usize = 256 * 1024;
        let Some((master_host_fd, description)) = crate::dispatch::pty_registry::master(index)
        else {
            return;
        };
        let mut rescued = Vec::new();
        let mut buf = [0u8; 8192];
        while rescued.len() < CAP {
            // BLOCKING-IO-OK: a pty master is adopted O_NONBLOCK.
            let n = unsafe { libc::read(master_host_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n <= 0 {
                break;
            }
            rescued.extend_from_slice(&buf[..n as usize]);
        }
        if !rescued.is_empty() {
            self.stage_splice_bytes_for_description(&description, rescued);
        }
    }

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

    pub(crate) fn initialize_controlling_tty_for(&self, context: &crate::kernel::KernelContext) {
        if self.fs.pty_table.lock().controlling().is_some() {
            context.kernel().initialize_launch_controlling_tty(context);
        }
    }

    /// Single-threaded dispatch (legacy + unit tests + the fork-based runtime
    /// path). Tid-aware handlers see `thread: None`. The exact current MM's
    /// executor census, not `&mut self`, proves mutation exclusivity.
    pub fn dispatch(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_with_lease(kernel, request, memory, reporter, None)
    }

    /// Single-threaded dispatch accepting an explicitly borrowed `ThreadExecutionLease`.
    pub(crate) fn dispatch_with_lease(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Invoke(syscall) => {
                self.dispatch_prepared_with_lease(kernel, syscall, memory, reporter, lease)
            }
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
        }
    }

    pub(crate) fn dispatch_prepared(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_prepared_with_lease(kernel, syscall, memory, reporter, None)
    }

    /// Handler-only single-threaded dispatch. Repeated readiness attempts reuse
    /// the same prepared envelope and enter here without running preflight.
    pub(crate) fn dispatch_prepared_with_lease(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Tree-wide forward-progress beat for the deadlock watchdog.
        crate::deadlock_watchdog::tick();
        let request = syscall.request;
        let mut executor = self
            .enter_mm_executor()
            .map_err(DispatchError::MmExecutorAdmission)?;
        if syscall_requires_mm_mutation(request.number.raw(), request.args) {
            let coordinator = executor.mutation_coordinator();
            let mm = executor.mm_id();
            crate::vcpu_loop::with_sole_mm_stage1(&mut executor, |authority| {
                let mut guard = mm_mutation::from_sole_executor(authority, coordinator, mm);
                self.dispatch_inner(
                    kernel,
                    request,
                    memory,
                    reporter,
                    None,
                    MutationDispatchRoute {
                        guard: &mut guard,
                        lease,
                    },
                )
            })
            .ok_or(DispatchError::MmMutationPeerExecutor)?
        } else {
            self.dispatch_inner(
                kernel,
                request,
                memory,
                reporter,
                None,
                OrdinaryDispatchRoute {
                    lease,
                    mm_executor: Some(&mut executor),
                },
            )
        }
    }

    /// Run a non-threaded completion under a fresh exact-MM census admission.
    pub(crate) fn with_mm_executor_mutation<T>(
        &mut self,
        run: impl FnOnce(&mut Self, &mut mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> Result<T, DispatchError> {
        let mut executor = self
            .enter_mm_executor()
            .map_err(DispatchError::MmExecutorAdmission)?;
        let coordinator = executor.mutation_coordinator();
        let mm = executor.mm_id();
        crate::vcpu_loop::with_sole_mm_stage1(&mut executor, |authority| {
            let mut guard = mm_mutation::from_sole_executor(authority, coordinator, mm);
            run(self, &mut guard)
        })
        .ok_or(DispatchError::MmMutationPeerExecutor)
    }

    /// Apply a launch-time container syscall policy (the `carrick run` /
    /// `--security-opt seccomp=…` resolution) with no capability grant —
    /// the bare `run-elf`/unit-test shape. Must be called before the guest
    /// boots — the field is then read-only and inherited across guest
    /// fork/execve like a Linux seccomp filter. `Unconfined` clears it.
    pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) {
        self.install_container_policy(
            policy,
            crate::namespace::process::CapabilitySet::docker_default(),
        );
    }

    /// Apply the launch-time policy from the container's OWN capability set,
    /// because Docker's profile is capability-conditional: the same
    /// `--cap-add SYS_ADMIN` that raises the capability set also lifts the
    /// profile's denial of `bpf`/`unshare`/`setns`/`io_uring`. The grant and
    /// the policy now come from one authority (`Container::granted_caps`), so
    /// they cannot disagree the way a static grant applied in a different
    /// order could. Must be called before the guest boots.
    pub fn apply_launch_privileges(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        container: &crate::kernel::container::Container,
    ) {
        self.install_container_policy(policy, container.granted_caps());
    }

    fn install_container_policy(
        &mut self,
        policy: carrick_spec::SeccompPolicy,
        caps: crate::namespace::process::CapabilitySet,
    ) {
        let policy_model = match policy {
            carrick_spec::SeccompPolicy::ContainerDefault => Some(
                crate::container_policy::ContainerPolicy::docker_model_with_capabilities(
                    caps.effective,
                ),
            ),
            carrick_spec::SeccompPolicy::Unconfined => None,
        };
        let user_observers = self
            .observers
            .as_ref()
            .map(|c| c.user_observers().to_vec())
            .unwrap_or_default();
        if policy_model.is_some() || !user_observers.is_empty() {
            self.observers = Some(Arc::new(crate::observe::ObserverChain::new(
                policy_model,
                user_observers,
            )));
        } else {
            self.observers = None;
        }
    }

    pub fn install_observer(&mut self, observer: Arc<dyn crate::observe::SyscallObserver>) {
        let policy = self.observers.as_ref().and_then(|c| c.policy().cloned());
        let mut user_observers = self
            .observers
            .as_ref()
            .map(|c| c.user_observers().to_vec())
            .unwrap_or_default();
        user_observers.push(observer);
        self.observers = Some(Arc::new(crate::observe::ObserverChain::new(
            policy,
            user_observers,
        )));
    }

    pub fn observers(&self) -> Option<&Arc<crate::observe::ObserverChain>> {
        self.observers.as_ref()
    }

    /// Append one trusted interceptor while the dispatcher is still being
    /// prepared. Each registration replaces the stored immutable chain; no
    /// execution-time mutation surface is exposed.
    pub fn install_interceptor(
        &mut self,
        interceptor: Arc<dyn crate::observe::SyscallInterceptor>,
    ) {
        let chain = match self.interceptors.as_ref() {
            Some(chain) => chain.with_appended(interceptor),
            None => crate::observe::intercept::InterceptorChain::new(vec![interceptor]),
        };
        self.interceptors = Some(Arc::new(chain));
    }

    #[cfg(test)]
    pub(crate) fn interceptors(&self) -> Option<&Arc<crate::observe::intercept::InterceptorChain>> {
        self.interceptors.as_ref()
    }

    pub fn set_observers(&mut self, observers: Option<Arc<crate::observe::ObserverChain>>) {
        self.observers = observers;
    }

    #[cfg(test)]
    pub(crate) fn container_policy(&self) -> Option<&crate::container_policy::ContainerPolicy> {
        self.observers.as_ref().and_then(|c| c.policy())
    }

    /// Evaluate installed seccomp filters against `request` before its handler
    /// runs. Returns `Some(outcome)` when a filter blocks the call (ERRNO →
    /// that errno; KILL/TRAP → terminate, fail-closed), or `None` to allow it.
    /// Fast path: no lock when no filter is installed.
    fn seccomp_precheck(&self, request: &SyscallRequest) -> Option<DispatchOutcome> {
        if !self.seccomp.is_active() {
            return None;
        }
        // Feed the filter the guest's ISA-native arch + syscall number. Using
        // the canonical (aarch64) number or a hardcoded aarch64 arch makes an
        // x86_64 guest fail its own Docker/libseccomp profile, which gates on
        // `arch == AUDIT_ARCH_X86_64` then switches on x86_64 syscall numbers.
        let data = crate::seccomp::SeccompData::for_guest(
            request.native_number.raw() as i32,
            request.guest_abi,
            request.args.0,
        );
        let ret = self.seccomp.check(&data);
        match ret & crate::seccomp::SECCOMP_RET_ACTION_FULL {
            crate::seccomp::SECCOMP_RET_ALLOW
            | crate::seccomp::SECCOMP_RET_LOG
            | crate::seccomp::SECCOMP_RET_TRACE => None,
            crate::seccomp::SECCOMP_RET_ERRNO => {
                // RET_DATA is the errno, clamped to the kernel's 0..=4095 range.
                // data == 0 is allowed by the ABI and makes the syscall return
                // 0 (-0): not a LinuxErrno domain value, so surface it as a
                // plain 0 return — the guest-visible retval is identical.
                let errno = (ret & crate::seccomp::SECCOMP_RET_DATA).min(4095) as i32;
                Some(if errno == 0 {
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::Errno {
                        errno: LinuxErrno::new(errno),
                    }
                })
            }
            // KILL_PROCESS / KILL_THREAD / TRAP (and any unmodelled action): fail
            // closed by KILLING the guest with SIGSYS — a real signal DEATH, so a
            // waiting parent sees WIFSIGNALED + SIGSYS (libseccomp's own tests and
            // container runtimes check exactly that), not WIFEXITED(159). Using
            // `Exit{128+31}` produced the same shell $? but the wrong wait status.
            // A *catchable* SIGSYS with SYS_SECCOMP si_code for RET_TRAP is a
            // follow-up.
            crate::seccomp::SECCOMP_RET_KILL_PROCESS
            | crate::seccomp::SECCOMP_RET_KILL_THREAD
            | crate::seccomp::SECCOMP_RET_TRAP => Some(DispatchOutcome::SignalDeath {
                signum: crate::linux_abi::LINUX_SIGSYS,
            }),
            _ => Some(DispatchOutcome::SignalDeath {
                signum: crate::linux_abi::LINUX_SIGSYS,
            }),
        }
    }

    /// Apply every one-time syscall transform and policy layer in the single
    /// authoritative order, then publish the effective entry exactly once.
    pub(crate) fn prepare_syscall(
        &self,
        kernel: &crate::kernel::KernelContext,
        original: SyscallRequest,
        reporter: &CompatReporter,
    ) -> Result<PreparedDispatch, DispatchError> {
        let original_args = original.args;
        let process = crate::observe::ProcessInfo::new(kernel);
        let interception = match self.interceptors.as_ref() {
            Some(chain) => chain.apply(&process, &original)?,
            None => crate::observe::intercept::Interception {
                effective_args: original_args,
                proposed: None,
            },
        };
        let mut syscall = PreparedSyscall {
            original_args,
            request: SyscallRequest {
                args: interception.effective_args,
                ..original
            },
        };
        let mut terminal = None;

        // Launch policy is authoritative over a trusted interceptor proposal.
        if let Some(chain) = self.observers.as_ref()
            && let Some(action) = chain.check_policy(&process, &syscall.effective_info())
        {
            match action {
                crate::observe::SyscallAction::Allow => {}
                crate::observe::SyscallAction::Deny(errno) => {
                    reporter.record(CompatEvent::partial_syscall(
                        syscall.request.number.raw(),
                        syscall.effective_info().name(),
                        syscall.request.args,
                        "denied by launch-time container syscall policy (Docker default-seccomp model)",
                    ));
                    merge_policy_terminal(&mut terminal, DispatchOutcome::Errno { errno });
                }
                crate::observe::SyscallAction::Kill(signal) => {
                    merge_policy_terminal(
                        &mut terminal,
                        DispatchOutcome::SignalDeath { signum: signal.0 },
                    );
                }
                crate::observe::SyscallAction::Short(count) => {
                    if crate::observe::is_shortable_syscall(syscall.request.number) {
                        syscall.request.args.0[2] =
                            (syscall.request.args.0[2] as usize).min(count) as u64;
                    }
                }
            }
        }

        // Guest seccomp validates the effective request and may veto a proposal.
        if let Some(outcome) = self.seccomp_precheck(&syscall.request) {
            merge_policy_terminal(&mut terminal, outcome);
        }

        // User observers see the same effective request the handler will receive.
        if let Some(chain) = self.observers.as_ref()
            && chain.has_user_observers()
        {
            match chain.on_user_syscall(&process, &syscall.effective_info()) {
                crate::observe::SyscallAction::Allow => {}
                crate::observe::SyscallAction::Deny(errno) => {
                    merge_policy_terminal(&mut terminal, DispatchOutcome::Errno { errno });
                }
                crate::observe::SyscallAction::Kill(signal) => {
                    merge_policy_terminal(
                        &mut terminal,
                        DispatchOutcome::SignalDeath { signum: signal.0 },
                    );
                }
                crate::observe::SyscallAction::Short(count) => {
                    if crate::observe::is_shortable_syscall(syscall.request.number) {
                        syscall.request.args.0[2] =
                            (syscall.request.args.0[2] as usize).min(count) as u64;
                    }
                }
            }
        }

        // CPU/resource policy remains a one-time entry check and cannot be
        // bypassed by a trusted terminal proposal.
        if terminal.is_none()
            && let Err(outcome) = time::check_cpu_limits(kernel)
        {
            terminal = Some(outcome);
        }

        let name = syscall.effective_info().name();
        for (number, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *number == syscall.request.number.raw() {
                check_syscall_flags(
                    reporter,
                    syscall.request.number.raw(),
                    name,
                    *arg_index,
                    syscall.request.arg(*arg_index as usize),
                    *mask,
                );
            }
        }
        reporter.record(CompatEvent::SyscallEntry {
            number: syscall.request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: syscall.request.args,
        });
        if syscall.original_args != syscall.request.args {
            reporter.record(CompatEvent::SyscallRewrite {
                number: syscall.request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                original_args: syscall.original_args,
                effective_args: syscall.request.args,
            });
        }

        let proposed = interception.proposed.map(|outcome| match outcome.errno {
            Some(errno) => DispatchOutcome::Errno { errno },
            None => DispatchOutcome::Returned {
                value: outcome.value,
            },
        });
        match terminal.or(proposed) {
            Some(outcome) => Ok(PreparedDispatch::Complete { syscall, outcome }),
            None => Ok(PreparedDispatch::Invoke(syscall)),
        }
    }

    pub(crate) fn identity_fast_path_enabled(&self) -> bool {
        // The EL1 shim answers identity syscalls without a dispatch, so it must
        // be off whenever a guest filter is active OR an observer requests full visibility.
        !self.requires_syscall_traps()
    }

    pub(crate) fn requires_syscall_traps(&self) -> bool {
        self.interceptors.is_some()
            || self.seccomp.is_active()
            || self.observers.as_ref().is_some_and(|chain| {
                chain.wants_fast_path_visibility() == crate::observe::FastPathVisibility::Required
            })
    }

    /// Live gate consumed by JIT contexts. The launch-time policy is
    /// immutable once execution starts; guest seccomp transitions flip the
    /// returned atomic word from 1 to 0 before publishing their filter.
    #[allow(dead_code)]
    pub(crate) fn identity_fast_path_word(&self) -> Option<&std::sync::atomic::AtomicU32> {
        if self.interceptors.is_some()
            || self.observers.as_ref().is_some_and(|chain| {
                chain.wants_fast_path_visibility() == crate::observe::FastPathVisibility::Required
            })
        {
            None
        } else {
            Some(self.seccomp.identity_fast_path_word())
        }
    }

    // (see `watch_addr` below)

    /// Multi-threaded dispatch through a shared dispatcher reference. Handlers
    /// that touch process-wide state must protect that state with subsystem
    /// locks; there is no dispatcher-wide fallback on this path.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_threaded(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_with_lease(
            kernel, request, memory, reporter, tid, registry, futex, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_with_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_with_executor_and_lease(
            kernel, request, memory, reporter, tid, registry, futex, lease, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_threaded_with_executor_and_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
        mm_executor: Option<&mut MmExecutorParticipation>,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Invoke(syscall) => self
                .dispatch_threaded_prepared_with_executor_and_lease(
                    kernel,
                    syscall,
                    memory,
                    reporter,
                    tid,
                    registry,
                    futex,
                    lease,
                    mm_executor,
                ),
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_prepared_with_mm_executor_and_lease(
        &self,
        executor: &mut MmExecutorParticipation,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_executor_and_lease(
            kernel,
            syscall,
            memory,
            reporter,
            tid,
            registry,
            futex,
            lease,
            Some(executor),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_threaded_prepared_with_executor_and_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
        mm_executor: Option<&mut MmExecutorParticipation>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_route(
            kernel,
            syscall,
            memory,
            reporter,
            tid,
            registry,
            futex,
            OrdinaryDispatchRoute { lease, mm_executor },
        )
    }

    /// Shared-dispatch semantics under an exact-MM executor participation.
    /// Mutation is admitted only while that participation can lock a real
    /// sole-executor census election. Production multi-vCPU dispatch uses the
    /// same participation and takes a real page-table pause when a peer exists.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_threaded_with_mm_executor(
        &self,
        executor: &mut MmExecutorParticipation,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        let authority = self.mm_binding.current.load_full();
        if !executor.authorizes(&authority) || executor.mm_id() != kernel.shared().mm().id() {
            return Err(DispatchError::MmMutationPeerExecutor);
        }
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
            PreparedDispatch::Invoke(syscall) => {
                if syscall_requires_mm_mutation(syscall.request.number.raw(), syscall.request.args)
                {
                    let coordinator = executor.mutation_coordinator();
                    crate::vcpu_loop::with_sole_mm_stage1(executor, |outer| {
                        let mut guard = mm_mutation::from_sole_executor(
                            outer,
                            coordinator,
                            kernel.shared().mm().id(),
                        );
                        self.dispatch_threaded_prepared_mutation_with_lease(
                            kernel, syscall, memory, reporter, tid, registry, futex, &mut guard,
                            None,
                        )
                    })
                    .ok_or(DispatchError::MmMutationPeerExecutor)?
                } else {
                    self.dispatch_threaded_prepared_with_mm_executor_and_lease(
                        executor, kernel, syscall, memory, reporter, tid, registry, futex, None,
                    )
                }
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_for_test(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Result<DispatchOutcome, DispatchError> {
        match self.prepare_syscall(kernel, request, reporter)? {
            PreparedDispatch::Complete { outcome, .. } => Ok(outcome),
            PreparedDispatch::Invoke(syscall) => {
                if syscall_requires_mm_mutation(syscall.request.number.raw(), syscall.request.args)
                {
                    mm_mutation::test_support::with_guard(self.mm_mutation_coordinator(), |guard| {
                        self.dispatch_threaded_prepared_mutation_with_lease(
                            kernel, syscall, memory, reporter, tid, registry, futex, guard, None,
                        )
                    })
                } else {
                    self.dispatch_threaded_prepared_with_executor_and_lease(
                        kernel, syscall, memory, reporter, tid, registry, futex, None, None,
                    )
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_prepared_mutation_with_lease(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        guard: &mut mm_mutation::MmMutationGuard<'_>,
        lease: Option<&crate::kernel::objects::ThreadExecutionLease>,
    ) -> Result<DispatchOutcome, DispatchError> {
        self.dispatch_threaded_prepared_with_route(
            kernel,
            syscall,
            memory,
            reporter,
            tid,
            registry,
            futex,
            MutationDispatchRoute { guard, lease },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_threaded_prepared_with_route<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        syscall: PreparedSyscall,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        mut route: R,
    ) -> Result<DispatchOutcome, DispatchError> {
        let request = syscall.request;

        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (one atomic compare when nothing changed).
        if let Err(error) =
            self.sync_vvar_realtime_offset(kernel.task().container().clock(), memory)
        {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }
        if let Some(result) = self
            .dispatch_threaded_independent(kernel, request, memory, reporter, tid, registry, futex)
        {
            return result;
        }
        resources::with_captured_resources(kernel, || {
            self.dispatch_threaded_captured(
                kernel, request, memory, reporter, tid, registry, futex, &mut route,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_threaded_captured<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        route: &mut R,
    ) -> Result<DispatchOutcome, DispatchError> {
        if let Some(result) = self.dispatch_threaded_shared(
            kernel, request, memory, reporter, tid, registry, futex, route,
        ) {
            return result;
        }

        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::unhandled_syscall(
            request.number.raw(),
            name,
            request.args,
        ));
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
    }

    /// Shared threaded dispatch path for subsystems already moved behind
    /// interior locks.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_threaded_shared<R: NormalizedDispatchRoute>(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
        route: &mut R,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if request.number.raw() == 64
            && !resources::with_captured_resources(kernel, || {
                self.write_shared_supported(request.args.0[0] as i32)
            })
        {
            return None;
        }

        if !Self::dispatch_normalized_known(request.number.raw()) {
            return None;
        }

        #[cfg(feature = "watchpoint")]
        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number.raw(), addr, u64::from_le_bytes(le));
        }

        let thread = Some(ThreadCtx {
            tid,
            registry,
            futex,
        });

        let result = route.dispatch(self, kernel, request, memory, reporter, thread);
        let outcome = match result {
            Some(r) => match lower_handler_result(r) {
                Ok(outcome) => outcome,
                Err(fatal) => return Some(Err(fatal)),
            },
            None => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };
        // Consumption-based EPOLLET re-arm: a read/write-family syscall on a
        // watched fd services the latched edge; clear it so the next sampled
        // assertion is delivered (the Linux-lane lost-edge wedge — see
        // `epoll_rearm_after_io`). Outcome matters: an EAGAIN write did not
        // consume writable capacity and must not synthesize another OUT edge.
        resources::with_captured_resources(kernel, || {
            self.epoll_rearm_after_io(&request, &outcome);
        });
        Some(Ok(outcome))
    }

    /// Thread-local syscall subset that does not touch mutable dispatcher
    /// subsystem state. The runtime checks this before taking the serialized
    /// legacy dispatcher path so futex and tid coordination can proceed without
    /// the dispatcher-wide lock.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_threaded_independent(
        &self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        tid: crate::thread::ThreadId,
        registry: &crate::thread::ThreadRegistry,
        futex: &crate::thread::FutexTable,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        if !threaded_independent_dispatch_supports(request.number.raw()) {
            return None;
        }
        match request.number.raw() {
            130 => {
                let target =
                    crate::namespace::pid::guest_tid_to_kernel_for(kernel, request.arg(0) as i32)
                        .map(crate::thread::ThreadId::from_guest_supplied_tid);
                let signum = request.arg(1);
                if signum <= LINUX_MAX_SIGNUM
                    && target.is_none_or(|target| target == tid || !registry.is_live(target))
                {
                    return None;
                }
            }
            131 => {
                let target =
                    crate::namespace::pid::guest_tid_to_kernel_for(kernel, request.arg(1) as i32)
                        .map(crate::thread::ThreadId::from_guest_supplied_tid);
                let signum = request.arg(2);
                if signum <= LINUX_MAX_SIGNUM
                    && target.is_none_or(|target| target == tid || !registry.is_live(target))
                {
                    return None;
                }
            }
            _ => {}
        }

        let outcome = match request.number.raw() {
            96 => {
                let addr = request.arg(0);
                registry.set_clear_child_tid(tid, addr);
                let Some(visible) = u32::try_from(kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(kernel, tid))
                else {
                    return Some(Ok(DispatchOutcome::errno(LINUX_ESRCH)));
                };
                DispatchOutcome::Returned {
                    value: i64::from(visible),
                }
            }
            98 => {
                let hvpatch_linux_tid = u32::try_from(kernel.thread().key().tid.raw())
                    .ok()
                    .and_then(|tid| crate::namespace::pid::kernel_to_ns_for(kernel, tid));
                let clock = Arc::clone(kernel.task().container().clock());
                dispatch_threaded_futex(
                    &clock,
                    request,
                    memory,
                    reporter,
                    futex,
                    tid,
                    registry,
                    hvpatch_linux_tid,
                )
            }
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
            124 => DispatchOutcome::SchedulerYield,
            172 => DispatchOutcome::Returned {
                value: i64::from(self.identity_snapshot(kernel).pid),
            },
            130 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(0) as i32);
                let signum = request.arg(1);
                {
                    let info = (signum != 0).then(|| {
                        crate::linux_abi::LinuxSiginfo::kill(
                            signum as i32,
                            crate::linux_abi::LINUX_SI_TKILL,
                            crate::dispatch::signal::ns_visible_sender_pid(kernel),
                            kernel.resources().credentials().ruid().raw(),
                        )
                    });
                    self.hvpatch_specific_thread_signal(kernel, None, target.raw(), signum, info)
                        .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
                }
            }
            131 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(1) as i32);
                let signum = request.arg(2);
                {
                    let info = (signum != 0).then(|| {
                        crate::linux_abi::LinuxSiginfo::kill(
                            signum as i32,
                            crate::linux_abi::LINUX_SI_TKILL,
                            crate::dispatch::signal::ns_visible_sender_pid(kernel),
                            kernel.resources().credentials().ruid().raw(),
                        )
                    });
                    self.hvpatch_specific_thread_signal(
                        kernel,
                        Some(request.arg(0) as i32),
                        target.raw(),
                        signum,
                        info,
                    )
                    .unwrap_or_else(|| DispatchOutcome::errno(LINUX_ESRCH))
                }
            }
            178 => match crate::vcpu_loop::ns_visible_guest_tid(self, kernel) {
                Some(tid) => DispatchOutcome::Returned {
                    value: i64::from(tid),
                },
                None => DispatchOutcome::errno(LINUX_ESRCH),
            },
            449 => {
                let clock = Arc::clone(kernel.task().container().clock());
                dispatch_futex_waitv_args(
                    &clock,
                    memory,
                    Some(futex),
                    request.arg(0),
                    request.arg(1),
                    request.arg(2),
                    request.arg(3),
                    request.arg(4),
                )
            }
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };

        Some(Ok(outcome))
    }

    fn dispatch_inner<R: NormalizedDispatchRoute>(
        &mut self,
        kernel: &crate::kernel::KernelContext,
        request: SyscallRequest,
        memory: &mut impl CurrentMmMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
        mut route: R,
    ) -> Result<DispatchOutcome, DispatchError> {
        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (see `dispatch_threaded`).
        if let Err(error) =
            self.sync_vvar_realtime_offset(kernel.task().container().clock(), memory)
        {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }

        // Reusable guest-memory watchpoint (`watchpoint` feature +
        // CARRICK_WATCH_ADDR=<hex>): fire a probe with the current u64 at the
        // watched address before each syscall, so a trace can bracket which
        // syscall changes it.
        #[cfg(feature = "watchpoint")]
        if let Some(addr) = watch_addr()
            && let Ok(bytes) = memory.read_bytes(addr, 8)
        {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[..8]);
            crate::probes::mem_watch(request.number.raw(), addr, u64::from_le_bytes(le));
        }

        // Syscalls migrated to the normalized SyscallCtx handler contract are
        // dispatched here first; the borrow of memory/reporter is scoped to
        // the call, so the legacy match below can still use them for the rest.
        if let Some(result) = route.dispatch(self, kernel, request, memory, reporter, thread) {
            let outcome = lower_handler_result(result)?;
            // Consumption-based EPOLLET re-arm (see `epoll_rearm_after_io`).
            resources::with_captured_resources(kernel, || {
                self.epoll_rearm_after_io(&request, &outcome);
            });
            return Ok(outcome);
        }

        // The normalized macro table is the single authoritative syscall
        // registry. Any number it does not claim is genuinely unimplemented:
        // record a structured compat event and return ENOSYS. The supervisor
        // must never panic on guest input — an unknown syscall is the guest's
        // problem to handle (it gets -ENOSYS), not ours to crash on.
        reporter.record(CompatEvent::unhandled_syscall(
            request.number.raw(),
            name,
            request.args,
        ));
        Ok(DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        })
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

#[cfg(test)]
mod mount_retirement_tests {
    use super::*;

    #[test]
    fn terminal_mount_retirement_waits_for_every_dispatch_and_archive_alias() {
        let dispatcher = SyscallDispatcher::new();
        let expected = dispatcher.fs.vfs_mounts.len();
        let archive = dispatcher.archive_authority();
        let mut retirement = dispatcher.prepare_mount_retirement();

        assert!(retirement.prepare().is_err());
        drop(dispatcher);
        assert!(retirement.prepare().is_err());
        drop(archive);

        retirement.prepare().expect("terminal mount owner");
        assert_eq!(retirement.clear(), expected);
    }
}

/// Untyped guest-memory write. Prefer [`write_kernel_struct`] over this
/// whenever the payload is a Linux UAPI struct: that path is bound to
/// `KernelAbi::ABI_SIZE` so it CAN'T accidentally over-write a caller's
/// stack buffer the way an ad-hoc `&[u8]` from `as_bytes()` can.
/// Apply `bytes` to an in-memory file backing at `*offset`, growing it
/// zero-filled if there's a gap and advancing the cursor. Dense files update
/// their vector; rootfs-backed files update only their dirty ranges.
fn write_into_file_contents(
    contents: &mut FileContents,
    offset: &mut usize,
    bytes: &[u8],
) -> Result<usize, LinuxErrno> {
    let end = (*offset).checked_add(bytes.len()).ok_or(LINUX_EFBIG)?;
    if !contents.accepts_len(end as u64) {
        return Err(LINUX_EFBIG);
    }
    let written = contents.write_at(*offset as u64, bytes)?;
    *offset += written;
    Ok(written)
}

/// Seal enforcement for a content-modifying write to a memfd (`seals` is the
/// description's seal set; `None` = not sealable). F_SEAL_WRITE /
/// F_SEAL_FUTURE_WRITE → EPERM on any write; F_SEAL_GROW → EPERM when the write
/// extends past `cur_len`. (memfd_create01)
fn memfd_seal_write_check(
    seals: Option<u32>,
    offset: usize,
    write_len: usize,
    cur_len: usize,
) -> Result<(), LinuxErrno> {
    let Some(seals) = seals.and_then(carrick_abi::LinuxMemfdSeals::from_bits) else {
        return Ok(());
    };
    if seals.intersects(
        carrick_abi::LinuxMemfdSeals::WRITE | carrick_abi::LinuxMemfdSeals::FUTURE_WRITE,
    ) {
        return Err(LINUX_EPERM);
    }
    if seals.contains(carrick_abi::LinuxMemfdSeals::GROW)
        && offset.saturating_add(write_len) > cur_len
    {
        return Err(LINUX_EPERM);
    }
    Ok(())
}

/// Seal enforcement for a size change (ftruncate / fallocate grow / hole punch).
/// Shrinking with F_SEAL_SHRINK or growing with F_SEAL_GROW → EPERM.
fn memfd_seal_resize_check(
    seals: Option<u32>,
    new_len: usize,
    cur_len: usize,
) -> Result<(), LinuxErrno> {
    let Some(seals) = seals.and_then(carrick_abi::LinuxMemfdSeals::from_bits) else {
        return Ok(());
    };
    if seals.contains(carrick_abi::LinuxMemfdSeals::SHRINK) && new_len < cur_len {
        return Err(LINUX_EPERM);
    }
    if seals.contains(carrick_abi::LinuxMemfdSeals::GROW) && new_len > cur_len {
        return Err(LINUX_EPERM);
    }
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

fn write_packed(memory: &mut impl CurrentMmMemory, address: u64, bytes: &[u8]) -> DispatchOutcome {
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
    memory: &mut impl CurrentMmMemory,
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
fn relative_from_absolute_timespec(
    clock: &crate::kernel::container::ClockDomain,
    tv_sec: i64,
    tv_nsec: i64,
    realtime: bool,
) -> Duration {
    let abs_ns = (tv_sec as i128) * 1_000_000_000 + tv_nsec as i128;
    if realtime && clock.is_frozen() {
        let frozen_ns = clock.realtime_now().as_nanos() as i128;
        if abs_ns <= frozen_ns {
            return Duration::ZERO;
        }
        return Duration::MAX;
    }
    let now_ns: i128 = if realtime {
        clock.realtime_now().as_nanos() as i128
    } else {
        clock.monotonic_now().as_nanos() as i128
    };
    let rel_ns = (abs_ns - now_ns).max(0);
    let dur = Duration::from_nanos(rel_ns.min(u64::MAX as i128) as u64);
    clock.scale_timeout(dur)
}

fn dispatch_futex_pi(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    command: u64,
    word: u32,
    tid: u32,
    futex: Option<&crate::thread::FutexTable>,
) -> DispatchOutcome {
    // The low 30 bits of a PI-futex word hold the owner TID (FUTEX_TID_MASK,
    // imported from carrick-abi); the upper two are FUTEX_WAITERS/OWNER_DIED.
    if tid == 0 || tid > LINUX_FUTEX_TID_MASK {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let owner = word & LINUX_FUTEX_TID_MASK;
    match command {
        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_TRYLOCK_PI => {
            if owner == 0 {
                if let Err(errno) = write_u32(memory, address, tid) {
                    return DispatchOutcome::Errno { errno };
                }
                return DispatchOutcome::Returned { value: 0 };
            }
            if owner == tid {
                return DispatchOutcome::Errno {
                    errno: LINUX_EDEADLK,
                };
            }
            DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            }
        }
        LINUX_FUTEX_UNLOCK_PI => {
            if owner != tid {
                return DispatchOutcome::Errno { errno: LINUX_EPERM };
            }
            if let Err(errno) = write_u32(memory, address, 0) {
                return DispatchOutcome::Errno { errno };
            }
            if let Some(futex) = futex {
                let woken = futex.wake(address, 1);
                crate::event_ring::rec_futex_wake(address, woken);
            }
            DispatchOutcome::Returned { value: 0 }
        }
        _ => DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_threaded_futex(
    clock: &crate::kernel::container::ClockDomain,
    request: SyscallRequest,
    memory: &mut impl CurrentMmMemory,
    reporter: &CompatReporter,
    futex: &crate::thread::FutexTable,
    _tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
    hvpatch_linux_tid: Option<u32>,
) -> DispatchOutcome {
    let address = request.arg(0);
    let operation = request.arg(1);
    let value = request.arg(2) as u32;
    let timeout_address = request.arg(3);

    let raw_command = operation & LINUX_FUTEX_CMD_MASK;
    let command = match raw_command {
        LINUX_FUTEX_WAIT_BITSET => LINUX_FUTEX_WAIT,
        LINUX_FUTEX_WAKE_BITSET => LINUX_FUTEX_WAKE,
        other => other,
    };
    let flags = operation & !LINUX_FUTEX_CMD_MASK;
    let futex_flags = LinuxFutexFlags::from_bits_retain(flags);
    // Unknown OPERATION outranks bad flags; see the `futex` handler.
    if !linux_futex_command_is_known(raw_command) {
        return DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        };
    }
    if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    // Identical well-formedness gate to the `futex` handler in `proc.rs`; a
    // guest thread reaches THIS path, so validating only there left every
    // check unreachable in practice (`eventwaitmatrix`).
    if !address.is_multiple_of(4) {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    if matches!(
        raw_command,
        LINUX_FUTEX_WAIT_BITSET | LINUX_FUTEX_WAKE_BITSET
    ) && request.arg(5) as u32 == 0
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    if timeout_address != 0
        && matches!(raw_command, LINUX_FUTEX_WAIT | LINUX_FUTEX_WAIT_BITSET)
        && let Ok(timespec) = read_timespec(memory, timeout_address)
        && !linux_timeout_timespec_is_valid(timespec)
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    // Only WAIT / CMP_REQUEUE / PI ops consult the futex VALUE; WAKE and plain
    // REQUEUE are keyed purely on the guest address (the parking-lot table keys
    // on the VA, which is identical across the shared guest address space). Real
    // Linux FUTEX_WAKE likewise computes only the hash key — it never reads the
    // word. So reading the word for a WAKE is unnecessary, and surfacing its
    // EFAULT is actively harmful: a cross-thread waker whose per-thread
    // `GuestMemory` view can't translate the *waiter's* futex page (the syscall
    // path uses a per-sibling window snapshot, unlike the coherent whole-RAM
    // view HVF exposes) would spuriously fail the wake. Go's
    // `runtime.futexwakeup` treats any unexpected errno (incl. EFAULT) as fatal
    // and self-crashes (SIGSEGV at 0x1006), which is exactly the intermittent
    // Go-on-KVM failure. Make the read non-fatal for value-independent ops.
    let needs_word = matches!(
        command,
        LINUX_FUTEX_WAIT
            | LINUX_FUTEX_LOCK_PI
            | LINUX_FUTEX_TRYLOCK_PI
            | LINUX_FUTEX_UNLOCK_PI
            | LINUX_FUTEX_CMP_REQUEUE
    );
    let word = match read_futex_word(memory, address) {
        Ok(word) => word,
        Err(errno) if needs_word => return DispatchOutcome::Errno { errno },
        // WAKE / plain REQUEUE: the value is unused; proceed address-keyed.
        Err(_) => 0,
    };

    if matches!(
        command,
        LINUX_FUTEX_LOCK_PI | LINUX_FUTEX_TRYLOCK_PI | LINUX_FUTEX_UNLOCK_PI
    ) {
        let Some(guest_tid) = hvpatch_linux_tid else {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        };
        return dispatch_futex_pi(memory, address, command, word, guest_tid, Some(futex));
    }

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
    //
    // EXCEPT a non-PRIVATE futex on a live thread's CLONE_CHILD_CLEARTID address:
    // glibc's `pthread_join` waits on `pd->tid` non-PRIVATE, but its waker is
    // carrick's IN-PROCESS `handle_thread_exit` (`futex.wake`), not a guest
    // `FUTEX_WAKE`. It must stay in the in-process table — on bhyve the cross-process
    // mirror is a SEPARATE word and a mirror `__ulock` WAIT would never be woken by
    // the in-process exit-wake, so the join HANGS (the immediate-`pthread_join`
    // failure; KVM is immune — its mirror IS the guest word). No-op on HVF/KVM, where
    // this private descriptor word never resolved to a mirror anyway.
    let shared_location = if futex_flags.contains(LinuxFutexFlags::PRIVATE)
        || registry.is_clear_child_tid_addr(address)
    {
        None
    } else {
        memory.shared_futex_location(address)
    };
    crate::probes::futex_route(
        address,
        command as i32,
        if shared_location.is_some() { 1 } else { 0 },
        shared_location
            .map(|location| location.wait_addr().raw() as u64)
            .unwrap_or(0),
    );

    match command {
        LINUX_FUTEX_WAKE => {
            if let Some(location) = shared_location {
                // Publish the waker's word to the SHARED MIRROR before the wake so
                // a cross-process WAITer observes it — but ONLY on a backend that
                // actually uses a separate mirror (bhyve, whose per-VM guest word
                // is not shared across fork). On HVF/KVM the wait address IS the guest
                // word, which the waker already wrote before this FUTEX_WAKE
                // syscall: republishing here is redundant AND races — the value we
                // could write is necessarily a slightly stale snapshot, so it
                // would OVERWRITE a concurrent peer update and REVERT it (measured
                // ~3% of wakes), which desynced cross-process semaphores/barriers
                // and hung cpython multiprocessing. So gate the publish on
                // `SharedFutexLocation::Mirror` and, when it IS needed, read the
                // word FRESH (not the stale top-of-handler `word`).
                if location.is_mirror() {
                    let fresh = read_futex_word(memory, address).unwrap_or(word);
                    // SAFETY: the wait address is a live 4-byte-aligned host mirror word.
                    unsafe {
                        (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
                            .store(fresh, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                // Cross-PROCESS (MAP_SHARED) wake: route through the
                // `PlatformFutex::shared_wake` seam (the wake counterpart of the
                // `SharedFutexWait` outcome) so the wake reaches a waiter parked
                // in another carrick process via the SAME backend the wait uses —
                // HVF's __ulock (one-at-a-time + sched_yield, the macOS spurious-
                // success cure) or KVM's host `SYS_futex(FUTEX_WAKE)`. The loop
                // completes the syscall with the count woken.
                return DispatchOutcome::SharedFutexWake {
                    target: SharedFutexTarget::new(location, location.waiter_key()),
                    count: value,
                };
            }
            let n = futex.wake(address, value);
            crate::event_ring::rec_futex_wake(address, n);
            DispatchOutcome::Returned {
                value: i64::from(n),
            }
        }
        LINUX_FUTEX_WAIT => {
            // For a SHARED (cross-process) futex the authoritative current value is at
            // the fork-coherent host word (the mirror on bhyve; == the guest word on
            // HVF/KVM). Compare THAT, not the possibly stale per-VM sysmem copy, and
            // publish it back to the guest word so the caller's retry loop re-reads what
            // another process wrote instead of spinning on the stale value (see proc.rs).
            let current = if let Some(location) = shared_location {
                // SAFETY: the wait address is a live 4-byte-aligned host word.
                let mirror = unsafe {
                    (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
                        .load(std::sync::atomic::Ordering::SeqCst)
                };
                // On bhyve (separate mirror) sync the mirror -> the waiter's
                // per-VM guest word so its retry loop re-reads what a peer wrote.
                // On HVF/KVM the wait address IS the guest word, so this write-back is
                // redundant AND races exactly like the FUTEX_WAKE store-back: a
                // concurrent peer write landing between the load above and this
                // store reverts the peer's update, desyncing the protocol (the
                // residual that hung multiprocessing test_thousand). Gate it on
                // the mirror flag — `mirror` is already the authoritative current
                // value used for the compare below regardless.
                if mirror != word && location.is_mirror() {
                    let _ = memory.write_bytes(address, &mirror.to_ne_bytes());
                }
                mirror
            } else {
                word
            };
            if current != value {
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
                        clock,
                        timespec.tv_sec,
                        timespec.tv_nsec,
                        futex_flags.contains(LinuxFutexFlags::CLOCK_REALTIME),
                    ))
                } else {
                    // A present (non-NULL) relative timespec ALWAYS specifies a
                    // deadline — even {0,0}, which means "expire IMMEDIATELY"
                    // (ETIMEDOUT now), NOT "infinite". duration_from_linux_timespec
                    // maps {0,0} to None ("no duration"); collapsing that to the
                    // `timeout_address == 0` None (block forever) made the threaded
                    // park (FutexWait) compute no deadline and spin forever on a
                    // zero-timeout WAIT that Linux returns ETIMEDOUT from at once.
                    // Force the zero case to a ZERO duration so the park deadline is
                    // `now` and fires immediately (mirrors the proc.rs fix 519dd40f).
                    match duration_from_linux_timespec(timespec) {
                        Ok(t) => Some(clock.scale_timeout(t.unwrap_or(std::time::Duration::ZERO))),
                        Err(errno) => return DispatchOutcome::Errno { errno },
                    }
                }
            };
            if let Some(location) = shared_location {
                // The shared path's compare-and-wait is atomic in the kernel
                // (__ulock UL_COMPARE_AND_WAIT re-checks the word), so no
                // generation snapshot is needed here.
                return DispatchOutcome::SharedFutexWait {
                    target: SharedFutexTarget::new(location, location.waiter_key()),
                    generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                        .prepare_wait(location.waiter_key() as u64),
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

            if let Some(location) = shared_location {
                let Some(to_location) = memory.shared_futex_location(uaddr2) else {
                    return DispatchOutcome::Errno {
                        errno: LINUX_EFAULT,
                    };
                };
                return DispatchOutcome::SharedFutexRequeue {
                    from: SharedFutexTarget::new(location, location.waiter_key()),
                    to: SharedFutexTarget::new(to_location, to_location.waiter_key()),
                    wake: nr_wake,
                    requeue: nr_requeue,
                };
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

#[derive(Debug, Clone, Copy)]
struct FutexWaitvEntry {
    address: u64,
    value: u32,
    private: bool,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_futex_waitv_args(
    clock: &crate::kernel::container::ClockDomain,
    memory: &mut impl CurrentMmMemory,
    futex: Option<&crate::thread::FutexTable>,
    waiters: u64,
    nr_futexes: u64,
    flags: u64,
    timeout_address: u64,
    clockid: u64,
) -> DispatchOutcome {
    if flags != 0
        || nr_futexes == 0
        || nr_futexes > LINUX_FUTEX_WAITV_MAX
        || waiters == 0
        || !matches!(clockid, LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_REALTIME)
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    let timeout = if timeout_address == 0 {
        None
    } else {
        let timespec = match read_timespec(memory, timeout_address) {
            Ok(timespec) => timespec,
            Err(errno) => return DispatchOutcome::Errno { errno },
        };
        Some(relative_from_absolute_timespec(
            clock,
            timespec.tv_sec,
            timespec.tv_nsec,
            clockid == LINUX_CLOCK_REALTIME,
        ))
    };

    let mut entries = Vec::with_capacity(nr_futexes as usize);
    for index in 0..nr_futexes {
        let Some(entry_address) = waiters.checked_add(index.saturating_mul(24)) else {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        };
        let bytes = match memory.read_bytes(entry_address, 24) {
            Ok(bytes) => bytes,
            Err(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        };
        let mut value_bytes = [0u8; 8];
        value_bytes.copy_from_slice(&bytes[0..8]);
        let mut address_bytes = [0u8; 8];
        address_bytes.copy_from_slice(&bytes[8..16]);
        let mut flags_bytes = [0u8; 4];
        flags_bytes.copy_from_slice(&bytes[16..20]);
        let mut reserved_bytes = [0u8; 4];
        reserved_bytes.copy_from_slice(&bytes[20..24]);

        let value = u64::from_ne_bytes(value_bytes);
        let address = u64::from_ne_bytes(address_bytes);
        let waiter_flags = u32::from_ne_bytes(flags_bytes) as u64;
        let reserved = u32::from_ne_bytes(reserved_bytes);

        let size = waiter_flags & LINUX_FUTEX_32;
        let unknown = waiter_flags & !(LINUX_FUTEX_32 | LINUX_FUTEX_PRIVATE_FLAG);
        if reserved != 0 || size != LINUX_FUTEX_32 || unknown != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if address == 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        if address & 0x3 != 0 {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        if value > u64::from(u32::MAX) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let expected = value as u32;
        let private = carrick_abi::LinuxFutexFlags::from_bits_truncate(waiter_flags)
            .contains(carrick_abi::LinuxFutexFlags::PRIVATE);
        match read_futex_word(memory, address) {
            Ok(word) if word == expected => {}
            Ok(_) => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }
            Err(errno) => return DispatchOutcome::Errno { errno },
        }
        entries.push(FutexWaitvEntry {
            address,
            value: expected,
            private,
        });
    }

    if let Some((index, entry)) = entries
        .len()
        .checked_sub(1)
        .and_then(|index| entries.get(index).map(|entry| (index, *entry)))
    {
        if !entry.private
            && let Some(location) = memory.shared_futex_location(entry.address)
        {
            return DispatchOutcome::SharedFutexWaitv {
                target: SharedFutexTarget::new(location, location.waiter_key()),
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(location.waiter_key() as u64),
                value: entry.value,
                timeout,
                index: index as i64,
            };
        }
        if let Some(futex) = futex {
            let wait = futex.prepare_wait(entry.address);
            match read_futex_word(memory, entry.address) {
                Ok(word) if word != entry.value => {
                    return DispatchOutcome::returned_len_or_errno(index);
                }
                Ok(_) => {}
                Err(errno) => return DispatchOutcome::Errno { errno },
            }
            return DispatchOutcome::FutexWaitv {
                wait,
                timeout,
                index: index as i64,
            };
        }
    }

    for (index, entry) in entries.iter().enumerate() {
        match read_futex_word(memory, entry.address) {
            Ok(word) if word != entry.value => {
                return DispatchOutcome::returned_len_or_errno(index);
            }
            Ok(_) => {}
            Err(errno) => return DispatchOutcome::Errno { errno },
        }
    }
    if let Some(timeout) = timeout {
        DispatchOutcome::WaitOnSleep {
            duration: timeout,
            remaining: None,
        }
    } else {
        DispatchOutcome::Errno {
            errno: LINUX_ETIMEDOUT,
        }
    }
}

/// Type-safe write for any Linux UAPI struct that implements
/// [`KernelAbi`]. Writes EXACTLY `T::ABI_SIZE` bytes — the size the
/// Linux kernel itself uses on the wire. The compiler refuses to pass
/// `T` here unless the trait is implemented, which forces every new
/// ABI struct to declare its kernel size up front and have a paired
/// const assert validating `ABI_SIZE <= size_of::<T>()`.
fn write_kernel_struct<T: KernelAbi>(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: &T,
) -> DispatchOutcome {
    write_packed(memory, address, value.abi_bytes())
}

/// Write a [`LinuxTermios`] as the full 44-byte `struct termios2` (TCGETS2),
/// i.e. including the `c_ispeed`/`c_ospeed` tail. [`write_kernel_struct`] would
/// truncate to the 36-byte legacy `struct termios` (the `KernelAbi::ABI_SIZE`),
/// which is correct for TCGETS but 8 bytes short for the termios2 buffer that
/// glibc-aarch64 hands to TCGETS2.
fn write_termios2(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: &LinuxTermios,
) -> DispatchOutcome {
    write_packed(memory, address, zerocopy::IntoBytes::as_bytes(value))
}

/// Lower-level form of [`write_kernel_struct`] for sites that already
/// handle `Result<(), MemoryError>` directly (typically because they
/// have post-write bookkeeping that the `DispatchOutcome::Errno` shape
/// would short-circuit). Same wire-size guarantee.
fn write_kernel_struct_raw<T: KernelAbi>(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: &T,
) -> Result<(), crate::dispatch::MemoryError> {
    memory.write_bytes(address, value.abi_bytes())
}

/// Type-safe read for Linux UAPI structs that implement [`KernelAbi`].
/// Reads exactly the Linux wire size, then zero-fills any Rust-only tail
/// bytes before returning the typed value.
fn read_kernel_struct<T>(memory: &impl CurrentMmMemory, address: u64) -> Result<T, LinuxErrno>
where
    T: KernelAbi + FromBytes,
{
    read_kernel_prefix(memory, address, T::ABI_SIZE)
}

/// Lower-level ABI read for variable-length structs such as clone_args.
/// `length` is the guest-provided prefix length and must fit inside the
/// Linux ABI size carried by the type.
fn read_kernel_prefix<T>(
    memory: &impl CurrentMmMemory,
    address: u64,
    length: usize,
) -> Result<T, LinuxErrno>
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

fn write_statfs(memory: &mut impl CurrentMmMemory, statfsbuf: u64) -> DispatchOutcome {
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
fn fd_is_tty<S: std::hash::BuildHasher>(open_files: &HashMap<i32, OpenFile, S>, fd: i32) -> bool {
    if !is_stdio_fd(fd) {
        return false;
    }
    !open_files.contains_key(&fd) && crate::host_tty::host_isatty(fd)
}

fn retain_open_file(description: &Arc<crate::kernel::FileDescription>) {
    description.retain_fd_ref();
}

pub(crate) fn close_open_file(open_file: &OpenFile) {
    open_file.description.release_fd_ref();
}

#[cfg(test)]
fn is_last_open_file_ref(open_file: &OpenFile) -> bool {
    open_file.description.fd_ref_count() == 1
}

fn linux_min_fd(value: u64) -> Result<i32, LinuxErrno> {
    i32::try_from(value).map_err(|_| LINUX_EINVAL)
}

/// A dynamic posix CPU-clock id (per-thread or per-process). These are NEGATIVE
/// (viewed as a signed 32-bit int) and encode a tid/pid; glibc/musl return them
/// from `clock_getcpuclockid`/`pthread_getcpuclockid`. CPython's
/// test_pthread_getcpuclockid does clock_gettime() on one — carrick rejected it.
pub(crate) enum DynamicCpuClock {
    /// Per-thread CPU clock → target thread kernel CPU accounting.
    PerThread,
    /// Per-process CPU clock → target task kernel CPU accounting.
    PerProcess,
}

pub(crate) fn dynamic_cpu_clock(clock_id: u64) -> Option<DynamicCpuClock> {
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

pub(super) fn linux_clock_duration(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Option<Duration> {
    match clock_id {
        LINUX_CLOCK_REALTIME
        | LINUX_CLOCK_REALTIME_COARSE
        | LINUX_CLOCK_REALTIME_ALARM
        | LINUX_CLOCK_TAI => Some(clock.realtime_now()),
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW | LINUX_CLOCK_MONOTONIC_COARSE => {
            Some(clock.monotonic_now())
        }
        // BOOTTIME includes suspend time; on macOS that is CLOCK_MONOTONIC.
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => Some(clock.boottime_now()),
        LINUX_CLOCK_PROCESS_CPUTIME_ID => Some(Duration::from_nanos(time::task_process_cpu_ns())),
        LINUX_CLOCK_THREAD_CPUTIME_ID => Some(Duration::from_nanos(time::task_thread_cpu_ns())),
        // A dynamic per-task CPU-clock id (negative) → current thread/process CPU time.
        _ => match dynamic_cpu_clock(clock_id)? {
            DynamicCpuClock::PerThread => Some(Duration::from_nanos(time::task_thread_cpu_ns())),
            DynamicCpuClock::PerProcess => Some(Duration::from_nanos(time::task_process_cpu_ns())),
        },
    }
}

fn linux_clock_nanosleep_now(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
) -> Result<Duration, LinuxErrno> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP);
    }
    linux_clock_duration(clock, clock_id).ok_or(LINUX_EINVAL)
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

/// Clocks a `timerfd` can be armed on.
///
/// Strictly smaller than [`linux_clock_is_known`]: the CPU-time clocks and the
/// coarse/raw variants are readable through `clock_gettime` but cannot back a
/// timer. carrick admitted anything it could read, so
/// `timerfd_create(CLOCK_PROCESS_CPUTIME_ID)` returned a working fd where
/// Linux answers EINVAL (`eventwaitmatrix` `timerfd_create_cputime_einval`).
fn linux_timerfd_clock_is_supported(clock_id: u64) -> bool {
    matches!(
        clock_id,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
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

fn linux_time_state_from_status(status: LinuxTimexStatus) -> i64 {
    if status.contains(LinuxTimexStatus::UNSYNC) {
        LINUX_TIME_ERROR
    } else if status.contains(LinuxTimexStatus::INS) {
        LINUX_TIME_INS
    } else if status.contains(LinuxTimexStatus::DEL) {
        LINUX_TIME_DEL
    } else {
        LINUX_TIME_OK
    }
}

fn linux_timex_from_state(
    time: LinuxTimeval,
    state: &crate::kernel::container::AdjtimexState,
) -> LinuxTimex {
    LinuxTimex {
        modes: 0,
        _pad0: 0,
        offset: state.offset,
        freq: state.freq,
        maxerror: state.maxerror,
        esterror: state.esterror,
        status: state.status,
        _pad1: 0,
        constant: state.constant,
        precision: 1,
        tolerance: 32_768_000,
        time,
        tick: state.tick,
        ppsfreq: 0,
        jitter: 0,
        shift: 0,
        _pad2: 0,
        stabil: 0,
        jitcnt: 0,
        calcnt: 0,
        errcnt: 0,
        stbcnt: 0,
        tai: state.tai,
        _pad3: [0; 11],
    }
}

fn linux_timex_time(duration: Duration, status: LinuxTimexStatus) -> LinuxTimeval {
    let sub = if status.contains(LinuxTimexStatus::NANO) {
        i64::from(duration.subsec_nanos())
    } else {
        i64::from(duration.subsec_micros())
    };
    LinuxTimeval::new(duration.as_secs() as i64, sub)
}

fn adjtimex_bootstrap(
    clock: &crate::kernel::container::ClockDomain,
    memory: &mut impl CurrentMmMemory,
    address: u64,
    can_adjust: bool,
) -> DispatchOutcome {
    let timex = match read_kernel_struct::<LinuxTimex>(memory, address) {
        Ok(timex) => timex,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };
    let modes = LinuxTimexModes::from_bits_retain(timex.modes);
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
        && !modes.contains(LinuxTimexModes::OFFSET)
    {
        let invalid = LinuxTimex::invalid_mode_error_state();
        return match write_kernel_struct(memory, address, &invalid) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
            other => other,
        };
    }
    if timex.modes == 0 {
        let state = clock.adjtimex_state();
        let status = LinuxTimexStatus::from_bits_retain(state.status);
        let now = clock.realtime_now();
        let time = linux_timex_time(now, status);
        let current = linux_timex_from_state(time, &state);
        let value = linux_time_state_from_status(status);
        return match write_kernel_struct(memory, address, &current) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
            other => other,
        };
    }
    if modes == LinuxTimexModes::OFFSET_SS_READ {
        let state = clock.adjtimex_state();
        let status = LinuxTimexStatus::from_bits_retain(state.status);
        let now = clock.realtime_now();
        let time = linux_timex_time(now, status);
        let mut current = linux_timex_from_state(time, &state);
        current.modes = timex.modes;
        current.offset = 0;
        let value = linux_time_state_from_status(status);
        return match write_kernel_struct(memory, address, &current) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
            other => other,
        };
    }
    if !can_adjust {
        return DispatchOutcome::Errno { errno: LINUX_EPERM };
    }

    const KNOWN_MODES: u32 = LinuxTimexModes::IDEMPOTENT_SUPPORTED.bits()
        | LinuxTimexModes::OFFSET_SINGLESHOT_FLAG.bits();
    if (timex.modes & !KNOWN_MODES) != 0 {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    // ADJ_MICRO|ADJ_NANO together and ADJ_TAI|ADJ_TIMECONST together are
    // ACCEPTED by Linux (native arm64 oracle, probe `adjtimexmodel`
    // `micro_nano_together_accepted` / `tai_timeconst_together_accepted`);
    // the later of the two stores simply wins.
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG)
        && modes != LinuxTimexModes::OFFSET_SINGLESHOT
    {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }

    if modes.contains(LinuxTimexModes::TICK) {
        let minimum = 900_000 / LINUX_CLK_TCK;
        let maximum = 1_100_000 / LINUX_CLK_TCK;
        let requested_tick = timex.tick;
        if !(minimum..=maximum).contains(&requested_tick) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
    }
    // An out-of-range `freq` is CLAMPED to +/-MAXFREQ, not refused: the
    // native arm64 oracle accepts 35_000_000 (probe `adjtimexmodel`,
    // `oversized_freq_accepted`). The clamp happens where the value is stored.
    if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG) {
        let requested_offset = timex.offset;
        if !(-131_071..=131_071).contains(&requested_offset) {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
    }
    // Unknown `status` bits are ignored, not refused: the oracle accepts
    // `1 << 20` (`unknown_status_bits_accepted`). Only the defined, writable
    // bits are stored where the value lands.

    let mut step_realtime_ns: Option<i64> = None;
    if modes.contains(LinuxTimexModes::SETOFFSET) {
        let is_nano = if modes.contains(LinuxTimexModes::NANO) {
            true
        } else if modes.contains(LinuxTimexModes::MICRO) {
            false
        } else {
            LinuxTimexStatus::from_bits_retain(clock.adjtimex_state().status)
                .contains(LinuxTimexStatus::NANO)
        };
        let max_sub = if is_nano { 1_000_000_000 } else { 1_000_000 };
        if timex.time.tv_usec < 0 || timex.time.tv_usec >= max_sub {
            return DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            };
        }
        let sec_ns = match timex.time.tv_sec.checked_mul(1_000_000_000) {
            Some(s) => s,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        let sub_ns = if is_nano {
            timex.time.tv_usec
        } else {
            timex.time.tv_usec.saturating_mul(1_000)
        };
        let delta_ns = match sec_ns.checked_add(sub_ns) {
            Some(d) => d,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        step_realtime_ns = Some(delta_ns);
    } else if modes == LinuxTimexModes::OFFSET_SINGLESHOT {
        let delta_ns = match timex.offset.checked_mul(1_000) {
            Some(ns) => ns,
            None => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EINVAL,
                };
            }
        };
        step_realtime_ns = Some(delta_ns);
    }

    if let Some(delta_ns) = step_realtime_ns {
        if let Err(errno) = clock.try_step_realtime_offset_ns(delta_ns) {
            return DispatchOutcome::Errno { errno };
        }
    }

    let updated_state = clock.with_adjtimex_mut(|state| {
        if modes.contains(LinuxTimexModes::OFFSET) {
            if modes.contains(LinuxTimexModes::OFFSET_SINGLESHOT_FLAG) {
                state.offset = 0;
            } else {
                state.offset = timex.offset;
            }
        }
        if modes.contains(LinuxTimexModes::FREQUENCY) {
            // Linux clamps to +/-MAXFREQ (scaled ppm) instead of refusing.
            state.freq = timex.freq.clamp(-32_768_000, 32_768_000);
        }
        if modes.contains(LinuxTimexModes::MAXERROR) {
            state.maxerror = timex.maxerror;
        }
        if modes.contains(LinuxTimexModes::ESTERROR) {
            state.esterror = timex.esterror;
        }
        if modes.contains(LinuxTimexModes::STATUS) {
            let current_status = LinuxTimexStatus::from_bits_retain(state.status);
            // `from_bits_truncate`: bits Linux does not define are dropped,
            // not refused (the oracle accepts `1 << 20`).
            let requested_status = LinuxTimexStatus::from_bits_truncate(timex.status);
            let merged = (current_status & LinuxTimexStatus::RONLY)
                | (requested_status & !LinuxTimexStatus::RONLY);
            state.status = merged.bits();
        }
        if modes.contains(LinuxTimexModes::NANO) {
            let mut s = LinuxTimexStatus::from_bits_retain(state.status);
            s.insert(LinuxTimexStatus::NANO);
            state.status = s.bits();
        }
        if modes.contains(LinuxTimexModes::MICRO) {
            let mut s = LinuxTimexStatus::from_bits_retain(state.status);
            s.remove(LinuxTimexStatus::NANO);
            state.status = s.bits();
        }
        if modes.contains(LinuxTimexModes::TIMECONST) {
            state.constant = timex.constant;
        }
        if modes.contains(LinuxTimexModes::TAI) {
            state.tai = timex.constant as i32;
        }
        if modes.contains(LinuxTimexModes::TICK) {
            state.tick = timex.tick;
        }
        state.clone()
    });

    let status = LinuxTimexStatus::from_bits_retain(updated_state.status);
    let now = clock.realtime_now();
    let time = linux_timex_time(now, status);
    let mut current = linux_timex_from_state(time, &updated_state);
    current.modes = timex.modes;
    let value = linux_time_state_from_status(status);
    match write_kernel_struct(memory, address, &current) {
        DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned { value },
        other => other,
    }
}

pub(in crate::dispatch) fn linux_task_name_from_bytes(bytes: &[u8]) -> [u8; LINUX_TASK_COMM_LEN] {
    let mut name = [0; LINUX_TASK_COMM_LEN];
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
        .min(LINUX_TASK_COMM_LEN - 1);
    name[..length].copy_from_slice(&bytes[..length]);
    name
}

pub(crate) fn linux_task_name_to_string(bytes: &[u8; LINUX_TASK_COMM_LEN]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn linux_statx_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW
        | LINUX_AT_EMPTY_PATH
        | LINUX_AT_NO_AUTOMOUNT
        | LINUX_AT_STATX_FORCE_SYNC
        | LINUX_AT_STATX_DONT_SYNC;
    let sync = flags & (LINUX_AT_STATX_FORCE_SYNC | LINUX_AT_STATX_DONT_SYNC);
    flags & !SUPPORTED == 0 && sync != (LINUX_AT_STATX_FORCE_SYNC | LINUX_AT_STATX_DONT_SYNC)
}

fn linux_access_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH;
    flags & !SUPPORTED == 0
}

/// Read a host (macOS) POSIX clock via `libc::clock_gettime`. `clock_id`
/// MUST be a host symbolic `libc::CLOCK_*` constant (Linux numbering
/// differs and is mapped by callers). Returns `None` only on failure.
pub(crate) fn host_clock_duration(clock_id: libc::clockid_t) -> Option<Duration> {
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

pub(crate) fn monotonic_duration() -> Duration {
    // On a Linux host the guest's CLOCK_MONOTONIC IS the host's — read the host
    // CLOCK_MONOTONIC (NOT CLOCK_MONOTONIC_RAW). RAW is the un-virtualized
    // hardware clock; inside a time-namespace (LXC/containers) it is NOT offset
    // by the namespace's boottime delta while CLOCK_MONOTONIC and CLOCK_BOOTTIME
    // ARE, so a RAW monotonic can exceed the virtualized BOOTTIME and break the
    // BOOTTIME >= MONOTONIC invariant. Keeping both on the virtualized family
    // makes the invariant hold; it also matches what the guest asked for.
    #[cfg(target_os = "linux")]
    {
        return host_clock_duration(libc::CLOCK_MONOTONIC).unwrap_or(Duration::ZERO);
    }
    // Linux CLOCK_MONOTONIC does NOT advance while the system is suspended.
    // On macOS that is CLOCK_UPTIME_RAW (mach_absolute_time) — NOT macOS
    // CLOCK_MONOTONIC, which (unlike Linux) keeps counting through sleep and
    // therefore corresponds to Linux CLOCK_BOOTTIME (see `boottime_duration`).
    #[cfg(not(target_os = "linux"))]
    {
        host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW).unwrap_or(Duration::ZERO)
    }
}

/// The guest's `CLOCK_BOOTTIME`. Also THE authority for `/proc/uptime` field 1
/// and `/proc/stat`'s `btime`, which Linux derives from this same clock — see
/// `crate::vfs::proc`.
pub(crate) fn boottime_duration() -> Duration {
    // On a Linux host the guest's CLOCK_BOOTTIME IS the host's — read it natively
    // so it shares the same (time-namespace-virtualized) epoch family as
    // monotonic_duration above; BOOTTIME = MONOTONIC + suspend, so the
    // BOOTTIME >= MONOTONIC invariant holds.
    #[cfg(target_os = "linux")]
    {
        return host_clock_duration(libc::CLOCK_BOOTTIME).unwrap_or_else(monotonic_duration);
    }
    // On macOS/HVF the guest's BOOTTIME must MATCH its own vDSO fast path, which
    // serves CLOCK_BOOTTIME (clock id 7) as the bare guest CNTVCT/freq — i.e.
    // suspend-EXCLUDING, identical to MONOTONIC (vdso_fns.s clock-7 path). HVF
    // gives the guest a virtual counter aligned to CLOCK_UPTIME_RAW that does NOT
    // advance through host sleep (trap.rs documents the guest CNTVCT tracks
    // CLOCK_UPTIME_RAW while the raw hardware MRS runs hours ahead after suspend),
    // so the guest's timeline never "suspends" in its own frame. Reading
    // mach_continuous_time (macOS CLOCK_MONOTONIC, suspend-INCLUDING) here made
    // the trapping syscall disagree with the vDSO by the host's accumulated sleep
    // (seconds) — LTP clock_gettime04 reads BOTH paths and sees time travel
    // backwards. Use the SAME suspend-excluding base as monotonic_duration so the
    // two paths agree and BOOTTIME >= MONOTONIC holds (as equality). The Linux
    // branch keeps native CLOCK_BOOTTIME (true suspend-inclusive, time-ns aware).
    #[cfg(not(target_os = "linux"))]
    {
        host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW).unwrap_or_else(monotonic_duration)
    }
}

fn linux_timespec_from_duration(duration: Duration) -> LinuxTimespec {
    LinuxTimespec::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_nanos()),
    )
}

pub(crate) fn complete_interrupted_sleep(
    memory: &mut impl CurrentMmMemory,
    remaining: Option<GuestPtr>,
    duration: Duration,
) -> DispatchOutcome {
    if let Some(address) = remaining {
        let rem = linux_timespec_from_duration(duration);
        match write_kernel_struct(memory, address.0, &rem) {
            DispatchOutcome::Returned { value: 0 } => {}
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EFAULT,
                };
            }
        }
    }
    DispatchOutcome::Errno { errno: LINUX_EINTR }
}

fn linux_timeval_from_duration(duration: Duration) -> LinuxTimeval {
    LinuxTimeval::new(
        duration.as_secs() as i64,
        i64::from(duration.subsec_micros()),
    )
}

fn write_stat_record(
    memory: &mut impl CurrentMmMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let blocks = record
        .blocks
        .map(|b| b as i64)
        .unwrap_or_else(|| blocks_512(size));
    let stat = LinuxStat {
        st_dev: 1,
        st_ino: record.ino,
        st_mode: record.mode,
        st_nlink: record.nlink,
        st_uid: record.uid.raw(),
        st_gid: record.gid.raw(),
        st_rdev: record.rdev,
        __pad1: 0,
        st_size: record.size as i64,
        st_blksize: 4096,
        __pad2: 0,
        st_blocks: blocks,
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

fn write_x8664_stat_record(
    memory: &mut impl CurrentMmMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let blocks = record
        .blocks
        .map(|b| b as i64)
        .unwrap_or_else(|| blocks_512(size));
    let stat = LinuxX8664Stat {
        st_dev: 1,
        st_ino: record.ino,
        st_nlink: record.nlink as u64,
        st_mode: record.mode,
        st_uid: record.uid.raw(),
        st_gid: record.gid.raw(),
        __pad0: 0,
        st_rdev: record.rdev,
        st_size: record.size as i64,
        st_blksize: 4096,
        st_blocks: blocks,
        st_atime: record.atime.0,
        st_atime_nsec: record.atime.1,
        st_mtime: record.mtime.0,
        st_mtime_nsec: record.mtime.1,
        st_ctime: record.ctime.0,
        st_ctime_nsec: record.ctime.1,
        __reserved: [0; 3],
    };

    if write_kernel_struct_raw(memory, statbuf, &stat).is_err() {
        DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

/// Build a [`RealStat`](crate::fs_backend::RealStat) from a live `libc::stat`
/// (e.g. an `fstat` of a host fd) carrying the REAL on-disk values: the true
/// file type (so a symlink stat'd with `AT_SYMLINK_NOFOLLOW` reports S_IFLNK)
/// and the real `st_nlink` (a true hard link reports more than 1). An fd-based
/// stat then reports the SAME real size/kind/times as the path-based
/// `real_stat` that statx/newfstatat use.
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
        uid: carrick_abi::NsUid::ROOT,
        gid: carrick_abi::NsGid::ROOT,
        size: st.st_size as u64,
        blocks: Some(st.st_blocks.max(0) as u64),
        atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
        mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
        ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
    }
}

/// Build and write a `statx` record from a real backing stat.
fn write_statx_real(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    real: &crate::fs_backend::RealStat,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_real(path, real))
}

fn write_statx(
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    metadata: &RootFsMetadata,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::from_metadata(metadata))
}

fn write_statx_record(
    memory: &mut impl CurrentMmMemory,
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
    let blocks = record.blocks.unwrap_or_else(|| blocks_512(size) as u64);
    let statx = LinuxStatx {
        stx_mask: LINUX_STATX_BASIC_STATS,
        stx_blksize: LINUX_PAGE_SIZE as u32,
        stx_attributes: 0,
        stx_nlink: record.nlink,
        stx_uid: record.uid.raw(),
        stx_gid: record.gid.raw(),
        stx_mode: record.mode as u16,
        __spare0: [0; 1],
        stx_ino: record.ino,
        stx_size: record.size,
        stx_blocks: blocks,
        stx_attributes_mask: 0,
        stx_atime: stx_ts(record.atime),
        stx_btime: zero_time,
        stx_ctime: stx_ts(record.ctime),
        stx_mtime: stx_ts(record.mtime),
        stx_rdev_major: linux_dev_major(record.rdev),
        stx_rdev_minor: linux_dev_minor(record.rdev),
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

fn write_synthetic_statx(
    memory: &mut impl CurrentMmMemory,
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
    memory: &mut impl CurrentMmMemory,
    statxbuf: u64,
    path: &str,
    size: usize,
    mode: u32,
) -> DispatchOutcome {
    write_statx_record(memory, statxbuf, &StatRecord::synthetic(path, size, mode))
}

impl SyscallDispatcher {
    fn synthetic_proc_identity(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Option<crate::vfs::SyntheticProcIdentity> {
        Some(()).and_then(|()| {
            let task = context.task();
            let identity = context.kernel().task_identity(task.key().id).ok()?;
            let to_ns = |raw: i32| {
                u32::try_from(raw)
                    .ok()
                    .and_then(|raw| crate::namespace::pid::kernel_to_ns_for(context, raw))
            };
            Some(crate::vfs::SyntheticProcIdentity {
                pid: to_ns(identity.task.id.raw())?,
                tid: to_ns(context.thread().key().tid.raw())?,
                ppid: identity
                    .parent
                    .and_then(|parent| to_ns(parent.id.raw()))
                    .unwrap_or(0),
                pgrp: crate::namespace::pid::process_group_to_ns_for(
                    context,
                    identity.process_group,
                )?,
                session: crate::namespace::pid::session_to_ns_for(context, identity.session)?,
                user_cpu_us: task.self_cpu_us(),
                system_cpu_us: task.self_system_cpu_us(),
            })
        })
    }

    /// Every LIVE Linux process, for the synthetic `/proc/<peer-pid>`
    /// renderers. `None` off the kernel-graph lane, where one Linux process is
    /// one host process and the mature host-process derivation is correct.
    ///
    /// Takes the process binding captured in `synthetic_proc_context` so every
    /// process-owned render field comes from one short mutex snapshot. The
    /// caller releases that mutex before entering MM snapshot authority.
    fn synthetic_proc_processes(
        context: &crate::kernel::KernelContext,
        hvpatch_process: Option<&crate::hvpatch::ProcessContext>,
    ) -> Option<Vec<crate::vfs::SyntheticProcProcess>> {
        let registry = hvpatch_process?.kernel_graph().registry();
        let container = context.container().id();
        let init = context.kernel().container_init(container)?;
        let to_ns = |raw: i32| {
            u32::try_from(raw)
                .ok()
                .and_then(|raw| crate::namespace::pid::kernel_to_ns_for(context, raw))
        };
        let mut processes: Vec<_> = registry
            .live_processes_for_container(container)
            .into_iter()
            .filter_map(|process| {
                let pid = to_ns(process.key.id.raw())?;
                let task_ref = registry.task(process.key.id);
                let (user_cpu_us, system_cpu_us, is_stopped) =
                    task_ref.as_ref().map_or((0, 0, false), |task| {
                        (
                            task.self_cpu_us(),
                            task.self_system_cpu_us(),
                            task.is_job_control_stopped(),
                        )
                    });
                Some(crate::vfs::SyntheticProcProcess {
                    pid,
                    // A parentless task is an orphan reparented to init — except
                    // for init ITSELF, which Linux reports with ppid 0. Without
                    // that case `/proc/1/stat` claims pid 1 is its own parent.
                    ppid: process
                        .parent
                        .and_then(|parent| to_ns(parent.id.raw()))
                        .unwrap_or(if process.key == init { 0 } else { 1 }),
                    pgrp: crate::namespace::pid::process_group_to_ns_for(
                        context,
                        process.process_group,
                    )?,
                    session: crate::namespace::pid::session_to_ns_for(context, process.session)?,
                    // The run-state table is keyed by the LOGICAL task pid on
                    // this lane (`publish_task_thread`), so it is the one live
                    // per-Linux-process state carrick has. A task that has not
                    // published yet reads as runnable, and one already inside
                    // its exit path reads `R` rather than `Z` — it becomes a
                    // zombie only when the registry moves it, which is when the
                    // zombie arm takes over. Stopped tasks query the kernel graph
                    // directly to report 'T'.
                    state: if is_stopped {
                        'T'
                    } else {
                        u32::try_from(process.key.id.raw())
                            .ok()
                            .and_then(crate::run_state::published_stat_char)
                            .unwrap_or('R')
                    },
                    tids: process
                        .tids
                        .iter()
                        .filter_map(|tid| to_ns(tid.raw()))
                        .collect(),
                    // HONEST GAP: this is the registry's fork-time label, not
                    // the Linux `comm`. Linux's is the exec basename as later
                    // amended by `prctl(PR_SET_NAME)`, and carrick keeps that
                    // in the per-process `ProcState.task_name` — which is
                    // reachable only from the process that owns it, so a peer
                    // cannot be asked. The same substitution already ships on
                    // the zombie arm. Closing it means promoting `comm` to a
                    // `Task` field (as `oom_score_adj` was) and retiring
                    // `ProcState.task_name`; identity is fixed first because
                    // it is what LTP and `getpgid`/`getsid` actually read.
                    comm: process.diagnostic_name,
                    user_cpu_us,
                    system_cpu_us,
                })
            })
            .collect();
        processes.sort_by_key(|process| process.pid);
        Some(processes)
    }

    fn synthetic_proc_threads(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
    ) -> Option<Vec<crate::vfs::SyntheticProcThread>> {
        #[cfg(feature = "platform-macos")]
        let states: Option<std::collections::HashMap<_, _>> = registry.map(|r| {
            r.thread_ports()
                .into_iter()
                .filter(|&(_, port)| port != 0)
                .map(|(id, port)| (id, crate::host_proc::thread_run_state_char(port)))
                .collect()
        });
        #[cfg(any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        let states: Option<std::collections::HashMap<_, _>> =
            registry.map(|r| r.thread_state_chars().into_iter().collect());
        let mut threads: Vec<_> = context
            .task()
            .threads()
            .into_iter()
            .map(|thread| {
                let registry_id = thread.registry_id();
                let internal_tid = u32::try_from(thread.key().tid.raw()).ok()?;
                let visible_tid = crate::namespace::pid::kernel_to_ns_for(context, internal_tid)?;
                let comm = registry
                    .and_then(|r| r.thread_name(registry_id))
                    .or_else(|| {
                        carrick_thread::thread::container_thread_name(
                            context.container().id(),
                            registry_id,
                        )
                    })
                    .map(|name| {
                        let len = name
                            .iter()
                            .position(|&byte| byte == 0)
                            .unwrap_or(name.len());
                        String::from_utf8_lossy(&name[..len]).into_owned()
                    });
                let state = thread
                    .linux_run_state()
                    .or_else(|| states.as_ref().and_then(|m| m.get(&registry_id).copied()))
                    .unwrap_or('R');
                Some(crate::vfs::SyntheticProcThread {
                    tid: visible_tid,
                    state,
                    comm,
                    user_cpu_us: thread.cpu_us(),
                    system_cpu_us: thread.system_cpu_us(),
                    processor: thread.last_cpu(),
                    cpus_allowed: thread.affinity(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        threads.sort_by_key(|thread| thread.tid);
        Some(threads)
    }

    fn mem_snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Result<mem::MemState, crate::kernel::SnapshotError> {
        // Select the authority exactly once: the coordinator guard and cloned
        // MemState must belong to one pre- or post-exec MM generation.
        let authority = self.mm_binding.current.load_full();
        let _snapshot = authority
            .mutation_coordinator
            .begin_snapshot_until(deadline)
            .ok_or_else(|| {
                if std::time::Instant::now() >= deadline {
                    crate::kernel::SnapshotError::TimedOut
                } else {
                    crate::kernel::SnapshotError::Busy
                }
            })?;
        let snapshot = authority.mem.lock().clone();
        Ok(snapshot)
    }

    fn mem_snapshot(&self) -> mem::MemState {
        self.mem_snapshot_until(std::time::Instant::now() + std::time::Duration::from_secs(30))
            .unwrap_or_else(|error| {
                tracing::error!(%error, "synthetic proc MemState snapshot timed out");
                carrick_fatal!(
                    "dispatch::mem_snapshot",
                    "synthetic proc MemState snapshot timed out"
                )
            })
    }

    fn synthetic_proc_context(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> crate::vfs::SyntheticProcContext {
        self.synthetic_proc_context_observed(context, || {})
    }

    /// Classify `path` as a synthetic `/proc`/`/sys` file without paying for
    /// the render context unless the path can name one — see
    /// [`crate::vfs::may_be_synthetic_virtual_path`].
    fn is_synthetic_virtual_path(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
    ) -> bool {
        crate::vfs::may_be_synthetic_virtual_path(path)
            && crate::vfs::is_synthetic_virtual_file(path, &self.synthetic_proc_context(context))
    }

    fn synthetic_proc_context_observed(
        &self,
        context: &crate::kernel::KernelContext,
        after_proc_snapshot: impl FnOnce(),
    ) -> crate::vfs::SyntheticProcContext {
        // /proc/<pid>/status renders hex words; escape the typed sets at the
        // render boundary.
        let (sig_ignored, sig_caught, sig_shdpnd) = self.proc_status_signal_masks(context);
        let (sig_ignored, sig_caught, sig_shdpnd) =
            (sig_ignored.raw(), sig_caught.raw(), sig_shdpnd.raw());
        // Snapshot every process-owned render field together, then release the
        // process mutex before entering MM snapshot authority. In-process fork
        // publication holds MM alias authority while cloning this same process
        // state, so retaining `proc` across `mem_snapshot()` would create the
        // exact cycle `proc -> MM snapshot` versus `MM alias -> proc`.
        let (hvpatch_process, executable_path, argv, task_comm, timerslack_ns, guest_arch, environ) = {
            let proc = self.proc.lock();
            (
                proc.hvpatch_process.clone(),
                proc.executable_path.clone(),
                proc.argv.clone(),
                linux_task_name_to_string(&proc.task_name),
                proc.timerslack,
                proc.reported_arch(),
                proc.env.clone(),
            )
        };
        let guest_hostname = context.task().uts_ns().nodename();
        let network_model = context.task().net_ns().view().as_ref().clone();
        after_proc_snapshot();
        let mem = self.mem_snapshot();
        let mut address_space_regions = mem.address_space_regions;
        if !mem.dynamic_maps.is_empty() {
            match &mut address_space_regions {
                Some(regions) => regions.extend(mem.dynamic_maps),
                None => address_space_regions = Some(mem.dynamic_maps),
            }
        }
        let creds = self.cred_snapshot();
        let groups = self.current_groups();
        // Per-process OOM bias comes from the kernel graph, the only authority
        // that can tell two Linux processes apart when both are threads of this
        // one Darwin process. A lane without a kernel graph publishes an empty
        // map and the renderer falls back to its single-host-process cell.
        let oom_score_adj = hvpatch_process
            .as_ref()
            .map(|process| {
                process
                    .kernel_graph()
                    .registry()
                    .oom_score_adj_by_pid_for_container(context.container().id())
                    .into_iter()
                    .filter_map(|(pid, value)| {
                        crate::namespace::pid::kernel_to_ns_for(context, pid)
                            .map(|pid| (pid, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Capabilities and the user-namespace view are the CALLER's own, read
        // straight off its task: unlike `oom_score_adj` these render only for
        // `/proc/self`, so there is no by-pid map to assemble.
        let creds_ns = context.task().creds_ns();
        let processes = Self::synthetic_proc_processes(context, hvpatch_process.as_ref());
        let zombies = hvpatch_process.map(|process| {
            process
                .kernel_graph()
                .registry()
                .zombies_for_container(context.container().id())
                .into_iter()
                .filter_map(|zombie| {
                    let to_ns = |raw: i32| {
                        u32::try_from(raw)
                            .ok()
                            .and_then(|raw| crate::namespace::pid::kernel_to_ns_for(context, raw))
                    };
                    Some(crate::vfs::SyntheticProcZombie {
                        pid: to_ns(zombie.key.id.raw())?,
                        ppid: zombie
                            .parent
                            .and_then(|parent| to_ns(parent.id.raw()))
                            .unwrap_or(1),
                        pgrp: zombie.namespace_process_group,
                        session: zombie.namespace_session,
                        comm: zombie.diagnostic_name,
                        user_cpu_us: u64::try_from(zombie.rusage.user_time.as_micros())
                            .unwrap_or(u64::MAX),
                        system_cpu_us: u64::try_from(zombie.rusage.system_time.as_micros())
                            .unwrap_or(u64::MAX),
                    })
                })
                .collect()
        });
        crate::vfs::SyntheticProcContext {
            executable_path,
            argv,
            task_comm,
            timerslack_ns,
            guest_arch,
            guest_hostname,
            environ,
            open_fds: self.open_fd_numbers(),
            network: self.network.spec.clone(),
            network_model: Some(network_model),
            runtime_endpoint_container: Some(context.container().id()),
            auxv: mem.linux_auxv_image,
            address_space_regions,
            locked_memory: mem.locked_ranges,
            brk_current: mem.brk_current,
            mmap_next: mem.mmap_next,
            heap_base: mem.layout.heap_base,
            native_guest_va: self.page_geometry().native_geometry().is_some(),
            ruid: creds.ruid,
            euid: creds.euid,
            suid: creds.suid,
            rgid: creds.rgid,
            egid: creds.egid,
            sgid: creds.sgid,
            groups,
            sig_ignored,
            sig_caught,
            sig_shdpnd,
            identity: self.synthetic_proc_identity(context),
            oom_score_adj,
            creds_ns,
            processes,
            threads: self.synthetic_proc_threads(context, None),
            zombies,
            sysvipc_shm: self.sysvipc_shm_table(),
            sysvipc_sem: self.sysvipc_sem_table(),
            sysvipc_msg: self.sysvipc_msg_table(),
        }
    }
}

fn read_eventfd(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    length: usize,
    state: &EventFdState,
    semaphore: bool,
    nonblocking: bool,
    authority: WaitFdAuthority,
) -> DispatchOutcome {
    if length < core::mem::size_of::<LinuxEventfdValue>() {
        return DispatchOutcome::Errno {
            errno: LINUX_EINVAL,
        };
    }
    let counter = state.counter_ref();
    loop {
        let current = counter.load(std::sync::atomic::Ordering::SeqCst);
        if current == 0 {
            let host_fd = state.read_fd.as_ref().map(|r| r.raw()).unwrap_or(-1);
            let owner = state.read_fd.clone();
            return would_block_outcome(host_fd, libc::POLLIN, nonblocking, owner, authority);
        }
        let taken = if semaphore { 1 } else { current };
        if counter
            .compare_exchange(
                current,
                current - taken,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            continue; // raced another reader/writer — re-derive
        }
        if current - taken == 0 {
            if let Some(r) = &state.read_fd {
                let mut buf = [0u8; 16];
                // BLOCKING-IO-OK: make_readiness_pipe creates non-blocking pipes with O_NONBLOCK.
                let _ = unsafe { libc::read(r.raw(), buf.as_mut_ptr() as *mut _, buf.len()) };
            }
        }
        let eventfd_value = LinuxEventfdValue {
            value: if semaphore { 1 } else { current },
        };
        if memory
            .write_bytes(address, eventfd_value.as_bytes())
            .is_err()
        {
            // Copyout fault: put the tokens back before surfacing EFAULT.
            counter.fetch_add(taken, std::sync::atomic::Ordering::SeqCst);
            return DispatchOutcome::Errno {
                errno: LINUX_EFAULT,
            };
        }
        crate::event_ring::rec(
            crate::event_ring::EFDREAD,
            -1,
            current as u32 as i32,
            (current - taken) as u32 as i32,
        );
        state.wait_queue.wake_all();
        return DispatchOutcome::returned_len_or_errno(core::mem::size_of::<LinuxEventfdValue>());
    }
}

fn write_eventfd(this: &SyscallDispatcher, bytes: &[u8], state: &EventFdState) -> DispatchOutcome {
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
    let counter = state.counter_ref();
    loop {
        let current = counter.load(std::sync::atomic::Ordering::SeqCst);
        let next = match current.checked_add(increment) {
            // Linux caps the counter at u64::MAX - 1; a write that would
            // exceed it fails EAGAIN (poll's POLLOUT check mirrors this).
            Some(next) if next < u64::MAX => next,
            _ => {
                return DispatchOutcome::Errno {
                    errno: LINUX_EAGAIN,
                };
            }
        };
        if counter
            .compare_exchange(
                current,
                next,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_err()
        {
            continue; // raced another writer/reader — re-derive
        }
        crate::event_ring::rec(
            crate::event_ring::EFDWRITE,
            -1,
            current as u32 as i32,
            next as u32 as i32,
        );
        if current == 0 && next > 0 {
            if let Some(w) = &state.write_fd {
                // BLOCKING-IO-OK: make_readiness_pipe creates non-blocking pipes with O_NONBLOCK.
                let _ = unsafe { libc::write(w.raw(), [1u8].as_ptr() as *const _, 1) };
            }
            this.notify_inmem_epoll();
        }
        state.wait_queue.wake_all();
        return DispatchOutcome::returned_len_or_errno(core::mem::size_of::<LinuxEventfdValue>());
    }
}

fn read_timerfd(
    memory: &mut impl CurrentMmMemory,
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
        let ready = refresh_timerfd_locked(&state.clock, &mut timer);
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
            return DispatchOutcome::returned_len_or_errno(core::mem::size_of::<
                LinuxTimerfdExpirations,
            >());
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
        let Some(now) = linux_clock_duration(&state.clock, timer.clock_id) else {
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

fn refresh_timerfd_locked(
    clock: &crate::kernel::container::ClockDomain,
    timer: &mut TimerFdInner,
) -> u64 {
    let (ready, next_deadline) = timerfd_expirations(
        clock,
        timer.clock_id,
        timer.interval,
        timer.deadline,
        timer.expirations,
    );
    timer.expirations = ready;
    timer.deadline = next_deadline;
    ready
}

pub(in crate::dispatch) fn timerfd_ready_count(state: &TimerFdState) -> u64 {
    let mut timer = state.inner.lock();
    refresh_timerfd_locked(&state.clock, &mut timer)
}

fn timerfd_itimerspec(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
) -> LinuxItimerspec {
    let now = linux_clock_duration(clock, clock_id).unwrap_or(Duration::ZERO);
    let remaining = deadline.map(|deadline| deadline.saturating_sub(now));
    LinuxItimerspec::new(
        linux_timespec_from_optional_duration(interval),
        linux_timespec_from_optional_duration(remaining),
    )
}

fn timerfd_expirations(
    clock: &crate::kernel::container::ClockDomain,
    clock_id: u64,
    interval: Option<Duration>,
    deadline: Option<Duration>,
    expirations: u64,
) -> (u64, Option<Duration>) {
    let Some(deadline) = deadline else {
        return (expirations, None);
    };
    let Some(now) = linux_clock_duration(clock, clock_id) else {
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
) -> Result<(Option<Duration>, Option<Duration>), LinuxErrno> {
    let interval = spec.it_interval;
    let value = spec.it_value;
    Ok((
        duration_from_linux_timespec(interval)?,
        duration_from_linux_timespec(value)?,
    ))
}

fn duration_from_linux_timespec(timespec: LinuxTimespec) -> Result<Option<Duration>, LinuxErrno> {
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

pub(super) fn read_u64(memory: &impl CurrentMmMemory, address: u64) -> Result<u64, LinuxErrno> {
    let mut buf = [0u8; 8];
    memory
        .read_into(address, &mut buf)
        .map_err(|_| LINUX_EFAULT)?;
    Ok(u64::from_ne_bytes(buf))
}

pub(super) fn read_u32(memory: &impl CurrentMmMemory, address: u64) -> Result<u32, LinuxErrno> {
    let mut buf = [0u8; 4];
    memory
        .read_into(address, &mut buf)
        .map_err(|_| LINUX_EFAULT)?;
    Ok(u32::from_ne_bytes(buf))
}

/// Read a futex word, falling back to the fork-coherent shared mapping when the
/// dispatcher's software guest-memory view can't translate the address. A
/// MAP_SHARED semaphore's futex word is reachable in a forked child via the
/// host `__ulock`-keyed shared pointer (the same one the wait/wake paths read)
/// even when the child's software memory view misses the high shared aperture
/// (the guest CPU reaches it through HVF stage-2, but the dispatcher's read
/// does not). Surfacing the read EFAULT instead trips glibc's
/// `futex_fatal_error()` (SIGABRT) on a VALID cross-process futex — observed in
/// CPython multiprocessing SyncManager teardown, where a forked server child's
/// `FUTEX_WAIT_BITSET|CLOCK_REALTIME` on a shared semaphore aborted the process.
pub(super) fn read_futex_word(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<u32, LinuxErrno> {
    match read_u32(memory, address) {
        Ok(word) => Ok(word),
        Err(errno) => match memory.shared_futex_location(address) {
            // SAFETY: a resolved shared host addr points into a live MAP_SHARED
            // region in THIS process — the identical pointer `shared_futex_wait`
            // reads at the wait site. `read_unaligned` avoids assuming stricter
            // alignment than the guest futex ABI's 4-byte guarantee.
            Some(location) => {
                Ok(unsafe { (location.wait_addr().raw() as *const u32).read_unaligned() })
            }
            None => Err(errno),
        },
    }
}

pub(super) fn write_u32(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(address, &value.to_ne_bytes())
        .map_err(|_| LINUX_EFAULT)
}

fn read_itimerspec(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxItimerspec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_itimerval(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<LinuxItimerval, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_timespec(memory: &impl CurrentMmMemory, address: u64) -> Result<LinuxTimespec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_open_how(memory: &impl CurrentMmMemory, address: u64) -> Result<LinuxOpenHow, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_iovecs(
    memory: &impl CurrentMmMemory,
    address: u64,
    count: usize,
) -> Result<Vec<LinuxIovec>, LinuxErrno> {
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
    memory: &mut impl CurrentMmMemory,
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

fn read_from_sparse_buffer_at(
    memory: &mut impl CurrentMmMemory,
    buffer: &crate::vfs::SparseBuffer,
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
        if offset >= buffer.len() {
            break;
        }
        let read_len = iov_len.min(buffer.len().saturating_sub(offset));
        if read_len == 0 {
            break;
        }
        let bytes = buffer.read_range(offset, read_len);
        if memory.write_bytes(iov_base, &bytes).is_err() {
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

fn read_from_synthetic_device_iovecs(
    memory: &mut impl CurrentMmMemory,
    kind: crate::vfs::SyntheticDeviceKind,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut total = 0usize;
    match kind {
        crate::vfs::SyntheticDeviceKind::Null => {}
        crate::vfs::SyntheticDeviceKind::Zero | crate::vfs::SyntheticDeviceKind::Full => {
            for iovec in iovecs {
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                if iov_len == 0 {
                    continue;
                }
                let zeroes = vec![0u8; iov_len];
                if memory.write_bytes(iovec.iov_base, &zeroes).is_err() {
                    return Ok(total);
                }
                total += iov_len;
            }
        }
        crate::vfs::SyntheticDeviceKind::Random | crate::vfs::SyntheticDeviceKind::Urandom => {
            for iovec in iovecs {
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                if iov_len == 0 {
                    continue;
                }
                let mut buf = vec![0u8; iov_len];
                unsafe {
                    libc::arc4random_buf(buf.as_mut_ptr().cast(), iov_len);
                }
                if memory.write_bytes(iovec.iov_base, &buf).is_err() {
                    return Ok(total);
                }
                total += iov_len;
            }
        }
    }
    Ok(total)
}

fn read_from_file_contents_at(
    memory: &mut impl CurrentMmMemory,
    contents: &FileContents,
    mut offset: usize,
    iovecs: &[LinuxIovec],
) -> Result<usize, DispatchError> {
    let mut max_iov_len = 0usize;
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len > max_iov_len {
            max_iov_len = iov_len;
        }
    }
    if max_iov_len == 0 {
        return Ok(0);
    }
    let mut scratch = vec![0u8; max_iov_len];
    let mut total = 0usize;
    for iovec in iovecs {
        let iov_base = iovec.iov_base;
        let iov_len = usize::try_from(iovec.iov_len)
            .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
        if iov_len == 0 {
            continue;
        }
        let buf = &mut scratch[..iov_len];
        match contents.read_at(offset as u64, buf) {
            Ok(0) => break,
            Ok(read_len) => {
                if memory.write_bytes(iov_base, &buf[..read_len]).is_err() {
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
            Err(errno) => {
                if total > 0 {
                    return Ok(total);
                }
                return Err(DispatchError::Errno(errno));
            }
        }
    }
    Ok(total)
}

/// Decode the major number from a raw Linux `dev_t` (the glibc `gnu_dev_major`
/// encoding documented in makedev(3)): the major occupies bits 8..20 and 32..64,
/// the minor bits 0..8 and 20..64 (interleaved so a 32-bit dev_t stays
/// compatible). `stat`/`mknod` carry the raw `dev_t` verbatim; only `statx`
/// reports the split fields, so the decode lives here. Clean-room from the man
/// page, not glibc source.
fn linux_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

/// Decode the minor number from a raw Linux `dev_t` (see `linux_dev_major`).
fn linux_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
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
/// guest-memory watchpoint. Compile-gated behind `watchpoint`; the whole
/// facility (env read + per-syscall probe) is absent from a stock build.
#[cfg(feature = "watchpoint")]
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
    if carrick_abi::LinuxAccessMode::from_bits_truncate(mode)
        .contains(carrick_abi::LinuxAccessMode::X_OK)
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
    uid: carrick_abi::NsUid,
    gid: carrick_abi::NsGid,
    file_uid: carrick_abi::NsUid,
    file_gid: carrick_abi::NsGid,
    file_mode: u32,
    is_dir: bool,
    mask: u64,
) -> Result<(), LinuxErrno> {
    let access_mode = carrick_abi::LinuxAccessMode::from_bits_truncate(mask);
    let need = (if access_mode.contains(carrick_abi::LinuxAccessMode::R_OK) {
        4
    } else {
        0
    }) | (if access_mode.contains(carrick_abi::LinuxAccessMode::W_OK) {
        2
    } else {
        0
    }) | (if access_mode.contains(carrick_abi::LinuxAccessMode::X_OK) {
        1
    } else {
        0
    });
    if need == 0 {
        return Ok(());
    }
    if uid.is_root() {
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
    synthetic_readonly_access_with_errno(mode, LINUX_EACCES)
}

fn synthetic_readonly_access_with_errno(mode: u64, write_errno: LinuxErrno) -> DispatchOutcome {
    if carrick_abi::LinuxAccessMode::from_bits_truncate(mode)
        .contains(carrick_abi::LinuxAccessMode::W_OK)
    {
        DispatchOutcome::Errno { errno: write_errno }
    } else {
        DispatchOutcome::Returned { value: 0 }
    }
}

pub(super) fn blocks_512(size: usize) -> i64 {
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
        // Real host inode when known, so scandir's DirEntry.inode() matches a
        // later stat()'s st_ino; else a stable path-hash (in-memory/synthetic).
        d_ino: if entry.ino != 0 {
            entry.ino
        } else {
            inode_for_path(&entry.metadata.path)
        },
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

pub fn rootfs_errno(error: RootFsError) -> LinuxErrno {
    match error {
        RootFsError::NotFound(_) => LINUX_ENOENT,
        RootFsError::UnsafePath(_) | RootFsError::Utf8(_) | RootFsError::TooManySymlinks(_) => {
            LINUX_EINVAL
        }
        RootFsError::DirectoryTooLarge(_) => LINUX_E2BIG,
        RootFsError::Io(_) => LINUX_EINVAL,
    }
}

/// Futex operations carrick implements. An operation outside this set is
/// ENOSYS -- "this op does not exist" -- which Linux distinguishes from the
/// EINVAL it gives a malformed call (`eventwaitmatrix`
/// `futex_invalid_op_enosys`).
pub(crate) fn linux_futex_command_is_known(command: u64) -> bool {
    matches!(
        command,
        LINUX_FUTEX_WAIT
            | LINUX_FUTEX_WAKE
            | LINUX_FUTEX_REQUEUE
            | LINUX_FUTEX_CMP_REQUEUE
            | LINUX_FUTEX_LOCK_PI
            | LINUX_FUTEX_UNLOCK_PI
            | LINUX_FUTEX_TRYLOCK_PI
            | LINUX_FUTEX_WAIT_BITSET
            | LINUX_FUTEX_WAKE_BITSET
    )
}

/// A `struct timespec` used as a syscall TIMEOUT: non-negative seconds and
/// `tv_nsec` in `[0, 1e9)`. Linux answers EINVAL otherwise, before it waits.
///
/// `ppoll` accepted both a negative `tv_nsec` and one at or past a full second
/// and silently folded them into a millisecond count, so a request Linux
/// rejects outright became a long sleep (`eventwaitmatrix`
/// `ppoll_negative_nsec_einval` / `ppoll_overflow_nsec_einval`).
pub(crate) fn linux_timeout_timespec_is_valid(timespec: LinuxTimespec) -> bool {
    // Copied out: `LinuxTimespec` is packed, so a reference to a field would
    // be unaligned.
    let (tv_sec, tv_nsec) = (timespec.tv_sec, timespec.tv_nsec);
    tv_sec >= 0 && (0..1_000_000_000).contains(&tv_nsec)
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
fn resolve_utimensat_timespec(
    clock: &crate::kernel::container::ClockDomain,
    timespec: LinuxTimespec,
) -> Option<(i64, i64)> {
    // Copy out of the packed struct before matching (taking a reference to
    // a packed field is UB).
    let nsec = timespec.tv_nsec;
    let sec = timespec.tv_sec;
    if nsec == LINUX_UTIME_OMIT {
        None
    } else if nsec == LINUX_UTIME_NOW {
        Some(now_realtime_timespec(clock))
    } else {
        Some((sec, nsec))
    }
}

/// The guest's current CLOCK_REALTIME as a (sec, nsec) pair, for UTIME_NOW /
/// NULL times.
fn now_realtime_timespec(clock: &crate::kernel::container::ClockDomain) -> (i64, i64) {
    let now = clock.realtime_now();
    (now.as_secs() as i64, i64::from(now.subsec_nanos()))
}

/// Read a NULL-terminated array of guest VA pointers, dereferencing each to a
/// C string as RAW BYTES — for `argv` / `envp` in `execve(2)`, which Linux
/// treats as opaque byte strings (NOT UTF-8). See [`read_guest_c_string_bytes`].
fn read_guest_string_array_bytes(
    memory: &impl CurrentMmMemory,
    array_addr: u64,
) -> Result<Vec<Vec<u8>>, LinuxErrno> {
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

fn validate_exec_vector_size(argv: &[Vec<u8>], env: &[Vec<u8>]) -> Result<(), LinuxErrno> {
    let pointer_bytes = argv
        .len()
        .checked_add(env.len())
        .and_then(|count| count.checked_add(2))
        .and_then(|count| count.checked_mul(std::mem::size_of::<u64>()))
        .ok_or(LINUX_E2BIG)?;
    let total = argv
        .iter()
        .chain(env)
        .try_fold(pointer_bytes, |total, item| {
            item.len()
                .checked_add(1)
                .and_then(|item_len| total.checked_add(item_len))
        })
        .ok_or(LINUX_E2BIG)?;
    if total > crate::linux_abi::LINUX_ARG_MAX {
        return Err(LINUX_E2BIG);
    }
    Ok(())
}

#[cfg(test)]
mod exec_vector_tests {
    use super::*;

    #[test]
    fn exec_vector_rejects_payload_beyond_linux_arg_max() {
        let allowed = vec![vec![b'x'; crate::linux_abi::LINUX_ARG_MAX - 32]];
        assert!(validate_exec_vector_size(&allowed, &[]).is_ok());

        let oversized = vec![vec![b'x'; crate::linux_abi::LINUX_ARG_MAX]];
        assert_eq!(validate_exec_vector_size(&oversized, &[]), Err(LINUX_E2BIG));
    }
}

/// Adapter from the VFS-trait [`Metadata`](crate::vfs::Metadata) back to
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
    /// The HOST errno as read from the host libc — NOT a Linux errno.
    raw_errno: i32,
    linux_errno: LinuxErrno,
}

impl HostSyscallError {
    pub(crate) fn last() -> Self {
        let raw_errno = carrick_portable::errno();

        Self {
            raw_errno,
            linux_errno: crate::host_to_linux_errno(raw_errno),
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn raw_errno(self) -> i32 {
        self.raw_errno
    }

    pub(crate) fn linux_errno(self) -> LinuxErrno {
        self.linux_errno
    }
}

pub(crate) trait HostSyscallResult: Sized {
    fn host_syscall_result(self) -> Result<Self, HostSyscallError>;

    fn host_syscall_errno(self) -> Result<Self, LinuxErrno> {
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
// ----- BSD socket translation helpers ------------------------------------

// ----- AF_NETLINK (rtnetlink) synthesis -----------------------------------

/// Linux `NLMSG_ALIGNTO` — netlink messages and attributes are 4-byte aligned.
const NLMSG_ALIGNTO: usize = 4;

/// Linux clamps a single read/recv/getrandom transfer to MAX_RW_COUNT (INT_MAX
/// rounded down to a page) and returns a short count; it never allocates the
/// caller's raw count. carrick stages guest reads into a host Vec, so without
/// this clamp a huge guest count is an immediate multi-terabyte allocation that
/// aborts the whole runtime (a one-syscall DoS). Probe: `bigread`.
pub(crate) const MAX_RW_COUNT: usize = 0x7fff_f000;
const SMALL_HOST_READ_BUF: usize = 8192;

/// read(2) on a host-backed fd (pipe/socket/file). Host-backed descriptions are
/// adopted non-blocking at creation time, so EAGAIN means a blocking-mode guest
/// fd hands off to the runtime's lockless kqueue wait via WaitOnFds while a
/// non-blocking guest fd gets EAGAIN. Never blocks under the dispatcher lock.
/// `nonblocking` is the guest's intended mode (status_flags / O_NONBLOCK).
fn read_host_pipe_into(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    host_fd: i32,
    host_fd_owner: Option<HostFdRef>,
    nonblocking: bool,
    buf: &mut [u8],
    authority: WaitFdAuthority,
) -> DispatchOutcome {
    // BLOCKING-IO-OK: host-backed descriptions are made O_NONBLOCK at creation
    // or adoption sites; EAGAIN becomes WaitOnFds for blocking guest fds.
    let n = unsafe { libc::read(host_fd, buf.as_mut_ptr() as *mut _, buf.len()) };
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
            return would_block_outcome(
                host_fd,
                libc::POLLIN,
                nonblocking,
                host_fd_owner,
                authority,
            );
        }
        return DispatchOutcome::Errno { errno: e };
    }
    let n_usize = n as usize;
    #[cfg(feature = "trace-io")]
    if n_usize > 0 {
        // Offset the read STARTED at. Without it a buffer beginning with an
        // `ar` member header is ambiguous: normal at a nonzero offset, corrupt
        // at 0. The read has already advanced the description, so subtract.
        let start = fs::host_fd_offset(HostFd(host_fd))
            .map(|end| end.saturating_sub(n_usize as u64))
            .map_or_else(|| "?".to_owned(), |start| start.to_string());
        eprintln!(
            "[IODBG] READ host_fd={host_fd} off={start} n={n_usize} bytes={:02x?}",
            &buf[..n_usize.min(64)]
        );
    }
    if n_usize > 0 && memory.write_bytes(guest_addr, &buf[..n_usize]).is_err() {
        return DispatchOutcome::Errno {
            errno: LINUX_EFAULT,
        };
    }
    DispatchOutcome::returned_isize_or_errno(n)
}

fn read_host_pipe(
    memory: &mut impl CurrentMmMemory,
    guest_addr: u64,
    length: usize,
    host_fd: i32,
    host_fd_owner: Option<HostFdRef>,
    nonblocking: bool,
    authority: WaitFdAuthority,
) -> DispatchOutcome {
    if length == 0 {
        return DispatchOutcome::Returned { value: 0 };
    }
    // Clamp to Linux's MAX_RW_COUNT before staging a host buffer; a huge guest
    // count would otherwise be a one-syscall OOM-abort of the runtime.
    let length = length.min(MAX_RW_COUNT);
    if length <= SMALL_HOST_READ_BUF {
        let mut buf = [0u8; SMALL_HOST_READ_BUF];
        read_host_pipe_into(
            memory,
            guest_addr,
            host_fd,
            host_fd_owner,
            nonblocking,
            &mut buf[..length],
            authority,
        )
    } else {
        let mut buf = vec![0u8; length];
        read_host_pipe_into(
            memory,
            guest_addr,
            host_fd,
            host_fd_owner,
            nonblocking,
            &mut buf,
            authority,
        )
    }
}

enum HostWritePayload<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

#[derive(Clone)]
struct HostPipeWriteTarget {
    host_fd: i32,
    host_fd_owner: Option<HostFdRef>,
    nonblocking: bool,
    write_kind: HostWriteKind,
    pipe_state: Option<(i64, usize)>,
    tid: crate::thread::ThreadId,
    sigpipe_on_epipe: bool,
    authority: WaitFdAuthority,
}

impl<'a> HostWritePayload<'a> {
    fn as_slice(&self) -> &[u8] {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes,
            HostWritePayload::Owned(bytes) => bytes,
        }
    }

    fn into_owned(self) -> Vec<u8> {
        match self {
            HostWritePayload::Borrowed(bytes) => bytes.to_vec(),
            HostWritePayload::Owned(bytes) => bytes,
        }
    }
}

/// write(2) on a host-backed fd. Same lockless discipline as `read_host_pipe`.
/// Host fds that have received an `ar` archive magic write, with the length
/// written and a monotonic sequence number.
///
/// Only touched on the two rare archive predicates (roughly 67 magic writes in
/// a whole cold `go build`), never on the ordinary write path. Its sole
/// purpose is to answer, when a member header is caught being written at
/// offset 0, whether that same description had previously received the magic.
static AR_MAGIC_WRITES: std::sync::LazyLock<parking_lot::Mutex<HashMap<i32, (usize, u64)>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));
static AR_MAGIC_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_ar_magic_write(host_fd: i32, length: usize) {
    let seq = AR_MAGIC_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    AR_MAGIC_WRITES.lock().insert(host_fd, (length, seq));
}

/// `(length, sequence)` of the last magic write seen on `host_fd`, if any.
fn prior_ar_magic_write(host_fd: i32) -> Option<(usize, u64)> {
    AR_MAGIC_WRITES.lock().get(&host_fd).copied()
}

fn write_host_pipe(bytes: &[u8], target: HostPipeWriteTarget) -> DispatchOutcome {
    write_host_pipe_payload(HostWritePayload::Borrowed(bytes), target)
}

fn write_host_pipe_owned(bytes: Vec<u8>, target: HostPipeWriteTarget) -> DispatchOutcome {
    write_host_pipe_payload(HostWritePayload::Owned(bytes), target)
}

fn host_pipe_write_room(capacity: i64, queued: usize) -> Option<usize> {
    let capacity = usize::try_from(capacity).ok()?;
    Some(capacity.saturating_sub(queued))
}

fn write_host_pipe_payload(
    payload: HostWritePayload<'_>,
    target: HostPipeWriteTarget,
) -> DispatchOutcome {
    let HostPipeWriteTarget {
        host_fd,
        host_fd_owner,
        nonblocking,
        write_kind,
        pipe_state,
        tid,
        sigpipe_on_epipe,
        authority,
    } = target;

    // Always-on, near-zero-cost detector for archive corruption. The predicate
    // is a byte compare on the payload head; only a match pays the `lseek`.
    // See `event_ring::ARWRITE` for why this is not in the `trace-io` log.
    // Correlate the magic write with the member write that should follow it on
    // the same description: if both land on one host fd the magic write was
    // lost or rewound, and if they land on different fds the description was
    // swapped underneath the guest. This is NORMAL traffic — roughly 67 writes
    // per cold `go build` — so it goes to the lock-free ring only. Logging it
    // would be debug spam on a healthy run, and the per-write cost is what
    // made `trace-io` perturb this bug out of existence.
    if crate::event_ring::payload_starts_at_ar_magic(payload.as_slice()) {
        let offset = fs::host_fd_offset(HostFd(host_fd)).map_or(-1, |offset| offset as u32 as i32);
        crate::event_ring::rec(
            crate::event_ring::ARMAGIC,
            host_fd,
            offset,
            payload.as_slice().len() as u32 as i32,
        );
        note_ar_magic_write(host_fd, payload.as_slice().len());
    }
    if crate::event_ring::payload_starts_at_ar_member_header(payload.as_slice()) {
        let offset = fs::host_fd_offset(HostFd(host_fd));
        crate::event_ring::rec(
            crate::event_ring::ARWRITE,
            host_fd,
            offset.map_or(-1, |offset| offset as u32 as i32),
            payload.as_slice().len() as u32 as i32,
        );
        // Offset 0 means the archive magic is being skipped: the file will not
        // be a valid `ar` archive. Report it once, at the moment it happens.
        // This is a genuine data-corruption event, not trace output — it fires
        // at most a handful of times in a whole build, so it cannot perturb
        // timing the way a per-I/O log does.
        if offset == Some(0) {
            // Did THIS description ever receive the magic? The answer picks the
            // fix: "never" means the magic write went to a different host fd,
            // i.e. the description was swapped underneath the guest; "yes"
            // means it reached this fd and the offset was then lost or rewound.
            let prior_magic = prior_ar_magic_write(host_fd);
            tracing::error!(
                target: "carrick::dispatch::fs",
                host_fd,
                length = payload.as_slice().len(),
                ?prior_magic,
                "ar member header written at offset 0; the archive will lack its magic"
            );
        }
    }

    #[cfg(feature = "trace-io")]
    if !payload.as_slice().is_empty() {
        let bytes = payload.as_slice();
        // Offset the write will START at, captured before it advances the
        // description. A buffer beginning with an `ar` member header is normal
        // at a nonzero offset and corrupt at 0.
        let start = fs::host_fd_offset(HostFd(host_fd))
            .map_or_else(|| "?".to_owned(), |start| start.to_string());
        eprintln!(
            "[IODBG] WRITE host_fd={host_fd} off={start} n={} bytes={:02x?}",
            bytes.len(),
            &bytes[..bytes.len().min(64)]
        );
    }
    // A blocking large pipe write may make partial progress before the host fd
    // reports EAGAIN. At that point we cannot re-dispatch the original syscall
    // (it would re-send the written prefix), but we also cannot park inside the
    // dispatcher because a sibling guest thread may be the reader/closer needed
    // to unblock this write. Hand the staged bytes to the runtime so it can wait
    // with dispatcher progress released.
    let block_until_complete = !nonblocking && write_kind == HostWriteKind::PipeLike;
    let mut offset = 0usize;
    loop {
        #[cfg(feature = "trace-tty")]
        if payload.as_slice().contains(&0x0a) {
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
                let blen = payload.as_slice().len();
                eprintln!(
                    "[TTYDBG-PRE] host_fd={host_fd} isatty={isatty} tg={tg} oflag=0x{oflag:x} lflag=0x{lflag:x} outq={outq} flags=0x{fl:x} rdev={rdev} n={blen}"
                );
            }
        }
        // host_fd was made O_NONBLOCK when adopted; an EAGAIN here routes
        // through would_block_outcome / wait_pipe_writable, which park with the
        // dispatcher lock released. BLOCKING-IO-OK: non-blocking by
        // construction, the lock is never held across a blocking write.
        let n = {
            let bytes = payload.as_slice();
            let mut len = bytes.len() - offset;
            if write_kind == HostWriteKind::PipeLike
                && let Some((capacity, queued)) = pipe_state
                && let Some(room) = host_pipe_write_room(capacity, queued.saturating_add(offset))
            {
                if room == 0 {
                    // A blocking pipe write that already made partial progress
                    // (offset > 0) must RESUME from `offset` — re-dispatching the
                    // guest write(2) from 0 (what would_block_outcome does) would
                    // re-send the delivered prefix and duplicate every byte past
                    // the first pipe-full (corrupting any >64 KiB stream, e.g.
                    // dpkg's data.tar). Hand the staged bytes to the runtime the
                    // same way the EAGAIN branch does.
                    if block_until_complete && offset > 0 {
                        if crate::host_signal::has_unblocked_pending_for(
                            tid.raw(),
                            carrick_abi::SigBlockMask::NONE,
                        ) {
                            return DispatchOutcome::returned_len_or_errno(offset);
                        }
                        return match BlockingHostWrite::from_vec(
                            host_fd,
                            payload.into_owned(),
                            offset,
                            tid,
                            sigpipe_on_epipe,
                        ) {
                            Ok(write) => DispatchOutcome::BlockingHostWrite(write),
                            Err(_) => DispatchOutcome::returned_len_or_errno(offset),
                        };
                    }
                    return would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                        authority.clone(),
                    );
                }
                if nonblocking && offset == 0 && len <= 4096 && len > room {
                    return would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                        authority.clone(),
                    );
                }
                len = len.min(room);
            }
            // BLOCKING-IO-OK: host_fd was adopted O_NONBLOCK; EAGAIN routes to
            // the lockless wait path below.
            unsafe { libc::write(host_fd, bytes[offset..].as_ptr() as *const _, len) }
        };
        #[cfg(feature = "trace-tty")]
        if payload.as_slice().contains(&0x0a) {
            unsafe {
                let mut outq: libc::c_int = -1;
                libc::ioctl(host_fd, libc::TIOCOUTQ, &mut outq);
                eprintln!("[TTYDBG-POST] host_fd={host_fd} wrote={n} outq_after={outq}");
            }
        }
        crate::probes::host_pipe_io(host_fd, 1, n as i64);
        if let Err(e) = n.host_syscall_errno() {
            // FreeBSD's AF_UNIX (notably DGRAM) write returns ENOBUFS when the peer
            // receive buffer is full; Linux reports EAGAIN for a non-blocking socket
            // that can't proceed (and blocks a blocking one until it drains). LTP
            // sendfile07 fills an out_fd socket buffer in a loop, treating EAGAIN as
            // "full, stop" but ENOBUFS as a hard setup error. Route a socket-write
            // ENOBUFS through the same readiness path as EAGAIN (EAGAIN if
            // non-blocking, else park on POLLOUT). No-op on Linux, which uses EAGAIN.
            #[cfg(not(target_os = "linux"))]
            if e == crate::linux_abi::LINUX_ENOBUFS && write_kind == HostWriteKind::SocketLike {
                return would_block_outcome(
                    host_fd,
                    libc::POLLOUT,
                    nonblocking,
                    host_fd_owner.clone(),
                    authority.clone(),
                );
            }
            // EINTR: interrupted by an internal host signal (e.g. SIGURG vCPU kick).
            // Route through the readiness wait rather than leaking it to the guest
            // (see read_host_pipe).
            if e == LINUX_EAGAIN || e == LINUX_EINTR {
                if e == LINUX_EAGAIN
                    && nonblocking
                    && offset == 0
                    && write_kind != HostWriteKind::RegularFile
                    && let Some(result) = try_small_nonblocking_write(host_fd, payload.as_slice())
                {
                    return match result {
                        Ok(written) => DispatchOutcome::returned_len_or_errno(written),
                        Err(errno) => DispatchOutcome::Errno { errno },
                    };
                }
                if block_until_complete && offset > 0 {
                    if crate::host_signal::has_unblocked_pending_for(
                        tid.raw(),
                        carrick_abi::SigBlockMask::NONE,
                    ) {
                        return DispatchOutcome::returned_len_or_errno(offset);
                    }
                    return match BlockingHostWrite::from_vec(
                        host_fd,
                        payload.into_owned(),
                        offset,
                        tid,
                        sigpipe_on_epipe,
                    ) {
                        Ok(write) => DispatchOutcome::BlockingHostWrite(write),
                        Err(_) => DispatchOutcome::returned_len_or_errno(offset),
                    };
                }
                return would_block_outcome(
                    host_fd,
                    libc::POLLOUT,
                    nonblocking,
                    host_fd_owner.clone(),
                    authority.clone(),
                );
            }
            return DispatchOutcome::Errno { errno: e };
        }
        if block_until_complete {
            offset += n as usize;
            if offset < payload.as_slice().len() {
                // A signal that arrives mid-write interrupts it on Linux,
                // returning the partial count; check between chunks so a long
                // write doesn't ignore an armed alarm (or a pending quiesce).
                if crate::host_signal::has_unblocked_pending_for(
                    tid.raw(),
                    carrick_abi::SigBlockMask::NONE,
                ) || crate::fork_quiesce::is_quiescing()
                {
                    if crate::fork_quiesce::is_quiescing() {
                        return match BlockingHostWrite::from_vec(
                            host_fd,
                            payload.into_owned(),
                            offset,
                            tid,
                            sigpipe_on_epipe,
                        ) {
                            Ok(write) => DispatchOutcome::BlockingHostWrite(write),
                            Err(_) => DispatchOutcome::returned_len_or_errno(offset),
                        };
                    }
                    return DispatchOutcome::returned_len_or_errno(offset);
                }
                continue;
            }
            return DispatchOutcome::returned_len_or_errno(payload.as_slice().len());
        }
        return DispatchOutcome::returned_isize_or_errno(n);
    }
}

fn try_small_nonblocking_write(host_fd: i32, bytes: &[u8]) -> Option<Result<usize, LinuxErrno>> {
    if bytes.len() <= 1 {
        return None;
    }
    const RETRIES: [usize; 6] = [16 * 1024, 4 * 1024, 1024, 256, 64, 1];
    for cap in RETRIES {
        let len = bytes.len().min(cap);
        if len == 0 || len == bytes.len() {
            continue;
        }
        // BLOCKING-IO-OK: this path is reached only after a prior write to the
        // same fd returned EAGAIN (see the caller's `e == LINUX_EAGAIN &&
        // nonblocking` guard), so host_fd is non-blocking and libc::write cannot
        // block — the loop treats EAGAIN as "retry a smaller chunk".
        let n = unsafe { libc::write(host_fd, bytes.as_ptr().cast(), len) };
        match n.host_syscall_errno() {
            Ok(value) if value > 0 => return Some(Ok(value as usize)),
            Ok(_) => continue,
            Err(errno) if errno == LINUX_EAGAIN || errno == LINUX_EINTR => continue,
            Err(errno) => return Some(Err(errno)),
        }
    }
    None
}

/// A host op returned EAGAIN: a non-blocking guest fd gets EAGAIN; a blocking
/// one gets a WaitOnFds hand-off so the runtime waits on readiness with the
/// dispatcher lock RELEASED (per-thread kqueue), then re-dispatches.
fn would_block_outcome(
    host_fd: i32,
    events: i16,
    nonblocking: bool,
    host_fd_owner: Option<HostFdRef>,
    authority: WaitFdAuthority,
) -> DispatchOutcome {
    if nonblocking {
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        }
    } else {
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::anchored_one(host_fd, events, host_fd_owner).with_authority(authority),
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Fd {
                on_timeout: LINUX_EAGAIN.guest_retval(),
            },
        }
    }
}

/// Read a NUL-terminated C string from guest memory as RAW BYTES. Linux paths/
/// argv/env are OPAQUE byte strings, not UTF-8 — e.g. CPython's regrtest sets a
/// non-UTF-8 `PYTHONREGRTEST_UNICODE_GUARD` env var, which made an execve EINVAL
/// when carrick required UTF-8. The execve argv/env path keeps these bytes
/// verbatim; callers needing a Rust `String` (fs path lookup) use the wrapper.
fn read_guest_c_string_bytes(
    memory: &impl CurrentMmMemory,
    address: u64,
) -> Result<Vec<u8>, LinuxErrno> {
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
fn read_guest_c_string(memory: &impl CurrentMmMemory, address: u64) -> Result<String, LinuxErrno> {
    Ok(crate::pathcodec::encode_bytes(&read_guest_c_string_bytes(
        memory, address,
    )?))
}

#[cfg(test)]
mod routing_tests {
    //! Characterization test for the per-module syscall routing refactor
    //! (Task A1). `ROUTED_NUMBERS` is the COMPLETE set of syscall numbers the
    //! dispatcher routed at the start of the refactor — every arm of the
    //! original central `normalized_dispatch!` table, with multi-number arms
    //! expanded and the carrick-private x86 numbers included by their constant
    //! values. The refactor moves these arms out of the central table and into
    //! each dispatch module's own `dispatch_<area>` routing fn; chaining those
    //! fns must keep routing IDENTICAL. `resolves(n)` must hold for every
    //! number here at every step, and a known-unrouted number must NOT resolve.
    use super::*;
    use crate::linux_abi::{
        CARRICK_PRIVATE_X86_ALARM, CARRICK_PRIVATE_X86_DUP2, CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT, CARRICK_PRIVATE_X86_NEWFSTATAT, CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT, CARRICK_PRIVATE_X86_STAT, CARRICK_PRIVATE_X86_TIME,
    };

    /// Every syscall number routed by the dispatcher, enumerated from the full
    /// original routing table (multi-number arms expanded). If the refactor
    /// drops or re-routes any number, the membership assertion below fails.
    const ROUTED_NUMBERS: &[u64] = &[
        // --- fs ---
        17,
        23,
        24,
        CARRICK_PRIVATE_X86_DUP2,
        CARRICK_PRIVATE_X86_STAT,
        CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT,
        CARRICK_PRIVATE_X86_NEWFSTATAT,
        25,
        26,
        27,
        28,
        29,
        32,
        33,
        46,
        47,
        48,
        34,
        35,
        36,
        37,
        38,
        49,
        50,
        52,
        53,
        452,
        54,
        55,
        56,
        57,
        59,
        61,
        62,
        63,
        64,
        65,
        66,
        67,
        68,
        69,
        70,
        71,
        76,
        78,
        79,
        80,
        81,
        82,
        83,
        88,
        267,
        84,
        451,
        276,
        279,
        285,
        286,
        287,
        291,
        436,
        437,
        439,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        43,
        44,
        45,
        75,
        77,
        // --- net ---
        19,
        20,
        21,
        22,
        CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT,
        72,
        73,
        198,
        199,
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        209,
        210,
        211,
        212,
        242,
        243,
        269,
        // --- mem ---
        214,
        215,
        216,
        222,
        223,
        226,
        227,
        228,
        229,
        230,
        231,
        232,
        233,
        425,
        426,
        427,
        283,
        // --- proc ---
        30,
        31,
        58,
        92,
        95,
        96,
        97,
        98,
        99,
        100,
        117,
        118,
        119,
        120,
        121,
        122,
        123,
        124,
        125,
        126,
        127,
        142,
        154,
        155,
        156,
        157,
        160,
        161,
        162,
        167,
        168,
        220,
        221,
        281,
        260,
        277,
        275,
        278,
        424,
        434,
        93,
        94,
        178,
        435,
        293,
        // --- signal ---
        74,
        129,
        130,
        131,
        132,
        133,
        134,
        135,
        136,
        137,
        138,
        139,
        240,
        // --- time ---
        85,
        86,
        87,
        101,
        102,
        103,
        107,
        108,
        109,
        110,
        111,
        112,
        113,
        114,
        115,
        CARRICK_PRIVATE_X86_ALARM,
        CARRICK_PRIVATE_X86_TIME,
        153,
        163,
        165,
        169,
        170,
        171,
        179,
        261,
        266,
        // --- creds ---
        90,
        91,
        140,
        141,
        143,
        144,
        145,
        146,
        147,
        148,
        149,
        150,
        158,
        166,
        151,
        152,
        159,
        172,
        173,
        174,
        175,
        176,
        177,
        // --- sysv ---
        186,
        187,
        188,
        189,
        190,
        191,
        192,
        193,
        194,
        195,
        196,
        197,
    ];

    #[test]
    fn dispatcher_activates_one_authenticated_file_authority_root() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        assert_eq!(dispatcher.file_authority_binding(), None);
        let binding = dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");
        assert_eq!(binding.epoch.raw(), 1);
        assert_eq!(binding.client.id.raw(), 1);
        assert_eq!(
            binding.generation,
            crate::file_authority::ObjectGeneration::INITIAL
        );
        assert_eq!(
            dispatcher
                .activate_file_authority(Arc::clone(&root_table))
                .expect("idempotent FileAuthority activation"),
            binding
        );
        assert_eq!(dispatcher.file_authority_binding(), Some(binding));

        // Different Arc with same table ID is fatal
        let foreign_table_same_id = Arc::new(crate::kernel::FileTable::new(root_table.id()));
        let res = dispatcher.activate_file_authority(foreign_table_same_id);
        assert!(matches!(
            res,
            Err(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));

        // Different Arc with different table ID is fatal
        let ids = crate::kernel::ObjectIdRegistry::new();
        let foreign_table = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table id"),
        ));
        let res = dispatcher.activate_file_authority(foreign_table);
        assert!(matches!(
            res,
            Err(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));

        // Dropping all external strong Arcs allows the root table to be dropped
        let weak = Arc::downgrade(&root_table);
        drop(root_table);
        // Note: dispatcher's one_task kernel context also holds a strong reference in its initial state,
        // so if we drop the dispatcher context or check the weak reference when only dispatcher holds it:
        assert_eq!(weak.strong_count(), 1); // Only the dispatcher's captured one-task kernel context
    }

    #[test]
    fn authority_call_operates_on_successor_table_without_launch_root_comparison() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");

        let ids = crate::kernel::ObjectIdRegistry::new();
        let successor_table = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table id"),
        ));
        let number = crate::kernel::FileSlotNumber::for_open_fd(3).expect("fd");
        let fixture = crate::dispatch::fd_table::InMemoryPipeTestFixture::new(10, 65536);
        successor_table.install(number, fixture.read, false);
        let slot = successor_table
            .capture_slot_authority(number)
            .expect("slot token");

        let command = crate::file_authority::Command::SetCanonicalPipeCapacity {
            slot,
            capacity: crate::file_authority::PipeCapacity::bounded(65536).expect("capacity"),
            accounting: crate::kernel::objects::PipeCapacityAccounting::InMemory,
        };

        let outcome = dispatcher
            .authority_call(successor_table, slot, command)
            .expect("authority call on successor table");
        assert!(matches!(
            outcome,
            crate::file_authority::Outcome::CanonicalPipeCapacitySet { .. }
        ));
    }

    #[test]
    fn authority_call_rejects_table_id_mismatch_as_fatal() {
        let dispatcher = SyscallDispatcher::new();
        let root_table = dispatcher.captured_file_table();
        dispatcher
            .activate_file_authority(Arc::clone(&root_table))
            .expect("activate FileAuthority");

        let ids = crate::kernel::ObjectIdRegistry::new();
        let table_a = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table a id"),
        ));
        let table_b = Arc::new(crate::kernel::FileTable::new(
            ids.file_table_id().expect("table b id"),
        ));
        let number = crate::kernel::FileSlotNumber::for_open_fd(3).expect("fd");
        let fixture = crate::dispatch::fd_table::InMemoryPipeTestFixture::new(10, 65536);
        table_a.install(number, fixture.read, false);
        let slot_a = table_a
            .capture_slot_authority(number)
            .expect("slot a token");

        let command = crate::file_authority::Command::SetCanonicalPipeCapacity {
            slot: slot_a,
            capacity: crate::file_authority::PipeCapacity::bounded(65536).expect("capacity"),
            accounting: crate::kernel::objects::PipeCapacityAccounting::InMemory,
        };

        // Passing table_b with slot_a (which belongs to table_a) is fatal
        let err = dispatcher
            .authority_call(table_b, slot_a, command)
            .expect_err("mismatched table and slot token");
        assert!(matches!(
            err,
            AuthorityCallError::Fatal(crate::file_authority::AuthorityFatal::InvariantViolation(_))
        ));
    }

    #[test]
    fn dispatch_error_file_authority_fatal_lowers_to_run_fatal() {
        let fatal_err = DispatchError::FileAuthorityFatal(
            crate::file_authority::AuthorityFatal::InvariantViolation("injected test fatal"),
        );
        let lowered = lower_handler_result(Err(fatal_err));
        assert!(matches!(
            lowered,
            Err(DispatchError::FileAuthorityFatal(
                crate::file_authority::AuthorityFatal::InvariantViolation(_)
            ))
        ));
    }

    #[test]
    fn every_routed_number_resolves() {
        // `resolves` is independent of dispatcher instance state, but matches the
        // brief's `&self` signature so a future per-instance routing could hook in.
        let d = SyscallDispatcher::new();
        for &n in ROUTED_NUMBERS {
            assert!(
                d.resolves(n),
                "syscall number {n} (0x{n:x}) lost its handler — routing changed!"
            );
        }
        // The full set is large; guard against accidental list truncation. This
        // is the count of INDIVIDUAL numbers (multi-number arms like `5 | 6`
        // expanded), which exceeds the original table's 235 arms.
        assert_eq!(
            ROUTED_NUMBERS.len(),
            243,
            "ROUTED_NUMBERS lost entries — the characterization set must stay complete"
        );
    }

    #[test]
    fn unrouted_number_does_not_resolve() {
        let d = SyscallDispatcher::new();
        // 9999 is not a Linux syscall and is not claimed by any module.
        assert!(!d.resolves(9999), "an unclaimed number must not resolve");
        // u64::MAX (no carrick-private constant uses it) is also unclaimed.
        assert!(!d.resolves(u64::MAX), "u64::MAX must not resolve");
    }
}

#[cfg(test)]
include!("tests.rs");
