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
//! `mem`, `proc`, `signal`, `time`, `creds`, `sysv`) owns its OWN routing table
//! via the `syscall_table!` macro, which emits a `dispatch_<area>(number) ->
//! Option<SyscallHandler<M>>`. `resolve_handler` chains those eight tables;
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
//!   [`DispatchOutcome::Fork`] (real `libc::fork` against the trap engine),
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
//!   `__ulock`), [`DispatchOutcome::WaitOnFds`] / [`DispatchOutcome::WaitOnFdsSelect`]
//!   / [`DispatchOutcome::WaitOnPollFds`] (poll/select/epoll-style fd readiness,
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
    LINUX_ADJ_OFFSET_SINGLESHOT_FLAG_ONLY,
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
    LINUX_F_SEAL_ALL,
    LINUX_F_SEAL_FUTURE_WRITE,
    LINUX_F_SEAL_GROW,
    LINUX_F_SEAL_SEAL,
    LINUX_F_SEAL_SHRINK,
    LINUX_F_SEAL_WRITE,
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
    LINUX_IFCONF_SIZE,
    LINUX_IFF_LOOPBACK,
    LINUX_IFF_RUNNING,
    LINUX_IFF_UP,
    LINUX_IFLA_ADDRESS,
    LINUX_IFLA_IFNAME,
    LINUX_IFNAMSIZ,
    LINUX_IFREQ_SIZE,
    LINUX_IOV_MAX,
    LINUX_IPPROTO_UDPLITE,
    LINUX_ITIMER_PROF,
    LINUX_ITIMER_REAL,
    LINUX_ITIMER_VIRTUAL,
    LINUX_LOCK_EX,
    LINUX_LOCK_NB,
    LINUX_LOCK_SH,
    LINUX_LOCK_UN,
    LINUX_MADV_COLLAPSE,
    LINUX_MADV_DOFORK,
    LINUX_MADV_DONTFORK,
    LINUX_MADV_DONTNEED,
    LINUX_MADV_FREE,
    LINUX_MADV_HUGEPAGE,
    LINUX_MADV_NOHUGEPAGE,
    LINUX_MADV_NORMAL,
    LINUX_MADV_RANDOM,
    LINUX_MADV_SEQUENTIAL,
    LINUX_MADV_WILLNEED,
    LINUX_MAP_ANONYMOUS,
    LINUX_MAP_FIXED,
    LINUX_MAP_FIXED_NOREPLACE,
    LINUX_MAX_SIGNUM,
    LINUX_MEMBARRIER_CMD_QUERY,
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
    LINUX_PRIO_PROCESS,
    LINUX_PRIO_USER,
    LINUX_PROT_READ,
    LINUX_PROT_WRITE,
    LINUX_R_OK,
    LINUX_RLIM_INFINITY,
    LINUX_RLIM_NLIMITS,
    LINUX_RLIMIT_AS,
    LINUX_RLIMIT_CPU,
    LINUX_RLIMIT_DATA,
    LINUX_RLIMIT_FSIZE,
    LINUX_RLIMIT_MEMLOCK,
    LINUX_RLIMIT_NOFILE,
    LINUX_RLIMIT_NPROC,
    LINUX_RLIMIT_STACK,
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
    LINUX_TFD_CLOEXEC,
    LINUX_TFD_NONBLOCK,
    LINUX_TIME_ERROR,
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
    LinuxFdFlags,
    LinuxFdPair,
    LinuxFutexFlags,
    LinuxGuestAbi,
    LinuxIfAddrMsg,
    LinuxIfInfoMsg,
    LinuxIovec,
    LinuxItimerspec,
    LinuxItimerval,
    LinuxMlock2Flags,
    LinuxMlockallFlags,
    LinuxMmapFlags,
    LinuxMmsghdr,
    LinuxMsgFlags,
    LinuxMsghdr,
    LinuxNlMsgHdr,
    LinuxOpenFlags,
    LinuxOpenHow,
    LinuxPollFd,
    LinuxProtFlags,
    LinuxRlimit,
    LinuxRtAttr,
    LinuxRusage,
    LinuxSigaction,
    LinuxSigaltstack,
    LinuxSocketTypeFlags,
    LinuxSpliceFlags,
    LinuxStat,
    LinuxStatfs,
    LinuxStatx,
    LinuxStatxTimestamp,
    LinuxSysinfo,
    LinuxTermios,
    LinuxTimerfdExpirations,
    LinuxTimespec,
    LinuxTimeval,
    LinuxTimex,
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
use crate::memory::{LINUX_HEAP_BASE, LINUX_HEAP_SIZE, LINUX_MMAP_BASE};
use crate::overlay::OverlayEntry;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsError, RootFsMetadata};
// Canonical-number lookups: carrick's canonical syscall numbering IS the
// aarch64 numbering. The dispatcher receives canonical numbers (a per-ISA
// table remaps raw numbers to canonical at the GuestArch seam — Phase 2 for
// x86_64), so its own metadata lookups stay aarch64-keyed by design; only
// raw-frame consumers (the vCPU-loop trace) use the per-ISA Arch::Table.
use crate::linux_abi::{CanonicalNr, LinuxErrno, NativeNr};
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
        $vis fn $name<M: GuestMemory>(number: u64) -> Option<SyscallHandler<M>> {
            Some(match number {
                $( $num => SyscallDispatcher::$handler, )*
                _ => return None,
            })
        }
    };
}

mod abi_args;
#[macro_use]
mod creds;
mod epoll_shim;
pub(crate) use epoll_shim::{
    EpollWakeRegistry, after_fork_child as reset_epoll_wake_registry_after_fork_child,
    new_epoll_wake_registry, notify_inmem_epoll, register_epoll_kqueue, unregister_epoll_kqueue,
};
pub(crate) use fifo_beacon::after_fork_child as reset_fifo_beacons_after_fork_child;
mod fd_table;
mod fifo_beacon;
mod ioring;
#[macro_use]
mod fs;
#[macro_use]
mod mem;
pub(crate) use mem::MemoryLayout;
#[macro_use]
mod net;
#[macro_use]
mod proc;
mod proctitle;
#[macro_use]
mod signal;
mod mqueue;
mod sysv;
#[macro_use]
mod time;

pub use proctitle::{init as proctitle_init, set_host_process_name};

pub use crate::vfs::{ProcMapSharing, ProcMapsEntry};
pub use abi_args::{Fd, GuestLen, GuestPtr, HostFd, HostPid, NsPid, Pid, Signal};
use fd_table::*;

#[derive(Debug, Clone)]
pub struct WaitFdGuard(#[allow(dead_code)] HostFdRef);

#[derive(Debug, Clone, Default)]
pub struct WaitFds {
    fds: Vec<crate::io_wait::WaitFd>,
    #[allow(dead_code)]
    guards: Vec<WaitFdGuard>,
}

impl WaitFds {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn raw(fds: Vec<(i32, i16)>) -> Self {
        Self {
            fds: fds
                .into_iter()
                .map(|(fd, events)| crate::io_wait::WaitFd::raw(fd, events))
                .collect(),
            guards: Vec::new(),
        }
    }

    pub fn raw_one(fd: i32, events: i16) -> Self {
        Self::raw(vec![(fd, events)])
    }

    pub(in crate::dispatch) fn anchored_one(
        fd: i32,
        events: i16,
        owner: Option<HostFdRef>,
    ) -> Self {
        match owner {
            Some(owner) => Self {
                fds: vec![crate::io_wait::WaitFd::anchored(fd, events)],
                guards: vec![WaitFdGuard(owner)],
            },
            None => Self::raw_one(fd, events),
        }
    }

    pub fn first(&self) -> Option<(i32, i16)> {
        self.fds.first().map(|fd| (fd.fd(), fd.events()))
    }
}

impl PartialEq for WaitFds {
    fn eq(&self, other: &Self) -> bool {
        self.fds == other.fds
    }
}

impl Eq for WaitFds {}

impl Serialize for WaitFds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let fds: Vec<(i32, i16)> = self.fds.iter().map(|fd| (fd.fd(), fd.events())).collect();
        fds.serialize(serializer)
    }
}

impl std::ops::Deref for WaitFds {
    type Target = [crate::io_wait::WaitFd];

    fn deref(&self) -> &Self::Target {
        &self.fds
    }
}

#[allow(dead_code)]
const MAX_GUEST_PATH: usize = 4096;

fn threaded_independent_dispatch_supports(number: u64) -> bool {
    matches!(number, 96 | 98 | 99 | 124 | 178 | 449)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyscallRequest {
    /// The CANONICAL (asm-generic/aarch64) syscall number the dispatch tables
    /// switch on. Typed [`CanonicalNr`] so it cannot be swapped with
    /// [`native_number`](Self::native_number) at a constructor.
    pub number: CanonicalNr,
    pub args: SyscallArgs,
    pub guest_abi: LinuxGuestAbi,
    /// The guest's architecture-native syscall number (see
    /// [`carrick_hal::RawSyscall::native_number`]): equals `number` for aarch64
    /// guests, the raw x86_64 UAPI number for x86_64 guests. seccomp filters are
    /// evaluated against this, not the normalized `number`.
    pub native_number: NativeNr,
    /// Current guest stack pointer at the syscall trap, when the run loop can
    /// cheaply read it from the vCPU. Legacy/synthetic dispatch paths leave
    /// this absent.
    pub current_guest_sp: Option<u64>,
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
        self.request.number.raw()
    }

    #[inline]
    pub fn raw_args(&self) -> SyscallArgs {
        self.request.args
    }

    #[inline]
    pub fn guest_abi(&self) -> LinuxGuestAbi {
        self.request.guest_abi
    }

    /// The current guest thread's Linux tid, as keyed by the signal/IO-wait
    /// machinery (`host_signal`, `io_wait`). Falls back to the process pid (the
    /// main thread's tid) on the single-threaded path where no thread ctx is
    /// present — matching how the run loop derives `this_tid`.
    #[inline]
    pub fn tid(&self) -> crate::thread::ThreadId {
        self.thread
            .map(|t| t.tid)
            .unwrap_or_else(crate::thread::ThreadId::main_from_host_pid)
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

pub(crate) fn guest_visible_tid(
    tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
) -> Option<u32> {
    let tid = u32::try_from(tid.raw()).ok()?;
    if registry.live_count() > 1 {
        if tid == std::process::id() {
            Some(crate::namespace::pid::host_to_ns_or_self(tid))
        } else {
            Some(tid)
        }
    } else {
        Some(crate::namespace::pid::self_ns_pid())
    }
}

// `GuestMemory` and `MemoryError` were lifted into the leaf crate
// `carrick-guest-mem` to break the `memory ↔ dispatch` cycle (see
// docs/archive/build-decomposition-design.md §3.A-A2). Re-exported here so every
// `crate::dispatch::{…}` / `carrick_runtime::dispatch::{…}` site is unchanged.
// (The `Aarch64SyscallFrame` re-export is gone: the dispatcher is ISA-neutral —
// backends decode raw frames behind `GuestArch` and hand over `RawSyscall`.)
pub use carrick_guest_mem::{Gpa, GuestMemory, GuestVa, HostVa, MemoryError};

impl SyscallRequest {
    /// Build an aarch64-ABI request from a bare canonical number (aarch64
    /// guests issue canonical numbers, so native == canonical). Takes `u64`
    /// deliberately — the hundreds of literal-number test call sites stay
    /// unchanged; the typed wrap happens here, in ONE place.
    pub fn new(number: u64, args: SyscallArgs) -> Self {
        Self {
            number: CanonicalNr(number),
            args,
            guest_abi: LinuxGuestAbi::Aarch64,
            native_number: NativeNr(number),
            current_guest_sp: None,
        }
    }

    pub fn with_guest_abi(mut self, guest_abi: LinuxGuestAbi) -> Self {
        self.guest_abi = guest_abi;
        self
    }

    pub fn with_current_guest_sp(mut self, current_guest_sp: Option<u64>) -> Self {
        self.current_guest_sp = current_guest_sp;
        self
    }

    pub fn arg(&self, index: usize) -> u64 {
        self.args.0[index]
    }

    /// Build a request from the ISA-neutral [`carrick_hal::RawSyscall`] the
    /// backend now hands back from `next_syscall` (the per-ISA register decode
    /// moved into the backend's `GuestArch`; the runtime loop only sees
    /// number + args).
    pub fn from_raw(raw: carrick_hal::RawSyscall) -> Self {
        Self {
            number: raw.number,
            args: SyscallArgs::from(raw.args),
            // The backend's `GuestArch` stamped the guest ABI onto the decoded
            // syscall (it cannot be inferred here — the no-threads / combined
            // Linux loops are type-erased over the ISA). Reading it off `raw`
            // means no call site can forget it and mis-marshal the x86 path.
            guest_abi: raw.guest_abi,
            native_number: raw.native_number,
            current_guest_sp: None,
        }
    }
}

#[derive(Eq)]
struct PinnedHostFd {
    fd: i32,
}

impl PinnedHostFd {
    fn new(fd: i32) -> Result<Self, LinuxErrno> {
        let duped = unsafe { libc::dup(fd) };
        if duped < 0 {
            let host = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EMFILE);
            return Err(crate::host_to_linux_errno(host));
        }
        Ok(Self { fd: duped })
    }
}

impl Drop for PinnedHostFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl std::fmt::Debug for PinnedHostFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PinnedHostFd").field(&self.fd).finish()
    }
}

impl PartialEq for PinnedHostFd {
    fn eq(&self, other: &Self) -> bool {
        self.fd == other.fd
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BlockingHostWrite {
    #[serde(skip_serializing)]
    host_fd: std::sync::Arc<PinnedHostFd>,
    #[serde(skip_serializing)]
    bytes: Vec<u8>,
    offset: usize,
    tid: crate::thread::ThreadId,
    sigpipe_on_epipe: bool,
}

impl BlockingHostWrite {
    fn from_vec(
        host_fd: i32,
        bytes: Vec<u8>,
        offset: usize,
        tid: crate::thread::ThreadId,
        sigpipe_on_epipe: bool,
    ) -> Result<Self, LinuxErrno> {
        Ok(Self {
            host_fd: std::sync::Arc::new(PinnedHostFd::new(host_fd)?),
            bytes,
            offset,
            tid,
            sigpipe_on_epipe,
        })
    }

    pub(crate) fn host_fd(&self) -> i32 {
        self.host_fd.fd
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn tid(&self) -> crate::thread::ThreadId {
        self.tid
    }

    pub(crate) fn sigpipe_on_epipe(&self) -> bool {
        self.sigpipe_on_epipe
    }
}

impl std::fmt::Debug for BlockingHostWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingHostWrite")
            .field("host_fd", &self.host_fd.fd)
            .field("bytes_len", &self.bytes.len())
            .field("offset", &self.offset)
            .field("tid", &self.tid)
            .field("sigpipe_on_epipe", &self.sigpipe_on_epipe)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BlockingRecordLock {
    #[serde(skip_serializing)]
    host_fd: std::sync::Arc<PinnedHostFd>,
    host_cmd: i32,
    l_start: i64,
    l_len: i64,
    l_type: i16,
    l_whence: i16,
}

impl BlockingRecordLock {
    pub(crate) fn new(
        host_fd: i32,
        host_cmd: i32,
        l_start: i64,
        l_len: i64,
        l_type: i16,
        l_whence: i16,
    ) -> Result<Self, LinuxErrno> {
        Ok(Self {
            host_fd: std::sync::Arc::new(PinnedHostFd::new(host_fd)?),
            host_cmd,
            l_start,
            l_len,
            l_type,
            l_whence,
        })
    }
}

impl std::fmt::Debug for BlockingRecordLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingRecordLock")
            .field("host_fd", &self.host_fd.fd)
            .field("host_cmd", &self.host_cmd)
            .field("l_start", &self.l_start)
            .field("l_len", &self.l_len)
            .field("l_type", &self.l_type)
            .field("l_whence", &self.l_whence)
            .finish()
    }
}

pub(crate) enum BlockingHostWriteStep {
    Done(DispatchOutcome),
    Wait,
}

pub(crate) fn drive_blocking_host_write(write: &mut BlockingHostWrite) -> BlockingHostWriteStep {
    loop {
        if write.offset >= write.bytes.len() {
            return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                value: write.bytes.len() as i64,
            });
        }
        // BLOCKING-IO-OK: BlockingHostWrite pins a dup of a host fd that was
        // adopted non-blocking before the handoff; EAGAIN returns Wait below.
        let n = unsafe {
            libc::write(
                write.host_fd(),
                write.bytes[write.offset..].as_ptr() as *const _,
                write.bytes.len() - write.offset,
            )
        };
        crate::probes::host_pipe_io(write.host_fd(), 1, n as i64);
        if let Err(errno) = n.host_syscall_errno() {
            if errno == LINUX_EAGAIN || errno == LINUX_EINTR {
                if crate::host_signal::has_unblocked_pending_for(
                    write.tid.raw(),
                    carrick_abi::SigBlockMask::NONE,
                ) {
                    return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                        value: write.offset as i64,
                    });
                }
                return BlockingHostWriteStep::Wait;
            }
            if write.offset > 0 {
                return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                    value: write.offset as i64,
                });
            }
            return BlockingHostWriteStep::Done(DispatchOutcome::Errno { errno });
        }
        if n == 0 {
            return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                value: write.offset as i64,
            });
        }
        write.offset += n as usize;
        if write.offset >= write.bytes.len() {
            return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                value: write.bytes.len() as i64,
            });
        }
        if crate::host_signal::has_unblocked_pending_for(
            write.tid.raw(),
            carrick_abi::SigBlockMask::NONE,
        ) {
            return BlockingHostWriteStep::Done(DispatchOutcome::Returned {
                value: write.offset as i64,
            });
        }
    }
}

pub(crate) fn drive_blocking_record_lock(lock: &BlockingRecordLock) -> DispatchOutcome {
    let mut fl: libc::flock = unsafe { core::mem::zeroed() };
    fl.l_start = lock.l_start as libc::off_t;
    fl.l_len = lock.l_len as libc::off_t;
    fl.l_type = lock.l_type;
    fl.l_whence = lock.l_whence;

    // BLOCKING-IO-OK: this is the blocking half of F_SETLKW/F_OFD_SETLKW after
    // the dispatcher has returned its state locks to the run loop. Sibling guest
    // threads can keep running and release the conflicting record lock.
    let rc = unsafe { libc::fcntl(lock.host_fd.fd, lock.host_cmd, &mut fl as *mut libc::flock) };
    match rc.host_syscall_errno() {
        Ok(_) => DispatchOutcome::Returned { value: 0 },
        Err(errno) => DispatchOutcome::Errno { errno },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Returned {
        value: i64,
    },
    Errno {
        errno: LinuxErrno,
    },
    Exit {
        code: i32,
    },
    SignalDeath {
        signum: i32,
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
        /// `CLONE_PARENT`: the child is guest-parented to the caller's parent,
        /// even though Carrick must still create it as a host child of the
        /// caller. Runtime fork code records that guest parent in fork-coherent
        /// shared state.
        clone_parent: bool,
        /// `CLONE_PARENT_SETTID`: write the child's guest-visible pid/tid to
        /// this `pid_t *` before returning to the caller. Linux makes the store
        /// visible in the child as well for CLONE_VM; Carrick's process fork is
        /// CoW, so runtime fork code mirrors the write into both branches.
        parent_tid_addr: Option<u64>,
        /// `CLONE_CHILD_SETTID`: write the child's guest-visible pid/tid to
        /// this child-memory `pid_t *` before the child returns from clone.
        child_tid_addr: Option<u64>,
        /// Guest-requested exit signal (low byte of clone flags / clone3
        /// `exit_signal`). Delivered to the parent on child exit instead of a
        /// hardcoded SIGCHLD. `0` means "no exit signal" (e.g. `clone(0)`).
        exit_signal: u32,
        /// The clone's stack argument for an ORDINARY (non-vfork) fork-like
        /// clone: `0` (fork/clone(SIGCHLD, NULL) — the common case) keeps the
        /// parent's SP; a nonzero value runs the CHILD on that stack, exactly
        /// as the kernel does — glibc/musl's `__clone` stub then pops the
        /// child function off the NEW stack (LTP clone01 et al. crashed
        /// without this, the child resuming on the parent's frames).
        child_stack: u64,
        /// `CLONE_VFORK` (+`CLONE_VM`): the vfork-for-exec shape (Go `os/exec`,
        /// glibc `posix_spawn`). `Some(child_stack)` requests the vfork path — the
        /// runtime forks a child that SHARES the parent's guest RAM (not a CoW
        /// snapshot) and SUSPENDS the parent vCPU until the child `execve`s or
        /// `_exit`s. `child_stack` is the clone's stack argument: `0` (NULL, which
        /// Go uses) keeps the parent's SP, a nonzero value runs the child on that
        /// stack. `None` is an ordinary CoW fork.
        vfork: Option<u64>,
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
        va: GuestVa,
        ipa: Gpa,
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
        /// The guest asked for `PROT_NONE`: after installing the alias mapping
        /// the runtime must make the range guest-INACCESSIBLE (invalidate the
        /// fresh leaves), so the guest's own access faults (SIGSEGV/ACCERR)
        /// instead of reaching the host backing — which for a PROT_NONE
        /// `MAP_SHARED` file is itself mapped `PROT_NONE`, and a guest touch
        /// through a present leaf crashes the vCPU (KVM_RUN EFAULT / stage-2
        /// abort: LTP mmap05's TBROK).
        prot_none: bool,
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
        stack: u64,       // child SP (clone arg)
        tls: Option<u64>, // CLONE_SETTLS value -> TPIDR_EL0
        flags: u64,
        parent_tid_addr: u64,      // CLONE_PARENT_SETTID target (0 = none)
        child_tid_addr: u64,       // CLONE_CHILD_SETTID target (0 = none)
        clear_child_tid_addr: u64, // CLONE_CHILD_CLEARTID target (0 = none)
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
        tid: crate::thread::ThreadId,
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
    FutexWaitv {
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
        index: i64,
    },
    /// A `FUTEX_WAIT` on a genuine `MAP_SHARED` file mapping — an inter-PROCESS
    /// rendezvous (LTP `tst_checkpoint`). The in-process parking-lot table can't
    /// reach a waker in another carrick process, so the runtime blocks on the
    /// host `__ulock` keyed by the SHARED physical page (`host_addr` is the host
    /// VA of the futex word). Like `FutexWait` it must not block under the
    /// dispatcher lock; the runtime waits interruptibly and completes the
    /// syscall. `value` is the expected futex word (the kernel re-compares).
    SharedFutexWait {
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
    },
    SharedFutexWaitv {
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        index: i64,
    },
    /// A `FUTEX_WAKE` on a genuine `MAP_SHARED` mapping — the cross-PROCESS wake
    /// counterpart of [`DispatchOutcome::SharedFutexWait`]. The wake must reach a
    /// waiter parked in ANOTHER carrick process on the same physical page, so it
    /// is routed through the `PlatformFutex::shared_wake` seam (HVF → `__ulock`
    /// one-at-a-time with `sched_yield`; KVM → host `SYS_futex(FUTEX_WAKE)`).
    /// The handler returns this outcome (instead of calling the backend wake
    /// inline) so the loop reaches the same `PlatformFutex` the `SharedFutexWait`
    /// side uses, keeping the wait/wake pair on ONE seam. `count` is the guest's
    /// requested wake count (`FUTEX_WAKE`'s `val`); the loop completes the syscall
    /// with the number actually woken.
    SharedFutexWake {
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        count: u32,
    },
    SharedFutexRequeue {
        from: carrick_guest_mem::SharedFutexLocation,
        from_key: usize,
        to: carrick_guest_mem::SharedFutexLocation,
        to_key: usize,
        wake: u32,
        requeue: u32,
    },
    /// Wait until an internal fork-shared word changes, then re-dispatch the
    /// original syscall. This is for runtime-owned kernel objects such as SysV
    /// message queues: the wait condition is not the syscall result, it only says
    /// the object state might have changed. The loop must release dispatcher and
    /// vCPU resources while parked, then retry the handler under fresh state.
    WaitOnSharedWord {
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
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
        fds: WaitFds,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// Value to complete the syscall with if the wait times out: `0` for
        /// poll/select (a timeout means "no fds ready"), `-EAGAIN` for a
        /// blocking recv/accept with a finite SO_RCVTIMEO (a timeout means
        /// "would have blocked"). Only consulted when `timeout` is `Some`.
        on_timeout: i64,
        /// The wait's signal-masking policy. `Replace(set)` carries a POSIX
        /// sigmask that REPLACES the thread's persistent mask for the wait
        /// (`ppoll`/`pselect6`/`epoll_pwait`): a signal blocked by the set does
        /// NOT interrupt the wait (it stays pending and is delivered after the
        /// syscall), and a signal the set UNBLOCKS must interrupt even if
        /// persistently blocked — the interrupt predicate uses the set ALONE.
        /// `Additive(set)` (the default for plain `read`/`recv`/`connect`,
        /// usually with an empty set) means the effective wait mask is the
        /// thread's persistent mask plus the set. (probe `ppollunblock` vs
        /// `maskfork`.)
        sig_mask: carrick_abi::WaitSigMask,
    },
    /// A blocking `write(2)` to a host FIFO made partial progress and then hit
    /// host EAGAIN. Re-dispatching the original syscall would duplicate the
    /// written prefix, while parking inside the dispatcher would starve sibling
    /// threads that may close the read end or deliver the interrupting signal.
    /// The runtime owns this staged continuation, waits for POLLOUT with the
    /// dispatcher lock released, and completes with the Linux-visible result.
    BlockingHostWrite(BlockingHostWrite),
    /// A blocking record-lock `fcntl(F_SETLKW/F_OFD_SETLKW)`. The dispatcher
    /// parsed and validated the guest `struct flock`, but the host call may
    /// sleep until a sibling thread releases a conflicting lock. Execute it in
    /// the run loop after dispatcher state locks have been released.
    BlockingRecordLock(BlockingRecordLock),
    /// Like [`DispatchOutcome::WaitOnFds`] but for `select`/`pselect6`, whose fd-set bitmaps are
    /// BOTH input and output (unlike `poll`'s separate `events`/`revents`).
    /// The handler therefore leaves the guest fd-sets UNMODIFIED across the
    /// wait, so:
    ///
    /// - a `Ready` re-dispatch re-reads the original input sets and reports
    ///   the now-ready fds (a fd that becomes ready *during* the block — the
    ///   primary use of select — is found correctly), and
    /// - an `Interrupted` (EINTR) return leaves the sets unmodified, exactly
    ///   as Linux specifies on signal interruption.
    ///
    /// Only `TimedOut` must present zeroed sets (select returns 0 with empty
    /// sets), which the runtime does by zeroing each `clear_on_timeout`
    /// `(guest_addr, byte_len)` range before completing the syscall with 0.
    /// `on_timeout` is implicitly 0 (a select timeout means "no fds ready").
    WaitOnFdsSelect {
        /// (host_fd, poll events) pairs to wait on.
        fds: WaitFds,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// The wait's signal-masking policy (`Replace` when pselect6 supplies a
        /// sigmask). See [`DispatchOutcome::WaitOnFds::sig_mask`].
        sig_mask: carrick_abi::WaitSigMask,
        /// Guest `(address, byte length)` of each present fd-set to zero if the
        /// wait times out. Empty when no fd-set was supplied.
        clear_on_timeout: Vec<(u64, usize)>,
    },
    /// Same contract as [`DispatchOutcome::WaitOnFds`], but serviced by `poll(2)` instead of
    /// the runtime's per-thread kqueue. This is for epoll's backing kqueue fd:
    /// polling a kqueue fd observes pending epoll events without consuming
    /// them, so the runtime can re-dispatch `epoll_pwait` and let that call
    /// drain the epoll instance kqueue normally.
    WaitOnPollFds {
        /// (host_fd, poll events) pairs to wait on.
        fds: WaitFds,
        /// `None` = wait forever (signal-interruptible).
        timeout: Option<Duration>,
        /// Value to complete the syscall with if the wait times out.
        on_timeout: i64,
        /// The wait's signal-masking policy (`Replace` when `ppoll`/
        /// `epoll_pwait` supplies a sigmask). See
        /// [`DispatchOutcome::WaitOnFds::sig_mask`].
        sig_mask: carrick_abi::WaitSigMask,
    },
    /// A blocking `waitid(P_PID, pid, …)` whose target child hasn't changed
    /// state yet. The runtime parks the vCPU thread on the child's exit via the
    /// per-thread kqueue's `EVFILT_PROC`/`NOTE_EXIT` (interruptible by a signal
    /// or a fork quiesce — unlike a raw `libc::waitid`), then re-dispatches the
    /// waitid to reap. `sig_mask` is always `Additive` here: waitpid/waitid
    /// carry no POSIX temp sigmask, only extra temporarily-blocked signals
    /// (empty for a plain waitid).
    WaitOnProcExit {
        pid: i32,
        sig_mask: carrick_abi::WaitSigMask,
    },
    /// A Darwin-native wait for a non-terminal child state (`WSTOPPED` or
    /// `WCONTINUED`). `EVFILT_PROC` only reports exit, so the runtime parks on
    /// the signal wake path with a bounded retry and re-dispatches the original
    /// wait syscall. `pid` keeps the concrete host target for diagnostics and a
    /// future selector-aware kqueue implementation.
    WaitOnProcState {
        pid: i32,
        sig_mask: carrick_abi::WaitSigMask,
    },
    /// A synchronous signal wait found no matching signal already pending and
    /// must wait until one of `wait_set` arrives, or until `timeout` elapses.
    /// `rt_sigtimedwait` uses its caller-supplied timeout; `rt_sigsuspend` uses
    /// `None` after installing its temporary mask and saved-mask restoration.
    /// The runtime
    /// parks without holding dispatcher locks, wakes for matching signals
    /// (re-dispatching the same syscall so the dispatcher can dequeue the
    /// signal and write `siginfo_t` through the original guest pointer) — OR
    /// for an unblocked signal OUTSIDE `wait_set`, which must interrupt the
    /// wait with EINTR after its handler is delivered (sigtimedwait is never
    /// restarted, even under SA_RESTART — signal(7)).
    WaitOnSignals {
        wait_set: carrick_abi::SigSet,
        /// Signals that must NOT wake the park
        /// ([`carrick_abi::SigBlockMask::for_signal_wait`], precomputed at
        /// dispatch). The distinct TYPE exists because passing `!wait_set`
        /// here was the empty-set hang: `rt_sigtimedwait(set=∅, NULL)`
        /// blocked every signal, so the unblocked caught signal that must
        /// EINTR the wait (LTP sigtimedwait01 et al.) could never wake the
        /// waiter.
        block_mask: carrick_abi::SigBlockMask,
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
        remaining: Option<GuestPtr>,
    },
}

impl DispatchOutcome {
    /// Construct an errno outcome. The guest receives `-errno`.
    #[inline]
    pub fn errno(errno: LinuxErrno) -> Self {
        DispatchOutcome::Errno { errno }
    }

    fn retval_errno(&self) -> (i64, Option<i32>) {
        match self {
            DispatchOutcome::Returned { value } => (*value, None),
            DispatchOutcome::Errno { errno } => (errno.guest_retval(), Some(errno.get())),
            DispatchOutcome::Exit { code } => (*code as i64, None),
            DispatchOutcome::SignalDeath { signum } => ((128 + *signum) as i64, None),
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
            DispatchOutcome::FutexWaitv { .. } => (0, None),
            DispatchOutcome::SharedFutexWait { .. } => (0, None),
            DispatchOutcome::SharedFutexWaitv { .. } => (0, None),
            DispatchOutcome::SharedFutexWake { .. } => (0, None),
            DispatchOutcome::SharedFutexRequeue { .. } => (0, None),
            DispatchOutcome::WaitOnSharedWord { .. } => (0, None),
            DispatchOutcome::WaitOnFds { .. } => (0, None),
            DispatchOutcome::BlockingHostWrite(_) => (0, None),
            DispatchOutcome::BlockingRecordLock(_) => (0, None),
            DispatchOutcome::WaitOnFdsSelect { .. } => (0, None),
            DispatchOutcome::WaitOnPollFds { .. } => (0, None),
            DispatchOutcome::WaitOnProcExit { .. } => (0, None),
            DispatchOutcome::WaitOnProcState { .. } => (0, None),
            DispatchOutcome::WaitOnSignals { .. } => (0, None),
            DispatchOutcome::WaitOnSleep { .. } => (0, None),
        }
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
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
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

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
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
    /// A guest-visible errno. Unlike [`DispatchError::LengthTooLarge`] (which is
    /// a fatal, unrepresentable condition that aborts the run), this is lowered
    /// to a [`DispatchOutcome::Errno`] at the dispatch boundary
    /// ([`lower_handler_result`]). It lets a handler `?`-propagate an errno —
    /// `let x = helper()?;` instead of `match helper() { Err(e) => return
    /// Ok(e.into()), Ok(v) => v }` — collapsing the pervasive errno-forwarding
    /// boilerplate. The guest observes exactly the same `-errno` either way.
    #[error("guest-visible errno: {}", .0.get())]
    Errno(LinuxErrno),
}

impl From<LinuxErrno> for DispatchError {
    /// A typed Linux errno propagated via `?` becomes [`DispatchError::Errno`],
    /// lowered back to a guest errno outcome at the dispatch boundary.
    fn from(errno: LinuxErrno) -> Self {
        DispatchError::Errno(errno)
    }
}

impl From<MemoryError> for DispatchError {
    /// A guest-memory access fault is the guest handing us a bad pointer →
    /// `EFAULT`. Lets handlers `?`-propagate `memory.read_bytes(..)` /
    /// `write_bytes(..)` directly instead of the `match { Err(_) => return
    /// Ok(DispatchOutcome::errno(LINUX_EFAULT)) }` boilerplate (in handlers
    /// returning `Result<_, DispatchError>`; helpers returning
    /// `Result<_, LinuxErrno>` keep `.map_err(|_| LINUX_EFAULT)?`).
    fn from(_: MemoryError) -> Self {
        DispatchError::Errno(LINUX_EFAULT)
    }
}

/// Lower a syscall handler's result for the run loop. A
/// [`DispatchError::Errno`] is a guest-visible errno, so it becomes a normal
/// [`DispatchOutcome::Errno`]; every other `DispatchError` variant is a fatal
/// condition that stays `Err` and aborts the guest run. This is what lets
/// handlers `?`-propagate an errno while `LengthTooLarge` still aborts.
fn lower_handler_result(
    result: Result<DispatchOutcome, DispatchError>,
) -> Result<DispatchOutcome, DispatchError> {
    match result {
        Err(DispatchError::Errno(errno)) => Ok(DispatchOutcome::Errno { errno }),
        other => other,
    }
}

/// Outcome of [`SyscallDispatcher::try_vfs_open`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum VfsOpenAttempt {
    Installed(i32),
    Errno(LinuxErrno),
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
    /// Lock-free MAY-HAVE-PENDING hints mirroring `signal`'s pending stores,
    /// so the per-dispatch delivery cycle (every syscall return / kick /
    /// sigreturn) can prove "nothing pending" without taking the signal lock.
    /// `signal_tid_pending_hint` carries bit `tid % 64` for every tid with a
    /// nonzero `pendings` set (collisions only cost a locked fallback);
    /// `signal_process_pending_hint` mirrors `process_pending.raw()`. Both are
    /// EXACT MIRRORS: every mutation of the underlying stores happens with the
    /// `signal` lock held and refreshes them before release
    /// (`signal::SyscallDispatcher::refresh_signal_pending_hints`). A reader
    /// racing a marker mid-critical-section linearizes before the mark; the
    /// marker's kick/unblock boundary runs a fresh delivery cycle that sees
    /// the refreshed hint.
    signal_tid_pending_hint: std::sync::atomic::AtomicU64,
    signal_process_pending_hint: std::sync::atomic::AtomicU64,
    /// Owned filesystem subsystem state (unified VFS mount table plus
    /// the `/` rootfs + writable overlay). See [`fs::FsState`]. Handlers
    /// that touch only fs state borrow `self.fs` narrowly.
    fs: fs::FsState,
    /// Installed seccomp(2) cBPF filters, checked before every syscall once
    /// active. Internally locked; `libc::fork` inherits the filters via the
    /// process memory copy and sibling threads share them (process-wide), which
    /// matches Linux's filter-inheritance semantics. See [`crate::seccomp`].
    seccomp: crate::seccomp::SeccompState,
    /// Launch-time container syscall-deny policy (the Docker default-seccomp
    /// model), checked at dispatch entry before any handler — alongside the
    /// guest-installed filters above, which stack on top of it exactly like a
    /// guest filter stacks on Docker's launch profile. `None` = unconfined.
    /// Plain field set once before boot (`apply_seccomp_policy`), read through
    /// `&self`; a forked child inherits it via the process memory copy and it
    /// survives in-process execve — per-process-tree, like a seccomp filter.
    /// See [`crate::container_policy`].
    container_policy: Option<crate::container_policy::ContainerPolicy>,
    /// SysV shared-memory registry (per-process; host-file-backed so forked
    /// guests share segments by inode through `/tmp/carrick-shm/`).
    sysv: Mutex<sysv::SysvShmState>,
    /// Active network namespace provider lease for this run. Host mode uses a
    /// no-op provider; bridge mode carries the socket namespace provider.
    network: std::sync::Arc<crate::network::RuntimeNetwork>,
    /// Linux/host page geometry selected for this run. Default dispatch stays
    /// 4 KiB Linux pages; native-only lanes can override before first syscall.
    page_geometry: crate::page_profile::PageGeometry,
    /// The supplementary group set installed by `setgroups(2)`, or `None` if the
    /// guest never called it (then `getgroups` falls back to the /etc/group-
    /// derived membership for `id(1)` compatibility). `setgroups` replaces this
    /// whole set; `getgroups` returns it verbatim. Process-wide; a `libc::fork`
    /// child inherits it via the memory copy and it survives `execve`
    /// (matching Linux — CPython subprocess `extra_groups=` sets it pre-exec).
    setgroups_override: Mutex<Option<Vec<u32>>>,
    /// Set by syscall handlers that make process-directed async signal delivery
    /// observable while guest userspace is spinning. The threaded runtime drains
    /// this after completing the syscall and starts the signal pump before
    /// re-entering guest code.
    signal_pump_requested: std::sync::atomic::AtomicBool,
    /// Whether `execve` image loading may fall back to reading the LITERAL host
    /// filesystem (`std::fs::read` at the absolute guest path) when the target
    /// is absent from the overlay/rootfs/bind-mounts. `true` only for bare
    /// run-elf boots (no container image — the guest IS a host ELF and its
    /// execve targets are host-staged test fixtures). Container runs (run-oci,
    /// `with_rootfs*`, `--fs host`/`--fs memory`) set this `false`: a guest
    /// execve of a path not in the container filesystem must `ENOENT`, never
    /// silently load the matching HOST binary (a containment hole that, e.g.,
    /// loaded the host's glibc `/usr/bin/echo` into a musl rootfs during an
    /// execvp PATH search). Plain `bool`: set once at construction, read at
    /// execve through `&self`.
    exec_host_fs_fallback: bool,
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

/// A normalized syscall handler resolved to a bare function pointer: the
/// `define_syscall!`-generated `sys_*` methods all share this signature, so a
/// `number → handler` table is just a `match` returning one of these. Each
/// dispatch module owns a `dispatch_<area>(number) -> Option<SyscallHandler<M>>`
/// over the numbers IT implements; `dispatch_normalized` chains them. Adding a
/// syscall is then a one-module edit — no shared routing table to contend on
/// (Task A1). See [[plan-concurrent-fanout-lanes]] Part A.
pub(crate) type SyscallHandler<M> =
    fn(&SyscallDispatcher, &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>;

/// Resolve a syscall number to its handler by chaining every dispatch module's
/// own routing table. This is the single source of truth for "is this number
/// claimed, and by which handler"; both `dispatch_normalized` (which builds the
/// ctx and invokes the handler) and `dispatch_normalized_known` (the membership
/// test) go through it. Each module owns its own arms, so a future agent adds a
/// syscall by editing ONE module's `dispatch_<area>` — never this function (the
/// central `dispatch()` chokepoint is gone). See [[plan-concurrent-fanout-lanes]].
fn resolve_handler<M: GuestMemory>(number: u64) -> Option<SyscallHandler<M>> {
    fs::dispatch_fs(number)
        .or_else(|| net::dispatch_net(number))
        .or_else(|| mem::dispatch_mem(number))
        .or_else(|| proc::dispatch_proc(number))
        .or_else(|| signal::dispatch_signal(number))
        .or_else(|| time::dispatch_time(number))
        .or_else(|| creds::dispatch_creds(number))
        .or_else(|| sysv::dispatch_sysv(number))
        .or_else(|| mqueue::dispatch_mqueue(number))
}

impl SyscallDispatcher {
    /// Dispatch a syscall through the chained per-module routing. Returns `None`
    /// for an unclaimed number (the caller ENOSYSes); otherwise builds the
    /// transient `SyscallCtx` and invokes the resolved handler.
    fn dispatch_normalized(
        &self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
        thread: Option<ThreadCtx>,
    ) -> Option<Result<DispatchOutcome, DispatchError>> {
        let handler = resolve_handler(request.number.raw())?;
        let canonical_nr = request.number.raw();
        let mut ctx = SyscallCtx {
            request,
            memory,
            reporter,
            thread,
        };
        let outcome = handler(self, &mut ctx);
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

    /// Membership test: is `number` claimed by some dispatch module? Mirrors
    /// `dispatch_normalized` exactly (both go through `resolve_handler`), so the
    /// two can never drift. Uses `LinearMemory` as the concrete memory type —
    /// the claimed set is independent of `M`.
    fn dispatch_normalized_known(number: u64) -> bool {
        resolve_handler::<LinearMemory>(number).is_some()
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

    pub fn new() -> Self {
        Self {
            io: fs::IoState::new(),
            mem: Mutex::new(mem::MemState::new()),
            proc: Mutex::new(proc::ProcState::new()),
            creds: Mutex::new(creds::CredState::new()),
            signal: Mutex::new(signal::SignalState::new()),
            signal_tid_pending_hint: std::sync::atomic::AtomicU64::new(0),
            signal_process_pending_hint: std::sync::atomic::AtomicU64::new(0),
            fs: fs::FsState::new(),
            seccomp: crate::seccomp::SeccompState::default(),
            // Unconfined until a frontend applies a policy: bare run-elf boots
            // and unit tests keep today's handler-honest behavior.
            container_policy: None,
            sysv: Mutex::new(sysv::SysvShmState::new()),
            network: std::sync::Arc::new(crate::network::RuntimeNetwork::host_default()),
            page_geometry: crate::page_profile::PageGeometry {
                host_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                native_profile: None,
            },
            setgroups_override: Mutex::new(None),
            signal_pump_requested: std::sync::atomic::AtomicBool::new(false),
            // Default: bare run-elf boot — allow the host-fs execve fallback.
            // Container constructors flip this off (see `with_rootfs*` /
            // `sandbox_exec_to_container`).
            exec_host_fs_fallback: true,
        }
    }

    pub fn with_network(network: std::sync::Arc<crate::network::RuntimeNetwork>) -> Self {
        let mut dispatcher = Self::new();
        if network.spec.mode != carrick_spec::NetworkMode::Host {
            dispatcher.fs.vfs_mounts.mount(
                "/sys",
                Box::new(crate::vfs::SysVfs::from_network_model(
                    network.model.clone(),
                )),
            );
        }
        if should_mount_network_resolv_conf(&network.model) {
            let contents = resolv_conf_contents_for_network(&network.model);
            dispatcher.fs.vfs_mounts.mount(
                "/etc/resolv.conf",
                Box::new(crate::vfs::ResolvConfVfs::from_contents(contents)),
            );
        }
        dispatcher.network = network;
        dispatcher
    }

    pub fn with_page_geometry(page_geometry: crate::page_profile::PageGeometry) -> Self {
        let mut dispatcher = Self::new();
        dispatcher.page_geometry = page_geometry;
        dispatcher
    }

    pub(crate) fn set_page_geometry(&mut self, page_geometry: crate::page_profile::PageGeometry) {
        self.page_geometry = page_geometry;
    }

    pub(crate) fn set_memory_layout(&self, layout: MemoryLayout) {
        *self.mem.lock() = mem::MemState::new_with_layout(layout);
    }

    pub fn page_geometry(&self) -> crate::page_profile::PageGeometry {
        self.page_geometry
    }

    pub(crate) fn linux_page_size(&self) -> u64 {
        self.page_geometry.linux_page_size
    }

    pub(crate) fn notify_inmem_epoll(&self) {
        notify_inmem_epoll(&self.io.epoll_wake_registry);
    }

    pub(crate) fn epoll_after_fork_child(&self) {
        reset_epoll_wake_registry_after_fork_child(&self.io.epoll_wake_registry);
    }

    pub fn set_guest_hostname(&self, hostname: impl Into<String>) {
        self.proc.lock().guest_hostname = hostname.into();
    }

    pub(crate) fn request_signal_pump(&self) {
        self.signal_pump_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn take_signal_pump_request(&self) -> bool {
        self.signal_pump_requested
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    /// Capture the guest's `AddressSpace` region list so that
    /// `/proc/self/maps` reflects the real loaded layout (executable
    /// ELF segments, runtime regions, mmap arena, stack, EL0
    /// trampoline, EL1 vectors, page tables) instead of a fixed
    /// summary. Called once after `HvfTrapEngine::map_address_space`
    /// succeeds.
    pub fn set_address_space_regions(&self, regions: Vec<ProcMapsEntry>) {
        self.mem.lock().address_space_regions = Some(regions);
    }

    /// Capture the guest's serialized ELF auxv image (from the loaded
    /// `AddressSpace`) so `/proc/self/auxv` can serve the byte-exact vector the
    /// guest received on its stack. Called alongside `set_address_space_regions`
    /// at boot and on each successful `execve`.
    pub fn set_auxv_image(&self, auxv: Vec<u8>) {
        self.mem.lock().linux_auxv_image = auxv;
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
        // A rootfs means a sandboxed container filesystem: no host-fs execve escape.
        s.exec_host_fs_fallback = false;
        s
    }

    pub fn with_rootfs_and_executable(rootfs: RootFs, executable_path: impl Into<String>) -> Self {
        let mut s = Self::new();
        s.fs.rootfs_vfs.rootfs = Some(rootfs);
        s.exec_host_fs_fallback = false;
        s.set_executable_path(executable_path);
        s
    }

    /// Mark this dispatcher as running a sandboxed CONTAINER filesystem (an
    /// extracted OCI image on a cap-std overlay), so `execve` never falls back
    /// to the literal host filesystem. Call after constructing a container
    /// dispatcher via `new()` + `set_fs_backend` (the run-oci / `--fs host`
    /// paths, which do not go through `with_rootfs*`). `with_rootfs*` already
    /// imply this; this is for the overlay-only container construction.
    pub fn sandbox_exec_to_container(&mut self) {
        self.exec_host_fs_fallback = false;
    }

    /// Whether `execve` image loading may read the literal host filesystem for a
    /// target absent from the overlay/rootfs/mounts. See `exec_host_fs_fallback`.
    pub fn exec_host_fs_fallback(&self) -> bool {
        self.exec_host_fs_fallback
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

    /// Enter a `binfmt_misc` redirect (Apple's Rosetta). `executable_path` stays
    /// the target (a binfmt redirect is transparent on real Linux), so this:
    ///  - flags the guest binfmt-interpreted, so `uname(2)` reports x86_64; and
    ///  - sets `/proc/self/cmdline` to `stack_argv` — the argv carrick puts on the
    ///    guest stack for Rosetta (`[argv0, target, args…]`). Rosetta serves the
    ///    guest's cmdline by applying its argv-skip to what it received on the
    ///    stack; if `proc.argv` instead held the bare program argv (no target
    ///    entry), that skip would strip the program's real `argv[0]`. Matching the
    ///    stack form makes the post-skip cmdline the faithful program argv.
    pub fn enter_binfmt(&self, stack_argv: &[Vec<u8>]) {
        let mut proc = self.proc.lock();
        proc.binfmt_interpreted = true;
        proc.argv = stack_argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
    }

    /// Seed the guest's initial credentials (`docker run --user` / image `USER`).
    /// Applied once before the guest starts; defaults to (0, 0) = root.
    pub fn set_credentials(&self, uid: u32, gid: u32) {
        self.creds.lock().seed_identity(uid, gid);
    }

    /// Record whether the guest's native ISA is x86_64 so `uname(2)` (and other
    /// arch-dependent syscalls) report it. Set once at run-image setup from
    /// `E::Arch::elf_machine()`; native aarch64 guests leave it false.
    pub fn set_native_x86_64(&self, native_x86_64: bool) {
        self.proc.lock().native_x86_64 = native_x86_64;
    }

    pub fn set_executable_identity(
        &self,
        path: impl Into<String>,
        argv: Vec<String>,
        env: Vec<Vec<u8>>,
    ) {
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
        let base = path.rsplit('/').next().unwrap_or(&path);
        proc.task_name = linux_task_name_from_bytes(base.as_bytes());
        proc.env = env;
        // A fresh image identity: clear the binfmt flag. The binfmt redirect
        // re-sets it (via set_binfmt_interpreted) iff THIS image is foreign-arch,
        // so the flag tracks the current image across execve (x86 -> native and
        // native -> x86).
        proc.binfmt_interpreted = false;
    }

    /// Name of the currently-installed backend (for logging / debug).
    pub fn fs_backend_name(&self) -> &'static str {
        self.fs.rootfs_vfs.overlay.name()
    }

    /// Snapshot the exact durable filesystem root used by a native host
    /// self-reexec. Memory-backed overlays reject this before guest image
    /// retirement through the backend's typed `Unsupported` result.
    pub fn native_fs_reexec_authority(
        &self,
    ) -> Result<crate::fs_backend::HostFsReexecAuthority, crate::fs_backend::BackendError> {
        self.fs.rootfs_vfs.overlay.native_reexec_authority()
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

    /// Whether guest stdout/stderr are live inherited host descriptors. Native
    /// host self-reexec restores this execution-mode bit in the fresh dispatcher.
    pub fn stream_stdio_enabled(&self) -> bool {
        *self.io.stream_stdio.lock()
    }

    /// Capsule version 1 initially carries only bare stdio. Reject every richer
    /// fd-table shape before host exec until typed descriptor snapshots land.
    pub fn native_reexec_minimal_fd_state_eligible(&self) -> bool {
        self.io.open_files.read().is_empty()
            && *self.io.stdio_cloexec.lock() == [false; 3]
            && *self.io.closed_stdio.lock() == [false; 3]
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
        let removed: Vec<(i32, OpenFile)> = {
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
                .filter_map(|fd| table.remove(&fd).map(|of| (fd, of)))
                .collect()
        };

        for (fd, open_file) in removed {
            self.io.splice_pushback.lock().remove(&fd);
            self.close_open_file_and_free_pty(&open_file);
            self.note_fd_closed(fd);
            // Linux auto-removes a closed fd from every epoll interest set.
            self.detach_fd_from_epolls(fd);
        }
    }

    /// Close `open_file`'s backing host fd AND, if it was the last reference
    /// to a pty master this process owns, drop its `/dev/pts` entry. Use this
    /// on every fd-close path (close, close_range, exec CLOEXEC sweep) so the
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
        let classic_lock_release_fd = match &*open_file.description.read() {
            OpenDescription::HostFile { host_fd, .. } => Some(host_fd.raw()),
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

        // Only act when THIS is the last reference (the host fd is actually
        // closing) — a dup'd fd sharing the Arc keeps the writer/pty alive.
        let last_ref = Arc::strong_count(&open_file.description) == 1;
        let mut pty_master_index = None;
        let mut fifo_host_fd = None;
        let mut closing_inotify = None;
        if last_ref {
            match &*open_file.description.read() {
                OpenDescription::HostPipe { pty, host_fd, .. } => {
                    fifo_host_fd = Some(host_fd.raw());
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
                _ => {}
            }
        }
        if let Some(state) = closing_inotify {
            self.fs.inotify_registry.unregister_all(&state);
        }
        close_open_file(open_file);
        if let Some(index) = pty_master_index {
            self.pty_table()
                .lock()
                .free_if_owner(index, std::process::id());
        }
        // A FIFO write-end close drops a beacon writer — wake epoll/poll so FIFO
        // read-ends re-check the (kernel-decided) EOF (see dispatch::fifo_beacon).
        // No-op for non-FIFO host pipes.
        if let Some(host_fd) = fifo_host_fd
            && crate::dispatch::fifo_beacon::register_close(host_fd)
        {
            self.notify_inmem_epoll();
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
        // Tree-wide forward-progress beat for the deadlock watchdog.
        crate::deadlock_watchdog::tick();
        self.dispatch_inner(request, memory, reporter, None)
    }

    /// Apply a launch-time container syscall policy (the `carrick run` /
    /// `--security-opt seccomp=…` resolution). Must be called before the guest
    /// boots — the field is then read-only and inherited across guest
    /// fork/execve like a Linux seccomp filter. `Unconfined` clears it.
    pub fn apply_seccomp_policy(&mut self, policy: carrick_spec::SeccompPolicy) {
        self.container_policy = match policy {
            carrick_spec::SeccompPolicy::ContainerDefault => {
                Some(crate::container_policy::ContainerPolicy::docker_default_model())
            }
            carrick_spec::SeccompPolicy::Unconfined => None,
        };
    }

    /// Evaluate the launch-time container deny table against `request` before
    /// its handler runs — the carrick seam where Docker's default seccomp
    /// profile sits (after the guest issues the syscall, before any handler).
    /// Returns `Some(errno outcome)` for a policy-denied call, `None` to pass
    /// through. The denial is recorded as a *policy* event (distinct from
    /// `UnhandledSyscall`, so coverage reporting never counts it as an
    /// unimplemented handler).
    fn container_policy_precheck(
        &self,
        request: &SyscallRequest,
        reporter: &CompatReporter,
    ) -> Option<DispatchOutcome> {
        let policy = self.container_policy.as_ref()?;
        let errno = policy.denied_errno(request.number.raw())?;
        let name = lookup_aarch64(request.number.raw()).map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::partial_syscall(
            request.number.raw(),
            name,
            request.args,
            "denied by launch-time container syscall policy (Docker default-seccomp model)",
        ));
        Some(DispatchOutcome::Errno { errno })
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

    pub(crate) fn identity_fast_path_enabled(&self) -> bool {
        // The EL1 shim answers identity syscalls without a dispatch, so it must
        // be off whenever a guest filter is active OR the launch-time policy
        // denies an identity syscall (the Docker default model never does —
        // container runs keep the fast path).
        !self.seccomp.is_active()
            && !self.container_policy.as_ref().is_some_and(|policy| {
                policy.denies_any(crate::container_policy::IDENTITY_FAST_PATH_SYSCALLS)
            })
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
        // Launch-time container policy first (it is installed before the guest
        // boots, like Docker's profile), then guest-installed seccomp filters —
        // both process-wide, both before any handler, including the lockless
        // hot path.
        if let Some(outcome) = self.container_policy_precheck(&request, reporter) {
            return Ok(outcome);
        }
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

        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let outcome = {
            reporter.record(CompatEvent::unhandled_syscall(
                request.number.raw(),
                name,
                request.args,
            ));
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            }
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number.raw(),
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

        if request.number.raw() == 64 && !self.write_shared_supported(request.args.0[0] as i32) {
            return None;
        }

        if !Self::dispatch_normalized_known(request.number.raw()) {
            return None;
        }

        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        for (nr, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *nr == request.number.raw() {
                let value = request.arg(*arg_index as usize);
                check_syscall_flags(
                    reporter,
                    request.number.raw(),
                    name,
                    *arg_index,
                    value,
                    *mask,
                );
            }
        }

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

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

        let result = self.dispatch_normalized(request, memory, reporter, thread);
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
        self.epoll_rearm_after_io(&request, &outcome);
        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number.raw(),
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
        if !threaded_independent_dispatch_supports(request.number.raw()) {
            return None;
        }
        match request.number.raw() {
            130 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(0) as i32);
                let signum = request.arg(1);
                if signum <= LINUX_MAX_SIGNUM && (target == tid || !registry.is_live(target)) {
                    return None;
                }
            }
            131 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(1) as i32);
                let signum = request.arg(2);
                if signum <= LINUX_MAX_SIGNUM && (target == tid || !registry.is_live(target)) {
                    return None;
                }
            }
            _ => {}
        }

        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);
        reporter.record(CompatEvent::SyscallEntry {
            number: request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        let outcome = match request.number.raw() {
            96 => {
                let addr = request.arg(0);
                registry.set_clear_child_tid(tid, addr);
                // set_tid_address(2) returns the caller's TID. In a PID namespace
                // the MAIN thread's host tid (== host pid) must read as the
                // process's ns-pid — identical to gettid (178)/getpid, so LTP
                // set_tid_address01 (which asserts the return == getpid()) holds.
                // `tid` is the caller's own live tid, so guest_visible_tid is
                // always Some; worker tids (> main_tid) are per-process and not
                // ns-translated. Identity when namespaces are off.
                let visible =
                    guest_visible_tid(tid, registry).map_or(i64::from(tid.raw()), i64::from);
                DispatchOutcome::Returned { value: visible }
            }
            98 => dispatch_threaded_futex(request, memory, reporter, futex, tid, registry),
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
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(0) as i32);
                let signum = request.arg(1);
                dispatch_threaded_signal_route(tid, registry, target, signum)?
            }
            131 => {
                let target =
                    crate::thread::ThreadId::from_guest_supplied_tid(request.arg(1) as i32);
                let signum = request.arg(2);
                dispatch_threaded_signal_route(tid, registry, target, signum)?
            }
            178 => {
                // gettid: the MAIN thread's tid equals the process host pid, so
                // in a PID namespace it must read as the process's ns-pid; a
                // single-threaded process reports its ns getpid. Worker tids
                // (> main_tid) are per-process and not ns-translated (§5.3).
                // Mirrors the `gettid` macro handler (proc.rs). Identity when
                // namespaces are off.
                let Some(tid) = guest_visible_tid(tid, registry) else {
                    return Some(Ok(DispatchOutcome::errno(LINUX_EINVAL)));
                };
                DispatchOutcome::Returned {
                    value: i64::from(tid),
                }
            }
            449 => dispatch_futex_waitv_args(
                memory,
                Some(futex),
                request.arg(0),
                request.arg(1),
                request.arg(2),
                request.arg(3),
                request.arg(4),
            ),
            _ => DispatchOutcome::Errno {
                errno: LINUX_ENOSYS,
            },
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number.raw(),
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
        let syscall = lookup_aarch64(request.number.raw());
        let name = syscall.map_or("unknown", |syscall| syscall.name);

        reporter.record(CompatEvent::SyscallEntry {
            number: request.number.raw(),
            name: ::std::borrow::Cow::Borrowed(name),
            args: request.args,
        });

        // Launch-time container policy: the Docker default-seccomp model vetoes
        // a denied syscall before its handler runs, exactly where the guest's
        // own filters are checked below.
        if let Some(outcome) = self.container_policy_precheck(&request, reporter) {
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                retval,
                errno,
            });
            return Ok(outcome);
        }

        // seccomp: installed cBPF filters get to veto the syscall before its
        // handler runs (ERRNO / kill), mirroring the kernel's pre-syscall check.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                retval,
                errno,
            });
            return Ok(outcome);
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

        // Systematic unknown-flag check. For each syscall whose flag
        // argument has a well-defined supported mask, validate the
        // bits BEFORE the handler runs. The handler still executes
        // (it makes its own EINVAL decisions); this just guarantees
        // a structured report entry whenever a bit drifts.
        for (nr, arg_index, mask) in SYSCALL_FLAG_VALIDATORS {
            if *nr == request.number.raw() {
                let value = request.arg(*arg_index as usize);
                check_syscall_flags(
                    reporter,
                    request.number.raw(),
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
            let outcome = lower_handler_result(result)?;
            // Consumption-based EPOLLET re-arm (see `epoll_rearm_after_io`).
            self.epoll_rearm_after_io(&request, &outcome);
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number.raw(),
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
            request.number.raw(),
            name,
            request.args,
        ));
        let outcome = DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        };

        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number.raw(),
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
/// Apply `bytes` to an in-memory file backing at `*offset`, growing it
/// zero-filled if there's a gap and advancing the cursor. Dense files update
/// their vector; rootfs-backed files update only their dirty ranges.
fn write_into_file_contents(
    contents: &mut FileContents,
    offset: &mut usize,
    bytes: &[u8],
) -> Result<(), LinuxErrno> {
    let end = (*offset).checked_add(bytes.len()).ok_or(LINUX_EFBIG)?;
    if end as u64 > crate::vfs::MAX_IN_MEMORY_FILE_SIZE {
        return Err(LINUX_EFBIG);
    }
    contents.write_at(*offset, bytes)?;
    *offset = end;
    Ok(())
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
    let Some(seals) = seals else {
        return Ok(());
    };
    if seals & (LINUX_F_SEAL_WRITE | LINUX_F_SEAL_FUTURE_WRITE) != 0 {
        return Err(LINUX_EPERM);
    }
    if seals & LINUX_F_SEAL_GROW != 0 && offset.saturating_add(write_len) > cur_len {
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
    let Some(seals) = seals else {
        return Ok(());
    };
    if seals & LINUX_F_SEAL_SHRINK != 0 && new_len < cur_len {
        return Err(LINUX_EPERM);
    }
    if seals & LINUX_F_SEAL_GROW != 0 && new_len > cur_len {
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
    // The guest built `abs_ns` on ITS clock, so "now" here MUST read the SAME
    // base or `abs_ns - now` is skewed and the deadline is mis-computed.
    //
    // Non-FUTEX_CLOCK_REALTIME → the guest clock is Linux CLOCK_MONOTONIC, which
    // carrick services via `monotonic_duration()` (Linux host: the *virtualized*
    // libc::CLOCK_MONOTONIC; macOS host: CLOCK_UPTIME_RAW — neither counts
    // suspend). Read "now" from that SAME function, not a raw clock id: reading
    // `carrick_portable::CLOCK_UPTIME_RAW` (== Linux CLOCK_MONOTONIC_RAW) skewed
    // `now` from the guest base by the MONOTONIC vs MONOTONIC_RAW delta — tens of
    // seconds inside an LXC/time-namespace (measured +57s on the KVM box) — so
    // every absolute deadline computed as already-past → instant spurious
    // ETIMEDOUT (broke timed lock/sem/condvar; probe: futexdeadline). On macOS
    // this is identical to the previous CLOCK_UPTIME_RAW read, so the HVF lane is
    // unchanged.
    //
    // The FUTEX_CLOCK_REALTIME case reads the host wall clock, correct because
    // the guest's vDSO CLOCK_REALTIME is calibrated to the same wall clock.
    // Probe: futexrealtime.
    let now_ns: i128 = if realtime {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: clock_gettime writes a timespec for a valid clock id.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
        (now.tv_sec as i128) * 1_000_000_000 + now.tv_nsec as i128
    } else {
        monotonic_duration().as_nanos() as i128
    };
    let rel_ns = (abs_ns - now_ns).max(0);
    Duration::from_nanos(rel_ns.min(u64::MAX as i128) as u64)
}

fn dispatch_futex_pi(
    memory: &mut impl GuestMemory,
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
                let _ = futex.wake(address, 1);
            }
            DispatchOutcome::Returned { value: 0 }
        }
        _ => DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        },
    }
}

fn dispatch_threaded_futex(
    request: SyscallRequest,
    memory: &mut impl GuestMemory,
    reporter: &CompatReporter,
    futex: &crate::thread::FutexTable,
    tid: crate::thread::ThreadId,
    registry: &crate::thread::ThreadRegistry,
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
    if flags & !LinuxFutexFlags::SUPPORTED_MASK != 0 {
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
        let Some(guest_tid) = guest_visible_tid(tid, registry) else {
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
                    location,
                    waiter_key: location.waiter_key(),
                    count: value,
                };
            }
            let n = futex.wake(address, value);
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
                        Ok(t) => Some(t.unwrap_or(std::time::Duration::ZERO)),
                        Err(errno) => return DispatchOutcome::Errno { errno },
                    }
                }
            };
            if let Some(location) = shared_location {
                // The shared path's compare-and-wait is atomic in the kernel
                // (__ulock UL_COMPARE_AND_WAIT re-checks the word), so no
                // generation snapshot is needed here.
                return DispatchOutcome::SharedFutexWait {
                    location,
                    waiter_key: location.waiter_key(),
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
                    from: location,
                    from_key: location.waiter_key(),
                    to: to_location,
                    to_key: to_location.waiter_key(),
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

pub(super) fn dispatch_futex_waitv_args(
    memory: &mut impl GuestMemory,
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
        let private = waiter_flags & LINUX_FUTEX_PRIVATE_FLAG != 0;
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
                location,
                waiter_key: location.waiter_key(),
                value: entry.value,
                timeout,
                index: index as i64,
            };
        }
        if let Some(futex) = futex {
            let wait = futex.prepare_wait(entry.address);
            match read_futex_word(memory, entry.address) {
                Ok(word) if word != entry.value => {
                    return DispatchOutcome::Returned {
                        value: index as i64,
                    };
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

    let start = Instant::now();
    loop {
        for (index, entry) in entries.iter().enumerate() {
            match read_futex_word(memory, entry.address) {
                Ok(word) if word != entry.value => {
                    return DispatchOutcome::Returned {
                        value: index as i64,
                    };
                }
                Ok(_) => {}
                Err(errno) => return DispatchOutcome::Errno { errno },
            }
        }
        if let Some(deadline) = timeout
            && start.elapsed() >= deadline
        {
            return DispatchOutcome::Errno {
                errno: LINUX_ETIMEDOUT,
            };
        }
        std::thread::sleep(Duration::from_millis(1));
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
/// const assert validating `ABI_SIZE <= size_of::<T>()`.
fn write_kernel_struct<T: KernelAbi>(
    memory: &mut impl GuestMemory,
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
    memory: &mut impl GuestMemory,
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
    memory: &mut impl GuestMemory,
    address: u64,
    value: &T,
) -> Result<(), crate::dispatch::MemoryError> {
    memory.write_bytes(address, value.abi_bytes())
}

/// Type-safe read for Linux UAPI structs that implement [`KernelAbi`].
/// Reads exactly the Linux wire size, then zero-fills any Rust-only tail
/// bytes before returning the typed value.
fn read_kernel_struct<T>(memory: &impl GuestMemory, address: u64) -> Result<T, LinuxErrno>
where
    T: KernelAbi + FromBytes,
{
    read_kernel_prefix(memory, address, T::ABI_SIZE)
}

/// Lower-level ABI read for variable-length structs such as clone_args.
/// `length` is the guest-provided prefix length and must fit inside the
/// Linux ABI size carried by the type.
fn read_kernel_prefix<T>(
    memory: &impl GuestMemory,
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

fn linux_min_fd(value: u64) -> Result<i32, LinuxErrno> {
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

fn linux_clock_nanosleep_now(clock_id: u64) -> Result<Duration, LinuxErrno> {
    if matches!(
        clock_id,
        LINUX_CLOCK_PROCESS_CPUTIME_ID | LINUX_CLOCK_THREAD_CPUTIME_ID
    ) || dynamic_cpu_clock(clock_id).is_some()
    {
        return Err(LINUX_EOPNOTSUPP);
    }
    linux_clock_duration(clock_id).ok_or(LINUX_EINVAL)
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

fn adjtimex_bootstrap(memory: &mut impl GuestMemory, address: u64) -> DispatchOutcome {
    let timex = match read_kernel_struct::<LinuxTimex>(memory, address) {
        Ok(timex) => timex,
        Err(errno) => return DispatchOutcome::Errno { errno },
    };
    if timex.modes == 0 {
        let current = LinuxTimex::new_read_state(linux_timeval_from_duration(realtime_duration()));
        return match write_kernel_struct(memory, address, &current) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Returned {
                value: LINUX_TIME_ERROR,
            },
            other => other,
        };
    }
    if timex.modes == LINUX_ADJ_OFFSET_SINGLESHOT_FLAG_ONLY {
        let invalid = LinuxTimex::invalid_mode_error_state();
        return match write_kernel_struct(memory, address, &invalid) {
            DispatchOutcome::Returned { value: 0 } => DispatchOutcome::Errno {
                errno: LINUX_EINVAL,
            },
            other => other,
        };
    }
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

fn linux_task_name_to_string(bytes: &[u8; LINUX_TASK_COMM_LEN]) -> String {
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
    flags & !SUPPORTED == 0
}

fn linux_access_flags_are_supported(flags: u64) -> bool {
    const SUPPORTED: u64 = LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EACCESS | LINUX_AT_EMPTY_PATH;
    flags & !SUPPORTED == 0
}

fn realtime_duration() -> Duration {
    // On macOS/HVF, compute REALTIME the SAME way the guest's vDSO fast path does
    // — the suspend-excluding uptime counter plus the shared realtime_off the vvar
    // page was stamped with — so the trapping clock_gettime read and the userspace
    // vDSO read agree by construction. Reading a live SystemTime::now() here used
    // an unrelated base (wall clock vs guest CNTVCT + boot-stamped offset), so LTP
    // clock_gettime04 (which reads each clock via BOTH paths) saw REALTIME travel
    // backwards. The offset is itself `unix_ns - uptime_ns`, so this still tracks
    // the wall clock (within the boot-stamp's NTP slew, sub-µs over a test). The
    // #[cfg(target_os = "linux")] path keeps the native time-ns-virtualized wall.
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(off_ns) = crate::vdso::realtime_off_ns()
            && let Some(uptime) = host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW)
        {
            return Duration::from_nanos((uptime.as_nanos() as u64).wrapping_add(off_ns));
        }
    }
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

fn boottime_duration() -> Duration {
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
    memory: &mut impl GuestMemory,
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
        st_rdev: record.rdev,
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

fn write_x8664_stat_record(
    memory: &mut impl GuestMemory,
    statbuf: u64,
    record: &StatRecord,
) -> DispatchOutcome {
    let size = record.size_usize();
    let stat = LinuxX8664Stat {
        st_dev: 1,
        st_ino: record.ino,
        st_nlink: record.nlink as u64,
        st_mode: record.mode,
        st_uid: record.uid,
        st_gid: record.gid,
        __pad0: 0,
        st_rdev: record.rdev,
        st_size: record.size as i64,
        st_blksize: 4096,
        st_blocks: blocks_512(size),
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
        uid: 0,
        gid: 0,
        size: st.st_size as u64,
        atime: (st.st_atime, carrick_portable::stat_atime_nsec(st)),
        mtime: (st.st_mtime, carrick_portable::stat_mtime_nsec(st)),
        ctime: (st.st_ctime, carrick_portable::stat_ctime_nsec(st)),
    }
}

/// Build and write a `statx` record from a real backing stat.
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
        // /proc/<pid>/status renders hex words; escape the typed sets at the
        // render boundary.
        let (sig_ignored, sig_caught, sig_shdpnd) = self.proc_status_signal_masks();
        let (sig_ignored, sig_caught, sig_shdpnd) =
            (sig_ignored.raw(), sig_caught.raw(), sig_shdpnd.raw());
        let proc = self.proc.lock();
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
        crate::vfs::SyntheticProcContext {
            executable_path: proc.executable_path.clone(),
            argv: proc.argv.clone(),
            task_comm: linux_task_name_to_string(&proc.task_name),
            timerslack_ns: proc.timerslack,
            guest_arch: proc.reported_arch(),
            guest_hostname: proc.guest_hostname().to_string(),
            environ: proc.env.clone(),
            open_fds: self.open_fd_numbers(),
            network: self.network.spec.clone(),
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
            sysvipc_shm: self.sysvipc_shm_table(),
            sysvipc_sem: self.sysvipc_sem_table(),
            sysvipc_msg: self.sysvipc_msg_table(),
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
    // The counter is a cross-process shared atomic (forked guest processes
    // share the eventfd — LTP eventfd2_03's semaphore ping-pong), so takes are
    // CAS loops and a BLOCKING read parks on the readiness pipe (kernel-shared
    // → a sibling process's write wakes the park) instead of a per-process
    // condvar that another process's write can never signal — which also
    // removes a dispatcher-blocking wait the fork-quiesce could deadlock on.
    let counter = state.counter_ref();
    loop {
        let current = counter.load(std::sync::atomic::Ordering::SeqCst);
        if current == 0 {
            // No readiness pipe (creation failed) keeps the historical `-1`
            // park fd: poll ignores a negative fd, preserving the degraded
            // behavior exactly. Owner stays `None` — the `Arc<EventFdState>`
            // held by the description keeps the pipe alive; no lifetime change.
            let park_fd = state.read_fd.as_ref().map_or(-1, |fd| fd.raw());
            return would_block_outcome(park_fd, libc::POLLIN, nonblocking, None);
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
        // Keep the host readiness pipe in sync (drains it when the counter
        // hits 0, so the read end stops being readable; EFD_SEMAPHORE keeps it
        // readable while the counter is still > 0).
        state.sync_readiness(current - taken);
        return DispatchOutcome::Returned {
            value: core::mem::size_of::<LinuxEventfdValue>() as i64,
        };
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
        // Mirror readiness onto the host pipe so the epoll instance kqueue sees
        // it natively (level-triggered, can't be lost) — the robust path for
        // Go's netpollBreak — and so a sibling PROCESS parked on the pipe wakes.
        state.sync_readiness(next);
        if current == 0 && next > 0 {
            // Belt-and-suspenders for any epoll instance that (rarely)
            // registered the eventfd before its host fd was available: also
            // poke the in-memory wake broadcast. Redundant with the host-backed
            // pipe above; harmless.
            this.notify_inmem_epoll();
        }
        return DispatchOutcome::Returned {
            value: core::mem::size_of::<LinuxEventfdValue>() as i64,
        };
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

fn take_pipe_bytes(
    pipe: &PipeRef,
    length: usize,
    _status_flags: u64,
) -> Result<Vec<u8>, LinuxErrno> {
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

pub(super) fn read_u64(memory: &impl GuestMemory, address: u64) -> Result<u64, LinuxErrno> {
    let mut buf = [0u8; 8];
    memory
        .read_into(address, &mut buf)
        .map_err(|_| LINUX_EFAULT)?;
    Ok(u64::from_ne_bytes(buf))
}

pub(super) fn read_u32(memory: &impl GuestMemory, address: u64) -> Result<u32, LinuxErrno> {
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
pub(super) fn read_futex_word(memory: &impl GuestMemory, address: u64) -> Result<u32, LinuxErrno> {
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
    memory: &mut impl GuestMemory,
    address: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(address, &value.to_ne_bytes())
        .map_err(|_| LINUX_EFAULT)
}

fn read_itimerspec(memory: &impl GuestMemory, address: u64) -> Result<LinuxItimerspec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_itimerval(memory: &impl GuestMemory, address: u64) -> Result<LinuxItimerval, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_timespec(memory: &impl GuestMemory, address: u64) -> Result<LinuxTimespec, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_open_how(memory: &impl GuestMemory, address: u64) -> Result<LinuxOpenHow, LinuxErrno> {
    read_kernel_struct(memory, address)
}

fn read_iovecs(
    memory: &impl GuestMemory,
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

fn read_from_file_contents_at(
    memory: &mut impl GuestMemory,
    contents: &FileContents,
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
        let bytes = contents.read_at(offset, iov_len);
        let read_len = bytes.len();
        if read_len == 0 {
            break;
        }
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
) -> Result<(), LinuxErrno> {
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
    synthetic_readonly_access_with_errno(mode, LINUX_EACCES)
}

fn synthetic_readonly_access_with_errno(mode: u64, write_errno: LinuxErrno) -> DispatchOutcome {
    if mode & LINUX_W_OK != 0 {
        DispatchOutcome::Errno { errno: write_errno }
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

    #[cfg(test)]
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
const SMALL_HOST_READ_BUF: usize = 8192;

/// read(2) on a host-backed fd (pipe/socket/file). Host-backed descriptions are
/// adopted non-blocking at creation time, so EAGAIN means a blocking-mode guest
/// fd hands off to the runtime's lockless kqueue wait via WaitOnFds while a
/// non-blocking guest fd gets EAGAIN. Never blocks under the dispatcher lock.
/// `nonblocking` is the guest's intended mode (status_flags / O_NONBLOCK).
fn read_host_pipe_into(
    memory: &mut impl GuestMemory,
    guest_addr: u64,
    host_fd: i32,
    host_fd_owner: Option<HostFdRef>,
    nonblocking: bool,
    buf: &mut [u8],
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
            return would_block_outcome(host_fd, libc::POLLIN, nonblocking, host_fd_owner);
        }
        return DispatchOutcome::Errno { errno: e };
    }
    let n_usize = n as usize;
    #[cfg(feature = "trace-io")]
    if n_usize > 0 {
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

fn read_host_pipe(
    memory: &mut impl GuestMemory,
    guest_addr: u64,
    length: usize,
    host_fd: i32,
    host_fd_owner: Option<HostFdRef>,
    nonblocking: bool,
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
    } = target;

    #[cfg(feature = "trace-io")]
    if !payload.as_slice().is_empty() {
        let bytes = payload.as_slice();
        eprintln!(
            "[IODBG] WRITE host_fd={host_fd} n={} bytes={:02x?}",
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
                            return DispatchOutcome::Returned {
                                value: offset as i64,
                            };
                        }
                        return match BlockingHostWrite::from_vec(
                            host_fd,
                            payload.into_owned(),
                            offset,
                            tid,
                            sigpipe_on_epipe,
                        ) {
                            Ok(write) => DispatchOutcome::BlockingHostWrite(write),
                            Err(_) => DispatchOutcome::Returned {
                                value: offset as i64,
                            },
                        };
                    }
                    return would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
                    );
                }
                if nonblocking && offset == 0 && len <= 4096 && len > room {
                    return would_block_outcome(
                        host_fd,
                        libc::POLLOUT,
                        nonblocking,
                        host_fd_owner.clone(),
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
                        Ok(written) => DispatchOutcome::Returned {
                            value: written as i64,
                        },
                        Err(errno) => DispatchOutcome::Errno { errno },
                    };
                }
                if block_until_complete && offset > 0 {
                    if crate::host_signal::has_unblocked_pending_for(
                        tid.raw(),
                        carrick_abi::SigBlockMask::NONE,
                    ) {
                        return DispatchOutcome::Returned {
                            value: offset as i64,
                        };
                    }
                    return match BlockingHostWrite::from_vec(
                        host_fd,
                        payload.into_owned(),
                        offset,
                        tid,
                        sigpipe_on_epipe,
                    ) {
                        Ok(write) => DispatchOutcome::BlockingHostWrite(write),
                        Err(_) => DispatchOutcome::Returned {
                            value: offset as i64,
                        },
                    };
                }
                return would_block_outcome(
                    host_fd,
                    libc::POLLOUT,
                    nonblocking,
                    host_fd_owner.clone(),
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
                            Err(_) => DispatchOutcome::Returned {
                                value: offset as i64,
                            },
                        };
                    }
                    return DispatchOutcome::Returned {
                        value: offset as i64,
                    };
                }
                continue;
            }
            return DispatchOutcome::Returned {
                value: payload.as_slice().len() as i64,
            };
        }
        return DispatchOutcome::Returned { value: n as i64 };
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
) -> DispatchOutcome {
    if nonblocking {
        DispatchOutcome::Errno {
            errno: LINUX_EAGAIN,
        }
    } else {
        DispatchOutcome::WaitOnFds {
            fds: WaitFds::anchored_one(host_fd, events, host_fd_owner),
            timeout: None,
            on_timeout: LINUX_EAGAIN.guest_retval(),
            sig_mask: carrick_abi::WaitSigMask::NONE,
        }
    }
}

/// Read a NUL-terminated C string from guest memory as RAW BYTES. Linux paths/
/// argv/env are OPAQUE byte strings, not UTF-8 — e.g. CPython's regrtest sets a
/// non-UTF-8 `PYTHONREGRTEST_UNICODE_GUARD` env var, which made an execve EINVAL
/// when carrick required UTF-8. The execve argv/env path keeps these bytes
/// verbatim; callers needing a Rust `String` (fs path lookup) use the wrapper.
fn read_guest_c_string_bytes(
    memory: &impl GuestMemory,
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
fn read_guest_c_string(memory: &impl GuestMemory, address: u64) -> Result<String, LinuxErrno> {
    Ok(crate::pathcodec::encode_bytes(&read_guest_c_string_bytes(
        memory, address,
    )?))
}

fn should_mount_network_resolv_conf(model: &crate::network::model::LinuxNetworkModel) -> bool {
    model.has_resolver_config()
}

fn resolv_conf_contents_for_network(model: &crate::network::model::LinuxNetworkModel) -> Vec<u8> {
    model.render_resolv_conf()
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
        CARRICK_PRIVATE_X86_SELECT, CARRICK_PRIVATE_X86_STAT,
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
            242,
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
    const SYS_CLONE: u64 = 220;
    const SYS_CLONE3: u64 = 435;
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
    fn host_write_kind_classifies_common_host_fds() {
        use std::os::fd::AsRawFd;

        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        assert_eq!(
            HostWriteKind::for_host_fd(pipe_fds[0]),
            HostWriteKind::PipeLike
        );

        let mut socket_fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, socket_fds.as_mut_ptr())
            },
            0
        );
        assert_eq!(
            HostWriteKind::for_host_fd(socket_fds[0]),
            HostWriteKind::SocketLike
        );

        let file = tempfile::tempfile().expect("tempfile");
        assert_eq!(
            HostWriteKind::for_host_fd(file.as_raw_fd()),
            HostWriteKind::RegularFile
        );

        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
            libc::close(socket_fds[0]);
            libc::close(socket_fds[1]);
        }
    }

    #[test]
    fn large_blocking_host_pipe_write_hands_off_after_partial_progress() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        crate::dispatch::net::set_host_nonblocking(fds[1]);

        let bytes = vec![0xA5; 4 * 1024 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[1],
                host_fd_owner: None,
                nonblocking: false,
                write_kind: HostWriteKind::PipeLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0101),
                sigpipe_on_epipe: true,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::BlockingHostWrite(write) = outcome else {
            panic!("large pipe write should hand off after partial progress, got {outcome:?}");
        };
        assert!(
            write.offset() > 0 && write.offset() < bytes.len(),
            "expected a positive partial offset after filling the pipe, got {}",
            write.offset()
        );
        assert!(write.sigpipe_on_epipe());
    }

    #[test]
    fn large_nonblocking_host_pipe_write_uses_small_ready_window() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        crate::dispatch::net::set_host_nonblocking(fds[1]);

        let chunk = [0xA5; 4096];
        loop {
            let n = unsafe { libc::write(fds[1], chunk.as_ptr().cast(), chunk.len()) };
            if n > 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert!(matches!(
                errno,
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            ));
            break;
        }

        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(fds[0], byte.as_mut_ptr().cast(), 1) },
            1
        );

        let bytes = vec![0x5A; 64 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[1],
                host_fd_owner: None,
                nonblocking: true,
                write_kind: HostWriteKind::PipeLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0103),
                sigpipe_on_epipe: false,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::Returned { value } = outcome else {
            panic!("large nonblocking write should make partial progress, got {outcome:?}");
        };
        assert!(
            value > 0 && (value as usize) < bytes.len(),
            "expected a positive partial write, got {value}"
        );
    }

    #[test]
    fn large_nonblocking_host_socket_write_uses_small_ready_window() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        crate::dispatch::net::set_host_nonblocking(fds[0]);

        let chunk = [0xA5; 4096];
        loop {
            let n = unsafe { libc::write(fds[0], chunk.as_ptr().cast(), chunk.len()) };
            if n > 0 {
                continue;
            }
            let errno = std::io::Error::last_os_error().raw_os_error();
            assert!(matches!(
                errno,
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK
            ));
            break;
        }

        let mut byte = [0u8; 1];
        assert_eq!(
            unsafe { libc::read(fds[1], byte.as_mut_ptr().cast(), 1) },
            1
        );

        let bytes = vec![0x5A; 64 * 1024];
        let outcome = write_host_pipe(
            &bytes,
            HostPipeWriteTarget {
                host_fd: fds[0],
                host_fd_owner: None,
                nonblocking: true,
                write_kind: HostWriteKind::SocketLike,
                pipe_state: None,
                tid: crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0104),
                sigpipe_on_epipe: false,
            },
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let DispatchOutcome::Returned { value } = outcome else {
            panic!("large nonblocking socket write should make partial progress, got {outcome:?}");
        };
        assert!(
            value > 0 && (value as usize) < bytes.len(),
            "expected a positive partial socket write, got {value}"
        );
    }

    #[test]
    fn anchored_wait_fds_keep_host_fd_live_after_open_file_drop() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let owner = HostFdRef::new(fds[0]);
        let open_file = OpenFile::new(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                base: OpenDescriptionBase::new(0),
                host_fd: owner.clone(),
                is_read_end: true,
                pipe_id: 0,
                pty: None,
                bidirectional: false,
                write_kind: HostWriteKind::PipeLike,
            })),
            0,
        );
        let wait_fds = WaitFds::anchored_one(fds[0], libc::POLLIN, Some(owner));
        drop(open_file);

        let mut pollfd = libc::pollfd {
            fd: wait_fds[0].fd(),
            events: wait_fds[0].events(),
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 0);
        // BLOCKING-IO-OK: test-only 1-byte write to a freshly created, empty pipe
        // to make its read end readable; an empty pipe buffer cannot block here.
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
        assert_ne!(pollfd.revents & libc::POLLIN, 0);

        drop(wait_fds);
        unsafe {
            libc::close(fds[1]);
        }
    }

    #[test]
    fn blocking_host_write_from_owned_bytes_reuses_buffer_storage() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

        let bytes = vec![0x5A; 4096];
        let expected_ptr = bytes.as_ptr();
        let expected_capacity = bytes.capacity();
        let write = BlockingHostWrite::from_vec(
            fds[1],
            bytes,
            128,
            crate::thread::ThreadId::synthetic_for_tests(0x7FFE_0102),
            true,
        )
        .expect("blocking write continuation should be created");

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        assert_eq!(
            write.bytes.as_ptr(),
            expected_ptr,
            "owned handoff should move the staged write buffer without cloning it"
        );
        assert_eq!(write.bytes.capacity(), expected_capacity);
        assert_eq!(write.offset(), 128);
        assert!(write.sigpipe_on_epipe());
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
        assert_eq!(supported, vec![96, 98, 99, 124, 178, 449]);

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
    fn exec_host_fs_fallback_off_for_container_dispatchers() {
        // A bare run-elf dispatcher (no container fs) may fall back to the host
        // filesystem for an execve target (host-staged RunElf fixtures).
        assert!(
            SyscallDispatcher::new().exec_host_fs_fallback(),
            "bare new() dispatcher must allow the host-fs execve fallback"
        );
        // A container dispatcher must NOT: a target absent from the rootfs must
        // ENOENT, never escape to the matching host binary (the containment hole
        // that loaded host glibc /usr/bin/echo into a musl rootfs mid-execvp).
        assert!(
            !SyscallDispatcher::with_rootfs(empty_rootfs()).exec_host_fs_fallback(),
            "with_rootfs dispatcher must forbid the host-fs execve fallback"
        );
        assert!(
            !SyscallDispatcher::with_rootfs_and_executable(empty_rootfs(), "/bin/sh")
                .exec_host_fs_fallback(),
            "with_rootfs_and_executable dispatcher must forbid the host-fs execve fallback"
        );
        // The overlay-only container path (run-oci / --fs host use new() +
        // set_fs_backend, not with_rootfs) opts in explicitly.
        let mut d = SyscallDispatcher::new();
        d.sandbox_exec_to_container();
        assert!(
            !d.exec_host_fs_fallback(),
            "sandbox_exec_to_container() must forbid the host-fs execve fallback"
        );
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
            DispatchOutcome::Errno { errno } => errno.get(),
            other => panic!("expected Errno, got {other:?}"),
        }
    }

    #[test]
    fn epoll_et_repolls_host_level_when_mux_misses_wake() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, reader as u64, ev_addr, 0, 0],
            )),
            0
        );

        let byte_addr = h.put_bytes(b"x");
        assert_eq!(
            returned(h.call(64, [writer as u64, byte_addr, 1, 0, 0, 0])),
            1
        );

        let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { kqueue, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let host_fd = h
                .dispatcher
                .host_fd_for_poll(reader)
                .expect("reader should be host-backed");
            kqueue.with_mux(|mux| {
                mux.deregister(host_fd.get())
                    .expect("test setup should remove host wake filter");
            });
        }

        let out_addr = h.reserve(16);
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "epoll_pwait must resample host fd levels when the host wake edge is stale"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, reader as u64);
    }

    #[test]
    fn epoll_et_delivers_new_host_edge_while_level_still_ready() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, reader as u64, ev_addr, 0, 0],
            )),
            0
        );

        let first_addr = h.put_bytes(b"a");
        assert_eq!(
            returned(h.call(64, [writer as u64, first_addr, 1, 0, 0, 0])),
            1
        );
        let out_addr = h.reserve(16);
        assert_eq!(returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])), 1);

        let second_addr = h.put_bytes(b"b");
        assert_eq!(
            returned(h.call(64, [writer as u64, second_addr, 1, 0, 0, 0])),
            1
        );
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "a new host ET edge must be delivered even while the fd remains level-readable"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, reader as u64);
    }

    #[test]
    fn epoll_et_read_via_dup_rearms_registered_sibling() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let reader = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let writer = i32::from_le_bytes(pair[4..8].try_into().unwrap());
        let registered_reader = returned(h.call(23, [reader as u64, 0, 0, 0, 0, 0])) as i32;
        assert_eq!(
            h.dispatcher.host_fd_for_poll(reader),
            h.dispatcher.host_fd_for_poll(registered_reader),
            "dup siblings should share the same host fd"
        );

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(registered_reader as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [
                    epfd,
                    LINUX_EPOLL_CTL_ADD,
                    registered_reader as u64,
                    ev_addr,
                    0,
                    0,
                ],
            )),
            0
        );

        let out_addr = h.reserve(16);
        let first_addr = h.put_bytes(b"a");
        assert_eq!(
            returned(h.call(64, [writer as u64, first_addr, 1, 0, 0, 0])),
            1
        );
        assert_eq!(returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])), 1);

        let read_addr = h.reserve(1);
        let read_args = SyscallArgs::from([reader as u64, read_addr, 1, 0, 0, 0]);
        let read_request = SyscallRequest::new(63, read_args);
        let read_outcome = h
            .dispatcher
            .dispatch(read_request, &mut h.memory, &h.reporter)
            .expect("read dispatch");
        assert_eq!(returned(read_outcome.clone()), 1);
        assert!(
            h.dispatcher.io.epoll_fds.read().contains(&(epfd as i32)),
            "epoll fd should be tracked for rearm"
        );
        h.dispatcher
            .epoll_rearm_after_io(&read_request, &read_outcome);
        {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest
                .get(&registered_reader)
                .expect("registered dup interest");
            assert_eq!(
                slot.last_ready & LINUX_EPOLLIN,
                0,
                "read through a dup sibling must clear the registered fd latch"
            );
        }

        let second_addr = h.put_bytes(b"b");
        assert_eq!(
            returned(h.call(64, [writer as u64, second_addr, 1, 0, 0, 0])),
            1
        );
        let host_fd = h
            .dispatcher
            .host_fd_for_poll(registered_reader)
            .expect("registered reader host fd");
        let mut pfd = libc::pollfd {
            fd: host_fd.get(),
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert_eq!(poll_rc, 1, "second write should make host fd readable");
        assert_ne!(pfd.revents & libc::POLLIN, 0);
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        assert_eq!(
            n, 1,
            "consuming readiness through a dup sibling must re-arm ET interest"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, registered_reader as u64);
    }

    #[test]
    fn epoll_et_delivers_listener_edge_without_read_byte_growth() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let listener = returned(h.call(
            198,
            [LINUX_AF_INET as u64, LINUX_SOCK_STREAM as u64, 0, 0, 0, 0],
        )) as i32;

        let bind_addr = h.reserve(16);
        let mut sockaddr = [0u8; 16];
        sockaddr[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
        sockaddr[2..4].copy_from_slice(&0u16.to_be_bytes());
        sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]);
        h.memory.write_bytes(bind_addr, &sockaddr).unwrap();
        assert_eq!(
            returned(h.call(200, [listener as u64, bind_addr, 16, 0, 0, 0])),
            0
        );
        assert_eq!(returned(h.call(201, [listener as u64, 8, 0, 0, 0, 0])), 0);

        let name_addr = h.reserve(16);
        let name_len_addr = h.reserve(4);
        h.memory
            .write_bytes(name_len_addr, &(16u32).to_ne_bytes())
            .unwrap();
        assert_eq!(
            returned(h.call(204, [listener as u64, name_addr, name_len_addr, 0, 0, 0],)),
            0
        );
        let bound = h.memory.read_bytes(name_addr, 16).unwrap();
        let port = u16::from_be_bytes([bound[2], bound[3]]);
        assert_ne!(port, 0);

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(listener as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, listener as u64, ev_addr, 0, 0],
            )),
            0
        );

        let mut host_addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            host_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        host_addr.sin_family = libc::AF_INET as libc::sa_family_t;
        host_addr.sin_port = port.to_be();
        host_addr.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        };
        let connect_client = || {
            let client = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            assert!(client >= 0, "host client socket");
            let rc = unsafe {
                libc::connect(
                    client,
                    &host_addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "host client connect");
            client
        };

        let out_addr = h.reserve(16);
        let client1 = connect_client();
        assert_eq!(returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])), 1);
        assert_eq!(
            returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0])),
            0,
            "EPOLLET must not blindly redeliver a still-unaccepted listener level"
        );

        let client2 = connect_client();
        let n = returned(h.call(22, [epfd, out_addr, 1, 0, 0, 0]));
        unsafe {
            libc::close(client1);
            libc::close(client2);
        }
        assert_eq!(
            n, 1,
            "a later listener EPOLLET edge must be delivered even though FIONREAD stays zero"
        );
        let out = h.memory.read_bytes(out_addr, 16).unwrap();
        let events = u32::from_le_bytes(out[0..4].try_into().unwrap());
        let data = u64::from_le_bytes(out[8..16].try_into().unwrap());
        assert_ne!(events & LINUX_EPOLLIN, 0);
        assert_eq!(data, listener as u64);
    }

    #[test]
    fn epoll_et_write_eagain_after_partial_write_keeps_write_filter_armed() {
        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let writer = i32::from_le_bytes(pair[0..4].try_into().unwrap());

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLOUT | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(writer as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, writer as u64, ev_addr, 0, 0,],
            )),
            0
        );

        let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
        {
            let mut open = epoll_open.description.write();
            let OpenDescription::Epoll { interest, .. } = &mut *open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get_mut(&writer).expect("writer interest");
            slot.last_ready = LINUX_EPOLLOUT;
            slot.write_backpressured = false;
        }

        let write_request =
            SyscallRequest::new(64, SyscallArgs::from([writer as u64, MEM_BASE, 1, 0, 0, 0]));
        h.dispatcher
            .epoll_rearm_after_io(&write_request, &DispatchOutcome::Returned { value: 1 });
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get(&writer).expect("writer interest");
            assert_eq!(slot.last_ready & LINUX_EPOLLOUT, 0);
            assert!(!slot.write_backpressured);
        }

        h.dispatcher.epoll_rearm_after_io(
            &write_request,
            &DispatchOutcome::Errno {
                errno: LINUX_EAGAIN,
            },
        );
        {
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { interest, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let slot = interest.get(&writer).expect("writer interest");
            assert!(
                slot.write_backpressured,
                "write EAGAIN after a partial nonblocking write must keep EPOLLET/EPOLLOUT armed"
            );
        }
    }

    #[test]
    fn epoll_close_rebinds_shared_host_fd_survivor() {
        use std::time::Duration;

        let mut h = Harness::new();
        let epfd = returned(h.call(20, [0, 0, 0, 0, 0, 0])) as u64;

        let pair_addr = h.reserve(8);
        assert_eq!(
            returned(h.call(
                199,
                [
                    LINUX_AF_UNIX as u64,
                    LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                    0,
                    pair_addr,
                    0,
                    0,
                ],
            )),
            0
        );
        let pair = h.memory.read_bytes(pair_addr, 8).unwrap();
        let survivor = i32::from_le_bytes(pair[0..4].try_into().unwrap());
        let peer = i32::from_le_bytes(pair[4..8].try_into().unwrap());
        let closing_dup = returned(h.call(23, [survivor as u64, 0, 0, 0, 0, 0])) as i32;

        let ev_addr = h.reserve(16);
        let mut ev = [0u8; 16];
        ev[0..4].copy_from_slice(&(LINUX_EPOLLIN | LINUX_EPOLLET).to_le_bytes());
        ev[8..16].copy_from_slice(&(survivor as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, survivor as u64, ev_addr, 0, 0],
            )),
            0
        );

        ev[8..16].copy_from_slice(&(closing_dup as u64).to_le_bytes());
        h.memory.write_bytes(ev_addr, &ev).unwrap();
        assert_eq!(
            returned(h.call(
                21,
                [epfd, LINUX_EPOLL_CTL_ADD, closing_dup as u64, ev_addr, 0, 0,],
            )),
            0
        );

        assert_eq!(returned(h.call(57, [closing_dup as u64, 0, 0, 0, 0, 0])), 0);

        let byte_addr = h.put_bytes(b"x");
        assert_eq!(
            returned(h.call(64, [peer as u64, byte_addr, 1, 0, 0, 0])),
            1
        );

        let delivered_guest_fd = {
            let epoll_open = h.dispatcher.open_file(epfd as i32).expect("epoll fd");
            let open = epoll_open.description.read();
            let OpenDescription::Epoll { kqueue, .. } = &*open else {
                panic!("epfd should be an epoll description");
            };
            let mut events = Vec::new();
            let n = kqueue
                .with_mux(|mux| mux.wait(&mut events, Some(Duration::from_millis(100))))
                .expect("kqueue wait");
            assert!(n > 0, "peer write should wake the epoll instance");
            let io_tokens = events
                .iter()
                .filter(|event| event.readiness.read || event.readiness.write || event.eof)
                .map(|event| (event.token & 0xffff_ffff) as u32 as i32)
                .collect::<Vec<_>>();
            assert_eq!(io_tokens.len(), 1, "expected one routed IO readiness event");
            io_tokens[0]
        };

        assert_eq!(
            delivered_guest_fd, survivor,
            "close of a dup must rebind the shared host-fd registration to a surviving guest fd"
        );
    }

    #[test]
    fn unix_accept_unnamed_peer_writes_family_only_sockaddr() {
        let mut h = Harness::new();
        let listener = returned(h.call(
            198,
            [
                LINUX_AF_UNIX as u64,
                LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                0,
                0,
                0,
                0,
            ],
        )) as i32;
        let client = returned(h.call(
            198,
            [
                LINUX_AF_UNIX as u64,
                LINUX_SOCK_STREAM as u64 | LINUX_O_NONBLOCK,
                0,
                0,
                0,
                0,
            ],
        )) as i32;

        let path = format!("/var/carrick-accept-{}", std::process::id());
        let mut sockaddr = vec![0u8; 2 + path.len() + 1];
        sockaddr[0..2].copy_from_slice(&(LINUX_AF_UNIX as u16).to_ne_bytes());
        sockaddr[2..2 + path.len()].copy_from_slice(path.as_bytes());
        let sockaddr_addr = h.put_bytes(&sockaddr);
        assert_eq!(
            returned(h.call(
                200,
                [
                    listener as u64,
                    sockaddr_addr,
                    sockaddr.len() as u64,
                    0,
                    0,
                    0
                ],
            )),
            0
        );
        assert_eq!(returned(h.call(201, [listener as u64, 1, 0, 0, 0, 0])), 0);
        assert_eq!(
            returned(h.call(
                203,
                [client as u64, sockaddr_addr, sockaddr.len() as u64, 0, 0, 0],
            )),
            0
        );

        let peer_addr = h.reserve(128);
        let peer_len_addr = h.reserve(4);
        h.memory
            .write_bytes(peer_len_addr, &128u32.to_ne_bytes())
            .unwrap();
        let accepted = returned(h.call(202, [listener as u64, peer_addr, peer_len_addr, 0, 0, 0]));
        assert!(
            accepted >= 0,
            "accept must return a guest fd, got {accepted}"
        );

        let peer_len = h.memory.read_bytes(peer_len_addr, 4).unwrap();
        assert_eq!(
            u32::from_ne_bytes(peer_len.try_into().unwrap()),
            2,
            "Linux reports only sa_family for an unnamed AF_UNIX peer"
        );
        let peer = h.memory.read_bytes(peer_addr, 2).unwrap();
        assert_eq!(
            u16::from_ne_bytes(peer.try_into().unwrap()),
            LINUX_AF_UNIX as u16
        );
    }

    /// GROUNDED REGRESSION GATE (Rust, in-tree, cross-platform: macOS kqueue +
    /// Linux epoll-emulation) for the epoll EPOLLET edge-loss hang. It drives the
    /// REAL `epoll_pwait`/`epoll_ctl`/`pipe2` handlers through the threaded
    /// dispatch path, mirroring the Go netpoller + os/exec pipe churn that hung
    /// `go build`: worker threads concurrently create a pipe, register the
    /// read-end EPOLLET in a SHARED epoll, write+close the write-end (EOF), and
    /// wait for a netpoller thread's `epoll_pwait` loop to report it. A pipe
    /// read-end at EOF MUST eventually be reported (EPOLLHUP/EPOLLIN); a lost edge
    /// ⇒ the worker times out ⇒ this test FAILS.
    ///
    /// ROOT CAUSE (fixed): `close(fd)` freed the fd number from `open_files` and
    /// only THEN detached it from epoll interest sets. In the window between, a
    /// sibling thread recycled that fd number and `epoll_ctl(ADD)`d it, and the
    /// late detach ripped out the NEW registration's interest — whose EPOLLET edge
    /// then never re-fired. Fixed by detaching BEFORE freeing the fd number (see
    /// `close` in dispatch/fs.rs). Routing is hardened with a generational udata
    /// handle (`EpollInterest::reg_gen`) against the residual drain-then-recycle
    /// ABA. Was RED on every run pre-fix (~3-5s); GREEN in ~0.1s after.
    #[cfg(unix)]
    #[test]
    fn epoll_et_pipe_eof_not_lost_under_concurrent_churn() {
        use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        const NWORKERS: usize = 6;
        const TOTAL: usize = 600;
        const EPOLLIN: u32 = 0x1;
        const EPOLLHUP: u32 = 0x10;
        const EPOLLERR: u32 = 0x8;
        const EPOLLET: u32 = 0x8000_0000;
        const CTL_ADD: u64 = 1;
        const CTL_DEL: u64 = 2;
        const EV_STRIDE: u64 = 16; // aarch64 LinuxEpollEvent stride

        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let futex = crate::thread::FutexTable::new();

        // Create the shared epoll instance up front.
        let epfd = {
            let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
            let out = dispatcher
                .dispatch_threaded(
                    SyscallRequest::new(20, SyscallArgs::from([0u64; 6])),
                    &mut mem,
                    &reporter,
                    crate::thread::ThreadId::synthetic_for_tests(1),
                    &registry,
                    &futex,
                )
                .expect("epoll_create1");
            returned(out) as u64
        };

        let eof_seen: Vec<AtomicBool> = (0..TOTAL).map(|_| AtomicBool::new(false)).collect();
        let next_slot = AtomicUsize::new(0);
        let active = AtomicUsize::new(NWORKERS);
        let stop = AtomicBool::new(false);
        let failed = AtomicI64::new(-1);

        let dispatcher = &dispatcher;
        let reporter = &reporter;
        let registry = &registry;
        let futex = &futex;
        let eof_seen = &eof_seen;
        let next_slot = &next_slot;
        let active = &active;
        let stop = &stop;
        let failed = &failed;

        std::thread::scope(|s| {
            // ---- netpoller ----
            s.spawn(move || {
                let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                let ev_buf = MEM_BASE + 0x800;
                let max = 32u64;
                while !stop.load(Ordering::Relaxed) {
                    let out = dispatcher
                        .dispatch_threaded(
                            SyscallRequest::new(
                                22,
                                SyscallArgs::from([epfd, ev_buf, max, 50, 0, 0]),
                            ),
                            &mut mem,
                            reporter,
                            crate::thread::ThreadId::synthetic_for_tests(2),
                            registry,
                            futex,
                        )
                        .expect("epoll_pwait");
                    match out {
                        DispatchOutcome::Returned { value } if value > 0 => {
                            for i in 0..(value as u64) {
                                let off = ev_buf + i * EV_STRIDE;
                                let b = mem.read_bytes(off, 16).unwrap();
                                let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
                                let data = u64::from_le_bytes(b[8..16].try_into().unwrap());
                                let slot = data as usize;
                                if events & (EPOLLHUP | EPOLLIN | EPOLLERR) != 0 && slot < TOTAL {
                                    eof_seen[slot].store(true, Ordering::Relaxed);
                                }
                            }
                        }
                        DispatchOutcome::Returned { .. } => {}
                        DispatchOutcome::WaitOnPollFds { fds, timeout, .. } => {
                            if let Some((fd, events)) = fds.first() {
                                let mut pfd = libc::pollfd {
                                    fd,
                                    events,
                                    revents: 0,
                                };
                                let ms =
                                    timeout.map(|d| d.as_millis().min(50) as i32).unwrap_or(50);
                                // SAFETY: one valid pollfd, bounded non-blocking wait.
                                unsafe {
                                    libc::poll(&mut pfd, 1, ms);
                                }
                            }
                        }
                        DispatchOutcome::WaitOnFds { timeout, .. } => {
                            let ms = timeout.map(|d| d.as_millis().min(50) as u64).unwrap_or(50);
                            std::thread::sleep(Duration::from_millis(ms));
                        }
                        _ => {}
                    }
                }
            });

            // ---- workers ----
            for w in 0..NWORKERS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(100 + w as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let wbuf = MEM_BASE + 0x140;
                    mem.write_bytes(wbuf, b"x").unwrap();
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    loop {
                        if stop.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) >= 0 {
                            break;
                        }
                        let slot = next_slot.fetch_add(1, Ordering::Relaxed);
                        if slot >= TOTAL {
                            break;
                        }
                        // pipe2(0): carrick makes the host ends non-blocking itself.
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        // epoll_ctl ADD rd, EPOLLIN|EPOLLET, data=slot
                        let mut ev = [0u8; 16];
                        ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                        ev[8..16].copy_from_slice(&(slot as u64).to_le_bytes());
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        // write a byte, then close the write end (EOF).
                        call(&mut mem, 64, [wr, wbuf, 1, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                        // The read-end is now at EOF — the netpoller MUST report it.
                        let t0 = Instant::now();
                        while !eof_seen[slot].load(Ordering::Relaxed) {
                            if t0.elapsed() > Duration::from_secs(3) {
                                failed.store(slot as i64, Ordering::Relaxed);
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            std::thread::yield_now();
                        }
                        call(&mut mem, 21, [epfd, CTL_DEL, rd, 0, 0, 0]);
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                    }
                    if active.fetch_sub(1, Ordering::Relaxed) == 1 {
                        stop.store(true, Ordering::Relaxed);
                    }
                });
            }
        });

        let f = failed.load(Ordering::Relaxed);
        assert!(
            f < 0,
            "epoll LOST the EOF edge for slot {f} under concurrent churn \
             (the Go-netpoller hang); native epoll never does this"
        );
    }

    /// FOCUSED regression gate for the close/reuse/detach ORDERING race that
    /// caused the edge-loss above. It isolates the exact mechanism: dedicated
    /// "recycler" threads `epoll_ctl(ADD)` a pipe read-end and immediately
    /// `close()` it with NO `EPOLL_CTL_DEL`, so `close`'s `detach_fd_from_epolls`
    /// is the sole remover AND the freed fd number is fed straight back to a
    /// victim's next `pipe2`. If `close` frees the fd number before detaching,
    /// the recycler's late detach rips out the victim's freshly-registered
    /// interest for that recycled fd and its EOF edge is lost. Distinct from the
    /// symmetric stress test above, which uses DEL+close; here close-detach is the
    /// only path under test. Was RED pre-fix; GREEN after detach-before-free.
    #[cfg(unix)]
    #[test]
    fn epoll_close_recycle_does_not_drop_interest() {
        use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
        use std::time::{Duration, Instant};

        const VICTIMS: usize = 4;
        const RECYCLERS: usize = 2;
        const TOTAL: usize = 400;
        const EPOLLIN: u32 = 0x1;
        const EPOLLHUP: u32 = 0x10;
        const EPOLLERR: u32 = 0x8;
        const EPOLLET: u32 = 0x8000_0000;
        const CTL_ADD: u64 = 1;
        const CTL_DEL: u64 = 2;
        const EV_STRIDE: u64 = 16;

        let dispatcher = SyscallDispatcher::with_rootfs(empty_rootfs());
        let reporter = CompatReporter::default();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let futex = crate::thread::FutexTable::new();

        let epfd = {
            let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
            let out = dispatcher
                .dispatch_threaded(
                    SyscallRequest::new(20, SyscallArgs::from([0u64; 6])),
                    &mut mem,
                    &reporter,
                    crate::thread::ThreadId::synthetic_for_tests(1),
                    &registry,
                    &futex,
                )
                .expect("epoll_create1");
            returned(out) as u64
        };

        let eof_seen: Vec<AtomicBool> = (0..TOTAL).map(|_| AtomicBool::new(false)).collect();
        let next_slot = AtomicUsize::new(0);
        let active = AtomicUsize::new(VICTIMS);
        let stop = AtomicBool::new(false);
        let failed = AtomicI64::new(-1);

        let dispatcher = &dispatcher;
        let reporter = &reporter;
        let registry = &registry;
        let futex = &futex;
        let eof_seen = &eof_seen;
        let next_slot = &next_slot;
        let active = &active;
        let stop = &stop;
        let failed = &failed;

        std::thread::scope(|s| {
            // ---- netpoller ----
            s.spawn(move || {
                let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                let ev_buf = MEM_BASE + 0x800;
                let max = 32u64;
                while !stop.load(Ordering::Relaxed) {
                    let out = dispatcher
                        .dispatch_threaded(
                            SyscallRequest::new(
                                22,
                                SyscallArgs::from([epfd, ev_buf, max, 50, 0, 0]),
                            ),
                            &mut mem,
                            reporter,
                            crate::thread::ThreadId::synthetic_for_tests(2),
                            registry,
                            futex,
                        )
                        .expect("epoll_pwait");
                    match out {
                        DispatchOutcome::Returned { value } if value > 0 => {
                            for i in 0..(value as u64) {
                                let off = ev_buf + i * EV_STRIDE;
                                let b = mem.read_bytes(off, 16).unwrap();
                                let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
                                let data = u64::from_le_bytes(b[8..16].try_into().unwrap());
                                let slot = data as usize;
                                if events & (EPOLLHUP | EPOLLIN | EPOLLERR) != 0 && slot < TOTAL {
                                    eof_seen[slot].store(true, Ordering::Relaxed);
                                }
                            }
                        }
                        DispatchOutcome::Returned { .. } => {}
                        DispatchOutcome::WaitOnPollFds { fds, timeout, .. } => {
                            if let Some((fd, events)) = fds.first() {
                                let mut pfd = libc::pollfd {
                                    fd,
                                    events,
                                    revents: 0,
                                };
                                let ms =
                                    timeout.map(|d| d.as_millis().min(50) as i32).unwrap_or(50);
                                // SAFETY: one valid pollfd, bounded non-blocking wait.
                                unsafe {
                                    libc::poll(&mut pfd, 1, ms);
                                }
                            }
                        }
                        DispatchOutcome::WaitOnFds { timeout, .. } => {
                            let ms = timeout.map(|d| d.as_millis().min(50) as u64).unwrap_or(50);
                            std::thread::sleep(Duration::from_millis(ms));
                        }
                        _ => {}
                    }
                }
            });

            // ---- recyclers: ADD a read-end then close it (NO DEL) to churn fd
            // numbers through close()'s detach path while victims reuse them. ----
            for r in 0..RECYCLERS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(200 + r as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    let mut ev = [0u8; 16];
                    ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                    while !stop.load(Ordering::Relaxed) {
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        // close the read-end WITHOUT DEL: close()'s detach is the
                        // remover, and rd's number is now free for a victim's pipe2.
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                    }
                });
            }

            // ---- victims ----
            for w in 0..VICTIMS {
                s.spawn(move || {
                    let mut mem = LinearMemory::new(MEM_BASE, vec![0u8; MEM_LEN]);
                    let tid = crate::thread::ThreadId::synthetic_for_tests(100 + w as i32);
                    let pipe_out = MEM_BASE + 0x100;
                    let ev_in = MEM_BASE + 0x120;
                    let wbuf = MEM_BASE + 0x140;
                    mem.write_bytes(wbuf, b"x").unwrap();
                    let call =
                        |mem: &mut LinearMemory, num: u64, args: [u64; 6]| -> DispatchOutcome {
                            dispatcher
                                .dispatch_threaded(
                                    SyscallRequest::new(num, SyscallArgs::from(args)),
                                    mem,
                                    reporter,
                                    tid,
                                    registry,
                                    futex,
                                )
                                .expect("dispatch")
                        };
                    loop {
                        if stop.load(Ordering::Relaxed) || failed.load(Ordering::Relaxed) >= 0 {
                            break;
                        }
                        let slot = next_slot.fetch_add(1, Ordering::Relaxed);
                        if slot >= TOTAL {
                            break;
                        }
                        if !matches!(
                            call(&mut mem, 59, [pipe_out, 0, 0, 0, 0, 0]),
                            DispatchOutcome::Returned { value: 0 }
                        ) {
                            continue;
                        }
                        let fp = mem.read_bytes(pipe_out, 8).unwrap();
                        let rd = i32::from_le_bytes(fp[0..4].try_into().unwrap()) as u64;
                        let wr = i32::from_le_bytes(fp[4..8].try_into().unwrap()) as u64;
                        let mut ev = [0u8; 16];
                        ev[0..4].copy_from_slice(&(EPOLLIN | EPOLLET).to_le_bytes());
                        ev[8..16].copy_from_slice(&(slot as u64).to_le_bytes());
                        mem.write_bytes(ev_in, &ev).unwrap();
                        call(&mut mem, 21, [epfd, CTL_ADD, rd, ev_in, 0, 0]);
                        call(&mut mem, 64, [wr, wbuf, 1, 0, 0, 0]);
                        call(&mut mem, 57, [wr, 0, 0, 0, 0, 0]);
                        let t0 = Instant::now();
                        while !eof_seen[slot].load(Ordering::Relaxed) {
                            if t0.elapsed() > Duration::from_secs(3) {
                                failed.store(slot as i64, Ordering::Relaxed);
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                            std::thread::yield_now();
                        }
                        call(&mut mem, 21, [epfd, CTL_DEL, rd, 0, 0, 0]);
                        call(&mut mem, 57, [rd, 0, 0, 0, 0, 0]);
                    }
                    if active.fetch_sub(1, Ordering::Relaxed) == 1 {
                        stop.store(true, Ordering::Relaxed);
                    }
                });
            }
        });

        let f = failed.load(Ordering::Relaxed);
        assert!(
            f < 0,
            "epoll lost the EOF edge for slot {f}: a sibling close() recycled the \
             fd number and a detach-after-free dropped the victim's new interest"
        );
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

    #[test]
    fn clone_thread_requires_thread_bit_not_pthread_superset() {
        let mut h = Harness::new();
        let flags = LinuxCloneFlags::VM.bits()
            | LinuxCloneFlags::SIGHAND.bits()
            | LinuxCloneFlags::THREAD.bits()
            | LinuxCloneFlags::CHILD_CLEARTID.bits()
            | u64::from(crate::linux_abi::LINUX_SIGCHLD as u32);
        let child_tid = h.reserve(4);

        let outcome = h.call(SYS_CLONE, [flags, MEM_BASE + 0x800, 0, 0, child_tid, 0]);

        assert!(matches!(
            outcome,
            DispatchOutcome::CloneThread {
                child_tid_addr,
                clear_child_tid_addr,
                tls: None,
                parent_tid_addr: 0,
                ..
            } if child_tid_addr == 0 && clear_child_tid_addr == child_tid
        ));
    }

    #[test]
    fn clone_preserves_parent_and_tid_pointer_semantics_for_fork_path() {
        let mut h = Harness::new();
        let parent_tid = h.reserve(4);
        let child_tid = h.reserve(4);
        let flags = LinuxCloneFlags::PARENT.bits()
            | LinuxCloneFlags::PARENT_SETTID.bits()
            | LinuxCloneFlags::CHILD_SETTID.bits()
            | u64::from(crate::linux_abi::LINUX_SIGCHLD as u32);

        let outcome = h.call(SYS_CLONE, [flags, 0, parent_tid, 0, child_tid, 0]);

        assert!(matches!(
            outcome,
            DispatchOutcome::Fork {
                clone_parent: true,
                parent_tid_addr: Some(p),
                child_tid_addr: Some(c),
                ..
            } if p == parent_tid && c == child_tid
        ));
    }

    #[test]
    fn clone3_preserves_parent_and_tid_pointer_semantics_for_fork_path() {
        let mut h = Harness::new();
        let args_addr = h.reserve(<LinuxCloneArgs as KernelAbi>::ABI_SIZE);
        let parent_tid = h.reserve(4);
        let child_tid = h.reserve(4);
        let args = LinuxCloneArgs {
            flags: LinuxCloneFlags::PARENT.bits()
                | LinuxCloneFlags::PARENT_SETTID.bits()
                | LinuxCloneFlags::CHILD_SETTID.bits(),
            pidfd: 0,
            child_tid,
            parent_tid,
            exit_signal: u64::from(crate::linux_abi::LINUX_SIGCHLD as u32),
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        h.memory.write_bytes(args_addr, args.abi_bytes()).unwrap();

        let outcome = h.call(
            SYS_CLONE3,
            [
                args_addr,
                <LinuxCloneArgs as KernelAbi>::ABI_SIZE as u64,
                0,
                0,
                0,
                0,
            ],
        );

        assert!(matches!(
            outcome,
            DispatchOutcome::Fork {
                clone_parent: true,
                parent_tid_addr: Some(p),
                child_tid_addr: Some(c),
                ..
            } if p == parent_tid && c == child_tid
        ));
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
        assert_eq!(errno(outcome), LINUX_ENOENT.get());
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
        assert_eq!(errno(outcome), LINUX_ENOENT.get());

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

    #[cfg(target_os = "macos")]
    #[test]
    fn host_syscall_result_translates_captured_host_errno() {
        use crate::dispatch::HostSyscallResult;
        use carrick_host_bsd::errno::linux_errno;

        carrick_portable::set_errno(libc::EINPROGRESS);
        let err = (-1i32).host_syscall_result().unwrap_err();
        assert_eq!(err.raw_errno(), libc::EINPROGRESS);
        assert_eq!(err.linux_errno(), linux_errno::EINPROGRESS);
        assert_ne!(err.linux_errno().get(), libc::EINPROGRESS);

        carrick_portable::set_errno(libc::EAGAIN);
        assert_eq!(
            (-1isize).host_syscall_result().unwrap_err().linux_errno(),
            linux_errno::EAGAIN
        );

        carrick_portable::set_errno(libc::ECONNREFUSED);
        assert_eq!(
            (-1i64).host_syscall_errno().unwrap_err(),
            linux_errno::ECONNREFUSED
        );

        assert_eq!(0i32.host_syscall_result().unwrap(), 0);
    }

    /// A MAP_SHARED futex word the dispatcher's software memory view can't
    /// translate (read fails) must still be read via the fork-coherent shared
    /// host pointer — never surfaced as EFAULT, which aborts glibc's futex code.
    /// Regression for the CPython multiprocessing SyncManager SIGABRT (a forked
    /// child's timed wait on a shared semaphore at the high mmap aperture).
    #[test]
    fn read_futex_word_falls_back_to_shared_mapping() {
        struct SharedOnly {
            word: u32,
        }
        impl GuestMemory for SharedOnly {
            fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
                Err(MemoryError::OutOfBounds { address, length })
            }
            fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })
            }
            fn shared_futex_location(
                &self,
                _guest_addr: u64,
            ) -> Option<carrick_guest_mem::SharedFutexLocation> {
                Some(carrick_guest_mem::SharedFutexLocation::Direct {
                    word: HostVa(&self.word as *const u32 as usize),
                    waiter_key: &self.word as *const u32 as usize,
                })
            }
        }
        // Software read fails, but the shared host pointer yields the word.
        let mem = SharedOnly { word: 0x00C0_FFEE };
        assert_eq!(read_futex_word(&mem, 0x0100_0160_0000), Ok(0x00C0_FFEE));

        // No shared mapping -> EFAULT propagates unchanged (no regression for
        // a genuinely bad private/anon address).
        let lin = LinearMemory::new(0x1000, vec![0u8; 8]);
        assert_eq!(read_futex_word(&lin, 0x9_9999_9999), Err(LINUX_EFAULT));
    }

    struct CountingMemory {
        base: u64,
        bytes: Vec<u8>,
        reads: std::cell::Cell<usize>,
        writes: std::cell::Cell<usize>,
        shared_futex_lookups: std::cell::Cell<usize>,
    }

    impl CountingMemory {
        fn new(base: u64, bytes: Vec<u8>) -> Self {
            Self {
                base,
                bytes,
                reads: std::cell::Cell::new(0),
                writes: std::cell::Cell::new(0),
                shared_futex_lookups: std::cell::Cell::new(0),
            }
        }
    }

    impl GuestMemory for CountingMemory {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
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

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.writes.set(self.writes.get() + 1);
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

        fn shared_futex_location(
            &self,
            _guest_addr: u64,
        ) -> Option<carrick_guest_mem::SharedFutexLocation> {
            self.shared_futex_lookups
                .set(self.shared_futex_lookups.get() + 1);
            None
        }
    }

    #[test]
    fn private_futex_wake_skips_shared_mapping_lookup() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        memory.write_bytes(0x10800, &0u32.to_le_bytes()).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([
                0x10800,
                LINUX_FUTEX_WAKE | LinuxFutexFlags::PRIVATE.bits(),
                1,
                0,
                0,
                0,
            ]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.shared_futex_lookups.get(), 0);
    }

    #[test]
    fn non_private_futex_wake_checks_shared_mapping_lookup() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        memory.write_bytes(0x10800, &0u32.to_le_bytes()).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([0x10800, LINUX_FUTEX_WAKE, 1, 0, 0, 0]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
        );

        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        assert_eq!(memory.shared_futex_lookups.get(), 1);
    }

    /// Task 7 fix #4: a non-private `FUTEX_WAKE` whose word lives in a genuine
    /// `MAP_SHARED` mapping (`shared_futex_location` → `Some`) must be routed
    /// through the `PlatformFutex::shared_wake` seam — i.e. returned as a
    /// `DispatchOutcome::SharedFutexWake`, NOT a `Returned` from an inline
    /// `ulock::wake`. The loop then drives the backend wake (HVF __ulock / KVM
    /// SYS_futex), keeping the shared wait+wake pair on ONE seam. (Before the fix
    /// the dispatcher called `ulock::wake` directly, so `KvmFutex::shared_wake`
    /// was never reached on Linux.)
    #[test]
    fn shared_futex_wake_routes_through_platform_seam() {
        struct SharedWord {
            word: u32,
        }
        impl GuestMemory for SharedWord {
            fn read_bytes_raw(&self, _address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
                Ok(self.word.to_le_bytes()[..length.min(4)].to_vec())
            }
            fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::OutOfBounds {
                    address,
                    length: bytes.len(),
                })
            }
            fn shared_futex_location(
                &self,
                _guest_addr: u64,
            ) -> Option<carrick_guest_mem::SharedFutexLocation> {
                Some(carrick_guest_mem::SharedFutexLocation::Direct {
                    word: HostVa(&self.word as *const u32 as usize),
                    waiter_key: &self.word as *const u32 as usize,
                })
            }
        }
        let mut memory = SharedWord { word: 0 };
        let location = carrick_guest_mem::SharedFutexLocation::Direct {
            word: HostVa(&memory.word as *const u32 as usize),
            waiter_key: &memory.word as *const u32 as usize,
        };
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        // Non-private FUTEX_WAKE (no PRIVATE flag) of up to 3 waiters.
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([0x10800, LINUX_FUTEX_WAKE, 3, 0, 0, 0]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
        );

        assert_eq!(
            outcome,
            DispatchOutcome::SharedFutexWake {
                location,
                waiter_key: location.waiter_key(),
                count: 3,
            },
            "a shared FUTEX_WAKE must defer to the PlatformFutex::shared_wake seam"
        );
    }

    /// On the LIVE multithreaded futex path (`dispatch_threaded_futex`), a present
    /// (non-NULL) `{tv_sec:0, tv_nsec:0}` relative `FUTEX_WAIT` timeout means
    /// "expire NOW" (ETIMEDOUT immediately), NOT "block forever" (the NULL-timeout
    /// case). Commit 519dd40f fixed this on the proc.rs `dispatch_normalized` path
    /// but the threaded path still collapsed `{0,0}` to `None`, parking forever.
    /// The parked `FutexWait` must carry `Some(Duration::ZERO)` (a deadline of
    /// `now`), never `None`.
    #[test]
    fn threaded_futex_wait_zero_but_present_timeout_parks_with_zero_deadline() {
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        // Futex word == the expected value, so WAIT does not short-circuit to
        // EAGAIN and must consult the timeout.
        memory.write_bytes(0x10800, &7u32.to_le_bytes()).unwrap();
        // A present (non-NULL) relative timespec of {0, 0} at 0x10810.
        memory.write_bytes(0x10810, &[0u8; 16]).unwrap();
        let reporter = CompatReporter::default();
        let futex = crate::thread::FutexTable::new();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(1000));
        // Private FUTEX_WAIT (no shared mapping) so the park stays in the
        // in-process parking-lot table and returns a `FutexWait` outcome.
        let request = SyscallRequest::new(
            98,
            SyscallArgs::from([
                0x10800,
                LINUX_FUTEX_WAIT | LinuxFutexFlags::PRIVATE.bits(),
                7,
                0x10810,
                0,
                0,
            ]),
        );

        let outcome = dispatch_threaded_futex(
            request,
            &mut memory,
            &reporter,
            &futex,
            crate::thread::ThreadId::synthetic_for_tests(1001),
            &registry,
        );

        match outcome {
            DispatchOutcome::FutexWait { timeout, .. } => assert_eq!(
                timeout,
                Some(std::time::Duration::ZERO),
                "a present {{0,0}} timeout must park with a zero deadline (expire now), \
                 not None (block forever)"
            ),
            other => panic!("expected a FutexWait park outcome, got {other:?}"),
        }
    }

    #[test]
    fn fresh_shared_anon_mmap_skips_zero_write() {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);

        let outcome = dispatcher
            .dispatch(
                SyscallRequest::new(
                    222,
                    SyscallArgs::from([
                        0,
                        0x4000,
                        LINUX_PROT_READ | LINUX_PROT_WRITE,
                        LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
                        u64::MAX,
                        0,
                    ]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();

        assert_eq!(
            outcome,
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        assert_eq!(
            memory.writes.get(),
            0,
            "fresh MAP_SHARED|MAP_ANON should use the boot-zeroed shared aperture without materializing a zero buffer"
        );
        assert!(reporter.finish().unhandled_syscalls.is_empty());
    }

    #[test]
    fn reused_shared_anon_mmap_zeroes_recycled_range() {
        let reporter = CompatReporter::default();
        let mut dispatcher = SyscallDispatcher::new();
        let mut memory = CountingMemory::new(0x10000, vec![0u8; 0x1000]);
        let mmap_args = SyscallArgs::from([
            0,
            0x4000,
            LINUX_PROT_READ | LINUX_PROT_WRITE,
            LINUX_MAP_SHARED | LINUX_MAP_ANONYMOUS,
            u64::MAX,
            0,
        ]);

        assert_eq!(
            dispatcher
                .dispatch(SyscallRequest::new(222, mmap_args), &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        memory.writes.set(0);

        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        215,
                        SyscallArgs::from([
                            crate::memory::LINUX_SHARED_FILE_BASE,
                            0x4000,
                            0,
                            0,
                            0,
                            0,
                        ]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 }
        );
        memory.writes.set(0);

        assert_eq!(
            dispatcher
                .dispatch(SyscallRequest::new(222, mmap_args), &mut memory, &reporter)
                .unwrap(),
            DispatchOutcome::Returned {
                value: crate::memory::LINUX_SHARED_FILE_BASE as i64
            }
        );
        assert_eq!(
            memory.writes.get(),
            1,
            "reused MAP_SHARED|MAP_ANON ranges must still be scrubbed before reuse"
        );
        assert!(reporter.finish().unhandled_syscalls.is_empty());
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

    #[test]
    fn dns_overrides_render_resolv_conf() {
        let spec = carrick_spec::NetworkNamespaceSpec {
            dns_servers: vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            dns_search: vec!["example.test".to_string()],
            dns_options: vec!["ndots:2".to_string()],
            ..Default::default()
        };

        let model = crate::network::model::LinuxNetworkModel::from_spec(&spec);
        let contents = String::from_utf8(resolv_conf_contents_for_network(&model)).unwrap();
        assert!(contents.contains("nameserver 1.1.1.1\n"));
        assert!(contents.contains("nameserver 9.9.9.9\n"));
        assert!(contents.contains("search example.test\n"));
        assert!(contents.contains("options ndots:2\n"));
    }

    #[test]
    fn with_network_mounts_sys_class_net_from_model() {
        let mut spec = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        spec.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web-front".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 44)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["web-back".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 44)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;
        let network = std::sync::Arc::new(crate::network::RuntimeNetwork::create(&spec).unwrap());
        let dispatcher = SyscallDispatcher::with_network(network);
        let sys = dispatcher.fs.vfs_mounts.resolve("/sys/class/net").unwrap();

        let names = sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["lo", "eth0", "eth1"]);

        let eth1 = sys
            .vfs
            .open(
                "/sys/class/net/eth1/ifindex",
                crate::vfs::OpenFlags::default(),
                &crate::vfs::OpenContext::default(),
            )
            .unwrap();
        let crate::vfs::VfsHandle::Bytes { contents, .. } = eth1 else {
            panic!("model-backed /sys/class/net ifindex should open as bytes");
        };
        assert_eq!(String::from_utf8(contents).unwrap(), "3\n");
    }

    #[test]
    fn with_host_network_preserves_host_sys_class_net() {
        let default_dispatcher = SyscallDispatcher::new();
        let default_sys = default_dispatcher
            .fs
            .vfs_mounts
            .resolve("/sys/class/net")
            .unwrap();
        let expected = default_sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        let network = std::sync::Arc::new(crate::network::RuntimeNetwork::host_default());
        let host_dispatcher = SyscallDispatcher::with_network(network);
        let host_sys = host_dispatcher
            .fs
            .vfs_mounts
            .resolve("/sys/class/net")
            .unwrap();

        let actual = host_sys
            .vfs
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    /// The Linux errno constants we publish must match the
    /// asm-generic kernel headers. Pinned values from
    /// linux/include/uapi/asm-generic/errno{,-base}.h.
    #[test]
    fn linux_errno_constants_match_kernel_uapi() {
        use crate::dispatch::linux_errno::*;
        assert_eq!(EPERM.get(), 1);
        assert_eq!(ENOENT.get(), 2);
        assert_eq!(EAGAIN.get(), 11);
        assert_eq!(ENOMEM.get(), 12);
        assert_eq!(EFAULT.get(), 14);
        assert_eq!(EINVAL.get(), 22);
        assert_eq!(ESPIPE.get(), 29);
        assert_eq!(EDEADLK.get(), 35);
        assert_eq!(ENAMETOOLONG.get(), 36);
        assert_eq!(ENOSYS.get(), 38);
        assert_eq!(EINPROGRESS.get(), 115);
        assert_eq!(ETIMEDOUT.get(), 110);
        assert_eq!(ECONNREFUSED.get(), 111);
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

#[cfg(test)]
mod container_policy_dispatch_tests {
    //! End-to-end tests for the launch-time container syscall policy at the
    //! dispatch-entry seam: deny hit, miss passthrough, unconfined opt-out
    //! (handlers stay honest ENOSYS), both dispatch paths, fork inheritance,
    //! and survival across the dispatcher's execve-time state resets.
    use super::*;
    use crate::compat::CompatReporter;
    use carrick_spec::SeccompPolicy;

    const SYS_ADD_KEY: u64 = 217;
    const SYS_REQUEST_KEY: u64 = 218;
    const SYS_KEYCTL: u64 = 219;
    const SYS_GETPID: u64 = 172;
    const MEM_BASE: u64 = 0x4000_0000;

    fn confined_dispatcher() -> SyscallDispatcher {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.apply_seccomp_policy(SeccompPolicy::ContainerDefault);
        dispatcher
    }

    fn dispatch_one(dispatcher: &mut SyscallDispatcher, nr: u64) -> DispatchOutcome {
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        dispatcher
            .dispatch(
                SyscallRequest::new(nr, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch")
    }

    #[test]
    fn policy_denies_keyring_family_with_eperm_before_handler() {
        let mut dispatcher = confined_dispatcher();
        for nr in [SYS_ADD_KEY, SYS_REQUEST_KEY, SYS_KEYCTL] {
            assert_eq!(
                dispatch_one(&mut dispatcher, nr),
                DispatchOutcome::Errno { errno: LINUX_EPERM },
                "syscall {nr} must be policy-denied EPERM at dispatch entry"
            );
        }
    }

    #[test]
    fn policy_denial_reports_as_policy_not_unimplemented() {
        let dispatcher = confined_dispatcher();
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        let mut dispatcher = dispatcher;
        dispatcher
            .dispatch(
                SyscallRequest::new(SYS_ADD_KEY, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
            )
            .expect("dispatch");
        let report = reporter.snapshot();
        assert!(
            report
                .partial_syscalls
                .iter()
                .any(|e| e.name == "add_key" && e.reason.contains("container syscall policy")),
            "policy denial must surface as a policy event: {report:?}"
        );
        assert!(
            !report
                .unhandled_syscalls
                .iter()
                .any(|e| e.name == "add_key"),
            "policy denial must NOT count as an unimplemented handler: {report:?}"
        );
    }

    #[test]
    fn policy_miss_passes_through_to_handler() {
        let mut dispatcher = confined_dispatcher();
        // getpid is NOT in the deny table: the handler must run and answer.
        match dispatch_one(&mut dispatcher, SYS_GETPID) {
            DispatchOutcome::Returned { value } => assert!(value > 0, "getpid returned {value}"),
            other => panic!("getpid must reach its handler under the policy, got {other:?}"),
        }
    }

    #[test]
    fn unconfined_opt_out_keeps_handlers_honest_enosys() {
        // Unconfined (run-elf default / --security-opt seccomp=unconfined):
        // the keyring handlers keep their honest absent-backend ENOSYS — the
        // policy layer NEVER leaks into handler behavior.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.apply_seccomp_policy(SeccompPolicy::Unconfined);
        for nr in [SYS_ADD_KEY, SYS_REQUEST_KEY, SYS_KEYCTL] {
            assert_eq!(
                dispatch_one(&mut dispatcher, nr),
                DispatchOutcome::Errno {
                    errno: LINUX_ENOSYS
                },
                "unconfined keyring syscall {nr} must stay honest ENOSYS"
            );
        }
        // And a fresh dispatcher (no policy applied at all) is unconfined too.
        let mut bare = SyscallDispatcher::new();
        assert_eq!(
            dispatch_one(&mut bare, SYS_ADD_KEY),
            DispatchOutcome::Errno {
                errno: LINUX_ENOSYS
            }
        );
    }

    #[test]
    fn policy_applies_on_threaded_dispatch_path_too() {
        let dispatcher = confined_dispatcher();
        let registry =
            crate::thread::ThreadRegistry::new(crate::thread::ThreadId::synthetic_for_tests(2200));
        let reporter = CompatReporter::default();
        let mut memory = LinearMemory::new(MEM_BASE, vec![0u8; 4096]);
        let outcome = dispatcher
            .dispatch_threaded(
                SyscallRequest::new(SYS_KEYCTL, SyscallArgs([0; 6])),
                &mut memory,
                &reporter,
                registry.main_tid(),
                &registry,
                &crate::thread::FutexTable::new(),
            )
            .expect("threaded dispatch");
        assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_EPERM });
    }

    #[test]
    fn policy_survives_execve_time_dispatcher_resets() {
        // carrick's guest execve keeps the dispatcher object and selectively
        // resets per-image state (signal handlers, executable path). The
        // policy must survive those resets — like a Linux seccomp filter
        // surviving execve.
        let mut dispatcher = confined_dispatcher();
        dispatcher.reset_signal_handlers_on_execve();
        dispatcher.set_executable_path("/replaced/image".to_string());
        assert_eq!(
            dispatch_one(&mut dispatcher, SYS_ADD_KEY),
            DispatchOutcome::Errno { errno: LINUX_EPERM }
        );
    }

    #[test]
    fn policy_is_inherited_by_forked_children() {
        // The runtime's guest fork is a host fork: the child inherits the
        // dispatcher (and thus the policy table) via the process memory copy.
        // Prove it with a real fork — the child dispatches add_key and reports
        // the outcome through its exit code.
        let mut dispatcher = confined_dispatcher();
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let denied = matches!(
                dispatch_one(&mut dispatcher, SYS_ADD_KEY),
                DispatchOutcome::Errno { errno } if errno == LINUX_EPERM
            );
            // SAFETY: _exit is async-signal-safe; no cleanup wanted post-fork.
            unsafe { libc::_exit(if denied { 0 } else { 1 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "forked child must inherit the deny table (status {status:#x})"
        );
    }

    #[test]
    fn docker_default_policy_keeps_identity_fast_path() {
        // The Docker default model never denies identity syscalls, so a
        // container run must NOT lose the EL1-shim fast path.
        let dispatcher = confined_dispatcher();
        assert!(dispatcher.identity_fast_path_enabled());
        // A guest seccomp filter still disables it, policy or not.
        dispatcher.seccomp.install(vec![]);
        assert!(!dispatcher.identity_fast_path_enabled());
    }
}
