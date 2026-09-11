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

#[cfg(test)]
pub(crate) use crate::compat::SyscallArgs;
use crate::compat::{CompatEvent, CompatReporter};
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
    LINUX_AT_SYMLINK_FOLLOW,
    LINUX_AT_SYMLINK_NOFOLLOW,
    LINUX_BOOTSTRAP_PID,
    LINUX_CAPABILITY_VERSION_1,
    LINUX_CAPABILITY_VERSION_2,
    LINUX_CAPABILITY_VERSION_3,
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
    LINUX_E2BIG,
    LINUX_EACCES,
    LINUX_EAFNOSUPPORT,
    LINUX_EAGAIN,
    LINUX_EALREADY,
    LINUX_EBADF,
    LINUX_EBUSY,
    LINUX_EEXIST,
    LINUX_EFAULT,
    LINUX_EFBIG,
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
    LINUX_EPOLLERR,
    LINUX_EPOLLHUP,
    LINUX_EPOLLIN,
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
    LINUX_FUTEX_CMD_MASK,
    LINUX_FUTEX_CMP_REQUEUE,
    LINUX_FUTEX_LOCK_PI,
    LINUX_FUTEX_REQUEUE,
    LINUX_FUTEX_TRYLOCK_PI,
    LINUX_FUTEX_UNLOCK_PI,
    LINUX_FUTEX_WAIT,
    LINUX_FUTEX_WAIT_BITSET,
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
    LINUX_SOL_IP,
    LINUX_SOL_IPV6,
    LINUX_SOL_SOCKET,
    LINUX_SOL_TCP,
    LINUX_SOL_UDP,
    LINUX_SS_DISABLE,
    LINUX_SS_ONSTACK,
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
    LINUX_W_OK,
    LINUX_X_OK,
    LinuxAccessMode,
    LinuxCapabilityData,
    LinuxCapabilityHeader,
    LinuxCloneArgs,
    LinuxCloneFlags,
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
    LinuxStatfs,
    LinuxSysinfo,
    LinuxTermios,
    LinuxTfdFlags,
    LinuxUtsname,
    LinuxWaitOptions,
    LinuxWinsize,
    LinuxX8664EpollEvent,
    align_up_u64,
};
#[cfg(test)]
use crate::linux_abi::{LINUX_MAP_PRIVATE, LINUX_MAP_SHARED};
use crate::overlay::OverlayEntry;
use crate::rootfs::{RootFs, RootFsDirEntry, RootFsEntryKind, RootFsMetadata};
#[cfg(test)]
use carrick_abi::{LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLLET};
use carrick_fatal::carrick_fatal;
// Canonical-number lookups: carrick's canonical syscall numbering IS the
// aarch64 numbering. The dispatcher receives canonical numbers (a per-ISA
// table remaps raw numbers to canonical at the GuestArch seam — Phase 2 for
// x86_64), so its own metadata lookups stay aarch64-keyed by design; only
// raw-frame consumers (the vCPU-loop trace) use the per-ISA Arch::Table.
use crate::linux_abi::LinuxErrno;
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
#[allow(unused_imports)]
pub(crate) use outcome::{
    BlockingHostWriteStep, BlockingRecordLockStep, drive_blocking_host_write,
    drive_blocking_record_lock, lower_handler_result, try_drive_blocking_record_lock,
};

pub mod request;
pub use request::{MutationSyscallCtx, SyscallCtx, SyscallRequest, ThreadCtx};
#[allow(unused_imports)]
pub(crate) use request::{
    PreparedDispatch, PreparedSyscall, SyscallCompletionToken, merge_policy_terminal,
    syscall_requires_execution_lease, threaded_independent_dispatch_supports,
};

pub mod host_alias;
pub use host_alias::HostAliasTransaction;
#[allow(unused_imports)]
pub(crate) use host_alias::HostAliasTransactions;
pub(crate) use host_alias::{HostAliasCommit, HostAliasDispatchGuard};

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

pub mod execution;
pub mod futex;
pub mod io_pipe;
pub mod routing;
pub mod seccomp_observer;
pub(crate) use io_pipe::{
    HostPipeWriteTarget, HostSyscallError, HostSyscallResult, MAX_RW_COUNT, host_pipe_write_room,
    read_host_pipe, would_block_outcome, write_host_pipe, write_host_pipe_owned,
};
#[allow(unused_imports)]
pub(crate) use routing::{
    MM_MUTATION_SYSCALLS, MutationDispatchRoute, MutationSyscallHandler, NormalizedDispatchRoute,
    OrdinaryDispatchRoute, SyscallHandler, resolve_handler, resolve_mutation_handler,
    syscall_requires_mm_mutation,
};
pub use seccomp_observer::check_syscall_flags;
pub mod format_stat;
pub(in crate::dispatch) use format_stat::*;
pub mod format_time;
pub(crate) use format_time::*;
pub mod rootfs_helpers;
pub use rootfs_helpers::linux_errno;
pub(crate) use rootfs_helpers::*;
pub mod mm_authority;
#[cfg(test)]
pub(crate) use carrick_abi::LINUX_FUTEX_PRIVATE_FLAG;
#[allow(unused_imports)]
pub(crate) use futex::{
    dispatch_futex_pi, dispatch_futex_waitv_args, dispatch_threaded_futex,
    linux_futex_command_is_known, read_futex_word,
};
pub(in crate::dispatch) use mm_authority::MmExecutorAdmissionRecipe;
pub use mm_authority::MmExecutorParticipation;
pub(crate) use mm_authority::{
    DispatchMmAuthority, DispatchMmBinding, PrepareDispatchMmForkError, PreparedDispatchMmExec,
    PreparedDispatchMmFork,
};

// `GuestMemory` and `MemoryError` were lifted into the leaf crate
// `carrick-guest-mem` to break the `memory ↔ dispatch` cycle (see
// docs/archive/build-decomposition-design.md §3.A-A2). Re-exported here so every
// `crate::dispatch::{…}` / `carrick_runtime::dispatch::{…}` site is unchanged.
// (The `Aarch64SyscallFrame` re-export is gone: the dispatcher is ISA-neutral —
// backends decode raw frames behind `GuestArch` and hand over `RawSyscall`.)
pub use carrick_guest_mem::{CurrentMmMemory, Gpa, GuestMemory, GuestVa, HostVa, MemoryError};

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

/// Parse `CARRICK_WATCH_ADDR` (hex, optional `0x`) once. `None` disables the
/// guest-memory watchpoint. Compile-gated behind `watchpoint`; the whole
/// facility (env read + per-syscall probe) is absent from a stock build.
#[cfg(feature = "watchpoint")]
pub(crate) fn watch_addr() -> Option<u64> {
    static WATCH_ADDR: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *WATCH_ADDR.get_or_init(|| {
        std::env::var("CARRICK_WATCH_ADDR").ok().and_then(|s| {
            let s = s.trim();
            let s = s.strip_prefix("0x").unwrap_or(s);
            u64::from_str_radix(s, 16).ok()
        })
    })
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

pub(super) fn write_u32(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    value: u32,
) -> Result<(), LinuxErrno> {
    memory
        .write_bytes(address, &value.to_ne_bytes())
        .map_err(|_| LINUX_EFAULT)
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

#[cfg(test)]
include!("tests.rs");
