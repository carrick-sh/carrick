//! Temporary root dispatch compatibility for #1393(a).
//!
//! These identities retain the existing host task implementation until the root
//! is born in ring. They are not an assertion that children implement the same
//! operation: #1335 F1-F24 and its ambient-state review describe that debt.
use carrick_abi::CanonicalNr;
use carrick_abi::syscall::nr;
use carrick_personality_linux::dispatch::{ServiceOwner, service_owner};

/// An explicitly admitted legacy root handler. Delete identities as their host
/// handlers disappear; adding a new service must use the shared owner instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RootOnly {
    ordinal: CanonicalNr,
}

// Cross-cutting state found by #1335's census and independent ambient-state
// review, plus #1409's root fork seed. These are retirement obligations, not
// permission for a child crossing to read the root's host state.
macro_rules! root_only_state {
    ($($state:ident,)*) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum RootOnlyState { $($state,)* }
        const ROOT_ONLY_STATE: &[RootOnlyState] = &[$(RootOnlyState::$state,)*];
    };
}
root_only_state! {
    CapturedFs,
    Credentials,
    FileTable,
    PipeLifetime,
    Exec,
    UserMemory,
    PendingHostWork,
    Signals,
    ProcessIdentity,
    RecordLockOwner,
    Rlimits,
    Umask,
    SysvScope,
    ChildCpuTimes,
    ProcSelf,
    NetworkView,
    Attribution,
    ResourceScope,
    ExecutionLease,
    HostWait,
    // Includes the live executable copied into fork MM custody (#1862).
    RootForkSeed,
}

// One typed declaration emits admission and the census population.
macro_rules! root_only {
    ($($nr:path,)*) => {
        impl RootOnly {
            pub(super) const fn admit(number: u64) -> Option<Self> {
                match CanonicalNr::new(number) {
                    $($nr => Some(Self { ordinal: $nr }),)*
                    _ => None,
                }
            }
        }
        const ROOT_ONLY_IDENTITIES: &[CanonicalNr] = &[$($nr,)*];
    };
}
root_only! {
    nr::ACCEPT,
    nr::ACCEPT4,
    nr::ADD_KEY,
    nr::ADJTIMEX,
    nr::BIND,
    nr::BPF,
    nr::BRK,
    nr::CACHESTAT,
    nr::CAPGET,
    nr::CAPSET,
    nr::CARRICK_PRIVATE_X86_ALARM,
    nr::CARRICK_PRIVATE_X86_DUP2,
    nr::CARRICK_PRIVATE_X86_EPOLL_CREATE,
    nr::CARRICK_PRIVATE_X86_FSTAT,
    nr::CARRICK_PRIVATE_X86_LSTAT,
    nr::CARRICK_PRIVATE_X86_NEWFSTATAT,
    nr::CARRICK_PRIVATE_X86_POLL,
    nr::CARRICK_PRIVATE_X86_SELECT,
    nr::CARRICK_PRIVATE_X86_STAT,
    nr::CARRICK_PRIVATE_X86_TIME,
    nr::CHDIR,
    nr::CHROOT,
    nr::CLOCK_ADJTIME,
    nr::CLOCK_GETRES,
    nr::CLOCK_GETTIME,
    nr::CLOCK_NANOSLEEP,
    nr::CLOCK_SETTIME,
    nr::CLONE,
    nr::CLONE3,
    nr::CLOSE,
    nr::CLOSE_RANGE,
    nr::CONNECT,
    nr::COPY_FILE_RANGE,
    nr::DUP,
    nr::DUP3,
    nr::EPOLL_CREATE1,
    nr::EPOLL_CTL,
    nr::EPOLL_PWAIT,
    nr::EPOLL_PWAIT2,
    nr::EVENTFD2,
    nr::EXECVE,
    nr::EXECVEAT,
    nr::EXIT,
    nr::EXIT_GROUP,
    nr::FACCESSAT,
    nr::FACCESSAT2,
    nr::FADVISE64,
    nr::FALLOCATE,
    nr::FANOTIFY_INIT,
    nr::FANOTIFY_MARK,
    nr::FCHDIR,
    nr::FCHMOD,
    nr::FCHMODAT,
    nr::FCHMODAT2,
    nr::FCHOWN,
    nr::FCHOWNAT,
    nr::FCNTL,
    nr::FDATASYNC,
    nr::FGETXATTR,
    nr::FLISTXATTR,
    nr::FLOCK,
    nr::FREMOVEXATTR,
    nr::FSCONFIG,
    nr::FSETXATTR,
    nr::FSMOUNT,
    nr::FSOPEN,
    nr::FSPICK,
    nr::FSTAT,
    nr::FSTATFS,
    nr::FSYNC,
    nr::FTRUNCATE,
    nr::FUTEX,
    nr::FUTEX_WAITV,
    nr::GETCPU,
    nr::GETCWD,
    nr::GETDENTS64,
    nr::GETEGID,
    nr::GETEUID,
    nr::GETGID,
    nr::GETGROUPS,
    nr::GETITIMER,
    nr::GETPEERNAME,
    nr::GETPGID,
    nr::GETPID,
    nr::GETPPID,
    nr::GETPRIORITY,
    nr::GETRANDOM,
    nr::GETRESGID,
    nr::GETRESUID,
    nr::GETRLIMIT,
    nr::GETRUSAGE,
    nr::GETSID,
    nr::GETSOCKNAME,
    nr::GETSOCKOPT,
    nr::GETTID,
    nr::GETTIMEOFDAY,
    nr::GETUID,
    nr::GETXATTR,
    nr::GET_ROBUST_LIST,
    nr::INOTIFY_ADD_WATCH,
    nr::INOTIFY_INIT1,
    nr::INOTIFY_RM_WATCH,
    nr::IOCTL,
    nr::IOPRIO_GET,
    nr::IOPRIO_SET,
    nr::IO_CANCEL,
    nr::IO_DESTROY,
    nr::IO_GETEVENTS,
    nr::IO_SETUP,
    nr::IO_SUBMIT,
    nr::IO_URING_ENTER,
    nr::IO_URING_REGISTER,
    nr::IO_URING_SETUP,
    nr::KCMP,
    nr::KEYCTL,
    nr::KILL,
    nr::LGETXATTR,
    nr::LINKAT,
    nr::LISTEN,
    nr::LISTXATTR,
    nr::LLISTXATTR,
    nr::LREMOVEXATTR,
    nr::LSEEK,
    nr::LSETXATTR,
    nr::MADVISE,
    nr::MEMBARRIER,
    nr::MEMFD_CREATE,
    nr::MEMFD_SECRET,
    nr::MINCORE,
    nr::MKDIRAT,
    nr::MKNODAT,
    nr::MLOCK,
    nr::MLOCK2,
    nr::MLOCKALL,
    nr::MMAP,
    nr::MOUNT_SETATTR,
    nr::MOVE_MOUNT,
    nr::MPROTECT,
    nr::MQ_GETSETATTR,
    nr::MQ_NOTIFY,
    nr::MQ_OPEN,
    nr::MQ_TIMEDRECEIVE,
    nr::MQ_TIMEDSEND,
    nr::MQ_UNLINK,
    nr::MREMAP,
    nr::MSGCTL,
    nr::MSGGET,
    nr::MSGRCV,
    nr::MSGSND,
    nr::MSYNC,
    nr::MUNLOCK,
    nr::MUNLOCKALL,
    nr::MUNMAP,
    nr::NAME_TO_HANDLE_AT,
    nr::NANOSLEEP,
    nr::NEWFSTATAT,
    nr::OPENAT,
    nr::OPENAT2,
    nr::OPEN_TREE,
    nr::PERF_EVENT_OPEN,
    nr::PERSONALITY,
    nr::PIDFD_GETFD,
    nr::PIDFD_OPEN,
    nr::PIDFD_SEND_SIGNAL,
    nr::PIPE2,
    nr::PPOLL,
    nr::PRCTL,
    nr::PREAD64,
    nr::PREADV,
    nr::PREADV2,
    nr::PRLIMIT64,
    nr::PROCESS_VM_READV,
    nr::PROCESS_VM_WRITEV,
    nr::PSELECT6,
    nr::PTRACE,
    nr::PWRITE64,
    nr::PWRITEV,
    nr::PWRITEV2,
    nr::READ,
    nr::READAHEAD,
    nr::READLINKAT,
    nr::READV,
    nr::REBOOT,
    nr::RECVFROM,
    nr::RECVMMSG,
    nr::RECVMSG,
    nr::REMAP_FILE_PAGES,
    nr::REMOVEXATTR,
    nr::RENAMEAT,
    nr::RENAMEAT2,
    nr::REQUEST_KEY,
    nr::RSEQ,
    nr::RT_SIGACTION,
    nr::RT_SIGPENDING,
    nr::RT_SIGPROCMASK,
    nr::RT_SIGQUEUEINFO,
    nr::RT_SIGRETURN,
    nr::RT_SIGSUSPEND,
    nr::RT_SIGTIMEDWAIT,
    nr::RT_TGSIGQUEUEINFO,
    nr::SCHED_GETAFFINITY,
    nr::SCHED_GETATTR,
    nr::SCHED_GETPARAM,
    nr::SCHED_GETSCHEDULER,
    nr::SCHED_GET_PRIORITY_MAX,
    nr::SCHED_GET_PRIORITY_MIN,
    nr::SCHED_RR_GET_INTERVAL,
    nr::SCHED_SETAFFINITY,
    nr::SCHED_SETPARAM,
    nr::SCHED_SETSCHEDULER,
    nr::SCHED_YIELD,
    nr::SECCOMP,
    nr::SEMCTL,
    nr::SEMGET,
    nr::SEMOP,
    nr::SEMTIMEDOP,
    nr::SENDFILE,
    nr::SENDMMSG,
    nr::SENDMSG,
    nr::SENDTO,
    nr::SETDOMAINNAME,
    nr::SETFSGID,
    nr::SETFSUID,
    nr::SETGID,
    nr::SETGROUPS,
    nr::SETHOSTNAME,
    nr::SETITIMER,
    nr::SETPGID,
    nr::SETPRIORITY,
    nr::SETREGID,
    nr::SETRESGID,
    nr::SETRESUID,
    nr::SETREUID,
    nr::SETSID,
    nr::SETSOCKOPT,
    nr::SETTIMEOFDAY,
    nr::SETUID,
    nr::SETXATTR,
    nr::SET_ROBUST_LIST,
    nr::SET_TID_ADDRESS,
    nr::SHMAT,
    nr::SHMCTL,
    nr::SHMDT,
    nr::SHMGET,
    nr::SHUTDOWN,
    nr::SIGALTSTACK,
    nr::SIGNALFD4,
    nr::SOCKET,
    nr::SOCKETPAIR,
    nr::SPLICE,
    nr::STATFS,
    nr::STATX,
    nr::SYMLINKAT,
    nr::SYNC,
    nr::SYNCFS,
    nr::SYNC_FILE_RANGE,
    nr::SYSINFO,
    nr::SYSLOG,
    nr::TEE,
    nr::TGKILL,
    nr::TIMERFD_CREATE,
    nr::TIMERFD_GETTIME,
    nr::TIMERFD_SETTIME,
    nr::TIMER_CREATE,
    nr::TIMER_DELETE,
    nr::TIMER_GETOVERRUN,
    nr::TIMER_GETTIME,
    nr::TIMER_SETTIME,
    nr::TIMES,
    nr::TKILL,
    nr::TRUNCATE,
    nr::UMASK,
    nr::UNAME,
    nr::UNLINKAT,
    nr::UNSHARE,
    nr::USERFAULTFD,
    nr::UTIMENSAT,
    nr::VHANGUP,
    nr::VMSPLICE,
    nr::WAIT4,
    nr::WAITID,
    nr::WRITE,
    nr::WRITEV,
}

const _: () = assert!(ROOT_ONLY_IDENTITIES.len() <= 283);
const _: () = assert!(ROOT_ONLY_STATE.len() <= 21);

/// Consult the same owner as native entry, retaining only enumerated root debt.
/// No task class is supplied to service_owner. The compatibility token is local
/// to this old host resolver; it cannot grant a child access to host task state.
pub(in crate::dispatch) fn resolve<T>(
    number: u64,
    legacy: impl FnOnce() -> Option<T>,
) -> Option<T> {
    let owner = service_owner(CanonicalNr::new(number), u64::MAX);
    // Every current host handler still depends on the root task, including
    // permanent crossings. Ownership alone grants no ambient state authority.
    let retained = RootOnly::admit(number)?;
    debug_assert_eq!(retained.ordinal.raw(), number);
    match owner {
        ServiceOwner::Crossing(_)
        | ServiceOwner::RingOwed(_)
        | ServiceOwner::Ring(_)
        | ServiceOwner::CountedEnosys => legacy(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::{LinearMemory, routing};

    #[test]
    fn root_only_compatibility_covers_existing_handlers_and_may_only_shrink() {
        let mut count = 0;
        // Include private x86 canonical identities as well as the Linux table.
        for number in (0..512).chain(
            (nr::CARRICK_PRIVATE_X86_TIME.raw()..=nr::CARRICK_PRIVATE_X86_DUP2.raw())
                .chain([u64::MAX]),
        ) {
            if RootOnly::admit(number).is_some() {
                count += 1;
            }
            let existing = routing::resolve_legacy_handler::<LinearMemory>(number).is_some()
                || routing::resolve_legacy_mutation_handler::<LinearMemory>(number).is_some();
            let threaded = crate::dispatch::request::threaded_independent_dispatch_supports(number);
            assert_eq!(
                RootOnly::admit(number).is_some(),
                existing || threaded,
                "root compatibility must exactly cover handlers and threaded entry: {number}"
            );
            assert_eq!(
                routing::resolve_handler::<LinearMemory>(number).is_some(),
                routing::resolve_legacy_handler::<LinearMemory>(number).is_some(),
                "root ordinary {number}"
            );
            assert_eq!(
                routing::resolve_mutation_handler::<LinearMemory>(number).is_some(),
                routing::resolve_legacy_mutation_handler::<LinearMemory>(number).is_some(),
                "root mutation {number}"
            );
        }
        assert_eq!(
            count, ROOT_ONLY_CEILING,
            "ratchet RootOnly ceiling down on retirement"
        );
        assert_eq!(
            ROOT_ONLY_STATE.len(),
            21,
            "ratchet ambient-state population on retirement"
        );
        assert_eq!(
            ROOT_ONLY_IDENTITIES.len(),
            count,
            "duplicate compatibility identity"
        );
    }

    #[test]
    fn root_resolution_enters_only_the_shared_owner_or_explicit_compatibility() {
        // The real root resolver's gate must not invoke even an available
        // host handler for a counted refusal absent from compatibility.
        for number in [512, u64::MAX] {
            let entered = std::cell::Cell::new(false);
            assert_eq!(
                resolve(number, || {
                    entered.set(true);
                    Some(7)
                }),
                None
            );
            assert!(!entered.get());
        }
        // Exercise the Ring and Crossing arms through the production gate.
        for number in [nr::GETPID.raw(), nr::MKDIRAT.raw()] {
            assert_eq!(resolve(number, || Some(7)), Some(7));
        }
    }

    const ROOT_ONLY_CEILING: usize = 283;
}
