//! Guest-safe Linux syscall numbering and wait-option domains.
#![no_std]

use bitflags::bitflags;

mod capability;
mod errno;
pub mod syscall_x86_64;
pub use capability::{
    CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_AUDIT_WRITE, CAP_BLOCK_SUSPEND, CAP_BPF,
    CAP_CHECKPOINT_RESTORE, CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,
    CAP_FSETID, CAP_IPC_LOCK, CAP_IPC_OWNER, CAP_KILL, CAP_LAST_CAP, CAP_LEASE,
    CAP_LINUX_IMMUTABLE, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_MKNOD, CAP_NET_ADMIN,
    CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, CAP_NET_RAW, CAP_PERFMON, CAP_SETFCAP, CAP_SETGID,
    CAP_SETPCAP, CAP_SETUID, CAP_SYS_ADMIN, CAP_SYS_BOOT, CAP_SYS_CHROOT, CAP_SYS_MODULE,
    CAP_SYS_NICE, CAP_SYS_PACCT, CAP_SYS_PTRACE, CAP_SYS_RAWIO, CAP_SYS_RESOURCE, CAP_SYS_TIME,
    CAP_SYS_TTY_CONFIG, CAP_SYSLOG, CAP_WAKE_ALARM, LinuxCapabilitySet,
};
pub use errno::{
    LINUX_EAGAIN, LINUX_EBADF, LINUX_ECHILD, LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_ENOSYS,
    LINUX_EPERM, LINUX_ESRCH, LinuxErrno,
};
mod signal;
pub use signal::{
    AARCH64_EL0_USER_PSTATE_MASK, CARRICK_SIGFRAME_MAGIC, CARRICK_X8664_XSTATE_TRAILER_MAGIC,
    CARRICK_X8664_XSTATE_TRAILER_VERSION, CarrickSigframe, CarrickX8664XstateTrailer,
    LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES, LINUX_BUS_ADRALN, LINUX_BUS_ADRERR, LINUX_CLD_DUMPED,
    LINUX_CLD_EXITED, LINUX_CLD_KILLED, LINUX_FPSIMD_MAGIC, LINUX_KERNEL_SIGSET_SIZE,
    LINUX_POLL_MSG, LINUX_RT_SIGSET_SIZE, LINUX_SA_NOCLDSTOP, LINUX_SA_NOCLDWAIT, LINUX_SA_NODEFER,
    LINUX_SA_ONSTACK, LINUX_SA_RESETHAND, LINUX_SA_RESTART, LINUX_SA_RESTORER, LINUX_SA_SIGINFO,
    LINUX_SEGV_ACCERR, LINUX_SEGV_MAPERR, LINUX_SI_KERNEL, LINUX_SI_MESGQ, LINUX_SI_QUEUE,
    LINUX_SI_TIMER, LINUX_SI_TKILL, LINUX_SI_USER, LINUX_SIG_DFL, LINUX_SIG_IGN, LINUX_SIGABRT,
    LINUX_SIGALRM, LINUX_SIGBUS, LINUX_SIGCHLD, LINUX_SIGCONT, LINUX_SIGFPE, LINUX_SIGHUP,
    LINUX_SIGILL, LINUX_SIGINFO_SIZE, LINUX_SIGINT, LINUX_SIGIO, LINUX_SIGKILL, LINUX_SIGPIPE,
    LINUX_SIGPROF, LINUX_SIGPWR, LINUX_SIGQUIT, LINUX_SIGSEGV, LINUX_SIGSET_WORDS, LINUX_SIGSTKFLT,
    LINUX_SIGSTOP, LINUX_SIGSYS, LINUX_SIGTERM, LINUX_SIGTRAP, LINUX_SIGTSTP, LINUX_SIGTTIN,
    LINUX_SIGTTOU, LINUX_SIGURG, LINUX_SIGUSR1, LINUX_SIGUSR2, LINUX_SIGVTALRM, LINUX_SIGWINCH,
    LINUX_SIGXCPU, LINUX_SIGXFSZ, LINUX_SS_AUTODISARM, LINUX_SS_DISABLE, LINUX_SS_ONSTACK,
    LINUX_UCONTEXT_SIGMASK_PAD_BYTES, LINUX_X8664_USER_CS, LINUX_X8664_USER_DS, LinuxFpsimdContext,
    LinuxSigaction, LinuxSigaltstack, LinuxSiginfo, LinuxSignalContext, LinuxSignalStack,
    LinuxUcontext, X8664_FP_XSTATE_MAGIC1, X8664_FP_XSTATE_MAGIC2, X8664_FP_XSTATE_MAGIC2_SIZE,
    X8664_FP_XSTATE_SW_BYTES_OFFSET, X8664_RTSIGFRAME_FPSTATE_OFFSET, X8664_XFEATURE_PKRU,
    X8664_XSAVE_AREA_MAX_LEN, X8664_XSAVE_HEADER_LEN, X8664_XSAVE_LEGACY_LEN, X8664_XSAVE_MIN_LEN,
    X8664Fpstate, X8664FpxSwBytes, X8664Rtsigframe, X8664Sigcontext, X8664Ucontext,
    X8664XsaveHeader,
};

/// Canonical numbers served by the shared guest lifecycle owner.
pub mod nr {
    use super::CanonicalNr;

    pub const CAPGET: CanonicalNr = CanonicalNr(90);
    pub const CAPSET: CanonicalNr = CanonicalNr(91);
    pub const PERSONALITY: CanonicalNr = CanonicalNr(92);
    pub const EXIT_GROUP: CanonicalNr = CanonicalNr(94);
    pub const SET_TID_ADDRESS: CanonicalNr = CanonicalNr(96);
    pub const GET_ROBUST_LIST: CanonicalNr = CanonicalNr(100);
    pub const SETREGID: CanonicalNr = CanonicalNr(143);
    pub const SETGID: CanonicalNr = CanonicalNr(144);
    pub const SETREUID: CanonicalNr = CanonicalNr(145);
    pub const SETUID: CanonicalNr = CanonicalNr(146);
    pub const SETRESUID: CanonicalNr = CanonicalNr(147);
    pub const GETRESUID: CanonicalNr = CanonicalNr(148);
    pub const SETRESGID: CanonicalNr = CanonicalNr(149);
    pub const GETRESGID: CanonicalNr = CanonicalNr(150);
    pub const SETFSUID: CanonicalNr = CanonicalNr(151);
    pub const SETFSGID: CanonicalNr = CanonicalNr(152);
    pub const SETPGID: CanonicalNr = CanonicalNr(154);
    pub const GETPGID: CanonicalNr = CanonicalNr(155);
    pub const GETSID: CanonicalNr = CanonicalNr(156);
    pub const SETSID: CanonicalNr = CanonicalNr(157);
    pub const GETGROUPS: CanonicalNr = CanonicalNr(158);
    pub const SETGROUPS: CanonicalNr = CanonicalNr(159);
    pub const UNAME: CanonicalNr = CanonicalNr(160);
    pub const SETHOSTNAME: CanonicalNr = CanonicalNr(161);
    pub const SETDOMAINNAME: CanonicalNr = CanonicalNr(162);
    pub const GETRLIMIT: CanonicalNr = CanonicalNr(163);
    pub const SETRLIMIT: CanonicalNr = CanonicalNr(164);
    pub const GETRUSAGE: CanonicalNr = CanonicalNr(165);
    pub const UMASK: CanonicalNr = CanonicalNr(166);
    pub const PRCTL: CanonicalNr = CanonicalNr(167);
    pub const GETPPID: CanonicalNr = CanonicalNr(173);
    pub const GETUID: CanonicalNr = CanonicalNr(174);
    pub const GETEUID: CanonicalNr = CanonicalNr(175);
    pub const GETGID: CanonicalNr = CanonicalNr(176);
    pub const GETEGID: CanonicalNr = CanonicalNr(177);
    pub const SYSINFO: CanonicalNr = CanonicalNr(179);
    pub const WAIT4: CanonicalNr = CanonicalNr(260);
    pub const PRLIMIT64: CanonicalNr = CanonicalNr(261);
}

/// A CANONICAL syscall number — the asm-generic/aarch64 numbering every guest
/// ISA is normalized to before dispatch (plus the `CARRICK_PRIVATE_*` range).
/// Distinct from [`NativeNr`]: the two were adjacent bare u64 fields, so a
/// constructor swap compiled clean and mis-routed dispatch/seccomp — the same
/// silent class as the historical x86 uname(63)-as-read(63) collision.
///
/// `Ord` is derived so a canonical number can key an ordered map WITHOUT being
/// unwrapped to a bare `u64` first — the amplification ledger orders its rows by
/// guest op, and re-raw-ing the number to sort it is exactly the boundary
/// crossing this type exists to prevent. The ordering is the table's own: the
/// aarch64 table is kept sorted by number.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct CanonicalNr(pub u64);

impl CanonicalNr {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    /// The bare canonical number, for match scrutinees / table lookups /
    /// formatting. All syscall-table arms stay integer-literal patterns; the
    /// conversion happens ONCE at each scrutinee.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// The guest ISA's own ("native"/raw) syscall number as trapped, BEFORE
/// normalization — kept alongside [`CanonicalNr`] for seccomp filtering and
/// diagnostics that must speak the guest's numbering.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeNr(pub u64);

impl NativeNr {
    /// The bare guest-native number (what the guest put in its syscall
    /// register), for seccomp `seccomp_data.nr` and diagnostics.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Ordinals for the carrick-internal ("private") normalized x86 syscall
/// numbers below. Each public constant derives its value from THIS enum's
/// sequential discriminants via [`private_x86_number`], so two entries can
/// never share a number — the compiler rejects duplicate discriminants and
/// sequential assignment leaves no hand-numbered gaps to fat-finger (alarm(2)
/// briefly shared 0x2a with epoll_create by exactly that mistake, silently
/// dispatching guest alarm() as epoll_create). Append new entries at the END;
/// values are internal-only and may shift, every consumer goes through the
/// named constants.
#[derive(Clone, Copy)]
enum PrivateX86Ordinal {
    Dup2,
    Stat,
    Fstat,
    Lstat,
    Newfstatat,
    Unsupported,
    Utime,
    Utimes,
    Poll,
    Select,
    EpollCreate,
    Alarm,
    Time,
}

/// The private numbers grow DOWN from `u64::MAX - 0x20`, far outside any real
/// Linux syscall-number range on any ISA.
const fn private_x86_number(ordinal: PrivateX86Ordinal) -> u64 {
    u64::MAX - 0x20 - ordinal as u64
}

/// Carrick-internal normalized syscall number for x86_64 `dup2(2)`.
///
/// The asm-generic/canonical table has `dup3(2)` but no `dup2(2)`, and using
/// canonical number 33 would collide with `mknodat(2)`. Keep this outside the
/// Linux syscall-number range so x86 normalization can preserve `dup2` semantics
/// without weakening canonical `dup3(oldfd, oldfd, flags)` handling.
pub const CARRICK_PRIVATE_X86_DUP2: u64 = private_x86_number(PrivateX86Ordinal::Dup2);
/// Carrick-internal normalized syscall number for x86_64 `stat(2)`.
///
/// The path lookup is equivalent to `newfstatat(AT_FDCWD, path, flags=0)`, but
/// the guest-visible output buffer is x86_64's 144-byte `struct stat`, not the
/// canonical asm-generic/aarch64 layout. Keep it private so the dispatcher can
/// select the x86 ABI writer without changing canonical `newfstatat`.
pub const CARRICK_PRIVATE_X86_STAT: u64 = private_x86_number(PrivateX86Ordinal::Stat);
/// Carrick-internal normalized syscall number for x86_64 `fstat(2)`.
///
/// Canonical syscall 80 is also named `fstat`, but it writes the
/// asm-generic/aarch64 `struct stat` layout. x86_64 legacy `fstat` needs the
/// same fd lookup with a LinuxX8664Stat writer.
pub const CARRICK_PRIVATE_X86_FSTAT: u64 = private_x86_number(PrivateX86Ordinal::Fstat);
/// Carrick-internal normalized syscall number for x86_64 `lstat(2)`.
///
/// Semantically this is `newfstatat(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW)` with
/// x86_64's legacy `struct stat` output layout.
pub const CARRICK_PRIVATE_X86_LSTAT: u64 = private_x86_number(PrivateX86Ordinal::Lstat);
/// Carrick-internal normalized syscall number for x86_64 `newfstatat(2)`.
///
/// The arguments match canonical `newfstatat`, but x86_64 still expects the
/// legacy 144-byte `struct stat` output layout.
pub const CARRICK_PRIVATE_X86_NEWFSTATAT: u64 = private_x86_number(PrivateX86Ordinal::Newfstatat);
/// Carrick-internal sink for unsupported x86_64 syscalls after normalization.
///
/// Leaving an x86-only number unchanged is unsafe: the canonical asm-generic
/// dispatcher may implement a different syscall at that numeric slot (for
/// example x86_64 `mkdir`=83 collides with canonical `fdatasync`=83). Normalize
/// unsupported x86 syscalls to this out-of-range number so they return ENOSYS
/// instead of mis-dispatching with the wrong argument shape.
pub const CARRICK_PRIVATE_X86_UNSUPPORTED: u64 = private_x86_number(PrivateX86Ordinal::Unsupported);
/// Carrick-internal normalized syscall number for x86_64 `utime(2)`.
///
/// `utime(path, *utimbuf)` differs from canonical `utimensat(dfd, path,
/// two `timespec` values, flags)` in BOTH arg0 (path vs dirfd) AND struct layout (16-byte
/// `utimbuf{actime,modtime}` in whole seconds vs 32-byte `timespec[2]`). A plain
/// `Direct(88)` would mis-dispatch the path pointer into the dirfd slot and feed
/// the wrong struct, so it routes to a private handler that converts utimbuf ->
/// `timespec[2]` (tv_nsec=0) then calls `utimensat(AT_FDCWD, path, &times, 0)`.
pub const CARRICK_PRIVATE_X86_UTIME: u64 = private_x86_number(PrivateX86Ordinal::Utime);
/// Carrick-internal normalized syscall number for x86_64 `utimes(2)`.
///
/// `utimes(path, *timeval[2])` carries microsecond timevals; the private handler
/// converts `timeval[2]` -> `timespec[2]` (tv_nsec = tv_usec*1000) then calls
/// `utimensat(AT_FDCWD, path, &times, flags=0)`. Out-of-range tv_usec
/// (outside `0..=999999`) -> -EINVAL; an unreadable guest pointer -> -EFAULT.
pub const CARRICK_PRIVATE_X86_UTIMES: u64 = private_x86_number(PrivateX86Ordinal::Utimes);
/// Carrick-internal normalized syscall number for x86_64 `poll(2)`.
///
/// x86_64 `poll(fds, nfds, timeout_ms)` carries an INT timeout (milliseconds:
/// -1 blocks, 0 returns now). The asm-generic/aarch64 canonical has only
/// `ppoll(fds, nfds, *timespec, ...)` whose 3rd arg is a POINTER (0 = NULL =
/// block forever) — so folding `poll` into `ppoll` mis-reads a `poll(.,.,0)`
/// non-blocking probe as an infinite wait (musl's startup `poll([0,1,2],3,0)`
/// then wedges the guest). This private number routes `poll` to the ppoll
/// handler's poll branch, which reads arg2 as `timeout_ms` and uses no sigmask.
pub const CARRICK_PRIVATE_X86_POLL: u64 = private_x86_number(PrivateX86Ordinal::Poll);
/// Carrick-internal normalized syscall number for x86_64 `select(2)`.
///
/// x86_64 `select(nfds, r, w, e, *timeval)` carries a `*timeval` timeout
/// (tv_sec + tv_usec). The asm-generic/aarch64 canonical has only `pselect6`,
/// whose timeout is a `*timespec` (tv_sec + tv_nsec) plus a sigmask — folding
/// select in would mis-read the timeval's tv_usec as tv_nsec. This private
/// number routes select to the pselect6 handler's select branch, which reads
/// the timeout as a timeval and uses no sigmask.
pub const CARRICK_PRIVATE_X86_SELECT: u64 = private_x86_number(PrivateX86Ordinal::Select);
/// Carrick-internal normalized syscall number for x86_64 legacy `epoll_create(2)`.
///
/// x86_64 exposes `epoll_create(size)` as syscall 213; asm-generic/aarch64 has
/// only `epoll_create1(flags)`. The `size` hint has been ignored since 2.6.8
/// BUT the kernel still rejects `size <= 0` with EINVAL — a check that is lost if
/// we fold straight into `epoll_create1(0)` (epoll-ltp / epoll_create02 assert
/// the EINVAL). This private number routes the legacy call to a handler that
/// validates `size` and then creates the instance.
pub const CARRICK_PRIVATE_X86_EPOLL_CREATE: u64 =
    private_x86_number(PrivateX86Ordinal::EpollCreate);
/// Carrick-internal normalized syscall number for x86_64 `alarm(2)`.
///
/// x86_64 exposes legacy `alarm(seconds)` as syscall 37, while asm-generic has
/// no canonical `alarm` entry. Route it privately so glibc/CPython can use the
/// same interval-timer state and SIGALRM delivery path as `setitimer`.
pub const CARRICK_PRIVATE_X86_ALARM: u64 = private_x86_number(PrivateX86Ordinal::Alarm);
/// Carrick-internal normalized syscall number for x86_64 `time(2)`.
///
/// x86_64 exposes legacy `time(time_t *)` as syscall 201, while asm-generic
/// implements libc `time()` through newer clock syscalls and has no canonical
/// entry. The private handler returns realtime seconds and optionally writes
/// the same 64-bit `time_t` through the guest pointer.
pub const CARRICK_PRIVATE_X86_TIME: u64 = private_x86_number(PrivateX86Ordinal::Time);

// Every CARRICK_PRIVATE_X86_* number must be UNIQUE: a collision silently
// routes one syscall through another's handler (alarm(2) briefly shared
// 0x2a with epoll_create, so guest alarm() returned fresh epoll FDS — LTP
// alarm02's "invalid retval 4/5/6"). Compile-time, like the SIG* table.
const _: () = {
    const PRIVATE_X86: [u64; 13] = [
        CARRICK_PRIVATE_X86_DUP2,
        CARRICK_PRIVATE_X86_STAT,
        CARRICK_PRIVATE_X86_FSTAT,
        CARRICK_PRIVATE_X86_LSTAT,
        CARRICK_PRIVATE_X86_NEWFSTATAT,
        CARRICK_PRIVATE_X86_UNSUPPORTED,
        CARRICK_PRIVATE_X86_UTIME,
        CARRICK_PRIVATE_X86_UTIMES,
        CARRICK_PRIVATE_X86_POLL,
        CARRICK_PRIVATE_X86_SELECT,
        CARRICK_PRIVATE_X86_EPOLL_CREATE,
        CARRICK_PRIVATE_X86_ALARM,
        CARRICK_PRIVATE_X86_TIME,
    ];
    let mut i = 0;
    while i < PRIVATE_X86.len() {
        let mut j = i + 1;
        while j < PRIVATE_X86.len() {
            assert!(
                PRIVATE_X86[i] != PRIVATE_X86[j],
                "duplicate CARRICK_PRIVATE_X86 syscall number"
            );
            j += 1;
        }
        i += 1;
    }
};

pub const LINUX_WNOHANG: u64 = 1;
pub const LINUX_WUNTRACED: u64 = 2;
pub const LINUX_WSTOPPED: u64 = 2;
pub const LINUX_WEXITED: u64 = 4;
pub const LINUX_WCONTINUED: u64 = 8;
pub const LINUX_WNOWAIT: u64 = 0x0100_0000;
pub const LINUX_WAITID_STATE_MASK: u64 = LINUX_WEXITED | LINUX_WSTOPPED | LINUX_WCONTINUED;
pub const LINUX_WCLONE: u64 = 0x8000_0000;
pub const LINUX_WALL: u64 = 0x4000_0000;
pub const LINUX_WNOTHREAD: u64 = 0x2000_0000;
pub const LINUX_WAITID_SUPPORTED_FLAGS: u64 = LINUX_WAITID_STATE_MASK
    | LINUX_WNOHANG
    | LINUX_WNOWAIT
    | LINUX_WCLONE
    | LINUX_WALL
    | LINUX_WNOTHREAD;
pub const LINUX_WAIT4_SUPPORTED_FLAGS: u64 = LINUX_WNOHANG
    | LINUX_WUNTRACED
    | LINUX_WCONTINUED
    | LINUX_WCLONE
    | LINUX_WALL
    | LINUX_WNOTHREAD;
bitflags! {
    /// `wait4`/`waitid` option bits. WSTOPPED is `waitid`'s alias for
    /// WUNTRACED (same value, 2). Each syscall accepts a DIFFERENT subset —
    /// see [`LinuxWaitOptions::WAITID_SUPPORTED`] /
    /// [`LinuxWaitOptions::WAIT4_SUPPORTED`]; unknown bits are EINVAL there,
    /// preserved via those exact masks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LinuxWaitOptions: u64 {
        const WNOHANG = LINUX_WNOHANG;
        const WUNTRACED = LINUX_WUNTRACED;
        /// `waitid` spelling of WUNTRACED (identical bit).
        const WSTOPPED = LINUX_WSTOPPED;
        const WEXITED = LINUX_WEXITED;
        const WCONTINUED = LINUX_WCONTINUED;
        const WNOWAIT = LINUX_WNOWAIT;
        const WNOTHREAD = LINUX_WNOTHREAD;
        const WALL = LINUX_WALL;
        const WCLONE = LINUX_WCLONE;
    }

}

impl LinuxWaitOptions {
    /// The `waitid` state selectors (WEXITED | WSTOPPED | WCONTINUED); at
    /// least one must be set or the call is EINVAL.
    pub const WAITID_STATE_MASK: Self = Self::from_bits_retain(LINUX_WAITID_STATE_MASK);
    /// Exactly [`LINUX_WAITID_SUPPORTED_FLAGS`]: any option bit outside this
    /// set is EINVAL for `waitid`.
    pub const WAITID_SUPPORTED: Self = Self::from_bits_retain(LINUX_WAITID_SUPPORTED_FLAGS);
    /// Exactly [`LINUX_WAIT4_SUPPORTED_FLAGS`]: any option bit outside this
    /// set is EINVAL for `wait4`.
    pub const WAIT4_SUPPORTED: Self = Self::from_bits_retain(LINUX_WAIT4_SUPPORTED_FLAGS);
}

/// Linux 64-bit rusage contains two timevals and fourteen signed counters.
pub const LINUX_RUSAGE_BYTES: usize = 144;
