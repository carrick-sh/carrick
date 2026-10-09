//! Guest-safe Linux syscall numbering and wait-option domains.
#![no_std]

use bitflags::bitflags;

mod errno;
pub mod syscall_x86_64;
pub use errno::{
    LINUX_EAGAIN, LINUX_ECHILD, LINUX_EFAULT, LINUX_EINVAL, LINUX_ENOSYS, LINUX_EPERM, LINUX_ESRCH,
    LinuxErrno,
};

/// Canonical numbers served by the shared guest lifecycle owner.
pub mod nr {
    use super::CanonicalNr;

    pub const EXIT_GROUP: CanonicalNr = CanonicalNr(94);
    pub const SCHED_GET_PRIORITY_MAX: CanonicalNr = CanonicalNr(125);
    pub const SCHED_GET_PRIORITY_MIN: CanonicalNr = CanonicalNr(126);
    pub const SCHED_RR_GET_INTERVAL: CanonicalNr = CanonicalNr(127);
    pub const WAIT4: CanonicalNr = CanonicalNr(260);
    pub const PPOLL: CanonicalNr = CanonicalNr(73);
}

/// Linux SCHED_* policy values (kernel ABI, not the libc-internal names).
/// From include/uapi/linux/sched.h. Value 4 is intentionally skipped
/// (reserved for the never-merged SCHED_ISO).
pub const LINUX_SCHED_OTHER: i32 = 0; // a.k.a. SCHED_NORMAL
pub const LINUX_SCHED_FIFO: i32 = 1;
pub const LINUX_SCHED_RR: i32 = 2;
pub const LINUX_SCHED_BATCH: i32 = 3;
pub const LINUX_SCHED_IDLE: i32 = 5;
pub const LINUX_SCHED_DEADLINE: i32 = 6;
pub const LINUX_SCHED_RESET_ON_FORK: i32 = 0x4000_0000;

pub const LINUX_SCHED_RR_TIMESLICE_MS: u64 = 100;
pub const LINUX_SCHED_OTHER_SLICE_NANOS: u64 = 2_000_000;

/// Wire bytes of `LinuxTimespec { tv_sec: 0, tv_nsec: 2_000_000 }` (2 ms)
/// reported for SCHED_OTHER tasks in sched_rr_get_interval.
pub const LINUX_SCHED_OTHER_SLICE_BYTES: [u8; 16] = {
    let mut b = [0u8; 16];
    let nsec_b = (LINUX_SCHED_OTHER_SLICE_NANOS as i64).to_ne_bytes();
    let mut i = 0;
    while i < 8 {
        b[8 + i] = nsec_b[i];
        i += 1;
    }
    b
};

pub const LINUX_PRIO_PROCESS: u64 = 0;
pub const LINUX_PRIO_PGRP: u64 = 1;
pub const LINUX_PRIO_USER: u64 = 2;

pub const LINUX_IOPRIO_WHO_PROCESS: u64 = 1;
pub const LINUX_IOPRIO_WHO_PGRP: u64 = 2;
pub const LINUX_IOPRIO_WHO_USER: u64 = 3;

pub const LINUX_IOPRIO_CLASS_NONE: u32 = 0;
pub const LINUX_IOPRIO_CLASS_RT: u32 = 1;
pub const LINUX_IOPRIO_CLASS_BE: u32 = 2;
pub const LINUX_IOPRIO_CLASS_IDLE: u32 = 3;

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
