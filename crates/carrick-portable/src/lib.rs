//! `carrick-portable` — a thin per-OS portability shim for the raw `libc`
//! symbols that differ (or are absent) across carrick's host platforms.
//!
//! carrick's runtime was written against macOS/Darwin `libc`. Many call sites
//! use BSD-only constants (`EV_*`/`NOTE_*` kqueue flags, `TCP_NOPUSH`, …), the
//! BSD errno accessor (`*libc::__error()`), or BSD-named equivalents of Linux
//! constants (`CLOCK_UPTIME_RAW`, `AF_LINK`). This crate re-exports each under a
//! single stable name resolved per `cfg(target_os)`, so the runtime can write
//! `carrick_portable::EV_ADD` once instead of cfg-gating every call site.
//!
//! Three flavors:
//!   * **alias** — a real equivalent exists on the other OS (e.g. Darwin
//!     `CLOCK_UPTIME_RAW` ↔ Linux `CLOCK_MONOTONIC_RAW`); re-exported natively.
//!   * **stub** — no equivalent (kqueue is BSD-only); on Linux these are typed
//!     placeholder values so macOS-shaped event-loop code COMPILES. They are
//!     **not functional on Linux** — the Linux event loop uses epoll via the
//!     HAL `EventMultiplexer` (full-Linux-backend spec, Phase C). Anything that
//!     reaches a stub at runtime on Linux is a bug to be fixed by that migration.
//!   * **fn** — an accessor that differs (`errno()`).
//!
//! A semgrep rule (`.semgrep/portability.yaml`) forbids new direct `libc::<X>`
//! uses for the symbols below, so the port doesn't regress.

/// Portable `termios` flag word. Darwin `tcflag_t` is `c_ulong` (u64); Linux's
/// is `c_uint` (u32). Use this for `c_iflag`/`c_oflag`/`c_cflag`/`c_lflag` bit
/// constants so the bitwise math matches the live `termios` fields on each OS.
pub type TcFlag = libc::tcflag_t;

/// Current thread errno. Darwin/FreeBSD use `__error()`, NetBSD `__errno()`,
/// Linux `__errno_location()`.
#[inline]
pub fn errno() -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error()` returns a valid per-thread pointer for the caller.
    {
        unsafe { *libc::__error() }
    }
    #[cfg(target_os = "netbsd")]
    // SAFETY: `__errno()` returns a valid per-thread pointer for the caller.
    {
        unsafe { *libc::__errno() }
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location()` returns a valid per-thread pointer.
    {
        unsafe { *libc::__errno_location() }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "linux"
    )))]
    {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

/// Set the current thread errno (inverse of [`errno`]). Used where carrick
/// synthesizes a host errno before mapping it to a Linux errno.
#[inline]
pub fn set_errno(value: i32) {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error()` returns a valid per-thread pointer for the caller.
    unsafe {
        *libc::__error() = value;
    }
    #[cfg(target_os = "netbsd")]
    // SAFETY: `__errno()` returns a valid per-thread pointer for the caller.
    unsafe {
        *libc::__errno() = value;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location()` returns a valid per-thread pointer.
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "linux"
    )))]
    {
        let _ = value;
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
unsafe extern "C" {
    #[link_name = "ptsname_r"]
    fn darwin_ptsname_r(
        fd: libc::c_int,
        buf: *mut libc::c_char,
        buflen: libc::size_t,
    ) -> libc::c_int;
}

/// `ptsname_r(3)` with one stable libc-shaped signature.
///
/// The libc crate exposes this on Linux, FreeBSD, and NetBSD, but not Darwin.
/// Darwin still provides the symbol, so keep the raw binding here instead of in
/// runtime code.
///
/// # Safety
///
/// `buf` must be valid for writes of `buflen` bytes, and `fd` must be a pty
/// master accepted by the host `ptsname_r`.
#[inline]
pub unsafe fn ptsname_r(
    fd: libc::c_int,
    buf: *mut libc::c_char,
    buflen: libc::size_t,
) -> libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
    {
        unsafe { libc::ptsname_r(fd, buf, buflen) }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        unsafe { darwin_ptsname_r(fd, buf, buflen) }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = (fd, buf, buflen);
        set_errno(libc::ENOSYS);
        -1
    }
}

/// Whether this host exposes real OFD (open file description) lock fcntl
/// commands with Linux-compatible ownership semantics.
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub const fn host_ofd_locks_supported() -> bool {
    true
}

/// Whether this host exposes real OFD (open file description) lock fcntl
/// commands with Linux-compatible ownership semantics.
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub const fn host_ofd_locks_supported() -> bool {
    false
}

/// OFD (open file description) lock fcntl commands. Linux and macOS libc define
/// `F_OFD_*`; FreeBSD and NetBSD have no OFD locks. On those hosts these retain
/// the historical classic-lock fallback for internal best-effort users, but
/// guest-facing syscall code must check [`host_ofd_locks_supported`] and reject
/// `F_OFD_*` rather than presenting process locks as OFD locks.
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub const F_OFD_GETLK: i32 = libc::F_OFD_GETLK;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub const F_OFD_GETLK: i32 = libc::F_GETLK;
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub const F_OFD_SETLK: i32 = libc::F_OFD_SETLK;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub const F_OFD_SETLK: i32 = libc::F_SETLK;
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub const F_OFD_SETLKW: i32 = libc::F_OFD_SETLKW;
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub const F_OFD_SETLKW: i32 = libc::F_SETLKW;

/// Nanosecond fields in `struct stat`. NetBSD's libc names these
/// `st_*timensec`; the other supported hosts expose `st_*time_nsec`. The field
/// is `c_long` (== `i64` on carrick's 64-bit hosts); the cast spells out the
/// width and is a no-op there, so the lint is allowed rather than dropped.
#[inline]
#[allow(clippy::unnecessary_cast)]
pub fn stat_atime_nsec(st: &libc::stat) -> i64 {
    #[cfg(target_os = "netbsd")]
    {
        st.st_atimensec as i64
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        st.st_atime_nsec as i64
    }
}

#[inline]
#[allow(clippy::unnecessary_cast)]
pub fn stat_mtime_nsec(st: &libc::stat) -> i64 {
    #[cfg(target_os = "netbsd")]
    {
        st.st_mtimensec as i64
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        st.st_mtime_nsec as i64
    }
}

#[inline]
#[allow(clippy::unnecessary_cast)]
pub fn stat_ctime_nsec(st: &libc::stat) -> i64 {
    #[cfg(target_os = "netbsd")]
    {
        st.st_ctimensec as i64
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        st.st_ctime_nsec as i64
    }
}

/// Assign the input/output speed fields in `struct termios`. NetBSD's fields
/// are `c_int` while `libc::speed_t` is `u32`.
#[inline]
pub fn set_termios_speeds(t: &mut libc::termios, ispeed: u32, ospeed: u32) {
    #[cfg(target_os = "netbsd")]
    {
        t.c_ispeed = ispeed as libc::c_int;
        t.c_ospeed = ospeed as libc::c_int;
    }
    #[cfg(not(target_os = "netbsd"))]
    {
        t.c_ispeed = ispeed as libc::speed_t;
        t.c_ospeed = ospeed as libc::speed_t;
    }
}

/// `ptrace(2)` wrapper with a portable integer address argument. The `request`
/// constants differ in libc type across platforms — glibc/musl bind the Linux
/// `PTRACE_*` enum values as `c_uint`, while the BSD/Darwin `PT_*` values are
/// `c_int` — so `request` is accepted as anything convertible to `i64` and cast
/// to each platform's expected type. NetBSD's libc binding takes `*mut c_void`;
/// Darwin/FreeBSD's binding takes `*mut c_char`; Linux's is variadic.
///
/// # Safety
/// Thin FFI wrapper over `ptrace(2)`: the caller must uphold that syscall's
/// contract for the given `request`/`data`, and `addr` is reinterpreted as the
/// platform pointer argument.
#[inline]
pub unsafe fn ptrace(
    request: impl Into<i64>,
    pid: libc::pid_t,
    addr: usize,
    data: libc::c_int,
) -> libc::c_int {
    let request: i64 = request.into();
    #[cfg(target_os = "netbsd")]
    {
        let ptr = if addr == 0 {
            std::ptr::null_mut::<libc::c_void>()
        } else {
            std::ptr::without_provenance_mut::<libc::c_void>(addr)
        };
        unsafe { libc::ptrace(request as libc::c_int, pid, ptr, data) }
    }
    #[cfg(target_os = "linux")]
    {
        // glibc/musl bind `ptrace` variadically as `ptrace(c_uint, ...) -> c_long`
        // for `long ptrace(enum __ptrace_request, pid_t, void *addr, void *data)`.
        // `addr` carries our integer address; `data` carries a signal number for
        // PT_CONTINUE/PT_DETACH, passed as the pointer-sized data word. The wide
        // result is truncated back to this shim's `c_int` return.
        let aptr = if addr == 0 {
            std::ptr::null_mut::<libc::c_void>()
        } else {
            std::ptr::without_provenance_mut::<libc::c_void>(addr)
        };
        let dptr = std::ptr::without_provenance_mut::<libc::c_void>(data as usize);
        unsafe { libc::ptrace(request as libc::c_uint, pid, aptr, dptr) as libc::c_int }
    }
    #[cfg(not(any(target_os = "netbsd", target_os = "linux")))]
    {
        // Darwin/FreeBSD: `int ptrace(int request, pid_t, caddr_t addr, int data)`.
        let ptr = if addr == 0 {
            std::ptr::null_mut::<libc::c_char>()
        } else {
            std::ptr::without_provenance_mut::<libc::c_char>(addr)
        };
        unsafe { libc::ptrace(request as libc::c_int, pid, ptr, data) }
    }
}

#[cfg(target_os = "netbsd")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sembuf {
    pub sem_num: libc::c_ushort,
    pub sem_op: libc::c_short,
    pub sem_flg: libc::c_short,
}

#[cfg(not(target_os = "netbsd"))]
pub type Sembuf = libc::sembuf;

#[cfg(target_os = "netbsd")]
#[repr(C)]
pub struct SemidDs {
    sem_perm: [u8; 32],
    pub sem_nsems: libc::c_ushort,
    _pad: [u8; 6],
    sem_otime: libc::time_t,
    sem_ctime: libc::time_t,
    sem_base: *mut libc::c_void,
}

#[cfg(not(target_os = "netbsd"))]
pub type SemidDs = libc::semid_ds;

/// `semget(2)` wrapper. Rust libc currently omits NetBSD SysV semaphore
/// bindings, so the NetBSD declarations live in this portability crate.
///
/// # Safety
/// Thin FFI wrapper over `semget(2)`; the arguments must be valid for that
/// syscall.
#[inline]
pub unsafe fn semget(key: libc::key_t, nsems: libc::c_int, semflg: libc::c_int) -> libc::c_int {
    #[cfg(target_os = "netbsd")]
    unsafe {
        unsafe extern "C" {
            fn semget(key: libc::key_t, nsems: libc::c_int, semflg: libc::c_int) -> libc::c_int;
        }
        semget(key, nsems, semflg)
    }
    #[cfg(not(target_os = "netbsd"))]
    unsafe {
        libc::semget(key, nsems, semflg)
    }
}

/// `semop(2)` wrapper (see [`semget`]).
///
/// # Safety
/// `sops` must point to `nsops` valid `Sembuf` entries for the duration of the
/// call.
#[inline]
pub unsafe fn semop(semid: libc::c_int, sops: *mut Sembuf, nsops: usize) -> libc::c_int {
    #[cfg(target_os = "netbsd")]
    unsafe {
        unsafe extern "C" {
            fn semop(semid: libc::c_int, sops: *mut Sembuf, nsops: usize) -> libc::c_int;
        }
        semop(semid, sops, nsops)
    }
    #[cfg(not(target_os = "netbsd"))]
    unsafe {
        libc::semop(semid, sops, nsops)
    }
}

/// `semctl(2)` wrapper for commands that take no fourth argument (`IPC_RMID`,
/// `GETVAL`, …).
///
/// # Safety
/// Thin FFI wrapper over `semctl(2)`; the arguments must be valid for `cmd`.
#[inline]
pub unsafe fn semctl0(semid: libc::c_int, semnum: libc::c_int, cmd: libc::c_int) -> libc::c_int {
    #[cfg(target_os = "netbsd")]
    unsafe {
        unsafe extern "C" {
            fn semctl(
                semid: libc::c_int,
                semnum: libc::c_int,
                cmd: libc::c_int,
                ...
            ) -> libc::c_int;
        }
        semctl(semid, semnum, cmd)
    }
    #[cfg(not(target_os = "netbsd"))]
    unsafe {
        libc::semctl(semid, semnum, cmd)
    }
}

/// `semctl(2)` wrapper for commands taking an `int` fourth argument (`SETVAL`).
///
/// # Safety
/// Thin FFI wrapper over `semctl(2)`; the arguments must be valid for `cmd`.
#[inline]
pub unsafe fn semctl_val(
    semid: libc::c_int,
    semnum: libc::c_int,
    cmd: libc::c_int,
    val: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "netbsd")]
    unsafe {
        unsafe extern "C" {
            fn semctl(
                semid: libc::c_int,
                semnum: libc::c_int,
                cmd: libc::c_int,
                ...
            ) -> libc::c_int;
        }
        semctl(semid, semnum, cmd, val)
    }
    #[cfg(not(target_os = "netbsd"))]
    unsafe {
        libc::semctl(semid, semnum, cmd, val)
    }
}

/// `semctl(2)` wrapper for commands taking a pointer fourth argument
/// (`IPC_STAT`/`IPC_SET`/`SETALL`/`GETALL`).
///
/// # Safety
/// `ptr` must be valid for the `semctl(2)` `cmd` (e.g. a `semid_ds` or
/// `semun`-style buffer) for the duration of the call.
#[inline]
pub unsafe fn semctl_ptr<T>(
    semid: libc::c_int,
    semnum: libc::c_int,
    cmd: libc::c_int,
    ptr: *mut T,
) -> libc::c_int {
    #[cfg(target_os = "netbsd")]
    unsafe {
        unsafe extern "C" {
            fn semctl(
                semid: libc::c_int,
                semnum: libc::c_int,
                cmd: libc::c_int,
                ...
            ) -> libc::c_int;
        }
        semctl(semid, semnum, cmd, ptr)
    }
    #[cfg(not(target_os = "netbsd"))]
    unsafe {
        libc::semctl(semid, semnum, cmd, ptr)
    }
}

#[inline]
pub fn sem_nsems(ds: &SemidDs) -> usize {
    ds.sem_nsems as usize
}

// ---- SysV IPC permission fields ----
// The Linux `ipc64_perm` owner/permission fields the guest reads back from an
// IPC_STAT (msgctl/semctl/shmctl) are a pure transform of the host object's
// `ipc_perm` (plus the guest's own creds). carrick runs as ONE host identity, so
// the owner and creator ids coincide. The host `mode` carries allocation flags
// the Linux ABI does not (macOS `SEM_ALLOC` = 0o1000, etc.); the guest must see
// only the 9 permission bits. Keeping the packing/masking here makes it testable
// on every host and shareable across the per-VMM lanes — the non-macOS lanes
// currently return a ZEROED perm (see carrick-runtime `dispatch/sysv.rs`
// IPC_STAT), which these helpers let a host-truth fill replace.

/// Permission-bit mask of a SysV IPC `mode` (rwx for owner/group/other).
pub const IPC_PERM_MODE_MASK: u32 = 0o777;

/// Mask a host IPC `mode` down to the Linux-visible permission bits, dropping
/// host allocation flags (e.g. macOS `SEM_ALLOC`). Used to fill `ipc_perm.mode`
/// for an IPC_STAT so the guest sees exactly the mode it created with.
#[inline]
pub fn ipc_perm_mode_to_linux(host_mode: u32) -> u32 {
    host_mode & IPC_PERM_MODE_MASK
}

/// Apply an IPC_SET `mode`: replace the host mode's permission bits with the
/// guest-supplied ones, preserving the host's non-permission (allocation) bits
/// so a subsequent IPC_STAT still reflects them. The host kernel re-adds its own
/// allocation flag regardless; this just keeps any other high bits intact.
#[inline]
pub fn ipc_set_apply_mode(host_mode: u32, guest_new_mode: u32) -> u32 {
    (host_mode & !IPC_PERM_MODE_MASK) | (guest_new_mode & IPC_PERM_MODE_MASK)
}

/// The Linux `ipc64_perm` owner/permission fields, built from host primitives.
/// (The full on-wire `ipc64_perm`/`semid64_ds` struct with its padding lives in
/// the runtime; this is only the value-carrying subset the transform decides.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpcPermFields {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: u16,
}

impl IpcPermFields {
    /// Build the `ipc_perm` fields from host-provided primitives. `owner_uid`/
    /// `owner_gid` are the effective owner (carrick is a single host identity,
    /// so creator == owner). `host_mode` is masked to the permission bits;
    /// `key`/`seq` come straight from the host `ipc_perm`.
    #[inline]
    pub fn from_host(key: i32, owner_uid: u32, owner_gid: u32, host_mode: u32, seq: u16) -> Self {
        Self {
            key,
            uid: owner_uid,
            gid: owner_gid,
            cuid: owner_uid,
            cgid: owner_gid,
            mode: ipc_perm_mode_to_linux(host_mode),
            seq,
        }
    }
}

// ---- extended attributes ----
// Darwin's f*xattr take a trailing `position` (resource-fork offset, always 0
// for the xattrs carrick uses) that Linux lacks; the `flags`/`options` arg also
// shifts position. These wrappers expose the common (Linux-shaped) signature.

/// Which BSD `extattr` namespace a Linux xattr name maps to. FreeBSD/NetBSD
/// expose only USER and SYSTEM `extattr` namespaces; the BSD call site turns this
/// enum into the matching `libc::EXTATTR_NAMESPACE_*` constant. Those constants
/// are BSD-only and do not exist on macOS, so the *mapping* lives here as a pure
/// transform that compiles and is unit-tested on every CI host (it regressed once
/// — commit 0660b721 — precisely because it could only be exercised on BSD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsdExtattrNamespace {
    /// `EXTATTR_NAMESPACE_USER` — holds Linux `user.*` (and any unprefixed name).
    User,
    /// `EXTATTR_NAMESPACE_SYSTEM` — holds the three privileged Linux namespaces
    /// (`system.`/`trusted.`/`security.`), distinguished by a 1-char stored tag.
    System,
}

/// Map a Linux-style xattr name to a BSD `(namespace, stored_name)` pair for the
/// `extattr_*` API.
///
/// FreeBSD/NetBSD `extattr` has only USER and SYSTEM namespaces, and the kernel
/// REJECTS any attr name that begins with a namespace name (`"user."`/`"system."`)
/// with EINVAL, so the Linux name can't be stored verbatim. Linux has four
/// namespaces (user/system/trusted/security): `user.*` lives in USER stripped
/// (USER unambiguously means `user.*`); the privileged three share SYSTEM but
/// carry a 1-char tag (`"s."`/`"t."`/`"c."`) so a list round-trip can tell them
/// apart. Without a tag all three collapsed to one indistinguishable
/// `SYSTEM:<name>`, so a `security.foo` set came back from listxattr as
/// `system.foo` (LTP flistxattr01/listxattr01). The tag is 1 char, so the stored
/// name never exceeds the Linux name (EXTATTR_MAXNAMELEN 255). Tags are not
/// namespace prefixes, so the kernel accepts them. An unrecognized prefix falls
/// back to USER, stored verbatim. [`bsd_xattr_to_linux`] is the inverse.
pub fn linux_xattr_to_bsd(name: &[u8]) -> (BsdExtattrNamespace, Vec<u8>) {
    if let Some(rest) = name.strip_prefix(&b"user."[..]) {
        return (BsdExtattrNamespace::User, rest.to_vec());
    }
    for (prefix, tag) in [
        (&b"system."[..], &b"s."[..]),
        (&b"trusted."[..], &b"t."[..]),
        (&b"security."[..], &b"c."[..]),
    ] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return (BsdExtattrNamespace::System, [tag, rest].concat());
        }
    }
    (BsdExtattrNamespace::User, name.to_vec())
}

/// Inverse of [`linux_xattr_to_bsd`]: decode a BSD `(namespace, stored_name)`
/// back to its Linux xattr name. Returns `None` for an UNtagged SYSTEM entry —
/// that is a host/OS attribute, not a guest one, and `listxattr` must skip it.
pub fn bsd_xattr_to_linux(ns: BsdExtattrNamespace, stored: &[u8]) -> Option<Vec<u8>> {
    match ns {
        BsdExtattrNamespace::User => Some([&b"user."[..], stored].concat()),
        BsdExtattrNamespace::System => {
            // Inverse of the tagging in `linux_xattr_to_bsd`.
            for (tag, prefix) in [
                (&b"s."[..], &b"system."[..]),
                (&b"t."[..], &b"trusted."[..]),
                (&b"c."[..], &b"security."[..]),
            ] {
                if let Some(rest) = stored.strip_prefix(tag) {
                    return Some([prefix, rest].concat());
                }
            }
            None
        }
    }
}

/// On BSD extattr hosts, parse a Linux-style xattr name into the
/// `(EXTATTR_NAMESPACE_*, attr_name)` pair the `extattr_*` API wants. Thin
/// BSD-only adapter over the pure [`linux_xattr_to_bsd`] transform: it only maps
/// the namespace enum to the libc constant and converts to a `CString`.
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
fn bsd_extattr_ns(name: &std::ffi::CStr) -> (libc::c_int, std::ffi::CString) {
    let (ns, attr) = linux_xattr_to_bsd(name.to_bytes());
    let ns_const = match ns {
        BsdExtattrNamespace::User => libc::EXTATTR_NAMESPACE_USER as libc::c_int,
        BsdExtattrNamespace::System => libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
    };
    (ns_const, std::ffi::CString::new(attr).unwrap_or_default())
}

/// `fsetxattr` with the portable `(fd, name, value, size, flags)` shape.
///
/// # Safety
/// `name` is a valid C string; `value` is readable for `size` bytes.
#[inline]
pub unsafe fn fsetxattr(
    fd: i32,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fsetxattr(fd, name, value, size, 0, flags) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fsetxattr(fd, name, value, size, flags) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        // extattr_set_fd has no flags parameter; xattr flags are ignored here.
        let _ = flags;
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_fd(fd, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (fd, name, value, size, flags);
        -libc::ENOSYS
    }
}

/// `fgetxattr` with the portable `(fd, name, value, size)` shape.
///
/// # Safety
/// `name` is a valid C string; `value` is writable for `size` bytes.
#[inline]
pub unsafe fn fgetxattr(
    fd: i32,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fgetxattr(fd, name, value, size, 0, 0) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fgetxattr(fd, name, value, size) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_fd(fd, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (fd, name, value, size);
        -libc::ENOSYS as isize
    }
}

/// `flistxattr` with the portable `(fd, list, size)` shape.
///
/// # Safety
/// `list` is writable for `size` bytes (or null with size 0).
#[inline]
pub unsafe fn flistxattr(fd: i32, list: *mut libc::c_char, size: usize) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::flistxattr(fd, list, size, 0) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::flistxattr(fd, list, size) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        // BSD extattr_list_fd returns per-namespace `[u8 len][name bytes]`
        // entries (no NUL terminator on each entry). Merge USER+SYSTEM
        // namespaces and re-emit Linux-style NUL-terminated `"prefix.name\0"`
        // entries.
        let mut out: Vec<u8> = Vec::new();
        for (ns, ns_enum) in [
            (
                libc::EXTATTR_NAMESPACE_USER as libc::c_int,
                BsdExtattrNamespace::User,
            ),
            (
                libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
                BsdExtattrNamespace::System,
            ),
        ] {
            let need = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
            if need <= 0 {
                continue;
            }
            let mut raw = vec![0u8; need as usize];
            let got = unsafe { libc::extattr_list_fd(fd, ns, raw.as_mut_ptr().cast(), raw.len()) };
            if got <= 0 {
                continue;
            }
            let raw = &raw[..got as usize];
            let mut i = 0usize;
            while i < raw.len() {
                let nlen = raw[i] as usize;
                i += 1;
                if i + nlen > raw.len() {
                    break;
                }
                let stored = &raw[i..i + nlen];
                i += nlen;
                // Decode back to the Linux namespace (inverse of bsd_extattr_ns):
                // USER holds user.* verbatim ("user." re-added); SYSTEM holds the
                // privileged three under 1-char tags. An UNtagged SYSTEM name is a
                // host/OS attribute, not a guest one — `bsd_xattr_to_linux` skips it.
                if let Some(name) = bsd_xattr_to_linux(ns_enum, stored) {
                    out.extend_from_slice(&name);
                    out.push(0);
                }
            }
        }
        if size == 0 {
            return out.len() as isize;
        }
        if out.len() > size {
            set_errno(libc::ERANGE);
            return -1;
        }
        unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), list.cast::<u8>(), out.len()) };
        out.len() as isize
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (fd, list, size);
        -libc::ENOSYS as isize
    }
}

/// `fremovexattr` with the portable `(fd, name)` shape.
///
/// # Safety
/// `name` is a valid C string.
#[inline]
pub unsafe fn fremovexattr(fd: i32, name: *const libc::c_char) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fremovexattr(fd, name, 0) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fremovexattr(fd, name) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_delete_fd(fd, ns, attr.as_ptr()) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (fd, name);
        -libc::ENOSYS
    }
}

// ---- path-based extended attributes ----
// Linux exposes path-based `{l,}{get,set}xattr`; macOS folds no-follow into a
// `XATTR_NOFOLLOW` option on `{get,set}xattr`; FreeBSD/NetBSD use
// `extattr_*_file` (follow) / `extattr_*_link` (no-follow). These wrappers
// expose the common Linux-shaped signature so call sites stay cfg-free.

/// Linux xattr flags, portable. BSD `extattr` has no create/replace flags; the
/// extattr shims accept and ignore them (matching the fd-based shims).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const XATTR_CREATE: libc::c_int = libc::XATTR_CREATE;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const XATTR_REPLACE: libc::c_int = libc::XATTR_REPLACE;
#[cfg(target_os = "linux")]
pub const XATTR_CREATE: libc::c_int = libc::XATTR_CREATE;
#[cfg(target_os = "linux")]
pub const XATTR_REPLACE: libc::c_int = libc::XATTR_REPLACE;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
pub const XATTR_CREATE: libc::c_int = 1;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
pub const XATTR_REPLACE: libc::c_int = 2;

/// Path-based `getxattr` (follow symlinks), portable `(path, name, value, size)`.
///
/// # Safety
/// `path`/`name` are valid C strings; `value` is writable for `size` bytes.
#[inline]
pub unsafe fn getxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::getxattr(path, name, value, size, 0, 0) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::getxattr(path, name, value, size) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_file(path, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (path, name, value, size);
        -libc::ENOSYS as isize
    }
}

/// Path-based `lgetxattr` (no-follow), portable `(path, name, value, size)`.
///
/// # Safety
/// As [`getxattr`].
#[inline]
pub unsafe fn lgetxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::getxattr(path, name, value, size, 0, libc::XATTR_NOFOLLOW) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::lgetxattr(path, name, value, size) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_link(path, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (path, name, value, size);
        -libc::ENOSYS as isize
    }
}

/// Path-based `setxattr` (follow symlinks), portable `(path, name, value, size, flags)`.
///
/// # Safety
/// `path`/`name` are valid C strings; `value` is readable for `size` bytes.
#[inline]
pub unsafe fn setxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::setxattr(path, name, value, size, 0, flags) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::setxattr(path, name, value, size, flags) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        // extattr_set_file has no flags parameter; xattr flags are ignored here.
        let _ = flags;
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_file(path, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (path, name, value, size, flags);
        -libc::ENOSYS
    }
}

/// Path-based `lsetxattr` (no-follow), portable `(path, name, value, size, flags)`.
///
/// # Safety
/// As [`setxattr`].
#[inline]
pub unsafe fn lsetxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::setxattr(path, name, value, size, 0, flags | libc::XATTR_NOFOLLOW) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::lsetxattr(path, name, value, size, flags) }
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let _ = flags;
        let (ns, attr) = bsd_extattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_link(path, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = (path, name, value, size, flags);
        -libc::ENOSYS
    }
}

/// Resolve a Darwin/FreeBSD `sendfile(2)` outcome to the Linux-shaped result.
///
/// Those hosts return `0` on success with the byte count in an out-parameter
/// (`*len`/`*sbytes`), and `-1` with `errno` set on failure — but on a partial
/// transfer over a non-blocking socket (or a signal) they set the out-parameter
/// to the bytes that DID reach the wire AND still return `-1` with `EAGAIN`/
/// `EINTR`. Linux's `sendfile` instead returns that partial count directly.
///
/// Given the raw host `rc`, the out-parameter `bytes_sent`, and `errno`, this
/// returns the value the guest should see: the byte count on full or partial
/// success, or a NEGATED errno on a hard error. Surfacing the partial count
/// (rather than `-EAGAIN`) is load-bearing — see commit f52046d5 and
/// `macos_sendfile_tests`: discarding it makes the caller re-send from the same
/// offset and duplicate everything already buffered.
#[inline]
pub fn resolve_sendfile_result(rc: i64, bytes_sent: usize, errno: i32) -> i64 {
    if rc == 0 {
        // Full success: all bytes are in the out-parameter.
        bytes_sent as i64
    } else if bytes_sent > 0 && (errno == libc::EAGAIN || errno == libc::EINTR) {
        // Partial transfer: report what reached the wire so the caller advances
        // the offset rather than re-sending and duplicating data.
        bytes_sent as i64
    } else {
        // Hard error (incl. EAGAIN/EINTR with nothing sent → caller should wait
        // for POLLOUT and retry from the same offset).
        -(errno as i64)
    }
}

/// Zero-copy regular-file → socket transfer. Returns bytes sent, or `-1` with the
/// thread-local `errno` set (Linux shape).
/// Darwin: `sendfile(file, sock, off, *len_in_out, hdtr, flags)`. Linux:
/// `sendfile(out_sock, in_file, *off, count)` — note the swapped fd order.
///
/// # Safety
/// `file_fd`/`sock_fd` are live fds owned by the caller.
#[inline]
pub unsafe fn sendfile_to_socket(file_fd: i32, sock_fd: i32, offset: i64, count: usize) -> isize {
    #[cfg(target_os = "macos")]
    {
        let mut len: libc::off_t = count as libc::off_t;
        // Darwin sendfile returns 0 on success (bytes in `len`) or -1 (errno set).
        // Normalize to the Linux shape via `resolve_sendfile_result`: bytes on
        // full/partial success, -1 (errno preserved in the thread-local) on a
        // hard error, so callers can recover the errno.
        let rc = unsafe {
            libc::sendfile(
                file_fd,
                sock_fd,
                offset as libc::off_t,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        let resolved = resolve_sendfile_result(rc as i64, len.max(0) as usize, errno());
        if resolved >= 0 {
            resolved as isize
        } else {
            // Hard error: the host call already set errno; preserve the
            // -1-with-errno-in-thread-local contract callers expect.
            rc as isize
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut off = offset as libc::off_t;
        unsafe { libc::sendfile(sock_fd, file_fd, &mut off, count) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let mut sbytes: libc::off_t = 0;
        // FreeBSD sendfile(2): sendfile(fd, s, offset, nbytes, hdtr, *sbytes, flags)
        // fd=source file, s=socket — note the arg order is opposite to Linux.
        // Returns 0 on success with bytes written in *sbytes; -1 on error (errno set).
        // SAFETY: file_fd/sock_fd are live caller-owned fds; sbytes is a valid out-param.
        let rc = unsafe {
            libc::sendfile(
                file_fd,
                sock_fd,
                offset as libc::off_t,
                count,
                std::ptr::null_mut(),
                &mut sbytes,
                0,
            )
        };
        // Same Linux-shape normalization as the Darwin arm (shared transform).
        let resolved = resolve_sendfile_result(rc as i64, sbytes.max(0) as usize, errno());
        if resolved >= 0 {
            resolved as isize
        } else {
            rc as isize
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (file_fd, sock_fd, offset, count);
        -libc::ENOSYS as isize
    }
}

/// Peer credentials `(pid, uid, gid)` of a connected `AF_UNIX` `host_fd`,
/// best-effort (`0` where unavailable). Linux exposes them in one call via
/// `SO_PEERCRED` -> `struct ucred`; Darwin has no single equivalent, so we read
/// `LOCAL_PEERCRED` (uid + primary gid via `xucred`) and `LOCAL_PEERPID` (pid).
/// Used to synthesize the `SO_PEERCRED`/`SCM_CREDENTIALS` the guest expects.
pub fn peer_ucred(host_fd: i32) -> (u32, u32, u32) {
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred/len are valid out-params for getsockopt on a socket fd.
        let rc = unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc == 0 {
            (cred.pid as u32, cred.uid, cred.gid)
        } else {
            (0, 0, 0)
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut xlen = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: xucred/xlen are valid out-params for getsockopt on a socket fd.
        let (uid, gid) = if unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                (&mut xucred as *mut libc::xucred).cast(),
                &mut xlen,
            )
        } == 0
        {
            (
                xucred.cr_uid,
                xucred.cr_groups.first().copied().unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        let mut peer_pid: libc::pid_t = 0;
        let mut plen = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: peer_pid/plen are valid out-params for getsockopt.
        let pid = if unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut peer_pid as *mut libc::pid_t).cast(),
                &mut plen,
            )
        } == 0
        {
            peer_pid as u32
        } else {
            0
        };
        (pid, uid, gid)
    }
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: uid/gid are valid out-params for getpeereid on a socket fd.
        // FreeBSD/NetBSD have no peer-pid API; report pid as 0.
        let rc = unsafe { libc::getpeereid(host_fd, &mut uid, &mut gid) };
        if rc == 0 {
            (0, uid as u32, gid as u32)
        } else {
            (0, 0, 0)
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = host_fd;
        (0, 0, 0)
    }
}

/// Re-export a constant that has a real (possibly differently-named) equivalent
/// on every platform. Two-way form: `port_alias!(NAME => bsd_name, linux_name)`
/// uses `bsd_name` on the BSD family (macOS, FreeBSD, NetBSD — for constants all
/// three share under the same libc name) and `linux_name` everywhere else.
/// Three-way form: `port_alias!(NAME => mac_name, freebsd_name, linux_name)` for
/// constants where macOS and FreeBSD use different libc names; here NetBSD takes
/// the `linux_name` arm by default — when NetBSD needs a *different* name, add an
/// explicit `netbsd =` clause: `port_alias!(NAME => mac, freebsd, linux, netbsd = nb)`.
///
/// NetBSD is a BSD, so it shares most constants with the `bsd_name` position
/// (e.g. `PT_*`); the explicit-`netbsd` form covers the deltas (e.g. NetBSD has
/// no `CLOCK_*_RAW`, so `CLOCK_UPTIME_RAW` maps to `CLOCK_MONOTONIC`).
macro_rules! port_alias {
    // BSD family (macOS + FreeBSD + NetBSD) share the same name; Linux differs.
    ($name:ident => $bsd:ident, $other:ident) => {
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
        pub use libc::$other as $name;
    };
    // macOS / FreeBSD / (Linux + NetBSD) each take a distinct name.
    ($name:ident => $mac:ident, $bsd:ident, $linux:ident) => {
        #[cfg(target_os = "freebsd")]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        pub use libc::$linux as $name;
        #[cfg(target_os = "macos")]
        pub use libc::$mac as $name;
    };
    // As the three-way form, but with an explicit NetBSD name distinct from all
    // three (NetBSD does not take the Linux arm).
    ($name:ident => $mac:ident, $bsd:ident, $linux:ident, netbsd = $nb:ident) => {
        #[cfg(target_os = "freebsd")]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
        pub use libc::$linux as $name;
        #[cfg(target_os = "macos")]
        pub use libc::$mac as $name;
        #[cfg(target_os = "netbsd")]
        pub use libc::$nb as $name;
    };
}

// Darwin name -> Linux equivalent. Re-exported as the Darwin name so call sites
// keep reading naturally; the value is the platform-native libc constant.
//
// CLOCK_UPTIME_RAW: macOS=CLOCK_UPTIME_RAW, FreeBSD=CLOCK_UPTIME_PRECISE
//   (both measure unhalted wall time; PRECISE is the highest-res FreeBSD clock);
//   NetBSD has no CLOCK_*_RAW/UPTIME clock, so map to CLOCK_MONOTONIC.
// TCP_KEEPALIVE: macOS name; FreeBSD/Linux/NetBSD all use TCP_KEEPIDLE (NetBSD
//   has no TCP_KEEPALIVE, so it correctly takes the `linux` = TCP_KEEPIDLE arm).
port_alias!(CLOCK_UPTIME_RAW => CLOCK_UPTIME_RAW, CLOCK_UPTIME_PRECISE, CLOCK_MONOTONIC_RAW, netbsd = CLOCK_MONOTONIC);
port_alias!(TCP_KEEPALIVE => TCP_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPIDLE);
port_alias!(AF_LINK => AF_LINK, AF_PACKET);

// TCP_NOPUSH: macOS/FreeBSD name; Linux uses TCP_CORK. NetBSD's libc bindings
// (libc 0.2.x) do NOT export TCP_NOPUSH even though <netinet/tcp.h> defines it,
// so supply the header value directly.
//   NetBSD /usr/include/netinet/tcp.h: `#define TCP_NOPUSH 4`
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use libc::TCP_NOPUSH;
#[cfg(target_os = "netbsd")]
pub const TCP_NOPUSH: libc::c_int = 4;
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
pub use libc::TCP_CORK as TCP_NOPUSH;

// Host `ptrace(2)` request constants (Darwin `PT_*` ↔ Linux `PTRACE_*`). NetBSD
// is a BSD and shares the `PT_*` names (libc `netbsdlike` module), so it takes
// the `bsd` arm of the two-way form. Used to drive the *host* ptrace when
// emulating the guest's ptrace; the request type also differs (Darwin `c_int`
// vs Linux `c_uint`), which the native re-export resolves automatically.
port_alias!(PT_TRACE_ME => PT_TRACE_ME, PTRACE_TRACEME);
port_alias!(PT_CONTINUE => PT_CONTINUE, PTRACE_CONT);
port_alias!(PT_KILL => PT_KILL, PTRACE_KILL);
port_alias!(PT_DETACH => PT_DETACH, PTRACE_DETACH);

/// `siginfo_t` field accessors. Darwin exposes `si_pid`/`si_uid`/`si_status` as
/// plain fields; the `libc` crate exposes them as *methods* on Linux (the
/// fields live in an anonymous union). These read-only accessors paper over
/// that so call sites read `carrick_portable::si_pid(&info)` on both.
macro_rules! siginfo_accessor {
    ($name:ident -> $ty:ty) => {
        #[inline]
        pub fn $name(info: &libc::siginfo_t) -> $ty {
            #[cfg(target_os = "macos")]
            {
                info.$name
            }
            #[cfg(not(target_os = "macos"))]
            // SAFETY: these read POSIX-defined members of the siginfo union;
            // libc marks the accessor `unsafe` only because it reads a union.
            {
                unsafe { info.$name() }
            }
        }
    };
}
siginfo_accessor!(si_pid -> libc::pid_t);
siginfo_accessor!(si_uid -> libc::uid_t);
siginfo_accessor!(si_status -> libc::c_int);

/// kqueue flag/filter/fflag constants. BSD-only; on Linux these are typed
/// placeholders (see the module doc) carrying the canonical BSD numeric value.
/// On macOS and FreeBSD the real `libc` constant is re-exported; on Linux a
/// typed placeholder carrying the canonical 4.4BSD numeric value is used.
macro_rules! port_kqueue {
    ($ty:ty: $($name:ident = $val:expr),+ $(,)?) => {
        $(
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            pub use libc::$name;
            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
            pub const $name: $ty = $val;
        )+
    };
}

// kevent.flags (EV_*) are u16, kevent.filter (EVFILT_*) i16, kevent.fflags
// (NOTE_*) u32. Linux placeholder values are the canonical 4.4BSD numbers.
port_kqueue!(u16:
    EV_ADD = 0x0001,
    EV_DELETE = 0x0002,
    EV_ENABLE = 0x0004,
    EV_ONESHOT = 0x0010,
    EV_CLEAR = 0x0020,
    EV_ERROR = 0x4000,
    EV_EOF = 0x8000,
);
port_kqueue!(i16:
    EVFILT_READ = -1,
    EVFILT_WRITE = -2,
);
port_kqueue!(u32:
    NOTE_DELETE = 0x0000_0001,
    NOTE_WRITE = 0x0000_0002,
    NOTE_EXTEND = 0x0000_0004,
    NOTE_ATTRIB = 0x0000_0008,
    NOTE_RENAME = 0x0000_0020,
);

#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_const_tests {
    #[test]
    fn port_kqueue_uses_real_freebsd_values() {
        assert_eq!(super::EV_CLEAR, libc::EV_CLEAR);
        assert_eq!(super::EVFILT_READ, libc::EVFILT_READ);
        assert_eq!(super::NOTE_WRITE, libc::NOTE_WRITE);
    }

    #[test]
    fn siginfo_accessor_reads_fields_on_freebsd() {
        let info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(super::si_pid(&info), 0);
        assert_eq!(super::si_uid(&info), 0);
        assert_eq!(super::si_status(&info), 0);
    }

    #[test]
    fn sendfile_to_socket_transfers_on_freebsd() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let mut tmp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open("/tmp/carrick_sendfile_test.bin")
            .unwrap();
        tmp.write_all(b"hello-sendfile").unwrap();
        tmp.flush().unwrap();
        let mut sv = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        let n = unsafe { super::sendfile_to_socket(tmp.as_raw_fd(), sv[0], 0, 14) };
        assert!(n > 0, "sendfile_to_socket returned {n}, expected > 0");
        let mut buf = [0u8; 14];
        let got = unsafe { libc::read(sv[1], buf.as_mut_ptr() as *mut libc::c_void, 14) };
        assert!(got > 0, "socket read returned {got}");
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_sendfile_tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    /// macOS `sendfile(2)` on a NON-BLOCKING socket whose send buffer fills
    /// transfers only a PARTIAL amount: it sets `*len` to the bytes actually
    /// sent AND returns -1 with errno `EAGAIN`. The wrapper must surface that
    /// partial count (Linux shape: bytes transferred), NOT -1 — otherwise the
    /// caller treats the call as "0 bytes sent", waits for `POLLOUT`, and
    /// re-sends from the SAME offset, duplicating everything already on the wire.
    /// (Repro: CPython `test_socket SendfileUsingSendfileTest` — a 10 MiB file
    /// puts hundreds of MiB on the wire and the guest spins.) carrick marks every
    /// host socket non-blocking, so this is the common case, not an edge case.
    #[test]
    fn partial_send_on_nonblocking_socket_reports_bytes_not_eagain() {
        // Far larger than any default socket send buffer, so the transfer is
        // guaranteed to be partial (nobody drains the peer).
        let size: usize = 16 * 1024 * 1024;
        let path = std::env::temp_dir().join(format!(
            "carrick_sendfile_partial_{}.bin",
            std::process::id()
        ));
        let mut tmp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        tmp.write_all(&vec![b'x'; size]).unwrap();
        tmp.flush().unwrap();

        let mut sv = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        // Send side non-blocking; peer sv[1] is never read, so the buffer fills.
        unsafe {
            let fl = libc::fcntl(sv[0], libc::F_GETFL);
            assert_eq!(libc::fcntl(sv[0], libc::F_SETFL, fl | libc::O_NONBLOCK), 0);
        }

        let n = unsafe { super::sendfile_to_socket(tmp.as_raw_fd(), sv[0], 0, size) };
        let err = super::errno();
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
        let _ = std::fs::remove_file(&path);

        assert!(
            n > 0,
            "expected the partial byte count (>0), got {n} (errno={err}); \
             macOS reported a partial transfer via EAGAIN and the wrapper discarded it"
        );
        assert!(
            (n as usize) < size,
            "expected a PARTIAL send (< {size}) on a filled non-blocking socket, got {n}"
        );
    }
}

#[cfg(all(test, any(target_os = "freebsd", target_os = "netbsd")))]
mod bsd_extattr_tests {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    fn xattr_unsupported(errno: i32) -> bool {
        errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP || errno == libc::ENOSYS
    }

    #[test]
    fn user_namespace_xattr_round_trip() {
        let f = std::fs::File::create("/tmp/carrick_xattr_test.bin").unwrap();
        let fd = f.as_raw_fd();
        let name = CString::new("user.carrick.test").unwrap();
        let val = b"42";
        let rc = unsafe { super::fsetxattr(fd, name.as_ptr(), val.as_ptr().cast(), val.len(), 0) };
        if rc < 0 {
            let errno = super::errno();
            assert!(
                xattr_unsupported(errno),
                "fsetxattr failed with unexpected errno {errno}"
            );
            let mut list = [0u8; 256];
            let ln = unsafe { super::flistxattr(fd, list.as_mut_ptr().cast(), list.len()) };
            assert_eq!(ln, 0, "unsupported flistxattr should be empty");
            return;
        }
        assert!(rc >= 0, "fsetxattr failed: {rc}");
        let mut buf = [0u8; 16];
        let got =
            unsafe { super::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(got, 2, "fgetxattr len");
        assert_eq!(&buf[..2], b"42");
        let mut list = [0u8; 256];
        let ln = unsafe { super::flistxattr(fd, list.as_mut_ptr().cast(), list.len()) };
        assert!(ln > 0, "flistxattr len {ln}");
        assert!(
            list[..ln as usize]
                .split(|&b| b == 0)
                .any(|e| e == b"user.carrick.test"),
            "list missing entry: {:?}",
            &list[..ln as usize]
        );
        let rm = unsafe { super::fremovexattr(fd, name.as_ptr()) };
        assert!(rm >= 0, "fremovexattr failed: {rm}");
    }

    #[test]
    fn path_namespace_xattr_round_trip() {
        let path = "/tmp/carrick_path_xattr_test.bin";
        std::fs::write(path, b"hi").unwrap();
        let cpath = CString::new(path).unwrap();
        let name = CString::new("user.carrick.ptest").unwrap();
        let val = 0x1122_3344u32.to_le_bytes();
        let rc = unsafe {
            super::setxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                val.as_ptr().cast(),
                val.len(),
                0,
            )
        };
        if rc < 0 {
            let errno = super::errno();
            assert!(
                xattr_unsupported(errno),
                "setxattr failed with unexpected errno {errno}"
            );
            let f = std::fs::File::open(path).unwrap();
            let mut list = [0u8; 256];
            let ln =
                unsafe { super::flistxattr(f.as_raw_fd(), list.as_mut_ptr().cast(), list.len()) };
            assert_eq!(ln, 0, "unsupported flistxattr should be empty");
            return;
        }
        assert_eq!(rc, 0, "setxattr failed: errno {}", super::errno());
        let mut out = [0u8; 4];
        let n = unsafe {
            super::getxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        assert_eq!(n, 4, "getxattr len");
        assert_eq!(out, val);
        // no-follow variant on a regular (non-symlink) file behaves identically.
        let ln = unsafe {
            super::lsetxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                val.as_ptr().cast(),
                val.len(),
                0,
            )
        };
        assert_eq!(ln, 0, "lsetxattr failed: errno {}", super::errno());
    }
}

/// Host-neutral tests for the PURE transforms (no syscalls). These run on the
/// macOS CI host — the very point of hoisting the logic here — covering the BSD
/// xattr-namespace mapping, the SysV `ipc_perm` packing/masking, and the
/// `sendfile` partial-count resolution that were previously trapped behind
/// BSD-only `cfg`s and exercised on zero CI lanes.
#[cfg(test)]
mod pure_transform_tests {
    use super::*;

    // ---- BSD xattr namespace tag round-trip (commit 0660b721) ----

    #[test]
    fn xattr_user_round_trips() {
        let (ns, stored) = linux_xattr_to_bsd(b"user.foo");
        assert_eq!(ns, BsdExtattrNamespace::User);
        // user.* is stored STRIPPED in the USER namespace (no tag).
        assert_eq!(stored, b"foo");
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"user.foo"[..])
        );
    }

    #[test]
    fn xattr_system_round_trips() {
        let (ns, stored) = linux_xattr_to_bsd(b"system.foo");
        assert_eq!(ns, BsdExtattrNamespace::System);
        // system.* shares SYSTEM but carries the "s." tag so it stays distinct
        // from trusted.*/security.* on a list round-trip.
        assert_eq!(stored, b"s.foo");
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"system.foo"[..])
        );
    }

    #[test]
    fn xattr_trusted_round_trips() {
        let (ns, stored) = linux_xattr_to_bsd(b"trusted.foo");
        assert_eq!(ns, BsdExtattrNamespace::System);
        assert_eq!(stored, b"t.foo");
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"trusted.foo"[..])
        );
    }

    #[test]
    fn xattr_security_round_trips() {
        let (ns, stored) = linux_xattr_to_bsd(b"security.foo");
        assert_eq!(ns, BsdExtattrNamespace::System);
        assert_eq!(stored, b"c.foo");
        // The regression guard: without the tag this came back as `system.foo`.
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"security.foo"[..])
        );
    }

    #[test]
    fn xattr_no_dot_falls_back_to_user() {
        // An unrecognized prefix (no namespace dot) is stored verbatim in USER.
        let (ns, stored) = linux_xattr_to_bsd(b"nodot");
        assert_eq!(ns, BsdExtattrNamespace::User);
        assert_eq!(stored, b"nodot");
        // On the way back out it is presented under the user namespace.
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"user.nodot"[..])
        );
    }

    #[test]
    fn xattr_each_namespace_decodes_distinctly() {
        // All three privileged namespaces share SYSTEM; the tags must keep them
        // from colliding (the original bug collapsed them to one).
        let cases: [(&[u8], &[u8]); 3] = [
            (b"system.x", b"system.x"),
            (b"trusted.x", b"trusted.x"),
            (b"security.x", b"security.x"),
        ];
        for (linux_name, expected) in cases {
            let (ns, stored) = linux_xattr_to_bsd(linux_name);
            assert_eq!(ns, BsdExtattrNamespace::System);
            assert_eq!(
                bsd_xattr_to_linux(ns, &stored).as_deref(),
                Some(expected),
                "round-trip failed for {linux_name:?}"
            );
        }
    }

    #[test]
    fn xattr_untagged_system_is_skipped() {
        // A SYSTEM entry that was NOT written by carrick (no s./t./c. tag) is a
        // host/OS attribute and must be skipped by listxattr.
        assert_eq!(
            bsd_xattr_to_linux(BsdExtattrNamespace::System, b"posix_acl"),
            None
        );
        assert_eq!(bsd_xattr_to_linux(BsdExtattrNamespace::System, b""), None);
    }

    #[test]
    fn xattr_empty_user_name() {
        // "user." with nothing after it stores an empty name and round-trips.
        let (ns, stored) = linux_xattr_to_bsd(b"user.");
        assert_eq!(ns, BsdExtattrNamespace::User);
        assert_eq!(stored, b"");
        assert_eq!(
            bsd_xattr_to_linux(ns, &stored).as_deref(),
            Some(&b"user."[..])
        );
    }

    // ---- SysV ipc_perm fill (sysv.rs IPC_STAT/IPC_SET) ----

    #[test]
    fn ipc_perm_mode_masks_allocation_flags() {
        // macOS sets SEM_ALLOC (0o1000) in the host mode; the guest must see only
        // the 9 permission bits.
        assert_eq!(ipc_perm_mode_to_linux(0o1666), 0o666);
        assert_eq!(ipc_perm_mode_to_linux(0o600), 0o600);
        assert_eq!(ipc_perm_mode_to_linux(0o777), 0o777);
        // Even higher host bits are dropped.
        assert_eq!(ipc_perm_mode_to_linux(0xffff_f000 | 0o644), 0o644);
    }

    #[test]
    fn ipc_set_mode_replaces_perm_bits_preserving_high() {
        // IPC_SET: take the guest's new perm bits, keep the host's allocation bits.
        assert_eq!(ipc_set_apply_mode(0o1666, 0o600), 0o1600);
        assert_eq!(ipc_set_apply_mode(0o1666, 0o000), 0o1000);
        // Guest mode wider than 0o777 is masked before being applied.
        assert_eq!(ipc_set_apply_mode(0o1000, 0o7777), 0o1777);
        // No host high bits → just the guest perm bits.
        assert_eq!(ipc_set_apply_mode(0o644, 0o600), 0o600);
    }

    #[test]
    fn ipc_perm_fields_from_host_packs_owner_and_creator() {
        let p = IpcPermFields::from_host(0x1234, 1000, 2000, 0o1640, 7);
        assert_eq!(p.key, 0x1234);
        assert_eq!(p.uid, 1000);
        assert_eq!(p.gid, 2000);
        // creator ids mirror the owner (single host identity).
        assert_eq!(p.cuid, 1000);
        assert_eq!(p.cgid, 2000);
        // mode masked to permission bits (SEM_ALLOC dropped).
        assert_eq!(p.mode, 0o640);
        assert_eq!(p.seq, 7);
    }

    #[test]
    fn ipc_perm_fields_default_is_zeroed() {
        let p = IpcPermFields::default();
        assert_eq!(
            p,
            IpcPermFields {
                key: 0,
                uid: 0,
                gid: 0,
                cuid: 0,
                cgid: 0,
                mode: 0,
                seq: 0
            }
        );
    }

    // ---- sendfile partial-count resolution (commit f52046d5) ----

    #[test]
    fn sendfile_full_success_reports_all_bytes() {
        // rc==0 → full success; bytes are in the out-parameter.
        assert_eq!(resolve_sendfile_result(0, 4096, 0), 4096);
        assert_eq!(resolve_sendfile_result(0, 0, 0), 0);
    }

    #[test]
    fn sendfile_partial_eagain_reports_partial_not_errno() {
        // The load-bearing case: -1/EAGAIN with bytes on the wire → report the
        // partial count, NOT -EAGAIN (else the caller re-sends and duplicates).
        assert_eq!(resolve_sendfile_result(-1, 512, libc::EAGAIN), 512);
        assert_eq!(resolve_sendfile_result(-1, 512, libc::EINTR), 512);
        assert_eq!(resolve_sendfile_result(-1, 1, libc::EAGAIN), 1);
    }

    #[test]
    fn sendfile_would_block_with_nothing_sent_is_hard_eagain() {
        // EAGAIN with zero bytes sent is a genuine "would block" → -EAGAIN so the
        // caller waits for POLLOUT and retries from the same offset.
        assert_eq!(
            resolve_sendfile_result(-1, 0, libc::EAGAIN),
            -(libc::EAGAIN as i64)
        );
        assert_eq!(
            resolve_sendfile_result(-1, 0, libc::EINTR),
            -(libc::EINTR as i64)
        );
    }

    #[test]
    fn sendfile_hard_error_reports_negated_errno() {
        // A real failure (EPIPE, EBADF, …) → negated errno regardless of any
        // partial count, since errno is not EAGAIN/EINTR.
        assert_eq!(
            resolve_sendfile_result(-1, 0, libc::EPIPE),
            -(libc::EPIPE as i64)
        );
        assert_eq!(
            resolve_sendfile_result(-1, 0, libc::EBADF),
            -(libc::EBADF as i64)
        );
        // Even with a stray byte count, a non-retryable errno is a hard error.
        assert_eq!(
            resolve_sendfile_result(-1, 100, libc::EPIPE),
            -(libc::EPIPE as i64)
        );
    }
}
