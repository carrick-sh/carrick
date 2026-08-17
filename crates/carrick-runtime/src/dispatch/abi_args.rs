//! Typed wrappers for raw syscall arguments, so handlers stop doing
//! `ctx.arg(0) as i32` by hand and the compiler distinguishes an fd from
//! a guest address. Zero-cost newtypes.
use super::{DispatchError, GuestMemory, SyscallCtx};

/// A **GUEST** file descriptor — a number in the guest's fd table (what the
/// guest passed as a syscall argument), NOT a host kernel fd. Resolve it
/// through the fd table (`open_file` and the typed accessors) to reach the
/// backing [`HostFd`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fd(pub i32);
/// A HOST kernel file descriptor — the other side of the fd seam from the
/// GUEST-fd [`Fd`]. Guest and host fds previously both flowed as bare `i32`,
/// and the splice/tee/sendfile paths juggle both under identical variable
/// names; passing a guest fd to libc (or a host fd back into the guest fd
/// table) compiled clean and operated on an unrelated descriptor. Escape to
/// raw only at the libc boundary via [`HostFd::get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFd(pub i32);

impl HostFd {
    /// The raw fd for a host `libc` call.
    #[inline]
    pub fn get(self) -> i32 {
        self.0
    }
}
/// A PID/TID **argument supplied by the guest** — an ns-namespace value (what
/// the guest's `getpid()`/`gettid()` reported), NOT a host pid. Operate on it
/// only after translating to a [`HostPid`] via [`NsPid::to_host`]; test
/// self-identity with [`NsPid::names_self`]. Keeping it distinct from `HostPid`
/// turns "forgot to translate" into a compile error instead of an ESRCH bug —
/// the recurring class (tkill / sched / setpgid / fcntl-owner / fasync / …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NsPid(pub i32);
/// A **host** pid/pgid carrick passes to libc or reads back from the host.
/// Present it to the guest via [`HostPid::to_guest`] (host→ns) — never leak a
/// raw host pid across the ns boundary into a guest-visible return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPid(pub u32);
/// Back-compat alias: existing handler signatures spell the guest pid arg
/// `Pid`; it IS an ns value. New/converted code uses the explicit `NsPid`.
pub type Pid = NsPid;

/// The calling task's own Linux pid, from carrick's kernel when a dispatch
/// scope is active, else the host process.
///
/// Measured on the kernel lane (`carrick debug hvpatch-kernel` against a live
/// run): the root task's id IS the host pid and a child's id IS the pid the
/// child's `getpid(2)` returns. So this single value distinguishes the two
/// cases the bootstrap-pid alias has to tell apart — a root, whose id equals
/// the host pid, from a child, whose id does not — without needing to know
/// which lane it is running on.
fn caller_task_pid() -> i32 {
    super::resources::with_active_context(|context| context.task().key().id.raw())
        .unwrap_or_else(|| std::process::id() as i32)
}

impl NsPid {
    /// The raw ns value the guest passed (for sentinel/sign checks like `-1`,
    /// or `0`/negative whole-group targets the caller interprets itself).
    #[inline]
    pub fn raw(self) -> i32 {
        self.0
    }

    /// True iff this names the CALLING PROCESS: the host pid, the bootstrap pid
    /// (1), or — under a PID namespace — the caller's own ns-pid (directly, or
    /// an ns value that maps back to our host pid). Deliberately NOT `0` (for
    /// signals `0` targets the caller's process GROUP, not self) and NOT sibling
    /// threads (resolve those through the thread registry); callers that want
    /// either add them explicitly. The ONE canonical self-check — the drift
    /// between four ad-hoc copies caused the tkill01 / sched ns-pid bugs.
    /// "Is this target me?" cannot be decided without knowing who is asking,
    /// so this resolves the caller from the active dispatch context rather
    /// than assuming the host process is the answer. See [`caller_task_pid`].
    pub fn names_self(self) -> bool {
        let host = std::process::id();
        let caller = caller_task_pid();
        // The precise case: the target IS the caller's own task id.
        if self.0 == caller {
            return true;
        }
        if self.0 == host as i32 {
            return true;
        }
        // The bootstrap-pid alias, NARROWED. It exists because on the
        // non-namespaced OCI path the guest init presents itself as pid 1 while
        // carrick has no distinct identity to offer it, so `caller` is the host
        // pid and a `kill(1)` from it really is a self-target.
        //
        // On the kernel lane that is no longer true: a Linux process is a
        // thread, `caller` is its own guest pid, and pid 1 is a DIFFERENT
        // process — the container init. Applying the alias there made every
        // child treat `kill(1, …)` as suicide. Gating it on `caller` having no
        // distinct identity keeps the original case and drops the wrong one.
        if self.0 == carrick_abi::LINUX_BOOTSTRAP_PID as i32 && caller == host as i32 {
            return true;
        }
        if self.0 > 0 && crate::namespace::pid::enabled() {
            let v = self.0 as u32;
            if v == crate::namespace::pid::self_ns_pid()
                || crate::namespace::pid::ns_to_host_or_self(v) == Some(host)
            {
                return true;
            }
        }
        false
    }

    /// Translate to the host pid to operate on (libc::kill, `/proc`, …). `None`
    /// (→ ESRCH) for a positive ns-pid naming no namespace member. Identity when
    /// namespaces are off. Only meaningful for a concrete pid (`> 0`); `0` and
    /// negative sentinels (whole-group, "any child") are the caller's to read.
    pub fn to_host(self) -> Option<HostPid> {
        if self.0 <= 0 {
            return None;
        }
        crate::namespace::pid::ns_to_host_or_self(self.0 as u32).map(HostPid)
    }

    /// Translate a guest ns-PGID to the host pgid. `None` (→ ESRCH) for an ns
    /// pgid naming no group. (`0` = "the caller's own pgid" — caller resolves.)
    pub fn to_host_pgid(self) -> Option<HostPid> {
        if self.0 <= 0 {
            return None;
        }
        crate::namespace::pid::ns_to_host_pgid(self.0 as u32).map(HostPid)
    }
}

impl HostPid {
    /// This process's own host pid.
    #[inline]
    pub fn current() -> Self {
        HostPid(std::process::id())
    }

    /// The raw host pid (for libc calls that take a bare `pid_t`).
    #[inline]
    pub fn get(self) -> u32 {
        self.0
    }

    /// Present this host pid to the guest as its ns-pid (host→ns). Use for every
    /// pid carrick RETURNS to the guest (getpid/getppid, fcntl `l_pid`, `si_pid`,
    /// wait status…) so the guest never observes a raw host pid.
    #[inline]
    pub fn to_guest(self) -> i64 {
        i64::from(crate::namespace::pid::host_to_ns_or_self(self.0))
    }
}

/// A signal number argument (`int` in the kernel ABI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(pub i32);
pub use carrick_guest_mem::GuestVa;

/// Typed guest memory pointer argument with seamless conversion to/from [`GuestVa`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct GuestPtr(pub u64);

impl GuestPtr {
    #[inline]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn to_va(self) -> GuestVa {
        GuestVa(self.0)
    }
}

impl From<GuestVa> for GuestPtr {
    #[inline]
    fn from(va: GuestVa) -> Self {
        Self(va.0)
    }
}

impl From<GuestPtr> for GuestVa {
    #[inline]
    fn from(ptr: GuestPtr) -> Self {
        GuestVa(ptr.0)
    }
}

impl From<u64> for GuestPtr {
    #[inline]
    fn from(raw: u64) -> Self {
        Self(raw)
    }
}

impl From<GuestPtr> for u64 {
    #[inline]
    fn from(ptr: GuestPtr) -> Self {
        ptr.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestLen(pub usize);

pub trait FromGuestArg: Sized {
    fn from_arg(raw: u64) -> Self;
}
impl FromGuestArg for Fd {
    fn from_arg(raw: u64) -> Self {
        Fd(raw as i32)
    }
}
impl FromGuestArg for NsPid {
    fn from_arg(raw: u64) -> Self {
        NsPid(raw as i32)
    }
}
impl FromGuestArg for Signal {
    fn from_arg(raw: u64) -> Self {
        Signal(raw as i32)
    }
}
impl FromGuestArg for GuestPtr {
    fn from_arg(raw: u64) -> Self {
        GuestPtr(raw)
    }
}
impl FromGuestArg for GuestVa {
    fn from_arg(raw: u64) -> Self {
        GuestVa(raw)
    }
}
impl FromGuestArg for u64 {
    fn from_arg(raw: u64) -> Self {
        raw
    }
}

impl GuestLen {
    /// Convert a raw arg to a length, rejecting values that can't be a
    /// host buffer size. (On a 64-bit host every u64 fits in usize, so
    /// this is mainly a typed marker + future-proofing.)
    pub fn try_from_arg(raw: u64) -> Result<Self, DispatchError> {
        usize::try_from(raw)
            .map(GuestLen)
            .map_err(|_| DispatchError::LengthTooLarge(raw))
    }
}

impl<M: GuestMemory> SyscallCtx<'_, M> {
    /// Typed argument extraction: `let fd: Fd = ctx.typed_arg(0);`
    #[inline]
    pub fn typed_arg<T: FromGuestArg>(&self, index: usize) -> T {
        T::from_arg(self.request.arg(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fd_from_arg_truncates_to_i32() {
        assert_eq!(Fd::from_arg(0xffff_ffff_0000_0005).0, 5);
    }
    #[test]
    fn pid_signal_read_pid_t_width() {
        // A guest tid=-1 arrives as 0xFFFFFFFF in the low 32 bits (upper bits
        // unspecified); reading it at pid_t width must yield -1, not a large
        // positive value — the tkill02/tgkill03 EINVAL bug.
        assert_eq!(Pid::from_arg(0x0000_0000_ffff_ffff).0, -1);
        assert_eq!(Pid::from_arg(0xffff_ffff_ffff_ffff).0, -1);
        assert_eq!(Signal::from_arg(0xdead_beef_0000_000a).0, 10);
    }
    #[test]
    fn guest_ptr_preserves_u64() {
        assert_eq!(GuestPtr::from_arg(0xdead_beef_cafe).0, 0xdead_beef_cafe);
    }
    #[test]
    fn guest_len_rejects_absurd() {
        assert!(GuestLen::try_from_arg(u64::MAX).is_err() || usize::BITS >= 64);
    }
}
