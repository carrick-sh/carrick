//! Typed wrappers for raw syscall arguments, so handlers stop doing
//! `ctx.arg(0) as i32` by hand and the compiler distinguishes an fd from
//! a guest address. Zero-cost newtypes.
use super::{DispatchError, GuestMemory, SyscallCtx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fd(pub i32);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub i32);
/// A signal number argument (`int` in the kernel ABI).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(pub i32);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPtr(pub u64);
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
impl FromGuestArg for Pid {
    fn from_arg(raw: u64) -> Self {
        Pid(raw as i32)
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
