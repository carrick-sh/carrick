/// A POSITIVE Linux errno (the `LINUX_E*` domain). The guest-visible retval is
/// its single negation — made in exactly ONE place
/// ([`LinuxErrno::guest_retval`]) so a pre-negated value can never be
/// double-negated and a positive errno can never leak as a "success" retval.
/// Debug builds assert the 1..=4095 kernel errno range at construction.
/// Serializes transparently as the positive errno number (a serde newtype
/// struct is its inner value on the wire), so reporter/JSON output is
/// unchanged by the typing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub struct LinuxErrno(i32);

impl LinuxErrno {
    /// Wrap a positive errno constant/translation result. `const` so the
    /// `LINUX_E*` table is a set of typed constants (usable in const items and
    /// match patterns) with zero per-site wrapping.
    #[inline]
    #[track_caller]
    pub const fn new(errno: i32) -> Self {
        // `RangeInclusive::contains` and format captures are not const;
        // spell the range check out so the assert works in const fn.
        debug_assert!(
            errno >= 1 && errno <= 4095,
            "errno outside the kernel's 1..=4095 range"
        );
        LinuxErrno(errno)
    }

    /// The positive errno value (reporting, siginfo, comparisons).
    #[inline]
    pub const fn get(self) -> i32 {
        self.0
    }

    /// THE negation choke point: the raw retval the guest receives.
    #[inline]
    pub const fn guest_retval(self) -> i64 {
        -(self.0 as i64)
    }

    /// Recover the errno from a guest retval in the kernel's errno window,
    /// `None` for any other value (a legitimate negative return is NOT an
    /// errno). Replaces the ad-hoc `(-ret) as u32` re-derivations.
    #[inline]
    #[allow(clippy::manual_range_contains)] // `RangeInclusive::contains` is not const.
    pub const fn from_guest_retval(ret: i64) -> Option<LinuxErrno> {
        if ret >= -4095 && ret <= -1 {
            Some(LinuxErrno(-ret as i32))
        } else {
            None
        }
    }
}

pub const LINUX_ECHILD: LinuxErrno = LinuxErrno::new(10);
pub const LINUX_EAGAIN: LinuxErrno = LinuxErrno::new(11);
pub const LINUX_EFAULT: LinuxErrno = LinuxErrno::new(14);
pub const LINUX_EINVAL: LinuxErrno = LinuxErrno::new(22);
