//! Shared HAL error and register/permission types used across the
//! hypervisor and host-primitive traits.

use thiserror::Error;

/// Uniform OS-operation error for HAL trait methods. Carries the raw host
/// errno (already host-namespaced; translate to Linux via
/// [`crate::host_to_linux_errno`]) plus a context string.
#[derive(Debug, Error)]
#[error("{context}: os error {errno}")]
pub struct OsError {
    pub errno: i32,
    pub context: String,
}

impl OsError {
    /// Construct from the current `errno`, tagging it with a static call-site context.
    pub fn last(context: &str) -> Self {
        Self::new(context)
    }

    /// Construct from the current `errno` with the given context.
    pub fn new(context: impl Into<String>) -> Self {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd"))]
        let errno = unsafe { *libc::__error() };
        #[cfg(target_os = "linux")]
        let errno = unsafe { *libc::__errno_location() };
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd", target_os = "netbsd", target_os = "linux")))]
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

        Self {
            errno,
            context: context.into(),
        }
    }

    /// Construct from a raw errno with no context.
    pub fn from_raw(errno: i32) -> Self {
        Self {
            errno,
            context: String::new(),
        }
    }
}

/// Guest-memory mapping permissions passed to [`crate::hypervisor::HvVm::map_memory`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemPerms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl MemPerms {
    /// Helper to construct Read-Write-Execute permissions.
    #[allow(non_upper_case_globals)]
    pub const ReadWriteExec: Self = Self {
        read: true,
        write: true,
        exec: true,
    };
}

/// General-purpose / control registers addressable through
/// [`crate::hypervisor::HvVcpu::reg`] / `set_reg`. `X(n)` is `x0..x30`
/// (`n` in `0..=30`). System registers are NOT here — see [`SysReg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    X(u32),
    Sp,
    Pc,
    Pstate,
}

/// AArch64 system registers programmed during guest bring-up
/// (stage-1 MMU + vector table + EL1 state). Set via
/// [`crate::hypervisor::HvVcpu::set_sys_reg`]. Short names (no `_EL1`
/// suffix); this is the canonical superset the KVM bring-up (`carrick-linux`)
/// programs — see reconciliation R5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysReg {
    Sctlr,
    Ttbr0,
    Ttbr1,
    Tcr,
    Mair,
    Vbar,
    Cpacr,
    SpEl1,
}
