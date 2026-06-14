//! Shared HAL error and register/permission types used across the
//! hypervisor and host-primitive traits.

use thiserror::Error;

/// Uniform OS-operation error for HAL trait methods. Carries the raw host
/// errno (already host-namespaced; translate to Linux via
/// `carrick_runtime::host_to_linux_errno`) plus a context string.
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
        // Darwin/FreeBSD/DragonFly expose the per-thread errno via `__error()`;
        // NetBSD/OpenBSD via `__errno()`; Linux via `__errno_location()`.
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "dragonfly"
        ))]
        let errno = unsafe { *libc::__error() };
        #[cfg(any(target_os = "openbsd", target_os = "netbsd"))]
        let errno = unsafe { *libc::__errno() };
        #[cfg(target_os = "linux")]
        let errno = unsafe { *libc::__errno_location() };
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "linux"
        )))]
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

/// Registers that live in KVM's **core** register file (`struct kvm_regs`),
/// addressed through [`crate::hypervisor::HvVcpu::reg`] / `set_reg`.
///
/// On aarch64 KVM, `kvm_regs` holds the `user_pt_regs` (x0..x30, `sp`, `pc`,
/// `pstate`) *plus* the EL1 exception-return state (`sp_el1`, `elr_el1`,
/// `spsr[]`). These are NOT in the sysreg "demux" interface — they must be set
/// via the core-register byte offsets, not [`SysReg`]. Note `Sp` is
/// `user_pt_regs.sp`, i.e. **SP_EL0** (the EL0/user stack).
///
/// `X(n)` is `x0..x30` (`n` in `0..=30`). True system registers (SCTLR, TTBR,
/// …) are in [`SysReg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    X(u32),
    /// `user_pt_regs.sp` == SP_EL0 (the EL0/user stack pointer).
    Sp,
    Pc,
    Pstate,
    /// `kvm_regs.sp_el1` — the EL1 stack pointer.
    SpEl1,
    /// `kvm_regs.elr_el1` — exception link register (eret target PC).
    ElrEl1,
    /// `kvm_regs.spsr[0]` == SPSR_EL1 — saved PSTATE (eret target PSTATE).
    SpsrEl1,
    // ── x86_64 user register view (kvm_regs). Disjoint from the aarch64 set
    // above: an x86 engine never uses X(n)/Sp/Pc/Pstate/SpEl1/ElrEl1/SpsrEl1, and
    // an aarch64 engine never uses these. Keeping them as explicit, separate
    // variants (vs aliasing onto the aarch64 names) makes every per-ISA match
    // total and turns a cross-ISA mixup into a compile error, not silent garbage.
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags,
}

/// AArch64 **system** registers reached through KVM's `KVM_REG_ARM64_SYSREG`
/// demux (op0/op1/CRn/CRm/op2 encoded), set via
/// [`crate::hypervisor::HvVcpu::set_sys_reg`]. These are the stage-1 MMU +
/// vector-table control registers programmed during guest bring-up.
///
/// EL1 exception-return state (ELR/SPSR/SP_EL1) is deliberately NOT here — on
/// KVM those are core-file registers; see [`Reg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysReg {
    Sctlr,
    Ttbr0,
    Ttbr1,
    Tcr,
    Mair,
    Vbar,
    Cpacr,
    /// `TPIDR_EL0` — the EL0 thread pointer (musl/glibc TLS base). Captured and
    /// restored across `fork(2)` so the child resumes with the correct thread
    /// pointer; otherwise the child's libc post-clone path computes thread-struct
    /// offsets from a bogus base. (KVM sysreg demux: op0=3,op1=3,CRn=13,CRm=0,op2=2.)
    TpidrEl0,
    /// x86_64 `FS.base` — the long-mode TLS pointer (arch_prctl ARCH_SET_FS).
    /// Disjoint from the aarch64 set above (see [`Reg`] for the rationale).
    FsBase,
    /// x86_64 `GS.base`.
    GsBase,
}
