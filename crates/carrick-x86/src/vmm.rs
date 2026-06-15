//! The thin per-VMM backend trait pair (`X86Vmm` + `X86Vcpu`) and the small
//! value types they trade in (`X86Exit`, `MsrInstall`, `ForkRamStrategy`,
//! `WindowPlan`, `X86Reg`, `X86Seg`).
//!
//! This is the Axis-2 (VMM-backend) seam: everything that is *genuinely*
//! per-VMM is named here, and `carrick-x86`'s engine scaffold is written ONCE
//! over this pair (Stage 2+). The trait surface is reverse-engineered from the
//! KVM ∩ bhyve intersection and the two bhyve outliers are quarantined as the
//! two enum returns [`MsrInstall::NeedsRing0Blob`] and `X86Vcpu::get_fp() ==
//! None`, so removing any one backend would not simplify the trait.
//!
//! Stage 1 defines this surface only — NOTHING implements it yet (no backend is
//! migrated). It must compile standalone.

use carrick_guest_mem::X8664SyscallFrame;
use carrick_hal::TrapError;

/// The shared x86 register view the engine reads/writes through the backend. The
/// union of KVM's `kvm_regs` named fields, bhyve's `vm_reg_name` ordinals, and
/// NVMM's `NvmmX64State.gprs[]` array — every backend marshals these to/from its
/// native register struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Reg {
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
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Efer,
}

/// The x86 segment registers the long-mode bring-up programs. Each backend
/// realizes `set_segment` via `kvm_segment`/`kvm_sregs` (KVM), `vm_set_desc`
/// ordinals (bhyve), or the `NvmmX64StateSeg` array (NVMM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Seg {
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Tr,
    Ldtr,
    Gdtr,
    Idtr,
}

/// The shared exit shape. Lifted from bhyve's private `X86Exit` ∪ KVM's
/// `VcpuExit::IoOut`/`Halt`/`Kicked`. Backends decode their native exit into
/// THIS.
///
/// `resume_pc` is the next-RIP to continue at after a syscall doorbell:
///   - auto-advancing VMMs (NVMM `io.npc`) fill it directly;
///   - KVM fills it = current RIP (sysretq already advanced it);
///   - bhyve computes it = `exit.rip + exit.inst_length` at decode time (its
///     native `VmExit` carries `rip` + `inst_length` separately; the
///     `inst_length` is consumed HERE, not retained by the backend).
///
/// STATEFUL OBLIGATION (the §2.1 contract): collapsing bhyve's old
/// `PendingInout { rip, inst_length }` into one `resume_pc` moves the "which
/// doorbell is pending" bookkeeping INTO the engine. The backend's `run()` is
/// stateless w.r.t. the pending syscall: it returns `Syscall { frame, resume_pc
/// }` and the engine — not the backend — holds the pending-completion state
/// until `complete_syscall` writes the return value and resumes at `resume_pc`.
#[derive(Debug, Clone)]
pub enum X86Exit {
    /// The SYSCALL doorbell (`out %al, $SYSCALL_DOORBELL_PORT`). `frame` is the
    /// decoded syscall frame; `resume_pc` is where to resume after completion.
    Syscall {
        frame: X8664SyscallFrame,
        resume_pc: u64,
    },
    /// `HLT` (requires the per-backend halt-exit capability).
    Halt,
    /// A spurious re-entry / cross-thread kick: no syscall pending. The threaded
    /// loop re-checks signals/futex/quiesce and re-enters.
    Kicked,
    /// The FP-stub completion doorbell (`out %al, $FP_STUB_DOORBELL_PORT`) fired:
    /// the ring-3 FXSAVE/FXRSTOR stub finished. Only a no-FP-getter backend
    /// (`get_fp() == None`) ever surfaces this, and only while
    /// [`crate::bringup::run_fp_stub`] is driving the stub.
    FpDoorbell,
    /// A synchronous guest fault → the runtime delivers it as
    /// [`carrick_hal::TrapError::GuestFault`] (SIGSEGV/SIGBUS). `gpa` is the
    /// faulting address (CR2 on x86); `error_code` is the page-fault error code.
    Fault {
        kind: X86FaultKind,
        gpa: u64,
        error_code: u64,
    },
}

/// The class of an [`X86Exit::Fault`]. Maps to the Linux `(signum, si_code)` the
/// runtime delivers via [`carrick_hal::TrapError::GuestFault`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86FaultKind {
    /// Page fault (#PF) → SIGSEGV.
    PageFault,
    /// General protection / alignment fault → SIGSEGV/SIGBUS.
    Protection,
    /// Any other fatal guest exception.
    Other,
}

/// What a VMM gives up to wrap an MSR write of LSTAR/STAR/SFMASK. The shared
/// bring-up branches on this ONCE instead of every backend re-deciding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsrInstall {
    /// `KVM_SET_MSRS` / NVMM `setstate(MSRS)` — bring-up calls `set_syscall_msrs`
    /// and the MSRs are live immediately.
    Direct,
    /// FreeBSD libvmmapi has no MSR ioctl — the bring-up must splice the
    /// ring-0 [`crate::bringup::msr_init_blob`] (a WRMSR-then-iretq stub) into
    /// the guest and run it once to install the MSRs.
    NeedsRing0Blob,
}

/// COW-inherit vs eager full-RAM copy at `fork(2)`. POLICY only: the shared
/// `fork_x86` reads this to decide *whether* to freeze; the `EagerCopy`
/// MECHANISM (frozen-RAM memcpy, fresh named child VM) stays in the backend,
/// exposed as `freeze_ram`/`rebuild_child_vm` that `fork_x86` *calls* but does
/// not own (§2.5b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkRamStrategy {
    /// KVM `MAP_PRIVATE` / NVMM host-fork COW: the child inherits RAM for free,
    /// nothing is copied.
    Cow,
    /// bhyve kernel-owned non-COW RAM: the parent freezes the whole segment into
    /// a host buffer pre-fork and the child rebuilds a fresh named VM from it.
    EagerCopy,
}

/// One region of the guest address space the bring-up wants mapped: a `va`/`gpa`
/// pair of `len` bytes with `perms`. The ordered list is the *union* of both
/// backends' needs (§2.5a): KVM reads it as N per-region slots; bhyve reads
/// `max(gpa + len)` + the base-0 contiguity assumption and folds it into ONE
/// sysmem segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRegion {
    pub va: u64,
    pub gpa: u64,
    pub len: u64,
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    /// User-accessible (ring 3) vs kernel-only.
    pub user: bool,
}

/// The ordered region list the bring-up hands every backend. The PML4
/// region-walk that produces it is shared; the slot-vs-segment *realization*
/// (`X86Vmm::setup_memory`) is the per-backend seam.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowPlan {
    pub regions: Vec<WindowRegion>,
}

impl WindowPlan {
    /// The minimum contiguous `[0, max_gpa)` size a single-segment backend
    /// (bhyve) needs to cover every planned region. Returns 0 for an empty plan.
    pub fn max_gpa_end(&self) -> u64 {
        self.regions
            .iter()
            .map(|r| r.gpa.saturating_add(r.len))
            .max()
            .unwrap_or(0)
    }
}

/// VM-level memory + lifecycle. One per guest process. See §2.1/§2.5 for the
/// honest semantic seams hiding behind `setup_memory`, `fork_ram_strategy`,
/// `freeze_ram`/`rebuild_child_vm`.
pub trait X86Vmm: Sized {
    type Vcpu: X86Vcpu;

    /// Consume the SHARED [`WindowPlan`]; the backend owns the slot-vs-segment
    /// decision (§2.5a).
    fn setup_memory(&mut self, plan: &WindowPlan) -> Result<(), TrapError>;

    /// Copy `bytes` into guest physical memory at `gpa`.
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError>;

    /// The host pointer backing `[gpa, gpa + len)`, or `None` if unmapped. The
    /// engine's `GuestMemory` impl copies through this.
    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8>;

    /// Create a fresh vCPU bound to this VM.
    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError>;

    /// POLICY: whether `fork(2)` can inherit RAM via COW or must eagerly copy
    /// the whole segment (§2.5b).
    fn fork_ram_strategy(&self) -> ForkRamStrategy;

    /// `EagerCopy` mechanism (no-op / unreachable for `Cow` backends): snapshot
    /// the full segment into a host buffer pre-fork. Returns the frozen RAM the
    /// child rebuilds.
    fn freeze_ram(&self) -> Result<Vec<u8>, TrapError> {
        Ok(Vec::new())
    }

    /// `EagerCopy` mechanism: create a fresh named child VM and restore `frozen`
    /// into it (bhyve); `Cow` backends never call this.
    fn rebuild_child_vm(&mut self, _frozen: &[u8]) -> Result<(), TrapError> {
        Ok(())
    }
}

/// Per-vCPU register/run surface. The ONLY thing genuinely per-VMM.
pub trait X86Vcpu {
    /// Read a GPR / control register (`Rax..R15`/`Rip`/`Rsp`/`Rflags`/
    /// `Cr0..4`/`Efer`/`Cr2`).
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError>;

    /// Write a GPR / control register.
    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError>;

    /// Program a segment/system descriptor (`base`/`limit`/access-rights).
    fn set_segment(&mut self, seg: X86Seg, base: u64, limit: u32, ar: u32)
    -> Result<(), TrapError>;

    /// The `SegmentBaseRegs` mechanism (arch_prctl FS/GS base): KVM/NVMM via the
    /// segment struct, bhyve via `vm_get/set_desc(FS/GS.base)`.
    fn get_fs_base(&self) -> Result<u64, TrapError>;
    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError>;
    fn get_gs_base(&self) -> Result<u64, TrapError>;
    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError>;

    /// Install the SYSCALL MSRs. Returns whether they took effect directly
    /// ([`MsrInstall::Direct`]) or the bring-up must run the ring-0 blob
    /// ([`MsrInstall::NeedsRing0Blob`], bhyve).
    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError>;

    /// `None` = "no FP getter, drive the ring-3 FXSAVE stub"
    /// ([`crate::bringup::run_fp_stub`]); `Some(fx)` = native 512-byte fxsave
    /// area (KVM `KVM_GET_FPU`, NVMM `STATE_FPU`).
    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError>;

    /// Apply a 512-byte fxsave area. `Ok(true)` = applied natively; `Ok(false)`
    /// = "no native FP setter, the caller must drive the ring-3 FXRSTOR stub".
    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError>;

    /// Run the vCPU until the next exit and decode it into [`X86Exit`]. The
    /// backend fills `resume_pc` at decode time; the ENGINE owns the
    /// pending-syscall state (§2.1).
    fn run(&mut self) -> Result<X86Exit, TrapError>;

    /// Enable the HALT exit capability (`KVM_CAP`/`vm_set_capability`); a no-op
    /// where halt already exits.
    fn enable_halt_exit(&mut self) -> Result<(), TrapError>;
}
