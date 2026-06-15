//! `X86EngineCore<V>` — the generic x86 trap engine (design §2.2).
//!
//! Implements the five `carrick-hal` engine traits ONCE over the thin
//! [`X86Vmm`]/[`X86Vcpu`] trait pair, replacing each per-VMM copy of the trap
//! loop, the register walk, the guest-memory access, the sigframe glue, and the
//! threaded lifecycle. A backend that implements the pair gets
//! `SyscallTrap + RegAccess + GuestMemory + SegmentBaseRegs + ThreadedEngine`
//! for free.
//!
//! ## The pending-syscall state lives HERE (§2.1)
//!
//! Collapsing each backend's `PendingInout {rip, inst_length}` into the single
//! `X86Exit::Syscall { resume_pc }` moves the "which doorbell is pending"
//! bookkeeping into the engine: `next_syscall` stashes `resume_pc`,
//! `complete_syscall` writes RAX and resumes at it. The backend's `run()` is
//! stateless w.r.t. the pending syscall.

use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::{SegmentBaseRegs, SyscallNorm, X8664GuestArch, service_arch_prctl};
use carrick_hal::{
    ForkOutcome, GuestEntryRegs, OsError, RawSyscall, Reg, SysReg, SyscallTrap, ThreadedEngine,
    TrapError,
};
use carrick_mem::memory::AddressSpace;

use crate::bringup_fns::{self, BringupLayout, X86VcpuSnapshot};
use crate::vmm::{X86Exit, X86FaultKind, X86Reg, X86Vcpu, X86Vmm};

/// fxsave-area byte offsets (Intel SDM vol. 1 §10.5.1 "FXSAVE Area"):
///   MXCSR at +24, XMM0 at +160 (16 bytes each).
const FXSAVE_MXCSR_OFF: usize = 24;
const FXSAVE_XMM0_OFF: usize = 160;
const X86_PFEC_PRESENT: u64 = 1 << 0;

fn x86_fault_signal(kind: X86FaultKind, error_code: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = libc::SIGSEGV;
    const SIGBUS: i32 = libc::SIGBUS;
    const SIGFPE: i32 = libc::SIGFPE;
    const SIGILL: i32 = libc::SIGILL;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const SI_KERNEL: i32 = 128;
    const BUS_ADRALN: i32 = 1;
    const FPE_INTDIV: i32 = 1;
    const ILL_ILLOPN: i32 = 2;
    match kind {
        X86FaultKind::PageFault => {
            let si_code = if error_code & X86_PFEC_PRESENT != 0 {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            };
            Some((SIGSEGV, si_code))
        }
        X86FaultKind::DivideError => Some((SIGFPE, FPE_INTDIV)),
        X86FaultKind::InvalidOpcode => Some((SIGILL, ILL_ILLOPN)),
        X86FaultKind::GeneralProtection => Some((SIGSEGV, SI_KERNEL)),
        X86FaultKind::AlignmentCheck => Some((SIGBUS, BUS_ADRALN)),
        X86FaultKind::Other => None,
    }
}

/// The generic x86 trap engine. Owns the VM, the (one) vCPU, the pending-syscall
/// resume PC, and the SA_RESTART syscall-number stash. Per-backend behaviour is
/// reached only through the [`X86Vmm`]/[`X86Vcpu`] trait pair.
pub struct X86EngineCore<V: X86Vmm> {
    vm: V,
    vcpu: V::Vcpu,
    /// The kernel-window GPA layout this engine was brought up with (trampoline /
    /// GDT / PML4). Carried so fork/clone re-seed and re-apply MSRs with the same
    /// LSTAR/CR3.
    layout: BringupLayout,
    /// The RIP to resume at after the pending syscall completes (the `SYSRETQ`
    /// after the LSTAR doorbell). `Some` between `next_syscall` and
    /// `complete_syscall`.
    pending_resume_pc: Option<u64>,
    /// RAX (the syscall NUMBER) captured at the trap, before `complete_syscall`
    /// overwrites RAX with the retval. SA_RESTART restores it so a restarted
    /// syscall re-executes with its number intact.
    last_orig_rax: u64,
    /// `true` on the child side of a guest `fork(2)`.
    is_forked_child: bool,
}

impl<V: X86Vmm> X86EngineCore<V> {
    /// Build an engine around an already-constructed VM + vCPU (the backend's
    /// bring-up produces these). `layout` is the GPA layout the bring-up used.
    pub fn from_parts(vm: V, vcpu: V::Vcpu, layout: BringupLayout) -> Self {
        Self {
            vm,
            vcpu,
            layout,
            pending_resume_pc: None,
            last_orig_rax: 0,
            is_forked_child: false,
        }
    }

    fn flush_current_tlb(&mut self) -> Result<(), MemoryError> {
        let cr3 = self
            .vcpu
            .get_gpr(X86Reg::Cr3)
            .map_err(|e| MemoryError::HostMap(format!("x86: read CR3 for TLB flush: {e}")))?;
        self.vcpu
            .set_gpr(X86Reg::Cr3, cr3)
            .map_err(|e| MemoryError::HostMap(format!("x86: reload CR3 for TLB flush: {e}")))
    }

    /// Immutable access to the underlying VM (sibling-spec construction, fork).
    pub fn vm(&self) -> &V {
        &self.vm
    }

    /// Mutable access to the underlying vCPU (rarely needed; the traits cover the
    /// hot paths).
    pub fn vcpu_mut(&mut self) -> &mut V::Vcpu {
        &mut self.vcpu
    }

    /// The resume RIP a freshly-built fork-child / clone-sibling vCPU starts at:
    /// the `SYSRETQ` immediately after the LSTAR `out` doorbell. (The trampoline
    /// is `out %al, $port` (2 bytes) + `sysretq`.)
    fn sysret_resume_rip(&self) -> u64 {
        self.layout.trampoline_base + 2
    }
}

// ─── SegmentBaseRegs (arch_prctl FS/GS base) ─────────────────────────────────

impl<V: X86Vmm> SegmentBaseRegs for X86EngineCore<V> {
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.vcpu.set_fs_base(addr)
    }
    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.vcpu.get_fs_base()
    }
    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.vcpu.set_gs_base(addr)
    }
    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        self.vcpu.get_gs_base()
    }
}

// ─── GuestMemory ─────────────────────────────────────────────────────────────

impl<V: X86Vmm> GuestMemory for X86EngineCore<V> {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let host = self
            .vm
            .host_ptr(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let mut out = vec![0u8; length];
        // SAFETY: `host_ptr` proved [host, host+length) is within a live window;
        // the destination slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), length) };
        Ok(out)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let host = self
            .vm
            .host_ptr(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        // SAFETY: `host_ptr` proved [host, host+length) is within a live window;
        // the source slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, length) };
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.vm.protect_range(address, len, prot)?;
        self.flush_current_tlb()
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.vm.unmap_range(address, len)?;
        self.flush_current_tlb()
    }

    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.vm.unmap_alias_range(address, len)?;
        self.flush_current_tlb()
    }
}

// ─── RegAccess ───────────────────────────────────────────────────────────────
//
// The Reg→X86Reg walk + FP/SIMD access served from the backend's fxsave area
// (`get_fp`/`set_fp`). KVM/NVMM have a native getter (`get_fp() == Some`); a
// no-FP-getter backend (bhyve) drives the ring-3 stub, after which `get_fp`
// returns the captured area, so this path is uniform.

fn reg_to_x86(r: Reg) -> Option<X86Reg> {
    Some(match r {
        Reg::Rax => X86Reg::Rax,
        Reg::Rbx => X86Reg::Rbx,
        Reg::Rcx => X86Reg::Rcx,
        Reg::Rdx => X86Reg::Rdx,
        Reg::Rsi => X86Reg::Rsi,
        Reg::Rdi => X86Reg::Rdi,
        Reg::Rbp => X86Reg::Rbp,
        Reg::Rsp => X86Reg::Rsp,
        Reg::R8 => X86Reg::R8,
        Reg::R9 => X86Reg::R9,
        Reg::R10 => X86Reg::R10,
        Reg::R11 => X86Reg::R11,
        Reg::R12 => X86Reg::R12,
        Reg::R13 => X86Reg::R13,
        Reg::R14 => X86Reg::R14,
        Reg::R15 => X86Reg::R15,
        Reg::Rip => X86Reg::Rip,
        Reg::Rflags => X86Reg::Rflags,
        _ => return None,
    })
}

impl<V: X86Vmm> carrick_hal::RegAccess for X86EngineCore<V> {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        let xr = reg_to_x86(r).ok_or_else(|| OsError::from_raw(libc::EINVAL))?;
        self.vcpu
            .get_gpr(xr)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        let xr = reg_to_x86(r).ok_or_else(|| OsError::from_raw(libc::EINVAL))?;
        self.vcpu
            .set_gpr(xr, v)
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        match r {
            SysReg::FsBase => self
                .vcpu
                .get_fs_base()
                .map_err(|_| OsError::from_raw(libc::EIO)),
            SysReg::GsBase => self
                .vcpu
                .get_gs_base()
                .map_err(|_| OsError::from_raw(libc::EIO)),
            _ => Err(OsError::from_raw(libc::EINVAL)),
        }
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        match r {
            SysReg::FsBase => self
                .vcpu
                .set_fs_base(v)
                .map_err(|_| OsError::from_raw(libc::EIO)),
            SysReg::GsBase => self
                .vcpu
                .set_gs_base(v)
                .map_err(|_| OsError::from_raw(libc::EIO)),
            _ => Err(OsError::from_raw(libc::EINVAL)),
        }
    }

    fn get_vreg(&self, n: u32) -> Result<u128, OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = FXSAVE_XMM0_OFF + (n as usize) * 16;
        let mut b = [0u8; 16];
        b.copy_from_slice(&fx[off..off + 16]);
        Ok(u128::from_le_bytes(b))
    }

    fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), OsError> {
        if n >= 16 {
            return Err(OsError::from_raw(libc::EINVAL));
        }
        let mut fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let off = FXSAVE_XMM0_OFF + (n as usize) * 16;
        fx[off..off + 16].copy_from_slice(&v.to_le_bytes());
        self.vcpu
            .set_fp(&fx)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpcr(&self) -> Result<u64, OsError> {
        // x86 has no FPCR; MXCSR is the nearest control word.
        let fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4]);
        Ok(u64::from(u32::from_le_bytes(b)))
    }

    fn set_fpcr(&mut self, v: u64) -> Result<(), OsError> {
        let mut fx = self
            .vcpu
            .get_fp()
            .map_err(|_| OsError::from_raw(libc::EIO))?
            .ok_or_else(|| OsError::from_raw(libc::EIO))?;
        fx[FXSAVE_MXCSR_OFF..FXSAVE_MXCSR_OFF + 4].copy_from_slice(&(v as u32).to_le_bytes());
        self.vcpu
            .set_fp(&fx)
            .map(|_| ())
            .map_err(|_| OsError::from_raw(libc::EIO))
    }

    fn get_fpsr(&self) -> Result<u64, OsError> {
        // No distinct x86 status word in this model (unused on the x86 sigframe path).
        Ok(0)
    }

    fn set_fpsr(&mut self, _v: u64) -> Result<(), OsError> {
        Ok(())
    }
}

// ─── SyscallTrap ─────────────────────────────────────────────────────────────

impl<V: X86Vmm> SyscallTrap for X86EngineCore<V> {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        loop {
            match self.vcpu.run()? {
                X86Exit::Syscall { frame, resume_pc } => {
                    // The engine — not the backend — owns the pending state.
                    self.pending_resume_pc = Some(resume_pc);
                    self.last_orig_rax = frame.rax;

                    match X8664GuestArch::normalize_syscall(&frame) {
                        SyscallNorm::ArchPrctl { code, addr } => {
                            let ret = service_arch_prctl(self, code, addr)?;
                            self.complete_syscall(ret)?;
                            continue;
                        }
                        SyscallNorm::Plain(raw) => return Ok(Some(raw)),
                    }
                }
                X86Exit::Halt => return Ok(None),
                // A cross-thread kick forced the vCPU out of the guest with no
                // syscall pending. Return `Ok(None)` so the run loop's kick path
                // delivers any pending async signal at the interrupted PC, then
                // re-enters (vcpu_loop.rs `Ok(None)` arm). Returning here (rather
                // than `continue`) is REQUIRED for async host→guest signal
                // delivery to a vCPU spinning in a syscall-free loop — a spurious
                // (un-requested) kick is harmless: the loop finds no pending
                // signal and resumes. (The backend already distinguishes a
                // requested kick from a spurious VT-x re-entry before surfacing
                // `Kicked`.)
                X86Exit::Kicked => return Ok(None),
                X86Exit::FpDoorbell => {
                    // The FP doorbell is only meaningful while `run_fp_stub` is
                    // driving the stub (it consumes the exit itself); reaching it
                    // here is a spurious re-entry — re-run the guest.
                    continue;
                }
                X86Exit::Fault {
                    kind,
                    fault_addr,
                    error_code,
                } => {
                    // Deliver as an ISA-neutral guest fault. For #PF, PFEC.P
                    // selects MAPERR vs ACCERR exactly like Linux; other x86
                    // vectors use the backend-resolved Linux si_addr.
                    let (signum, si_code) =
                        x86_fault_signal(kind, error_code).ok_or_else(|| {
                            TrapError::Hypervisor(format!("unsupported x86 fault kind {kind:?}"))
                        })?;
                    return Err(TrapError::GuestFault {
                        signum,
                        si_code,
                        fault_addr,
                    });
                }
            }
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu.get_gpr(X86Reg::Rip)
    }

    fn process_exit_cleanup(&mut self) {
        // Delegate to the backend (§2.5c): a HOOK, not Drop — the forked child
        // `_exit`s skipping Drops. Default is a no-op (KVM/NVMM RAM is released by
        // the OS on `_exit`); bhyve overrides it to tear down its `/dev/vmm` node
        // (and skip a vfork-shared/borrowed VM).
        self.vm.process_exit_cleanup();
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write RAX = return value and resume at the stashed SYSRETQ. For KVM the
        // resume_pc equals the RIP KVM already advanced to past the OUT, so the
        // RIP write is a no-op; for bhyve it is `rip + inst_length`. Either way
        // the engine owns the resume.
        self.vcpu.set_gpr(X86Reg::Rax, return_value as u64)?;
        if let Some(pc) = self.pending_resume_pc.take() {
            self.vcpu.set_gpr(X86Reg::Rip, pc)?;
        }
        Ok(())
    }

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        crate::engine::fork_x86(self)
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        // Delegate the image replacement to the backend (it rebuilds a fresh VM
        // from `new_image` and re-points the live vCPU). The default
        // `X86Vmm::execve_rebuild` is NYI (KVM/NVMM Phase-2 hello do not execve);
        // bhyve overrides it. Clear the pending-syscall state — the fresh image
        // resumes at its own entry, not the old doorbell resume.
        self.vm.execve_rebuild(&mut self.vcpu, new_image)?;
        self.pending_resume_pc = None;
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        self.vm.map_host_alias(va, ipa, len, payload, file)
    }

    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        use carrick_hal::RegAccess as _;
        // The interrupted RFLAGS, saved into the frame's eflags and restored
        // verbatim by rt_sigreturn (x86 has no privilege-latched SPSR analogue).
        let pstate_source = self
            .get_reg(Reg::Rflags)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source,
            // x86 reinterpretation: `orig_x0` carries the original RAX (the
            // syscall NUMBER) so SA_RESTART can restore it.
            orig_x0: self.last_orig_rax,
            // x86 has no ESR; the faulting address rides in sigcontext.cr2/si_addr.
            fault_esr: 0,
            fpsimd_enabled: true,
            // x86-64 MANDATES sa_restorer (no kernel vDSO sigreturn trampoline).
            sigreturn_trampoline_base: 0,
        };
        <Self as ThreadedEngine>::Arch::build_sigframe(self, params)?;
        Ok(())
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        let restored = <Self as ThreadedEngine>::Arch::restore_sigframe(self, true)?;
        Ok(restored.sigmask)
    }
}

/// Shared `fork(2)` sequencing (design §2.5b). Snapshots the parent vCPU, does the
/// host `libc::fork`, and on the child side rebuilds the guest per
/// `fork_ram_strategy`:
///   - `Cow` (KVM/NVMM): the child inherits RAM via COW; the backend's
///     `rebuild_child_after_fork` may still replace VMM objects whose fds are not
///     valid in the fork child (KVM), then the generic engine re-seeds the vCPU.
///   - `EagerCopy` (bhyve): freeze the segment, rebuild a fresh named child VM
///     from it (`freeze_ram` / `rebuild_child_vm`), then re-seed.
fn fork_x86<V: X86Vmm>(engine: &mut X86EngineCore<V>) -> Result<ForkOutcome, TrapError> {
    use crate::vmm::ForkRamStrategy;

    // Snapshot the parent vCPU BEFORE forking (suspended at the trap — atomic).
    let snap = bringup_fns::snapshot(&engine.vcpu)?;
    let strategy = engine.vm.fork_ram_strategy();

    // For EagerCopy backends, freeze the whole segment pre-fork (the parent does
    // this so the child can rebuild from a coherent image).
    let frozen = match strategy {
        ForkRamStrategy::EagerCopy => engine.vm.freeze_ram()?,
        ForkRamStrategy::Cow => Vec::new(),
    };

    // Real host fork. The run loop quiesces other threads around a guest fork;
    // the calling thread is the only active one here.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(TrapError::ForkFailed(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if pid > 0 {
        return Ok(ForkOutcome::Parent { child_pid: pid });
    }

    // CHILD.
    engine
        .vm
        .rebuild_child_after_fork(&mut engine.vcpu, &frozen)?;
    let layout = engine.layout;
    let child_snap =
        bringup_fns::seed_entry(&snap, GuestEntryRegs::default(), engine.sysret_resume_rip());
    engine
        .vm
        .restore_vcpu(&mut engine.vcpu, layout, &child_snap)?;
    // Runtime still completes the clone syscall once this returns. The child has
    // already been restored at the syscall-return point, so completion must only
    // write RAX=0 and must not reuse the parent's pending resume PC.
    engine.pending_resume_pc = None;
    engine.is_forked_child = true;
    Ok(ForkOutcome::Child)
}

// ─── ThreadedEngine ──────────────────────────────────────────────────────────

/// The `Send` payload `build_sibling_spec` hands to a freshly spawned host thread,
/// which `materialize_sibling` turns into a sibling engine. Backend-parameterized:
/// the backend supplies how to build a sibling VM/vCPU from this.
pub struct X86SiblingSpec<V: X86Vmm> {
    pub builder: V::SiblingBuilder,
    pub snapshot: X86VcpuSnapshot,
    pub layout: BringupLayout,
}

// SAFETY: the snapshot is POD and the layout is `Copy`; the builder is the
// backend's own `Send` payload (bounded `Send` on the trait).
unsafe impl<V: X86Vmm> Send for X86SiblingSpec<V> where V::SiblingBuilder: Send {}

impl<V: X86Vmm> ThreadedEngine for X86EngineCore<V> {
    type Arch = X8664GuestArch;
    type KickHandle = V::KickHandle;
    type SiblingSpec = X86SiblingSpec<V>;

    fn kick_handle(&self) -> Self::KickHandle {
        self.vm.kick_handle()
    }

    fn wait_for_vcpu_slot() {
        V::wait_for_vcpu_slot();
    }

    fn fork_vfork(&mut self) -> Result<ForkOutcome, TrapError> {
        crate::engine::fork_x86(self)
    }

    fn build_sibling_spec(&self, entry: GuestEntryRegs) -> Result<Self::SiblingSpec, TrapError> {
        let parent = bringup_fns::snapshot(&self.vcpu)?;
        let snapshot = bringup_fns::seed_entry(&parent, entry, self.sysret_resume_rip());
        let builder = self.vm.build_sibling_builder()?;
        Ok(X86SiblingSpec {
            builder,
            snapshot,
            layout: self.layout,
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError> {
        let (vm, mut vcpu) = V::materialize_sibling(spec.builder)?;
        vm.restore_vcpu(&mut vcpu, spec.layout, &spec.snapshot)?;
        Ok(Self::from_parts(vm, vcpu, spec.layout))
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.current_pc()
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        self.vm.set_guest_sp(&self.vcpu, sp)
    }

    fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
        // No in-guest gettid fast path on the x86 backends (no syscall shim);
        // the dispatcher services gettid. Mirrors the aarch64 no-shim path.
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> std::sync::Arc<dyn carrick_hal::VcpuRegistry> {
        self.vm.fresh_fork_kicker()
    }
}

/// `X86EngineCore` is `Send` when the backend pair is: the VM/vCPU hold the host
/// VMM fds (Send) and raw window pointers valid in every thread.
//
// SAFETY: `V`/`V::Vcpu` carry only host VMM fds + raw window pointers that are
// valid in every thread of the process (threads share the address space). The
// engine is moved to its owning sibling/vCPU thread before use.
unsafe impl<V: X86Vmm> Send for X86EngineCore<V> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_page_fault_present_bit_selects_accerr() {
        assert_eq!(
            x86_fault_signal(X86FaultKind::PageFault, 0),
            Some((libc::SIGSEGV, 1)),
            "non-present #PF is SEGV_MAPERR"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::PageFault, X86_PFEC_PRESENT),
            Some((libc::SIGSEGV, 2)),
            "present-page protection #PF is SEGV_ACCERR"
        );
    }

    #[test]
    fn x86_non_page_fault_vectors_match_linux_oracle() {
        assert_eq!(
            x86_fault_signal(X86FaultKind::InvalidOpcode, 0),
            Some((libc::SIGILL, 2)),
            "UD2 is SIGILL/ILL_ILLOPN on Docker linux/amd64"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::DivideError, 0),
            Some((libc::SIGFPE, 1)),
            "integer divide error is SIGFPE/FPE_INTDIV on Docker linux/amd64"
        );
        assert_eq!(
            x86_fault_signal(X86FaultKind::GeneralProtection, 0),
            Some((libc::SIGSEGV, 128)),
            "user CLI #GP is SIGSEGV/SI_KERNEL on Docker linux/amd64"
        );
    }
}
