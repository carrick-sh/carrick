//! The KVM x86_64 backend on the shared `carrick-x86` scaffold (portability S4).
//!
//! `KvmVmm` (+ `impl X86Vcpu for KvmVcpu`) is the thin per-VMM trait pair the
//! generic [`carrick_x86::X86EngineCore`] is parameterized over. It replaces the
//! hand-rolled `KvmX86TrapEngine`: the trap loop, register walk, guest-memory
//! access, snapshot triple, long-mode bring-up, and run-elf loop all now live
//! ONCE in `carrick-x86`; this module supplies only the KVM-specific
//! marshalling.
//!
//! KVM answers the three quirk seams `Direct` / `Some` / `Cow`:
//!   - `set_syscall_msrs` → `MsrInstall::Direct` (`KVM_SET_MSRS`).
//!   - `get_fp` → `Some` (`KVM_GET_FPU` 512-byte fxsave area, native).
//!   - `fork_ram_strategy` → `Cow` (`MAP_PRIVATE` — KVM never freezes RAM).
//!
//! ## Whole-`kvm_sregs` read-modify-write
//!
//! KVM has no per-register x86 ioctl: control regs + EFER + every segment
//! descriptor live in one `kvm_sregs`, GPRs/RIP/RFLAGS in one `kvm_regs`, FP in
//! one `kvm_fpu`. Each `X86Vcpu` setter therefore reads the whole struct,
//! mutates the one field, and writes it back. The "all control regs + 64-bit CS
//! in one `KVM_SET_SREGS`" validation invariant (paging-on-without-64-bit-CS →
//! EINVAL) is preserved because the snapshot/restore path writes the full
//! `kvm_sregs` it captured; the per-field setters used during bring-up touch
//! only off-hot-path regs after long mode is already established.
//!
//! ## KERNEL_GS_BASE
//!
//! `gs.base` is the active GS base (what `arch_prctl(ARCH_SET_GS)` programs and
//! the sigframe carries). `KERNEL_GS_BASE` (the SWAPGS shadow) is not used by
//! the ring-3-only guest, so `get/set_gs_base` operate on `sregs.gs.base`.

use std::sync::Arc;

use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;
use carrick_x86::{
    BringupLayout, ForkRamStrategy, MsrInstall, WindowPlan, X86EngineCore, X86Exit, X86Reg, X86Seg,
    X86Vcpu, X86Vmm,
};
use kvm_bindings::{Msrs, kvm_dtable, kvm_msr_entry, kvm_segment};

use crate::guest_setup::{GuestRam, WindowDesc};
use crate::guest_setup_x86::{X86_GDT_BASE, X86_PML4_BASE, X86_TRAMPOLINE_BASE};
use crate::kvm::{KvmVcpu, KvmVm, SharedVmHandle, VcpuLiveTicket};
use crate::kvm_kicker::{KvmKickHandle, KvmKicker};

/// The KVM x86 kernel-window GPA layout (the §2.5a/`BringupLayout` per-backend
/// choice). KVM places the trampoline/GDT/PML4 in a low 256 MiB window so CR3
/// stays below the host's 36-bit physical-address ceiling.
pub const KVM_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: X86_TRAMPOLINE_BASE,
    gdt_base: X86_GDT_BASE,
    pml4_base: X86_PML4_BASE,
};

// ─── KvmVmm ──────────────────────────────────────────────────────────────────

/// The KVM `X86Vmm`: a `KvmVm` plus the `GuestRam` window table backing it. One
/// per guest process. The generic engine drives memory through `host_ptr`,
/// lifecycle through `add_vcpu` / the sibling hooks.
pub struct KvmVmm {
    vm: KvmVm,
    ram: GuestRam,
}

impl KvmVmm {
    /// Build a sibling `KvmVmm` over the shared VM handle + window descriptors (a
    /// `clone(CLONE_THREAD)` sibling shares every slot — no re-registration).
    fn from_sibling(
        handle: SharedVmHandle,
        windows: &[WindowDesc],
        protections: Arc<carrick_mem::protections::MemoryProtections>,
    ) -> Self {
        let vm = KvmVm::from_shared_vm(handle);
        let ram = GuestRam::from_shared_windows(windows, protections);
        Self { vm, ram }
    }
}

/// The `Send` payload a sibling thread materializes into a fresh vCPU on the SAME
/// VM. Mirrors the old `X8664SiblingSpec` minus the snapshot (the engine carries
/// the seeded snapshot in `X86SiblingSpec`).
pub struct KvmSiblingBuilder {
    vm: SharedVmHandle,
    windows: Vec<WindowDesc>,
    protections: Arc<carrick_mem::protections::MemoryProtections>,
    ticket: VcpuLiveTicket,
}

impl X86Vmm for KvmVmm {
    type Vcpu = KvmVcpu;
    type KickHandle = KvmKickHandle;
    type SiblingBuilder = KvmSiblingBuilder;

    fn setup_memory(&mut self, _plan: &WindowPlan) -> Result<(), TrapError> {
        // KVM realizes the plan as N MAP_NORESERVE slots; that registration is
        // done by `bring_up` (it builds the `GuestRam` window table + registers
        // every window as a KVM slot, capped 64 MiB each — §2.5a KVM column).
        // This hook is a no-op for KVM because `bring_up` constructs an already-
        // memory-mapped `KvmVmm`; it exists for backends that defer memory setup.
        Ok(())
    }

    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        // GuestRam::write_gpa takes &mut self; the bring-up holds &mut, but the
        // trait is &self. The window host pointers are stable, so copy directly
        // through host_ptr.
        let host = self.ram.host_ptr(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("kvm-x86: write_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: host_ptr proved [host, host+len) is within a live window.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        self.ram.host_ptr(gpa, len)
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        use carrick_hal::HvVm as _;
        self.vm
            .add_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // KVM: MAP_PRIVATE windows inherit via COW; nothing is frozen/copied.
        ForkRamStrategy::Cow
    }

    fn kick_handle(&self) -> Self::KickHandle {
        KvmKickHandle::for_current_thread()
    }

    fn wait_for_vcpu_slot() {
        // KVM has no Apple-HVF concurrent-vCPU admission cap.
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        Ok(KvmSiblingBuilder {
            vm: self.vm.vm_handle(),
            windows: self.ram.window_descriptors(),
            protections: self.ram.shared_protections(),
            // Reserve the sibling's VCPU_LIVE slot now (closes the execve-drain
            // blind window); consumed at materialization.
            ticket: VcpuLiveTicket::acquire(),
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let vmm = Self::from_sibling(builder.vm, &builder.windows, builder.protections);
        let vcpu = vmm
            .vm
            .add_sibling_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Transfer the reserved VCPU_LIVE slot to the vcpu before the (fallible)
        // restore the engine runs next.
        builder.ticket.consume();
        Ok((vmm, vcpu))
    }

    fn set_guest_sp(&self, vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        // &self read-modify-write of RSP (KVM_SET_REGS is &self on VcpuFd).
        let mut regs = vcpu
            .fd()
            .get_regs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(set_rsp): {e}")))?;
        regs.rsp = sp;
        vcpu.fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(rsp): {e}")))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(KvmKicker::new())
    }
}

// ─── impl X86Vcpu for KvmVcpu ────────────────────────────────────────────────

/// Map an `X86Seg` to the KVM bring-up selector (KVM uses the hidden `kvm_segment`
/// directly and does not re-load from the GDT, but a consistent selector keeps
/// the descriptor self-describing). CS=0x23, SS/DS/ES=0x1B, others 0.
fn seg_selector(seg: X86Seg) -> u16 {
    match seg {
        X86Seg::Cs => 0x23,
        X86Seg::Ss | X86Seg::Ds | X86Seg::Es => 0x1B,
        _ => 0,
    }
}

/// Unpack a packed long-mode access-rights word (see `carrick_x86`'s `seg_ar`)
/// into the `kvm_segment` bit-fields.
fn ar_to_kvm_segment(base: u64, limit: u32, ar: u32, selector: u16) -> kvm_segment {
    kvm_segment {
        base,
        limit,
        selector,
        type_: (ar & 0xF) as u8,
        s: ((ar >> 4) & 1) as u8,
        dpl: ((ar >> 5) & 3) as u8,
        present: ((ar >> 7) & 1) as u8,
        avl: ((ar >> 12) & 1) as u8,
        l: ((ar >> 13) & 1) as u8,
        db: ((ar >> 14) & 1) as u8,
        g: ((ar >> 15) & 1) as u8,
        unusable: ((ar >> 16) & 1) as u8,
        ..Default::default()
    }
}

impl X86Vcpu for KvmVcpu {
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        // GPRs/RIP/RSP/RFLAGS via KVM_GET_REGS; control regs/EFER via KVM_GET_SREGS.
        Ok(match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                let s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0,
                    X86Reg::Cr2 => s.cr2,
                    X86Reg::Cr3 => s.cr3,
                    X86Reg::Cr4 => s.cr4,
                    X86Reg::Efer => s.efer,
                    _ => unreachable!(),
                }
            }
            _ => {
                let r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax,
                    X86Reg::Rbx => r.rbx,
                    X86Reg::Rcx => r.rcx,
                    X86Reg::Rdx => r.rdx,
                    X86Reg::Rsi => r.rsi,
                    X86Reg::Rdi => r.rdi,
                    X86Reg::Rbp => r.rbp,
                    X86Reg::Rsp => r.rsp,
                    X86Reg::R8 => r.r8,
                    X86Reg::R9 => r.r9,
                    X86Reg::R10 => r.r10,
                    X86Reg::R11 => r.r11,
                    X86Reg::R12 => r.r12,
                    X86Reg::R13 => r.r13,
                    X86Reg::R14 => r.r14,
                    X86Reg::R15 => r.r15,
                    X86Reg::Rip => r.rip,
                    X86Reg::Rflags => r.rflags,
                    _ => unreachable!(),
                }
            }
        })
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                let mut s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0 = v,
                    X86Reg::Cr2 => s.cr2 = v,
                    X86Reg::Cr3 => s.cr3 = v,
                    X86Reg::Cr4 => s.cr4 = v,
                    X86Reg::Efer => s.efer = v,
                    _ => unreachable!(),
                }
                self.fd()
                    .set_sregs(&s)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS: {e}")))
            }
            _ => {
                let mut r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax = v,
                    X86Reg::Rbx => r.rbx = v,
                    X86Reg::Rcx => r.rcx = v,
                    X86Reg::Rdx => r.rdx = v,
                    X86Reg::Rsi => r.rsi = v,
                    X86Reg::Rdi => r.rdi = v,
                    X86Reg::Rbp => r.rbp = v,
                    X86Reg::Rsp => r.rsp = v,
                    X86Reg::R8 => r.r8 = v,
                    X86Reg::R9 => r.r9 = v,
                    X86Reg::R10 => r.r10 = v,
                    X86Reg::R11 => r.r11 = v,
                    X86Reg::R12 => r.r12 = v,
                    X86Reg::R13 => r.r13 = v,
                    X86Reg::R14 => r.r14 = v,
                    X86Reg::R15 => r.r15 = v,
                    X86Reg::Rip => r.rip = v,
                    X86Reg::Rflags => r.rflags = v,
                    _ => unreachable!(),
                }
                self.fd()
                    .set_regs(&r)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS: {e}")))
            }
        }
    }

    fn set_segment(
        &mut self,
        seg: X86Seg,
        base: u64,
        limit: u32,
        ar: u32,
    ) -> Result<(), TrapError> {
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(seg): {e}")))?;
        match seg {
            X86Seg::Gdtr => {
                s.gdt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            X86Seg::Idtr => {
                s.idt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            _ => {
                let kseg = ar_to_kvm_segment(base, limit, ar, seg_selector(seg));
                match seg {
                    X86Seg::Cs => s.cs = kseg,
                    X86Seg::Ds => s.ds = kseg,
                    X86Seg::Es => s.es = kseg,
                    X86Seg::Fs => s.fs = kseg,
                    X86Seg::Gs => s.gs = kseg,
                    X86Seg::Ss => s.ss = kseg,
                    X86Seg::Tr => s.tr = kseg,
                    X86Seg::Ldtr => s.ldt = kseg,
                    X86Seg::Gdtr | X86Seg::Idtr => unreachable!(),
                }
            }
        }
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(seg): {e}")))
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        Ok(s.fs.base)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        s.fs.base = v;
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(fs.base): {e}")))
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        Ok(s.gs.base)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        s.gs.base = v;
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(gs.base): {e}")))
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // KVM exposes the SYSCALL MSRs directly via KVM_SET_MSRS — Direct.
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0xc000_0081,
                data: star,
                ..Default::default()
            }, // STAR
            kvm_msr_entry {
                index: 0xc000_0082,
                data: lstar,
                ..Default::default()
            }, // LSTAR
            kvm_msr_entry {
                index: 0xc000_0084,
                data: sfmask,
                ..Default::default()
            }, // SFMASK
        ])
        .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: Msrs::from_entries: {e}")))?;
        let n = self
            .fd()
            .set_msrs(&msrs)
            .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: KVM_SET_MSRS: {e}")))?;
        if n != 3 {
            return Err(TrapError::Hypervisor(format!(
                "kvm-x86: KVM_SET_MSRS wrote {n}/3 (partial)"
            )));
        }
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // KVM_GET_FPU yields the native 512-byte fxsave area. The `kvm_fpu`
        // struct's first 512 bytes ARE the legacy fxsave region (fpr/xmm/mxcsr/
        // control words at the architectural offsets), so we serialize it.
        let fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU: {e}")))?;
        Ok(Some(kvm_fpu_to_fxsave(&fpu)))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        let mut fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU(set): {e}")))?;
        fxsave_into_kvm_fpu(fx, &mut fpu);
        self.fd()
            .set_fpu(&fpu)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_FPU: {e}")))?;
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        use carrick_hal::{HvVcpu, VcpuExit};

        match <Self as HvVcpu>::run(self).map_err(|e| TrapError::Hypervisor(e.to_string()))? {
            // SYSCALL doorbell: OUT 0xC5 → KVM_EXIT_IO. KVM already advanced RIP
            // past the OUT, so resume_pc = current RIP (the SYSRETQ).
            VcpuExit::IoOut { port, .. } if port == carrick_hal::SYSCALL_DOORBELL_PORT => {
                let regs = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(doorbell): {e}")))?;
                let frame = carrick_guest_mem::X8664SyscallFrame {
                    rax: regs.rax,
                    rdi: regs.rdi,
                    rsi: regs.rsi,
                    rdx: regs.rdx,
                    r10: regs.r10,
                    r8: regs.r8,
                    r9: regs.r9,
                };
                Ok(X86Exit::Syscall {
                    frame,
                    resume_pc: regs.rip,
                })
            }
            VcpuExit::IoOut { port, .. } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected OUT to port 0x{port:04X}"
            ))),
            VcpuExit::Halt => Ok(X86Exit::Halt),
            VcpuExit::Kicked => Ok(X86Exit::Kicked),
            VcpuExit::MmioWrite { gpa, .. } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected MMIO write to gpa=0x{gpa:x} (ring-3 fault / PML4 gap)"
            ))),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected Exception syndrome=0x{syndrome:x} far=0x{far:x}"
            ))),
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        // KVM exits on HLT by default (KVM_EXIT_HLT); no capability to enable.
        Ok(())
    }
}

/// Serialize a `kvm_fpu` into the 512-byte legacy fxsave layout (Intel SDM
/// vol. 1 §10.5.1): control words +0, st_space (x87) +32, xmm_space +160,
/// mxcsr +24.
fn kvm_fpu_to_fxsave(fpu: &kvm_bindings::kvm_fpu) -> [u8; 512] {
    let mut fx = [0u8; 512];
    fx[0] = (fpu.fcw & 0xFF) as u8;
    fx[1] = (fpu.fcw >> 8) as u8;
    fx[2] = (fpu.fsw & 0xFF) as u8;
    fx[3] = (fpu.fsw >> 8) as u8;
    fx[4] = fpu.ftwx;
    fx[5] = 0; // reserved
    fx[6] = (fpu.last_opcode & 0xFF) as u8;
    fx[7] = (fpu.last_opcode >> 8) as u8;
    fx[8..16].copy_from_slice(&fpu.last_ip.to_le_bytes());
    fx[16..24].copy_from_slice(&fpu.last_dp.to_le_bytes());
    fx[24..28].copy_from_slice(&fpu.mxcsr.to_le_bytes());
    // st_space: 8 × 16 bytes at +32 (KVM stores [u32; 32] = 128 bytes).
    for (i, w) in fpu.fpr.iter().enumerate() {
        let off = 32 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    // xmm_space: 16 × 16 bytes at +160.
    for (i, w) in fpu.xmm.iter().enumerate() {
        let off = 160 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    fx
}

/// Inverse of [`kvm_fpu_to_fxsave`]: load a 512-byte fxsave image into `fpu`.
fn fxsave_into_kvm_fpu(fx: &[u8; 512], fpu: &mut kvm_bindings::kvm_fpu) {
    fpu.fcw = u16::from_le_bytes([fx[0], fx[1]]);
    fpu.fsw = u16::from_le_bytes([fx[2], fx[3]]);
    fpu.ftwx = fx[4];
    fpu.last_opcode = u16::from_le_bytes([fx[6], fx[7]]);
    fpu.last_ip = u64::from_le_bytes(fx[8..16].try_into().unwrap_or_default());
    fpu.last_dp = u64::from_le_bytes(fx[16..24].try_into().unwrap_or_default());
    fpu.mxcsr = u32::from_le_bytes(fx[24..28].try_into().unwrap_or_default());
    for (i, w) in fpu.fpr.iter_mut().enumerate() {
        let off = 32 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
    for (i, w) in fpu.xmm.iter_mut().enumerate() {
        let off = 160 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
}

// ─── bring_up ────────────────────────────────────────────────────────────────

/// Bring up a KVM x86 guest for `image` and wrap it in the generic
/// [`X86EngineCore`]. Builds the `GuestRam` window table (N MAP_NORESERVE slots),
/// writes the trampoline/GDT/PML4 images, creates the vCPU, and programs long
/// mode via the shared [`carrick_x86::program_longmode_entry`].
pub fn bring_up(image: &AddressSpace) -> Result<X86EngineCore<KvmVmm>, TrapError> {
    use carrick_hal::HvVm as _;

    // 1. Lay out guest RAM (identity GPA = VA; N capped MAP_NORESERVE windows).
    let mut ram =
        GuestRam::build_for_image_x86(image).map_err(|e| TrapError::Hypervisor(e.to_string()))?;

    // 2. Create the VM + register every window as a KVM slot.
    let mut vm = KvmVm::create_empty().map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    for (gpa, host, len) in ram.windows_for_kvm() {
        vm.map_memory(gpa, host, len, carrick_hal::MemPerms::ReadWriteExec)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    }

    // 3. Write the bring-up byte images (trampoline + GDT + PML4) into RAM.
    //    The plan/PML4 are built via the shared region-walk.
    let plan = carrick_x86::plan_windows(image, KVM_X86_LAYOUT)?;
    let pml4_bytes = carrick_x86::build_pml4(&plan, KVM_X86_LAYOUT)?;
    write_bringup_images_via_ram(&mut ram, &pml4_bytes)?;

    // 4. Create the vCPU and program long mode (CR/EFER/segs/GDTR/MSRs).
    let vcpu = vm
        .add_vcpu()
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);
    let mut vcpu = vcpu;
    let _install =
        carrick_x86::program_longmode_entry(&mut vcpu, KVM_X86_LAYOUT, image.entry(), rsp)?;
    // KVM is MsrInstall::Direct — the SYSCALL MSRs are already live; no ring-0 blob.

    let vmm = KvmVmm { vm, ram };
    Ok(X86EngineCore::from_parts(vmm, vcpu, KVM_X86_LAYOUT))
}

/// Write the trampoline/GDT/PML4 byte images into `ram` directly (the bring-up
/// holds `&mut GuestRam`, so it uses `GuestRam::write_gpa` rather than the
/// `&self` `X86Vmm::write_gpa` hook).
fn write_bringup_images_via_ram(ram: &mut GuestRam, pml4_bytes: &[u8]) -> Result<(), TrapError> {
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    ram.write_gpa(
        X86_TRAMPOLINE_BASE,
        &X8664GuestArch::entry_trampoline_bytes(),
    )
    .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    let boot = X8664GuestArch::bootstrap_sysregs();
    let gdt_bytes: Vec<u8> = boot.gdt.iter().flat_map(|e| e.to_le_bytes()).collect();
    ram.write_gpa(X86_GDT_BASE, &gdt_bytes)
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    ram.write_gpa(X86_PML4_BASE, pml4_bytes)
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    Ok(())
}
