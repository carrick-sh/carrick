//! Stopped-CPU programming for the soft carrier.
//!
//! [`SoftBootVcpu`] is the soft realization of the shared [`X86Vcpu`] setter
//! surface, so the neutral [`BootCpuState::program_entry`] programs a
//! [`SoftCpuContext`] exactly as it programs a KVM vCPU. The remaining
//! direct-map aliases, CR4 requirements, LAPIC and syscall MSRs follow the
//! KVM carrier's order in `Cpl0Carrier::boot_bytes_inner`.

use carrick_hal::TrapError;
use carrick_softcpu_x86::{
    CpuidAuthority, DescriptorTablePtr, LAPIC_SVR_OFFSET, MSR_IA32_APIC_BASE, MSR_IA32_FMASK,
    MSR_IA32_LSTAR, MSR_IA32_STAR, MsrCapabilities, MsrIndex, SoftCpuContext, SoftSegment, reg,
};
use carrick_x86::{MsrInstall, SegmentDescriptor, X86Exit, X86Reg, X86Seg, X86Vcpu};
use carrick_x86_cpl0_host::cpl0_boot::{BootCpuState, fail};

/// The shared `X86Vcpu` setter surface over a stopped soft CPU context.
pub struct SoftBootVcpu<'a> {
    ctx: &'a mut SoftCpuContext,
    caps: MsrCapabilities,
}

impl<'a> SoftBootVcpu<'a> {
    pub fn new(ctx: &'a mut SoftCpuContext, cpuid: &dyn CpuidAuthority) -> Self {
        Self {
            ctx,
            caps: MsrCapabilities::from_cpuid(cpuid),
        }
    }

    fn write_msr(&mut self, index: MsrIndex, value: u64) -> Result<(), TrapError> {
        self.ctx
            .write_msr(index, value, self.caps)
            .map(|_| ())
            .map_err(|_| fail(format!("soft MSR {:#x} refused {value:#x}", index.raw())))
    }
}

const fn gpr_index(reg: X86Reg) -> Option<usize> {
    Some(match reg {
        X86Reg::Rax => reg::RAX,
        X86Reg::Rcx => reg::RCX,
        X86Reg::Rdx => reg::RDX,
        X86Reg::Rbx => reg::RBX,
        X86Reg::Rsp => reg::RSP,
        X86Reg::Rbp => reg::RBP,
        X86Reg::Rsi => reg::RSI,
        X86Reg::Rdi => reg::RDI,
        X86Reg::R8 => reg::R8,
        X86Reg::R9 => reg::R9,
        X86Reg::R10 => reg::R10,
        X86Reg::R11 => reg::R11,
        X86Reg::R12 => reg::R12,
        X86Reg::R13 => reg::R13,
        X86Reg::R14 => reg::R14,
        X86Reg::R15 => reg::R15,
        _ => return None,
    })
}

const fn soft_segment(descriptor: SegmentDescriptor) -> SoftSegment {
    SoftSegment {
        selector: descriptor.selector(),
        base: descriptor.base(),
        limit: descriptor.limit(),
        ar: descriptor.access_rights(),
    }
}

impl X86Vcpu for SoftBootVcpu<'_> {
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        Ok(match reg {
            X86Reg::Rip => self.ctx.rip,
            X86Reg::Rflags => self.ctx.rflags,
            X86Reg::Cr0 => self.ctx.cr0,
            X86Reg::Cr2 => self.ctx.cr2,
            X86Reg::Cr3 => self.ctx.cr3,
            X86Reg::Cr4 => self.ctx.cr4,
            X86Reg::Efer => self.ctx.efer(),
            gpr => self.ctx.gpr[gpr_index(gpr).ok_or_else(|| fail("soft register"))?],
        })
    }

    fn set_gpr(&mut self, reg: X86Reg, value: u64) -> Result<(), TrapError> {
        match reg {
            X86Reg::Rip => self.ctx.rip = value,
            X86Reg::Rflags => self.ctx.rflags = value,
            X86Reg::Cr0 => self.ctx.cr0 = value,
            X86Reg::Cr2 => self.ctx.cr2 = value,
            X86Reg::Cr3 => self.ctx.cr3 = value,
            X86Reg::Cr4 => self.ctx.cr4 = value,
            X86Reg::Efer => self.write_msr(carrick_softcpu_x86::MSR_IA32_EFER, value)?,
            gpr => self.ctx.gpr[gpr_index(gpr).ok_or_else(|| fail("soft register"))?] = value,
        }
        if matches!(reg, X86Reg::Cr0 | X86Reg::Cr3 | X86Reg::Cr4) {
            self.ctx.flush_tlb();
            self.ctx.sync_tlb_tag_bits();
        }
        Ok(())
    }

    fn set_segment(&mut self, seg: X86Seg, descriptor: SegmentDescriptor) -> Result<(), TrapError> {
        let segment = soft_segment(descriptor);
        match seg {
            X86Seg::Cs => {
                self.ctx.cs = segment;
                self.ctx.set_cpl(segment.dpl());
            }
            X86Seg::Ss => self.ctx.ss = segment,
            X86Seg::Ds => self.ctx.ds = segment,
            X86Seg::Es => self.ctx.es = segment,
            X86Seg::Fs => {
                self.ctx.fs = SoftSegment {
                    base: self.ctx.fs_base(),
                    ..segment
                }
            }
            X86Seg::Gs => {
                self.ctx.gs = SoftSegment {
                    base: self.ctx.gs_base(),
                    ..segment
                }
            }
            X86Seg::Tr => self.ctx.tr = segment,
            X86Seg::Ldtr => self.ctx.ldtr = segment,
            X86Seg::Gdtr | X86Seg::Idtr => {
                let limit = u16::try_from(descriptor.limit())
                    .map_err(|_| fail("descriptor table limit width"))?;
                let table = DescriptorTablePtr::new(limit, descriptor.base());
                if seg == X86Seg::Gdtr {
                    self.ctx.gdtr = table;
                } else {
                    self.ctx.idtr = table;
                }
            }
        }
        Ok(())
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        Ok(self.ctx.fs_base())
    }
    fn set_fs_base(&mut self, value: u64) -> Result<(), TrapError> {
        self.ctx
            .set_fs_base(value)
            .map_err(|_| fail("soft FS base refused"))
    }
    fn get_gs_base(&self) -> Result<u64, TrapError> {
        Ok(self.ctx.gs_base())
    }
    fn set_gs_base(&mut self, value: u64) -> Result<(), TrapError> {
        self.ctx
            .set_gs_base(value)
            .map_err(|_| fail("soft GS base refused"))
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        self.write_msr(MSR_IA32_LSTAR, lstar)?;
        self.write_msr(MSR_IA32_STAR, star)?;
        self.write_msr(MSR_IA32_FMASK, sfmask)?;
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        Ok(None)
    }
    fn set_fp(&mut self, _fx: &[u8; 512]) -> Result<bool, TrapError> {
        Ok(false)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        Err(fail(
            "SoftBootVcpu programs stopped state; SoftMachine runs it",
        ))
    }
    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        Ok(())
    }
}

/// Install `state` on a stopped soft CPU in the KVM carrier's order:
/// shared long-mode entry, production CR4/CPUID requirements, direct-map
/// GDTR/IDTR/TR aliases, xAPIC base, syscall MSRs, `KERNEL_GS_BASE`, and
/// (with hardware interrupts) a software-enabled LAPIC.
pub fn apply_boot_cpu_state(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn CpuidAuthority,
    state: &BootCpuState,
    hardware_interrupts: bool,
    production: bool,
) -> Result<(), TrapError> {
    let mut vcpu = SoftBootVcpu::new(ctx, cpuid);
    state.program_entry(&mut vcpu)?;
    if production {
        let features = cpuid.cpuid(7, 0).ebx;
        if features & state.cpuid_leaf7_required != state.cpuid_leaf7_required {
            return Err(fail("production CPL0 requires CPUID SMEP and SMAP"));
        }
        vcpu.set_gpr(X86Reg::Cr4, vcpu.ctx.cr4 | state.cr4_required)?;
    }
    let gdt_limit = vcpu.ctx.gdtr.limit;
    vcpu.ctx.gdtr = DescriptorTablePtr::new(gdt_limit, state.gdt_base);
    let idt_limit = vcpu.ctx.idtr.limit;
    vcpu.ctx.idtr = DescriptorTablePtr::new(idt_limit, state.idt_base);
    vcpu.set_segment(X86Seg::Tr, state.tr)?;
    if let Some(apic_base) = state.apic_base {
        vcpu.write_msr(MSR_IA32_APIC_BASE, apic_base)?;
    }
    vcpu.set_syscall_msrs(state.lstar, state.star, state.sfmask)?;
    vcpu.ctx
        .set_kernel_gs_base(state.kernel_gs_base)
        .map_err(|_| fail("KERNEL_GS_BASE not installed"))?;
    if hardware_interrupts {
        let svr = 0x100_u32 | u32::from(carrick_x86::interrupts::SPURIOUS_VECTOR);
        vcpu.ctx
            .lapic_mmio_write(LAPIC_SVR_OFFSET, &svr.to_le_bytes());
    }
    Ok(())
}
