//! SDM-accurate CPL0 privileged and system-instruction emulation for `carrick-softcpu-x86`.
//!
//! Covers:
//! - `MOV CR0/CR2/CR3/CR4/CR8` and `MOV DR0..DR7`
//! - `RDMSR` / `WRMSR` over [`crate::msr::MsrFile`]
//! - `LGDT`, `LIDT`, `LTR` and unprivileged/UMIP queries `SGDT`, `SIDT`, `SLDT`, `STR`, `SMSW`
//! - `SWAPGS`, `SYSRET` / `SYSRETQ`, `IRET` / `IRETD` / `IRETQ`
//! - `HLT`, `INVLPG`, `CLI`, `STI`, `CLAC`, `STAC`, `XSETBV`, `XGETBV`
//! - `CPUID` routed through [`crate::cpuid::GuestCpuidView`]

use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::cflow::compute_effective_va;
use crate::context::{DescriptorTablePtr, SoftCpuContext, SoftSegment, X86Exception, reg};
use crate::cpuid::GuestCpuidView;
use crate::decode::{SensitiveOp, gpr_index};
use crate::mmu::{
    SoftAccessKind, SoftMmuMemory, check_guest_alignment, check_system_write, is_canonical_va,
    read_guest_bytes, read_system_bytes, write_guest_bytes, write_system_bytes,
};
use crate::msr::{EFER_LMA, EFER_LME, EFER_SCE, MsrCapabilities, MsrIndex};

const CR0_PE: u64 = 1 << 0;
const CR0_ET: u64 = 1 << 4;
const CR0_WP: u64 = 1 << 16;
const CR0_NW: u64 = 1 << 29;
const CR0_CD: u64 = 1 << 30;
const CR0_PG: u64 = 1 << 31;
// SDM Vol. 3A §2.5: bits [15:6], [17], and [28:19] in CR0[31:0] are reserved zero.
const CR0_WRITABLE_MASK: u64 = 0xe005_003f;

const CR4_VME: u64 = 1 << 0;
const CR4_PVI: u64 = 1 << 1;
const CR4_TSD: u64 = 1 << 2;
const CR4_DE: u64 = 1 << 3;
const CR4_PAE: u64 = 1 << 5;
const CR4_PGE: u64 = 1 << 7;
const CR4_UMIP: u64 = 1 << 11;
const CR4_LA57: u64 = 1 << 12;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_PCIDE: u64 = 1 << 17;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const CR4_UNSUPPORTED_MASK: u64 = (0x7 << 13) | (1 << 19) | (0x3ff << 22) | 0xffff_ffff_0000_0000;

const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_NT: u64 = 1 << 14;
const RFLAGS_RF: u64 = 1 << 16;
const RFLAGS_VM: u64 = 1 << 17;
const RFLAGS_AC: u64 = 1 << 18;

const DR6_FIXED_ONES: u64 = 0xffff_0ff0;
const DR6_WRITABLE_MASK: u64 = 0x0000_e00f;
const DR6_BD: u64 = 1 << 13;

const DR7_FIXED_ONES: u64 = 0x0000_0400;
const DR7_WRITABLE_MASK: u64 = 0xffff_23ff;
const DR7_GD: u64 = 1 << 13;

/// Internal step outcome returned by [`emulate_sensitive_op`].
pub(crate) enum PrivilegedOutcome {
    Continue { next_rip: u64 },
    Hlt { rip: u64, next_rip: u64 },
    Exception(X86Exception),
    Unhandled,
}

fn dr_index(r: Register) -> Option<usize> {
    match r {
        Register::DR0 => Some(0),
        Register::DR1 => Some(1),
        Register::DR2 => Some(2),
        Register::DR3 => Some(3),
        Register::DR4 => Some(4),
        Register::DR5 => Some(5),
        Register::DR6 => Some(6),
        Register::DR7 => Some(7),
        _ => None,
    }
}

/// Decoded GDT segment descriptor with deferred Accessed-bit (`bit 40`) writeback,
/// committed only after all instruction/gate checks succeed.
pub(crate) struct LoadedGdtSegment {
    pub desc: u64,
    pub seg: SoftSegment,
    desc_va: u64,
    writeback_desc: Option<u64>,
}

impl LoadedGdtSegment {
    pub(crate) fn precheck_accessed_write<M: SoftMmuMemory>(
        &self,
        ctx: &mut SoftCpuContext,
        mem: &mut M,
        va: u64,
    ) -> Result<(), X86Exception> {
        if self.writeback_desc.is_some() {
            check_system_write(ctx, mem, self.desc_va, 8)
                .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
        }
        Ok(())
    }

    pub(crate) fn commit_accessed_write<M: SoftMmuMemory>(
        &self,
        ctx: &mut SoftCpuContext,
        mem: &mut M,
        va: u64,
    ) -> Result<(), X86Exception> {
        if let Some(accessed) = self.writeback_desc {
            write_system_bytes(ctx, mem, self.desc_va, &accessed.to_le_bytes())
                .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
        }
        Ok(())
    }
}

/// Read an 8-byte non-system descriptor from `GDTR` at selector `sel`, staging its
/// architectural Accessed bit (`bit 40`) without mutating memory until commit.
pub(crate) fn load_gdt_code_or_data_descriptor<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    sel: u16,
    sel_err: u32,
) -> Result<LoadedGdtSegment, X86Exception> {
    if (sel & 4) != 0 {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let idx = sel >> 3;
    let offset = u64::from(idx) * 8;
    if offset.saturating_add(7) > u64::from(ctx.gdtr.limit) {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let desc_va = ctx.gdtr.base.wrapping_add(offset);
    if !is_canonical_va(desc_va) || !is_canonical_va(desc_va.wrapping_add(7)) {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let mut raw_bytes = [0u8; 8];
    read_system_bytes(ctx, mem, desc_va, &mut raw_bytes)
        .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
    let desc = u64::from_le_bytes(raw_bytes);
    let s = ((desc >> 44) & 1) != 0;
    let p = ((desc >> 47) & 1) != 0;
    let writeback_desc = (s && p && (desc & (1 << 40)) == 0).then_some(desc | (1 << 40));
    let final_desc = writeback_desc.unwrap_or(desc);
    let raw_limit = ((final_desc & 0xffff) | (((final_desc >> 48) & 0xf) << 16)) as u32;
    let g = ((final_desc >> 55) & 1) != 0;
    let limit = if g {
        (raw_limit << 12) | 0xfff
    } else {
        raw_limit
    };
    let base32 = ((final_desc >> 16) & 0xffff)
        | (((final_desc >> 32) & 0xff) << 16)
        | (((final_desc >> 56) & 0xff) << 24);
    let ar = (((final_desc >> 40) & 0xff) as u32) | ((((final_desc >> 52) & 0xf) as u32) << 12);
    let seg = SoftSegment {
        selector: sel,
        base: base32,
        limit,
        ar,
    };
    Ok(LoadedGdtSegment {
        desc: final_desc,
        seg,
        desc_va,
        writeback_desc,
    })
}

/// Emulate CPL0 privileged and system instructions on `ctx` before falling back to host exit.
pub(crate) fn emulate_sensitive_op<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
    op: SensitiveOp,
    raw: &Instruction,
    mem: &mut M,
) -> PrivilegedOutcome {
    let res = match op {
        SensitiveOp::MovFromCr { cr, gpr } => emulate_mov_from_cr(ctx, va, resume, cr, gpr),
        SensitiveOp::MovToCr { cr, gpr } => emulate_mov_to_cr(ctx, cpuid, va, resume, cr, gpr),
        SensitiveOp::MovDr => emulate_mov_dr(ctx, va, resume, raw),
        SensitiveOp::Rdmsr => emulate_rdmsr(ctx, cpuid, va, resume),
        SensitiveOp::Wrmsr => emulate_wrmsr(ctx, cpuid, va, resume),
        SensitiveOp::Rdtsc => emulate_rdtsc(ctx, cpuid, va, resume),
        SensitiveOp::Lgdt => emulate_lgdt_lidt(ctx, mem, va, resume, raw, true),
        SensitiveOp::Lidt => emulate_lgdt_lidt(ctx, mem, va, resume, raw, false),
        SensitiveOp::Sgdt => emulate_sgdt_sidt(ctx, mem, va, resume, raw, true),
        SensitiveOp::Sidt => emulate_sgdt_sidt(ctx, mem, va, resume, raw, false),
        SensitiveOp::Sldt => emulate_sldt_str(ctx, mem, va, resume, raw, true),
        SensitiveOp::Str => emulate_sldt_str(ctx, mem, va, resume, raw, false),
        SensitiveOp::Smsw => emulate_smsw(ctx, mem, va, resume, raw),
        SensitiveOp::Ltr => emulate_ltr(ctx, mem, va, resume, raw),
        SensitiveOp::Swapgs => emulate_swapgs(ctx, va, resume),
        SensitiveOp::Sysret => emulate_sysret(ctx, va, raw),
        SensitiveOp::Iretq => emulate_iret(ctx, mem, va, raw),
        SensitiveOp::Hlt => {
            if ctx.cpl != 0 {
                return PrivilegedOutcome::Exception(X86Exception::general_protection(va, 0));
            }
            ctx.halted = true;
            ctx.rip = resume;
            return PrivilegedOutcome::Hlt {
                rip: va,
                next_rip: resume,
            };
        }
        SensitiveOp::Invlpg => emulate_invlpg(ctx, va, resume, raw),
        SensitiveOp::Cpuid => emulate_cpuid(ctx, cpuid, resume),
        SensitiveOp::Cli => emulate_cli_sti(ctx, va, resume, false),
        SensitiveOp::Sti => emulate_cli_sti(ctx, va, resume, true),
        SensitiveOp::Clac => emulate_clac_stac(ctx, cpuid, va, resume, raw, false),
        SensitiveOp::Stac => emulate_clac_stac(ctx, cpuid, va, resume, raw, true),
        SensitiveOp::Xgetbv => emulate_xgetbv(ctx, va, resume),
        SensitiveOp::Xsetbv => emulate_xsetbv(ctx, cpuid, va, resume),
        _ => return PrivilegedOutcome::Unhandled,
    };

    match res {
        Ok(next_rip) => PrivilegedOutcome::Continue { next_rip },
        Err(exc) => PrivilegedOutcome::Exception(exc),
    }
}

fn emulate_mov_from_cr(
    ctx: &mut SoftCpuContext,
    va: u64,
    resume: u64,
    cr: u8,
    gpr: usize,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let val = match cr {
        0 => ctx.cr0,
        2 => ctx.cr2,
        3 => ctx.cr3,
        4 => ctx.cr4,
        8 => ctx.cr8,
        _ => return Err(X86Exception::invalid_opcode(va)),
    };
    if gpr >= ctx.gpr.len() {
        return Err(X86Exception::invalid_opcode(va));
    }
    ctx.gpr[gpr] = val;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_mov_to_cr(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
    cr: u8,
    gpr: usize,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    if gpr >= ctx.gpr.len() {
        return Err(X86Exception::invalid_opcode(va));
    }
    let val = ctx.gpr[gpr];
    match cr {
        0 => {
            if (val >> 32) != 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            let pe = (val & CR0_PE) != 0;
            let pg = (val & CR0_PG) != 0;
            let nw = (val & CR0_NW) != 0;
            let cd = (val & CR0_CD) != 0;
            if (pg && !pe) || (nw && !cd) {
                return Err(X86Exception::general_protection(va, 0));
            }
            let efer = ctx.efer();
            let long_mode_active = (efer & EFER_LMA) != 0;
            if pg && (efer & EFER_LME) != 0 && (ctx.cr4 & CR4_PAE) == 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            if !pg && ((long_mode_active && ctx.cs.is_64bit_code()) || (ctx.cr4 & CR4_PCIDE) != 0) {
                return Err(X86Exception::general_protection(va, 0));
            }
            if !pe && long_mode_active {
                return Err(X86Exception::general_protection(va, 0));
            }
            let next = (val & CR0_WRITABLE_MASK) | CR0_ET;
            let tlb_sensitive = CR0_PG | CR0_WP | CR0_NW | CR0_CD;
            let flush = (ctx.cr0 & tlb_sensitive) != (next & tlb_sensitive);
            ctx.cr0 = next;
            ctx.sync_efer_lma();
            ctx.sync_tlb_tag_bits();
            if flush {
                ctx.flush_tlb();
            }
        }
        2 => {
            ctx.cr2 = val;
        }
        3 => {
            let max_phy = cpuid.max_phy_addr();
            let phy_limit = if max_phy >= 64 {
                u64::MAX
            } else {
                (1u64 << max_phy) - 1
            };
            ctx.walker.set_max_phy_addr(max_phy);
            let clean = if (ctx.cr4 & CR4_PCIDE) != 0 {
                val & !(1 << 63)
            } else {
                val
            };
            if (clean & !phy_limit) != 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            ctx.cr3 = clean;
            // `SoftTlb` has no PCID/ASID tag yet: flush unconditionally on every CR3 write
            // so `CR4.PCIDE=1` + `CR3[63]` (NOFLUSH) cannot leak translations across roots.
            ctx.flush_tlb();
        }
        4 => {
            if (val & CR4_UNSUPPORTED_MASK) != 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            let long_mode_active = (ctx.efer() & EFER_LMA) != 0;
            // SDM Vol. 3A §4.1.1: clearing CR4.PAE or toggling CR4.LA57 while EFER.LMA=1 raises #GP(0).
            if long_mode_active
                && ((val & CR4_PAE) == 0 || (val & CR4_LA57) != (ctx.cr4 & CR4_LA57))
            {
                return Err(X86Exception::general_protection(va, 0));
            }
            if !long_mode_active && (val & CR4_LA57) != 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            for (bit, supported) in [
                (CR4_VME, cpuid.supports_vme()),
                (CR4_PVI, cpuid.supports_vme()),
                (CR4_UMIP, cpuid.supports_umip()),
                (CR4_FSGSBASE, cpuid.supports_fsgsbase()),
                (CR4_OSXSAVE, cpuid.supports_xsave()),
                (CR4_SMEP, cpuid.supports_smep()),
                (CR4_SMAP, cpuid.supports_smap()),
            ] {
                if (val & bit) != 0 && !supported {
                    return Err(X86Exception::general_protection(va, 0));
                }
            }
            // SDM Vol. 3A §4.10.1: 0->1 transition of CR4.PCIDE requires LMA=1 and CR3[11:0] == 0.
            if (val & CR4_PCIDE) != 0
                && (!cpuid.supports_pcid()
                    || !long_mode_active
                    || ((ctx.cr4 & CR4_PCIDE) == 0 && (ctx.cr3 & 0xfff) != 0))
            {
                return Err(X86Exception::general_protection(va, 0));
            }
            let tlb_sensitive = CR4_PAE | CR4_PGE | CR4_PCIDE | CR4_SMEP | CR4_SMAP;
            let flush = (ctx.cr4 & tlb_sensitive) != (val & tlb_sensitive);
            ctx.cr4 = val;
            ctx.sync_tlb_tag_bits();
            if flush {
                ctx.flush_tlb();
            }
        }
        8 => {
            if (val & !0xf) != 0 {
                return Err(X86Exception::general_protection(va, 0));
            }
            ctx.cr8 = val;
        }
        _ => return Err(X86Exception::invalid_opcode(va)),
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_mov_dr(
    ctx: &mut SoftCpuContext,
    va: u64,
    resume: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    let r0 = raw.op0_register();
    let r1 = raw.op1_register();
    let (is_write, raw_dr, gpr) = if let (Some(dr), Some(gpr)) = (dr_index(r0), gpr_index(r1)) {
        (true, dr, gpr)
    } else if let (Some(gpr), Some(dr)) = (gpr_index(r0), dr_index(r1)) {
        (false, dr, gpr)
    } else {
        return Err(X86Exception::invalid_opcode(va));
    };

    // SDM Vol. 2B `MOV—Move to/from Debug Registers`:
    // 1. CR4.DE == 1 with DR4/DR5 -> #UD (evaluated before CPL check in SDM Operation).
    if (ctx.cr4 & CR4_DE) != 0 && matches!(raw_dr, 4 | 5) {
        return Err(X86Exception::invalid_opcode(va));
    }
    // 2. CPL != 0 -> #GP(0).
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    // 3. DR7.GD == 1 -> set DR6.BD, clear DR7.GD, raise #DB.
    if (ctx.dr[7] & DR7_GD) != 0 {
        ctx.dr[6] |= DR6_BD;
        ctx.dr[7] &= !DR7_GD;
        return Err(X86Exception::debug(va));
    }

    let eff_dr = match raw_dr {
        4 => 6,
        5 => 7,
        other => other,
    };

    if is_write {
        let val = ctx.gpr[gpr];
        match eff_dr {
            0..=3 => {
                ctx.dr[eff_dr] = val;
            }
            6 => {
                if (val >> 32) != 0 {
                    return Err(X86Exception::general_protection(va, 0));
                }
                ctx.dr[6] = (val & DR6_WRITABLE_MASK) | DR6_FIXED_ONES;
            }
            7 => {
                if (val >> 32) != 0 {
                    return Err(X86Exception::general_protection(va, 0));
                }
                ctx.dr[7] = (val & DR7_WRITABLE_MASK) | DR7_FIXED_ONES;
            }
            _ => return Err(X86Exception::invalid_opcode(va)),
        }
    } else {
        ctx.gpr[gpr] = ctx.dr[eff_dr];
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_rdmsr(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let index = MsrIndex::new(ctx.gpr[reg::RCX] as u32);
    let caps = MsrCapabilities::from_cpuid(cpuid);
    let val = ctx
        .msrs()
        .read(index, caps)
        .map_err(|_| X86Exception::general_protection(va, 0))?;
    ctx.gpr[reg::RAX] = val & 0xffff_ffff;
    ctx.gpr[reg::RDX] = val >> 32;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_wrmsr(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let index = MsrIndex::new(ctx.gpr[reg::RCX] as u32);
    let val = ((ctx.gpr[reg::RDX] & 0xffff_ffff) << 32) | (ctx.gpr[reg::RAX] & 0xffff_ffff);
    let caps = MsrCapabilities::from_cpuid(cpuid);
    ctx.write_msr(index, val, caps)
        .map_err(|_| X86Exception::general_protection(va, 0))?;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_rdtsc(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 && (ctx.cr4 & CR4_TSD) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let tsc = ctx.msrs().read_tsc(cpuid.tsc_hz());
    ctx.gpr[reg::RAX] = tsc & 0xffff_ffff;
    ctx.gpr[reg::RDX] = tsc >> 32;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_lgdt_lidt<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    resume: u64,
    raw: &Instruction,
    is_gdt: bool,
) -> Result<u64, X86Exception> {
    if raw.op0_kind() != OpKind::Memory {
        return Err(X86Exception::invalid_opcode(va));
    }
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let ea = compute_effective_va(raw, ctx);
    if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(9)) {
        return Err(X86Exception::general_protection(va, 0));
    }
    let mut buf = [0u8; 10];
    read_guest_bytes(ctx, mem, ea, &mut buf, SoftAccessKind::Read)
        .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
    let [l0, l1, b @ ..] = buf;
    let (limit, base) = (u16::from_le_bytes([l0, l1]), u64::from_le_bytes(b));
    if !is_canonical_va(base) {
        return Err(X86Exception::general_protection(va, 0));
    }
    let ptr = DescriptorTablePtr::new(limit, base);
    if is_gdt {
        ctx.gdtr = ptr;
    } else {
        ctx.idtr = ptr;
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_sgdt_sidt<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    resume: u64,
    raw: &Instruction,
    is_gdt: bool,
) -> Result<u64, X86Exception> {
    if raw.op0_kind() != OpKind::Memory {
        return Err(X86Exception::invalid_opcode(va));
    }
    if ctx.cpl != 0 && (ctx.cr4 & CR4_UMIP) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let ea = compute_effective_va(raw, ctx);
    if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(9)) {
        return Err(X86Exception::general_protection(va, 0));
    }
    let dt = if is_gdt { ctx.gdtr } else { ctx.idtr };
    let mut buf = [0u8; 10];
    buf[0..2].copy_from_slice(&dt.limit.to_le_bytes());
    buf[2..10].copy_from_slice(&dt.base.to_le_bytes());
    write_guest_bytes(ctx, mem, ea, &buf)
        .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_sldt_str<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    resume: u64,
    raw: &Instruction,
    is_ldt: bool,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 && (ctx.cr4 & CR4_UMIP) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let sel = if is_ldt {
        ctx.ldtr.selector
    } else {
        ctx.tr.selector
    };
    match raw.op0_kind() {
        OpKind::Register => {
            let r = raw.op0_register();
            let idx = gpr_index(r).ok_or_else(|| X86Exception::invalid_opcode(va))?;
            if r.size() == 2 {
                ctx.gpr[idx] = (ctx.gpr[idx] & !0xffff) | u64::from(sel);
            } else {
                ctx.gpr[idx] = u64::from(sel);
            }
        }
        OpKind::Memory => {
            let ea = compute_effective_va(raw, ctx);
            if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(1)) {
                return Err(X86Exception::general_protection(va, 0));
            }
            check_guest_alignment(ctx, mem, ea, 2, 2, SoftAccessKind::Write, va)?;
            write_guest_bytes(ctx, mem, ea, &sel.to_le_bytes())
                .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
        }
        _ => return Err(X86Exception::invalid_opcode(va)),
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_smsw<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    resume: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 && (ctx.cr4 & CR4_UMIP) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    match raw.op0_kind() {
        OpKind::Register => {
            let r = raw.op0_register();
            let idx = gpr_index(r).ok_or_else(|| X86Exception::invalid_opcode(va))?;
            match r.size() {
                2 => ctx.gpr[idx] = (ctx.gpr[idx] & !0xffff) | (ctx.cr0 & 0xffff),
                4 => ctx.gpr[idx] = ctx.cr0 & 0xffff_ffff,
                _ => ctx.gpr[idx] = ctx.cr0,
            }
        }
        OpKind::Memory => {
            let ea = compute_effective_va(raw, ctx);
            if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(1)) {
                return Err(X86Exception::general_protection(va, 0));
            }
            check_guest_alignment(ctx, mem, ea, 2, 2, SoftAccessKind::Write, va)?;
            let word = (ctx.cr0 as u16).to_le_bytes();
            write_guest_bytes(ctx, mem, ea, &word)
                .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
        }
        _ => return Err(X86Exception::invalid_opcode(va)),
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_ltr<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    resume: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let raw_sel = match raw.op0_kind() {
        OpKind::Register => {
            let idx =
                gpr_index(raw.op0_register()).ok_or_else(|| X86Exception::invalid_opcode(va))?;
            (ctx.gpr[idx] & 0xffff) as u16
        }
        OpKind::Memory => {
            let ea = compute_effective_va(raw, ctx);
            if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(1)) {
                return Err(X86Exception::general_protection(va, 0));
            }
            let mut b = [0u8; 2];
            read_guest_bytes(ctx, mem, ea, &mut b, SoftAccessKind::Read)
                .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
            u16::from_le_bytes(b)
        }
        _ => return Err(X86Exception::invalid_opcode(va)),
    };

    // SDM Vol. 2A `LTR`: only Index=0 && TI=0 (`0x0000..=0x0003`) is a null selector (#GP(0));
    // TI=1 (LDT, including `0x0004`) raises #GP(selector & 0xfffc).
    if (raw_sel & 0xfffc) == 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let sel_err = u32::from(raw_sel & 0xfffc);
    if (raw_sel & 4) != 0 {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let idx = raw_sel >> 3;
    let offset = u64::from(idx) * 8;
    if offset.saturating_add(15) > u64::from(ctx.gdtr.limit) {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let desc_va = ctx.gdtr.base.wrapping_add(offset);
    if !is_canonical_va(desc_va) || !is_canonical_va(desc_va.wrapping_add(15)) {
        return Err(X86Exception::general_protection(va, sel_err));
    }

    let mut desc_bytes = [0u8; 16];
    read_system_bytes(ctx, mem, desc_va, &mut desc_bytes)
        .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;
    let [l0, l1, l2, l3, l4, l5, l6, l7, h @ ..] = desc_bytes;
    let low = u64::from_le_bytes([l0, l1, l2, l3, l4, l5, l6, l7]);
    let high = u64::from_le_bytes(h);

    let typ = ((low >> 40) & 0xf) as u8;
    let s = ((low >> 44) & 1) != 0;
    let p = ((low >> 47) & 1) != 0;
    let raw_limit = ((low & 0xffff) | (((low >> 48) & 0xf) << 16)) as u32;
    let g = ((low >> 55) & 1) != 0;
    let limit = if g {
        (raw_limit << 12) | 0xfff
    } else {
        raw_limit
    };
    // SDM Vol. 3A §7.2.2/§7.2.3: 64-bit Available TSS requires S=0, Type=0x9,
    // upper dword bits [12:8] == 0, and byte limit >= 0x67 (104-byte TSS64).
    let upper_dword_zero_field = (high >> 40) & 0x1f;
    if s || typ != 0x9 || upper_dword_zero_field != 0 || limit < 0x67 {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    let base = ((low >> 16) & 0xffff)
        | (((low >> 32) & 0xff) << 16)
        | (((low >> 56) & 0xff) << 24)
        | ((high & 0xffff_ffff) << 32);
    if !is_canonical_va(base) {
        return Err(X86Exception::general_protection(va, sel_err));
    }
    if !p {
        return Err(X86Exception::segment_not_present(va, sel_err));
    }

    // Mark TSS descriptor busy (Type 0x9 -> 0xb) in GDT.
    let busy_low = low | (0x2 << 40);
    write_system_bytes(ctx, mem, desc_va, &busy_low.to_le_bytes())
        .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;

    let ar = (((busy_low >> 40) & 0xff) as u32) | ((((busy_low >> 52) & 0xf) as u32) << 12);
    ctx.tr = SoftSegment {
        selector: raw_sel,
        base,
        limit,
        ar,
    };
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_swapgs(ctx: &mut SoftCpuContext, va: u64, resume: u64) -> Result<u64, X86Exception> {
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    ctx.swapgs();
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_sysret(
    ctx: &mut SoftCpuContext,
    va: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    let efer = ctx.efer();
    // SDM Vol. 2B `SYSRET` Operation: EFER.SCE == 0 raises #UD BEFORE checking CPL != 0.
    if (efer & EFER_SCE) == 0 || (efer & EFER_LMA) == 0 || !ctx.cs.is_64bit_code() {
        return Err(X86Exception::invalid_opcode(va));
    }
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }

    let star_hi = ((ctx.msrs().star() >> 48) & 0xffff) as u16;
    if raw.mnemonic() == Mnemonic::Sysretq {
        let rcx = ctx.gpr[reg::RCX];
        if !is_canonical_va(rcx) {
            return Err(X86Exception::general_protection(va, 0));
        }
        ctx.cs = SoftSegment::user_code64(star_hi.wrapping_add(16));
        ctx.ss = SoftSegment::user_data(star_hi.wrapping_add(8));
        ctx.rflags = (ctx.gpr[reg::R11] & 0x003c_7fd7) | 0x2;
        ctx.rflags &= !(RFLAGS_RF | RFLAGS_VM);
        ctx.set_cpl(3);
        ctx.halted = false;
        ctx.rip = rcx;
        Ok(rcx)
    } else {
        // Non-REX.W SYSRET would drop to 32-bit compatibility mode (`CS.L = 0`), which
        // 64-bit-only SoftCpu refuses with #GP(0) before mutating state.
        Err(X86Exception::general_protection(va, 0))
    }
}

fn clear_outer_data_segments(ctx: &mut SoftCpuContext, new_cpl: u8) {
    for seg in [&mut ctx.ds, &mut ctx.es, &mut ctx.fs, &mut ctx.gs] {
        if !seg.is_unusable() {
            let typ = seg.ar & 0xf;
            let is_conforming_code = (typ & 0xc) == 0xc;
            if !is_conforming_code && seg.dpl() < new_cpl {
                *seg = SoftSegment::unusable();
            }
        }
    }
}

fn emulate_iret<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    va: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    let slot = match raw.mnemonic() {
        Mnemonic::Iretq => 8usize,
        Mnemonic::Iretd => 4usize,
        Mnemonic::Iret => 2usize,
        _ => return Err(X86Exception::invalid_opcode(va)),
    };
    // SDM Vol. 2A `IRET/IRETD/IRETQ` IA-32e-Mode: RFLAGS.NT == 1 raises #GP(0) before popping the stack.
    if (ctx.rflags & RFLAGS_NT) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let frame_bytes = slot * 5;
    let rsp = ctx.gpr[reg::RSP];
    if !is_canonical_va(rsp) || !is_canonical_va(rsp.wrapping_add((frame_bytes - 1) as u64)) {
        return Err(X86Exception::stack_segment_fault(va, 0));
    }

    let mut frame = [0u8; 40];
    read_guest_bytes(
        ctx,
        mem,
        rsp,
        &mut frame[..frame_bytes],
        SoftAccessKind::Read,
    )
    .map_err(|pf| X86Exception::page_fault(va, pf.error_code, pf.cr2))?;

    let read_slot = |index: usize| -> u64 {
        let s = &frame[index * slot..];
        match slot {
            8 => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
            4 => u64::from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])),
            _ => u64::from(u16::from_le_bytes([s[0], s[1]])),
        }
    };

    let new_rip = read_slot(0);
    let cs_sel = (read_slot(1) & 0xffff) as u16;
    let new_rflags = read_slot(2);
    let new_rsp = read_slot(3);
    let ss_sel = (read_slot(4) & 0xffff) as u16;

    // 1. Validate return CS selector and descriptor (Intel SDM Vol. 2A `IRET` IA-32e Mode).
    if (cs_sel & 0xfffc) == 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let rpl = (cs_sel & 3) as u8;
    let cs_err = u32::from(cs_sel & 0xfffc);
    if rpl < ctx.cpl {
        return Err(X86Exception::general_protection(va, cs_err));
    }

    let mut cs_loaded = load_gdt_code_or_data_descriptor(ctx, mem, va, cs_sel, cs_err)?;
    let cs_desc = cs_loaded.desc;
    let cs_type = ((cs_desc >> 40) & 0xf) as u8;
    let cs_s = ((cs_desc >> 44) & 1) != 0;
    let cs_dpl = ((cs_desc >> 45) & 3) as u8;
    let cs_p = ((cs_desc >> 47) & 1) != 0;
    let cs_l = ((cs_desc >> 53) & 1) != 0;
    let cs_db = ((cs_desc >> 54) & 1) != 0;
    if !cs_s || (cs_type & 0x8) == 0 {
        return Err(X86Exception::general_protection(va, cs_err));
    }
    let conforming = (cs_type & 0x4) != 0;
    if (!conforming && cs_dpl != rpl) || (conforming && cs_dpl > rpl) {
        return Err(X86Exception::general_protection(va, cs_err));
    }
    if !cs_p {
        return Err(X86Exception::segment_not_present(va, cs_err));
    }
    // L=1 && D/B=1 is architecturally #GP(cs_err); L=0 compatibility mode is unsupported in 64-bit SoftCpu.
    if !cs_l || cs_db {
        return Err(X86Exception::general_protection(va, cs_err));
    }
    cs_loaded.seg.selector = cs_sel;

    // 2. Validate return RIP canonicality.
    if !is_canonical_va(new_rip) {
        return Err(X86Exception::general_protection(va, 0));
    }

    // 3. Validate return SS selector and descriptor.
    // SDM Vol. 2A `IRET` IA-32e Mode: NULL SS selector is permitted when returning to CPL < 3,
    // and forbidden (#GP(0)) when returning to CPL == 3.
    let (new_ss, ss_loaded) = if (ss_sel & 0xfffc) == 0 {
        if rpl == 3 || ((ss_sel & 3) as u8 != rpl && ss_sel != 0) {
            return Err(X86Exception::general_protection(va, 0));
        }
        (
            SoftSegment {
                selector: ss_sel,
                base: 0,
                limit: 0,
                ar: SoftSegment::UNUSABLE_BIT,
            },
            None,
        )
    } else {
        let ss_err = u32::from(ss_sel & 0xfffc);
        if (ss_sel & 3) as u8 != rpl {
            return Err(X86Exception::general_protection(va, ss_err));
        }
        let mut loaded = load_gdt_code_or_data_descriptor(ctx, mem, va, ss_sel, ss_err)?;
        let ss_desc = loaded.desc;
        let ss_type = ((ss_desc >> 40) & 0xf) as u8;
        let ss_s = ((ss_desc >> 44) & 1) != 0;
        let ss_dpl = ((ss_desc >> 45) & 3) as u8;
        let ss_p = ((ss_desc >> 47) & 1) != 0;
        // Must be writable data segment (S=1, code=0, writable=1) with DPL == RPL.
        if !ss_s || (ss_type & 0xa) != 0x2 || ss_dpl != rpl {
            return Err(X86Exception::general_protection(va, ss_err));
        }
        if !ss_p {
            return Err(X86Exception::stack_segment_fault(va, ss_err));
        }
        loaded.seg.selector = ss_sel;
        let seg = loaded.seg;
        (seg, Some(loaded))
    };

    // 4. Validate return RSP canonicality.
    if !is_canonical_va(new_rsp) {
        return Err(X86Exception::stack_segment_fault(va, 0));
    }

    // 4b. Precheck then commit GDT Accessed bits only after all CS/RIP/SS/RSP checks pass.
    cs_loaded.precheck_accessed_write(ctx, mem, va)?;
    if let Some(ss) = &ss_loaded {
        ss.precheck_accessed_write(ctx, mem, va)?;
    }
    cs_loaded.commit_accessed_write(ctx, mem, va)?;
    if let Some(ss) = &ss_loaded {
        ss.commit_accessed_write(ctx, mem, va)?;
    }
    let new_cs = cs_loaded.seg;

    // 5. Commit RFLAGS according to old CPL / IOPL rules (SDM Vol. 2A `IRET`).
    let old_cpl = ctx.cpl;
    let iopl = ((ctx.rflags >> 12) & 3) as u8;
    let mut mask: u64 = if slot == 2 { 0x4dd5 } else { 0x0025_4dd5 };
    if old_cpl <= iopl {
        mask |= RFLAGS_IF;
    }
    if old_cpl == 0 {
        mask |= 3 << 12;
        if slot >= 4 {
            mask |= (1 << 19) | (1 << 20);
        }
    }

    ctx.rflags = ((ctx.rflags & !mask) | (new_rflags & mask) | 0x2) & !RFLAGS_VM;
    ctx.rip = new_rip;
    ctx.gpr[reg::RSP] = new_rsp;
    ctx.cs = new_cs;
    ctx.ss = new_ss;
    if rpl > old_cpl {
        clear_outer_data_segments(ctx, rpl);
    }
    ctx.set_cpl(rpl);
    ctx.halted = false;
    Ok(new_rip)
}

fn emulate_invlpg(
    ctx: &mut SoftCpuContext,
    va: u64,
    resume: u64,
    raw: &Instruction,
) -> Result<u64, X86Exception> {
    if raw.op0_kind() != OpKind::Memory {
        return Err(X86Exception::invalid_opcode(va));
    }
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let ea = compute_effective_va(raw, ctx);
    // SDM Vol. 2A `INVLPG`: never faults on unmapped or non-canonical addresses;
    // canonical addresses invalidate matching TLB entries.
    if is_canonical_va(ea) {
        ctx.evict_tlb_va(ea);
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_cpuid(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    resume: u64,
) -> Result<u64, X86Exception> {
    let leaf = ctx.gpr[reg::RAX] as u32;
    let subleaf = ctx.gpr[reg::RCX] as u32;
    let mut out = cpuid.cpuid(leaf, subleaf);
    if leaf == 1 && cpuid.mirrors_osxsave() && (out.ecx & (1 << 26)) != 0 {
        if (ctx.cr4 & CR4_OSXSAVE) != 0 {
            out.ecx |= 1 << 27;
        } else {
            out.ecx &= !(1 << 27);
        }
    }
    ctx.gpr[reg::RAX] = u64::from(out.eax);
    ctx.gpr[reg::RBX] = u64::from(out.ebx);
    ctx.gpr[reg::RCX] = u64::from(out.ecx);
    ctx.gpr[reg::RDX] = u64::from(out.edx);
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_cli_sti(
    ctx: &mut SoftCpuContext,
    va: u64,
    resume: u64,
    enable: bool,
) -> Result<u64, X86Exception> {
    let iopl = ((ctx.rflags >> 12) & 3) as u8;
    if ctx.cpl > iopl {
        return Err(X86Exception::general_protection(va, 0));
    }
    if enable {
        ctx.rflags |= RFLAGS_IF;
    } else {
        ctx.rflags &= !RFLAGS_IF;
    }
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_clac_stac(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
    raw: &Instruction,
    set_ac: bool,
) -> Result<u64, X86Exception> {
    // SDM Vol. 2A `CLAC`/`STAC`: #UD when CPL > 0, SMAP unsupported, or prefixed with F2/F3/66/LOCK.
    if ctx.cpl != 0 || !cpuid.supports_smap() || raw.has_rep_prefix() || raw.has_repne_prefix() {
        return Err(X86Exception::invalid_opcode(va));
    }
    if set_ac {
        ctx.rflags |= RFLAGS_AC;
    } else {
        ctx.rflags &= !RFLAGS_AC;
    }
    ctx.sync_tlb_tag_bits();
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_xgetbv(ctx: &mut SoftCpuContext, va: u64, resume: u64) -> Result<u64, X86Exception> {
    if (ctx.cr4 & CR4_OSXSAVE) == 0 {
        return Err(X86Exception::invalid_opcode(va));
    }
    if (ctx.gpr[reg::RCX] as u32) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    ctx.gpr[reg::RAX] = ctx.xcr0 & 0xffff_ffff;
    ctx.gpr[reg::RDX] = ctx.xcr0 >> 32;
    ctx.rip = resume;
    Ok(resume)
}

fn emulate_xsetbv(
    ctx: &mut SoftCpuContext,
    cpuid: &dyn GuestCpuidView,
    va: u64,
    resume: u64,
) -> Result<u64, X86Exception> {
    // SDM Vol. 2C `XSETBV` Operation: CR4.OSXSAVE == 0 raises #UD before CPL check.
    if (ctx.cr4 & CR4_OSXSAVE) == 0 {
        return Err(X86Exception::invalid_opcode(va));
    }
    if ctx.cpl != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    if (ctx.gpr[reg::RCX] as u32) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    let val = ((ctx.gpr[reg::RDX] & 0xffff_ffff) << 32) | (ctx.gpr[reg::RAX] & 0xffff_ffff);
    let supported = cpuid.supported_xcr0_mask();
    // XCR0[0] (x87) must always be 1; AVX (bit 2) without SSE (bit 1) is illegal; unsupported bits -> #GP(0).
    if (val & 1) == 0 || (val & 0x6) == 0x4 || (val & !supported) != 0 {
        return Err(X86Exception::general_protection(va, 0));
    }
    ctx.xcr0 = val;
    ctx.rip = resume;
    Ok(resume)
}
