//! VM-free CPL0 + CPL3 x86_64 machine harness (`SoftMachine`) over [`SoftCpu`] and [`SoftMmuMemory`].
//!
//! Connects user-mode `SYSCALL`, CPL0 privileged instructions (`WRMSR`/`RDMSR`, `LGDT`/`LIDT`/`LTR`,
//! `SWAPGS`, `SYSRET`/`IRETQ`, `MOV CR`/`DR`, `INVLPG`, `HLT`, `CPUID`), 64-bit `IDT` exception
//! and software-interrupt delivery (with `TSS` `RSP0`/`IST` stack switching and `#DF` / triple-fault
//! escalation), and Ring-0 port I/O exits so CPL0 kernels (including `carrick-x86-cpl0-fixture`)
//! execute deterministically without `/dev/kvm`.

use crate::context::{SoftCpuContext, SoftSegment, X86Exception, X86ExceptionVector, reg};
use crate::cpu::{SoftCpu, SoftCpuExit, SoftCpuNewError};
use crate::cpuid::GuestCpuidView;
use crate::decode::SensitiveOp;
use crate::emit::EmitError;
use crate::mmu::{SoftMmuMemory, is_canonical_va, read_system_bytes, write_system_bytes};
use crate::privileged::load_gdt_code_or_data_descriptor;

const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_NT: u64 = 1 << 14;
const RFLAGS_RF: u64 = 1 << 16;
const RFLAGS_VM: u64 = 1 << 17;

/// Host-observable machine exit returned by [`SoftMachine::step`] and [`SoftMachine::run`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftMachineExit {
    /// Guest CPL0 executed `HLT` (`ctx.rip` points at `next_rip`, `ctx.halted == true`).
    Hlt { rip: u64, next_rip: u64 },
    /// Guest CPL0 executed `OUT` (`ctx.rip` is already advanced to `next_rip`, matching KVM PIO exit completion).
    IoOut {
        rip: u64,
        next_rip: u64,
        port: u16,
        size: u8,
        value: u32,
    },
    /// Guest CPL0 executed `IN` (`ctx.rip` is advanced to `next_rip`; call [`SoftMachine::complete_io_in`] to deposit `AL`/`AX`/`EAX`).
    IoIn {
        rip: u64,
        next_rip: u64,
        port: u16,
        size: u8,
    },
    /// An unemulated sensitive instruction (`INVD`, `WBINVD`, `MOV segreg`, etc.) exited at CPL0.
    UnhandledSensitive {
        rip: u64,
        next_rip: u64,
        op: SensitiveOp,
    },
    /// Escalated exception faulted while delivering `#DF` (or `IDTR` was unmapped/empty).
    TripleFault { last_exception: X86Exception },
    /// `SoftMachine::run` exhausted `max_steps` basic blocks without hitting a terminal exit.
    StepBudgetExhausted { steps: usize, rip: u64 },
}

/// Self-contained 64-bit x86 (`CPL0` + `CPL3`) virtual machine pairing [`SoftCpu`] with `M: SoftMmuMemory`.
pub struct SoftMachine<M: SoftMmuMemory> {
    cpu: SoftCpu,
    mem: M,
}

impl<M: SoftMmuMemory> SoftMachine<M> {
    /// Create a [`SoftMachine`] seated in `mem.extents()` with `cpuid`.
    pub fn new(mem: M, cpuid: Box<dyn GuestCpuidView>) -> Result<Self, SoftCpuNewError> {
        let cpu = SoftCpu::with_cpuid_view(mem.extents(), cpuid)?;
        Ok(Self { cpu, mem })
    }

    /// Construct a [`SoftMachine`] from an existing [`SoftCpu`] and `mem`.
    #[must_use]
    pub fn from_parts(cpu: SoftCpu, mem: M) -> Self {
        Self { cpu, mem }
    }

    /// Split into the underlying `(SoftCpu, M)`.
    #[must_use]
    pub fn into_parts(self) -> (SoftCpu, M) {
        (self.cpu, self.mem)
    }

    #[must_use]
    pub fn cpu(&self) -> &SoftCpu {
        &self.cpu
    }

    pub fn cpu_mut(&mut self) -> &mut SoftCpu {
        &mut self.cpu
    }

    #[must_use]
    pub fn mem(&self) -> &M {
        &self.mem
    }

    pub fn mem_mut(&mut self) -> &mut M {
        &mut self.mem
    }

    #[must_use]
    pub fn context(&self) -> &SoftCpuContext {
        self.cpu.context()
    }

    pub fn context_mut(&mut self) -> &mut SoftCpuContext {
        self.cpu.context_mut()
    }

    /// Deposit the input value for a preceding [`SoftMachineExit::IoIn`] into `AL`/`AX`/`EAX`.
    pub fn complete_io_in(&mut self, size: u8, value: u32) {
        let rax = &mut self.cpu.context_mut().gpr[reg::RAX];
        match size {
            1 => *rax = (*rax & !0xff) | u64::from(value & 0xff),
            2 => *rax = (*rax & !0xffff) | u64::from(value & 0xffff),
            _ => *rax = u64::from(value),
        }
    }

    /// Execute one basic block and resolve internal architectural transitions (`SYSCALL`,
    /// 64-bit `IDT` exception/interrupt delivery). Returns `Ok(None)` when guest execution
    /// continues inside the machine, or `Ok(Some(exit))` on a host-visible exit (`HLT`, PIO, triple fault).
    pub fn step(&mut self) -> Result<Option<SoftMachineExit>, EmitError> {
        let exit = self.cpu.step_block(&mut self.mem)?;
        Ok(handle_cpu_exit(&mut self.cpu, &mut self.mem, exit))
    }

    /// Run up to `max_steps` basic blocks until a [`SoftMachineExit`] occurs.
    pub fn run(&mut self, max_steps: usize) -> Result<SoftMachineExit, EmitError> {
        for _ in 0..max_steps {
            if let Some(exit) = self.step()? {
                return Ok(exit);
            }
        }
        Ok(SoftMachineExit::StepBudgetExhausted {
            steps: max_steps,
            rip: self.cpu.context().rip,
        })
    }
}

fn handle_cpu_exit<M: SoftMmuMemory>(
    cpu: &mut SoftCpu,
    mem: &mut M,
    exit: SoftCpuExit,
) -> Option<SoftMachineExit> {
    match exit {
        SoftCpuExit::Continue { .. } => None,
        SoftCpuExit::Hlt { rip, next_rip } => Some(SoftMachineExit::Hlt { rip, next_rip }),
        SoftCpuExit::Syscall { next_rip, .. } => {
            deliver_syscall(cpu.context_mut(), next_rip);
            None
        }
        SoftCpuExit::Exception(exc) => deliver_exception_with_escalation(cpu.context_mut(), mem, exc),
        SoftCpuExit::SoftwareInterrupt {
            vector,
            rip,
            next_rip,
        } => {
            let ctx = cpu.context_mut();
            match deliver_idt_vector(ctx, mem, vector, rip, next_rip, None, None, true) {
                Ok(()) => None,
                Err(fault) => deliver_exception_with_escalation(ctx, mem, fault),
            }
        }
        SoftCpuExit::Sensitive { rip, next_rip, op } => {
            let ctx = cpu.context_mut();
            let mask_val = |size: u8, raw: u64| -> u32 {
                match size {
                    1 => (raw & 0xff) as u32,
                    2 => (raw & 0xffff) as u32,
                    _ => (raw & 0xffff_ffff) as u32,
                }
            };
            match op {
                SensitiveOp::OutImm { port, size } => {
                    let value = mask_val(size, ctx.gpr[reg::RAX]);
                    ctx.rip = next_rip;
                    Some(SoftMachineExit::IoOut {
                        rip,
                        next_rip,
                        port: u16::from(port),
                        size,
                        value,
                    })
                }
                SensitiveOp::OutDx { size } => {
                    let port = (ctx.gpr[reg::RDX] & 0xffff) as u16;
                    let value = mask_val(size, ctx.gpr[reg::RAX]);
                    ctx.rip = next_rip;
                    Some(SoftMachineExit::IoOut {
                        rip,
                        next_rip,
                        port,
                        size,
                        value,
                    })
                }
                SensitiveOp::InImm { port, size } => {
                    ctx.rip = next_rip;
                    Some(SoftMachineExit::IoIn {
                        rip,
                        next_rip,
                        port: u16::from(port),
                        size,
                    })
                }
                SensitiveOp::InDx { size } => {
                    let port = (ctx.gpr[reg::RDX] & 0xffff) as u16;
                    ctx.rip = next_rip;
                    Some(SoftMachineExit::IoIn {
                        rip,
                        next_rip,
                        port,
                        size,
                    })
                }
                _ => Some(SoftMachineExit::UnhandledSensitive { rip, next_rip, op }),
            }
        }
    }
}

/// IA-32e `SYSCALL` transition into Ring 0 (`LSTAR`, `STAR[47:32]`, `FMASK`).
fn deliver_syscall(ctx: &mut SoftCpuContext, next_rip: u64) {
    ctx.sync_msr_mirrors();
    ctx.gpr[reg::RCX] = next_rip;
    ctx.gpr[reg::R11] = (ctx.rflags & 0x003c_7fd7) | 0x2;
    ctx.rflags = ((ctx.rflags & !ctx.msrs.fmask) & !(RFLAGS_RF | RFLAGS_VM)) | 0x2;
    let star_k = ((ctx.msrs.star >> 32) & 0xfffc) as u16;
    ctx.cs = SoftSegment::kernel_code64(star_k);
    ctx.ss = SoftSegment::kernel_data(star_k.wrapping_add(8));
    ctx.set_cpl(0);
    ctx.halted = false;
    ctx.rip = ctx.msrs.lstar;
}

fn deliver_exception_with_escalation<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    exc: X86Exception,
) -> Option<SoftMachineExit> {
    let vector = exc.vector as u8;
    let is_bp = exc.vector == X86ExceptionVector::Breakpoint;
    match deliver_idt_vector(
        ctx,
        mem,
        vector,
        exc.rip,
        exc.rip,
        exc.error_code,
        exc.cr2,
        is_bp,
    ) {
        Ok(()) => None,
        Err(secondary) => {
            if let Some(cr2) = secondary.cr2 {
                ctx.cr2 = cr2;
            }
            if exc.vector == X86ExceptionVector::DoubleFault {
                return Some(SoftMachineExit::TripleFault {
                    last_exception: secondary,
                });
            }
            let df = X86Exception::double_fault(exc.rip);
            match deliver_idt_vector(
                ctx,
                mem,
                X86ExceptionVector::DoubleFault as u8,
                df.rip,
                df.rip,
                df.error_code,
                None,
                false,
            ) {
                Ok(()) => None,
                Err(_) => Some(SoftMachineExit::TripleFault {
                    last_exception: exc,
                }),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn deliver_idt_vector<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    vector: u8,
    fault_va: u64,
    saved_rip: u64,
    error_code: Option<u32>,
    cr2_update: Option<u64>,
    software_origin: bool,
) -> Result<(), X86Exception> {
    let ext = u32::from(!software_origin);
    let gate_err = (u32::from(vector) << 3) | 0x2 | ext;
    let offset = u64::from(vector) * 16;
    if offset.saturating_add(15) > u64::from(ctx.idtr.limit) {
        return Err(X86Exception::general_protection(fault_va, gate_err));
    }
    let gate_va = ctx.idtr.base.wrapping_add(offset);
    if !is_canonical_va(gate_va) || !is_canonical_va(gate_va.wrapping_add(15)) {
        return Err(X86Exception::general_protection(fault_va, gate_err));
    }

    let mut gate = [0u8; 16];
    read_system_bytes(ctx, mem, gate_va, &mut gate)
        .map_err(|pf| X86Exception::page_fault(fault_va, pf.error_code, pf.cr2))?;

    let offset_low = u16::from_le_bytes([gate[0], gate[1]]);
    let target_cs_sel = u16::from_le_bytes([gate[2], gate[3]]);
    let ist = gate[4] & 0x7;
    let attrs = gate[5];
    let offset_mid = u16::from_le_bytes([gate[6], gate[7]]);
    let offset_high = u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]]);
    let reserved = u32::from_le_bytes([gate[12], gate[13], gate[14], gate[15]]);

    let gate_type = attrs & 0x1f;
    // Must be a 64-bit Interrupt Gate (0x0e) or Trap Gate (0x0f) with upper bits [12:8] == 0.
    if !matches!(gate_type, 0x0e | 0x0f) || (reserved & 0x1f00) != 0 {
        return Err(X86Exception::general_protection(fault_va, gate_err));
    }
    let gate_dpl = (attrs >> 5) & 3;
    let gate_p = (attrs & 0x80) != 0;
    if software_origin && ctx.cpl > gate_dpl {
        return Err(X86Exception::general_protection(fault_va, gate_err));
    }
    if !gate_p {
        return Err(X86Exception::segment_not_present(fault_va, gate_err));
    }

    let entry_rip = u64::from(offset_low)
        | (u64::from(offset_mid) << 16)
        | (u64::from(offset_high) << 32);
    if !is_canonical_va(entry_rip) {
        return Err(X86Exception::general_protection(fault_va, 0));
    }

    if (target_cs_sel & 0xfffc) == 0 {
        return Err(X86Exception::general_protection(fault_va, ext));
    }
    let cs_err = u32::from(target_cs_sel & 0xfffc) | ext;
    let (cs_desc, mut new_cs) =
        load_gdt_code_or_data_descriptor(ctx, mem, fault_va, target_cs_sel, cs_err)?;
    let cs_type = ((cs_desc >> 40) & 0xf) as u8;
    let cs_s = ((cs_desc >> 44) & 1) != 0;
    let cs_dpl = ((cs_desc >> 45) & 3) as u8;
    let cs_p = ((cs_desc >> 47) & 1) != 0;
    let cs_l = ((cs_desc >> 53) & 1) != 0;
    let cs_db = ((cs_desc >> 54) & 1) != 0;
    if !cs_s || (cs_type & 0x8) == 0 || !cs_l || cs_db || cs_dpl > ctx.cpl {
        return Err(X86Exception::general_protection(fault_va, cs_err));
    }
    if !cs_p {
        return Err(X86Exception::segment_not_present(fault_va, cs_err));
    }
    let conforming = (cs_type & 0x4) != 0;
    let new_cpl = if conforming { ctx.cpl } else { cs_dpl };
    new_cs.selector = (target_cs_sel & 0xfffc) | u16::from(new_cpl);

    let old_cpl = ctx.cpl;
    let old_rsp = ctx.gpr[reg::RSP];
    let old_ss = ctx.ss.selector;
    let old_cs = ctx.cs.selector;
    let old_rflags = (ctx.rflags & 0x003c_7fd7) | 0x2;

    let raw_target_rsp = if ist != 0 {
        read_tss_stack_ptr(ctx, mem, fault_va, 36 + (u64::from(ist) - 1) * 8, ext)?
    } else if new_cpl < old_cpl {
        read_tss_stack_ptr(ctx, mem, fault_va, 4 + u64::from(new_cpl) * 8, ext)?
    } else {
        old_rsp
    };

    // SDM Vol. 3A §6.14.2: IA-32e mode aligns RSP to a 16-byte boundary before pushing the frame.
    let aligned_rsp = raw_target_rsp & !0xf;
    let frame_len = if error_code.is_some() { 48usize } else { 40usize };
    let new_rsp = aligned_rsp.wrapping_sub(frame_len as u64);
    if !is_canonical_va(new_rsp) || !is_canonical_va(new_rsp.wrapping_add((frame_len - 1) as u64)) {
        return Err(X86Exception::stack_segment_fault(fault_va, ext));
    }

    let mut frame_buf = [0u8; 48];
    let mut cursor = 0usize;
    if let Some(ec) = error_code {
        frame_buf[0..8].copy_from_slice(&u64::from(ec).to_le_bytes());
        cursor = 8;
    }
    frame_buf[cursor..cursor + 8].copy_from_slice(&saved_rip.to_le_bytes());
    frame_buf[cursor + 8..cursor + 16].copy_from_slice(&u64::from(old_cs).to_le_bytes());
    frame_buf[cursor + 16..cursor + 24].copy_from_slice(&old_rflags.to_le_bytes());
    frame_buf[cursor + 24..cursor + 32].copy_from_slice(&old_rsp.to_le_bytes());
    frame_buf[cursor + 32..cursor + 40].copy_from_slice(&u64::from(old_ss).to_le_bytes());

    // Set CR2 before memory push if delivering a #PF, while preserving secondary #PF updates on failure.
    if let Some(cr2) = cr2_update {
        ctx.cr2 = cr2;
    }
    write_system_bytes(ctx, mem, new_rsp, &frame_buf[..frame_len])
        .map_err(|pf| X86Exception::page_fault(fault_va, pf.error_code, pf.cr2))?;

    ctx.cs = new_cs;
    if new_cpl < old_cpl {
        // SDM Vol. 3A §6.14.2: Inter-privilege interrupt/exception loads NULL SS selector with RPL = new_cpl.
        ctx.ss = SoftSegment {
            selector: u16::from(new_cpl),
            base: 0,
            limit: 0,
            ar: SoftSegment::UNUSABLE_BIT,
        };
    }
    ctx.gpr[reg::RSP] = new_rsp;
    ctx.rflags &= !(RFLAGS_TF | RFLAGS_NT | RFLAGS_RF | RFLAGS_VM);
    if gate_type == 0x0e {
        ctx.rflags &= !RFLAGS_IF;
    }
    ctx.set_cpl(new_cpl);
    ctx.halted = false;
    ctx.rip = entry_rip;
    Ok(())
}

fn read_tss_stack_ptr<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    fault_va: u64,
    tss_offset: u64,
    ext: u32,
) -> Result<u64, X86Exception> {
    let tr_err = u32::from(ctx.tr.selector & 0xfffc) | ext;
    if ctx.tr.is_unusable() || tss_offset.saturating_add(7) > u64::from(ctx.tr.limit) {
        return Err(X86Exception::invalid_tss(fault_va, tr_err));
    }
    let va = ctx.tr.base.wrapping_add(tss_offset);
    if !is_canonical_va(va) || !is_canonical_va(va.wrapping_add(7)) {
        return Err(X86Exception::invalid_tss(fault_va, tr_err));
    }
    let mut b = [0u8; 8];
    read_system_bytes(ctx, mem, va, &mut b)
        .map_err(|pf| X86Exception::page_fault(fault_va, pf.error_code, pf.cr2))?;
    Ok(u64::from_le_bytes(b))
}
