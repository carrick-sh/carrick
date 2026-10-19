//! Level 0 `SoftCpu` execution engine and executable code-buffer management.

use std::ptr::NonNull;

use carrick_softmmu::VcpuShootdown;
use iced_x86::{Instruction, Mnemonic};

use crate::block::{BlockExit, BlockFetchFault, PlannedBlock, plan_block_from_memory};
use crate::cflow::{compute_effective_va, resolve_cflow};
use crate::context::{
    EXIT_REASON_CFLOW, EXIT_REASON_CONTINUE, EXIT_REASON_RESTART, EXIT_REASON_SENSITIVE,
    EXIT_REASON_SYSCALL, GUEST_MXCSR_MASK, SoftCpuContext, X86Exception, X86ExceptionVector, reg,
};
use crate::decode::SensitiveOp;
use crate::emit::{EmitError, emit_block};
use crate::mmu::{
    SoftAccessKind, SoftMmuMemory, is_canonical_va, read_guest_bytes, write_guest_bytes,
};

#[cfg(test)]
thread_local! {
    pub(crate) static JIT_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static FAIL_SMALL_JIT: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inject_small_jit_failure(capacity: usize, publish: bool) -> bool {
    capacity == 4096
        && FAIL_SMALL_JIT.with(|fault| {
            if fault.get() == Some(publish) {
                fault.set(None);
                true
            } else {
                false
            }
        })
}

const DEFAULT_JIT_CAPACITY: usize = 256 * 1024;

/// Outcome of executing one basic block on [`SoftCpu`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftCpuExit {
    Continue {
        next_rip: u64,
    },
    Syscall {
        rip: u64,
        next_rip: u64,
    },
    Sensitive {
        rip: u64,
        next_rip: u64,
        op: SensitiveOp,
    },
    Exception(X86Exception),
    SoftwareInterrupt {
        vector: u8,
        rip: u64,
        next_rip: u64,
    },
}

/// Host executable scratch buffer for translated blocks (never maps guest VAs).
pub struct JitCodeBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
    cursor: usize,
    executable: bool,
}

// SAFETY: `JitCodeBuffer` owns a private `mmap` allocation not shared across threads without sync.
unsafe impl Send for JitCodeBuffer {}

impl JitCodeBuffer {
    /// Allocate a host executable scratch buffer of `capacity` bytes.
    pub fn new(capacity: usize) -> Option<Self> {
        let cap = capacity.max(4096).checked_add(4095)? & !4095;
        #[cfg(test)]
        {
            JIT_ALLOCATIONS.with(|count| count.set(count.get() + 1));
            if inject_small_jit_failure(cap, false) {
                return None;
            }
        }
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANON;
        // SAFETY: anonymous private host allocation for translated block bytes only.
        let raw = unsafe { libc::mmap(std::ptr::null_mut(), cap, prot, flags, -1, 0) };
        if raw == libc::MAP_FAILED {
            return None;
        }
        Some(Self {
            ptr: NonNull::new(raw.cast::<u8>())?,
            capacity: cap,
            cursor: 0,
            executable: false,
        })
    }

    /// Publish under W^X, returning an RX address only after mprotect succeeds.
    /// The owner must ensure no previously published code is executing while
    /// this exclusive publication changes the mapping back to RW.
    pub fn publish(&mut self, bytes: &[u8]) -> Option<u64> {
        #[cfg(test)]
        if inject_small_jit_failure(self.capacity, true) {
            return None;
        }
        if bytes.is_empty() || bytes.len() > self.capacity {
            return None;
        }
        if self.executable {
            // SAFETY: the exclusive owner holds the entire live mmap allocation.
            if unsafe {
                libc::mprotect(
                    self.ptr.as_ptr().cast(),
                    self.capacity,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
            {
                return None;
            }
            self.executable = false;
        }
        if self.cursor.checked_add(bytes.len())? > self.capacity {
            self.cursor = 0;
        }
        // SAFETY: `self.cursor + bytes.len() <= self.capacity`.
        let dst = unsafe { self.ptr.as_ptr().add(self.cursor) };
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        self.cursor += (bytes.len() + 15) & !15;
        // SAFETY: publication is complete and no mutable pointer escapes this owner.
        if unsafe {
            libc::mprotect(
                self.ptr.as_ptr().cast(),
                self.capacity,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            return None;
        }
        self.executable = true;
        Some(dst as u64)
    }
}

impl Drop for JitCodeBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` and `self.capacity` came from `libc::mmap` in `Self::new`.
        unsafe {
            let _ = libc::munmap(self.ptr.as_ptr().cast(), self.capacity);
        }
    }
}

/// Level 0 x86_64 soft vCPU.
///
/// Raw plans contain native bytes and are not an externally callable execution API.
/// ```compile_fail
/// use carrick_softcpu_x86::{SoftCpu, SoftMmuMemory};
/// fn raw_entry<M: SoftMmuMemory>() { let _ = SoftCpu::execute_planned_block::<M>; }
/// ```
/// The owned context cannot be replaced by a caller; use the typed borrows.
/// ```compile_fail
/// use carrick_softcpu_x86::SoftCpu;
/// fn replace_context(cpu: &mut SoftCpu) { cpu.ctx = Default::default(); }
/// ```
pub struct SoftCpu {
    ctx: Box<SoftCpuContext>,
    jit: JitCodeBuffer,
    pub max_block_insns: usize,
    pub max_block_span: usize,
    shootdown: Option<VcpuShootdown>,
}

impl SoftCpu {
    /// Create a new [`SoftCpu`] initialized for 64-bit user mode (`CPL = 3`).
    #[must_use]
    pub fn new() -> Option<Self> {
        Some(Self {
            ctx: Box::new(SoftCpuContext::new()),
            jit: JitCodeBuffer::new(DEFAULT_JIT_CAPACITY)?,
            max_block_insns: 64,
            max_block_span: 4096,
            shootdown: None,
        })
    }

    /// Borrow architectural state; gateway addresses and memory bindings stay private.
    pub fn context(&self) -> &SoftCpuContext {
        &self.ctx
    }

    /// Mutate architectural state between blocks.
    pub fn context_mut(&mut self) -> &mut SoftCpuContext {
        &mut self.ctx
    }

    /// Bind this CPU's local TLB to its extent-table retirement authority.
    pub fn bind_shootdown(&mut self, registration: VcpuShootdown) {
        self.shootdown = Some(registration);
    }

    /// Publish that this CPU is parked and cannot look up a translation until resumed.
    pub fn leave_parked(&self) {
        if let Some(registration) = &self.shootdown {
            registration.leave_parked();
        }
    }

    fn raise(&mut self, exc: X86Exception) -> Result<SoftCpuExit, EmitError> {
        if let Some(cr2) = exc.cr2 {
            self.ctx.cr2 = cr2;
        }
        self.ctx.rip = exc.rip;
        self.ctx.pending_exception = Some(exc);
        Ok(SoftCpuExit::Exception(exc))
    }

    /// Plan, emit, and execute one basic block starting at `self.ctx.rip` over `mem`.
    pub fn step_block<M: SoftMmuMemory>(&mut self, mem: &mut M) -> Result<SoftCpuExit, EmitError> {
        if let Some(registration) = &self.shootdown {
            registration.enter_running(&mut self.ctx.tlb);
        }
        let result = self.step_block_running(mem);
        if let Some(registration) = &self.shootdown {
            registration.synchronize(&mut self.ctx.tlb);
            registration.leave_idle();
        }
        result
    }

    fn step_block_running<M: SoftMmuMemory>(
        &mut self,
        mem: &mut M,
    ) -> Result<SoftCpuExit, EmitError> {
        self.ctx.pending_exception = None;
        crate::context::prepare_gateway(self.ctx.rip)?;
        self.ctx.reset_bounce();
        self.ctx.sync_tlb_tag_bits();

        let (rip, max_i, max_s) = (self.ctx.rip, self.max_block_insns, self.max_block_span);
        match plan_block_from_memory(rip, max_i, max_s, &mut self.ctx, mem) {
            Ok(b) => {
                let single_step = self.ctx.rflags & (1 << 8) != 0;
                let result = self.execute_planned_block(&b, mem)?;
                if single_step && matches!(result, SoftCpuExit::Continue { .. }) {
                    return self.raise(X86Exception::new(
                        X86ExceptionVector::Debug,
                        self.ctx.rip,
                        None,
                        None,
                    ));
                }
                Ok(result)
            }
            Err(BlockFetchFault::GeneralProtection { rip, error_code }) => {
                self.raise(X86Exception::general_protection(rip, error_code))
            }
            Err(BlockFetchFault::PageFault { rip, fault }) => {
                self.raise(X86Exception::page_fault(rip, fault.error_code, fault.cr2))
            }
        }
    }

    /// Execute only plans produced by this crate: raw bytes must agree with decoded metadata.
    pub(crate) fn execute_planned_block<M: SoftMmuMemory>(
        &mut self,
        planned: &PlannedBlock,
        mem: &mut M,
    ) -> Result<SoftCpuExit, EmitError> {
        // Secure all host executable resources before any guest instruction runs.
        crate::context::prepare_gateway(planned.start)?;
        self.ctx.prepare_block(planned)?;
        let emitted = emit_block(planned)?;
        let exec_addr = self
            .jit
            .publish(&emitted.code)
            .ok_or_else(|| EmitError::EncodeFailed {
                va: planned.start,
                detail: "translated block exceeds JIT buffer capacity".to_string(),
            })?;

        // SAFETY: entry belongs to this CPU's freshly published translated block.
        let raw_exit = unsafe { self.ctx.execute(mem, exec_addr, planned) }?;

        self.ctx.fxsave.0[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
        self.ctx.sync_tlb_tag_bits();
        if let Some(exc) = self.ctx.pending_exception.take() {
            return Ok(SoftCpuExit::Exception(exc));
        }

        match raw_exit {
            EXIT_REASON_RESTART => Ok(SoftCpuExit::Continue {
                next_rip: self.ctx.rip,
            }),
            EXIT_REASON_CONTINUE => {
                if let BlockExit::Continue { target } = planned.exit {
                    self.ctx.rip = target;
                }
                Ok(SoftCpuExit::Continue {
                    next_rip: self.ctx.rip,
                })
            }
            EXIT_REASON_SYSCALL => match planned.exit {
                BlockExit::Syscall { va, resume, .. } => {
                    self.ctx.rip = resume;
                    Ok(SoftCpuExit::Syscall {
                        rip: va,
                        next_rip: resume,
                    })
                }
                _ => Ok(SoftCpuExit::Syscall {
                    rip: self.ctx.exit_insn_va,
                    next_rip: self.ctx.rip,
                }),
            },
            EXIT_REASON_CFLOW => match &planned.exit {
                BlockExit::ControlFlow { va, kind, raw, .. } => {
                    match resolve_cflow(raw, *va, *kind, &mut self.ctx, mem) {
                        Ok(target) => Ok(SoftCpuExit::Continue { next_rip: target }),
                        Err(exc) => self.raise(exc),
                    }
                }
                _ => Ok(SoftCpuExit::Continue {
                    next_rip: self.ctx.rip,
                }),
            },
            EXIT_REASON_SENSITIVE => match &planned.exit {
                BlockExit::Sensitive {
                    va,
                    resume,
                    op,
                    raw,
                    ..
                } => self.handle_sensitive_exit(*va, *resume, *op, raw, mem),
                _ => Ok(SoftCpuExit::Continue {
                    next_rip: self.ctx.rip,
                }),
            },
            _ => self.raise(X86Exception::invalid_opcode(self.ctx.exit_insn_va)),
        }
    }

    fn handle_sensitive_exit<M: SoftMmuMemory>(
        &mut self,
        va: u64,
        resume: u64,
        op: SensitiveOp,
        raw: &Instruction,
        mem: &mut M,
    ) -> Result<SoftCpuExit, EmitError> {
        // SDM CLAC/STAC specify #UD at CPL>0, unlike ordinary privileged ops.
        if self.ctx.cpl != 0 && matches!(op, SensitiveOp::Clac | SensitiveOp::Stac) {
            return self.raise(X86Exception::invalid_opcode(va));
        }
        if self.ctx.cpl != 0
            && self.ctx.cr4 & (1 << 11) != 0
            && matches!(
                op,
                SensitiveOp::Sgdt
                    | SensitiveOp::Sidt
                    | SensitiveOp::Sldt
                    | SensitiveOp::Str
                    | SensitiveOp::Smsw
            )
        {
            return self.raise(X86Exception::general_protection(va, 0));
        }
        if op.is_privileged() {
            if self.ctx.cpl != 0 {
                return self.raise(X86Exception::general_protection(va, 0));
            }
            self.ctx.rip = va;
            return Ok(SoftCpuExit::Sensitive {
                rip: va,
                next_rip: resume,
                op,
            });
        }

        match op {
            SensitiveOp::Icebp => self.raise(X86Exception::new(
                X86ExceptionVector::Debug,
                resume,
                None,
                None,
            )),
            SensitiveOp::Interrupt { vector } => {
                self.ctx.rip = resume;
                if raw.mnemonic() == iced_x86::Mnemonic::Int3 {
                    return self.raise(X86Exception::new(
                        X86ExceptionVector::Breakpoint,
                        resume,
                        None,
                        None,
                    ));
                }
                Ok(SoftCpuExit::SoftwareInterrupt {
                    vector,
                    rip: va,
                    next_rip: resume,
                })
            }
            SensitiveOp::Ldmxcsr | SensitiveOp::Stmxcsr => {
                let ea = compute_effective_va(raw, &self.ctx);
                if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add(3)) {
                    return self.raise(X86Exception::general_protection(va, 0));
                }
                if let Err(exc) = crate::mmu::check_guest_alignment(
                    &mut self.ctx,
                    mem,
                    ea,
                    4,
                    4,
                    if op == SensitiveOp::Stmxcsr {
                        SoftAccessKind::Write
                    } else {
                        SoftAccessKind::Read
                    },
                    va,
                ) {
                    return self.raise(exc);
                }
                let mut bytes = [0; 4];
                let result = if op == SensitiveOp::Stmxcsr {
                    bytes.copy_from_slice(&self.ctx.fxsave.0[24..28]);
                    write_guest_bytes(&mut self.ctx, mem, ea, &bytes)
                } else {
                    read_guest_bytes(&mut self.ctx, mem, ea, &mut bytes, SoftAccessKind::Read)
                };
                if let Err(pf) = result {
                    return self.raise(X86Exception::page_fault(va, pf.error_code, pf.cr2));
                }
                if op == SensitiveOp::Ldmxcsr {
                    if u32::from_le_bytes(bytes) & !GUEST_MXCSR_MASK != 0 {
                        return self.raise(X86Exception::general_protection(va, 0));
                    }
                    self.ctx.fxsave.0[24..28].copy_from_slice(&bytes);
                }
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Rdssp { .. } => {
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Rdpkru | SensitiveOp::Wrpkru | SensitiveOp::Rdtscp => {
                // These extensions are absent from this layer's CPUID/CR4 view.
                self.raise(X86Exception::invalid_opcode(va))
            }
            SensitiveOp::Xgetbv => {
                if self.ctx.gpr[reg::RCX] as u32 != 0 {
                    return self.raise(X86Exception::general_protection(va, 0));
                }
                self.ctx.gpr[reg::RAX] = self.ctx.xcr0 & 0xffff_ffff;
                self.ctx.gpr[reg::RDX] = self.ctx.xcr0 >> 32;
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Rdtsc => {
                // SAFETY: TSC is a baseline x86_64 instruction advertised by CPUID.
                let tsc = unsafe { core::arch::x86_64::_rdtsc() };
                self.ctx.gpr[reg::RAX] = tsc & 0xffff_ffff;
                self.ctx.gpr[reg::RDX] = tsc >> 32;
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Cpuid => {
                let (a, b, c, d) = emulate_pinned_cpuid(
                    self.ctx.gpr[reg::RAX] as u32,
                    self.ctx.gpr[reg::RCX] as u32,
                );
                self.ctx.gpr[reg::RAX] = u64::from(a);
                self.ctx.gpr[reg::RBX] = u64::from(b);
                self.ctx.gpr[reg::RCX] = u64::from(c);
                self.ctx.gpr[reg::RDX] = u64::from(d);
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Fnsave
            | SensitiveOp::Fnstenv
            | SensitiveOp::Fldenv
            | SensitiveOp::Frstor
            | SensitiveOp::Fwait => {
                if let Err(exc) = emulate_legacy_x87(&mut self.ctx, mem, raw, op, va) {
                    return self.raise(exc);
                }
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Fxsave
            | SensitiveOp::Xsave
            | SensitiveOp::Xsaveopt
            | SensitiveOp::Xsavec
            | SensitiveOp::Fxrstor
            | SensitiveOp::Xrstor => {
                if let Err(exc) = emulate_xstate(&mut self.ctx, mem, raw, op, va) {
                    return self.raise(exc);
                }
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            _ => {
                self.ctx.rip = va;
                Ok(SoftCpuExit::Sensitive {
                    rip: va,
                    next_rip: resume,
                    op,
                })
            }
        }
    }
}

/// Fixed Level 0 view, independent of the host. Baseline integer/SSE2 state,
/// emulated XSAVE legacy components only; no AVX, monitor, INVPCID, XSAVES,
/// RDPID, CET, or other host extensions. Native admission remains a separate
/// instruction-level allowlist: Level 0 is deliberately a partial ISA.
/// CR0.EM=0 permits the admitted SSE subset; CPUID.FPU=0 promises no x87.
fn emulate_pinned_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    match (leaf, subleaf) {
        (0, _) => (
            0x0d,
            u32::from_le_bytes(*b"Genu"),
            u32::from_le_bytes(*b"ntel"),
            u32::from_le_bytes(*b"ineI"),
        ),
        (1, _) => (
            0x0000_0663,
            0,
            (1 << 26) | (1 << 27),
            (1 << 4) | (1 << 8) | (1 << 15) | (1 << 24) | (1 << 25) | (1 << 26),
        ),
        (0x0d, 0) => (3, 576, 576, 0),
        (0x0d, 1) => (3, 576, 0, 0), // XSAVEOPT and XSAVEC, no supervisor state
        (0x8000_0000, _) => (0x8000_0008, 0, 0, 0),
        (0x8000_0001, _) => (0, 0, 1, (1 << 11) | (1 << 20) | (1 << 29)),
        (0x8000_0008, _) => (48 | (48 << 8), 0, 0, 0),
        _ => (0, 0, 0, 0),
    }
}

// Intel SDM Vol. 1, chapter 13: only requested legacy components participate.
// No YMM/supervisor component is enabled or exposed by this CPU.
fn emulate_xstate<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    insn: &Instruction,
    op: SensitiveOp,
    ip: u64,
) -> Result<(), X86Exception> {
    let format64 = matches!(
        insn.mnemonic(),
        Mnemonic::Fxsave64
            | Mnemonic::Fxrstor64
            | Mnemonic::Xsave64
            | Mnemonic::Xsaveopt64
            | Mnemonic::Xsavec64
            | Mnemonic::Xrstor64
    );
    let ext = !matches!(op, SensitiveOp::Fxsave | SensitiveOp::Fxrstor);
    let save = !matches!(op, SensitiveOp::Fxrstor | SensitiveOp::Xrstor);
    let compact = op == SensitiveOp::Xsavec;
    let ea = compute_effective_va(insn, ctx);
    if ea & (if ext { 63 } else { 15 }) != 0
        || !is_canonical_va(ea)
        || !is_canonical_va(ea.wrapping_add(if ext { 575 } else { 511 }))
    {
        return Err(X86Exception::general_protection(ip, 0));
    }
    let request = if ext {
        ((ctx.gpr[reg::RAX] as u32 as u64) | ((ctx.gpr[reg::RDX] as u32 as u64) << 32))
            & ctx.xcr0
            & 3
    } else {
        3
    };
    let mut area = [0u8; 576];
    let mut ranges = Vec::new();
    let fault = |pf: crate::mmu::SoftPageFault| X86Exception::page_fault(ip, pf.error_code, pf.cr2);
    let mut state = request;
    let mut xcomp = 0;
    if ext {
        if !save || !compact {
            read_guest_bytes(
                ctx,
                mem,
                ea.wrapping_add(512),
                &mut area[512..576],
                // XSAVE/XSAVEOPT update XSTATE_BV as part of a write access.
                if save {
                    SoftAccessKind::Write
                } else {
                    SoftAccessKind::Read
                },
            )
            .map_err(fault)?;
        }
        let header = u64::from_le_bytes(
            area[512..520]
                .try_into()
                .map_err(|_| X86Exception::invalid_opcode(ip))?,
        );
        xcomp = u64::from_le_bytes(
            area[520..528]
                .try_into()
                .map_err(|_| X86Exception::invalid_opcode(ip))?,
        );
        if !save {
            if header & !3 != 0
                || (xcomp != 0
                    && (xcomp & (1 << 63) == 0
                        || xcomp & !((1 << 63) | 3) != 0
                        || header & !xcomp != 0))
                // SDM Vol. 1 13.8.1 checks header bytes 8..24 for the
                // standard form; 13.8.2 checks bytes 16..64 when compacted.
                || area[528..if xcomp == 0 { 536 } else { 576 }].iter().any(|&b| b != 0)
            {
                return Err(X86Exception::general_protection(ip, 0));
            }
            state = header;
        } else {
            let bits = if compact {
                request
            } else {
                (header & !request) | request
            };
            area[512..520].copy_from_slice(&bits.to_le_bytes());
            if compact {
                area[520..528].copy_from_slice(&((1u64 << 63) | request).to_le_bytes());
                ranges.push((512, 576));
            } else {
                ranges.push((512, 520));
            }
        }
    }
    if !ext {
        ranges.push((0, if save { 464 } else { 512 }));
    } else {
        if request & 1 != 0 && (save || state & 1 != 0) {
            ranges.extend_from_slice(&[(0, 24), (32, 160)]);
        }
        if request & 2 != 0 {
            // Standard XRSTOR loads MXCSR even when SSE is in initial state.
            if save || xcomp == 0 || state & 2 != 0 {
                ranges.push((24, 32));
            }
            if save || state & 2 != 0 {
                ranges.push((160, 416));
            }
        }
    }
    if save {
        let mut legacy = ctx.fxsave.clone();
        if !format64 {
            legacy.0[12..16].fill(0);
            legacy.0[12..14].copy_from_slice(&ctx.x87_code_selector.to_le_bytes());
            legacy.0[20..24].fill(0);
            legacy.0[20..22].copy_from_slice(&ctx.x87_data_selector.to_le_bytes());
        }
        if !ext {
            // Validate the nominal operand, but never overwrite software bytes
            // 464..512 (Intel SDM, FXSAVE layout).
            for off in [0, 511] {
                crate::mmu::translate_va(ctx, mem, ea.wrapping_add(off), SoftAccessKind::Write)
                    .map_err(fault)?;
            }
        }
        for &(start, end) in &ranges {
            if start < 512 {
                area[start..end].copy_from_slice(&legacy.0[start..end]);
            }
            // Validate every touched page before publishing any component.
            for off in [start, end - 1] {
                let va = ea.wrapping_add(off as u64);
                if !is_canonical_va(va) {
                    return Err(X86Exception::general_protection(ip, 0));
                }
                crate::mmu::translate_va(ctx, mem, va, SoftAccessKind::Write).map_err(fault)?;
            }
        }
        for (start, end) in ranges {
            write_guest_bytes(ctx, mem, ea.wrapping_add(start as u64), &area[start..end])
                .map_err(fault)?;
        }
    } else {
        for &(start, end) in &ranges {
            let va = ea.wrapping_add(start as u64);
            if !is_canonical_va(va) || !is_canonical_va(ea.wrapping_add((end - 1) as u64)) {
                return Err(X86Exception::general_protection(ip, 0));
            }
            read_guest_bytes(ctx, mem, va, &mut area[start..end], SoftAccessKind::Read)
                .map_err(fault)?;
        }
        if request & 2 != 0
            && u32::from_le_bytes([area[24], area[25], area[26], area[27]]) & !GUEST_MXCSR_MASK != 0
        {
            return Err(X86Exception::general_protection(ip, 0));
        }
        let mut restored = ctx.fxsave.clone();
        if ext {
            let init = crate::context::FxsaveArea::default();
            if request & 1 != 0 && state & 1 == 0 {
                restored.0[..24].copy_from_slice(&init.0[..24]);
                restored.0[32..160].copy_from_slice(&init.0[32..160]);
            }
            if request & 2 != 0 && state & 2 == 0 {
                restored.0[160..416].fill(0);
                if xcomp != 0 {
                    restored.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
                }
            }
        }
        for (start, end) in ranges {
            restored.0[start..end].copy_from_slice(&area[start..end]);
        }
        if request & 1 != 0 {
            if ext && state & 1 == 0 {
                ctx.x87_code_selector = 0;
                ctx.x87_data_selector = 0;
            } else if !format64 {
                ctx.x87_code_selector = u16::from_le_bytes([area[12], area[13]]);
                ctx.x87_data_selector = u16::from_le_bytes([area[20], area[21]]);
                restored.0[12..16].fill(0);
                restored.0[20..24].fill(0);
            }
        }
        restored.0[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
        ctx.fxsave = restored;
    }
    Ok(())
}

/// Intel SDM Vol. 1, x87 environment and FSAVE/FXSAVE formats. The largest
/// legacy image is 108 bytes; no legacy state instruction executes on host RAM.
fn emulate_legacy_x87<M: SoftMmuMemory>(
    ctx: &mut SoftCpuContext,
    mem: &mut M,
    insn: &Instruction,
    op: SensitiveOp,
    ip: u64,
) -> Result<(), X86Exception> {
    if op == SensitiveOp::Fwait {
        let cw = u16::from_le_bytes([ctx.fxsave.0[0], ctx.fxsave.0[1]]);
        let sw = u16::from_le_bytes([ctx.fxsave.0[2], ctx.fxsave.0[3]]);
        return if sw & !cw & 0x3f != 0 {
            Err(X86Exception::new(
                X86ExceptionVector::X87FloatingPoint,
                ip,
                None,
                None,
            ))
        } else {
            Ok(())
        };
    }
    let size = insn.memory_size().size();
    let full = matches!(op, SensitiveOp::Fnsave | SensitiveOp::Frstor);
    let env_len = match (size, full) {
        (108, true) | (28, false) => 28,
        (94, true) | (14, false) => 14,
        _ => return Err(X86Exception::invalid_opcode(ip)),
    };
    let ea = compute_effective_va(insn, ctx);
    if !is_canonical_va(ea) || !is_canonical_va(ea.wrapping_add((size - 1) as u64)) {
        return Err(X86Exception::general_protection(ip, 0));
    }
    let save = matches!(op, SensitiveOp::Fnsave | SensitiveOp::Fnstenv);
    crate::mmu::check_guest_alignment(
        ctx,
        mem,
        ea,
        size,
        if env_len == 28 { 4 } else { 2 },
        if save {
            SoftAccessKind::Write
        } else {
            SoftAccessKind::Read
        },
        ip,
    )?;
    let mut image = [0u8; 108];
    let fault = |pf: crate::mmu::SoftPageFault| X86Exception::page_fault(ip, pf.error_code, pf.cr2);
    let (cw, sw, tag, fip, fcs, fdp, fds) = if env_len == 28 {
        (0, 4, 8, 12, 16, 20, 24)
    } else {
        (0, 2, 4, 6, 8, 10, 12)
    };
    if save {
        image[cw..cw + 2].copy_from_slice(&ctx.fxsave.0[..2]);
        image[sw..sw + 2].copy_from_slice(&ctx.fxsave.0[2..4]);
        let top = (u16::from_le_bytes([ctx.fxsave.0[2], ctx.fxsave.0[3]]) >> 11) as usize & 7;
        let mut tags = 0u16;
        for physical in 0..8 {
            let logical = (physical + 8 - top) & 7;
            let off = 32 + logical * 16;
            let significand = u64::from_le_bytes(
                ctx.fxsave.0[off..off + 8]
                    .try_into()
                    .map_err(|_| X86Exception::invalid_opcode(ip))?,
            );
            let exp = u16::from_le_bytes([ctx.fxsave.0[off + 8], ctx.fxsave.0[off + 9]]) & 0x7fff;
            let kind = if ctx.fxsave.0[4] & (1 << physical) == 0 {
                3
            } else if exp == 0 && significand == 0 {
                1
            } else if exp == 0 || exp == 0x7fff || significand >> 63 == 0 {
                2
            } else {
                0
            };
            tags |= kind << (physical * 2);
            if full {
                image[env_len + logical * 10..env_len + logical * 10 + 10]
                    .copy_from_slice(&ctx.fxsave.0[off..off + 10]);
            }
        }
        image[tag..tag + 2].copy_from_slice(&tags.to_le_bytes());
        let ptr_width = if env_len == 28 { 4 } else { 2 };
        image[fip..fip + ptr_width].copy_from_slice(&ctx.fxsave.0[8..8 + ptr_width]);
        image[fdp..fdp + ptr_width].copy_from_slice(&ctx.fxsave.0[16..16 + ptr_width]);
        image[fcs..fcs + 2].copy_from_slice(&ctx.x87_code_selector.to_le_bytes());
        image[fds..fds + 2].copy_from_slice(&ctx.x87_data_selector.to_le_bytes());
        if env_len == 28 {
            image[18..20].copy_from_slice(&ctx.fxsave.0[6..8]);
            for off in [2, 6, 10, 26] {
                image[off..off + 2].fill(0xff);
            }
        }
        write_guest_bytes(ctx, mem, ea, &image[..size]).map_err(fault)?;
        if full {
            // FNSAVE initializes x87 only; SSE state is unaffected.
            let initial = crate::context::FxsaveArea::default();
            ctx.fxsave.0[..24].copy_from_slice(&initial.0[..24]);
            ctx.fxsave.0[32..160].copy_from_slice(&initial.0[32..160]);
            ctx.x87_code_selector = 0;
            ctx.x87_data_selector = 0;
        } else {
            ctx.fxsave.0[0] |= 0x3f;
        }
    } else {
        read_guest_bytes(ctx, mem, ea, &mut image[..size], SoftAccessKind::Read).map_err(fault)?;
        let mut restored = ctx.fxsave.clone();
        restored.0[..2].copy_from_slice(&image[cw..cw + 2]);
        restored.0[2..4].copy_from_slice(&image[sw..sw + 2]);
        let tags = u16::from_le_bytes([image[tag], image[tag + 1]]);
        restored.0[4] = (0..8).fold(0u8, |v, i| {
            v | if (tags >> (i * 2)) & 3 != 3 {
                1 << i
            } else {
                0
            }
        });
        let ptr_width = if env_len == 28 { 4 } else { 2 };
        restored.0[8..24].fill(0);
        restored.0[8..8 + ptr_width].copy_from_slice(&image[fip..fip + ptr_width]);
        restored.0[16..16 + ptr_width].copy_from_slice(&image[fdp..fdp + ptr_width]);
        if env_len == 28 {
            restored.0[6..8].copy_from_slice(&image[18..20]);
        }
        if full {
            for i in 0..8 {
                restored.0[32 + i * 16..42 + i * 16]
                    .copy_from_slice(&image[env_len + i * 10..env_len + i * 10 + 10]);
            }
        }
        ctx.x87_code_selector = u16::from_le_bytes([image[fcs], image[fcs + 1]]);
        ctx.x87_data_selector = u16::from_le_bytes([image[fds], image[fds + 1]]);
        restored.0[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
        ctx.fxsave = restored;
    }
    Ok(())
}
