//! Level 0 `SoftCpu` execution engine and executable code-buffer management.

use std::ptr::NonNull;

use iced_x86::Instruction;

use crate::block::{BlockExit, BlockFetchFault, PlannedBlock, plan_block_from_memory};
use crate::cflow::{compute_effective_va, resolve_cflow};
use crate::context::{
    EXIT_REASON_CFLOW, EXIT_REASON_CONTINUE, EXIT_REASON_SENSITIVE, EXIT_REASON_SYSCALL,
    GUEST_MXCSR_MASK, SoftCpuContext, X86Exception, X86ExceptionVector, reg,
};
use crate::decode::SensitiveOp;
use crate::emit::{EmitError, emit_block};
use crate::mmu::{
    SoftAccessKind, SoftMmuMemory, is_canonical_va, read_guest_bytes, write_guest_bytes,
};

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
        self.ctx.pending_exception = None;
        self.ctx.reset_bounce();
        self.ctx.sync_tlb_tag_bits();

        let (rip, max_i, max_s) = (self.ctx.rip, self.max_block_insns, self.max_block_span);
        match plan_block_from_memory(rip, max_i, max_s, &mut self.ctx, mem) {
            Ok(b) => self.execute_planned_block(&b, mem),
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
        let emitted = emit_block(planned)?;
        let exec_addr = self
            .jit
            .publish(&emitted.code)
            .ok_or_else(|| EmitError::EncodeFailed {
                va: planned.start,
                detail: "translated block exceeds JIT buffer capacity".to_string(),
            })?;

        // SAFETY: entry belongs to this CPU's freshly published translated block.
        let raw_exit = unsafe { self.ctx.execute(mem, exec_addr, planned) };

        self.ctx.fxsave.0[28..32].copy_from_slice(&GUEST_MXCSR_MASK.to_le_bytes());
        self.ctx.sync_tlb_tag_bits();
        if let Some(exc) = self.ctx.pending_exception.take() {
            return Ok(SoftCpuExit::Exception(exc));
        }

        match raw_exit {
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
            SensitiveOp::Rdpkru
            | SensitiveOp::Wrpkru
            | SensitiveOp::Rdtscp
            | SensitiveOp::Xgetbv => {
                // These extensions are absent from this layer's CPUID/CR4 view.
                self.raise(X86Exception::invalid_opcode(va))
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
/// no x87 or FXSAVE/XSAVE image helpers yet; no AVX, monitor, INVPCID, XSAVES,
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
            0,
            (1 << 4) | (1 << 8) | (1 << 15) | (1 << 25) | (1 << 26),
        ),
        (0x0d, 0) => (0, 0, 0, 0),
        (0x0d, 1) => (0, 0, 0, 0),
        (0x8000_0000, _) => (0x8000_0008, 0, 0, 0),
        (0x8000_0001, _) => (0, 0, 1, (1 << 11) | (1 << 20) | (1 << 29)),
        (0x8000_0008, _) => (48 | (48 << 8), 0, 0, 0),
        _ => (0, 0, 0, 0),
    }
}
