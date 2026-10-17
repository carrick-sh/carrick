//! Level 0 `SoftCpu` execution engine and executable code-buffer management.

use std::ptr::NonNull;

use iced_x86::Instruction;

use crate::block::{BlockExit, BlockFetchFault, PlannedBlock, plan_block_from_memory};
use crate::cflow::{compute_effective_va, resolve_cflow};
use crate::context::{
    EXIT_REASON_CFLOW, EXIT_REASON_CONTINUE, EXIT_REASON_SENSITIVE, EXIT_REASON_SYSCALL,
    SoftCpuContext, X86Exception, reg, softcpu_enter_translated, translate_for_mem,
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
}

/// Host executable scratch buffer for translated blocks (never maps guest VAs).
pub struct JitCodeBuffer {
    ptr: NonNull<u8>,
    capacity: usize,
    cursor: usize,
}

// SAFETY: `JitCodeBuffer` owns a private `mmap` allocation not shared across threads without sync.
unsafe impl Send for JitCodeBuffer {}

impl JitCodeBuffer {
    /// Allocate a host executable scratch buffer of `capacity` bytes.
    pub fn new(capacity: usize) -> Option<Self> {
        let cap = capacity.max(4096);
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
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
        })
    }

    /// Write `bytes` into the executable buffer and return the host execution address.
    pub fn publish(&mut self, bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() || bytes.len() > self.capacity {
            return None;
        }
        if self.cursor + bytes.len() > self.capacity {
            self.cursor = 0;
        }
        // SAFETY: `self.cursor + bytes.len() <= self.capacity`.
        let dst = unsafe { self.ptr.as_ptr().add(self.cursor) };
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len()) };
        self.cursor += (bytes.len() + 15) & !15;
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

struct ActiveMemGuard<'a>(&'a mut SoftCpuContext);

impl Drop for ActiveMemGuard<'_> {
    fn drop(&mut self) {
        self.0.active_mem_ptr = None;
        self.0.active_translate_fn = None;
    }
}

/// Level 0 x86_64 soft vCPU.
pub struct SoftCpu {
    pub ctx: Box<SoftCpuContext>,
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
        self.ctx.bounce_active = 0;
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

    /// Emit and execute an already-planned [`PlannedBlock`] over `mem`.
    pub fn execute_planned_block<M: SoftMmuMemory>(
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

        self.ctx.block_start_va = planned.start;
        self.ctx.entry_exec_addr = exec_addr;
        self.ctx.exit_reason = 0;
        self.ctx.pending_exception = None;
        self.ctx.active_block_insns.clear();
        self.ctx
            .active_block_insns
            .extend(planned.insns.iter().map(|d| (d.va, d.raw)));

        let raw_exit = {
            self.ctx.active_mem_ptr = Some(NonNull::from(&mut *mem).cast::<()>());
            self.ctx.active_translate_fn = Some(translate_for_mem::<M>);
            let guard = ActiveMemGuard(&mut self.ctx);
            let ctx_ptr: *mut SoftCpuContext = &mut *guard.0;
            // SAFETY: `exec_addr` points to freshly emitted machine code ending in an exit stub.
            unsafe { softcpu_enter_translated(ctx_ptr.cast::<u8>()) }
        };

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
            SensitiveOp::Rdssp { .. } => {
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Rdpkru | SensitiveOp::Wrpkru | SensitiveOp::Xgetbv => {
                let bad_rcx = (self.ctx.gpr[reg::RCX] as u32) != 0;
                let bad_rdx =
                    matches!(op, SensitiveOp::Wrpkru) && (self.ctx.gpr[reg::RDX] as u32) != 0;
                if bad_rcx || bad_rdx {
                    return self.raise(X86Exception::general_protection(va, 0));
                }
                match op {
                    SensitiveOp::Rdpkru => {
                        self.ctx.gpr[reg::RAX] = u64::from(self.ctx.pkru);
                        self.ctx.gpr[reg::RDX] = 0;
                    }
                    SensitiveOp::Wrpkru => self.ctx.pkru = self.ctx.gpr[reg::RAX] as u32,
                    _ => {
                        self.ctx.gpr[reg::RAX] = self.ctx.xcr0 & 0xffff_ffff;
                        self.ctx.gpr[reg::RDX] = self.ctx.xcr0 >> 32;
                    }
                }
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Continue { next_rip: resume })
            }
            SensitiveOp::Rdtsc | SensitiveOp::Rdtscp => {
                let mut aux = 0u32;
                // SAFETY: `_rdtsc`/`__rdtscp` are available on x86_64 hosts.
                let tsc = unsafe {
                    if matches!(op, SensitiveOp::Rdtscp) {
                        core::arch::x86_64::__rdtscp(&mut aux)
                    } else {
                        core::arch::x86_64::_rdtsc()
                    }
                };
                self.ctx.gpr[reg::RAX] = tsc & 0xffff_ffff;
                self.ctx.gpr[reg::RDX] = tsc >> 32;
                if matches!(op, SensitiveOp::Rdtscp) {
                    self.ctx.gpr[reg::RCX] = 0;
                }
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
            SensitiveOp::Fxsave
            | SensitiveOp::Xsave
            | SensitiveOp::Xsaveopt
            | SensitiveOp::Xsavec
            | SensitiveOp::Fxrstor
            | SensitiveOp::Xrstor => {
                let is_save = !matches!(op, SensitiveOp::Fxrstor | SensitiveOp::Xrstor);
                let is_ext = !matches!(op, SensitiveOp::Fxsave | SensitiveOp::Fxrstor);
                let (align_mask, total_len) = if is_ext {
                    (0x3fu64, 576)
                } else {
                    (0xfu64, 512)
                };
                let ea = compute_effective_va(raw, &self.ctx);
                if (ea & align_mask) != 0
                    || !is_canonical_va(ea)
                    || !is_canonical_va(ea.wrapping_add((total_len - 1) as u64))
                {
                    return self.raise(X86Exception::general_protection(va, 0));
                }
                let mut area = [0u8; 576];
                let io_res = if is_save {
                    area[..512].copy_from_slice(&self.ctx.fxsave.0);
                    if is_ext {
                        area[512..520].copy_from_slice(&0x3u64.to_le_bytes());
                    }
                    write_guest_bytes(&mut self.ctx, mem, ea, &area[..total_len])
                } else {
                    read_guest_bytes(
                        &mut self.ctx,
                        mem,
                        ea,
                        &mut area[..total_len],
                        SoftAccessKind::Read,
                    )
                };
                if let Err(pf) = io_res {
                    return self.raise(X86Exception::page_fault(va, pf.error_code, pf.cr2));
                }
                if !is_save {
                    if (u32::from_le_bytes([area[24], area[25], area[26], area[27]]) & 0xffff_0000)
                        != 0
                    {
                        return self.raise(X86Exception::general_protection(va, 0));
                    }
                    self.ctx.fxsave.0.copy_from_slice(&area[..512]);
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

/// Pinned x86-64-v3 guest CPUID view (§4.3.5: SSE4.2, AVX2, BMI1/2, FMA, F16C, MOVBE, POPCNT;
/// no AVX-512, no AMX, no CET, hypervisor bit clear).
fn emulate_pinned_cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let host = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    match (leaf, subleaf) {
        (1, _) => (host.eax, host.ebx, host.ecx & !(1 << 31), host.edx),
        (7, 0) => (host.eax, host.ebx & !0xdc23_0000, host.ecx & !(1 << 7), 0),
        _ => (host.eax, host.ebx, host.ecx, host.edx),
    }
}
