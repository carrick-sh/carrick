//! Level 0 `SoftCpu` execution engine and executable code-buffer management.

use std::ptr::NonNull;

use carrick_softmmu::{ExtentTable, InventoryTerminal, SoftRequester, SoftSeatError};
use iced_x86::{Instruction, Mnemonic};

use crate::block::{BlockExit, BlockFetchFault, PlannedBlock, plan_block_from_memory};
use crate::cflow::{compute_effective_va, resolve_cflow};
use crate::context::{
    EXIT_REASON_CFLOW, EXIT_REASON_CONTINUE, EXIT_REASON_RESTART, EXIT_REASON_SENSITIVE,
    EXIT_REASON_SYSCALL, GUEST_MXCSR_MASK, SoftCpuContext, X86Exception, X86ExceptionVector, reg,
};
use crate::cpuid::{GuestCpuidView, Level0CpuidView};
use crate::decode::SensitiveOp;
use crate::emit::{EmitError, emit_block};
use crate::mmu::{
    SoftAccessKind, SoftMmuMemory, is_canonical_va, read_guest_bytes, write_guest_bytes,
};
use crate::msr::EFER_SCE;
use crate::privileged::{PrivilegedOutcome, emulate_sensitive_op};

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
    Hlt {
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
    cpuid: Box<dyn GuestCpuidView>,
    pub max_block_insns: usize,
    pub max_block_span: usize,
}

/// Scoped mutable view of architectural state on a [`RunningCpu`] that
/// never exposes `&mut SoftCpuContext`, so the running context and its
/// seat cannot be moved or swapped out of the active run guard.
pub struct RunningContext<'c> {
    ctx: &'c mut SoftCpuContext,
}

impl std::ops::Deref for RunningContext<'_> {
    type Target = SoftCpuContext;
    fn deref(&self) -> &SoftCpuContext {
        self.ctx
    }
}

impl RunningContext<'_> {
    pub fn set_rip(&mut self, rip: u64) {
        self.ctx.rip = rip;
    }

    pub fn gpr_mut(&mut self) -> &mut [u64; 16] {
        &mut self.ctx.gpr
    }

    pub fn set_rflags(&mut self, rflags: u64) {
        self.ctx.rflags = rflags;
    }

    pub fn set_fs_base(&mut self, fs_base: u64) -> Result<(), crate::msr::MsrError> {
        self.ctx.set_fs_base(fs_base)
    }

    pub fn set_gs_base(&mut self, gs_base: u64) -> Result<(), crate::msr::MsrError> {
        self.ctx.set_gs_base(gs_base)
    }

    pub fn set_kernel_gs_base(&mut self, kernel_gs_base: u64) -> Result<(), crate::msr::MsrError> {
        self.ctx.set_kernel_gs_base(kernel_gs_base)
    }

    pub fn set_cpl(&mut self, cpl: u8) {
        self.ctx.set_cpl(cpl);
    }

    pub fn set_smap_enabled(&mut self, enabled: bool) {
        self.ctx.set_smap_enabled(enabled);
    }

    pub fn set_cr3(&mut self, cr3: u64) {
        self.ctx.cr3 = cr3;
    }

    pub fn flush_tlb(&mut self) {
        self.ctx.flush_tlb();
    }

    pub fn reset_tlb_stats(&mut self) {
        self.ctx.reset_tlb_stats();
    }
}

/// A run of blocks on one [`SoftCpu`]; the CPU parks when this drops.
///
/// Never exposes `&mut SoftCpuContext`, so safe code cannot swap the
/// running context out of the guard and leave the original seat running
/// after drop:
///
/// ```compile_fail
/// use carrick_softcpu_x86::{SoftCpu, SoftCpuContext};
/// use carrick_softmmu::ExtentTable;
///
/// let inventory = ExtentTable::new().unwrap();
/// let mut cpu = SoftCpu::new(&inventory).unwrap();
/// let mut other = SoftCpuContext::new(&inventory).unwrap();
/// let mut run = cpu.run();
/// std::mem::swap(&mut *run.context_mut(), &mut other);
/// ```
pub struct RunningCpu<'c> {
    cpu: &'c mut SoftCpu,
}

impl RunningCpu<'_> {
    /// One block; this CPU stays running until the guard drops.
    pub fn step_block<M: SoftMmuMemory>(&mut self, mem: &mut M) -> Result<SoftCpuExit, EmitError> {
        // SAFETY: this guard parks the CPU on drop.
        unsafe { self.cpu.step_block_in_run(mem) }
    }

    pub fn context(&self) -> &SoftCpuContext {
        &self.cpu.ctx
    }

    /// Scoped mutable architectural access between blocks of the run
    /// without exposing `&mut SoftCpuContext`.
    pub fn context_mut(&mut self) -> RunningContext<'_> {
        RunningContext {
            ctx: &mut self.cpu.ctx,
        }
    }

    /// Whether a retirement asked this CPU to reach block entry.
    pub fn exit_requested(&self) -> bool {
        self.cpu.ctx.seat.exit_requested()
    }

    /// This running CPU as the requester of a retirement it issues itself:
    /// served inline, never kicked.
    pub fn requester(&mut self) -> SoftRequester<'_> {
        self.cpu.ctx.requester()
    }
}

impl Drop for RunningCpu<'_> {
    fn drop(&mut self) {
        self.cpu.ctx.seat.park();
    }
}

/// Why a [`SoftCpu`] could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoftCpuNewError {
    /// Every member of the inventory's invalidation domain is seated.
    Seat(SoftSeatError),
    /// The host refused the JIT code buffer.
    Jit,
}

impl SoftCpu {
    /// Create a new [`SoftCpu`] initialized for 64-bit user mode (`CPL = 3`),
    /// seated in `extents`' invalidation domain and parked, using [`Level0CpuidView`].
    pub fn new(extents: &ExtentTable) -> Result<Self, SoftCpuNewError> {
        Self::with_cpuid_view(extents, Box::new(Level0CpuidView))
    }

    /// Create a new [`SoftCpu`] configured with a custom [`GuestCpuidView`].
    pub fn with_cpuid_view(
        extents: &ExtentTable,
        cpuid: Box<dyn GuestCpuidView>,
    ) -> Result<Self, SoftCpuNewError> {
        let mut ctx = SoftCpuContext::new(extents).map_err(SoftCpuNewError::Seat)?;
        ctx.walker.set_max_phy_addr(cpuid.max_phy_addr());
        ctx.tsc_hz = cpuid.tsc_hz();
        ctx.lapic.set_apic_id(cpuid.apic_id());
        Ok(Self {
            ctx: Box::new(ctx),
            jit: JitCodeBuffer::new(DEFAULT_JIT_CAPACITY).ok_or(SoftCpuNewError::Jit)?,
            cpuid,
            max_block_insns: 64,
            max_block_span: 4096,
        })
    }

    /// Inspect the installed [`GuestCpuidView`].
    #[must_use]
    pub fn cpuid_view(&self) -> &dyn GuestCpuidView {
        &*self.cpuid
    }

    /// Replace the installed [`GuestCpuidView`] between runs, updating `MAXPHYADDR`, `tsc_hz`,
    /// and local APIC ID.
    pub fn set_cpuid_view(&mut self, cpuid: Box<dyn GuestCpuidView>) {
        self.ctx.walker.set_max_phy_addr(cpuid.max_phy_addr());
        self.ctx.tsc_hz = cpuid.tsc_hz();
        self.ctx.lapic.set_apic_id(cpuid.apic_id());
        self.cpuid = cpuid;
    }

    /// Attaches an injectable [`crate::apic::TscClock`] to this CPU.
    pub fn set_clock(&mut self, clock: std::sync::Arc<dyn crate::apic::TscClock>) {
        self.ctx.set_clock(clock);
    }

    /// Attaches this CPU's local xAPIC to a shared [`crate::apic::ApicCluster`].
    pub fn attach_apic_cluster(&mut self, cluster: std::sync::Arc<crate::apic::ApicCluster>) {
        self.ctx.attach_apic_cluster(cluster);
    }

    /// Returns a shared handle to this CPU's [`crate::apic::ApicNode`] for cross-thread IPIs and kicks.
    #[must_use]
    pub fn apic_node(&self) -> std::sync::Arc<crate::apic::ApicNode> {
        self.ctx.apic_node()
    }

    /// Polls the local APIC timer against the current TSC value.
    pub fn poll_apic_timer(&mut self) -> bool {
        self.ctx.poll_apic_timer()
    }

    /// Injects an external interrupt `vector` into this CPU's local APIC `IRR` and kicks it.
    pub fn inject_interrupt(&self, vector: u8) -> bool {
        self.ctx.lapic.inject_interrupt(vector)
    }

    /// Run a sequence of blocks. Block entry inside the run costs own-line
    /// loads only; dropping the guard parks the CPU, so a finished run never
    /// holds a retirement up.
    pub fn run(&mut self) -> RunningCpu<'_> {
        RunningCpu { cpu: self }
    }

    /// Whether a retirement asked this CPU to reach block entry.
    pub fn exit_requested(&self) -> bool {
        self.ctx.seat.exit_requested()
    }

    /// This (parked) CPU as the requester of a retirement it issues itself.
    pub fn requester(&mut self) -> SoftRequester<'_> {
        self.ctx.requester()
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

    /// Plan, emit, and execute one basic block starting at `self.ctx.rip`
    /// over `mem`, as a run of one block: the CPU parks again afterwards.
    /// A loop of blocks uses [`Self::run`].
    pub fn step_block<M: SoftMmuMemory>(&mut self, mem: &mut M) -> Result<SoftCpuExit, EmitError> {
        self.run().step_block(mem)
    }

    /// One block on a running CPU. Block entry is the invalidation safe
    /// point: it enters a parked CPU (serving what it owes) and otherwise
    /// checks its own debt with own-line loads, flushing only when owed.
    ///
    /// # Safety
    /// Called only by [`RunningCpu`], whose drop parks the CPU.
    unsafe fn step_block_in_run<M: SoftMmuMemory>(
        &mut self,
        mem: &mut M,
    ) -> Result<SoftCpuExit, EmitError> {
        self.ctx.pending_exception = None;
        self.ctx.icebp_trap = false;
        self.ctx.halted = false;
        let _ = self.ctx.poll_apic_timer();
        crate::context::prepare_gateway(self.ctx.rip)?;
        if !mem.extents().is_member(&self.ctx.seat) {
            return Err(EmitError::ForeignInventory { va: self.ctx.rip });
        }
        // SAFETY: the caller is a `RunningCpu`, which parks on drop.
        unsafe { self.ctx.seat.block_entry_unguarded(&mut self.ctx.tlb) }
            .map_err(|InventoryTerminal| EmitError::InventoryTerminal { va: self.ctx.rip })?;
        self.ctx.reset_bounce();
        self.ctx.sync_tlb_tag_bits();

        let (rip, max_i, max_s) = (self.ctx.rip, self.max_block_insns, self.max_block_span);
        // SDM Vol. 3A §17.3.1.1 / §18.2.4: instruction-execution breakpoints (DR0..DR3 with
        // R/W_i == 0b00 and LEN_i == 0b00) fire as pre-fetch faults when RFLAGS.RF == 0.
        if (self.ctx.rflags & (1 << 16)) == 0 && (self.ctx.dr[7] & 0xff) != 0 {
            let dr7 = self.ctx.dr[7];
            let mut matched = 0u64;
            for i in 0..4 {
                let enabled = (dr7 & (0x3 << (i * 2))) != 0;
                let rw = (dr7 >> (16 + i * 4)) & 0x3;
                let len = (dr7 >> (18 + i * 4)) & 0x3;
                if enabled && rw == 0 && len == 0 && self.ctx.dr[i] == rip {
                    matched |= 1 << i;
                }
            }
            if matched != 0 {
                self.ctx.dr[6] = (self.ctx.dr[6] & !0xf) | matched | 0xffff_0ff0;
                self.ctx.dr[7] &= !(1 << 13);
                return self.raise(X86Exception::debug(rip));
            }
        }

        match plan_block_from_memory(rip, max_i, max_s, &mut self.ctx, mem) {
            Ok(b) => {
                let single_step = self.ctx.rflags & (1 << 8) != 0;
                let had_sti_shadow = self.ctx.interrupt_shadow;
                let block_exit = &b.exit;
                let is_iret = matches!(
                    block_exit,
                    BlockExit::Sensitive {
                        op: SensitiveOp::Iretq,
                        ..
                    }
                );
                let result = self.execute_planned_block(&b, mem)?;
                if had_sti_shadow {
                    self.ctx.interrupt_shadow = false;
                }
                if !is_iret && !matches!(result, SoftCpuExit::Exception(_)) {
                    // SDM Vol. 3A §2.3 / §17.3.1.1: RF is cleared after any non-IRET instruction
                    // completes without faulting; IRET loads RF from stacked RFLAGS so RF=1 can
                    // suppress an instruction breakpoint on the returned-to instruction.
                    self.ctx.rflags &= !(1 << 16);
                }
                if single_step && matches!(result, SoftCpuExit::Continue { .. }) {
                    self.ctx.dr[6] = (self.ctx.dr[6] & !0xf) | (1 << 14) | 0xffff_0ff0;
                    self.ctx.dr[7] &= !(1 << 13);
                    return self.raise(X86Exception::debug(self.ctx.rip));
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
        if (self.ctx.cr0 & 0xc) != 0
            && let Some(first) = planned.insns.first()
            && (0..first.raw.op_count()).any(|i| {
                first.raw.op_kind(i) == iced_x86::OpKind::Register
                    && first.raw.op_register(i).is_xmm()
            })
        {
            if (self.ctx.cr0 & (1 << 2)) != 0 {
                return self.raise(X86Exception::invalid_opcode(first.va));
            }
            if (self.ctx.cr0 & (1 << 3)) != 0 {
                return self.raise(X86Exception::device_not_available(first.va));
            }
        }
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
            EXIT_REASON_SYSCALL => {
                let (va, resume) = match planned.exit {
                    BlockExit::Syscall { va, resume, .. } => (va, resume),
                    _ => (self.ctx.exit_insn_va, self.ctx.rip),
                };
                if (self.ctx.efer() & EFER_SCE) == 0 || !self.ctx.cs.is_64bit_code() {
                    return self.raise(X86Exception::invalid_opcode(va));
                }
                self.ctx.rip = resume;
                Ok(SoftCpuExit::Syscall {
                    rip: va,
                    next_rip: resume,
                })
            }
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
        self.ctx.exit_insn_va = va;
        match emulate_sensitive_op(&mut self.ctx, &*self.cpuid, va, resume, op, raw, mem) {
            PrivilegedOutcome::Continue { next_rip } => Ok(SoftCpuExit::Continue { next_rip }),
            PrivilegedOutcome::Hlt { rip, next_rip } => Ok(SoftCpuExit::Hlt { rip, next_rip }),
            PrivilegedOutcome::Exception(exc) => self.raise(exc),
            PrivilegedOutcome::Unhandled => {
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
                    SensitiveOp::Icebp => {
                        self.ctx.icebp_trap = true;
                        self.ctx.dr[6] = (self.ctx.dr[6] & !0xf) | (1 << 14) | 0xffff_0ff0;
                        self.ctx.dr[7] &= !(1 << 13);
                        self.ctx.rflags &= !(1 << 16);
                        self.raise(X86Exception::debug(resume))
                    }
                    SensitiveOp::Interrupt { vector } => {
                        self.ctx.rip = resume;
                        if raw.mnemonic() == iced_x86::Mnemonic::Int3 {
                            return self.raise(X86Exception::breakpoint(resume));
                        }
                        Ok(SoftCpuExit::SoftwareInterrupt {
                            vector,
                            rip: va,
                            next_rip: resume,
                        })
                    }
                    SensitiveOp::Ldmxcsr | SensitiveOp::Stmxcsr => {
                        if (self.ctx.cr0 & (1 << 2)) != 0 {
                            return self.raise(X86Exception::invalid_opcode(va));
                        }
                        if (self.ctx.cr0 & (1 << 3)) != 0 {
                            return self.raise(X86Exception::device_not_available(va));
                        }
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
                            read_guest_bytes(
                                &mut self.ctx,
                                mem,
                                ea,
                                &mut bytes,
                                SoftAccessKind::Read,
                            )
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
    if ext && (ctx.cr4 & (1 << 18)) == 0 {
        return Err(X86Exception::invalid_opcode(ip));
    }
    if (ctx.cr0 & (1 << 3)) != 0 || (!ext && (ctx.cr0 & (1 << 2)) != 0) {
        return Err(X86Exception::device_not_available(ip));
    }
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
        if (ctx.cr0 & 0xa) == 0xa {
            return Err(X86Exception::device_not_available(ip));
        }
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
    if (ctx.cr0 & 0xc) != 0 {
        return Err(X86Exception::device_not_available(ip));
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
