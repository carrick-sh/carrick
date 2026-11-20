//! Exit handlers: the Rust half of the copy-through engine. A block exits
//! before an instruction it cannot run natively; the handler performs that one
//! instruction against `CpuState` and `GuestMemory` and leaves `cpu.pc` at the
//! next guest PC (the exception vector, the branch target or PC+4).
//! Semantics: Arm ARM DDI0487G.a C6.2 instruction pages (LDR/STR/LDP/STP,
//! LDXR/STXR, LDADD, BR/BLR/RET, MSR immediate), D1.10/D1.11 exception entry
//! and return (via `exception`), and D13.2 register access (via `state`).
//! Data alignment is checked before translation; with SCTLR_EL1.M set every
//! access uses stage-1 translation (`mmu`) and its faults are
//! taken as EL1 data aborts.
use crate::exception::{
    DataAccess, Exception, ExceptionOutcome, ProviderExit, WaitInstruction, eret, take_exception,
};
use crate::mmu::{self, AccessClass, Stage1Error};
use crate::state::{
    CpuState, DC_ZVA_BYTES, ExceptionLevel, InterruptMasks, ProgramCounter, RegisterValue,
    StackSelect, SystemAccessException, SystemValue, VirtualAddress,
};
use crate::translate::GuestInstruction;
use crate::{
    AtomicTransferKind, Barrier, BarrierKind, Branch, Decoded, ExceptionKind, Extend, Hint,
    IcOperation, Immediate16, Instruction, MemoryAddress, MemoryIndex, MemoryOperation,
    MemoryRegister, MemorySize, OperandRegister, PstateField, RegisterBranch, SystemDirection,
    SystemRegister, TlbiOperation, Width,
};
use carrick_guest_arch::{FrameGpa, Gpa, GuestVa};
use carrick_mmu_core::aarch64::stage1_walk::Aarch64Fault;
use carrick_mmu_core::stage1::{LeafAccess, Stage1Leaf};

/// A guest access guest memory cannot serve (an unbacked physical address,
/// such as MMIO). Not an architectural abort: stage-1 faults are delivered
/// as aborts through `mmu`; this is the provider's boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFault {
    pub address: VirtualAddress,
}

/// Identifies the bytes and backing of one guest-physical code frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeGeneration(pub u64);

/// Guest memory as the handlers see it. Little-endian data. Addresses are
/// physical: with SCTLR_EL1.M clear they equal the virtual address, with M
/// set they are the stage-1 output.
pub trait GuestMemory {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault>;
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault>;

    /// A generation is supplied only for a fully readable code frame whose
    /// memory owner tracks all guest and host writes and backing changes.
    /// The owner must never reuse a generation for changed bytes or backing
    /// during a run, and must exclude concurrent mutation during dispatch.
    /// Untracked memory is translated afresh.
    fn code_generation(&self, _frame: FrameGpa) -> Option<CodeGeneration> {
        None
    }

    /// Activate tracking for a frame before publishing a resident block.
    /// Owners that already track every frame can return the current generation.
    fn mark_code_page(&mut self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.code_generation(frame)
    }

    /// Whether this provider serves one local stage-1 seat for the duration
    /// of a dispatcher run. Shared providers must leave this disabled until
    /// their external invalidations are delivered before translation reuse.
    fn stage1_is_local(&self) -> bool {
        false
    }

    /// Translate a single-page access with stage 1 enabled. The dispatcher
    /// wrapper may reuse successful walks within the current run.
    #[doc(hidden)]
    fn translate_stage1(
        &mut self,
        cpu: &CpuState,
        va: GuestVa,
        access: LeafAccess,
        class: AccessClass,
    ) -> Result<Gpa, Stage1Error>
    where
        Self: Sized,
    {
        mmu::walk(cpu, self, va.raw(), access, class).map(|leaf| Gpa::from_frame_gpa(leaf.output()))
    }

    /// Observe an attempted hardware-format stage-1 walk, including faults.
    fn record_stage1_walk(&mut self) {}
}

/// The virtual per-CPU exclusive monitor (D1.7 local monitor): a host
/// reservation never survives a handler, so the monitor is ours.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveMonitor {
    reservation: Option<(u64, u8)>,
}

impl ExclusiveMonitor {
    pub fn clear(&mut self) {
        self.reservation = None;
    }
    pub fn is_open(&self) -> bool {
        self.reservation.is_some()
    }
}

/// Something the handler's owner must apply or decide; the instruction has
/// retired unless stated otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// HVC at EL1: Carrick's provider boundary. PC is the next instruction.
    ProviderExit(ProviderExit),
    Tlbi(TlbiOperation),
    Ic(IcOperation),
    Hint(Hint),
    /// MSR SCTLR_EL1 would set M under a TCR_EL1 the stage-1 walker does
    /// not admit. Not retired.
    MmuEnable {
        value: SystemValue,
    },
    /// Not retired: guest memory could not serve this (physical) access.
    MemoryFault(MemoryFault),
    /// Not retired: the stage-1 walk could not run (descriptor memory
    /// refused, or translation enabled under an unadmitted TCR_EL1).
    Translation(Stage1Error),
    /// Not retired: decoded, but not implemented by this slice.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Retired; continue at `cpu.pc` (including SVC's exception entry).
    Continue,
    /// Entered a guest exception without retiring the instruction.
    Fault,
    Event(Event),
}

fn next(cpu: &mut CpuState) {
    cpu.pc = ProgramCounter(cpu.pc.0.wrapping_add(4));
}

fn undefined(cpu: &mut CpuState) -> Outcome {
    take_exception(cpu, Exception::Unknown);
    Outcome::Fault
}

fn operand(cpu: &CpuState, r: OperandRegister) -> u64 {
    cpu.read_operand(r).0
}

fn set_operand(cpu: &mut CpuState, r: OperandRegister, value: u64) {
    cpu.write_operand(r, RegisterValue(value));
}

/// D13.2.116: SCTLR_EL1 is op0=3, op1=0, CRn=1, CRm=0, op2=0.
fn is_sctlr(r: SystemRegister) -> bool {
    (r.op0, r.op1, r.crn, r.crm, r.op2) == (3, 0, 1, 0, 0)
}

/// Perform the instruction a block exited on. `cpu.pc` must equal `i.pc()`.
pub fn execute(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    i: &GuestInstruction,
) -> Outcome {
    debug_assert_eq!(cpu.pc, i.pc());
    match i.instruction() {
        Instruction::SystemAccess(a) => match a.direction {
            SystemDirection::Read => match cpu.mrs(a.encoding, a.rt) {
                Ok(v) => {
                    set_operand(cpu, a.rt, v.0);
                    next(cpu);
                    Outcome::Continue
                }
                Err(e) => system_trap(cpu, e),
            },
            SystemDirection::Write => {
                let value = SystemValue(operand(cpu, a.rt));
                // Setting M under a TCR_EL1 the walker does not admit stops;
                // an admitted regime enables translation (`mmu`).
                if is_sctlr(a.encoding)
                    && cpu.pstate.el == ExceptionLevel::El1
                    && value.0 & 1 != 0
                    && cpu.el1.sctlr.0 & 1 == 0
                    && mmu::regime(cpu).is_err()
                {
                    return Outcome::Event(Event::MmuEnable { value });
                }
                match cpu.msr(a.encoding, a.rt, value) {
                    Ok(()) => {
                        next(cpu);
                        Outcome::Continue
                    }
                    Err(e) => system_trap(cpu, e),
                }
            }
        },
        Instruction::PstateImmediate(p) => pstate(cpu, i.word(), p.field, p.immediate),
        Instruction::InstructionCache(op) => match op {
            IcOperation::Ialluis | IcOperation::Iallu => {
                // C5.3 Table C5-6: the whole-cache forms require EL1.
                if cpu.pstate.el == ExceptionLevel::El0 {
                    return undefined(cpu);
                }
                next(cpu);
                Outcome::Event(Event::Ic(op))
            }
            IcOperation::Ivau(rt) => {
                if cpu.pstate.el == ExceptionLevel::El0 && !cpu.el1.sctlr.uci() {
                    return sys_trap(cpu, i.word(), rt);
                }
                let address = operand(cpu, rt);
                // Translate as a data cache-maintenance address, not as a
                // fetch: execute permission is not needed to invalidate it.
                match mmu::translate(
                    cpu,
                    memory,
                    address,
                    LeafAccess::Read,
                    AccessClass::Ordinary,
                ) {
                    Ok(_) => {
                        next(cpu);
                        Outcome::Event(Event::Ic(op))
                    }
                    Err(Stage1Error::Abort(fault)) => enter_memory_exception(
                        cpu,
                        mmu::fault_status(fault).map(|status| Exception::CacheMaintenanceAbort {
                            status,
                            address: VirtualAddress(fault.va.raw()),
                        }),
                    ),
                    Err(error) => Outcome::Event(Event::Translation(error)),
                }
            }
        },
        Instruction::DataCacheZero(rt) => {
            if cpu.pstate.el == ExceptionLevel::El0 && !cpu.el1.sctlr.dze() {
                return sys_trap(cpu, i.word(), rt);
            }
            let result = dc_zva(cpu, memory, operand(cpu, rt));
            finish_memory(cpu, result.map(Some))
        }
        Instruction::SystemOperation(op) => {
            // C5.4: op1 selects the minimum EL for these TLBI encodings.
            if cpu.pstate.el == ExceptionLevel::El0 || op.op1 != 0 {
                return undefined(cpu);
            }
            next(cpu);
            Outcome::Event(Event::Tlbi(op.operation))
        }
        Instruction::CensusGap(Decoded::AddressTranslate { op, xt }) => {
            // C5.3, Table C5-3: only the op1=0 AT aliases are available at EL1.
            if cpu.pstate.el == ExceptionLevel::El0 {
                return undefined(cpu);
            }
            let va = match crate::Gpr::new(xt.number()) {
                Some(r) => cpu.read_operand(OperandRegister::Gpr(r)).0,
                None => 0, // C6.2.21: Rt=31 is XZR.
            };
            let Some(result) = mmu::address_translate(cpu, memory, op, va) else {
                return undefined(cpu);
            };
            match result {
                Ok(par) => {
                    cpu.named.par = SystemValue(par);
                    next(cpu);
                    Outcome::Continue
                }
                Err(error) => Outcome::Event(Event::Translation(error)),
            }
        }
        Instruction::CensusGap(Decoded::ClearExclusive { .. }) => {
            monitor.clear();
            next(cpu);
            Outcome::Continue
        }
        Instruction::CensusGap(Decoded::Breakpoint { immediate }) => {
            take_exception(cpu, Exception::Brk(immediate.value()));
            Outcome::Fault
        }
        Instruction::ExceptionGeneration(e) => {
            let immediate = Immediate16::new(e.immediate);
            let exception = match e.kind {
                ExceptionKind::Svc => Exception::Svc(immediate),
                ExceptionKind::Hvc => Exception::Hvc(immediate),
                ExceptionKind::Brk => Exception::Brk(e.immediate),
                // No EL2/EL3, no halting debug: SMC, HLT and DCPS are undefined.
                _ => Exception::Unknown,
            };
            match take_exception(cpu, exception) {
                ExceptionOutcome::Entered if e.kind == ExceptionKind::Svc => Outcome::Continue,
                ExceptionOutcome::Entered => Outcome::Fault,
                ExceptionOutcome::ProviderExit(exit) => {
                    next(cpu);
                    Outcome::Event(Event::ProviderExit(exit))
                }
            }
        }
        Instruction::Eret => match eret(cpu) {
            Ok(()) => {
                monitor.clear();
                Outcome::Continue
            }
            Err(_) => undefined(cpu),
        },
        Instruction::Barrier(Barrier {
            kind: BarrierKind::Isb,
            ..
        }) => {
            // B2.3.4: the next guest fetch must occur after this boundary.
            next(cpu);
            Outcome::Continue
        }
        Instruction::Hint(h) => {
            // Hint_WFE consumes a pending event before testing for a trap.
            if h == Hint::Wfe && cpu.consume_local_event() {
                next(cpu);
                return Outcome::Continue;
            }
            if matches!(h, Hint::Sev | Hint::Sevl) {
                cpu.signal_local_event();
            }
            let wait = match h {
                Hint::Wfi => Some(WaitInstruction::Wfi),
                Hint::Wfe => Some(WaitInstruction::Wfe),
                _ => None,
            };
            // This dispatcher surfaces waits that would otherwise suspend the CPU.
            if cpu.pstate.el == ExceptionLevel::El0
                && let Some(wait) = wait
                && cpu.el1.sctlr.traps_el0_wait(wait)
            {
                take_exception(cpu, Exception::WaitTrap(wait));
                return Outcome::Fault;
            }
            next(cpu);
            Outcome::Event(Event::Hint(h))
        }
        Instruction::Unallocated => undefined(cpu),
        Instruction::Branch(Branch::Register { op, rn }) => {
            let target = operand(cpu, rn);
            if op == RegisterBranch::Call {
                let link = cpu.pc.0.wrapping_add(4);
                set_operand(cpu, OperandRegister::Gpr(LINK), link);
            }
            cpu.pc = ProgramCounter(target);
            Outcome::Continue
        }
        _ => {
            let result = memory_operation(cpu, monitor, memory, i);
            finish_memory(cpu, result)
        }
    }
}

fn enter_memory_exception(cpu: &mut CpuState, exception: Option<Exception>) -> Outcome {
    match exception {
        Some(exception) => {
            take_exception(cpu, exception);
            Outcome::Fault
        }
        None => Outcome::Event(Event::Unsupported),
    }
}

fn finish_memory(cpu: &mut CpuState, result: Result<Option<()>, MemoryAccessError>) -> Outcome {
    match result {
        Ok(Some(())) => {
            next(cpu);
            Outcome::Continue
        }
        Ok(None) => Outcome::Event(Event::Unsupported),
        Err(MemoryAccessError::Provider(fault)) => Outcome::Event(Event::MemoryFault(fault)),
        Err(MemoryAccessError::Alignment { access, address }) => {
            enter_memory_exception(cpu, Some(Exception::Alignment { access, address }))
        }
        Err(MemoryAccessError::Abort(fault)) => {
            enter_memory_exception(cpu, mmu::fault_exception(fault))
        }
        Err(MemoryAccessError::Translation(error)) => Outcome::Event(Event::Translation(error)),
    }
}

/// DC ZVA translates the operand as a store and zeros a single aligned block.
/// At 64 bytes the block cannot straddle this profile's 4 KiB translation.
fn dc_zva(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    address: u64,
) -> Result<(), MemoryAccessError> {
    // When translation is disabled the baseline data memory type is Device.
    let (pa, device) = if mmu::enabled(cpu) {
        let leaf = mmu::walk(
            cpu,
            memory,
            address,
            LeafAccess::Write,
            AccessClass::Ordinary,
        )?;
        let attributes = (cpu.el1.mair.0 >> (8 * leaf.attr_index())) as u8;
        (leaf.output().raw(), attributes & 0xf0 == 0)
    } else {
        (address, true)
    };
    if device {
        return Err(MemoryAccessError::Alignment {
            access: DataAccess::Write,
            address: VirtualAddress(address),
        });
    }
    let base = pa & !(DC_ZVA_BYTES as u64 - 1);
    memory.write(VirtualAddress(base), &[0; DC_ZVA_BYTES])?;
    Ok(())
}

const LINK: crate::Gpr = match crate::Gpr::new(30) {
    Some(r) => r,
    None => panic!("X30 is a general-purpose register"),
};

fn system_trap(cpu: &mut CpuState, e: SystemAccessException) -> Outcome {
    take_exception(cpu, Exception::SystemAccess(e));
    Outcome::Fault
}

fn sys_trap(cpu: &mut CpuState, word: u32, rt: OperandRegister) -> Outcome {
    system_trap(
        cpu,
        SystemAccessException::sys64(SystemRegister::from_word(word), rt, false),
    )
}

/// C6.2.195 MSR (immediate), C5.2.2 DAIF, C5.2.10 PAN, C5.2.16 SPSel.
/// At EL0, DAIFSet/DAIFClr trap with EC=0x18 unless SCTLR_EL1.UMA; every other
/// field is undefined there. DIT, SSBS and TCO are not implemented, so those
/// encodings are undefined.
fn pstate(cpu: &mut CpuState, word: u32, field: PstateField, immediate: u8) -> Outcome {
    let el0 = cpu.pstate.el == ExceptionLevel::El0;
    match field {
        PstateField::DaifSet | PstateField::DaifClr => {
            if el0 && cpu.el1.sctlr.0 & (1 << 9) == 0 {
                let iss = (u64::from((word >> 5) & 7) << 17)
                    | (u64::from((word >> 16) & 7) << 14)
                    | (4 << 10)
                    | (31 << 5)
                    | (u64::from((word >> 8) & 15) << 1);
                return system_trap(
                    cpu,
                    SystemAccessException {
                        syndrome: crate::exception::Syndrome((0x18 << 26) | (1 << 25) | iss),
                    },
                );
            }
            let daif = cpu.pstate.daif.0;
            cpu.pstate.daif = InterruptMasks(if field == PstateField::DaifSet {
                daif | immediate
            } else {
                daif & !immediate
            });
        }
        PstateField::SpSel if !el0 => {
            cpu.pstate.sp = if immediate & 1 == 0 {
                StackSelect::El0
            } else {
                StackSelect::El1
            };
        }
        PstateField::Pan if !el0 => cpu.pstate.pan = immediate & 1 != 0,
        PstateField::Uao if !el0 => cpu.pstate.uao = immediate & 1 != 0,
        _ => return undefined(cpu),
    }
    next(cpu);
    Outcome::Continue
}

fn extend(value: u64, e: Extend) -> u64 {
    match e {
        Extend::Uxtb => value & 0xff,
        Extend::Uxth => value & 0xffff,
        Extend::Uxtw => value & 0xffff_ffff,
        Extend::Uxtx | Extend::Sxtx => value,
        Extend::Sxtb => value as u8 as i8 as i64 as u64,
        Extend::Sxth => value as u16 as i16 as i64 as u64,
        Extend::Sxtw => value as u32 as i32 as i64 as u64,
    }
}

/// One data access at `address`: stage-1 translated piecewise when
/// SCTLR_EL1.M is set (`mmu`), every page translated before any byte moves,
/// so a fault on the second page of a crossing access writes nothing.
struct DataAccessor {
    class: AccessClass,
}

impl DataAccessor {
    /// The physical pieces of `[address, address + len)`, at most two.
    fn pieces(
        &self,
        cpu: &CpuState,
        memory: &mut impl GuestMemory,
        address: u64,
        len: usize,
        access: LeafAccess,
    ) -> Result<([(u64, usize); 2], usize), MemoryAccessError> {
        if !mmu::enabled(cpu) {
            return Ok(([(address, len), (0, 0)], 1));
        }
        let first = (PAGE - (address & (PAGE - 1))) as usize;
        let pa = mmu::translate(cpu, memory, address, access, self.class)?;
        if len <= first {
            return Ok(([(pa, len), (0, 0)], 1));
        }
        // FAR for a second-page fault is the lowest address it touches.
        let next = mmu::translate(
            cpu,
            memory,
            address.wrapping_add(first as u64),
            access,
            self.class,
        )?;
        if next == pa.wrapping_add(first as u64) {
            return Ok(([(pa, len), (0, 0)], 1));
        }
        Ok(([(pa, first), (next, len - first)], 2))
    }

    fn load(
        &self,
        cpu: &CpuState,
        memory: &mut impl GuestMemory,
        address: u64,
        size: MemorySize,
    ) -> Result<u64, MemoryAccessError> {
        let mut bytes = [0; 8];
        let n = usize::from(size.bytes());
        self.read(cpu, memory, address, &mut bytes[..n])?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn store(
        &self,
        cpu: &CpuState,
        memory: &mut impl GuestMemory,
        address: u64,
        size: MemorySize,
        value: u64,
    ) -> Result<(), MemoryAccessError> {
        self.write(
            cpu,
            memory,
            address,
            &value.to_le_bytes()[..usize::from(size.bytes())],
        )
    }

    fn read(
        &self,
        cpu: &CpuState,
        memory: &mut impl GuestMemory,
        address: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryAccessError> {
        let (pieces, count) = self.pieces(cpu, memory, address, bytes.len(), LeafAccess::Read)?;
        let mut at = 0;
        for &(pa, len) in &pieces[..count] {
            memory.read(VirtualAddress(pa), &mut bytes[at..at + len])?;
            at += len;
        }
        Ok(())
    }

    fn write(
        &self,
        cpu: &CpuState,
        memory: &mut impl GuestMemory,
        address: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryAccessError> {
        let (pieces, count) = self.pieces(cpu, memory, address, bytes.len(), LeafAccess::Write)?;
        let mut at = 0;
        for &(pa, len) in &pieces[..count] {
            memory.write(VirtualAddress(pa), &bytes[at..at + len])?;
            at += len;
        }
        Ok(())
    }
}

const PAGE: u64 = 4096;

/// Sign-extend a `size`-byte value to `width` (W results are zero-extended
/// into the X register, C6.2.142 LDRSB and friends).
fn sign_extend(value: u64, size: MemorySize, width: Width) -> u64 {
    let bits = 8 * u32::from(size.bytes());
    let wide = ((value << (64 - bits)) as i64 >> (64 - bits)) as u64;
    match width {
        Width::X64 => wide,
        Width::W32 => wide & 0xffff_ffff,
    }
}

fn loaded(value: u64, size: MemorySize, op: MemoryOperation, width: Width) -> u64 {
    if op == MemoryOperation::LoadSigned {
        sign_extend(value, size, width)
    } else {
        value
    }
}

fn register_bytes(cpu: &CpuState, register: MemoryRegister) -> [u8; 16] {
    match register {
        MemoryRegister::Integer { register, .. } => u128::from(operand(cpu, register)),
        MemoryRegister::Vector(register) => cpu.read_vector(register),
    }
    .to_le_bytes()
}

fn set_memory_register(
    cpu: &mut CpuState,
    register: MemoryRegister,
    bytes: [u8; 16],
    size: MemorySize,
    op: MemoryOperation,
) {
    let value = u128::from_le_bytes(bytes);
    match register {
        MemoryRegister::Integer { register, width } => {
            set_operand(cpu, register, loaded(value as u64, size, op, width));
        }
        // A narrow SIMD&FP load zeros the upper bits of the 128-bit register.
        MemoryRegister::Vector(register) => cpu.write_vector(register, value),
    }
}

enum MemoryAccessError {
    Provider(MemoryFault),
    Alignment {
        access: DataAccess,
        address: VirtualAddress,
    },
    Abort(Aarch64Fault),
    Translation(Stage1Error),
}

impl From<MemoryFault> for MemoryAccessError {
    fn from(fault: MemoryFault) -> Self {
        Self::Provider(fault)
    }
}

impl From<Stage1Error> for MemoryAccessError {
    fn from(error: Stage1Error) -> Self {
        match error {
            Stage1Error::Abort(fault) => Self::Abort(fault),
            other => Self::Translation(other),
        }
    }
}

fn data_access(operation: MemoryOperation) -> DataAccess {
    if operation == MemoryOperation::Store {
        DataAccess::Write
    } else {
        DataAccess::Read
    }
}

/// DDI0487G.a J1.1 AArch64.CheckAlignment; this profile lacks FEAT_LSE2.
fn check_alignment(address: u64, bytes: u64, access: DataAccess) -> Result<(), MemoryAccessError> {
    if !address.is_multiple_of(bytes) {
        return Err(MemoryAccessError::Alignment {
            access,
            address: VirtualAddress(address),
        });
    }
    Ok(())
}

/// Returns Ok(None) when the instruction is not a supported memory form.
fn memory_operation(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    i: &GuestInstruction,
) -> Result<Option<()>, MemoryAccessError> {
    match i.instruction() {
        Instruction::ScalarMemory(m) | Instruction::UnprivilegedMemory(m) => {
            let data = DataAccessor {
                class: if matches!(i.instruction(), Instruction::UnprivilegedMemory(_)) {
                    AccessClass::Unprivileged
                } else {
                    AccessClass::Ordinary
                },
            };
            let (address, writeback) = match m.address {
                MemoryAddress::Immediate {
                    base,
                    offset,
                    index,
                    ..
                } => {
                    let b = operand(cpu, base);
                    let moved = b.wrapping_add(offset.bytes() as i64 as u64);
                    match index {
                        MemoryIndex::Offset => (moved, None),
                        MemoryIndex::Pre => (moved, Some((base, moved))),
                        MemoryIndex::Post => (b, Some((base, moved))),
                    }
                }
                MemoryAddress::Register {
                    base,
                    offset,
                    extend: e,
                    scaled,
                } => {
                    let shift = if scaled {
                        m.size.bytes().trailing_zeros()
                    } else {
                        0
                    };
                    let index = extend(operand(cpu, offset), e) << shift;
                    (operand(cpu, base).wrapping_add(index), None)
                }
                MemoryAddress::Literal(offset) => {
                    (cpu.pc.0.wrapping_add(offset.bytes() as u64), None)
                }
            };
            let access = data_access(m.operation);
            if cpu.el1.sctlr.alignment_check() {
                check_alignment(address, u64::from(m.size.bytes()), access)?;
            }
            let size = usize::from(m.size.bytes());
            if access == DataAccess::Write {
                data.write(
                    cpu,
                    memory,
                    address,
                    &register_bytes(cpu, m.register)[..size],
                )?;
            } else {
                let mut bytes = [0; 16];
                data.read(cpu, memory, address, &mut bytes[..size])?;
                set_memory_register(cpu, m.register, bytes, m.size, m.operation);
            }
            if let Some((base, value)) = writeback {
                set_operand(cpu, base, value);
            }
        }
        Instruction::PairMemory(p) => {
            let b = operand(cpu, p.base);
            let moved = b.wrapping_add(p.offset.bytes() as i64 as u64);
            let address = if p.index == MemoryIndex::Post {
                b
            } else {
                moved
            };
            let step = u64::from(p.size.bytes());
            let access = data_access(p.operation);
            let data = DataAccessor {
                class: AccessClass::Ordinary,
            };
            if cpu.el1.sctlr.alignment_check() {
                check_alignment(address, step, access)?;
            }
            let size = usize::from(p.size.bytes());
            let next_address = address.wrapping_add(step);
            if access == DataAccess::Write {
                // Both halves translate before either is written.
                data.pieces(cpu, memory, address, 2 * size, LeafAccess::Write)?;
                data.write(cpu, memory, address, &register_bytes(cpu, p.first)[..size])?;
                data.write(
                    cpu,
                    memory,
                    next_address,
                    &register_bytes(cpu, p.second)[..size],
                )?;
            } else {
                let mut first = [0; 16];
                let mut second = [0; 16];
                data.read(cpu, memory, address, &mut first[..size])?;
                data.read(cpu, memory, next_address, &mut second[..size])?;
                set_memory_register(cpu, p.first, first, p.size, p.operation);
                set_memory_register(cpu, p.second, second, p.size, p.operation);
            }
            if p.index != MemoryIndex::Offset {
                set_operand(cpu, p.base, moved);
            }
        }
        Instruction::AtomicTransfer(t) => {
            let data = DataAccessor {
                class: AccessClass::Ordinary,
            };
            let address = operand(cpu, t.base);
            let step = u64::from(t.size.bytes());
            let count = if t.second.is_some() { 2 } else { 1 };
            // An exclusive pair checks its full size. Check before the
            // reservation test, the early-fault choice permitted by STXR.
            let access = match t.kind {
                AtomicTransferKind::LoadAcquire | AtomicTransferKind::LoadExclusive { .. } => {
                    DataAccess::Read
                }
                AtomicTransferKind::StoreRelease | AtomicTransferKind::StoreExclusive { .. } => {
                    DataAccess::Write
                }
            };
            check_alignment(address, step * u64::from(count), access)?;
            match t.kind {
                AtomicTransferKind::LoadAcquire | AtomicTransferKind::LoadExclusive { .. } => {
                    let a = data.load(cpu, memory, address, t.size)?;
                    let c = match t.second {
                        Some(_) => data.load(cpu, memory, address.wrapping_add(step), t.size)?,
                        None => 0,
                    };
                    set_operand(cpu, t.first, a);
                    if let Some(second) = t.second {
                        set_operand(cpu, second, c);
                    }
                    if matches!(t.kind, AtomicTransferKind::LoadExclusive { .. }) {
                        monitor.reservation = Some((address, t.size.bytes() * count));
                    }
                }
                AtomicTransferKind::StoreRelease => {
                    data.store(cpu, memory, address, t.size, operand(cpu, t.first))?;
                }
                AtomicTransferKind::StoreExclusive { status, .. } => {
                    let held = monitor.reservation == Some((address, t.size.bytes() * count));
                    if held {
                        data.store(cpu, memory, address, t.size, operand(cpu, t.first))?;
                        if let Some(second) = t.second {
                            data.store(
                                cpu,
                                memory,
                                address.wrapping_add(step),
                                t.size,
                                operand(cpu, second),
                            )?;
                        }
                    }
                    monitor.clear();
                    set_operand(cpu, status, u64::from(!held));
                }
            }
        }
        Instruction::AtomicAdd(a) => {
            let address = operand(cpu, a.base);
            // TranslateAddressForAtomicAccess checks alignment as a read.
            check_alignment(address, u64::from(a.size.bytes()), DataAccess::Read)?;
            let data = DataAccessor {
                class: AccessClass::Ordinary,
            };
            let old = data.load(cpu, memory, address, a.size)?;
            let addend = operand(cpu, a.source);
            data.store(cpu, memory, address, a.size, old.wrapping_add(addend))?;
            set_operand(cpu, a.destination, old);
        }
        _ => return Ok(None),
    }
    Ok(Some(()))
}
