//! Exit handlers: the Rust half of the copy-through engine. A block exits
//! before an instruction it cannot run natively; the handler performs that one
//! instruction against `CpuState` and `GuestMemory` and leaves `cpu.pc` at the
//! next guest PC (the exception vector, the branch target or PC+4).
//! Semantics: Arm ARM DDI0487G.a C6.2 instruction pages (LDR/STR/LDP/STP,
//! LDXR/STXR, LDADD, BR/BLR/RET, MSR immediate), D1.10/D1.11 exception entry
//! and return (via `exception`), and D13.2 register access (via `state`).
//! This slice models guest memory as flat pages: no stage-1 walk, so no
//! translation or permission faults are raised here. Data alignment is checked
//! before accessing memory.
use crate::exception::{
    DataAccess, Exception, ExceptionOutcome, ProviderExit, eret, take_exception,
};
use crate::state::{
    CpuState, ExceptionLevel, InterruptMasks, ProgramCounter, RegisterValue, StackSelect,
    SystemAccessException, SystemValue, VirtualAddress,
};
use crate::translate::GuestInstruction;
use crate::{
    AtomicTransferKind, Barrier, BarrierKind, Branch, Decoded, ExceptionKind, Extend, Hint,
    Immediate16, Instruction, MemoryAddress, MemoryIndex, MemoryOperation, MemoryRegister,
    MemorySize, OperandRegister, PstateField, RegisterBranch, SystemDirection, SystemRegister,
    TlbiOperation, Translation, Width,
};

/// A guest access the flat memory model cannot serve (an unmapped address,
/// such as MMIO). Not an architectural abort: there is no walker yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFault {
    pub address: VirtualAddress,
}

/// Guest memory as the handlers see it. Little-endian data.
pub trait GuestMemory {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault>;
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault>;
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
    Hint(Hint),
    /// MSR SCTLR_EL1 would set M. Not retired: the flat model has no walker.
    MmuEnable {
        value: SystemValue,
    },
    /// AT needs a stage-1 walk. Not retired.
    AddressTranslate,
    /// Not retired: the flat model could not serve this access.
    MemoryFault(MemoryFault),
    /// Not retired: decoded, but not implemented by this slice.
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Retired, or delivered as a guest exception; continue at `cpu.pc`.
    Continue,
    Event(Event),
}

fn next(cpu: &mut CpuState) {
    cpu.pc = ProgramCounter(cpu.pc.0.wrapping_add(4));
}

fn undefined(cpu: &mut CpuState) -> Outcome {
    take_exception(cpu, Exception::Unknown);
    Outcome::Continue
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

/// Perform the instruction a block exited on. `cpu.pc` must equal `i.pc`.
pub fn execute(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    i: &GuestInstruction,
) -> Outcome {
    debug_assert_eq!(cpu.pc, i.pc);
    match i.instruction {
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
                if is_sctlr(a.encoding)
                    && cpu.pstate.el == ExceptionLevel::El1
                    && value.0 & 1 != 0
                    && cpu.el1.sctlr.0 & 1 == 0
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
        Instruction::PstateImmediate(p) => pstate(cpu, i.word, p.field, p.immediate),
        Instruction::SystemOperation(op) => {
            // C5.4: op1 selects the minimum EL for these TLBI encodings.
            if cpu.pstate.el == ExceptionLevel::El0 || op.op1 != 0 {
                return undefined(cpu);
            }
            next(cpu);
            Outcome::Event(Event::Tlbi(op.operation))
        }
        Instruction::CensusGap(Decoded::AddressTranslate { op, .. }) => {
            // C5.3, Table C5-3: only the op1=0 AT aliases are available at EL1.
            if cpu.pstate.el == ExceptionLevel::El0
                || !matches!(
                    op,
                    Translation::S1E1R
                        | Translation::S1E1W
                        | Translation::S1E0R
                        | Translation::S1E0W
                        | Translation::S1E1Rp
                        | Translation::S1E1Wp
                )
            {
                return undefined(cpu);
            }
            Outcome::Event(Event::AddressTranslate)
        }
        Instruction::CensusGap(Decoded::ClearExclusive { .. }) => {
            monitor.clear();
            next(cpu);
            Outcome::Continue
        }
        Instruction::CensusGap(Decoded::Breakpoint { immediate }) => {
            take_exception(cpu, Exception::Brk(immediate.value()));
            Outcome::Continue
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
                ExceptionOutcome::Entered => Outcome::Continue,
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
        _ => match memory_operation(cpu, monitor, memory, i) {
            Ok(Some(())) => {
                next(cpu);
                Outcome::Continue
            }
            Ok(None) => Outcome::Event(Event::Unsupported),
            Err(MemoryAccessError::Provider(fault)) => Outcome::Event(Event::MemoryFault(fault)),
            Err(MemoryAccessError::Alignment { access, address }) => {
                take_exception(cpu, Exception::Alignment { access, address });
                Outcome::Continue
            }
        },
    }
}

const LINK: crate::Gpr = match crate::Gpr::new(30) {
    Some(r) => r,
    None => panic!("X30 is a general-purpose register"),
};

fn system_trap(cpu: &mut CpuState, e: SystemAccessException) -> Outcome {
    take_exception(cpu, Exception::SystemAccess(e));
    Outcome::Continue
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

fn load(memory: &mut impl GuestMemory, address: u64, size: MemorySize) -> Result<u64, MemoryFault> {
    let mut bytes = [0; 8];
    let n = usize::from(size.bytes()).min(8);
    memory.read(VirtualAddress(address), &mut bytes[..n])?;
    Ok(u64::from_le_bytes(bytes))
}

fn store(
    memory: &mut impl GuestMemory,
    address: u64,
    size: MemorySize,
    value: u64,
) -> Result<(), MemoryFault> {
    let n = usize::from(size.bytes()).min(8);
    memory.write(VirtualAddress(address), &value.to_le_bytes()[..n])
}

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

fn integer(r: MemoryRegister) -> Option<(OperandRegister, Width)> {
    match r {
        MemoryRegister::Integer { register, width } => Some((register, width)),
        MemoryRegister::Vector(_) => None,
    }
}

enum MemoryAccessError {
    Provider(MemoryFault),
    Alignment {
        access: DataAccess,
        address: VirtualAddress,
    },
}

impl From<MemoryFault> for MemoryAccessError {
    fn from(fault: MemoryFault) -> Self {
        Self::Provider(fault)
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

/// Returns Ok(None) for a decoded memory form this slice does not implement
/// (SIMD&FP registers); nothing is changed then.
fn memory_operation(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    i: &GuestInstruction,
) -> Result<Option<()>, MemoryAccessError> {
    match i.instruction {
        Instruction::ScalarMemory(m) | Instruction::UnprivilegedMemory(m) => {
            let Some((rt, width)) = integer(m.register) else {
                return Ok(None);
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
            if access == DataAccess::Write {
                store(memory, address, m.size, operand(cpu, rt))?;
            } else {
                let v = load(memory, address, m.size)?;
                set_operand(cpu, rt, loaded(v, m.size, m.operation, width));
            }
            if let Some((base, value)) = writeback {
                set_operand(cpu, base, value);
            }
        }
        Instruction::PairMemory(p) => {
            let (Some((first, width)), Some((second, _))) = (integer(p.first), integer(p.second))
            else {
                return Ok(None);
            };
            let b = operand(cpu, p.base);
            let moved = b.wrapping_add(p.offset.bytes() as i64 as u64);
            let address = if p.index == MemoryIndex::Post {
                b
            } else {
                moved
            };
            let step = u64::from(p.size.bytes());
            let access = data_access(p.operation);
            if cpu.el1.sctlr.alignment_check() {
                check_alignment(address, step, access)?;
            }
            if access == DataAccess::Write {
                store(memory, address, p.size, operand(cpu, first))?;
                store(
                    memory,
                    address.wrapping_add(step),
                    p.size,
                    operand(cpu, second),
                )?;
            } else {
                let a = load(memory, address, p.size)?;
                let c = load(memory, address.wrapping_add(step), p.size)?;
                set_operand(cpu, first, loaded(a, p.size, p.operation, width));
                set_operand(cpu, second, loaded(c, p.size, p.operation, width));
            }
            if p.index != MemoryIndex::Offset {
                set_operand(cpu, p.base, moved);
            }
        }
        Instruction::AtomicTransfer(t) => {
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
                    let a = load(memory, address, t.size)?;
                    let c = match t.second {
                        Some(_) => load(memory, address.wrapping_add(step), t.size)?,
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
                    store(memory, address, t.size, operand(cpu, t.first))?;
                }
                AtomicTransferKind::StoreExclusive { status, .. } => {
                    let held = monitor.reservation == Some((address, t.size.bytes() * count));
                    if held {
                        store(memory, address, t.size, operand(cpu, t.first))?;
                        if let Some(second) = t.second {
                            store(
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
            let old = load(memory, address, a.size)?;
            let addend = operand(cpu, a.source);
            store(memory, address, a.size, old.wrapping_add(addend))?;
            set_operand(cpu, a.destination, old);
        }
        _ => return Ok(None),
    }
    Ok(Some(()))
}
