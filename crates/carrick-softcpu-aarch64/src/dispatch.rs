//! The dispatcher: split and translate the block at `cpu.pc`, run it through
//! an `ExecuteBlock` (the host launch, implemented outside this crate on an
//! arm64 host), map the exit index back to a guest exit, run its handler, and
//! repeat under a block budget. Resident blocks are reused only after checking
//! the current execute translation and the memory owner's code generation.
use crate::exception::{Exception, take_exception};
use crate::handler::{
    self, CodeGeneration, Event, ExclusiveMonitor, GuestMemory, InlineRam, MemoryFault, Outcome,
};
use crate::mmu::{self, AccessClass, PermissionMode, Stage1Error, Stage1Registers};
use crate::state::{CpuState, ExceptionLevel, ProgramCounter, VirtualAddress};
use crate::translate::{
    BlockExit, BlockLimits, CODE_PAGE_BYTES, ExitReason, GuestInstruction, InstructionClass,
    TranslateError, TranslatedBlock, emit_block, split_block_for_run,
};
use carrick_guest_arch::{FrameGpa, Gpa, GuestVa};
use carrick_mmu_core::stage1::{LeafAccess, Stage1Leaf};
use carrick_softmmu::block_cache::BlockCache;
use carrick_softmmu::physical_tlb::PhysicalTlb;
use core::fmt;

/// Permission-checked virtual page tags and RAM loans, live for one launch.
#[derive(Default)]
pub struct BlockMemory<'a> {
    pub read: Option<GuestVa>,
    pub write: Option<GuestVa>,
    pub ram: InlineRam<'a>,
}

/// Prepares translated code and runs it against the CPU's architectural state.
/// The implementation owns executable memory; this crate never executes it.
pub trait ExecuteBlock {
    type Error;
    type Code;

    /// Whether the dispatcher may keep prepared blocks resident.
    fn retain_blocks(&self) -> bool {
        true
    }

    /// Whether to cache stage-1 translations on providers with a local seat.
    fn retain_stage1(&self) -> bool {
        true
    }

    fn inline_memory(&self) -> bool {
        false
    }

    fn execute_with_memory(
        &mut self,
        block: &TranslatedBlock,
        code: &Self::Code,
        cpu: &mut CpuState,
        _memory: BlockMemory<'_>,
    ) -> Result<usize, Self::Error> {
        self.execute(block, code, cpu)
    }

    fn prepare(&mut self, block: &TranslatedBlock) -> Result<Self::Code, Self::Error>;

    /// Run the code prepared for `block`, update `cpu` on success, and return the
    /// index into the block's exit table.
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        code: &Self::Code,
        cpu: &mut CpuState,
    ) -> Result<usize, Self::Error>;
}

/// Why `run` returned. `cpu` holds the exact state at that point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop<E> {
    /// The block budget was spent; `cpu.pc` is the next block.
    Budget,
    /// The first word of a block could not be fetched.
    Fetch(VirtualAddress),
    /// A handler event the dispatcher does not absorb, at the instruction's PC.
    Event {
        instruction: GuestInstruction,
        event: Event,
    },
    Translate(TranslateError),
    /// The host launch failed, or returned an exit index outside the table.
    Execute(E),
    BadExit(usize),
}

/// Guest-engine work performed during one bounded run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunWork {
    pub retired_instructions: u64,
    /// Host launch attempts.
    pub dispatches: u64,
    /// Host launches that returned a valid exit index.
    pub executed_blocks: u64,
    /// Calls to split and decode a block.
    pub decoded_blocks: u64,
    /// Calls to emit a decoded block.
    pub emitted_blocks: u64,
    pub stage1_walks: u64,
    /// Exits into a scalar, pair, atomic or cache-zero memory handler.
    pub memory_exits: u64,
}

/// The result of a bounded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<E> {
    /// Budget steps, including instruction aborts taken before a launch.
    pub blocks: u64,
    pub work: RunWork,
    pub pc: ProgramCounter,
    pub stop: Stop<E>,
}

impl<E: fmt::Debug> fmt::Display for Report<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "boots to PC={:#x} after {} blocks / ",
            self.pc.0, self.blocks
        )?;
        match self.stop {
            Stop::Budget => write!(f, "stops at the block budget"),
            Stop::Fetch(a) => write!(f, "fails at: instruction fetch from {:#x}", a.0),
            Stop::Event {
                instruction: i,
                event: Event::MmuEnable { value },
            } => write!(
                f,
                "fails at: SCTLR_EL1.M enable at PC={:#x} (word {:#010x}, value {:#x})",
                i.pc().0,
                i.word(),
                value.0
            ),
            Stop::Event {
                instruction: i,
                event: Event::MemoryFault(m),
            } => write!(
                f,
                "fails at: unmapped guest access {:#x} at PC={:#x} (word {:#010x}, {:?})",
                m.address.0,
                i.pc().0,
                i.word(),
                i.instruction()
            ),
            Stop::Event {
                instruction: i,
                event,
            } => write!(
                f,
                "fails at: {:?} at PC={:#x} (word {:#010x}, {:?})",
                event,
                i.pc().0,
                i.word(),
                i.class()
            ),
            Stop::Translate(e) => write!(f, "fails at: translation {e:?}"),
            Stop::Execute(ref e) => write!(f, "fails at: host launch {e:?}"),
            Stop::BadExit(i) => write!(f, "fails at: exit index {i} outside the block"),
        }
    }
}

/// Events the dispatcher absorbs and continues past.
fn absorbed(event: Event) -> bool {
    matches!(
        event,
        Event::Tlbi(_)
            | Event::Ic(_)
            | Event::IcFrame(_)
            | Event::Hint(crate::Hint::Sev | crate::Hint::Sevl)
    )
}

fn fetch_address(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    pc: ProgramCounter,
) -> Result<Gpa, Stage1Error> {
    mmu::translate(
        cpu,
        memory,
        pc.0,
        LeafAccess::Execute,
        AccessClass::Ordinary,
    )
    .map(Gpa::new)
}

fn read_word(memory: &mut impl GuestMemory, pa: Gpa) -> Result<u32, MemoryFault> {
    let mut bytes = [0; 4];
    memory.read(VirtualAddress(pa.raw()), &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BlockKey {
    pc: u64,
    registers: Stage1Registers,
    el1: bool,
}

impl BlockKey {
    fn for_cpu(cpu: &CpuState) -> Self {
        Self {
            pc: cpu.pc.0,
            registers: Stage1Registers::for_cpu(cpu),
            el1: cpu.pstate.el == ExceptionLevel::El1,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CodeIdentity {
    frame: FrameGpa,
    generation: CodeGeneration,
}

struct ResidentBlock<C> {
    identity: CodeIdentity,
    prepared: (TranslatedBlock, C),
}

struct MeasuredMemory<'a, M> {
    inner: &'a mut M,
    walks: u64,
    retain_stage1: bool,
    tlb: Option<PhysicalTlb<Stage1Registers, PermissionMode>>,
    last_read: Option<GuestVa>,
    last_write: Option<GuestVa>,
}

impl<M: GuestMemory> MeasuredMemory<'_, M> {
    fn inline_ram(
        &mut self,
        cpu: &CpuState,
        code_frame: FrameGpa,
        monitor: &ExclusiveMonitor,
    ) -> BlockMemory<'_> {
        let Some(tlb) = self.tlb.as_mut() else {
            return BlockMemory::default();
        };
        let regime = Stage1Registers::for_cpu(cpu);
        let mut probe = |page, access| {
            tlb.probe(
                regime,
                page,
                access,
                PermissionMode::for_access(cpu, access, AccessClass::Ordinary),
            )
            .map(Gpa::to_frame_gpa)
        };
        let read = self
            .last_read
            .and_then(|page| probe(page, LeafAccess::Read));
        let write = self
            .last_write
            .filter(|_| !monitor.is_open())
            .and_then(|page| probe(page, LeafAccess::Write))
            .filter(|frame| *frame != code_frame);
        BlockMemory {
            read: self.last_read,
            write: self.last_write,
            ram: self.inner.inline_ram(read, write),
        }
    }
}

impl<M: GuestMemory> GuestMemory for MeasuredMemory<'_, M> {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.inner.read(address, bytes)
    }

    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        self.inner.write(address, bytes)
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.inner.code_generation(frame)
    }

    fn invalidate_code_frame(&mut self, frame: FrameGpa) -> Result<bool, MemoryFault> {
        self.inner.invalidate_code_frame(frame)
    }

    fn translate_stage1(
        &mut self,
        cpu: &CpuState,
        va: GuestVa,
        access: LeafAccess,
        class: AccessClass,
    ) -> Result<Gpa, Stage1Error> {
        let mode = PermissionMode::for_access(cpu, access, class);
        if self.retain_stage1 {
            if class == AccessClass::Ordinary {
                let page = Some(GuestVa::new(va.raw() & !(CODE_PAGE_BYTES - 1)));
                match access {
                    LeafAccess::Read => self.last_read = page,
                    LeafAccess::Write => self.last_write = page,
                    LeafAccess::Execute => {}
                }
            }
            let tlb = self.tlb.get_or_insert_with(PhysicalTlb::default);
            if let Some(pa) = tlb.probe(Stage1Registers::for_cpu(cpu), va, access, mode) {
                return Ok(pa);
            }
        }
        let leaf = mmu::walk(cpu, self, va.raw(), access, class)?;
        let pa = Gpa::from_frame_gpa(leaf.output());
        if let Some(tlb) = &mut self.tlb {
            tlb.fill(va, access, mode, pa);
        }
        Ok(pa)
    }

    fn record_stage1_walk(&mut self) {
        self.walks += 1;
        self.inner.record_stage1_walk();
    }
}

/// Run at most `budget` blocks from `cpu.pc`.
pub fn run<X: ExecuteBlock>(
    cpu: &mut CpuState,
    monitor: &mut ExclusiveMonitor,
    memory: &mut impl GuestMemory,
    executor: &mut X,
    limits: BlockLimits,
    budget: u64,
) -> Report<X::Error> {
    let mut blocks = 0;
    let mut work = RunWork::default();
    let memory = &mut MeasuredMemory {
        retain_stage1: executor.retain_stage1() && memory.stage1_is_local(),
        inner: memory,
        walks: 0,
        tlb: None,
        last_read: None,
        last_write: None,
    };
    let inline_memory = memory.retain_stage1 && executor.inline_memory();
    // The run borrows one memory owner and one set of block limits. Keeping
    // residency within that borrow also discards code at provider handoffs.
    let mut cache = BlockCache::<BlockKey, ResidentBlock<X::Code>>::default();
    let retain_blocks = executor.retain_blocks();
    let stop = loop {
        if blocks >= budget {
            break Stop::Budget;
        }
        // DDI0487G.a D1.12.4: PC alignment precedes instruction aborts
        // and illegal execution state, so both checks precede block fetch.
        if !cpu.pc.0.is_multiple_of(4) {
            take_exception(cpu, Exception::PcAlignment);
        } else if cpu.pstate.il {
            take_exception(cpu, Exception::IllegalExecutionState);
        }
        // D5.8: an instruction abort on the block's first word is taken at
        // that PC; later words that fault end the block before them, and
        // fault as the first word of the next block.
        let pa = match fetch_address(cpu, memory, cpu.pc) {
            Ok(pa) => pa,
            Err(Stage1Error::Abort(fault)) => match mmu::fault_exception(fault) {
                Some(exception) => {
                    // A taken abort spends one budget step, so a vector that
                    // itself faults cannot spin without bound.
                    take_exception(cpu, exception);
                    blocks += 1;
                    continue;
                }
                None => break Stop::Fetch(VirtualAddress(cpu.pc.0)),
            },
            Err(_) => break Stop::Fetch(VirtualAddress(cpu.pc.0)),
        };
        let key = BlockKey::for_cpu(cpu);
        let frame = Gpa::new(pa.raw() & !(CODE_PAGE_BYTES - 1)).to_frame_gpa();
        let code = if retain_blocks {
            memory
                .code_generation(frame)
                .map(|generation| CodeIdentity { frame, generation })
        } else {
            None
        };
        let uncached;
        let (block, executable) =
            if let Some(resident) = cache.get(&key).filter(|r| Some(r.identity) == code) {
                &resident.prepared
            } else {
                let Ok(first) = read_word(memory, pa) else {
                    break Stop::Fetch(VirtualAddress(cpu.pc.0));
                };
                work.decoded_blocks += 1;
                let mut fetched_whole_block = true;
                let guest =
                    split_block_for_run(cpu.pc, limits, inline_memory && mmu::enabled(cpu), |pc| {
                        let word = if pc == cpu.pc {
                            Some(first)
                        } else {
                            fetch_address(cpu, memory, pc)
                                .ok()
                                .and_then(|pa| read_word(memory, pa).ok())
                        };
                        fetched_whole_block &= word.is_some();
                        word
                    });
                work.emitted_blocks += 1;
                let block = match emit_block(&guest) {
                    Ok(block) => block,
                    Err(error) => break Stop::Translate(error),
                };
                let executable = match executor.prepare(&block) {
                    Ok(code) => code,
                    Err(error) => break Stop::Execute(error),
                };
                let prepared = (block, executable);
                let identity = if retain_blocks && fetched_whole_block {
                    memory
                        .inner
                        .mark_code_page(frame)
                        .map(|generation| CodeIdentity { frame, generation })
                } else {
                    None
                };
                if let Some(identity) = identity {
                    &cache
                        .insert(key, ResidentBlock { identity, prepared })
                        .prepared
                } else {
                    uncached = prepared;
                    &uncached
                }
            };
        work.dispatches += 1;
        let inline_ram = if block.has_inline_memory() {
            memory.inline_ram(cpu, frame, monitor)
        } else {
            BlockMemory::default()
        };
        let index = match executor.execute_with_memory(block, executable, cpu, inline_ram) {
            Ok(i) => i,
            Err(e) => break Stop::Execute(e),
        };
        blocks += 1;
        let Some(exit) = block.exits().get(index).copied() else {
            break Stop::BadExit(index);
        };
        work.executed_blocks += 1;
        let instructions = block.guest().instructions().len() as u64;
        match exit {
            BlockExit::Continue(pc) => {
                work.retired_instructions += instructions;
                cpu.pc = pc;
            }
            BlockExit::Handler(i) => {
                // The generated block retires the prefix before the handler.
                work.retired_instructions += i.pc().0.wrapping_sub(block.guest().start().0) / 4;
                if i.class() == InstructionClass::Exit(ExitReason::Memory)
                    || matches!(i.instruction(), crate::Instruction::DataCacheZero(_))
                {
                    work.memory_exits += 1;
                }
                cpu.pc = i.pc();
                match handler::execute(cpu, monitor, memory, &i) {
                    Outcome::Continue => {
                        work.retired_instructions += 1;
                        // A flat access bypasses the TLB. Drop the previous
                        // regime now, even if the guest later restores its
                        // exact register values before re-enabling stage 1.
                        if memory.tlb.is_some() && !mmu::enabled(cpu) {
                            memory.tlb = None;
                        }
                    }
                    Outcome::Fault => {}
                    Outcome::Event(event) => {
                        match event {
                            Event::Ic(_) => cache.clear(),
                            Event::Tlbi(_) => {
                                // One local seat. A full flush also covers every
                                // cached 4 KiB subpage of a large stage-1 leaf.
                                if let Some(tlb) = &mut memory.tlb {
                                    tlb.invalidate();
                                }
                            }
                            _ => {}
                        }
                        if matches!(
                            event,
                            Event::ProviderExit(_)
                                | Event::Tlbi(_)
                                | Event::Ic(_)
                                | Event::IcFrame(_)
                                | Event::Hint(_)
                        ) {
                            work.retired_instructions += 1;
                        }
                        if !absorbed(event) {
                            break Stop::Event {
                                instruction: i,
                                event,
                            };
                        }
                    }
                }
            }
        }
    };
    work.stage1_walks = memory.walks;
    Report {
        blocks,
        work,
        pc: cpu.pc,
        stop,
    }
}

#[cfg(test)]
mod tests {
    //! Dispatcher tests. `GuestSemantics` is a test-only `ExecuteBlock` double
    //! that applies a block's guest meaning for a tiny instruction subset; it
    //! exists only to drive the dispatcher's exit mapping and is never a
    //! product path (the product launch runs the emitted host words).
    extern crate std;
    use super::*;
    use crate::state::{ExceptionLevel, StackSelect};
    use crate::translate::{BlockFrame, Terminator, frame};
    use crate::{
        AddSubtract, ArithmeticOperand, Branch, Condition, Instruction, MoveWideOperation,
    };
    use std::collections::BTreeMap;

    struct GuestSemantics;

    fn gpr(frame: &BlockFrame, r: crate::OperandRegister) -> u64 {
        match r {
            crate::OperandRegister::Gpr(g) => frame.slots[usize::from(g.number())],
            crate::OperandRegister::Zr => 0,
            crate::OperandRegister::Sp => frame.slots[(frame::GUEST_SP / 8) as usize],
        }
    }
    fn set(frame: &mut BlockFrame, r: crate::OperandRegister, v: u64) {
        match r {
            crate::OperandRegister::Gpr(g) => frame.slots[usize::from(g.number())] = v,
            crate::OperandRegister::Zr => {}
            crate::OperandRegister::Sp => frame.slots[(frame::GUEST_SP / 8) as usize] = v,
        }
    }

    impl ExecuteBlock for GuestSemantics {
        type Error = &'static str;
        type Code = ();
        fn prepare(&mut self, _: &TranslatedBlock) -> Result<(), Self::Error> {
            Ok(())
        }

        fn execute(
            &mut self,
            block: &TranslatedBlock,
            _: &(),
            cpu: &mut CpuState,
        ) -> Result<usize, &'static str> {
            let mut frame = BlockFrame::from_cpu(cpu);
            let f = &mut frame;
            let nzcv = (frame::NZCV / 8) as usize;
            for i in block.guest().instructions() {
                match i.instruction() {
                    Instruction::MoveWide(m) => {
                        let shift = u32::from(m.shift.value());
                        let imm = u64::from(m.immediate) << shift;
                        let v = match m.operation {
                            MoveWideOperation::Zero => imm,
                            MoveWideOperation::Keep => (gpr(f, m.rd) & !(0xffff << shift)) | imm,
                            MoveWideOperation::Not => !imm,
                        };
                        set(f, m.rd, v);
                    }
                    Instruction::Arithmetic(a) => {
                        let ArithmeticOperand::Immediate(imm) = a.operand else {
                            return Err("double: register operands");
                        };
                        let n = gpr(f, a.rn);
                        let r = match a.op {
                            AddSubtract::Add => n.wrapping_add(imm.value()),
                            AddSubtract::Subtract => n.wrapping_sub(imm.value()),
                        };
                        if a.set_flags {
                            let z = u64::from(r == 0) << 30;
                            let neg = (r >> 63) << 31;
                            let c = u64::from(match a.op {
                                AddSubtract::Add => r < n,
                                AddSubtract::Subtract => n >= imm.value(),
                            }) << 29;
                            f.slots[nzcv] = neg | z | c;
                        }
                        set(f, a.rd, r);
                    }
                    Instruction::Hint(crate::Hint::Nop) | Instruction::Barrier(_) => {}
                    _ if i.class().terminates() => {}
                    _ => return Err("double: instruction outside its subset"),
                }
            }
            let index = match block.terminator() {
                Terminator::Handler(e) | Terminator::Jump(e) | Terminator::Fallthrough(e) => e,
                Terminator::Conditional { fallthrough, taken } => {
                    let Some(Instruction::Branch(Branch::Conditional { condition, .. })) =
                        block.guest().terminator().map(|t| t.instruction())
                    else {
                        return Err("double: only B.cond");
                    };
                    let z = f.slots[nzcv] & (1 << 30) != 0;
                    match condition {
                        Condition::Eq if z => taken,
                        Condition::Ne if !z => taken,
                        Condition::Eq | Condition::Ne => fallthrough,
                        _ => return Err("double: only EQ/NE"),
                    }
                }
            };
            frame.store_to(cpu);
            Ok(index)
        }
    }

    /// Lies about its exit index, to witness the dispatcher's bounds check.
    struct WrongExit;
    impl ExecuteBlock for WrongExit {
        type Error = ();
        type Code = ();
        fn prepare(&mut self, _: &TranslatedBlock) -> Result<(), ()> {
            Ok(())
        }
        fn execute(&mut self, b: &TranslatedBlock, _: &(), _: &mut CpuState) -> Result<usize, ()> {
            Ok(b.exits().len())
        }
    }

    #[derive(Default)]
    struct Flat(BTreeMap<u64, u8>);
    impl Flat {
        fn code(&mut self, at: u64, words: &[u32]) {
            for (i, w) in words.iter().enumerate() {
                for (j, b) in w.to_le_bytes().iter().enumerate() {
                    self.0.insert(at + 4 * i as u64 + j as u64, *b);
                }
            }
        }
    }
    impl GuestMemory for Flat {
        fn read(&mut self, a: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = *self.0.get(&(a.0 + i as u64)).ok_or(MemoryFault {
                    address: VirtualAddress(a.0 + i as u64),
                })?;
            }
            Ok(())
        }
        fn write(&mut self, a: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
            for (i, b) in bytes.iter().enumerate() {
                self.0.insert(a.0 + i as u64, *b);
            }
            Ok(())
        }
    }

    const ENTRY: u64 = 0x4000;
    const VBAR: u64 = 0x8000;

    fn el1() -> CpuState {
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(VBAR);
        cpu.pc = ProgramCounter(ENTRY);
        cpu
    }

    fn go<X: ExecuteBlock>(
        cpu: &mut CpuState,
        m: &mut Flat,
        x: &mut X,
        budget: u64,
    ) -> Report<X::Error> {
        run(
            cpu,
            &mut ExclusiveMonitor::default(),
            m,
            x,
            BlockLimits::default(),
            budget,
        )
    }

    #[test]
    fn run_work_distinguishes_retired_instructions_from_memory_exits() {
        let mut m = Flat::default();
        // movz x1, #0; ldr x2, [x1]; hvc #2
        m.code(ENTRY, &[0xd280_0001, 0xf940_0022, 0xd400_0042]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::MemoryFault(_),
                ..
            }
        ));
        assert_eq!(r.blocks, 1);
        assert_eq!(
            r.work,
            RunWork {
                retired_instructions: 1,
                dispatches: 1,
                executed_blocks: 1,
                decoded_blocks: 1,
                emitted_blocks: 1,
                stage1_walks: 0,
                memory_exits: 1,
            }
        );

        m.code(0, &[42, 0]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(r.work.retired_instructions, 3);
        assert_eq!(r.work.memory_exits, 1);

        // A fault delivered to the guest vector never retired.
        m.code(ENTRY, &[0xd280_0001, 0]);
        m.code(VBAR + 0x200, &[0xd400_0042]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
        assert_eq!(r.work.retired_instructions, 2);
    }

    #[test]
    fn loop_svc_vector_and_hvc_reach_the_provider_exit() {
        let mut m = Flat::default();
        // movz x0, #3 ; loop: subs x0, x0, #1 ; b.ne loop ; svc #0
        m.code(ENTRY, &[0xd2800060, 0xf1000400, 0x54ffffe1, 0xd4000001]);
        // EL1h synchronous vector: movz x1, #7 ; hvc #2
        m.code(VBAR + 0x200, &[0xd28000e1, 0xd4000042]);
        let mut cpu = el1();
        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 100);
        // Blocks: [movz,subs,b.ne] + 2x[subs,b.ne] + [svc] + [movz,hvc].
        assert_eq!(r.blocks, 5);
        let Stop::Event {
            instruction,
            event: Event::ProviderExit(exit),
        } = r.stop
        else {
            panic!("{r}");
        };
        assert_eq!(
            (instruction.pc().0, exit.immediate.value()),
            (VBAR + 0x204, 2)
        );
        assert_eq!(r.pc, ProgramCounter(VBAR + 0x208));
        assert_eq!(cpu.el1.elr, ProgramCounter(ENTRY + 16));
        let x = |n| cpu.read_operand(crate::OperandRegister::field(n, false)).0;
        assert_eq!((x(0), x(1)), (0, 7));
        assert_eq!(cpu.pstate.nzcv & 0b0100, 0b0100, "Z from the last subs");
    }

    #[test]
    fn budget_fetch_and_mmu_enable_stop_with_exact_pcs() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0x14000000]); // b . (self loop)
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 3);
        assert_eq!(
            (r.blocks, r.pc, r.stop),
            (3, ProgramCounter(ENTRY), Stop::Budget)
        );

        let r = go(&mut el1(), &mut Flat::default(), &mut GuestSemantics, 3);
        assert_eq!(r.stop, Stop::Fetch(VirtualAddress(ENTRY)));
        assert_eq!(
            std::format!("{r}"),
            "boots to PC=0x4000 after 0 blocks / fails at: instruction fetch from 0x4000"
        );

        let mut m = Flat::default();
        // movz x0, #1 ; msr sctlr_el1, x0
        m.code(ENTRY, &[0xd2800020, 0xd5181000]);
        let mut cpu = el1();
        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 10);
        assert_eq!(
            std::format!("{r}"),
            "boots to PC=0x4004 after 1 blocks / fails at: SCTLR_EL1.M enable at \
             PC=0x4004 (word 0xd5181000, value 0x1)"
        );
        assert_eq!(cpu.el1.sctlr.0, 0);
    }

    #[test]
    fn an_exit_index_outside_the_table_is_a_launch_defect() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0xd4000001]);
        let r = go(&mut el1(), &mut m, &mut WrongExit, 10);
        assert_eq!(r.stop, Stop::BadExit(1));
        assert_eq!(r.pc, ProgramCounter(ENTRY));
    }

    #[test]
    fn misaligned_pc_takes_priority_over_illegal_execution_state() {
        for (el, sp, offset, mode) in [
            (ExceptionLevel::El0, StackSelect::El0, 0x400, 0),
            (ExceptionLevel::El1, StackSelect::El0, 0, 4),
            (ExceptionLevel::El1, StackSelect::El1, 0x200, 5),
        ] {
            let mut cpu = el1();
            cpu.pc = ProgramCounter(ENTRY + 2);
            cpu.pstate.el = el;
            cpu.pstate.sp = sp;
            cpu.pstate.il = true;
            let mut m = Flat::default();
            m.code(VBAR + offset, &[0xd4000002]); // hvc #0
            let r = go(&mut cpu, &mut m, &mut GuestSemantics, 1);
            assert!(
                matches!(
                    r.stop,
                    Stop::Event {
                        event: Event::ProviderExit(_),
                        ..
                    }
                ),
                "{r}"
            );
            assert_eq!(cpu.el1.esr.0, 0x8a00_0000);
            assert_eq!(cpu.el1.far.0, ENTRY + 2);
            assert_eq!(cpu.el1.elr.0, ENTRY + 2);
            assert_eq!(cpu.el1.spsr.0, (1 << 20) | mode);
            assert!(!cpu.pstate.il);
        }
    }

    #[test]
    fn restored_il_takes_an_exception_before_the_next_guest_instruction() {
        for (saved_mode, vector, expected_mode) in [
            (1 << 20, 0x400, 0), // legal EL0t return with SPSR.IL set
            (8, 0x200, 5),       // illegal EL2t return retains EL1h
        ] {
            let mut cpu = el1();
            cpu.el1.spsr = crate::state::SavedPstate(saved_mode);
            cpu.el1.elr = ProgramCounter(ENTRY + 4);
            let mut m = Flat::default();
            m.code(ENTRY, &[0xd69f03e0, 0xd28000e0]); // eret; movz x0, #7
            m.code(VBAR + vector, &[0xd4000002]); // hvc #0
            let r = go(&mut cpu, &mut m, &mut GuestSemantics, 2);
            assert!(
                matches!(
                    r.stop,
                    Stop::Event {
                        event: Event::ProviderExit(_),
                        ..
                    }
                ),
                "{r}"
            );
            assert_eq!(cpu.el1.esr.0, 0x3a00_0000);
            assert_eq!(cpu.el1.elr.0, ENTRY + 4);
            assert_eq!(cpu.el1.spsr.0 & 0x10_001f, (1 << 20) | expected_mode);
            assert_eq!(
                cpu.read_operand(crate::OperandRegister::field(0, false)).0,
                0
            );
            assert!(!cpu.pstate.il);
        }
    }

    #[test]
    fn svc_and_eret_restore_the_origin_and_signal_one_local_event() {
        for (el, sp, offset, mode) in [
            (ExceptionLevel::El0, StackSelect::El0, 0x400, 0),
            (ExceptionLevel::El1, StackSelect::El0, 0, 4),
            (ExceptionLevel::El1, StackSelect::El1, 0x200, 5),
        ] {
            let mut cpu = el1();
            cpu.pstate.el = el;
            cpu.pstate.sp = sp;
            cpu.pstate.nzcv = 0xa;
            cpu.pstate.daif.0 = 5;
            cpu.pstate.uao = true;
            let initial = cpu.pstate;
            // Permit WFE so a second wait reports a suspension at either EL.
            cpu.el1.sctlr.0 = 1 << 18;
            let mut m = Flat::default();
            m.code(ENTRY, &[0xd40000e1, 0xd503205f, 0xd503205f]); // svc #7; wfe; wfe
            m.code(VBAR + offset, &[0xd69f03e0]); // eret

            let entry = go(&mut cpu, &mut m, &mut GuestSemantics, 1);
            assert_eq!(entry.pc, ProgramCounter(VBAR + offset));
            assert_eq!(cpu.el1.esr.0, 0x5600_0007);
            assert_eq!(cpu.el1.elr.0, ENTRY + 4);
            assert_eq!(cpu.el1.spsr.0, 0xa080_0140 | mode);
            assert_eq!(cpu.pstate.sp, StackSelect::El1);
            assert_eq!(cpu.pstate.daif.0, 15);
            assert!(cpu.pstate.pan);
            assert!(!cpu.pstate.uao);

            let returned = go(&mut cpu, &mut m, &mut GuestSemantics, 3);
            assert_eq!(cpu.pstate, initial);
            let Stop::Event {
                instruction,
                event: Event::Hint(crate::Hint::Wfe),
            } = returned.stop
            else {
                panic!("{returned}");
            };
            assert_eq!(instruction.pc().0, ENTRY + 8);
            assert_eq!(returned.pc.0, ENTRY + 12);
        }
    }

    #[test]
    fn isb_retires_and_starts_a_new_dispatch_at_the_next_word() {
        let mut m = Flat::default();
        m.code(ENTRY, &[0xd503_3fdf, 0xd400_0002]); // isb; hvc #0
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 2);
        assert_eq!((r.blocks, r.pc), (2, ProgramCounter(ENTRY + 8)));
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
    }

    #[test]
    fn tlbi_is_absorbed_and_execution_continues() {
        let mut m = Flat::default();
        // tlbi vmalle1 ; hvc #0
        m.code(ENTRY, &[0xd508871f, 0xd4000002]);
        let r = go(&mut el1(), &mut m, &mut GuestSemantics, 10);
        assert_eq!(r.blocks, 2);
        assert!(matches!(
            r.stop,
            Stop::Event {
                event: Event::ProviderExit(_),
                ..
            }
        ));
    }

    #[test]
    fn production_el0_entry_trampoline_drops_to_el0_and_enters_lower_el_svc_vector() {
        use crate::state::{InterruptMasks, SavedPstate};
        let trampoline = carrick_mem::memory::el0_trampoline_bytes();
        let words: std::vec::Vec<u32> = trampoline
            .chunks_exact(4)
            .take(8)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        let tramp_base = carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
        let user_entry = 0x21_0120;
        let mut m = Flat::default();
        m.code(tramp_base, &words);
        // Unmodified EL0 SVC #0 at user entry.
        m.code(user_entry, &[0xd400_0001]);
        // Current-EL sync fault vector (hvc #3) vs Lower-EL sync vector (hvc #2).
        m.code(VBAR + 0x200, &[0xd400_0062]);
        m.code(VBAR + 0x400, &[0xd400_0042]);

        let mut cpu = el1();
        cpu.pc = ProgramCounter(tramp_base);
        cpu.pstate.daif = InterruptMasks::ALL;
        cpu.el1.elr = ProgramCounter(user_entry);
        // SPSR_EL1 = EL0t with DAIF masked (0x3c0), matching StagedCpu::initial_root.
        cpu.el1.spsr = SavedPstate(0x3c0);

        let r = go(&mut cpu, &mut m, &mut GuestSemantics, 16);
        let Stop::Event {
            instruction,
            event: Event::ProviderExit(exit),
        } = r.stop
        else {
            panic!("{r}");
        };
        assert_eq!(
            (instruction.pc().0, exit.immediate.value()),
            (VBAR + 0x400, 2),
            "expected lower-EL SVC vector (HVC #2), got ESR={:#x} ELR={:#x}: {r}",
            cpu.el1.esr.0,
            cpu.el1.elr.0
        );
        assert_eq!(cpu.el1.elr, ProgramCounter(user_entry + 4));
        assert_eq!(cpu.el1.esr.0, (0x15 << 26) | (1 << 25));
    }
}
