//! The dispatcher: split and translate the block at `cpu.pc`, run it through
//! an `ExecuteBlock` (the host launch, implemented outside this crate on an
//! arm64 host), map the exit index back to a guest exit, run its handler, and
//! repeat under a block budget. No translation cache in this slice: see
//! docs/design/soft-aarch64-translator.md, "Cache".
use crate::exception::{Exception, take_exception};
use crate::handler::{self, Event, ExclusiveMonitor, GuestMemory, Outcome};
use crate::mmu::{self, AccessClass, Stage1Error};
use crate::state::{CpuState, ProgramCounter, VirtualAddress};
use crate::translate::{
    BlockExit, BlockFrame, BlockLimits, GuestInstruction, TranslateError, TranslatedBlock,
    emit_block, split_block,
};
use carrick_mmu_core::stage1::LeafAccess;
use core::fmt;

/// Runs one translated block against `frame` and returns its exit index.
/// The implementation owns executable memory; this crate never executes.
pub trait ExecuteBlock {
    type Error;
    fn execute(
        &mut self,
        block: &TranslatedBlock,
        frame: &mut BlockFrame,
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

/// The result of a bounded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<E> {
    pub blocks: u64,
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

/// Events the dispatcher absorbs and continues past. There is no translation
/// cache, so a TLBI has nothing to invalidate; NOP-like hints never stop.
fn absorbed(event: Event) -> bool {
    matches!(
        event,
        Event::Tlbi(_) | Event::Hint(crate::Hint::Sev | crate::Hint::Sevl)
    )
}

/// Fetch one instruction word, stage-1 translated when SCTLR_EL1.M is set.
fn fetch(
    cpu: &CpuState,
    memory: &mut impl GuestMemory,
    pc: ProgramCounter,
) -> Result<u32, Option<Stage1Error>> {
    let pa = mmu::translate(
        cpu,
        memory,
        pc.0,
        LeafAccess::Execute,
        AccessClass::Ordinary,
    )
    .map_err(Some)?;
    let mut bytes = [0; 4];
    memory
        .read(VirtualAddress(pa), &mut bytes)
        .map_err(|_| None)?;
    Ok(u32::from_le_bytes(bytes))
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
        match fetch(cpu, memory, cpu.pc) {
            Ok(_) => {}
            Err(Some(Stage1Error::Abort(fault))) => match mmu::fault_exception(fault) {
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
        }
        let guest = {
            let cpu = &*cpu;
            split_block(cpu.pc, limits, |pc| fetch(cpu, memory, pc).ok())
        };
        if guest.instructions().is_empty() {
            break Stop::Fetch(VirtualAddress(cpu.pc.0));
        }
        let block = match emit_block(&guest) {
            Ok(b) => b,
            Err(e) => break Stop::Translate(e),
        };
        let mut frame = BlockFrame::from_cpu(cpu);
        let index = match executor.execute(&block, &mut frame) {
            Ok(i) => i,
            Err(e) => break Stop::Execute(e),
        };
        frame.store_to(cpu);
        blocks += 1;
        match block.exits().get(index) {
            None => break Stop::BadExit(index),
            Some(BlockExit::Continue(pc)) => cpu.pc = *pc,
            Some(BlockExit::Handler(i)) => {
                cpu.pc = i.pc();
                match handler::execute(cpu, monitor, memory, i) {
                    Outcome::Continue => {}
                    Outcome::Event(e) if absorbed(e) => {}
                    Outcome::Event(event) => {
                        break Stop::Event {
                            instruction: *i,
                            event,
                        };
                    }
                }
            }
        }
    };
    Report {
        blocks,
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
    use crate::handler::MemoryFault;
    use crate::state::{ExceptionLevel, StackSelect};
    use crate::translate::{Terminator, frame};
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
        fn execute(
            &mut self,
            block: &TranslatedBlock,
            f: &mut BlockFrame,
        ) -> Result<usize, &'static str> {
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
                    Instruction::Hint(crate::Hint::Nop) => {}
                    _ if i.class().terminates() => {}
                    _ => return Err("double: instruction outside its subset"),
                }
            }
            Ok(match block.terminator() {
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
            })
        }
    }

    /// Lies about its exit index, to witness the dispatcher's bounds check.
    struct WrongExit;
    impl ExecuteBlock for WrongExit {
        type Error = ();
        fn execute(&mut self, b: &TranslatedBlock, _: &mut BlockFrame) -> Result<usize, ()> {
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
}
