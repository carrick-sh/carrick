//! Native copy-through translation, host-independent half
//! (docs/design/soft-aarch64-translator.md). Guest A64 words become host A64
//! words: register-only words are copied, PC-relative words are rewritten as
//! immediates, branches are relocated, and everything else leaves the block
//! through an exit stub. No word is executed here.
//! Encodings: Arm ARM DDI0487G.a C4.1 encoding index and C6.2 instruction
//! pages (LDP/STP C6.2.130/C6.2.277, LDR/STR immediate C6.2.132/C6.2.278,
//! ADD immediate C6.2.4, MOVZ/MOVK C6.2.193/C6.2.191, B C6.2.26, RET C6.2.219,
//! MRS/MSR C6.2.194/C6.2.196, B.cond C6.2.25, CBZ C6.2.45, TBZ C6.2.331).
use crate::state::{CpuState, ProgramCounter, RegisterValue, StackPointer};
use crate::{
    AddressBase, Branch, Decoded, ExceptionKind, Gpr, Hint, Instruction, LogicalOperand,
    OperandRegister, RegisterBranch, decode_instruction,
};
use alloc::vec::Vec;

/// How a copy-through word reaches the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyKind {
    /// The guest word runs unchanged.
    Verbatim,
    /// The word names SP; it runs against a scratch register holding guest SP.
    StackPointer,
    /// ADR/ADRP: the guest PC is known, so Rd is loaded with an immediate.
    PcRelative,
}

/// Why an instruction leaves native execution for a Rust handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Memory,
    SystemRegister,
    Pstate,
    SystemOperation,
    AddressTranslate,
    ClearExclusive,
    Exception(ExceptionKind),
    Eret,
    Hint(Hint),
    Undefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchKind {
    Direct { link: bool },
    Conditional,
    Indirect(RegisterBranch),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionClass {
    Copy(CopyKind),
    Exit(ExitReason),
    Branch(BranchKind),
}

impl InstructionClass {
    /// True for every class that ends a block.
    pub fn terminates(self) -> bool {
        !matches!(self, Self::Copy(_))
    }
}

/// Classify one typed instruction for the copy-through engine.
pub fn classify_instruction(instruction: Instruction) -> InstructionClass {
    match instruction {
        Instruction::Arithmetic(a) => {
            if a.rd == OperandRegister::Sp || a.rn == OperandRegister::Sp {
                InstructionClass::Copy(CopyKind::StackPointer)
            } else {
                InstructionClass::Copy(CopyKind::Verbatim)
            }
        }
        Instruction::Logical(l) => {
            if l.rd == OperandRegister::Sp || l.rn == OperandRegister::Sp {
                InstructionClass::Copy(CopyKind::StackPointer)
            } else {
                InstructionClass::Copy(CopyKind::Verbatim)
            }
        }
        Instruction::MoveWide(_)
        | Instruction::Bitfield(_)
        | Instruction::Extract(_)
        | Instruction::Multiply(_)
        | Instruction::Divide(_)
        | Instruction::ConditionalSelect(_)
        | Instruction::ConditionalCompare(_)
        | Instruction::Barrier(_)
        | Instruction::CensusGap(Decoded::VariableShift { .. } | Decoded::OneSource { .. })
        | Instruction::Hint(Hint::Nop | Hint::Yield) => InstructionClass::Copy(CopyKind::Verbatim),
        Instruction::Address(_) => InstructionClass::Copy(CopyKind::PcRelative),
        Instruction::Hint(hint) => InstructionClass::Exit(ExitReason::Hint(hint)),
        Instruction::ScalarMemory(_)
        | Instruction::UnprivilegedMemory(_)
        | Instruction::PairMemory(_)
        | Instruction::AtomicTransfer(_)
        | Instruction::AtomicAdd(_) => InstructionClass::Exit(ExitReason::Memory),
        Instruction::SystemAccess(_) => InstructionClass::Exit(ExitReason::SystemRegister),
        Instruction::PstateImmediate(_) => InstructionClass::Exit(ExitReason::Pstate),
        Instruction::SystemOperation(_) => InstructionClass::Exit(ExitReason::SystemOperation),
        Instruction::CensusGap(Decoded::AddressTranslate { .. }) => {
            InstructionClass::Exit(ExitReason::AddressTranslate)
        }
        Instruction::CensusGap(Decoded::ClearExclusive { .. }) => {
            InstructionClass::Exit(ExitReason::ClearExclusive)
        }
        Instruction::CensusGap(Decoded::Breakpoint { .. }) => {
            InstructionClass::Exit(ExitReason::Exception(ExceptionKind::Brk))
        }
        Instruction::ExceptionGeneration(e) => {
            InstructionClass::Exit(ExitReason::Exception(e.kind))
        }
        Instruction::Eret => InstructionClass::Exit(ExitReason::Eret),
        Instruction::Unallocated => InstructionClass::Exit(ExitReason::Undefined),
        Instruction::Branch(Branch::Immediate { link, .. }) => {
            InstructionClass::Branch(BranchKind::Direct { link })
        }
        Instruction::Branch(
            Branch::Conditional { .. } | Branch::Compare { .. } | Branch::Test { .. },
        ) => InstructionClass::Branch(BranchKind::Conditional),
        Instruction::Branch(Branch::Register { op, .. }) => {
            InstructionClass::Branch(BranchKind::Indirect(op))
        }
    }
}

/// One decoded guest instruction at its guest address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestInstruction {
    pub pc: ProgramCounter,
    pub word: u32,
    pub instruction: Instruction,
    pub class: InstructionClass,
}

impl GuestInstruction {
    pub fn decode(pc: ProgramCounter, word: u32) -> Self {
        let instruction = decode_instruction(word);
        Self {
            pc,
            word,
            instruction,
            class: classify_instruction(instruction),
        }
    }
}

/// Structural limits on one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLimits {
    pub max_instructions: usize,
}

impl Default for BlockLimits {
    fn default() -> Self {
        Self {
            max_instructions: 64,
        }
    }
}

/// The guest code page: a block never crosses one, so a page is the unit of
/// code invalidation.
pub const CODE_PAGE_BYTES: u64 = 4096;

/// A straight-line guest block. If the last instruction terminates, it is the
/// block's terminator; otherwise the block was cut by a limit, a page
/// boundary or an unfetchable word, and falls through to `next_pc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBlock {
    pub start: ProgramCounter,
    pub instructions: Vec<GuestInstruction>,
}

impl GuestBlock {
    pub fn terminator(&self) -> Option<&GuestInstruction> {
        self.instructions.last().filter(|i| i.class.terminates())
    }
    /// The PC after the last instruction of the block.
    pub fn next_pc(&self) -> ProgramCounter {
        ProgramCounter(
            self.start
                .0
                .wrapping_add(4 * self.instructions.len() as u64),
        )
    }
}

/// Split one block starting at `start`. `fetch` returns the guest word at an
/// address, or None when it cannot be fetched; an empty block means the very
/// first word could not be fetched.
pub fn split_block(
    start: ProgramCounter,
    limits: BlockLimits,
    mut fetch: impl FnMut(ProgramCounter) -> Option<u32>,
) -> GuestBlock {
    let mut instructions = Vec::new();
    let mut pc = start;
    let page = start.0 / CODE_PAGE_BYTES;
    while instructions.len() < limits.max_instructions.max(1) && pc.0 / CODE_PAGE_BYTES == page {
        let Some(word) = fetch(pc) else { break };
        let instruction = GuestInstruction::decode(pc, word);
        instructions.push(instruction);
        if instruction.class.terminates() {
            break;
        }
        pc = ProgramCounter(pc.0.wrapping_add(4));
    }
    GuestBlock {
        start,
        instructions,
    }
}

/// Partition a linear code span into consecutive blocks, each starting where
/// the previous one ended. Used to measure real images.
pub fn split_span(base: ProgramCounter, words: &[u32], limits: BlockLimits) -> Vec<GuestBlock> {
    let mut blocks = Vec::new();
    let mut pc = base;
    let end = base.0.wrapping_add(4 * words.len() as u64);
    while pc.0 < end {
        let block = split_block(pc, limits, |at| {
            words
                .get(usize::try_from((at.0 - base.0) / 4).ok()?)
                .copied()
        });
        pc = block.next_pc();
        blocks.push(block);
    }
    blocks
}

/// Engine frame layout, in bytes. Host SP points at the frame while a block
/// runs (see the design doc's "Register convention").
pub mod frame {
    /// Guest X0..X30 at `8 * n`.
    pub const GPRS: u32 = 0x000;
    pub const GUEST_SP: u32 = 0x0f8;
    /// Guest NZCV in MRS NZCV format (bits 31:28).
    pub const NZCV: u32 = 0x100;
    pub const HOST_SP: u32 = 0x108;
    pub const SCRATCH: u32 = 0x110;
    pub const SLOTS: usize = 36;
    pub const BYTES: usize = SLOTS * 8;
}

/// The frame a block runs against. The host adapter places it at the top of a
/// dedicated host stack region; this crate only defines its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct BlockFrame {
    pub slots: [u64; frame::SLOTS],
}

impl Default for BlockFrame {
    fn default() -> Self {
        Self {
            slots: [0; frame::SLOTS],
        }
    }
}

const fn slot(offset: u32) -> usize {
    (offset / 8) as usize
}

impl BlockFrame {
    /// Load the guest registers a block can observe: X0..X30, the current
    /// banked SP and NZCV.
    pub fn from_cpu(cpu: &CpuState) -> Self {
        let mut f = Self::default();
        for n in 0..31u8 {
            if let Some(r) = Gpr::new(n) {
                f.slots[usize::from(n)] = cpu.read_operand(OperandRegister::Gpr(r)).0;
            }
        }
        f.slots[slot(frame::GUEST_SP)] = cpu.sp().0;
        f.slots[slot(frame::NZCV)] = u64::from(cpu.pstate.nzcv & 15) << 28;
        f
    }
    /// Write back what a block may have changed.
    pub fn store_to(&self, cpu: &mut CpuState) {
        for n in 0..31u8 {
            if let Some(r) = Gpr::new(n) {
                cpu.write_operand(
                    OperandRegister::Gpr(r),
                    RegisterValue(self.slots[usize::from(n)]),
                );
            }
        }
        cpu.set_sp(StackPointer(self.slots[slot(frame::GUEST_SP)]));
        cpu.pstate.nzcv = ((self.slots[slot(frame::NZCV)] >> 28) & 15) as u8;
    }
}

/// What the dispatcher does when a block returns exit index `i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockExit {
    /// Every instruction up to here retired; continue at this guest PC.
    Continue(ProgramCounter),
    /// The instruction at `pc` did not run; its handler performs it.
    Handler(GuestInstruction),
}

/// How the block ends, by exit index, for diagnostics and the test double.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminator {
    Handler(usize),
    Jump(usize),
    Conditional { fallthrough: usize, taken: usize },
    Fallthrough(usize),
}

/// A translated block: host words (an AAPCS64 function taking the frame in
/// x0 and returning the exit index in x0) plus its exit table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedBlock {
    pub guest: GuestBlock,
    pub words: Vec<u32>,
    pub exits: Vec<BlockExit>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslateError {
    /// The block holds no instruction (its first word was not fetchable).
    Empty,
    /// A copy-through word could not be re-encoded; a host JIT defect, never a
    /// guest exception.
    Encoding(u32),
}

/// Host instruction encoders (DDI0487G.a C6.2). 64-bit forms only.
pub mod encode {
    pub const SP: u32 = 31;
    /// STP Xt1, Xt2, [Xn|SP, #imm] (signed offset).
    pub const fn stp(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        0xa900_0000 | ((((offset / 8) as u32) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    /// STP Xt1, Xt2, [Xn|SP, #imm]! (pre-index).
    pub const fn stp_pre(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        0xa980_0000 | ((((offset / 8) as u32) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    /// LDP Xt1, Xt2, [Xn|SP, #imm] (signed offset).
    pub const fn ldp(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        0xa940_0000 | ((((offset / 8) as u32) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    /// LDP Xt1, Xt2, [Xn|SP], #imm (post-index).
    pub const fn ldp_post(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        0xa8c0_0000 | ((((offset / 8) as u32) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    /// STR Xt, [Xn|SP, #imm] (unsigned offset).
    pub const fn str(rt: u32, rn: u32, offset: u32) -> u32 {
        0xf900_0000 | ((offset / 8) << 10) | (rn << 5) | rt
    }
    /// LDR Xt, [Xn|SP, #imm] (unsigned offset).
    pub const fn ldr(rt: u32, rn: u32, offset: u32) -> u32 {
        0xf940_0000 | ((offset / 8) << 10) | (rn << 5) | rt
    }
    /// ADD Xd|SP, Xn|SP, #imm12 (MOV to or from SP when imm12 = 0).
    pub const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    /// MOVZ Xd, #imm16, LSL #(16 * hw).
    pub const fn movz(rd: u32, imm16: u16, hw: u32) -> u32 {
        0xd280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
    }
    /// MOVK Xd, #imm16, LSL #(16 * hw).
    pub const fn movk(rd: u32, imm16: u16, hw: u32) -> u32 {
        0xf280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
    }
    /// MRS Xt, NZCV (op0=3, op1=3, CRn=4, CRm=2, op2=0).
    pub const fn mrs_nzcv(rt: u32) -> u32 {
        0xd53b_4200 | rt
    }
    /// MSR NZCV, Xt.
    pub const fn msr_nzcv(rt: u32) -> u32 {
        0xd51b_4200 | rt
    }
    /// B label, `offset` in bytes from this word.
    pub const fn b(offset: i64) -> u32 {
        0x1400_0000 | (((offset / 4) as u32) & 0x03ff_ffff)
    }
    /// RET (X30).
    pub const RET: u32 = 0xd65f_03c0;
}

use encode::SP;

/// Host words that enter a block: an AAPCS64 prologue saving x19..x30, then
/// host SP to the frame, SP = frame, guest NZCV and guest X0..X30.
pub fn entry_stub() -> Vec<u32> {
    let mut w = Vec::with_capacity(24);
    w.push(encode::stp_pre(29, 30, SP, -96));
    for (i, r) in [19, 21, 23, 25, 27].into_iter().enumerate() {
        w.push(encode::stp(r, r + 1, SP, 16 * (i as i32 + 1)));
    }
    w.push(encode::add_imm(1, SP, 0));
    w.push(encode::str(1, 0, frame::HOST_SP));
    w.push(encode::add_imm(SP, 0, 0));
    w.push(encode::ldr(1, SP, frame::NZCV));
    w.push(encode::msr_nzcv(1));
    for r in (0..30).step_by(2) {
        w.push(encode::ldp(r, r + 1, SP, 8 * r as i32));
    }
    w.push(encode::ldr(30, SP, 8 * 30));
    w
}

/// Host words shared by every exit site, entered with guest x0/x1 already
/// stored and the exit index in x0: store guest X2..X30 and NZCV, restore the
/// host stack and callee-saved registers, return the exit index.
pub fn common_exit() -> Vec<u32> {
    let mut w = Vec::with_capacity(28);
    for r in (2..30).step_by(2) {
        w.push(encode::stp(r, r + 1, SP, 8 * r as i32));
    }
    w.push(encode::str(30, SP, 8 * 30));
    w.push(encode::mrs_nzcv(1));
    w.push(encode::str(1, SP, frame::NZCV));
    w.push(encode::ldr(1, SP, frame::HOST_SP));
    w.push(encode::add_imm(SP, 1, 0));
    for (i, r) in [19, 21, 23, 25, 27].into_iter().enumerate() {
        w.push(encode::ldp(r, r + 1, SP, 16 * (i as i32 + 1)));
    }
    w.push(encode::ldp_post(29, 30, SP, 96));
    w.push(encode::RET);
    w
}

/// Words an exit site occupies: `stp x0, x1, [sp]; movz x0, #i; b common`.
pub const EXIT_SITE_WORDS: usize = 3;

/// Immediate materialisation of `value` into Xd: MOVZ of the low halfword,
/// then MOVK for each nonzero higher halfword.
pub fn materialize(rd: u32, value: u64) -> Vec<u32> {
    let mut w = alloc::vec![encode::movz(rd, value as u16, 0)];
    for hw in 1..4 {
        let half = (value >> (16 * hw)) as u16;
        if half != 0 {
            w.push(encode::movk(rd, half, hw));
        }
    }
    w
}

fn gpr_number(r: OperandRegister) -> Option<u32> {
    match r {
        OperandRegister::Gpr(g) => Some(u32::from(g.number())),
        _ => None,
    }
}

/// Rewrite a word that names SP to use scratch register `s`: each register
/// field (Rd, Rn) that the typed decode reports as SP is replaced by `s`.
/// Returns the rewritten word and whether SP is written.
fn stack_pointer_rewrite(i: &GuestInstruction, s: u32) -> Option<(u32, bool)> {
    let (rd, rn) = match i.instruction {
        Instruction::Arithmetic(a) => (a.rd, a.rn),
        Instruction::Logical(l) => {
            if !matches!(l.operand, LogicalOperand::Immediate(_)) {
                return None;
            }
            (l.rd, l.rn)
        }
        _ => return None,
    };
    let mut word = i.word;
    if rd == OperandRegister::Sp {
        word = (word & !0x1f) | s;
    }
    if rn == OperandRegister::Sp {
        word = (word & !(0x1f << 5)) | (s << 5);
    }
    Some((word, rd == OperandRegister::Sp))
}

/// A scratch register not named by any register field of a rewritten word:
/// Rd, Rn and (extended register form) Rm. Immediate forms are treated as if
/// bits 20:16 named a register too, which only narrows the choice.
fn scratch_for(w: u32) -> u32 {
    let fields = [w & 31, (w >> 5) & 31, (w >> 16) & 31];
    [16, 17, 15, 14]
        .into_iter()
        .find(|s| !fields.contains(s))
        .unwrap_or(13)
}

/// Relocate a conditional branch so that it targets `offset` bytes ahead.
fn relocate_conditional(i: &GuestInstruction, offset: i64) -> Option<u32> {
    let words = offset / 4;
    match i.instruction {
        Instruction::Branch(Branch::Conditional { .. } | Branch::Compare { .. }) => {
            Some((i.word & 0xff00_001f) | (((words as u32) & 0x7ffff) << 5))
        }
        Instruction::Branch(Branch::Test { .. }) => {
            Some((i.word & 0xfff8_001f) | (((words as u32) & 0x3fff) << 5))
        }
        _ => None,
    }
}

fn branch_target(i: &GuestInstruction) -> Option<ProgramCounter> {
    let offset = match i.instruction {
        Instruction::Branch(
            Branch::Immediate { offset, .. }
            | Branch::Conditional { offset, .. }
            | Branch::Compare { offset, .. }
            | Branch::Test { offset, .. },
        ) => offset,
        _ => return None,
    };
    Some(ProgramCounter(i.pc.0.wrapping_add(offset.bytes() as u64)))
}

struct Emitter {
    words: Vec<u32>,
    exits: Vec<BlockExit>,
    /// Positions of the `b common` words to patch.
    sites: Vec<usize>,
}

impl Emitter {
    fn exit(&mut self, exit: BlockExit) -> usize {
        let index = self.exits.len();
        self.exits.push(exit);
        self.words.push(encode::stp(0, 1, SP, 0));
        self.words.push(encode::movz(0, index as u16, 0));
        self.sites.push(self.words.len());
        self.words.push(0);
        index
    }
}

/// Translate a guest block into host words. Pure and deterministic.
pub fn emit_block(guest: &GuestBlock) -> Result<TranslatedBlock, TranslateError> {
    if guest.instructions.is_empty() {
        return Err(TranslateError::Empty);
    }
    let mut e = Emitter {
        words: entry_stub(),
        exits: Vec::new(),
        sites: Vec::new(),
    };
    let mut terminator = None;
    for i in &guest.instructions {
        match i.class {
            InstructionClass::Copy(CopyKind::Verbatim) => e.words.push(i.word),
            InstructionClass::Copy(CopyKind::StackPointer) => {
                let s = scratch_for(i.word);
                let (word, writes) =
                    stack_pointer_rewrite(i, s).ok_or(TranslateError::Encoding(i.word))?;
                e.words.push(encode::str(s, SP, frame::SCRATCH));
                e.words.push(encode::ldr(s, SP, frame::GUEST_SP));
                e.words.push(word);
                if writes {
                    e.words.push(encode::str(s, SP, frame::GUEST_SP));
                }
                e.words.push(encode::ldr(s, SP, frame::SCRATCH));
            }
            InstructionClass::Copy(CopyKind::PcRelative) => {
                let Instruction::Address(a) = i.instruction else {
                    return Err(TranslateError::Encoding(i.word));
                };
                let base = match a.base {
                    AddressBase::Pc => i.pc.0,
                    AddressBase::Page => i.pc.0 & !0xfff,
                };
                if let Some(rd) = gpr_number(a.rd) {
                    e.words
                        .extend(materialize(rd, base.wrapping_add(a.offset.bytes() as u64)));
                }
            }
            InstructionClass::Exit(_) | InstructionClass::Branch(BranchKind::Indirect(_)) => {
                terminator = Some(Terminator::Handler(e.exit(BlockExit::Handler(*i))));
            }
            InstructionClass::Branch(BranchKind::Direct { link }) => {
                let target = branch_target(i).ok_or(TranslateError::Encoding(i.word))?;
                if link {
                    e.words.extend(materialize(30, i.pc.0.wrapping_add(4)));
                }
                terminator = Some(Terminator::Jump(e.exit(BlockExit::Continue(target))));
            }
            InstructionClass::Branch(BranchKind::Conditional) => {
                let target = branch_target(i).ok_or(TranslateError::Encoding(i.word))?;
                let taken_offset = 4 * (1 + EXIT_SITE_WORDS as i64);
                e.words.push(
                    relocate_conditional(i, taken_offset)
                        .ok_or(TranslateError::Encoding(i.word))?,
                );
                let fallthrough =
                    e.exit(BlockExit::Continue(ProgramCounter(i.pc.0.wrapping_add(4))));
                let taken = e.exit(BlockExit::Continue(target));
                terminator = Some(Terminator::Conditional { fallthrough, taken });
            }
        }
    }
    let terminator = match terminator {
        Some(t) => t,
        None => Terminator::Fallthrough(e.exit(BlockExit::Continue(guest.next_pc()))),
    };
    let common = e.words.len();
    e.words.extend(common_exit());
    for site in core::mem::take(&mut e.sites) {
        e.words[site] = encode::b(4 * (common as i64 - site as i64));
    }
    Ok(TranslatedBlock {
        guest: guest.clone(),
        words: e.words,
        exits: e.exits,
        terminator,
    })
}
