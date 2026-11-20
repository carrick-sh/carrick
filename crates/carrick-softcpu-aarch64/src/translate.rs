//! Native copy-through translation, host-independent half
//! (docs/design/soft-aarch64-translator.md). Guest A64 words become host A64
//! words: register-only words are copied, PC-relative words are rewritten as
//! immediates, branches are relocated, and everything else leaves the block
//! through an exit stub. No word is executed here.
//! Encodings: Arm ARM DDI0487G.a C4.1 encoding index and C6.2 instruction
//! pages (LDP/STP C6.2.130/C6.2.277, LDR/STR immediate C6.2.132/C6.2.278,
//! ADD immediate C6.2.4, MOVZ/MOVK C6.2.193/C6.2.191, B C6.2.26, RET C6.2.219,
//! MRS/MSR C6.2.194/C6.2.196, B.cond C6.2.25, CBZ C6.2.45, TBZ C6.2.331).
use crate::state::{
    CpuState, ExceptionLevel, FPCR_MASK, FPSR_MASK, ProgramCounter, RegisterValue, StackPointer,
    SystemValue,
};
use crate::{
    AddressBase, Barrier, BarrierKind, Branch, Decoded, ExceptionKind, GUEST_CPU_PROFILE, Gpr,
    Hint, Instruction, LogicalOperand, MemoryAddress, MemoryIndex, MemoryOperation, MemoryRegister,
    OperandRegister, RegisterBranch, ScalarMemory, decode_instruction,
};
use alloc::vec::Vec;

/// How a copy-through word reaches the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyKind {
    /// The guest word runs unchanged.
    Verbatim,
    /// Use a plain NOP so host CPU extensions cannot execute a guest hint.
    NoOperation,
    /// The word names SP; it runs against a scratch register holding guest SP.
    StackPointer,
    /// ADR/ADRP: the guest PC is known, so Rd is loaded with an immediate.
    PcRelative,
}

/// Why an instruction leaves native execution for a Rust handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Memory,
    RegisterCompute,
    SystemRegister,
    Pstate,
    SystemOperation,
    AddressTranslate,
    ClearExclusive,
    InstructionSynchronization,
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
        Instruction::Barrier(Barrier {
            kind: BarrierKind::Isb,
            ..
        }) => InstructionClass::Exit(ExitReason::InstructionSynchronization),
        Instruction::MoveWide(_)
        | Instruction::Bitfield(_)
        | Instruction::Extract(_)
        | Instruction::Multiply(_)
        | Instruction::Divide(_)
        | Instruction::SimdCopy(_)
        | Instruction::SimdCompute(_)
        | Instruction::ConditionalSelect(_)
        | Instruction::ConditionalCompare(_)
        | Instruction::Barrier(_)
        | Instruction::CensusGap(Decoded::VariableShift { .. } | Decoded::OneSource { .. })
        | Instruction::Hint(Hint::Nop | Hint::Yield) => InstructionClass::Copy(CopyKind::Verbatim),
        Instruction::CompatibilityHint => InstructionClass::Copy(CopyKind::NoOperation),
        Instruction::Address(_) => InstructionClass::Copy(CopyKind::PcRelative),
        Instruction::Hint(hint) => InstructionClass::Exit(ExitReason::Hint(hint)),
        Instruction::ScalarMemory(_)
        | Instruction::UnprivilegedMemory(_)
        | Instruction::PairMemory(_)
        | Instruction::AtomicTransfer(_)
        | Instruction::AtomicAdd(_)
        | Instruction::StructureMemory(_)
        | Instruction::Prefetch => InstructionClass::Exit(ExitReason::Memory),
        Instruction::Crc32(_) => InstructionClass::Exit(ExitReason::RegisterCompute),
        Instruction::SystemAccess(_) => InstructionClass::Exit(ExitReason::SystemRegister),
        Instruction::PstateImmediate(_) => InstructionClass::Exit(ExitReason::Pstate),
        Instruction::SystemOperation(_)
        | Instruction::InstructionCache(_)
        | Instruction::DataCacheZero(_) => InstructionClass::Exit(ExitReason::SystemOperation),
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
///
/// The raw word and its decoded classification are inseparable.
/// ```compile_fail
/// use carrick_softcpu_aarch64::{state::ProgramCounter, translate::GuestInstruction};
/// let mut instruction = GuestInstruction::decode(ProgramCounter(0), 0xd503_201f);
/// instruction.word = 0;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestInstruction {
    pc: ProgramCounter,
    word: u32,
    instruction: Instruction,
    class: InstructionClass,
}

impl GuestInstruction {
    pub fn pc(&self) -> ProgramCounter {
        self.pc
    }

    pub fn word(&self) -> u32 {
        self.word
    }

    pub fn instruction(&self) -> Instruction {
        self.instruction
    }

    pub fn class(&self) -> InstructionClass {
        self.class
    }

    pub fn decode(pc: ProgramCounter, word: u32) -> Self {
        Self::decode_at_level(pc, word, ExceptionLevel::El1)
    }

    pub fn decode_el0(pc: ProgramCounter, word: u32) -> Self {
        Self::decode_at_level(pc, word, ExceptionLevel::El0)
    }

    fn decode_at_level(pc: ProgramCounter, word: u32, el: ExceptionLevel) -> Self {
        let mut instruction = decode_instruction(word);
        if !GUEST_CPU_PROFILE.admits(instruction, el) {
            instruction = Instruction::Unallocated;
        }
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
/// Only the splitter constructs blocks, enforcing page and terminator boundaries.
/// ```compile_fail
/// use carrick_softcpu_aarch64::{state::ProgramCounter, translate::GuestBlock};
/// let _ = GuestBlock { start: ProgramCounter(0), instructions: vec![] };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBlock {
    start: ProgramCounter,
    instructions: Vec<GuestInstruction>,
    inline_memory: bool,
}

impl GuestBlock {
    pub fn start(&self) -> ProgramCounter {
        self.start
    }

    pub fn instructions(&self) -> &[GuestInstruction] {
        &self.instructions
    }

    pub fn terminator(&self) -> Option<&GuestInstruction> {
        self.instructions
            .last()
            .filter(|i| i.class.terminates() && self.inline_op(i).is_none())
    }
    fn inline_op(&self, i: &GuestInstruction) -> Option<ScalarMemory> {
        self.inline_memory.then(|| inline_op(i)).flatten()
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
/// address, or None when it cannot be fetched. An unaligned start returns an
/// empty block without calling `fetch`; otherwise an empty block means the
/// first word could not be fetched.
pub fn split_block(
    start: ProgramCounter,
    limits: BlockLimits,
    fetch: impl FnMut(ProgramCounter) -> Option<u32>,
) -> GuestBlock {
    split_block_for_run(start, limits, ExceptionLevel::El1, false, fetch)
}

pub(crate) fn split_block_for_run(
    start: ProgramCounter,
    limits: BlockLimits,
    el: ExceptionLevel,
    inline_memory: bool,
    mut fetch: impl FnMut(ProgramCounter) -> Option<u32>,
) -> GuestBlock {
    let mut instructions = Vec::new();
    if !start.0.is_multiple_of(4) {
        return GuestBlock {
            start,
            instructions,
            inline_memory,
        };
    }
    let mut pc = start;
    let page = start.0 / CODE_PAGE_BYTES;
    while instructions.len() < limits.max_instructions.max(1) && pc.0 / CODE_PAGE_BYTES == page {
        let Some(word) = fetch(pc) else { break };
        let instruction = GuestInstruction::decode_at_level(pc, word, el);
        instructions.push(instruction);
        if instruction.class.terminates() && !(inline_memory && inline_op(&instruction).is_some()) {
            break;
        }
        pc = ProgramCounter(pc.0.wrapping_add(4));
    }
    GuestBlock {
        start,
        instructions,
        inline_memory,
    }
}

// Admit only ordinary unsigned-offset integer loads and stores. Keep
// atomics, SIMD, signed loads and addressing with writeback on the handler.
fn inline_op(i: &GuestInstruction) -> Option<ScalarMemory> {
    match i.instruction {
        Instruction::ScalarMemory(
            op @ ScalarMemory {
                operation: MemoryOperation::Load | MemoryOperation::Store,
                register: MemoryRegister::Integer { .. },
                address:
                    MemoryAddress::Immediate {
                        index: MemoryIndex::Offset,
                        unscaled: false,
                        ..
                    },
                ..
            },
        ) => Some(op),
        _ => None,
    }
}

/// Partition a linear code span into consecutive blocks, each starting where
/// the previous one ended. An unaligned base yields no blocks. Used to
/// measure real images.
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
        if block.instructions.is_empty() {
            break;
        }
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
    pub const FPCR: u32 = 0x118;
    pub const FPSR: u32 = 0x120;
    pub const HOST_FPCR: u32 = 0x128;
    pub const HOST_FPSR: u32 = 0x130;
    pub const INLINE_READ_VA: u32 = 0x138;
    pub const INLINE_READ_PTR: u32 = 0x140;
    pub const INLINE_WRITE_VA: u32 = 0x148;
    pub const INLINE_WRITE_PTR: u32 = 0x150;
    pub const CHAIN_TABLE: u32 = 0x158;
    pub const CHAIN_REMAINING: u32 = 0x160;
    pub const CHAIN_RETIRED: u32 = 0x168;
    pub const CHAIN_LAST: u32 = 0x170;
    pub const CHAIN_TARGET: u32 = 0x178;
    pub const CHAIN_EXIT: u32 = 0x180;
    pub const CHAIN_PENDING: u32 = 0x188;
    pub const CHAIN_POLL_MASK: u32 = 0x190;
    pub const CHAIN_X2: u32 = 0x198;
    pub const SLOTS: usize = 54;

    pub const CHAIN_INDEX_BITS: u32 = 6;
    pub const CHAIN_SLOTS: usize = 1 << CHAIN_INDEX_BITS;
    // Fold virtual page bits into the index so equal page offsets can coexist.
    pub const CHAIN_PAGE_XOR_SHIFT: u32 = 10;

    pub const fn chain_slot(pc: u64) -> usize {
        (((pc ^ (pc >> CHAIN_PAGE_XOR_SHIFT)) >> 2) as usize) & (CHAIN_SLOTS - 1)
    }
    pub const LINK_PC: u32 = 0;
    pub const LINK_ENTRY: u32 = 8;
    pub const LINK_SHIFT: u32 = 4;
    /// Guest Q0..Q31, sixteen bytes per register.
    pub const VECTORS: u32 = (SLOTS * 8) as u32;
    pub const BYTES: usize = SLOTS * 8 + 32 * 16;
}

/// The frame a block runs against. The host adapter places it at the top of a
/// dedicated host stack region; this crate only defines its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct BlockFrame {
    pub slots: [u64; frame::SLOTS],
    pub vectors: [u128; 32],
}

const _: () = {
    assert!(core::mem::offset_of!(BlockFrame, vectors) == frame::VECTORS as usize);
    assert!(core::mem::size_of::<BlockFrame>() == frame::BYTES);
};

impl Default for BlockFrame {
    fn default() -> Self {
        Self {
            slots: [0; frame::SLOTS],
            vectors: [0; 32],
        }
    }
}

const fn slot(offset: u32) -> usize {
    (offset / 8) as usize
}

impl BlockFrame {
    pub fn from_cpu(cpu: &CpuState) -> Self {
        let mut f = Self::default();
        f.load_from(cpu);
        f
    }

    /// Load the guest registers a block can observe: X0..X30, the current
    /// banked SP, NZCV, and Q0..Q31.
    pub fn load_from(&mut self, cpu: &CpuState) {
        for n in 0..31u8 {
            if let Some(r) = Gpr::new(n) {
                self.slots[usize::from(n)] = cpu.read_operand(OperandRegister::Gpr(r)).0;
            }
        }
        self.vectors = cpu.vectors;
        self.slots[slot(frame::FPCR)] = cpu.named.fpcr.0 & FPCR_MASK;
        self.slots[slot(frame::FPSR)] = cpu.named.fpsr.0 & FPSR_MASK;
        self.slots[slot(frame::GUEST_SP)] = cpu.sp().0;
        self.slots[slot(frame::NZCV)] = u64::from(cpu.pstate.nzcv & 15) << 28;
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
        cpu.vectors = self.vectors;
        cpu.named.fpcr = SystemValue(self.slots[slot(frame::FPCR)] & FPCR_MASK);
        cpu.named.fpsr = SystemValue(self.slots[slot(frame::FPSR)] & FPSR_MASK);
        cpu.set_sp(StackPointer(self.slots[slot(frame::GUEST_SP)]));
        cpu.pstate.nzcv = ((self.slots[slot(frame::NZCV)] >> 28) & 15) as u8;
    }
}

/// What the dispatcher does when a block returns exit index `i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockExit {
    /// Every instruction up to here retired; continue at this guest PC.
    Continue(ProgramCounter),
    /// A register branch retired with the next guest PC in CHAIN_TARGET.
    Indirect,
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
/// Only the emitter constructs blocks that a native runner can execute.
/// ```compile_fail
/// use carrick_softcpu_aarch64::{
///     state::ProgramCounter,
///     translate::{BlockLimits, Terminator, TranslatedBlock, split_block},
/// };
/// let guest = split_block(ProgramCounter(0), BlockLimits::default(), |_| None);
/// let _ = TranslatedBlock {
///     guest,
///     words: vec![],
///     exits: vec![],
///     terminator: Terminator::Fallthrough(0),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedBlock {
    guest: GuestBlock,
    words: Vec<u32>,
    exits: Vec<BlockExit>,
    terminator: Terminator,
    inline_memory: bool,
    linked_entry: Option<usize>,
    simd: bool,
}

impl TranslatedBlock {
    pub fn guest(&self) -> &GuestBlock {
        &self.guest
    }

    /// Read-only AAPCS64 machine code produced by the emitter.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    pub fn exits(&self) -> &[BlockExit] {
        &self.exits
    }

    pub fn has_inline_memory(&self) -> bool {
        self.inline_memory
    }

    /// Offset in bytes to the entry that inherits the current guest
    /// registers, frame and host return address.
    pub fn linked_entry(&self) -> Option<usize> {
        self.linked_entry
    }

    pub fn uses_simd(&self) -> bool {
        self.simd
    }

    pub fn terminator(&self) -> Terminator {
        self.terminator
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslateError {
    /// The block holds no instruction (its first word was not fetchable).
    Empty,
    /// A copy-through word could not be re-encoded; a host JIT defect, never a
    /// guest exception.
    Encoding(u32),
}

/// Host instruction encoders (DDI0487G.a C6.2).
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
    /// STP Qt1, Qt2, [Xn|SP, #imm] (signed offset).
    pub const fn stp_q(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        0xad00_0000 | ((((offset / 16) as u32) & 0x7f) << 15) | (rt2 << 10) | (rn << 5) | rt
    }
    /// LDP Qt1, Qt2, [Xn|SP, #imm] (signed offset).
    pub const fn ldp_q(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        stp_q(rt, rt2, rn, offset) | (1 << 22)
    }
    /// STP Qt1, Qt2, [Xn|SP, #imm]! (pre-index).
    pub const fn stp_q_pre(rt: u32, rt2: u32, rn: u32, offset: i32) -> u32 {
        stp_q(rt, rt2, rn, offset) | (1 << 23)
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
    pub(super) const fn eor(rd: u32, rn: u32, rm: u32) -> u32 {
        0xca00_0000 | (rm << 16) | (rn << 5) | rd
    }
    pub(super) const fn eor_lsr(rd: u32, rn: u32, rm: u32, shift: u32) -> u32 {
        eor(rd, rn, rm) | (1 << 22) | (shift << 10)
    }
    pub(super) const fn add(rd: u32, rn: u32, rm: u32) -> u32 {
        0x8b00_0000 | (rm << 16) | (rn << 5) | rd
    }
    pub(super) const fn ubfx(rd: u32, rn: u32, lsb: u32, width: u32) -> u32 {
        0xd340_0000 | (lsb << 16) | ((lsb + width - 1) << 10) | (rn << 5) | rd
    }
    pub(super) const fn cbz(rt: u32, nonzero: bool, words: usize) -> u32 {
        0xb400_0000 | ((nonzero as u32) << 24) | ((words as u32) << 5) | rt
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
    pub(super) const fn mrs_fpcr(rt: u32) -> u32 {
        0xd53b_4400 | rt
    }
    pub(super) const fn msr_fpcr(rt: u32) -> u32 {
        0xd51b_4400 | rt
    }
    pub(super) const fn mrs_fpsr(rt: u32) -> u32 {
        0xd53b_4420 | rt
    }
    pub(super) const fn msr_fpsr(rt: u32) -> u32 {
        0xd51b_4420 | rt
    }
    /// B label, `offset` in bytes from this word.
    pub const fn b(offset: i64) -> u32 {
        0x1400_0000 | (((offset / 4) as u32) & 0x03ff_ffff)
    }
    pub(super) const fn br(rn: u32) -> u32 {
        0xd61f_0000 | (rn << 5)
    }
    pub(super) const fn ldar_b(rt: u32, rn: u32) -> u32 {
        0x08df_fc00 | (rn << 5) | rt
    }
    pub(super) const fn and(rd: u32, rn: u32, rm: u32) -> u32 {
        0x8a00_0000 | (rm << 16) | (rn << 5) | rd
    }
    pub(super) const fn sub_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
        0xd100_0000 | (imm12 << 10) | (rn << 5) | rd
    }
    pub(super) const fn add_shift(rd: u32, rn: u32, rm: u32, shift: u32) -> u32 {
        add(rd, rn, rm) | (shift << 10)
    }
    /// RET (X30).
    pub const RET: u32 = 0xd65f_03c0;
}

use encode::SP;

/// Host words that enter a block: an AAPCS64 prologue saving x19..x30, then
/// host SP to the frame, SP = frame, guest NZCV and guest X0..X30.
pub fn entry_stub() -> Vec<u32> {
    entry_stub_for(false)
}

fn entry_stub_for(simd: bool) -> Vec<u32> {
    let mut w = Vec::with_capacity(if simd { 55 } else { 27 });
    w.push(encode::stp_pre(29, 30, SP, -96));
    for (i, r) in [19, 21, 23, 25, 27].into_iter().enumerate() {
        w.push(encode::stp(r, r + 1, SP, 16 * (i as i32 + 1)));
    }
    if simd {
        // AAPCS64 requires the low half of V8..V15 to survive. Save full
        // vectors in pairs, on the host stack, before loading guest state.
        w.push(encode::stp_q_pre(8, 9, SP, -128));
        for r in [10, 12, 14] {
            w.push(encode::stp_q(r, r + 1, SP, 16 * (r as i32 - 8)));
        }
    }
    w.push(encode::add_imm(1, SP, 0));
    w.push(encode::str(1, 0, frame::HOST_SP));
    w.push(encode::add_imm(SP, 0, 0));
    if simd {
        w.extend([
            encode::mrs_fpcr(1),
            encode::str(1, SP, frame::HOST_FPCR),
            encode::mrs_fpsr(1),
            encode::str(1, SP, frame::HOST_FPSR),
            encode::ldr(1, SP, frame::FPCR),
            encode::msr_fpcr(1),
            encode::ldr(1, SP, frame::FPSR),
            encode::msr_fpsr(1),
        ]);
    }
    w.push(encode::ldr(1, SP, frame::NZCV));
    w.push(encode::msr_nzcv(1));
    for r in (0..30).step_by(2) {
        w.push(encode::ldp(r, r + 1, SP, 8 * r as i32));
    }
    w.push(encode::ldr(30, SP, 8 * 30));
    if simd {
        for r in (0..32).step_by(2) {
            w.push(encode::ldp_q(
                r,
                r + 1,
                SP,
                frame::VECTORS as i32 + 16 * r as i32,
            ));
        }
    }
    w
}

/// Host words shared by every exit site, entered with guest x0/x1 already
/// stored and the exit index in x0: store guest X2..X30 and NZCV, restore the
/// host stack and callee-saved registers, return the exit index.
pub fn common_exit() -> Vec<u32> {
    common_exit_for(false)
}

fn common_exit_for(simd: bool) -> Vec<u32> {
    let mut w = Vec::with_capacity(if simd { 57 } else { 28 });
    for r in (2..30).step_by(2) {
        w.push(encode::stp(r, r + 1, SP, 8 * r as i32));
    }
    w.push(encode::str(30, SP, 8 * 30));
    w.push(encode::mrs_nzcv(1));
    w.push(encode::str(1, SP, frame::NZCV));
    if simd {
        for r in (0..32).step_by(2) {
            w.push(encode::stp_q(
                r,
                r + 1,
                SP,
                frame::VECTORS as i32 + 16 * r as i32,
            ));
        }
    }
    if simd {
        w.extend([
            encode::mrs_fpcr(1),
            encode::str(1, SP, frame::FPCR),
            encode::mrs_fpsr(1),
            encode::str(1, SP, frame::FPSR),
            encode::ldr(1, SP, frame::HOST_FPCR),
            encode::msr_fpcr(1),
            encode::ldr(1, SP, frame::HOST_FPSR),
            encode::msr_fpsr(1),
        ]);
    }
    w.push(encode::ldr(1, SP, frame::HOST_SP));
    w.push(encode::add_imm(SP, 1, 0));
    if simd {
        for r in [8, 10, 12, 14] {
            w.push(encode::ldp_q(r, r + 1, SP, 16 * (r as i32 - 8)));
        }
        w.push(encode::add_imm(SP, SP, 128));
    }
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
    chain_sites: Vec<usize>,
    chaining: bool,
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

    fn continuation(&mut self, pc: ProgramCounter) -> usize {
        if !self.chaining {
            return self.exit(BlockExit::Continue(pc));
        }
        let index = self.chain_site(BlockExit::Continue(pc));
        self.words.extend(materialize(0, pc.0));
        self.branch_to_chain(index);
        index
    }

    fn indirect(&mut self, i: &GuestInstruction) -> Result<usize, TranslateError> {
        let Instruction::Branch(Branch::Register { op, rn }) = i.instruction else {
            return Err(TranslateError::Encoding(i.word));
        };
        let index = self.chain_site(BlockExit::Indirect);
        // ORR X0, XZR, Xn (MOV). Read the target before writing LR for BLR X30.
        self.words.push(match rn {
            OperandRegister::Zr => 0xaa1f_03e0,
            OperandRegister::Gpr(r) => 0xaa00_03e0 | (u32::from(r.number()) << 16),
            OperandRegister::Sp => return Err(TranslateError::Encoding(i.word)),
        });
        if op == RegisterBranch::Call {
            self.words.extend(materialize(30, i.pc.0.wrapping_add(4)));
        }
        self.branch_to_chain(index);
        Ok(index)
    }

    fn chain_site(&mut self, exit: BlockExit) -> usize {
        let index = self.exits.len();
        self.exits.push(exit);
        self.words.push(encode::stp(0, 1, SP, 0));
        index
    }

    fn branch_to_chain(&mut self, index: usize) {
        self.words.push(encode::movz(1, index as u16, 0));
        self.words.push(encode::str(1, SP, frame::CHAIN_EXIT));
        self.chain_sites.push(self.words.len());
        self.words.push(0);
    }

    /// X0 is the guest target PC; guest X0/X1 are already spilled. All
    /// checks preserve NZCV. A hit branches over the target's host prologue.
    /// A miss, pending event, or exhausted quantum takes the normal epilogue.
    fn chain_tail(&mut self, instructions: u32) {
        use encode::{
            add_imm, add_shift, and, br, cbz, eor, eor_lsr, ldar_b, ldr, str, sub_imm, ubfx,
        };
        let words = &mut self.words;
        words.extend([
            str(0, SP, frame::CHAIN_TARGET),
            str(2, SP, frame::CHAIN_X2),
            ldr(2, SP, frame::CHAIN_TABLE),
        ]);
        let no_table = words.len();
        words.extend([
            0, // CBZ X2, stop
            eor_lsr(1, 0, 0, frame::CHAIN_PAGE_XOR_SHIFT),
            ubfx(1, 1, 2, frame::CHAIN_INDEX_BITS),
            add_shift(2, 2, 1, frame::LINK_SHIFT),
            ldr(1, 2, frame::LINK_PC),
            eor(1, 1, 0),
        ]);
        let mismatch = words.len();
        words.extend([0, ldr(1, 2, frame::LINK_ENTRY)]);
        let empty = words.len();
        words.extend([0, ldr(2, SP, frame::CHAIN_REMAINING)]);
        let no_budget = words.len();
        words.extend([0, ldr(2, SP, frame::CHAIN_PENDING)]);
        let no_control = words.len();
        words.extend([
            0, // CBZ X2, commit
            ldar_b(2, 2),
            ldr(0, SP, frame::CHAIN_POLL_MASK),
            and(2, 2, 0),
        ]);
        let pending = words.len();
        words.extend([0, ldr(0, SP, frame::CHAIN_TARGET)]);
        let commit = words.len();
        words[no_control] = cbz(2, false, commit - no_control);
        words.extend([
            eor_lsr(0, 0, 0, frame::CHAIN_PAGE_XOR_SHIFT),
            ubfx(0, 0, 2, frame::CHAIN_INDEX_BITS),
            str(0, SP, frame::CHAIN_LAST),
            ldr(2, SP, frame::CHAIN_REMAINING),
            sub_imm(2, 2, 1),
            str(2, SP, frame::CHAIN_REMAINING),
            ldr(2, SP, frame::CHAIN_RETIRED),
            add_imm(2, 2, instructions),
            str(2, SP, frame::CHAIN_RETIRED),
            ldr(2, SP, frame::CHAIN_X2),
            br(1),
        ]);
        let stop = words.len();
        for (at, register, nonzero) in [
            (no_table, 2, false),
            (mismatch, 1, true),
            (empty, 1, false),
            (no_budget, 2, false),
            (pending, 2, true),
        ] {
            words[at] = cbz(register, nonzero, stop - at);
        }
        words.extend([ldr(2, SP, frame::CHAIN_X2), ldr(0, SP, frame::CHAIN_EXIT)]);
    }

    fn inline_memory(
        &mut self,
        i: &GuestInstruction,
        op: ScalarMemory,
    ) -> Result<(), TranslateError> {
        let MemoryAddress::Immediate { base, offset, .. } = op.address else {
            return Err(TranslateError::Encoding(i.word));
        };
        let rn = gpr_number(base).unwrap_or(SP);
        let rt = i.word & 31;
        let mut scratches = [9, 10, 11, 12].into_iter().filter(|r| *r != rn && *r != rt);
        let (Some(address), Some(temp)) = (scratches.next(), scratches.next()) else {
            return Err(TranslateError::Encoding(i.word));
        };
        let store = op.operation == MemoryOperation::Store;
        let (page_slot, ptr_slot) = if store {
            (frame::INLINE_WRITE_VA, frame::INLINE_WRITE_PTR)
        } else {
            (frame::INLINE_READ_VA, frame::INLINE_READ_PTR)
        };
        let w = &mut self.words;
        w.push(encode::stp(address, temp, SP, frame::SCRATCH as i32));
        let base_reg = if rn == SP {
            w.push(encode::ldr(address, SP, frame::GUEST_SP));
            address
        } else {
            rn
        };
        let bytes = offset.bytes() as u32;
        let base_reg = if bytes >= 4096 {
            w.push(encode::add_imm(address, base_reg, bytes >> 12) | (1 << 22));
            address
        } else {
            base_reg
        };
        w.push(encode::add_imm(address, base_reg, bytes & 4095));
        // Compare the whole virtual page tag, preserving guest NZCV.
        w.push(encode::ldr(temp, SP, page_slot));
        w.push(encode::eor(temp, address, temp));
        w.push(encode::ubfx(temp, temp, 12, 52));
        let tag_miss = w.len();
        w.push(0);
        // Natural alignment also proves the access fits in the borrowed page.
        let alignment_miss = if op.size.bytes() > 1 {
            w.push(encode::ubfx(
                temp,
                address,
                0,
                op.size.bytes().trailing_zeros(),
            ));
            let site = w.len();
            w.push(0);
            Some(site)
        } else {
            None
        };
        w.push(encode::ldr(temp, SP, ptr_slot));
        let ptr_miss = w.len();
        w.push(0);
        w.push(encode::ubfx(address, address, 0, 12));
        w.push(encode::add(address, temp, address));
        // Reuse the admitted unsigned-offset opcode with the translated base
        // and immediate zero. Width and Rt (including ZR) remain unchanged.
        w.push((i.word & !0x003f_ffe0) | (address << 5));
        w.push(encode::ldp(address, temp, SP, frame::SCRATCH as i32));
        let skip = w.len();
        w.push(0);
        let slow = w.len();
        w[tag_miss] = encode::cbz(temp, true, slow - tag_miss);
        if let Some(site) = alignment_miss {
            w[site] = encode::cbz(temp, true, slow - site);
        }
        w[ptr_miss] = encode::cbz(temp, false, slow - ptr_miss);
        w.push(encode::ldp(address, temp, SP, frame::SCRATCH as i32));
        self.exit(BlockExit::Handler(*i));
        self.words[skip] = encode::b(4 * (self.words.len() - skip) as i64);
        Ok(())
    }
}

/// Translate a guest block into host words. Pure and deterministic.
pub fn emit_block(guest: &GuestBlock) -> Result<TranslatedBlock, TranslateError> {
    emit_block_for_run(guest, false)
}

pub(crate) fn emit_block_for_run(
    guest: &GuestBlock,
    chaining: bool,
) -> Result<TranslatedBlock, TranslateError> {
    if guest.instructions.is_empty() {
        return Err(TranslateError::Empty);
    }
    let simd = guest.instructions.iter().any(|i| {
        matches!(
            i.instruction,
            Instruction::SimdCopy(_) | Instruction::SimdCompute(_)
        )
    });
    let mut e = Emitter {
        words: entry_stub_for(simd),
        exits: Vec::new(),
        sites: Vec::new(),
        chain_sites: Vec::new(),
        chaining,
    };
    let body = e.words.len();
    let mut terminator = None;
    let mut inline_memory = false;
    for i in &guest.instructions {
        if let Some(op) = guest.inline_op(i) {
            e.inline_memory(i, op)?;
            inline_memory = true;
            continue;
        }
        match i.class {
            InstructionClass::Copy(CopyKind::Verbatim) => e.words.push(i.word),
            InstructionClass::Copy(CopyKind::NoOperation) => e.words.push(0xd503_201f),
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
            InstructionClass::Branch(BranchKind::Indirect(_)) if chaining => {
                terminator = Some(Terminator::Jump(e.indirect(i)?));
            }
            InstructionClass::Exit(_) | InstructionClass::Branch(BranchKind::Indirect(_)) => {
                terminator = Some(Terminator::Handler(e.exit(BlockExit::Handler(*i))));
            }
            InstructionClass::Branch(BranchKind::Direct { link }) => {
                let target = branch_target(i).ok_or(TranslateError::Encoding(i.word))?;
                if link {
                    e.words.extend(materialize(30, i.pc.0.wrapping_add(4)));
                }
                terminator = Some(Terminator::Jump(e.continuation(target)));
            }
            InstructionClass::Branch(BranchKind::Conditional) => {
                let target = branch_target(i).ok_or(TranslateError::Encoding(i.word))?;
                let conditional = e.words.len();
                e.words.push(0);
                let fallthrough = e.continuation(ProgramCounter(i.pc.0.wrapping_add(4)));
                let taken_offset = 4 * (e.words.len() - conditional) as i64;
                e.words[conditional] = relocate_conditional(i, taken_offset)
                    .ok_or(TranslateError::Encoding(i.word))?;
                let taken = e.continuation(target);
                terminator = Some(Terminator::Conditional { fallthrough, taken });
            }
        }
    }
    let terminator = match terminator {
        Some(t) => t,
        None => Terminator::Fallthrough(e.continuation(guest.next_pc())),
    };
    if !e.chain_sites.is_empty() {
        let chain = e.words.len();
        for site in core::mem::take(&mut e.chain_sites) {
            e.words[site] = encode::b(4 * (chain as i64 - site as i64));
        }
        e.chain_tail(guest.instructions.len() as u32);
    }
    let common = e.words.len();
    e.words.extend(common_exit_for(simd));
    for site in core::mem::take(&mut e.sites) {
        e.words[site] = encode::b(4 * (common as i64 - site as i64));
    }
    let linked_entry = chaining.then(|| {
        let entry = e.words.len();
        e.words.extend([
            encode::ldp(0, 1, SP, 0),
            encode::b(4 * (body as i64 - entry as i64 - 1)),
        ]);
        entry * size_of::<u32>()
    });
    Ok(TranslatedBlock {
        guest: guest.clone(),
        words: e.words,
        exits: e.exits,
        terminator,
        inline_memory,
        linked_entry,
        simd,
    })
}
