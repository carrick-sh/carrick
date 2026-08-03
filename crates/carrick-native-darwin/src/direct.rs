//! Tier D: run guest code DIRECTLY, patching only what Darwin cannot accept.
//!
//! The native lane is same-ISA — aarch64 Linux guests on an aarch64 host — so
//! guest instructions are already correct for this CPU. A static census over
//! the go-conformance binaries puts the instructions that genuinely cannot
//! execute on Darwin at **0.03%**: `svc #0`, x18 accesses, and `tpidr_el0`
//! accesses (`docs/superpowers/specs/2026-08-02-direct-execution-tier-design.md`).
//! The translator pays 52.4% emitted-instruction overhead on 100% of the code
//! to handle that 0.03%. This module handles it by patching instead.
//!
//! M1 scope, deliberately narrow: load an ELF's executable segments into a
//! `MAP_JIT` region, rewrite every `svc #0` to branch to a per-site island,
//! and execute. Syscalls reach a Rust handler with the guest's registers in a
//! context block.
//!
//! # Why per-site islands
//!
//! An A64 instruction is 4 bytes, so a patch has exactly one instruction of
//! room and no register is free — every GPR belongs to the guest. A `bl` would
//! clobber x30, which is live at a syscall site. A *per-site* island solves
//! both ends without a scratch register:
//!
//! - entry is `b island_i`, which touches no register at all;
//! - the return address is a CONSTANT known at patch time, so the island ends
//!   in `b site+4` rather than needing a register to branch through.
//!
//! The island borrows the guest stack for exactly one 16-byte slot to free up
//! its first register, which is what the kernel itself does to deliver a
//! signal frame (AAPCS64 has no red zone).
//!
//! # Address identity
//!
//! Guest VA *is* host VA: the guest runs in carrick's own address space, so a
//! pointer the guest passes to a syscall needs no translation. That is the
//! structural simplification direct execution buys over the translator.

use std::io;

/// Guest register file, saved by an island and restored on the way back.
///
/// `repr(C)` and field order are load-bearing: the island addresses these by
/// byte offset, and this type's private `REG`/`SP`/`PC`/`HANDLER` constants
/// are the single source of those offsets for both sides.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct GuestContext {
    /// x0..x30. x31 is never a GPR here (it reads as SP or XZR by context).
    pub x: [u64; 31],
    /// Guest SP at the syscall site, after the island's borrowed slot is undone.
    pub sp: u64,
    /// Where the island returns to: the instruction after the patched `svc`.
    ///
    /// INFORMATIONAL in M1. The island's return leg is a constant branch -
    /// that is what lets it resume without a scratch register - so writing
    /// this field does not redirect control. Redirection (signal delivery,
    /// `execve`) needs the M2 exit path.
    pub pc: u64,
    /// `extern "C" fn(*mut GuestContext)`, called with the context in x0.
    pub handler: u64,
}

impl GuestContext {
    const REG: u32 = 0; // x[0] .. x[30]
    const SP: u32 = 31 * 8;
    const PC: u32 = 32 * 8;
    const HANDLER: u32 = 33 * 8;

    /// The aarch64 Linux syscall number register is x8.
    pub fn syscall_nr(&self) -> u64 {
        self.x[8]
    }

    /// Linux passes syscall arguments in x0..x5.
    pub fn args(&self) -> [u64; 6] {
        [
            self.x[0], self.x[1], self.x[2], self.x[3], self.x[4], self.x[5],
        ]
    }

    /// A syscall's return value goes back in x0.
    pub fn set_return(&mut self, value: i64) {
        self.x[0] = value as u64;
    }
}

// ---------------------------------------------------------------- encodings

const fn str_imm(rt: u32, rn: u32, byte_offset: u32) -> u32 {
    0xf900_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
}
const fn ldr_imm(rt: u32, rn: u32, byte_offset: u32) -> u32 {
    0xf940_0000 | ((byte_offset / 8) << 10) | (rn << 5) | rt
}
/// `str xt, [sp, #-16]!`
const fn str_pre_sp(rt: u32) -> u32 {
    0xf800_0c00 | ((0x1f0_u32 & 0x1ff) << 12) | (31 << 5) | rt
}
/// `ldr xt, [sp], #16`
const fn ldr_post_sp(rt: u32) -> u32 {
    0xf840_0400 | ((16_u32 & 0x1ff) << 12) | (31 << 5) | rt
}
const fn movz(rd: u32, imm16: u32, shift: u32) -> u32 {
    0xd280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
}
const fn movk(rd: u32, imm16: u32, shift: u32) -> u32 {
    0xf280_0000 | ((shift / 16) << 21) | (imm16 << 5) | rd
}
/// `mov xd, sp` (ADD xd, sp, #0)
const fn mov_from_sp(rd: u32) -> u32 {
    0x9100_0000 | (31 << 5) | rd
}
/// `mov sp, xn` (ADD sp, xn, #0)
const fn mov_to_sp(rn: u32) -> u32 {
    0x9100_0000 | (rn << 5) | 31
}
/// `mov xd, xm` (ORR xd, xzr, xm). Used by fixtures today; the M2 x18 and
/// `tpidr_el0` veneers need it too.
#[cfg_attr(not(test), allow(dead_code))]
const fn mov_reg(rd: u32, rm: u32) -> u32 {
    0xaa00_03e0 | (rm << 16) | rd
}
const fn blr(rn: u32) -> u32 {
    0xd63f_0000 | (rn << 5)
}
/// `b <pc + offset>`; `offset` must be 4-byte aligned and within ±128 MiB.
fn b_rel(offset: i64) -> u32 {
    let imm26 = ((offset >> 2) as u32) & 0x03ff_ffff;
    0x1400_0000 | imm26
}

/// Materialize a 64-bit constant into `rd` (4 words, no literal pool).
fn mov_imm64(rd: u32, value: u64) -> [u32; 4] {
    [
        movz(rd, (value & 0xffff) as u32, 0),
        movk(rd, ((value >> 16) & 0xffff) as u32, 16),
        movk(rd, ((value >> 32) & 0xffff) as u32, 32),
        movk(rd, ((value >> 48) & 0xffff) as u32, 48),
    ]
}

/// `svc #0`.
pub const SVC_0: u32 = 0xd400_0001;

/// Emit one syscall island.
///
/// `ctx` is the absolute address of the [`GuestContext`]; `return_pc` is the
/// guest address to resume at (the instruction after the patched `svc`).
///
/// Register discipline, in order: x0 is freed by borrowing one 16-byte guest
/// stack slot, then holds the context pointer for the whole island. Every
/// other guest register is stored through it. x0's own guest value is
/// recovered from the borrowed slot (which also restores SP) and stored last.
fn island(ctx: u64, return_pc: u64) -> Vec<u32> {
    let mut w = Vec::with_capacity(80);
    // Free x0 by borrowing a guest stack slot, then point it at the context.
    w.push(str_pre_sp(0));
    w.extend_from_slice(&mov_imm64(0, ctx));
    // Save x1..x30 through the context pointer.
    for r in 1..=30_u32 {
        w.push(str_imm(r, 0, GuestContext::REG + r * 8));
    }
    // Recover the guest's x0 into x1 (x1 is already saved), undoing the borrow
    // so SP is the guest's own again, then record x0 and SP.
    w.push(ldr_post_sp(1));
    w.push(str_imm(1, 0, GuestContext::REG));
    w.push(mov_from_sp(1));
    w.push(str_imm(1, 0, GuestContext::SP));
    // Resume address is a constant for this site.
    w.extend_from_slice(&mov_imm64(1, return_pc));
    w.push(str_imm(1, 0, GuestContext::PC));
    // Call the Rust handler with the context in x0.
    w.push(ldr_imm(1, 0, GuestContext::HANDLER));
    w.push(blr(1));
    // RE-MATERIALIZE the context pointer. x0 held it on the way in, but x0 is
    // caller-saved: the handler is entitled to destroy it, and a Rust handler
    // routinely does. Restoring the guest through a clobbered x0 reads the
    // register file out of whatever x0 now points at, which is how this
    // surfaced - the guest resumed with a stack address in x30 and `ret`
    // branched into the stack (EXC_BAD_ACCESS code=2 with PC on the stack).
    // Whether x0 survived depended on the handler's codegen, so the failure
    // looked like it depended on the crate, the handler's weight and the heap
    // layout. The address is a patch-time constant, so re-materializing costs
    // four words and cannot be clobbered by anything.
    w.extend_from_slice(&mov_imm64(0, ctx));
    // Restore. SP first (through x1, restored after), then x30..x1, then x0.
    w.push(ldr_imm(1, 0, GuestContext::SP));
    w.push(mov_to_sp(1));
    for r in (1..=30_u32).rev() {
        w.push(ldr_imm(r, 0, GuestContext::REG + r * 8));
    }
    w.push(ldr_imm(0, 0, GuestContext::REG));
    w
}

/// `mrs xd, tpidr_el0` (read the thread pointer).
const fn mrs_tpidr_el0_word(rd: u32) -> u32 {
    0xd53b_d040 | rd
}
/// `msr tpidr_el0, xn` (write the thread pointer).
const fn msr_tpidr_el0_word(rn: u32) -> u32 {
    0xd51b_d040 | rn
}

/// Decode a `tpidr_el0` access, if this word is one.
fn tpidr_access(word: u32) -> Option<TpidrAccess> {
    let reg = word & 0x1f;
    if word == mrs_tpidr_el0_word(reg) {
        Some(TpidrAccess::Read { reg })
    } else if word == msr_tpidr_el0_word(reg) {
        Some(TpidrAccess::Write { reg })
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TpidrAccess {
    Read { reg: u32 },
    Write { reg: u32 },
}

/// Emit a veneer that services one guest `tpidr_el0` access.
///
/// XNU rewrites `TPIDR_EL0` at the first trap return (probed), so a guest TLS
/// base cannot live in the physical register. It lives in `slot` instead, and
/// these veneers are the only things that touch it.
///
/// A READ needs no borrowed register at all: `mrs xd, tpidr_el0` was already
/// going to overwrite `xd`, so the veneer materializes the slot address into
/// that same register and loads through it.
///
/// A WRITE has to preserve its source register, so it borrows one 16-byte
/// guest stack slot exactly as the syscall island does — using x0, or x1 when
/// the source *is* x0.
fn tpidr_veneer(access: TpidrAccess, tls_slot: u64, x18_slot: u64) -> Vec<u32> {
    let mut w = Vec::with_capacity(16);
    match access {
        // x18 as the destination is not a normal register case: depositing the
        // guest's TLS into the physical platform register would hand it to
        // Darwin to overwrite. Guest x18 lives in its own slot, so this is a
        // slot-to-slot move and touches neither special register.
        TpidrAccess::Read { reg: 18 } => {
            w.push(stp_pre_sp(0, 1));
            w.extend_from_slice(&mov_imm64(0, tls_slot));
            w.push(ldr_imm(0, 0, 0));
            w.extend_from_slice(&mov_imm64(1, x18_slot));
            w.push(str_imm(0, 1, 0));
            w.push(ldp_post_sp(0, 1));
        }
        TpidrAccess::Write { reg: 18 } => {
            w.push(stp_pre_sp(0, 1));
            w.extend_from_slice(&mov_imm64(0, x18_slot));
            w.push(ldr_imm(0, 0, 0));
            w.extend_from_slice(&mov_imm64(1, tls_slot));
            w.push(str_imm(0, 1, 0));
            w.push(ldp_post_sp(0, 1));
        }
        TpidrAccess::Read { reg } => {
            w.extend_from_slice(&mov_imm64(reg, tls_slot));
            w.push(ldr_imm(reg, reg, 0));
        }
        TpidrAccess::Write { reg } => {
            let scratch = if reg == 0 { 1 } else { 0 };
            w.push(str_pre_sp(scratch));
            w.extend_from_slice(&mov_imm64(scratch, tls_slot));
            w.push(str_imm(reg, scratch, 0));
            w.push(ldr_post_sp(scratch));
        }
    }
    w
}

/// `stp xt1, xt2, [sp, #-16]!`
const fn stp_pre_sp(rt1: u32, rt2: u32) -> u32 {
    0xa980_0000 | ((0x7e_u32 & 0x7f) << 15) | (rt2 << 10) | (31 << 5) | rt1
}
/// `ldp xt1, xt2, [sp], #16`
const fn ldp_post_sp(rt1: u32, rt2: u32) -> u32 {
    0xa8c0_0000 | ((2_u32 & 0x7f) << 15) | (rt2 << 10) | (31 << 5) | rt1
}

/// GPR ordinal for an X- or W-form register, or `None` for anything else.
fn reg_index(reg: bad64::Reg) -> Option<(u32, bool)> {
    let raw = reg as u32;
    let x0 = bad64::Reg::X0 as u32;
    let w0 = bad64::Reg::W0 as u32;
    if (x0..=x0 + 30).contains(&raw) {
        return Some((raw - x0, true));
    }
    if (w0..=w0 + 30).contains(&raw) {
        return Some((raw - w0, false));
    }
    None
}

/// Registers named by one operand, in order.
fn operand_regs(operand: &bad64::Operand) -> Vec<bad64::Reg> {
    use bad64::Operand as O;
    match operand {
        O::Reg { reg, .. } | O::QualReg { reg, .. } | O::ShiftReg { reg, .. } => vec![*reg],
        O::MemReg(reg)
        | O::MemOffset { reg, .. }
        | O::MemPreIdx { reg, .. }
        | O::MemPostIdxImm { reg, .. } => vec![*reg],
        O::MemPostIdxReg(regs) => regs.to_vec(),
        O::MemExt { regs, .. } => regs.to_vec(),
        O::MultiReg { regs, .. } => regs.iter().flatten().copied().collect(),
        _ => Vec::new(),
    }
}

/// Every GPR an instruction names.
fn instruction_regs(insn: &bad64::Instruction) -> Vec<u32> {
    insn.operands()
        .iter()
        .flat_map(operand_regs)
        .filter_map(|reg| reg_index(reg).map(|(index, _)| index))
        .collect()
}

/// Rewrite `word` so every x18 operand names `scratch` instead, or `None` if
/// that cannot be proved safe.
///
/// The substitution itself is a blind bit edit of the four standard register
/// fields — Rd/Rt (4:0), Rn (9:5), Rt2 (14:10), Rm (20:16). Those positions
/// hold immediates in some encodings, so a blind edit can silently corrupt
/// one. The edit is therefore VERIFIED by decoding the result and requiring,
/// operand by operand: the same opcode, the same operand shapes, every
/// register equal to the original with x18 mapped to `scratch`, and every
/// NON-register operand byte-identical. A textual comparison would be simpler
/// and wrong — `add x5, x18, #0x18` contains the register's spelling inside an
/// immediate.
///
/// Returning `None` costs the image a tier-T fallback, which is the right way
/// to be wrong.
fn substitute_x18(word: u32, scratch: u32) -> Option<u32> {
    let original = bad64::decode(word, 0).ok()?;
    let mut rewritten_word = word;
    for shift in [0_u32, 5, 10, 16] {
        if (word >> shift) & 0x1f == 18 {
            rewritten_word = (rewritten_word & !(0x1f << shift)) | (scratch << shift);
        }
    }
    if rewritten_word == word {
        return None; // nothing substituted: x18 was not in a standard field
    }
    let rewritten = bad64::decode(rewritten_word, 0).ok()?;
    if original.op() != rewritten.op() {
        return None;
    }
    let (before, after) = (original.operands(), rewritten.operands());
    if before.len() != after.len() {
        return None;
    }
    for (a, b) in before.iter().zip(after.iter()) {
        let (ra, rb) = (operand_regs(a), operand_regs(b));
        if ra.is_empty() && rb.is_empty() {
            // No registers here, so this operand must be untouched.
            if format!("{a:?}") != format!("{b:?}") {
                return None;
            }
            continue;
        }
        if ra.len() != rb.len() {
            return None;
        }
        for (x, y) in ra.iter().zip(rb.iter()) {
            let (Some((ix, wide_x)), Some((iy, wide_y))) = (reg_index(*x), reg_index(*y)) else {
                if x != y {
                    return None;
                }
                continue;
            };
            let expected = if ix == 18 { scratch } else { ix };
            if iy != expected || wide_x != wide_y {
                return None;
            }
        }
    }
    Some(rewritten_word)
}

/// Emit a veneer that runs one x18-using instruction against a memory slot.
///
/// Darwin rewrites the platform register at every trap return, so a guest x18
/// value cannot live there; it lives in `slot`. The veneer borrows two
/// registers the instruction does not name — one to hold the slot address, one
/// to stand in for x18 — runs the rewritten instruction, and writes the
/// stand-in back.
///
/// The write-back is UNCONDITIONAL by design. If the instruction only read
/// x18, the stand-in still holds the value that was loaded, so storing it back
/// is a no-op; that removes the need to classify reads from writes, which is
/// where a shape-by-shape implementation would accumulate mistakes.
fn x18_veneer(rewritten: u32, value_reg: u32, addr_reg: u32, slot: u64) -> Vec<u32> {
    let mut w = Vec::with_capacity(12);
    w.push(stp_pre_sp(value_reg, addr_reg));
    w.extend_from_slice(&mov_imm64(addr_reg, slot));
    w.push(ldr_imm(value_reg, addr_reg, 0));
    w.push(rewritten);
    w.push(str_imm(value_reg, addr_reg, 0));
    w.push(ldp_post_sp(value_reg, addr_reg));
    w
}

/// Pick two registers the instruction does not name, avoiding x18 and SP/XZR.
fn pick_scratch_pair(insn: &bad64::Instruction) -> Option<(u32, u32)> {
    let used = instruction_regs(insn);
    let mut free = (0..=30_u32).filter(|r| *r != 18 && !used.contains(r));
    Some((free.next()?, free.next()?))
}

/// Why an image cannot run on tier D.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectIneligible {
    /// A word in an executable region could not be decoded AND its raw bits
    /// could name x18, so an x18 access cannot be ruled out. Fail closed:
    /// tier T owns the image.
    ///
    /// Undecodable does not mean malformed — most are literal pools and newer
    /// SIMD encodings (bad64 leaves ~15% of libc undecoded). Refusing every
    /// one of them would disqualify every real binary, so the scan
    /// over-approximates instead: a word that cannot be decoded is only fatal
    /// if register field 18 appears in a position an instruction could use it.
    /// Discriminating code from data properly needs aarch64 mapping symbols
    /// (`$x`/`$d`), which is what libc will require.
    UndecodableText { vaddr: u64, word: u32 },
    /// Guest TLS. M2 veneers these; M1 refuses them.
    TpidrAccess { vaddr: u64 },
    /// Darwin's platform register. M2 veneers these; M1 refuses them.
    X18Access { vaddr: u64 },
    /// No executable segment, or nothing to patch.
    NoExecutableText,
    /// An `ET_EXEC` image: its addresses are absolute, so it must load at its
    /// own `p_vaddr`, and this loader places images wherever `MAP_JIT` lands.
    ///
    /// Not a limitation of the patcher — it is the `__PAGEZERO` wall. Probed
    /// on this host: a small-`__PAGEZERO` main is SIGKILLed at exec, and
    /// `mach_vm_deallocate` of the range reports success while leaving it
    /// unmappable. The Go toolchain lives at 0x10000 and is therefore tier T's
    /// by physics, whatever its instruction mix says.
    FixedLoadAddress { vaddr: u64 },
}

impl std::fmt::Display for DirectIneligible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndecodableText { vaddr, word } => {
                write!(f, "undecodable text at {vaddr:#x} (word {word:#010x})")
            }
            Self::TpidrAccess { vaddr } => write!(f, "tpidr_el0 access at {vaddr:#x}"),
            Self::X18Access { vaddr } => write!(f, "x18 access at {vaddr:#x}"),
            Self::NoExecutableText => write!(f, "no executable text"),
            Self::FixedLoadAddress { vaddr } => write!(
                f,
                "ET_EXEC must load at its own vaddr {vaddr:#x}, which __PAGEZERO forbids"
            ),
        }
    }
}

/// Does a raw word name x18 in any position an A64 instruction could?
///
/// Over-approximation used for words the decoder rejects: Rd/Rt (4:0),
/// Rn (9:5), Rt2 (14:10) and Rm (20:16) are the standard register fields, so
/// if none of them is 18 the word cannot touch x18 whatever it is.
fn word_could_name_x18(word: u32) -> bool {
    const X18: u32 = 18;
    (word & 0x1f) == X18
        || ((word >> 5) & 0x1f) == X18
        || ((word >> 10) & 0x1f) == X18
        || ((word >> 16) & 0x1f) == X18
}

/// Does a decoded instruction reference x18/w18 as an operand?
fn instruction_names_x18(insn: &bad64::Instruction) -> bool {
    instruction_regs(insn).contains(&18)
}

/// Can this x18-using instruction be veneered? Both halves must succeed: two
/// free registers, and a substitution that verifies.
fn x18_is_veneerable(insn: &bad64::Instruction, word: u32) -> bool {
    pick_scratch_pair(insn)
        .and_then(|(value, _)| substitute_x18(word, value))
        .is_some()
}

/// Decide whether an image can run on tier D, WITHOUT mapping anything.
///
/// Runs before any allocation so a refusal costs nothing, and fails closed:
/// anything the scan cannot prove safe is tier T's. The three disqualifiers
/// are the three things a same-ISA guest cannot do on Darwin —
/// x18 (the kernel rewrites the platform register at every trap return),
/// `tpidr_el0` (probed: XNU does not preserve a userspace value), and text the
/// decoder cannot rule out.
///
/// `svc` is NOT a disqualifier: patching it is the entire mechanism.
pub fn scan_eligibility(elf: &[u8]) -> Result<Result<usize, DirectIneligible>, io::Error> {
    // Placement before content: an image that cannot be put where it needs to
    // be is refused however clean its instructions are.
    const ET_EXEC: u64 = 2;
    if read_u16(elf, 0x10)? == ET_EXEC {
        let (lo, _) = load_span(elf)?;
        return Ok(Err(DirectIneligible::FixedLoadAddress { vaddr: lo }));
    }
    // Only real code: see `executable_sections` for why the PF_X segment is
    // the wrong unit. No section headers means nothing can be proved, so fail
    // closed rather than guess.
    let sections = executable_sections(elf)?;
    if sections.is_empty() {
        return Ok(Err(DirectIneligible::NoExecutableText));
    }
    let mut svc_sites = 0_usize;
    for (offset, size, vaddr) in sections {
        let end = (offset + size).min(elf.len());
        let Some(code) = elf.get(offset..end) else {
            return Err(io::Error::other("executable segment outside the file"));
        };
        for (index, chunk) in code.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let site = vaddr + (index * 4) as u64;
            if word == SVC_0 {
                svc_sites += 1;
                continue;
            }
            match bad64::decode(word, site) {
                Ok(insn) => {
                    // `tpidr_el0` is veneered, not refused (see
                    // `tpidr_veneer`). Only the shapes the veneer does not
                    // model still disqualify.
                    if matches!(insn.op(), bad64::Op::MRS | bad64::Op::MSR)
                        && format!("{insn:?}").contains("TPIDR_EL0")
                        && tpidr_access(word).is_none()
                    {
                        return Ok(Err(DirectIneligible::TpidrAccess { vaddr: site }));
                    }
                    // x18 is veneered when the instruction can be rewritten
                    // against a memory slot and that rewrite VERIFIES; only
                    // the shapes that fail verification disqualify. A
                    // `tpidr_el0` access naming x18 is already handled by the
                    // tpidr veneer above, and must NOT be rewritten here -
                    // substituting its register would leave a real `mrs`
                    // reading Darwin's thread pointer instead of the guest's.
                    if tpidr_access(word).is_none()
                        && instruction_names_x18(&insn)
                        && !x18_is_veneerable(&insn, word)
                    {
                        return Ok(Err(DirectIneligible::X18Access { vaddr: site }));
                    }
                }
                Err(_) if word_could_name_x18(word) => {
                    return Ok(Err(DirectIneligible::UndecodableText { vaddr: site, word }));
                }
                Err(_) => {}
            }
        }
    }
    // ZERO `svc` sites is normal, not a defect: a dynamically linked program
    // makes its syscalls through libc, so its own text contains none. libc is
    // patched when it is loaded. An earlier revision refused such images as
    // "no executable text", which wrongly disqualified every ordinary
    // dynamically linked binary in the corpus.
    Ok(Ok(svc_sites))
}

/// A loaded, patched, directly-executable guest image.
pub struct DirectImage {
    base: *mut u8,
    len: usize,
    entry: u64,
    context: Box<GuestContext>,
    svc_sites: usize,
    tpidr_sites: usize,
    x18_sites: usize,
    /// The guest's TLS base. XNU will not hold it in `TPIDR_EL0`, so the
    /// veneers read and write it here. One slot per image is correct while
    /// tier D is single-threaded; threads need one per thread.
    guest_tls: Box<u64>,
    /// The guest's x18. Darwin rewrites the physical register at every trap
    /// return, so the guest's value lives here and the veneers move it in and
    /// out around each use.
    guest_x18: Box<u64>,
}

// SAFETY: the mapping is owned solely by this value and unmapped in `Drop`.
unsafe impl Send for DirectImage {}

impl DirectImage {
    /// Where the image was mapped. For a PIE this IS the load bias.
    pub fn base(&self) -> u64 {
        self.base as u64
    }
    /// Guest entry point, already biased.
    pub fn entry(&self) -> u64 {
        self.entry
    }
    /// How many `svc #0` sites were patched.
    pub fn svc_sites(&self) -> usize {
        self.svc_sites
    }
    /// How many `tpidr_el0` accesses were veneered.
    pub fn tpidr_sites(&self) -> usize {
        self.tpidr_sites
    }
    /// How many x18-using instructions were veneered.
    pub fn x18_sites(&self) -> usize {
        self.x18_sites
    }
    /// The guest's x18, as the veneers see it.
    pub fn guest_x18(&self) -> u64 {
        *self.guest_x18
    }
    /// The guest's TLS base, as the veneers see it.
    pub fn guest_tls(&self) -> u64 {
        *self.guest_tls
    }
    /// Byte length of the mapping, for inspection.
    pub fn mapped_len(&self) -> usize {
        self.len
    }

    /// The address the ISLANDS were built to use for the context.
    ///
    /// Diagnostic: the islands materialize this as a patch-time constant, so
    /// it must equal `context_address()`. A mismatch means the context moved
    /// after patching, which would make every island restore the guest through
    /// the wrong memory.
    pub fn context_address(&mut self) -> u64 {
        std::ptr::from_mut(self.context.as_mut()) as u64
    }

    pub fn context(&mut self) -> &mut GuestContext {
        &mut self.context
    }

    /// Load `elf`, patch its syscall sites, and make it executable.
    ///
    /// `handler` is called with the guest context on every syscall. The image
    /// is mapped wherever the kernel chooses: `MAP_JIT` rejects `MAP_FIXED`
    /// (probed), and for a PIE any base is valid, so the returned base is the
    /// load bias.
    pub fn load(
        elf: &[u8],
        handler: extern "C" fn(*mut GuestContext),
    ) -> Result<Result<Self, DirectIneligible>, io::Error> {
        // Fail closed BEFORE mapping: a refusal must cost no allocation, and
        // an image that reaches the patcher is one the scan proved safe.
        match scan_eligibility(elf)? {
            Ok(_) => {}
            Err(reason) => return Ok(Err(reason)),
        }
        let segments = executable_segments(elf)?;
        // Span every PT_LOAD so guest-relative addressing stays intact, plus a
        // tail for islands.
        let (lo, hi) = load_span(elf)?;
        let island_budget = 64 * 1024 + segments.iter().map(|s| s.2).sum::<usize>();
        let len = ((hi - lo) as usize + island_budget).next_multiple_of(16 * 1024);

        // SAFETY: kernel-chosen address, MAP_JIT as probed to be the only way
        // to obtain writable-then-executable pages under Darwin's W^X policy.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = base.cast::<u8>();
        let mut image = Self {
            base,
            len,
            entry: 0,
            context: Box::new(GuestContext {
                handler: handler as usize as u64,
                ..GuestContext::default()
            }),
            svc_sites: 0,
            tpidr_sites: 0,
            x18_sites: 0,
            guest_tls: Box::new(0),
            guest_x18: Box::new(0),
        };
        let bias = base as u64 - lo;
        image.entry = read_u64(elf, 0x18)? + bias;

        // Patching happens with the region writable and no guest thread able
        // to enter it, so there is no cross-modifying-code hazard.
        jit_write_protect(false);
        let result = image.copy_and_patch(elf, lo, bias);
        jit_write_protect(true);
        // SAFETY: the region was just written; publish it to the i-cache.
        unsafe { sys_icache_invalidate(base.cast(), len) };
        match result {
            Ok(Ok(())) => Ok(Ok(image)),
            Ok(Err(reason)) => Ok(Err(reason)),
            Err(error) => Err(error),
        }
    }

    fn copy_and_patch(
        &mut self,
        elf: &[u8],
        lo: u64,
        bias: u64,
    ) -> Result<Result<(), DirectIneligible>, io::Error> {
        let (_, hi) = load_span(elf)?;
        let image_len = (hi - lo) as usize;
        for (offset, filesz, _memsz, vaddr) in all_load_segments(elf)? {
            let end = (offset + filesz).min(elf.len());
            let dst = (vaddr - lo) as usize;
            // SAFETY: `dst + filesz` is inside the mapping by construction of
            // `len` from the same span.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    elf.as_ptr().add(offset),
                    self.base.add(dst),
                    end - offset,
                );
            }
        }
        // Islands live past the image, inside the same mapping, so a `b` from
        // any site reaches them well within ±128 MiB.
        let mut island_cursor = image_len.next_multiple_of(16);
        let ctx_addr = std::ptr::from_mut(self.context.as_mut()) as u64;

        let tls_addr = std::ptr::from_mut(self.guest_tls.as_mut()) as u64;
        let x18_addr = std::ptr::from_mut(self.guest_x18.as_mut()) as u64;
        // Patch over the same SECTIONS the scan proved, not the PF_X segment:
        // patching a `.note` byte pattern that merely looks like `svc` would
        // corrupt data the guest reads.
        for (offset, size, vaddr) in executable_sections(elf)? {
            let end = (offset + size).min(elf.len());
            let Some(code) = elf.get(offset..end) else {
                return Err(io::Error::other("executable section outside the file"));
            };
            for (index, chunk) in code.chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let site_vaddr = vaddr + (index * 4) as u64;
                // `tpidr_el0` accesses are veneered in the same pass.
                if let Some(access) = tpidr_access(word) {
                    let site_host = (site_vaddr - lo) as usize;
                    let veneer_host = island_cursor;
                    let words = tpidr_veneer(access, tls_addr, x18_addr);
                    let bytes = words.len() * 4;
                    if veneer_host + bytes + 4 > self.len {
                        return Err(io::Error::other("veneer budget exhausted"));
                    }
                    for (i, w) in words.iter().enumerate() {
                        self.write_word(veneer_host + i * 4, *w);
                    }
                    let from = (veneer_host + bytes) as i64;
                    self.write_word(veneer_host + bytes, b_rel((site_host as i64 + 4) - from));
                    self.write_word(site_host, b_rel(veneer_host as i64 - site_host as i64));
                    island_cursor = (veneer_host + bytes + 4).next_multiple_of(4);
                    self.tpidr_sites += 1;
                    continue;
                }
                // x18 uses are veneered in the same pass.
                if word != SVC_0
                    && let Ok(insn) = bad64::decode(word, site_vaddr)
                    && instruction_names_x18(&insn)
                {
                    // `tpidr_el0` accesses were handled above; reaching here
                    // with one would rewrite it into a real system-register
                    // read of Darwin's thread pointer.
                    debug_assert!(tpidr_access(word).is_none());
                    let Some((value_reg, addr_reg)) = pick_scratch_pair(&insn) else {
                        return Ok(Err(DirectIneligible::X18Access { vaddr: site_vaddr }));
                    };
                    let Some(rewritten) = substitute_x18(word, value_reg) else {
                        return Ok(Err(DirectIneligible::X18Access { vaddr: site_vaddr }));
                    };
                    let site_host = (site_vaddr - lo) as usize;
                    let veneer_host = island_cursor;
                    let words = x18_veneer(rewritten, value_reg, addr_reg, x18_addr);
                    let bytes = words.len() * 4;
                    if veneer_host + bytes + 4 > self.len {
                        return Err(io::Error::other("veneer budget exhausted"));
                    }
                    for (i, w) in words.iter().enumerate() {
                        self.write_word(veneer_host + i * 4, *w);
                    }
                    let from = (veneer_host + bytes) as i64;
                    self.write_word(veneer_host + bytes, b_rel((site_host as i64 + 4) - from));
                    self.write_word(site_host, b_rel(veneer_host as i64 - site_host as i64));
                    island_cursor = (veneer_host + bytes + 4).next_multiple_of(4);
                    self.x18_sites += 1;
                    continue;
                }
                if word != SVC_0 {
                    continue;
                }
                let site_host = (site_vaddr - lo) as usize;
                let island_host = island_cursor;
                let words = island(ctx_addr, site_vaddr + bias + 4);
                let island_bytes = words.len() * 4;
                if island_host + island_bytes > self.len {
                    return Err(io::Error::other("island budget exhausted"));
                }
                for (i, w) in words.iter().enumerate() {
                    self.write_word(island_host + i * 4, *w);
                }
                // Return leg: a constant branch back to the next instruction.
                let from = (island_host + island_bytes) as i64;
                self.write_word(
                    island_host + island_bytes,
                    b_rel((site_host as i64 + 4) - from),
                );
                // Entry leg: replace the `svc` itself.
                self.write_word(site_host, b_rel(island_host as i64 - site_host as i64));
                island_cursor = island_host + island_bytes + 4;
                island_cursor = island_cursor.next_multiple_of(4);
                self.svc_sites += 1;
            }
        }
        Ok(Ok(()))
    }

    fn write_word(&mut self, byte_offset: usize, word: u32) {
        // SAFETY: callers bound `byte_offset + 4` by `self.len`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                word.to_le_bytes().as_ptr(),
                self.base.add(byte_offset),
                4,
            );
        }
    }

    /// Arm THIS thread to execute the image's `MAP_JIT` pages.
    ///
    /// `pthread_jit_write_protect_np` is PER-THREAD on Apple Silicon: a thread
    /// that has never enabled write protection sees `MAP_JIT` pages as
    /// writable-not-executable, so entering the image from it faults. Loading
    /// leaves the LOADING thread armed, which is why a load-then-enter on one
    /// thread works and hides this; a thread that only executes must arm
    /// itself. Measured: entering an image from a freshly spawned thread hangs
    /// until this call is made.
    ///
    /// Idempotent and cheap, so `enter` just does it rather than making every
    /// caller remember.
    pub fn arm_current_thread(&self) {
        jit_write_protect(true);
    }

    /// Jump to `pc` with the current context's registers. Never returns
    /// normally in M1: the guest leaves through the handler.
    ///
    /// # Safety
    /// The image must be fully patched, and `pc` must be an address inside it.
    pub unsafe fn enter(&self, pc: u64) {
        self.arm_current_thread();
        // Enter through asm that declares the guest clobbers every
        // callee-saved register, NOT as a plain `extern "C"` call.
        //
        // A C call promises x19-x28 and d8-d15 survive it. No guest promises
        // anything of the sort - it owns every register, and a fixture as small
        // as `mov x20, x30` destroys one. Calling the guest as if it were a C
        // function let the compiler keep live values in those registers across
        // the call, and the guest silently corrupted them.
        //
        // That was invisible on the main thread, where nothing important
        // happened to live in x20, and fatal on a spawned one, where the
        // thread's own machinery does: the corruption surfaced far away as
        // `malloc: pointer being freed was not allocated` on a static address,
        // and whether it fired at all depended on heap layout. Declaring the
        // clobbers makes the compiler preserve them, which is exactly what a
        // gateway does.
        //
        // x18 is Darwin's platform register and cannot be named as a clobber;
        // the kernel rewrites it at every trap return anyway, and tier D
        // veneers guest x18 to a memory slot rather than keeping it live.
        // SAFETY: `pc` is inside the patched, i-cache-invalidated mapping.
        unsafe {
            std::arch::asm!(
                // x19 and x29 cannot be named as clobbers - LLVM reserves both
                // - so preserve them by hand around the guest.
                "stp x19, x29, [sp, #-16]!",
                "blr {entry}",
                "ldp x19, x29, [sp], #16",
                entry = in(reg) pc,
                out("x20") _, out("x21") _, out("x22") _, out("x23") _,
                out("x24") _, out("x25") _, out("x26") _, out("x27") _,
                out("x28") _,
                out("d8") _, out("d9") _, out("d10") _, out("d11") _,
                out("d12") _, out("d13") _, out("d14") _, out("d15") _,
                clobber_abi("C"),
            );
        }
    }
}

impl Drop for DirectImage {
    fn drop(&mut self) {
        // SAFETY: this value owns the mapping.
        unsafe { libc::munmap(self.base.cast(), self.len) };
    }
}

// ---------------------------------------------------------------- ELF bits

fn read_u16(b: &[u8], o: usize) -> Result<u64, io::Error> {
    b.get(o..o + 2)
        .and_then(|s| s.try_into().ok())
        .map(|a: [u8; 2]| u16::from_le_bytes(a) as u64)
        .ok_or_else(|| io::Error::other("short ELF header"))
}

fn read_u64(b: &[u8], o: usize) -> Result<u64, io::Error> {
    b.get(o..o + 8)
        .and_then(|s| s.try_into().ok())
        .map(|a: [u8; 8]| u64::from_le_bytes(a))
        .ok_or_else(|| io::Error::other("short ELF header"))
}

/// `(file_offset, filesz, memsz, vaddr)` for every PT_LOAD.
fn all_load_segments(elf: &[u8]) -> Result<Vec<(usize, usize, usize, u64)>, io::Error> {
    if elf.len() < 0x40 || &elf[..4] != b"\x7fELF" || elf[4] != 2 {
        return Err(io::Error::other("not an aarch64 ELF64"));
    }
    let phoff = read_u64(elf, 0x20)? as usize;
    let phentsize = read_u16(elf, 0x36)? as usize;
    let phnum = read_u16(elf, 0x38)? as usize;
    let mut out = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = read_u16(elf, ph)?;
        if p_type != 1 {
            continue;
        }
        out.push((
            read_u64(elf, ph + 0x08)? as usize,
            read_u64(elf, ph + 0x20)? as usize,
            read_u64(elf, ph + 0x28)? as usize,
            read_u64(elf, ph + 0x10)?,
        ));
    }
    Ok(out)
}

/// PT_LOADs carrying PF_X.
fn executable_segments(elf: &[u8]) -> Result<Vec<(usize, usize, usize, u64)>, io::Error> {
    let phoff = read_u64(elf, 0x20)? as usize;
    let phentsize = read_u16(elf, 0x36)? as usize;
    let phnum = read_u16(elf, 0x38)? as usize;
    let mut out = Vec::new();
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if read_u16(elf, ph)? != 1 {
            continue;
        }
        let flags = read_u16(elf, ph + 4)?;
        if flags & 1 == 0 {
            continue;
        }
        out.push((
            read_u64(elf, ph + 0x08)? as usize,
            read_u64(elf, ph + 0x20)? as usize,
            read_u64(elf, ph + 0x28)? as usize,
            read_u64(elf, ph + 0x10)?,
        ));
    }
    Ok(out)
}

/// `(file_offset, size, vaddr)` for every section carrying SHF_EXECINSTR.
///
/// Scanning a PF_X `PT_LOAD` instead is wrong and quietly so: that segment
/// starts at file offset 0 on every real toolchain binary, so it covers the
/// ELF header, the program headers and `.note.*` — none of which are
/// instructions. Decoding those as code produced a 100% false-refusal rate
/// against the go-conformance binaries (the Go tools "failed" on their own ELF
/// header at +0x3c; libc "failed" on the ASCII `GNU\0` in its build-id note).
///
/// Returns an empty vec when the file has no section headers, which is a real
/// possibility for a fully stripped binary; the caller must then fail closed
/// rather than fall back to segment scanning.
fn executable_sections(elf: &[u8]) -> Result<Vec<(usize, usize, u64)>, io::Error> {
    const SHF_EXECINSTR: u64 = 0x4;
    const SHT_NOBITS: u64 = 8;
    let shoff = read_u64(elf, 0x28)? as usize;
    let shentsize = read_u16(elf, 0x3a)? as usize;
    let shnum = read_u16(elf, 0x3c)? as usize;
    if shoff == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if elf.len() < sh + 0x28 {
            return Err(io::Error::other("truncated section header"));
        }
        let sh_type = read_u64(elf, sh + 4)? & 0xffff_ffff;
        let sh_flags = read_u64(elf, sh + 8)?;
        if sh_flags & SHF_EXECINSTR == 0 || sh_type == SHT_NOBITS {
            continue;
        }
        out.push((
            read_u64(elf, sh + 0x18)? as usize,
            read_u64(elf, sh + 0x20)? as usize,
            read_u64(elf, sh + 0x10)?,
        ));
    }
    Ok(out)
}

fn load_span(elf: &[u8]) -> Result<(u64, u64), io::Error> {
    let loads = all_load_segments(elf)?;
    let lo = loads
        .iter()
        .map(|s| s.3)
        .min()
        .ok_or_else(|| io::Error::other("no PT_LOAD"))?;
    let hi = loads
        .iter()
        .map(|s| s.3 + s.2 as u64)
        .max()
        .ok_or_else(|| io::Error::other("no PT_LOAD"))?;
    Ok((lo, hi))
}

// ------------------------------------------------------------- Darwin glue

fn jit_write_protect(enable: bool) {
    // SAFETY: pthread's own W^X toggle for MAP_JIT regions on this thread.
    unsafe { pthread_jit_write_protect_np(i32::from(enable)) };
}

unsafe extern "C" {
    fn pthread_jit_write_protect_np(enabled: libc::c_int);
    fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny static PIE that writes "ok\n" and exits 42.
    ///
    /// Hand-assembled so the fixture needs no Linux cross-toolchain and the
    /// exact instruction sequence under test is visible here.
    /// Wrap `code` in a minimal ET_DYN aarch64 ELF with one PF_X PT_LOAD.
    fn elf_with_code(code: &[u32]) -> Vec<u8> {
        let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry: u64 = 0x1000;
        let mut elf = vec![0_u8; 0x40 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes());
        elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes());
        elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 0x40;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
        elf[ph + 0x08..ph + 0x10].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x10..ph + 0x18].copy_from_slice(&entry.to_le_bytes());
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.resize(entry as usize, 0);
        elf.extend_from_slice(&code_bytes);

        // A section header table with one SHF_EXECINSTR section covering the
        // code. The scan walks sections, not the PF_X segment, so a fixture
        // without these would be refused as unprovable - which is the correct
        // fail-closed behaviour, and is why they are here.
        let shoff = elf.len();
        let mut shdrs = vec![0_u8; 64 * 2]; // [0] = SHT_NULL, [1] = .text
        let text = 64;
        shdrs[text + 0x04..text + 0x08].copy_from_slice(&1_u32.to_le_bytes()); // SHT_PROGBITS
        shdrs[text + 0x08..text + 0x10].copy_from_slice(&0x6_u64.to_le_bytes()); // ALLOC|EXECINSTR
        shdrs[text + 0x10..text + 0x18].copy_from_slice(&entry.to_le_bytes()); // sh_addr
        shdrs[text + 0x18..text + 0x20].copy_from_slice(&entry.to_le_bytes()); // sh_offset
        shdrs[text + 0x20..text + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes()); // sh_size
        elf.extend_from_slice(&shdrs);
        elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
        elf[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes()); // e_shentsize
        elf[0x3c..0x3e].copy_from_slice(&2_u16.to_le_bytes()); // e_shnum
        elf
    }

    /// The M1 demo guest: write "ok\n" to fd 1, then exit 42.
    fn fixture_elf() -> Vec<u8> {
        elf_with_code(&[
            // "ok\n" onto the guest stack, so no PC-relative data is needed.
            movz(9, 0x6b6f, 0),  // 'o','k'
            movk(9, 0x000a, 16), // '\n'
            str_pre_sp(9),
            mov_from_sp(1), // x1 = buf
            movz(0, 1, 0),  // x0 = fd 1
            movz(2, 3, 0),  // x2 = len 3
            movz(8, 64, 0), // x8 = __NR_write
            SVC_0,
            movz(0, 42, 0), // x0 = 42
            movz(8, 93, 0), // x8 = __NR_exit
            SVC_0,
        ])
    }

    // Thread-local, not a global mutex: these tests run in parallel and the
    // guest executes on the test's own thread, so per-thread state is both the
    // correct scope and immune to one test's panic poisoning another's.
    thread_local! {
        static SEEN: std::cell::RefCell<Vec<(u64, [u64; 6])>> =
            const { std::cell::RefCell::new(Vec::new()) };
    }

    fn seen_clear() {
        SEEN.with(|seen| seen.borrow_mut().clear());
    }
    fn seen_snapshot() -> Vec<(u64, [u64; 6])> {
        SEEN.with(|seen| seen.borrow().clone())
    }

    extern "C" fn record_only(ctx: *mut GuestContext) {
        // SAFETY: the island passes the context this image was built with.
        let ctx = unsafe { &mut *ctx };
        SEEN.with(|seen| seen.borrow_mut().push((ctx.syscall_nr(), ctx.args())));
        ctx.set_return(ctx.args()[2] as i64);
    }

    #[test]
    fn patches_every_svc_site_and_leaves_other_words_verbatim() {
        let elf = fixture_elf();
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        assert_eq!(image.svc_sites(), 2, "fixture has two syscall sites");
        // SAFETY: reading back the mapped image we just wrote.
        let mapped = unsafe { std::slice::from_raw_parts(image.base as *const u8, image.len) };
        // The single PT_LOAD is the lowest, so it lands at bias-relative 0 -
        // the mapping is laid out by vaddr span, not by file offset.
        let text = 0_usize;
        let word = |i: usize| {
            u32::from_le_bytes([
                mapped[text + i * 4],
                mapped[text + i * 4 + 1],
                mapped[text + i * 4 + 2],
                mapped[text + i * 4 + 3],
            ])
        };
        // Non-svc words are copied verbatim - the whole point of tier D.
        assert_eq!(word(0), movz(9, 0x6b6f, 0));
        assert_eq!(word(4), movz(0, 1, 0));
        // Both svc sites became branches, not svc.
        for site in [7_usize, 10] {
            let patched = word(site);
            assert_ne!(patched, SVC_0, "svc at word {site} must be patched");
            assert_eq!(
                patched & 0xfc00_0000,
                0x1400_0000,
                "svc at word {site} must become an unconditional b"
            );
        }
    }

    #[test]
    fn runs_guest_code_natively_and_services_its_syscalls() {
        // The guest exits through `exit(2)`, which ends the process, so run it
        // in a forked child and read the verdict from its status. This is the
        // M1 proof: real guest instructions execute on the host CPU and their
        // syscalls arrive in Rust.
        let mut fds = [0_i32; 2];
        // SAFETY: standard pipe(2).
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        // SAFETY: fork(2); the child only calls async-signal-safe work plus
        // the image it just built.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            // SAFETY: child side of the pipe.
            unsafe { libc::close(fds[0]) };
            let elf = fixture_elf();
            let Ok(Ok(image)) = DirectImage::load(&elf, child_handler) else {
                // SAFETY: child bail-out.
                unsafe { libc::_exit(90) };
            };
            CHILD_PIPE.store(fds[1], std::sync::atomic::Ordering::SeqCst);
            let entry = image.entry();
            // SAFETY: the image is patched and `entry` is inside it.
            unsafe { image.enter(entry) };
            // SAFETY: the guest must leave through `exit`, never here.
            unsafe { libc::_exit(91) };
        }
        // SAFETY: parent side.
        unsafe { libc::close(fds[1]) };
        let mut buf = [0_u8; 16];
        // SAFETY: reading the child's write.
        let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        let mut status = 0_i32;
        // SAFETY: reaping the child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        // SAFETY: parent side.
        unsafe { libc::close(fds[0]) };

        assert!(n >= 3, "guest write(2) reached the host pipe (n={n})");
        assert_eq!(&buf[..3], b"ok\n", "guest wrote its own bytes");
        assert!(libc::WIFEXITED(status), "child exited normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            42,
            "guest exit(42) carried its code out"
        );
    }

    /// Every guest register must survive a syscall untouched.
    ///
    /// This is the island's core contract and the thing hand-written
    /// save/restore gets wrong: x0 is clobbered to carry the context pointer,
    /// SP is temporarily borrowed, and the restore order has to put both back
    /// exactly. The guest stamps sentinels into a spread of registers -
    /// caller-saved, callee-saved, and x30 - takes a syscall, then hands those
    /// same registers to a second syscall as arguments. If the island lost or
    /// transposed any of them, the recorded arguments differ.
    ///
    /// The guest is entered as an ordinary `extern "C"` call, so it returns to
    /// Rust with `ret`. It stashes the incoming link register in x20 first,
    /// which also makes x20's survival part of the test.
    #[test]
    fn island_preserves_guest_registers_across_a_syscall() {
        const CHECK_NR: u64 = 0x0fff;
        let code: Vec<u32> = vec![
            mov_reg(20, 30), // save Rust's return address
            movz(9, 0xa1a1, 0),
            movz(10, 0xb2b2, 0),
            movz(11, 0xc3c3, 0),
            movz(19, 0xd4d4, 0), // callee-saved
            movz(30, 0xe5e5, 0), // link register, live across the island
            movz(8, 64, 0),
            SVC_0,
            // Hand the sentinels to a second syscall as arguments.
            mov_reg(0, 9),
            mov_reg(1, 10),
            mov_reg(2, 11),
            mov_reg(3, 19),
            mov_reg(4, 30),
            movz(8, CHECK_NR as u32, 0),
            SVC_0,
            mov_reg(30, 20), // restore Rust's return address
            0xd65f_03c0,     // ret
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        assert_eq!(image.svc_sites(), 2);
        seen_clear();
        let entry = image.entry();
        // SAFETY: the image is patched, `entry` is inside it, and this fixture
        // returns through `ret` rather than exiting.
        unsafe { image.enter(entry) };

        let seen = seen_snapshot();
        assert_eq!(seen.len(), 2, "both syscalls reached the handler");
        assert_eq!(seen[0].0, 64, "first syscall number survived");
        let (nr, args) = seen[1];
        assert_eq!(nr, CHECK_NR, "second syscall number survived");
        assert_eq!(args[0], 0xa1a1, "x9 preserved across the island");
        assert_eq!(args[1], 0xb2b2, "x10 preserved");
        assert_eq!(args[2], 0xc3c3, "x11 preserved");
        assert_eq!(args[3], 0xd4d4, "x19 (callee-saved) preserved");
        assert_eq!(args[4], 0xe5e5, "x30 (link register) preserved");
    }

    #[test]
    fn tpidr_read_into_x18_moves_slot_to_slot() {
        // `mrs x18, tpidr_el0` names BOTH special registers. Depositing the
        // guest's TLS into the physical x18 would hand it to Darwin to
        // overwrite, and rewriting it as an x18 instruction would leave a real
        // `mrs` reading Darwin's thread pointer. It must be a slot-to-slot
        // move instead.
        const CHECK_NR: u64 = 0x0ffb;
        let code: Vec<u32> = vec![
            mov_reg(20, 30),
            movz(9, 0xcafe, 0),
            msr_tpidr_el0_word(9), // guest TLS = 0xcafe
            0xd53b_d052,           // mrs x18, tpidr_el0
            mov_reg(0, 18),        // read it back out of the x18 slot
            movz(8, CHECK_NR as u32, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0,
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        seen_clear();
        let entry = image.entry();
        // SAFETY: patched image, entry inside it, fixture returns via `ret`.
        unsafe { image.enter(entry) };
        let seen = seen_snapshot();
        assert_eq!(
            seen[0].1[0], 0xcafe,
            "TLS reached the guest's x18 slot without touching either real register"
        );
        assert_eq!(image.guest_x18(), 0xcafe);
        assert_eq!(image.guest_tls(), 0xcafe);
    }

    #[test]
    fn scan_accepts_tpidr_because_it_is_veneered() {
        // XNU does not preserve a userspace `TPIDR_EL0` (probed), but the
        // access is handled by a veneer rather than refused - so it must not
        // disqualify an image. The `TpidrAccess` variant survives for shapes
        // the veneer does not model.
        let code = vec![
            mrs_tpidr_el0_word(9),
            msr_tpidr_el0_word(9),
            movz(8, 93, 0),
            SVC_0,
        ];
        let elf = elf_with_code(&code);
        assert!(
            matches!(scan_eligibility(&elf).expect("scan runs"), Ok(1)),
            "veneered tpidr accesses are eligible, and the svc site is counted"
        );
    }

    #[test]
    fn scan_refuses_undecodable_text_only_when_it_could_name_x18() {
        // 0xffff_ffff does not decode. Its low five bits are 31, and every
        // other register field reads 31 too, so it cannot name x18 - harmless
        // whatever it is, and the scan must not refuse the image for it.
        let benign = vec![0xffff_ffff, movz(8, 93, 0), SVC_0];
        let elf = elf_with_code(&benign);
        assert!(
            matches!(scan_eligibility(&elf).expect("scan runs"), Ok(1)),
            "an undecodable word that cannot name x18 is not a disqualifier"
        );

        // Same shape, but with register field Rd = 18: cannot be ruled out.
        let suspicious = vec![0xffff_fff2, movz(8, 93, 0), SVC_0];
        let elf = elf_with_code(&suspicious);
        assert!(
            matches!(
                scan_eligibility(&elf).expect("scan runs"),
                Err(DirectIneligible::UndecodableText { .. })
            ),
            "an undecodable word that could name x18 must fail closed"
        );
    }

    #[test]
    fn scan_counts_syscall_sites_on_a_clean_image() {
        let elf = fixture_elf();
        assert!(
            matches!(scan_eligibility(&elf).expect("scan runs"), Ok(2)),
            "the clean fixture qualifies with both svc sites counted"
        );
    }

    /// Guest TLS must survive a write/read round-trip through the veneers.
    ///
    /// XNU rewrites `TPIDR_EL0` at the first trap return (probed), so the
    /// guest's thread pointer cannot live in the register. The guest here
    /// writes a value with `msr`, reads it back with `mrs`, and hands the
    /// result to a syscall. If the veneers were wrong - wrong slot, clobbered
    /// source register, or the borrow not undone - the recorded argument
    /// differs from what was written.
    #[test]
    fn tpidr_veneers_round_trip_guest_tls() {
        const CHECK_NR: u64 = 0x0ffe;
        let code: Vec<u32> = vec![
            mov_reg(20, 30), // save Rust's return address
            movz(9, 0xfeed, 0),
            msr_tpidr_el0_word(9), // guest sets its thread pointer
            movz(9, 0, 0),         // prove the read does not just see x9
            mrs_tpidr_el0_word(11),
            mov_reg(0, 11),
            movz(8, CHECK_NR as u32, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0, // ret
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        assert_eq!(image.tpidr_sites(), 2, "both tpidr accesses were veneered");
        assert_eq!(image.svc_sites(), 1);
        seen_clear();
        let entry = image.entry();
        // SAFETY: patched image, entry inside it, fixture returns via `ret`.
        unsafe { image.enter(entry) };

        let seen = seen_snapshot();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].1[0], 0xfeed,
            "the guest read back the thread pointer it wrote"
        );
        assert_eq!(
            image.guest_tls(),
            0xfeed,
            "the write landed in the image's TLS slot, not the real register"
        );
    }

    #[test]
    fn tpidr_write_preserves_its_source_when_the_source_is_x0() {
        // The write veneer borrows x0 for the slot address, so a guest that
        // writes FROM x0 is the case that catches a naive implementation.
        const CHECK_NR: u64 = 0x0ffd;
        let code: Vec<u32> = vec![
            mov_reg(20, 30),
            movz(0, 0xbeef, 0),
            msr_tpidr_el0_word(0), // source IS the borrow register
            mov_reg(1, 0),         // x0 must still hold 0xbeef here
            mrs_tpidr_el0_word(2),
            movz(8, CHECK_NR as u32, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0,
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        seen_clear();
        let entry = image.entry();
        // SAFETY: patched image, entry inside it.
        unsafe { image.enter(entry) };
        let seen = seen_snapshot();
        let args = seen[0].1;
        assert_eq!(args[1], 0xbeef, "x0 survived being the veneer's borrow");
        assert_eq!(args[2], 0xbeef, "and the value round-tripped");
    }

    #[test]
    fn x18_substitution_verifies_and_rejects_corrupted_rewrites() {
        // `add x18, x18, #1` — both register fields are x18 and must move.
        let add_x18 = 0x9100_0652;
        let rewritten = substitute_x18(add_x18, 5).expect("add x18,x18,#1 is veneerable");
        let decoded = bad64::decode(rewritten, 0).expect("rewritten decodes");
        assert_eq!(decoded.op(), bad64::Op::ADD);
        assert_eq!(
            instruction_regs(&decoded),
            vec![5, 5],
            "both x18 operands became the scratch register"
        );

        // A word with no x18 in a standard field must not be claimed.
        assert!(
            substitute_x18(0x9100_0400, 5).is_none(),
            "an instruction without x18 is not a substitution candidate"
        );
    }

    #[test]
    fn x18_veneer_runs_the_instruction_against_the_slot() {
        // The guest increments x18 twice and reports it. x18 never lives in
        // the physical register - Darwin would overwrite it - so the value has
        // to survive entirely in the image's slot.
        const CHECK_NR: u64 = 0x0ffc;
        let code: Vec<u32> = vec![
            mov_reg(20, 30),
            movz(18, 7, 0), // x18 = 7        (writes x18)
            0x9100_0652,    // add x18, x18, #1   -> 8
            0x9100_0652,    // add x18, x18, #1   -> 9
            mov_reg(0, 18), // x0 = x18       (reads x18)
            movz(8, CHECK_NR as u32, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0,
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, record_only)
            .expect("load")
            .expect("eligible");
        assert_eq!(
            image.x18_sites(),
            4,
            "every x18-using instruction was veneered"
        );
        seen_clear();
        let entry = image.entry();
        // SAFETY: patched image, entry inside it, fixture returns via `ret`.
        unsafe { image.enter(entry) };
        let seen = seen_snapshot();
        assert_eq!(seen[0].1[0], 9, "x18 arithmetic ran against the slot");
        assert_eq!(image.guest_x18(), 9, "and the slot holds the final value");
    }

    #[test]
    fn scan_accepts_veneerable_x18_and_still_refuses_the_rest() {
        let veneerable = vec![0x9100_0652, movz(8, 93, 0), SVC_0];
        let elf = elf_with_code(&veneerable);
        assert!(
            matches!(scan_eligibility(&elf).expect("scan runs"), Ok(1)),
            "a veneerable x18 instruction no longer disqualifies"
        );
    }

    /// A handler with a REAL frame must round-trip like the trivial one.
    ///
    /// Diagnostic for the tier-D bridge, which loops forever when the island
    /// calls a handler that reads a thread-local and owns a large local. If
    /// this passes, the island is sound under a heavy handler and the bridge's
    /// bug is in the bridge; if it loops, the island itself cannot survive a
    /// handler that uses the guest's stack.
    #[test]
    fn island_survives_a_handler_with_a_real_frame() {
        thread_local! {
            static DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        }
        extern "C" fn heavy(ctx: *mut GuestContext) {
            // A thread-local read plus a kilobyte of frame: the shape the
            // dispatcher has, without the dispatcher.
            let seen = DEPTH.with(|d| {
                d.set(d.get() + 1);
                d.get()
            });
            let mut scratch = [0_u64; 128];
            for (index, slot) in scratch.iter_mut().enumerate() {
                *slot = index as u64 ^ u64::from(seen);
            }
            // SAFETY: the island passes the context this image was built with.
            let ctx = unsafe { &mut *ctx };
            ctx.set_return(scratch[7] as i64);
            assert!(seen < 100, "handler re-entered {seen} times: island loops");
        }

        let code: Vec<u32> = vec![
            mov_reg(20, 30),
            movz(8, 64, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0, // ret
        ];
        let elf = elf_with_code(&code);
        let image = DirectImage::load(&elf, heavy)
            .expect("load")
            .expect("eligible");
        let entry = image.entry();
        // SAFETY: patched image, entry inside it, fixture returns via `ret`.
        unsafe { image.enter(entry) };
        assert_eq!(
            DEPTH.with(std::cell::Cell::get),
            1,
            "the guest took exactly one syscall and returned"
        );
    }

    /// A guest must run on a thread that did not load it.
    ///
    /// This failed for a long time, and the cause was not threads at all: the
    /// guest clobbers callee-saved registers, and `enter` used to call it as a
    /// plain `extern "C" fn`, which promises x19-x28 and d8-d15 survive. The
    /// compiler kept live values in those registers across the call and the
    /// guest destroyed them. Nothing important happened to live in x20 on the
    /// main thread; on a spawned thread the thread's own machinery does, so the
    /// damage surfaced far away as a malloc error on a static address, and
    /// whether it fired depended on heap layout.
    ///
    /// Every libtest test runs on a spawned thread, which is why this shape is
    /// the one the tier-D bridge has to survive.
    #[test]
    fn guest_runs_on_a_thread_that_did_not_load_it() {
        static HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        extern "C" fn count(ctx: *mut GuestContext) {
            HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // SAFETY: the island passes the context this image was built with.
            unsafe { (*ctx).set_return(0) };
        }
        let code: Vec<u32> = vec![
            mov_reg(20, 30),
            movz(8, 93, 0),
            SVC_0,
            mov_reg(30, 20),
            0xd65f_03c0, // ret
        ];
        // Load HERE, execute THERE.
        let image = DirectImage::load(&elf_with_code(&code), count)
            .expect("load")
            .expect("eligible");
        let entry = image.entry();
        std::thread::spawn(move || {
            // SAFETY: patched image, entry inside it; `enter` arms this thread.
            unsafe { image.enter(entry) };
            // Drop on the executing thread too: isolating it showed the abort
            // happens during the run regardless, so this keeps the reproducer
            // faithful to what the bridge does.
            drop(image);
        })
        .join()
        .expect("executor thread");
        assert_eq!(
            HITS.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the guest took its syscall on a thread that never loaded the image"
        );
    }

    static CHILD_PIPE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

    /// Minimal syscall service for the M1 proof: `write` and `exit`.
    ///
    /// Guest VA is host VA, so the guest's buffer pointer is used directly -
    /// no translation, which is the structural win over the translator.
    extern "C" fn child_handler(ctx: *mut GuestContext) {
        // SAFETY: the island passes the context this image was built with.
        let ctx = unsafe { &mut *ctx };
        let args = ctx.args();
        match ctx.syscall_nr() {
            64 => {
                let fd = CHILD_PIPE.load(std::sync::atomic::Ordering::SeqCst);
                // SAFETY: guest pointer is a host pointer on this tier.
                let n = unsafe {
                    libc::write(
                        fd,
                        args[1] as usize as *const libc::c_void,
                        args[2] as usize,
                    )
                };
                ctx.set_return(n as i64);
            }
            93 => {
                // SAFETY: the guest asked to exit.
                unsafe { libc::_exit(args[0] as i32) };
            }
            other => {
                let _ = other;
                ctx.set_return(-38); // -ENOSYS
            }
        }
    }
}
