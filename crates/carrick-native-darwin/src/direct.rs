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
    // Restore. SP first (through x1, restored after), then x30..x1, then x0.
    w.push(ldr_imm(1, 0, GuestContext::SP));
    w.push(mov_to_sp(1));
    for r in (1..=30_u32).rev() {
        w.push(ldr_imm(r, 0, GuestContext::REG + r * 8));
    }
    w.push(ldr_imm(0, 0, GuestContext::REG));
    w
}

/// Why an image cannot run on tier D.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectIneligible {
    /// bad64 could not decode a word in an executable region, so an x18 or
    /// `tpidr_el0` access cannot be ruled out. Fail closed: tier T owns it.
    UndecodableText { vaddr: u64, word: u32 },
    /// Guest TLS. M2 veneers these; M1 refuses them.
    TpidrAccess { vaddr: u64 },
    /// Darwin's platform register. M2 veneers these; M1 refuses them.
    X18Access { vaddr: u64 },
    /// No executable segment, or nothing to patch.
    NoExecutableText,
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
        }
    }
}

/// A loaded, patched, directly-executable guest image.
pub struct DirectImage {
    base: *mut u8,
    len: usize,
    entry: u64,
    context: Box<GuestContext>,
    svc_sites: usize,
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
        let segments = executable_segments(elf)?;
        if segments.is_empty() {
            return Ok(Err(DirectIneligible::NoExecutableText));
        }
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

        for (offset, filesz, _memsz, vaddr) in executable_segments(elf)? {
            let end = (offset + filesz).min(elf.len());
            let code = &elf[offset..end];
            for (index, chunk) in code.chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let site_vaddr = vaddr + (index * 4) as u64;
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

    /// Jump to `pc` with the current context's registers. Never returns
    /// normally in M1: the guest leaves through the handler.
    ///
    /// # Safety
    /// The image must be fully patched, and `pc` must be an address inside it.
    pub unsafe fn enter(&self, pc: u64) {
        // SAFETY: transmuting the mapped, i-cache-invalidated entry point to a
        // function and calling it. This is a one-way door in M1 (see the
        // module docs): the guest exits through the handler.
        unsafe {
            let entry: extern "C" fn() = std::mem::transmute(pc as usize as *const ());
            entry();
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
        elf
    }

    fn fixture_elf() -> Vec<u8> {
        let code: Vec<u32> = vec![
            // "ok\n" onto the guest stack, so no PC-relative data is needed.
            movz(9, 0x6b6f, 0),  // 'o','k'
            movk(9, 0x000a, 16), // '\n'
            str_pre_sp(9),       // str x9, [sp, #-16]!
            mov_from_sp(1),      // x1 = buf
            movz(0, 1, 0),       // x0 = fd 1
            movz(2, 3, 0),       // x2 = len 3
            movz(8, 64, 0),      // x8 = __NR_write
            SVC_0,
            movz(0, 42, 0), // x0 = 42
            movz(8, 93, 0), // x8 = __NR_exit
            SVC_0,
        ];
        let code_bytes: Vec<u8> = code.iter().flat_map(|w| w.to_le_bytes()).collect();
        let entry: u64 = 0x1000;
        let mut elf = vec![0_u8; 0x40 + 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // little endian
        elf[6] = 1; // EI_VERSION
        elf[0x10..0x12].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        elf[0x12..0x14].copy_from_slice(&183_u16.to_le_bytes()); // EM_AARCH64
        elf[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
        elf[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes()); // e_phoff
        elf[0x36..0x38].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        elf[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        let ph = 0x40;
        elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R|PF_X
        elf[ph + 0x08..ph + 0x10].copy_from_slice(&entry.to_le_bytes()); // p_offset
        elf[ph + 0x10..ph + 0x18].copy_from_slice(&entry.to_le_bytes()); // p_vaddr
        elf[ph + 0x20..ph + 0x28].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf[ph + 0x28..ph + 0x30].copy_from_slice(&(code_bytes.len() as u64).to_le_bytes());
        elf.resize(entry as usize, 0);
        elf.extend_from_slice(&code_bytes);
        elf
    }

    static SEEN: std::sync::Mutex<Vec<(u64, [u64; 6])>> = std::sync::Mutex::new(Vec::new());

    extern "C" fn record_only(ctx: *mut GuestContext) {
        // SAFETY: the island passes the context this image was built with.
        let ctx = unsafe { &mut *ctx };
        if let Ok(mut seen) = SEEN.lock() {
            seen.push((ctx.syscall_nr(), ctx.args()));
        }
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
        if let Ok(mut seen) = SEEN.lock() {
            seen.clear();
        }
        let entry = image.entry();
        // SAFETY: the image is patched, `entry` is inside it, and this fixture
        // returns through `ret` rather than exiting.
        unsafe { image.enter(entry) };

        let seen = SEEN.lock().expect("seen");
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
