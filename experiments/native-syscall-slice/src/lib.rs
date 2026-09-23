//! Bounded research executor; deliberately outside the product dependency graph.
use anyhow::{Result, bail, ensure};
use carrick_guest_mem::{CurrentMmMemory, GuestMemory, MemoryError};
use std::{ops::Range, sync::Arc};

pub mod carrier_memory;
pub mod native;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Instruction {
    Integer,
    Syscall,
    Branch,
    Address,
    Memory,
    Tls,
}

fn reserved(r: u32) -> bool {
    r == 18 || r == 28
}

/// A whitelist, never a default "copy unknown instruction" path.
pub fn classify(w: u32) -> Result<Instruction, &'static str> {
    let rd = w & 31;
    let rn = (w >> 5) & 31;
    let rm = (w >> 16) & 31;
    if w == 0xd4000001 {
        return Ok(Instruction::Syscall);
    }
    if w & 0xffe0001f == 0xd520001f {
        return Err("unqualified system instruction");
    }
    if w & !31 == 0xd53bd040 || w & !31 == 0xd51bd040 {
        return Ok(Instruction::Tls);
    }
    if w & 0x7c000000 == 0x14000000 && w >> 31 == 0
        || w & 0xff000010 == 0x54000000 && w & 15 < 14
        || w & 0x7e000000 == 0x34000000 && !reserved(rd)
    {
        return Ok(Instruction::Branch);
    }
    if w & 0x1f000000 == 0x10000000 {
        return Ok(Instruction::Address);
    }
    // Only unsigned-offset scalar 32/64-bit LDR/STR, no atomics or SIMD.
    if w & 0x3f000000 == 0x39000000 && w >> 30 >= 2 && (w >> 22) & 3 <= 1 {
        return Ok(Instruction::Memory);
    }
    if reserved(rd) {
        return Err("reserved physical destination");
    }
    let wide =
        w & 0x1f800000 == 0x12800000 && (w >> 29) & 3 != 1 && (w >> 31 != 0 || (w >> 21) & 3 < 2);
    let immediate = w & 0x1f800000 == 0x11000000
        && !reserved(rn)
        && rn != 31
        && (rd != 31 || w & (1 << 29) != 0);
    let shifted = w & 0x1f200000 == 0x0b000000
        && !reserved(rn)
        && !reserved(rm)
        && (w >> 22) & 3 != 3
        && (w >> 31 != 0 || w & (1 << 15) == 0);
    let mov = w & 0x7fe0ffe0 == 0x2a0003e0 && !reserved(rm);
    if wide || immediate || shifted || mov {
        Ok(Instruction::Integer)
    } else {
        Err("instruction outside bounded native subset")
    }
}

pub fn validate_word(word: u32) -> Result<(), &'static str> {
    classify(word).map(|_| ())
}

#[derive(Clone)]
struct Segment {
    base: u64,
    bytes: Vec<u8>,
    flags: u32,
    ever_executable: bool,
}

/// Private identity and exclusive ownership prevent cross-MM code reuse and
/// concurrent mutation. No host pointer or clone of the backing is exposed.
pub struct Memory {
    segments: Vec<Segment>,
    identity: Arc<()>,
    epoch: u64,
}

pub struct Image {
    pub(crate) identity: Arc<()>,
    pub(crate) epoch: u64,
    pub(crate) base: u64,
    pub(crate) entry: u64,
    pub(crate) words: Vec<u32>,
}
impl Image {
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn words(&self) -> &[u32] {
        &self.words
    }
}

impl Memory {
    /// Read-only initialization bytes for the bounded single data segment.
    /// This exposes no carrier authority; syscall copies must use the carrier.
    pub fn writable_data(&self) -> Result<(u64, &[u8])> {
        let mut found = self
            .segments
            .iter()
            .filter(|s| s.flags == 6 && !s.ever_executable);
        let data = found
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing writable ELF data"))?;
        ensure!(
            found.next().is_none(),
            "bounded executor requires one data segment"
        );
        Ok((data.base, &data.bytes))
    }
    pub fn load_elf(bytes: &[u8]) -> Result<(Self, Image)> {
        let elf = goblin::elf::Elf::parse(bytes)?;
        ensure!(
            elf.is_64
                && elf.little_endian
                && elf.header.e_machine == 183
                && elf.header.e_type == 2
                && elf.interpreter.is_none(),
            "requires static AArch64 ET_EXEC"
        );
        let mut memory = Self {
            segments: Vec::new(),
            identity: Arc::new(()),
            epoch: 1,
        };
        let mut code = None;
        for p in &elf.program_headers {
            if p.p_type != 1 {
                continue;
            }
            ensure!(
                p.p_memsz > 0 && p.p_memsz <= 16 * 1024 * 1024 && p.p_filesz <= p.p_memsz,
                "invalid/beyond bounded segment size"
            );
            ensure!(
                p.p_flags & !7 == 0 && p.p_flags & 3 != 3,
                "W+X mapping rejected"
            );
            let end = p
                .p_vaddr
                .checked_add(p.p_memsz)
                .ok_or_else(|| anyhow::anyhow!("segment overflow"))?;
            ensure!(
                memory
                    .segments
                    .iter()
                    .all(|s| end <= s.base || p.p_vaddr >= s.base + s.bytes.len() as u64),
                "overlapping ELF segments"
            );
            let file_end = p
                .p_offset
                .checked_add(p.p_filesz)
                .ok_or_else(|| anyhow::anyhow!("file overflow"))?;
            let source = bytes
                .get(usize::try_from(p.p_offset)?..usize::try_from(file_end)?)
                .ok_or_else(|| anyhow::anyhow!("truncated ELF"))?;
            let mut backing = vec![0; p.p_memsz as usize];
            backing[..source.len()].copy_from_slice(source);
            if p.p_flags & 1 != 0 {
                ensure!(
                    code.is_none() && p.p_vaddr % 4 == 0 && p.p_memsz % 4 == 0,
                    "one aligned code segment required"
                );
                code = Some((
                    p.p_vaddr,
                    backing
                        .chunks_exact(4)
                        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                        .collect::<Vec<_>>(),
                ));
            }
            memory.segments.push(Segment {
                base: p.p_vaddr,
                bytes: backing,
                flags: p.p_flags,
                ever_executable: p.p_flags & 1 != 0,
            });
        }
        let (base, words) = code.ok_or_else(|| anyhow::anyhow!("no executable segment"))?;
        ensure!(
            elf.entry >= base && elf.entry < base + words.len() as u64 * 4 && elf.entry % 4 == 0,
            "invalid entry"
        );
        for (i, &word) in words.iter().enumerate() {
            classify(word)
                .map_err(|e| anyhow::anyhow!("{:#x}: {word:08x}: {e}", base + i as u64 * 4))?;
        }
        let image = Image {
            identity: memory.identity.clone(),
            epoch: memory.epoch,
            base,
            entry: elf.entry,
            words,
        };
        Ok((memory, image))
    }
    pub fn validate(&self, image: &Image) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.identity, &image.identity) && self.epoch == image.epoch,
            "stale or wrong-MM executable capability"
        );
        self.range(image.base, image.words.len() * 4, 1)?;
        Ok(())
    }
    fn range(
        &self,
        address: u64,
        length: usize,
        permission: u32,
    ) -> Result<(usize, Range<usize>), MemoryError> {
        let fail = || MemoryError::OutOfBounds { address, length };
        let end = address.checked_add(length as u64).ok_or_else(fail)?;
        self.segments
            .iter()
            .enumerate()
            .find_map(|(i, s)| {
                (address >= s.base
                    && end <= s.base + s.bytes.len() as u64
                    && s.flags & permission == permission)
                    .then(|| (i, (address - s.base) as usize..(end - s.base) as usize))
            })
            .ok_or_else(fail)
    }
    /// Experimental mapping mutation boundary, used by revocation tests.
    /// A product mprotect/unmap/foreign-write path is not implemented here.
    pub fn protect(&mut self, base: u64, flags: u32) -> Result<()> {
        ensure!(flags & !7 == 0 && flags & 3 != 3, "W+X rejected");
        let s = self
            .segments
            .iter_mut()
            .find(|s| s.base == base)
            .ok_or_else(|| anyhow::anyhow!("mapping absent"))?;
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("generation exhaustion"))?;
        s.flags = flags;
        s.ever_executable |= flags & 1 != 0;
        Ok(())
    }
    pub fn unmap(&mut self, base: u64) -> Result<()> {
        let i = self
            .segments
            .iter()
            .position(|s| s.base == base)
            .ok_or_else(|| anyhow::anyhow!("mapping absent"))?;
        self.epoch = self
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("generation exhaustion"))?;
        self.segments.remove(i);
        Ok(())
    }
}
impl GuestMemory for Memory {
    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let (i, r) = self.range(address, length, 4)?;
        Ok(self.segments[i].bytes[r].to_vec())
    }
    fn read_into_raw(&self, address: u64, dst: &mut [u8]) -> Result<(), MemoryError> {
        let (i, r) = self.range(address, dst.len(), 4)?;
        dst.copy_from_slice(&self.segments[i].bytes[r]);
        Ok(())
    }
    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let (i, r) = self.range(address, bytes.len(), 2)?;
        // Even writes while formerly executable backing is RW revoke drafts.
        if self.segments[i].ever_executable {
            self.epoch = self.epoch.checked_add(1).ok_or(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            })?;
        }
        self.segments[i].bytes[r].copy_from_slice(bytes);
        Ok(())
    }
}
impl CurrentMmMemory for Memory {}

pub fn branch_target(w: u32, pc: u64) -> u64 {
    let offset = if w & 0x7c000000 == 0x14000000 {
        ((w << 6) as i32 >> 4) as i64
    } else {
        (((w >> 5) & 0x7ffff) << 13) as i32 as i64 >> 11
    };
    pc.wrapping_add_signed(offset)
}

pub fn condition(w: u32, nzcv: u64) -> bool {
    let n = nzcv & (1 << 31) != 0;
    let z = nzcv & (1 << 30) != 0;
    let c = nzcv & (1 << 29) != 0;
    let v = nzcv & (1 << 28) != 0;
    let base = match (w & 15) >> 1 {
        0 => z,
        1 => c,
        2 => n,
        3 => v,
        4 => c && !z,
        5 => n == v,
        6 => !z && n == v,
        _ => true,
    };
    base ^ (w & 1 != 0)
}

/// Slow lowering never dereferences a semantic guest address in host code.
pub fn emulate(w: u32, state: &mut native::State, memory: &mut impl GuestMemory) -> Result<()> {
    let r = (w & 31) as usize;
    let kind = classify(w).map_err(anyhow::Error::msg)?;
    let next = state.pc + 4;
    match kind {
        Instruction::Branch => {
            let taken = if w & 0x7c000000 == 0x14000000 {
                true
            } else if w & 0xff000010 == 0x54000000 {
                condition(w, state.nzcv)
            } else {
                let value = if r == 31 { 0 } else { state.x[r] };
                let value = if w >> 31 == 0 {
                    value as u32 as u64
                } else {
                    value
                };
                (value != 0) == (w & (1 << 24) != 0)
            };
            state.pc = if taken {
                branch_target(w, state.pc)
            } else {
                next
            };
            return Ok(());
        }
        Instruction::Address => {
            let imm = ((((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)) << 11;
            let imm = (imm as i32 >> 11) as i64;
            if r != 31 {
                state.x[r] = if w >> 31 == 0 {
                    state.pc.wrapping_add_signed(imm)
                } else {
                    (state.pc & !4095).wrapping_add_signed(imm << 12)
                };
            }
        }
        Instruction::Tls => {
            if w & !31 == 0xd53bd040 {
                if r != 31 {
                    state.x[r] = state.tls;
                }
            } else {
                state.tls = if r == 31 { 0 } else { state.x[r] };
            }
        }
        Instruction::Memory => {
            let base = ((w >> 5) & 31) as usize;
            let width = 1usize << (w >> 30);
            let address = (if base == 31 { state.sp } else { state.x[base] })
                .wrapping_add(((w >> 10) & 4095) as u64 * width as u64);
            if w & (1 << 22) != 0 {
                let mut bytes = [0; 8];
                memory.read_into(address, &mut bytes[..width])?;
                if r != 31 {
                    state.x[r] = u64::from_le_bytes(bytes);
                }
            } else {
                let value = if r == 31 { 0 } else { state.x[r] };
                memory.write_bytes(address, &value.to_le_bytes()[..width])?;
            }
        }
        _ => bail!("not a slow instruction"),
    }
    state.pc = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn publish_compact(image: &Image, memory: &Memory) -> Result<native::Code> {
        native::Code::publish_with_layout(image, memory, native::Layout::Compact)
    }
    pub(super) fn elf(words: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x3000];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, v) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 2)] {
            bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        for (at, v) in [(24, 0x400000u64), (32, 64)] {
            bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
        }
        for (i, base, len, flags) in [
            (0, 0x400000u64, words.len() * 4, 5u32),
            (1, 0x500000, 4096, 6),
        ] {
            let h = 64 + i * 56;
            bytes[h..h + 4].copy_from_slice(&1u32.to_le_bytes());
            bytes[h + 4..h + 8].copy_from_slice(&flags.to_le_bytes());
            for (offset, value) in [
                (8, 0x1000u64 * (i as u64 + 1)),
                (16, base),
                (32, len as u64),
                (40, len as u64),
                (48, 4096),
            ] {
                bytes[h + offset..h + offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        for (i, w) in words.iter().enumerate() {
            bytes[0x1000 + i * 4..0x1004 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn accepts_real_syscall_and_integer_instructions() {
        for word in [0xd2800368, 0xd4000001, 0xf1000694, 0xb5ffffb4] {
            validate_word(word).expect("bounded native instruction");
        }
    }
    #[test]
    fn rejects_host_register_stack_and_system_instructions() {
        for word in [0xd2800032, 0xd280003c, 0x910043ff, 0xd4001001, 0xd65f03c0] {
            assert!(validate_word(word).is_err(), "{word:08x}");
        }
    }
    #[test]
    fn same_va_isolation_permissions_and_revocation() {
        let bytes = elf(&[0xd28000e0, 0xd4000001]);
        let (mut a, ai) = Memory::load_elf(&bytes).unwrap();
        let (mut b, bi) = Memory::load_elf(&bytes).unwrap();
        assert!(a.validate(&bi).is_err());
        assert!(a.write_bytes(0x400000, &[0; 4]).is_err());
        a.write_bytes(0x500000, &[42; 8]).unwrap();
        a.validate(&ai).unwrap();
        assert_eq!(b.read_bytes(0x500000, 8).unwrap(), [0; 8]);
        assert!(a.read_bytes(u64::MAX, 8).is_err());
        assert!(a.protect(0x400000, 7).is_err());
        a.protect(0x400000, 6).unwrap();
        a.write_bytes(0x400000, &0xd2800100u32.to_le_bytes())
            .unwrap();
        a.protect(0x400000, 5).unwrap();
        assert!(a.validate(&ai).is_err());
        b.unmap(0x400000).unwrap();
        assert!(b.validate(&bi).is_err());
    }
    #[test]
    fn native_data_demand_covers_branches_cycles_and_checkpoint_barriers() {
        // Explicit control-flow cases: a false result must exclude *every*
        // native memory path, not merely the most likely or fallthrough path.
        let cases: &[(&[u32], &[bool])] = &[
            (
                &[0x91000400, 0xd4000001, 0xf9400020, 0xd4000001],
                &[false, false, true, false],
            ),
            (
                &[0xb4000040, 0xd4000001, 0xf9400020, 0xd4000001],
                &[true, false, true, false],
            ),
            (&[0x14000002, 0xf9400020, 0xd4000001], &[false, true, false]),
            (&[0xd4000001, 0xf9400020, 0x17ffffff], &[false, true, true]),
            (
                &[0xd1000400, 0xb5ffffe0, 0xd4000001, 0xf9400020, 0xd4000001],
                &[false, false, false, true, false],
            ),
            (
                &[0xd1000400, 0xb5ffffe0, 0xf9400020, 0xd4000001],
                &[true, true, true, false],
            ),
            (&[0xd51bd040, 0xf9400020, 0xd4000001], &[false, true, false]),
            (&[0x10000012, 0xf9400020, 0xd4000001], &[false, true, false]),
        ];
        for &(words, expected) in cases {
            let (memory, image) = Memory::load_elf(&elf(words)).unwrap();
            let code = publish_compact(&image, &memory).unwrap();
            for (index, &demand) in expected.iter().enumerate() {
                assert_eq!(
                    code.requires_native_data(image.base + index as u64 * 4)
                        .unwrap(),
                    demand,
                    "{words:x?} at {index}"
                );
            }
            assert!(code.requires_native_data(image.base - 4).is_err());
            assert!(code.requires_native_data(image.base + 1).is_err());
            assert!(
                code.requires_native_data(image.base + words.len() as u64 * 4)
                    .is_err()
            );
        }
        for word in [0x14000002, 0x17ffffff, 0xb4000040] {
            let (memory, image) = Memory::load_elf(&elf(&[word, 0xd4000001])).unwrap();
            assert!(publish_compact(&image, &memory).is_err());
        }
    }

    #[test]
    fn native_integer_syscalls_preserve_registers_vectors_and_flags() {
        use native::State;
        // mov x0,#7; mov x17,#17; cmp x0,#7; svc; add x0,x0,#1; svc
        let (mut memory, image) = Memory::load_elf(&elf(&[
            0xd28000e0, 0xd2800231, 0xf1001c1f, 0xd4000001, 0x91000400, 0xd4000001,
        ]))
        .unwrap();
        let code = publish_compact(&image, &memory).unwrap();
        let mut state = State::new(image.entry);
        for i in 0..31 {
            state.x[i] = (i * 37 + 3) as u64;
        }
        state.sp = 0x500800;
        state.tls = 0xabcd;
        for i in 0..32 {
            state.vectors[i] = (i + 1) as u128 * 0x12345678;
        }
        let original = state.x;
        let vectors = state.vectors;
        let mut calls = 0;
        code.run(&image, &mut memory, &mut state, &mut |s, _| {
            calls += 1;
            for (i, &expected) in original.iter().enumerate().skip(1) {
                assert_eq!(s.x[i], if i == 17 { 17 } else { expected }, "x{i}");
            }
            assert_eq!(s.vectors, vectors);
            assert_eq!(s.sp, 0x500800);
            assert_eq!(s.tls, 0xabcd);
            assert_eq!(s.nzcv, 0x60000000);
            assert_eq!(s.x[0], if calls == 1 { 7 } else { 100 });
            s.x[0] = 99;
            s.pc += 4;
            Ok(calls == 1)
        })
        .unwrap();
        assert_eq!(calls, 2);
    }
    #[test]
    fn executable_revocation_and_wrong_publication_stop_before_resume() {
        use native::State;
        let bytes = elf(&[0xd4000001, 0x17ffffff]);
        let (mut a, ai) = Memory::load_elf(&bytes).unwrap();
        let (mut b, bi) = Memory::load_elf(&bytes).unwrap();
        let code = publish_compact(&ai, &a).unwrap();
        assert!(
            code.run(&bi, &mut b, &mut State::new(bi.entry), &mut |_, _| panic!(
                "must not enter"
            ))
            .is_err()
        );
        let mut calls = 0;
        let result = code.run(&ai, &mut a, &mut State::new(ai.entry), &mut |s, m| {
            calls += 1;
            m.protect(ai.base, 6)?;
            m.write_bytes(ai.base, &0xd4001001u32.to_le_bytes())?;
            s.pc += 4;
            Ok(true)
        });
        assert!(result.is_err());
        assert_eq!(calls, 1);
    }
    #[test]
    fn backward_edges_are_bounded_and_tls_is_virtual() {
        use native::State;
        // msr tpidr_el0,x0; mrs x1,tpidr_el0; b .
        let (mut m, i) = Memory::load_elf(&elf(&[0xd51bd040, 0xd53bd041, 0x14000000])).unwrap();
        let code = publish_compact(&i, &m).unwrap();
        let mut state = State::new(i.entry);
        state.x[0] = 0x987654321;
        let mut callbacks = 0;
        code.run(&i, &mut m, &mut state, &mut |s, m| {
            callbacks += 1;
            emulate(i.words[((s.pc - i.base) / 4) as usize], s, m)?;
            Ok(callbacks < 10)
        })
        .unwrap();
        assert_eq!(callbacks, 10);
        assert_eq!(state.x[1], 0x987654321);
    }
    #[test]
    fn bounded_native_loop_does_not_call_rust_per_iteration() {
        use native::State;
        // mov x0,#1024; sub x0,x0,#1; cbnz x0,previous; svc
        let (mut m, i) =
            Memory::load_elf(&elf(&[0xd2808000, 0xd1000400, 0xb5ffffe0, 0xd4000001])).unwrap();
        let code = publish_compact(&i, &m).unwrap();
        let mut state = State::new(i.entry);
        let mut callbacks = 0;
        code.run(&i, &mut m, &mut state, &mut |s, m| {
            callbacks += 1;
            let word = i.words[((s.pc - i.base) / 4) as usize];
            if classify(word).unwrap() == Instruction::Syscall {
                assert_eq!(s.x[0], 0);
                return Ok(false);
            }
            emulate(word, s, m)?;
            Ok(true)
        })
        .unwrap();
        assert!(
            callbacks <= 5,
            "1024 backedges made {callbacks} host callbacks"
        );
    }
    #[test]
    fn native_memory_work_budget() {
        use native::State;
        // ldr x1,[x2]; add x1,x1,#1; str x1,[x2]; sub x0,x0,#1;
        // cbnz x0,loop; svc. Same semantic data backing as syscall buffers.
        let bytes = elf(&[
            0xf9400041, 0x91000421, 0xf9000041, 0xd1000400, 0xb5ffff80, 0xd4000001,
        ]);
        let mut slow_counts = Vec::new();
        for n in [1u64, 8, 32, 128, 1024] {
            let (mut m, i) = Memory::load_elf(&bytes).unwrap();
            let code = publish_compact(&i, &m).unwrap();
            let mut state = State::new(i.entry);
            state.x[0] = n;
            state.x[2] = 0x500000;
            state.nzcv = 0x90000000;
            let mut callbacks = 0;
            let mut memory_callbacks = 0;
            code.run(&i, &mut m, &mut state, &mut |s, m| {
                callbacks += 1;
                assert_eq!(s.nzcv, 0x90000000);
                let word = i.words[((s.pc - i.base) / 4) as usize];
                match classify(word).unwrap() {
                    Instruction::Syscall => return Ok(false),
                    Instruction::Memory => memory_callbacks += 1,
                    _ => {}
                }
                emulate(word, s, m)?;
                Ok(true)
            })
            .unwrap();
            assert_eq!(state.x[1], n);
            assert_eq!(m.read_bytes(0x500000, 8).unwrap(), n.to_le_bytes());
            slow_counts.push((n, memory_callbacks, callbacks));
        }
        assert!(
            slow_counts
                .iter()
                .all(|&(n, slow, all)| slow == 0 && all == n / 256 + 1),
            "native memory work budget: {slow_counts:?}"
        );
    }

    #[test]
    fn native_scalar_access_all_registers_matches_checked_memory() {
        use native::State;
        // All aliases, including scratch registers, Darwin-reserved virtual
        // registers, virtual SP, and W/XZR. Offset 4095 exercises both ADD parts.
        for rn in 0..32u32 {
            for rt in 0..32u32 {
                for width in [4u32, 8] {
                    for load in [false, true] {
                        for offset in [0u32, 1, 4095] {
                            let word = (if width == 8 { 0xf9000000 } else { 0xb9000000 })
                                | ((load as u32) << 22)
                                | (offset << 10)
                                | (rn << 5)
                                | rt;
                            let bytes = elf(&[word, 0xd4000001]);
                            let (mut memory, image) = Memory::load_elf(&bytes).unwrap();
                            let (mut expected_memory, _) = Memory::load_elf(&bytes).unwrap();
                            let value = 0xfedcba9876543210u64.to_le_bytes();
                            memory.write_bytes(0x500008, &value).unwrap();
                            expected_memory.write_bytes(0x500008, &value).unwrap();
                            let mut state = State::new(image.entry);
                            state.x = std::array::from_fn(|n| 0xaabbccdd00000000 | n as u64);
                            let base = 0x500008 - u64::from(offset * width);
                            if rn == 31 {
                                state.sp = base;
                            } else {
                                state.x[rn as usize] = base;
                            }
                            state.nzcv = u64::from((rn + rt) & 15) << 28;
                            state.tls = 0x123456;
                            state.vectors = std::array::from_fn(|n| (n as u128 + 1) << 64);
                            let vectors = state.vectors;
                            let mut expected = State::new(image.entry);
                            expected.x = state.x;
                            expected.sp = state.sp;
                            expected.nzcv = state.nzcv;
                            emulate(word, &mut expected, &mut expected_memory).unwrap();
                            let code = publish_compact(&image, &memory).unwrap();
                            let mut calls = 0;
                            code.run(&image, &mut memory, &mut state, &mut |s, _| {
                                calls += 1;
                                assert_eq!(s.pc, image.base + 4, "memory callback for {word:08x}");
                                Ok(false)
                            })
                            .unwrap();
                            assert_eq!(calls, 1);
                            assert_eq!(state.x, expected.x, "word {word:08x}");
                            assert_eq!(state.sp, expected.sp);
                            assert_eq!(state.nzcv, expected.nzcv);
                            assert_eq!(state.vectors, vectors);
                            assert_eq!(state.tls, 0x123456);
                            assert_eq!(
                                memory.read_bytes(0x500000, 24).unwrap(),
                                expected_memory.read_bytes(0x500000, 24).unwrap()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn native_memory_misses_preserve_fault_state_and_permissions() {
        use native::State;
        for width in [4u64, 8] {
            for load in [false, true] {
                for address in [
                    0,
                    0x400000,
                    0x500000 - 1,
                    0x500000,
                    0x501000 - width,
                    0x501001 - width,
                    0x501000,
                    u64::MAX,
                ] {
                    let word = (if width == 8 { 0xf9000000 } else { 0xb9000000 })
                        | ((load as u32) << 22)
                        | (2 << 5)
                        | 16;
                    let bytes = elf(&[word, 0xd4000001]);
                    let (mut memory, image) = Memory::load_elf(&bytes).unwrap();
                    let (mut expected_memory, _) = Memory::load_elf(&bytes).unwrap();
                    let mut state = State::new(image.entry);
                    state.x[2] = address;
                    state.x[16] = 0xfedcba9876543210;
                    state.x[17] = 0x1122334455667788;
                    state.nzcv = 0xb0000000;
                    let mut expected = State::new(image.entry);
                    expected.x = state.x;
                    let expected_ok = emulate(word, &mut expected, &mut expected_memory).is_ok();
                    let code = publish_compact(&image, &memory).unwrap();
                    let mut misses = 0;
                    let result = code.run(&image, &mut memory, &mut state, &mut |s, m| {
                        assert_eq!(s.nzcv, 0xb0000000);
                        if s.pc == image.base + 4 {
                            return Ok(false);
                        }
                        misses += 1;
                        emulate(word, s, m)?;
                        Ok(true)
                    });
                    assert_eq!(result.is_ok(), expected_ok, "{address:#x}/{width}/{load}");
                    assert_eq!(state.x, expected.x);
                    assert_eq!(state.nzcv, 0xb0000000);
                    assert_eq!(
                        misses,
                        usize::from(!(0x500000..=0x501000 - width).contains(&address))
                    );
                    assert_eq!(
                        memory.read_bytes(0x500000, 4096).unwrap(),
                        expected_memory.read_bytes(0x500000, 4096).unwrap()
                    );
                }
            }
        }
        // A read-only data segment must not acquire a write-capable cache.
        let mut bytes = elf(&[0xf9000040, 0xd4000001]);
        bytes[124..128].copy_from_slice(&4u32.to_le_bytes());
        let (mut memory, image) = Memory::load_elf(&bytes).unwrap();
        let code = publish_compact(&image, &memory).unwrap();
        let mut state = State::new(image.entry);
        state.x[2] = 0x500000;
        assert!(
            code.run(&image, &mut memory, &mut state, &mut |s, m| {
                emulate(image.words[0], s, m)?;
                Ok(true)
            })
            .is_err()
        );
        assert_eq!(memory.read_bytes(0x500000, 8).unwrap(), [0; 8]);
    }

    #[test]
    fn native_data_borrow_refresh_and_revocation_before_resume() {
        use native::State;
        // Load; callback; load; callback. Native and syscall-side byte access
        // must observe the exact same backing after every callback reborrow.
        let bytes = elf(&[0xf9400040, 0xd4000001, 0xf9400041, 0xd4000001]);
        for mutation in 0..5 {
            let (mut memory, image) = Memory::load_elf(&bytes).unwrap();
            let (other, _) = Memory::load_elf(&bytes).unwrap();
            let mut replacement = Some(other);
            memory.write_bytes(0x500000, &7u64.to_le_bytes()).unwrap();
            let code = publish_compact(&image, &memory).unwrap();
            let mut state = State::new(image.entry);
            state.x[2] = 0x500000;
            let mut calls = 0;
            let result = code.run(&image, &mut memory, &mut state, &mut |s, m| {
                calls += 1;
                assert_eq!(s.x[0], 7);
                if calls == 2 {
                    assert_eq!(s.x[1], 11);
                    return Ok(false);
                }
                match mutation {
                    0 => m.write_bytes(0x500000, &11u64.to_le_bytes())?,
                    1 => m.protect(0x500000, 4)?,
                    2 => m.unmap(0x500000)?,
                    3 => *m = replacement.take().unwrap(),
                    _ => {
                        m.protect(0x500000, 4)?;
                        m.protect(0x500000, 6)?;
                    }
                }
                s.pc += 4;
                Ok(true)
            });
            assert_eq!(result.is_ok(), mutation == 0);
            assert_eq!(calls, if mutation == 0 { 2 } else { 1 });
        }
    }
}

#[cfg(test)]
mod compact_tests;
