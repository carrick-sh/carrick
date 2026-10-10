#![allow(dead_code)]

use carrick_mem::memory::el1_vectors_bytes;
use std::sync::atomic::AtomicU32;

pub const REGION_ALIGN: usize = 0x4000;
pub const LOWER_EL_SYNC_OFFSET: usize = 0x400;
pub const PORTAL_SLOT_BASE: u64 = 0x0041_4000;
pub const PORTAL_EXIT_NR: u16 = 1;

pub const AARCH64_SVC0: u32 = 0xd400_0001;
pub const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
pub const AARCH64_HVC_SYSCALL_OPCODE: u32 = 0xd400_0042;

/// One fixed-layout host/EL1 protocol slot used only by the feasibility probe.
///
/// The fields are named and offset-checked so the emitted instructions and
/// host helper share a typed protocol rather than ad-hoc byte offsets.
#[repr(C, align(64))]
pub struct PortalSlot {
    pub request: AtomicU32,
    pub response: AtomicU32,
    pub stop: AtomicU32,
    pub _reserved: [u8; 52],
}

impl PortalSlot {
    pub const fn new() -> Self {
        Self {
            request: AtomicU32::new(0),
            response: AtomicU32::new(0),
            stop: AtomicU32::new(0),
            _reserved: [0; 52],
        }
    }
}

impl Default for PortalSlot {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(std::mem::size_of::<PortalSlot>() == 64);
const _: () = assert!(std::mem::align_of::<PortalSlot>() == 64);

pub fn enc_movz_xn(reg: u32, imm16: u16, hw: u32) -> u32 {
    0xD280_0000 | (hw << 21) | (u32::from(imm16) << 5) | (reg & 0x1f)
}

pub fn enc_movk_xn(reg: u32, imm16: u16, hw: u32) -> u32 {
    0xF280_0000 | (hw << 21) | (u32::from(imm16) << 5) | (reg & 0x1f)
}

pub fn enc_cmp_x8_imm(imm: u16) -> u32 {
    0xF100_011F | ((u32::from(imm) & 0xfff) << 10)
}

pub fn enc_bne(pc: usize, target: usize) -> u32 {
    let imm19 = (((target as i64 - pc as i64) >> 2) as u32) & 0x7ffff;
    0x5400_0001 | (imm19 << 5)
}

pub fn enc_add_xd_xn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
    0x9100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
}

pub fn enc_ldr_wt_xn(rt: u32, rn: u32, offset: usize) -> u32 {
    0xB940_0000 | ((((offset / 4) as u32) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rt & 0x1f)
}

pub fn enc_add_wd_wn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
    0x1100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
}

pub fn enc_subs_xd_xn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
    0xF100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
}

pub fn enc_stlr_wt_xn(rt: u32, rn: u32) -> u32 {
    0x889F_FC00 | ((rn & 0x1f) << 5) | (rt & 0x1f)
}

pub fn enc_ldar_wt_xn(rt: u32, rn: u32) -> u32 {
    0x88DF_FC00 | ((rn & 0x1f) << 5) | (rt & 0x1f)
}

pub fn enc_cmp_wn_wm(rn: u32, rm: u32) -> u32 {
    0x6B00_001F | ((rm & 0x1f) << 16) | ((rn & 0x1f) << 5)
}

pub fn put_word(bytes: &mut [u8], offset: usize, word: u32) {
    bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
}

/// EL1 handler for the experiment. SVCs with x8=0 publish `request` and
/// wait for the matching `response`; nonzero x8 exits to the host. The
/// latter provides one untimed ready exit and one timed exit after the
/// full batch, without adding a separate instruction protocol.
pub fn portal_vector_page() -> Vec<u8> {
    let mut bytes = el1_vectors_bytes();
    let mut pc = LOWER_EL_SYNC_OFFSET;
    let emit = |bytes: &mut [u8], pc: &mut usize, word: u32| {
        put_word(bytes, *pc, word);
        *pc += 4;
    };
    emit(&mut bytes, &mut pc, enc_cmp_x8_imm(0));
    let exit_branch = pc;
    emit(&mut bytes, &mut pc, 0);
    emit(
        &mut bytes,
        &mut pc,
        enc_movz_xn(16, PORTAL_SLOT_BASE as u16, 0),
    );
    for half in 1..4 {
        emit(
            &mut bytes,
            &mut pc,
            enc_movk_xn(16, (PORTAL_SLOT_BASE >> (half * 16)) as u16, half),
        );
    }
    emit(
        &mut bytes,
        &mut pc,
        enc_ldr_wt_xn(17, 16, std::mem::offset_of!(PortalSlot, request)),
    );
    emit(&mut bytes, &mut pc, enc_add_wd_wn_imm(17, 17, 1));
    emit(&mut bytes, &mut pc, enc_stlr_wt_xn(17, 16));
    emit(&mut bytes, &mut pc, enc_add_xd_xn_imm(16, 16, 4));
    let poll = pc;
    emit(&mut bytes, &mut pc, enc_ldar_wt_xn(0, 16));
    emit(&mut bytes, &mut pc, enc_cmp_wn_wm(0, 17));
    let poll_branch = pc;
    emit(&mut bytes, &mut pc, enc_bne(poll_branch, poll));
    emit(&mut bytes, &mut pc, enc_movz_xn(0, 0, 0));
    emit(&mut bytes, &mut pc, AARCH64_ERET_OPCODE);
    let exit = pc;
    emit(&mut bytes, &mut pc, AARCH64_HVC_SYSCALL_OPCODE);
    emit(&mut bytes, &mut pc, AARCH64_ERET_OPCODE);
    put_word(&mut bytes, exit_branch, enc_bne(exit_branch, exit));
    bytes
}

pub fn portal_guest_code_page() -> Vec<u8> {
    let mut bytes = vec![0u8; REGION_ALIGN];
    // Untimed ready exit: the timed run starts after the trampoline and
    // first EL0->EL1->host transition have completed.
    put_word(&mut bytes, 0, enc_movz_xn(8, PORTAL_EXIT_NR, 0));
    put_word(&mut bytes, 4, AARCH64_SVC0);
    put_word(&mut bytes, 8, enc_movz_xn(8, 0, 0));
    put_word(&mut bytes, 12, AARCH64_SVC0);
    put_word(&mut bytes, 16, enc_subs_xd_xn_imm(20, 20, 1));
    put_word(&mut bytes, 20, enc_bne(20, 12));
    put_word(&mut bytes, 24, enc_movz_xn(8, PORTAL_EXIT_NR, 0));
    put_word(&mut bytes, 28, AARCH64_SVC0);
    put_word(&mut bytes, 32, 0x1400_0000); // b .
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_slot_has_stable_typed_layout() {
        assert_eq!(std::mem::align_of::<PortalSlot>(), 64);
        assert_eq!(std::mem::size_of::<PortalSlot>(), 64);
        assert_eq!(std::mem::offset_of!(PortalSlot, request), 0);
        assert_eq!(std::mem::offset_of!(PortalSlot, response), 4);
        assert_eq!(std::mem::offset_of!(PortalSlot, stop), 8);
    }

    #[test]
    fn portal_vector_routes_one_svc_through_shared_state_before_batch_exit() {
        let words = portal_vector_page()
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
            .collect::<Vec<_>>();
        let sync = 0x400 / 4;
        assert_eq!(words[sync], enc_cmp_x8_imm(0));
        assert!(words[sync..].contains(&enc_stlr_wt_xn(17, 16)));
        assert!(words[sync..].contains(&enc_ldar_wt_xn(0, 16)));
        assert!(words[sync..].contains(&AARCH64_HVC_SYSCALL_OPCODE));
        assert!(words[sync..].contains(&AARCH64_ERET_OPCODE));
    }
}
