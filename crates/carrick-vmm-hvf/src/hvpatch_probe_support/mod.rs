#![allow(dead_code)]

pub mod kernel_memory;
pub mod svc_tax;

pub const GUEST_CODE_BASE: u64 = 0x40_0000;
pub const ISLAND_CODE_BASE: u64 = 0x40_4000;
pub const INFO_PAGE_BASE: u64 = 0x40_8000;

pub const AARCH64_SVC0: u32 = 0xd400_0001;
pub const AARCH64_RET: u32 = 0xd65f_03c0;
pub const AARCH64_MOV_X0_42: u32 = 0xd280_0540;

pub fn encode_bl(pc: u64, target: u64) -> u32 {
    let delta = target as i64 - pc as i64;
    assert_eq!(delta & 3, 0, "BL target must be instruction aligned");
    let words = delta >> 2;
    assert!(
        (-(1_i64 << 25)..(1_i64 << 25)).contains(&words),
        "BL target is outside the signed imm26 range"
    );
    0x9400_0000 | ((words as u32) & 0x03ff_ffff)
}

pub fn encode_bne(pc: u64, target: u64) -> u32 {
    let delta = target as i64 - pc as i64;
    assert_eq!(delta & 3, 0, "B.NE target must be instruction aligned");
    let words = delta >> 2;
    assert!(
        (-(1_i64 << 18)..(1_i64 << 18)).contains(&words),
        "B.NE target is outside the signed imm19 range"
    );
    0x5400_0001 | (((words as u32) & 0x7ffff) << 5)
}

pub fn encode_subs_imm(rd: u32, rn: u32, imm12: u16) -> u32 {
    assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0xf100_0000 | (u32::from(imm12) << 10) | (rn << 5) | rd
}

pub fn encode_ldr_x(rt: u32, rn: u32, byte_offset: u16) -> u32 {
    assert!(rt < 32 && rn < 32);
    assert_eq!(byte_offset & 7, 0, "LDR X offset must be 8-byte aligned");
    0xf940_0000 | ((u32::from(byte_offset) / 8) << 10) | (rn << 5) | rt
}

pub fn words_to_page(words: &[u32]) -> Vec<u8> {
    assert!(words.len() * 4 <= 0x4000);
    let mut page = vec![0; 0x4000];
    for (index, word) in words.iter().enumerate() {
        let offset = index * 4;
        page[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    page
}

pub fn bl_probe_guest_words() -> Vec<u32> {
    vec![
        encode_bl(GUEST_CODE_BASE, ISLAND_CODE_BASE),
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn bl_probe_island_words() -> Vec<u32> {
    vec![AARCH64_MOV_X0_42, AARCH64_RET]
}

pub fn info_load_words() -> Vec<u32> {
    vec![
        encode_ldr_x(0, 20, 0),
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn tpidr_read_words() -> Vec<u32> {
    vec![
        0xd53b_d040,
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn compute_words() -> Vec<u32> {
    let mut words = compute_loop_words();
    words.extend([AARCH64_SVC0, 0x1400_0000]);
    words
}

pub fn host_compute_words() -> Vec<u32> {
    let mut words = compute_loop_words();
    words.push(AARCH64_RET);
    words
}

fn compute_loop_words() -> Vec<u32> {
    vec![
        0xaa02_03e9,
        0x8b01_0003,
        0xaa01_03e0,
        0xaa03_03e1,
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 20, GUEST_CODE_BASE + 4),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnderlyingExit {
    CompletionSvc,
    SystemRegisterRead,
    Other(u64),
}

pub fn classify_underlying_exit(esr: u64) -> UnderlyingExit {
    let exception_class = (esr >> 26) & 0x3f;
    match exception_class {
        0x15 => UnderlyingExit::CompletionSvc,
        0x18 => UnderlyingExit::SystemRegisterRead,
        other => UnderlyingExit::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_encoders_preserve_forward_and_backward_targets() {
        assert_eq!(encode_bl(0x40_0000, 0x40_4000), 0x9400_1000);
        assert_eq!(encode_bne(0x40_0008, 0x40_0000), 0x54ff_ffc1);
    }

    #[test]
    fn data_processing_encoders_name_the_intended_registers() {
        assert_eq!(encode_subs_imm(9, 9, 1), 0xf100_0529);
        assert_eq!(encode_ldr_x(0, 20, 0), 0xf940_0280);
        assert_eq!(encode_ldr_x(3, 20, 24), 0xf940_0e83);
    }

    #[test]
    fn word_page_is_little_endian_and_hvf_granule_sized() {
        let page = words_to_page(&[AARCH64_SVC0, AARCH64_RET]);
        assert_eq!(&page[..8], &[1, 0, 0, 0xd4, 0xc0, 3, 0x5f, 0xd6]);
        assert_eq!(page.len(), 0x4000);
        assert!(page[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bl_probe_calls_the_island_exactly_before_each_countdown_step() {
        assert_eq!(
            bl_probe_guest_words(),
            vec![
                0x9400_1000,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            bl_probe_island_words(),
            vec![AARCH64_MOV_X0_42, AARCH64_RET]
        );
    }

    #[test]
    fn info_load_and_tpidr_arms_share_the_same_counted_completion_shape() {
        assert_eq!(
            info_load_words(),
            vec![
                0xf940_0280,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            tpidr_read_words(),
            vec![
                0xd53b_d040,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
    }

    #[test]
    fn compute_arm_is_a_dependent_fibonacci_loop_with_one_completion_svc() {
        assert_eq!(
            compute_words(),
            vec![
                0xaa02_03e9,
                0x8b01_0003,
                0xaa01_03e0,
                0xaa03_03e1,
                0xf100_0529,
                0x54ff_ff81,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            host_compute_words(),
            vec![
                0xaa02_03e9,
                0x8b01_0003,
                0xaa01_03e0,
                0xaa03_03e1,
                0xf100_0529,
                0x54ff_ff81,
                AARCH64_RET,
            ]
        );
    }

    #[test]
    fn underlying_esr_classification_distinguishes_completion_from_sysreg_traps() {
        assert_eq!(
            classify_underlying_exit(0x15 << 26),
            UnderlyingExit::CompletionSvc
        );
        assert_eq!(
            classify_underlying_exit(0x18 << 26),
            UnderlyingExit::SystemRegisterRead
        );
        assert_eq!(
            classify_underlying_exit(0x24 << 26),
            UnderlyingExit::Other(0x24)
        );
    }
}
