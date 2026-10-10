#![allow(dead_code)]

pub const COMPOUND_FRAME_SIZE: usize = 0x4000;
pub const STAGE1_PAGE_SIZE: usize = 0x1000;
pub const TABLE_ENTRIES: usize = STAGE1_PAGE_SIZE / 8;

pub const TRAMPOLINE_VA: u64 = 0x0040_0000;
pub const VECTOR_VA: u64 = 0x0040_4000;
pub const CODE_VA: u64 = 0x0040_8000;
pub const DATA_VA: u64 = 0x0040_c000;
pub const MAINTENANCE_VA: u64 = 0x0041_0000;
pub const WRITE_CODE_VA: u64 = CODE_VA + 0x100;

pub const TRAMPOLINE_IPA: u64 = 0x0100_0000;
pub const VECTOR_IPA: u64 = 0x0100_4000;
pub const CODE_IPA: u64 = 0x0100_8000;
pub const SHARED_DATA_IPA: u64 = 0x0100_c000;
pub const PRIVATE_DATA_IPA: u64 = 0x0101_0000;
pub const MAINTENANCE_IPA: u64 = 0x0101_4000;

pub const PARENT_L0_IPA: u64 = 0x0200_0000;
pub const PARENT_L1_IPA: u64 = 0x0200_4000;
pub const PARENT_L2_IPA: u64 = 0x0200_8000;
pub const PARENT_L3_IPA: u64 = 0x0200_c000;
pub const CHILD_L0_IPA: u64 = 0x0201_0000;
pub const CHILD_L1_IPA: u64 = 0x0201_4000;
pub const CHILD_L2_IPA: u64 = 0x0201_8000;
pub const CHILD_L3_IPA: u64 = 0x0201_c000;

pub const PARENT_ASID: u16 = 0x41;
pub const CHILD_ASID: u16 = 0x42;

pub const VALID: u64 = 1;
pub const TABLE_OR_PAGE: u64 = 0b11;
pub const AP_MASK: u64 = 0b11 << 6;
pub const AP_RW_EL0: u64 = 0b01 << 6;
pub const AP_RO_EL0: u64 = 0b11 << 6;
pub const INNER_SHAREABLE: u64 = 0b11 << 8;
pub const ACCESS_FLAG: u64 = 1 << 10;
pub const NOT_GLOBAL: u64 = 1 << 11;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;
pub const PA_MASK: u64 = 0x0000_ffff_ffff_f000;

pub const KERNEL_RX_PAGE: u64 = UXN | ACCESS_FLAG | INNER_SHAREABLE | TABLE_OR_PAGE;
pub const USER_RX_PAGE: u64 =
    PXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RW_EL0 | TABLE_OR_PAGE;
pub const USER_RO_DATA_PAGE: u64 =
    PXN | UXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RO_EL0 | TABLE_OR_PAGE;
pub const USER_RW_DATA_PAGE: u64 =
    PXN | UXN | NOT_GLOBAL | ACCESS_FLAG | INNER_SHAREABLE | AP_RW_EL0 | TABLE_OR_PAGE;

pub const AARCH64_SVC0: u32 = 0xd400_0001;
pub const AARCH64_B_SELF: u32 = 0x1400_0000;
pub const AARCH64_LDR_X0_X20: u32 = 0xf940_0280;
pub const AARCH64_STR_X1_X20: u32 = 0xf900_0281;
pub const AARCH64_DSB_ISHST: u32 = 0xd503_3a9f;
pub const AARCH64_TLBI_ASIDE1IS_X0: u32 = 0xd508_8340;
pub const AARCH64_DSB_ISH: u32 = 0xd503_3b9f;
pub const AARCH64_ISB: u32 = 0xd503_3fdf;
pub const AARCH64_HVC1: u32 = 0xd400_0022;

#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub struct TableIpas {
    pub l1: u64,
    pub l2: u64,
    pub l3: u64,
}

pub const PARENT_TABLE_IPAS: TableIpas = TableIpas {
    l1: PARENT_L1_IPA,
    l2: PARENT_L2_IPA,
    l3: PARENT_L3_IPA,
};

pub const CHILD_TABLE_IPAS: TableIpas = TableIpas {
    l1: CHILD_L1_IPA,
    l2: CHILD_L2_IPA,
    l3: CHILD_L3_IPA,
};

#[derive(::core::clone::Clone)]
pub struct TablePath {
    pub l0: Vec<u8>,
    pub l1: Vec<u8>,
    pub l2: Vec<u8>,
    pub l3: Vec<u8>,
}

pub fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}

pub fn table_descriptor(next_ipa: u64) -> u64 {
    (next_ipa & PA_MASK) | TABLE_OR_PAGE
}

pub fn leaf_descriptor(ipa: u64, flags: u64) -> u64 {
    assert_ne!(flags & VALID, 0, "probe leaf must be valid");
    (ipa & PA_MASK) | flags
}

pub fn read_descriptor(table: &[u8], index: usize) -> u64 {
    assert!(index < TABLE_ENTRIES);
    let offset = index * 8;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&table[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn write_descriptor(table: &mut [u8], index: usize, value: u64) {
    assert!(index < TABLE_ENTRIES);
    let offset = index * 8;
    table[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn map_compound_leaf(table: &mut [u8], va: u64, ipa: u64, flags: u64) {
    let first = indices(va)[3];
    assert!(first + 4 <= TABLE_ENTRIES);
    for page in 0..4usize {
        write_descriptor(
            table,
            first + page,
            leaf_descriptor(ipa + (page * STAGE1_PAGE_SIZE) as u64, flags),
        );
    }
}

pub fn build_parent_tables() -> TablePath {
    let mut path = TablePath {
        l0: vec![0; COMPOUND_FRAME_SIZE],
        l1: vec![0; COMPOUND_FRAME_SIZE],
        l2: vec![0; COMPOUND_FRAME_SIZE],
        l3: vec![0; COMPOUND_FRAME_SIZE],
    };
    let path_index = indices(DATA_VA);
    for va in [TRAMPOLINE_VA, VECTOR_VA, CODE_VA, DATA_VA, MAINTENANCE_VA] {
        let current = indices(va);
        assert_eq!(
            current[..3],
            path_index[..3],
            "probe VAs must share one L3 path"
        );
    }
    write_descriptor(
        &mut path.l0,
        path_index[0],
        table_descriptor(PARENT_TABLE_IPAS.l1),
    );
    write_descriptor(
        &mut path.l1,
        path_index[1],
        table_descriptor(PARENT_TABLE_IPAS.l2),
    );
    write_descriptor(
        &mut path.l2,
        path_index[2],
        table_descriptor(PARENT_TABLE_IPAS.l3),
    );
    map_compound_leaf(&mut path.l3, TRAMPOLINE_VA, TRAMPOLINE_IPA, KERNEL_RX_PAGE);
    map_compound_leaf(&mut path.l3, VECTOR_VA, VECTOR_IPA, KERNEL_RX_PAGE);
    map_compound_leaf(&mut path.l3, CODE_VA, CODE_IPA, USER_RX_PAGE);
    map_compound_leaf(&mut path.l3, DATA_VA, SHARED_DATA_IPA, USER_RO_DATA_PAGE);
    map_compound_leaf(
        &mut path.l3,
        MAINTENANCE_VA,
        MAINTENANCE_IPA,
        KERNEL_RX_PAGE,
    );
    path
}

pub fn build_child_root(parent: &TablePath) -> Vec<u8> {
    let mut root = parent.l0.clone();
    let index = indices(DATA_VA)[0];
    assert_eq!(
        read_descriptor(&root, index) & PA_MASK,
        PARENT_TABLE_IPAS.l1,
        "forked child root must initially share the parent L1"
    );
    root.shrink_to_fit();
    root
}

pub fn copy_child_table_path(
    parent: &TablePath,
    child_root: &mut [u8],
    child_l1: &mut [u8],
    child_l2: &mut [u8],
    child_l3: &mut [u8],
) {
    child_l1.copy_from_slice(&parent.l1);
    child_l2.copy_from_slice(&parent.l2);
    child_l3.copy_from_slice(&parent.l3);

    let index = indices(DATA_VA);
    write_descriptor(child_l1, index[1], table_descriptor(CHILD_TABLE_IPAS.l2));
    write_descriptor(child_l2, index[2], table_descriptor(CHILD_TABLE_IPAS.l3));
    map_compound_leaf(child_l3, DATA_VA, PRIVATE_DATA_IPA, USER_RW_DATA_PAGE);

    // Publish the new root edge last. The live implementation must use release
    // stores; this pure builder is also used by unit tests before publication.
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    write_descriptor(child_root, index[0], table_descriptor(CHILD_TABLE_IPAS.l1));
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn code_frame() -> Vec<u8> {
    let mut bytes = vec![0; COMPOUND_FRAME_SIZE];
    for (offset, word) in [AARCH64_LDR_X0_X20, AARCH64_SVC0, AARCH64_B_SELF]
        .into_iter()
        .enumerate()
    {
        bytes[offset * 4..offset * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (offset, word) in [AARCH64_STR_X1_X20, AARCH64_SVC0, AARCH64_B_SELF]
        .into_iter()
        .enumerate()
    {
        let byte = 0x100 + offset * 4;
        bytes[byte..byte + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

pub fn scoped_tlbi_frame() -> Vec<u8> {
    let mut bytes = vec![0; COMPOUND_FRAME_SIZE];
    for (offset, word) in [
        AARCH64_DSB_ISHST,
        AARCH64_TLBI_ASIDE1IS_X0,
        AARCH64_DSB_ISH,
        AARCH64_ISB,
        AARCH64_HVC1,
        AARCH64_B_SELF,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[offset * 4..offset * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

pub fn ttbr(root: u64, asid: u16) -> u64 {
    root | (u64::from(asid) << 48)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_tlbi_sequence_is_exact() {
        assert_eq!(
            [
                AARCH64_DSB_ISHST,
                AARCH64_TLBI_ASIDE1IS_X0,
                AARCH64_DSB_ISH,
                AARCH64_ISB,
                AARCH64_HVC1,
            ],
            [
                0xd503_3a9f,
                0xd508_8340,
                0xd503_3b9f,
                0xd503_3fdf,
                0xd400_0022
            ]
        );
        let frame = scoped_tlbi_frame();
        assert_eq!(&frame[4..8], &0xd508_8340_u32.to_le_bytes());
    }

    #[test]
    fn user_leaf_is_non_global_and_cow_source_is_read_only() {
        let parent = build_parent_tables();
        let leaf = read_descriptor(&parent.l3, indices(DATA_VA)[3]);
        assert_eq!(leaf & PA_MASK, SHARED_DATA_IPA);
        assert_ne!(leaf & VALID, 0);
        assert_ne!(leaf & NOT_GLOBAL, 0);
        assert_eq!(leaf & AP_MASK, AP_RO_EL0);
        assert_ne!(leaf & UXN, 0);
    }

    #[test]
    fn fork_root_shares_lower_tables_until_child_path_copy() {
        let parent = build_parent_tables();
        let mut child_root = build_child_root(&parent);
        let index = indices(DATA_VA);
        assert_eq!(
            read_descriptor(&child_root, index[0]) & PA_MASK,
            PARENT_TABLE_IPAS.l1
        );

        let mut child_l1 = vec![0; COMPOUND_FRAME_SIZE];
        let mut child_l2 = vec![0; COMPOUND_FRAME_SIZE];
        let mut child_l3 = vec![0; COMPOUND_FRAME_SIZE];
        copy_child_table_path(
            &parent,
            &mut child_root,
            &mut child_l1,
            &mut child_l2,
            &mut child_l3,
        );
        assert_eq!(
            read_descriptor(&child_root, index[0]) & PA_MASK,
            CHILD_TABLE_IPAS.l1
        );
        assert_eq!(
            read_descriptor(&child_l1, index[1]) & PA_MASK,
            CHILD_TABLE_IPAS.l2
        );
        assert_eq!(
            read_descriptor(&child_l2, index[2]) & PA_MASK,
            CHILD_TABLE_IPAS.l3
        );
        let child_leaf = read_descriptor(&child_l3, index[3]);
        assert_eq!(child_leaf & PA_MASK, PRIVATE_DATA_IPA);
        assert_eq!(child_leaf & AP_MASK, AP_RW_EL0);
        assert_ne!(child_leaf & NOT_GLOBAL, 0);

        let parent_leaf = read_descriptor(&parent.l3, index[3]);
        assert_eq!(parent_leaf & PA_MASK, SHARED_DATA_IPA);
        assert_eq!(parent_leaf & AP_MASK, AP_RO_EL0);
    }

    #[test]
    fn asid_lives_in_ttbr_high_half() {
        assert_eq!(ttbr(PARENT_L0_IPA, PARENT_ASID), 0x0041_0000_0200_0000);
        assert_eq!(ttbr(CHILD_L0_IPA, CHILD_ASID), 0x0042_0000_0201_0000);
    }

    #[test]
    fn read_and_write_routines_name_the_expected_registers() {
        let frame = code_frame();
        assert_eq!(&frame[..4], &AARCH64_LDR_X0_X20.to_le_bytes());
        assert_eq!(&frame[4..8], &AARCH64_SVC0.to_le_bytes());
        assert_eq!(&frame[0x100..0x104], &AARCH64_STR_X1_X20.to_le_bytes());
        assert_eq!(&frame[0x104..0x108], &AARCH64_SVC0.to_le_bytes());
    }
}
