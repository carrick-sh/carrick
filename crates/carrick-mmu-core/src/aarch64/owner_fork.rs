//! AArch64 descriptor and private control-window geometry for shared fork.
//!
//! # Authoritative Translation Geometry
//! The active stage-1 translation regime is programmed in `TCR_EL1`
//! (see `crates/carrick-mem/src/arch_sysregs.rs:43-58`):
//! - `T0SZ = 16`: 48-bit virtual address space ($64 - 16 = 48$ bits, `1 << 48`)
//! - `TG0 = 0b00`: 4 KiB translation granule (`1 << 12` = 4096 bytes)
//! - `IPS = 0b010`: 40-bit intermediate physical address space
//! - 4 levels of translation table walks with 512 entries (9 bits) each:
//!   - Level 0: bits \[47:39\], shift 39 (512 GiB block span)
//!   - Level 1: bits \[38:30\], shift 30 (1 GiB block span)
//!   - Level 2: bits \[29:21\], shift 21 (2 MiB block span)
//!   - Level 3: bits \[20:12\], shift 12 (4 KiB page span)
//!
//! # Kernel Control Window
//! The kernel control window is mapped in stage-1 translation at L1 index 180
//! (180 GiB = `180 << 30` = `0x2D_0000_0000`, see `crates/carrick-mem/src/memory.rs:220-222`
//! and `crates/carrick-mem/src/memory.rs:3896-3908`):
//! - Span: exactly one 2 MiB Level-2 block (`1 << 21` = `0x20_0000`)
//! - Stage-1 table primary alias: offset `0x2_0000`, span `0x1B_C000` (444 4 KiB pages)
//! - Per-process identity page: offset `0x1E_4000`, span `0x4000` (16 KiB / 4 pages)

use crate::aarch64::LeafAccess;
use crate::owner_mmu::{Aarch64Mmu, OwnerForkMmu, OwnerMmuRefusal};
use carrick_guest_arch::{FrameGpa, UserVa};

/// Stage-1 translation virtual address bits configured by TCR_EL1 (T0SZ=16).
pub const VA_BITS: u32 = 48;

/// Translation granule shift: 4 KiB (TG0=0b00).
pub const GRANULE_SHIFT: u32 = 12;

/// Translation granule size: 4096 bytes.
pub const GRANULE_SIZE: u64 = 1 << GRANULE_SHIFT;

/// Number of index bits per translation level: 9 (512 entries of 8 bytes = 4 KiB).
pub const LEVEL_BITS: u32 = 9;

/// Number of translation levels for 48-bit VA with 4 KiB granule: 4 (L0..=L3).
pub const LEVELS: usize = 4;

/// Bit shifts for each level in the 4-level translation walk.
pub const SHIFTS: [usize; LEVELS] = [39, 30, 21, 12];

/// Kernel control region base VA: 180 GiB (L1 index 180).
pub const KERNEL_CONTROL_BASE: u64 = 180 << 30; // 0x2D_0000_0000

/// Kernel control region span: 2 MiB (exactly one Level-2 block).
pub const KERNEL_CONTROL_SPAN: u64 = 1 << 21; // 0x20_0000

/// Kernel control region end VA: 0x2D_0020_0000.
pub const KERNEL_CONTROL_END: u64 = KERNEL_CONTROL_BASE + KERNEL_CONTROL_SPAN;

/// Offset of the primary stage-1 table alias within the kernel control region.
pub const STAGE1_TABLES_ALIAS_OFFSET: u64 = 0x2_0000;

/// Current-MM primary stage-1 table alias, mapped EL1-only.
pub const STAGE1_TABLES_ALIAS_BASE: u64 = KERNEL_CONTROL_BASE + STAGE1_TABLES_ALIAS_OFFSET;

/// Bytes available through the primary stage-1 table alias (444 pages).
pub const STAGE1_TABLES_PRIMARY_SIZE: u64 = 0x1B_C000;

/// Offset of the per-process identity page within the kernel control region.
pub const IDENTITY_PAGE_OFFSET: u64 = 0x1E_4000;

/// Per-process identity page base VA.
pub const IDENTITY_PAGE_BASE: u64 = KERNEL_CONTROL_BASE + IDENTITY_PAGE_OFFSET;

/// Per-process identity page size (16 KiB = 0x4000).
pub const IDENTITY_PAGE_SIZE: u64 = 0x4000;

const _: () = {
    assert!(VA_BITS == 48);
    assert!(GRANULE_SIZE == 4096);
    assert!(LEVELS == 4);
    assert!(SHIFTS[0] == 39);
    assert!(SHIFTS[1] == 30);
    assert!(SHIFTS[2] == 21);
    assert!(SHIFTS[3] == 12);
    assert!(KERNEL_CONTROL_BASE == 0x2D_0000_0000);
    assert!(KERNEL_CONTROL_SPAN == 0x20_0000);
    assert!(KERNEL_CONTROL_END == 0x2D_0020_0000);
    assert!(STAGE1_TABLES_ALIAS_BASE == 0x2D_0002_0000);
    assert!(STAGE1_TABLES_PRIMARY_SIZE == 0x1B_C000);
    assert!(IDENTITY_PAGE_BASE == 0x2D_001E_4000);
    assert!(IDENTITY_PAGE_SIZE == 0x4000);
    assert!(STAGE1_TABLES_ALIAS_BASE >= KERNEL_CONTROL_BASE);
    assert!(STAGE1_TABLES_ALIAS_BASE + STAGE1_TABLES_PRIMARY_SIZE <= IDENTITY_PAGE_BASE);
    assert!(IDENTITY_PAGE_BASE + IDENTITY_PAGE_SIZE <= KERNEL_CONTROL_END);
};

impl OwnerForkMmu for Aarch64Mmu {
    const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;

    fn omit_unloaned_control_alias() -> bool {
        true
    }

    fn control_window() -> Option<(UserVa, UserVa)> {
        Some((
            UserVa::new(KERNEL_CONTROL_BASE),
            UserVa::new(KERNEL_CONTROL_END),
        ))
    }

    fn is_control_alias(va: UserVa) -> bool {
        (STAGE1_TABLES_ALIAS_BASE..STAGE1_TABLES_ALIAS_BASE + STAGE1_TABLES_PRIMARY_SIZE)
            .contains(&va.raw())
    }

    fn control_alias_destination(
        va: UserVa,
        child_tables: FrameGpa,
    ) -> Result<FrameGpa, OwnerMmuRefusal> {
        if !Self::is_control_alias(va) {
            return Err(OwnerMmuRefusal::Unreachable);
        }
        child_tables
            .raw()
            .checked_add(va.raw() - STAGE1_TABLES_ALIAS_BASE)
            .map(FrameGpa::new)
            .ok_or(OwnerMmuRefusal::Unreachable)
    }

    fn control_copy_destination(
        va: UserVa,
        child_control: FrameGpa,
    ) -> Result<FrameGpa, OwnerMmuRefusal> {
        if !(KERNEL_CONTROL_BASE..KERNEL_CONTROL_END).contains(&va.raw()) {
            return Err(OwnerMmuRefusal::Unreachable);
        }
        child_control
            .raw()
            .checked_add(va.raw() - KERNEL_CONTROL_BASE)
            .map(FrameGpa::new)
            .ok_or(OwnerMmuRefusal::Unreachable)
    }

    fn is_table(word: u64, level: usize) -> bool {
        level < 3 && word & 3 == 3
    }

    fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64 {
        const TABLE_FLAGS: u64 = 0b11111 << 59;
        (output.raw() & Self::ADDRESS_MASK) | 3 | inherited.map_or(0, |word| word & TABLE_FLAGS)
    }

    fn is_user(word: u64) -> bool {
        word & (1 << 6) != 0
    }

    fn is_retired(word: u64) -> bool {
        crate::aarch64::terminal_descriptor_is_retired(word)
    }

    fn is_absent_unowned(word: u64) -> bool {
        word & 1 == 0
            && !Self::is_retired(word)
            && crate::aarch64::el1_private_leaf_state(word)
                == crate::aarch64::El1PrivateLeafState::Unowned
    }

    fn is_owned_resident(word: u64) -> bool {
        crate::aarch64::el1_private_leaf_state(word)
            == crate::aarch64::El1PrivateLeafState::Resident
    }

    fn is_writable_user(word: u64) -> bool {
        crate::aarch64::terminal_descriptor_permits_el0(word, LeafAccess::Write)
    }

    fn is_executable_control(word: u64) -> bool {
        word & (1 << 53) == 0
    }

    fn control_needs_copy(va: UserVa, _word: u64) -> bool {
        (IDENTITY_PAGE_BASE..IDENTITY_PAGE_BASE + IDENTITY_PAGE_SIZE).contains(&va.raw())
    }

    fn split(word: u64, level: usize, index: usize) -> Result<u64, OwnerMmuRefusal> {
        crate::aarch64::split_terminal_descriptor(word, level, index)
            .map_err(|_| OwnerMmuRefusal::Unreachable)
    }

    fn arm_private(word: u64, level: usize, va: UserVa) -> Result<u64, OwnerMmuRefusal> {
        crate::aarch64::terminal_rule_edit(
            true,
            crate::aarch64::TerminalRule::fork_arm(true),
            word,
            level,
            va.raw(),
        )
        .map(|changed| changed.unwrap_or(word))
        .map_err(|_| OwnerMmuRefusal::Unreachable)
    }

    fn needs_break_before_make(before: u64, after: u64, level: usize) -> bool {
        if before & 1 == 0 || !Self::is_table(after, level) {
            return false;
        }
        if !Self::is_table(before, level) {
            // Block to table transition requires BBM
            return true;
        }
        // Replacing a valid table pointer with a different table pointer requires BBM
        // because the old table translation can be cached by concurrent/earlier page walks.
        (before & Self::ADDRESS_MASK) != (after & Self::ADDRESS_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_mmu::{Aarch64Mmu, OwnerForkMmu};

    #[test]
    fn arm_translation_regime_matches_tcr_bootstrap() {
        // Citation: crates/carrick-mem/src/arch_sysregs.rs:43-58
        let tcr = carrick_mem::arch_sysregs::TCR_EL1_BOOTSTRAP;
        let t0sz = tcr & 0x3f;
        assert_eq!(t0sz, 16, "TCR_EL1.T0SZ must be 16 for 48-bit VA");
        assert_eq!(64 - t0sz, VA_BITS as u64);

        let tg0 = (tcr >> 14) & 0x3;
        assert_eq!(tg0, 0b00, "TCR_EL1.TG0 must be 0b00 for 4 KiB granule");

        let ips = (tcr >> 32) & 0x7;
        assert_eq!(ips, 0b010, "TCR_EL1.IPS must be 0b010 for 40-bit IPA");

        // Citation: crates/carrick-mem/src/arch_sysregs.rs:21
        assert_eq!(carrick_mem::arch_sysregs::MAIR_EL1_BOOTSTRAP, 0xFF);

        // Citation: crates/carrick-mem/src/memory.rs:220-222
        assert_eq!(
            carrick_mem::memory::LINUX_KERNEL_REGION_BASE,
            KERNEL_CONTROL_BASE
        );
        assert_eq!(
            carrick_mem::memory::LINUX_KERNEL_REGION_SIZE,
            KERNEL_CONTROL_SPAN
        );

        // Citation: crates/carrick-mem/src/memory.rs:251
        assert_eq!(
            carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
            STAGE1_TABLES_ALIAS_BASE
        );

        // Citation: crates/carrick-mem/src/memory.rs:300
        assert_eq!(
            carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE,
            IDENTITY_PAGE_BASE
        );
    }

    #[test]
    fn arm_descriptor_classification_per_level() {
        let table_desc = 0x1000 | 0b11;
        assert!(Aarch64Mmu::is_table(table_desc, 0));
        assert!(Aarch64Mmu::is_table(table_desc, 1));
        assert!(Aarch64Mmu::is_table(table_desc, 2));
        assert!(
            !Aarch64Mmu::is_table(table_desc, 3),
            "L3 descriptor is page, never table"
        );

        let block_desc = 0x20_0000 | 0b01;
        assert!(!Aarch64Mmu::is_table(block_desc, 1));
        assert!(!Aarch64Mmu::is_table(block_desc, 2));

        assert!(!Aarch64Mmu::is_table(0, 0));
        assert!(!Aarch64Mmu::is_table(0x1000, 1));
    }

    #[test]
    fn arm_retired_and_absent_classification() {
        let tagged_retired = (1 << 56) | (1 << 55) | 0x1000;
        assert!(Aarch64Mmu::is_retired(tagged_retired));
        assert!(!Aarch64Mmu::is_absent_unowned(tagged_retired));

        // Untagged retired lease (SW_RETIRED set, VALID clear, SW_EL1_PRIVATE clear)
        let untagged_retired = (1 << 55) | 0x1000;
        assert!(
            Aarch64Mmu::is_retired(untagged_retired),
            "untagged retired lease must be recognized as retired"
        );
        assert!(!Aarch64Mmu::is_absent_unowned(untagged_retired));

        assert!(!Aarch64Mmu::is_retired(0));
        assert!(Aarch64Mmu::is_absent_unowned(0));

        let prepared_private = (1 << 56) | 0x1000;
        assert!(!Aarch64Mmu::is_retired(prepared_private));
        assert!(!Aarch64Mmu::is_absent_unowned(prepared_private));
    }

    #[test]
    fn arm_needs_break_before_make() {
        let block_desc = 0x20_0000 | 0b01;
        let table_desc = 0x1000 | 0b11;

        // Transition from valid block to table descriptor requires BBM
        assert!(Aarch64Mmu::needs_break_before_make(
            block_desc, table_desc, 1
        ));
        assert!(Aarch64Mmu::needs_break_before_make(
            block_desc, table_desc, 2
        ));

        // Table to different table address requires BBM
        let table_desc2 = 0x2000 | 0b11;
        assert!(
            Aarch64Mmu::needs_break_before_make(table_desc, table_desc2, 1),
            "table-to-different-table transition requires break-before-make"
        );

        // Table to same table address (e.g. upper attribute change) does NOT require BBM
        let table_desc_same_addr = 0x1000 | 0b11 | (1 << 59);
        assert!(
            !Aarch64Mmu::needs_break_before_make(table_desc, table_desc_same_addr, 1),
            "table-to-same-table transition does not require break-before-make"
        );

        // Modifying leaf permissions (e.g. block armed for COW) does not require BBM
        let armed_block = block_desc | (1 << 55) | (1 << 11);
        assert!(!Aarch64Mmu::needs_break_before_make(
            block_desc,
            armed_block,
            2
        ));

        // Invalid to table does not require BBM
        assert!(!Aarch64Mmu::needs_break_before_make(0, table_desc, 1));

        // Level 3 is never table
        assert!(!Aarch64Mmu::needs_break_before_make(
            0x1000 | 0b11,
            0x2000 | 0b11,
            3
        ));
    }

    #[test]
    fn arm_control_destinations() {
        assert_eq!(
            Aarch64Mmu::control_window(),
            Some((
                UserVa::new(KERNEL_CONTROL_BASE),
                UserVa::new(KERNEL_CONTROL_END)
            ))
        );
        assert!(Aarch64Mmu::is_control_alias(UserVa::new(
            STAGE1_TABLES_ALIAS_BASE
        )));
        assert!(Aarch64Mmu::is_control_alias(UserVa::new(
            STAGE1_TABLES_ALIAS_BASE + 0x1000
        )));
        assert!(!Aarch64Mmu::is_control_alias(UserVa::new(
            STAGE1_TABLES_ALIAS_BASE - 1
        )));
        assert!(!Aarch64Mmu::is_control_alias(UserVa::new(
            STAGE1_TABLES_ALIAS_BASE + STAGE1_TABLES_PRIMARY_SIZE
        )));

        let child_tables = FrameGpa::new(0x80_0000);
        assert_eq!(
            Aarch64Mmu::control_alias_destination(
                UserVa::new(STAGE1_TABLES_ALIAS_BASE + 0x1000),
                child_tables
            ),
            Ok(FrameGpa::new(0x80_1000))
        );

        let child_control = FrameGpa::new(0x90_0000);
        assert_eq!(
            Aarch64Mmu::control_copy_destination(UserVa::new(IDENTITY_PAGE_BASE), child_control),
            Ok(FrameGpa::new(0x90_0000 + IDENTITY_PAGE_OFFSET))
        );
        assert!(Aarch64Mmu::control_needs_copy(
            UserVa::new(IDENTITY_PAGE_BASE),
            0
        ));
        assert!(Aarch64Mmu::control_needs_copy(
            UserVa::new(IDENTITY_PAGE_BASE + IDENTITY_PAGE_SIZE - 1),
            0
        ));
        assert!(!Aarch64Mmu::control_needs_copy(
            UserVa::new(IDENTITY_PAGE_BASE + IDENTITY_PAGE_SIZE),
            0
        ));
    }
}
