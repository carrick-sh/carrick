//! AArch64 descriptor and private control-window geometry for shared fork.
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{Aarch64Mmu, OwnerForkMmu, OwnerMmuRefusal};
use carrick_guest_arch::{FrameGpa, UserVa};

/// Current-MM primary stage-1 table alias, mapped EL1-only.
pub const STAGE1_TABLES_ALIAS_BASE: u64 = 0x2D_0002_0000;
/// Bytes available through the primary stage-1 table alias.
pub const STAGE1_TABLES_PRIMARY_SIZE: u64 = 0x1C_0000;
/// Per-MM identity/control mapping inside the structural bootstrap window.
pub const IDENTITY_PAGE_BASE: u64 = 0x2D_001E_4000;
pub const IDENTITY_PAGE_SIZE: u64 = 0x4000;
const CONTROL_BASE: u64 = STAGE1_TABLES_ALIAS_BASE - 0x2_0000;
const CONTROL_END: u64 = CONTROL_BASE + 0x20_0000;

impl OwnerForkMmu for Aarch64Mmu {
    const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
    fn control_window() -> Option<(UserVa, UserVa)> {
        Some((UserVa::new(CONTROL_BASE), UserVa::new(CONTROL_END)))
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
        if !(CONTROL_BASE..CONTROL_END).contains(&va.raw()) {
            return Err(OwnerMmuRefusal::Unreachable);
        }
        child_control
            .raw()
            .checked_add(va.raw() - CONTROL_BASE)
            .map(FrameGpa::new)
            .ok_or(OwnerMmuRefusal::Unreachable)
    }
    fn is_table(word: u64, level: usize) -> bool {
        level < 3 && word & 3 == 3
    }
    fn table_word(output: FrameGpa, _: Option<u64>) -> u64 {
        output.raw() | 3
    }
    fn is_user(word: u64) -> bool {
        word & (1 << 6) != 0
    }
    fn is_retired(word: u64) -> bool {
        crate::aarch64::el1_private_leaf_state(word) == crate::aarch64::El1PrivateLeafState::Retired
    }
    fn is_absent_unowned(word: u64) -> bool {
        word & 1 == 0
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
    fn is_private_control(va: UserVa) -> bool {
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
        before & 1 != 0 && Self::is_table(after, level)
    }
}
