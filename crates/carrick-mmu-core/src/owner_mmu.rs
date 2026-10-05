//! Hardware hooks for the one reservation/transfer owner. A translation is
//! physical evidence only; MmPortal authenticates Linux permission and lifetime.
use crate::aarch64::LeafAccess;
use crate::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerTranslation {
    pub output: FrameGpa,
    pub executable: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerMmuRefusal {
    Protection,
    Unreachable,
    ExecutableCow,
}

/// ISA hooks contain no reservation, permit, frame inventory or fault policy.
/// The caller holds the exact owner editor and supplies its admitted root.
pub trait OwnerMmu {
    fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal>;
    fn translate<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        access: LeafAccess,
        user: bool,
    ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal>;
    fn classify_cow<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        executable_publication: bool,
    ) -> Result<(), OwnerMmuRefusal>;
}

/// Descriptor geometry used by the owner's existing Fork transaction. VMA
/// inheritance, custody selection, admission and rollback stay in that owner.
pub trait OwnerForkMmu: OwnerMmu {
    const ADDRESS_MASK: u64;
    const PRIVATE_CONTROL_WINDOW: bool;
    fn is_table(word: u64, level: usize) -> bool;
    fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64;
    fn is_user(word: u64) -> bool;
    fn is_retired(word: u64) -> bool;
    fn is_absent_unowned(word: u64) -> bool;
    fn is_owned_resident(word: u64) -> bool;
    fn is_writable_user(word: u64) -> bool;
    fn is_executable_control(word: u64) -> bool;
    fn control_needs_copy(word: u64) -> bool;
    fn split(word: u64, level: usize, index: usize) -> Result<u64, OwnerMmuRefusal>;
    fn arm_private(word: u64, level: usize, va: UserVa) -> Result<u64, OwnerMmuRefusal>;
    fn needs_break_before_make(before: u64, after: u64, level: usize) -> bool;
}

pub struct Aarch64Mmu;
impl OwnerForkMmu for Aarch64Mmu {
    const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
    const PRIVATE_CONTROL_WINDOW: bool = true;
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
    fn control_needs_copy(word: u64) -> bool {
        word & (1 << 7) == 0
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
impl OwnerMmu for Aarch64Mmu {
    fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal> {
        RootGpa::page_aligned(FrameGpa::new(register & 0x0000_ffff_ffff_f000))
            .filter(|root| root.address().raw() != 0)
            .ok_or(OwnerMmuRefusal::Unreachable)
    }
    fn translate<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        access: LeafAccess,
        user: bool,
    ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal> {
        use crate::aarch64::terminal_descriptor_permits_el0;
        const PA: u64 = 0x0000_ffff_ffff_f000;
        let mut table = root.address().raw();
        for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
            let descriptor = words
                .load(table + ((va.raw() >> shift) & 511) * 8)
                .map_err(|_| OwnerMmuRefusal::Unreachable)?;
            if descriptor & 1 == 0 {
                return Ok(None);
            }
            if level == 3 || descriptor & 3 == 1 {
                if level == 0 {
                    return Err(OwnerMmuRefusal::Unreachable);
                }
                if user && !terminal_descriptor_permits_el0(descriptor, access) {
                    return Err(OwnerMmuRefusal::Protection);
                }
                let mask = (1u64 << shift) - 1;
                return Ok(Some(OwnerTranslation {
                    output: FrameGpa::new((descriptor & PA & !mask) + (va.raw() & mask)),
                    executable: terminal_descriptor_permits_el0(descriptor, LeafAccess::Execute),
                }));
            }
            table = descriptor & PA;
        }
        Err(OwnerMmuRefusal::Unreachable)
    }
    fn classify_cow<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        executable_publication: bool,
    ) -> Result<(), OwnerMmuRefusal> {
        use crate::aarch64::descriptor_txn::guest_cow::{
            GuestCowClass, GuestCowNotArmed, classify_guest_cow_write,
        };
        match classify_guest_cow_write(
            words,
            crate::aarch64::SubstrateGpa(root.address().raw()),
            va.raw(),
            executable_publication,
        ) {
            Ok(_) | Err(GuestCowClass::AlreadyWritable) => Ok(()),
            Err(GuestCowClass::NotArmed(GuestCowNotArmed::Executable)) => {
                Err(OwnerMmuRefusal::ExecutableCow)
            }
            Err(GuestCowClass::NotArmed(_)) => Err(OwnerMmuRefusal::Protection),
            Err(GuestCowClass::Unreachable(_)) => Err(OwnerMmuRefusal::Unreachable),
        }
    }
}
