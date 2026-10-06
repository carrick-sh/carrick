//! Hardware hooks for the one reservation/transfer owner. A translation is
//! physical evidence only; MmPortal authenticates Linux permission and lifetime.
use crate::aarch64::LeafAccess;
use crate::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerTranslation {
    pub output: FrameGpa,
    pub executable: bool,
    pub kernel_writable_nonexecutable: bool,
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
    /// Half-open ISA-private control window. None means no such mappings.
    fn control_window() -> Option<(UserVa, UserVa)>;
    fn is_control_alias(va: UserVa) -> bool;
    fn control_alias_destination(
        va: UserVa,
        child_tables: FrameGpa,
    ) -> Result<FrameGpa, OwnerMmuRefusal>;
    fn control_copy_destination(
        va: UserVa,
        child_control: FrameGpa,
    ) -> Result<FrameGpa, OwnerMmuRefusal>;
    fn is_table(word: u64, level: usize) -> bool;
    fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64;
    fn is_user(word: u64) -> bool;
    fn is_retired(word: u64) -> bool;
    fn is_absent_unowned(word: u64) -> bool;
    fn is_owned_resident(word: u64) -> bool;
    fn is_writable_user(word: u64) -> bool;
    fn is_executable_control(word: u64) -> bool;
    /// Per-MM control data needs private custody; carrier mappings remain shared.
    fn is_private_control(va: UserVa) -> bool;
    fn split(word: u64, level: usize, index: usize) -> Result<u64, OwnerMmuRefusal>;
    fn arm_private(word: u64, level: usize, va: UserVa) -> Result<u64, OwnerMmuRefusal>;
    fn needs_break_before_make(before: u64, after: u64, level: usize) -> bool;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aarch64Mmu;
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
                    kernel_writable_nonexecutable: descriptor & (3 << 6) == 0
                        && descriptor & (1 << 54) != 0,
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

/// ISA descriptor publication for an already authenticated owner grant.
/// The entire prepared span and its first resident page share one journal.
pub trait OwnerGrantMmu: OwnerForkMmu {
    fn execute_grant<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        register: u64,
        txn: &crate::aarch64::descriptor_txn::DescriptorTxn,
    ) -> crate::aarch64::descriptor_txn::DescriptorOutcome;
}
impl OwnerGrantMmu for Aarch64Mmu {
    fn execute_grant<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        register: u64,
        txn: &crate::aarch64::descriptor_txn::DescriptorTxn,
    ) -> crate::aarch64::descriptor_txn::DescriptorOutcome {
        use crate::aarch64::descriptor_txn::{InlineJournal, execute_descriptor_txn};
        execute_descriptor_txn(
            words,
            crate::aarch64::SubstrateGpa(register & Self::ADDRESS_MASK),
            txn,
            &mut InlineJournal::new(),
        )
        .outcome
    }
}
