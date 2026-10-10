//! Four-level x86 hardware projection for the shared production MM owner.
use super::descriptor_txn::*;
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{OwnerForkMmu, OwnerMmu, OwnerMmuRefusal, OwnerTranslation};
use carrick_guest_arch::{
    EditBacking, EditIntent, EditOperation, EditOwner, EditPermissions, FrameGpa, GuestLen,
    RootGpa, UserRange, UserVa,
};

/// MM-private supervisor branch for the two-page COW copy window.
pub const COW_COPY_ROOT_INDEX: usize = 508;

/// Whether a carrier maintenance PML4 may stand in for `live`: it must hold
/// exactly `live`'s shared supervisor entries and nothing else. A maintenance
/// root is a copy taken when fork stock is installed; this is the check that
/// a later change to a shared upper entry cannot go unnoticed.
pub fn maintenance_root_matches(live: &[u64; 512], maintenance: &[u64; 512]) -> bool {
    (0..512).all(|index| {
        if X86Mmu::is_shared_root_entry(index) {
            live[index] == maintenance[index]
        } else {
            maintenance[index] == 0
        }
    })
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct X86Mmu;
impl OwnerForkMmu for X86Mmu {
    const ADDRESS_MASK: u64 = ADDRESS;
    fn is_shared_root_entry(index: usize) -> bool {
        index >= 256 && index != COW_COPY_ROOT_INDEX
    }
    fn control_window() -> Option<(UserVa, UserVa)> {
        None
    }
    fn is_control_alias(_: UserVa) -> bool {
        false
    }
    fn control_alias_destination(_: UserVa, _: FrameGpa) -> Result<FrameGpa, OwnerMmuRefusal> {
        Err(OwnerMmuRefusal::Unreachable)
    }
    fn control_copy_destination(_: UserVa, _: FrameGpa) -> Result<FrameGpa, OwnerMmuRefusal> {
        Err(OwnerMmuRefusal::Unreachable)
    }
    fn is_table(word: u64, level: usize) -> bool {
        level < 3 && word & PRESENT != 0 && word & HUGE == 0
    }
    fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64 {
        const TABLE_FLAGS: u64 = PRESENT | WRITE | USER | NX;
        output.raw() | inherited.map_or(PRESENT, |word| (word & TABLE_FLAGS) | PRESENT)
    }
    fn is_user(word: u64) -> bool {
        word & USER != 0
    }
    fn is_retired(word: u64) -> bool {
        word & RETIRED != 0 && word & (PRESENT | PREPARED) == 0
    }
    fn is_absent_unowned(word: u64) -> bool {
        word & (PRESENT | PREPARED | RETIRED) == 0
    }
    fn is_owned_resident(word: u64) -> bool {
        word & (PRESENT | PREPARED | MAY_WRITE) == PRESENT | MAY_WRITE
    }
    fn is_writable_user(word: u64) -> bool {
        word & (PRESENT | WRITE | USER) == PRESENT | WRITE | USER
    }
    fn is_executable_control(word: u64) -> bool {
        word & NX == 0
    }
    fn control_needs_copy(_: UserVa, _: u64) -> bool {
        false
    }
    fn split(word: u64, level: usize, index: usize) -> Result<u64, OwnerMmuRefusal> {
        split_terminal_descriptor(word, level, index).map_err(|_| OwnerMmuRefusal::Unreachable)
    }
    fn arm_private(word: u64, _: usize, _: UserVa) -> Result<u64, OwnerMmuRefusal> {
        arm_cow_terminal(word).map_err(|_| OwnerMmuRefusal::Unreachable)
    }
    fn needs_break_before_make(_: u64, _: u64, _: usize) -> bool {
        false
    }
}
impl OwnerMmu for X86Mmu {
    fn root(register: u64) -> Result<RootGpa, OwnerMmuRefusal> {
        // Initial carrier mode has no PCID, global pages or LA57. Refuse,
        // rather than silently masking a different address-context mode.
        if register == 0 || register & !ADDRESS != 0 {
            return Err(OwnerMmuRefusal::Unreachable);
        }
        RootGpa::page_aligned(FrameGpa::new(register)).ok_or(OwnerMmuRefusal::Unreachable)
    }
    fn translate<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        access: LeafAccess,
        user: bool,
    ) -> Result<Option<OwnerTranslation>, OwnerMmuRefusal> {
        let access = match access {
            LeafAccess::Read => Access::Read,
            LeafAccess::Write => Access::Write,
            LeafAccess::Execute => Access::Execute,
        };
        match translate_leaf(words, root, va, access, user) {
            Ok(leaf) => Ok(Some(OwnerTranslation {
                output: leaf.output,
                executable: leaf.executable,
            })),
            Err(FaultClass::NotPresent) => Ok(None),
            Err(FaultClass::Reserved) => Err(OwnerMmuRefusal::Unreachable),
            Err(_) => Err(OwnerMmuRefusal::Protection),
        }
    }
    fn classify_cow<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: RootGpa,
        va: UserVa,
        executable_publication: bool,
    ) -> Result<(), OwnerMmuRefusal> {
        let leaf = translate_leaf(words, root, va, Access::Read, true).map_err(|e| match e {
            FaultClass::Reserved => OwnerMmuRefusal::Unreachable,
            _ => OwnerMmuRefusal::Protection,
        })?;
        if !leaf.ancestors_writable {
            return Err(OwnerMmuRefusal::Protection);
        }
        if leaf.descriptor & WRITE != 0 {
            return Ok(());
        }
        if leaf.size != PAGE || leaf.descriptor & (COW | MAY_WRITE) != COW | MAY_WRITE {
            return Err(OwnerMmuRefusal::Protection);
        }
        if leaf.executable && !executable_publication {
            return Err(OwnerMmuRefusal::ExecutableCow);
        }
        Ok(())
    }
}

impl crate::owner_mmu::OwnerGrantMmu for X86Mmu {
    fn execute_grant<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        register: u64,
        txn: &crate::aarch64::descriptor_txn::DescriptorTxn,
    ) -> crate::aarch64::descriptor_txn::DescriptorOutcome {
        use crate::aarch64::descriptor_txn::{
            DescriptorApplied, DescriptorOutcome as WireOutcome, ReclaimedTables,
        };
        let result = Self::project_grant(register, txn, |native| {
            execute_descriptor_txn(words, native, native.root, &mut InlineJournal::new())
        });
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(reason) => return WireOutcome::Refused(reason),
        };
        match receipt.outcome {
            DescriptorOutcome::Applied {
                stores,
                tables_linked,
            } => {
                let (Ok(live_stores), Ok(tables_linked)) =
                    (u32::try_from(stores), u8::try_from(tables_linked))
                else {
                    return WireOutcome::Indeterminate(DescriptorRefusal::BadEncoding);
                };
                WireOutcome::Applied(DescriptorApplied {
                    pages: txn.op.span().len / PAGE,
                    resident: match txn.op {
                        crate::aarch64::descriptor_txn::DescriptorOp::Prepare {
                            resident, ..
                        } => resident,
                        _ => return WireOutcome::Refused(DescriptorRefusal::BadEncoding),
                    },
                    tables_linked,
                    reclaimed: ReclaimedTables::NONE,
                    live_stores,
                    flush_required: stores != 0,
                })
            }
            DescriptorOutcome::Refused(reason) => WireOutcome::Refused(reason),
            DescriptorOutcome::RolledBack(reason) => WireOutcome::RolledBack(reason),
            DescriptorOutcome::Indeterminate(reason) => WireOutcome::Indeterminate(reason),
        }
    }
}

impl X86Mmu {
    /// One projection for guest execution and host receipt authentication.
    /// This does not select Linux mappings or grant descriptor-write authority.
    pub fn project_grant<T>(
        register: u64,
        txn: &crate::aarch64::descriptor_txn::DescriptorTxn,
        consume: impl FnOnce(&DescriptorTxn<'_>) -> T,
    ) -> Result<T, DescriptorRefusal> {
        use crate::aarch64::descriptor_txn::DescriptorOp as WireOp;
        let WireOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return Err(DescriptorRefusal::BadEncoding);
        };
        let root = Self::root(register).map_err(|_| DescriptorRefusal::StaleRoot)?;
        if root.address().raw() != txn.root.raw() {
            return Err(DescriptorRefusal::StaleRoot);
        }
        let tables: alloc::vec::Vec<_> = txn
            .tables
            .as_slice()
            .iter()
            .map(|&pa| RootGpa::page_aligned(FrameGpa::new(pa)))
            .collect();
        let Some(tables) = tables.into_iter().collect::<Option<alloc::vec::Vec<_>>>() else {
            return Err(DescriptorRefusal::BadTableGrant);
        };
        let Some(range) =
            UserRange::checked(UserVa::new(publication.va), GuestLen::new(publication.len))
        else {
            return Err(DescriptorRefusal::BadRange);
        };
        let Some(resident_range) =
            UserRange::checked(UserVa::new(resident.va), GuestLen::new(resident.len))
        else {
            return Err(DescriptorRefusal::BadRange);
        };
        // SAFETY: apply_grant retains this exact-MM editor, and the authenticated
        // grant root and operation generation were checked before this call.
        let owner = unsafe { EditOwner::issue(root, txn.id.mm_key, txn.id.generation) };
        let Some(intent) = EditIntent::checked(
            owner,
            range,
            EditOperation::Prepare {
                output: FrameGpa::new(publication.ipa),
                permissions: EditPermissions {
                    readable: true,
                    writable: publication.writable,
                    executable: publication.executable,
                    user: true,
                },
                resident: resident_range,
                backing: EditBacking {
                    frame_id: backing.frame_id,
                    mapping_id: backing.mapping_id,
                    owner_generation: backing.owner_generation,
                    inventory_revision: backing.inventory_revision,
                },
            },
            &tables,
        ) else {
            return Err(DescriptorRefusal::BadRange);
        };
        let native = DescriptorTxn::from_intent(&intent)?;
        Ok(consume(&native))
    }
}

#[cfg(test)]
mod maintenance_root_tests {
    use super::*;

    fn roots() -> ([u64; 512], [u64; 512]) {
        let mut live = [0u64; 512];
        live[3] = 0x5_0007; // private user branch
        live[COW_COPY_ROOT_INDEX] = 0x6_0003; // MM-private copy window
        let mut maintenance = [0u64; 512];
        for index in 256..512 {
            if X86Mmu::is_shared_root_entry(index) {
                live[index] = 0x10_0003 + (index as u64) * 0x1000;
                maintenance[index] = live[index];
            }
        }
        (live, maintenance)
    }

    #[test]
    fn maintenance_root_matches_only_the_live_shared_entries() {
        let (live, maintenance) = roots();
        assert!(maintenance_root_matches(&live, &maintenance));
    }

    #[test]
    fn a_shared_upper_entry_changed_after_install_is_caught() {
        let (mut live, maintenance) = roots();
        live[511] ^= 0x1000;
        assert!(!maintenance_root_matches(&live, &maintenance));
    }

    #[test]
    fn maintenance_root_may_not_carry_private_or_user_entries() {
        let (live, mut maintenance) = roots();
        maintenance[COW_COPY_ROOT_INDEX] = live[COW_COPY_ROOT_INDEX];
        assert!(!maintenance_root_matches(&live, &maintenance));
        let (live, mut maintenance) = roots();
        maintenance[3] = live[3];
        assert!(!maintenance_root_matches(&live, &maintenance));
    }
}
