//! Four-level x86 hardware projection for the shared production MM owner.
use super::descriptor_txn::*;
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{OwnerForkMmu, OwnerMmu, OwnerMmuRefusal, OwnerTranslation};
use carrick_guest_arch::{
    EditBacking, EditIntent, EditOperation, EditOwner, EditPermissions, FrameGpa, GuestLen,
    RootGpa, UserRange, UserVa,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86Mmu;
impl OwnerForkMmu for X86Mmu {
    const ADDRESS_MASK: u64 = ADDRESS;
    fn shared_root_start() -> usize {
        256
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
    fn is_private_control(_: UserVa) -> bool {
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
                        _ => unreachable!(),
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
