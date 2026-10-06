//! Four-level x86 hardware projection for the shared production MM owner.
use super::descriptor_txn::*;
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{OwnerForkMmu, OwnerMmu, OwnerMmuRefusal, OwnerTranslation};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct X86Mmu;
impl OwnerForkMmu for X86Mmu {
    const ADDRESS_MASK: u64 = ADDRESS;
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
    fn is_retired(_: u64) -> bool {
        false
    }
    fn is_absent_unowned(word: u64) -> bool {
        word & (PRESENT | PREPARED) == 0
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
            DescriptorApplied, DescriptorOp as WireOp, DescriptorOutcome as WireOutcome,
            ReclaimedTables,
        };
        let WireOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return WireOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        let Ok(root) = Self::root(register) else {
            return WireOutcome::Refused(DescriptorRefusal::StaleRoot);
        };
        if root.address().raw() != txn.root.raw() {
            return WireOutcome::Refused(DescriptorRefusal::StaleRoot);
        }
        let slice = txn.tables.as_slice();
        if slice.len() > crate::aarch64::descriptor_txn::MAX_TABLE_GRANTS {
            return WireOutcome::Refused(DescriptorRefusal::BadTableGrant);
        }
        let dummy = match RootGpa::page_aligned(FrameGpa::new(0)) {
            Some(r) => r,
            None => return WireOutcome::Refused(DescriptorRefusal::BadTableGrant),
        };
        let mut tables = [dummy; crate::aarch64::descriptor_txn::MAX_TABLE_GRANTS];
        for (i, &pa) in slice.iter().enumerate() {
            let Some(root) = RootGpa::page_aligned(FrameGpa::new(pa)) else {
                return WireOutcome::Refused(DescriptorRefusal::BadTableGrant);
            };
            tables[i] = root;
        }
        let native = DescriptorTxn {
            id: txn.id,
            root,
            op: DescriptorOp::Prepare {
                span: PageSpan::new(publication.va, publication.len),
                output: FrameGpa::new(publication.ipa),
                permissions: Permissions {
                    writable: publication.writable,
                    executable: publication.executable,
                    user: true,
                },
                resident,
                backing,
            },
            tables: &tables[..slice.len()],
        };
        // Retain the bounded plan through publication and rollback. Its
        // applied prefix is the journal; duplicating every entry here would
        // overflow the CPL0 stack at the admitted 2 MiB grant ceiling.
        let receipt = execute_retained_descriptor_txn(words, &native, root);
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
                    pages: publication.len / PAGE,
                    resident,
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
