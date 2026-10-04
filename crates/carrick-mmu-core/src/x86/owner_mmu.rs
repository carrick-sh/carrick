//! Four-level x86 hardware projection for the shared production MM owner.
use super::descriptor_txn::*;
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{OwnerMmu, OwnerMmuRefusal, OwnerTranslation};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

pub struct X86Mmu;
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
