//! Four-level x86 hardware projection for the shared production MM owner.
use super::descriptor_txn::*;
use crate::aarch64::LeafAccess;
use crate::owner_mmu::{OwnerForkMmu, OwnerMmu, OwnerMmuRefusal, OwnerTranslation};
use carrick_guest_arch::{FrameGpa, RootGpa, UserVa};

pub struct X86Mmu;
impl OwnerForkMmu for X86Mmu {
    const ADDRESS_MASK: u64 = ADDRESS;
    const PRIVATE_CONTROL_WINDOW: bool = false;
    fn is_table(word: u64, level: usize) -> bool {
        level < 3 && word & PRESENT != 0 && word & HUGE == 0
    }
    fn table_word(output: FrameGpa, inherited: Option<u64>) -> u64 {
        output.raw() | inherited.map_or(PRESENT | WRITE | USER, |word| word & !ADDRESS)
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
    fn control_needs_copy(_: u64) -> bool {
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
