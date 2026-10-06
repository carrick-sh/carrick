//! Native owner root and invalidation pending the CPL0 MMU binding.

use super::{ArchError, X86Backend, user_access};
use carrick_guest_arch::{
    Access, AddressContext, CopyProgress, GuestLen, MmuBackend, UserRange, UserVa,
};

fn unbound<T>() -> Result<T, ArchError> {
    carrick_x86_unbound_mmu_owner();
    Err(ArchError::Unbound)
}

impl MmuBackend for X86Backend {
    fn live_root(&mut self) -> Result<Self::Root, Self::Error> {
        unbound()
    }
    fn read_user_word(
        &mut self,
        owner: &Self::MmOwner,
        address: UserVa,
        width: GuestLen,
    ) -> Result<u64, Self::Error> {
        match width.raw() {
            4 => user_access::read_u32(owner, address.raw()).map(u64::from),
            8 => user_access::read_u64(owner, address.raw()),
            _ => return Err(ArchError::InvalidWidth),
        }
        .ok_or(ArchError::Unbound)
    }
    fn validate_user_access(
        &mut self,
        owner: &Self::MmOwner,
        range: UserRange,
        access: Access,
    ) -> Result<GuestLen, Self::Error> {
        user_access::validate(owner, range, access)
    }
    fn install_context(&mut self, _context: AddressContext<Self::Root>) -> Result<(), Self::Error> {
        unbound()
    }
    fn translate_live(
        &mut self,
        _owner: &Self::MmOwner,
        _address: UserVa,
        _access: Access,
    ) -> Result<Self::OwnedTranslation, Self::Error> {
        unbound()
    }
    fn prepare_leaf_edit(
        &mut self,
        _owner: &Self::MmOwner,
        _range: UserRange,
        _translation: Self::OwnedTranslation,
    ) -> Result<Self::LeafEdit, Self::Error> {
        unbound()
    }
    fn apply_leaf_edit(&mut self, _edit: &mut Self::LeafEdit) -> Result<(), Self::Error> {
        unbound()
    }
    fn undo_leaf_edit(&mut self, _edit: Self::LeafEdit) -> Result<(), Self::Error> {
        unbound()
    }
    fn request_invalidation(
        &mut self,
        _context: AddressContext<Self::Root>,
        _range: UserRange,
    ) -> Result<Self::DrainTicket, Self::Error> {
        unbound()
    }
    fn ack_drain(&mut self, _ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error> {
        unbound()
    }
    fn copy_user_chunk(
        &mut self,
        transfer: &mut Self::UserTransfer,
        limit: GuestLen,
    ) -> Result<CopyProgress, Self::Error> {
        transfer.advance(limit)
    }
    fn publish_executable(
        &mut self,
        _owner: &Self::MmOwner,
        _range: UserRange,
    ) -> Result<Self::PublicationReceipt, Self::Error> {
        unbound()
    }
}

/// ARM TTBR/TLBI records cannot describe an x86 CR3/PML4 owner.
#[cold]
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn carrick_x86_unbound_mmu_owner() -> u64 {
    // SAFETY: fail closed before publishing a translation or drain receipt.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}
