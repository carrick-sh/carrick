//! CPL0 CR3 root and local TLB maintenance.

use super::{ArchError, X86Backend, user_access};
use carrick_guest_arch::{
    Access, AddressContext, CopyProgress, FrameGpa, GuestLen, MmuBackend, RootGpa, UserRange,
    UserVa,
};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const CR4_PGE: u64 = 1 << 7;
const CR4_PCIDE: u64 = 1 << 17;
const LOCAL_PAGE_BUDGET: u64 = 32;

/// A pending local drain bound to the root that issued it.
pub struct DrainTicket {
    context: AddressContext<RootGpa>,
    range: UserRange,
}

/// Evidence that this CPU invalidated the active root after the edit.
pub struct DrainReceipt {
    context: AddressContext<RootGpa>,
}

impl DrainReceipt {
    pub const fn root(&self) -> RootGpa {
        self.context.root
    }

    pub const fn context(&self) -> AddressContext<RootGpa> {
        self.context
    }
}

fn live_root() -> Result<RootGpa, ArchError> {
    let (cr3, cr4): (u64, u64);
    // SAFETY: CPL0 may read this CPU's CR3 and CR4. The KVM bootstrap uses
    // non-global, non-PCID roots; those modes need a separate shootdown.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if cr4 & (CR4_PGE | CR4_PCIDE) != 0 || cr3 & ADDRESS_MASK == 0 {
        return Err(ArchError::Unbound);
    }
    RootGpa::page_aligned(FrameGpa::new(cr3 & ADDRESS_MASK)).ok_or(ArchError::Unbound)
}

/// The executing CPL0 page-table root, for x86-only callers migrating from
/// the ARM TTBR path. This does not confer authority to edit that root.
pub fn hardware_live_root() -> Result<RootGpa, ArchError> {
    live_root()
}

/// Legacy ARM descriptor callers need a separate x86 table owner before they
/// can interpret any descriptor; returning a CR3 here would be unsound.
#[cold]
#[inline(never)]
pub fn unsupported_arm_descriptor_path() -> u64 {
    // SAFETY: no ARM descriptor mutation may proceed against an x86 PML4.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

impl MmuBackend for X86Backend {
    fn live_root(&mut self) -> Result<Self::Root, Self::Error> {
        live_root()
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
    fn install_context(&mut self, context: AddressContext<Self::Root>) -> Result<(), Self::Error> {
        let root = context.root.address().raw();
        live_root()?;
        // SAFETY: the caller holds a live AddressContext and retains its
        // supervisor mappings. PCID/PGE were ruled out by live_root, so MOV
        // CR3 flushes local non-global translations.
        unsafe { core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags)) }
        Ok(())
    }
    fn translate_live(
        &mut self,
        _owner: &Self::MmOwner,
        _address: UserVa,
        _access: Access,
    ) -> Result<Self::OwnedTranslation, Self::Error> {
        Err(ArchError::Unbound)
    }
    fn prepare_leaf_edit(
        &mut self,
        _owner: &Self::MmOwner,
        _range: UserRange,
        _translation: Self::OwnedTranslation,
    ) -> Result<Self::LeafEdit, Self::Error> {
        Err(ArchError::Unbound)
    }
    fn apply_leaf_edit(&mut self, _edit: &mut Self::LeafEdit) -> Result<(), Self::Error> {
        Err(ArchError::Unbound)
    }
    fn undo_leaf_edit(&mut self, _edit: Self::LeafEdit) -> Result<(), Self::Error> {
        Err(ArchError::Unbound)
    }
    fn request_invalidation(
        &mut self,
        context: AddressContext<Self::Root>,
        range: UserRange,
    ) -> Result<Self::DrainTicket, Self::Error> {
        if live_root()? != context.root {
            return Err(ArchError::Unbound);
        }
        Ok(DrainTicket { context, range })
    }
    fn ack_drain(&mut self, ticket: Self::DrainTicket) -> Result<Self::DrainReceipt, Self::Error> {
        if live_root()? != ticket.context.root {
            return Err(ArchError::Unbound);
        }
        let start = ticket.range.start().raw();
        let len = ticket.range.len().raw();
        let first = start >> 12;
        let last = start
            .checked_add(len)
            .and_then(|end| end.checked_add(4095))
            .ok_or(ArchError::Unbound)?
            >> 12;
        if last - first > LOCAL_PAGE_BUDGET {
            let root = ticket.context.root.address().raw();
            // SAFETY: PCID/PGE are disabled and this is the still-live root;
            // reloading CR3 flushes all local task translations.
            unsafe {
                core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags))
            }
        } else {
            for page in first..last {
                // SAFETY: INVLPG invalidates this CPU's translation for the
                // supplied canonical user page.
                unsafe {
                    core::arch::asm!("invlpg [{}]", in(reg) page << 12, options(nostack, preserves_flags))
                }
            }
        }
        Ok(DrainReceipt {
            context: ticket.context,
        })
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
        Err(ArchError::Unbound)
    }
}
