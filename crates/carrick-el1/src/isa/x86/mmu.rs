//! CPL0 CR3 root and local TLB maintenance.

use super::{ArchError, X86Backend, user_access};
use carrick_guest_arch::{
    Access, AddressContext, CopyProgress, EditIntent, FrameGpa, GuestLen, KernelVa, MmuBackend,
    MmuEditBackend, RootGpa, TableWindow, UserRange, UserVa,
};
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
use carrick_mmu_core::x86::descriptor_txn::{
    DescriptorOutcome, DescriptorReceipt, DescriptorTxn, DescriptorTxnId, InlineJournal,
    execute_descriptor_txn,
};
use core::cell::Cell;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering, fence};

const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const KERNEL_CANONICAL_BASE: u64 = 0xffff_8000_0000_0000;
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

/// Borrow the one upper supervisor direct window for the live portal root.
/// The portal owner authenticates the MM grant before calling this leaf.
pub(crate) fn portal_descriptor_words(target: u64) -> Result<NativeDescriptorWords, ArchError> {
    let root = RootGpa::page_aligned(FrameGpa::new(target)).ok_or(ArchError::Unbound)?;
    if root.address().raw() != target {
        return Err(ArchError::Unbound);
    }
    let mapped = carrick_el1_abi::X86_CPL0_DIRECT_VA
        .checked_add(target)
        .ok_or(ArchError::Unbound)?;
    // SAFETY: CPL0 boot retains this single writable supervisor direct window
    // for the full table arena; the portal owner holds the exact-MM editor.
    let tables = unsafe {
        TableWindow::issue(
            root.address(),
            KernelVa::new(mapped),
            GuestLen::new(carrick_el1_abi::X86_CPL0_TABLE_ARENA_BYTES),
        )
    }
    .ok_or(ArchError::Unbound)?;
    NativeDescriptorWords::checked(
        root,
        DescriptorTxnId {
            mm_key: NonZeroU64::MIN,
            generation: NonZeroU64::MIN,
        },
        &tables,
    )
}

/// Authenticate a portal grant's exact root against the live CPL0 CR3 and
/// the sole supervisor table window, without conferring edit authority.
pub fn portal_root_is_live(target: u64) -> bool {
    portal_descriptor_words(target).is_ok()
}

/// Drain all non-global translations after a portal grant under the live root.
pub(crate) fn portal_invalidate_root(target: u64) -> Result<(), ArchError> {
    if live_root()?.address().raw() != target {
        return Err(ArchError::Unbound);
    }
    // SAFETY: this is the active CPL0 root; live_root rejected PCID and PGE,
    // so reloading CR3 drains every local non-global translation.
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) target, options(nostack, preserves_flags)) }
    Ok(())
}

/// Legacy ARM descriptor callers need a separate x86 table owner before they
/// can interpret any descriptor; returning a CR3 here would be unsound.
#[cold]
#[inline(never)]
pub fn unsupported_arm_descriptor_path() -> u64 {
    // SAFETY: no ARM descriptor mutation may proceed against an x86 PML4.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

/// Exact physical page-table window reached through a retained supervisor
/// alias for a CPL0 transaction. Construction requires the caller's MM editor.
pub(crate) struct NativeDescriptorWords {
    context: AddressContext<RootGpa>,
    base: u64,
    end: u64,
    mapped: u64,
    failed_drain: Cell<bool>,
}

impl NativeDescriptorWords {
    pub(crate) fn checked(
        root: RootGpa,
        id: DescriptorTxnId,
        tables: &TableWindow,
    ) -> Result<Self, ArchError> {
        let base = tables.physical().raw();
        let bytes = tables.bytes().raw();
        if live_root()? != root
            || base != root.address().raw()
            || bytes < 4096
            || bytes & 4095 != 0
            || tables.mapped().raw() < KERNEL_CANONICAL_BASE
        {
            return Err(ArchError::Unbound);
        }
        let end = base.checked_add(bytes).ok_or(ArchError::Unbound)?;
        Ok(Self {
            context: AddressContext {
                root,
                mm: carrick_guest_arch::MmGeneration::new(id.mm_key),
                generation: carrick_guest_arch::ContextGeneration::new(id.generation),
            },
            base,
            end,
            mapped: tables.mapped().raw(),
            failed_drain: Cell::new(false),
        })
    }

    fn word(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        if pa & 7 != 0 || pa < self.base || pa.checked_add(8).is_none_or(|end| end > self.end) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let offset = pa - self.base;
        let address = self
            .mapped
            .checked_add(offset)
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        // SAFETY: the caller of execute_native_descriptor_txn retains this
        // writable supervisor alias of the aligned arena throughout the edit.
        Ok(unsafe { &*(address as *const AtomicU64) })
    }
}

impl LiveDescriptorWords for NativeDescriptorWords {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        Ok(self.word(pa)?.load(Ordering::Acquire))
    }

    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        if self
            .word(pa)?
            .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(DescriptorRefusal::Contended);
        }
        Ok(())
    }

    fn publish_barrier(&self) {
        fence(Ordering::SeqCst);
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        let Some(range) = UserRange::checked(UserVa::new(va), GuestLen::new(len)) else {
            self.failed_drain.set(true);
            return;
        };
        let mut backend = X86Backend;
        let drained = backend
            .request_invalidation(self.context, range)
            .and_then(|ticket| backend.ack_drain(ticket));
        if drained.is_err() {
            self.failed_drain.set(true);
        }
    }
}

/// Execute a journaled native x86 descriptor operation under the exact MM
/// editor. A caller must treat `Err` as indeterminate and stop guest execution.
///
/// # Safety
/// `tables` must be a retained, writable supervisor alias of the page-table
/// arena for `txn.root`. The caller holds exclusive MM edit
/// authority across this call and excludes concurrent hardware A/D writers.
pub unsafe fn execute_native_descriptor_txn(
    txn: &DescriptorTxn<'_>,
    tables: &TableWindow,
) -> Result<DescriptorReceipt, ArchError> {
    let words = NativeDescriptorWords::checked(txn.root, txn.id, tables)?;
    let guard = crate::substrate::sched::hw::disable_irq_save();
    let receipt = execute_descriptor_txn(&words, txn, txn.root, &mut InlineJournal::new());
    crate::substrate::sched::hw::restore_irq(guard);
    if words.failed_drain.get() || matches!(receipt.outcome, DescriptorOutcome::Indeterminate(_)) {
        return Err(ArchError::Busy);
    }
    Ok(receipt)
}

/// Confirm that a published user leaf already names the expected frame and
/// permits the faulting access, after a competing editor committed it.
///
/// # Safety
/// The caller retains the exact-MM editor and the supervisor table alias
/// while this read-only walk executes. The root is authenticated live.
pub unsafe fn resident_leaf_matches(
    root: RootGpa,
    tables: &TableWindow,
    address: UserVa,
    expected: FrameGpa,
    access: Access,
) -> Result<bool, ArchError> {
    let id = DescriptorTxnId {
        mm_key: core::num::NonZeroU64::MIN,
        generation: core::num::NonZeroU64::MIN,
    };
    let words = NativeDescriptorWords::checked(root, id, tables)?;
    let native_access = match access {
        Access::Read => carrick_mmu_core::x86::descriptor_txn::Access::Read,
        Access::Write => carrick_mmu_core::x86::descriptor_txn::Access::Write,
        Access::Execute => carrick_mmu_core::x86::descriptor_txn::Access::Execute,
    };
    Ok(carrick_mmu_core::x86::descriptor_txn::translate_leaf(
        &words,
        root,
        address,
        native_access,
        true,
    )
    .is_ok_and(|leaf| leaf.size == 4096 && leaf.output == expected))
}

/// Lower an exact editor's ISA-neutral intent to the four-level x86 engine.
/// No unsupported permission is rounded up to a successful descriptor.
///
/// # Safety
/// The table window must remain mapped and writable through this
/// operation. `intent.owner()` must have been issued by the exact-MM editor,
/// which excludes other software and hardware descriptor writers.
pub unsafe fn execute_native_edit_intent(
    intent: EditIntent<'_, RootGpa>,
    tables: TableWindow,
) -> Result<DescriptorReceipt, ArchError> {
    let transaction = DescriptorTxn::from_intent(&intent).map_err(|_| ArchError::Unbound)?;
    // SAFETY: this function's caller retains the exact editor and page-table
    // alias; lowering above preserves the complete intent.
    unsafe { execute_native_descriptor_txn(&transaction, &tables) }
}

impl MmuEditBackend for X86Backend {
    type EditReceipt = DescriptorReceipt;

    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, RootGpa>,
        tables: TableWindow,
    ) -> Result<Self::EditReceipt, Self::Error> {
        // SAFETY: this trait leaf preserves the caller's exact-MM editor and
        // retained window obligations for the native x86 transaction.
        unsafe { execute_native_edit_intent(intent, tables) }
    }
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
}
