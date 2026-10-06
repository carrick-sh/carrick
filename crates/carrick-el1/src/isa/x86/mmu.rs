//! CPL0 CR3 root and local TLB maintenance.

use super::{ArchError, X86Backend, user_access};
use carrick_guest_arch::{
    Access, AddressContext, CopyProgress, EditBacking, EditCowAccess, EditIntent, EditLeafSize,
    EditOperation, EditPermissions, FrameGpa, GuestLen, MmuBackend, MmuEditBackend, RootGpa,
    UserRange, UserVa,
};
use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorRefusal, LiveDescriptorWords};
use carrick_mmu_core::x86::descriptor_txn::{
    DescriptorOp, DescriptorOutcome, DescriptorReceipt, DescriptorTxn, DescriptorTxnId,
    InlineJournal, LeafSize, PageSpan, Permissions, execute_descriptor_txn,
};
use core::cell::Cell;
use core::sync::atomic::{AtomicU64, Ordering, fence};

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

/// Exact physical page-table window retained and identity mapped for a CPL0
/// descriptor transaction. Construction requires the caller's MM editor.
struct NativeDescriptorWords {
    context: AddressContext<RootGpa>,
    base: u64,
    end: u64,
    failed_drain: Cell<bool>,
}

impl NativeDescriptorWords {
    fn word(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        if pa & 7 != 0 || pa < self.base || pa.checked_add(8).is_none_or(|end| end > self.end) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        // SAFETY: the caller of execute_native_descriptor_txn retains this
        // identity mapped and aligned table window through the transaction.
        Ok(unsafe { &*(pa as *const AtomicU64) })
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
/// `table_base..table_base+table_bytes` must be a retained, writable, identity
/// mapped page-table window for `txn.root`. The caller holds exclusive MM edit
/// authority across this call and excludes concurrent hardware A/D writers.
pub unsafe fn execute_native_descriptor_txn(
    txn: &DescriptorTxn<'_>,
    table_base: u64,
    table_bytes: u64,
) -> Result<DescriptorReceipt, ArchError> {
    if live_root()? != txn.root
        || table_base != txn.root.address().raw()
        || table_bytes < 4096
        || table_bytes & 4095 != 0
    {
        return Err(ArchError::Unbound);
    }
    let end = table_base
        .checked_add(table_bytes)
        .ok_or(ArchError::Unbound)?;
    let words = NativeDescriptorWords {
        context: AddressContext {
            root: txn.root,
            mm: carrick_guest_arch::MmGeneration::new(txn.id.mm_key),
            generation: carrick_guest_arch::ContextGeneration::new(txn.id.generation),
        },
        base: table_base,
        end,
        failed_drain: Cell::new(false),
    };
    let guard = crate::substrate::sched::hw::disable_irq_save();
    let receipt = execute_descriptor_txn(&words, txn, txn.root, &mut InlineJournal::new());
    crate::substrate::sched::hw::restore_irq(guard);
    if words.failed_drain.get() || matches!(receipt.outcome, DescriptorOutcome::Indeterminate(_)) {
        return Err(ArchError::Busy);
    }
    Ok(receipt)
}

fn native_permissions(permissions: EditPermissions) -> Result<Permissions, ArchError> {
    // Long mode cannot express a present user mapping that denies reads while
    // allowing a different access. Refuse that semantic intent explicitly.
    if !permissions.readable {
        return Err(ArchError::Unbound);
    }
    Ok(Permissions {
        writable: permissions.writable,
        executable: permissions.executable,
        user: permissions.user,
    })
}

fn native_backing(backing: EditBacking) -> carrick_mmu_core::x86::descriptor_txn::BackingIdentity {
    carrick_mmu_core::x86::descriptor_txn::BackingIdentity {
        frame_id: backing.frame_id,
        mapping_id: backing.mapping_id,
        owner_generation: backing.owner_generation,
        inventory_revision: backing.inventory_revision,
    }
}

fn native_size(size: EditLeafSize) -> LeafSize {
    match size {
        EditLeafSize::Page => LeafSize::Page,
        EditLeafSize::Block2M => LeafSize::Block2M,
        EditLeafSize::Block1G => LeafSize::Block1G,
    }
}

/// Lower an exact editor's ISA-neutral intent to the four-level x86 engine.
/// No unsupported permission is rounded up to a successful descriptor.
///
/// # Safety
/// The table window must remain identity mapped and writable through this
/// operation. `intent.owner()` must have been issued by the exact-MM editor,
/// which excludes other software and hardware descriptor writers.
pub unsafe fn execute_native_edit_intent(
    intent: EditIntent<'_, RootGpa>,
    table_base: u64,
    table_bytes: u64,
) -> Result<DescriptorReceipt, ArchError> {
    let owner = intent.owner();
    let span = PageSpan::new(intent.range().start().raw(), intent.range().len().raw());
    let operation = match intent.operation() {
        EditOperation::Prepare {
            output,
            permissions,
            resident,
            backing,
        } => DescriptorOp::Prepare {
            span,
            output,
            permissions: native_permissions(permissions)?,
            resident: PageSpan::new(resident.start().raw(), resident.len().raw()),
            backing: native_backing(backing),
        },
        EditOperation::Map {
            output,
            permissions,
            size,
            resident,
            backing,
        } => DescriptorOp::Map {
            span,
            output,
            permissions: native_permissions(permissions)?,
            size: native_size(size),
            resident,
            backing: native_backing(backing),
        },
        EditOperation::Publish { expected, access } => DescriptorOp::Publish {
            span,
            expected,
            access: match access {
                Access::Read => carrick_mmu_core::x86::descriptor_txn::Access::Read,
                Access::Write => carrick_mmu_core::x86::descriptor_txn::Access::Write,
                Access::Execute => carrick_mmu_core::x86::descriptor_txn::Access::Execute,
            },
        },
        EditOperation::Protect { permissions } => DescriptorOp::Protect {
            span,
            permissions: native_permissions(permissions)?,
        },
        EditOperation::ArmCow {
            kernel_only: false,
            executable: false,
            adopt_private: false,
            excluded_len,
            ..
        } if excluded_len.raw() == 0 => DescriptorOp::ArmCow(span),
        EditOperation::CowRepoint {
            old,
            new,
            backing,
            access: EditCowAccess::RecordedPrivate,
        } => DescriptorOp::CowRepoint {
            span,
            old,
            new,
            backing: native_backing(backing),
        },
        EditOperation::Unmap => DescriptorOp::Unmap(span),
        EditOperation::Coalesce { size } => DescriptorOp::Coalesce {
            span,
            size: native_size(size),
        },
        _ => return Err(ArchError::Unbound),
    };
    let transaction = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: owner.mm_key(),
            generation: owner.generation(),
        },
        root: owner.root(),
        op: operation,
        tables: intent.table_grants(),
    };
    // SAFETY: this function's caller retains the exact editor and identity
    // mapped table window; lowering above preserves the complete intent.
    unsafe { execute_native_descriptor_txn(&transaction, table_base, table_bytes) }
}

impl MmuEditBackend for X86Backend {
    type EditReceipt = DescriptorReceipt;

    unsafe fn execute_edit(
        &mut self,
        intent: EditIntent<'_, RootGpa>,
        table_base: FrameGpa,
        table_bytes: GuestLen,
    ) -> Result<Self::EditReceipt, Self::Error> {
        // SAFETY: this trait leaf preserves the caller's exact-MM editor and
        // retained window obligations for the native x86 transaction.
        unsafe { execute_native_edit_intent(intent, table_base.raw(), table_bytes.raw()) }
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
