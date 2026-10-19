//! Owner-selected fork over live descriptors and the production reservation root.
#[cfg(target_os = "none")]
use super::MmPortal;
use super::{El1MmHandle, MmError};
#[cfg(target_os = "none")]
use crate::rust_alloc::vec::Vec;
use carrick_core::mm::transaction::{MmPortal as CoreMmPortal, OwnerVenue};
use carrick_el1_abi::{EntryContext, ReservationGeometry, ReservationPolicy};
use carrick_el1_abi::{
    PinnedMetadataExtent, PortalForkCompletion, PortalForkCustody, PortalForkRequest,
    ReservationNodeFlags,
};
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
use carrick_mmu_core::owner_mmu::Aarch64Mmu as NativeForkMmu;
use carrick_mmu_core::owner_mmu::OwnerForkMmu;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use carrick_mmu_core::x86::owner_mmu::X86Mmu as NativeForkMmu;
#[cfg(target_os = "none")]
use carrick_personality_linux::mm::MmErrorLinux;
use core::num::NonZeroU64;
#[cfg(not(target_os = "none"))]
use std::vec::Vec;

#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
const PA: u64 = 0x0000_ffff_ffff_f000;

/// Check the supplied table arenas and choose the primary window that the
/// maintenance service can address. The ordinal is returned to the host only
/// on a stage-3 refusal.
#[cfg(any(test, all(target_os = "none", target_arch = "aarch64")))]
pub(super) fn fork_table_window(
    request: PortalForkRequest,
    parent_ttbr0: u64,
) -> Result<carrick_mmu_core::aarch64::descriptor_txn::TableWindow, u64> {
    let pool = carrick_el1_abi::stage1_table_pool_window();
    for (check, arena) in [(1, request.child_tables), (2, request.parent_tables)] {
        if arena.base < pool.physical_base
            || arena.base + arena.len > pool.physical_base + pool.byte_len as u64
        {
            return Err(check);
        }
    }
    let base = parent_ttbr0 & PA;
    if base < pool.physical_base || base + 4096 > pool.physical_base + pool.byte_len as u64 {
        return Err(3);
    }
    Ok(carrick_mmu_core::aarch64::descriptor_txn::TableWindow {
        words: base as *mut core::sync::atomic::AtomicU64,
        physical_base: base,
        byte_len: 4096,
    })
}

pub use carrick_core::mm::fork::ForkScratch;
pub type PreparedOwnerFork<B = NativeForkMmu> = carrick_core::mm::fork::PreparedOwnerFork<B>;

#[derive(Clone, Copy, Default)]
pub struct LinuxForkPolicy;

impl carrick_core::mm::fork::MappingInheritancePolicy for LinuxForkPolicy {
    fn inheritance_policy(
        &self,
        mapping: &carrick_core::mm::fork::Mapping,
    ) -> carrick_core::mm::fork::Policy {
        if mapping.flags.contains(ReservationNodeFlags::DONTFORK) {
            carrick_core::mm::fork::Policy::Omit
        } else if mapping.flags.contains(ReservationNodeFlags::WIPEONFORK) {
            carrick_core::mm::fork::Policy::Wipe
        } else if mapping.flags.contains(ReservationNodeFlags::PRIVATE) {
            carrick_core::mm::fork::Policy::Private
        } else {
            carrick_core::mm::fork::Policy::Keep
        }
    }

    fn is_shared(&self, mapping: &carrick_core::mm::fork::Mapping) -> bool {
        !mapping.flags.contains(ReservationNodeFlags::PRIVATE)
    }
}

/// An unpublished memory result. Task admission chooses commit or rollback;
/// the child gate is closed throughout, and its exact parent undo remains owned.
pub struct UnpublishedEl1Child<B: OwnerForkMmu = NativeForkMmu> {
    pub(crate) inner: carrick_core::mm::fork::UnpublishedChild<B>,
}

impl<B: OwnerForkMmu> core::ops::Deref for UnpublishedEl1Child<B> {
    type Target = carrick_core::mm::fork::UnpublishedChild<B>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<B: OwnerForkMmu> core::ops::DerefMut for UnpublishedEl1Child<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<B: OwnerForkMmu> UnpublishedEl1Child<B> {
    pub fn commit<
        P: PinnedMetadataExtent,
        Policy: ReservationPolicy,
        Geometry: ReservationGeometry,
        Venue: OwnerVenue<Context>,
        Context: EntryContext,
    >(
        &mut self,
        portal: &CoreMmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
        worker: u32,
    ) -> Result<PortalForkCompletion, MmError> {
        let request = self.inner.completion.request;
        let parent = portal.root(request.operation.mm, worker)?;
        let child = portal.child_root(request.child_mm, worker)?;
        self.inner.commit(parent, child).map_err(Into::into)
    }

    pub fn abort<
        P: PinnedMetadataExtent,
        W: LiveDescriptorWords + ?Sized,
        Policy: ReservationPolicy,
        Geometry: ReservationGeometry,
        Venue: OwnerVenue<Context>,
        Context: EntryContext,
    >(
        &mut self,
        portal: &CoreMmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
        words: &W,
        worker: u32,
    ) -> Result<(), MmError> {
        let parent = self.inner.completion.request.operation.mm;
        let child = self.inner.completion.child.mm();
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let parent_index = portal.spaces.find(parent.raw()).ok_or(MmError::Stale)?;
        let _parent_editor = portal
            .space_access(worker)?
            .try_begin_edit(parent_index, parent.raw(), owner)
            .ok_or(MmError::Busy)?;
        let child_index = portal.spaces.find(child.raw()).ok_or(MmError::Stale)?;
        let child_editor = portal
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, child.raw(), owner)
            .ok_or(MmError::Busy)?;
        let root = portal.root(parent, worker)?;
        let child_root = portal.child_root(child, worker)?;
        drop(child_editor);
        self.inner
            .abort(words, root, child_root)
            .map_err(Into::into)
    }
}

pub trait NativeForkPortal<P: PinnedMetadataExtent, B: OwnerForkMmu = NativeForkMmu> {
    fn census_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        words: &W,
        worker: u32,
    ) -> Result<ForkScratch, MmError>;
    fn prepare_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        scratch: ForkScratch,
        words: &W,
        worker: u32,
    ) -> Result<PreparedOwnerFork<B>, MmError>;
    fn publish_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        plan: PreparedOwnerFork<B>,
        words: &W,
        worker: u32,
    ) -> Result<UnpublishedEl1Child<B>, MmError>;
}
impl<
    P: PinnedMetadataExtent,
    B: OwnerForkMmu,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    Context: EntryContext,
> NativeForkPortal<P, B> for CoreMmPortal<'_, P, Policy, Geometry, Venue, B, Context>
{
    /// First census the reachable graph with fixed recursion and a bounded
    /// temporary owner reservation observation. Allocate undo/table storage
    /// only after releasing editors and metadata, proportional to actual work.
    fn census_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        words: &W,
        worker: u32,
    ) -> Result<ForkScratch, MmError> {
        let capacity = self.fork_mapping_count(request.operation.mm, worker)?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(capacity)
            .map_err(|_| MmError::NoMemory)?;
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let grant = self
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        let mut root = self.root(request.operation.mm, worker)?;
        if root.generation() != request.parent_generation
            || root.incarnation().raw() != request.operation.incarnation.get()
            || root.operation_sequence() != request.operation.sequence.get()
        {
            return Err(MmError::Stale);
        }
        if !root.fork_ready() {
            return Err(MmError::Busy);
        }
        let mut full = false;
        root.observe_mappings(&mut |mapping| {
            if mappings.len() == mappings.capacity() {
                full = true;
            } else {
                mappings.push(mapping);
            }
        })?;
        if full {
            return Err(MmError::NoMemory);
        }
        drop(root);
        let mut count = ForkCensus {
            child: 0,
            parent: 0,
            live: 0,
            custody: mappings
                .iter()
                .filter(|m| {
                    m.host_backing.is_some()
                        && !m.flags.intersects(
                            ReservationNodeFlags::DONTFORK.union(ReservationNodeFlags::WIPEONFORK),
                        )
                })
                .count(),
        };
        census_table::<B, _, _>(
            &LinuxForkPolicy,
            words,
            &mappings,
            grant.ttbr0 & B::ADDRESS_MASK,
            0,
            0,
            &mut count,
        )?;
        drop(editor);
        ForkScratch::bounded(
            request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(Into::into)
    }
    fn prepare_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        request: PortalForkRequest,
        mut scratch: ForkScratch,
        words: &W,
        worker: u32,
    ) -> Result<PreparedOwnerFork<B>, MmError> {
        if !request.valid() || request.operation.carrier != self.carrier {
            return Err(MmError::Invalid);
        }
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let grant = self
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        let child_index = self
            .spaces
            .find(request.child_mm.raw())
            .ok_or(MmError::Stale)?;
        let child_editor = self
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, request.child_mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        if child_editor.grant().ttbr0 & B::ADDRESS_MASK != request.child_tables.base {
            return Err(MmError::Stale);
        }
        let mut root = self.root(request.operation.mm, worker)?;
        if root.incarnation().raw() != request.operation.incarnation.get()
            || root.generation() != request.parent_generation
            || root.operation_sequence() != request.operation.sequence.get()
        {
            return Err(MmError::Stale);
        }
        if !root.fork_ready() {
            return Err(MmError::Busy);
        }
        let child = self.child_root(request.child_mm, worker)?;
        if child.is_admitted() {
            return Err(MmError::Stale);
        }
        drop(child);
        let mut capacity_refused = false;
        root.observe_mappings(&mut |mapping| {
            if scratch.mappings.len() == scratch.mappings.capacity() {
                capacity_refused = true;
                return;
            }
            scratch.mappings.push(mapping);
            if !mapping
                .flags
                .intersects(ReservationNodeFlags::DONTFORK.union(ReservationNodeFlags::WIPEONFORK))
                && let Some(source) = mapping.host_backing
            {
                if scratch.custody.len() == scratch.custody.capacity() {
                    capacity_refused = true;
                    return;
                }
                scratch.custody.push(PortalForkCustody::HostBacking {
                    handle: source.handle(),
                    generation: source.generation(),
                });
            }
        })?;
        if capacity_refused {
            return Err(MmError::NoMemory);
        }
        let parent_root = grant.ttbr0 & B::ADDRESS_MASK;
        copy_table::<B, _, _>(
            &LinuxForkPolicy,
            words,
            request,
            &mut scratch,
            carrick_core::mm::fork::ForkTableCursor {
                table: parent_root,
                level: 0,
                base: 0,
                child_offset: 0,
            },
        )?;
        if scratch.reads.iter().any(|(pa, _)| {
            request.child_tables.contains(*pa) || request.parent_tables.contains(*pa)
        }) {
            return Err(MmError::Stale);
        }
        drop(root);
        drop(child_editor);
        drop(editor);
        Ok(PreparedOwnerFork::new(request, parent_root, scratch))
    }
    /// Physical custody is acquired from `plan.custody()` with no owner lock.
    /// After that effect, this phase revalidates every live parent word before
    /// linking any new table, then clones only the owner's reservation tree.
    fn publish_fork<W: LiveDescriptorWords + ?Sized>(
        &self,
        plan: PreparedOwnerFork<B>,
        words: &W,
        worker: u32,
    ) -> Result<UnpublishedEl1Child<B>, MmError> {
        let request = plan.request;
        let owner = NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
        let index = self
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let editor = self
            .space_access(worker)?
            .try_begin_edit(index, request.operation.mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        let child_index = self
            .spaces
            .find(request.child_mm.raw())
            .ok_or(MmError::Stale)?;
        let child_editor = self
            .space_access(worker)?
            .try_begin_closed_child_edit(child_index, request.child_mm.raw(), owner)
            .ok_or(MmError::Busy)?;
        if child_editor.grant().ttbr0 & B::ADDRESS_MASK != request.child_tables.base {
            return Err(MmError::Stale);
        }
        let root = self.root(request.operation.mm, worker)?;
        let child = self.child_root(request.child_mm, worker)?;
        let child_incarnation = NonZeroU64::new(child.incarnation().raw()).ok_or(MmError::Stale)?;
        let child_handle = unsafe {
            El1MmHandle::from_admitted_owner(self.carrier, request.child_mm, child_incarnation)
        };
        let mmap_next = editor.mmap_next();
        let brk = root.brk_current();
        let inner = plan.publish(words, root, child, child_handle)?;
        child_editor.set_mmap_next(mmap_next);
        child_editor.set_brk_current(brk);
        Ok(UnpublishedEl1Child { inner })
    }
}

pub use carrick_core::mm::fork::{
    ForkCensus, Policy, census_entry, census_table, copy_entry, copy_table, policy, rollback,
};

// Only publication words live in the code image; the per-slot locks and
// unpublished children belong to the existing mapped metadata heap.
#[cfg(any(test, target_os = "none"))]
mod runtime_storage {
    use super::UnpublishedEl1Child;
    #[cfg(target_os = "none")]
    use crate::rust_alloc::boxed::Box;
    use carrick_el1::lock::SpinLock;
    use core::sync::atomic::{AtomicPtr, Ordering};
    #[cfg(not(target_os = "none"))]
    use std::boxed::Box;

    type PendingForkSlot = SpinLock<Option<UnpublishedEl1Child>>;
    type PendingForkTable = [PendingForkSlot; carrick_el1_abi::EL1_STACK_SLOTS as usize];

    struct PendingForkStorage {
        table: AtomicPtr<PendingForkTable>,
        init_lock: SpinLock<()>,
    }

    impl PendingForkStorage {
        const fn new() -> Self {
            Self {
                table: AtomicPtr::new(core::ptr::null_mut()),
                init_lock: SpinLock::new(()),
            }
        }

        fn get(&'static self) -> &'static PendingForkTable {
            let mut table = self.table.load(Ordering::Acquire);
            if table.is_null() {
                table = self.initialize();
            }
            // SAFETY: initialize publishes only a fully initialized, leaked
            // table. Acquire pairs with publication; slot locks own mutations.
            unsafe { &*table }
        }

        #[inline(never)]
        fn initialize(&'static self) -> *mut PendingForkTable {
            // A same-CPU interrupt must not wait on its own initializer.
            let irq = carrick_el1::alloc::disable_irq_save();
            let guard = self.init_lock.lock();
            let mut table = self.table.load(Ordering::Acquire);
            if table.is_null() {
                let mut storage = Box::<PendingForkTable>::new_uninit();
                let slots = storage.as_mut_ptr().cast::<PendingForkSlot>();
                for slot in 0..carrick_el1_abi::EL1_STACK_SLOTS as usize {
                    // SAFETY: write each aligned slot directly in its final
                    // heap allocation, never materializing the array on stack.
                    unsafe { slots.add(slot).write(SpinLock::new(None)) };
                }
                // SAFETY: every element was initialized above. The table is
                // retained for the image lifetime, just like the old static.
                table = Box::into_raw(unsafe { storage.assume_init() });
                self.table.store(table, Ordering::Release);
            }
            drop(guard);
            carrick_el1::alloc::restore_irq(irq);
            table
        }
    }

    static PENDING_FORKS: PendingForkStorage = PendingForkStorage::new();

    #[cfg(target_os = "none")]
    pub(super) fn pending_forks() -> &'static PendingForkTable {
        PENDING_FORKS.get()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pending_fork_image_storage_fits_one_page() {
            assert!(core::mem::size_of_val(&PENDING_FORKS) <= 4096);
        }

        #[test]
        fn concurrent_initialization_retains_one_table_and_slot_locks() {
            let storage = Box::leak(Box::new(PendingForkStorage::new()));
            let storage: &'static PendingForkStorage = storage;
            let tables = std::thread::scope(|scope| {
                let peers: Vec<_> = (0..8).map(|_| scope.spawn(|| storage.get())).collect();
                peers
                    .into_iter()
                    .map(|peer| peer.join().unwrap())
                    .collect::<Vec<_>>()
            });
            let table = tables[0];
            assert_eq!(table.len(), carrick_el1_abi::EL1_STACK_SLOTS as usize);
            for peer in tables {
                assert!(core::ptr::eq(table, peer));
            }
            for slot in table {
                assert!(slot.try_lock().unwrap().is_none());
            }
            let held = table[0].lock();
            assert!(core::ptr::eq(table, storage.get()));
            assert!(storage.get()[0].try_lock().is_none());
            assert!(storage.get()[1].try_lock().is_some());
            drop(held);
            assert!(storage.get()[0].try_lock().is_some());
        }
    }
}

#[cfg(target_os = "none")]
use runtime_storage::pending_forks;

/// Complete runtime-table bring-up before routing any ARM EL1 entry. Repeated
/// entries perform only an acquire load, retaining live unpublished children.
#[cfg(target_os = "none")]
pub fn initialize_pending_forks() {
    let _ = pending_forks();
}

/// Production service runs on the carrier maintenance root. The owner drops
/// both root/editor guards before requesting physical custody. Its unpublished
/// child capsule remains owned in EL1 until the separately scheduled FINISH.
#[cfg(target_os = "none")]
pub(crate) fn authenticate_pending_parent_write(
    slot: usize,
    handle: El1MmHandle,
    sequence: NonZeroU64,
) -> Result<(), MmError> {
    let pending = pending_forks().get(slot).ok_or(MmError::Invalid)?.lock();
    let child = pending.as_ref().ok_or(MmError::Stale)?;
    let operation = child.completion.request.operation;
    if operation.carrier != handle.carrier()
        || operation.mm != handle.mm()
        || operation.incarnation != handle.incarnation()
        || operation.sequence != sequence
    {
        return Err(MmError::Stale);
    }
    Ok(())
}
#[cfg(target_os = "none")]
pub(crate) fn reconcile_pending_parent_write<W: LiveDescriptorWords + ?Sized>(
    slot: usize,
    handle: El1MmHandle,
    sequence: NonZeroU64,
    completion: carrick_el1_abi::CowGrantCompletion,
    words: &W,
) -> Result<(), MmError> {
    authenticate_pending_parent_write(slot, handle, sequence)?;
    let mut pending = pending_forks().get(slot).ok_or(MmError::Invalid)?.lock();
    let child = pending.as_mut().ok_or(MmError::Stale)?;
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    let _ = words;
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    let fork_words = {
        let request = child.completion.request;
        // SAFETY: this COW completion still owns the exact parent editor;
        // the detached fork retains both physical table arenas through FINISH.
        unsafe {
            carrick_el1::isa::x86::ForkDescriptorWords::checked(
                child.parent_root,
                request.child_tables,
                request.parent_tables,
            )
        }
        .map_err(|_| MmError::Stale)?
    };
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    let words = &fork_words;
    child
        .reconcile_parent_write(words, completion)
        .map_err(Into::into)
}

#[cfg(target_os = "none")]
pub fn serve_fork_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    #[cfg(target_arch = "aarch64")]
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    frame.x[1] = 0; // Slot claim.
    let slots =
        unsafe { &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots) };
    let Some(slot) = slots.fork(frame.slot as usize) else {
        frame.x[0] = 22;
        return;
    };
    let Some(service) = slot.claim() else {
        frame.x[0] = 16;
        return;
    };
    let request = service.request();
    let mut run = || -> Result<PortalForkCompletion, MmError> {
        frame.x[1] = 1; // Exact operation and outstanding work.
        if slots.carrier() != Some(request.operation.carrier) {
            return Err(MmError::Stale);
        }
        if slots.has_outstanding_transfer(request.operation.mm) {
            return Err(MmError::Busy);
        }
        let pending = pending_forks()
            .get(frame.slot as usize)
            .ok_or(MmError::Invalid)?;
        if pending.lock().is_some() {
            return Err(MmError::Busy);
        }
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<super::production::GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier: request.operation.carrier,
            roots: carrick_el1::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        frame.x[1] = 2; // Parent space and grant.
        let index = zone
            .spaces
            .find(request.operation.mm.raw())
            .ok_or(MmError::Stale)?;
        let grant = zone
            .spaces
            .grant(index, request.operation.mm.raw())
            .ok_or(MmError::Busy)?;
        frame.x[1] = 3; // Physical table pool and live word access.
        frame.x[3] = grant.ttbr0; // Failure-only host diagnostic.
        #[cfg(target_arch = "aarch64")]
        let pool = carrick_el1_abi::stage1_table_pool_window();
        #[cfg(target_arch = "aarch64")]
        let primary = fork_table_window(request, grant.ttbr0).map_err(|check| {
            frame.x[2] = check;
            MmError::Invalid
        })?;
        #[cfg(target_arch = "aarch64")]
        let maintenance = CallerInvalidatesAsid;
        #[cfg(target_arch = "aarch64")]
        let words = unsafe {
            PrimaryTableWords::new(
                primary.words,
                primary.physical_base,
                primary.byte_len,
                &maintenance,
            )
            .and_then(|words| words.with_window(pool))
        }
        .map_err(|_| MmError::Core)?;
        #[cfg(target_arch = "x86_64")]
        let words = {
            // SAFETY: the carrier retains the single upper direct window and
            // both granted arenas through the exact owner fork settlement.
            unsafe {
                carrick_el1::isa::x86::ForkDescriptorWords::checked(
                    grant.ttbr0,
                    request.child_tables,
                    request.parent_tables,
                )
            }
            .map_err(|_| MmError::Stale)?
        };
        frame.x[1] = 4; // Reachable graph census.
        let scratch = portal.census_fork(request, &words, frame.slot as u32)?;
        frame.x[1] = 5; // Owner fork preparation.
        let plan = portal.prepare_fork(request, scratch, &words, frame.slot as u32)?;
        frame.x[1] = 6; // Exact physical custody.
        for (index, custody) in plan.custody().iter().copied().enumerate() {
            if !service.retain(index as u64, custody, super::production::yield_host_effect) {
                return Err(MmError::Busy);
            }
        }
        frame.x[1] = 7; // Parent and closed child publication.
        let child = portal.publish_fork(plan, &words, frame.slot as u32)?;
        #[cfg(target_arch = "aarch64")]
        crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, grant.ttbr0);
        #[cfg(target_arch = "x86_64")]
        if !words.drain_succeeded()
            || carrick_el1::isa::x86::portal_invalidate_root(grant.ttbr0).is_err()
        {
            carrick_el1::isa::x86::fatal_entry_binding();
        }
        let completion = child.completion();
        *pending.lock() = Some(child);
        frame.x[1] = 8; // Detached receipt publication.
        service.publish_detached(completion).ok_or(MmError::Stale)?;
        Ok(completion)
    };
    match run() {
        Ok(_) => {
            frame.x[0] = 0;
        }
        Err(error) => {
            let errno = error.errno();
            service.complete(errno);
            frame.x[0] = u64::from(errno);
        }
    }
}

#[cfg(target_os = "none")]
pub fn finish_fork_hw(frame: &mut carrick_el1_abi::TrapFrame) {
    #[cfg(target_arch = "aarch64")]
    use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
    let result = (|| -> Result<(), MmError> {
        let slots = unsafe {
            &*(carrick_el1_abi::EL1_MM_PORTAL_BASE as *const carrick_el1_abi::MmPortalSlots)
        };
        let slot = slots.fork(frame.slot as usize).ok_or(MmError::Invalid)?;
        let (request, commit) = slot.finish_request().ok_or(MmError::Stale)?;
        if slots.carrier() != Some(request.operation.carrier) {
            return Err(MmError::Stale);
        }
        let pending = pending_forks()
            .get(frame.slot as usize)
            .ok_or(MmError::Invalid)?;
        let mut child = pending.lock().take().ok_or(MmError::Stale)?;
        if child.completion().request != request {
            *pending.lock() = Some(child);
            return Err(MmError::Stale);
        }
        let zone =
            unsafe { &*(carrick_el1_abi::EL1_ZONE_BASE as *const carrick_el1_abi::ZoneTables) };
        let portal = MmPortal::<super::production::GuestMetadataPin> {
            backend: core::marker::PhantomData,
            carrier: request.operation.carrier,
            roots: carrick_el1::memory::reservations::shared_guest(),
            spaces: &zone.spaces,
            nodes: None,
            zone: Some(zone),
        };
        let settlement = if commit {
            child.commit(&portal, frame.slot as u32).map(|_| ())
        } else {
            #[cfg(target_arch = "aarch64")]
            let maintenance = CallerInvalidatesAsid;
            let base = child.parent_root;
            #[cfg(target_arch = "aarch64")]
            let words = unsafe {
                PrimaryTableWords::new(
                    base as *mut core::sync::atomic::AtomicU64,
                    base,
                    4096,
                    &maintenance,
                )
                .and_then(|words| words.with_window(carrick_el1_abi::stage1_table_pool_window()))
            }
            .map_err(|_| MmError::Core);
            #[cfg(target_arch = "x86_64")]
            let words = {
                // SAFETY: the detached child retains both granted table
                // arenas, while FINISH owns the exact parent/child editors.
                unsafe {
                    carrick_el1::isa::x86::ForkDescriptorWords::checked(
                        base,
                        request.child_tables,
                        request.parent_tables,
                    )
                }
                .map_err(|_| MmError::Stale)
            };
            words.and_then(|words| {
                child.abort(&portal, &words, frame.slot as u32)?;
                #[cfg(target_arch = "x86_64")]
                if !words.drain_succeeded() {
                    carrick_el1::isa::x86::fatal_entry_binding();
                }
                Ok(())
            })
        };
        if let Err(error) = settlement {
            *pending.lock() = Some(child);
            return Err(error);
        }
        if !commit
            && let Some(index) = zone.spaces.find(request.operation.mm.raw())
            && let Some(grant) = zone.spaces.grant(index, request.operation.mm.raw())
        {
            #[cfg(target_arch = "aarch64")]
            crate::sched::ThreadCpu::invalidate_asid(&mut crate::sched::HardwareCpu, grant.ttbr0);
            #[cfg(target_arch = "x86_64")]
            if carrick_el1::isa::x86::portal_invalidate_root(grant.ttbr0).is_err() {
                carrick_el1::isa::x86::fatal_entry_binding();
            }
        }
        if !slot.complete_finish_receipt(child.completion()) {
            return Err(MmError::Stale);
        }
        Ok(())
    })();
    frame.x[0] = result.err().map_or(0, |error| u64::from(error.errno()));
}
