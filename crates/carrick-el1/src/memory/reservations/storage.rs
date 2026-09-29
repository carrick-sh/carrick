//! Elastic node storage. Growth uses the existing guest allocator outside MM
//! locks. Published banks contain guest addresses and exact extent receipts;
//! host aliases are cached only in an owned, venue-local resolved view.

use super::*;
use crate::alloc::{ExtentGrantReceipt, MetadataStorage};

pub(super) const BANK_NODES: usize = 4096;
const BANKS: usize = 256;

#[derive(Clone, Copy)]
#[repr(C)]
struct Bank {
    guest_base: u64,
    extent_base: u64,
    extent_len: u64,
    token: u64,
}

#[repr(C)]
pub(super) struct Storage {
    publishing: AtomicU32,
    count: AtomicU32,
    banks: [UnsafeCell<MaybeUninit<Bank>>; BANKS],
}
// Published banks are immutable. Release publication of count exposes their
// initialized identities; the short append lock never blocks MM operations.
unsafe impl Sync for Storage {}

impl Storage {
    fn bank(&self, index: usize) -> Bank {
        // SAFETY: index is below the acquired published count; bank is immutable.
        unsafe { *(*self.banks[index].get()).assume_init_ref() }
    }
    pub(super) fn bank_count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
    pub(super) fn capacity(&self) -> u32 {
        NODES as u32 + self.count.load(Ordering::Acquire) * BANK_NODES as u32
    }
}

/// An operation uses one immutable venue-local bank view. Resolving/pinning is
/// done before acquiring MM authority, once per storage-growth generation.
pub(super) trait NodeBanks {
    fn count(&self) -> u32;
    fn base(&self, index: usize) -> *mut Node;
}

/// The host's owned mapping pins. Refresh after MetadataRequired, outside MM
/// locks; an unchanged generation does zero resolution/allocation work. A view
/// for one carrier/table cannot be attached to another table.
pub struct ResolvedReservationNodes<P: PinnedMetadataExtent> {
    table: *const SharedReservations,
    count: u32,
    bases: [*mut Node; BANKS],
    pins: [Option<P>; BANKS],
}
impl<P: PinnedMetadataExtent> Default for ResolvedReservationNodes<P> {
    fn default() -> Self {
        Self {
            table: core::ptr::null(),
            count: 0,
            bases: [core::ptr::null_mut(); BANKS],
            pins: core::array::from_fn(|_| None),
        }
    }
}
impl<P: PinnedMetadataExtent> ResolvedReservationNodes<P> {
    /// Dynamic banks are resolved from exact grants. Bootstrap banks require
    /// the same carrier-owned EL1 region as `table`; its mapping already owns
    /// the table's lifetime and is never translated as guest user memory.
    ///
    /// # Safety
    /// `region` must name this table's live carrier EL1 region host mapping and
    /// remain mapped through every use of this resolved view.
    pub unsafe fn refresh<R: MetadataExtentResolver<Pin = P>>(
        &mut self,
        table: &SharedReservations,
        resolver: &R,
        region: core::ptr::NonNull<u8>,
    ) -> Result<(), Refusal> {
        if !self.table.is_null() && !core::ptr::eq(self.table, table) {
            return Err(Refusal::Stale);
        }
        let count = table.storage.count.load(Ordering::Acquire);
        while self.count < count {
            let bank = table.storage.bank(self.count as usize);
            let bytes = core::mem::size_of::<Node>() * BANK_NODES;
            let (base, pin) = if bank.token == 0 {
                if bank.extent_base != EL1_BOOTSTRAP_METADATA_BASE
                    || bank.extent_len != EL1_BOOTSTRAP_METADATA_SIZE
                {
                    return Err(Refusal::Stale);
                }
                let offset = usize::try_from(bank.guest_base - EL1_REGION_BASE)
                    .map_err(|_| Refusal::Invalid)?;
                // SAFETY: caller owns this carrier's region; published bank
                // construction checked containment in its enclosing extent.
                (unsafe { region.as_ptr().add(offset).cast() }, None)
            } else {
                let extent = MetadataExtent::new(bank.extent_base, bank.extent_len, bank.token)
                    .ok_or(Refusal::Stale)?;
                if !extent.contains(bank.guest_base, bytes as u64) {
                    return Err(Refusal::Stale);
                }
                let pin = resolver.pin(extent).map_err(|_| Refusal::Stale)?;
                if pin.extent() != extent {
                    return Err(Refusal::Stale);
                }
                let offset = (bank.guest_base - bank.extent_base) as usize;
                let base = unsafe { pin.host_base().as_ptr().add(offset).cast() };
                (base, Some(pin))
            };
            self.table = table;
            self.bases[self.count as usize] = base;
            self.pins[self.count as usize] = pin;
            self.count += 1;
        }
        self.table = table;
        Ok(())
    }
}
impl<P: PinnedMetadataExtent> NodeBanks for ResolvedReservationNodes<P> {
    fn count(&self) -> u32 {
        self.count
    }
    fn base(&self, index: usize) -> *mut Node {
        self.bases[index]
    }
}

struct IdentityBanks<'a>(&'a SharedReservations);
impl NodeBanks for IdentityBanks<'_> {
    fn count(&self) -> u32 {
        self.0.storage.count.load(Ordering::Acquire)
    }
    fn base(&self, index: usize) -> *mut Node {
        self.0.storage.bank(index).guest_base as *mut Node
    }
}

impl SharedReservations {
    /// Supply one bank through GLOBAL_ALLOCATOR (or the same allocator in a
    /// host-only model test). MetadataRequired means unwind and service the
    /// allocator's existing grant request before resubmission, never ENOMEM.
    /// The pool owns successful allocations until carrier teardown and reuses
    /// freed nodes across MM incarnations.
    fn provision_nodes(
        &self,
        allocator: &MetadataStorage,
        expected_capacity: u32,
    ) -> Result<(), Refusal> {
        if self.storage.capacity() > expected_capacity {
            return Ok(());
        }
        if self.storage.count.load(Ordering::Acquire) as usize == BANKS {
            return Err(Refusal::MetadataRequired);
        }
        let layout =
            core::alloc::Layout::array::<Node>(BANK_NODES).map_err(|_| Refusal::Invalid)?;
        let (ptr, receipt) = allocator
            .allocate_with_extent(layout)
            .ok_or(Refusal::MetadataRequired)?;
        let result = self.install_bank(ptr, receipt, expected_capacity);
        if result.is_err() {
            allocator.deallocate(ptr, layout);
        }
        result
    }

    fn install_bank(
        &self,
        ptr: *mut u8,
        receipt: ExtentGrantReceipt,
        expected_capacity: u32,
    ) -> Result<(), Refusal> {
        let bytes = core::mem::size_of::<Node>() * BANK_NODES;
        let base = ptr as u64;
        if !base.is_multiple_of(core::mem::align_of::<Node>() as u64)
            || base < receipt.base_va
            || base.checked_add(bytes as u64).is_none_or(|end| {
                receipt
                    .base_va
                    .checked_add(receipt.size as u64)
                    .is_none_or(|limit| end > limit)
            })
        {
            return Err(Refusal::Invalid);
        }
        // SAFETY: this fresh allocation is exclusively owned until publication.
        unsafe { core::ptr::write_bytes(ptr, 0, bytes) };
        self.storage
            .publishing
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Refusal::Busy)?;
        if self.storage.capacity() != expected_capacity {
            self.storage.publishing.store(0, Ordering::Release);
            return Err(Refusal::Busy);
        }
        let index = self.storage.count.load(Ordering::Relaxed) as usize;
        if index == BANKS {
            self.storage.publishing.store(0, Ordering::Release);
            return Err(Refusal::MetadataRequired);
        }
        unsafe {
            (*self.storage.banks[index].get()).write(Bank {
                guest_base: base,
                extent_base: receipt.base_va,
                extent_len: receipt.size as u64,
                token: receipt.token,
            });
        }
        self.storage
            .count
            .store(index as u32 + 1, Ordering::Release);
        self.storage.publishing.store(0, Ordering::Release);
        Ok(())
    }

    pub fn lock_resolved<'a, P: PinnedMetadataExtent>(
        &'a self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P>,
    ) -> Result<Reservations<'a>, Refusal> {
        if !core::ptr::eq(nodes.table, self) {
            return Err(Refusal::Stale);
        }
        self.lock_using(index, mm, Some(nodes), false)
    }

    #[cfg(test)]
    pub(super) fn lock_identity_for_test(
        &self,
        index: usize,
        mm: ReservationMm,
    ) -> Result<Reservations<'_>, Refusal> {
        self.lock_using(index, mm, None, true)
    }

    pub(super) fn node<'a>(&'a self, id: u32, banks: Option<&'a dyn NodeBanks>) -> &'a Node {
        let index = id as usize - 1;
        if index < NODES {
            return &self.nodes[index];
        }
        let index = index - NODES;
        let bank = index / BANK_NODES;
        let base = match banks {
            Some(banks) => banks.base(bank),
            None => IdentityBanks(self).base(bank),
        };
        // SAFETY: the view covers the locked tree and every node handed out
        // by its capacity-bounded allocator; bank identities never change.
        // Guest identity addresses are used only by guest or host model tests.
        unsafe { &*base.add(index % BANK_NODES) }
    }
}

impl Reservations<'_> {
    /// Consume the MM guard before asking the existing allocator for capacity.
    /// MetadataRequired leaves the Linux operation uncommitted; service the
    /// allocator request at the ordinary host boundary, then reacquire/redecide.
    /// Other MMs remain runnable throughout allocation and bank publication.
    pub fn provision_metadata(self, allocator: &MetadataStorage) -> Result<(), Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        let table = self.table;
        let capacity = self.node_capacity;
        drop(self);
        table.provision_nodes(allocator, capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;
    use std::cell::{Cell, UnsafeCell};
    use std::rc::Rc;

    struct Backing(UnsafeCell<Vec<u128>>);
    struct Pin {
        extent: MetadataExtent,
        owner: Rc<Backing>,
    }
    // SAFETY: the owned buffer never resizes and remains mapped through the pin;
    // test access uses the same per-MM exclusive guards as production.
    unsafe impl PinnedMetadataExtent for Pin {
        fn extent(&self) -> MetadataExtent {
            self.extent
        }
        fn host_base(&self) -> NonNull<u8> {
            NonNull::new(unsafe { (&mut *self.owner.0.get()).as_mut_ptr().cast() }).unwrap()
        }
    }
    struct Resolver {
        extent: MetadataExtent,
        owner: Rc<Backing>,
        calls: Cell<usize>,
    }
    impl MetadataExtentResolver for Resolver {
        type Pin = Pin;
        fn pin(&self, extent: MetadataExtent) -> Result<Pin, MetadataResolutionError> {
            self.calls.set(self.calls.get() + 1);
            if extent != self.extent {
                return Err(MetadataResolutionError::StaleOwner);
            }
            Ok(Pin {
                extent,
                owner: Rc::clone(&self.owner),
            })
        }
    }
    fn table() -> Box<SharedReservations> {
        let ptr =
            unsafe { std::alloc::alloc_zeroed(core::alloc::Layout::new::<SharedReservations>()) };
        assert!(!ptr.is_null());
        unsafe { Box::from_raw(ptr.cast()) }
    }
    fn layout() -> Layout {
        Layout {
            heap: ReservationRange::new(4096, 0x100000).unwrap(),
            arena: ReservationRange::new(0x100000, 0x10000000).unwrap(),
            brk: 4096,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        }
    }
    fn bank(table: &SharedReservations) -> Resolver {
        let owner = Rc::new(Backing(UnsafeCell::new(vec![
            0u128;
            core::mem::size_of::<Node>()
                * BANK_NODES
                / 16
        ])));
        let ptr = unsafe { (&mut *owner.0.get()).as_mut_ptr().cast::<u8>() };
        let size = core::mem::size_of::<Node>() * BANK_NODES;
        let extent = MetadataExtent::new(ptr as u64, size as u64, 91).unwrap();
        table
            .install_bank(
                ptr,
                ExtentGrantReceipt {
                    base_va: ptr as u64,
                    size,
                    token: 91,
                },
                table.storage.capacity(),
            )
            .unwrap();
        Resolver {
            extent,
            owner,
            calls: Cell::new(0),
        }
    }
    fn finish(model: &mut Reservations<'_>, decision: Decision) -> ReservationRequest {
        let Decision::Work(request) = decision else {
            panic!()
        };
        let completion = unsafe {
            ReservationCompletion::after_descriptor_and_backing_commit(
                request,
                ReservationBackingReceipt {
                    receipt: 1,
                    granted_bytes: 0,
                    returned_bytes: 0,
                },
            )
        }
        .unwrap();
        model.complete(completion).unwrap();
        request
    }

    #[test]
    fn reservation_elastic_host_views_pin_once_and_keep_two_mm_generations_separate() {
        let table = table();
        let a = ReservationMm::new(81).unwrap();
        let b = ReservationMm::new(82).unwrap();
        for (index, mm) in [(0, a), (1, b)] {
            table.publish(index, mm, layout()).unwrap();
            table.lock(index, mm).unwrap().finish_import().unwrap();
        }
        let resolver = bank(&table);
        // Force the new operations into elastic storage without spending the
        // test's work budget constructing unrelated bootstrap mappings.
        table.allocated.store(NODES as u32, Ordering::Relaxed);
        let mut host = ResolvedReservationNodes::default();
        for _ in 0..32 {
            unsafe { host.refresh(&table, &resolver, NonNull::dangling()) }.unwrap();
        }
        assert_eq!(
            resolver.calls.get(),
            1,
            "refresh must not rescan or repin stable banks"
        );
        assert!(
            matches!(table.lock(0, a), Err(Refusal::MetadataRequired)),
            "unresolved host view must not dereference guest addresses"
        );
        for (index, mm) in [(0, a), (1, b)] {
            let mut model = table.lock_resolved(index, mm, &host).unwrap();
            let decision = model
                .mmap(Placement::Anywhere, 8192, ReservationProtection::READ_WRITE)
                .unwrap();
            finish(&mut model, decision);
            assert!(model.work < 64);
        }
        let mut guest = table.lock_identity_for_test(0, a).unwrap();
        let old = guest
            .fault_plan(0x100000, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        let decision = guest
            .mprotect(
                ReservationRange::new(0x100000, 0x101000).unwrap(),
                ReservationProtection::NONE,
            )
            .unwrap();
        let Decision::Work(request) = decision else {
            panic!()
        };
        guest.refuse(request).unwrap();
        assert_eq!(guest.generation(), old.generation);
        let decision = guest.mprotect(request.range, request.protection).unwrap();
        finish(&mut guest, decision);
        let committed_generation = guest.generation();
        drop(guest);
        let mut first = table.lock_resolved(0, a, &host).unwrap();
        assert!(!first.authenticate_fault(old));
        assert_eq!(
            first.mapping(0x100000).unwrap().generation,
            committed_generation
        );
        assert_eq!(
            first.mapping(0x100000).unwrap().protection,
            ReservationProtection::NONE
        );
        drop(first);
        let mut second = table.lock_resolved(1, b, &host).unwrap();
        assert_eq!(
            second.mapping(0x100000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert_eq!(second.generation(), old.generation);
    }

    #[test]
    fn reservation_bank_append_does_not_extend_an_unresolved_host_guard() {
        let table = table();
        let mm = ReservationMm::new(18).unwrap();
        table.publish(0, mm, layout()).unwrap();
        let mut old_host = table.lock(0, mm).unwrap();
        old_host.finish_import().unwrap();
        table.allocated.store(NODES as u32, Ordering::Relaxed);
        let _resolver = bank(&table);
        assert_eq!(
            old_host.mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE),
            Err(Refusal::MetadataRequired)
        );
        assert!(old_host.pending().is_none());
        assert_eq!(old_host.generation().raw(), 1);
        drop(old_host);
        let empty = MetadataStorage::new();
        // A concurrent bank already supplied capacity: no second allocation.
        table.provision_nodes(&empty, NODES as u32).unwrap();
        assert_eq!(table.storage.capacity(), (NODES + BANK_NODES) as u32);
    }

    #[test]
    fn reservation_growth_consumes_its_guard_without_excluding_another_mm() {
        let table = table();
        let a = ReservationMm::new(18).unwrap();
        let b = ReservationMm::new(19).unwrap();
        table.publish(0, a, layout()).unwrap();
        table.publish(1, b, layout()).unwrap();
        let model = table.lock(0, a).unwrap();
        let other = table.lock(1, b).unwrap();
        let mut backing = vec![0u8; 2 * 1024 * 1024];
        let allocator = MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        model.provision_metadata(&allocator).unwrap();
        assert_eq!(other.generation().raw(), 1);
        assert_eq!(table.storage.capacity(), (NODES + BANK_NODES) as u32);
        // The consumed MM lock was released before provisioning.
        table.lock_identity_for_test(0, a).unwrap();
    }
}
