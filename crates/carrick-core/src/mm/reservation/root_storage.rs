//! Elastic node storage. Growth uses the existing guest allocator outside MM
//! locks. Published banks contain guest addresses and exact extent receipts;
//! host aliases are cached only in an owned, venue-local resolved view.

use super::*;

pub(super) const BANK_NODES: usize = 4096;
pub(super) const BANKS: usize = 256;

/// The shared node pool's capacity, as an operation observed it before a
/// `MetadataRequired` refusal ([`SharedReservations::node_capacity`]). Only
/// the table mints it, so a bank supply always names the capacity it found
/// too small.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct NodeCapacity(u32);

/// Why a node bank supply left the pool at the capacity it observed
/// (#3085). A concurrent bank that grew the pool is success, never here.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum NodeBankShortfall {
    /// The `BANKS` table is full: the pool can never grow again.
    Full,
    /// Another supplier holds the bank append window. Not now: its close
    /// wakes every space's Metadata cause, which the caller observed before
    /// it tried.
    Publishing,
    /// The allocator had no extent for a bank: a grant in flight for this
    /// requester's boundary, or memory no grant can add.
    Metadata(MetadataMiss),
    /// The allocator's receipt does not cover the bank it returned.
    Invalid,
}

/// What a host bank grant installed by [`SharedReservations::provision_metadata`]
/// decided (#3085). Only `Published` consumes the grant; the caller retires
/// it on either other answer.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum HostBankInstall {
    /// This grant is now a bank: decide again.
    Published,
    /// The pool already grew past the generation the caller sampled (a
    /// guest fork's bank, or another host venue's): this grant is redundant,
    /// and the pool serves the caller as well as it would have. Decide again.
    Redundant,
    /// Another supplier holds the bank append window. Not now: its close
    /// wakes every space's `SpaceWaitCause::Metadata`, which the caller
    /// observed before it sampled the generation.
    WindowHeld,
}

/// The one decision an append makes under the bank window.
enum Append {
    /// This bank is published.
    Published,
    /// The pool already holds more than the caller observed (a racing
    /// append): this bank is redundant and stays the caller's.
    Grown,
    /// The `BANKS` table is full.
    Full,
    /// Another appender holds the window: this bank stays the caller's.
    WindowHeld,
}

#[derive(::core::clone::Clone, ::core::marker::Copy)]
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
        Self::capacity_of(self.count.load(Ordering::Acquire))
    }
    const fn capacity_of(count: u32) -> u32 {
        NODES as u32 + count * BANK_NODES as u32
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
pub struct ResolvedReservationNodes<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
> {
    pub(super) table: *const SharedReservations<Policy, Geometry>,
    count: u32,
    bases: [*mut Node; BANKS],
    pins: [Option<P>; BANKS],
}
impl<P: PinnedMetadataExtent, Policy: ReservationPolicy, Geometry: ReservationGeometry> Default
    for ResolvedReservationNodes<P, Policy, Geometry>
{
    fn default() -> Self {
        Self {
            table: core::ptr::null(),
            count: 0,
            bases: [core::ptr::null_mut(); BANKS],
            pins: core::array::from_fn(|_| None),
        }
    }
}
impl<P: PinnedMetadataExtent, Policy: ReservationPolicy, Geometry: ReservationGeometry>
    ResolvedReservationNodes<P, Policy, Geometry>
{
    /// Dynamic banks are resolved from exact grants. Bootstrap banks live in
    /// the carrier's bootstrap metadata arena (`Geometry::BOOTSTRAP_BASE`,
    /// `Geometry::BOOTSTRAP_SIZE`): inside the EL1 region on AArch64, in its
    /// own supervisor window on x86 CPL0. `bootstrap` is the host alias of
    /// that arena's first byte; its mapping already owns the table's
    /// lifetime and is never translated as guest user memory.
    ///
    /// # Safety
    /// `bootstrap` must alias this table's live carrier bootstrap metadata
    /// arena, all `Geometry::BOOTSTRAP_SIZE` bytes of it, and remain mapped
    /// through every use of this resolved view.
    pub unsafe fn refresh<R: MetadataExtentResolver<Pin = P>>(
        &mut self,
        table: &SharedReservations<Policy, Geometry>,
        resolver: &R,
        bootstrap: core::ptr::NonNull<u8>,
    ) -> Result<(), Refusal> {
        if table.layout_hash.load(Ordering::Acquire)
            != SharedReservations::<Policy, Geometry>::LAYOUT_HASH
        {
            return Err(Refusal::Stale);
        }
        if !self.table.is_null() && !core::ptr::eq(self.table, table) {
            return Err(Refusal::Stale);
        }
        let count = table.storage.count.load(Ordering::Acquire);
        if count as usize > BANKS || self.count > count {
            return Err(Refusal::Stale);
        }
        while self.count < count {
            let bank = table.storage.bank(self.count as usize);
            let bytes = core::mem::size_of::<Node>() * BANK_NODES;
            let (base, pin) = if bank.token == 0 {
                if bank.extent_base != Geometry::BOOTSTRAP_BASE
                    || bank.extent_len != Geometry::BOOTSTRAP_SIZE
                {
                    return Err(Refusal::Stale);
                }
                let offset = bank
                    .guest_base
                    .checked_sub(Geometry::BOOTSTRAP_BASE)
                    .filter(|offset| {
                        offset
                            .checked_add(bytes as u64)
                            .is_some_and(|end| end <= Geometry::BOOTSTRAP_SIZE)
                    })
                    .ok_or(Refusal::Stale)?;
                let offset = usize::try_from(offset).map_err(|_| Refusal::Invalid)?;
                // SAFETY: the caller aliases this carrier's whole bootstrap
                // arena, and the bank lies inside it (checked above).
                (unsafe { bootstrap.as_ptr().add(offset).cast() }, None)
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
    /// How many published banks this view resolves. A root lock refuses a
    /// view behind the table's [`SharedReservations::storage_generation`]
    /// with `MetadataRequired`; refresh, then lock again.
    pub fn bank_count(&self) -> u32 {
        self.count
    }
}
impl<P: PinnedMetadataExtent, Policy: ReservationPolicy, Geometry: ReservationGeometry> NodeBanks
    for ResolvedReservationNodes<P, Policy, Geometry>
{
    fn count(&self) -> u32 {
        self.count
    }
    fn base(&self, index: usize) -> *mut Node {
        self.bases[index]
    }
}

struct IdentityBanks<'a, Policy: ReservationPolicy, Geometry: ReservationGeometry>(
    &'a SharedReservations<Policy, Geometry>,
);
impl<Policy: ReservationPolicy, Geometry: ReservationGeometry> NodeBanks
    for IdentityBanks<'_, Policy, Geometry>
{
    fn count(&self) -> u32 {
        self.0.storage.count.load(Ordering::Acquire)
    }
    fn base(&self, index: usize) -> *mut Node {
        self.0.storage.bank(index).guest_base as *mut Node
    }
}

impl<Policy: ReservationPolicy, Geometry: ReservationGeometry>
    SharedReservations<Policy, Geometry>
{
    /// Layout of one elastic reservation bank, independent of MM population.
    pub fn metadata_bank_layout() -> core::alloc::Layout {
        core::alloc::Layout::new::<[Node; BANK_NODES]>()
    }

    /// Publish a retained carrier extent allocated outside every MM lock.
    /// The pin authenticates both the host alias and the EL1 address; these
    /// domains need not be numerically equal. A concurrent publication makes
    /// this grant redundant and leaves it unpublished; a held append window
    /// leaves it unpublished too ([`HostBankInstall`]). Neither is a refusal:
    /// only a full table (`MetadataRequired`) or a bad grant is.
    /// `waiters` are woken when this call's append window closes.
    pub fn provision_metadata<P: PinnedMetadataExtent>(
        &self,
        pin: &P,
        expected_generation: u32,
        waiters: &impl MetadataWaiters,
    ) -> Result<HostBankInstall, Refusal> {
        let extent = pin.extent();
        let capacity = expected_generation
            .checked_mul(BANK_NODES as u32)
            .and_then(|n| n.checked_add(NODES as u32))
            .ok_or(Refusal::Invalid)?;
        match self.install_bank(
            pin.host_base().as_ptr(),
            ExtentGrantReceipt {
                base_va: extent.base(),
                size: usize::try_from(extent.len()).map_err(|_| Refusal::Invalid)?,
                token: extent.token(),
            },
            extent.base(),
            capacity,
            waiters,
        )? {
            Append::Published => Ok(HostBankInstall::Published),
            Append::Grown => Ok(HostBankInstall::Redundant),
            Append::WindowHeld => Ok(HostBankInstall::WindowHeld),
            Append::Full => Err(Refusal::MetadataRequired),
        }
    }
    /// Published immutable bank generation; prepare a new pinned view only
    /// after this changes. The generation is monotonic for this table lifetime.
    pub fn storage_generation(&self) -> u32 {
        self.storage.bank_count()
    }

    /// The shared pool's node capacity now. An operation samples it before
    /// it locks a root, so a later [`Self::supply_node_bank`] for the same
    /// refusal adds nothing when another supplier grew the pool meanwhile.
    pub fn node_capacity(&self) -> NodeCapacity {
        NodeCapacity(self.storage.capacity())
    }

    /// Supply one node bank for an operation that was refused
    /// `MetadataRequired` against the `observed` capacity, holding no MM
    /// guard, editor or loan. `Ok` means the pool now holds more than
    /// `observed` (this bank, or a concurrent one): rerun the operation.
    /// Every answer is one decision against one read of the bank count, so
    /// a concurrent supplier can only turn a refusal into `Ok`, never the
    /// reverse. A held append window answers `Publishing`, and `waiters`
    /// are woken when this call's own window closes.
    pub fn supply_node_bank(
        &self,
        allocator: &impl ReservationMetadataAllocator,
        observed: NodeCapacity,
        waiters: &impl MetadataWaiters,
    ) -> Result<(), NodeBankShortfall> {
        let expected = observed.0;
        // One read decides growth and fullness together: `count` only
        // grows, and `BANKS` is its ceiling.
        let count = self.storage.bank_count();
        if Storage::capacity_of(count) > expected {
            return Ok(());
        }
        if count as usize >= BANKS {
            return Err(NodeBankShortfall::Full);
        }
        let layout = Self::metadata_bank_layout();
        let (ptr, receipt) = match allocator.allocate_with_extent(layout) {
            Ok(allocation) => allocation,
            // A peer holding the window may have taken the last extent for
            // its bank: its close wakes the caller, never a false ENOMEM.
            // The flag is read before the count: a holder publishes the
            // count, then closes.
            Err(_) if self.storage.publishing.load(Ordering::Acquire) != 0 => {
                return Err(NodeBankShortfall::Publishing);
            }
            // A peer's bank published while this allocation missed serves
            // the operation as well as this one would have.
            Err(_) if self.storage.capacity() > expected => return Ok(()),
            Err(miss) => return Err(NodeBankShortfall::Metadata(miss)),
        };
        let append = self.install_bank(ptr, receipt, ptr as u64, expected, waiters);
        if !matches!(append, Ok(Append::Published)) {
            allocator.deallocate(ptr, layout);
        }
        match append {
            Ok(Append::Published | Append::Grown) => Ok(()),
            Ok(Append::Full) => Err(NodeBankShortfall::Full),
            Ok(Append::WindowHeld) => Err(NodeBankShortfall::Publishing),
            Err(_) => Err(NodeBankShortfall::Invalid),
        }
    }

    /// Supply one bank through GLOBAL_ALLOCATOR (or the same allocator in a
    /// host-only model test). MetadataRequired means unwind and service the
    /// allocator's existing grant request before resubmission, never ENOMEM.
    /// The pool owns successful allocations until carrier teardown and reuses
    /// freed nodes across MM incarnations.
    fn provision_nodes(
        &self,
        allocator: &impl ReservationMetadataAllocator,
        expected_capacity: u32,
        waiters: &impl MetadataWaiters,
    ) -> Result<(), Refusal> {
        self.supply_node_bank(allocator, NodeCapacity(expected_capacity), waiters)
            .map_err(|shortfall| match shortfall {
                NodeBankShortfall::Full | NodeBankShortfall::Metadata(_) => {
                    Refusal::MetadataRequired
                }
                NodeBankShortfall::Publishing => Refusal::Busy,
                NodeBankShortfall::Invalid => Refusal::Invalid,
            })
    }

    fn install_bank(
        &self,
        ptr: *mut u8,
        receipt: ExtentGrantReceipt,
        base: u64,
        expected_capacity: u32,
        waiters: &impl MetadataWaiters,
    ) -> Result<Append, Refusal> {
        let bytes = core::mem::size_of::<Node>() * BANK_NODES;
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
        // A held window is "not now", never waited out here: its holder's
        // close wakes the Metadata cause the caller observed (#3085).
        let Some(window) = MetadataPublicationWindow::open(&self.storage.publishing, waiters)
        else {
            return Ok(Append::WindowHeld);
        };
        // One read of `count` under the window decides.
        let count = self.storage.count.load(Ordering::Relaxed);
        if Storage::capacity_of(count) > expected_capacity {
            return Ok(Append::Grown);
        }
        if count as usize >= BANKS {
            return Ok(Append::Full);
        }
        if Storage::capacity_of(count) != expected_capacity {
            // An observation above the pool's capacity is no observation.
            return Err(Refusal::Invalid);
        }
        let index = count as usize;
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
        drop(window);
        Ok(Append::Published)
    }

    /// Open the bank append window through the production guard, as another
    /// supplier's append does, for a test of the contended supply (#3085).
    /// Dropping it is that holder's real close: it releases the flag and
    /// wakes `waiters`. `None` when the window is already held.
    #[cfg(any(test, feature = "host-test"))]
    pub fn open_bank_window_for_test<'a, W: MetadataWaiters>(
        &'a self,
        waiters: &'a W,
    ) -> Option<impl Drop + 'a> {
        MetadataPublicationWindow::open(&self.storage.publishing, waiters)
    }

    #[cfg(any(test, feature = "host-test"))]
    pub fn lock_resolved<'a, P: PinnedMetadataExtent>(
        &'a self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
        wait: &dyn RootWait,
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        if !core::ptr::eq(nodes.table, self) {
            return Err(Refusal::Stale);
        }
        self.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: Some(nodes),
                identity: false,
            },
            wait,
            RootHolder::Host.word(),
            RootAuthority::SourceFree(self.source_free()),
        )
    }

    /// EL1's single-attempt owner venue over authenticated elastic banks.
    /// Resolution and capacity provision must precede this acquisition.
    #[cfg(any(test, feature = "host-test"))]
    pub fn lock_el1_resolved<'a, P: PinnedMetadataExtent>(
        &'a self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
        slot: u32,
    ) -> Result<Reservations<'a, Policy, Geometry>, Refusal> {
        self.lock_el1_resolved_with_context(index, mm, nodes, slot)
    }

    /// Source-free resolved acquisition preserves the caller's context ABI.
    #[cfg(any(test, feature = "host-test"))]
    pub fn lock_el1_resolved_with_context<
        'a,
        P: PinnedMetadataExtent,
        Context: Copy + Send + Sync + zerocopy::FromZeros,
    >(
        &'a self,
        index: usize,
        mm: ReservationMm,
        nodes: &'a ResolvedReservationNodes<P, Policy, Geometry>,
        slot: u32,
    ) -> Result<Reservations<'a, Policy, Geometry, Context>, Refusal> {
        if !core::ptr::eq(nodes.table, self) {
            return Err(Refusal::Stale);
        }
        self.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: Some(nodes),
                identity: false,
            },
            &NoRootWait,
            RootHolder::El1Slot(slot).word(),
            RootAuthority::SourceFree(self.source_free()),
        )
    }

    #[cfg(test)]
    pub(super) fn lock_identity_for_test(
        &self,
        index: usize,
        mm: ReservationMm,
    ) -> Result<Reservations<'_, Policy, Geometry>, Refusal> {
        self.lock_using(
            index,
            mm,
            RootStorageAccess {
                banks: None,
                identity: true,
            },
            &NoRootWait,
            RootHolder::Host.word(),
            RootAuthority::SourceFree(self.source_free()),
        )
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

impl<
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    C: Copy + Send + Sync + zerocopy::FromZeros,
> Reservations<'_, Policy, Geometry, C>
{
    /// Consume the MM guard before asking the existing allocator for capacity.
    /// MetadataRequired leaves the Linux operation uncommitted; service the
    /// allocator request at the ordinary host boundary, then reacquire/redecide.
    /// Other MMs remain runnable throughout allocation and bank publication.
    pub fn provision_metadata(
        self,
        allocator: &impl ReservationMetadataAllocator,
    ) -> Result<(), Refusal> {
        if self.pending().is_some() {
            return Err(Refusal::Busy);
        }
        let table = self.table;
        let capacity = self.node_capacity;
        // The guard's own release venue wakes the Metadata waiters when the
        // bank window closes (#3085); a source-free guard has none.
        let waiters = self.release_venue.as_ref().map(|venue| venue.release);
        drop(self);
        table.provision_nodes(allocator, capacity, &waiters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type SharedReservations = super::SharedReservations<
        carrick_personality_linux::mm::LinuxReservationPolicy,
        carrick_el1::memory::reservations::NativeReservationGeometry,
    >;
    type Reservations<'a> = super::Reservations<
        'a,
        carrick_personality_linux::mm::LinuxReservationPolicy,
        carrick_el1::memory::reservations::NativeReservationGeometry,
    >;
    type ResolvedReservationNodes<P> = super::ResolvedReservationNodes<
        P,
        carrick_personality_linux::mm::LinuxReservationPolicy,
        carrick_el1::memory::reservations::NativeReservationGeometry,
    >;
    use carrick_el1::alloc::MetadataStorage;
    use core::ptr::NonNull;
    use std::cell::{Cell, UnsafeCell};
    use std::rc::Rc;
    use std::{boxed::Box, vec, vec::Vec};

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
    fn layout() -> carrick_personality_linux::mm::LinuxReservationLayout {
        carrick_personality_linux::mm::LinuxReservationLayout {
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
                ptr as u64,
                table.storage.capacity(),
                &Wakes::default(),
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
    fn reservation_retained_capacity_uses_guest_identity_and_host_alias() {
        let table = table();
        let mm = ReservationMm::new(81).unwrap();
        table.publish(0, mm, layout()).unwrap();
        table.lock(0, mm).unwrap().finish_import().unwrap();
        table.allocated.store(NODES as u32, Ordering::Relaxed);
        let bytes = SharedReservations::metadata_bank_layout().size();
        let owner = Rc::new(Backing(UnsafeCell::new(vec![0u128; bytes / 16])));
        // Deliberately unmapped guest identity: dereferencing it on the host
        // would crash. The resolver alone supplies the authenticated alias.
        let extent = MetadataExtent::new(0x4000_0000_0000, bytes as u64, 92).unwrap();
        let resolver = Resolver {
            extent,
            owner,
            calls: Cell::new(0),
        };
        let pin = resolver.pin(extent).unwrap();
        assert_eq!(
            table.provision_metadata(&pin, 0, &Wakes::default()),
            Ok(HostBankInstall::Published)
        );
        let mut host = ResolvedReservationNodes::default();
        unsafe { host.refresh(&table, &resolver, NonNull::dangling()) }.unwrap();
        let mut model = table.lock_resolved(0, mm, &host, &NoRootWait).unwrap();
        let decision = model
            .mmap(Placement::Anywhere, 4096, ReservationProtection::READ_WRITE)
            .unwrap();
        let request = finish(&mut model, decision);
        assert!(model.mapping(request.range.start()).is_some());
        assert_eq!(table.storage_generation(), 1);
        assert!(model.work < 64);
    }

    #[test]
    fn reservation_host_resolution_refuses_an_unpublished_layout_before_pinning() {
        let table = table();
        let resolver = bank(&table);
        let mut host = ResolvedReservationNodes::default();
        assert_eq!(
            unsafe { host.refresh(&table, &resolver, NonNull::dangling()) },
            Err(Refusal::Stale)
        );
        assert_eq!(resolver.calls.get(), 0);
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
            let mut model = table.lock_resolved(index, mm, &host, &NoRootWait).unwrap();
            let decision = model
                .mmap(Placement::Anywhere, 8192, ReservationProtection::READ_WRITE)
                .unwrap();
            finish(&mut model, decision);
            assert!(model.work < 64);
        }
        let mut guest = table.lock_identity_for_test(0, a).unwrap();
        let old_generation = guest.generation();
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
        assert_eq!(guest.generation(), old_generation);
        let decision = guest.mprotect(request.range, request.protection).unwrap();
        finish(&mut guest, decision);
        let committed_generation = guest.generation();
        drop(guest);
        let mut first = table.lock_resolved(0, a, &host, &NoRootWait).unwrap();
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
        let mut second = table.lock_resolved(1, b, &host, &NoRootWait).unwrap();
        assert_eq!(
            second.mapping(0x100000).unwrap().protection,
            ReservationProtection::READ_WRITE
        );
        assert_eq!(second.generation(), old_generation);
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
        table
            .provision_nodes(&empty, NODES as u32, &Wakes::default())
            .unwrap();
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

    /// #3085: a refused operation supplies one bank against the capacity it
    /// observed, holding no MM guard; a capacity another supplier already
    /// raised adds nothing, and a full `BANKS` table refuses for good.
    #[test]
    fn node_bank_supply_adds_one_bank_against_the_observed_capacity() {
        let table = table();
        let mut backing = vec![0u8; 2 * 1024 * 1024];
        let allocator = MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        let observed = table.node_capacity();
        assert_eq!(observed, NodeCapacity(NODES as u32));
        let wakes = Wakes::default();
        table
            .supply_node_bank(&allocator, observed, &wakes)
            .unwrap();
        assert_eq!(wakes.0.get(), 1);
        assert_eq!(table.storage.bank_count(), 1);
        assert_eq!(
            table.node_capacity(),
            NodeCapacity((NODES + BANK_NODES) as u32)
        );
        // The same stale observation (a concurrent supplier's) adds nothing,
        // even with an allocator that has nothing to give.
        table
            .supply_node_bank(&MetadataStorage::new(), observed, &wakes)
            .unwrap();
        assert_eq!(table.storage.bank_count(), 1);
        // An allocator with no extent cannot add a bank: memory exhausted.
        assert_eq!(
            table.supply_node_bank(&MetadataStorage::new(), table.node_capacity(), &wakes),
            Err(NodeBankShortfall::Metadata(MetadataMiss::Exhausted))
        );
        // A full table refuses before it allocates.
        table.storage.count.store(BANKS as u32, Ordering::Release);
        assert_eq!(
            table.supply_node_bank(&allocator, table.node_capacity(), &wakes),
            Err(NodeBankShortfall::Full)
        );
        table.storage.count.store(1, Ordering::Release);
        // Only the one window this test opened woke waiters.
        assert_eq!(wakes.0.get(), 1);
    }

    /// A peer's bank published inside this supply's check-then-act window:
    /// its allocation runs between this supply's read of the bank count and
    /// its own decision.
    struct PeerSupplies<'a> {
        table: &'a SharedReservations,
        peer: &'a MetadataStorage,
        then: &'a MetadataStorage,
        supplied: Cell<usize>,
        returned: Cell<usize>,
    }
    // SAFETY: delegates to MetadataStorage, which owns its extents.
    unsafe impl ReservationMetadataAllocator for PeerSupplies<'_> {
        fn allocate_with_extent(
            &self,
            layout: core::alloc::Layout,
        ) -> Result<(*mut u8, ExtentGrantReceipt), MetadataMiss> {
            let observed = self.table.node_capacity();
            self.table
                .supply_node_bank(self.peer, observed, &Wakes::default())
                .unwrap();
            self.supplied.set(self.supplied.get() + 1);
            self.then.allocate_with_extent(layout)
        }
        fn deallocate(&self, ptr: *mut u8, layout: core::alloc::Layout) {
            self.returned.set(self.returned.get() + 1);
            self.then.deallocate(ptr, layout)
        }
    }

    /// #3085: a supply is one decision. A peer that publishes a bank,
    /// even the table's last, between this supply's read and its act turns
    /// the answer into "grown, rerun", never a false refusal, whether this
    /// supply's own allocation then misses or succeeds.
    #[test]
    fn node_bank_supply_never_refuses_a_pool_a_peer_grew() {
        let table = table();
        let mut peer_backing = vec![0u8; 4 * 1024 * 1024];
        let peer = MetadataStorage::new();
        peer.admit_bootstrap_region(peer_backing.as_mut_ptr() as u64, peer_backing.len())
            .unwrap();
        let mut own_backing = vec![0u8; 2 * 1024 * 1024];
        let own = MetadataStorage::new();
        own.admit_bootstrap_region(own_backing.as_mut_ptr() as u64, own_backing.len())
            .unwrap();
        let empty = MetadataStorage::new();
        // One bank short of full, so the peer's bank is the table's last.
        table
            .storage
            .count
            .store(BANKS as u32 - 1, Ordering::Release);
        let observed = table.node_capacity();
        // The supply's allocation misses after the peer's last bank landed.
        let missing = PeerSupplies {
            table: &table,
            peer: &peer,
            then: &empty,
            supplied: Cell::new(0),
            returned: Cell::new(0),
        };
        assert_eq!(
            table.supply_node_bank(&missing, observed, &Wakes::default()),
            Ok(())
        );
        assert_eq!(missing.supplied.get(), 1);
        assert_eq!(missing.returned.get(), 0);
        assert_eq!(table.storage.bank_count(), BANKS as u32);
        // The supply's allocation succeeds after a peer's bank landed: its
        // bank is redundant, returned, and the answer is still "grown".
        table
            .storage
            .count
            .store(BANKS as u32 - 2, Ordering::Release);
        let observed = table.node_capacity();
        let allocating = PeerSupplies {
            table: &table,
            peer: &peer,
            then: &own,
            supplied: Cell::new(0),
            returned: Cell::new(0),
        };
        assert_eq!(
            table.supply_node_bank(&allocating, observed, &Wakes::default()),
            Ok(())
        );
        assert_eq!(allocating.supplied.get(), 1);
        assert_eq!(table.storage.bank_count(), BANKS as u32 - 1);
        assert_eq!(allocating.returned.get(), 1);
        table.storage.count.store(0, Ordering::Release);
    }

    /// Counts Metadata wakes: each closed bank window is one.
    #[derive(Default)]
    struct Wakes(Cell<usize>);
    impl MetadataWaiters for Wakes {
        fn wake_metadata_waiters(&self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// A supplier parked on the Metadata cause: its holder's close wakes it.
    #[derive(Default)]
    struct Parked {
        wakes: std::sync::Mutex<usize>,
        woken: std::sync::Condvar,
    }
    impl MetadataWaiters for Parked {
        fn wake_metadata_waiters(&self) {
            *self.wakes.lock().unwrap() += 1;
            self.woken.notify_all();
        }
    }
    impl Parked {
        /// Park until a wake after `observed`; the bound only stops a broken
        /// close from hanging the suite.
        fn park(&self, observed: usize) -> usize {
            let (wakes, _) = self
                .woken
                .wait_timeout_while(
                    self.wakes.lock().unwrap(),
                    std::time::Duration::from_secs(30),
                    |wakes| *wakes == observed,
                )
                .unwrap();
            *wakes
        }
    }

    /// #3085: a supply that meets another supplier's bank window held is
    /// "not now" (`Publishing`), returns its bank and wakes nobody. The
    /// holder is a second live thread holding the production window guard;
    /// its own close (the guard's drop) is what wakes the parked supplier,
    /// and the supplier's rerun then publishes (contention once, then
    /// success).
    #[test]
    fn node_bank_supply_refuses_a_held_window_and_the_holders_close_wakes_it() {
        let table = table();
        let mut backing = vec![0u8; 4 * 1024 * 1024];
        let allocator = MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        let wakes = Wakes::default();
        let parked = Parked::default();
        let observed = table.node_capacity();
        let before = allocator.diagnostics().allocated_bytes;
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
        let (close_tx, close_rx) = std::sync::mpsc::sync_channel::<()>(0);
        std::thread::scope(|scope| {
            // Owned here, so a failed assertion drops it and frees the holder.
            let close_tx = close_tx;
            let table = &*table;
            let parked = &parked;
            let holder = scope.spawn(move || {
                let window = table.open_bank_window_for_test(parked).unwrap();
                held_tx.send(()).unwrap();
                close_rx.recv().unwrap();
                drop(window);
            });
            held_rx.recv().unwrap();
            let seen = *parked.wakes.lock().unwrap();
            assert_eq!(
                table.supply_node_bank(&allocator, observed, &wakes),
                Err(NodeBankShortfall::Publishing)
            );
            assert_eq!(table.storage.bank_count(), 0);
            assert_eq!(wakes.0.get(), 0);
            assert_eq!(allocator.diagnostics().allocated_bytes, before);
            // The holder may have taken the last extent: a miss under a
            // held window is the same "not now", never ENOMEM.
            assert_eq!(
                table.supply_node_bank(&MetadataStorage::new(), observed, &wakes),
                Err(NodeBankShortfall::Publishing)
            );
            // Nothing but the holder's close can wake the parked supplier.
            assert_eq!(*parked.wakes.lock().unwrap(), seen);
            close_tx.send(()).unwrap();
            assert_eq!(parked.park(seen), seen + 1, "the holder's close woke");
            holder.join().unwrap();
        });
        assert_eq!(table.storage.publishing.load(Ordering::Acquire), 0);
        assert_eq!(table.supply_node_bank(&allocator, observed, &wakes), Ok(()));
        assert_eq!(table.storage.bank_count(), 1);
        assert_eq!(wakes.0.get(), 1);
        table.storage.count.store(0, Ordering::Release);
    }

    /// #3085 P0 B: a host bank grant that meets a held window, or a pool a
    /// peer already grew, is a decision, never `Busy`: `WindowHeld` (not
    /// now, the holder's close wakes the caller) or `Redundant` (decide
    /// again). Neither consumes the grant.
    #[test]
    fn host_bank_install_answers_a_held_window_and_a_grown_pool() {
        let table = table();
        let bytes = SharedReservations::metadata_bank_layout().size();
        let grant = |token| {
            let owner = Rc::new(Backing(UnsafeCell::new(vec![0u128; bytes / 16])));
            let base = unsafe { (&mut *owner.0.get()).as_mut_ptr() } as u64;
            Pin {
                extent: MetadataExtent::new(base, bytes as u64, token).unwrap(),
                owner,
            }
        };
        let sampled = table.storage_generation();
        let parked = Parked::default();
        let window = table.open_bank_window_for_test(&parked).unwrap();
        assert_eq!(
            table.provision_metadata(&grant(93), sampled, &Wakes::default()),
            Ok(HostBankInstall::WindowHeld)
        );
        assert_eq!(table.storage_generation(), sampled);
        drop(window);
        assert_eq!(*parked.wakes.lock().unwrap(), 1);
        // A peer's bank lands after the sample: this grant is redundant.
        let mut backing = vec![0u8; 2 * 1024 * 1024];
        let allocator = MetadataStorage::new();
        allocator
            .admit_bootstrap_region(backing.as_mut_ptr() as u64, backing.len())
            .unwrap();
        table
            .supply_node_bank(&allocator, table.node_capacity(), &Wakes::default())
            .unwrap();
        assert_eq!(
            table.provision_metadata(&grant(94), sampled, &Wakes::default()),
            Ok(HostBankInstall::Redundant)
        );
        assert_eq!(table.storage_generation(), sampled + 1);
        assert_eq!(
            table.provision_metadata(&grant(95), sampled + 1, &Wakes::default()),
            Ok(HostBankInstall::Published)
        );
        assert_eq!(table.storage_generation(), sampled + 2);
        table.storage.count.store(0, Ordering::Release);
    }
}
