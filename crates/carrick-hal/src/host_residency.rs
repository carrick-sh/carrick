//! Host-side resolution of retained bootstrap and dynamic residency segments.
//!
//! Host retirement, dirty reconciliation, `mincore`, and refusal census must
//! traverse every segment the guest residency table grew into, never only the
//! initial 4,096-slot bootstrap segment. This module caches resolved aliases
//! behind monotonic `Arc` snapshots keyed to the exact live carrier region.

use std::ptr::NonNull;
use std::sync::Arc;

use carrick_el1_abi::{
    EL1_BOOTSTRAP_METADATA_BASE, EL1_BOOTSTRAP_METADATA_OFFSET, EL1_BOOTSTRAP_METADATA_SIZE,
    FrameGrantResidencyTable, MetadataExtent, MetadataExtentResolver, MetadataResolutionError,
    PinnedMetadataExtent, ResidencyRows, ResolvedResidencyTable,
};
use parking_lot::Mutex;

/// Type-erased pinned dynamic metadata extent owned by a host residency view.
pub struct DynamicResidencyPin {
    pin: Box<dyn PinnedMetadataExtent + Send + Sync>,
}

impl DynamicResidencyPin {
    pub fn new<P: PinnedMetadataExtent + Send + Sync + 'static>(pin: P) -> Self {
        Self { pin: Box::new(pin) }
    }
}

// SAFETY: delegates directly to the inner `PinnedMetadataExtent`, whose
// contract retains the host mapping until drop.
unsafe impl PinnedMetadataExtent for DynamicResidencyPin {
    fn extent(&self) -> MetadataExtent {
        self.pin.extent()
    }

    fn host_base(&self) -> NonNull<u8> {
        self.pin.host_base()
    }
}

/// Carrier-owned dynamic metadata resolver installed by the active host VMM so
/// host residency views can pin dynamic (`token != 0`) segments alongside
/// bootstrap (`token == 0`) segments.
pub trait HostMetadataPinResolver: Send + Sync {
    fn pin_dynamic(
        &self,
        extent: MetadataExtent,
    ) -> Result<DynamicResidencyPin, MetadataResolutionError>;
}

struct ResolverAdapter<'a>(Option<&'a dyn HostMetadataPinResolver>);

impl MetadataExtentResolver for ResolverAdapter<'_> {
    type Pin = DynamicResidencyPin;

    fn pin(&self, extent: MetadataExtent) -> Result<Self::Pin, MetadataResolutionError> {
        match self.0 {
            Some(resolver) => resolver.pin_dynamic(extent),
            None => Err(MetadataResolutionError::InvalidExtent),
        }
    }
}

struct HostResidencySnapshot {
    region_ptr: usize,
    table: &'static FrameGrantResidencyTable,
    resolved: Box<ResolvedResidencyTable<DynamicResidencyPin>>,
}

static HOST_RESIDENCY_CACHE: Mutex<Option<Arc<HostResidencySnapshot>>> = Mutex::new(None);
static HOST_RESIDENCY_RESOLVER: Mutex<Option<(usize, Arc<dyn HostMetadataPinResolver>)>> =
    Mutex::new(None);

/// Register the dynamic-extent pin resolver for the active carrier mapping at
/// `region_ptr`. Keyed by the exact host region address so a retired carrier
/// cannot collide with its successor.
pub fn install_host_residency_resolver(
    region_ptr: usize,
    resolver: Arc<dyn HostMetadataPinResolver>,
) {
    if region_ptr == 0 {
        return;
    }
    *HOST_RESIDENCY_RESOLVER.lock() = Some((region_ptr, resolver));
    let mut cache = HOST_RESIDENCY_CACHE.lock();
    if cache
        .as_ref()
        .is_some_and(|snapshot| snapshot.region_ptr != region_ptr)
    {
        *cache = None;
    }
}

/// Clear the dynamic-extent resolver and any cached pins belonging to
/// `region_ptr` before unmapping the carrier region.
pub fn clear_host_residency_resolver(region_ptr: usize) {
    if region_ptr == 0 {
        return;
    }
    let mut resolver = HOST_RESIDENCY_RESOLVER.lock();
    if resolver.as_ref().is_some_and(|(ptr, _)| *ptr == region_ptr) {
        *resolver = None;
    }
    drop(resolver);
    let mut cache = HOST_RESIDENCY_CACHE.lock();
    if cache
        .as_ref()
        .is_some_and(|snapshot| snapshot.region_ptr == region_ptr)
    {
        *cache = None;
    }
}

/// Pinned host view of the carrier's bootstrap and grown residency segments.
#[derive(Clone)]
pub struct HostResidencyView {
    snapshot: Arc<HostResidencySnapshot>,
}

impl HostResidencyView {
    /// Borrow the complete resolved residency table covering bootstrap and
    /// every published extension segment retained by this snapshot.
    pub fn table(&self) -> FrameGrantResidencyTable<ResidencyRows<'_>> {
        self.snapshot
            .resolved
            .view_or_bootstrap(self.snapshot.table)
    }

    /// Preclaim every live residency row overlapping `[start, start + len)`
    /// across all segments and return a `'static` guard that retains the
    /// segment pins until [`HostResidencyRetirement::commit`] or drop.
    pub fn begin_retire_overlapping(
        self,
        mm_key: u64,
        start: u64,
        len: u64,
    ) -> Option<HostResidencyRetirement> {
        let (mm_key, start, end) = self
            .table()
            .begin_retire_overlapping(mm_key, start, len)?
            .into_preclaimed_range();
        Some(HostResidencyRetirement {
            view: self,
            mm_key,
            start,
            end,
            active: true,
        })
    }
}

/// `'static` RAII retirement token retaining resolved segment pins across an
/// exact-MM host alias install or unmap transaction.
pub struct HostResidencyRetirement {
    view: HostResidencyView,
    mm_key: u64,
    start: u64,
    end: u64,
    active: bool,
}

impl HostResidencyRetirement {
    /// Retire the preclaimed rows across all segments after stage-1 leaves are
    /// unreachable. Exact-MM exclusion makes a failed commit an invariant error.
    #[must_use]
    pub fn commit(mut self) -> bool {
        let committed =
            self.view
                .table()
                .commit_preclaimed_retirement(self.mm_key, self.start, self.end);
        self.active = false;
        committed
    }
}

impl Drop for HostResidencyRetirement {
    fn drop(&mut self) {
        if self.active {
            self.view
                .table()
                .cancel_preclaimed_retirement(self.mm_key, self.start, self.end);
        }
    }
}

/// Resolve the active carrier's residency table including every published
/// bootstrap and dynamic extension segment. An unchanged extension count hits
/// the cached snapshot with zero resolution or allocation work.
pub fn current_host_residency() -> Option<HostResidencyView> {
    let region_ptr = carrick_el1_abi::get_el1_region_host_ptr();
    if region_ptr == 0 {
        return None;
    }
    let table = carrick_el1_abi::frame_grant_residency_host()?;
    let extensions = table.extension_count();
    {
        let cache = HOST_RESIDENCY_CACHE.lock();
        if let Some(snapshot) = cache.as_ref()
            && snapshot.region_ptr == region_ptr
            && snapshot.resolved.extension_count() == extensions
            && core::ptr::eq(snapshot.resolved.table_ptr(), table)
        {
            return Some(HostResidencyView {
                snapshot: Arc::clone(snapshot),
            });
        }
    }
    let bootstrap_host =
        NonNull::new((region_ptr + EL1_BOOTSTRAP_METADATA_OFFSET as usize) as *mut u8)?;
    let resolver = HOST_RESIDENCY_RESOLVER
        .lock()
        .as_ref()
        .and_then(|(ptr, resolver)| (*ptr == region_ptr).then(|| Arc::clone(resolver)));
    let adapter = ResolverAdapter(resolver.as_deref());
    let mut resolved = Box::new(ResolvedResidencyTable::new());
    // SAFETY: `table` and `bootstrap_host` belong to the active EL1 carrier
    // region published at `region_ptr`, and `adapter` pins any dynamic extents
    // in that exact carrier generation.
    unsafe {
        resolved
            .refresh(
                table,
                &adapter,
                Some((
                    EL1_BOOTSTRAP_METADATA_BASE,
                    EL1_BOOTSTRAP_METADATA_SIZE as usize,
                    bootstrap_host,
                )),
            )
            .ok()?;
    }
    let snapshot = Arc::new(HostResidencySnapshot {
        region_ptr,
        table,
        resolved,
    });
    let mut cache = HOST_RESIDENCY_CACHE.lock();
    if let Some(existing) = cache.as_ref()
        && existing.region_ptr == region_ptr
        && existing.resolved.extension_count() >= snapshot.resolved.extension_count()
        && core::ptr::eq(existing.resolved.table_ptr(), table)
    {
        return Some(HostResidencyView {
            snapshot: Arc::clone(existing),
        });
    }
    *cache = Some(Arc::clone(&snapshot));
    Some(HostResidencyView { snapshot })
}

/// Run `f` against the active carrier's fully resolved residency table
/// (bootstrap plus every grown segment alias).
pub fn with_host_residency<R>(
    f: impl FnOnce(&FrameGrantResidencyTable<ResidencyRows<'_>>) -> R,
) -> Option<R> {
    let view = current_host_residency()?;
    let table = view.table();
    Some(f(&table))
}

/// Preclaim an exact-MM residency retirement across all resolved segments of
/// the active carrier.
pub fn begin_host_residency_retirement(
    mm_key: u64,
    start: u64,
    len: u64,
) -> Option<HostResidencyRetirement> {
    current_host_residency()?.begin_retire_overlapping(mm_key, start, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_el1_abi::{
        EL1_FRAME_GRANT_RESIDENCY_OFFSET, ExtentGrantReceipt, FRAME_GRANT_RESIDENCY_SLOTS,
        FrameGrantResidencyIdentity, GRANT_PAGE_SIZE, ReservationMetadataAllocator,
    };
    use carrick_test_support::TestEl1Region;
    use core::alloc::Layout;
    use std::cell::RefCell;

    static TEST_REGION_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn host_residency_resolves_bootstrap_and_dynamic_aliases_for_reconciliation_and_retirement() {
        let _guard = TEST_REGION_LOCK.lock();
        let previous = carrick_el1_abi::get_el1_region_host_ptr();
        let mut region = TestEl1Region::zeroed();
        let region_ptr = region.as_mut_ptr() as usize;
        // SAFETY: aligned residency table inside the fixture EL1 region.
        let table = unsafe {
            let ptr =
                (region_ptr + EL1_FRAME_GRANT_RESIDENCY_OFFSET as usize).cast_mut_residency_ptr();
            FrameGrantResidencyTable::init_in_place(ptr);
            &*ptr
        };
        carrick_el1_abi::record_el1_region_host_ptr(region_ptr);

        // Populate a dynamic segment (token 77) with an explicit pin resolver.
        let dyn_layout = Layout::new::<carrick_el1_abi::ResidencySegment>();
        let dyn_host = unsafe { std::alloc::alloc_zeroed(dyn_layout) };
        assert!(!dyn_host.is_null());

        struct DirectHostAllocator {
            entries: RefCell<Vec<(*mut u8, ExtentGrantReceipt)>>,
        }
        // SAFETY: `dyn_host` remains allocated until the end of this test.
        unsafe impl ReservationMetadataAllocator for DirectHostAllocator {
            fn allocate_with_extent(
                &self,
                _layout: Layout,
            ) -> Option<(*mut u8, ExtentGrantReceipt)> {
                self.entries.borrow_mut().pop()
            }
            fn deallocate(&self, _ptr: *mut u8, _layout: Layout) {}
        }
        let alloc = DirectHostAllocator {
            entries: RefCell::new(vec![(
                dyn_host,
                ExtentGrantReceipt {
                    base_va: dyn_host as u64,
                    size: dyn_layout.size(),
                    token: 77,
                },
            )]),
        };
        struct TestPin(MetadataExtent, NonNull<u8>);
        // SAFETY: `dyn_host` remains allocated until end of test.
        unsafe impl Send for TestPin {}
        unsafe impl Sync for TestPin {}
        unsafe impl PinnedMetadataExtent for TestPin {
            fn extent(&self) -> MetadataExtent {
                self.0
            }
            fn host_base(&self) -> NonNull<u8> {
                self.1
            }
        }
        struct TestResolver {
            expected: MetadataExtent,
            host: usize,
        }
        impl HostMetadataPinResolver for TestResolver {
            fn pin_dynamic(
                &self,
                extent: MetadataExtent,
            ) -> Result<DynamicResidencyPin, MetadataResolutionError> {
                if extent != self.expected {
                    return Err(MetadataResolutionError::InvalidExtent);
                }
                Ok(DynamicResidencyPin::new(TestPin(
                    extent,
                    NonNull::new(self.host as *mut u8).unwrap(),
                )))
            }
        }
        table.grow(&alloc, 0).expect("grow dynamic segment 0");
        assert_eq!(table.extension_count(), 1);

        // Without resolver installed, dynamic segment resolution fails closed.
        assert!(current_host_residency().is_none());

        let expected_extent =
            MetadataExtent::new(dyn_host as u64, dyn_layout.size() as u64, 77).unwrap();
        install_host_residency_resolver(
            region_ptr,
            Arc::new(TestResolver {
                expected: expected_extent,
                host: dyn_host as usize,
            }),
        );

        // Publish 4,097 rows across bootstrap + dynamic segment via guest_view.
        let guest = unsafe { table.guest_view() };
        let base_va = 0x1000_0000_u64;
        for index in 0..=FRAME_GRANT_RESIDENCY_SLOTS {
            let offset = index as u64 * GRANT_PAGE_SIZE;
            let row = FrameGrantResidencyIdentity {
                mm_key: 42,
                semantic_base: base_va + offset,
                physical_ipa: 0x2000_0000 + offset,
                len: GRANT_PAGE_SIZE,
                mapping_id: index as u64 + 1,
                frame_id: index as u64 + 1,
                owner_generation: 1,
                inventory_revision: 1,
            };
            let slot = guest.try_publish(row).expect("publish across segments");
            let page = guest.lookup(42, row.semantic_base).expect("lookup");
            assert_eq!(page.slot, slot);
            assert!(guest.record_commit(page));
        }

        // Host dirty reconciliation sees and acks all 4,097 rows across both segments.
        let reconciled = with_host_residency(|host| {
            let mut count = 0usize;
            let _: core::ops::ControlFlow<()> = host.for_each_dirty_mm(42, |slot, row, bits| {
                assert_eq!(bits[0], 1);
                assert!(host.ack_dirty(slot, row));
                count += 1;
                core::ops::ControlFlow::Continue(())
            });
            count
        })
        .expect("resolved host view");
        assert_eq!(reconciled, FRAME_GRANT_RESIDENCY_SLOTS + 1);

        // Host `'static` retirement retires every row across both segments with zero leaks.
        let retirement = begin_host_residency_retirement(
            42,
            base_va,
            (FRAME_GRANT_RESIDENCY_SLOTS + 1) as u64 * GRANT_PAGE_SIZE,
        )
        .expect("begin retirement");
        assert!(retirement.commit());
        let remaining = with_host_residency(|host| host.observed_slots_used()).unwrap();
        assert_eq!(remaining, 0);

        clear_host_residency_resolver(region_ptr);
        carrick_el1_abi::record_el1_region_host_ptr(previous);
        unsafe { std::alloc::dealloc(dyn_host, dyn_layout) };
    }

    trait CastResidencyPtr {
        fn cast_mut_residency_ptr(self) -> *mut FrameGrantResidencyTable;
    }
    impl CastResidencyPtr for usize {
        fn cast_mut_residency_ptr(self) -> *mut FrameGrantResidencyTable {
            self as *mut FrameGrantResidencyTable
        }
    }
}
