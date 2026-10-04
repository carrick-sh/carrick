//! VM-free fixtures of the real reservation, descriptor, scheduler and transfer owners.
use super::*;
use crate::fault::{NoopCowResolver, NoopPreparedResolver};
use crate::memory::reservations::{Layout, ResolvedReservationNodes, SharedReservations};
use carrick_el1_abi::{
    FrameGrantMailbox, FrameGrantResidencyTable, MetadataExtent, MetadataExtentResolver,
    MetadataResolutionError, PinnedMetadataExtent, ReservationProtection, ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::{CallerInvalidatesAsid, PrimaryTableWords};
use carrick_sched_core::AddressSpaces;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

pub const VA: u64 = 0x4000_0000;
pub const IPA: u64 = 0x9000_0000;
pub const ROOT: u64 = 0x8000_0000;
pub const RW: u64 = 3 | (1 << 6) | (1 << 10) | (1 << 54);

pub struct Region {
    pub ptr: NonNull<u8>,
    pub layout: std::alloc::Layout,
    pub bank: Option<std::sync::Arc<Bank>>,
}
impl Default for Region {
    fn default() -> Self {
        Self::new()
    }
}
impl Region {
    pub fn new() -> Self {
        let layout =
            std::alloc::Layout::from_size_align(carrick_el1_abi::EL1_REGION_SIZE as usize, 64)
                .unwrap();
        // SAFETY: allocation is the exact retained carrier region layout.
        let ptr = NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).unwrap();
        Self {
            ptr,
            layout,
            bank: None,
        }
    }
    pub fn portal_slots(&self) -> &carrick_el1_abi::MmPortalSlots {
        // SAFETY: exact zero-initialized retained carrier region and ABI offset.
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                .cast()
        }
    }
    pub fn zone(&self) -> &carrick_sched_core::ZoneTables {
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast()
        }
    }
    pub fn table(&self) -> &SharedReservations {
        // SAFETY: zero-initialized production table in its real region offset;
        // the retained region outlives every borrowed view.
        unsafe {
            &*self
                .ptr
                .as_ptr()
                .add(carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
                .cast()
        }
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}
pub struct Bank {
    pub ptr: NonNull<u8>,
    pub layout: std::alloc::Layout,
}
// SAFETY: node accesses use production per-MM locks; the allocation is stable.
unsafe impl Send for Bank {}
unsafe impl Sync for Bank {}
impl Drop for Bank {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}
pub struct NoPin(std::sync::Arc<Bank>);
// SAFETY: the retained bank allocation cannot move or be freed before this pin.
unsafe impl PinnedMetadataExtent for NoPin {
    fn extent(&self) -> MetadataExtent {
        MetadataExtent::new(self.0.ptr.as_ptr() as u64, self.0.layout.size() as u64, 91).unwrap()
    }
    fn host_base(&self) -> NonNull<u8> {
        self.0.ptr
    }
}
pub struct NoResolver<'a>(&'a Region);
impl MetadataExtentResolver for NoResolver<'_> {
    type Pin = NoPin;
    fn pin(&self, extent: MetadataExtent) -> Result<NoPin, MetadataResolutionError> {
        let pin = NoPin(
            self.0
                .bank
                .as_ref()
                .ok_or(MetadataResolutionError::StaleOwner)?
                .clone(),
        );
        if pin.extent() != extent {
            return Err(MetadataResolutionError::StaleOwner);
        }
        Ok(pin)
    }
}
impl Region {
    pub fn add_bank(&mut self) {
        let layout = std::alloc::Layout::from_size_align(4 * 1024 * 1024, 64).unwrap();
        let bank = std::sync::Arc::new(Bank {
            ptr: NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).unwrap(),
            layout,
        });
        self.table()
            .provision_metadata(&NoPin(bank.clone()), self.table().storage_generation())
            .unwrap();
        self.bank = Some(bank);
    }
}
pub struct CountWords<'a, W> {
    pub words: &'a W,
    pub loads: core::cell::Cell<usize>,
}
impl<W: carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords>
    carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords for CountWords<'_, W>
{
    fn load(
        &self,
        pa: u64,
    ) -> Result<u64, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.loads.set(self.loads.get() + 1);
        self.words.load(pa)
    }
    fn compare_exchange(
        &self,
        pa: u64,
        current: u64,
        new: u64,
    ) -> Result<bool, carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.words.compare_exchange(pa, current, new)
    }
    fn store_unlinked(
        &self,
        pa: u64,
        value: u64,
    ) -> Result<(), carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal> {
        self.words.store_unlinked(pa, value)
    }
    fn publish_barrier(&self) {
        self.words.publish_barrier()
    }
    fn invalidate_range(&self, va: u64, len: u64) {
        self.words.invalidate_range(va, len)
    }
}
pub struct Tables {
    pub base: u64,
    pub words: Box<[AtomicU64]>,
}
impl Tables {
    pub fn new(base: u64, ipa: u64, pages: usize) -> Self {
        let words = (0..6 * 512)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        words[0].store((base + 4096) | 3, Ordering::Relaxed);
        words[512 + 1].store((base + 8192) | 3, Ordering::Relaxed);
        words[1024].store((base + 12288) | 3, Ordering::Relaxed);
        for page in 0..pages {
            words[1536 + page].store((ipa + page as u64 * 4096) | RW, Ordering::Relaxed);
        }
        Self { base, words }
    }
    pub fn live<'a>(
        &'a self,
        maintenance: &'a CallerInvalidatesAsid,
    ) -> PrimaryTableWords<'a, CallerInvalidatesAsid> {
        // SAFETY: this is the production primary-table venue over a retained,
        // aligned atomic arena. Every mutation holds this MM's editor.
        unsafe {
            PrimaryTableWords::new(
                self.words.as_ptr().cast_mut(),
                self.base,
                self.words.len() * 8,
                maintenance,
            )
        }
        .unwrap()
    }
}
pub fn admit(
    region: &Region,
    spaces: &AddressSpaces,
    mm: u64,
    root: u64,
    pages: usize,
    unrelated: usize,
) -> ReservationMm {
    admit_kind(region, spaces, mm, root, pages, unrelated, true)
}
pub fn admit_kind(
    region: &Region,
    spaces: &AddressSpaces,
    mm: u64,
    root: u64,
    pages: usize,
    unrelated: usize,
    anonymous: bool,
) -> ReservationMm {
    admit_access(
        region,
        carrick_sched_core::spaces::notification::SpaceAccess::source_free(spaces),
        mm,
        root,
        pages,
        unrelated,
        anonymous,
    )
}
pub fn admit_notified(
    region: &Region,
    mm: u64,
    root: u64,
    pages: usize,
    unrelated: usize,
) -> ReservationMm {
    admit_access(
        region,
        crate::sched::object_wait::space_access(region.zone(), carrick_sched_core::SlotId::new(0)),
        mm,
        root,
        pages,
        unrelated,
        true,
    )
}
fn admit_access(
    region: &Region,
    spaces: carrick_sched_core::spaces::notification::SpaceAccess<'_>,
    mm: u64,
    root: u64,
    pages: usize,
    unrelated: usize,
    anonymous: bool,
) -> ReservationMm {
    let index = spaces.publish_closed(mm, root, root).unwrap();
    let mm = ReservationMm::new(mm).unwrap();
    let table = region.table();
    table
        .publish(
            index.index(),
            mm,
            Layout {
                heap: ReservationRange::new(4096, VA).unwrap(),
                arena: ReservationRange::new(VA, VA + 0x1000_0000).unwrap(),
                brk: 4096,
                address_limit: u64::MAX,
                data_limit: u64::MAX,
                external_address_bytes: 0,
                external_data_bytes: 0,
            },
        )
        .unwrap();
    let view = nodes(region);
    let mut owner = if let Some(venue) = spaces.venue() {
        crate::memory::reservations::RootReleaseVenue::new(table, venue)
            .unwrap()
            .lock_el1_resolved(index.index(), mm, &view, 0)
            .unwrap()
    } else {
        table
            .lock_el1_resolved(index.index(), mm, &view, 0)
            .unwrap()
    };
    owner
        .import(
            ReservationRange::new(VA, VA + pages as u64 * 4096).unwrap(),
            ReservationProtection::READ_WRITE,
            anonymous,
        )
        .unwrap();
    for n in 0..unrelated {
        let va = VA + 0x0100_0000 + n as u64 * 8192;
        owner
            .import(
                ReservationRange::new(va, va + 4096).unwrap(),
                ReservationProtection::READ_WRITE,
                true,
            )
            .unwrap();
    }
    owner.finish_import().unwrap();
    drop(owner);
    spaces.open(index);
    mm
}
pub fn nodes(region: &Region) -> ResolvedReservationNodes<NoPin> {
    let mut nodes = ResolvedReservationNodes::default();
    unsafe { nodes.refresh(region.table(), &NoResolver(region), region.ptr) }.unwrap();
    nodes
}
pub fn residency() -> Box<FrameGrantResidencyTable> {
    let layout = std::alloc::Layout::new::<FrameGrantResidencyTable>();
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) }.cast::<FrameGrantResidencyTable>();
    assert!(!ptr.is_null());
    unsafe { Box::from_raw(ptr) }
}
pub fn select(
    portal: &MmPortal<'_, NoPin>,
    continuation: &TransferContinuation,
    tables: &Tables,
) -> TransferStep {
    let maintenance = CallerInvalidatesAsid;
    portal
        .select(
            continuation,
            &tables.live(&maintenance),
            &mut NoopPreparedResolver,
            &mut NoopCowResolver,
            &residency(),
            &FrameGrantMailbox::new(),
            0,
        )
        .unwrap()
}
pub fn selected(step: TransferStep) -> SelectedChunk {
    match step {
        TransferStep::Selected(chunk) => chunk,
        _ => panic!("expected selected data"),
    }
}

/// A physical fixture drives the unchanged production selection/service path.
/// Its implementation must assert one actual pin per copy and none on release.
pub trait PhysicalTransferFixture {
    fn carrier(&self) -> NonZeroU64;
    fn provision(&mut self, ipa: u64, len: usize);
    fn retain(
        &mut self,
        selected: carrick_el1_abi::PortalSelectedData,
        len: usize,
        intent: TransferIntent,
    ) -> carrick_el1_abi::PortalRetainedData;
    fn copy(
        &mut self,
        authorization: carrick_el1_abi::PortalCopyRequest<'_>,
        bytes: &mut [u8],
    ) -> bool;
    fn release(&mut self);
}

pub fn native_owner_matrix(mut make: impl FnMut() -> Box<dyn PhysicalTransferFixture>) {
    for pages in [16, 64, 256] {
        for unrelated in [16, 512] {
            let mut physical = make();
            physical.provision(IPA, pages * 4096);
            physical.provision(IPA + 0x100_000, pages * 4096);
            let mut region = Region::new();
            region.add_bank();
            let zone = region.zone();
            let spaces =
                crate::sched::object_wait::space_access(zone, carrick_sched_core::SlotId::new(0));
            let a = admit_notified(&region, 77, ROOT, pages, unrelated);
            // Both live MMs retain the original unrelated mapping population.
            let b = admit_notified(&region, 78, ROOT + 0x100_000, pages, unrelated);
            let identity = |tid| carrick_sched_core::ThreadIdentity {
                tid,
                serial: 1,
                mm: a.raw(),
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            };
            let target = zone.alloc_record(identity(1000)).unwrap();
            zone.publish_park(target, zone.next_seq(target));
            let gate = spaces.gate(spaces.find(a.raw()).unwrap());
            let mut waiting = Vec::new();
            for n in 0..carrick_sched_core::ZONE_SLOTS {
                let record = zone.alloc_host_runnable(identity(n as u64 + 1)).unwrap();
                let slot = carrick_sched_core::SlotId::from_index(n).unwrap();
                let driver = n as u64 + 1;
                zone.publish_slot(slot, 1, None, 0);
                zone.drive(slot, driver);
                assert!(zone.step_away(
                    slot,
                    driver,
                    &mut |_| panic!("unexpected take"),
                    &mut |_| panic!("unexpected place")
                ));
                assert!(zone.requeue_on(slot, record));
                waiting.push((slot, record, driver));
            }
            let view = nodes(&region);
            let portal = MmPortal::new(physical.carrier(), region.table(), &spaces, &view)
                .with_zone(zone)
                .unwrap();
            for (mm, root, ipa, intent) in [
                (a, ROOT, IPA, TransferIntent::UserWrite),
                (
                    b,
                    ROOT + 0x100_000,
                    IPA + 0x100_000,
                    TransferIntent::UserWrite,
                ),
                (a, ROOT, IPA, TransferIntent::UserRead),
                (
                    b,
                    ROOT + 0x100_000,
                    IPA + 0x100_000,
                    TransferIntent::UserRead,
                ),
            ] {
                let tables = Tables::new(root, ipa, pages);
                let handle = portal.admitted_handle(mm, 0).unwrap();
                let mut transfer = portal
                    .begin(handle, GuestVa::new(VA), pages as u64 * 4096, intent, 0)
                    .unwrap();
                let maintenance = CallerInvalidatesAsid;
                let words = tables.live(&maintenance);
                let mut chunks = 0;
                let source = vec![if mm == a { 0x31 } else { 0x72 }; pages * 4096];
                let mut copied = if intent == TransferIntent::UserWrite {
                    source.clone()
                } else {
                    vec![0; source.len()]
                };
                let visits_before = portal.vma_visits.load(Ordering::Relaxed);
                let counted = CountWords {
                    words: &words,
                    loads: core::cell::Cell::new(0),
                };
                while !transfer.is_complete() {
                    let chunk = selected(
                        portal
                            .select(
                                &transfer,
                                &counted,
                                &mut NoopPreparedResolver,
                                &mut NoopCowResolver,
                                &residency(),
                                &FrameGrantMailbox::new(),
                                0,
                            )
                            .unwrap(),
                    );
                    assert_eq!(chunk.ipa, ipa + transfer.offset());
                    assert!(region.table().el1_slot_holding(0).is_none());
                    let identity = physical.retain(
                        carrick_el1_abi::PortalSelectedData {
                            ipa: chunk.ipa,
                            executable: chunk.executable,
                            root_generation: NonZeroU64::new(chunk.generation).unwrap(),
                            offset: transfer.offset(),
                        },
                        chunk.len as usize,
                        intent,
                    );
                    let request = chunk.request(intent, identity).unwrap();
                    let slot = carrick_el1_abi::PortalTransferSlot::new();
                    let mut ticket = slot.submit(request).unwrap();
                    serve_transfer(&portal, slot.claim().unwrap(), &counted, 0, || {
                        assert!(region.table().el1_slot_holding(0).is_none());
                        // COMMIT retains exact range admission, not the MM
                        // editor: unrelated edits must remain possible.
                        let editor = spaces
                            .try_begin_edit(
                                spaces.find(mm.raw()).unwrap(),
                                mm.raw(),
                                NonZeroU64::new(2).unwrap(),
                            )
                            .expect("prepared COMMIT must not hold the MM editor");
                        let mut root = portal.root(mm, 1).unwrap();
                        assert!(
                            root.prepared_overlaps(
                                ReservationRange::new(chunk.va.raw(), chunk.va.raw() + chunk.len)
                                    .unwrap()
                            )
                        );
                        drop(root);
                        drop(editor);
                        assert!(ticket.copy_requested(|authorization| {
                            let selected = authorization.request().selected;
                            let start = (selected.ipa - ipa) as usize;
                            physical.copy(authorization, &mut copied[start..start + 4096])
                        }));
                    })
                    .unwrap();
                    transfer
                        .settle(request, ticket.take_completion().unwrap())
                        .unwrap();
                    physical.release();
                    chunks += 1;
                }
                for &(slot, record, driver) in &waiting {
                    assert!(!zone.slot(slot).is_live());
                    assert_eq!(zone.slot(slot).driver(), Some(driver));
                    assert_eq!(zone.slot(slot).queued(), 1);
                    assert!(zone.record(record).needs_host());
                    assert!(
                        matches!(zone.record(record).claim(),carrick_sched_core::Claim::Queued{slot:queued,..} if queued==slot)
                    );
                }
                assert!(matches!(
                    zone.record(target).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                ));
                assert_eq!(spaces.gate(spaces.find(a.raw()).unwrap()), gate);
                assert!(spaces.is_open(a.raw()));
                assert_eq!(copied, source);
                assert_eq!(chunks, pages);
                assert!(
                    counted.loads.get() <= pages * 8,
                    "two bounded live walks per copied page"
                );
                assert!(
                    portal.vma_visits.load(Ordering::Relaxed) - visits_before
                        <= pages * (unrelated + 1).ilog2() as usize * 4
                );
            }
            let a_tables = Tables::new(ROOT, IPA, pages);
            let b_tables = Tables::new(ROOT + 0x100_000, IPA + 0x100_000, pages);
            for protection in [
                Some(ReservationProtection::from_bits(1).unwrap()),
                Some(ReservationProtection::from_bits(0).unwrap()),
                None,
            ] {
                change_policy(&region, spaces, a, &a_tables, protection);
                let read = copy_one(
                    &mut *physical,
                    &portal,
                    a,
                    &a_tables,
                    TransferIntent::UserRead,
                );
                if protection.is_some_and(|p| p.bits() == 1) {
                    assert_eq!(read.unwrap(), [0x31; 4]);
                } else {
                    assert_eq!(read.unwrap_err().errno(), 14);
                }
                assert_eq!(
                    copy_one(
                        &mut *physical,
                        &portal,
                        a,
                        &a_tables,
                        TransferIntent::UserWrite
                    )
                    .unwrap_err()
                    .errno(),
                    14
                );
                assert_eq!(
                    copy_one(
                        &mut *physical,
                        &portal,
                        b,
                        &b_tables,
                        TransferIntent::UserRead
                    )
                    .unwrap(),
                    [0x72; 4]
                );
            }
        }
    }
}

/// Complete a real reservation decision and its core descriptor edit while
/// retaining that MM's editor. The fixture has no host policy mirror.
pub fn change_policy(
    region: &Region,
    spaces: carrick_sched_core::spaces::notification::SpaceAccess<'_>,
    mm: ReservationMm,
    tables: &Tables,
    protection: Option<ReservationProtection>,
) {
    use crate::memory::reservations::Decision;
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan, TableGrants, TerminalEdit,
        execute_descriptor_op,
    };
    use carrick_mmu_core::aarch64::{PtOp, SubstrateGpa, TerminalRule};
    let index = spaces.find(mm.raw()).unwrap();
    let _editor = spaces
        .try_begin_edit(index, mm.raw(), NonZeroU64::new(2).unwrap())
        .unwrap();
    let view = nodes(region);
    let request = {
        let mut root = match spaces.venue() {
            Some(venue) => {
                crate::memory::reservations::RootReleaseVenue::new(region.table(), venue)
                    .unwrap()
                    .lock_el1_resolved(index.index(), mm, &view, 0)
                    .unwrap()
            }
            None => region
                .table()
                .lock_el1_resolved(index.index(), mm, &view, 0)
                .unwrap(),
        };
        let range = ReservationRange::new(VA, VA + 4096).unwrap();
        let decision = match protection {
            Some(protection) => root.mprotect(range, protection).unwrap(),
            None => root.munmap(range).unwrap(),
        };
        let Decision::Work(request) = decision else {
            panic!("missing owner work")
        };
        request
    };
    let operation = match protection {
        None => DescriptorOp::Retire(PageSpan::new(VA, 4096)),
        Some(protection) => DescriptorOp::Terminal {
            span: PageSpan::new(VA, 4096),
            edit: TerminalEdit {
                rule: TerminalRule::Pt {
                    op: Some(if protection.bits() == 0 {
                        PtOp::Invalidate
                    } else {
                        PtOp::ReadOnly { exec: false }
                    }),
                    reset_retired: false,
                    deny_host_buffers: protection.bits() == 0,
                    fork_arm: false,
                    adopt_private: true,
                },
                asid_scoped: true,
                excluded_ipa: 0,
                excluded_len: 0,
                reclaim_budget: 0,
            },
        },
    };
    let outcome = execute_descriptor_op(
        &tables.live(&CallerInvalidatesAsid),
        SubstrateGpa(tables.base),
        operation,
        &TableGrants::NONE,
        &mut InlineJournal::new(),
    );
    assert!(
        matches!(outcome, DescriptorOutcome::Applied(_)),
        "{operation:?}: {outcome:?}"
    );
    let receipt = unsafe {
        carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            carrick_el1_abi::ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .unwrap();
    (match spaces.venue() {
        Some(venue) => crate::memory::reservations::RootReleaseVenue::new(region.table(), venue)
            .unwrap()
            .lock_el1_resolved(index.index(), mm, &view, 0)
            .unwrap(),
        None => region
            .table()
            .lock_el1_resolved(index.index(), mm, &view, 0)
            .unwrap(),
    })
    .complete(receipt)
    .unwrap();
}

fn copy_one(
    physical: &mut dyn PhysicalTransferFixture,
    portal: &MmPortal<'_, NoPin>,
    mm: ReservationMm,
    tables: &Tables,
    intent: TransferIntent,
) -> Result<[u8; 4], MmError> {
    let mut transfer = portal.begin(
        portal.admitted_handle(mm, 0)?,
        GuestVa::new(VA),
        4,
        intent,
        0,
    )?;
    let words = tables.live(&CallerInvalidatesAsid);
    let chunk = selected(portal.select(
        &transfer,
        &words,
        &mut NoopPreparedResolver,
        &mut NoopCowResolver,
        &residency(),
        &FrameGrantMailbox::new(),
        0,
    )?);
    let identity = physical.retain(
        carrick_el1_abi::PortalSelectedData {
            ipa: chunk.ipa,
            executable: chunk.executable,
            root_generation: NonZeroU64::new(chunk.generation).unwrap(),
            offset: 0,
        },
        4,
        intent,
    );
    let request = chunk.request(intent, identity)?;
    let slot = carrick_el1_abi::PortalTransferSlot::new();
    let mut ticket = slot.submit(request).unwrap();
    let mut bytes = [0; 4];
    serve_transfer(portal, slot.claim().unwrap(), &words, 0, || {
        assert!(ticket.copy_requested(|authorization| physical.copy(authorization, &mut bytes)));
    })?;
    transfer.settle(request, ticket.take_completion().unwrap())?;
    physical.release();
    assert!(transfer.is_complete());
    Ok(bytes)
}
