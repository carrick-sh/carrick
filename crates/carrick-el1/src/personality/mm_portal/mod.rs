//! N0 owner experiment over the production reservation and MMU cores.
//!
//! This is an EL1 owner venue, not an HVF admission adapter. Physical callbacks
//! accept only extent custody and bytes; all VA, permission and COW decisions
//! occur here. N1 must bind this capability to the production carrier portal.
#[cfg(target_os = "none")]
use crate::rust_alloc as owned;
#[cfg(not(target_os = "none"))]
extern crate alloc as owned;

use crate::memory::reservations::{
    Decision, Layout, MoveTarget, Placement, Refusal, Reservations, ResolvedReservationNodes,
    SharedReservations,
};
use carrick_el1_abi::{
    MetadataExtent, MetadataExtentResolver, PinnedMetadataExtent, ReservationBackingReceipt,
    ReservationCompletion, ReservationMm, ReservationNodeFlags, ReservationProtection,
    ReservationRange,
};
use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
    GuestCowClass, classify_guest_cow_write,
};
use carrick_mmu_core::aarch64::descriptor_txn::{
    BackingIdentity, CowRepointAccess, DescriptorOp, DescriptorOutcome, DescriptorRefusal,
    DescriptorTxnId, InlineJournal, LiveDescriptorWords, PageSpan, TableGrants,
    execute_descriptor_op, execute_descriptor_txn,
};
use carrick_mmu_core::aarch64::{
    GuestLeafPublication, HostArenaResolver, LiveDescriptorOwner, PageTableError,
    PageTableLayoutConfig, PageTableManager, PtOp, SubstrateGpa, TerminalRule,
};
use core::{
    num::NonZeroU64,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use owned::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

pub const PAGE_BYTES: u64 = 4096;
pub const COMPOUND_BYTES: u64 = 16384;
pub const EXTENT_BYTES: u64 = 1048576;
const INTERNAL_VA: u64 = 0x2d001e4000;

/// Guest address, never a physical extent or a host pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestVa(u64);
impl GuestVa {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Identity only. Sealing consumes bootstrap input; no editor escapes.
///
/// ```compile_fail,E0599
/// use carrick_el1::personality::mm_portal::El1MmHandle;
/// fn escape(h: El1MmHandle) { let _ = h.page_table_manager(); }
/// ```
/// ```compile_fail,E0599
/// use carrick_el1::personality::mm_portal::El1MmHandle;
/// fn escape(h: El1MmHandle) { let _ = h.mutable_vma(); }
/// ```
/// ```compile_fail,E0599
/// use carrick_el1::personality::mm_portal::El1MmHandle;
/// fn escape(h: El1MmHandle) { let _ = h.memory_protections(); }
/// ```
/// ```compile_fail,E0599
/// use carrick_el1::personality::mm_portal::El1MmHandle;
/// fn escape(h: El1MmHandle) { let _ = h.host_ptr(); }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct El1MmHandle {
    carrier: NonZeroU64,
    mm: ReservationMm,
    incarnation: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmError {
    Fault,
    Stale,
    Busy,
    NoMemory,
    Invalid,
    Core,
    Reservation(Refusal),
    Table(PageTableError),
}
impl MmError {
    pub const fn errno(self) -> u32 {
        match self {
            Self::Fault => 14,
            Self::Stale => 3,
            Self::Busy => 16,
            Self::NoMemory => 12,
            Self::Invalid => 22,
            Self::Core | Self::Reservation(_) | Self::Table(_) => 5,
        }
    }
}
impl From<Refusal> for MmError {
    fn from(e: Refusal) -> Self {
        match e {
            Refusal::Stale => Self::Stale,
            Refusal::Busy => Self::Busy,
            Refusal::Hole | Refusal::Limit => Self::Fault,
            Refusal::MetadataRequired => Self::NoMemory,
            _ => Self::Reservation(e),
        }
    }
}
impl From<PageTableError> for MmError {
    fn from(e: PageTableError) -> Self {
        Self::Table(e)
    }
}

/// Internal reads are confined to the immutable boot control page. They are
/// not a privileged user-copy bypass, and cannot write or name other windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferIntent {
    UserRead,
    UserWrite,
    ReadInstruction,
    CarrickInternalRead,
}

/// Owner memory operations associated with the transfer family. They never
/// expose a mutable VMA and never invoke a host mmap/protection callback.
pub enum UserTransfer<'a> {
    MapLazy {
        range: ReservationRange,
        protection: ReservationProtection,
    },
    Protect {
        range: ReservationRange,
        protection: ReservationProtection,
    },
    Unmap {
        range: ReservationRange,
    },
    Remap {
        source: ReservationRange,
        destination: GuestVa,
    },
    CopyOut {
        address: GuestVa,
        bytes: &'a [u8],
        intent: TransferIntent,
    },
    CopyIn {
        address: GuestVa,
        bytes: &'a mut [u8],
        intent: TransferIntent,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtentKind {
    Data,
    Tables,
    Metadata,
    TransferStorage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentGrant {
    pub carrier: NonZeroU64,
    pub extent: MetadataExtent,
    pub kind: ExtentKind,
    pub zero_provenance: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capacity {
    Grant,
    Return(ExtentGrant),
    Settle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityResult {
    Granted(ExtentGrant),
    Returned,
}

/// Stage-2 custody only. No GuestVa, MM, predecessor, AP, VMA or semantic
/// reference count appears in this interface. The backend is moved into owner
/// construction and is never reachable through an admitted handle.
pub trait PhysicalExtentBackend: MetadataExtentResolver
where
    Self::Pin: Send + Sync + 'static,
{
    fn grant(&mut self, kind: ExtentKind, bytes: u64) -> Result<ExtentGrant, MmError>;
    fn return_extent(&mut self, grant: ExtentGrant) -> Result<(), MmError>;
    fn read(
        &mut self,
        extent: MetadataExtent,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), MmError>;
    fn write(&mut self, extent: MetadataExtent, offset: u64, bytes: &[u8]) -> Result<(), MmError>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Live table range resolutions (one per word access or bulk span), not
    /// the capacity of the extent resolved. Fork copied words are separate.
    pub table_visits: u64,
    pub fork_copied_words: u64,
    pub capacity_frame_visits: u64,
    pub vma_nodes: u64,
    pub pin_acquires: u64,
    pub pin_releases: u64,
    pub capacity_grants: u64,
    pub capacity_returns: u64,
    pub physical_callbacks: u64,
    pub host_semantic_callbacks: u64,
    pub host_protection_decisions: u64,
    pub host_cow_decisions: u64,
    pub host_projection_decisions: u64,
    pub host_worker_parks: u64,
    pub el0_entries: u64,
    pub retired_frame_visits: u64,
}
#[derive(Default)]
struct Meter {
    tables: AtomicU64,
    callbacks: AtomicU64,
    acquires: AtomicU64,
    releases: AtomicU64,
}
struct TableAlias<P> {
    pin: P,
    meter: Arc<Meter>,
}
// SAFETY: the physical pin retains this aligned extent; the owner serializes
// graph access. The resolver cannot select mappings or permissions.
unsafe impl<P: PinnedMetadataExtent> HostArenaResolver for TableAlias<P> {
    fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
        let extent = self.pin.extent();
        if !extent.contains(base, len as u64) || !base.is_multiple_of(8) {
            return None;
        }
        self.meter.tables.fetch_add(1, Ordering::Relaxed);
        self.meter.callbacks.fetch_add(1, Ordering::Relaxed);
        Some(
            self.pin
                .host_base()
                .as_ptr()
                .wrapping_add((base - extent.base()) as usize),
        )
    }
    fn publish_user_executable(&self, _: u64, _: u64) -> Result<(), PageTableError> {
        // Physical instruction-cache custody callback only. VM-free N0 never
        // enters EL0; hardware cache maintenance is an N1 binding.
        self.meter.callbacks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
struct LiveWords<'a> {
    tables: &'a PageTableManager,
    meter: &'a Meter,
}
impl LiveWords<'_> {
    fn word(&self, pa: u64) -> Result<&AtomicU64, DescriptorRefusal> {
        let ptr = self
            .tables
            .resolver()
            .and_then(|r| r.host_ptr_for_range(pa, 8))
            .ok_or(DescriptorRefusal::TableOutsidePrimary)?;
        // SAFETY: retained resolver pin, aligned checked range, owner exclusion.
        Ok(unsafe { &*ptr.cast::<AtomicU64>() })
    }
}
impl LiveDescriptorWords for LiveWords<'_> {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.word(pa).map(|p| p.load(Ordering::Acquire))
    }
    fn compare_exchange(&self, pa: u64, old: u64, new: u64) -> Result<bool, DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.word(pa)?.store(value, Ordering::Release);
        Ok(())
    }
    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    fn invalidate_range(&self, _: u64, _: u64) {
        // VM-free proof only; N1 needs hardware broadcast TLBI + negative control.
        core::sync::atomic::fence(Ordering::SeqCst);
        let _ = self.meter;
    }
}

#[derive(Default)]
struct Counts {
    references: AtomicU64,
    pins: AtomicU64,
}
struct Frame {
    extent: MetadataExtent,
    owner: usize,
    counts: Arc<Counts>,
    imported: bool,
}
struct Mm<P> {
    transaction_generation: u64,
    pending: Arc<AtomicU64>,
    handle: El1MmHandle,
    tables: PageTableManager,
    free: BTreeSet<u64>,
    internal: u64,
    imports: Arc<Vec<P>>,
    transfer_sequence: u64,
}
struct Extent {
    grant: ExtentGrant,
    owner: Option<usize>,
}
struct Chunk {
    page: u64,
    extent: Option<MetadataExtent>,
    offset: u64,
    len: usize,
}
struct OwnerPin {
    pending: Arc<AtomicU64>,
    counts: Arc<Counts>,
    meter: Arc<Meter>,
    reap: Arc<AtomicBool>,
}
impl Drop for OwnerPin {
    fn drop(&mut self) {
        self.counts.pins.fetch_sub(1, Ordering::AcqRel);
        self.pending.fetch_sub(1, Ordering::AcqRel);
        self.meter.releases.fetch_add(1, Ordering::Relaxed);
        self.reap.store(true, Ordering::Release);
    }
}
/// Bounded completion storage and exact physical-generation pins. Drop does
/// atomic release only; it never waits for EL0, an MM lock, or host I/O.
pub struct PendingCopy<P> {
    handle: El1MmHandle,
    revision: u64,
    chunks: Vec<Chunk>,
    bytes: Vec<u8>,
    _physical: Vec<P>,
    _pins: Vec<OwnerPin>,
}
/// Memory has committed, but no task or EL0 entry has been published.
pub struct UnpublishedEl1Child {
    handle: El1MmHandle,
}
impl UnpublishedEl1Child {
    /// Supplies identity to the task owner; this does not run the child.
    pub fn into_handle(self) -> El1MmHandle {
        self.handle
    }
}
/// Pre-admission declarations only; this type cannot take an admitted handle
/// or obtain the owner's manager. Seal consumes the declarations.
/// Backing provenance supplied once before admission, never inferred from VA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentBacking {
    Owned,
    HostBackingPrivate,
    HostBackingShared,
    CopyOnly,
}

struct ResidentImport<P> {
    range: ReservationRange,
    pin: P,
    offset: u64,
    backing: ResidentBacking,
}

pub struct BootMmBuilder<P> {
    image: Vec<u8>,
    image_base: u64,
    layout: Layout,
    seeds: Vec<(ReservationRange, ReservationProtection)>,
    resident: Vec<ResidentImport<P>>,
}
impl<P: PinnedMetadataExtent + Send + Sync + 'static> BootMmBuilder<P> {
    pub fn new(layout: Layout, image: Vec<u8>, image_base: u64) -> Self {
        Self {
            image,
            image_base,
            layout,
            seeds: Vec::new(),
            resident: Vec::new(),
        }
    }
    pub fn map_lazy(&mut self, range: ReservationRange, protection: ReservationProtection) {
        self.seeds.push((range, protection));
    }
    /// Consume exact-generation physical custody before admission. The pin
    /// keeps input bytes alive until the owner has adopted or copied them.
    pub fn import_resident(
        &mut self,
        range: ReservationRange,
        pin: P,
        offset: u64,
        backing: ResidentBacking,
    ) -> Result<(), MmError> {
        let extent = pin.extent();
        if !range.start().is_multiple_of(PAGE_BYTES)
            || !range.len().is_multiple_of(PAGE_BYTES)
            || !offset.is_multiple_of(PAGE_BYTES)
            || !extent.base().is_multiple_of(PAGE_BYTES)
            || extent
                .base()
                .checked_add(offset)
                .is_none_or(|start| !extent.contains(start, range.len()))
            || self
                .resident
                .iter()
                .any(|old| old.range.start() < range.end() && range.start() < old.range.end())
        {
            return Err(MmError::Invalid);
        }
        self.resident.push(ResidentImport {
            range,
            pin,
            offset,
            backing,
        });
        Ok(())
    }
    pub fn seal<B: PhysicalExtentBackend<Pin = P>>(
        self,
        portal: &mut MmPortal<B>,
    ) -> Result<El1MmHandle, MmError>
    where
        B::Pin: Send + Sync + 'static,
    {
        portal.seal(self)
    }
}

/// The owner holds the sole table and reservation venues. After seal, every
/// memory operation takes an opaque handle through one of the three families.
/// No lock guard survives a physical callback; a pending copy owns pins, not
/// an MM lock or execution slot. This core is no_std + alloc compatible.
pub struct MmPortal<B: PhysicalExtentBackend>
where
    B::Pin: Send + Sync + 'static,
{
    carrier: NonZeroU64,
    table: Box<SharedReservations>,
    nodes: ResolvedReservationNodes<B::Pin>,
    backend: B,
    mms: Vec<Mm<B::Pin>>,
    extents: BTreeMap<u64, Extent>,
    frames: BTreeMap<u64, Frame>,
    retired: BTreeSet<u64>,
    reap: Arc<AtomicBool>,
    meter: Arc<Meter>,
    work: Work,
    seal_grants: Option<Vec<ExtentGrant>>,
}
impl<B: PhysicalExtentBackend> MmPortal<B>
where
    B::Pin: Send + Sync + 'static,
{
    pub fn new(carrier: NonZeroU64, table: Box<SharedReservations>, backend: B) -> Self {
        Self {
            carrier,
            table,
            nodes: ResolvedReservationNodes::default(),
            backend,
            mms: Vec::new(),
            extents: BTreeMap::new(),
            frames: BTreeMap::new(),
            retired: BTreeSet::new(),
            reap: Arc::new(AtomicBool::new(false)),
            meter: Arc::new(Meter::default()),
            work: Work::default(),
            seal_grants: None,
        }
    }
    pub fn work(&self) -> Work {
        Work {
            table_visits: self.meter.tables.load(Ordering::Relaxed),
            physical_callbacks: self.meter.callbacks.load(Ordering::Relaxed),
            pin_acquires: self.meter.acquires.load(Ordering::Relaxed),
            pin_releases: self.meter.releases.load(Ordering::Relaxed),
            ..self.work
        }
    }
    fn callback(&self) {
        self.meter.callbacks.fetch_add(1, Ordering::Relaxed);
    }
    fn index(&self, h: El1MmHandle) -> Result<usize, MmError> {
        let i = usize::try_from(h.mm.raw() - 1).map_err(|_| MmError::Stale)?;
        if h.carrier != self.carrier || self.mms.get(i).is_none_or(|m| m.handle != h) {
            return Err(MmError::Stale);
        }
        Ok(i)
    }
    fn root(&self, i: usize) -> Result<Reservations<'_>, MmError> {
        Ok(self
            .table
            .lock_el1_resolved(i, self.mms[i].handle.mm, &self.nodes, 0)?)
    }
    fn grant(&mut self, kind: ExtentKind, owner: Option<usize>) -> Result<ExtentGrant, MmError> {
        self.callback();
        let grant = self.backend.grant(kind, EXTENT_BYTES)?;
        if grant.carrier != self.carrier
            || grant.kind != kind
            || !grant.zero_provenance
            || grant.extent.len() != EXTENT_BYTES
            || !grant.extent.base().is_multiple_of(COMPOUND_BYTES)
            || self.extents.contains_key(&grant.extent.base())
        {
            return Err(MmError::Stale);
        }
        self.extents
            .insert(grant.extent.base(), Extent { grant, owner });
        self.work.capacity_grants += 1;
        if kind != ExtentKind::Metadata
            && let Some(journal) = &mut self.seal_grants
        {
            journal.push(grant);
        }
        if let Some(i) = owner.filter(|_| kind == ExtentKind::Data) {
            for page in (grant.extent.base()..grant.extent.base() + EXTENT_BYTES)
                .step_by(PAGE_BYTES as usize)
            {
                self.frames.insert(
                    page,
                    Frame {
                        extent: grant.extent,
                        owner: i,
                        counts: Arc::new(Counts::default()),
                        imported: false,
                    },
                );
                self.mms[i].free.insert(page);
            }
        }
        Ok(grant)
    }
    fn pin(&self, extent: MetadataExtent) -> Result<B::Pin, MmError> {
        self.callback();
        let pin = self.backend.pin(extent).map_err(|_| MmError::Stale)?;
        if pin.extent() != extent {
            return Err(MmError::Stale);
        }
        Ok(pin)
    }
    fn refresh_nodes(&mut self) -> Result<(), MmError> {
        if self.table.storage_generation() == 0 {
            let grant = self.grant(ExtentKind::Metadata, None)?;
            let pin = self.pin(grant.extent)?;
            if SharedReservations::metadata_bank_layout().size() as u64 > EXTENT_BYTES {
                return Err(MmError::NoMemory);
            }
            self.table.provision_metadata(&pin, 0)?;
        }
        // SAFETY: no bootstrap banks are published here; only exact physical
        // grants. The resolved view retains all pins for this table lifetime.
        self.callback();
        unsafe {
            self.nodes
                .refresh(&self.table, &self.backend, NonNull::dangling())?;
        }
        Ok(())
    }
    fn empty_tables(
        &mut self,
        mut image: Vec<u8>,
        image_base: u64,
        arena: ReservationRange,
    ) -> Result<PageTableManager, MmError> {
        let grant = self.grant(ExtentKind::Tables, None)?;
        let resolver: Arc<dyn HostArenaResolver + Send + Sync> = Arc::new(TableAlias {
            pin: self.pin(grant.extent)?,
            meter: self.meter.clone(),
        });
        image.resize(EXTENT_BYTES as usize, 0);
        let mut tables = PageTableManager::new(
            image,
            image_base,
            PageTableLayoutConfig::new(0x100000, EXTENT_BYTES as usize, 0, 0),
        );
        tables.set_stage1_exclusive(true);
        tables.set_prot_none(arena.start(), arena.len() as usize, None)?;
        tables.rebase(grant.extent.base(), None)?;
        tables.provision_cow_copy_window(None)?;
        // SAFETY: resolver retains exact aligned backing until manager drop.
        unsafe {
            tables.restore_quiesced_snapshot_to_host(&resolver)?;
            tables.make_live(resolver);
        }
        Ok(tables)
    }
    fn seal(&mut self, boot: BootMmBuilder<B::Pin>) -> Result<El1MmHandle, MmError> {
        if self.seal_grants.is_some() {
            return Err(MmError::Busy);
        }
        let i = self.mms.len();
        // Rollback visits only the imported spans and grants made by this
        // bootstrap. It never snapshots an unrelated MM/frame population.
        let mut prior_frames = BTreeMap::new();
        for import in &boot.resident {
            for offset in (0..import.range.len()).step_by(PAGE_BYTES as usize) {
                let page = import.pin.extent().base() + import.offset + offset;
                prior_frames.insert(
                    page,
                    self.frames
                        .get(&page)
                        .map(|frame| frame.counts.references.load(Ordering::Acquire)),
                );
            }
        }
        self.seal_grants = Some(Vec::new());
        let result = self.seal_inner(boot);
        let rollback = self.seal_grants.take().ok_or(MmError::Core)?;
        if result.is_err() {
            let mm = ReservationMm::new(i as u64 + 1).ok_or(MmError::Invalid)?;
            if let Ok(root) = self.table.lock_el1_resolved(i, mm, &self.nodes, 0) {
                root.retire()?;
            }
            self.mms.truncate(i);
            for (page, references) in prior_frames {
                if let Some(references) = references {
                    if let Some(frame) = self.frames.get(&page) {
                        frame.counts.references.store(references, Ordering::Release);
                    }
                } else {
                    self.frames.remove(&page);
                }
            }
            for grant in rollback {
                for page in (grant.extent.base()..grant.extent.base() + grant.extent.len())
                    .step_by(PAGE_BYTES as usize)
                {
                    self.frames.remove(&page);
                }
                self.backend.return_extent(grant)?;
                self.extents.remove(&grant.extent.base());
                self.work.capacity_returns += 1;
            }
        }
        result
    }
    fn seal_inner(&mut self, boot: BootMmBuilder<B::Pin>) -> Result<El1MmHandle, MmError> {
        let i = self.mms.len();
        for import in &boot.resident {
            if !boot.seeds.iter().any(|(range, _)| *range == import.range) {
                return Err(MmError::Invalid);
            }
            if import.backing != ResidentBacking::CopyOnly {
                let live = self.pin(import.pin.extent())?;
                if live.host_base() != import.pin.host_base() {
                    return Err(MmError::Stale);
                }
            }
        }
        let mm = ReservationMm::new(i as u64 + 1).ok_or(MmError::Invalid)?;
        let h = El1MmHandle {
            carrier: self.carrier,
            mm,
            incarnation: NonZeroU64::new(i as u64 + 1).ok_or(MmError::Invalid)?,
        };
        self.table.publish(i, mm, boot.layout)?;
        self.refresh_nodes()?;
        let tables = self.empty_tables(boot.image, boot.image_base, boot.layout.arena)?;
        self.mms.push(Mm {
            transaction_generation: 0,
            pending: Arc::new(AtomicU64::new(0)),
            handle: h,
            tables,
            free: BTreeSet::new(),
            internal: 0,
            imports: Arc::new(Vec::new()),
            transfer_sequence: 0,
        });
        let mut root = self.root(i)?;
        for (range, protection) in boot.seeds {
            let backing = boot
                .resident
                .iter()
                .find(|r| r.range == range)
                .map(|r| r.backing);
            let flags = match backing {
                Some(ResidentBacking::HostBackingPrivate) => ReservationNodeFlags::PRIVATE,
                Some(ResidentBacking::HostBackingShared) => ReservationNodeFlags::EMPTY,
                _ => ReservationNodeFlags::ANONYMOUS_PRIVATE,
            };
            root.import_with(range, protection, flags)?;
        }
        root.finish_import()?;
        let visits = root.work as u64;
        drop(root);
        self.work.vma_nodes += visits;
        let internal = self.page(i)?;
        self.mms[i]
            .tables
            .map_kernel_data_aliased(INTERNAL_VA, internal, PAGE_BYTES, None)?;
        let resolver = self.mms[i]
            .tables
            .resolver()
            .cloned()
            .ok_or(MmError::Core)?;
        unsafe {
            self.mms[i].tables.sync_to_host(&resolver)?;
        }
        self.mms[i]
            .tables
            .set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        self.mms[i].internal = internal;
        let mut imports = Vec::new();
        for import in boot.resident {
            let extent = import.pin.extent();
            // Authenticate exact backend generation while the consumed source
            // pin still owns custody. No source VA or host permission query.
            if import.backing != ResidentBacking::CopyOnly {
                let authenticated = self.pin(extent)?;
                if authenticated.host_base() != import.pin.host_base() {
                    return Err(MmError::Stale);
                }
            }
            for offset in (0..import.range.len()).step_by(PAGE_BYTES as usize) {
                let va = import.range.start() + offset;
                let source = extent.base() + import.offset + offset;
                let page = if import.backing == ResidentBacking::CopyOnly {
                    let page = self.page(i)?;
                    let target = self.frames[&page].extent;
                    let mut bytes = [0; PAGE_BYTES as usize];
                    // SAFETY: the consumed source pin owns this exact bounded
                    // span even when its physical extent cannot be transferred
                    // to this backend. The source is not looked up in the
                    // destination's physical namespace.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            import
                                .pin
                                .host_base()
                                .as_ptr()
                                .add((source - extent.base()) as usize),
                            bytes.as_mut_ptr(),
                            bytes.len(),
                        );
                    }
                    self.callback();
                    self.backend.write(target, page - target.base(), &bytes)?;
                    page
                } else {
                    if let Some(frame) = self.frames.get(&source) {
                        if frame.extent != extent {
                            return Err(MmError::Stale);
                        }
                        frame.counts.references.fetch_add(1, Ordering::AcqRel);
                    } else {
                        self.frames.insert(
                            source,
                            Frame {
                                extent,
                                owner: i,
                                imported: true,
                                counts: Arc::new(Counts {
                                    references: AtomicU64::new(1),
                                    pins: AtomicU64::new(0),
                                }),
                            },
                        );
                    }
                    source
                };
                let protection = self.root(i)?.mapping(va).ok_or(MmError::Fault)?.protection;
                // The unpublished owner installs exact Linux protection before
                // its handle escapes; read-only input never acquires write intent.
                self.publish(
                    i,
                    va,
                    page,
                    protection.permits(ReservationProtection::READ_WRITE),
                )?;
                let exec = protection.bits() & 4 != 0;
                let permissions = if protection == ReservationProtection::NONE {
                    PtOp::KernelReadOnly { exec }
                } else if protection.permits(ReservationProtection::READ_WRITE) {
                    PtOp::ReadWrite { exec }
                } else {
                    PtOp::ReadOnly { exec }
                };
                let op =
                    self.mms[i]
                        .tables
                        .terminal_op(va, PAGE_BYTES, TerminalRule::pt(permissions));
                self.transaction(i, op)?;
                // Private host-file aliases must COW before any guest write.
                if import.backing == ResidentBacking::HostBackingPrivate {
                    let op = self.mms[i]
                        .tables
                        .fork_arm_op(va, PAGE_BYTES, false, exec, false);
                    self.transaction(i, op)?;
                }
            }
            if import.backing != ResidentBacking::CopyOnly {
                imports.push(import.pin);
            }
        }
        self.mms[i].imports = Arc::new(imports);
        Ok(h)
    }
    fn reap(&mut self) {
        if !self.reap.swap(false, Ordering::AcqRel) {
            return;
        }
        let ready: Vec<_> = self
            .retired
            .iter()
            .copied()
            .filter(|page| {
                let f = &self.frames[page];
                f.counts.pins.load(Ordering::Acquire) == 0
                    && f.counts.references.load(Ordering::Acquire) == 0
            })
            .collect();
        self.work.retired_frame_visits += self.retired.len() as u64;
        for page in ready {
            self.retired.remove(&page);
            if !self.frames[&page].imported {
                self.mms[self.frames[&page].owner].free.insert(page);
            }
        }
    }
    fn page(&mut self, i: usize) -> Result<u64, MmError> {
        self.reap();
        if self.mms[i].free.len() < (COMPOUND_BYTES / PAGE_BYTES) as usize {
            self.grant(ExtentKind::Data, Some(i))?;
        }
        let page = self.mms[i].free.pop_first().ok_or(MmError::NoMemory)?;
        let f = &self.frames[&page];
        f.counts.references.store(1, Ordering::Release);
        let extent = f.extent;
        self.callback();
        self.backend
            .write(extent, page - extent.base(), &[0; PAGE_BYTES as usize])?;
        Ok(page)
    }
    fn release_frame(&mut self, page: u64) -> Result<(), MmError> {
        let f = self.frames.get(&page).ok_or(MmError::Stale)?;
        if f.counts.references.load(Ordering::Acquire) == 0 {
            return Err(MmError::Core);
        }
        if f.counts.references.fetch_sub(1, Ordering::AcqRel) == 1 {
            if f.counts.pins.load(Ordering::Acquire) == 0 {
                if !f.imported {
                    self.mms[f.owner].free.insert(page);
                }
            } else {
                self.retired.insert(page);
            }
        }
        Ok(())
    }
    fn mapped_frames(&self, i: usize, range: ReservationRange) -> Vec<(u64, u64)> {
        (range.start()..range.end())
            .step_by(PAGE_BYTES as usize)
            .filter_map(|va| {
                if carrick_mmu_core::aarch64::terminal_descriptor_is_retired(
                    carrick_mmu_core::aarch64::terminal_descriptor(
                        self.mms[i].tables.debug_walk(va),
                    ),
                ) {
                    return None;
                }
                self.mms[i]
                    .tables
                    .try_translate_retained_output(va)
                    .ok()
                    .flatten()
                    .filter(|ipa| self.frames.contains_key(&(ipa & !(PAGE_BYTES - 1))))
                    .map(|ipa| (va, ipa & !(PAGE_BYTES - 1)))
            })
            .collect()
    }
    fn finish(root: &mut Reservations<'_>, decision: Decision) -> Result<(), MmError> {
        if let Decision::Work(request) = decision {
            // SAFETY: only called by the owner after its descriptor transaction
            // and frame reference update commit. Lazy metadata moves zero bytes.
            let completion = unsafe {
                ReservationCompletion::after_descriptor_and_backing_commit(
                    request,
                    ReservationBackingReceipt {
                        receipt: request.sequence.raw(),
                        granted_bytes: 0,
                        returned_bytes: 0,
                    },
                )
            }
            .ok_or(MmError::Core)?;
            root.complete(completion)?;
        }
        Ok(())
    }
    fn transaction(&mut self, i: usize, op: DescriptorOp) -> Result<(), MmError> {
        self.mms[i].transaction_generation = self.mms[i]
            .transaction_generation
            .checked_add(1)
            .ok_or(MmError::Stale)?;
        let id = DescriptorTxnId {
            mm_key: NonZeroU64::new(self.mms[i].handle.mm.raw()).ok_or(MmError::Core)?,
            generation: NonZeroU64::new(self.mms[i].transaction_generation)
                .ok_or(MmError::Stale)?,
        };
        let txn = self.mms[i]
            .tables
            .prepare_guest_descriptor_txn(id, op, None)
            .map_err(|_| MmError::Core)?;
        let receipt = {
            let words = LiveWords {
                tables: &self.mms[i].tables,
                meter: &self.meter,
            };
            execute_descriptor_txn(
                &words,
                SubstrateGpa(self.mms[i].tables.base()),
                &txn,
                &mut InlineJournal::new(),
            )
        };
        self.mms[i]
            .tables
            .settle_guest_descriptor_receipt(&txn, &receipt)
            .map_err(|_| MmError::Core)?;
        if matches!(receipt.outcome, DescriptorOutcome::Applied(_)) {
            Ok(())
        } else {
            Err(MmError::Core)
        }
    }
    fn publish(&mut self, i: usize, va: u64, ipa: u64, writable: bool) -> Result<(), MmError> {
        let extent = self.frames[&ipa].extent;
        let identity = BackingIdentity {
            frame_id: NonZeroU64::new(ipa).ok_or(MmError::Core)?,
            mapping_id: NonZeroU64::new(ipa).ok_or(MmError::Core)?,
            owner_generation: NonZeroU64::new(extent.token()).ok_or(MmError::Core)?,
            inventory_revision: NonZeroU64::new(extent.token()).ok_or(MmError::Core)?,
        };
        self.transaction(
            i,
            DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va,
                    ipa,
                    len: PAGE_BYTES,
                    writable,
                    executable: false,
                },
                resident: PageSpan::new(va, PAGE_BYTES),
                backing: identity,
            },
        )
    }
    fn metadata(&mut self, i: usize, operation: UserTransfer<'_>) -> Result<(), MmError> {
        let mut root = self.root(i)?;
        let decision = match operation {
            UserTransfer::MapLazy { range, protection } => {
                root.mmap(Placement::Fixed(range.start()), range.len(), protection)?
            }
            UserTransfer::Protect { range, protection } => root.mprotect(range, protection)?,
            UserTransfer::Unmap { range } => root.munmap(range)?,
            UserTransfer::Remap {
                source,
                destination,
            } => root.mremap(source, source.len(), MoveTarget::Fixed(destination.raw()))?,
            _ => return Err(MmError::Invalid),
        };
        let visits = root.work as u64;
        drop(root); // Physical callbacks are forbidden while a root guard exists.
        self.work.vma_nodes += visits;
        let result = (|| {
            match operation {
                UserTransfer::MapLazy { range, .. } | UserTransfer::Unmap { range } => {
                    let frames = self.mapped_frames(i, range);
                    let op = self.mms[i]
                        .tables
                        .unmap_aliased_op(range.start(), range.len());
                    self.transaction(i, op)?;
                    for (_, page) in frames {
                        self.release_frame(page)?;
                    }
                }
                UserTransfer::Protect { range, protection } => {
                    let op = if protection.bits() == 0 {
                        PtOp::KernelReadOnly { exec: false }
                    } else if protection.permits(ReservationProtection::READ_WRITE) {
                        PtOp::ReadWrite { exec: false }
                    } else {
                        PtOp::ReadOnly { exec: false }
                    };
                    let op = self.mms[i].tables.terminal_op(
                        range.start(),
                        range.len(),
                        TerminalRule::pt(op),
                    );
                    self.transaction(i, op)?;
                }
                UserTransfer::Remap {
                    source,
                    destination,
                } => {
                    let frames = self.mapped_frames(i, source);
                    let op = self.mms[i]
                        .tables
                        .unmap_aliased_op(source.start(), source.len());
                    self.transaction(i, op)?;
                    let op = self.mms[i]
                        .tables
                        .unmap_aliased_op(destination.raw(), source.len());
                    self.transaction(i, op)?;
                    for (va, ipa) in frames {
                        let target = destination.raw() + va - source.start();
                        self.publish(i, target, ipa, true)?;
                    }
                }
                _ => return Err(MmError::Invalid),
            }
            Ok(())
        })();
        let mut root = self.root(i)?;
        if result.is_ok() {
            Self::finish(&mut root, decision)?;
        } else if let Decision::Work(request) = decision {
            root.refuse(request)?;
        }
        let visits = root.work as u64;
        drop(root);
        self.work.vma_nodes += visits;
        result
    }
    fn cow(&mut self, i: usize, va: u64) -> Result<(), MmError> {
        let run = {
            let words = LiveWords {
                tables: &self.mms[i].tables,
                meter: &self.meter,
            };
            match classify_guest_cow_write(&words, SubstrateGpa(self.mms[i].tables.base()), va) {
                Ok(run) => run,
                Err(GuestCowClass::AlreadyWritable) => return Ok(()),
                Err(_) => return Err(MmError::Fault),
            }
        };
        // The existing classifier chooses the exact contiguous run inside a
        // 16 KiB compound; the backend sees only byte copy spans afterward.
        let mut replacements = Vec::new();
        self.reap();
        let mut candidate = self.mms[i].free.iter().copied().find(|p| {
            p.is_multiple_of(COMPOUND_BYTES)
                && (0..4).all(|n| self.mms[i].free.contains(&(p + n * PAGE_BYTES)))
        });
        if candidate.is_none() {
            self.grant(ExtentKind::Data, Some(i))?;
            candidate = self.mms[i].free.iter().copied().find(|p| {
                p.is_multiple_of(COMPOUND_BYTES)
                    && (0..4).all(|n| self.mms[i].free.contains(&(p + n * PAGE_BYTES)))
            });
        }
        let start = candidate.ok_or(MmError::NoMemory)?;
        for n in 0..4 {
            let p = start + n * PAGE_BYTES;
            self.mms[i].free.remove(&p);
            self.frames[&p]
                .counts
                .references
                .store(1, Ordering::Release);
            replacements.push(p);
        }
        let base = replacements[0];
        if !base.is_multiple_of(COMPOUND_BYTES)
            || replacements
                .iter()
                .enumerate()
                .any(|(n, p)| *p != base + n as u64 * PAGE_BYTES)
        {
            // An actual early-disproof outcome, never a fallback host COW.
            for p in replacements {
                self.release_frame(p)?;
            }
            return Err(MmError::Core);
        }
        let target = base + run.compound_offset();
        let extent = self.frames[&base].extent;
        for off in (0..run.len).step_by(PAGE_BYTES as usize) {
            let old = self.frames[&(run.old_ipa.raw() + off)].extent;
            let mut bytes = [0; PAGE_BYTES as usize];
            self.callback();
            self.backend
                .read(old, run.old_ipa.raw() + off - old.base(), &mut bytes)?;
            self.callback();
            self.backend
                .write(extent, target + off - extent.base(), &bytes)?;
        }
        let words = LiveWords {
            tables: &self.mms[i].tables,
            meter: &self.meter,
        };
        let mut journal = InlineJournal::new();
        let op = DescriptorOp::CowRepoint {
            access: CowRepointAccess::RecordedPrivate,
            va: run.va,
            len: run.len,
            old_ipa: run.old_ipa,
            new_ipa: SubstrateGpa(target),
            backing: BackingIdentity {
                frame_id: NonZeroU64::new(base).ok_or(MmError::Core)?,
                mapping_id: NonZeroU64::new(base).ok_or(MmError::Core)?,
                owner_generation: NonZeroU64::new(extent.token()).ok_or(MmError::Core)?,
                inventory_revision: NonZeroU64::new(extent.token()).ok_or(MmError::Core)?,
            },
        };
        if !matches!(
            execute_descriptor_op(
                &words,
                SubstrateGpa(self.mms[i].tables.base()),
                op,
                &TableGrants::NONE,
                &mut journal
            ),
            DescriptorOutcome::Applied(_)
        ) {
            return Err(MmError::Core);
        }
        for off in (0..run.len).step_by(PAGE_BYTES as usize) {
            self.release_frame(run.old_ipa.raw() + off)?;
        }
        for p in replacements {
            if p < target || p >= target + run.len {
                self.release_frame(p)?;
            }
        }
        Ok(())
    }
    fn chunks(
        &mut self,
        i: usize,
        address: GuestVa,
        len: usize,
        intent: TransferIntent,
        writing: bool,
    ) -> Result<(u64, Vec<Chunk>), MmError> {
        let end = address
            .raw()
            .checked_add(len as u64)
            .ok_or(MmError::Fault)?;
        let mut chunks = Vec::new();
        let mut cursor = address.raw();
        let revision;
        {
            let mut root = self.root(i)?;
            revision = root.generation().raw();
            while cursor < end {
                let internal = intent == TransferIntent::CarrickInternalRead;
                let stop = if internal {
                    if writing || cursor < INTERNAL_VA || end > INTERNAL_VA + PAGE_BYTES {
                        return Err(MmError::Fault);
                    }
                    end
                } else {
                    let m = root.mapping(cursor).ok_or(MmError::Fault)?;
                    let access = if writing {
                        ReservationProtection::READ_WRITE
                    } else {
                        ReservationProtection::from_bits(1).ok_or(MmError::Core)?
                    };
                    let access = if intent == TransferIntent::ReadInstruction {
                        ReservationProtection::from_bits(5).ok_or(MmError::Core)?
                    } else {
                        access
                    };
                    if !m.protection.permits(access) {
                        return Err(MmError::Fault);
                    }
                    m.range.end().min(end)
                };
                if (writing && intent != TransferIntent::UserWrite)
                    || (!writing && intent == TransferIntent::UserWrite)
                {
                    return Err(MmError::Fault);
                }
                // Record VA segments only transiently in owner completion storage.
                let next = ((cursor & !(PAGE_BYTES - 1)) + PAGE_BYTES).min(stop);
                chunks.push(Chunk {
                    page: cursor & !(PAGE_BYTES - 1),
                    extent: None,
                    offset: cursor % PAGE_BYTES,
                    len: (next - cursor) as usize,
                });
                cursor = next;
            }
            let visits = root.work as u64;
            drop(root);
            self.work.vma_nodes += visits;
        }
        for c in &mut chunks {
            let va = c.page;
            let internal = intent == TransferIntent::CarrickInternalRead;
            if !internal && self.mms[i].tables.translate(va).is_none() {
                let page = self.page(i)?;
                self.publish(i, va, page, true)?;
            }
            if writing {
                self.cow(i, va)?;
            }
            let ipa = if internal {
                self.mms[i].tables.translate_retained_output(va)
            } else {
                self.mms[i].tables.translate(va)
            }
            .ok_or(MmError::Fault)?;
            c.page = ipa & !(PAGE_BYTES - 1);
            c.extent = Some(self.frames.get(&c.page).ok_or(MmError::Stale)?.extent);
        }
        Ok((revision, chunks))
    }
    pub fn begin_copyout(
        &mut self,
        h: El1MmHandle,
        address: GuestVa,
        bytes: &[u8],
        intent: TransferIntent,
    ) -> Result<PendingCopy<B::Pin>, MmError> {
        let i = self.index(h)?;
        let (revision, chunks) = self.chunks(i, address, bytes.len(), intent, true)?;
        let mut physical = Vec::new();
        let mut pins = Vec::new();
        let mut seen = BTreeSet::new();
        for c in &chunks {
            let extent = c.extent.ok_or(MmError::Core)?;
            if seen.insert(extent.base()) {
                physical.push(self.pin(extent)?);
            }
            let counts = self.frames[&c.page].counts.clone();
            counts.pins.fetch_add(1, Ordering::AcqRel);
            self.meter.acquires.fetch_add(1, Ordering::Relaxed);
            self.mms[i].pending.fetch_add(1, Ordering::AcqRel);
            pins.push(OwnerPin {
                pending: self.mms[i].pending.clone(),
                counts,
                meter: self.meter.clone(),
                reap: self.reap.clone(),
            });
        }
        Ok(PendingCopy {
            handle: h,
            revision,
            chunks,
            bytes: bytes.to_vec(),
            _physical: physical,
            _pins: pins,
        })
    }
    pub fn complete_copyout(&mut self, pending: PendingCopy<B::Pin>) -> Result<(), MmError> {
        let i = self.index(pending.handle)?;
        let root = self.root(i)?;
        if root.generation().raw() != pending.revision {
            return Err(MmError::Stale);
        }
        drop(root);
        let mut copied = 0;
        for c in &pending.chunks {
            let extent = c.extent.ok_or(MmError::Core)?;
            self.callback();
            self.backend.write(
                extent,
                c.page - extent.base() + c.offset,
                &pending.bytes[copied..copied + c.len],
            )?;
            copied += c.len;
        }
        Ok(()) // pending drop releases pins without any wait.
    }
    /// Physical transfer storage is separate from user data and remains
    /// allocated until the producer settles the exact wire completion.
    pub fn transfer_storage(&mut self) -> Result<ExtentGrant, MmError> {
        self.grant(ExtentKind::TransferStorage, None)
    }

    /// Owner-side decoding of the shared service ABI. Every validation and
    /// translation below executes locally at EL1, not through host callbacks.
    pub fn serve_user_transfer(
        &mut self,
        service: carrick_el1_abi::PortalTransferService<'_>,
    ) -> bool {
        use carrick_el1_abi::PortalTransferIntent as WireIntent;
        let request = service.request();
        let result = (|| {
            let operation = request.operation;
            let handle = El1MmHandle {
                carrier: operation.carrier,
                mm: operation.mm,
                incarnation: operation.incarnation,
            };
            let i = self.index(handle)?;
            if operation.sequence.get() <= self.mms[i].transfer_sequence {
                return Err(MmError::Stale);
            }
            let storage = request.storage();
            let registered = self.extents.get(&storage.base()).ok_or(MmError::Stale)?;
            if registered.grant.extent != storage
                || registered.grant.kind != ExtentKind::TransferStorage
            {
                return Err(MmError::Stale);
            }
            let _storage_pin = self.pin(storage)?;
            self.mms[i].transfer_sequence = operation.sequence.get();
            let mut bytes = owned::vec![0; request.range.len() as usize];
            let address = GuestVa::new(request.range.address());
            if request.intent == WireIntent::UserWrite {
                self.callback();
                self.backend
                    .read(storage, request.storage_offset(), &mut bytes)?;
                self.user_transfer(
                    handle,
                    UserTransfer::CopyOut {
                        address,
                        bytes: &bytes,
                        intent: TransferIntent::UserWrite,
                    },
                )?;
            } else {
                let intent = match request.intent {
                    WireIntent::UserRead => TransferIntent::UserRead,
                    WireIntent::ReadInstruction => TransferIntent::ReadInstruction,
                    WireIntent::CarrickInternalRead => TransferIntent::CarrickInternalRead,
                    WireIntent::UserWrite => return Err(MmError::Invalid),
                };
                self.user_transfer(
                    handle,
                    UserTransfer::CopyIn {
                        address,
                        bytes: &mut bytes,
                        intent,
                    },
                )?;
                self.callback();
                self.backend
                    .write(storage, request.storage_offset(), &bytes)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => service.complete(request.range.len(), 0),
            Err(error) => service.complete(0, error.errno()),
        }
    }

    pub fn user_transfer(
        &mut self,
        h: El1MmHandle,
        operation: UserTransfer<'_>,
    ) -> Result<(), MmError> {
        let i = self.index(h)?;
        match operation {
            UserTransfer::CopyOut {
                address,
                bytes,
                intent,
            } => {
                let pending = self.begin_copyout(h, address, bytes, intent)?;
                self.complete_copyout(pending)
            }
            UserTransfer::CopyIn {
                address,
                bytes,
                intent,
            } => {
                let (_, chunks) = self.chunks(i, address, bytes.len(), intent, false)?;
                let mut copied = 0;
                for c in chunks {
                    let extent = c.extent.ok_or(MmError::Core)?;
                    let _pin = self.pin(extent)?;
                    self.meter.acquires.fetch_add(1, Ordering::Relaxed);
                    self.callback();
                    let result = self.backend.read(
                        extent,
                        c.page - extent.base() + c.offset,
                        &mut bytes[copied..copied + c.len],
                    );
                    self.meter.releases.fetch_add(1, Ordering::Relaxed);
                    result?;
                    copied += c.len;
                }
                Ok(())
            }
            operation => self.metadata(i, operation),
        }
    }
    pub fn capacity(
        &mut self,
        h: El1MmHandle,
        operation: Capacity,
    ) -> Result<CapacityResult, MmError> {
        let i = self.index(h)?;
        self.reap();
        match operation {
            Capacity::Settle => {
                let grants: Vec<_> = self
                    .extents
                    .values()
                    .filter(|e| e.owner == Some(i) && e.grant.kind == ExtentKind::Data)
                    .map(|e| e.grant)
                    .collect();
                let mut retained = false;
                for grant in grants {
                    self.work.capacity_frame_visits += EXTENT_BYTES / PAGE_BYTES;
                    let free = self
                        .frames
                        .range(grant.extent.base()..grant.extent.base() + grant.extent.len())
                        .all(|(_, f)| {
                            f.counts.references.load(Ordering::Acquire) == 0
                                && f.counts.pins.load(Ordering::Acquire) == 0
                        });
                    if free {
                        if retained {
                            self.capacity(h, Capacity::Return(grant))?;
                        } else {
                            retained = true;
                        }
                    }
                }
                Ok(CapacityResult::Returned)
            }
            Capacity::Grant => Ok(CapacityResult::Granted(
                self.grant(ExtentKind::Data, Some(i))?,
            )),
            Capacity::Return(grant) => {
                let e = self
                    .extents
                    .get(&grant.extent.base())
                    .ok_or(MmError::Stale)?;
                if e.grant != grant || e.owner != Some(i) || grant.kind != ExtentKind::Data {
                    return Err(MmError::Stale);
                }
                if self
                    .frames
                    .range(grant.extent.base()..grant.extent.base() + grant.extent.len())
                    .any(|(_, f)| {
                        f.counts.references.load(Ordering::Acquire) != 0
                            || f.counts.pins.load(Ordering::Acquire) != 0
                    })
                {
                    return Err(MmError::Busy);
                }
                self.callback();
                self.backend.return_extent(grant)?;
                for page in (grant.extent.base()..grant.extent.base() + grant.extent.len())
                    .step_by(PAGE_BYTES as usize)
                {
                    self.mms[i].free.remove(&page);
                    self.frames.remove(&page);
                    self.retired.remove(&page);
                }
                self.extents.remove(&grant.extent.base());
                self.work.capacity_returns += 1;
                Ok(CapacityResult::Returned)
            }
        }
    }
    pub fn fork(&mut self, h: El1MmHandle) -> Result<UnpublishedEl1Child, MmError> {
        let parent = self.index(h)?;
        if self.mms[parent].pending.load(Ordering::Acquire) != 0 {
            return Err(MmError::Busy);
        }
        let child = self.mms.len();
        let mm = ReservationMm::new(child as u64 + 1).ok_or(MmError::Invalid)?;
        let handle = El1MmHandle {
            carrier: self.carrier,
            mm,
            incarnation: NonZeroU64::new(child as u64 + 1).ok_or(MmError::Invalid)?,
        };
        let layout = self.root(parent)?.layout();
        self.table.publish(child, mm, layout)?;
        // Physical capacity is secured before either root is locked.
        let grant = self.grant(ExtentKind::Tables, None)?;
        let resolver: Arc<dyn HostArenaResolver + Send + Sync> = Arc::new(TableAlias {
            pin: self.pin(grant.extent)?,
            meter: self.meter.clone(),
        });
        let mut ranges = Vec::new();
        let mut root = self.root(parent)?;
        root.observe_nodes(layout.arena, &mut |m, _| ranges.push((m.range, m.flags)))?;
        let mut child_root = self.table.lock_el1_resolved(child, mm, &self.nodes, 0)?;
        root.clone_into(&mut child_root)?;
        let visits = root.work as u64 + child_root.work as u64;
        drop(child_root);
        drop(root);
        self.work.vma_nodes += visits;
        // This snapshot is made by the EL1 owner from its live tables. There
        // is no host VMA/refcount input or host exclusion/pause capability.
        for (range, flags) in &ranges {
            if !flags.contains(ReservationNodeFlags::PRIVATE) {
                continue;
            }
            let op = self.mms[parent].tables.fork_arm_op(
                range.start(),
                range.len(),
                false,
                false,
                false,
            );
            self.transaction(parent, op)?;
        }
        self.work.fork_copied_words += self.mms[parent].tables.copied_bytes() / 8;
        let mut tables = self.mms[parent].tables.snapshot_image()?;
        tables.rebase(grant.extent.base(), None)?;
        unsafe {
            tables.restore_quiesced_snapshot_to_host(&resolver)?;
            tables.make_live(resolver);
        }
        tables.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        let internal = self.mms[parent].internal;
        for (range, _) in ranges {
            for (_, page) in self.mapped_frames(parent, range) {
                self.frames[&page]
                    .counts
                    .references
                    .fetch_add(1, Ordering::AcqRel);
            }
        }
        self.frames[&internal]
            .counts
            .references
            .fetch_add(1, Ordering::AcqRel);
        self.mms.push(Mm {
            transaction_generation: 0,
            pending: Arc::new(AtomicU64::new(0)),
            handle,
            tables,
            free: BTreeSet::new(),
            internal,
            imports: self.mms[parent].imports.clone(),
            transfer_sequence: 0,
        });
        Ok(UnpublishedEl1Child { handle })
    }
    /// Immutable owner observation, not a host projection or mutable VMA.
    pub fn references(&self) -> (u64, u64) {
        self.frames.values().fold((0, 0), |(r, p), f| {
            (
                r + f.counts.references.load(Ordering::Acquire),
                p + f.counts.pins.load(Ordering::Acquire),
            )
        })
    }
}

#[cfg(test)]
mod tests;
