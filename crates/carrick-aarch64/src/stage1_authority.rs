//! Stage-1 page-table and arena-source authority type.
//!
//! Encapsulates ownership of stage-1 page-table translation tables (`PageTableManager`),
//! the extension arena source (`TableArenaSource`), and the fork/vfork sharing state
//! (`ShareState`). Eliminates loose `Arc<Mutex<Option<PageTableManager>>>` heuristics
//! and prevents arena-source leaks across clone, rollback, and execve transitions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use carrick_hal::TrapError;
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOp, DescriptorReceipt, DescriptorTxn, DescriptorTxnId, VerifiedDescriptorReceipt,
};
use carrick_mmu_core::aarch64::{
    GuestLaneRefusal, GuestTxnPrepareError, GuestTxnSettleError, HostArenaResolver,
    LiveDescriptorOwner, PageTableApplyOutcome, PageTableError, PageTableManager, PtOp,
    TableArenaSource, TerminalRule, UserLeafAccess,
};

/// Explicit sharing lifecycle for stage-1 page tables across process fork/execve boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareState {
    /// Sole owner of this stage-1 authority. Edits, coalescing, extension retirements,
    /// and exec replacements are solely owned by this task or its CLONE_THREAD siblings.
    Exclusive,
    /// Shared with an in-flight `CLONE_VM` / `vfork` child awaiting its `execve` or `_exit`.
    /// The parent's live tables, extension arenas, and arena source must not be stolen or retired.
    SharedWithVforkChild,
}

/// All mutable access to the software image advances this generation before
/// exposing the manager. Failed edits and rollbacks invalidate too. Exhaustion
/// permanently disables reuse; it never wraps to an older valid generation.
struct TrackedStage1Image {
    image: Option<PageTableManager>,
    generation: Option<std::num::NonZeroU64>,
}
impl std::ops::Deref for TrackedStage1Image {
    type Target = Option<PageTableManager>;
    fn deref(&self) -> &Self::Target {
        &self.image
    }
}
impl std::ops::DerefMut for TrackedStage1Image {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.generation = self
            .generation
            .and_then(|g| g.get().checked_add(1))
            .and_then(std::num::NonZeroU64::new);
        &mut self.image
    }
}

/// The backend venue that makes a newly grown extension arena usable by both
/// venues before any descriptor names it: its stage-2 backing and owner
/// (exactly what the host editor publishes after an edit that grew one).
pub trait TableArenaPublisher: Send + Sync {
    /// Publish every extension arena of `manager` the backend does not hold
    /// yet. An error leaves the arenas unpublished.
    fn publish_extension_arenas(&self, manager: &PageTableManager) -> Result<(), String>;
    /// Publish physical capacity before the owner chooses any descriptors.
    fn publish_raw_fork_arena(&self, _base: u64) -> Result<(), String> {
        Err("raw Fork table capacity is unavailable".into())
    }
    /// Release unused capacity after the owner's exact abort/unused receipt.
    fn retire_raw_fork_arena(&self, _base: u64) -> Result<(), String> {
        Err("raw Fork table capacity retirement is unavailable".into())
    }
}

struct Stage1AuthorityInner {
    manager: TrackedStage1Image,
    arena_source: Option<Box<dyn TableArenaSource>>,
    /// Publishes extension arenas a guest descriptor transaction grows into.
    arena_publisher: Option<Arc<dyn TableArenaPublisher>>,
    /// Extension arenas the publisher accepted. An arena the image holds
    /// but this set lacks (its publication was refused) is published again
    /// before any guest transaction is returned.
    published_arenas: Vec<u64>,
    host_resolver: Option<Arc<dyn HostArenaResolver + Send + Sync>>,
    vfork_shares: usize,
    engines: usize,
    /// Recycle pool shared by this authority and every child authority it
    /// forks. The retiring image of an exited process returns here on drop.
    image_pool: Arc<Stage1ImagePool>,
    /// The only venue allowed to store into this authority's live tables.
    /// Every image lent for editing carries it, whichever path installed it.
    live_owner: LiveDescriptorOwner,
    /// Last guest descriptor transaction generation issued for this MM.
    txn_generation: u64,
    /// The guest lane was admitted for this MM before its live backing was
    /// bound; `bind_live_backing` completes the selection.
    guest_lane_pending: bool,
}

impl Drop for Stage1AuthorityInner {
    fn drop(&mut self) {
        if let Some(image) = self.manager.take() {
            self.image_pool.recycle(image);
        }
    }
}

/// Bounded recycle pool for retired stage-1 software images.
///
/// A forked child owns a private `PageTableManager` image (one 1.75 MiB arena
/// set plus any extension arenas) for its whole lifetime. Dropping it on exit
/// and allocating a fresh one on the next fork turned a 16k-child fork storm
/// (`ltp-fork14`) into ~28 GiB of host `mmap`/`madvise(MADV_FREE_REUSABLE)`
/// churn. Retired images return here and the next fork clones the parent into
/// a recycled buffer with `clone_from`, so steady-state image allocations are
/// bounded by the number of concurrently live child images, never by fork
/// count (`kernel.fork.stage1-image`).
///
/// The pool travels with the authority: a child authority inherits its
/// parent's pool; an authority built for an exec'd image starts a fresh one.
/// Buffers are content-agnostic host heap; the clone overwrites every
/// descriptor word and scalar, so a recycled image is indistinguishable from
/// a fresh clone.
pub struct Stage1ImagePool {
    images: Mutex<Vec<PageTableManager>>,
    capacity: usize,
    fresh_allocations: AtomicU64,
    recycled_images: AtomicU64,
}

impl std::fmt::Debug for Stage1ImagePool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stage1ImagePool")
            .field("retained", &self.retained())
            .field("capacity", &self.capacity)
            .field("fresh_allocations", &self.fresh_allocations())
            .field("recycled_images", &self.recycled_images())
            .finish()
    }
}

impl Stage1ImagePool {
    /// Retained images per process tree. A serial fork/exit/wait loop keeps at
    /// most one child image live plus one in teardown; the headroom covers a
    /// few concurrently exiting children without pinning unbounded memory.
    pub const DEFAULT_CAPACITY: usize = 4;

    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            images: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
            fresh_allocations: AtomicU64::new(0),
            recycled_images: AtomicU64::new(0),
        })
    }

    /// Take a retired image buffer, if one is retained.
    pub fn take(&self) -> Option<PageTableManager> {
        self.images.lock().pop()
    }

    /// Return a retired image. Beyond `capacity` the image is dropped.
    pub fn recycle(&self, image: PageTableManager) {
        let mut images = self.images.lock();
        if images.len() < self.capacity {
            images.push(image);
            self.recycled_images.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_fresh_allocation(&self) {
        self.fresh_allocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Images currently retained for reuse.
    pub fn retained(&self) -> usize {
        self.images.lock().len()
    }

    /// Fresh image allocations performed because no retired image was
    /// available.
    pub fn fresh_allocations(&self) -> u64 {
        self.fresh_allocations.load(Ordering::Relaxed)
    }

    /// Images returned to the pool over its lifetime.
    pub fn recycled_images(&self) -> u64 {
        self.recycled_images.load(Ordering::Relaxed)
    }
}

/// The concrete Rust type governing stage-1 page-table translation and arena growth.
///
/// An `Arc`-wrapped handle to the stage-1 inner state, safe to clone across
/// `CLONE_THREAD` sibling threads while guaranteeing zero `Arc::strong_count` heuristics
/// on fork, rollback, or execve.
#[derive(Clone)]
pub struct Stage1Authority {
    inner: Arc<Mutex<Stage1AuthorityInner>>,
}

impl Default for Stage1Authority {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Stage1Authority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("Stage1Authority")
            .field("authority_id", &self.authority_id())
            .field("has_manager", &inner.manager.is_some())
            .field("has_source", &inner.arena_source.is_some())
            .field("share_state", &self.share_state())
            .field("vfork_shares", &inner.vfork_shares)
            .field("engines", &inner.engines)
            .finish()
    }
}

impl Stage1Authority {
    /// Create a new, unpopulated stage-1 authority in the `Exclusive` state.
    pub fn new() -> Self {
        Self::new_with_manager(None)
    }

    /// Create a stage-1 authority pre-populated with an optional manager in the `Exclusive` state.
    ///
    /// The authority starts its own [`Stage1ImagePool`]; fork children created
    /// through [`Self::child_with_manager`] share it.
    pub fn new_with_manager(manager: Option<PageTableManager>) -> Self {
        Self::with_pool(
            manager,
            Stage1ImagePool::new(Stage1ImagePool::DEFAULT_CAPACITY),
        )
    }

    fn with_pool(manager: Option<PageTableManager>, image_pool: Arc<Stage1ImagePool>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Stage1AuthorityInner {
                manager: TrackedStage1Image {
                    image: manager,
                    generation: std::num::NonZeroU64::new(1),
                },
                arena_source: None,
                arena_publisher: None,
                published_arenas: Vec::new(),
                host_resolver: None,
                vfork_shares: 0,
                engines: 1,
                image_pool,
                live_owner: LiveDescriptorOwner::Host,
                txn_generation: 0,
                guest_lane_pending: false,
            })),
        }
    }

    /// Bind a live host arena resolver, making hardware-visible backing authoritative.
    ///
    /// # Safety
    /// `resolver` must uphold the safety contracts of `HostArenaResolver`.
    ///
    /// Returns `true` when this binding completed a guest lane selection
    /// that was admitted before the backing existed.
    pub unsafe fn bind_live_backing(
        &self,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
    ) -> bool {
        // SAFETY: forwarded caller contract.
        unsafe { self.bind_live_backing_with_promotion(resolver, true) }
    }

    /// Bind backing without completing a deferred guest selection. The
    /// production MM state uses this until its exact pending user-memory
    /// owner can be consumed in the same admission transaction.
    ///
    /// # Safety
    /// `resolver` must be authenticated for this authority's arenas.
    pub unsafe fn bind_live_backing_without_promotion(
        &self,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
    ) {
        // SAFETY: forwarded caller contract.
        unsafe { self.bind_live_backing_with_promotion(resolver, false) };
    }

    unsafe fn bind_live_backing_with_promotion(
        &self,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
        permit_promotion: bool,
    ) -> bool {
        let mut inner = self.inner.lock();
        inner.host_resolver = Some(Arc::clone(&resolver));
        // Making the manager live discards its owned descriptor copy. Host
        // edits not yet synced (still host-owned here) are first published
        // to the backing that becomes authoritative; a manager that cannot
        // publish them keeps them and the selection stays pending.
        let host_owned = inner.live_owner == LiveDescriptorOwner::Host;
        let synced = match inner.manager.as_mut() {
            Some(manager) if host_owned && manager.has_unsynced_edits() => {
                // SAFETY: the caller authenticated `resolver` for this
                // authority's arenas (this function's contract).
                unsafe { manager.sync_to_host(&resolver) }.is_ok()
            }
            _ => true,
        };
        let promote = permit_promotion
            && synced
            && inner.guest_lane_pending
            && inner.live_owner == LiveDescriptorOwner::Host
            && inner
                .manager
                .as_ref()
                .is_none_or(|manager| !manager.has_unsynced_edits());
        if let Some(manager) = inner.manager.as_mut() {
            if !synced {
                return false;
            }
            unsafe { manager.make_live(resolver) };
            if promote {
                manager.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
            }
        }
        if promote {
            inner.live_owner = LiveDescriptorOwner::Guest;
            inner.guest_lane_pending = false;
        }
        promote
    }

    /// Why this authority is on the host lane right now, or `None` when EL1
    /// owns its live descriptors. Pure observation, no state changes.
    pub fn host_lane_cause(&self) -> Option<HostLaneCause> {
        let inner = self.inner.lock();
        if inner.live_owner == LiveDescriptorOwner::Guest {
            return None;
        }
        Some(if !inner.guest_lane_pending {
            HostLaneCause::NeverSelected
        } else if inner.host_resolver.is_none() {
            HostLaneCause::PendingNoBacking
        } else if inner.manager.is_none() {
            HostLaneCause::PendingNoManager
        } else if inner
            .manager
            .as_ref()
            .is_some_and(|manager| manager.has_unsynced_edits())
        {
            HostLaneCause::PendingUnsyncedEdits
        } else {
            HostLaneCause::PendingAwaitingBind
        })
    }

    /// Record the live backing WITHOUT making the manager live: the
    /// authority keeps editing its owned copy on the host lane, and a guest
    /// lane selection (immediate now, since the backing is known) makes it
    /// live at that point. A selection already pending completes here,
    /// exactly as [`Self::bind_live_backing`] would. Returns whether it did.
    ///
    /// # Safety
    /// `resolver` must uphold the safety contracts of `HostArenaResolver`.
    pub unsafe fn record_live_backing(
        &self,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
    ) -> bool {
        let pending = {
            let mut inner = self.inner.lock();
            inner.host_resolver = Some(Arc::clone(&resolver));
            inner.guest_lane_pending && inner.live_owner == LiveDescriptorOwner::Host
        };
        // SAFETY: forwarded contract.
        pending && unsafe { self.bind_live_backing(resolver) }
    }

    /// Record backing while preserving a pending guest selection until the
    /// shared MM owner guard can authenticate and commit it.
    ///
    /// # Safety
    /// `resolver` must be authenticated for this authority's arenas.
    pub unsafe fn record_live_backing_without_promotion(
        &self,
        resolver: Arc<dyn HostArenaResolver + Send + Sync>,
    ) {
        self.inner.lock().host_resolver = Some(resolver);
    }

    /// Create the `Exclusive` authority of a forked child around its private
    /// image. The child shares this authority's image pool, so its image
    /// returns to the parent's pool when the child retires.
    pub fn child_with_manager(&self, manager: PageTableManager) -> Self {
        let (image_pool, live_owner, pending) = {
            let inner = self.inner.lock();
            (
                Arc::clone(&inner.image_pool),
                inner.live_owner,
                inner.guest_lane_pending,
            )
        };
        let child = Self::with_pool(Some(manager), image_pool);
        // The child's image was built and published offline; once live, it
        // belongs to the same lane as its parent, including a parent whose
        // guest selection still awaits its live backing.
        child.select_live_descriptor_owner(live_owner);
        child.inner.lock().guest_lane_pending = pending;
        child
    }

    /// The image recycle pool shared across this authority's process tree.
    pub fn image_pool(&self) -> Arc<Stage1ImagePool> {
        Arc::clone(&self.inner.lock().image_pool)
    }

    /// Select the venue that owns this address space's live descriptor stores.
    ///
    /// `Guest` is the lane on which EL1 is the only live writer: host edits
    /// through this authority may still stage and validate, but every live
    /// store (`sync_to_host`, snapshot restore, published rollback) is refused
    /// with [`PageTableError::GuestOwnsLiveDescriptors`], and live work must
    /// be built with [`Self::prepare_guest_descriptor_txn`] and submitted to
    /// EL1. Offline images (a fork child before publication, an exec image
    /// before installation) are separate authorities and are not affected.
    pub fn select_live_descriptor_owner(&self, owner: LiveDescriptorOwner) {
        let mut inner = self.inner.lock();
        inner.live_owner = owner;
        if let Some(manager) = inner.manager.as_mut() {
            manager.set_live_descriptor_owner(owner);
        }
    }

    /// Select the guest-owned lane only when EL1 can edit the exact tables
    /// the host reads: the authority must hold a live host resolver, and an
    /// installed manager is made live on it, so every host walk and every
    /// transaction plan reads the hardware-visible descriptors EL1 edits
    /// rather than an owned copy last synced by a host edit. Without a
    /// resolver, or with host edits not yet synced, the lane is refused and
    /// stays host-owned.
    pub fn select_guest_descriptor_owner(&self) -> Result<GuestLaneSelection, GuestLaneRefusal> {
        let mut inner = self.inner.lock();
        if inner.live_owner == LiveDescriptorOwner::Guest {
            return Ok(GuestLaneSelection::Selected);
        }
        let Some(resolver) = inner.host_resolver.clone() else {
            // Admitted before the MM's live backing exists (an initial
            // runner prepared on a handoff engine): `bind_live_backing`
            // completes the selection once EL1 and the host share tables.
            inner.guest_lane_pending = true;
            return Ok(GuestLaneSelection::Deferred);
        };
        if let Some(manager) = inner.manager.as_mut() {
            if manager.has_unsynced_edits() {
                // Never discard a host edit that has not reached hardware.
                return Err(GuestLaneRefusal::UnsyncedEdits);
            }
            if !manager.is_live() {
                // SAFETY: the resolver was bound through `bind_live_backing`,
                // whose caller authenticated it for this authority's arenas.
                unsafe { manager.make_live(resolver) };
            }
            manager.set_live_descriptor_owner(LiveDescriptorOwner::Guest);
        }
        inner.live_owner = LiveDescriptorOwner::Guest;
        Ok(GuestLaneSelection::Selected)
    }

    /// Install the backend publisher for extension arenas a guest descriptor
    /// transaction grows into (see [`TableArenaPublisher`]).
    pub fn set_arena_publisher(&self, publisher: Arc<dyn TableArenaPublisher>) {
        self.inner.lock().arena_publisher = Some(publisher);
    }

    /// The venue that owns this address space's live descriptor stores.
    pub fn live_descriptor_owner(&self) -> LiveDescriptorOwner {
        self.inner.lock().live_owner
    }

    /// Build one guest descriptor transaction for `mm_key` on the guest-owned
    /// lane: a fresh nonzero generation for this authority, the live root,
    /// and exactly the primary-arena table grants the operation needs. No
    /// live descriptor is stored.
    pub fn prepare_guest_descriptor_txn(
        &self,
        mm_key: std::num::NonZeroU64,
        op: DescriptorOp,
    ) -> Result<DescriptorTxn, GuestTxnPrepareError> {
        let mut inner = self.inner.lock();
        if inner.live_owner != LiveDescriptorOwner::Guest {
            return Err(GuestTxnPrepareError::NotGuestOwned);
        }
        let generation = inner
            .txn_generation
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or(GuestTxnPrepareError::Manager(PageTableError::BadAddress))?;
        let live_owner = inner.live_owner;
        let inner_ref = &mut *inner;
        let manager = inner_ref
            .manager
            .as_mut()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        manager.set_live_descriptor_owner(live_owner);
        // The guest lane grows into extension arenas exactly as the host
        // editor does; EL1 reaches every arena through its table view.
        let source: Option<&mut dyn TableArenaSource> = match inner_ref.arena_source.as_mut() {
            Some(source) => Some(source.as_mut()),
            None => None,
        };
        let txn = manager.prepare_guest_descriptor_txn(
            DescriptorTxnId { mm_key, generation },
            op,
            source,
        )?;
        // A grant from a grown arena is usable only once its backing and
        // owner are published, before EL1 can touch it. An arena whose
        // publication was refused stays in the image, so membership, not
        // growth during this call, decides.
        let arenas = manager.extension_arena_bases();
        if let Some(&unpublished) = arenas
            .iter()
            .find(|base| !inner_ref.published_arenas.contains(base))
        {
            let published = inner_ref
                .arena_publisher
                .as_ref()
                .is_some_and(|publisher| publisher.publish_extension_arenas(manager).is_ok());
            if !published {
                let _ = manager.abandon_guest_descriptor_txn(&txn);
                return Err(GuestTxnPrepareError::Manager(
                    PageTableError::UnresolvedArena(unpublished),
                ));
            }
            inner_ref.published_arenas = arenas;
        }
        inner.txn_generation = generation.get();
        Ok(txn)
    }

    /// Execute a prepared guest transaction with the host as the MM's
    /// editor: EL1's journaled executor and receipt, no drain call. Only a
    /// holder of the MM's EL1 editor exclusion on this thread can name
    /// `excluded`; an exclusion of another MM is refused. The caller
    /// performs the ASID invalidation the receipt requires before settling
    /// it ([`Self::settle_guest_descriptor_receipt`]).
    pub fn execute_guest_descriptor_txn_as_host<M>(
        &self,
        txn: &DescriptorTxn,
        excluded: &carrick_hal::el1_editor_exclusion::El1EditorExcluded,
        maintenance: &M,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt, GuestTxnPrepareError>
    where
        M: carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance + ?Sized,
    {
        if excluded.mm() != txn.id.mm_key.get() {
            return Err(GuestTxnPrepareError::Manager(
                PageTableError::GuestOwnsLiveDescriptors,
            ));
        }
        let inner = self.inner.lock();
        let manager = inner
            .manager
            .as_ref()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        // SAFETY: `excluded` proves this thread holds the exact MM's EL1
        // editor exclusion for at least the duration of this call.
        unsafe { manager.execute_guest_descriptor_txn_as_host(txn, maintenance) }
    }

    /// Apply every submission already waiting for `excluded`'s MM, in
    /// submission order, with the host as the editor, as EL1's drain would
    /// (each receipt is left in its slot for its owner to settle). `false`
    /// without applying anything when one of them must be EL1's: a COW
    /// repoint (EL1 copies its page) or a submission mid-application.
    pub fn apply_submitted_as_host<M>(
        &self,
        slots: &carrick_el1_abi::DescriptorTxnSlots,
        excluded: &carrick_hal::el1_editor_exclusion::El1EditorExcluded,
        maintenance: &M,
        invalidate_asid: &dyn Fn(),
    ) -> Result<bool, GuestTxnPrepareError>
    where
        M: carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance + ?Sized,
    {
        let mm = excluded.mm();
        if slots
            .as_slice()
            .iter()
            .any(|slot| slot.applying_for(mm) || slot.submitted_cow_repoint_for(mm))
        {
            return Ok(false);
        }
        let inner = self.inner.lock();
        let manager = inner
            .manager
            .as_ref()
            .ok_or(GuestTxnPrepareError::NotLive)?;
        for slot in slots.submitted_in_order(mm) {
            // SAFETY: `excluded` proves this thread holds the exact MM's EL1
            // editor exclusion for at least the duration of this call.
            unsafe {
                manager.apply_submitted_descriptor_txn_as_host(slot, mm, maintenance, || {
                    invalidate_asid();
                })?;
            }
        }
        Ok(true)
    }

    /// Authenticate EL1's receipt for a transaction built by
    /// [`Self::prepare_guest_descriptor_txn`] and return its unused grants.
    /// Backing adapters require the returned receipt before committing
    /// residency, repointing inventory or retiring an old owner.
    pub fn settle_guest_descriptor_receipt(
        &self,
        txn: &DescriptorTxn,
        receipt: &DescriptorReceipt,
    ) -> Result<VerifiedDescriptorReceipt, GuestTxnSettleError> {
        let mut inner = self.inner.lock();
        let manager = inner
            .manager
            .as_mut()
            .ok_or(GuestTxnSettleError::Manager(PageTableError::BadAddress))?;
        manager.settle_guest_descriptor_receipt(txn, receipt)
    }

    /// Return every grant of a submission withdrawn before EL1 claimed it.
    pub fn abandon_guest_descriptor_txn(&self, txn: &DescriptorTxn) -> Result<(), PageTableError> {
        let mut inner = self.inner.lock();
        let manager = inner.manager.as_mut().ok_or(PageTableError::BadAddress)?;
        manager.abandon_guest_descriptor_txn(txn)
    }

    /// Replace or update the inner manager directly. Used primarily for test harnesses and initialization.
    pub fn replace_manager(&self, manager: Option<PageTableManager>) -> Option<PageTableManager> {
        let mut inner = self.inner.lock();
        std::mem::replace(&mut *inner.manager, manager)
    }

    /// Set the inner manager directly. Used primarily for test harnesses.
    pub fn set_manager(&self, manager: PageTableManager) {
        let mut inner = self.inner.lock();
        *inner.manager = Some(manager);
    }

    /// Number of active execution engines sharing this stage-1 authority.
    pub fn engines(&self) -> usize {
        self.inner.lock().engines
    }

    /// Register an additional sibling engine sharing this stage-1 authority.
    pub fn increment_engine_count(&self) {
        self.inner.lock().engines += 1;
    }

    /// Unregister an engine when a sibling terminates.
    pub fn decrement_engine_count(&self) {
        let mut inner = self.inner.lock();
        inner.engines = inner.engines.saturating_sub(1);
    }

    /// Numerical authority identity (pointer address of the shared inner representation).
    pub fn authority_id(&self) -> u64 {
        Arc::as_ptr(&self.inner) as usize as u64
    }

    /// True if `self` and `other` point to the exact same inner authority.
    pub fn shares_exact_authority(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// True if a `PageTableManager` has been built and is currently present.
    pub fn is_present(&self) -> bool {
        self.inner.lock().manager.is_some()
    }

    /// True if the `PageTableManager` is currently absent (not yet built).
    pub fn is_none(&self) -> bool {
        self.inner.lock().manager.is_none()
    }

    /// True if an extension arena source is installed.
    pub fn has_source(&self) -> bool {
        self.inner.lock().arena_source.is_some()
    }

    /// Current share state (`Exclusive` vs `SharedWithVforkChild`).
    pub fn share_state(&self) -> ShareState {
        if self.inner.lock().vfork_shares > 0 {
            ShareState::SharedWithVforkChild
        } else {
            ShareState::Exclusive
        }
    }

    /// True if solely owned (`Exclusive`).
    pub fn is_exclusive(&self) -> bool {
        self.inner.lock().vfork_shares == 0
    }

    /// True if currently shared with an in-flight `CLONE_VM` / `vfork` child.
    pub fn is_shared_with_vfork_child(&self) -> bool {
        self.inner.lock().vfork_shares > 0
    }

    /// Mark this authority as shared with a newly created `vfork` child.
    pub fn share_with_vfork_child(&self) {
        self.inner.lock().vfork_shares += 1;
    }

    /// Explicit release when the `vfork` child completes `execve` or `_exit`.
    pub fn child_exec_or_exit_released(&self) {
        let mut inner = self.inner.lock();
        inner.vfork_shares = inner.vfork_shares.saturating_sub(1);
    }

    /// Pool statistics: `(in_use, free, capacity, arenas)`.
    pub fn pool_stats(&self) -> Option<(u32, u32, u32, u32)> {
        self.inner.lock().manager.as_ref().map(|m| m.pool_stats())
    }

    /// Base guest-physical address of the stage-1 translation table root.
    pub fn root_base(&self) -> Option<u64> {
        self.inner.lock().manager.as_ref().map(|m| m.base())
    }

    /// Snapshot the current `PageTableManager` image (if present) for rollback.
    /// Extension arenas are cloned, but the `TableArenaSource` remains exclusively
    /// owned by this `Stage1Authority`.
    pub fn snapshot_image(&self) -> Option<PageTableManager> {
        let guard = self.inner.lock();
        let source = guard.manager.as_ref()?;
        source.snapshot_image().ok()
    }

    /// Snapshot the current image into a recycled buffer when the pool holds
    /// one, cloning fresh otherwise. Returns the image and whether a fresh
    /// host allocation was needed (`true` = fresh). A recycled image is
    /// overwritten via `snapshot_into`, so its contents equal [`Self::snapshot_image`].
    pub fn snapshot_image_recycled(&self) -> Option<(PageTableManager, bool)> {
        let guard = self.inner.lock();
        let source = guard.manager.as_ref()?;
        match guard.image_pool.take() {
            Some(mut image) => match source.snapshot_into(&mut image) {
                Ok(()) => Some((image, false)),
                Err(_) => {
                    let snap = source.snapshot_image().ok()?;
                    Some((snap, true))
                }
            },
            None => {
                let snap = source.snapshot_image().ok()?;
                guard.image_pool.record_fresh_allocation();
                Some((snap, true))
            }
        }
    }

    /// Execute a closure with a reference to the inner `PageTableManager`, if present.
    pub fn with_manager<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&PageTableManager) -> R,
    {
        self.inner.lock().manager.as_ref().map(f)
    }

    /// Exclude descriptor access while retiring its physical backing.
    ///
    /// Unlike `with_manager`, the callback also runs when no image is installed:
    /// abandoned publication may still own backing that needs retirement. The
    /// callback must not re-enter this authority.
    pub fn with_retirement_exclusion<R>(
        &self,
        f: impl FnOnce(Option<&PageTableManager>) -> R,
    ) -> R {
        let inner = self.inner.lock();
        f(inner.manager.as_ref())
    }

    /// Run terminal backing retirement while excluding descriptor access,
    /// then revoke this authority's software image before the backing can be
    /// recycled. On error the authority remains intact for rollback/retry.
    pub fn retire_with_exclusion<R, E>(
        &self,
        f: impl FnOnce(Option<&PageTableManager>) -> Result<R, E>,
    ) -> Result<R, E> {
        let (result, image, source) = {
            let mut inner = self.inner.lock();
            let result = f(inner.manager.as_ref())?;
            let image = inner.manager.take();
            let source = inner.arena_source.take();
            inner.host_resolver = None;
            inner.published_arenas.clear();
            (result, image, source)
        };
        if let Some(image) = image {
            self.inner.lock().image_pool.recycle(image);
        }
        drop(source);
        Ok(result)
    }

    /// Execute a closure with a reference to the inner `PageTableManager` if acquired before deadline.
    pub fn try_with_manager_until<F, R, E>(
        &self,
        deadline: std::time::Instant,
        on_timeout: E,
        on_absent: E,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&PageTableManager) -> Result<R, E>,
    {
        let guard = self.inner.try_lock_until(deadline).ok_or(on_timeout)?;
        let manager = guard.manager.as_ref().ok_or(on_absent)?;
        f(manager)
    }

    /// Observe the exact image and its mutation generation under one lock.
    /// A generation has meaning only with this retained authority's identity.
    /// `None` disables reuse after generation exhaustion. The callback cannot
    /// mutate the image or retain a reference beyond this lock.
    pub fn try_with_manager_generation_until<F, R, E>(
        &self,
        deadline: std::time::Instant,
        on_timeout: E,
        on_absent: E,
        f: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&PageTableManager, Option<std::num::NonZeroU64>) -> Result<R, E>,
    {
        let guard = self.inner.try_lock_until(deadline).ok_or(on_timeout)?;
        let manager = guard.manager.as_ref().ok_or(on_absent)?;
        f(manager, guard.manager.generation)
    }

    /// Discard the open undo journal, committing all edits in the current transaction.
    pub fn commit_undo(&self) {
        if let Some(manager) = self.inner.lock().manager.as_mut() {
            manager.commit_undo();
        }
    }

    /// Revert uncommitted page table edits recorded in the undo journal to shadow and host memory.
    ///
    /// # Safety
    ///
    /// `resolver` must return valid host pointers for all touched page table arenas.
    pub unsafe fn rollback_undo(
        &self,
        resolver: impl HostArenaResolver,
    ) -> Result<Vec<u64>, PageTableError> {
        let mut inner = self.inner.lock();
        let inner = &mut *inner;
        let live_owner = inner.live_owner;
        if let Some(manager) = inner.manager.as_mut() {
            manager.set_live_descriptor_owner(live_owner);
            unsafe { manager.rollback_undo(resolver, inner.arena_source.as_deref_mut()) }
        } else {
            Ok(Vec::new())
        }
    }

    /// Perform a scoped, locked edit over the stage-1 page tables if acquired before `deadline`.
    ///
    /// If the `PageTableManager` is not yet present, lazily constructs it using `builder()`.
    #[allow(clippy::expect_used)]
    pub fn try_edit_until<B, F, R, E>(
        &self,
        deadline: std::time::Instant,
        on_timeout: E,
        on_absent: E,
        builder: B,
        f: F,
    ) -> Result<R, E>
    where
        B: FnOnce() -> Result<PageTableManager, E>,
        F: FnOnce(&mut Stage1Editor<'_>) -> Result<R, E>,
    {
        let authority = self.authority_id();
        let mut inner = self.inner.try_lock_until(deadline).ok_or(on_timeout)?;
        if inner.manager.is_none() {
            let mut manager = builder()?;
            if let Some(ref resolver) = inner.host_resolver {
                unsafe { manager.make_live(Arc::clone(resolver)) };
            }
            let had_source = inner.arena_source.is_some();
            carrick_observability::probes::stage1_arena_install(
                4,
                u32::from(had_source),
                0,
                authority,
            );
            *inner.manager = Some(manager);
        }
        let Stage1AuthorityInner {
            ref mut manager,
            ref mut arena_source,
            live_owner,
            ..
        } = *inner;
        let manager = manager.as_mut().ok_or(on_absent)?;
        manager.declare_live_hardware_image();
        manager.set_live_descriptor_owner(live_owner);
        let mut editor = Stage1Editor {
            manager,
            arena_source,
        };
        f(&mut editor)
    }

    /// Reserve physically published, unlinked table capacity for owner Fork.
    /// This method neither observes nor edits the MM's descriptor graph.
    pub fn reserve_owner_fork_arena(&self) -> Result<OwnerForkTableArena, String> {
        let (base, publisher) = {
            let mut inner = self.inner.lock();
            let publisher = inner
                .arena_publisher
                .clone()
                .ok_or_else(|| "Fork table capacity has no physical publisher".to_owned())?;
            let base = inner
                .arena_source
                .as_mut()
                .and_then(|source| source.take_arena())
                .ok_or_else(|| "Fork table capacity is exhausted".to_owned())?;
            (base, publisher)
        };
        if let Err(error) = publisher.publish_raw_fork_arena(base.0) {
            if let Some(source) = self.inner.lock().arena_source.as_mut() {
                source.return_arena(base);
            }
            return Err(error);
        }
        Ok(OwnerForkTableArena {
            authority: self.clone(),
            publisher,
            base: Some(base),
        })
    }

    /// Install an arena source. Refuses conflicting lease identities.
    /// Fires probe site 1 if the manager is already present, or site 3 if deferred.
    pub fn install_source(&self, source: Box<dyn TableArenaSource>) -> Result<(), PageTableError> {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if let Some(existing) = inner.arena_source.as_ref()
            && existing.id() != source.id()
        {
            return Err(PageTableError::ConflictingArenaSource);
        }
        if inner.manager.is_some() {
            carrick_observability::probes::stage1_arena_install(1, 1, 0, authority);
        } else {
            carrick_observability::probes::stage1_arena_install(3, 0, 1, authority);
        }
        inner.arena_source = Some(source);
        Ok(())
    }

    /// Install an arena source with an eager builder fallback when the manager is absent.
    ///
    /// - If the manager is present, fires site 1 and installs the source.
    /// - If absent, attempts `eager_builder()`:
    ///   - On success: fires site 2, installs the manager and source.
    ///   - On failure: fires site 3, defers the source for future lazy building.
    pub fn install_source_with_eager_builder<B, E>(
        &self,
        source: Box<dyn TableArenaSource>,
        eager_builder: B,
    ) -> Result<(), TrapError>
    where
        B: FnOnce() -> Result<PageTableManager, E>,
        E: std::fmt::Display,
    {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if let Some(existing) = inner.arena_source.as_ref()
            && existing.id() != source.id()
        {
            return Err(TrapError::Hypervisor(
                "set stage-1 table arena source: conflicting arena source".to_owned(),
            ));
        }
        if inner.manager.is_some() {
            carrick_observability::probes::stage1_arena_install(1, 1, 0, authority);
            inner.arena_source = Some(source);
            Ok(())
        } else {
            match eager_builder() {
                Ok(mut manager) => {
                    if let Some(ref resolver) = inner.host_resolver {
                        unsafe { manager.make_live(Arc::clone(resolver)) };
                    }
                    carrick_observability::probes::stage1_arena_install(2, 1, 0, authority);
                    inner.arena_source = Some(source);
                    *inner.manager = Some(manager);
                    Ok(())
                }
                Err(_) => {
                    carrick_observability::probes::stage1_arena_install(3, 0, 1, authority);
                    inner.arena_source = Some(source);
                    Ok(())
                }
            }
        }
    }

    /// Load the software manager from `builder()` when it is absent, without
    /// editing anything. Returns whether this call installed it.
    ///
    /// This is the read-only counterpart of the lazy build inside
    /// [`Self::edit`]: it stages and stores no descriptor, so it is valid on
    /// every lane, including a guest-owned MM (whose manager may be absent
    /// after persistent exec) where `edit` would refuse. The installed manager
    /// carries this authority's live owner exactly as `edit` applies it.
    pub fn load_manager_if_absent<B, E>(&self, builder: B) -> Result<bool, E>
    where
        B: FnOnce() -> Result<PageTableManager, E>,
    {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if inner.manager.is_some() {
            return Ok(false);
        }
        let mut manager = builder()?;
        if let Some(ref resolver) = inner.host_resolver {
            unsafe { manager.make_live(Arc::clone(resolver)) };
        }
        manager.declare_live_hardware_image();
        manager.set_live_descriptor_owner(inner.live_owner);
        carrick_observability::probes::stage1_arena_install(
            4,
            u32::from(inner.arena_source.is_some()),
            0,
            authority,
        );
        *inner.manager = Some(manager);
        Ok(true)
    }

    /// Perform a scoped, locked edit over the stage-1 page tables via [`Stage1Editor`].
    ///
    /// If the `PageTableManager` is not yet present, lazily constructs it using `builder()`,
    /// firing probe site 4 with `applied = 1` if an arena source was already present, or
    /// `0` if absent.
    #[allow(clippy::expect_used)]
    pub fn edit<B, F, R, E>(&self, builder: B, f: F) -> Result<R, E>
    where
        B: FnOnce() -> Result<PageTableManager, E>,
        F: FnOnce(&mut Stage1Editor<'_>) -> Result<R, E>,
    {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if inner.manager.is_none() {
            let mut manager = builder()?;
            if let Some(ref resolver) = inner.host_resolver {
                unsafe { manager.make_live(Arc::clone(resolver)) };
            }
            let had_source = inner.arena_source.is_some();
            carrick_observability::probes::stage1_arena_install(
                4,
                u32::from(had_source),
                0,
                authority,
            );
            *inner.manager = Some(manager);
        }
        let Stage1AuthorityInner {
            ref mut manager,
            ref mut arena_source,
            live_owner,
            ..
        } = *inner;
        let manager = manager
            .as_mut()
            .expect("manager must be present after lazy initialization");
        manager.declare_live_hardware_image();
        manager.set_live_descriptor_owner(live_owner);
        let mut editor = Stage1Editor {
            manager,
            arena_source,
        };
        f(&mut editor)
    }

    /// Restore a previous manager image (e.g. during rollback).
    /// The input remains owned by the caller on error and is consumed only on success.
    ///
    /// Adopts live extension arenas from the active manager into `image`, retains
    /// this authority's arena source, fires `stage1_arena_replace(site, before, after, authority)`,
    /// restores quiesced descriptors to live host memory, and replaces the manager. Returns the replaced manager.
    pub fn restore_image(
        &self,
        image: &mut Option<PageTableManager>,
        site: u32,
    ) -> Result<Option<PageTableManager>, PageTableError> {
        let snapshot = image.as_mut().ok_or(PageTableError::BadAddress)?;
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if inner.live_owner == LiveDescriptorOwner::Guest {
            return Err(PageTableError::GuestOwnsLiveDescriptors);
        }
        if let Some(live) = inner.manager.as_ref() {
            let before = u32::from(inner.arena_source.is_some());
            snapshot.adopt_live_extension_state(live);
            let after = before;
            carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        }
        if let Some(ref resolver) = inner.host_resolver {
            unsafe {
                snapshot.restore_quiesced_snapshot_to_host(resolver)?;
                snapshot.make_live(Arc::clone(resolver));
            }
        }
        Ok(inner
            .manager
            .replace(image.take().ok_or(PageTableError::BadAddress)?))
    }

    /// Like [`Self::restore_image`], but also restores quiesced table descriptors to host memory.
    /// The caller retains `image` on every error.
    ///
    /// # Safety
    ///
    /// `resolve_page_table_host` must return a valid, writable host pointer for each
    /// physical GPA arena belonging to `image`.
    ///
    /// Note: `stage1_arena_replace` probes fire `before == after` by construction because the
    /// `TableArenaSource` is exclusively owned by this `Stage1Authority` and is invariant
    /// across manager image restores.
    pub unsafe fn restore_image_and_host<H>(
        &self,
        image: &mut Option<PageTableManager>,
        site: u32,
        resolve_page_table_host: H,
    ) -> Result<Option<PageTableManager>, PageTableError>
    where
        H: HostArenaResolver,
    {
        let snapshot = image.as_mut().ok_or(PageTableError::BadAddress)?;
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if inner.live_owner == LiveDescriptorOwner::Guest {
            return Err(PageTableError::GuestOwnsLiveDescriptors);
        }
        if let Some(live) = inner.manager.as_ref() {
            let before = u32::from(inner.arena_source.is_some());
            snapshot.adopt_live_extension_state(live);
            let after = before;
            carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        }
        unsafe { snapshot.restore_quiesced_snapshot_to_host(resolve_page_table_host)? };
        if let Some(ref resolver) = inner.host_resolver {
            unsafe { snapshot.make_live(Arc::clone(resolver)) };
        }
        Ok(inner
            .manager
            .replace(image.take().ok_or(PageTableError::BadAddress)?))
    }

    /// Replace the stage-1 authority for `execve`.
    ///
    /// - If `SharedWithVforkChild` (or `predecessor_shared` is true): the shared authority
    ///   belongs to the parent! Decrements the parent's vfork-shares count (restoring
    ///   the parent to `Exclusive` once all shared children have detached) without
    ///   touching its manager or extension arenas; creates and returns a brand-new
    ///   `Stage1Authority` with `builder()?` for the child.
    /// - If `Exclusive`: retires the old image's extension arenas via `retirer`,
    ///   retires its arena source WITH it (the source belongs to the lease of
    ///   the mm being replaced; the runtime installs the replacement lease's
    ///   source right after `execve_into`, and a stale source would refuse it
    ///   `ConflictingArenaSource`), installs the new manager, fires probe
    ///   site 5, and returns `self.clone()` — the authority identity survives.
    pub fn replace_for_exec<B, R, E>(
        &mut self,
        builder: B,
        retirer: R,
    ) -> Result<Stage1Authority, E>
    where
        B: FnOnce() -> Result<Option<PageTableManager>, E>,
        R: FnMut(&mut PageTableManager) -> Result<(), E>,
    {
        self.replace_for_exec_internal(builder, retirer)
            .map(|(auth, _)| auth)
    }

    /// Pure transition for `execve` authority replacement returning `(new_authority, was_shared)`.
    pub(crate) fn replace_for_exec_internal<B, R, E>(
        &mut self,
        builder: B,
        mut retirer: R,
    ) -> Result<(Stage1Authority, bool), E>
    where
        B: FnOnce() -> Result<Option<PageTableManager>, E>,
        R: FnMut(&mut PageTableManager) -> Result<(), E>,
    {
        let is_shared = {
            let mut inner = self.inner.lock();
            if inner.vfork_shares > 0 {
                inner.vfork_shares -= 1;
                true
            } else {
                false
            }
        };

        if is_shared {
            let new_manager = builder()?;
            let new_authority = Stage1Authority::new_with_manager(new_manager);
            *self = new_authority.clone();
            Ok((new_authority, true))
        } else {
            let (mut old_mgr, old_source) = {
                let mut inner = self.inner.lock();
                (inner.manager.take(), inner.arena_source.take())
            };
            if let Some(mut old) = old_mgr.take() {
                retirer(&mut old)?;
                self.inner.lock().image_pool.recycle(old);
            }
            // The retired image's source retires with it: its extension
            // arenas were just handed back and the replacement lease brings
            // its own source.
            drop(old_source);
            let new_manager = builder()?;
            let authority = self.authority_id();
            let mut inner = self.inner.lock();
            *inner.manager = new_manager;
            if inner.manager.is_some() {
                carrick_observability::probes::stage1_arena_install(5, 0, 0, authority);
            }
            Ok((self.clone(), false))
        }
    }

    /// Adopt extension arenas and arena source from an unshared predecessor authority
    /// during `bind_page_tables_authority`.
    ///
    /// This is called exclusively during `rebind_exec_mm_authority` (execve of an unshared
    /// task) when transitioning the task's `MmAccessState` from the predecessor mm to the
    /// freshly created stage-1 authority. Because `execve` replaces the process image,
    /// the predecessor mm is retiring and being destroyed; any extension arenas and the
    /// exclusive arena source belong to the retiring process carrier and are transferred to
    /// the successor authority. If the predecessor could ever remain live, stealing the
    /// arena source would starve it of future growth. Hence, this adoption is strictly
    /// gated on `previous.is_exclusive()` and occurs only across the execve transition
    /// where the predecessor is guaranteed retiring.
    ///
    /// Does nothing if `previous` is shared with an in-flight `vfork` child. Fires probe site 12.
    pub fn adopt_unshared_predecessor(&self, previous: &Stage1Authority) {
        if self.shares_exact_authority(previous) {
            return;
        }
        let authority = self.authority_id();
        if previous.is_exclusive() {
            let mut prev_guard = previous.inner.lock();
            let mut new_guard = self.inner.lock();
            if new_guard.host_resolver.is_none() {
                new_guard.host_resolver = prev_guard.host_resolver.clone();
            }
            let before = u32::from(new_guard.arena_source.is_some());
            if let Some(old_source) = prev_guard.arena_source.take()
                && new_guard.arena_source.is_none()
            {
                new_guard.arena_source = Some(old_source);
            }
            if let Some(old) = prev_guard.manager.take() {
                if let Some(new_mgr) = new_guard.manager.as_mut() {
                    new_mgr.adopt_live_extension_state(&old);
                    *prev_guard.manager = Some(old);
                } else {
                    *new_guard.manager = Some(old);
                }
            }
            let resolver_opt = new_guard.host_resolver.clone();
            if let Some(ref resolver) = resolver_opt
                && let Some(mgr) = new_guard.manager.as_mut()
            {
                unsafe { mgr.make_live(Arc::clone(resolver)) };
            }
            let after = u32::from(new_guard.arena_source.is_some());
            carrick_observability::probes::stage1_arena_replace(12, before, after, authority);
        }
    }

    /// Emit the `stage1_arena_bind` DTrace probe for this authority.
    pub fn emit_bind_probe(&self) {
        let inner = self.inner.lock();
        let present = inner.manager.is_some();
        let has_source = inner.arena_source.is_some();
        let arenas = inner.manager.as_ref().map_or(0, |m| m.pool_stats().3);
        carrick_observability::probes::stage1_arena_bind(
            self.authority_id(),
            u32::from(present),
            u32::from(has_source),
            arenas,
        );
    }

    /// Emit the `stage1_arena_absent` DTrace probe for this authority at `site`.
    pub fn emit_absent_probe(&self, site: u32) {
        carrick_observability::probes::stage1_arena_absent(site, self.authority_id());
    }
}

/// A borrowed editor over the stage-1 page tables and optional arena source.
///
/// Created inside [`Stage1Authority::edit`]. Automatically routes mutating operations
/// to `PageTableManager`'s `*_with_source` variants, passing the active arena source.
/// One host `mprotect` of `[address, address+len)` as shared terminal rules,
/// in the order they must apply. Both lanes use this one plan: the host
/// editor applies it with `apply_rule`, the guest lane submits each entry as
/// an EL1 `DescriptorOp::Terminal`. It preserves the historical ordering
/// (retired-leaf reset for a new mapping, then the
/// protection over the whole range, then fork re-arming of every
/// overlapping armed range, in full) by composing those passes per
/// terminal: armed intersections carry `fork_arm`, armed parts outside the
/// range get a plain fork arm. Every span in the plan is disjoint, so each
/// guest transaction takes its pages straight to their final state. Imported
/// page-granule private sources additionally acquire EL1-private authority
/// from their admitted permissions before COW is armed; compound-only ranges
/// keep their existing coarse-descriptor policy.
pub fn protection_terminal_rules(
    address: u64,
    len: usize,
    prot: u64,
    armed_cow: &[crate::vmm::ForkCowRange],
    new_mapping: bool,
) -> Vec<(u64, usize, TerminalRule)> {
    use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
    let exec = prot & LINUX_PROT_EXEC != 0;
    let (op, deny_host_buffers) = if prot & LINUX_PROT_WRITE != 0 {
        (PtOp::ReadWrite { exec }, false)
    } else if prot & (LINUX_PROT_READ | LINUX_PROT_EXEC) != 0 {
        (PtOp::ReadOnly { exec }, false)
    } else {
        // PROT_NONE over EL1-private leaves also denies host buffer access.
        (PtOp::Invalidate, true)
    };
    let start = address;
    let end = address.saturating_add(len as u64);
    // Sweep range edges, preserving the imported-file page granule through
    // overlap merging. Compound arming must not eagerly split its blocks.
    let mut events = Vec::with_capacity(armed_cow.len() * 2);
    for range in armed_cow.iter().filter(|range| range.len != 0) {
        let page = i32::from(range.granule == crate::vmm::CowGranule::Page);
        events.push((range.va, 1i32, page));
        events.push((range.va.saturating_add(range.len as u64), -1i32, -page));
    }
    events.sort_unstable();
    let mut merged = Vec::with_capacity(events.len());
    let (mut active, mut pages, mut previous) = (0, 0, 0);
    for (edge, delta, page_delta) in events {
        if active > 0 && previous < edge {
            merged.push((previous, edge, pages > 0));
        }
        active += delta;
        pages += page_delta;
        previous = edge;
    }
    let rule = |fork_arm, adopt_private| TerminalRule::Pt {
        op: Some(op),
        reset_retired: new_mapping,
        deny_host_buffers,
        fork_arm,
        adopt_private,
    };
    let arm_only = TerminalRule::pt(PtOp::ForkReadOnly);
    let mut plan = Vec::new();
    let mut push = |lo: u64, hi: u64, rule: TerminalRule| {
        if lo < hi {
            plan.push((lo, (hi - lo) as usize, rule));
        }
    };
    let mut cursor = start;
    for &(lo, hi, page_private) in &merged {
        // Armed part before the protected range: re-arm only.
        push(lo, hi.min(start), arm_only);
        let (in_lo, in_hi) = (lo.max(start), hi.min(end));
        if in_lo < in_hi {
            push(cursor, in_lo, rule(false, false));
            push(in_lo, in_hi, rule(true, page_private));
            cursor = cursor.max(in_hi);
        }
        // Armed part after the protected range: re-arm only.
        push(lo.max(end), hi, arm_only);
    }
    push(cursor, end, rule(false, false));
    plan
}

/// An admitted guest descriptor lane selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestLaneSelection {
    /// EL1 owns the MM's live descriptors now.
    Selected,
    /// Awaiting the MM's live backing; completed by `bind_live_backing`.
    Deferred,
}

/// Lifecycle point at which an MM's lane was sampled (see
/// [`HostLaneCause`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum GuestLaneSite {
    /// The MM's stage-1 authority was bound to its live backing.
    InitialBind = 0,
    /// Fork planning, after the pending-selection retry.
    ForkPlan = 1,
    /// A COW the host completed for an MM on the host lane.
    HostCow = 2,
}

impl GuestLaneSite {
    pub const COUNT: usize = 3;
}

/// Why an MM is on the host descriptor lane at a sampled instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum HostLaneCause {
    /// No guest selection was ever admitted on this authority (select never
    /// ran for it, or ran on another authority object).
    NeverSelected = 0,
    /// Selection admitted; no live backing is bound to this authority.
    PendingNoBacking = 1,
    /// Selection admitted; the authority holds no manager to promote.
    PendingNoManager = 2,
    /// Selection admitted; host edits are staged and unsynced.
    PendingUnsyncedEdits = 3,
    /// Selection admitted, backing bound, nothing blocks it: only a bind
    /// that never happened is missing.
    PendingAwaitingBind = 4,
    /// The authority the engine plans with is not the one the backend binds
    /// its live backing and COW lane to.
    AuthorityMismatch = 5,
}

impl HostLaneCause {
    pub const COUNT: usize = 6;
}

/// Physical source lifetime for one owner-selected parent split-table extent.
#[must_use = "Fork table capacity must settle from an exact owner receipt"]
pub struct OwnerForkTableArena {
    authority: Stage1Authority,
    publisher: Arc<dyn TableArenaPublisher>,
    base: Option<carrick_mmu_core::aarch64::SubstrateGpa>,
}
impl OwnerForkTableArena {
    pub fn arena(&self) -> Option<carrick_el1_abi::PortalForkTableArena> {
        self.base
            .and_then(|base| carrick_el1_abi::PortalForkTableArena::new(base.0, 2 * 1024 * 1024))
    }
    /// Called only after owner FINISH; used capacity remains part of this MM.
    pub fn settle(mut self, used: u64) -> Result<(), String> {
        if used > 2 * 1024 * 1024 {
            return Err("owner Fork exceeded table capacity".into());
        }
        if used != 0
            && let Some(base) = self.base.take()
        {
            self.authority.inner.lock().published_arenas.push(base.0);
        }
        Ok(())
    }
}
impl Drop for OwnerForkTableArena {
    fn drop(&mut self) {
        if let Some(base) = self.base.take() {
            if self.publisher.retire_raw_fork_arena(base.0).is_err() {
                // The physical publisher still holds this exact allocation;
                // quarantine it rather than recycle capacity that remains live.
                return;
            }
            if let Some(source) = self.authority.inner.lock().arena_source.as_mut() {
                source.return_arena(base);
            }
        }
    }
}

pub struct Stage1Editor<'a> {
    pub manager: &'a mut PageTableManager,
    pub arena_source: &'a mut Option<Box<dyn TableArenaSource>>,
}

impl<'a> std::ops::Deref for Stage1Editor<'a> {
    type Target = PageTableManager;
    fn deref(&self) -> &Self::Target {
        self.manager
    }
}

impl<'a> Stage1Editor<'a> {
    pub fn has_arena_source(&self) -> bool {
        self.arena_source.is_some()
    }

    /// Claim a new transaction while the authority's manager lock is held.
    pub fn begin_fresh_undo(&mut self) -> Result<bool, PageTableError> {
        self.manager.begin_fresh_undo()
    }

    pub fn begin_undo(&mut self) -> Result<(), PageTableError> {
        self.manager.begin_undo()
    }

    pub fn commit_undo(&mut self) {
        self.manager.commit_undo();
    }

    pub fn undo_is_open(&self) -> bool {
        self.manager.undo_is_open()
    }

    /// Synchronize dirty page table descriptors to the live host backing.
    ///
    /// # Safety
    ///
    /// `resolver` must return writable mappings for all attached arenas.
    pub unsafe fn sync_to_host(
        &mut self,
        resolver: impl HostArenaResolver,
    ) -> Result<(), PageTableError> {
        unsafe { self.manager.sync_to_host(resolver) }
    }

    pub fn set_multi_vcpu(&mut self, multi_vcpu: bool) {
        self.manager.set_multi_vcpu(multi_vcpu);
    }

    pub fn set_stage1_exclusive(&mut self, exclusive: bool) {
        self.manager.set_stage1_exclusive(exclusive);
    }

    /// See [`crate::engine::reserve_hvpatch_process_apertures`].
    pub fn reserve_hvpatch_process_apertures(
        &mut self,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        crate::engine::reserve_hvpatch_process_apertures(self.manager)
    }

    /// Host-lane mprotect: apply [`protection_terminal_rules`] with the
    /// shared per-terminal rule, exactly what the guest lane submits.
    pub fn apply_protection_edit(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
        armed_cow: &[crate::vmm::ForkCowRange],
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.apply_terminal_rules(&protection_terminal_rules(
            address, len, prot, armed_cow, false,
        ))
    }

    /// Apply shared terminal rules in order. A retired-leaf reset is
    /// validated over its whole span first, so the journal-less host editor
    /// refuses an occupied new mapping without a partial edit.
    pub fn apply_terminal_rules(
        &mut self,
        rules: &[(u64, usize, TerminalRule)],
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        for &(va, len, rule) in rules {
            if matches!(
                rule,
                TerminalRule::Pt {
                    reset_retired: true,
                    ..
                }
            ) {
                self.manager.check_vacant_for_new_mapping(va, len)?;
            }
        }
        let mut outcome = PageTableApplyOutcome::default();
        for &(va, len, rule) in rules {
            outcome |= self
                .manager
                .apply_rule(va, len, rule, self.arena_source.as_deref_mut())?;
        }
        Ok(outcome)
    }

    pub fn apply(
        &mut self,
        base: u64,
        size: usize,
        op: PtOp,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .apply(base, size, op, self.arena_source.as_deref_mut())
    }

    pub fn set_prot_none(
        &mut self,
        base: u64,
        size: usize,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .set_prot_none(base, size, self.arena_source.as_deref_mut())
    }

    pub fn invalidate(
        &mut self,
        base: u64,
        size: usize,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .invalidate(base, size, self.arena_source.as_deref_mut())
    }

    pub fn unmap_aliased(
        &mut self,
        base: u64,
        size: usize,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .unmap_aliased(base, size, self.arena_source.as_deref_mut())
    }

    pub fn set_readonly(
        &mut self,
        base: u64,
        size: usize,
        exec: bool,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .set_readonly(base, size, exec, self.arena_source.as_deref_mut())
    }

    pub fn set_fork_readonly(
        &mut self,
        base: u64,
        size: usize,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .set_fork_readonly(base, size, self.arena_source.as_deref_mut())
    }

    pub fn set_kernel_readonly(
        &mut self,
        base: u64,
        size: usize,
        exec: bool,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .set_kernel_readonly(base, size, exec, self.arena_source.as_deref_mut())
    }

    pub fn set_rw(
        &mut self,
        base: u64,
        size: usize,
        exec: bool,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.manager
            .set_rw(base, size, exec, self.arena_source.as_deref_mut())
    }

    pub fn map_aliased(
        &mut self,
        guest_va: u64,
        target_ipa: u64,
        size: u64,
        access: UserLeafAccess,
    ) -> Result<bool, PageTableError> {
        self.manager.map_aliased(
            guest_va,
            target_ipa,
            size,
            access,
            self.arena_source.as_deref_mut(),
        )
    }

    pub fn map_private_aliased(
        &mut self,
        guest_va: u64,
        target_ipa: u64,
        size: u64,
        access: UserLeafAccess,
    ) -> Result<bool, PageTableError> {
        self.manager.map_private_aliased(
            guest_va,
            target_ipa,
            size,
            access,
            self.arena_source.as_deref_mut(),
        )
    }

    pub fn map_kernel_aliased(
        &mut self,
        guest_va: u64,
        target_ipa: u64,
        size: u64,
    ) -> Result<bool, PageTableError> {
        self.manager.map_kernel_aliased(
            guest_va,
            target_ipa,
            size,
            self.arena_source.as_deref_mut(),
        )
    }

    /// See [`PageTableManager::clear_el1_cow_arm`].
    pub fn clear_el1_cow_arm(&mut self, va: u64, len: usize) -> Result<bool, PageTableError> {
        self.manager
            .clear_el1_cow_arm(va, len, self.arena_source.as_deref_mut())
    }

    pub fn repoint_preserving_attributes(
        &mut self,
        guest_va: u64,
        target_ipa: u64,
        size: u64,
    ) -> Result<bool, PageTableError> {
        self.manager.repoint_preserving_attributes(
            guest_va,
            target_ipa,
            size,
            self.arena_source.as_deref_mut(),
        )
    }

    pub fn set_writable_preserving_attributes(
        &mut self,
        guest_va: u64,
        size: usize,
    ) -> Result<bool, PageTableError> {
        self.manager.set_writable_preserving_attributes(
            guest_va,
            size,
            self.arena_source.as_deref_mut(),
        )
    }

    pub fn rebase(&mut self, new_base: u64) -> Result<(), PageTableError> {
        self.manager
            .rebase(new_base, self.arena_source.as_deref_mut())
    }

    /// Revert uncommitted page table edits recorded in the undo journal.
    ///
    /// # Safety
    ///
    /// `resolver` must return valid host pointers for all page table arenas.
    pub unsafe fn rollback_undo(
        &mut self,
        resolver: impl HostArenaResolver,
    ) -> Result<Vec<u64>, PageTableError> {
        unsafe {
            self.manager
                .rollback_undo(resolver, self.arena_source.as_deref_mut())
        }
    }

    /// Restore descriptors, then retire external backing before returning arena
    /// addresses to the allocator. On retirement failure the addresses remain
    /// quarantined; the caller must retain backing or fail-stop safely.
    ///
    /// # Safety
    /// `resolver` must provide live writable arena pointers. The caller must
    /// hold mutation exclusion and make `retire` flush stale translations and
    /// retire every supplied arena's backing before returning success.
    pub unsafe fn rollback_undo_retiring<E, F>(
        &mut self,
        resolver: impl HostArenaResolver,
        map_err: impl FnOnce(PageTableError) -> E,
        retire: F,
    ) -> Result<Vec<u64>, E>
    where
        F: FnOnce(&[u64]) -> Result<(), E>,
    {
        let popped = unsafe {
            self.manager
                .rollback_undo(resolver, None)
                .map_err(map_err)?
        };
        retire(&popped)?;
        if let Some(source) = self.arena_source.as_deref_mut() {
            for &base in &popped {
                source.return_arena(carrick_mmu_core::aarch64::SubstrateGpa(base));
            }
        }
        Ok(popped)
    }

    /// Restore a pre-transaction image over the live manager, adopting extension arenas,
    /// preserving the arena source, restoring descriptors to hardware memory, and firing `stage1_arena_replace`.
    pub fn restore_image(
        &mut self,
        image: &mut Option<PageTableManager>,
        site: u32,
        authority: u64,
    ) -> Result<(), PageTableError> {
        if self.manager.live_descriptor_owner() == LiveDescriptorOwner::Guest {
            return Err(PageTableError::GuestOwnsLiveDescriptors);
        }
        let snapshot = image.as_mut().ok_or(PageTableError::BadAddress)?;
        let before = u32::from(self.arena_source.is_some());
        snapshot.adopt_live_extension_state(self.manager);
        let after = before;
        carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        if let Some(resolver) = self.manager.resolver().cloned() {
            unsafe {
                snapshot.restore_quiesced_snapshot_to_host(&resolver)?;
                snapshot.make_live(resolver);
            }
        }
        *self.manager = image.take().ok_or(PageTableError::BadAddress)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Raw `(base, host)` arenas for a VM-free test whose edits publish
    /// executable leaves (production refuses those on page-table-only
    /// resolvers).
    #[derive(Clone, Copy)]
    struct TestArenas<const N: usize>([(u64, *mut u8); N]);

    unsafe impl<const N: usize> HostArenaResolver for TestArenas<N> {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            self.0.iter().find_map(|&(b, p)| (b == base).then_some(p))
        }

        fn publish_user_executable(&self, _output: u64, _len: u64) -> Result<(), PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }
    use carrick_guest_mem::Gpa;

    /// The executable leaves these fixtures were written against.
    const RWX: UserLeafAccess = UserLeafAccess {
        writable: true,
        executable: true,
    };
    use carrick_mem::memory::{
        AARCH64_LINUX_PAGE_TABLE_LAYOUT, LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE,
        LINUX_PAGE_TABLES_SIZE, stage1_hvpatch_page_tables,
    };
    use carrick_mmu_core::aarch64::{SubstrateGpa, TableArenaSource, TableArenaSourceId};
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct CountingArenaSource {
        id: TableArenaSourceId,
        available: Arc<Mutex<Vec<Gpa>>>,
        returned: Arc<Mutex<Vec<Gpa>>>,
    }

    impl TableArenaSource for CountingArenaSource {
        fn id(&self) -> TableArenaSourceId {
            self.id
        }

        fn take_arena(&mut self) -> Option<SubstrateGpa> {
            self.available
                .lock()
                .unwrap()
                .pop()
                .map(|gpa| SubstrateGpa(gpa.0))
        }

        fn return_arena(&mut self, gpa: SubstrateGpa) {
            self.returned.lock().unwrap().push(Gpa(gpa.0));
        }
    }

    /// The shared protection plan reproduces the host's historical mprotect
    /// sequence exactly: retired-leaf reset (new mapping), protection over
    /// the whole range, then fork re-arming of every overlapping armed range
    /// in full. Page for page, across prepared/resident/armed/retired EL1
    /// grants, coarse blocks and armed ranges inside, straddling and
    /// outside the protected range.
    #[test]
    fn protection_plan_matches_the_sequential_host_mprotect() {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        use carrick_mmu_core::aarch64::{GuestLeafPublication, terminal_descriptor};
        const PAGE: u64 = 4096;
        const TWO_MIB: u64 = 2 << 20;
        let base = LINUX_MMAP_BASE + 0x40_0000;
        let mut image = test_manager();
        image
            .set_prot_none(LINUX_MMAP_BASE, 64 << 20, None)
            .unwrap();
        // Eight 4-page EL1 grants, one resident page each.
        for slot in 0..8u64 {
            image
                .publish_private_pages(
                    GuestLeafPublication {
                        va: base + slot * 16 * PAGE,
                        ipa: 0x009b_4000_0000 + slot * 16 * PAGE,
                        len: 4 * PAGE,
                        writable: true,
                        executable: false,
                    },
                    base + slot * 16 * PAGE + (slot % 4) * PAGE,
                    None,
                )
                .unwrap();
        }
        // Grant 2 fork-armed, grant 3 retired, plus a coarse RW block.
        image
            .set_fork_readonly(base + 32 * PAGE, 4 * PAGE as usize, None)
            .unwrap();
        image
            .apply(base + 48 * PAGE, 4 * PAGE as usize, PtOp::Retire, None)
            .unwrap();
        let block = LINUX_MMAP_BASE + 16 * TWO_MIB;
        image.set_rw(block, TWO_MIB as usize, false, None).unwrap();
        let armed = |va: u64, len: u64| crate::vmm::ForkCowRange {
            va,
            len: len as usize,
            executable: false,
            kernel_only: false,
            granule: crate::vmm::CowGranule::Page,
        };
        // (address, len, prot, armed ranges, new mapping)
        let cases: Vec<(u64, u64, u64, Vec<crate::vmm::ForkCowRange>, bool)> = vec![
            (
                base,
                4 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                vec![],
                false,
            ),
            (
                base + 16 * PAGE,
                4 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_EXEC,
                vec![],
                false,
            ),
            (base + 16 * PAGE, 4 * PAGE, 0, vec![], false),
            // Armed range inside, straddling the start, and wholly outside.
            (
                base + 32 * PAGE,
                4 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                vec![armed(base + 33 * PAGE, 2 * PAGE)],
                false,
            ),
            (
                base + 34 * PAGE,
                2 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                vec![
                    armed(base + 32 * PAGE, 3 * PAGE),
                    armed(base + 64 * PAGE, 4 * PAGE),
                ],
                false,
            ),
            (
                base + 32 * PAGE,
                4 * PAGE,
                0,
                vec![armed(base + 32 * PAGE, 4 * PAGE)],
                false,
            ),
            // New mapping over the retired grant.
            (
                base + 48 * PAGE,
                4 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                vec![],
                true,
            ),
            // Mixed granules overlap: only the page subrange is adopted;
            // compound-only portions retain the existing coarse policy.
            (
                block,
                8 * PAGE,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                vec![
                    crate::vmm::ForkCowRange {
                        granule: crate::vmm::CowGranule::Compound,
                        ..armed(block, 8 * PAGE)
                    },
                    armed(block + 2 * PAGE, 2 * PAGE),
                ],
                false,
            ),
            // Bisected coarse block, with an armed range inside it.
            (
                block + 3 * PAGE,
                5 * PAGE,
                LINUX_PROT_READ,
                vec![armed(block + 4 * PAGE, PAGE)],
                false,
            ),
        ];
        for (index, (address, len, prot, armed_cow, new_mapping)) in cases.iter().enumerate() {
            let (address, len, prot) = (*address, *len as usize, *prot);
            let mut sequential = image.snapshot_image().unwrap();
            if *new_mapping {
                sequential
                    .clear_retired_for_new_mapping(address, len, None)
                    .unwrap();
            }
            for range in armed_cow
                .iter()
                .filter(|range| range.granule == crate::vmm::CowGranule::Page)
            {
                sequential
                    .set_fork_readonly_adopting(range.va, range.len, None)
                    .unwrap();
            }
            let exec = prot & LINUX_PROT_EXEC != 0;
            if prot & LINUX_PROT_WRITE != 0 {
                sequential.set_rw(address, len, exec, None).unwrap();
            } else if prot & (LINUX_PROT_READ | LINUX_PROT_EXEC) != 0 {
                sequential.set_readonly(address, len, exec, None).unwrap();
            } else {
                sequential
                    .set_prot_none_denying_host_buffers(address, len, None)
                    .unwrap();
            }
            for range in armed_cow {
                sequential
                    .apply_rule(
                        range.va,
                        range.len,
                        TerminalRule::Pt {
                            op: None,
                            reset_retired: false,
                            deny_host_buffers: false,
                            fork_arm: true,
                            adopt_private: range.granule == crate::vmm::CowGranule::Page,
                        },
                        None,
                    )
                    .unwrap();
            }

            let mut planned = image.snapshot_image().unwrap();
            let mut source = None;
            let mut editor = Stage1Editor {
                manager: &mut planned,
                arena_source: &mut source,
            };
            let plan = protection_terminal_rules(address, len, prot, armed_cow, *new_mapping);
            editor.apply_terminal_rules(&plan).unwrap();

            let lo = armed_cow
                .iter()
                .map(|range| range.va)
                .chain([address])
                .min()
                .unwrap()
                .saturating_sub(2 * PAGE);
            let hi = armed_cow
                .iter()
                .map(|range| range.va + range.len as u64)
                .chain([address + len as u64])
                .max()
                .unwrap()
                + 2 * PAGE;
            let mut page = lo;
            let mut changed = false;
            while page < hi {
                let expected = terminal_descriptor(sequential.debug_walk(page));
                let actual = terminal_descriptor(planned.debug_walk(page));
                assert_eq!(
                    expected, actual,
                    "case {index} page {page:#x}: sequential {expected:#x} plan {actual:#x}"
                );
                changed |= expected != terminal_descriptor(image.debug_walk(page));
                page += PAGE;
            }
            assert!(changed, "case {index} is vacuous");
        }
    }

    fn test_manager() -> PageTableManager {
        PageTableManager::new(
            stage1_hvpatch_page_tables(),
            LINUX_PAGE_TABLES_BASE,
            AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        )
    }

    fn test_manager_at(base: u64) -> PageTableManager {
        PageTableManager::new(
            stage1_hvpatch_page_tables(),
            base,
            AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        )
    }

    fn observed_generation(authority: &Stage1Authority) -> Option<std::num::NonZeroU64> {
        authority
            .try_with_manager_generation_until(
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                (),
                (),
                |_, generation| Ok(generation),
            )
            .unwrap()
    }

    #[test]
    fn protection_edit_preserves_copyout_intent_when_rearming_cow() {
        use carrick_abi::{LINUX_PROT_READ, LINUX_PROT_WRITE};
        use carrick_mmu_core::aarch64::{
            GuestLeafPublication, LeafAccess, terminal_descriptor, terminal_descriptor_permits_el0,
            terminal_descriptor_permits_host_buffer,
        };
        let va = LINUX_MMAP_BASE;
        let mut manager = test_manager();
        manager
            .publish_private_pages(
                GuestLeafPublication {
                    va,
                    ipa: 0x009b_4000_0000,
                    len: 4096,
                    writable: true,
                    executable: false,
                },
                va,
                None,
            )
            .unwrap();
        let mut source = None;
        let mut editor = Stage1Editor {
            manager: &mut manager,
            arena_source: &mut source,
        };
        let cow = [crate::vmm::ForkCowRange {
            va,
            len: 4096,
            executable: false,
            kernel_only: false,
            granule: crate::vmm::CowGranule::Page,
        }];
        for (prot, can_copyout) in [
            (LINUX_PROT_READ | LINUX_PROT_WRITE, true),
            (LINUX_PROT_READ, false),
            (0, false),
            (LINUX_PROT_READ | LINUX_PROT_WRITE, true),
        ] {
            editor.apply_protection_edit(va, 4096, prot, &cow).unwrap();
            let descriptor = terminal_descriptor(editor.debug_walk(va));
            assert!(!terminal_descriptor_permits_el0(
                descriptor,
                LeafAccess::Write
            ));
            assert_eq!(
                terminal_descriptor_permits_host_buffer(descriptor, LeafAccess::Write),
                can_copyout
            );
        }
    }

    #[test]
    fn image_generation_invalidates_edits_errors_restore_and_replacement() {
        let manager = || test_manager();
        let mut authority = Stage1Authority::new_with_manager(Some(manager()));
        let original = observed_generation(&authority);
        authority.with_manager(|m| m.debug_walk(0x40_0000));
        let image = authority.snapshot_image().unwrap();
        assert_eq!(
            observed_generation(&authority),
            original,
            "reads preserve generation"
        );
        let failed = authority.edit(
            || Err(()),
            |editor| {
                editor.set_readonly(0x40_0000, 0x1000, false).unwrap();
                Err::<(), _>(())
            },
        );
        assert!(failed.is_err());
        let after_error = observed_generation(&authority);
        assert_ne!(after_error, original);
        authority.restore_image(&mut Some(image), 0).unwrap();
        let after_restore = observed_generation(&authority);
        assert_ne!(after_restore, original);
        assert_ne!(after_restore, after_error);
        authority
            .try_edit_until(
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                (),
                (),
                || Err(()),
                |_| Ok(()),
            )
            .unwrap();
        let after_try_edit = observed_generation(&authority);
        assert_ne!(after_try_edit, after_restore);
        authority.set_manager(manager());
        let after_set = observed_generation(&authority);
        assert_ne!(after_set, after_try_edit);
        let saved = authority.replace_manager(None).unwrap();
        authority.replace_manager(Some(saved));
        let after_replace = observed_generation(&authority);
        assert_ne!(after_replace, after_set);
        let previous = Stage1Authority::new_with_manager(Some(manager()));
        let previous_generation = observed_generation(&previous);
        authority.adopt_unshared_predecessor(&previous);
        assert_ne!(observed_generation(&previous), previous_generation);
        assert_ne!(observed_generation(&authority), after_replace);
        let before_exec = observed_generation(&authority);
        let exact = authority.clone();
        authority
            .replace_for_exec(|| Ok::<_, ()>(Some(manager())), |_| Ok(()))
            .unwrap();
        assert!(authority.shares_exact_authority(&exact));
        assert_ne!(observed_generation(&authority), before_exec);
        // Taking an image invalidates even if exec preparation subsequently fails.
        assert!(
            authority
                .replace_for_exec(|| Err::<Option<PageTableManager>, _>(()), |_| Ok(()))
                .is_err()
        );
        assert!(authority.is_none());
        authority.set_manager(manager());
        assert_ne!(observed_generation(&authority), before_exec);
    }

    #[test]
    fn image_generation_exhaustion_never_reenables_reuse() {
        let authority = Stage1Authority::new_with_manager(Some(test_manager()));
        authority.inner.lock().manager.generation = std::num::NonZeroU64::new(u64::MAX);
        for _ in 0..2 {
            authority
                .edit(|| Err::<PageTableManager, ()>(()), |_| Ok(()))
                .unwrap();
            assert_eq!(observed_generation(&authority), None);
        }
    }

    #[test]
    fn retiring_child_authority_returns_its_image_to_the_shared_pool() {
        // `kernel.fork.stage1-image`: the parent forks, the child owns a
        // private image, the child exits. The image must come back to the
        // parent's pool so the next fork clones into it instead of allocating.
        let parent = Stage1Authority::new_with_manager(Some(test_manager()));
        let pool = parent.image_pool();
        assert_eq!(pool.retained(), 0);

        let (image, fresh) = parent.snapshot_image_recycled().expect("parent image");
        assert!(fresh, "an empty pool forces one fresh allocation");
        assert_eq!(pool.fresh_allocations(), 1);
        let child = parent.child_with_manager(image);
        assert!(Arc::ptr_eq(&child.image_pool(), &pool));

        drop(child);
        assert_eq!(pool.retained(), 1, "the retiring child image is recycled");
        assert_eq!(pool.recycled_images(), 1);

        let (image, fresh) = parent.snapshot_image_recycled().expect("parent image");
        assert!(!fresh, "the second fork reuses the recycled image");
        assert_eq!(pool.fresh_allocations(), 1);
        assert_eq!(pool.retained(), 0);
        assert_eq!(image.base(), LINUX_PAGE_TABLES_BASE);
        assert_eq!(
            image.copied_bytes(),
            parent
                .with_manager(|manager| manager.copied_bytes())
                .expect("parent manager"),
            "a recycled image carries the exact parent snapshot"
        );
    }

    #[test]
    fn image_pool_is_bounded_and_exec_recycles_the_retired_image() {
        let pool = Stage1ImagePool::new(2);
        for _ in 0..3 {
            pool.recycle(test_manager());
        }
        assert_eq!(pool.retained(), 2, "images beyond capacity are dropped");
        assert_eq!(pool.recycled_images(), 2);

        let mut authority = Stage1Authority::new_with_manager(Some(test_manager()));
        let pool = authority.image_pool();
        authority
            .replace_for_exec(|| Ok::<_, PageTableError>(Some(test_manager())), |_| Ok(()))
            .expect("exec replacement");
        assert_eq!(
            pool.retained(),
            1,
            "the pre-exec image is recycled for the exec'd process's forks"
        );
    }

    #[test]
    fn exec_replacement_drops_the_retired_source_so_the_replacement_lease_installs() {
        // A forked child that execs: the runtime installs the source for the
        // REPLACEMENT lease after `execve_into`. The retired image's source
        // must go with the retired image, or the install refuses
        // `ConflictingArenaSource` and the exec dies past its point of no
        // return (busybox `sh -c /bin/true` under the first landing).
        let old = CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(LINUX_PAGE_TABLES_BASE)),
            available: Arc::new(Mutex::new(Vec::new())),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let replacement = CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(0x9a_0020_0000)),
            available: Arc::new(Mutex::new(Vec::new())),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let manager = test_manager();
        let mut authority = Stage1Authority::new_with_manager(Some(manager));
        authority
            .install_source(Box::new(old))
            .expect("install the pre-exec source");
        let retired = authority
            .replace_for_exec(|| Ok::<_, PageTableError>(Some(test_manager())), |_| Ok(()))
            .expect("exclusive exec replacement");
        assert!(retired.shares_exact_authority(&authority));
        assert!(
            !authority.has_source(),
            "the retired image's arena source must retire with it"
        );
        authority
            .install_source(Box::new(replacement))
            .expect("the replacement lease's source installs after exec");
        assert!(authority.has_source());
    }

    #[test]
    fn rollback_returns_allocated_extension_arena_to_source() {
        exercise_rollback_retirement(false, false);
    }

    #[test]
    fn rollback_retires_backing_before_returning_arena_to_source() {
        exercise_rollback_retirement(true, false);
    }

    #[test]
    fn rollback_retirement_failure_quarantines_arena_address() {
        exercise_rollback_retirement(true, true);
    }

    fn exercise_rollback_retirement(retire_first: bool, fail_retirement: bool) {
        let root = Gpa(LINUX_PAGE_TABLES_BASE);
        let ext_base = Gpa(0xb0_0000_0000);
        let available = Arc::new(Mutex::new(vec![ext_base]));
        let returned = Arc::new(Mutex::new(Vec::new()));

        let source = CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(root.0)),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        let mut manager = test_manager();
        manager.set_multi_vcpu(false);
        manager.set_stage1_exclusive(true);
        manager
            .set_prot_none(
                LINUX_MMAP_BASE,
                carrick_mem::memory::mmap_arena_size() as usize,
                None,
            )
            .expect("reserve sparse arena");

        const TWO_MIB: u64 = 2 * 1024 * 1024;
        let mut block = LINUX_MMAP_BASE + 64 * TWO_MIB;
        loop {
            let (_, free, _, _) = manager.pool_stats();
            let spare = manager.spare_tables_available();
            if spare == 0 && free == 0 {
                break;
            }
            if manager.set_rw(block + 0x1000, 0x1000, false, None).is_err() {
                break;
            }
            block += TWO_MIB;
        }
        assert_eq!(
            manager.spare_tables_available(),
            0,
            "spare tables pool exhausted"
        );
        assert_eq!(manager.pool_stats().3, 1, "starts with exactly 1 arena");

        let va = LINUX_MMAP_BASE + 600 * TWO_MIB + 0x1000;

        let authority = Stage1Authority::new_with_manager(Some(manager));
        authority
            .install_source(Box::new(source))
            .expect("install counting arena source");

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let mut host_arena1 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let p0 = host_arena0.as_mut_ptr();
        let p1 = host_arena1.as_mut_ptr();
        let resolver = TestArenas([(LINUX_PAGE_TABLES_BASE, p0), (ext_base.0, p1)]);

        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    editor
                        .set_rw(va, 0x1000, false)
                        .expect("allocates extension arena from source");
                    assert_eq!(editor.pool_stats().3, 2, "grew to 2 arenas");
                    assert_eq!(
                        available.lock().unwrap().len(),
                        0,
                        "source slot was consumed"
                    );

                    let va2 = va + 0x1000;
                    editor.set_rw(va2, 0x1000, false).expect("subsequent edit");

                    let popped = if retire_first {
                        let result = unsafe {
                            editor.rollback_undo_retiring(
                                resolver,
                                |e| e,
                                |bases| {
                                    assert_eq!(bases, &[ext_base.0]);
                                    assert!(
                                        returned.lock().unwrap().is_empty(),
                                        "arena address escaped before backing retirement"
                                    );
                                    assert!(available.lock().unwrap().is_empty());
                                    if fail_retirement {
                                        Err(PageTableError::UnresolvedArena(ext_base.0))
                                    } else {
                                        Ok(())
                                    }
                                },
                            )
                        };
                        if fail_retirement {
                            assert!(result.is_err());
                            assert!(returned.lock().unwrap().is_empty());
                            assert_eq!(editor.pool_stats().3, 1);
                            return Ok(());
                        }
                        result.unwrap()
                    } else {
                        unsafe { editor.rollback_undo(resolver).unwrap() }
                    };
                    assert_eq!(popped, vec![ext_base.0], "rollback popped extension arena");
                    assert_eq!(editor.pool_stats().3, 1, "manager restored to 1 arena");
                    Ok::<(), ()>(())
                },
            )
            .unwrap();

        assert_eq!(
            *returned.lock().unwrap(),
            if fail_retirement {
                Vec::new()
            } else {
                vec![ext_base]
            },
            "only retired backing may return its arena address"
        );
    }

    #[test]
    fn concurrent_vfork_children_share_authority_and_detach_independently() {
        let root = Gpa(LINUX_PAGE_TABLES_BASE);
        let available = Arc::new(Mutex::new(Vec::new()));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let source = CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(root.0)),
            available,
            returned,
        };

        let manager = test_manager();
        let parent = Stage1Authority::new_with_manager(Some(manager));
        parent
            .install_source(Box::new(source))
            .expect("install source");
        assert!(parent.is_exclusive());
        assert_eq!(parent.root_base(), Some(LINUX_PAGE_TABLES_BASE));

        // Two concurrent vfork children are spawned.
        parent.share_with_vfork_child();
        assert!(parent.is_shared_with_vfork_child());
        assert!(!parent.is_exclusive());

        parent.share_with_vfork_child();
        assert!(parent.is_shared_with_vfork_child());
        assert!(!parent.is_exclusive());

        let mut child1 = parent.clone();
        let mut child2 = parent.clone();

        // Child 1 execs first.
        let mut retired1 = false;
        let new_child1 = child1
            .replace_for_exec(
                || Ok::<_, ()>(Some(test_manager_at(0x9a_0020_0000))),
                |_| {
                    retired1 = true;
                    Ok(())
                },
            )
            .expect("child1 exec");

        assert!(
            !retired1,
            "parent extension arenas must not be retired by child1"
        );
        assert!(!new_child1.shares_exact_authority(&parent));
        assert_eq!(new_child1.root_base(), Some(0x9a_0020_0000));
        assert!(!new_child1.has_source());

        // Parent must STILL have its original root and source, and STILL be shared with child2!
        assert_eq!(parent.root_base(), Some(LINUX_PAGE_TABLES_BASE));
        assert!(parent.has_source());
        assert!(parent.is_shared_with_vfork_child());
        assert!(!parent.is_exclusive());

        // Child 2 execs second.
        let mut retired2 = false;
        let new_child2 = child2
            .replace_for_exec(
                || Ok::<_, ()>(Some(test_manager_at(0x9a_0040_0000))),
                |_| {
                    retired2 = true;
                    Ok(())
                },
            )
            .expect("child2 exec");

        assert!(
            !retired2,
            "parent extension arenas must not be retired by child2"
        );
        assert!(!new_child2.shares_exact_authority(&parent));
        assert_eq!(new_child2.root_base(), Some(0x9a_0040_0000));
        assert!(!new_child2.has_source());

        // Now that all children detached, parent is back to Exclusive!
        assert_eq!(parent.root_base(), Some(LINUX_PAGE_TABLES_BASE));
        assert!(parent.has_source());
        assert!(parent.is_exclusive());
        assert!(!parent.is_shared_with_vfork_child());

        // Parent itself execs exclusively.
        let mut retired_parent = false;
        let mut parent_exec = parent.clone();
        let exec_parent = parent_exec
            .replace_for_exec(
                || Ok::<_, ()>(Some(test_manager_at(0x9a_0060_0000))),
                |_| {
                    retired_parent = true;
                    Ok(())
                },
            )
            .expect("parent exec");

        assert!(
            retired_parent,
            "parent old arenas must be retired on exclusive exec"
        );
        assert!(exec_parent.shares_exact_authority(&parent));
        assert_eq!(exec_parent.root_base(), Some(0x9a_0060_0000));
        assert!(
            !exec_parent.has_source(),
            "source retired on exclusive exec"
        );
    }

    #[test]
    fn vfork_shares_prevents_exclusive_path_even_if_called_as_first_or_only_child() {
        let root = Gpa(LINUX_PAGE_TABLES_BASE);
        let available = Arc::new(Mutex::new(Vec::new()));
        let returned = Arc::new(Mutex::new(Vec::new()));
        let source = CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(root.0)),
            available,
            returned,
        };

        let manager = test_manager();
        let parent = Stage1Authority::new_with_manager(Some(manager));
        parent
            .install_source(Box::new(source))
            .expect("install source");

        // Authority is shared with a vfork child
        parent.share_with_vfork_child();
        assert!(parent.is_shared_with_vfork_child());

        let mut child = parent.clone();
        let mut retired = false;

        // Child execs: the internal decision sees vfork_shares > 0
        let (new_child, was_shared) = child
            .replace_for_exec_internal(
                || Ok::<_, ()>(Some(test_manager_at(0x9a_0020_0000))),
                |_| {
                    retired = true;
                    Ok(())
                },
            )
            .expect("child exec");

        assert!(was_shared, "internal decision must report shared");
        assert!(
            !retired,
            "parent arenas must NOT be retired while vfork_shares > 0"
        );
        assert!(parent.is_present(), "parent manager must not be stolen");
        assert!(parent.has_source(), "parent source must not be stolen");
        assert_eq!(parent.root_base(), Some(LINUX_PAGE_TABLES_BASE));
        assert!(!new_child.shares_exact_authority(&parent));
        assert_eq!(new_child.root_base(), Some(0x9a_0020_0000));
    }

    #[test]
    fn stage1_authority_undo_journal_commit_and_rollback() {
        let manager = test_manager();
        let authority = Stage1Authority::new_with_manager(Some(manager));

        let mut host_arena0 = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let p0 = host_arena0.as_mut_ptr();
        let resolver = TestArenas([(LINUX_PAGE_TABLES_BASE, p0)]);

        let va = 0x40_0000;
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.set_rw(va, 0x1000, false).expect("initial mapping");
                    unsafe { editor.sync_to_host(resolver).expect("sync") };
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit");

        // Open undo, perform edit, then rollback
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    editor
                        .set_readonly(va, 0x1000, false)
                        .expect("readonly edit");
                    unsafe { editor.sync_to_host(resolver).expect("sync") };
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit");

        // Rollback via Stage1Authority::rollback_undo
        let before_rollback = observed_generation(&authority);
        unsafe {
            authority.rollback_undo(resolver).unwrap();
        }
        assert_ne!(observed_generation(&authority), before_rollback);

        // Verify that after rollback, the mapping is restored to writable
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    assert!(!editor.undo_is_open());
                    let desc = editor.debug_walk(va)[3];
                    assert_eq!(desc & (1 << 7), 0, "must be writable after rollback");
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("verify");

        // Now test commit_undo: open undo, edit, commit
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    editor
                        .set_readonly(va, 0x1000, false)
                        .expect("readonly edit");
                    unsafe { editor.sync_to_host(resolver).expect("sync") };
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit");

        authority.commit_undo();

        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    assert!(!editor.undo_is_open());
                    let desc = editor.debug_walk(va)[3];
                    assert_ne!(desc & (1 << 7), 0, "must remain readonly after commit");
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("verify");
    }

    struct BufferResolver {
        buf: std::sync::Mutex<Vec<u8>>,
        base: u64,
    }

    unsafe impl HostArenaResolver for BufferResolver {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            if base == self.base {
                Some(self.buf.lock().unwrap().as_mut_ptr())
            } else {
                None
            }
        }
        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            if base == self.base {
                Some(self.buf.lock().unwrap().as_ptr())
            } else {
                None
            }
        }
        fn publish_user_executable(
            &self,
            _output: u64,
            _len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    unsafe impl HostArenaResolver for &BufferResolver {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (*self).host_ptr_for_base(base)
        }
        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            (*self).host_const_ptr_for_base(base)
        }
        fn publish_user_executable(
            &self,
            _output: u64,
            _len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    /// Guest lane selection needs EL1 and the host to edit and read the same
    /// descriptors. Admitted before the MM's live backing exists, it is
    /// deferred and completed by `bind_live_backing`; a child forked in
    /// between inherits the pending selection; host edits not yet synced
    /// refuse promotion rather than being discarded.
    #[test]
    fn guest_lane_selection_waits_for_live_backing_and_never_drops_unsynced_edits() {
        let resolver = || {
            Arc::new(BufferResolver {
                buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
                base: LINUX_PAGE_TABLES_BASE,
            }) as Arc<dyn HostArenaResolver + Send + Sync>
        };

        let authority = Stage1Authority::new_with_manager(Some(test_manager()));
        assert_eq!(
            authority.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Deferred)
        );
        assert_eq!(authority.live_descriptor_owner(), LiveDescriptorOwner::Host);
        let child = authority.child_with_manager(test_manager());
        assert!(unsafe { authority.bind_live_backing(resolver()) });
        assert_eq!(
            authority.live_descriptor_owner(),
            LiveDescriptorOwner::Guest
        );
        assert_eq!(
            authority.with_manager(|m| (m.is_live(), m.live_descriptor_owner())),
            Some((true, LiveDescriptorOwner::Guest))
        );
        assert!(
            unsafe { child.bind_live_backing(resolver()) },
            "a child forked while the selection was pending completes it too"
        );
        assert!(
            !unsafe { authority.bind_live_backing(resolver()) },
            "only the first binding completes a selection"
        );

        // Already bound: the selection is immediate.
        let bound = Stage1Authority::new_with_manager(Some(test_manager()));
        assert!(!unsafe { bound.bind_live_backing(resolver()) });
        assert_eq!(
            bound.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Selected)
        );

        // A bound authority whose owned manager holds unsynced host edits is
        // refused: making it live would discard them.
        let mut staged = test_manager();
        staged.set_prot_none(LINUX_MMAP_BASE, 0x1000, None).unwrap();
        assert!(
            staged.has_unsynced_edits(),
            "fixture must hold unsynced edits"
        );
        let dirty = Stage1Authority::new_with_manager(Some(staged));
        dirty.inner.lock().host_resolver = Some(resolver());
        assert_eq!(
            dirty.select_guest_descriptor_owner(),
            Err(GuestLaneRefusal::UnsyncedEdits)
        );
        assert_eq!(dirty.live_descriptor_owner(), LiveDescriptorOwner::Host);
    }

    /// A pending guest selection whose live backing arrives while host edits
    /// are still unsynced must neither discard those edits (making the
    /// manager live drops its owned copy) nor strand the selection: once the
    /// edits reach the live backing the authority is exactly as admissible as
    /// a clean one, and nothing else ever retries the promotion. A stranded
    /// MM stays on the host lane for its whole life, and every fork child
    /// (which inherits the pending flag and binds clean) is promoted instead.
    #[test]
    fn pending_guest_selection_syncs_unsynced_edits_at_live_bind_and_completes() {
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
            base: LINUX_PAGE_TABLES_BASE,
        });
        let mut staged = test_manager();
        staged.set_prot_none(LINUX_MMAP_BASE, 0x1000, None).unwrap();
        assert!(staged.has_unsynced_edits(), "fixture must hold host edits");
        let owned_walk = staged.debug_walk(LINUX_MMAP_BASE);
        assert_ne!(owned_walk[0], 0, "fixture edit must be visible offline");
        let authority = Stage1Authority::new_with_manager(Some(staged));
        assert_eq!(
            authority.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Deferred)
        );
        let child = authority.child_with_manager(test_manager());

        assert!(
            unsafe {
                authority.bind_live_backing(
                    Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
                )
            },
            "the binding that makes the edits live completes the pending selection"
        );
        assert_eq!(
            authority.live_descriptor_owner(),
            LiveDescriptorOwner::Guest
        );
        assert_eq!(
            authority.with_manager(|m| (m.is_live(), m.has_unsynced_edits())),
            Some((true, false))
        );
        // The terminal the host edit wrote is in the backing EL1 now edits
        // (the tables above it were published with the image before bind).
        let l3_table = owned_walk[2] & 0x0000_FFFF_FFFF_F000;
        let slot = (l3_table - LINUX_PAGE_TABLES_BASE) as usize
            + ((LINUX_MMAP_BASE >> 12) & 511) as usize * 8;
        let live_terminal = {
            let buf = resolver.buf.lock().unwrap();
            u64::from_le_bytes(buf[slot..slot + 8].try_into().unwrap())
        };
        assert_eq!(
            live_terminal, owned_walk[3],
            "the host edit reached the live backing instead of being discarded"
        );
        // The child forked while pending still completes its own selection.
        assert!(unsafe {
            child.bind_live_backing(Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>)
        });
    }

    #[test]
    fn stage1_authority_live_restore_and_rollback_updates_hardware_backing() {
        let manager = test_manager();
        let authority = Stage1Authority::new_with_manager(Some(manager));

        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
            base: LINUX_PAGE_TABLES_BASE,
        });

        unsafe {
            authority.bind_live_backing(
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
            );
        }

        let va = 0x50_0000;
        let ipa1 = 0x80_0000;
        let ipa2 = 0x90_0000;

        // Map initial translation to ipa1
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.map_aliased(va, ipa1, 0x1000, RWX).expect("map 1");
                    unsafe { editor.sync_to_host(&*resolver).expect("sync 1") };
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit 1");

        // Take snapshot image
        let snap1 = authority.snapshot_image().expect("snapshot 1");

        // Map translation to ipa2
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.map_aliased(va, ipa2, 0x1000, RWX).expect("map 2");
                    unsafe { editor.sync_to_host(&*resolver).expect("sync 2") };
                    Ok::<(), PageTableError>(())
                },
            )
            .expect("edit 2");

        authority.with_manager(|mgr| {
            assert_eq!(mgr.translate(va), Some(ipa2));
        });

        // Restore snapshot 1
        authority.restore_image(&mut Some(snap1), 1).unwrap();

        // Hardware memory and live translation must now reflect ipa1
        authority.with_manager(|mgr| {
            assert_eq!(mgr.translate(va), Some(ipa1));
        });
    }

    struct FailingResolver;
    unsafe impl HostArenaResolver for FailingResolver {
        fn host_ptr_for_base(&self, _base: u64) -> Option<*mut u8> {
            None
        }
        fn host_const_ptr_for_base(&self, _base: u64) -> Option<*const u8> {
            None
        }
        fn publish_user_executable(
            &self,
            _output: u64,
            _len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    #[test]
    fn stage1_authority_snapshot_fails_on_unresolved_live_backing() {
        let manager = test_manager();
        let authority = Stage1Authority::new_with_manager(Some(manager));
        let resolver = Arc::new(FailingResolver);
        unsafe {
            authority.bind_live_backing(resolver);
        }

        // Snapshot must fail closed and return None
        assert!(authority.snapshot_image().is_none());
        assert!(authority.snapshot_image_recycled().is_none());
    }

    #[test]
    fn stage1_authority_restore_and_rollback_fail_and_preserve_on_unresolved_arena() {
        let manager = test_manager();
        let authority = Stage1Authority::new_with_manager(Some(manager));
        let snap = authority.snapshot_image().expect("initial snapshot");

        // Attempt restore with a failing resolver
        let mut snapshot = Some(snap);
        let res = unsafe { authority.restore_image_and_host(&mut snapshot, 0, FailingResolver) };
        assert!(
            snapshot.is_some(),
            "failed restore retains caller recovery image"
        );
        assert!(matches!(res, Err(PageTableError::UnresolvedArena(_))));
        assert!(
            authority.is_present(),
            "manager remains present after failed restore"
        );

        let mut host = vec![0u8; LINUX_PAGE_TABLES_SIZE as usize];
        let restored = unsafe {
            authority.restore_image_and_host(
                &mut snapshot,
                0,
                TestArenas([(LINUX_PAGE_TABLES_BASE, host.as_mut_ptr())]),
            )
        }
        .expect("retry retained snapshot with available backing");
        assert!(
            snapshot.is_none(),
            "successful restore consumes the recovery image"
        );
        assert!(
            restored.is_some(),
            "previous manager is available for recycling"
        );

        // Attempt rollback with failing resolver
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    editor.set_readonly(0x40_0000, 0x1000, false).unwrap();
                    let rollback_res = unsafe { editor.rollback_undo(FailingResolver) };
                    assert!(matches!(
                        rollback_res,
                        Err(PageTableError::UnresolvedArena(_))
                    ));
                    assert!(editor.undo_is_open(), "undo journal preserved on failure");
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
    }

    mod test_allocator {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;
        std::thread_local! {
            pub(super) static FAIL_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
            pub(super) static OP_COUNT: Cell<Option<u64>> = const { Cell::new(None) };
            pub(super) static ALLOC_BYTES: Cell<Option<usize>> = const { Cell::new(None) };
            pub(super) static REFUSED_ALLOCS: Cell<usize> = const { Cell::new(0) };
        }
        struct CountingAllocator;
        #[global_allocator]
        static ALLOCATOR: CountingAllocator = CountingAllocator;
        fn check_and_record(size: usize) -> bool {
            let _ = OP_COUNT.try_with(|count| {
                if let Some(n) = count.get() {
                    count.set(Some(n.checked_add(1).unwrap()));
                }
            });
            let _ = ALLOC_BYTES.try_with(|bytes| {
                if let Some(b) = bytes.get() {
                    bytes.set(Some(b.saturating_add(size)));
                }
            });
            let should_fail = FAIL_AFTER
                .try_with(|limit_cell| {
                    if let Some(limit) = limit_cell.get() {
                        if limit == 0 {
                            let _ = REFUSED_ALLOCS.try_with(|refused| {
                                refused.set(refused.get().saturating_add(1));
                            });
                            true
                        } else {
                            limit_cell.set(Some(limit - 1));
                            false
                        }
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            !should_fail
        }
        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                if !check_and_record(layout.size()) {
                    return std::ptr::null_mut();
                }
                unsafe { System.alloc(layout) }
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) }
            }
        }
    }

    struct MultiBufferResolver {
        arenas: std::sync::Mutex<std::collections::HashMap<u64, Vec<u8>>>,
    }

    impl MultiBufferResolver {
        fn new() -> Self {
            Self {
                arenas: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn register(&self, base: u64, size: usize) {
            self.arenas.lock().unwrap().insert(base, vec![0u8; size]);
        }
    }

    unsafe impl HostArenaResolver for MultiBufferResolver {
        fn host_ptr_for_range(&self, base: u64, _len: usize) -> Option<*mut u8> {
            self.arenas
                .lock()
                .unwrap()
                .get_mut(&base)
                .map(|v| v.as_mut_ptr())
        }
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            self.host_ptr_for_range(base, 0)
        }
        fn publish_user_executable(
            &self,
            _output: u64,
            _len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    unsafe impl HostArenaResolver for &MultiBufferResolver {
        fn host_ptr_for_range(&self, base: u64, len: usize) -> Option<*mut u8> {
            (*self).host_ptr_for_range(base, len)
        }
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (*self).host_ptr_for_base(base)
        }
        fn publish_user_executable(
            &self,
            _output: u64,
            _len: u64,
        ) -> Result<(), carrick_mmu_core::aarch64::PageTableError> {
            // VM-free test backing: no instruction cache to maintain.
            Ok(())
        }
    }

    #[test]
    fn stage1_authority_metadata_refusal_propagation() {
        let manager = test_manager();
        let authority = Stage1Authority::new_with_manager(Some(manager));
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
            base: LINUX_PAGE_TABLES_BASE,
        });
        unsafe {
            authority.bind_live_backing(
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
            );
        }

        let va1 = 0x40_0000;
        let va2 = 0x50_0000;

        // Establish initial valid mapping and commit
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    assert!(!editor.undo_is_open());
                    editor.begin_undo().unwrap();
                    assert!(editor.undo_is_open());
                    editor.map_aliased(va1, 0x80_0000, 0x1000, RWX).unwrap();
                    editor.set_readonly(va1, 0x1000, false).unwrap();
                    unsafe { editor.sync_to_host(&*resolver).unwrap() };
                    editor.commit_undo();
                    assert!(!editor.undo_is_open());
                    Ok::<(), PageTableError>(())
                },
            )
            .unwrap();

        authority.with_manager(|mgr| {
            assert_eq!(mgr.translate(va1), Some(0x80_0000));
        });

        // Inject allocator refusal during map_aliased
        test_allocator::REFUSED_ALLOCS.with(|c| c.set(0));
        test_allocator::FAIL_AFTER.with(|c| c.set(Some(0)));
        let edit_res = authority.edit(
            || panic!("manager must be present"),
            |editor| {
                editor.begin_undo()?;
                editor.map_aliased(va2, 0x90_0000, 0x1000, RWX)
            },
        );
        test_allocator::FAIL_AFTER.with(|c| c.set(None));
        let refused = test_allocator::REFUSED_ALLOCS.with(|c| c.get());

        assert!(refused > 0, "must trigger allocator refusal");
        assert_eq!(edit_res, Err(PageTableError::MetadataAllocation));

        // Exercise nonallocating typed adapter lowering with refusal active
        test_allocator::OP_COUNT.with(|c| c.set(Some(0)));
        test_allocator::ALLOC_BYTES.with(|c| c.set(Some(0)));
        test_allocator::FAIL_AFTER.with(|c| c.set(Some(0)));
        let pt_err = edit_res.unwrap_err();
        let mem_err = crate::engine::page_table_rollback_error_to_memory_error(pt_err);
        assert_eq!(mem_err, carrick_guest_mem::MemoryError::MetadataAllocation);
        let trap_err = crate::engine::memory_error_to_trap_error(mem_err, "stage1 authority edit");
        assert!(matches!(
            trap_err,
            carrick_hal::TrapError::MetadataAllocation
        ));
        test_allocator::FAIL_AFTER.with(|c| c.set(None));
        let conv_allocs = test_allocator::OP_COUNT.with(|c| c.replace(None)).unwrap();
        let conv_bytes = test_allocator::ALLOC_BYTES
            .with(|c| c.replace(None))
            .unwrap();
        assert_eq!(conv_allocs, 0, "error lowering must not allocate");
        assert_eq!(conv_bytes, 0, "error lowering must not allocate bytes");

        // Inject allocator refusal during set_rw with journal open and verify rollback on same authority
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    test_allocator::REFUSED_ALLOCS.with(|c| c.set(0));
                    test_allocator::FAIL_AFTER.with(|c| c.set(Some(0)));
                    let res = editor.set_rw(va1, 0x1000, true);
                    test_allocator::FAIL_AFTER.with(|c| c.set(None));
                    assert_eq!(res, Err(PageTableError::MetadataAllocation));
                    assert!(editor.undo_is_open());
                    unsafe { editor.rollback_undo(&*resolver).unwrap() };
                    assert!(!editor.undo_is_open());
                    Ok::<(), PageTableError>(())
                },
            )
            .unwrap();

        // Authority state is preserved: va1 is still translated, va2 is not translated
        authority.with_manager(|mgr| {
            assert_eq!(mgr.translate(va1), Some(0x80_0000));
            assert_eq!(mgr.translate(va2), None);
        });

        // Subsequent transaction on the SAME authority succeeds
        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo().unwrap();
                    editor.map_aliased(va2, 0x90_0000, 0x1000, RWX).unwrap();
                    unsafe { editor.sync_to_host(&*resolver).unwrap() };
                    editor.commit_undo();
                    assert!(!editor.undo_is_open());
                    Ok::<(), PageTableError>(())
                },
            )
            .unwrap();

        authority.with_manager(|mgr| {
            assert_eq!(mgr.translate(va1), Some(0x80_0000));
            assert_eq!(mgr.translate(va2), Some(0x90_0000));
        });

        // Real >8-arena overflow-scratch refusal in sync_to_host flowing into production converter
        let multi_resolver = Arc::new(MultiBufferResolver::new());
        multi_resolver.register(LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE as usize);
        for i in 0..30 {
            multi_resolver.register(0x90_0000_0000 + (i as u64) * 0x20_0000, 4096);
        }

        let mut layout = AARCH64_LINUX_PAGE_TABLE_LAYOUT;
        layout.extension_arena_capacity = 4096;
        let mut multi_mgr =
            PageTableManager::new(stage1_hvpatch_page_tables(), LINUX_PAGE_TABLES_BASE, layout);
        multi_mgr.arenas[0].next_free = multi_mgr.arenas[0].capacity as u64;
        let multi_authority = Stage1Authority::new_with_manager(Some(multi_mgr));
        let ext_bases: Vec<Gpa> = (0..30)
            .map(|i| Gpa(0x90_0000_0000 + (i as u64) * 0x20_0000))
            .collect();
        let source = Box::new(CountingArenaSource {
            id: TableArenaSourceId(SubstrateGpa(0x90_0000_0000)),
            available: Arc::new(Mutex::new(ext_bases)),
            returned: Arc::new(Mutex::new(Vec::new())),
        });
        multi_authority.install_source(source).unwrap();

        unsafe {
            multi_authority.bind_live_backing(
                Arc::clone(&multi_resolver) as Arc<dyn HostArenaResolver + Send + Sync>
            );
        }

        multi_authority
            .edit(
                || panic!("manager present"),
                |editor| {
                    // Attach extension arenas (>8 inline threshold in sync_to_host)
                    for i in 0..10 {
                        let va = 0x80_0000_0000 + (i as u64) * 0x20_0000;
                        let ipa = 0x90_0000_0000 + (i as u64) * 0x20_0000;
                        editor.map_aliased(va, ipa, 0x1000, RWX).unwrap();
                    }
                    assert!(editor.manager.arenas.len() > 8);

                    // Inject refusal during sync_to_host (>8-arena overflow hosts vector reservation)
                    test_allocator::FAIL_AFTER.with(|c| c.set(Some(0)));
                    let sync_err = unsafe { editor.sync_to_host(&*multi_resolver) };
                    assert_eq!(sync_err, Err(PageTableError::MetadataAllocation));

                    // Lower through production converter under active refusal
                    test_allocator::OP_COUNT.with(|c| c.set(Some(0)));
                    test_allocator::ALLOC_BYTES.with(|c| c.set(Some(0)));
                    let mem_err =
                        crate::engine::page_table_sync_error_to_memory_error(sync_err.unwrap_err());
                    assert_eq!(mem_err, carrick_guest_mem::MemoryError::MetadataAllocation);
                    let trap_err =
                        crate::engine::memory_error_to_trap_error(mem_err, "stage-1 sync");
                    assert!(matches!(
                        trap_err,
                        carrick_hal::TrapError::MetadataAllocation
                    ));
                    test_allocator::FAIL_AFTER.with(|c| c.set(None));

                    let sync_conv_allocs =
                        test_allocator::OP_COUNT.with(|c| c.replace(None)).unwrap();
                    let sync_conv_bytes = test_allocator::ALLOC_BYTES
                        .with(|c| c.replace(None))
                        .unwrap();
                    assert_eq!(
                        sync_conv_allocs, 0,
                        "sync_to_host lowering must not allocate"
                    );
                    assert_eq!(
                        sync_conv_bytes, 0,
                        "sync_to_host lowering must not allocate bytes"
                    );

                    Ok::<(), PageTableError>(())
                },
            )
            .unwrap();
    }

    #[test]
    fn guest_owned_authority_loads_an_absent_manager_without_an_edit() {
        let authority = Stage1Authority::new_with_manager(None);
        authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
        assert!(authority.is_none());
        // `edit` would refuse the guest lane at the engine funnel; the load
        // path is valid there and stores nothing.
        let loaded = authority
            .load_manager_if_absent(|| Ok::<_, PageTableError>(test_manager()))
            .unwrap();
        assert!(loaded);
        assert!(authority.is_present());
        assert_eq!(
            authority.with_manager(|m| m.live_descriptor_owner()),
            Some(LiveDescriptorOwner::Guest)
        );
        // Present: the builder is not consulted and nothing is replaced.
        let again = authority
            .load_manager_if_absent(|| -> Result<PageTableManager, PageTableError> {
                panic!("builder must not run when the manager is present")
            })
            .unwrap();
        assert!(!again);
    }

    #[test]
    fn guest_owned_authority_refuses_host_live_stores_and_builds_guest_transactions() {
        use carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        use carrick_mmu_core::aarch64::descriptor_txn::{
            BackingIdentity, CallerInvalidatesAsid, DescriptorOutcome, DescriptorRefusal,
            InlineJournal, PageSpan, PrimaryTableWords, execute_descriptor_txn,
        };
        use carrick_mmu_core::aarch64::{
            El1PrivateLeafState, GuestLeafPublication, el1_private_leaf_state, terminal_descriptor,
        };
        use std::num::NonZeroU64;

        let nz = |value| NonZeroU64::new(value).unwrap();
        let va = LINUX_MMAP_BASE + 0x80_0000;
        // The sparse mmap window is reserved (invalid) before any grant.
        let mut manager = test_manager();
        manager.set_prot_none(va, 0x20_0000, None).unwrap();
        let mut boot = manager.as_bytes().to_vec();
        boot.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(boot),
            base: LINUX_PAGE_TABLES_BASE,
        });
        let authority = Stage1Authority::new_with_manager(Some(manager));
        unsafe {
            authority.bind_live_backing(
                Arc::clone(&resolver) as Arc<dyn HostArenaResolver + Send + Sync>
            );
        }
        let snapshot = authority.snapshot_image().unwrap();
        authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
        assert_eq!(
            authority.live_descriptor_owner(),
            LiveDescriptorOwner::Guest
        );
        let bytes = || resolver.buf.lock().unwrap().clone();
        let before = bytes();

        // The engine edit funnel: staging is refused publication.
        let edit = authority.edit(
            || panic!("manager must be present"),
            |editor| {
                editor.set_readonly(LINUX_MMAP_BASE, 0x1000, false)?;
                unsafe { editor.sync_to_host(&*resolver) }
            },
        );
        assert_eq!(edit, Err(PageTableError::GuestOwnsLiveDescriptors));
        // Snapshot restores are live stores too, through every entry point.
        let mut image = Some(snapshot.snapshot_image().unwrap());
        assert_eq!(
            authority.restore_image(&mut image, 0).err(),
            Some(PageTableError::GuestOwnsLiveDescriptors)
        );
        assert_eq!(
            unsafe { authority.restore_image_and_host(&mut image, 0, &*resolver) }.err(),
            Some(PageTableError::GuestOwnsLiveDescriptors)
        );
        let editor_restore = authority.edit(
            || panic!("manager must be present"),
            |editor| editor.restore_image(&mut image, 0, 0),
        );
        assert_eq!(
            editor_restore,
            Err(PageTableError::GuestOwnsLiveDescriptors)
        );
        assert!(
            image.is_some(),
            "a refused restore keeps the caller's image"
        );
        assert_eq!(bytes(), before);

        // Live work is built as an authenticated guest transaction.
        let ipa = LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000;
        let backing = BackingIdentity {
            frame_id: nz(3),
            mapping_id: nz(4),
            owner_generation: nz(5),
            inventory_revision: nz(6),
        };
        let op = DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va,
                ipa,
                len: 4 * 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(va, 4096),
            backing,
        };
        let txn = authority.prepare_guest_descriptor_txn(nz(9), op).unwrap();
        assert_eq!(txn.id.generation, nz(1));
        assert_eq!(txn.root.raw(), LINUX_PAGE_TABLES_BASE);
        assert_eq!(bytes(), before, "building a transaction stores nothing");

        // EL1 executes it; the host settles the exact receipt.
        let receipt = {
            let mut buf = resolver.buf.lock().unwrap();
            let maintenance = CallerInvalidatesAsid;
            let words = unsafe {
                PrimaryTableWords::new(
                    buf.as_mut_ptr().cast(),
                    LINUX_PAGE_TABLES_BASE,
                    LINUX_PAGE_TABLES_SIZE as usize,
                    &maintenance,
                )
            }
            .unwrap();
            let mut journal = InlineJournal::new();
            execute_descriptor_txn(
                &words,
                carrick_mmu_core::aarch64::SubstrateGpa(LINUX_PAGE_TABLES_BASE),
                &txn,
                &mut journal,
            )
        };
        assert!(matches!(receipt.outcome, DescriptorOutcome::Applied(_)));
        let verified = authority
            .settle_guest_descriptor_receipt(&txn, &receipt)
            .unwrap();
        assert_eq!(verified.resident(), PageSpan::new(va, 4096));
        let leaf = authority
            .with_manager(|manager| terminal_descriptor(manager.debug_walk(va + 4096)))
            .unwrap();
        assert_eq!(el1_private_leaf_state(leaf), El1PrivateLeafState::Prepared);

        // Generations advance per transaction; refusals reserve nothing.
        assert_eq!(
            authority.prepare_guest_descriptor_txn(nz(9), op),
            Err(GuestTxnPrepareError::Refused(
                DescriptorRefusal::AlreadyValid
            ))
        );
        let retire = authority
            .prepare_guest_descriptor_txn(nz(9), DescriptorOp::Retire(PageSpan::new(va, 4096)))
            .unwrap();
        assert_eq!(retire.id.generation, nz(2));
        authority.abandon_guest_descriptor_txn(&retire).unwrap();

        // The host-owned lane never builds guest transactions.
        let host_lane = Stage1Authority::new_with_manager(Some(test_manager()));
        assert_eq!(
            host_lane.prepare_guest_descriptor_txn(nz(9), op),
            Err(GuestTxnPrepareError::NotGuestOwned)
        );
    }

    /// A guest descriptor transaction that grows into a new extension arena
    /// is returned only after the backend published that arena: EL1 must
    /// never receive a grant whose backing and owner are unpublished. A
    /// refused publication returns the grants and keeps refusing until the
    /// arena is published, even though the image already holds it.
    #[test]
    fn guest_transactions_publish_a_grown_arena_before_submission() {
        use carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
        use carrick_mmu_core::aarch64::GuestLeafPublication;
        use carrick_mmu_core::aarch64::descriptor_txn::{BackingIdentity, PageSpan};
        use std::num::NonZeroU64;
        use std::sync::atomic::AtomicBool;

        struct RecordingPublisher {
            accept: AtomicBool,
            published: Mutex<Vec<Vec<u64>>>,
        }
        impl TableArenaPublisher for RecordingPublisher {
            fn publish_extension_arenas(&self, manager: &PageTableManager) -> Result<(), String> {
                if !self.accept.load(Ordering::SeqCst) {
                    return Err("backend refused".into());
                }
                self.published
                    .lock()
                    .unwrap()
                    .push(manager.extension_arena_bases());
                Ok(())
            }
        }

        let nz = |value| NonZeroU64::new(value).unwrap();
        let va = LINUX_MMAP_BASE + 0x80_0000;
        let mut manager = test_manager();
        manager.set_prot_none(va, 0x20_0000, None).unwrap();
        while manager.alloc_table_for_test().is_ok() {}
        let mut boot = manager.as_bytes().to_vec();
        boot.resize(LINUX_PAGE_TABLES_SIZE as usize, 0);
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(boot),
            base: LINUX_PAGE_TABLES_BASE,
        });
        let authority = Stage1Authority::new_with_manager(Some(manager));
        unsafe {
            authority.bind_live_backing(resolver as Arc<dyn HostArenaResolver + Send + Sync>);
        }
        authority.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
        let op = DescriptorOp::Prepare {
            publication: GuestLeafPublication {
                va,
                ipa: LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x40_0000,
                len: 4 * 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(va, 4096),
            backing: BackingIdentity {
                frame_id: nz(3),
                mapping_id: nz(4),
                owner_generation: nz(5),
                inventory_revision: nz(6),
            },
        };
        assert_eq!(
            authority.prepare_guest_descriptor_txn(nz(9), op),
            Err(GuestTxnPrepareError::Manager(PageTableError::OutOfTables)),
            "the exhausted primary needs an arena for this operation"
        );

        let extension = LINUX_PAGE_TABLES_BASE + 0x40_0000;
        let available = Arc::new(Mutex::new(vec![Gpa(extension)]));
        let returned = Arc::new(Mutex::new(Vec::new()));
        authority
            .install_source(Box::new(CountingArenaSource {
                id: TableArenaSourceId(SubstrateGpa(extension)),
                available: Arc::clone(&available),
                returned: Arc::clone(&returned),
            }))
            .unwrap();
        let publisher = Arc::new(RecordingPublisher {
            accept: AtomicBool::new(false),
            published: Mutex::new(Vec::new()),
        });
        authority.set_arena_publisher(Arc::clone(&publisher) as Arc<dyn TableArenaPublisher>);

        // Refused publication: no transaction, the grants come back.
        for _ in 0..2 {
            assert_eq!(
                authority.prepare_guest_descriptor_txn(nz(9), op),
                Err(GuestTxnPrepareError::Manager(
                    PageTableError::UnresolvedArena(extension)
                )),
                "an unpublished arena is never granted, on the first or a later attempt"
            );
        }
        assert!(publisher.published.lock().unwrap().is_empty());

        // Accepted publication precedes the transaction that names it.
        publisher.accept.store(true, Ordering::SeqCst);
        let txn = authority.prepare_guest_descriptor_txn(nz(9), op).unwrap();
        assert_eq!(
            publisher.published.lock().unwrap().as_slice(),
            &[vec![extension]]
        );
        let grants = txn.tables.as_slice();
        assert!(!grants.is_empty());
        assert_eq!(grants[0], extension, "refused grants were returned");
        for &page in grants {
            assert!((extension..extension + 0x20_0000).contains(&page));
        }
        // A published arena is not republished for the next transaction.
        authority.abandon_guest_descriptor_txn(&txn).unwrap();
        let again = authority.prepare_guest_descriptor_txn(nz(9), op).unwrap();
        assert_eq!(again.tables.as_slice()[0], extension);
        assert_eq!(publisher.published.lock().unwrap().len(), 1);
        assert!(returned.lock().unwrap().is_empty());
    }

    #[test]
    fn fork_children_inherit_their_parents_live_descriptor_lane() {
        let parent = Stage1Authority::new_with_manager(Some(test_manager()));
        let host_child = parent.child_with_manager(test_manager());
        assert_eq!(
            host_child.live_descriptor_owner(),
            LiveDescriptorOwner::Host
        );
        parent.select_live_descriptor_owner(LiveDescriptorOwner::Guest);
        let guest_child = parent.child_with_manager(test_manager());
        assert_eq!(
            guest_child.live_descriptor_owner(),
            LiveDescriptorOwner::Guest
        );
        assert_eq!(
            guest_child.with_manager(PageTableManager::live_descriptor_owner),
            Some(LiveDescriptorOwner::Guest)
        );
        assert!(!guest_child.shares_exact_authority(&parent));
    }

    /// A fork child inherits the parent's lane once the parent's pending
    /// selection completed at its live bind.
    #[test]
    fn a_fork_child_inherits_guest_from_a_parent_whose_pending_selection_completed() {
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
            base: LINUX_PAGE_TABLES_BASE,
        }) as Arc<dyn HostArenaResolver + Send + Sync>;
        let parent = Stage1Authority::new_with_manager(Some(test_manager()));
        assert_eq!(
            parent.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Deferred)
        );
        assert!(unsafe { parent.bind_live_backing(resolver) });
        let child = parent.child_with_manager(test_manager());
        assert_eq!(child.live_descriptor_owner(), LiveDescriptorOwner::Guest);
    }

    /// Every way an MM can sit on the host lane is named, without side
    /// effects, so a signed run can say which one a stranded parent is in.
    #[test]
    fn host_lane_cause_names_why_a_pending_selection_has_not_completed() {
        let resolver = Arc::new(BufferResolver {
            buf: std::sync::Mutex::new(vec![0u8; LINUX_PAGE_TABLES_SIZE as usize]),
            base: LINUX_PAGE_TABLES_BASE,
        }) as Arc<dyn HostArenaResolver + Send + Sync>;
        let never = Stage1Authority::new_with_manager(Some(test_manager()));
        assert_eq!(never.host_lane_cause(), Some(HostLaneCause::NeverSelected));

        let pending = Stage1Authority::new_with_manager(Some(test_manager()));
        assert_eq!(
            pending.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Deferred)
        );
        assert_eq!(
            pending.host_lane_cause(),
            Some(HostLaneCause::PendingNoBacking)
        );
        pending.inner.lock().host_resolver = Some(Arc::clone(&resolver));
        assert_eq!(
            pending.host_lane_cause(),
            Some(HostLaneCause::PendingAwaitingBind)
        );
        assert_eq!(
            pending.host_lane_cause(),
            Some(HostLaneCause::PendingAwaitingBind),
            "observation changes nothing"
        );
        assert!(unsafe { pending.bind_live_backing(Arc::clone(&resolver)) });
        assert_eq!(pending.host_lane_cause(), None);

        let mut staged = test_manager();
        staged.set_prot_none(LINUX_MMAP_BASE, 0x1000, None).unwrap();
        let dirty = Stage1Authority::new_with_manager(Some(staged));
        assert_eq!(
            dirty.select_guest_descriptor_owner(),
            Ok(GuestLaneSelection::Deferred)
        );
        dirty.inner.lock().host_resolver = Some(resolver);
        assert_eq!(
            dirty.host_lane_cause(),
            Some(HostLaneCause::PendingUnsyncedEdits)
        );
    }
}
