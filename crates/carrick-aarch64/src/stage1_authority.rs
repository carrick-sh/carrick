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
use carrick_mmu_core::aarch64::{
    HostArenaResolver, PageTableApplyOutcome, PageTableError, PageTableManager, PtOp,
    TableArenaSource,
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

struct Stage1AuthorityInner {
    manager: TrackedStage1Image,
    arena_source: Option<Box<dyn TableArenaSource>>,
    host_resolver: Option<Arc<dyn HostArenaResolver + Send + Sync>>,
    vfork_shares: usize,
    engines: usize,
    /// Recycle pool shared by this authority and every child authority it
    /// forks. The retiring image of an exited process returns here on drop.
    image_pool: Arc<Stage1ImagePool>,
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
                host_resolver: None,
                vfork_shares: 0,
                engines: 1,
                image_pool,
            })),
        }
    }

    /// Bind a live host arena resolver, making hardware-visible backing authoritative.
    ///
    /// # Safety
    /// `resolver` must uphold the safety contracts of `HostArenaResolver`.
    pub unsafe fn bind_live_backing(&self, resolver: Arc<dyn HostArenaResolver + Send + Sync>) {
        let mut inner = self.inner.lock();
        inner.host_resolver = Some(Arc::clone(&resolver));
        if let Some(manager) = inner.manager.as_mut() {
            unsafe { manager.make_live(resolver) };
        }
    }

    /// Create the `Exclusive` authority of a forked child around its private
    /// image. The child shares this authority's image pool, so its image
    /// returns to the parent's pool when the child retires.
    pub fn child_with_manager(&self, manager: PageTableManager) -> Self {
        let image_pool = Arc::clone(&self.inner.lock().image_pool);
        Self::with_pool(Some(manager), image_pool)
    }

    /// The image recycle pool shared across this authority's process tree.
    pub fn image_pool(&self) -> Arc<Stage1ImagePool> {
        Arc::clone(&self.inner.lock().image_pool)
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
        if let Some(manager) = inner.manager.as_mut() {
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
            ..
        } = *inner;
        let manager = manager.as_mut().ok_or(on_absent)?;
        manager.declare_live_hardware_image();
        let mut editor = Stage1Editor {
            manager,
            arena_source,
        };
        f(&mut editor)
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
            ..
        } = *inner;
        let manager = manager
            .as_mut()
            .expect("manager must be present after lazy initialization");
        manager.declare_live_hardware_image();
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

    pub fn begin_undo(&mut self) {
        self.manager.begin_undo();
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

    pub fn reserve_hvpatch_process_apertures(
        &mut self,
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        self.set_prot_none(
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            (carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE
                + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE) as usize,
        )
    }

    pub fn apply_protection_edit(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
        armed_cow: &[crate::vmm::ForkCowRange],
    ) -> Result<PageTableApplyOutcome, PageTableError> {
        use carrick_abi::{LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE};
        let exec = prot & LINUX_PROT_EXEC != 0;
        let mut outcome = if prot & LINUX_PROT_WRITE != 0 {
            self.set_rw(address, len, exec)?
        } else if prot & (LINUX_PROT_READ | LINUX_PROT_EXEC) != 0 {
            self.set_readonly(address, len, exec)?
        } else {
            self.set_prot_none(address, len)?
        };
        for range in armed_cow {
            outcome |= self.set_readonly(range.va, range.len, exec)?;
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
        writable: bool,
    ) -> Result<bool, PageTableError> {
        self.manager.map_aliased(
            guest_va,
            target_ipa,
            size,
            writable,
            self.arena_source.as_deref_mut(),
        )
    }

    pub fn map_private_aliased(
        &mut self,
        guest_va: u64,
        target_ipa: u64,
        size: u64,
        writable: bool,
    ) -> Result<bool, PageTableError> {
        self.manager.map_private_aliased(
            guest_va,
            target_ipa,
            size,
            writable,
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
    use carrick_guest_mem::Gpa;
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
        let resolver = [(LINUX_PAGE_TABLES_BASE, p0), (ext_base.0, p1)];

        authority
            .edit(
                || panic!("manager must be present"),
                |editor| {
                    editor.begin_undo();
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
        let resolver = (LINUX_PAGE_TABLES_BASE, p0);

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
                    editor.begin_undo();
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
                    editor.begin_undo();
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
    }

    unsafe impl HostArenaResolver for &BufferResolver {
        fn host_ptr_for_base(&self, base: u64) -> Option<*mut u8> {
            (*self).host_ptr_for_base(base)
        }
        fn host_const_ptr_for_base(&self, base: u64) -> Option<*const u8> {
            (*self).host_const_ptr_for_base(base)
        }
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
                    editor.map_aliased(va, ipa1, 0x1000, true).expect("map 1");
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
                    editor.map_aliased(va, ipa2, 0x1000, true).expect("map 2");
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
                (LINUX_PAGE_TABLES_BASE, host.as_mut_ptr()),
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
                    editor.begin_undo();
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
}
