//! Stage-1 page-table and arena-source authority type.
//!
//! Encapsulates ownership of stage-1 page-table translation tables (`PageTableManager`),
//! the extension arena source (`TableArenaSource`), and the fork/vfork sharing state
//! (`ShareState`). Eliminates loose `Arc<Mutex<Option<PageTableManager>>>` heuristics
//! and prevents arena-source leaks across clone, rollback, and execve transitions.

use std::sync::Arc;

use parking_lot::Mutex;

use carrick_hal::TrapError;
use carrick_mem::page_table::{
    HostArenaResolver, PageTableApplyOutcome, PageTableError, PageTableManager, TableArenaSource,
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

struct Stage1AuthorityInner {
    manager: Option<PageTableManager>,
    arena_source: Option<Box<dyn TableArenaSource>>,
    share_state: ShareState,
    engines: usize,
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
            .field("share_state", &inner.share_state)
            .field("engines", &inner.engines)
            .finish()
    }
}

impl Stage1Authority {
    /// Create a new, unpopulated stage-1 authority in the `Exclusive` state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Stage1AuthorityInner {
                manager: None,
                arena_source: None,
                share_state: ShareState::Exclusive,
                engines: 1,
            })),
        }
    }

    /// Create a stage-1 authority pre-populated with an optional manager in the `Exclusive` state.
    pub fn new_with_manager(manager: Option<PageTableManager>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Stage1AuthorityInner {
                manager,
                arena_source: None,
                share_state: ShareState::Exclusive,
                engines: 1,
            })),
        }
    }

    /// Replace or update the inner manager directly. Used primarily for test harnesses and initialization.
    pub fn replace_manager(&self, manager: Option<PageTableManager>) -> Option<PageTableManager> {
        let mut inner = self.inner.lock();
        std::mem::replace(&mut inner.manager, manager)
    }

    /// Set the inner manager directly. Used primarily for test harnesses.
    pub fn set_manager(&self, manager: PageTableManager) {
        self.inner.lock().manager = Some(manager);
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
        self.inner.lock().share_state
    }

    /// True if solely owned (`Exclusive`).
    pub fn is_exclusive(&self) -> bool {
        self.inner.lock().share_state == ShareState::Exclusive
    }

    /// True if currently shared with an in-flight `CLONE_VM` / `vfork` child.
    pub fn is_shared_with_vfork_child(&self) -> bool {
        self.inner.lock().share_state == ShareState::SharedWithVforkChild
    }

    /// Mark this authority as shared with a newly created `vfork` child.
    pub fn share_with_vfork_child(&self) {
        self.inner.lock().share_state = ShareState::SharedWithVforkChild;
    }

    /// Explicit release when the `vfork` child completes `execve` or `_exit`.
    pub fn child_exec_or_exit_released(&self) {
        self.inner.lock().share_state = ShareState::Exclusive;
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
        self.inner.lock().manager.clone()
    }

    /// Execute a closure with a reference to the inner `PageTableManager`, if present.
    pub fn with_manager<F, R>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&PageTableManager) -> R,
    {
        self.inner.lock().manager.as_ref().map(f)
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
            let manager = builder()?;
            let had_source = inner.arena_source.is_some();
            carrick_observability::probes::stage1_arena_install(
                4,
                u32::from(had_source),
                0,
                authority,
            );
            inner.manager = Some(manager);
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
                Ok(manager) => {
                    carrick_observability::probes::stage1_arena_install(2, 1, 0, authority);
                    inner.arena_source = Some(source);
                    inner.manager = Some(manager);
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
            let manager = builder()?;
            let had_source = inner.arena_source.is_some();
            carrick_observability::probes::stage1_arena_install(
                4,
                u32::from(had_source),
                0,
                authority,
            );
            inner.manager = Some(manager);
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
    ///
    /// Adopts live extension arenas from the active manager into `image`, retains
    /// this authority's arena source, fires `stage1_arena_replace(site, before, after, authority)`,
    /// and replaces the manager. Returns the replaced manager.
    ///
    /// Note: `stage1_arena_replace` probes fire `before == after` by construction because the
    /// `TableArenaSource` is exclusively owned by this `Stage1Authority` and is invariant
    /// across manager image restores.
    pub fn restore_image(
        &self,
        mut image: PageTableManager,
        site: u32,
    ) -> Option<PageTableManager> {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if let Some(live) = inner.manager.as_ref() {
            let before = u32::from(inner.arena_source.is_some());
            image.adopt_live_extension_state(live);
            let after = before;
            carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        }
        inner.manager.replace(image)
    }

    /// Like [`Self::restore_image`], but also restores quiesced table descriptors to host memory.
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
        mut image: PageTableManager,
        site: u32,
        resolve_page_table_host: H,
    ) -> Option<PageTableManager>
    where
        H: HostArenaResolver,
    {
        let authority = self.authority_id();
        let mut inner = self.inner.lock();
        if let Some(live) = inner.manager.as_ref() {
            let before = u32::from(inner.arena_source.is_some());
            image.adopt_live_extension_state(live);
            let after = before;
            carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        }
        unsafe { image.restore_quiesced_snapshot_to_host(resolve_page_table_host) };
        inner.manager.replace(image)
    }

    /// Replace the stage-1 authority for `execve`.
    ///
    /// - If `SharedWithVforkChild`: the shared authority belongs to the parent!
    ///   Transitions the parent's authority back to `Exclusive` without touching
    ///   its manager or extension arenas; creates and returns a brand-new `Stage1Authority`
    ///   with `builder()?` for the child.
    /// - If `Exclusive`: retires the old image's extension arenas via `retirer`,
    ///   retires its arena source WITH it (the source belongs to the lease of
    ///   the mm being replaced; the runtime installs the replacement lease's
    ///   source right after `execve_into`, and a stale source would refuse it
    ///   `ConflictingArenaSource`), installs the new manager, fires probe
    ///   site 5, and returns `self.clone()` — the authority identity survives.
    pub fn replace_for_exec<B, R, E>(
        &mut self,
        builder: B,
        mut retirer: R,
    ) -> Result<Stage1Authority, E>
    where
        B: FnOnce() -> Result<Option<PageTableManager>, E>,
        R: FnMut(&mut PageTableManager) -> Result<(), E>,
    {
        let is_shared = {
            let mut inner = self.inner.lock();
            if inner.share_state == ShareState::SharedWithVforkChild {
                inner.share_state = ShareState::Exclusive;
                true
            } else {
                false
            }
        };

        if is_shared {
            let new_manager = builder()?;
            let new_authority = Stage1Authority::new_with_manager(new_manager);
            *self = new_authority.clone();
            Ok(new_authority)
        } else {
            let (mut old_mgr, old_source) = {
                let mut inner = self.inner.lock();
                (inner.manager.take(), inner.arena_source.take())
            };
            if let Some(mut old) = old_mgr.take() {
                retirer(&mut old)?;
            }
            // The retired image's source retires with it: its extension
            // arenas were just handed back and the replacement lease brings
            // its own source.
            drop(old_source);
            let new_manager = builder()?;
            let authority = self.authority_id();
            let mut inner = self.inner.lock();
            inner.manager = new_manager;
            if inner.manager.is_some() {
                carrick_observability::probes::stage1_arena_install(5, 0, 0, authority);
            }
            Ok(self.clone())
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
            let before = u32::from(new_guard.arena_source.is_some());
            if let Some(old_source) = prev_guard.arena_source.take()
                && new_guard.arena_source.is_none()
            {
                new_guard.arena_source = Some(old_source);
            }
            if let Some(old) = prev_guard.manager.take() {
                if let Some(new_mgr) = new_guard.manager.as_mut() {
                    new_mgr.adopt_live_extension_state(&old);
                    prev_guard.manager = Some(old);
                } else {
                    new_guard.manager = Some(old);
                }
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
        op: carrick_mem::page_table::PtOp,
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
        resolver: impl carrick_mem::page_table::HostArenaResolver,
    ) -> Vec<u64> {
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
    pub unsafe fn rollback_undo_retiring<E>(
        &mut self,
        resolver: impl carrick_mem::page_table::HostArenaResolver,
        retire: impl FnOnce(&[u64]) -> Result<(), E>,
    ) -> Result<Vec<u64>, E> {
        let popped = unsafe { self.manager.rollback_undo(resolver, None) };
        retire(&popped)?;
        if let Some(source) = self.arena_source.as_deref_mut() {
            for &base in &popped {
                source.return_arena(carrick_guest_mem::Gpa(base));
            }
        }
        Ok(popped)
    }

    /// Restore a pre-transaction image over the live manager, adopting extension arenas,
    /// preserving the arena source, and firing `stage1_arena_replace`.
    pub fn restore_image(&mut self, mut image: PageTableManager, site: u32, authority: u64) {
        let before = u32::from(self.arena_source.is_some());
        image.adopt_live_extension_state(self.manager);
        let after = before;
        carrick_observability::probes::stage1_arena_replace(site, before, after, authority);
        *self.manager = image;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::Gpa;
    use carrick_mem::memory::{
        LINUX_MMAP_BASE, LINUX_PAGE_TABLES_BASE, LINUX_PAGE_TABLES_SIZE, stage1_hvpatch_page_tables,
    };
    use carrick_mem::page_table::{TableArenaSource, TableArenaSourceId};
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

        fn take_arena(&mut self) -> Option<Gpa> {
            self.available.lock().unwrap().pop()
        }

        fn return_arena(&mut self, gpa: Gpa) {
            self.returned.lock().unwrap().push(gpa);
        }
    }

    #[test]
    fn exec_replacement_drops_the_retired_source_so_the_replacement_lease_installs() {
        // A forked child that execs: the runtime installs the source for the
        // REPLACEMENT lease after `execve_into`. The retired image's source
        // must go with the retired image, or the install refuses
        // `ConflictingArenaSource` and the exec dies past its point of no
        // return (busybox `sh -c /bin/true` under the first landing).
        let old = CountingArenaSource {
            id: TableArenaSourceId(Gpa(LINUX_PAGE_TABLES_BASE)),
            available: Arc::new(Mutex::new(Vec::new())),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let replacement = CountingArenaSource {
            id: TableArenaSourceId(Gpa(0x9a_0020_0000)),
            available: Arc::new(Mutex::new(Vec::new())),
            returned: Arc::new(Mutex::new(Vec::new())),
        };
        let manager = PageTableManager::new(stage1_hvpatch_page_tables(), LINUX_PAGE_TABLES_BASE);
        let mut authority = Stage1Authority::new_with_manager(Some(manager));
        authority
            .install_source(Box::new(old))
            .expect("install the pre-exec source");
        let retired = authority
            .replace_for_exec(
                || {
                    Ok::<_, PageTableError>(Some(PageTableManager::new(
                        stage1_hvpatch_page_tables(),
                        LINUX_PAGE_TABLES_BASE,
                    )))
                },
                |_| Ok(()),
            )
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
            id: TableArenaSourceId(root),
            available: Arc::clone(&available),
            returned: Arc::clone(&returned),
        };

        let mut manager =
            PageTableManager::new(stage1_hvpatch_page_tables(), LINUX_PAGE_TABLES_BASE);
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
        let resolver = move |base: u64| {
            if base == LINUX_PAGE_TABLES_BASE {
                Some(p0)
            } else if base == ext_base.0 {
                Some(p1)
            } else {
                None
            }
        };

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
                            editor.rollback_undo_retiring(resolver, |bases| {
                                assert_eq!(bases, &[ext_base.0]);
                                assert!(
                                    returned.lock().unwrap().is_empty(),
                                    "arena address escaped before backing retirement"
                                );
                                assert!(available.lock().unwrap().is_empty());
                                if fail_retirement { Err(()) } else { Ok(()) }
                            })
                        };
                        if fail_retirement {
                            assert!(result.is_err());
                            assert!(returned.lock().unwrap().is_empty());
                            assert_eq!(editor.pool_stats().3, 1);
                            return Ok(());
                        }
                        result.unwrap()
                    } else {
                        unsafe { editor.rollback_undo(resolver) }
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
}
