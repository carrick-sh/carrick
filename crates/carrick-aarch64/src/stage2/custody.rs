//! Generation-bound stage-2 custody: the one owner of a carrier VM's
//! lifecycle and the only way to reach its [`Stage2Backend`].
//!
//! A carrier's stage 2 exists from `begin_create` until the raw destroy. Every
//! map, unmap and the raw destroy itself run under the custody's lifecycle
//! lock, through a [`Stage2Generation`] guard that only this module can mint.
//! So:
//!
//! - a mapping records the generation it was installed in at map time
//!   ([`Stage2Mapping`]); nothing samples the generation afterwards;
//! - an unmap of a mapping whose generation is gone never reaches the backend
//!   (it would hit the successor VM): the guard for a later generation, or
//!   [`Stage2Custody::stage2_in`] returning [`Stage2Gone`], says so with no
//!   check-to-unmap window;
//! - the raw destroy runs with the lock held, then publishes
//!   [`Stage2Lifecycle::Gone`], so no admission can succeed for a VM that no
//!   longer exists, whether it was `Creating` or `Destroying`;
//! - a mapping whose unmap failed stays in the custody's unretired list with
//!   the backing that keeps its host range alive, until an idle retry unmaps
//!   it or its generation's raw destroy drains it.
//!
//! **Lock order.** The custody state lock comes first. Every lock a backend
//! client takes while it may map or unmap (frame pools, fork stock, replay
//! registries) is a [`Stage2Inner`] and is taken under the guard, never the
//! other way round. Taking the custody lock while this thread holds a
//! `Stage2Inner` lock is a broken invariant and panics at the acquisition, so
//! an inversion fails the first test that reaches it instead of deadlocking
//! under load.

use core::cell::{Cell, RefCell};
use core::ops::{Deref, DerefMut};

use carrick_core_abi::mm::custody::CarrierVmGeneration;
use carrick_hal::MemPerms;
use parking_lot::{Mutex, MutexGuard};

use super::{Stage2Backend, Stage2Status};

/// Where the carrier VM of one custody is in its life.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2Lifecycle {
    /// No VM, and no stage 2.
    Vacant,
    /// The VM exists and is being set up; its stage 2 accepts mappings.
    Creating(CarrierVmGeneration),
    /// The VM runs; its stage 2 accepts mappings.
    Live(CarrierVmGeneration),
    /// Teardown began: the stage 2 still exists, so unmaps reach it, but it
    /// admits no new mapping.
    Destroying(CarrierVmGeneration),
    /// The raw destroy succeeded: the stage 2 is gone. The backend's own
    /// settlement still has to finish before a successor may be created.
    Gone(CarrierVmGeneration),
}

impl Stage2Lifecycle {
    /// The generation whose stage 2 exists now, if any.
    pub fn stage2_generation(self) -> Option<CarrierVmGeneration> {
        match self {
            Self::Creating(generation) | Self::Live(generation) | Self::Destroying(generation) => {
                Some(generation)
            }
            Self::Vacant | Self::Gone(_) => None,
        }
    }

    /// The generation that admits new mappings, if any.
    pub fn admitting_generation(self) -> Option<CarrierVmGeneration> {
        match self {
            Self::Creating(generation) | Self::Live(generation) => Some(generation),
            Self::Vacant | Self::Destroying(_) | Self::Gone(_) => None,
        }
    }
}

/// A lifecycle transition that the custody refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2CustodyError {
    /// The lifecycle is not in the state this transition starts from.
    LifecycleConflict,
    /// The lifecycle names another generation.
    StaleGeneration,
    /// The generation counter is exhausted.
    GenerationExhausted,
    /// The backend refused the raw destroy; the exact lifecycle is kept.
    Backend(Stage2Status),
    /// The stage 2 is gone, but the backend's own settlement of it (grants,
    /// pools) could not finish; the generation stays `Gone`, admitting no
    /// successor.
    UnsettledAfterDestroy,
}

/// The stage 2 of the asked-for generation no longer exists (or never did):
/// any mapping in it is gone with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stage2Gone;

/// In-process unique token identifying one [`Stage2Custody`] instance for as
/// long as the custody or any [`Stage2Mapping`] it issued stays alive.
#[derive(Clone)]
struct CustodyToken(std::sync::Arc<()>);

impl CustodyToken {
    fn new() -> Self {
        Self(std::sync::Arc::new(()))
    }
}

impl PartialEq for CustodyToken {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for CustodyToken {}

impl core::fmt::Debug for CustodyToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Custody({:p})", std::sync::Arc::as_ptr(&self.0))
    }
}

/// One installed stage-2 extent, stamped with the issuing custody and
/// generation of the guard that installed it. Only [`Stage2Generation::map`]
/// makes one, and only an unmap or its generation's destroy ends it, so a lease
/// can never hold a mapping without knowing which custody and VM hold it.
#[must_use = "a stage-2 mapping must be unmapped or outlived by its VM's destroy"]
#[derive(Debug, Eq, PartialEq)]
pub struct Stage2Mapping {
    custody: CustodyToken,
    generation: CarrierVmGeneration,
    ipa: u64,
    size: usize,
    perms: MemPerms,
}

impl Stage2Mapping {
    /// The generation whose stage 2 holds this extent.
    pub fn generation(&self) -> CarrierVmGeneration {
        self.generation
    }

    /// The extent's first guest-physical address.
    pub fn ipa(&self) -> u64 {
        self.ipa
    }

    /// The extent's length in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The stage-2 permissions installed for this extent.
    pub fn perms(&self) -> MemPerms {
        self.perms
    }
}

/// What keeps an unretired mapping's host range alive. Dropping it releases
/// the backing, so the custody drops it only once the mapping is gone.
pub type Stage2Backing = Box<dyn core::any::Any + Send>;

/// A mapping whose unmap failed, held with the backing of its host range.
struct UnretiredStage2 {
    mapping: Stage2Mapping,
    backing: Stage2Backing,
}

/// The lifecycle-locked state: the lifecycle, the unretired list, and the
/// backend's own records (`R`), which deref through every guard.
pub struct Stage2CustodyState<R> {
    lifecycle: Stage2Lifecycle,
    next_generation: u64,
    unretired: Vec<UnretiredStage2>,
    records: R,
}

impl<R> Stage2CustodyState<R> {
    /// The lifecycle, read under the lock.
    pub fn lifecycle(&self) -> Stage2Lifecycle {
        self.lifecycle
    }

    /// Forge the lifecycle, so a test can show a check failing closed for
    /// one exact reason (test builds only; production moves it only through
    /// the custody's transitions).
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_lifecycle_for_test(&mut self, lifecycle: Stage2Lifecycle) {
        self.lifecycle = lifecycle;
    }

    /// How many unretired mappings the custody still holds.
    pub fn unretired_count(&self) -> usize {
        self.unretired.len()
    }
}

impl<R> Deref for Stage2CustodyState<R> {
    type Target = R;
    fn deref(&self) -> &R {
        &self.records
    }
}

impl<R> DerefMut for Stage2CustodyState<R> {
    fn deref_mut(&mut self) -> &mut R {
        &mut self.records
    }
}

/// A named point in a custody transaction, where a test can park the real
/// sequence to order a race (the hook exists only in test builds).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage2HookPoint {
    /// The raw destroy of this generation is about to run, with the custody
    /// lock held.
    RawDestroyHoldingLock(CarrierVmGeneration),
    /// `begin_destroy` published `Destroying` and released the lock.
    DestroyingPublished(CarrierVmGeneration),
    /// A thread found the custody lock held and is about to wait for it
    /// (`operation` names the custody call): the event a race witness waits
    /// on to know its rival is excluded, with no sleep.
    LockContended(&'static str),
    /// A named point in a backend client's own custody transaction.
    Client(&'static str),
}

#[cfg(any(test, feature = "test-support"))]
type Stage2Hook = std::sync::Arc<dyn Fn(Stage2HookPoint) + Send + Sync>;

/// Generation-bound stage-2 custody over one backend.
pub struct Stage2Custody<R> {
    custody: CustodyToken,
    backend: Box<dyn Stage2Backend + Send>,
    state: Mutex<Stage2CustodyState<R>>,
    #[cfg(any(test, feature = "test-support"))]
    hook: Mutex<Option<Stage2Hook>>,
}

impl<R> core::fmt::Debug for Stage2Custody<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Stage2Custody")
            .field("lifecycle", &self.lifecycle())
            .finish_non_exhaustive()
    }
}

/// The custody lock, held without a generation: record bookkeeping and
/// lifecycle reads, but no backend access.
pub struct Stage2StateGuard<'a, R> {
    state: HeldState<'a, R>,
}

impl<R> Deref for Stage2StateGuard<'_, R> {
    type Target = Stage2CustodyState<R>;
    fn deref(&self) -> &Stage2CustodyState<R> {
        &self.state
    }
}

impl<R> DerefMut for Stage2StateGuard<'_, R> {
    fn deref_mut(&mut self) -> &mut Stage2CustodyState<R> {
        &mut self.state
    }
}

/// Proof that generation `g`'s stage 2 exists, held for as long as the guard
/// lives: the custody lock is held, so no raw destroy can run. It is the only
/// way to map or unmap.
pub struct Stage2Generation<'a, R> {
    custody: &'a CustodyToken,
    state: HeldState<'a, R>,
    backend: &'a (dyn Stage2Backend + Send),
    generation: CarrierVmGeneration,
}

impl<R> Deref for Stage2Generation<'_, R> {
    type Target = Stage2CustodyState<R>;
    fn deref(&self) -> &Stage2CustodyState<R> {
        &self.state
    }
}

impl<R> DerefMut for Stage2Generation<'_, R> {
    fn deref_mut(&mut self) -> &mut Stage2CustodyState<R> {
        &mut self.state
    }
}

impl<R> Stage2Generation<'_, R> {
    /// The generation whose stage 2 this guard holds.
    pub fn generation(&self) -> CarrierVmGeneration {
        self.generation
    }

    /// Whether this generation still admits new mappings (it is `Creating`
    /// or `Live`, not `Destroying`).
    pub fn admits_mappings(&self) -> bool {
        self.state.lifecycle.admitting_generation() == Some(self.generation)
    }

    /// Install `[host, host + size)` at `[ipa, ipa + size)` in this
    /// generation's stage 2. A `Destroying` generation refuses with
    /// [`Stage2Status::NO_LIVE_VM`] and never reaches the backend.
    ///
    /// # Safety
    ///
    /// As [`Stage2Backend::map`]: the host range stays mapped and unused for
    /// anything else until the returned mapping is unmapped or its
    /// generation is destroyed.
    pub unsafe fn map(
        &mut self,
        host: *mut core::ffi::c_void,
        ipa: u64,
        size: usize,
        perms: MemPerms,
    ) -> Result<Stage2Mapping, Stage2Status> {
        if !self.admits_mappings() {
            return Err(Stage2Status::NO_LIVE_VM);
        }
        // SAFETY: forwarded from this function's contract; the lock excludes
        // the raw destroy, so the generation's stage 2 exists.
        let status = unsafe { self.backend.map(host, ipa, size, perms) };
        if !status.is_success() {
            return Err(status);
        }
        Ok(Stage2Mapping {
            custody: self.custody.clone(),
            generation: self.generation,
            ipa,
            size,
            perms,
        })
    }

    /// Remove `mapping`. A mapping of an earlier generation is gone with that
    /// generation's stage 2, so it is consumed without a backend call (an
    /// unmap now would hit this VM instead). A refused unmap hands the
    /// mapping back with the backend's status.
    ///
    /// # Safety
    ///
    /// As [`Stage2Backend::unmap`]: no guest CPU may depend on the extent
    /// once this returns success.
    pub unsafe fn unmap(
        &mut self,
        mapping: Stage2Mapping,
    ) -> Result<(), (Stage2Mapping, Stage2Status)> {
        assert!(
            mapping.custody == *self.custody,
            "stage-2 mapping of {:?} offered to foreign {:?}",
            mapping.custody,
            self.custody
        );
        if mapping.generation != self.generation {
            assert!(
                mapping.generation.0 < self.generation.0,
                "stage-2 mapping of generation {:?} offered to the older generation {:?}",
                mapping.generation,
                self.generation
            );
            return Ok(());
        }
        // SAFETY: forwarded; the lock excludes the raw destroy.
        let status = unsafe { self.backend.unmap(mapping.ipa, mapping.size) };
        if status.is_success() {
            Ok(())
        } else {
            Err((mapping, status))
        }
    }

    /// Keep a mapping whose unmap failed, with the backing of its host range,
    /// until [`Self::retry_unretired`] unmaps it or its generation's raw
    /// destroy drains it. A mapping of an earlier generation is already
    /// gone, so its backing is handed straight back for the caller to drop.
    pub fn keep_unretired(
        &mut self,
        mapping: Stage2Mapping,
        backing: Stage2Backing,
    ) -> Option<Stage2Backing> {
        assert!(
            mapping.custody == *self.custody,
            "stage-2 mapping of {:?} kept on foreign {:?}",
            mapping.custody,
            self.custody
        );
        if mapping.generation != self.generation {
            return Some(backing);
        }
        self.state
            .unretired
            .push(UnretiredStage2 { mapping, backing });
        None
    }

    /// Retry every unretired mapping of this generation once. Returns the
    /// backings whose mapping is now gone, for the caller to drop after it
    /// releases the guard (a backing's drop may take locks below this one).
    pub fn retry_unretired(&mut self) -> Vec<Stage2Backing> {
        let pending = core::mem::take(&mut self.state.unretired);
        let mut released = Vec::new();
        for entry in pending {
            let UnretiredStage2 { mapping, backing } = entry;
            // SAFETY: an unretired mapping has no guest dependence left: its
            // owner already gave it up and only the unmap failed.
            match unsafe { self.unmap(mapping) } {
                Ok(()) => released.push(backing),
                Err((mapping, _)) => self
                    .state
                    .unretired
                    .push(UnretiredStage2 { mapping, backing }),
            }
        }
        released
    }
}

thread_local! {
    /// How many [`Stage2Inner`] locks this thread holds.
    static STAGE2_INNER_HELD: Cell<usize> = const { Cell::new(0) };
    /// The custodies (by address) whose lock this thread holds.
    static STAGE2_CUSTODY_HELD: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// A thread that already holds a custody's lock and asks for it again would
/// wait on itself forever. That is a broken invariant (a callback run under
/// the guard re-entered the custody), so it panics at the acquisition.
fn assert_custody_not_held(custody: usize, operation: &'static str) {
    let held = STAGE2_CUSTODY_HELD.with(|held| held.borrow().contains(&custody));
    assert!(
        !held,
        "stage-2 custody re-entry: {operation} took the custody lock this thread already \
         holds (a callback run under the custody's guard re-entered it)"
    );
}

/// The custody lock, held: it records itself as held by this thread until
/// it drops, so a re-entry panics instead of deadlocking.
struct HeldState<'a, R> {
    guard: MutexGuard<'a, Stage2CustodyState<R>>,
    custody: usize,
}

impl<'a, R> HeldState<'a, R> {
    fn new(guard: MutexGuard<'a, Stage2CustodyState<R>>, custody: usize) -> Self {
        STAGE2_CUSTODY_HELD.with(|held| held.borrow_mut().push(custody));
        Self { guard, custody }
    }
}

impl<R> Drop for HeldState<'_, R> {
    fn drop(&mut self) {
        STAGE2_CUSTODY_HELD.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(index) = held.iter().rposition(|&custody| custody == self.custody) {
                held.remove(index);
            }
        });
    }
}

impl<R> Deref for HeldState<'_, R> {
    type Target = Stage2CustodyState<R>;
    fn deref(&self) -> &Stage2CustodyState<R> {
        &self.guard
    }
}

impl<R> DerefMut for HeldState<'_, R> {
    fn deref_mut(&mut self) -> &mut Stage2CustodyState<R> {
        &mut self.guard
    }
}

fn assert_no_inner_lock_held(operation: &'static str) {
    let held = STAGE2_INNER_HELD.with(Cell::get);
    assert!(
        held == 0,
        "stage-2 lock order: {operation} took the custody lock while holding {held} \
         Stage2Inner lock(s); the custody lock comes first"
    );
}

/// A lock below the custody lock in the stage-2 lock order. Taking the
/// custody lock while holding one panics.
#[derive(Debug, Default)]
pub struct Stage2Inner<T> {
    inner: Mutex<T>,
}

/// A held [`Stage2Inner`] lock.
pub struct Stage2InnerGuard<'a, T> {
    guard: MutexGuard<'a, T>,
}

impl<T> Stage2Inner<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    pub fn lock(&self) -> Stage2InnerGuard<'_, T> {
        let guard = self.inner.lock();
        STAGE2_INNER_HELD.with(|held| held.set(held.get() + 1));
        Stage2InnerGuard { guard }
    }

    pub fn try_lock(&self) -> Option<Stage2InnerGuard<'_, T>> {
        let guard = self.inner.try_lock()?;
        STAGE2_INNER_HELD.with(|held| held.set(held.get() + 1));
        Some(Stage2InnerGuard { guard })
    }
}

impl<T> Drop for Stage2InnerGuard<'_, T> {
    fn drop(&mut self) {
        STAGE2_INNER_HELD.with(|held| held.set(held.get() - 1));
    }
}

impl<T> Deref for Stage2InnerGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for Stage2InnerGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

/// What the raw destroy released: the backings of the generation's
/// unretired mappings, for the caller to drop after it settles.
#[must_use]
pub struct Stage2Destroyed {
    pub generation: CarrierVmGeneration,
    pub released_backings: Vec<Stage2Backing>,
}

impl<R> Stage2Custody<R> {
    /// A vacant custody over `backend`, with the backend's own records.
    pub fn new(backend: Box<dyn Stage2Backend + Send>, records: R) -> Self {
        Self {
            custody: CustodyToken::new(),
            backend,
            state: Mutex::new(Stage2CustodyState {
                lifecycle: Stage2Lifecycle::Vacant,
                next_generation: 1,
                unretired: Vec::new(),
                records,
            }),
            #[cfg(any(test, feature = "test-support"))]
            hook: Mutex::new(None),
        }
    }

    fn lock_state(&self, operation: &'static str) -> HeldState<'_, R> {
        assert_no_inner_lock_held(operation);
        let custody = core::ptr::from_ref(self).addr();
        assert_custody_not_held(custody, operation);
        #[cfg(any(test, feature = "test-support"))]
        {
            if let Some(guard) = self.state.try_lock() {
                return HeldState::new(guard, custody);
            }
            self.at(Stage2HookPoint::LockContended(operation));
        }
        HeldState::new(self.state.lock(), custody)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn at(&self, point: Stage2HookPoint) {
        let hook = self.hook.lock().clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }

    #[cfg(not(any(test, feature = "test-support")))]
    #[inline(always)]
    fn at(&self, _point: Stage2HookPoint) {}

    /// Mark a named point in a backend client's custody transaction, where a
    /// test hook can order a race (a no-op outside test builds).
    #[inline(always)]
    pub fn at_client_point(&self, name: &'static str) {
        self.at(Stage2HookPoint::Client(name));
    }

    /// Park the custody's transactions at named points (tests only).
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_hook(&self, hook: Option<Stage2Hook>) {
        *self.hook.lock() = hook;
    }

    /// The custody lock without a generation: records and lifecycle only.
    pub fn lock(&self) -> Stage2StateGuard<'_, R> {
        Stage2StateGuard {
            state: self.lock_state("lock"),
        }
    }

    /// The current lifecycle (a snapshot: hold a guard to act on it).
    pub fn lifecycle(&self) -> Stage2Lifecycle {
        self.lock_state("lifecycle").lifecycle
    }

    /// The guard for generation `generation`, or [`Stage2Gone`] if its stage
    /// 2 no longer exists. A caller that found its mapping gone forgets it.
    pub fn stage2_in(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<Stage2Generation<'_, R>, Stage2Gone> {
        let state = self.lock_state("stage2_in");
        if state.lifecycle.stage2_generation() != Some(generation) {
            return Err(Stage2Gone);
        }
        Ok(Stage2Generation {
            custody: &self.custody,
            state,
            backend: &*self.backend,
            generation,
        })
    }

    /// The guard for whichever generation's stage 2 exists now.
    pub fn stage2(&self) -> Option<Stage2Generation<'_, R>> {
        let state = self.lock_state("stage2");
        let generation = state.lifecycle.stage2_generation()?;
        Some(Stage2Generation {
            custody: &self.custody,
            state,
            backend: &*self.backend,
            generation,
        })
    }

    /// Unmap `mapping` if its stage 2 still exists; a gone generation
    /// consumes it with no backend call.
    ///
    /// # Safety
    ///
    /// As [`Stage2Generation::unmap`].
    pub unsafe fn unmap(
        &self,
        mapping: Stage2Mapping,
    ) -> Result<(), (Stage2Mapping, Stage2Status)> {
        assert!(
            mapping.custody == self.custody,
            "stage-2 mapping of {:?} offered to foreign {:?}",
            mapping.custody,
            self.custody
        );
        match self.stage2_in(mapping.generation) {
            // SAFETY: forwarded.
            Ok(mut guard) => unsafe { guard.unmap(mapping) },
            Err(Stage2Gone) => Ok(()),
        }
    }

    /// `Vacant` to `Creating(g)` for a fresh generation.
    pub fn begin_create(&self) -> Result<CarrierVmGeneration, Stage2CustodyError> {
        let mut state = self.lock_state("begin_create");
        if state.lifecycle != Stage2Lifecycle::Vacant {
            return Err(Stage2CustodyError::LifecycleConflict);
        }
        let next = state
            .next_generation
            .checked_add(1)
            .ok_or(Stage2CustodyError::GenerationExhausted)?;
        let generation = CarrierVmGeneration(state.next_generation);
        state.next_generation = next;
        state.lifecycle = Stage2Lifecycle::Creating(generation);
        Ok(generation)
    }

    /// `Creating(g)` to `Live(g)`; `publish` runs under the lock just before.
    pub fn commit_create_with(
        &self,
        generation: CarrierVmGeneration,
        publish: impl FnOnce(&mut R),
    ) -> Result<(), Stage2CustodyError> {
        let mut state = self.lock_state("commit_create");
        match state.lifecycle {
            Stage2Lifecycle::Creating(current) if current == generation => {
                publish(&mut state.records);
                state.lifecycle = Stage2Lifecycle::Live(generation);
                Ok(())
            }
            Stage2Lifecycle::Creating(_) | Stage2Lifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            _ => Err(Stage2CustodyError::LifecycleConflict),
        }
    }

    /// `Creating(g)` to `Vacant` when the backend never created the VM.
    pub fn abort_create(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        let mut state = self.lock_state("abort_create");
        match state.lifecycle {
            Stage2Lifecycle::Creating(current) if current == generation => {
                state.lifecycle = Stage2Lifecycle::Vacant;
                Ok(())
            }
            Stage2Lifecycle::Creating(_) | Stage2Lifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            _ => Err(Stage2CustodyError::LifecycleConflict),
        }
    }

    /// `Live(g)` to `Destroying(g)`: no new mapping is admitted, unmaps still
    /// reach the stage 2.
    pub fn begin_destroy(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        {
            let mut state = self.lock_state("begin_destroy");
            match state.lifecycle {
                Stage2Lifecycle::Live(current) if current == generation => {
                    state.lifecycle = Stage2Lifecycle::Destroying(generation);
                }
                Stage2Lifecycle::Live(_) => return Err(Stage2CustodyError::StaleGeneration),
                _ => return Err(Stage2CustodyError::LifecycleConflict),
            }
        }
        self.at(Stage2HookPoint::DestroyingPublished(generation));
        Ok(())
    }

    /// `Destroying(g)` back to `Live(g)` when teardown is abandoned before
    /// the raw destroy.
    pub fn abort_destroy(&self, generation: CarrierVmGeneration) -> Result<(), Stage2CustodyError> {
        let mut state = self.lock_state("abort_destroy");
        match state.lifecycle {
            Stage2Lifecycle::Destroying(current) if current == generation => {
                state.lifecycle = Stage2Lifecycle::Live(generation);
                Ok(())
            }
            Stage2Lifecycle::Destroying(_) | Stage2Lifecycle::Live(_) => {
                Err(Stage2CustodyError::StaleGeneration)
            }
            _ => Err(Stage2CustodyError::LifecycleConflict),
        }
    }

    /// The raw destroy of generation `g`'s stage 2, from `Destroying(g)` or
    /// (for a failed setup) `Creating(g)`, with the custody lock held
    /// throughout: no map or unmap can run beside it, and on success the
    /// lifecycle is `Gone(g)` before the lock is released, with `settle`
    /// having run on the records under the same lock. A refused destroy
    /// keeps the exact lifecycle.
    ///
    /// # Safety
    ///
    /// As [`Stage2Backend::destroy`]: no guest CPU of the VM may still run.
    pub unsafe fn destroy_stage2(
        &self,
        generation: CarrierVmGeneration,
        settle: impl FnOnce(&mut R, CarrierVmGeneration),
    ) -> Result<Stage2Destroyed, Stage2CustodyError> {
        let mut state = self.lock_state("destroy_stage2");
        match state.lifecycle {
            Stage2Lifecycle::Destroying(current) | Stage2Lifecycle::Creating(current)
                if current == generation => {}
            Stage2Lifecycle::Destroying(_)
            | Stage2Lifecycle::Creating(_)
            | Stage2Lifecycle::Live(_) => return Err(Stage2CustodyError::StaleGeneration),
            Stage2Lifecycle::Vacant | Stage2Lifecycle::Gone(_) => {
                return Err(Stage2CustodyError::LifecycleConflict);
            }
        }
        self.at(Stage2HookPoint::RawDestroyHoldingLock(generation));
        // SAFETY: forwarded; the lock excludes every map and unmap.
        let status = unsafe { self.backend.destroy() };
        if !status.is_success() {
            return Err(Stage2CustodyError::Backend(status));
        }
        state.lifecycle = Stage2Lifecycle::Gone(generation);
        settle(&mut state.records, generation);
        let mut released_backings = Vec::new();
        let unretired = core::mem::take(&mut state.unretired);
        for entry in unretired {
            if entry.mapping.generation == generation {
                released_backings.push(entry.backing);
            } else {
                state.unretired.push(entry);
            }
        }
        Ok(Stage2Destroyed {
            generation,
            released_backings,
        })
    }

    /// `Gone(g)` to `Vacant` once the backend's settlement finished; only
    /// then may a successor generation be created.
    pub fn finish_destroy(
        &self,
        generation: CarrierVmGeneration,
    ) -> Result<(), Stage2CustodyError> {
        let mut state = self.lock_state("finish_destroy");
        match state.lifecycle {
            Stage2Lifecycle::Gone(current) if current == generation => {
                state.lifecycle = Stage2Lifecycle::Vacant;
                Ok(())
            }
            Stage2Lifecycle::Gone(_) => Err(Stage2CustodyError::StaleGeneration),
            _ => Err(Stage2CustodyError::LifecycleConflict),
        }
    }
}

#[cfg(test)]
mod tests;
