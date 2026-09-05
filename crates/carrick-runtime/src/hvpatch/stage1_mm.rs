use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::{Mutex, RwLock};

use super::asid::{
    AsidAllocator, AsidError, AsidGeneration, AsidLoad, AsidResidency, AsidResidencyError,
    AsidRetirement, InvalidationAck, PreparedAsidAllocatorRetirement,
    PreparedAsidResidencyRetirement, RetiredAsid,
};
use crate::kernel::{
    MmBackend, MmBackendSnapshot, MmBinding, SharedVmaSnapshotSource, SnapshotError, SnapshotTable,
    Stage1Root, Stage1RootError, Ttbr0, VmaRevision,
};

/// Per-mm stage-1 table backing. Guest frames never live in this slot.
const STAGE1_ROOT_SLOT_SIZE: u64 = 2 * 1024 * 1024;
const STAGE1_ROOT_SLOT_COUNT: u32 =
    (carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_ARENA_SIZE / STAGE1_ROOT_SLOT_SIZE) as u32;

static NEXT_ROOT_RETIREMENT_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Stage1RootSlot(u32);

impl Stage1RootSlot {
    pub(crate) fn base(self) -> u64 {
        carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE
            + u64::from(self.0) * STAGE1_ROOT_SLOT_SIZE
    }

    pub(crate) fn size(self) -> u64 {
        STAGE1_ROOT_SLOT_SIZE
    }
}

/// One-shot request proving which reusable stage-1 slot the VMM must retire.
///
/// The VMM receives only the coordinates. The nonce stays opaque and is moved
/// into a receipt only after the backend proves the exact stage-2 custody
/// record is terminal, so allocator reuse cannot race physical retirement.
#[derive(Debug)]
pub struct Stage1RootRetirementTicket {
    slot: Stage1RootSlot,
    nonce: u64,
}

impl Stage1RootRetirementTicket {
    pub(crate) fn base(&self) -> u64 {
        self.slot.base()
    }

    pub(crate) fn size(&self) -> u64 {
        self.slot.size()
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn redeem_vmm(
        self,
        proof: carrick_vmm_hvf::hvf_aarch64_engine::HvpatchMmRootRetirementProof,
    ) -> Result<Stage1RootRetirementReceipt, Stage1MmError> {
        let base = proof.root_slot_base();
        let size = proof.root_slot_size();
        if (base, size) != (self.slot.base(), self.slot.size()) {
            return Err(Stage1MmError::RootRetirementMismatch {
                expected_base: self.slot.base(),
                expected_size: self.slot.size(),
                actual_base: base,
                actual_size: size,
            });
        }
        Ok(Stage1RootRetirementReceipt {
            slot: self.slot,
            nonce: self.nonce,
        })
    }

    #[cfg(test)]
    pub(crate) fn complete_for_test(self) -> Stage1RootRetirementReceipt {
        Stage1RootRetirementReceipt {
            slot: self.slot,
            nonce: self.nonce,
        }
    }
}

/// Opaque proof that the VMM terminalized the exact reusable root slot.
#[derive(Debug)]
pub struct Stage1RootRetirementReceipt {
    slot: Stage1RootSlot,
    nonce: u64,
}

#[derive(Debug)]
pub(crate) struct Stage1MmState {
    binding: RwLock<MmBinding>,
    asid_generation: AsidGeneration,
}

impl Stage1MmState {
    fn new(binding: MmBinding, asid_generation: AsidGeneration) -> Self {
        Self {
            binding: RwLock::new(binding),
            asid_generation,
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        *self.binding.read()
    }

    fn publish_binding(&self, binding: MmBinding) {
        *self.binding.write() = binding;
    }
}

#[derive(Debug)]
pub(crate) struct Stage1MmLease {
    state: Arc<Stage1MmState>,
    backend: Arc<Stage1MmBackend>,
    asid: AsidGeneration,
    residency: AsidResidency,
    root_slot: Option<Stage1RootSlot>,
    extension_slots: Mutex<Vec<Stage1RootSlot>>,
    lifecycle: Mutex<Stage1MmLeaseLifecycle>,
    cow_invalidation_published: Arc<AtomicU64>,
    cow_invalidation: Mutex<CowInvalidationState>,
    #[cfg(test)]
    cow_invalidation_slow_paths: AtomicU64,
}

#[derive(Debug, Default)]
struct CowInvalidationState {
    generation: u64,
    pending: BTreeSet<crate::kernel::objects::ExecutorId>,
    observed: std::collections::BTreeMap<crate::kernel::objects::ExecutorId, Arc<AtomicU64>>,
}

/// Per-resident fast-path observation retained by the loaded owner executor.
/// Two atomic loads answer the no-work case; the lease mutex is entered only
/// after a published generation differs.
#[derive(Clone, Debug)]
pub(crate) struct CowInvalidationObserver {
    executor: crate::kernel::objects::ExecutorId,
    asid: AsidGeneration,
    published: Arc<AtomicU64>,
    observed: Arc<AtomicU64>,
}

impl CowInvalidationObserver {
    fn needs_service(&self) -> bool {
        self.observed.load(Ordering::Acquire) != self.published.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CowInvalidationTicket {
    asid: AsidGeneration,
    generation: carrick_hal::ForeignCowInvalidationGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CowInvalidationPublication {
    ticket: CowInvalidationTicket,
    pending: Vec<crate::kernel::objects::ExecutorId>,
}

impl CowInvalidationPublication {
    #[cfg(test)]
    pub(crate) const fn asid_generation(&self) -> AsidGeneration {
        self.ticket.asid
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> Vec<crate::kernel::objects::ExecutorId> {
        self.pending.clone()
    }

    pub(crate) const fn ticket(&self) -> CowInvalidationTicket {
        self.ticket
    }
}

impl CowInvalidationTicket {
    pub(crate) const fn asid_generation(self) -> AsidGeneration {
        self.asid
    }

    pub(crate) const fn generation(self) -> carrick_hal::ForeignCowInvalidationGeneration {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CowInvalidationError {
    #[error("stale COW ASID invalidation generation")]
    StaleGeneration,
    #[error("executor was not pending for COW ASID invalidation")]
    UnexpectedExecutor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage1MmLeaseLifecycle {
    Live,
    RetirementPrepared,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum Stage1RetirementPreparationFailpoint {
    Disabled,
    AfterLeaseGate,
    AfterResidency,
    AfterAllocator,
}

impl Stage1MmLease {
    fn new(
        asid: AsidGeneration,
        stage1_root: Stage1Root,
        root_slot: Option<Stage1RootSlot>,
    ) -> Self {
        let state = Arc::new(Stage1MmState::new(
            MmBinding {
                asid: asid.asid(),
                stage1_root,
                ttbr0: Ttbr0::for_aarch64(asid.asid(), stage1_root),
            },
            asid,
        ));
        let backend = Arc::new(Stage1MmBackend::new(Arc::clone(&state)));
        Self {
            state,
            backend,
            asid,
            residency: AsidResidency::new(asid),
            root_slot,
            extension_slots: Mutex::new(Vec::new()),
            lifecycle: Mutex::new(Stage1MmLeaseLifecycle::Live),
            cow_invalidation_published: Arc::new(AtomicU64::new(0)),
            cow_invalidation: Mutex::new(CowInvalidationState::default()),
            #[cfg(test)]
            cow_invalidation_slow_paths: AtomicU64::new(0),
        }
    }

    pub(crate) fn binding(&self) -> MmBinding {
        self.state.binding()
    }

    pub(crate) fn root_slot(&self) -> Option<Stage1RootSlot> {
        self.root_slot
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn table_arena_source(
        self: &Arc<Self>,
        pool: Stage1MmPool,
    ) -> Box<dyn carrick_mem::page_table::TableArenaSource> {
        Box::new(Stage1MmTableArenaSource {
            pool,
            lease: Arc::clone(self),
        })
    }

    #[cfg(test)]
    pub(crate) fn extension_slots(&self) -> Vec<Stage1RootSlot> {
        self.extension_slots.lock().clone()
    }

    pub(crate) fn backend(&self) -> Arc<Stage1MmBackend> {
        Arc::clone(&self.backend)
    }

    pub(crate) const fn asid_generation(&self) -> AsidGeneration {
        self.asid
    }

    pub(crate) fn foreign_stage1_identity(
        &self,
        mm: crate::kernel::MmId,
    ) -> carrick_hal::ForeignStage1Identity {
        let binding = self.binding();
        let mm = carrick_hal::ForeignMmId::from_kernel_allocation(
            std::num::NonZeroU64::new(mm.raw()).unwrap_or_else(|| std::process::abort()),
        );
        let asid = carrick_hal::ForeignAsid::from_kernel_allocation(
            std::num::NonZeroU16::new(binding.asid.raw()).unwrap_or_else(|| std::process::abort()),
        );
        let binding = carrick_hal::ForeignMmBinding::for_aarch64(asid, binding.stage1_root.gpa());
        let asid_generation = carrick_hal::ForeignAsidGeneration::from_runtime_binding(
            asid,
            std::num::NonZeroU64::new(self.asid.generation())
                .unwrap_or_else(|| std::process::abort()),
        );
        carrick_hal::ForeignStage1Identity::new(mm, binding, asid_generation)
            .unwrap_or_else(|| std::process::abort())
    }

    /// Whether this lease has stopped admitting executor loads, for either
    /// reason: the lease itself is retiring, or its ASID generation is.
    pub(crate) fn is_retiring(&self) -> bool {
        *self.lifecycle.lock() != Stage1MmLeaseLifecycle::Live || self.residency.is_retiring()
    }

    pub(crate) fn begin_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<AsidLoad, AsidResidencyError> {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != Stage1MmLeaseLifecycle::Live {
            return Err(AsidResidencyError::Retiring);
        }
        let load = self.residency.begin_load(executor)?;
        let mut state = self.cow_invalidation.lock();
        let initial = if state.pending.contains(&executor) {
            0
        } else {
            state.generation
        };
        state
            .observed
            .entry(executor)
            .or_insert_with(|| Arc::new(AtomicU64::new(initial)));
        Ok(load)
    }

    pub(crate) fn cow_invalidation_observer(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> CowInvalidationObserver {
        let observed = self
            .cow_invalidation
            .lock()
            .observed
            .get(&executor)
            .cloned()
            .unwrap_or_else(|| std::process::abort());
        CowInvalidationObserver {
            executor,
            asid: self.asid,
            published: Arc::clone(&self.cow_invalidation_published),
            observed,
        }
    }

    pub(crate) fn publish_cow_invalidation(&self) -> CowInvalidationPublication {
        let pending = self.residency.residents();
        let mut state = self.cow_invalidation.lock();
        state.generation = state
            .generation
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        let generation = carrick_hal::ForeignCowInvalidationGeneration::from_runtime_publication(
            std::num::NonZeroU64::new(state.generation).unwrap_or_else(|| std::process::abort()),
        );
        for executor in &pending {
            state
                .observed
                .entry(*executor)
                .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        }
        state.pending = pending.iter().copied().collect();
        let publication = CowInvalidationPublication {
            ticket: CowInvalidationTicket {
                asid: self.asid,
                generation,
            },
            pending,
        };
        self.cow_invalidation_published
            .store(state.generation, Ordering::Release);
        publication
    }

    pub(crate) fn pending_cow_invalidation(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Option<CowInvalidationTicket> {
        let state = self.cow_invalidation.lock();
        state
            .pending
            .contains(&executor)
            .then_some(CowInvalidationTicket {
                asid: self.asid,
                generation: carrick_hal::ForeignCowInvalidationGeneration::from_runtime_publication(
                    std::num::NonZeroU64::new(state.generation)
                        .unwrap_or_else(|| std::process::abort()),
                ),
            })
    }

    #[cfg(test)]
    fn cow_invalidation_slow_paths_for_tests(&self) -> u64 {
        self.cow_invalidation_slow_paths.load(Ordering::Relaxed)
    }

    pub(crate) fn acknowledge_cow_invalidation(
        &self,
        executor: crate::kernel::objects::ExecutorId,
        ticket: CowInvalidationTicket,
    ) -> Result<(), CowInvalidationError> {
        let mut state = self.cow_invalidation.lock();
        if ticket.asid != self.asid || ticket.generation.raw_for_probe() != state.generation {
            return Err(CowInvalidationError::StaleGeneration);
        }
        if !state.pending.remove(&executor) {
            return Err(CowInvalidationError::UnexpectedExecutor);
        }
        state
            .observed
            .get(&executor)
            .unwrap_or_else(|| std::process::abort())
            .store(state.generation, Ordering::Release);
        Ok(())
    }

    /// Mandatory exact-binding pre-entry service. A failed hardware operation
    /// leaves the ticket pending, so this executor cannot silently cross into
    /// guest with stale translations.
    pub(crate) fn service_pending_cow_invalidation<E>(
        &self,
        observer: &CowInvalidationObserver,
        invalidate: impl FnOnce(AsidGeneration) -> Result<(), E>,
    ) -> Result<(), E> {
        if observer.asid != self.asid
            || !Arc::ptr_eq(&observer.published, &self.cow_invalidation_published)
        {
            std::process::abort();
        }
        if !observer.needs_service() {
            return Ok(());
        }
        #[cfg(test)]
        self.cow_invalidation_slow_paths
            .fetch_add(1, Ordering::Relaxed);
        let Some(ticket) = self.pending_cow_invalidation(observer.executor) else {
            std::process::abort();
        };
        invalidate(ticket.asid_generation())?;
        self.acknowledge_cow_invalidation(observer.executor, ticket)
            .unwrap_or_else(|_| std::process::abort());
        Ok(())
    }

    pub(crate) fn publish_stage1_root(&self, stage1_root: u64) -> Result<MmBinding, Stage1MmError> {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != Stage1MmLeaseLifecycle::Live {
            return Err(Stage1MmError::Retired);
        }
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let binding = MmBinding {
            asid: self.asid.asid(),
            stage1_root,
            ttbr0: Ttbr0::for_aarch64(self.asid.asid(), stage1_root),
        };
        self.state.publish_binding(binding);
        Ok(binding)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Stage1MmPool {
    inner: Arc<Mutex<Stage1MmPoolInner>>,
}

#[derive(Debug)]
struct Stage1MmPoolInner {
    asids: AsidAllocator,
    free_root_slots: BTreeSet<Stage1RootSlot>,
}

fn carrier_stage1_mm_pool() -> &'static Arc<Mutex<Stage1MmPoolInner>> {
    static CELL: std::sync::OnceLock<Arc<Mutex<Stage1MmPoolInner>>> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        Arc::new(Mutex::new(Stage1MmPoolInner {
            asids: AsidAllocator::new(),
            free_root_slots: (0..STAGE1_ROOT_SLOT_COUNT).map(Stage1RootSlot).collect(),
        }))
    })
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug)]
pub(crate) struct Stage1MmTableArenaSource {
    pool: Stage1MmPool,
    lease: Arc<Stage1MmLease>,
}

impl carrick_mem::page_table::TableArenaSource for Stage1MmTableArenaSource {
    fn take_arena(&mut self) -> Option<carrick_guest_mem::Gpa> {
        let mut inner = self.pool.inner.lock();
        let slot = inner.free_root_slots.pop_first()?;
        self.lease.extension_slots.lock().push(slot);
        Some(carrick_guest_mem::Gpa(slot.base()))
    }

    fn return_arena(&mut self, base: carrick_guest_mem::Gpa) {
        let slot = {
            let mut ext = self.lease.extension_slots.lock();
            ext.iter()
                .position(|s| s.base() == base.0)
                .map(|pos| ext.remove(pos))
        };
        if let Some(slot) = slot {
            let mut inner = self.pool.inner.lock();
            inner.free_root_slots.insert(slot);
        }
    }

    fn clone_source(&self) -> Option<Box<dyn carrick_mem::page_table::TableArenaSource>> {
        Some(Box::new(self.clone()))
    }
}

impl Stage1MmPool {
    pub(crate) fn new_root(stage1_root: u64) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        let pool = Self {
            inner: Arc::clone(carrier_stage1_mm_pool()),
        };
        let inner = pool.inner.lock();
        let asid = inner.asids.allocate()?;
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let root = Arc::new(Stage1MmLease::new(asid, stage1_root, None));
        drop(inner);
        Ok((pool, root))
    }

    #[cfg(test)]
    pub(crate) fn new_root_for_tests(
        stage1_root: u64,
        asid_limit: u16,
    ) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        Self::with_allocator(stage1_root, AsidAllocator::with_limit_for_tests(asid_limit))
    }

    #[cfg(test)]
    fn with_allocator(
        stage1_root: u64,
        asids: AsidAllocator,
    ) -> Result<(Self, Arc<Stage1MmLease>), Stage1MmError> {
        let asid = asids.allocate()?;
        let stage1_root = Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(stage1_root))?;
        let root = Arc::new(Stage1MmLease::new(asid, stage1_root, None));
        Ok((
            Self {
                inner: Arc::new(Mutex::new(Stage1MmPoolInner {
                    asids,
                    free_root_slots: (0..STAGE1_ROOT_SLOT_COUNT).map(Stage1RootSlot).collect(),
                })),
            },
            root,
        ))
    }

    pub(crate) fn prepare_child(&self) -> Result<PreparedStage1Mm, Stage1MmError> {
        let mut inner = self.inner.lock();
        let root_slot = inner
            .free_root_slots
            .pop_first()
            .ok_or(Stage1MmError::RootSlotExhausted)?;
        let stage1_root = match Stage1Root::for_aarch64_4k(carrick_guest_mem::Gpa(root_slot.base()))
        {
            Ok(root) => root,
            Err(error) => {
                inner.free_root_slots.insert(root_slot);
                return Err(error.into());
            }
        };
        let asid = match inner.asids.allocate() {
            Ok(asid) => asid,
            Err(error) => {
                inner.free_root_slots.insert(root_slot);
                return Err(error.into());
            }
        };
        let lease = Arc::new(Stage1MmLease::new(asid, stage1_root, Some(root_slot)));
        drop(inner);
        Ok(PreparedStage1Mm {
            pool: self.clone(),
            lease,
            committed: false,
            #[cfg(test)]
            abort_classification_hook: None,
        })
    }

    fn release_unpublished(&self, lease: &Stage1MmLease) -> Result<(), Stage1MmError> {
        let mut inner = self.inner.lock();
        inner.asids.release_unpublished(lease.asid)?;
        if let Some(root_slot) = lease.root_slot {
            inner.free_root_slots.insert(root_slot);
        }
        for slot in lease.extension_slots.lock().drain(..) {
            inner.free_root_slots.insert(slot);
        }
        Ok(())
    }

    pub(crate) fn retire(
        &self,
        lease: &Arc<Stage1MmLease>,
    ) -> Result<Stage1MmRetirement, Stage1MmError> {
        Ok(self.prepare_retirement(lease)?.commit())
    }

    /// Reserve every layer of one exact live MM for retirement without yet
    /// publishing retirement. Lock order is lease lifecycle -> residency ->
    /// pool inventory -> ASID allocator. Commit and rollback keep the lease
    /// gate closed while visiting the same lower layers in that order, so load
    /// admission and root publication cannot observe a partially transitioned
    /// predecessor.
    pub(crate) fn prepare_retirement(
        &self,
        lease: &Arc<Stage1MmLease>,
    ) -> Result<PreparedStage1MmRetirement, Stage1MmError> {
        self.prepare_retirement_inner(lease, Stage1RetirementPreparationFailpoint::Disabled)
    }

    #[cfg(test)]
    fn prepare_retirement_with_failpoint_for_tests(
        &self,
        lease: &Arc<Stage1MmLease>,
        failpoint: Stage1RetirementPreparationFailpoint,
    ) -> Result<PreparedStage1MmRetirement, Stage1MmError> {
        self.prepare_retirement_inner(lease, failpoint)
    }

    fn prepare_retirement_inner(
        &self,
        lease: &Arc<Stage1MmLease>,
        failpoint: Stage1RetirementPreparationFailpoint,
    ) -> Result<PreparedStage1MmRetirement, Stage1MmError> {
        let mut lifecycle = lease.lifecycle.lock();
        if *lifecycle != Stage1MmLeaseLifecycle::Live {
            return Err(Stage1MmError::Retired);
        }
        *lifecycle = Stage1MmLeaseLifecycle::RetirementPrepared;
        if failpoint == Stage1RetirementPreparationFailpoint::AfterLeaseGate {
            *lifecycle = Stage1MmLeaseLifecycle::Live;
            return Err(Stage1MmError::Retired);
        }

        let residency = match lease.residency.prepare_retirement() {
            Ok(residency) => residency,
            Err(error) => {
                *lifecycle = Stage1MmLeaseLifecycle::Live;
                return Err(error.into());
            }
        };
        if failpoint == Stage1RetirementPreparationFailpoint::AfterResidency {
            drop(residency);
            *lifecycle = Stage1MmLeaseLifecycle::Live;
            return Err(Stage1MmError::Retired);
        }
        let asid = {
            let inner = self.inner.lock();
            inner.asids.prepare_retirement(lease.asid)
        };
        let asid = match asid {
            Ok(asid) => asid,
            Err(error) => {
                drop(residency);
                *lifecycle = Stage1MmLeaseLifecycle::Live;
                return Err(error.into());
            }
        };
        if failpoint == Stage1RetirementPreparationFailpoint::AfterAllocator {
            drop(asid);
            drop(residency);
            *lifecycle = Stage1MmLeaseLifecycle::Live;
            return Err(Stage1MmError::Retired);
        }
        drop(lifecycle);

        Ok(PreparedStage1MmRetirement {
            pool: self.clone(),
            lease: Arc::clone(lease),
            residency: Some(residency),
            asid: Some(asid),
            root_slot: lease.root_slot,
            finished: false,
            #[cfg(test)]
            rollback_hook: None,
        })
    }
}

/// Owned, non-cloneable reservation of the lease gate, executor residency,
/// exact allocator generation, and root slot for one stage-1 MM retirement.
#[derive(Debug)]
pub(crate) struct PreparedStage1MmRetirement {
    pool: Stage1MmPool,
    lease: Arc<Stage1MmLease>,
    residency: Option<PreparedAsidResidencyRetirement>,
    asid: Option<PreparedAsidAllocatorRetirement>,
    root_slot: Option<Stage1RootSlot>,
    finished: bool,
    #[cfg(test)]
    rollback_hook: Option<RollbackOrderHook>,
}

#[cfg(test)]
#[derive(Debug)]
struct RollbackOrderHook {
    after_allocator: Arc<std::sync::Barrier>,
    resume_after_allocator: Arc<std::sync::Barrier>,
    after_residency: Arc<std::sync::Barrier>,
    resume_after_residency: Arc<std::sync::Barrier>,
}

impl PreparedStage1MmRetirement {
    #[cfg(test)]
    fn install_rollback_hook_for_tests(&mut self, hook: RollbackOrderHook) {
        self.rollback_hook = Some(hook);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn pending(&self) -> Vec<crate::kernel::objects::ExecutorId> {
        let Some(residency) = self.residency.as_ref() else {
            std::process::abort();
        };
        residency.pending()
    }

    fn requires_quarantine(&self) -> bool {
        let Some(residency) = self.residency.as_ref() else {
            std::process::abort();
        };
        residency.requires_quarantine()
    }

    pub(crate) fn commit(mut self) -> Stage1MmRetirement {
        let mut lifecycle = self.lease.lifecycle.lock();
        assert_eq!(
            *lifecycle,
            Stage1MmLeaseLifecycle::RetirementPrepared,
            "prepared stage-1 retirement lost its lease-gate reservation"
        );
        let Some(residency) = self.residency.take() else {
            std::process::abort();
        };
        let residency = residency.commit();
        let Some(asid) = self.asid.take() else {
            std::process::abort();
        };
        let asid = asid.commit();
        *lifecycle = Stage1MmLeaseLifecycle::Retired;
        drop(lifecycle);
        self.finished = true;
        let root_retirement_nonce = self.root_slot.map(|_| {
            NEXT_ROOT_RETIREMENT_NONCE
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    current.checked_add(1)
                })
                .unwrap_or_else(|_| std::process::abort())
        });
        let extension_slots = self.lease.extension_slots.lock().drain(..).collect();
        Stage1MmRetirement {
            pool: self.pool.clone(),
            asid,
            residency,
            root_slot: self.root_slot,
            root_retirement_nonce,
            root_ticket_issued: false,
            extension_slots,
        }
    }
}

impl Drop for PreparedStage1MmRetirement {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut lifecycle = self.lease.lifecycle.lock();
        assert_eq!(
            *lifecycle,
            Stage1MmLeaseLifecycle::RetirementPrepared,
            "prepared stage-1 retirement lost its lease-gate reservation"
        );
        drop(self.asid.take());
        #[cfg(test)]
        if let Some(hook) = self.rollback_hook.as_ref() {
            hook.after_allocator.wait();
            hook.resume_after_allocator.wait();
        }
        drop(self.residency.take());
        #[cfg(test)]
        if let Some(hook) = self.rollback_hook.as_ref() {
            hook.after_residency.wait();
            hook.resume_after_residency.wait();
        }
        *lifecycle = Stage1MmLeaseLifecycle::Live;
    }
}

#[derive(Debug)]
pub(crate) struct PreparedStage1Mm {
    pool: Stage1MmPool,
    lease: Arc<Stage1MmLease>,
    committed: bool,
    #[cfg(test)]
    abort_classification_hook: Option<AbortClassificationHook>,
}

#[cfg(test)]
#[derive(Debug)]
struct AbortClassificationHook {
    reached_classification: Arc<std::sync::Barrier>,
    resume_classification: Arc<std::sync::Barrier>,
}

#[cfg(test)]
impl AbortClassificationHook {
    fn run(self) {
        self.reached_classification.wait();
        self.resume_classification.wait();
    }
}

/// Exhaustive settlement of an explicitly aborted unpublished replacement.
/// The retirement arm is deliberately non-cloneable because it owns the only
/// route from hardware-exposed quarantine back to numeric ASID/root reuse.
#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum PreparedStage1MmAbort {
    Unpublished {
        binding: MmBinding,
        root_slot: Option<Stage1RootSlot>,
    },
    Retirement(Stage1MmRetirement),
}

impl PreparedStage1Mm {
    #[cfg(test)]
    fn install_abort_classification_hook_for_tests(&mut self, hook: AbortClassificationHook) {
        self.abort_classification_hook = Some(hook);
    }

    pub(crate) fn binding(&self) -> MmBinding {
        self.lease.binding()
    }

    pub(crate) fn root_slot(&self) -> Option<Stage1RootSlot> {
        self.lease.root_slot()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn table_arena_source(&self) -> Box<dyn carrick_mem::page_table::TableArenaSource> {
        self.lease.table_arena_source(self.pool.clone())
    }

    #[cfg(test)]
    pub(crate) fn extension_slots(&self) -> Vec<Stage1RootSlot> {
        self.lease.extension_slots()
    }

    pub(crate) fn backend(&self) -> Arc<Stage1MmBackend> {
        self.lease.backend()
    }

    pub(crate) fn publish_stage1_root(&self, stage1_root: u64) -> Result<MmBinding, Stage1MmError> {
        self.lease.publish_stage1_root(stage1_root)
    }

    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.lease.asid_generation()
    }

    pub(crate) fn begin_asid_load(
        &self,
        executor: crate::kernel::objects::ExecutorId,
    ) -> Result<AsidLoad, AsidResidencyError> {
        self.lease.begin_asid_load(executor)
    }

    pub(crate) fn commit(mut self) -> Arc<Stage1MmLease> {
        self.committed = true;
        Arc::clone(&self.lease)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn abort(mut self) -> Result<PreparedStage1MmAbort, Stage1MmError> {
        let root_slot = self.lease.root_slot;
        let retirement = self.pool.prepare_retirement(&self.lease)?;
        let binding = self.lease.binding();
        #[cfg(test)]
        if let Some(hook) = self.abort_classification_hook.take() {
            hook.run();
        }
        if retirement.requires_quarantine() {
            let retirement = retirement.commit();
            self.committed = true;
            return Ok(PreparedStage1MmAbort::Retirement(retirement));
        }

        // Admission was closed and residency proved that no load ever crossed
        // the hardware-dirty boundary and none remains capable of crossing it.
        // Roll back the retirement reservation before returning the unpublished
        // ASID/root pair to their immediate reuse pools.
        drop(retirement);
        self.pool.release_unpublished(&self.lease)?;
        self.committed = true;
        Ok(PreparedStage1MmAbort::Unpublished { binding, root_slot })
    }
}

impl Drop for PreparedStage1Mm {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Ok(retirement) = self.pool.prepare_retirement(&self.lease) else {
            tracing::error!(
                "failed to quarantine or release dropped unpublished hvpatch mm root slot"
            );
            return;
        };
        #[cfg(test)]
        if let Some(hook) = self.abort_classification_hook.take() {
            hook.run();
        }
        if retirement.requires_quarantine() {
            // No owner remains to drive acknowledgements. Permanently leak the
            // exact retirement receipt: this is fail-closed quarantine, never
            // an unpublished release of hardware-exposed identity.
            std::mem::forget(retirement.commit());
            return;
        }
        drop(retirement);
        if let Err(error) = self.pool.release_unpublished(&self.lease) {
            tracing::error!(%error, "failed to release unpublished hvpatch mm root slot");
        }
    }
}

#[derive(Debug)]
pub(crate) struct Stage1MmRetirement {
    pool: Stage1MmPool,
    asid: RetiredAsid,
    residency: AsidRetirement,
    root_slot: Option<Stage1RootSlot>,
    root_retirement_nonce: Option<u64>,
    root_ticket_issued: bool,
    extension_slots: Vec<Stage1RootSlot>,
}

impl Stage1MmRetirement {
    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.residency.generation()
    }

    pub(crate) fn pending(&self) -> Vec<crate::kernel::objects::ExecutorId> {
        self.residency.pending()
    }

    pub(crate) fn acknowledge(&self, ack: InvalidationAck) -> Result<(), AsidResidencyError> {
        self.residency.acknowledge(ack)
    }

    pub(crate) fn take_root_retirement_ticket(
        &mut self,
    ) -> Result<Option<Stage1RootRetirementTicket>, Stage1MmError> {
        let Some(slot) = self.root_slot else {
            return Ok(None);
        };
        if self.root_ticket_issued {
            return Err(Stage1MmError::RootRetirementTicketAlreadyIssued);
        }
        let nonce = self
            .root_retirement_nonce
            .ok_or(Stage1MmError::RootRetirementTicketUnavailable)?;
        self.root_ticket_issued = true;
        Ok(Some(Stage1RootRetirementTicket { slot, nonce }))
    }

    pub(crate) fn complete(
        self,
        root_receipt: Option<Stage1RootRetirementReceipt>,
    ) -> Result<(), Stage1MmError> {
        if !self.residency.is_complete() {
            return Err(Stage1MmError::RetirementIncomplete);
        }
        match (self.root_slot, self.root_retirement_nonce, root_receipt) {
            (None, None, None) => {}
            (Some(slot), Some(nonce), Some(receipt))
                if receipt.slot == slot && receipt.nonce == nonce => {}
            (Some(slot), _, Some(receipt)) => {
                return Err(Stage1MmError::RootRetirementMismatch {
                    expected_base: slot.base(),
                    expected_size: slot.size(),
                    actual_base: receipt.slot.base(),
                    actual_size: receipt.slot.size(),
                });
            }
            (Some(_), _, None) => return Err(Stage1MmError::RootRetirementReceiptMissing),
            (None, _, Some(_)) => return Err(Stage1MmError::UnexpectedRootRetirementReceipt),
            (None, Some(_), None) => return Err(Stage1MmError::UnexpectedRootRetirementReceipt),
        }
        let mut inner = self.pool.inner.lock();
        inner.asids.acknowledge_tlb_flush(self.asid)?;
        if let Some(root_slot) = self.root_slot {
            inner.free_root_slots.insert(root_slot);
        }
        for slot in self.extension_slots {
            inner.free_root_slots.insert(slot);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn complete_for_test(mut self) -> Result<(), Stage1MmError> {
        let receipt = self
            .take_root_retirement_ticket()?
            .map(Stage1RootRetirementTicket::complete_for_test);
        self.complete(receipt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum Stage1MmError {
    #[error("guest ASID space is exhausted")]
    AsidExhausted,
    #[error(transparent)]
    Asid(AsidError),
    #[error(transparent)]
    Stage1Root(#[from] Stage1RootError),
    #[error("all hvpatch stage-1 root slots are live or awaiting TLB-safe reuse")]
    RootSlotExhausted,
    #[error("hvpatch stage-1 mm is already retired")]
    Retired,
    #[error("hvpatch stage-1 mm retirement still awaits executor invalidation")]
    RetirementIncomplete,
    #[error("hvpatch stage-1 root retirement ticket was already issued")]
    RootRetirementTicketAlreadyIssued,
    #[error("hvpatch stage-1 root retirement ticket is unavailable")]
    RootRetirementTicketUnavailable,
    #[error("hvpatch stage-1 root retirement completed without a backend receipt")]
    RootRetirementReceiptMissing,
    #[error("hvpatch backend returned a root retirement receipt for a rootless address space")]
    UnexpectedRootRetirementReceipt,
    #[error(
        "hvpatch backend root retirement mismatch: expected ({expected_base:#x}, {expected_size:#x}), got ({actual_base:#x}, {actual_size:#x})"
    )]
    RootRetirementMismatch {
        expected_base: u64,
        expected_size: u64,
        actual_base: u64,
        actual_size: u64,
    },
    #[error(transparent)]
    Residency(#[from] AsidResidencyError),
}

impl From<AsidError> for Stage1MmError {
    fn from(error: AsidError) -> Self {
        match error {
            AsidError::Exhausted => Self::AsidExhausted,
            other => Self::Asid(other),
        }
    }
}

/// Live K1 observation seam over each ASID-owned stage-1 root.
/// MmResources publishes every binding into this stable per-mm state before
/// lifecycle retirement, so draining objects cannot follow PID reuse or regress
/// to an older root under concurrent observation.
#[derive(Debug)]
pub(crate) struct Stage1MmBackend {
    binding: RwLock<MmBinding>,
    asid_generation: AsidGeneration,
    inventory: RwLock<Option<InventoryBinding>>,
    vma_source: RwLock<Option<SharedVmaSnapshotSource>>,
    revision: AtomicU64,
}

#[derive(Debug)]
struct InventoryBinding {
    kernel: std::sync::Weak<crate::kernel::Kernel>,
    mm: crate::kernel::MmId,
}

impl Stage1MmBackend {
    pub(crate) fn new(state: Arc<Stage1MmState>) -> Self {
        Self::for_binding(state.binding(), state.asid_generation)
    }

    fn for_binding(binding: MmBinding, asid_generation: AsidGeneration) -> Self {
        Self {
            binding: RwLock::new(binding),
            asid_generation,
            inventory: RwLock::new(None),
            vma_source: RwLock::new(None),
            revision: AtomicU64::new(1),
        }
    }

    pub(crate) fn asid_generation(&self) -> AsidGeneration {
        self.asid_generation
    }

    pub(crate) fn publish_binding(&self, binding: MmBinding) {
        let mut current = self.binding.write();
        *current = binding;
        self.bump_revision();
    }

    pub(crate) fn bind_inventory(
        &self,
        kernel: &Arc<crate::kernel::Kernel>,
        mm: crate::kernel::MmId,
    ) {
        let mut inventory = self.inventory.write();
        *inventory = Some(InventoryBinding {
            kernel: Arc::downgrade(kernel),
            mm,
        });
        self.bump_revision();
    }

    pub(crate) fn bind_vma_source(&self, source: SharedVmaSnapshotSource) {
        *self.vma_source.write() = Some(source);
        self.bump_revision();
    }

    /// Capture the old image without detaching the still-live backend. The
    /// caller publishes this only after engine replacement is irreversible, so
    /// every earlier exec error leaves the old mm following live VMA updates.
    pub(crate) fn prepare_vma_freeze(
        &self,
        deadline: Instant,
    ) -> Result<PreparedVmaFreeze, SnapshotError> {
        let source = self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .clone()
            .ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))?;
        let snapshot = source.snapshot(deadline)?;
        if source.revision() != snapshot.revision {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        let expected_revision = snapshot.revision;
        Ok(PreparedVmaFreeze {
            source,
            snapshot,
            expected_revision,
        })
    }

    #[cfg(test)]
    pub(crate) fn inventory_mm_for_tests(&self) -> Option<crate::kernel::MmId> {
        self.inventory.read().as_ref().map(|binding| binding.mm)
    }

    pub(crate) fn binding(&self) -> MmBinding {
        *self.binding.read()
    }

    fn bump_revision(&self) {
        if self.revision.fetch_add(1, Ordering::Release) == u64::MAX {
            std::process::abort();
        }
    }
}

#[derive(Debug)]
pub(crate) struct PreparedVmaFreeze {
    source: SharedVmaSnapshotSource,
    snapshot: crate::kernel::OwnedVmaSnapshot,
    expected_revision: crate::kernel::VmaRevision,
}

impl PreparedVmaFreeze {
    /// Accept the caller's deliberate exec-image staging mutations while
    /// retaining the pre-staging snapshot for the historical MM.
    pub(crate) fn acknowledge_staged_revision(
        &mut self,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        self.expected_revision = self.source.snapshot(deadline)?.revision;
        Ok(())
    }

    pub(crate) fn validate(
        &self,
        backend: &Stage1MmBackend,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        self.source
            .publish_if_revision(self.expected_revision, deadline, &mut || {
                let slot = backend
                    .vma_source
                    .try_read_until(deadline)
                    .ok_or_else(|| deadline_error(deadline))?;
                let Some(current) = slot.as_ref() else {
                    return Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas));
                };
                if !Arc::ptr_eq(current, &self.source) {
                    return Err(SnapshotError::ChangedDuringObservation);
                }
                Ok(())
            })
    }

    pub(crate) fn commit(
        self,
        backend: &Stage1MmBackend,
        deadline: Instant,
    ) -> Result<(), SnapshotError> {
        let Self {
            source,
            snapshot,
            expected_revision,
        } = self;
        let mut snapshot = Some(snapshot);
        source.publish_if_revision(expected_revision, deadline, &mut || {
            let mut slot = backend
                .vma_source
                .try_write_until(deadline)
                .ok_or_else(|| deadline_error(deadline))?;
            let Some(current) = slot.as_ref() else {
                return Err(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas));
            };
            if !Arc::ptr_eq(current, &source) {
                return Err(SnapshotError::ChangedDuringObservation);
            }
            let frozen = snapshot
                .take()
                .ok_or(SnapshotError::ChangedDuringObservation)?;
            *slot = Some(Arc::new(frozen));
            drop(slot);
            backend.bump_revision();
            Ok(())
        })
    }
}

fn deadline_error(deadline: Instant) -> SnapshotError {
    if Instant::now() >= deadline {
        SnapshotError::TimedOut
    } else {
        SnapshotError::Busy
    }
}

impl MmBackend for Stage1MmBackend {
    fn snapshot(&self, deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        let before = self.revision.load(Ordering::Acquire);
        let binding = {
            let Some(guard) = self.binding.try_read_until(deadline) else {
                return Err(deadline_error(deadline));
            };
            *guard
        };
        let vma_source = self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .clone()
            .ok_or(SnapshotError::AuthorityUnavailable(SnapshotTable::Vmas))?;
        let (kernel, mm) = {
            let Some(guard) = self.inventory.try_read_until(deadline) else {
                return Err(deadline_error(deadline));
            };
            let inventory = guard.as_ref().ok_or(SnapshotError::AuthorityUnavailable(
                crate::kernel::SnapshotTable::Mappings,
            ))?;
            let kernel = inventory
                .kernel
                .upgrade()
                .ok_or(SnapshotError::AuthorityUnavailable(
                    crate::kernel::SnapshotTable::Mappings,
                ))?;
            (kernel, inventory.mm)
        };
        // No backend lock is held while either independent authority is
        // observed. This preserves the K1 backend/frame/kernel lock boundary.
        let vma_snapshot = vma_source.snapshot(deadline)?;
        let frame_snapshot = kernel
            .frame_inventory()
            .snapshot_for_mm_until(mm, deadline)
            .ok_or_else(|| {
                if Instant::now() >= deadline {
                    SnapshotError::TimedOut
                } else {
                    SnapshotError::Busy
                }
            })?;
        let after = self.revision.load(Ordering::Acquire);
        if before != after || vma_source.revision() != vma_snapshot.revision {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        Ok(MmBackendSnapshot {
            revision: after,
            binding,
            vmas: vma_snapshot.vmas,
            vma_revision: Some(vma_snapshot.revision),
            mapping_ids: frame_snapshot
                .mappings
                .into_iter()
                .map(|mapping| mapping.mapping)
                .collect(),
            frame_inventory_revision: Some(frame_snapshot.revision),
        })
    }

    fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    fn vma_revision(&self, deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(self
            .vma_source
            .try_read_until(deadline)
            .ok_or_else(|| deadline_error(deadline))?
            .as_ref()
            .map(|source| source.revision()))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::super::mm_resources::MmResources;
    use super::*;

    fn root_key() -> crate::kernel::TaskKey {
        crate::kernel::TaskKey {
            id: crate::kernel::TaskId::for_root_bootstrap(40).unwrap(),
            serial: crate::kernel::TaskSerial::from_registry_allocation(
                NonZeroU64::new(1).unwrap(),
            ),
        }
    }

    fn executor(raw: i32) -> crate::kernel::objects::ExecutorId {
        crate::kernel::objects::ExecutorId::for_transitional_thread(
            crate::thread::ThreadId::synthetic_for_tests(raw),
        )
        .expect("test executor id")
    }

    #[test]
    fn old_observer_keeps_its_binding_after_exec_and_retirement() {
        let task = root_key();
        let (table, backend) = MmResources::new_root(0x8000).expect("root table");
        table.publish_root(task).expect("publish root");
        let initial = backend.binding();

        let prepared = table.prepare_exec(task).expect("prepare replacement");
        let replacement_root = prepared.root_slot().expect("root slot").base();
        let (replacement, retired) = table
            .commit_exec(task, prepared, replacement_root)
            .expect("commit replacement");
        assert_ne!(replacement.binding().asid, initial.asid);
        assert_ne!(replacement.binding().stage1_root, initial.stage1_root);
        assert_eq!(
            replacement.binding().ttbr0,
            crate::kernel::Ttbr0::for_aarch64(
                replacement.binding().asid,
                replacement.binding().stage1_root,
            )
        );
        assert_eq!(backend.binding(), initial);
        retired
            .expect("unshared exec retirement")
            .complete_for_test()
            .expect("ack retire");
        assert_eq!(backend.binding(), initial);
    }

    #[test]
    fn dropped_preparation_returns_root_slot_and_asid_without_retirement_proof() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("first preparation");
        let first_binding = prepared.binding();
        let first_root_slot = prepared.root_slot();

        drop(prepared);

        let replacement = pool.prepare_child().expect("replacement preparation");
        assert_eq!(replacement.binding().asid, first_binding.asid);
        assert_eq!(replacement.root_slot(), first_root_slot);
        let lease = replacement.commit();
        let retirement = pool.retire(&lease).expect("retire committed lease");
        retirement
            .complete_for_test()
            .expect("acknowledge retirement");
    }

    #[test]
    fn reusable_root_slot_stays_quarantined_without_backend_retirement_receipt() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 3).expect("root pool");
        let lease = pool.prepare_child().expect("first child").commit();
        let retired_slot = lease.root_slot().expect("reusable root slot");
        let retirement = pool.retire(&lease).expect("retire child");

        assert!(matches!(
            retirement.complete(None),
            Err(Stage1MmError::RootRetirementReceiptMissing)
        ));

        let replacement = pool.prepare_child().expect("replacement child");
        assert_ne!(
            replacement.root_slot(),
            Some(retired_slot),
            "a missing physical-retirement proof must quarantine the numeric slot"
        );
        pool.retire(&replacement.commit())
            .expect("retire replacement")
            .complete_for_test()
            .expect("complete replacement retirement");
    }

    #[test]
    fn committed_mm_reuses_neither_asid_nor_root_until_all_residency_acks() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("child preparation");
        let binding = prepared.binding();
        let root_slot = prepared.root_slot();
        let lease = prepared.commit();
        lease
            .begin_asid_load(executor(20))
            .expect("executor load")
            .mark_resident()
            .expect("executor resident");
        let retirement = pool.retire(&lease).expect("retire live mm");

        assert_eq!(retirement.pending(), vec![executor(20)]);
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "numeric ASID and root slot stay quarantined"
        );
        retirement
            .acknowledge(super::super::asid::InvalidationAck::new(
                executor(20),
                retirement.asid_generation(),
            ))
            .expect("owner-thread invalidation ack");
        retirement.complete_for_test().expect("complete retirement");

        let replacement = pool.prepare_child().expect("replacement child");
        assert_eq!(replacement.binding().asid, binding.asid);
        assert_eq!(replacement.root_slot(), root_slot);
        assert_ne!(
            replacement.asid_generation(),
            lease.asid_generation(),
            "numeric reuse must mint a new strong generation"
        );
    }

    #[test]
    fn quarantined_root_slot_is_skipped_then_reused_exactly_after_completion() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 3).expect("root pool");
        let first = pool.prepare_child().expect("first child");
        let first_binding = first.binding();
        let first_generation = first.asid_generation();
        let first_root = first.root_slot().expect("first root slot");
        let first = first.commit();
        let resident = executor(47);
        first
            .begin_asid_load(resident)
            .expect("resident load")
            .mark_resident()
            .expect("resident commit");
        let retirement = pool.retire(&first).expect("first retirement");

        let other = pool.prepare_child().expect("other live ASID/root");
        assert_ne!(other.root_slot(), Some(first_root));
        let _other = other.commit();
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted
        );

        retirement
            .acknowledge(InvalidationAck::new(resident, first_generation))
            .expect("exact first invalidation acknowledgement");
        retirement
            .complete_for_test()
            .expect("complete first retirement");
        let reused = pool.prepare_child().expect("reuse completed root slot");
        assert_eq!(reused.binding().asid, first_binding.asid);
        assert_eq!(reused.root_slot(), Some(first_root));
        assert_ne!(reused.asid_generation(), first_generation);
    }

    #[test]
    fn dropped_retirement_preparation_reopens_the_exact_live_predecessor() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let binding = lease.binding();
        let generation = lease.asid_generation();
        let first = executor(30);
        let second = executor(31);
        lease
            .begin_asid_load(first)
            .expect("first load")
            .mark_resident()
            .expect("first resident");

        let prepared = pool.prepare_retirement(&lease).expect("prepare retirement");
        assert_eq!(
            lease.begin_asid_load(second).unwrap_err(),
            AsidResidencyError::Retiring
        );
        assert_eq!(prepared.pending(), vec![first]);

        drop(prepared);

        assert_eq!(lease.binding(), binding);
        assert_eq!(lease.asid_generation(), generation);
        assert_eq!(lease.residency.residents(), vec![first]);
        lease
            .begin_asid_load(second)
            .expect("rollback reopens exact predecessor")
            .mark_resident()
            .expect("second resident");
        assert_eq!(lease.residency.residents(), vec![first, second]);
    }

    #[test]
    fn failure_after_lease_gate_transition_restores_an_exact_retry() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let binding = lease.binding();
        let generation = lease.asid_generation();
        let resident = executor(32);
        lease
            .begin_asid_load(resident)
            .expect("resident load")
            .mark_resident()
            .expect("resident commit");

        pool.prepare_retirement_with_failpoint_for_tests(
            &lease,
            Stage1RetirementPreparationFailpoint::AfterLeaseGate,
        )
        .expect_err("failure after lease gate transition");

        assert_eq!(lease.binding(), binding);
        assert_eq!(lease.asid_generation(), generation);
        assert_eq!(lease.residency.residents(), vec![resident]);
        let retry = pool.prepare_retirement(&lease).expect("exact retry");
        assert_eq!(retry.pending(), vec![resident]);
    }

    #[test]
    fn failure_after_residency_preparation_restores_every_earlier_layer() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let binding = lease.binding();
        let generation = lease.asid_generation();
        let resident = executor(33);
        let retry_executor = executor(34);
        lease
            .begin_asid_load(resident)
            .expect("resident load")
            .mark_resident()
            .expect("resident commit");

        pool.prepare_retirement_with_failpoint_for_tests(
            &lease,
            Stage1RetirementPreparationFailpoint::AfterResidency,
        )
        .expect_err("failure after residency preparation");

        assert_eq!(lease.binding(), binding);
        assert_eq!(lease.asid_generation(), generation);
        assert_eq!(lease.residency.residents(), vec![resident]);
        let retry_load = lease
            .begin_asid_load(retry_executor)
            .expect("lease and residency admission both reopen");
        let retry = pool.prepare_retirement(&lease).expect("exact retry");
        assert_eq!(retry.pending(), vec![resident, retry_executor]);
        drop(retry);
        drop(retry_load);
    }

    #[test]
    fn failure_after_allocator_preparation_restores_exact_generation_and_retry() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let binding = lease.binding();
        let generation = lease.asid_generation();
        let root_slot = lease.root_slot();
        let resident = executor(35);
        lease
            .begin_asid_load(resident)
            .expect("resident load")
            .mark_resident()
            .expect("resident commit");

        pool.prepare_retirement_with_failpoint_for_tests(
            &lease,
            Stage1RetirementPreparationFailpoint::AfterAllocator,
        )
        .expect_err("failure after allocator preparation");

        assert_eq!(lease.binding(), binding);
        assert_eq!(lease.asid_generation(), generation);
        assert_eq!(lease.residency.residents(), vec![resident]);
        let retirement = pool
            .prepare_retirement(&lease)
            .expect("exact retry after every layer rollback")
            .commit();
        assert_eq!(retirement.pending(), vec![resident]);
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "prepared generation commits into TLB quarantine"
        );
        retirement
            .acknowledge(InvalidationAck::new(resident, generation))
            .expect("exact invalidation acknowledgement");
        retirement
            .complete_for_test()
            .expect("complete exact retirement");

        let replacement = pool.prepare_child().expect("reuse after exact ack");
        assert_eq!(replacement.binding().asid, binding.asid);
        assert_eq!(replacement.root_slot(), root_slot);
        assert_ne!(replacement.asid_generation(), generation);
    }

    #[test]
    fn rollback_keeps_load_and_root_publication_blocked_until_every_layer_restores() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let mut prepared = pool.prepare_retirement(&lease).expect("prepare retirement");
        let after_allocator = Arc::new(std::sync::Barrier::new(2));
        let resume_after_allocator = Arc::new(std::sync::Barrier::new(2));
        let after_residency = Arc::new(std::sync::Barrier::new(2));
        let resume_after_residency = Arc::new(std::sync::Barrier::new(2));
        prepared.install_rollback_hook_for_tests(RollbackOrderHook {
            after_allocator: Arc::clone(&after_allocator),
            resume_after_allocator: Arc::clone(&resume_after_allocator),
            after_residency: Arc::clone(&after_residency),
            resume_after_residency: Arc::clone(&resume_after_residency),
        });

        let rollback = std::thread::spawn(move || drop(prepared));
        after_allocator.wait();

        let (load_started_tx, load_started_rx) = std::sync::mpsc::channel();
        let (load_done_tx, load_done_rx) = std::sync::mpsc::channel();
        let load_lease = Arc::clone(&lease);
        let load = std::thread::spawn(move || {
            load_started_tx.send(()).unwrap();
            let result = load_lease.begin_asid_load(executor(46)).map(drop);
            load_done_tx.send(result).unwrap();
        });
        let (publish_started_tx, publish_started_rx) = std::sync::mpsc::channel();
        let (publish_done_tx, publish_done_rx) = std::sync::mpsc::channel();
        let publish_lease = Arc::clone(&lease);
        let root = lease.root_slot().expect("child root slot").base();
        let publish = std::thread::spawn(move || {
            publish_started_tx.send(()).unwrap();
            let result = publish_lease.publish_stage1_root(root).map(drop);
            publish_done_tx.send(result).unwrap();
        });
        load_started_rx.recv().unwrap();
        publish_started_rx.recv().unwrap();
        assert!(lease.lifecycle.try_lock().is_none());
        assert!(load_done_rx.try_recv().is_err());
        assert!(publish_done_rx.try_recv().is_err());

        resume_after_allocator.wait();
        after_residency.wait();
        assert!(lease.lifecycle.try_lock().is_none());
        assert!(load_done_rx.try_recv().is_err());
        assert!(publish_done_rx.try_recv().is_err());

        resume_after_residency.wait();
        rollback.join().unwrap();
        load_done_rx
            .recv()
            .unwrap()
            .expect("load admitted only after complete rollback");
        publish_done_rx
            .recv()
            .unwrap()
            .expect("root publication admitted only after complete rollback");
        load.join().unwrap();
        publish.join().unwrap();
    }

    #[test]
    fn clean_inflight_load_cancellation_stays_cancelled_across_retirement_rollback() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let loading = executor(36);
        let later = executor(37);
        let load = lease.begin_asid_load(loading).expect("in-flight load");
        let prepared = pool
            .prepare_retirement(&lease)
            .expect("prepare around in-flight load");
        assert_eq!(prepared.pending(), vec![loading]);

        drop(load);
        assert!(prepared.pending().is_empty());
        drop(prepared);

        assert!(lease.residency.residents().is_empty());
        lease
            .begin_asid_load(later)
            .expect("rollback reopens admission after clean cancellation");
    }

    #[test]
    fn dirty_inflight_load_cancellation_survives_retirement_rollback_as_resident() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let lease = pool.prepare_child().expect("child preparation").commit();
        let executor = executor(38);
        let mut load = lease.begin_asid_load(executor).expect("in-flight load");
        load.arm_hardware_dirty().expect("real dirty boundary");
        let prepared = pool
            .prepare_retirement(&lease)
            .expect("prepare around dirty in-flight load");
        assert_eq!(prepared.pending(), vec![executor]);

        drop(load);
        assert_eq!(prepared.pending(), vec![executor]);
        drop(prepared);

        assert_eq!(lease.residency.residents(), vec![executor]);
        let retry = pool.prepare_retirement(&lease).expect("exact retry");
        assert_eq!(retry.pending(), vec![executor]);
    }

    #[test]
    fn clean_replacement_abort_releases_exact_unpublished_asid_and_root() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("replacement preparation");
        let binding = prepared.binding();
        let root_slot = prepared.root_slot();
        let clean_load = prepared
            .begin_asid_load(executor(39))
            .expect("clean replacement load");
        drop(clean_load);

        let settlement = prepared.abort().expect("settle clean abort");
        match settlement {
            PreparedStage1MmAbort::Unpublished {
                binding: released_binding,
                root_slot: released_root_slot,
            } => {
                assert_eq!(released_binding, binding);
                assert_eq!(released_root_slot, root_slot);
            }
            PreparedStage1MmAbort::Retirement(_) => {
                panic!("a never-hardware-dirty replacement must not enter quarantine")
            }
        }

        let replacement = pool.prepare_child().expect("immediate exact reuse");
        assert_eq!(replacement.binding(), binding);
        assert_eq!(replacement.root_slot(), root_slot);
    }

    #[test]
    fn dirty_replacement_abort_quarantines_until_exact_invalidation_completes() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("replacement preparation");
        let binding = prepared.binding();
        let generation = prepared.asid_generation();
        let root_slot = prepared.root_slot();
        let dirty_executor = executor(40);
        let mut load = prepared
            .begin_asid_load(dirty_executor)
            .expect("replacement load");
        load.arm_hardware_dirty().expect("real dirty boundary");
        drop(load);

        let settlement = prepared.abort().expect("settle dirty abort");
        let PreparedStage1MmAbort::Retirement(retirement) = settlement else {
            panic!("hardware-dirty replacement must enter retirement quarantine");
        };
        assert_eq!(retirement.asid_generation(), generation);
        assert_eq!(retirement.pending(), vec![dirty_executor]);
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "dirty ASID/root stay unavailable before exact acknowledgement"
        );
        retirement
            .acknowledge(InvalidationAck::new(dirty_executor, generation))
            .expect("exact dirty invalidation acknowledgement");
        retirement
            .complete_for_test()
            .expect("complete dirty quarantine");

        let replacement = pool.prepare_child().expect("reuse after dirty ack");
        assert_eq!(replacement.binding().asid, binding.asid);
        assert_eq!(replacement.root_slot(), root_slot);
        assert_ne!(replacement.asid_generation(), generation);
    }

    #[test]
    fn explicit_abort_classifies_hardware_exposure_atomically() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let mut prepared = pool.prepare_child().expect("replacement preparation");
        let generation = prepared.asid_generation();
        let dirty_executor = executor(44);
        let mut load = prepared
            .begin_asid_load(dirty_executor)
            .expect("replacement load");
        let reached_classification = Arc::new(std::sync::Barrier::new(2));
        let resume_classification = Arc::new(std::sync::Barrier::new(2));
        prepared.install_abort_classification_hook_for_tests(AbortClassificationHook {
            reached_classification: Arc::clone(&reached_classification),
            resume_classification: Arc::clone(&resume_classification),
        });

        let abort = std::thread::spawn(move || prepared.abort().expect("explicit abort"));
        reached_classification.wait();
        load.arm_hardware_dirty()
            .expect("race crosses dirty boundary");
        load.mark_resident().expect("race settles as resident");
        resume_classification.wait();

        let settlement = abort.join().expect("abort thread");
        let PreparedStage1MmAbort::Retirement(retirement) = settlement else {
            panic!("atomic classification must quarantine the raced dirty load");
        };
        assert_eq!(retirement.pending(), vec![dirty_executor]);
        retirement
            .acknowledge(InvalidationAck::new(dirty_executor, generation))
            .expect("exact raced invalidation acknowledgement");
        retirement
            .complete_for_test()
            .expect("complete raced quarantine");
    }

    #[test]
    fn clean_inflight_abort_retirement_completes_after_the_load_cancels() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("replacement preparation");
        let binding = prepared.binding();
        let root_slot = prepared.root_slot();
        let loading_executor = executor(41);
        let load = prepared
            .begin_asid_load(loading_executor)
            .expect("clean in-flight replacement load");

        let settlement = prepared.abort().expect("settle in-flight abort");
        let PreparedStage1MmAbort::Retirement(retirement) = settlement else {
            panic!("an in-flight load must be quarantined until it settles");
        };
        assert_eq!(retirement.pending(), vec![loading_executor]);

        drop(load);

        assert!(retirement.pending().is_empty());
        retirement
            .complete_for_test()
            .expect("clean cancellation discharges retirement");
        let replacement = pool.prepare_child().expect("reuse after cancellation");
        assert_eq!(replacement.binding(), binding);
        assert_eq!(replacement.root_slot(), root_slot);
    }

    #[test]
    fn dirty_resident_replacement_abort_has_the_same_quarantine_requirement() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("replacement preparation");
        let generation = prepared.asid_generation();
        let resident_executor = executor(42);
        let mut load = prepared
            .begin_asid_load(resident_executor)
            .expect("replacement load");
        load.arm_hardware_dirty().expect("real dirty boundary");
        load.mark_resident().expect("dirty load becomes resident");

        let settlement = prepared.abort().expect("settle dirty resident abort");
        let PreparedStage1MmAbort::Retirement(retirement) = settlement else {
            panic!("resident hardware-dirty replacement must enter quarantine");
        };
        assert_eq!(retirement.pending(), vec![resident_executor]);
        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted
        );
        retirement
            .acknowledge(InvalidationAck::new(resident_executor, generation))
            .expect("exact resident invalidation acknowledgement");
        retirement
            .complete_for_test()
            .expect("complete resident quarantine");
        assert!(pool.prepare_child().is_ok());
    }

    #[test]
    fn dropping_dirty_replacement_without_settlement_quarantines_permanently() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let prepared = pool.prepare_child().expect("replacement preparation");
        let dirty_executor = executor(43);
        let mut load = prepared
            .begin_asid_load(dirty_executor)
            .expect("replacement load");
        load.arm_hardware_dirty().expect("real dirty boundary");
        drop(load);

        drop(prepared);

        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "implicit dirty drop must never release unpublished identity"
        );
    }

    #[test]
    fn implicit_drop_classifies_hardware_exposure_atomically() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 2).expect("root pool");
        let mut prepared = pool.prepare_child().expect("replacement preparation");
        let dirty_executor = executor(45);
        let mut load = prepared
            .begin_asid_load(dirty_executor)
            .expect("replacement load");
        let reached_classification = Arc::new(std::sync::Barrier::new(2));
        let resume_classification = Arc::new(std::sync::Barrier::new(2));
        prepared.install_abort_classification_hook_for_tests(AbortClassificationHook {
            reached_classification: Arc::clone(&reached_classification),
            resume_classification: Arc::clone(&resume_classification),
        });

        let dropped = std::thread::spawn(move || drop(prepared));
        reached_classification.wait();
        load.arm_hardware_dirty()
            .expect("race crosses dirty boundary");
        load.mark_resident().expect("race settles as resident");
        resume_classification.wait();
        dropped.join().expect("drop thread");

        assert_eq!(
            pool.prepare_child().unwrap_err(),
            Stage1MmError::AsidExhausted,
            "atomic implicit-drop classification must quarantine the raced dirty load"
        );
    }

    #[test]
    fn hvpatch_task_binding_carries_the_exact_shared_mm_residency_authority() {
        struct ExitJob;
        impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
            fn poll_quantum_with_engine(
                &mut self,
                _engine: &mut dyn std::any::Any,
                _control: &mut crate::vcpu_loop::executor::HvpatchQuantumControl<'_, '_>,
            ) -> crate::vcpu_loop::executor::ExecutorExit {
                crate::vcpu_loop::executor::ExecutorExit::Exited
            }
        }

        let (pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 1).expect("root pool");
        let generation = lease.asid_generation();
        let binding = crate::vcpu_loop::continuation::HvpatchTaskBinding::new_with_stage1_mm(
            crate::vcpu_loop::executor::TaskLoadIdentity {
                abi: carrick_abi::LinuxGuestAbi::Aarch64,
                version: 1,
                mm: crate::kernel::MmId::from_registry_allocation(NonZeroU64::new(91).unwrap()),
                asid_generation: generation.generation(),
            },
            Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
                Box::new(ExitJob),
                crate::vcpu_loop::continuation::LogicalJobCompletion::pending(),
            )),
            Box::new(7_u64),
            Arc::clone(&lease),
        )
        .expect("binding owns exact stage-1 lease");
        binding
            .begin_asid_load(executor(21))
            .expect("binding load authority")
            .mark_resident()
            .expect("binding resident");

        let retirement = pool.retire(&lease).expect("retirement");
        assert_eq!(retirement.pending(), vec![executor(21)]);
        assert_eq!(retirement.asid_generation(), generation);
    }

    #[test]
    fn cow_invalidation_tracks_exact_generation_and_defers_inactive_residents() {
        let (_pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 4).expect("root pool");
        let active = executor(31);
        let inactive = executor(32);
        lease
            .begin_asid_load(active)
            .expect("active load")
            .mark_resident()
            .expect("active resident");
        lease
            .begin_asid_load(inactive)
            .expect("inactive load")
            .mark_resident()
            .expect("inactive resident");

        let publication = lease.publish_cow_invalidation();
        assert_eq!(publication.asid_generation(), lease.asid_generation());
        assert_eq!(publication.pending(), vec![active, inactive]);
        let active_ticket = lease
            .pending_cow_invalidation(active)
            .expect("active pending ticket");
        lease
            .acknowledge_cow_invalidation(active, active_ticket)
            .expect("active acknowledgement");
        assert!(lease.pending_cow_invalidation(active).is_none());
        assert_eq!(
            lease.pending_cow_invalidation(inactive),
            Some(publication.ticket())
        );
    }

    #[test]
    fn cow_invalidation_rejects_stale_or_wrong_executor_acknowledgement() {
        let (_pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 4).expect("root pool");
        let resident = executor(41);
        lease
            .begin_asid_load(resident)
            .expect("load")
            .mark_resident()
            .expect("resident");
        let first = lease.publish_cow_invalidation();
        let second = lease.publish_cow_invalidation();
        assert_eq!(
            lease.acknowledge_cow_invalidation(resident, first.ticket()),
            Err(CowInvalidationError::StaleGeneration)
        );
        assert_eq!(
            lease.acknowledge_cow_invalidation(executor(42), second.ticket()),
            Err(CowInvalidationError::UnexpectedExecutor)
        );
    }

    #[test]
    fn pre_entry_service_is_exact_and_acknowledges_only_after_hardware_success() {
        let (_pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 4).expect("root pool");
        let resident = executor(51);
        lease
            .begin_asid_load(resident)
            .expect("load")
            .mark_resident()
            .expect("resident");
        let observer = lease.cow_invalidation_observer(resident);
        let publication = lease.publish_cow_invalidation();
        let mut invalidated = Vec::new();
        lease
            .service_pending_cow_invalidation(&observer, |asid| {
                invalidated.push(asid);
                Ok::<(), &'static str>(())
            })
            .expect("pre-entry service");
        assert_eq!(invalidated, vec![publication.asid_generation()]);
        assert!(lease.pending_cow_invalidation(resident).is_none());

        lease.publish_cow_invalidation();
        assert_eq!(
            lease.service_pending_cow_invalidation(&observer, |_| Err("hardware failed")),
            Err("hardware failed")
        );
        assert!(lease.pending_cow_invalidation(resident).is_some());
    }

    #[test]
    fn no_work_current_mm_reentry_never_enters_cow_invalidation_slow_path() {
        let (_pool, lease) = Stage1MmPool::new_root_for_tests(0x8000, 4).expect("root pool");
        let resident = executor(52);
        lease
            .begin_asid_load(resident)
            .expect("load")
            .mark_resident()
            .expect("resident");
        let observer = lease.cow_invalidation_observer(resident);
        let hardware_calls = std::cell::Cell::new(0_u64);

        lease
            .service_pending_cow_invalidation(&observer, |_| {
                hardware_calls.set(hardware_calls.get() + 1);
                Ok::<(), ()>(())
            })
            .expect("no-work re-entry");

        assert_eq!(hardware_calls.get(), 0, "no vtable/hardware callback");
        assert_eq!(
            lease.cow_invalidation_slow_paths_for_tests(),
            0,
            "no-work re-entry must not lock or perform a resident lookup"
        );
    }

    #[test]
    fn page_table_root_slots_scale_to_the_complete_arena() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 64).expect("root slot pool");
        let prepared: Vec<_> = (0..32)
            .map(|_| pool.prepare_child().expect("dense page-table root slot"))
            .collect();
        assert_eq!(prepared.len(), 32);
    }

    #[test]
    fn fails_closed_when_vma_authority_is_unbound() {
        let (_table, backend) = MmResources::new_root(0x8000).expect("root table");

        assert_eq!(
            backend.snapshot(Instant::now() + std::time::Duration::from_secs(1)),
            Err(SnapshotError::AuthorityUnavailable(
                crate::kernel::SnapshotTable::Vmas
            ))
        );
    }

    #[test]
    fn concurrent_carrier_roots_allocate_distinct_asids_and_root_slots() {
        let start_barrier = Arc::new(std::sync::Barrier::new(3));
        let hold_barrier = Arc::new(std::sync::Barrier::new(3));
        let s1 = Arc::clone(&start_barrier);
        let s2 = Arc::clone(&start_barrier);
        let h1 = Arc::clone(&hold_barrier);
        let h2 = Arc::clone(&hold_barrier);

        let t1 = std::thread::spawn(move || {
            s1.wait();
            let (pool, root) = Stage1MmPool::new_root(0x10000).expect("first carrier root");
            let child = pool.prepare_child().expect("child for root 1");
            let slot = child.root_slot();
            let lease = child.commit();
            h1.wait();
            (root.binding(), lease.binding(), slot)
        });

        let t2 = std::thread::spawn(move || {
            s2.wait();
            let (pool, root) = Stage1MmPool::new_root(0x20000).expect("second carrier root");
            let child = pool.prepare_child().expect("child for root 2");
            let slot = child.root_slot();
            let lease = child.commit();
            h2.wait();
            (root.binding(), lease.binding(), slot)
        });

        start_barrier.wait();
        hold_barrier.wait();
        let (root1, child1, slot1) = t1.join().expect("thread 1");
        let (root2, child2, slot2) = t2.join().expect("thread 2");

        // ASIDs must be all mutually distinct across both containers
        let asids = vec![root1.asid, child1.asid, root2.asid, child2.asid];
        let asid_set: std::collections::BTreeSet<_> = asids.iter().copied().collect();
        assert_eq!(asid_set.len(), 4, "all 4 ASIDs must be distinct: {asids:?}");

        // Child root slots must also be distinct
        assert_ne!(slot1, slot2, "child root slots must not collide");
    }

    #[test]
    fn extension_slots_return_to_free_root_slots_on_retirement() {
        let (pool, _root) = Stage1MmPool::new_root_for_tests(0x8000, 64).expect("root slot pool");
        let initial_free = pool.inner.lock().free_root_slots.len();

        let child = pool.prepare_child().expect("child preparation");
        assert_eq!(pool.inner.lock().free_root_slots.len(), initial_free - 1);

        let mut source = child.table_arena_source();
        let ext1 = source.take_arena().expect("extension slot 1");
        let _ext2 = source.take_arena().expect("extension slot 2");
        assert_eq!(pool.inner.lock().free_root_slots.len(), initial_free - 3);
        assert_eq!(child.extension_slots().len(), 2);

        // Returning ext1 directly via source
        source.return_arena(ext1);
        assert_eq!(pool.inner.lock().free_root_slots.len(), initial_free - 2);
        assert_eq!(child.extension_slots().len(), 1);

        let lease = child.commit();
        let retirement = pool.retire(&lease).expect("retire");
        retirement.complete_for_test().expect("complete");

        // Primary root slot and ext2 must both be back in free_root_slots
        assert_eq!(pool.inner.lock().free_root_slots.len(), initial_free);
    }
}
