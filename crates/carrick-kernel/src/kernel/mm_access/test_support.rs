//! Foreign-mm and COW fixtures shared with a sibling crate's tests.
//!
//! `carrick-runtime`'s `vcpu_loop::memory` suites drive the carrier's
//! foreign-mm path against a kernel graph with no VM: the mock COW transport
//! and its fault injection (`MockCowTransport`, `MockCowFault`,
//! `MockCowCounters`, `MockCowReceipt`), a mutable mm backend
//! (`fixture_backend`), a booted root (`bootstrap`), a fork over a chosen
//! backend (`fork_with_backend`), an execution lease (`execution_lease`), a
//! foreign-mm handle (`foreign_mm`), a published COW mapping
//! (`publish_cow_mapping`, `cow_fixture`) and the mutation helper
//! (`with_foreign_mutation`).
//!
//! They live here rather than in the `#[test]` module for the reason
//! `carrier_process::test_support` already states: only the fixtures a
//! sibling crate consumes belong on the `test-support` feature. Compiling the
//! whole suite through the feature pulled 26 `#[test]` bodies into every
//! sibling build and needed a blanket `allow(dead_code, unused_imports)` to
//! stay quiet, which suppressed exactly the warnings that say a fixture has
//! gone unused.

// Test-only code that a sibling crate compiles through `test-support`, so
// `cfg(test)` is not set for it and clippy's `allow-{unwrap,expect,panic}-in-
// tests` does not apply. These are fixtures: an invariant they cannot satisfy
// is a broken fixture, not a runtime condition.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::num::{NonZeroU16, NonZeroU64};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use carrick_abi::LinuxCloneFlags;
use carrick_guest_mem::{Gpa, GuestVa};
use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
use carrick_hal::{
    ForeignCowReceipt, ForeignMmPreparedWrite, ForeignMmReadLease, ForeignMmReadReceipt,
    ForeignMmSnapshot, ForeignMmTransport, ForeignMmTransportError, ForeignMmWriteReceipt,
    ThreadId,
};

use super::super::objects::{ExecutorId, MigratableTaskState, ThreadExecutionLease};
use super::super::{
    Asid, ClonePlan, Kernel, KernelContext, MmBackend, MmBackendSnapshot, MmBinding, MmId,
    MmRelation, RootBootstrap, SnapshotError, Stage1Root, TaskKey, VmaAccess, VmaRevision,
    VmaSummary,
};

#[derive(Debug)]
pub(crate) struct FixtureBackend {
    binding: MmBinding,
}

impl MmBackend for FixtureBackend {
    fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        Ok(MmBackendSnapshot {
            revision: 17,
            binding: self.binding,
            vmas: vec![
                VmaSummary {
                    start: GuestVa(0x1000),
                    end: GuestVa(0x2000),
                    access: VmaAccess {
                        readable: true,
                        writable: false,
                        executable: false,
                        kernel_visible: true,
                    },
                },
                VmaSummary {
                    start: GuestVa(0x2000),
                    end: GuestVa(0x3000),
                    access: VmaAccess {
                        readable: true,
                        writable: false,
                        executable: false,
                        kernel_visible: true,
                    },
                },
                VmaSummary {
                    start: GuestVa(0x3000),
                    end: GuestVa(0x4000),
                    access: VmaAccess {
                        readable: true,
                        writable: true,
                        executable: false,
                        kernel_visible: true,
                    },
                },
                VmaSummary {
                    start: GuestVa(0x4000),
                    end: GuestVa(0x5000),
                    access: VmaAccess {
                        readable: true,
                        writable: false,
                        executable: false,
                        kernel_visible: false,
                    },
                },
            ],
            vma_revision: Some(VmaRevision::from_authority_raw(19)),
            mapping_ids: Vec::new(),
            frame_inventory_revision: Some(23),
        })
    }

    fn revision(&self) -> u64 {
        17
    }

    fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(Some(VmaRevision::from_authority_raw(19)))
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ChurningBackend {
    pub(crate) backend_revision: AtomicU64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum MockReadMode {
    RetryOnce,
    AlwaysRetry,
    EmptyOwners,
    Deadline,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MockForeignTransport {
    pub(crate) calls: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) mode: MockReadMode,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MockForeignLease {
    calls: Arc<std::sync::atomic::AtomicUsize>,
    mode: MockReadMode,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct MockForeignReceipt {
    bytes: usize,
    owners: Vec<carrick_hal::ForeignOwnerGeneration>,
}

#[cfg(test)]
impl ForeignMmReadReceipt for MockForeignReceipt {
    fn bytes_read(&self) -> usize {
        self.bytes
    }
    fn owner_generations(&self) -> &[carrick_hal::ForeignOwnerGeneration] {
        &self.owners
    }
    fn authenticates(&self, _snapshot: &dyn ForeignMmSnapshot) -> bool {
        true
    }
}

#[cfg(test)]
impl ForeignMmReadLease for MockForeignLease {
    fn read(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
        _snapshot: &dyn ForeignMmSnapshot,
        _va: GuestVa,
        dst: &mut [u8],
        _deadline: Instant,
    ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        if matches!(self.mode, MockReadMode::Deadline) {
            while Instant::now() < _deadline {
                std::hint::spin_loop();
            }
            return Err(ForeignMmTransportError::TimedOut);
        }
        if matches!(self.mode, MockReadMode::AlwaysRetry) || call == 0 {
            return Err(ForeignMmTransportError::Retry);
        }
        dst.copy_from_slice(b"root");
        Ok(Box::new(MockForeignReceipt {
            bytes: dst.len(),
            owners: (!matches!(self.mode, MockReadMode::EmptyOwners))
                .then_some(carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    std::num::NonZeroU64::MIN,
                ))
                .into_iter()
                .collect(),
        }))
    }
}

#[cfg(test)]
impl ForeignMmTransport for MockForeignTransport {
    fn retain(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _snapshot: &dyn ForeignMmSnapshot,
        _deadline: Instant,
    ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
        Ok(Arc::new(MockForeignLease {
            calls: Arc::clone(&self.calls),
            mode: self.mode,
        }))
    }
}

#[cfg(test)]
impl MmBackend for ChurningBackend {
    fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        let observed = self.backend_revision.load(Ordering::Acquire);
        let changed = self.backend_revision.fetch_add(1, Ordering::AcqRel) + 1;
        if observed != changed {
            return Err(SnapshotError::ChangedDuringObservation);
        }
        unreachable!("the fixture mutates the revision during every snapshot")
    }

    fn revision(&self) -> u64 {
        self.backend_revision.load(Ordering::Acquire)
    }

    fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(Some(VmaRevision::from_authority_raw(31)))
    }
}

#[derive(Debug)]
pub struct MutableFixtureBackend {
    binding: MmBinding,
    backend_revision: Arc<AtomicU64>,
    vma_revision: AtomicU64,
    inventory_revision: AtomicU64,
    mapping: parking_lot::RwLock<carrick_hal::MappingId>,
    access: parking_lot::RwLock<VmaAccess>,
}

impl MutableFixtureBackend {
    fn new() -> Arc<Self> {
        let asid = Asid::from_registry_allocation(NonZeroU16::new(9).expect("nonzero ASID"));
        let root = Stage1Root::for_aarch64_4k(Gpa(0xa000)).expect("aligned stage-1 root");
        Arc::new(Self {
            binding: MmBinding::for_aarch64(asid, root),
            backend_revision: Arc::new(AtomicU64::new(41)),
            vma_revision: AtomicU64::new(43),
            inventory_revision: AtomicU64::new(47),
            mapping: parking_lot::RwLock::new(carrick_hal::MappingId::from_kernel_allocation(
                NonZeroU64::new(53).unwrap(),
            )),
            access: parking_lot::RwLock::new(VmaAccess {
                readable: true,
                writable: true,
                executable: false,
                kernel_visible: true,
            }),
        })
    }

    fn bind_inventory_mapping(&self, mapping: carrick_hal::MappingId, revision: u64) {
        *self.mapping.write() = mapping;
        self.inventory_revision.store(revision, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn set_access(&self, access: VmaAccess) {
        *self.access.write() = access;
    }

    #[cfg(test)]
    pub(crate) fn advance(&self, domain: usize) {
        match domain {
            0 => &self.backend_revision,
            1 => &self.vma_revision,
            _ => &self.inventory_revision,
        }
        .fetch_add(1, Ordering::AcqRel);
    }
}

impl MmBackend for MutableFixtureBackend {
    fn snapshot(&self, _deadline: Instant) -> Result<MmBackendSnapshot, SnapshotError> {
        Ok(MmBackendSnapshot {
            revision: self.backend_revision.load(Ordering::Acquire),
            binding: self.binding,
            vmas: vec![VmaSummary {
                start: GuestVa(0x3000),
                end: GuestVa(0x4000),
                access: *self.access.read(),
            }],
            vma_revision: Some(VmaRevision::from_authority_raw(
                self.vma_revision.load(Ordering::Acquire),
            )),
            mapping_ids: vec![*self.mapping.read()],
            frame_inventory_revision: Some(self.inventory_revision.load(Ordering::Acquire)),
        })
    }

    fn revision(&self) -> u64 {
        self.backend_revision.load(Ordering::Acquire)
    }

    fn vma_revision(&self, _deadline: Instant) -> Result<Option<VmaRevision>, SnapshotError> {
        Ok(Some(VmaRevision::from_authority_raw(
            self.vma_revision.load(Ordering::Acquire),
        )))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockCowFault {
    None,
    ReacquireSnapshot,
    WrongMm,
    WrongRange,
    InflatedSemanticSpan,
    WrongMapping,
    WrongFrame,
    WrongPhysical,
    WrongPhysicalLength,
    WrongOwner,
    ForgedConsistentMapping,
    ForgedConsistentFrame,
    ForgedConsistentPhysical,
    ForgedConsistentOwner,
    AdvancedBackend,
    AdvancedVma,
    AdvancedInventory,
    PostCopyError,
    WrongWriteReceipt,
    AdvancedBackendAfterWrite,
}

#[derive(Clone, Debug, Default)]
pub struct MockCowCounters {
    pub(crate) break_calls: Arc<AtomicUsize>,
    pub(crate) prepare_calls: Arc<AtomicUsize>,
    pub(crate) commit_calls: Arc<AtomicUsize>,
    caller_census_probe: Arc<parking_lot::Mutex<Option<Arc<crate::kernel::GuestExecutorCensus>>>>,
    break_observed_caller_executor: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
pub struct MockCowTransport {
    pub owner_generation: Arc<AtomicU64>,
    pub bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
    pub counters: MockCowCounters,
    pub fault: MockCowFault,
    pub proof: crate::kernel::KernelForeignCowProof,
    pub ptrace_proof: Option<crate::kernel::KernelForeignCowProof>,
    pub mapping: carrick_hal::MappingId,
    pub frame: carrick_hal::FrameId,
    pub physical_base: Gpa,
    pub physical_len: u64,
    pub post_write_backend_revision: Option<Arc<AtomicU64>>,
}

#[derive(Debug)]
pub(crate) struct MockCowLease {
    owner_generation: Arc<AtomicU64>,
    bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
    counters: MockCowCounters,
    fault: MockCowFault,
    proof: crate::kernel::KernelForeignCowProof,
    ptrace_proof: Option<crate::kernel::KernelForeignCowProof>,
    mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    physical_base: Gpa,
    physical_len: u64,
    post_write_backend_revision: Option<Arc<AtomicU64>>,
}

#[derive(Debug)]
pub struct MockCowReceipt {
    pub mm: carrick_hal::ForeignMmId,
    pub start: GuestVa,
    pub len: usize,
    pub backend: carrick_hal::ForeignBackendRevision,
    pub vma: carrick_hal::ForeignVmaRevision,
    pub inventory: carrick_hal::ForeignFrameInventoryRevision,
    pub mapping: carrick_hal::MappingId,
    pub frame: carrick_hal::FrameId,
    pub physical_base: Gpa,
    pub physical_len: u64,
    pub owner: carrick_hal::ForeignOwnerGeneration,
    pub kernel_proof: carrick_hal::ForeignCowKernelProof,
}

impl ForeignCowReceipt for MockCowReceipt {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.mm
    }
    fn range_start(&self) -> GuestVa {
        self.start
    }
    fn range_len(&self) -> usize {
        self.len
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.backend
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.vma
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.inventory
    }
    fn mapping(&self) -> carrick_hal::MappingId {
        self.mapping
    }
    fn frame(&self) -> carrick_hal::FrameId {
        self.frame
    }
    fn physical_base(&self) -> Gpa {
        self.physical_base
    }
    fn physical_len(&self) -> u64 {
        self.physical_len
    }
    fn owner_generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.owner
    }
    fn kernel_proof(&self) -> &carrick_hal::ForeignCowKernelProof {
        &self.kernel_proof
    }
}

#[derive(Debug)]
pub(crate) struct MockWriteReceipt(MockCowReceipt);

impl ForeignMmWriteReceipt for MockWriteReceipt {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.0.mm()
    }
    fn range_start(&self) -> GuestVa {
        self.0.range_start()
    }
    fn range_len(&self) -> usize {
        self.0.range_len()
    }
    fn bytes_written(&self) -> usize {
        self.0.len
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.0.backend_revision()
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.0.vma_revision()
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.0.frame_inventory_revision()
    }
    fn mapping(&self) -> carrick_hal::MappingId {
        self.0.mapping()
    }
    fn frame(&self) -> carrick_hal::FrameId {
        self.0.frame()
    }
    fn owner_generation(&self) -> carrick_hal::ForeignOwnerGeneration {
        self.0.owner_generation()
    }
}

#[derive(Debug)]
pub(crate) struct MockPreparedWrite<'a> {
    bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
    counters: MockCowCounters,
    cow_base: GuestVa,
    src: &'a [u8],
    receipt: Box<MockWriteReceipt>,
}

impl ForeignMmPreparedWrite for MockPreparedWrite<'_> {
    fn commit(self: Box<Self>) {
        self.counters.commit_calls.fetch_add(1, Ordering::SeqCst);
        let start = self.receipt.0.start.raw();
        let base = self.cow_base.raw();
        let offset = usize::try_from(start.saturating_sub(base)).unwrap_or(0);
        let mut guard = self.bytes.lock();
        if guard.len() < offset + self.src.len() {
            guard.resize(offset + self.src.len(), 0);
        }
        guard[offset..offset + self.src.len()].copy_from_slice(self.src);
    }

    fn receipt(&self) -> &dyn ForeignMmWriteReceipt {
        self.receipt.as_ref()
    }
}

impl ForeignMmReadLease for MockCowLease {
    fn read(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
        _snapshot: &dyn ForeignMmSnapshot,
        _va: GuestVa,
        _dst: &mut [u8],
        _deadline: Instant,
    ) -> Result<Box<dyn ForeignMmReadReceipt>, ForeignMmTransportError> {
        Err(ForeignMmTransportError::AuthorityUnavailable)
    }

    fn break_cow(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        len: usize,
        executable: Option<&carrick_hal::ForeignPtraceTextCowPlan>,
        _deadline: Instant,
    ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
        self.counters.break_calls.fetch_add(1, Ordering::SeqCst);
        if self
            .counters
            .caller_census_probe
            .lock()
            .as_ref()
            .is_some_and(|census| census.participant_count_for_probe() != 0)
        {
            self.counters
                .break_observed_caller_executor
                .store(true, Ordering::SeqCst);
        }
        let next = |raw| NonZeroU64::new(raw + 1).unwrap();
        let mm = if self.fault == MockCowFault::WrongMm {
            carrick_hal::ForeignMmId::from_kernel_allocation(next(snapshot.mm().raw_for_probe()))
        } else {
            snapshot.mm()
        };
        let (authorized_start, authorized_len) = match executable {
            Some(plan) => plan
                .authenticated_cow_span(snapshot, va, len)
                .ok_or(ForeignMmTransportError::MutationFailed)?,
            None => (va, self.physical_len as usize),
        };
        let start = if self.fault == MockCowFault::WrongRange {
            GuestVa(authorized_start.raw() + 1)
        } else {
            authorized_start
        };
        let backend = carrick_hal::ForeignBackendRevision::from_authority_raw(
            snapshot.backend_revision().raw_for_probe()
                + u64::from(self.fault == MockCowFault::AdvancedBackend),
        );
        let vma = carrick_hal::ForeignVmaRevision::from_authority_raw(
            snapshot.vma_revision().raw_for_probe()
                + u64::from(self.fault == MockCowFault::AdvancedVma),
        );
        let inventory = carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
            snapshot.frame_inventory_revision().raw_for_probe()
                + u64::from(self.fault == MockCowFault::AdvancedInventory),
        );
        let mapping = if matches!(
            self.fault,
            MockCowFault::WrongMapping | MockCowFault::ForgedConsistentMapping
        ) {
            carrick_hal::MappingId::from_kernel_allocation(
                NonZeroU64::new(self.mapping.raw().checked_add(1).unwrap()).unwrap(),
            )
        } else {
            self.mapping
        };
        let frame = if matches!(
            self.fault,
            MockCowFault::WrongFrame | MockCowFault::ForgedConsistentFrame
        ) {
            carrick_hal::FrameId::from_kernel_allocation(
                NonZeroU64::new(self.frame.raw().checked_add(1).unwrap()).unwrap(),
            )
        } else {
            self.frame
        };
        let physical_base = if matches!(
            self.fault,
            MockCowFault::WrongPhysical | MockCowFault::ForgedConsistentPhysical
        ) {
            Gpa(self.physical_base.raw().checked_add(0x4000).unwrap())
        } else {
            self.physical_base
        };
        let owner_raw = self.owner_generation.load(Ordering::Acquire)
            + u64::from(matches!(
                self.fault,
                MockCowFault::WrongOwner | MockCowFault::ForgedConsistentOwner
            ));
        let proof = executable
            .and(self.ptrace_proof.as_ref())
            .unwrap_or(&self.proof);
        Ok(Box::new(MockCowReceipt {
            mm,
            start,
            len: if self.fault == MockCowFault::WrongRange {
                authorized_len
            } else if self.fault == MockCowFault::InflatedSemanticSpan {
                self.physical_len as usize * 2
            } else {
                authorized_len
            },
            backend,
            vma,
            inventory,
            mapping,
            frame,
            physical_base,
            physical_len: if self.fault == MockCowFault::WrongPhysicalLength {
                self.physical_len / 2
            } else {
                self.physical_len
            },
            owner: carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                NonZeroU64::new(owner_raw).unwrap(),
            ),
            kernel_proof: carrick_hal::ForeignCowKernelProof::from_runtime_authority(Box::new(
                proof.clone(),
            )),
        }))
    }

    fn prepare_write<'a>(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        cow: &dyn ForeignCowReceipt,
        va: GuestVa,
        src: &'a [u8],
        _publication: &carrick_hal::ForeignInstructionPublicationPlan,
        _deadline: Instant,
    ) -> Result<Box<dyn carrick_hal::ForeignMmPreparedWrite + 'a>, ForeignMmTransportError> {
        self.counters.prepare_calls.fetch_add(1, Ordering::SeqCst);
        if cow.owner_generation().raw_for_probe() != self.owner_generation.load(Ordering::Acquire) {
            return Err(ForeignMmTransportError::OwnerStale);
        }
        let va_end = va
            .raw()
            .checked_add(src.len() as u64)
            .ok_or(ForeignMmTransportError::MutationFailed)?;
        let span_end = cow
            .range_start()
            .raw()
            .checked_add(cow.range_len() as u64)
            .ok_or(ForeignMmTransportError::MutationFailed)?;
        if va.raw() < cow.range_start().raw() || va_end > span_end {
            return Err(ForeignMmTransportError::MutationFailed);
        }
        if cow.mm() != snapshot.mm()
            || cow.backend_revision() != snapshot.backend_revision()
            || cow.vma_revision() != snapshot.vma_revision()
            || cow.frame_inventory_revision() != snapshot.frame_inventory_revision()
        {
            return Err(ForeignMmTransportError::Retry);
        }
        if self.fault == MockCowFault::PostCopyError {
            return Err(ForeignMmTransportError::OwnerStale);
        }
        if self.fault == MockCowFault::AdvancedBackendAfterWrite {
            self.post_write_backend_revision
                .as_ref()
                .expect("post-write backend revision fixture")
                .fetch_add(1, Ordering::AcqRel);
        }
        let owner = if self.fault == MockCowFault::WrongWriteReceipt {
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                NonZeroU64::new(cow.owner_generation().raw_for_probe() + 1).unwrap(),
            )
        } else {
            cow.owner_generation()
        };
        let receipt = Box::new(MockWriteReceipt(MockCowReceipt {
            mm: cow.mm(),
            start: va,
            len: src.len(),
            backend: cow.backend_revision(),
            vma: cow.vma_revision(),
            inventory: cow.frame_inventory_revision(),
            mapping: cow.mapping(),
            frame: cow.frame(),
            physical_base: cow.physical_base(),
            physical_len: cow.physical_len(),
            owner,
            kernel_proof: carrick_hal::ForeignCowKernelProof::from_runtime_authority(Box::new(
                self.proof.clone(),
            )),
        }));
        Ok(Box::new(MockPreparedWrite {
            bytes: Arc::clone(&self.bytes),
            counters: self.counters.clone(),
            cow_base: cow.range_start(),
            src,
            receipt,
        }))
    }
}

impl ForeignMmTransport for MockCowTransport {
    fn retain(
        &self,
        _invocation: &carrick_hal::ForeignMmInvocation,
        _snapshot: &dyn ForeignMmSnapshot,
        _deadline: Instant,
    ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
        Ok(Arc::new(MockCowLease {
            owner_generation: Arc::clone(&self.owner_generation),
            bytes: Arc::clone(&self.bytes),
            counters: self.counters.clone(),
            fault: self.fault,
            proof: self.proof.clone(),
            ptrace_proof: self.ptrace_proof.clone(),
            mapping: self.mapping,
            frame: self.frame,
            physical_base: self.physical_base,
            physical_len: self.physical_len,
            post_write_backend_revision: self.post_write_backend_revision.clone(),
        }))
    }
}

pub fn fixture_backend() -> Arc<dyn MmBackend> {
    let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("nonzero ASID"));
    let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned stage-1 root");
    Arc::new(FixtureBackend {
        binding: MmBinding::for_aarch64(asid, root),
    })
}

pub fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
    let input = RootBootstrap::with_mm_backend(
        pid,
        ThreadId::synthetic_for_tests(pid),
        fixture_backend(),
        "mm-authority root".to_owned(),
        Arc::new(carrick_hal::NullHostSignalBridge::default()),
    )
    .expect("root bootstrap");
    Kernel::bootstrap_root(input).expect("root kernel")
}

pub(crate) fn task_state_for_mm(mm: MmId, marker: u64) -> MigratableTaskState {
    MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: [marker; 31],
            pc: marker,
            pstate: marker,
            trap_pc: marker,
            trap_pstate: marker,
            sp_el0: marker,
            elr_el1: marker,
            spsr_el1: marker,
            ttbr0: marker,
            ttbr1: marker,
            tcr: marker,
            sctlr_el1: marker,
            mair_el1: marker,
            vbar_el1: marker,
            cpacr_el1: marker,
            cntkctl_el1: marker,
            tpidr_el1: marker,
            actlr_el1: marker,
            tpidr_el0: marker,
            tpidrro_el0: marker,
            contextidr_el1: marker,
            vregs: [u128::from(marker); 32],
            fpsr: marker as u32,
            fpcr: marker as u32,
            pending_resume_pc: None,
            last_syscall_nr: None,
            last_syscall_orig_x0: marker,
            last_fault_esr: marker,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation: None,
            mm_generation: mm.raw(),
            asid_generation: mm.raw(),
        }),
        mm,
        asid_generation: mm.raw(),
    }
}

pub(crate) fn execution_lease_for_mm(
    context: &KernelContext,
    mm: MmId,
    marker: u64,
) -> ThreadExecutionLease {
    context
        .thread()
        .publish_initial_task_state(task_state_for_mm(mm, marker))
        .expect("publish scheduler task-state authority");
    context
        .thread()
        .claim_runnable(ExecutorId::synthetic_for_tests(marker as u32))
        .expect("claim exact execution authority")
}

pub fn execution_lease(context: &KernelContext, marker: u64) -> ThreadExecutionLease {
    execution_lease_for_mm(context, context.shared().mm().id(), marker)
}

pub fn fork_with_backend(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    registry_id: i32,
    name: &str,
    backend: Arc<dyn MmBackend>,
) -> KernelContext {
    kernel
        .reserve_fork(
            parent,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("copied-mm fork plan"),
            name.to_owned(),
            None,
        )
        .expect("reserve copied-mm fork")
        .prepare_with_mm_backend(backend, ThreadId::synthetic_for_tests(registry_id))
        .expect("prepare copied-mm fork")
        .commit()
        .expect("publish copied-mm fork")
        .into_parts()
        .expect("start copied-mm child")
        .0
}

#[cfg(test)]
pub(crate) fn fork_with_transport(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    registry_id: i32,
    name: &str,
    transport: Arc<dyn ForeignMmTransport>,
) -> KernelContext {
    let child = fork_with_backend(kernel, parent, registry_id, name, fixture_backend());
    child.shared().mm().install_foreign_mm_endpoint_for_test(
        carrick_hal::ForeignMmEndpoint::for_carrier(transport),
    );
    child
}

pub fn foreign_mm(
    kernel: &Arc<Kernel>,
    caller: &KernelContext,
    execution: &ThreadExecutionLease,
    target: TaskKey,
) -> super::super::ForeignMm {
    match kernel
        .foreign_mm(caller, execution, target)
        .expect("foreign MM authority")
    {
        MmRelation::Foreign(foreign) => foreign,
        MmRelation::Current(_) => panic!("copied-MM target must be foreign"),
    }
}

pub fn publish_cow_mapping(
    kernel: &Arc<Kernel>,
    mm: MmId,
    gpa: Gpa,
    len: u64,
) -> (carrick_hal::MappingId, carrick_hal::FrameId, u64) {
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
    let mut reservation = kernel.reserve_frame_inventory(1, 1, capacity).unwrap();
    let transaction = reservation.transaction();
    let frame = reservation.claim_frame().unwrap();
    let mapping = reservation.claim_mapping().unwrap();
    let generation =
        carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::new(1).unwrap());
    let length = carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(len).unwrap());
    reservation
        .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
            transaction,
            frame,
            mapping,
            generation,
            gpa,
            length,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
        })
        .unwrap();
    reservation
        .push(carrick_hal::FrameInventoryEvent::PublishMapping {
            transaction,
            mapping,
            generation,
        })
        .unwrap();
    let (_, revision) = kernel
        .frame_inventory()
        .apply(mm, reservation.commit(()))
        .unwrap();
    (mapping, frame, revision)
}

#[allow(clippy::type_complexity)]
pub fn cow_fixture(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    registry_id: i32,
    fault: MockCowFault,
) -> (
    KernelContext,
    Arc<MutableFixtureBackend>,
    Arc<AtomicU64>,
    Arc<parking_lot::Mutex<Vec<u8>>>,
    MockCowCounters,
) {
    let backend = MutableFixtureBackend::new();
    let child = fork_with_backend(
        kernel,
        parent,
        registry_id,
        "foreign COW child",
        Arc::clone(&backend) as Arc<dyn MmBackend>,
    );
    let owner_generation = Arc::new(AtomicU64::new(61));
    let bytes = Arc::new(parking_lot::Mutex::new(b"same".to_vec()));
    let counters = MockCowCounters::default();
    let mm = child.shared().mm().id();
    let physical_base = Gpa(0xb000);
    let physical_len = 0x4000;
    let (mapping, frame, inventory_revision) =
        publish_cow_mapping(kernel, mm, physical_base, physical_len);
    backend.bind_inventory_mapping(mapping, inventory_revision);
    let owner = carrick_hal::ForeignOwnerGeneration::from_backend_counter(
        NonZeroU64::new(owner_generation.load(Ordering::Acquire)).unwrap(),
    );
    let proof = crate::kernel::KernelForeignCowProof::new(
        Arc::clone(kernel),
        mm,
        GuestVa(0x3000),
        std::num::NonZeroUsize::new(physical_len as usize).unwrap(),
        inventory_revision,
        mapping,
        frame,
        physical_base,
        carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(physical_len).unwrap()),
        owner,
    );
    let ptrace_proof = crate::kernel::KernelForeignCowProof::new(
        Arc::clone(kernel),
        mm,
        GuestVa(0x3000),
        std::num::NonZeroUsize::new(0x1000).unwrap(),
        inventory_revision,
        mapping,
        frame,
        physical_base,
        carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(physical_len).unwrap()),
        owner,
    );
    child.shared().mm().install_foreign_mm_endpoint_for_test(
        carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockCowTransport {
            owner_generation: Arc::clone(&owner_generation),
            bytes: Arc::clone(&bytes),
            counters: counters.clone(),
            fault,
            proof,
            ptrace_proof: Some(ptrace_proof),
            mapping,
            frame,
            physical_base,
            physical_len,
            post_write_backend_revision: (fault == MockCowFault::AdvancedBackendAfterWrite)
                .then(|| Arc::clone(&backend.backend_revision)),
        })),
    );
    let stage1 = Arc::new(crate::kernel::TestStage1MmProjection::new(
        crate::kernel::test_mm_binding(1, 0x8000),
    ));
    child
        .shared()
        .mm()
        .install_foreign_mm_mutation_authority_for_test(
            crate::dispatch::mm_mutation::ForeignMmMutationAuthority::new(
                mm,
                Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm)),
                Arc::new(crate::kernel::GuestExecutorCensus::default()),
                stage1,
                Arc::clone(child.shared().mm().pt_quiesce()),
            ),
        );
    (child, backend, owner_generation, bytes, counters)
}

#[cfg(test)]
/// Authenticated foreign-COW fixture shared by syscall-consumer tests.
/// The retained peer bytes model the pre-COW source while `child_bytes`
/// are the exact backing mutated only after the runtime validates a
/// genuine kernel proof and commits a prepared write.
pub struct ConsumerCowFixture {
    target: KernelContext,
    backend: Arc<MutableFixtureBackend>,
    peer_bytes: Vec<u8>,
    child_bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
    counters: MockCowCounters,
}

#[cfg(test)]
impl ConsumerCowFixture {
    pub(crate) fn target(&self) -> &KernelContext {
        &self.target
    }

    pub(crate) fn peer_bytes(&self) -> &[u8] {
        &self.peer_bytes
    }

    pub(crate) fn child_bytes(&self, offset: usize, len: usize) -> Vec<u8> {
        self.child_bytes.lock()[offset..offset + len].to_vec()
    }

    pub(crate) fn break_calls(&self) -> usize {
        self.counters.break_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn prepare_calls(&self) -> usize {
        self.counters.prepare_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn commit_calls(&self) -> usize {
        self.counters.commit_calls.load(Ordering::SeqCst)
    }

    pub(crate) fn observe_caller_executor_census(
        &self,
        census: Arc<crate::kernel::GuestExecutorCensus>,
    ) {
        *self.counters.caller_census_probe.lock() = Some(census);
    }

    pub(crate) fn break_observed_caller_executor(&self) -> bool {
        self.counters
            .break_observed_caller_executor
            .load(Ordering::SeqCst)
    }

    pub(crate) fn set_vma_access_for_test(&self, access: VmaAccess) {
        self.backend.set_access(access);
    }
}

#[cfg(test)]
pub(crate) fn consumer_cow_fixture(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    registry_id: i32,
    initial_bytes: Vec<u8>,
) -> ConsumerCowFixture {
    assert_eq!(
        initial_bytes.len(),
        0x4000,
        "consumer fixture covers one exact 16 KiB COW compound",
    );
    let peer_bytes = initial_bytes.clone();
    let (target, backend, _owner, child_bytes, counters) =
        cow_fixture(kernel, parent, registry_id, MockCowFault::None);
    *child_bytes.lock() = initial_bytes;
    ConsumerCowFixture {
        target,
        backend,
        peer_bytes,
        child_bytes,
        counters,
    }
}

pub fn with_foreign_mutation<T>(
    foreign: &super::super::ForeignMm,
    run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
) -> T {
    super::MmAccessAuthority::new()
        .with_foreign_mutation(foreign, ThreadId::synthetic_for_tests(31_079), |mutation| {
            Ok(run(mutation))
        })
        .expect("acquire exact target-MM mutation authority")
}
