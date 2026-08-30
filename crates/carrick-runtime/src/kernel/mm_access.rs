//! Kernel-minted authority for one exact Linux address-space incarnation.

use std::marker::PhantomData;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_guest_mem::GuestVa;

use super::objects::{ThreadExecutionError, ThreadExecutionLease};
use super::{
    Kernel, KernelContext, Mm, MmBackendSnapshot, MmId, SnapshotError, TaskKey, TaskLifecycle,
};

const MM_SNAPSHOT_TIMEOUT: Duration = Duration::from_millis(50);

/// Unforgeable permission for the MM-access module to retrieve the carrier
/// endpoint installed on an exact kernel MM. Other kernel modules may name the
/// type where required by signatures, but cannot construct it.
pub(super) struct ForeignEndpointPermit {
    _private: (),
}

/// A retained, coherent observation of one exact `mm` incarnation.
///
/// Construction is confined to the kernel graph. The retained [`Arc`] keeps
/// the old address space alive across target exec and retirement without
/// retaining or following the task itself.
#[derive(Clone, Debug)]
pub struct MmToken {
    #[allow(dead_code)]
    // retained for later live-task reauthentication without exposing a raw accessor
    task: TaskKey,
    kernel: Arc<Kernel>,
    mm: Arc<Mm>,
    snapshot: MmBackendSnapshot,
    foreign_lease: Option<carrick_hal::ForeignMmLeaseEndpoint>,
    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    foreign_mutation: Option<crate::dispatch::mm_mutation::ForeignMmMutationAuthority>,
}

impl MmToken {
    pub fn mm_id(&self) -> MmId {
        self.mm.id()
    }

    pub fn read_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmReadRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::Read)?;
        Ok(Some(MmReadRange {
            token: self,
            start,
            len,
        }))
    }

    pub fn kernel_read_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmReadRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::KernelRead)?;
        Ok(Some(MmReadRange {
            token: self,
            start,
            len,
        }))
    }

    pub fn write_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmWriteRange<'_>>, MmAccessError> {
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        self.validate_range(start, len, RangeAccess::Write)?;
        Ok(Some(MmWriteRange {
            token: self,
            start,
            len,
        }))
    }

    fn validate_range(
        &self,
        start: GuestVa,
        len: NonZeroUsize,
        requested: RangeAccess,
    ) -> Result<(), MmAccessError> {
        validate_range_in_snapshot(&self.snapshot, start, len, requested)
    }
}

fn validate_range_in_snapshot(
    snapshot: &MmBackendSnapshot,
    start: GuestVa,
    len: NonZeroUsize,
    requested: RangeAccess,
) -> Result<(), MmAccessError> {
    let len_u64 = u64::try_from(len.get()).map_err(|_| MmAccessError::RangeOverflow {
        start,
        len: len.get(),
    })?;
    let end = start
        .raw()
        .checked_add(len_u64)
        .ok_or(MmAccessError::RangeOverflow {
            start,
            len: len.get(),
        })?;
    let mut cursor = start.raw();

    for vma in &snapshot.vmas {
        if vma.end.raw() <= cursor {
            continue;
        }
        if vma.start.raw() > cursor {
            return Err(MmAccessError::Unmapped {
                address: GuestVa(cursor),
            });
        }

        let access_error = match requested {
            RangeAccess::Read if !vma.access.readable => Some(MmAccessError::ReadDenied {
                address: GuestVa(cursor),
            }),
            RangeAccess::Write if !vma.access.writable => Some(MmAccessError::WriteDenied {
                address: GuestVa(cursor),
            }),
            RangeAccess::KernelRead if !vma.access.kernel_visible => {
                Some(MmAccessError::KernelHidden {
                    address: GuestVa(cursor),
                })
            }
            RangeAccess::KernelRead if !vma.access.readable => Some(MmAccessError::ReadDenied {
                address: GuestVa(cursor),
            }),
            _ => None,
        };
        if let Some(error) = access_error {
            return Err(error);
        }

        cursor = vma.end.raw().min(end);
        if cursor == end {
            return Ok(());
        }
    }

    Err(MmAccessError::Unmapped {
        address: GuestVa(cursor),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeAccess {
    Read,
    KernelRead,
    Write,
}

/// A readable non-empty range bound by lifetime to its exact MM token.
#[derive(Clone, Copy, Debug)]
pub struct MmReadRange<'mm> {
    token: &'mm MmToken,
    start: GuestVa,
    len: NonZeroUsize,
}

impl MmReadRange<'_> {
    pub const fn start(&self) -> GuestVa {
        self.start
    }

    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// A writable non-empty range bound by lifetime to its exact MM token.
#[derive(Clone, Copy, Debug)]
pub struct MmWriteRange<'mm> {
    token: &'mm MmToken,
    start: GuestVa,
    len: NonZeroUsize,
}

impl MmWriteRange<'_> {
    pub const fn start(&self) -> GuestVa {
        self.start
    }

    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// Current-MM authority tied to the exact captured kernel context.
#[derive(Clone, Debug)]
pub struct CurrentMm<'context> {
    token: MmToken,
    context: PhantomData<&'context KernelContext>,
}

impl CurrentMm<'_> {
    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }
}

/// Foreign-MM authority retaining an exact target address space.
#[derive(Clone, Debug)]
pub struct ForeignMm {
    token: MmToken,
}

impl ForeignMm {
    pub fn mm_id(&self) -> MmId {
        self.token.mm_id()
    }

    pub fn read_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmReadRange<'_>>, MmAccessError> {
        self.token.read_range(start, len)
    }

    pub fn write_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmWriteRange<'_>>, MmAccessError> {
        self.token.write_range(start, len)
    }
}

/// Reusable runtime witness that one exact foreign-MM range now names a
/// private, authenticated owner. Structurally retains the real exact
/// mutation guard; HAL receipts alone cannot manufacture write authority.
#[allow(dead_code)] // Minted and consumed by the canonical Task 8 syscall path.
pub struct CowBroken<'mm, 'guard, 'authority> {
    range: MmWriteRange<'mm>,
    transport: Box<dyn carrick_hal::ForeignCowReceipt>,
    guard: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
}

impl std::fmt::Debug for CowBroken<'_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CowBroken")
            .field("range", &self.range)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

/// Single-use runtime authority for one prepared foreign copy. Commit consumes
/// the prepared state and performs the write infallibly.
#[allow(dead_code)] // Minted and consumed by the canonical Task 8 syscall path.
pub(crate) struct PreparedForeignWrite<'mm, 'src, 'witness, 'guard, 'authority> {
    witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
    src: &'src [u8],
    transport: Box<dyn carrick_hal::ForeignMmPreparedWrite + 'src>,
    receipt: ForeignWriteReceipt,
    _marker: PhantomData<&'mm ()>,
}

impl std::fmt::Debug for PreparedForeignWrite<'_, '_, '_, '_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedForeignWrite")
            .field("src_len", &self.src.len())
            .field("transport", &self.transport)
            .field("receipt", &self.receipt)
            .finish_non_exhaustive()
    }
}

impl PreparedForeignWrite<'_, '_, '_, '_, '_> {
    #[allow(dead_code)] // Process_vm consumer in Task 8.
    pub(crate) fn commit(self) -> ForeignWriteReceipt {
        self.transport.commit();
        self.receipt
    }
}

/// Authenticated completion of one foreign copy through a consumed COW
/// witness.
#[derive(Debug)]
pub struct ForeignWriteReceipt {
    bytes_written: usize,
}

impl ForeignWriteReceipt {
    pub fn bytes_written(&self) -> usize {
        self.bytes_written
    }
}

/// Authenticated completion of a private runtime foreign read.
#[derive(Debug)]
#[allow(dead_code)] // Task 8 is the first syscall consumer.
pub(crate) struct ForeignReadReceipt {
    transport: Box<dyn carrick_hal::ForeignMmReadReceipt>,
}

impl ForeignReadReceipt {
    #[allow(dead_code)] // Task 8 is the first syscall consumer.
    pub(crate) fn bytes_read(&self) -> usize {
        self.transport.bytes_read()
    }
}

/// Private runtime facade over the carrier transport. Syscall handlers receive
/// only token-bound ranges and never transport snapshots or constructors.
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)] // Installed in Task 5; consumed by process_vm in Task 8.
pub(crate) struct MmAccessAuthority;

impl MmAccessAuthority {
    #[allow(dead_code)] // Task 8 is the first syscall consumer.
    const MAX_ATTEMPTS: usize = 3;

    const OVERALL_DEADLINE: Duration = Duration::from_millis(50);

    pub(crate) fn new() -> Self {
        Self
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub fn with_foreign_mutation<T>(
        &self,
        mm: &ForeignMm,
        tid: carrick_hal::ThreadId,
        operation: impl FnOnce(
            &mut crate::dispatch::mm_mutation::MmMutationGuard<'_>,
        ) -> Result<T, MmAccessError>,
    ) -> Result<T, MmAccessError> {
        let authority = mm
            .token
            .foreign_mutation
            .as_ref()
            .ok_or(MmAccessError::MissingForeignMutationAuthority(mm.mm_id()))?;
        authority
            .with_guard(tid, operation)
            .map_err(|error| MmAccessError::ForeignMutation(error.to_string()))?
    }

    #[allow(dead_code)] // Task 8 is the first syscall consumer.
    pub fn read_foreign(
        &self,
        mm: &ForeignMm,
        range: MmReadRange<'_>,
        dst: &mut [u8],
    ) -> Result<ForeignReadReceipt, MmAccessError> {
        if !Arc::ptr_eq(&range.token.mm, &mm.token.mm) || range.token.task != mm.token.task {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        if dst.len() != range.len.get() {
            return Err(MmAccessError::DestinationLengthMismatch {
                range: range.len.get(),
                destination: dst.len(),
            });
        }

        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let lease = mm
            .token
            .foreign_lease
            .as_ref()
            .ok_or(MmAccessError::MissingForeignTransport(mm.mm_id()))?;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&mm.token.mm),
        };
        for _ in 0..Self::MAX_ATTEMPTS {
            if Instant::now() >= deadline {
                return Err(MmAccessError::ForeignReadTimedOut);
            }
            let before_snapshot = snapshot_backend(&mm.token.mm, deadline)?;
            validate_snapshot_vmas(&before_snapshot)?;
            validate_range_in_snapshot(
                &before_snapshot,
                range.start,
                range.len,
                RangeAccess::Read,
            )?;
            let snapshot =
                ProjectedForeignMmSnapshot::from_backend(mm.token.mm_id(), &before_snapshot)?;
            let receipt = match lease.read(&live, &snapshot, range.start, dst, deadline) {
                Ok(receipt) => receipt,
                Err(carrick_hal::ForeignMmTransportError::Retry) => continue,
                Err(carrick_hal::ForeignMmTransportError::TimedOut) => {
                    return Err(MmAccessError::ForeignReadTimedOut);
                }
                Err(error) => return Err(MmAccessError::ForeignTransport(error)),
            };
            let after = ProjectedForeignMmSnapshot::from_backend(
                mm.token.mm_id(),
                &snapshot_backend(&mm.token.mm, deadline)?,
            )?;
            if after != snapshot {
                continue;
            }
            if !receipt.authenticates(&snapshot)
                || receipt.bytes_read() != dst.len()
                || (!dst.is_empty() && receipt.owner_generations().is_empty())
            {
                return Err(MmAccessError::ForeignReceiptMismatch);
            }
            return Ok(ForeignReadReceipt { transport: receipt });
        }
        Err(MmAccessError::ForeignReadRetryExhausted)
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub fn break_foreign_cow<'mm, 'guard, 'authority>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm ForeignMm,
        range: MmWriteRange<'mm>,
    ) -> Result<CowBroken<'mm, 'guard, 'authority>, MmAccessError> {
        self.break_foreign_cow_inner(mutation, mm, range, false)
    }

    #[cfg(test)]
    fn break_foreign_cow_with_final_snapshot_contended_for_test<'mm, 'guard, 'authority>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm ForeignMm,
        range: MmWriteRange<'mm>,
    ) -> Result<CowBroken<'mm, 'guard, 'authority>, MmAccessError> {
        self.break_foreign_cow_inner(mutation, mm, range, true)
    }

    fn break_foreign_cow_inner<'mm, 'guard, 'authority>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm ForeignMm,
        range: MmWriteRange<'mm>,
        contend_final_snapshot: bool,
    ) -> Result<CowBroken<'mm, 'guard, 'authority>, MmAccessError> {
        if !Arc::ptr_eq(&range.token.mm, &mm.token.mm) || range.token.task != mm.token.task {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let target_mutation = mm
            .token
            .foreign_mutation
            .as_ref()
            .ok_or(MmAccessError::MissingForeignMutationAuthority(mm.mm_id()))?;
        if !target_mutation.authorizes(mutation) {
            return Err(MmAccessError::ForeignMutationAuthorityMismatch);
        }
        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let lease = mm
            .token
            .foreign_lease
            .as_ref()
            .ok_or(MmAccessError::MissingForeignTransport(mm.mm_id()))?;
        let before = snapshot_backend(&mm.token.mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
        let requested = ProjectedForeignMmSnapshot::from_backend(mm.mm_id(), &before)?;
        let receipt = mutation.with_host_alias(|invalidator| {
            lease.break_cow(
                invalidator,
                &requested,
                range.start,
                range.len.get(),
                deadline,
            )
        });
        let receipt = match receipt {
            Ok(receipt) => receipt,
            Err(carrick_hal::ForeignMmTransportError::TimedOut) => {
                return Err(MmAccessError::ForeignWriteTimedOut);
            }
            Err(error) => return Err(MmAccessError::ForeignTransport(error)),
        };
        let validates = || {
            let req_start = range.start.raw();
            let req_len = range.len.get() as u64;
            let req_end = match req_start.checked_add(req_len) {
                Some(end) => end,
                None => return false,
            };
            let span_start = receipt.range_start().raw();
            let span_len = receipt.range_len() as u64;
            let span_end = match span_start.checked_add(span_len) {
                Some(end) => end,
                None => return false,
            };
            receipt.mm() == requested.mm
                && req_start >= span_start
                && req_end <= span_end
                && receipt.backend_revision() == requested.backend_revision
                && receipt.vma_revision() == requested.vma_revision
                && receipt.physical_len() >= range.len.get() as u64
                && receipt
                    .physical_base()
                    .raw()
                    .checked_add(receipt.physical_len())
                    .is_some()
                && receipt
                    .kernel_proof()
                    .downcast_ref::<crate::vcpu_loop::KernelForeignCowProof>()
                    .is_some_and(|proof| {
                        proof.authenticates(
                            &mm.token.kernel,
                            mm.mm_id(),
                            receipt.range_start(),
                            receipt.range_len(),
                            receipt.frame_inventory_revision().raw_for_probe(),
                            receipt.mapping(),
                            receipt.frame(),
                            receipt.physical_base(),
                            receipt.physical_len(),
                            receipt.owner_generation(),
                        )
                    })
        };
        // Test-only reblocking makes any post-commit snapshot reader time out
        // against the exact production mutation coordinator. Receipt-only
        // authentication must remain independent of that reader.
        let valid = if contend_final_snapshot {
            mutation.with_host_alias(|_| validates())
        } else {
            validates()
        };
        if !valid {
            return Err(MmAccessError::ForeignCowReceiptMismatch);
        }
        Ok(CowBroken {
            range,
            transport: receipt,
            guard: mutation,
        })
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub(crate) fn prepare_foreign_write<'mm, 'src, 'witness, 'guard, 'authority>(
        &self,
        witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
        src: &'src [u8],
    ) -> Result<PreparedForeignWrite<'mm, 'src, 'witness, 'guard, 'authority>, MmAccessError> {
        let range = witness.range;
        self.prepare_foreign_write_range(witness, range, src)
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub(crate) fn prepare_foreign_write_range<'mm, 'src, 'witness, 'guard, 'authority>(
        &self,
        witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
        range: MmWriteRange<'mm>,
        src: &'src [u8],
    ) -> Result<PreparedForeignWrite<'mm, 'src, 'witness, 'guard, 'authority>, MmAccessError> {
        if src.len() != range.len.get() {
            return Err(MmAccessError::SourceLengthMismatch {
                range: range.len.get(),
                source_len: src.len(),
            });
        }
        if !Arc::ptr_eq(&range.token.mm, &witness.range.token.mm)
            || range.token.task != witness.range.token.task
        {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let req_start = range.start.raw();
        let req_len = range.len.get() as u64;
        let req_end = req_start
            .checked_add(req_len)
            .ok_or(MmAccessError::RangeOverflow {
                start: range.start,
                len: range.len.get(),
            })?;
        let span_start = witness.transport.range_start().raw();
        let span_len = witness.transport.range_len() as u64;
        let span_end = span_start
            .checked_add(span_len)
            .ok_or(MmAccessError::RangeOverflow {
                start: witness.transport.range_start(),
                len: witness.transport.range_len(),
            })?;
        if req_start < span_start || req_end > span_end {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let mm = &range.token.mm;
        let target_mutation = range
            .token
            .foreign_mutation
            .as_ref()
            .ok_or(MmAccessError::MissingForeignMutationAuthority(mm.id()))?;
        if !target_mutation.authorizes(witness.guard) {
            return Err(MmAccessError::ForeignMutationAuthorityMismatch);
        }
        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let before = snapshot_backend(mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &before)?;
        if snapshot.mm != witness.transport.mm()
            || snapshot.backend_revision != witness.transport.backend_revision()
            || snapshot.vma_revision != witness.transport.vma_revision()
            || snapshot.frame_inventory_revision != witness.transport.frame_inventory_revision()
            || !snapshot.mapping_ids.contains(&witness.transport.mapping())
            || !witness
                .transport
                .kernel_proof()
                .downcast_ref::<crate::vcpu_loop::KernelForeignCowProof>()
                .is_some_and(|proof| {
                    proof.authenticates(
                        &range.token.kernel,
                        mm.id(),
                        witness.transport.range_start(),
                        witness.transport.range_len(),
                        witness.transport.frame_inventory_revision().raw_for_probe(),
                        witness.transport.mapping(),
                        witness.transport.frame(),
                        witness.transport.physical_base(),
                        witness.transport.physical_len(),
                        witness.transport.owner_generation(),
                    )
                })
        {
            return Err(MmAccessError::StaleCowBroken);
        }
        let lease = range
            .token
            .foreign_lease
            .as_ref()
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let live = RetainedMmLiveAuthority { mm: Arc::clone(mm) };
        let prepared_transport = match lease.prepare_write(
            &live,
            &snapshot,
            witness.transport.as_ref(),
            range.start,
            src,
            deadline,
        ) {
            Ok(prepared) => prepared,
            Err(carrick_hal::ForeignMmTransportError::TimedOut) => {
                return Err(MmAccessError::ForeignWriteTimedOut);
            }
            Err(error) => return Err(MmAccessError::ForeignTransport(error)),
        };
        let after =
            ProjectedForeignMmSnapshot::from_backend(mm.id(), &snapshot_backend(mm, deadline)?)?;
        if after != snapshot {
            return Err(MmAccessError::StaleCowBroken);
        }
        let receipt = prepared_transport.receipt();
        if receipt.mm() != snapshot.mm
            || receipt.range_start() != range.start
            || receipt.range_len() != range.len.get()
            || receipt.bytes_written() != src.len()
            || receipt.backend_revision() != snapshot.backend_revision
            || receipt.vma_revision() != snapshot.vma_revision
            || receipt.frame_inventory_revision() != snapshot.frame_inventory_revision
            || receipt.mapping() != witness.transport.mapping()
            || receipt.frame() != witness.transport.frame()
            || receipt.owner_generation() != witness.transport.owner_generation()
        {
            return Err(MmAccessError::ForeignWriteReceiptMismatch);
        }
        let receipt = ForeignWriteReceipt {
            bytes_written: receipt.bytes_written(),
        };
        Ok(PreparedForeignWrite {
            witness,
            src,
            transport: prepared_transport,
            receipt,
            _marker: PhantomData,
        })
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub(crate) fn commit_foreign_write(
        &self,
        prepared: PreparedForeignWrite<'_, '_, '_, '_, '_>,
    ) -> ForeignWriteReceipt {
        prepared.commit()
    }
}

#[allow(dead_code)] // Task 8 is the first syscall consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectedForeignMmSnapshot {
    mm: carrick_hal::ForeignMmId,
    binding: carrick_hal::ForeignMmBinding,
    backend_revision: carrick_hal::ForeignBackendRevision,
    vma_revision: carrick_hal::ForeignVmaRevision,
    frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision,
    mapping_ids: Vec<carrick_hal::MappingId>,
}

impl ProjectedForeignMmSnapshot {
    fn from_backend(mm_id: MmId, snapshot: &MmBackendSnapshot) -> Result<Self, MmAccessError> {
        let vma_revision = snapshot
            .vma_revision
            .ok_or(MmAccessError::IncompleteForeignSnapshot(mm_id))?;
        let frame_inventory_revision = snapshot
            .frame_inventory_revision
            .ok_or(MmAccessError::IncompleteForeignSnapshot(mm_id))?;
        Ok(Self {
            mm: carrick_hal::ForeignMmId::from_kernel_allocation(
                NonZeroU64::new(mm_id.raw())
                    .ok_or(MmAccessError::IncompleteForeignSnapshot(mm_id))?,
            ),
            binding: carrick_hal::ForeignMmBinding::for_aarch64(
                carrick_hal::ForeignAsid::from_kernel_allocation(
                    NonZeroU16::new(snapshot.binding.asid.raw())
                        .ok_or(MmAccessError::IncompleteForeignSnapshot(mm_id))?,
                ),
                snapshot.binding.stage1_root.gpa(),
            ),
            backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(
                snapshot.revision,
            ),
            vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(vma_revision.raw()),
            frame_inventory_revision:
                carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                    frame_inventory_revision,
                ),
            mapping_ids: snapshot.mapping_ids.clone(),
        })
    }
}

impl carrick_hal::ForeignMmSnapshot for ProjectedForeignMmSnapshot {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        self.mm
    }
    fn binding(&self) -> carrick_hal::ForeignMmBinding {
        self.binding
    }
    fn backend_revision(&self) -> carrick_hal::ForeignBackendRevision {
        self.backend_revision
    }
    fn vma_revision(&self) -> carrick_hal::ForeignVmaRevision {
        self.vma_revision
    }
    fn frame_inventory_revision(&self) -> carrick_hal::ForeignFrameInventoryRevision {
        self.frame_inventory_revision
    }
    fn mapping_ids(&self) -> &[carrick_hal::MappingId] {
        &self.mapping_ids
    }
}

#[derive(Debug)]
struct RetainedMmLiveAuthority {
    mm: Arc<Mm>,
}

impl carrick_hal::ForeignMmLiveAuthority for RetainedMmLiveAuthority {
    fn snapshot(
        &self,
        deadline: Instant,
    ) -> Result<Box<dyn carrick_hal::ForeignMmSnapshot>, carrick_hal::ForeignMmTransportError> {
        let snapshot =
            snapshot_backend(&self.mm, deadline).map_err(snapshot_error_for_transport)?;
        let projected = ProjectedForeignMmSnapshot::from_backend(self.mm.id(), &snapshot)
            .map_err(|_| carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?;
        Ok(Box::new(projected))
    }
}

fn snapshot_error_for_transport(error: MmAccessError) -> carrick_hal::ForeignMmTransportError {
    match error {
        MmAccessError::Snapshot(SnapshotError::TimedOut) => {
            carrick_hal::ForeignMmTransportError::TimedOut
        }
        MmAccessError::Snapshot(SnapshotError::ChangedDuringObservation | SnapshotError::Busy) => {
            carrick_hal::ForeignMmTransportError::Retry
        }
        _ => carrick_hal::ForeignMmTransportError::AuthorityUnavailable,
    }
}

#[derive(Clone, Debug)]
pub enum MmRelation<'context> {
    Current(CurrentMm<'context>),
    Foreign(ForeignMm),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MmAccessError {
    #[error("kernel task {0:?} is not live at the requested generation")]
    UnknownTask(TaskKey),
    #[error("kernel context for task {0:?} no longer names its exact live task/MM binding")]
    StaleContext(TaskKey),
    #[error(transparent)]
    ExecutionAuthority(#[from] ThreadExecutionError),
    #[error("execution authority does not name the exact scheduler MM for task {task:?}")]
    StaleExecutionAuthority { task: TaskKey },
    #[error("MM {0:?} has no backend snapshot authority")]
    MissingBackendAuthority(MmId),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error("MM snapshot contains malformed or overlapping VMA {start:?}..{end:?}")]
    MalformedVma { start: GuestVa, end: GuestVa },
    #[error("MM range {start:?} + {len} bytes overflows the guest VA domain")]
    RangeOverflow { start: GuestVa, len: usize },
    #[error("guest address {address:?} is not mapped in this MM")]
    Unmapped { address: GuestVa },
    #[error("guest address {address:?} is not readable in this MM")]
    ReadDenied { address: GuestVa },
    #[error("guest address {address:?} is not writable in this MM")]
    WriteDenied { address: GuestVa },
    #[error("guest address {address:?} is hidden from kernel memory access")]
    KernelHidden { address: GuestVa },
    #[error("foreign read range is not bound to the supplied retained MM")]
    ForeignRangeAuthorityMismatch,
    #[error("page-table mutation authority does not name the exact foreign MM")]
    ForeignMutationAuthorityMismatch,
    #[error("foreign read destination length {destination} does not match range length {range}")]
    DestinationLengthMismatch { range: usize, destination: usize },
    #[error("MM {0:?} lacks typed HVPatch foreign-read snapshot domains")]
    IncompleteForeignSnapshot(MmId),
    #[error("MM {0:?} has no carrier foreign-read transport")]
    MissingForeignTransport(MmId),
    #[error("MM {0:?} has no exact target-MM mutation authority")]
    MissingForeignMutationAuthority(MmId),
    #[error("foreign MM mutation authority failed: {0}")]
    ForeignMutation(String),
    #[error(transparent)]
    ForeignTransport(carrick_hal::ForeignMmTransportError),
    #[error("foreign MM transport receipt does not authenticate the requested snapshot")]
    ForeignReceiptMismatch,
    #[error("foreign MM changed throughout the bounded read retry budget")]
    ForeignReadRetryExhausted,
    #[error("foreign MM read exceeded its overall deadline budget")]
    ForeignReadTimedOut,
    #[error("foreign COW receipt does not authenticate the exact MM/range/revisions")]
    ForeignCowReceiptMismatch,
    #[error("foreign write receipt does not authenticate the consumed COW witness")]
    ForeignWriteReceiptMismatch,
    #[error("foreign write source length {source_len} does not match range length {range}")]
    SourceLengthMismatch { range: usize, source_len: usize },
    #[error("foreign COW witness no longer matches the three live MM revisions")]
    StaleCowBroken,
    #[error("foreign MM write exceeded its overall deadline budget")]
    ForeignWriteTimedOut,
}

impl KernelContext {
    pub fn current_mm(
        &self,
        execution: &ThreadExecutionLease,
    ) -> Result<CurrentMm<'_>, MmAccessError> {
        let mm = self.authenticate_current_mm(execution)?;
        let token = snapshot_token(self.task.key(), Arc::clone(&self.kernel), mm, false)?;
        Ok(CurrentMm {
            token,
            context: PhantomData,
        })
    }

    fn authenticate_current_mm(
        &self,
        execution: &ThreadExecutionLease,
    ) -> Result<Arc<Mm>, MmAccessError> {
        let key = self.task.key();
        if self.task.lifecycle() != TaskLifecycle::Live || self.thread.task_key() != key {
            return Err(MmAccessError::StaleContext(key));
        }
        let Some(live_task) = self.kernel.registry().task(key.id) else {
            return Err(MmAccessError::StaleContext(key));
        };
        let Some(live_thread) = live_task.thread(self.thread.key().tid) else {
            return Err(MmAccessError::StaleContext(key));
        };
        let live_shared = live_task.shared();
        let context_mm = self.shared.mm();
        let live_mm = live_shared.mm();
        if live_task.key() != key
            || !Arc::ptr_eq(&live_task, &self.task)
            || !Arc::ptr_eq(&live_thread, &self.thread)
            || !Arc::ptr_eq(&live_shared, &self.shared)
            || live_mm.id() != context_mm.id()
            || !Arc::ptr_eq(&live_mm, &context_mm)
        {
            return Err(MmAccessError::StaleContext(key));
        }
        let (scheduler_mm, _scheduler_asid_generation) =
            self.thread.authenticate_task_state_authority(execution)?;
        if scheduler_mm != context_mm.id() {
            return Err(MmAccessError::StaleExecutionAuthority { task: key });
        }
        Ok(context_mm)
    }
}

impl Kernel {
    pub fn foreign_mm<'context>(
        &self,
        caller: &'context KernelContext,
        execution: &ThreadExecutionLease,
        target: TaskKey,
    ) -> Result<MmRelation<'context>, MmAccessError> {
        if !std::ptr::eq(self, caller.kernel.as_ref()) {
            return Err(MmAccessError::StaleContext(caller.task.key()));
        }
        let caller_mm = caller.authenticate_current_mm(execution)?;
        let Some(task) = self.registry().task(target.id) else {
            return Err(MmAccessError::UnknownTask(target));
        };
        if task.key() != target || task.lifecycle() != TaskLifecycle::Live {
            return Err(MmAccessError::UnknownTask(target));
        }
        let target_mm = task.shared().mm();
        let is_foreign = target_mm.id() != caller_mm.id() || !Arc::ptr_eq(&target_mm, &caller_mm);
        let token = snapshot_token(target, Arc::clone(&caller.kernel), target_mm, is_foreign)?;
        if token.mm_id() == caller_mm.id() && Arc::ptr_eq(&token.mm, &caller_mm) {
            Ok(MmRelation::Current(CurrentMm {
                token,
                context: PhantomData,
            }))
        } else {
            Ok(MmRelation::Foreign(ForeignMm { token }))
        }
    }
}

fn snapshot_token(
    task: TaskKey,
    kernel: Arc<Kernel>,
    mm: Arc<Mm>,
    retain_foreign: bool,
) -> Result<MmToken, MmAccessError> {
    let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
    let snapshot = snapshot_backend(&mm, deadline)?;
    validate_snapshot_vmas(&snapshot)?;
    let foreign_lease = if retain_foreign {
        let permit = ForeignEndpointPermit { _private: () };
        let endpoint = mm
            .foreign_mm_endpoint(&permit, deadline)
            .ok_or(MmAccessError::ForeignReadTimedOut)?
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let projected = ProjectedForeignMmSnapshot::from_backend(mm.id(), &snapshot)?;
        Some(
            endpoint
                .retain(&projected, deadline)
                .map_err(MmAccessError::ForeignTransport)?,
        )
    } else {
        None
    };
    let foreign_mutation = if retain_foreign {
        let permit = ForeignEndpointPermit { _private: () };
        mm.foreign_mm_mutation_authority(&permit, deadline)
            .ok_or(MmAccessError::ForeignReadTimedOut)?
    } else {
        None
    };
    Ok(MmToken {
        task,
        kernel,
        mm,
        snapshot,
        foreign_lease,
        foreign_mutation,
    })
}

fn snapshot_backend(mm: &Arc<Mm>, deadline: Instant) -> Result<MmBackendSnapshot, MmAccessError> {
    let backend = mm
        .backend()
        .ok_or(MmAccessError::MissingBackendAuthority(mm.id()))?;
    let mut snapshot = backend.snapshot(deadline)?;
    if backend.revision() != snapshot.revision
        || backend.vma_revision(deadline)? != snapshot.vma_revision
    {
        return Err(MmAccessError::Snapshot(
            SnapshotError::ChangedDuringObservation,
        ));
    }
    snapshot
        .vmas
        .sort_unstable_by_key(|vma| (vma.start.raw(), vma.end.raw()));
    Ok(snapshot)
}

fn validate_snapshot_vmas(snapshot: &MmBackendSnapshot) -> Result<(), MmAccessError> {
    let mut previous_end = None;
    for vma in &snapshot.vmas {
        if vma.start.raw() >= vma.end.raw() || previous_end.is_some_and(|end| vma.start.raw() < end)
        {
            return Err(MmAccessError::MalformedVma {
                start: vma.start,
                end: vma.end,
            });
        }
        previous_end = Some(vma.end.raw());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::num::{NonZeroU16, NonZeroU64};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
    use carrick_hal::{
        ForeignCowReceipt, ForeignMmPreparedWrite, ForeignMmReadLease, ForeignMmReadReceipt,
        ForeignMmSnapshot, ForeignMmTransport, ForeignMmTransportError, ForeignMmWriteReceipt,
        ThreadId, VcpuKickDyn, VcpuRegistry,
    };

    use super::ProjectedForeignMmSnapshot;

    struct LeaveGuestOnKick(Arc<carrick_hal::InGuestFlag>);

    impl VcpuKickDyn for LeaveGuestOnKick {
        fn kick(&self) {
            self.0.leave_guest();
        }
    }

    use super::super::objects::{
        ExecutorId, MigratableTaskState, ThreadExecutionError, ThreadExecutionLease,
    };
    use super::super::{
        Asid, ClonePlan, Kernel, KernelContext, LinuxWaitStatus, MmAccessError, MmBackend,
        MmBackendSnapshot, MmBinding, MmId, MmReadRange, MmRelation, MmToken, MmWriteRange,
        RootBootstrap, SnapshotError, Stage1Root, TaskKey, VmaAccess, VmaRevision, VmaSummary,
    };

    #[derive(Debug)]
    struct FixtureBackend {
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

    #[derive(Debug)]
    struct ChurningBackend {
        backend_revision: AtomicU64,
    }

    #[derive(Clone, Copy, Debug)]
    enum MockReadMode {
        RetryOnce,
        AlwaysRetry,
        EmptyOwners,
        Deadline,
    }

    #[derive(Debug)]
    struct MockForeignTransport {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        mode: MockReadMode,
    }

    #[derive(Debug)]
    struct MockForeignLease {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        mode: MockReadMode,
    }

    #[derive(Debug)]
    struct MockForeignReceipt {
        bytes: usize,
        owners: Vec<carrick_hal::ForeignOwnerGeneration>,
    }

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
    struct MutableFixtureBackend {
        binding: MmBinding,
        backend_revision: Arc<AtomicU64>,
        vma_revision: AtomicU64,
        inventory_revision: AtomicU64,
        mapping: parking_lot::RwLock<carrick_hal::MappingId>,
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
            })
        }

        fn bind_inventory_mapping(&self, mapping: carrick_hal::MappingId, revision: u64) {
            *self.mapping.write() = mapping;
            self.inventory_revision.store(revision, Ordering::Release);
        }

        fn advance(&self, domain: usize) {
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
                    access: VmaAccess {
                        readable: true,
                        writable: true,
                        executable: false,
                        kernel_visible: true,
                    },
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
    enum MockCowFault {
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
    struct MockCowCounters {
        break_calls: Arc<AtomicUsize>,
        prepare_calls: Arc<AtomicUsize>,
        commit_calls: Arc<AtomicUsize>,
        caller_census_probe:
            Arc<parking_lot::Mutex<Option<Arc<crate::kernel::GuestExecutorCensus>>>>,
        break_observed_caller_executor: Arc<std::sync::atomic::AtomicBool>,
    }

    #[derive(Debug)]
    struct MockCowTransport {
        owner_generation: Arc<AtomicU64>,
        bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
        counters: MockCowCounters,
        fault: MockCowFault,
        proof: crate::vcpu_loop::KernelForeignCowProof,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: Gpa,
        physical_len: u64,
        post_write_backend_revision: Option<Arc<AtomicU64>>,
    }

    struct OwnerSigningOracleTransport {
        lease: Arc<OwnerSigningOracleLease>,
    }

    impl std::fmt::Debug for OwnerSigningOracleTransport {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OwnerSigningOracleTransport")
                .finish_non_exhaustive()
        }
    }

    struct OwnerSigningOracleLease {
        authority: Arc<dyn carrick_hal::FrameCowAuthority>,
        commit: parking_lot::Mutex<Option<carrick_hal::FrameInventoryCommit<()>>>,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: Gpa,
        physical_len: carrick_hal::FrameLength,
        transport_chosen_owner: carrick_hal::ForeignOwnerGeneration,
    }

    impl std::fmt::Debug for OwnerSigningOracleLease {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("OwnerSigningOracleLease")
                .field("mapping", &self.mapping)
                .field("frame", &self.frame)
                .field("physical_base", &self.physical_base)
                .field("physical_len", &self.physical_len)
                .field("transport_chosen_owner", &self.transport_chosen_owner)
                .finish_non_exhaustive()
        }
    }

    #[derive(Debug)]
    struct MockCowLease {
        owner_generation: Arc<AtomicU64>,
        bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
        counters: MockCowCounters,
        fault: MockCowFault,
        proof: crate::vcpu_loop::KernelForeignCowProof,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: Gpa,
        physical_len: u64,
        post_write_backend_revision: Option<Arc<AtomicU64>>,
    }

    #[derive(Debug)]
    struct MockCowReceipt {
        mm: carrick_hal::ForeignMmId,
        start: GuestVa,
        len: usize,
        backend: carrick_hal::ForeignBackendRevision,
        vma: carrick_hal::ForeignVmaRevision,
        inventory: carrick_hal::ForeignFrameInventoryRevision,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        physical_base: Gpa,
        physical_len: u64,
        owner: carrick_hal::ForeignOwnerGeneration,
        kernel_proof: carrick_hal::ForeignCowKernelProof,
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
    struct MockWriteReceipt(MockCowReceipt);

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
    struct MockPreparedWrite<'a> {
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
                carrick_hal::ForeignMmId::from_kernel_allocation(next(
                    snapshot.mm().raw_for_probe(),
                ))
            } else {
                snapshot.mm()
            };
            let start = if self.fault == MockCowFault::WrongRange {
                GuestVa(va.raw() + 1)
            } else {
                va
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
            Ok(Box::new(MockCowReceipt {
                mm,
                start,
                len: if self.fault == MockCowFault::WrongRange {
                    len
                } else if self.fault == MockCowFault::InflatedSemanticSpan {
                    self.physical_len as usize * 2
                } else {
                    self.physical_len as usize
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
                    self.proof.clone(),
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
            _deadline: Instant,
        ) -> Result<Box<dyn carrick_hal::ForeignMmPreparedWrite + 'a>, ForeignMmTransportError>
        {
            self.counters.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if cow.owner_generation().raw_for_probe()
                != self.owner_generation.load(Ordering::Acquire)
            {
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
                mapping: self.mapping,
                frame: self.frame,
                physical_base: self.physical_base,
                physical_len: self.physical_len,
                post_write_backend_revision: self.post_write_backend_revision.clone(),
            }))
        }
    }

    impl ForeignMmReadLease for OwnerSigningOracleLease {
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
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
            let commit = self
                .commit
                .lock()
                .take()
                .ok_or(ForeignMmTransportError::MutationFailed)?;
            let (apply, kernel_proof, _independent_owner) = self
                .authority
                .apply_foreign_cow(
                    commit,
                    va,
                    std::num::NonZeroUsize::new(len)
                        .ok_or(ForeignMmTransportError::MutationFailed)?,
                    self.mapping,
                    self.frame,
                    self.physical_base,
                    self.physical_len,
                )
                .map_err(|_| ForeignMmTransportError::MutationFailed)?;
            Ok(Box::new(MockCowReceipt {
                mm: snapshot.mm(),
                start: va,
                len,
                backend: snapshot.backend_revision(),
                vma: snapshot.vma_revision(),
                inventory: carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                    apply.revision(),
                ),
                mapping: self.mapping,
                frame: self.frame,
                physical_base: self.physical_base,
                physical_len: self.physical_len.raw(),
                owner: self.transport_chosen_owner,
                kernel_proof,
            }))
        }
    }

    impl ForeignMmTransport for OwnerSigningOracleTransport {
        fn retain(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _snapshot: &dyn ForeignMmSnapshot,
            _deadline: Instant,
        ) -> Result<Arc<dyn ForeignMmReadLease>, ForeignMmTransportError> {
            Ok(self.lease.clone())
        }
    }

    fn fixture_backend() -> Arc<dyn MmBackend> {
        let asid = Asid::from_registry_allocation(NonZeroU16::new(7).expect("nonzero ASID"));
        let root = Stage1Root::for_aarch64_4k(Gpa(0x8000)).expect("aligned stage-1 root");
        Arc::new(FixtureBackend {
            binding: MmBinding::for_aarch64(asid, root),
        })
    }

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::with_mm_backend(
            pid,
            ThreadId::synthetic_for_tests(pid),
            fixture_backend(),
            "mm-authority root".to_owned(),
        )
        .expect("root bootstrap");
        Kernel::bootstrap_root(input).expect("root kernel")
    }

    fn task_state_for_mm(mm: MmId, marker: u64) -> MigratableTaskState {
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

    fn execution_lease_for_mm(
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

    fn execution_lease(context: &KernelContext, marker: u64) -> ThreadExecutionLease {
        execution_lease_for_mm(context, context.shared().mm().id(), marker)
    }

    fn fork_with_backend(
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

    fn fork_with_transport(
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

    fn foreign_mm(
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

    fn publish_cow_mapping(
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
    fn cow_fixture(
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
        let proof = crate::vcpu_loop::KernelForeignCowProof::new(
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
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockCowTransport {
                owner_generation: Arc::clone(&owner_generation),
                bytes: Arc::clone(&bytes),
                counters: counters.clone(),
                fault,
                proof,
                mapping,
                frame,
                physical_base,
                physical_len,
                post_write_backend_revision: (fault == MockCowFault::AdvancedBackendAfterWrite)
                    .then(|| Arc::clone(&backend.backend_revision)),
            })),
        );
        let (_stage1_pool, stage1) = crate::hvpatch::Stage1MmPool::new_root_for_tests(0x8000, 4)
            .expect("foreign mutation test stage-1 lease");
        child
            .shared()
            .mm()
            .install_foreign_mm_mutation_authority_for_test(
                crate::dispatch::mm_mutation::ForeignMmMutationAuthority::new(
                    mm,
                    Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm)),
                    Arc::new(crate::kernel::GuestExecutorCensus::default()),
                    stage1,
                ),
            );
        (child, backend, owner_generation, bytes, counters)
    }

    /// Authenticated foreign-COW fixture shared by syscall-consumer tests.
    /// The retained peer bytes model the pre-COW source while `child_bytes`
    /// are the exact backing mutated only after the runtime validates a
    /// genuine kernel proof and commits a prepared write.
    pub(crate) struct ConsumerCowFixture {
        target: KernelContext,
        peer_bytes: Vec<u8>,
        child_bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
        counters: MockCowCounters,
    }

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
    }

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
        let (target, _backend, _owner, child_bytes, counters) =
            cow_fixture(kernel, parent, registry_id, MockCowFault::None);
        *child_bytes.lock() = initial_bytes;
        ConsumerCowFixture {
            target,
            peer_bytes,
            child_bytes,
            counters,
        }
    }

    fn production_composition_cow_fixture(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
    ) -> KernelContext {
        let (_stage1_pool, stage1) = crate::hvpatch::Stage1MmPool::new_root_for_tests(
            0x20_0000 + (registry_id as u64 & 0xff) * 0x1000,
            4,
        )
        .expect("production composition stage-1 lease");
        let backend = stage1.backend();
        let child = fork_with_backend(
            kernel,
            parent,
            registry_id,
            "production foreign COW composition",
            Arc::clone(&backend) as Arc<dyn MmBackend>,
        );
        let mm = child.shared().mm().id();
        let (dispatch_mm, mutation) =
            crate::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                Arc::clone(&stage1),
                0x3000,
                0x4000,
            );
        backend.bind_inventory(kernel, mm);
        backend.bind_vma_source(dispatch_mm);
        let physical_base = Gpa(0xb000);
        let physical_len = 0x4000;
        let (mapping, frame, inventory_revision) =
            publish_cow_mapping(kernel, mm, physical_base, physical_len);
        let owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(61).unwrap());
        let proof = crate::vcpu_loop::KernelForeignCowProof::new(
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
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockCowTransport {
                owner_generation: Arc::new(AtomicU64::new(61)),
                bytes: Arc::new(parking_lot::Mutex::new(b"same".to_vec())),
                counters: MockCowCounters::default(),
                fault: MockCowFault::ReacquireSnapshot,
                proof,
                mapping,
                frame,
                physical_base,
                physical_len,
                post_write_backend_revision: None,
            })),
        );
        child
            .shared()
            .mm()
            .install_foreign_mm_mutation_authority_for_test(mutation);
        child
    }

    struct RealProductionCowFixture {
        child: KernelContext,
        stage1: Arc<crate::hvpatch::Stage1MmLease>,
        dispatch_mm: Arc<crate::dispatch::DispatchMmAuthority>,
        carrier:
            carrick_vmm_hvf::trap::foreign_cow_test_support::ProductionCarrierForeignCowHarness,
    }

    fn real_production_cow_fixture(
        kernel: &Arc<Kernel>,
        parent: &KernelContext,
        registry_id: i32,
        stage1_root: u64,
        data_ipa: u64,
        caller_tid: ThreadId,
    ) -> RealProductionCowFixture {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::{
            FixtureShape, InitialInventoryIdentity, ProductionCarrierForeignCowHarness, TEST_VA,
        };

        let (_stage1_pool, stage1) =
            crate::hvpatch::Stage1MmPool::new_root_for_tests(stage1_root, 4)
                .expect("real production foreign COW stage-1 lease");
        let backend = stage1.backend();
        let child = fork_with_backend(
            kernel,
            parent,
            registry_id,
            "real production carrier foreign COW",
            Arc::clone(&backend) as Arc<dyn MmBackend>,
        );
        let mm = child.shared().mm().id();
        let shape = FixtureShape::new(Gpa(stage1_root), Gpa(data_ipa))
            .expect("real production carrier fixture shape");
        let (dispatch_mm, mutation) =
            crate::dispatch::DispatchMmAuthority::foreign_cow_composition_for_test(
                mm,
                Arc::clone(&stage1),
                TEST_VA,
                TEST_VA + shape.data_len,
            );
        backend.bind_inventory(kernel, mm);
        let vma_source: crate::kernel::SharedVmaSnapshotSource = dispatch_mm.clone();
        backend.bind_vma_source(vma_source);
        let (root_mapping, root_frame, _) =
            publish_cow_mapping(kernel, mm, shape.stage1_root, shape.page_table_len);
        let (data_mapping, data_frame, _) =
            publish_cow_mapping(kernel, mm, shape.data_ipa, shape.data_len);
        let backend_snapshot = backend
            .snapshot(Instant::now() + std::time::Duration::from_secs(1))
            .expect("real production carrier snapshot");
        let projected = ProjectedForeignMmSnapshot::from_backend(mm, &backend_snapshot)
            .expect("typed real production carrier snapshot");
        let census = dispatch_mm.foreign_cow_executor_census_for_test();
        let authority = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(kernel),
            mm,
            census,
            caller_tid,
            projected.binding.asid().raw_for_probe(),
            carrick_vmm_hvf::trap::foreign_cow_test_support::owner_inventory(),
        );
        let identity = carrick_hal::FrameCowIdentity {
            linux_pid: caller_tid.raw(),
            linux_tid: caller_tid.raw(),
            mm: mm.raw(),
            asid: projected.binding.asid().raw_for_probe(),
        };
        let carrier = ProductionCarrierForeignCowHarness::install(
            &projected,
            shape,
            InitialInventoryIdentity {
                root_mapping,
                root_frame,
                data_mapping,
                data_frame,
            },
            authority,
            identity,
            registry_id as u64,
            *b"same",
        )
        .expect("install production carrier foreign COW transport");
        child
            .shared()
            .mm()
            .install_foreign_mm_endpoint_for_test(carrier.endpoint());
        child
            .shared()
            .mm()
            .install_foreign_mm_mutation_authority_for_test(mutation);
        RealProductionCowFixture {
            child,
            stage1,
            dispatch_mm,
            carrier,
        }
    }

    fn with_mm_mutation<T>(
        mm: MmId,
        run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> T {
        let coordinator = Arc::new(crate::dispatch::mm_mutation::MmMutationCoordinator::new(mm));
        crate::vcpu_loop::with_real_pt_pause_for_test(coordinator, |pause| {
            let mut mutation = crate::dispatch::mm_mutation::from_pt_pause(pause);
            run(&mut mutation)
        })
    }

    fn with_foreign_mutation<T>(
        foreign: &super::super::ForeignMm,
        run: impl FnOnce(&mut crate::dispatch::mm_mutation::MmMutationGuard<'_>) -> T,
    ) -> T {
        super::MmAccessAuthority::new()
            .with_foreign_mutation(foreign, ThreadId::synthetic_for_tests(31_079), |mutation| {
                Ok(run(mutation))
            })
            .expect("acquire exact target-MM mutation authority")
    }

    #[test]
    fn foreign_cow_write_separates_copied_parent_and_child_at_the_same_va() {
        let (kernel, root) = bootstrap(31_080);
        let execution = execution_lease(&root, 80);
        let parent_bytes = b"same".to_vec();
        let (child, _backend, _owner, child_bytes, _counters) =
            cow_fixture(&kernel, &root, 31_081, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            let mut cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("break exact child COW");
            let prepared = super::MmAccessAuthority::new()
                .prepare_foreign_write(&mut cow, b"edit")
                .expect("copy through authenticated child owner");
            let receipt = super::MmAccessAuthority::new().commit_foreign_write(prepared);
            assert_eq!(receipt.bytes_written(), 4);
        });

        assert_eq!(parent_bytes, b"same");
        assert_eq!(&*child_bytes.lock(), b"edit");
    }

    #[test]
    fn production_composition_foreign_cow_does_not_reacquire_snapshot_under_alias() {
        let (kernel, root) = bootstrap(31_075);
        let execution = execution_lease(&root, 75);
        let child = production_composition_cow_fixture(&kernel, &root, 31_076);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(result.is_ok(), "production composition failed: {result:?}");
    }

    #[test]
    fn production_composition_committed_cow_ignores_final_snapshot_contention() {
        let (kernel, root) = bootstrap(31_077);
        let execution = execution_lease(&root, 77);
        let child = production_composition_cow_fixture(&kernel, &root, 31_078);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            super::MmAccessAuthority::new()
                .break_foreign_cow_with_final_snapshot_contended_for_test(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(
            result.is_ok(),
            "post-commit receipt validation reacquired a contended snapshot: {result:?}"
        );
    }

    #[test]
    fn production_carrier_foreign_cow_runs_end_to_end_through_runtime_facade() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_110);
        let execution = execution_lease(&root, 110);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_111,
            0x9a00_3000_0000,
            0x9b00_3000_0000,
            ThreadId::synthetic_for_tests(31_079),
        );
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let write = with_foreign_mutation(&foreign, |mutation| {
            let mut cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("production carrier COW transaction");
            let prepared = super::MmAccessAuthority::new()
                .prepare_foreign_write(&mut cow, b"edit")
                .expect("production carrier authenticated write");
            super::MmAccessAuthority::new().commit_foreign_write(prepared)
        });

        assert_eq!(write.bytes_written(), 4);
        assert_eq!(
            fixture.stage1.binding().stage1_root.gpa(),
            Gpa(0x9a00_3000_0000)
        );
        assert_ne!(fixture.dispatch_mm.vma_revision().raw(), 0);
        let _keep_carrier_live = &fixture.carrier;
    }

    #[test]
    fn production_carrier_budget_one_full_occupancy_defers_caller_self_ack_to_entry() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        const ISOLATED_ENV: &str = "CARRICK_TASK7_BUDGET_ONE_CHILD";
        if std::env::var_os(ISOLATED_ENV).is_none() {
            let status = std::process::Command::new(
                std::env::current_exe().expect("locate runtime unit-test executable"),
            )
            .arg("--exact")
            .arg(
                "kernel::mm_access::tests::production_carrier_budget_one_full_occupancy_defers_caller_self_ack_to_entry",
            )
            .arg("--nocapture")
            .env(ISOLATED_ENV, "1")
            .status()
            .expect("run isolated production vCPU-budget test");
            assert!(
                status.success(),
                "isolated production vCPU-budget test failed"
            );
            return;
        }
        let _handshake = crate::vcpu_loop::quiesce::foreign_cow_handshake_test_lock();
        let (kernel, root) = bootstrap(31_112);
        let execution = execution_lease(&root, 112);
        let caller_tid = ThreadId::synthetic_for_tests(31_079);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_113,
            0x9a00_3100_0000,
            0x9b00_3100_0000,
            caller_tid,
        );
        let mm = fixture.child.shared().mm().id();
        let caller_executor = ExecutorId::for_transitional_thread(caller_tid)
            .expect("production caller executor identity");
        fixture
            .stage1
            .begin_asid_load(caller_executor)
            .expect("publish caller target-MM load")
            .mark_resident()
            .expect("publish caller target-MM residency");
        let binding = crate::vcpu_loop::quiesce::foreign_cow_task_binding_for_test(
            Arc::clone(&fixture.stage1),
            mm,
        )
        .expect("construct caller foreign-COW task binding");
        let observer = binding.cow_invalidation_observer(caller_executor);
        carrick_hal::vcpu_sched::install_for_budget(1);
        let scheduler = carrick_hal::vcpu_sched::global();
        let occupied = scheduler.acquire(caller_tid.raw() as u64);
        assert!(
            !scheduler.has_spare_capacity(),
            "the caller owns the sole vCPU"
        );
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("full-occupancy carrier COW must not acquire a maintenance vCPU");
        });
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(caller_executor)
                .is_some(),
            "foreign caller resident must not be awaited as its own command"
        );
        assert!(
            !scheduler.has_waiters(),
            "COW attempted a second vCPU acquisition"
        );

        let in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let hardware_calls = AtomicUsize::new(0);
        let entered =
            crate::vcpu_loop::quiesce::enter_hvpatch_guest_or_service_invalidation_for_test(
                &in_guest,
                caller_tid,
                caller_executor,
                &binding,
                &observer,
                |_| {
                    hardware_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect("mandatory production pre-entry invalidation service");
        assert!(
            entered,
            "inactive resident should continue into guest after service"
        );
        in_guest.leave_guest();
        assert_eq!(hardware_calls.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(caller_executor)
                .is_none()
        );
        scheduler.release(occupied, carrick_hal::vcpu_sched::Yield::Exited);
    }

    #[test]
    fn production_carrier_active_target_services_publication_on_owner_entry_path() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let _handshake = crate::vcpu_loop::quiesce::foreign_cow_handshake_test_lock();
        let (kernel, root) = bootstrap(31_114);
        let execution = execution_lease(&root, 114);
        let caller_tid = ThreadId::synthetic_for_tests(31_079);
        let fixture = real_production_cow_fixture(
            &kernel,
            &root,
            31_115,
            0x9a00_3200_0000,
            0x9b00_3200_0000,
            caller_tid,
        );
        let mm = fixture.child.shared().mm().id();
        let active_tid = ThreadId::synthetic_for_tests(31_116);
        let active_executor = ExecutorId::for_transitional_thread(active_tid)
            .expect("production active executor identity");
        fixture
            .stage1
            .begin_asid_load(active_executor)
            .expect("publish active target-MM load")
            .mark_resident()
            .expect("publish active target-MM residency");
        let binding = crate::vcpu_loop::quiesce::foreign_cow_task_binding_for_test(
            Arc::clone(&fixture.stage1),
            mm,
        )
        .expect("construct active foreign-COW task binding");
        let observer = binding.cow_invalidation_observer(active_executor);
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let in_guest = Arc::new(carrick_hal::InGuestFlag::for_guest_thread());
        assert!(matches!(
            registry.subscribe_register(
                active_tid,
                Box::new(LeaveGuestOnKick(Arc::clone(&in_guest))),
                &in_guest,
                Arc::new(|| {}),
            ),
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ));
        let census = fixture.dispatch_mm.foreign_cow_executor_census_for_test();
        let endpoint: Arc<dyn VcpuRegistry> = registry.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let hardware_calls = Arc::new(AtomicUsize::new(0));
        let worker_calls = Arc::clone(&hardware_calls);
        let worker = std::thread::spawn(move || {
            let _participation = census
                .enter_with_pause_endpoint(None, endpoint, active_tid)
                .expect("production active target census participation");
            in_guest.enter_guest();
            ready_tx.send(()).expect("publish active target entry");
            let deadline = Instant::now() + Duration::from_secs(1);
            while !crate::vcpu_loop::quiesce::pt_barrier().is_quiescing() {
                assert!(
                    Instant::now() < deadline,
                    "production target pause was never raised"
                );
                std::thread::yield_now();
            }
            let entered =
                crate::vcpu_loop::quiesce::enter_hvpatch_guest_or_service_invalidation_for_test(
                    &in_guest,
                    active_tid,
                    active_executor,
                    &binding,
                    &observer,
                    |_| {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .expect("active target production entry service");
            assert!(
                !entered,
                "paused target returns to the outer execution loop"
            );
        });
        ready_rx.recv().expect("active target is in guest");
        let foreign = foreign_mm(&kernel, &root, &execution, fixture.child.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });
        worker
            .join()
            .expect("active target resumes after COW commit");

        assert!(
            result.is_ok(),
            "active target carrier COW failed: {result:?}"
        );
        assert_eq!(hardware_calls.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .stage1
                .pending_cow_invalidation(active_executor)
                .is_none()
        );
        registry.unregister(active_tid);
    }

    #[test]
    fn production_carrier_clone_vm_target_reuses_exact_cow_authority() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        let (kernel, root) = bootstrap(31_079);
        let execution = execution_lease(&root, 79);
        let target = real_production_cow_fixture(
            &kernel,
            &root,
            31_080,
            0x9a00_3300_0000,
            0x9b00_3300_0000,
            ThreadId::synthetic_for_tests(31_079),
        );
        let shared = kernel
            .reserve_fork(
                &target.child,
                ClonePlan::from_flags(LinuxCloneFlags::VM).expect("CLONE_VM plan"),
                "production foreign COW CLONE_VM peer".to_owned(),
                None,
            )
            .expect("reserve CLONE_VM peer")
            .prepare_shared_mm(ThreadId::synthetic_for_tests(31_081))
            .expect("prepare shared target MM")
            .commit()
            .expect("publish CLONE_VM peer")
            .into_parts()
            .expect("start CLONE_VM peer")
            .0;
        assert!(Arc::ptr_eq(
            &target.child.shared().mm(),
            &shared.shared().mm()
        ));
        let foreign = foreign_mm(&kernel, &root, &execution, shared.task().key());
        let range = foreign.write_range(GuestVa(TEST_VA), 4).unwrap().unwrap();

        let result = with_foreign_mutation(&foreign, |mutation| {
            super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .map(|_| ())
        });

        assert!(
            result.is_ok(),
            "CLONE_VM lost exact COW authority: {result:?}"
        );
    }

    #[test]
    fn production_carrier_target_exec_and_retirement_race_foreign_acquisition() {
        use carrick_vmm_hvf::trap::foreign_cow_test_support::TEST_VA;

        fn finish_acquisition(acquired: Result<MmRelation<'_>, MmAccessError>, expected_mm: MmId) {
            match acquired {
                Ok(MmRelation::Foreign(foreign)) => {
                    assert_eq!(foreign.mm_id(), expected_mm, "race selected the wrong MM");
                    let range = foreign
                        .write_range(GuestVa(TEST_VA), 4)
                        .expect("race target range validation")
                        .expect("race target has writable production VMA");
                    let result = super::MmAccessAuthority::new().with_foreign_mutation(
                        &foreign,
                        ThreadId::synthetic_for_tests(31_079),
                        |mutation| {
                            super::MmAccessAuthority::new()
                                .break_foreign_cow(mutation, &foreign, range)
                                .map(|_| ())
                        },
                    );
                    assert!(
                        result.is_ok(),
                        "retained race winner failed COW: {result:?}"
                    );
                }
                Err(
                    MmAccessError::UnknownTask(_)
                    | MmAccessError::StaleContext(_)
                    | MmAccessError::MissingForeignTransport(_),
                ) => {}
                Err(MmAccessError::Snapshot(SnapshotError::TimedOut)) => {}
                Ok(MmRelation::Current(_)) => panic!("foreign race selected caller MM"),
                Err(error) => panic!("unexpected foreign acquisition race outcome: {error:?}"),
            }
        }

        {
            let (kernel, root) = bootstrap(31_117);
            let execution = execution_lease(&root, 117);
            let target = real_production_cow_fixture(
                &kernel,
                &root,
                31_118,
                0x9a00_3400_0000,
                0x9b00_3400_0000,
                ThreadId::synthetic_for_tests(31_079),
            );
            let target_key = target.child.task().key();
            let expected_mm = target.child.shared().mm().id();
            let start = Arc::new(std::sync::Barrier::new(2));
            let (acquired, replacement) = std::thread::scope(|scope| {
                let worker_start = Arc::clone(&start);
                let worker_kernel = &kernel;
                let worker_target = &target.child;
                let worker = scope.spawn(move || {
                    worker_start.wait();
                    worker_kernel
                        .commit_exec(
                            worker_kernel
                                .prepare_exec_with_mm_backend(
                                    worker_target,
                                    fixture_backend(),
                                    None,
                                )
                                .expect("prepare racing target exec"),
                            None,
                        )
                        .expect("commit racing target exec")
                });
                start.wait();
                let acquired = kernel.foreign_mm(&root, &execution, target_key);
                let replacement = worker.join().expect("racing exec worker");
                (acquired, replacement)
            });
            finish_acquisition(acquired, expected_mm);
            assert_ne!(replacement.shared().mm().id(), expected_mm);
        }

        {
            let (kernel, root) = bootstrap(31_119);
            let execution = execution_lease(&root, 119);
            let target = real_production_cow_fixture(
                &kernel,
                &root,
                31_120,
                0x9a00_3500_0000,
                0x9b00_3500_0000,
                ThreadId::synthetic_for_tests(31_079),
            );
            let target_key = target.child.task().key();
            let expected_mm = target.child.shared().mm().id();
            let start = Arc::new(std::sync::Barrier::new(2));
            let acquired = std::thread::scope(|scope| {
                let worker_start = Arc::clone(&start);
                let worker_kernel = &kernel;
                let worker = scope.spawn(move || {
                    worker_start.wait();
                    worker_kernel
                        .exit_task_key_eventually(
                            target_key,
                            LinuxWaitStatus::from_wait_encoding(0),
                        )
                        .expect("racing target retirement")
                });
                start.wait();
                let acquired = kernel.foreign_mm(&root, &execution, target_key);
                worker.join().expect("racing retirement worker");
                acquired
            });
            finish_acquisition(acquired, expected_mm);
        }
    }

    #[test]
    fn foreign_cow_rejects_wrong_mm_guard_range_and_backend_receipt_identity() {
        let (kernel, root) = bootstrap(31_082);
        let execution = execution_lease(&root, 82);
        let (child, _backend, _owner, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_083, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        let wrong_mm =
            MmId::from_registry_allocation(NonZeroU64::new(foreign.mm_id().raw() + 1).unwrap());
        with_mm_mutation(wrong_mm, |mutation| {
            assert!(matches!(
                super::MmAccessAuthority::new().break_foreign_cow(mutation, &foreign, range),
                Err(MmAccessError::ForeignMutationAuthorityMismatch)
            ));
        });

        let (other, _backend, _owner, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_084, MockCowFault::None);
        let other_foreign = foreign_mm(&kernel, &root, &execution, other.task().key());
        let other_range = other_foreign
            .write_range(GuestVa(0x3000), 4)
            .unwrap()
            .unwrap();
        with_foreign_mutation(&foreign, |mutation| {
            assert!(matches!(
                super::MmAccessAuthority::new().break_foreign_cow(mutation, &foreign, other_range,),
                Err(MmAccessError::ForeignRangeAuthorityMismatch)
            ));
        });

        for fault in [MockCowFault::WrongMm, MockCowFault::WrongRange] {
            let (target, _backend, _owner, _bytes, _counters) =
                cow_fixture(&kernel, &root, 31_085 + fault as i32, fault);
            let target = foreign_mm(&kernel, &root, &execution, target.task().key());
            let target_range = target.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&target, |mutation| {
                assert!(matches!(
                    super::MmAccessAuthority::new().break_foreign_cow(
                        mutation,
                        &target,
                        target_range,
                    ),
                    Err(MmAccessError::ForeignCowReceiptMismatch)
                ));
            });
        }
    }

    #[test]
    fn foreign_cow_rejects_wrong_mapping_frame_physical_range_and_current_owner() {
        let (kernel, root) = bootstrap(31_086);
        let execution = execution_lease(&root, 86);
        for (index, fault) in [
            MockCowFault::WrongMapping,
            MockCowFault::WrongFrame,
            MockCowFault::WrongPhysical,
            MockCowFault::WrongPhysicalLength,
            MockCowFault::WrongOwner,
        ]
        .into_iter()
        .enumerate()
        {
            let (target, _backend, _owner, _bytes, _counters) =
                cow_fixture(&kernel, &root, 31_087 + index as i32, fault);
            let target = foreign_mm(&kernel, &root, &execution, target.task().key());
            let range = target.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&target, |mutation| {
                assert!(matches!(
                    super::MmAccessAuthority::new().break_foreign_cow(mutation, &target, range,),
                    Err(MmAccessError::ForeignCowReceiptMismatch)
                ));
            });
        }
    }

    #[test]
    fn foreign_cow_rejects_internally_consistent_transport_forgery() {
        let (kernel, root) = bootstrap(31_096);
        let execution = execution_lease(&root, 96);
        for (index, fault) in [
            MockCowFault::ForgedConsistentMapping,
            MockCowFault::ForgedConsistentFrame,
            MockCowFault::ForgedConsistentPhysical,
            MockCowFault::ForgedConsistentOwner,
        ]
        .into_iter()
        .enumerate()
        {
            let (target, _backend, _owner, _bytes, _counters) =
                cow_fixture(&kernel, &root, 31_097 + index as i32, fault);
            let target = foreign_mm(&kernel, &root, &execution, target.task().key());
            let range = target.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&target, |mutation| {
                assert!(matches!(
                    super::MmAccessAuthority::new().break_foreign_cow(mutation, &target, range,),
                    Err(MmAccessError::ForeignCowReceiptMismatch)
                ));
            });
        }
    }

    #[test]
    fn foreign_cow_rejects_genuine_proof_with_inflated_semantic_span() {
        let (kernel, root) = bootstrap(31_130);
        let execution = execution_lease(&root, 130);
        let (child, _backend, _owner, bytes, counters) =
            cow_fixture(&kernel, &root, 31_131, MockCowFault::InflatedSemanticSpan);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            assert!(matches!(
                super::MmAccessAuthority::new().break_foreign_cow(mutation, &foreign, range,),
                Err(MmAccessError::ForeignCowReceiptMismatch)
            ));
        });

        assert_eq!(&*bytes.lock(), b"same");
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn foreign_cow_proof_issuer_does_not_sign_transport_chosen_owner_generation() {
        let (kernel, root) = bootstrap(31_128);
        let mm = root.shared().mm().id();
        let tid = ThreadId::synthetic_for_tests(31_128);
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        let mut reservation = kernel.reserve_frame_inventory(1, 1, capacity).unwrap();
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation =
            carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::new(1).unwrap());
        let gpa = Gpa(0xd000);
        let length =
            carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(0x4000).unwrap());
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
        let current_owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(61).unwrap());
        let transport_chosen_owner =
            carrick_hal::ForeignOwnerGeneration::from_backend_counter(NonZeroU64::new(62).unwrap());
        let authority = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(&kernel),
            mm,
            Arc::new(crate::kernel::GuestExecutorCensus::default()),
            tid,
            7,
            crate::vcpu_loop::fixed_frame_cow_owner_inventory_for_test(current_owner),
        );

        let (receipt, proof, authenticated_owner) = authority
            .apply_foreign_cow(
                reservation.commit(()),
                GuestVa(0x3000),
                std::num::NonZeroUsize::new(0x4000).unwrap(),
                mapping,
                frame,
                gpa,
                length,
            )
            .expect("apply foreign COW inventory transaction");
        let proof = proof
            .downcast_ref::<crate::vcpu_loop::KernelForeignCowProof>()
            .expect("runtime-private kernel proof");

        assert!(
            authenticated_owner == current_owner,
            "proof issuer returned a transport-selected owner generation"
        );
        assert!(
            proof.authenticates(
                &kernel,
                mm,
                GuestVa(0x3000),
                0x4000,
                receipt.revision(),
                mapping,
                frame,
                gpa,
                length.raw(),
                current_owner,
            ),
            "proof issuer signed a transport-chosen owner instead of the independent current owner"
        );
        assert!(
            !proof.authenticates(
                &kernel,
                mm,
                GuestVa(0x3000),
                0x4000,
                receipt.revision(),
                mapping,
                frame,
                gpa,
                length.raw(),
                transport_chosen_owner,
            ),
            "transport-selected owner generation was accepted by the kernel proof issuer"
        );
    }

    #[test]
    fn foreign_cow_runtime_rejects_transport_owner_after_independent_proof_issuance() {
        let (kernel, root) = bootstrap(31_129);
        let execution = execution_lease(&root, 129);
        let (child, _backend, owner_generation, _bytes, _counters) =
            cow_fixture(&kernel, &root, 31_130, MockCowFault::None);
        let mm = child.shared().mm().id();
        let current_owner = carrick_hal::ForeignOwnerGeneration::from_backend_counter(
            NonZeroU64::new(owner_generation.load(Ordering::Acquire)).unwrap(),
        );
        let transport_chosen_owner = carrick_hal::ForeignOwnerGeneration::from_backend_counter(
            NonZeroU64::new(current_owner.raw_for_probe().checked_add(1).unwrap()).unwrap(),
        );
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        let mut reservation = kernel.reserve_frame_inventory(1, 1, capacity).unwrap();
        let transaction = reservation.transaction();
        let frame = reservation.claim_frame().unwrap();
        let mapping = reservation.claim_mapping().unwrap();
        let generation =
            carrick_hal::MappingGeneration::from_backend_counter(NonZeroU64::new(1).unwrap());
        let physical_base = Gpa(0x20_000);
        let physical_len =
            carrick_hal::FrameLength::from_mapping_extent(NonZeroU64::new(0x4000).unwrap());
        reservation
            .push(carrick_hal::FrameInventoryEvent::PrepareMapping {
                transaction,
                frame,
                mapping,
                generation,
                gpa: physical_base,
                length: physical_len,
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
        let proof_issuer = crate::vcpu_loop::kernel_frame_cow_authority_for_test(
            Arc::clone(&kernel),
            mm,
            Arc::new(crate::kernel::GuestExecutorCensus::default()),
            ThreadId::synthetic_for_tests(31_130),
            9,
            crate::vcpu_loop::fixed_frame_cow_owner_inventory_for_test(current_owner),
        );
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(OwnerSigningOracleTransport {
                lease: Arc::new(OwnerSigningOracleLease {
                    authority: proof_issuer,
                    commit: parking_lot::Mutex::new(Some(reservation.commit(()))),
                    mapping,
                    frame,
                    physical_base,
                    physical_len,
                    transport_chosen_owner,
                }),
            })),
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            assert!(matches!(
                super::MmAccessAuthority::new().break_foreign_cow(mutation, &foreign, range,),
                Err(MmAccessError::ForeignCowReceiptMismatch)
            ));
        });
    }

    #[test]
    fn foreign_cow_rejects_receipts_with_any_advanced_revision_domain() {
        let (kernel, root) = bootstrap(31_090);
        let execution = execution_lease(&root, 90);
        for (index, fault) in [
            MockCowFault::AdvancedBackend,
            MockCowFault::AdvancedVma,
            MockCowFault::AdvancedInventory,
        ]
        .into_iter()
        .enumerate()
        {
            let (child, _backend, _owner, _bytes, _counters) =
                cow_fixture(&kernel, &root, 31_091 + index as i32, fault);
            let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
            let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&foreign, |mutation| {
                assert!(matches!(
                    super::MmAccessAuthority::new().break_foreign_cow(mutation, &foreign, range,),
                    Err(MmAccessError::ForeignCowReceiptMismatch)
                ));
            });
        }
    }

    #[test]
    fn cow_broken_is_stale_after_any_revision_or_owner_generation_changes() {
        for domain in 0..3 {
            let (kernel, root) = bootstrap(31_100 + domain as i32 * 10);
            let execution = execution_lease(&root, 100 + domain as u64);
            let (child, backend, _owner, bytes, _counters) = cow_fixture(
                &kernel,
                &root,
                31_101 + domain as i32 * 10,
                MockCowFault::None,
            );
            let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
            let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&foreign, |mutation| {
                let mut cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .unwrap();
                backend.advance(domain);
                assert!(matches!(
                    super::MmAccessAuthority::new().prepare_foreign_write(&mut cow, b"edit"),
                    Err(MmAccessError::StaleCowBroken)
                ));
            });
            assert_eq!(&*bytes.lock(), b"same");
        }

        let (kernel, root) = bootstrap(31_140);
        let execution = execution_lease(&root, 140);
        let (child, _backend, owner, bytes, _counters) =
            cow_fixture(&kernel, &root, 31_141, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        with_foreign_mutation(&foreign, |mutation| {
            let mut cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .unwrap();
            owner.fetch_add(1, Ordering::AcqRel);
            assert!(matches!(
                super::MmAccessAuthority::new().prepare_foreign_write(&mut cow, b"edit"),
                Err(MmAccessError::ForeignTransport(
                    ForeignMmTransportError::OwnerStale
                ))
            ));
        });
        assert_eq!(&*bytes.lock(), b"same");
    }

    #[test]
    fn foreign_write_no_fault_control_commits_exact_bytes_and_records_phase_counters() {
        let (kernel, root) = bootstrap(31_145);
        let execution = execution_lease(&root, 145);
        let (child, _backend, _owner, bytes, counters) =
            cow_fixture(&kernel, &root, 31_146, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let receipt = with_foreign_mutation(&foreign, |mutation| {
            let mut cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("break exact child COW");
            let prepared = super::MmAccessAuthority::new()
                .prepare_foreign_write(&mut cow, b"edit")
                .expect("prepare foreign write");
            super::MmAccessAuthority::new().commit_foreign_write(prepared)
        });

        assert_eq!(receipt.bytes_written(), 4);
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 1);
        assert_eq!(&*bytes.lock(), b"edit");
    }

    #[test]
    fn foreign_write_transport_error_cannot_follow_target_mutation() {
        let (kernel, root) = bootstrap(31_150);
        let execution = execution_lease(&root, 150);
        let (child, _backend, _owner, bytes, counters) =
            cow_fixture(&kernel, &root, 31_151, MockCowFault::PostCopyError);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result: Result<super::ForeignWriteReceipt, super::MmAccessError> =
            with_foreign_mutation(&foreign, |mutation| {
                let mut cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .expect("prepare exact child COW");
                let prepared =
                    super::MmAccessAuthority::new().prepare_foreign_write(&mut cow, b"edit")?;
                Ok(super::MmAccessAuthority::new().commit_foreign_write(prepared))
            });

        assert!(
            matches!(
                result,
                Err(MmAccessError::ForeignTransport(
                    ForeignMmTransportError::OwnerStale
                ))
            ),
            "expected OwnerStale transport error, got {result:?}"
        );
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            &*bytes.lock(),
            b"same",
            "a reported transport failure must leave target bytes unchanged",
        );
    }

    #[test]
    fn foreign_write_receipt_rejection_cannot_follow_target_mutation() {
        let (kernel, root) = bootstrap(31_160);
        let execution = execution_lease(&root, 160);
        let (child, _backend, _owner, bytes, counters) =
            cow_fixture(&kernel, &root, 31_161, MockCowFault::WrongWriteReceipt);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result: Result<super::ForeignWriteReceipt, super::MmAccessError> =
            with_foreign_mutation(&foreign, |mutation| {
                let mut cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .expect("prepare exact child COW");
                let prepared =
                    super::MmAccessAuthority::new().prepare_foreign_write(&mut cow, b"edit")?;
                Ok(super::MmAccessAuthority::new().commit_foreign_write(prepared))
            });

        assert!(
            matches!(result, Err(MmAccessError::ForeignWriteReceiptMismatch)),
            "expected ForeignWriteReceiptMismatch error, got {result:?}"
        );
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            &*bytes.lock(),
            b"same",
            "a reported receipt rejection must leave target bytes unchanged",
        );
    }

    #[test]
    fn foreign_write_revision_recheck_cannot_follow_target_mutation() {
        let (kernel, root) = bootstrap(31_170);
        let execution = execution_lease(&root, 170);
        let (child, _backend, _owner, bytes, counters) = cow_fixture(
            &kernel,
            &root,
            31_171,
            MockCowFault::AdvancedBackendAfterWrite,
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        let result: Result<super::ForeignWriteReceipt, super::MmAccessError> =
            with_foreign_mutation(&foreign, |mutation| {
                let mut cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .expect("prepare exact child COW");
                let prepared =
                    super::MmAccessAuthority::new().prepare_foreign_write(&mut cow, b"edit")?;
                Ok(super::MmAccessAuthority::new().commit_foreign_write(prepared))
            });

        assert!(
            matches!(result, Err(MmAccessError::StaleCowBroken)),
            "expected StaleCowBroken error, got {result:?}"
        );
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            &*bytes.lock(),
            b"same",
            "a reported revision recheck failure must leave target bytes unchanged",
        );
    }

    #[test]
    fn foreign_cow_one_compound_authorizes_sequential_subrange_writes_through_runtime_facade() {
        let (kernel, root) = bootstrap(31_180);
        let execution = execution_lease(&root, 180);
        let parent_bytes = b"same_old_data_".to_vec();
        let (child, _backend, _owner, child_bytes, counters) =
            cow_fixture(&kernel, &root, 31_181, MockCowFault::None);
        *child_bytes.lock() = parent_bytes.clone();
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let compound_range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        let first_range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        let second_range = foreign.write_range(GuestVa(0x3004), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            let mut cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, compound_range)
                .expect("break exact compound COW once");

            let first_prepared = super::MmAccessAuthority::new()
                .prepare_foreign_write_range(&mut cow, first_range, b"one!")
                .expect("prepare first subrange write");
            let first_receipt =
                super::MmAccessAuthority::new().commit_foreign_write(first_prepared);
            assert_eq!(first_receipt.bytes_written(), 4);

            let second_prepared = super::MmAccessAuthority::new()
                .prepare_foreign_write_range(&mut cow, second_range, b"two!")
                .expect("prepare second subrange write using same cow broken witness");
            let second_receipt =
                super::MmAccessAuthority::new().commit_foreign_write(second_prepared);
            assert_eq!(second_receipt.bytes_written(), 4);
        });

        assert_eq!(parent_bytes, b"same_old_data_");
        assert_eq!(&*child_bytes.lock(), b"one!two!_data_");
        assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 2);
        assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn retained_foreign_token_keeps_the_exact_mm_across_target_exec_and_retirement() {
        let (kernel, root) = bootstrap(31_100);
        let execution = execution_lease(&root, 101);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(MockForeignTransport {
            calls: Arc::clone(&calls),
            mode: MockReadMode::RetryOnce,
        });
        let child = fork_with_transport(&kernel, &root, 31_101, "retained-mm child", transport);
        let old_mm_arc = child.shared().mm();
        let old_mm_weak = Arc::downgrade(&old_mm_arc);
        let old_mm = old_mm_arc.id();
        let token = foreign_mm(&kernel, &root, &execution, child.task().key());

        let replacement = kernel
            .commit_exec(
                kernel
                    .prepare_exec_with_mm_backend(&child, fixture_backend(), None)
                    .expect("prepare target exec"),
                None,
            )
            .expect("commit target exec");
        let replacement_key = replacement.task().key();

        assert_eq!(token.mm_id(), old_mm);
        assert_ne!(replacement.shared().mm().id(), token.mm_id());
        drop(child);
        drop(old_mm_arc);
        let retained_after_exec = old_mm_weak
            .upgrade()
            .expect("foreign token must retain the pre-exec MM");
        assert!(Arc::ptr_eq(&token.token.mm, &retained_after_exec));
        drop(retained_after_exec);

        kernel
            .exit_task_key_eventually(replacement_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("retire exec replacement");
        drop(replacement);
        let _ = kernel
            .wait_child_key(
                root.task().key().id,
                replacement_key,
                super::super::WaitMode::Consume,
            )
            .expect("reap retired replacement");
        kernel.sweep_retired_threads();

        let retained_after_retirement = old_mm_weak
            .upgrade()
            .expect("foreign token must retain the retired MM");
        assert!(Arc::ptr_eq(&token.token.mm, &retained_after_retirement));
        drop(retained_after_retirement);
        let range = token
            .read_range(GuestVa(0x1000), 4)
            .expect("retained old-MM range")
            .expect("nonempty retained old-MM range");
        let mut bytes = [0_u8; 4];
        super::MmAccessAuthority::new()
            .read_foreign(&token, range, &mut bytes)
            .expect("read old token after exec, retirement, and numeric binding reuse");
        assert_eq!(&bytes, b"root");
        assert_eq!(calls.load(Ordering::Acquire), 2);
        drop(token);
        assert!(
            old_mm_weak.upgrade().is_none(),
            "the token must be the old MM's final owner after exec and retirement"
        );
    }

    #[test]
    fn stale_task_key_is_rejected_after_pid_reuse() {
        let (kernel, root) = bootstrap(31_110);
        let execution = execution_lease(&root, 111);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child = fork_with_backend(&kernel, &root, 31_111, "stale-mm child", fixture_backend());
        let stale_key = child.task().key();

        kernel
            .exit_task_key_eventually(stale_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("retire target");
        drop(child);
        let _ = kernel
            .wait_child_key(
                root.task().key().id,
                stale_key,
                super::super::WaitMode::Consume,
            )
            .expect("reap target");
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(stale_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let replacement = fork_with_backend(
            &kernel,
            &fresh_root,
            31_112,
            "replacement child",
            fixture_backend(),
        );
        assert_eq!(replacement.task().key().id, stale_key.id);
        assert_ne!(replacement.task().key(), stale_key);

        assert!(matches!(
            kernel.foreign_mm(&fresh_root, &execution, stale_key),
            Err(MmAccessError::UnknownTask(key)) if key == stale_key
        ));
    }

    #[test]
    fn an_uninitialized_context_cannot_supply_execution_authority() {
        let (_kernel, root) = bootstrap(31_115);

        assert!(matches!(
            root.thread()
                .claim_runnable(ExecutorId::synthetic_for_tests(115)),
            Err(super::super::objects::ThreadExecutionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn current_mm_rejects_scheduler_authority_for_a_different_mm() {
        let (kernel, root) = bootstrap(31_116);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_117,
            "different-mm child",
            fixture_backend(),
        );
        let execution = execution_lease_for_mm(&root, child.shared().mm().id(), 116);

        assert!(matches!(
            root.current_mm(&execution),
            Err(MmAccessError::StaleExecutionAuthority { .. })
        ));
    }

    #[test]
    fn current_mm_rejects_another_threads_execution_lease() {
        let (_kernel, root) = bootstrap(31_118);
        let (_other_kernel, other) = bootstrap(31_119);
        let execution = execution_lease(&other, 119);

        assert!(matches!(
            root.current_mm(&execution),
            Err(MmAccessError::ExecutionAuthority(
                ThreadExecutionError::LeaseOwnerMismatch { .. }
            ))
        ));
    }

    #[test]
    fn current_mm_rejects_same_identity_lease_from_another_kernel() {
        let (_kernel, root) = bootstrap(31_125);
        let (_other_kernel, other) = bootstrap(31_125);
        let _local_execution = execution_lease(&root, 125);
        let foreign_execution = execution_lease(&other, 125);

        assert_eq!(root.thread().key(), other.thread().key());
        assert_eq!(root.shared().mm().id(), other.shared().mm().id());
        assert_eq!(
            root.thread().execution_state(),
            other.thread().execution_state()
        );
        assert!(matches!(
            root.current_mm(&foreign_execution),
            Err(MmAccessError::ExecutionAuthority(
                ThreadExecutionError::LeaseOwnerMismatch { .. }
            ))
        ));
    }

    #[test]
    fn foreign_mm_rejects_another_threads_execution_lease() {
        let (kernel, root) = bootstrap(31_122);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_123,
            "foreign-authority child",
            fixture_backend(),
        );
        let (_other_kernel, other) = bootstrap(31_124);
        let execution = execution_lease(&other, 124);

        assert!(matches!(
            kernel.foreign_mm(&root, &execution, child.task().key()),
            Err(MmAccessError::ExecutionAuthority(
                ThreadExecutionError::LeaseOwnerMismatch { .. }
            ))
        ));
    }

    #[test]
    fn foreign_mm_rejects_same_identity_lease_from_another_kernel() {
        let (kernel, root) = bootstrap(31_126);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_127,
            "same-identity foreign-authority child",
            fixture_backend(),
        );
        let (_other_kernel, other) = bootstrap(31_126);
        let _local_execution = execution_lease(&root, 126);
        let foreign_execution = execution_lease(&other, 126);

        assert_eq!(root.thread().key(), other.thread().key());
        assert_eq!(root.shared().mm().id(), other.shared().mm().id());
        assert_eq!(
            root.thread().execution_state(),
            other.thread().execution_state()
        );
        assert!(matches!(
            kernel.foreign_mm(&root, &foreign_execution, child.task().key()),
            Err(MmAccessError::ExecutionAuthority(
                ThreadExecutionError::LeaseOwnerMismatch { .. }
            ))
        ));
    }

    #[test]
    fn token_bound_ranges_require_permissions_and_complete_vma_coverage() {
        let (kernel, root) = bootstrap(31_120);
        let execution = execution_lease(&root, 121);
        let child = fork_with_transport(
            &kernel,
            &root,
            31_121,
            "range-mm child",
            Arc::new(MockForeignTransport {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                mode: MockReadMode::RetryOnce,
            }),
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let token: &MmToken = &foreign.token;

        assert_eq!(foreign.token.snapshot.revision, 17);
        assert_eq!(
            foreign.token.snapshot.vma_revision,
            Some(VmaRevision::from_authority_raw(19))
        );
        assert_eq!(foreign.token.snapshot.frame_inventory_revision, Some(23));

        let read: MmReadRange<'_> = token
            .read_range(GuestVa(0x1000), 16)
            .expect("readable range")
            .expect("nonempty read range");
        let write: MmWriteRange<'_> = token
            .write_range(GuestVa(0x3000), 16)
            .expect("writable range")
            .expect("nonempty write range");
        let _ = (read, write);
        assert!(matches!(
            token.write_range(GuestVa(0x2000), 16),
            Err(MmAccessError::WriteDenied { .. })
        ));
        assert!(token.write_range(GuestVa(0x3000), 16).is_ok());
        assert!(matches!(
            token.kernel_read_range(GuestVa(0x4000), 16),
            Err(MmAccessError::KernelHidden { .. })
        ));
        assert!(token.read_range(GuestVa(0x1ff0), 0x20).is_ok());
        assert!(matches!(
            token.write_range(GuestVa(0x3ff0), 0x20),
            Err(MmAccessError::WriteDenied { .. })
        ));
        assert!(matches!(
            token.kernel_read_range(GuestVa(0x3ff0), 0x20),
            Err(MmAccessError::KernelHidden { .. })
        ));
        assert!(token.read_range(GuestVa(0x4ff0), 0x20).is_err());
        assert!(token.read_range(GuestVa(u64::MAX - 7), 16).is_err());
        assert!(token.read_range(GuestVa(0x5000), 16).is_err());
        assert!(matches!(token.read_range(GuestVa(0x5000), 0), Ok(None)));
        assert!(matches!(token.write_range(GuestVa(u64::MAX), 0), Ok(None)));
    }

    #[test]
    fn foreign_mm_rejects_a_churning_backend_snapshot() {
        let (kernel, root) = bootstrap(31_130);
        let execution = execution_lease(&root, 131);
        let child = fork_with_backend(
            &kernel,
            &root,
            31_131,
            "churning-mm child",
            Arc::new(ChurningBackend {
                backend_revision: AtomicU64::new(29),
            }),
        );

        assert!(matches!(
            kernel.foreign_mm(&root, &execution, child.task().key()),
            Err(MmAccessError::Snapshot(
                SnapshotError::ChangedDuringObservation
            ))
        ));
    }

    #[test]
    fn mm_access_authority_retries_from_a_fresh_snapshot_and_authenticates_receipt() {
        let (kernel, root) = bootstrap(31_140);
        let execution = execution_lease(&root, 141);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(MockForeignTransport {
            calls: Arc::clone(&calls),
            mode: MockReadMode::RetryOnce,
        });
        let child = fork_with_transport(&kernel, &root, 31_141, "foreign-read child", transport);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign
            .read_range(GuestVa(0x1000), 4)
            .expect("validated read range")
            .expect("nonempty read range");
        let authority = super::MmAccessAuthority::new();
        let mut bytes = [0_u8; 4];

        let receipt = authority
            .read_foreign(&foreign, range, &mut bytes)
            .expect("bounded retry succeeds");

        assert_eq!(&bytes, b"root");
        assert_eq!(receipt.bytes_read(), bytes.len());
        assert_eq!(calls.load(Ordering::Acquire), 2);
    }

    #[test]
    fn mm_access_authority_exhausts_a_fixed_retry_budget() {
        let (kernel, root) = bootstrap(31_142);
        let execution = execution_lease(&root, 143);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(MockForeignTransport {
            calls: Arc::clone(&calls),
            mode: MockReadMode::AlwaysRetry,
        });
        let child = fork_with_transport(
            &kernel,
            &root,
            31_143,
            "churning foreign-read child",
            transport,
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign
            .read_range(GuestVa(0x1000), 4)
            .expect("validated read range")
            .expect("nonempty read range");
        let authority = super::MmAccessAuthority::new();
        let mut bytes = [0_u8; 4];

        assert!(matches!(
            authority.read_foreign(&foreign, range, &mut bytes),
            Err(MmAccessError::ForeignReadRetryExhausted)
        ));
        assert_eq!(calls.load(Ordering::Acquire), 3);
    }

    #[test]
    fn mm_access_authority_rejects_nonempty_reads_without_owner_generations() {
        let (kernel, root) = bootstrap(31_144);
        let execution = execution_lease(&root, 145);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(MockForeignTransport {
            calls,
            mode: MockReadMode::EmptyOwners,
        });
        let child = fork_with_transport(
            &kernel,
            &root,
            31_145,
            "ownerless foreign-read child",
            transport,
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.read_range(GuestVa(0x1000), 4).unwrap().unwrap();
        let mut bytes = [0_u8; 4];

        assert!(matches!(
            super::MmAccessAuthority::new().read_foreign(&foreign, range, &mut bytes),
            Err(MmAccessError::ForeignReceiptMismatch)
        ));
    }

    #[test]
    fn mm_access_authority_enforces_one_overall_deadline_across_attempts() {
        let (kernel, root) = bootstrap(31_146);
        let execution = execution_lease(&root, 147);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let transport: Arc<dyn ForeignMmTransport> = Arc::new(MockForeignTransport {
            calls: Arc::clone(&calls),
            mode: MockReadMode::Deadline,
        });
        let child = fork_with_transport(
            &kernel,
            &root,
            31_147,
            "deadline foreign-read child",
            transport,
        );
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.read_range(GuestVa(0x1000), 4).unwrap().unwrap();
        let mut bytes = [0_u8; 4];
        let started = Instant::now();

        assert!(matches!(
            super::MmAccessAuthority::new().read_foreign(&foreign, range, &mut bytes),
            Err(MmAccessError::ForeignReadTimedOut)
        ));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
    }

    #[test]
    fn cow_broken_type_invariants_and_guard_containment() {
        static_assertions::assert_not_impl_any!(
            super::CowBroken<'static, 'static, 'static>: Send, Sync, Clone, Copy
        );
        static_assertions::assert_not_impl_any!(
            super::PreparedForeignWrite<'static, 'static, 'static, 'static, 'static>: Send, Sync, Clone, Copy
        );
    }
}
