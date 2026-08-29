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
#[derive(Debug)]
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

/// Single-use runtime witness that one exact foreign-MM range now names a
/// private, authenticated owner. Its fields and constructor stay inside the
/// MM facade; HAL receipts alone cannot manufacture write authority.
#[derive(Debug)]
#[allow(dead_code)] // Minted and consumed by the canonical Task 8 syscall path.
pub struct CowBroken<'mm> {
    range: MmWriteRange<'mm>,
    snapshot: ProjectedForeignMmSnapshot,
    transport: Box<dyn carrick_hal::ForeignCowReceipt>,
}

/// Authenticated completion of one foreign copy through a consumed COW
/// witness.
#[derive(Debug)]
pub struct ForeignWriteReceipt {
    transport: Box<dyn carrick_hal::ForeignMmWriteReceipt>,
}

impl ForeignWriteReceipt {
    pub fn bytes_written(&self) -> usize {
        self.transport.bytes_written()
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
    pub fn break_foreign_cow<'mm>(
        &self,
        mutation: &mut crate::dispatch::mm_mutation::MmMutationGuard<'_>,
        mm: &'mm ForeignMm,
        range: MmWriteRange<'mm>,
    ) -> Result<CowBroken<'mm>, MmAccessError> {
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
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&mm.token.mm),
        };
        let before = snapshot_backend(&mm.token.mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
        let requested = ProjectedForeignMmSnapshot::from_backend(mm.mm_id(), &before)?;
        let receipt = mutation.with_host_alias(|invalidator| {
            lease.break_cow(
                &live,
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
        let after = ProjectedForeignMmSnapshot::from_backend(
            mm.mm_id(),
            &snapshot_backend(&mm.token.mm, deadline)?,
        )?;
        if receipt.mm() != after.mm
            || receipt.range_start() != range.start
            || receipt.range_len() != range.len.get()
            || receipt.backend_revision() != after.backend_revision
            || receipt.vma_revision() != after.vma_revision
            || receipt.frame_inventory_revision() != after.frame_inventory_revision
            || receipt.physical_len() == 0
            || receipt.owner_generation().raw_for_probe() == 0
        {
            return Err(MmAccessError::ForeignCowReceiptMismatch);
        }
        Ok(CowBroken {
            range,
            snapshot: after,
            transport: receipt,
        })
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub fn write_foreign(
        &self,
        witness: CowBroken<'_>,
        src: &[u8],
    ) -> Result<ForeignWriteReceipt, MmAccessError> {
        if src.len() != witness.range.len.get() {
            return Err(MmAccessError::SourceLengthMismatch {
                range: witness.range.len.get(),
                source_len: src.len(),
            });
        }
        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let mm = &witness.range.token.mm;
        let before = snapshot_backend(mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        validate_range_in_snapshot(
            &before,
            witness.range.start,
            witness.range.len,
            RangeAccess::Write,
        )?;
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &before)?;
        if snapshot != witness.snapshot {
            return Err(MmAccessError::StaleCowBroken);
        }
        let lease = witness
            .range
            .token
            .foreign_lease
            .as_ref()
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let live = RetainedMmLiveAuthority { mm: Arc::clone(mm) };
        let receipt = match lease.write(
            &live,
            &snapshot,
            witness.transport.as_ref(),
            witness.range.start,
            src,
            deadline,
        ) {
            Ok(receipt) => receipt,
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
        if receipt.mm() != snapshot.mm
            || receipt.range_start() != witness.range.start
            || receipt.range_len() != witness.range.len.get()
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
        Ok(ForeignWriteReceipt { transport: receipt })
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
        let token = snapshot_token(self.task.key(), mm, false)?;
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
        let token = snapshot_token(target, target_mm, is_foreign)?;
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
mod tests {
    use std::num::{NonZeroU16, NonZeroU64};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    use carrick_abi::LinuxCloneFlags;
    use carrick_guest_mem::{Gpa, GuestVa};
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};
    use carrick_hal::{
        ForeignCowReceipt, ForeignMmReadLease, ForeignMmReadReceipt, ForeignMmSnapshot,
        ForeignMmTransport, ForeignMmTransportError, ForeignMmWriteReceipt, ThreadId,
    };

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
        backend_revision: AtomicU64,
        vma_revision: AtomicU64,
        inventory_revision: AtomicU64,
    }

    impl MutableFixtureBackend {
        fn new() -> Arc<Self> {
            let asid = Asid::from_registry_allocation(NonZeroU16::new(9).expect("nonzero ASID"));
            let root = Stage1Root::for_aarch64_4k(Gpa(0xa000)).expect("aligned stage-1 root");
            Arc::new(Self {
                binding: MmBinding::for_aarch64(asid, root),
                backend_revision: AtomicU64::new(41),
                vma_revision: AtomicU64::new(43),
                inventory_revision: AtomicU64::new(47),
            })
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
                mapping_ids: vec![carrick_hal::MappingId::from_kernel_allocation(
                    NonZeroU64::new(53).unwrap(),
                )],
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
        WrongMm,
        WrongRange,
        AdvancedBackend,
        AdvancedVma,
        AdvancedInventory,
    }

    #[derive(Debug)]
    struct MockCowTransport {
        owner_generation: Arc<AtomicU64>,
        bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
        fault: MockCowFault,
    }

    #[derive(Debug)]
    struct MockCowLease {
        owner_generation: Arc<AtomicU64>,
        bytes: Arc<parking_lot::Mutex<Vec<u8>>>,
        fault: MockCowFault,
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
        owner: carrick_hal::ForeignOwnerGeneration,
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
            Gpa(0xb000)
        }
        fn physical_len(&self) -> u64 {
            0x4000
        }
        fn owner_generation(&self) -> carrick_hal::ForeignOwnerGeneration {
            self.owner
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
            _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
            _invalidator: &mut dyn carrick_hal::ForeignMmInvalidator,
            snapshot: &dyn ForeignMmSnapshot,
            va: GuestVa,
            len: usize,
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignCowReceipt>, ForeignMmTransportError> {
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
            Ok(Box::new(MockCowReceipt {
                mm,
                start,
                len,
                backend,
                vma,
                inventory,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    NonZeroU64::new(53).unwrap(),
                ),
                frame: carrick_hal::FrameId::from_kernel_allocation(NonZeroU64::new(59).unwrap()),
                owner: carrick_hal::ForeignOwnerGeneration::from_backend_counter(
                    NonZeroU64::new(self.owner_generation.load(Ordering::Acquire)).unwrap(),
                ),
            }))
        }

        fn write(
            &self,
            _invocation: &carrick_hal::ForeignMmInvocation,
            _authority: &dyn carrick_hal::ForeignMmLiveAuthority,
            snapshot: &dyn ForeignMmSnapshot,
            cow: &dyn ForeignCowReceipt,
            va: GuestVa,
            src: &[u8],
            _deadline: Instant,
        ) -> Result<Box<dyn ForeignMmWriteReceipt>, ForeignMmTransportError> {
            if cow.owner_generation().raw_for_probe()
                != self.owner_generation.load(Ordering::Acquire)
            {
                return Err(ForeignMmTransportError::OwnerStale);
            }
            if cow.mm() != snapshot.mm()
                || cow.range_start() != va
                || cow.range_len() != src.len()
                || cow.backend_revision() != snapshot.backend_revision()
                || cow.vma_revision() != snapshot.vma_revision()
                || cow.frame_inventory_revision() != snapshot.frame_inventory_revision()
            {
                return Err(ForeignMmTransportError::Retry);
            }
            self.bytes.lock()[..src.len()].copy_from_slice(src);
            Ok(Box::new(MockWriteReceipt(MockCowReceipt {
                mm: cow.mm(),
                start: va,
                len: src.len(),
                backend: cow.backend_revision(),
                vma: cow.vma_revision(),
                inventory: cow.frame_inventory_revision(),
                mapping: cow.mapping(),
                frame: cow.frame(),
                owner: cow.owner_generation(),
            })))
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
                fault: self.fault,
            }))
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
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockCowTransport {
                owner_generation: Arc::clone(&owner_generation),
                bytes: Arc::clone(&bytes),
                fault,
            })),
        );
        let mm = child.shared().mm().id();
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
        (child, backend, owner_generation, bytes)
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
        let (child, _backend, _owner, child_bytes) =
            cow_fixture(&kernel, &root, 31_081, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();

        with_foreign_mutation(&foreign, |mutation| {
            let cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .expect("break exact child COW");
            let receipt = super::MmAccessAuthority::new()
                .write_foreign(cow, b"edit")
                .expect("copy through authenticated child owner");
            assert_eq!(receipt.bytes_written(), 4);
        });

        assert_eq!(parent_bytes, b"same");
        assert_eq!(&*child_bytes.lock(), b"edit");
    }

    #[test]
    fn foreign_cow_rejects_wrong_mm_guard_range_and_backend_receipt_identity() {
        let (kernel, root) = bootstrap(31_082);
        let execution = execution_lease(&root, 82);
        let (child, _backend, _owner, _bytes) =
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

        let (other, _backend, _owner, _bytes) =
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
            let (target, _backend, _owner, _bytes) =
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
            let (child, _backend, _owner, _bytes) =
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
            let (child, backend, _owner, bytes) = cow_fixture(
                &kernel,
                &root,
                31_101 + domain as i32 * 10,
                MockCowFault::None,
            );
            let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
            let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&foreign, |mutation| {
                let cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .unwrap();
                backend.advance(domain);
                assert!(matches!(
                    super::MmAccessAuthority::new().write_foreign(cow, b"edit"),
                    Err(MmAccessError::StaleCowBroken)
                ));
            });
            assert_eq!(&*bytes.lock(), b"same");
        }

        let (kernel, root) = bootstrap(31_140);
        let execution = execution_lease(&root, 140);
        let (child, _backend, owner, bytes) =
            cow_fixture(&kernel, &root, 31_141, MockCowFault::None);
        let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
        let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
        with_foreign_mutation(&foreign, |mutation| {
            let cow = super::MmAccessAuthority::new()
                .break_foreign_cow(mutation, &foreign, range)
                .unwrap();
            owner.fetch_add(1, Ordering::AcqRel);
            assert!(matches!(
                super::MmAccessAuthority::new().write_foreign(cow, b"edit"),
                Err(MmAccessError::ForeignTransport(
                    ForeignMmTransportError::OwnerStale
                ))
            ));
        });
        assert_eq!(&*bytes.lock(), b"same");
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
}
