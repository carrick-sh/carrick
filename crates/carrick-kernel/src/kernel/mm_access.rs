//! Kernel-minted authority for one exact Linux address-space incarnation.

use std::marker::PhantomData;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use carrick_guest_mem::GuestVa;

use super::objects::{PtraceTextAccess, ThreadExecutionError, ThreadExecutionLease};
use super::{
    Kernel, KernelContext, Mm, MmBackendSnapshot, MmId, SnapshotError, TaskKey, TaskLifecycle,
};

mod current_read;
mod instruction_content;
pub use current_read::{CurrentReadCache, CurrentReadWindow};
pub use instruction_content::{ActiveInstructionContent, PreparedInstructionContent};

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
    /// Carrier read lease. Replaced in place when the carrier reports it
    /// stale (the target's frame inventory moved after the retain), so every
    /// later chunk of the same token reuses the fresh lease.
    foreign_lease: Arc<parking_lot::RwLock<Option<carrick_hal::ForeignMmLeaseEndpoint>>>,
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

    fn ptrace_text_range<'mm, 'witness>(
        &'mm self,
        access: &'witness PtraceTextAccess<'witness>,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<PtraceTextWriteRange<'mm, 'witness>>, MmAccessError> {
        if access.mm_id() != self.mm_id() {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let Some(len) = NonZeroUsize::new(len) else {
            return Ok(None);
        };
        let policy = validate_ptrace_text_range_in_snapshot(&self.snapshot, start, len)?;
        let vma_revision = self
            .snapshot
            .vma_revision
            .ok_or(MmAccessError::IncompleteForeignSnapshot(self.mm_id()))?;
        let frame_inventory_revision = self
            .snapshot
            .frame_inventory_revision
            .ok_or(MmAccessError::IncompleteForeignSnapshot(self.mm_id()))?;
        Ok(Some(PtraceTextWriteRange {
            token: self,
            start,
            len,
            binding: carrick_hal::ForeignMmBinding::for_aarch64(
                carrick_hal::ForeignAsid::from_kernel_allocation(
                    NonZeroU16::new(self.snapshot.binding.asid.raw())
                        .ok_or(MmAccessError::IncompleteForeignSnapshot(self.mm_id()))?,
                ),
                self.snapshot.binding.stage1_root.gpa(),
            ),
            backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(
                self.snapshot.revision,
            ),
            vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(vma_revision.raw()),
            frame_inventory_revision:
                carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                    frame_inventory_revision,
                ),
            executable: policy.executable,
            _witness: PhantomData,
        }))
    }

    fn validate_range(
        &self,
        start: GuestVa,
        len: NonZeroUsize,
        requested: RangeAccess,
    ) -> Result<(), MmAccessError> {
        validate_range_in_snapshot(&self.snapshot, start, len, requested).map(|_| ())
    }
}

fn validate_range_in_snapshot(
    snapshot: &MmBackendSnapshot,
    start: GuestVa,
    len: NonZeroUsize,
    requested: RangeAccess,
) -> Result<bool, MmAccessError> {
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
            RangeAccess::Execute if !vma.access.kernel_visible => {
                Some(MmAccessError::KernelHidden {
                    address: GuestVa(cursor),
                })
            }
            RangeAccess::Execute if !vma.access.executable => Some(MmAccessError::ExecuteDenied {
                address: GuestVa(cursor),
            }),
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
            return Ok(false);
        }
    }

    Err(MmAccessError::Unmapped {
        address: GuestVa(cursor),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RangeAccess {
    Execute,
    Read,
    KernelRead,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PtraceTextRangePolicy {
    executable: bool,
}

fn validate_ptrace_text_range_in_snapshot(
    snapshot: &MmBackendSnapshot,
    start: GuestVa,
    len: NonZeroUsize,
) -> Result<PtraceTextRangePolicy, MmAccessError> {
    let end = start
        .raw()
        .checked_add(len.get() as u64)
        .ok_or(MmAccessError::RangeOverflow {
            start,
            len: len.get(),
        })?;
    let mut cursor = start.raw();
    let mut executable = true;
    for vma in &snapshot.vmas {
        if vma.end.raw() <= cursor {
            continue;
        }
        if vma.start.raw() > cursor {
            return Err(MmAccessError::Unmapped {
                address: GuestVa(cursor),
            });
        }
        if !vma.access.kernel_visible {
            return Err(MmAccessError::KernelHidden {
                address: GuestVa(cursor),
            });
        }
        if !vma.access.writable && !vma.access.executable {
            return Err(MmAccessError::WriteDenied {
                address: GuestVa(cursor),
            });
        }
        executable &= vma.access.executable;
        cursor = vma.end.raw().min(end);
        if cursor == end {
            return Ok(PtraceTextRangePolicy { executable });
        }
    }
    Err(MmAccessError::Unmapped {
        address: GuestVa(cursor),
    })
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

/// Non-copy exceptional range whose lifetime is bounded by the exact settled
/// ptrace stop that minted it.
pub struct PtraceTextWriteRange<'mm, 'witness> {
    token: &'mm MmToken,
    start: GuestVa,
    len: NonZeroUsize,
    binding: carrick_hal::ForeignMmBinding,
    backend_revision: carrick_hal::ForeignBackendRevision,
    vma_revision: carrick_hal::ForeignVmaRevision,
    frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision,
    executable: bool,
    _witness: PhantomData<&'witness mut ()>,
}

// SAFETY: construction is private to `MmToken::ptrace_text_range`, which
// requires the non-cloneable lock-bounded `PtraceTextAccess`, authenticates the
// exact MM id, and copies every revision/range from that token's coherent
// backend snapshot.
unsafe impl carrick_hal::ForeignPtraceTextAuthority for PtraceTextWriteRange<'_, '_> {
    fn mm(&self) -> carrick_hal::ForeignMmId {
        carrick_hal::ForeignMmId::from_kernel_allocation(self.token.mm_id().nonzero())
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

    fn start(&self) -> GuestVa {
        self.start
    }

    fn len(&self) -> usize {
        self.len.get()
    }
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

    pub fn write_range(
        &self,
        start: GuestVa,
        len: usize,
    ) -> Result<Option<MmWriteRange<'_>>, MmAccessError> {
        self.token.write_range(start, len)
    }
}

pub trait MmAccessTarget {
    fn access_token(&self) -> &MmToken;
}

impl MmAccessTarget for CurrentMm<'_> {
    fn access_token(&self) -> &MmToken {
        &self.token
    }
}

impl MmAccessTarget for ForeignMm {
    fn access_token(&self) -> &MmToken {
        &self.token
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
pub struct PreparedForeignWrite<'mm, 'src, 'witness, 'guard, 'authority> {
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
pub struct ForeignReadReceipt {
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
pub struct MmAccessAuthority;

impl MmAccessAuthority {
    #[allow(dead_code)] // Task 8 is the first syscall consumer.
    const MAX_ATTEMPTS: usize = 3;

    const OVERALL_DEADLINE: Duration = Duration::from_millis(50);

    pub fn new() -> Self {
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

    pub fn with_current_mutation<T>(
        &self,
        mm: &CurrentMm<'_>,
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
        self.read_mm(&mm.token, range, dst)
    }

    fn read_mm(
        &self,
        token: &MmToken,
        range: MmReadRange<'_>,
        dst: &mut [u8],
    ) -> Result<ForeignReadReceipt, MmAccessError> {
        if !Arc::ptr_eq(&range.token.mm, &token.mm) || range.token.task != token.task {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        if dst.len() != range.len.get() {
            return Err(MmAccessError::DestinationLengthMismatch {
                range: range.len.get(),
                destination: dst.len(),
            });
        }

        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let token_lease = token
            .foreign_lease
            .read()
            .clone()
            .ok_or(MmAccessError::MissingForeignTransport(token.mm_id()))?;
        // A lease retained when the token was minted can predate the target's
        // current frame inventory (a sibling breaking COW on a frame it shares
        // with the target republishes that frame and bumps the target's
        // inventory revision — LTP process_vm_readv03's parent does exactly
        // that to its own heap mid-syscall). The carrier reports that as
        // `LeaseStale`; the binding is intact, so retain again and retry.
        let mut lease = token_lease;
        let mut stale_retains = 0usize;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&token.mm),
        };
        for _ in 0..Self::MAX_ATTEMPTS {
            if Instant::now() >= deadline {
                return Err(MmAccessError::ForeignReadTimedOut);
            }
            let before_snapshot = snapshot_backend(&token.mm, deadline)?;
            validate_snapshot_vmas(&before_snapshot)?;
            validate_range_in_snapshot(
                &before_snapshot,
                range.start,
                range.len,
                RangeAccess::Read,
            )?;
            let snapshot =
                ProjectedForeignMmSnapshot::from_backend(token.mm_id(), &before_snapshot)?;
            let receipt = match lease.read(&live, &snapshot, range.start, dst, deadline) {
                Ok(receipt) => receipt,
                Err(carrick_hal::ForeignMmTransportError::Retry) => continue,
                Err(carrick_hal::ForeignMmTransportError::LeaseStale) => {
                    stale_retains += 1;
                    if stale_retains > Self::MAX_ATTEMPTS {
                        return Err(MmAccessError::ForeignReadRetryExhausted);
                    }
                    lease = retain_foreign_lease(&token.mm, &snapshot, deadline)?;
                    *token.foreign_lease.write() = Some(lease.clone());
                    continue;
                }
                Err(carrick_hal::ForeignMmTransportError::TimedOut) => {
                    return Err(MmAccessError::ForeignReadTimedOut);
                }
                Err(error) => return Err(MmAccessError::ForeignTransport(error)),
            };
            let after = ProjectedForeignMmSnapshot::from_backend(
                token.mm_id(),
                &snapshot_backend(&token.mm, deadline)?,
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
    pub fn break_foreign_cow<'mm, 'guard, 'authority, T: MmAccessTarget + ?Sized>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm T,
        range: MmWriteRange<'mm>,
    ) -> Result<CowBroken<'mm, 'guard, 'authority>, MmAccessError> {
        self.break_foreign_cow_inner(mutation, mm, range, None, false)
            .map(|(cow, plan)| {
                debug_assert!(plan.is_none());
                cow
            })
    }

    pub fn write_ptrace_text_under_witness<
        'mm,
        'src,
        'witness,
        'guard,
        'authority,
        T: MmAccessTarget + ?Sized,
    >(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm T,
        access: &'witness PtraceTextAccess<'witness>,
        start: GuestVa,
        src: &'src [u8],
    ) -> Result<ForeignWriteReceipt, MmAccessError> {
        let range = mm
            .access_token()
            .ptrace_text_range(access, start, src.len())?
            .ok_or(MmAccessError::SourceLengthMismatch {
                range: 0,
                source_len: src.len(),
            })?;
        let ordinary_shape = MmWriteRange {
            token: range.token,
            start: range.start,
            len: range.len,
        };
        if !range.executable {
            let (mut cow, plan) =
                self.break_foreign_cow_inner(mutation, mm, ordinary_shape, None, false)?;
            debug_assert!(plan.is_none());
            return Ok(self
                .prepare_foreign_write_inner(&mut cow, ordinary_shape, src, None)?
                .commit());
        }
        let (mut cow, plan) =
            self.break_foreign_cow_inner(mutation, mm, ordinary_shape, Some(&range), false)?;
        let plan = plan.ok_or(MmAccessError::ForeignRangeAuthorityMismatch)?;
        Ok(self
            .prepare_foreign_write_inner(&mut cow, ordinary_shape, src, Some(&plan))?
            .commit())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn break_foreign_cow_with_final_snapshot_contended_for_test<'mm, 'guard, 'authority>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm ForeignMm,
        range: MmWriteRange<'mm>,
    ) -> Result<CowBroken<'mm, 'guard, 'authority>, MmAccessError> {
        self.break_foreign_cow_inner(mutation, mm, range, None, true)
            .map(|(cow, plan)| {
                debug_assert!(plan.is_none());
                cow
            })
    }

    fn break_foreign_cow_inner<'mm, 'guard, 'authority, 'ptrace, T: MmAccessTarget + ?Sized>(
        &self,
        mutation: &'guard mut crate::dispatch::mm_mutation::MmMutationGuard<'authority>,
        mm: &'mm T,
        range: MmWriteRange<'mm>,
        ptrace_authority: Option<&'ptrace dyn carrick_hal::ForeignPtraceTextAuthority>,
        contend_final_snapshot: bool,
    ) -> Result<
        (
            CowBroken<'mm, 'guard, 'authority>,
            Option<carrick_hal::ForeignPtraceTextCowPlan<'ptrace>>,
        ),
        MmAccessError,
    > {
        let token = mm.access_token();
        if !Arc::ptr_eq(&range.token.mm, &token.mm) || range.token.task != token.task {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let target_mutation = token.foreign_mutation.as_ref().ok_or(
            MmAccessError::MissingForeignMutationAuthority(token.mm_id()),
        )?;
        if !target_mutation.authorizes(mutation) {
            return Err(MmAccessError::ForeignMutationAuthorityMismatch);
        }
        let deadline = Instant::now() + Self::OVERALL_DEADLINE;
        let lease = token
            .foreign_lease
            .read()
            .clone()
            .ok_or(MmAccessError::MissingForeignTransport(token.mm_id()))?;
        let before = snapshot_backend(&token.mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        let ptrace_policy = if ptrace_authority.is_some() {
            Some(validate_ptrace_text_range_in_snapshot(
                &before,
                range.start,
                range.len,
            )?)
        } else {
            validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
            None
        };
        let requested = ProjectedForeignMmSnapshot::from_backend(token.mm_id(), &before)?;
        let executable_plan =
            if let (Some(authority), Some(policy)) = (ptrace_authority, ptrace_policy) {
                if !policy.executable {
                    None
                } else {
                    Some(
                        lease
                            .prepare_ptrace_text_cow(&requested, authority)
                            .map_err(MmAccessError::ForeignTransport)?,
                    )
                }
            } else {
                None
            };
        let receipt = mutation.with_host_alias(|invalidator| {
            if let Some(plan) = executable_plan.as_ref() {
                lease.break_cow_prepared_ptrace_text(
                    invalidator,
                    &requested,
                    range.start,
                    range.len.get(),
                    plan,
                    deadline,
                )
            } else {
                lease.break_cow(
                    invalidator,
                    &requested,
                    range.start,
                    range.len.get(),
                    deadline,
                )
            }
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
                    .downcast_ref::<crate::kernel::KernelForeignCowProof>()
                    .is_some_and(|proof| {
                        proof.authenticates(
                            &token.kernel,
                            token.mm_id(),
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
        Ok((
            CowBroken {
                range,
                transport: receipt,
                guard: mutation,
            },
            executable_plan,
        ))
    }

    #[allow(dead_code)] // Canonical process_vm consumer lands in Task 8.
    pub fn prepare_foreign_write<'mm, 'src, 'witness, 'guard, 'authority>(
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
        self.prepare_foreign_write_inner(witness, range, src, None)
    }

    fn prepare_foreign_write_inner<'mm, 'src, 'witness, 'guard, 'authority>(
        &self,
        witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
        range: MmWriteRange<'mm>,
        src: &'src [u8],
        executable_plan: Option<&carrick_hal::ForeignPtraceTextCowPlan>,
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
        if executable_plan.is_some() {
            if !validate_ptrace_text_range_in_snapshot(&before, range.start, range.len)?.executable
            {
                return Err(MmAccessError::ForeignRangeAuthorityMismatch);
            }
        } else {
            validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
        }
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &before)?;
        if snapshot.mm != witness.transport.mm()
            || snapshot.backend_revision != witness.transport.backend_revision()
            || snapshot.vma_revision != witness.transport.vma_revision()
            || snapshot.frame_inventory_revision != witness.transport.frame_inventory_revision()
            || !snapshot.mapping_ids.contains(&witness.transport.mapping())
            || !witness
                .transport
                .kernel_proof()
                .downcast_ref::<crate::kernel::KernelForeignCowProof>()
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
            .read()
            .clone()
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let live = RetainedMmLiveAuthority { mm: Arc::clone(mm) };
        let prepared = if let Some(plan) = executable_plan {
            lease.prepare_executable_write_commit(
                &live,
                &snapshot,
                witness.transport.as_ref(),
                range.start,
                src,
                plan,
                deadline,
            )
        } else {
            lease.prepare_write(
                &live,
                &snapshot,
                witness.transport.as_ref(),
                range.start,
                src,
                deadline,
            )
        };
        let prepared_transport = match prepared {
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
    pub fn commit_foreign_write(
        &self,
        prepared: PreparedForeignWrite<'_, '_, '_, '_, '_>,
    ) -> ForeignWriteReceipt {
        prepared.commit()
    }
}

#[allow(dead_code)] // Task 8 is the first syscall consumer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedForeignMmSnapshot {
    mm: carrick_hal::ForeignMmId,
    pub binding: carrick_hal::ForeignMmBinding,
    backend_revision: carrick_hal::ForeignBackendRevision,
    vma_revision: carrick_hal::ForeignVmaRevision,
    frame_inventory_revision: carrick_hal::ForeignFrameInventoryRevision,
    mapping_ids: Vec<carrick_hal::MappingId>,
    executable_ranges: Vec<carrick_hal::ForeignExecutableRange>,
    readable_ranges: Vec<carrick_hal::ForeignReadableRange>,
}

impl ProjectedForeignMmSnapshot {
    pub fn from_backend(mm_id: MmId, snapshot: &MmBackendSnapshot) -> Result<Self, MmAccessError> {
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
            executable_ranges: snapshot
                .vmas
                .iter()
                .filter(|vma| vma.access.executable && vma.access.kernel_visible)
                .filter_map(|vma| {
                    carrick_hal::ForeignExecutableRange::from_kernel_projection(vma.start, vma.end)
                })
                .collect(),
            readable_ranges: snapshot
                .vmas
                .iter()
                .filter(|vma| vma.access.readable && vma.access.kernel_visible)
                .filter_map(|vma| {
                    carrick_hal::ForeignReadableRange::from_kernel_projection(vma.start, vma.end)
                })
                .collect(),
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

    fn executable_ranges(&self) -> &[carrick_hal::ForeignExecutableRange] {
        &self.executable_ranges
    }

    fn readable_ranges(&self) -> &[carrick_hal::ForeignReadableRange] {
        &self.readable_ranges
    }
}

#[derive(Debug)]
struct RetainedMmLiveAuthority {
    mm: Arc<Mm>,
}

impl carrick_hal::ForeignMmLiveAuthority for RetainedMmLiveAuthority {
    fn matches_authenticated_snapshot(
        &self,
        expected: &dyn carrick_hal::ForeignMmSnapshot,
        deadline: Instant,
    ) -> Result<bool, carrick_hal::ForeignMmTransportError> {
        let backend = self
            .mm
            .backend()
            .ok_or(carrick_hal::ForeignMmTransportError::AuthorityUnavailable)?;
        if let Some(stamp) = backend
            .snapshot_stamp(deadline)
            .map_err(|e| snapshot_error_for_transport(MmAccessError::Snapshot(e)))?
        {
            return Ok(expected.mm().raw_for_probe() == self.mm.id().raw()
                && expected.binding().asid().raw_for_probe() == stamp.binding.asid.raw()
                && expected.binding().stage1_root() == stamp.binding.stage1_root.gpa()
                && expected.backend_revision()
                    == carrick_hal::ForeignBackendRevision::from_authority_raw(stamp.revision)
                && expected.vma_revision()
                    == carrick_hal::ForeignVmaRevision::from_authority_raw(
                        stamp.vma_revision.raw(),
                    )
                && expected.frame_inventory_revision()
                    == carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(
                        stamp.frame_inventory_revision,
                    ));
        }
        Ok(self.snapshot(deadline)?.has_same_contents(expected))
    }

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
    #[error("guest address {address:?} is not executable in this MM")]
    ExecuteDenied { address: GuestVa },
    #[error("instruction read no longer names the same live MM mapping snapshot")]
    StaleInstructionRead,
    #[error("instruction fetch must contain at least one byte")]
    EmptyInstructionRead,
    #[error("instruction bytes changed through a tracked carrier host writer")]
    StaleInstructionContent,
    #[error("instruction transport does not track backing content writes")]
    UntrackedInstructionContent,
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
    #[error("native data grant intersects executable memory at {address:?}")]
    NativeDataExecutable { address: GuestVa },
    #[error("native data activation requires a host control safe point")]
    NativeDataControlPending,
    #[error("prepared native data no longer names the exact live MM snapshot")]
    StaleNativeData,
    #[error("foreign COW witness no longer matches the three live MM revisions")]
    StaleCowBroken,
    #[error("foreign MM write exceeded its overall deadline budget")]
    ForeignWriteTimedOut,
}

/// Resident native data scoped to a current execution lease and an existing
/// COW mutation transaction. This is a data-only integration primitive, not a
/// concurrent execution-quantum or translated-code publication permit.
///
/// The transport drops its owner pin before the witness borrow is released.
/// Keeping real borrows prevents lease transfer or mutation-guard release while
/// this capability is live. Raw-pointer use remains an unsafe backend operation.
///
/// ```compile_fail
/// use carrick_kernel::kernel::{KernelContext, objects::ThreadExecutionLease};
/// use carrick_kernel::kernel::mm_access::{CowBroken, CurrentNativeData};
/// fn escape(c: &KernelContext, e: &ThreadExecutionLease, cow: &mut CowBroken<'_, '_, '_>)
///     -> CurrentNativeData<'static, 'static, 'static, 'static, 'static> {
///     c.borrow_current_native_data(e, cow).unwrap()
/// }
/// ```
/// The execution lease cannot be transferred while its data grant is live.
///
/// ```compile_fail,E0505
/// use carrick_kernel::kernel::{KernelContext, objects::ThreadExecutionLease};
/// use carrick_kernel::kernel::mm_access::CowBroken;
/// fn transfer(c: &KernelContext, e: ThreadExecutionLease, cow: &mut CowBroken<'_, '_, '_>) {
///     let data = c.borrow_current_native_data(&e, cow).unwrap();
///     c.thread().yield_from_executor(e).unwrap();
///     let _ = data.len();
/// }
/// ```
pub struct CurrentNativeData<'execution, 'witness, 'mm, 'guard, 'authority> {
    transport: Box<dyn carrick_hal::ForeignNativeDataSpan>,
    snapshot: ProjectedForeignMmSnapshot,
    start: GuestVa,
    len: NonZeroUsize,
    _context: &'execution KernelContext,
    _execution: &'execution ThreadExecutionLease,
    _witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
    _thread: PhantomData<std::rc::Rc<()>>,
}

impl CurrentNativeData<'_, '_, '_, '_, '_> {
    pub fn start(&self) -> GuestVa {
        self.start
    }
    pub fn len(&self) -> usize {
        self.len.get()
    }
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Retain an opaque pin beyond this COW transaction. This consumes the
    /// mutation-scoped pointer grant; only activation under a new execution
    /// scope can restore pointer access. Preparation itself grants no access.
    pub fn prepare_for_execution(mut self) -> PreparedNativeData {
        self.transport.finish_native_access();
        PreparedNativeData {
            transport: self.transport,
            token: self._witness.range.token.clone(),
            snapshot: self.snapshot,
            start: self.start,
            len: self.len,
            _thread: PhantomData,
        }
    }

    /// # Safety
    /// Access only `[start(), start() + len())` through the returned backing
    /// pointer and never use it after this grant drops. Do not re-enter kernel
    /// dispatch/mutation, publish executable code, or manufacture Rust references
    /// incompatible with other live backing access. The enclosing COW exclusion
    /// must remain live for the whole bounded native operation.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: the wrapper retains the exact execution and COW exclusion;
        // the caller accepts the bounded-use and no-escape obligations above.
        unsafe { self.transport.as_mut_ptr() }
    }
}

impl KernelContext {
    /// Borrow resident data only after the current MM's exact COW transaction.
    /// The data backing comes from the MM-installed carrier endpoint. No host
    /// pointer, independent GuestMemory, or caller-selected MM is accepted.
    pub fn borrow_current_native_data<'execution, 'witness, 'mm, 'guard, 'authority>(
        &'execution self,
        execution: &'execution ThreadExecutionLease,
        witness: &'witness mut CowBroken<'mm, 'guard, 'authority>,
    ) -> Result<CurrentNativeData<'execution, 'witness, 'mm, 'guard, 'authority>, MmAccessError>
    {
        let mm = self.authenticate_current_mm(execution)?;
        let range = witness.range;
        if !Arc::ptr_eq(&mm, &range.token.mm)
            || !Arc::ptr_eq(&self.kernel, &range.token.kernel)
            || self.task.key() != range.token.task
        {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let mutation = range
            .token
            .foreign_mutation
            .as_ref()
            .ok_or(MmAccessError::MissingForeignMutationAuthority(mm.id()))?;
        if !mutation.authorizes(witness.guard) {
            return Err(MmAccessError::ForeignMutationAuthorityMismatch);
        }
        let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
        let before = snapshot_backend(&mm, deadline)?;
        validate_snapshot_vmas(&before)?;
        validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::KernelRead)?;
        validate_range_in_snapshot(&before, range.start, range.len, RangeAccess::Write)?;
        let end = range
            .start
            .raw()
            .checked_add(range.len.get() as u64)
            .ok_or(MmAccessError::RangeOverflow {
                start: range.start,
                len: range.len.get(),
            })?;
        if let Some(vma) = before.vmas.iter().find(|vma| {
            vma.start.raw() < end && range.start.raw() < vma.end.raw() && vma.access.executable
        }) {
            return Err(MmAccessError::NativeDataExecutable { address: vma.start });
        }
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &before)?;
        let cow = witness.transport.as_ref();
        if snapshot.mm != cow.mm()
            || snapshot.backend_revision != cow.backend_revision()
            || snapshot.vma_revision != cow.vma_revision()
            || snapshot.frame_inventory_revision != cow.frame_inventory_revision()
            || !snapshot.mapping_ids.contains(&cow.mapping())
            || !cow
                .kernel_proof()
                .downcast_ref::<crate::kernel::KernelForeignCowProof>()
                .is_some_and(|proof| {
                    proof.authenticates(
                        &self.kernel,
                        mm.id(),
                        cow.range_start(),
                        cow.range_len(),
                        cow.frame_inventory_revision().raw_for_probe(),
                        cow.mapping(),
                        cow.frame(),
                        cow.physical_base(),
                        cow.physical_len(),
                        cow.owner_generation(),
                    )
                })
        {
            return Err(MmAccessError::StaleCowBroken);
        }
        let lease = range
            .token
            .foreign_lease
            .read()
            .clone()
            .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&mm),
        };
        let transport = lease
            .borrow_native_data(
                &live,
                &snapshot,
                cow,
                range.start,
                range.len.get(),
                deadline,
            )
            .map_err(MmAccessError::ForeignTransport)?;
        let after =
            ProjectedForeignMmSnapshot::from_backend(mm.id(), &snapshot_backend(&mm, deadline)?)?;
        if after != snapshot || !Arc::ptr_eq(&mm, &self.authenticate_current_mm(execution)?) {
            return Err(MmAccessError::StaleCowBroken);
        }
        if !transport.authenticates(&snapshot, cow, range.start, range.len.get()) {
            return Err(MmAccessError::ForeignReceiptMismatch);
        }
        Ok(CurrentNativeData {
            transport,
            snapshot,
            start: range.start,
            len: range.len,
            _context: self,
            _execution: execution,
            _witness: witness,
            _thread: PhantomData,
        })
    }
}

/// Opaque, pinned carrier backing prepared by an authenticated COW transaction.
/// Keeping this value alive does not retain mutation exclusion or permit access.
/// Activation checks the live MM snapshot and transport authority on every scope.
pub struct PreparedNativeData {
    transport: Box<dyn carrick_hal::ForeignNativeDataSpan>,
    token: MmToken,
    snapshot: ProjectedForeignMmSnapshot,
    start: GuestVa,
    len: NonZeroUsize,
    _thread: PhantomData<std::rc::Rc<()>>,
}

impl PreparedNativeData {
    pub fn activate<'active, 'scope>(
        &'active mut self,
        scope: &'active crate::dispatch::native_execution::NativeExecution<'scope>,
    ) -> Result<ActiveNativeData<'active, 'scope>, MmAccessError> {
        let mutation = self.token.foreign_mutation.as_ref().ok_or(
            MmAccessError::MissingForeignMutationAuthority(self.token.mm.id()),
        )?;
        let context = scope.data_context(mutation)?;
        if !Arc::ptr_eq(&context.kernel, &self.token.kernel)
            || context.task.key() != self.token.task
            || !Arc::ptr_eq(&context.shared.mm(), &self.token.mm)
        {
            return Err(MmAccessError::ForeignRangeAuthorityMismatch);
        }
        let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
        use carrick_hal::ForeignMmLiveAuthority;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&self.token.mm),
        };
        // The opaque preparation already authenticated permissions and contents.
        // These revisions belong to its immutable MM backend; they cannot grant
        // authority to a new or caller-created snapshot.
        if !live
            .matches_authenticated_snapshot(&self.snapshot, deadline)
            .map_err(MmAccessError::ForeignTransport)?
        {
            return Err(MmAccessError::StaleNativeData);
        }
        self.transport
            .validate_native_activation(&self.snapshot, deadline)
            .map_err(MmAccessError::ForeignTransport)?;
        if !live
            .matches_authenticated_snapshot(&self.snapshot, deadline)
            .map_err(MmAccessError::ForeignTransport)?
        {
            return Err(MmAccessError::StaleNativeData);
        }
        scope.data_context(mutation)?;
        Ok(ActiveNativeData {
            prepared: self,
            _scope: scope,
        })
    }
}

/// Data access borrowed from the exact native running scope. Dropping this grant
/// releases access; dropping the scope afterward acknowledges the safe point.
///
/// ```compile_fail,E0505
/// use carrick_kernel::{kernel::mm_access::PreparedNativeData, dispatch::native_execution::NativeExecution};
/// fn end_scope(mut p: PreparedNativeData, scope: NativeExecution<'_>) {
///     let mut active = p.activate(&scope).unwrap();
///     drop(scope);
///     unsafe { active.as_mut_ptr(); }
/// }
/// ```
/// ```compile_fail,E0499
/// use carrick_kernel::{kernel::mm_access::PreparedNativeData, dispatch::native_execution::NativeExecution};
/// fn duplicate(p: &mut PreparedNativeData, scope: &NativeExecution<'_>) {
///     let a = p.activate(scope).unwrap();
///     let b = p.activate(scope).unwrap();
///     drop((a, b));
/// }
/// ```
pub struct ActiveNativeData<'active, 'scope> {
    prepared: &'active mut PreparedNativeData,
    _scope: &'active crate::dispatch::native_execution::NativeExecution<'scope>,
}
impl ActiveNativeData<'_, '_> {
    pub fn start(&self) -> GuestVa {
        self.prepared.start
    }
    pub fn len(&self) -> usize {
        self.prepared.len.get()
    }
    pub fn is_empty(&self) -> bool {
        false
    }
    /// # Safety
    /// Only access this grant's bounded range while both grant and execution
    /// scope remain live. Do not manufacture incompatible Rust references,
    /// publish executable code, re-enter dispatch/mutation or escape the pointer.
    /// The native executor must return at bounded control checkpoints.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: activation validated the live carrier state after entering the
        // exact running handshake. The retained scope prevents mutation passing
        // its drain until this grant and all bounded pointer accesses have ended.
        unsafe { self.prepared.transport.as_mut_ptr() }
    }
}

impl Drop for ActiveNativeData<'_, '_> {
    fn drop(&mut self) {
        self.prepared.transport.finish_native_access();
    }
}

#[cfg(test)]
mod native_data_type_tests {
    use super::{ActiveNativeData, CurrentNativeData, PreparedNativeData};
    static_assertions::assert_not_impl_any!(PreparedNativeData: Send, Sync, Clone, Copy);
    static_assertions::assert_not_impl_any!(ActiveNativeData<'static, 'static>: Send, Sync, Clone, Copy);
    static_assertions::assert_not_impl_any!(CurrentNativeData<'static, 'static, 'static, 'static, 'static>: Send, Sync, Clone, Copy);
}

/// Copied instructions from one authenticated current-MM observation.
///
/// This retains the exact execution lease borrow for decoding. Mapping
/// validation detects topology/permission/backing changes, but does NOT detect
/// every in-place executable write. The retained receipt additionally detects
/// participating carrier host writes; untracked transports and deferred bytes
/// explicitly decline that check. Neither check grants code-cache publication.
/// A translator must mediate all writers and obtain atomic publication authority
/// before executing emitted code from these bytes.
pub struct InstructionRead<'execution> {
    context: &'execution KernelContext,
    execution: &'execution ThreadExecutionLease,
    mm: Arc<Mm>,
    snapshot: ProjectedForeignMmSnapshot,
    bytes: Vec<u8>,
    receipt: Box<dyn carrick_hal::ForeignMmReadReceipt>,
}

impl InstructionRead<'_> {
    /// Reject mapping changes and participating host writes since capture.
    /// Success is NOT a native execution/publication permit: mediation of guest
    /// stores and all writers, alias admission, and active-code drain remain
    /// separate obligations. An uninstrumented transport is never a success.
    pub fn validate_tracked_content(&self) -> Result<(), MmAccessError> {
        use carrick_hal::foreign_mm::ForeignInstructionContentStatus;
        self.validate_mapping()?;
        match self.receipt.instruction_content_status() {
            ForeignInstructionContentStatus::UnchangedTrackedWrites => Ok(()),
            ForeignInstructionContentStatus::Changed => Err(MmAccessError::StaleInstructionContent),
            ForeignInstructionContentStatus::Untracked => {
                Err(MmAccessError::UntrackedInstructionContent)
            }
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reauthenticate execution and mapping identity. This does not authorize
    /// execution or guarantee instruction contents remained unchanged.
    pub fn validate_mapping(&self) -> Result<(), MmAccessError> {
        let mm = self.context.authenticate_current_mm(self.execution)?;
        if !Arc::ptr_eq(&mm, &self.mm) {
            return Err(MmAccessError::StaleInstructionRead);
        }
        let live = snapshot_backend(&mm, Instant::now() + MM_SNAPSHOT_TIMEOUT)?;
        validate_snapshot_vmas(&live)?;
        if ProjectedForeignMmSnapshot::from_backend(mm.id(), &live)? != self.snapshot {
            return Err(MmAccessError::StaleInstructionRead);
        }
        Ok(())
    }
}

impl KernelContext {
    /// Fetch through the carrier endpoint installed on the authenticated MM.
    /// No independently supplied GuestMemory or caller-selected MM identity is
    /// accepted. A concurrent mutation is returned to the caller, not retried
    /// into a different translation generation. This is translation setup work,
    /// not a per-syscall path.
    pub fn fetch_instruction_bytes<'execution>(
        &'execution self,
        execution: &'execution ThreadExecutionLease,
        start: GuestVa,
        len: usize,
    ) -> Result<InstructionRead<'execution>, MmAccessError> {
        let mm = self.authenticate_current_mm(execution)?;
        let len = NonZeroUsize::new(len).ok_or(MmAccessError::EmptyInstructionRead)?;
        let deadline = Instant::now() + MM_SNAPSHOT_TIMEOUT;
        let backend = snapshot_backend(&mm, deadline)?;
        validate_snapshot_vmas(&backend)?;
        validate_range_in_snapshot(&backend, start, len, RangeAccess::Execute)?;
        let snapshot = ProjectedForeignMmSnapshot::from_backend(mm.id(), &backend)?;
        let lease = retain_foreign_lease(&mm, &snapshot, deadline)?;
        let live = RetainedMmLiveAuthority {
            mm: Arc::clone(&mm),
        };
        let mut bytes = vec![0; len.get()];
        let receipt = lease
            .read_instructions(&live, &snapshot, start, &mut bytes, deadline)
            .map_err(MmAccessError::ForeignTransport)?;
        if !receipt.authenticates(&snapshot)
            || receipt.bytes_read() != bytes.len()
            || receipt.owner_generations().is_empty()
        {
            return Err(MmAccessError::ForeignReceiptMismatch);
        }
        let read = InstructionRead {
            context: self,
            execution,
            mm,
            snapshot,
            bytes,
            receipt,
        };
        read.validate_mapping()?;
        Ok(read)
    }
}

impl KernelContext {
    /// Copy syscall input from the carrier of the authenticated current MM.
    /// No caller-supplied byte store or numeric MM selector is accepted. The
    /// execution lease stays borrowed; no native pointer or mapping grant
    /// escapes this operation. Zero-length copies still authenticate the lease.
    pub fn copy_current_into(
        &self,
        execution: &ThreadExecutionLease,
        start: GuestVa,
        dst: &mut [u8],
    ) -> Result<(), MmAccessError> {
        self.authenticate_current_mm(execution)?;
        if dst.is_empty() {
            return Ok(());
        }
        let current = self.current_mm(execution)?;
        let range = current.token.read_range(start, dst.len())?.ok_or(
            MmAccessError::DestinationLengthMismatch {
                range: 0,
                destination: dst.len(),
            },
        )?;
        MmAccessAuthority::new().read_mm(&current.token, range, dst)?;
        Ok(())
    }

    /// Copy ordinary syscall output through the current carrier's COW path.
    /// Exact-MM exclusion is local to this copy; it is never held across the
    /// surrounding syscall. Each prepared write owns its real COW witness.
    /// Executable writes require separate publication authority and are refused.
    /// A later-chunk fault may leave earlier chunks copied, as with copy_to_user;
    /// this is not an atomic multi-page transaction.
    pub fn copy_current_from(
        &self,
        execution: &ThreadExecutionLease,
        start: GuestVa,
        src: &[u8],
    ) -> Result<(), MmAccessError> {
        self.authenticate_current_mm(execution)?;
        if src.is_empty() {
            return Ok(());
        }
        let current = self.current_mm(execution)?;
        // Validate the complete semantic range before the first byte changes.
        current.write_range(start, src.len())?;
        let reject_executable = |current: &CurrentMm, address: GuestVa, len: usize| {
            let snapshot =
                snapshot_backend(&current.token.mm, Instant::now() + MM_SNAPSHOT_TIMEOUT)?;
            let end =
                address
                    .raw()
                    .checked_add(len as u64)
                    .ok_or(MmAccessError::RangeOverflow {
                        start: address,
                        len,
                    })?;
            if let Some(vma) = snapshot.vmas.iter().find(|vma| {
                vma.start.raw() < end && address.raw() < vma.end.raw() && vma.access.executable
            }) {
                return Err(MmAccessError::NativeDataExecutable { address: vma.start });
            }
            Ok(())
        };
        reject_executable(&current, start, src.len())?;
        let authority = MmAccessAuthority::new();
        authority.with_current_mutation(&current, self.thread().registry_id(), |mutation| {
            let mut offset = 0;
            while offset < src.len() {
                let address =
                    start
                        .raw()
                        .checked_add(offset as u64)
                        .ok_or(MmAccessError::RangeOverflow {
                            start,
                            len: src.len(),
                        })?;
                // Identity receipts authenticate one 4 KiB guest leaf; a
                // COW compound may be larger, but subsequent copies must use
                // the same leaf-bounded contract as already-private memory.
                let remaining = 0x1000 - address % 0x1000;
                let len = (src.len() - offset).min(remaining as usize);
                // A preceding compound COW may have advanced inventory. Mint
                // this chunk against its current snapshot, not the first one.
                let chunk_mm = self.current_mm(execution)?;
                reject_executable(&chunk_mm, GuestVa(address), len)?;
                let range = chunk_mm.write_range(GuestVa(address), len)?.ok_or(
                    MmAccessError::SourceLengthMismatch {
                        range: 0,
                        source_len: len,
                    },
                )?;
                let mut cow = authority.break_foreign_cow(mutation, &chunk_mm, range)?;
                let prepared =
                    authority.prepare_foreign_write(&mut cow, &src[offset..offset + len])?;
                authority.commit_foreign_write(prepared);
                offset += len;
            }
            Ok(())
        })
    }

    /// Authenticate the exact live task, thread, execution lease and MM without
    /// collecting a mapping snapshot. Execution backends use this at a resume
    /// boundary when they already own their backing and executable capability.
    ///
    /// The returned identity grants no access to bytes, mappings or executable
    /// publication. Those still require the appropriate memory authority. Use
    /// `current_mm` when constructing a permission-checked memory range.
    pub fn validate_current_execution_mm(
        &self,
        execution: &ThreadExecutionLease,
    ) -> Result<MmId, MmAccessError> {
        self.authenticate_current_mm(execution).map(|mm| mm.id())
    }

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

/// Retain a carrier read lease for `mm` against `projected`, the snapshot the
/// caller just validated. Used at token mint and again whenever the carrier
/// reports the retained lease stale.
fn retain_foreign_lease(
    mm: &Arc<Mm>,
    projected: &ProjectedForeignMmSnapshot,
    deadline: Instant,
) -> Result<carrick_hal::ForeignMmLeaseEndpoint, MmAccessError> {
    let permit = ForeignEndpointPermit { _private: () };
    let endpoint = mm
        .foreign_mm_endpoint(&permit, deadline)
        .ok_or(MmAccessError::ForeignReadTimedOut)?
        .ok_or(MmAccessError::MissingForeignTransport(mm.id()))?;
    endpoint
        .retain(projected, deadline)
        .map_err(MmAccessError::ForeignTransport)
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
        let projected = ProjectedForeignMmSnapshot::from_backend(mm.id(), &snapshot)?;
        Some(retain_foreign_lease(&mm, &projected, deadline)?)
    } else {
        let permit = ForeignEndpointPermit { _private: () };
        mm.foreign_mm_endpoint(&permit, deadline)
            .flatten()
            .and_then(|endpoint| {
                ProjectedForeignMmSnapshot::from_backend(mm.id(), &snapshot)
                    .ok()
                    .and_then(|projected| endpoint.retain(&projected, deadline).ok())
            })
    };
    let foreign_mutation = if retain_foreign {
        let permit = ForeignEndpointPermit { _private: () };
        mm.foreign_mm_mutation_authority(&permit, deadline)
            .ok_or(MmAccessError::ForeignReadTimedOut)?
    } else {
        let permit = ForeignEndpointPermit { _private: () };
        mm.foreign_mm_mutation_authority(&permit, deadline)
            .flatten()
    };
    Ok(MmToken {
        task,
        kernel,
        mm,
        snapshot,
        foreign_lease: Arc::new(parking_lot::RwLock::new(foreign_lease)),
        foreign_mutation,
    })
}

/// Thread-local structural instrument for current-copy contract windows.
#[cfg(feature = "conformance-metrics")]
pub mod copy_work_for_test {
    std::thread_local! { static SNAPSHOTS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
    pub fn snapshots() -> u64 {
        SNAPSHOTS.get()
    }
    pub(super) fn collected() {
        SNAPSHOTS.set(SNAPSHOTS.get() + 1);
    }
}

fn snapshot_backend(mm: &Arc<Mm>, deadline: Instant) -> Result<MmBackendSnapshot, MmAccessError> {
    #[cfg(feature = "conformance-metrics")]
    copy_work_for_test::collected();
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

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    use carrick_guest_mem::GuestVa;
    use carrick_hal::{ForeignMmTransport, ForeignMmTransportError};

    use super::super::objects::{ExecutorId, ThreadExecutionError};
    use super::super::{
        LinuxWaitStatus, MmAccessError, MmReadRange, MmToken, MmWriteRange, SnapshotError,
        VmaRevision,
    };
    use super::test_support::*;

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
    fn native_data_borrow_refuses_unimplemented_transport_and_each_stale_revision() {
        for domain in 0..3 {
            let (kernel, root) = bootstrap(32_100 + domain as i32 * 10);
            let execution = execution_lease(&root, 100 + domain as u64);
            let (child, backend, _owner, bytes, counters) = cow_fixture(
                &kernel,
                &root,
                32_101 + domain as i32 * 10,
                MockCowFault::None,
            );
            let child_execution = execution_lease(&child, 200 + domain as u64);
            let foreign = foreign_mm(&kernel, &root, &execution, child.task().key());
            let range = foreign.write_range(GuestVa(0x3000), 4).unwrap().unwrap();
            with_foreign_mutation(&foreign, |mutation| {
                let mut cow = super::MmAccessAuthority::new()
                    .break_foreign_cow(mutation, &foreign, range)
                    .unwrap();
                // This transport supports prepared copies but has no resident
                // pointer capability. A successful COW must not invent one.
                assert!(matches!(
                    child.borrow_current_native_data(&child_execution, &mut cow),
                    Err(MmAccessError::ForeignTransport(
                        ForeignMmTransportError::AuthorityUnavailable
                    ))
                ));
                backend.set_access(super::super::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: false,
                });
                assert!(matches!(
                    child.borrow_current_native_data(&child_execution, &mut cow),
                    Err(MmAccessError::KernelHidden { .. })
                ));
                backend.set_access(super::super::VmaAccess {
                    readable: true,
                    writable: true,
                    executable: false,
                    kernel_visible: true,
                });
                backend.advance(domain);
                assert!(matches!(
                    child.borrow_current_native_data(&child_execution, &mut cow),
                    Err(MmAccessError::StaleCowBroken)
                ));
            });
            assert_eq!(&*bytes.lock(), b"same");
            assert_eq!(counters.prepare_calls.load(Ordering::SeqCst), 0);
            assert_eq!(counters.commit_calls.load(Ordering::SeqCst), 0);
        }
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
                super::super::WaitChildClass::Sigchld,
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
                super::super::WaitChildClass::Sigchld,
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
    fn instruction_fetch_rejects_readable_non_executable_memory() {
        let (_kernel, root) = bootstrap(31_150);
        let execution = execution_lease(&root, 150);
        assert!(matches!(
            root.fetch_instruction_bytes(&execution, GuestVa(0x1000), 4),
            Err(MmAccessError::ExecuteDenied {
                address: GuestVa(0x1000)
            })
        ));
    }

    #[test]
    fn instruction_fetch_borrows_exact_lease_and_detects_revision_changes() {
        let (kernel, root) = bootstrap(31_151);
        let (child, backend, _, _, _) = cow_fixture(&kernel, &root, 31_152, MockCowFault::None);
        backend.set_access(super::super::VmaAccess {
            readable: false,
            writable: false,
            executable: true,
            kernel_visible: true,
        });
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        child.shared().mm().install_foreign_mm_endpoint_for_test(
            carrick_hal::ForeignMmEndpoint::for_carrier(Arc::new(MockForeignTransport {
                calls: Arc::clone(&calls),
                mode: MockReadMode::RetryOnce,
            })),
        );
        let execution = execution_lease(&child, 152);
        let wrong_execution = execution_lease(&root, 151);
        assert!(matches!(
            child.fetch_instruction_bytes(&wrong_execution, GuestVa(0x3000), 4),
            Err(MmAccessError::ExecutionAuthority(_))
        ));
        assert!(matches!(
            child.fetch_instruction_bytes(&execution, GuestVa(0x3ffe), 4),
            Err(MmAccessError::Unmapped {
                address: GuestVa(0x4000)
            })
        ));
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "rejections must precede backing read"
        );
        for domain in 0..3 {
            let read = child
                .fetch_instruction_bytes(&execution, GuestVa(0x3000), 4)
                .unwrap();
            assert_eq!(read.bytes(), b"root");
            read.validate_mapping().unwrap();
            assert!(matches!(
                read.validate_tracked_content(),
                Err(MmAccessError::UntrackedInstructionContent)
            ));
            backend.advance(domain);
            assert!(matches!(
                read.validate_mapping(),
                Err(MmAccessError::StaleInstructionRead)
            ));
        }
        assert_eq!(calls.load(Ordering::Acquire), 4);
        backend.set_access(super::super::VmaAccess {
            readable: true,
            writable: false,
            executable: false,
            kernel_visible: true,
        });
        assert!(matches!(
            child.fetch_instruction_bytes(&execution, GuestVa(0x3000), 4),
            Err(MmAccessError::ExecuteDenied { .. })
        ));
        assert_eq!(calls.load(Ordering::Acquire), 4);
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
        assert!(matches!(
            root.validate_current_execution_mm(&execution),
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
        assert!(matches!(
            root.validate_current_execution_mm(&execution),
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
        // MM ids are carrier-unique (`ObjectIdRegistry::mm_id`); the thread key still collides.
        assert_ne!(root.shared().mm().id(), other.shared().mm().id());
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
        assert!(matches!(
            root.validate_current_execution_mm(&foreign_execution),
            Err(MmAccessError::ExecutionAuthority(
                ThreadExecutionError::LeaseOwnerMismatch { .. }
            ))
        ));
    }

    #[test]
    fn execution_mm_validation_does_not_snapshot_mappings() {
        struct ObservedBackend {
            inner: Arc<dyn super::super::MmBackend>,
            snapshots: std::sync::atomic::AtomicU64,
        }
        impl super::super::MmBackend for ObservedBackend {
            fn snapshot(
                &self,
                deadline: Instant,
            ) -> Result<super::super::MmBackendSnapshot, SnapshotError> {
                self.snapshots.fetch_add(1, Ordering::Relaxed);
                self.inner.snapshot(deadline)
            }
            fn revision(&self) -> u64 {
                self.inner.revision()
            }
            fn vma_revision(
                &self,
                deadline: Instant,
            ) -> Result<Option<VmaRevision>, SnapshotError> {
                self.inner.vma_revision(deadline)
            }
        }
        let (kernel, root) = bootstrap(31_180);
        let backend = Arc::new(ObservedBackend {
            inner: fixture_backend(),
            snapshots: std::sync::atomic::AtomicU64::new(0),
        });
        let child = fork_with_backend(
            &kernel,
            &root,
            31_181,
            "execution identity",
            backend.clone(),
        );
        let execution = execution_lease(&child, 180);
        let before = backend.snapshots.load(Ordering::Relaxed);
        for scale in [1, 8, 32, 128] {
            for _ in 0..scale {
                assert_eq!(
                    child.validate_current_execution_mm(&execution).unwrap(),
                    child.shared().mm().id()
                );
            }
            assert_eq!(backend.snapshots.load(Ordering::Relaxed), before);
        }
        child.current_mm(&execution).unwrap();
        assert!(backend.snapshots.load(Ordering::Relaxed) > before);
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
        // MM ids are carrier-unique (`ObjectIdRegistry::mm_id`); the thread key still collides.
        assert_ne!(root.shared().mm().id(), other.shared().mm().id());
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
