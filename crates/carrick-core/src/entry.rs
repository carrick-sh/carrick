//! Neutral one-owner entry completion.
use carrick_core_abi::{
    BornEntryCompletion, BornInZoneSource, EntryCompletion, EntryContext, EntryMmKey,
    EntryRecordBinding, EntryRecordGeneration, EntryRecordIncarnation, EntryTaskKey,
    EntryThreadGeneration, ExecutionBinding, ExecutionIdentity, ExecutionMm, SnapshotGeneration,
};
use core::sync::atomic::Ordering;

/// Acquire the exact loaded execution/MM binding, retaining the pre-move
/// generation recheck. Host/native writers publish while the executor is stopped.
pub fn binding(identity: &ExecutionIdentity, mm: &ExecutionMm) -> ExecutionBinding {
    let generation = identity.generation.load(Ordering::Acquire);
    let captured = ExecutionBinding {
        task: EntryTaskKey::from_raw(identity.task.load(Ordering::Acquire)),
        generation,
        mm: EntryMmKey::from_raw(mm.key.load(Ordering::Acquire)),
        thread_generation: EntryThreadGeneration::from_raw(
            mm.thread_generation.load(Ordering::Acquire),
        ),
    };
    if identity.generation.load(Ordering::Acquire) == generation {
        captured
    } else {
        ExecutionBinding {
            task: EntryTaskKey::from_raw(0),
            generation: SnapshotGeneration::UNISSUED,
            mm: EntryMmKey::from_raw(0),
            thread_generation: EntryThreadGeneration::from_raw(0),
        }
    }
}

pub fn admit<C: EntryContext>(
    binding: ExecutionBinding,
    source: Option<BornInZoneSource<'_, C>>,
) -> Option<EntryCompletion<'_, C>> {
    if !binding.issued() {
        return None;
    }
    let scope = match source {
        Some(source) => Some(execution_scope(binding, source)?),
        None => None,
    };
    // SAFETY: the source lifetime and optional exact record scope are retained;
    // the task/execution generation are issued; the owned token keeps
    // every captured MM/thread word until complete consumes it exactly once.
    Some(unsafe {
        EntryCompletion::from_admitted_binding(binding, scope, source.map(|source| source.zone))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionError {
    WrongGeneration,
}

/// Consume the sole completion authority after authenticating the same exact
/// execution binding that was admitted.
pub fn complete<C: EntryContext>(
    completion: EntryCompletion<'_, C>,
    current: ExecutionBinding,
    source: Option<BornInZoneSource<'_, C>>,
) -> Result<(), CompletionError> {
    let scope = match source {
        Some(source) => {
            Some(execution_scope(current, source).ok_or(CompletionError::WrongGeneration)?)
        }
        None => None,
    };
    if completion.binding() == current && completion.scope() == scope {
        Ok(())
    } else {
        Err(CompletionError::WrongGeneration)
    }
}

#[derive(Clone, Copy)]
enum RecordPhase {
    Admission,
    Completion,
}
fn current_born_record<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    phase: RecordPhase,
) -> Option<EntryRecordBinding<C>> {
    if binding.generation.raw() != 0
        || binding.task.raw() == 0
        || binding.mm.raw() == 0
        || binding.thread_generation.raw() == 0
    {
        return None;
    }
    let record = source.zone.slot(source.slot).current()?;
    let owned = source.zone.record(record);
    if !owned.is_unadopted_birth() {
        return None;
    }
    let generation = match owned.claim() {
        carrick_sched_core::Claim::OnCpu { slot, seq } if slot == source.slot => seq,
        carrick_sched_core::Claim::OnCpuRequested { slot, seq }
            if slot == source.slot && matches!(phase, RecordPhase::Completion) =>
        {
            seq
        }
        _ => return None,
    };
    let id = owned.identity();
    if id.tid != binding.task.raw()
        || id.generation != binding.generation.raw()
        || id.mm != binding.mm.raw()
        || id.serial != binding.thread_generation.raw()
        || source.zone.installed_space(source.slot) != id.mm
    {
        return None;
    }
    Some(EntryRecordBinding {
        owner: core::ptr::NonNull::from(source.zone),
        slot: source.slot,
        record,
        generation: EntryRecordGeneration(generation),
        incarnation: EntryRecordIncarnation(owned.incarnation()),
    })
}

/// Authenticate an in-zone execution independently of host adoption. A zero
/// host generation is valid only with the exact live OnCpu record authority.
/// The token retains its scheduler region's lifetime:
/// ```compile_fail
/// use carrick_core::entry::admit_born_in_zone;
/// use carrick_core_abi::{BornEntryCompletion, BornInZoneSource, ExecutionBinding};
/// fn escape<C: carrick_core_abi::EntryContext>(binding: ExecutionBinding, source: BornInZoneSource<'_, C>) -> Option<BornEntryCompletion<'static, C>> {
///     admit_born_in_zone(binding, source)
/// }
/// ```
pub fn admit_born_in_zone<'a, C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'a, C>,
) -> Option<BornEntryCompletion<'a, C>> {
    let record = current_born_record(binding, source, RecordPhase::Admission)?;
    // SAFETY: current_born_record authenticated an unadopted OnCpu record's
    // owner/slot/claim/incarnation, installed MM and every loaded identity word.
    Some(unsafe { BornEntryCompletion::from_admitted_record(binding, record, source.zone) })
}

pub fn complete_born_in_zone<C: EntryContext>(
    completion: BornEntryCompletion<'_, C>,
    current: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
) -> Result<(), CompletionError> {
    if completion.binding() == current
        && Some(completion.record())
            == current_born_record(current, source, RecordPhase::Completion)
    {
        Ok(())
    } else {
        Err(CompletionError::WrongGeneration)
    }
}

/// Consume ordinary entry authority against its actual owned transition.
pub fn handoff<C: EntryContext>(
    completion: EntryCompletion<'_, C>,
    receipt: carrick_core_abi::EntryHandoffReceipt<C>,
) -> Result<(), CompletionError> {
    if completion.binding() != receipt.binding() {
        return Err(CompletionError::WrongGeneration);
    }
    let Some(scope) = completion.scope() else {
        return Err(CompletionError::WrongGeneration);
    };
    let record = receipt.record();
    if scope.owner == record.owner
        && scope.slot == record.slot
        && scope
            .record
            .map_or(record.generation.0 == 0, |expected| expected == record)
    {
        Ok(())
    } else {
        Err(CompletionError::WrongGeneration)
    }
}

/// Born handoff retains the exact initiating owner/slot/claim/incarnation,
/// even though publication has already transferred or retired the record.
pub fn handoff_born_in_zone<C: EntryContext>(
    completion: BornEntryCompletion<'_, C>,
    receipt: carrick_core_abi::EntryHandoffReceipt<C>,
) -> Result<(), CompletionError> {
    if completion.binding() == receipt.binding() && completion.record() == receipt.record() {
        Ok(())
    } else {
        Err(CompletionError::WrongGeneration)
    }
}

/// Authenticated prepublication custody. Only a successful existing wait or
/// retirement authority can turn this into a handoff receipt.
pub struct HandoffStart<'a, C: EntryContext = carrick_sched_core::ThreadCtx> {
    source: BornInZoneSource<'a, C>,
    binding: ExecutionBinding,
    record: EntryRecordBinding<C>,
}
fn execution_scope<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
) -> Option<carrick_core_abi::EntryExecutionScope<C>> {
    let record = match source.zone.slot(source.slot).current() {
        Some(record) => Some(record_binding(binding, source, record)?),
        None => None,
    };
    Some(carrick_core_abi::EntryExecutionScope {
        owner: core::ptr::NonNull::from(source.zone),
        slot: source.slot,
        record,
    })
}
fn record_binding<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    record: carrick_sched_core::RecordId,
) -> Option<EntryRecordBinding<C>> {
    let owned = source.zone.record(record);
    let identity = owned.identity();
    if identity.tid != binding.task.raw()
        || identity.generation != binding.generation.raw()
        || identity.mm != binding.mm.raw()
        || identity.serial != binding.thread_generation.raw()
        || source.zone.installed_space(source.slot) != identity.mm
    {
        return None;
    }
    let generation = match owned.claim() {
        carrick_sched_core::Claim::OnCpu { slot, seq }
        | carrick_sched_core::Claim::OnCpuRequested { slot, seq }
            if slot == source.slot && source.zone.slot(slot).current() == Some(record) =>
        {
            seq
        }
        carrick_sched_core::Claim::Free
            if source.zone.slot(source.slot).current().is_none()
                && source.zone.slot(source.slot).host_record() == Some(record) =>
        {
            0
        }
        _ => return None,
    };
    Some(EntryRecordBinding {
        owner: core::ptr::NonNull::from(source.zone),
        slot: source.slot,
        record,
        generation: EntryRecordGeneration(generation),
        incarnation: EntryRecordIncarnation(owned.incarnation()),
    })
}
pub fn prepare_handoff<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    record: carrick_sched_core::RecordId,
) -> Option<HandoffStart<'_, C>> {
    Some(HandoffStart {
        source,
        binding,
        record: record_binding(binding, source, record)?,
    })
}
pub type RecordReleaseHook = fn(usize, carrick_sched_core::SlotId, carrick_sched_core::RecordRef);

static RECORD_RELEASE_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Install the notification hook invoked after an `OnCpu` or home record is
/// released from its slot (parked, yielded, or retired).
pub fn set_record_release_hook(hook: RecordReleaseHook) {
    RECORD_RELEASE_HOOK.store(
        hook as *const () as usize,
        core::sync::atomic::Ordering::Release,
    );
}

impl<C: EntryContext> HandoffStart<'_, C> {
    fn published_yield(self, published: bool) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
        published.then(|| self.published())
    }

    pub(crate) fn published(self) -> carrick_core_abi::EntryHandoffReceipt<C> {
        let raw = RECORD_RELEASE_HOOK.load(core::sync::atomic::Ordering::Acquire);
        if raw != 0 {
            // SAFETY: `set_record_release_hook` only stores valid `RecordReleaseHook` function pointers.
            let hook = unsafe { core::mem::transmute::<usize, RecordReleaseHook>(raw) };
            hook(
                core::ptr::from_ref(self.source.zone).addr(),
                self.source.slot,
                carrick_sched_core::RecordRef {
                    id: self.record.record,
                    incarnation: self.record.incarnation.0,
                },
            );
        }
        // SAFETY: callers invoke this only after their existing exact-record
        // publication succeeds, using the captured prepublication custody.
        unsafe {
            carrick_core_abi::EntryHandoffReceipt::<C>::from_published_transition(
                self.binding,
                self.record,
            )
        }
    }
}

/// Publish under the existing futex guard, without reading the record after
/// its successful CAS transfers ownership to a waker/cancellation authority.
pub fn publish_handoff_park<C: EntryContext>(
    start: HandoffStart<'_, C>,
    guard: &carrick_sched_core::BucketGuard<'_, C>,
    sequence: EntryRecordGeneration,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    publish_handoff_park_with(start, guard, sequence, ParkCustody::Interruptible)
}

enum ParkCustody {
    Interruptible,
    Terminal,
}

/// Terminal custody cannot return an interrupted park to its syscall caller.
/// A pending host request instead receives the retained owner continuation.
pub(crate) fn publish_terminal_park<C: EntryContext>(
    start: HandoffStart<'_, C>,
    guard: &carrick_sched_core::BucketGuard<'_, C>,
    sequence: EntryRecordGeneration,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    publish_handoff_park_with(start, guard, sequence, ParkCustody::Terminal)
}

fn publish_handoff_park_with<C: EntryContext>(
    start: HandoffStart<'_, C>,
    guard: &carrick_sched_core::BucketGuard<'_, C>,
    sequence: EntryRecordGeneration,
    custody: ParkCustody,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    if !core::ptr::eq(start.source.zone, guard.zone())
        || record_binding(start.binding, start.source, start.record.record) != Some(start.record)
        || sequence.0 != start.source.zone.next_seq(start.record.record)
    {
        return None;
    }
    let zone = start.source.zone;
    let record = start.record.record;
    if !zone.publish_guest_park(guard, start.source.slot, record, sequence.0) {
        // Failed publication undid enrollment and retained the running owner.
        // Only this exact host-request transition licenses a terminal handback;
        // no missing, stale, foreign-slot or cancelled record is accepted.
        if !matches!(custody, ParkCustody::Terminal)
            || zone.record(record).is_cancelled()
            || !matches!(
                zone.record(record).resume_disposition(),
                carrick_sched_core::object_wait::ResumeDisposition::OwnerContinuation(_)
            )
            || !matches!(zone.record(record).claim(),
                carrick_sched_core::Claim::OnCpuRequested { slot, .. }
                    if slot == start.source.slot)
            || record_binding(start.binding, start.source, record) != Some(start.record)
            || !zone.unswitch(start.source.slot, record)
        {
            return None;
        }
    }
    Some(start.published())
}

/// Publish a yield handoff only after the running record has left the CPU
/// for the run queue. The initiating entry's receipt still names its exact
/// pre-switch record and binding, even though the live frame names a sibling.
pub fn publish_handoff_yield<C: EntryContext>(
    start: HandoffStart<'_, C>,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    let zone = start.source.zone;
    let slot = start.source.slot;
    if zone.slot(slot).current() == Some(start.record.record)
        || !matches!(zone.record(start.record.record).claim(),
            carrick_sched_core::Claim::Queued { slot: owner, .. } if owner == slot)
    {
        return None;
    }
    Some(start.published())
}

/// Yield a consumed native continuation to its host execution owner. The
/// selected record stays queued for host service, with the exact handoff
/// receipt retained by the caller; it must not return to user execution.
pub fn yield_current_to_host<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    record: carrick_sched_core::RecordId,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    let start = prepare_handoff(binding, source, record)?;
    let retained = source.zone.record(record);
    if retained.has_object_operation()
        || retained.resume_disposition()
            != carrick_sched_core::object_wait::ResumeDisposition::UserReturn
    {
        return None;
    }
    if !matches!(
        source.zone.claim_for_host(
            source.zone.record_ref(record),
            None,
            carrick_sched_core::Handback::Control,
            &carrick_sched_core::ShortLockSpin,
        ),
        carrick_sched_core::HostClaim::El1Held { slot } if slot == source.slot
    ) {
        return None;
    }
    // The successful transition proves publication even if the host claims
    // the row immediately after the queue lock is released. Do not reread
    // its now independently owned custody to decide whether we handed off.
    start.published_yield(source.zone.unswitch(source.slot, record))
}

/// Authenticate and retire the current record through its existing owner.
pub fn retire_current<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    record: carrick_sched_core::RecordId,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    retire_current_with(binding, source, record, || true)
}

/// The terminal owner commits provenance at the scheduler's release seam.
pub(crate) fn retire_current_with<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    record: carrick_sched_core::RecordId,
    finish: impl carrick_sched_core::RecordRelease,
) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
    let start = prepare_handoff(binding, source, record)?;
    let identity = source.zone.record(record).identity();
    let released = if source.zone.slot(source.slot).current().is_none() {
        source
            .zone
            .release_host_home_with(source.slot, record, finish)
    } else {
        source.zone.release_current_with(
            source.slot,
            record,
            &carrick_sched_core::ShortLockSpin,
            finish,
        )? == carrick_sched_core::CurrentRelease::Released
    };
    if !released {
        return None;
    }
    source.zone.publish_terminal(source.slot, identity);
    Some(start.published())
}

/// Terminal authentication uses retained execution custody, never a freed
/// record's identity or a carrier executor's unrelated loaded task.
pub fn terminal_matches<C: EntryContext>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_, C>,
    phase: carrick_sched_core::TerminalPhase,
) -> bool {
    source.zone.terminal_matches(
        source.slot,
        carrick_sched_core::ThreadIdentity {
            tid: binding.task.raw(),
            generation: binding.generation.raw(),
            mm: binding.mm.raw(),
            serial: binding.thread_generation.raw(),
            ..Default::default()
        },
        phase,
    )
}

/// A compact-context receipt cannot authorize a second entry turn.
/// ```compile_fail
/// use carrick_core::entry::handoff_born_in_zone;
/// use carrick_core_abi::{BornEntryCompletion, EntryHandoffReceipt};
/// use carrick_sched_core::ParkedContextWords;
/// fn replay(first: BornEntryCompletion<'_, ParkedContextWords>,
///           second: BornEntryCompletion<'_, ParkedContextWords>,
///           receipt: EntryHandoffReceipt<ParkedContextWords>) {
///     let _ = handoff_born_in_zone(first, receipt);
///     let _ = handoff_born_in_zone(second, receipt);
/// }
/// ```
///
/// A transferred token cannot subsequently complete the same call.
/// ```compile_fail
/// use carrick_core::entry::{admit, complete, handoff};
/// use carrick_core_abi::{ExecutionBinding, EntryHandoffReceipt};
/// fn park(binding: ExecutionBinding, receipt: EntryHandoffReceipt) {
///     if let Some(token) = admit::<carrick_sched_core::ThreadCtx>(binding, None) {
///         let _ = handoff(token, receipt);
///         let _ = complete(token, binding, None);
///     }
/// }
/// ```
const _: () = ();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_claim_after_yield_does_not_revoke_publication_receipt() {
        use carrick_sched_core::{
            Handback, HostClaim, ShortLockSpin, SlotId, ThreadIdentity, ZoneTables,
        };
        let layout = std::alloc::Layout::new::<ZoneTables>();
        // SAFETY: zero is the valid initial zone state; the Box owns the allocation.
        let zone = unsafe {
            let pointer = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!pointer.is_null());
            std::boxed::Box::from_raw(pointer)
        };
        let slot = SlotId::new(0);
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(7),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(13),
            thread_generation: EntryThreadGeneration::from_raw(17),
        };
        zone.drive(slot, 1);
        zone.publish_slot(slot, 0, Some(0), 0);
        zone.enter_guest(slot);
        let space = zone.spaces.publish_closed(13, 0x1000, 0x1000).unwrap();
        zone.spaces.open(space);
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 7,
                serial: 17,
                mm: 13,
                generation: 11,
                file_table: 0,
                affinity: 0,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        assert!(zone.mark_native_owned(record));
        zone.requeue_preempted(slot, record);
        assert_eq!(zone.switch_in(slot), Some(record));
        assert!(zone.install_space(slot, 13).is_some());
        let source = BornInZoneSource { zone: &zone, slot };
        let start = prepare_handoff(binding, source, record).unwrap();
        let reference = zone.record_ref(record);
        assert!(matches!(
            zone.claim_for_host(reference, None, Handback::Control, &ShortLockSpin),
            HostClaim::El1Held { .. }
        ));
        let published = zone.unswitch(slot, record);
        // Deterministically interleave the host claimant before receipt completion.
        assert!(matches!(
            zone.claim_for_host(reference, None, Handback::Control, &ShortLockSpin),
            HostClaim::Claimed
        ));
        assert!(start.published_yield(published).is_some());
    }

    #[test]
    fn wrong_generation_cannot_complete_admitted_entry() {
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(7),
            generation: SnapshotGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(13),
            thread_generation: EntryThreadGeneration::from_raw(17),
        };
        let completion = admit::<carrick_sched_core::ThreadCtx>(binding, None).unwrap();
        assert_eq!(complete(completion, binding, None), Ok(()));
        let completion = admit::<carrick_sched_core::ThreadCtx>(binding, None).unwrap();
        assert_eq!(
            complete(
                completion,
                ExecutionBinding {
                    generation: SnapshotGeneration::from_raw(12),
                    ..binding
                },
                None,
            ),
            Err(CompletionError::WrongGeneration)
        );
    }
}
