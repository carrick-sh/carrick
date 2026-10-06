//! Neutral one-owner entry completion.
use carrick_core_abi::{
    BornEntryCompletion, BornInZoneSource, EntryCompletion, EntryGeneration, EntryMmKey,
    EntryRecordBinding, EntryRecordGeneration, EntryRecordIncarnation, EntryTaskKey,
    EntryThreadGeneration, ExecutionBinding, ExecutionIdentity, ExecutionMm,
};
use core::sync::atomic::Ordering;

/// Acquire the exact loaded execution/MM binding, retaining the pre-move
/// generation recheck. Host/native writers publish while the executor is stopped.
pub fn binding(identity: &ExecutionIdentity, mm: &ExecutionMm) -> ExecutionBinding {
    let generation = identity.generation.load(Ordering::Acquire);
    let captured = ExecutionBinding {
        task: EntryTaskKey::from_raw(identity.task.load(Ordering::Acquire)),
        generation: EntryGeneration::from_raw(generation),
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
            generation: EntryGeneration::from_raw(0),
            mm: EntryMmKey::from_raw(0),
            thread_generation: EntryThreadGeneration::from_raw(0),
        }
    }
}

pub fn admit(binding: ExecutionBinding) -> Option<EntryCompletion> {
    if !binding.issued() {
        return None;
    }
    // SAFETY: the task/execution generation are issued; the owned token keeps
    // every captured MM/thread word until complete consumes it exactly once.
    Some(unsafe { EntryCompletion::from_admitted_binding(binding) })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionError {
    WrongGeneration,
}

/// Consume the sole completion authority after authenticating the same exact
/// execution binding that was admitted.
pub fn complete(
    completion: EntryCompletion,
    current: ExecutionBinding,
) -> Result<(), CompletionError> {
    if completion.binding() == current {
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
fn current_born_record(
    binding: ExecutionBinding,
    source: BornInZoneSource<'_>,
    phase: RecordPhase,
) -> Option<EntryRecordBinding> {
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
/// fn escape(binding: ExecutionBinding, source: BornInZoneSource<'_>) -> Option<BornEntryCompletion<'static>> {
///     admit_born_in_zone(binding, source)
/// }
/// ```
pub fn admit_born_in_zone<'a>(
    binding: ExecutionBinding,
    source: BornInZoneSource<'a>,
) -> Option<BornEntryCompletion<'a>> {
    let record = current_born_record(binding, source, RecordPhase::Admission)?;
    // SAFETY: current_born_record authenticated an unadopted OnCpu record's
    // owner/slot/claim/incarnation, installed MM and every loaded identity word.
    Some(unsafe { BornEntryCompletion::from_admitted_record(binding, record, source.zone) })
}

pub fn complete_born_in_zone(
    completion: BornEntryCompletion<'_>,
    current: ExecutionBinding,
    source: BornInZoneSource<'_>,
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

/// The exact scheduler record retains the operation; no host completion token
/// can be fabricated or recovered from this consuming handoff.
pub fn handoff_born_in_zone(completion: BornEntryCompletion<'_>) {
    let _ = completion;
}

/// End an entry turn whose operation is owned by the already-published exact
/// wait/scheduler record. This consumes the entry token without completing the
/// syscall, writing a result, or creating another continuation ledger.
///
/// An ordinary completion cannot reuse the transferred token:
/// ```compile_fail
/// use carrick_core::entry::{admit, complete, handoff};
/// use carrick_core_abi::ExecutionBinding;
/// fn park(binding: ExecutionBinding) {
///     if let Some(token) = admit(binding) {
///         handoff(token);
///         let _ = complete(token, binding);
///     }
/// }
/// ```
pub fn handoff(completion: EntryCompletion) {
    let _ = completion;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_generation_cannot_complete_admitted_entry() {
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(7),
            generation: EntryGeneration::from_raw(11),
            mm: EntryMmKey::from_raw(13),
            thread_generation: EntryThreadGeneration::from_raw(17),
        };
        let completion = admit(binding).unwrap();
        assert_eq!(complete(completion, binding), Ok(()));
        let completion = admit(binding).unwrap();
        assert_eq!(
            complete(
                completion,
                ExecutionBinding {
                    generation: EntryGeneration::from_raw(12),
                    ..binding
                }
            ),
            Err(CompletionError::WrongGeneration)
        );
    }
}
