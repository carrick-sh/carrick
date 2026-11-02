//! The exact refusing check of a native process entry admission (#1100).
//!
//! Admission authenticates through about seventy checks that all answered
//! one `NativeProcessError::Stale`, so a fatal could not say which one
//! refused. [`AdmissionRefusal`] keeps the error and names the check; the
//! fatal transport carries it as a typed [`carrick_el1_abi::FatalAttribution`].
//! Diagnostics only: every refusal still refuses with the same error.
//!
//! Entry functions keep returning `NativeProcessError`: the refusal is
//! recorded in its vCPU slot's [`RefusalCell`] where it leaves admission, and
//! the fatal site reads it back for the error it was handed. Carrying the
//! wider refusal through `with_process_entry` itself grew the frame the
//! native backing reply chain sums past its EL1 stack budget.
use super::native_process_runtime::NativeProcessError;
pub use carrick_el1_abi::{AdmissionCheck, AdmissionError, AdmissionPath, MemberIdentity};
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::Claim;
use core::sync::atomic::{AtomicU64, Ordering};

/// A refused admission: the error it always returned, plus the check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct AdmissionRefusal {
    pub check: AdmissionCheck,
    pub error: NativeProcessError,
    /// The record claim word the refusing check read, when it read one.
    /// Kept encoded so the refusal stays small on admitting EL1 frames.
    pub claim: Option<u64>,
    /// The registry route taken before the refusal.
    pub path: AdmissionPath,
}

impl AdmissionRefusal {
    pub const fn stale(check: AdmissionCheck) -> Self {
        Self::new(check, NativeProcessError::Stale)
    }
    pub const fn new(check: AdmissionCheck, error: NativeProcessError) -> Self {
        Self {
            check,
            error,
            claim: None,
            path: AdmissionPath::Unrouted,
        }
    }
    /// `map_err` adapter naming the check a propagated error came from.
    pub fn at(check: AdmissionCheck) -> impl FnOnce(NativeProcessError) -> Self {
        move |error| Self::new(check, error)
    }
    /// Name the route on which the refusal happened (first route wins).
    pub const fn routed(mut self, path: AdmissionPath) -> Self {
        if matches!(self.path, AdmissionPath::Unrouted) {
            self.path = path;
        }
        self
    }
    /// Record the claim the refusing check itself observed.
    pub const fn observed(mut self, claim: Claim) -> Self {
        self.claim = Some(claim.encode());
        self
    }
}

impl From<AdmissionRefusal> for NativeProcessError {
    fn from(refusal: AdmissionRefusal) -> Self {
        refusal.error
    }
}

pub fn admission_error(error: NativeProcessError) -> AdmissionError {
    match error {
        NativeProcessError::Invalid => AdmissionError::Invalid,
        NativeProcessError::Stale => AdmissionError::Stale,
        NativeProcessError::Exhausted => AdmissionError::Exhausted,
        NativeProcessError::Fault => AdmissionError::Fault,
        NativeProcessError::OwnerWait(_) => AdmissionError::OwnerWait,
        NativeProcessError::ForkRefused(_) => AdmissionError::ForkRefused,
        NativeProcessError::Unsupported => AdmissionError::Unsupported,
        NativeProcessError::GroupExitCustody => AdmissionError::GroupExitCustody,
        NativeProcessError::Busy => AdmissionError::Busy,
        NativeProcessError::Quarantined => AdmissionError::Quarantined,
        NativeProcessError::NoChild => AdmissionError::NoChild,
    }
}

/// Assemble the typed attribution on the fatal path: the refusal, plus the
/// slot's record custody and the registry member read once more now.
#[inline(never)]
#[cold]
pub fn attribute<M: Clone>(
    refusal: AdmissionRefusal,
    zone: &carrick_sched_core::ZoneTables<carrick_sched_core::Aarch64ParkedContext>,
    slot: carrick_sched_core::SlotId,
    task: &carrick_el1_abi::CurrentTask,
    registry: &super::native_process_runtime::NativeProcessRegistry<
        '_,
        M,
        carrick_sched_core::Aarch64ParkedContext,
    >,
    live_root: u64,
) -> carrick_el1_abi::AdmissionAttribution {
    let binding = super::common_entry::execution_binding(task);
    let lane = zone.slot(slot);
    let record = lane.current().or_else(|| lane.host_record());
    let owned = record.map(|record| zone.record(record));
    let (member, member_generation) = registry.member_identity_of(binding);
    // The parked context's address and the group registered under it, read
    // again here rather than carried through every admitting frame.
    // SAFETY: the fatal path runs on the CPU that owns this slot's record.
    let context =
        record.and_then(|record| unsafe { zone.record(record).ctx_mut() }.address_context());
    let group = context
        .zip(task.lifecycle_refs())
        .zip(task.visible_pid())
        .and_then(|((context, (page, _)), pid)| registry.group_address(zone, context, page, pid));
    carrick_el1_abi::AdmissionAttribution {
        check: refusal.check,
        error: admission_error(refusal.error),
        member,
        member_generation,
        binding_generation: binding.generation.raw() as u32,
        record: record.map(|record| record.raw() as u16),
        claim: refusal
            .claim
            .map(Claim::decode)
            .or(owned.map(|record| record.claim())),
        claim_from_check: refusal.claim.is_some(),
        requested: owned.and_then(|record| record.requested_handback()),
        cancelled: owned.is_some_and(|record| record.is_cancelled()),
        unadopted_birth: owned.is_some_and(|record| record.is_unadopted_birth()),
        native_owner: owned.is_some_and(|record| record.has_native_execution_owner()),
        path: refusal.path,
        context: context.map(address_words),
        group: group.map(address_words),
        root_generation: task
            .root_generation()
            .map(|generation| generation.raw().get() as u32),
        live_root,
    }
}

fn address_words(address: AddressContext<RootGpa>) -> carrick_el1_abi::AddressWords {
    carrick_el1_abi::AddressWords {
        mm: address.mm.raw().get() as u32,
        generation: address.generation.raw().get() as u32,
        root: address.root.address().raw(),
    }
}

/// The last admission refusal on one vCPU slot. Single writer (the slot's
/// own CPU); read only by that CPU's fatal path. Grants nothing.
pub struct RefusalCell {
    word: AtomicU64,
    claim: AtomicU64,
}

const CLAIM_PRESENT: u64 = 1 << 32;

static REFUSALS: [RefusalCell; carrick_el1_abi::EL1_STACK_SLOTS as usize] = [const {
    RefusalCell {
        word: AtomicU64::new(0),
        claim: AtomicU64::new(0),
    }
};
    carrick_el1_abi::EL1_STACK_SLOTS as usize];

/// Record `refusal` for `slot` and hand back the error it always returned.
#[cold]
#[inline(never)]
pub fn leave_admission(
    slot: carrick_sched_core::SlotId,
    refusal: AdmissionRefusal,
) -> NativeProcessError {
    if let Some(cell) = REFUSALS.get(usize::from(slot.raw())) {
        cell.claim
            .store(refusal.claim.unwrap_or(0), Ordering::Relaxed);
        cell.word.store(
            (u64::from(refusal.check as u16) << 16)
                | (u64::from(refusal.path as u8) << 8)
                | admission_error(refusal.error) as u64
                | if refusal.claim.is_some() {
                    CLAIM_PRESENT
                } else {
                    0
                },
            Ordering::Release,
        );
    }
    refusal.error
}

/// The refusal `slot` last recorded, if it was refused with `error`.
pub fn recorded(slot: carrick_sched_core::SlotId, error: NativeProcessError) -> AdmissionRefusal {
    let Some(cell) = REFUSALS.get(usize::from(slot.raw())) else {
        return AdmissionRefusal::new(AdmissionCheck::Unrecorded, error);
    };
    let word = cell.word.load(Ordering::Acquire);
    let (Some(check), Some(path)) = (
        AdmissionCheck::from_raw((word >> 16) as u16),
        AdmissionPath::from_raw((word >> 8) as u8),
    ) else {
        return AdmissionRefusal::new(AdmissionCheck::Unrecorded, error);
    };
    if word & 0xff != admission_error(error) as u64 {
        return AdmissionRefusal::new(AdmissionCheck::Unrecorded, error);
    }
    AdmissionRefusal {
        check,
        error,
        claim: (word & CLAIM_PRESENT != 0).then(|| cell.claim.load(Ordering::Relaxed)),
        path,
    }
}

static CANCEL_TALLIES: [AtomicU64; carrick_el1_abi::EL1_STACK_SLOTS as usize] =
    [const { AtomicU64::new(0) }; carrick_el1_abi::EL1_STACK_SLOTS as usize];
const TALLY_PRESENT: u64 = 1 << 63;

/// Record the closing owner's `cancel_members` tally for its slot.
pub fn record_cancel_tally(slot: carrick_sched_core::SlotId, tally: carrick_el1_abi::CancelTally) {
    if let Some(cell) = CANCEL_TALLIES.get(usize::from(slot.raw())) {
        cell.store(tally.pack() | TALLY_PRESENT, Ordering::Release);
    }
}

/// The last tally `slot` recorded, for its retirement fatal.
pub fn cancel_tally(slot: carrick_sched_core::SlotId) -> Option<carrick_el1_abi::CancelTally> {
    let word = CANCEL_TALLIES
        .get(usize::from(slot.raw()))?
        .load(Ordering::Acquire);
    (word & TALLY_PRESENT != 0).then(|| carrick_el1_abi::CancelTally::unpack(word))
}

static RETIRE_DENIALS: [[AtomicU64; 2]; carrick_el1_abi::EL1_STACK_SLOTS as usize] =
    [const { [AtomicU64::new(0), AtomicU64::new(0)] }; carrick_el1_abi::EL1_STACK_SLOTS as usize];

/// Record the host's typed child-retire denial for the crossing worker.
pub fn record_retire_denial(worker: u64, denial: carrick_el1_abi::TerminalRetireRefusal) {
    if let Some(cell) = usize::try_from(worker)
        .ok()
        .and_then(|w| RETIRE_DENIALS.get(w))
    {
        let [arm, detail] = denial.words();
        cell[1].store(detail, Ordering::Relaxed);
        cell[0].store(arm | TALLY_PRESENT, Ordering::Release);
    }
}

/// The denial the worker's last refused child-retire crossing reported.
pub fn retire_denial(worker: u64) -> Option<carrick_el1_abi::TerminalRetireRefusal> {
    let cell = RETIRE_DENIALS.get(usize::try_from(worker).ok()?)?;
    let arm = cell[0].load(Ordering::Acquire);
    (arm & TALLY_PRESENT != 0).then(|| {
        carrick_el1_abi::TerminalRetireRefusal::from_words([
            arm & !TALLY_PRESENT,
            cell[1].load(Ordering::Relaxed),
        ])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_returns_its_last_refusal_only_for_the_same_error() {
        let slot = carrick_sched_core::SlotId::new(200);
        let claim = Claim::OnCpuRequested { slot, seq: 9 };
        let refusal = AdmissionRefusal::stale(AdmissionCheck::AuthHandoff)
            .observed(claim)
            .routed(AdmissionPath::Rehome);
        assert_eq!(leave_admission(slot, refusal), NativeProcessError::Stale);
        assert_eq!(recorded(slot, NativeProcessError::Stale), refusal);
        assert_eq!(
            recorded(slot, NativeProcessError::Busy).check,
            AdmissionCheck::Unrecorded
        );
    }
}
