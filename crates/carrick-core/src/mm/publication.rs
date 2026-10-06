//! Neutral host consumer for MMU publication v2 records.
//!
//! The guest plans and executes every descriptor edit and publishes one
//! [`MmPublication`] per settled edit. This consumer only authenticates each
//! record against the host's own physical ledger and then applies or releases
//! physical custody. It never plans, walks or undoes a descriptor and never
//! resolves the informational user span. Any mismatch quarantines: the host
//! has no authority to author a corrective edit.

use carrick_core_abi::{
    EditSequence, MmIncarnation, MmPublication, PublicationDecodeError, PublicationDrain,
    PublicationMm, PublicationOutcome, PublicationView,
};
use carrick_guest_arch::{EditBacking, FrameGpa, GuestLen, RootGpa};

/// Ledger facts for one live MM incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerMm {
    pub incarnation: MmIncarnation,
    pub root: RootGpa,
}

/// Ledger facts for the physical extent containing an output range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerExtent {
    pub owner: PublicationMm,
    pub owner_incarnation: MmIncarnation,
    pub backing: EditBacking,
}

/// Publication bookkeeping for one MM incarnation. The ledger stores it next
/// to the MM so it shares that incarnation's lifetime; only this module can
/// change it, so every ledger obeys the same sequencing and drain rules.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmPublicationState {
    last: Option<EditSequence>,
    local_pending: Option<EditSequence>,
}

impl MmPublicationState {
    pub const fn new() -> Self {
        Self {
            last: None,
            local_pending: None,
        }
    }
    pub const fn last_sequence(&self) -> Option<EditSequence> {
        self.last
    }
    /// Highest LocalOnly record with live stores not yet covered by a global
    /// drain. While set, the MM's frames may still be cached by remote CPUs.
    pub const fn unacknowledged_local(&self) -> Option<EditSequence> {
        self.local_pending
    }
}

/// A record that passed every ledger check. Only [`consume`] constructs it,
/// so a ledger can never apply or release an unauthenticated record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedPublication {
    view: PublicationView,
    output: Option<LedgerExtent>,
}

impl AuthenticatedPublication {
    pub const fn view(&self) -> &PublicationView {
        &self.view
    }
    /// The authenticated extent containing the output, when the kind names one.
    pub const fn output_extent(&self) -> Option<LedgerExtent> {
        self.output
    }
}

/// The host's physical ledger, as seen by the neutral consumer. Every lookup
/// is by physical address or exact identity; none takes a user VA.
pub trait PhysicalLedger {
    type Fault: Copy + core::fmt::Debug;

    /// Sticky quarantine: once set, no further record is consumed.
    fn is_quarantined(&self) -> bool;
    fn quarantine(&mut self, mm: Option<PublicationMm>);

    /// Live MM incarnation and root for `mm`, if the slot is live.
    fn mm(&self, mm: PublicationMm) -> Option<LedgerMm>;
    fn publication_state(&mut self, mm: PublicationMm) -> Option<&mut MmPublicationState>;

    /// The single extent wholly containing `[output, output + len)`.
    fn extent(&self, output: FrameGpa, len: GuestLen) -> Option<LedgerExtent>;

    /// Commit an Applied record: publish alias edges and inventory for the
    /// output and drop edges to `prior_output`. Must be all-or-nothing.
    fn apply(&mut self, record: &AuthenticatedPublication) -> Result<(), Self::Fault>;
    /// Release prepared custody named by a Refused or RolledBack record.
    fn release_prepared(&mut self, record: &AuthenticatedPublication) -> Result<(), Self::Fault>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineCause<F> {
    AlreadyQuarantined,
    Malformed(PublicationDecodeError),
    UnknownMm,
    StaleIncarnation,
    RootMismatch,
    SequenceRegression,
    UnbackedOutput,
    ForeignOutput,
    StaleOwnerGeneration,
    BackingMismatch,
    UnbackedPrior,
    Ledger(F),
}

/// The record at `index` failed; records before it were consumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Quarantine<F> {
    pub index: usize,
    pub mm: Option<PublicationMm>,
    pub cause: QuarantineCause<F>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConsumeReport {
    pub applied: usize,
    pub released: usize,
    /// Ledger lookups made by the consumer. Bounded by a constant per record,
    /// independent of the number of unrelated extents or MMs.
    pub ledger_visits: usize,
}

fn authenticate<L: PhysicalLedger>(
    ledger: &mut L,
    view: PublicationView,
    visits: &mut usize,
) -> Result<AuthenticatedPublication, QuarantineCause<L::Fault>> {
    *visits += 1;
    let live = ledger.mm(view.mm()).ok_or(QuarantineCause::UnknownMm)?;
    if live.incarnation != view.incarnation() {
        return Err(QuarantineCause::StaleIncarnation);
    }
    if live.root != view.root() {
        return Err(QuarantineCause::RootMismatch);
    }
    let state = ledger
        .publication_state(view.mm())
        .ok_or(QuarantineCause::UnknownMm)?;
    if state.last.is_some_and(|last| view.edit_sequence() <= last) {
        return Err(QuarantineCause::SequenceRegression);
    }
    let output = match (view.output(), view.backing()) {
        (Some(output), Some(backing)) => {
            *visits += 1;
            let extent = ledger
                .extent(output, view.output_len())
                .ok_or(QuarantineCause::UnbackedOutput)?;
            if extent.owner != view.mm() || extent.owner_incarnation != view.incarnation() {
                return Err(QuarantineCause::ForeignOutput);
            }
            if extent.backing.owner_generation != backing.owner_generation {
                return Err(QuarantineCause::StaleOwnerGeneration);
            }
            if extent.backing != backing {
                return Err(QuarantineCause::BackingMismatch);
            }
            Some(extent)
        }
        (None, None) => None,
        // `PublicationView::checked` already rejects a half-named output.
        _ => {
            return Err(QuarantineCause::Malformed(PublicationDecodeError::Backing));
        }
    };
    if let Some(prior) = view.prior_output()
        && view.outcome() == PublicationOutcome::Applied
    {
        *visits += 1;
        ledger
            .extent(prior, view.output_len())
            .ok_or(QuarantineCause::UnbackedPrior)?;
    }
    Ok(AuthenticatedPublication { view, output })
}

fn settle<L: PhysicalLedger>(
    ledger: &mut L,
    record: &AuthenticatedPublication,
    report: &mut ConsumeReport,
) -> Result<(), QuarantineCause<L::Fault>> {
    let view = record.view;
    match view.outcome() {
        PublicationOutcome::Applied => {
            ledger.apply(record).map_err(QuarantineCause::Ledger)?;
            report.applied += 1;
        }
        PublicationOutcome::Refused | PublicationOutcome::RolledBack => {
            if record.output.is_some() {
                ledger
                    .release_prepared(record)
                    .map_err(QuarantineCause::Ledger)?;
                report.released += 1;
            }
        }
    }
    let state = ledger
        .publication_state(view.mm())
        .ok_or(QuarantineCause::UnknownMm)?;
    state.last = Some(view.edit_sequence());
    // A refused edit made no store, so its drain scope changes nothing.
    if view.outcome() != PublicationOutcome::Refused {
        match view.drain() {
            PublicationDrain::LocalOnly => state.local_pending = Some(view.edit_sequence()),
            PublicationDrain::Global => state.local_pending = None,
        }
    }
    Ok(())
}

/// Authenticate and settle `records` in order. Stops at the first mismatch,
/// quarantines the ledger and reports the failing index.
pub fn consume<L, I>(ledger: &mut L, records: I) -> Result<ConsumeReport, Quarantine<L::Fault>>
where
    L: PhysicalLedger,
    I: IntoIterator<Item = MmPublication>,
{
    let mut report = ConsumeReport::default();
    for (index, record) in records.into_iter().enumerate() {
        if ledger.is_quarantined() {
            return Err(Quarantine {
                index,
                mm: None,
                cause: QuarantineCause::AlreadyQuarantined,
            });
        }
        let view = match record.decode() {
            Ok(view) => view,
            Err(reason) => {
                ledger.quarantine(None);
                return Err(Quarantine {
                    index,
                    mm: None,
                    cause: QuarantineCause::Malformed(reason),
                });
            }
        };
        let outcome = authenticate(ledger, view, &mut report.ledger_visits)
            .and_then(|record| settle(ledger, &record, &mut report));
        if let Err(cause) = outcome {
            ledger.quarantine(Some(view.mm()));
            return Err(Quarantine {
                index,
                mm: Some(view.mm()),
                cause,
            });
        }
    }
    Ok(report)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainAckError {
    UnknownMm,
    /// The acknowledgement predates the newest LocalOnly record.
    StaleAcknowledgement,
}

/// Record a completed global drain over `mm` covering every edit through
/// `through`. A drain that predates the newest LocalOnly record does not
/// acknowledge it.
pub fn acknowledge_global_drain<L: PhysicalLedger>(
    ledger: &mut L,
    mm: PublicationMm,
    through: EditSequence,
) -> Result<(), DrainAckError> {
    let state = ledger
        .publication_state(mm)
        .ok_or(DrainAckError::UnknownMm)?;
    match state.local_pending {
        Some(pending) if through < pending => Err(DrainAckError::StaleAcknowledgement),
        _ => {
            state.local_pending = None;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementBlocked {
    UnknownMm,
    Quarantined,
    /// A LocalOnly record is not yet covered by a global drain.
    LocalDrainPending(EditSequence),
}

/// Gate for MM retirement and capacity return: a remote CPU may still cache a
/// translation to this MM's frames until a global drain acknowledges every
/// LocalOnly publication.
pub fn retirement_permitted<L: PhysicalLedger>(
    ledger: &mut L,
    mm: PublicationMm,
) -> Result<(), RetirementBlocked> {
    if ledger.is_quarantined() {
        return Err(RetirementBlocked::Quarantined);
    }
    let state = ledger
        .publication_state(mm)
        .ok_or(RetirementBlocked::UnknownMm)?;
    match state.local_pending {
        Some(pending) => Err(RetirementBlocked::LocalDrainPending(pending)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
