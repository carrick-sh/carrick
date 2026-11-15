//! The one owner of a carrier's native exec preparations (#2305).
//!
//! Every carrier that serves the ring's exec ticket, the HVF carrier and the
//! x86 CPL0 host, keeps its preparations in one [`ExecPreparations`]. The
//! receipt allocator, the row states, the fork-stock park, the retirement
//! report and the settlement route exist here once. A carrier keeps only its
//! own mechanics in the row's type parameters: `D`, the staged successor (an
//! ISA's tables and frames); `P`, the transport continuation a parked row
//! resumes with; and `A`, a typed attachment the row carries from claim to
//! adoption (#2142's root exec instantiates it with its loader image).
//!
//! One row, keyed by the receipt reserved when the ring's ticket is claimed:
//!
//! ```text
//! claim ──► Claimed ──► Staged ──► Sealed ──► adopt ──► settling ──► settle
//!             │   ▲                  │
//!       park  ▼   │ rerun            └──► cancel
//!            Parked ──► park-cancel
//! ```
//!
//! A carrier refuses a Claimed or Staged row (a loader errno, a stock
//! ENOMEM, a publication the ring had already cancelled) with
//! [`ExecPreparations::retire`]. Every retirement returns an
//! [`ExecRetirement`] report and is counted in the [`ExecOwnerCensus`], so a
//! reserved receipt is always accounted for, and is never reused.
//!
//! The ring learns a receipt only from the sealed manifest; reserving it at
//! claim changes nothing the ring sees, but gives a parked or unsealed row
//! its name before the seal.
use crate::fork_stock::{
    ChildAddressTags, ForkStock, GrantExecution, StockRelease, StockReleaseWake,
};
use carrick_core_abi::service::{ExecAdoptionReceipt, ServiceIdentity, ServiceOrigin};
use carrick_el1_abi::{ExecCommitEffects, ReservationMm};
use core::num::NonZeroU64;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// What a carrier's exec owner did, for run reports and witnesses: every
/// receipt it reserved is accounted for by one retirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecOwnerCensus {
    /// Receipts reserved at claim.
    pub reserved: u64,
    /// Rows parked on the fork stock's release.
    pub parked: u64,
    /// Parked rows handed back to rerun after their release.
    pub reruns: u64,
    /// Rows whose manifest was sealed with the receipt reserved at claim.
    pub sealed: u64,
    /// Sealed rows the ring adopted.
    pub adopted: u64,
    /// Sealed rows the ring cancelled.
    pub cancelled: u64,
    /// Rows refused before the seal (a loader errno, a stock ENOMEM).
    pub refused: u64,
    /// Parked rows the ring cancelled before they reran.
    pub park_cancelled: u64,
    /// Sealed rows whose publication the ring had already cancelled.
    pub publish_cancelled: u64,
    /// Adopted execs settled on the lane that serves their origin.
    pub settled: u64,
    /// Settlements handed back, unchanged, from a lane that cannot serve them.
    pub handed_back: u64,
    /// Signal-reset obligations discharged from the ring's commit effects.
    pub signal_resets_discharged: u64,
    /// Settlements refused for an incomplete commit-effects word.
    pub short_effects: u64,
}

impl ExecOwnerCensus {
    /// Rows retired for any reason.
    pub const fn retired(&self) -> u64 {
        self.adopted + self.cancelled + self.refused + self.park_cancelled + self.publish_cancelled
    }
}

/// The ring's exec request as the owner recorded it at claim: the receipt
/// reserved for it, the authenticated service identity (whose birth carries
/// the [`ServiceOrigin`]), and the successor MM the ring issued for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecClaim {
    receipt: ExecAdoptionReceipt,
    identity: ServiceIdentity,
    successor: ReservationMm,
    root_generation: NonZeroU64,
}

impl ExecClaim {
    pub const fn receipt(&self) -> ExecAdoptionReceipt {
        self.receipt
    }

    pub const fn identity(&self) -> ServiceIdentity {
        self.identity
    }

    /// The authenticated lineage the ring selected: the root or a descendant.
    pub const fn origin(&self) -> ServiceOrigin {
        self.identity.birth.origin
    }

    /// The successor MM the ring issued and proposed for this exec.
    pub const fn successor(&self) -> ReservationMm {
        self.successor
    }

    pub const fn root_generation(&self) -> NonZeroU64 {
        self.root_generation
    }

    /// The claim was made for `execution`'s exact MM incarnation on
    /// `carrier`: what a cancellation must name.
    pub fn predecessor_is(&self, carrier: NonZeroU64, execution: GrantExecution) -> bool {
        let mm = self.identity.birth.mm;
        mm.carrier() == carrier
            && mm.mm().raw() == execution.binding.mm.raw()
            && mm.incarnation().get() == execution.context.generation.raw().get()
    }

    /// [`Self::predecessor_is`], and the claim names `execution`'s exact
    /// task, thread and execution generation: what an adoption must name.
    pub fn names_execution(&self, carrier: NonZeroU64, execution: GrantExecution) -> bool {
        let birth = self.identity.birth;
        self.predecessor_is(carrier, execution)
            && birth.process.id.raw() as u64 == execution.binding.task.raw()
            && self.identity.execution == execution.binding.generation
            && birth.thread == execution.binding.thread_generation
    }
}

/// The ring-issued successor MM, authenticated by the sealed receipt when
/// the ring adopted it. It is not `Clone`: one adoption names one MM. It is
/// the carrier's only evidence of the MM a Kernel exec preparation installs
/// (#2142 R2 hands it to `prepare_exec_with_registry_id`, which stays the
/// one function that takes the issued MM), so the carrier issues no second.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthenticatedExecMm {
    receipt: ExecAdoptionReceipt,
    origin: ServiceOrigin,
    successor: ReservationMm,
    root_generation: NonZeroU64,
}

impl AuthenticatedExecMm {
    pub const fn receipt(&self) -> ExecAdoptionReceipt {
        self.receipt
    }

    pub const fn origin(&self) -> ServiceOrigin {
        self.origin
    }

    pub const fn successor(&self) -> ReservationMm {
        self.successor
    }

    pub const fn root_generation(&self) -> NonZeroU64 {
        self.root_generation
    }
}

/// Why a row retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecRetireReason {
    /// The ring adopted the sealed successor.
    Adopted,
    /// The ring cancelled the sealed successor before adopting it.
    Cancelled,
    /// The carrier refused before the seal: the exec returns an errno and the
    /// predecessor runs on.
    Refused,
    /// The ring cancelled a parked row (a fatal signal, `exit_group`).
    ParkCancelled,
    /// The ring had cancelled the ticket before the sealed manifest reached
    /// it.
    PublishCancelled,
}

/// One row's retirement: every receipt the owner reserved ends in exactly
/// one. `sealed` is false for a row the ring never learned the receipt of,
/// so nothing past the seal (Kernel or ring) was owed for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecRetirement {
    pub receipt: ExecAdoptionReceipt,
    pub origin: ServiceOrigin,
    pub reason: ExecRetireReason,
    pub sealed: bool,
}

/// A refused owner operation. Each is a broken carrier invariant: the
/// receipt is not this owner's, or the row is not in the phase the
/// operation needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecOwnerError {
    /// The receipt space is spent.
    ReceiptsExhausted,
    /// No live row has this receipt.
    UnknownReceipt,
    /// The row is not in the phase this operation needs.
    WrongPhase,
    /// Another row already staged this successor.
    SuccessorStaged,
}

/// Not now: an operation whose fork-stock tables a holder has. It owns the
/// operation and the stock release observed before the refused reservation;
/// the wake enrolled on that release wakes it exactly once.
#[derive(Debug)]
#[must_use]
pub struct StockParked<R> {
    continuation: R,
    observed: StockRelease,
}

impl<R> StockParked<R> {
    pub fn new(continuation: R, observed: StockRelease) -> Self {
        Self {
            continuation,
            observed,
        }
    }

    /// Probe once, after the enrolled wake: the operation back to rerun if
    /// a holder has returned tables since the refusal, else still parked.
    pub fn probe<T: ChildAddressTags, C>(self, stock: &ForkStock<T, C>) -> Result<R, Self> {
        if stock.released_since(self.observed) {
            Ok(self.continuation)
        } else {
            Err(self)
        }
    }

    pub fn continuation(&self) -> &R {
        &self.continuation
    }

    /// The same park around a wider continuation.
    pub fn map<Q>(self, wrap: impl FnOnce(R) -> Q) -> StockParked<Q> {
        StockParked {
            continuation: wrap(self.continuation),
            observed: self.observed,
        }
    }
}

/// The wake a parked row enrols on the stock's release: delivery only sets
/// the row's flag, and the carrier's next probe reads it.
#[derive(Debug)]
pub struct ExecParkWake(Arc<AtomicBool>);

impl ExecParkWake {
    /// A row's flag and the stock wake that sets it.
    pub fn new() -> (Self, StockReleaseWake) {
        let woken = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&woken);
        (
            Self(woken),
            StockReleaseWake::new(move || flag.store(true, Ordering::Release)),
        )
    }

    fn woken(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// One probe of a parked row.
#[derive(Debug)]
#[must_use]
pub enum ParkedProbe<P> {
    /// No parked row has this receipt.
    Absent,
    /// Still parked: no wake yet, or no table returned since the refusal.
    Still,
    /// The ring cancelled the parked request; the row retired unsealed.
    Cancelled(P, ExecRetirement),
    /// The release landed: the row is Claimed again; rerun its staging.
    Rerun(ExecClaim, P),
}

/// What a retired, unadopted row held.
#[derive(Debug)]
pub enum ExecRetained<D, P> {
    Claimed,
    Parked(P),
    Staged(D),
}

/// A retired, unadopted row: what it held, its attachment, and its report.
#[derive(Debug)]
#[must_use]
pub struct ExecRetired<D, P, A> {
    pub held: ExecRetained<D, P>,
    pub attachment: Option<A>,
    pub retirement: ExecRetirement,
}

/// A sealed row the ring adopted: the staged successor, the attachment the
/// row carried, and the authenticated successor MM.
#[derive(Debug)]
#[must_use]
pub struct ExecAdoption<D, A> {
    pub data: D,
    pub attachment: Option<A>,
    pub mm: AuthenticatedExecMm,
    pub retirement: ExecRetirement,
}

/// The lane a settlement crossing landed on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecSettleLane {
    /// The lane that holds the root task's loaded custody (and any lane, on
    /// a carrier whose root custody is not per lane).
    RootCustody,
    /// A lane without the root's loaded custody: the x86 idle peer.
    Peer,
}

/// One adopted exec the ring settled: its predecessor and successor MMs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettledExec {
    pub receipt: ExecAdoptionReceipt,
    pub predecessor: ReservationMm,
    pub successor: ReservationMm,
}

/// A settled root exec. The carrier must consume it: it carries the root's
/// custody move from predecessor to successor, which only the lane holding
/// the root's loaded custody can apply.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct RootExecSettlement {
    settled: SettledExec,
}

impl RootExecSettlement {
    pub const fn settled(&self) -> SettledExec {
        self.settled
    }

    /// Consume the settlement once the root's custody has moved.
    pub fn consume(self) -> SettledExec {
        self.settled
    }
}

/// Where a settlement crossing goes.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub enum ExecSettlement<C = SettledExec> {
    /// A descendant's exec, settled; the carrier registers its successor.
    Child(C),
    /// The root's exec, settled on the lane that holds its custody.
    Root(RootExecSettlement),
    /// The root's exec reached a lane without its custody. Nothing changed:
    /// the row stays settling, and the record goes back to the lane that
    /// can serve it.
    NotHere,
}

impl ExecSettlement {
    /// The same route with a descendant's settlement in the carrier's terms.
    pub fn map_child<C>(self, child: impl FnOnce(SettledExec) -> C) -> ExecSettlement<C> {
        match self {
            Self::Child(settled) => ExecSettlement::Child(child(settled)),
            Self::Root(root) => ExecSettlement::Root(root),
            Self::NotHere => ExecSettlement::NotHere,
        }
    }
}

/// A refused settlement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecSettleRefusal {
    /// No adopted exec names this predecessor and successor.
    Unknown,
    /// The ring's commit left an obligation undone: a broken invariant past
    /// the point of no return. The exec is retired from settling.
    ShortEffects(ExecCommitEffects),
}

#[derive(Debug)]
enum RowPhase<D, P> {
    Claimed,
    Parked {
        parked: StockParked<P>,
        wake: ExecParkWake,
    },
    Staged(D),
    Sealed(D),
}

#[derive(Debug)]
struct ExecRow<D, P, A> {
    claim: ExecClaim,
    phase: RowPhase<D, P>,
    attachment: Option<A>,
}

/// An adopted exec awaiting its settlement crossing. Its signal reset is
/// owed until the ring's commit effects discharge it.
#[derive(Clone, Copy, Debug)]
struct SettlingExec {
    receipt: ExecAdoptionReceipt,
    origin: ServiceOrigin,
    predecessor: ReservationMm,
    successor: ReservationMm,
}

/// A carrier's exec preparations, keyed by the receipt reserved at claim.
pub struct ExecPreparations<D, P = (), A = ()> {
    issued: u64,
    rows: BTreeMap<NonZeroU64, ExecRow<D, P, A>>,
    settling: Vec<SettlingExec>,
    census: ExecOwnerCensus,
}

impl<D, P, A> Default for ExecPreparations<D, P, A> {
    fn default() -> Self {
        Self {
            issued: 0,
            rows: BTreeMap::new(),
            settling: Vec::new(),
            census: ExecOwnerCensus::default(),
        }
    }
}

impl<D, P, A> core::fmt::Debug for ExecPreparations<D, P, A> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ExecPreparations")
            .field("receipts", &self.rows.keys().collect::<Vec<_>>())
            .field("settling", &self.settling)
            .field("census", &self.census)
            .finish()
    }
}

impl<D, P, A> ExecPreparations<D, P, A> {
    /// Reserve the receipt for the ring's exec request `identity` asked for
    /// `successor`, and open its row. The receipt names the row from here,
    /// before anything is staged or sealed.
    pub fn claim(
        &mut self,
        identity: ServiceIdentity,
        successor: ReservationMm,
        root_generation: NonZeroU64,
    ) -> Result<ExecClaim, ExecOwnerError> {
        let raw = self
            .issued
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(ExecOwnerError::ReceiptsExhausted)?;
        let receipt = ExecAdoptionReceipt::checked(raw).ok_or(ExecOwnerError::ReceiptsExhausted)?;
        self.issued = raw.get();
        let claim = ExecClaim {
            receipt,
            identity,
            successor,
            root_generation,
        };
        self.rows.insert(
            raw,
            ExecRow {
                claim,
                phase: RowPhase::Claimed,
                attachment: None,
            },
        );
        self.census.reserved += 1;
        Ok(claim)
    }

    /// Attach `attachment` to an unsealed row, once. It returns by value
    /// with the adoption and drops with any other retirement.
    pub fn attach(&mut self, receipt: ExecAdoptionReceipt, attachment: A) -> Result<(), A> {
        match self.rows.get_mut(&receipt.raw()) {
            Some(row) if row.attachment.is_none() && !matches!(row.phase, RowPhase::Sealed(_)) => {
                row.attachment = Some(attachment);
                Ok(())
            }
            _ => Err(attachment),
        }
    }

    pub fn attachment(&self, receipt: ExecAdoptionReceipt) -> Option<&A> {
        self.rows.get(&receipt.raw())?.attachment.as_ref()
    }

    /// The live row's claim.
    pub fn claim_of(&self, receipt: ExecAdoptionReceipt) -> Option<ExecClaim> {
        self.rows.get(&receipt.raw()).map(|row| row.claim)
    }

    /// Live rows, in any phase before adoption.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Adopted execs not yet settled.
    pub fn settling(&self) -> usize {
        self.settling.len()
    }

    pub fn census(&self) -> ExecOwnerCensus {
        self.census
    }

    /// True when the Claimed row `receipt` asked for `successor`, and no
    /// other row has staged it.
    pub fn stageable(&self, receipt: ExecAdoptionReceipt, successor: ReservationMm) -> bool {
        self.rows.get(&receipt.raw()).is_some_and(|row| {
            matches!(row.phase, RowPhase::Claimed) && row.claim.successor == successor
        }) && self.staged_for(successor).is_none()
    }

    /// Stage a Claimed row's successor.
    pub fn stage(
        &mut self,
        receipt: ExecAdoptionReceipt,
        data: D,
    ) -> Result<(), (ExecOwnerError, D)> {
        let Some(successor) = self.claim_of(receipt).map(|claim| claim.successor) else {
            return Err((ExecOwnerError::UnknownReceipt, data));
        };
        if self.staged_for(successor).is_some() {
            return Err((ExecOwnerError::SuccessorStaged, data));
        }
        match self.rows.get_mut(&receipt.raw()) {
            Some(row) if matches!(row.phase, RowPhase::Claimed) => {
                row.phase = RowPhase::Staged(data);
                Ok(())
            }
            _ => Err((ExecOwnerError::WrongPhase, data)),
        }
    }

    /// A staged (or sealed) row's successor.
    pub fn staged(&self, receipt: ExecAdoptionReceipt) -> Option<&D> {
        match &self.rows.get(&receipt.raw())?.phase {
            RowPhase::Staged(data) | RowPhase::Sealed(data) => Some(data),
            RowPhase::Claimed | RowPhase::Parked { .. } => None,
        }
    }

    /// The row that staged (or sealed) `successor`.
    pub fn staged_for(&self, successor: ReservationMm) -> Option<(ExecClaim, &D)> {
        self.rows.values().find_map(|row| match &row.phase {
            RowPhase::Staged(data) | RowPhase::Sealed(data) if row.claim.successor == successor => {
                Some((row.claim, data))
            }
            _ => None,
        })
    }

    /// Park a Claimed row on the fork stock's release, with the wake the
    /// carrier enrolled on it.
    pub fn park(
        &mut self,
        receipt: ExecAdoptionReceipt,
        parked: StockParked<P>,
        wake: ExecParkWake,
    ) -> Result<(), (ExecOwnerError, StockParked<P>)> {
        match self.rows.get_mut(&receipt.raw()) {
            Some(row) if matches!(row.phase, RowPhase::Claimed) => {
                row.phase = RowPhase::Parked { parked, wake };
                self.census.parked += 1;
                Ok(())
            }
            Some(_) => Err((ExecOwnerError::WrongPhase, parked)),
            None => Err((ExecOwnerError::UnknownReceipt, parked)),
        }
    }

    /// The parked rows, in receipt order: a probe pass visits each once.
    pub fn parked(&self) -> Vec<ExecAdoptionReceipt> {
        self.rows
            .values()
            .filter(|row| matches!(row.phase, RowPhase::Parked { .. }))
            .map(|row| row.claim.receipt)
            .collect()
    }

    /// Probe one parked row: first whether the ring cancelled it (then it
    /// retires unsealed), then, once its wake has landed, whether a table
    /// returned since its refusal (then it is Claimed again and reruns).
    pub fn probe_parked<T: ChildAddressTags, C, E>(
        &mut self,
        receipt: ExecAdoptionReceipt,
        stock: &ForkStock<T, C>,
        cancelled: impl FnOnce(&P) -> Result<bool, E>,
    ) -> Result<ParkedProbe<P>, E> {
        let Some(row) = self.rows.get_mut(&receipt.raw()) else {
            return Ok(ParkedProbe::Absent);
        };
        let RowPhase::Parked { parked, wake } = &row.phase else {
            return Ok(ParkedProbe::Absent);
        };
        if cancelled(parked.continuation())? {
            let Some(ExecRow {
                claim,
                phase: RowPhase::Parked { parked, .. },
                ..
            }) = self.rows.remove(&receipt.raw())
            else {
                return Ok(ParkedProbe::Absent);
            };
            self.census.park_cancelled += 1;
            return Ok(ParkedProbe::Cancelled(
                parked.continuation,
                ExecRetirement {
                    receipt,
                    origin: claim.origin(),
                    reason: ExecRetireReason::ParkCancelled,
                    sealed: false,
                },
            ));
        }
        if !wake.woken() || !stock.released_since(parked.observed) {
            return Ok(ParkedProbe::Still);
        }
        let RowPhase::Parked { parked, .. } = core::mem::replace(&mut row.phase, RowPhase::Claimed)
        else {
            return Ok(ParkedProbe::Absent);
        };
        self.census.reruns += 1;
        Ok(ParkedProbe::Rerun(row.claim, parked.continuation))
    }

    /// Seal a staged row: the manifest carries the receipt reserved at
    /// claim. The seal reserves nothing.
    pub fn seal(&mut self, receipt: ExecAdoptionReceipt) -> Result<ExecClaim, ExecOwnerError> {
        let row = self
            .rows
            .get_mut(&receipt.raw())
            .ok_or(ExecOwnerError::UnknownReceipt)?;
        let phase = core::mem::replace(&mut row.phase, RowPhase::Claimed);
        match phase {
            RowPhase::Staged(data) => {
                row.phase = RowPhase::Sealed(data);
                self.census.sealed += 1;
                Ok(row.claim)
            }
            other => {
                row.phase = other;
                Err(ExecOwnerError::WrongPhase)
            }
        }
    }

    /// A sealed row's claim and successor.
    pub fn sealed(&self, receipt: ExecAdoptionReceipt) -> Option<(ExecClaim, &D)> {
        let row = self.rows.get(&receipt.raw())?;
        match &row.phase {
            RowPhase::Sealed(data) => Some((row.claim, data)),
            _ => None,
        }
    }

    /// The ring adopted the sealed row `receipt` from `predecessor`: retire
    /// it, and hold the exec as settling until its settlement crossing.
    pub fn adopt(
        &mut self,
        receipt: ExecAdoptionReceipt,
        predecessor: ReservationMm,
    ) -> Result<ExecAdoption<D, A>, ExecOwnerError> {
        if self.sealed(receipt).is_none() {
            return Err(if self.rows.contains_key(&receipt.raw()) {
                ExecOwnerError::WrongPhase
            } else {
                ExecOwnerError::UnknownReceipt
            });
        }
        let ExecRow {
            claim,
            phase: RowPhase::Sealed(data),
            attachment,
        } = self
            .rows
            .remove(&receipt.raw())
            .ok_or(ExecOwnerError::UnknownReceipt)?
        else {
            return Err(ExecOwnerError::WrongPhase);
        };
        self.settling.push(SettlingExec {
            receipt,
            origin: claim.origin(),
            predecessor,
            successor: claim.successor,
        });
        self.census.adopted += 1;
        Ok(ExecAdoption {
            data,
            attachment,
            mm: AuthenticatedExecMm {
                receipt,
                origin: claim.origin(),
                successor: claim.successor,
                root_generation: claim.root_generation,
            },
            retirement: ExecRetirement {
                receipt,
                origin: claim.origin(),
                reason: ExecRetireReason::Adopted,
                sealed: true,
            },
        })
    }

    /// The ring cancelled the sealed row `receipt` before adopting it.
    pub fn cancel(
        &mut self,
        receipt: ExecAdoptionReceipt,
    ) -> Result<(D, Option<A>, ExecRetirement), ExecOwnerError> {
        if self.sealed(receipt).is_none() {
            return Err(if self.rows.contains_key(&receipt.raw()) {
                ExecOwnerError::WrongPhase
            } else {
                ExecOwnerError::UnknownReceipt
            });
        }
        let ExecRow {
            claim,
            phase: RowPhase::Sealed(data),
            attachment,
        } = self
            .rows
            .remove(&receipt.raw())
            .ok_or(ExecOwnerError::UnknownReceipt)?
        else {
            return Err(ExecOwnerError::WrongPhase);
        };
        self.census.cancelled += 1;
        Ok((
            data,
            attachment,
            ExecRetirement {
                receipt,
                origin: claim.origin(),
                reason: ExecRetireReason::Cancelled,
                sealed: true,
            },
        ))
    }

    /// Retire an unadopted row the carrier refused (`Refused`, any phase but
    /// sealed) or whose sealed manifest the ring had already cancelled
    /// (`PublishCancelled`, sealed only).
    pub fn retire(
        &mut self,
        receipt: ExecAdoptionReceipt,
        reason: ExecRetireReason,
    ) -> Result<ExecRetired<D, P, A>, ExecOwnerError> {
        let row = self
            .rows
            .get(&receipt.raw())
            .ok_or(ExecOwnerError::UnknownReceipt)?;
        let sealed = matches!(row.phase, RowPhase::Sealed(_));
        match (reason, sealed) {
            (ExecRetireReason::Refused, false) | (ExecRetireReason::PublishCancelled, true) => {}
            _ => return Err(ExecOwnerError::WrongPhase),
        }
        let ExecRow {
            claim,
            phase,
            attachment,
        } = self
            .rows
            .remove(&receipt.raw())
            .ok_or(ExecOwnerError::UnknownReceipt)?;
        match reason {
            ExecRetireReason::Refused => self.census.refused += 1,
            _ => self.census.publish_cancelled += 1,
        }
        let held = match phase {
            RowPhase::Claimed => ExecRetained::Claimed,
            RowPhase::Parked { parked, .. } => ExecRetained::Parked(parked.continuation),
            RowPhase::Staged(data) | RowPhase::Sealed(data) => ExecRetained::Staged(data),
        };
        Ok(ExecRetired {
            held,
            attachment,
            retirement: ExecRetirement {
                receipt,
                origin: claim.origin(),
                reason,
                sealed,
            },
        })
    }

    /// Route the ring's settlement of `predecessor` → `successor`, served on
    /// `lane` with the ring's commit `effects`. A root exec on a lane without
    /// the root's custody is handed back before anything changes. Otherwise
    /// the ring's commit must have completed every exec obligation, which
    /// discharges the signal reset the adoption left owed; a short word is
    /// refused, and the exec leaves settling (the ring kills the process).
    pub fn settle(
        &mut self,
        predecessor: ReservationMm,
        successor: ReservationMm,
        effects: ExecCommitEffects,
        lane: ExecSettleLane,
    ) -> Result<ExecSettlement, ExecSettleRefusal> {
        let index = self
            .settling
            .iter()
            .position(|exec| exec.predecessor == predecessor && exec.successor == successor)
            .ok_or(ExecSettleRefusal::Unknown)?;
        let exec = self.settling[index];
        if exec.origin == ServiceOrigin::Initial && lane == ExecSettleLane::Peer {
            self.census.handed_back += 1;
            return Ok(ExecSettlement::NotHere);
        }
        self.settling.swap_remove(index);
        if !effects.is_complete() {
            self.census.short_effects += 1;
            return Err(ExecSettleRefusal::ShortEffects(effects));
        }
        self.census.settled += 1;
        self.census.signal_resets_discharged += 1;
        let settled = SettledExec {
            receipt: exec.receipt,
            predecessor,
            successor,
        };
        Ok(match exec.origin {
            ServiceOrigin::Initial => ExecSettlement::Root(RootExecSettlement { settled }),
            ServiceOrigin::Descendant => ExecSettlement::Child(settled),
        })
    }

    /// The adopted exec whose successor retired before its settlement
    /// crossing: it leaves settling with its obligations undischarged.
    pub fn abandon_settling(&mut self, successor: ReservationMm) -> bool {
        let Some(index) = self
            .settling
            .iter()
            .position(|exec| exec.successor == successor)
        else {
            return false;
        };
        self.settling.swap_remove(index);
        true
    }
}

#[cfg(test)]
#[path = "exec_owner/tests.rs"]
mod tests;
