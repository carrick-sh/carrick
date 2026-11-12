//! Host reconciliation of the returns guest EL1 deferred.
//!
//! EL1 serves a resident private-anonymous `munmap` (or a `Prepare` that
//! replaces resident memory) by retiring its stage-1 terminals in place
//! (`SW_RETIRED`) and journaling the range as an owed return in its root
//! (`Reservations::complete_deferring_return`). The range's stage-2
//! mappings and frame-inventory extents stay live, and the root hands
//! neither the VA nor the frames out again, until the host venue reconciles
//! the extent and acknowledges its sequence.
//!
//! [`MemView::reconcile_el1_deferred_returns`] is that reconciliation, ONE
//! transaction per boundary, run through the neutral settlement routine
//! ([`carrick_hal::return_settlement::settle_owed_returns`]): every owed
//! extent is retired through the backend's ordinary unmap (stage-1 retired
//! leaves and their tables, stage-2, the frame inventory, returning the
//! frames to the host); only after all of them succeeded are the extents'
//! host residency and mapping metadata removed, and then each journal slot
//! is acknowledged by its (slot, epoch, start). A backend failure applies
//! and acknowledges nothing: the extents stay owed (their frames
//! unreusable) and the next boundary retries; the backend retirement is
//! idempotent over an already-retired range.
//!
//! It runs under the MM's mutation authority, whose EL1 editor exclusion
//! keeps guest EL1 from journaling a new return meanwhile, and under the
//! MM's settlement lock. #1393 deletes this host venue once every root is
//! ring-owned; the routine stays.

use super::*;
use carrick_el1_abi::{
    OwedReturnRetirement, ReservationSequence, ReturnJournal, SettlementOutcome,
};
use carrick_hal::return_settlement::{
    ReturnJournalAccess, ReturnSettlementError, settle_owed_returns,
};

/// Why a reconciliation acknowledged nothing. The owed extents stay owed.
#[derive(::core::fmt::Debug)]
pub enum El1ReturnError {
    /// The permit is not this MM's, or the root refused a host-venue step.
    Authority(RootAccessRefusal),
    /// The backend could not retire an owed extent.
    Backend {
        range: ReservationRange,
        error: MemoryError,
    },
}

/// Every extent `model` owes the host, and the newest sequence among them.
pub(crate) fn owed_returns(
    model: &Reservations<'_>,
) -> (Vec<ReservationRange>, Option<ReservationSequence>) {
    let mut owed = Vec::new();
    let mut through: Option<ReservationSequence> = None;
    model.observe_deferred_returns(&mut |entry| {
        owed.push(entry.range);
        if through.is_none_or(|newest| newest.raw() < entry.sequence.raw()) {
            through = Some(entry.sequence);
        }
    });
    (owed, through)
}

impl MemView<'_> {
    pub(in crate::dispatch) fn fork_backing_is_unsettled(&self) -> bool {
        let authority = self.mem();
        let mem = authority.lock();
        if !mem.first_touch_stock.is_empty() {
            return true;
        }
        let Some(root) = mem.delegated_root() else {
            return false;
        };
        root.with_root(|model| Ok(owed_returns(model).1.is_some()))
            .unwrap_or_else(|refusal| {
                super::super::anonymous::broken_root("a fork settlement observation", refusal)
            })
    }

    /// Take this MM's unused first-touch stock: the root holes still under
    /// the stock-holding grants recorded at their commit. Work is
    /// proportional to those spans: an MM that holds none pays one check.
    /// The spans leave the list; [`Self::restore_first_touch_stock`] puts
    /// them back when their return fails.
    pub(in crate::dispatch) fn take_first_touch_stock(
        &self,
    ) -> (Vec<ReservationRange>, Vec<ReservationRange>) {
        let (root, spans) = {
            let authority = self.mem();
            let mut mem = authority.lock();
            if mem.first_touch_stock.is_empty() {
                return (Vec::new(), Vec::new());
            }
            let Some(root) = mem.delegated_root().cloned() else {
                mem.first_touch_stock.clear();
                return (Vec::new(), Vec::new());
            };
            (root, std::mem::take(&mut mem.first_touch_stock))
        };
        let mut stock = Vec::new();
        for span in &spans {
            let holes = root
                .with_root(|model| super::super::fault::root_holes(model, *span))
                .unwrap_or_default();
            stock.extend(
                holes
                    .into_iter()
                    .filter_map(|(start, end)| ReservationRange::new(start, end)),
            );
        }
        (spans, stock)
    }

    pub(in crate::dispatch) fn restore_first_touch_stock(&self, spans: Vec<ReservationRange>) {
        self.mem().lock().first_touch_stock.extend(spans);
    }

    /// Whether this MM's root owes the host any deferred return: the cheap
    /// check a host boundary makes before taking the MM's mutation
    /// authority for [`Self::reconcile_el1_deferred_returns`]. `false` for a
    /// host-setup MM.
    pub(in crate::dispatch) fn el1_returns_owed(&self) -> bool {
        let Some(root) = self.mem().lock().delegated_root().cloned() else {
            return false;
        };
        root.with_root(|model| Ok(owed_returns(model).1.is_some()))
            .unwrap_or(false)
    }

    /// See [`SyscallDispatcher::reconcile_el1_deferred_returns`].
    pub(in crate::dispatch) fn reconcile_el1_deferred_returns<M: CurrentMmMemory + ?Sized>(
        &self,
        permit: &HostAliasPermit<'_>,
        memory: &mut M,
    ) -> Result<usize, El1ReturnError> {
        let authority = self.mm_authority();
        if !permit.authorizes(&authority.mutation_coordinator, authority.mm_id) {
            return Err(El1ReturnError::Authority(Refusal::Stale.into()));
        }
        let Some(root) = self.mem().lock().delegated_root().cloned() else {
            return Ok(0);
        };
        crate::kernel::mm_occupancy::with_excluded_el1_editor(
            authority.mm_id,
            permit.excluded_editor(),
            |excluded| {
                let guard = authority.return_settlement.lock(excluded);
                let mut retirement = HostReturnRetirement {
                    view: self,
                    permit,
                    memory,
                    dispatch: None,
                    stock_spans: Vec::new(),
                    stock: Vec::new(),
                };
                match settle_owed_returns(excluded, &guard, &root, &mut retirement) {
                    Ok(SettlementOutcome::Settled(receipt)) => Ok(receipt.freed),
                    // The permit's MM is the excluded MM's, and the host
                    // venue never defers its own returns.
                    Ok(SettlementOutcome::Stale | SettlementOutcome::Skipped(_)) => {
                        Err(El1ReturnError::Authority(Refusal::Stale.into()))
                    }
                    Err(ReturnSettlementError::Journal(refusal)) => {
                        Err(El1ReturnError::Authority(refusal))
                    }
                    Err(ReturnSettlementError::Backend(error)) => Err(error),
                }
            },
        )
        .unwrap_or_else(|| Err(El1ReturnError::Authority(Refusal::Stale.into())))
    }
}

impl ReturnJournalAccess for DelegatedRoot {
    type Error = RootAccessRefusal;
    fn with_journal<R>(
        &self,
        step: impl FnOnce(&mut dyn ReturnJournal) -> Result<R, Refusal>,
    ) -> Result<R, RootAccessRefusal> {
        self.with_root(|model| step(model))
    }
}

/// The host venue's retirement of owed extents: the backend's ordinary unmap
/// for each, then, once all succeeded, the host's residency and mapping
/// facts for them. Unused first-touch stock retires with them: a host
/// mapping step must never place over backing EL1 holds for no node.
struct HostReturnRetirement<'v, 'p, 'g, M: CurrentMmMemory + ?Sized> {
    view: &'v MemView<'v>,
    permit: &'p HostAliasPermit<'g>,
    memory: &'v mut M,
    dispatch: Option<crate::dispatch::HostAliasDispatchGuard<'p>>,
    /// The stock spans taken for this settlement, restored if it fails.
    stock_spans: Vec<ReservationRange>,
    stock: Vec<ReservationRange>,
}

impl<M: CurrentMmMemory + ?Sized> OwedReturnRetirement for HostReturnRetirement<'_, '_, '_, M> {
    type Prepared = Vec<ReservationRange>;
    type Error = El1ReturnError;
    fn prepare(
        &mut self,
        request: &carrick_el1_abi::ReturnSettlementRequest,
    ) -> Result<Vec<ReservationRange>, El1ReturnError> {
        (self.stock_spans, self.stock) = self.view.take_first_touch_stock();
        if request.is_empty() && self.stock.is_empty() {
            return Ok(Vec::new());
        }
        let ranges: Vec<ReservationRange> = request
            .iter()
            .map(|owed| owed.range)
            .chain(self.stock.iter().copied())
            .collect();
        self.dispatch = Some(self.view.begin_conditional_vma_dispatch(self.permit));
        for range in &ranges {
            let retired = usize::try_from(range.len())
                .map_err(|_| El1ReturnError::Authority(Refusal::Invalid.into()))
                .and_then(|len| {
                    self.memory
                        .unmap_range(range.start(), len)
                        .map_err(|error| El1ReturnError::Backend {
                            range: *range,
                            error,
                        })
                });
            if let Err(error) = retired {
                // Nothing is acknowledged; the stock is retried too.
                self.dispatch = None;
                self.view
                    .restore_first_touch_stock(std::mem::take(&mut self.stock_spans));
                return Err(error);
            }
        }
        Ok(ranges)
    }
    fn apply(&mut self, retired: Vec<ReservationRange>) {
        for range in &retired {
            // Lossless: `prepare` converted every length.
            let len = range.len() as usize;
            // The VA is the root's to place again once acknowledged:
            // leave no host protection fact behind for its next mapping.
            self.memory.return_to_root(range.start(), len);
            self.view
                .remove_mapping_metadata(range.start(), range.len());
        }
        if let Some(mut dispatch) = self.dispatch.take() {
            self.view.mark_vma_dispatch(&mut dispatch);
        }
    }
}

impl SyscallDispatcher {
    /// Whether this MM's EL1 root owes the host a deferred return (a host
    /// boundary then reconciles it with
    /// [`Self::reconcile_el1_deferred_returns`]). Takes no MM authority.
    pub fn el1_returns_owed(&self) -> bool {
        self.mem_view().el1_returns_owed()
    }

    /// Reconcile every return this MM's EL1 root owes, as one transaction:
    /// the backend retires each owed extent (stage-1 retired leaves, stage-2,
    /// frame inventory: the frames return to the host), the host drops its
    /// residency and mapping facts for it, and the root's journal is then
    /// acknowledged through the newest observed sequence, which makes those
    /// VAs placeable again. Returns the number of extents released (0 for a
    /// host-setup MM or an empty journal).
    ///
    /// Locking contract: the caller holds THIS MM's mutation guard (`permit`
    /// is borrowed from it; its EL1 editor exclusion keeps EL1 from
    /// journaling meanwhile) and `memory` is this MM's backend. Call it at a
    /// host boundary of a delegated MM, and before planning a fork of it
    /// (fork seeds the child from settled memory only). Host mapping
    /// syscalls of a delegated MM reconcile first on their own. `Err`:
    /// nothing was acknowledged; the extents stay owed.
    pub fn reconcile_el1_deferred_returns<M: CurrentMmMemory + ?Sized>(
        &self,
        permit: &HostAliasPermit<'_>,
        memory: &mut M,
    ) -> Result<usize, El1ReturnError> {
        self.mem_view()
            .reconcile_el1_deferred_returns(permit, memory)
    }
}
