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
//! transaction per boundary: every owed extent is retired through the
//! backend's ordinary unmap (stage-1 retired leaves and their tables,
//! stage-2, the frame inventory, returning the frames to the host), its host
//! residency and mapping metadata are removed, and only after all of them
//! succeeded is the journal acknowledged through the newest sequence
//! observed. A backend failure acknowledges nothing: the extents stay owed
//! (their frames unreusable) and the next boundary retries; the backend
//! retirement is idempotent over an already-retired range.
//!
//! It runs under the MM's mutation authority, whose EL1 editor exclusion
//! keeps guest EL1 from journaling a new return meanwhile.

use super::*;
use carrick_el1_abi::ReservationSequence;

/// Why a reconciliation acknowledged nothing. The owed extents stay owed.
#[derive(Debug)]
pub enum El1ReturnError {
    /// The permit is not this MM's, or the root refused a host-venue step.
    Authority(Refusal),
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

/// Final-MM settlement of a root: acknowledge every owed return, then retire
/// the root. Only for the final settlement of the MM: its address space is
/// closed and drained (no EL1 can journal again), and its frame inventory
/// retires as a whole with the MM, owed extents included, so nothing is
/// reconciled range by range. Returns the number of extents released.
pub(crate) fn settle_final_root(mut model: Reservations<'_>) -> Result<usize, Refusal> {
    let (_, through) = owed_returns(&model);
    let released = match through {
        Some(through) => model.acknowledge_deferred_returns(through)?,
        None => 0,
    };
    model.retire()?;
    Ok(released)
}

impl MemView<'_> {
    /// The root holes of this MM that its live first-touch grants back:
    /// unused stock (`fault::root_grant_for_page`). Spans of `table`'s live
    /// grants for this MM, minus every node the root holds now.
    pub(in crate::dispatch) fn first_touch_stock(
        &self,
        table: &carrick_el1_abi::FrameGrantResidencyTable,
    ) -> Vec<ReservationRange> {
        let Some(root) = self.mem().lock().delegated_root().cloned() else {
            return Vec::new();
        };
        let mut spans = Vec::new();
        table.live_spans_overlapping(root.mm().raw(), 0, u64::MAX, |start, end| {
            spans.push((start, end));
        });
        let mut stock = Vec::new();
        for (start, end) in spans {
            let Some(span) = ReservationRange::new(start, end) else {
                continue;
            };
            let holes = root
                .with_root(|model| super::super::fault::root_holes(model, span))
                .unwrap_or_default();
            stock.extend(
                holes
                    .into_iter()
                    .filter_map(|(start, end)| ReservationRange::new(start, end)),
            );
        }
        stock
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
            return Err(El1ReturnError::Authority(Refusal::Stale));
        }
        let Some(root) = self.mem().lock().delegated_root().cloned() else {
            return Ok(0);
        };
        // The root guard is released before any backend service runs.
        let (owed, through) = root
            .with_root(|model| Ok(owed_returns(model)))
            .map_err(El1ReturnError::Authority)?;
        // Unused first-touch stock returns with the owed extents: a host
        // mapping step must never place over backing EL1 holds for no node.
        let stock = carrick_el1_abi::frame_grant_residency_host()
            .map(|table| self.first_touch_stock(table))
            .unwrap_or_default();
        if through.is_none() && stock.is_empty() {
            return Ok(0);
        }
        {
            let mut dispatch = self.begin_conditional_vma_dispatch(permit);
            for range in owed.iter().chain(&stock) {
                let len = usize::try_from(range.len())
                    .map_err(|_| El1ReturnError::Authority(Refusal::Invalid))?;
                memory.unmap_range(range.start(), len).map_err(|error| {
                    El1ReturnError::Backend {
                        range: *range,
                        error,
                    }
                })?;
                memory.set_unmapped(range.start(), len, true);
                self.remove_mapping_metadata(range.start(), range.len());
            }
            self.mark_vma_dispatch(&mut dispatch);
        }
        match through {
            Some(through) => root
                .with_root(|model| model.acknowledge_deferred_returns(through))
                .map_err(El1ReturnError::Authority),
            None => Ok(0),
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
