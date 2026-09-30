//! Program break (`brk`/`sbrk`) heap management.
//!
//! One owner answers for the break: [`BreakAuthority::HostSetup`] while the MM
//! is set up by the host, [`BreakAuthority::Delegated`] once the MM's shared
//! EL1 reservation root is admitted. A delegated break has no copy in
//! `MemState`; host-forwarded `brk` then runs the root's own `brk` proposal and
//! completes it after the same backend work the host-setup venue performs.
//! Growing re-validates identity leaves as RW and publishes permissions;
//! shrinking invalidates released pages and zeroes their raw backing so subsequent
//! re-growth re-exposes clean zero-filled anonymous memory matching Linux semantics.

use super::el1_reservations::DelegatedBreak;
use super::*;
use carrick_el1::memory::reservations::{Decision, Refusal};
use carrick_el1_abi::{ReservationBackingReceipt, ReservationCompletion, ReservationOperation};
use carrick_fatal::carrick_fatal;

pub(in crate::dispatch) fn update_semantic_heap_pages(
    mem: &mut MemState,
    old_page_end: u64,
    new_page_end: u64,
) {
    mem.semantic_vmas
        .update_heap_pages(old_page_end, new_page_end);
}

/// The single owner of one MM's program break.
#[derive(Clone)]
pub(in crate::dispatch) enum BreakAuthority {
    /// Host setup: `MemState` owns the break value.
    HostSetup(u64),
    /// The exact admitted reservation root owns the break; nothing here
    /// carries a value a caller could consult instead. Constructed only by
    /// root admission, which production still refuses until the remaining
    /// anonymous facts leave `MemState` (the conformance fixture seals it).
    #[cfg_attr(not(test), allow(dead_code))]
    Delegated(DelegatedBreak),
}

impl BreakAuthority {
    /// The break as its owner answers it. A delegated root that cannot be
    /// observed is a broken ownership invariant (the MM mutation permit and
    /// the host queue exclude every host-venue contender), never a reason to
    /// answer from a stale host value.
    pub(super) fn observe(&self) -> u64 {
        match self {
            Self::HostSetup(brk) => *brk,
            Self::Delegated(root) => root
                .with_root(|model| Ok(model.brk_current()))
                .unwrap_or_else(|refusal| {
                    carrick_fatal!(
                        "dispatch::brk",
                        "delegated program break is unobservable: {refusal:?}"
                    )
                }),
        }
    }

    /// A fork child is a different MM whose own root is not admitted: it
    /// inherits the break VALUE in host setup, never the parent's root.
    pub(super) fn fork_private(&self) -> Self {
        Self::HostSetup(self.observe())
    }
}

/// A page-granular break move both venues back identically. `pending` is the
/// delegated root's proposal awaiting this backend work.
struct BreakMove {
    requested: u64,
    old_page_end: u64,
    new_page_end: u64,
    pending: Option<(DelegatedBreak, carrick_el1_abi::ReservationRequest)>,
}

impl<'a> MemView<'a> {
    define_syscall! {
        mm_mutation fn brk(this, cx, requested: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let mem_authority_13 = this.mem();
            let mut mem = mem_authority_13.lock();
            let step = match mem.break_authority().clone() {
                BreakAuthority::HostSetup(current) => {
                    this.plan_host_setup_brk(&mut mem, current, requested)
                }
                BreakAuthority::Delegated(root) => {
                    this.plan_delegated_brk(&mem, root, requested)?
                }
            };
            let movement = match step {
                Err(answer) => {
                    if answer.changed {
                        host_alias_dispatch.mark_vma_revision(mem_authority_13.revision_publisher());
                    }
                    return Ok(DispatchOutcome::returned_u64(answer.value)?);
                }
                Ok(movement) => movement,
            };
            let BreakMove { requested, old_page_end, new_page_end, pending } = movement;
            if new_page_end > old_page_end {
                // Grow: revalidate old-page-end..new-page-end identity leaves as RW,
                // then publish RW in MemoryProtections (clearing unmapped atomically), then commit.
                let grow_start = old_page_end;
                let Some(grow_len) = new_page_end
                    .checked_sub(old_page_end)
                    .and_then(|len| usize::try_from(len).ok())
                else {
                    return this.refuse_brk(&mem, pending);
                };
                let rw = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
                if let Err(error) = cx.memory.protect_range(grow_start, grow_len, rw) {
                    carrick_fatal!(
                        "dispatch::brk",
                        "protect_range failed during brk heap expansion 0x{grow_start:x}+0x{grow_len:x}: {error}"
                    );
                }
                cx.memory.set_mapping_protection(grow_start, grow_len, false, false);
            } else {
                // Shrink: first make removed page tail stage-1-invalid, then publish
                // unmapped, then zero raw backing for safe reuse, then commit.
                let shrink_start = new_page_end;
                let Some(shrink_len) = old_page_end
                    .checked_sub(new_page_end)
                    .and_then(|len| usize::try_from(len).ok())
                else {
                    return this.refuse_brk(&mem, pending);
                };
                if cx.memory.protect_range(shrink_start, shrink_len, 0).is_err() {
                    carrick_fatal!(
                        "dispatch::brk",
                        "protect_range failed during brk heap contraction"
                    );
                }
                cx.memory.set_unmapped(shrink_start, shrink_len, true);
                if cx.memory.zero_backing(shrink_start, shrink_len).is_err() {
                    carrick_fatal!(
                        "dispatch::brk",
                        "zero_backing failed during brk heap contraction"
                    );
                }
            }
            update_semantic_heap_pages(&mut mem, old_page_end, new_page_end);
            let value = match pending {
                None => {
                    *mem.break_authority_mut() = BreakAuthority::HostSetup(requested);
                    requested
                }
                Some((root, request)) => complete_delegated_brk(&root, request)?,
            };
            host_alias_dispatch.mark_vma_revision(mem_authority_13.revision_publisher());
            Ok(DispatchOutcome::returned_u64(value)?)
        }
    }

    /// Host-setup venue: the break lives in `mem`. `Err` is the final answer.
    fn plan_host_setup_brk(
        &self,
        mem: &mut MemState,
        current: u64,
        requested: u64,
    ) -> Result<BreakMove, BreakAnswer> {
        let unchanged = BreakAnswer {
            value: current,
            changed: false,
        };
        if requested == 0 || !range_within(requested, 0, mem.layout.heap_base, mem.layout.heap_size)
        {
            return Err(unchanged);
        }
        let page_size = self.linux_page_size();
        let (Some(old_page_end), Some(new_page_end)) = (
            align_up_u64(current, page_size),
            align_up_u64(requested, page_size),
        ) else {
            return Err(unchanged);
        };
        if requested > current {
            // RLIMIT_AS / RLIMIT_DATA on the page-rounded growth; the heap is
            // data by definition. brk(2) reports ENOMEM by returning the
            // unchanged break.
            if let Some((as_limit, data_limit)) = self.address_space_limits_apply(true) {
                let grow = new_page_end.saturating_sub(old_page_end);
                if self
                    .check_address_space_limits_locked(mem, as_limit, data_limit, grow, true)
                    .is_err()
                {
                    return Err(unchanged);
                }
            }
        }
        if new_page_end == old_page_end {
            // Same-page movement: only update byte-precise break.
            *mem.break_authority_mut() = BreakAuthority::HostSetup(requested);
            return Err(BreakAnswer {
                value: requested,
                changed: requested != current,
            });
        }
        Ok(BreakMove {
            requested,
            old_page_end,
            new_page_end,
            pending: None,
        })
    }

    /// Delegated venue: the exact root decides, with the host's current
    /// limits and the charges of everything the root does not model pushed
    /// first. The root guard is released before any backend work.
    fn plan_delegated_brk(
        &self,
        mem: &MemState,
        root: DelegatedBreak,
        requested: u64,
    ) -> Result<Result<BreakMove, BreakAnswer>, DispatchError> {
        let (address_limit, data_limit) = self
            .address_space_limits_apply(true)
            .unwrap_or((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY));
        let (external_address, external_data) = host_owned_charges(mem);
        let (current, decision) = root
            .with_root(|model| {
                model.set_limits(address_limit, data_limit);
                model.set_external_charges(external_address, external_data);
                let current = model.brk_current();
                Ok((current, model.brk(requested)?))
            })
            .map_err(DispatchError::ReservationAuthority)?;
        let request = match decision {
            Decision::Complete(value) => {
                return Ok(Err(BreakAnswer {
                    value,
                    changed: value != current,
                }));
            }
            Decision::Work(request) => request,
        };
        let range = request.range;
        let (old_page_end, new_page_end) = match request.operation {
            ReservationOperation::Prepare => (range.start(), range.end()),
            ReservationOperation::Retire => (range.end(), range.start()),
            ReservationOperation::Protect | ReservationOperation::Move => {
                // Not a break proposal: leave the root as it was.
                root.with_root(|model| model.refuse(request))
                    .map_err(DispatchError::ReservationAuthority)?;
                return Err(DispatchError::ReservationAuthority(Refusal::Invalid));
            }
        };
        Ok(Ok(BreakMove {
            requested,
            old_page_end,
            new_page_end,
            pending: Some((root, request)),
        }))
    }

    /// `setrlimit(RLIMIT_AS | RLIMIT_DATA)` on this MM's own process: push
    /// the new limits to a delegated break's root, so the guest venue decides
    /// against them as well. A host-setup break reads them at each `brk`.
    pub(in crate::dispatch) fn push_break_limits(&self) -> Result<(), DispatchError> {
        let authority = self.mem();
        let mem = authority.lock();
        let BreakAuthority::Delegated(root) = mem.break_authority() else {
            return Ok(());
        };
        let (address_limit, data_limit) = self
            .address_space_limits_apply(true)
            .unwrap_or((LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY));
        root.with_root(|model| {
            model.set_limits(address_limit, data_limit);
            Ok(())
        })
        .map_err(DispatchError::ReservationAuthority)
    }

    /// No backend work happened: withdraw a delegated proposal and answer
    /// the unchanged break, as brk(2) reports failure.
    fn refuse_brk(
        &self,
        mem: &MemState,
        pending: Option<(DelegatedBreak, carrick_el1_abi::ReservationRequest)>,
    ) -> Result<DispatchOutcome, DispatchError> {
        if let Some((root, request)) = pending {
            root.with_root(|model| model.refuse(request))
                .map_err(DispatchError::ReservationAuthority)?;
        }
        Ok(DispatchOutcome::returned_u64(mem.program_break())?)
    }
}

/// A break answer that needs no backend work.
struct BreakAnswer {
    value: u64,
    changed: bool,
}

/// Commit the delegated proposal after its backend work.
fn complete_delegated_brk(
    root: &DelegatedBreak,
    request: carrick_el1_abi::ReservationRequest,
) -> Result<u64, DispatchError> {
    // SAFETY: the caller holds this exact MM's mutation permit and the root
    // still holds `request` pending (it excludes every other edit). The stage-1
    // protection, MemoryProtections publication and, for a retire, the scrub
    // of the released pages completed above. Heap backing is identity memory:
    // no frame was granted to or returned from the inventory. The pending
    // sequence names this substrate transaction.
    let completion = unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    }
    .ok_or(DispatchError::ReservationAuthority(Refusal::Invalid))?;
    root.with_root(|model| model.complete(completion))
        .map_err(DispatchError::ReservationAuthority)
}

#[cfg(test)]
mod tests;
