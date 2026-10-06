//! ISA-neutral private-anonymous descriptor transaction.
//!
//! Linux syscall decoding and ISA descriptor encoding remain in adapters.
//! This module owns the common decision, edit ordering, retirement custody,
//! and reservation-root commit.

use super::reservation::{ReservationGeometry, ReservationPolicy, Reservations};
use carrick_core_abi::{
    Refusal, ReservationBackingReceipt, ReservationCompletion, ReservationOperation,
    ReservationProtection, ReservationRequest,
};

/// What one exact MM's live translation graph holds under an edit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeBacking {
    Empty,
    Private,
    Prepared,
    Retired,
    Foreign,
}

/// Why a range cannot be edited by the private-anonymous owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForeignBacking {
    HostOwnedLeaf,
    Block,
    TooManyRuns,
    Malformed,
}

pub const MAX_BACKED_RUNS: usize = 8;

/// Classification plus maximal backed runs in address order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage1Backing {
    pub summary: RangeBacking,
    pub foreign: ForeignBacking,
    runs: [(u64, u64); MAX_BACKED_RUNS],
    count: usize,
}

impl Stage1Backing {
    pub const fn of(summary: RangeBacking) -> Self {
        Self {
            summary,
            foreign: ForeignBacking::Malformed,
            runs: [(0, 0); MAX_BACKED_RUNS],
            count: 0,
        }
    }

    pub const fn foreign(why: ForeignBacking) -> Self {
        let mut backing = Self::of(RangeBacking::Foreign);
        backing.foreign = why;
        backing
    }

    pub fn with_runs(summary: RangeBacking, runs: &[(u64, u64)]) -> Self {
        let mut backing = Self::of(summary);
        for &(start, end) in runs {
            backing.push(start, end);
        }
        backing
    }

    pub fn push(&mut self, start: u64, end: u64) {
        if self.count > 0 && self.runs[self.count - 1].1 == start {
            self.runs[self.count - 1].1 = end;
        } else if self.count == MAX_BACKED_RUNS {
            self.summary = RangeBacking::Foreign;
            self.foreign = ForeignBacking::TooManyRuns;
        } else {
            self.runs[self.count] = (start, end);
            self.count += 1;
        }
    }

    pub fn runs(&self) -> &[(u64, u64)] {
        &self.runs[..self.count]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionEdit {
    pub va: u64,
    pub len: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorEditError {
    Refused,
    RollbackFailed,
}

/// ISA binding for classification, descriptor encoding and invalidation.
pub trait AnonymousDescriptorEditor {
    fn backing(&mut self, root: u64, va: u64, len: u64) -> Stage1Backing;
    fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)>;
    fn protect_and_invalidate(
        &mut self,
        root: u64,
        edit: PermissionEdit,
    ) -> Result<(), DescriptorEditError>;
    fn retire_and_invalidate(
        &mut self,
        root: u64,
        address: u64,
        len: u64,
    ) -> Result<(), DescriptorEditError>;
    fn retire_residency(&mut self, _mm_key: u64, _address: u64, _len: u64) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousRefusal {
    Foreign(ForeignBacking),
    BackingRetired,
    MultiRun,
    EditRefused,
    JournalFull,
    RootDeclined,
    Root(Refusal),
    RollbackFailed,
    CommitAfterEdit(Refusal),
}

fn refuse<P: ReservationPolicy, G: ReservationGeometry>(
    model: &mut Reservations<'_, P, G>,
    request: ReservationRequest,
    refusal: AnonymousRefusal,
) -> Result<u64, AnonymousRefusal> {
    model
        .refuse(request)
        .map_err(AnonymousRefusal::Root)
        .and(Err(refusal))
}

/// A descriptor backend bound to the exact MM and root retained by a live
/// scheduler editor. The integer root and MM cannot be supplied independently.
pub struct AnonymousEditAuthority<'g, 's, E> {
    _guard: &'g carrick_sched_core::SpaceEditor<'s>,
    editor: &'g mut E,
    mm: carrick_core_abi::ReservationMm,
    root: u64,
}
impl<'g, 's, E: AnonymousDescriptorEditor> AnonymousEditAuthority<'g, 's, E> {
    /// # Safety
    /// `editor` must faithfully classify/edit this guard's retained MM root,
    /// using mapped, aligned storage in its qualified execution venue for the
    /// entire borrow. Success must include the required hardware invalidation
    /// and backing custody; failure must leave the old state or report failed
    /// rollback. No alternate descriptor editor may access the same MM.
    pub unsafe fn from_editor(
        guard: &'g carrick_sched_core::SpaceEditor<'s>,
        editor: &'g mut E,
    ) -> Option<Self> {
        let (mm, grant) = guard.grant()?;
        Some(Self {
            _guard: guard,
            editor,
            mm: carrick_core_abi::ReservationMm::new(mm.get())?,
            root: grant.ttbr0,
        })
    }
}

/// Perform and commit one admitted anonymous edit under an exact-MM editor.
pub fn edit_and_commit<P, G, E>(
    model: &mut Reservations<'_, P, G>,
    request: ReservationRequest,
    authority: &mut AnonymousEditAuthority<'_, '_, E>,
) -> Result<u64, AnonymousRefusal>
where
    P: ReservationPolicy,
    G: ReservationGeometry,
    E: AnonymousDescriptorEditor,
{
    if !model.is_admitted()
        || model.pending() != Some(request)
        || request.mm != model.mm()
        || request.generation != model.generation()
        || authority.mm != model.mm()
    {
        return Err(AnonymousRefusal::Root(Refusal::Stale));
    }
    let (root, mm_key) = (authority.root, authority.mm.raw());
    let editor = &mut *authority.editor;
    let (va, len) = (request.range.start(), request.range.len());
    if request.operation == ReservationOperation::Move {
        return refuse(model, request, AnonymousRefusal::RootDeclined);
    }
    let backing = editor.backing(root, va, len);
    let run = match backing.runs() {
        [] => None,
        [(start, end)] => Some((*start, *end - *start)),
        _ => return refuse(model, request, AnonymousRefusal::MultiRun),
    };
    let adopts_stock = request.operation == ReservationOperation::Prepare
        && backing.summary == RangeBacking::Prepared
        && run.is_some_and(|(start, run_len)| {
            editor
                .stock_span(mm_key, start)
                .is_some_and(|(base, end)| base <= start && start + run_len <= end)
        })
        && {
            let mut nodes = 0usize;
            model
                .observe_range(request.range, &mut |_| nodes += 1)
                .is_ok()
                && nodes == 0
        };
    let mut edited = false;
    let owed_return = match (request.operation, backing.summary, run) {
        (_, RangeBacking::Foreign, _) => {
            return refuse(model, request, AnonymousRefusal::Foreign(backing.foreign));
        }
        (ReservationOperation::Prepare, RangeBacking::Retired, None) => None,
        (_, RangeBacking::Retired, _) => {
            return refuse(model, request, AnonymousRefusal::BackingRetired);
        }
        (_, RangeBacking::Empty, _) | (_, _, None) => None,
        (
            ReservationOperation::Protect,
            RangeBacking::Private | RangeBacking::Prepared,
            Some((start, run_len)),
        )
        | (ReservationOperation::Prepare, RangeBacking::Prepared, Some((start, run_len)))
            if request.operation == ReservationOperation::Protect || adopts_stock =>
        {
            let protection = request.protection;
            let edit = PermissionEdit {
                va: start,
                len: run_len,
                readable: protection.permits(ReservationProtection::READ),
                writable: protection.permits(ReservationProtection::WRITE),
                executable: protection.permits(ReservationProtection::EXECUTE),
            };
            match editor.protect_and_invalidate(root, edit) {
                Ok(()) => {
                    edited = true;
                    None
                }
                Err(DescriptorEditError::Refused) => {
                    return refuse(model, request, AnonymousRefusal::EditRefused);
                }
                Err(DescriptorEditError::RollbackFailed) => {
                    return Err(AnonymousRefusal::RollbackFailed);
                }
            }
        }
        (
            ReservationOperation::Retire | ReservationOperation::Prepare,
            RangeBacking::Private | RangeBacking::Prepared,
            Some((start, run_len)),
        ) => {
            let slot = match model.reserve_return(request.range) {
                Ok(slot) => slot,
                Err(_) => return refuse(model, request, AnonymousRefusal::JournalFull),
            };
            match editor.retire_and_invalidate(root, start, run_len) {
                Ok(()) => {
                    edited = true;
                    editor.retire_residency(mm_key, va, len);
                    Some(slot)
                }
                Err(DescriptorEditError::Refused) => {
                    model.release_return(slot);
                    return refuse(model, request, AnonymousRefusal::EditRefused);
                }
                Err(DescriptorEditError::RollbackFailed) => {
                    model.release_return(slot);
                    return Err(AnonymousRefusal::RollbackFailed);
                }
            }
        }
        _ => return refuse(model, request, AnonymousRefusal::RootDeclined),
    };
    // SAFETY: the exact admitted root and descriptor editor are held by the
    // caller. Every required descriptor edit and invalidation completed above;
    // retirement custody remains in `owed_return` until inventory receipt.
    let completion = unsafe {
        ReservationCompletion::after_descriptor_and_backing_commit(
            request,
            ReservationBackingReceipt {
                receipt: request.sequence.raw(),
                granted_bytes: 0,
                returned_bytes: 0,
            },
        )
    };
    let Some(completion) = completion else {
        if let Some(slot) = owed_return {
            model.release_return(slot);
        }
        return if edited {
            Err(AnonymousRefusal::CommitAfterEdit(Refusal::Invalid))
        } else {
            refuse(model, request, AnonymousRefusal::Root(Refusal::Invalid))
        };
    };
    let result = match owed_return {
        Some(slot) => model.complete_deferring_return(completion, slot),
        None => model.complete(completion),
    };
    result.map_err(|error| {
        if edited {
            AnonymousRefusal::CommitAfterEdit(error)
        } else {
            AnonymousRefusal::Root(error)
        }
    })
}
