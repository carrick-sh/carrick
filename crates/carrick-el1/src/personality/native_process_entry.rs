//! Owned primitive work at the shared process entry boundary.
//! Callers hold their graph guard only during owner admission/publication.
extern crate alloc;
use super::process_owner::*;
use alloc::boxed::Box;
use carrick_sched_core::process::birth::{BirthAttachment, BirthSnapshot};
use carrick_sched_core::process::exit::ReservedTaskSet;
use carrick_sched_core::process::wait::{WaitQuery, WaitSelection};
use carrick_sched_core::process::{LinuxWaitStatus, TaskKey, WaitTarget, Zombie};

/// Snapshot ready for external status copying. No numeric claim is removed.
#[must_use]
pub struct WaitStatusCopy<C, U> {
    caller: TaskKey,
    query: WaitQuery,
    zombie: Zombie<C, U>,
}
/// Only a successful external copy can construct this reap authorization.
#[must_use]
pub struct CopiedWaitStatus<C, U>(WaitStatusCopy<C, U>);
impl<C, U> WaitStatusCopy<C, U> {
    pub fn zombie(&self) -> &Zombie<C, U> {
        &self.zombie
    }
    pub fn copy_with<E>(
        self,
        copy: impl FnOnce(&Zombie<C, U>) -> Result<(), E>,
    ) -> Result<CopiedWaitStatus<C, U>, E> {
        copy(&self.zombie)?;
        Ok(CopiedWaitStatus(self))
    }
}
pub enum CopiedWaitOutcome<C, U, N: NativeProcessCustody> {
    Consumed(GuestConsumedWait<C, U, N>),
    Rescan(WaitWork<C, U, N>),
}
impl<C: Copy + Ord, U: Clone> CopiedWaitStatus<C, U> {
    pub fn consume<N: NativeProcessCustody, F: GuestProcessFailure>(
        self,
        owner: &mut GuestProcessOwner<C, U, N, F>,
    ) -> Result<CopiedWaitOutcome<C, U, N>, GuestProcessError<N::Error>> {
        let mut query = self.0.query;
        query.target = WaitTarget::Exact(self.0.zombie.key);
        let consumed = owner.consume_wait(self.0.caller, query)?;
        if matches!(consumed.selection, WaitSelection::NoChild) {
            return scan_wait(owner, self.0.caller, self.0.query).map(CopiedWaitOutcome::Rescan);
        }
        Ok(CopiedWaitOutcome::Consumed(consumed))
    }
}
/// Preserve shared readiness and enrollment tokens for every non-zombie result.
pub enum WaitWork<C, U, N: NativeProcessCustody> {
    Status(WaitStatusCopy<C, U>),
    Other(GuestWaitSelection<C, U, N>),
}
pub fn scan_wait<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>(
    owner: &GuestProcessOwner<C, U, N, F>,
    caller: TaskKey,
    query: WaitQuery,
) -> Result<WaitWork<C, U, N>, GuestProcessError<N::Error>> {
    owner.precheck_wait(caller, query)?;
    Ok(match owner.scan_wait(caller, query)? {
        WaitSelection::Exited(zombie) => WaitWork::Status(WaitStatusCopy {
            caller,
            query,
            zombie,
        }),
        other => WaitWork::Other(other),
    })
}

/// The MM preparation retains its own rollback authority. Reservation custody
/// must be returned to the owner by abort or after successful publication.
#[must_use]
pub struct PreparedFork<C, U, N: NativeProcessCustody, M> {
    caller: BirthSnapshot,
    parent: BirthSnapshot,
    child: Box<GuestTask<C, U, N>>,
    mm: M,
    attachment: BirthAttachment,
    permit: ReservedTaskSet<N::Transaction>,
}
#[must_use]
pub struct PublishedFork<T, B> {
    pub reservation: ReservedTaskSet<T>,
    pub born: B,
}
pub type ForkPreparationResult<C, U, N, M> = Result<
    PreparedFork<C, U, N, M>,
    Box<(
        GuestProcessError<<N as NativeProcessCustody>::Error>,
        GuestTask<C, U, N>,
        M,
    )>,
>;
pub type ForkAbortResult<C, U, N, M> =
    Result<(GuestTask<C, U, N>, M), Box<PreparedFork<C, U, N, M>>>;
pub type ForkPublicationResult<C, U, N, M, B> = Result<
    PublishedFork<<N as NativeProcessCustody>::Transaction, B>,
    Box<(
        GuestProcessError<<N as NativeProcessCustody>::Error>,
        PreparedFork<C, U, N, M>,
    )>,
>;
pub type ExitPublicationResult<C, U, N> = Result<
    (
        Option<<N as NativeProcessCustody>::Resources>,
        GuestPublishedExit<C, U, N>,
    ),
    GuestProcessError<<N as NativeProcessCustody>::Error>,
>;
pub enum ForkTryError<E, P, NativeError> {
    Admission(GuestProcessError<NativeError>, Box<P>),
    Commit(E, Box<P>),
}
pub type ForkTryResult<C, U, N, M, B, E> = Result<
    PublishedFork<<N as NativeProcessCustody>::Transaction, B>,
    ForkTryError<E, PreparedFork<C, U, N, M>, <N as NativeProcessCustody>::Error>,
>;
impl<C: Copy + Ord, U: Clone, N: NativeProcessCustody, M> PreparedFork<C, U, N, M> {
    pub fn prepare<F: GuestProcessFailure>(
        owner: &mut GuestProcessOwner<C, U, N, F>,
        caller: TaskKey,
        parent: TaskKey,
        child: GuestTask<C, U, N>,
        mm: M,
        attachment: BirthAttachment,
        transaction: N::Transaction,
    ) -> ForkPreparationResult<C, U, N, M> {
        let result = (|| {
            let caller = owner.capture_parent(caller)?;
            let parent = owner.capture_parent(parent)?;
            let permit = owner.reserve_birth(caller, parent, transaction)?;
            Ok((caller, parent, permit))
        })();
        match result {
            Ok((caller, parent, permit)) => Ok(Self {
                caller,
                parent,
                child: Box::new(child),
                mm,
                attachment,
                permit,
            }),
            Err(error) => Err(Box::new((error, child, mm))),
        }
    }
    pub fn abort<F: GuestProcessFailure>(
        self,
        owner: &mut GuestProcessOwner<C, U, N, F>,
    ) -> ForkAbortResult<C, U, N, M> {
        if !owner.rollback_birth(&self.permit) {
            return Err(Box::new(self));
        }
        Ok((*self.child, self.mm))
    }
    /// Retain an already owned shared reservation while attaching the caller's
    /// prepared MM and child. Shared admission authenticates all fields.
    pub fn from_reserved(
        caller: BirthSnapshot,
        parent: BirthSnapshot,
        child: Box<GuestTask<C, U, N>>,
        mm: M,
        attachment: BirthAttachment,
        permit: ReservedTaskSet<N::Transaction>,
    ) -> Self {
        Self {
            caller,
            parent,
            child,
            mm,
            attachment,
            permit,
        }
    }
    /// A refused guest-MM publication leaves the exact child and preparation
    /// owned, with the process unpublished and its reservation still retained.
    pub fn try_publish_with<F: GuestProcessFailure, B, E>(
        mut self: Box<Self>,
        owner: &mut GuestProcessOwner<C, U, N, F>,
        commit_mm: impl FnOnce(M) -> Result<B, (E, M)>,
    ) -> ForkTryResult<C, U, N, M, B, E> {
        let admission = match owner.admit_child(
            self.caller,
            self.parent,
            &self.child,
            self.attachment,
            Some(&self.permit),
        ) {
            Ok(admission) => admission,
            Err(error) => return Err(ForkTryError::Admission(error, self)),
        };
        let born = match commit_mm(self.mm) {
            Ok(born) => born,
            Err((error, mm)) => {
                self.mm = mm;
                drop(admission);
                return Err(ForkTryError::Commit(error, self));
            }
        };
        admission.publish(self.child);
        Ok(PublishedFork {
            reservation: self.permit,
            born,
        })
    }
    /// MM commit is infallible only after the caller's MM preparation and shared
    /// child admission have both succeeded. Its retained Born effect is returned.
    pub fn publish_with<F: GuestProcessFailure, B>(
        self,
        owner: &mut GuestProcessOwner<C, U, N, F>,
        commit_mm: impl FnOnce(M) -> B,
    ) -> ForkPublicationResult<C, U, N, M, B> {
        let admission = match owner.admit_child(
            self.caller,
            self.parent,
            &self.child,
            self.attachment,
            Some(&self.permit),
        ) {
            Ok(admission) => admission,
            Err(error) => return Err(Box::new((error, self))),
        };
        let born = commit_mm(self.mm);
        admission.publish(self.child);
        Ok(PublishedFork {
            reservation: self.permit,
            born,
        })
    }
}
/// Resources and cancellation effects are owned results for service after the
/// enclosing graph guard is dropped. No cancellation or signal sampling occurs.
pub fn publish_exit<C: Copy + Ord, U: Clone, N: NativeProcessCustody, F: GuestProcessFailure>(
    owner: &mut GuestProcessOwner<C, U, N, F>,
    task: TaskKey,
    adopter: Option<TaskKey>,
    transaction: N::Transaction,
    status: LinuxWaitStatus,
) -> ExitPublicationResult<C, U, N> {
    let pending = owner
        .prepare_exit(task, adopter)?
        .reserve(transaction)?
        .begin(status)?;
    let mut published = pending.publish()?;
    let resources = published.take_resources();
    Ok((resources, published))
}
