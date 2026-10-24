//! Prepared descriptor cutover. Selection belongs here; venues own storage,
//! task admission, private staging and physical release custody.

use crate::Fd;
use carrick_sched_core::process::TaskKey;

/// One descriptor in the private staged namespace, including implicit streams.
#[derive(Clone, Copy, Debug)]
pub struct ExecDescriptor {
    pub fd: Fd,
    pub close_on_exec: bool,
}

/// Custody minted by the task/table owner while its lifecycle admission is held.
/// Implementations authenticate their domain and exact table incarnation; a
/// task number or an observational table reference cannot mint this custody.
pub trait TableCustody: Sized {
    type Error;
    type Stage: CloseOnExecStage<Custody = Self, Error = Self::Error>;

    fn exact_task(&self) -> TaskKey;
    /// Freeze and unshare before changing any descriptor. On refusal return the
    /// unchanged source. The stage must own rollback and preallocated releases.
    fn stage(self) -> Result<Self::Stage, PrepareError<Self, Self::Error>>;
}

/// Venue primitives over a private namespace. Only the shared selection loop
/// decides which descriptors close. No staged namespace may be guest-visible.
pub trait CloseOnExecStage: Sized {
    type Custody: TableCustody<Stage = Self, Error = Self::Error>;
    type Error;
    type Releases;

    /// Visit each live descriptor once, with no duplicates or wraparound.
    fn next_descriptor(&mut self) -> Option<ExecDescriptor>;
    /// Remove this selected descriptor, retaining its physical obligation.
    fn retain_closed(&mut self, fd: Fd) -> Result<(), Self::Error>;
    /// Finish all fallible metadata/storage preparation before the no-return cut.
    fn finish_preparation(&mut self) -> Result<(), Self::Error>;
    /// Drop private staging before thawing the source.
    fn rollback(self) -> Self::Custody;
    /// Move already prepared custody only: no scan, allocation or fallible work.
    /// The release custody retains any source freeze through task publication.
    fn commit(self) -> (Self::Custody, Self::Releases);
}

#[derive(Debug)]
pub enum PreparationError<E> {
    WrongTask,
    Venue(E),
}

/// Refusal never consumes the caller's table custody.
pub struct PrepareError<C, E> {
    reason: PreparationError<E>,
    custody: C,
}

impl<C, E> PrepareError<C, E> {
    pub fn venue(error: E, custody: C) -> Self {
        Self {
            reason: PreparationError::Venue(error),
            custody,
        }
    }
    pub fn reason(&self) -> &PreparationError<E> {
        &self.reason
    }
    pub fn into_parts(self) -> (PreparationError<E>, C) {
        (self.reason, self.custody)
    }
}

/// Single-consumption authority for descriptor cutover. There is deliberately
/// no public constructor and no Clone. Dropping it rolls back its owned stage.
#[must_use]
pub struct PreparedCloseOnExec<S: CloseOnExecStage> {
    stage: S,
}

impl<S: CloseOnExecStage> PreparedCloseOnExec<S> {
    /// Owner-private staging access. A venue must not expose methods that
    /// publish or mutate its private successor through this shared reference.
    pub fn stage(&self) -> &S {
        &self.stage
    }
    pub fn commit(self) -> (S::Custody, S::Releases) {
        self.stage.commit()
    }
}

pub fn prepare_close_on_exec<C: TableCustody>(
    exact_task: TaskKey,
    custody: C,
) -> Result<PreparedCloseOnExec<C::Stage>, PrepareError<C, C::Error>> {
    if custody.exact_task() != exact_task {
        return Err(PrepareError {
            reason: PreparationError::WrongTask,
            custody,
        });
    }
    let mut stage = custody.stage()?;
    while let Some(entry) = stage.next_descriptor() {
        if entry.close_on_exec
            && let Err(error) = stage.retain_closed(entry.fd)
        {
            return Err(PrepareError::venue(error, stage.rollback()));
        }
    }
    if let Err(error) = stage.finish_preparation() {
        return Err(PrepareError::venue(error, stage.rollback()));
    }
    Ok(PreparedCloseOnExec { stage })
}

pub fn commit<S: CloseOnExecStage>(prepared: PreparedCloseOnExec<S>) -> (S::Custody, S::Releases) {
    prepared.commit()
}
