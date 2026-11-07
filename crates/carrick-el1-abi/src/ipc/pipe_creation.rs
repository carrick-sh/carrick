//! Retained pipe-creation custody across user copy and bounded lock refusal.
use super::{End, IpcBacking, IpcError, IpcPipeStorage, IpcRegion, IpcReleased, LockWait};
use carrick_fd_core::reservation::SlotPairReservation;
use carrick_fd_core::{AccessMode, BackingToken, Description, Fd, OfdPin, StatusFlags, TableId};

struct BorrowedWait<'a, W>(&'a W);
impl<W: LockWait> LockWait for BorrowedWait<'_, W> {
    fn wait(&self, attempt: u32) -> bool {
        self.0.wait(attempt)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Preparing,
    Published,
    Cancelling,
    SettledPublished,
    SettledCancelled,
}

/// One creation operation, including unpublished endpoint references and both
/// numeric claims. No table or object lock survives a method call. The caller
/// retains this operation on refusal, including Busy, and enrolls with its
/// execution owner before retrying. Never translate contention into an errno.
///
/// Prepare, copy `fds()` to userspace, then publish and finish. A copy fault
/// cancels claims rather than closing numbers. `finish` and `cancel` deliver
/// physical release effects outside the descriptor and object locks.
#[must_use = "retain creation custody until finish or cancel has settled"]
pub struct PendingPipePair<'a> {
    region: IpcRegion<'a>,
    table: TableId,
    capacity: usize,
    flags: StatusFlags,
    cloexec: bool,
    claim: Option<SlotPairReservation>,
    pins: [Option<OfdPin>; 2],
    backings: [Option<BackingToken>; 2],
    created: bool,
    phase: Phase,
}

impl<'a> PendingPipePair<'a> {
    pub fn new(
        region: IpcRegion<'a>,
        table: TableId,
        capacity: usize,
        flags: StatusFlags,
        cloexec: bool,
    ) -> Self {
        Self {
            region,
            table,
            capacity,
            flags,
            cloexec,
            claim: None,
            pins: [None, None],
            backings: [None, None],
            created: false,
            phase: Phase::Preparing,
        }
    }

    /// Supply independently owned pipe storage. Its ownership follows
    /// `IpcRegion::create_backed_pipe`, including on a later OFD refusal.
    /// Re-entry resumes the admitted stage without creating another object.
    pub fn prepare<W: LockWait>(
        &mut self,
        storage: &mut IpcPipeStorage,
        wait: &W,
    ) -> Result<(), IpcError> {
        if self.phase != Phase::Preparing {
            return Err(IpcError::Corrupt);
        }
        let authority = self.region.fd(BorrowedWait(wait));
        if self.claim.is_none() {
            self.claim = Some(
                authority
                    .reserve_pair(self.table, Fd(0))
                    .map_err(IpcError::Fd)?,
            );
        }
        if !self.created {
            let object = self
                .region
                .create_backed_pipe(self.capacity, storage, wait)?;
            self.backings = [
                Some(
                    IpcBacking::Pipe {
                        object,
                        end: End::Reader,
                    }
                    .encode(),
                ),
                Some(
                    IpcBacking::Pipe {
                        object,
                        end: End::Writer,
                    }
                    .encode(),
                ),
            ];
            self.created = true;
        }
        for index in 0..2 {
            if let Some(backing) = self.backings[index] {
                let access = if index == 0 {
                    AccessMode::ReadOnly
                } else {
                    AccessMode::WriteOnly
                };
                let pin = authority
                    .create_pinned(Description::new(backing, access, self.flags))
                    .map_err(IpcError::Fd)?;
                self.pins[index] = Some(pin);
                self.backings[index] = None;
            }
        }
        Ok(())
    }

    /// Numbers are available only once both descriptions are prepared. Neither
    /// is visible to lookup or fork until successful publication.
    pub fn fds(&self) -> Option<[Fd; 2]> {
        if self.phase != Phase::Preparing || self.pins.iter().any(Option::is_none) {
            return None;
        }
        self.claim.as_ref().map(SlotPairReservation::fds)
    }

    /// Commit the pair with the fd authority's one sequence write. The caller
    /// must have completed copyout; refusal preserves the exact claims/pins.
    pub fn publish<W: LockWait>(&mut self, wait: &W) -> Result<(), IpcError> {
        if self.phase != Phase::Preparing {
            return Err(IpcError::Corrupt);
        }
        let [Some(reader), Some(writer)] = &self.pins else {
            return Err(IpcError::Corrupt);
        };
        let claim = self.claim.take().ok_or(IpcError::Corrupt)?;
        match self
            .region
            .fd(BorrowedWait(wait))
            .commit_pair(claim, [reader, writer], self.cloexec)
        {
            Ok(_) => {
                self.phase = Phase::Published;
                Ok(())
            }
            Err(refusal) => {
                let error = refusal.error();
                self.claim = Some(refusal.into_reservation());
                Err(IpcError::Fd(error))
            }
        }
    }

    /// Revoke only unpublished claims and release the owned endpoints. A
    /// retired table already revoked the claims; its generation is never reused
    /// through this receipt. Cancellation cannot undo a published pair.
    pub fn cancel<W: LockWait>(
        &mut self,
        wait: &W,
        deliver: impl FnMut(IpcReleased),
    ) -> Result<(), IpcError> {
        match self.phase {
            Phase::Preparing => self.phase = Phase::Cancelling,
            Phase::Cancelling => {}
            Phase::SettledCancelled => return Ok(()),
            _ => return Err(IpcError::Corrupt),
        }
        if let Some(claim) = self.claim.take() {
            if let Err(refusal) = self.region.fd(BorrowedWait(wait)).cancel_pair(claim) {
                if refusal.error() != carrick_fd_core::Error::StaleTable {
                    let error = refusal.error();
                    self.claim = Some(refusal.into_reservation());
                    return Err(IpcError::Fd(error));
                }
            }
        }
        self.release(wait, deliver)?;
        self.phase = Phase::SettledCancelled;
        Ok(())
    }

    /// Drop creation pins after publication. Concurrent close may leave this
    /// operation owning the final backing; retain it on object-lock refusal.
    pub fn finish<W: LockWait>(
        &mut self,
        wait: &W,
        deliver: impl FnMut(IpcReleased),
    ) -> Result<(), IpcError> {
        match self.phase {
            Phase::Published => {}
            Phase::SettledPublished => return Ok(()),
            _ => return Err(IpcError::Corrupt),
        }
        self.release(wait, deliver)?;
        self.phase = Phase::SettledPublished;
        Ok(())
    }

    fn release<W: LockWait>(
        &mut self,
        wait: &W,
        mut deliver: impl FnMut(IpcReleased),
    ) -> Result<(), IpcError> {
        for index in 0..2 {
            if let Some(pin) = self.pins[index].take() {
                // Invalid pins are broken invariants, never a retryable lock
                // refusal: unpin is atomic and does not acquire a table lock.
                if let Some(description) = self
                    .region
                    .fd(BorrowedWait(wait))
                    .unpin(pin)
                    .map_err(IpcError::Fd)?
                {
                    self.backings[index] = Some(description.backing);
                }
            }
            if let Some(backing) = self.backings[index] {
                let released = self.region.release_backing(backing, wait)?;
                self.backings[index] = None;
                deliver(released);
            }
        }
        Ok(())
    }

    pub fn is_settled(&self) -> bool {
        matches!(
            self.phase,
            Phase::SettledPublished | Phase::SettledCancelled
        )
    }
}
