//! Owned numeric slot claims. These are operations, not descriptor entries:
//! lookups still see the prior description, fork does not inherit claims, and
//! close cannot make a claimed number available to an unrelated opener.
use super::{
    Authority, DeferredRelease, Description, Entry, Error, Fd, LockWait, OfdPin, REF, SlotBacking,
    TableId,
};

/// One reservation in an exact table incarnation. Move into commit or cancel;
/// on refusal ownership is returned, including lock contention. Like OfdPin,
/// this pointer-free receipt can live in an owned operation continuation.
/// The venue must retain it until settlement or table retirement.
#[must_use = "settle this reservation or retain it in the operation continuation"]
#[derive(Debug)]
pub struct SlotReservation {
    table: TableId,
    fd: Fd,
}

impl SlotReservation {
    pub const fn fd(&self) -> Fd {
        self.fd
    }
    pub const fn table(&self) -> TableId {
        self.table
    }
}

/// A refused settlement still owns the numeric claim; it never loses custody.
#[must_use]
#[derive(Debug)]
pub struct ReservationRefusal {
    error: Error,
    reservation: SlotReservation,
}

impl ReservationRefusal {
    pub const fn error(&self) -> Error {
        self.error
    }
    pub fn into_reservation(self) -> SlotReservation {
        self.reservation
    }
}

impl<B: SlotBacking, W: LockWait, const T: usize> Authority<'_, B, W, T> {
    /// Reserve the lowest free slot at or above min. A claim has no OFD and
    /// cannot be read, duplicated or inherited as an open descriptor.
    pub fn reserve_min(&self, table: TableId, min: Fd) -> Result<SlotReservation, Error> {
        if min.0 < 0 {
            return Err(Error::InvalidArgument);
        }
        let (_guard, t) = self.lock(table)?;
        let fd = t.allocate(min.0 as usize)?;
        t.storage.reserve(fd);
        Ok(SlotReservation {
            table,
            fd: Fd(fd as i32),
        })
    }

    /// F_DUPFD/F_DUPFD_CLOEXEC admission: unlike open/dup's lowest-slot
    /// selection, a minimum at or above the soft limit is EINVAL.
    pub fn reserve_dup_min(&self, table: TableId, min: Fd) -> Result<SlotReservation, Error> {
        let (_guard, t) = self.lock(table)?;
        if min.0 < 0 || min.0 as usize >= t.limit {
            return Err(Error::InvalidArgument);
        }
        let fd = t.allocate(min.0 as usize)?;
        t.storage.reserve(fd);
        Ok(SlotReservation {
            table,
            fd: Fd(fd as i32),
        })
    }

    /// Reserve an exact replacement target without hiding its current OFD.
    /// Competing dup2/dup3 or replacement admission returns Busy (Linux EBUSY).
    pub fn reserve_exact(&self, table: TableId, fd: Fd) -> Result<SlotReservation, Error> {
        let (_guard, t) = self.lock(table)?;
        if fd.0 < 0 || fd.0 as usize >= t.limit {
            return Err(Error::BadFd);
        }
        if fd.0 as usize >= t.storage.capacity() {
            return Err(Error::NeedsBacking {
                descriptors: fd.0 as usize + 1,
            });
        }
        if t.storage.reserved(fd.0 as usize) {
            return Err(Error::Busy);
        }
        t.storage.reserve(fd.0 as usize);
        Ok(SlotReservation { table, fd })
    }

    /// Cancel only this operation's claim. Concurrent close/flag changes to
    /// the original descriptor remain effective; cancellation cannot undo them.
    pub fn cancel_reservation(
        &self,
        reservation: SlotReservation,
    ) -> Result<(), ReservationRefusal> {
        let result = (|| {
            let (_guard, t) = self.lock(reservation.table)?;
            if !t.storage.reserved(reservation.fd.0 as usize) {
                return Err(Error::InvalidArgument);
            }
            t.storage.unreserve(reservation.fd.0 as usize);
            Ok(())
        })();
        result.map_err(|error| ReservationRefusal { error, reservation })
    }

    /// Publish a prepared description and consume the claim atomically. Pins
    /// remain caller-owned. The returned final description owns any displaced
    /// physical release and must be consumed outside the descriptor lock.
    /// Lowering RLIMIT_NOFILE after admission does not revoke a reservation.
    pub fn commit_reservation(
        &self,
        reservation: SlotReservation,
        pin: &OfdPin,
        cloexec: bool,
    ) -> Result<Option<Description>, ReservationRefusal> {
        let result = (|| {
            let (_guard, t) = self.lock(reservation.table)?;
            self.check_pin(pin)?;
            let fd = reservation.fd.0 as usize;
            if !t.storage.reserved(fd) {
                return Err(Error::InvalidArgument);
            }
            let covered = self.cover(fd)?;
            // Retain before touching the target. A refusal leaves both its
            // old description and the numeric claim unchanged.
            self.retain(pin.key.index, REF)?;
            let old = t.storage.get(fd);
            t.storage.install(
                covered,
                Entry {
                    ofd: pin.key.index,
                    cloexec,
                },
            );
            t.storage.unreserve(fd);
            match old {
                Some(old) => self.drop_hold(old.ofd, REF),
                None => Ok(None),
            }
        })();
        result.map_err(|error| ReservationRefusal { error, reservation })
    }

    /// Publish a prepared description while deferring selected displaced
    /// physical releases to the authority's host retirement queue.
    pub fn commit_reservation_filtered(
        &self,
        reservation: SlotReservation,
        pin: &OfdPin,
        cloexec: bool,
        release_here: impl FnOnce(Description) -> bool,
    ) -> Result<DeferredRelease, ReservationRefusal> {
        let result = (|| {
            let (_guard, t) = self.lock(reservation.table)?;
            self.check_pin(pin)?;
            let fd = reservation.fd.0 as usize;
            if !t.storage.reserved(fd) {
                return Err(Error::InvalidArgument);
            }
            let covered = self.cover(fd)?;
            self.retain(pin.key.index, REF)?;
            let old = t.storage.get(fd);
            t.storage.install(
                covered,
                Entry {
                    ofd: pin.key.index,
                    cloexec,
                },
            );
            t.storage.unreserve(fd);
            match old {
                Some(old) => self.drop_hold_filtered(old.ofd, REF, release_here),
                None => Ok(DeferredRelease::None),
            }
        })();
        result.map_err(|error| ReservationRefusal { error, reservation })
    }
}

/// Two empty numeric slots held by one pipe-creation operation. Copy their
/// numbers to userspace before committing; a copy fault cancels the claims,
/// so no published endpoint ever needs to be closed by numeric fd on rollback.
#[must_use = "settle this pair or retain it in the operation continuation"]
#[derive(Debug)]
pub struct SlotPairReservation {
    table: TableId,
    fds: [Fd; 2],
}

impl SlotPairReservation {
    pub const fn fds(&self) -> [Fd; 2] {
        self.fds
    }
    pub const fn table(&self) -> TableId {
        self.table
    }
}

/// Both slot claims remain owned on contention or any other refusal.
#[must_use]
#[derive(Debug)]
pub struct PairReservationRefusal {
    error: Error,
    reservation: SlotPairReservation,
}

impl PairReservationRefusal {
    pub const fn error(&self) -> Error {
        self.error
    }
    pub fn into_reservation(self) -> SlotPairReservation {
        self.reservation
    }
}

impl<B: SlotBacking, W: LockWait, const T: usize> Authority<'_, B, W, T> {
    /// Claim two lowest free slots in one table-lock scope. Failure to find
    /// the second slot leaves no first claim behind. Nothing is published;
    /// fork and lock-free lookup see neither endpoint while copyout waits.
    pub fn reserve_pair(&self, table: TableId, min: Fd) -> Result<SlotPairReservation, Error> {
        if min.0 < 0 {
            return Err(Error::InvalidArgument);
        }
        let (_guard, t) = self.lock(table)?;
        let first = t.allocate(min.0 as usize)?;
        let second = t.allocate(first + 1)?;
        // Prepare ceiling coverage before claiming either slot, so a refusal
        // cannot strand a reservation without an owned receipt.
        self.cover(first)?;
        self.cover(second)?;
        t.storage.reserve(first);
        t.storage.reserve(second);
        Ok(SlotPairReservation {
            table,
            fds: [Fd(first as i32), Fd(second as i32)],
        })
    }

    /// Cancel the pair before publication. No descriptor entry or physical
    /// description is closed, including in a sibling table or reused number.
    pub fn cancel_pair(
        &self,
        reservation: SlotPairReservation,
    ) -> Result<(), PairReservationRefusal> {
        let result = (|| {
            let (_guard, t) = self.lock(reservation.table)?;
            for fd in reservation.fds {
                if !t.storage.reserved(fd.0 as usize) || t.storage.get(fd.0 as usize).is_some() {
                    return Err(Error::InvalidArgument);
                }
            }
            for fd in reservation.fds {
                t.storage.unreserve(fd.0 as usize);
            }
            Ok(())
        })();
        result.map_err(|error| PairReservationRefusal { error, reservation })
    }

    /// Publish both prepared descriptions under the same sequence write as
    /// immediate pair installation. Pins remain caller-owned; no user copy,
    /// object release or allocation runs under the table lock. Admission
    /// survives a later lowering of the descriptor limit, like a single claim.
    pub fn commit_pair(
        &self,
        reservation: SlotPairReservation,
        pins: [&OfdPin; 2],
        cloexec: bool,
    ) -> Result<[Fd; 2], PairReservationRefusal> {
        let result = (|| {
            let mut transaction = self.transaction(reservation.table)?;
            for fd in reservation.fds {
                if !transaction.table.storage.reserved(fd.0 as usize)
                    || transaction.table.storage.get(fd.0 as usize).is_some()
                {
                    return Err(Error::InvalidArgument);
                }
            }
            transaction.publish_pair(reservation.fds, pins, cloexec, true)
        })();
        result.map_err(|error| PairReservationRefusal { error, reservation })
    }
}
