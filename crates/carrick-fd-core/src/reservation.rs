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
            // Retain before touching the target. A refusal leaves both its
            // old description and the numeric claim unchanged.
            self.retain(pin.key.index, REF)?;
            let old = t.storage.get(fd);
            t.storage.set(
                fd,
                Some(Entry {
                    ofd: pin.key.index,
                    cloexec,
                }),
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
            self.retain(pin.key.index, REF)?;
            let old = t.storage.get(fd);
            t.storage.set(
                fd,
                Some(Entry {
                    ofd: pin.key.index,
                    cloexec,
                }),
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
