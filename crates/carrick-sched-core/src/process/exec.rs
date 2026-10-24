//! Exec admission and sibling-drain custody shared by execution venues.
//!
//! The process owner selects the siblings and retains its reservation. This
//! guard orders release of those owned resources; it never discovers tasks,
//! waits on a host process, or chooses an MM on behalf of the owner.

/// Exact process reservation. Drop releases uncommitted admission; committing
/// keeps birth admission closed after publication of the successor.
pub trait ExecReservation {
    type Transaction: Copy;
    fn transaction(&self) -> Self::Transaction;
    fn commit(&mut self);
}

/// Already admitted sibling drain. Each operation consumes its custody only
/// after the venue has acknowledged the disposition of every predecessor.
pub trait ExecSiblingDrain {
    fn resume(self);
    fn terminate(self);
}

/// One rollback boundary, retained across image preparation and publication.
/// Before no-return, drop restores siblings before releasing admission. After
/// no-return, drop terminates them; an old image must never become runnable.
#[must_use = "retain exec custody until publication or terminal failure"]
pub struct ExecOperationGuard<R: ExecReservation, D: ExecSiblingDrain> {
    reservation: Option<R>,
    drain: Option<D>,
    no_return: bool,
}

impl<R: ExecReservation, D: ExecSiblingDrain> ExecOperationGuard<R, D> {
    pub fn new(reservation: R) -> Self {
        Self {
            reservation: Some(reservation),
            drain: None,
            no_return: false,
        }
    }

    pub fn reservation_mut(&mut self) -> Option<&mut R> {
        self.reservation.as_mut()
    }

    pub fn reservation(&self) -> Option<&R> {
        self.reservation.as_ref()
    }

    /// Install the sole admitted drain without dropping an earlier one. A
    /// refused second drain remains owned by the caller.
    pub fn attach_drain(&mut self, drain: D) -> Result<(), D> {
        if self.drain.is_some() {
            return Err(drain);
        }
        self.drain = Some(drain);
        Ok(())
    }

    pub fn terminate_siblings(&mut self) {
        if let Some(drain) = self.drain.take() {
            drain.terminate();
        }
    }

    pub fn commit_reservation(&mut self) {
        if let Some(mut reservation) = self.reservation.take() {
            reservation.commit();
        }
    }

    pub fn enter_no_return(&mut self) {
        self.no_return = true;
    }

    pub fn transaction(&self) -> Option<R::Transaction> {
        self.reservation.as_ref().map(ExecReservation::transaction)
    }
}

impl<R: ExecReservation, D: ExecSiblingDrain> Drop for ExecOperationGuard<R, D> {
    fn drop(&mut self) {
        if self.no_return {
            self.terminate_siblings();
        } else if let Some(drain) = self.drain.take() {
            drain.resume();
        }
        // Release admission last, including on rollback. A new mutator may
        // not acquire the process while predecessor runners still settle.
        drop(self.reservation.take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Resume(u32),
        Terminate(u32),
        Commit(u32),
        Release(u32),
    }

    type Events = Rc<RefCell<Vec<Event>>>;

    struct Reservation(u32, Events);
    impl ExecReservation for Reservation {
        type Transaction = u32;
        fn transaction(&self) -> u32 {
            self.0
        }
        fn commit(&mut self) {
            self.1.borrow_mut().push(Event::Commit(self.0));
        }
    }
    impl Drop for Reservation {
        fn drop(&mut self) {
            self.1.borrow_mut().push(Event::Release(self.0));
        }
    }
    struct Drain(u32, Events);
    impl ExecSiblingDrain for Drain {
        fn resume(self) {
            self.1.borrow_mut().push(Event::Resume(self.0));
        }
        fn terminate(self) {
            self.1.borrow_mut().push(Event::Terminate(self.0));
        }
    }

    fn guard(id: u32, events: &Events) -> ExecOperationGuard<Reservation, Drain> {
        let mut guard = ExecOperationGuard::new(Reservation(id, Rc::clone(events)));
        assert!(guard.attach_drain(Drain(id, Rc::clone(events))).is_ok());
        guard
    }

    #[test]
    fn rollback_settles_siblings_before_releasing_admission() {
        let events = Events::default();
        drop(guard(1, &events));
        assert_eq!(*events.borrow(), vec![Event::Resume(1), Event::Release(1)]);
    }

    #[test]
    fn no_return_drop_terminates_and_never_resumes_siblings() {
        let events = Events::default();
        let mut owner = guard(1, &events);
        owner.enter_no_return();
        drop(owner);
        assert_eq!(
            *events.borrow(),
            vec![Event::Terminate(1), Event::Release(1)]
        );
    }

    #[test]
    fn independent_custody_survives_peer_rollback_and_settles_once() {
        let events = Events::default();
        let first = guard(1, &events);
        let mut second = guard(2, &events);
        drop(first);
        assert_eq!(second.transaction(), Some(2));
        assert_eq!(*events.borrow(), vec![Event::Resume(1), Event::Release(1)]);
        second.enter_no_return();
        second.terminate_siblings();
        second.terminate_siblings();
        second.commit_reservation();
        assert_eq!(second.transaction(), None);
        drop(second);
        assert_eq!(
            *events.borrow(),
            vec![
                Event::Resume(1),
                Event::Release(1),
                Event::Terminate(2),
                Event::Commit(2),
                Event::Release(2),
            ]
        );
    }

    #[test]
    fn second_drain_is_returned_without_losing_either_custody() {
        let events = Events::default();
        let mut owner = guard(1, &events);
        let rejected = owner.attach_drain(Drain(2, Rc::clone(&events)));
        assert!(events.borrow().is_empty());
        match rejected {
            Err(drain) => drain.resume(),
            Ok(()) => panic!("second drain replaced the admitted siblings"),
        }
        drop(owner);
        assert_eq!(
            *events.borrow(),
            vec![Event::Resume(2), Event::Resume(1), Event::Release(1)]
        );
    }
}
