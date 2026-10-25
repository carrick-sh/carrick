//! Neutral point-of-no-return ordering for process-owned exec replacement.
//!
//! Image loading and successor-MM construction happen before this module is
//! entered. The venue methods are deliberately infallible: after
//! [`adopt_native_exec`] marks the shared exec guard no-return, an inability to
//! publish or rebind is a terminal carrier failure, never an errno return to
//! the predecessor image.

extern crate alloc;

use alloc::boxed::Box;
use carrick_sched_core::process::exec::{ExecOperationGuard, ExecReservation, ExecSiblingDrain};

/// All fallible successor construction, retained off an EL1/CPL0 stack.
pub struct PreparedNativeExec<I, M, F> {
    pub image: I,
    pub successor_mm: M,
    pub close_on_exec: F,
}

/// The process-owner operations that are legal after exec's point of no
/// return. None may fail back into the predecessor image.
pub trait NativeExecAdoption<I, M, F> {
    type Published;
    type Output;

    /// Publish physical image backing and open the already-closed successor
    /// MM as one owner transaction.
    fn publish_successor(&mut self, image: I, successor_mm: M) -> Self::Published;

    /// Commit descriptor cutover while the predecessor can no longer run.
    fn commit_close_on_exec(&mut self, files: F);

    /// Retire the predecessor MM through the same owner that published the
    /// successor. Siblings have already acknowledged termination.
    fn retire_predecessor(&mut self, successor: &Self::Published);

    /// Linux exec resets caught dispositions and retains ignored ones.
    fn reset_signal_dispositions(&mut self);

    /// Replace process-registry and scheduler identity with the successor
    /// execution generation. This is the final externally visible step.
    fn rebind_successor(&mut self, successor: Self::Published) -> Self::Output;
}

/// Consume one completely prepared replacement at the sole point of no
/// return. The caller retains the shared guard across all earlier fallible
/// work; dropping it before this call resumes the admitted siblings.
#[allow(
    clippy::boxed_local,
    reason = "the prepared image/MM/file aggregate must stay off EL1/CPL0 stacks"
)]
#[inline(never)]
pub fn adopt_native_exec<R, D, V, I, M, F>(
    guard: &mut ExecOperationGuard<R, D>,
    prepared: Box<PreparedNativeExec<I, M, F>>,
    venue: &mut V,
) -> V::Output
where
    R: ExecReservation,
    D: ExecSiblingDrain,
    V: NativeExecAdoption<I, M, F>,
{
    guard.enter_no_return();
    guard.terminate_siblings();
    let PreparedNativeExec {
        image,
        successor_mm,
        close_on_exec,
    } = *prepared;
    let successor = venue.publish_successor(image, successor_mm);
    venue.commit_close_on_exec(close_on_exec);
    venue.retire_predecessor(&successor);
    venue.reset_signal_dispositions();
    let output = venue.rebind_successor(successor);
    guard.commit_reservation();
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        ResumeSibling,
        TerminateSibling,
        ReleaseReservation,
        CommitReservation,
        Publish,
        CloseFiles,
        RetireOldMm,
        ResetSignals,
        Rebind,
    }

    type Events = Rc<RefCell<Vec<Event>>>;

    struct Reservation(Events);
    impl ExecReservation for Reservation {
        type Transaction = ();
        fn transaction(&self) {}
        fn commit(&mut self) {
            self.0.borrow_mut().push(Event::CommitReservation);
        }
    }
    impl Drop for Reservation {
        fn drop(&mut self) {
            self.0.borrow_mut().push(Event::ReleaseReservation);
        }
    }

    struct Drain(Events);
    impl ExecSiblingDrain for Drain {
        fn resume(self) {
            self.0.borrow_mut().push(Event::ResumeSibling);
        }
        fn terminate(self) {
            self.0.borrow_mut().push(Event::TerminateSibling);
        }
    }

    struct Venue(Events);
    impl NativeExecAdoption<u8, u8, u8> for Venue {
        type Published = u8;
        type Output = u8;
        fn publish_successor(&mut self, image: u8, mm: u8) -> u8 {
            self.0.borrow_mut().push(Event::Publish);
            image + mm
        }
        fn commit_close_on_exec(&mut self, _: u8) {
            self.0.borrow_mut().push(Event::CloseFiles);
        }
        fn retire_predecessor(&mut self, _: &u8) {
            self.0.borrow_mut().push(Event::RetireOldMm);
        }
        fn reset_signal_dispositions(&mut self) {
            self.0.borrow_mut().push(Event::ResetSignals);
        }
        fn rebind_successor(&mut self, successor: u8) -> u8 {
            self.0.borrow_mut().push(Event::Rebind);
            successor
        }
    }

    fn guard(events: &Events) -> ExecOperationGuard<Reservation, Drain> {
        let mut guard = ExecOperationGuard::new(Reservation(Rc::clone(events)));
        guard
            .attach_drain(Drain(Rc::clone(events)))
            .unwrap_or_else(|_| unreachable!());
        guard
    }

    #[test]
    fn rollback_before_adoption_preserves_predecessor() {
        let events = Events::default();
        drop(guard(&events));
        assert_eq!(
            *events.borrow(),
            vec![Event::ResumeSibling, Event::ReleaseReservation]
        );
    }

    #[test]
    fn adoption_has_one_infallible_point_of_no_return() {
        let events = Events::default();
        let mut guard = guard(&events);
        let output = adopt_native_exec(
            &mut guard,
            Box::new(PreparedNativeExec {
                image: 3,
                successor_mm: 4,
                close_on_exec: 5,
            }),
            &mut Venue(Rc::clone(&events)),
        );
        assert_eq!(output, 7);
        drop(guard);
        assert_eq!(
            *events.borrow(),
            vec![
                Event::TerminateSibling,
                Event::Publish,
                Event::CloseFiles,
                Event::RetireOldMm,
                Event::ResetSignals,
                Event::Rebind,
                Event::CommitReservation,
                Event::ReleaseReservation,
            ]
        );
    }
}
