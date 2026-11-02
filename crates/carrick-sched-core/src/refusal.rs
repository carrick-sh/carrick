//! Typed refusal of an owned operation. Contention retains an authenticated
//! release source and the revision observed before the failed probe.
use crate::object_wait::{
    BorrowedObjectNotificationSource, ObjectNotificationTicket, ObjectWaitSnapshot,
};
use crate::spaces::notification::{
    SpaceNotificationIdentity, SpaceNotificationLease, SpaceWaitCause,
};
use crate::{ThreadCtx, ZoneTables};

/// A named neutral invariant; the execution venue supplies its fatal policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvariantKind {
    pub domain: &'static str,
    pub code: u16,
}

/// Post-commit results cannot contain a new contention refusal.
#[derive(Debug)]
pub enum Settled<G> {
    Invariant(InvariantKind),
    Guest(G),
}

/// A refusal retains the operation's distinction between waiting, a broken
/// invariant, and a personality-defined answer. There is no errno conversion.
#[derive(Debug)]
#[must_use]
pub enum Refusal<'z, G, C: Copy + Send + Sync + zerocopy::FromZeros = ThreadCtx> {
    Contended(ReleaseTicket<'z, C>),
    Invariant(InvariantKind),
    Guest(G),
}
impl<'z, G, C: Copy + Send + Sync + zerocopy::FromZeros> Refusal<'z, G, C> {
    pub fn map_guest<H>(self, f: impl FnOnce(G) -> H) -> Refusal<'z, H, C> {
        match self {
            Self::Contended(ticket) => Refusal::Contended(ticket),
            Self::Invariant(kind) => Refusal::Invariant(kind),
            Self::Guest(g) => Refusal::Guest(f(g)),
        }
    }
}

/// A probe must be side-effect free on a miss. A committed operation must
/// first construct a checkpoint owning its committed result before probing.
#[derive(Debug)]
pub enum Attempt<G> {
    Contended(ReleaseCause),
    Settled(Settled<G>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseCause {
    Object,
    Space(SpaceWaitCause),
}
impl ReleaseCause {
    fn index(self) -> usize {
        match self {
            Self::Object => 0,
            Self::Space(c) => c as usize + 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelReason {
    OperationCancelled,
    OperationCompleted,
    Superseded,
}

/// A race at enrollment returns the exact owned operation for one immediate
/// rerun. It is never an invariant failure or a guest errno.
#[derive(Debug)]
#[must_use]
pub enum Rerun<T, O = T> {
    Now(O),
    Park(T),
}

struct Custody<'z, C: Copy + Send + Sync + zerocopy::FromZeros> {
    notification: ObjectNotificationTicket<'z, C>,
    observed: ObjectWaitSnapshot,
    cause: ReleaseCause,
    identity: Option<SpaceNotificationIdentity>,
}

/// A linear ticket, constructed only by an attached source's observe/probe.
///
/// ```compile_fail,E0599
/// use carrick_sched_core::refusal::ReleaseTicket;
/// let ticket = ReleaseTicket::new();
/// ```
/// ```compile_fail,E0599
/// use carrick_sched_core::refusal::ReleaseTicket;
/// fn duplicate(t: ReleaseTicket<'_>) { let _ = t.clone(); }
/// ```
/// ```compile_fail,E0277
/// use carrick_sched_core::refusal::{Refusal, Settled};
/// fn commit(r: Refusal<'_, u16>) -> Settled<u16> { r.into() }
/// ```
/// ```compile_fail,E0277
/// use carrick_sched_core::refusal::ReleaseTicket;
/// fn errno(t: ReleaseTicket<'_>) -> i32 { t.into() }
/// ```
#[must_use = "park and rerun the owned operation, or explicitly cancel the ticket"]
pub struct ReleaseTicket<'z, C: Copy + Send + Sync + zerocopy::FromZeros = ThreadCtx> {
    custody: Custody<'z, C>,
    discharged: bool,
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> core::fmt::Debug for ReleaseTicket<'_, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReleaseTicket").finish_non_exhaustive()
    }
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> Drop for ReleaseTicket<'_, C> {
    fn drop(&mut self) {
        if !self.discharged {
            self.custody.notification.record_dropped_ticket();
            // Abandonment is a broken ownership invariant in every build,
            // including signed gates; it is not a contention verdict.
            // Host unwinding must preserve the original panic, not abort the
            // carrier with a second panic. Bare guest venues do not unwind.
            #[cfg(not(target_os = "none"))]
            if std::thread::panicking() {
                return;
            }
            assert!(
                self.discharged,
                "release ticket abandoned without park or cancellation"
            );
        }
    }
}
/// Authenticated enrollment data, borrowed only while the linear ticket's
/// notification custody is retained. Adapters use the existing object queue.
pub struct TicketEnrollment<'a, 'z, C: Copy + Send + Sync + zerocopy::FromZeros> {
    custody: &'a Custody<'z, C>,
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> TicketEnrollment<'_, '_, C> {
    pub fn observed(&self) -> ObjectWaitSnapshot {
        self.custody.observed
    }
    pub fn cause(&self) -> ReleaseCause {
        self.custody.cause
    }
    pub fn identity(&self) -> Option<SpaceNotificationIdentity> {
        self.custody.identity
    }
    pub fn key(&self) -> crate::object_wait::ObjectWaitKey {
        self.custody.notification.key()
    }
    pub fn belongs_to(&self, zone: &ZoneTables<C>) -> bool {
        self.custody.notification.belongs_to(zone)
    }
    pub fn unchanged(&self) -> bool {
        self.custody.notification.unchanged(self.custody.observed)
            && self
                .custody
                .identity
                .is_none_or(|id| self.custody.notification.space_is_live(id))
    }
}
impl<'z, C: Copy + Send + Sync + zerocopy::FromZeros> ReleaseTicket<'z, C> {
    pub fn cancel(mut self, reason: CancelReason) {
        self.custody.notification.record_cancelled_ticket(reason);
        self.discharged = true;
    }

    /// The sole transfer to an entry adapter. The adapter must return ownership
    /// on a revision/source race and park through the existing scheduler path.
    ///
    /// # Safety
    /// This is an entry-adapter boundary. The adapter must retain `op` in the
    /// existing scheduler queue or return it for immediate rerun, and release
    /// execution capacity after publication. No object guard may cross a park.
    pub unsafe fn park_and_rerun<O, T>(
        mut self,
        op: O,
        enroll: impl FnOnce(O, TicketEnrollment<'_, 'z, C>) -> T,
    ) -> T {
        self.discharged = true;
        enroll(
            op,
            TicketEnrollment {
                custody: &self.custody,
            },
        )
    }
}

#[doc(hidden)]
pub type SourceObservation<'z, C> = (
    ObjectNotificationTicket<'z, C>,
    ObjectWaitSnapshot,
    Option<SpaceNotificationIdentity>,
);

mod sealed {
    pub trait Sealed {}
}
/// Sealed: an unnotified holder cannot manufacture a release ticket.
///
/// ```compile_fail,E0277
/// use carrick_sched_core::refusal::ContentionSource;
/// struct Unattached;
/// impl<'z> ContentionSource<'z> for Unattached {}
/// ```
pub trait ContentionSource<'z, C: Copy + Send + Sync + zerocopy::FromZeros = ThreadCtx>:
    sealed::Sealed
{
    #[doc(hidden)]
    fn observation(&self, cause: ReleaseCause) -> Option<SourceObservation<'z, C>>;

    /// Each newly encountered cause is observed before retrying the predicate.
    /// Revisited causes already have a pre-probe observation. The finite cause
    /// set bounds the probes to one plus its size, without polling or observing
    /// after failure.
    fn contend<T, G>(
        &self,
        mut probe: impl FnMut() -> Result<T, Attempt<G>>,
    ) -> Result<T, Refusal<'z, G, C>> {
        match probe() {
            Ok(value) => Ok(value),
            Err(Attempt::Settled(Settled::Guest(g))) => Err(Refusal::Guest(g)),
            Err(Attempt::Settled(Settled::Invariant(k))) => Err(Refusal::Invariant(k)),
            Err(Attempt::Contended(cause)) => contend_cold(self, cause, probe),
        }
    }
}

#[cold]
#[inline(never)]
fn contend_cold<'z, S, C, T, G>(
    source: &S,
    mut cause: ReleaseCause,
    mut probe: impl FnMut() -> Result<T, Attempt<G>>,
) -> Result<T, Refusal<'z, G, C>>
where
    C: Copy + Send + Sync + zerocopy::FromZeros,
    S: ContentionSource<'z, C> + ?Sized,
{
    let mut observations = [const { None }; SpaceWaitCause::ALL.len() + 1];
    loop {
        let index = cause.index();
        if let Some(custody) = observations[index].take() {
            return Err(Refusal::Contended(ReleaseTicket {
                custody,
                discharged: false,
            }));
        }
        let Some((notification, observed, identity)) = source.observation(cause) else {
            return Err(Refusal::Invariant(InvariantKind {
                domain: "contention_source",
                code: 1,
            }));
        };
        observations[index] = Some(Custody {
            notification,
            observed,
            cause,
            identity,
        });
        cause = match probe() {
            Ok(value) => return Ok(value),
            Err(Attempt::Settled(Settled::Guest(g))) => return Err(Refusal::Guest(g)),
            Err(Attempt::Settled(Settled::Invariant(k))) => return Err(Refusal::Invariant(k)),
            Err(Attempt::Contended(cause)) => cause,
        };
    }
}

impl<C: Copy + Send + Sync + zerocopy::FromZeros> sealed::Sealed for SpaceNotificationLease<'_, C> {}
impl<'z, C: Copy + Send + Sync + zerocopy::FromZeros> ContentionSource<'z, C>
    for SpaceNotificationLease<'z, C>
{
    fn observation(&self, cause: ReleaseCause) -> Option<SourceObservation<'z, C>> {
        let ReleaseCause::Space(cause) = cause else {
            return None;
        };
        Some((
            self.reserve(cause),
            self.observe(cause),
            Some(self.identity()),
        ))
    }
}
impl<C: Copy + Send + Sync + zerocopy::FromZeros> sealed::Sealed
    for BorrowedObjectNotificationSource<'_, '_, C>
{
}
impl<'scope, 'z, C: Copy + Send + Sync + zerocopy::FromZeros> ContentionSource<'z, C>
    for BorrowedObjectNotificationSource<'scope, 'z, C>
{
    fn observation(&self, cause: ReleaseCause) -> Option<SourceObservation<'z, C>> {
        if cause != ReleaseCause::Object {
            return None;
        }
        Some((self.reserve(), self.observe(), None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_wait::ObjectWaitKey;
    use crate::{ShortLockSpin, ZoneTables};
    use std::boxed::Box;

    fn zone() -> Box<ZoneTables> {
        // SAFETY: ZoneTables has an all-zero initial state; allocate off-stack.
        unsafe {
            let p = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!p.is_null());
            Box::from_raw(p.cast())
        }
    }

    #[test]
    fn attached_source_probes_before_issuing_ticket() {
        let zone = zone();
        let key = ObjectWaitKey::new(1, 7).unwrap();
        zone.bind_object_wait_with_completion(key, &ShortLockSpin, &|_| {})
            .unwrap();
        let source = zone
            .admit_object_notification(key, &ShortLockSpin, &|_| {})
            .unwrap()
            .into_source();
        let mut probes = 0;
        let ticket = source
            .borrow()
            .contend(|| {
                probes += 1;
                Err::<(), _>(Attempt::<()>::Contended(ReleaseCause::Object))
            })
            .unwrap_err();
        assert_eq!(probes, 2);
        let Refusal::Contended(ticket) = ticket else {
            panic!("expected contention")
        };
        ticket.cancel(CancelReason::OperationCancelled);
    }
}

#[cfg(test)]
mod queue_witnesses {
    use super::*;
    use crate::object_wait::{OperationToken, OwnedObjectWakeEffects};
    use crate::spaces::notification::{SpaceReleaseVenue, SpaceWakeDelivery};
    use crate::{ShortLockSpin, ThreadIdentity, Waker};
    use core::num::NonZeroU64;
    use std::boxed::Box;

    fn zone() -> Box<ZoneTables> {
        // SAFETY: zero is the initial state, allocated directly off-stack.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<ZoneTables>());
            assert!(!ptr.is_null());
            Box::from_raw(ptr.cast())
        }
    }
    fn complete(effects: OwnedObjectWakeEffects<'_>) {
        let _ = effects.deliver_handbacks(&mut |_| {});
    }
    fn deliver(_: &ZoneTables, _: Waker, effects: OwnedObjectWakeEffects<'_>) {
        complete(effects);
    }
    fn venue(zone: &ZoneTables) -> SpaceReleaseVenue<'_> {
        SpaceReleaseVenue {
            zone,
            waker: Waker::Host,
            deliver: SpaceWakeDelivery::Function(deliver),
        }
    }
    fn source(zone: &ZoneTables) -> SpaceNotificationLease<'_> {
        zone.spaces.publish_closed(77, 0x30000, 0x30000).unwrap();
        let entry = zone.space_entry(NonZeroU64::new(77).unwrap()).unwrap();
        entry
            .admit_notifications(NonZeroU64::MIN, &ShortLockSpin, &complete)
            .unwrap();
        entry.notifications(NonZeroU64::MIN).unwrap()
    }
    fn contend<'z>(source: &SpaceNotificationLease<'z>, cause: SpaceWaitCause) -> Refusal<'z, ()> {
        source
            .contend(|| Err::<(), _>(Attempt::Contended(ReleaseCause::Space(cause))))
            .unwrap_err()
    }
    #[test]
    fn switched_cause_uses_its_own_preprobe_revision() {
        let zone = zone();
        let source = source(&zone);
        let mut probes = 0;
        let result = source.contend(|| {
            probes += 1;
            Err::<(), _>(Attempt::<()>::Contended(ReleaseCause::Space(
                if probes == 1 {
                    SpaceWaitCause::Editor
                } else {
                    SpaceWaitCause::Gate
                },
            )))
        });
        let Err(Refusal::Contended(ticket)) = result else {
            panic!("ticket");
        };
        assert_eq!(
            probes, 3,
            "cause switch must observe the second cause then re-probe"
        );
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe {
            ticket.park_and_rerun((), |(), enrollment| {
                assert_eq!(enrollment.key(), source.key(SpaceWaitCause::Gate));
                assert_eq!(
                    enrollment.cause(),
                    ReleaseCause::Space(SpaceWaitCause::Gate)
                );
                assert!(enrollment.unchanged());
            })
        };
    }
    #[test]
    fn release_between_miss_and_park_returns_owned_operation() {
        let zone = zone();
        let source = source(&zone);
        let Refusal::Contended(ticket) = contend(&source, SpaceWaitCause::Gate) else {
            panic!("ticket");
        };
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    crate::spaces::notification::SpaceAccess::notified(venue(&zone))
                        .open(zone.spaces.find(77).unwrap());
                })
                .join()
                .unwrap();
        });
        let op = OperationToken::new(91, 3).unwrap();
        let rerun = // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe { ticket.park_and_rerun(op, |op, enrollment| {
            if enrollment.unchanged() {
                Rerun::Park(op)
            } else {
                Rerun::Now(op)
            }
        }) };
        let Rerun::Now(op) = rerun else {
            panic!("release must cause immediate rerun");
        };
        assert_eq!((op.index(), op.generation()), (91, 3));
    }
    #[test]
    fn retired_source_reruns_then_returns_guest_answer() {
        let zone = zone();
        let source = source(&zone);
        let Refusal::Contended(ticket) = contend(&source, SpaceWaitCause::Gate) else {
            panic!("ticket");
        };
        zone.space_entry(NonZeroU64::new(77).unwrap())
            .unwrap()
            .retire_entry(venue(&zone));
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe { ticket.park_and_rerun((), |(), enrollment| assert!(!enrollment.unchanged())) };
        let answer = source.contend(|| {
            zone.spaces
                .try_begin_edit_cause(
                    zone.spaces.find(77).unwrap(),
                    77,
                    NonZeroU64::MIN,
                    Some(venue(&zone)),
                )
                .map_err(|refusal| match refusal {
                    crate::spaces::EditAdmissionRefusal::Stale => {
                        Attempt::Settled(Settled::Guest("retired"))
                    }
                    _ => panic!("retired space must refuse as stale"),
                })
        });
        assert!(matches!(answer, Err(Refusal::Guest("retired"))));
    }
    #[test]
    fn parked_operation_has_exactly_one_wake() {
        let zone = zone();
        let source = source(&zone);
        let Refusal::Contended(ticket) = contend(&source, SpaceWaitCause::Gate) else {
            panic!("ticket");
        };
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 77,
                serial: 1,
                mm: 77,
                file_table: 1,
                generation: 1,
                affinity_source: crate::AffinitySource::UNBOUND,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        // SAFETY: this adapter transfers the owned operation through the existing
        // scheduler enrollment or returns it; witnesses use the same real queue.
        unsafe {
            ticket.park_and_rerun(
                OperationToken::new(91, 3).unwrap(),
                |operation, enrollment| {
                    zone.object_wait_with_completion(enrollment.key(), &ShortLockSpin, &complete)
                        .unwrap()
                        .park_host_rechecked(enrollment.observed(), record, operation, || true)
                        .unwrap();
                },
            )
        };
        let queue = zone
            .object_wait_with_completion(
                source.key(SpaceWaitCause::Gate),
                &ShortLockSpin,
                &complete,
            )
            .unwrap();
        let mut handed = 0;
        let first = queue
            .notify_object_host(&mut |_| handed += 1, &mut |_| {})
            .unwrap();
        let second = queue
            .notify_object_host(&mut |_| handed += 1, &mut |_| {})
            .unwrap();
        assert_eq!(first.visited, 1);
        assert_eq!(second.visited, 0);
        assert_eq!(handed, 1);
    }
    #[test]
    fn abandoned_ticket_during_unwind_preserves_original_panic() {
        let zone = zone();
        let source = source(&zone);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Refusal::Contended(_ticket) = contend(&source, SpaceWaitCause::Gate) else {
                panic!("ticket");
            };
            panic!("original panic");
        }))
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"original panic"));
        assert_eq!(
            zone.counters
                .contention_tickets_dropped
                .load(core::sync::atomic::Ordering::Relaxed),
            1
        );
    }
    #[test]
    fn cancelled_ticket_does_not_count_as_abandoned() {
        let zone = zone();
        let source = source(&zone);
        let Refusal::Contended(ticket) = contend(&source, SpaceWaitCause::Gate) else {
            panic!("ticket");
        };
        ticket.cancel(CancelReason::OperationCancelled);
        assert_eq!(
            zone.counters.contention_tickets_cancelled[CancelReason::OperationCancelled as usize]
                .load(core::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            zone.counters
                .contention_tickets_dropped
                .load(core::sync::atomic::Ordering::Relaxed),
            0
        );
        let Refusal::Contended(ticket) = contend(&source, SpaceWaitCause::Gate) else {
            panic!("ticket");
        };
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(ticket))).is_err());
        assert_eq!(
            zone.counters
                .contention_tickets_dropped
                .load(core::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}
