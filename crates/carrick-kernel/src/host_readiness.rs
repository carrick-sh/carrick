//! Host readiness of the host objects a native member waits on (#231).
//!
//! A host network socket is a real host object, so its readiness is a host
//! crossing: when a native call on one would block, the carrier sampled the
//! member's host-readiness queue before its non-blocking probe, enrols the
//! host descriptors with the carrier's one wait reactor (the
//! [`CarrierWaitService`](crate::kernel::continuation::CarrierWaitService)
//! that also serves the run root's host-fd waits) and answers the member's
//! service with an owner wait on that queue. When the host reports a
//! descriptor ready, or a poll's deadline passes, the reactor notifies the
//! queue and the member reruns its call once. Nothing polls, no second
//! reactor thread exists, and a member's execution capacity is released
//! while it waits.
//!
//! A member waits in at most one call, so its enrolments are that call's: a
//! new wait replaces them, and they are dropped once notified. Enrolments
//! hold their own duplicate of the host descriptor and are dropped by their
//! source when the guest's last descriptor closes, so a closed socket never
//! lingers in the reactor's poll set.

use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::el1_zone::CarrierZone;
use crate::kernel::continuation::CarrierWaitService;

/// The identity of one enrolled host object, so its source can drop its
/// enrolments when the object closes: the address of a token the source
/// owns for its whole life ([`HostReadinessToken`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct HostReadinessSource(usize);

/// A host object's readiness identity, held for the object's life.
#[derive(Debug)]
pub(crate) struct HostReadinessToken(Box<u8>);

impl HostReadinessToken {
    pub(crate) fn new() -> Self {
        Self(Box::new(0))
    }

    pub(crate) fn source(&self) -> HostReadinessSource {
        HostReadinessSource(&*self.0 as *const u8 as usize)
    }
}

/// One host descriptor of a member's wait.
pub(crate) struct HostReadinessInterest<'a> {
    pub(crate) source: HostReadinessSource,
    pub(crate) fd: std::os::fd::BorrowedFd<'a>,
    /// Host poll bits.
    pub(crate) events: i16,
}

/// The member a host-readiness wait notifies: its ring record, exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct HostReadyKey {
    record: u32,
    incarnation: u64,
}

impl HostReadyKey {
    fn of(record: carrick_el1_abi::RecordRef) -> Self {
        Self {
            record: record.id.raw(),
            incarnation: record.incarnation,
        }
    }
}

/// One member's enrolled wait in the reactor: the host descriptors it waits
/// on (each the reactor's own duplicate) and its deadline, if any.
pub(crate) struct HostReadyWait {
    record: carrick_el1_abi::RecordRef,
    /// Distinguishes this wait from a later one of the same member, so a
    /// readiness the reactor saw for a replaced wait notifies nobody.
    serial: u64,
    interests: Vec<(HostReadinessSource, OwnedFd, i16)>,
    deadline: Option<Instant>,
    carrier: Option<CarrierZone>,
}

impl std::fmt::Debug for HostReadyWait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostReadyWait")
            .field("record", &self.record)
            .field("serial", &self.serial)
            .field("interests", &self.interests.len())
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl HostReadyWait {
    /// Publish this wait's readiness to its member: the member reruns its
    /// call once.
    pub(crate) fn notify(self) {
        crate::el1_zone::notify_host_ready(self.carrier.as_ref(), self.record);
    }
}

/// The reactor's table of native members' host-readiness waits, held under
/// the wait service's state lock. Every row contributes pollfds (or only a
/// deadline), so a reactor cycle visits exactly the rows it polls.
#[derive(Debug, Default)]
pub(crate) struct HostReadyWaits {
    waits: BTreeMap<HostReadyKey, HostReadyWait>,
    next_serial: u64,
}

impl HostReadyWaits {
    /// Replace `record`'s wait.
    fn enrol(
        &mut self,
        record: carrick_el1_abi::RecordRef,
        interests: Vec<(HostReadinessSource, OwnedFd, i16)>,
        deadline: Option<Instant>,
        carrier: Option<CarrierZone>,
    ) {
        self.next_serial = self.next_serial.wrapping_add(1);
        self.waits.insert(
            HostReadyKey::of(record),
            HostReadyWait {
                record,
                serial: self.next_serial,
                interests,
                deadline,
                carrier,
            },
        );
    }

    /// Drop every wait on `source` (its last guest descriptor closed).
    /// `true` when one was dropped.
    fn forget(&mut self, source: HostReadinessSource) -> bool {
        let before = self.waits.len();
        self.waits
            .retain(|_, wait| !wait.interests.iter().any(|(held, _, _)| *held == source));
        self.waits.len() != before
    }

    /// Append this table's pollfds and their owners, and fold its nearest
    /// deadline into `nearest`.
    pub(crate) fn poll_set(
        &self,
        pollfds: &mut Vec<libc::pollfd>,
        owners: &mut Vec<(HostReadyKey, u64)>,
        nearest: &mut Option<Instant>,
    ) {
        for (key, wait) in &self.waits {
            for (_, fd, events) in &wait.interests {
                pollfds.push(libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: *events,
                    revents: 0,
                });
                owners.push((*key, wait.serial));
            }
            if let Some(deadline) = wait.deadline {
                *nearest = Some(nearest.map_or(deadline, |current| current.min(deadline)));
            }
        }
    }

    /// Take the waits that `fired` (by key and serial) or whose deadline
    /// passed by `now`. Each member is taken once.
    pub(crate) fn take_woken(
        &mut self,
        fired: &[(HostReadyKey, u64)],
        now: Instant,
    ) -> Vec<HostReadyWait> {
        let keys: Vec<HostReadyKey> = self
            .waits
            .iter()
            .filter(|(key, wait)| {
                fired.contains(&(**key, wait.serial))
                    || wait.deadline.is_some_and(|deadline| deadline <= now)
            })
            .map(|(key, _)| *key)
            .collect();
        keys.iter()
            .filter_map(|key| self.waits.remove(key))
            .collect()
    }

    /// Take every wait (the host refused the reactor's poll itself).
    pub(crate) fn take_all(&mut self) -> Vec<HostReadyWait> {
        std::mem::take(&mut self.waits).into_values().collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.waits.len()
    }
}

/// A kernel's route to the carrier wait reactor that serves its native
/// members' host-readiness waits. The executor pool's wait service binds
/// itself here when it starts ([`CarrierWaitService::serve_host_readiness`]);
/// without a live one a wait is refused, never left unobserved.
#[derive(Default)]
pub(crate) struct HostReadinessReactor {
    /// Type-erased: the wait service owns the scheduler, which owns the
    /// kernel that holds this route.
    service: Mutex<Option<Weak<dyn HostReadyTable>>>,
}

impl std::fmt::Debug for HostReadinessReactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostReadinessReactor")
            .field("bound", &self.service().is_some())
            .finish()
    }
}

/// The wait reactor's host-readiness table (#231).
pub(crate) trait HostReadyTable: Send + Sync {
    /// Change the table and, when `change` reports a change, wake the
    /// reactor to rebuild its poll set.
    fn change_host_ready_waits(&self, change: &mut dyn FnMut(&mut HostReadyWaits) -> bool);
    #[cfg(test)]
    fn host_ready_waits(&self) -> usize;
}

impl HostReadinessReactor {
    pub(crate) fn bind(&self, service: &CarrierWaitService) {
        let inner: Arc<dyn HostReadyTable> = service.inner.clone();
        *self.service.lock() = Some(Arc::downgrade(&inner));
    }

    fn service(&self) -> Option<Arc<dyn HostReadyTable>> {
        self.service.lock().as_ref().and_then(Weak::upgrade)
    }

    /// Replace `record`'s host-readiness wait with one on `interests` (each
    /// descriptor duplicated for the reactor) and, if given, `deadline`: the
    /// first to report its events, or the deadline, notifies `record`'s
    /// host-readiness queue. `false` when no reactor serves this kernel or
    /// a descriptor cannot be retained: the caller refuses the wait.
    pub(crate) fn watch(
        &self,
        record: carrick_el1_abi::RecordRef,
        interests: &[HostReadinessInterest<'_>],
        deadline: Option<Instant>,
        carrier: Option<CarrierZone>,
    ) -> bool {
        let Some(service) = self.service() else {
            return false;
        };
        let mut held = Vec::with_capacity(interests.len());
        for interest in interests {
            let Ok(fd) = interest.fd.try_clone_to_owned() else {
                return false;
            };
            held.push((interest.source, fd, interest.events));
        }
        let mut enrolment = Some((held, carrier));
        service.change_host_ready_waits(&mut |waits| {
            if let Some((held, carrier)) = enrolment.take() {
                waits.enrol(record, held, deadline, carrier);
            }
            true
        });
        true
    }

    /// Drop every host-readiness wait on `source`.
    pub(crate) fn forget(&self, source: HostReadinessSource) {
        if let Some(service) = self.service() {
            service.change_host_ready_waits(&mut |waits| waits.forget(source));
        }
    }

    #[cfg(test)]
    pub(crate) fn enrolled(&self) -> usize {
        self.service()
            .map_or(0, |service| service.host_ready_waits())
    }
}

/// A member's poll deadline (#231), keyed by the member and the poll call's
/// ring serial (#2414 review P0-2). The call's first empty snapshot fixes
/// it; every record the ring publishes again for the same call after a
/// readiness wake carries the same serial and keeps it, as Linux keeps one
/// call's timeout across its wakes. A new call, including one issued again
/// after an interruption, carries a new serial and starts its own deadline,
/// which replaces the old call's: a deadline lives no longer than its call.
#[derive(Debug, Default)]
pub(crate) struct PollDeadlines {
    held: Mutex<HashMap<(u32, u64), (carrick_core_abi::host_file::HostCallSerial, Instant)>>,
}

impl PollDeadlines {
    fn key(record: carrick_el1_abi::RecordRef) -> (u32, u64) {
        (record.id.raw(), record.incarnation)
    }

    /// The deadline of `record`'s poll call `call` with `timeout`.
    pub(crate) fn deadline(
        &self,
        record: carrick_el1_abi::RecordRef,
        call: carrick_core_abi::host_file::HostCallSerial,
        timeout: Duration,
    ) -> Instant {
        let mut held = self.held.lock();
        let now = Instant::now();
        // Bounded by the members waiting: drop deadlines long past.
        held.retain(|_, (_, deadline)| *deadline + Duration::from_secs(60) > now);
        let entry = held
            .entry(Self::key(record))
            .or_insert((call, now + timeout));
        if entry.0 != call {
            *entry = (call, now + timeout);
        }
        entry.1
    }

    /// `record`'s poll call answered: its deadline is spent.
    pub(crate) fn clear(&self, record: carrick_el1_abi::RecordRef) {
        self.held.lock().remove(&Self::key(record));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    fn record(id: u32) -> carrick_el1_abi::RecordRef {
        carrick_el1_abi::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(id).unwrap(),
            incarnation: 7,
        }
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe(2) returned two fresh descriptors this test owns.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    /// The kernel's pool wait service, bound as its host-readiness reactor.
    fn reactor(pid: i32) -> (HostReadinessReactor, CarrierWaitService) {
        let (kernel, _) = crate::kernel::continuation::test_support::bootstrap(pid);
        let service = CarrierWaitService::new(Arc::new(crate::kernel::Scheduler::new(kernel)));
        let reactor = HostReadinessReactor::default();
        reactor.bind(&service);
        (reactor, service)
    }

    /// Bounded: the reactor drops a fired member's wait.
    fn settles(reactor: &HostReadinessReactor, enrolled: usize) -> bool {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if reactor.enrolled() == enrolled {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    fn a_ready_descriptor_fires_its_member_once_and_a_new_wait_replaces_the_old() {
        let (reactor, service) = reactor(15_901);
        let polls = service.reactor_poll_calls();
        let (read, write) = pipe_pair();
        let token = HostReadinessToken::new();
        let source = token.source();
        let interest = |events| HostReadinessInterest {
            source,
            fd: std::os::fd::AsFd::as_fd(&read),
            events,
        };
        assert!(reactor.watch(record(1), &[interest(libc::POLLIN)], None, None));
        // The member's next wait replaces its first: one wait.
        assert!(reactor.watch(record(1), &[interest(libc::POLLIN)], None, None));
        assert_eq!(reactor.enrolled(), 1);
        // Not ready: the wait stays.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(reactor.enrolled(), 1);
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        assert!(
            settles(&reactor, 0),
            "a ready descriptor notifies its member"
        );
        // The carrier's one wait reactor observed it: no second thread.
        assert!(service.reactor_poll_calls() > polls);
    }

    #[test]
    fn a_deadline_fires_without_a_descriptor_and_a_closed_source_is_forgotten() {
        let (reactor, _service) = reactor(15_902);
        assert!(reactor.watch(
            record(2),
            &[],
            Some(Instant::now() + Duration::from_millis(5)),
            None,
        ));
        assert!(settles(&reactor, 0), "the deadline notifies its member");

        let (read, _write) = pipe_pair();
        let token = HostReadinessToken::new();
        let source = token.source();
        assert!(reactor.watch(
            record(3),
            &[HostReadinessInterest {
                source,
                fd: std::os::fd::AsFd::as_fd(&read),
                events: libc::POLLIN,
            }],
            None,
            None,
        ));
        assert_eq!(reactor.enrolled(), 1);
        reactor.forget(source);
        assert_eq!(reactor.enrolled(), 0);
    }

    #[test]
    fn a_kernel_without_a_live_reactor_refuses_the_wait() {
        let reactor = HostReadinessReactor::default();
        assert!(!reactor.watch(record(4), &[], None, None));
        let (bound, service) = self::reactor(15_903);
        drop(service);
        assert!(!bound.watch(record(4), &[], None, None));
    }

    #[test]
    fn a_poll_deadline_is_fixed_by_its_first_wait_and_spent_when_answered() {
        let call = |raw| carrick_core_abi::host_file::HostCallSerial::from_raw(raw).unwrap();
        let deadlines = PollDeadlines::default();
        let first = deadlines.deadline(record(4), call(11), Duration::from_secs(30));
        // The same call's record, published again after a wake, keeps its
        // deadline.
        assert_eq!(
            deadlines.deadline(record(4), call(11), Duration::from_secs(30)),
            first
        );
        // Another call starts afresh.
        assert_ne!(
            deadlines.deadline(record(4), call(12), Duration::from_secs(60)),
            first
        );
        deadlines.clear(record(4));
        assert!(deadlines.deadline(record(4), call(11), Duration::from_secs(30)) >= first);
    }

    /// #2414 review P0-2: an identical poll issued again after an
    /// interrupted one (the same set and timeout, a new ring serial) waits
    /// its own full timeout, never the interrupted call's spent deadline.
    #[test]
    fn an_identical_poll_after_an_interrupted_one_starts_its_own_deadline() {
        let call = |raw| carrick_core_abi::host_file::HostCallSerial::from_raw(raw).unwrap();
        let deadlines = PollDeadlines::default();
        let interrupted = deadlines.deadline(record(5), call(21), Duration::from_millis(20));
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            interrupted <= Instant::now(),
            "the interrupted call's deadline passed"
        );
        let again = deadlines.deadline(record(5), call(22), Duration::from_secs(30));
        assert!(
            again > Instant::now() + Duration::from_secs(29),
            "the new call waits its own timeout"
        );
    }
}
