//! The carrier's readiness watch over host objects a native member waits on
//! (#231). A host network socket is a real host object, so its readiness is
//! a host crossing: when a native call on one would block, the carrier
//! sampled the member's host-readiness queue before its non-blocking probe,
//! enrols the host descriptors here and answers the member's service with an
//! owner wait on that queue. When the host reports a descriptor ready, or a
//! poll's deadline passes, this watch notifies the queue and the member
//! reruns its call once. Nothing polls, and a member's execution capacity is
//! released while it waits.
//!
//! A member waits in at most one call, so its enrolments are that call's: a
//! new wait replaces them, and they are dropped once notified. The watch
//! thread blocks in `poll(2)` on the enrolled descriptors and its own control
//! pipe, which carries only enrolment and shutdown changes. Enrolments hold
//! their own duplicate of the host descriptor and are dropped by their source
//! when the guest's last descriptor closes, so a closed socket never lingers
//! here.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::el1_zone::CarrierZone;

/// The identity of one enrolled host object, so its source can drop its
/// enrolments when the object closes: the address of a token the source
/// owns for its whole life ([`HostReadinessToken`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct HostReadinessSource(usize);

impl HostReadinessSource {
    /// A deadline alone, which no source forgets.
    const DEADLINE: Self = Self(0);
}

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

struct Enrolment {
    source: HostReadinessSource,
    /// `None`: the member's deadline alone.
    fd: Option<OwnedFd>,
    events: i16,
    record: carrick_el1_abi::RecordRef,
    deadline: Option<Instant>,
    carrier: Option<CarrierZone>,
}

struct Shared {
    enrolments: Mutex<Vec<Enrolment>>,
    control: OwnedFd,
    shutdown: AtomicBool,
}

impl Shared {
    fn wake(&self) {
        let byte = 1u8;
        // A full control pipe already holds a pending wake.
        let _ = unsafe { libc::write(self.control.as_raw_fd(), (&byte as *const u8).cast(), 1) };
    }
}

/// One carrier's watch. Dropping it stops the thread.
pub(crate) struct HostReadinessWatch {
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for HostReadinessWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostReadinessWatch")
            .field("enrolled", &self.shared.enrolments.lock().len())
            .finish()
    }
}

fn pipe_pair() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pipe(2) returned two fresh descriptors this function owns.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [&pair.0, &pair.1] {
        let raw = fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        let fd_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        if flags < 0
            || fd_flags < 0
            || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(raw, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(pair)
}

impl HostReadinessWatch {
    pub(crate) fn start() -> std::io::Result<Self> {
        let (read, write) = pipe_pair()?;
        let shared = Arc::new(Shared {
            enrolments: Mutex::new(Vec::new()),
            control: write,
            shutdown: AtomicBool::new(false),
        });
        let watcher = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("carrick-host-ready".into())
            .spawn(move || run(&watcher, &read))?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// Replace `record`'s wait with one on `interests` (each descriptor
    /// duplicated here) and, if given, `deadline`: the first to report its
    /// events, or the deadline, notifies `record`'s host-readiness queue.
    pub(crate) fn enrol(
        &self,
        record: carrick_el1_abi::RecordRef,
        interests: &[HostReadinessInterest<'_>],
        deadline: Option<Instant>,
        carrier: Option<CarrierZone>,
    ) -> std::io::Result<()> {
        let mut enrolled = Vec::with_capacity(interests.len().max(1));
        for interest in interests {
            enrolled.push(Enrolment {
                source: interest.source,
                fd: Some(interest.fd.try_clone_to_owned()?),
                events: interest.events,
                record,
                deadline,
                carrier: carrier.clone(),
            });
        }
        if enrolled.is_empty() {
            enrolled.push(Enrolment {
                source: HostReadinessSource::DEADLINE,
                fd: None,
                events: 0,
                record,
                deadline,
                carrier,
            });
        }
        {
            let mut enrolments = self.shared.enrolments.lock();
            enrolments.retain(|held| held.record != record);
            enrolments.extend(enrolled);
        }
        self.shared.wake();
        Ok(())
    }

    /// Drop every enrolment of `source` (its last guest descriptor closed).
    pub(crate) fn forget(&self, source: HostReadinessSource) {
        let mut enrolments = self.shared.enrolments.lock();
        let before = enrolments.len();
        enrolments.retain(|held| held.source != source);
        if enrolments.len() != before {
            drop(enrolments);
            self.shared.wake();
        }
    }

    #[cfg(test)]
    pub(crate) fn enrolled(&self) -> usize {
        self.shared.enrolments.lock().len()
    }
}

impl Drop for HostReadinessWatch {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::Release);
        self.shared.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn drain(control: &OwnedFd) {
    let mut buffer = [0u8; 64];
    while unsafe {
        libc::read(
            control.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    } > 0
    {}
}

/// Milliseconds until `deadline`, rounded up so a wake is never early.
fn poll_timeout(deadline: Option<Instant>, now: Instant) -> i32 {
    match deadline {
        None => -1,
        Some(deadline) => {
            let left = deadline.saturating_duration_since(now);
            let ms = left.as_micros().div_ceil(1000);
            ms.min(i32::MAX as u128) as i32
        }
    }
}

fn run(shared: &Shared, control: &OwnedFd) {
    let mut pollfds = Vec::new();
    // The enrolment each polled entry (after the control pipe) came from.
    let mut polled = Vec::new();
    loop {
        if shared.shutdown.load(Ordering::Acquire) {
            return;
        }
        pollfds.clear();
        polled.clear();
        pollfds.push(libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        let nearest = {
            let enrolments = shared.enrolments.lock();
            for held in enrolments.iter() {
                if let Some(fd) = &held.fd {
                    pollfds.push(libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: held.events,
                        revents: 0,
                    });
                    polled.push((held.record, fd.as_raw_fd()));
                }
            }
            enrolments.iter().filter_map(|held| held.deadline).min()
        };
        let ready = unsafe {
            libc::poll(
                pollfds.as_mut_ptr(),
                pollfds.len() as libc::nfds_t,
                poll_timeout(nearest, Instant::now()),
            )
        };
        if ready < 0 {
            // EINTR, or a host refusal of the wait itself: every member
            // reruns its call once and re-enrols, rather than wait unseen.
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                let woken = std::mem::take(&mut *shared.enrolments.lock());
                notify_once(woken);
            }
            continue;
        }
        if pollfds[0].revents != 0 {
            drain(control);
        }
        let fired: Vec<(carrick_el1_abi::RecordRef, i32)> = pollfds[1..]
            .iter()
            .zip(&polled)
            .filter(|(entry, _)| entry.revents != 0)
            .map(|(_, polled)| *polled)
            .collect();
        let now = Instant::now();
        // A member is notified once, for whichever of its interests fired
        // or its deadline; all of its enrolments go with it. An enrolment
        // replaced since the scan carries a different duplicate descriptor.
        let woken: Vec<Enrolment> = {
            let mut enrolments = shared.enrolments.lock();
            let mut records: Vec<carrick_el1_abi::RecordRef> = Vec::new();
            for held in enrolments.iter() {
                let fd_fired = held
                    .fd
                    .as_ref()
                    .is_some_and(|fd| fired.contains(&(held.record, fd.as_raw_fd())));
                let expired = held.deadline.is_some_and(|deadline| deadline <= now);
                if (fd_fired || expired) && !records.contains(&held.record) {
                    records.push(held.record);
                }
            }
            let mut woken = Vec::new();
            let mut index = 0;
            while index < enrolments.len() {
                if records.contains(&enrolments[index].record) {
                    woken.push(enrolments.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            woken
        };
        notify_once(woken);
    }
}

/// Notify each member of `woken` once.
fn notify_once(woken: Vec<Enrolment>) {
    let mut notified: Vec<carrick_el1_abi::RecordRef> = Vec::new();
    for held in woken {
        if notified.contains(&held.record) {
            continue;
        }
        notified.push(held.record);
        crate::el1_zone::notify_host_ready(held.carrier.as_ref(), held.record);
    }
}

/// A member's poll deadline (#231): fixed by its first empty snapshot of one
/// exact poll call, so the call's reruns after a wake keep the deadline Linux
/// would have, and an identical later call starts afresh once it answered.
#[derive(Debug, Default)]
pub(crate) struct PollDeadlines {
    held: Mutex<HashMap<(u32, u64), (u64, Instant)>>,
}

impl PollDeadlines {
    fn key(record: carrick_el1_abi::RecordRef) -> (u32, u64) {
        (record.id.raw(), record.incarnation)
    }

    /// The deadline of `record`'s poll call `fingerprint` with `timeout`.
    pub(crate) fn deadline(
        &self,
        record: carrick_el1_abi::RecordRef,
        fingerprint: u64,
        timeout: Duration,
    ) -> Instant {
        let mut held = self.held.lock();
        let now = Instant::now();
        // Bounded by the members waiting: drop deadlines long past.
        held.retain(|_, (_, deadline)| *deadline + Duration::from_secs(60) > now);
        let entry = held
            .entry(Self::key(record))
            .or_insert((fingerprint, now + timeout));
        if entry.0 != fingerprint {
            *entry = (fingerprint, now + timeout);
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

    fn record(id: u32) -> carrick_el1_abi::RecordRef {
        carrick_el1_abi::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(id).unwrap(),
            incarnation: 7,
        }
    }

    /// Bounded: the watch thread drops a fired member's enrolments.
    fn settles(watch: &HostReadinessWatch, enrolled: usize) -> bool {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if watch.enrolled() == enrolled {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    fn a_ready_descriptor_fires_its_member_once_and_a_new_wait_replaces_the_old() {
        let watch = HostReadinessWatch::start().unwrap();
        let (read, write) = pipe_pair().unwrap();
        let token = HostReadinessToken::new();
        let source = token.source();
        let interest = |events| HostReadinessInterest {
            source,
            fd: std::os::fd::AsFd::as_fd(&read),
            events,
        };
        watch
            .enrol(record(1), &[interest(libc::POLLIN)], None, None)
            .unwrap();
        // The member's next wait replaces its first: one enrolment.
        watch
            .enrol(record(1), &[interest(libc::POLLIN)], None, None)
            .unwrap();
        assert_eq!(watch.enrolled(), 1);
        // Not ready: the enrolment stays.
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(watch.enrolled(), 1);
        assert_eq!(
            unsafe { libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        assert!(settles(&watch, 0), "a ready descriptor notifies its member");
    }

    #[test]
    fn a_deadline_fires_without_a_descriptor_and_a_closed_source_is_forgotten() {
        let watch = HostReadinessWatch::start().unwrap();
        watch
            .enrol(
                record(2),
                &[],
                Some(Instant::now() + Duration::from_millis(5)),
                None,
            )
            .unwrap();
        assert!(settles(&watch, 0), "the deadline notifies its member");

        let (read, _write) = pipe_pair().unwrap();
        let token = HostReadinessToken::new();
        let source = token.source();
        watch
            .enrol(
                record(3),
                &[HostReadinessInterest {
                    source,
                    fd: std::os::fd::AsFd::as_fd(&read),
                    events: libc::POLLIN,
                }],
                None,
                None,
            )
            .unwrap();
        assert_eq!(watch.enrolled(), 1);
        watch.forget(source);
        assert_eq!(watch.enrolled(), 0);
    }

    #[test]
    fn a_poll_deadline_is_fixed_by_its_first_wait_and_spent_when_answered() {
        let deadlines = PollDeadlines::default();
        let first = deadlines.deadline(record(4), 11, Duration::from_secs(30));
        // The same call's rerun keeps its deadline.
        assert_eq!(
            deadlines.deadline(record(4), 11, Duration::from_secs(30)),
            first
        );
        // Another call starts afresh.
        assert_ne!(
            deadlines.deadline(record(4), 12, Duration::from_secs(60)),
            first
        );
        deadlines.clear(record(4));
        assert!(deadlines.deadline(record(4), 11, Duration::from_secs(30)) >= first);
    }
}
