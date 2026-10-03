//! Owned open-description cursor admission. The host fd remains the offset
//! authority; a released reservation grants exactly one owned successor.
use super::FileDescription;
use crate::kernel::{WaitCallbackEnrollment, WaitQueue};
use carrick_fatal::carrick_fatal;
use parking_lot::Mutex;
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Weak};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CursorTicket(NonZeroU64);
const WAITING: u8 = 0;
const GRANTED: u8 = 1;
const CONSUMED: u8 = 2;
#[derive(Debug)]
struct CursorState {
    owner: Option<CursorTicket>,
    next: u64,
    draining: bool,
    notifications: VecDeque<Arc<CursorWaiter>>,
    waiting: BTreeMap<CursorTicket, Weak<CursorWaiter>>,
}
#[derive(Debug)]
pub(super) struct FileCursor {
    state: Mutex<CursorState>,
}
impl FileCursor {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(CursorState {
                owner: None,
                next: 1,
                draining: false,
                notifications: VecDeque::new(),
                waiting: BTreeMap::new(),
            }),
        }
    }
    fn release(&self, ticket: CursorTicket) {
        {
            let mut state = self.state.lock();
            if state.owner != Some(ticket) {
                carrick_fatal!("kernel::file_cursor", "lost exact cursor reservation");
            }
            state.owner = None;
            while let Some((_, weak)) = state.waiting.pop_first() {
                if let Some(waiter) = weak.upgrade() {
                    state.owner = Some(waiter.ticket);
                    waiter.status.store(GRANTED, Ordering::Release);
                    state.notifications.push_back(waiter);
                    break;
                }
            }
            if state.draining {
                return;
            }
            state.draining = true;
        }
        loop {
            let next = {
                let mut state = self.state.lock();
                match state.notifications.pop_front() {
                    Some(next) => next,
                    None => {
                        // The same lock admits new effects and relinquishes
                        // drain ownership, so concurrent release cannot lose
                        // an edge at the empty-to-idle transition.
                        state.draining = false;
                        return;
                    }
                }
            };
            // Each queue belongs to one operation. Keep drain ownership
            // through callback AND final Arc drop: either can cancel the
            // granted ticket, appending the successor instead of recursing.
            next.changed.wake_all();
            drop(next);
        }
    }
}

/// Exact description and elected incarnation, without any borrowed backing
/// lock. Drop cancels without moving f_pos and hands authority to one waiter.
#[derive(Debug)]
pub struct FileCursorReservation {
    description: Arc<FileDescription>,
    ticket: CursorTicket,
}
impl FileCursorReservation {
    pub fn description(&self) -> &Arc<FileDescription> {
        &self.description
    }
}
impl Drop for FileCursorReservation {
    fn drop(&mut self) {
        self.description.common.cursor.release(self.ticket);
    }
}
#[derive(Debug)]
struct CursorWaiter {
    description: Arc<FileDescription>,
    ticket: CursorTicket,
    status: AtomicU8,
    changed: WaitQueue,
}
impl Drop for CursorWaiter {
    fn drop(&mut self) {
        match *self.status.get_mut() {
            GRANTED => self.description.common.cursor.release(self.ticket),
            WAITING => {
                self.description
                    .common
                    .cursor
                    .state
                    .lock()
                    .waiting
                    .remove(&self.ticket);
            }
            CONSUMED => {}
            _ => carrick_fatal!("kernel::file_cursor", "invalid cursor wait state"),
        }
    }
}
/// Owned successor ticket independent of guest fd number. A ready ticket owns
/// the cursor already: resumption takes it instead of competing a second time.
#[derive(Clone, Debug)]
pub struct FileCursorWait(Arc<CursorWaiter>);
impl FileCursorWait {
    pub fn changed(&self) -> bool {
        self.0.status.load(Ordering::Acquire) == GRANTED
    }
    pub fn subscribe(
        &self,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> (WaitCallbackEnrollment, bool) {
        let enrollment = self.0.changed.enroll_callback(move |_| wake());
        // The grant is published before the producer edge; registration then
        // recheck covers a handoff between the failed probe and enrollment.
        (enrollment, self.changed())
    }
    pub fn take_reservation(&self) -> Option<FileCursorReservation> {
        self.0
            .status
            .compare_exchange(GRANTED, CONSUMED, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        Some(FileCursorReservation {
            description: self.0.description.clone(),
            ticket: self.0.ticket,
        })
    }
    pub fn description(&self) -> &Arc<FileDescription> {
        &self.0.description
    }
}
impl FileDescription {
    /// Short authority bookkeeping only. Competitors receive owned tickets
    /// and must park continuations, never wait on another task's pool worker.
    pub fn try_reserve_cursor(self: &Arc<Self>) -> Result<FileCursorReservation, FileCursorWait> {
        let mut state = self.common.cursor.state.lock();
        let ticket =
            CursorTicket(NonZeroU64::new(state.next).unwrap_or_else(|| {
                carrick_fatal!("kernel::file_cursor", "zero cursor generation")
            }));
        state.next = state.next.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!("kernel::file_cursor", "cursor generation exhausted")
        });
        if state.owner.is_none() {
            state.owner = Some(ticket);
            return Ok(FileCursorReservation {
                description: self.clone(),
                ticket,
            });
        }
        let waiter = Arc::new(CursorWaiter {
            description: self.clone(),
            ticket,
            status: AtomicU8::new(WAITING),
            changed: WaitQueue::new(),
        });
        state.waiting.insert(ticket, Arc::downgrade(&waiter));
        Err(FileCursorWait(waiter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    fn description() -> Arc<FileDescription> {
        Arc::new(FileDescription::regular(
            crate::kernel::ids::allocate_file_description_id().unwrap(),
        ))
    }
    #[test]
    fn cursor_release_between_probe_and_enrollment_is_observed() {
        let description = description();
        let first = description.try_reserve_cursor().unwrap();
        let wait = description.try_reserve_cursor().unwrap_err();
        drop(first);
        let wakes = Arc::new(AtomicU64::new(0));
        let target = wakes.clone();
        let (_subscription, ready) = wait.subscribe(move || {
            target.fetch_add(1, Ordering::Relaxed);
        });
        assert!(ready, "release before enrollment must not park");
        assert_eq!(wakes.load(Ordering::Relaxed), 0);
        let next = wait.take_reservation().unwrap();
        assert!(
            wait.take_reservation().is_none(),
            "one wait cannot mint two cursor owners"
        );
        drop(next);
        assert!(description.try_reserve_cursor().is_ok());
    }
    #[test]
    fn cursor_owner_moves_without_holding_description_lock_and_wakes_after_release() {
        let description = description();
        let first = description.try_reserve_cursor().unwrap();
        let wait = description.clone().try_reserve_cursor().unwrap_err();
        let ready = Arc::new(AtomicU64::new(0));
        let target = ready.clone();
        let successor = wait.clone();
        let retained = Arc::new(parking_lot::Mutex::new(None));
        let destination = retained.clone();
        let (subscription, changed) = wait.subscribe(move || {
            *destination.lock() = Some(successor.take_reservation().unwrap());
            target.fetch_add(1, Ordering::Relaxed);
        });
        assert!(!changed);
        std::thread::spawn(move || drop(first)).join().unwrap();
        assert_eq!(ready.load(Ordering::Relaxed), 1);
        drop(subscription);
        drop(retained.lock().take());
        assert!(description.try_reserve_cursor().is_ok());
    }
    #[test]
    fn cursor_release_wakes_one_successor_at_any_waiter_population() {
        for count in [2, 32, 256] {
            let description = description();
            let first = description.try_reserve_cursor().unwrap();
            let wakes = Arc::new(AtomicU64::new(0));
            let mut waits = Vec::new();
            let mut subscriptions = Vec::new();
            for _ in 0..count {
                let wait = description.try_reserve_cursor().unwrap_err();
                let target = wakes.clone();
                let (subscription, ready) = wait.subscribe(move || {
                    target.fetch_add(1, Ordering::Relaxed);
                });
                assert!(!ready);
                waits.push(wait);
                subscriptions.push(subscription);
            }
            drop(first);
            assert_eq!(
                wakes.load(Ordering::Relaxed),
                1,
                "one completed operation must not wake every competitor"
            );
            for (i, wait) in waits.iter().enumerate() {
                let owner = wait.take_reservation().unwrap();
                assert!(waits.iter().skip(i + 1).all(|next| !next.changed()));
                drop(owner);
                assert_eq!(wakes.load(Ordering::Relaxed), ((i + 2).min(count)) as u64);
            }
            assert_eq!(description.common.cursor.state.lock().waiting.len(), 0);
            assert!(description.try_reserve_cursor().is_ok());
            drop(subscriptions);
            drop(waits);
        }
    }
    #[test]
    fn canceled_waiters_remove_storage_and_granted_successor_hands_off_once() {
        let description = description();
        let first = description.try_reserve_cursor().unwrap();
        let next = description.try_reserve_cursor().unwrap_err();
        for _ in 0..256 {
            let canceled = description.try_reserve_cursor().unwrap_err();
            drop(canceled);
            assert_eq!(description.common.cursor.state.lock().waiting.len(), 1);
        }
        let last = description.try_reserve_cursor().unwrap_err();
        let wakes = Arc::new(AtomicU64::new(0));
        let target = wakes.clone();
        let (_subscription, ready) = last.subscribe(move || {
            target.fetch_add(1, Ordering::Relaxed);
        });
        assert!(!ready);
        drop(first);
        assert!(next.changed());
        assert!(!last.changed());
        drop(next);
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        let owner = last.take_reservation().unwrap();
        assert!(last.take_reservation().is_none());
        drop(owner);
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        assert_eq!(description.common.cursor.state.lock().waiting.len(), 0);
        assert!(description.try_reserve_cursor().is_ok());
    }
    #[test]
    fn cursor_callback_cancellation_does_not_recurse_through_successors() {
        let description = description();
        let first = description.try_reserve_cursor().unwrap();
        let depth = Arc::new(AtomicU64::new(0));
        let maximum = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicU64::new(0));
        let mut subscriptions = Vec::new();
        for _ in 0..256 {
            let wait = description.try_reserve_cursor().unwrap_err();
            let active = depth.clone();
            let high = maximum.clone();
            let count = completed.clone();
            let successor = wait.clone();
            let (subscription, ready) = wait.subscribe(move || {
                let current = active.fetch_add(1, Ordering::Relaxed) + 1;
                high.fetch_max(current, Ordering::Relaxed);
                drop(successor.take_reservation().unwrap());
                count.fetch_add(1, Ordering::Relaxed);
                active.fetch_sub(1, Ordering::Relaxed);
            });
            assert!(!ready);
            subscriptions.push(subscription);
        }
        drop(first);
        assert_eq!(completed.load(Ordering::Relaxed), 256);
        assert_eq!(
            maximum.load(Ordering::Relaxed),
            1,
            "canceled successors must not grow the notification stack"
        );
        assert!(description.try_reserve_cursor().is_ok());
        drop(subscriptions);
    }
    #[test]
    fn cursor_concurrent_release_during_notification_keeps_successor_edge() {
        use std::sync::mpsc;
        use std::time::Duration;
        let description = description();
        let first = description.try_reserve_cursor().unwrap();
        let next = description.try_reserve_cursor().unwrap_err();
        let last = description.try_reserve_cursor().unwrap_err();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let finish_rx = Mutex::new(finish_rx);
        let (subscription, ready) = next.subscribe(move || {
            entered_tx.send(()).unwrap();
            finish_rx
                .lock()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        });
        assert!(!ready);
        let wakes = Arc::new(AtomicU64::new(0));
        let target = wakes.clone();
        let (_last_subscription, ready) = last.subscribe(move || {
            target.fetch_add(1, Ordering::Relaxed);
        });
        assert!(!ready);
        let producer = std::thread::spawn(move || drop(first));
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(next.take_reservation().unwrap());
        assert!(last.changed());
        assert_eq!(
            wakes.load(Ordering::Relaxed),
            0,
            "the existing drainer owns the pending successor notification"
        );
        finish_tx.send(()).unwrap();
        producer.join().unwrap();
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
        drop(last.take_reservation().unwrap());
        assert!(!description.common.cursor.state.lock().draining);
        assert!(
            description
                .common
                .cursor
                .state
                .lock()
                .notifications
                .is_empty()
        );
        drop(subscription);
    }
}
