#![cfg_attr(
    all(not(target_os = "macos"), not(test)),
    expect(
        dead_code,
        reason = "KVM persistent runtime binding follows the shared driver API"
    )
)]

//! Carrier-lifetime deadline delivery, independent of vCPU execution leases.
//!
//! Uses the Condvar/shutdown discipline of #1836's ClockResourceService.
//! Targets supply their own calibrated counter and exact expiry arbitration;
//! this driver neither interprets syscalls nor keeps a second timer inventory.
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};

pub(crate) trait DeadlineTarget: Send + Sync + 'static {
    fn remaining(&self) -> Option<Duration>;
    fn expire(&self);
}

#[derive(Default)]
struct State {
    shutdown: bool,
}
#[derive(Default)]
pub(crate) struct Doorbell {
    state: Mutex<State>,
    changed: Condvar,
}
impl Doorbell {
    pub(crate) fn notify(&self) {
        let _guard = self.state.lock();
        self.changed.notify_one();
    }
}

pub(crate) struct DeadlineDriver {
    doorbell: Arc<Doorbell>,
    worker: Option<JoinHandle<()>>,
}
impl DeadlineDriver {
    pub(crate) fn start(target: Arc<dyn DeadlineTarget>) -> std::io::Result<Self> {
        let doorbell = Arc::new(Doorbell::default());
        let thread_doorbell = Arc::clone(&doorbell);
        let worker = std::thread::Builder::new()
            .name("carrier-deadlines".into())
            .spawn(move || {
                let mut state = thread_doorbell.state.lock();
                loop {
                    if state.shutdown {
                        break;
                    }
                    match target.remaining() {
                        Some(remaining) if remaining.is_zero() => {
                            drop(state);
                            target.expire();
                            state = thread_doorbell.state.lock();
                        }
                        Some(remaining) => {
                            thread_doorbell.changed.wait_for(&mut state, remaining);
                        }
                        None => thread_doorbell.changed.wait(&mut state),
                    }
                }
            })?;
        Ok(Self {
            doorbell,
            worker: Some(worker),
        })
    }
    pub(crate) fn notifier(&self) -> Arc<dyn Fn() + Send + Sync> {
        let doorbell = Arc::clone(&self.doorbell);
        Arc::new(move || doorbell.notify())
    }
}
impl Drop for DeadlineDriver {
    fn drop(&mut self) {
        {
            let mut state = self.doorbell.state.lock();
            state.shutdown = true;
            self.doorbell.changed.notify_one();
        }
        if let Some(worker) = self.worker.take() {
            // Mapping custody outlives the in-flight callback and this join.
            if worker.join().is_err() {
                carrick_fatal::carrick_fatal!("carrier-deadlines", "deadline worker panicked");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use carrick_sched_core::{
        Claim, Handback, RecordRef, ShortLockSpin, SlotId, ThreadIdentity, ZoneTables,
    };
    use std::sync::mpsc;
    use std::time::Instant;

    struct NativeTarget {
        zone: Box<ZoneTables>,
        origin: Instant,
        completed: mpsc::SyncSender<RecordRef>,
        waiting: mpsc::SyncSender<()>,
    }
    impl DeadlineTarget for NativeTarget {
        fn remaining(&self) -> Option<Duration> {
            let park = self.zone.native_timed_park();
            if park.is_none() {
                let _ = self.waiting.try_send(());
            }
            park.map(|park| {
                Duration::from_nanos(park.deadline.raw()).saturating_sub(self.origin.elapsed())
            })
        }
        fn expire(&self) {
            let now = u64::try_from(self.origin.elapsed().as_nanos()).unwrap();
            while let Some(record) = self.zone.expire_native_timer(
                carrick_guest_arch::CounterTick::new(now),
                &ShortLockSpin,
                &|owned| {
                    let _ = owned.into_parts();
                },
            ) {
                self.completed.send(record).unwrap();
            }
        }
    }

    /// Uses the real indexed timer and futex enrollment, with no live vCPU,
    /// and requires the Condvar worker itself to deliver the original expiry.
    #[test]
    fn driver_delivers_native_park_with_no_slots_and_joins_before_zone_drop() {
        // SAFETY: the typed allocation meets ZoneTables alignment, and all
        // zero is the valid initial shared ABI representation.
        let zone = unsafe { Box::<ZoneTables>::new_zeroed().assume_init() };
        let slot = SlotId::new(0);
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 1,
                serial: 1,
                mm: 1,
                file_table: 1,
                generation: 1,
                affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
                affinity: 1,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let exact = zone.record_ref(record);
        assert!(zone.mark_native_owned(record));
        let seq = zone.next_seq(record);
        let origin = Instant::now();
        let deadline = 100_000_000;
        zone.arm_timer_result(
            slot,
            record,
            seq,
            carrick_guest_arch::NativeReturnWord(0xface),
        )
        .unwrap();
        let guard = zone
            .lock(ZoneTables::bucket_of(1, 0x4400), &ShortLockSpin)
            .unwrap();
        zone.enqueue(&guard, record, seq, 1, 0x4400, u32::MAX, 0)
            .unwrap();
        zone.set_deadline(record, deadline);
        zone.publish_park(record, seq);
        drop(guard);
        zone.leave_guest(slot, &ShortLockSpin);
        let (tx, rx) = mpsc::sync_channel(1);
        let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
        let target = Arc::new(NativeTarget {
            zone,
            origin,
            completed: tx,
            waiting: waiting_tx,
        });
        let driver = DeadlineDriver::start(target.clone()).unwrap();
        waiting_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(target.zone.take_foreign_timer(slot).unwrap().native);
        assert!(target.zone.reset_slot(slot));
        driver.notifier()();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), exact);
        assert!(origin.elapsed() >= Duration::from_nanos(deadline));
        drop(driver);
        assert!(matches!(
            target.zone.record(record).claim(),
            Claim::Host { .. }
        ));
        assert!(target.zone.record(record).needs_native_handback());
        assert_eq!(target.zone.record(record).result(), 0xface);
        assert_eq!(target.zone.record(record).entry_count(), 0);
        assert_eq!(target.zone.timer_node_count(), 0);
        assert!(rx.try_recv().is_err());
        target.zone.free_record(record);
        assert!(target.zone.live(exact).is_none());
        assert_ne!(
            target.zone.record(record).handback(),
            Some(Handback::Control)
        );
    }
    #[test]
    fn shutdown_joins_an_admitted_callback_before_releasing_target() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Target {
            done: AtomicBool,
            entered: mpsc::SyncSender<()>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl DeadlineTarget for Target {
            fn remaining(&self) -> Option<Duration> {
                (!self.done.load(Ordering::Acquire)).then_some(Duration::ZERO)
            }
            fn expire(&self) {
                self.done.store(true, Ordering::Release);
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let driver = DeadlineDriver::start(Arc::new(Target {
            done: AtomicBool::new(false),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }))
        .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (joined_tx, joined_rx) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            scope.spawn(move || {
                drop(driver);
                joined_tx.send(()).unwrap();
            });
            assert!(joined_rx.try_recv().is_err());
            release_tx.send(()).unwrap();
            joined_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        });
    }
}
