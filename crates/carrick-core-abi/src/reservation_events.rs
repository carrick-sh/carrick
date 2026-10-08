//! Guest-visible, bounded reservation lifecycle evidence in the shared EL1 aperture.
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

pub const RESERVATION_EVENT_SLOTS: usize = 256;
pub const PREPARED_SETTLED: u64 = 1;
pub const PREPARED_REAP: u64 = 2;
pub const ANONYMOUS_RETIRE_REFUSED: u64 = 3;

#[repr(C)]
pub struct ReservationEvent {
    pub sequence: AtomicU64,
    pub phase: AtomicU64,
    pub mm: AtomicU64,
    pub incarnation: AtomicU64,
    pub id: AtomicU64,
    pub tail_id: AtomicU64,
}
impl ReservationEvent {
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            phase: AtomicU64::new(0),
            mm: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
            id: AtomicU64::new(0),
            tail_id: AtomicU64::new(0),
        }
    }
}
impl Default for ReservationEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct ReservationEventRing {
    pub next: AtomicU64,
    pub slots: [ReservationEvent; RESERVATION_EVENT_SLOTS],
}
impl ReservationEventRing {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            slots: [const { ReservationEvent::new() }; RESERVATION_EVENT_SLOTS],
        }
    }
    pub fn record(&self, phase: u64, mm: u64, incarnation: u64, id: u32, tail_id: u32) {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let slot = &self.slots[(sequence as usize - 1) % RESERVATION_EVENT_SLOTS];
        slot.sequence.store(0, Ordering::Relaxed);
        slot.phase.store(phase, Ordering::Relaxed);
        slot.mm.store(mm, Ordering::Relaxed);
        slot.incarnation.store(incarnation, Ordering::Relaxed);
        slot.id.store(u64::from(id), Ordering::Relaxed);
        slot.tail_id.store(u64::from(tail_id), Ordering::Relaxed);
        slot.sequence.store(sequence, Ordering::Release);
    }
}
impl Default for ReservationEventRing {
    fn default() -> Self {
        Self::new()
    }
}

static ACTIVE_RING: AtomicPtr<ReservationEventRing> = AtomicPtr::new(core::ptr::null_mut());

/// Register the shared aperture from the guest's syscall entry.
pub fn register_reservation_events(ring: &ReservationEventRing) {
    ACTIVE_RING.store(
        (ring as *const ReservationEventRing).cast_mut(),
        Ordering::Release,
    );
}

pub fn record_reservation_event(phase: u64, mm: u64, incarnation: u64, id: u32, tail_id: u32) {
    let ring = ACTIVE_RING.load(Ordering::Acquire);
    if !ring.is_null() {
        // SAFETY: guest registration points into the carrier's permanent shared aperture.
        unsafe { &*ring }.record(phase, mm, incarnation, id, tail_id);
    }
}
