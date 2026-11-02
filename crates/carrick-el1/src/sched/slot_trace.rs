//! Per-vCPU-slot occupancy trace (#1100), diagnostics only.
//!
//! Hypothesis under test: an `Action::Idle` exit keeps the thread's address
//! space named on the slot's occupancy word, the host's idle entry rewrites
//! TTBR0/TTBR1 to the maintenance root without touching the word, and the
//! next switch-in of that space trusts the word (`enter_space`'s early
//! return) and runs on the maintenance root. Each step appends one packed
//! [`SlotEvent`] to the slot's ring here, and the switch-in check reads the
//! ring back into its [`carrick_el1_abi::StaleRootAttribution`] fatal, so one
//! fatal carries the whole sequence.
//!
//! Single writer per slot (its own CPU); grants nothing, changes no
//! decision. Producers name themselves with [`note_producer`] /
//! [`note_route`]; the entry boundary takes the names ([`record_exit`]),
//! so a name never outlives the entry that set it.
use carrick_el1_abi::{IdleProducer, IdleRoute, SlotEvent, SlotEventKind, SlotId, ZoneTables};
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

const EVENTS: usize = 8;
const SLOTS: usize = carrick_el1_abi::EL1_STACK_SLOTS as usize;

struct SlotTrace {
    head: AtomicU64,
    events: [AtomicU64; EVENTS],
    producer: AtomicU8,
    route: AtomicU8,
}

static TRACES: [SlotTrace; SLOTS] = [const {
    SlotTrace {
        head: AtomicU64::new(0),
        events: [const { AtomicU64::new(0) }; EVENTS],
        producer: AtomicU8::new(0),
        route: AtomicU8::new(0),
    }
}; SLOTS];

fn trace(slot: SlotId) -> Option<&'static SlotTrace> {
    TRACES.get(usize::from(slot.raw()))
}

/// The scheduler arm about to end this entry with `Action::Idle`.
pub fn note_producer(slot: SlotId, producer: IdleProducer) {
    if let Some(trace) = trace(slot) {
        trace.producer.store(producer as u8, Ordering::Relaxed);
    }
}

/// The dispatch route about to turn this entry's completion into `Idle`.
pub fn note_route(slot: SlotId, route: IdleRoute) {
    if let Some(trace) = trace(slot) {
        trace.route.store(route as u8, Ordering::Relaxed);
    }
}

/// Append one event: the occupancy word's space and the live TTBR0 now.
#[inline(never)]
pub fn record(
    zone: &ZoneTables,
    slot: SlotId,
    kind: SlotEventKind,
    producer: IdleProducer,
    route: IdleRoute,
    live_ttbr0: Option<u64>,
) {
    let Some(trace) = trace(slot) else {
        return;
    };
    let live = live_ttbr0.unwrap_or(0);
    let idle = zone.spaces.idle_ttbr();
    let event = SlotEvent::new(
        kind,
        producer,
        route,
        zone.installed_space(slot),
        live,
        live != 0
            && idle != 0
            && carrick_el1_abi::ttbr_baddr(live) == carrick_el1_abi::ttbr_baddr(idle),
    );
    let at = trace.head.fetch_add(1, Ordering::Relaxed) as usize % EVENTS;
    trace.events[at].store(event.0, Ordering::Release);
}

/// The entry boundary: take this entry's producer names, and when it leaves
/// with `Action::Idle` record that exit (with the word's space as it leaves).
#[inline(never)]
pub fn record_exit(zone: &ZoneTables, slot: SlotId, idle: bool, live_ttbr0: Option<u64>) {
    let Some(trace) = trace(slot) else {
        return;
    };
    let producer = IdleProducer::from_raw(trace.producer.swap(0, Ordering::Relaxed));
    let route = IdleRoute::from_raw(trace.route.swap(0, Ordering::Relaxed));
    if idle {
        record(
            zone,
            slot,
            SlotEventKind::IdleExit,
            producer,
            route,
            live_ttbr0,
        );
    }
}

/// The slot's most recent `IdleExit` still in its ring, and its last
/// `N` events oldest first.
pub fn snapshot<const N: usize>(slot: SlotId) -> (SlotEvent, [SlotEvent; N]) {
    let mut recent = [SlotEvent::EMPTY; N];
    let Some(trace) = trace(slot) else {
        return (SlotEvent::EMPTY, recent);
    };
    let head = trace.head.load(Ordering::Relaxed) as usize;
    let at = |back: usize| {
        SlotEvent(trace.events[(head.wrapping_sub(back + 1)) % EVENTS].load(Ordering::Acquire))
    };
    for (index, event) in recent.iter_mut().enumerate() {
        let back = N - 1 - index;
        if back < EVENTS.min(head) {
            *event = at(back);
        }
    }
    let last_exit = (0..EVENTS.min(head))
        .map(at)
        .find(|event| event.kind() == SlotEventKind::IdleExit)
        .unwrap_or(SlotEvent::EMPTY);
    (last_exit, recent)
}
