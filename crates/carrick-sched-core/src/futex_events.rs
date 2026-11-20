//! Bounded forensic history shared by the carrier and the guest scheduler.
use core::sync::atomic::{AtomicU64, Ordering};

use crate::RecordRef;

pub const CAPACITY: usize = 1024;
pub const WAITV_OP: u32 = u32::MAX;

// The debugger reads the pointer from the stopped carrier and follows it
// while the original metadata backing is retained.
#[cfg(not(target_os = "none"))]
static FUTEX_EVENTS_ADDR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(not(target_os = "none"))]
pub fn publish_host_address(address: usize) {
    FUTEX_EVENTS_ADDR.store(address, Ordering::Release);
}

#[cfg(not(target_os = "none"))]
pub fn clear_host_address(address: usize) {
    let _ = FUTEX_EVENTS_ADDR.compare_exchange(address, 0, Ordering::AcqRel, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexKey {
    pub mm: u64,
    pub scheduler_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FutexActor {
    pub tid: u32,
    pub serial: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FutexEventKind {
    Wait = 1,
    Wake = 2,
    Complete = 3,
    Requeue = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FutexCompletion {
    Woken = 1,
    Timeout = 2,
    Signal = 3,
}

/// A park's payload, captured while its bucket and unpublished record are owned.
pub struct FutexEnrollment {
    pub(crate) key: FutexKey,
    pub(crate) actor: FutexActor,
    pub(crate) park: RecordRef,
    pub(crate) seq: u32,
    pub(crate) op: u32,
    pub(crate) val: u32,
}

// Layout is consumed by scripts/carrick_lldb.py.
#[repr(C, align(64))]
struct Slot {
    generation: AtomicU64,
    words: [AtomicU64; 7],
}

#[repr(C, align(64))]
pub struct FutexEvents {
    next: AtomicU64,
    slots: [Slot; CAPACITY],
}

impl FutexEvents {
    pub fn next(&self) -> u64 {
        self.next.load(Ordering::Acquire)
    }

    /// The slot is accepted only if both generation reads identify this
    /// logical record. A missing slot can mean concurrent publication or wrap.
    pub fn read(&self, index: u64) -> Option<[u64; 7]> {
        let slot = &self.slots[index as usize % CAPACITY];
        let complete = index / CAPACITY as u64 * 2 + 2;
        if slot.generation.load(Ordering::Acquire) != complete {
            return None;
        }
        let words = slot
            .words
            .each_ref()
            .map(|word| word.load(Ordering::Relaxed));
        core::sync::atomic::fence(Ordering::Acquire);
        (slot.generation.load(Ordering::Relaxed) == complete).then_some(words)
    }

    fn record(&self, words: [u64; 7]) {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        let slot = &self.slots[index as usize % CAPACITY];
        let busy = index / CAPACITY as u64 * 2 + 1;
        let observed = slot.generation.load(Ordering::Relaxed);
        // Never overwrite an in-flight writer. A failed claim leaves a gap.
        if observed & 1 != 0
            || observed >= busy
            || slot
                .generation
                .compare_exchange(observed, busy, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        for (cell, word) in slot.words.iter().zip(words) {
            cell.store(word, Ordering::Relaxed);
        }
        slot.generation.store(busy + 1, Ordering::Release);
    }

    pub fn enrolled(&self, wait: FutexEnrollment) {
        self.park_event(
            FutexEventKind::Wait,
            wait.key,
            wait.actor,
            wait.park,
            wait.seq,
            wait.op,
            wait.val,
        );
    }

    pub(crate) fn complete(
        &self,
        key: FutexKey,
        actor: FutexActor,
        park: RecordRef,
        seq: u32,
        why: FutexCompletion,
    ) {
        self.park_event(
            FutexEventKind::Complete,
            key,
            actor,
            park,
            seq,
            why as u32,
            0,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn park_event(
        &self,
        kind: FutexEventKind,
        key: FutexKey,
        actor: FutexActor,
        park: RecordRef,
        seq: u32,
        detail: u32,
        val: u32,
    ) {
        self.record([
            pair(kind as u32, park.id.raw()),
            key.mm,
            key.scheduler_address,
            pair(actor.tid, val),
            actor.serial,
            park.incarnation,
            pair(seq, detail),
        ]);
    }

    pub fn wake(&self, key: FutexKey, actor: FutexActor, requested: u32, woken: u32) {
        self.record([
            FutexEventKind::Wake as u64,
            key.mm,
            key.scheduler_address,
            u64::from(actor.tid),
            actor.serial,
            pair(requested, woken),
            0,
        ]);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn requeue(
        &self,
        key: FutexKey,
        actor: FutexActor,
        to_scheduler_address: u64,
        woken: u32,
        moved: u32,
        requested: u32,
    ) {
        self.record([
            pair(FutexEventKind::Requeue as u32, requested),
            key.mm,
            key.scheduler_address,
            u64::from(actor.tid),
            actor.serial,
            to_scheduler_address,
            pair(woken, moved),
        ]);
    }
}

fn pair(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

const _: () = {
    assert!(core::mem::size_of::<Slot>() == 64);
    assert!(core::mem::offset_of!(FutexEvents, slots) == 64);
};
