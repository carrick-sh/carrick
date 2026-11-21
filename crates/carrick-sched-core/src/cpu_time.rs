//! Per-record and per-slot guest user/system CPU tick accounting.
//!
//! Each CPU slot tracks its current guest mode (off/idle/host, user, or ring
//! system) against hardware counter ticks (`CNTVCT_EL0` / `RDTSC`) and flushes
//! completed intervals into the bound [`RecordId`]'s [`RecordCpuTicks`] row.
//! Idle spins, architectural `wfi`/`hlt`, parked waits, and synchronous host
//! crossings close the slot window so blocked time accrues zero CPU ticks.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use carrick_guest_arch::{CounterFrequency, CounterTick};

use crate::{RecordId, RecordRef, SlotId, ZONE_RECORDS, ZONE_SLOTS};

const MODE_OFF: u32 = 0;
const MODE_USER: u32 = 1;
const MODE_SYSTEM: u32 = 2;
/// Bound to a record whose thread is out on a host crossing: charges nothing.
const MODE_HOST: u32 = 3;

/// Sampled user and system hardware counter ticks for one record or process.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuTickPair {
    pub user: u64,
    pub system: u64,
}

#[inline(never)]
fn ticks_to_nanos(ticks: u64, frequency: CounterFrequency) -> u64 {
    let hz = u128::from(frequency.raw().get());
    u64::try_from(u128::from(ticks).saturating_mul(1_000_000_000) / hz).unwrap_or(u64::MAX)
}

impl CpuTickPair {
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            user: self.user.saturating_add(other.user),
            system: self.system.saturating_add(other.system),
        }
    }

    pub fn total_nanos(self, frequency: CounterFrequency) -> u64 {
        if let Some(sum) = self.user.checked_add(self.system) {
            return ticks_to_nanos(sum, frequency);
        }
        let hz = u128::from(frequency.raw().get());
        let total = u128::from(self.user).saturating_add(u128::from(self.system));
        u64::try_from(total.saturating_mul(1_000_000_000) / hz).unwrap_or(u64::MAX)
    }

    pub fn user_nanos(self, frequency: CounterFrequency) -> u64 {
        ticks_to_nanos(self.user, frequency)
    }

    pub fn system_nanos(self, frequency: CounterFrequency) -> u64 {
        ticks_to_nanos(self.system, frequency)
    }
}

#[repr(C)]
pub struct RecordCpuTicks {
    incarnation: AtomicU64,
    user_ticks: AtomicU64,
    system_ticks: AtomicU64,
    last_reported_ns: AtomicU64,
    active_slot: AtomicU32,
    _pad: u32,
}

#[repr(C)]
pub struct SlotCpuWindow {
    seq: AtomicU32,
    record: AtomicU32,
    mode: AtomicU32,
    _pad: u32,
    incarnation: AtomicU64,
    since_tick: AtomicU64,
    unadmitted_user_ticks: AtomicU64,
    unadmitted_system_ticks: AtomicU64,
}

/// Append-only CPU tick accounting table inside [`crate::ZoneTables`].
/// All-zero bytes represent an empty ledger.
#[repr(C)]
pub struct ZoneCpuLedger {
    counter_hz: AtomicU64,
    latest_tick: AtomicU64,
    records: [RecordCpuTicks; ZONE_RECORDS],
    slots: [SlotCpuWindow; ZONE_SLOTS],
}

impl ZoneCpuLedger {
    pub fn publish_frequency(&self, frequency: CounterFrequency) {
        self.counter_hz
            .store(frequency.raw().get(), Ordering::Release);
    }

    pub fn frequency(&self) -> Option<CounterFrequency> {
        NonZeroU64::new(self.counter_hz.load(Ordering::Acquire)).map(CounterFrequency::new)
    }

    pub fn latest_tick(&self) -> CounterTick {
        CounterTick::new(self.latest_tick.load(Ordering::Acquire))
    }

    pub fn reset_record(&self, id: RecordId, incarnation: u64) {
        let index = id.index();
        if index >= ZONE_RECORDS {
            return;
        }
        let row = &self.records[index];
        row.incarnation.store(incarnation, Ordering::Release);
        row.user_ticks.store(0, Ordering::Release);
        row.system_ticks.store(0, Ordering::Release);
        row.last_reported_ns.store(0, Ordering::Release);
        row.active_slot.store(0, Ordering::Release);
    }

    pub fn enter_ring(&self, slot: SlotId, record: Option<RecordRef>, tick: CounterTick) {
        self.transition(slot, record, MODE_SYSTEM, tick);
    }

    pub fn enter_user(&self, slot: SlotId, record: Option<RecordRef>, tick: CounterTick) {
        self.transition(slot, record, MODE_USER, tick);
    }

    pub fn bind_record(&self, slot: SlotId, record: RecordRef, tick: CounterTick) {
        self.transition(slot, Some(record), MODE_SYSTEM, tick);
    }

    pub fn leave_slot(&self, slot: SlotId, tick: CounterTick) {
        self.transition(slot, None, MODE_OFF, tick);
    }

    /// Stop charging `slot` while its thread waits on a host crossing, but
    /// keep the thread's record bound: the crossing returns to the same
    /// thread, which the next `enter_ring` may not name (an initial root the
    /// scheduler never switched in has no current record).
    pub fn cross_to_host(&self, slot: SlotId, tick: CounterTick) {
        self.transition(slot, None, MODE_HOST, tick);
    }

    #[inline(never)]
    pub fn adopt_unadmitted(&self, slot: SlotId, record: RecordRef) {
        let slot_index = slot.index();
        let rec_index = record.id.index();
        if slot_index >= ZONE_SLOTS || rec_index >= ZONE_RECORDS {
            return;
        }
        let window = &self.slots[slot_index];
        let row = &self.records[rec_index];
        if row.incarnation.load(Ordering::Acquire) != record.incarnation {
            return;
        }
        window.seq.fetch_add(1, Ordering::AcqRel);
        if window.record.load(Ordering::Relaxed) == 0 {
            let u = window.unadmitted_user_ticks.swap(0, Ordering::AcqRel);
            let s = window.unadmitted_system_ticks.swap(0, Ordering::AcqRel);
            if u != 0 {
                row.user_ticks.fetch_add(u, Ordering::AcqRel);
            }
            if s != 0 {
                row.system_ticks.fetch_add(s, Ordering::AcqRel);
            }
            window.record.store(record.id.raw(), Ordering::Relaxed);
            window
                .incarnation
                .store(record.incarnation, Ordering::Relaxed);
            row.active_slot
                .store(slot_index as u32 + 1, Ordering::Release);
        }
        window.seq.fetch_add(1, Ordering::Release);
    }

    #[inline(never)]
    fn transition(
        &self,
        slot: SlotId,
        record: Option<RecordRef>,
        next_mode: u32,
        tick: CounterTick,
    ) {
        let slot_index = slot.index();
        if slot_index >= ZONE_SLOTS {
            return;
        }
        let now = tick.raw();
        self.latest_tick.fetch_max(now, Ordering::Relaxed);
        let window = &self.slots[slot_index];
        let old_rec = window.record.load(Ordering::Relaxed);
        let old_inc = window.incarnation.load(Ordering::Relaxed);
        let old_mode = window.mode.load(Ordering::Relaxed);
        let old_since = window.since_tick.load(Ordering::Relaxed);

        let (target_rec, target_inc) = if next_mode == MODE_OFF {
            (0, 0)
        } else if let Some(rec) = record {
            (rec.id.raw(), rec.incarnation)
        } else {
            (old_rec, old_inc)
        };

        window.seq.fetch_add(1, Ordering::AcqRel);
        if old_mode != MODE_OFF {
            let delta = now.saturating_sub(old_since);
            if delta != 0 {
                if old_rec != 0 && (old_rec as usize) < ZONE_RECORDS {
                    let row = &self.records[old_rec as usize];
                    if row.incarnation.load(Ordering::Acquire) == old_inc {
                        if old_mode == MODE_USER {
                            row.user_ticks.fetch_add(delta, Ordering::AcqRel);
                        } else if old_mode == MODE_SYSTEM {
                            row.system_ticks.fetch_add(delta, Ordering::AcqRel);
                        }
                    }
                } else if old_mode == MODE_USER {
                    window
                        .unadmitted_user_ticks
                        .fetch_add(delta, Ordering::AcqRel);
                } else if old_mode == MODE_SYSTEM {
                    window
                        .unadmitted_system_ticks
                        .fetch_add(delta, Ordering::AcqRel);
                }
            }
        }

        if old_rec != 0 && old_rec != target_rec && (old_rec as usize) < ZONE_RECORDS {
            let old_row = &self.records[old_rec as usize];
            if old_row.incarnation.load(Ordering::Acquire) == old_inc {
                let _ = old_row.active_slot.compare_exchange(
                    slot_index as u32 + 1,
                    0,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }

        if target_rec != 0 && (target_rec as usize) < ZONE_RECORDS {
            let new_row = &self.records[target_rec as usize];
            if old_rec == 0 {
                let u = window.unadmitted_user_ticks.swap(0, Ordering::AcqRel);
                let s = window.unadmitted_system_ticks.swap(0, Ordering::AcqRel);
                if (u != 0 || s != 0) && new_row.incarnation.load(Ordering::Acquire) == target_inc {
                    if u != 0 {
                        new_row.user_ticks.fetch_add(u, Ordering::AcqRel);
                    }
                    if s != 0 {
                        new_row.system_ticks.fetch_add(s, Ordering::AcqRel);
                    }
                }
            }
            if new_row.incarnation.load(Ordering::Acquire) == target_inc {
                new_row
                    .active_slot
                    .store(slot_index as u32 + 1, Ordering::Release);
            }
        }

        window.record.store(target_rec, Ordering::Relaxed);
        window.incarnation.store(target_inc, Ordering::Relaxed);
        window.mode.store(next_mode, Ordering::Relaxed);
        window.since_tick.store(now, Ordering::Relaxed);
        window.seq.fetch_add(1, Ordering::Release);
    }

    #[inline(never)]
    pub fn sample_record(&self, record: RecordRef, now: Option<CounterTick>) -> CpuTickPair {
        let index = record.id.index();
        if index >= ZONE_RECORDS {
            return CpuTickPair::default();
        }
        let row = &self.records[index];
        for _ in 0..64 {
            if row.incarnation.load(Ordering::Acquire) != record.incarnation {
                return CpuTickPair::default();
            }
            let slot_plus_1 = row.active_slot.load(Ordering::Acquire);
            if let (Some(now_tick), Some(slot_index)) = (now, slot_plus_1.checked_sub(1))
                && (slot_index as usize) < ZONE_SLOTS
            {
                let window = &self.slots[slot_index as usize];
                let seq1 = window.seq.load(Ordering::Acquire);
                if seq1 & 1 != 0 {
                    core::hint::spin_loop();
                    continue;
                }
                let mut user = row.user_ticks.load(Ordering::Acquire);
                let mut system = row.system_ticks.load(Ordering::Acquire);
                let w_rec = window.record.load(Ordering::Acquire);
                let w_inc = window.incarnation.load(Ordering::Acquire);
                let w_mode = window.mode.load(Ordering::Acquire);
                let w_since = window.since_tick.load(Ordering::Acquire);
                let seq2 = window.seq.load(Ordering::Acquire);
                if seq1 != seq2 {
                    core::hint::spin_loop();
                    continue;
                }
                if row.incarnation.load(Ordering::Acquire) != record.incarnation {
                    return CpuTickPair::default();
                }
                if w_rec == record.id.raw() && w_inc == record.incarnation {
                    let delta = now_tick.raw().saturating_sub(w_since);
                    if w_mode == MODE_USER {
                        user = user.saturating_add(delta);
                    } else if w_mode == MODE_SYSTEM {
                        system = system.saturating_add(delta);
                    }
                }
                return CpuTickPair { user, system };
            }
            let user = row.user_ticks.load(Ordering::Acquire);
            let system = row.system_ticks.load(Ordering::Acquire);
            if row.incarnation.load(Ordering::Acquire) != record.incarnation {
                return CpuTickPair::default();
            }
            return CpuTickPair { user, system };
        }
        let user = row.user_ticks.load(Ordering::Acquire);
        let system = row.system_ticks.load(Ordering::Acquire);
        if row.incarnation.load(Ordering::Acquire) != record.incarnation {
            return CpuTickPair::default();
        }
        CpuTickPair { user, system }
    }

    pub fn ratchet_record_nanos(&self, record: RecordRef, nanos: u64) -> u64 {
        let index = record.id.index();
        if index >= ZONE_RECORDS {
            return nanos;
        }
        let row = &self.records[index];
        if row.incarnation.load(Ordering::Acquire) != record.incarnation {
            return nanos;
        }
        row.last_reported_ns
            .fetch_max(nanos, Ordering::AcqRel)
            .max(nanos)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::RecordId;
    use std::boxed::Box;

    fn ledger() -> Box<ZoneCpuLedger> {
        // SAFETY: all-zero bytes are an empty ledger; every field is atomic.
        unsafe { Box::<ZoneCpuLedger>::new_zeroed().assume_init() }
    }

    /// An initial root the scheduler never switched in has no current
    /// record, so it re-enters the ring after a host crossing naming none.
    /// The crossing charges nothing and keeps the root's record bound.
    #[test]
    fn a_host_crossing_keeps_an_unscheduled_record_bound() {
        let ledger = ledger();
        let slot = SlotId::from_index(0).unwrap();
        let record = RecordRef {
            id: RecordId::from_raw(1).unwrap(),
            incarnation: 7,
        };
        ledger.reset_record(record.id, record.incarnation);
        ledger.enter_user(slot, None, CounterTick::new(100));
        ledger.adopt_unadmitted(slot, record);
        ledger.enter_ring(slot, None, CounterTick::new(200));
        ledger.cross_to_host(slot, CounterTick::new(250));
        ledger.enter_ring(slot, None, CounterTick::new(1_000));
        ledger.enter_user(slot, None, CounterTick::new(1_010));
        assert_eq!(
            ledger.sample_record(record, Some(CounterTick::new(2_010))),
            CpuTickPair {
                user: 1_100,
                system: 60
            }
        );
        // A departure still unbinds: the slot then charges nobody.
        ledger.leave_slot(slot, CounterTick::new(2_010));
        ledger.enter_user(slot, None, CounterTick::new(2_020));
        assert_eq!(
            ledger.sample_record(record, Some(CounterTick::new(3_020))),
            CpuTickPair {
                user: 1_100,
                system: 60
            }
        );
    }
}
