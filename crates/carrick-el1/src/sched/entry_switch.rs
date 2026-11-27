//! The scheduler switch a park owes its entry (#3093).
//!
//! A park vacates its slot. Choosing and loading the next thread runs that
//! thread's resume (a wait4 checkpoint, a signal delivery) on the current
//! stack, so it must happen where only the entry's frames are live, never
//! beneath the park site's own frames: the arm64 `apt-get update` overflow
//! resumed a wait4 checkpoint under `serve_ipc_with_signals`. A park site
//! stages its [`OwedSwitch`] and returns `Served::Idle`, which every park
//! caller already unwinds as a released slot; the entry runs the switch
//! ([`Sched::run_entry_switch`]) once the dispatch has unwound.
//!
//! A thread the scheduler resumes may itself park. Its stage is discharged
//! where `load` reports that it left: the scheduler loop that loaded it
//! chooses again, so the slot owes nothing more.
//!
//! The cell is the slot's own: only the vCPU running that slot's EL1 entry
//! stages or takes it.

use crate::substrate::sched::{Sched, Served, ThreadCpu, UserWord};
use carrick_el1_abi::{SlotId, TrapFrame};

/// What the entry must run for a slot a park vacated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwedSwitch {
    /// Run the next runnable thread, or idle ([`Sched::run_next`]);
    /// `timeout_result` is the result of a timed futex the idle loop serves.
    Next { timeout_result: u64 },
    /// Run only zone work that is already ready, else keep the caller's
    /// host handoff ([`Sched::run_ready`]).
    Ready,
}

impl OwedSwitch {
    /// Two parks in one entry (a lifecycle transfer that parked through a
    /// park site): the full switch covers the ready-only one.
    fn merge(self, later: Self) -> Self {
        match (self, later) {
            (Self::Next { .. }, _) => self,
            (Self::Ready, later) => later,
        }
    }
}

#[cfg(target_os = "none")]
mod cell {
    use crate::substrate::sched::entry_switch::OwedSwitch;
    use carrick_el1_abi::SlotId;
    use core::sync::atomic::{AtomicU64, Ordering};

    const NONE: u64 = 0;
    const READY: u64 = 1;
    const NEXT: u64 = 2;

    struct Cell {
        kind: AtomicU64,
        timeout_result: AtomicU64,
    }

    static CELLS: [Cell; carrick_sched_core::ZONE_SLOTS] = [const {
        Cell {
            kind: AtomicU64::new(NONE),
            timeout_result: AtomicU64::new(0),
        }
    }; carrick_sched_core::ZONE_SLOTS];

    fn decode(cell: &Cell, kind: u64) -> Option<OwedSwitch> {
        match kind {
            READY => Some(OwedSwitch::Ready),
            NEXT => Some(OwedSwitch::Next {
                timeout_result: cell.timeout_result.load(Ordering::Relaxed),
            }),
            _ => None,
        }
    }

    pub(super) fn replace(slot: SlotId, owed: Option<OwedSwitch>) -> Option<OwedSwitch> {
        let cell = &CELLS[usize::from(slot.raw())];
        let kind = match owed {
            None => NONE,
            Some(OwedSwitch::Ready) => READY,
            Some(OwedSwitch::Next { timeout_result }) => {
                cell.timeout_result.store(timeout_result, Ordering::Relaxed);
                NEXT
            }
        };
        let previous = cell.kind.swap(kind, Ordering::Relaxed);
        decode(cell, previous)
    }
}

#[cfg(not(target_os = "none"))]
mod cell {
    use crate::substrate::sched::entry_switch::OwedSwitch;
    use carrick_el1_abi::SlotId;

    // One fixed cell per slot, as at EL1: staging a switch never allocates
    // (the zero-allocation I/O witnesses run through this tail). Per thread,
    // because host tests share a process.
    std::thread_local! {
        static CELLS: [core::cell::Cell<Option<OwedSwitch>>; carrick_sched_core::ZONE_SLOTS] =
            const { [const { core::cell::Cell::new(None) }; carrick_sched_core::ZONE_SLOTS] };
    }

    pub(super) fn replace(slot: SlotId, owed: Option<OwedSwitch>) -> Option<OwedSwitch> {
        CELLS.with(|cells| cells[usize::from(slot.raw())].replace(owed))
    }
}

fn stage(slot: SlotId, owed: OwedSwitch) {
    let merged = cell::replace(slot, None).map_or(owed, |earlier| earlier.merge(owed));
    let _ = cell::replace(slot, Some(merged));
}

/// Discharge `slot`'s owed switch: a scheduler loop is choosing for it.
pub(super) fn discharge(slot: SlotId) {
    let _ = cell::replace(slot, None);
}

/// Whether a park staged a switch for `slot` that no entry has run yet.
pub fn owed(slot: SlotId) -> bool {
    let staged = cell::replace(slot, None);
    if let Some(staged) = staged {
        let _ = cell::replace(slot, Some(staged));
    }
    staged.is_some()
}

impl<C: ThreadCpu, U: UserWord> Sched<'_, C, U> {
    /// The running thread parked: owe the switch to the entry. Returns the
    /// released slot's `Served::Idle`.
    pub fn defer_run_next(&mut self, timeout_result: u64) -> Served {
        stage(self.slot, OwedSwitch::Next { timeout_result });
        Served::Idle
    }

    /// An owned native transfer released its slot: owe the entry a run of
    /// already-ready zone work (none keeps the host handoff).
    pub fn defer_run_ready(&mut self) {
        stage(self.slot, OwedSwitch::Ready);
    }

    /// The entry boundary, with the dispatch unwound: run the switch a park
    /// owed this slot. `None`: nothing was owed.
    pub fn run_entry_switch(&mut self, frame: &mut TrapFrame) -> Option<Served> {
        let owed = cell::replace(self.slot, None)?;
        Some(match owed {
            OwedSwitch::Next { timeout_result } => self.run_next(frame, timeout_result),
            OwedSwitch::Ready => self.run_ready(frame).unwrap_or(Served::Idle),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_switch_covers_a_ready_only_one() {
        let slot = SlotId::new(1);
        discharge(slot);
        stage(slot, OwedSwitch::Ready);
        stage(slot, OwedSwitch::Next { timeout_result: 7 });
        stage(slot, OwedSwitch::Ready);
        assert!(owed(slot));
        assert_eq!(
            cell::replace(slot, None),
            Some(OwedSwitch::Next { timeout_result: 7 })
        );
        assert!(!owed(slot));
    }
}
