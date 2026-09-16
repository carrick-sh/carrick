//! Per-namespace PID-numbering slots in the kernel arena.
//!
//! One `ProcessSection` record table serves every container in the carrier —
//! Linux's own model: one process table, per-namespace membership. A member's
//! ns pid is its kernel task id (the kernel graph's `IdRegistry` is the pid
//! domain of the container's namespace, init being task 1); there is
//! deliberately no second counter here, because an independently ticked
//! number drifted from the task id and left `getpid()` naming a task `/proc`
//! did not list. Each PID namespace claims one slot for its ns-init identity
//! words and tags its member records with its `ns_id`
//! (`ProcessRecord::pid_ns`), so two containers' `ns_to_host(1)` name two
//! different inits. Slots are claimed by CAS and released only by
//! the exact generation-stamped reference the owner holds, so a stale handle
//! can never free a slot a later namespace has reused.

use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arena::ArenaError;
use crate::domains::ProcessGeneration;

/// Namespace slots per carrier arena. Exhaustion is loud
/// (`ArenaError::Exhausted`), never a silent fallback to a shared counter.
pub const PID_NAMESPACE_SLOTS: usize = 64;

/// Set in `owner` while the claimant resets the numbering words; readers treat
/// such a slot as unpublished.
const CLAIMING: u64 = 1 << 63;

#[repr(C)]
pub struct PidNamespaceSlot {
    /// `0` = free. Published value is exactly `pack(ns_id, generation)`;
    /// `pack(..) | CLAIMING` while the claimant is still resetting the slot.
    pub owner: AtomicU64,
    pub init_host_pid: AtomicU32,
    pub init_host_pgid: AtomicU32,
    pub init_host_sid: AtomicU32,
    pub init_sig_handlers: AtomicU64,
}

#[repr(C)]
pub struct PidNamespaceSection {
    pub slots: [PidNamespaceSlot; PID_NAMESPACE_SLOTS],
}

/// Index + generation + namespace id, so a stale ref cannot touch a reused
/// slot (same discipline as `ProcessRecordRef`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidNamespaceRef {
    pub index: usize,
    pub generation: ProcessGeneration,
    pub ns_id: NonZeroU32,
}

fn pack(ns_id: NonZeroU32, generation: ProcessGeneration) -> u64 {
    (u64::from(generation.raw()) << 32) | u64::from(ns_id.get())
}

impl PidNamespaceSection {
    /// Claim a free slot for `ns_id`, reset its identity words, and publish
    /// the owner word last. Returns the reference the owner must present to
    /// [`Self::release`] and the slot itself (valid until that release).
    pub fn claim(
        &self,
        ns_id: NonZeroU32,
        generation: ProcessGeneration,
    ) -> Result<(PidNamespaceRef, &PidNamespaceSlot), ArenaError> {
        let packed = pack(ns_id, generation);
        for (index, slot) in self.slots.iter().enumerate() {
            if slot
                .owner
                .compare_exchange(0, packed | CLAIMING, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            slot.init_host_pid.store(0, Ordering::Relaxed);
            slot.init_host_pgid.store(0, Ordering::Relaxed);
            slot.init_host_sid.store(0, Ordering::Relaxed);
            slot.init_sig_handlers.store(0, Ordering::Relaxed);
            slot.owner.store(packed, Ordering::Release);
            return Ok((
                PidNamespaceRef {
                    index,
                    generation,
                    ns_id,
                },
                slot,
            ));
        }
        Err(ArenaError::Exhausted {
            section: "pid_namespaces",
            capacity: PID_NAMESPACE_SLOTS,
        })
    }

    /// The slot `r` names, or `None` once it was released or reclaimed.
    pub fn slot(&self, r: PidNamespaceRef) -> Option<&PidNamespaceSlot> {
        let slot = self.slots.get(r.index)?;
        (slot.owner.load(Ordering::Acquire) == pack(r.ns_id, r.generation)).then_some(slot)
    }

    /// Release the slot `r` names. `false` if it was already released or has
    /// been reclaimed by a later namespace — a stale ref never frees a reused
    /// slot.
    pub fn release(&self, r: PidNamespaceRef) -> bool {
        let Some(slot) = self.slots.get(r.index) else {
            return false;
        };
        slot.owner
            .compare_exchange(
                pack(r.ns_id, r.generation),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Slots currently owned — the number of live PID namespaces.
    pub fn claimed(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.owner.load(Ordering::Acquire) != 0)
            .count()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::arena::{ArenaError, KernelArena};

    fn ns(id: u32) -> NonZeroU32 {
        NonZeroU32::new(id).unwrap()
    }

    #[test]
    fn two_claims_take_disjoint_slots_with_fresh_identity() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        let (a, a_slot) = section.claim(ns(2), arena.allocate_generation()).unwrap();
        let (b, b_slot) = section.claim(ns(3), arena.allocate_generation()).unwrap();
        assert_ne!(a.index, b.index);
        a_slot.init_host_pid.store(4100, Ordering::Release);
        assert_eq!(
            b_slot.init_host_pid.load(Ordering::Acquire),
            0,
            "b's identity is untouched by a's init publication"
        );
        assert!(std::ptr::eq(section.slot(a).unwrap(), a_slot));
        assert_eq!(section.claimed(), 2);
    }

    #[test]
    fn release_returns_the_slot_for_reuse_and_resets_it() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        let (a, a_slot) = section.claim(ns(2), arena.allocate_generation()).unwrap();
        let (b, _) = section.claim(ns(3), arena.allocate_generation()).unwrap();
        a_slot.init_host_pid.store(4100, Ordering::Relaxed);
        a_slot.init_host_pgid.store(4100, Ordering::Relaxed);
        assert!(section.release(a));
        assert!(
            section.slot(a).is_none(),
            "a released ref no longer resolves"
        );
        let (c, c_slot) = section.claim(ns(4), arena.allocate_generation()).unwrap();
        assert_eq!(c.index, a.index, "the freed slot is reused first");
        assert_ne!(c.index, b.index);
        assert_eq!(c_slot.init_host_pid.load(Ordering::Acquire), 0);
        assert_eq!(c_slot.init_host_pgid.load(Ordering::Acquire), 0);
        assert!(
            !section.release(a),
            "a stale ref cannot free the reused slot"
        );
        assert!(section.slot(c).is_some());
        assert_eq!(section.claimed(), 2);
    }

    #[test]
    fn exhaustion_is_loud() {
        let arena = KernelArena::create().unwrap();
        let section = &arena.layout().pid_namespaces;
        for i in 0..PID_NAMESPACE_SLOTS {
            section
                .claim(ns(2 + i as u32), arena.allocate_generation())
                .unwrap();
        }
        assert!(matches!(
            section.claim(ns(999), arena.allocate_generation()),
            Err(ArenaError::Exhausted {
                section: "pid_namespaces",
                capacity: PID_NAMESPACE_SLOTS
            })
        ));
    }
}
