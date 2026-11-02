//! Which address space each vCPU is running: the one authority for "vCPU
//! slot `s` executes address space `Y`" (EL1 increment 2, step 1).
//!
//! A slot here is an [`ExecutionSlot`]: a zone slot (the syscall-mailbox
//! slot a vCPU leases, [`SlotId`]) or, for a vCPU that has no mailbox lease
//! (a staged root, or a backend without the EL1 mailbox), a host-only slot
//! allocated from the same table. Each slot holds one word: the key of the
//! address space installed on that vCPU (0: none).
//!
//! Every reader of "who may be executing `Y`" (a stage-1 page-table pause,
//! the frame-COW sole check, the fork and crash drains, ASID retirement)
//! scans this table for `Y`; none of them asks which *thread* an executor
//! loaded. So whoever changes a vCPU's address space (today the host loading
//! a task; later EL1 switching `TTBR0_EL1` between threads of different
//! processes) keeps every reader true by writing one word here.
//!
//! # Ordering (the Dekker pair every installer and pauser follows)
//!
//! An address space `Y` has a fence (on the host, `Y`'s page-table pause
//! barrier). A pauser raises the fence, then scans the table; an installer
//! publishes `Y` on its slot here, then (later, before it runs guest code)
//! marks the vCPU in guest and reads the fence. Every store and load of the
//! pair is `SeqCst`, so in the single total order either the installer's
//! fence read follows the pauser's raise (it sees the fence and does not
//! run) or the pauser's scan follows the installer's publication (it sees
//! the slot and drains it). A slot is vacated only while its vCPU is out of
//! the guest, so a scan that misses a vacated slot misses nothing running.
//!
//! All-zero bytes are a valid empty table, so the table can live in the
//! shared EL1 region as well as in host memory.

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{SlotId, ZONE_SLOTS};

/// Host-only execution slots, for vCPUs without a mailbox lease.
pub const HOST_EXECUTION_SLOTS: usize = 256;

/// Every execution slot: the zone slots, then the host-only ones.
pub const EXECUTION_SLOTS: usize = ZONE_SLOTS + HOST_EXECUTION_SLOTS;

const OCCUPIED_WORDS: usize = EXECUTION_SLOTS / 64;
const HOST_WORDS: usize = HOST_EXECUTION_SLOTS / 64;

#[cfg(not(all(test, feature = "loom")))]
const _: () = assert!(ZONE_SLOTS.is_multiple_of(64));
const _: () = assert!(HOST_EXECUTION_SLOTS.is_multiple_of(64));

/// A vCPU's execution slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct ExecutionSlot(u16);

impl ExecutionSlot {
    /// The execution slot of a zone slot (the vCPU's mailbox lease).
    pub const fn zone(slot: SlotId) -> Self {
        Self(slot.raw() as u16)
    }

    /// The zone slot, if this is one.
    pub fn as_zone(self) -> Option<SlotId> {
        u8::try_from(self.0).ok().map(SlotId::new)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// The slot at `index`, if it is one.
    pub fn from_index(index: usize) -> Option<Self> {
        (index < EXECUTION_SLOTS)
            .then(|| u16::try_from(index).ok().map(Self))
            .flatten()
    }
}

/// The key of an address space (the zone key: the host's exact MM id).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(transparent)]
pub struct AddressSpaceKey(NonZeroU64);

impl AddressSpaceKey {
    pub const fn new(raw: NonZeroU64) -> Self {
        Self(raw)
    }

    pub fn from_raw(raw: u64) -> Option<Self> {
        NonZeroU64::new(raw).map(Self)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// An install found the slot already running an address space.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotBusy {
    pub running: AddressSpaceKey,
}

/// The table. See the module docs.
#[repr(C, align(64))]
pub struct Occupancy {
    /// Per slot: the key of the address space installed (0: none).
    running: [AtomicU64; EXECUTION_SLOTS],
    /// One bit per slot whose word is nonzero (a scan hint; the word
    /// decides).
    occupied: [AtomicU64; OCCUPIED_WORDS],
    /// One bit per host-only slot that is allocated.
    host_allocated: [AtomicU64; HOST_WORDS],
}

impl Default for Occupancy {
    fn default() -> Self {
        Self::new()
    }
}

impl Occupancy {
    pub const fn new() -> Self {
        Self {
            running: [const { AtomicU64::new(0) }; EXECUTION_SLOTS],
            occupied: [const { AtomicU64::new(0) }; OCCUPIED_WORDS],
            host_allocated: [const { AtomicU64::new(0) }; HOST_WORDS],
        }
    }

    /// Publish that `slot`'s vCPU runs `space`. The slot must be empty: one
    /// vCPU runs one address space at a time.
    pub fn install(&self, slot: ExecutionSlot, space: AddressSpaceKey) -> Result<(), SlotBusy> {
        let index = slot.index();
        if let Err(current) =
            self.running[index].compare_exchange(0, space.raw(), Ordering::SeqCst, Ordering::SeqCst)
        {
            return Err(SlotBusy {
                running: AddressSpaceKey::from_raw(current).unwrap_or(space),
            });
        }
        // The hint after the word: an installer marks its vCPU in guest and
        // reads the fence only after this, so a scan ordered after that
        // fence read sees the bit (module docs). A concurrent vacate of the
        // slot's previous occupant re-checks the word after clearing.
        self.occupied[index / 64].fetch_or(1 << (index % 64), Ordering::SeqCst);
        Ok(())
    }

    /// Replace `from` with `to` on `slot` (the shape of an in-guest
    /// address-space switch). False if the slot does not run `from`. The
    /// caller follows `to`'s fence exactly as an install does.
    pub fn switch(&self, slot: ExecutionSlot, from: AddressSpaceKey, to: AddressSpaceKey) -> bool {
        self.running[slot.index()]
            .compare_exchange(from.raw(), to.raw(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Replace `slot`'s word `from` with `to` (either may be 0, no address
    /// space): the in-guest shape of an address-space switch, by the vCPU's
    /// own EL1. False if the slot does not hold `from`. A nonzero `to` sets
    /// the scan hint before the caller reads `to`'s gate (module docs); a
    /// zero `to` clears it as [`Self::vacate`] does.
    pub fn replace(&self, slot: ExecutionSlot, from: u64, to: u64) -> bool {
        let index = slot.index();
        if self.running[index]
            .compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        if to != 0 {
            self.occupied[index / 64].fetch_or(1 << (index % 64), Ordering::SeqCst);
        } else {
            self.occupied[index / 64].fetch_and(!(1 << (index % 64)), Ordering::SeqCst);
            if self.running[index].load(Ordering::SeqCst) != 0 {
                self.occupied[index / 64].fetch_or(1 << (index % 64), Ordering::SeqCst);
            }
        }
        true
    }

    /// Empty `slot` whatever address space it holds (the host, with the
    /// vCPU out of the guest: EL1 may have switched it since the executor
    /// installed its own). Returns what it held (0: nothing).
    pub fn vacate_any(&self, slot: ExecutionSlot) -> u64 {
        let index = slot.index();
        let held = self.running[index].swap(0, Ordering::SeqCst);
        if held != 0 {
            self.occupied[index / 64].fetch_and(!(1 << (index % 64)), Ordering::SeqCst);
            if self.running[index].load(Ordering::SeqCst) != 0 {
                self.occupied[index / 64].fetch_or(1 << (index % 64), Ordering::SeqCst);
            }
        }
        held
    }

    /// The raw word of `slot` (0: none).
    pub fn running_raw(&self, slot: ExecutionSlot) -> u64 {
        self.running[slot.index()].load(Ordering::SeqCst)
    }

    /// `slot`'s vCPU no longer runs `space`; only while it is out of the
    /// guest. False if the slot did not run `space`.
    pub fn vacate(&self, slot: ExecutionSlot, space: AddressSpaceKey) -> bool {
        let index = slot.index();
        let vacated = self.running[index]
            .compare_exchange(space.raw(), 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if vacated {
            self.occupied[index / 64].fetch_and(!(1 << (index % 64)), Ordering::SeqCst);
            // A new occupant may have installed between the word's release
            // and the clear, and set its bit before the clear: re-set it.
            if self.running[index].load(Ordering::SeqCst) != 0 {
                self.occupied[index / 64].fetch_or(1 << (index % 64), Ordering::SeqCst);
            }
        }
        vacated
    }

    /// The address space `slot`'s vCPU runs.
    pub fn running(&self, slot: ExecutionSlot) -> Option<AddressSpaceKey> {
        AddressSpaceKey::from_raw(self.running[slot.index()].load(Ordering::SeqCst))
    }

    /// Call `visit` for every slot running `space`, in slot order.
    pub fn for_each_running(&self, space: AddressSpaceKey, mut visit: impl FnMut(ExecutionSlot)) {
        for (word_index, word) in self.occupied.iter().enumerate() {
            let mut bits = word.load(Ordering::SeqCst);
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let index = word_index * 64 + bit;
                if self.running[index].load(Ordering::SeqCst) == space.raw() {
                    visit(ExecutionSlot(index as u16));
                }
            }
        }
    }

    /// Whether any slot runs `space`.
    pub fn is_running_anywhere(&self, space: AddressSpaceKey) -> bool {
        let mut found = false;
        self.for_each_running(space, |_| found = true);
        found
    }

    /// Allocate a host-only slot (a vCPU without a mailbox lease).
    pub fn alloc_host_slot(&self) -> Option<ExecutionSlot> {
        for (word_index, word) in self.host_allocated.iter().enumerate() {
            let mut current = word.load(Ordering::Acquire);
            while current != u64::MAX {
                let bit = (!current).trailing_zeros() as usize;
                match word.compare_exchange_weak(
                    current,
                    current | (1 << bit),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        return Some(ExecutionSlot((ZONE_SLOTS + word_index * 64 + bit) as u16));
                    }
                    Err(observed) => current = observed,
                }
            }
        }
        None
    }

    /// Return a host-only slot. It must be empty.
    pub fn free_host_slot(&self, slot: ExecutionSlot) -> bool {
        let Some(host) = slot.index().checked_sub(ZONE_SLOTS) else {
            return false;
        };
        if self.running[slot.index()].load(Ordering::SeqCst) != 0 {
            return false;
        }
        let bit = 1 << (host % 64);
        self.host_allocated[host / 64].fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }
}

/// How a switch-in of address space `space` treats the vCPU's live
/// translation root (#1100), on either ISA. The slot's word is only half of
/// "this vCPU runs `space`". A kept word is authenticated twice: against the
/// space's open grant (gate open, key still `space`, no owed invalidation;
/// [`crate::AddressSpaces::grant`]) and with the live root against the
/// grant's root. Roots are table base addresses; the caller masks ISA tag
/// bits (ARM's ASID and CnP).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchInRoot {
    /// The word names `space`, its grant is open with nothing owed, and the
    /// live root is the grant's root (or the CPU cannot report one): run on
    /// it, with no install.
    Keep,
    /// The word names `space` and its grant is open, but the live root is
    /// another table: an exit left the word behind while the root was
    /// rewritten. ARM fails loud here (every exit vacates there); x86
    /// reinstalls (#1405).
    StaleWord,
    /// Install `space` through the installer protocol (word, then gate),
    /// which refuses a raised gate or a freed key. Chosen as well for a kept
    /// word whose grant is refused or owes an invalidation, so a kept word
    /// never bypasses the gate. When `leave_live_root`, the live root is not
    /// the maintenance root, so the CPU moves there first: vacancy is never
    /// published on a slot whose live root still names a space.
    Install { leave_live_root: bool },
}

/// The open grant a kept word is checked against: its root and whether an
/// invalidation is owed before the space may run again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeptGrant {
    pub root: u64,
    pub invalidation_owed: bool,
}

/// What authenticates a kept word for `space` ([`crate::AddressSpaces::kept_authority`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeptAuthority {
    /// Published with its gate open.
    Open(KeptGrant),
    /// Published, but its gate is raised or closed (a pause, a retirement)
    /// or the entry no longer names `space`: never kept.
    Refused,
    /// No published entry names `space`. EL1 installs only published
    /// spaces, so such a word is a host installer's (its task's own roots
    /// are live), governed by the host's occupancy, not by an EL1 gate.
    Unpublished,
}

/// Decide [`SwitchInRoot`] from the slot's word, the live root, `space`'s
/// [`KeptAuthority`] and the maintenance root.
pub fn switch_in_root(
    installed: u64,
    space: u64,
    live: Option<u64>,
    authority: KeptAuthority,
    maintenance: u64,
) -> SwitchInRoot {
    if space != 0 && installed == space {
        match (authority, live) {
            (KeptAuthority::Open(grant), Some(live)) if live != grant.root => {
                return SwitchInRoot::StaleWord;
            }
            (KeptAuthority::Open(grant), Some(_)) if !grant.invalidation_owed => {
                return SwitchInRoot::Keep;
            }
            (KeptAuthority::Unpublished, _) => return SwitchInRoot::Keep,
            _ => {}
        }
    }
    SwitchInRoot::Install {
        leave_live_root: live != Some(maintenance),
    }
}

#[cfg(test)]
#[cfg(not(feature = "loom"))]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, AtomicU32};
    use std::sync::Arc;
    use std::vec::Vec;

    fn key(raw: u64) -> AddressSpaceKey {
        AddressSpaceKey::from_raw(raw).unwrap()
    }

    fn running(table: &Occupancy, space: AddressSpaceKey) -> Vec<usize> {
        let mut slots = Vec::new();
        table.for_each_running(space, |slot| slots.push(slot.index()));
        slots
    }

    /// #1100 W6 (x86 #1405 and the ARM switch-in): a kept word is trusted
    /// only with an open grant and its own live root. A word left over a
    /// rewritten root is stale. A kept word whose space is regated, freed or
    /// owes an invalidation is reinstalled through the gate, never kept. An
    /// install leaves the live root first unless the CPU is already on the
    /// maintenance root, so vacancy is never published while the live root
    /// names a space.
    #[test]
    fn a_switch_in_authenticates_the_live_root_and_never_vacates_under_a_space() {
        const MAINTENANCE: u64 = 0x1000;
        const ROOT_Y: u64 = 0x7000;
        const ROOT_Z: u64 = 0x9000;
        let open = KeptAuthority::Open(KeptGrant {
            root: ROOT_Y,
            invalidation_owed: false,
        });
        let plan = |installed, live| switch_in_root(installed, 7, live, open, MAINTENANCE);
        let reinstall = |leave_live_root| SwitchInRoot::Install { leave_live_root };
        assert_eq!(plan(7, Some(ROOT_Y)), SwitchInRoot::Keep);
        assert_eq!(plan(7, Some(MAINTENANCE)), SwitchInRoot::StaleWord);
        assert_eq!(plan(7, Some(ROOT_Z)), SwitchInRoot::StaleWord);
        // An unreadable root cannot authenticate an open grant.
        assert_eq!(plan(7, None), reinstall(true));
        // Regated, closed or re-keyed: through the gate again.
        let refused = KeptAuthority::Refused;
        assert_eq!(
            switch_in_root(7, 7, Some(ROOT_Y), refused, MAINTENANCE),
            reinstall(true)
        );
        assert_eq!(
            switch_in_root(7, 7, Some(MAINTENANCE), refused, MAINTENANCE),
            reinstall(false)
        );
        // A word no published entry names is a host installer's.
        assert_eq!(
            switch_in_root(7, 7, Some(ROOT_Z), KeptAuthority::Unpublished, MAINTENANCE),
            SwitchInRoot::Keep
        );
        // An owed invalidation is never skipped by a keep.
        let owed = KeptAuthority::Open(KeptGrant {
            root: ROOT_Y,
            invalidation_owed: true,
        });
        assert_eq!(
            switch_in_root(7, 7, Some(ROOT_Y), owed, MAINTENANCE),
            reinstall(true)
        );
        assert_eq!(plan(0, Some(MAINTENANCE)), reinstall(false));
        for (installed, live) in [(9, Some(ROOT_Z)), (0, Some(ROOT_Z)), (0, None)] {
            assert_eq!(
                plan(installed, live),
                reinstall(true),
                "word {installed} live {live:?}"
            );
        }
        // Space 0 is never kept.
        assert_eq!(
            switch_in_root(0, 0, Some(MAINTENANCE), open, MAINTENANCE),
            reinstall(false)
        );
    }

    #[test]
    fn one_vcpu_runs_one_address_space() {
        let table = Occupancy::new();
        let slot = ExecutionSlot::zone(SlotId::new(3));
        table.install(slot, key(7)).unwrap();
        assert_eq!(
            table.install(slot, key(9)),
            Err(SlotBusy { running: key(7) }),
            "a second install must not replace the running address space"
        );
        assert_eq!(table.running(slot), Some(key(7)));
        assert!(!table.vacate(slot, key(9)));
        assert!(table.vacate(slot, key(7)));
        assert_eq!(table.running(slot), None);
        assert!(running(&table, key(7)).is_empty());
    }

    /// The point of the authority: a vCPU that changes address space while
    /// its host executor still has another process's thread loaded is
    /// counted for the address space it runs, not the one loaded.
    #[test]
    fn a_switched_slot_is_counted_for_the_address_space_it_runs() {
        let table = Occupancy::new();
        let a = ExecutionSlot::zone(SlotId::new(0));
        let b = ExecutionSlot::zone(SlotId::new(1));
        table.install(a, key(10)).unwrap();
        table.install(b, key(20)).unwrap();
        assert!(table.switch(b, key(20), key(10)));
        assert_eq!(running(&table, key(10)), [0, 1]);
        assert!(running(&table, key(20)).is_empty());
        assert!(!table.switch(b, key(20), key(30)));
        assert!(table.vacate(b, key(10)));
        assert_eq!(running(&table, key(10)), [0]);
    }

    #[test]
    fn host_slots_are_distinct_from_zone_slots_and_reusable() {
        let table = Occupancy::new();
        let mut taken = Vec::new();
        for _ in 0..HOST_EXECUTION_SLOTS {
            let slot = table.alloc_host_slot().unwrap();
            assert!(slot.index() >= ZONE_SLOTS && slot.as_zone().is_none());
            taken.push(slot);
        }
        assert!(table.alloc_host_slot().is_none());
        table.install(taken[5], key(1)).unwrap();
        assert!(
            !table.free_host_slot(taken[5]),
            "an occupied slot is not free"
        );
        assert!(table.vacate(taken[5], key(1)));
        assert!(table.free_host_slot(taken[5]));
        assert_eq!(table.alloc_host_slot(), Some(taken[5]));
        assert!(!table.free_host_slot(ExecutionSlot::zone(SlotId::new(1))));
    }

    /// The Dekker pair of the module docs, with more installers than slots
    /// cycling two address spaces through shared slots (installs, switches
    /// and vacates), against a pauser of one of them. An installer that
    /// passed the fence while the pauser believes the address space drained
    /// is a violation.
    #[test]
    fn a_pause_never_misses_a_vcpu_about_to_run_its_address_space() {
        const SLOTS: usize = 4;
        const INSTALLERS: usize = 8;
        const ROUNDS: u32 = 2_000;
        const MIN_ENTRIES: u32 = 200_000;
        let y = key(0x1111);
        let z = key(0x2222);
        let table = Arc::new(Occupancy::new());
        let fence = Arc::new(AtomicBool::new(false));
        let drained = Arc::new(AtomicBool::new(false));
        let in_guest: Arc<[AtomicU32; SLOTS]> = Arc::new([const { AtomicU32::new(0) }; SLOTS]);
        let slot_locks: Arc<[AtomicBool; SLOTS]> =
            Arc::new([const { AtomicBool::new(false) }; SLOTS]);
        let stop = Arc::new(AtomicBool::new(false));
        let violations = Arc::new(AtomicU32::new(0));
        let entries = Arc::new(AtomicU32::new(0));
        let mut installers = Vec::new();
        for id in 0..INSTALLERS {
            let (table, fence, drained, in_guest, slot_locks, stop, violations, entries) = (
                table.clone(),
                fence.clone(),
                drained.clone(),
                in_guest.clone(),
                slot_locks.clone(),
                stop.clone(),
                violations.clone(),
                entries.clone(),
            );
            installers.push(std::thread::spawn(move || {
                let mut turn = id;
                while !stop.load(Ordering::Relaxed) {
                    turn += 1;
                    let index = turn % SLOTS;
                    // One executor per vCPU at a time.
                    if slot_locks[index]
                        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                        .is_err()
                    {
                        continue;
                    }
                    let slot = ExecutionSlot::zone(SlotId::new(index as u8));
                    let (first, second) = if turn % 2 == 0 { (y, z) } else { (z, y) };
                    table.install(slot, first).unwrap();
                    let mut current = first;
                    for _ in 0..2 {
                        // Enter the guest for `current`: mark, then read the
                        // fence (only `y` is fenced here).
                        in_guest[index].store(1, Ordering::SeqCst);
                        if current != y || !fence.load(Ordering::SeqCst) {
                            entries.fetch_add(1, Ordering::Relaxed);
                            if current == y && drained.load(Ordering::SeqCst) {
                                violations.fetch_add(1, Ordering::Relaxed);
                            }
                            for _ in 0..32 {
                                core::hint::spin_loop();
                            }
                            if current == y && drained.load(Ordering::SeqCst) {
                                violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        in_guest[index].store(0, Ordering::SeqCst);
                        // Switch address space on the vCPU, as EL1 would.
                        assert!(table.switch(slot, current, second));
                        current = second;
                    }
                    assert!(table.vacate(slot, current));
                    slot_locks[index].store(false, Ordering::Release);
                }
            }));
        }
        let mut rounds = 0;
        while rounds < ROUNDS || entries.load(Ordering::Relaxed) < MIN_ENTRIES {
            rounds += 1;
            fence.store(true, Ordering::SeqCst);
            let mut pending = Vec::new();
            table.for_each_running(y, |slot| pending.push(slot.index()));
            // A pause kicks and waits; here the installers leave by
            // themselves, and only the scanned slots are waited for.
            for index in pending {
                while in_guest[index].load(Ordering::SeqCst) != 0 {
                    core::hint::spin_loop();
                }
            }
            drained.store(true, Ordering::SeqCst);
            for _ in 0..2_000 {
                core::hint::spin_loop();
            }
            drained.store(false, Ordering::SeqCst);
            fence.store(false, Ordering::SeqCst);
        }
        stop.store(true, Ordering::Relaxed);
        for installer in installers {
            installer.join().unwrap();
        }
        assert!(entries.load(Ordering::Relaxed) > 0);
        assert_eq!(violations.load(Ordering::Relaxed), 0);
    }
}
