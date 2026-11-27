//! Who holds each backing slot of a carrier, so a slot is released exactly
//! when its last holder lets go (#3127).
//!
//! A backing slot (on x86, one KVM memslot) has three kinds of holder, each
//! one MM:
//! - an **admission**: the MM may publish leaves into the slot (the MM that
//!   owns it, or one it is shared with);
//! - an **alias**: one live descriptor edge of the MM names a page of it;
//! - a **drain debt**: the MM unlinked an alias, so one of its translation
//!   contexts must drain before the backing can go.
//!
//! Every hold is added and dropped only through [`SlotHolds`]. An MM's
//! retirement drops every hold it has at once ([`SlotHolds::retirement`]
//! plans it, [`SlotHolds::retire`] commits it), and the plan names exactly
//! the slots whose last hold that retirement dropped, whichever kind of hold
//! it was: the owner's admission, an inheritor's aliases, or the drain debt
//! an inheritor left by unmapping its last page. Those are the only slots a
//! retirement may revoke, and no slot whose holds all went is left out, so
//! no caller decides on its own which slots to look at.
//!
//! Invariants, checked by [`SlotHolds::check_invariants`]:
//! - **H1** an MM's index names exactly the slots it holds anything in;
//! - **H2** a slot's alias counts are nonzero, and its admissions and drain
//!   debts have no duplicates;
//! - **H3** a drain debt names a context of the MM it is indexed under.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::mm::MmKey;

/// A translation context a drain debt names: it belongs to one MM.
pub trait DrainContext: Copy + Eq {
    fn mm(&self) -> MmKey;
}

/// A hold edit that does not match the ledger: always a broken invariant of
/// the caller, never contention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldError {
    /// The slot is not registered (or registered twice).
    UnknownSlot,
    DuplicateSlot,
    /// An alias was dropped that the MM does not hold, or a count overflowed.
    AliasUnderflow,
    AliasOverflow,
    /// A drain debt was offered for another MM's context.
    ForeignDrain,
    /// The slot still has descriptor aliases, so it cannot be forgotten.
    StillAliased,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Holds<C> {
    admitted: Vec<MmKey>,
    aliases: BTreeMap<MmKey, usize>,
    drains: Vec<C>,
}

impl<C: DrainContext> Holds<C> {
    const fn new() -> Self {
        Self {
            admitted: Vec::new(),
            aliases: BTreeMap::new(),
            drains: Vec::new(),
        }
    }
    fn held_by(&self, mm: MmKey) -> bool {
        self.admitted.contains(&mm)
            || self.aliases.contains_key(&mm)
            || self.drains.iter().any(|drain| drain.mm() == mm)
    }
    /// Whether anything other than `mm` still holds the slot.
    fn held_beyond(&self, mm: MmKey) -> bool {
        self.admitted.iter().any(|held| *held != mm)
            || self.aliases.keys().any(|held| *held != mm)
            || self.drains.iter().any(|drain| drain.mm() != mm)
    }
    fn drop_mm(&mut self, mm: MmKey) {
        self.admitted.retain(|held| *held != mm);
        self.aliases.remove(&mm);
        self.drains.retain(|drain| drain.mm() != mm);
    }
}

/// An MM's retirement, planned before anything changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HoldRetirement<S> {
    /// Every slot the MM holds anything in.
    pub held: Vec<S>,
    /// The slots whose last hold is the MM's: nothing holds them once it
    /// retires. The caller revokes exactly these.
    pub released: Vec<S>,
    /// How many aliases the MM held, over every slot.
    pub aliases: usize,
}

/// The holds of every backing slot of one carrier, by slot id `S`.
#[derive(Clone, Debug)]
pub struct SlotHolds<S, C> {
    slots: BTreeMap<S, Holds<C>>,
    by_mm: BTreeMap<MmKey, BTreeSet<S>>,
}

impl<S: Copy + Ord, C: DrainContext> Default for SlotHolds<S, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Copy + Ord, C: DrainContext> SlotHolds<S, C> {
    pub const fn new() -> Self {
        Self {
            slots: BTreeMap::new(),
            by_mm: BTreeMap::new(),
        }
    }

    /// A newly installed slot, held by nothing yet.
    pub fn register(&mut self, slot: S) -> Result<(), HoldError> {
        if self.slots.contains_key(&slot) {
            return Err(HoldError::DuplicateSlot);
        }
        self.slots.insert(slot, Holds::new());
        Ok(())
    }

    fn holds_mut(&mut self, slot: S) -> Result<&mut Holds<C>, HoldError> {
        self.slots.get_mut(&slot).ok_or(HoldError::UnknownSlot)
    }

    /// Admit `mm` to `slot` (idempotent).
    pub fn admit(&mut self, slot: S, mm: MmKey) -> Result<(), HoldError> {
        let holds = self.holds_mut(slot)?;
        if !holds.admitted.contains(&mm) {
            holds.admitted.push(mm);
        }
        self.by_mm.entry(mm).or_default().insert(slot);
        Ok(())
    }

    /// One more descriptor alias of `mm` into `slot`.
    pub fn alias(&mut self, slot: S, mm: MmKey) -> Result<(), HoldError> {
        let holds = self.holds_mut(slot)?;
        let count = holds.aliases.entry(mm).or_default();
        *count = count.checked_add(1).ok_or(HoldError::AliasOverflow)?;
        self.by_mm.entry(mm).or_default().insert(slot);
        Ok(())
    }

    /// `mm` unlinked one alias into `slot`: the alias becomes a drain debt
    /// of `drain` (one per context), so the slot stays held until that
    /// context's MM retires or the slot is revoked with the drain.
    pub fn unalias(&mut self, slot: S, mm: MmKey, drain: C) -> Result<(), HoldError> {
        if drain.mm() != mm {
            return Err(HoldError::ForeignDrain);
        }
        let holds = self.holds_mut(slot)?;
        let count = holds
            .aliases
            .get_mut(&mm)
            .ok_or(HoldError::AliasUnderflow)?;
        *count -= 1;
        if *count == 0 {
            holds.aliases.remove(&mm);
        }
        if !holds.drains.contains(&drain) {
            holds.drains.push(drain);
        }
        // `mm` still holds the slot through the debt: its index is unchanged.
        Ok(())
    }

    /// Plan `mm`'s retirement: every slot it holds, and those it is the
    /// last holder of. Changes nothing.
    pub fn retirement(&self, mm: MmKey) -> HoldRetirement<S> {
        let mut plan = HoldRetirement {
            held: Vec::new(),
            released: Vec::new(),
            aliases: 0,
        };
        for &slot in self.by_mm.get(&mm).into_iter().flatten() {
            let Some(holds) = self.slots.get(&slot) else {
                continue;
            };
            plan.held.push(slot);
            plan.aliases += holds.aliases.get(&mm).copied().unwrap_or(0);
            if !holds.held_beyond(mm) {
                plan.released.push(slot);
            }
        }
        plan
    }

    /// Drop every hold of `mm`, returning the plan [`Self::retirement`]
    /// gave. The released slots stay registered until [`Self::forget`].
    pub fn retire(&mut self, mm: MmKey) -> HoldRetirement<S> {
        let plan = self.retirement(mm);
        for slot in self.by_mm.remove(&mm).unwrap_or_default() {
            if let Some(holds) = self.slots.get_mut(&slot) {
                holds.drop_mm(mm);
            }
        }
        plan
    }

    /// The slot leaves the carrier (revoked or rolled back). Refused while
    /// it still has aliases; its admissions and drain debts go with it (a
    /// revoke drains the debts first).
    pub fn forget(&mut self, slot: S) -> Result<(), HoldError> {
        let holds = self.slots.get(&slot).ok_or(HoldError::UnknownSlot)?;
        if !holds.aliases.is_empty() {
            return Err(HoldError::StillAliased);
        }
        let holders: Vec<MmKey> = holds
            .admitted
            .iter()
            .copied()
            .chain(holds.drains.iter().map(DrainContext::mm))
            .collect();
        self.slots.remove(&slot);
        for mm in holders {
            if let Some(slots) = self.by_mm.get_mut(&mm) {
                slots.remove(&slot);
                if slots.is_empty() {
                    self.by_mm.remove(&mm);
                }
            }
        }
        Ok(())
    }

    /// The MMs admitted to `slot`, in admission order.
    pub fn admitted(&self, slot: S) -> &[MmKey] {
        self.slots
            .get(&slot)
            .map_or(&[][..], |holds| holds.admitted.as_slice())
    }
    /// How many aliases name `slot`, over every MM.
    pub fn alias_count(&self, slot: S) -> usize {
        self.slots
            .get(&slot)
            .map_or(0, |holds| holds.aliases.values().sum())
    }
    /// The contexts that must drain before `slot` is revoked.
    pub fn drains(&self, slot: S) -> &[C] {
        self.slots
            .get(&slot)
            .map_or(&[][..], |holds| holds.drains.as_slice())
    }
    /// Whether anything holds `slot`.
    pub fn is_held(&self, slot: S) -> bool {
        self.slots.get(&slot).is_some_and(|holds| {
            !holds.admitted.is_empty() || !holds.aliases.is_empty() || !holds.drains.is_empty()
        })
    }
    /// The slots `mm` holds anything in.
    pub fn held_by(&self, mm: MmKey) -> impl Iterator<Item = S> + '_ {
        self.by_mm.get(&mm).into_iter().flatten().copied()
    }

    /// H1 to H3.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        for (&mm, slots) in &self.by_mm {
            if slots.is_empty() {
                return Err("H1: an empty MM index");
            }
            for slot in slots {
                if !self.slots.get(slot).is_some_and(|holds| holds.held_by(mm)) {
                    return Err("H1: an MM index names a slot it holds nothing in");
                }
            }
        }
        for (slot, holds) in &self.slots {
            let holders = holds
                .admitted
                .iter()
                .copied()
                .chain(holds.aliases.keys().copied())
                .chain(holds.drains.iter().map(DrainContext::mm));
            for mm in holders {
                if !self
                    .by_mm
                    .get(&mm)
                    .is_some_and(|slots| slots.contains(slot))
                {
                    return Err("H1: a holder's index misses its slot");
                }
            }
            if holds.aliases.values().any(|count| *count == 0) {
                return Err("H2: a zero alias count");
            }
            let mut admitted = holds.admitted.clone();
            admitted.sort();
            admitted.dedup();
            if admitted.len() != holds.admitted.len() {
                return Err("H2: a duplicate admission");
            }
            for (i, drain) in holds.drains.iter().enumerate() {
                if holds.drains[..i].contains(drain) {
                    return Err("H2: a duplicate drain debt");
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;
    use core::num::NonZeroU64;

    /// A context: (its MM, which of the MM's contexts).
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Ctx(MmKey, u8);
    impl DrainContext for Ctx {
        fn mm(&self) -> MmKey {
            self.0
        }
    }
    fn mm(raw: u64) -> MmKey {
        MmKey::new(NonZeroU64::new(raw).unwrap())
    }

    /// The #3127 shapes, by name. Owner 1 owns slot 7; inheritor 2 aliases
    /// it, and the owner retires first.
    #[test]
    fn a_slot_is_released_by_whichever_retirement_drops_its_last_hold() {
        // The inheritor retires with its alias.
        let mut holds = SlotHolds::<u32, Ctx>::new();
        holds.register(7).unwrap();
        holds.admit(7, mm(1)).unwrap();
        holds.alias(7, mm(2)).unwrap();
        assert!(
            holds.retire(mm(1)).released.is_empty(),
            "the alias holds it"
        );
        assert_eq!(holds.retire(mm(2)).released, [7]);
        holds.check_invariants().unwrap();

        // The inheritor unmaps first: its drain debt is its last hold.
        let mut holds = SlotHolds::<u32, Ctx>::new();
        holds.register(7).unwrap();
        holds.admit(7, mm(1)).unwrap();
        holds.alias(7, mm(2)).unwrap();
        assert!(holds.retire(mm(1)).released.is_empty());
        holds.unalias(7, mm(2), Ctx(mm(2), 0)).unwrap();
        assert!(holds.is_held(7), "the drain debt still holds it");
        assert_eq!(holds.retirement(mm(2)).released, [7]);
        assert_eq!(holds.retire(mm(2)).released, [7]);
        assert!(!holds.is_held(7));
        holds.forget(7).unwrap();
        holds.check_invariants().unwrap();

        // Cross-unmap: owner 1 owns slots 7 and 8; inheritors 2 and 3 alias
        // both; each unmaps the other's. Neither retirement refuses or waits:
        // the slot goes with whichever retires last.
        let mut holds = SlotHolds::<u32, Ctx>::new();
        for slot in [7, 8] {
            holds.register(slot).unwrap();
            holds.admit(slot, mm(1)).unwrap();
            holds.alias(slot, mm(2)).unwrap();
            holds.alias(slot, mm(3)).unwrap();
        }
        assert!(holds.retire(mm(1)).released.is_empty());
        holds.unalias(8, mm(2), Ctx(mm(2), 0)).unwrap();
        holds.unalias(7, mm(3), Ctx(mm(3), 0)).unwrap();
        assert!(holds.retire(mm(2)).released.is_empty(), "3 holds both");
        assert_eq!(holds.retire(mm(3)).released, [7, 8]);
        holds.check_invariants().unwrap();
    }

    #[test]
    fn edits_that_do_not_match_the_ledger_are_refused_and_change_nothing() {
        let mut holds = SlotHolds::<u32, Ctx>::new();
        holds.register(7).unwrap();
        assert_eq!(holds.register(7), Err(HoldError::DuplicateSlot));
        assert_eq!(holds.alias(8, mm(1)), Err(HoldError::UnknownSlot));
        assert_eq!(
            holds.unalias(7, mm(1), Ctx(mm(1), 0)),
            Err(HoldError::AliasUnderflow)
        );
        holds.alias(7, mm(1)).unwrap();
        assert_eq!(
            holds.unalias(7, mm(1), Ctx(mm(2), 0)),
            Err(HoldError::ForeignDrain)
        );
        assert_eq!(holds.forget(7), Err(HoldError::StillAliased));
        assert_eq!(holds.alias_count(7), 1);
        holds.check_invariants().unwrap();
    }

    /// Every reachable state of two slots and three MMs under admit, alias
    /// (at most one per MM and slot), unalias and retire, in every order:
    /// the ledger keeps H1 to H3, and a slot is released by exactly the
    /// retirement that drops its last hold, whatever kind of hold it was.
    /// The reference is a plain set of holds.
    #[test]
    fn every_edit_order_releases_each_slot_exactly_when_its_last_hold_drops() {
        #[derive(Clone, Copy, Debug)]
        enum Edit {
            Admit(u32, u64),
            Alias(u32, u64),
            Unalias(u32, u64),
            Retire(u64),
        }
        let mut edits = Vec::new();
        for slot in [1, 2] {
            for m in 1..=3 {
                edits.push(Edit::Admit(slot, m));
                edits.push(Edit::Alias(slot, m));
                edits.push(Edit::Unalias(slot, m));
            }
        }
        for m in 1..=3 {
            edits.push(Edit::Retire(m));
        }
        // Reference model: per slot, (admitted MMs, alias counts, debt MMs).
        type Model = BTreeMap<u32, (BTreeSet<u64>, BTreeMap<u64, usize>, BTreeSet<u64>)>;
        fn held(model: &Model, slot: u32) -> bool {
            let (a, b, c) = &model[&slot];
            !a.is_empty() || !b.is_empty() || !c.is_empty()
        }
        let mut stack: Vec<(SlotHolds<u32, Ctx>, Model, BTreeSet<u64>)> = Vec::new();
        let mut seen: BTreeSet<(Model, BTreeSet<u64>)> = BTreeSet::new();
        let mut start = SlotHolds::new();
        let mut model = Model::new();
        for slot in [1, 2] {
            start.register(slot).unwrap();
            model.insert(slot, Default::default());
        }
        stack.push((start, model, BTreeSet::new()));
        let mut visited = 0usize;
        while let Some((holds, model, retired)) = stack.pop() {
            if !seen.insert((model.clone(), retired.clone())) {
                continue;
            }
            visited += 1;
            holds.check_invariants().unwrap();
            for edit in &edits {
                let mut holds = holds.clone();
                let mut model = model.clone();
                let mut retired = retired.clone();
                match *edit {
                    Edit::Admit(slot, m) | Edit::Alias(slot, m) | Edit::Unalias(slot, m)
                        if retired.contains(&m) =>
                    {
                        let _ = slot;
                        continue;
                    }
                    Edit::Admit(slot, m) => {
                        holds.admit(slot, mm(m)).unwrap();
                        model.get_mut(&slot).unwrap().0.insert(m);
                    }
                    Edit::Alias(slot, m) if model[&slot].1.contains_key(&m) => continue,
                    Edit::Alias(slot, m) => {
                        holds.alias(slot, mm(m)).unwrap();
                        *model.get_mut(&slot).unwrap().1.entry(m).or_default() += 1;
                    }
                    Edit::Unalias(slot, m) => {
                        let entry = model.get_mut(&slot).unwrap();
                        let Some(count) = entry.1.get_mut(&m) else {
                            assert_eq!(
                                holds.unalias(slot, mm(m), Ctx(mm(m), 0)),
                                Err(HoldError::AliasUnderflow)
                            );
                            continue;
                        };
                        *count -= 1;
                        if *count == 0 {
                            entry.1.remove(&m);
                        }
                        entry.2.insert(m);
                        holds.unalias(slot, mm(m), Ctx(mm(m), 0)).unwrap();
                    }
                    Edit::Retire(m) => {
                        if !retired.insert(m) {
                            continue;
                        }
                        let before: BTreeSet<u32> =
                            [1, 2].into_iter().filter(|s| held(&model, *s)).collect();
                        for (a, b, c) in model.values_mut() {
                            a.remove(&m);
                            b.remove(&m);
                            c.remove(&m);
                        }
                        let expected: Vec<u32> =
                            before.into_iter().filter(|s| !held(&model, *s)).collect();
                        let plan = holds.retirement(mm(m));
                        assert_eq!(holds.retire(mm(m)), plan, "the plan is what commits");
                        assert_eq!(plan.released, expected, "{edit:?}");
                    }
                }
                stack.push((holds, model, retired));
            }
        }
        assert!(visited > 1_000, "explored {visited} states");
    }
}
