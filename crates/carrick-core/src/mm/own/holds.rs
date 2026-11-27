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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldRetirement<S> {
    /// Every slot the MM holds anything in.
    pub held: Vec<S>,
    /// The slots whose last hold is the MM's: nothing holds them once it
    /// retires. The caller revokes exactly these.
    pub released: Vec<S>,
    /// How many aliases the MM held in each slot (nonzero counts only), so
    /// a backend checks its own alias records slot by slot: an extra alias
    /// on one slot never cancels a missing one on another.
    pub aliases: BTreeMap<S, usize>,
}

impl<S> HoldRetirement<S> {
    /// The MM's aliases over every slot.
    pub fn alias_total(&self) -> usize {
        self.aliases.values().sum()
    }
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
            aliases: BTreeMap::new(),
        };
        for &slot in self.by_mm.get(&mm).into_iter().flatten() {
            let Some(holds) = self.slots.get(&slot) else {
                continue;
            };
            plan.held.push(slot);
            if let Some(&count) = holds.aliases.get(&mm) {
                plan.aliases.insert(slot, count);
            }
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

    /// The ledger's holds in the reference model's shape: per slot, the
    /// admitted MMs, the alias count per MM, and the (MM, context) debts.
    type Model = BTreeMap<u32, (BTreeSet<u64>, BTreeMap<u64, usize>, BTreeSet<(u64, u8)>)>;
    fn project(holds: &SlotHolds<u32, Ctx>) -> Model {
        holds
            .slots
            .iter()
            .map(|(&slot, h)| {
                (
                    slot,
                    (
                        h.admitted.iter().map(|m| m.raw().get()).collect(),
                        h.aliases.iter().map(|(m, c)| (m.raw().get(), *c)).collect(),
                        h.drains.iter().map(|d| (d.0.raw().get(), d.1)).collect(),
                    ),
                )
            })
            .collect()
    }
    fn held(model: &Model, slot: u32) -> bool {
        model
            .get(&slot)
            .is_some_and(|(a, b, c)| !a.is_empty() || !b.is_empty() || !c.is_empty())
    }

    /// Explore every reachable state of `slots` and MMs `1..=mms` under
    /// admit, alias (up to `max_alias` per MM and slot), unalias (into any
    /// of `contexts` contexts per MM), retire and forget, in every order.
    /// Each reached ledger state must equal the reference model reached by
    /// the same edits (checked before deduplication, so no ledger state
    /// hides behind an equal model reached another way); the ledger keeps
    /// H1 to H3; and each retirement's plan names exactly the slots whose
    /// last hold it drops and the MM's exact alias count per slot.
    fn explore(slots: &[u32], mms: u64, max_alias: usize, contexts: u8, forget: bool) -> usize {
        #[derive(Clone, Copy, Debug)]
        enum Edit {
            Admit(u32, u64),
            Alias(u32, u64),
            Unalias(u32, u64, u8),
            Retire(u64),
            Forget(u32),
        }
        let mut edits = Vec::new();
        for &slot in slots {
            for m in 1..=mms {
                edits.push(Edit::Admit(slot, m));
                edits.push(Edit::Alias(slot, m));
                for c in 0..contexts {
                    edits.push(Edit::Unalias(slot, m, c));
                }
            }
            if forget {
                edits.push(Edit::Forget(slot));
            }
        }
        for m in 1..=mms {
            edits.push(Edit::Retire(m));
        }
        let mut start = SlotHolds::new();
        let mut model = Model::new();
        for &slot in slots {
            start.register(slot).unwrap();
            model.insert(slot, Default::default());
        }
        let mut stack: Vec<(SlotHolds<u32, Ctx>, Model, BTreeSet<u64>)> =
            alloc::vec![(start, model, BTreeSet::new())];
        let mut seen: BTreeSet<(Model, BTreeSet<u64>)> = BTreeSet::new();
        seen.insert((stack[0].1.clone(), BTreeSet::new()));
        while let Some((holds, model, retired)) = stack.pop() {
            for edit in &edits {
                let mut holds = holds.clone();
                let mut model = model.clone();
                let mut retired = retired.clone();
                match *edit {
                    Edit::Admit(_, m) | Edit::Alias(_, m) | Edit::Unalias(_, m, _)
                        if retired.contains(&m) =>
                    {
                        continue;
                    }
                    Edit::Admit(slot, m) | Edit::Alias(slot, m) | Edit::Unalias(slot, m, _)
                        if !model.contains_key(&slot) =>
                    {
                        let result = match *edit {
                            Edit::Admit(..) => holds.admit(slot, mm(m)),
                            Edit::Alias(..) => holds.alias(slot, mm(m)),
                            _ => holds.unalias(slot, mm(m), Ctx(mm(m), 0)),
                        };
                        assert_eq!(result, Err(HoldError::UnknownSlot));
                        assert_eq!(project(&holds), model, "{edit:?}: a refusal moved");
                        holds.check_invariants().unwrap();
                        continue;
                    }
                    Edit::Admit(slot, m) => {
                        holds.admit(slot, mm(m)).unwrap();
                        model.get_mut(&slot).unwrap().0.insert(m);
                    }
                    Edit::Alias(slot, m)
                        if model[&slot].1.get(&m).copied().unwrap_or(0) >= max_alias =>
                    {
                        continue;
                    }
                    Edit::Alias(slot, m) => {
                        holds.alias(slot, mm(m)).unwrap();
                        *model.get_mut(&slot).unwrap().1.entry(m).or_default() += 1;
                    }
                    Edit::Unalias(slot, m, c) => {
                        let entry = model.get_mut(&slot).unwrap();
                        let Some(count) = entry.1.get_mut(&m) else {
                            assert_eq!(
                                holds.unalias(slot, mm(m), Ctx(mm(m), c)),
                                Err(HoldError::AliasUnderflow)
                            );
                            assert_eq!(project(&holds), model, "{edit:?}: a refusal moved");
                            holds.check_invariants().unwrap();
                            continue;
                        };
                        *count -= 1;
                        if *count == 0 {
                            entry.1.remove(&m);
                        }
                        entry.2.insert((m, c));
                        holds.unalias(slot, mm(m), Ctx(mm(m), c)).unwrap();
                    }
                    Edit::Forget(slot) => {
                        let Some(entry) = model.get(&slot) else {
                            assert_eq!(holds.forget(slot), Err(HoldError::UnknownSlot));
                            assert_eq!(project(&holds), model, "{edit:?}: a refusal moved");
                            holds.check_invariants().unwrap();
                            continue;
                        };
                        if !entry.1.is_empty() {
                            assert_eq!(holds.forget(slot), Err(HoldError::StillAliased));
                            assert_eq!(project(&holds), model, "{edit:?}: a refusal moved");
                            holds.check_invariants().unwrap();
                            continue;
                        }
                        // With no alias left the slot may leave (a revoke or
                        // a rollback) even while admissions or drain debts
                        // hold it: they go with it, and every MM index that
                        // named it must drop it (H1).
                        holds.forget(slot).unwrap();
                        model.remove(&slot);
                    }
                    Edit::Retire(m) => {
                        if !retired.insert(m) {
                            continue;
                        }
                        let before: BTreeSet<u32> =
                            model.keys().copied().filter(|s| held(&model, *s)).collect();
                        let aliases: BTreeMap<u32, usize> = model
                            .iter()
                            .filter_map(|(s, (_, b, _))| b.get(&m).map(|count| (*s, *count)))
                            .collect();
                        for (a, b, c) in model.values_mut() {
                            a.remove(&m);
                            b.remove(&m);
                            c.retain(|(owner, _)| *owner != m);
                        }
                        let expected: Vec<u32> =
                            before.into_iter().filter(|s| !held(&model, *s)).collect();
                        let plan = holds.retirement(mm(m));
                        assert_eq!(holds.retire(mm(m)), plan, "the plan is what commits");
                        assert_eq!(plan.released, expected, "{edit:?}");
                        assert_eq!(plan.aliases, aliases, "{edit:?}");
                    }
                }
                // Every reached ledger state is checked, before the model
                // state is deduplicated: no ledger state hides behind an
                // equal model reached by another edit order.
                assert_eq!(
                    project(&holds),
                    model,
                    "{edit:?}: the ledger left the model"
                );
                holds.check_invariants().unwrap();
                if seen.insert((model.clone(), retired.clone())) {
                    stack.push((holds, model, retired));
                }
            }
        }
        seen.len()
    }

    /// Two slots and two MMs (an owner and an inheritor) with up to two
    /// aliases each: every release shape across slots, including a forget,
    /// with the per-MM index spanning both slots. (Two slots and three MMs
    /// reach 274625 states, minutes in a debug build; the three-holder
    /// shapes are explored on one slot below, and the cross-unmap of two
    /// slots by two inheritors is the named case above.)
    #[test]
    fn every_edit_order_releases_each_slot_exactly_when_its_last_hold_drops() {
        let visited = explore(&[1, 2], 2, 2, 1, true);
        assert!(visited > 1_000, "explored {visited} states");
    }

    /// One slot and three MMs with up to two aliases each and two contexts:
    /// multiplicity, so a count or a second debt never masks a release and
    /// no third holder is missed.
    #[test]
    fn alias_and_drain_multiplicity_never_releases_a_slot_early() {
        let visited = explore(&[1], 3, 2, 2, true);
        assert!(visited > 1_000, "explored {visited} states");
    }
}
