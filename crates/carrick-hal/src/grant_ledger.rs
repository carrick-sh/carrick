//! The host's ledger of grants it published to the guest and has not yet
//! settled.
//!
//! A host backend publishes a physical grant (a frame grant, a copy-on-write
//! replacement) before the guest uses it, and settles or rolls it back only
//! after the guest's verified receipt. Between the two the host owes that
//! grant's physical state to an owner that outlives the crossing: the
//! address space the grant serves, never the CPU or lane that happened to
//! ask for it. Any member of the address space may use the grant and any
//! exclusion of it may settle the receipt.
//!
//! This is that owner's record, shared by every backend. A pending grant is
//! named to its settlement by its exact incarnation, and one span never
//! holds two pending grants.

/// One published grant awaiting the guest's receipt.
pub trait PendingGrant {
    /// The exact incarnation settlement names: equal only for the same
    /// publication, never for a successor over the same span.
    type Grant: PartialEq;

    /// The grant as its completion or rollback names it.
    fn grant(&self) -> &Self::Grant;

    /// `(base, len)` of the span this grant alone owns while it is pending,
    /// in the domain the backend publishes in.
    fn span(&self) -> (u64, u64);
}

/// The ledger of [`PendingGrant`]s of one owner. The producer inserts at
/// publication; completion or rollback removes the exact grant. A leaf lock
/// where it is shared: never held while taking another.
#[derive(Debug)]
pub struct PendingGrantLedger<E> {
    entries: Vec<E>,
}

impl<E> Default for PendingGrantLedger<E> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<E: PendingGrant> PendingGrantLedger<E> {
    /// Whether any pending grant overlaps `[base, base + len)`.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        let end = base.saturating_add(len);
        self.entries.iter().any(|entry| {
            let (start, size) = entry.span();
            start < end && base < start.saturating_add(size)
        })
    }

    /// Record a published grant. `false`: its span overlaps one already
    /// pending, and the entry is dropped (the caller declines before
    /// publishing, so the ledger never holds two owners for one span).
    #[must_use]
    pub fn insert(&mut self, entry: E) -> bool {
        let (base, len) = entry.span();
        if self.overlaps(base, len) {
            return false;
        }
        self.entries.push(entry);
        true
    }

    /// Remove and return the entry pending for exactly `grant`. A grant with
    /// the same span but another incarnation never matches.
    pub fn take(&mut self, grant: &E::Grant) -> Option<E> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.grant() == grant)?;
        Some(self.entries.swap_remove(index))
    }

    /// Remove and return every entry `retiring` selects: the grants of an
    /// owner that is going away, which no receipt will ever name.
    pub fn take_all(&mut self, mut retiring: impl FnMut(&E) -> bool) -> Vec<E> {
        let (taken, kept) = core::mem::take(&mut self.entries)
            .into_iter()
            .partition(|entry| retiring(entry));
        self.entries = kept;
        taken
    }

    /// How many grants are pending.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no grant is pending.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Keyed {
        key: (u64, u64),
        owner: u64,
    }
    impl PendingGrant for Keyed {
        type Grant = (u64, u64);
        fn grant(&self) -> &(u64, u64) {
            &self.key
        }
        fn span(&self) -> (u64, u64) {
            (self.key.0, 0x4000)
        }
    }
    fn keyed(base: u64, incarnation: u64, owner: u64) -> Keyed {
        Keyed {
            key: (base, incarnation),
            owner,
        }
    }

    /// A pending grant is named by its exact incarnation, taken once, and
    /// one span never holds two.
    #[test]
    fn a_pending_grant_is_taken_once_by_its_exact_incarnation() {
        let mut ledger = PendingGrantLedger::default();
        assert!(ledger.insert(keyed(0x10_0000, 3, 1)));
        assert!(ledger.overlaps(0x10_3000, 0x1000));
        assert!(!ledger.overlaps(0x10_4000, 0x1000));
        assert!(!ledger.overlaps(0x0f_c000, 0x4000));
        assert!(
            !ledger.insert(keyed(0x10_2000, 9, 1)),
            "an overlapping grant is refused"
        );
        assert_eq!(ledger.len(), 1);
        // Same span, another incarnation: not this grant.
        assert_eq!(ledger.take(&(0x10_0000, 4)), None);
        assert!(ledger.insert(keyed(0x20_0000, 3, 1)));
        assert_eq!(ledger.take(&(0x10_0000, 3)), Some(keyed(0x10_0000, 3, 1)));
        assert_eq!(ledger.take(&(0x10_0000, 3)), None, "taken exactly once");
        assert!(!ledger.overlaps(0x10_0000, 0x4000));
        assert!(ledger.take(&(0x20_0000, 3)).is_some());
        assert!(ledger.is_empty());
    }

    /// The grant belongs to its owner, not to whoever asked: a retiring
    /// owner takes all of its grants and leaves every other owner's.
    #[test]
    fn a_retiring_owner_takes_only_its_own_grants() {
        let mut ledger = PendingGrantLedger::default();
        assert!(ledger.insert(keyed(0x10_0000, 1, 7)));
        assert!(ledger.insert(keyed(0x20_0000, 1, 8)));
        assert!(ledger.insert(keyed(0x30_0000, 1, 7)));
        let mut taken = ledger.take_all(|entry| entry.owner == 7);
        taken.sort_by_key(|entry| entry.key);
        assert_eq!(taken, [keyed(0x10_0000, 1, 7), keyed(0x30_0000, 1, 7)]);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.take(&(0x20_0000, 1)).is_some());
        assert!(ledger.take_all(|_| true).is_empty());
    }
}
