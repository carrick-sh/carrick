//! Venue-neutral refusal counts for the KVM witnesses.
//!
//! A refused call lands in `refused` (ring routing) or `venue_refused`
//! (carrier venue), at root or child scope, depending on which venue owns
//! the call today. A venue change must not break a witness whose claim is
//! "this call is a counted refusal", so witnesses assert the TOTAL. Assert a
//! single bucket (`refused`, `venue_refused`, ...) explicitly only where the
//! bucket itself is the claim.

use carrick_el1_abi::Counters;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefusalCount {
    pub refused: u64,
    pub refused_child: u64,
    pub venue_refused: u64,
    pub venue_refused_child: u64,
}

impl RefusalCount {
    /// The four buckets for one native ordinal.
    pub fn of(counters: &Counters, nr: usize) -> Self {
        let load = |bucket: &[AtomicU64]| bucket[nr].load(Ordering::Acquire);
        Self {
            refused: load(&counters.refused),
            refused_child: load(&counters.refused_child),
            venue_refused: load(&counters.venue_refused),
            venue_refused_child: load(&counters.venue_refused_child),
        }
    }

    /// Refusals at any venue, any scope.
    pub fn total(&self) -> u64 {
        self.refused + self.venue_refused
    }

    /// Refusals at any venue issued for a descendant process.
    pub fn child_total(&self) -> u64 {
        self.refused_child + self.venue_refused_child
    }
}

/// Assert `nr` was refused `total` times in all, `child_total` of them for
/// descendants, whichever venue counted them.
#[track_caller]
pub fn assert_refused_total(
    counters: &Counters,
    nr: usize,
    total: u64,
    child_total: u64,
    why: &str,
) {
    let count = RefusalCount::of(counters, nr);
    assert_eq!(
        (count.total(), count.child_total()),
        (total, child_total),
        "(total, child total) refusals of native {nr}: {why}; buckets {count:?}"
    );
}

/// Every native ordinal with a nonzero total refusal count, ascending.
pub fn refusal_totals(counters: &Counters) -> Vec<(usize, u64)> {
    (0..counters.refused.len())
        .map(|nr| (nr, RefusalCount::of(counters, nr).total()))
        .filter(|&(_, total)| total != 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters_with(set: impl FnOnce(&Counters)) -> Counters {
        let counters = Counters::new();
        set(&counters);
        counters
    }

    #[test]
    fn total_ignores_which_bucket_holds_the_count() {
        let ring = counters_with(|c| {
            c.refused[267].store(1, Ordering::Release);
            c.refused_child[267].store(1, Ordering::Release);
        });
        let venue = counters_with(|c| {
            c.venue_refused[267].store(1, Ordering::Release);
            c.venue_refused_child[267].store(1, Ordering::Release);
        });
        assert_ne!(RefusalCount::of(&ring, 267), RefusalCount::of(&venue, 267));
        assert_refused_total(&ring, 267, 1, 1, "ring bucket");
        assert_refused_total(&venue, 267, 1, 1, "venue bucket");
        assert_eq!(refusal_totals(&ring), refusal_totals(&venue));
    }

    #[test]
    #[should_panic(expected = "refusals of native 267")]
    fn a_wrong_total_still_fails() {
        let counters = counters_with(|c| c.venue_refused[267].store(2, Ordering::Release));
        assert_refused_total(&counters, 267, 1, 0, "two refusals");
    }
}
