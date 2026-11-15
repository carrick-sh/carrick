//! The one owner of a carrier's native exec preparations (#2305).

/// What a carrier's exec owner did, for run reports and witnesses: every
/// receipt it reserved is accounted for by one retirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecOwnerCensus {
    /// Receipts reserved at claim.
    pub reserved: u64,
    /// Rows parked on the fork stock's release.
    pub parked: u64,
    /// Parked rows handed back to rerun after their release.
    pub reruns: u64,
    /// Rows whose manifest was sealed with the receipt reserved at claim.
    pub sealed: u64,
    /// Sealed rows the ring adopted.
    pub adopted: u64,
    /// Sealed rows the ring cancelled.
    pub cancelled: u64,
    /// Rows refused before the seal (a loader errno, a stock ENOMEM).
    pub refused: u64,
    /// Parked rows the ring cancelled before they reran.
    pub park_cancelled: u64,
    /// Sealed rows whose publication the ring had already cancelled.
    pub publish_cancelled: u64,
    /// Adopted execs settled on the lane that serves their origin.
    pub settled: u64,
    /// Settlements handed back, unchanged, from a lane that cannot serve them.
    pub handed_back: u64,
    /// Signal-reset obligations discharged from the ring's commit effects.
    pub signal_resets_discharged: u64,
    /// Settlements refused for an incomplete commit-effects word.
    pub short_effects: u64,
}

impl ExecOwnerCensus {
    /// Rows retired for any reason.
    pub const fn retired(&self) -> u64 {
        self.adopted + self.cancelled + self.refused + self.park_cancelled + self.publish_cancelled
    }
}
