//! Where a host-dispatched `mprotect` answered `ENOMEM`.
//!
//! Linux never answers `ENOMEM` for protection edits of a mapped range, so
//! every `ENOMEM` the host `mprotect` path produces is a defect or a real
//! hole. Each return site records itself here as a typed
//! [`MprotectEnomemSite`], with the first detail string that site saw (the
//! backend error for a failed protection publish). Witnesses print
//! [`report`], so one signed run names the source instead of a bare errno.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// One `ENOMEM` return site of the host `mprotect` path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum MprotectEnomemSite {
    /// The page-rounded length overflowed.
    LengthOverflow,
    /// The length does not fit `usize`.
    LengthConversion,
    /// The guest-memory protection registry says the range is unmapped.
    RegistryUnmapped,
    /// No complete backend metadata, no committed VMA covers the range and
    /// the backing probe failed.
    BackendProbeUnmapped,
    /// A lazy alias reservation was expected but not committed.
    LazyAliasNotCommitted,
    /// The lazy alias reservation could not be described.
    LazyAliasNoReservation,
    /// The lazy alias backing publication failed.
    LazyAliasPublish,
    /// `protect_range` failed inside the mmap arena (the engine error is the
    /// recorded detail).
    ArenaProtectRange,
    /// Re-arming first-touch residency after the edit failed.
    ArenaFirstTouchRearm,
    /// `protect_range` failed on the identity image (native 16k).
    IdentityProtectRange,
    /// `protect_range` failed on an alias-backed or concurrently protected
    /// range.
    AliasBackingProtectRange,
    /// Re-applying a SIGBUS hole after the edit failed.
    BusFaultReapply,
    /// `ENOMEM` left the `mprotect` dispatch without any site above
    /// recording it (an error converted below the handler).
    Unattributed,
}

const SITES: [MprotectEnomemSite; 13] = [
    MprotectEnomemSite::LengthOverflow,
    MprotectEnomemSite::LengthConversion,
    MprotectEnomemSite::RegistryUnmapped,
    MprotectEnomemSite::BackendProbeUnmapped,
    MprotectEnomemSite::LazyAliasNotCommitted,
    MprotectEnomemSite::LazyAliasNoReservation,
    MprotectEnomemSite::LazyAliasPublish,
    MprotectEnomemSite::ArenaProtectRange,
    MprotectEnomemSite::ArenaFirstTouchRearm,
    MprotectEnomemSite::IdentityProtectRange,
    MprotectEnomemSite::AliasBackingProtectRange,
    MprotectEnomemSite::BusFaultReapply,
    MprotectEnomemSite::Unattributed,
];

static COUNTS: [AtomicU64; SITES.len()] = [const { AtomicU64::new(0) }; SITES.len()];
static FIRST_DETAIL: Mutex<[Option<String>; SITES.len()]> =
    Mutex::new([const { None }; SITES.len()]);

/// Record an `ENOMEM` returned at `site`; `detail` is kept for the first
/// occurrence only.
pub fn record(site: MprotectEnomemSite, detail: impl FnOnce() -> Option<String>) {
    let previous = COUNTS[site as usize].fetch_add(1, Ordering::Relaxed);
    if previous == 0
        && let Some(detail) = detail()
        && let Ok(mut details) = FIRST_DETAIL.lock()
    {
        details[site as usize] = Some(detail);
    }
}

/// Total `ENOMEM` records so far, to tell whether a call recorded one.
pub fn total() -> u64 {
    COUNTS
        .iter()
        .map(|count| count.load(Ordering::Relaxed))
        .sum()
}

/// The counts per site (nonzero only) with each site's first detail.
pub fn report() -> Vec<(MprotectEnomemSite, u64, Option<String>)> {
    let details = FIRST_DETAIL.lock().map(|d| d.clone()).unwrap_or_default();
    SITES
        .iter()
        .enumerate()
        .filter_map(|(index, site)| {
            let count = COUNTS[index].load(Ordering::Relaxed);
            (count != 0).then(|| (*site, count, details.get(index).cloned().flatten()))
        })
        .collect()
}

/// [`report`] as one line, `none` when no site fired.
pub fn report_line() -> String {
    let rows = report();
    if rows.is_empty() {
        return "none".to_owned();
    }
    rows.iter()
        .map(|(site, count, detail)| match detail {
            Some(detail) => format!("{site:?}={count} first={detail:?}"),
            None => format!("{site:?}={count}"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Zero every counter (a witness resets before its run).
pub fn reset() {
    for count in &COUNTS {
        count.store(0, Ordering::Relaxed);
    }
    if let Ok(mut details) = FIRST_DETAIL.lock() {
        *details = [const { None }; SITES.len()];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_counts_and_keeps_its_first_detail() {
        reset();
        assert_eq!(report_line(), "none");
        record(MprotectEnomemSite::ArenaProtectRange, || {
            Some("first".to_owned())
        });
        record(MprotectEnomemSite::ArenaProtectRange, || {
            Some("second".to_owned())
        });
        record(MprotectEnomemSite::RegistryUnmapped, || None);
        assert_eq!(
            report(),
            vec![
                (MprotectEnomemSite::RegistryUnmapped, 1, None),
                (
                    MprotectEnomemSite::ArenaProtectRange,
                    2,
                    Some("first".to_owned())
                ),
            ]
        );
        reset();
    }
}
