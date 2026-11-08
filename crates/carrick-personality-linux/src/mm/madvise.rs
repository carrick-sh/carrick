//! Shared Linux `madvise` validation and effect planning.
//!
//! Policy is extracted from the host dispatcher, including its existing gaps:
//! FREE rejects shared mappings but accepts private files and locked ranges;
//! THP hints (including COLLAPSE) are accepted without changing backing.
//! Authority: <https://man7.org/linux/man-pages/man2/madvise.2.html>.
//! No coverage lookup or effect occurs before argument validation. All per-VMA
//! EINVAL checks precede effects; holes are reported only after covered effects.

use alloc::vec::Vec;
use carrick_guest_arch::{GuestLen, GuestVa};
use carrick_syscall_abi::*;

/// Advice classification, independent of the execution venue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Advice {
    Normal,
    Random,
    Sequential,
    WillNeed,
    DontNeed,
    Free,
    DontFork,
    DoFork,
    WipeOnFork,
    KeepOnFork,
    DontDump,
    DoDump,
    HugePage,
    NoHugePage,
    Collapse,
    Unsupported,
}

impl Advice {
    /// Decode the guest register once. All other values retain the host's
    /// EINVAL policy (REMOVE, COLD, PAGEOUT, MERGEABLE, POPULATE, etc.).
    pub const fn from_guest_arg(raw: u64) -> Self {
        match raw {
            LINUX_MADV_NORMAL => Self::Normal,
            LINUX_MADV_RANDOM => Self::Random,
            LINUX_MADV_SEQUENTIAL => Self::Sequential,
            LINUX_MADV_WILLNEED => Self::WillNeed,
            LINUX_MADV_DONTNEED => Self::DontNeed,
            LINUX_MADV_FREE => Self::Free,
            LINUX_MADV_DONTFORK => Self::DontFork,
            LINUX_MADV_DOFORK => Self::DoFork,
            LINUX_MADV_WIPEONFORK => Self::WipeOnFork,
            LINUX_MADV_KEEPONFORK => Self::KeepOnFork,
            LINUX_MADV_DONTDUMP => Self::DontDump,
            LINUX_MADV_DODUMP => Self::DoDump,
            LINUX_MADV_HUGEPAGE => Self::HugePage,
            LINUX_MADV_NOHUGEPAGE => Self::NoHugePage,
            LINUX_MADV_COLLAPSE => Self::Collapse,
            _ => Self::Unsupported,
        }
    }

    /// Dump/fork attributes require the host venue until root attribute edits
    /// exist. This classification does not route or serve any ring calls.
    pub const fn requires_host_attributes(self) -> bool {
        matches!(
            self,
            Self::DontFork
                | Self::DoFork
                | Self::WipeOnFork
                | Self::KeepOnFork
                | Self::DontDump
                | Self::DoDump
        )
    }
}

/// A half-open guest range; coverage segments are nonempty, ordered, disjoint
/// and clipped to the requested range by the coverage provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub start: GuestVa,
    pub end: GuestVa,
}
impl Range {
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }

    pub fn len(self) -> GuestLen {
        GuestLen::new(self.end.raw() - self.start.raw())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    PrivateAnonymous,
    Shared,
    PrivateFile,
    Special,
}

/// A venue's retained segment, including any data needed to apply its effect.
pub trait Segment {
    fn range(&self) -> Range;
    fn class(&self) -> Class;
    fn droppable(&self) -> bool;
}

/// Coverage observed under the caller's MM authority. Holes are implicit
/// between segments; lock state also includes locks overlapping those holes,
/// preserving the existing host locked-range-table check.
pub struct Snapshot<S> {
    pub covered: Vec<S>,
    pub fully_mapped: bool,
    pub any_droppable: bool,
    locked: bool,
}
impl<S: Segment> Snapshot<S> {
    pub fn new(range: Range, covered: Vec<S>, locked: bool) -> Self {
        let mut cursor = range.start;
        let mut fully_mapped = true;
        let mut any_droppable = false;
        for segment in &covered {
            let next = segment.range();
            fully_mapped &= next.start == cursor;
            cursor = next.end;
            any_droppable |= segment.droppable();
        }
        fully_mapped &= cursor == range.end;
        Self {
            covered,
            fully_mapped,
            any_droppable,
            locked,
        }
    }
}

pub trait Coverage {
    type Segment: Segment;

    /// Venue-specific guard, after rounding and before coverage (e.g. the
    /// host's EL0 clock stub EPERM). Native venues must supply their own rule.
    fn check_range(&self, range: Range) -> Result<(), LinuxErrno>;
    fn snapshot(&self, range: Range) -> Snapshot<Self::Segment>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    DiscardPrivateAnonymous,
    RestorePrivateFile,
    /// The caller applies the advice's dump/fork attributes. Host callers may
    /// batch the ordered segments into one metadata edit over `Plan::range`.
    UpdateAttributes(Advice),
}

pub struct Step<S> {
    pub segment: S,
    pub action: Action,
}

/// Successful admission. Apply steps in order, then return `result` (which can
/// be ENOMEM for a hole). Effect failures still take precedence over `result`.
pub struct Plan<S> {
    pub range: Range,
    pub advice: Advice,
    pub steps: Vec<Step<S>>,
    pub result: Result<(), LinuxErrno>,
}

pub fn plan<C: Coverage>(
    coverage: &C,
    address: GuestVa,
    length: GuestLen,
    advice: Advice,
    page_size: GuestLen,
) -> Result<Plan<C::Segment>, LinuxErrno> {
    let page_size = page_size.raw();
    if !address.raw().is_multiple_of(page_size) || advice == Advice::Unsupported {
        return Err(LINUX_EINVAL);
    }
    if length.raw() == 0 {
        return Ok(Plan {
            range: Range {
                start: address,
                end: address,
            },
            advice,
            steps: Vec::new(),
            result: Ok(()),
        });
    }
    // Retain the host handler's size_t admission before endpoint rounding.
    usize::try_from(length.raw()).map_err(|_| LINUX_ENOMEM)?;
    let raw_end = address
        .raw()
        .checked_add(length.raw())
        .ok_or(LINUX_ENOMEM)?;
    let end = raw_end
        .checked_add(page_size - 1)
        .map(|end| end & !(page_size - 1))
        .ok_or(LINUX_ENOMEM)?;
    let range = Range {
        start: address,
        end: GuestVa::new(end),
    };
    coverage.check_range(range)?;
    let snapshot = coverage.snapshot(range);
    if snapshot.covered.is_empty() {
        return Err(LINUX_ENOMEM);
    }
    // Validate every covered VMA before exposing any executable plan.
    let rejected = (advice == Advice::DontNeed && snapshot.locked)
        || (advice == Advice::KeepOnFork && snapshot.any_droppable)
        || snapshot.covered.iter().any(|segment| match advice {
            Advice::DoFork => segment.class() == Class::Special,
            Advice::WipeOnFork => segment.class() != Class::PrivateAnonymous,
            Advice::Free => segment.class() == Class::Shared,
            _ => false,
        });
    if rejected {
        return Err(LINUX_EINVAL);
    }
    let result = if snapshot.fully_mapped {
        Ok(())
    } else {
        Err(LINUX_ENOMEM)
    };
    let steps = snapshot
        .covered
        .into_iter()
        .map(|segment| {
            let action = if advice.requires_host_attributes() {
                Action::UpdateAttributes(advice)
            } else if advice == Advice::DontNeed {
                match segment.class() {
                    Class::PrivateAnonymous => Action::DiscardPrivateAnonymous,
                    Class::PrivateFile => Action::RestorePrivateFile,
                    Class::Shared | Class::Special => Action::None,
                }
            } else {
                Action::None
            };
            Step { segment, action }
        })
        .collect();
    Ok(Plan {
        range,
        advice,
        steps,
        result,
    })
}

#[cfg(test)]
mod tests;
