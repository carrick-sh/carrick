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
use carrick_syscall_abi::{
    LINUX_EINVAL, LINUX_ENOMEM, LINUX_MADV_COLLAPSE, LINUX_MADV_DODUMP, LINUX_MADV_DOFORK,
    LINUX_MADV_DONTDUMP, LINUX_MADV_DONTFORK, LINUX_MADV_DONTNEED, LINUX_MADV_FREE,
    LINUX_MADV_HUGEPAGE, LINUX_MADV_KEEPONFORK, LINUX_MADV_NOHUGEPAGE, LINUX_MADV_NORMAL,
    LINUX_MADV_RANDOM, LINUX_MADV_SEQUENTIAL, LINUX_MADV_WILLNEED, LINUX_MADV_WIPEONFORK,
    LinuxErrno,
};

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

    /// Dump and fork attributes live on the mapping owner.
    pub const fn reservation_attribute(
        self,
    ) -> Option<(carrick_core_abi::ReservationNodeFlags, bool)> {
        use carrick_core_abi::ReservationNodeFlags as Flags;
        match self {
            Self::DontFork => Some((Flags::DONTFORK, true)),
            Self::DoFork => Some((Flags::DONTFORK, false)),
            Self::WipeOnFork => Some((Flags::WIPEONFORK, true)),
            Self::KeepOnFork => Some((Flags::WIPEONFORK, false)),
            Self::DontDump => Some((Flags::DONTDUMP, true)),
            Self::DoDump => Some((Flags::DONTDUMP, false)),
            _ => None,
        }
    }

    fn action(self, class: Class) -> Action {
        if self.reservation_attribute().is_some() {
            Action::UpdateAttributes(self)
        } else if self == Self::DontNeed {
            match class {
                Class::PrivateAnonymous => Action::DiscardPrivateAnonymous,
                Class::PrivateFile => Action::RestorePrivateFile,
                Class::Shared | Class::Special => Action::None,
            }
        } else {
            Action::None
        }
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
    pub fn from_args(
        address: GuestVa,
        length: GuestLen,
        advice: Advice,
        page_size: GuestLen,
    ) -> Result<Self, LinuxErrno> {
        let page_size = page_size.raw();
        if !address.raw().is_multiple_of(page_size) || advice == Advice::Unsupported {
            return Err(LINUX_EINVAL);
        }
        // Retain the host handler's size_t admission before endpoint rounding.
        usize::try_from(length.raw()).map_err(|_| LINUX_ENOMEM)?;
        let end = address
            .raw()
            .checked_add(length.raw())
            .and_then(|end| end.checked_next_multiple_of(page_size))
            .ok_or(LINUX_ENOMEM)?;
        Ok(Self {
            start: address,
            end: GuestVa::new(end),
        })
    }

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

impl Class {
    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// A venue's retained segment, including any data needed to apply its effect.
pub trait Segment {
    fn range(&self) -> Range;
    fn class(&self) -> Class;
    fn droppable(&self) -> bool;
}

/// Shared streaming admission over ordered, clipped VMA segments. A ring
/// caller walks its tree without allocating while it holds the MM root.
pub struct Assessment {
    cursor: GuestVa,
    end: GuestVa,
    contiguous: bool,
    any_segment: bool,
    any_droppable: bool,
    classes: u8,
}
impl Assessment {
    pub fn new(range: Range) -> Self {
        Self {
            cursor: range.start,
            end: range.end,
            contiguous: true,
            any_segment: false,
            any_droppable: false,
            classes: 0,
        }
    }

    pub fn observe(&mut self, range: Range, class: Class, droppable: bool) {
        self.contiguous &= range.start == self.cursor;
        self.cursor = range.end;
        self.any_segment = true;
        self.any_droppable |= droppable;
        self.classes |= class.bit();
    }

    pub fn fully_mapped(&self) -> bool {
        self.contiguous && self.cursor == self.end
    }

    /// Pre-effect errors are distinct from the hole verdict returned after
    /// successful effects on covered mappings.
    pub fn verdict(
        &self,
        advice: Advice,
        locked: bool,
    ) -> Result<Result<(), LinuxErrno>, LinuxErrno> {
        if !self.any_segment {
            return Err(LINUX_ENOMEM);
        }
        let rejected = match advice {
            Advice::DontNeed => locked,
            Advice::KeepOnFork => self.any_droppable,
            Advice::DoFork => self.classes & Class::Special.bit() != 0,
            Advice::WipeOnFork => self.classes & !Class::PrivateAnonymous.bit() != 0,
            Advice::Free => self.classes & Class::Shared.bit() != 0,
            _ => false,
        };
        if rejected {
            return Err(LINUX_EINVAL);
        }
        Ok(if self.fully_mapped() {
            Ok(())
        } else {
            Err(LINUX_ENOMEM)
        })
    }
}

/// Coverage observed under the caller's MM authority. Lock state also
/// includes locks overlapping holes, preserving the host lock-table check.
pub struct Snapshot<S> {
    pub covered: Vec<S>,
    pub fully_mapped: bool,
    pub any_droppable: bool,
    assessment: Assessment,
    locked: bool,
}
impl<S: Segment> Snapshot<S> {
    pub fn new(range: Range, covered: Vec<S>, locked: bool) -> Self {
        let mut assessment = Assessment::new(range);
        for segment in &covered {
            assessment.observe(segment.range(), segment.class(), segment.droppable());
        }
        Self {
            covered,
            fully_mapped: assessment.fully_mapped(),
            any_droppable: assessment.any_droppable,
            assessment,
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
    let range = Range::from_args(address, length, advice, page_size)?;
    if range.is_empty() {
        return Ok(Plan {
            range,
            advice,
            steps: Vec::new(),
            result: Ok(()),
        });
    }
    coverage.check_range(range)?;
    let snapshot = coverage.snapshot(range);
    let result = snapshot.assessment.verdict(advice, snapshot.locked)?;
    let steps = snapshot
        .covered
        .into_iter()
        .map(|segment| Step {
            action: advice.action(segment.class()),
            segment,
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
