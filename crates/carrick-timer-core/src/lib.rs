//! Platform-NEUTRAL interval/POSIX timer-slot bookkeeping + guest-CPU-due math,
//! shared by every backend. Delivery (kqueue EVFILT_TIMER vs the wall-clock
//! fallback thread) is the backend's concern; this crate owns the slot state,
//! `cpu_timer_decision`, and the shared fallback-thread timing loop body
//! (`run_fallback`). The thread spawn and the actual fire action (publish a
//! signal + kick) stay per-backend.
//!
//! The two timer families live in submodules ([`itimer`] for `setitimer`'s
//! REAL/VIRTUAL/PROF interval timers, [`posix`] for the `timer_create` family)
//! because both expose an `arm`/`clear`; a backend re-exports each into its own
//! `itimer` / `posix_timer` wrapper module via `pub use ...::itimer::*` /
//! `pub use ...::posix::*`.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod itimer;
pub mod posix;

use core::time::Duration;

/// Source of guest CPU time and active vCPU concurrency for CPU-time timers.
pub trait CpuSampler {
    /// Aggregate guest CPU nanoseconds.
    fn total_cpu_ns(&self) -> u64;
    /// Number of active vCPUs running guest code.
    fn active_vcpus(&self) -> u64 {
        1
    }
}

// ─── Time-domain newtypes (value/interval adjacency + wall-vs-CPU axis) ─────
//
// Two swap surfaces motivate these (docs/typed-interfaces-audit.md P1.6):
// (1) `value_ns`/`interval_ns` rode as ADJACENT bare `u64`s through ~6 public
// signatures across timer-core, `carrick-hal`'s `TimerDelivery`, and every VMM
// backend — a transposition compiles clean; the named-field struct is the swap
// guard. (2) a guest-CPU-time quantity (`ITIMER_VIRTUAL`/`PROF` budgets,
// `cpu_due_ns` remainders) and a wall-clock quantity (sleep delays, `EVFILT_TIMER`
// data) shared one integer type, even though sleeping a CPU quantity is exactly
// the fires-while-idle bug the CPU poll loops exist to prevent.

/// A WALL-CLOCK nanosecond quantity: a delay/deadline that elapses with real
/// time (`ITIMER_REAL` values, `thread::sleep` durations, kqueue `EVFILT_TIMER`
/// data). Distinct from [`CpuNs`] so a CPU-time remainder can never be slept
/// directly; the one sanctioned CPU→wall crossing is
/// [`itimer::cpu_timer_recheck_delay_ns`]. Raw escapes via [`WallNs::raw`] at
/// the `Duration::from_nanos` / kevent-data boundary only.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WallNs(pub u64);

impl WallNs {
    /// The raw nanosecond count (`Duration::from_nanos` / kevent-data boundary).
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A GUEST-CPU-TIME nanosecond quantity: a budget/remainder measured against
/// the aggregate guest CPU total (`ITIMER_VIRTUAL`/`ITIMER_PROF`,
/// `CLOCK_PROCESS_CPUTIME_ID`, `cpu_due_ns` deltas). NEVER sleep this value —
/// it only advances while the guest burns CPU. Convert to a wall-clock recheck
/// delay through [`itimer::cpu_timer_recheck_delay_ns`], the one sanctioned
/// crossing to [`WallNs`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CpuNs(pub u64);

impl CpuNs {
    /// The raw nanosecond count (atomic-slot / guest-CPU-total boundary).
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A `setitimer`/`timer_settime`-shaped `(value, interval)` nanosecond pair.
/// The NAMED fields are the swap guard; the fields themselves stay raw `u64`
/// wire values (`value == 0` disarms, `interval == 0` is one-shot). Whether the
/// pair measures wall or CPU time is the TIMER's property (its `which`/clock),
/// not the pair's, so the fields are deliberately not [`WallNs`]/[`CpuNs`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TimerSpecNs {
    /// First expiry in nanoseconds. 0 disarms.
    pub value: u64,
    /// Repeat period in nanoseconds. 0 = one-shot.
    pub interval: u64,
}

impl TimerSpecNs {
    /// The disarm spec (`it_value == 0`), named so a disarm site reads as one.
    pub const DISARM: Self = Self {
        value: 0,
        interval: 0,
    };

    /// Saturate a `Duration` pair into the ns pair — THE single home of the
    /// `u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)` saturation that was
    /// previously copied at every arm site.
    pub fn from_durations(value: Duration, interval: Duration) -> Self {
        let ns = |d: Duration| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX);
        Self {
            value: ns(value),
            interval: ns(interval),
        }
    }
}

/// The clock domain a timer measures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub enum ClockKind {
    /// Wall-clock time (elapses with real time).
    #[default]
    Wall,
    /// Aggregate guest process CPU time.
    ProcessCpu,
    /// Aggregate guest thread CPU time.
    ThreadCpu,
}

impl ClockKind {
    /// Whether this clock measures guest CPU time rather than wall-clock time.
    #[inline]
    pub const fn is_cpu(self) -> bool {
        matches!(self, Self::ProcessCpu | Self::ThreadCpu)
    }

    /// Whether this clock measures per-thread guest CPU time.
    #[inline]
    pub const fn is_thread_cpu(self) -> bool {
        matches!(self, Self::ThreadCpu)
    }

    /// Whether this clock measures per-process guest CPU time.
    #[inline]
    pub const fn is_process_cpu(self) -> bool {
        matches!(self, Self::ProcessCpu)
    }
}
