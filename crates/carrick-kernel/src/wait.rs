//! Pluggable block/wake primitive for arena waiters. The arena never sleeps
//! on its own: callers supply the host futex (macOS `os_sync_wait_on_address`
//! via carrick-host ulock, Linux futex, FreeBSD `_umtx_op`). `SpinYield` is
//! the portable fallback used by unit tests and non-hot diagnostics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// A waker woke us (or the backend cannot distinguish; treat as retry).
    Woken,
    /// The word no longer holds `expected`; retry the caller's CAS loop.
    ValueChanged,
    /// The bounded wait elapsed.
    TimedOut,
}

pub trait WaitWake {
    /// Block while `*word == expected`, bounded by `timeout` (`None` =
    /// unbounded for the backend, but arena callers always pass a bound -- a
    /// broken wake path must surface as a timeout diagnostic, not a hang).
    fn wait(&self, word: &AtomicU64, expected: u64, timeout: Option<Duration>) -> WaitOutcome;

    /// Wake up to `count` waiters; returns how many the backend reports woken
    /// (0 when unknown).
    fn wake(&self, word: &AtomicU64, count: u32) -> u32;
}

/// Portable spin/yield fallback. Correct, not fast; test-grade.
pub struct SpinYield;

impl WaitWake for SpinYield {
    fn wait(&self, word: &AtomicU64, expected: u64, timeout: Option<Duration>) -> WaitOutcome {
        let start = Instant::now();
        loop {
            if word.load(Ordering::Acquire) != expected {
                return WaitOutcome::ValueChanged;
            }
            if let Some(timeout) = timeout
                && start.elapsed() >= timeout
            {
                return WaitOutcome::TimedOut;
            }
            std::thread::yield_now();
        }
    }

    fn wake(&self, _word: &AtomicU64, _count: u32) -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[test]
    fn spin_yield_returns_value_changed_when_word_moves() {
        let word = AtomicU64::new(1);
        word.store(2, Ordering::Release);
        let out = SpinYield.wait(&word, 1, Some(Duration::from_millis(50)));
        assert_eq!(out, WaitOutcome::ValueChanged);
    }

    #[test]
    fn spin_yield_times_out_when_word_holds() {
        let word = AtomicU64::new(1);
        let out = SpinYield.wait(&word, 1, Some(Duration::from_millis(20)));
        assert_eq!(out, WaitOutcome::TimedOut);
    }
}
