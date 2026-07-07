//! Robust bucket lock: a single fork-shared `AtomicU64` whose holder is
//! (host pid, generation)-stamped, so a holder that dies mid-critical-section
//! is detectable and breakable by the supervisor sweep.
//!
//! Packing (same discipline as the vCPU permit slot, trap.rs:962):
//!   bits 63..62  state       (0 = free, 1 = held)
//!   bits 61..32  generation  (30 bits)
//!   bits 31..0   owner pid   (32 bits)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::domains::{HostPid, ProcessGeneration};
use crate::wait::{WaitOutcome, WaitWake};

const STATE_SHIFT: u32 = 62;
const STATE_HELD: u64 = 1 << STATE_SHIFT;
const GEN_SHIFT: u32 = 32;
const GEN_BITS: u32 = 30;
const GEN_MASK_VALUE: u64 = (1 << GEN_BITS) - 1;
const PID_MASK: u64 = 0xFFFF_FFFF;
const FREE: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOwner {
    pub pid: HostPid,
    pub generation: ProcessGeneration,
}

#[derive(Debug)]
pub enum LockError {
    Timeout { holder: Option<LockOwner> },
}

fn pack(owner: LockOwner) -> u64 {
    STATE_HELD
        | ((u64::from(owner.generation.raw()) & GEN_MASK_VALUE) << GEN_SHIFT)
        | u64::from(owner.pid.raw())
}

fn unpack(word: u64) -> Option<LockOwner> {
    if word & STATE_HELD == 0 {
        return None;
    }
    Some(LockOwner {
        pid: HostPid::new((word & PID_MASK) as u32),
        generation: ProcessGeneration::new(((word >> GEN_SHIFT) & GEN_MASK_VALUE) as u32),
    })
}

#[repr(transparent)]
pub struct RobustLock {
    word: AtomicU64,
}

impl RobustLock {
    pub const fn new() -> Self {
        Self {
            word: AtomicU64::new(FREE),
        }
    }

    pub fn holder(&self) -> Option<LockOwner> {
        unpack(self.word.load(Ordering::Acquire))
    }

    pub fn lock<'a>(
        &'a self,
        me: LockOwner,
        ww: &dyn WaitWake,
        timeout: Duration,
    ) -> Result<RobustGuard<'a>, LockError> {
        let packed = pack(me);
        let start = Instant::now();
        loop {
            match self
                .word
                .compare_exchange(FREE, packed, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(RobustGuard { lock: self }),
                Err(observed) => {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Err(LockError::Timeout {
                            holder: unpack(observed),
                        });
                    }
                    match ww.wait(&self.word, observed, Some(remaining)) {
                        WaitOutcome::Woken | WaitOutcome::ValueChanged => continue,
                        WaitOutcome::TimedOut => {
                            return Err(LockError::Timeout {
                                holder: self.holder(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Supervisor sweep: free the lock iff still held by exactly `dead`
    /// (pid AND generation). The caller must have confirmed the owner process
    /// is gone.
    pub fn force_break(&self, dead: LockOwner) -> bool {
        self.word
            .compare_exchange(pack(dead), FREE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn unlock(&self) {
        self.word.store(FREE, Ordering::Release);
    }
}

impl Default for RobustLock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RobustGuard<'a> {
    lock: &'a RobustLock,
}

impl Drop for RobustGuard<'_> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// Two-bucket critical section (futex requeue, SysV multi-sem): callers order
/// buckets by ascending BucketKey; this additionally orders by address so a
/// mis-ordered call cannot deadlock against a correctly-ordered one.
pub fn lock_pair<'a>(
    a: &'a RobustLock,
    b: &'a RobustLock,
    me: LockOwner,
    ww: &dyn WaitWake,
    timeout: Duration,
) -> Result<(RobustGuard<'a>, RobustGuard<'a>), LockError> {
    let (first, second) = if (a as *const RobustLock) <= (b as *const RobustLock) {
        (a, b)
    } else {
        (b, a)
    };
    let g1 = first.lock(me, ww, timeout)?;
    let g2 = second.lock(me, ww, timeout)?;
    Ok((g1, g2))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::domains::{HostPid, ProcessGeneration};
    use crate::wait::SpinYield;
    use std::time::Duration;

    fn me(pid: u32, generation: u32) -> LockOwner {
        LockOwner {
            pid: HostPid::new(pid),
            generation: ProcessGeneration::new(generation),
        }
    }

    #[test]
    fn lock_unlock_round_trip() {
        let l = RobustLock::new();
        assert!(l.holder().is_none());
        let g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .map_err(|e| format!("{e:?}"))
            .unwrap_or_else(|e| panic!("lock failed: {e}"));
        assert_eq!(l.holder(), Some(me(10, 1)));
        drop(g);
        assert!(l.holder().is_none());
    }

    #[test]
    fn contended_lock_times_out_and_names_holder() {
        let l = RobustLock::new();
        let _g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("first lock"));
        let e = l
            .lock(me(11, 2), &SpinYield, Duration::from_millis(20))
            .err()
            .unwrap_or_else(|| panic!("second lock must time out"));
        let LockError::Timeout { holder } = e;
        assert_eq!(holder, Some(me(10, 1)));
    }

    #[test]
    fn force_break_frees_only_the_named_dead_owner() {
        let l = RobustLock::new();
        let g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("lock"));
        std::mem::forget(g);
        assert!(!l.force_break(me(10, 2)));
        assert!(l.force_break(me(10, 1)));
        assert!(l.holder().is_none());
        let _g2 = l
            .lock(me(12, 3), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("relock"));
    }

    #[test]
    fn lock_pair_orders_by_address_and_survives_reversed_call() {
        let a = RobustLock::new();
        let b = RobustLock::new();
        let (g1, g2) = lock_pair(&a, &b, me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("pair ab"));
        drop((g1, g2));
        let (g1, g2) = lock_pair(&b, &a, me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("pair ba"));
        drop((g1, g2));
    }
}
