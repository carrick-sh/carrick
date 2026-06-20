//! Pluggable M:N admission scheduler: bounds M guest (host) threads onto N vCPU
//! slot ids. Phase 1 is admission + recycle only (lifetime-bind); Phase 2 adds
//! reclaim-on-block. The default impl leans on a host Mutex+Condvar (generalizing
//! the HVF `vcpu_gate`) and the host thread scheduler for the M.
//!
//! See `docs/superpowers/specs/2026-06-20-mn-vcpu-scheduler-design.md`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

pub type SlotId = u32;

/// Why a thread is giving its slot back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Yield {
    /// The guest thread is blocking but still alive (Phase 2 reclaim source).
    Blocked,
    /// The guest thread exited; free the id permanently for reuse.
    Exited,
}

/// An opaque grant of one vCPU slot. The generation guards against a stale double
/// release recycling an id that was already handed to another thread.
#[derive(Clone, Copy, Debug)]
pub struct SlotLease {
    pub slot: SlotId,
    generation: u64,
}

impl SlotLease {
    /// Construct a lease from raw parts (test / fork-rebuild use only).
    pub fn from_parts(slot: SlotId, generation: u64) -> Self {
        Self { slot, generation }
    }

    /// The grant generation (opaque; used by the gen guard).
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Process-wide admission: pluggable so a deployment can swap the policy without
/// touching backends or the runtime.
pub trait VcpuScheduler: Send + Sync + 'static {
    /// Block (parking the host thread) until a slot id is granted.
    fn acquire(&self, tid: u64) -> SlotLease;
    /// Return a slot. `Exited` frees it for reuse; `Blocked` is treated as
    /// `Exited` in Phase 1 (no reclaim yet) but distinguished for Phase 2.
    fn release(&self, lease: SlotLease, why: Yield);
    /// N — the live vCPU budget.
    fn budget(&self) -> usize;
    /// Reset the pool on a fork CHILD: free every slot EXCEPT `keep` (the forking
    /// thread's, whose inherited lease must stay valid), since the child inherits
    /// the parent's scheduler state but none of the parent's other threads. Without
    /// this the child's new threads block forever on slots held by threads that do
    /// not exist in the child. A no-op where there is no pool.
    fn reset_for_fork(&self, keep: SlotId);
}

struct PoolState {
    /// Available ids (LIFO recycle).
    free: Vec<SlotId>,
    /// Per-id generation; bumped on each grant, zeroed when free.
    generations: Vec<u64>,
}

/// Default scheduler: an N-slot free-list behind a host Mutex+Condvar.
pub struct HostCondvarScheduler {
    budget: usize,
    state: Mutex<PoolState>,
    cv: Condvar,
    grant_gen: AtomicU64,
}

impl HostCondvarScheduler {
    pub fn new(budget: usize) -> Self {
        let n = budget.max(1);
        Self {
            budget: n,
            state: Mutex::new(PoolState {
                // rev() so pop() yields 0,1,2,... — stable, low ids first.
                free: (0..n as SlotId).rev().collect(),
                generations: vec![0; n],
            }),
            cv: Condvar::new(),
            grant_gen: AtomicU64::new(1),
        }
    }
}

impl VcpuScheduler for HostCondvarScheduler {
    fn acquire(&self, _tid: u64) -> SlotLease {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(slot) = st.free.pop() {
                let generation = self.grant_gen.fetch_add(1, Ordering::SeqCst);
                st.generations[slot as usize] = generation;
                return SlotLease { slot, generation };
            }
            // 50ms backstop like HVF's gate — never miss a release wakeup.
            let (g, _) = self
                .cv
                .wait_timeout(st, Duration::from_millis(50))
                .unwrap_or_else(|e| e.into_inner());
            st = g;
        }
    }

    fn release(&self, lease: SlotLease, _why: Yield) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Generation guard: only free the id if THIS lease is still the live grant.
        if st.generations[lease.slot as usize] != lease.generation {
            return; // stale / double release — ignore
        }
        st.generations[lease.slot as usize] = 0; // invalidate the grant
        if !st.free.contains(&lease.slot) {
            st.free.push(lease.slot);
        }
        drop(st);
        self.cv.notify_one();
    }

    fn budget(&self) -> usize {
        self.budget
    }

    fn reset_for_fork(&self, keep: SlotId) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Free every id except the forking thread's; keep that id's generation so
        // its inherited lease stays the live grant.
        st.free = (0..self.budget as SlotId)
            .filter(|&i| i != keep)
            .rev()
            .collect();
        for (i, g) in st.generations.iter_mut().enumerate() {
            if i as SlotId != keep {
                *g = 0;
            }
        }
    }
}

/// A no-op scheduler for backends with no carrick-side cap (budget =
/// `usize::MAX`): `acquire` never blocks and returns a throwaway lease, `release`
/// is a no-op. Used by HVF (whose own `vcpu_gate` stays in Phase 1) and KVM, so
/// the shared thread-spawn path can call the scheduler unconditionally without
/// changing their behaviour. A bounded `HostCondvarScheduler(usize::MAX)` would
/// try to materialize a 4-billion-entry free-list — hence this separate type.
pub struct NoopScheduler {
    next: AtomicU64,
}

impl NoopScheduler {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }
}

impl Default for NoopScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl VcpuScheduler for NoopScheduler {
    fn acquire(&self, _tid: u64) -> SlotLease {
        SlotLease {
            slot: 0,
            generation: self.next.fetch_add(1, Ordering::Relaxed),
        }
    }
    fn release(&self, _lease: SlotLease, _why: Yield) {}
    fn budget(&self) -> usize {
        usize::MAX
    }
    fn reset_for_fork(&self, _keep: SlotId) {}
}

std::thread_local! {
    /// The slot lease the CURRENT host thread holds. Set by the runtime right
    /// after `acquire` (on the guest thread's own host thread), read by the
    /// backend when it creates that thread's vCPU, and taken by the runtime at
    /// thread exit to `release`. Per-host-thread by nature — a thread-local is the
    /// natural representation, and the runtime owns the set/clear lifecycle.
    static CURRENT_LEASE: std::cell::Cell<Option<SlotLease>> = const { std::cell::Cell::new(None) };
}

/// Record the lease the current host thread just acquired (runtime, post-acquire).
pub fn set_current_lease(lease: SlotLease) {
    CURRENT_LEASE.with(|c| c.set(Some(lease)));
}

/// Take the current thread's lease (runtime, at thread exit, to release it).
pub fn take_current_lease() -> Option<SlotLease> {
    CURRENT_LEASE.with(|c| c.take())
}

/// The slot id the current host thread holds, if any — the backend's vCPU id.
pub fn current_slot() -> Option<SlotId> {
    CURRENT_LEASE.with(|c| c.get().map(|l| l.slot))
}

static GLOBAL: OnceLock<Box<dyn VcpuScheduler>> = OnceLock::new();

/// Install the process scheduler once at startup (idempotent; first wins).
pub fn install_global(sched: Box<dyn VcpuScheduler>) {
    let _ = GLOBAL.set(sched);
}

/// Install the right scheduler for a backend's `vcpu_budget()`: a bounded
/// [`HostCondvarScheduler`], or a [`NoopScheduler`] when unbounded (`usize::MAX`).
pub fn install_for_budget(budget: usize) {
    if budget == usize::MAX {
        install_global(Box::new(NoopScheduler::new()));
    } else {
        install_global(Box::new(HostCondvarScheduler::new(budget)));
    }
}

/// The process scheduler. Panics if not installed — startup MUST install it before
/// any guest thread spawns.
pub fn global() -> &'static dyn VcpuScheduler {
    GLOBAL.get().expect("vcpu scheduler not installed").as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn acquire_grants_distinct_ids_up_to_budget() {
        let s = HostCondvarScheduler::new(4);
        let a = s.acquire(1);
        let b = s.acquire(2);
        let c = s.acquire(3);
        let d = s.acquire(4);
        let mut ids = [a.slot, b.slot, c.slot, d.slot];
        ids.sort();
        assert_eq!(
            ids,
            [0, 1, 2, 3],
            "N acquires yield the N distinct ids 0..N"
        );
        assert_eq!(s.budget(), 4);
        for l in [a, b, c, d] {
            s.release(l, Yield::Exited);
        }
    }

    #[test]
    fn over_budget_acquire_blocks_until_release() {
        let s = Arc::new(HostCondvarScheduler::new(1));
        let held = s.acquire(1);
        let s2 = Arc::clone(&s);
        let waiter = std::thread::spawn(move || s2.acquire(2).slot);
        std::thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished(), "2nd acquire must block at budget=1");
        s.release(held, Yield::Exited);
        let got = waiter.join().unwrap();
        assert_eq!(got, 0, "the freed id 0 is recycled to the waiter");
    }

    #[test]
    fn released_id_is_recycled_not_grown() {
        let s = HostCondvarScheduler::new(2);
        let a = s.acquire(1);
        let b = s.acquire(2);
        let first = a.slot;
        s.release(a, Yield::Exited);
        let c = s.acquire(3); // must reuse `first`, never id 2
        assert_eq!(
            c.slot, first,
            "exited id recycled, pool never exceeds N ids"
        );
        s.release(b, Yield::Exited);
        s.release(c, Yield::Exited);
    }

    #[test]
    fn double_release_is_rejected_by_generation_guard() {
        let s = HostCondvarScheduler::new(2);
        let a = s.acquire(1);
        let slot = a.slot;
        let stale = SlotLease {
            slot,
            generation: a.generation,
        };
        s.release(a, Yield::Exited);
        let b = s.acquire(2);
        s.release(stale, Yield::Exited); // stale gen: no-op
        let c = s.acquire(3);
        assert_ne!(
            b.slot, c.slot,
            "stale double-release must not duplicate a free id"
        );
        s.release(b, Yield::Exited);
        s.release(c, Yield::Exited);
    }

    #[test]
    fn noop_scheduler_never_blocks_and_budget_is_max() {
        let s = NoopScheduler::new();
        let a = s.acquire(1);
        let b = s.acquire(2);
        assert_eq!(s.budget(), usize::MAX);
        assert_ne!(a.generation(), b.generation(), "leases are distinguishable");
        s.release(a, Yield::Exited);
        s.release(b, Yield::Exited); // no-op, no panic, no double-free concern
    }

    #[test]
    fn reset_for_fork_frees_all_but_the_keeper() {
        let s = HostCondvarScheduler::new(4);
        let a = s.acquire(1);
        let b = s.acquire(2);
        let _c = s.acquire(3);
        let keep = b.slot;
        s.reset_for_fork(keep);
        // The 3 non-keep ids are free again; 3 acquires succeed without blocking and
        // none returns `keep` (it stays allocated to the forking thread).
        let got: Vec<_> = (0..3).map(|_| s.acquire(9).slot).collect();
        assert!(
            !got.contains(&keep),
            "the kept slot stays allocated across fork"
        );
        let mut all = got.clone();
        all.push(keep);
        all.sort();
        assert_eq!(
            all,
            vec![0, 1, 2, 3],
            "the pool is whole again, each id once"
        );
        // The keeper's inherited lease is still the live grant.
        s.release(b, Yield::Exited);
        let _ = a; // a's slot was freed by reset (generation cleared); no release
    }
}
