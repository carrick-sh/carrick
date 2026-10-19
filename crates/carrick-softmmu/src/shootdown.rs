//! Cross-vCPU software-TLB retirement barrier.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::thread_local;

thread_local! {
    static ACTIVE_AUTHORITY: core::cell::Cell<(usize, u32)> = const { core::cell::Cell::new((0, 0)) };
}

use crate::SoftTlb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShootdownAuthority(usize);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShootdownEpoch(u64);

impl ShootdownEpoch {
    pub const INITIAL: Self = Self(0);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShootdownStamp {
    authority: ShootdownAuthority,
    epoch: ShootdownEpoch,
}

impl ShootdownStamp {
    pub const UNBOUND: Self = Self {
        authority: ShootdownAuthority(0),
        epoch: ShootdownEpoch::INITIAL,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VcpuShootdownState {
    Running = 0,
    Idle = 1,
    Parked = 2,
}

pub trait ShootdownKick: Send + Sync {
    fn kick(&self);
}

impl<F> ShootdownKick for F
where
    F: Fn() + Send + Sync,
{
    fn kick(&self) {
        self()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShootdownStats {
    pub retirements: u64,
    pub peer_visits: u64,
    pub kicks: u64,
    pub stale_epoch_lock_acquisitions: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetiredIdentity {
    ExtentBase(u64),
    ExtentGeneration(u64),
    Root(u64),
    RootGeneration(u64),
}

struct Peer {
    state: AtomicU8,
    acknowledged: AtomicU64,
    kick: Arc<dyn ShootdownKick>,
}

impl Peer {
    fn state(&self) -> VcpuShootdownState {
        match self.state.load(Ordering::Acquire) {
            0 => VcpuShootdownState::Running,
            1 => VcpuShootdownState::Idle,
            2 => VcpuShootdownState::Parked,
            _ => unreachable!("invalid vCPU shootdown state"),
        }
    }
}

struct PendingEpoch {
    epoch: ShootdownEpoch,
    waiting: Vec<usize>,
    identities: Vec<RetiredIdentity>,
}

struct CoordinatorState {
    peers: Vec<Weak<Peer>>,
    pending: Vec<PendingEpoch>,
    stats: ShootdownStats,
}

pub(crate) struct ShootdownCoordinator {
    epoch: AtomicU64,
    state: Mutex<CoordinatorState>,
    changed: Condvar,
}

impl core::fmt::Debug for ShootdownCoordinator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShootdownCoordinator")
            .field("epoch", &self.current_epoch())
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl ShootdownCoordinator {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch: AtomicU64::new(0),
            state: Mutex::new(CoordinatorState {
                peers: Vec::new(),
                pending: Vec::new(),
                stats: ShootdownStats::default(),
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, CoordinatorState> {
        self.state.lock().expect("shootdown coordinator poisoned")
    }

    pub(crate) fn current_epoch(&self) -> ShootdownEpoch {
        ShootdownEpoch(self.epoch.load(Ordering::Acquire))
    }

    fn stamp(self: &Arc<Self>, epoch: ShootdownEpoch) -> ShootdownStamp {
        ShootdownStamp {
            authority: ShootdownAuthority(Arc::as_ptr(self) as usize),
            epoch,
        }
    }

    pub(crate) fn register(self: &Arc<Self>, kick: Arc<dyn ShootdownKick>) -> VcpuShootdown {
        let epoch = self.current_epoch();
        let peer = Arc::new(Peer {
            state: AtomicU8::new(VcpuShootdownState::Idle as u8),
            acknowledged: AtomicU64::new(epoch.0),
            kick,
        });
        self.lock().peers.push(Arc::downgrade(&peer));
        VcpuShootdown {
            coordinator: Arc::clone(self),
            peer,
        }
    }

    pub(crate) fn has_pending(&self, identities: &[RetiredIdentity]) -> bool {
        self.lock().pending.iter().any(|pending| {
            pending
                .identities
                .iter()
                .any(|identity| identities.contains(identity))
        })
    }

    pub(crate) fn begin<T>(
        self: &Arc<Self>,
        identities: Vec<RetiredIdentity>,
        value: T,
    ) -> PendingShootdown<T> {
        let mut state = self.lock();
        assert!(
            !state.pending.iter().any(|pending| pending
                .identities
                .iter()
                .any(|identity| identities.contains(identity))),
            "retired extent or generation reused before shootdown completion"
        );
        let next_raw = self
            .epoch
            .load(Ordering::Relaxed)
            .checked_add(1)
            .expect("shootdown epoch exhausted");
        let next = ShootdownEpoch(next_raw);
        self.epoch.store(next.0, Ordering::Release);
        state.stats.retirements = state.stats.retirements.saturating_add(1);
        let peers = core::mem::take(&mut state.peers);
        let mut live = Vec::with_capacity(peers.len());
        let mut waiting = Vec::new();
        let mut kicks = Vec::new();
        for weak in peers {
            let Some(peer) = weak.upgrade() else { continue };
            state.stats.peer_visits = state.stats.peer_visits.saturating_add(1);
            if peer.state() == VcpuShootdownState::Running
                && peer.acknowledged.load(Ordering::Acquire) < next.0
            {
                waiting.push(Arc::as_ptr(&peer) as usize);
                state.stats.kicks = state.stats.kicks.saturating_add(1);
                kicks.push(Arc::clone(&peer.kick));
            }
            live.push(Arc::downgrade(&peer));
        }
        state.peers = live;
        state.pending.push(PendingEpoch {
            epoch: next,
            waiting,
            identities,
        });
        drop(state);
        for kick in kicks {
            kick.kick();
        }
        PendingShootdown {
            coordinator: Arc::clone(self),
            epoch: next,
            value: Some(value),
        }
    }

    fn acknowledge(&self, peer_id: usize, epoch: ShootdownEpoch) {
        let mut state = self.lock();
        state.stats.stale_epoch_lock_acquisitions =
            state.stats.stale_epoch_lock_acquisitions.saturating_add(1);
        let mut completed = false;
        for pending in &mut state.pending {
            if pending.epoch <= epoch
                && let Some(index) = pending.waiting.iter().position(|id| *id == peer_id)
            {
                pending.waiting.swap_remove(index);
                completed |= pending.waiting.is_empty();
            }
        }
        drop(state);
        if completed {
            self.changed.notify_all();
        }
    }

    fn unregister(&self, peer_id: usize) {
        let mut state = self.lock();
        let mut completed = false;
        for pending in &mut state.pending {
            if let Some(index) = pending.waiting.iter().position(|id| *id == peer_id) {
                pending.waiting.swap_remove(index);
                completed |= pending.waiting.is_empty();
            }
        }
        drop(state);
        if completed {
            self.changed.notify_all();
        }
    }

    fn finish(&self, epoch: ShootdownEpoch) {
        let authority = self as *const Self as usize;
        assert!(
            !ACTIVE_AUTHORITY.with(|active| {
                let (current, depth) = active.get();
                current == authority && depth != 0
            }),
            "a vCPU cannot complete its own shootdown while running"
        );
        let mut state = self.lock();
        loop {
            let pending = state
                .pending
                .iter()
                .find(|pending| pending.epoch == epoch)
                .expect("unknown pending shootdown epoch");
            if pending.waiting.is_empty() {
                break;
            }
            state = self
                .changed
                .wait(state)
                .expect("shootdown coordinator poisoned while waiting");
        }
        let index = state
            .pending
            .iter()
            .position(|pending| pending.epoch == epoch)
            .expect("unknown pending shootdown epoch");
        state.pending.swap_remove(index);
    }

    pub(crate) fn stats(&self) -> ShootdownStats {
        self.lock().stats
    }
}

pub struct VcpuShootdown {
    coordinator: Arc<ShootdownCoordinator>,
    peer: Arc<Peer>,
}

impl core::fmt::Debug for VcpuShootdown {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VcpuShootdown").finish_non_exhaustive()
    }
}

impl VcpuShootdown {
    fn mark_running_thread(&self) {
        let authority = Arc::as_ptr(&self.coordinator) as usize;
        ACTIVE_AUTHORITY.with(|active| {
            let (current, depth) = active.get();
            assert!(
                depth == 0 || current == authority,
                "thread entered two shootdown domains"
            );
            active.set((authority, depth.saturating_add(1)));
        });
    }

    fn unmark_running_thread(&self) {
        ACTIVE_AUTHORITY.with(|active| {
            let (authority, depth) = active.get();
            assert_eq!(authority, Arc::as_ptr(&self.coordinator) as usize);
            assert_ne!(depth, 0);
            active.set(if depth == 1 {
                (0, 0)
            } else {
                (authority, depth - 1)
            });
        });
    }

    pub(crate) fn belongs_to(&self, coordinator: &Arc<ShootdownCoordinator>) -> bool {
        Arc::ptr_eq(&self.coordinator, coordinator)
    }

    pub fn synchronize(&self, tlb: &mut SoftTlb) {
        let epoch = self.coordinator.current_epoch();
        let stamp = self.coordinator.stamp(epoch);
        if tlb.synchronized_stamp() == stamp {
            return;
        }
        tlb.flush_all();
        tlb.set_synchronized_stamp(stamp);
        self.peer.acknowledged.store(epoch.0, Ordering::Release);
        self.coordinator
            .acknowledge(Arc::as_ptr(&self.peer) as usize, epoch);
    }

    pub fn enter_running(&self, tlb: &mut SoftTlb) {
        self.peer
            .state
            .store(VcpuShootdownState::Running as u8, Ordering::Release);
        self.mark_running_thread();
        self.synchronize(tlb);
    }

    pub fn begin_lookup(&self, tlb: &mut SoftTlb) -> VcpuShootdownState {
        if self.peer.state() == VcpuShootdownState::Running {
            self.synchronize(tlb);
            return VcpuShootdownState::Running;
        }
        let previous = match self
            .peer
            .state
            .swap(VcpuShootdownState::Running as u8, Ordering::AcqRel)
        {
            0 => VcpuShootdownState::Running,
            1 => VcpuShootdownState::Idle,
            2 => VcpuShootdownState::Parked,
            _ => unreachable!("invalid vCPU shootdown state"),
        };
        if previous != VcpuShootdownState::Running {
            self.mark_running_thread();
        }
        self.synchronize(tlb);
        previous
    }

    pub fn end_lookup(&self, previous: VcpuShootdownState, tlb: &mut SoftTlb) {
        if previous != VcpuShootdownState::Running {
            self.leave(previous, tlb);
        }
    }

    #[cfg(test)]
    fn enter_running_with_hook(&self, tlb: &mut SoftTlb, hook: impl FnOnce()) {
        self.peer
            .state
            .store(VcpuShootdownState::Running as u8, Ordering::Release);
        self.mark_running_thread();
        hook();
        self.synchronize(tlb);
    }

    pub fn leave_idle(&self, tlb: &mut SoftTlb) {
        self.leave(VcpuShootdownState::Idle, tlb);
    }

    pub fn leave_parked(&self, tlb: &mut SoftTlb) {
        self.leave(VcpuShootdownState::Parked, tlb);
    }

    fn leave(&self, next: VcpuShootdownState, tlb: &mut SoftTlb) {
        self.peer.state.store(next as u8, Ordering::Release);
        self.synchronize(tlb);
        self.unmark_running_thread();
    }
}

impl Drop for VcpuShootdown {
    fn drop(&mut self) {
        self.coordinator
            .unregister(Arc::as_ptr(&self.peer) as usize);
    }
}

#[must_use = "retired generations remain unavailable until complete() finishes the shootdown"]
pub struct PendingShootdown<T> {
    coordinator: Arc<ShootdownCoordinator>,
    epoch: ShootdownEpoch,
    value: Option<T>,
}

impl<T> PendingShootdown<T> {
    pub const fn epoch(&self) -> ShootdownEpoch {
        self.epoch
    }

    pub fn complete(mut self) -> T {
        let value = self.value.take().expect("pending shootdown value missing");
        self.coordinator.finish(self.epoch);
        value
    }
}

impl<T> Drop for PendingShootdown<T> {
    fn drop(&mut self) {
        if self.value.is_some() {
            panic!("pending shootdown dropped without complete()")
        }
    }
}

#[cfg(test)]
#[path = "../test-support/shootdown_unit.rs"]
mod tests;
