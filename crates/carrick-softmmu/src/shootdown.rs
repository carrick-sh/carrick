//! Cross-vCPU software-TLB retirement barrier.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};

use crate::SoftTlb;

/// Identity of one extent-table shootdown domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShootdownAuthority(usize);

/// Monotone extent-table retirement epoch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ShootdownEpoch(u64);

impl ShootdownEpoch {
    pub const INITIAL: Self = Self(0);
}

/// Identity and epoch last synchronized by one local TLB.
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

/// Execution state used to decide whether a peer needs a kick or may defer its flush.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VcpuShootdownState {
    Running,
    Idle,
    Parked,
}

/// Backend hook which forces a running vCPU to its next safe point.
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
}

struct PeerState {
    state: VcpuShootdownState,
    acknowledged: ShootdownEpoch,
    needs_sync: bool,
}

struct Peer {
    state: Mutex<PeerState>,
    kick: Arc<dyn ShootdownKick>,
}

struct CoordinatorState {
    peers: Vec<Weak<Peer>>,
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
                stats: ShootdownStats::default(),
            }),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, CoordinatorState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn current_epoch(&self) -> ShootdownEpoch {
        ShootdownEpoch(self.epoch.load(Ordering::Acquire))
    }

    fn current_stamp(self: &Arc<Self>) -> ShootdownStamp {
        ShootdownStamp {
            authority: ShootdownAuthority(Arc::as_ptr(self) as usize),
            epoch: self.current_epoch(),
        }
    }

    pub(crate) fn register(self: &Arc<Self>, kick: Arc<dyn ShootdownKick>) -> VcpuShootdown {
        let epoch = self.current_epoch();
        let peer = Arc::new(Peer {
            state: Mutex::new(PeerState {
                state: VcpuShootdownState::Idle,
                acknowledged: epoch,
                needs_sync: true,
            }),
            kick,
        });
        self.lock().peers.push(Arc::downgrade(&peer));
        VcpuShootdown {
            coordinator: Arc::clone(self),
            peer,
        }
    }

    pub(crate) fn begin<T>(self: &Arc<Self>, value: T) -> PendingShootdown<T> {
        let mut state = self.lock();
        let next_raw = self.epoch.load(Ordering::Relaxed).saturating_add(1);
        let next = ShootdownEpoch(next_raw);
        self.epoch.store(next.0, Ordering::Release);
        state.stats.retirements = state.stats.retirements.saturating_add(1);
        let peers = core::mem::take(&mut state.peers);
        let mut live = Vec::with_capacity(peers.len());
        let mut kicks = Vec::new();
        for weak in peers {
            let Some(peer) = weak.upgrade() else { continue };
            state.stats.peer_visits = state.stats.peer_visits.saturating_add(1);
            let mut peer_state = peer.state.lock().unwrap_or_else(|p| p.into_inner());
            peer_state.needs_sync = true;
            match peer_state.state {
                VcpuShootdownState::Running => {
                    peer_state.acknowledged = ShootdownEpoch::INITIAL;
                    state.stats.kicks = state.stats.kicks.saturating_add(1);
                    kicks.push(Arc::clone(&peer.kick));
                }
                VcpuShootdownState::Idle | VcpuShootdownState::Parked => {
                    peer_state.acknowledged = next;
                }
            }
            drop(peer_state);
            live.push(Arc::downgrade(&peer));
        }
        state.peers = live;
        drop(state);
        for kick in kicks {
            kick.kick();
        }
        PendingShootdown {
            coordinator: Arc::clone(self),
            epoch: next,
            value,
        }
    }

    fn is_complete(state: &CoordinatorState, epoch: ShootdownEpoch) -> bool {
        state.peers.iter().filter_map(Weak::upgrade).all(|peer| {
            let peer = peer.state.lock().unwrap_or_else(|p| p.into_inner());
            peer.state != VcpuShootdownState::Running || peer.acknowledged >= epoch
        })
    }

    pub(crate) fn stats(&self) -> ShootdownStats {
        self.lock().stats
    }
}

/// Per-vCPU registration. Its methods serialize lifecycle transitions with retirement admission.
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
    /// Flush to the owning table's current epoch and publish a safe-point acknowledgement.
    pub fn synchronize(&self, tlb: &mut SoftTlb) {
        let _coordinator = self.coordinator.lock();
        let epoch = self.coordinator.current_epoch();
        let stamp = self.coordinator.current_stamp();
        let mut peer = self.peer.state.lock().unwrap_or_else(|p| p.into_inner());
        if peer.needs_sync || tlb.synchronized_stamp() != stamp {
            tlb.flush_all();
            tlb.set_synchronized_stamp(stamp);
        }
        peer.needs_sync = false;
        peer.acknowledged = epoch;
        drop(peer);
        self.coordinator.changed.notify_all();
    }

    /// Enter guest execution. Synchronization happens before the peer becomes kickable.
    pub fn enter_running(&self, tlb: &mut SoftTlb) {
        let _coordinator = self.coordinator.lock();
        let epoch = self.coordinator.current_epoch();
        let stamp = self.coordinator.current_stamp();
        let mut peer = self.peer.state.lock().unwrap_or_else(|p| p.into_inner());
        if peer.needs_sync || tlb.synchronized_stamp() != stamp {
            tlb.flush_all();
            tlb.set_synchronized_stamp(stamp);
        }
        peer.needs_sync = false;
        peer.acknowledged = epoch;
        peer.state = VcpuShootdownState::Running;
    }

    pub fn leave_idle(&self) {
        self.leave(VcpuShootdownState::Idle);
    }

    pub fn leave_parked(&self) {
        self.leave(VcpuShootdownState::Parked);
    }

    fn leave(&self, next: VcpuShootdownState) {
        let _coordinator = self.coordinator.lock();
        let epoch = self.coordinator.current_epoch();
        let mut peer = self.peer.state.lock().unwrap_or_else(|p| p.into_inner());
        peer.state = next;
        peer.acknowledged = epoch;
        drop(peer);
        self.coordinator.changed.notify_all();
    }
}

impl Drop for VcpuShootdown {
    fn drop(&mut self) {
        self.coordinator.changed.notify_all();
    }
}

/// Linear retirement capability. The retired value is inaccessible until the barrier completes.
#[must_use = "retired generations remain unavailable until complete() finishes the shootdown"]
pub struct PendingShootdown<T> {
    coordinator: Arc<ShootdownCoordinator>,
    epoch: ShootdownEpoch,
    value: T,
}

impl<T> PendingShootdown<T> {
    pub const fn epoch(&self) -> ShootdownEpoch {
        self.epoch
    }

    pub fn complete(self) -> T {
        let mut state = self.coordinator.lock();
        while !ShootdownCoordinator::is_complete(&state, self.epoch) {
            state = self
                .coordinator
                .changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        self.value
    }
}

#[cfg(test)]
#[path = "../test-support/shootdown_unit.rs"]
mod tests;
