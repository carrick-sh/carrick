//! Executor-wide shutdown observation at physical vCPU entry, including
//! backend-internal re-entry. This is distinct from a consumable reschedule.
//!
//! This handshake does NOT make an edge-triggered hardware kick persistent.
//! A backend must either latch cancellation across entry, or supply a durable
//! interrupt when shutdown was observed. See the signed HVF qualification.
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

const SHUTDOWN: u8 = 1;
const ENTERED: u8 = 2;

/// Atomic operations used by the shipping protocol and its loom binding.
/// Implementations must use one sequentially consistent atomic word.
pub trait RunStateWord {
    fn load(&self) -> u8;
    fn set_bits(&self, bits: u8) -> u8;
    fn clear_bits(&self, bits: u8);
}
impl RunStateWord for AtomicU8 {
    fn load(&self) -> u8 {
        self.load(Ordering::SeqCst)
    }
    fn set_bits(&self, bits: u8) -> u8 {
        self.fetch_or(bits, Ordering::SeqCst)
    }
    fn clear_bits(&self, bits: u8) {
        self.fetch_and(!bits, Ordering::SeqCst);
    }
}

/// One state per executor, independent of task, mailbox and run generation.
/// Only the executor owner may enter/leave; shutdown may be requested remotely.
pub struct VcpuRunState<W = AtomicU8> {
    word: W,
}
impl Default for VcpuRunState {
    fn default() -> Self {
        Self::with_word(AtomicU8::new(0))
    }
}
impl<W: RunStateWord> VcpuRunState<W> {
    pub const fn with_word(word: W) -> Self {
        Self { word }
    }
    pub fn shutdown_requested(&self) -> bool {
        self.word.load() & SHUTDOWN != 0
    }
    /// Latch before observing entry. A worker publishing afterwards sees the
    /// latch in its RMW. A worker publishing beforehand is kicked, even if it
    /// has not yet reached the backend's actual run instruction.
    pub fn request_shutdown(&self, kick: impl FnOnce()) {
        if self.word.set_bits(SHUTDOWN) & ENTERED != 0 {
            kick();
        }
    }
    /// Publish first, then observe shutdown in the same atomic operation.
    /// The caller must finish the entry before publishing another one.
    fn publish_entry(&self) -> bool {
        self.word.set_bits(ENTERED) & SHUTDOWN != 0
    }
    pub fn enter(&self) -> RunEntry<'_, W> {
        let shutdown = self.publish_entry();
        RunEntry {
            state: self,
            shutdown,
            _owner_thread: PhantomData,
        }
    }
}

#[must_use]
pub struct RunEntry<'a, W: RunStateWord = AtomicU8> {
    state: &'a VcpuRunState<W>,
    shutdown: bool,
    _owner_thread: PhantomData<Rc<()>>,
}
impl<W: RunStateWord> RunEntry<'_, W> {
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown
    }
}
impl<W: RunStateWord> Drop for RunEntry<'_, W> {
    fn drop(&mut self) {
        self.state.word.clear_bits(ENTERED);
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<VcpuRunState>>> = const { RefCell::new(None) };
}

/// Installs the runtime-owned state for this executor's lifetime. Backends
/// discover it at the physical entry, so nested engine loops cannot bypass it.
#[must_use]
pub struct ExecutorRunScope(Option<Arc<VcpuRunState>>, PhantomData<Rc<()>>);
impl ExecutorRunScope {
    pub fn install(state: Arc<VcpuRunState>) -> Self {
        Self(
            CURRENT.with(|current| current.replace(Some(state))),
            PhantomData,
        )
    }
}
impl Drop for ExecutorRunScope {
    fn drop(&mut self) {
        CURRENT.with(|current| current.replace(self.0.take()));
    }
}

/// Owned guard for a physical entry. Non-executor callers have no state and
/// keep their ordinary backend behavior. Drop on every run return or error.
#[must_use]
pub struct PhysicalRunEntry {
    state: Option<Arc<VcpuRunState>>,
    shutdown: bool,
    _owner_thread: PhantomData<Rc<()>>,
}
impl PhysicalRunEntry {
    pub fn current() -> Self {
        let state = CURRENT.with(|current| current.borrow().clone());
        let shutdown = state.as_ref().is_some_and(|state| state.publish_entry());
        Self {
            state,
            shutdown,
            _owner_thread: PhantomData,
        }
    }
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown
    }
}
impl Drop for PhysicalRunEntry {
    fn drop(&mut self) {
        if let Some(state) = &self.state {
            state.word.clear_bits(ENTERED);
        }
    }
}

/// The runtime's quantum control must also observe the sticky state after a
/// backend surfaces an interrupted run, independently of reschedule clearing.
pub fn current_shutdown_requested() -> bool {
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .is_some_and(|state| state.shutdown_requested())
    })
}
