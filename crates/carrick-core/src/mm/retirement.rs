//! Load admission, drain and invalidation custody shared by both ISAs.
//! Synchronization and architectural invalidation stay with the execution venue.

use core::fmt;
use core::ops::DerefMut;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidencyError {
    Retiring,
    AlreadyRetiring,
    ExecutorStillLoading,
    HardwareAlreadyDirty,
    UnexpectedLoad,
    StaleGeneration,
}
impl fmt::Display for ResidencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Retiring => "address generation is closed to new executor loads",
            Self::AlreadyRetiring => "address generation retirement already began",
            Self::ExecutorStillLoading => "an executor load is still in flight",
            Self::HardwareAlreadyDirty => "load hardware-dirty boundary was already armed",
            Self::UnexpectedLoad => "load already completed",
            Self::StaleGeneration => "stale address generation invalidation",
        })
    }
}
impl core::error::Error for ResidencyError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResidencyLifecycle {
    #[default]
    Live,
    RetirementPrepared,
    Retired,
}

/// The sole logical residency state. Its fields cannot be mutated by adapters.
#[derive(Debug, Default)]
pub struct ResidencyState {
    lifecycle: ResidencyLifecycle,
    loading: usize,
    hardware_dirty: bool,
    installed: bool,
    invalidated: bool,
}

/// Exclusive access and notification for one residency owner.
///
/// # Safety
/// Clones must access the same state. Guards must exclude all other accesses.
/// Waiting must atomically release and reacquire that guard, and notifications
/// must wake a waiter after an admitted load settles.
pub unsafe trait ResidencyVenue: Clone + fmt::Debug + Default {
    type Guard<'a>: DerefMut<Target = ResidencyState>
    where
        Self: 'a;
    fn lock(&self) -> Self::Guard<'_>;
    fn wait(&self, guard: &mut Self::Guard<'_>);
    fn notify_all(&self);
}

/// Architectural completion, minted after invalidating this exact generation.
///
/// # Safety
/// The reported generation must identify a completed invalidation covering
/// every execution venue which could cache its translations.
pub unsafe trait InvalidationProof<G> {
    fn generation(&self) -> G;
}

#[derive(Clone, Debug)]
pub struct AddressResidency<V: ResidencyVenue, G: Copy + Eq> {
    generation: G,
    venue: V,
}
impl<V: ResidencyVenue, G: Copy + Eq> AddressResidency<V, G> {
    pub fn new(generation: G) -> Self {
        Self {
            generation,
            venue: V::default(),
        }
    }
    pub fn begin_load(&self) -> Result<ResidencyLoad<V>, ResidencyError> {
        let mut state = self.venue.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(ResidencyError::Retiring);
        }
        state.loading += 1;
        Ok(ResidencyLoad {
            venue: self.venue.clone(),
            active: true,
            hardware_dirty: false,
        })
    }
    pub fn is_retiring(&self) -> bool {
        self.venue.lock().lifecycle != ResidencyLifecycle::Live
    }
    pub fn was_installed(&self) -> bool {
        let state = self.venue.lock();
        state.installed || state.hardware_dirty
    }
    pub fn prepare_retirement(&self) -> Result<PreparedResidencyRetirement<V, G>, ResidencyError> {
        let mut state = self.venue.lock();
        if state.lifecycle != ResidencyLifecycle::Live {
            return Err(ResidencyError::AlreadyRetiring);
        }
        state.lifecycle = ResidencyLifecycle::RetirementPrepared;
        Ok(PreparedResidencyRetirement {
            residency: self.clone(),
            active: true,
        })
    }
    pub fn begin_retirement(&self) -> Result<ResidencyRetirement<V, G>, ResidencyError> {
        Ok(self.prepare_retirement()?.commit())
    }
}

#[derive(Debug)]
pub struct ResidencyLoad<V: ResidencyVenue> {
    venue: V,
    active: bool,
    hardware_dirty: bool,
}
impl<V: ResidencyVenue> ResidencyLoad<V> {
    pub fn arm_hardware_dirty(&mut self) -> Result<(), ResidencyError> {
        if self.hardware_dirty {
            return Err(ResidencyError::HardwareAlreadyDirty);
        }
        if !self.active {
            return Err(ResidencyError::UnexpectedLoad);
        }
        self.venue.lock().hardware_dirty = true;
        self.hardware_dirty = true;
        Ok(())
    }
    pub fn mark_resident(mut self) -> Result<(), ResidencyError> {
        let mut state = self.venue.lock();
        state.loading = state
            .loading
            .checked_sub(1)
            .ok_or(ResidencyError::UnexpectedLoad)?;
        state.installed = true;
        self.active = false;
        self.venue.notify_all();
        Ok(())
    }
}
impl<V: ResidencyVenue> Drop for ResidencyLoad<V> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Cancellation after the hardware boundary cannot erase exposure.
        let mut state = self.venue.lock();
        state.loading = state.loading.saturating_sub(1);
        self.venue.notify_all();
    }
}

#[derive(Debug)]
pub struct PreparedResidencyRetirement<V: ResidencyVenue, G: Copy + Eq> {
    residency: AddressResidency<V, G>,
    active: bool,
}
impl<V: ResidencyVenue, G: Copy + Eq> PreparedResidencyRetirement<V, G> {
    pub fn needs_invalidation(&self) -> bool {
        let state = self.residency.venue.lock();
        state.installed || state.hardware_dirty || state.loading != 0
    }
    pub fn requires_quarantine(&self) -> bool {
        let state = self.residency.venue.lock();
        state.hardware_dirty || state.loading != 0
    }
    pub fn commit(mut self) -> ResidencyRetirement<V, G> {
        // Only this non-cloneable token can leave RetirementPrepared.
        self.residency.venue.lock().lifecycle = ResidencyLifecycle::Retired;
        self.active = false;
        ResidencyRetirement {
            generation: self.residency.generation,
            venue: self.residency.venue.clone(),
        }
    }
}
impl<V: ResidencyVenue, G: Copy + Eq> Drop for PreparedResidencyRetirement<V, G> {
    fn drop(&mut self) {
        if self.active {
            self.residency.venue.lock().lifecycle = ResidencyLifecycle::Live;
        }
    }
}

#[derive(Debug)]
pub struct ResidencyRetirement<V: ResidencyVenue, G: Copy + Eq> {
    generation: G,
    venue: V,
}
impl<V: ResidencyVenue, G: Copy + Eq> ResidencyRetirement<V, G> {
    pub const fn generation(&self) -> G {
        self.generation
    }
    pub fn wait_for_admitted_loads(&self) {
        let mut state = self.venue.lock();
        while state.loading != 0 {
            self.venue.wait(&mut state);
        }
    }
    pub fn needs_invalidation(&self) -> bool {
        let state = self.venue.lock();
        (state.installed || state.hardware_dirty || state.loading != 0) && !state.invalidated
    }
    pub fn acknowledge(
        &self,
        invalidation: impl InvalidationProof<G>,
    ) -> Result<(), ResidencyError> {
        if invalidation.generation() != self.generation {
            return Err(ResidencyError::StaleGeneration);
        }
        let mut state = self.venue.lock();
        if state.loading != 0 {
            return Err(ResidencyError::ExecutorStillLoading);
        }
        state.invalidated = true;
        Ok(())
    }
    pub fn is_complete(&self) -> bool {
        let state = self.venue.lock();
        state.invalidated || (!state.installed && !state.hardware_dirty && state.loading == 0)
    }
}

use core::sync::atomic::{AtomicU64, Ordering};
static NEXT_ROOT_RETIREMENT_NONCE: AtomicU64 = AtomicU64::new(1);

/// Native geometry of one structural root extent; no ownership is conferred.
pub trait RootSlot: Copy + Eq + fmt::Debug {
    fn base(self) -> u64;
    fn size(self) -> u64;
}

/// Backend proof that structural backing is terminal, including every pin.
///
/// # Safety
/// Coordinates must name the exact terminal physical custody record. Removing
/// a memslot or reloading one CPU's root is insufficient to mint this proof.
pub unsafe trait TerminalRootProof {
    fn base(&self) -> u64;
    fn size(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRetirementError {
    Incomplete,
    TicketAlreadyIssued,
    TicketUnavailable,
    ReceiptMissing,
    UnexpectedReceipt,
    Mismatch {
        expected_base: u64,
        expected_size: u64,
        actual_base: u64,
        actual_size: u64,
    },
}
impl fmt::Display for RootRetirementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "root retirement: {self:?}")
    }
}
impl core::error::Error for RootRetirementError {}

/// One-shot ticket; it carries the nonce through terminal backend custody.
#[derive(Debug)]
pub struct RootRetirementTicket<S: RootSlot> {
    slot: S,
    nonce: u64,
}
impl<S: RootSlot> RootRetirementTicket<S> {
    pub fn base(&self) -> u64 {
        self.slot.base()
    }
    pub fn size(&self) -> u64 {
        self.slot.size()
    }
    pub fn redeem(
        self,
        proof: impl TerminalRootProof,
    ) -> Result<RootRetirementReceipt<S>, RootRetirementError> {
        if (proof.base(), proof.size()) != (self.slot.base(), self.slot.size()) {
            return Err(RootRetirementError::Mismatch {
                expected_base: self.slot.base(),
                expected_size: self.slot.size(),
                actual_base: proof.base(),
                actual_size: proof.size(),
            });
        }
        Ok(RootRetirementReceipt {
            slot: self.slot,
            nonce: self.nonce,
        })
    }
}
#[derive(Debug)]
pub struct RootRetirementReceipt<S: RootSlot> {
    slot: S,
    nonce: u64,
}

/// The sole root-reuse gate for one retirement. Neither cloneable nor mintable
/// from a receipt; aborted admission burns a nonce without authorizing reuse.
#[derive(Debug)]
pub struct RootQuarantine<S: RootSlot> {
    slot: Option<S>,
    nonce: Option<u64>,
    ticket_issued: bool,
}
impl<S: RootSlot> RootQuarantine<S> {
    pub const fn rootless() -> Self {
        Self {
            slot: None,
            nonce: None,
            ticket_issued: false,
        }
    }
    pub fn reserve(slot: Option<S>) -> Result<Self, RootRetirementError> {
        let Some(slot) = slot else {
            return Ok(Self::rootless());
        };
        let nonce = NEXT_ROOT_RETIREMENT_NONCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| RootRetirementError::TicketUnavailable)?;
        Ok(Self {
            slot: Some(slot),
            nonce: Some(nonce),
            ticket_issued: false,
        })
    }
    pub fn take_ticket(&mut self) -> Result<Option<RootRetirementTicket<S>>, RootRetirementError> {
        let Some(slot) = self.slot else {
            return Ok(None);
        };
        if self.ticket_issued {
            return Err(RootRetirementError::TicketAlreadyIssued);
        }
        let nonce = self.nonce.ok_or(RootRetirementError::TicketUnavailable)?;
        self.ticket_issued = true;
        Ok(Some(RootRetirementTicket { slot, nonce }))
    }
    fn settle(
        self,
        receipt: Option<RootRetirementReceipt<S>>,
    ) -> Result<Option<S>, RootRetirementError> {
        match (self.slot, self.nonce, receipt) {
            (None, None, None) => Ok(None),
            (Some(slot), Some(nonce), Some(receipt))
                if receipt.slot == slot && receipt.nonce == nonce =>
            {
                Ok(Some(slot))
            }
            (Some(slot), _, Some(receipt)) => Err(RootRetirementError::Mismatch {
                expected_base: slot.base(),
                expected_size: slot.size(),
                actual_base: receipt.slot.base(),
                actual_size: receipt.slot.size(),
            }),
            (Some(_), _, None) => Err(RootRetirementError::ReceiptMissing),
            (None, _, Some(_)) | (None, Some(_), None) => {
                Err(RootRetirementError::UnexpectedReceipt)
            }
        }
    }
}
impl<V: ResidencyVenue, G: Copy + Eq> ResidencyRetirement<V, G> {
    /// Reuse follows settled loads, required invalidation, and exact terminal
    /// structural custody. No caller-supplied completion boolean is accepted.
    pub fn complete_root<S: RootSlot>(
        &self,
        root: RootQuarantine<S>,
        receipt: Option<RootRetirementReceipt<S>>,
    ) -> Result<Option<S>, RootRetirementError> {
        if !self.is_complete() {
            return Err(RootRetirementError::Incomplete);
        }
        root.settle(receipt)
    }
}
