//! Interrupted-wait policy from signal(7), "Interruption of system calls":
//! <https://man7.org/linux/man-pages/man7/signal.7.html>.
//! No wait registration, transport, syscall-number table or scheduler here.

use alloc::collections::BTreeMap;
use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::SignalSet;
use crate::policy::SigBlockMask;

/// The syscall adapter classifies the actual operation (including socket
/// timeout state), rather than treating SA_RESTART as a universal restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartClass {
    /// ppoll, pselect, sigsuspend, sleeps, timeout-bearing socket waits, etc.
    Never,
    /// Slow I/O before progress, child waits, restartable futex waits, etc.
    IfSaRestart,
}

/// A successful I/O prefix can never be restarted from zero on interruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferredBytes(NonZeroUsize);

impl TransferredBytes {
    pub const fn new(bytes: usize) -> Option<Self> {
        match NonZeroUsize::new(bytes) {
            Some(bytes) => Some(Self(bytes)),
            None => None,
        }
    }
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitProgress {
    Blocked,
    /// An already committed ready result, not a sampled readiness hint. The
    /// owner resolves readiness-versus-interruption under its wait authority.
    Ready,
    Transferred(TransferredBytes),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitDecision {
    Continue,
    CompleteReady,
    CompletePartial(TransferredBytes),
    Restart,
    Eintr,
}

/// Combine a thread's effective wait block mask with the sighand's current
/// non-interrupting signal set (`SIG_IGN` and default-ignore signals).
pub const fn wait_effective_block_mask(
    blocked: SigBlockMask,
    non_interrupting: SignalSet,
) -> SigBlockMask {
    SigBlockMask::blocking_all_of(blocked.signals().union(non_interrupting))
}

/// Select pending signals that can actually interrupt a blocking wait.
pub const fn select_wait_interrupting(
    pending: SignalSet,
    blocked: SigBlockMask,
    non_interrupting: SignalSet,
) -> SignalSet {
    wait_effective_block_mask(blocked, non_interrupting).select(pending)
}

static NON_INTERRUPTING_LOCK: AtomicBool = AtomicBool::new(false);
static mut NON_INTERRUPTING_BY_TID: Option<BTreeMap<i32, SignalSet>> = None;

fn with_non_interrupting<R>(f: impl FnOnce(&mut BTreeMap<i32, SignalSet>) -> R) -> R {
    while NON_INTERRUPTING_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            NON_INTERRUPTING_LOCK.store(false, Ordering::Release);
        }
    }
    let _guard = Guard;
    // SAFETY: guarded by `NON_INTERRUPTING_LOCK`.
    let map = unsafe {
        let slot = &raw mut NON_INTERRUPTING_BY_TID;
        (*slot).get_or_insert_with(BTreeMap::new)
    };
    f(map)
}

/// Publish the current non-interrupting signal mask for `tid`.
pub fn publish_non_interrupting_for(tid: i32, non_interrupting: SignalSet) {
    if tid <= 0 {
        return;
    }
    with_non_interrupting(|map| {
        if non_interrupting.is_empty() {
            map.remove(&tid);
        } else {
            map.insert(tid, non_interrupting);
        }
    });
}

/// Remove any published non-interrupting signal mask for `tid`.
pub fn clear_non_interrupting_for(tid: i32) {
    if tid <= 0 {
        return;
    }
    with_non_interrupting(|map| {
        map.remove(&tid);
    });
}

/// Clear all published per-tid non-interrupting signal masks.
pub fn clear_all_non_interrupting() {
    with_non_interrupting(BTreeMap::clear);
}

/// Read the published non-interrupting signal mask for `tid`.
pub fn non_interrupting_for(tid: i32) -> SignalSet {
    if tid <= 0 {
        return SignalSet::EMPTY;
    }
    with_non_interrupting(|map| map.get(&tid).copied().unwrap_or(SignalSet::EMPTY))
}

/// `handler_restart` is None for no caught handler (e.g. ignored signal), or
/// the saved original handler's SA_RESTART value from HandlerDelivery. Delivery
/// still occurs when this returns a committed ready/partial success. Restart
/// preserves the owned continuation's cursor/endpoint and happens after the
/// handler; the owner must never replay consumed work.
pub fn interrupted_wait(
    class: RestartClass,
    progress: WaitProgress,
    handler_restart: Option<bool>,
) -> WaitDecision {
    match progress {
        WaitProgress::Ready => WaitDecision::CompleteReady,
        WaitProgress::Transferred(bytes) => WaitDecision::CompletePartial(bytes),
        WaitProgress::Blocked => match handler_restart {
            None => WaitDecision::Continue,
            Some(true) if class == RestartClass::IfSaRestart => WaitDecision::Restart,
            Some(_) => WaitDecision::Eintr,
        },
    }
}
