//! Interrupted-wait policy from signal(7), "Interruption of system calls":
//! <https://man7.org/linux/man-pages/man7/signal.7.html>.
//! No wait registration, transport, syscall-number table or scheduler here.

use core::num::NonZeroUsize;

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
