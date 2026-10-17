//! Interrupted-wait policy from signal(7), "Interruption of system calls":
//! <https://man7.org/linux/man-pages/man7/signal.7.html>.
//! No wait registration, transport, or scheduler here. Numbering is canonical
//! Linux asm-generic, matching [`crate::policy`].

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

/// Socket or fd-wait deadline state known when classifying a syscall wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketWaitTimeout {
    /// No fd-wait continuation outcome is present (e.g. number-only fallback
    /// when no continuation was captured, or a non-fd wait).
    NotSocketWait,
    /// Blocked fd wait with no socket or call deadline (`timeout: None`).
    Untimed,
    /// Blocked fd wait with an active `SO_RCVTIMEO`, `SO_SNDTIMEO`, or call
    /// (`recvmmsg`) deadline.
    Timed,
}

impl SocketWaitTimeout {
    /// Classify a blocked fd wait from its canonical syscall number, arguments,
    /// and whether the dispatcher published an `SO_RCVTIMEO`/`SO_SNDTIMEO`
    /// deadline on the fd wait.
    ///
    /// `recvmmsg` (243) carries an optional per-call `timeout` pointer in
    /// `args[4]` without bounding the first-datagram fd wait; any non-NULL
    /// `timeout` pointer still makes the call a timed socket wait (`signal(7)`).
    pub const fn for_fd_wait(number: u64, args: [u64; 6], has_fd_deadline: bool) -> Self {
        let has_recvmmsg_timeout = number == 243 && args[4] != 0;
        if has_fd_deadline || has_recvmmsg_timeout {
            Self::Timed
        } else {
            Self::Untimed
        }
    }
}

/// Canonical Linux (asm-generic) socket wait syscall numbers whose
/// `SA_RESTART` eligibility requires proving [`SocketWaitTimeout::Untimed`].
pub const fn is_socket_restart_syscall(number: u64) -> bool {
    matches!(
        number,
        202 // accept
        | 242 // accept4
        | 203 // connect
        | 206 // sendto
        | 207 // recvfrom
        | 211 // sendmsg
        | 212 // recvmsg
        | 243 // recvmmsg
        | 269 // sendmmsg
    )
}

/// Canonical Linux (asm-generic) syscalls that must return `EINTR` (never
/// restart under `SA_RESTART`) when interrupted during a timed socket fd wait
/// (`SO_RCVTIMEO`, `SO_SNDTIMEO`, or `recvmmsg` timeout).
pub const fn is_timeout_sensitive_socket_call(number: u64) -> bool {
    // 63..=66 = read, write, readv, writev.
    is_socket_restart_syscall(number) || matches!(number, 63..=66)
}

/// Classify whether a canonical Linux (asm-generic) syscall restarts under
/// `SA_RESTART` (`signal(7)`).
///
/// Dedicated socket calls (`accept`, `accept4`, `connect`, `recvfrom`,
/// `recvmsg`, `recvmmsg`, `sendto`, `sendmsg`, `sendmmsg`) restart only when a
/// blocked fd wait proves [`SocketWaitTimeout::Untimed`]; without that
/// continuation evidence ([`SocketWaitTimeout::NotSocketWait`]) or when a
/// deadline is active ([`SocketWaitTimeout::Timed`]), they return
/// [`RestartClass::Never`]. Stream I/O calls (`read`, `write`, `readv`,
/// `writev`) restart on slow devices unless a blocked fd wait carries
/// [`SocketWaitTimeout::Timed`].
pub const fn classify_syscall_restart(
    number: u64,
    socket_timeout: SocketWaitTimeout,
) -> RestartClass {
    if matches!(socket_timeout, SocketWaitTimeout::Timed)
        && is_timeout_sensitive_socket_call(number)
    {
        return RestartClass::Never;
    }
    if is_socket_restart_syscall(number) {
        return match socket_timeout {
            SocketWaitTimeout::Untimed => RestartClass::IfSaRestart,
            SocketWaitTimeout::NotSocketWait | SocketWaitTimeout::Timed => RestartClass::Never,
        };
    }
    if matches!(
        number,
        // Reads and writes on "slow" devices — pipes, terminals, sockets:
        // 63..=70 = read, write, readv, writev, pread64, pwrite64, preadv, pwritev.
        63..=70
        | 286 // preadv2
        | 287 // pwritev2
        | 29  // ioctl (on a slow device)
        | 56  // openat (blocks opening a FIFO)
        // Advisory file locking: flock, and fcntl's F_SETLKW.
        | 32  // flock
        | 25  // fcntl
        // POSIX message queues.
        | 182 // mq_timedsend
        | 183 // mq_timedreceive
        | 278 // getrandom
        // Waits.
        | 95  // waitid
        | 260 // wait4
    ) {
        RestartClass::IfSaRestart
    } else {
        RestartClass::Never
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_calls_restart_only_when_proven_untimed() {
        for nr in [202, 242, 203, 206, 207, 211, 212, 243, 269] {
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::NotSocketWait),
                RestartClass::Never,
                "socket syscall {nr} must not restart without continuation timeout proof"
            );
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::Timed),
                RestartClass::Never,
                "timed socket syscall {nr} must fail with EINTR"
            );
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::Untimed),
                RestartClass::IfSaRestart,
                "untimed socket syscall {nr} must restart under SA_RESTART"
            );
        }
        for nr in [63, 64, 65, 66] {
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::NotSocketWait),
                RestartClass::IfSaRestart,
            );
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::Untimed),
                RestartClass::IfSaRestart,
            );
            assert_eq!(
                classify_syscall_restart(nr, SocketWaitTimeout::Timed),
                RestartClass::Never,
            );
        }
        assert_eq!(
            SocketWaitTimeout::for_fd_wait(243, [3, 0x1000, 1, 0, 0, 0], false),
            SocketWaitTimeout::Untimed,
        );
        assert_eq!(
            SocketWaitTimeout::for_fd_wait(243, [3, 0x1000, 1, 0, 0x2000, 0], false),
            SocketWaitTimeout::Timed,
        );
    }
}
