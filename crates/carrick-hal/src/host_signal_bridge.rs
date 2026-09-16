//! The host-signal seam between the backend-neutral dispatcher/kernel and the
//! execution backend that owns the host process's signal plumbing.
//!
//! The dispatcher publishes and consumes pending guest signals, mirrors guest
//! dispositions onto the host, enqueues cross-process signals and translates
//! signal numbers. Which host mechanism sits behind each of those — a kqueue
//! pump with per-thread wake pipes on HVF, a self-pipe pump plus a vCPU kick
//! signal on the kick+futex lanes — is the backend's business. Dispatch and the
//! kernel reach it ONLY through [`HostSignalBridge`], so an external backend
//! plugs in its own signal delivery by implementing this trait.
//!
//! Every method keeps the argument and return types of the free function it
//! replaced (`carrick-signal-core` / the HVF `host_signal` module): a bare
//! `i32` signum or tid stays bare here; typing that surface is a follow-up.
//!
//! Two implementations live in this crate:
//!
//! - [`GenericHostSignalBridge`], the shared body for every kick+futex lane
//!   (KVM, bhyve, NVMM, native BSD), generic over the lane's
//!   [`HostSignalGlue`](carrick_signal_core::HostSignalGlue) exactly as the
//!   kick+futex `signal_pump` and `fork_coord` modules are (both cfg'd off
//!   this crate's macOS docs). It replaces the runtime's former inline Linux
//!   `host_signal` module, which was parameterised the same way through an
//!   `ActiveGlue` alias.
//! - `NullHostSignalBridge` (feature `test-support`, so not linkable from a
//!   product docs build), the bridge a dispatcher boots with when no carrier
//!   has handed it one: the SAME generic body over `NullHostSignalGlue`, a
//!   glue with no host plumbing behind it.

use std::marker::PhantomData;
use std::os::fd::RawFd;

use carrick_abi::{SigBlockMask, SigSet};
use carrick_signal_core::HostSignalGlue;

pub use carrick_signal_core::NO_PENDING_SIGNAL;

/// One host fd (plus poll events) a blocking wait parks on. `anchored` marks a
/// descriptor the waiter must NOT pin (dup) because the caller already holds
/// its functional reference for the whole park.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitFd {
    fd: RawFd,
    events: i16,
    anchored: bool,
}

impl WaitFd {
    /// A plain fd the waiter pins for the duration of the park.
    pub fn raw(fd: RawFd, events: i16) -> Self {
        Self {
            fd,
            events,
            anchored: false,
        }
    }

    /// An fd whose functional reference the caller retains across the park, so
    /// the waiter watches it without duplicating it.
    pub fn anchored(fd: RawFd, events: i16) -> Self {
        Self {
            fd,
            events,
            anchored: true,
        }
    }

    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn events(&self) -> i16 {
        self.events
    }

    pub fn is_anchored(&self) -> bool {
        self.anchored
    }
}

/// The backend's host-signal plumbing as the dispatcher and kernel consume it.
///
/// Signum arguments are LINUX signal numbers unless the method name says
/// `host`. Thread ids are the backend's registry keys (`ThreadId::raw()`).
pub trait HostSignalBridge: Send + Sync {
    /// Is a signal deliverable to `tid` pending that `block_mask` does not
    /// block? Covers a thread-directed signal for this tid, a process-directed
    /// signal, and (where the lane has one) an unconsumed cross-process ring
    /// entry. A blocked signal stays pending but must not break a wait.
    fn has_unblocked_pending_for(&self, tid: i32, block_mask: SigBlockMask) -> bool;

    /// Dequeue the lowest pending signum deliverable to `tid`
    /// ([`NO_PENDING_SIGNAL`] if none).
    fn take_pending_for(&self, tid: i32) -> i32;

    /// Dequeue the lowest pending signum for `tid` that is in `wait_set`
    /// ([`NO_PENDING_SIGNAL`] if none) — the `sigwait`/`rt_sigtimedwait` form.
    fn take_pending_in_for(&self, tid: i32, wait_set: SigSet) -> i32;

    /// Publish a thread-directed pending signal for `tid`. The lane wakes the
    /// target's parked wait if it has such a mechanism; the caller manages any
    /// vCPU kick.
    fn publish_pending_for(&self, tid: i32, signum: i32);

    /// Publish a process-directed pending signal (any unblocked thread may
    /// deliver it) and wake parked waiters where the lane can.
    fn publish_process_signal(&self, signum: i32);

    /// The host pid recorded as the sender of the most recent `signum`
    /// (`0` when unknown), for `si_pid` on delivery.
    fn last_sender_for(&self, signum: i32) -> i32;

    /// Self-directed `kill(getpid(), signum)` for an unblocked signal: publish
    /// it so the calling thread's own loop delivers it at the next pending
    /// check, with the sender recorded as this process.
    fn raise_for_self(&self, signum: i32);

    /// Wake every parked private waiter so it re-samples its wait sources.
    fn wake_all_waiters(&self);

    /// Mirror a guest-installed handler for `linux_signum` onto a routed HOST
    /// handler (idempotent; no-op for signals the lane must keep for itself).
    fn ensure_host_handler(&self, linux_signum: i32);

    /// Mirror a guest `SIG_IGN` onto the host disposition.
    fn set_host_ignore(&self, linux_signum: i32);

    /// Reset the mirrored host disposition of `linux_signum` to `SIG_DFL`.
    fn set_host_default(&self, linux_signum: i32);

    /// Guest `execve`: reset every routed host disposition to default except
    /// the signals the new image keeps ignored.
    fn reset_routed_handlers_after_execve(&self, ignored: SigSet);

    /// Enqueue a cross-process guest signal into the shared xsignal ring.
    /// `false` when there is no ring or it is full. `target_ns_tid` is `0` for
    /// a process-directed send, or the target's guest tid for a thread-directed
    /// one.
    #[allow(clippy::too_many_arguments)]
    fn xsig_enqueue(
        &self,
        target_host_pid: i32,
        signum: i32,
        code: i32,
        sender_ns_pid: i32,
        sender_uid: u32,
        value: i64,
        target_ns_tid: i32,
    ) -> bool;

    /// Nudge the target to drain its xsignal ring.
    fn xsig_nudge(&self, target_host_pid: i32);

    /// Drain every xsignal-ring entry targeting THIS process as
    /// `(signum, code, sender_ns_pid, sender_uid, value, target_ns_tid)`.
    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, i32, u32, i64, i32)>;

    /// Translate a host kernel signal number to its Linux (guest) number.
    fn host_to_linux_signum(&self, host_signum: i32) -> i32;

    /// Translate a Linux (guest) signal number to the host kernel's number.
    fn linux_to_host_signum(&self, linux_signum: i32) -> i32;
}

impl std::fmt::Debug for dyn HostSignalBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostSignalBridge")
    }
}

/// The shared [`HostSignalBridge`] of every kick+futex lane, generic over the
/// lane's [`HostSignalGlue`] (KVM identity numbering; the BSD lanes' signum
/// tables). The pending bookkeeping is the neutral `carrick-signal-core`
/// store; the host-disposition mirror, the xsignal nudge and the signum
/// translation go through `carrick_signal_core::host_glue::<G>`.
///
/// There is no per-thread waiter registry on these lanes (the waiter is a
/// stateless `ppoll` woken by the kick's `EINTR`), so `wake_all_waiters` is a
/// no-op and publication never carries a wake of its own — the caller's kick
/// closes the lost-wakeup window.
pub struct GenericHostSignalBridge<G: HostSignalGlue>(PhantomData<fn() -> G>);

impl<G: HostSignalGlue> GenericHostSignalBridge<G> {
    /// The bridge over glue `G`; `const` so a lane can hold one in a `static`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<G: HostSignalGlue> Default for GenericHostSignalBridge<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: HostSignalGlue> std::fmt::Debug for GenericHostSignalBridge<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GenericHostSignalBridge")
    }
}

impl<G: HostSignalGlue> HostSignalBridge for GenericHostSignalBridge<G> {
    fn has_unblocked_pending_for(&self, tid: i32, block_mask: SigBlockMask) -> bool {
        // A cross-process guest signal may be sitting in the shared xsignal
        // ring: peek it WITHOUT consuming so a temporary ppoll/epoll_pwait mask
        // keeps genuinely blocked signals pending until the syscall returns.
        if carrick_signal_core::xsig::xsig_has_unblocked_for_self(block_mask) {
            return true;
        }
        carrick_signal_core::has_unblocked_pending_for(tid, block_mask)
    }

    fn take_pending_for(&self, tid: i32) -> i32 {
        carrick_signal_core::take_pending_for(tid)
    }

    fn take_pending_in_for(&self, tid: i32, wait_set: SigSet) -> i32 {
        carrick_signal_core::take_pending_in_for(tid, wait_set)
    }

    fn publish_pending_for(&self, tid: i32, signum: i32) {
        carrick_signal_core::publish_pending_for(tid, signum);
    }

    fn publish_process_signal(&self, signum: i32) {
        carrick_signal_core::publish_process_signal(signum);
    }

    fn last_sender_for(&self, signum: i32) -> i32 {
        carrick_signal_core::last_sender_for(signum)
    }

    fn raise_for_self(&self, signum: i32) {
        // No host pump: the same-thread syscall return re-checks pending.
        carrick_signal_core::publish_process_signal(signum);
    }

    fn wake_all_waiters(&self) {}

    fn ensure_host_handler(&self, linux_signum: i32) {
        carrick_signal_core::host_glue::ensure_host_handler::<G>(linux_signum);
    }

    fn set_host_ignore(&self, linux_signum: i32) {
        carrick_signal_core::host_glue::set_host_ignore::<G>(linux_signum);
    }

    fn set_host_default(&self, linux_signum: i32) {
        carrick_signal_core::host_glue::set_host_default::<G>(linux_signum);
    }

    fn reset_routed_handlers_after_execve(&self, ignored: SigSet) {
        carrick_signal_core::host_glue::reset_routed_handlers_after_execve::<G>(ignored);
    }

    fn xsig_enqueue(
        &self,
        target_host_pid: i32,
        signum: i32,
        code: i32,
        sender_ns_pid: i32,
        sender_uid: u32,
        value: i64,
        target_ns_tid: i32,
    ) -> bool {
        carrick_signal_core::xsig::xsig_enqueue(
            target_host_pid,
            signum,
            code,
            sender_ns_pid,
            sender_uid,
            value,
            target_ns_tid,
        )
    }

    fn xsig_nudge(&self, target_host_pid: i32) {
        carrick_signal_core::host_glue::xsig_nudge::<G>(target_host_pid);
    }

    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, i32, u32, i64, i32)> {
        carrick_signal_core::xsig::xsig_drain_for_self()
    }

    fn host_to_linux_signum(&self, host_signum: i32) -> i32 {
        carrick_signal_core::host_glue::glue_host_to_linux::<G>(host_signum)
    }

    fn linux_to_host_signum(&self, linux_signum: i32) -> i32 {
        carrick_signal_core::host_glue::glue_linux_to_host::<G>(linux_signum)
    }
}

/// The [`HostSignalGlue`] of a lane with NO host signal plumbing behind it:
/// signal numbers translate as identity, every disposition mirror is skipped
/// (the host's real dispositions are not this lane's to touch), the pump poke
/// is a no-op and no kick or nudge signal exists (`0`; nothing ever installs
/// them). [`GenericHostSignalBridge`] over this glue is
/// [`NullHostSignalBridge`], the bridge a dispatcher boots with when no
/// carrier has handed it one (`SyscallDispatcher::new()`, the example
/// backend). It is one instantiation of the shared body, not a second
/// implementation: the neutral `carrick-signal-core` pending store and xsignal
/// ring it reads and writes are kernel (compat-zone) state — which is why a
/// test that publishes a signal and expects the dispatcher to see it still
/// exercises the kernel — while nothing behind them happens: no host
/// disposition is mirrored, no waiter is woken, no sibling is nudged.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct NullHostSignalGlue;

#[cfg(any(test, feature = "test-support"))]
impl HostSignalGlue for NullHostSignalGlue {
    /// No kick mechanism: nothing installs or sends it.
    fn kick_signal() -> i32 {
        0
    }

    /// No nudge mechanism either (the default would derive `kick + 1`).
    fn nudge_signum() -> i32 {
        0
    }

    fn host_to_linux(host_signum: i32) -> i32 {
        host_signum
    }

    fn linux_to_host(linux_signum: i32) -> i32 {
        linux_signum
    }

    /// Every signal stays the host's own: the mirror never installs, ignores
    /// or resets a host disposition on this lane.
    fn is_claimed(_linux_signum: i32) -> bool {
        true
    }

    fn skip_install_routing(_linux_signum: i32) -> bool {
        true
    }

    fn skip_ignore_mirror(_linux_signum: i32) -> bool {
        true
    }

    fn skip_execve_reset(_linux_signum: i32) -> bool {
        true
    }

    fn poke() {}

    fn install_kick_handler() {}
}

/// The bridge a dispatcher boots with when no carrier has handed it one: the
/// shared [`GenericHostSignalBridge`] body over [`NullHostSignalGlue`].
#[cfg(any(test, feature = "test-support"))]
pub type NullHostSignalBridge = GenericHostSignalBridge<NullHostSignalGlue>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_fd_keeps_anchoring_distinct_from_raw() {
        let raw = WaitFd::raw(7, libc::POLLIN);
        let anchored = WaitFd::anchored(7, libc::POLLIN);
        assert_eq!(raw.fd(), 7);
        assert_eq!(raw.events(), libc::POLLIN);
        assert!(!raw.is_anchored());
        assert!(anchored.is_anchored());
        assert_ne!(raw, anchored);
    }

    #[test]
    fn null_bridge_is_identity_on_signum_translation_and_inert_on_host_glue() {
        let bridge = NullHostSignalBridge::default();
        assert_eq!(bridge.linux_to_host_signum(10), 10);
        assert_eq!(bridge.host_to_linux_signum(31), 31);
        // The host-glue methods are no-ops; they must not touch the process's
        // real dispositions, so calling them for every signal is safe here.
        // The shared install mask is the observable: a mirrored route marks
        // it, and the Null glue must never mark it.
        for signum in 1..=64 {
            carrick_signal_core::host_disposition::clear_installed(signum);
            bridge.ensure_host_handler(signum);
            assert!(
                !carrick_signal_core::host_disposition::is_installed(signum),
                "signal {signum} must not be routed onto the host by the Null glue"
            );
            bridge.set_host_ignore(signum);
            bridge.set_host_default(signum);
        }
        bridge.reset_routed_handlers_after_execve(SigSet::EMPTY);
        bridge.wake_all_waiters();
        bridge.xsig_nudge(0);
        assert_eq!(NullHostSignalGlue::kick_signal(), 0);
        assert_eq!(NullHostSignalGlue::nudge_signum(), 0);
    }
}
