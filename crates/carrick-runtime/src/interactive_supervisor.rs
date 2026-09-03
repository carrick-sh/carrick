//! Carrier-local interactive PTY session for `carrick run -t`.
//!
//! Linux sessions, process groups, controlling-terminal ownership, and signal
//! routing belong to Carrick's Kernel graph. The host PTY supplies only byte,
//! termios, and window-size transport; no host process topology is created.

use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::dispatch::SyscallDispatcher;
use crate::pty_relay::{PtyPair, PtyRelay};

/// Run-lifetime carrier-local PTY guard. It restores the carrier's original
/// stdio before stopping the relay, including unwinding/error paths.
pub struct InteractiveSession {
    _admission: InteractiveSessionAdmission,
    saved_stdio: [RawFd; 3],
    relay: Option<PtyRelay>,
}

impl std::fmt::Debug for InteractiveSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InteractiveSession")
            .field("saved_stdio", &self.saved_stdio)
            .finish_non_exhaustive()
    }
}

impl InteractiveSession {
    pub fn start(dispatcher: &mut SyscallDispatcher) -> io::Result<Self> {
        let admission = InteractiveSessionAdmission::acquire()?;
        crate::kernel::tty::prepare();
        let mut setup = SessionSetupGuard {
            admission: Some(admission),
            saved_stdio: [-1; 3],
            owned_fds: Vec::new(),
            relay: None,
            committed: false,
        };
        for fd in 0..=2 {
            setup.saved_stdio[fd] = dup_fd(fd as RawFd)?;
        }
        let relay_in = dup_fd(setup.saved_stdio[0])?;
        setup.owned_fds.push(relay_in);
        let relay_out = dup_fd(setup.saved_stdio[1])?;
        setup.owned_fds.push(relay_out);
        let pair = PtyPair::allocate()?;
        let relay = PtyRelay::start_with_pair(pair, relay_in, relay_out)?;
        setup.owned_fds.clear();
        setup.relay = Some(relay);
        let (slave_fd, slave_name) = match setup.relay.as_ref() {
            Some(relay) => (relay.slave_fd(), relay.slave_name().to_owned()),
            None => return Err(io::Error::other("pty relay setup lost ownership")),
        };
        for target in 0..=2 {
            if unsafe { libc::dup2(slave_fd, target) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        dispatcher.set_stdio_sink(crate::dispatch::StdioSink::Inherit);
        dispatcher.register_controlling_pty(slave_name);
        setup.committed = true;
        Ok(Self {
            _admission: setup
                .admission
                .take()
                .unwrap_or_else(|| std::process::abort()),
            saved_stdio: setup.saved_stdio,
            relay: setup.relay.take(),
        })
    }

    fn restore(&mut self) {
        for (target, saved) in self.saved_stdio.iter().copied().enumerate() {
            if saved >= 0 {
                unsafe {
                    libc::dup2(saved, target as RawFd);
                    libc::close(saved);
                }
            }
        }
        self.saved_stdio = [-1; 3];
        if let Some(relay) = self.relay.take() {
            relay.stop();
        }
    }
}

struct SessionSetupGuard {
    admission: Option<InteractiveSessionAdmission>,
    saved_stdio: [RawFd; 3],
    owned_fds: Vec<RawFd>,
    relay: Option<PtyRelay>,
    committed: bool,
}

static INTERACTIVE_SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Process-stdio and SIGWINCH routing are host-process resources, so only one
/// interactive session may own them at a time. Non-interactive containers stay
/// fully concurrent; a second tty request fails before it can clear or replace
/// the live relay route.
#[derive(Debug)]
struct InteractiveSessionAdmission;

impl InteractiveSessionAdmission {
    fn acquire() -> io::Result<Self> {
        INTERACTIVE_SESSION_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| io::Error::from(io::ErrorKind::ResourceBusy))
    }
}

impl Drop for InteractiveSessionAdmission {
    fn drop(&mut self) {
        if !INTERACTIVE_SESSION_ACTIVE.swap(false, Ordering::AcqRel) {
            std::process::abort();
        }
    }
}

impl Drop for SessionSetupGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (target, saved) in self.saved_stdio.iter().copied().enumerate() {
            if saved >= 0 {
                unsafe {
                    libc::dup2(saved, target as RawFd);
                    libc::close(saved);
                }
            }
        }
        for fd in self.owned_fds.drain(..) {
            unsafe { libc::close(fd) };
        }
        if let Some(relay) = self.relay.take() {
            relay.stop();
        }
    }
}

impl Drop for InteractiveSession {
    fn drop(&mut self) {
        self.restore();
    }
}

fn dup_fd(fd: RawFd) -> io::Result<RawFd> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(crate::host_signal::relocate_internal_fd(duplicated))
    }
}

#[cfg(test)]
mod tests {
    use super::InteractiveSessionAdmission;

    #[test]
    fn concurrent_interactive_session_admission_is_rejected_and_reusable() {
        let first = InteractiveSessionAdmission::acquire().expect("first tty session");
        let error = InteractiveSessionAdmission::acquire().expect_err("second tty must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::ResourceBusy);
        drop(first);
        let replacement =
            InteractiveSessionAdmission::acquire().expect("tty admission released on drop");
        drop(replacement);
    }
}
