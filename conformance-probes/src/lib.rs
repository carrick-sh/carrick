//! Shared probe helpers. Conformance probes have a LOT of identical
//! signal/fd/process boilerplate (install handler, block/unblock a signal,
//! query disposition, fetch errno, fork+pipe a blocked child, …); extracting
//! it here lets each probe stay close to its INVARIANT — the part the diff
//! actually encodes — instead of drowning it in scaffolding. Helpers are
//! pure thin wrappers around libc; they panic on no result for safety, so a
//! buggy probe FAILS LOUD (the wrong thing to do is silently swallow setup
//! errors and print a `false` that looks like a real divergence).
//!
//! Conventions every helper assumes:
//! - probes are aarch64-linux-musl static ELFs run inside a container;
//! - probe output is one `key=value` line per observation (NEVER timing data,
//!   never PIDs, never addresses) so the harness can diff line-for-line;
//! - no allocator surprises around fork/execve — helpers take/return POD.

#![allow(clippy::missing_safety_doc)]

use core::mem::MaybeUninit;
use std::io;

/// Complete, deterministic observation of one boolean probe case executed in
/// a bounded child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedChildResult {
    /// The byte reported by the child, or `None` when it died before reporting.
    pub result: Option<bool>,
    /// Normal exit status, when the child exited normally.
    pub exit: Option<i32>,
    /// Terminating signal, when the child was killed by a signal.
    pub signal: Option<i32>,
    /// Whether the parent enforced the wall-clock timeout with `SIGKILL`.
    pub timed_out: bool,
}

impl std::fmt::Display for BoundedChildResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let result = self
            .result
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_owned());
        let exit = self
            .exit
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned());
        let signal = self
            .signal
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_owned());
        write!(
            f,
            "result={result},exit={exit},signal={signal},timeout={}",
            self.timed_out
        )
    }
}

/// Last `errno`, or `-1` if libc gave us a non-os error.
#[inline]
pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Install a CAUGHT handler (`sa_sigaction = handler as *const () as usize`)
/// for `sig`. `flags` is passed through (`0`, `SA_RESTART`, `SA_ONSTACK`, ...).
/// The signal mask used inside the handler is empty. Returns whether the
/// kernel accepted the install.
pub unsafe fn install_handler(sig: i32, handler: extern "C" fn(i32), flags: i32) -> bool {
    let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    sa.sa_sigaction = handler as *const () as usize;
    sa.sa_flags = flags;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, core::ptr::null_mut()) == 0
}

/// Install `SIG_IGN` for `sig`.
pub unsafe fn install_ign(sig: i32) -> bool {
    let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    sa.sa_sigaction = libc::SIG_IGN;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, core::ptr::null_mut()) == 0
}

/// Install `SIG_DFL` for `sig`.
pub unsafe fn install_dfl(sig: i32) -> bool {
    let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    sa.sa_sigaction = libc::SIG_DFL;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, core::ptr::null_mut()) == 0
}

/// Return the CURRENT disposition of `sig` as the raw `sa_sigaction` value
/// (`SIG_DFL == 0`, `SIG_IGN == 1`, otherwise a handler address). Callers
/// compare against `libc::SIG_DFL` / `libc::SIG_IGN`.
pub unsafe fn current_disposition(sig: i32) -> usize {
    let mut cur: libc::sigaction = MaybeUninit::zeroed().assume_init();
    libc::sigaction(sig, core::ptr::null(), &mut cur);
    cur.sa_sigaction
}

fn singleton_set(sig: i32) -> libc::sigset_t {
    unsafe {
        let mut s: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigemptyset(&mut s);
        libc::sigaddset(&mut s, sig);
        s
    }
}

/// `sigprocmask(SIG_BLOCK, {sig}, NULL)`. Returns whether the call succeeded.
pub unsafe fn block_signal(sig: i32) -> bool {
    let set = singleton_set(sig);
    libc::sigprocmask(libc::SIG_BLOCK, &set, core::ptr::null_mut()) == 0
}

/// `sigprocmask(SIG_UNBLOCK, {sig}, NULL)`.
pub unsafe fn unblock_signal(sig: i32) -> bool {
    let set = singleton_set(sig);
    libc::sigprocmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut()) == 0
}

/// Is `sig` currently blocked in this thread's mask?
pub unsafe fn is_blocked(sig: i32) -> bool {
    let mut cur: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigprocmask(libc::SIG_SETMASK, core::ptr::null(), &mut cur);
    libc::sigismember(&cur, sig) == 1
}

/// Is `sig` currently pending on this thread/process?
pub unsafe fn is_pending(sig: i32) -> bool {
    let mut p: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigpending(&mut p);
    libc::sigismember(&p, sig) == 1
}

/// `setitimer(ITIMER_REAL, {0, ms}, NULL)`. One-shot, no repeat.
pub unsafe fn arm_alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
        it_value: libc::timeval {
            tv_sec: (ms / 1000) as _,
            tv_usec: ((ms % 1000) * 1000) as _,
        },
    };
    libc::setitimer(libc::ITIMER_REAL, &it, core::ptr::null_mut());
}

/// Disarm `ITIMER_REAL`.
pub unsafe fn disarm_alarm() {
    let zero: libc::itimerval = MaybeUninit::zeroed().assume_init();
    libc::setitimer(libc::ITIMER_REAL, &zero, core::ptr::null_mut());
}

/// Create a pipe, returning `(read_fd, write_fd)` or panicking on failure.
/// Probes treat pipe-creation as setup; a failure here indicates a broken
/// runtime, not an ABI divergence.
pub fn pipe2() -> (i32, i32) {
    unsafe {
        let mut fds = [0i32; 2];
        let rc = libc::pipe(fds.as_mut_ptr());
        if rc != 0 {
            panic!("pipe() failed: errno={}", errno());
        }
        (fds[0], fds[1])
    }
}

/// Fork a child that blocks on a 1-byte read of a fresh pipe, then exits 0
/// when released. Returns `(child_pid, release_fd)`; closing or writing one
/// byte to `release_fd` lets the child exit. Used by signal-restart probes
/// to keep a `wait4` GUARANTEED blocked until the parent's handler chooses
/// to release the child.
pub unsafe fn spawn_blocked_child() -> (i32, i32) {
    let (r, w) = pipe2();
    let pid = libc::fork();
    if pid == 0 {
        libc::close(w);
        let mut b = 0u8;
        let _ = libc::read(r, &mut b as *mut u8 as *mut libc::c_void, 1);
        libc::_exit(0);
    }
    libc::close(r);
    (pid, w)
}

/// `waitpid(pid, &status, 0)` retrying through EINTR. Returns the final
/// `(rc, status)` once the child has been reaped (or the wait stops on a
/// non-EINTR error, in which case `rc == -1`).
pub unsafe fn reap(pid: i32) -> (i32, i32) {
    let mut status = 0i32;
    loop {
        let r = libc::wait4(pid, &mut status, 0, core::ptr::null_mut());
        if r == -1 && errno() == libc::EINTR {
            continue;
        }
        return (r, status);
    }
}

/// Run one boolean probe case in a child, killing it after one second if it
/// neither returns nor terminates. The parent always records the child's exact
/// result byte, normal exit status, terminating signal, and timeout state.
///
/// Setup failures panic instead of turning into a plausible conformance value.
pub unsafe fn run_bounded_bool_child<F: FnOnce() -> bool>(f: F) -> BoundedChildResult {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

    let (read_fd, write_fd) = pipe2();
    let pid = libc::fork();
    if pid < 0 {
        let error = errno();
        libc::close(read_fd);
        libc::close(write_fd);
        panic!("fork() failed: errno={error}");
    }
    if pid == 0 {
        libc::close(read_fd);
        let byte = [u8::from(f())];
        loop {
            let written = libc::write(write_fd, byte.as_ptr().cast(), byte.len());
            if written == 1 || errno() != libc::EINTR {
                break;
            }
        }
        libc::close(write_fd);
        libc::_exit(0);
    }

    libc::close(write_fd);
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut poll_fd = libc::pollfd {
        fd: read_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut timed_out = false;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        let remaining_ms = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let poll_result = libc::poll(&mut poll_fd, 1, remaining_ms);
        if poll_result > 0 {
            break;
        }
        if poll_result == 0 {
            timed_out = true;
            break;
        }
        if errno() != libc::EINTR {
            let error = errno();
            libc::kill(pid, libc::SIGKILL);
            let _ = reap(pid);
            libc::close(read_fd);
            panic!("poll() failed while waiting for probe child: errno={error}");
        }
    }

    if timed_out {
        libc::kill(pid, libc::SIGKILL);
    }
    let mut byte = [0u8; 1];
    let read = libc::read(read_fd, byte.as_mut_ptr().cast(), byte.len());
    libc::close(read_fd);
    let (waited, status) = reap(pid);
    if waited != pid {
        panic!(
            "wait4() failed for probe child {pid}: rc={waited} errno={}",
            errno()
        );
    }

    BoundedChildResult {
        result: (read == 1).then_some(byte[0] != 0),
        exit: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
        signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
        timed_out,
    }
}

/// Print one `key=value` boolean line on stdout. The conformance harness
/// reads stdout byte-for-byte and diffs against the Linux oracle, so this
/// is the *single allowed channel* for probe output. Use it instead of
/// hand-rolled `println!`s to keep formatting consistent.
#[macro_export]
macro_rules! report {
    ($($k:tt = $v:expr),+ $(,)?) => {
        $(
            println!("{}={}", stringify!($k), $v);
        )+
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_child_result_formats_every_observation() {
        assert_eq!(
            BoundedChildResult {
                result: Some(true),
                exit: Some(0),
                signal: None,
                timed_out: false,
            }
            .to_string(),
            "result=true,exit=0,signal=none,timeout=false"
        );
        assert_eq!(
            BoundedChildResult {
                result: None,
                exit: None,
                signal: Some(libc::SIGSEGV),
                timed_out: false,
            }
            .to_string(),
            "result=missing,exit=none,signal=11,timeout=false"
        );
    }

    #[test]
    fn bounded_child_reports_success_false_and_signal() {
        let success = unsafe { run_bounded_bool_child(|| true) };
        assert_eq!(success.result, Some(true));
        assert_eq!(success.exit, Some(0));
        assert_eq!(success.signal, None);
        assert!(!success.timed_out);

        let failure = unsafe { run_bounded_bool_child(|| false) };
        assert_eq!(failure.result, Some(false));
        assert_eq!(failure.exit, Some(0));
        assert_eq!(failure.signal, None);
        assert!(!failure.timed_out);

        let signal = unsafe {
            run_bounded_bool_child(|| {
                libc::raise(libc::SIGKILL);
                true
            })
        };
        assert_eq!(signal.result, None);
        assert_eq!(signal.exit, None);
        assert_eq!(signal.signal, Some(libc::SIGKILL));
        assert!(!signal.timed_out);
    }

    #[test]
    fn bounded_child_times_out_and_reaps_never_returning_child() {
        let timeout = unsafe {
            run_bounded_bool_child(|| loop {
                libc::pause();
            })
        };
        assert_eq!(timeout.result, None);
        assert_eq!(timeout.exit, None);
        assert_eq!(timeout.signal, Some(libc::SIGKILL));
        assert!(timeout.timed_out);
    }
}
