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
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
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
