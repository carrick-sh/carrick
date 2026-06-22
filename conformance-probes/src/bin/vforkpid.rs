//! vfork must not leave the parent's fast-path getpid identity stamped with the
//! child's pid. Go's os/signal TestDetectNohup uses vfork/exec before later
//! kill(getpid(), sig) checks; if the EL1 identity page keeps the child's pid,
//! self-kill returns ESRCH and no handler runs.
//!
//! The vfork is issued through the libc `clone()` WRAPPER (child function +
//! dedicated child stack), exactly like the sibling `vforkvmshare` probe — NOT a
//! raw `syscall(SYS_clone, …, NULL_stack)`. A raw CLONE_VM clone with a NULL
//! stack returns into the PARENT's stack frame, so any code the child runs
//! before `_exit` corrupts the shared frame: undefined behaviour that aarch64
//! tolerated but that SEGV'd real Linux on x86_64 (the Docker oracle core-dumped),
//! making the probe diverge on the x86_64 lane for a reason unrelated to carrick.
//! The wrapper runs the child on its OWN stack, so the SAME source exercises the
//! identical CLONE_VM|CLONE_VFORK shared-RAM window in carrick on every target
//! without invoking UB. The child does nothing but `_exit(0)` — the only thing a
//! vfork child may legally do.
//!
//! Deterministic only: no raw pids or timings.

use conformance_probes::{errno, install_handler, report};
use std::sync::atomic::{AtomicU32, Ordering};

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Runs in the child on its own `child_stack`. Touches nothing and `_exit`s
/// immediately (never returns), so it is safe on the shared-VM vfork path.
extern "C" fn child_fn(_arg: *mut libc::c_void) -> libc::c_int {
    unsafe { libc::_exit(0) }
}

fn main() {
    unsafe {
        let _ = install_handler(libc::SIGUSR1, on_usr1, 0);

        let before = libc::getpid();

        // 64 KiB child stack, 16-byte aligned top (AArch64/x86_64 SP alignment).
        let mut stack = vec![0u8; 1usize << 16];
        let top = (stack.as_mut_ptr().add(stack.len()) as usize & !0xf) as *mut libc::c_void;

        // CLONE_VM => shared address space; CLONE_VFORK => the parent is
        // suspended until the child execve/_exit; SIGCHLD => reapable child.
        let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
        let child = libc::clone(child_fn, top, flags, std::ptr::null_mut());

        let mut status = 0;
        let waited = if child > 0 {
            libc::waitpid(child, &mut status, 0)
        } else {
            -1
        };
        report!(
            vfork_child_created = child > 0,
            vfork_child_reaped = child > 0 && waited == child && libc::WIFEXITED(status),
        );

        let after = libc::getpid();
        report!(getpid_stable_after_vfork = after == before);

        USR1_HITS.store(0, Ordering::SeqCst);
        let rc = libc::kill(after, libc::SIGUSR1);
        let rc_errno = errno();
        report!(
            kill_getpid_after_vfork_rc_zero = rc == 0,
            kill_getpid_after_vfork_not_esrch = rc == 0 || rc_errno != libc::ESRCH,
            kill_getpid_after_vfork_handler_ran = USR1_HITS.load(Ordering::SeqCst) == 1,
        );
    }
}
