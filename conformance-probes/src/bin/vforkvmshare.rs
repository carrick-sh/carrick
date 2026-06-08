//! vfork-style spawn must SHARE the address space (`CLONE_VM`) and SUSPEND the
//! parent (`CLONE_VFORK`) — the exact shape Go `os/exec` and glibc `vfork`/
//! `posix_spawn` use:
//!
//!   clone(child_stack, CLONE_VM | CLONE_VFORK | SIGCHLD)   // + CLONE_PIDFD in Go
//!
//! carrick today mis-routes this to a FULL fork (separate CoW VM, parent NOT
//! suspended) because the flags lack the full `THREAD_MASK`
//! (`VM|FS|FILES|SIGHAND|THREAD`), so dispatch falls through to
//! `DispatchOutcome::Fork`; `CLONE_VFORK` is unmodeled. That mis-modeling is the
//! confirmed root cause of the concurrent-`go build` deadlock: the vfork child
//! runs Go's constrained pre-exec code expecting a shared address space, gets a
//! private copy instead, and busy-spins forever.
//!
//! This pins the defect WITHOUT a flaky/spinning hang: a `CLONE_VM` child stores
//! a sentinel into the (shared) address space, then the `CLONE_VFORK`-suspended
//! parent reads it. Real Linux => shared => visible. carrick today => private
//! copy => not visible. The child `_exit`s immediately, so the probe can never
//! fork-bomb or hang regardless of which path the host takes.
//!
//! Deterministic output: booleans only.
//!
//! GREEN target: honour `CLONE_VM` (child shares the parent address space) +
//! `CLONE_VFORK` (suspend the parent until the child `execve`/`_exit`).

use conformance_probes::report;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A word in the data segment — shared with the child iff `CLONE_VM` is honoured.
static WORD: AtomicUsize = AtomicUsize::new(0);
const SENTINEL: usize = 0x00C0_FFEE;

/// Runs in the child on `child_stack`. Touches nothing but the shared word and
/// then `_exit`s (never returns), so it is safe under both the correct shared-VM
/// path and carrick's current private-copy fork path.
extern "C" fn child_fn(_arg: *mut libc::c_void) -> libc::c_int {
    WORD.store(SENTINEL, Ordering::SeqCst);
    unsafe { libc::_exit(0) }
}

fn main() {
    // 64 KiB child stack, 16-byte aligned top (AArch64 SP alignment).
    let mut stack = vec![0u8; 1usize << 16];
    let top = unsafe { stack.as_mut_ptr().add(stack.len()) } as usize & !0xf;

    // CLONE_VM => shared address space; CLONE_VFORK => parent suspended until the
    // child execve/_exit (so the read below needs no synchronization).
    let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
    let pid = unsafe {
        libc::clone(
            child_fn,
            top as *mut libc::c_void,
            flags,
            std::ptr::null_mut(),
        )
    };

    let returned_child = pid > 0;
    // Under CLONE_VFORK the child has already _exited here; under a wrong
    // (non-suspending) fork this still reads a deterministic value (the private
    // copy the parent never sees the child write to => 0).
    let shared_write_visible = returned_child && WORD.load(Ordering::SeqCst) == SENTINEL;

    if returned_child {
        let mut st = 0;
        unsafe { libc::waitpid(pid, &mut st, 0) };
    }

    report!(
        vfork_clone_returned_child = returned_child,
        clone_vm_shared_write_visible = shared_write_visible,
    );
}
