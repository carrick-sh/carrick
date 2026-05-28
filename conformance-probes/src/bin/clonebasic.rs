//! `clone(2)` basic invariants — gives the LTP `clone01..clone09` family an
//! owning probe (the row that read "(LTP)" in conformance-coverage.md).
//!
//! Scope note: clone's seccomp-sensitive edges (invalid exit_signal,
//! CLONE_FILES fd-table sharing, CLONE_FS fork-style cwd sharing) are
//! deliberately NOT asserted here. Two reasons: (a) they behave non-portably
//! under Docker's default seccomp profile (a clone Linux would reject is
//! silently allowed; an fd-table share is blocked), making them poor
//! differential invariants; (b) fork-style fs/fd sharing across separate
//! processes is an architectural gap carrick maps guest processes onto host
//! processes, and LTP's clone02/clone06 actually exercise the FULL-thread
//! form (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD), which
//! carrick handles correctly via its shared-address-space thread path. The
//! portable arg-validation lives in `clone3args` (modern clone3 ABI). This
//! probe pins the substantive process-semantics every container agrees on:
//!
//!   1. `clone(SIGCHLD)` (bare fork) → positive pid in parent, 0 in child,
//!      child exits cleanly and reaps. (clone01)
//!   2. `clone(CLONE_THREAD | SIGCHLD)` without CLONE_VM|CLONE_SIGHAND →
//!      EINVAL (thread-group threads MUST share VM + handlers; the kernel
//!      rejects it before any seccomp-observable side effect). (clone08
//!      negative shape)
//!
//! CRITICAL probe-safety invariant: a raw `clone` with a NULL child stack and
//! no CLONE_VM gives the child a COW copy of the parent stack, so a child that
//! returns from `raw_clone` re-enters `main`'s control flow. EVERY clone path
//! below therefore `_exit`s the child immediately — including the "expected to
//! fail" case, in case the host unexpectedly succeeds — so the probe can never
//! fork-bomb or duplicate its own output.
//!
//! Deterministic output: booleans only, one line per assertion.

use conformance_probes::{errno, report};

const CLONE_THREAD: u64 = 0x0001_0000;
const LINUX_SIGCHLD: u64 = 17;

/// Raw clone via the aarch64 syscall — the kernel ABI, not glibc's fork
/// wrapper. `clone(flags, child_stack=NULL, ...)`: NULL stack means the child
/// shares the parent's stack VA (COW without CLONE_VM), fork-style.
unsafe fn raw_clone(flags: u64) -> i64 {
    libc::syscall(libc::SYS_clone, flags as i64, 0i64, 0i64, 0i64, 0i64)
}

fn reap(pid: i32) -> bool {
    unsafe {
        let mut status = 0i32;
        let r = libc::waitpid(pid, &mut status, 0);
        r == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }
}

fn main() {
    unsafe {
        // (1) Basic clone(SIGCHLD) — fork equivalent.
        let r = raw_clone(LINUX_SIGCHLD);
        if r == 0 {
            libc::_exit(0);
        }
        report!(
            clone_basic_rc_positive = r > 0,
            clone_basic_child_reaped = r > 0 && reap(r as i32),
        );

        // (2) CLONE_THREAD without CLONE_VM|CLONE_SIGHAND → EINVAL. Guard the
        // child path even though we expect failure: if the host wrongly
        // succeeds, the child must _exit rather than fall through.
        let r = raw_clone(CLONE_THREAD | LINUX_SIGCHLD);
        if r == 0 {
            libc::_exit(0);
        }
        let er = if r < 0 { errno() } else { 0 };
        if r > 0 {
            // Unexpected success — reap so we don't leak the child.
            let _ = reap(r as i32);
        }
        report!(
            clone_thread_alone_rc_neg_one = r == -1,
            clone_thread_alone_errno_einval = er == libc::EINVAL,
        );
    }
}
