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
use std::{env, hint};

const CLONE_THREAD: u64 = 0x0001_0000;
const LINUX_SIGCHLD: u64 = 17;

fn env_usize(key: &str) -> usize {
    env::var(key)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn mem_mb_arg_or_env() -> usize {
    std::env::args()
        .nth(1)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| env_usize("FORK_MEM_MB"))
}

fn maps_arg_or_env() -> usize {
    std::env::args()
        .nth(2)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| env_usize("FORK_MAPS"))
}

/// Fragment the guest VA space before the fork: `count` disjoint 64 KiB
/// anonymous mappings, each followed by a 64 KiB munmap hole so neighbors
/// can never coalesce, with every other region dropped to PROT_READ so the
/// host also sees protection boundaries. Touches one byte per 4 KiB page so
/// the kept pages are resident. Returns how many regions were made.
fn fragmented_mappings(count: usize) -> usize {
    const KEEP: usize = 64 * 1024;
    const SPAN: usize = 128 * 1024;
    let mut made = 0usize;
    for i in 0..count {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SPAN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            break;
        }
        let mut off = 0usize;
        while off < KEEP {
            unsafe { *p.cast::<u8>().add(off) = 1 };
            off += 4096;
        }
        unsafe {
            libc::munmap(p.cast::<u8>().add(KEEP).cast(), SPAN - KEEP);
            if i % 2 == 1 {
                libc::mprotect(p, KEEP, libc::PROT_READ);
            }
        }
        made += 1;
    }
    made
}

fn resident_memory(mem_mb: usize) -> Vec<u8> {
    let bytes = mem_mb.saturating_mul(1024 * 1024);
    let mut mem = vec![0u8; bytes];
    let mut i = 0usize;
    while i < mem.len() {
        mem[i] = 1;
        i = i.saturating_add(4096);
    }
    mem
}

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
    let mem_mb = mem_mb_arg_or_env();
    let mem = resident_memory(mem_mb);
    let maps_made = fragmented_mappings(maps_arg_or_env());
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
    if !mem.is_empty() {
        hint::black_box(mem[0]);
    }
    hint::black_box(maps_made);
}
