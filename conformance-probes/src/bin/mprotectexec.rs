//! W^X / NX enforcement for guest mmap memory. On Linux, an instruction fetch
//! from a page mapped without PROT_EXEC faults SIGSEGV; a PROT_EXEC page
//! executes. carrick has historically mapped all guest user pages executable
//! (aarch64: stage-1 UXN=0 uniformly; x86_64: the PTE NX bit not set from mmap
//! prot) so a non-exec page executes — diverging from Linux (no W^X). Each case
//! runs in a forked child and the parent reports the child's exit shape
//! (crash-class probe; deterministic). Portable across aarch64/x86_64 (the page
//! is filled with the arch's one-instruction `ret`).
//!
//! Known x86_64 gap (2026-06-18): `nonexec_mmap_faults` is FALSE on carrick — a
//! fresh non-exec mmap page executes — while `mprotect_drop_exec_faults` is TRUE,
//! i.e. carrick sets the PTE NX bit on the mprotect path but NOT from the initial
//! mmap prot. Linux: all five reported invariants are true.

use conformance_probes::report;

/// Fill the page with the architecture's one-instruction `ret` so a `call` to
/// offset 0 returns cleanly on the EXEC-permitted paths, then make the deposited
/// code fetchable. We detect execute permission purely by SIGSEGV-vs-not below,
/// so the only requirement is that the FETCH (not the bytes' cache coherence) is
/// what gates execution.
#[cfg(target_arch = "aarch64")]
unsafe fn fill_ret_and_sync(p: *mut u8, len: usize) {
    const RET: u32 = 0xd65f_03c0; // aarch64 `ret`
    let w = p as *mut u32;
    for i in 0..len / 4 {
        w.add(i).write(RET);
    }
    // Only EL0-legal barriers (dsb/isb) — NOT `dc cvau`/`ic ivau`, which require
    // SCTLR_EL1.UCI and would TRAP at EL0 on a host that doesn't enable it,
    // confounding "fetch blocked by NX" with "cache-op trapped". A fresh
    // never-executed page has no stale i-cache line anyway.
    core::arch::asm!("dsb ish");
    core::arch::asm!("isb");
}

#[cfg(target_arch = "x86_64")]
unsafe fn fill_ret_and_sync(p: *mut u8, len: usize) {
    // x86-64 `ret` = 0xC3 (single byte): a `call` to offset 0 returns at once.
    // x86 has a coherent unified/instruction cache for a fresh, never-executed
    // page, so no explicit i-cache sync is needed before the first fetch.
    for i in 0..len {
        p.add(i).write(0xC3);
    }
}

/// Run `prot`-mapped, optionally mprotect'd, then jump. Returns the child's
/// wait status. The child exits 0 iff the jump returned (page executed).
unsafe fn child_exec(prot: i32, mprotect_to: Option<i32>) -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        let len = 4096;
        let p = libc::mmap(
            core::ptr::null_mut(),
            len,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            libc::_exit(2);
        }
        // Make it writable to deposit the `ret`, then drop to the target prot.
        // (If prot already lacks WRITE we briefly need it; map RW then mprotect.)
        if prot & libc::PROT_WRITE == 0 {
            libc::_exit(3); // all our cases include WRITE for the deposit
        }
        fill_ret_and_sync(p as *mut u8, len);
        if let Some(mp) = mprotect_to {
            if libc::mprotect(p, len, mp) != 0 {
                libc::_exit(4);
            }
        }
        let f: extern "C" fn() = core::mem::transmute(p);
        f(); // Linux: faults SIGSEGV if the in-force prot lacks EXEC.
        libc::_exit(0); // reached only if the page executed.
    }
    let mut st = 0;
    while libc::wait4(pid, &mut st, 0, core::ptr::null_mut()) < 0 {}
    st
}

fn sig_segv(st: i32) -> bool {
    libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == libc::SIGSEGV
}
/// The fetch path is usable only when the deposited `ret` executes and the
/// child exits cleanly. Setup failures are not evidence that execution was
/// permitted.
fn fetch_allowed(st: i32) -> bool {
    libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
}

fn main() {
    unsafe {
        let report_status = std::env::args().any(|arg| arg == "status");
        // Case 1: mmap PROT_READ|WRITE (no EXEC) → jump must fault SIGSEGV (NX).
        let rw = child_exec(libc::PROT_READ | libc::PROT_WRITE, None);
        // Case 2: mmap PROT_READ|WRITE|EXEC → jump executes, child exits 0.
        let rwx = child_exec(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, None);
        // Case 3: mmap RWX, then mprotect to RW (drop EXEC) → jump faults.
        let drop_exec = child_exec(
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            Some(libc::PROT_READ | libc::PROT_WRITE),
        );
        // Case 4: mmap RW, then mprotect to RWX (add EXEC) → jump executes.
        let add_exec = child_exec(
            libc::PROT_READ | libc::PROT_WRITE,
            Some(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC),
        );
        // Case 5: mmap RW, then mprotect to EXEC-only → jump executes. LTP
        // mprotect04 copies a function into an anonymous page, protects it with
        // PROT_EXEC, then calls it.
        let exec_only = child_exec(libc::PROT_READ | libc::PROT_WRITE, Some(libc::PROT_EXEC));

        report!(
            nonexec_mmap_faults = sig_segv(rw),
            exec_mmap_fetch_allowed = fetch_allowed(rwx),
            mprotect_drop_exec_faults = sig_segv(drop_exec),
            mprotect_add_exec_fetch_allowed = fetch_allowed(add_exec),
            mprotect_exec_only_fetch_allowed = fetch_allowed(exec_only),
        );
        if report_status {
            println!("nonexec_mmap_status={rw}");
            println!("exec_mmap_status={rwx}");
            println!("mprotect_drop_exec_status={drop_exec}");
            println!("mprotect_add_exec_status={add_exec}");
            println!("mprotect_exec_only_status={exec_only}");
        }
    }
}
