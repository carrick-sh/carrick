//! W^X / NX enforcement for guest mmap memory. On Linux, instruction fetch from
//! a page mapped without PROT_EXEC faults SIGSEGV; a PROT_EXEC page executes.
//! carrick maps all guest user pages EL0-executable (stage-1 UXN=0 uniformly)
//! and never sets UXN from mmap/mprotect prot, so a non-exec page executes —
//! diverging from Linux (no W^X). Each case runs in a forked child and the
//! parent reports the child's exit shape (crash-class probe; deterministic).
//!
//! A page is filled with `ret` (0xd65f03c0) and the data/instruction caches are
//! synced so that on the NO-NX path the fetch reliably executes a `ret` (returns
//! cleanly) rather than faulting on stale icache — making "fetch faulted" mean
//! exactly "NX enforced", not "cache incoherent".

use conformance_probes::report;

const RET: u32 = 0xd65f_03c0; // aarch64 `ret`

unsafe fn fill_ret_and_sync(p: *mut u8, len: usize) {
    let words = len / 4;
    let w = p as *mut u32;
    for i in 0..words {
        w.add(i).write(RET);
    }
    // Only EL0-legal barriers (dsb/isb) — NOT `dc cvau`/`ic ivau`, which require
    // SCTLR_EL1.UCI and would TRAP at EL0 on a host that doesn't enable it,
    // confounding "fetch blocked by NX" with "cache-op trapped". We detect
    // execute permission purely by SIGSEGV-vs-not below, so we don't depend on
    // the `ret` bytes being i-cache-coherent — only on whether the FETCH is
    // permitted. (A fresh never-executed page has no stale i-cache line anyway.)
    core::arch::asm!("dsb ish");
    core::arch::asm!("isb");
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
/// The FETCH was permitted (page is executable) iff the child did NOT take a
/// SIGSEGV. A clean `ret` exits 0; a stale-i-cache fetch might SIGILL — both
/// mean "fetch allowed", distinct from the NX SIGSEGV.
fn fetch_allowed(st: i32) -> bool {
    !sig_segv(st)
}

fn main() {
    unsafe {
        // Case 1: mmap PROT_READ|WRITE (no EXEC) → jump must fault SIGSEGV (NX).
        let rw = child_exec(libc::PROT_READ | libc::PROT_WRITE, None);
        // Case 2: mmap PROT_READ|WRITE|EXEC → jump executes, child exits 0.
        let rwx = child_exec(
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            None,
        );
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

        report!(
            nonexec_mmap_faults = sig_segv(rw),
            exec_mmap_fetch_allowed = fetch_allowed(rwx),
            mprotect_drop_exec_faults = sig_segv(drop_exec),
            mprotect_add_exec_fetch_allowed = fetch_allowed(add_exec),
        );
    }
}
