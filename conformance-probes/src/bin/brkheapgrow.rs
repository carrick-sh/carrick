//! brk heap-growth conformance: the program break must be growable far past its
//! initial position, and every page of the grown range must be readable
//! (zero-filled) and writable on FIRST touch. The bhyve/x86 backend eagerly
//! GPA-backed only the first 4 MiB of the 128 MiB heap window (`M2_HEAP_CAP`)
//! and left the tail with neither a window nor a demand-commit reservation, so
//! the first guest store past `LINUX_HEAP_BASE + 4 MiB` took a #PF that
//! `demand_commit` classified as a genuine fault → SIGSEGV. Every non-trivial
//! glibc-malloc workload (any cpython extension import) grows brk past 4 MiB,
//! so this killed the whole cpython lane on bhyve.
//!
//! This probe grows the break by 32 MiB, touches a byte every 64 KiB ascending
//! (verifying zero-fill), writes + verifies a pattern, shrinks back to the
//! initial break, regrows, and touches again. Regrown CONTENT is deliberately
//! not compared (Linux zero-fills a shrink+regrow; carrick keeps the pages
//! backed on every lane — a separate, pre-existing gap): the invariant here is
//! grow/touch/readback, byte-exact and address-free.
//!
//! Raw `SYS_brk` is used directly: musl's `sbrk()` is a stub that fails with
//! ENOMEM for any nonzero increment, and the glibc build's malloc owns the
//! break — so drive the syscall ourselves and emit with heap-free `write(2)`
//! (static strings only) so no allocator traffic interleaves with our brk
//! manipulation.

use std::os::raw::c_void;

const GROW: usize = 32 * 1024 * 1024; // 32 MiB — well past the 4 MiB prefix
const STEP: usize = 64 * 1024; // touch cadence

fn emit(s: &'static str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn line(key: &'static str, ok: bool) {
    emit(key);
    emit(if ok { "=true\n" } else { "=false\n" });
}

/// Raw brk(2): returns the (possibly unchanged) break — NOT the libc -1/0
/// convention. `brk(0)` queries the current break.
fn brk(addr: u64) -> u64 {
    unsafe { libc::syscall(libc::SYS_brk, addr) as u64 }
}

fn main() {
    let initial = brk(0);
    line("brk_initial_nonzero", initial != 0);

    let target = initial + GROW as u64;
    let grown = brk(target);
    line("brk_grow_32mib", grown == target);
    if grown != target {
        unsafe { libc::_exit(1) };
    }

    let base = initial as *mut u8;

    // First touch ascending: every 64 KiB plus the very last byte must read 0.
    // (On the broken backend the READ at initial+4MiB already SIGSEGVs here.)
    let mut zero_ok = true;
    let mut off = 0usize;
    while off < GROW {
        if unsafe { base.add(off).read_volatile() } != 0 {
            zero_ok = false;
        }
        off += STEP;
    }
    if unsafe { base.add(GROW - 1).read_volatile() } != 0 {
        zero_ok = false;
    }
    line("grow_zero_fill", zero_ok);

    // Write a pattern over the same cadence and read it back.
    off = 0;
    while off < GROW {
        unsafe { base.add(off).write_volatile(0xA5) };
        off += STEP;
    }
    unsafe { base.add(GROW - 1).write_volatile(0xA5) };
    let mut rw_ok = true;
    off = 0;
    while off < GROW {
        if unsafe { base.add(off).read_volatile() } != 0xA5 {
            rw_ok = false;
        }
        off += STEP;
    }
    if unsafe { base.add(GROW - 1).read_volatile() } != 0xA5 {
        rw_ok = false;
    }
    line("grow_write_readback", rw_ok);

    // Shrink back to OUR initial break (never below: the allocator's arena is
    // under it), then regrow and prove the range is touchable again.
    let shrunk = brk(initial);
    line("brk_shrink", shrunk == initial);
    let regrown = brk(target);
    line("brk_regrow", regrown == target);

    off = 0;
    while off < GROW {
        unsafe { base.add(off).write_volatile(0x5A) };
        off += STEP;
    }
    let mut re_ok = true;
    off = 0;
    while off < GROW {
        if unsafe { base.add(off).read_volatile() } != 0x5A {
            re_ok = false;
        }
        off += STEP;
    }
    line("regrow_write_readback", re_ok);

    emit("brkheapgrow=done\n");
    unsafe { libc::_exit(0) };
}
