//! Bisection probe for the bhyve/x86 large-allocation demand-paging crash.
//!
//! `spliceunixpoll`/`go-net_http` crash inside musl mallocng asserts
//! (`a_crash()` -> `hlt` -> #GP) on large Vec alloc/free churn. This probe
//! reproduces the SAME pattern, single-threaded, with the allocation SIZE (MiB)
//! and iteration COUNT read from env so the threshold can be binary-searched
//! WITHOUT rebuilding:
//!     CARRICK_TEST_SIZE_MB (default 6)   CARRICK_TEST_ITERS (default 8)
//!
//! Heap- and stdio-free signalling (the bug corrupts heap-backed output): a raw
//! `write(2)` of a `.rodata` tag plus the process exit code.
//!   exit 0  + "bigalloc=OK\n"    -> all iterations allocated/verified/freed
//!   exit 60 + "bigalloc=BAD\n"   -> a readback mismatch (silent corruption)
//!   (a musl assert crash is the third outcome: SIGSEGV/139, no tag)

use std::os::raw::c_void;

fn emit(s: &'static str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let size = env_usize("CARRICK_TEST_SIZE_MB", 6) * 1024 * 1024;
    let iters = env_usize("CARRICK_TEST_ITERS", 8);

    for i in 0..iters {
        let tag = 0x11u8.wrapping_add(i as u8);
        let mut v: Vec<u8> = Vec::with_capacity(size);
        v.resize(size, tag); // touch every page -> demand-commit
        // Verify a sampling across pages; the free()/alloc churn that follows is
        // what trips mallocng if a live page was re-zeroed.
        let mut acc: u64 = 0;
        let mut off = 0;
        while off < size {
            acc = acc.wrapping_add(v[off] as u64);
            off += 4096;
        }
        let pages = (size as u64 + 4095) / 4096;
        if acc != (tag as u64).wrapping_mul(pages) {
            emit("bigalloc=BAD\n");
            unsafe { libc::_exit(60) };
        }
        drop(v); // musl free() of the large allocation
    }

    // The big-alloc churn leaves mallocng metadata latently corrupted on bhyve;
    // the assert fires on the NEXT allocation. Exercise the small-alloc path that
    // the old `report!` string hit, to surface it deterministically.
    emit("bigalloc=loop-done\n");
    let mut small: Vec<Vec<u8>> = Vec::new();
    for i in 0..256 {
        let mut s = vec![0u8; 32 + (i % 97)];
        s[0] = i as u8;
        small.push(s);
    }
    let mut sum = 0u64;
    for s in &small {
        sum = sum.wrapping_add(s[0] as u64);
    }
    if sum == 0xDEAD_BEEF {
        emit("bigalloc=never\n"); // unreachable; defeats DCE
    }
    emit("bigalloc=OK\n");
    unsafe { libc::_exit(0) };
}
