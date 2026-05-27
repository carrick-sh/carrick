//! Transparent-huge-page madvise-hint probe (WS-G2). Real Linux treats
//! MADV_HUGEPAGE / MADV_NOHUGEPAGE as advisory and returns 0 whenever THP is
//! built in (Docker's arm64 kernel reports `[always]`), regardless of whether a
//! huge page is actually used. carrick presents 4 KiB guest pages and never
//! promotes to a huge page, but it must still accept the hint with success —
//! returning EINVAL makes allocators (Go runtime, jemalloc, glibc) treat a
//! benign hint as a hard error. The harness diffs this byte-for-byte vs Docker.
//!
//! Deterministic only: booleans. MADV_COLLAPSE and MAP_HUGETLB are intentionally
//! NOT asserted — their real-Linux result depends on reserved-hugepage state and
//! would be a false cross-machine DIFF.

const MADV_HUGEPAGE: i32 = 14;
const MADV_NOHUGEPAGE: i32 = 15;

fn main() {
    // A 2 MiB anonymous region — the natural THP candidate size, page-aligned.
    let len = 2 * 1024 * 1024;
    let hint_ok = unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            (false, false)
        } else {
            let hp = libc::madvise(p, len, MADV_HUGEPAGE);
            let nohp = libc::madvise(p, len, MADV_NOHUGEPAGE);
            libc::munmap(p, len);
            (hp == 0, nohp == 0)
        }
    };
    println!("madv_hugepage_ok={}", hint_ok.0);
    println!("madv_nohugepage_ok={}", hint_ok.1);
}
