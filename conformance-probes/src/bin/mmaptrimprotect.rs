//! `mprotect` on a mapping carrick placed at a HIGH HINT address.
//!
//! This is why Node.js 22 dies before running a line of JavaScript with
//! "Fatal JavaScript out of memory: MemoryChunk allocation failed during
//! deserialization" — on the kernel lane AND on the mature vmm lane.
//!
//! Captured from a live `carrick trace` of `node -e 1`. V8's
//! `MemoryAllocator::AllocateAlignedMemory` over-reserves at a hinted address,
//! trims, then commits with `mprotect`:
//!
//! ```text
//! mmap(0x13828ed00000, 0x7f000, PROT_NONE, PRIVATE|ANON|NORESERVE) -> honoured
//! madvise(aligned, 0x7f000, MADV_DONTFORK)                         -> 0
//! munmap(aligned + 0x40000, 0x3f000)                               -> 0
//! mprotect(aligned, 0x40000, PROT_READ|PROT_WRITE)                 -> -ENOMEM
//! ```
//!
//! Linux returns ENOMEM from `mprotect` only when the range contains addresses
//! that are not mapped. carrick had just placed a mapping there and reported
//! success, so ENOMEM means it does not recognise its own mapping.
//!
//! **What the hint has to do with it.** The trimming is a red herring, and the
//! tree has already been down that road: `mmapcage` walks the same
//! over-reserve-and-trim shape and PASSES, which correctly refuted the aligned
//! cage as the cause. Earlier drafts of THIS probe also passed while they let
//! the kernel choose the address. The discriminator is the HINT: ask for a
//! region far above the arena carrick hands out by default, and the mapping is
//! placed but not tracked. The controls below hold every other variable —
//! trimming, `MAP_NORESERVE`, `MADV_DONTFORK`, geometry — constant, and pass.
//!
//! Every unmap here is CLAMPED to the probe's own reservation. An earlier draft
//! reproduced V8's tail unmap literally, which runs past the end of the
//! mapping; on real Linux the pages just past it belong to the process's own
//! libc, so the probe unmapped its own text and died of SIGSEGV under the
//! oracle. Overshooting is legal and Linux ignores the unmapped remainder —
//! but a probe cannot reproduce it safely without owning the neighbourhood, and
//! it is not what distinguishes carrick here.

use conformance_probes::report;
use std::ffi::c_void;

const MADV_DONTFORK: i32 = 10;
const MAP_NORESERVE: i32 = 0x4000;

/// V8's read-only-page geometry, verbatim from the trace.
const RESERVE: usize = 0x7f000;
const ALIGNMENT: usize = 0x40000;
const COMMIT: usize = 0x40000;

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

/// One full aligned-allocation cycle. Returns the errno `mprotect` failed with,
/// or 0 on success, so carrick and Linux are compared on the same number.
unsafe fn aligned_commit_errno(reserve: usize, alignment: usize, commit: usize) -> i32 {
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            reserve,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            return -1;
        }
        let base_addr = base as usize;
        // V8 hints the kernel it will not need this across fork. Advisory:
        // failure here is not the thing under test, so it is not reported.
        libc::madvise(base, reserve, MADV_DONTFORK);

        let aligned = align_up(base_addr, alignment);
        // Trim the HEAD, if the kernel did not already hand back an aligned
        // base. A prefix unmap must split the mapping, not destroy it.
        if aligned > base_addr {
            libc::munmap(base, aligned - base_addr);
        }
        // Trim the TAIL: everything past the aligned commit window.
        let tail = aligned + commit;
        let end = base_addr + reserve;
        if end > tail {
            libc::munmap(tail as *mut c_void, end - tail);
        }

        // THE STEP UNDER TEST. `aligned .. aligned+commit` is wholly inside the
        // survivor of the two trims, so Linux makes this succeed.
        let rc = libc::mprotect(
            aligned as *mut c_void,
            commit,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        let errno = if rc == 0 {
            0
        } else {
            *libc::__errno_location()
        };
        if rc == 0 {
            // A commit that reports success must actually be writable, and
            // anonymous memory must read back as zero.
            let cell = aligned as *mut u64;
            let observed_zero = cell.read_volatile() == 0;
            cell.write_volatile(0x5eed_1234_5eed_1234);
            let round_trip = cell.read_volatile() == 0x5eed_1234_5eed_1234;
            if !observed_zero || !round_trip {
                return -2;
            }
        }
        libc::munmap(aligned as *mut c_void, commit);
        errno
    }
}

/// The same cycle, but at an explicit high HINT address the way V8 asks for it.
///
/// V8 does not let the kernel choose: it hints, and the trace shows carrick
/// honouring a hint of `0x13828ed00000` (~21 TiB) — far outside the arena
/// carrick hands out by default. Returns a packed result so one report line
/// carries both halves: `1000 + errno` if `mprotect` failed, `-1` if the
/// reservation itself failed, `-3` if carrick placed it somewhere unrelated to
/// the hint (in which case the hint is not what is being tested), else 0.
unsafe fn hinted_high_commit_result(hint: usize) -> i32 {
    unsafe {
        let base = libc::mmap(
            hint as *mut c_void,
            RESERVE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            return -1;
        }
        let base_addr = base as usize;
        // Only meaningful if the hint was actually honoured (same 4 GiB region).
        if base_addr >> 32 != hint >> 32 {
            libc::munmap(base, RESERVE);
            return -3;
        }
        let aligned = align_up(base_addr, ALIGNMENT);
        libc::madvise(aligned as *mut c_void, RESERVE, MADV_DONTFORK);
        libc::munmap((aligned + COMMIT) as *mut c_void, RESERVE - COMMIT);
        let rc = libc::mprotect(
            aligned as *mut c_void,
            COMMIT,
            libc::PROT_READ | libc::PROT_WRITE,
        );
        if rc != 0 {
            return 1000 + *libc::__errno_location();
        }
        let cell = aligned as *mut u64;
        cell.write_volatile(0x5eed_1234_5eed_1234);
        let ok = cell.read_volatile() == 0x5eed_1234_5eed_1234;
        libc::munmap(aligned as *mut c_void, COMMIT);
        if ok { 0 } else { -2 }
    }
}

/// Does a high-hinted mapping actually WORK, even where `mprotect` calls it
/// unmapped? Map it read-write directly — no trimming, no protection change —
/// and round-trip a value through it.
///
/// This separates the two possible faults, which need different fixes:
///   * `0` — the mapping is REAL and only carrick's bookkeeping is missing, so
///     `mprotect` is consulting metadata that was never written;
///   * a SIGSEGV — the address was handed out without being mapped at all.
///
/// Run last, because the second outcome kills the probe.
unsafe fn hinted_high_rw_roundtrip(hint: usize) -> i32 {
    unsafe {
        let base = libc::mmap(
            hint as *mut c_void,
            COMMIT,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            return -1;
        }
        if (base as usize) >> 32 != hint >> 32 {
            libc::munmap(base, COMMIT);
            return -3;
        }
        let cell = base as *mut u64;
        let was_zero = cell.read_volatile() == 0;
        cell.write_volatile(0xfeed_face_feed_face);
        let ok = cell.read_volatile() == 0xfeed_face_feed_face;
        libc::munmap(base, COMMIT);
        if !was_zero {
            -4
        } else if ok {
            0
        } else {
            -2
        }
    }
}

/// `mprotect` a high-hinted mapping that is DEFINITELY live: mapped read-write
/// and proven writable a moment earlier. No trimming, no `PROT_NONE`.
///
/// If even this returns ENOMEM, the fault is not about trimming or about the
/// mapping being absent — carrick's backing probe simply cannot see a high-VA
/// mapping that the guest is demonstrably using.
unsafe fn hinted_high_live_mprotect(hint: usize) -> i32 {
    unsafe {
        let base = libc::mmap(
            hint as *mut c_void,
            COMMIT,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            return -1;
        }
        if (base as usize) >> 32 != hint >> 32 {
            libc::munmap(base, COMMIT);
            return -3;
        }
        // Prove it is live before asking to re-protect it.
        let cell = base as *mut u64;
        cell.write_volatile(0x1234);
        if cell.read_volatile() != 0x1234 {
            libc::munmap(base, COMMIT);
            return -2;
        }
        let rc = libc::mprotect(base, COMMIT, libc::PROT_READ);
        let out = if rc == 0 { 0 } else { *libc::__errno_location() };
        libc::munmap(base, COMMIT);
        out
    }
}

fn main() {
    // The address V8 actually asked for, from the trace.
    report!(hinted_high_result = unsafe { hinted_high_commit_result(0x1382_8ed0_0000) });
    // A second high hint, to show the answer is about the REGION and not that
    // one magic number.
    report!(hinted_high2_result = unsafe { hinted_high_commit_result(0x2000_0000_0000) });


    // The tidied-up geometry, kept because it is the shape most people would
    // write and it must keep working.
    report!(v8_readonly_page_errno = unsafe { aligned_commit_errno(RESERVE, ALIGNMENT, COMMIT) });

    // A tail trim only (the reservation is already aligned-sized), isolating
    // "mprotect after a suffix unmap" from any head-trim interaction.
    report!(
        tail_trim_only_errno = unsafe { aligned_commit_errno(ALIGNMENT * 2, ALIGNMENT, ALIGNMENT) }
    );

    // Larger geometry, to show the answer does not depend on the size fitting
    // in some particular arena bucket.
    report!(
        large_reserve_errno =
            unsafe { aligned_commit_errno(0x40_0000 + 0x1_0000, 0x10_0000, 0x10_0000) }
    );

    // Control: commit a reservation that was NEVER trimmed. If this diverges
    // too, the fault is plain mprotect-on-PROT_NONE and has nothing to do with
    // trimming — which would point the fix somewhere else entirely.
    let untrimmed = unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            COMMIT,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_NORESERVE,
            -1,
            0,
        );
        if base == libc::MAP_FAILED {
            -1
        } else {
            let rc = libc::mprotect(base, COMMIT, libc::PROT_READ | libc::PROT_WRITE);
            let errno = if rc == 0 {
                0
            } else {
                *libc::__errno_location()
            };
            libc::munmap(base, COMMIT);
            errno
        }
    };
    report!(untrimmed_control_errno = untrimmed);

    report!(hinted_high_live_mprotect_errno = unsafe { hinted_high_live_mprotect(0x1382_8ed0_0000) });
    // LAST: this faults if the address was never really mapped.
    report!(hinted_high_rw_roundtrip = unsafe { hinted_high_rw_roundtrip(0x1382_8ed0_0000) });
}
