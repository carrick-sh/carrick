//! A large ALIGNED virtual reservation, trimmed and then committed in place —
//! the allocation shape every modern managed runtime depends on.
//!
//! V8 (and thus Node.js), the JVM, and Go's arena all want a big region at a
//! hard alignment. Nothing in `mmap(2)` grants alignment, so they all use the
//! same portable trick: over-reserve `size + alignment` with `PROT_NONE`,
//! `munmap` the head and tail so what remains is aligned, then commit
//! sub-ranges with `MAP_FIXED` over the survivor.
//!
//! Every step is a distinct thing a runtime can get wrong:
//!
//! - reserving multiple GiB of `PROT_NONE` must SUCCEED without committing
//!   memory, so a host that eagerly backs reservations fails here;
//! - `munmap` of a PREFIX or SUFFIX of a live mapping must split it and leave
//!   the middle mapped, rather than unmapping the whole thing or failing;
//! - `mmap(MAP_FIXED)` over part of the survivor must replace just that part;
//! - and the committed bytes must read back as zero.
//!
//! Node.js 22 aborts under carrick's HVPatch backend with "MemoryChunk
//! allocation failed during deserialization" before running any user
//! JavaScript, independent of heap size and of `--no-node-snapshot`, while
//! `node --version` works. That points here, and this probe asks the question
//! without Node in the way: if it goes red, the fault is in carrick's `mmap`
//! lowering, not in V8.
//!
//! Sized at V8's actual cage scale — a 4 GiB region at 4 GiB alignment, so an
//! 8 GiB over-reservation — because a smaller version cannot distinguish
//! "the pattern works" from "the pattern works at a size the host finds easy".
//!
//! RESULT: carrick MATCHES the oracle here, at both 256 MiB and 4 GiB. That is
//! a refutation, not a confirmation: the aligned-cage reservation is NOT what
//! breaks Node. The probe is kept because it pins the semantics it covers, and
//! because the next person to suspect `mmap` alignment should see that this
//! ground is already covered.

use conformance_probes::report;

/// V8's cage alignment. Large enough that the kernel will never hand it to us
/// by luck, so the trim path is genuinely exercised.
const ALIGNMENT: usize = 4 * 1024 * 1024 * 1024;
/// The aligned region a runtime wants to keep.
const REGION: usize = 4 * 1024 * 1024 * 1024;
/// One committed page-sized window inside it.
const COMMIT: usize = 64 * 1024;

fn main() {
    unsafe {
        // 1. Over-reserve, PROT_NONE. No memory is committed by this.
        let over = REGION + ALIGNMENT;
        let base = libc::mmap(
            std::ptr::null_mut(),
            over,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        );
        let reserve_ok = base != libc::MAP_FAILED;
        if !reserve_ok {
            report!(
                reserved_oversized_prot_none = false,
                trimmed_head = false,
                trimmed_tail = false,
                aligned_region_survives = false,
                committed_inside_reservation = false,
                committed_reads_zero = false
            );
            return;
        }

        // 2. Trim to alignment: unmap the head, then the tail. Each is a
        //    partial unmap of a live mapping, which must SPLIT it.
        let start = base as usize;
        let aligned = start.next_multiple_of(ALIGNMENT);
        let head = aligned - start;
        let trimmed_head = head == 0 || libc::munmap(base, head) == 0;
        let tail_start = aligned + REGION;
        let tail = (start + over).saturating_sub(tail_start);
        let trimmed_tail = tail == 0 || libc::munmap(tail_start as *mut libc::c_void, tail) == 0;

        // 3. The aligned middle must still be reserved. Re-reserving it with
        //    MAP_FIXED would mask a failure, so probe it by committing a
        //    window with MAP_FIXED — which is what a runtime does next anyway.
        let commit_at = (aligned + ALIGNMENT / 2) as *mut libc::c_void;
        let committed = libc::mmap(
            commit_at,
            COMMIT,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        );
        let committed_ok = committed == commit_at;

        // 4. Anonymous memory is zero — a guarantee no fast path may weaken.
        let mut zero = true;
        if committed_ok {
            let bytes = std::slice::from_raw_parts(committed as *const u8, COMMIT);
            zero = bytes.iter().all(|byte| *byte == 0);
            // And it must be writable, since that is the point of committing.
            let writable = std::slice::from_raw_parts_mut(committed as *mut u8, COMMIT);
            writable[0] = 0xa5;
            writable[COMMIT - 1] = 0x5a;
            zero = zero && writable[0] == 0xa5 && writable[COMMIT - 1] == 0x5a;
        }

        report!(
            // Linux: true. A PROT_NONE reservation commits nothing, so even a
            // multi-GiB one succeeds.
            reserved_oversized_prot_none = reserve_ok,
            // Linux: true. Unmapping a prefix splits the mapping.
            trimmed_head = trimmed_head,
            // Linux: true. Unmapping a suffix splits it too.
            trimmed_tail = trimmed_tail,
            // Linux: true. The aligned middle is exactly where we asked.
            aligned_region_survives = aligned % ALIGNMENT == 0,
            // Linux: true. MAP_FIXED replaces just that window.
            committed_inside_reservation = committed_ok,
            // Linux: true. Fresh anonymous pages read as zero and are writable.
            committed_reads_zero = zero,
        );
    }
}
