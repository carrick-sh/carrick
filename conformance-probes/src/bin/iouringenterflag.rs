//! io_uring_enter must reject unsupported `flags` bits with EINVAL (Linux
//! validates `flags & ~IORING_ENTER_*_MASK` at syscall entry, before touching
//! the SQ ring), and bound SQE processing by `to_submit`. carrick's handler
//! binds `_flags`/`_min_complete`/`_argp`/`_argsz` and discards them, and the
//! enter loop drains `while sq_head != sq_tail` ignoring `to_submit`
//! (dispatch/mem.rs:804-806, dispatch/ioring.rs:337-408). So a bogus flag is
//! silently accepted and a queued NOP still completes — wrong on Linux.
//!
//! Oracle constraint (same as the existing `iouring` probe): the harness runs
//! Docker under its DEFAULT seccomp profile, which BLOCKS io_uring_setup(425)
//! with EPERM. So the Linux oracle never reaches the enter call. Both the
//! seccomp-blocked path AND a correct carrick must therefore print the SAME
//! booleans. We encode that as: "io_uring was unavailable, OR it behaved
//! correctly". Pre-fix carrick reaches enter, accepts the bad flag (rc>=0),
//! and submits the NOP -> `bad_flag_rejected=false` while Docker prints true:
//! a DIFF. Post-fix carrick EINVALs the bad flag and still completes a clean
//! NOP submit -> both true: MATCH. (The existing `iouring` probe is NOT in
//! KNOWN_PROBE_GAPS, which confirms the Docker-blocks-with-EPERM assumption
//! holds in this harness.)
//!
//! Deterministic only: every reported value is a boolean; no addresses/sizes/
//! pids/times. Enter is synchronous (NOP), so no hang risk; we also never
//! block (we submit a NOP, not a socket op). All ring-driving mechanics mirror
//! the proven `iouring` probe (same params[120], same offset reads, same
//! SQES mmap offset 0x1000_0000 == carrick's LINUX_IORING_OFF_SQES).

use std::ptr;

const SYS_IO_URING_SETUP: libc::c_long = 425;
const SYS_IO_URING_ENTER: libc::c_long = 426;
const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_SQES: i64 = 0x1000_0000;
const IORING_OP_NOP: u8 = 0;
const IORING_ENTER_GETEVENTS: u32 = 1;
// A flag bit that is NOT part of any defined IORING_ENTER_* flag. The defined
// set occupies bits 0..=6 (GETEVENTS|SQ_WAKEUP|SQ_WAIT|EXT_ARG|REGISTERED_RING|
// ABS_TIMER|EXT_ARG_REG). Bit 31 is reserved/undefined -> Linux returns EINVAL.
const IORING_ENTER_BOGUS_FLAG: u32 = 1 << 31;

const P_SQ_ENTRIES: usize = 0;
const P_SQ_OFF: usize = 40;
const P_CQ_OFF: usize = 80;

unsafe fn rd32(base: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(base.add(off) as *const u32)
}

fn main() {
    // Each value is `true` either because io_uring is unavailable (Docker
    // seccomp) OR because carrick behaved exactly like Linux would.
    let (rejected, completes) = match unsafe { run() } {
        None => (true, true), // io_uring blocked here — the matching answer
        Some((r, c)) => (r, c),
    };
    println!("bad_flag_rejected={rejected}");
    println!("normal_nop_completes={completes}");
}

/// `None` = io_uring unavailable (setup blocked with EPERM/ENOSYS/EACCES, as
/// under Docker's default seccomp). `Some((bad_flag_rejected, nop_ok))`
/// otherwise: setup/mmap succeeded and we drove two enters.
unsafe fn run() -> Option<(bool, bool)> {
    let mut params = [0u8; 120];
    let fd = libc::syscall(SYS_IO_URING_SETUP, 8u64, params.as_mut_ptr()) as i32;
    if fd < 0 {
        let e = *libc::__errno_location();
        return if e == libc::EPERM || e == libc::ENOSYS || e == libc::EACCES {
            None
        } else {
            // setup failed for an unexpected reason — report a hard mismatch.
            Some((false, false))
        };
    }

    let p = params.as_ptr();
    let sq_entries = rd32(p, P_SQ_ENTRIES);
    let cqes_off = rd32(p, P_CQ_OFF + 20) as usize;
    let ring_sz = cqes_off + (sq_entries as usize) * 2 * 16;

    let ring = libc::mmap(
        ptr::null_mut(),
        ring_sz,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        IORING_OFF_SQ_RING,
    );
    let sqes = libc::mmap(
        ptr::null_mut(),
        (sq_entries as usize) * 64,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        IORING_OFF_SQES,
    );
    if ring == libc::MAP_FAILED || sqes == libc::MAP_FAILED {
        libc::close(fd);
        return Some((false, false));
    }
    let ring = ring as *mut u8;
    let sqes = sqes as *mut u8;

    let sq_tail_off = rd32(p, P_SQ_OFF + 4) as usize;
    let sq_array_off = rd32(p, P_SQ_OFF + 24) as usize;
    let sq_mask = ptr::read_unaligned(ring.add(rd32(p, P_SQ_OFF + 8) as usize) as *const u32);
    let cq_head_off = rd32(p, P_CQ_OFF) as usize;
    let cq_tail_off = rd32(p, P_CQ_OFF + 4) as usize;

    // Helper: queue one NOP into SQE slot derived from `seq` and point the
    // array at it, then advance the SQ tail to `seq + 1`.
    let queue_nop = |seq: u32| {
        let slot = (seq & sq_mask) as usize;
        let sqe = sqes.add(slot * 64);
        ptr::write_bytes(sqe, 0, 64);
        *sqe.add(0) = IORING_OP_NOP;
        ptr::write_unaligned(sqe.add(32) as *mut u64, 0xABCD_u64); // user_data
        ptr::write_unaligned(ring.add(sq_array_off + slot * 4) as *mut u32, slot as u32);
        ptr::write_unaligned(ring.add(sq_tail_off) as *mut u32, seq + 1);
    };

    // (1) Submit one NOP with a BOGUS flag bit. Linux validates flags before
    //     consuming the SQ, so it returns -1/EINVAL and the SQE is NOT consumed
    //     (cq_tail stays put). A correct carrick must do the same.
    queue_nop(0);
    let cq_tail_before = ptr::read_unaligned(ring.add(cq_tail_off) as *const u32);
    let bad = libc::syscall(
        SYS_IO_URING_ENTER,
        fd,
        1u32, // to_submit
        0u32, // min_complete
        IORING_ENTER_GETEVENTS | IORING_ENTER_BOGUS_FLAG,
        ptr::null::<u8>(),
        0usize,
    );
    let bad_errno = *libc::__errno_location();
    let cq_tail_after_bad = ptr::read_unaligned(ring.add(cq_tail_off) as *const u32);
    // Rejected iff enter returned an error with EINVAL AND no completion was
    // posted (the SQE was not silently drained).
    let bad_flag_rejected =
        bad < 0 && bad_errno == libc::EINVAL && cq_tail_after_bad == cq_tail_before;

    // (2) A normal NOP submit (no bogus flag) must still complete: enter
    //     returns >=1 and a CQE with res 0 appears. The SQ tail still points at
    //     the NOP queued in (1) (un-consumed by the rejected enter), so we
    //     simply re-enter with a clean flag set.
    let nop = libc::syscall(
        SYS_IO_URING_ENTER,
        fd,
        1u32,
        1u32,
        IORING_ENTER_GETEVENTS,
        ptr::null::<u8>(),
        0usize,
    );
    let normal_nop_completes = if nop >= 1 {
        let cq_tail = ptr::read_unaligned(ring.add(cq_tail_off) as *const u32);
        let cq_head = ptr::read_unaligned(ring.add(cq_head_off) as *const u32);
        if cq_tail != cq_head {
            // res lives at cqe+8; NOP completes with 0.
            let cq_mask =
                ptr::read_unaligned(ring.add(rd32(p, P_CQ_OFF + 8) as usize) as *const u32);
            let cqe = ring.add(cqes_off + ((cq_head & cq_mask) as usize) * 16);
            ptr::read_unaligned(cqe.add(8) as *const i32) == 0
        } else {
            false
        }
    } else {
        false
    };

    libc::close(fd);
    Some((bad_flag_rejected, normal_nop_completes))
}