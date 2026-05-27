//! io_uring NOP probe (WS-H4-B1). Raw (no liburing): io_uring_setup → mmap the
//! rings off the ring fd → submit one IORING_OP_NOP → io_uring_enter → reap the
//! CQE. Proves the full setup/mmap/enter/CQE mechanic end to end.
//!
//! Asserts "io_uring is either correctly UNAVAILABLE here, or it WORKS": the
//! probe prints true if io_uring_setup is refused (EPERM/ENOSYS/EACCES — e.g.
//! Docker's default seccomp profile blocks the io_uring syscalls) OR a NOP
//! round-trips with res=0 and the user_data echoed. This keeps the cross-host
//! diff deterministic (the conformance harness runs Docker under its default
//! seccomp, where io_uring is blocked → "unavailable" → true) while still
//! catching a carrick regression: carrick DOES permit io_uring, so it takes the
//! round-trip path and must actually complete the NOP — a broken ring there
//! prints false and mismatches Docker's true. Verified equal to a real Linux
//! kernel via `docker run --security-opt seccomp=unconfined` (both true).
//!
//! Deterministic only: a single boolean; the enter syscall is synchronous so
//! there is no hang risk.

use std::ptr;

const SYS_IO_URING_SETUP: libc::c_long = 425;
const SYS_IO_URING_ENTER: libc::c_long = 426;
const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_SQES: i64 = 0x1000_0000;
const IORING_OP_NOP: u8 = 0;
const IORING_ENTER_GETEVENTS: u32 = 1;
const NOP_USER_DATA: u64 = 0xCAFE_F00D;

// io_uring_params field byte offsets (see the kernel ABI / carrick-abi).
const P_SQ_ENTRIES: usize = 0;
const P_FEATURES: usize = 20;
const P_SQ_OFF: usize = 40; // io_sqring_offsets (head,tail,ring_mask,ring_entries,flags,dropped,array,…)
const P_CQ_OFF: usize = 80; // io_cqring_offsets (head,tail,ring_mask,ring_entries,overflow,cqes,…)

unsafe fn rd32(base: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(base.add(off) as *const u32)
}

fn main() {
    println!("iouring_ok={}", unsafe { nop_roundtrip_or_unavailable() });
}

unsafe fn nop_roundtrip_or_unavailable() -> bool {
    let mut params = [0u8; 120];
    let fd = libc::syscall(SYS_IO_URING_SETUP, 8u64, params.as_mut_ptr()) as i32;
    if fd < 0 {
        // io_uring not permitted here (e.g. Docker's default seccomp) — the
        // correct, matching answer on a host that blocks it.
        let e = *libc::__errno_location();
        return e == libc::EPERM || e == libc::ENOSYS || e == libc::EACCES;
    }
    let p = params.as_ptr();
    let sq_entries = rd32(p, P_SQ_ENTRIES);
    let _features = rd32(p, P_FEATURES);

    // io_sqring_offsets
    let sq_tail_off = rd32(p, P_SQ_OFF + 4) as usize;
    let sq_ring_mask_off = rd32(p, P_SQ_OFF + 8) as usize;
    let sq_array_off = rd32(p, P_SQ_OFF + 24) as usize;
    // io_cqring_offsets
    let cq_head_off = rd32(p, P_CQ_OFF) as usize;
    let cq_tail_off = rd32(p, P_CQ_OFF + 4) as usize;
    let cq_ring_mask_off = rd32(p, P_CQ_OFF + 8) as usize;
    let cqes_off = rd32(p, P_CQ_OFF + 20) as usize;

    // Single mmap covers both SQ and CQ rings; size it past the cqes array.
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
        return false;
    }
    let ring = ring as *mut u8;
    let sqes = sqes as *mut u8;

    // Fill SQE[0] = NOP with our user_data (opcode @0, user_data @32).
    ptr::write_bytes(sqes, 0, 64);
    *sqes.add(0) = IORING_OP_NOP;
    ptr::write_unaligned(sqes.add(32) as *mut u64, NOP_USER_DATA);

    // Publish: array[0] = 0 (SQE index), then advance the SQ tail to 1.
    let sq_mask = ptr::read_unaligned(ring.add(sq_ring_mask_off) as *const u32);
    ptr::write_unaligned(ring.add(sq_array_off + ((0 & sq_mask) as usize) * 4) as *mut u32, 0);
    ptr::write_unaligned(ring.add(sq_tail_off) as *mut u32, 1);

    let submitted = libc::syscall(SYS_IO_URING_ENTER, fd, 1u32, 1u32, IORING_ENTER_GETEVENTS, ptr::null::<u8>(), 0usize);
    if submitted < 1 {
        libc::close(fd);
        return false;
    }

    // Reap CQE[cq_head]: check res == 0 and user_data echoed.
    let cq_tail = ptr::read_unaligned(ring.add(cq_tail_off) as *const u32);
    if cq_tail < 1 {
        libc::close(fd);
        return false;
    }
    let cq_mask = ptr::read_unaligned(ring.add(cq_ring_mask_off) as *const u32);
    let cq_head = ptr::read_unaligned(ring.add(cq_head_off) as *const u32);
    let cqe = ring.add(cqes_off + ((cq_head & cq_mask) as usize) * 16);
    let user_data = ptr::read_unaligned(cqe as *const u64);
    let res = ptr::read_unaligned(cqe.add(8) as *const i32);
    libc::close(fd);
    user_data == NOP_USER_DATA && res == 0
}
