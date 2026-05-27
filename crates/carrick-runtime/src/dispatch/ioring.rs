//! io_uring ring engine (WS-H4-B1): the ring-region layout math and the
//! per-SQE completion logic — the correctness-critical core, kept standalone so
//! it can be exhaustively unit-tested before it is wired into the syscall path.
//!
//! Why standalone first: a half-wired io_uring is the one genuinely harmful
//! state — if `io_uring_setup` succeeds but `io_uring_enter` mishandles ops,
//! liburing stops falling back to its (working) epoll path and breaks. So the
//! ring index math and the opcode→CQE mapping are proven here in isolation; the
//! dispatch wiring (`io_uring_setup` allocating the rings in the guest arena,
//! the `mmap(ring_fd, IORING_OFF_*)` integration, and `io_uring_enter` draining
//! the SQ ring) is the atomic step that flips `io_uring_setup` off ENOSYS, and
//! it builds directly on this engine.
//!
//! Phase 1 services NOP/READV/WRITEV/READ/WRITE/FSYNC/CLOSE; every other opcode
//! completes with a CQE `res = -EINVAL`, which is exactly the kernel's response
//! to an unsupported opcode — so even the partial set is non-harmful (apps see
//! a normal CQE error, not a hang).

#![allow(dead_code)] // wired by the io_uring_setup/enter step; see module docs.

use crate::linux_abi::{
    LinuxIoCqringOffsets, LinuxIoSqringOffsets, LinuxIoUringCqe, LinuxIoUringParams,
    LinuxIoUringSqe, LINUX_IORING_FEAT_NODROP, LINUX_IORING_FEAT_SINGLE_MMAP,
    LINUX_IORING_OP_CLOSE, LINUX_IORING_OP_FSYNC, LINUX_IORING_OP_NOP, LINUX_IORING_OP_READ,
    LINUX_IORING_OP_READV, LINUX_IORING_OP_WRITE, LINUX_IORING_OP_WRITEV,
};

const EINVAL: i32 = 22;
const U32: u32 = 4;

/// The byte layout carrick uses for a ring's mmapped regions. The SQ ring and
/// CQ ring share one mapping (IORING_FEAT_SINGLE_MMAP); the SQE array is a
/// second mapping. All offsets are reported to the guest via io_uring_params,
/// so carrick is free to choose them as long as params describes them honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RingLayout {
    pub sq_entries: u32,
    pub cq_entries: u32,
    /// Size of the combined SQ+CQ ring mapping (IORING_OFF_SQ_RING).
    pub ring_bytes: usize,
    /// Size of the SQE-array mapping (IORING_OFF_SQES).
    pub sqes_bytes: usize,
    sq_off: LinuxIoSqringOffsets,
    cq_off: LinuxIoCqringOffsets,
    cqes_offset: u32,
}

impl RingLayout {
    /// Compute the layout for `requested` SQ entries (rounded up to a power of
    /// two, min 1; CQ ring is 2× per the kernel default).
    pub(crate) fn new(requested: u32) -> Self {
        let sq_entries = requested.max(1).next_power_of_two();
        let cq_entries = sq_entries.saturating_mul(2);

        // SQ ring region: 8 u32 control words, then the index `array`
        // (sq_entries u32s). We place the control words first.
        let sq_head = 0;
        let sq_tail = U32;
        let sq_ring_mask = 2 * U32;
        let sq_ring_entries = 3 * U32;
        let sq_flags = 4 * U32;
        let sq_dropped = 5 * U32;
        let sq_array = 8 * U32; // leave 6,7 reserved, 8-align the array
        let sq_array_end = sq_array + sq_entries * U32;

        // CQ ring region follows, in the same mapping. cqes are 16 bytes each.
        let cq_base = align_up_u32(sq_array_end, 64);
        let cq_head = cq_base;
        let cq_tail = cq_base + U32;
        let cq_ring_mask = cq_base + 2 * U32;
        let cq_ring_entries = cq_base + 3 * U32;
        let cq_overflow = cq_base + 4 * U32;
        let cq_flags = cq_base + 5 * U32;
        let cqes_offset = align_up_u32(cq_base + 8 * U32, 64);
        let ring_bytes = (cqes_offset + cq_entries * 16) as usize;
        let sqes_bytes = (sq_entries as usize) * core::mem::size_of::<LinuxIoUringSqe>();

        Self {
            sq_entries,
            cq_entries,
            ring_bytes,
            sqes_bytes,
            sq_off: LinuxIoSqringOffsets {
                head: sq_head,
                tail: sq_tail,
                ring_mask: sq_ring_mask,
                ring_entries: sq_ring_entries,
                flags: sq_flags,
                dropped: sq_dropped,
                array: sq_array,
                resv1: 0,
                resv2: 0,
            },
            cq_off: LinuxIoCqringOffsets {
                head: cq_head,
                tail: cq_tail,
                ring_mask: cq_ring_mask,
                ring_entries: cq_ring_entries,
                overflow: cq_overflow,
                cqes: cqes_offset,
                flags: cq_flags,
                resv1: 0,
                resv2: 0,
            },
            cqes_offset,
        }
    }

    /// Fill the out-param the guest reads after `io_uring_setup`.
    pub(crate) fn fill_params(&self, params: &mut LinuxIoUringParams) {
        params.sq_entries = self.sq_entries;
        params.cq_entries = self.cq_entries;
        params.features = LINUX_IORING_FEAT_SINGLE_MMAP | LINUX_IORING_FEAT_NODROP;
        params.sq_off = self.sq_off;
        params.cq_off = self.cq_off;
    }
}

fn align_up_u32(v: u32, align: u32) -> u32 {
    v.div_ceil(align) * align
}

/// True for the opcodes carrick phase 1 actually executes (the rest complete
/// with -EINVAL). Exposed so the enter path can decide whether to invoke I/O.
pub(crate) fn opcode_serviced(op: u8) -> bool {
    matches!(
        op,
        LINUX_IORING_OP_NOP
            | LINUX_IORING_OP_READV
            | LINUX_IORING_OP_WRITEV
            | LINUX_IORING_OP_READ
            | LINUX_IORING_OP_WRITE
            | LINUX_IORING_OP_FSYNC
            | LINUX_IORING_OP_CLOSE
    )
}

/// Build the completion for one submission. NOP completes with 0; serviced I/O
/// opcodes are run by `io` (which returns bytes transferred or `-errno`); any
/// other opcode completes with `-EINVAL`, matching the kernel's handling of an
/// unsupported opcode. The CQE carries the SQE's `user_data` unchanged.
pub(crate) fn complete_sqe(
    sqe: &LinuxIoUringSqe,
    io: impl FnOnce(&LinuxIoUringSqe) -> i32,
) -> LinuxIoUringCqe {
    let res = match sqe.opcode {
        LINUX_IORING_OP_NOP => 0,
        op if opcode_serviced(op) => io(sqe),
        _ => -EINVAL,
    };
    LinuxIoUringCqe {
        user_data: sqe.user_data,
        res,
        flags: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqe(opcode: u8, user_data: u64) -> LinuxIoUringSqe {
        LinuxIoUringSqe {
            opcode,
            flags: 0,
            ioprio: 0,
            fd: 0,
            off: 0,
            addr: 0,
            len: 0,
            op_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            pad2: [0; 2],
        }
    }

    #[test]
    fn layout_rounds_entries_to_power_of_two_and_sizes_regions() {
        let l = RingLayout::new(3);
        assert_eq!(l.sq_entries, 4); // 3 -> 4
        assert_eq!(l.cq_entries, 8); // 2x
        // SQE array mapping is sq_entries * 64 bytes.
        assert_eq!(l.sqes_bytes, 4 * 64);
        // Copy packed nested-struct fields to locals before asserting (taking a
        // reference to a packed field is UB; PartialEq/Copy avoid it).
        let (sq_head, sq_tail, sq_array) = (l.sq_off.head, l.sq_off.tail, l.sq_off.array);
        let cqes = l.cq_off.cqes;
        // Ring mapping must contain all cqes past the cqes offset.
        assert!(l.ring_bytes >= (cqes + l.cq_entries * 16) as usize);
        // Control-word offsets are distinct and within the mapping.
        assert_eq!(sq_head, 0);
        assert_ne!(sq_tail, sq_head);
        assert!(cqes > sq_array);
    }

    #[test]
    fn params_describe_the_layout() {
        let l = RingLayout::new(8);
        let mut p = LinuxIoUringParams::default();
        l.fill_params(&mut p);
        assert_eq!(p.sq_entries, 8);
        assert_eq!(p.cq_entries, 16);
        assert_eq!(p.features & LINUX_IORING_FEAT_SINGLE_MMAP, LINUX_IORING_FEAT_SINGLE_MMAP);
        assert_eq!(p.sq_off, l.sq_off);
        assert_eq!(p.cq_off, l.cq_off);
    }

    #[test]
    fn nop_completes_with_zero_and_preserves_user_data() {
        let c = complete_sqe(&sqe(LINUX_IORING_OP_NOP, 0xABCD), |_| panic!("NOP must not call io"));
        assert_eq!(c.res, 0);
        assert_eq!(c.user_data, 0xABCD);
    }

    #[test]
    fn unknown_opcode_completes_with_einval_not_io() {
        // 200 is not a real opcode; must NOT invoke io, must CQE -EINVAL.
        let c = complete_sqe(&sqe(200, 0x11), |_| panic!("unknown opcode must not call io"));
        assert_eq!(c.res, -EINVAL);
        assert_eq!(c.user_data, 0x11);
    }

    #[test]
    fn serviced_opcode_runs_io_and_returns_its_result() {
        let c = complete_sqe(&sqe(LINUX_IORING_OP_WRITE, 0x22), |s| {
            assert_eq!(s.opcode, LINUX_IORING_OP_WRITE);
            7 // pretend 7 bytes written
        });
        assert_eq!(c.res, 7);
        assert_eq!(c.user_data, 0x22);
    }
}
