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

#![allow(dead_code)] // complete_sqe/opcode_serviced are the unit-tested reference; the
// wired enter path inlines the op match for borrow simplicity.

use super::*;
use crate::linux_abi::{
    LINUX_IORING_ENTER_EXT_ARG, LINUX_IORING_ENTER_FLAGS_MASK, LINUX_IORING_FEAT_NODROP,
    LINUX_IORING_FEAT_SINGLE_MMAP, LINUX_IORING_OFF_CQ_RING, LINUX_IORING_OFF_SQ_RING,
    LINUX_IORING_OFF_SQES, LINUX_IORING_OP_ACCEPT, LINUX_IORING_OP_CLOSE, LINUX_IORING_OP_CONNECT,
    LINUX_IORING_OP_FSYNC, LINUX_IORING_OP_NOP, LINUX_IORING_OP_POLL_ADD, LINUX_IORING_OP_READ,
    LINUX_IORING_OP_READV, LINUX_IORING_OP_RECV, LINUX_IORING_OP_RECVMSG, LINUX_IORING_OP_SEND,
    LINUX_IORING_OP_SENDMSG, LINUX_IORING_OP_WRITE, LINUX_IORING_OP_WRITEV, LinuxIoCqringOffsets,
    LinuxIoSqringOffsets, LinuxIoUringCqe, LinuxIoUringParams, LinuxIoUringSqe, LinuxIovec,
    LinuxMsghdr,
};
use zerocopy::{FromBytes, IntoBytes};

const EINVAL: i32 = 22;
const U32: u32 = 4;
const SUPPORTED_SETUP_FLAGS: u32 = 0;

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

/// A live io_uring instance, tracked in a side table keyed by the ring fd (so
/// no `OpenDescription` variant — and its ~24 match sites — is needed). The SQ/
/// CQ rings and SQE array live in the guest mmap arena at these addresses;
/// carrick reads/writes them coherently, and the guest maps them via
/// `mmap(ring_fd, IORING_OFF_*)` which returns these same addresses.
#[derive(Debug, Clone, Copy)]
pub(in crate::dispatch) struct IoUringState {
    pub layout: RingLayout,
    /// Base of the combined SQ+CQ ring mapping (IORING_OFF_SQ_RING/CQ_RING).
    pub ring_addr: u64,
    /// Base of the SQE-array mapping (IORING_OFF_SQES).
    pub sqes_addr: u64,
}

/// Outcome of attempting an async (readiness-driven) op: it either completed
/// now, or would block and must wait on `host_fd` for `events`.
enum AsyncOutcome {
    Ready(i32),
    Block(i32, i16),
}

/// Opcodes serviced via the kqueue/ThreadWaiter readiness path (SEND/RECV on
/// sockets, POLL_ADD) — they may need to wait, so the enter loop routes them
/// through `try_async_op` rather than the synchronous `io_uring_run_op`.
fn is_async_op(op: u8) -> bool {
    matches!(
        op,
        LINUX_IORING_OP_SEND
            | LINUX_IORING_OP_RECV
            | LINUX_IORING_OP_SENDMSG
            | LINUX_IORING_OP_RECVMSG
            | LINUX_IORING_OP_POLL_ADD
            | LINUX_IORING_OP_ACCEPT
            | LINUX_IORING_OP_CONNECT
    )
}

/// Read the iovec array referenced by a Linux `msghdr` at `addr` (RECVMSG/
/// SENDMSG point their SQE at one). msg_name/msg_control are ignored — carrick
/// services connected-socket message I/O, the common io_uring case.
fn read_msghdr_iovecs(memory: &impl GuestMemory, addr: u64) -> Option<Vec<LinuxIovec>> {
    let bytes = memory
        .read_bytes(addr, core::mem::size_of::<LinuxMsghdr>())
        .ok()?;
    let (mh, _) = LinuxMsghdr::read_from_prefix(&bytes).ok()?;
    let (iov, iovlen) = (mh.iov, mh.iovlen); // copy packed fields to locals
    read_iovecs(memory, iov, iovlen as usize)
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

fn read_ring_u32(memory: &impl GuestMemory, addr: u64) -> u32 {
    memory
        .read_bytes(addr, 4)
        .ok()
        .and_then(|b| <[u8; 4]>::try_from(b.as_slice()).ok())
        .map(u32::from_ne_bytes)
        .unwrap_or(0)
}

fn write_ring_u32(memory: &mut impl GuestMemory, addr: u64, v: u32) {
    let _ = memory.write_bytes(addr, &v.to_ne_bytes());
}

/// Read `count` `iovec`s (16 bytes each) from the guest array at `addr`. `count`
/// is capped at IOV_MAX (1024) so a bogus SQE can't drive an unbounded alloc.
fn read_iovecs(memory: &impl GuestMemory, addr: u64, count: usize) -> Option<Vec<LinuxIovec>> {
    if count > 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let bytes = memory.read_bytes(addr + (i as u64) * 16, 16).ok()?;
        let (iov, _) = LinuxIovec::read_from_prefix(&bytes).ok()?;
        out.push(iov);
    }
    Some(out)
}

impl SyscallDispatcher {
    /// `io_uring_setup(entries, params)`: allocate the SQ/CQ rings and the SQE
    /// array in the guest mmap arena, initialise the control words the guest
    /// reads, fill `params`, install a placeholder fd (so close/stat work), and
    /// record the instance in the side table. Returns the ring fd.
    pub(in crate::dispatch) fn io_uring_setup_impl(
        &self,
        memory: &mut impl GuestMemory,
        entries: u32,
        params_ptr: u64,
    ) -> DispatchOutcome {
        if entries == 0 || entries > 4096 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let Some(user_params) = memory
            .read_bytes(params_ptr, core::mem::size_of::<LinuxIoUringParams>())
            .ok()
            .and_then(|b| {
                LinuxIoUringParams::read_from_prefix(&b)
                    .ok()
                    .map(|(params, _)| params)
            })
        else {
            return DispatchOutcome::errno(LINUX_EFAULT);
        };
        if user_params.flags & !SUPPORTED_SETUP_FLAGS != 0 {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let layout = RingLayout::new(entries);
        let prot = LINUX_PROT_READ | LINUX_PROT_WRITE;
        let (Some((ring_addr, _)), Some((sqes_addr, _))) = (
            self.next_mmap_address(0, layout.ring_bytes as u64, prot, 0),
            self.next_mmap_address(0, layout.sqes_bytes as u64, prot, 0),
        ) else {
            return DispatchOutcome::errno(LINUX_ENOMEM);
        };
        if memory
            .write_bytes(ring_addr, &vec![0u8; layout.ring_bytes])
            .is_err()
            || memory
                .write_bytes(sqes_addr, &vec![0u8; layout.sqes_bytes])
                .is_err()
        {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        // Control words the guest's ring code reads (mask + entry count).
        write_ring_u32(
            memory,
            ring_addr + layout.sq_off.ring_mask as u64,
            layout.sq_entries - 1,
        );
        write_ring_u32(
            memory,
            ring_addr + layout.sq_off.ring_entries as u64,
            layout.sq_entries,
        );
        write_ring_u32(
            memory,
            ring_addr + layout.cq_off.ring_mask as u64,
            layout.cq_entries - 1,
        );
        write_ring_u32(
            memory,
            ring_addr + layout.cq_off.ring_entries as u64,
            layout.cq_entries,
        );

        let mut params = LinuxIoUringParams::default();
        layout.fill_params(&mut params);
        if memory.write_bytes(params_ptr, params.as_bytes()).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }

        let desc = OpenDescription::SyntheticFile {
            base: OpenDescriptionBase::new(0),
            path: "[io_uring]".to_owned(),
            contents: Vec::new(),
            offset: 0,
        };
        let open_file = OpenFile::new(std::sync::Arc::new(parking_lot::RwLock::new(desc)), 0);
        let Ok(fd) = self.install_fd_at_or_above(3, open_file) else {
            return DispatchOutcome::errno(linux_errno::EMFILE);
        };
        self.io.io_uring_instances.write().insert(
            fd,
            IoUringState {
                layout,
                ring_addr,
                sqes_addr,
            },
        );
        DispatchOutcome::Returned { value: fd as i64 }
    }

    /// The guest-arena address a `mmap(ring_fd, off)` should resolve to, or
    /// `None` if `fd` is not an io_uring ring. The ring memory already lives in
    /// the arena, so mmap just hands back its address.
    pub(in crate::dispatch) fn io_uring_mmap_addr(&self, fd: i32, off: u64) -> Option<u64> {
        let table = self.io.io_uring_instances.read();
        let state = table.get(&fd)?;
        match off {
            LINUX_IORING_OFF_SQ_RING | LINUX_IORING_OFF_CQ_RING => Some(state.ring_addr),
            LINUX_IORING_OFF_SQES => Some(state.sqes_addr),
            _ => None,
        }
    }

    /// `io_uring_enter(fd, to_submit, …)`: drain up to `to_submit` SQEs from the
    /// SQ ring, run each, and post a CQE. Synchronous — every completion is
    /// ready by the time enter returns, so `min_complete` is already satisfied.
    pub(in crate::dispatch) fn io_uring_enter_impl(
        &self,
        memory: &mut impl GuestMemory,
        fd: i32,
        to_submit: u32,
        flags: u32,
        argp: u64,
        argsz: u64,
    ) -> DispatchOutcome {
        let Some(state) = self.io.io_uring_instances.read().get(&fd).copied() else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        // Reject any flag bit Linux does not define (before consuming the SQ
        // ring, matching the kernel entry check). carrick services neither the
        // SQPOLL kthread nor the EXT_ARG getevents timeout/sigmask struct, so
        // reject EXT_ARG and any nonzero argp/argsz too, rather than silently
        // ignoring them. (audit M4; probe iouringenterflag)
        if flags & !LINUX_IORING_ENTER_FLAGS_MASK != 0
            || flags & LINUX_IORING_ENTER_EXT_ARG != 0
            || argp != 0
            || argsz != 0
        {
            return DispatchOutcome::errno(LINUX_EINVAL);
        }
        let layout = state.layout;
        let ring = state.ring_addr;
        let sq_mask = layout.sq_entries - 1;
        let cq_mask = layout.cq_entries - 1;

        let sq_tail = read_ring_u32(memory, ring + layout.sq_off.tail as u64);
        let mut sq_head = read_ring_u32(memory, ring + layout.sq_off.head as u64);
        let mut cq_tail = read_ring_u32(memory, ring + layout.cq_off.tail as u64);
        let mut processed: u32 = 0;

        // Process submitted SQEs in order. Synchronous ops (and ready async ops)
        // complete inline; an async op that would block hands off to the runtime's
        // kqueue wait via WaitOnFds WITHOUT advancing sq_head — so the re-dispatch
        // resumes at the same op (all ring state lives in guest memory, which
        // persists across the re-dispatch). carrick assumes `to_submit` matches
        // the number of SQEs the guest queued (the liburing invariant); ops run in
        // submission order (head-of-line), not Linux's out-of-order async.
        while sq_head != sq_tail && processed < to_submit {
            let arr_slot = ring + layout.sq_off.array as u64 + ((sq_head & sq_mask) as u64) * 4;
            let sqe_idx = read_ring_u32(memory, arr_slot);
            let sqe_addr = state.sqes_addr + (sqe_idx as u64) * 64;
            let sqe = memory
                .read_bytes(sqe_addr, core::mem::size_of::<LinuxIoUringSqe>())
                .ok()
                .and_then(|b| LinuxIoUringSqe::read_from_prefix(&b).ok().map(|(s, _)| s));
            let res = match &sqe {
                Some(sqe) if is_async_op(sqe.opcode) => match self.try_async_op(memory, sqe) {
                    AsyncOutcome::Ready(res) => res,
                    AsyncOutcome::Block(host_fd, events) => {
                        // Persist progress and wait on readiness; the runtime
                        // re-dispatches io_uring_enter, which resumes here.
                        write_ring_u32(memory, ring + layout.sq_off.head as u64, sq_head);
                        write_ring_u32(memory, ring + layout.cq_off.tail as u64, cq_tail);
                        return DispatchOutcome::WaitOnFds {
                            fds: vec![(host_fd, events)],
                            timeout: None,
                            on_timeout: 0,
                            block_signals: 0,
                        };
                    }
                },
                Some(sqe) => self.io_uring_run_op(memory, sqe),
                None => -LINUX_EFAULT,
            };
            let cqe = LinuxIoUringCqe {
                user_data: sqe.map(|s| s.user_data).unwrap_or(0),
                res,
                flags: 0,
            };
            let cqe_addr = ring + layout.cq_off.cqes as u64 + ((cq_tail & cq_mask) as u64) * 16;
            let _ = memory.write_bytes(cqe_addr, cqe.as_bytes());
            cq_tail = cq_tail.wrapping_add(1);
            sq_head = sq_head.wrapping_add(1);
            processed = processed.wrapping_add(1);
        }
        // Publish the consumed SQ head and the produced CQ tail back to the guest.
        write_ring_u32(memory, ring + layout.sq_off.head as u64, sq_head);
        write_ring_u32(memory, ring + layout.cq_off.tail as u64, cq_tail);
        // Number of SQEs this call submitted (bounded by to_submit; correct
        // across a WaitOnFds re-dispatch, which recounts only still-pending SQEs).
        DispatchOutcome::Returned {
            value: processed as i64,
        }
    }

    /// Execute one SQE, returning the CQE `res` (bytes transferred or `-errno`).
    /// Phase 1: NOP and host-file READ/WRITE; any other opcode → `-EINVAL`,
    /// matching the kernel's response to an unsupported opcode.
    fn io_uring_run_op(&self, memory: &mut impl GuestMemory, sqe: &LinuxIoUringSqe) -> i32 {
        match sqe.opcode {
            LINUX_IORING_OP_NOP => 0,
            LINUX_IORING_OP_READ => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return -LINUX_EINVAL;
                };
                let len = sqe.len as usize;
                let mut buf = vec![0u8; len];
                let n = unsafe {
                    libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, sqe.off as libc::off_t)
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        if memory.write_bytes(sqe.addr, &buf[..got]).is_err() {
                            return -LINUX_EFAULT;
                        }
                        got as i32
                    }
                    Err(e) => -e,
                }
            }
            LINUX_IORING_OP_WRITE => {
                let Some(hfd) = self.regular_host_file_write_fd(sqe.fd) else {
                    return if self.regular_host_file_fd(sqe.fd).is_some() {
                        -LINUX_EBADF
                    } else {
                        -LINUX_EINVAL
                    };
                };
                let Ok(buf) = memory.read_bytes(sqe.addr, sqe.len as usize) else {
                    return -LINUX_EFAULT;
                };
                let n = unsafe {
                    libc::pwrite(
                        hfd,
                        buf.as_ptr() as *const _,
                        buf.len(),
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => put as i32,
                    Err(e) => -e,
                }
            }
            LINUX_IORING_OP_READV => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return -LINUX_EINVAL;
                };
                let Some(iovs) = read_iovecs(memory, sqe.addr, sqe.len as usize) else {
                    return -LINUX_EFAULT;
                };
                let total: usize = iovs.iter().map(|v| v.iov_len as usize).sum();
                let mut buf = vec![0u8; total];
                let n = unsafe {
                    libc::pread(
                        hfd,
                        buf.as_mut_ptr() as *mut _,
                        total,
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        // Scatter the bytes read across the iovecs in order.
                        let mut done = 0usize;
                        for v in &iovs {
                            if done >= got {
                                break;
                            }
                            let chunk = (v.iov_len as usize).min(got - done);
                            if memory
                                .write_bytes(v.iov_base, &buf[done..done + chunk])
                                .is_err()
                            {
                                return -LINUX_EFAULT;
                            }
                            done += chunk;
                        }
                        got as i32
                    }
                    Err(e) => -e,
                }
            }
            LINUX_IORING_OP_WRITEV => {
                let Some(hfd) = self.regular_host_file_write_fd(sqe.fd) else {
                    return if self.regular_host_file_fd(sqe.fd).is_some() {
                        -LINUX_EBADF
                    } else {
                        -LINUX_EINVAL
                    };
                };
                let Some(iovs) = read_iovecs(memory, sqe.addr, sqe.len as usize) else {
                    return -LINUX_EFAULT;
                };
                // Gather the iovecs into one buffer, then a single pwrite.
                let mut buf = Vec::new();
                for v in &iovs {
                    let Ok(chunk) = memory.read_bytes(v.iov_base, v.iov_len as usize) else {
                        return -LINUX_EFAULT;
                    };
                    buf.extend_from_slice(&chunk);
                }
                let n = unsafe {
                    libc::pwrite(
                        hfd,
                        buf.as_ptr() as *const _,
                        buf.len(),
                        sqe.off as libc::off_t,
                    )
                };
                match n.host_syscall_errno() {
                    Ok(put) => put as i32,
                    Err(e) => -e,
                }
            }
            LINUX_IORING_OP_FSYNC => {
                let Some(hfd) = self.regular_host_file_fd(sqe.fd) else {
                    return -LINUX_EINVAL;
                };
                match unsafe { libc::fsync(hfd) }.host_syscall_errno() {
                    Ok(_) => 0,
                    Err(e) => -e,
                }
            }
            LINUX_IORING_OP_CLOSE => {
                // Same path as close(2): drop the fd from the table and free its
                // host fd / pty entry. Also clear any io_uring side-table entry
                // (closing a ring fd this way).
                let removed = self.io.open_files.write().remove(&sqe.fd);
                match removed {
                    Some(open_file) => {
                        self.close_open_file_and_free_pty(&open_file);
                        // Linux auto-removes a closed fd from every epoll interest set.
                        self.detach_fd_from_epolls(sqe.fd);
                        self.io.io_uring_instances.write().remove(&sqe.fd);
                        0
                    }
                    None => -LINUX_EBADF,
                }
            }
            _ => -LINUX_EINVAL,
        }
    }

    /// Attempt a readiness-driven op without blocking: Ready(res) if it completed
    /// or errored, Block(host_fd, poll_events) if it would block (the enter loop
    /// then hands off to the runtime's kqueue wait). RECV/SEND go through the host
    /// socket; POLL_ADD polls the fd with a zero timeout.
    fn try_async_op(&self, memory: &mut impl GuestMemory, sqe: &LinuxIoUringSqe) -> AsyncOutcome {
        match sqe.opcode {
            LINUX_IORING_OP_RECV => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(-LINUX_EINVAL);
                };
                let len = sqe.len as usize;
                let mut buf = vec![0u8; len];
                let n =
                    unsafe { libc::recv(hfd, buf.as_mut_ptr() as *mut _, len, libc::MSG_DONTWAIT) };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        if memory.write_bytes(sqe.addr, &buf[..got]).is_err() {
                            return AsyncOutcome::Ready(-LINUX_EFAULT);
                        }
                        AsyncOutcome::Ready(got as i32)
                    }
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd, libc::POLLIN),
                    Err(e) => AsyncOutcome::Ready(-e),
                }
            }
            LINUX_IORING_OP_SEND => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(-LINUX_EINVAL);
                };
                let Ok(buf) = memory.read_bytes(sqe.addr, sqe.len as usize) else {
                    return AsyncOutcome::Ready(-LINUX_EFAULT);
                };
                let n = unsafe {
                    libc::send(hfd, buf.as_ptr() as *const _, buf.len(), libc::MSG_DONTWAIT)
                };
                match n.host_syscall_errno() {
                    Ok(put) => AsyncOutcome::Ready(put as i32),
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd, libc::POLLOUT),
                    Err(e) => AsyncOutcome::Ready(-e),
                }
            }
            LINUX_IORING_OP_RECVMSG => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(-LINUX_EINVAL);
                };
                let Some(iovs) = read_msghdr_iovecs(memory, sqe.addr) else {
                    return AsyncOutcome::Ready(-LINUX_EFAULT);
                };
                let total: usize = iovs.iter().map(|v| v.iov_len as usize).sum();
                let mut buf = vec![0u8; total];
                let n = unsafe {
                    libc::recv(hfd, buf.as_mut_ptr() as *mut _, total, libc::MSG_DONTWAIT)
                };
                match n.host_syscall_errno() {
                    Ok(got) => {
                        let got = got as usize;
                        let mut done = 0usize;
                        for v in &iovs {
                            if done >= got {
                                break;
                            }
                            let chunk = (v.iov_len as usize).min(got - done);
                            if memory
                                .write_bytes(v.iov_base, &buf[done..done + chunk])
                                .is_err()
                            {
                                return AsyncOutcome::Ready(-LINUX_EFAULT);
                            }
                            done += chunk;
                        }
                        AsyncOutcome::Ready(got as i32)
                    }
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd, libc::POLLIN),
                    Err(e) => AsyncOutcome::Ready(-e),
                }
            }
            LINUX_IORING_OP_SENDMSG => {
                let Some(hfd) = self.host_socket_fd(sqe.fd) else {
                    return AsyncOutcome::Ready(-LINUX_EINVAL);
                };
                let Some(iovs) = read_msghdr_iovecs(memory, sqe.addr) else {
                    return AsyncOutcome::Ready(-LINUX_EFAULT);
                };
                let mut buf = Vec::new();
                for v in &iovs {
                    let Ok(chunk) = memory.read_bytes(v.iov_base, v.iov_len as usize) else {
                        return AsyncOutcome::Ready(-LINUX_EFAULT);
                    };
                    buf.extend_from_slice(&chunk);
                }
                let n = unsafe {
                    libc::send(hfd, buf.as_ptr() as *const _, buf.len(), libc::MSG_DONTWAIT)
                };
                match n.host_syscall_errno() {
                    Ok(put) => AsyncOutcome::Ready(put as i32),
                    Err(e) if e == LINUX_EAGAIN => AsyncOutcome::Block(hfd, libc::POLLOUT),
                    Err(e) => AsyncOutcome::Ready(-e),
                }
            }
            LINUX_IORING_OP_ACCEPT => {
                // Reuse the accept(2) path: sqe.addr = sockaddr-out, sqe.off =
                // addrlen-out, sqe.op_flags = accept4 flags. It returns the new
                // guest fd (Returned), or signals would-block as WaitOnFds/EAGAIN
                // which we translate to a readiness wait on the listen socket.
                let outcome = self.accept_common(
                    Fd(sqe.fd),
                    GuestPtr(sqe.addr),
                    GuestPtr(sqe.off),
                    memory,
                    sqe.op_flags as i32,
                );
                match outcome {
                    DispatchOutcome::Returned { value } => AsyncOutcome::Ready(value as i32),
                    DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN => {
                        match self.host_socket_fd(sqe.fd) {
                            Some(h) => AsyncOutcome::Block(h, libc::POLLIN),
                            None => AsyncOutcome::Ready(-LINUX_EINVAL),
                        }
                    }
                    DispatchOutcome::Errno { errno } => AsyncOutcome::Ready(-errno),
                    DispatchOutcome::WaitOnFds { fds, .. } => match fds.first() {
                        Some(&(h, e)) => AsyncOutcome::Block(h, e),
                        None => AsyncOutcome::Ready(-LINUX_EAGAIN),
                    },
                    _ => AsyncOutcome::Ready(-LINUX_EINVAL),
                }
            }
            LINUX_IORING_OP_CONNECT => {
                // sqe.addr = sockaddr, sqe.off = addrlen. connect_common waits on
                // POLLOUT while in progress; we map its outcome to the ring.
                match self.connect_common(sqe.fd, sqe.addr, sqe.off as u32, memory) {
                    DispatchOutcome::Returned { value } => AsyncOutcome::Ready(value as i32),
                    DispatchOutcome::Errno { errno } => AsyncOutcome::Ready(-errno),
                    DispatchOutcome::WaitOnFds { fds, .. } => match fds.first() {
                        Some(&(h, e)) => AsyncOutcome::Block(h, e),
                        None => AsyncOutcome::Ready(-LINUX_EINVAL),
                    },
                    _ => AsyncOutcome::Ready(-LINUX_EINVAL),
                }
            }
            LINUX_IORING_OP_POLL_ADD => {
                let Some(hfd) = self
                    .host_socket_fd(sqe.fd)
                    .or_else(|| self.regular_host_file_fd(sqe.fd))
                else {
                    return AsyncOutcome::Ready(-LINUX_EINVAL);
                };
                let want = (sqe.op_flags & 0xFFFF) as i16;
                let mut pfd = libc::pollfd {
                    fd: hfd,
                    events: want,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut pfd, 1, 0) } > 0 {
                    AsyncOutcome::Ready(i32::from(pfd.revents))
                } else {
                    AsyncOutcome::Block(hfd, want)
                }
            }
            _ => AsyncOutcome::Ready(-LINUX_EINVAL),
        }
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
        assert_eq!(
            p.features & LINUX_IORING_FEAT_SINGLE_MMAP,
            LINUX_IORING_FEAT_SINGLE_MMAP
        );
        assert_eq!(p.sq_off, l.sq_off);
        assert_eq!(p.cq_off, l.cq_off);
    }

    #[test]
    fn nop_completes_with_zero_and_preserves_user_data() {
        let c = complete_sqe(&sqe(LINUX_IORING_OP_NOP, 0xABCD), |_| {
            panic!("NOP must not call io")
        });
        assert_eq!(c.res, 0);
        assert_eq!(c.user_data, 0xABCD);
    }

    #[test]
    fn unknown_opcode_completes_with_einval_not_io() {
        // 200 is not a real opcode; must NOT invoke io, must CQE -EINVAL.
        let c = complete_sqe(&sqe(200, 0x11), |_| {
            panic!("unknown opcode must not call io")
        });
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
