//! io_uring probe (WS-H4-B1). Raw (no liburing): io_uring_setup → mmap the rings
//! → submit ops → io_uring_enter → reap CQEs. Exercises NOP plus the host-file
//! data path (WRITE, READ, READV) end to end.
//!
//! Asserts "io_uring is either correctly UNAVAILABLE here, or it WORKS": prints
//! true if io_uring_setup is refused (EPERM/ENOSYS/EACCES — e.g. Docker's default
//! seccomp blocks the io_uring syscalls) OR every op round-trips correctly. This
//! keeps the cross-host diff deterministic (the harness runs Docker under its
//! default seccomp, where io_uring is blocked → "unavailable" → true) while still
//! catching a carrick regression: carrick permits io_uring, so it takes the
//! round-trip path and must actually complete every op. Verified equal to a real
//! Linux kernel via `docker run --security-opt seccomp=unconfined` (both true).
//!
//! Deterministic only: a single boolean; enter is synchronous so no hang risk.

use std::ptr;

const SYS_IO_URING_SETUP: libc::c_long = 425;
const SYS_IO_URING_ENTER: libc::c_long = 426;
const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_SQES: i64 = 0x1000_0000;
const IORING_OP_NOP: u8 = 0;
const IORING_OP_READV: u8 = 1;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_OP_CLOSE: u8 = 19;
const IORING_OP_SEND: u8 = 26;
const IORING_OP_RECV: u8 = 27;
const IORING_OP_SENDMSG: u8 = 9;
const IORING_OP_RECVMSG: u8 = 10;

#[repr(C)]
struct Iovec {
    base: u64,
    len: u64,
}

#[repr(C)]
struct Msghdr {
    name: u64,
    namelen: u32,
    _p0: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: u32,
    _p1: u32,
}
const IORING_ENTER_GETEVENTS: u32 = 1;

const P_SQ_ENTRIES: usize = 0;
const P_SQ_OFF: usize = 40;
const P_CQ_OFF: usize = 80;

unsafe fn rd32(base: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(base.add(off) as *const u32)
}

/// Minimal SQ/CQ ring driver over the mmapped regions.
struct Ring {
    ring: *mut u8,
    sqes: *mut u8,
    sq_entries: u32,
    sq_tail_off: usize,
    sq_array_off: usize,
    sq_mask: u32,
    cq_head_off: usize,
    cq_tail_off: usize,
    cq_mask: u32,
    cqes_off: usize,
    seq: u32, // submissions so far (drives the SQE slot + ring positions)
    fd: i32,
}

impl Ring {
    /// Submit one SQE (built by `fill`) and reap its CQE `res`. Returns None if
    /// enter failed or no completion appeared.
    unsafe fn submit_reap(&mut self, fill: impl FnOnce(*mut u8)) -> Option<i32> {
        let slot = (self.seq & self.sq_mask) as usize;
        let sqe = self.sqes.add(slot * 64);
        ptr::write_bytes(sqe, 0, 64);
        fill(sqe);
        // array[tail & mask] = slot; advance SQ tail.
        ptr::write_unaligned(
            self.ring.add(self.sq_array_off + ((self.seq & self.sq_mask) as usize) * 4) as *mut u32,
            slot as u32,
        );
        ptr::write_unaligned(self.ring.add(self.sq_tail_off) as *mut u32, self.seq + 1);

        let fd = self.fd;
        let n = libc::syscall(
            SYS_IO_URING_ENTER,
            fd,
            1u32,
            1u32,
            IORING_ENTER_GETEVENTS,
            ptr::null::<u8>(),
            0usize,
        );
        if n < 1 {
            return None;
        }
        // Reap CQE at cq_head.
        let cq_tail = ptr::read_unaligned(self.ring.add(self.cq_tail_off) as *const u32);
        let cq_head = ptr::read_unaligned(self.ring.add(self.cq_head_off) as *const u32);
        if cq_tail == cq_head {
            return None;
        }
        let cqe = self
            .ring
            .add(self.cqes_off + ((cq_head & self.cq_mask) as usize) * 16);
        let res = ptr::read_unaligned(cqe.add(8) as *const i32);
        // Consume it.
        ptr::write_unaligned(self.ring.add(self.cq_head_off) as *mut u32, cq_head + 1);
        self.seq += 1;
        Some(res)
    }
}

fn main() {
    let v = match unsafe { run() } {
        None => true, // io_uring not permitted here — the correct matching answer
        Some(ok) => ok,
    };
    println!("iouring_ok={v}");
}

/// `None` = io_uring unavailable (blocked); `Some(ok)` = it ran, ok iff every op
/// round-tripped.
unsafe fn run() -> Option<bool> {
    let mut params = [0u8; 120];
    let fd = libc::syscall(SYS_IO_URING_SETUP, 8u64, params.as_mut_ptr()) as i32;
    if fd < 0 {
        let e = *libc::__errno_location();
        return if e == libc::EPERM || e == libc::ENOSYS || e == libc::EACCES {
            None
        } else {
            Some(false)
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
        return Some(false);
    }
    let ring = ring as *mut u8;
    let mut r = Ring {
        ring,
        sqes: sqes as *mut u8,
        sq_entries,
        sq_tail_off: rd32(p, P_SQ_OFF + 4) as usize,
        sq_array_off: rd32(p, P_SQ_OFF + 24) as usize,
        sq_mask: ptr::read_unaligned(ring.add(rd32(p, P_SQ_OFF + 8) as usize) as *const u32),
        cq_head_off: rd32(p, P_CQ_OFF) as usize,
        cq_tail_off: rd32(p, P_CQ_OFF + 4) as usize,
        cq_mask: ptr::read_unaligned(ring.add(rd32(p, P_CQ_OFF + 8) as usize) as *const u32),
        cqes_off,
        seq: 0,
        fd,
    };

    let ok = ring_ops(&mut r);
    libc::close(fd);
    Some(ok)
}

unsafe fn ring_ops(r: &mut Ring) -> bool {
    // NOP completes with res 0.
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_NOP;
        ptr::write_unaligned(sqe.add(32) as *mut u64, 0xABCD);
    }) != Some(0)
    {
        return false;
    }

    // Host-file WRITE then READ round-trip. run-elf's rootfs is empty: mkdir /tmp.
    libc::mkdir(c"/tmp".as_ptr(), 0o755);
    let path = c"/tmp/iou_probe";
    let file = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC, 0o644);
    if file < 0 {
        return false;
    }
    let msg = b"io_uring!";
    let wbuf = msg.as_ptr() as u64;
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_WRITE;
        ptr::write_unaligned(sqe.add(4) as *mut i32, file);
        ptr::write_unaligned(sqe.add(16) as *mut u64, wbuf); // addr
        ptr::write_unaligned(sqe.add(24) as *mut u32, msg.len() as u32); // len
    }) != Some(msg.len() as i32)
    {
        return false;
    }

    // READ back into one buffer.
    let mut rbuf = [0u8; 16];
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_READ;
        ptr::write_unaligned(sqe.add(4) as *mut i32, file);
        ptr::write_unaligned(sqe.add(16) as *mut u64, rbuf.as_mut_ptr() as u64);
        ptr::write_unaligned(sqe.add(24) as *mut u32, msg.len() as u32);
    }) != Some(msg.len() as i32)
        || &rbuf[..msg.len()] != msg
    {
        return false;
    }

    // READV: scatter the read across two iovecs.
    let mut a = [0u8; 4];
    let mut b = [0u8; 5];
    let iov = [
        (a.as_mut_ptr() as u64, 4u64),
        (b.as_mut_ptr() as u64, 5u64),
    ];
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_READV;
        ptr::write_unaligned(sqe.add(4) as *mut i32, file);
        ptr::write_unaligned(sqe.add(16) as *mut u64, iov.as_ptr() as u64);
        ptr::write_unaligned(sqe.add(24) as *mut u32, 2); // iovcnt
    }) != Some(msg.len() as i32)
        || &a != b"io_u"
        || &b != b"ring!"
    {
        return false;
    }

    // CLOSE the file via the ring (res 0).
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_CLOSE;
        ptr::write_unaligned(sqe.add(4) as *mut i32, file);
    }) != Some(0)
    {
        return false;
    }

    // Socket SEND/RECV over a socketpair — first the ready path, then a blocking
    // RECV that must park on the kqueue until a forked child writes.
    let mut sv = [0i32; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
        return false;
    }
    let (a, b) = (sv[0], sv[1]);

    let ping = b"ping!";
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_SEND;
        ptr::write_unaligned(sqe.add(4) as *mut i32, a);
        ptr::write_unaligned(sqe.add(16) as *mut u64, ping.as_ptr() as u64);
        ptr::write_unaligned(sqe.add(24) as *mut u32, ping.len() as u32);
    }) != Some(ping.len() as i32)
    {
        return false;
    }
    let mut rb = [0u8; 8];
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_RECV;
        ptr::write_unaligned(sqe.add(4) as *mut i32, b);
        ptr::write_unaligned(sqe.add(16) as *mut u64, rb.as_mut_ptr() as u64);
        ptr::write_unaligned(sqe.add(24) as *mut u32, ping.len() as u32);
    }) != Some(ping.len() as i32)
        || &rb[..ping.len()] != ping
    {
        return false;
    }

    // Blocking RECV: the child writes after a delay; the parent's io_uring RECV
    // has no data yet, so it must park on the socket's readiness (the kqueue/
    // WaitOnFds path) and complete only once the child writes.
    let pid = libc::fork();
    if pid == 0 {
        libc::close(b);
        let ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 80_000_000,
        };
        libc::nanosleep(&ts, ptr::null_mut());
        libc::write(a, b"delayed!".as_ptr() as *const _, 8);
        libc::_exit(0);
    }
    libc::close(a);
    let mut db = [0u8; 8];
    let rv = r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_RECV;
        ptr::write_unaligned(sqe.add(4) as *mut i32, b);
        ptr::write_unaligned(sqe.add(16) as *mut u64, db.as_mut_ptr() as u64);
        ptr::write_unaligned(sqe.add(24) as *mut u32, 8);
    });
    let mut st = 0i32;
    libc::waitpid(pid, &mut st, 0);
    if rv != Some(8) || &db != b"delayed!" {
        return false;
    }

    // SENDMSG / RECVMSG over a fresh socketpair (single iovec each).
    let mut sv2 = [0i32; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv2.as_mut_ptr()) != 0 {
        return false;
    }
    let (c, d) = (sv2[0], sv2[1]);
    let payload = b"msg-hi";
    let siov = Iovec {
        base: payload.as_ptr() as u64,
        len: payload.len() as u64,
    };
    let smsg = msghdr_one(&siov);
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_SENDMSG;
        ptr::write_unaligned(sqe.add(4) as *mut i32, c);
        ptr::write_unaligned(sqe.add(16) as *mut u64, &smsg as *const Msghdr as u64);
    }) != Some(payload.len() as i32)
    {
        return false;
    }
    let mut mb = [0u8; 8];
    let riov = Iovec {
        base: mb.as_mut_ptr() as u64,
        len: mb.len() as u64,
    };
    let rmsg = msghdr_one(&riov);
    if r.submit_reap(|sqe| {
        *sqe.add(0) = IORING_OP_RECVMSG;
        ptr::write_unaligned(sqe.add(4) as *mut i32, d);
        ptr::write_unaligned(sqe.add(16) as *mut u64, &rmsg as *const Msghdr as u64);
    }) != Some(payload.len() as i32)
        || &mb[..payload.len()] != payload
    {
        return false;
    }

    true
}

fn msghdr_one(iov: &Iovec) -> Msghdr {
    Msghdr {
        name: 0,
        namelen: 0,
        _p0: 0,
        iov: iov as *const Iovec as u64,
        iovlen: 1,
        control: 0,
        controllen: 0,
        flags: 0,
        _p1: 0,
    }
}
