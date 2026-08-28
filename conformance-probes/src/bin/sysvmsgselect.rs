//! SysV message queue msgrcv(2) selection and truncation semantics probe.
//!
//! Covers:
//!   1. `IPC_NOWAIT` on empty queue returns `ENOMSG`.
//!   2. `msgtyp == 0` selects queue head in FIFO order.
//!   3. Positive `msgtyp` selects exact type; returns `ENOMSG` if absent.
//!   4. `MSG_EXCEPT` with positive `msgtyp` selects first message with type != msgtyp.
//!   5. Negative `msgtyp` selects the lowest type <= abs(msgtyp).
//!   6. Undersized receive without `MSG_NOERROR` returns `E2BIG` and leaves message queued.
//!   7. `MSG_NOERROR` truncates payload to msgsz and dequeues the message.
//!   8. `IPC_RMID` cleanup.

use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_NOWAIT: i32 = 0o4000;
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;
const E2BIG: i32 = 7;
const ENOMSG: i32 = 42;

#[repr(C)]
struct Msgbuf {
    mtype: i64,
    mtext: [u8; 32],
}

unsafe fn msgget(key: i32, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgget, key, flg)
}

unsafe fn msgsnd(id: i32, msgp: *const Msgbuf, sz: usize, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgsnd, id, msgp, sz, flg)
}

unsafe fn msgrcv(id: i32, msgp: *mut Msgbuf, sz: usize, typ: i64, flg: i32) -> i64 {
    libc::syscall(libc::SYS_msgrcv, id, msgp, sz, typ, flg)
}

unsafe fn msgctl(id: i32, cmd: i32, buf: *mut u8) -> i64 {
    libc::syscall(libc::SYS_msgctl, id, cmd, buf)
}

struct QueueGuard(i32);

impl Drop for QueueGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                let _ = msgctl(self.0, IPC_RMID, core::ptr::null_mut());
            }
        }
    }
}

unsafe fn send_msg(id: i32, mtype: i64, payload: &[u8]) -> bool {
    let mut buf = Msgbuf {
        mtype,
        mtext: [0; 32],
    };
    buf.mtext[..payload.len()].copy_from_slice(payload);
    msgsnd(id, &buf, payload.len(), 0) == 0
}

fn main() {
    unsafe {
        libc::alarm(5);

        let id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600);
        report!(msgget_ok = id >= 0);
        if id < 0 {
            report!(
                nowait_empty_rc = -1,
                nowait_empty_errno = errno(),
                zero_head_fifo = false,
                exact_type_select = false,
                exact_type_miss_enomsg = false,
                msg_except_select = false,
                msg_except_miss_enomsg = false,
                negative_lowest_type_select = false,
                negative_miss_enomsg = false,
                undersized_noerror_e2big = false,
                e2big_retained_received_by_noerror = false,
                msg_noerror_truncates_and_dequeues = false,
                ipc_rmid_ok = false,
            );
            return;
        }

        let id = id as i32;
        let mut guard = QueueGuard(id);

        let mut got = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };

        // 1. IPC_NOWAIT on empty queue returns ENOMSG.
        let empty_rc = msgrcv(id, &mut got, 32, 0, IPC_NOWAIT);
        let empty_errno = if empty_rc < 0 { errno() } else { 0 };
        report!(nowait_empty_rc = empty_rc, nowait_empty_errno = empty_errno,);

        // 2. msgtyp == 0 selects queue head in FIFO order.
        let s1 = send_msg(id, 10, b"first");
        let s2 = send_msg(id, 20, b"second");
        let s3 = send_msg(id, 10, b"third");

        let mut r1 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let mut r2 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let mut r3 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rc1 = msgrcv(id, &mut r1, 32, 0, IPC_NOWAIT);
        let rc2 = msgrcv(id, &mut r2, 32, 0, IPC_NOWAIT);
        let rc3 = msgrcv(id, &mut r3, 32, 0, IPC_NOWAIT);
        let empty_after_fifo = msgrcv(id, &mut got, 32, 0, IPC_NOWAIT);

        let fifo_ok = s1
            && s2
            && s3
            && rc1 == 5
            && r1.mtype == 10
            && &r1.mtext[..5] == b"first"
            && rc2 == 6
            && r2.mtype == 20
            && &r2.mtext[..6] == b"second"
            && rc3 == 5
            && r3.mtype == 10
            && &r3.mtext[..5] == b"third"
            && empty_after_fifo == -1
            && errno() == ENOMSG;
        report!(zero_head_fifo = fifo_ok);

        // 3. Positive msgtyp selects exact type; returns ENOMSG when absent.
        let sp1 = send_msg(id, 100, b"m100");
        let sp2 = send_msg(id, 200, b"m200");
        let sp3 = send_msg(id, 300, b"m300");

        let mut r_exact = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rc_exact = msgrcv(id, &mut r_exact, 32, 200, IPC_NOWAIT);
        let exact_ok = sp1
            && sp2
            && sp3
            && rc_exact == 4
            && r_exact.mtype == 200
            && &r_exact.mtext[..4] == b"m200";
        report!(exact_type_select = exact_ok);

        let rc_miss = msgrcv(id, &mut got, 32, 999, IPC_NOWAIT);
        report!(exact_type_miss_enomsg = rc_miss == -1 && errno() == ENOMSG);

        // 4. MSG_EXCEPT with positive msgtyp selects first message with type != msgtyp.
        // Queue currently contains: [100 ("m100"), 300 ("m300")].
        let mut r_except = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rc_except = msgrcv(id, &mut r_except, 32, 100, MSG_EXCEPT | IPC_NOWAIT);
        let except_ok = rc_except == 4 && r_except.mtype == 300 && &r_except.mtext[..4] == b"m300";
        report!(msg_except_select = except_ok);

        // Queue now contains only [100 ("m100")]. Asking for != 100 should return ENOMSG.
        let rc_except_miss = msgrcv(id, &mut got, 32, 100, MSG_EXCEPT | IPC_NOWAIT);
        report!(msg_except_miss_enomsg = rc_except_miss == -1 && errno() == ENOMSG);

        // Drain the remaining message of type 100.
        let _ = msgrcv(id, &mut got, 32, 0, IPC_NOWAIT);

        // 5. Negative msgtyp selects lowest type <= abs(msgtyp).
        let sn1 = send_msg(id, 30, b"t30");
        let sn2 = send_msg(id, 10, b"t10");
        let sn3 = send_msg(id, 20, b"t20");
        let sn4 = send_msg(id, 50, b"t50");

        // Queue: [30, 10, 20, 50]. Request -25 -> candidates <= 25 are 10, 20; lowest is 10.
        let mut rn1 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rcn1 = msgrcv(id, &mut rn1, 32, -25, IPC_NOWAIT);
        let n1_ok =
            sn1 && sn2 && sn3 && sn4 && rcn1 == 3 && rn1.mtype == 10 && &rn1.mtext[..3] == b"t10";

        // Queue: [30, 20, 50]. Request -40 -> candidates <= 40 are 30, 20; lowest is 20.
        let mut rn2 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rcn2 = msgrcv(id, &mut rn2, 32, -40, IPC_NOWAIT);
        let n2_ok = rcn2 == 3 && rn2.mtype == 20 && &rn2.mtext[..3] == b"t20";

        // Queue: [30, 50]. Request -5 -> no candidate <= 5 -> ENOMSG.
        let rcn_miss = msgrcv(id, &mut got, 32, -5, IPC_NOWAIT);
        let n_miss_ok = rcn_miss == -1 && errno() == ENOMSG;
        report!(negative_miss_enomsg = n_miss_ok);

        // Queue: [30, 50]. Request -100 -> lowest is 30.
        let mut rn3 = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rcn3 = msgrcv(id, &mut rn3, 32, -100, IPC_NOWAIT);
        let n3_ok = rcn3 == 3 && rn3.mtype == 30 && &rn3.mtext[..3] == b"t30";

        // Drain remaining message (type 50).
        let _ = msgrcv(id, &mut got, 32, 0, IPC_NOWAIT);

        report!(negative_lowest_type_select = n1_ok && n2_ok && n3_ok);

        // 6. Undersized receive without MSG_NOERROR returns E2BIG and leaves message queued.
        let su = send_msg(id, 77, b"0123456789ABCDEF"); // 16 bytes
        let mut r_trunc = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rc_e2big = msgrcv(id, &mut r_trunc, 6, 77, IPC_NOWAIT);
        let e2big_err = if rc_e2big < 0 { errno() } else { 0 };
        report!(undersized_noerror_e2big = su && rc_e2big == -1 && e2big_err == E2BIG);

        // 7. MSG_NOERROR truncates payload to msgsz and dequeues the message.
        let mut r_trunc_ok = Msgbuf {
            mtype: 0,
            mtext: [0; 32],
        };
        let rc_noerror = msgrcv(id, &mut r_trunc_ok, 6, 77, MSG_NOERROR | IPC_NOWAIT);
        let trunc_dequeued =
            rc_noerror == 6 && r_trunc_ok.mtype == 77 && &r_trunc_ok.mtext[..6] == b"012345";
        report!(e2big_retained_received_by_noerror = trunc_dequeued);

        // Verify queue is now empty (message was dequeued).
        let rc_after_trunc = msgrcv(id, &mut got, 32, 0, IPC_NOWAIT);
        report!(
            msg_noerror_truncates_and_dequeues =
                trunc_dequeued && rc_after_trunc == -1 && errno() == ENOMSG
        );

        // 8. IPC_RMID cleanup.
        let rm = msgctl(id, IPC_RMID, core::ptr::null_mut());
        if rm == 0 {
            guard.0 = -1; // Disarm RAII guard only upon successful explicit removal
        }
        report!(ipc_rmid_ok = rm == 0);
    }
}
