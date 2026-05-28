//! SysV message queues: msgget / msgsnd / msgrcv / msgctl(IPC_STAT/IPC_RMID).
//! carrick forwards these to the host (macOS has SysV msg queues; the msgbuf
//! `{long mtype; char mtext[]}` layout + IPC_* constants match Linux, and the
//! msqid_ds is field-translated for IPC_STAT). Guest processes are separate
//! host processes sharing the host queue → cross-process for free. Was ENOSYS
//! (the ipc area's other TBROK half). Stands in for LTP msgget/msgsnd/msgrcv.
//!
//! Invariants (deterministic):
//!   1. msgget(IPC_PRIVATE, IPC_CREAT|0600) → id >= 0.
//!   2. msgsnd(type=5, payload) → 0; msgrcv(type=5) returns the same bytes.
//!   3. IPC_STAT msg_qnum: 1 after one send, 0 after the receive.
//!   4. type-selective receive: with messages of type 5 and 7 queued,
//!      msgrcv(type=7) returns the type-7 message (not the type-5 one).
//!   5. cross-process: a forked child msgsnds; the parent msgrcvs it.
//!   6. IPC_RMID → 0.

use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const LIN_MSG_QNUM_OFF: usize = 80;

#[repr(C)]
struct Msgbuf {
    mtype: i64,
    mtext: [u8; 16],
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

unsafe fn qnum(id: i32) -> u64 {
    let mut ds = [0u8; 120];
    if msgctl(id, IPC_STAT, ds.as_mut_ptr()) != 0 {
        return u64::MAX;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&ds[LIN_MSG_QNUM_OFF..LIN_MSG_QNUM_OFF + 8]);
    u64::from_le_bytes(a)
}

fn main() {
    unsafe {
        let id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600);
        report!(msgget_ok = id >= 0);
        if id < 0 {
            report!(
                send_recv_roundtrip = false,
                qnum_after_send_is_1 = false,
                qnum_after_recv_is_0 = false,
                type_selective_recv = false,
                xprocess_send_recv = false,
                ipc_rmid_ok = false,
            );
            return;
        }
        let id = id as i32;

        // (2) send type 5, receive it.
        let mut m = Msgbuf { mtype: 5, mtext: [0; 16] };
        m.mtext[..5].copy_from_slice(b"hello");
        let s = msgsnd(id, &m, 5, 0);
        let q1 = qnum(id);
        let mut r = Msgbuf { mtype: 0, mtext: [0; 16] };
        let rc = msgrcv(id, &mut r, 16, 5, 0);
        let q0 = qnum(id);
        report!(
            send_recv_roundtrip = s == 0 && rc == 5 && &r.mtext[..5] == b"hello" && r.mtype == 5,
            qnum_after_send_is_1 = q1 == 1,
            qnum_after_recv_is_0 = q0 == 0,
        );

        // (4) type-selective receive: queue type 5 then type 7; ask for 7.
        let mut a = Msgbuf { mtype: 5, mtext: [0; 16] };
        a.mtext[..3].copy_from_slice(b"aaa");
        let mut b = Msgbuf { mtype: 7, mtext: [0; 16] };
        b.mtext[..3].copy_from_slice(b"bbb");
        msgsnd(id, &a, 3, 0);
        msgsnd(id, &b, 3, 0);
        let mut got = Msgbuf { mtype: 0, mtext: [0; 16] };
        let rc = msgrcv(id, &mut got, 16, 7, 0);
        report!(type_selective_recv = rc == 3 && got.mtype == 7 && &got.mtext[..3] == b"bbb");
        // drain the type-5 leftover.
        let mut drain = Msgbuf { mtype: 0, mtext: [0; 16] };
        msgrcv(id, &mut drain, 16, 5, 0);

        // (5) cross-process: child sends type 9, parent receives.
        let pid = libc::fork();
        if pid == 0 {
            let mut c = Msgbuf { mtype: 9, mtext: [0; 16] };
            c.mtext[..4].copy_from_slice(b"xpro");
            msgsnd(id, &c, 4, 0);
            libc::_exit(0);
        }
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);
        let mut cr = Msgbuf { mtype: 0, mtext: [0; 16] };
        let rc = msgrcv(id, &mut cr, 16, 9, 0);
        report!(xprocess_send_recv = rc == 4 && &cr.mtext[..4] == b"xpro");

        let rm = msgctl(id, IPC_RMID, core::ptr::null_mut());
        report!(ipc_rmid_ok = rm == 0);
        let _ = errno();
    }
}
