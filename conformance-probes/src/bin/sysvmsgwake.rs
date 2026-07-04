use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const IPC_NOWAIT: i32 = 0o4000;
const ENOMSG: i32 = 42;
const EAGAIN: i32 = 11;
const EIDRM: i32 = 43;
const LIN_MSG_QBYTES_OFF: usize = 88;

#[repr(C)]
struct Msgbuf {
    mtype: i64,
    mtext: [u8; 64],
}

unsafe fn msgget(key: i32, flg: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgget, key, flg) }
}

unsafe fn msgsnd(id: i32, msgp: *const Msgbuf, sz: usize, flg: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgsnd, id, msgp, sz, flg) }
}

unsafe fn msgrcv(id: i32, msgp: *mut Msgbuf, sz: usize, typ: i64, flg: i32) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgrcv, id, msgp, sz, typ, flg) }
}

unsafe fn msgctl(id: i32, cmd: i32, buf: *mut u8) -> i64 {
    unsafe { libc::syscall(libc::SYS_msgctl, id, cmd, buf) }
}

unsafe fn set_qbytes(id: i32, qbytes: u64) -> bool {
    let mut ds = [0u8; 120];
    if unsafe { msgctl(id, IPC_STAT, ds.as_mut_ptr()) } != 0 {
        return false;
    }
    ds[LIN_MSG_QBYTES_OFF..LIN_MSG_QBYTES_OFF + 8].copy_from_slice(&qbytes.to_le_bytes());
    (unsafe { msgctl(id, IPC_SET, ds.as_mut_ptr()) }) == 0
}

fn child_exited_zero(status: i32) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn main() {
    unsafe {
        libc::alarm(20);
        let id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600);
        if id < 0 {
            report!(
                nowait_empty_enomsg = false,
                nowait_full_eagain = false,
                fork_reader_wakes_sender = false,
                rmid_wakes_receiver = false,
            );
            return;
        }
        let id = id as i32;
        let mut msg = Msgbuf {
            mtype: 1,
            mtext: [0; 64],
        };
        msg.mtext[..4].copy_from_slice(b"wake");
        let mut got = Msgbuf {
            mtype: 0,
            mtext: [0; 64],
        };

        let empty_rc = msgrcv(id, &mut got, 64, 1, IPC_NOWAIT);
        report!(nowait_empty_enomsg = empty_rc == -1 && errno() == ENOMSG);

        let qbytes_set = set_qbytes(id, 4);
        let first_send = msgsnd(id, &msg, 4, 0);
        let full_rc = msgsnd(id, &msg, 4, IPC_NOWAIT);
        report!(
            nowait_full_eagain =
                qbytes_set && first_send == 0 && full_rc == -1 && errno() == EAGAIN,
        );

        let reader = libc::fork();
        if reader == 0 {
            let mut recv = Msgbuf {
                mtype: 0,
                mtext: [0; 64],
            };
            let rc = msgrcv(id, &mut recv, 64, 1, 0);
            libc::_exit((rc == 4 && &recv.mtext[..4] == b"wake") as i32 ^ 1);
        }
        let mut sender_msg = Msgbuf {
            mtype: 1,
            mtext: [0; 64],
        };
        sender_msg.mtext[..4].copy_from_slice(b"next");
        let send_after_reader = msgsnd(id, &sender_msg, 4, 0);
        let mut reader_status = 0;
        libc::waitpid(reader, &mut reader_status, 0);
        report!(
            fork_reader_wakes_sender = send_after_reader == 0 && child_exited_zero(reader_status)
        );

        let remove_id = msgget(IPC_PRIVATE, IPC_CREAT | 0o600) as i32;
        let receiver = libc::fork();
        if receiver == 0 {
            let mut recv = Msgbuf {
                mtype: 0,
                mtext: [0; 64],
            };
            let rc = msgrcv(remove_id, &mut recv, 64, 1, 0);
            libc::_exit((rc == -1 && errno() == EIDRM) as i32 ^ 1);
        }
        libc::usleep(100_000);
        let rm = msgctl(remove_id, IPC_RMID, core::ptr::null_mut());
        let mut receiver_status = 0;
        libc::waitpid(receiver, &mut receiver_status, 0);
        report!(rmid_wakes_receiver = rm == 0 && child_exited_zero(receiver_status));

        let _ = msgctl(id, IPC_RMID, core::ptr::null_mut());
    }
}
