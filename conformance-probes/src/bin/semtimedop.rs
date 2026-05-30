//! semtimedop (syscall 192) — the timed SysV-semaphore wait glibc's
//! sem_timedwait uses for bounded blocking. Only untimed semop is probe/LTP
//! covered; carrick emulates the macOS-missing semtimedop by polling IPC_NOWAIT
//! semop to a deadline (dispatch/sysv.rs), so its timeout/EAGAIN edges were
//! ungated. Asserts: a wait on a zero-valued sem TIMES OUT with EAGAIN; once the
//! sem is posted the timed wait ACQUIRES immediately; IPC_NOWAIT still EAGAINs.
//! Prints booleans only (never the elapsed time), so it diffs line-exact.

use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_RMID: i32 = 0;
const SETVAL: i32 = 16;
const GETVAL: i32 = 12;

#[repr(C)]
#[derive(Clone, Copy)]
struct Sembuf {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

unsafe fn semget(key: i32, nsems: i32, flg: i32) -> i64 {
    libc::syscall(libc::SYS_semget, key, nsems, flg)
}
unsafe fn semctl(id: i64, num: i32, cmd: i32, arg: u64) -> i64 {
    libc::syscall(libc::SYS_semctl, id, num, cmd, arg)
}
unsafe fn semtimedop(id: i64, sops: *mut Sembuf, n: usize, t: *const libc::timespec) -> i64 {
    libc::syscall(libc::SYS_semtimedop, id, sops, n, t)
}

fn main() {
    unsafe {
        let id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600);
        if id < 0 {
            report!(
                timed_wait_eagain = false,
                nowait_eagain = false,
                timed_acquire_ok = false,
                val_zero_after_acquire = false,
            );
            return;
        }
        semctl(id, 0, SETVAL, 0); // sem0 = 0

        let short = libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        }; // 50ms

        // wait-for-decrement on a 0 sem must time out with EAGAIN.
        let mut dec = Sembuf {
            sem_num: 0,
            sem_op: -1,
            sem_flg: 0,
        };
        let r1 = semtimedop(id, &mut dec, 1, &short);
        report!(timed_wait_eagain = r1 == -1 && errno() == libc::EAGAIN);

        // IPC_NOWAIT decrement on a 0 sem: immediate EAGAIN.
        let mut dec_nw = Sembuf {
            sem_num: 0,
            sem_op: -1,
            sem_flg: IPC_NOWAIT,
        };
        let r2 = semtimedop(id, &mut dec_nw, 1, &short);
        report!(nowait_eagain = r2 == -1 && errno() == libc::EAGAIN);

        // post the sem, then the timed wait must acquire immediately.
        semctl(id, 0, SETVAL, 1); // sem0 = 1
        let mut dec2 = Sembuf {
            sem_num: 0,
            sem_op: -1,
            sem_flg: 0,
        };
        let r3 = semtimedop(id, &mut dec2, 1, &short);
        report!(timed_acquire_ok = r3 == 0);
        report!(val_zero_after_acquire = semctl(id, 0, GETVAL, 0) == 0);

        semctl(id, 0, IPC_RMID, 0);
    }
}
