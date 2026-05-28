//! SysV semaphores: semget / semop / semctl(SETVAL/GETVAL/SETALL/GETALL/
//! IPC_RMID). carrick forwards these to the host (macOS has SysV semaphores;
//! the `sembuf` layout matches Linux, the semctl command constants are
//! translated). Guest processes are separate host processes sharing the host
//! semaphore set, so the host kernel gives cross-process coherence — the whole
//! point of a semaphore. Was ENOSYS (whole ipc area TBROK'd); stands in for
//! the LTP semget/semop/semctl basic-operation tests.
//!
//! Invariants (deterministic):
//!   1. semget(IPC_PRIVATE, 2, IPC_CREAT|0600) → id >= 0.
//!   2. SETVAL sem0=5 → GETVAL sem0 == 5.
//!   3. SETALL [3,7] → GETALL reads back [3,7].
//!   4. semop decrement sem0 by 2 → GETVAL sem0 == 1.
//!   5. cross-process: a forked child does semop +4 on sem0; the parent's
//!      GETVAL then sees 5 (1+4) — the host set is shared across processes.
//!   6. IPC_RMID → 0.
//!
//! NOTE: deliberately does NOT assert IPC_STAT semid_ds contents or the
//! error-path errnos/limits — those edges aren't fully faithful yet (tracked).

use conformance_probes::{errno, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;

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
unsafe fn semop(id: i32, sops: *mut Sembuf, n: usize) -> i64 {
    libc::syscall(libc::SYS_semop, id, sops, n)
}
unsafe fn semctl(id: i32, num: i32, cmd: i32, arg: u64) -> i64 {
    libc::syscall(libc::SYS_semctl, id, num, cmd, arg)
}

fn main() {
    unsafe {
        let id = semget(IPC_PRIVATE, 2, IPC_CREAT | 0o600);
        report!(semget_ok = id >= 0);
        if id < 0 {
            report!(
                setval_getval = false,
                setall_getall = false,
                semop_decrement = false,
                xprocess_shared = false,
                ipc_rmid_ok = false,
            );
            return;
        }
        let id = id as i32;

        // SETVAL / GETVAL.
        let sv = semctl(id, 0, SETVAL, 5);
        let gv = semctl(id, 0, GETVAL, 0);
        report!(setval_getval = sv == 0 && gv == 5);

        // SETALL / GETALL (array of u16).
        let set: [u16; 2] = [3, 7];
        let sa = semctl(id, 0, SETALL, set.as_ptr() as u64);
        let mut got: [u16; 2] = [0; 2];
        let ga = semctl(id, 0, GETALL, got.as_mut_ptr() as u64);
        report!(setall_getall = sa == 0 && ga == 0 && got == [3, 7]);

        // semop: sem0 is 3 now (from SETALL); decrement by 2 → 1.
        let mut dec = Sembuf { sem_num: 0, sem_op: -2, sem_flg: 0 };
        let op = semop(id, &mut dec, 1);
        let after = semctl(id, 0, GETVAL, 0);
        report!(semop_decrement = op == 0 && after == 1);

        // Cross-process: child increments sem0 by 4; parent sees 5.
        let pid = libc::fork();
        if pid == 0 {
            let mut inc = Sembuf { sem_num: 0, sem_op: 4, sem_flg: 0 };
            let _ = semop(id, &mut inc, 1);
            libc::_exit(0);
        }
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);
        let shared = semctl(id, 0, GETVAL, 0);
        report!(xprocess_shared = shared == 5);

        let rm = semctl(id, 0, IPC_RMID, 0);
        report!(ipc_rmid_ok = rm == 0);
        let _ = errno();
    }
}
