//! SysV shared-memory probe: shmget / shmat / shmdt / shmctl(IPC_RMID).
//! The LTP `kill05`/`kill07` tests TBROK because `shmget` returned ENOSYS;
//! this probe pins the post-fix invariants down so a regression breaks
//! `cargo test` line-exact against Docker.
//!
//! Invariants encoded:
//!   1. shmget(IPC_PRIVATE, 4096, IPC_CREAT|0666) → shmid >= 1, errno=0.
//!   2. shmat(shmid, NULL, 0) → a non-null mapped address.
//!   3. Reads/writes through the mapping persist (byte we write, byte we
//!      read back).
//!   4. A forked child attaching the same shmid sees the byte the parent
//!      wrote (the WHOLE POINT of shmem — cross-process coherence).
//!   5. shmdt(addr) → returns 0.
//!   6. shmctl(shmid, IPC_RMID, NULL) → returns 0.
//!
//! Deterministic output: booleans only. No PIDs, no addresses, no inodes.

use conformance_probes::report;
use std::time::{Duration, Instant};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const SIZE: usize = 4096;

unsafe fn shmget(key: i32, size: usize, flags: i32) -> i64 {
    libc::syscall(libc::SYS_shmget, key as i64, size as i64, flags as i64)
}

unsafe fn shmat(shmid: i32, addr: *const libc::c_void, flag: i32) -> *mut libc::c_void {
    libc::syscall(libc::SYS_shmat, shmid as i64, addr, flag as i64) as *mut libc::c_void
}

unsafe fn shmdt(addr: *const libc::c_void) -> i64 {
    libc::syscall(libc::SYS_shmdt, addr)
}

unsafe fn shmctl(shmid: i32, cmd: i32, buf: *mut libc::c_void) -> i64 {
    libc::syscall(libc::SYS_shmctl, shmid as i64, cmd as i64, buf)
}

fn main() {
    unsafe {
        let shmid = shmget(IPC_PRIVATE, SIZE, IPC_CREAT | 0o666);
        // shmget(2): success → shmid >= 0 (Linux can return 0 for the first
        // segment); error → -1.
        report!(shmget_ok = shmid >= 0);
        if shmid < 0 {
            // Print stable falses for the line-aligned diff.
            report!(
                shmat_ok = false,
                rw_roundtrip_ok = false,
                xproc_coherence_ok = false,
                shmdt_ok = false,
                shmctl_rmid_ok = false,
            );
            return;
        }

        let addr = shmat(shmid as i32, core::ptr::null(), 0);
        let shmat_ok = !addr.is_null() && addr as isize != -1;
        report!(shmat_ok = shmat_ok);
        if !shmat_ok {
            report!(
                rw_roundtrip_ok = false,
                xproc_coherence_ok = false,
                shmdt_ok = false,
                shmctl_rmid_ok = false,
            );
            return;
        }

        // (3) Write a sentinel and read it back.
        let bytes = addr as *mut u8;
        const SENTINEL: u8 = 0xA5;
        core::ptr::write_volatile(bytes, SENTINEL);
        // Memory barrier so other threads / forked children see the write.
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let readback = core::ptr::read_volatile(bytes);
        report!(rw_roundtrip_ok = readback == SENTINEL);

        // (4) Fork a child; child re-attaches the SAME shmid and reads.
        //     Cross-process coherence: the byte parent wrote must be there.
        // We use a pipe for the child to report its observation deterministically.
        let mut pipefd = [0i32; 2];
        if libc::pipe(pipefd.as_mut_ptr()) != 0 {
            report!(
                xproc_coherence_ok = false,
                shmdt_ok = false,
                shmctl_rmid_ok = false,
            );
            return;
        }

        let pid = libc::fork();
        if pid == 0 {
            libc::close(pipefd[0]);
            let child_addr = shmat(shmid as i32, core::ptr::null(), 0);
            let ok = !child_addr.is_null()
                && child_addr as isize != -1
                && core::ptr::read_volatile(child_addr as *const u8) == SENTINEL;
            let byte = if ok { 1u8 } else { 0u8 };
            libc::write(pipefd[1], &byte as *const u8 as *const libc::c_void, 1);
            libc::close(pipefd[1]);
            libc::_exit(0);
        }
        libc::close(pipefd[1]);
        let mut byte = 0u8;
        let mut got = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while got == 0 && Instant::now() < deadline {
            let n = libc::read(pipefd[0], &mut byte as *mut u8 as *mut libc::c_void, 1);
            if n > 0 {
                got = 1;
            } else if n == 0 {
                break;
            }
        }
        libc::close(pipefd[0]);
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        report!(xproc_coherence_ok = got == 1 && byte == 1);

        // (5) shmdt.
        let dt = shmdt(addr);
        report!(shmdt_ok = dt == 0);

        // (6) shmctl IPC_RMID.
        let ctl = shmctl(shmid as i32, IPC_RMID, core::ptr::null_mut());
        report!(shmctl_rmid_ok = ctl == 0);
    }
}
