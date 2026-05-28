//! POSIX classic advisory record locks via `fcntl(F_SETLK/F_GETLK/F_SETLKW)`.
//! carrick forwards these to the host fd's real fcntl locking (macOS supports
//! byte-range locks with conflict + deadlock detection), translating the
//! `struct flock` layout + `l_type` constants Linux↔macOS. Stands in for the
//! LTP `fcntl` record-lock cluster (fcntl11..fcntl27, fcntl31/32 — conflict,
//! F_GETLK reporting, deadlock detection). Was a no-op stub (always rc=0), so
//! every test expecting real conflict/deadlock detection failed.
//!
//! Invariants (a forked child gives a SECOND lock owner — classic locks are
//! per-process, and carrick guest processes are separate host processes
//! sharing the host file, so the host kernel arbitrates):
//!
//!   1. **F_SETLK conflict → EAGAIN/EACCES**: parent holds a write lock on
//!      [0,10); child's F_SETLK write lock on the same range fails with
//!      EAGAIN (or EACCES — Linux allows either) instead of succeeding.
//!   2. **F_GETLK reports the conflicting lock**: child's F_GETLK on [0,10)
//!      returns l_type=F_WRLCK (not F_UNLCK) — the held lock is visible.
//!   3. **F_GETLK on a free range → F_UNLCK**: child's F_GETLK on [100,110)
//!      returns l_type=F_UNLCK (no conflict).
//!   4. **Unlock releases**: after the parent F_UNLCKs, the child's F_SETLK
//!      on [0,10) succeeds.
//!
//! Deterministic booleans; the child reports via a pipe; bounded so a broken
//! lock path prints false, never hangs.

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

const F_SETLK: i32 = 6;
const F_GETLK: i32 = 5;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const SEEK_SET: i16 = 0;

/// Linux aarch64 struct flock: l_type:i16@0, l_whence:i16@2, l_start:i64@8,
/// l_len:i64@16, l_pid:i32@24 (32 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    _pad: i32,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    _pad2: i32,
}

unsafe fn flock_op(fd: i32, cmd: i32, fl: &mut Flock) -> i64 {
    libc::syscall(libc::SYS_fcntl, fd, cmd, fl as *mut Flock as *mut libc::c_void)
}

fn mk(l_type: i16, start: i64, len: i64) -> Flock {
    Flock {
        l_type,
        l_whence: SEEK_SET,
        _pad: 0,
        l_start: start,
        l_len: len,
        l_pid: 0,
        _pad2: 0,
    }
}

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/carrick_fcntllock\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            report!(setup = false);
            return;
        }
        libc::ftruncate(fd, 4096);

        // Parent takes a WRITE lock on [0,10).
        let mut wl = mk(F_WRLCK, 0, 10);
        let parent_lock_ok = flock_op(fd, F_SETLK, &mut wl) == 0;
        report!(parent_write_lock_ok = parent_lock_ok);

        let mut pipefd = [0i32; 2];
        libc::pipe(pipefd.as_mut_ptr());

        let pid = libc::fork();
        if pid == 0 {
            libc::close(pipefd[0]);
            // Child opens its OWN fd (separate process → separate lock owner).
            let cfd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR);
            // (a) Conflicting F_SETLK on [0,10) must FAIL with EAGAIN/EACCES.
            let mut cl = mk(F_WRLCK, 0, 10);
            let rc = flock_op(cfd, F_SETLK, &mut cl);
            let er = if rc < 0 { errno() } else { 0 };
            let conflict_blocked = rc == -1 && (er == libc::EAGAIN || er == libc::EACCES);
            // (b) F_GETLK on [0,10) must report the conflicting WRITE lock.
            let mut gl = mk(F_WRLCK, 0, 10);
            let g_rc = flock_op(cfd, F_GETLK, &mut gl);
            let getlk_sees_conflict = g_rc == 0 && gl.l_type == F_WRLCK;
            // (c) F_GETLK on a FREE range [100,110) must report F_UNLCK.
            let mut fl = mk(F_WRLCK, 100, 10);
            let f_rc = flock_op(cfd, F_GETLK, &mut fl);
            let getlk_free_unlck = f_rc == 0 && fl.l_type == F_UNLCK;
            let byte: u8 = (conflict_blocked as u8)
                | ((getlk_sees_conflict as u8) << 1)
                | ((getlk_free_unlck as u8) << 2);
            libc::write(pipefd[1], &byte as *const u8 as *const libc::c_void, 1);
            libc::close(pipefd[1]);
            libc::_exit(0);
        }
        libc::close(pipefd[1]);
        let mut byte = 0u8;
        let mut got = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let n = libc::read(pipefd[0], &mut byte as *mut u8 as *mut libc::c_void, 1);
            if n == 1 {
                got = true;
                break;
            }
            if n <= 0 {
                break;
            }
        }
        libc::close(pipefd[0]);
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);

        report!(
            child_conflict_blocked = got && (byte & 1) != 0,
            child_getlk_sees_conflict = got && (byte & 2) != 0,
            child_getlk_free_unlck = got && (byte & 4) != 0,
        );

        // (d) Parent unlocks; a fresh child can now lock [0,10).
        let mut ul = mk(F_UNLCK, 0, 10);
        let unlock_ok = flock_op(fd, F_SETLK, &mut ul) == 0;

        let mut pipefd2 = [0i32; 2];
        libc::pipe(pipefd2.as_mut_ptr());
        let pid2 = libc::fork();
        if pid2 == 0 {
            libc::close(pipefd2[0]);
            let cfd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR);
            let mut cl = mk(F_WRLCK, 0, 10);
            let rc = flock_op(cfd, F_SETLK, &mut cl);
            let ok = (rc == 0) as u8;
            libc::write(pipefd2[1], &ok as *const u8 as *const libc::c_void, 1);
            libc::close(pipefd2[1]);
            libc::_exit(0);
        }
        libc::close(pipefd2[1]);
        let mut b2 = 0u8;
        let mut got2 = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let n = libc::read(pipefd2[0], &mut b2 as *mut u8 as *mut libc::c_void, 1);
            if n == 1 {
                got2 = true;
                break;
            }
            if n <= 0 {
                break;
            }
        }
        libc::close(pipefd2[0]);
        let mut st2 = 0i32;
        libc::waitpid(pid2, &mut st2, 0);

        report!(
            parent_unlock_ok = unlock_ok,
            child_relock_after_unlock_ok = got2 && b2 == 1,
        );

        let _ = F_RDLCK;
        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
    }
}
