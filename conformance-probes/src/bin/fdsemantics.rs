//! File descriptor semantics probe: pidfd_open O_NONBLOCK and memfd sealing.
//!
//! Covers:
//! 1. pidfd_open with PIDFD_NONBLOCK sets O_NONBLOCK in fcntl(F_GETFL).
//! 2. pidfd_open without PIDFD_NONBLOCK leaves O_NONBLOCK clear.
//! 3. waitid(P_PIDFD) on a non-blocking pidfd returns EAGAIN while child is alive.
//! 4. waitid(P_PIDFD) on the pidfd succeeds after child exits.
//! 5. pidfd_open rejects unknown flags with EINVAL.
//! 6. memfd_create without MFD_ALLOW_SEALING starts with F_SEAL_SEAL set.
//! 7. memfd_create without MFD_ALLOW_SEALING rejects F_ADD_SEALS with EPERM.
//! 8. memfd_create with MFD_ALLOW_SEALING starts with 0 seals.
//! 9. memfd_create with MFD_ALLOW_SEALING allows adding F_SEAL_WRITE.
//! 10. Adding F_SEAL_SEAL blocks subsequent F_ADD_SEALS with EPERM.
//!
//! Expected Linux output:
//!   getfl_nonblock_set=true
//!   getfl_default_clear=true
//!   waitid_nonblock_eagain_while_alive=true
//!   waitid_after_exit_ok=true
//!   unknown_flag_einval=true
//!   noseal_get_seals_is_seal_seal=true
//!   noseal_add_seals_eperm=true
//!   allowseal_get_seals_zero=true
//!   allowseal_add_write_ok=true
//!   allowseal_add_after_seal_seal_eperm=true

use conformance_probes::{errno, report, spawn_blocked_child};
use std::ffi::CString;

const SYS_PIDFD_OPEN: libc::c_long = 434;

#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_CREATE: libc::c_long = 319;
#[cfg(target_arch = "aarch64")]
const SYS_MEMFD_CREATE: libc::c_long = 279;

const PIDFD_NONBLOCK: libc::c_uint = 0o4000;
const P_PIDFD: libc::idtype_t = 3;
const WEXITED: libc::c_int = 4;

const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;
const F_ADD_SEALS: libc::c_int = 1033;
const F_GET_SEALS: libc::c_int = 1034;
const F_SEAL_SEAL: i32 = 0x0001;
const F_SEAL_GROW: i32 = 0x0004;
const F_SEAL_WRITE: i32 = 0x0008;

unsafe fn sys_pidfd_open(pid: libc::pid_t, flags: libc::c_uint) -> libc::c_int {
    libc::syscall(SYS_PIDFD_OPEN, pid as libc::c_long, flags as libc::c_long) as libc::c_int
}

unsafe fn sys_memfd_create(name: &str, flags: libc::c_uint) -> libc::c_int {
    let Ok(c) = CString::new(name) else {
        return -1;
    };
    libc::syscall(
        SYS_MEMFD_CREATE,
        c.as_ptr(),
        flags as libc::c_ulong,
    ) as libc::c_int
}

fn main() {
    unsafe {
        // Bounded alarm watchdog: prevent harness hangs if execution wedges.
        libc::alarm(10);

        // Unknown flags -> EINVAL
        let bad_rc = sys_pidfd_open(libc::getpid(), 0x12345);
        let unknown_flag_einval = bad_rc == -1 && errno() == libc::EINVAL;

        // Gap 1: child process + pidfd
        let (child_pid, release_fd) = spawn_blocked_child();

        let pfd_def = sys_pidfd_open(child_pid, 0);
        let mut getfl_default_clear = false;
        if pfd_def >= 0 {
            let fl = libc::fcntl(pfd_def, libc::F_GETFL, 0);
            getfl_default_clear = fl >= 0 && (fl & libc::O_NONBLOCK) == 0;
        }

        let pfd_nb = sys_pidfd_open(child_pid, PIDFD_NONBLOCK);
        let mut getfl_nonblock_set = false;
        let mut waitid_nonblock_eagain_while_alive = false;
        let mut waitid_after_exit_ok = false;

        if pfd_nb >= 0 {
            let fl = libc::fcntl(pfd_nb, libc::F_GETFL, 0);
            getfl_nonblock_set = fl >= 0 && (fl & libc::O_NONBLOCK) != 0;

            // Child is alive; waitid on nonblocking pidfd must yield EAGAIN
            let mut siginfo: libc::siginfo_t = std::mem::zeroed();
            let rc_wait = libc::waitid(P_PIDFD, pfd_nb as libc::id_t, &mut siginfo, WEXITED);
            waitid_nonblock_eagain_while_alive = rc_wait == -1 && errno() == libc::EAGAIN;

            // Release the child so it terminates
            libc::close(release_fd);

            // Now child exits; waitid on pidfd must succeed and reap child
            let mut siginfo_after: libc::siginfo_t = std::mem::zeroed();
            let mut rc_after = -1;
            for _ in 0..100 {
                rc_after = libc::waitid(
                    P_PIDFD,
                    pfd_nb as libc::id_t,
                    &mut siginfo_after,
                    WEXITED,
                );
                if rc_after == 0 {
                    break;
                }
                if errno() == libc::EAGAIN || errno() == libc::EINTR {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    continue;
                }
                break;
            }
            waitid_after_exit_ok = rc_after == 0;
            libc::close(pfd_nb);
        } else {
            libc::close(release_fd);
        }

        if pfd_def >= 0 {
            libc::close(pfd_def);
        }

        // Clean up child just in case waitid didn't reap
        let mut status = 0;
        let _ = libc::waitpid(child_pid, &mut status, libc::WNOHANG);

        // Gap 2: memfd sealing
        // Case A: without MFD_ALLOW_SEALING -> starts with F_SEAL_SEAL, F_ADD_SEALS fails with EPERM
        let fd_noseal = sys_memfd_create("probe_noseal", 0);
        let mut noseal_get_seals_is_seal_seal = false;
        let mut noseal_add_seals_eperm = false;
        if fd_noseal >= 0 {
            let seals = libc::fcntl(fd_noseal, F_GET_SEALS);
            noseal_get_seals_is_seal_seal = seals == F_SEAL_SEAL;

            let rc_add = libc::fcntl(fd_noseal, F_ADD_SEALS, F_SEAL_WRITE);
            noseal_add_seals_eperm = rc_add == -1 && errno() == libc::EPERM;

            libc::close(fd_noseal);
        }

        // Case B: with MFD_ALLOW_SEALING -> starts with 0 seals, allows F_ADD_SEALS
        let fd_allow = sys_memfd_create("probe_allow", MFD_ALLOW_SEALING);
        let mut allowseal_get_seals_zero = false;
        let mut allowseal_add_write_ok = false;
        let mut allowseal_add_after_seal_seal_eperm = false;
        if fd_allow >= 0 {
            let seals = libc::fcntl(fd_allow, F_GET_SEALS);
            allowseal_get_seals_zero = seals == 0;

            let rc_write = libc::fcntl(fd_allow, F_ADD_SEALS, F_SEAL_WRITE);
            let seals_after_write = libc::fcntl(fd_allow, F_GET_SEALS);
            allowseal_add_write_ok = rc_write == 0 && seals_after_write == F_SEAL_WRITE;

            let rc_seal = libc::fcntl(fd_allow, F_ADD_SEALS, F_SEAL_SEAL);
            let rc_after_seal = libc::fcntl(fd_allow, F_ADD_SEALS, F_SEAL_GROW);
            allowseal_add_after_seal_seal_eperm =
                rc_seal == 0 && rc_after_seal == -1 && errno() == libc::EPERM;

            libc::close(fd_allow);
        }

        report!(
            getfl_nonblock_set = getfl_nonblock_set,
            getfl_default_clear = getfl_default_clear,
            waitid_nonblock_eagain_while_alive = waitid_nonblock_eagain_while_alive,
            waitid_after_exit_ok = waitid_after_exit_ok,
            unknown_flag_einval = unknown_flag_einval,
            noseal_get_seals_is_seal_seal = noseal_get_seals_is_seal_seal,
            noseal_add_seals_eperm = noseal_add_seals_eperm,
            allowseal_get_seals_zero = allowseal_get_seals_zero,
            allowseal_add_write_ok = allowseal_add_write_ok,
            allowseal_add_after_seal_seal_eperm = allowseal_add_after_seal_seal_eperm,
        );

        libc::alarm(0);
    }
}
