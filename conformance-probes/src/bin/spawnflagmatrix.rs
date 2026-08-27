//! Process spawning, exec, file-descriptor inheritance, and lifecycle matrix probe.
//!
//! Exercises Linux flag validation, descriptor inheritance, and process lifecycle
//! invariants across:
//! 1. `close_range(2)` flags (0, CLOSE_RANGE_CLOEXEC, invalid flags, inverted ranges).
//! 2. `fcntl(2)` descriptor allocation and flags (F_DUPFD, F_DUPFD_CLOEXEC, min_fd bounds,
//!    FD_CLOEXEC roundtrips, O_NONBLOCK/O_APPEND description sharing).
//! 3. `dup2(2)` and `dup3(2)` flags (O_CLOEXEC, 0, same fd, invalid flags, bad fd).
//! 4. `pipe2(2)` flags and capacity (O_CLOEXEC, O_NONBLOCK, O_DIRECT, invalid flags,
//!    F_SETPIPE_SZ, F_GETPIPE_SZ on pipe vs non-pipe).
//! 5. `prctl(2)` process lifecycle (PR_SET_PDEATHSIG, PR_GET_PDEATHSIG, PR_SET_NO_NEW_PRIVS,
//!    PR_GET_NO_NEW_PRIVS, PR_SET_DUMPABLE, PR_GET_DUMPABLE).
//! 6. `execve(2)` descriptor inheritance and flag persistence across self-exec.
//! 7. `waitid(2)` and `wait4(2)` status and flags (P_PID, P_ALL, WEXITED, WNOWAIT, WNOHANG,
//!    siginfo_t status and rusage reporting).
//!
//! Compact table-driven structure reporting deterministic boolean and error observations.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

const SYS_CLOSE_RANGE: libc::c_long = 436;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

const F_DUPFD_CLOEXEC: libc::c_int = 1030;
const F_SETPIPE_SZ: libc::c_int = 1031;
const F_GETPIPE_SZ: libc::c_int = 1032;

const PR_SET_PDEATHSIG: libc::c_int = 1;
const PR_GET_PDEATHSIG: libc::c_int = 2;
const PR_GET_DUMPABLE: libc::c_int = 3;
const PR_SET_DUMPABLE: libc::c_int = 4;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;

unsafe fn sys_close_range(
    first: libc::c_uint,
    last: libc::c_uint,
    flags: libc::c_uint,
) -> libc::c_int {
    libc::syscall(
        SYS_CLOSE_RANGE,
        first as libc::c_ulong,
        last as libc::c_ulong,
        flags as libc::c_ulong,
    ) as libc::c_int
}

unsafe fn sys_dup3(oldfd: libc::c_int, newfd: libc::c_int, flags: libc::c_int) -> libc::c_int {
    libc::syscall(
        libc::SYS_dup3,
        oldfd as libc::c_long,
        newfd as libc::c_long,
        flags as libc::c_long,
    ) as libc::c_int
}

unsafe fn sys_pipe2(pipefd: *mut libc::c_int, flags: libc::c_int) -> libc::c_int {
    libc::syscall(
        libc::SYS_pipe2,
        pipefd as libc::c_long,
        flags as libc::c_long,
    ) as libc::c_int
}

struct DirGuard(String);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// -----------------------------------------------------------------------------
// Execve Helper Sub-process
// -----------------------------------------------------------------------------

unsafe fn run_spawn_exec_helper() {
    // fd 40: regular file without FD_CLOEXEC, with O_APPEND
    let fl_40 = libc::fcntl(40, libc::F_GETFL);
    let fd_40 = libc::fcntl(40, libc::F_GETFD);
    let ok_40 = fl_40 >= 0 && (fl_40 & libc::O_APPEND) != 0 && fd_40 == 0;

    // fd 41: pipe read end with FD_CLOEXEC -> must be closed
    let fd_41 = libc::fcntl(41, libc::F_GETFD);
    let err_41 = errno();
    let ok_41 = fd_41 == -1 && err_41 == libc::EBADF;

    // fd 42: socket without FD_CLOEXEC, with O_NONBLOCK
    let fl_42 = libc::fcntl(42, libc::F_GETFL);
    let fd_42 = libc::fcntl(42, libc::F_GETFD);
    let ok_42 = fl_42 >= 0 && (fl_42 & libc::O_NONBLOCK) != 0 && fd_42 == 0;

    // fd 43: pipe write end without FD_CLOEXEC -> write token
    let token = b"spawn_exec_token_ok\n";
    let w_43 = libc::write(43, token.as_ptr().cast(), token.len());
    let ok_43 = w_43 == token.len() as isize;

    if ok_40 && ok_41 && ok_42 && ok_43 {
        libc::_exit(0);
    } else {
        libc::_exit(101);
    }
}

// -----------------------------------------------------------------------------
// 1. close_range Matrix
// -----------------------------------------------------------------------------

unsafe fn test_close_range_matrix(base: &str) {
    let dummy_path = CString::new(format!("{base}/cr_dummy")).unwrap();
    let dummy_fd = libc::open(
        dummy_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );

    if dummy_fd < 0 {
        report!(close_range_setup_ok = false);
        return;
    }

    // Allocate range of fds: 50..55
    for fd in 50..=54 {
        libc::dup2(dummy_fd, fd);
    }

    // 1.1 close_range(50, 54, 0)
    let rc = sys_close_range(50, 54, 0);
    let mut all_closed = true;
    for fd in 50..=54 {
        if libc::fcntl(fd, libc::F_GETFD) != -1 || errno() != libc::EBADF {
            all_closed = false;
        }
    }
    report!(close_range_normal_ok = rc == 0 && all_closed);

    // 1.2 close_range(60, 64, CLOSE_RANGE_CLOEXEC)
    for fd in 60..=64 {
        libc::dup2(dummy_fd, fd);
        libc::fcntl(fd, libc::F_SETFD, 0); // ensure no cloexec initially
    }
    let rc_cloexec = sys_close_range(60, 64, CLOSE_RANGE_CLOEXEC);
    let mut all_cloexec_set = true;
    for fd in 60..=64 {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags != libc::FD_CLOEXEC {
            all_cloexec_set = false;
        }
        libc::close(fd);
    }
    report!(close_range_cloexec_ok = rc_cloexec == 0 && all_cloexec_set);

    // 1.3 Inverted range: first > last -> EINVAL
    let rc_inv = sys_close_range(50, 40, 0);
    report!(close_range_inverted_einval = rc_inv == -1 && errno() == libc::EINVAL);

    // 1.4 Invalid flags -> EINVAL
    let rc_badfl = sys_close_range(50, 55, 0x8000_0000);
    report!(close_range_invalid_flags_einval = rc_badfl == -1 && errno() == libc::EINVAL);

    // 1.5 Non-existent range closing -> 0
    let rc_nonexist = sys_close_range(1000, 1010, 0);
    report!(close_range_nonexistent_range_ok = rc_nonexist == 0);

    // 1.6 High range closing up to max uint -> 0
    let rc_max = sys_close_range(20000, !0u32, 0);
    report!(close_range_max_range_ok = rc_max == 0);

    libc::close(dummy_fd);
}

// -----------------------------------------------------------------------------
// 2. fcntl FD Allocation & Flags Matrix
// -----------------------------------------------------------------------------

unsafe fn test_fcntl_matrix(base: &str) {
    let path = CString::new(format!("{base}/fcntl_dummy")).unwrap();
    let src_fd = libc::open(
        path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if src_fd < 0 {
        return;
    }

    // Set FD_CLOEXEC on src_fd
    libc::fcntl(src_fd, libc::F_SETFD, libc::FD_CLOEXEC);

    // 2.1 F_DUPFD clears FD_CLOEXEC on new descriptor
    let dup_fd = libc::fcntl(src_fd, libc::F_DUPFD, 30);
    let dup_flags = if dup_fd >= 30 {
        libc::fcntl(dup_fd, libc::F_GETFD)
    } else {
        -1
    };
    report!(fcntl_dupfd_clears_cloexec = dup_fd >= 30 && dup_flags == 0);
    if dup_fd >= 0 {
        libc::close(dup_fd);
    }

    // 2.2 F_DUPFD_CLOEXEC sets FD_CLOEXEC on new descriptor
    libc::fcntl(src_fd, libc::F_SETFD, 0); // clear on src_fd
    let dup_clx_fd = libc::fcntl(src_fd, F_DUPFD_CLOEXEC, 35);
    let dup_clx_flags = if dup_clx_fd >= 35 {
        libc::fcntl(dup_clx_fd, libc::F_GETFD)
    } else {
        -1
    };
    report!(
        fcntl_dupfd_cloexec_sets_cloexec = dup_clx_fd >= 35 && dup_clx_flags == libc::FD_CLOEXEC
    );
    if dup_clx_fd >= 0 {
        libc::close(dup_clx_fd);
    }

    // 2.3 Negative min_fd -> EINVAL
    let rc_neg = libc::fcntl(src_fd, libc::F_DUPFD, -1);
    report!(fcntl_dupfd_negative_min_einval = rc_neg == -1 && errno() == libc::EINVAL);

    let rc_neg_clx = libc::fcntl(src_fd, F_DUPFD_CLOEXEC, -5);
    report!(fcntl_dupfd_cloexec_negative_min_einval = rc_neg_clx == -1 && errno() == libc::EINVAL);

    // 2.4 Bad fd -> EBADF
    let rc_bad = libc::fcntl(-1, libc::F_DUPFD, 10);
    report!(fcntl_dupfd_bad_fd_ebadf = rc_bad == -1 && errno() == libc::EBADF);

    // 2.5 F_SETFD / F_GETFD roundtrip
    libc::fcntl(src_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    let f1 = libc::fcntl(src_fd, libc::F_GETFD);
    libc::fcntl(src_fd, libc::F_SETFD, 0);
    let f2 = libc::fcntl(src_fd, libc::F_GETFD);
    report!(fcntl_setfd_getfd_roundtrip = f1 == libc::FD_CLOEXEC && f2 == 0);

    // 2.6 F_SETFL description flag sharing across dup
    let dup_share = libc::dup(src_fd);
    let fl_orig = libc::fcntl(src_fd, libc::F_GETFL);
    libc::fcntl(
        src_fd,
        libc::F_SETFL,
        fl_orig | libc::O_NONBLOCK | libc::O_APPEND,
    );
    let fl_dup = libc::fcntl(dup_share, libc::F_GETFL);
    report!(
        fcntl_setfl_description_sharing =
            (fl_dup & libc::O_NONBLOCK) != 0 && (fl_dup & libc::O_APPEND) != 0
    );
    if dup_share >= 0 {
        libc::close(dup_share);
    }

    libc::close(src_fd);
}

// -----------------------------------------------------------------------------
// 3. dup2 and dup3 Matrix
// -----------------------------------------------------------------------------

unsafe fn test_dup_matrix(base: &str) {
    let path = CString::new(format!("{base}/dup_dummy")).unwrap();
    let src_fd = libc::open(
        path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if src_fd < 0 {
        return;
    }

    // 3.1 dup3 with O_CLOEXEC sets FD_CLOEXEC on target
    let target1 = 70;
    let r1 = sys_dup3(src_fd, target1, libc::O_CLOEXEC);
    let f1 = if r1 == target1 {
        libc::fcntl(target1, libc::F_GETFD)
    } else {
        -1
    };
    report!(dup3_cloexec_sets_flag = r1 == target1 && f1 == libc::FD_CLOEXEC);
    if r1 >= 0 {
        libc::close(target1);
    }

    // 3.2 dup3 with flags = 0 clears FD_CLOEXEC on target even if source has it
    libc::fcntl(src_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    let target2 = 71;
    let r2 = sys_dup3(src_fd, target2, 0);
    let f2 = if r2 == target2 {
        libc::fcntl(target2, libc::F_GETFD)
    } else {
        -1
    };
    report!(dup3_zero_flags_clears_cloexec = r2 == target2 && f2 == 0);
    if r2 >= 0 {
        libc::close(target2);
    }

    // 3.3 dup3 with oldfd == newfd -> EINVAL
    let r3 = sys_dup3(src_fd, src_fd, libc::O_CLOEXEC);
    report!(dup3_same_fd_einval = r3 == -1 && errno() == libc::EINVAL);

    // 3.4 dup3 with invalid flags -> EINVAL
    let r4 = sys_dup3(src_fd, 72, 0x1234);
    report!(dup3_invalid_flags_einval = r4 == -1 && errno() == libc::EINVAL);

    // 3.5 dup2 with same fd is a no-op returning oldfd
    libc::fcntl(src_fd, libc::F_SETFD, libc::FD_CLOEXEC);
    let r5 = libc::dup2(src_fd, src_fd);
    let f5 = libc::fcntl(src_fd, libc::F_GETFD);
    report!(dup2_same_fd_noop = r5 == src_fd && f5 == libc::FD_CLOEXEC);

    // 3.6 dup2 bad old fd -> EBADF
    let r6 = libc::dup2(-1, 73);
    report!(dup2_bad_oldfd_ebadf = r6 == -1 && errno() == libc::EBADF);

    // 3.7 dup2 negative new fd -> EBADF
    let r7 = libc::dup2(src_fd, -1);
    report!(dup2_negative_newfd_ebadf = r7 == -1 && errno() == libc::EBADF);

    libc::close(src_fd);
}

// -----------------------------------------------------------------------------
// 4. pipe2 Flags & Capacity Matrix
// -----------------------------------------------------------------------------

unsafe fn test_pipe2_matrix(base: &str) {
    let mut fds = [-1i32; 2];

    // 4.1 pipe2 with O_CLOEXEC | O_NONBLOCK
    let r1 = sys_pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK);
    let f_r = if r1 == 0 {
        libc::fcntl(fds[0], libc::F_GETFD)
    } else {
        -1
    };
    let f_w = if r1 == 0 {
        libc::fcntl(fds[1], libc::F_GETFD)
    } else {
        -1
    };
    let fl_r = if r1 == 0 {
        libc::fcntl(fds[0], libc::F_GETFL)
    } else {
        -1
    };
    let fl_w = if r1 == 0 {
        libc::fcntl(fds[1], libc::F_GETFL)
    } else {
        -1
    };

    report!(
        pipe2_cloexec_nonblock_ok = r1 == 0
            && f_r == libc::FD_CLOEXEC
            && f_w == libc::FD_CLOEXEC
            && (fl_r & libc::O_NONBLOCK) != 0
            && (fl_w & libc::O_NONBLOCK) != 0
    );

    // 4.2 pipe capacity F_SETPIPE_SZ and F_GETPIPE_SZ
    if r1 == 0 {
        let set_sz = libc::fcntl(fds[0], F_SETPIPE_SZ, 65536);
        let get_sz = libc::fcntl(fds[0], F_GETPIPE_SZ);
        report!(pipe_set_get_capacity_ok = set_sz >= 65536 && get_sz == set_sz);
        libc::close(fds[0]);
        libc::close(fds[1]);
    } else {
        report!(pipe_set_get_capacity_ok = false);
    }

    // 4.3 pipe2 invalid flags -> EINVAL
    let r_bad = sys_pipe2(fds.as_mut_ptr(), 0x8000_0000u32 as i32);
    report!(pipe2_invalid_flags_einval = r_bad == -1 && errno() == libc::EINVAL);

    // 4.4 F_SETPIPE_SZ on non-pipe -> EINVAL or EBADF
    let reg_path = CString::new(format!("{base}/pipe_reg")).unwrap();
    let reg_fd = libc::open(
        reg_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if reg_fd >= 0 {
        let r_sz = libc::fcntl(reg_fd, F_SETPIPE_SZ, 65536);
        report!(pipe_setpipe_sz_on_non_pipe_einval = r_sz == -1 && errno() == libc::EINVAL);
        libc::close(reg_fd);
    }
}

// -----------------------------------------------------------------------------
// 5. prctl Process Lifecycle & Capabilities
// -----------------------------------------------------------------------------

unsafe fn test_prctl_matrix() {
    // 5.1 PR_SET_PDEATHSIG / PR_GET_PDEATHSIG
    let r_set = libc::prctl(PR_SET_PDEATHSIG, libc::SIGUSR1, 0, 0, 0);
    let mut sig: libc::c_int = 0;
    let r_get = libc::prctl(
        PR_GET_PDEATHSIG,
        &mut sig as *mut _ as libc::c_ulong,
        0,
        0,
        0,
    );
    report!(prctl_pdeathsig_set_get = r_set == 0 && r_get == 0 && sig == libc::SIGUSR1);

    // Clear pdeathsig
    libc::prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0);
    let mut sig_zero: libc::c_int = -1;
    libc::prctl(
        PR_GET_PDEATHSIG,
        &mut sig_zero as *mut _ as libc::c_ulong,
        0,
        0,
        0,
    );
    report!(prctl_pdeathsig_clear = sig_zero == 0);

    // Invalid signal -> EINVAL
    let r_inv = libc::prctl(PR_SET_PDEATHSIG, 9999, 0, 0, 0);
    report!(prctl_pdeathsig_invalid_einval = r_inv == -1 && errno() == libc::EINVAL);

    // 5.2 PR_SET_NO_NEW_PRIVS / PR_GET_NO_NEW_PRIVS
    let cur_nnp = libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    let set_nnp = libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    let after_nnp = libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    report!(prctl_no_new_privs_set_get = cur_nnp >= 0 && set_nnp == 0 && after_nnp == 1);

    let r_bad_nnp = libc::prctl(PR_SET_NO_NEW_PRIVS, 2, 0, 0, 0);
    report!(prctl_no_new_privs_invalid_arg_einval = r_bad_nnp == -1 && errno() == libc::EINVAL);

    // 5.3 PR_SET_DUMPABLE / PR_GET_DUMPABLE
    let cur_d = libc::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    let set_d0 = libc::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    let get_d0 = libc::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    let set_d1 = libc::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    let get_d1 = libc::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    report!(
        prctl_dumpable_roundtrip =
            cur_d >= 0 && set_d0 == 0 && get_d0 == 0 && set_d1 == 0 && get_d1 == 1
    );
}

// -----------------------------------------------------------------------------
// 6. execve FD Inheritance & Flag Persistence
// -----------------------------------------------------------------------------

unsafe fn test_execve_inheritance_matrix(base: &str) {
    let self_exe = std::env::current_exe().unwrap();
    let self_c = CString::new(self_exe.to_str().unwrap()).unwrap();
    let mode_c = CString::new("--spawn-exec-helper").unwrap();

    let dummy_path = CString::new(format!("{base}/exec_dummy")).unwrap();
    let reg_fd = libc::open(
        dummy_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND,
        0o644,
    );
    if reg_fd < 0 {
        report!(execve_inheritance_setup_ok = false);
        return;
    }

    // Target fd 40: regular file without CLOEXEC
    libc::dup2(reg_fd, 40);
    libc::fcntl(40, libc::F_SETFD, 0);

    // Target fd 41: pipe read end with CLOEXEC
    let mut p41 = [0i32; 2];
    sys_pipe2(p41.as_mut_ptr(), libc::O_CLOEXEC);
    libc::dup2(p41[0], 41);
    libc::fcntl(41, libc::F_SETFD, libc::FD_CLOEXEC);
    libc::close(p41[0]);
    libc::close(p41[1]);

    // Target fd 42: socket with O_NONBLOCK without CLOEXEC
    let sock = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
    libc::dup2(sock, 42);
    libc::fcntl(42, libc::F_SETFD, 0);
    if sock >= 0 {
        libc::close(sock);
    }

    // Communication pipe for child token
    let mut pipe_comm = [0i32; 2];
    libc::pipe(pipe_comm.as_mut_ptr());
    // Move write end to fd 43 without CLOEXEC
    libc::dup2(pipe_comm[1], 43);
    libc::fcntl(43, libc::F_SETFD, 0);
    libc::close(pipe_comm[1]);

    let pid = libc::fork();
    if pid == 0 {
        libc::close(pipe_comm[0]);
        let argv = [self_c.as_ptr(), mode_c.as_ptr(), core::ptr::null()];
        let envp = [core::ptr::null()];
        libc::execve(self_c.as_ptr(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(127);
    }

    libc::close(40);
    libc::close(41);
    libc::close(42);
    libc::close(43);
    libc::close(reg_fd);

    if pid < 0 {
        libc::close(pipe_comm[0]);
        report!(execve_inheritance_fork_ok = false);
        return;
    }

    // Read token from child
    let mut buf = [0u8; 64];
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut read_len = 0;
    while Instant::now() < deadline {
        let n = libc::read(
            pipe_comm[0],
            buf[read_len..].as_mut_ptr().cast(),
            buf.len() - read_len,
        );
        if n > 0 {
            read_len += n as usize;
            if &buf[..read_len] == b"spawn_exec_token_ok\n" {
                break;
            }
        } else if n == 0 {
            break;
        } else if errno() != libc::EINTR && errno() != libc::EAGAIN {
            break;
        }
    }
    libc::close(pipe_comm[0]);

    let mut status = 0;
    while libc::waitpid(pid, &mut status, 0) < 0 && errno() == libc::EINTR {}
    let exited = libc::WIFEXITED(status);
    let exit_code = if exited {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };

    report!(
        execve_inheritance_child_exited_zero = exited && exit_code == 0,
        execve_inheritance_token_matched = &buf[..read_len] == b"spawn_exec_token_ok\n",
    );
}

// -----------------------------------------------------------------------------
// 7. waitid & wait4 Status & Flags Matrix
// -----------------------------------------------------------------------------

unsafe fn test_wait_matrix() {
    // 7.1 waitid with WNOWAIT leaves child reapable by wait4
    let pid1 = libc::fork();
    if pid1 == 0 {
        libc::_exit(42);
    }
    if pid1 < 0 {
        report!(waitid_wnowait_preserves_child = false);
    } else {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let r_waitid = libc::waitid(
            libc::P_PID,
            pid1 as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT,
        );
        let info_ok = r_waitid == 0
            && info.si_signo == libc::SIGCHLD
            && info.si_code == libc::CLD_EXITED
            && info.si_status() == 42;

        let mut status = 0;
        let mut ru: libc::rusage = std::mem::zeroed();
        let r_wait4 = libc::wait4(pid1, &mut status, 0, &mut ru);
        let wait4_ok =
            r_wait4 == pid1 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42;

        report!(waitid_wnowait_preserves_child = info_ok && wait4_ok);
    }

    // 7.2 waitid with P_ALL
    let pid2 = libc::fork();
    if pid2 == 0 {
        libc::_exit(17);
    }
    if pid2 < 0 {
        report!(waitid_p_all_ok = false);
    } else {
        let mut info2: libc::siginfo_t = std::mem::zeroed();
        let r2 = libc::waitid(libc::P_ALL, 0, &mut info2, libc::WEXITED);
        let p_all_ok = r2 == 0 && info2.si_pid() == pid2 && info2.si_status() == 17;
        report!(waitid_p_all_ok = p_all_ok);
    }

    // 7.3 waitid invalid idtype -> EINVAL
    let mut info_bad: libc::siginfo_t = std::mem::zeroed();
    let r_bad_id = libc::waitid(999, 0, &mut info_bad, libc::WEXITED);
    report!(waitid_invalid_idtype_einval = r_bad_id == -1 && errno() == libc::EINVAL);

    // 7.4 waitid invalid options (0) -> EINVAL
    let r_bad_opt = libc::waitid(libc::P_PID, 1, &mut info_bad, 0);
    report!(waitid_invalid_options_einval = r_bad_opt == -1 && errno() == libc::EINVAL);

    // 7.5 waitid on non-child pid -> ECHILD
    let r_echild = libc::waitid(libc::P_PID, 999999, &mut info_bad, libc::WEXITED);
    report!(waitid_non_child_echild = r_echild == -1 && errno() == libc::ECHILD);
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--spawn-exec-helper" {
        unsafe {
            run_spawn_exec_helper();
        }
        return;
    }

    let pid = unsafe { libc::getpid() };
    let base = format!("/tmp/spawnflagmatrix_{pid}");
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::create_dir_all(&base);
    let _guard = DirGuard(base.clone());

    unsafe {
        test_close_range_matrix(&base);
        test_fcntl_matrix(&base);
        test_dup_matrix(&base);
        test_pipe2_matrix(&base);
        test_prctl_matrix();
        test_execve_inheritance_matrix(&base);
        test_wait_matrix();
    }
}
