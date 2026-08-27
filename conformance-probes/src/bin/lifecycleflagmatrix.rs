//! Process lifecycle, identity, and process-control flag and error matrix probe.
//!
//! Exercises Linux flag combinations, error returns, identity invariants, and
//! parent/child state interactions across:
//! 1. `clone(2)` and `clone3(2)` flag matrix (CLONE_THREAD without CLONE_SIGHAND -> EINVAL,
//!    CLONE_SIGHAND without CLONE_VM -> EINVAL, CLONE_PARENT with CLONE_THREAD -> EINVAL,
//!    invalid exit signal in CSIGNAL mask -> EINVAL, CLONE_FS with CLONE_NEWNS -> EINVAL,
//!    CLONE_PARENT_SETTID writeback, and clone3 argument/flag bounds).
//! 2. `fork(2)` state invariants (PID relationships, signal handler/mask preservation vs
//!    pending signal isolation, open file description & offset sharing, FD_CLOEXEC
//!    inheritance, and COW memory isolation).
//! 3. Process & thread identity (getpid consistency, getppid in direct child and
//!    grandchild orphan reparenting, gettid in main vs child vs cloned subthread).
//! 4. `pidfd_open(2)` & `pidfd_send_signal(2)` matrix (invalid flags -> EINVAL, invalid
//!    PIDs -> EINVAL/ESRCH, dead process ESRCH, signal delivery, siginfo mismatch -> EINVAL,
//!    non-pidfd descriptors -> EINVAL, bad fd -> EBADF, and waitid(P_PIDFD)).
//! 5. `process_vm_readv(2)` & `process_vm_writev(2)` matrix (invalid flags/iovcnt/pids ->
//!    EINVAL/ESRCH, zero-length transfers, self read/write, cross-process child read/write,
//!    and unmapped/read-only memory fault handling -> EFAULT).
//! 6. `ptrace(2)` error & access matrix (PTRACE_ATTACH to self/init/negative -> EPERM/ESRCH,
//!    invalid request -> EIO, detach/cont on untraced process -> ESRCH, and
//!    duplicate PTRACE_TRACEME -> EPERM).
//! 7. `setns(2)` error matrix (invalid fd -> EBADF, non-ns fd -> EINVAL, invalid nstype ->
//!    EINVAL, mismatched nstype vs fd -> EINVAL, and nstype=0 wildcards).
//! 8. `setsid(2)`, `getsid(2)`, `setpgid(2)`, and `getpgid(2)` matrix (session leader
//!    setsid/setpgid -> EPERM, child setsid -> new sid/pgid, child setpgid(0, 0), cross-session
//!    or invalid pgid -> EPERM, getsid/getpgid error and query paths).
//! 9. Process control & `waitid(2)` lifecycle (PR_SET_PDEATHSIG/PR_GET_PDEATHSIG error &
//!    roundtrip, PR_SET_NAME/PR_GET_NAME, waitid invalid idtype/options -> EINVAL, WNOWAIT
//!    non-destructive inspection + clean reap, WNOHANG empty poll, and P_PGID waits).
//!
//! Deterministic boolean/key-value output only. Exact assertions on Linux/aarch64 defined errnos.
//! All parent-child operations use bounded monotonic timeouts and scoped SIGKILL cleanup.
//! Filesystem paths use per-process unique names with explicit unlink cleanup before and after use.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::mem::{size_of, MaybeUninit};
use std::time::{Duration, Instant};

const SYS_GETTID: libc::c_long = 178;
const SYS_SETNS: libc::c_long = 268;
const SYS_PROCESS_VM_READV: libc::c_long = 270;
const SYS_PROCESS_VM_WRITEV: libc::c_long = 271;
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_CLONE3: libc::c_long = 435;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_PARENT: u64 = 0x0000_8000;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;

const PR_SET_PDEATHSIG: libc::c_int = 1;
const PR_GET_PDEATHSIG: libc::c_int = 2;
const PR_SET_NAME: libc::c_int = 15;
const PR_GET_NAME: libc::c_int = 16;

const P_ALL: libc::idtype_t = 0;
const P_PID: libc::idtype_t = 1;
const P_PGID: libc::idtype_t = 2;
const P_PIDFD: libc::idtype_t = 3;

const WNOHANG: libc::c_int = 1;
const WEXITED: libc::c_int = 4;
const WNOWAIT: libc::c_int = 0x0100_0000;

const CLD_EXITED: libc::c_int = 1;

const DEFAULT_DEADLINE: Duration = Duration::from_millis(500);
const CLEANUP_DEADLINE: Duration = Duration::from_millis(200);

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

unsafe fn raw_clone(flags: u64, ptid: *mut i32, ctid: *mut i32) -> i64 {
    libc::syscall(
        libc::SYS_clone,
        flags as libc::c_long,
        core::ptr::null_mut::<libc::c_void>(),
        ptid,
        core::ptr::null_mut::<libc::c_void>(),
        ctid,
    ) as i64
}

fn poll_readable(fd: i32, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms.max(1)) };
        if rc > 0 {
            return pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn poll_writable(fd: i32, deadline: Instant) -> bool {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms.max(1)) };
        if rc > 0 {
            return pfd.revents & libc::POLLOUT != 0;
        }
        if rc == -1 && errno() == libc::EINTR {
            continue;
        }
        return false;
    }
}

fn read_exact_bounded(fd: i32, bytes: &mut [u8], deadline: Instant) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        if !poll_readable(fd, deadline) {
            return false;
        }
        let rc = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if rc > 0 {
            offset += rc as usize;
        } else if rc == 0 || (rc == -1 && errno() != libc::EINTR) {
            return false;
        }
    }
    true
}

fn write_exact_bounded(fd: i32, bytes: &[u8], deadline: Instant) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        if !poll_writable(fd, deadline) {
            return false;
        }
        let rc = unsafe {
            libc::write(
                fd,
                bytes[offset..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if rc > 0 {
            offset += rc as usize;
        } else if rc == -1 && errno() != libc::EINTR {
            return false;
        }
    }
    true
}

unsafe fn waitpid_bounded(pid: libc::pid_t, deadline: Instant) -> Option<i32> {
    if pid <= 0 {
        return None;
    }
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return Some(status);
        }
        if rc == -1 {
            if errno() == libc::EINTR {
                continue;
            }
            return None;
        }
        if Instant::now() >= deadline {
            return None;
        }
        libc::usleep(500);
    }
}

unsafe fn cleanup_child_bounded(pid: libc::pid_t) {
    if pid <= 0 {
        return;
    }
    let mut status = 0;
    let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
    if rc == pid || (rc == -1 && errno() == libc::ECHILD) {
        return;
    }
    let _ = libc::kill(pid, libc::SIGKILL);
    let deadline = Instant::now() + CLEANUP_DEADLINE;
    loop {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid || (rc == -1 && errno() != libc::EINTR) || Instant::now() >= deadline {
            return;
        }
        libc::usleep(500);
    }
}

// -----------------------------------------------------------------------------
// 1. Clone & Clone3 Flag Matrix
// -----------------------------------------------------------------------------

unsafe fn test_clone_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 1.1 CLONE_THREAD without CLONE_SIGHAND -> EINVAL
    let r1 = raw_clone(
        CLONE_THREAD | (libc::SIGCHLD as u64),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if r1 == 0 {
        libc::_exit(0);
    }
    let r1_einval = r1 == -1 && errno() == libc::EINVAL;
    if r1 > 0 {
        let _ = waitpid_bounded(r1 as i32, deadline);
        cleanup_child_bounded(r1 as i32);
    }

    // 1.2 CLONE_SIGHAND without CLONE_VM -> EINVAL
    let r2 = raw_clone(
        CLONE_SIGHAND | (libc::SIGCHLD as u64),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if r2 == 0 {
        libc::_exit(0);
    }
    let r2_einval = r2 == -1 && errno() == libc::EINVAL;
    if r2 > 0 {
        let _ = waitpid_bounded(r2 as i32, deadline);
        cleanup_child_bounded(r2 as i32);
    }

    // 1.3 CLONE_PARENT with CLONE_THREAD -> EINVAL
    let r3 = raw_clone(
        CLONE_PARENT | CLONE_THREAD | CLONE_VM | CLONE_SIGHAND | (libc::SIGCHLD as u64),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if r3 == 0 {
        libc::_exit(0);
    }
    let r3_einval = r3 == -1 && errno() == libc::EINVAL;
    if r3 > 0 {
        let _ = waitpid_bounded(r3 as i32, deadline);
        cleanup_child_bounded(r3 as i32);
    }

    // 1.4 Invalid exit signal in CSIGNAL mask -> EINVAL
    let r4 = raw_clone(
        CLONE_VM | 0xff,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if r4 == 0 {
        libc::_exit(0);
    }
    let r4_einval = r4 == -1 && errno() == libc::EINVAL;
    if r4 > 0 {
        let _ = waitpid_bounded(r4 as i32, deadline);
        cleanup_child_bounded(r4 as i32);
    }

    // 1.5 CLONE_FS with CLONE_NEWNS -> EINVAL
    let r5 = raw_clone(
        CLONE_FS | CLONE_NEWNS | (libc::SIGCHLD as u64),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if r5 == 0 {
        libc::_exit(0);
    }
    let r5_einval = r5 == -1 && errno() == libc::EINVAL;
    if r5 > 0 {
        let _ = waitpid_bounded(r5 as i32, deadline);
        cleanup_child_bounded(r5 as i32);
    }

    // 1.6 CLONE_PARENT_SETTID writeback
    let mut ptid: i32 = -1;
    let r6 = raw_clone(
        CLONE_PARENT_SETTID | (libc::SIGCHLD as u64),
        &mut ptid,
        core::ptr::null_mut(),
    );
    let r6_ok = if r6 == 0 {
        libc::_exit(0);
    } else if r6 > 0 {
        let wait_res = waitpid_bounded(r6 as i32, deadline);
        cleanup_child_bounded(r6 as i32);
        ptid == r6 as i32
            && matches!(wait_res, Some(st) if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0)
    } else {
        false
    };

    // 1.7 clone3 argument validation (Linux exact error: EINVAL)
    let mut cargs = CloneArgs {
        flags: 0,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let c3_small = libc::syscall(SYS_CLONE3, &mut cargs, 8usize) as i64;
    let c3_small_er = errno();
    let c3_small_ok = c3_small == -1 && c3_small_er == libc::EINVAL;

    let mut cargs_bad_flags = CloneArgs {
        flags: 1 << 63,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let c3_bad_flags =
        libc::syscall(SYS_CLONE3, &mut cargs_bad_flags, size_of::<CloneArgs>()) as i64;
    let c3_bad_flags_er = errno();
    let c3_bad_flags_ok = c3_bad_flags == -1 && c3_bad_flags_er == libc::EINVAL;

    let mut cargs_bad_stack = CloneArgs {
        flags: 0,
        stack: 0,
        stack_size: 4096,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let c3_bad_stack =
        libc::syscall(SYS_CLONE3, &mut cargs_bad_stack, size_of::<CloneArgs>()) as i64;
    let c3_bad_stack_er = errno();
    let c3_bad_stack_ok = c3_bad_stack == -1 && c3_bad_stack_er == libc::EINVAL;

    let mut cargs_bad_sig = CloneArgs {
        flags: 0,
        exit_signal: 255,
        ..CloneArgs::default()
    };
    let c3_bad_sig = libc::syscall(SYS_CLONE3, &mut cargs_bad_sig, size_of::<CloneArgs>()) as i64;
    let c3_bad_sig_er = errno();
    let c3_bad_sig_ok = c3_bad_sig == -1 && c3_bad_sig_er == libc::EINVAL;

    report!(
        clone_thread_no_sighand_einval = r1_einval,
        clone_sighand_no_vm_einval = r2_einval,
        clone_parent_with_thread_einval = r3_einval,
        clone_invalid_exit_signal_einval = r4_einval,
        clone_fs_with_newns_einval = r5_einval,
        clone_parent_settid_ok = r6_ok,
        clone3_size_truncated_einval = c3_small_ok,
        clone3_reserved_flags_einval = c3_bad_flags_ok,
        clone3_bad_stack_einval = c3_bad_stack_ok,
        clone3_bad_signal_einval = c3_bad_sig_ok,
    );
}

// -----------------------------------------------------------------------------
// 2. Fork State Invariants & Inheritance
// -----------------------------------------------------------------------------

extern "C" fn custom_usr1_handler(_sig: libc::c_int) {}

unsafe fn test_fork_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 2.1 Basic fork return value
    let pid1 = libc::fork();
    let fork_basic_ok = if pid1 == 0 {
        libc::_exit(0);
    } else if pid1 > 0 {
        let wait_res = waitpid_bounded(pid1, deadline);
        cleanup_child_bounded(pid1);
        matches!(wait_res, Some(status) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
    } else {
        false
    };

    // 2.2 Signal inheritance across fork:
    // - Custom handler for SIGUSR1
    // - Blocked mask for SIGUSR2
    // - Pending signal SIGUSR2 in parent
    let mut sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    sa.sa_sigaction = custom_usr1_handler as *const () as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut());

    let mut set: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGUSR2);
    libc::sigprocmask(libc::SIG_BLOCK, &set, core::ptr::null_mut());

    // Raise SIGUSR2 so it becomes pending in parent
    libc::raise(libc::SIGUSR2);

    let mut pipe_sig = [0i32; 2];
    libc::pipe(pipe_sig.as_mut_ptr());

    let pid2 = libc::fork();
    if pid2 == 0 {
        libc::close(pipe_sig[0]);
        let mut cur_sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
        libc::sigaction(libc::SIGUSR1, core::ptr::null(), &mut cur_sa);
        let handler_match = cur_sa.sa_sigaction == custom_usr1_handler as *const () as usize;

        let mut cur_mask: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigprocmask(libc::SIG_SETMASK, core::ptr::null(), &mut cur_mask);
        let mask_blocked = libc::sigismember(&cur_mask, libc::SIGUSR2) == 1;

        let mut pending: libc::sigset_t = MaybeUninit::zeroed().assume_init();
        libc::sigpending(&mut pending);
        let pending_cleared = libc::sigismember(&pending, libc::SIGUSR2) == 0;

        let result = [
            handler_match as u8,
            mask_blocked as u8,
            pending_cleared as u8,
        ];
        let _ = write_exact_bounded(pipe_sig[1], &result, deadline);
        libc::close(pipe_sig[1]);
        libc::_exit(0);
    }
    libc::close(pipe_sig[1]);
    let mut sig_res = [0u8; 3];
    let sig_read_ok = read_exact_bounded(pipe_sig[0], &mut sig_res, deadline);
    libc::close(pipe_sig[0]);
    if pid2 > 0 {
        let _ = waitpid_bounded(pid2, deadline);
        cleanup_child_bounded(pid2);
    }

    // Clean up parent signal state
    let mut unblock_set: libc::sigset_t = MaybeUninit::zeroed().assume_init();
    libc::sigemptyset(&mut unblock_set);
    libc::sigaddset(&mut unblock_set, libc::SIGUSR2);
    let mut ign_sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    ign_sa.sa_sigaction = libc::SIG_IGN;
    libc::sigaction(libc::SIGUSR2, &ign_sa, core::ptr::null_mut());
    libc::sigprocmask(libc::SIG_UNBLOCK, &unblock_set, core::ptr::null_mut());
    let mut dfl_sa: libc::sigaction = MaybeUninit::zeroed().assume_init();
    dfl_sa.sa_sigaction = libc::SIG_DFL;
    libc::sigaction(libc::SIGUSR1, &dfl_sa, core::ptr::null_mut());
    libc::sigaction(libc::SIGUSR2, &dfl_sa, core::ptr::null_mut());

    // 2.3 Open file table description & offset sharing across fork
    let tmp_path = format!("/tmp/carrick_fork_off_{}.tmp", std::process::id());
    let c_path = CString::new(tmp_path).unwrap();
    libc::unlink(c_path.as_ptr());
    let fd_file = libc::open(
        c_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    let mut fd_offset_shared = false;
    if fd_file >= 0 {
        let dummy = [0u8; 128];
        let _ = libc::write(fd_file, dummy.as_ptr().cast(), dummy.len());
        libc::lseek(fd_file, 10, libc::SEEK_SET);

        let pid3 = libc::fork();
        if pid3 == 0 {
            libc::lseek(fd_file, 30, libc::SEEK_CUR); // 10 + 30 = 40
            libc::close(fd_file);
            libc::_exit(0);
        }
        if pid3 > 0 {
            let _ = waitpid_bounded(pid3, deadline);
            cleanup_child_bounded(pid3);
        }
        let cur_off = libc::lseek(fd_file, 0, libc::SEEK_CUR);
        fd_offset_shared = cur_off == 40;
        libc::close(fd_file);
        libc::unlink(c_path.as_ptr());
    }

    // 2.4 FD_CLOEXEC flag inheritance
    let mut pipe_clo = [0i32; 2];
    libc::pipe(pipe_clo.as_mut_ptr());
    libc::fcntl(pipe_clo[0], libc::F_SETFD, libc::FD_CLOEXEC);

    let mut pipe_clo_out = [0i32; 2];
    libc::pipe(pipe_clo_out.as_mut_ptr());

    let pid4 = libc::fork();
    if pid4 == 0 {
        libc::close(pipe_clo_out[0]);
        let fl = libc::fcntl(pipe_clo[0], libc::F_GETFD);
        let is_clo = (fl & libc::FD_CLOEXEC) != 0;
        let _ = write_exact_bounded(pipe_clo_out[1], &[is_clo as u8], deadline);
        libc::close(pipe_clo_out[1]);
        libc::close(pipe_clo[0]);
        libc::close(pipe_clo[1]);
        libc::_exit(0);
    }
    libc::close(pipe_clo_out[1]);
    let mut clo_res = [0u8; 1];
    let clo_read_ok = read_exact_bounded(pipe_clo_out[0], &mut clo_res, deadline);
    libc::close(pipe_clo_out[0]);
    libc::close(pipe_clo[0]);
    libc::close(pipe_clo[1]);
    if pid4 > 0 {
        let _ = waitpid_bounded(pid4, deadline);
        cleanup_child_bounded(pid4);
    }

    // 2.5 Memory isolation (COW)
    let page = libc::mmap(
        core::ptr::null_mut(),
        4096,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    ) as *mut u8;
    let mut cow_isolated = false;
    if page != libc::MAP_FAILED as *mut u8 {
        *page = 0x42;
        let pid5 = libc::fork();
        if pid5 == 0 {
            *page = 0x99;
            let child_read = *page == 0x99;
            libc::_exit(if child_read { 0 } else { 1 });
        }
        let mut child_ok = false;
        if pid5 > 0 {
            let wait_res = waitpid_bounded(pid5, deadline);
            cleanup_child_bounded(pid5);
            child_ok = matches!(wait_res, Some(status) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        }
        let parent_still_42 = *page == 0x42;
        cow_isolated = child_ok && parent_still_42;
        libc::munmap(page as *mut libc::c_void, 4096);
    }

    report!(
        fork_basic_rc_positive = fork_basic_ok,
        fork_sig_handler_inherited = sig_read_ok && sig_res[0] == 1,
        fork_sig_mask_inherited = sig_read_ok && sig_res[1] == 1,
        fork_sig_pending_cleared = sig_read_ok && sig_res[2] == 1,
        fork_fd_offset_shared = fd_offset_shared,
        fork_cloexec_inherited = clo_read_ok && clo_res[0] == 1,
        fork_cow_isolated = cow_isolated,
    );
}

// -----------------------------------------------------------------------------
// 3. Process & Thread Identity Matrix
// -----------------------------------------------------------------------------

extern "C" fn subthread_fn(arg: *mut libc::c_void) -> *mut libc::c_void {
    let out = arg as *mut [i32; 2];
    unsafe {
        let tid = libc::syscall(SYS_GETTID) as i32;
        let pid = libc::getpid();
        (*out)[0] = tid;
        (*out)[1] = pid;
    }
    core::ptr::null_mut()
}

unsafe fn test_identity_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 3.1 getpid positive and repeat consistency
    let pid1 = libc::getpid();
    let pid2 = libc::getpid();
    let pid_positive = pid1 > 0;
    let pid_repeat_match = pid1 == pid2;

    // 3.2 getppid in direct child
    let mut pipe_ppid = [0i32; 2];
    libc::pipe(pipe_ppid.as_mut_ptr());
    let pid_child = libc::fork();
    if pid_child == 0 {
        libc::close(pipe_ppid[0]);
        let ppid = libc::getppid();
        let _ = write_exact_bounded(pipe_ppid[1], &ppid.to_ne_bytes(), deadline);
        libc::close(pipe_ppid[1]);
        libc::_exit(0);
    }
    libc::close(pipe_ppid[1]);
    let mut child_ppid_bytes = [0u8; 4];
    let ppid_read_ok = read_exact_bounded(pipe_ppid[0], &mut child_ppid_bytes, deadline);
    libc::close(pipe_ppid[0]);
    if pid_child > 0 {
        let _ = waitpid_bounded(pid_child, deadline);
        cleanup_child_bounded(pid_child);
    }
    let child_ppid = i32::from_ne_bytes(child_ppid_bytes);
    let child_ppid_matches = ppid_read_ok && child_ppid == pid1;

    // 3.3 gettid in main thread vs child vs pthread
    let main_tid = libc::syscall(SYS_GETTID) as i32;
    let main_tid_eq_pid = main_tid == pid1;

    let mut pipe_tid = [0i32; 2];
    libc::pipe(pipe_tid.as_mut_ptr());
    let pid_child2 = libc::fork();
    if pid_child2 == 0 {
        libc::close(pipe_tid[0]);
        let c_tid = libc::syscall(SYS_GETTID) as i32;
        let c_pid = libc::getpid();
        let mut res = [0u8; 8];
        res[..4].copy_from_slice(&c_tid.to_ne_bytes());
        res[4..].copy_from_slice(&c_pid.to_ne_bytes());
        let _ = write_exact_bounded(pipe_tid[1], &res, deadline);
        libc::close(pipe_tid[1]);
        libc::_exit(0);
    }
    libc::close(pipe_tid[1]);
    let mut child_tid_bytes = [0u8; 8];
    let tid_read_ok = read_exact_bounded(pipe_tid[0], &mut child_tid_bytes, deadline);
    libc::close(pipe_tid[0]);
    if pid_child2 > 0 {
        let _ = waitpid_bounded(pid_child2, deadline);
        cleanup_child_bounded(pid_child2);
    }
    let c_tid = i32::from_ne_bytes([
        child_tid_bytes[0],
        child_tid_bytes[1],
        child_tid_bytes[2],
        child_tid_bytes[3],
    ]);
    let c_pid = i32::from_ne_bytes([
        child_tid_bytes[4],
        child_tid_bytes[5],
        child_tid_bytes[6],
        child_tid_bytes[7],
    ]);
    let child_tid_eq_pid = tid_read_ok && c_tid == c_pid && c_tid == pid_child2;

    let mut thread_info = [0i32; 2];
    let mut th: libc::pthread_t = MaybeUninit::zeroed().assume_init();
    let th_created = libc::pthread_create(
        &mut th,
        core::ptr::null(),
        subthread_fn,
        thread_info.as_mut_ptr().cast(),
    ) == 0;
    if th_created {
        libc::pthread_join(th, core::ptr::null_mut());
    }
    let thread_tid_differs_pid = th_created
        && thread_info[1] == pid1
        && thread_info[0] != pid1
        && thread_info[0] > 0;

    // 3.4 getppid in orphaned grandchild reparented to init / subreaper
    let mut pipe_orphan = [0i32; 2];
    libc::pipe(pipe_orphan.as_mut_ptr());
    let mut pipe_sync = [0i32; 2];
    libc::pipe(pipe_sync.as_mut_ptr());

    let child_a = libc::fork();
    if child_a == 0 {
        libc::close(pipe_orphan[0]);
        libc::close(pipe_sync[1]);
        let grandchild = libc::fork();
        if grandchild == 0 {
            // Grandchild waits until child A exits and parent signals
            let mut b = [0u8; 1];
            let _ = read_exact_bounded(pipe_sync[0], &mut b, deadline);
            libc::close(pipe_sync[0]);
            let ppid = libc::getppid();
            let _ = write_exact_bounded(pipe_orphan[1], &ppid.to_ne_bytes(), deadline);
            libc::close(pipe_orphan[1]);
            libc::_exit(0);
        }
        libc::close(pipe_sync[0]);
        // Child A exits immediately to orphan grandchild
        libc::_exit(0);
    }
    libc::close(pipe_sync[0]);
    libc::close(pipe_orphan[1]);
    if child_a > 0 {
        let _ = waitpid_bounded(child_a, deadline);
        cleanup_child_bounded(child_a);
    }
    // Now tell grandchild parent is reaped
    let _ = write_exact_bounded(pipe_sync[1], b"k", deadline);
    libc::close(pipe_sync[1]);

    let mut orphan_ppid_bytes = [0u8; 4];
    let orphan_read_ok = read_exact_bounded(pipe_orphan[0], &mut orphan_ppid_bytes, deadline);
    libc::close(pipe_orphan[0]);
    let orphan_ppid = i32::from_ne_bytes(orphan_ppid_bytes);
    let orphan_reparent_ok = orphan_read_ok && orphan_ppid >= 1 && orphan_ppid != pid1;

    report!(
        getpid_positive = pid_positive,
        getpid_repeated_match = pid_repeat_match,
        child_getppid_matches_parent_pid = child_ppid_matches,
        main_gettid_eq_getpid = main_tid_eq_pid,
        child_gettid_eq_getpid = child_tid_eq_pid,
        thread_gettid_differs_getpid = thread_tid_differs_pid,
        orphan_reparent_ppid_is_init_or_subreaper = orphan_reparent_ok,
    );
}

// -----------------------------------------------------------------------------
// 4. PIDFD Matrix (pidfd_open, pidfd_send_signal, waitid P_PIDFD)
// -----------------------------------------------------------------------------

unsafe fn test_pidfd_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 4.1 pidfd_open error paths
    let r_bad_flags = libc::syscall(
        SYS_PIDFD_OPEN,
        libc::getpid() as libc::c_long,
        1i64 << 31,
    ) as i32;
    let er_bad_flags = errno();
    let pfd_flags_einval = r_bad_flags == -1 && er_bad_flags == libc::EINVAL;

    let r_zero = libc::syscall(SYS_PIDFD_OPEN, 0i64, 0i64) as i32;
    let er_zero = errno();
    let pfd_zero_einval = r_zero == -1 && er_zero == libc::EINVAL;

    let r_neg = libc::syscall(SYS_PIDFD_OPEN, -1i64, 0i64) as i32;
    let er_neg = errno();
    let pfd_neg_einval = r_neg == -1 && er_neg == libc::EINVAL;

    let r_nonexist = libc::syscall(SYS_PIDFD_OPEN, 999999i64, 0i64) as i32;
    let er_nonexist = errno();
    let pfd_nonexist_esrch = r_nonexist == -1 && er_nonexist == libc::ESRCH;

    // 4.2 pidfd_open valid child and self
    let mut pipe_wait = [0i32; 2];
    libc::pipe(pipe_wait.as_mut_ptr());
    let child_pid = libc::fork();
    if child_pid == 0 {
        libc::close(pipe_wait[1]);
        let mut b = [0u8; 1];
        let _ = read_exact_bounded(pipe_wait[0], &mut b, deadline);
        libc::close(pipe_wait[0]);
        libc::_exit(42);
    }
    libc::close(pipe_wait[0]);

    let pfd_child = libc::syscall(SYS_PIDFD_OPEN, child_pid as libc::c_long, 0i64) as i32;
    let pfd_child_ok = pfd_child >= 0;

    let pfd_self = libc::syscall(SYS_PIDFD_OPEN, libc::getpid() as libc::c_long, 0i64) as i32;
    let pfd_self_ok = pfd_self >= 0;
    if pfd_self >= 0 {
        libc::close(pfd_self);
    }

    // 4.3 pidfd_send_signal error matrix
    let mut pfd_sig_bad_flags = false;
    let mut pfd_sig_bad_sig = false;
    let mut pfd_sig_null_sig = false;
    let mut pfd_sig_mismatch = false;
    if pfd_child >= 0 {
        let r = libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pfd_child as libc::c_long,
            0i64,
            0i64,
            1i64 << 31,
        ) as i32;
        pfd_sig_bad_flags = r == -1 && errno() == libc::EINVAL;

        let r = libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pfd_child as libc::c_long,
            -1i64,
            0i64,
            0i64,
        ) as i32;
        pfd_sig_bad_sig = r == -1 && errno() == libc::EINVAL;

        let r = libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pfd_child as libc::c_long,
            0i64,
            0i64,
            0i64,
        ) as i32;
        pfd_sig_null_sig = r == 0;

        let mut si_bad: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        si_bad.si_signo = libc::SIGUSR2;
        let r = libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pfd_child as libc::c_long,
            libc::SIGUSR1 as libc::c_long,
            &si_bad as *const libc::siginfo_t,
            0i64,
        ) as i32;
        pfd_sig_mismatch = r == -1 && errno() == libc::EINVAL;
    }

    let mut pipe_non_pfd = [0i32; 2];
    libc::pipe(pipe_non_pfd.as_mut_ptr());
    let r_non_pfd = libc::syscall(
        SYS_PIDFD_SEND_SIGNAL,
        pipe_non_pfd[0] as libc::c_long,
        0i64,
        0i64,
        0i64,
    ) as i32;
    let er_non_pfd = errno();
    let pfd_non_pidfd_einval = r_non_pfd == -1 && er_non_pfd == libc::EINVAL;
    libc::close(pipe_non_pfd[0]);
    libc::close(pipe_non_pfd[1]);

    let r_bad_fd = libc::syscall(SYS_PIDFD_SEND_SIGNAL, -1i64, 0i64, 0i64, 0i64) as i32;
    let er_bad_fd = errno();
    let pfd_bad_fd_ebadf = r_bad_fd == -1 && er_bad_fd == libc::EBADF;

    // Release child to exit(42)
    let _ = write_exact_bounded(pipe_wait[1], b"x", deadline);
    libc::close(pipe_wait[1]);

    // 4.4 waitid(P_PIDFD, pfd_child, ...) with bounded loop
    let mut waitid_pfd_ok = false;
    let mut pfd_sig_reaped_esrch = false;
    let mut pfd_open_reaped_esrch = false;
    if pfd_child >= 0 {
        let reap_deadline = Instant::now() + DEFAULT_DEADLINE;
        loop {
            let mut si: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            let rc = libc::waitid(P_PIDFD, pfd_child as libc::id_t, &mut si, WEXITED | WNOHANG);
            if rc == 0 && si.si_pid() == child_pid {
                waitid_pfd_ok = si.si_code == CLD_EXITED && si.si_status() == 42;
                break;
            }
            if rc == -1 && errno() != libc::EINTR {
                break;
            }
            if Instant::now() >= reap_deadline {
                break;
            }
            libc::usleep(500);
        }

        // pidfd_send_signal after child reaped -> ESRCH
        let r_reaped = libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            pfd_child as libc::c_long,
            0i64,
            0i64,
            0i64,
        ) as i32;
        let er_reaped = errno();
        pfd_sig_reaped_esrch = r_reaped == -1 && er_reaped == libc::ESRCH;

        // pidfd_open on reaped child -> ESRCH
        let r_open_reaped =
            libc::syscall(SYS_PIDFD_OPEN, child_pid as libc::c_long, 0i64) as i32;
        let er_open_reaped = errno();
        pfd_open_reaped_esrch = r_open_reaped == -1 && er_open_reaped == libc::ESRCH;

        libc::close(pfd_child);
    }
    if child_pid > 0 {
        cleanup_child_bounded(child_pid);
    }

    report!(
        pidfd_open_invalid_flags_einval = pfd_flags_einval,
        pidfd_open_pid_zero_einval = pfd_zero_einval,
        pidfd_open_pid_neg_einval = pfd_neg_einval,
        pidfd_open_nonexistent_esrch = pfd_nonexist_esrch,
        pidfd_open_child_ok = pfd_child_ok,
        pidfd_open_self_ok = pfd_self_ok,
        pidfd_send_signal_invalid_flags_einval = pfd_sig_bad_flags,
        pidfd_send_signal_invalid_sig_einval = pfd_sig_bad_sig,
        pidfd_send_signal_null_sig_zero = pfd_sig_null_sig,
        pidfd_send_signal_siginfo_mismatch_einval = pfd_sig_mismatch,
        pidfd_send_signal_non_pidfd_einval = pfd_non_pidfd_einval,
        pidfd_send_signal_bad_fd_ebadf = pfd_bad_fd_ebadf,
        waitid_pidfd_reap_ok = waitid_pfd_ok,
        pidfd_send_signal_reaped_esrch = pfd_sig_reaped_esrch,
        pidfd_open_reaped_esrch = pfd_open_reaped_esrch,
    );
}

// -----------------------------------------------------------------------------
// 5. Process VM Read/Write Matrix (process_vm_readv, process_vm_writev)
// -----------------------------------------------------------------------------

unsafe fn test_process_vm_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    let mut buf_a = *b"HELLO_PROCESS_VM";
    let mut buf_b = [0u8; 16];
    let liov = libc::iovec {
        iov_base: buf_b.as_mut_ptr().cast(),
        iov_len: buf_b.len(),
    };
    let riov = libc::iovec {
        iov_base: buf_a.as_mut_ptr().cast(),
        iov_len: buf_a.len(),
    };

    // 5.1 Argument validation
    let r_bad_flags = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        1i64,
        &riov as *const libc::iovec,
        1i64,
        1i64,
    ) as i32;
    let pvm_bad_flags_einval = r_bad_flags == -1 && errno() == libc::EINVAL;

    let r_bad_liov = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        -1i64,
        &riov as *const libc::iovec,
        1i64,
        0i64,
    ) as i32;
    let pvm_bad_liov_einval = r_bad_liov == -1 && errno() == libc::EINVAL;

    let r_bad_riov = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        1i64,
        &riov as *const libc::iovec,
        -1i64,
        0i64,
    ) as i32;
    let pvm_bad_riov_einval = r_bad_riov == -1 && errno() == libc::EINVAL;

    let r_max_iov = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        1025i64,
        &riov as *const libc::iovec,
        1i64,
        0i64,
    ) as i32;
    let pvm_max_iov_einval = r_max_iov == -1 && errno() == libc::EINVAL;

    let r_zero_iov = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        0i64,
        &riov as *const libc::iovec,
        0i64,
        0i64,
    ) as isize;
    let pvm_zero_iov_zero = r_zero_iov == 0;

    let r_bad_pid = libc::syscall(
        SYS_PROCESS_VM_READV,
        999999i64,
        &liov as *const libc::iovec,
        1i64,
        &riov as *const libc::iovec,
        1i64,
        0i64,
    ) as i32;
    let pvm_nonexist_esrch = r_bad_pid == -1 && errno() == libc::ESRCH;

    // 5.2 Self-process read & write
    let r_self_read = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        1i64,
        &riov as *const libc::iovec,
        1i64,
        0i64,
    ) as isize;
    let pvm_self_read_ok = r_self_read == 16 && buf_b == buf_a;

    let mut buf_c = *b"WORLD_PROCESS_VM";
    let liov_write = libc::iovec {
        iov_base: buf_c.as_mut_ptr().cast(),
        iov_len: buf_c.len(),
    };
    let riov_target = libc::iovec {
        iov_base: buf_b.as_mut_ptr().cast(),
        iov_len: buf_b.len(),
    };
    let r_self_write = libc::syscall(
        SYS_PROCESS_VM_WRITEV,
        libc::getpid() as libc::c_long,
        &liov_write as *const libc::iovec,
        1i64,
        &riov_target as *const libc::iovec,
        1i64,
        0i64,
    ) as isize;
    let pvm_self_write_ok = r_self_write == 16 && buf_b == buf_c;

    // 5.3 Cross-process child read & write
    let mut pipe_pvm_addr = [0i32; 2];
    libc::pipe(pipe_pvm_addr.as_mut_ptr());
    let mut pipe_pvm_ack = [0i32; 2];
    libc::pipe(pipe_pvm_ack.as_mut_ptr());

    let child_pvm = libc::fork();
    if child_pvm == 0 {
        libc::close(pipe_pvm_addr[0]);
        libc::close(pipe_pvm_ack[1]);
        let mut child_buf = *b"CHILD_DATA_12345";
        let addr = child_buf.as_mut_ptr() as usize;
        let _ = write_exact_bounded(pipe_pvm_addr[1], &addr.to_ne_bytes(), deadline);
        libc::close(pipe_pvm_addr[1]);

        let mut b = [0u8; 1];
        let _ = read_exact_bounded(pipe_pvm_ack[0], &mut b, deadline);
        libc::close(pipe_pvm_ack[0]);

        let updated_ok = &child_buf == b"PARENT_OVERWRITE";
        libc::_exit(if updated_ok { 0 } else { 1 });
    }
    libc::close(pipe_pvm_addr[1]);
    libc::close(pipe_pvm_ack[0]);

    let mut remote_addr_bytes = [0u8; size_of::<usize>()];
    let addr_read_ok = read_exact_bounded(pipe_pvm_addr[0], &mut remote_addr_bytes, deadline);
    libc::close(pipe_pvm_addr[0]);
    let remote_addr = usize::from_ne_bytes(remote_addr_bytes);

    let mut child_read_out = [0u8; 16];
    let liov_from_child = libc::iovec {
        iov_base: child_read_out.as_mut_ptr().cast(),
        iov_len: child_read_out.len(),
    };
    let riov_in_child = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: 16,
    };
    let r_pvm_read_child = if addr_read_ok && remote_addr != 0 {
        libc::syscall(
            SYS_PROCESS_VM_READV,
            child_pvm as libc::c_long,
            &liov_from_child as *const libc::iovec,
            1i64,
            &riov_in_child as *const libc::iovec,
            1i64,
            0i64,
        ) as isize
    } else {
        -1
    };
    let pvm_read_child_ok =
        r_pvm_read_child == 16 && &child_read_out == b"CHILD_DATA_12345";

    let mut parent_write_data = *b"PARENT_OVERWRITE";
    let liov_to_child = libc::iovec {
        iov_base: parent_write_data.as_mut_ptr().cast(),
        iov_len: parent_write_data.len(),
    };
    let r_pvm_write_child = if addr_read_ok && remote_addr != 0 {
        libc::syscall(
            SYS_PROCESS_VM_WRITEV,
            child_pvm as libc::c_long,
            &liov_to_child as *const libc::iovec,
            1i64,
            &riov_in_child as *const libc::iovec,
            1i64,
            0i64,
        ) as isize
    } else {
        -1
    };
    let pvm_write_child_ok = r_pvm_write_child == 16;

    let _ = write_exact_bounded(pipe_pvm_ack[1], b"w", deadline);
    libc::close(pipe_pvm_ack[1]);

    let mut child_exit_ok = false;
    if child_pvm > 0 {
        let wait_res = waitpid_bounded(child_pvm, deadline);
        cleanup_child_bounded(child_pvm);
        child_exit_ok = matches!(wait_res, Some(status) if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    // 5.4 Memory fault handling
    let bad_riov = libc::iovec {
        iov_base: 0x1000 as *mut libc::c_void,
        iov_len: 16,
    };
    let r_bad_rem = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &liov as *const libc::iovec,
        1i64,
        &bad_riov as *const libc::iovec,
        1i64,
        0i64,
    ) as i32;
    let pvm_bad_remote_efault = r_bad_rem == -1 && errno() == libc::EFAULT;

    let bad_liov = libc::iovec {
        iov_base: 0x1000 as *mut libc::c_void,
        iov_len: 16,
    };
    let r_bad_loc = libc::syscall(
        SYS_PROCESS_VM_READV,
        libc::getpid() as libc::c_long,
        &bad_liov as *const libc::iovec,
        1i64,
        &riov as *const libc::iovec,
        1i64,
        0i64,
    ) as i32;
    let pvm_bad_local_efault = r_bad_loc == -1 && errno() == libc::EFAULT;

    report!(
        process_vm_readv_bad_flags_einval = pvm_bad_flags_einval,
        process_vm_readv_bad_liovcnt_einval = pvm_bad_liov_einval,
        process_vm_readv_bad_riovcnt_einval = pvm_bad_riov_einval,
        process_vm_readv_max_iovcnt_einval = pvm_max_iov_einval,
        process_vm_readv_zero_iovcnt_zero = pvm_zero_iov_zero,
        process_vm_readv_nonexistent_esrch = pvm_nonexist_esrch,
        process_vm_readv_self_ok = pvm_self_read_ok,
        process_vm_writev_self_ok = pvm_self_write_ok,
        process_vm_readv_child_ok = pvm_read_child_ok,
        process_vm_writev_child_ok = pvm_write_child_ok && child_exit_ok,
        process_vm_readv_bad_remote_efault = pvm_bad_remote_efault,
        process_vm_readv_bad_local_efault = pvm_bad_local_efault,
    );
}

// -----------------------------------------------------------------------------
// 6. Ptrace Error & Access Matrix (ptrace11)
// -----------------------------------------------------------------------------

unsafe fn test_ptrace_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 6.1 Attachment errors
    let r_self = libc::ptrace(
        libc::PTRACE_ATTACH,
        libc::getpid(),
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let pt_attach_self_eperm = r_self == -1 && errno() == libc::EPERM;

    let r_init = libc::ptrace(
        libc::PTRACE_ATTACH,
        1,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let pt_attach_init_eperm = r_init == -1 && errno() == libc::EPERM;

    let r_zero = libc::ptrace(
        libc::PTRACE_ATTACH,
        0,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let er_zero = errno();
    let pt_attach_zero_esrch = r_zero == -1 && er_zero == libc::ESRCH;

    let r_neg = libc::ptrace(
        libc::PTRACE_ATTACH,
        -1,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let pt_attach_neg_esrch = r_neg == -1 && errno() == libc::ESRCH;

    let r_nonexist = libc::ptrace(
        libc::PTRACE_ATTACH,
        999999,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let pt_attach_nonexist_esrch = r_nonexist == -1 && errno() == libc::ESRCH;

    // 6.2 Invalid request codes & untraced detach/cont
    let mut pipe_pt = [0i32; 2];
    libc::pipe(pipe_pt.as_mut_ptr());
    let child_pt = libc::fork();
    if child_pt == 0 {
        libc::close(pipe_pt[1]);
        let mut b = [0u8; 1];
        let _ = read_exact_bounded(pipe_pt[0], &mut b, deadline);
        libc::close(pipe_pt[0]);
        libc::_exit(0);
    }
    libc::close(pipe_pt[0]);

    let r_inv_req = libc::ptrace(
        (-1i32) as _,
        child_pt,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let er_inv_req = errno();
    let pt_inv_req_eio = r_inv_req == -1 && er_inv_req == libc::EIO;

    let r_detach_unattached = libc::ptrace(
        libc::PTRACE_DETACH,
        child_pt,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let er_detach = errno();
    let pt_detach_unattached_esrch = r_detach_unattached == -1 && er_detach == libc::ESRCH;

    let r_cont_unattached = libc::ptrace(
        libc::PTRACE_CONT,
        child_pt,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    );
    let pt_cont_unattached_esrch = r_cont_unattached == -1 && errno() == libc::ESRCH;

    let _ = write_exact_bounded(pipe_pt[1], b"q", deadline);
    libc::close(pipe_pt[1]);
    if child_pt > 0 {
        let _ = waitpid_bounded(child_pt, deadline);
        cleanup_child_bounded(child_pt);
    }

    // 6.3 Traceme duplicate error
    let mut pipe_tm = [0i32; 2];
    libc::pipe(pipe_tm.as_mut_ptr());
    let child_tm = libc::fork();
    if child_tm == 0 {
        libc::close(pipe_tm[0]);
        let r1 = libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            core::ptr::null_mut::<libc::c_void>(),
            0,
        );
        let r2 = libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            core::ptr::null_mut::<libc::c_void>(),
            0,
        );
        let r2_er = errno();
        let tm_dup_eperm = r1 == 0 && r2 == -1 && r2_er == libc::EPERM;
        let _ = write_exact_bounded(pipe_tm[1], &[tm_dup_eperm as u8], deadline);
        libc::close(pipe_tm[1]);
        libc::_exit(0);
    }
    libc::close(pipe_tm[1]);
    let mut tm_res = [0u8; 1];
    let tm_read_ok = read_exact_bounded(pipe_tm[0], &mut tm_res, deadline);
    libc::close(pipe_tm[0]);
    if child_tm > 0 {
        let _ = waitpid_bounded(child_tm, deadline);
        cleanup_child_bounded(child_tm);
    }

    report!(
        ptrace_attach_self_eperm = pt_attach_self_eperm,
        ptrace_attach_init_eperm = pt_attach_init_eperm,
        ptrace_attach_zero_esrch = pt_attach_zero_esrch,
        ptrace_attach_neg_esrch = pt_attach_neg_esrch,
        ptrace_attach_nonexistent_esrch = pt_attach_nonexist_esrch,
        ptrace_invalid_request_eio = pt_inv_req_eio,
        ptrace_detach_unattached_esrch = pt_detach_unattached_esrch,
        ptrace_cont_unattached_esrch = pt_cont_unattached_esrch,
        ptrace_traceme_duplicate_eperm = tm_read_ok && tm_res[0] == 1,
    );
}

// -----------------------------------------------------------------------------
// 7. Namespace Error Matrix (setns02)
// -----------------------------------------------------------------------------

unsafe fn test_setns_matrix() {
    // 7.1 setns error paths
    let r_bad_fd = libc::syscall(SYS_SETNS, -1i64, 0i64) as i32;
    let setns_bad_fd_ebadf = r_bad_fd == -1 && errno() == libc::EBADF;

    let mut pipe_ns = [0i32; 2];
    libc::pipe(pipe_ns.as_mut_ptr());
    let r_non_ns = libc::syscall(SYS_SETNS, pipe_ns[0] as libc::c_long, 0i64) as i32;
    let setns_non_ns_einval = r_non_ns == -1 && errno() == libc::EINVAL;
    libc::close(pipe_ns[0]);
    libc::close(pipe_ns[1]);

    let c_uts = CString::new("/proc/self/ns/uts").unwrap();
    let fd_uts = libc::open(c_uts.as_ptr(), libc::O_RDONLY);
    let mut setns_bad_nstype_einval = false;
    let mut setns_mismatched_einval = false;
    let mut setns_zero_rc_zero = false;
    let mut setns_zero_errno = 0i32;
    if fd_uts >= 0 {
        let r_bad_nstype =
            libc::syscall(SYS_SETNS, fd_uts as libc::c_long, 0x1000_0000i64) as i32;
        setns_bad_nstype_einval = r_bad_nstype == -1 && errno() == libc::EINVAL;

        let r_mismatch = libc::syscall(
            SYS_SETNS,
            fd_uts as libc::c_long,
            CLONE_NEWIPC as libc::c_long,
        ) as i32;
        setns_mismatched_einval = r_mismatch == -1 && errno() == libc::EINVAL;

        let r_zero_nstype = libc::syscall(SYS_SETNS, fd_uts as libc::c_long, 0i64) as i32;
        let er_zero = if r_zero_nstype < 0 { errno() } else { 0 };
        setns_zero_rc_zero = r_zero_nstype == 0;
        setns_zero_errno = er_zero;

        libc::close(fd_uts);
    }

    report!(
        setns_bad_fd_ebadf = setns_bad_fd_ebadf,
        setns_non_ns_fd_einval = setns_non_ns_einval,
        setns_bad_nstype_einval = setns_bad_nstype_einval,
        setns_mismatched_nstype_einval = setns_mismatched_einval,
        setns_zero_nstype_rc_zero = setns_zero_rc_zero,
        setns_zero_nstype_errno = setns_zero_errno,
    );
}

// -----------------------------------------------------------------------------
// 8. Session & Process Group Matrix (setsid01, setpgid01)
// -----------------------------------------------------------------------------

unsafe fn test_session_pgid_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 8.1 setsid in child vs session leader
    let mut pipe_sid = [0i32; 2];
    libc::pipe(pipe_sid.as_mut_ptr());

    let parent_pgrp = libc::getpgrp();
    let child_sid_pid = libc::fork();
    if child_sid_pid == 0 {
        libc::close(pipe_sid[0]);
        let c_pid = libc::getpid();
        let sid = libc::setsid();
        let sid_ok = sid == c_pid;
        let pgrp_ok = libc::getpgrp() == c_pid;
        let getsid_ok = libc::getsid(0) == c_pid;

        // Second setsid in same process (now session leader) -> EPERM
        let sid2 = libc::setsid();
        let sid2_er = errno();
        let sid2_eperm = sid2 == -1 && sid2_er == libc::EPERM;

        let res = [
            sid_ok as u8,
            pgrp_ok as u8,
            getsid_ok as u8,
            sid2_eperm as u8,
        ];
        let _ = write_exact_bounded(pipe_sid[1], &res, deadline);
        libc::close(pipe_sid[1]);
        libc::_exit(0);
    }
    libc::close(pipe_sid[1]);
    let mut sid_res = [0u8; 4];
    let sid_read_ok = read_exact_bounded(pipe_sid[0], &mut sid_res, deadline);
    libc::close(pipe_sid[0]);
    if child_sid_pid > 0 {
        let _ = waitpid_bounded(child_sid_pid, deadline);
        cleanup_child_bounded(child_sid_pid);
    }

    // 8.2 getsid query
    let self_sid = libc::getsid(0);
    let getsid_self_ok = self_sid > 0 && self_sid == libc::getsid(libc::getpid());
    let getsid_neg = libc::getsid(-1);
    let getsid_neg_einval = getsid_neg == -1 && errno() == libc::EINVAL;
    let getsid_nonexist = libc::getsid(999999);
    let getsid_nonexist_esrch = getsid_nonexist == -1 && errno() == libc::ESRCH;

    // 8.3 setpgid error & lifecycle paths
    let setpgid_neg_pid = libc::setpgid(-1, 0);
    let setpgid_neg_pid_einval = setpgid_neg_pid == -1 && errno() == libc::EINVAL;

    let setpgid_neg_pgid = libc::setpgid(0, -1);
    let setpgid_neg_pgid_einval = setpgid_neg_pgid == -1 && errno() == libc::EINVAL;

    let setpgid_nonexist = libc::setpgid(999999, 0);
    let setpgid_nonexist_esrch = setpgid_nonexist == -1 && errno() == libc::ESRCH;

    let mut pipe_pgid = [0i32; 2];
    libc::pipe(pipe_pgid.as_mut_ptr());
    let child_pgid_pid = libc::fork();
    if child_pgid_pid == 0 {
        libc::close(pipe_pgid[0]);
        let c_pid = libc::getpid();
        // setpgid(0, 0) sets pgid to child pid
        let r0 = libc::setpgid(0, 0);
        let pgrp_is_cpid = r0 == 0 && libc::getpgrp() == c_pid;

        // setpgid(0, 999999) -> EPERM (not in same session)
        let r_bad_pgid = libc::setpgid(0, 999999);
        let r_bad_er = errno();
        let bad_pgid_eperm = r_bad_pgid == -1 && r_bad_er == libc::EPERM;

        // setpgid(0, parent_pgrp) -> joins parent group
        let r_parent = libc::setpgid(0, parent_pgrp);
        let joined_parent = r_parent == 0 && libc::getpgrp() == parent_pgrp;

        let res = [
            pgrp_is_cpid as u8,
            bad_pgid_eperm as u8,
            joined_parent as u8,
        ];
        let _ = write_exact_bounded(pipe_pgid[1], &res, deadline);
        libc::close(pipe_pgid[1]);
        libc::_exit(0);
    }
    libc::close(pipe_pgid[1]);
    let mut pgid_res = [0u8; 3];
    let pgid_read_ok = read_exact_bounded(pipe_pgid[0], &mut pgid_res, deadline);
    libc::close(pipe_pgid[0]);
    if child_pgid_pid > 0 {
        let _ = waitpid_bounded(child_pgid_pid, deadline);
        cleanup_child_bounded(child_pgid_pid);
    }

    // 8.4 getpgid query
    let self_pgrp = libc::getpgrp();
    let getpgid_zero_ok = libc::getpgid(0) == self_pgrp;
    let getpgid_self_ok = libc::getpgid(libc::getpid()) == self_pgrp;
    let getpgid_neg = libc::getpgid(-1);
    let getpgid_neg_einval = getpgid_neg == -1 && errno() == libc::EINVAL;
    let getpgid_nonexist = libc::getpgid(999999);
    let getpgid_nonexist_esrch = getpgid_nonexist == -1 && errno() == libc::ESRCH;

    report!(
        setsid_in_child_ok = sid_read_ok && sid_res[0] == 1,
        setsid_pgrp_updated = sid_read_ok && sid_res[1] == 1,
        setsid_getsid_updated = sid_read_ok && sid_res[2] == 1,
        setsid_leader_eperm = sid_read_ok && sid_res[3] == 1,
        getsid_zero_eq_self = getsid_self_ok,
        getsid_neg_einval = getsid_neg_einval,
        getsid_nonexistent_esrch = getsid_nonexist_esrch,
        setpgid_neg_pid_einval = setpgid_neg_pid_einval,
        setpgid_neg_pgid_einval = setpgid_neg_pgid_einval,
        setpgid_nonexistent_pid_esrch = setpgid_nonexist_esrch,
        setpgid_zero_zero_sets_pgrp = pgid_read_ok && pgid_res[0] == 1,
        setpgid_invalid_pgrp_eperm = pgid_read_ok && pgid_res[1] == 1,
        setpgid_join_parent_ok = pgid_read_ok && pgid_res[2] == 1,
        getpgid_zero_eq_pgrp = getpgid_zero_ok && getpgid_self_ok,
        getpgid_neg_einval = getpgid_neg_einval,
        getpgid_nonexistent_esrch = getpgid_nonexist_esrch,
    );
}

// -----------------------------------------------------------------------------
// 9. Process Control & Waitid Matrix
// -----------------------------------------------------------------------------

unsafe fn test_process_control_waitid_matrix() {
    let deadline = Instant::now() + DEFAULT_DEADLINE;

    // 9.1 prctl(PR_SET_PDEATHSIG)
    let r_pdeath_neg = libc::prctl(PR_SET_PDEATHSIG, -1, 0, 0, 0);
    let pdeath_neg_einval = r_pdeath_neg == -1 && errno() == libc::EINVAL;

    let r_pdeath_large = libc::prctl(PR_SET_PDEATHSIG, 1000, 0, 0, 0);
    let pdeath_large_einval = r_pdeath_large == -1 && errno() == libc::EINVAL;

    let r_pdeath_set = libc::prctl(PR_SET_PDEATHSIG, libc::SIGUSR1, 0, 0, 0);
    let mut sig_got = 0i32;
    let r_pdeath_get = libc::prctl(
        PR_GET_PDEATHSIG,
        &mut sig_got as *mut i32 as usize,
        0,
        0,
        0,
    );
    let pdeath_roundtrip_usr1 =
        r_pdeath_set == 0 && r_pdeath_get == 0 && sig_got == libc::SIGUSR1;

    let r_pdeath_clear = libc::prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0);
    let r_pdeath_get_zero = libc::prctl(
        PR_GET_PDEATHSIG,
        &mut sig_got as *mut i32 as usize,
        0,
        0,
        0,
    );
    let pdeath_clear_zero = r_pdeath_clear == 0 && r_pdeath_get_zero == 0 && sig_got == 0;

    // 9.2 prctl(PR_SET_NAME) & PR_GET_NAME
    let target_name = b"lifecycle_probe\0";
    let r_name_set = libc::prctl(PR_SET_NAME, target_name.as_ptr() as usize, 0, 0, 0);
    let mut name_buf = [0u8; 16];
    let r_name_get = libc::prctl(PR_GET_NAME, name_buf.as_mut_ptr() as usize, 0, 0, 0);
    let name_ok =
        r_name_set == 0 && r_name_get == 0 && &name_buf[..15] == b"lifecycle_probe";

    // 9.3 waitid argument validation & options
    let mut si: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let r_bad_idtype = libc::waitid(99, 0, &mut si, WEXITED);
    let waitid_bad_idtype_einval = r_bad_idtype == -1 && errno() == libc::EINVAL;

    let r_bad_opts = libc::waitid(P_ALL, 0, &mut si, 0);
    let waitid_bad_opts_einval = r_bad_opts == -1 && errno() == libc::EINVAL;

    // waitid with WNOWAIT then reap
    let mut pipe_wait = [0i32; 2];
    libc::pipe(pipe_wait.as_mut_ptr());
    let child_w = libc::fork();
    if child_w == 0 {
        libc::close(pipe_wait[1]);
        let mut b = [0u8; 1];
        let _ = read_exact_bounded(pipe_wait[0], &mut b, deadline);
        libc::close(pipe_wait[0]);
        libc::_exit(33);
    }
    libc::close(pipe_wait[0]);

    // Running child + WNOHANG -> returns 0 with si_pid == 0
    let mut si_run: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let r_run = libc::waitid(
        P_PID,
        child_w as libc::id_t,
        &mut si_run,
        WEXITED | WNOHANG,
    );
    let running_nohang_zero = r_run == 0 && si_run.si_pid() == 0;

    // Release child
    let _ = write_exact_bounded(pipe_wait[1], b"g", deadline);
    libc::close(pipe_wait[1]);

    // Inspect exit code with WNOWAIT (without reaping) in bounded loop
    let peek_deadline = Instant::now() + DEFAULT_DEADLINE;
    let mut peek_ok = false;
    loop {
        let mut si_peek: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        let r_peek = libc::waitid(
            P_PID,
            child_w as libc::id_t,
            &mut si_peek,
            WEXITED | WNOWAIT | WNOHANG,
        );
        if r_peek == 0 && si_peek.si_pid() == child_w {
            peek_ok = si_peek.si_code == CLD_EXITED && si_peek.si_status() == 33;
            break;
        }
        if r_peek == -1 && errno() != libc::EINTR {
            break;
        }
        if Instant::now() >= peek_deadline {
            break;
        }
        libc::usleep(500);
    }

    // Follow-up waitpid must successfully reap the child
    let reap_res = waitpid_bounded(child_w, deadline);
    let reap_ok = matches!(reap_res, Some(st) if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 33);
    cleanup_child_bounded(child_w);

    // All children reaped -> P_ALL + WNOHANG -> ECHILD
    let mut si_none: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let r_none = libc::waitid(P_ALL, 0, &mut si_none, WEXITED | WNOHANG);
    let no_children_echild = r_none == -1 && errno() == libc::ECHILD;

    // 9.4 waitid(P_PGID)
    let child_pgid = libc::fork();
    if child_pgid == 0 {
        libc::setpgid(0, 0);
        libc::_exit(55);
    }
    let pgid_deadline = Instant::now() + DEFAULT_DEADLINE;
    let mut waitid_p_pgid_ok = false;
    loop {
        let mut si_pgid: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        let r_pgid = libc::waitid(
            P_PGID,
            child_pgid as libc::id_t,
            &mut si_pgid,
            WEXITED | WNOHANG,
        );
        if r_pgid == 0 && si_pgid.si_pid() == child_pgid {
            waitid_p_pgid_ok = si_pgid.si_status() == 55;
            break;
        }
        if r_pgid == -1 && errno() != libc::EINTR {
            break;
        }
        if Instant::now() >= pgid_deadline {
            break;
        }
        libc::usleep(500);
    }
    cleanup_child_bounded(child_pgid);

    report!(
        prctl_pdeathsig_bad_neg_einval = pdeath_neg_einval,
        prctl_pdeathsig_bad_large_einval = pdeath_large_einval,
        prctl_pdeathsig_roundtrip_usr1 = pdeath_roundtrip_usr1,
        prctl_pdeathsig_clear_zero = pdeath_clear_zero,
        prctl_thread_name_roundtrip = name_ok,
        waitid_bad_idtype_einval = waitid_bad_idtype_einval,
        waitid_bad_options_einval = waitid_bad_opts_einval,
        waitid_running_child_nohang_zero = running_nohang_zero,
        waitid_wnowait_inspects_without_reap = peek_ok,
        waitid_after_wnowait_reap_clean = reap_ok,
        waitid_no_children_echild = no_children_echild,
        waitid_p_pgid_reap_ok = waitid_p_pgid_ok,
    );
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

fn main() {
    unsafe {
        test_clone_matrix();
        test_fork_matrix();
        test_identity_matrix();
        test_pidfd_matrix();
        test_process_vm_matrix();
        test_ptrace_matrix();
        test_setns_matrix();
        test_session_pgid_matrix();
        test_process_control_waitid_matrix();
    }
}
