//! waitrestart: when a signal interrupts a BLOCKING `wait4`, does carrick match
//! Linux's restart semantics? This is the framework-level blocker behind nearly
//! the whole LTP sweep: LTP's `tst_test` parent reaps its test child with
//! `SAFE_WAITPID(pid, &st, 0)`, and the test processes install SA_RESTART
//! handlers (SIGALRM/SIGUSR1 heartbeat+timeout). A signal landing during that
//! reap must RESTART the wait on Linux, not surface EINTR.
//!
//! DETERMINISTIC (no timing races): the child blocks on a pipe read and never
//! exits until the parent releases it, so `wait4` is GUARANTEED still blocking
//! when the (short, one-shot) alarm fires. Three scenarios, booleans only:
//!   A  SA_RESTART handler fires mid-wait -> wait restarts; the handler itself
//!      releases the child, so the restarted wait then reaps it (no EINTR).
//!   B  non-SA_RESTART handler fires mid-wait -> wait returns -1/EINTR (child
//!      still alive); the parent then releases + reaps it.
//!   C  the awaited child's own exit must NOT spuriously EINTR (no alarm armed).

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

static ALRM: AtomicU32 = AtomicU32::new(0);
// write-end of the child's release pipe; the SA_RESTART handler writes here to
// let the child exit so the restarted wait4 has something to reap.
static RELEASE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_alrm_release(_: i32) {
    ALRM.fetch_add(1, Ordering::SeqCst);
    let fd = RELEASE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = [b'x'];
        unsafe { libc::write(fd, b.as_ptr() as *const libc::c_void, 1) };
    }
}
extern "C" fn on_alrm_noop(_: i32) {
    ALRM.fetch_add(1, Ordering::SeqCst);
}

unsafe fn install(sig: i32, h: extern "C" fn(i32), flags: i32) {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = h as usize;
    sa.sa_flags = flags;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut());
}

unsafe fn arm_alarm_ms(ms: i64) {
    let it = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval {
            tv_sec: ms / 1000,
            tv_usec: (ms % 1000) * 1000,
        },
    };
    libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
}
unsafe fn disarm_alarm() {
    let it: libc::itimerval = std::mem::zeroed();
    libc::setitimer(libc::ITIMER_REAL, &it, std::ptr::null_mut());
}
unsafe fn reap(pid: i32) {
    loop {
        let mut st = 0i32;
        let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
}

/// Fork a child that blocks reading `read_fd` until the parent (or the alarm
/// handler) writes to `write_fd`. Returns (pid, write_fd).
unsafe fn spawn_blocked_child() -> (i32, i32) {
    let mut fds = [0i32; 2];
    libc::pipe(fds.as_mut_ptr());
    let pid = libc::fork();
    if pid == 0 {
        libc::close(fds[1]);
        let mut b = [0u8; 1];
        // Block until released, then exit cleanly.
        let _ = libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        libc::_exit(0);
    }
    libc::close(fds[0]);
    (pid, fds[1])
}

fn main() {
    unsafe {
        // A: SA_RESTART handler interrupts the blocking wait4. The handler
        // releases the child, so the RESTARTED wait4 reaps it -> returns pid,
        // never EINTR.
        ALRM.store(0, Ordering::SeqCst);
        let a = {
            let (pid, wfd) = spawn_blocked_child();
            RELEASE_FD.store(wfd, Ordering::SeqCst);
            install(libc::SIGALRM, on_alrm_release, libc::SA_RESTART);
            arm_alarm_ms(50);
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            disarm_alarm();
            RELEASE_FD.store(-1, Ordering::SeqCst);
            libc::close(wfd);
            r == pid && ALRM.load(Ordering::SeqCst) >= 1
        };
        println!("A_restart_reaps_child={a}");

        // B: non-SA_RESTART handler interrupts the blocking wait4 -> EINTR
        // (child still alive). Then release + reap.
        ALRM.store(0, Ordering::SeqCst);
        let b = {
            let (pid, wfd) = spawn_blocked_child();
            install(libc::SIGALRM, on_alrm_noop, 0);
            arm_alarm_ms(50);
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            let e = *libc::__errno_location();
            disarm_alarm();
            let got_eintr = r == -1 && e == libc::EINTR;
            let rel = [b'x'];
            libc::write(wfd, rel.as_ptr() as *const libc::c_void, 1);
            libc::close(wfd);
            reap(pid);
            got_eintr
        };
        println!("B_norestart_eintr={b}");

        // C: the awaited child's OWN release/exit must not spuriously EINTR (no
        // alarm armed). Release immediately; the blocking wait4 returns the pid.
        let c = {
            let (pid, wfd) = spawn_blocked_child();
            let rel = [b'x'];
            libc::write(wfd, rel.as_ptr() as *const libc::c_void, 1);
            libc::close(wfd);
            let mut st = 0i32;
            let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
            if r != pid {
                reap(pid);
            }
            r == pid
        };
        println!("C_child_exit_no_eintr={c}");
    }
}
