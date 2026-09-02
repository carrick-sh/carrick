//! A sibling's exit must not release a parent parked in a cross-process
//! `FUTEX_WAIT`. This is LTP `pause01`'s shape — `tst_checkpoint_wait`/
//! `tst_checkpoint_wake` under repeated fork — with the sibling's exit pinned
//! to the moment the parent enters its next wait:
//!
//!   parent: FUTEX_WAIT(word, 0)          child N:   FUTEX_WAKE(word) until
//!           kill(child N, sig)                       the summed count == 1
//!           fork child N+1                          park for the signal
//!           release child N                         read the release byte
//!           FUTEX_WAIT(word, 0) ...                 _exit(0)
//!
//! The futex word lives in a `MAP_SHARED` mapping and is NEVER modified, so
//! the parent's wait can only legitimately end on a counted `FUTEX_WAKE`.
//! Children are NOT reaped between rounds (pause01 reaps in cleanup); child
//! N's `exit_group` — and the child-exit event it posts to the parent — lands
//! while the parent is entering or already parked in round N+1's wait. Linux
//! keeps those two events apart: the exit never wakes the futex waiter, so
//! child N+1's first wake that finds the parent parked returns exactly 1 and
//! its loop terminates. A runtime that treats the sibling's exit as a wake
//! edge resumes the parent with 0 and no counted producer; child N+1's wakes
//! then all return 0 and its loop spins to its budget — `ltp-pause01`
//! reported that as TBROK `tst_checkpoint_wake` ETIMEDOUT.
//!
//! Output (deterministic, order-independent facts only): the parent's wait
//! result, the first non-zero `FUTEX_WAKE` count the child saw, the maximum
//! count, whether its loop terminated, and every child's final exit status.
//! The number of zero-count attempts before the parent parks is
//! scheduling-dependent and deliberately not shown.

use std::sync::atomic::{AtomicBool, Ordering, compiler_fence};

// Per-target: libc resolves to 98 on aarch64-linux, 202 on x86_64-linux.
const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_WAIT: libc::c_int = 0; // shared (no FUTEX_PRIVATE_FLAG)
const FUTEX_WAKE: libc::c_int = 1;
/// pause01 walks the catchable signals; the identity of the signal is
/// irrelevant to the invariant, the per-round handler + park shape is.
const ROUND_SIGNALS: [libc::c_int; 12] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGUSR1,
    libc::SIGUSR2,
];
/// `tst_checkpoint_wake` budgets 10 s at 1 ms per attempt; two seconds is
/// ample to distinguish "never counted" from "not parked yet".
const WAKE_ATTEMPTS: usize = 2_000;

static HANDLED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    HANDLED.store(true, Ordering::SeqCst);
}

unsafe fn futex_wait(uaddr: *mut u32, val: u32, timeout: &libc::timespec) -> libc::c_long {
    libc::syscall(SYS_FUTEX, uaddr, FUTEX_WAIT, val, timeout as *const _)
}

unsafe fn futex_wake(uaddr: *mut u32, count: u32) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        uaddr,
        FUTEX_WAKE,
        count,
        std::ptr::null::<libc::timespec>(),
    )
}

/// Child side: install the round's handler, run the `tst_checkpoint_wake`
/// loop, report `(first_nonzero, max, terminated)` through `report_fd` as
/// three little-endian i64s, park until the parent's signal, then hold the
/// exit until the parent's release byte arrives on `release_fd`. The park is
/// `sigsuspend` with the round's signal blocked up to that point rather than
/// pause01's bare `pause()`: the parent may deliver the signal between the
/// report and the park, and a `pause()` entered after the handler already
/// ran would sleep forever. That window is the probe's own race, not the
/// futex invariant under test, so it is closed atomically here.
unsafe fn child(
    word: *mut u32,
    sig: libc::c_int,
    report_fd: libc::c_int,
    release_fd: libc::c_int,
) -> ! {
    libc::signal(sig, on_signal as *const () as libc::sighandler_t);
    let mut block: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut block);
    libc::sigaddset(&mut block, sig);
    let mut park: libc::sigset_t = std::mem::zeroed();
    libc::sigprocmask(libc::SIG_BLOCK, &block, &mut park);
    libc::sigdelset(&mut park, sig);
    let mut waked: i64 = 0;
    let mut first_nonzero: i64 = -1;
    let mut max: i64 = 0;
    let mut terminated = false;
    for _ in 0..WAKE_ATTEMPTS {
        let rc = futex_wake(word, u32::MAX) as i64;
        if rc > 0 && first_nonzero < 0 {
            first_nonzero = rc;
        }
        if rc > max {
            max = rc;
        }
        waked += rc;
        if waked == 1 {
            terminated = true;
            break;
        }
        libc::usleep(1000);
    }
    let report = [first_nonzero, max, terminated as i64];
    let bytes: [u8; 24] = std::mem::transmute(report);
    let _ = libc::write(report_fd, bytes.as_ptr().cast(), bytes.len());
    libc::close(report_fd);
    libc::sigsuspend(&park);
    let mut release = 0u8;
    loop {
        let n = libc::read(release_fd, (&mut release as *mut u8).cast(), 1);
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
    libc::_exit(if HANDLED.load(Ordering::SeqCst) { 0 } else { 2 });
}

unsafe fn read_report(fd: libc::c_int) -> (i64, i64, bool) {
    let mut bytes = [0u8; 24];
    let mut got = 0usize;
    while got < bytes.len() {
        let n = libc::read(fd, bytes.as_mut_ptr().add(got).cast(), bytes.len() - got);
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    if got < bytes.len() {
        return (-2, -2, false);
    }
    let report: [i64; 3] = std::mem::transmute(bytes);
    (report[0], report[1], report[2] == 1)
}

fn main() {
    unsafe {
        let map = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if map == libc::MAP_FAILED {
            println!("setup=false");
            return;
        }
        let word = map as *mut u32;
        *word = 0;
        compiler_fence(Ordering::SeqCst);
        println!("setup=true");

        // (round, pid, release-pipe write end) of every child still holding
        // its exit; each is released right before the NEXT round's wait so
        // its `exit_group` lands on the parent's park.
        let mut children: Vec<(usize, libc::pid_t, libc::c_int)> = Vec::new();
        for (round, sig) in ROUND_SIGNALS.iter().copied().enumerate() {
            let mut report = [-1, -1];
            let mut release = [-1, -1];
            if libc::pipe(report.as_mut_ptr()) != 0 || libc::pipe(release.as_mut_ptr()) != 0 {
                println!("round={round} pipe=false");
                break;
            }
            let pid = libc::fork();
            if pid == 0 {
                libc::close(report[0]);
                libc::close(release[1]);
                for (_, _, sibling_release) in &children {
                    libc::close(*sibling_release);
                }
                child(word, sig, report[1], release[0]);
            }
            libc::close(report[1]);
            libc::close(release[0]);
            if pid < 0 {
                libc::close(report[0]);
                libc::close(release[1]);
                println!("round={round} fork=false");
                break;
            }
            if let Some((_, _, previous_release)) = children.last() {
                let _ = libc::write(*previous_release, b"x".as_ptr().cast(), 1);
            }
            children.push((round, pid, release[1]));

            let timeout = libc::timespec {
                tv_sec: 10,
                tv_nsec: 0,
            };
            let rc = futex_wait(word, 0, &timeout);
            let errno = if rc < 0 { *libc::__errno_location() } else { 0 };
            let wait = match (rc, errno) {
                (0, _) => "woken".to_string(),
                (_, e) if e == libc::ETIMEDOUT => "timeout".to_string(),
                (_, e) => format!("errno{e}"),
            };

            // The child's loop terminates only once its count reaches one,
            // so its report is the ground truth for what FUTEX_WAKE returned.
            let (first_nonzero, max, terminated) = read_report(report[0]);
            libc::close(report[0]);
            println!(
                "round={round} wait={wait} wake_first_nonzero={first_nonzero} wake_max={max} \
                 wake_loop_terminated={terminated}"
            );

            // pause01: signal the parked child and go straight to the next
            // fork — the exit is left to land on its own.
            libc::kill(pid, sig);
        }

        if let Some((_, _, last_release)) = children.last() {
            let _ = libc::write(*last_release, b"x".as_ptr().cast(), 1);
        }
        for (round, pid, release_fd) in children {
            let mut status = 0i32;
            let rc = libc::waitpid(pid, &mut status, 0);
            let exit = if rc != pid {
                format!("waitpid_errno{}", *libc::__errno_location())
            } else if libc::WIFSIGNALED(status) {
                format!("sig{}", libc::WTERMSIG(status))
            } else {
                format!("exit{}", libc::WEXITSTATUS(status))
            };
            libc::close(release_fd);
            println!("round={round} child={exit}");
        }
        libc::munmap(map, 4096);
    }
}
