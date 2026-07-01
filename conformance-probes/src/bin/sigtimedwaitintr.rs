//! rt_sigtimedwait(2) interruption semantics — the kvm-lane LTP
//! sigtimedwait01/rt_sigtimedwait01/sigwaitinfo01 TIMEOUT cluster. Four
//! invariants (signal(7) + sigtimedwait(2)):
//!   1. A wait on an EMPTY set is interrupted by an unblocked CAUGHT signal:
//!      the handler runs and the call returns EINTR (never restarted, even
//!      under SA_RESTART).
//!   2. A wait-set signal is dequeued and returned as the signum — without
//!      running its handler — even while blocked (the canonical
//!      block-then-wait usage).
//!   3. A bounded empty-set wait with nothing pending times out with EAGAIN.
//!   4. A to-be-IGNORED signal (handler-less SIGCHLD from a dying child)
//!      neither interrupts the wait nor wakes it early.
//! carrick's park previously blocked `!wait_set`, so case 1 wedged forever
//! (empty set → everything blocked → the waker could never fire).

use conformance_probes::{block_signal, errno, install_handler};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_sig: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Raw rt_sigtimedwait over a u64 sigset. Returns (raw_return, errno).
unsafe fn rt_sigtimedwait(set: u64, timeout: Option<Duration>) -> (i64, i32) {
    let ts = timeout.map(|d| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    });
    let tsp = ts
        .as_ref()
        .map_or(core::ptr::null(), |t| t as *const libc::timespec);
    let rc = libc::syscall(
        libc::SYS_rt_sigtimedwait,
        &set as *const u64,
        core::ptr::null_mut::<libc::c_void>(),
        tsp,
        8usize,
    ) as i64;
    (rc, if rc < 0 { errno() } else { 0 })
}

/// Fork a child that sleeps `delay_ms` then kills the parent with `sig` (or
/// just exits for `sig == 0`). Returns the child pid.
unsafe fn fork_killer(sig: i32, delay_ms: u64) -> libc::pid_t {
    let ppid = libc::getpid();
    let pid = libc::fork();
    if pid == 0 {
        libc::usleep((delay_ms * 1000) as libc::c_uint);
        if sig != 0 {
            libc::kill(ppid, sig);
        }
        libc::_exit(0);
    }
    pid
}

unsafe fn reap(pid: libc::pid_t) {
    let mut status = 0;
    libc::waitpid(pid, &mut status, 0);
}

fn main() {
    unsafe {
        // Case 1: empty-set wait, unblocked caught SIGUSR1 arrives → the
        // handler runs and the wait returns EINTR (bounded: a broken runtime
        // returns EAGAIN after 6s instead of hanging the harness).
        if !install_handler(libc::SIGUSR1, on_usr1, 0) {
            println!("install_ok=false");
            return;
        }
        let child = fork_killer(libc::SIGUSR1, 150);
        let (rc, err) = rt_sigtimedwait(0, Some(Duration::from_secs(6)));
        reap(child);
        println!("eintr_on_caught_nonset={}", rc == -1 && err == libc::EINTR);
        println!("handler_ran={}", USR1_HITS.load(Ordering::SeqCst) == 1);

        // Case 2: a BLOCKED wait-set signal is dequeued and returned as the
        // signum; no handler involvement (none installed for SIGUSR2).
        let _ = block_signal(libc::SIGUSR2);
        let child = fork_killer(libc::SIGUSR2, 150);
        let (rc, _) = rt_sigtimedwait(1u64 << (libc::SIGUSR2 - 1), Some(Duration::from_secs(6)));
        reap(child);
        println!("waitset_signum_ok={}", rc == libc::SIGUSR2 as i64);

        // Case 3: bounded empty-set wait, nothing pending → EAGAIN.
        let (rc, err) = rt_sigtimedwait(0, Some(Duration::from_millis(300)));
        println!("eagain_on_timeout={}", rc == -1 && err == libc::EAGAIN);

        // Case 4: a handler-less (default-ignore) SIGCHLD from a dying child
        // must NOT interrupt the wait — still EAGAIN after the full timeout.
        let child = fork_killer(0, 100);
        let (rc, err) = rt_sigtimedwait(0, Some(Duration::from_millis(700)));
        reap(child);
        println!(
            "sigchld_ignored_no_eintr={}",
            rc == -1 && err == libc::EAGAIN
        );

        // Case 5: a BLOCKED RT signal from an already-reaped child is dequeued
        // with a correct siginfo: si_signo, si_code == SI_USER, si_pid == the
        // child's pid (LTP tse_masked_matching_rt).
        let rt = libc::SIGRTMIN() + 1;
        let _ = block_signal(rt);
        let child = fork_killer(rt, 0);
        reap(child); // signal already pending before the wait
        let mut info = [0u8; 128];
        let rc = libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &(1u64 << (rt - 1)) as *const u64,
            info.as_mut_ptr(),
            core::ptr::null::<libc::timespec>(),
            8usize,
        ) as i64;
        let si_signo = i32::from_le_bytes(info[0..4].try_into().unwrap());
        let si_code = i32::from_le_bytes(info[8..12].try_into().unwrap());
        let si_pid = i32::from_le_bytes(info[16..20].try_into().unwrap());
        println!("rt_signum_ok={}", rc == rt as i64);
        println!("rt_si_signo_ok={}", si_signo == rt);
        println!("rt_si_code_is_user={}", si_code == 0);
        println!("rt_si_pid_is_child={}", si_pid == child);

        // Case 6: EFAULT (not a crash, not success) when `info` is a bad
        // pointer and a wait-set signal arrives (LTP tse_bad_address).
        let child = fork_killer(libc::SIGUSR2, 100);
        let rc = libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &(1u64 << (libc::SIGUSR2 - 1)) as *const u64,
            1usize as *mut libc::c_void,
            core::ptr::null::<libc::timespec>(),
            8usize,
        ) as i64;
        let e = if rc < 0 { errno() } else { 0 };
        reap(child);
        println!("bad_info_efault={}", rc == -1 && e == libc::EFAULT);

        println!("handler_total_ok={}", USR1_HITS.load(Ordering::SeqCst) == 1);
    }
}
