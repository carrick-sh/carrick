//! Death-by-signal wait-status encoding. When a child is terminated by a
//! signal, the parent's wait4 status must report WIFSIGNALED with WTERMSIG ==
//! the killing signal (and not WIFEXITED). carrick synthesizes this for guest
//! processes that die by signal (forked_child_die_by_signal / host waitpid
//! translation), so this pins the encoding against Linux. Covers a normal exit
//! too, as the negative case. Deterministic booleans; every child is reaped so
//! nothing hangs.

unsafe fn fork_kill_status(sig: i32) -> (bool, bool) {
    let pid = libc::fork();
    if pid == 0 {
        // Child: block nothing, just wait to be killed. Pause loops so the
        // signal (default action = terminate) is what ends it.
        loop {
            libc::pause();
        }
    }
    // Parent: give the child a moment to reach pause(), then kill it.
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 20_000_000,
    };
    libc::nanosleep(&ts, std::ptr::null_mut());
    libc::kill(pid, sig);
    let mut st = 0i32;
    loop {
        let r = libc::wait4(pid, &mut st, 0, std::ptr::null_mut());
        if r == -1 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        break;
    }
    (
        libc::WIFSIGNALED(st),
        libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == sig,
    )
}

fn main() {
    unsafe {
        let (term_sig, term_num) = fork_kill_status(libc::SIGTERM);
        println!("sigterm_wifsignaled={term_sig}");
        println!("sigterm_wtermsig_matches={term_num}");

        let (kill_sig, kill_num) = fork_kill_status(libc::SIGKILL);
        println!("sigkill_wifsignaled={kill_sig}");
        println!("sigkill_wtermsig_matches={kill_num}");

        // Negative case: a child that exits(0) is WIFEXITED, NOT WIFSIGNALED.
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(0);
        }
        let mut st = 0i32;
        while libc::wait4(pid, &mut st, 0, std::ptr::null_mut()) < 0 {}
        println!("clean_exit_not_signalled={}", !libc::WIFSIGNALED(st));
        println!(
            "clean_exit_status_zero={}",
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0
        );
    }
}
