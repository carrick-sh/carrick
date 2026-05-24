//! ppoll with a signal mask: a blocked signal raised mid-wait (before the fd is
//! ready) must NOT interrupt the wait — it returns 1 once the fd is made ready.
//! Deterministic boolean; bounded so a broken path prints false.
//!
//! (pselect6 has the same contract but a different carrick code shape — it blocks
//! directly in libc::poll rather than the WaitOnFds path — so its sigmask fix is
//! a separate follow-up; see the go-bringup-followups spec.)

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = noop as usize;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

    println!("ppoll_blocks={}", run_one());
}

unsafe fn run_one() -> bool {
    let mut sv = [0i32; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
        return false;
    }
    let parent = libc::getpid();
    let pid = libc::fork();
    if pid == 0 {
        // Raise the masked signal while the parent is blocked and the socket is
        // empty; make the fd ready only later.
        libc::usleep(50_000);
        libc::kill(parent, libc::SIGUSR1);
        libc::usleep(150_000);
        libc::write(sv[1], b"w".as_ptr().cast(), 1);
        libc::_exit(0);
    }
    let mut mask: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut mask);
    libc::sigaddset(&mut mask, libc::SIGUSR1);
    let ts = libc::timespec {
        tv_sec: 4,
        tv_nsec: 0,
    };
    let mut pfd = libc::pollfd {
        fd: sv[0],
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = libc::ppoll(&mut pfd, 1, &ts, &mask);
    let mut st = 0i32;
    libc::waitpid(pid, &mut st, 0);
    libc::close(sv[0]);
    libc::close(sv[1]);
    ret == 1
}

extern "C" fn noop(_sig: libc::c_int) {}
