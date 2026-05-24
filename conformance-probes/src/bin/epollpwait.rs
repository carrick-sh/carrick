//! `epoll_pwait` with a signal mask over a host socketpair — the shape of LTP
//! epoll_pwait01. Two checks, both deterministic booleans:
//!
//!  * `ready_immediate`: a byte already waiting on `sv[0]` is reported by
//!    `epoll_pwait` (with a non-NULL sigmask) on the first call → ret==1.
//!  * `woke_crossproc`: a blocked `epoll_pwait` (sigmask set) wakes when a
//!    FORKED CHILD writes the socketpair peer — the cross-process readiness
//!    wake that the Go netpoller and epoll_pwait01 both rely on.
//!
//! Every wait is bounded (finite timeout), so a broken wake prints `false`
//! rather than hanging the harness.

const EPOLLIN: u32 = 0x001;

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    // A sigmask that blocks SIGUSR1 (mirrors epoll_pwait01's call).
    let mut mask: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut mask);
    libc::sigaddset(&mut mask, libc::SIGUSR1);

    // (1) ready_immediate: byte already present before epoll_pwait.
    let ready_immediate = {
        let mut sv = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            println!("setup=false");
            return;
        }
        let epfd = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: EPOLLIN,
            u64: sv[0] as u64,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sv[0], &mut ev);
        libc::write(sv[1], b"w".as_ptr().cast(), 1);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let ret = libc::epoll_pwait(epfd, out.as_mut_ptr(), 1, 4000, &mask);
        let ok = ret == 1 && (out[0].events & EPOLLIN) != 0;
        libc::close(epfd);
        libc::close(sv[0]);
        libc::close(sv[1]);
        ok
    };

    // (2) woke_crossproc: forked child writes the peer while the parent blocks.
    let woke_crossproc = {
        let mut sv = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            println!("setup=false");
            return;
        }
        let epfd = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: EPOLLIN,
            u64: sv[0] as u64,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sv[0], &mut ev);
        let pid = libc::fork();
        if pid == 0 {
            // Child: let the parent reach epoll_pwait first, then write.
            libc::usleep(100_000);
            libc::write(sv[1], b"w".as_ptr().cast(), 1);
            libc::_exit(0);
        }
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let ret = libc::epoll_pwait(epfd, out.as_mut_ptr(), 1, 4000, &mask);
        let ok = ret == 1 && (out[0].events & EPOLLIN) != 0;
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);
        libc::close(epfd);
        libc::close(sv[0]);
        libc::close(sv[1]);
        ok
    };

    // (3) sigmask_blocks: a blocked signal raised WHILE the parent is in
    // epoll_pwait (socket still empty) must NOT interrupt it — the wait keeps
    // going and returns 1 only once the fd is later made ready. This is the
    // crux of LTP epoll_pwait01: the sigmask must be applied during the wait.
    let sigmask_blocks = {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = noop_handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());

        let mut sv = [0i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            println!("setup=false");
            return;
        }
        let epfd = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: EPOLLIN,
            u64: sv[0] as u64,
        };
        libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sv[0], &mut ev);
        let parent = libc::getpid();
        let pid = libc::fork();
        if pid == 0 {
            // Raise the masked signal FIRST (socket still empty, parent blocked):
            // a correct kernel ignores it and keeps waiting. Make the fd ready
            // only later.
            libc::usleep(50_000);
            libc::kill(parent, libc::SIGUSR1);
            libc::usleep(150_000);
            libc::write(sv[1], b"w".as_ptr().cast(), 1);
            libc::_exit(0);
        }
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let ret = libc::epoll_pwait(epfd, out.as_mut_ptr(), 1, 4000, &mask);
        let ok = ret == 1 && (out[0].events & EPOLLIN) != 0;
        let mut st = 0i32;
        libc::waitpid(pid, &mut st, 0);
        libc::close(epfd);
        libc::close(sv[0]);
        libc::close(sv[1]);
        ok
    };

    println!("ready_immediate={ready_immediate}");
    println!("woke_crossproc={woke_crossproc}");
    println!("sigmask_blocks={sigmask_blocks}");
}

extern "C" fn noop_handler(_sig: libc::c_int) {}
