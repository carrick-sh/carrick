//! signal(7): group stop interrupts epoll, but preserves a blocking pipe read.
use conformance_probes::errno;
use std::time::{Duration, Instant};

unsafe fn pipe() -> [i32; 2] {
    let mut fds = [-1; 2];
    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
    fds
}

fn exercise(epoll: bool) -> (i32, i32, bool) {
    unsafe {
        let ready = pipe();
        let data = pipe();
        let parent = libc::getpid();
        let helper = libc::fork();
        assert!(helper >= 0);
        if helper == 0 {
            libc::close(ready[1]);
            let mut byte = 0u8;
            let mut pollfd = libc::pollfd {
                fd: ready[0],
                events: libc::POLLIN,
                revents: 0,
            };
            if libc::poll(&mut pollfd, 1, 5000) != 1
                || libc::read(ready[0], (&mut byte as *mut u8).cast(), 1) != 1
            {
                libc::_exit(2);
            }
            libc::usleep(100_000);
            if libc::kill(parent, libc::SIGSTOP) != 0 {
                libc::_exit(3);
            }
            libc::usleep(100_000);
            if libc::kill(parent, libc::SIGCONT) != 0 {
                libc::_exit(4);
            }
            libc::usleep(100_000);
            libc::write(data[1], (&byte as *const u8).cast(), 1);
            libc::_exit(0);
        }
        libc::close(ready[0]);
        libc::close(data[1]);
        let worker = std::thread::spawn(move || {
            let epfd = if epoll { libc::epoll_create1(0) } else { -1 };
            if epoll {
                assert!(epfd >= 0);
            }
            let byte = 1u8;
            assert_eq!(libc::write(ready[1], (&byte as *const u8).cast(), 1), 1);
            libc::close(ready[1]);
            let start = Instant::now();
            let mut event: libc::epoll_event = std::mem::zeroed();
            let mut value = 0u8;
            let rc = if epoll {
                libc::epoll_wait(epfd, &mut event, 1, 5000)
            } else {
                libc::read(data[0], (&mut value as *mut u8).cast(), 1) as i32
            };
            let error = if rc < 0 { errno() } else { 0 };
            let before = start.elapsed() < Duration::from_secs(5);
            if epfd >= 0 {
                libc::close(epfd);
            }
            libc::close(data[0]);
            (rc, error, before)
        });
        let result = worker.join().expect("wait thread");
        let mut status = 0;
        assert_eq!(libc::waitpid(helper, &mut status, 0), helper);
        assert_eq!(status, 0);
        result
    }
}

fn main() {
    let (rc, error, before) = exercise(true);
    println!("epoll_rc={rc}");
    println!("epoll_errno={error}");
    println!("epoll_returned_before_timeout={before}");
    let (rc, error, before) = exercise(false);
    println!("pipe_rc={rc}");
    println!("pipe_errno={error}");
    println!("pipe_returned_before_timeout={before}");
}
