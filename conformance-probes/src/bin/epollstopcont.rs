//! signal(7): group stop interrupts epoll, but preserves a blocking pipe read.
use conformance_probes::errno;
use std::time::{Duration, Instant};

unsafe fn pipe() -> [i32; 2] {
    let mut fds = [-1; 2];
    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
    fds
}

fn exercise(epoll: bool) -> (i32, i32, bool, Option<(i32, i32, bool)>) {
    unsafe {
        let ready = pipe();
        let data = pipe();
        let post = pipe();
        let parent = libc::getpid();
        let helper = libc::fork();
        assert!(helper >= 0);
        if helper == 0 {
            libc::close(ready[1]);
            libc::close(post[1]);
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
            if epoll {
                pollfd.fd = post[0];
                pollfd.revents = 0;
                if libc::poll(&mut pollfd, 1, 5000) != 1
                    || libc::read(post[0], (&mut byte as *mut u8).cast(), 1) != 1
                {
                    libc::_exit(5);
                }
            }
            libc::write(data[1], (&byte as *const u8).cast(), 1);
            libc::_exit(0);
        }
        libc::close(ready[0]);
        libc::close(data[1]);
        libc::close(post[0]);
        let (completed_tx, completed_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let epfd = if epoll { libc::epoll_create1(0) } else { -1 };
            if epoll {
                assert!(epfd >= 0);
                let mut registration = libc::epoll_event {
                    events: (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
                    u64: 0x5354_4f50,
                };
                assert_eq!(
                    libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, data[0], &mut registration),
                    0
                );
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
            let later = if epoll {
                // The helper cannot post until the interrupted wait has returned.
                assert_eq!(libc::write(post[1], (&byte as *const u8).cast(), 1), 1);
                let later_rc = libc::epoll_wait(epfd, &mut event, 1, 5000);
                let later_error = if later_rc < 0 { errno() } else { 0 };
                let delivered = later_rc == 1
                    && event.u64 == 0x5354_4f50
                    && event.events & libc::EPOLLIN as u32 != 0
                    && libc::read(data[0], (&mut value as *mut u8).cast(), 1) == 1
                    && value == byte;
                libc::close(epfd);
                Some((later_rc, later_error, delivered))
            } else {
                None
            };
            libc::close(post[1]);
            libc::close(data[0]);
            completed_tx
                .send((rc, error, before, later))
                .expect("publish wait result");
        });
        let result = completed_rx
            .recv_timeout(Duration::from_secs(6))
            .unwrap_or_else(|_| {
                println!("wait_completed=false");
                std::process::exit(1);
            });
        drop(worker);
        let mut status = 0;
        assert_eq!(libc::waitpid(helper, &mut status, 0), helper);
        assert_eq!(status, 0);
        result
    }
}

fn main() {
    let (rc, error, before, later) = exercise(true);
    println!("epoll_rc={rc}");
    println!("epoll_errno={error}");
    println!("epoll_returned_before_timeout={before}");
    let (later_rc, later_error, delivered) = later.expect("epoll follow-up result");
    println!("epoll_later_rc={later_rc}");
    println!("epoll_later_errno={later_error}");
    println!("epoll_later_event_delivered={delivered}");
    let (rc, error, before, _) = exercise(false);
    println!("pipe_rc={rc}");
    println!("pipe_errno={error}");
    println!("pipe_returned_before_timeout={before}");
}
