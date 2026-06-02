#[cfg(target_os = "macos")]
#[test]
fn kqueue_wait_still_observes_readable_socket_with_listener_write_interest() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use carrick_runtime::io_wait::{ThreadWaiter, WaitResult};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("make listener nonblocking");
    let mut client = TcpStream::connect(listener.local_addr().expect("listener addr"))
        .expect("connect client to listener");
    let (server, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    };

    client.write_all(b"request").expect("write request bytes");

    let waiter = ThreadWaiter::new(unsafe { libc::getpid() });
    let result = waiter.wait(
        &[
            (server.as_raw_fd(), libc::POLLIN),
            (listener.as_raw_fd(), libc::POLLIN | libc::POLLOUT),
        ],
        Some(Duration::from_millis(100)),
        0,
    );

    assert!(matches!(result, WaitResult::Ready));
}

#[cfg(target_os = "macos")]
#[test]
fn kqueue_wait_wakes_when_peer_writes_after_registration() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::Duration;

    use carrick_runtime::io_wait::{ThreadWaiter, WaitResult};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("make listener nonblocking");
    let mut client = TcpStream::connect(listener.local_addr().expect("listener addr"))
        .expect("connect client to listener");
    let (server, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::yield_now();
            }
            Err(err) => panic!("accept failed: {err}"),
        }
    };

    let server_fd: RawFd = server.as_raw_fd();
    let listener_fd: RawFd = listener.as_raw_fd();
    let waiter_thread = std::thread::spawn(move || {
        let waiter = ThreadWaiter::new(unsafe { libc::getpid() });
        waiter.wait(
            &[
                (server_fd, libc::POLLIN),
                (listener_fd, libc::POLLIN | libc::POLLOUT),
            ],
            Some(Duration::from_millis(500)),
            0,
        )
    });

    std::thread::sleep(Duration::from_millis(25));
    client.write_all(b"request").expect("write request bytes");

    let result = waiter_thread.join().expect("waiter thread panicked");
    assert!(matches!(result, WaitResult::Ready));
}

// NOTE: the EBADF-recovery regression test lives in its own top-level test
// binary (tests/wait_proc_exit_recovery.rs) so it runs in an isolated process.
// `wait_proc_exit` consults process-global signal/quiesce state, which the HVF
// and fork tests in *this* binary mutate concurrently — running it here makes it
// flaky for reasons unrelated to the fix.
