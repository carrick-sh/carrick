#[cfg(target_os = "macos")]
#[test]
fn kqueue_wait_still_observes_readable_socket_with_listener_write_interest() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use carrick_hal::WaitFd;
    use carrick_vmm_hvf::io_wait::{ThreadWaiter, WaitResult};

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

    let waiter = ThreadWaiter::new(carrick_runtime::thread::ThreadId::main_from_host_pid_value(
        unsafe { libc::getpid() },
    ));
    let result = waiter.wait(
        &[
            WaitFd::raw(server.as_raw_fd(), libc::POLLIN),
            WaitFd::raw(listener.as_raw_fd(), libc::POLLIN | libc::POLLOUT),
        ],
        Some(Duration::from_millis(100)),
        carrick_abi::SigBlockMask::NONE,
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

    use carrick_hal::WaitFd;
    use carrick_vmm_hvf::io_wait::{ThreadWaiter, WaitResult};

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
        let waiter = ThreadWaiter::new(
            carrick_runtime::thread::ThreadId::main_from_host_pid_value(unsafe { libc::getpid() }),
        );
        waiter.wait(
            &[
                WaitFd::raw(server_fd, libc::POLLIN),
                WaitFd::raw(listener_fd, libc::POLLIN | libc::POLLOUT),
            ],
            Some(Duration::from_millis(500)),
            carrick_abi::SigBlockMask::NONE,
        )
    });

    std::thread::sleep(Duration::from_millis(25));
    client.write_all(b"request").expect("write request bytes");

    let result = waiter_thread.join().expect("waiter thread panicked");
    assert!(matches!(result, WaitResult::Ready));
}

// NOTE: the EBADF-recovery regression test that used to live in its own
// top-level binary (tests/wait_proc_exit_recovery.rs) is gone with the
// host-process wait family it covered: under HVPatch a guest `fork` creates no
// host process, so there is no `EVFILT_PROC`/`NOTE_EXIT` wait on a Darwin pid to
// recover. Its isolation rationale (the family read process-global
// signal/quiesce state that the HVF and fork tests in *this* binary mutate)
// stands as the reason any future process-global wait test needs its own binary.
