//! Reduced epoll contracts from the LTP epoll regression cluster.
//!
//! The cases here avoid timing and fd-number output. Each line is a stable
//! Linux observation that Carrick must match.

use conformance_probes::{errno, report};

const SYS_EPOLL_PWAIT2: libc::c_long = 441;
const F_SETPIPE_SZ: libc::c_int = 1031;

static RODATA_EVENTS: [u8; 16] = [0; 16];

fn syscall_errno(rc: libc::c_int) -> i32 {
    if rc < 0 { errno() } else { 0 }
}

fn syscall_errno_long(rc: libc::c_long) -> i32 {
    if rc < 0 { errno() } else { 0 }
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn pipe2() -> [libc::c_int; 2] {
    let mut fds = [-1; 2];
    unsafe {
        libc::pipe(fds.as_mut_ptr());
    }
    fds
}

fn add_epoll_interest(epfd: libc::c_int, fd: libc::c_int, events: u32) -> i32 {
    let mut event = libc::epoll_event { events, u64: 0 };
    unsafe { syscall_errno(libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut event)) }
}

fn epoll_wait_one(epfd: libc::c_int) -> (i32, u32) {
    let mut event = libc::epoll_event { events: 0, u64: 0 };
    let rc = unsafe { libc::epoll_wait(epfd, &mut event, 1, 0) };
    (rc, if rc > 0 { event.events } else { 0 })
}

fn epollpri_pipe_add_errno() -> i32 {
    let epfd = unsafe { libc::epoll_create1(0) };
    let fds = pipe2();
    let add_errno = add_epoll_interest(epfd, fds[0], libc::EPOLLPRI as u32);
    close_fd(fds[0]);
    close_fd(fds[1]);
    close_fd(epfd);
    add_errno
}

fn nested_epoll_cycle_errno() -> (i32, i32) {
    let ep1 = unsafe { libc::epoll_create1(0) };
    let ep2 = unsafe { libc::epoll_create1(0) };
    let add_nested_errno = add_epoll_interest(ep1, ep2, libc::EPOLLIN as u32);
    let add_cycle_errno = add_epoll_interest(ep2, ep1, libc::EPOLLIN as u32);
    close_fd(ep2);
    close_fd(ep1);
    (add_nested_errno, add_cycle_errno)
}

/// libuv's backend fd is itself polled and can be watched by another epoll.
/// An internal control notification must not masquerade as a queued guest event.
/// Every sample is nonblocking; a missing wake/readiness edge becomes an output
/// difference, never an unbounded wait in the public embedded probe gate.
fn epoll_fd_readiness() {
    fn poll_one(fd: i32) -> (i32, i16) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
        (rc, pfd.revents)
    }

    let child = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let outer = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    let nested_add = add_epoll_interest(outer, child, libc::EPOLLIN as u32);
    let (empty_poll, empty_poll_mask) = poll_one(child);
    let (empty_outer, empty_outer_mask) = epoll_wait_one(outer);
    let child_add = add_epoll_interest(child, fd, libc::EPOLLIN as u32);
    let (registered_poll, registered_poll_mask) = poll_one(child);
    let (registered_outer, registered_outer_mask) = epoll_wait_one(outer);

    let value = 1u64;
    let write_rc = unsafe { libc::write(fd, (&value as *const u64).cast(), 8) };
    let (signalled_poll, signalled_poll_mask) = poll_one(child);
    let (signalled_outer, signalled_outer_mask) = epoll_wait_one(outer);
    let (signalled_child, signalled_child_mask) = epoll_wait_one(child);
    let mut received = 0u64;
    let read_rc = unsafe { libc::read(fd, (&mut received as *mut u64).cast(), 8) };
    let (drained_poll, drained_poll_mask) = poll_one(child);
    let (drained_outer, drained_outer_mask) = epoll_wait_one(outer);
    let (drained_child, drained_child_mask) = epoll_wait_one(child);

    report!(
        epollfd_nested_add_errno = nested_add,
        epollfd_empty_poll = empty_poll,
        epollfd_empty_poll_mask = empty_poll_mask,
        epollfd_empty_outer = empty_outer,
        epollfd_empty_outer_mask = empty_outer_mask,
        epollfd_child_add_errno = child_add,
        epollfd_registered_poll = registered_poll,
        epollfd_registered_poll_mask = registered_poll_mask,
        epollfd_registered_outer = registered_outer,
        epollfd_registered_outer_mask = registered_outer_mask,
        epollfd_write = write_rc,
        epollfd_signalled_poll = signalled_poll,
        epollfd_signalled_poll_mask = signalled_poll_mask,
        epollfd_signalled_outer = signalled_outer,
        epollfd_signalled_outer_mask = signalled_outer_mask,
        epollfd_signalled_child = signalled_child,
        epollfd_signalled_child_mask = signalled_child_mask,
        epollfd_read = read_rc,
        epollfd_read_value = received,
        epollfd_drained_poll = drained_poll,
        epollfd_drained_poll_mask = drained_poll_mask,
        epollfd_drained_outer = drained_outer,
        epollfd_drained_outer_mask = drained_outer_mask,
        epollfd_drained_child = drained_child,
        epollfd_drained_child_mask = drained_child_mask,
    );
    close_fd(outer);
    close_fd(child);
    close_fd(fd);
}

/// Polling an epoll descriptor must wake when an observed eventfd is written
/// by another thread, including after an empty epoll_wait clears control wakes.
/// The writer owns a duplicate descriptor and every synchronization wait is bounded.
fn epoll_fd_thread_wake() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;
    let child = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    let add_errno = add_epoll_interest(child, fd, libc::EPOLLIN as u32);
    let (initial_child, _) = epoll_wait_one(child);
    let mut pfd = libc::pollfd {
        fd: child,
        events: libc::POLLIN,
        revents: 0,
    };
    let initial_poll = unsafe { libc::poll(&mut pfd, 1, 0) };
    let writer_fd = unsafe { libc::dup(fd) };
    let mut spawn_errno = if writer_fd < 0 { errno() } else { 0 };
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    if writer_fd >= 0 {
        let writer = unsafe { OwnedFd::from_raw_fd(writer_fd) };
        if let Err(error) = std::thread::Builder::new().spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let value = 1u64;
            let written =
                unsafe { libc::write(writer.as_raw_fd(), (&value as *const u64).cast(), 8) };
            drop(writer);
            let _ = tx.send(written);
        }) {
            spawn_errno = error.raw_os_error().unwrap_or(-1);
        }
    }
    pfd.revents = 0;
    let wake_poll = unsafe { libc::poll(&mut pfd, 1, 5000) };
    let wake_mask = pfd.revents;
    let written = rx.recv_timeout(Duration::from_secs(5)).unwrap_or(-1);
    let (child_ready, child_mask) = epoll_wait_one(child);
    let mut value = 0u64;
    let read_rc = unsafe { libc::read(fd, (&mut value as *mut u64).cast(), 8) };
    let (drained_child, _) = epoll_wait_one(child);
    pfd.revents = 0;
    let drained_poll = unsafe { libc::poll(&mut pfd, 1, 0) };
    report!(
        epollfd_thread_add_errno = add_errno,
        epollfd_thread_initial_child = initial_child,
        epollfd_thread_initial_poll = initial_poll,
        epollfd_thread_spawn_errno = spawn_errno,
        epollfd_thread_poll = wake_poll,
        epollfd_thread_poll_mask = wake_mask,
        epollfd_thread_write = written,
        epollfd_thread_child = child_ready,
        epollfd_thread_child_mask = child_mask,
        epollfd_thread_read = read_rc,
        epollfd_thread_value = value,
        epollfd_thread_drained_child = drained_child,
        epollfd_thread_drained_poll = drained_poll,
    );
    close_fd(child);
    close_fd(fd);
}

fn epoll_pwait2_zero_timeout_errno() -> (libc::c_long, i32) {
    let epfd = unsafe { libc::epoll_create1(0) };
    let mut event = libc::epoll_event { events: 0, u64: 0 };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        libc::syscall(
            SYS_EPOLL_PWAIT2,
            epfd,
            &mut event as *mut libc::epoll_event,
            1,
            &timeout as *const libc::timespec,
            core::ptr::null::<libc::sigset_t>(),
            8usize,
        )
    };
    close_fd(epfd);
    (rc, syscall_errno_long(rc))
}

fn ready_pipe_epoll() -> (libc::c_int, [libc::c_int; 2]) {
    let epfd = unsafe { libc::epoll_create1(0) };
    let fds = pipe2();
    let byte = b"x";
    unsafe {
        libc::write(fds[1], byte.as_ptr().cast(), byte.len());
    }
    let _ = add_epoll_interest(epfd, fds[0], libc::EPOLLIN as u32);
    (epfd, fds)
}

fn readonly_events_errno() -> (i32, i32) {
    let (epfd, fds) = ready_pipe_epoll();
    let rodata_rc = unsafe {
        libc::epoll_wait(
            epfd,
            RODATA_EVENTS.as_ptr().cast::<libc::epoll_event>() as *mut libc::epoll_event,
            1,
            0,
        )
    };
    let rodata_errno = syscall_errno(rodata_rc);

    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let mmap_errno = if page == libc::MAP_FAILED {
        errno()
    } else {
        let rc = unsafe { libc::epoll_wait(epfd, page.cast::<libc::epoll_event>(), 1, 0) };
        let e = syscall_errno(rc);
        unsafe {
            libc::munmap(page, 4096);
        }
        e
    };

    close_fd(fds[0]);
    close_fd(fds[1]);
    close_fd(epfd);
    (rodata_errno, mmap_errno)
}

fn nonblocking_pipe_second_write_errno() -> (libc::c_int, isize, i32) {
    let fds = pipe2();
    let cap = unsafe { libc::fcntl(fds[1], F_SETPIPE_SZ, 4096) };
    let flags = unsafe { libc::fcntl(fds[1], libc::F_GETFL) };
    unsafe {
        libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let bytes = [0u8; 4096];
    let first = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), bytes.len()) };
    let second = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), 1) };
    let second_errno = syscall_errno(second as libc::c_int);
    close_fd(fds[0]);
    close_fd(fds[1]);
    (cap, first, second_errno)
}

fn socket_peer_close_events() -> (i32, u32) {
    let epfd = unsafe { libc::epoll_create1(0) };
    let mut sv = [-1; 2];
    unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
    }
    let _ = add_epoll_interest(epfd, sv[0], (libc::EPOLLIN | libc::EPOLLRDHUP) as u32);
    close_fd(sv[1]);
    let result = epoll_wait_one(epfd);
    close_fd(sv[0]);
    close_fd(epfd);
    result
}

fn et_pipe_progression() -> (i32, u32, i32, i32, u32) {
    let epfd = unsafe { libc::epoll_create1(0) };
    let fds = pipe2();
    let bytes = *b"abcdefgh";
    unsafe {
        libc::write(fds[1], bytes.as_ptr().cast(), bytes.len());
    }
    let _ = add_epoll_interest(epfd, fds[0], (libc::EPOLLIN | libc::EPOLLET) as u32);
    let (first_rc, first_events) = epoll_wait_one(epfd);
    let mut half = [0u8; 4];
    unsafe {
        libc::read(fds[0], half.as_mut_ptr().cast(), half.len());
    }
    let (after_half_rc, _) = epoll_wait_one(epfd);
    let more = b"z";
    unsafe {
        libc::write(fds[1], more.as_ptr().cast(), more.len());
    }
    let (after_refill_rc, after_refill_events) = epoll_wait_one(epfd);
    close_fd(fds[0]);
    close_fd(fds[1]);
    close_fd(epfd);
    (
        first_rc,
        first_events,
        after_half_rc,
        after_refill_rc,
        after_refill_events,
    )
}

fn main() {
    let epollpri_pipe_add_errno = epollpri_pipe_add_errno();
    let (nested_epoll_add_errno, nested_epoll_cycle_errno) = nested_epoll_cycle_errno();
    let (pwait2_zero_rc, pwait2_zero_errno) = epoll_pwait2_zero_timeout_errno();
    let (rodata_events_errno, mmap_ro_events_errno) = readonly_events_errno();
    let (pipe_set_capacity, pipe_first_write, pipe_second_write_errno) =
        nonblocking_pipe_second_write_errno();
    let (socket_peer_close_rc, socket_peer_close_events) = socket_peer_close_events();
    let (
        et_first_rc,
        et_first_events,
        et_after_half_rc,
        et_after_refill_rc,
        et_after_refill_events,
    ) = et_pipe_progression();

    report!(
        epollpri_pipe_add_errno = epollpri_pipe_add_errno,
        nested_epoll_add_errno = nested_epoll_add_errno,
        nested_epoll_cycle_errno = nested_epoll_cycle_errno,
        pwait2_zero_rc = pwait2_zero_rc,
        pwait2_zero_errno = pwait2_zero_errno,
        rodata_events_errno = rodata_events_errno,
        mmap_ro_events_errno = mmap_ro_events_errno,
        pipe_set_capacity = pipe_set_capacity,
        pipe_first_write = pipe_first_write,
        pipe_second_write_errno = pipe_second_write_errno,
        socket_peer_close_rc = socket_peer_close_rc,
        socket_peer_close_events = socket_peer_close_events,
        et_first_rc = et_first_rc,
        et_first_events = et_first_events,
        et_after_half_rc = et_after_half_rc,
        et_after_refill_rc = et_after_refill_rc,
        et_after_refill_events = et_after_refill_events,
    );
    epoll_fd_readiness();
    epoll_fd_thread_wake();
}
