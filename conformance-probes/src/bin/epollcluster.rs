//! Reduced epoll contracts from the LTP epoll regression cluster.
//!
//! The cases here avoid timing and fd-number output. Each line is a stable
//! Linux observation that Carrick must match.

use conformance_probes::{errno, report};

const SYS_EPOLL_PWAIT2: libc::c_long = 441;
const F_SETPIPE_SZ: libc::c_int = 1031;

static RODATA_EVENTS: [u8; 16] = [0; 16];

fn syscall_errno(rc: libc::c_int) -> i32 {
    if rc < 0 {
        errno()
    } else {
        0
    }
}

fn syscall_errno_long(rc: libc::c_long) -> i32 {
    if rc < 0 {
        errno()
    } else {
        0
    }
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
}
