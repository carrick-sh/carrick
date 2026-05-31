//! TCP urgent data must wake an epoll waiter with EPOLLPRI.
//!
//! This owns the Linux invariant behind libuv's `poll_oob` test: a socket
//! registered for EPOLLPRI must become ready when its peer sends MSG_OOB data,
//! and the byte must be readable with recv(MSG_OOB). The probe is bounded by a
//! one-second epoll_wait timeout, so a missed wake prints `false` instead of
//! hanging the harness.

use conformance_probes::report;
use std::mem::MaybeUninit;

const EPOLLPRI: u32 = 0x002;

unsafe fn close_if_open(fd: i32) {
    if fd >= 0 {
        libc::close(fd);
    }
}

unsafe fn run() {
    let mut setup_ok = false;
    let mut add_ok = false;
    let mut send_ok = false;
    let mut wait_ready = false;
    let mut revents_pri = false;
    let mut recv_oob = false;

    let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if listener < 0 {
        report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);
        return;
    }

    let mut addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    if libc::bind(listener, &addr as *const _ as *const libc::sockaddr, addr_len) != 0
        || libc::listen(listener, 1) != 0
    {
        report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);
        close_if_open(listener);
        return;
    }

    let mut got: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut got_len = addr_len;
    if libc::getsockname(
        listener,
        &mut got as *mut _ as *mut libc::sockaddr,
        &mut got_len,
    ) != 0
    {
        report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);
        close_if_open(listener);
        return;
    }

    let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if client < 0
        || libc::connect(client, &got as *const _ as *const libc::sockaddr, got_len) != 0
    {
        report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);
        close_if_open(client);
        close_if_open(listener);
        return;
    }

    let server = libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut());
    if server < 0 {
        report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);
        close_if_open(client);
        close_if_open(listener);
        return;
    }
    setup_ok = true;

    let epfd = libc::epoll_create1(0);
    if epfd >= 0 {
        let mut ev = libc::epoll_event {
            events: EPOLLPRI,
            u64: client as u64,
        };
        add_ok = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, client, &mut ev) == 0;
    }

    if add_ok {
        send_ok = libc::send(server, b"!".as_ptr().cast(), 1, libc::MSG_OOB) == 1;
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let n = libc::epoll_wait(epfd, out.as_mut_ptr(), 1, 1000);
        wait_ready = n == 1;
        revents_pri = wait_ready && (out[0].events & EPOLLPRI) != 0;

        let mut byte = 0u8;
        recv_oob =
            libc::recv(client, &mut byte as *mut _ as *mut libc::c_void, 1, libc::MSG_OOB) == 1
                && byte == b'!';
    }

    report_results(setup_ok, add_ok, send_ok, wait_ready, revents_pri, recv_oob);

    close_if_open(epfd);
    close_if_open(server);
    close_if_open(client);
    close_if_open(listener);
}

fn report_results(
    setup_ok: bool,
    add_ok: bool,
    send_ok: bool,
    wait_ready: bool,
    revents_pri: bool,
    recv_oob: bool,
) {
    report!(
        epollpri_setup_ok = setup_ok,
        epollpri_add_ok = add_ok,
        epollpri_send_oob_ok = send_ok,
        epollpri_wait_ready = wait_ready,
        epollpri_revents_pri = revents_pri,
        epollpri_recv_oob_ok = recv_oob,
    );
}

fn main() {
    unsafe { run() }
}
