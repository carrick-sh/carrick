//! A datagram the runtime answers IN-PROCESS must wake `epoll_wait` exactly
//! like one the kernel delivered.
//!
//! Under `--net bridge` the `/etc/resolv.conf` nameserver is the embedded DNS
//! gateway (`172.31.0.1:53`); carrick answers a query from `sendto` itself and
//! parks the reply on the socket, never on the host kernel. Linux semantics
//! (epoll(7)): a queued datagram makes the socket EPOLLIN-ready, and a thread
//! already blocked in `epoll_wait` on it wakes when the datagram arrives. Both
//! halves are checked, each bounded by an `epoll_wait` timeout so a missed
//! wake prints `false` instead of hanging the harness. Only booleans are
//! printed: the oracle's resolver may answer NXDOMAIN where carrick answers
//! `localhost.` from `/etc/hosts`, and the diff must not see that.

use conformance_probes::report;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

const EPOLLIN: u32 = libc::EPOLLIN as u32;
const QUERY_ID_READY: u16 = 0x1234;
const QUERY_ID_PARKED: u16 = 0x5678;

#[derive(Default)]
struct Results {
    nameserver_ok: bool,
    socket_ok: bool,
    add_ok: bool,
    send_ok: bool,
    ready_after_send: bool,
    reply_id_matches: bool,
    wake_while_parked: bool,
    parked_reply_id_matches: bool,
}

fn report_results(r: &Results) {
    report!(
        dns_epoll_nameserver_ok = r.nameserver_ok,
        dns_epoll_socket_ok = r.socket_ok,
        dns_epoll_add_ok = r.add_ok,
        dns_epoll_send_ok = r.send_ok,
        dns_epoll_ready_after_send = r.ready_after_send,
        dns_epoll_reply_id_matches = r.reply_id_matches,
        dns_epoll_wake_while_parked = r.wake_while_parked,
        dns_epoll_parked_reply_id_matches = r.parked_reply_id_matches,
    );
}

/// First IPv4 `nameserver` of `/etc/resolv.conf`, as a stub resolver reads it.
fn resolv_conf_nameserver() -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        match fields.next() {
            Some("nameserver") => fields.next()?.parse::<Ipv4Addr>().ok(),
            _ => None,
        }
    })
}

/// A minimal RFC 1035 A query: header (id, RD, QDCOUNT=1) and one question.
fn dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0u8; 6]); // ANCOUNT, NSCOUNT, ARCOUNT
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    out
}

unsafe fn send_query(sock: i32, nameserver: Ipv4Addr, id: u16) -> bool {
    let query = dns_a_query(id, "localhost.");
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 53u16.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(nameserver.octets()),
    };
    let rc = libc::sendto(
        sock,
        query.as_ptr().cast::<libc::c_void>(),
        query.len(),
        0,
        (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    rc == query.len() as isize
}

/// One bounded `epoll_wait`; true iff exactly one EPOLLIN event came back.
fn wait_epollin(epfd: i32, timeout_ms: i32) -> bool {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { libc::epoll_wait(epfd, out.as_mut_ptr(), 1, timeout_ms) };
    n == 1 && out[0].events & EPOLLIN != 0
}

/// Drain one reply without blocking and return its transaction id.
unsafe fn recv_reply_id(sock: i32) -> Option<u16> {
    let mut buf = [0u8; 512];
    let n = libc::recv(
        sock,
        buf.as_mut_ptr().cast::<libc::c_void>(),
        buf.len(),
        libc::MSG_DONTWAIT,
    );
    if n < 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]))
}

unsafe fn run(r: &mut Results) {
    let Some(nameserver) = resolv_conf_nameserver() else {
        return;
    };
    r.nameserver_ok = true;

    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    r.socket_ok = sock >= 0;
    if !r.socket_ok {
        return;
    }
    let epfd = libc::epoll_create1(0);
    if epfd >= 0 {
        let mut ev = libc::epoll_event {
            events: EPOLLIN,
            u64: sock as u64,
        };
        r.add_ok = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sock, &mut ev) == 0;
    }
    if !r.add_ok {
        if epfd >= 0 {
            libc::close(epfd);
        }
        libc::close(sock);
        return;
    }

    // (a) Reply queued before the wait: the readiness sample must see it.
    r.send_ok = send_query(sock, nameserver, QUERY_ID_READY);
    if r.send_ok {
        r.ready_after_send = wait_epollin(epfd, 2000);
        r.reply_id_matches = recv_reply_id(sock) == Some(QUERY_ID_READY);
    }

    // (b) Waiter parked first, reply arrives later: the wake must be
    // published. The sleep only makes "parked first" likely; if the send
    // lands before the park, case (a) applies and the boolean is still true.
    let waiter = thread::spawn(move || wait_epollin(epfd, 3000));
    thread::sleep(Duration::from_millis(300));
    if send_query(sock, nameserver, QUERY_ID_PARKED) {
        r.wake_while_parked = waiter.join().unwrap_or(false);
        r.parked_reply_id_matches = recv_reply_id(sock) == Some(QUERY_ID_PARKED);
    } else {
        let _ = waiter.join();
    }

    libc::close(epfd);
    libc::close(sock);
}

fn main() {
    let mut results = Results::default();
    unsafe { run(&mut results) };
    report_results(&results);
}
