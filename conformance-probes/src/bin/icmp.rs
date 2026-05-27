//! ICMP ping-socket probe (WS-C3). Exercises an unprivileged
//! `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)` "ping socket" — the modern,
//! root-free path the `ping` utility uses (Linux gates it on
//! net.ipv4.ping_group_range, which Docker's arm64 image opens to all). macOS
//! likewise allows unprivileged SOCK_DGRAM/ICMP, so carrick passes the socket
//! straight through to the host. The harness diffs this byte-for-byte vs Docker.
//!
//! Deterministic only: a single boolean for "sent an echo request to loopback
//! and got a reply back". Bounded recv (no hang). The SOCK_RAW variant needs
//! root on macOS and is intentionally not probed.

use std::time::{Duration, Instant};

const IPPROTO_ICMP: i32 = 1;
const ICMP_ECHO: u8 = 8;

fn icmp_echo_packet(id: u16, seq: u16) -> [u8; 8] {
    let mut p = [0u8; 8];
    p[0] = ICMP_ECHO; // type
    p[1] = 0; // code
    // checksum (p[2..4]) left zero for now
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    let ck = checksum(&p);
    p[2..4].copy_from_slice(&ck.to_be_bytes());
    p
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn main() {
    let ok = unsafe { ping_loopback() };
    println!("icmp_ping_ok={ok}");
}

unsafe fn ping_loopback() -> bool {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, IPPROTO_ICMP);
    if fd < 0 {
        return false;
    }
    // Non-blocking + a deadline so a lost reply can't hang the harness.
    let flags = libc::fcntl(fd, libc::F_GETFL, 0);
    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();

    let pkt = icmp_echo_packet(0x1234, 1);
    let sent = libc::sendto(
        fd,
        pkt.as_ptr() as *const _,
        pkt.len(),
        0,
        &addr as *const _ as *const libc::sockaddr,
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    if sent < 0 {
        libc::close(fd);
        return false;
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 1500];
    let got = loop {
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n >= 8 {
            // Received an ICMP message back (echo reply). The exact framing
            // (IP header present or not) differs between kernels, so we only
            // assert "a reply of at least an ICMP header arrived".
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::hint::spin_loop();
    };
    libc::close(fd);
    got
}
