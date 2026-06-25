//! setsockopt(MCAST_JOIN_GROUP) probe. The protocol-independent multicast-join
//! sockopt (level IPPROTO_IP, optname 42, a 136-byte struct group_req) is what
//! the LTP networking framework sets during setup; carrick rejects it with
//! ENOPROTOOPT (macOS has no MCAST_JOIN_GROUP), TBROK'ing accept02/connect02/etc.
//! This probe records exactly what Linux returns on a TCP and a UDP socket so the
//! fix can match it. The harness diffs carrick vs Linux line by line.
//!
//! Deterministic: rc + errno only (never addresses/pids/times).

const MCAST_JOIN_GROUP: i32 = 42;
const IPPROTO_IP: i32 = 0;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn try_join(sock_type: i32, label: &str) {
    let fd = unsafe { libc::socket(libc::AF_INET, sock_type, 0) };
    if fd < 0 {
        println!("{}_socket=ERR:{}", label, errno());
        return;
    }
    // struct group_req { __u32 gr_interface; <4 pad>; struct sockaddr_storage gr_group; }
    // = 136 bytes on aarch64. gr_group @8 = sockaddr_in{AF_INET, port 0, 224.0.0.1}.
    let mut buf = [0u8; 136];
    buf[8..10].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes()); // sin_family @8
    buf[12..16].copy_from_slice(&[224, 0, 0, 1]); // sin_addr @12 (network order)
    let rc = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            MCAST_JOIN_GROUP,
            buf.as_ptr() as *const libc::c_void,
            136,
        )
    };
    println!("{}_rc={}", label, rc);
    println!("{}_errno={}", label, if rc < 0 { errno() } else { 0 });
    unsafe { libc::close(fd) };
}

fn main() {
    try_join(libc::SOCK_STREAM, "tcp");
    try_join(libc::SOCK_DGRAM, "udp");
}
