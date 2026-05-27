//! rtnetlink RTM_GETROUTE probe (WS-C3). Opens an AF_NETLINK/NETLINK_ROUTE
//! socket, sends an RTM_GETROUTE dump request, and walks the multipart reply.
//! Real Linux returns the kernel routing table; carrick synthesizes a connected
//! route per host address. The exact routes differ per host, so we assert only
//! the deterministic SHAPE both must satisfy: at least one RTM_NEWROUTE message,
//! terminated by NLMSG_DONE. The harness diffs these booleans vs Docker.

use std::time::{Duration, Instant};

const NETLINK_ROUTE: i32 = 0;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWROUTE: u16 = 24;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH

fn main() {
    let (routes, done) = unsafe { dump_routes() };
    println!("route_dump_ok={}", routes >= 1);
    println!("route_dump_done={done}");
}

unsafe fn dump_routes() -> (usize, bool) {
    let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE);
    if fd < 0 {
        return (0, false);
    }
    // Request: nlmsghdr (16) + rtgenmsg (1 byte family), 4-byte aligned to 20.
    let mut req = [0u8; 20];
    let len: u32 = 20;
    req[0..4].copy_from_slice(&len.to_ne_bytes());
    req[4..6].copy_from_slice(&RTM_GETROUTE.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    req[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid (kernel assigns)
    req[16] = libc::AF_UNSPEC as u8; // rtgen_family

    let sent = libc::send(fd, req.as_ptr() as *const _, req.len(), 0);
    if sent < 0 {
        libc::close(fd);
        return (0, false);
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 8192];
    let mut routes = 0usize;
    let mut done = false;
    'outer: while Instant::now() < deadline {
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0);
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        let total = n as usize;
        while off + 16 <= total {
            let msg_len =
                u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
            let msg_type = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
            if msg_len < 16 || off + msg_len > total {
                break;
            }
            match msg_type {
                RTM_NEWROUTE => routes += 1,
                NLMSG_DONE => {
                    done = true;
                    break 'outer;
                }
                _ => {}
            }
            off += (msg_len + 3) & !3; // NLMSG_ALIGN(4)
        }
    }
    libc::close(fd);
    (routes, done)
}
