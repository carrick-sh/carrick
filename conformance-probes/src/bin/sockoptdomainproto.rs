//! getsockopt(SOL_SOCKET, SO_DOMAIN/SO_PROTOCOL) — Linux-only options with no
//! macOS equivalent. CPython's `socket.socket(fileno=fd)` queries SO_PROTOCOL
//! (and SO_DOMAIN via SO_DOMAIN) to reconstruct a socket from an inherited fd
//! (the multiprocessing forkserver path). carrick used to return ENOPROTOOPT,
//! breaking that reconstruct. Deterministic, line-exact carrick-vs-Linux.

const SO_DOMAIN: libc::c_int = 39;
const SO_PROTOCOL: libc::c_int = 38;

fn dom_proto(fd: i32) -> (i32, i32, i32) {
    unsafe {
        let mut dom: i32 = -1;
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        let rd = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_DOMAIN,
            (&mut dom as *mut i32).cast(),
            &mut len,
        );
        let mut proto: i32 = -1;
        let mut len2 = std::mem::size_of::<i32>() as libc::socklen_t;
        let rp = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PROTOCOL,
            (&mut proto as *mut i32).cast(),
            &mut len2,
        );
        // (combined rc, domain, protocol)
        ((rd == 0 && rp == 0) as i32, dom, proto)
    }
}

fn main() {
    unsafe {
        // AF_UNIX stream socket → SO_DOMAIN=AF_UNIX(1), SO_PROTOCOL=0.
        let u = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        let (ok_u, dom_u, proto_u) = dom_proto(u);
        println!("unix_getsockopt_ok={}", ok_u == 1);
        println!("unix_domain_af_unix={}", dom_u == libc::AF_UNIX);
        println!("unix_protocol_zero={}", proto_u == 0);
        libc::close(u);

        // AF_INET TCP socket → SO_DOMAIN=AF_INET(2), SO_PROTOCOL=IPPROTO_TCP(6).
        let t = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let (ok_t, dom_t, _proto_t) = dom_proto(t);
        println!("inet_getsockopt_ok={}", ok_t == 1);
        println!("inet_domain_af_inet={}", dom_t == libc::AF_INET);
        libc::close(t);
    }
}
