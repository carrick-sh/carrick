//! Linux treats the entire `127.0.0.0/8` as loopback — a process can bind and
//! connect to any `127.x.y.z` on `lo`. macOS only assigns `127.0.0.1` to `lo0`,
//! so carrick's host-passthrough bind/connect to e.g. `127.0.1.1` fails
//! EADDRNOTAVAIL. That matters because the Debian-convention `/etc/hosts`
//! self-mapping puts the hostname on `127.0.1.1`, so `bind((gethostname(), port))`
//! — a common server idiom — broke.
//!
//! carrick must fold the whole `127/8` range onto `127.0.0.1` when translating a
//! guest sockaddr to the host (read_linux_sockaddr), so loopback behaves as
//! Linux apps expect. INVARIANT: bind to a non-`.0.1` loopback address succeeds,
//! and a full TCP round-trip over such an address works (bind + connect + accept
//! all translate consistently).

use conformance_probes::report;

unsafe fn sockaddr_in(octets: [u8; 4], port_be: u16) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = core::mem::zeroed();
    sa.sin_family = libc::AF_INET as _;
    sa.sin_port = port_be; // network byte order
    // s_addr is network byte order; `octets` are already in network order.
    sa.sin_addr.s_addr = u32::from_ne_bytes(octets);
    sa
}

unsafe fn try_bind(octets: [u8; 4]) -> bool {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        return false;
    }
    let sa = sockaddr_in(octets, 0);
    let rc = libc::bind(
        fd,
        &sa as *const _ as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    );
    libc::close(fd);
    rc == 0
}

fn main() {
    unsafe {
        // (a) bind to two non-.0.1 loopback addresses.
        let bind_127_0_1_1 = try_bind([127, 0, 1, 1]);
        let bind_127_0_0_9 = try_bind([127, 0, 0, 9]);

        // (b) full TCP round-trip over a 127/8 address that isn't .0.1.
        let mut roundtrip = false;
        let lfd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if lfd >= 0 {
            let mut la = sockaddr_in([127, 0, 3, 3], 0);
            let sz = core::mem::size_of::<libc::sockaddr_in>() as u32;
            let b = libc::bind(lfd, &la as *const _ as *const libc::sockaddr, sz);
            let l = libc::listen(lfd, 1);
            // Recover the assigned port.
            let mut alen = sz;
            libc::getsockname(lfd, &mut la as *mut _ as *mut libc::sockaddr, &mut alen);
            let port = la.sin_port;
            if b == 0 && l == 0 {
                let cfd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let ca = sockaddr_in([127, 0, 3, 3], port);
                let crc = libc::connect(cfd, &ca as *const _ as *const libc::sockaddr, sz);
                let afd = libc::accept(lfd, core::ptr::null_mut(), core::ptr::null_mut());
                let mut ok = crc == 0 && afd >= 0;
                if ok {
                    let msg = b"X";
                    let sent = libc::send(cfd, msg.as_ptr().cast(), 1, 0);
                    let mut buf = [0u8; 1];
                    let got = libc::recv(afd, buf.as_mut_ptr().cast(), 1, 0);
                    ok = sent == 1 && got == 1 && buf[0] == b'X';
                }
                roundtrip = ok;
                if cfd >= 0 {
                    libc::close(cfd);
                }
                if afd >= 0 {
                    libc::close(afd);
                }
            }
            libc::close(lfd);
        }

        report!(
            bind_127_0_1_1 = bind_127_0_1_1,
            bind_127_0_0_9 = bind_127_0_0_9,
            loopback_subnet_roundtrip = roundtrip,
        );
    }
}
