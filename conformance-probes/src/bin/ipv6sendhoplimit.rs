//! sendmsg(2) with an IPV6_HOPLIMIT ancillary cmsg must set the outgoing
//! packet's hop limit — CPython's testSetHopLimit sends with a chosen hop limit
//! and asserts the receiver reads it back. carrick forwarded only SCM_RIGHTS on
//! send, so the IPV6_HOPLIMIT cmsg was dropped and the packet used the default
//! hop limit instead of the requested one.
//!
//!  * sent_hoplimit_roundtrips: send a loopback datagram with IPV6_HOPLIMIT=7
//!    via a send cmsg; the receiver's IPV6_HOPLIMIT cmsg reads 7 (not the
//!    default 64).

use conformance_probes::report;

const IPPROTO_IPV6: i32 = 41;
const IPV6_RECVHOPLIMIT: i32 = 51;
const IPV6_HOPLIMIT: i32 = 52;

fn main() {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            report!(sent_hoplimit_roundtrips = false);
            return;
        }
        let on: i32 = 1;
        libc::setsockopt(
            fd,
            IPPROTO_IPV6,
            IPV6_RECVHOPLIMIT,
            &on as *const _ as *const libc::c_void,
            4,
        );
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_addr.s6_addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let alen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let mut ok = false;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, alen) == 0 {
            let mut bound: libc::sockaddr_in6 = std::mem::zeroed();
            let mut blen = alen;
            libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut blen);

            let payload = b"hl";
            let mut iov = libc::iovec {
                iov_base: payload.as_ptr() as *mut _,
                iov_len: payload.len(),
            };
            // Send cmsg: IPV6_HOPLIMIT = 7.
            let mut cbuf = [0u8; 64];
            let mut smh: libc::msghdr = std::mem::zeroed();
            smh.msg_name = &mut bound as *mut _ as *mut libc::c_void;
            smh.msg_namelen = blen;
            smh.msg_iov = &mut iov;
            smh.msg_iovlen = 1;
            smh.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            smh.msg_controllen = cbuf.len() as _;
            let cmsg = libc::CMSG_FIRSTHDR(&smh);
            (*cmsg).cmsg_level = IPPROTO_IPV6;
            (*cmsg).cmsg_type = IPV6_HOPLIMIT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(4) as _;
            let hl: i32 = 7;
            std::ptr::copy_nonoverlapping(&hl as *const i32 as *const u8, libc::CMSG_DATA(cmsg), 4);
            smh.msg_controllen = libc::CMSG_SPACE(4) as _;
            let sent = libc::sendmsg(fd, &smh, 0);

            if sent == payload.len() as isize {
                let mut buf = [0u8; 16];
                let mut riov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut _,
                    iov_len: buf.len(),
                };
                let mut rcbuf = [0u8; 256];
                let mut rmh: libc::msghdr = std::mem::zeroed();
                rmh.msg_iov = &mut riov;
                rmh.msg_iovlen = 1;
                rmh.msg_control = rcbuf.as_mut_ptr() as *mut libc::c_void;
                rmh.msg_controllen = rcbuf.len() as _;
                if libc::recvmsg(fd, &mut rmh, 0) >= 0 {
                    let mut c = libc::CMSG_FIRSTHDR(&rmh);
                    while !c.is_null() {
                        if (*c).cmsg_level == IPPROTO_IPV6 && (*c).cmsg_type == IPV6_HOPLIMIT {
                            let mut v: i32 = 0;
                            std::ptr::copy_nonoverlapping(
                                libc::CMSG_DATA(c),
                                &mut v as *mut i32 as *mut u8,
                                4,
                            );
                            ok = v == 7;
                        }
                        c = libc::CMSG_NXTHDR(&rmh, c);
                    }
                }
            }
        }
        report!(sent_hoplimit_roundtrips = ok);
        libc::close(fd);
    }
}
