//! recvmsg(2) must return IPv6 ancillary data (IPV6_HOPLIMIT) when the socket
//! has IPV6_RECVHOPLIMIT set — CPython's RecvmsgRFC3542AncillaryUDP6Test relies
//! on this (`assertEqual(len(ancdata), 1)`). macOS supports RFC 3542 ancillary
//! data but assigns DIFFERENT constant values than Linux (and gates them behind
//! __APPLE_USE_RFC_3542); carrick passed the Linux IPV6_RECVHOPLIMIT value (51)
//! untranslated to macOS (where 51 means something else, so the option never
//! took effect) and recvmsg_inner forwarded only SCM_RIGHTS, dropping the cmsg.
//!
//!  * hoplimit_cmsg_received: after setsockopt(IPV6_RECVHOPLIMIT,1), a recvmsg
//!    of a self-sent datagram returns exactly one cmsg with
//!    cmsg_level==IPPROTO_IPV6 && cmsg_type==IPV6_HOPLIMIT (Linux value 52).

use conformance_probes::report;

const IPPROTO_IPV6: i32 = 41;
const IPV6_RECVHOPLIMIT: i32 = 51; // Linux value
const IPV6_HOPLIMIT: i32 = 52; // Linux value

fn main() {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            report!(hoplimit_cmsg_received = false);
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
        // bind ::1:0
        let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_addr.s6_addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        let alen = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let mut got = false;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, alen) == 0 {
            let mut bound: libc::sockaddr_in6 = std::mem::zeroed();
            let mut blen = alen;
            libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut blen);
            let msg = b"hop";
            libc::sendto(
                fd,
                msg.as_ptr() as *const libc::c_void,
                msg.len(),
                0,
                &bound as *const _ as *const libc::sockaddr,
                blen,
            );
            let mut buf = [0u8; 16];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut control = [0u8; 256];
            let mut mh: libc::msghdr = std::mem::zeroed();
            mh.msg_iov = &mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            mh.msg_controllen = control.len() as _;
            let n = libc::recvmsg(fd, &mut mh, 0);
            if n >= 0 {
                let mut cmsg = libc::CMSG_FIRSTHDR(&mh);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == IPPROTO_IPV6 && (*cmsg).cmsg_type == IPV6_HOPLIMIT {
                        got = true;
                    }
                    cmsg = libc::CMSG_NXTHDR(&mh, cmsg);
                }
            }
        }
        report!(hoplimit_cmsg_received = got);
        libc::close(fd);
    }
}
