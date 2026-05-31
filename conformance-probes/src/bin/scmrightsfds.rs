//! SCM_RIGHTS fd-passing over an AF_UNIX socketpair (sendmsg/recvmsg ancillary
//! data). This is the multiprocessing.reduction.send_fds/recv_fds path the
//! forkserver uses to hand a process its inherited descriptors. carrick used to
//! model NO ancillary data, so recv_fds got empty ancdata and the child died.
//!
//! We open a temp file, write a known marker into it, send its fd over the pair
//! via SCM_RIGHTS, receive it on the other end as a FRESH fd, then read the
//! marker back through the received fd — proving it's a real, live description
//! and not the same integer. Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

const MARKER: &[u8] = b"scm-rights-ok\n";
const TMP_PATH: &[u8] = b"/tmp/carrick_scmrights_payload\0";

fn main() {
    unsafe {
        // A connected AF_UNIX stream pair to pass the fd over.
        let mut sv = [0i32; 2];
        let pr = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
        println!("socketpair_ok={}", pr == 0);

        // A regular file with a known marker; this fd is what we pass.
        libc::unlink(TMP_PATH.as_ptr() as *const libc::c_char);
        let payload = libc::open(
            TMP_PATH.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        println!("open_payload_ok={}", payload >= 0);
        let w = libc::write(
            payload,
            MARKER.as_ptr() as *const libc::c_void,
            MARKER.len(),
        );
        println!("write_marker_ok={}", w == MARKER.len() as isize);

        // --- sender: sendmsg with one SCM_RIGHTS cmsg carrying `payload` ---
        let mut iov_byte = [b'.'; 1];
        let mut iov = libc::iovec {
            iov_base: iov_byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let cmsg_space = libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) as usize;
        let mut cbuf = vec![0u8; cmsg_space];
        let mut smsg: libc::msghdr = std::mem::zeroed();
        smsg.msg_iov = &mut iov;
        smsg.msg_iovlen = 1;
        smsg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        smsg.msg_controllen = cbuf.len() as _;
        let cmsg = libc::CMSG_FIRSTHDR(&smsg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        let dp = libc::CMSG_DATA(cmsg) as *mut i32;
        std::ptr::write(dp, payload);
        let sent = libc::sendmsg(sv[0], &smsg, 0);
        println!("sendmsg_ok={}", sent == 1);

        // --- receiver: recvmsg pulls the byte + the SCM_RIGHTS cmsg ---
        let mut rbyte = [0u8; 1];
        let mut riov = libc::iovec {
            iov_base: rbyte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut rcbuf = vec![0u8; cmsg_space];
        let mut rmsg: libc::msghdr = std::mem::zeroed();
        rmsg.msg_iov = &mut riov;
        rmsg.msg_iovlen = 1;
        rmsg.msg_control = rcbuf.as_mut_ptr() as *mut libc::c_void;
        rmsg.msg_controllen = rcbuf.len() as _;
        let got = libc::recvmsg(sv[1], &mut rmsg, 0);
        println!("recvmsg_ok={}", got == 1);

        // Exactly one SCM_RIGHTS cmsg with one fd should have arrived.
        let mut received_fd = -1i32;
        let mut n_cmsg = 0;
        let mut c = libc::CMSG_FIRSTHDR(&rmsg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                n_cmsg += 1;
                received_fd = std::ptr::read(libc::CMSG_DATA(c) as *const i32);
            }
            c = libc::CMSG_NXTHDR(&rmsg, c);
        }
        println!("one_scm_cmsg={}", n_cmsg == 1);
        println!("received_fd_valid={}", received_fd >= 0);
        // The received fd must be a DIFFERENT integer than the sent one (the
        // kernel installs a fresh fd in the receiver), and not the socket itself.
        println!(
            "received_fd_fresh={}",
            received_fd >= 0
                && received_fd != payload
                && received_fd != sv[0]
                && received_fd != sv[1]
        );

        // Read the marker back through the RECEIVED fd from offset 0 — proves
        // it's a real, live description pointing at the same file.
        let mut back = [0u8; 32];
        let n = if received_fd >= 0 {
            libc::lseek(received_fd, 0, libc::SEEK_SET);
            libc::read(
                received_fd,
                back.as_mut_ptr() as *mut libc::c_void,
                back.len(),
            )
        } else {
            -1
        };
        println!(
            "readback_matches={}",
            n == MARKER.len() as isize && &back[..MARKER.len()] == MARKER
        );

        if received_fd >= 0 {
            libc::close(received_fd);
        }
        libc::close(payload);
        libc::close(sv[0]);
        libc::close(sv[1]);
        libc::unlink(TMP_PATH.as_ptr() as *const libc::c_char);
        let _ = errno;
    }
}
