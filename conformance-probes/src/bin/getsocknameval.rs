//! getsockname(2) output-pointer validation (LTP getsockname01): a NULL addr
//! or NULL addrlen → EFAULT; a negative input *addrlen → EINVAL; valid
//! pointers → success. carrick let the NULL/negative cases succeed.
//! Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let addr_ptr = &mut addr as *mut _ as *mut libc::sockaddr;

        // NULL addr → EFAULT.
        let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let r1 = libc::getsockname(s, std::ptr::null_mut(), &mut len);
        println!(
            "getsockname_null_addr_efault={}",
            r1 == -1 && errno() == libc::EFAULT
        );

        // NULL addrlen → EFAULT.
        let r2 = libc::getsockname(s, addr_ptr, std::ptr::null_mut());
        println!(
            "getsockname_null_len_efault={}",
            r2 == -1 && errno() == libc::EFAULT
        );

        // negative *addrlen (0xFFFFFFFF == -1 as i32) → EINVAL.
        let mut neg: libc::socklen_t = u32::MAX;
        let r3 = libc::getsockname(s, addr_ptr, &mut neg);
        println!(
            "getsockname_neg_len_einval={}",
            r3 == -1 && errno() == libc::EINVAL
        );

        // valid pointers → success.
        let mut good: libc::socklen_t = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let r4 = libc::getsockname(s, addr_ptr, &mut good);
        println!("getsockname_ok={}", r4 == 0);

        libc::close(s);
        let _ = errno;
    }
}
