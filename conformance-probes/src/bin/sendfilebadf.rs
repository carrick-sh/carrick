//! sendfile(2) validates fd access modes: a write-only (O_WRONLY) in_fd → EBADF
//! (sendfile READS the source, LTP sendfile03 case 4); a read-only out_fd →
//! EBADF; a valid O_RDONLY→O_WRONLY transfer of N bytes returns N. carrick
//! previously read the source regardless of the guest's in_fd access mode.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let src = b"/tmp/sf_src\0".as_ptr() as *const libc::c_char;
        let dst = b"/tmp/sf_dst\0".as_ptr() as *const libc::c_char;
        // Seed src with 8 bytes; create dst.
        let fc = libc::open(src, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        libc::write(fc, b"sendfile".as_ptr() as *const _, 8);
        libc::close(fc);
        let dc = libc::open(dst, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        libc::close(dc);

        // in_fd opened O_WRONLY → EBADF (can't read the source).
        let in_wr = libc::open(src, libc::O_WRONLY);
        let out_wr = libc::open(dst, libc::O_WRONLY);
        let r1 = libc::sendfile(out_wr, in_wr, std::ptr::null_mut(), 8);
        println!(
            "sendfile_in_wronly_ebadf={}",
            r1 == -1 && errno() == libc::EBADF
        );
        libc::close(in_wr);

        // out_fd opened O_RDONLY → EBADF (can't write the destination).
        let in_rd = libc::open(src, libc::O_RDONLY);
        let out_rd = libc::open(dst, libc::O_RDONLY);
        let r2 = libc::sendfile(out_rd, in_rd, std::ptr::null_mut(), 8);
        println!(
            "sendfile_out_rdonly_ebadf={}",
            r2 == -1 && errno() == libc::EBADF
        );
        libc::close(out_rd);

        // Valid transfer: O_RDONLY in → O_WRONLY out, 8 bytes.
        let r3 = libc::sendfile(out_wr, in_rd, std::ptr::null_mut(), 8);
        println!("sendfile_valid_returns_8={}", r3 == 8);

        libc::close(in_rd);
        libc::close(out_wr);
        libc::unlink(src);
        libc::unlink(dst);
    }
}
