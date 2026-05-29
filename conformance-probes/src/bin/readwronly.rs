//! read(2) fd access-mode validation (LTP open09, creat01): read() on a regular
//! file opened write-only (O_WRONLY, e.g. via creat()) → EBADF; a readable fd
//! returns the bytes. carrick read the fd regardless of access mode.
//! Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/readwr_f\0".as_ptr() as *const libc::c_char;
        // creat() returns a WRITE-ONLY fd; seed 4 bytes through it.
        let wr = libc::creat(path, 0o644);
        let data = b"wxyz";
        libc::write(wr, data.as_ptr() as *const _, 4);

        // read() on that write-only fd → EBADF (not open for reading).
        let mut buf = [0u8; 4];
        let r1 = libc::read(wr, buf.as_mut_ptr() as *mut _, 4);
        println!("read_wronly_ebadf={}", r1 == -1 && errno() == libc::EBADF);
        libc::close(wr);

        // read() on an O_RDONLY fd → returns the 4 bytes.
        let rd = libc::open(path, libc::O_RDONLY);
        let r2 = libc::read(rd, buf.as_mut_ptr() as *mut _, 4);
        println!("read_rdonly_reads4={}", r2 == 4 && &buf == data);
        libc::close(rd);

        let _ = errno;
    }
}
