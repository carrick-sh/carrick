//! cachestat(fd, range, cstat, flags) (nr 451): page-cache stats for a file
//! range. carrick was ENOSYS; now it succeeds on a regular file and validates
//! args. This probe asserts only the ORACLE-AGREED parts — a valid call
//! succeeds, unknown flags → EINVAL, a bad fd → EBADF. The nr_cache/nr_evicted
//! page-accounting invariant (nr_cache + nr_evicted == num_pages) is a
//! Docker-LinuxKit-sensitive value (the container's cachestat reports it
//! inconsistently across filesystems), so it's covered by LTP cachestat02
//! (which runs on a real-fs tmpdir and MATCHes 20/20), NOT asserted here.
//! Raw syscall (nr 451). Deterministic booleans, line-exact vs Linux.

use conformance_probes::errno;

#[repr(C)]
struct CachestatRange {
    off: u64,
    len: u64,
}

fn main() {
    unsafe {
        let pg = libc::sysconf(libc::_SC_PAGESIZE) as u64;
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let fd = libc::open(
            b"/tmp/cstat\0".as_ptr() as *const _,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let buf = vec![0xABu8; (pg * 4) as usize];
        libc::write(fd, buf.as_ptr() as *const _, buf.len());

        let range = CachestatRange { off: 0, len: pg * 4 };
        let mut cs = [0u64; 5]; // nr_cache, nr_dirty, nr_writeback, nr_evicted, nr_recently_evicted

        // A valid cachestat on a regular file succeeds.
        let rc = libc::syscall(451, fd as i64, &range as *const _ as i64, cs.as_mut_ptr() as i64, 0i64);
        println!("cachestat_ok={}", rc == 0);

        // unknown flags → EINVAL.
        let r2 = libc::syscall(451, fd as i64, &range as *const _ as i64, cs.as_mut_ptr() as i64, 1i64);
        println!("cachestat_bad_flags_einval={}", r2 == -1 && errno() == libc::EINVAL);

        // bad fd → EBADF.
        let r3 = libc::syscall(451, -1i64, &range as *const _ as i64, cs.as_mut_ptr() as i64, 0i64);
        println!("cachestat_badfd_ebadf={}", r3 == -1 && errno() == libc::EBADF);

        let _ = errno;
        libc::close(fd);
        libc::unlink(b"/tmp/cstat\0".as_ptr() as *const _);
    }
}
