//! Named-pipe (FIFO) support: `mknod(S_IFIFO)` creates a real node that stats
//! as `S_IFIFO` with the requested mode; opening it `O_RDWR` yields a
//! bidirectional fd that `select` reports writable (empty) and readable after a
//! write; `mknod(S_IFMT)` (ambiguous type) → EINVAL. Stands in for LTP
//! mknod01/mknod09 and the FIFO leg of select01. Crucially, a writer-less
//! `O_RDONLY` open returns immediately (carrick opens the host FIFO
//! NON-BLOCKING so it can't wedge the single dispatcher thread).
//!
//! Deterministic booleans, diffed line-exact carrick-vs-Linux. `umask(0)` keeps
//! the mode comparison independent of the ambient umask on both sides.

use conformance_probes::errno;

unsafe fn select_ready(fd: i32, want_read: bool) -> bool {
    let mut set: libc::fd_set = std::mem::zeroed();
    libc::FD_ZERO(&mut set);
    libc::FD_SET(fd, &mut set);
    // 50ms bound: readiness for a FIFO with/without buffered data is
    // deterministic; the timeout only caps a (never-expected) hang.
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 50_000,
    };
    let (r, w) = if want_read {
        (&mut set as *mut _, std::ptr::null_mut())
    } else {
        (std::ptr::null_mut(), &mut set as *mut _)
    };
    let rc = libc::select(fd + 1, r, w, std::ptr::null_mut(), &mut tv);
    rc == 1 && libc::FD_ISSET(fd, &set)
}

fn main() {
    unsafe {
        libc::umask(0);
        // run-elf's rootfs is empty; ensure /tmp exists (no-op under Docker).
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/cfifo\0".as_ptr() as *const libc::c_char;
        libc::unlink(path);

        // 1. mknod S_IFIFO succeeds.
        let rc = libc::mknod(path, libc::S_IFIFO | 0o644, 0);
        println!("mknod_fifo_ok={}", rc == 0);

        // 2. stat reports S_IFIFO + the (umask-0) mode.
        let mut st: libc::stat = std::mem::zeroed();
        let strc = libc::stat(path, &mut st);
        println!("stat_ok={}", strc == 0);
        println!(
            "stat_is_fifo={}",
            (st.st_mode & libc::S_IFMT) == libc::S_IFIFO
        );
        println!("stat_mode_0644={}", (st.st_mode & 0o7777) == 0o644);

        // 3. open O_RDWR — never blocks (single fd is both reader and writer).
        let fd = libc::open(path, libc::O_RDWR);
        println!("open_rdwr_ok={}", fd >= 0);

        // 4. empty FIFO: writable (buffer has space), not readable (no data).
        println!("writable_when_empty={}", select_ready(fd, false));
        println!("readable_when_empty={}", select_ready(fd, true));

        // 5. write through the O_RDWR fd, then it becomes readable.
        let w = libc::write(fd, b"hi".as_ptr() as *const _, 2);
        println!("write_ok={}", w == 2);
        println!("readable_after_write={}", select_ready(fd, true));

        // 5b. the SAME O_RDWR fd in BOTH readfds and writefds in one select():
        // it is readable (data present) and writable (buffer space), so select
        // counts it twice → returns 2 (LTP select01's FIFO leg).
        {
            let mut rset: libc::fd_set = std::mem::zeroed();
            let mut wset: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut rset);
            libc::FD_ZERO(&mut wset);
            libc::FD_SET(fd, &mut rset);
            libc::FD_SET(fd, &mut wset);
            let mut tv = libc::timeval {
                tv_sec: 0,
                tv_usec: 50_000,
            };
            let rc = libc::select(fd + 1, &mut rset, &mut wset, std::ptr::null_mut(), &mut tv);
            println!("select_rdwr_returns_2={}", rc == 2);
        }

        // 6. read it back.
        let mut rb = [0u8; 2];
        let r = libc::read(fd, rb.as_mut_ptr() as *mut _, 2);
        println!("read_ok={}", r == 2 && &rb == b"hi");

        libc::close(fd);

        // 7. O_RDONLY open of the (now writer-less) FIFO with O_NONBLOCK returns
        // immediately (no writer present) — proves the non-blocking open path.
        let rofd = libc::open(path, libc::O_RDONLY | libc::O_NONBLOCK);
        println!("open_rdonly_nonblock_ok={}", rofd >= 0);
        if rofd >= 0 {
            libc::close(rofd);
        }
        libc::unlink(path);

        // 8. mknod with an ambiguous type (S_IFMT) → EINVAL (LTP mknod09).
        let bad = b"/tmp/cbad\0".as_ptr() as *const libc::c_char;
        libc::unlink(bad);
        let brc = libc::mknod(bad, libc::S_IFMT, 0);
        println!(
            "mknod_ifmt_einval={}",
            brc == -1 && errno() == libc::EINVAL
        );
    }
}
