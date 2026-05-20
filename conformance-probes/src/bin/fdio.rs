//! File-descriptor / IO probe. Exercises pipe2/dup/lseek/pread/pwrite/fcntl/
//! O_APPEND/ftruncate/readv/writev syscalls and prints one labelled line per
//! observation. The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing syscall.
//!
//! Deterministic only: no fd numbers, timestamps, pids, or addresses. Where
//! content contains newlines they are shown as '|' so each line stays single.

use std::ffi::CString;

fn main() {
    // pipe2(): write "ping" to write end, read it back; then close write end
    // and confirm read returns 0 (EOF).
    {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
        if rc != 0 {
            println!("pipe2=ERR:{}", errno());
        } else {
            let (rd, wr) = (fds[0], fds[1]);
            let msg = b"ping";
            unsafe { libc::write(wr, msg.as_ptr() as *const _, msg.len()) };
            let mut buf = [0u8; 16];
            let n = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
            println!("pipe2_read={}", show(&buf[..n.max(0) as usize]));
            unsafe { libc::close(wr) };
            let n2 = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
            println!("pipe2_eof={}", n2 == 0);
            unsafe { libc::close(rd) };
        }
    }

    // dup/dup2/dup3: dup a pipe write fd, write via the dup, read back.
    // dup3(fd, fd, 0) must fail EINVAL (same oldfd == newfd).
    {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
        if rc != 0 {
            println!("dup=ERR:{}", errno());
        } else {
            let (rd, wr) = (fds[0], fds[1]);
            let dwr = unsafe { libc::dup(wr) };
            let msg = b"dup!";
            unsafe { libc::write(dwr, msg.as_ptr() as *const _, msg.len()) };
            let mut buf = [0u8; 16];
            let n = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
            println!("dup_roundtrip={}", &buf[..n.max(0) as usize] == msg);

            // dup3 with oldfd == newfd is EINVAL.
            let r3 = unsafe { libc::dup3(wr, wr, 0) };
            println!(
                "dup3_same_einval={}",
                r3 == -1 && errno() == libc::EINVAL
            );

            unsafe {
                libc::close(dwr);
                libc::close(wr);
                libc::close(rd);
            }
        }
    }

    // lseek: create /tmp/seek with "0123456789"; seek to 3, read 2 -> "34";
    // SEEK_END offset is 10.
    {
        let fd = open("/tmp/seek", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            println!("lseek=ERR:{}", errno());
        } else {
            let data = b"0123456789";
            unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
            unsafe { libc::lseek(fd, 3, libc::SEEK_SET) };
            let mut buf = [0u8; 2];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
            println!("lseek_read={}", show(&buf[..n.max(0) as usize]));
            let end = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
            println!("lseek_end={}", end);
            unsafe { libc::close(fd) };
        }
    }

    // pread/pwrite: pwrite "XY" at offset 5 of /tmp/seek (no seek change), then
    // pread 2 at offset 5 -> "XY". Confirm SEEK_CUR is unchanged across both.
    {
        let fd = open("/tmp/seek", libc::O_RDWR, 0);
        if fd < 0 {
            println!("pwrite=ERR:{}", errno());
        } else {
            // Position the file offset somewhere known (2) first.
            unsafe { libc::lseek(fd, 2, libc::SEEK_SET) };
            let before = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
            let xy = b"XY";
            unsafe { libc::pwrite(fd, xy.as_ptr() as *const _, xy.len(), 5) };
            let mut buf = [0u8; 2];
            let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut _, buf.len(), 5) };
            println!("pread={}", show(&buf[..n.max(0) as usize]));
            let after = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
            println!("pread_offset_unchanged={}", before == after);
            unsafe { libc::close(fd) };
        }
    }

    // fcntl: F_GETFL on an O_WRONLY fd -> access mode bits == O_WRONLY (1).
    // F_GETFD/F_SETFD FD_CLOEXEC round-trip.
    {
        let fd = open("/tmp/seek", libc::O_WRONLY, 0);
        if fd < 0 {
            println!("fcntl=ERR:{}", errno());
        } else {
            let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            println!("fcntl_accmode={}", fl & libc::O_ACCMODE);

            // Initially no FD_CLOEXEC.
            let fd0 = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            println!("fcntl_cloexec_initial={}", (fd0 & libc::FD_CLOEXEC) != 0);
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            let fd1 = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            println!("fcntl_cloexec_set={}", (fd1 & libc::FD_CLOEXEC) != 0);
            unsafe { libc::close(fd) };
        }
    }

    // O_APPEND: write "one\n", reopen with O_APPEND and write "two\n", read
    // whole file -> "one|two|".
    {
        let fd = open("/tmp/ap", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd >= 0 {
            let one = b"one\n";
            unsafe { libc::write(fd, one.as_ptr() as *const _, one.len()) };
            unsafe { libc::close(fd) };
        }
        let fd = open("/tmp/ap", libc::O_WRONLY | libc::O_APPEND, 0);
        if fd >= 0 {
            let two = b"two\n";
            unsafe { libc::write(fd, two.as_ptr() as *const _, two.len()) };
            unsafe { libc::close(fd) };
        }
        match std::fs::read("/tmp/ap") {
            Ok(b) => println!("o_append={}", show(&b)),
            Err(e) => println!("o_append=ERR:{}", e.raw_os_error().unwrap_or(-1)),
        }
    }

    // ftruncate: write "abcdef" to /tmp/tr, truncate to 3, read -> "abc".
    {
        let fd = open("/tmp/tr", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            println!("ftruncate=ERR:{}", errno());
        } else {
            let data = b"abcdef";
            unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
            unsafe { libc::ftruncate(fd, 3) };
            unsafe { libc::close(fd) };
            match std::fs::read("/tmp/tr") {
                Ok(b) => println!("ftruncate={}", show(&b)),
                Err(e) => println!("ftruncate=ERR:{}", e.raw_os_error().unwrap_or(-1)),
            }
        }
    }

    // readv/writev: writev two iovecs ("AB","CD") to /tmp/v, read 4 -> "ABCD".
    {
        let fd = open("/tmp/v", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if fd < 0 {
            println!("writev=ERR:{}", errno());
        } else {
            let a = b"AB";
            let c = b"CD";
            let wiov = [
                libc::iovec {
                    iov_base: a.as_ptr() as *mut _,
                    iov_len: a.len(),
                },
                libc::iovec {
                    iov_base: c.as_ptr() as *mut _,
                    iov_len: c.len(),
                },
            ];
            unsafe { libc::writev(fd, wiov.as_ptr(), wiov.len() as i32) };
            unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
            let mut b0 = [0u8; 2];
            let mut b1 = [0u8; 2];
            let riov = [
                libc::iovec {
                    iov_base: b0.as_mut_ptr() as *mut _,
                    iov_len: b0.len(),
                },
                libc::iovec {
                    iov_base: b1.as_mut_ptr() as *mut _,
                    iov_len: b1.len(),
                },
            ];
            let n = unsafe { libc::readv(fd, riov.as_ptr(), riov.len() as i32) };
            let mut out = Vec::new();
            out.extend_from_slice(&b0);
            out.extend_from_slice(&b1);
            let n = n.max(0) as usize;
            println!("readv={}", show(&out[..n.min(out.len())]));
            unsafe { libc::close(fd) };
        }
    }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Render bytes as a deterministic single-line token: newlines -> '|', other
/// non-printable bytes -> \xHH, printable ASCII verbatim.
fn show(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'\n' => s.push('|'),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{:02x}", b)),
        }
    }
    s
}
