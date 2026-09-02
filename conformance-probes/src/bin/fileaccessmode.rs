//! A regular file's guest-visible access mode and status flags are what the
//! guest asked for, independent of how carrick opened the host fd.
//!
//! carrick opens every host-backed file `O_NONBLOCK` (a racing FIFO must
//! never block the dispatcher) and used to open a guest `O_RDONLY` file
//! `O_RDWR` on the host so a later `MAP_SHARED` mapping could carry the
//! write max-protection HVF demands. Both leaked: `fcntl(F_GETFL)` reported
//! `O_NONBLOCK` the guest never set, and `mprotect(PROT_WRITE)` on a
//! `MAP_SHARED` mapping of a read-only fd SUCCEEDED where Linux clears
//! `VM_MAYWRITE` and answers `EACCES`. The fix opens with the guest's own
//! access mode and upgrades the host fd only when a shared mapping needs
//! it, so the invariants below pin both the visible flags and the things
//! the upgrade must not disturb: the fd's file offset and the mapping's
//! coherence with later writes through another descriptor.
//!
//! Invariants encoded (one `key=value` line each, no addresses or pids):
//!   * `F_GETFL` of `O_RDONLY`/`O_WRONLY`/`O_RDWR|O_APPEND` opens reports
//!     exactly the access mode (+`O_APPEND`) with no `O_NONBLOCK`
//!   * an explicit `O_NONBLOCK` on open, or set by `F_SETFL`, IS reported,
//!     and a child's `F_SETFL` is visible through the parent's shared
//!     description
//!   * `mmap(PROT_READ, MAP_SHARED)` of an `O_RDONLY` fd works, sees a write
//!     made through a second descriptor, and refuses `mprotect(PROT_WRITE)`
//!     with `EACCES`; `mmap(PROT_WRITE, MAP_SHARED)` of it is `EACCES`
//!   * a read issued before the shared map continues from the same offset
//!     after it
//!   * `mmap(PROT_WRITE, MAP_PRIVATE)` of the read-only fd is writable and
//!     its stores never reach the file

use conformance_probes::{errno, report};
use std::ffi::CString;

const PATH: &str = "/tmp/carrick-fileaccessmode";
const CONTENT: &[u8] = b"hello world\n";

unsafe fn getfl(fd: i32) -> i32 {
    libc::fcntl(fd, libc::F_GETFL)
}

fn main() {
    unsafe {
        let path = CString::new(PATH).unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR, 0o644);
        report!(create_ok = fd >= 0);
        let n = libc::write(fd, CONTENT.as_ptr().cast(), CONTENT.len());
        report!(seed_written = n == CONTENT.len() as isize);
        libc::close(fd);

        let rd = libc::open(path.as_ptr(), libc::O_RDONLY);
        let fl = getfl(rd);
        report!(rdonly_accmode = fl & libc::O_ACCMODE);
        report!(rdonly_nonblock = fl & libc::O_NONBLOCK != 0);
        report!(rdonly_append = fl & libc::O_APPEND != 0);

        let wr = libc::open(path.as_ptr(), libc::O_WRONLY);
        let fl = getfl(wr);
        report!(wronly_accmode = fl & libc::O_ACCMODE);
        report!(wronly_nonblock = fl & libc::O_NONBLOCK != 0);
        libc::close(wr);

        let ap = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_APPEND);
        let fl = getfl(ap);
        report!(rdwr_append_accmode = fl & libc::O_ACCMODE);
        report!(rdwr_append_append = fl & libc::O_APPEND != 0);
        report!(rdwr_append_nonblock = fl & libc::O_NONBLOCK != 0);
        libc::close(ap);

        let nb = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
        report!(explicit_nonblock_reported = getfl(nb) & libc::O_NONBLOCK != 0);
        report!(setfl_clear_rc = libc::fcntl(nb, libc::F_SETFL, 0));
        report!(after_clear_nonblock = getfl(nb) & libc::O_NONBLOCK != 0);
        // The status flags live on the shared open file description: a
        // child's F_SETFL is the parent's F_GETFL.
        let child = libc::fork();
        if child == 0 {
            libc::fcntl(nb, libc::F_SETFL, libc::O_NONBLOCK);
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
        report!(child_setfl_visible = getfl(nb) & libc::O_NONBLOCK != 0);
        libc::close(nb);

        // Consume the first five bytes so the offset is mid-file when the
        // shared mapping is established.
        let mut head = [0u8; 5];
        let n = libc::read(rd, head.as_mut_ptr().cast(), head.len());
        report!(read_before_map = n == 5 && &head == b"hello");

        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let m = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_SHARED,
            rd,
            0,
        );
        report!(shared_read_map_ok = m != libc::MAP_FAILED);
        let m = m.cast::<u8>();
        report!(shared_map_content = std::slice::from_raw_parts(m, 5) == b"hello");

        let mut tail = [0u8; 6];
        let n = libc::read(rd, tail.as_mut_ptr().cast(), tail.len());
        report!(read_after_map_continues = n == 6 && &tail == b" world");

        let wr = libc::open(path.as_ptr(), libc::O_WRONLY);
        let n = libc::pwrite(wr, b"HELLO".as_ptr().cast(), 5, 0);
        libc::close(wr);
        report!(write_via_other_fd = n == 5);
        report!(shared_map_sees_write = std::slice::from_raw_parts(m, 5) == b"HELLO");

        let rc = libc::mprotect(m.cast(), page, libc::PROT_READ | libc::PROT_WRITE);
        report!(mprotect_write_rc = rc);
        report!(mprotect_write_errno = if rc < 0 { errno() } else { 0 });
        libc::munmap(m.cast(), page);

        let bad = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            rd,
            0,
        );
        report!(shared_write_map_failed = bad == libc::MAP_FAILED);
        report!(shared_write_map_errno = if bad == libc::MAP_FAILED { errno() } else { 0 });

        let p = libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            rd,
            0,
        );
        report!(private_write_map_ok = p != libc::MAP_FAILED);
        let p = p.cast::<u8>();
        *p = b'x';
        let mut byte = [0u8; 1];
        let n = libc::pread(rd, byte.as_mut_ptr().cast(), 1, 0);
        report!(private_store_not_in_file = n == 1 && byte[0] == b'H');
        libc::munmap(p.cast(), page);

        libc::close(rd);
        libc::unlink(path.as_ptr());
    }
}
