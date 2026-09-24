//! inotify(7) readiness when a sibling thread produces the event.
//!
//! One thread waits on an empty inotify instance; a sibling thread in the same
//! process then writes the watched file. Linux wakes the waiter with the
//! IN_MODIFY record. A drained instance must not report readable first.
//!
//! This is the shape Carrick's in-guest (EL1) kernel must handle: the sibling's
//! write can complete without any host syscall, so the waiter is woken only if
//! the in-guest enqueue reaches the host waiter.
//!
//! Every wait is bounded (3 s poll), so a lost wakeup is a false line, never a
//! hang. Output is normalized to deterministic boolean observations.

use conformance_probes::report;
use std::ffi::CString;
use std::time::Duration;

const IN_MODIFY: u32 = 0x0000_0002;
const EVENT_HEADER: isize = 16;

fn main() {
    let dir = format!("/tmp/inotifywakethread.{}", std::process::id());
    let dir_c = CString::new(dir.clone()).unwrap();
    let path_c = CString::new(format!("{dir}/f")).unwrap();
    unsafe {
        libc::mkdir(dir_c.as_ptr(), 0o700);
        let fd = libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_CLOEXEC,
            0o644,
        );
        let q = libc::inotify_init1(libc::IN_CLOEXEC);
        let wd = libc::inotify_add_watch(q, path_c.as_ptr(), IN_MODIFY);
        // Several writes first, so an implementation that serves steady-state
        // writes without the host kernel is doing so by the time it matters.
        for _ in 0..64 {
            libc::write(fd, b"w".as_ptr().cast(), 1);
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        // Drain without blocking; then the instance must not poll readable.
        libc::fcntl(q, libc::F_SETFL, libc::O_NONBLOCK);
        let mut buf = vec![0u8; 65536];
        while libc::read(q, buf.as_mut_ptr().cast(), buf.len()) > 0 {}
        let mut pfd = libc::pollfd {
            fd: q,
            events: libc::POLLIN,
            revents: 0,
        };
        let drained_ready = libc::poll(&mut pfd, 1, 0);
        libc::fcntl(q, libc::F_SETFL, 0);

        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            libc::write(fd, b"x".as_ptr().cast(), 1)
        });
        let mut pfd = libc::pollfd {
            fd: q,
            events: libc::POLLIN,
            revents: 0,
        };
        let woke = libc::poll(&mut pfd, 1, 3000);
        let n = if woke > 0 {
            libc::read(q, buf.as_mut_ptr().cast(), buf.len())
        } else {
            -1
        };
        let wrote = writer.join().unwrap_or(-1);
        let record_wd = if n >= EVENT_HEADER {
            i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]])
        } else {
            -1
        };
        let record_mask = if n >= EVENT_HEADER {
            u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]])
        } else {
            0
        };

        report!(
            setup_ok = fd >= 0 && q >= 0 && wd > 0,
            drained_instance_not_readable = drained_ready == 0,
            sibling_write_ok = wrote == 1,
            waiter_woken_by_sibling_write = woke == 1,
            woken_read_is_one_record = n == EVENT_HEADER,
            woken_record_is_modify_on_watch = record_wd == wd && record_mask == IN_MODIFY,
        );

        libc::close(q);
        libc::close(fd);
        libc::unlink(path_c.as_ptr());
        libc::rmdir(dir_c.as_ptr());
    }
}
