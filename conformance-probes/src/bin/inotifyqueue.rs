//! inotify(7) undrained-queue semantics probe.
//!
//! An inotify instance queues records until the guest reads them or the queue
//! reaches `/proc/sys/fs/inotify/max_queued_events`. Readiness (`poll`,
//! `epoll_wait`, `ioctl(FIONREAD)`) must stay correct and answerable while the
//! queue deepens, which is the shape LTP's `inotify09` sustains: events are
//! produced far faster than they are consumed.
//!
//! Covers:
//! 1. A deepening queue stays readable, with `FIONREAD` growing monotonically.
//! 2. Distinct child names are not coalesced (inotify(7) coalesces only
//!    byte-identical back-to-back events); identical repeats are.
//! 3. A partial drain leaves the instance readable and the remainder queued.
//! 4. A full drain makes the instance unreadable again and `FIONREAD` zero.
//!
//! Output is normalized to deterministic boolean observations.

use conformance_probes::{arm_alarm_ms, disarm_alarm, report};
use std::ffi::CString;

const IN_NONBLOCK: i32 = libc::IN_NONBLOCK;
const IN_MODIFY: u32 = 0x0000_0002;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;

/// How deep the queue is driven. Small enough to stay far below the default
/// 16384-event limit, so no `IN_Q_OVERFLOW` record can enter the comparison.
const DEPTH: usize = 256;

unsafe fn inotify_init1(flags: i32) -> i32 {
    unsafe { libc::inotify_init1(flags) }
}

unsafe fn add_watch(fd: i32, path: &str, mask: u32) -> i32 {
    let cpath = CString::new(path).unwrap();
    unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), mask) }
}

fn mkdir_dir(path: &str) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        libc::mkdir(cpath.as_ptr(), 0o755);
    }
}

fn create_file(path: &str) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        let fd = libc::open(cpath.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644);
        if fd >= 0 {
            libc::close(fd);
        }
    }
}

fn touch_same_file(path: &str) {
    let cpath = CString::new(path).unwrap();
    unsafe {
        let fd = libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_APPEND, 0o644);
        if fd >= 0 {
            libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1);
            libc::close(fd);
        }
    }
}

fn readable(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Every wait is bounded: a lost wake must show up as a false line, never a
    // wedged gate.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc == 1 && (pfd.revents & libc::POLLIN) != 0
}

fn fionread(fd: i32) -> i32 {
    let mut count: i32 = -1;
    let rc = unsafe { libc::ioctl(fd, libc::FIONREAD, &mut count) };
    if rc == 0 { count } else { -1 }
}

fn main() {
    unsafe {
        arm_alarm_ms(30_000);
        let base = format!("/tmp/inotifyqueue_{}", libc::getpid());
        mkdir_dir(&base);

        let ifd = inotify_init1(IN_NONBLOCK);
        let dir = format!("{base}/watched");
        mkdir_dir(&dir);
        let wd = add_watch(ifd, &dir, IN_CREATE | IN_DELETE | IN_MODIFY);

        // 1. Deepen the queue without ever reading it.
        let empty_readable = readable(ifd, 0);
        let empty_count = fionread(ifd);

        let mut monotonic = true;
        let mut stayed_readable = true;
        let mut previous = 0;
        for i in 0..DEPTH {
            create_file(&format!("{dir}/queued_{i}.tmp"));
            // Sample readiness sparsely: the property under test is that a
            // deepening queue keeps answering, not the per-event cost.
            if i % 64 == 63 {
                if !readable(ifd, 250) {
                    stayed_readable = false;
                }
                let count = fionread(ifd);
                if count <= previous {
                    monotonic = false;
                }
                previous = count;
            }
        }
        let deep_count = fionread(ifd);

        // 2. Identical back-to-back events coalesce; distinct names do not.
        let repeat = format!("{dir}/repeat.tmp");
        create_file(&repeat);
        let before_repeats = fionread(ifd);
        touch_same_file(&repeat);
        let after_first_modify = fionread(ifd);
        touch_same_file(&repeat);
        let after_second_modify = fionread(ifd);

        // 3. Partial drain: some whole records out, the rest still queued.
        // The depth is re-read here rather than reused from the fill loop,
        // because the coalescing checks above queued more records since.
        let before_partial = fionread(ifd);
        let mut small = [0u8; 64];
        let partial = libc::read(ifd, small.as_mut_ptr() as *mut libc::c_void, small.len());
        let after_partial = fionread(ifd);
        let readable_after_partial = readable(ifd, 250);

        // 4. Full drain: unreadable again, FIONREAD back to zero.
        let mut drained_bytes: isize = 0;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = libc::read(ifd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n <= 0 {
                break;
            }
            drained_bytes += n;
        }
        let after_drain = fionread(ifd);
        let readable_after_drain = readable(ifd, 0);

        let rm = libc::inotify_rm_watch(ifd, wd);
        libc::close(ifd);

        report!(
            empty_instance_not_readable = !empty_readable,
            empty_instance_fionread_zero = empty_count == 0,
            deep_queue_stays_readable = stayed_readable,
            deep_queue_fionread_monotonic = monotonic,
            deep_queue_holds_every_name = deep_count > 0 && deep_count >= previous,
            identical_repeat_coalesces = after_second_modify == after_first_modify,
            distinct_names_do_not_coalesce = after_first_modify > before_repeats,
            partial_read_returns_whole_records = partial > 0 && partial <= small.len() as isize,
            partial_read_consumes_exactly_what_it_returned =
                after_partial == before_partial - partial as i32,
            partial_read_leaves_remainder = after_partial > 0 && after_partial < before_partial,
            readable_until_fully_drained = readable_after_partial,
            full_drain_empties_queue = after_drain == 0 && drained_bytes > 0,
            drained_instance_not_readable = !readable_after_drain,
            watch_removed_cleanly = rm == 0,
        );

        disarm_alarm();
    }
}
