//! fanotify mark semantics LTP `fanotify04` exercises: FAN_ONDIR on a
//! directory open, symlink marks with and without FAN_MARK_DONT_FOLLOW,
//! FAN_MARK_ONLYDIR, and FAN_MARK_FLUSH.
//!
//! Needs `CAP_SYS_ADMIN` for `fanotify_init(2)` (declared in both probe lanes'
//! privilege tables, as `pipeblockedge` is).
//!
//! Invariants encoded, all boolean:
//!
//!   * `FAN_MARK_ONLYDIR` on a regular file fails with ENOTDIR; on a directory
//!     it succeeds.
//!   * A mark on a symlink with `FAN_MARK_DONT_FOLLOW` marks the link itself:
//!     opening the target yields NO event (EAGAIN on the non-blocking group).
//!   * A mark on a symlink WITHOUT `FAN_MARK_DONT_FOLLOW` marks the target:
//!     opening through the link yields a `FAN_OPEN` event whose fd is a
//!     regular file.
//!   * A `FAN_OPEN | FAN_ONDIR` mark on a directory: `open(O_DIRECTORY)` of
//!     that directory yields a `FAN_OPEN` event whose fd is a directory.
//!   * `FAN_MARK_FLUSH` removes every inode mark: the same directory open
//!     afterwards yields no event.
//!
//! Deterministic output: booleans only.

use conformance_probes::{errno, report};
use std::ffi::CString;

#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_INIT: libc::c_long = 262;
#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_MARK: libc::c_long = 263;
#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_INIT: libc::c_long = 300;
#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_MARK: libc::c_long = 301;

const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_NONBLOCK: u32 = 0x0000_0002;
const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_MARK_REMOVE: u32 = 0x0000_0002;
const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;
const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;
const FAN_MARK_FLUSH: u32 = 0x0000_0080;
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_ONDIR: u64 = 0x4000_0000;
const FAN_NOFD: i32 = -1;

#[repr(C)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

unsafe fn sys_fanotify_init(flags: u32, event_f_flags: u32) -> i32 {
    libc::syscall(
        SYS_FANOTIFY_INIT,
        flags as libc::c_long,
        event_f_flags as libc::c_long,
    ) as i32
}

unsafe fn sys_fanotify_mark(fan_fd: i32, flags: u32, mask: u64, path: &CString) -> i32 {
    libc::syscall(
        SYS_FANOTIFY_MARK,
        fan_fd as libc::c_long,
        flags as libc::c_long,
        mask as libc::c_long,
        libc::AT_FDCWD as libc::c_long,
        path.as_ptr() as libc::c_long,
    ) as i32
}

/// Read one event; `Some((mask, S_IFMT of the event fd))`, or `None` when the
/// non-blocking group has nothing queued (EAGAIN).
unsafe fn take_event(fan_fd: i32) -> Option<(u64, u32)> {
    let mut buf = [0u8; 256];
    let n = libc::read(fan_fd, buf.as_mut_ptr().cast(), buf.len());
    if n < 0 {
        assert!(
            errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK,
            "fanotify read errno {}",
            errno()
        );
        return None;
    }
    assert!(n as usize >= std::mem::size_of::<FanotifyEventMetadata>());
    let ev = std::ptr::read_unaligned(buf.as_ptr().cast::<FanotifyEventMetadata>());
    let mut fmt = 0u32;
    if ev.fd != FAN_NOFD {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(ev.fd, &mut st) == 0 {
            fmt = (st.st_mode as u32) & (libc::S_IFMT as u32);
        }
        libc::close(ev.fd);
    }
    Some((ev.mask, fmt))
}

unsafe fn open_close(path: &CString, flags: i32) {
    let fd = libc::open(path.as_ptr(), flags);
    assert!(fd >= 0, "open {:?} errno {}", path, errno());
    libc::close(fd);
}

fn main() {
    unsafe {
        let dir = CString::new("/tmp/fanotifyondir").unwrap();
        libc::mkdir(dir.as_ptr(), 0o755);
        assert_eq!(libc::chdir(dir.as_ptr()), 0);
        let fname = CString::new("fname").unwrap();
        let sname = CString::new("symlink").unwrap();
        let sub = CString::new("subdir").unwrap();
        let dot = CString::new(".").unwrap();
        libc::unlink(sname.as_ptr());
        libc::rmdir(sub.as_ptr());
        let fd = libc::open(fname.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o644);
        assert!(fd >= 0);
        libc::close(fd);
        assert_eq!(libc::symlink(fname.as_ptr(), sname.as_ptr()), 0);
        assert_eq!(libc::mkdir(sub.as_ptr(), 0o755), 0);

        let fan = sys_fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, libc::O_RDONLY as u32);
        assert!(fan >= 0, "fanotify_init errno {}", errno());

        let onlydir_on_dir_ok = sys_fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN, &dot) == 0;
        sys_fanotify_mark(fan, FAN_MARK_REMOVE, FAN_OPEN, &dot);
        let onlydir_on_file_rc = sys_fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_ONLYDIR, FAN_OPEN, &fname);
        let onlydir_on_file_enotdir = onlydir_on_file_rc == -1 && errno() == libc::ENOTDIR;

        // DONT_FOLLOW: the link itself is marked; opening the target is silent.
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW, FAN_OPEN, &sname), 0);
        open_close(&sname, libc::O_RDONLY);
        let dont_follow_open_no_event = take_event(fan).is_none();
        sys_fanotify_mark(fan, FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW, FAN_OPEN, &sname);

        // Without DONT_FOLLOW: the target is marked; opening through the link reports it.
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN, &sname), 0);
        open_close(&sname, libc::O_RDONLY);
        let follow_open_event_regular = matches!(take_event(fan), Some((m, f)) if m & FAN_OPEN != 0 && f == libc::S_IFREG as u32);
        sys_fanotify_mark(fan, FAN_MARK_REMOVE, FAN_OPEN, &sname);

        // FAN_ONDIR: a directory open on a directory mark that asked for it.
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, &sub), 0);
        open_close(&sub, libc::O_RDONLY | libc::O_DIRECTORY);
        let ondir_dir_open_event_directory = matches!(take_event(fan), Some((m, f)) if m & FAN_OPEN != 0 && f == libc::S_IFDIR as u32);

        // Without FAN_ONDIR the same open is silent.
        sys_fanotify_mark(fan, FAN_MARK_REMOVE, FAN_OPEN | FAN_ONDIR, &sub);
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN, &sub), 0);
        open_close(&sub, libc::O_RDONLY | libc::O_DIRECTORY);
        let no_ondir_dir_open_silent = take_event(fan).is_none();

        // FLUSH drops every inode mark.
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_ONDIR, &sub), 0);
        assert_eq!(sys_fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN, &fname), 0);
        let flush_rc_zero = sys_fanotify_mark(fan, FAN_MARK_FLUSH, 0, &dot) == 0;
        open_close(&sub, libc::O_RDONLY | libc::O_DIRECTORY);
        open_close(&fname, libc::O_RDONLY);
        let flush_removes_marks = take_event(fan).is_none();

        report!(
            onlydir_on_dir_ok = onlydir_on_dir_ok,
            onlydir_on_file_enotdir = onlydir_on_file_enotdir,
            dont_follow_open_no_event = dont_follow_open_no_event,
            follow_open_event_regular = follow_open_event_regular,
            ondir_dir_open_event_directory = ondir_dir_open_event_directory,
            no_ondir_dir_open_silent = no_ondir_dir_open_silent,
            flush_rc_zero = flush_rc_zero,
            flush_removes_marks = flush_removes_marks,
        );
        libc::close(fan);
    }
}
