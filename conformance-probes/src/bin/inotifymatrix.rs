//! inotify(7) API contract and event semantics conformance probe.
//!
//! Covers:
//! 1. `inotify_init1` valid `IN_NONBLOCK` and `IN_CLOEXEC` flags, and invalid flag rejection.
//! 2. `inotify_add_watch` error cases (missing path, bad fd, null pointer) and stable
//!    watch descriptor (wd) reuse, including `IN_MASK_ADD` behavior.
//! 3. File event generation and record parsing (`IN_CREATE`, `IN_MODIFY`, `IN_DELETE`),
//!    verifying wd, mask, cookie, child name, and struct memory alignment.
//! 4. `IN_ONESHOT` watch behavior: delivery of event followed by `IN_IGNORED`,
//!    suppression of subsequent events, and automatic watch removal (`EINVAL` on `rm_watch`).
//! 5. Explicit `inotify_rm_watch`: delivery of `IN_IGNORED`, suppression of subsequent events,
//!    and `EINVAL` on repeated removal.
//! 6. Read buffer sizing: too-small read buffers returning `EINVAL` without dropping events.
//! 7. Nonblocking empty read returning `EAGAIN`.
//! 8. `ioctl(FIONREAD)` reporting pending queued byte counts accurately.
//!
//! Output is normalized to deterministic boolean observations.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, report};
use std::ffi::CString;

const IN_CLOEXEC: i32 = libc::IN_CLOEXEC;
const IN_NONBLOCK: i32 = libc::IN_NONBLOCK;

const IN_MODIFY: u32 = 0x0000_0002;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct InotifyEventHeader {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
}

#[derive(Debug, Clone)]
struct ParsedEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
    name: String,
    total_len: usize,
}

fn parse_events(buf: &[u8]) -> Vec<ParsedEvent> {
    let mut events = Vec::new();
    let header_size = std::mem::size_of::<InotifyEventHeader>();
    let mut offset = 0;

    while offset + header_size <= buf.len() {
        let header_bytes = &buf[offset..offset + header_size];
        let header: InotifyEventHeader =
            unsafe { std::ptr::read_unaligned(header_bytes.as_ptr() as *const InotifyEventHeader) };

        let event_len = header.len as usize;
        let total_event_len = header_size + event_len;

        if offset + total_event_len > buf.len() {
            break;
        }

        let name = if event_len > 0 {
            let name_slice = &buf[offset + header_size..offset + total_event_len];
            let null_pos = name_slice
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_slice.len());
            String::from_utf8_lossy(&name_slice[..null_pos]).to_string()
        } else {
            String::new()
        };

        events.push(ParsedEvent {
            wd: header.wd,
            mask: header.mask,
            cookie: header.cookie,
            len: header.len,
            name,
            total_len: total_event_len,
        });

        offset += total_event_len;
    }

    events
}

struct FdGuard(i32);

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

struct DirGuard {
    path: String,
}

impl DirGuard {
    fn new(path: String) -> Self {
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::create_dir_all(&path);
        Self { path }
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

unsafe fn raw_inotify_init1(flags: i32) -> (i32, i32) {
    let rc = libc::inotify_init1(flags);
    let err = if rc == -1 { errno() } else { 0 };
    (rc, err)
}

unsafe fn raw_inotify_add_watch(fd: i32, pathname: *const libc::c_char, mask: u32) -> (i32, i32) {
    let rc = libc::inotify_add_watch(fd, pathname, mask);
    let err = if rc == -1 { errno() } else { 0 };
    (rc, err)
}

unsafe fn raw_inotify_rm_watch(fd: i32, wd: i32) -> (i32, i32) {
    let rc = libc::inotify_rm_watch(fd, wd);
    let err = if rc == -1 { errno() } else { 0 };
    (rc, err)
}

unsafe fn check_fd_flags(fd: i32) -> (bool, bool) {
    let fl = libc::fcntl(fd, libc::F_GETFL);
    let fd_flags = libc::fcntl(fd, libc::F_GETFD);
    let is_nonblock = fl >= 0 && (fl & libc::O_NONBLOCK) != 0;
    let is_cloexec = fd_flags >= 0 && (fd_flags & libc::FD_CLOEXEC) != 0;
    (is_nonblock, is_cloexec)
}

unsafe fn get_fionread(fd: i32) -> (i32, i32) {
    let mut bytes: libc::c_int = 0;
    let rc = libc::ioctl(fd, libc::FIONREAD, &mut bytes);
    let err = if rc == -1 { errno() } else { 0 };
    if rc == 0 {
        (0, bytes)
    } else {
        (err, -1)
    }
}

fn poll_readable(fd: i32, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    rc == 1 && (pfd.revents & libc::POLLIN) != 0
}

fn create_file(path: &str, data: &[u8]) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        return false;
    }
    let written = if !data.is_empty() {
        unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) }
    } else {
        0
    };
    unsafe {
        libc::close(fd);
    }
    written == data.len() as isize
}

fn append_or_modify_file(path: &str, data: &[u8]) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_APPEND) };
    if fd < 0 {
        return false;
    }
    let written = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
    unsafe {
        libc::close(fd);
    }
    written == data.len() as isize
}

fn unlink_file(path: &str) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    unsafe { libc::unlink(c.as_ptr()) == 0 }
}

fn mkdir_dir(path: &str) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    unsafe { libc::mkdir(c.as_ptr(), 0o755) == 0 }
}

fn main() {
    unsafe {
        // Probe-local 3-second upper-bound alarm.
        arm_alarm_ms(3000);

        let pid = libc::getpid();
        let base = format!("/tmp/inotifymatrix_{pid}");
        let _base_guard = DirGuard::new(base.clone());

        // =====================================================================
        // 1. inotify_init1 Flag Validation Matrix
        // =====================================================================
        let (fd_def, _) = raw_inotify_init1(0);
        let (nb_def, ce_def) = if fd_def >= 0 {
            check_fd_flags(fd_def)
        } else {
            (false, false)
        };
        if fd_def >= 0 {
            libc::close(fd_def);
        }

        let (fd_ce, _) = raw_inotify_init1(IN_CLOEXEC);
        let (nb_ce, ce_ce) = if fd_ce >= 0 {
            check_fd_flags(fd_ce)
        } else {
            (false, false)
        };
        if fd_ce >= 0 {
            libc::close(fd_ce);
        }

        let (fd_nb, _) = raw_inotify_init1(IN_NONBLOCK);
        let (nb_nb, ce_nb) = if fd_nb >= 0 {
            check_fd_flags(fd_nb)
        } else {
            (false, false)
        };
        if fd_nb >= 0 {
            libc::close(fd_nb);
        }

        let (fd_both, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let (nb_both, ce_both) = if fd_both >= 0 {
            check_fd_flags(fd_both)
        } else {
            (false, false)
        };
        if fd_both >= 0 {
            libc::close(fd_both);
        }

        let (inv1_rc, inv1_err) = raw_inotify_init1(1);
        let (inv4_rc, inv4_err) = raw_inotify_init1(4);
        let (inv_bogus_rc, inv_bogus_err) = raw_inotify_init1(0x0080_0000);
        let (inv_all_rc, inv_all_err) = raw_inotify_init1(!(IN_NONBLOCK | IN_CLOEXEC));

        let init1_default_flags_ok = fd_def >= 0 && !nb_def && !ce_def;
        let init1_cloexec_ok = fd_ce >= 0 && !nb_ce && ce_ce;
        let init1_nonblock_ok = fd_nb >= 0 && nb_nb && !ce_nb;
        let init1_both_flags_ok = fd_both >= 0 && nb_both && ce_both;
        let init1_invalid_flags_einval = (inv1_rc == -1 && inv1_err == libc::EINVAL)
            && (inv4_rc == -1 && inv4_err == libc::EINVAL)
            && (inv_bogus_rc == -1 && inv_bogus_err == libc::EINVAL)
            && (inv_all_rc == -1 && inv_all_err == libc::EINVAL);

        report!(
            init1_default_flags_ok = init1_default_flags_ok,
            init1_cloexec_ok = init1_cloexec_ok,
            init1_nonblock_ok = init1_nonblock_ok,
            init1_both_flags_ok = init1_both_flags_ok,
            init1_invalid_flags_einval = init1_invalid_flags_einval,
        );

        // =====================================================================
        // 2. inotify_add_watch Errors and Stable WD Reuse with IN_MASK_ADD
        // =====================================================================
        let (ifd2, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd2 = FdGuard(ifd2);

        let missing_path = format!("{base}/missing_s2_path");
        let missing_c = CString::new(missing_path.as_str()).unwrap();
        let (miss_rc, miss_err) = raw_inotify_add_watch(ifd2, missing_c.as_ptr(), IN_CREATE);

        let dir2 = format!("{base}/s2_dir");
        mkdir_dir(&dir2);
        let dir2_c = CString::new(dir2.as_str()).unwrap();

        let (badfd_rc, badfd_err) = raw_inotify_add_watch(-1, dir2_c.as_ptr(), IN_CREATE);
        let (null_rc, null_err) = raw_inotify_add_watch(ifd2, std::ptr::null(), IN_CREATE);

        // Step 2a: Initial watch on dir2 for IN_CREATE
        let (wd1, err1) = raw_inotify_add_watch(ifd2, dir2_c.as_ptr(), IN_CREATE);

        // Step 2b: Replace mask with IN_DELETE (no IN_MASK_ADD) -> returns same wd1
        let (wd2, err2) = raw_inotify_add_watch(ifd2, dir2_c.as_ptr(), IN_DELETE);

        // Verify creation produces no event under replaced mask
        let child2 = format!("{dir2}/s2_child.tmp");
        create_file(&child2, b"s2_data");
        let mut buf2 = [0u8; 512];
        let n_create = libc::read(ifd2, buf2.as_mut_ptr() as *mut libc::c_void, buf2.len());
        let create_err = if n_create < 0 { errno() } else { 0 };

        // Deletion should produce IN_DELETE event
        unlink_file(&child2);
        let _ = poll_readable(ifd2, 250);
        let n_delete = libc::read(ifd2, buf2.as_mut_ptr() as *mut libc::c_void, buf2.len());
        let events_del = if n_delete > 0 {
            parse_events(&buf2[..n_delete as usize])
        } else {
            Vec::new()
        };
        let del_ev_ok = events_del.len() == 1
            && events_del[0].wd == wd1
            && (events_del[0].mask & IN_DELETE) != 0
            && events_del[0].name == "s2_child.tmp";

        // Step 2c: Add IN_CREATE using IN_MASK_ADD -> returns same wd1, now watches CREATE | DELETE
        let (wd3, err3) = raw_inotify_add_watch(ifd2, dir2_c.as_ptr(), IN_MASK_ADD | IN_CREATE);

        create_file(&child2, b"s2_again");
        let _ = poll_readable(ifd2, 250);
        let n_c2 = libc::read(ifd2, buf2.as_mut_ptr() as *mut libc::c_void, buf2.len());
        let events_c2 = if n_c2 > 0 {
            parse_events(&buf2[..n_c2 as usize])
        } else {
            Vec::new()
        };

        unlink_file(&child2);
        let _ = poll_readable(ifd2, 250);
        let n_d2 = libc::read(ifd2, buf2.as_mut_ptr() as *mut libc::c_void, buf2.len());
        let events_d2 = if n_d2 > 0 {
            parse_events(&buf2[..n_d2 as usize])
        } else {
            Vec::new()
        };

        let mask_add_events_ok = events_c2.len() == 1
            && events_c2[0].wd == wd1
            && (events_c2[0].mask & IN_CREATE) != 0
            && events_c2[0].name == "s2_child.tmp"
            && events_d2.len() == 1
            && events_d2[0].wd == wd1
            && (events_d2[0].mask & IN_DELETE) != 0
            && events_d2[0].name == "s2_child.tmp";

        report!(
            add_watch_missing_path_enoent = miss_rc == -1 && miss_err == libc::ENOENT,
            add_watch_bad_fd_ebadf = badfd_rc == -1 && badfd_err == libc::EBADF,
            add_watch_null_path_efault = null_rc == -1 && null_err == libc::EFAULT,
            add_watch_initial_ok = wd1 >= 0 && err1 == 0,
            add_watch_replace_mask_same_wd = wd2 == wd1 && err2 == 0,
            add_watch_replaced_mask_no_create_event = n_create == -1 && create_err == libc::EAGAIN,
            add_watch_replaced_mask_delete_event = del_ev_ok,
            add_watch_mask_add_same_wd = wd3 == wd1 && err3 == 0,
            add_watch_mask_add_both_events = mask_add_events_ok,
        );

        // =====================================================================
        // 3. File Create, Modify, Delete Event Parsing and Record Alignment
        // =====================================================================
        let (ifd3, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd3 = FdGuard(ifd3);

        let dir3 = format!("{base}/s3_dir");
        mkdir_dir(&dir3);
        let dir3_c = CString::new(dir3.as_str()).unwrap();
        let (wd3_dir, _) =
            raw_inotify_add_watch(ifd3, dir3_c.as_ptr(), IN_CREATE | IN_MODIFY | IN_DELETE);

        let child3 = format!("{dir3}/item_test.dat");
        let child3_c = CString::new(child3.as_str()).unwrap();

        // Step 3a: Create file
        let fd3 = libc::open(
            child3_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        // Step 3b: Modify file
        if fd3 >= 0 {
            libc::write(fd3, b"hello".as_ptr() as *const libc::c_void, 5);
            libc::close(fd3);
        }
        // Step 3c: Delete file
        libc::unlink(child3_c.as_ptr());

        let _ = poll_readable(ifd3, 250);
        let mut buf3 = [0u8; 2048];
        let n3 = libc::read(ifd3, buf3.as_mut_ptr() as *mut libc::c_void, buf3.len());
        let events3 = if n3 > 0 {
            parse_events(&buf3[..n3 as usize])
        } else {
            Vec::new()
        };

        let ev3_ok = events3.len() == 3;
        let ev1_create = ev3_ok
            && events3[0].wd == wd3_dir
            && (events3[0].mask & IN_CREATE) != 0
            && events3[0].cookie == 0
            && events3[0].len > 0
            && events3[0].name == "item_test.dat";
        let ev2_modify = ev3_ok
            && events3[1].wd == wd3_dir
            && (events3[1].mask & IN_MODIFY) != 0
            && events3[1].cookie == 0
            && events3[1].len > 0
            && events3[1].name == "item_test.dat";
        let ev3_delete = ev3_ok
            && events3[2].wd == wd3_dir
            && (events3[2].mask & IN_DELETE) != 0
            && events3[2].cookie == 0
            && events3[2].len > 0
            && events3[2].name == "item_test.dat";

        let align_ok = if ev3_ok {
            let off1 = 0;
            let off2 = off1 + events3[0].total_len;
            let off3 = off2 + events3[1].total_len;
            let off_end = off3 + events3[2].total_len;
            (off1 % 4 == 0)
                && (off2 % 4 == 0)
                && (off3 % 4 == 0)
                && (off_end % 4 == 0)
                && (n3 == off_end as isize)
        } else {
            false
        };

        report!(
            event_create_parsed_ok = ev1_create,
            event_modify_parsed_ok = ev2_modify,
            event_delete_parsed_ok = ev3_delete,
            event_records_aligned_and_exact = align_ok,
        );

        // =====================================================================
        // 4. IN_ONESHOT Watch and IN_IGNORED Delivery
        // =====================================================================
        let (ifd4, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd4 = FdGuard(ifd4);

        let file4 = format!("{base}/s4_oneshot.tmp");
        create_file(&file4, b"init4");
        let file4_c = CString::new(file4.as_str()).unwrap();

        let (wd_one, err_one) =
            raw_inotify_add_watch(ifd4, file4_c.as_ptr(), IN_MODIFY | IN_ONESHOT);

        append_or_modify_file(&file4, b"_mod1");
        let _ = poll_readable(ifd4, 250);

        let mut buf4 = [0u8; 1024];
        let n4 = libc::read(ifd4, buf4.as_mut_ptr() as *mut libc::c_void, buf4.len());
        let events4 = if n4 > 0 {
            parse_events(&buf4[..n4 as usize])
        } else {
            Vec::new()
        };

        let oneshot_events_ok = events4.len() == 2
            && events4[0].wd == wd_one
            && (events4[0].mask & IN_MODIFY) != 0
            && events4[1].wd == wd_one
            && (events4[1].mask & IN_IGNORED) != 0;

        // Subsequent modification must generate no events
        append_or_modify_file(&file4, b"_mod2");
        let n4_sub = libc::read(ifd4, buf4.as_mut_ptr() as *mut libc::c_void, buf4.len());
        let err4_sub = if n4_sub < 0 { errno() } else { 0 };

        // Attempting to remove the oneshot watch after it triggered should fail with EINVAL
        let (rm4_rc, rm4_err) = raw_inotify_rm_watch(ifd4, wd_one);

        report!(
            oneshot_watch_added = wd_one >= 0 && err_one == 0,
            oneshot_event_and_ignored_delivered = oneshot_events_ok,
            oneshot_no_further_events_eagain = n4_sub == -1 && err4_sub == libc::EAGAIN,
            oneshot_auto_removed_rm_einval = rm4_rc == -1 && rm4_err == libc::EINVAL,
        );

        // =====================================================================
        // 5. Explicit inotify_rm_watch and IN_IGNORED Delivery
        // =====================================================================
        let (ifd5, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd5 = FdGuard(ifd5);

        let file5 = format!("{base}/s5_rmwatch.tmp");
        create_file(&file5, b"init5");
        let file5_c = CString::new(file5.as_str()).unwrap();

        let (wd_rm, _) = raw_inotify_add_watch(ifd5, file5_c.as_ptr(), IN_MODIFY);
        let (rm5_rc, rm5_err) = raw_inotify_rm_watch(ifd5, wd_rm);

        let _ = poll_readable(ifd5, 250);
        let mut buf5 = [0u8; 512];
        let n5 = libc::read(ifd5, buf5.as_mut_ptr() as *mut libc::c_void, buf5.len());
        let events5 = if n5 > 0 {
            parse_events(&buf5[..n5 as usize])
        } else {
            Vec::new()
        };

        let rm_ignored_ok =
            events5.len() == 1 && events5[0].wd == wd_rm && (events5[0].mask & IN_IGNORED) != 0;

        let (rm5_sec_rc, rm5_sec_err) = raw_inotify_rm_watch(ifd5, wd_rm);

        append_or_modify_file(&file5, b"_mod_after_rm");
        let n5_sub = libc::read(ifd5, buf5.as_mut_ptr() as *mut libc::c_void, buf5.len());
        let err5_sub = if n5_sub < 0 { errno() } else { 0 };

        report!(
            rm_watch_ok = rm5_rc == 0 && rm5_err == 0,
            rm_watch_ignored_event_delivered = rm_ignored_ok,
            rm_watch_second_rm_einval = rm5_sec_rc == -1 && rm5_sec_err == libc::EINVAL,
            rm_watch_no_subsequent_events_eagain = n5_sub == -1 && err5_sub == libc::EAGAIN,
        );

        // =====================================================================
        // 6. Too-Small Read Buffer EINVAL
        // =====================================================================
        let (ifd6, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd6 = FdGuard(ifd6);

        let dir6 = format!("{base}/s6_dir");
        mkdir_dir(&dir6);
        let dir6_c = CString::new(dir6.as_str()).unwrap();
        let (wd6_dir, _) = raw_inotify_add_watch(ifd6, dir6_c.as_ptr(), IN_CREATE);

        let child6 = format!("{dir6}/s6_short_child.tmp");
        create_file(&child6, b"s6");
        let _ = poll_readable(ifd6, 250);

        let mut tiny_buf = [0u8; 16];
        // Test zero buffer length
        let r0 = libc::read(ifd6, tiny_buf.as_mut_ptr() as *mut libc::c_void, 0);
        let err0 = if r0 < 0 { errno() } else { 0 };

        // Test buffer size smaller than inotify_event header (15 bytes < 16)
        let r15 = libc::read(ifd6, tiny_buf.as_mut_ptr() as *mut libc::c_void, 15);
        let err15 = if r15 < 0 { errno() } else { 0 };

        // Test buffer size equal to header (16 bytes), which is smaller than header + name_len
        let r16 = libc::read(ifd6, tiny_buf.as_mut_ptr() as *mut libc::c_void, 16);
        let err16 = if r16 < 0 { errno() } else { 0 };

        // Full read should succeed and yield the queued event intact
        let mut full_buf = [0u8; 512];
        let r_ok = libc::read(
            ifd6,
            full_buf.as_mut_ptr() as *mut libc::c_void,
            full_buf.len(),
        );
        let events6 = if r_ok > 0 {
            parse_events(&full_buf[..r_ok as usize])
        } else {
            Vec::new()
        };
        let adequate_ok = r_ok > 0
            && events6.len() == 1
            && events6[0].wd == wd6_dir
            && (events6[0].mask & IN_CREATE) != 0
            && events6[0].len > 0
            && events6[0].name == "s6_short_child.tmp";

        report!(
            read_zero_bytes_einval = r0 == -1 && err0 == libc::EINVAL,
            read_sub_header_einval = r15 == -1 && err15 == libc::EINVAL,
            read_header_only_for_named_event_einval = r16 == -1 && err16 == libc::EINVAL,
            read_adequate_buffer_succeeds = adequate_ok,
        );

        // =====================================================================
        // 7. Nonblocking Empty Read Returns EAGAIN
        // =====================================================================
        let (ifd7, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd7 = FdGuard(ifd7);

        let mut buf7 = [0u8; 128];
        let r_empty = libc::read(ifd7, buf7.as_mut_ptr() as *mut libc::c_void, buf7.len());
        let err_empty = if r_empty < 0 { errno() } else { 0 };

        report!(empty_read_eagain = r_empty == -1 && err_empty == libc::EAGAIN);

        // =====================================================================
        // 8. ioctl(FIONREAD) Pending Byte Count Accounting
        // =====================================================================
        let (ifd8, _) = raw_inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        let _guard_ifd8 = FdGuard(ifd8);

        let (rc0, count0) = get_fionread(ifd8);

        let dir8 = format!("{base}/s8_dir");
        mkdir_dir(&dir8);
        let dir8_c = CString::new(dir8.as_str()).unwrap();
        let _ = raw_inotify_add_watch(ifd8, dir8_c.as_ptr(), IN_CREATE | IN_DELETE);

        let f8_1 = format!("{dir8}/f1_item.tmp");
        create_file(&f8_1, b"f1");
        let _ = poll_readable(ifd8, 250);
        let (rc1, count1) = get_fionread(ifd8);

        let f8_2 = format!("{dir8}/f2_item.tmp");
        create_file(&f8_2, b"f2");
        let _ = poll_readable(ifd8, 250);
        let (rc2, count2) = get_fionread(ifd8);

        let mut buf8 = [0u8; 1024];
        let n_read8 = libc::read(ifd8, buf8.as_mut_ptr() as *mut libc::c_void, buf8.len());
        let (rc3, count3) = get_fionread(ifd8);

        report!(
            fionread_empty_zero = rc0 == 0 && count0 == 0,
            fionread_one_event_positive = rc1 == 0 && count1 > 0,
            fionread_two_events_accumulates = rc2 == 0 && count2 > count1,
            fionread_drained_zero = rc3 == 0 && count3 == 0 && n_read8 == count2 as isize,
        );

        disarm_alarm();
    }
}
