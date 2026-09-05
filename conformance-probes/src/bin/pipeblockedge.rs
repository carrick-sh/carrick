//! Pipe, notification fd (inotify, fanotify) blocking & edge semantics,
//! and pwritev2/preadv2 conformance probe.
//!
//! Covers:
//! 1. Full-pipe blocking write parks on readiness and completes all 65536 bytes
//!    once a reader drains data (ltp-pipe12 gap).
//! 2. Full-pipe nonblocking write returns EAGAIN.
//! 3. Pipe write with partial room in nonblocking mode writes available room
//!    and returns partial count.
//! 4. Zero-length write returns 0 without accessing or modifying pipe state.
//! 5. `pwritev2` and `preadv2` on pipe descriptions return `ESPIPE` (ltp-pwritev202 gap).
//! 6. `pwritev2` on a read-only regular file returns `EBADF`.
//! 7. `pwritev2` with `offset == -1` on a regular file appends/writes at the current
//!    file position and advances the file offset.
//! 8. Blocking `read` on an empty inotify fd parks on readiness and returns
//!    the event once triggered (ltp-inotify11 gap).
//! 9. Nonblocking `read` on an empty inotify fd returns `EAGAIN`.
//! 10. Blocking `read` on an empty fanotify group parks on readiness and returns
//!     the event once triggered (ltp-fanotify04 gap).
//! 11. Nonblocking `read` on an empty fanotify group returns `EAGAIN`.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, pipe2, reap, report};
use std::ffi::CString;

#[cfg(target_arch = "aarch64")]
const SYS_PREADV2: libc::c_long = 286;
#[cfg(target_arch = "aarch64")]
const SYS_PWRITEV2: libc::c_long = 287;
#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_INIT: libc::c_long = 262;
#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_MARK: libc::c_long = 263;

#[cfg(target_arch = "x86_64")]
const SYS_PREADV2: libc::c_long = 327;
#[cfg(target_arch = "x86_64")]
const SYS_PWRITEV2: libc::c_long = 328;
#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_INIT: libc::c_long = 300;
#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_MARK: libc::c_long = 301;

const F_SETPIPE_SZ: libc::c_int = 1031;

const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
const FAN_NONBLOCK: u32 = 0x0000_0002;
const FAN_MARK_ADD: u32 = 0x0000_0001;
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_EVENT_METADATA_LEN: usize = 24;

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

unsafe fn sys_preadv2(
    fd: i32,
    iov: *const libc::iovec,
    vlen: i32,
    offset_low: libc::c_ulong,
    offset_high: libc::c_ulong,
    flags: i32,
) -> isize {
    libc::syscall(
        SYS_PREADV2,
        fd as libc::c_long,
        iov as libc::c_long,
        vlen as libc::c_long,
        offset_low as libc::c_long,
        offset_high as libc::c_long,
        flags as libc::c_long,
    ) as isize
}

unsafe fn sys_pwritev2(
    fd: i32,
    iov: *const libc::iovec,
    vlen: i32,
    offset_low: libc::c_ulong,
    offset_high: libc::c_ulong,
    flags: i32,
) -> isize {
    libc::syscall(
        SYS_PWRITEV2,
        fd as libc::c_long,
        iov as libc::c_long,
        vlen as libc::c_long,
        offset_low as libc::c_long,
        offset_high as libc::c_long,
        flags as libc::c_long,
    ) as isize
}

unsafe fn sys_fanotify_init(flags: u32, event_f_flags: u32) -> i32 {
    libc::syscall(
        SYS_FANOTIFY_INIT,
        flags as libc::c_long,
        event_f_flags as libc::c_long,
    ) as i32
}

unsafe fn sys_fanotify_mark(
    fanotify_fd: i32,
    flags: u32,
    mask: u64,
    dirfd: i32,
    pathname: *const libc::c_char,
) -> i32 {
    libc::syscall(
        SYS_FANOTIFY_MARK,
        fanotify_fd as libc::c_long,
        flags as libc::c_long,
        mask as libc::c_long,
        dirfd as libc::c_long,
        pathname as libc::c_long,
    ) as i32
}

fn main() {
    unsafe {
        arm_alarm_ms(5000);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);

        // =====================================================================
        // 1. Pipe blocking, nonblocking, and capacity edges
        // =====================================================================
        let (rd, wr) = pipe2();
        let _ = libc::fcntl(wr, F_SETPIPE_SZ, 65536);

        let initial_flags = libc::fcntl(wr, libc::F_GETFL);
        libc::fcntl(wr, libc::F_SETFL, initial_flags | libc::O_NONBLOCK);

        let chunk = [0x5au8; 4096];
        loop {
            let n = libc::write(wr, chunk.as_ptr() as *const libc::c_void, chunk.len());
            if n <= 0 {
                break;
            }
        }

        let nb_rc = libc::write(wr, chunk.as_ptr() as *const libc::c_void, chunk.len());
        let full_pipe_nonblock_write_eagain =
            nb_rc == -1 && (errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK);

        let mut drain_buf = [0u8; 4096];
        let drained = libc::read(rd, drain_buf.as_mut_ptr() as *mut libc::c_void, 4096);

        let partial_buf = [0x42u8; 8192];
        let partial_rc = libc::write(wr, partial_buf.as_ptr() as *const libc::c_void, 8192);
        let partial_room_nonblock_write_len = drained == 4096 && partial_rc == 4096;

        loop {
            let n = libc::write(wr, chunk.as_ptr() as *const libc::c_void, chunk.len());
            if n <= 0 {
                break;
            }
        }

        let zero_rc = libc::write(wr, chunk.as_ptr() as *const libc::c_void, 0);
        let write_zero_len_returns_zero = zero_rc == 0;

        libc::fcntl(wr, libc::F_SETFL, initial_flags & !libc::O_NONBLOCK);
        let write_buf_65536 = vec![0x77u8; 65536];

        let pipe_child = libc::fork();
        if pipe_child == 0 {
            libc::close(wr);
            libc::usleep(50_000);
            let mut drain = [0u8; 16384];
            let mut total_read = 0;
            while total_read < 65536 * 2 {
                let r = libc::read(rd, drain.as_mut_ptr() as *mut libc::c_void, drain.len());
                if r <= 0 {
                    break;
                }
                total_read += r as usize;
            }
            libc::close(rd);
            libc::_exit(0);
        }

        let bw_ret = libc::write(wr, write_buf_65536.as_ptr() as *const libc::c_void, 65536);
        let full_pipe_blocking_write_len_65536 = bw_ret == 65536;

        libc::close(wr);
        libc::close(rd);
        let _ = reap(pipe_child);

        // =====================================================================
        // 2. pwritev2 / preadv2 semantics on pipe & regular files
        // =====================================================================
        let (p_rd, p_wr) = pipe2();
        let mut pv_buf = [0xa5u8; 16];
        let pv_iov = [libc::iovec {
            iov_base: pv_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: pv_buf.len(),
        }];

        let pw_wr = sys_pwritev2(p_wr, pv_iov.as_ptr(), 1, 0, 0, 0);
        let pw_wr_err = errno();
        let pw_rd = sys_pwritev2(p_rd, pv_iov.as_ptr(), 1, 0, 0, 0);
        let pw_rd_err = errno();
        let pwritev2_pipe_espipe =
            pw_wr == -1 && pw_wr_err == libc::ESPIPE && pw_rd == -1 && pw_rd_err == libc::ESPIPE;

        let pr_rd = sys_preadv2(p_rd, pv_iov.as_ptr(), 1, 0, 0, 0);
        let pr_rd_err = errno();
        let pr_wr = sys_preadv2(p_wr, pv_iov.as_ptr(), 1, 0, 0, 0);
        let pr_wr_err = errno();
        let preadv2_pipe_espipe =
            pr_rd == -1 && pr_rd_err == libc::ESPIPE && pr_wr == -1 && pr_wr_err == libc::ESPIPE;

        libc::close(p_rd);
        libc::close(p_wr);

        let pid = libc::getpid();
        let ro_path = CString::new(format!("/tmp/pipeblockedge_ro_{pid}")).unwrap();
        let ro_fd = libc::open(
            ro_path.as_ptr(),
            libc::O_RDONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let pw_ro = sys_pwritev2(ro_fd, pv_iov.as_ptr(), 1, 0, 0, 0);
        let pw_ro_err = errno();
        let pwritev2_rdonly_file_ebadf = pw_ro == -1 && pw_ro_err == libc::EBADF;
        if ro_fd >= 0 {
            libc::close(ro_fd);
        }
        libc::unlink(ro_path.as_ptr());

        let app_path = CString::new(format!("/tmp/pipeblockedge_app_{pid}")).unwrap();
        let app_fd = libc::open(
            app_path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let initial_text = b"prefix_";
        libc::write(
            app_fd,
            initial_text.as_ptr() as *const libc::c_void,
            initial_text.len(),
        );

        let appended_text = b"appended";
        let app_iov = [libc::iovec {
            iov_base: appended_text.as_ptr() as *mut libc::c_void,
            iov_len: appended_text.len(),
        }];
        let app_rc = sys_pwritev2(
            app_fd,
            app_iov.as_ptr(),
            1,
            (!0u64) as libc::c_ulong,
            (!0u64) as libc::c_ulong,
            0,
        );
        let pos_after = libc::lseek(app_fd, 0, libc::SEEK_CUR);
        let mut read_content = [0u8; 15];
        libc::lseek(app_fd, 0, libc::SEEK_SET);
        let read_len = libc::read(
            app_fd,
            read_content.as_mut_ptr() as *mut libc::c_void,
            read_content.len(),
        );
        let pwritev2_offset_minus_one_regular_file_appends_at_current = app_rc
            == appended_text.len() as isize
            && pos_after == 15
            && read_len == 15
            && &read_content == b"prefix_appended";

        if app_fd >= 0 {
            libc::close(app_fd);
        }
        libc::unlink(app_path.as_ptr());

        // =====================================================================
        // 3. inotify blocking & nonblocking read semantics
        // =====================================================================
        let ifd_block = libc::inotify_init1(0);
        let in_dir = CString::new(format!("/tmp/pipeblockedge_indir_{pid}")).unwrap();
        libc::mkdir(in_dir.as_ptr(), 0o755);
        let in_wd = libc::inotify_add_watch(ifd_block, in_dir.as_ptr(), libc::IN_CREATE);

        let in_child = libc::fork();
        if in_child == 0 {
            libc::usleep(50_000);
            let child_target =
                CString::new(format!("/tmp/pipeblockedge_indir_{pid}/child.tmp")).unwrap();
            let c_fd = libc::open(
                child_target.as_ptr(),
                libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
                0o644,
            );
            if c_fd >= 0 {
                libc::close(c_fd);
            }
            libc::_exit(0);
        }

        let mut in_buf = [0u8; 256];
        let n_in = libc::read(
            ifd_block,
            in_buf.as_mut_ptr() as *mut libc::c_void,
            in_buf.len(),
        );
        let _ = reap(in_child);

        let inotify_blocking_read_returns_event = if n_in >= 16 {
            let header: libc::inotify_event = std::ptr::read_unaligned(in_buf.as_ptr() as *const _);
            in_wd >= 0 && header.wd == in_wd && (header.mask & libc::IN_CREATE) != 0
        } else {
            false
        };

        if ifd_block >= 0 {
            libc::close(ifd_block);
        }
        let child_target =
            CString::new(format!("/tmp/pipeblockedge_indir_{pid}/child.tmp")).unwrap();
        libc::unlink(child_target.as_ptr());
        libc::rmdir(in_dir.as_ptr());

        let ifd_nb = libc::inotify_init1(libc::IN_NONBLOCK);
        let mut empty_in_buf = [0u8; 128];
        let nb_in_rc = libc::read(
            ifd_nb,
            empty_in_buf.as_mut_ptr() as *mut libc::c_void,
            empty_in_buf.len(),
        );
        let inotify_nonblock_read_eagain =
            nb_in_rc == -1 && (errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK);
        if ifd_nb >= 0 {
            libc::close(ifd_nb);
        }

        // =====================================================================
        // 4. fanotify blocking & nonblocking read semantics
        // =====================================================================
        let fan_target = CString::new(format!("/tmp/pipeblockedge_fantarget_{pid}")).unwrap();
        let target_fd = libc::open(
            fan_target.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o644,
        );
        if target_fd >= 0 {
            libc::close(target_fd);
        }

        let fan_fd = sys_fanotify_init(FAN_CLASS_NOTIF, libc::O_RDONLY as u32);
        let mark_rc = sys_fanotify_mark(
            fan_fd,
            FAN_MARK_ADD,
            FAN_OPEN,
            libc::AT_FDCWD,
            fan_target.as_ptr(),
        );

        let fan_child = libc::fork();
        if fan_child == 0 {
            libc::usleep(50_000);
            let c_fd = libc::open(fan_target.as_ptr(), libc::O_RDONLY);
            if c_fd >= 0 {
                libc::close(c_fd);
            }
            libc::_exit(0);
        }

        let mut fan_buf = [0u8; 128];
        let n_fan = libc::read(
            fan_fd,
            fan_buf.as_mut_ptr() as *mut libc::c_void,
            fan_buf.len(),
        );
        let _ = reap(fan_child);

        let fanotify_blocking_read_returns_event = if n_fan >= FAN_EVENT_METADATA_LEN as isize {
            let meta: FanotifyEventMetadata =
                std::ptr::read_unaligned(fan_buf.as_ptr() as *const _);
            if meta.fd >= 0 {
                libc::close(meta.fd);
            }
            mark_rc == 0 && (meta.mask & FAN_OPEN) != 0 && meta.vers == 3
        } else {
            false
        };

        if fan_fd >= 0 {
            libc::close(fan_fd);
        }
        libc::unlink(fan_target.as_ptr());

        let fan_nb_fd = sys_fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, libc::O_RDONLY as u32);
        let mut empty_fan_buf = [0u8; 128];
        let nb_fan_rc = libc::read(
            fan_nb_fd,
            empty_fan_buf.as_mut_ptr() as *mut libc::c_void,
            empty_fan_buf.len(),
        );
        let fanotify_nonblock_read_eagain =
            nb_fan_rc == -1 && (errno() == libc::EAGAIN || errno() == libc::EWOULDBLOCK);
        if fan_nb_fd >= 0 {
            libc::close(fan_nb_fd);
        }

        report!(
            full_pipe_blocking_write_len_65536 = full_pipe_blocking_write_len_65536,
            full_pipe_nonblock_write_eagain = full_pipe_nonblock_write_eagain,
            partial_room_nonblock_write_len = partial_room_nonblock_write_len,
            write_zero_len_returns_zero = write_zero_len_returns_zero,
            pwritev2_pipe_espipe = pwritev2_pipe_espipe,
            preadv2_pipe_espipe = preadv2_pipe_espipe,
            pwritev2_rdonly_file_ebadf = pwritev2_rdonly_file_ebadf,
            pwritev2_offset_minus_one_regular_file_appends_at_current =
                pwritev2_offset_minus_one_regular_file_appends_at_current,
            inotify_blocking_read_returns_event = inotify_blocking_read_returns_event,
            inotify_nonblock_read_eagain = inotify_nonblock_read_eagain,
            fanotify_blocking_read_returns_event = fanotify_blocking_read_returns_event,
            fanotify_nonblock_read_eagain = fanotify_nonblock_read_eagain,
        );

        disarm_alarm();
    }
}
