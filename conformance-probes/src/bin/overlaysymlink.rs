//! A symlink the GUEST creates whose target lives in the (read-only) image
//! layers must resolve for every operation, not just `open`.
//!
//! carrick's `--fs host` layout is a sparse writable UPPER over an immutable
//! LOWER holding the image layers. `stat(2)` asked the overlay backend to
//! follow the link, and that backend can only follow WITHIN the upper — so a
//! link pointing at image content looked dangling and got ENOENT, while
//! `open(2)` through the same link succeeded because open takes the layered
//! path. Anything that stats before acting (a PATH search, `os.path.exists`,
//! `execve`'s target check) therefore failed on a link real Linux resolves
//! fine. CPython `test_posix.test_posix_spawnp` is the canonical shape: it
//! symlinks a temp-dir program name at `sys.executable`, puts the temp dir on
//! PATH, and spawns it.
//!
//!  * link_to_image_file_stats: stat() through the link succeeds.
//!  * link_to_image_file_same_size: it describes the TARGET, not the link.
//!  * link_to_image_file_opens: open() through the link succeeds (control —
//!    this always worked, so a diff here means something else broke).
//!  * link_to_image_file_access_x: access(X_OK) through a link to an
//!    executable image file succeeds.
//!  * link_to_image_binary_execs: execve through the link runs the target.
//!  * dangling_link_stat_enoent: a link to a genuinely absent target still
//!    reports ENOENT — the fix must not make stat over-permissive.
//!  * dangling_link_lstat_ok: lstat of that same dangling link still
//!    describes the link itself.

use conformance_probes::report;

unsafe fn stat_follow(path: &std::ffi::CStr) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(path.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

unsafe fn lstat_nofollow(path: &std::ffi::CStr) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(path.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

fn main() {
    unsafe {
        libc::mkdir(c"/tmp/carrick-overlay-symlink".as_ptr(), 0o755);

        // A regular, non-executable image file, and an executable one.
        let data_link = c"/tmp/carrick-overlay-symlink/data";
        let exe_link = c"/tmp/carrick-overlay-symlink/prog";
        libc::unlink(data_link.as_ptr());
        libc::unlink(exe_link.as_ptr());
        libc::symlink(c"/etc/passwd".as_ptr(), data_link.as_ptr());
        libc::symlink(c"/bin/sh".as_ptr(), exe_link.as_ptr());

        let via_link = stat_follow(data_link);
        let direct = stat_follow(c"/etc/passwd");
        report!(link_to_image_file_stats = via_link.is_some());
        report!(
            link_to_image_file_same_size = match (&via_link, &direct) {
                (Some(a), Some(b)) => a.st_size == b.st_size,
                _ => false,
            }
        );

        let fd = libc::open(data_link.as_ptr(), libc::O_RDONLY);
        report!(link_to_image_file_opens = fd >= 0);
        if fd >= 0 {
            libc::close(fd);
        }

        report!(link_to_image_file_access_x = libc::access(exe_link.as_ptr(), libc::X_OK) == 0);

        // execve THROUGH the link: the exec target check stats it first.
        let pid = libc::fork();
        if pid == 0 {
            // argv[0] is "sh", NOT the link path: busybox dispatches its applet
            // on argv[0], so passing the link name makes even real Linux fail
            // with "applet not found" and the assertion would prove nothing.
            let argv = [
                b"sh\0".as_ptr() as *const libc::c_char,
                b"-c\0".as_ptr() as *const libc::c_char,
                b"exit 0\0".as_ptr() as *const libc::c_char,
                std::ptr::null(),
            ];
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::execve(exe_link.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(99);
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        report!(
            link_to_image_binary_execs = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        );

        // A genuinely dangling link must still be ENOENT under stat, and must
        // still be visible to lstat.
        let dangling = c"/tmp/carrick-overlay-symlink/dangling";
        libc::unlink(dangling.as_ptr());
        libc::symlink(
            c"/carrick-no-such-target-anywhere".as_ptr(),
            dangling.as_ptr(),
        );
        let enoent = stat_follow(dangling).is_none()
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT);
        report!(dangling_link_stat_enoent = enoent);
        report!(
            dangling_link_lstat_ok = lstat_nofollow(dangling)
                .is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFLNK)
        );

        libc::unlink(data_link.as_ptr());
        libc::unlink(exe_link.as_ptr());
        libc::unlink(dangling.as_ptr());
        libc::rmdir(c"/tmp/carrick-overlay-symlink".as_ptr());
    }
}
