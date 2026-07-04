//! Reducer for the small ioctl regressions covered by LTP ioctl01, ioctl07,
//! and ioctl_ficlone04.

use std::ffi::CString;

use conformance_probes::report;

const TCGETA: libc::Ioctl = 0x5405;
const RNDGETENTCNT: libc::Ioctl = 0x8004_5200u32 as libc::Ioctl;
const FICLONE: libc::Ioctl = 0x4004_9409;

const EBADF: i32 = 9;
const EOPNOTSUPP: i32 = 95;
const EPERM: i32 = 1;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const EXDEV: i32 = 18;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn open(path: &str, flags: i32) -> i32 {
    let c_path = match CString::new(path) {
        Ok(c_path) => c_path,
        Err(_) => return -1,
    };
    unsafe { libc::open(c_path.as_ptr(), flags, 0o600) }
}

fn read_trimmed_i32(path: &str) -> Option<i32> {
    let fd = open(path, libc::O_RDONLY);
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 32];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None;
    }
    std::str::from_utf8(&buf[..n as usize])
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn accepted_ficlone_errno(errno: i32) -> bool {
    matches!(
        errno,
        EOPNOTSUPP | EPERM | EISDIR | EBADF | EINVAL | EXDEV
    )
}

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            report!(setup_ok = false);
            return;
        }
        let name_ptr = libc::ptsname(master);
        if name_ptr.is_null() {
            report!(setup_ok = false);
            libc::close(master);
            return;
        }
        let slave = libc::open(name_ptr, libc::O_RDWR | libc::O_NOCTTY, 0);
        if slave < 0 {
            report!(setup_ok = false);
            libc::close(master);
            return;
        }

        let tcgeta_null_rc = libc::ioctl(slave, TCGETA, 0usize);
        let tcgeta_null_errno = if tcgeta_null_rc < 0 { errno() } else { 0 };
        let mut termio = [0u8; 18];
        let tcgeta_ok_rc = libc::ioctl(slave, TCGETA, termio.as_mut_ptr());
        let tcgeta_ok_errno = if tcgeta_ok_rc < 0 { errno() } else { 0 };

        let null_fd = open("/dev/null", libc::O_RDONLY);
        let tcgeta_devnull_rc = libc::ioctl(null_fd, TCGETA, termio.as_mut_ptr());
        let tcgeta_devnull_errno = if tcgeta_devnull_rc < 0 { errno() } else { 0 };

        let random_fd = open("/dev/random", libc::O_RDONLY);
        let mut entropy_count = -1i32;
        let rnd_rc = libc::ioctl(random_fd, RNDGETENTCNT, &mut entropy_count as *mut i32);
        let rnd_errno = if rnd_rc < 0 { errno() } else { 0 };
        let proc_entropy =
            read_trimmed_i32("/proc/sys/kernel/random/entropy_avail").unwrap_or(-1);

        let out_fd = open("/tmp/carrick-ioctlcluster-out", libc::O_CREAT | libc::O_RDWR);
        let ficlone_bad_src_rc = libc::ioctl(out_fd, FICLONE, -1i32);
        let ficlone_bad_src_errno = if ficlone_bad_src_rc < 0 { errno() } else { 0 };
        let ficlone_devnull_rc = libc::ioctl(out_fd, FICLONE, null_fd);
        let ficlone_devnull_errno = if ficlone_devnull_rc < 0 { errno() } else { 0 };

        report!(
            setup_ok = true,
            tcgeta_null_errno = tcgeta_null_errno,
            tcgeta_ok_errno = tcgeta_ok_errno,
            tcgeta_devnull_errno = tcgeta_devnull_errno,
            rndgetentcnt_errno = rnd_errno,
            rndgetentcnt_count = entropy_count,
            proc_entropy = proc_entropy,
            rndgetentcnt_matches_proc = entropy_count == proc_entropy,
            ficlone_bad_src_errno = ficlone_bad_src_errno,
            ficlone_devnull_errno_accepted = accepted_ficlone_errno(ficlone_devnull_errno),
        );

        if out_fd >= 0 {
            libc::close(out_fd);
        }
        if random_fd >= 0 {
            libc::close(random_fd);
        }
        if null_fd >= 0 {
            libc::close(null_fd);
        }
        libc::close(slave);
        libc::close(master);
    }
}
