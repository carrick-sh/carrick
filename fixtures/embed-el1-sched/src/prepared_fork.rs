//! Inherited prepared backing and two-live-process isolation.
use crate::pipe_count::{poll_read_count, read_count, write_count};

/// Keep both processes alive while publishing inherited prepared backing,
/// restoring PROT_NONE data and writing both inherited pages independently.
pub(crate) fn run() -> i32 {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return 1;
    }
    let page = page as usize;
    let len = page * 3;
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if base == libc::MAP_FAILED {
        return 1;
    }
    struct Region(*mut libc::c_void, usize);
    impl Drop for Region {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.0, self.1);
            }
        }
    }
    let _region = Region(base, len);
    let data = base.cast::<u8>();
    let hidden = unsafe { data.add(page * 2) };
    unsafe {
        // The first touch prepares the middle page without making it valid.
        data.write_volatile(0x11);
        hidden.write_volatile(0x22);
    }
    if unsafe { libc::mprotect(hidden.cast(), page, libc::PROT_NONE) } != 0 {
        return 1;
    }
    let pipes: Option<Vec<(OwnedFd, OwnedFd)>> = (0..2)
        .map(|_| {
            let mut fds = [-1; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
                return None;
            }
            // SAFETY: pipe2 returned two fresh owned descriptors.
            Some(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
        })
        .collect();
    let Some(mut pipes) = pipes else {
        return 1;
    };
    let (c2p_read, c2p_write) = pipes.pop().unwrap();
    let (p2c_read, p2c_write) = pipes.pop().unwrap();
    struct Alarm;
    impl Drop for Alarm {
        fn drop(&mut self) {
            unsafe {
                libc::alarm(0);
            }
        }
    }
    unsafe {
        libc::alarm(10);
    }
    let _alarm = Alarm;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return 1;
    }
    if pid == 0 {
        drop(c2p_read);
        drop(p2c_write);
        unsafe {
            libc::alarm(10);
        }
        let ok = unsafe {
            libc::mprotect(hidden.cast(), page, libc::PROT_READ) == 0
                && hidden.read_volatile() == 0x22
                && libc::mprotect(hidden.cast(), page, libc::PROT_READ | libc::PROT_WRITE) == 0
        };
        if !ok {
            unsafe {
                libc::_exit(1);
            }
        }
        unsafe {
            hidden.write_volatile(0x44);
        }
        // Fault the still-prepared neighbor after breaking COW, including
        // hosts whose physical COW compound covers several guest pages.
        if unsafe { data.add(page).read_volatile() } != 0 {
            unsafe {
                libc::_exit(1);
            }
        }
        unsafe {
            data.add(page).write_volatile(0x33);
        }
        // The parent checks its bytes before permitting this child to exit.
        // This native child waits with a blocking read, not ppoll (#894),
        // bounded by its alarm and by EOF if the parent exits early.
        let ok = write_count(c2p_write.as_raw_fd(), 1)
            && read_count(p2c_read.as_raw_fd()) == Some(1)
            && unsafe {
                data.read_volatile() == 0x11
                    && data.add(page).read_volatile() == 0x33
                    && hidden.read_volatile() == 0x44
            };
        unsafe {
            libc::_exit(if ok { 0 } else { 1 });
        }
    }
    drop(c2p_write);
    drop(p2c_read);
    let ready = poll_read_count(c2p_read.as_raw_fd(), 5_000) == Some(1);
    let isolated = ready
        && unsafe {
            libc::mprotect(hidden.cast(), page, libc::PROT_READ) == 0
                && hidden.read_volatile() == 0x22
                && data.add(page).read_volatile() == 0
        };
    unsafe {
        data.write_volatile(0x55);
    }
    let notified = write_count(p2c_write.as_raw_fd(), 1);
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let ok = isolated
        && notified
        && waited == pid
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0;
    unsafe {
        libc::alarm(0);
    }
    println!(
        "prepared-fork inherited_zero={isolated} prot_none_bytes={isolated} two_live_isolation={ok} ok={ok}"
    );
    if ok { 0 } else { 1 }
}
