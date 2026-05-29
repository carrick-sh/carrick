//! Writing through a read-only MAP_SHARED file alias must NOT crash the host.
//! On Linux, a syscall that would write into a PROT_READ user mapping returns
//! EFAULT to the calling task. carrick's write_guest_bytes ignores mapping
//! permissions (it consults only the PROT_NONE set, trap.rs:1941), so the host
//! memcpy faults SIGBUS on the read-only host page and host_signal treats the
//! synchronous fault as a fatal carrick bug — the whole process dies.
//!
//! Run under `--fs host` (a real file -> a genuinely PROT_READ host page).
//! Crash-class: the write runs in a forked child; the parent reports how it
//! terminated. Linux child: read -> EFAULT, exits clean. carrick child: SIGBUS.

use conformance_probes::{errno, reap, report};

unsafe fn write_through_ro_alias() -> i32 {
    let path = b"/etc/hostname\0".as_ptr() as *const libc::c_char;
    let fd = libc::open(path, libc::O_RDONLY);
    if fd < 0 {
        return 90;
    }
    let p = libc::mmap(
        core::ptr::null_mut(),
        4096,
        libc::PROT_READ,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if p == libc::MAP_FAILED {
        return 91;
    }
    // Source of bytes to write INTO the read-only mapping.
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return 92;
    }
    let data = b"XXXX";
    libc::write(fds[1], data.as_ptr() as *const libc::c_void, data.len());
    libc::close(fds[1]);
    // read() must write the 4 bytes into the PROT_READ mapping.
    // Linux: -1/EFAULT. carrick: host SIGBUS before returning.
    let r = libc::read(fds[0], p, 4);
    if r < 0 {
        errno()
    } else {
        0
    }
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let e = write_through_ro_alias();
            // 0 => clean exit (Linux: EFAULT path); 2 => write wrongly succeeded.
            libc::_exit(if e == libc::EFAULT {
                0
            } else if e == 0 {
                2
            } else {
                3
            });
        }
        let (_, status) = reap(pid);
        report!(
            child_exited_clean = libc::WIFEXITED(status),
            child_read_efault = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            child_killed_by_signal = libc::WIFSIGNALED(status),
        );
    }
}
