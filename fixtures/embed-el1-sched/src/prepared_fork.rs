//! Inherited prepared backing and two-live-process isolation.
use crate::pipe_count::{read_count, write_count};

fn errno_if_failed(rc: i64) -> i64 {
    if rc < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64
    } else {
        0
    }
}

/// The readiness word precedes the diagnostic record even when ppoll failed.
/// `consumed` includes any partial readiness read; never decode its remainder
/// as child fields. The caller has reaped the child, so EOF bounds every read.
fn read_diagnostics(fd: libc::c_int, consumed: usize, payload: &mut [u8; 96]) -> isize {
    let mut remainder = [0u8; 8];
    let mut skipped = consumed;
    while skipped < remainder.len() {
        let rc = unsafe { libc::read(fd, remainder.as_mut_ptr().cast(), remainder.len() - skipped) };
        if rc <= 0 { return rc; }
        skipped += rc as usize;
    }
    let mut have = 0;
    while have < payload.len() {
        let rc = unsafe { libc::read(fd, payload[have..].as_mut_ptr().cast(), payload.len() - have) };
        if rc < 0 { return rc; }
        if rc == 0 { break; }
        have += rc as usize;
    }
    have as isize
}

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
        // Diagnostic payload follows the original 8-byte readiness count. It is
        // sent after the parent acknowledgement, so it cannot be read as ready.
        // -999 means not reached; errno is zero on success, numeric on failure.
        let mut steps = [-999i64; 12];
        let mut sent = false;
        let ok = (|| {
            steps[0] = unsafe { libc::mprotect(hidden.cast(), page, libc::PROT_READ) } as i64;
            steps[1] = errno_if_failed(steps[0]);
            if steps[0] != 0 {
                return false;
            }
            steps[2] = unsafe { hidden.read_volatile() } as i64;
            if steps[2] != 0x22 {
                return false;
            }
            steps[3] =
                unsafe { libc::mprotect(hidden.cast(), page, libc::PROT_READ | libc::PROT_WRITE) }
                    as i64;
            steps[4] = errno_if_failed(steps[3]);
            if steps[3] != 0 {
                return false;
            }
            unsafe { hidden.write_volatile(0x44) };
            // Fault the still-prepared neighbor after breaking COW.
            steps[5] = unsafe { data.add(page).read_volatile() } as i64;
            if steps[5] != 0 {
                return false;
            }
            unsafe { data.add(page).write_volatile(0x33) };
            let bytes = 1u64.to_le_bytes();
            steps[6] =
                unsafe { libc::write(c2p_write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) }
                    as i64;
            steps[7] = errno_if_failed(steps[6]);
            sent = true;
            // Native child blocking read stays bounded by alarm and peer EOF.
            steps[6] == 8 && read_count(p2c_read.as_raw_fd()) == Some(1) && {
                steps[9] = unsafe { data.read_volatile() } as i64;
                steps[9] == 0x11 && {
                    steps[10] = unsafe { data.add(page).read_volatile() } as i64;
                    steps[10] == 0x33 && {
                        steps[11] = unsafe { hidden.read_volatile() } as i64;
                        steps[11] == 0x44
                    }
                }
            }
        })();
        if !sent {
            // An early failure formerly closed the pipe without a count. Zero
            // preserves ready=false while allowing diagnostics on the same pipe.
            let bytes = 0u64.to_le_bytes();
            steps[6] =
                unsafe { libc::write(c2p_write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) }
                    as i64;
            steps[7] = errno_if_failed(steps[6]);
            // Keep the read endpoint live for the parent's unchanged ack even
            // on a diagnostic early-failure path (avoid losing output to SIGPIPE).
            if steps[6] == 8 {
                let _ = read_count(p2c_read.as_raw_fd());
            }
        }
        steps[8] = i64::from(!ok);
        let mut bytes = [0u8; 96];
        for (chunk, value) in bytes.chunks_exact_mut(8).zip(steps) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        unsafe {
            libc::write(c2p_write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len());
            libc::_exit(steps[8] as i32);
        }
    }
    drop(c2p_write);
    drop(p2c_read);
    let mut pfd = libc::pollfd {
        fd: c2p_read.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    let polled = unsafe { libc::ppoll(&mut pfd, 1, &timeout, std::ptr::null()) };
    let poll_errno = errno_if_failed(polled as i64);
    let mut count = [0u8; 8];
    let mut have = 0;
    let mut read_rc = -999;
    let mut read_errno = -999;
    if polled > 0 && pfd.revents & libc::POLLIN != 0 {
        loop {
            read_rc = unsafe {
                libc::read(
                    c2p_read.as_raw_fd(),
                    count[have..].as_mut_ptr().cast(),
                    8 - have,
                )
            } as i64;
            read_errno = errno_if_failed(read_rc);
            if read_rc <= 0 {
                break;
            }
            have += read_rc as usize;
            if have == 8 {
                break;
            }
            // Preserve the original helper's bounded readiness check per read.
            if unsafe { libc::ppoll(&mut pfd, 1, &timeout, std::ptr::null()) } <= 0
                || pfd.revents & libc::POLLIN == 0
            {
                break;
            }
        }
    }
    let ready = have == 8 && u64::from_le_bytes(count) == 1;
    let mut parent_protect = -999;
    let mut parent_errno = -999;
    let mut parent_hidden = -999;
    let mut parent_middle = -999;
    let isolated = ready && {
        parent_protect = unsafe { libc::mprotect(hidden.cast(), page, libc::PROT_READ) };
        parent_errno = errno_if_failed(parent_protect as i64);
        parent_protect == 0 && {
            parent_hidden = unsafe { hidden.read_volatile() } as i64;
            parent_hidden == 0x22 && {
                parent_middle = unsafe { data.add(page).read_volatile() } as i64;
                parent_middle == 0
            }
        }
    };
    unsafe {
        data.write_volatile(0x55);
    }
    let notified = write_count(p2c_write.as_raw_fd(), 1);
    let mut status = 0;
    let waited = unsafe { libc::wait4(pid, &mut status, 0, std::ptr::null_mut()) };
    let wait_errno = errno_if_failed(waited as i64);
    let mut child = [-999i64; 12];
    let mut payload = [0u8; 96];
    // Child has exited (or alarm will terminate this fixture); EOF cannot hang.
    let diagnostic_read = read_diagnostics(c2p_read.as_raw_fd(), have, &mut payload);
    let diagnostic_errno = errno_if_failed(diagnostic_read as i64);
    if diagnostic_read == payload.len() as isize {
        for (value, bytes) in child.iter_mut().zip(payload.chunks_exact(8)) {
            *value = i64::from_le_bytes(bytes.try_into().unwrap());
        }
    }
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
    // Stable additive protocol: decimal values, fixed key order, -999 for
    // unreached/missing observations; *_errno is 0 on success or errno NUMBER.
    // child_exit is requested _exit status; wait_status is the raw wait4 status.
    println!(
        "prepared-fork-steps child_mprotect_r={} child_mprotect_r_errno={} child_hidden={} child_mprotect_rw={} child_mprotect_rw_errno={} child_middle={} child_write={} child_write_errno={} child_exit={} child_final_first={} child_final_middle={} child_final_hidden={} parent_mprotect_r={parent_protect} parent_mprotect_r_errno={parent_errno} parent_hidden={parent_hidden} parent_middle={parent_middle} ppoll={polled} ppoll_errno={poll_errno} revents={} read={read_rc} read_errno={read_errno} wait4={waited} wait4_errno={wait_errno} wait_status={status} diagnostic_read={diagnostic_read} diagnostic_errno={diagnostic_errno}",
        child[0],
        child[1],
        child[2],
        child[3],
        child[4],
        child[5],
        child[6],
        child[7],
        child[8],
        child[9],
        child[10],
        child[11],
        pfd.revents
    );
    if ok { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    #[test]
    fn diagnostic_record_stays_aligned_after_failed_or_partial_poll_read() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let expected = [0i64, 0, 34, 0, 0, 0, 8, 0, 0, 17, 51, 68];
        for consumed in [0, 3, 8] {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            let mut stream = 1u64.to_le_bytes().to_vec();
            for field in expected { stream.extend(field.to_le_bytes()); }
            // Simulate exactly the bytes already consumed by the readiness path.
            let remaining = &stream[consumed..];
            assert_eq!(unsafe { libc::write(writer.as_raw_fd(), remaining.as_ptr().cast(), remaining.len()) }, remaining.len() as isize);
            drop(writer);
            let mut payload = [0; 96];
            assert_eq!(super::read_diagnostics(reader.as_raw_fd(), consumed, &mut payload), 96);
            let actual: Vec<_> = payload.chunks_exact(8).map(|word| i64::from_le_bytes(word.try_into().unwrap())).collect();
            assert_eq!(actual, expected, "readiness bytes consumed: {consumed}");
        }
    }
}
