//! macOS/FreeBSD CrossProcessFutex implementation.

use carrick_hal::futex::CrossProcessFutex;

pub struct BsdFutex;

impl CrossProcessFutex for BsdFutex {
    fn wait(&self, host_addr: usize, expected: u32, timeout_us: u32) -> i64 {
        #[cfg(target_os = "macos")]
        {
            carrick_host::ulock::wait(host_addr, expected, timeout_us)
        }
        #[cfg(target_os = "freebsd")]
        {
            carrick_host::umtx::wait(host_addr, expected, timeout_us)
        }
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        {
            let _ = (host_addr, expected, timeout_us);
            -(libc::ENOSYS as i64)
        }
    }

    fn wake(&self, host_addr: usize, all: bool) -> i64 {
        #[cfg(target_os = "macos")]
        {
            carrick_host::ulock::wake(host_addr, all)
        }
        #[cfg(target_os = "freebsd")]
        {
            carrick_host::umtx::wake(host_addr, all)
        }
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        {
            let _ = (host_addr, all);
            -(libc::ENOSYS as i64)
        }
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::BsdFutex;
    use carrick_hal::futex::CrossProcessFutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    #[test]
    fn shared_futex_wakes_across_fork() {
        unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            );
            assert_ne!(page, libc::MAP_FAILED, "mmap failed");
            let word = &*(page as *const AtomicU32);
            word.store(0, Ordering::SeqCst);
            let addr = page as usize;
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                word.store(1, Ordering::SeqCst);
                BsdFutex.wake(addr, true);
                libc::_exit(0);
            }
            let rc = BsdFutex.wait(addr, 0, 5_000_000);
            assert!(rc >= 0, "wait returned {rc}");
            assert_eq!(
                word.load(Ordering::SeqCst),
                1,
                "child should have set the word"
            );
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            libc::munmap(page, 4096);
        }
    }
}
