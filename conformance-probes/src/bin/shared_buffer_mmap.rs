//! Conformance probe for shared buffer mapping and cross-task futex synchronization.
//!
//! Verifies from inside the guest:
//! 1. Exposing or mapping a shared file via `mmap(MAP_SHARED)`.
//! 2. Zero-copy read/write page visibility between parent and child tasks.
//! 3. Futex wait and wake coordination across tasks on shared pages.
//! 4. Deterministic output lines diffed against the Linux oracle.

use std::sync::atomic::{compiler_fence, Ordering};
use std::time::Duration;

const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;

unsafe fn futex_wait_timed(uaddr: *mut u32, val: u32, timeout_ms: i64) -> libc::c_long {
    let ts = libc::timespec {
        tv_sec: timeout_ms / 1000,
        tv_nsec: (timeout_ms % 1000) * 1_000_000,
    };
    libc::syscall(SYS_FUTEX, uaddr, FUTEX_WAIT, val, &ts)
}

unsafe fn futex_wake(uaddr: *mut u32, val: u32) -> libc::c_long {
    libc::syscall(
        SYS_FUTEX,
        uaddr,
        FUTEX_WAKE,
        val,
        std::ptr::null::<libc::timespec>(),
    )
}

fn main() {
    unsafe {
        let shm_dir = b"/dev/carrick/shm\0".as_ptr() as *const libc::c_char;
        let mut stat_buf = std::mem::zeroed::<libc::stat>();
        let has_shm_dir = libc::stat(shm_dir, &mut stat_buf) == 0;

        let test_path = if has_shm_dir {
            format!("/dev/carrick/shm/probe_buf_{}\0", libc::getpid())
        } else {
            libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
            format!("/tmp/carrick_shm_probe_{}\0", libc::getpid())
        };

        let fd = libc::open(
            test_path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o666,
        );
        if fd < 0 {
            println!("shbuf_open=ERR");
            return;
        }
        libc::ftruncate(fd, 4096);

        let map = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        if map == libc::MAP_FAILED {
            println!("shbuf_mmap=ERR");
            libc::close(fd);
            libc::unlink(test_path.as_ptr() as *const libc::c_char);
            return;
        }

        let words = map as *mut u32;
        std::ptr::write_volatile(words.add(0), 0x12345678);
        std::ptr::write_volatile(words.add(1), 0);
        compiler_fence(Ordering::SeqCst);

        let pid = libc::fork();
        if pid == 0 {
            // Child: verify initial value, wait on futex word at words.add(1)
            let val0 = std::ptr::read_volatile(words.add(0));
            if val0 != 0x12345678 {
                libc::_exit(1);
            }
            while std::ptr::read_volatile(words.add(1)) == 0 {
                let _ = futex_wait_timed(words.add(1), 0, 1000);
            }
            std::ptr::write_volatile(words.add(0), 0x87654321);
            compiler_fence(Ordering::SeqCst);
            libc::_exit(0);
        }

        if pid < 0 {
            println!("shbuf_fork=ERR");
            libc::munmap(map, 4096);
            libc::close(fd);
            libc::unlink(test_path.as_ptr() as *const libc::c_char);
            return;
        }

        // Parent: sleep briefly, wake child, and wait for child update
        std::thread::sleep(Duration::from_millis(50));
        std::ptr::write_volatile(words.add(1), 1);
        compiler_fence(Ordering::SeqCst);
        let wake_rc = futex_wake(words.add(1), 1);

        let mut status = 0i32;
        let wait_rc = libc::waitpid(pid, &mut status, 0);
        let child_ok = wait_rc == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        let final_val0 = std::ptr::read_volatile(words.add(0));
        let zero_copy_matches = final_val0 == 0x87654321;

        libc::munmap(map, 4096);
        libc::close(fd);
        libc::unlink(test_path.as_ptr() as *const libc::c_char);

        println!("shbuf_setup=true");
        println!("shbuf_wake_rc_one={}", wake_rc == 1);
        println!("shbuf_child_ok={child_ok}");
        println!("shbuf_zero_copy_matches={zero_copy_matches}");
    }
}
