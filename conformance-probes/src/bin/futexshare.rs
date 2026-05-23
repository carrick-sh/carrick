//! Cross-process futex probe. A parent and a forked child rendezvous on a
//! FUTEX word living in a `MAP_SHARED` file mapping — the shape LTP's
//! `tst_checkpoint` uses everywhere for parent↔child sync. The child blocks in
//! `FUTEX_WAIT` (no timeout) until the parent flips the word and `FUTEX_WAKE`s
//! it. On macOS carrick must bridge this across processes via `__ulock`
//! (parking-lot is per-process), so this is the regression guard for that path.
//!
//! Deterministic: prints a single boolean. The parent bounds its wait (~3s,
//! retrying the wake) so a broken cross-process wake yields `false` instead of
//! hanging the harness.

use std::sync::atomic::{compiler_fence, Ordering};

const SYS_FUTEX: libc::c_long = 98; // aarch64
const FUTEX_WAIT: libc::c_int = 0; // shared (no FUTEX_PRIVATE_FLAG)
const FUTEX_WAKE: libc::c_int = 1;

unsafe fn futex(uaddr: *mut u32, op: libc::c_int, val: u32) -> libc::c_long {
    libc::syscall(SYS_FUTEX, uaddr, op, val, std::ptr::null::<libc::timespec>())
}

fn main() {
    unsafe {
        // A 4 KiB shared file mapping holding two u32 words: [0]=futex, [1]=ready.
        // Ensure /tmp exists (a bare run-elf rootfs may not have it).
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/carrick_futexshare_ipc\0";
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            println!("futex_shared_setup=false");
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
            println!("futex_shared_setup=false");
            return;
        }
        let futex_word = map as *mut u32;
        let ready_word = (map as *mut u32).add(1);
        *futex_word = 0;
        *ready_word = 0;
        compiler_fence(Ordering::SeqCst);

        let pid = libc::fork();
        if pid == 0 {
            // Child: announce readiness, then block until the word changes.
            *ready_word = 1;
            compiler_fence(Ordering::SeqCst);
            while std::ptr::read_volatile(futex_word) == 0 {
                futex(futex_word, FUTEX_WAIT, 0);
            }
            libc::_exit(0);
        }

        // Parent: wait for the child to be ready, then flip the word and wake.
        // Bound the whole thing so a broken cross-process wake reports false.
        let mut woke = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::ptr::read_volatile(ready_word) == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        *futex_word = 1;
        compiler_fence(Ordering::SeqCst);
        while std::time::Instant::now() < deadline {
            futex(futex_word, FUTEX_WAKE, u32::MAX);
            let mut status = 0i32;
            let r = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if r == pid {
                woke = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if !woke {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0i32;
            libc::waitpid(pid, &mut status, 0);
        }
        libc::munmap(map, 4096);
        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);
        println!("futex_shared_cross_process={woke}");
    }
}
