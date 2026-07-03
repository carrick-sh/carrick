//! Shared futex alias probe. Two futex words in the same `MAP_SHARED` page must
//! be independent wait keys: `FUTEX_WAKE(word_a, 1)` cannot consume the waiter
//! parked on `word_b`.

use std::sync::atomic::{Ordering, compiler_fence};
use std::time::{Duration, Instant};

// Per-target: libc resolves to 98 on aarch64-linux, 202 on x86_64-linux. A raw
// `98` ran getrusage on the x86_64 lanes and false-MATCHed.
const SYS_FUTEX: libc::c_long = libc::SYS_futex;
const FUTEX_WAIT: libc::c_int = 0; // shared (no FUTEX_PRIVATE_FLAG)
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

unsafe fn make_pipe() -> Option<[libc::c_int; 2]> {
    let mut fds = [-1, -1];
    if libc::pipe(fds.as_mut_ptr()) == 0 {
        Some(fds)
    } else {
        None
    }
}

unsafe fn signal_ready(fd: libc::c_int) {
    let byte = [1u8];
    let _ = libc::write(fd, byte.as_ptr() as *const libc::c_void, byte.len());
    libc::close(fd);
}

unsafe fn wait_ready(fd: libc::c_int, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let now = Instant::now();
        let remaining = if deadline > now {
            deadline - now
        } else {
            Duration::ZERO
        };
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = libc::poll(&mut pollfd, 1, timeout_ms);
        if rc > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            let mut byte = 0u8;
            return libc::read(fd, &mut byte as *mut u8 as *mut libc::c_void, 1) == 1;
        }
        if rc == 0 {
            break;
        }
    }
    false
}

unsafe fn wait_for_word(word: *mut u32, ready_fd: libc::c_int) -> ! {
    signal_ready(ready_fd);
    compiler_fence(Ordering::SeqCst);
    while std::ptr::read_volatile(word) == 0 {
        // Long enough that the parent can prove a single wake, but still
        // bounded so a cleanup failure cannot wedge the harness forever.
        let _ = futex_wait_timed(word, 0, 1000);
    }
    libc::_exit(0);
}

unsafe fn wait_child(pid: i32, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    let mut status = 0i32;
    while Instant::now() < deadline {
        let rc = libc::waitpid(pid, &mut status, libc::WNOHANG);
        if rc == pid {
            return Some(status);
        }
        if rc == -1 {
            return None;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}

unsafe fn child_alive(pid: i32) -> bool {
    let mut status = 0i32;
    libc::waitpid(pid, &mut status, libc::WNOHANG) == 0
}

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path: Vec<u8> =
            format!("/tmp/carrick_futexsharedalias_pid{}\0", libc::getpid()).into_bytes();
        let fd = libc::open(
            path.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if fd < 0 {
            println!("futex_shared_alias_setup=false");
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
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
            println!("futex_shared_alias_setup=false");
            return;
        }

        // word[0] and word[1] are distinct futexes on the same shared page.
        let words = map as *mut u32;
        let word_a = words.add(0);
        let word_b = words.add(1);
        for i in 0..2 {
            std::ptr::write_volatile(words.add(i), 0);
        }
        compiler_fence(Ordering::SeqCst);
        let (Some(ready_a_pipe), Some(ready_b_pipe)) = (make_pipe(), make_pipe()) else {
            println!("futex_shared_alias_setup=false");
            libc::munmap(map, 4096);
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
            return;
        };

        let pid_b = libc::fork();
        if pid_b == 0 {
            libc::close(ready_b_pipe[0]);
            libc::close(ready_a_pipe[0]);
            libc::close(ready_a_pipe[1]);
            wait_for_word(word_b, ready_b_pipe[1]);
        }
        libc::close(ready_b_pipe[1]);
        if pid_b < 0 {
            println!("futex_shared_alias_setup=false");
            libc::munmap(map, 4096);
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
            return;
        }

        let b_ready = wait_ready(ready_b_pipe[0], Duration::from_secs(2));
        libc::close(ready_b_pipe[0]);
        std::thread::sleep(Duration::from_millis(100));

        let pid_a = libc::fork();
        if pid_a == 0 {
            libc::close(ready_a_pipe[0]);
            wait_for_word(word_a, ready_a_pipe[1]);
        }
        libc::close(ready_a_pipe[1]);
        if pid_a < 0 {
            libc::kill(pid_b, libc::SIGKILL);
            let mut status = 0i32;
            libc::waitpid(pid_b, &mut status, 0);
            println!("futex_shared_alias_setup=false");
            libc::munmap(map, 4096);
            libc::close(fd);
            libc::unlink(path.as_ptr() as *const libc::c_char);
            return;
        }

        let a_ready = wait_ready(ready_a_pipe[0], Duration::from_secs(2));
        libc::close(ready_a_pipe[0]);
        std::thread::sleep(Duration::from_millis(100));

        std::ptr::write_volatile(word_a, 1);
        compiler_fence(Ordering::SeqCst);
        let wake_a_rc = futex_wake(word_a, 1);
        let a_status = wait_child(pid_a, Duration::from_millis(200));
        let a_exited_after_single_wake = a_status
            .map(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
            .unwrap_or(false);
        let b_still_blocked_after_single_wake = child_alive(pid_b);

        std::ptr::write_volatile(word_b, 1);
        compiler_fence(Ordering::SeqCst);
        let _ = futex_wake(word_a, i32::MAX as u32);
        let _ = futex_wake(word_b, i32::MAX as u32);

        let a_clean = if a_status.is_some() {
            a_exited_after_single_wake
        } else {
            wait_child(pid_a, Duration::from_secs(2))
                .map(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
                .unwrap_or(false)
        };
        let b_clean = wait_child(pid_b, Duration::from_secs(2))
            .map(|status| libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0)
            .unwrap_or(false);

        if !a_clean {
            libc::kill(pid_a, libc::SIGKILL);
            let mut status = 0i32;
            libc::waitpid(pid_a, &mut status, 0);
        }
        if !b_clean {
            libc::kill(pid_b, libc::SIGKILL);
            let mut status = 0i32;
            libc::waitpid(pid_b, &mut status, 0);
        }

        libc::munmap(map, 4096);
        libc::close(fd);
        libc::unlink(path.as_ptr() as *const libc::c_char);

        println!("futex_shared_alias_setup=true");
        println!("futex_shared_alias_b_ready={b_ready}");
        println!("futex_shared_alias_a_ready={a_ready}");
        println!("futex_shared_alias_wake_a_rc_one={}", wake_a_rc == 1);
        println!("futex_shared_alias_a_exited_after_single_wake={a_exited_after_single_wake}");
        println!(
            "futex_shared_alias_b_still_blocked_after_single_wake={b_still_blocked_after_single_wake}"
        );
        println!("futex_shared_alias_cleanup_ok={}", a_clean && b_clean);
    }
}
