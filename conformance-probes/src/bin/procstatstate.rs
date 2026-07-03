//! `/proc/<pid>/stat` state for a sleeping forked process.
//!
//! A forked child blocked in a shared `FUTEX_WAIT` should report state `S` to
//! its parent through `/proc/<child-pid>/stat`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;

unsafe fn futex_wait(uaddr: *mut u32, val: u32) -> libc::c_long {
    libc::syscall(
        libc::SYS_futex,
        uaddr,
        FUTEX_WAIT,
        val,
        std::ptr::null::<libc::timespec>(),
    )
}

unsafe fn futex_wake(uaddr: *mut u32, n: u32) -> libc::c_long {
    libc::syscall(
        libc::SYS_futex,
        uaddr,
        FUTEX_WAKE,
        n,
        std::ptr::null::<libc::timespec>(),
    )
}

fn stat_state(pid: i32) -> Option<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rparen = stat.rfind(')')?;
    stat[rparen + 1..].split_whitespace().next()?.chars().next()
}

fn main() {
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if map == libc::MAP_FAILED {
        println!("child_pid_known=false");
        println!("child_state_is_sleeping=false");
        println!("child_reaped=false");
        return;
    }
    let word = map as *mut AtomicU32;
    unsafe { (*word).store(0, Ordering::SeqCst) };

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            let raw = word as *mut u32;
            while (*word).load(Ordering::SeqCst) == 0 {
                let _ = futex_wait(raw, 0);
            }
            libc::_exit(0);
        }
    }
    if pid < 0 {
        println!("child_pid_known=false");
        println!("child_state_is_sleeping=false");
        println!("child_reaped=false");
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = None;
    while Instant::now() < deadline {
        state = stat_state(pid);
        if state == Some('S') {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    unsafe {
        (*word).store(1, Ordering::SeqCst);
        let _ = futex_wake(word as *mut u32, 1);
    }
    let mut status = 0i32;
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) } == pid;
    unsafe {
        libc::munmap(map, 4096);
    }

    println!("child_pid_known=true");
    println!("child_state={}", state.unwrap_or('?'));
    println!("child_state_is_sleeping={}", state == Some('S'));
    println!("child_reaped={reaped}");
}
