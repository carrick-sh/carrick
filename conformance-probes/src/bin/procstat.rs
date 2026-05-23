//! /proc/<pid>/stat introspection probe. A parent forks a child that blocks in
//! pause(), then reads the child's /proc/<pid>/stat and checks it can (a) open
//! it and (b) observe the child sleeping ('S'). This is the shape LTP pause01
//! and the futex tests use to wait for a peer to be blocked before waking it.
//!
//! Deterministic: booleans only (open success + whether the state char is one
//! of the "blocked" states). The parent bounds its poll so a missing /proc
//! reports false instead of hanging.

use std::time::{Duration, Instant};

fn read_state(pid: i32) -> Option<char> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Field 3 (state) is the first char after the final ") ".
    let after = s.rsplit_once(") ")?.1;
    after.chars().next()
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::pause();
            libc::_exit(0);
        }
        // Poll the child's stat until it is sleeping, or give up.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut opened = false;
        let mut sleeping = false;
        while Instant::now() < deadline {
            match read_state(pid) {
                Some(st) => {
                    opened = true;
                    if st == 'S' || st == 'D' {
                        sleeping = true;
                        break;
                    }
                }
                None => {}
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
        println!("proc_pid_stat_open={opened}");
        println!("proc_pid_stat_child_sleeping={sleeping}");
    }
}
