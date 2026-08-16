//! `/proc/<pid>/oom_score_adj` as a PER-PROCESS, cross-process-writable file.
//!
//! This is the exact shape LTP's `tst_test` framework performs during setup:
//! `tst_memutils.c:set_oom_score_adj()` `access(2)`-checks
//! `/proc/<pid>/oom_score_adj` for a pid that is NOT the caller, writes -1000
//! to it, then reads it back and `tst_brk(TBROK)`s on any mismatch. carrick
//! served that file only under `/proc/self/`, so the access check failed and
//! EVERY new-API LTP test broke out before its first assertion.
//!
//! It also pins the part a process-global store cannot model: two live
//! processes must hold INDEPENDENT values, and a child must inherit the
//! parent's at fork (proc(5)). Under carrick's HVPatch backend every Linux
//! process is a thread of one host process, so a single shared cell would
//! publish one guest's write to every other guest and this probe would print
//! `child_sees_own=false` / `parent_unchanged_after_child_write=false`.
//!
//! Deterministic: booleans and one fixed integer only — never a pid, a time,
//! or an address. Every wait is bounded, so a broken path prints `false`
//! rather than hanging the harness.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn path_for(pid: i32) -> String {
    format!("/proc/{pid}/oom_score_adj")
}

fn read_value(path: &str) -> Option<i32> {
    let mut buf = String::new();
    std::fs::File::open(path)
        .ok()?
        .read_to_string(&mut buf)
        .ok()?;
    buf.trim().parse().ok()
}

fn write_value(path: &str, value: i32) -> bool {
    match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(mut f) => write!(f, "{value}").is_ok(),
        Err(_) => false,
    }
}

fn exists(path: &str) -> bool {
    let c = std::ffi::CString::new(path).expect("probe path has no interior NUL");
    unsafe { libc::access(c.as_ptr(), libc::F_OK) == 0 }
}

fn main() {
    // A pipe carries the child's findings back as two bytes, so the parent
    // never has to read the child's memory or race on a file.
    let mut fds = [0i32; 2];
    let piped = unsafe { libc::pipe(fds.as_mut_ptr()) } == 0;
    let (rd, wr) = (fds[0], fds[1]);

    // The parent's own value, set BEFORE the fork so the child must inherit it.
    let self_path = "/proc/self/oom_score_adj".to_string();
    let self_write_ok = write_value(&self_path, -1000);
    let self_readback = read_value(&self_path) == Some(-1000);

    let child = unsafe { libc::fork() };
    if child == 0 {
        // Child: prove it INHERITED -1000, then take a different value and
        // confirm it sees its own, not the parent's.
        let inherited = read_value("/proc/self/oom_score_adj") == Some(-1000);
        let own_ok = write_value("/proc/self/oom_score_adj", 250)
            && read_value("/proc/self/oom_score_adj") == Some(250);
        let report = [u8::from(inherited), u8::from(own_ok)];
        unsafe {
            libc::write(wr, report.as_ptr().cast(), report.len());
            // Stay alive so the parent can address us by pid, then wait to be
            // reaped. Bounded: the parent kills us regardless.
            libc::pause();
            libc::_exit(0);
        }
    }

    unsafe { libc::close(wr) };
    let mut report = [0u8; 2];
    let got = unsafe { libc::read(rd, report.as_mut_ptr().cast(), report.len()) };
    let child_inherited = got == 2 && report[0] == 1;
    let child_sees_own = got == 2 && report[1] == 1;

    // The framework's exact probe: does ANOTHER live process's file exist?
    let child_path = path_for(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut foreign_exists = false;
    while Instant::now() < deadline {
        if exists(&child_path) {
            foreign_exists = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    // Read the CHILD's value from the parent: it must be the child's 250, not
    // the parent's -1000. This is the assertion a shared cell fails.
    let foreign_value_is_childs = read_value(&child_path) == Some(250);

    // Writing another process's file must take effect on THAT process only.
    let foreign_write_ok = write_value(&child_path, 500);
    let foreign_write_visible = read_value(&child_path) == Some(500);
    let parent_unchanged_after_child_write = read_value(&self_path) == Some(-1000);

    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
        libc::close(rd);
    }

    println!("pipe_ok={piped}");
    println!("self_write_ok={self_write_ok}");
    println!("self_readback_is_minus1000={self_readback}");
    println!("child_inherited_parent_value={child_inherited}");
    println!("child_sees_own={child_sees_own}");
    println!("foreign_pid_file_exists={foreign_exists}");
    println!("foreign_value_is_childs={foreign_value_is_childs}");
    println!("foreign_write_ok={foreign_write_ok}");
    println!("foreign_write_visible={foreign_write_visible}");
    println!("parent_unchanged_after_child_write={parent_unchanged_after_child_write}");
    // A dead pid has no oom_score_adj: Linux answers ENOENT, and LTP's
    // access(2) probe is exactly what distinguishes that from a fabricated 0.
    println!("dead_pid_file_absent={}", !exists(&path_for(child)));
}
