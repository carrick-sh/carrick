//! Process-lifecycle probe. Exercises fork/execve/wait4 and the exit-status
//! decoding macros (WIFEXITED/WEXITSTATUS/WIFSIGNALED/WTERMSIG), WNOHANG
//! reaping, and the process-group/session calls (getpgrp/setpgid/getpgid,
//! getsid/setsid). The conformance harness runs this identical static binary
//! under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing behaviour.
//!
//! Deterministic only: no pids, timestamps, or addresses are printed; values
//! are reduced to fixed exit codes, booleans, and stable relationships.

use std::process::exit;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    exit_status_normal();
    exit_status_signalled();
    execve_exit_codes();
    wnohang_reaping();
    process_group();
    session();
}

/// fork() a child that _exit(42); parent decodes the status.
fn exit_status_normal() {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(42) };
    }
    if pid < 0 {
        println!("exit_normal=ERR:{}", errno());
        return;
    }
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    println!(
        "exit_normal reaped_match={} ifexited={} exitstatus={} ifsignaled={}",
        waited == pid,
        libc::WIFEXITED(status),
        libc::WEXITSTATUS(status),
        libc::WIFSIGNALED(status),
    );
}

/// fork() a child that kills itself with SIGTERM; parent decodes the status.
fn exit_status_signalled() {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        // Should never reach here; if SIGTERM didn't terminate us, exit with a
        // sentinel so the parent's decode visibly diverges.
        unsafe { libc::_exit(99) };
    }
    if pid < 0 {
        println!("exit_signalled=ERR:{}", errno());
        return;
    }
    let mut status: libc::c_int = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    println!(
        "exit_signalled reaped_match={} ifsignaled={} termsig={} ifexited={}",
        waited == pid,
        libc::WIFSIGNALED(status),
        libc::WTERMSIG(status),
        libc::WIFEXITED(status),
    );
}

/// fork()+execve() /bin/true and /bin/false; verify the inherited exit codes.
fn execve_exit_codes() {
    for (label, path, want) in [
        ("true", b"/bin/true\0".as_ref(), 0),
        ("false", b"/bin/false\0".as_ref(), 1),
    ] {
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let argv = [path.as_ptr() as *const libc::c_char, std::ptr::null()];
            let envp = [std::ptr::null()];
            unsafe {
                libc::execve(
                    path.as_ptr() as *const libc::c_char,
                    argv.as_ptr(),
                    envp.as_ptr(),
                );
                // execve only returns on failure.
                libc::_exit(127);
            }
        }
        if pid < 0 {
            println!("execve_{label}=ERR:{}", errno());
            continue;
        }
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        println!(
            "execve_{label} ifexited={} exitstatus_match={}",
            libc::WIFEXITED(status),
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == want,
        );
    }
}

/// WNOHANG must return 0 for a still-running child, then reap it after it
/// exits. The child sleeps briefly so the first poll observes it alive.
fn wnohang_reaping() {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // ~150ms: long enough that the parent's first WNOHANG poll sees us
        // alive, short enough to keep the probe fast.
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 150_000_000 };
        unsafe {
            libc::nanosleep(&ts, std::ptr::null_mut());
            libc::_exit(7);
        }
    }
    if pid < 0 {
        println!("wnohang=ERR:{}", errno());
        return;
    }
    let mut status: libc::c_int = 0;
    let first = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    // Now block until it exits.
    let final_ = unsafe { libc::waitpid(pid, &mut status, 0) };
    println!(
        "wnohang first_zero={} final_match={} exitstatus={}",
        first == 0,
        final_ == pid,
        libc::WEXITSTATUS(status),
    );
}

/// getpgrp / setpgid: after setpgid(0,0) the process leads its own group,
/// so getpgid(0) == getpid().
fn process_group() {
    let pgrp = unsafe { libc::getpgrp() };
    if unsafe { libc::setpgid(0, 0) } != 0 {
        println!("pgroup setpgid=ERR:{}", errno());
        return;
    }
    let pgid = unsafe { libc::getpgid(0) };
    let pid = unsafe { libc::getpid() };
    println!(
        "pgroup pgrp_pos={} leads_own_group={}",
        pgrp > 0,
        pgid == pid,
    );
}

/// getsid / setsid: a group leader cannot become a session leader, so
/// setsid() must fail with EPERM here (we just called setpgid(0,0) above,
/// making us a group leader). getsid(0) must be positive.
fn session() {
    let sid = unsafe { libc::getsid(0) };
    let r = unsafe { libc::setsid() };
    let e = errno();
    println!(
        "session sid_pos={} setsid_failed_eperm={}",
        sid > 0,
        r == -1 && e == libc::EPERM,
    );
}
