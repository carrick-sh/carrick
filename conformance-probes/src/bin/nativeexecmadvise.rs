//! `madvise(MADV_DONTNEED)` in a forked and exec'd child (#1846, PR #1849).
//! Linux authority: madvise(2) returns 0 for DONTNEED over private anonymous
//! memory, keeps the mapping and its protection, and later reads of the range
//! see zero-filled pages; a misaligned start is EINVAL (22).
//!
//! V8 (Node) checks `madvise(base, length, MADV_DONTNEED) == 0` when it
//! discards code-range pages; under Carrick a fork+exec child is a ring-owned
//! native task, where the call used to return -38 (ENOSYS). The parent forks;
//! the child only `execve`s this binary again with `child`, and the new image
//! runs every case:
//!   1. `rw`: a private anonymous RW range is written, discarded, reads back
//!      zero and is still writable;
//!   2. `code`: V8's code-range shape: a `PROT_NONE`/`MAP_NORESERVE`
//!      reservation, part of it made RW, filled, made RX and read back, then
//!      the whole reservation discarded; the RX pages read back zero and the
//!      range is recommitted (RW, refilled, RX) and read back again;
//!   3. `rwx`: an RWX range is filled, discarded, reads back zero, and is
//!      rewritten in place;
//!   4. `misaligned`: a start one byte past a page boundary is EINVAL.
//!
//! The probe never executes the ranges: it proves the discard result and the
//! readback, not instruction fetch, so it needs no inline cache maintenance,
//! which an added probe may not carry (`candidate_probes::unlisted_reader`).
//!
//! The child is bounded by `alarm(10)` (it survives `execve`, and is set again
//! after it); the parent's `waitpid` by a non-restarting `alarm(20)` that
//! SIGKILLs and reaps the child. A child signal is reported, never accepted.
use conformance_probes::{errno, report};
use std::ffi::CString;

extern "C" fn on_alarm(_signal: libc::c_int) {}

fn outcome(ret: libc::c_int) -> (libc::c_int, i32) {
    (ret, if ret < 0 { errno() } else { 0 })
}

unsafe fn all_byte(base: *const u8, len: usize, value: u8) -> bool {
    std::slice::from_raw_parts(base, len)
        .iter()
        .all(|byte| *byte == value)
}

unsafe fn map(len: usize, prot: libc::c_int, extra: libc::c_int) -> *mut u8 {
    let base = libc::mmap(
        std::ptr::null_mut(),
        len,
        prot,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | extra,
        -1,
        0,
    );
    if base == libc::MAP_FAILED {
        println!("mmap_errno={}", errno());
        libc::_exit(2);
    }
    base.cast()
}

unsafe fn discard(base: *mut u8, len: usize) -> (libc::c_int, i32) {
    outcome(libc::madvise(base.cast(), len, libc::MADV_DONTNEED))
}

unsafe fn rw_case(page: usize) {
    let len = 2 * page;
    let base = map(len, libc::PROT_READ | libc::PROT_WRITE, 0);
    std::ptr::write_bytes(base, 0xa5, len);
    let (ret, err) = discard(base, len);
    report!(rw_madvise_ret = ret, rw_madvise_errno = err);
    report!(rw_zero_after_discard = all_byte(base, len, 0));
    base.add(page).write(0x5a);
    report!(rw_rewrite_kept = base.add(page).read() == 0x5a && base.read() == 0);
}

unsafe fn code_case(page: usize) {
    let len = 4 * page;
    let committed = 2 * page;
    let base = map(len, libc::PROT_NONE, libc::MAP_NORESERVE);
    let rw = outcome(libc::mprotect(
        base.cast(),
        committed,
        libc::PROT_READ | libc::PROT_WRITE,
    ));
    report!(code_commit_rw_ret = rw.0, code_commit_rw_errno = rw.1);
    if rw.0 != 0 {
        libc::_exit(3);
    }
    std::ptr::write_bytes(base, 0xa5, committed);
    let rx = outcome(libc::mprotect(
        base.cast(),
        committed,
        libc::PROT_READ | libc::PROT_EXEC,
    ));
    report!(code_rx_ret = rx.0, code_rx_errno = rx.1);
    if rx.0 != 0 {
        libc::_exit(3);
    }
    report!(code_rx_readback = all_byte(base, committed, 0xa5));

    let (ret, err) = discard(base, len);
    report!(code_madvise_ret = ret, code_madvise_errno = err);
    report!(code_zero_after_discard = all_byte(base, committed, 0));

    let recommit = outcome(libc::mprotect(
        base.cast(),
        committed,
        libc::PROT_READ | libc::PROT_WRITE,
    ));
    report!(
        code_recommit_rw_ret = recommit.0,
        code_recommit_rw_errno = recommit.1
    );
    if recommit.0 != 0 {
        libc::_exit(3);
    }
    std::ptr::write_bytes(base, 0x5a, committed);
    let rx = outcome(libc::mprotect(
        base.cast(),
        committed,
        libc::PROT_READ | libc::PROT_EXEC,
    ));
    report!(code_recommit_rx_ret = rx.0, code_recommit_rx_errno = rx.1);
    if rx.0 != 0 {
        libc::_exit(3);
    }
    report!(code_recommit_readback = all_byte(base, committed, 0x5a));
}

unsafe fn rwx_case(page: usize) {
    let len = 2 * page;
    let base = map(len, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, 0);
    std::ptr::write_bytes(base, 0xa5, len);
    report!(rwx_written = all_byte(base, len, 0xa5));
    let (ret, err) = discard(base, len);
    report!(rwx_madvise_ret = ret, rwx_madvise_errno = err);
    report!(rwx_zero_after_discard = all_byte(base, len, 0));
    std::ptr::write_bytes(base, 0x33, page);
    report!(rwx_rewrite_kept = all_byte(base, page, 0x33) && all_byte(base.add(page), page, 0));
}

unsafe fn misaligned_case(page: usize) {
    let base = map(2 * page, libc::PROT_READ | libc::PROT_WRITE, 0);
    let (ret, err) = discard(base.add(1), page);
    report!(misaligned_madvise_ret = ret, misaligned_madvise_errno = err);
}

/// Runs in the exec'd image of the fork child.
fn child() -> ! {
    unsafe {
        libc::alarm(10);
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        rw_case(page);
        code_case(page);
        rwx_case(page);
        misaligned_case(page);
        use std::io::Write;
        let flushed = std::io::stdout().flush().is_ok();
        libc::_exit(if flushed { 0 } else { 5 });
    }
}

fn parent(exe: &str) {
    let path = CString::new(exe).expect("argv[0]");
    let mode = CString::new("child").expect("child");
    let argv = [path.as_ptr(), mode.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::alarm(10);
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
        if pid < 0 {
            println!("fork_errno={}", errno());
            std::process::exit(1);
        }

        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
        libc::alarm(20);
        let mut status = 0;
        let mut timed_out = false;
        let mut reaped = libc::waitpid(pid, &mut status, 0);
        if reaped < 0 && errno() == libc::EINTR {
            timed_out = true;
            libc::kill(pid, libc::SIGKILL);
            reaped = libc::waitpid(pid, &mut status, 0);
        }
        libc::alarm(0);
        let exited = reaped == pid && libc::WIFEXITED(status);
        let signalled = reaped == pid && libc::WIFSIGNALED(status);
        report!(
            child_exit = if exited {
                libc::WEXITSTATUS(status).to_string()
            } else {
                "none".to_owned()
            },
            child_signal = if signalled {
                libc::WTERMSIG(status).to_string()
            } else {
                "none".to_owned()
            },
            child_timeout = timed_out
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("child") => child(),
        _ => parent(args.first().map(String::as_str).unwrap_or("/tmp/p")),
    }
}
