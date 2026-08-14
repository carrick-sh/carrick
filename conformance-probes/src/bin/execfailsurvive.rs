//! `execve(2)` failure atomicity: a failed exec must leave the CALLER alive
//! with its old image completely intact.
//!
//! Linux's rule is that `execve` either replaces the image or returns an error
//! with the caller unchanged and still running. There is a point of no return:
//! everything detected before the new image is committed returns an errno;
//! everything after kills the process. This probe covers the *before* half,
//! which is the half a caller can observe.
//!
//! Carrick had 19 exec probes and every one of them exercised a SUCCESSFUL
//! exec — their failure branches uniformly treat a failed exec as a probe bug
//! ("print the errno and `_exit`"), so nothing had ever asked whether the
//! caller survived. The audit in
//! `docs/perf-results/2026-08-13-exec-failure-atomicity-audit.md` found six
//! pre-commit failure paths that kill the caller with exit code 127 instead of
//! returning an errno — four of them driven by wall-clock timeouts, so
//! load-dependent rather than theoretical. 127 is also exactly what a shell
//! reports for "command not found", which is why the failure hides.
//!
//! Deliberately run from the MAIN process, not a forked child: a child that
//! dies is invisible to the parent's own state, and the state being checked is
//! precisely the caller's.
//!
//! Each case asserts the errno AND that the old image survived it: an open fd
//! still reads, a `SIG_IGN` disposition is still ignored, the argv the guest
//! sees is unchanged, and `/proc/self/exe` still names this binary. That the
//! later lines print at all is itself the survival assertion.

use conformance_probes::{current_disposition, errno, install_ign, report};
use std::ffi::CString;
use std::io::Write;

/// State the old image must still have after every failed exec.
struct Image {
    fd: libc::c_int,
    exe: String,
    cmdline: String,
}

impl Image {
    fn capture(fd: libc::c_int) -> Self {
        Self {
            fd,
            exe: read_proc("/proc/self/exe"),
            cmdline: read_proc("/proc/self/cmdline"),
        }
    }

    /// Re-read everything and report whether the old image is intact. Runs
    /// after each failed exec; a `false` anywhere is a torn image.
    fn intact(&self) -> bool {
        // The fd must still be open AND readable at the offset we left it.
        let mut buf = [0_u8; 8];
        let n =
            unsafe { libc::pread(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        let fd_alive = n == buf.len() as isize && &buf[..5] == b"KEEPM";
        // A SIG_IGN disposition survives a SUCCESSFUL exec, so it must
        // certainly survive a failed one. Carrick resets live handler state
        // before its last fallible step, which is what this catches.
        let ign_kept = unsafe { current_disposition(libc::SIGPIPE) } == libc::SIG_IGN;
        // The identity a failed exec must NOT have rewritten to the target it
        // failed to load.
        let exe_kept = read_proc("/proc/self/exe") == self.exe;
        let cmdline_kept = read_proc("/proc/self/cmdline") == self.cmdline;
        fd_alive && ign_kept && exe_kept && cmdline_kept
    }
}

fn read_proc(path: &str) -> String {
    std::fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_else(|_| "<unreadable>".to_owned())
}

/// `execve` the given path with a minimal argv and return the errno it failed
/// with. Returns 0 if the exec unexpectedly SUCCEEDED, which cannot happen —
/// a successful exec never returns — so 0 marks a probe bug, not a pass.
fn exec_expecting_failure(path: &str) -> i32 {
    let Ok(c_path) = CString::new(path) else {
        return -1;
    };
    let arg0 = CString::new("probe").expect("arg0");
    let argv = [arg0.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];
    unsafe {
        libc::execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    errno()
}

fn write_file(path: &str, contents: &[u8], mode: u32) -> bool {
    let Ok(mut file) = std::fs::File::create(path) else {
        return false;
    };
    if file.write_all(contents).is_err() {
        return false;
    }
    drop(file);
    let Ok(c_path) = CString::new(path) else {
        return false;
    };
    unsafe { libc::chmod(c_path.as_ptr(), mode as libc::mode_t) == 0 }
}

fn main() {
    // The fd whose survival every case checks. Its content is the marker
    // `intact()` reads back, so a recycled or reopened fd cannot pass.
    let keep_path = "/tmp/execfail-keep";
    if !write_file(keep_path, b"KEEPME-01", 0o644) {
        report!(setup_keepfile = false);
        std::process::exit(2);
    }
    let c_keep = CString::new(keep_path).expect("keep path");
    let fd = unsafe { libc::open(c_keep.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        report!(setup_open = false);
        std::process::exit(2);
    }
    unsafe {
        install_ign(libc::SIGPIPE);
    }
    let image = Image::capture(fd);
    report!(setup_ok = true);

    // ENOENT — nothing at the path at all.
    report!(enoent_errno = exec_expecting_failure("/nonexistent/binary"));
    report!(enoent_image_intact = image.intact());

    // EACCES — the file exists and is not executable.
    let noexec = "/tmp/execfail-noexec";
    if !write_file(noexec, b"not executable\n", 0o644) {
        report!(setup_noexec = false);
        std::process::exit(2);
    }
    report!(eacces_errno = exec_expecting_failure(noexec));
    report!(eacces_image_intact = image.intact());

    // ENOEXEC — executable, but neither an ELF nor a `#!` script. The leading
    // bytes are deliberately not a recognised magic of any kind.
    let badmagic = "/tmp/execfail-badmagic";
    if !write_file(badmagic, b"\x00\x01\x02\x03not-an-elf\n", 0o755) {
        report!(setup_badmagic = false);
        std::process::exit(2);
    }
    report!(enoexec_errno = exec_expecting_failure(badmagic));
    report!(enoexec_image_intact = image.intact());

    // EACCES — a directory is not executable.
    report!(eisdir_errno = exec_expecting_failure("/tmp"));
    report!(eisdir_image_intact = image.intact());

    // ENOTDIR — a path component that is a regular file.
    report!(enotdir_errno = exec_expecting_failure("/tmp/execfail-keep/bin"));
    report!(enotdir_image_intact = image.intact());

    // ENAMETOOLONG — well past PATH_MAX.
    let long_path = format!("/tmp/{}", "a".repeat(5000));
    report!(enametoolong_errno = exec_expecting_failure(&long_path));
    report!(enametoolong_image_intact = image.intact());

    // ELOOP — a symlink that points at itself.
    let loop_path = "/tmp/execfail-loop";
    let _ = std::fs::remove_file(loop_path);
    let loop_made = std::os::unix::fs::symlink(loop_path, loop_path).is_ok();
    report!(setup_loop = loop_made);
    if loop_made {
        report!(eloop_errno = exec_expecting_failure(loop_path));
        report!(eloop_image_intact = image.intact());
    }

    // Reaching here at all is the headline assertion: seven failed execs and
    // the caller is still the same process running the same image.
    report!(survived_all = true);
    report!(final_image_intact = image.intact());
}
