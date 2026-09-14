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
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

const EXEC_STRING_CHILD: &[u8] = b"--exec-string-child";
const EXEC_STRING_UNEXPECTED_SUCCESS: &[u8] = b"--exec-string-unexpected-success";
const EXEC_WAIT: Duration = Duration::from_secs(5);
const EXEC_ERRNO_READ_ERROR: i32 = -1001;
const EXEC_ERRNO_SHORT_READ: i32 = -1002;
const EXEC_POLL: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

fn exec_string_child_status() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).map(|arg| arg.as_bytes()) == Some(EXEC_STRING_UNEXPECTED_SUCCESS) {
        return Some(105);
    }
    if args.get(1).map(|arg| arg.as_bytes()) != Some(EXEC_STRING_CHILD) {
        return None;
    }
    let Some(kind) = args.get(2).map(|arg| arg.as_bytes()) else {
        return Some(101);
    };
    let Some(expected_len) = args
        .get(3)
        .and_then(|arg| std::str::from_utf8(arg.as_bytes()).ok())
        .and_then(|arg| arg.parse::<usize>().ok())
    else {
        return Some(102);
    };
    let valid = match kind {
        b"argv" => {
            args.len() == 5
                && args[4].as_bytes().len() == expected_len
                && args[4].as_bytes().iter().all(|byte| *byte == 0xfe)
        }
        b"env" => {
            let value = std::env::var_os("X");
            args.len() == 4
                && expected_len >= 2
                && value.as_ref().is_some_and(|value| {
                    value.as_bytes().len() == expected_len - 2
                        && value.as_bytes().iter().all(|byte| *byte == 0xfe)
                })
        }
        _ => false,
    };
    Some(if valid { 0 } else { 103 })
}

fn sleep_exec_poll() {
    unsafe {
        libc::nanosleep(&EXEC_POLL, std::ptr::null_mut());
    }
}

fn wait_exec_child(pid: libc::pid_t) -> i32 {
    let deadline = Instant::now() + EXEC_WAIT;
    loop {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return status;
        }
        if rc == -1 && errno() != libc::EINTR {
            return -1;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let reap_deadline = Instant::now() + EXEC_WAIT;
            loop {
                let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if rc == pid {
                    return status;
                }
                if rc == -1 && errno() != libc::EINTR {
                    return -1;
                }
                if Instant::now() >= reap_deadline {
                    return -2;
                }
                sleep_exec_poll();
            }
        }
        sleep_exec_poll();
    }
}

struct ExecStringOutcome {
    success: bool,
    wait_status: i32,
    exec_errno: i32,
}

fn write_exec_errno(fd: libc::c_int, value: i32) {
    let bytes = value.to_ne_bytes();
    unsafe {
        libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    }
}

fn exec_string_success_at(path: &CStr, kind: &str, payload_len: usize) -> ExecStringOutcome {
    let mut pipe_fds = [-1; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        return ExecStringOutcome {
            success: false,
            wait_status: -3,
            exec_errno: errno(),
        };
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let fork_errno = errno();
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return ExecStringOutcome {
            success: false,
            wait_status: -4,
            exec_errno: fork_errno,
        };
    }
    if pid == 0 {
        unsafe {
            libc::close(pipe_fds[0]);
        }
        let arg0 = c"execfailsurvive";
        let marker = c"--exec-string-child";
        let kind = CString::new(kind).expect("static exec string kind");
        let len = CString::new(payload_len.to_string()).expect("decimal payload length");
        let payload = CString::new(vec![0xfe; payload_len]).expect("non-NUL payload");
        let env = if kind.as_bytes() == b"env" {
            let mut entry = Vec::with_capacity(payload_len);
            entry.extend_from_slice(b"X=");
            entry.resize(payload_len, 0xfe);
            Some(CString::new(entry).expect("non-NUL environment entry"))
        } else {
            None
        };
        let argv_payload = (kind.as_bytes() == b"argv").then_some(payload.as_ptr());
        let argv = [
            arg0.as_ptr(),
            marker.as_ptr(),
            kind.as_ptr(),
            len.as_ptr(),
            argv_payload.unwrap_or(std::ptr::null()),
            std::ptr::null(),
        ];
        let envp = [
            env.as_ref()
                .map_or(std::ptr::null(), |entry| entry.as_ptr()),
            std::ptr::null(),
        ];
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            write_exec_errno(pipe_fds[1], errno());
            libc::_exit(104);
        }
    }
    unsafe {
        libc::close(pipe_fds[1]);
    }
    let wait_status = wait_exec_child(pid);
    let mut exec_errno = 0_i32;
    if wait_status >= 0 {
        let read = unsafe {
            libc::read(
                pipe_fds[0],
                (&mut exec_errno as *mut i32).cast(),
                std::mem::size_of::<i32>(),
            )
        };
        if read == -1 {
            exec_errno = EXEC_ERRNO_READ_ERROR;
        } else if read != 0 && read != std::mem::size_of::<i32>() as isize {
            exec_errno = EXEC_ERRNO_SHORT_READ;
        }
    }
    unsafe {
        libc::close(pipe_fds[0]);
    }
    ExecStringOutcome {
        success: wait_status >= 0
            && libc::WIFEXITED(wait_status)
            && libc::WEXITSTATUS(wait_status) == 0,
        wait_status,
        exec_errno,
    }
}

fn exec_string_success(kind: &str, payload_len: usize) -> ExecStringOutcome {
    let Ok(path) = std::env::current_exe() else {
        return ExecStringOutcome {
            success: false,
            wait_status: -5,
            exec_errno: 0,
        };
    };
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return ExecStringOutcome {
            success: false,
            wait_status: -6,
            exec_errno: 0,
        };
    };
    exec_string_success_at(&path, kind, payload_len)
}

fn exec_string_expecting_failure(kind: &str, payload_len: usize) -> i32 {
    let path = c"/proc/self/exe";
    let arg0 = c"execfailsurvive";
    let unexpected_success = c"--exec-string-unexpected-success";
    let payload = CString::new(vec![0xfe; payload_len]).expect("non-NUL payload");
    let env = if kind == "env" {
        let mut entry = Vec::with_capacity(payload_len);
        entry.extend_from_slice(b"X=");
        entry.resize(payload_len, 0xfe);
        Some(CString::new(entry).expect("non-NUL environment entry"))
    } else {
        None
    };
    let argv = [
        arg0.as_ptr(),
        unexpected_success.as_ptr(),
        (kind == "argv")
            .then_some(payload.as_ptr())
            .unwrap_or(std::ptr::null()),
        std::ptr::null(),
    ];
    let envp = [
        env.as_ref()
            .map_or(std::ptr::null(), |entry| entry.as_ptr()),
        std::ptr::null(),
    ];
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    errno()
}

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
    if let Some(status) = exec_string_child_status() {
        std::process::exit(status);
    }

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

    let argv_8192 = exec_string_success("argv", 8192);
    report!(argv_8192_exec = argv_8192.success);
    report!(argv_8192_wait_status = argv_8192.wait_status);
    report!(argv_8192_exec_errno = argv_8192.exec_errno);
    let argv_131071 = exec_string_success("argv", 131071);
    report!(argv_131071_exec = argv_131071.success);
    report!(argv_131071_wait_status = argv_131071.wait_status);
    report!(argv_131071_exec_errno = argv_131071.exec_errno);
    let env_8192 = exec_string_success("env", 8192);
    report!(env_8192_exec = env_8192.success);
    report!(env_8192_wait_status = env_8192.wait_status);
    report!(env_8192_exec_errno = env_8192.exec_errno);
    let env_131071 = exec_string_success("env", 131071);
    report!(env_131071_exec = env_131071.success);
    report!(env_131071_wait_status = env_131071.wait_status);
    report!(env_131071_exec_errno = env_131071.exec_errno);

    let proc_self_exe = exec_string_success_at(c"/proc/self/exe", "argv", 16);
    report!(proc_self_exe_exec = proc_self_exe.success);
    report!(proc_self_exe_wait_status = proc_self_exe.wait_status);
    report!(proc_self_exe_exec_errno = proc_self_exe.exec_errno);

    report!(argv_131072_errno = exec_string_expecting_failure("argv", 131072));
    report!(argv_131072_image_intact = image.intact());
    report!(env_131072_errno = exec_string_expecting_failure("env", 131072));
    report!(env_131072_image_intact = image.intact());
}
