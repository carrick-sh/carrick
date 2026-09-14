//! `/proc/self/exe` is a magic link to the task's retained executable object.
//!
//! It must remain executable after unlink, rename, pathname replacement, fork,
//! and a failed exec.  Each top-level case runs in a fresh child so a successful
//! exec never replaces the probe driver.  All waits and cleanup are bounded.

use conformance_probes::{errno, report};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WAIT_LIMIT: Duration = Duration::from_secs(5);
const POLL: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 10_000_000,
};

fn sleep_poll() {
    unsafe {
        libc::nanosleep(&POLL, std::ptr::null_mut());
    }
}

fn wait_bounded(pid: libc::pid_t) -> i32 {
    let deadline = Instant::now() + WAIT_LIMIT;
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            return status;
        }
        if rc < 0 && errno() != libc::EINTR {
            return -1;
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let reap_deadline = Instant::now() + WAIT_LIMIT;
            loop {
                let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if rc == pid {
                    return status;
                }
                if rc < 0 && errno() != libc::EINTR {
                    return -2;
                }
                if Instant::now() >= reap_deadline {
                    return -3;
                }
                sleep_poll();
            }
        }
        sleep_poll();
    }
}

fn exited_zero(status: i32) -> bool {
    status >= 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn exec(path: &CStr, stage: &CStr, old: &CStr, renamed: &CStr) -> ! {
    let argv = [
        c"procexeidentity".as_ptr(),
        stage.as_ptr(),
        old.as_ptr(),
        renamed.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(120);
    }
}

fn exec_with_fd(path: &CStr, stage: &CStr, old: &CStr, renamed: &CStr, fd: libc::c_int) -> ! {
    let fd = match CString::new(fd.to_string()) {
        Ok(fd) => fd,
        Err(_) => unsafe { libc::_exit(122) },
    };
    let argv = [
        c"procexeidentity".as_ptr(),
        stage.as_ptr(),
        old.as_ptr(),
        renamed.as_ptr(),
        fd.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    unsafe {
        libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        libc::_exit(123);
    }
}

fn exec_fd(fd: libc::c_int, stage: &CStr, old: &CStr, renamed: &CStr) -> ! {
    let argv = [
        c"procexeidentity".as_ptr(),
        stage.as_ptr(),
        old.as_ptr(),
        renamed.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(124);
    }
}

fn proc_link() -> Option<Vec<u8>> {
    std::fs::read_link("/proc/self/exe")
        .ok()
        .map(|path| path.as_os_str().as_bytes().to_vec())
}

fn fd_link(fd: libc::c_int) -> Option<Vec<u8>> {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .ok()
        .map(|path| path.as_os_str().as_bytes().to_vec())
}

fn open_proc_exe() -> Result<libc::c_int, i32> {
    let fd = unsafe { libc::open(c"/proc/self/exe".as_ptr(), libc::O_RDONLY) };
    if fd >= 0 { Ok(fd) } else { Err(errno()) }
}

fn close_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

fn executable_fd_cross_operation_checks(old: &CStr) -> i32 {
    let ordinary = unsafe { libc::open(old.as_ptr(), libc::O_RDONLY) };
    if ordinary < 0 {
        return 75;
    }
    let executable = match open_proc_exe() {
        Ok(fd) => fd,
        Err(_) => {
            close_fd(ordinary);
            return 76;
        }
    };

    let mut ordinary_stat: libc::stat = unsafe { std::mem::zeroed() };
    let mut executable_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(ordinary, &mut ordinary_stat) } != 0
        || unsafe { libc::fstat(executable, &mut executable_stat) } != 0
    {
        close_fd(executable);
        close_fd(ordinary);
        return 77;
    }
    if ordinary_stat.st_dev != executable_stat.st_dev
        || ordinary_stat.st_ino != executable_stat.st_ino
        || ordinary_stat.st_mode != executable_stat.st_mode
        || ordinary_stat.st_size != executable_stat.st_size
        || ordinary_stat.st_nlink != executable_stat.st_nlink
        || ordinary_stat.st_uid != executable_stat.st_uid
        || ordinary_stat.st_gid != executable_stat.st_gid
        || ordinary_stat.st_blocks != executable_stat.st_blocks
        || ordinary_stat.st_atime != executable_stat.st_atime
        || ordinary_stat.st_atime_nsec != executable_stat.st_atime_nsec
        || ordinary_stat.st_mtime != executable_stat.st_mtime
        || ordinary_stat.st_mtime_nsec != executable_stat.st_mtime_nsec
        || ordinary_stat.st_ctime != executable_stat.st_ctime
        || ordinary_stat.st_ctime_nsec != executable_stat.st_ctime_nsec
    {
        close_fd(executable);
        close_fd(ordinary);
        return 78;
    }

    let mut ordinary_bytes = [0u8; 64];
    let mut executable_bytes = [0u8; 64];
    let ordinary_read = unsafe {
        libc::pread(
            ordinary,
            ordinary_bytes.as_mut_ptr().cast(),
            ordinary_bytes.len(),
            0,
        )
    };
    let executable_read = unsafe {
        libc::pread(
            executable,
            executable_bytes.as_mut_ptr().cast(),
            executable_bytes.len(),
            0,
        )
    };
    if ordinary_read <= 0
        || executable_read != ordinary_read
        || executable_bytes[..executable_read as usize] != ordinary_bytes[..ordinary_read as usize]
    {
        close_fd(executable);
        close_fd(ordinary);
        return 79;
    }

    let ordinary_readv = unsafe { libc::open(old.as_ptr(), libc::O_RDONLY) };
    let executable_readv = match open_proc_exe() {
        Ok(fd) => fd,
        Err(_) => {
            close_fd(executable);
            close_fd(ordinary);
            close_fd(ordinary_readv);
            return 80;
        }
    };
    if ordinary_readv < 0 {
        close_fd(executable_readv);
        close_fd(executable);
        close_fd(ordinary);
        return 80;
    }
    let mut ordinary_first = [0u8; 17];
    let mut ordinary_second = [0u8; 47];
    let mut executable_first = [0u8; 17];
    let mut executable_second = [0u8; 47];
    let ordinary_iov = [
        libc::iovec {
            iov_base: ordinary_first.as_mut_ptr().cast(),
            iov_len: ordinary_first.len(),
        },
        libc::iovec {
            iov_base: ordinary_second.as_mut_ptr().cast(),
            iov_len: ordinary_second.len(),
        },
    ];
    let executable_iov = [
        libc::iovec {
            iov_base: executable_first.as_mut_ptr().cast(),
            iov_len: executable_first.len(),
        },
        libc::iovec {
            iov_base: executable_second.as_mut_ptr().cast(),
            iov_len: executable_second.len(),
        },
    ];
    let ordinary_readv_result = unsafe { libc::readv(ordinary_readv, ordinary_iov.as_ptr(), 2) };
    let executable_readv_result =
        unsafe { libc::readv(executable_readv, executable_iov.as_ptr(), 2) };
    if ordinary_readv_result <= 0
        || executable_readv_result != ordinary_readv_result
        || executable_first != ordinary_first
        || executable_second != ordinary_second
    {
        close_fd(executable_readv);
        close_fd(ordinary_readv);
        close_fd(executable);
        close_fd(ordinary);
        return 81;
    }

    let ordinary_end = unsafe { libc::lseek(ordinary, 0, libc::SEEK_END) };
    let executable_end = unsafe { libc::lseek(executable, 0, libc::SEEK_END) };
    if ordinary_end < 0 || executable_end != ordinary_end {
        close_fd(executable_readv);
        close_fd(ordinary_readv);
        close_fd(executable);
        close_fd(ordinary);
        return 82;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        close_fd(executable_readv);
        close_fd(ordinary_readv);
        close_fd(executable);
        close_fd(ordinary);
        return 83;
    }
    let mapped = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size as usize,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            executable,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        close_fd(executable_readv);
        close_fd(ordinary_readv);
        close_fd(executable);
        close_fd(ordinary);
        return 84;
    }
    let mapped_bytes =
        unsafe { std::slice::from_raw_parts(mapped.cast::<u8>(), ordinary_read as usize) };
    let mapped_matches = mapped_bytes == &ordinary_bytes[..ordinary_read as usize];
    unsafe { libc::munmap(mapped, page_size as usize) };
    close_fd(executable_readv);
    close_fd(ordinary_readv);
    close_fd(executable);
    close_fd(ordinary);
    if mapped_matches { 0 } else { 85 }
}

fn deleted_link_ends_with(old: &CStr) -> bool {
    let mut expected = old.to_bytes().to_vec();
    expected.extend_from_slice(b" (deleted)");
    proc_link().as_deref() == Some(expected.as_slice())
}

fn run_stage(stage: &[u8], old: &CStr, renamed: &CStr) -> i32 {
    match stage {
        b"--small" => exec(c"/proc/self/exe", c"--small-done", old, renamed),
        b"--small-done" | b"--unlink-done" | b"--failed-done" | b"--fork-child" => 0,
        b"--unlink" => {
            if unsafe { libc::unlink(old.as_ptr()) } != 0 {
                return 21;
            }
            if !deleted_link_ends_with(old) {
                return 22;
            }
            exec(c"/proc/self/exe", c"--unlink-done", old, renamed)
        }
        b"--rename" => {
            if unsafe { libc::rename(old.as_ptr(), renamed.as_ptr()) } != 0 {
                return 31;
            }
            if proc_link().as_deref() != Some(renamed.to_bytes()) {
                return 32;
            }
            if std::fs::write(Path::new(old.to_str().unwrap_or("")), b"not an elf\n").is_err() {
                return 33;
            }
            if std::fs::set_permissions(
                Path::new(old.to_str().unwrap_or("")),
                std::fs::Permissions::from_mode(0o755),
            )
            .is_err()
            {
                return 35;
            }
            exec(c"/proc/self/exe", c"--rename-done", old, renamed)
        }
        b"--rename-done" => {
            let argv = [c"replacement".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            unsafe {
                libc::execve(old.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            if errno() == libc::ENOEXEC { 0 } else { 34 }
        }
        b"--fork" => {
            if unsafe { libc::unlink(old.as_ptr()) } != 0 {
                return 41;
            }
            if !deleted_link_ends_with(old) {
                return 42;
            }
            // All CString/argv storage used by the child is prepared before fork.
            let child_stage = c"--fork-child";
            let argv = [
                c"procexeidentity".as_ptr(),
                child_stage.as_ptr(),
                old.as_ptr(),
                renamed.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [std::ptr::null::<libc::c_char>()];
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return 43;
            }
            if pid == 0 {
                unsafe {
                    libc::execve(c"/proc/self/exe".as_ptr(), argv.as_ptr(), envp.as_ptr());
                    libc::_exit(44);
                }
            }
            if exited_zero(wait_bounded(pid)) {
                0
            } else {
                45
            }
        }
        b"--failed" => {
            if unsafe { libc::unlink(old.as_ptr()) } != 0 {
                return 51;
            }
            let argv = [c"missing".as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            unsafe {
                libc::execve(
                    c"/definitely/missing/procexeidentity".as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                );
            }
            if errno() != libc::ENOENT || !deleted_link_ends_with(old) {
                return 52;
            }
            exec(c"/proc/self/exe", c"--failed-done", old, renamed)
        }
        b"--fd-rename" => {
            let fd = match open_proc_exe() {
                Ok(fd) => fd,
                Err(_) => return 61,
            };
            if unsafe { libc::rename(old.as_ptr(), renamed.as_ptr()) } != 0 {
                return 62;
            }
            if fd_link(fd).as_deref() != Some(renamed.to_bytes()) {
                return 63;
            }
            unsafe { libc::close(fd) };
            0
        }
        b"--fd-unlink" => {
            let fd = match open_proc_exe() {
                Ok(fd) => fd,
                Err(_) => return 64,
            };
            let mut before: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut before) } != 0 {
                close_fd(fd);
                return 66;
            }
            if unsafe { libc::unlink(old.as_ptr()) } != 0 {
                return 65;
            }
            let mut expected = old.to_bytes().to_vec();
            expected.extend_from_slice(b" (deleted)");
            let mut after: libc::stat = unsafe { std::mem::zeroed() };
            let valid = fd_link(fd).as_deref() == Some(expected.as_slice())
                && unsafe { libc::fstat(fd, &mut after) } == 0
                && after.st_nlink < before.st_nlink;
            close_fd(fd);
            if valid { 0 } else { 66 }
        }
        b"--hardlink-rename-noop" => {
            if unsafe { libc::link(old.as_ptr(), renamed.as_ptr()) } != 0 {
                return 67;
            }
            if unsafe { libc::rename(old.as_ptr(), renamed.as_ptr()) } != 0 {
                return 68;
            }
            if proc_link().as_deref() != Some(old.to_bytes()) {
                return 69;
            }
            if unsafe { libc::access(old.as_ptr(), libc::F_OK) } != 0
                || unsafe { libc::access(renamed.as_ptr(), libc::F_OK) } != 0
            {
                return 70;
            }
            0
        }
        b"--fd-intermediate-a" => {
            let fd = match open_proc_exe() {
                Ok(fd) => fd,
                Err(_) => return 71,
            };
            exec_with_fd(renamed, c"--fd-intermediate-b", old, renamed, fd)
        }
        b"--fd-intermediate-b" => {
            let fd = match std::env::args_os().nth(4) {
                Some(value) => match value.to_string_lossy().parse::<libc::c_int>() {
                    Ok(fd) if fd >= 0 => fd,
                    _ => return 72,
                },
                None => return 73,
            };
            exec_fd(fd, c"--fd-intermediate-a-done", old, renamed)
        }
        b"--fd-intermediate-a-done" => {
            if proc_link().as_deref() == Some(old.to_bytes()) {
                0
            } else {
                74
            }
        }
        b"--fd-cross-operations" => executable_fd_cross_operation_checks(old),
        _ => 99,
    }
}

fn make_copy(source: &Path, path: &Path) -> bool {
    std::fs::copy(source, path).is_ok()
        && std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).is_ok()
}

fn run_case(source: &Path, base: &Path, name: &str, stage: &CStr) -> i32 {
    run_case_with_second_image(source, base, name, stage, false)
}

fn run_case_with_second_image(
    source: &Path,
    base: &Path,
    name: &str,
    stage: &CStr,
    second_image: bool,
) -> i32 {
    let old_path = base.join(format!("{name}.old"));
    let renamed_path = base.join(format!("{name}.renamed"));
    if !make_copy(source, &old_path) {
        return -10;
    }
    if second_image && !make_copy(source, &renamed_path) {
        let _ = std::fs::remove_file(&old_path);
        return -14;
    }
    let old = match CString::new(old_path.as_os_str().as_bytes()) {
        Ok(path) => path,
        Err(_) => return -11,
    };
    let renamed = match CString::new(renamed_path.as_os_str().as_bytes()) {
        Ok(path) => path,
        Err(_) => return -12,
    };
    let argv = [
        c"procexeidentity".as_ptr(),
        stage.as_ptr(),
        old.as_ptr(),
        renamed.as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::execve(old.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(121);
        }
    }
    let status = if pid < 0 { -13 } else { wait_bounded(pid) };
    let _ = std::fs::remove_file(&old_path);
    let _ = std::fs::remove_file(&renamed_path);
    status
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_some_and(|arg| arg.as_bytes().starts_with(b"--"))
    {
        let old = args.get(2).and_then(|v| CString::new(v.as_bytes()).ok());
        let renamed = args.get(3).and_then(|v| CString::new(v.as_bytes()).ok());
        let code = match (old, renamed) {
            (Some(old), Some(renamed)) => run_stage(args[1].as_bytes(), &old, &renamed),
            _ => 98,
        };
        std::process::exit(code);
    }

    let source = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => {
            report!(setup_ok = false);
            return;
        }
    };
    let base = PathBuf::from(format!("/tmp/procexeidentity-{}", std::process::id()));
    if std::fs::create_dir(&base).is_err() {
        report!(setup_ok = false);
        return;
    }
    report!(setup_ok = true);

    let small = run_case(&source, &base, "small", c"--small");
    report!(small_self_exec = exited_zero(small));
    report!(small_self_exec_status = small);
    let unlink = run_case(&source, &base, "unlink", c"--unlink");
    report!(unlink_self_exec = exited_zero(unlink));
    report!(unlink_self_exec_status = unlink);
    let rename = run_case(&source, &base, "rename", c"--rename");
    report!(rename_replace_self_exec = exited_zero(rename));
    report!(rename_replace_self_exec_status = rename);
    let fork = run_case(&source, &base, "fork", c"--fork");
    report!(fork_retains_self_exec = exited_zero(fork));
    report!(fork_retains_self_exec_status = fork);
    let failed = run_case(&source, &base, "failed", c"--failed");
    report!(failed_exec_preserves_self = exited_zero(failed));
    report!(failed_exec_preserves_self_status = failed);
    let fd_rename = run_case(&source, &base, "fd-rename", c"--fd-rename");
    report!(fd_rename_readlink_tracks_dentry = exited_zero(fd_rename));
    report!(fd_rename_readlink_tracks_dentry_status = fd_rename);
    let fd_unlink = run_case(&source, &base, "fd-unlink", c"--fd-unlink");
    report!(fd_unlink_readlink_marks_deleted = exited_zero(fd_unlink));
    report!(fd_unlink_readlink_marks_deleted_status = fd_unlink);
    let hardlink_noop = run_case(
        &source,
        &base,
        "hardlink-rename-noop",
        c"--hardlink-rename-noop",
    );
    report!(hardlink_rename_same_inode_is_noop = exited_zero(hardlink_noop));
    report!(hardlink_rename_same_inode_is_noop_status = hardlink_noop);
    let fd_intermediate = run_case_with_second_image(
        &source,
        &base,
        "fd-intermediate",
        c"--fd-intermediate-a",
        true,
    );
    report!(fd_survives_intermediate_exec_and_fexecves_original = exited_zero(fd_intermediate));
    report!(fd_survives_intermediate_exec_and_fexecves_original_status = fd_intermediate);
    let fd_cross_operations = run_case(
        &source,
        &base,
        "fd-cross-operations",
        c"--fd-cross-operations",
    );
    report!(fd_cross_operations_match_original = exited_zero(fd_cross_operations));
    report!(fd_cross_operations_match_original_status = fd_cross_operations);

    let cleanup_ok = std::fs::remove_dir(&base).is_ok();
    report!(cleanup_ok = cleanup_ok);
}
