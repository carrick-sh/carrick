//! seccomp and no_new_privs survive execve(2).
//!
//! The child installs a getppid-denying cBPF filter, then execs this image.
//! The replacement image reports both irreversible process properties through
//! an inherited pipe. This catches native host self-reexec reconstructing only
//! Carrick's launch policy while silently dropping guest-installed filters.

use conformance_probes::report;
use std::ffi::CString;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

fn filter(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

unsafe fn install_getppid_deny() -> bool {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return false;
    }
    let mut program = [
        filter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0),
        filter(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, libc::SYS_getppid as u32),
        filter(
            BPF_RET | BPF_K,
            0,
            0,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ),
        filter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
    ];
    let descriptor = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_long,
            &descriptor as *const libc::sock_fprog as libc::c_long,
            0,
            0,
        ) == 0
    }
}

unsafe fn replacement(write_fd: i32) -> ! {
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1;
    unsafe { *libc::__errno_location() = 0 };
    let result = unsafe { libc::syscall(libc::SYS_getppid) };
    let denied = result == -1 && unsafe { *libc::__errno_location() } == libc::EPERM;
    let findings = [u8::from(no_new_privs), u8::from(denied)];
    let written = unsafe { libc::write(write_fd, findings.as_ptr().cast(), findings.len()) };
    unsafe {
        libc::_exit(if written == findings.len() as isize {
            0
        } else {
            125
        })
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--replacement") {
        let write_fd = args
            .get(2)
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(-1);
        unsafe { replacement(write_fd) };
    }

    let exec_path = CString::new(args[0].as_bytes()).expect("exec path");
    unsafe {
        let mut pipe = [0_i32; 2];
        let pipe_ok = libc::pipe(pipe.as_mut_ptr()) == 0;
        if !pipe_ok {
            report!(
                no_new_privs_survives_exec = false,
                seccomp_filter_survives_exec = false,
                replacement_exited_zero = false,
            );
            return;
        }

        let child = libc::fork();
        if child == 0 {
            libc::close(pipe[0]);
            if !install_getppid_deny() {
                libc::_exit(124);
            }
            let marker = CString::new("--replacement").expect("marker");
            let fd = CString::new(pipe[1].to_string()).expect("fd");
            let argv = [
                exec_path.as_ptr(),
                marker.as_ptr(),
                fd.as_ptr(),
                core::ptr::null(),
            ];
            libc::execv(exec_path.as_ptr(), argv.as_ptr());
            libc::_exit(123);
        }

        libc::close(pipe[1]);
        let mut findings = [0_u8; 2];
        let mut offset = 0;
        while offset < findings.len() {
            let read = libc::read(
                pipe[0],
                findings[offset..].as_mut_ptr().cast(),
                findings.len() - offset,
            );
            if read <= 0 {
                break;
            }
            offset += read as usize;
        }
        libc::close(pipe[0]);
        let mut status = 0;
        while libc::waitpid(child, &mut status, 0) < 0 {
            if *libc::__errno_location() != libc::EINTR {
                break;
            }
        }
        report!(
            no_new_privs_survives_exec = offset == 2 && findings[0] != 0,
            seccomp_filter_survives_exec = offset == 2 && findings[1] != 0,
            replacement_exited_zero = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        );
    }
}
