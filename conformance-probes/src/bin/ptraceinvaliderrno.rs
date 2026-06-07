//! Ptrace invalid PEEK/POKE errno ownership.
//!
//! Stands in for the now-visible `ptrace06` failure matrix after exec-stop is
//! fixed: invalid PEEK/POKE TEXT/DATA/USER requests against a stopped tracee
//! must fail like Linux with `EIO` or `EFAULT`, not `ENOSYS`. This is not a
//! general debugger-memory-access probe.
//!
//! Deterministic output only: booleans and stable errno values.

use conformance_probes::{errno, report};

const WAIT_ITERS: usize = 200;

#[derive(Copy, Clone)]
struct WaitStatus {
    rc: i32,
    status: i32,
}

#[derive(Copy, Clone)]
struct PtraceCase {
    request: libc::c_int,
    addr: isize,
    data: isize,
}

#[derive(Copy, Clone)]
struct PtraceResult {
    failed: bool,
    errno: i32,
    errno_is_eio_or_efault: bool,
}

unsafe fn ptrace_traceme() -> bool {
    libc::ptrace(
        libc::PTRACE_TRACEME,
        0,
        core::ptr::null_mut::<libc::c_void>(),
        0,
    ) == 0
}

unsafe fn ptrace_cont(pid: i32, signal: i32) -> bool {
    libc::ptrace(
        libc::PTRACE_CONT,
        pid,
        core::ptr::null_mut::<libc::c_void>(),
        signal,
    ) == 0
}

unsafe fn wait_changed(pid: i32, options: i32) -> WaitStatus {
    let mut status = 0;
    for _ in 0..WAIT_ITERS {
        let rc = libc::waitpid(pid, &mut status, options | libc::WNOHANG);
        if rc != 0 {
            return WaitStatus { rc, status };
        }
        libc::usleep(10_000);
    }
    WaitStatus { rc: 0, status: 0 }
}

unsafe fn spawn_stopped_tracee() -> i32 {
    let pid = libc::fork();
    if pid == 0 {
        if !ptrace_traceme() {
            libc::_exit(70);
        }
        libc::raise(libc::SIGSTOP);
        libc::_exit(77);
    }
    pid
}

unsafe fn run_ptrace_case(pid: i32, case: PtraceCase) -> PtraceResult {
    *libc::__errno_location() = 0;
    let ret = libc::ptrace(
        case.request as _,
        pid,
        case.addr as *mut libc::c_void,
        case.data,
    );
    let er = errno();
    PtraceResult {
        failed: ret == -1,
        errno: er,
        errno_is_eio_or_efault: er == libc::EIO || er == libc::EFAULT,
    }
}

unsafe fn cleanup(pid: i32) {
    let _ = ptrace_cont(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
    let _ = libc::kill(pid, libc::SIGKILL);
    let _ = wait_changed(pid, 0);
}

fn main() {
    unsafe {
        let pid = spawn_stopped_tracee();
        if pid < 0 {
            report!(fork_ok = false);
            return;
        }

        let stop = wait_changed(pid, 0);
        let stopped = stop.rc == pid && libc::WIFSTOPPED(stop.status);
        if !stopped {
            cleanup(pid);
            report!(fork_ok = true, tracee_stopped = false, tracee_stopsig = 0,);
            return;
        }

        let peekdata = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_PEEKDATA as _,
                addr: 0,
                data: 0,
            },
        );
        let peektext = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_PEEKTEXT as _,
                addr: -1,
                data: 0,
            },
        );
        let peekuser = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_PEEKUSER as _,
                addr: 4097,
                data: 0,
            },
        );
        let pokedata = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_POKEDATA as _,
                addr: 0,
                data: 0,
            },
        );
        let poketext = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_POKETEXT as _,
                addr: -1,
                data: 0,
            },
        );
        let pokeuser = run_ptrace_case(
            pid,
            PtraceCase {
                request: libc::PTRACE_POKEUSER as _,
                addr: 4097,
                data: 0,
            },
        );

        cleanup(pid);

        report!(
            fork_ok = true,
            tracee_stopped = true,
            tracee_stopsig = libc::WSTOPSIG(stop.status),
            peekdata_failed = peekdata.failed,
            peekdata_errno = peekdata.errno,
            peekdata_errno_is_eio_or_efault = peekdata.errno_is_eio_or_efault,
            peektext_failed = peektext.failed,
            peektext_errno = peektext.errno,
            peektext_errno_is_eio_or_efault = peektext.errno_is_eio_or_efault,
            peekuser_failed = peekuser.failed,
            peekuser_errno = peekuser.errno,
            peekuser_errno_is_eio_or_efault = peekuser.errno_is_eio_or_efault,
            pokedata_failed = pokedata.failed,
            pokedata_errno = pokedata.errno,
            pokedata_errno_is_eio_or_efault = pokedata.errno_is_eio_or_efault,
            poketext_failed = poketext.failed,
            poketext_errno = poketext.errno,
            poketext_errno_is_eio_or_efault = poketext.errno_is_eio_or_efault,
            pokeuser_failed = pokeuser.failed,
            pokeuser_errno = pokeuser.errno,
            pokeuser_errno_is_eio_or_efault = pokeuser.errno_is_eio_or_efault,
        );
    }
}
