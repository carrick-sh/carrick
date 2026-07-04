//! clone301-shaped clone3 signal sequence.
//!
//! Runs the mixed clone3 cases that exposed Carrick's intermittent parent
//! exit-signal loss: default fork with SIGCHLD, SIGUSR2 exit_signal, CLONE_FS,
//! CLONE_NEWPID, and CLONE_PIDFD/PARENT_SETTID/CHILD_SETTID with a pidfd
//! SIGUSR1 payload before child exit.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicI32, Ordering};

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLONE_VFORK: u64 = 0x0000_4000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const SETUP_STACK_SIZE: usize = 0x9000;
const ITERS: usize = 24;
const PAYLOAD: i32 = 777;

static PARENT_SIGNAL: AtomicI32 = AtomicI32::new(0);
static CHILD_SIGNAL: AtomicI32 = AtomicI32::new(0);
static CHILD_VALUE: AtomicI32 = AtomicI32::new(0);

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

extern "C" fn on_parent(sig: i32) {
    PARENT_SIGNAL.store(sig, Ordering::SeqCst);
}

extern "C" fn on_child(sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    CHILD_SIGNAL.store(sig, Ordering::SeqCst);
    if !info.is_null() {
        let p = info as *const u8;
        unsafe {
            CHILD_VALUE.store(
                core::ptr::read_unaligned(p.add(24) as *const i32),
                Ordering::SeqCst,
            );
        }
    }
}

unsafe fn clone3(args: *mut CloneArgs) -> i64 {
    libc::syscall(
        libc::SYS_clone3,
        args,
        core::mem::size_of::<CloneArgs>() as libc::c_long,
    ) as i64
}

unsafe fn install_child_handler() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = on_child as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    libc::sigemptyset(&mut sa.sa_mask);
    let _ = libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut());
}

unsafe fn wait_parent_signal(expected: i32) -> bool {
    for _ in 0..1000 {
        if PARENT_SIGNAL.load(Ordering::SeqCst) == expected {
            return true;
        }
        libc::usleep(1000);
    }
    false
}

unsafe fn reap(child: i32) -> bool {
    let mut status = 0;
    libc::waitpid(child, &mut status, 0) == child
}

unsafe fn run_setup_vfork() -> Result<bool, i32> {
    let stack = libc::mmap(
        core::ptr::null_mut(),
        SETUP_STACK_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if stack == libc::MAP_FAILED {
        return Ok(false);
    }
    let mut args = CloneArgs {
        flags: CLONE_VM | CLONE_VFORK | CLONE_CLEAR_SIGHAND,
        exit_signal: libc::SIGCHLD as u64,
        stack: stack as u64,
        stack_size: SETUP_STACK_SIZE as u64,
        ..CloneArgs::default()
    };
    let child = clone3(&mut args);
    let er = errno();
    if child == 0 {
        libc::_exit(0);
    }
    let mut ok = true;
    if child < 0 {
        ok = er == libc::ENOSYS;
    } else {
        ok &= reap(child as i32);
    }
    libc::munmap(stack, SETUP_STACK_SIZE);
    if child < 0 && er != libc::ENOSYS {
        return Err(er);
    }
    Ok(ok)
}

unsafe fn run_exit_case(flags: u64, signal: i32) -> Result<bool, i32> {
    PARENT_SIGNAL.store(0, Ordering::SeqCst);
    let mut pidfd = -1i32;
    let mut child_tid = 0i32;
    let mut parent_tid = 0i32;
    let mut args = CloneArgs {
        flags,
        pidfd: &mut pidfd as *mut i32 as u64,
        child_tid: &mut child_tid as *mut i32 as u64,
        parent_tid: &mut parent_tid as *mut i32 as u64,
        exit_signal: signal as u64,
        ..CloneArgs::default()
    };
    let child = clone3(&mut args);
    let er = errno();
    if child == 0 {
        libc::_exit(0);
    }
    if child < 0 {
        return Err(er);
    }
    let saw = wait_parent_signal(signal);
    let reaped = reap(child as i32);
    Ok(saw && reaped)
}

unsafe fn run_pidfd_case() -> Result<(bool, bool), i32> {
    PARENT_SIGNAL.store(0, Ordering::SeqCst);
    CHILD_SIGNAL.store(0, Ordering::SeqCst);
    CHILD_VALUE.store(0, Ordering::SeqCst);

    let mut ready = [0; 2];
    if libc::pipe(ready.as_mut_ptr()) != 0 {
        return Ok((false, false));
    }
    let mut pidfd = -1i32;
    let mut child_tid = 0i32;
    let mut parent_tid = 0i32;
    let mut args = CloneArgs {
        flags: CLONE_PIDFD | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID,
        pidfd: &mut pidfd as *mut i32 as u64,
        child_tid: &mut child_tid as *mut i32 as u64,
        parent_tid: &mut parent_tid as *mut i32 as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let child = clone3(&mut args);
    let er = errno();
    if child == 0 {
        libc::close(ready[0]);
        install_child_handler();
        let _ = libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
        libc::close(ready[1]);
        for _ in 0..1000 {
            if CHILD_SIGNAL.load(Ordering::SeqCst) == libc::SIGUSR1 {
                break;
            }
            libc::usleep(1000);
        }
        libc::_exit((CHILD_VALUE.load(Ordering::SeqCst) != PAYLOAD) as i32);
    }
    if child < 0 {
        libc::close(ready[0]);
        libc::close(ready[1]);
        return Err(er);
    }

    libc::close(ready[1]);
    let mut b = [0u8; 1];
    let _ = libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
    libc::close(ready[0]);

    let mut info: libc::siginfo_t = core::mem::zeroed();
    let info_bytes = &mut info as *mut libc::siginfo_t as *mut u8;
    core::ptr::write(info_bytes.add(0) as *mut i32, libc::SIGUSR1);
    core::ptr::write(info_bytes.add(8) as *mut i32, libc::SI_QUEUE);
    core::ptr::write(info_bytes.add(0x18) as *mut i32, PAYLOAD);
    let signal_rc = libc::syscall(
        424i64,
        pidfd as i64,
        libc::SIGUSR1 as i64,
        &info as *const _,
        0i64,
    ) as i64;
    if pidfd >= 0 {
        libc::close(pidfd);
    }
    let saw_parent = wait_parent_signal(libc::SIGCHLD);
    let mut status = 0;
    let reaped = libc::waitpid(child as i32, &mut status, 0) == child as i32;
    let child_payload = reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    Ok((signal_rc == 0 && child_payload, saw_parent))
}

fn main() {
    unsafe {
        let mut setup_ok = true;
        let mut setup_blocked = false;
        for _ in 0..2 {
            match run_setup_vfork() {
                Ok(ok) => {
                    if !ok {
                        setup_blocked = true;
                        break;
                    }
                }
                Err(_) => setup_ok = false,
            }
        }

        let install_chld = conformance_probes::install_handler(libc::SIGCHLD, on_parent, 0);
        let install_usr2 = conformance_probes::install_handler(libc::SIGUSR2, on_parent, 0);
        if !setup_ok || !install_chld || !install_usr2 {
            report!(
                setup_vfork_ok_or_blocked = setup_blocked,
                install_ok = false,
                clone3_blocked_or_sequence_ok = false,
                child_payload_ok = false,
                parent_exit_signals_ok = false,
            );
            return;
        }

        let mut blocked = false;
        let mut parent_ok = true;
        for _ in 0..ITERS {
            for (flags, sig) in [
                (0, libc::SIGCHLD),
                (0, libc::SIGUSR2),
                (CLONE_FS, libc::SIGCHLD),
                (CLONE_NEWPID, libc::SIGCHLD),
            ] {
                match run_exit_case(flags, sig) {
                    Ok(ok) => parent_ok &= ok,
                    Err(er) if er == libc::ENOSYS => {
                        blocked = true;
                        break;
                    }
                    Err(er) if flags == CLONE_NEWPID && er == libc::EPERM => {}
                    Err(_) => parent_ok = false,
                }
            }
            if blocked || !parent_ok {
                break;
            }
        }

        let mut child_payload_ok = true;
        if !blocked {
            match run_pidfd_case() {
                Ok((child_ok, parent_sig_ok)) => {
                    child_payload_ok = child_ok;
                    parent_ok &= parent_sig_ok;
                }
                Err(er) if er == libc::ENOSYS => blocked = true,
                Err(_) => {
                    child_payload_ok = false;
                    parent_ok = false;
                }
            }
        }

        report!(
            setup_vfork_ok_or_blocked = setup_blocked || setup_ok,
            install_ok = true,
            clone3_blocked_or_sequence_ok = blocked || (parent_ok && child_payload_ok),
            child_payload_ok = blocked || child_payload_ok,
            parent_exit_signals_ok = blocked || parent_ok,
        );
    }
}
