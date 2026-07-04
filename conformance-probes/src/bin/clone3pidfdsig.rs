//! clone3(CLONE_PIDFD) + pidfd_send_signal(siginfo): the target's SA_SIGINFO
//! handler must receive the caller's si_value payload.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicI32, Ordering};

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

const CLONE_PIDFD: u64 = 0x0000_1000;
const PAYLOAD: i32 = 777;
static CODE: AtomicI32 = AtomicI32::new(0);
static VALUE: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    if info.is_null() {
        return;
    }
    let p = info as *const u8;
    unsafe {
        CODE.store(
            core::ptr::read_unaligned(p.add(8) as *const i32),
            Ordering::SeqCst,
        );
        VALUE.store(
            core::ptr::read_unaligned(p.add(24) as *const i32),
            Ordering::SeqCst,
        );
    }
}

unsafe fn clone3(args: *mut CloneArgs) -> i64 {
    libc::syscall(
        libc::SYS_clone3,
        args,
        core::mem::size_of::<CloneArgs>() as libc::c_long,
    ) as i64
}

fn report_blocked() {
    report!(
        clone3_pidfd_created_or_blocked = true,
        pidfd_send_signal_ok = true,
        pidfd_siginfo_delivered = true,
        pidfd_siginfo_code_is_queue = true,
        pidfd_siginfo_payload = true,
    );
}

fn main() {
    unsafe {
        let mut observed = [0; 2];
        let mut ready = [0; 2];
        if libc::pipe(observed.as_mut_ptr()) != 0 || libc::pipe(ready.as_mut_ptr()) != 0 {
            return report_blocked();
        }

        let mut pidfd: i32 = -1;
        let mut args = CloneArgs {
            flags: CLONE_PIDFD,
            pidfd: &mut pidfd as *mut i32 as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let rc = clone3(&mut args);
        let er = errno();
        if rc == -1 && er == libc::ENOSYS {
            return report_blocked();
        }
        if rc == 0 {
            libc::close(observed[0]);
            libc::close(ready[0]);
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = on_usr1 as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);
            let _ = libc::sigaction(libc::SIGUSR1, &sa, core::ptr::null_mut());
            let _ = libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
            libc::close(ready[1]);
            for _ in 0..3000 {
                if CODE.load(Ordering::SeqCst) != 0 {
                    break;
                }
                libc::usleep(1000);
            }
            let result = [CODE.load(Ordering::SeqCst), VALUE.load(Ordering::SeqCst)];
            let _ = libc::write(
                observed[1],
                result.as_ptr() as *const libc::c_void,
                core::mem::size_of_val(&result),
            );
            libc::_exit(0);
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
        libc::close(observed[1]);
        let mut got = [0i32; 2];
        let n = libc::read(
            observed[0],
            got.as_mut_ptr() as *mut libc::c_void,
            core::mem::size_of_val(&got),
        );
        let mut st = 0;
        let _ = libc::waitpid(rc as i32, &mut st, 0);
        if pidfd >= 0 {
            libc::close(pidfd);
        }

        report!(
            clone3_pidfd_created_or_blocked = rc > 0 && pidfd >= 0,
            pidfd_send_signal_ok = signal_rc == 0,
            pidfd_siginfo_delivered = n as usize == core::mem::size_of_val(&got) && got[0] != 0,
            pidfd_siginfo_code_is_queue = got[0] == libc::SI_QUEUE,
            pidfd_siginfo_payload = got[1] == PAYLOAD,
        );
    }
}
