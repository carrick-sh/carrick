//! clone3 exit_signal with a caught SIGCHLD handler.
//!
//! Docker's default seccomp profile may block clone3 with ENOSYS; that is an
//! acceptable oracle outcome. If clone3 succeeds, each fast-exiting child must
//! deliver SIGCHLD to the parent's caught handler before the parent reaps it.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicU32, Ordering};

const ITERS: u32 = 24;
static HITS: AtomicU32 = AtomicU32::new(0);

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

extern "C" fn on_sigchld(_sig: i32) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

unsafe fn clone3(args: *mut CloneArgs) -> i64 {
    libc::syscall(
        libc::SYS_clone3,
        args,
        core::mem::size_of::<CloneArgs>() as libc::c_long,
    ) as i64
}

fn main() {
    unsafe {
        let install_ok = conformance_probes::install_handler(libc::SIGCHLD, on_sigchld, 0);
        let mut clone3_blocked = false;
        let mut cloned_all = install_ok;
        let mut reaped_all = install_ok;
        let mut all_seen = install_ok;

        for expected in 1..=ITERS {
            let mut args = CloneArgs {
                exit_signal: libc::SIGCHLD as u64,
                ..CloneArgs::default()
            };
            let child = clone3(&mut args);
            let er = errno();
            if child == 0 {
                libc::_exit(0);
            }
            if child < 0 {
                clone3_blocked = er == libc::ENOSYS;
                cloned_all = clone3_blocked;
                reaped_all = clone3_blocked;
                all_seen = clone3_blocked;
                break;
            }

            for _ in 0..1000 {
                if HITS.load(Ordering::SeqCst) >= expected {
                    break;
                }
                libc::usleep(1000);
            }
            if HITS.load(Ordering::SeqCst) < expected {
                all_seen = false;
            }

            let mut status = 0;
            if libc::waitpid(child as i32, &mut status, 0) != child as i32 {
                reaped_all = false;
                all_seen = false;
                break;
            }
        }

        report!(
            install_ok = install_ok,
            clone3_blocked_or_cloned_all = clone3_blocked || cloned_all,
            reaped_all = reaped_all,
            all_exit_handlers_observed_or_blocked = all_seen,
        );
    }
}
