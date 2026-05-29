//! sched_* / get-set-priority errno edges:
//!   - sched_{getscheduler,getparam,setparam,setscheduler} with a NEGATIVE pid
//!     → EINVAL (rejected before the ESRCH/param path).
//!   - sched_setscheduler(self, SCHED_OTHER, BAD_PTR) → EFAULT (a bad param
//!     pointer is checked before the priority-range validation).
//!   - getpriority(INVAL which) → EINVAL; getpriority/setpriority with a valid
//!     PRIO_* class and a negative `who` (no such pid/pgid/uid) → ESRCH.
//!
//! Stands in for LTP sched_getparam03, sched_setparam04, sched_setscheduler01,
//! getpriority02 (and the negative-who half of setpriority02). Raw syscalls so
//! the probe exercises carrick's dispatch, not the libc wrapper's errno
//! remapping. Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;

const SCHED_SETPARAM: libc::c_long = 118;
const SCHED_SETSCHEDULER: libc::c_long = 119;
const SCHED_GETSCHEDULER: libc::c_long = 120;
const SCHED_GETPARAM: libc::c_long = 121;
const SETPRIORITY: libc::c_long = 140;
const GETPRIORITY: libc::c_long = 141;
const PRIO_PROCESS: libc::c_long = 0;
const PRIO_PGRP: libc::c_long = 1;
const PRIO_USER: libc::c_long = 2;

fn err_is(rc: libc::c_long, e: i32) -> bool {
    rc == -1 && errno() == e
}

fn main() {
    unsafe {
        let mut param: i32 = 0;
        let pp = &mut param as *mut i32;

        // Negative pid → EINVAL across the sched_* family.
        println!(
            "getscheduler_negpid_einval={}",
            err_is(libc::syscall(SCHED_GETSCHEDULER, -1i64), libc::EINVAL)
        );
        println!(
            "getparam_negpid_einval={}",
            err_is(libc::syscall(SCHED_GETPARAM, -1i64, pp), libc::EINVAL)
        );
        println!(
            "setparam_negpid_einval={}",
            err_is(libc::syscall(SCHED_SETPARAM, -1i64, pp), libc::EINVAL)
        );
        println!(
            "setscheduler_negpid_einval={}",
            err_is(libc::syscall(SCHED_SETSCHEDULER, -1i64, 0i64, pp), libc::EINVAL)
        );

        // Bad param pointer (self, SCHED_OTHER) → EFAULT.
        println!(
            "setscheduler_badptr_efault={}",
            err_is(
                libc::syscall(SCHED_SETSCHEDULER, 0i64, 0i64, usize::MAX as i64),
                libc::EFAULT
            )
        );

        // getpriority: bad `which` → EINVAL; negative `who` → ESRCH (all classes).
        println!(
            "getpriority_badwhich_einval={}",
            err_is(libc::syscall(GETPRIORITY, -1i64, 0i64), libc::EINVAL)
        );
        println!(
            "getpriority_process_negwho_esrch={}",
            err_is(libc::syscall(GETPRIORITY, PRIO_PROCESS, -1i64), libc::ESRCH)
        );
        println!(
            "getpriority_pgrp_negwho_esrch={}",
            err_is(libc::syscall(GETPRIORITY, PRIO_PGRP, -1i64), libc::ESRCH)
        );
        println!(
            "getpriority_user_negwho_esrch={}",
            err_is(libc::syscall(GETPRIORITY, PRIO_USER, -1i64), libc::ESRCH)
        );
        println!(
            "setpriority_pgrp_negwho_esrch={}",
            err_is(libc::syscall(SETPRIORITY, PRIO_PGRP, -1i64, 0i64), libc::ESRCH)
        );
    }
}
