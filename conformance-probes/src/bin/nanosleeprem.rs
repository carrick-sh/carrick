//! Interrupted nanosleep writes a sane `rem` timespec.
//!
//! Invariant: a caught SIGALRM interrupts a 1s nanosleep, the syscall returns
//! EINTR, the handler ran, and the non-null `rem` output is positive but less
//! than the original request. This catches runtimes that surface EINTR without
//! copying out remaining time, which makes restart loops sleep the full request
//! again under signal storms.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, install_handler, report};

static ALRM_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_alrm(_: i32) {
    ALRM_HITS.fetch_add(1, Ordering::SeqCst);
}

fn timespec_ns(ts: libc::timespec) -> i128 {
    i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec)
}

fn main() {
    unsafe {
        ALRM_HITS.store(0, Ordering::SeqCst);
        let installed = install_handler(libc::SIGALRM, on_alrm, 0);
        let req = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let mut rem = MaybeUninit::<libc::timespec>::zeroed().assume_init();

        arm_alarm_ms(50);
        let rc = libc::nanosleep(&req, &mut rem);
        let e = errno();
        disarm_alarm();

        let req_ns = timespec_ns(req);
        let rem_ns = timespec_ns(rem);
        report!(
            nanosleeprem_handler_installed = installed,
            nanosleeprem_interrupted = rc == -1 && e == libc::EINTR,
            nanosleeprem_handler_ran = ALRM_HITS.load(Ordering::SeqCst) >= 1,
            nanosleeprem_positive = rem_ns > 0,
            nanosleeprem_less_than_request = rem_ns < req_ns,
        );
    }
}
