//! POSIX per-process timers (CLOCK_MONOTONIC + SIGEV_SIGNAL). Stands in for
//! LTP `timer_create01`–`07`, `timer_settime01`/`02`, `timer_gettime01`,
//! `timer_delete01`, `timer_getoverrun01`. carrick currently has the whole
//! timer_* family as ENOSYS / unregistered, so until those land this probe
//! is the headline divergence vs the Docker oracle.
//!
//! Invariants encoded, all boolean:
//!
//!   * `timer_create(CLOCK_MONOTONIC, &sigevent{SIGEV_SIGNAL, SIGUSR1}, &id)`
//!     returns 0.
//!   * Immediately after `timer_settime(id, 0, {50ms,0}, NULL)` the timer's
//!     remaining `tv_nsec` (read via `timer_gettime`) is POSITIVE — never
//!     printed as a number, just as `remaining_is_positive=true`.
//!   * Once fired, SIGUSR1 is delivered and the installed handler runs.
//!   * `timer_delete(id)` returns 0, and a subsequent `timer_gettime(id, …)`
//!     fails (-1 with EINVAL — the id is now stale).
//!   * `timer_getoverrun(id_live)` returns >= 0 (boolean), exercised on a
//!     fresh live timer before delete.
//!
//! musl exposes the timer_* family as both functions and SYS_* numbers; we
//! use the functions for clarity. sigevent's reserved fields must be zeroed
//! (libc::Padding), so the struct is constructed via `MaybeUninit::zeroed`
//! and then the four named fields are filled in.
//!
//! Deterministic only: NEVER print the actual remaining-ns, the timer id
//! address, or the overrun count — only booleans (is-positive, is-nonneg,
//! handler-ran).

use conformance_probes::{errno, install_handler, report};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let _ = install_handler(libc::SIGUSR1, on_usr1, libc::SA_RESTART);
        USR1_HITS.store(0, Ordering::SeqCst);

        // Build a sigevent that asks the kernel to deliver SIGUSR1 on expiry.
        let mut sev: libc::sigevent = MaybeUninit::zeroed().assume_init();
        sev.sigev_notify = libc::SIGEV_SIGNAL;
        sev.sigev_signo = libc::SIGUSR1;
        // sigev_value is zeroed (we don't use it).

        let mut id: libc::timer_t = std::ptr::null_mut();
        let create_rc = libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut id);
        report!(timer_create_rc_zero = create_rc == 0);
        if create_rc != 0 {
            // Without a timer we can't run the rest. Print false-for-all so
            // the diff still has a stable shape under carrick-without-timers.
            report!(
                timer_settime_rc_zero = false,
                timer_gettime_remaining_is_positive = false,
                timer_signal_delivered = false,
                timer_getoverrun_nonneg = false,
                timer_delete_rc_zero = false,
                timer_gettime_after_delete_fails = false,
            );
            return;
        }

        // Arm a one-shot 50ms timer. it_interval=0 → no auto-rearm.
        let spec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 },
        };
        let settime_rc = libc::timer_settime(id, 0, &spec, std::ptr::null_mut());
        report!(timer_settime_rc_zero = settime_rc == 0);

        // Read the remaining time before it has fired. Should be positive.
        let mut cur: libc::itimerspec = MaybeUninit::zeroed().assume_init();
        let gettime_rc = libc::timer_gettime(id, &mut cur);
        let remaining_positive = gettime_rc == 0
            && (cur.it_value.tv_sec > 0 || cur.it_value.tv_nsec > 0);
        report!(timer_gettime_remaining_is_positive = remaining_positive);

        // Check overrun query on a live timer — boolean is-nonneg only.
        let overrun = libc::timer_getoverrun(id);
        report!(timer_getoverrun_nonneg = overrun >= 0);

        // Spin until the signal lands or a generous wall-clock bound elapses.
        // A broken delivery path turns the boolean false rather than hanging.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if USR1_HITS.load(Ordering::SeqCst) >= 1 {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            // pause-friendly sleep; nanosleep would EINTR on delivery which is
            // exactly what we want.
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
        report!(timer_signal_delivered = USR1_HITS.load(Ordering::SeqCst) >= 1);

        // Delete it; a subsequent op on the same id must fail.
        let del_rc = libc::timer_delete(id);
        report!(timer_delete_rc_zero = del_rc == 0);

        let mut after: libc::itimerspec = MaybeUninit::zeroed().assume_init();
        let post_rc = libc::timer_gettime(id, &mut after);
        let post_errno = errno();
        // Linux returns EINVAL for an unknown timer_t.
        report!(
            timer_gettime_after_delete_fails = post_rc == -1 && post_errno == libc::EINVAL,
        );
    }
}
