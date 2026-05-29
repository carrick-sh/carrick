//! `timer_settime` ABI fidelity on two axes the existing `posixtimers` probe
//! does not exercise:
//!
//!   1. timespec VALIDATION: `it_value.tv_nsec >= 1_000_000_000`, a negative
//!      tv_nsec, and a negative tv_sec must each make `timer_settime` fail with
//!      EINVAL. carrick today funnels the spec through saturating arithmetic
//!      (`saturating_mul` + `u64::try_from(...).unwrap_or(0)` in
//!      dispatch/time.rs:387-394) so an out-of-range tv_nsec is silently
//!      clamped and the call (wrongly) succeeds.
//!
//!   2. TIMER_ABSTIME semantics: an absolute deadline already in the PAST must
//!      fire essentially immediately. carrick currently drops the flag
//!      (`_flags` is unused, dispatch/time.rs:374) and treats every it_value as
//!      a RELATIVE duration. We pass an absolute deadline equal to "now on
//!      CLOCK_MONOTONIC" (a large monotonic value). Correct ABSTIME handling
//!      sees a now/past deadline and fires at once; the broken relative
//!      interpretation sleeps ~uptime-seconds and never fires inside the bound.
//!      That asymmetry is what makes this boolean DISCRIMINATING: a `{0,small}`
//!      deadline would fire under BOTH the buggy (relative) and fixed (absolute)
//!      paths and prove nothing, so we deliberately use the large "now" value.
//!
//! We read `now` with clock_gettime and feed it back UNCHANGED as the absolute
//! it_value (no subtraction) so there is no risk of integer underflow on a
//! low-uptime host: monotonic only moves forward, so by the time the kernel
//! evaluates the deadline `now_at_arm >= now_read`, i.e. the deadline is at or
//! before the current instant and must fire immediately.
//!
//! Deterministic only: we never print remaining-ns, ids, addresses, or counts —
//! only EINVAL booleans and a bounded "the abstime-past arm delivered its
//! signal" boolean (the wait is bounded by a wall-clock deadline so a broken
//! delivery turns the boolean false rather than hanging).
//!
//! Linux + fixed carrick MATCH on every line below.

use conformance_probes::{errno, install_handler, report};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static USR1_HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr1(_: i32) {
    USR1_HITS.fetch_add(1, Ordering::SeqCst);
}

// TIMER_ABSTIME = 1 on every Linux arch; spell it locally so the probe does not
// depend on the libc-crate const name.
const TIMER_ABSTIME: libc::c_int = 1;

unsafe fn make_timer() -> Option<libc::timer_t> {
    let mut sev: libc::sigevent = MaybeUninit::zeroed().assume_init();
    sev.sigev_notify = libc::SIGEV_SIGNAL;
    sev.sigev_signo = libc::SIGUSR1;
    let mut id: libc::timer_t = std::ptr::null_mut();
    if libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut id) == 0 {
        Some(id)
    } else {
        None
    }
}

fn main() {
    unsafe {
        let _ = install_handler(libc::SIGUSR1, on_usr1, libc::SA_RESTART);
        USR1_HITS.store(0, Ordering::SeqCst);

        let Some(id) = make_timer() else {
            // Without a timer we cannot run anything; emit the stable shape so the
            // diff has the same lines under a timer-less runtime.
            report!(
                create_ok = false,
                nsec_too_big_einval = false,
                nsec_negative_einval = false,
                sec_negative_einval = false,
                valid_arm_ok = false,
                abstime_past_delivered = false,
            );
            return;
        };
        report!(create_ok = true);

        // (1a) it_value.tv_nsec >= 1e9 -> EINVAL, and the call must NOT succeed.
        let bad_nsec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 2_000_000_000 },
        };
        let rc = libc::timer_settime(id, 0, &bad_nsec, std::ptr::null_mut());
        report!(nsec_too_big_einval = rc == -1 && errno() == libc::EINVAL);

        // (1b) negative tv_nsec -> EINVAL.
        let neg_nsec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: -1 },
        };
        let rc = libc::timer_settime(id, 0, &neg_nsec, std::ptr::null_mut());
        report!(nsec_negative_einval = rc == -1 && errno() == libc::EINVAL);

        // (1c) negative tv_sec -> EINVAL.
        let neg_sec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: -1, tv_nsec: 0 },
        };
        let rc = libc::timer_settime(id, 0, &neg_sec, std::ptr::null_mut());
        report!(sec_negative_einval = rc == -1 && errno() == libc::EINVAL);

        // A well-formed relative arm must still succeed (regression guard so the
        // validation does not over-reject). This re-arms the SAME id; the next
        // abstime arm overwrites it, and the generation bump in posix_timer::arm
        // retires this 50ms thread, so it cannot leak a spurious SIGUSR1.
        let good = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 },
        };
        report!(valid_arm_ok = libc::timer_settime(id, 0, &good, std::ptr::null_mut()) == 0);

        // (2) TIMER_ABSTIME with a deadline == "now on CLOCK_MONOTONIC" (a large
        // monotonic value). Correct ABSTIME: now/past -> fires immediately.
        // Broken relative interpretation: ~uptime-seconds sleep -> never fires
        // in the bound. No subtraction -> no underflow on a low-uptime host.
        USR1_HITS.store(0, Ordering::SeqCst);
        let mut now: libc::timespec = MaybeUninit::zeroed().assume_init();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
        let past = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: now.tv_sec, tv_nsec: now.tv_nsec },
        };
        let _ = libc::timer_settime(id, TIMER_ABSTIME, &past, std::ptr::null_mut());

        // Bounded wait: a broken path makes this false, never hangs.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if USR1_HITS.load(Ordering::SeqCst) >= 1 || Instant::now() >= deadline {
                break;
            }
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
        report!(abstime_past_delivered = USR1_HITS.load(Ordering::SeqCst) >= 1);

        let _ = libc::timer_delete(id);
    }
}