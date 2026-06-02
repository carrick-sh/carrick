//! `prctl` set/get round-trips for the common sandboxing/init options that
//! carrick previously rejected with EINVAL (audit H1): PR_SET_NO_NEW_PRIVS,
//! PR_SET_KEEPCAPS, PR_SET_CHILD_SUBREAPER, PR_SET_TIMERSLACK. PR_SET_NO_NEW_PRIVS
//! in particular is the precondition for an unprivileged seccomp filter install
//! (Docker/systemd/Go/Chrome), so a wrong errno here breaks real workloads.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - PR_GET_NO_NEW_PRIVS starts 0; PR_SET_NO_NEW_PRIVS(1) → 0; GET → 1.
//!   - PR_SET_NO_NEW_PRIVS with a bad arg (arg2 != 1, or arg3 nonzero) → EINVAL.
//!   - PR_GET_KEEPCAPS starts 0; PR_SET_KEEPCAPS(1) → 0; GET → 1; SET(2) → EINVAL.
//!   - PR_SET_CHILD_SUBREAPER(1) → 0; PR_GET_CHILD_SUBREAPER writes 1 to *arg2.
//!   - PR_GET_TIMERSLACK is the default 50000; PR_SET_TIMERSLACK(120000) → 0;
//!     GET → 120000; SET(0) resets to the 50000 default.

use conformance_probes::{errno, report};

const PR_SET_KEEPCAPS: libc::c_int = 8;
const PR_GET_KEEPCAPS: libc::c_int = 7;
const PR_SET_TIMERSLACK: libc::c_int = 29;
const PR_GET_TIMERSLACK: libc::c_int = 30;
const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
const PR_GET_CHILD_SUBREAPER: libc::c_int = 37;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;

fn main() {
    unsafe {
        // NO_NEW_PRIVS: 0 → set 1 → 1 (one-way latch).
        report!(nnp_initial_zero = libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
        report!(nnp_set_ok = libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        report!(nnp_now_one = libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
        // Bad arg → EINVAL (arg3 nonzero).
        let bad = libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 7, 0, 0);
        report!(nnp_bad_arg_einval = bad == -1 && errno() == libc::EINVAL);

        // KEEPCAPS: 0 → set 1 → 1; SET(2) → EINVAL.
        report!(keepcaps_initial_zero = libc::prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0);
        report!(keepcaps_set_ok = libc::prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
        report!(keepcaps_now_one = libc::prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1);
        let kc_bad = libc::prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0);
        report!(keepcaps_two_einval = kc_bad == -1 && errno() == libc::EINVAL);

        // CHILD_SUBREAPER: set 1, then GET writes the value to *arg2.
        report!(subreaper_set_ok = libc::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
        let mut out: libc::c_int = -1;
        let gr = libc::prctl(
            PR_GET_CHILD_SUBREAPER,
            &mut out as *mut libc::c_int as libc::c_ulong,
            0,
            0,
            0,
        );
        report!(subreaper_get_ok = gr == 0);
        report!(subreaper_value_one = out == 1);

        // TIMERSLACK: default 50000 → set 120000 → 120000 → reset(0) → 50000.
        report!(timerslack_default_50000 = libc::prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);
        report!(timerslack_set_ok = libc::prctl(PR_SET_TIMERSLACK, 120000, 0, 0, 0) == 0);
        report!(timerslack_now_120000 = libc::prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 120000);
        report!(timerslack_reset_ok = libc::prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0);
        report!(timerslack_back_to_default = libc::prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);
    }
}
