//! `prctl(PR_SET_DUMPABLE / PR_GET_DUMPABLE)` round-trip. The dumpable flag
//! gates core-dump generation, `/proc/self/{mem,maps,...}` access, and the
//! `ptrace(PTRACE_ATTACH)` permission check; setuid programs clear it on
//! exec. LTP `prctl04` / `prctl08` exercise the value transitions. The
//! existing `sysinfo` probe lists "prctl01–08" but doesn't actually round-
//! trip dumpable through its tri-state — this probe pins the values down.
//!
//! Invariants encoded:
//!   - Initial PR_GET_DUMPABLE returns 1 (default for a forked process not
//!     setuid-exec'd).
//!   - PR_SET_DUMPABLE(0) → PR_GET_DUMPABLE returns 0 ("not dumpable").
//!   - PR_SET_DUMPABLE(1) → PR_GET_DUMPABLE returns 1 ("dumpable").
//!   - PR_SET_DUMPABLE(2) → PR_GET_DUMPABLE returns 2 on Linux (the
//!     "suidsafe" state — kept distinct from 1 for ptrace heuristics) OR
//!     EINVAL on a kernel that rejects the value. The probe treats either
//!     outcome as conforming as long as both sides agree.
//!   - PR_SET_DUMPABLE(99) (invalid) → -1/EINVAL.

use conformance_probes::{errno, report};

const PR_SET_DUMPABLE: libc::c_int = 4;
const PR_GET_DUMPABLE: libc::c_int = 3;

unsafe fn set_dumpable(v: libc::c_long) -> (i32, i32) {
    let rc = libc::prctl(PR_SET_DUMPABLE, v, 0, 0, 0);
    let er = if rc == -1 { errno() } else { 0 };
    (rc, er)
}

unsafe fn get_dumpable() -> i32 {
    libc::prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
}

fn main() {
    unsafe {
        // Initial state — Linux default for a non-suid binary is 1 (dumpable).
        let initial = get_dumpable();
        report!(prctl_initial_dumpable_is_one = initial == 1);

        // Transition: 1 → 0.
        let (rc_to_0, _) = set_dumpable(0);
        let after_0 = get_dumpable();
        report!(
            prctl_set_zero_ok = rc_to_0 == 0,
            prctl_get_after_zero_is_zero = after_0 == 0,
        );

        // Transition: 0 → 1.
        let (rc_to_1, _) = set_dumpable(1);
        let after_1 = get_dumpable();
        report!(
            prctl_set_one_ok = rc_to_1 == 0,
            prctl_get_after_one_is_one = after_1 == 1,
        );

        // Transition: 1 → 2 ("suidsafe"). Linux accepts it; the GET returns 2.
        let (rc_to_2, er_to_2) = set_dumpable(2);
        let after_2 = get_dumpable();
        // Either both sides accept it (rc=0, GET=2) or both reject (rc=-1, EINVAL).
        // The probe diffs the OBSERVED tuple — agreement on EITHER outcome means
        // carrick matches Linux semantics; only a SPLIT (carrick rejects, Linux
        // accepts or vice versa) is a real bug.
        report!(
            prctl_set_two_rc = rc_to_2,
            prctl_set_two_errno = er_to_2,
            prctl_get_after_two = after_2,
        );

        // Invalid value rejection.
        let (rc_bad, er_bad) = set_dumpable(99);
        report!(
            prctl_set_invalid_rc_is_neg_one = rc_bad == -1,
            prctl_set_invalid_errno_is_einval = er_bad == libc::EINVAL,
        );
    }
}
