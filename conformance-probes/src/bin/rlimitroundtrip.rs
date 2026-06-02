//! `setrlimit`/`getrlimit` per-resource round-trip (audit H2): a value set for a
//! resource OTHER than RLIMIT_NOFILE must read back — carrick previously honored
//! only NOFILE and reported a hardcoded default for everything else, so a
//! `setrlimit` "succeeded" but the matching `getrlimit` lied.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - setrlimit(RLIMIT_CORE, {soft, hard}) then getrlimit returns the same pair.
//!   - setrlimit(RLIMIT_STACK, {soft, prior_hard}) then getrlimit's soft matches.
//!   - Resources are independent: setting CORE does not perturb STACK.
//!   - rlim_cur > rlim_max is rejected with EINVAL.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // RLIMIT_CORE is freely settable and harmless — set a distinctive pair.
        let core_in = libc::rlimit {
            rlim_cur: 12345,
            rlim_max: 67890,
        };
        report!(core_set_ok = libc::setrlimit(libc::RLIMIT_CORE, &core_in) == 0);
        let mut core = zero;
        libc::getrlimit(libc::RLIMIT_CORE, &mut core);
        report!(core_cur_roundtrips = core.rlim_cur == 12345);
        report!(core_max_roundtrips = core.rlim_max == 67890);

        // RLIMIT_STACK: lower the SOFT limit (does not affect the running stack)
        // to 64 MiB, keeping the prior hard limit; the soft must read back.
        let mut stack0 = zero;
        libc::getrlimit(libc::RLIMIT_STACK, &mut stack0);
        let stack_in = libc::rlimit {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: stack0.rlim_max,
        };
        report!(stack_set_ok = libc::setrlimit(libc::RLIMIT_STACK, &stack_in) == 0);
        let mut stack = zero;
        libc::getrlimit(libc::RLIMIT_STACK, &mut stack);
        report!(stack_soft_roundtrips = stack.rlim_cur == 64 * 1024 * 1024);

        // Independence: setting STACK did not change CORE.
        let mut core2 = zero;
        libc::getrlimit(libc::RLIMIT_CORE, &mut core2);
        report!(core_unchanged_by_stack = core2.rlim_cur == 12345 && core2.rlim_max == 67890);

        // rlim_cur > rlim_max → EINVAL.
        let bad = libc::rlimit {
            rlim_cur: 100,
            rlim_max: 50,
        };
        let rc = libc::setrlimit(libc::RLIMIT_CORE, &bad);
        report!(core_cur_gt_max_einval = rc == -1 && errno() == libc::EINVAL);
    }
}
