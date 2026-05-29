//! setpriority/getpriority nice-value model (LTP nice02/nice03). carrick had a
//! stateless model: setpriority returned 0 without storing and getpriority
//! always reported nice 0, and an out-of-range nice was rejected EINVAL instead
//! of clamped. Fixed: a persisted per-process nice, clamped to [-20,19], that
//! getpriority reflects. libc getpriority() returns the nice directly (the
//! kernel's `20 - nice` is converted back by the wrapper).
//!
//! The nice04 "non-root nice-lowering → EPERM" leg is NOT probed here: the
//! probe runs privileged (root in docker / guest-root under run-elf), so the
//! lowering succeeds on both sides. LTP nice04 (which drops to nobody) gates it.

use conformance_probes::errno;

fn main() {
    unsafe {
        // set nice 2 → getpriority reports 2.
        let s2 = libc::setpriority(libc::PRIO_PROCESS, 0, 2);
        println!("set_nice_2_ok={}", s2 == 0);
        *libc::__errno_location() = 0;
        println!(
            "get_nice_is_2={}",
            libc::getpriority(libc::PRIO_PROCESS, 0) == 2 && errno() == 0
        );

        // nice 50 is out of range → Linux CLAMPS to 19 and succeeds (no EINVAL).
        let s50 = libc::setpriority(libc::PRIO_PROCESS, 0, 50);
        println!("set_nice_50_ok={}", s50 == 0);
        *libc::__errno_location() = 0;
        println!(
            "get_nice_clamped_19={}",
            libc::getpriority(libc::PRIO_PROCESS, 0) == 19 && errno() == 0
        );

        // getpriority with an invalid `which` → EINVAL.
        *libc::__errno_location() = 0;
        let bad = libc::getpriority(99, 0);
        println!("getpriority_bad_which_einval={}", bad == -1 && errno() == libc::EINVAL);

        let _ = errno;
    }
}
