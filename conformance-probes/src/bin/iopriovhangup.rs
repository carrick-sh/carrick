//! ioprio_set/ioprio_get + vhangup — previously ENOSYS. carrick has no real
//! I/O scheduler or controlling tty, so ioprio stores a per-process value
//! echoed by get (validating class/level per the kernel), and vhangup is a
//! privilege-gated no-op. Stands in for LTP ioprio_set02/03, ioprio_get01,
//! vhangup01.
//!
//! Invariants (deterministic):
//!   1. ioprio_set(PROCESS, 0, BE/4) → 0; ioprio_get → that value back.
//!   2. CLASS_NONE with level 0 → 0 (reset to default); with non-zero → EINVAL.
//!   3. bad `which` → EINVAL.
//!
//! NOTE: several edges are deliberately NOT asserted because the Docker oracle
//! doesn't agree (and carrick matches modern Linux, not the LinuxKit VM):
//! RT-class needs CAP_SYS_ADMIN (Docker → EPERM before any level check);
//! BE/IDLE level>=8 is EINVAL on modern Linux (IOPRIO_NR_LEVELS=8) but the
//! Docker kernel accepts it; vhangup-success needs a controlling tty Docker's
//! container lacks. vhangup's privilege gate is covered by LTP vhangup01
//! (non-root → EPERM); the level/RT edges by LTP ioprio_set02/03.

use conformance_probes::{errno, report};

const WHO_PROCESS: i64 = 1;
const CLASS_RT: u32 = 1;
const CLASS_BE: u32 = 2;
const CLASS_NONE: u32 = 0;
fn prio(class: u32, level: u32) -> i64 {
    (((class << 13) | level) as i64)
}

unsafe fn ioprio_set(which: i64, who: i64, ioprio: i64) -> i64 {
    libc::syscall(libc::SYS_ioprio_set, which, who, ioprio)
}
unsafe fn ioprio_get(which: i64, who: i64) -> i64 {
    libc::syscall(libc::SYS_ioprio_get, which, who)
}

fn main() {
    unsafe {
        // (1) set BE/4, get it back.
        let s = ioprio_set(WHO_PROCESS, 0, prio(CLASS_BE, 4));
        let g = ioprio_get(WHO_PROCESS, 0);
        report!(
            set_be4_ok = s == 0,
            get_returns_be4 = g == prio(CLASS_BE, 4),
        );

        // (2) CLASS_NONE level 0 ok; level 5 → EINVAL.
        let none0 = ioprio_set(WHO_PROCESS, 0, prio(CLASS_NONE, 0));
        let none5 = ioprio_set(WHO_PROCESS, 0, prio(CLASS_NONE, 5));
        let none5_e = if none5 < 0 { errno() } else { 0 };
        report!(
            none_level0_ok = none0 == 0,
            none_nonzero_einval = none5 == -1 && none5_e == libc::EINVAL,
        );

        // (3) bad `which` → EINVAL (oracle-agreed; no privilege/level edge).
        let badwhich = ioprio_set(99, 0, prio(CLASS_BE, 0));
        let badwhich_e = if badwhich < 0 { errno() } else { 0 };
        report!(bad_which_einval = badwhich == -1 && badwhich_e == libc::EINVAL);
        let _ = CLASS_RT;
    }
}
