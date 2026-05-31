//! Line-discipline control ioctl probe: TCSBRK / TCSBRKP / TCFLSH / TCXONC on
//! a pty slave (the tcdrain/tcsendbreak/tcflush/tcflow primitives that
//! CPython's `termios` module exercises in test_termios).
//!
//! Motivation: carrick handled TCGETS/TCSETS/winsize on pty fds but fell
//! through to the ENOTTY catch-all for the four flow-control ioctls, so
//! test_termios::{test_tcdrain,test_tcflow,test_tcflush,test_tcsendbreak} and
//! the *_errors variants ERROR'd/FAIL'd. The Linux↔Darwin trap is that the
//! TCFLSH queue selectors (TCIFLUSH=0/TCOFLUSH=1/TCIOFLUSH=2) and the TCXONC
//! action selectors (TCOOFF=0..TCION=3) are numbered DIFFERENTLY on Darwin
//! (Linux+1), so a passthrough that forwards the raw arg corrupts the queue.
//!
//! This probe issues the RAW ioctls (Linux request numbers + Linux selectors)
//! so it pins carrick's ioctl-ABI translation directly (not glibc's tc*
//! wrappers, which may pick a different request). It prints BOOLEANS only:
//!   - each valid (request, selector) on a pty slave returns rc==0
//!   - an out-of-range selector for TCFLSH/TCXONC returns -1/EINVAL
//!   - every request on a NON-tty fd (a pipe) returns -1/ENOTTY
//! On real Linux every line below is the value shown; carrick must match.

use std::ffi::CStr;

use conformance_probes::{errno, report};

// Linux line-discipline control ioctl request numbers. `libc::Ioctl` is the
// platform request type for ioctl(2) (i32 on linux-musl, u64 on glibc).
const TCSBRK: libc::Ioctl = 0x5409;
const TCXONC: libc::Ioctl = 0x540A;
const TCFLSH: libc::Ioctl = 0x540B;
const TCSBRKP: libc::Ioctl = 0x5425;

// Linux TCFLSH queue selectors.
const TCIFLUSH: libc::c_int = 0;
const TCOFLUSH: libc::c_int = 1;
const TCIOFLUSH: libc::c_int = 2;
// Linux TCXONC action selectors.
const TCOOFF: libc::c_int = 0;
const TCOON: libc::c_int = 1;
const TCIOFF: libc::c_int = 2;
const TCION: libc::c_int = 3;

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;

/// Issue `ioctl(fd, request, arg)` (arg as a scalar int, the line-discipline
/// convention) and return the raw rc.
unsafe fn ioc(fd: libc::c_int, request: libc::Ioctl, arg: libc::c_int) -> libc::c_int {
    libc::ioctl(fd, request, arg)
}

/// "ok" => rc==0; otherwise "errno:<n>".
fn classify(rc: libc::c_int) -> String {
    if rc == 0 {
        "ok".to_string()
    } else {
        format!("errno:{}", errno())
    }
}

fn main() {
    unsafe {
        // ── Open a pty pair (slave is a real tty). ──────────────────────────
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            report!(setup_ok = false);
            return;
        }
        let name_ptr = libc::ptsname(master);
        if name_ptr.is_null() {
            report!(setup_ok = false);
            return;
        }
        let name = CStr::from_ptr(name_ptr).to_owned();
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
        if slave < 0 {
            report!(setup_ok = false);
            return;
        }

        // A non-tty fd (pipe read end) for the ENOTTY arms.
        let mut pipefds = [0i32; 2];
        if libc::pipe(pipefds.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }
        let notty = pipefds[0];

        report!(setup_ok = true);

        // ── tcdrain / tcsendbreak (TCSBRK / TCSBRKP) ───────────────────────
        // TCSBRK with arg!=0 drains the output queue (tcdrain).
        report!(tcsbrk_drain = classify(ioc(slave, TCSBRK, 1)));
        // TCSBRK with arg==0 sends a break (tcsendbreak duration 0).
        report!(tcsbrk_break = classify(ioc(slave, TCSBRK, 0)));
        // TCSBRKP with arg!=0 sends a break for `arg` deciseconds.
        report!(tcsbrkp_break = classify(ioc(slave, TCSBRKP, 1)));

        // ── tcflush (TCFLSH) ────────────────────────────────────────────────
        report!(tcflsh_iflush = classify(ioc(slave, TCFLSH, TCIFLUSH)));
        report!(tcflsh_oflush = classify(ioc(slave, TCFLSH, TCOFLUSH)));
        report!(tcflsh_ioflush = classify(ioc(slave, TCFLSH, TCIOFLUSH)));
        // Out-of-range queue selector → EINVAL.
        report!(tcflsh_badsel = classify(ioc(slave, TCFLSH, -1)));

        // ── tcflow (TCXONC) ─────────────────────────────────────────────────
        report!(tcxonc_ooff = classify(ioc(slave, TCXONC, TCOOFF)));
        report!(tcxonc_oon = classify(ioc(slave, TCXONC, TCOON)));
        report!(tcxonc_ioff = classify(ioc(slave, TCXONC, TCIOFF)));
        report!(tcxonc_ion = classify(ioc(slave, TCXONC, TCION)));
        // Out-of-range action selector → EINVAL.
        report!(tcxonc_badsel = classify(ioc(slave, TCXONC, -1)));

        // ── Non-tty fd → ENOTTY for every flow-control request. ─────────────
        report!(notty_tcsbrk = classify(ioc(notty, TCSBRK, 1)));
        report!(notty_tcflsh = classify(ioc(notty, TCFLSH, TCIFLUSH)));
        report!(notty_tcxonc = classify(ioc(notty, TCXONC, TCOON)));

        // ── Booleans: errno values match the Linux contract exactly. ────────
        // (Re-derive without printing raw errno so the lines above already
        //  carry the verdict; these are explicit relationship assertions.)
        let badsel_flsh = ioc(slave, TCFLSH, -1);
        report!(tcflsh_badsel_is_einval = (badsel_flsh < 0 && errno() == EINVAL));
        let badsel_xonc = ioc(slave, TCXONC, -1);
        report!(tcxonc_badsel_is_einval = (badsel_xonc < 0 && errno() == EINVAL));
        let nt = ioc(notty, TCSBRK, 1);
        report!(notty_is_enotty = (nt < 0 && errno() == ENOTTY));

        libc::close(slave);
        libc::close(master);
        libc::close(pipefds[0]);
        libc::close(pipefds[1]);
    }
}
