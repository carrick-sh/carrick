//! select()/pselect6 must be interruptible by a signal: a pending unblocked
//! signal makes a blocking select return -1/EINTR. carrick's all-host fast path
//! calls a blocking libc::poll directly (dispatch/net.rs:1494) with no
//! signal-wake fd, so a guest SIGALRM never interrupts it (asymmetric with
//! ppoll, which hands off to the signal-interruptible WaitOnFds waiter).
//!
//! Linux: select returns EINTR ~500ms after the alarm. carrick: select never
//! returns -> the probe hangs -> the harness timeout fires -> DIFF (Linux emits
//! three lines, carrick emits none). Run via the threaded path (run-probe.sh).

use conformance_probes::{arm_alarm_ms, errno, install_handler, report};

extern "C" fn on_alarm(_: i32) {}

fn main() {
    unsafe {
        let mut sv = [0i32; 2];
        // socketpair -> both fds host-backed (HostSocket) -> all-host fast path.
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            report!(setup_ok = false);
            return;
        }
        // SIGALRM handler WITHOUT SA_RESTART so select returns EINTR (not restart).
        install_handler(libc::SIGALRM, on_alarm, 0);
        arm_alarm_ms(500);

        let mut rset: libc::fd_set = core::mem::zeroed();
        libc::FD_ZERO(&mut rset);
        libc::FD_SET(sv[0], &mut rset);
        // No data ever arrives, so only the SIGALRM can wake this select.
        let r = libc::select(
            sv[0] + 1,
            &mut rset,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let e = errno();
        report!(
            select_returned = true,
            select_rc_negative = r < 0,
            select_eintr = r < 0 && e == libc::EINTR,
        );
    }
}
