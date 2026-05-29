//! FIONREAD on a pty SLAVE must SUCCEED (rc==0) and report a positive count of
//! bytes queued in the line-discipline input buffer — NOT fail with ENOTTY.
//!
//! carrick's ioctl dispatch (crates/carrick-runtime/src/dispatch/fs.rs ~2073)
//! handles a pty fd in a dedicated early-`return` match
//! (`if let Some((role, host_fd)) = this.pty_info(fd.0) { return Ok(match ...) }`)
//! whose arms are TIOC{GPTN,SPTLCK} / TC{GETS,SETS,SETSW,SETSF} /
//! TIOC{GWINSZ,SWINSZ,GPGRP,SPGRP,SCTTY}. FIONREAD is NOT among them, so a pty
//! fd falls into that block's catch-all `_ => ENOTTY` (~2172). The general
//! FIONREAD handler (which forwards to the backing host fd for HostPipe/
//! HostSocket) lives AFTER this early return (~2292), so it is unreachable for
//! pty fds. A macOS pts slave supports FIONREAD/TIOCINQ on its input queue, so
//! once the pty block forwards FIONREAD to the host slave fd, carrick matches
//! Linux.
//!
//! Probe path: posix_openpt -> grantpt -> unlockpt -> ptsname -> open slave —
//! the exact path ptypair/termiosbits already exercise (both pass under carrick
//! --fs host + Docker linux/arm64 as aarch64-musl static ELFs), which carrick
//! routes through devpts + a real macOS pty (HostPipe tagged `pty: Some(role)`,
//! so `pty_info` returns Some). The slave is put in raw mode (ICANON/ECHO
//! cleared) so the master payload reaches the slave input queue byte-for-byte
//! with no canonical/echo processing.
//!
//! DETERMINISM: the raw FIONREAD count is intentionally NEVER printed, because
//! the tty flip buffer may chunk delivery so the count at the poll moment
//! differs run-to-run / platform-to-platform. Only booleans are emitted:
//!   - fionread_rc_zero  : ioctl succeeded (the BUG flips this to false/ENOTTY)
//!   - fionread_positive : count > 0 once POLLIN is signalled (true on Linux &
//!                         on any pts; never asserts an exact value)
//!   - drain_matches     : a SELF-CONSISTENCY check — read exactly the reported
//!                         count and confirm `read` returns that many bytes.
//!                         Deterministic on BOTH platforms regardless of how
//!                         the flip buffer chunked delivery.
//! Bounded: one capped poll loop (<=2s total), one drain read, no fork/waitpid;
//! cannot hang. Any setup failure prints a single `setup_ok=false` and returns.
//!
//! Buggy carrick: setup_ok=true, ..., fionread_rc_zero=false,
//!                fionread_positive=false, drain_matches=false (ENOTTY).
//! Linux + fixed: setup_ok=true, ..., fionread_rc_zero=true,
//!                fionread_positive=true, drain_matches=true.

use std::ffi::CStr;

use conformance_probes::{errno, report};

const PAYLOAD: &[u8] = b"abcdefghij"; // 10 bytes, no NL (raw mode: passes 1:1)

fn main() {
    unsafe {
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

        // Raw mode: clear ICANON/ECHO so the master payload reaches the slave
        // input queue byte-for-byte (no line buffering, no echo to master).
        let mut tio: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(slave, &mut tio) != 0 {
            report!(setup_ok = false);
            return;
        }
        tio.c_lflag &= !((libc::ICANON | libc::ECHO) as libc::tcflag_t);
        if libc::tcsetattr(slave, libc::TCSANOW, &tio) != 0 {
            report!(setup_ok = false);
            return;
        }

        // Master -> slave.
        let w = libc::write(
            master,
            PAYLOAD.as_ptr() as *const libc::c_void,
            PAYLOAD.len(),
        );
        if w != PAYLOAD.len() as isize {
            report!(setup_ok = false);
            return;
        }

        // Bounded wait for the line discipline to make bytes readable on the
        // slave. Caps total wait so the probe can never hang.
        let mut pfd = libc::pollfd {
            fd: slave,
            events: libc::POLLIN,
            revents: 0,
        };
        let mut readable = false;
        for _ in 0..20 {
            let pr = libc::poll(&mut pfd, 1, 100); // 100ms each, <=2s total
            if pr > 0 && (pfd.revents & libc::POLLIN) != 0 {
                readable = true;
                break;
            }
            if pr < 0 && errno() == libc::EINTR {
                continue;
            }
        }

        // FIONREAD on the slave: the bug makes this fail (ENOTTY) under carrick.
        let mut n: libc::c_int = 0;
        let rc = libc::ioctl(slave, libc::FIONREAD, &mut n as *mut libc::c_int);
        let fionread_rc_zero = rc == 0;
        let fionread_positive = fionread_rc_zero && n > 0;

        // Self-consistency: drain exactly `n` bytes (capped at the payload size
        // so a buggy huge count can never trigger a giant allocation) and confirm
        // `read` returns that many. A correct FIONREAD count matches the bytes
        // actually readable, deterministic on both platforms. Skipped (false)
        // when FIONREAD failed so the bug shows as drain_matches=false too.
        let drain_matches = if fionread_positive {
            let want = (n as usize).min(PAYLOAD.len());
            let mut buf = vec![0u8; want];
            let got = libc::read(slave, buf.as_mut_ptr() as *mut libc::c_void, want);
            got == want as isize
        } else {
            false
        };

        report!(
            setup_ok = true,
            slave_isatty = libc::isatty(slave) == 1,
            poll_readable = readable,
            // Linux + fixed carrick: true. Buggy carrick: false (ENOTTY).
            fionread_rc_zero = fionread_rc_zero,
            fionread_positive = fionread_positive,
            drain_matches = drain_matches,
        );

        libc::close(slave);
        libc::close(master);
    }
}