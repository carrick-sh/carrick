//! End-to-end smoke tests for `carrick run -t` (interactive pty). Drive the
//! built binary over a real pty and prove the guest gets a fully working
//! terminal: live line discipline (echo), a resolvable tty name (`tty(1)` →
//! `/dev/pts/N`), a working `/dev/tty`, and live window-resize propagation.
//!
//! `#[ignore]` by default: needs a SIGNED release binary (HVF entitlement) +
//! the debian image + Docker, and is timing-based. Run explicitly:
//!   ./scripts/build-signed.sh
//!   cargo test --test interactive_tty -- --ignored --nocapture
//
// Test code: helpers are plain `fn`s (not `#[test]`), so clippy's
// allow-unwrap-in-tests heuristic doesn't exempt them. The no-panic gate
// targets production code, so allow unwrap/expect across this test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::io::FromRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the SIGNED release binary, or `None` (with a SKIP message) if it's
/// missing or unsigned. HVF needs `com.apple.security.hypervisor`, present only
/// on the build-signed.sh output; the unsigned debug binary fails HV_DENIED.
fn signed_bin() -> Option<&'static str> {
    let bin = concat!(env!("CARGO_MANIFEST_DIR"), "/target/release/carrick");
    if !std::path::Path::new(bin).exists() {
        eprintln!("SKIP: {bin} not found — run ./scripts/build-signed.sh first");
        return None;
    }
    let signed = Command::new("codesign")
        .args(["-d", "--entitlements", "-", bin])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains("hypervisor")
                || String::from_utf8_lossy(&o.stderr).contains("hypervisor")
        })
        .unwrap_or(false);
    if !signed {
        eprintln!(
            "SKIP: {bin} not signed with the hypervisor entitlement — run ./scripts/build-signed.sh"
        );
        return None;
    }
    Some(bin)
}

/// Allocate a host pty (master, slave_fd) for driving carrick.
fn open_pty() -> (i32, i32) {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    unsafe {
        libc::grantpt(master);
        libc::unlockpt(master);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(master)) }.to_owned();
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
    assert!(slave >= 0, "open slave");
    (master, slave)
}

fn set_nonblocking(fd: i32) {
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
}

fn set_winsize(master: i32, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(master, libc::TIOCSWINSZ, &ws);
    }
}

/// Spawn `carrick run -t … <guest-args>` with `slave` as the child's stdio.
fn spawn_run_t(bin: &str, slave: i32, guest_args: &[&str]) -> std::process::Child {
    spawn_run_t_image(bin, slave, "docker.io/library/debian:stable", guest_args)
}

fn spawn_run_t_image(
    bin: &str,
    slave: i32,
    image: &str,
    guest_args: &[&str],
) -> std::process::Child {
    let dup_out = unsafe { libc::dup(slave) };
    let mut args = vec!["run", "-t", "--fs", "host", image];
    args.extend_from_slice(guest_args);
    Command::new(bin)
        .args(&args)
        .stdin(unsafe { Stdio::from_raw_fd(slave) })
        .stdout(unsafe { Stdio::from_raw_fd(dup_out) })
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn carrick")
}

/// Read from `master` into `out` (appending) until `done(&out)` is true or the
/// deadline passes. Accumulating into a caller-owned buffer lets multi-phase
/// reads (e.g. read-then-resize-then-read) keep all earlier output.
fn read_until(master: i32, out: &mut Vec<u8>, secs: u64, done: impl Fn(&[u8]) -> bool) {
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            if done(out) {
                break;
            }
        } else {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
#[ignore]
fn interactive_run_provides_a_working_pty() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    // /bin/cat: the pty line discipline echoes typed input; cat echoes it
    // again. A real tty under -t => the marker appears at least twice.
    let mut child = spawn_run_t(bin, slave, &["/bin/cat"]);
    set_nonblocking(master);

    std::thread::sleep(Duration::from_secs(20)); // boot
    let marker = b"carricktty7\n";
    unsafe {
        libc::write(master, marker.as_ptr().cast(), marker.len());
    }
    let mut out = Vec::new();
    read_until(master, &mut out, 10, |o| {
        o.windows(11).filter(|w| *w == b"carricktty7").count() >= 2
    });
    unsafe {
        libc::write(master, b"\x04".as_ptr().cast(), 1); // Ctrl-D
    }
    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    let hits = text.matches("carricktty7").count();
    assert!(
        hits >= 2,
        "expected the marker echoed by the pty line discipline AND by cat (>=2). Output:\n{text}"
    );
}

#[test]
#[ignore]
fn interactive_ctrl_c_interrupts_foreground_command() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    let mut child = spawn_run_t(bin, slave, &["/bin/sh"]);
    set_nonblocking(master);

    std::thread::sleep(Duration::from_secs(20)); // boot
    // Start a long sleep, then send Ctrl-C (0x03). The pty line discipline must
    // turn it into SIGINT for the foreground process group, killing the sleep.
    let w = |b: &[u8]| unsafe {
        libc::write(master, b.as_ptr().cast(), b.len());
    };
    w(b"sleep 40\n");
    std::thread::sleep(Duration::from_secs(1));
    w(b"\x03"); // Ctrl-C
    std::thread::sleep(Duration::from_secs(1));
    // Probe with COMPUTED output: the line discipline echoes the typed bytes
    // "echo B$((20+22))" but only an executing shell prints "B42". If Ctrl-C
    // failed, the shell is still blocked in `sleep 40` and B42 never appears
    // within the deadline.
    w(b"echo B$((20+22))\n");
    let mut out = Vec::new();
    read_until(master, &mut out, 8, |o| o.windows(3).any(|x| x == b"B42"));

    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("GUEST ABORT") && !text.contains("panicked"),
        "Ctrl-C must not crash a guest process. Output:\n{text}"
    );
    assert!(
        text.contains("B42"),
        "Ctrl-C should interrupt `sleep 40` so the shell runs the next command \
         (expected computed output B42). Output:\n{text}"
    );
}

#[test]
#[ignore]
fn interactive_ctrl_z_fg_and_ctrl_c_job_control() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    let mut child = spawn_run_t(bin, slave, &["/bin/bash"]);
    set_nonblocking(master);

    std::thread::sleep(Duration::from_secs(20)); // boot
    let w = |b: &[u8]| unsafe {
        libc::write(master, b.as_ptr().cast(), b.len());
    };

    // Start a foreground job, stop it with Ctrl-Z, and prove the shell regains
    // control by running a computed marker. The literal command echo is not
    // enough; only an executing shell prints Z42.
    w(b"sleep 40\n");
    std::thread::sleep(Duration::from_secs(1));
    w(b"\x1a"); // Ctrl-Z
    std::thread::sleep(Duration::from_secs(1));
    w(b"jobs\n");
    w(b"echo Z$((20+22))\n");

    let mut out = Vec::new();
    read_until(master, &mut out, 10, |o| o.windows(3).any(|x| x == b"Z42"));

    // Resume the stopped job in the foreground, interrupt it with Ctrl-C, and
    // prove the shell is usable again.
    w(b"fg\n");
    std::thread::sleep(Duration::from_secs(1));
    w(b"\x03"); // Ctrl-C
    std::thread::sleep(Duration::from_secs(1));
    w(b"echo F$((30+12))\n");
    read_until(master, &mut out, 10, |o| o.windows(3).any(|x| x == b"F42"));

    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("GUEST ABORT") && !text.contains("panicked"),
        "job control must not crash carrick. Output:\n{text}"
    );
    assert!(
        text.contains("Z42"),
        "Ctrl-Z should stop `sleep 40` and return control to the shell. Output:\n{text}"
    );
    assert!(
        text.contains("F42"),
        "`fg` followed by Ctrl-C should return control to the shell. Output:\n{text}"
    );
    assert!(
        text.contains("Stopped") || text.contains("sleep 40"),
        "`jobs` should report the stopped foreground job. Output:\n{text}"
    );
}

#[test]
#[ignore]
fn interactive_forked_foreground_job_keeps_stdout_alive() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    let script = "(echo hi | cat); ls /bin/sh >/dev/null; echo OK";
    let mut child = spawn_run_t(bin, slave, &["/bin/sh", "-c", script]);
    set_nonblocking(master);

    let mut out = Vec::new();
    read_until(master, &mut out, 30, |o| o.windows(2).any(|x| x == b"OK"));

    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("hi") && text.contains("OK"),
        "forked foreground command should preserve stdout through pipes. Output:\n{text}"
    );
    assert!(
        !text.contains("EPIPE")
            && !text.contains("Broken pipe")
            && !text.contains("GUEST ABORT")
            && !text.contains("panicked"),
        "forked foreground command should not hit pipe/signal failure. Output:\n{text}"
    );
}

/// Regression: an interactive job-control shell launching a foreground command
/// that writes to the tty must NOT have that command stopped by SIGTTOU.
///
/// busybox `ash` (alpine) enables job control under `-t`; its `forkchild` does
/// `setpgid(0, childpgrp)` then `tcsetpgrp(tty, childpgrp)` while the child is
/// still in a background process group. That `tcsetpgrp` raises SIGTTOU
/// regardless of TOSTOP. carrick runs the child as a real macOS process, so the
/// HOST kernel stopped it ("Stopped (tty output)") because the guest's
/// `SIG_IGN(SIGTTOU)` lived only in carrick's emulated table — the fix blocks
/// host SIGTTOU around the tty-control passthrough when the guest ignores it, so
/// `ls` actually runs and lists `/` instead of stopping before its first write.
#[test]
#[ignore]
fn interactive_jobcontrol_foreground_command_not_stopped_by_sigttou() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    // No command → the image's default interactive shell (busybox ash on alpine),
    // which turns on job control under a pty.
    let mut child = spawn_run_t_image(bin, slave, "docker.io/library/alpine", &[]);
    set_nonblocking(master);

    std::thread::sleep(Duration::from_secs(20)); // boot
    let w = |b: &[u8]| unsafe {
        libc::write(master, b.as_ptr().cast(), b.len());
    };
    // Run a foreground external command that PRODUCES output (so the buggy path —
    // stopped before its first tty write — is observable), then a computed marker
    // the shell only prints if it stayed usable.
    w(b"ls /\n");
    std::thread::sleep(Duration::from_secs(1));
    w(b"echo R$((40+2))\n");

    let mut out = Vec::new();
    read_until(master, &mut out, 12, |o| o.windows(3).any(|x| x == b"R42"));

    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("GUEST ABORT") && !text.contains("panicked"),
        "job-control command must not crash the guest. Output:\n{text}"
    );
    assert!(
        !text.contains("Stopped"),
        "foreground command must NOT be stopped by a spurious host SIGTTOU \
         (job-control tcsetpgrp from a background pgrp). Output:\n{text}"
    );
    // `ls /` on alpine lists `usr` (and `bin`); its presence proves `ls` actually
    // ran and wrote, i.e. it was foreground rather than stopped before its write.
    assert!(
        text.contains("usr"),
        "expected `ls /` output (e.g. `usr`), proving the command ran to its \
         first write instead of being stopped. Output:\n{text}"
    );
}

#[test]
#[ignore]
fn interactive_run_resolves_ttyname_dev_tty_and_resize() {
    let Some(bin) = signed_bin() else { return };
    let (master, slave) = open_pty();
    set_winsize(master, 24, 80);
    // Print the tty name and probe /dev/tty up front; then sleep so the test
    // can resize the window; then print the (new) size.
    let guest = "tty; echo dev_tty=$(echo HI >/dev/tty 2>/dev/null && echo OK || echo FAIL); \
                 sleep 12; echo size=$(stty size); echo END";
    let mut child = spawn_run_t(bin, slave, &["/bin/sh", "-c", guest]);
    set_nonblocking(master);

    // Wait for boot + the tty/dev_tty lines, then resize during the sleep.
    let mut out = Vec::new();
    read_until(master, &mut out, 25, |o| o.windows(4).any(|w| w == b"dev_"));
    set_winsize(master, 50, 132);
    read_until(master, &mut out, 18, |o| o.windows(3).any(|w| w == b"END"));

    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master) };

    let text = String::from_utf8_lossy(&out);
    // (1) ttyname(3) resolves: `tty` prints /dev/pts/N (not "not a tty").
    assert!(
        text.contains("/dev/pts/"),
        "tty(1) should resolve to /dev/pts/N. Output:\n{text}"
    );
    // (2) /dev/tty is openable+writable (controlling terminal).
    assert!(
        text.contains("dev_tty=OK"),
        "/dev/tty should be writable. Output:\n{text}"
    );
    // (3) live SIGWINCH resize propagates to the guest.
    assert!(
        text.contains("size=50 132"),
        "live resize should propagate (expected 50 132). Output:\n{text}"
    );
}
