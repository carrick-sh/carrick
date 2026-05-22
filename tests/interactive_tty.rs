//! End-to-end smoke test for `carrick run -t` (interactive pty). Drives the
//! built binary over a real pty and proves the guest gets a working tty with
//! live line discipline (typed input is echoed by the pty AND by `cat`, so a
//! unique marker appears twice). #[ignore] by default: needs a signed release
//! binary + the debian image + Docker, and is timing-based. Run explicitly:
//!   ./scripts/build-signed.sh
//!   cargo test --test interactive_tty -- --ignored --nocapture
use std::os::unix::io::FromRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
#[ignore]
fn interactive_run_provides_a_working_pty() {
    // Allocate a pty; the child's stdio = the slave.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    unsafe { libc::grantpt(master); libc::unlockpt(master); }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(master)) }.to_owned();
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
    assert!(slave >= 0, "open slave");

    // /bin/cat: the pty line discipline echoes typed input; cat echoes it
    // again. A real tty under -t => the marker appears at least twice.
    let dup_slave = unsafe { libc::dup(slave) };
    let mut child = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["run", "-t", "--fs", "host", "docker.io/library/debian:stable", "/bin/cat"])
        .stdin(unsafe { Stdio::from_raw_fd(slave) })
        .stdout(unsafe { Stdio::from_raw_fd(dup_slave) })
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn carrick");

    // make the master non-blocking for bounded reads
    unsafe {
        let fl = libc::fcntl(master, libc::F_GETFL);
        libc::fcntl(master, libc::F_SETFL, fl | libc::O_NONBLOCK);
    }

    // Give the guest time to boot (image pull + HVF boot), then "type" a marker.
    std::thread::sleep(Duration::from_secs(20));
    let marker = b"carricktty7\n";
    unsafe { libc::write(master, marker.as_ptr().cast(), marker.len()); }

    // Read for up to ~10s looking for the marker twice.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            let hits = out.windows(b"carricktty7".len()).filter(|w| *w == b"carricktty7").count();
            if hits >= 2 { break; }
        } else {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    // Ctrl-D so cat exits; then tear down.
    unsafe { libc::write(master, b"\x04".as_ptr().cast(), 1); }
    std::thread::sleep(Duration::from_millis(500));
    let _ = child.kill();
    let _ = child.wait();
    unsafe { libc::close(master); }

    let text = String::from_utf8_lossy(&out);
    let hits = text.matches("carricktty7").count();
    assert!(hits >= 2,
        "expected the typed marker echoed by the pty line discipline AND by cat (>=2 occurrences), \
         got {hits}. A real tty under -t echoes input. Output:\n{text}");
}
