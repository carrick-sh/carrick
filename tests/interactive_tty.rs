//! End-to-end smoke test for `carrick run -t` (interactive pty). Drives the
//! built binary over a real pty. #[ignore] by default: needs a signed release
//! binary + the debian image + Docker, and is timing-based. Run explicitly:
//!   ./scripts/build-signed.sh
//!   cargo test --test interactive_tty -- --ignored --nocapture
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
#[ignore]
fn interactive_run_sees_a_tty() {
    // Allocate a pty; the child's stdio = the slave.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    unsafe {
        libc::grantpt(master);
        libc::unlockpt(master);
    }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(master)) }.to_owned();
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
    assert!(slave >= 0, "open slave");

    let mut child = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args([
            "run",
            "-t",
            "--fs",
            "host",
            "docker.io/library/debian:stable",
            "/bin/sh",
            "-c",
            "test -t 0 && echo IS_A_TTY; tty; exit 0",
        ])
        .stdin(unsafe { Stdio::from_raw_fd(slave) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn carrick");

    // Read from the master in a background thread with an overall timeout so a
    // hang can't wedge the test. Collect whatever the guest emitted.
    let mut mf = unsafe { std::fs::File::from_raw_fd(master) };
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match mf.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.windows(8).any(|w| w == b"IS_A_TTY")
                        && out.windows(9).any(|w| w == b"/dev/pts/")
                    {
                        break;
                    }
                }
                Err(_) => break, // EIO when all slaves close = guest exited
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    });

    // Bound the whole thing.
    std::thread::sleep(Duration::from_secs(45)); // image pull + boot + run
    let _ = child.kill();
    let _ = child.wait();
    let out = reader.join().unwrap_or_default();

    assert!(
        out.contains("IS_A_TTY"),
        "guest stdin should be a tty under -t. Output:\n{out}"
    );
    assert!(
        out.contains("/dev/pts/"),
        "tty(1) should report /dev/pts/N. Output:\n{out}"
    );
}
