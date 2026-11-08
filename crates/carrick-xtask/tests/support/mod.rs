// Each target includes this module and uses a subset of it, so an item
// unused by one consumer is not dead code for the crate.
#![allow(dead_code)]

use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PipeReadinessError {
    TimedOut,
    ChildExited,
    InvalidDescriptor,
    Io(i32),
}

impl fmt::Display for PipeReadinessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimedOut => f.write_str("readiness signal timed out"),
            Self::ChildExited => f.write_str("child exited before readiness"),
            Self::InvalidDescriptor => f.write_str("poll reported invalid descriptor"),
            Self::Io(errno) => write!(f, "{}", std::io::Error::from_raw_os_error(*errno)),
        }
    }
}

impl std::error::Error for PipeReadinessError {}

/// Run the calling test case in an ambient environment the fixture build
/// policy accepts, and report its verdict.
///
/// Worker VMs export `CARGO_BUILD_JOBS` and an empty `RUSTC_WORKSPACE_WRAPPER`,
/// which the fixture build policy refuses, so 63 cases in `tests/fixtures.rs`
/// failed for the shape of the invoking shell rather than for Carrick (#1888).
/// The refusal is right: a publisher must not seal a bundle from a host whose
/// Cargo settings could change what it compiles. A *test* of the controlled
/// environment therefore states its own compliant ambient environment - the
/// parent re-executes the same case in a child prepared by
/// `fixtures::scrub_ambient_overrides`, the production policy's own rule.
/// Nothing here relaxes that policy: a case that expects a refusal still plants
/// the override on the command it audits, as
/// `cache_selection_preserves_ambient_wrapper_rejection_at_fixture_entrypoint`
/// does.
///
/// `scrub` is spelled by each consumer because this file is shared:
/// `src/ci_scaler/security_tests.rs` includes it with `#[path]` into the lib
/// test, where the crate is `crate`, and every integration target compiles it
/// with `carrick-xtask` as a dependency.
///
/// Returns `true` only in the scrubbed child, where the caller runs its body;
/// the parent asserts the child's result and returns `false`. A case re-run by
/// name from another case (an `#[ignore]`d child spawned with `--exact`) must
/// not call this: it would not match its own name and would report zero passed.
#[allow(clippy::unwrap_used)]
pub fn compliant_ambient_case(scrub: fn(&mut Command) -> &mut Command) -> bool {
    const CHILD: &str = "CARRICK_XTASK_AMBIENT_CASE";
    // A name the policy refuses, planted immediately before the scrub so its
    // absence in the child proves the scrub matched it: a policy that stopped
    // refusing this name would fail here, on any host, instead of passing
    // vacuously because nothing happened to be set.
    const PROBE: &str = "RUSTC_WORKSPACE_WRAPPER";
    // The harness names each test thread exactly as `--exact` matches it, so
    // the case cannot drift from a pinned name list.
    let exact = std::thread::current().name().unwrap_or_default().to_owned();
    if std::env::var(CHILD).as_deref() == Ok(exact.as_str()) {
        assert!(
            std::env::var_os(PROBE).is_none(),
            "case {exact} ran with an unscrubbed Cargo override"
        );
        return true;
    }
    assert!(
        !exact.is_empty(),
        "cannot derive the test name to re-execute it"
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", &exact, "--nocapture"])
        .env(CHILD, &exact)
        .env(PROBE, "/carrick/ambient-probe-wrapper");
    scrub(&mut command);
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "compliant-ambient case {exact} failed: {}\n{stdout}\n{stderr}",
        output.status
    );
    false
}

pub fn wait_for_pipe_readiness(
    read_fd: BorrowedFd<'_>,
    timeout: Duration,
) -> Result<(), PipeReadinessError> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PipeReadinessError::TimedOut);
        }
        let timeout_ms =
            libc::c_int::try_from(remaining.as_millis().max(1)).unwrap_or(libc::c_int::MAX);
        let mut pollfd = libc::pollfd {
            fd: read_fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pollfd` is a valid single-element local struct, and `read_fd`
        // borrows a live pipe descriptor for the duration of `poll`.
        let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(PipeReadinessError::Io(errno));
        }
        if ret == 0 {
            return Err(PipeReadinessError::TimedOut);
        }
        if (pollfd.revents & libc::POLLNVAL) != 0 {
            return Err(PipeReadinessError::InvalidDescriptor);
        }
        break;
    }
    let mut buf = [0u8; 1];
    loop {
        // SAFETY: `buf` is a valid 1-byte mutable buffer, and `read_fd` borrows
        // a live pipe descriptor for the duration of `read`.
        let n = unsafe {
            libc::read(
                read_fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(PipeReadinessError::Io(errno));
        }
        if n == 0 {
            return Err(PipeReadinessError::ChildExited);
        }
        return Ok(());
    }
}
