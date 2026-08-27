//! Shared helpers for carrick-conformance-next guest-running tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use carrick_conformance_next::EmbedError;

/// The canonical conformance image: arm64 Ubuntu 24.04.
pub const SMOKE_IMAGE: &str = "docker.io/library/ubuntu:24.04";

/// Generic probes whose Docker result is deliberately not committed as a
/// static oracle. The old gate quarantines these for timing sensitivity or
/// excludes them from its routine regression lane; they remain live-oracle
/// work and must not make the ordinary cached lane depend on Docker.
pub const LIVE_ORACLE_PROBES: &[&str] = &[
    "clockgetres",
    "forksleepfork",
    "futexextra",
    "futexghost",
    "futexrequeue",
    "futexshare",
    "futexsharedalias",
    "futexwakecount",
    "iouring",
    "iouringenterflag",
    "itimer",
    "manythreads",
    "mmapfileforkwriteback",
    "mmaprecl",
    "mtforkcorrupt",
    "netpoll",
    "pauseeintr",
    "pidnsinitreap",
    "posixtimers",
    "ppollsig",
    "pselecteintr",
    "selecttimeout",
    "sigchld",
    "splicenetpoll",
    "timeclock",
    "timeextra",
    "timersettimeabs",
    "waitexitstorm",
    "waitsiblingsigchld",
];

/// Probes that cannot share an embedded test process after they fail. Keep
/// these on the old out-of-process lane until the runtime teardown is fixed.
pub const OUT_OF_PROCESS_PROBES: &[&str] = &["execthreads"];

pub fn needs_live_oracle(probe: &str) -> bool {
    LIVE_ORACLE_PROBES.contains(&probe)
}

pub fn runs_in_cached_lane(probe: &str) -> bool {
    !needs_live_oracle(probe) && !OUT_OF_PROCESS_PROBES.contains(&probe)
}

/// Run one embedded container while host fd 0 is an already-EOF pipe, matching
/// the old direct-probe transport and Docker's `-i` pipe after payload upload.
/// Callers must hold [`guest_lock`] because fd 0 is process-global.
pub fn with_empty_stdin_pipe<T>(run: impl FnOnce() -> T) -> T {
    struct RestoreStdin(i32);

    impl Drop for RestoreStdin {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live duplicate of fd 0 owned by this guard.
            unsafe {
                libc::dup2(self.0, libc::STDIN_FILENO);
                libc::close(self.0);
            }
        }
    }

    // SAFETY: all returned fds are checked, uniquely owned here, and closed.
    unsafe {
        let saved = libc::dup(libc::STDIN_FILENO);
        assert!(saved >= 0, "failed to duplicate host stdin");
        let restore = RestoreStdin(saved);
        let mut pipe_fds = [-1; 2];
        assert_eq!(
            libc::pipe(pipe_fds.as_mut_ptr()),
            0,
            "failed to create stdin pipe"
        );
        libc::close(pipe_fds[1]);
        assert_eq!(
            libc::dup2(pipe_fds[0], libc::STDIN_FILENO),
            libc::STDIN_FILENO,
            "failed to install stdin pipe"
        );
        libc::close(pipe_fds[0]);
        let outcome = run();
        drop(restore);
        outcome
    }
}

static GUEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize guest-running tests inside one process.
pub fn guest_lock() -> MutexGuard<'static, ()> {
    GUEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn empty_stdin_transport_is_an_eof_fifo() {
    let _guard = guest_lock();
    with_empty_stdin_pipe(|| {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` is a valid output pointer and fd 0 is installed above.
        assert_eq!(
            unsafe { libc::fstat(libc::STDIN_FILENO, stat.as_mut_ptr()) },
            0
        );
        // SAFETY: fstat succeeded and initialized the structure.
        let stat = unsafe { stat.assume_init() };
        assert_eq!(stat.st_mode & libc::S_IFMT, libc::S_IFIFO);
        let mut byte = 0u8;
        // SAFETY: the one-byte destination is valid; the pipe's writer is closed.
        assert_eq!(
            unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) },
            0
        );
    });
}

/// The repository root (`crates/carrick-conformance-next` is two levels down).
pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("carrick-conformance-next lives under crates/carrick-conformance-next")
        .to_path_buf()
}

/// Unwrap a container run, converting `EmbedError::Entitlement` into a loud failure.
pub fn run_or_fail<T>(outcome: Result<T, EmbedError>) -> T {
    run_named_or_fail("container", outcome)
}

pub fn run_named_or_fail<T>(case: &str, outcome: Result<T, EmbedError>) -> T {
    match outcome {
        Ok(result) => result,
        Err(EmbedError::Entitlement) => panic!(
            "{case}: HV_DENIED (0xfae94007): this test executable lacks \
             com.apple.security.hypervisor. Run it through `just test-conformance-next` \
             or `scripts/test-signed.sh carrick-conformance-next`."
        ),
        Err(err) => panic!("{case}: container run failed: {err}"),
    }
}

/// The run id exported by the test runner.
pub fn run_id() -> String {
    std::env::var("CARRICK_RUN_ID")
        .ok()
        .filter(|id| !id.is_empty())
        .expect(
            "CARRICK_RUN_ID must be set: scripts/test-signed.sh exports it so \
             scripts/sudo/kill.sh can reap this run's guests",
        )
}
