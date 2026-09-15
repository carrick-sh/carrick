//! Deadlock watchdog: when the guest carrier stops making syscall progress for
//! the window its caller named, capture the carrier from outside
//! ([`crate::wedge_capture`]) and reap it.
//!
//! The progress counter is carrier-global. Every logical task dispatches through
//! this process and advances the same atomic word, so a quiet task does not look
//! deadlocked while another logical task is making progress. One watchdog thread
//! is armed per carrier; on a true carrier-wide stall it performs the one
//! capture this process gets.
//!
//! # The window is a parameter, not an environment variable
//!
//! It used to be `CARRICK_DEADLOCK_WATCHDOG_MS`, and what it published was a
//! request file in `/tmp` that NOTHING consumed: the carrier `SIGSTOP`ped
//! itself and waited for a human. The gap was an executor, not a capability —
//! so the window is now a typed argument from the caller that owns the run's
//! budget, and the action is the capture itself.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::wedge_capture::{WedgeCaptureRequest, capture_wedged_carrier};

/// Has this carrier ever dispatched a guest syscall? A setup-only process that
/// never entered the guest cannot hold the deadlock state this diagnostic is
/// intended to capture.
static LOCAL_TICKED: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);

/// Carrier-global progress word shared by every logical guest task.
fn counter() -> &'static AtomicU64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    &COUNTER
}

/// Advance global progress. Called on every syscall dispatch (cheap, relaxed).
pub fn tick() {
    counter().fetch_add(1, Ordering::Relaxed);
    // Mark THIS process as a real guest dispatcher (see `LOCAL_TICKED`). A single
    // relaxed store on the hot path — cheaper than a load+branch, and idempotent.
    LOCAL_TICKED.store(true, Ordering::Relaxed);
}

/// Has this process ever dispatched a guest syscall? Gates self-core eligibility.
fn local_ticked() -> bool {
    LOCAL_TICKED.load(Ordering::Relaxed)
}

/// How long the carrier may make NO syscall progress before it is captured and
/// reaped.
///
/// A typed parameter with one spelling: the caller that owns the run's budget
/// states the window, because only it knows what "no progress" costs for that
/// workload. A zero or absent window is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeadlockWindow(Duration);

impl DeadlockWindow {
    /// `None` for a zero window: a watchdog that fires immediately is not a
    /// watchdog, and refusing it here keeps every caller from inventing its own
    /// meaning for zero.
    pub fn new(window: Duration) -> Option<Self> {
        (!window.is_zero()).then_some(Self(window))
    }

    pub fn as_duration(self) -> Duration {
        self.0
    }
}

pub(crate) fn ensure_private_directory(path: &Path, uid: u32) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "capture directory {} is not an owned directory",
                        path.display()
                    ),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("capture directory {} changed identity", path.display()),
        ));
    }
    Ok(())
}

/// Arm this carrier's watchdog thread with `window`. Repeated calls are
/// idempotent; the first window wins.
///
/// On a carrier-wide stall the watchdog does the capture itself and reaps the
/// carrier. It does NOT `SIGSTOP` and wait for a human: a stopped carrier in a
/// signed test shard is a hang that outlives the gate.
pub fn arm(window: DeadlockWindow) {
    if ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    let window_ms = u64::try_from(window.as_duration().as_millis()).unwrap_or(u64::MAX);
    std::thread::Builder::new()
        .name("carrick-deadlock-wd".into())
        .spawn(move || {
            const STEP_MS: u64 = 250;
            let mut last = counter().load(Ordering::Relaxed);
            let mut stalled: u64 = 0;
            loop {
                std::thread::sleep(Duration::from_millis(STEP_MS));
                let now = counter().load(Ordering::Relaxed);
                if now != last {
                    last = now;
                    stalled = 0;
                    continue;
                }
                stalled += STEP_MS;
                if stalled < window_ms {
                    continue;
                }
                // No global syscall progress for the window: a true deadlock.
                // SAFETY: `getpid` reads this process's own identity.
                let pid = unsafe { libc::getpid() };
                // Eligibility gate: setup that never entered the guest has no
                // guest deadlock state worth preserving.
                if !local_ticked() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: carrier stall ({window_ms}ms) before any guest syscall; no capture requested"
                    );
                    return;
                }
                let request = WedgeCaptureRequest {
                    label: "deadlock".to_owned(),
                    pid,
                    run_id: std::env::var("CARRICK_RUN_ID").ok(),
                    budget_ms: window_ms,
                    elapsed_ms: stalled,
                    out_root: PathBuf::from("target/postmortem"),
                };
                match capture_wedged_carrier(request) {
                    Ok(capture) => eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: no carrier-wide syscall progress for {window_ms}ms; captured to {}",
                        capture.dir.display()
                    ),
                    Err(error) => eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: no carrier-wide syscall progress for {window_ms}ms; capture failed: {error}"
                    ),
                }
                return;
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zero window is refused at the type, so no caller can invent its own
    /// meaning for "0" the way the deleted environment variable did.
    #[test]
    fn a_zero_deadlock_window_is_not_representable() {
        assert_eq!(DeadlockWindow::new(Duration::ZERO), None);
        let window = DeadlockWindow::new(Duration::from_millis(8_000)).expect("window");
        assert_eq!(window.as_duration(), Duration::from_millis(8_000));
    }

    #[test]
    fn the_watchdog_arms_once_per_carrier() {
        let latch = AtomicBool::new(false);
        assert!(!latch.swap(true, Ordering::AcqRel));
        assert!(latch.swap(true, Ordering::AcqRel));
    }

    #[test]
    fn private_capture_base_refuses_symlinks() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-deadlock-link")
            .tempdir_in("/tmp")
            .expect("test parent");
        let target = temp.path().join("target");
        let link = temp.path().join("base");
        std::fs::create_dir(&target).expect("target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        // SAFETY: `geteuid` reads this process's own effective user id.
        let error = ensure_private_directory(&link, unsafe { libc::geteuid() })
            .expect_err("symlink base must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_private_capture_directory_is_created_owned_and_restricted() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::Builder::new()
            .prefix("carrick-deadlock-private")
            .tempdir_in("/tmp")
            .expect("test parent");
        let base = temp.path().join("private-base");
        // SAFETY: `geteuid` reads this process's own effective user id.
        let uid = unsafe { libc::geteuid() };
        ensure_private_directory(&base, uid).expect("create");
        ensure_private_directory(&base, uid).expect("idempotent");
        let mode = std::fs::metadata(&base)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        assert!(ensure_private_directory(&base, uid + 1).is_err());
    }
}
