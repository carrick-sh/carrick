//! Deadlock watchdog: when the guest carrier stops making syscall progress for
//! `CARRICK_DEADLOCK_WATCHDOG_MS`, publish a durable external-debug request and
//! stop the carrier in place. An operator or orchestrator can then attach a
//! debugger and save a core without the carrier spawning a helper process.
//!
//! The progress counter is carrier-global. Every logical task dispatches through
//! this process and advances the same atomic word, so a quiet task does not look
//! deadlocked while another logical task is making progress. One watchdog thread
//! is armed per carrier; on a true carrier-wide stall it publishes one request
//! and stops the carrier for an external debugger.
//!
//! Off unless `CARRICK_DEADLOCK_WATCHDOG_MS` is set. Diagnostic only.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const CAPTURE_REQUEST_SCHEMA: &str = "carrick.deadlock-capture-request.v1";

/// Has this carrier ever dispatched a guest syscall? A setup-only process that
/// never entered the guest cannot hold the deadlock state this diagnostic is
/// intended to capture.
static LOCAL_TICKED: AtomicBool = AtomicBool::new(false);
static ARMED: AtomicBool = AtomicBool::new(false);
static CAPTURE_CLAIMED: AtomicBool = AtomicBool::new(false);

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

/// Only one request may be published for this carrier lifetime.
fn claim_core_slot() -> bool {
    !CAPTURE_CLAIMED.swap(true, Ordering::AcqRel)
}

fn window_ms() -> Option<u64> {
    static CELL: OnceLock<Option<u64>> = OnceLock::new();
    *CELL.get_or_init(|| {
        std::env::var("CARRICK_DEADLOCK_WATCHDOG_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&ms| ms > 0)
    })
}

struct CaptureRequest {
    request_path: PathBuf,
    command: String,
    contents: String,
}

fn ensure_private_directory(path: &Path, uid: u32) -> std::io::Result<()> {
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

fn fresh_capture_directory(base: &Path, pid: i32, uid: u32) -> std::io::Result<PathBuf> {
    ensure_private_directory(base, uid)?;
    for _ in 0..4 {
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy)
            .map_err(|error| std::io::Error::other(format!("capture entropy: {error:?}")))?;
        let token = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let directory = base.join(format!("capture-{pid}-{token}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {
                ensure_private_directory(&directory, uid)?;
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "capture directory entropy collided repeatedly",
    ))
}

fn prepare_capture_request_in(base: &Path, pid: i32, uid: u32) -> std::io::Result<CaptureRequest> {
    let directory = fresh_capture_directory(base, pid, uid)?;
    let request_path = directory.join("request.txt");
    let core_path = directory.join("carrier.core");
    let command = format!(
        "sudo -n lldb -p {pid} -b -o 'process save-core --style modified-memory {}' -o detach -o quit",
        core_path.display(),
    );
    let contents = format!(
        "schema={CAPTURE_REQUEST_SCHEMA}\npid={pid}\ncore_path={}\nattach_command={command}\n",
        core_path.display(),
    );
    Ok(CaptureRequest {
        request_path,
        command,
        contents,
    })
}

fn publish_capture_request(pid: i32) -> std::io::Result<(String, String)> {
    let uid = unsafe { libc::geteuid() };
    let base = std::env::temp_dir().join(format!("carrick-deadlock-{uid}"));
    let request = prepare_capture_request_in(&base, pid, uid)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&request.request_path)?;
    file.write_all(request.contents.as_bytes())?;
    file.sync_all()?;
    std::fs::set_permissions(
        &request.request_path,
        std::fs::Permissions::from_mode(0o600),
    )?;
    Ok((request.request_path.display().to_string(), request.command))
}

/// Arm this carrier's watchdog thread. Repeated calls are idempotent.
pub fn arm() {
    let Some(ms) = window_ms() else { return };
    if ARMED.swap(true, Ordering::AcqRel) {
        return;
    }
    std::thread::Builder::new()
        .name("carrick-deadlock-wd".into())
        .spawn(move || {
            const STEP_MS: u64 = 250;
            let mut last = counter().load(Ordering::Relaxed);
            let mut stalled: u64 = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(STEP_MS));
                let now = counter().load(Ordering::Relaxed);
                if now != last {
                    last = now;
                    stalled = 0;
                    continue;
                }
                stalled += STEP_MS;
                if stalled < ms {
                    continue;
                }
                // No global syscall progress for the window: a true deadlock.
                let pid = unsafe { libc::getpid() };
                // Eligibility gate: setup that never entered the guest has no
                // guest deadlock state worth preserving.
                if !local_ticked() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: carrier stall ({ms}ms) before any guest syscall; no capture requested"
                    );
                    return;
                }
                // One carrier publishes at most one capture request.
                if !claim_core_slot() {
                    eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: capture already requested for this carrier"
                    );
                    return;
                }
                match publish_capture_request(pid) {
                    Ok((request_path, command)) => eprintln!(
                        "DEADLOCK WATCHDOG pid={pid}: no tree-wide syscall progress for {ms}ms; external capture requested at {request_path}; carrier stopping in place\nrun: {command}"
                    ),
                    Err(error) => {
                        eprintln!(
                            "DEADLOCK WATCHDOG pid={pid}: capture-request publication failed: {error}; carrier stopping in place\nattach with: sudo -n lldb -p {pid}"
                        );
                    }
                }
                // Fail closed: preserve the exact carrier state for an external
                // debugger even when the durable request could not be written.
                // SIGSTOP cannot be caught or ignored; an operator may resume
                // the carrier after capture if desired.
                unsafe { libc::raise(libc::SIGSTOP) };
                return;
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_capture_claim_is_one_shot() {
        let latch = AtomicBool::new(false);
        assert!(!latch.swap(true, Ordering::AcqRel));
        assert!(latch.swap(true, Ordering::AcqRel));
    }

    #[test]
    fn capture_request_uses_private_unpredictable_directory() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-deadlock-test")
            .tempdir_in("/tmp")
            .expect("test parent");
        let base = temp.path().join("private-base");
        let uid = unsafe { libc::geteuid() };

        let first = prepare_capture_request_in(&base, 4242, uid).expect("first request");
        let second = prepare_capture_request_in(&base, 4242, uid).expect("second request");

        let first_directory = first.request_path.parent().expect("first directory");
        let second_directory = second.request_path.parent().expect("second directory");
        assert_ne!(first_directory, second_directory);
        assert_eq!(first.request_path.parent(), Some(first_directory));
        assert!(
            first
                .command
                .contains(&first_directory.display().to_string())
        );
        assert!(
            first
                .contents
                .contains(&format!("schema={CAPTURE_REQUEST_SCHEMA}\n"))
        );
        assert!(first.contents.contains("pid=4242\n"));
        for directory in [&base, first_directory, second_directory] {
            let mode = std::fs::metadata(directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn published_marker_is_private_and_core_path_is_unclaimed_inside_private_directory() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-deadlock-publish")
            .tempdir_in("/tmp")
            .expect("test parent");
        let base = temp.path().join("private-base");
        let uid = unsafe { libc::geteuid() };
        let request = prepare_capture_request_in(&base, 4343, uid).expect("request");
        let directory = request.request_path.parent().expect("capture directory");
        let core_path = directory.join("carrier.core");
        let mut marker = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&request.request_path)
            .expect("marker");
        marker
            .write_all(request.contents.as_bytes())
            .expect("write marker");
        marker.sync_all().expect("sync marker");
        let mode = std::fs::metadata(&request.request_path)
            .expect("marker metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!core_path.exists());
        assert_eq!(core_path.parent(), Some(directory));
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
        let error = ensure_private_directory(&link, unsafe { libc::geteuid() })
            .expect_err("symlink base must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
