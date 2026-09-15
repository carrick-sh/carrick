//! External capture of a WEDGED carrier, and the reap that follows it.
//!
//! # Why this exists
//!
//! The in-process abort sink ([`crate::kernel::debug::request_abort`]) is the
//! one fail-closed exit for a run that can never finish: it freezes the
//! scheduler, captures a post-mortem and returns it as a value. It is read at
//! a supervised-wait boundary, so a carrier whose executor is SPINNING never
//! reaches the boundary and never consumes the latch. That state has a name
//! and a cost: during one `just conformance-probes`, a carrier spun 29m45s at
//! 104% CPU on the `forkstackstorm` probe and ended only because a human
//! attached `lldb` by hand, saved a backtrace and a core, and killed it.
//!
//! This module is that human, written down. It runs from a HEALTHY thread
//! (the budget's waiter, or the watchdog thread — only executor threads are
//! wedged), captures the same two artifacts into an owned private directory,
//! and then reaps the carrier so the shard cannot hang forever.
//!
//! # Fail closed, never empty
//!
//! "Zero events" is an error here, never a quiet success: an absent or empty
//! backtrace, an absent or empty core, an unavailable `lldb`, or a capture
//! that outran its own hard bound all produce a NAMED error that still points
//! at the directory. No rung may produce an empty pass, and every rung —
//! success or failure — still arms the reap, because a carrier that cannot be
//! captured is exactly the one that must not outlive its budget.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::deadlock_watchdog::ensure_private_directory;

/// How long one `lldb` invocation may run before it is killed and the capture
/// reported as timed out. A backtrace of ~26 threads returns in seconds; a
/// modified-memory core of a multi-GiB carrier is the slow one.
const CAPTURE_STEP_TIMEOUT: Duration = Duration::from_secs(180);

/// How long after a capture the carrier is left alive. The named failure has
/// to reach the log before the process dies, so the reap is delayed by enough
/// for the error to propagate out of the run and be printed, and no longer.
const REAP_GRACE: Duration = Duration::from_secs(5);

/// Only one capture may run for a carrier lifetime, whichever rung reaches it
/// first.
static CAPTURE_CLAIMED: AtomicBool = AtomicBool::new(false);

fn claim_capture() -> bool {
    !CAPTURE_CLAIMED.swap(true, Ordering::AcqRel)
}

/// What to capture, and the facts that make the artifacts attributable.
#[derive(Debug, Clone)]
pub struct WedgeCaptureRequest {
    /// Names the artifact directory: the probe or container that wedged.
    pub label: String,
    /// The carrier process to attach to. It is this process.
    pub pid: i32,
    /// `CARRICK_RUN_ID`, so a capture can be tied to the run that produced it.
    pub run_id: Option<String>,
    /// The budget that was breached, in milliseconds.
    pub budget_ms: u64,
    /// How long the run had actually taken when the capture was ordered.
    pub elapsed_ms: u64,
    /// Directory the per-carrier capture directory is created under.
    pub out_root: PathBuf,
}

/// The artifacts a completed capture left on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WedgeCapture {
    pub dir: PathBuf,
    pub backtrace: PathBuf,
    pub core: Option<PathBuf>,
}

/// Why a capture produced no usable evidence. Every variant names the
/// directory, so a caller can report where to look even when the capture
/// itself failed.
#[derive(Debug, thiserror::Error)]
pub enum WedgeCaptureError {
    /// The capture directory could not be created or is not privately owned.
    #[error("wedge capture directory {dir} is unusable: {reason}")]
    Directory { dir: PathBuf, reason: String },
    /// Another rung already claimed this carrier's one capture.
    #[error(
        "a wedge capture was already claimed for this carrier; the earlier \
         capture owns the artifacts"
    )]
    AlreadyClaimed,
    /// A capture step could not be started at all (no `lldb`, `sudo -n`
    /// refused, or the command could not be spawned).
    #[error("wedge capture tool unavailable for {dir}: {reason}")]
    ToolUnavailable { dir: PathBuf, reason: String },
    /// A capture step outran its own hard bound and was killed.
    #[error("wedge capture of {dir} exceeded its {after_ms}ms bound at step {step}")]
    TimedOut {
        dir: PathBuf,
        step: &'static str,
        after_ms: u64,
    },
    /// The capture ran but left nothing to read. This is a failure, never a
    /// quiet pass.
    #[error("wedge capture of {dir} produced no evidence: {reason}")]
    NoEvidence { dir: PathBuf, reason: String },
}

impl WedgeCaptureError {
    /// The artifact directory this failure refers to, when one was created.
    pub fn directory(&self) -> Option<&Path> {
        match self {
            Self::Directory { dir, .. }
            | Self::ToolUnavailable { dir, .. }
            | Self::TimedOut { dir, .. }
            | Self::NoEvidence { dir, .. } => Some(dir.as_path()),
            Self::AlreadyClaimed => None,
        }
    }
}

/// One step of the capture, in the order they run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureStep {
    /// `thread backtrace all` — every host thread of the wedged carrier.
    Backtrace,
    /// `process save-core --style modified-memory` — the carrier's state.
    Core,
}

impl CaptureStep {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Backtrace => "backtrace",
            Self::Core => "core",
        }
    }
}

/// Outcome of one capture step, as the runner reports it.
#[derive(Debug)]
pub(crate) enum StepOutcome {
    Completed,
    Unavailable(String),
    TimedOut,
}

/// Runs one capture step against a live pid, writing to `output`.
///
/// A seam, so the fail-closed rungs (empty artifact, unavailable tool, step
/// timeout) are provable on a host with no `lldb` and no wedged carrier.
pub(crate) trait CaptureRunner {
    fn run(&self, step: CaptureStep, pid: i32, output: &Path, bound: Duration) -> StepOutcome;
}

/// Arms the carrier's own death after `grace`.
///
/// A seam for the same reason: a test must prove the reap is armed on every
/// path without the test process killing itself.
pub(crate) trait CarrierReaper {
    fn arm(&self, pid: i32, grace: Duration);
}

/// Capture the wedged carrier and arm its reap.
///
/// Returns the artifacts on success. Never returns `Ok` with an empty
/// backtrace or an empty core, and arms the reap on every path — including
/// every error path.
pub fn capture_wedged_carrier(
    request: WedgeCaptureRequest,
) -> Result<WedgeCapture, WedgeCaptureError> {
    // The claim lives on the shipped entry point, not in `capture_with`: it is
    // a property of the carrier (one capture per lifetime), not of the capture
    // procedure, and the procedure has to stay callable more than once for its
    // fail-closed rungs to be provable.
    if !claim_capture() {
        return Err(WedgeCaptureError::AlreadyClaimed);
    }
    capture_with(request, &LldbCaptureRunner, &SigkillReaper)
}

pub(crate) fn capture_with(
    request: WedgeCaptureRequest,
    runner: &dyn CaptureRunner,
    reaper: &dyn CarrierReaper,
) -> Result<WedgeCapture, WedgeCaptureError> {
    // The reap is armed BEFORE the capture, not after it: a capture that hangs
    // in a way even its own bound cannot see must not buy the wedge more life.
    // The grace covers the whole capture plus the error's trip to the log.
    reaper.arm(
        request.pid,
        REAP_GRACE + CAPTURE_STEP_TIMEOUT + CAPTURE_STEP_TIMEOUT,
    );

    let dir = prepare_capture_directory(&request.out_root, &request.label, request.pid).map_err(
        |error| WedgeCaptureError::Directory {
            dir: request
                .out_root
                .join(directory_name(&request.label, request.pid)),
            reason: error.to_string(),
        },
    )?;
    write_manifest(&dir, &request).map_err(|error| WedgeCaptureError::Directory {
        dir: dir.clone(),
        reason: format!("manifest could not be written: {error}"),
    })?;

    let backtrace = dir.join("backtrace.txt");
    run_step(
        runner,
        CaptureStep::Backtrace,
        request.pid,
        &backtrace,
        &dir,
    )?;
    require_evidence(&dir, &backtrace, CaptureStep::Backtrace)?;

    let core = dir.join("carrier.core");
    run_step(runner, CaptureStep::Core, request.pid, &core, &dir)?;
    require_evidence(&dir, &core, CaptureStep::Core)?;

    Ok(WedgeCapture {
        dir,
        backtrace,
        core: Some(core),
    })
}

fn run_step(
    runner: &dyn CaptureRunner,
    step: CaptureStep,
    pid: i32,
    output: &Path,
    dir: &Path,
) -> Result<(), WedgeCaptureError> {
    match runner.run(step, pid, output, CAPTURE_STEP_TIMEOUT) {
        StepOutcome::Completed => Ok(()),
        StepOutcome::Unavailable(reason) => Err(WedgeCaptureError::ToolUnavailable {
            dir: dir.to_path_buf(),
            reason: format!("{}: {reason}", step.name()),
        }),
        StepOutcome::TimedOut => Err(WedgeCaptureError::TimedOut {
            dir: dir.to_path_buf(),
            step: step.name(),
            after_ms: u64::try_from(CAPTURE_STEP_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        }),
    }
}

/// An artifact that does not exist, or exists with zero bytes, is a failed
/// capture. Reporting it as a capture would reproduce the exact trap AGENTS.md
/// names: "zero events means the probe did not fire, never that it did not
/// happen".
fn require_evidence(
    dir: &Path,
    artifact: &Path,
    step: CaptureStep,
) -> Result<(), WedgeCaptureError> {
    let bytes = std::fs::symlink_metadata(artifact)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map_or(0, |metadata| metadata.len());
    if bytes == 0 {
        return Err(WedgeCaptureError::NoEvidence {
            dir: dir.to_path_buf(),
            reason: format!(
                "{} artifact {} is absent or empty",
                step.name(),
                artifact.display()
            ),
        });
    }
    Ok(())
}

fn directory_name(label: &str, pid: i32) -> String {
    let sanitized: String = label
        .chars()
        .map(|c| {
            // `.` is excluded deliberately: it is the only character that can
            // make a single path segment read as a traversal.
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let sanitized = if sanitized.is_empty() {
        "carrier".to_owned()
    } else {
        sanitized
    };
    format!("{sanitized}-{pid}")
}

/// Create `<out_root>/<label>-<pid>/`, owned by this user and 0700, refusing a
/// symlink or a directory somebody else owns at either level.
///
/// The name is DELIBERATELY predictable, unlike the watchdog's unpredictable
/// request directory: an operator and a gate log both have to be able to name
/// the artifacts of a given probe. The safety comes from the ownership and
/// permission checks, not from the name.
pub(crate) fn prepare_capture_directory(
    out_root: &Path,
    label: &str,
    pid: i32,
) -> std::io::Result<PathBuf> {
    // SAFETY: `geteuid` reads this process's own effective user id.
    let uid = unsafe { libc::geteuid() };
    if let Some(parent) = out_root.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent)?;
    }
    ensure_private_directory(out_root, uid)?;
    let dir = out_root.join(directory_name(label, pid));
    ensure_private_directory(&dir, uid)?;
    Ok(dir)
}

fn write_manifest(dir: &Path, request: &WedgeCaptureRequest) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let contents = format!(
        "{{\n  \"schema\": \"carrick.wedge-capture.v1\",\n  \"label\": {},\n  \
         \"pid\": {},\n  \"run_id\": {},\n  \"budget_ms\": {},\n  \"elapsed_ms\": {}\n}}\n",
        json_string(&request.label),
        request.pid,
        request
            .run_id
            .as_deref()
            .map_or_else(|| "null".to_owned(), json_string),
        request.budget_ms,
        request.elapsed_ms,
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join("manifest.json"))?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

fn json_string(value: &str) -> String {
    let escaped: String = value
        .chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            c if c.is_control() => vec!['-'],
            c => vec![c],
        })
        .collect();
    format!("\"{escaped}\"")
}

/// The shipped runner: `sudo -n lldb`, exactly the commands a human runs by
/// hand on a wedged carrier (AGENTS.md's post-mortem instruction), with the
/// step's stdout captured into the artifact.
struct LldbCaptureRunner;

impl CaptureRunner for LldbCaptureRunner {
    fn run(&self, step: CaptureStep, pid: i32, output: &Path, bound: Duration) -> StepOutcome {
        let pid_text = pid.to_string();
        let mut command = Command::new("sudo");
        command.arg("-n").arg("lldb").arg("-p").arg(&pid_text);
        command.arg("--batch");
        match step {
            CaptureStep::Backtrace => {
                command.arg("-o").arg("thread backtrace all");
            }
            CaptureStep::Core => {
                command.arg("-o").arg(format!(
                    "process save-core --style modified-memory {}",
                    output.display()
                ));
            }
        }
        command.arg("-o").arg("detach").arg("-o").arg("quit");

        let sink = match step {
            // The backtrace IS lldb's stdout.
            CaptureStep::Backtrace => match std::fs::File::create(output) {
                Ok(file) => Stdio::from(file),
                Err(error) => {
                    return StepOutcome::Unavailable(format!(
                        "cannot create {}: {error}",
                        output.display()
                    ));
                }
            },
            // `save-core` writes the file itself; its stdout is only progress.
            CaptureStep::Core => Stdio::null(),
        };
        command
            .stdin(Stdio::null())
            .stdout(sink)
            .stderr(Stdio::null());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => return StepOutcome::Unavailable(format!("sudo -n lldb: {error}")),
        };
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return if status.success() {
                        StepOutcome::Completed
                    } else {
                        StepOutcome::Unavailable(format!("sudo -n lldb exited with {status}"))
                    };
                }
                Ok(None) => {}
                Err(error) => return StepOutcome::Unavailable(format!("wait failed: {error}")),
            }
            if started.elapsed() >= bound {
                let _ = child.kill();
                let _ = child.wait();
                return StepOutcome::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The shipped reaper: a detached thread that outlives the capture and ends
/// THIS process once the named failure has had its grace to reach the log.
///
/// The carrier is this process — under embed there is no separate process to
/// kill — so the reap is `raise(SIGKILL)`, not a kill of some other pid. That
/// is the fail-closed outcome the design states plainly: killing the carrier
/// kills the shard, `scripts/test-signed.sh` then publishes no receipt.
///
/// A plain sleeping thread is the whole mechanism: only executor threads are
/// wedged, so it needs no `fork` in a multi-threaded process to survive.
struct SigkillReaper;

impl CarrierReaper for SigkillReaper {
    fn arm(&self, pid: i32, grace: Duration) {
        // SAFETY: `getpid` reads this process's own identity.
        let self_pid = unsafe { libc::getpid() };
        if pid != self_pid {
            eprintln!(
                "WEDGE CAPTURE: refusing to reap pid={pid} from carrier pid={self_pid}; the \
                 carrier reaps only itself"
            );
            return;
        }
        std::thread::Builder::new()
            .name("carrick-wedge-reaper".to_owned())
            .spawn(move || {
                std::thread::sleep(grace);
                eprintln!(
                    "WEDGE CAPTURE pid={pid}: carrier did not finish after its capture; ending it"
                );
                // SAFETY: `raise` delivers to this process; SIGKILL is not
                // catchable, so this is the last statement that runs.
                unsafe { libc::raise(libc::SIGKILL) };
            })
            .ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubRunner {
        bytes: usize,
        outcome: fn() -> StepOutcome,
    }

    impl CaptureRunner for StubRunner {
        fn run(
            &self,
            _step: CaptureStep,
            _pid: i32,
            output: &Path,
            _bound: Duration,
        ) -> StepOutcome {
            if self.bytes > 0 {
                std::fs::write(output, vec![b'x'; self.bytes]).expect("stub artifact");
            } else {
                std::fs::write(output, b"").expect("stub artifact");
            }
            (self.outcome)()
        }
    }

    #[derive(Default)]
    struct RecordingReaper {
        armed: Mutex<Vec<(i32, Duration)>>,
    }

    impl CarrierReaper for RecordingReaper {
        fn arm(&self, pid: i32, grace: Duration) {
            self.armed.lock().expect("reaper record").push((pid, grace));
        }
    }

    fn request(root: &Path, label: &str) -> WedgeCaptureRequest {
        WedgeCaptureRequest {
            label: label.to_owned(),
            pid: 4242,
            run_id: Some("sep15-wedge".to_owned()),
            budget_ms: 2_000,
            elapsed_ms: 32_000,
            out_root: root.to_path_buf(),
        }
    }

    /// The capture directory is named for the probe so a gate log can point at
    /// it, and is private and owner-checked so the name being predictable buys
    /// an attacker nothing.
    #[test]
    fn capture_directory_is_private_owned_and_named_for_the_probe() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = tempfile::Builder::new()
            .prefix("carrick-wedge-dir")
            .tempdir_in("/tmp")
            .expect("test parent");
        let root = temp.path().join("postmortem");
        let dir = prepare_capture_directory(&root, "forkstackstorm", 4242).expect("directory");
        assert_eq!(dir, root.join("forkstackstorm-4242"));
        for path in [&root, &dir] {
            let mode = std::fs::metadata(path)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "{} must be private", path.display());
        }

        let link_root = temp.path().join("linked");
        std::os::unix::fs::symlink(temp.path(), &link_root).expect("symlink");
        let error = prepare_capture_directory(&link_root, "forkstackstorm", 4242)
            .expect_err("a symlinked root must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn empty_backtrace_is_an_error_not_a_capture() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-wedge-empty")
            .tempdir_in("/tmp")
            .expect("test parent");
        let root = temp.path().join("postmortem");
        let reaper = RecordingReaper::default();
        let error = capture_with(
            request(&root, "emptyprobe"),
            &StubRunner {
                bytes: 0,
                outcome: || StepOutcome::Completed,
            },
            &reaper,
        )
        .expect_err("an empty artifact is never a capture");
        assert!(
            matches!(&error, WedgeCaptureError::NoEvidence { dir, .. } if dir == &root.join("emptyprobe-4242")),
            "{error}"
        );
        assert_eq!(
            error.directory(),
            Some(root.join("emptyprobe-4242").as_path())
        );
        assert_eq!(reaper.armed.lock().expect("record").len(), 1);
    }

    #[test]
    fn capture_timeout_still_reaps_and_names_the_directory() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-wedge-timeout")
            .tempdir_in("/tmp")
            .expect("test parent");
        let root = temp.path().join("postmortem");
        let reaper = RecordingReaper::default();
        let error = capture_with(
            request(&root, "slowprobe"),
            &StubRunner {
                bytes: 16,
                outcome: || StepOutcome::TimedOut,
            },
            &reaper,
        )
        .expect_err("a timed-out capture is a failure");
        assert!(
            matches!(&error, WedgeCaptureError::TimedOut { step, .. } if *step == "backtrace"),
            "{error}"
        );
        assert_eq!(
            error.directory(),
            Some(root.join("slowprobe-4242").as_path())
        );
        let armed = reaper.armed.lock().expect("record");
        assert_eq!(armed.len(), 1, "the reap is armed even when capture fails");
        assert_eq!(armed[0].0, 4242);
    }

    #[test]
    fn a_complete_capture_names_both_artifacts_and_a_manifest() {
        let temp = tempfile::Builder::new()
            .prefix("carrick-wedge-complete")
            .tempdir_in("/tmp")
            .expect("test parent");
        let root = temp.path().join("postmortem");
        let reaper = RecordingReaper::default();
        let capture = capture_with(
            request(&root, "forkstackstorm"),
            &StubRunner {
                bytes: 64,
                outcome: || StepOutcome::Completed,
            },
            &reaper,
        )
        .expect("a complete capture");
        assert_eq!(capture.dir, root.join("forkstackstorm-4242"));
        assert_eq!(capture.backtrace, capture.dir.join("backtrace.txt"));
        assert_eq!(capture.core, Some(capture.dir.join("carrier.core")));
        let manifest =
            std::fs::read_to_string(capture.dir.join("manifest.json")).expect("manifest");
        assert!(
            manifest.contains("\"label\": \"forkstackstorm\""),
            "{manifest}"
        );
        assert!(manifest.contains("\"budget_ms\": 2000"), "{manifest}");
        assert!(
            manifest.contains("\"run_id\": \"sep15-wedge\""),
            "{manifest}"
        );
        assert_eq!(reaper.armed.lock().expect("record").len(), 1);
    }

    #[test]
    fn one_capture_per_carrier_lifetime() {
        let latch = AtomicBool::new(false);
        assert!(!latch.swap(true, Ordering::AcqRel));
        assert!(latch.swap(true, Ordering::AcqRel));
    }

    #[test]
    fn a_label_cannot_escape_the_capture_root() {
        assert_eq!(directory_name("../../etc", 7), "------etc-7");
        assert_eq!(directory_name("", 7), "carrier-7");
        assert_eq!(directory_name("generic probe/1", 7), "generic-probe-1-7");
    }
}
