//! A KVM witness bounded in a child test process: a lost wake must fail
//! within its bound, never hang the lane, and a child that reaches its bound
//! is captured through its run-scoped debug endpoint before it is killed.
//!
//! The child runs under its own `CARRICK_RUN_ID`, so the pool publishes
//! `carrick debug zonedump --run-id <id>` for it. At the bound the parent
//! takes the same non-aborting capture, keeps the whole post-mortem as JSON
//! under `CARGO_TARGET_TMPDIR`, and prints its zone report (every slot, the
//! idle and queued maps, every parked record with its saved syscall) in the
//! failure, so a hang arrives with its real values.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The child's marker: the exact test it runs.
const CHILD: &str = "CARRICK_BOUNDED_WITNESS_CHILD";

/// Run `test` bounded by `bound` in a child test process and assert it
/// passed. Returns `true` in the child, which then runs the witness body,
/// and `false` in the parent once the child passed.
pub fn in_bounded_child(test: &str, bound: Duration) -> bool {
    if is_bounded_child(test) {
        return true;
    }
    let child = run_bounded_child(test, bound);
    assert!(child.passed(), "{child}");
    false
}

/// Whether this process is the bounded child running `test`.
pub fn is_bounded_child(test: &str) -> bool {
    std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(test))
}

/// What one bounded child did.
pub struct BoundedChild {
    pub test: String,
    pub run_id: String,
    /// `None` when the child reached its bound and was killed.
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
    /// At the bound: the capture's zone report, or why there was none.
    pub capture: Option<Result<String, String>>,
    /// At the bound: where the whole post-mortem was kept.
    pub post_mortem: Option<std::path::PathBuf>,
}

impl BoundedChild {
    /// The child exited zero after running exactly this witness.
    pub fn passed(&self) -> bool {
        self.status.is_some_and(|status| status.success())
            && self.stdout.contains("test result: ok. 1 passed")
    }
}

impl std::fmt::Display for BoundedChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => writeln!(
                f,
                "bounded child {} ({}): {status:?}",
                self.test, self.run_id
            )?,
            None => writeln!(
                f,
                "bounded child {} ({}): reached its bound and was killed",
                self.test, self.run_id
            )?,
        }
        if let Some(capture) = &self.capture {
            match capture {
                Ok(report) => writeln!(f, "zone capture at the bound:\n{report}")?,
                Err(error) => writeln!(f, "zone capture at the bound failed: {error}")?,
            }
        }
        if let Some(path) = &self.post_mortem {
            writeln!(f, "post-mortem: {}", path.display())?;
        }
        write!(
            f,
            "--- stdout\n{}\n--- stderr\n{}",
            self.stdout, self.stderr
        )
    }
}

/// Run `test` in a child test process under its own run id, and capture its
/// zone if it is still running at `bound`.
pub fn run_bounded_child(test: &str, bound: Duration) -> BoundedChild {
    let run_id = format!("kvm-witness-{}-{test}", std::process::id());
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            test,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, test)
        .env("CARRICK_RUN_ID", &run_id)
        // Its own process group: a process the witness starts (a native
        // oracle) inherits the output pipes, and the group kill below ends
        // it with the child, so the readers always reach EOF.
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bounded child");
    let stdout = drain(child.stdout.take().expect("child stdout"));
    let stderr = drain(child.stderr.take().expect("child stderr"));
    let exited = exit_notice(child.id());

    let mut capture = None;
    let mut post_mortem = None;
    let reached_bound = match exited.recv_timeout(bound) {
        Ok(observed) => {
            observed.expect("observe the bounded child's exit");
            false
        }
        Err(_) => {
            // The child is unreaped (the notice never reaps), so its pid
            // still names it: capture it before the kill below.
            capture = Some(
                carrick_kernel::kernel::debug::capture(&run_id)
                    .map_err(|error| error.to_string())
                    .and_then(|capture| {
                        post_mortem = keep_post_mortem(&run_id, &capture);
                        capture
                            .zone_report()
                            .ok_or_else(|| "the capture carries no zone state".to_owned())
                    }),
            );
            true
        }
    };
    // End the child's whole group, whether the child exited or reached its
    // bound. The leader is still unreaped, so its pid, the group's id,
    // cannot have been recycled.
    // SAFETY: kill(2) on the group this function created.
    let _ = unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
    let status = child.wait().expect("reap bounded child");
    // A child still running at its bound failed, however it ended after.
    let status = (!reached_bound).then_some(status);
    BoundedChild {
        test: test.to_owned(),
        run_id,
        status,
        stdout: stdout.join().expect("child stdout reader"),
        stderr: stderr.join().expect("child stderr reader"),
        capture,
        post_mortem,
    }
}

fn drain(mut pipe: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = pipe.read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    })
}

/// One message when `pid` exits, without reaping it (`WNOWAIT`), so the
/// owner's `Child` stays the only reaper and its pid is never recycled under
/// a later kill.
fn exit_notice(pid: u32) -> mpsc::Receiver<std::io::Result<()>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let observed = loop {
            // SAFETY: waitid writes only the zeroed siginfo it is given.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 {
                break Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                break Err(error);
            }
        };
        let _ = tx.send(observed);
    });
    rx
}

fn keep_post_mortem(
    run_id: &str,
    capture: &carrick_kernel::kernel::debug::PostMortem,
) -> Option<std::path::PathBuf> {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("bounded-child");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{run_id}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(capture).ok()?).ok()?;
    Some(path)
}
