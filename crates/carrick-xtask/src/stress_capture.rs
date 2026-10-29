//! Repository-owned signed-test stress orchestration. No guest service lives here.
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args as ClapArgs, ValueEnum};
use regex::bytes::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};

// Literal observation cadence for external process statuses and append-only
// diagnostic logs. It never repairs guest timing or coordinates our actors.
const OBSERVATION_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, ClapArgs, Serialize)]
pub struct Args {
    /// Already signed, symbol-bearing Rust test executable (never rebuilt).
    #[arg(long)]
    pub executable: PathBuf,
    /// Exact libtest name; runs ignored tests with one test thread.
    #[arg(long)]
    pub test: String,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..))]
    pub iterations: u32,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_seconds: u64,
    /// Earlier live-process deadline; must not exceed per-run timeout.
    #[arg(long)]
    pub hang_seconds: Option<u64>,
    #[arg(long, default_value = "carrick fatal|panicked at")]
    pub stderr_regex: Vec<String>,
    #[arg(long, value_delimiter = ',', default_value = "134,139")]
    pub exit_codes: Vec<i32>,
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "bt,ring,core"
    )]
    pub capture: Vec<Capture>,
    /// DTrace probe descriptions, e.g. carrick*:::hvpatch-executor-load-failure.
    #[arg(long)]
    pub probe: Vec<String>,
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..))]
    pub trace_seconds: u64,
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    pub capture_seconds: u64,
    #[arg(long, default_value_t = 8192)]
    pub ring_records: u32,
    /// Must not already exist: evidence is never overwritten.
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "stress")]
    pub run_id_prefix: String,
}

/// Internal detached launcher: DTrace must be armed before the test execs.
#[derive(Debug, ClapArgs)]
pub struct ChildArgs {
    #[arg(long)]
    executable: PathBuf,
    #[arg(long)]
    test: String,
    #[arg(long)]
    gate: PathBuf,
}
pub fn run_child(args: ChildArgs) -> Result<(), Error> {
    if !cfg!(target_os = "macos") {
        return Err(Error::Invalid("signed child requires macOS".into()));
    }
    let mut gate = UnixStream::connect(args.gate)?;
    gate.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut admission = [0];
    gate.read_exact(&mut admission)?;
    if admission != [1] {
        return Err(Error::Invalid("invalid startup admission".into()));
    }
    let error = Command::new(args.executable)
        .args([
            &args.test,
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .exec();
    Err(error.into())
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Serialize)]
pub enum Capture {
    Bt,
    Ring,
    Core,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Lease(#[from] crate::host_lease::HostLeaseError),
    #[error(transparent)]
    Load(#[from] crate::host_load::HostLoadError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Passed,
    Failed,
    Stderr,
    Signal,
    ExitCode,
    Hang,
    Interrupted,
    Error,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Stderr => "stderr",
            Self::Signal => "signal",
            Self::ExitCode => "exit_code",
            Self::Hang => "hang",
            Self::Interrupted => "interrupted",
            Self::Error => "error",
        }
    }
}

fn classify(
    status: Option<ExitStatus>,
    matched: bool,
    expired: bool,
    interrupted: bool,
    codes: &[i32],
) -> Option<Outcome> {
    if interrupted {
        return Some(Outcome::Interrupted);
    }
    if matched {
        return Some(Outcome::Stderr);
    }
    if let Some(status) = status {
        return Some(if status.signal().is_some() {
            Outcome::Signal
        } else if status.code().is_some_and(|code| codes.contains(&code)) {
            Outcome::ExitCode
        } else if status.success() {
            Outcome::Passed
        } else {
            Outcome::Failed
        });
    }
    expired.then_some(Outcome::Hang)
}

fn selected(outcome: Outcome) -> bool {
    !matches!(outcome, Outcome::Passed | Outcome::Failed)
}

#[derive(Serialize)]
struct Record {
    run_id: String,
    outcome: Outcome,
    exit_code: Option<i32>,
    signal: Option<i32>,
    elapsed_ms: u128,
    trace_events: Option<bool>,
    fatal_pid: Option<u32>,
    artifacts: Vec<PathBuf>,
    errors: Vec<String>,
}
#[derive(Serialize)]
struct Summary {
    schema: &'static str,
    binary: PathBuf,
    binary_sha256: String,
    test: String,
    configuration: Args,
    load: crate::host_load::HostLoadReport,
    counts: BTreeMap<String, usize>,
    stopped_run: Option<String>,
    runs: Vec<Record>,
}

/// setsid breaks terminal/session membership before exec. Stdio never inherits a tty.
fn detached(command: &mut Command) {
    command.stdin(Stdio::null());
    // SAFETY: only async-signal-safe setsid and errno access in the fork child.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

// Our startup actors use a notification, not a sleep-and-check protocol.
fn accept_start(listener: &UnixListener) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // BSD may inherit the listener's nonblocking status.
                stream.set_nonblocking(false)?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        let remaining = Duration::from_secs(10).saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "startup accept deadline",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let milliseconds = i32::try_from(remaining.as_millis()).map_err(io::Error::other)?;
        // SAFETY: one initialized pollfd for the listener owned for this call.
        let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn leader_exited(child: &Child) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: valid output storage; WNOWAIT preserves our child's PID custody.
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: waitid initialized the structure, including si_pid=0 if running.
    Ok(unsafe { info.assume_init().si_pid() } != 0)
}

fn kill_group(child: &Child) -> io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(io::Error::other)?;
    // SAFETY: group is created by setsid in this owned, unreaped child.
    if unsafe { libc::kill(-pid, libc::SIGKILL) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH)
            || (error.raw_os_error() == Some(libc::EPERM) && leader_exited(child)?)
        {
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn term_leader(child: &mut Child) -> io::Result<()> {
    // try_wait caches an exit status, preventing signals to a reused PID.
    if child.try_wait()?.is_none() {
        let pid = i32::try_from(child.id()).map_err(io::Error::other)?;
        // SAFETY: the live or unreaped child still reserves this PID.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
    }
    Ok(())
}

fn wait_bounded(child: &mut Child, bound: Duration) -> io::Result<Option<ExitStatus>> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if start.elapsed() >= bound {
            return Ok(None);
        }
        std::thread::sleep(OBSERVATION_INTERVAL);
    }
}

fn bounded(command: &mut Command, log: &Path, seconds: u64) -> Result<(), Error> {
    let output = File::create(log)?;
    command.stdout(output.try_clone()?).stderr(output);
    detached(command);
    let mut child = command.spawn()?;
    let observed = wait_bounded(&mut child, Duration::from_secs(seconds));
    let status = match observed {
        Ok(status) => status,
        Err(error) => {
            let cleanup = stop_local(&mut child);
            return Err(Error::Invalid(format!(
                "tool wait: {error}; cleanup: {cleanup:?}"
            )));
        }
    };
    if let Some(status) = status {
        if status.success() {
            return Ok(());
        }
        return Err(Error::Invalid(format!(
            "command exited {status}; see {}",
            log.display()
        )));
    }
    stop_local(&mut child)?;
    Err(Error::Invalid(format!(
        "command exceeded {seconds}s; see {}",
        log.display()
    )))
}

fn stop_local(child: &mut Child) -> Result<(), Error> {
    term_leader(child)?;
    if wait_bounded(child, Duration::from_secs(5))?.is_none() {
        kill_group(child)?;
        if wait_bounded(child, Duration::from_secs(5))?.is_none() {
            return Err(Error::Invalid("tool launcher did not reap".into()));
        }
    }
    Ok(())
}

fn scoped_argv(command: &str, dir: &Path) -> bool {
    let scope = dir.to_string_lossy();
    command.match_indices(scope.as_ref()).any(|(pos, _)| {
        command
            .as_bytes()
            .get(pos + scope.len())
            .is_none_or(|next| b"/ \t\"'".contains(next))
    })
}

fn tool_pids(dir: &Path) -> Result<Vec<u32>, Error> {
    let log = dir.join("tool-processes.log");
    bounded(
        Command::new("ps").args(["-axww", "-o", "pid=,comm=,command="]),
        &log,
        5,
    )?;
    Ok(fs::read_to_string(log)?
        .lines()
        .filter_map(|line| {
            let pid = line.split_whitespace().next()?.parse().ok()?;
            // No helper exclusion here: this scan runs outside the escalation
            // helper and must report even an orphaned helper as a survivor.
            scoped_argv(line, dir).then_some(pid)
        })
        .collect())
}

fn stop_tool(root: &Path, child: &mut Child, dir: &Path) -> Result<(), Error> {
    // Signal sudo itself: sudo relays TERM and gives DTrace its END flush.
    // Killing its group/leader with KILL first can orphan the privileged tool.
    let mut errors = Vec::new();
    if let Err(error) = term_leader(child) {
        errors.push(error.to_string());
    }
    if let Err(error) = wait_bounded(child, Duration::from_secs(5)) {
        errors.push(error.to_string());
    }
    let needs_reap = match tool_pids(dir) {
        Ok(pids) => !pids.is_empty(),
        Err(error) => {
            errors.push(error.to_string());
            true
        }
    };
    if needs_reap
        && let Err(error) = bounded(
            Command::new("sudo")
                .arg("-n")
                .arg(root.join("scripts/sudo/kill-capture.sh"))
                .arg(dir),
            &dir.join("tool-kill.log"),
            15,
        )
    {
        errors.push(error.to_string());
    }
    if let Err(error) = stop_local(child) {
        errors.push(error.to_string());
    }
    match tool_pids(dir) {
        Ok(pids) if pids.is_empty() => {}
        Ok(_) => errors.push("processes with the run directory in argv survived cleanup".into()),
        Err(error) => errors.push(error.to_string()),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::Invalid(errors.join("; ")))
    }
}

fn privileged_bounded(
    root: &Path,
    command: &mut Command,
    log: &Path,
    dir: &Path,
    bound: Duration,
) -> Result<(), Error> {
    let output = File::create(log)?;
    command.stdout(output.try_clone()?).stderr(output);
    detached(command);
    let mut child = command.spawn()?;
    let observed = wait_bounded(&mut child, bound);
    // Verify the scoped argv even when sudo exits before its root child.
    let cleanup = stop_tool(root, &mut child, dir);
    match (observed, cleanup) {
        (Ok(Some(status)), Ok(())) if status.success() => Ok(()),
        (status, cleanup) => Err(Error::Invalid(format!(
            "privileged tool result {status:?}; cleanup {cleanup:?}; see {}",
            log.display()
        ))),
    }
}

fn persist_cleanup_error(dir: &Path, error: &Error) {
    let written = (|| -> io::Result<()> {
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("cleanup-error.txt"))?;
        writeln!(log, "{error}")
    })();
    if let Err(write_error) = written {
        let _ = writeln!(
            io::stderr(),
            "stress-capture cleanup: {error}; cannot persist: {write_error}"
        );
    }
}

/// Owns cleanup even if monitoring or capture returns an error.
struct RunGuard<'a> {
    root: &'a Path,
    id: String,
    dir: PathBuf,
    child: Child,
    cleaned: bool,
}
impl RunGuard<'_> {
    fn cleanup(&mut self) -> Result<(), Error> {
        // An unreaped leader reserves its PID/group identity through the
        // scoped reap. Never signal a group after its leader was reaped and
        // its numeric identity could have been reused by another host lane.
        let group_owned = matches!(self.child.try_wait(), Ok(None));
        let group = if group_owned {
            kill_group(&self.child)
        } else {
            Ok(())
        };
        // Always attempt the scoped reap, even if killing the group failed.
        let scoped = bounded(
            Command::new("sudo")
                .arg("-n")
                .arg(self.root.join("scripts/sudo/kill.sh"))
                .arg(&self.id),
            &self.dir.join("cleanup.log"),
            15,
        );
        let waited = wait_bounded(&mut self.child, Duration::from_secs(5));
        self.cleaned = true;
        let mut errors = Vec::new();
        if let Err(error) = scoped {
            errors.push(error.to_string());
        }
        if let Err(error) = group {
            errors.push(error.to_string());
        }
        match waited {
            Ok(Some(_)) => {}
            Ok(None) => errors.push("test process did not reap within 5s".into()),
            Err(error) => errors.push(error.to_string()),
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Error::Invalid(errors.join("; ")))
        }
    }
}
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned
            && let Err(error) = self.cleanup()
        {
            persist_cleanup_error(&self.dir, &error);
        }
    }
}

/// Incremental stderr matching keeps memory bounded, including unterminated lines.
/// Regex matches spanning more than 64 KiB are outside this command's contract.
struct StderrTail {
    file: File,
    overlap: Vec<u8>,
}
impl StderrTail {
    fn matches(&mut self, patterns: &[Regex]) -> io::Result<bool> {
        let mut buffer = [0; 65536];
        for _ in 0..16 {
            let size = self.file.read(&mut buffer)?;
            if size == 0 {
                return Ok(false);
            }
            self.overlap.extend_from_slice(&buffer[..size]);
            let matched = patterns
                .iter()
                .any(|pattern| pattern.is_match(&self.overlap));
            // Keep two chunks so a complete short hold notice remains available
            // to the PID parser even when it straddles a read. Trim matches too:
            // a pending fatal must not retain unlimited subsequent stderr.
            let keep = self.overlap.len().saturating_sub(2 * 65536);
            self.overlap.drain(..keep);
            if matched {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn monitor(
    child: &mut Child,
    stderr: &Path,
    patterns: &[Regex],
    deadline: Duration,
    stop: &AtomicBool,
    codes: &[i32],
    mut tracer: Option<&mut TraceGuard>,
) -> Result<(Outcome, Option<ExitStatus>, Option<u32>), Error> {
    let start = Instant::now();
    let mut tail = StderrTail {
        file: File::open(stderr)?,
        overlap: Vec::new(),
    };
    let hold_notice =
        Regex::new(r"carrick fatal: holding [1-9][0-9]* s for a debugger \(pid [1-9][0-9]*\)\n")
            .map_err(|error| Error::Invalid(error.to_string()))?;
    let mut watched = patterns.to_vec();
    watched.push(hold_notice.clone());
    let mut pending = false;
    let mut fatal = false;
    let mut holding = None;
    loop {
        if let Some(trace) = tracer.as_deref_mut() {
            trace.enforce_deadline()?;
        }
        let status = child.try_wait()?;
        pending |= tail.matches(&watched)?;
        fatal |= tail
            .overlap
            .windows(b"carrick fatal".len())
            .any(|bytes| bytes == b"carrick fatal");
        if holding.is_none() && hold_notice.is_match(&tail.overlap) {
            holding = tail
                .overlap
                .split_inclusive(|byte| *byte == b'\n')
                .filter(|line| line.ends_with(b"\n"))
                .find_map(|line| {
                    std::str::from_utf8(line)
                        .ok()
                        .and_then(carrick_fatal::parse_debugger_hold_pid)
                        .and_then(|pid| u32::try_from(pid).ok())
                });
        }
        // The fatal line precedes the hold and may arrive in a separate write.
        // Wait for the hold announcement before stopping the process in LLDB;
        // an exited process still reports its matched stderr normally.
        let matched = holding.is_some()
            || (pending && (!fatal || status.is_some() || start.elapsed() >= deadline));
        // A fast failing child can leave more than one bounded read's worth
        // of stderr. Drain its recorded output before classifying the exit.
        if status.is_some()
            && !matched
            && !stop.load(Ordering::Relaxed)
            && tail.file.stream_position()? < tail.file.metadata()?.len()
        {
            if start.elapsed() >= deadline {
                return Err(Error::Invalid(
                    "stderr scan exceeded the run deadline".into(),
                ));
            }
            continue;
        }
        if let Some(outcome) = classify(
            status,
            matched,
            start.elapsed() >= deadline,
            stop.load(Ordering::Relaxed),
            codes,
        ) {
            return Ok((outcome, status, holding));
        }
        std::thread::sleep(OBSERVATION_INTERVAL);
    }
}

fn quote(path: &Path) -> String {
    format!(
        "\"{}\"",
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

fn capture(
    root: &Path,
    args: &Args,
    guard: &RunGuard<'_>,
    record: &mut Record,
    capture_started: Instant,
) {
    // Root libtest can own the VM itself; renamed descendants own carrier VMs.
    // Snapshot all exact run-id matches, never assume CLI parent owns the ring.
    let ps_path = guard.dir.join("processes.txt");
    if let Err(error) = bounded(
        Command::new("ps").args(["-axww", "-o", "pid=,lstart=,command="]),
        &ps_path,
        5,
    ) {
        record.errors.push(error.to_string());
        return;
    }
    record.artifacts.push(ps_path.clone());
    let mut pids = vec![guard.child.id()];
    let mut identities = BTreeMap::new();
    let needle = format!("carrick:{}:", guard.id);
    if let Ok(text) = fs::read_to_string(ps_path) {
        for line in text.lines() {
            if let Some(pid) = line
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok())
            {
                identities.insert(pid, line.trim().to_owned());
            }
            if line.contains(&needle)
                && let Some(pid) = line
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
            {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    if let Some(pid) = record.fatal_pid {
        if let Some(position) = pids.iter().position(|candidate| *candidate == pid) {
            pids.swap(0, position);
        } else {
            record.errors.push(format!(
                "fatal hold pid {pid} is outside the scoped process census"
            ));
        }
    }
    for pid in pids {
        if capture_started.elapsed() >= Duration::from_secs(args.capture_seconds) {
            record
                .errors
                .push("shared capture deadline exhausted".into());
            break;
        }
        let identity_log = guard.dir.join(format!("{pid}.identity.txt"));
        let checked = bounded(
            Command::new("ps").args(["-ww", "-p", &pid.to_string(), "-o", "pid=,lstart=,command="]),
            &identity_log,
            5,
        );
        record.artifacts.push(identity_log.clone());
        if checked.is_err()
            || fs::read_to_string(&identity_log)
                .ok()
                .as_deref()
                .map(str::trim)
                != identities.get(&pid).map(String::as_str)
        {
            record.errors.push(format!(
                "pid {pid} exited or changed identity before attach"
            ));
            continue;
        }
        let log = guard.dir.join(format!("{pid}.lldb.txt"));
        let core = guard.dir.join(format!("{pid}.core"));
        let commands = guard.dir.join(format!("{pid}.lldb.commands"));
        let mut script = format!(
            "target create {}\ncommand script import {}\nprocess attach --pid {pid}\n",
            quote(&args.executable),
            quote(&root.join("scripts/carrick_lldb.py"))
        );
        if args.capture.contains(&Capture::Bt) {
            script.push_str("thread backtrace all\n");
        }
        if args.capture.contains(&Capture::Ring) {
            script.push_str(&format!(
                "carrick eventring {}\ncarrick eventring --high-rate {}\n",
                args.ring_records, args.ring_records
            ));
        }
        if args.capture.contains(&Capture::Core) {
            script.push_str(&format!(
                "process save-core --style modified-memory {}\n",
                quote(&core)
            ));
        }
        script.push_str("detach\n");
        if let Err(error) = fs::write(&commands, script) {
            record.errors.push(error.to_string());
            continue;
        }
        record.artifacts.push(commands.clone());
        let mut command = Command::new("sudo");
        command
            .args(["-n", "/usr/bin/lldb", "--batch", "--source"])
            .arg(commands);
        let remaining =
            Duration::from_secs(args.capture_seconds).saturating_sub(capture_started.elapsed());
        if remaining.is_zero() {
            record
                .errors
                .push("shared capture deadline exhausted".into());
            break;
        }
        if let Err(error) = privileged_bounded(root, &mut command, &log, &guard.dir, remaining) {
            record.errors.push(error.to_string());
        }
        record.artifacts.push(log);
        if core.exists() {
            record.artifacts.push(core);
        } else if args.capture.contains(&Capture::Core) {
            record.errors.push(format!("core absent for pid {pid}"));
        }
    }
}

fn trace(args: &Args, guard: &RunGuard<'_>) -> Result<Option<Child>, Error> {
    if args.probe.is_empty() {
        return Ok(None);
    }
    let mut program =
        String::from("#pragma D option quiet\nBEGIN { printf(\"STRESS_TRACE_READY\\n\"); }\n");
    for probe in &args.probe {
        program.push_str(&format!("{probe} /pid == {} || progenyof({})/ {{ printf(\"probe=%s pid=%d arg0=%llu arg1=%llu arg2=%llu\\n\", probename, pid, arg0, arg1, arg2); }}\n", guard.child.id(), guard.child.id()));
    }
    program.push_str(&format!(
        "tick-1s {{ seconds++; }} tick-1s /seconds >= {}/ {{ exit(0); }}\n",
        args.trace_seconds
    ));
    let script = guard.dir.join("probes.d");
    fs::write(
        guard.dir.join("probes.sha256"),
        format!("{:x}\n", Sha256::digest(program.as_bytes())),
    )?;
    fs::write(&script, program)?;
    let log = File::create(guard.dir.join("dtrace.log"))?;
    let mut command = Command::new("sudo");
    command
        .args(["-n", "/usr/sbin/dtrace", "-Z", "-s"])
        .arg(script)
        .stdout(log.try_clone()?)
        .stderr(log);
    detached(&mut command);
    Ok(Some(command.spawn()?))
}

struct TraceGuard {
    root: PathBuf,
    child: Child,
    dir: PathBuf,
    started: Instant,
    bound: Duration,
    stopped: bool,
}
impl TraceGuard {
    fn enforce_deadline(&mut self) -> Result<(), Error> {
        if !self.stopped && self.started.elapsed() >= self.bound {
            self.stop()?;
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Error> {
        stop_tool(&self.root, &mut self.child, &self.dir)?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for TraceGuard {
    fn drop(&mut self) {
        if !self.stopped
            && let Err(error) = self.stop()
        {
            persist_cleanup_error(&self.dir, &error);
        }
    }
}

fn wait_trace_ready(trace: &mut TraceGuard) -> Result<(), Error> {
    let start = Instant::now();
    let mut tail = StderrTail {
        file: File::open(trace.dir.join("dtrace.log"))?,
        overlap: Vec::new(),
    };
    let ready = Regex::new("STRESS_TRACE_READY").map_err(|e| Error::Invalid(e.to_string()))?;
    loop {
        if tail.matches(std::slice::from_ref(&ready))? {
            return Ok(());
        }
        if trace.child.try_wait()?.is_some() || start.elapsed() >= Duration::from_secs(10) {
            return Err(Error::Invalid(
                "DTrace did not arm before test startup; see dtrace.log".into(),
            ));
        }
        std::thread::sleep(OBSERVATION_INTERVAL);
    }
}

struct SignalGuard(Vec<signal_hook::SigId>);
impl Drop for SignalGuard {
    fn drop(&mut self) {
        for signal in self.0.drain(..) {
            signal_hook::low_level::unregister(signal);
        }
    }
}

pub fn run(root: &Path, mut args: Args) -> Result<(), Error> {
    if !cfg!(target_os = "macos") {
        return Err(Error::Invalid(
            "stress-capture execution requires macOS/HVF; unit tests are portable".into(),
        ));
    }
    if args
        .hang_seconds
        .is_some_and(|n| n == 0 || n > args.timeout_seconds)
        || args.run_id_prefix.is_empty()
        || !args
            .run_id_prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::Invalid(
            "invalid hang threshold or run-id prefix".into(),
        ));
    }
    for probe in &args.probe {
        if !probe.starts_with("carrick")
            || !probe
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_*:-?".contains(&b))
            || probe.split(':').count() != 4
        {
            return Err(Error::Invalid(format!(
                "invalid Carrick USDT probe: {probe}"
            )));
        }
    }
    let patterns = args
        .stderr_regex
        .iter()
        .map(|s| Regex::new(s).map_err(|e| Error::Invalid(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let root = root.canonicalize()?;
    args.executable = args.executable.canonicalize()?;
    for path in [&root, &args.executable, &args.output] {
        if path
            .to_str()
            .is_none_or(|value| value.chars().any(char::is_control))
        {
            return Err(Error::Invalid(
                "capture paths require UTF-8 without control characters".into(),
            ));
        }
    }
    let lease = crate::host_lease::HostLease::acquire(crate::host_lease::HostLeaseMode::Carrick)?;
    let load = crate::host_load::check()?;
    fs::create_dir(&args.output)?;
    args.output = args.output.canonicalize()?;
    if args
        .output
        .to_str()
        .is_none_or(|value| value.chars().any(char::is_control))
    {
        return Err(Error::Invalid(
            "output path requires UTF-8 without control characters".into(),
        ));
    }
    bounded(
        Command::new("codesign")
            .args(["--verify", "--strict"])
            .arg(&args.executable),
        &args.output.join("codesign.log"),
        10,
    )?;
    let entitlement_log = args.output.join("entitlements.log");
    bounded(
        Command::new("codesign")
            .args(["--display", "--entitlements", ":-"])
            .arg(&args.executable),
        &entitlement_log,
        10,
    )?;
    let entitlements = fs::read_to_string(&entitlement_log)?;
    if !entitlements.contains("<key>com.apple.security.hypervisor</key>") {
        return Err(Error::Invalid(
            "test executable lacks hypervisor entitlement".into(),
        ));
    }
    let list_log = args.output.join("test-list.log");
    bounded(
        Command::new(&args.executable).args([&args.test, "--exact", "--list"]),
        &list_log,
        10,
    )?;
    let listed = fs::read_to_string(list_log)?;
    if listed
        .lines()
        .filter(|line| *line == format!("{}: test", args.test))
        .count()
        != 1
    {
        return Err(Error::Invalid(
            "exact test name must select exactly one test".into(),
        ));
    }
    let mut file = File::open(&args.executable)?;
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash)?;
    let digest = format!("{:x}", hash.finalize());
    let stop = Arc::new(AtomicBool::new(false));
    let mut signals = SignalGuard(Vec::new());
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        signals
            .0
            .push(signal_hook::flag::register(signal, stop.clone())?);
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let mut summary = Summary {
        schema: "carrick.stress-capture.v1",
        binary: args.executable.clone(),
        binary_sha256: digest,
        test: args.test.clone(),
        configuration: args.clone(),
        load,
        counts: BTreeMap::new(),
        stopped_run: None,
        runs: Vec::new(),
    };
    run_iterations(args.iterations, |index| {
        let id = format!(
            "{}-{}-{nonce}-{index}",
            args.run_id_prefix,
            std::process::id()
        );
        let dir = args.output.join(&id);
        let record = run_iteration(&root, &args, &lease, &patterns, &stop, id.clone(), dir);
        let halted = selected(record.outcome) || !record.errors.is_empty();
        *summary
            .counts
            .entry(record.outcome.name().to_owned())
            .or_default() += 1;
        if halted {
            summary.stopped_run = Some(id);
        }
        summary.runs.push(record);
        fs::write(
            args.output.join("summary.json"),
            serde_json::to_vec_pretty(&summary)?,
        )?;
        let table = render(&summary);
        fs::write(args.output.join("summary.txt"), &table)?;
        Ok(halted)
    })?;
    drop(signals);
    println!("{}", render(&summary));
    if summary.stopped_run.is_some()
        || summary
            .runs
            .iter()
            .any(|record| record.outcome == Outcome::Failed)
    {
        return Err(Error::Invalid(format!(
            "stress stopped; see {}",
            args.output.join("summary.json").display()
        )));
    }
    Ok(())
}
// One iteration always returns a record, including failures before spawn,
// startup admission failures, trace-read errors and explicit cleanup errors.
fn run_iteration(
    root: &Path,
    args: &Args,
    lease: &crate::host_lease::HostLease,
    patterns: &[Regex],
    stop: &AtomicBool,
    id: String,
    dir: PathBuf,
) -> Record {
    let start = Instant::now();
    let stdout = dir.join("stdout.log");
    let stderr = dir.join("stderr.log");
    let mut record = Record {
        run_id: id.clone(),
        outcome: Outcome::Error,
        exit_code: None,
        signal: None,
        elapsed_ms: 0,
        trace_events: None,
        fatal_pid: None,
        artifacts: vec![
            stdout.clone(),
            stderr.clone(),
            dir.join("cleanup.log"),
            dir.join("cleanup-error.txt"),
            dir.join("tool-processes.log"),
        ],
        errors: Vec::new(),
    };
    let mut guard = None;
    let mut tracer = None;
    let observed = (|| -> Result<_, Error> {
        fs::create_dir(&dir)?;
        fs::write(dir.join(".stress-capture-run"), &id)?;
        // Darwin AF_UNIX paths are short; TempDir owns the startup socket.
        let gate_dir = tempfile::Builder::new()
            .prefix("carrick-stress-")
            .tempdir_in("/tmp")?;
        let gate = gate_dir.path().join("start.sock");
        let listener = UnixListener::bind(&gate)?;
        listener.set_nonblocking(true)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("stress-capture-child")
            .arg("--executable")
            .arg(&args.executable)
            .arg("--test")
            .arg(&args.test)
            .arg("--gate")
            .arg(&gate)
            .env("CARRICK_RUN_ID", &id)
            .env(
                "CARRICK_FATAL_HOLD_SECS",
                args.capture_seconds
                    .saturating_add(10)
                    .min(u64::from(u32::MAX))
                    .to_string(),
            )
            .stdout(File::create(&stdout)?)
            .stderr(File::create(&stderr)?);
        lease.configure_command(&mut command)?;
        detached(&mut command);
        guard = Some(RunGuard {
            root,
            id: id.clone(),
            dir: dir.clone(),
            child: command.spawn()?,
            cleaned: false,
        });
        let active = guard
            .as_mut()
            .ok_or_else(|| Error::Invalid("missing run custody".into()))?;
        let mut startup = accept_start(&listener)?;
        tracer = trace(args, active)?.map(|child| TraceGuard {
            root: root.to_owned(),
            child,
            dir: dir.clone(),
            started: Instant::now(),
            bound: Duration::from_secs(args.trace_seconds.saturating_add(5)),
            stopped: false,
        });
        if let Some(trace) = tracer.as_mut() {
            wait_trace_ready(trace)?;
        }
        startup.write_all(&[1])?;
        monitor(
            &mut active.child,
            &stderr,
            patterns,
            Duration::from_secs(args.hang_seconds.unwrap_or(args.timeout_seconds)),
            stop,
            &args.exit_codes,
            tracer.as_mut(),
        )
    })();
    // This budget starts at observation, so stopping a tracer cannot consume
    // the fatal hold and then silently start a fresh capture budget per PID.
    let capture_started = Instant::now();
    if let Some(trace) = tracer.as_mut() {
        if let Err(error) = trace.stop() {
            persist_cleanup_error(&dir, &error);
            record.errors.push(error.to_string());
        }
        record.artifacts.extend([
            dir.join("dtrace.log"),
            dir.join("probes.d"),
            dir.join("probes.sha256"),
            dir.join("tool-kill.log"),
        ]);
        let events = (|| -> Result<bool, Error> {
            let mut tail = StderrTail {
                file: File::open(dir.join("dtrace.log"))?,
                overlap: Vec::new(),
            };
            let event = Regex::new("probe=").map_err(|error| Error::Invalid(error.to_string()))?;
            Ok(tail.matches(std::slice::from_ref(&event))?)
        })();
        match events {
            Ok(fired) => record.trace_events = Some(fired),
            Err(error) => record.errors.push(error.to_string()),
        }
    }
    match observed {
        Ok((outcome, status, fatal_pid)) => {
            record.outcome = outcome;
            record.exit_code = status.and_then(|status| status.code());
            record.signal = status.and_then(|status| status.signal());
            record.fatal_pid = fatal_pid;
            if matches!(outcome, Outcome::Hang | Outcome::Stderr)
                && status.is_none()
                && let Some(active) = guard.as_ref()
            {
                capture(root, args, active, &mut record, capture_started);
            }
        }
        Err(error) => record.errors.push(error.to_string()),
    }
    if selected(record.outcome) && record.trace_events == Some(false) {
        record
            .errors
            .push("DTrace recorded zero scoped probe events; trace is inconclusive".into());
    }
    if let Some(active) = guard.as_mut()
        && let Err(error) = active.cleanup()
    {
        persist_cleanup_error(&dir, &error);
        record.errors.push(error.to_string());
    }
    record.elapsed_ms = start.elapsed().as_millis();
    record
}

// The production loop and fake-child tests share first-stop and iteration limits.
fn run_iterations(
    mut count: u32,
    mut iteration: impl FnMut(u32) -> Result<bool, Error>,
) -> Result<(), Error> {
    let mut index = 1;
    while count > 0 {
        if iteration(index)? {
            break;
        }
        count -= 1;
        index = index.saturating_add(1);
    }
    Ok(())
}

fn render(summary: &Summary) -> String {
    let mut text = format!(
        "binary SHA-256: {}\nRUN  OUTCOME      MS       ARTIFACTS ERRORS\n",
        summary.binary_sha256
    );
    for (index, record) in summary.runs.iter().enumerate() {
        text.push_str(&format!(
            "{:4} {:12?} {:8} {:9} {}\n",
            index + 1,
            record.outcome,
            record.elapsed_ms,
            record.artifacts.len(),
            record.errors.len()
        ));
        text.push_str(&format!("     run-id: {}\n", record.run_id));
        for path in &record.artifacts {
            text.push_str(&format!("     {}\n", path.display()));
        }
        for error in &record.errors {
            text.push_str(&format!("     error: {error}\n"));
        }
    }
    text.push_str(&format!(
        "counts: {:?}\nstopped: {:?}\n",
        summary.counts, summary.stopped_run
    ));
    text
}

#[cfg(test)]
mod serial_host {
    // Fixture setup failures should identify the failed prerequisite.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::io::{Seek, SeekFrom};
    struct TestChild(Child);
    impl Drop for TestChild {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = kill_group(&self.0);
                let _ = wait_bounded(&mut self.0, Duration::from_secs(2));
            }
        }
    }

    #[test]
    fn serial_host_scoped_helper_reaps_tools_and_preserves_sibling_prefix() {
        use std::os::unix::fs::symlink;
        let base = tempfile::tempdir().expect("directory");
        let run = base.path().join("run [1]\\t");
        let sibling = base.path().join("run [1]\\t-other");
        let spawn = |dir: &Path| {
            fs::create_dir(dir).expect("run dir");
            fs::write(dir.join(".stress-capture-run"), "test").expect("marker");
            let program = dir.join("tool");
            symlink("/bin/sleep", &program).expect("tool path");
            let mut command = Command::new(program);
            command
                .arg("60")
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            detached(&mut command);
            TestChild(command.spawn().expect("fake tool"))
        };
        let mut target = spawn(&run);
        let mut survivor = spawn(&sibling);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        bounded(
            Command::new(root.join("scripts/sudo/kill-capture.sh")).arg(&run),
            &base.path().join("helper.log"),
            10,
        )
        .expect("scoped helper");
        assert!(
            wait_bounded(&mut target.0, Duration::from_secs(5))
                .expect("reap")
                .is_some()
        );
        assert!(survivor.0.try_wait().expect("sibling status").is_none());
        assert!(tool_pids(&run).expect("scope verification").is_empty());
        assert!(!scoped_argv(&sibling.join("tool").to_string_lossy(), &run));
        assert!(scoped_argv(
            &run.join("commands with spaces").to_string_lossy(),
            &run
        ));
    }

    #[test]
    fn serial_host_tool_term_reaps_and_preserves_end_output() {
        let dir = tempfile::tempdir().expect("directory");
        let stderr = dir.path().join("tool.log");
        let (reader, _writer) = UnixStream::pair().expect("notification stream");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "trap 'echo END; exit 0' TERM; echo READY; read line"])
            .stdout(File::create(&stderr).expect("log"))
            .stderr(Stdio::null());
        detached(&mut command);
        command.stdin(Stdio::from(std::os::fd::OwnedFd::from(reader)));
        let mut child = TestChild(command.spawn().expect("tool"));
        let mut tail = StderrTail {
            file: File::open(&stderr).expect("log"),
            overlap: Vec::new(),
        };
        let ready_pattern = Regex::new("READY").expect("pattern");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !tail
            .matches(std::slice::from_ref(&ready_pattern))
            .expect("read")
        {
            assert!(Instant::now() < deadline, "tool did not arm");
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        stop_tool(&root, &mut child.0, dir.path()).expect("TERM cleanup");
        assert!(
            fs::read_to_string(&stderr)
                .expect("END output")
                .contains("END")
        );
    }

    #[test]
    fn serial_host_privileged_tool_timeout_reaps_scoped_argv() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("directory");
        fs::write(dir.path().join(".stress-capture-run"), "test").expect("marker");
        let program = dir.path().join("fake-lldb");
        symlink("/bin/sleep", &program).expect("tool path");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let error = privileged_bounded(
            &root,
            Command::new(program).arg("60"),
            &dir.path().join("capture.log"),
            dir.path(),
            Duration::from_millis(10),
        )
        .expect_err("capture deadline");
        assert!(error.to_string().contains("Ok(None)"));
        assert!(
            tool_pids(dir.path())
                .expect("scoped verification")
                .is_empty()
        );
    }

    #[test]
    fn serial_host_waitid_observes_exit_without_reaping_pid_custody() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exit 0"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detached(&mut command);
        let mut child = TestChild(command.spawn().expect("child"));
        let deadline = Instant::now() + Duration::from_secs(30);
        while !leader_exited(&child.0).expect("WNOWAIT") {
            assert!(Instant::now() < deadline);
            std::thread::sleep(OBSERVATION_INTERVAL);
        }
        assert!(leader_exited(&child.0).expect("WNOWAIT remains observable"));
        kill_group(&child.0).expect("zombie group cleanup");
        assert!(child.0.try_wait().expect("reap").expect("status").success());
    }

    #[test]
    fn serial_host_setup_error_still_returns_a_serializable_run_record() {
        use clap::Parser;
        let base = tempfile::tempdir().expect("directory");
        let cli = crate::cli::Cli::try_parse_from([
            "xtask",
            "stress-capture",
            "--executable",
            "/not/a/test",
            "--test",
            "test",
            "--output",
            "/not/output",
        ])
        .expect("CLI");
        let crate::cli::Commands::StressCapture(args) = cli.command else {
            unreachable!()
        };
        let lease = crate::host_lease::HostLease::acquire_path(
            &base.path().join("lease"),
            crate::host_lease::HostLeaseMode::Carrick,
        )
        .expect("isolated lease");
        let dir = base.path().join("already-exists");
        fs::create_dir(&dir).expect("inject create_dir failure");
        let record = run_iteration(
            base.path(),
            &args,
            &lease,
            &[],
            &AtomicBool::new(false),
            "setup-error".into(),
            dir.clone(),
        );
        assert_eq!(record.outcome, Outcome::Error);
        assert!(!record.errors.is_empty());
        let json = serde_json::to_value(&record).expect("JSON record");
        assert_eq!(json["run_id"], "setup-error");
        assert_eq!(json["outcome"], "error");
        for message in ["trace cleanup denied", "guest cleanup denied"] {
            persist_cleanup_error(&dir, &Error::Invalid(message.into()));
        }
        let cleanup =
            fs::read_to_string(dir.join("cleanup-error.txt")).expect("durable cleanup errors");
        assert!(cleanup.contains("trace cleanup denied"));
        assert!(cleanup.contains("guest cleanup denied"));
    }

    #[test]
    fn classify_exit_signal_pattern_and_deadline() {
        assert_eq!(
            classify(Some(ExitStatus::from_raw(0)), false, true, false, &[139]),
            Some(Outcome::Passed)
        );
        assert_eq!(
            classify(
                Some(ExitStatus::from_raw(139 << 8)),
                false,
                false,
                false,
                &[139]
            ),
            Some(Outcome::ExitCode)
        );
        assert_eq!(
            classify(Some(ExitStatus::from_raw(11)), false, false, false, &[]),
            Some(Outcome::Signal)
        );
        assert_eq!(
            classify(None, true, true, false, &[]),
            Some(Outcome::Stderr)
        );
        assert_eq!(classify(None, false, true, false, &[]), Some(Outcome::Hang));
        assert_eq!(classify(None, false, false, false, &[]), None);
        assert_eq!(
            classify(None, false, false, true, &[]),
            Some(Outcome::Interrupted)
        );
    }
    #[test]
    fn serial_host_fake_child_monitor_and_detachment() {
        let dir = tempfile::tempdir().expect("directory");
        let patterns = [Regex::new("(?m)^carrick fatal$").expect("regex")];
        for (script, expected) in [
            ("exit 0", Outcome::Passed),
            ("exit 1", Outcome::Failed),
            (
                "echo 'carrick fatal' >&2; echo 'carrick fatal: holding 5 s for a debugger (pid 123)' >&2; sleep 5",
                Outcome::Stderr,
            ),
            (
                "echo 'carrick fatal: holding 5 s for a debugger (pid 123)' >&2; sleep 5",
                Outcome::Stderr,
            ),
            ("echo 'carrick fatal' >&2; exit 134", Outcome::Stderr),
            ("echo 'carrick fatal' >&2; sleep 60", Outcome::Stderr),
            ("sleep 60", Outcome::Hang),
            ("kill -KILL $$", Outcome::Signal),
        ] {
            let stderr = dir.path().join("stderr");
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", script])
                .stdout(Stdio::null())
                .stderr(File::create(&stderr).expect("stderr"));
            detached(&mut cmd);
            let mut child = cmd.spawn().expect("fake child");
            let observed_from = Instant::now();
            let (outcome, _, _) = monitor(
                &mut child,
                &stderr,
                &patterns,
                if script == "sleep 60" || script == "echo 'carrick fatal' >&2; sleep 60" {
                    Duration::from_millis(200)
                } else {
                    Duration::from_secs(30)
                },
                &AtomicBool::new(false),
                &[134, 139],
                None,
            )
            .expect("monitor");
            assert_eq!(outcome, expected);
            if script == "echo 'carrick fatal' >&2; sleep 60" {
                assert!(observed_from.elapsed() >= Duration::from_millis(200));
            }
            if outcome == Outcome::Hang {
                let pid = i32::try_from(child.id()).expect("pid fits");
                // SAFETY: read-only identity queries on our live fake child.
                assert_eq!(unsafe { libc::getsid(pid) }, pid);
                assert_eq!(unsafe { libc::getpgid(pid) }, pid);
            }
            if child.try_wait().expect("status").is_none() {
                kill_group(&child).expect("kill");
            }
            assert!(
                wait_bounded(&mut child, Duration::from_secs(2))
                    .expect("reap")
                    .is_some()
            );
        }
    }
    #[test]
    fn run_loop_stops_at_first_selected_fake_child_and_respects_count() {
        let dir = tempfile::tempdir().expect("directory");
        for (limit, stop_at, expected) in [(5, 3, 3), (2, 3, 2)] {
            let mut observed = Vec::new();
            run_iterations(limit, |index| {
                let stderr = dir.path().join("loop.err");
                let mut command = Command::new("/bin/sh");
                command
                    .args([
                        "-c",
                        if index == stop_at {
                            "exit 139"
                        } else {
                            "exit 0"
                        },
                    ])
                    .stdout(Stdio::null())
                    .stderr(File::create(&stderr)?);
                detached(&mut command);
                let mut child = command.spawn()?;
                let (outcome, _, _) = monitor(
                    &mut child,
                    &stderr,
                    &[],
                    Duration::from_secs(30),
                    &AtomicBool::new(false),
                    &[139],
                    None,
                )?;
                if child.try_wait()?.is_none() {
                    kill_group(&child)?;
                }
                observed.push(outcome);
                Ok(selected(outcome))
            })
            .expect("loop");
            assert_eq!(observed.len(), expected);
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn execution_is_refused_on_linux_before_output_or_guest_launch() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from([
            "xtask",
            "stress-capture",
            "--executable",
            "/not/a/test",
            "--test",
            "test",
            "--output",
            "/not/an/output",
        ])
        .expect("CLI");
        let crate::cli::Commands::StressCapture(args) = cli.command else {
            unreachable!()
        };
        let error = run(Path::new("."), args).expect_err("macOS gate");
        assert!(error.to_string().contains("requires macOS"));
    }

    #[test]
    fn startup_notification_releases_the_connected_child() {
        let dir = tempfile::tempdir_in("/tmp").expect("directory");
        let path = dir.path().join("start.sock");
        let listener = UnixListener::bind(&path).expect("listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let mut client = UnixStream::connect(&path).expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read bound");
        let mut server = accept_start(&listener).expect("bounded accept");
        server.write_all(&[1]).expect("notify");
        let mut admission = [0];
        client.read_exact(&mut admission).expect("notification");
        assert_eq!(admission, [1]);
    }

    #[test]
    fn matches_across_stderr_chunks() {
        let mut file = tempfile::tempfile().expect("file");
        use std::io::Write;
        file.write_all(b"carrick fa").expect("write");
        file.seek(SeekFrom::Start(0)).expect("seek");
        let mut tail = StderrTail {
            file,
            overlap: Vec::new(),
        };
        let patterns = [Regex::new("carrick fatal").expect("regex")];
        assert!(!tail.matches(&patterns).expect("read"));
        tail.file.write_all(b"tal").expect("append");
        tail.file.seek(SeekFrom::Current(-3)).expect("seek");
        assert!(tail.matches(&patterns).expect("read"));
    }
}
