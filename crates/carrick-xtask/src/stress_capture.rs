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

fn kill_group(child: &Child) -> io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(io::Error::other)?;
    // SAFETY: group is created by setsid in this owned child before exec.
    if unsafe { libc::kill(-pid, libc::SIGKILL) } == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
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
    let status = wait_bounded(&mut child, Duration::from_secs(seconds))?;
    if let Some(status) = status {
        if status.success() {
            return Ok(());
        }
        return Err(Error::Invalid(format!(
            "command exited {status}; see {}",
            log.display()
        )));
    }
    if let Err(error) = kill_group(&child) {
        if error.raw_os_error() != Some(libc::EPERM) {
            return Err(error.into());
        }
        let group = format!("-{}", child.id());
        let mut kill = Command::new("sudo");
        kill.args(["-n", "/bin/kill", "-KILL", "--", &group])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detached(&mut kill);
        let mut killer = kill.spawn()?;
        if !wait_bounded(&mut killer, Duration::from_secs(5))?
            .is_some_and(|status| status.success())
        {
            let _ = kill_group(&killer);
            let _ = wait_bounded(&mut killer, Duration::from_secs(5));
            return Err(Error::Invalid("privileged tool cleanup failed".into()));
        }
    }
    let _ = wait_bounded(&mut child, Duration::from_secs(5))?;
    Err(Error::Invalid(format!(
        "command exceeded {seconds}s; see {}",
        log.display()
    )))
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
        // Mark only after attempting both cleanup paths.
        let scoped = bounded(
            Command::new("sudo")
                .arg("-n")
                .arg(self.root.join("scripts/sudo/kill.sh"))
                .arg(&self.id),
            &self.dir.join("cleanup.log"),
            15,
        );
        let group = if group_owned {
            kill_group(&self.child)
        } else {
            Ok(())
        };
        let waited = wait_bounded(&mut self.child, Duration::from_secs(5));
        self.cleaned = true;
        scoped?;
        group?;
        if waited?.is_none() {
            return Err(Error::Invalid("test process did not reap within 5s".into()));
        }
        Ok(())
    }
}
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
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
            if patterns
                .iter()
                .any(|pattern| pattern.is_match(&self.overlap))
            {
                return Ok(true);
            }
            let keep = self.overlap.len().saturating_sub(65536);
            self.overlap.drain(..keep);
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
) -> Result<(Outcome, Option<ExitStatus>), Error> {
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
    let mut holding = false;
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
        holding |= hold_notice.is_match(&tail.overlap);
        // The fatal line precedes the hold and may arrive in a separate write.
        // Wait for the hold announcement before stopping the process in LLDB;
        // an exited process still reports its matched stderr normally.
        let matched =
            holding || (pending && (!fatal || status.is_some() || start.elapsed() >= deadline));
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
            return Ok((outcome, status));
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

fn capture(root: &Path, args: &Args, guard: &RunGuard<'_>, record: &mut Record) {
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
    for pid in pids {
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
        let mut command = Command::new("sudo");
        command.args(["-n", "/usr/bin/lldb"]);
        command
            .args(["--batch", "-o"])
            .arg(format!("target create {}", quote(&args.executable)))
            .arg("-o")
            .arg(format!(
                "command script import {}",
                quote(&root.join("scripts/carrick_lldb.py"))
            ))
            .arg("-o")
            .arg(format!("process attach --pid {pid}"));
        if args.capture.contains(&Capture::Bt) {
            command.args(["-o", "thread backtrace all"]);
        }
        if args.capture.contains(&Capture::Ring) {
            command
                .arg("-o")
                .arg(format!("carrick eventring {}", args.ring_records));
            command.arg("-o").arg(format!(
                "carrick eventring --high-rate {}",
                args.ring_records
            ));
        }
        if args.capture.contains(&Capture::Core) {
            command.arg("-o").arg(format!(
                "process save-core --style modified-memory {}",
                quote(&core)
            ));
        }
        command.args(["-o", "detach"]);
        if let Err(error) = bounded(&mut command, &log, args.capture_seconds) {
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
        stop_trace(&mut self.child, &self.dir)?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for TraceGuard {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
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

// Match literal artifact paths rather than regexes or a global dtrace reap.
fn trace_pids(dir: &Path) -> Result<Vec<u32>, Error> {
    let log = dir.join("dtrace-processes.log");
    bounded(
        Command::new("ps").args(["-axww", "-o", "pid=,command="]),
        &log,
        5,
    )?;
    let script = dir.join("probes.d");
    let needle = script.to_string_lossy();
    Ok(fs::read_to_string(log)?
        .lines()
        .filter(|line| line.contains("/usr/sbin/dtrace") && line.contains(needle.as_ref()))
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .collect())
}
fn stop_trace(child: &mut Child, dir: &Path) -> Result<(), Error> {
    let mut signal_error = None;
    for (signal, log) in [("-INT", "dtrace-stop.log"), ("-KILL", "dtrace-kill.log")] {
        let pids = trace_pids(dir)?;
        if pids.is_empty() {
            break;
        }
        let mut command = Command::new("sudo");
        command.args(["-n", "/bin/kill", signal, "--"]);
        for pid in pids {
            command.arg(pid.to_string());
        }
        // Still escalate when interrupting is denied or a process exits mid-scan.
        if let Err(error) = bounded(&mut command, &dir.join(log), 5) {
            signal_error = Some(error);
        }
        let _ = wait_bounded(child, Duration::from_secs(5))?;
    }
    if !trace_pids(dir)?.is_empty() {
        return Err(signal_error
            .unwrap_or_else(|| Error::Invalid("scoped dtrace processes survived cleanup".into())));
    }
    if wait_bounded(child, Duration::from_secs(5))?.is_none() {
        kill_group(child)?;
        if wait_bounded(child, Duration::from_secs(5))?.is_none() {
            return Err(Error::Invalid("trace launcher failed to reap".into()));
        }
    }
    Ok(())
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
    for path in [&root, &args.executable] {
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
        fs::create_dir(&dir)?;
        let stdout = dir.join("stdout.log");
        let stderr = dir.join("stderr.log");
        // Darwin AF_UNIX paths are short; do not derive a socket name from
        // an arbitrarily deep artifact directory. TempDir owns its removal.
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
        let start = Instant::now();
        let child = command.spawn()?;
        let mut guard = RunGuard {
            root: &root,
            id: id.clone(),
            dir: dir.clone(),
            child,
            cleaned: false,
        };
        let mut startup = accept_start(&listener)?;
        let trace_result = trace(&args, &guard);
        let trace_error = trace_result.as_ref().err().map(ToString::to_string);
        let mut trace_child = trace_result.unwrap_or(None).map(|child| TraceGuard {
            child,
            dir: dir.clone(),
            started: Instant::now(),
            bound: Duration::from_secs(args.trace_seconds.saturating_add(5)),
            stopped: false,
        });
        let ready = if let Some(error) = trace_error {
            Err(Error::Invalid(error))
        } else if let Some(ref mut tracer) = trace_child {
            wait_trace_ready(tracer)
        } else {
            Ok(())
        };
        if ready.is_ok() {
            startup.write_all(&[1])?;
        }
        let observed = ready.and_then(|()| {
            monitor(
                &mut guard.child,
                &stderr,
                &patterns,
                Duration::from_secs(args.hang_seconds.unwrap_or(args.timeout_seconds)),
                &stop,
                &args.exit_codes,
                trace_child.as_mut(),
            )
        });
        let mut record = Record {
            run_id: id.clone(),
            outcome: Outcome::Error,
            exit_code: None,
            signal: None,
            elapsed_ms: start.elapsed().as_millis(),
            trace_events: None,
            artifacts: vec![stdout, stderr, dir.join("cleanup.log")],
            errors: Vec::new(),
        };
        if let Some(ref mut tracer) = trace_child {
            if let Err(error) = tracer.stop() {
                record.errors.push(error.to_string());
            }
            record.artifacts.extend([
                dir.join("dtrace.log"),
                dir.join("probes.d"),
                dir.join("probes.sha256"),
                dir.join("dtrace-processes.log"),
            ]);
            let mut tail = StderrTail {
                file: File::open(dir.join("dtrace.log"))?,
                overlap: Vec::new(),
            };
            let event = Regex::new("probe=").map_err(|e| Error::Invalid(e.to_string()))?;
            let fired = tail.matches(std::slice::from_ref(&event))?;
            record.trace_events = Some(fired);
        }
        match observed {
            Ok((outcome, status)) => {
                record.outcome = outcome;
                record.exit_code = status.and_then(|s| s.code());
                record.signal = status.and_then(|s| s.signal());
                if matches!(outcome, Outcome::Hang | Outcome::Stderr) && status.is_none() {
                    capture(&root, &args, &guard, &mut record);
                }
            }
            Err(error) => record.errors.push(error.to_string()),
        }
        if selected(record.outcome) && record.trace_events == Some(false) {
            record
                .errors
                .push("DTrace recorded zero scoped probe events; trace is inconclusive".into());
        }
        if let Err(error) = guard.cleanup() {
            record.errors.push(error.to_string());
        }
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
#[path = "../../carrick-embed/tests/common/fatal_hold.rs"]
mod embed_fatal_hold;

#[cfg(test)]
mod serial_host {
    // Fixture setup failures should identify the failed prerequisite.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::io::{Seek, SeekFrom};
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
            ("echo 'carrick fatal' >&2; sleep 5", Outcome::Stderr),
            ("sleep 5", Outcome::Hang),
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
            let (outcome, _) = monitor(
                &mut child,
                &stderr,
                &patterns,
                Duration::from_millis(200),
                &AtomicBool::new(false),
                &[134, 139],
                None,
            )
            .expect("monitor");
            assert_eq!(outcome, expected);
            if script == "echo 'carrick fatal' >&2; sleep 5" {
                assert!(observed_from.elapsed() >= Duration::from_millis(200));
            }
            if outcome == Outcome::Hang {
                let pid = i32::try_from(child.id()).expect("pid fits");
                // SAFETY: read-only identity queries on our live fake child.
                assert_eq!(unsafe { libc::getsid(pid) }, pid);
                assert_eq!(unsafe { libc::getpgid(pid) }, pid);
            }
            kill_group(&child).expect("kill");
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
                let (outcome, _) = monitor(
                    &mut child,
                    &stderr,
                    &[],
                    Duration::from_secs(2),
                    &AtomicBool::new(false),
                    &[139],
                    None,
                )?;
                kill_group(&child)?;
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
