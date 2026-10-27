//! Evidence capture for loom binaries, without changing their exploration.
//! Recipe capture preserves Cargo's separate feature closures (test-batch
//! deliberately unifies them). Its dispatch deadline helper is account-specific
//! and does not stream libtest output, so supervision here owns just one group.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(clap::Args, Debug)]
pub struct LoomRunArgs {
    /// Private recipe containing the authoritative Cargo test selections.
    pub recipe: String,
    /// Wall-clock budget per binary invocation, including its --list discovery.
    #[arg(long, env = "CARRICK_LOOM_TIMEOUT_SECS", default_value_t = 1200, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout_secs: u64,
    /// Extra Cargo/libtest arguments forwarded to the source recipe.
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("loom command failed: {0}")]
pub struct FailureStatus(pub ExitStatus);

struct Lane {
    build: Vec<String>,
    harness: Vec<String>,
    cwd: PathBuf,
    env: [String; 2],
    no_run: bool,
}

fn lane(record: Vec<String>) -> Result<Lane> {
    let lib = record
        .iter()
        .position(|s| s == "--lib")
        .ok_or("loom lane requires --lib")?;
    let mut build = record.get(3..=lib).ok_or("invalid Cargo record")?.to_vec();
    let mut tail = &record[lib + 1..];
    let mut harness = Vec::new();
    // The recipes place their filter immediately after --lib. Remaining flags
    // before `--` belong to Cargo; everything after it belongs to libtest.
    if let Some(filter) = tail.first().filter(|s| !s.starts_with('-')) {
        harness.push(filter.clone());
        tail = &tail[1..];
    }
    let separator = tail.iter().position(|s| s == "--").unwrap_or(tail.len());
    build.extend_from_slice(&tail[..separator]);
    if separator < tail.len() {
        harness.extend_from_slice(&tail[separator + 1..]);
    }
    let no_run = build.iter().any(|s| s == "--no-run");
    if !no_run {
        build.push("--no-run".into());
    }
    build.push("--message-format=json-render-diagnostics".into());
    Ok(Lane {
        build,
        harness,
        no_run,
        cwd: PathBuf::from(record.get(2).ok_or("missing recipe directory")?),
        env: [
            record.first().ok_or("missing thread environment")?.clone(),
            record.get(1).ok_or("missing stack environment")?.clone(),
        ],
    })
}

fn stamp(message: impl std::fmt::Display) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!("loom-run: [unix {:.3}] {message}", now.as_secs_f64());
}

pub fn run(root: &Path, args: LoomRunArgs) -> Result<()> {
    // Preserve the source commands when called by the recipe coverage scanner.
    if std::env::var_os("CARRICK_TEST_CAPTURE").is_some() {
        let status = Command::new("just")
            .arg(&args.recipe)
            .args(&args.args)
            .current_dir(root)
            .status()?;
        return checked(status);
    }
    let lanes = crate::test_shards::records(root, &args.recipe, &args.args)?
        .into_iter()
        .map(lane)
        .collect::<Result<Vec<_>>>()?;
    if lanes.is_empty() {
        return Err("loom recipe selected no binaries".into());
    }
    let mut binaries = BTreeMap::new();
    for lane in &lanes {
        // Runtime's two filters share exactly one compilation, without unifying
        // features with other packages as test-batch does.
        let key = (lane.cwd.clone(), lane.build.clone());
        if let std::collections::btree_map::Entry::Vacant(entry) = binaries.entry(key) {
            entry.insert(build(lane)?);
        }
    }
    for lane in &lanes {
        if lane.no_run {
            continue;
        }
        let (exe, cwd) = binaries
            .get(&(lane.cwd.clone(), lane.build.clone()))
            .ok_or("missing loom binary")?;
        run_binary(exe, cwd, lane, Duration::from_secs(args.timeout_secs))?;
    }
    Ok(())
}

fn checked(status: ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(Box::new(FailureStatus(status)))
    }
}

fn build(lane: &Lane) -> Result<(PathBuf, PathBuf)> {
    let mut command = Command::new("cargo");
    command
        .current_dir(&lane.cwd)
        .args(&lane.build)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    crate::command::sanitize_cargo_package_env(&mut command);
    stamp(format_args!("BUILD start {command:?}"));
    let started = Instant::now();
    let mut child = command.spawn()?;
    let result = (|| -> Result<Option<(PathBuf, PathBuf)>> {
        use std::io::BufRead;
        let stdout = child.stdout.take().ok_or("missing Cargo stdout")?;
        let mut executable = None;
        for line in std::io::BufReader::new(stdout).lines() {
            let msg: Value = serde_json::from_str(&line?)?;
            if msg["reason"] == "compiler-artifact"
                && msg["profile"]["test"] == true
                && let Some(exe) = msg["executable"].as_str()
            {
                let manifest = Path::new(
                    msg["manifest_path"]
                        .as_str()
                        .ok_or("missing artifact manifest")?,
                );
                if executable.is_some() {
                    return Err("loom build produced multiple test executables".into());
                }
                executable = Some((
                    PathBuf::from(exe),
                    manifest
                        .parent()
                        .ok_or("missing package directory")?
                        .to_path_buf(),
                ));
            }
        }
        Ok(executable)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    stamp(format_args!(
        "BUILD end {status}; elapsed {:.3}s",
        started.elapsed().as_secs_f64()
    ));
    checked(status)?;
    result?.ok_or_else(|| "loom build produced no test executable".into())
}

#[derive(Clone, Copy, Debug)]
enum Progress {
    Pending,
    Started(Instant),
    Over60(Instant),
    Finished,
}

#[derive(Default)]
struct Tests {
    states: BTreeMap<String, Progress>,
    partial: Vec<u8>,
}

impl Tests {
    fn observe(&mut self, bytes: &[u8], now: Instant) {
        for byte in bytes {
            if *byte == b'\n' {
                self.parse(now);
                self.partial.clear();
            } else if self.partial.len() < 65536 {
                self.partial.push(*byte);
            }
        }
        // Serial libtest prints `test NAME ... ` before invoking the test,
        // without a newline. Parallel libtest only reports starts at 60s.
        self.parse(now);
    }

    fn parse(&mut self, now: Instant) {
        let line = String::from_utf8_lossy(&self.partial);
        let Some(test) = line.strip_prefix("test ") else {
            return;
        };
        if let Some((name, result)) = test.split_once(" ... ") {
            if let Some(state) = self.states.get_mut(name) {
                if ["ok", "FAILED", "ignored"]
                    .iter()
                    .any(|s| result.starts_with(s))
                {
                    *state = Progress::Finished;
                } else if matches!(state, Progress::Pending) {
                    *state = Progress::Started(now);
                }
            }
        } else if let Some((name, _)) = test.split_once(" has been running for over ")
            && let Some(state) = self.states.get_mut(name)
            && matches!(state, Progress::Pending)
        {
            *state = Progress::Over60(now);
        }
    }

    fn stalled(&self, exe: &Path, started: Instant) {
        eprintln!("loom-run: STALLED {}", exe.display());
        for (name, state) in &self.states {
            let elapsed = match state {
                Progress::Finished => continue,
                Progress::Pending => format!(
                    "start not observed; binary elapsed {:.3}s",
                    started.elapsed().as_secs_f64()
                ),
                Progress::Started(at) => {
                    format!("observed elapsed {:.3}s", at.elapsed().as_secs_f64())
                }
                Progress::Over60(at) => {
                    format!("elapsed at least {:.3}s", 60.0 + at.elapsed().as_secs_f64())
                }
            };
            eprintln!("loom-run: unfinished {name}: {elapsed}");
        }
        if self.states.is_empty() {
            eprintln!(
                "loom-run: test discovery incomplete; binary elapsed {:.3}s",
                started.elapsed().as_secs_f64()
            );
        }
    }
}

struct Group(Child);
impl Group {
    fn kill(&mut self) -> std::io::Result<()> {
        let pgid = i32::try_from(self.0.id()).map_err(std::io::Error::other)?;
        // SAFETY: this child was spawned into its own process group.
        if unsafe { libc::kill(-pgid, libc::SIGKILL) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        let _ = self.kill();
        // SIGKILL normally reaps immediately, but an uninterruptible host wait
        // must not turn the watchdog itself into an unlimited wait.
        let deadline = Instant::now() + Duration::from_secs(5);
        while matches!(self.0.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn nonblocking(fd: &impl AsRawFd) -> std::io::Result<()> {
    // SAFETY: fcntl operates on a borrowed live pipe, with no pointer arguments.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same descriptor, preserving its existing flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn run_binary(exe: &Path, cwd: &Path, lane: &Lane, limit: Duration) -> Result<()> {
    stamp(format_args!(
        "RUN start {} {:?}; deadline {}s",
        exe.display(),
        lane.harness,
        limit.as_secs()
    ));
    let started = Instant::now();
    let deadline = started
        .checked_add(limit)
        .ok_or("loom deadline out of range")?;
    let mut tests = Tests::default();
    let listing = supervise(exe, cwd, lane, true, started, deadline, &mut tests)?;
    checked(listing.0)?;
    for line in listing.1.lines() {
        if let Some(name) = line.strip_suffix(": test") {
            tests.states.insert(name.into(), Progress::Pending);
        }
    }
    let (status, _) = supervise(exe, cwd, lane, false, started, deadline, &mut tests)?;
    stamp(format_args!(
        "RUN end {} {status}; elapsed {:.3}s",
        exe.display(),
        started.elapsed().as_secs_f64()
    ));
    checked(status)
}

fn supervise(
    exe: &Path,
    cwd: &Path,
    lane: &Lane,
    list: bool,
    started: Instant,
    deadline: Instant,
    tests: &mut Tests,
) -> Result<(ExitStatus, String)> {
    let mut command = Command::new(exe);
    command
        .current_dir(cwd)
        .args(&lane.harness)
        .args(["--format=pretty", "--color=never"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if list {
        command.arg("--list");
    }
    for (name, value) in ["RUST_TEST_THREADS", "RUST_MIN_STACK"]
        .iter()
        .zip(&lane.env)
    {
        if value.is_empty() {
            command.env_remove(name);
        } else {
            command.env(name, value);
        }
    }
    let mut group = Group(command.spawn()?);
    let mut stdout = group.0.stdout.take().ok_or("missing test stdout")?;
    let mut stderr = group.0.stderr.take().ok_or("missing test stderr")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut streams: [&mut dyn Read; 2] = [&mut stdout, &mut stderr];
    let mut open = [true; 2];
    let mut listing = Vec::new();
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            tests.stalled(exe, started);
            group.kill()?;
            return Err("loom binary deadline expired".into());
        }
        for (index, stream) in streams.iter_mut().enumerate() {
            if !open[index] {
                continue;
            }
            let mut buffer = [0; 8192];
            // Limit each drain so continuous output cannot defeat the deadline.
            for _ in 0..8 {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        open[index] = false;
                        break;
                    }
                    Ok(n) => {
                        if index == 0 {
                            if list {
                                listing.extend_from_slice(&buffer[..n]);
                            } else {
                                tests.observe(&buffer[..n], Instant::now());
                            }
                            let mut out = std::io::stdout().lock();
                            out.write_all(&buffer[..n])?;
                            out.flush()?;
                        } else {
                            std::io::stderr().write_all(&buffer[..n])?;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if status.is_none() {
            status = group.0.try_wait()?;
        }
        if !open.contains(&true)
            && let Some(status) = status
        {
            return Ok((status, String::from_utf8(listing)?));
        }
        std::thread::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_output_tracks_partial_starts_completions_and_slow_tests() {
        let now = Instant::now();
        let mut tests = Tests::default();
        for name in ["serial", "slow", "failed", "ignored", "pending"] {
            tests.states.insert(name.into(), Progress::Pending);
        }
        tests.observe(b"test serial ... ", now);
        assert!(matches!(tests.states["serial"], Progress::Started(_)));
        tests.observe(b"ok\ntest slow has been running for over 60 seconds\n", now);
        tests.observe(
            b"test failed ... FAILED\ntest ignored ... ignored, reason\n",
            now,
        );
        for name in ["serial", "failed", "ignored"] {
            assert!(matches!(tests.states[name], Progress::Finished));
        }
        assert!(matches!(tests.states["slow"], Progress::Over60(_)));
        assert!(matches!(tests.states["pending"], Progress::Pending));
    }
}
