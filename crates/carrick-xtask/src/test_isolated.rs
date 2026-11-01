//! Run each libtest test of one package's lib target in its own process
//! (#1297). `carrick-el1-linux`'s native-process fixtures leak their
//! `'static` structures for the life of the test process, so one process
//! running the whole suite accumulated past a 16 GiB runner (cgroup
//! `memory.peak` at the cap, `oom_kill 1`), while no single test peaks
//! above 1 GiB. A process per test returns each test's memory when it
//! exits, at the same parallelism libtest would use.
//!
//! The output is libtest's own format (`Running … (<binary>)`,
//! `test <name> ... ok|FAILED|ignored`, the `failures:` block and the
//! `test result:` line), so `xtask accept` itemizes failures exactly as it
//! does for `cargo test`. A test whose process is killed or crashes is an
//! itemized FAILED with its output, never a missing test.
use serde_json::Value;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

type Result<T> = std::result::Result<T, String>;

#[derive(clap::Args, Debug, Clone)]
pub struct TestIsolatedArgs {
    /// Package whose lib target is tested.
    #[arg(long)]
    pub package: String,
    /// Run only tests whose names contain this text (libtest filter rule).
    #[arg(long, conflicts_with = "skip")]
    pub only: Option<String>,
    /// Skip tests whose names contain this text (libtest `--skip` rule).
    #[arg(long)]
    pub skip: Option<String>,
    /// Concurrent test processes. Defaults to `RUST_TEST_THREADS`, then the
    /// available parallelism: the same count libtest's threads would use.
    #[arg(long)]
    pub jobs: Option<usize>,
    /// Seconds one test process may run before it is killed and itemized
    /// as FAILED, so a hang can't cost the whole receipt.
    #[arg(long, default_value_t = 600)]
    pub timeout_secs: u64,
    /// `cargo --config` values for the compile (for example the cache config).
    #[arg(long = "cargo-config")]
    pub cargo_config: Vec<String>,
}

/// One test's process outcome.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Ignored,
    Failed(String),
}

/// Classify a child that ran exactly one test. A clean exit counts only
/// when libtest reports that one test passed or was ignored: a child that
/// matched no test (an `--exact` mismatch) ran nothing and fails.
pub fn classify(status: ExitStatus, stdout: &str, stderr: &str) -> Outcome {
    if status.success() {
        if stdout.contains(" 1 passed; 0 failed; 0 ignored;") {
            return Outcome::Ok;
        }
        if stdout.contains(" 0 passed; 0 failed; 1 ignored;") {
            return Outcome::Ignored;
        }
        return Outcome::Failed(format!(
            "{stdout}{stderr}\ntest process exited cleanly but ran no test\n"
        ));
    }
    let mut text = String::new();
    text.push_str(stdout);
    text.push_str(stderr);
    let how = match status.code() {
        Some(code) => format!("test process exited with status {code}"),
        None => {
            use std::os::unix::process::ExitStatusExt;
            format!(
                "test process was killed by signal {}",
                status.signal().unwrap_or_default()
            )
        }
    };
    text.push_str(&format!("\n{how}\n"));
    Outcome::Failed(text)
}

/// Test names from `--list --format terse`, filtered like libtest.
pub fn select(listing: &str, only: Option<&str>, skip: Option<&str>) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|name| only.is_none_or(|f| name.contains(f)))
        .filter(|name| skip.is_none_or(|f| !name.contains(f)))
        .map(str::to_owned)
        .collect()
}

/// The libtest summary for one binary's run.
pub fn summary(binary: &Path, results: &[(String, Outcome)], elapsed_secs: f64) -> (String, bool) {
    let mut out = String::new();
    let passed = results.iter().filter(|(_, o)| *o == Outcome::Ok).count();
    let ignored = results
        .iter()
        .filter(|(_, o)| *o == Outcome::Ignored)
        .count();
    let failed: Vec<_> = results
        .iter()
        .filter_map(|(name, o)| match o {
            Outcome::Failed(text) => Some((name, text)),
            _ => None,
        })
        .collect();
    if !failed.is_empty() {
        out.push_str("\nfailures:\n\n");
        for (name, text) in &failed {
            out.push_str(&format!("---- {name} stdout ----\n{text}\n"));
        }
        out.push_str("\nfailures:\n");
        for (name, _) in &failed {
            out.push_str(&format!("    {name}\n"));
        }
    }
    let verdict = if failed.is_empty() { "ok" } else { "FAILED" };
    out.push_str(&format!(
        "\ntest result: {verdict}. {passed} passed; {} failed; {ignored} ignored; 0 measured; 0 filtered out; finished in {elapsed_secs:.2}s (one process per test: {})\n",
        failed.len(),
        binary.display()
    ));
    (out, failed.is_empty())
}

fn compile(root: &Path, args: &TestIsolatedArgs) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    for config in &args.cargo_config {
        cmd.args(["--config", config]);
    }
    cmd.current_dir(root).args([
        "test",
        "--locked",
        "--no-run",
        "--message-format=json-render-diagnostics",
        "-p",
        &args.package,
        "--lib",
    ]);
    let mut child = cmd
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cargo: {e}"))?;
    let stdout = child.stdout.take().ok_or("missing Cargo stdout")?;
    let mut binary = None;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|e| e.to_string())?;
        let msg: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if msg["reason"] == "compiler-message"
            && let Some(rendered) = msg["message"]["rendered"].as_str()
        {
            eprint!("{rendered}");
        }
        if msg["reason"] == "compiler-artifact"
            && msg["profile"]["test"] == true
            && msg["target"]["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|k| k == "lib"))
            && let Some(exe) = msg["executable"].as_str()
        {
            binary = Some(PathBuf::from(exe));
        }
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("cargo test --no-run failed: {status}"));
    }
    binary.ok_or_else(|| format!("no lib test executable for {}", args.package))
}

fn run_one(binary: &Path, name: &str, timeout: std::time::Duration) -> Outcome {
    use std::io::Read;
    let spawned = Command::new(binary)
        .args(["--exact", name, "--test-threads=1"])
        .env_remove("RUST_TEST_THREADS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return Outcome::Failed(format!("could not start the test process: {e}\n")),
    };
    // Drain both pipes concurrently so a chatty test can't block on a full pipe.
    fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        })
    }
    let out = drain(child.stdout.take());
    let err = drain(child.stderr.take());
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(e) => {
                return Outcome::Failed(format!("could not wait for the test process: {e}\n"));
            }
        }
    };
    let out = out.join().unwrap_or_default();
    let err = err.join().unwrap_or_default();
    match status {
        Some(status) => classify(status, &out, &err),
        None => Outcome::Failed(format!(
            "{out}{err}\ntest process timed out after {}s and was killed\n",
            timeout.as_secs()
        )),
    }
}

pub fn run(root: &Path, args: TestIsolatedArgs) -> Result<()> {
    let binary = compile(root, &args)?;
    let listing = Command::new(&binary)
        .args(["--list", "--format", "terse"])
        .output()
        .map_err(|e| format!("{}: {e}", binary.display()))?;
    if !listing.status.success() {
        return Err(format!("{} --list failed", binary.display()));
    }
    let tests = select(
        &String::from_utf8_lossy(&listing.stdout),
        args.only.as_deref(),
        args.skip.as_deref(),
    );
    let jobs = args
        .jobs
        .or_else(|| std::env::var("RUST_TEST_THREADS").ok()?.parse().ok())
        .or_else(|| std::thread::available_parallelism().ok().map(usize::from))
        .unwrap_or(1)
        .max(1);
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "     Running unittests src/lib.rs ({})\n\nrunning {} tests",
        binary.display(),
        tests.len()
    );
    let started = Instant::now();
    let queue = Arc::new(Mutex::new(tests.into_iter().collect::<VecDeque<_>>()));
    let (send, receive) = mpsc::channel();
    let workers: Vec<_> = (0..jobs)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let send = send.clone();
            let binary = binary.clone();
            let timeout = std::time::Duration::from_secs(args.timeout_secs);
            std::thread::spawn(move || {
                loop {
                    let next = queue.lock().ok().and_then(|mut q| q.pop_front());
                    let Some(name) = next else { break };
                    let outcome = run_one(&binary, &name, timeout);
                    if send.send((name, outcome)).is_err() {
                        break;
                    }
                }
            })
        })
        .collect();
    drop(send);
    let mut results = Vec::new();
    for (name, outcome) in receive {
        let word = match outcome {
            Outcome::Ok => "ok",
            Outcome::Ignored => "ignored",
            Outcome::Failed(_) => "FAILED",
        };
        let _ = writeln!(stdout, "test {name} ... {word}");
        results.push((name, outcome));
    }
    for worker in workers {
        let _ = worker.join();
    }
    let (text, ok) = summary(&binary, &results, started.elapsed().as_secs_f64());
    let _ = write!(stdout, "{text}");
    let _ = stdout.flush();
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{} of {} tests failed",
            results
                .iter()
                .filter(|(_, o)| matches!(o, Outcome::Failed(_)))
                .count(),
            results.len()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn selection_follows_libtest_filters() {
        let listing = "a::one: test\nb::serial_host_two: test\nc::bench: benchmark\n";
        assert_eq!(
            select(listing, None, None),
            ["a::one", "b::serial_host_two"]
        );
        assert_eq!(
            select(listing, Some("serial_host"), None),
            ["b::serial_host_two"]
        );
        assert_eq!(select(listing, None, Some("serial_host")), ["a::one"]);
    }

    /// The #344 lesson: a dead test process must not read clean.
    #[test]
    fn a_killed_or_crashed_test_is_an_itemized_failure() {
        let killed = classify(ExitStatus::from_raw(libc::SIGKILL), "running 1 test\n", "");
        let Outcome::Failed(text) = killed else {
            panic!("killed test read as passing");
        };
        assert!(text.contains("killed by signal 9"), "{text}");
        let crashed = classify(ExitStatus::from_raw(101 << 8), "", "thread panicked");
        assert!(matches!(crashed, Outcome::Failed(t) if t.contains("status 101")));
        assert_eq!(
            classify(
                ExitStatus::from_raw(0),
                "test result: ok. 1 passed; 0 failed; 0 ignored;",
                ""
            ),
            Outcome::Ok
        );
        assert_eq!(
            classify(
                ExitStatus::from_raw(0),
                "test result: ok. 0 passed; 0 failed; 1 ignored;",
                ""
            ),
            Outcome::Ignored
        );
        // An `--exact` mismatch exits 0 having run nothing: not a pass.
        let none = classify(
            ExitStatus::from_raw(0),
            "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 651 filtered out;",
            "",
        );
        assert!(matches!(none, Outcome::Failed(t) if t.contains("ran no test")));
    }

    /// Through real child processes: a hang is killed at the deadline and
    /// itemized, and a clean exit that ran no test fails.
    #[test]
    fn a_hung_or_empty_test_process_is_an_itemized_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let hang = dir.path().join("hang");
        crate::lock_file::tests::write_test_executable(
            &hang,
            "#!/bin/sh\nexec sleep 30\n",
            std::fs::Permissions::from_mode(0o755),
        );
        let started = Instant::now();
        let outcome = run_one(&hang, "t", std::time::Duration::from_millis(300));
        assert!(
            matches!(&outcome, Outcome::Failed(t) if t.contains("timed out")),
            "{outcome:?}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        let empty = dir.path().join("empty");
        crate::lock_file::tests::write_test_executable(
            &empty,
            "#!/bin/sh\necho 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;'\n",
            std::fs::Permissions::from_mode(0o755),
        );
        let outcome = run_one(&empty, "t", std::time::Duration::from_secs(10));
        assert!(
            matches!(&outcome, Outcome::Failed(t) if t.contains("ran no test")),
            "{outcome:?}"
        );
    }

    /// Output parses exactly as `cargo test`'s does for `xtask accept`.
    #[test]
    fn accept_itemizes_isolated_failures_by_binary() {
        let binary = Path::new("target/debug/deps/carrick_el1_linux-abcdef");
        let results = vec![
            ("passes".to_owned(), Outcome::Ok),
            (
                "killed".to_owned(),
                Outcome::Failed("killed by signal 9\n".into()),
            ),
        ];
        let (text, ok) = summary(binary, &results, 1.0);
        assert!(!ok);
        let log = format!(
            "     Running unittests src/lib.rs ({})\n\nrunning 2 tests\ntest passes ... ok\ntest killed ... FAILED\n{text}",
            binary.display()
        );
        assert_eq!(
            crate::accept::parse_failed_tests(&log),
            ["carrick_el1_linux::killed"]
        );
        assert!(
            crate::accept::parse_unitemized_failures(&log).is_empty(),
            "{log}"
        );
    }
}
