//! First signed end-to-end tests for `carrick-embed`: a real HVF guest booted
//! from a cargo test executable, compared against the shipped CLI on the
//! same image and command, with each stdio sink proven.
//!
//! Run ONLY through `just test-embed` (scripts/test-signed.sh): it signs this
//! executable with the hypervisor entitlement, exports `CARRICK_RUN_ID`, and
//! runs it under `RUST_TEST_THREADS=1`. A bare `cargo test` fails here with
//! `EmbedError::Entitlement` — by design, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_embed::testing::ResultAssert;
use carrick_embed::{ContainerBuilder, ContainerResult, StdioConfig};
use carrick_image::{ImageStore, PullPolicy};

const HELLO: &[u8] = b"hello world\n";

/// The conformance gate's per-case budget (`CASE_DEADLINE`,
/// `crates/carrick-cli/tests/conformance.rs:169`).
const CLI_DEADLINE: Duration = Duration::from_secs(45);

fn hello_builder(store: &ImageStore) -> ContainerBuilder {
    ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .image_store(store.clone())
        .pull_policy(PullPolicy::Missing)
        .command(["echo", "hello world"])
}

fn assert_clean_exit(result: &ContainerResult) {
    assert!(
        result.success(),
        "exit_code={} signal={:?} trap_limit_hit={}",
        result.exit_code,
        result.signal.is_some(),
        result.trap_limit_hit
    );
    assert_eq!(result.exit_code, 0);
    assert!(result.signal.is_none(), "guest was killed by a signal");
    assert!(!result.trap_limit_hit, "trap limit hit");
}

#[test]
fn captured_stdout_is_hello_world() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let result = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(result.stdout, HELLO, "stdout={:?}", result.stdout_utf8());
    assert_eq!(result.stdout_utf8(), "hello world\n");
    assert_eq!(result.stderr, b"", "stderr={:?}", result.stderr_utf8());
}

#[test]
fn captured_stdio_round_trips_guest_output_and_exit_code() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command([
                "/bin/sh",
                "-c",
                "echo hello-from-embed; echo to-stderr 1>&2; exit 7",
            ])
            .run_blocking(),
    );
    result
        .assert_exit_code(7)
        .assert_stdout_contains("hello-from-embed");
    assert_eq!(result.stdout_utf8(), "hello-from-embed\n");
    assert_eq!(result.stderr_utf8(), "to-stderr\n");
    assert!(!result.success());
    assert_eq!(result.signal, None);
}

struct CliRun {
    streamed_stdout: Vec<u8>,
    envelope: serde_json::Value,
    status: i32,
}

fn split_json_envelope(stdout: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let start = if stdout.starts_with(b"{\n") {
        0
    } else {
        stdout
            .windows(3)
            .position(|w| w == b"\n{\n")
            .map(|i| i + 1)
            .unwrap_or_else(|| {
                panic!(
                    "no JSON envelope in `carrick run --json` stdout: {:?}",
                    String::from_utf8_lossy(stdout)
                )
            })
    };
    let envelope = serde_json::from_slice(&stdout[start..]).expect("parse --json envelope");
    (stdout[..start].to_vec(), envelope)
}

fn run_cli_json(store: &ImageStore) -> CliRun {
    let bin = common::repo_root().join("target/release/carrick");
    assert!(
        bin.exists(),
        "{} missing: `just test-embed` depends on `build`",
        bin.display()
    );
    let run_id = format!("{}-cli", common::run_id());
    let child = Command::new(&bin)
        .args([
            "run",
            "--json",
            "--pull",
            "missing",
            common::SMOKE_IMAGE,
            "echo",
            "hello world",
        ])
        .env("CARRICK_RUN_ID", &run_id)
        .env("CARRICK_HOME", store.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .expect("spawn target/release/carrick");
    let pgid: libc::pid_t = libc::pid_t::try_from(child.id()).expect("child pid fits pid_t");
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let start = Instant::now();
            while !done.load(Ordering::Relaxed) {
                if start.elapsed() > CLI_DEADLINE {
                    // SAFETY: kill(2) on the child's own process group; the
                    // pgid was created by `process_group(0)` above.
                    let _ = unsafe { libc::kill(-pgid, libc::SIGKILL) };
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let output = child.wait_with_output().expect("wait for carrick run");
    done.store(true, Ordering::Relaxed);
    watchdog.join().expect("watchdog thread");
    let status = output.status.code().unwrap_or_else(|| {
        panic!(
            "carrick run died by signal (deadline {CLI_DEADLINE:?}?): {:?}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let (streamed_stdout, envelope) = split_json_envelope(&output.stdout);
    CliRun {
        streamed_stdout,
        envelope,
        status,
    }
}

#[test]
fn library_result_matches_cli_run() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();

    let cli = run_cli_json(&store);
    assert_eq!(cli.status, 0, "carrick run exit status");
    assert_eq!(
        cli.streamed_stdout,
        HELLO,
        "cli stdout={:?}",
        String::from_utf8_lossy(&cli.streamed_stdout)
    );
    assert_eq!(cli.envelope["exit_code"], serde_json::json!(0));
    assert_eq!(cli.envelope["trap_limit_hit"], serde_json::json!(false));

    let lib = common::run_or_fail(
        hello_builder(&store)
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking(),
    );
    assert_clean_exit(&lib);
    assert_eq!(
        lib.stdout, cli.streamed_stdout,
        "library stdout != CLI stdout"
    );
    assert_eq!(
        i64::from(lib.exit_code),
        cli.envelope["exit_code"].as_i64().expect("exit_code"),
        "library exit code != CLI exit code"
    );
    assert_eq!(
        lib.trap_limit_hit,
        cli.envelope["trap_limit_hit"]
            .as_bool()
            .expect("trap_limit_hit")
    );
}

struct StdoutRedirect {
    saved: libc::c_int,
}

impl StdoutRedirect {
    fn install(file: &std::fs::File) -> Self {
        std::io::stdout().flush().expect("flush real stdout");
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0, "dup(1) failed");
        let rc = unsafe { libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO) };
        assert_eq!(rc, libc::STDOUT_FILENO, "dup2(file, 1) failed");
        Self { saved }
    }
}

impl Drop for StdoutRedirect {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved, libc::STDOUT_FILENO);
            libc::close(self.saved);
        }
    }
}

#[test]
fn inherit_streams_to_the_carrier_stdout() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let mut sink = tempfile::tempfile().expect("tempfile");
    let result = {
        let _redirect = StdoutRedirect::install(&sink);
        common::run_or_fail(
            hello_builder(&store)
                .stdout(StdioConfig::Inherit)
                .stderr(StdioConfig::Captured)
                .run_blocking(),
        )
    };
    assert_clean_exit(&result);
    assert!(
        result.stdout.is_empty(),
        "Inherit must not also capture: {:?}",
        result.stdout_utf8()
    );
    let mut seen = Vec::new();
    sink.seek(SeekFrom::Start(0)).expect("rewind");
    sink.read_to_end(&mut seen).expect("read fd-1 sink");
    assert_eq!(
        seen,
        HELLO,
        "carrier fd 1 received {:?}",
        String::from_utf8_lossy(&seen)
    );
}

#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn piped_delivers_stdout_and_stderr_to_caller_writers() {
    let _guard = common::guest_lock();
    let store = ImageStore::default_for_user();
    let out = SharedSink::default();
    let err = SharedSink::default();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .image_store(store.clone())
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo hello world; echo to-stderr 1>&2"])
            .stdout(StdioConfig::Piped(Box::new(out.clone())))
            .stderr(StdioConfig::Piped(Box::new(err.clone())))
            .run_blocking(),
    );
    assert_clean_exit(&result);
    assert_eq!(
        out.bytes(),
        HELLO,
        "piped stdout={:?}",
        String::from_utf8_lossy(&out.bytes())
    );
    assert_eq!(
        err.bytes(),
        b"to-stderr\n",
        "piped stderr={:?}",
        String::from_utf8_lossy(&err.bytes())
    );
    assert!(
        result.stdout.is_empty() && result.stderr.is_empty(),
        "Piped must not also capture"
    );
}

#[test]
fn env_workdir_and_hostname_reach_the_guest() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo $GREETING; pwd; hostname"])
            .env("GREETING", "hi")
            .workdir("/tmp")
            .hostname("embedded-host")
            .run_blocking(),
    );
    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hi\n/tmp\nembedded-host\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::await_holding_lock)]
async fn async_run_executes_on_the_blocking_pool() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "echo async-ok"])
            .run()
            .await,
    );
    result.assert_success().assert_stdout_contains("async-ok");
}

#[test]
fn a_trap_limit_is_reported_not_erred() {
    let _guard = common::guest_lock();
    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", "while :; do :; done"])
            .max_traps(2_000)
            .run_blocking(),
    );
    assert!(result.trap_limit_hit);
    assert!(!result.success());
}
