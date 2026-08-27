//! Signed end-to-end smoke for `carrick-embed`. REQUIRES an HVF-entitled test
//! executable: run only via `just test-embed` (which codesigns the test binary
//! with scripts/entitlements.plist and serializes with RUST_TEST_THREADS=1).
//! `EmbedError::Entitlement` here is a FAILURE, never a skip.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use carrick_embed::testing::ResultAssert;
use carrick_embed::{ContainerBuilder, StdioConfig};

const IMAGE: &str = "ubuntu:24.04";

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn captured_stdio_round_trips_guest_output_and_exit_code() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command([
            "/bin/sh",
            "-c",
            "echo hello-from-embed; echo to-stderr 1>&2; exit 7",
        ])
        .run_blocking()
        .expect("guest ran (HV_DENIED means the test binary is unsigned)");
    result
        .assert_exit_code(7)
        .assert_stdout_contains("hello-from-embed");
    assert_eq!(result.stdout_utf8(), "hello-from-embed\n");
    assert_eq!(result.stderr_utf8(), "to-stderr\n");
    assert!(!result.success());
    assert_eq!(result.signal, None);
}

#[test]
fn env_workdir_and_hostname_reach_the_guest() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo $GREETING; pwd; hostname"])
        .env("GREETING", "hi")
        .workdir("/tmp")
        .hostname("embedded-host")
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    assert_eq!(result.stdout_utf8(), "hi\n/tmp\nembedded-host\n");
}

#[test]
fn piped_stdout_reaches_the_callers_writer_and_captured_stderr_stays_in_result() {
    let writer = SharedWriter::default();
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo piped-line; echo err-line 1>&2"])
        .stdout(StdioConfig::Piped(Box::new(writer.clone())))
        .stderr(StdioConfig::Captured)
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    let piped = writer
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(String::from_utf8_lossy(&piped), "piped-line\n");
    assert!(
        result.stdout.is_empty(),
        "piped stdout is not also captured"
    );
    assert_eq!(result.stderr_utf8(), "err-line\n");
}

#[test]
fn inherit_mode_leaves_the_result_buffers_empty() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo inherited-to-host-stdout"])
        .stdout(StdioConfig::Inherit)
        .stderr(StdioConfig::Inherit)
        .run_blocking()
        .expect("guest ran");
    result.assert_success();
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_run_executes_on_the_blocking_pool() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "echo async-ok"])
        .run()
        .await
        .expect("guest ran");
    result.assert_success().assert_stdout_contains("async-ok");
}

#[test]
fn a_trap_limit_is_reported_not_erred() {
    let result = ContainerBuilder::from_image(IMAGE)
        .command(["/bin/sh", "-c", "while :; do :; done"])
        .max_traps(2_000)
        .run_blocking()
        .expect("a trap-limited run still returns a result");
    assert!(result.trap_limit_hit);
    assert!(!result.success());
}
