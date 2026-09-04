//! Focused ecosystem failures executed through the public embedding path.
//! Run with scripts/test-signed.sh carrick-conformance-next ecosystem_cpython_forkserver_result_pickle --nocapture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use carrick_conformance_next::{
    ContainerResult, EmbedError, PullPolicy, ResultAssert, StdioConfig, TestContainer,
};

/// Writer wrapper that delegates raw writes while capturing the first I/O error into shared state.
/// This prevents diagnostic write losses from being silently translated to guest errno without
/// failing the host-side capture closed.
struct RecordingWriter<W> {
    inner: W,
    path: PathBuf,
    first_error: Arc<Mutex<Option<(PathBuf, io::Error)>>>,
}

impl<W> RecordingWriter<W> {
    fn new(inner: W, path: PathBuf, first_error: Arc<Mutex<Option<(PathBuf, io::Error)>>>) -> Self {
        Self {
            inner,
            path,
            first_error,
        }
    }

    fn record_error(&self, err: &io::Error) {
        let mut guard = self.first_error.lock().unwrap();
        if guard.is_none() {
            *guard = Some((
                self.path.clone(),
                io::Error::new(err.kind(), err.to_string()),
            ));
        }
    }
}

impl<W: Write> Write for RecordingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(err) => {
                if err.kind() != io::ErrorKind::Interrupted {
                    self.record_error(&err);
                }
                Err(err)
            }
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.inner.write_all(buf) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.record_error(&err);
                Err(err)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(err) => {
                if err.kind() != io::ErrorKind::Interrupted {
                    self.record_error(&err);
                }
                Err(err)
            }
        }
    }
}

/// Run a test container, streaming guest stdout and stderr directly into host log files
/// when `CARRICK_REDUCER_ARTIFACT_DIR` is set so diagnostics are preserved during execution
/// even if the host aborts. When no artifact directory is configured, falls back to default
/// in-memory captured stdio.
fn run_reducer_container<I, S>(
    test_name: &str,
    container: TestContainer,
    argv: I,
) -> Result<ContainerResult, EmbedError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    if let Some(artifact_dir) = std::env::var_os("CARRICK_REDUCER_ARTIFACT_DIR") {
        let dir = Path::new(&artifact_dir);
        std::fs::create_dir_all(dir).unwrap_or_else(|err| {
            panic!(
                "failed to create CARRICK_REDUCER_ARTIFACT_DIR at {}: {err}",
                dir.display()
            )
        });
        let stdout_path = dir.join(format!("{test_name}.stdout.log"));
        let stderr_path = dir.join(format!("{test_name}.stderr.log"));
        let stdout_file = std::fs::File::create(&stdout_path).unwrap_or_else(|err| {
            panic!(
                "failed to create stdout log file at {}: {err}",
                stdout_path.display()
            )
        });
        let stderr_file = std::fs::File::create(&stderr_path).unwrap_or_else(|err| {
            panic!(
                "failed to create stderr log file at {}: {err}",
                stderr_path.display()
            )
        });

        let first_error: Arc<Mutex<Option<(PathBuf, io::Error)>>> = Arc::new(Mutex::new(None));
        let stdout_writer =
            RecordingWriter::new(stdout_file, stdout_path.clone(), Arc::clone(&first_error));
        let stderr_writer =
            RecordingWriter::new(stderr_file, stderr_path.clone(), Arc::clone(&first_error));

        let run_result = container
            .builder(argv)
            .stdout(StdioConfig::Piped(Box::new(stdout_writer)))
            .stderr(StdioConfig::Piped(Box::new(stderr_writer)))
            .run_blocking();

        if let Some((err_path, err)) = first_error.lock().unwrap().take() {
            panic!(
                "streamed reducer diagnostic write failed for artifact at {}: {err}",
                err_path.display()
            );
        }

        let mut result = run_result?;

        result.stdout = std::fs::read(&stdout_path).unwrap_or_else(|err| {
            panic!(
                "failed to read stdout log file at {}: {err}",
                stdout_path.display()
            )
        });
        result.stderr = std::fs::read(&stderr_path).unwrap_or_else(|err| {
            panic!(
                "failed to read stderr log file at {}: {err}",
                stderr_path.display()
            )
        });

        Ok(result)
    } else {
        container.run(argv)
    }
}

#[test]
fn ecosystem_cpython_forkserver_result_pickle() {
    let _guard = common::guest_lock();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let mut container = TestContainer::new("localhost:5050/cpython-test:3.12.13")
        .pull_policy(PullPolicy::Never)
        .env("PYTHONFAULTHANDLER", "1")
        .env("PYTHONUNBUFFERED", "1");
    if let Some(path) = std::env::var_os("CARRICK_REDUCER_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).expect("create reducer artifact directory");
        container = container
            .mount(path.to_string_lossy(), "/evidence")
            .workdir("/evidence");
    }
    let result = common::run_or_fail(run_reducer_container(
        "ecosystem_cpython_forkserver_result_pickle",
        container,
        [
            "/usr/local/bin/python3",
            "-m",
            "unittest",
            "-v",
            "test.test_concurrent_futures.test_deadlock.ProcessPoolForkserverExecutorDeadlockTest.test_error_during_result_pickle_on_worker",
        ],
    ));
    result.assert_success();
    assert!(
        result.stderr_utf8().contains("Ran 1 test"),
        "stdout:\n{}\nstderr:\n{}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
    assert!(
        result.stderr_utf8().contains("\nOK\n"),
        "stdout:\n{}\nstderr:\n{}",
        result.stdout_utf8(),
        result.stderr_utf8()
    );
}

/// Slow full-module execution of CPython's `test_concurrent_futures` regrtest suite.
///
/// NOTE on limitation: This wrapper provides aggregate execution and completion
/// evidence (exit code 0, positive unittest counts, and terminal `Result: SUCCESS`),
/// but does NOT establish line-exact per-assertion oracle parity for all individual
/// tests. Full assertion parity is evaluated by the dedicated conformance parser
/// harness (`carrick-conformance`).
///
/// Run via signed test wrapper:
///   ./scripts/test-signed.sh carrick-conformance-next ecosystem_cpython_concurrent_futures_module --ignored --nocapture
#[test]
#[ignore = "slow full module test; run explicitly via ./scripts/test-signed.sh carrick-conformance-next ecosystem_cpython_concurrent_futures_module --ignored --nocapture"]
fn ecosystem_cpython_concurrent_futures_module() {
    let _guard = common::guest_lock();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let mut container = TestContainer::new("localhost:5050/cpython-test:3.12.13")
        .pull_policy(PullPolicy::Never)
        .env("PYTHONFAULTHANDLER", "1")
        .env("PYTHONUNBUFFERED", "1");
    if let Some(path) = std::env::var_os("CARRICK_REDUCER_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).expect("create reducer artifact directory");
        container = container
            .mount(path.to_string_lossy(), "/evidence")
            .workdir("/evidence");
    }
    let result = common::run_or_fail(run_reducer_container(
        "ecosystem_cpython_concurrent_futures_module",
        container,
        [
            "/usr/local/bin/python3",
            "-m",
            "test",
            "-v",
            "--randseed",
            "0",
            "test_concurrent_futures",
        ],
    ));
    assert_regrtest_completion(&result);
}

/// Summary of aggregated unittest outcomes and terminal regrtest status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegrtestCompletionSummary {
    /// Sum of all `Ran <N> test[s]` parsed across unittest summary blocks.
    pub total_ran: usize,
    /// Sum of all skips parsed across `OK (skipped=<N>)`.
    pub total_skipped: usize,
    /// Sum of all expected failures parsed across `OK (expected failures=<N>)`.
    pub total_expected_failures: usize,
    /// Derived genuine passed count (`total_ran.saturating_sub(total_skipped + total_expected_failures)`).
    pub total_passed: usize,
    /// Whether the terminal regrtest status was confirmed as `Result: SUCCESS`.
    pub regrtest_success: bool,
}

/// Parse a "Ran <N> test[s] in <duration>s" summary line according to the exact unittest grammar.
/// Validates both the integer test count and that the duration is a valid nonnegative finite numeric second value.
fn parse_ran_line(line: &str) -> Option<usize> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() == 5
        && tokens[0] == "Ran"
        && (tokens[2] == "test" || tokens[2] == "tests")
        && tokens[3] == "in"
    {
        let count = tokens[1].parse::<usize>().ok()?;
        let duration_str = tokens[4].strip_suffix('s')?;
        let duration = duration_str.parse::<f64>().ok()?;
        if duration.is_finite() && duration >= 0.0 {
            Some(count)
        } else {
            None
        }
    } else {
        None
    }
}

/// Validate a CPython regrtest / unittest transcript host-side without spawning guests.
///
/// Fails closed on:
/// - Empty stdout and stderr
/// - Unmatched, overlapping, or malformed unittest summary blocks (`Ran <N> test[s] in <T>s`)
/// - Malformed, duplicate, or unknown fields in `OK (...)` summaries, or exclusions exceeding `ran`
/// - Any unittest summary block failure (`FAILED (...)`, `FAILED`) or regrtest failure marker (`Result: FAILURE`, `== Tests result: FAILURE ==`)
/// - Missing or non-SUCCESS terminal `Result:` marker, or conflicting multiple `Result:` markers
/// - Zero executed tests or suites where 0 genuine tests passed (e.g. skipped-only or expected-failures-only)
pub fn parse_and_validate_regrtest_transcript(
    stdout: &str,
    stderr: &str,
) -> Result<RegrtestCompletionSummary, String> {
    if stdout.trim().is_empty() && stderr.trim().is_empty() {
        return Err("empty transcript: neither stdout nor stderr contained output".to_string());
    }

    let mut total_ran = 0usize;
    let mut total_skipped = 0usize;
    let mut total_expected_failures = 0usize;
    let mut has_unittest_summary = false;
    let mut terminal_results: Vec<String> = Vec::new();
    let mut failure_reasons: Vec<String> = Vec::new();

    let mut pending_ran: Option<usize> = None;

    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Track terminal regrtest result statuses
        if let Some(status) = trimmed.strip_prefix("Result:") {
            terminal_results.push(status.trim().to_string());
        } else if trimmed == "== Tests result: FAILURE ==" {
            failure_reasons.push("regrtest reported '== Tests result: FAILURE =='".to_string());
        } else if trimmed.starts_with("== Tests result: ") && !trimmed.contains("SUCCESS") {
            failure_reasons.push(format!(
                "regrtest reported non-success terminal marker: '{trimmed}'"
            ));
        }

        // Check if line is a "Ran N test[s] in <T>s" line
        if trimmed.starts_with("Ran ") {
            if pending_ran.is_some() {
                failure_reasons.push(
                    "unmatched or overlapping unittest Ran block: found new Ran block before previous block was completed"
                        .to_string(),
                );
            }
            if let Some(count) = parse_ran_line(trimmed) {
                pending_ran = Some(count);
                continue;
            } else {
                failure_reasons.push(format!("malformed Ran summary syntax: '{trimmed}'"));
                pending_ran = None;
                continue;
            }
        }

        // If a Ran block is pending, resolve its outcome from this non-empty line
        if let Some(ran) = pending_ran {
            if trimmed == "OK" {
                total_ran += ran;
                has_unittest_summary = true;
                pending_ran = None;
            } else if trimmed.starts_with("OK (") && trimmed.ends_with(')') {
                let inner = trimmed
                    .strip_prefix("OK (")
                    .and_then(|s| s.strip_suffix(')'))
                    .unwrap_or("");
                let mut block_skipped = 0usize;
                let mut block_xfail = 0usize;
                let mut seen_skipped = false;
                let mut seen_xfail = false;
                let mut ok_parse_err = None;

                for part in inner.split(',') {
                    let part = part.trim();
                    if let Some(val) = part.strip_prefix("skipped=") {
                        if seen_skipped {
                            ok_parse_err =
                                Some("duplicate 'skipped' field in OK summary".to_string());
                            break;
                        }
                        seen_skipped = true;
                        match val.parse::<usize>() {
                            Ok(num) => block_skipped = num,
                            Err(_) => {
                                ok_parse_err = Some(format!("malformed skipped count '{val}'"));
                                break;
                            }
                        }
                    } else if let Some(val) = part
                        .strip_prefix("expected failures=")
                        .or_else(|| part.strip_prefix("expected failure="))
                    {
                        if seen_xfail {
                            ok_parse_err = Some(
                                "duplicate 'expected failures' field in OK summary".to_string(),
                            );
                            break;
                        }
                        seen_xfail = true;
                        match val.parse::<usize>() {
                            Ok(num) => block_xfail = num,
                            Err(_) => {
                                ok_parse_err =
                                    Some(format!("malformed expected failures count '{val}'"));
                                break;
                            }
                        }
                    } else {
                        ok_parse_err = Some(format!(
                            "unknown or unsupported field '{part}' in OK summary"
                        ));
                        break;
                    }
                }

                if let Some(err) = ok_parse_err {
                    failure_reasons.push(err);
                } else {
                    let block_exclusions = block_skipped + block_xfail;
                    if block_exclusions > ran {
                        failure_reasons.push(format!(
                            "block exclusions ({block_exclusions} = {block_skipped} skipped + {block_xfail} expected failures) exceed total ran ({ran})"
                        ));
                    } else {
                        total_ran += ran;
                        total_skipped += block_skipped;
                        total_expected_failures += block_xfail;
                        has_unittest_summary = true;
                    }
                }
                pending_ran = None;
            } else if trimmed.starts_with("FAILED (") || trimmed == "FAILED" {
                failure_reasons.push(format!("unittest summary block failed: '{trimmed}'"));
                total_ran += ran;
                has_unittest_summary = true;
                pending_ran = None;
            } else {
                // The line following Ran was neither OK nor FAILED
                failure_reasons.push(format!(
                    "unmatched unittest Ran block: expected OK or FAILED summary, found '{trimmed}'"
                ));
                pending_ran = None;
            }
        }
    }

    if pending_ran.is_some() {
        failure_reasons.push(
            "unmatched unittest Ran block at end of transcript (missing OK/FAILED outcome)"
                .to_string(),
        );
    }

    if !failure_reasons.is_empty() {
        return Err(format!(
            "transcript rejected due to failures: {}",
            failure_reasons.join("; ")
        ));
    }

    if terminal_results.is_empty() {
        return Err(
            "transcript missing terminal 'Result:' marker (test died, aborted, or was truncated)"
                .to_string(),
        );
    }

    if terminal_results.len() > 1 {
        return Err(format!(
            "multiple conflicting terminal Result markers found: {:?}",
            terminal_results
        ));
    }

    if terminal_results[0] != "SUCCESS" {
        return Err(format!(
            "terminal regrtest status was not SUCCESS: 'Result: {}'",
            terminal_results[0]
        ));
    }

    if !has_unittest_summary || total_ran == 0 {
        return Err(
            "transcript contained no valid executed unittest summary blocks ('Ran N tests')"
                .to_string(),
        );
    }

    let total_exclusions = total_skipped + total_expected_failures;
    let total_passed = total_ran.saturating_sub(total_exclusions);
    if total_passed == 0 {
        return Err(format!(
            "transcript had 0 genuine passed tests (total_ran={total_ran}, total_skipped={total_skipped}, total_expected_failures={total_expected_failures})"
        ));
    }

    Ok(RegrtestCompletionSummary {
        total_ran,
        total_skipped,
        total_expected_failures,
        total_passed,
        regrtest_success: true,
    })
}

/// Assert that a container run finished cleanly with exit 0 and that its regrtest transcript
/// completed with real passing tests, honest skip accounting, and no failures or errors.
fn assert_regrtest_completion(result: &ContainerResult) {
    let stdout = result.stdout_utf8();
    let stderr = result.stderr_utf8();
    assert!(
        result.success(),
        "expected successful container execution (exit 0, no signal), got exit_code={} signal={:?} trap_limit_hit={}\n\n=== STDOUT ===\n{}\n\n=== STDERR ===\n{}\n",
        result.exit_code,
        result.signal,
        result.trap_limit_hit,
        stdout,
        stderr
    );
    match parse_and_validate_regrtest_transcript(&stdout, &stderr) {
        Ok(summary) => {
            assert!(
                summary.total_passed > 0,
                "regrtest transcript had 0 passed tests\n\n=== STDOUT ===\n{}\n\n=== STDERR ===\n{}\n",
                stdout,
                stderr
            );
        }
        Err(err) => {
            panic!(
                "regrtest transcript validation failed: {err}\n\n=== STDOUT ===\n{}\n\n=== STDERR ===\n{}\n",
                stdout, stderr
            );
        }
    }
}

// ===========================================================================
// Host-only validation tests (no guest execution)
// ===========================================================================

#[test]
fn transcript_rejects_empty() {
    let err = parse_and_validate_regrtest_transcript("", "").unwrap_err();
    assert!(err.contains("empty transcript"), "{err}");

    let err_spaces = parse_and_validate_regrtest_transcript("   \n\t", " \n ").unwrap_err();
    assert!(err_spaces.contains("empty transcript"), "{err_spaces}");
}

#[test]
fn transcript_rejects_skipped_only() {
    // Illustrative fixture: submodule where every test was skipped.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
test_map_timeout (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_map_timeout) ... skipped \"resource 'walltime' is not enabled\"
----------------------------------------------------------------------
Ran 1 test in 0.002s

OK (skipped=1)
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("0 genuine passed tests"), "{err}");
}

#[test]
fn transcript_rejects_expected_failures_only_as_zero_passed() {
    // Illustrative fixture: suite of only expected failures must not count as genuine passed evidence.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 2 tests in 0.100s

OK (expected failures=2)
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("0 genuine passed tests"), "{err}");
}

#[test]
fn transcript_rejects_zero_tests_ran() {
    // Illustrative fixture: empty runner reporting 0 tests.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 0 tests in 0.000s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(
        err.contains("no valid executed unittest summary blocks")
            || err.contains("0 genuine passed tests"),
        "{err}"
    );
}

#[test]
fn transcript_rejects_unittest_failure_summary() {
    // Representative failure syntax matching conf-88115-c00.out.
    let stdout = "\
== Tests result: FAILURE ==

1 test failed:
    test_concurrent_futures.test_process_pool

Result: FAILURE
";
    let stderr = "\
======================================================================
ERROR: test_ressources_gced_in_workers (test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_ressources_gced_in_workers)
----------------------------------------------------------------------
Traceback (most recent call last):
  File \"/usr/local/lib/python3.12/test/test_concurrent_futures/test_process_pool.py\", line 95, in test_ressources_gced_in_workers
    future.result()
concurrent.futures.process.BrokenProcessPool: A process in the process pool was terminated abruptly
----------------------------------------------------------------------
Ran 63 tests in 53.425s

FAILED (errors=1, skipped=9)
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("rejected due to failures"), "{err}");
}

#[test]
fn transcript_rejects_terminal_regrtest_failure() {
    let stdout = "\
== Tests result: FAILURE ==
Result: FAILURE
";
    let stderr = "\
----------------------------------------------------------------------
Ran 10 tests in 1.000s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("rejected due to failures"), "{err}");
}

#[test]
fn transcript_rejects_conflicting_or_non_success_terminal_results() {
    // Result: SUCCESS followed by non-SUCCESS status
    let stdout = "\
== Tests result: SUCCESS ==
Result: SUCCESS
Result: INTERRUPTED
";
    let stderr = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(
        err.contains("multiple conflicting terminal Result markers"),
        "{err}"
    );

    // Non-SUCCESS terminal result
    let stdout_no_tests = "Result: NO TESTS RAN\n";
    let stderr_no_tests = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK
";
    let err_no_tests =
        parse_and_validate_regrtest_transcript(stdout_no_tests, stderr_no_tests).unwrap_err();
    assert!(
        err_no_tests.contains("terminal regrtest status was not SUCCESS"),
        "{err_no_tests}"
    );
}

#[test]
fn transcript_rejects_incomplete_or_aborted_run() {
    // Intermediate submodule ran OK, but process died before terminal 'Result: SUCCESS'.
    let stdout = "0:00:00 load avg: 0.00 [1/8] test_concurrent_futures.test_process_pool\n";
    let stderr = "\
test_free_reference (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference) ... 0.29s ok
----------------------------------------------------------------------
Ran 1 test in 0.290s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("missing terminal 'Result:' marker"), "{err}");
}

#[test]
fn transcript_rejects_unmatched_dangling_ran_block() {
    // Ran block at end of transcript without an OK/FAILED outcome line.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 10 tests in 1.000s
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(
        err.contains("unmatched unittest Ran block at end of transcript"),
        "{err}"
    );
}

#[test]
fn transcript_rejects_overlapping_ran_blocks() {
    // Second Ran block before first is resolved.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s
Ran 10 tests in 1.000s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(
        err.contains("unmatched or overlapping unittest Ran block"),
        "{err}"
    );
}

#[test]
fn transcript_rejects_malformed_ran_syntax() {
    // Arbitrary text or missing fields in Ran syntax.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran some arbitrary tests in 1s

OK
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(err.contains("malformed Ran summary syntax"), "{err}");

    // Non-numeric, non-finite, negative, or missing duration tokens in Ran syntax
    for invalid_dur in ["foos", "NaNs", "-1.0s", "infs", "-infs", "s"] {
        let stderr_bad_dur = format!(
            "----------------------------------------------------------------------\nRan 1 test in {invalid_dur}\n\nOK\n"
        );
        let err_dur = parse_and_validate_regrtest_transcript(stdout, &stderr_bad_dur).unwrap_err();
        assert!(
            err_dur.contains("malformed Ran summary syntax"),
            "expected rejection for duration '{invalid_dur}': {err_dur}"
        );
    }
}

#[test]
fn transcript_rejects_malformed_or_duplicate_or_unknown_ok_fields() {
    // Malformed skipped count
    let stdout = "Result: SUCCESS\n";
    let stderr_bad_skip = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK (skipped=invalid)
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr_bad_skip).unwrap_err();
    assert!(err.contains("malformed skipped count"), "{err}");

    // Duplicate skipped field
    let stderr_dup_skip = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK (skipped=1, skipped=2)
";
    let err_dup = parse_and_validate_regrtest_transcript(stdout, stderr_dup_skip).unwrap_err();
    assert!(err_dup.contains("duplicate 'skipped' field"), "{err_dup}");

    // Unknown field
    let stderr_unknown = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK (skipped=1, unknown_tag=2)
";
    let err_unknown = parse_and_validate_regrtest_transcript(stdout, stderr_unknown).unwrap_err();
    assert!(
        err_unknown.contains("unknown or unsupported field"),
        "{err_unknown}"
    );
}

#[test]
fn transcript_rejects_block_exclusions_exceeding_ran() {
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 5 tests in 0.500s

OK (skipped=6)
";
    let err = parse_and_validate_regrtest_transcript(stdout, stderr).unwrap_err();
    assert!(
        err.contains("block exclusions (6 = 6 skipped + 0 expected failures) exceed total ran (5)"),
        "{err}"
    );
}

#[test]
fn transcript_accepts_singular_and_plural_ran_blocks() {
    // Exact singular "Ran 1 test in 0.001s" and plural "Ran 239 tests in 25.432s" blocks.
    let stdout = "Result: SUCCESS\n";
    let stderr = "\
----------------------------------------------------------------------
Ran 1 test in 0.001s

OK
----------------------------------------------------------------------
Ran 239 tests in 25.432s

OK (skipped=14)
";
    let summary = parse_and_validate_regrtest_transcript(stdout, stderr)
        .expect("valid singular and plural Ran blocks should pass");
    assert_eq!(summary.total_ran, 240);
    assert_eq!(summary.total_skipped, 14);
    assert_eq!(summary.total_expected_failures, 0);
    assert_eq!(summary.total_passed, 226);
    assert!(summary.regrtest_success);
}

#[test]
fn transcript_accepts_illustrative_completion_with_expected_child_diagnostic() {
    // A deadlock / worker crash test where expected child exception diagnostics
    // are printed during the run, but the test handler succeeds and regrtest finishes SUCCESS.
    let stdout = "\
== Tests result: SUCCESS ==
1 test OK.
Result: SUCCESS
";
    let stderr = "\
test_crash_during_func_exec_on_worker (test.test_concurrent_futures.test_deadlock.ProcessPoolForkExecutorDeadlockTest.test_crash_during_func_exec_on_worker) ...
Traceback (most recent call last):
  File \"/usr/local/lib/python3.12/concurrent/futures/process.py\", line 245, in _sendback_result
    result_item = ResultItem(work_id, exception=e)
concurrent.futures.process.BrokenProcessPool: A process in the process pool was terminated abruptly
1.85s ok
----------------------------------------------------------------------
Ran 1 test in 1.850s

OK
";
    let summary = parse_and_validate_regrtest_transcript(stdout, stderr)
        .expect("successful run with expected child diagnostic should pass");
    assert_eq!(summary.total_ran, 1);
    assert_eq!(summary.total_skipped, 0);
    assert_eq!(summary.total_expected_failures, 0);
    assert_eq!(summary.total_passed, 1);
    assert!(summary.regrtest_success);
}

#[test]
fn transcript_accepts_illustrative_multi_submodule_completion_with_skips() {
    // Representative multi-submodule summary blocks using syntax from conf-88115-c00.out.
    let stdout = "\
== Tests result: SUCCESS ==
2 tests OK.
Result: SUCCESS
";
    let stderr = "\
0:00:00 load avg: 0.00 [1/2] test_concurrent_futures.test_process_pool
test_free_reference (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference) ... 0.29s ok
test_idle_process_reuse_multiple (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_multiple) ... skipped 'Incompatible with the fork start method.'
0.03s test_idle_process_reuse_one (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_one) ... skipped 'Incompatible with the fork start method.'
----------------------------------------------------------------------
Ran 3 tests in 1.234s

OK (skipped=2)
0:00:02 load avg: 0.00 [2/2] test_concurrent_futures.test_thread_pool
test_default_workers (test.test_concurrent_futures.test_thread_pool.ThreadPoolExecutorTest.test_default_workers) ... 0.01s ok
----------------------------------------------------------------------
Ran 1 test in 0.050s

OK
";
    let summary = parse_and_validate_regrtest_transcript(stdout, stderr)
        .expect("multi-submodule run with skips should pass");
    assert_eq!(summary.total_ran, 4);
    assert_eq!(summary.total_skipped, 2);
    assert_eq!(summary.total_expected_failures, 0);
    assert_eq!(summary.total_passed, 2);
    assert!(summary.regrtest_success);
}

#[test]
fn recording_writer_write_all_interrupted_then_success_records_no_error() {
    struct InterruptedThenSuccessWriter {
        interrupted_once: bool,
        written: Vec<u8>,
    }

    impl Write for InterruptedThenSuccessWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if !self.interrupted_once {
                self.interrupted_once = true;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "simulated interrupted syscall",
                ));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error_state = Arc::new(Mutex::new(None));
    let path = PathBuf::from("/evidence/test_reducer.stdout.log");
    let inner = InterruptedThenSuccessWriter {
        interrupted_once: false,
        written: Vec::new(),
    };
    let mut writer = RecordingWriter::new(inner, path, Arc::clone(&error_state));

    writer
        .write_all(b"payload after retry")
        .expect("write_all should retry Interrupted and succeed");
    assert!(
        error_state.lock().unwrap().is_none(),
        "transient Interrupted must not record an error"
    );
    assert_eq!(writer.inner.written, b"payload after retry");
}

#[test]
fn recording_writer_write_all_nonempty_ok_zero_records_write_zero() {
    struct ZeroWriter;

    impl Write for ZeroWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error_state = Arc::new(Mutex::new(None));
    let path = PathBuf::from("/evidence/test_reducer.stdout.log");
    let mut writer = RecordingWriter::new(ZeroWriter, path.clone(), Arc::clone(&error_state));

    let err = writer
        .write_all(b"nonempty buffer")
        .expect_err("nonempty Ok(0) must synthesize WriteZero");
    assert_eq!(err.kind(), io::ErrorKind::WriteZero);

    let guard = error_state.lock().unwrap();
    let (err_path, captured_err) = guard.as_ref().expect("WriteZero error must be recorded");
    assert_eq!(err_path, &path);
    assert_eq!(captured_err.kind(), io::ErrorKind::WriteZero);
}

#[test]
fn recording_writer_write_all_empty_succeeds_without_error() {
    struct PanickingWriter;

    impl Write for PanickingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            panic!("write should not be called for empty buffer");
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error_state = Arc::new(Mutex::new(None));
    let path = PathBuf::from("/evidence/test_reducer.stdout.log");
    let mut writer = RecordingWriter::new(PanickingWriter, path, Arc::clone(&error_state));

    writer
        .write_all(b"")
        .expect("empty write_all must succeed immediately");
    assert!(error_state.lock().unwrap().is_none());
}

#[test]
fn recording_writer_write_all_partial_writes_then_terminal_err_records_first_and_preserves_bytes() {
    struct FailingWriter {
        fail_after_bytes: usize,
        written: Vec<u8>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.written.len() >= self.fail_after_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "simulated broken pipe during streaming",
                ));
            }
            let take = (self.fail_after_bytes - self.written.len()).min(buf.len());
            self.written.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.written.len() >= self.fail_after_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "simulated secondary flush error",
                ));
            }
            Ok(())
        }
    }

    let error_state = Arc::new(Mutex::new(None));
    let path = PathBuf::from("/evidence/test_reducer.stdout.log");
    let inner = FailingWriter {
        fail_after_bytes: 5,
        written: Vec::new(),
    };
    let mut writer = RecordingWriter::new(inner, path.clone(), Arc::clone(&error_state));

    let err = writer
        .write_all(b"hello world")
        .expect_err("write_all must fail when inner writer fails");
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

    // Streamed bytes before failure are preserved
    assert_eq!(writer.inner.written, b"hello");

    // First error is recorded
    {
        let guard = error_state.lock().unwrap();
        let (err_path, captured_err) = guard.as_ref().expect("first error recorded");
        assert_eq!(err_path, &path);
        assert_eq!(captured_err.kind(), io::ErrorKind::BrokenPipe);
        assert!(captured_err.to_string().contains("simulated broken pipe"));
    }

    // Secondary error from flush does not overwrite the first recorded error
    let flush_err = writer.flush().expect_err("flush should fail");
    assert_eq!(flush_err.kind(), io::ErrorKind::PermissionDenied);
    {
        let guard = error_state.lock().unwrap();
        let (err_path, captured_err) = guard.as_ref().expect("first error retained");
        assert_eq!(err_path, &path);
        assert_eq!(captured_err.kind(), io::ErrorKind::BrokenPipe);
        assert!(
            captured_err
                .to_string()
                .contains("simulated broken pipe during streaming")
        );
    }
}

#[test]
fn recording_writer_direct_write_interrupted_does_not_record_permanent_error() {
    struct InterruptedWriter;

    impl Write for InterruptedWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "transient signal interrupt",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let error_state = Arc::new(Mutex::new(None));
    let path = PathBuf::from("/evidence/test_reducer.stdout.log");
    let mut writer = RecordingWriter::new(InterruptedWriter, path, Arc::clone(&error_state));

    let err = writer
        .write(b"chunk")
        .expect_err("direct write should return transient Interrupted");
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    assert!(
        error_state.lock().unwrap().is_none(),
        "direct Interrupted error should not be recorded as permanent failure"
    );
}
