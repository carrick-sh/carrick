//! CPython `python3 -m test -v` (unittest verbose) parser. Lifted from
//! `scripts/cpython-parity.py`. The per-test line is
//! `[<duration>] <method> (<dotted.id>)[ [N]] ... [<duration>] <outcome>` (single-line)
//! or `<method> (<dotted.id>)` followed by `<docstring> ... [<duration>] <outcome>` (two-line docstring);
//! the dotted id is the key and first-occurrence wins in regression mode. Closure mode retains every
//! occurrence and includes `[N]` subtest ordinals in the assertion identity.
//!
//! Note on caching: richer parsing accounts for timing decorations (`0.29s ok`, `0.03s <method>`)
//! and two-line docstring formatting in observed CPython 3.12 output. Old cached outputs must be
//! deliberately requalified and are not automatically valid under richer parsing.

use super::{AssertionCollector, Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::BTreeMap;

pub struct RegrtestParser;

/// Determinant of every cached regrtest oracle. The cache stores PARSED
/// outcomes, not the raw transcript, so a parser that recognises more (or
/// different) assertion lines silently disagrees with every committed row: the
/// timed/multiline extension surfaced 21 phantom `cpython-subprocess`
/// regressions whose oracle ids were merely `absent` under the old parse. Bump
/// this whenever the recognised id set or outcome mapping changes; the key
/// change forces a deliberate `--refresh-oracle` instead of a false verdict.
pub const PARSER_FINGERPRINT: &str = "regrtest-v2-timed-multiline";

const LINE: &str = r"^(?:\d+(?:\.\d+)?s )?(\S+) \(([\w.]+)\)(?: \[\d+\])? \.\.\.(?: (.*))?$";
const HEADER_LINE: &str = r"^(?:\d+(?:\.\d+)?s )?(\S+) \(([\w.]+)\)(?: \[\d+\])?$";
const CONT_LINE: &str = r"^.* \.\.\.(?: (.*))?$";

const CLOSURE_LINE: &str =
    r"^(?:\d+(?:\.\d+)?s )?(\S+) \(([\w.]+)\)(?: \[(\d+)\])? \.\.\.(?: (.*))?$";
const CLOSURE_HEADER_LINE: &str = r"^(?:\d+(?:\.\d+)?s )?(\S+) \(([\w.]+)\)(?: \[(\d+)\])?$";

const RESULT: &str = r"(?m)^Result:\s*(\w+)";

/// Strips an optional leading duration prefix like `0.29s ` from the outcome text.
/// If the text is only a duration (e.g. `0.29s`) without a subsequent status,
/// an empty string is returned so it falls through to [`Outcome::Other`].
fn strip_duration_prefix(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return None;
    }
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == frac_start {
            return None;
        }
    }
    if i < bytes.len() && bytes[i] == b's' {
        i += 1;
        if i < bytes.len() && bytes[i].is_ascii_whitespace() {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            return Some(&s[i..]);
        } else if i == bytes.len() {
            return Some("");
        }
    }
    None
}

fn is_status_boundary(rest: &str, kw: &str) -> bool {
    if let Some(suffix) = rest.strip_prefix(kw) {
        suffix.is_empty()
            || suffix.starts_with(' ')
            || suffix.starts_with('\t')
            || suffix.starts_with(':')
    } else {
        false
    }
}

fn classify(rest: &str) -> Outcome {
    let mut r = rest.trim();
    if let Some(stripped) = strip_duration_prefix(r) {
        r = stripped;
    }
    if is_status_boundary(r, "ok") {
        Outcome::Ok
    } else if is_status_boundary(r, "FAIL") {
        Outcome::Fail
    } else if is_status_boundary(r, "ERROR") {
        Outcome::Error
    } else if is_status_boundary(r, "expected failure") {
        Outcome::Xfail
    } else if is_status_boundary(r, "unexpected success") {
        Outcome::Uxsuccess
    } else if is_status_boundary(r, "skipped") {
        Outcome::Skipped
    } else {
        Outcome::Other
    }
}

impl RegrtestParser {
    pub(crate) fn parse_closure(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let (Ok(line_re), Ok(header_re), Ok(cont_re), Ok(result_re)) = (
            Regex::new(CLOSURE_LINE),
            Regex::new(CLOSURE_HEADER_LINE),
            Regex::new(CONT_LINE),
            Regex::new(RESULT),
        ) else {
            return SuiteResult::empty();
        };

        let mut collector = AssertionCollector::default();
        let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
        let mut push_assertion =
            |collector: &mut AssertionCollector, id: &str, ordinal: &str, outcome: Outcome| {
                match outcome {
                    Outcome::Ok => passed += 1,
                    Outcome::Fail | Outcome::Error | Outcome::Uxsuccess => failed += 1,
                    Outcome::Skipped | Outcome::Xfail => skipped += 1,
                    _ => {}
                }
                collector.push(format!("py:{id}{ordinal}"), outcome);
            };

        let mut pending_header: Option<(String, String)> = None;

        for line in text.lines() {
            let trimmed = line.trim_end();
            if let Some(caps) = line_re.captures(trimmed) {
                if let Some((pid, pord)) = pending_header.take() {
                    push_assertion(&mut collector, &pid, &pord, Outcome::Other);
                }
                let Some(id) = caps.get(2) else {
                    continue;
                };
                let ordinal = caps
                    .get(3)
                    .map_or(String::new(), |value| format!("[{}]", value.as_str()));
                let rest = caps.get(4).map_or("", |m| m.as_str());
                let outcome = classify(rest);
                push_assertion(&mut collector, id.as_str(), &ordinal, outcome);
            } else if let Some(caps) = header_re.captures(trimmed) {
                if let Some((pid, pord)) = pending_header.take() {
                    push_assertion(&mut collector, &pid, &pord, Outcome::Other);
                }
                let Some(id) = caps.get(2) else {
                    continue;
                };
                let ordinal = caps
                    .get(3)
                    .map_or(String::new(), |value| format!("[{}]", value.as_str()));
                pending_header = Some((id.as_str().to_string(), ordinal));
            } else if let Some((pid, pord)) = pending_header.take() {
                if let Some(caps) = cont_re.captures(trimmed) {
                    let rest = caps.get(1).map_or("", |m| m.as_str());
                    let outcome = classify(rest);
                    push_assertion(&mut collector, &pid, &pord, outcome);
                } else {
                    push_assertion(&mut collector, &pid, &pord, Outcome::Other);
                }
            }
        }
        if let Some((pid, pord)) = pending_header.take() {
            push_assertion(&mut collector, &pid, &pord, Outcome::Other);
        }

        let ids = collector.into_ids();
        let result = match result_re.captures(&text).and_then(|caps| caps.get(1)) {
            Some(value) if value.as_str().eq_ignore_ascii_case("SUCCESS") => SuiteOutcome::Success,
            Some(_) => SuiteOutcome::Failure,
            None if ids.is_empty() => SuiteOutcome::Empty,
            None => SuiteOutcome::None,
        };
        SuiteResult {
            totals: Totals {
                n: passed + failed,
                passed,
                failed,
                broken: 0,
                skipped,
            },
            result,
            ids,
        }
    }
}

impl VerdictParser for RegrtestParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let (Ok(line_re), Ok(header_re), Ok(cont_re), Ok(result_re)) = (
            Regex::new(LINE),
            Regex::new(HEADER_LINE),
            Regex::new(CONT_LINE),
            Regex::new(RESULT),
        ) else {
            return SuiteResult::empty();
        };

        let mut ids: BTreeMap<String, Outcome> = BTreeMap::new();
        let mut pending_header: Option<String> = None;

        for line in text.lines() {
            let trimmed = line.trim_end();
            if let Some(caps) = line_re.captures(trimmed) {
                if let Some(pid) = pending_header.take() {
                    ids.entry(pid).or_insert(Outcome::Other);
                }
                let Some(id) = caps.get(2) else {
                    continue;
                };
                let rest = caps.get(3).map_or("", |m| m.as_str());
                // first-occurrence wins (cpython-parity's setdefault)
                ids.entry(id.as_str().to_string())
                    .or_insert_with(|| classify(rest));
            } else if let Some(caps) = header_re.captures(trimmed) {
                if let Some(pid) = pending_header.take() {
                    ids.entry(pid).or_insert(Outcome::Other);
                }
                let Some(id) = caps.get(2) else {
                    continue;
                };
                pending_header = Some(id.as_str().to_string());
            } else if let Some(pid) = pending_header.take() {
                if let Some(caps) = cont_re.captures(trimmed) {
                    let rest = caps.get(1).map_or("", |m| m.as_str());
                    ids.entry(pid).or_insert_with(|| classify(rest));
                } else {
                    ids.entry(pid).or_insert(Outcome::Other);
                }
            }
        }
        if let Some(pid) = pending_header.take() {
            ids.entry(pid).or_insert(Outcome::Other);
        }

        let result = match result_re.captures(&text).and_then(|c| c.get(1)) {
            Some(m) if m.as_str().eq_ignore_ascii_case("SUCCESS") => SuiteOutcome::Success,
            Some(_) => SuiteOutcome::Failure,
            // No `Result:` line at all -> mid-run crash/hang (distinct from a clean FAILURE).
            None if ids.is_empty() => SuiteOutcome::Empty,
            None => SuiteOutcome::None,
        };

        let mut t = Totals::default();
        for o in ids.values() {
            match o {
                Outcome::Ok => t.passed += 1,
                Outcome::Fail | Outcome::Error | Outcome::Uxsuccess => t.failed += 1,
                Outcome::Skipped | Outcome::Xfail => t.skipped += 1,
                _ => {}
            }
        }
        t.n = t.passed + t.failed;

        SuiteResult {
            totals: t,
            result,
            ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(stdout: &str) -> Raw {
        Raw {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        }
    }

    #[test]
    fn parses_pass_fail_skip_and_result() {
        let out = "\
test_a (test.test_x.C.test_a) ... ok
test_b (test.test_x.C.test_b) ... FAIL
test_c (test.test_x.C.test_c) ... skipped 'no SCTP'
test_d (test.test_x.C.test_d) [1] ... ok
test_e (test.test_x.C.test_e) ... expected failure

Ran 5 tests in 0.1s

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(r.ids.get("test.test_x.C.test_a"), Some(&Outcome::Ok));
        assert_eq!(r.ids.get("test.test_x.C.test_b"), Some(&Outcome::Fail));
        assert_eq!(r.ids.get("test.test_x.C.test_c"), Some(&Outcome::Skipped));
        assert_eq!(r.ids.get("test.test_x.C.test_e"), Some(&Outcome::Xfail));
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.totals.n, 3);
    }

    #[test]
    fn missing_result_with_tests_is_crash() {
        // tests ran, then the process died before printing `Result:`.
        let out = "test_a (m.C.test_a) ... ok\ntest_b (m.C.test_b) ... ok\n";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::None);
        assert_eq!(r.totals.passed, 2);
    }

    #[test]
    fn empty_output_is_empty() {
        let r = RegrtestParser.parse(&raw(""));
        assert_eq!(r.result, SuiteOutcome::Empty);
        assert!(r.ids.is_empty());
    }

    #[test]
    fn first_occurrence_wins() {
        let out = "test_a (m.C.test_a) ... ok\ntest_a (m.C.test_a) ... FAIL\nResult: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.ids.get("m.C.test_a"), Some(&Outcome::Ok));
    }

    #[test]
    fn closure_keeps_python_duplicate_subtest_ordinals() {
        let out =
            "test_a (m.C.test_a) [1] ... ok\ntest_a (m.C.test_a) [2] ... FAIL\nResult: FAILURE\n";
        let result = RegrtestParser.parse_closure(&raw(out));
        assert!(result.ids.contains_key("py:m.C.test_a[1]#1"));
        assert!(result.ids.contains_key("py:m.C.test_a[2]#1"));
        assert_eq!(result.ids.len(), 2);
    }

    #[test]
    fn parses_duration_before_status() {
        let out = "\
test_free_reference (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference) ... 0.29s ok
test_map (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_map) ... 1.26s ok
test_duplicate_futures (test.test_concurrent_futures.test_as_completed.ProcessPoolForkAsCompletedTest.test_duplicate_futures) ... 10.56s ok
test_zero_seconds (m.C.test_zero_seconds) ... 0.00s ok

Result: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_map"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_as_completed.ProcessPoolForkAsCompletedTest.test_duplicate_futures"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.ids.get("m.C.test_zero_seconds"), Some(&Outcome::Ok));
        assert_eq!(r.totals.passed, 4);
        assert_eq!(r.totals.failed, 0);
        assert_eq!(r.totals.n, 4);
    }

    #[test]
    fn parses_duration_before_next_test_name() {
        let out = "\
0.03s test_idle_process_reuse_one (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_one) ... skipped 'Incompatible with the fork start method.'
0.02s test_killed_child (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_killed_child) ... 0.80s ok
0.09s test_max_tasks_per_child (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_max_tasks_per_child) ... 0.05s ok

Result: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_one"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_killed_child"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_max_tasks_per_child"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.skipped, 1);
        assert_eq!(r.totals.n, 2);
    }

    #[test]
    fn parses_standard_undecorated_rows() {
        let out = "\
test_cancel (test.test_concurrent_futures.test_future.FutureTests.test_cancel) ... ok
test_b (test.test_x.C.test_b) ... FAIL
test_err (test.test_x.C.test_err) ... ERROR
test_skip (test.test_x.C.test_skip) ... skipped 'reason'
test_xfail (test.test_x.C.test_xfail) ... expected failure
test_uxsucc (test.test_x.C.test_uxsucc) ... unexpected success

Result: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_future.FutureTests.test_cancel"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.ids.get("test.test_x.C.test_b"), Some(&Outcome::Fail));
        assert_eq!(r.ids.get("test.test_x.C.test_err"), Some(&Outcome::Error));
        assert_eq!(
            r.ids.get("test.test_x.C.test_skip"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(r.ids.get("test.test_x.C.test_xfail"), Some(&Outcome::Xfail));
        assert_eq!(
            r.ids.get("test.test_x.C.test_uxsucc"),
            Some(&Outcome::Uxsuccess)
        );
        assert_eq!(r.totals.passed, 1);
        assert_eq!(r.totals.failed, 3); // FAIL, ERROR, Uxsuccess
        assert_eq!(r.totals.skipped, 2); // Skipped, Xfail
        assert_eq!(r.totals.n, 4);
    }

    #[test]
    fn parses_timed_fail_error_skipped_and_xfail() {
        let out = "\
test_ressources_gced_in_workers (test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_ressources_gced_in_workers) ... ERROR
0.58s test_saturation (test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_saturation) ... 0.55s ok
0.45s test_exit_during_result_pickle_on_worker (test.test_concurrent_futures.test_deadlock.ProcessPoolForkserverExecutorDeadlockTest.test_exit_during_result_pickle_on_worker) ... ERROR
test_interpreter_shutdown (test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_interpreter_shutdown) ... FAIL
2.13s test_processes_terminate (test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_processes_terminate) ... 0.64s ok
test_timed_fail (m.C.test_timed_fail) ... 1.23s FAIL
test_timed_skip (m.C.test_timed_skip) ... 0.04s skipped 'not supported'
test_timed_xfail (m.C.test_timed_xfail) ... 0.05s expected failure
test_timed_uxsucc (m.C.test_timed_uxsucc) ... 0.06s unexpected success

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_ressources_gced_in_workers"),
            Some(&Outcome::Error)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_saturation"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_deadlock.ProcessPoolForkserverExecutorDeadlockTest.test_exit_during_result_pickle_on_worker"),
            Some(&Outcome::Error)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_interpreter_shutdown"),
            Some(&Outcome::Fail)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_processes_terminate"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.ids.get("m.C.test_timed_fail"), Some(&Outcome::Fail));
        assert_eq!(r.ids.get("m.C.test_timed_skip"), Some(&Outcome::Skipped));
        assert_eq!(r.ids.get("m.C.test_timed_xfail"), Some(&Outcome::Xfail));
        assert_eq!(
            r.ids.get("m.C.test_timed_uxsucc"),
            Some(&Outcome::Uxsuccess)
        );
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.failed, 5); // 2 ERROR + 2 FAIL + 1 uxsucc
        assert_eq!(r.totals.skipped, 2); // 1 skipped + 1 xfail
        assert_eq!(r.totals.n, 7);
    }

    #[test]
    fn retains_other_for_incomplete_or_timing_only_lines() {
        let out = "\
test_incomp (m.C.test_incomp) ... 0.29s
test_empty (m.C.test_empty) ... 
test_unknown (m.C.test_unknown) ... 0.12s mysterious_status
0.05s test_noise (m.C.test_noise) ... unexpected output format

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.ids.get("m.C.test_incomp"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_empty"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_unknown"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_noise"), Some(&Outcome::Other));
        assert_eq!(r.totals.passed, 0);
        assert_eq!(r.totals.failed, 0);
        assert_eq!(r.totals.skipped, 0);
        assert_eq!(r.totals.n, 0);
    }

    #[test]
    fn closure_preserves_duplicate_subtest_identity_with_timing() {
        let out = "\
test_sub (m.C.test_sub) [1] ... 0.12s ok
0.05s test_sub (m.C.test_sub) [2] ... 0.23s FAIL
test_sub (m.C.test_sub) ... 0.34s ok
test_sub (m.C.test_sub) ... 0.45s skipped 'skip reason'

Result: FAILURE";
        let result = RegrtestParser.parse_closure(&raw(out));
        assert_eq!(result.ids.get("py:m.C.test_sub[1]#1"), Some(&Outcome::Ok));
        assert_eq!(result.ids.get("py:m.C.test_sub[2]#1"), Some(&Outcome::Fail));
        assert_eq!(result.ids.get("py:m.C.test_sub#1"), Some(&Outcome::Ok));
        assert_eq!(result.ids.get("py:m.C.test_sub#2"), Some(&Outcome::Skipped));
        assert_eq!(result.ids.len(), 4);
        assert_eq!(result.totals.passed, 2);
        assert_eq!(result.totals.failed, 1);
        assert_eq!(result.totals.skipped, 1);
        assert_eq!(result.totals.n, 3);
    }

    #[test]
    fn parses_exact_real_diagnostic_transcript_lines() {
        let out = "\
== CPython 3.12.13 (main, Aug 5 2026, 03:49:12) [GCC 14.2.0]
== Linux-6.12.0-carrick-aarch64-with-glibc2.41 little-endian
== Python build: release shared LTO+PGO
== cwd: /tmp/test_python_worker_1æ
== CPU count: 4
== encodings: locale=UTF-8 FS=utf-8
== resources: all test resources are disabled, use -u option to unskip tests

Using random seed: 0
0:00:00 load avg: 0.00 Run 8 tests sequentially in a single process
0:00:00 load avg: 0.00 [1/8] test_concurrent_futures.test_process_pool
test_free_reference (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference) ... 0.29s ok
test_idle_process_reuse_multiple (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_multiple) ... skipped 'Incompatible with the fork start method.'
0.03s test_idle_process_reuse_one (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_one) ... skipped 'Incompatible with the fork start method.'
0.02s test_killed_child (test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_killed_child) ... 0.80s ok
test_ressources_gced_in_workers (test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_ressources_gced_in_workers) ... ERROR
0.58s test_saturation (test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_saturation) ... 0.55s ok
test_interpreter_shutdown (test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_interpreter_shutdown) ... FAIL
2.13s test_processes_terminate (test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_processes_terminate) ... 0.64s ok

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_free_reference"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_multiple"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_idle_process_reuse_one"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkProcessPoolExecutorTest.test_killed_child"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_ressources_gced_in_workers"),
            Some(&Outcome::Error)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_process_pool.ProcessPoolForkserverProcessPoolExecutorTest.test_saturation"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_interpreter_shutdown"),
            Some(&Outcome::Fail)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkserverProcessPoolShutdownTest.test_processes_terminate"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.totals.passed, 4);
        assert_eq!(r.totals.failed, 2);
        assert_eq!(r.totals.skipped, 2);
        assert_eq!(r.totals.n, 6);

        let closure = RegrtestParser.parse_closure(&raw(out));
        assert_eq!(closure.ids.len(), 8);
        assert_eq!(closure.totals.passed, 4);
        assert_eq!(closure.totals.failed, 2);
        assert_eq!(closure.totals.skipped, 2);
        assert_eq!(closure.totals.n, 6);
    }

    #[test]
    fn parses_multiline_docstring_header_and_continuation() {
        let out = "\
test_hang_gh83386 (test.test_concurrent_futures.test_shutdown.ProcessPoolForkProcessPoolShutdownTest.test_hang_gh83386)
shutdown(wait=False) doesn't hang at exit with running futures. ... skipped 'Hangs, see https://github.com/python/cpython/issues/83386'
0.23s test_hang_gh94440 (test.test_concurrent_futures.test_shutdown.ProcessPoolForkProcessPoolShutdownTest.test_hang_gh94440)
shutdown(wait=True) doesn't hang when a future was submitted and ... 3.17s ok
test_future_times_out (test.test_concurrent_futures.test_as_completed.ProcessPoolForkAsCompletedTest.test_future_times_out)
Test ``futures.as_completed`` timing out before ... 9.64s ok
test_map_submits_without_iteration (test.test_concurrent_futures.test_thread_pool.ThreadPoolExecutorTest.test_map_submits_without_iteration)
Tests verifying issue 11777. ... 0.23s ok

Result: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkProcessPoolShutdownTest.test_hang_gh83386"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_shutdown.ProcessPoolForkProcessPoolShutdownTest.test_hang_gh94440"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_as_completed.ProcessPoolForkAsCompletedTest.test_future_times_out"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_concurrent_futures.test_thread_pool.ThreadPoolExecutorTest.test_map_submits_without_iteration"),
            Some(&Outcome::Ok)
        );
        assert_eq!(r.totals.passed, 3);
        assert_eq!(r.totals.skipped, 1);
        assert_eq!(r.totals.failed, 0);
        assert_eq!(r.totals.n, 3);
    }

    #[test]
    fn interrupted_multiline_docstring_does_not_steal_status_from_next_test() {
        let out = "\
test_interrupted (m.C.test_interrupted)
test_next (m.C.test_next) ... 0.15s ok
test_interrupted2 (m.C.test_interrupted2)
Traceback (most recent call last):
  File \"test.py\", line 10
test_after_traceback (m.C.test_after_traceback) ... 0.20s ok

Result: SUCCESS";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.ids.get("m.C.test_interrupted"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_next"), Some(&Outcome::Ok));
        assert_eq!(r.ids.get("m.C.test_interrupted2"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_after_traceback"), Some(&Outcome::Ok));
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.failed, 0);
        assert_eq!(r.totals.n, 2);
    }

    #[test]
    fn pending_header_at_eof_is_other() {
        let out = "\
test_a (m.C.test_a) ... ok
test_pending (m.C.test_pending)
";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.ids.get("m.C.test_a"), Some(&Outcome::Ok));
        assert_eq!(r.ids.get("m.C.test_pending"), Some(&Outcome::Other));
        assert_eq!(r.result, SuiteOutcome::None);

        let closure = RegrtestParser.parse_closure(&raw(out));
        assert_eq!(closure.ids.get("py:m.C.test_a#1"), Some(&Outcome::Ok));
        assert_eq!(
            closure.ids.get("py:m.C.test_pending#1"),
            Some(&Outcome::Other)
        );
    }

    #[test]
    fn rejects_invalid_status_boundaries_as_other() {
        let out = "\
test_okay (m.C.test_okay) ... 0.29s okay
test_failish (m.C.test_failish) ... 0.10s FAILUREISH
test_err_none (m.C.test_err_none) ... ERRORFUL
test_skip_not (m.C.test_skip_not) ... skipper

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.ids.get("m.C.test_okay"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_failish"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_err_none"), Some(&Outcome::Other));
        assert_eq!(r.ids.get("m.C.test_skip_not"), Some(&Outcome::Other));
        assert_eq!(r.totals.passed, 0);
        assert_eq!(r.totals.failed, 0);
        assert_eq!(r.totals.n, 0);
    }

    #[test]
    fn closure_multiline_preserves_subtest_ordinals_and_duplicates() {
        let out = "\
test_sub (m.C.test_sub) [1]
subtest doc 1 ... 0.10s ok
0.05s test_sub (m.C.test_sub) [2]
subtest doc 2 ... 0.20s FAIL
test_sub (m.C.test_sub)
plain doc 1 ... 0.30s ok
test_sub (m.C.test_sub)
plain doc 2 ... 0.40s skipped 'skip'

Result: FAILURE";
        let result = RegrtestParser.parse_closure(&raw(out));
        assert_eq!(result.ids.get("py:m.C.test_sub[1]#1"), Some(&Outcome::Ok));
        assert_eq!(result.ids.get("py:m.C.test_sub[2]#1"), Some(&Outcome::Fail));
        assert_eq!(result.ids.get("py:m.C.test_sub#1"), Some(&Outcome::Ok));
        assert_eq!(result.ids.get("py:m.C.test_sub#2"), Some(&Outcome::Skipped));
        assert_eq!(result.ids.len(), 4);
        assert_eq!(result.totals.passed, 2);
        assert_eq!(result.totals.failed, 1);
        assert_eq!(result.totals.skipped, 1);
        assert_eq!(result.totals.n, 3);
    }

    #[test]
    fn parses_representative_mixed_single_and_multiline_fixture() {
        let out = "\
test_cancel (test.test_future.FutureTests.test_cancel) ... ok
test_hang_gh83386 (test.test_shutdown.ShutdownTest.test_hang_gh83386)
shutdown(wait=False) doesn't hang at exit with running futures. ... skipped 'Hangs'
0.23s test_hang_gh94440 (test.test_shutdown.ShutdownTest.test_hang_gh94440)
shutdown(wait=True) doesn't hang when a future was submitted and ... 3.17s ok
test_error (test.test_deadlock.DeadlockTest.test_error) ... ERROR
test_future_times_out (test.test_as_completed.AsCompletedTest.test_future_times_out)
Test ``futures.as_completed`` timing out before ... 9.64s ok
test_fail (test.test_shutdown.ShutdownTest.test_fail) ... FAIL

Result: FAILURE";
        let r = RegrtestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(
            r.ids.get("test.test_future.FutureTests.test_cancel"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids
                .get("test.test_shutdown.ShutdownTest.test_hang_gh83386"),
            Some(&Outcome::Skipped)
        );
        assert_eq!(
            r.ids
                .get("test.test_shutdown.ShutdownTest.test_hang_gh94440"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids.get("test.test_deadlock.DeadlockTest.test_error"),
            Some(&Outcome::Error)
        );
        assert_eq!(
            r.ids
                .get("test.test_as_completed.AsCompletedTest.test_future_times_out"),
            Some(&Outcome::Ok)
        );
        assert_eq!(
            r.ids.get("test.test_shutdown.ShutdownTest.test_fail"),
            Some(&Outcome::Fail)
        );
        assert_eq!(r.totals.passed, 3);
        assert_eq!(r.totals.failed, 2);
        assert_eq!(r.totals.skipped, 1);
        assert_eq!(r.totals.n, 5);

        let closure = RegrtestParser.parse_closure(&raw(out));
        assert_eq!(closure.ids.len(), 6);
        assert_eq!(closure.totals.passed, 3);
        assert_eq!(closure.totals.failed, 2);
        assert_eq!(closure.totals.skipped, 1);
        assert_eq!(closure.totals.n, 5);
    }
}
