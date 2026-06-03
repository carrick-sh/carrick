//! CPython `python3 -m test -v` (unittest verbose) parser. Lifted from
//! `scripts/cpython-parity.py`. The per-test line is
//! `<method> (<dotted.id>)[ [N]] ... <outcome>`; the dotted id is the key and
//! first-occurrence wins (a later subtest line for the same id is ignored).

use super::{Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::BTreeMap;

pub struct RegrtestParser;

const LINE: &str = r"^(\S+) \(([\w.]+)\)(?: \[\d+\])? \.\.\. (.*)$";
const RESULT: &str = r"(?m)^Result:\s*(\w+)";

fn classify(rest: &str) -> Outcome {
    let r = rest.trim();
    if r.starts_with("ok") {
        Outcome::Ok
    } else if r.starts_with("FAIL") {
        Outcome::Fail
    } else if r.starts_with("ERROR") {
        Outcome::Error
    } else if r.starts_with("expected failure") {
        Outcome::Xfail
    } else if r.starts_with("unexpected success") {
        Outcome::Uxsuccess
    } else if r.starts_with("skipped") {
        Outcome::Skipped
    } else {
        Outcome::Other
    }
}

impl VerdictParser for RegrtestParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let (Ok(line_re), Ok(result_re)) = (Regex::new(LINE), Regex::new(RESULT)) else {
            return SuiteResult::empty();
        };

        let mut ids: BTreeMap<String, Outcome> = BTreeMap::new();
        for line in text.lines() {
            if let Some(caps) = line_re.captures(line.trim_end()) {
                let (Some(id), Some(rest)) = (caps.get(2), caps.get(3)) else {
                    continue;
                };
                // first-occurrence wins (cpython-parity's setdefault)
                ids.entry(id.as_str().to_string())
                    .or_insert_with(|| classify(rest.as_str()));
            }
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
}
