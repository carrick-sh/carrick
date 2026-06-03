//! Go `go test -test.v` text parser (NOT test2json). Lifted from
//! `scripts/go-conformance.sh`: extract `--- PASS/FAIL/SKIP: <Test>` lines.
//!
//! Crash guard FIRST: a guest abort (`failed to run static ELF`, `fault not
//! handled by trap path`, `trap engine failed`, `UnexpectedException`) makes
//! every downstream test look "absent". We classify the whole suite as a
//! mid-run crash (`SuiteOutcome::None`) so the classifier reports one
//! root-cause verdict instead of a per-test diff storm (design §4.4).

use super::{Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::BTreeMap;

pub struct GotestParser;

const CRASH_SIGNATURES: &[&str] = &[
    "failed to run static ELF",
    "fault not handled by trap path",
    "trap engine failed",
    "UnexpectedException",
];

const LINE: &str = r"^\s*--- (PASS|FAIL|SKIP): (\S+)";

impl VerdictParser for GotestParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let crashed = CRASH_SIGNATURES.iter().any(|sig| text.contains(sig));

        let Ok(re) = Regex::new(LINE) else {
            return SuiteResult::empty();
        };

        let mut ids: BTreeMap<String, Outcome> = BTreeMap::new();
        for line in text.lines() {
            if let Some(caps) = re.captures(line) {
                let (Some(status), Some(name)) = (caps.get(1), caps.get(2)) else {
                    continue;
                };
                let o = match status.as_str() {
                    "PASS" => Outcome::Ok,
                    "FAIL" => Outcome::Fail,
                    _ => Outcome::Skipped,
                };
                // Fail dominates Ok dominates Skip for a repeated name.
                let slot = ids.entry(name.as_str().to_string()).or_insert(o);
                if dominance(o) > dominance(*slot) {
                    *slot = o;
                }
            }
        }

        let mut t = Totals::default();
        for o in ids.values() {
            match o {
                Outcome::Ok => t.passed += 1,
                Outcome::Fail => t.failed += 1,
                Outcome::Skipped => t.skipped += 1,
                _ => {}
            }
        }
        t.n = t.passed + t.failed;

        let result = if crashed {
            SuiteOutcome::None
        } else if ids.is_empty() {
            SuiteOutcome::Empty
        } else if t.failed > 0 {
            SuiteOutcome::Failure
        } else {
            SuiteOutcome::Success
        };

        SuiteResult {
            totals: t,
            result,
            ids,
        }
    }
}

fn dominance(o: Outcome) -> u8 {
    match o {
        Outcome::Skipped => 0,
        Outcome::Ok => 1,
        Outcome::Fail => 2,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(s: &str) -> Raw {
        Raw {
            stdout: s.to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        }
    }

    #[test]
    fn parses_pass_fail_skip() {
        let out = "\
=== RUN   TestA
--- PASS: TestA (0.00s)
=== RUN   TestB
--- FAIL: TestB (0.01s)
=== RUN   TestC
--- SKIP: TestC (0.00s)
FAIL";
        let r = GotestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(r.ids.get("TestA"), Some(&Outcome::Ok));
        assert_eq!(r.ids.get("TestB"), Some(&Outcome::Fail));
        assert_eq!(r.ids.get("TestC"), Some(&Outcome::Skipped));
        assert_eq!(r.totals.passed, 1);
        assert_eq!(r.totals.failed, 1);
    }

    #[test]
    fn crash_signature_is_none() {
        let out = "--- PASS: TestA (0.00s)\nfault not handled by trap path esr=0x96000004";
        let r = GotestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::None);
    }

    #[test]
    fn all_pass_is_success() {
        let out = "--- PASS: TestA (0.0s)\n--- PASS: TestB (0.0s)\nPASS\nok\truntime\t0.3s";
        let r = GotestParser.parse(&raw(out));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.passed, 2);
    }
}
