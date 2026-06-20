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
        // A Go test binary exits 0 (all passed) or 1 (some failed) ONLY when it
        // ran to completion; any OTHER code is a panic/fatal/signal death
        // mid-run (e.g. the docker `os.test` oracle fatals at
        // TestSpliceFile/TCP-To-TTY → exit 2, truncating at 104/727). Treat that
        // as a crash so a partial run becomes ORACLE_FAIL (oracle side) /
        // CARRICK_CRASH (carrick side) instead of gating against half a suite.
        let recovered_expected_panic_failure = raw.exit_code == 2
            && text.contains("panic: did not panic [recovered]")
            && text.contains("--- FAIL:");
        let crashed = CRASH_SIGNATURES.iter().any(|sig| text.contains(sig))
            || (!matches!(raw.exit_code, 0 | 1) && !recovered_expected_panic_failure);

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
                let slot = ids.entry(normalize_id(name.as_str())).or_insert(o);
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
        } else if ids.is_empty() && text.contains("testing: warning: no tests to run") {
            SuiteOutcome::Success
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

/// Strip run-varying hex addresses from a subtest name so ids are STABLE
/// across runs. Some Go subtests embed pointer values in their names (e.g.
/// errors' `TestAs/As(Errorf(...),_0x6048040008)`) — ASLR makes the address
/// differ every run, so a blessed baseline id can never match a later run
/// (or the other lane), producing phantom per-id diffs on suites where both
/// sides pass everything. `0x` followed by hex becomes `0xADDR`.
pub(crate) fn normalize_id(name: &str) -> String {
    // Only `0x` + >= 8 hex digits collapses to `0xADDR`: short hex literals
    // are usually STABLE test inputs, not pointers (netip's
    // `TestParseAddr/0xc0.0xa8.0x8c.0xff` is a hex-encoded IP — eating those
    // merged distinct subtests and mismatched the cached oracle's raw ids).
    const MIN_PTR_HEX_DIGITS: usize = 8;
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(pos) = rest.find("0x") {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        let hex_len = tail[2..]
            .bytes()
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        if hex_len >= MIN_PTR_HEX_DIGITS {
            out.push_str("0xADDR");
        } else {
            // Short hex literal (or bare "0x"): keep verbatim.
            out.push_str(&tail[..2 + hex_len]);
        }
        rest = &tail[2 + hex_len..];
    }
    out.push_str(rest);
    out
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
    fn pointer_addresses_normalize_to_stable_ids() {
        // errors' TestAs subtests embed pointer values (ASLR-varying) in their
        // names; ids must be stable across runs/lanes or the baseline can
        // never excuse them (phantom diffs on an all-pass suite).
        let out = "\
--- PASS: TestAs/As(Errorf(...),_0x6048040008) (0.00s)
--- PASS: TestAs/As(Errorf(...),_0x604801cb10) (0.00s)
--- PASS: TestParseAddr/0xc0.0xa8.0x8c.0xff (0.00s)
--- PASS: TestNotHex/0xzz (0.00s)
PASS";
        let r = GotestParser.parse(&raw(out));
        assert_eq!(
            r.ids.get("TestAs/As(Errorf(...),_0xADDR)"),
            Some(&Outcome::Ok)
        );
        // Two different pointer addresses collapse to ONE stable id.
        assert_eq!(r.ids.len(), 3);
        // SHORT hex literals are stable test inputs (hex-encoded IPs), kept
        // verbatim — collapsing them merged distinct subtests and mismatched
        // pre-normalization cached oracle ids.
        assert_eq!(
            r.ids.get("TestParseAddr/0xc0.0xa8.0x8c.0xff"),
            Some(&Outcome::Ok)
        );
        // A non-hex "0x" tail is left alone.
        assert_eq!(r.ids.get("TestNotHex/0xzz"), Some(&Outcome::Ok));
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

    #[test]
    fn nonzero_exit_is_crash_not_partial() {
        // 104 PASS then the binary dies mid-run (exit 2), no top-level summary —
        // the docker os.test panic at TestSpliceFile/TCP-To-TTY. Must be `None`
        // (→ ORACLE_FAIL) not a partial Success that gates carrick. Exit 1 (some
        // tests failed but ran to completion) stays a real Failure.
        let out =
            "--- PASS: TestA (0.0s)\n--- PASS: TestB (0.0s)\n=== RUN   TestSpliceFile/TCP-To-TTY";
        let mut crashed = raw(out);
        crashed.exit_code = 2;
        assert_eq!(GotestParser.parse(&crashed).result, SuiteOutcome::None);
        let mut killed = raw(out);
        killed.exit_code = 137; // SIGKILL (timeout)
        assert_eq!(GotestParser.parse(&killed).result, SuiteOutcome::None);
        let mut failed = raw("--- FAIL: TestA (0.0s)\nFAIL");
        failed.exit_code = 1;
        assert_eq!(GotestParser.parse(&failed).result, SuiteOutcome::Failure);
    }

    #[test]
    fn no_tests_to_run_is_success() {
        let r = GotestParser.parse(&raw("testing: warning: no tests to run\nPASS\n"));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.n, 0);
        assert!(r.ids.is_empty());
    }

    #[test]
    fn recovered_expected_panic_is_failure_not_crash() {
        let mut out = raw("\
=== RUN   TestTypeFieldReadOnly
--- FAIL: TestTypeFieldReadOnly (0.00s)
panic: did not panic [recovered]
\tpanic: did not panic
");
        out.exit_code = 2;
        let r = GotestParser.parse(&out);
        assert_eq!(r.result, SuiteOutcome::Failure);
        assert_eq!(r.ids.get("TestTypeFieldReadOnly"), Some(&Outcome::Fail));
    }
}
