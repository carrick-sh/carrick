//! LTP verdict parser, lifted from `ltp-check.sh`. Two-tier extraction over the
//! combined stdout+stderr:
//!   - Tier 1 (new `tst_test` API): the `Summary:` block (`passed/failed/broken`).
//!   - Tier 2 (old API): count per-line `TPASS/TFAIL/TBROK/TCONF` tokens (those
//!     tests print NO Summary, so a summary-only verdict would false-MATCH them).
//!
//! The LTP verdict is count-based (the skill warns: a count MATCH is NOT proof of
//! the same assertions — probes are the precise gate). We collapse the side to one
//! synthetic `"summary"` id whose coarse outcome (Ok / Fail / Broken / Conf)
//! captures the regression-relevant transition, with the exact counts kept in
//! `Totals` for the matrix fraction.

use super::{Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::BTreeMap;

pub struct LtpParser;

impl VerdictParser for LtpParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        // An explicit `timeout(1)` exit propagated as the child's code.
        if raw.exit_code == 124 || raw.exit_code == 137 {
            return SuiteResult {
                totals: Totals::default(),
                result: SuiteOutcome::None,
                ids: BTreeMap::new(),
            };
        }
        let text = super::strip_carrick_banners(&raw.combined());

        let (mut passed, mut failed, mut broken, mut conf) = (0usize, 0usize, 0usize, 0usize);

        // Tier 1: the Summary block (`passed   5` / `failed   1` / `broken   0`).
        let mut tier1 = false;
        if let Ok(re) = Regex::new(r"(?m)^(passed|failed|broken)\s+(\d+)\s*$") {
            for caps in re.captures_iter(&text) {
                let (Some(k), Some(v)) = (caps.get(1), caps.get(2)) else {
                    continue;
                };
                let n: usize = v.as_str().parse().unwrap_or(0);
                match k.as_str() {
                    "passed" => passed += n,
                    "failed" => failed += n,
                    "broken" => broken += n,
                    _ => {}
                }
                tier1 = true;
            }
        }

        // Tier 2: old-API per-line token counting.
        if !tier1 {
            for line in text.lines() {
                if line.contains("TPASS") {
                    passed += 1;
                } else if line.contains("TFAIL") {
                    failed += 1;
                } else if line.contains("TBROK") {
                    broken += 1;
                } else if line.contains("TCONF") {
                    conf += 1;
                }
            }
        }

        let t = Totals {
            n: passed + failed + broken,
            passed,
            failed,
            broken,
            skipped: 0,
        };

        let (summary, result) = if t.n == 0 && conf == 0 {
            // No tokens at all -> crashed before producing a verdict.
            return SuiteResult {
                totals: t,
                result: SuiteOutcome::Empty,
                ids: BTreeMap::new(),
            };
        } else if broken > 0 {
            (Outcome::Broken, SuiteOutcome::Failure)
        } else if failed > 0 {
            (Outcome::Fail, SuiteOutcome::Failure)
        } else if passed > 0 {
            (Outcome::Ok, SuiteOutcome::Success)
        } else {
            // only TCONF -> not exercised on this kernel
            (Outcome::Conf, SuiteOutcome::Success)
        };

        let mut ids = BTreeMap::new();
        ids.insert("summary".to_string(), summary);

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

    fn raw(s: &str) -> Raw {
        Raw {
            stdout: s.to_string(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        }
    }

    #[test]
    fn tier1_summary_block() {
        let out = "tst_test.c:1: TINFO: ...\nSummary:\npassed   5\nfailed   1\nbroken   0\nskipped  0\nwarnings 0\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.passed, 5);
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Fail));
        assert_eq!(r.result, SuiteOutcome::Failure);
    }

    #[test]
    fn tier1_all_pass() {
        let out = "Summary:\npassed   3\nfailed   0\nbroken   0\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Ok));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.n, 3);
    }

    #[test]
    fn tier2_old_api_tokens() {
        let out = "foo    1  TPASS  :  ok\nfoo    2  TPASS  :  ok\nfoo    3  TFAIL  :  bad\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.totals.passed, 2);
        assert_eq!(r.totals.failed, 1);
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Fail));
    }

    #[test]
    fn tbrok_is_broken() {
        let out = "Summary:\npassed   0\nfailed   0\nbroken   1\n";
        let r = LtpParser.parse(&raw(out));
        assert_eq!(r.ids.get("summary"), Some(&Outcome::Broken));
    }

    #[test]
    fn empty_is_empty() {
        let r = LtpParser.parse(&raw("nothing here\n"));
        assert_eq!(r.result, SuiteOutcome::Empty);
    }
}
