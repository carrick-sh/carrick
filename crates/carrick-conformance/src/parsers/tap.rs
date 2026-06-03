//! Node (libuv + node-core) TAP parser — STAGE 1 (coarse), per the phased plan
//! in design §4.3/§13. The legacy Node harness recorded only a coarse
//! PASS/TIMEOUT/FAIL suite verdict from the runner's exit code; stage 1
//! reproduces exactly that fidelity: one synthetic `"suite"` id carrying
//! Ok/Fail, with `totals.n == 0` so the matrix renders the *status word* rather
//! than a fraction.
//!
//! STAGE 2 (a follow-up milestone) will add the real per-test parse
//! (`ok N`/`not ok N`/`1..N`/`# SKIP`/`Bail out!`) for true granularity. The
//! manifest does not change between stages — only this parser deepens.

use super::{Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use std::collections::BTreeMap;

pub struct TapParser;

impl VerdictParser for TapParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let bailed = text.contains("Bail out!");
        // Stage-1 verdict: the runner's exit code is authoritative (0 -> pass),
        // strengthened by an explicit TAP bail-out.
        let ok = raw.exit_code == 0 && !bailed;

        let (outcome, result) = if ok {
            (Outcome::Ok, SuiteOutcome::Success)
        } else {
            (Outcome::Fail, SuiteOutcome::Failure)
        };

        let mut ids = BTreeMap::new();
        ids.insert("suite".to_string(), outcome);

        SuiteResult {
            // n == 0: coarse verdict, matrix shows the status word, not a fraction.
            totals: Totals::default(),
            result,
            ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(exit_code: i32, s: &str) -> Raw {
        Raw {
            stdout: s.to_string(),
            stderr: String::new(),
            exit_code,
            timed_out: false,
        }
    }

    #[test]
    fn exit_zero_is_pass() {
        let r = TapParser.parse(&raw(0, "1..3\nok 1\nok 2\nok 3\n"));
        assert_eq!(r.ids.get("suite"), Some(&Outcome::Ok));
        assert_eq!(r.result, SuiteOutcome::Success);
        assert_eq!(r.totals.n, 0); // coarse -> status word in the matrix
    }

    #[test]
    fn nonzero_exit_is_fail() {
        let r = TapParser.parse(&raw(1, "1..3\nok 1\nnot ok 2\n"));
        assert_eq!(r.ids.get("suite"), Some(&Outcome::Fail));
        assert_eq!(r.result, SuiteOutcome::Failure);
    }

    #[test]
    fn bail_out_is_fail_even_on_exit_zero() {
        let r = TapParser.parse(&raw(0, "ok 1\nBail out! crashed\n"));
        assert_eq!(r.ids.get("suite"), Some(&Outcome::Fail));
    }
}
