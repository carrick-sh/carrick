//! Node (libuv + node-core) TAP parser. Regression mode preserves the legacy
//! coarse exit-code verdict. Closure mode parses assertion numbers and names,
//! requires one exact plan, and rejects duplicates, gaps, and bailouts.

use super::{AssertionCollector, Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};

pub struct TapParser;

impl TapParser {
    pub(crate) fn parse_closure(&self, raw: &Raw) -> SuiteResult {
        let text = super::strip_carrick_banners(&raw.combined());
        let (Ok(plan_re), Ok(assertion_re)) = (
            Regex::new(r"^1\.\.(\d+)\s*$"),
            Regex::new(r"^(ok|not ok)\s+(\d+)(?:\s*-\s*)?(.*)$"),
        ) else {
            return SuiteResult::empty();
        };

        let mut plans = Vec::new();
        let mut numbers = BTreeSet::new();
        let mut collector = AssertionCollector::default();
        let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
        let mut structurally_valid = !text.contains("Bail out!");

        for line in text.lines().map(str::trim) {
            if let Some(caps) = plan_re.captures(line) {
                if let Some(plan) = caps
                    .get(1)
                    .and_then(|value| value.as_str().parse::<usize>().ok())
                {
                    plans.push(plan);
                }
                continue;
            }

            let Some(caps) = assertion_re.captures(line) else {
                continue;
            };
            let Some(number) = caps
                .get(2)
                .and_then(|value| value.as_str().parse::<usize>().ok())
            else {
                structurally_valid = false;
                continue;
            };
            if !numbers.insert(number) {
                structurally_valid = false;
            }

            let tail = caps.get(3).map_or("", |value| value.as_str()).trim();
            let lower = tail.to_ascii_lowercase();
            let description = tail
                .find(" #")
                .map_or(tail, |directive| &tail[..directive])
                .trim();
            let is_ok = caps.get(1).is_some_and(|value| value.as_str() == "ok");
            let outcome = if lower.contains("# skip") {
                Outcome::Skipped
            } else if lower.contains("# todo") {
                if is_ok {
                    Outcome::Uxsuccess
                } else {
                    Outcome::Xfail
                }
            } else if is_ok {
                Outcome::Ok
            } else {
                Outcome::Fail
            };
            match outcome {
                Outcome::Ok => passed += 1,
                Outcome::Fail | Outcome::Uxsuccess => failed += 1,
                Outcome::Skipped | Outcome::Xfail => skipped += 1,
                _ => {}
            }
            let base = if description.is_empty() {
                format!("tap:{number}")
            } else {
                format!("tap:{number}:{description}")
            };
            collector.push(base, outcome);
        }

        let ids = collector.into_ids();
        let plan = plans.first().copied();
        structurally_valid &= plans.len() == 1;
        structurally_valid &= plan.is_some_and(|count| {
            count > 0
                && count == ids.len()
                && numbers.iter().all(|number| (1..=count).contains(number))
        });

        let totals = Totals {
            n: passed + failed,
            passed,
            failed,
            broken: 0,
            skipped,
        };
        let result = if !structurally_valid || ids.is_empty() {
            SuiteOutcome::None
        } else if failed > 0 || raw.exit_code != 0 {
            SuiteOutcome::Failure
        } else {
            SuiteOutcome::Success
        };
        SuiteResult {
            totals,
            result,
            ids,
        }
    }
}

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

    #[test]
    fn closure_tap_requires_plan_and_assertions() {
        let result = TapParser.parse_closure(&raw(
            0,
            "TAP version 13\n1..2\nok 1 - alpha\nnot ok 2 - beta\n",
        ));
        assert_eq!(result.ids["tap:1:alpha#1"], Outcome::Ok);
        assert_eq!(result.ids["tap:2:beta#1"], Outcome::Fail);
        assert_ne!(
            TapParser.parse_closure(&raw(0, "ok 1 - no-plan\n")).result,
            SuiteOutcome::Success
        );
    }

    #[test]
    fn closure_tap_rejects_duplicate_out_of_range_or_mismatched_assertions() {
        for text in [
            "1..2\nok 1 - alpha\nok 1 - duplicate\n",
            "1..1\nok 2 - out-of-range\n",
            "1..2\nok 1 - missing-two\n",
            "1..1\nok 1 - alpha\n1..1\n",
            "1..1\nok 1 - alpha\nBail out! later\n",
        ] {
            assert_ne!(
                TapParser.parse_closure(&raw(0, text)).result,
                SuiteOutcome::Success,
                "{text}"
            );
        }
    }
}
