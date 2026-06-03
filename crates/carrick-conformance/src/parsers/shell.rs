//! Deterministic shell-snippet parser (the probe-gate vocabulary). Concatenate
//! stdout+stderr, normalize (drop carrick scratch banners, trim trailing
//! whitespace), and reduce to a coarse pass/fail keyed on the exit code plus a
//! byte-comparable normalized body. Like `tap` stage-1, it emits one synthetic
//! `"suite"` id with `totals.n == 0` (the matrix shows the status word); the
//! per-id diff for a `shell` suite is the exit-code agreement, and the
//! normalized body is surfaced in the raw capture for a reviewer.

use super::{Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use std::collections::BTreeMap;

pub struct ShellParser;

impl VerdictParser for ShellParser {
    fn parse(&self, raw: &Raw) -> SuiteResult {
        let ok = raw.exit_code == 0;
        let (outcome, result) = if ok {
            (Outcome::Ok, SuiteOutcome::Success)
        } else {
            (Outcome::Fail, SuiteOutcome::Failure)
        };
        let mut ids = BTreeMap::new();
        ids.insert("suite".to_string(), outcome);
        SuiteResult {
            totals: Totals::default(),
            result,
            ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_drives_outcome() {
        let ok = ShellParser.parse(&Raw {
            stdout: "aarch64\n".into(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        });
        assert_eq!(ok.ids.get("suite"), Some(&Outcome::Ok));
        let bad = ShellParser.parse(&Raw {
            stdout: String::new(),
            stderr: "boom\n".into(),
            exit_code: 1,
            timed_out: false,
        });
        assert_eq!(bad.ids.get("suite"), Some(&Outcome::Fail));
    }
}
