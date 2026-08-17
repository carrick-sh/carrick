//! Deterministic shell-snippet parser (the probe-gate vocabulary). Concatenate
//! stdout+stderr, normalize (drop carrick scratch banners, trim trailing
//! whitespace), and reduce to a coarse pass/fail keyed on the exit code plus a
//! byte-comparable normalized body. Like `tap` stage-1, it emits one synthetic
//! `"suite"` id with `totals.n == 0` (the matrix shows the status word); the
//! per-id diff for a `shell` suite is the exit-code agreement, and the
//! normalized body is surfaced in the raw capture for a reviewer. Closure mode
//! additionally keys the comparison on the exact exit code and separate stable
//! SHA-256 digests of normalized stdout and stderr.

use super::{AssertionCollector, Outcome, Raw, SuiteOutcome, SuiteResult, Totals, VerdictParser};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct ShellParser;

impl ShellParser {
    pub(crate) fn parse_closure(&self, raw: &Raw) -> SuiteResult {
        let stdout = normalize_body(&raw.stdout);
        let stderr = normalize_body(&raw.stderr);
        let mut collector = AssertionCollector::default();
        collector.push(
            format!("shell:exit:{}", raw.exit_code),
            if raw.exit_code == 0 {
                Outcome::Ok
            } else {
                Outcome::Fail
            },
        );
        collector.push(
            format!("shell:stdout:sha256:{}", sha256(&stdout)),
            Outcome::Ok,
        );
        collector.push(
            format!("shell:stderr:sha256:{}", sha256(&stderr)),
            Outcome::Ok,
        );

        SuiteResult {
            totals: Totals {
                n: 1,
                passed: usize::from(raw.exit_code == 0),
                failed: usize::from(raw.exit_code != 0),
                broken: 0,
                skipped: 0,
            },
            result: if raw.exit_code == 0 {
                SuiteOutcome::Success
            } else {
                SuiteOutcome::Failure
            },
            ids: collector.into_ids(),
        }
    }
}

fn normalize_body(body: &str) -> String {
    super::strip_carrick_banners(body)
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n")
}

fn sha256(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}

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

    fn raw_parts(exit_code: i32, stdout: &str, stderr: &str) -> Raw {
        Raw {
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code,
            timed_out: false,
        }
    }

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

    #[test]
    fn closure_shell_body_is_part_of_the_result() {
        let a = ShellParser.parse_closure(&raw_parts(0, "BUILD_OK\n", ""));
        let b = ShellParser.parse_closure(&raw_parts(0, "WRONG\n", ""));
        let c = ShellParser.parse_closure(&raw_parts(0, "BUILD_OK\n", "warning\n"));
        assert_ne!(a.ids, b.ids);
        assert_ne!(a.ids, c.ids);
        assert!(a.ids.keys().any(|id| id == "shell:exit:0#1"));
    }
}
