//! Per-ecosystem verdict parsers: map an engine's raw captured output into a
//! normalized, deterministic per-test outcome map. Each parser is a small pure
//! function over [`Raw`] — unit-tested against checked-in fixtures, needing
//! neither carrick nor docker. This is where the parse logic of the four legacy
//! drivers is lifted into Rust (see the design spec §4.3).
//!
//! The cardinal rule: parsers emit *outcome categories* and invariant counts —
//! never timings, pids, tracebacks, or addresses. The classifier diffs these
//! across two machines, so any nondeterminism would be a false divergence.

pub mod gotest;
pub mod ltp;
pub mod regrtest;
pub mod shell;
pub mod tap;

use crate::manifest::VerdictKind;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    Regression,
    Closure,
}

#[derive(Default)]
pub(crate) struct AssertionCollector {
    ids: BTreeMap<String, Outcome>,
    occurrences: BTreeMap<String, usize>,
}

impl AssertionCollector {
    pub fn push(&mut self, base: String, outcome: Outcome) {
        let occurrence = self.occurrences.entry(base.clone()).or_default();
        *occurrence += 1;
        self.ids.insert(format!("{base}#{}", *occurrence), outcome);
    }

    pub fn into_ids(self) -> BTreeMap<String, Outcome> {
        self.ids
    }
}

/// Raw captured output from one engine run, handed to a parser.
#[derive(Debug, Clone)]
pub struct Raw {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
}

impl Raw {
    /// stdout+stderr joined — most LTP/Go output interleaves the two.
    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// A single test's outcome category. Deliberately coarse and deterministic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    Fail,
    Error,
    Skipped,
    /// expected failure (regrtest "expected failure")
    Xfail,
    /// unexpected success (regrtest "unexpected success")
    Uxsuccess,
    /// LTP TBROK — framework setup broke (a hidden test, not a fail)
    Broken,
    /// LTP TCONF — not configured / skipped on this kernel
    Conf,
    Other,
    /// present on the *other* side only — used by the differ, never emitted by a parser
    Absent,
}

/// Suite-level shape, used to short-circuit the per-id diff on crash/empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteOutcome {
    Success,
    Failure,
    /// mid-run crash / hang: no result summary was produced
    None,
    /// produced nothing comparable at all
    Empty,
    /// The run hit its deadline. Any ids alongside this outcome are what it
    /// emitted BEFORE the deadline — real observations, but NOT the complete
    /// inventory, so the suite can never be read as a pass.
    ///
    /// Distinct from [`Self::None`], which used to cover this case by
    /// discarding the transcript entirely. That destroyed the evidence of how
    /// far the run actually got and made the classifier charge the suite's WHOLE
    /// oracle inventory as unexercised — roughly 1,900 phantom rows across 85
    /// suites in the 2026-08-17 closure.
    Truncated,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Totals {
    /// comparable tests (passed + failed + broken, parser-defined)
    pub n: usize,
    pub passed: usize,
    pub failed: usize,
    pub broken: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuiteResult {
    pub totals: Totals,
    pub result: SuiteOutcome,
    pub ids: BTreeMap<String, Outcome>,
}

impl SuiteResult {
    pub fn empty() -> Self {
        SuiteResult {
            totals: Totals::default(),
            result: SuiteOutcome::Empty,
            ids: BTreeMap::new(),
        }
    }
}

pub trait VerdictParser {
    fn parse(&self, raw: &Raw) -> SuiteResult;
}

/// Dispatch a [`Raw`] to the parser named by the manifest's `verdict` field.
/// A `timed_out` raw is still PARSED — see [`parse_for_mode`].
pub fn parse(kind: VerdictKind, raw: &Raw) -> SuiteResult {
    parse_for_mode(kind, raw, ParseMode::Regression)
}

pub fn parse_for_mode(kind: VerdictKind, raw: &Raw, mode: ParseMode) -> SuiteResult {
    let parsed = parse_transcript(kind, raw, mode);
    if raw.timed_out {
        // Parse the transcript we DO have, then stamp it `Truncated`. This used
        // to discard the transcript and return an empty map, which was wrong
        // twice over: it threw away the rows the run genuinely produced (so
        // triage could not see where it died — the "no output means died before
        // flushing, never did not run" trap), and it left the classifier to
        // union the id sets and mint an `[Absent, Ok]` pair for every oracle row,
        // charging the suite its ENTIRE inventory as unexercised.
        //
        // The suite is still a gating failure; a deadline is never a pass. What
        // changes is only that the accounting is now truthful.
        return SuiteResult {
            result: SuiteOutcome::Truncated,
            ..parsed
        };
    }
    parsed
}

fn parse_transcript(kind: VerdictKind, raw: &Raw, mode: ParseMode) -> SuiteResult {
    match (kind, mode) {
        (VerdictKind::Regrtest, ParseMode::Regression) => regrtest::RegrtestParser.parse(raw),
        (VerdictKind::Gotest, ParseMode::Regression) => gotest::GotestParser.parse(raw),
        (VerdictKind::Tap, ParseMode::Regression) => tap::TapParser.parse(raw),
        (VerdictKind::Ltp, ParseMode::Regression) => ltp::LtpParser.parse(raw),
        (VerdictKind::Shell, ParseMode::Regression) => shell::ShellParser.parse(raw),
        (VerdictKind::Regrtest, ParseMode::Closure) => regrtest::RegrtestParser.parse_closure(raw),
        (VerdictKind::Gotest, ParseMode::Closure) => gotest::GotestParser.parse_closure(raw),
        (VerdictKind::Tap, ParseMode::Closure) => tap::TapParser.parse_closure(raw),
        (VerdictKind::Ltp, ParseMode::Closure) => ltp::LtpParser.parse_closure(raw),
        (VerdictKind::Shell, ParseMode::Closure) => shell::ShellParser.parse_closure(raw),
    }
}

/// Strip carrick's host-only advisory banners so its output lines up with docker's.
/// (e.g. `… is case-insensitive; defaulting --fs to memory`, `Pass \`--fs host\``.)
pub(crate) fn strip_carrick_banners(s: &str) -> String {
    s.lines()
        .filter(|l| {
            let lc = l.to_ascii_lowercase();
            !(lc.contains("case-insensitive")
                || lc.contains("pass `--fs")
                || lc.contains("pass --fs"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_keeps_regression_coarse_and_makes_closure_exact() {
        let raw = Raw {
            stdout: "TAP version 13\n1..1\nok 1 - alpha\n".into(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
        };

        let regression = parse(VerdictKind::Tap, &raw);
        let closure = parse_for_mode(VerdictKind::Tap, &raw, ParseMode::Closure);

        assert!(regression.ids.contains_key("suite"));
        assert!(closure.ids.contains_key("tap:1:alpha#1"));
    }
}
