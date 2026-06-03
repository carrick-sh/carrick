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
/// A `timed_out` raw short-circuits to a `None`-result empty map (the classifier
/// turns that into a TIMEOUT/ORACLE_FAIL verdict before any per-id diff).
pub fn parse(kind: VerdictKind, raw: &Raw) -> SuiteResult {
    if raw.timed_out {
        return SuiteResult {
            totals: Totals::default(),
            result: SuiteOutcome::None,
            ids: BTreeMap::new(),
        };
    }
    match kind {
        VerdictKind::Regrtest => regrtest::RegrtestParser.parse(raw),
        VerdictKind::Gotest => gotest::GotestParser.parse(raw),
        VerdictKind::Tap => tap::TapParser.parse(raw),
        VerdictKind::Ltp => ltp::LtpParser.parse(raw),
        VerdictKind::Shell => shell::ShellParser.parse(raw),
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
