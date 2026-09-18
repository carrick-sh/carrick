//! The classifier: given a carrick `SuiteResult`, a docker `SuiteResult`, the
//! suite's `known_gaps`, and the committed baseline (absent on the first run),
//! produce one verdict per suite — and decide whether it *gates* (fails the
//! build). See design §4.4 / §8.
//!
//! A per-id divergence is EXCUSED iff it is (1) listed in `known_gaps`, OR
//! (2) identical to the baseline's recorded `(carrick, docker)` pair (unchanged).
//! REGRESSION = a divergence excused by neither, against a *present* baseline.
//! With no baseline entry the suite is `New` (write-only, non-gating).

use crate::manifest::Suite;
use crate::parsers::{Outcome, SuiteOutcome, SuiteResult, Totals};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Match,
    /// Closure mode requires identical, nonempty all-pass results from both
    /// sides, so every other observation is a gating incomplete result.
    Incomplete,
    Diff,
    Regression,
    New,
    CarrickCrash,
    Timeout,
    /// Cut off at the operator's Carrick-only diagnostic budget, BELOW the
    /// suite's own declaration. Non-gating (it proves nothing about
    /// correctness) and bless-blocking (there is no measured result to bless);
    /// Phase 1b re-runs it serially at the declared budget for its real verdict.
    BudgetKill,
    OracleFail,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Match => "MATCH",
            Verdict::Incomplete => "INCOMPLETE",
            Verdict::Diff => "DIFF",
            Verdict::Regression => "REGRESSION",
            Verdict::New => "NEW",
            Verdict::CarrickCrash => "CARRICK_CRASH",
            Verdict::Timeout => "TIMEOUT",
            Verdict::BudgetKill => "BUDGET_KILL",
            Verdict::OracleFail => "ORACLE_FAIL",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SideSummary {
    pub result: SuiteOutcome,
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PerfSummary {
    pub carrick_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oracle_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrick_to_oracle_ratio: Option<f64>,
}

/// One per-suite record — the unit of both `results.jsonl` and `baseline.jsonl`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuiteReport {
    pub name: String,
    pub ecosystem: String,
    pub tier: String,
    pub verdict: Verdict,
    /// Whether this verdict should fail the gate (non-zero exit).
    pub gating: bool,
    pub carrick: SideSummary,
    pub docker: SideSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perf: Option<PerfSummary>,
    /// For a TIMEOUT only: WHY the deadline was missed (spinning / starved /
    /// blocked). A starved verdict measured the box, not carrick — see
    /// [`crate::engine::classify_timeout`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_kind: Option<crate::engine::TimeoutKind>,
    /// The deadline the carrick run was actually held to, and which budget
    /// produced it. `Option` (and skipped when absent) so committed baselines
    /// and prior `results.jsonl` files written before this field existed still
    /// parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<crate::engine::CarrickDeadline>,
    /// Phase 1b evidence for a row whose phase-1 measurement was an artefact of
    /// how it was measured. `Option` (and skipped when absent) so committed
    /// baselines and prior results files still parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<SerialConfirmation>,
    /// diverging ids that are NOT excused (the regression set, or first-obs NEW set).
    pub new_diffs: Vec<String>,
    /// diverging ids excused by known_gaps or an unchanged baseline pair.
    pub known_diffs: Vec<String>,
    pub carrick_run_id: String,
    pub docker_run_id: String,
    pub carrick_argv: Vec<String>,
    pub docker_argv: Vec<String>,
    /// id -> [carrick, docker] outcome (the baseline payload for excuser 2).
    pub pairs: BTreeMap<String, [Outcome; 2]>,
}

/// Why a row was re-measured serially in Phase 1b.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmReason {
    /// Cut off at the operator's diagnostic budget, below the declaration.
    BudgetKill,
    /// Got little CPU on an oversubscribed box: the measurement was invalid.
    Starved,
}

/// What Phase 1b observed for one row: the load-run kill it was resolving, and
/// the serial re-measurement that replaced it (or why there was none).
///
/// `perf.carrick_ms` on the report carries the SERIAL number — the only one
/// from a controlled single-variable run and therefore the only citable one.
/// The load run's timing survives here, labelled as a kill observation, never
/// as a ratio.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SerialConfirmation {
    pub reason: ConfirmReason,
    /// Wall time the phase-1 run reached before it was cut off.
    pub load_ms: u64,
    /// The deadline that cut it off, in milliseconds.
    pub load_budget_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_timeout_kind: Option<crate::engine::TimeoutKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_ms: Option<u64>,
    pub serial_timed_out: bool,
    /// Set when no serial re-run happened: `"budget pool exhausted"` or
    /// `"disabled"`. Such a row keeps its phase-1 verdict and still blocks
    /// bless — silent truncation is forbidden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// Per-suite baseline pairs loaded from a prior `baseline.jsonl`.
#[derive(Debug, Default)]
pub struct Baseline {
    by_suite: HashMap<String, BTreeMap<String, [Outcome; 2]>>,
}

impl Baseline {
    pub fn from_jsonl(text: &str) -> Baseline {
        let mut by_suite = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(rep) = serde_json::from_str::<SuiteReport>(line) {
                by_suite.insert(rep.name.clone(), rep.pairs);
            }
        }
        Baseline { by_suite }
    }
    fn pairs_for(&self, suite: &str) -> Option<&BTreeMap<String, [Outcome; 2]>> {
        self.by_suite.get(suite)
    }
    /// UNION an overlay baseline onto this one, returning the combined baseline.
    /// A divergence is excused iff its `(carrick, docker)` pair matches EITHER
    /// the shared baseline OR the overlay — so the overlay's per-suite, per-id
    /// pairs take precedence on collision and otherwise extend the shared set.
    /// Used by the KVM lane to layer `baseline.kvm.jsonl` over the shared
    /// `baseline.jsonl`; an empty overlay is a no-op.
    pub fn with_overlay(mut self, overlay: Baseline) -> Baseline {
        for (suite, pairs) in overlay.by_suite {
            self.by_suite.entry(suite).or_default().extend(pairs);
        }
        self
    }
}

pub struct Classification {
    pub verdict: Verdict,
    pub gating: bool,
    pub new_diffs: Vec<String>,
    pub known_diffs: Vec<String>,
    pub pairs: BTreeMap<String, [Outcome; 2]>,
}

impl Classification {
    fn exact_match(carrick: &SuiteResult, _docker: &SuiteResult) -> Self {
        let pairs = carrick
            .ids
            .iter()
            .map(|(id, outcome)| (id.clone(), [*outcome, *outcome]))
            .collect();
        Self {
            verdict: Verdict::Match,
            gating: false,
            new_diffs: vec![],
            known_diffs: vec![],
            pairs,
        }
    }

    fn incomplete_or_diff(carrick: &SuiteResult, docker: &SuiteResult) -> Self {
        let mut ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        ids.extend(carrick.ids.keys().map(String::as_str));
        ids.extend(docker.ids.keys().map(String::as_str));

        let mut pairs = BTreeMap::new();
        let mut new_diffs = Vec::new();
        for id in ids {
            let carrick_outcome = carrick.ids.get(id).copied().unwrap_or(Outcome::Absent);
            let docker_outcome = docker.ids.get(id).copied().unwrap_or(Outcome::Absent);
            pairs.insert(id.to_string(), [carrick_outcome, docker_outcome]);
            if carrick_outcome != docker_outcome {
                new_diffs.push(id.to_string());
            }
        }

        Self {
            verdict: Verdict::Incomplete,
            gating: true,
            new_diffs,
            known_diffs: vec![],
            pairs,
        }
    }
}

/// Everything the classifier needs to know about the carrick side of one
/// suite. The bare `carrick_timed_out: bool` it replaces could not say WHICH
/// deadline fired, so "missed its own declared budget" and "was cut off by the
/// operator's diagnostic budget" were indistinguishable at the only place a
/// verdict is decided.
pub struct CarrickRunFacts<'a> {
    pub timed_out: bool,
    /// `None` only when carrick never ran (spawn failure).
    pub deadline: Option<crate::engine::CarrickDeadline>,
    pub result: &'a SuiteResult,
}

impl CarrickRunFacts<'_> {
    /// A kill at a deadline BELOW the suite's declaration. Decided by
    /// construction from the recorded provenance, never from elapsed-vs-budget
    /// arithmetic.
    fn is_budget_kill(&self) -> bool {
        self.timed_out && self.deadline.is_some_and(|d| d.is_diagnostic())
    }
}

/// Strict, baseline-free classification for a closure run. Any missing,
/// unequal, failed, skipped, broken, crashed, timed-out, or empty observation
/// is a gating [`Verdict::Incomplete`]; known gaps and prior results are never
/// consulted.
pub fn classify_closure(
    _suite: &Suite,
    facts: CarrickRunFacts<'_>,
    docker: &SuiteResult,
    docker_timed_out: bool,
) -> Classification {
    // Closure demands a complete, identical, nonempty all-pass observation, so
    // a truncated carrick run cannot satisfy it whichever budget truncated it.
    let carrick_timed_out = facts.timed_out;
    let carrick = &align_descriptor_residue(facts.result, docker);
    // Closure is stronger than regression parity: both sides must contain a
    // non-empty all-pass observation. Native failures, broken assertions and
    // skips are missing oracle evidence, even when Carrick reproduces them.
    // True non-applicability must be encoded explicitly in the frozen suite
    // declaration rather than smuggled through as a matched skip.
    if !carrick_timed_out
        && !docker_timed_out
        && carrick.is_strict_closure_success()
        && docker.is_strict_closure_success()
        && carrick.ids == docker.ids
        && carrick.totals.n == docker.totals.n
        && carrick.totals.passed == docker.totals.passed
        && carrick.totals.failed == docker.totals.failed
        && carrick.totals.broken == docker.totals.broken
        && carrick.totals.skipped == docker.totals.skipped
    {
        return Classification::exact_match(carrick, docker);
    }
    Classification::incomplete_or_diff(carrick, docker)
}

/// Rewrite carrick-only assertion ids onto docker-only ids that share the same
/// `ltp:<file>:<line>` anchor, in sorted order, so run-variable descriptor
/// text (ASLR'd pointers, mkstemp suffixes — `chroot02`'s `/tmp/LTP_chrXXXXXX`,
/// `getrusage01`'s `0xffff…` argument) pairs the way the positional scheme
/// always paired it, while ids that DO match exactly (the deterministic
/// fd-type descriptors the scheme exists for) keep identity pairing. A group
/// with more ids on one side leaves the surplus absent — a missing tst_fd
/// inventory entry stays exactly one unexercised pair and shifts nothing.
/// Pairing within a group is by sorted id on both sides; when outcomes within
/// a group differ AND the text varies per run this can mis-pair — the same
/// ambiguity the purely positional scheme had, now confined to the residue.
fn align_descriptor_residue(carrick: &SuiteResult, docker: &SuiteResult) -> SuiteResult {
    let anchor = |id: &str| -> Option<String> {
        // `ltp:<file>:<line>:<descriptor>#<occ>` -> `ltp:<file>:<line>`.
        let rest = id.strip_prefix("ltp:")?;
        let (file, tail) = rest.split_once(':')?;
        // Descriptor-less ids (`ltp:file:line#N`) have nothing to align.
        let (line, tail) = tail.split_once(':')?;
        if line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let _ = tail;
        Some(format!("ltp:{file}:{line}"))
    };
    let mut docker_only: BTreeMap<String, Vec<&String>> = BTreeMap::new();
    for id in docker
        .ids
        .keys()
        .filter(|id| !carrick.ids.contains_key(*id))
    {
        if let Some(anchor) = anchor(id) {
            docker_only.entry(anchor).or_default().push(id);
        }
    }
    let mut renamed: BTreeMap<String, Outcome> = BTreeMap::new();
    for (id, outcome) in &carrick.ids {
        if docker.ids.contains_key(id) {
            renamed.insert(id.clone(), *outcome);
            continue;
        }
        let target = anchor(id)
            .and_then(|anchor| docker_only.get_mut(&anchor))
            .and_then(|ids| {
                if ids.is_empty() {
                    None
                } else {
                    Some(ids.remove(0))
                }
            });
        match target {
            Some(docker_id) => renamed.insert(docker_id.clone(), *outcome),
            None => renamed.insert(id.clone(), *outcome),
        };
    }
    SuiteResult {
        totals: carrick.totals.clone(),
        result: carrick.result,
        ids: renamed,
    }
}

fn known_gap_match(id: &str, known_gaps: &[String]) -> bool {
    known_gaps
        .iter()
        .any(|g| !g.is_empty() && (id == g || id.contains(g.as_str())))
}

pub fn classify(
    suite: &Suite,
    facts: CarrickRunFacts<'_>,
    docker: &SuiteResult,
    baseline: &Baseline,
) -> Classification {
    let carrick = facts.result;
    let carrick_timed_out = facts.timed_out;
    // An empty-pairs baseline entry has no per-id comparisons, so later comparable
    // output should read as NEW rather than REGRESSION. It is still a baseline
    // entry for current crash/timeout classification, otherwise stale crash rows
    // can be blessed again as first observations.
    let baseline_entry = baseline.pairs_for(&suite.name);
    let base = baseline_entry.filter(|p| !p.is_empty());

    // 1. Oracle short-circuit: a hung/broken oracle never counts against carrick.
    // `Truncated` belongs here too: a timed-out oracle produces it rather than
    // `None` now that a deadline no longer discards the transcript, and a hung
    // oracle must still never count against carrick.
    if docker.result == SuiteOutcome::None
        || docker.result == SuiteOutcome::Empty
        || docker.result == SuiteOutcome::Truncated
    {
        return Classification {
            verdict: Verdict::OracleFail,
            gating: false,
            new_diffs: vec![],
            known_diffs: vec![],
            pairs: BTreeMap::new(),
        };
    }

    // 2. A kill at the operator's diagnostic budget is a perf observation by
    // construction: the adaptive deadline IS the project's 2x-Docker bar, so
    // the run was cut off, not stuck. It cannot gate (nothing about parity was
    // measured) and cannot be blessed (there is no result). Phase 1b re-runs it
    // serially at the declared budget for its real verdict.
    if facts.is_budget_kill() {
        return Classification {
            verdict: Verdict::BudgetKill,
            gating: false,
            new_diffs: vec![],
            known_diffs: vec![],
            pairs: BTreeMap::new(),
        };
    }

    // 3. carrick crash/timeout short-circuit (one root-cause verdict, no diff storm).
    if carrick_timed_out || carrick.result == SuiteOutcome::None {
        let v = if carrick_timed_out {
            Verdict::Timeout
        } else {
            Verdict::CarrickCrash
        };
        // Gating unless there is genuinely no baseline entry. Empty-pair entries
        // are not comparable baselines, but they must not hide a current crash.
        let gating = baseline_entry.is_some();
        let verdict = if baseline_entry.is_none() {
            Verdict::New
        } else {
            v
        };
        return Classification {
            verdict,
            gating,
            new_diffs: vec![],
            known_diffs: vec![],
            pairs: BTreeMap::new(),
        };
    }

    // 4. Both sides produced comparable output -> per-id diff.
    let mut ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    ids.extend(carrick.ids.keys().map(String::as_str));
    ids.extend(docker.ids.keys().map(String::as_str));

    let mut pairs = BTreeMap::new();
    let mut new_diffs = Vec::new();
    let mut known_diffs = Vec::new();

    for id in ids {
        let co = carrick.ids.get(id).copied().unwrap_or(Outcome::Absent);
        let dobs = docker.ids.get(id).copied().unwrap_or(Outcome::Absent);
        pairs.insert(id.to_string(), [co, dobs]);
        if co == dobs {
            continue; // agree
        }
        // A native test may self-skip because the condition it is meant to
        // exercise is unavailable or too fast to measure. If Carrick executes
        // that same test and it passes, the stronger Carrick observation is not
        // a regression. Keep the unequal pair visible as a non-gating DIFF;
        // closure remains strict and will still reject either-side skips.
        if co == Outcome::Ok && dobs == Outcome::Skipped {
            known_diffs.push(id.to_string());
            continue;
        }
        // diverging — is it excused?
        let by_gap = known_gap_match(id, &suite.known_gaps);
        let by_baseline = base
            .and_then(|p| p.get(id))
            .map(|b| *b == [co, dobs])
            .unwrap_or(false);
        if by_gap || by_baseline {
            known_diffs.push(id.to_string());
        } else {
            new_diffs.push(id.to_string());
        }
    }

    let (verdict, gating) = if new_diffs.is_empty() {
        if known_diffs.is_empty() {
            (Verdict::Match, false)
        } else {
            (Verdict::Diff, false)
        }
    } else if base.is_none() {
        // First observation: nothing to regress against -> NEW, non-gating.
        (Verdict::New, false)
    } else {
        (Verdict::Regression, true)
    };

    Classification {
        verdict,
        gating,
        new_diffs,
        known_diffs,
        pairs,
    }
}

#[cfg(test)]
mod tests {

    mod closure_outcome_equality {
        use super::super::*;
        use super::facts;

        fn result(ids: &[(&str, Outcome)], outcome: SuiteOutcome) -> SuiteResult {
            let map: BTreeMap<String, Outcome> =
                ids.iter().map(|(k, v)| (k.to_string(), *v)).collect();
            let passed = map.values().filter(|o| **o == Outcome::Ok).count();
            let failed = map.values().filter(|o| **o == Outcome::Fail).count();
            let skipped = map.values().filter(|o| **o == Outcome::Conf).count();
            SuiteResult {
                totals: Totals {
                    n: passed + failed,
                    passed,
                    failed,
                    broken: 0,
                    skipped,
                },
                result: outcome,
                ids: map,
            }
        }

        fn s() -> Suite {
            super::suite(&[])
        }

        /// Closure cannot call an unexercised assertion parity. Applicability
        /// must be made explicit in the frozen declaration instead of being
        /// hidden behind an equal skip on both sides.
        #[test]
        fn matched_skips_are_incomplete() {
            let side = result(
                &[("a#1", Outcome::Ok), ("b#1", Outcome::Conf)],
                SuiteOutcome::Success,
            );
            let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }

        /// A native-oracle failure is not Linux-conformance evidence, even when
        /// Carrick reproduces it exactly.
        #[test]
        fn matched_failures_are_incomplete() {
            let side = result(
                &[("a#1", Outcome::Ok), ("b#1", Outcome::Fail)],
                SuiteOutcome::Failure,
            );
            let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }

        /// Parser totals are independently fail-closed: a broken assertion
        /// cannot disappear merely because the parsed id map contains only Ok.
        #[test]
        fn matched_broken_totals_are_incomplete() {
            let mut side = result(&[("a#1", Outcome::Ok)], SuiteOutcome::Success);
            side.totals.broken = 1;
            let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }

        #[test]
        fn matched_empty_assertion_inventory_is_incomplete() {
            let side = result(&[], SuiteOutcome::Success);
            let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }

        #[test]
        fn matched_non_ok_assertions_are_incomplete() {
            for outcome in [
                Outcome::Fail,
                Outcome::Error,
                Outcome::Skipped,
                Outcome::Xfail,
                Outcome::Uxsuccess,
                Outcome::Broken,
                Outcome::Conf,
                Outcome::Other,
                Outcome::Absent,
            ] {
                let mut side = result(&[("a#1", Outcome::Ok)], SuiteOutcome::Success);
                side.ids.insert("a#1".into(), outcome);
                let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
                assert_eq!(got.verdict, Verdict::Incomplete, "{outcome:?}");
            }
        }

        /// Result-kind divergence is never parity, even with equal ids.
        #[test]
        fn result_kind_divergence_is_incomplete() {
            let a = result(&[("a#1", Outcome::Ok)], SuiteOutcome::Success);
            let b = result(&[("a#1", Outcome::Ok)], SuiteOutcome::Failure);
            let got = classify_closure(&s(), facts(&a, false), &b, false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }

        /// Truncated/empty/none observations never MATCH, however equal.
        #[test]
        fn non_parsed_outcomes_never_match() {
            for outcome in [
                SuiteOutcome::Truncated,
                SuiteOutcome::Empty,
                SuiteOutcome::None,
            ] {
                let side = result(&[("a#1", Outcome::Ok)], outcome);
                let got = classify_closure(&s(), facts(&side, false), &side.clone(), false);
                assert_eq!(got.verdict, Verdict::Incomplete, "{outcome:?}");
            }
        }

        /// A skip present ONLY on carrick's side stays a divergence.
        #[test]
        fn one_sided_skip_stays_incomplete() {
            let a = result(&[("a#1", Outcome::Conf)], SuiteOutcome::Success);
            let b = result(&[("a#1", Outcome::Ok)], SuiteOutcome::Success);
            let got = classify_closure(&s(), facts(&a, false), &b, false);
            assert_eq!(got.verdict, Verdict::Incomplete);
        }
    }

    mod residue_alignment {
        use super::super::*;
        use super::facts;

        fn suite(ids: &[(&str, Outcome)]) -> SuiteResult {
            let map: BTreeMap<String, Outcome> =
                ids.iter().map(|(k, v)| (k.to_string(), *v)).collect();
            let ok = map.values().filter(|o| **o == Outcome::Ok).count();
            SuiteResult {
                totals: Totals {
                    n: map.len(),
                    passed: ok,
                    failed: map.len() - ok,
                    broken: 0,
                    skipped: 0,
                },
                result: if map.values().all(|o| *o == Outcome::Ok) {
                    SuiteOutcome::Success
                } else {
                    SuiteOutcome::Failure
                },
                ids: map,
            }
        }

        fn s() -> Suite {
            super::suite(&[])
        }

        /// Run-variable descriptor text (mkstemp suffixes, ASLR'd pointers)
        /// must pair positionally within its file:line anchor and MATCH.
        #[test]
        fn variable_text_pairs_within_anchor() {
            let carrick = suite(&[
                (
                    "ltp:chroot02.c:28:chroot(/tmp/LTP_chrAAAAAA)_passed#1",
                    Outcome::Ok,
                ),
                (
                    "ltp:chroot02.c:28:chroot(/tmp/LTP_chrBBBBBB)_passed#1",
                    Outcome::Ok,
                ),
            ]);
            let docker = suite(&[
                (
                    "ltp:chroot02.c:28:chroot(/tmp/LTP_chrCCCCCC)_passed#1",
                    Outcome::Ok,
                ),
                (
                    "ltp:chroot02.c:28:chroot(/tmp/LTP_chrDDDDDD)_passed#1",
                    Outcome::Ok,
                ),
            ]);
            let got = classify_closure(&s(), facts(&carrick, false), &docker, false);
            assert_eq!(got.verdict, Verdict::Match, "{:?}", got.pairs);
        }

        /// A genuinely missing assertion (tst_fd inventory gap) must stay one
        /// absent pair and shift nothing else.
        #[test]
        fn missing_inventory_entry_stays_absent() {
            let carrick = suite(&[("ltp:splice07.c:56:on_pipe#1", Outcome::Ok)]);
            let docker = suite(&[
                ("ltp:splice07.c:56:on_pipe#1", Outcome::Ok),
                ("ltp:splice07.c:56:on_fanotify#1", Outcome::Ok),
            ]);
            let got = classify_closure(&s(), facts(&carrick, false), &docker, false);
            assert_eq!(got.verdict, Verdict::Incomplete);
            assert_eq!(
                got.pairs["ltp:splice07.c:56:on_pipe#1"],
                [Outcome::Ok, Outcome::Ok]
            );
            assert_eq!(
                got.pairs["ltp:splice07.c:56:on_fanotify#1"],
                [Outcome::Absent, Outcome::Ok]
            );
        }

        /// Exact-id matches keep identity pairing even when a residue exists
        /// at the same anchor: a divergent OUTCOME on a shared descriptor
        /// must stay a semantic pair, not be re-paired away.
        #[test]
        fn exact_ids_keep_identity_pairing() {
            let carrick = suite(&[
                ("ltp:splice07.c:56:on_pipe#1", Outcome::Fail),
                ("ltp:splice07.c:56:on_0xAAAA#1", Outcome::Ok),
            ]);
            let docker = suite(&[
                ("ltp:splice07.c:56:on_pipe#1", Outcome::Ok),
                ("ltp:splice07.c:56:on_0xBBBB#1", Outcome::Ok),
            ]);
            let got = classify_closure(&s(), facts(&carrick, false), &docker, false);
            assert_eq!(
                got.pairs["ltp:splice07.c:56:on_pipe#1"],
                [Outcome::Fail, Outcome::Ok]
            );
            assert_eq!(
                got.pairs["ltp:splice07.c:56:on_0xBBBB#1"],
                [Outcome::Ok, Outcome::Ok]
            );
        }

        /// Non-LTP ids never align: a go test name only pairs by identity.
        #[test]
        fn non_ltp_ids_do_not_align() {
            let carrick = suite(&[("go:TestOne#1", Outcome::Ok)]);
            let docker = suite(&[("go:TestTwo#1", Outcome::Ok)]);
            let got = classify_closure(&s(), facts(&carrick, false), &docker, false);
            assert_eq!(got.verdict, Verdict::Incomplete);
            assert_eq!(got.pairs["go:TestOne#1"], [Outcome::Ok, Outcome::Absent]);
            assert_eq!(got.pairs["go:TestTwo#1"], [Outcome::Absent, Outcome::Ok]);
        }
    }
    use super::*;
    use crate::manifest::{Ecosystem, Suite, Tier, VerdictKind, Weight};

    fn suite(known: &[&str]) -> Suite {
        Suite {
            name: "s".into(),
            ecosystem: Ecosystem::Cpython,
            image: "localhost:5050/x:1".into(),
            cmd: vec!["c".into()],
            verdict: VerdictKind::Regrtest,
            tier: Tier::Full,
            weight: Weight::Heavy,
            timeout_s: 10,
            known_gaps: known.iter().map(|s| s.to_string()).collect(),
            entrypoint: None,
            carrick_flags: vec!["--fs".into(), "host".into()],
            docker_flags: vec![],
            bind_mounts: vec![],
            env: vec![],
            env_carrick: vec![],
            env_docker: vec![],
            workdir: None,
        }
    }

    /// Test shorthand for the ordinary case: a carrick run held to the suite's
    /// OWN declared budget, so a timeout there is a genuine hang rather than a
    /// budget kill.
    fn facts(result: &SuiteResult, timed_out: bool) -> CarrickRunFacts<'_> {
        CarrickRunFacts {
            timed_out,
            deadline: Some(declared_deadline()),
            result,
        }
    }

    fn res(pairs: &[(&str, Outcome)]) -> SuiteResult {
        let mut ids = BTreeMap::new();
        for (k, v) in pairs {
            ids.insert(k.to_string(), *v);
        }
        SuiteResult {
            totals: Totals::default(),
            result: SuiteOutcome::Success,
            ids,
        }
    }

    fn diagnostic_deadline() -> crate::engine::CarrickDeadline {
        // The sep14 `go-go_types` shape: 14 s of adaptive budget against a
        // 300 s declaration.
        crate::engine::CarrickDeadline {
            declared_s: 300,
            effective_s: 14,
            origin: crate::engine::DeadlineOrigin::AdaptiveOracle,
        }
    }

    fn declared_deadline() -> crate::engine::CarrickDeadline {
        crate::engine::CarrickDeadline {
            declared_s: 300,
            effective_s: 300,
            origin: crate::engine::DeadlineOrigin::Declared,
        }
    }

    fn baseline_with(name: &str, id: &str, pair: [Outcome; 2]) -> Baseline {
        let mut by = HashMap::new();
        let mut p = BTreeMap::new();
        p.insert(id.to_string(), pair);
        by.insert(name.to_string(), p);
        Baseline { by_suite: by }
    }

    /// A kill at the operator's diagnostic budget is a perf observation BY
    /// CONSTRUCTION — AGENTS.md: a row sitting exactly on its budget has a
    /// meaningless ratio — so it can never be a hang verdict. It proves nothing
    /// about correctness (non-gating) and has no measured result to bless.
    #[test]
    fn a_diagnostic_budget_kill_is_not_a_hang_verdict() {
        let baseline = baseline_with("s", "a", [Outcome::Ok, Outcome::Ok]);
        let carrick = res(&[]);
        let got = classify(
            &suite(&[]),
            CarrickRunFacts {
                timed_out: true,
                deadline: Some(diagnostic_deadline()),
                result: &carrick,
            },
            &res(&[("a", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(got.verdict, Verdict::BudgetKill);
        assert!(!got.gating, "a truncated run proves nothing about parity");
        assert_eq!(Verdict::BudgetKill.as_str(), "BUDGET_KILL");
    }

    /// A kill at the suite's OWN declared budget is still a hang: the suite
    /// cannot finish inside the deadline it declares. `Progressing` there means
    /// "making progress but too slow to ever finish", which is a genuine defect
    /// and explicitly not a measurement waiver.
    #[test]
    fn a_declared_budget_kill_stays_a_gating_timeout() {
        let baseline = baseline_with("s", "a", [Outcome::Ok, Outcome::Ok]);
        let carrick = res(&[]);
        let got = classify(
            &suite(&[]),
            CarrickRunFacts {
                timed_out: true,
                deadline: Some(declared_deadline()),
                result: &carrick,
            },
            &res(&[("a", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(got.verdict, Verdict::Timeout);
        assert!(got.gating, "a kill at the declared budget must gate");
        assert!(
            !crate::engine::TimeoutKind::Progressing.is_measurement_failure(),
            "progressing past the DECLARED budget is a defect, never a waiver"
        );

        // With no baseline entry the existing first-observation rule still
        // applies unchanged.
        let got = classify(
            &suite(&[]),
            CarrickRunFacts {
                timed_out: true,
                deadline: Some(declared_deadline()),
                result: &carrick,
            },
            &res(&[("a", Outcome::Ok)]),
            &Baseline::default(),
        );
        assert_eq!(got.verdict, Verdict::New);
        assert!(!got.gating);
    }

    #[test]
    fn clean_match() {
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]), false),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::Match);
        assert!(!c.gating);
    }

    #[test]
    fn carrick_pass_when_oracle_skips_is_non_gating_diff() {
        let baseline = {
            let mut by = HashMap::new();
            let mut p = BTreeMap::new();
            p.insert("a".to_string(), [Outcome::Ok, Outcome::Ok]);
            by.insert("s".to_string(), p);
            Baseline { by_suite: by }
        };
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Ok)]), false),
            &res(&[("a", Outcome::Skipped)]),
            &baseline,
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
        assert!(c.new_diffs.is_empty());
        assert_eq!(c.known_diffs, vec!["a".to_string()]);
        assert_eq!(c.pairs["a"], [Outcome::Ok, Outcome::Skipped]);
    }

    #[test]
    fn known_gap_excuses_diff() {
        let c = classify(
            &suite(&["b"]),
            facts(&res(&[("a", Outcome::Ok), ("b", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
    }

    #[test]
    fn first_obs_diff_is_new_not_regression() {
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok)]),
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::New);
        assert!(!c.gating);
    }

    #[test]
    fn unexcused_diff_against_baseline_is_regression() {
        // baseline says a -> [Ok, Ok]; now a -> [Fail, Ok] (new break)
        let baseline = {
            let mut by = HashMap::new();
            let mut p = BTreeMap::new();
            p.insert("a".to_string(), [Outcome::Ok, Outcome::Ok]);
            by.insert("s".to_string(), p);
            Baseline { by_suite: by }
        };
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(c.verdict, Verdict::Regression);
        assert!(c.gating);
    }

    #[test]
    fn unchanged_baseline_diff_is_green() {
        // baseline already had a -> [Fail, Ok]; still [Fail, Ok] -> excused.
        let baseline = {
            let mut by = HashMap::new();
            let mut p = BTreeMap::new();
            p.insert("a".to_string(), [Outcome::Fail, Outcome::Ok]);
            by.insert("s".to_string(), p);
            Baseline { by_suite: by }
        };
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
    }

    #[test]
    fn overlay_baseline_suppresses_kvm_only_divergence() {
        // The shared baseline lacks any pair for suite "s"; the KVM overlay
        // records a -> [Fail, Ok]. After `with_overlay`, that divergence is
        // excused (DIFF, non-gating) — but a divergence the overlay does NOT
        // cover (b -> [Fail, Ok]) is still a first-obs NEW (and would be a
        // REGRESSION against a present-but-incomplete baseline).
        let shared = Baseline::from_jsonl("");
        let overlay = {
            let mut by = HashMap::new();
            let mut p = BTreeMap::new();
            p.insert("a".to_string(), [Outcome::Fail, Outcome::Ok]);
            by.insert("s".to_string(), p);
            Baseline { by_suite: by }
        };
        let combined = shared.with_overlay(overlay);

        // a is excused by the overlay; with a present baseline for "s" and no
        // unexcused diff, the verdict is DIFF (non-gating).
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok)]),
            &combined,
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
        assert_eq!(c.known_diffs, vec!["a".to_string()]);

        // b is NOT in the overlay -> unexcused divergence against a present
        // baseline -> gating REGRESSION.
        let c2 = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail), ("b", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            &combined,
        );
        assert_eq!(c2.verdict, Verdict::Regression);
        assert!(c2.gating);
        assert_eq!(c2.new_diffs, vec!["b".to_string()]);
    }

    #[test]
    fn empty_overlay_is_a_noop() {
        // Layering an empty overlay leaves the shared baseline unchanged.
        let shared = {
            let mut by = HashMap::new();
            let mut p = BTreeMap::new();
            p.insert("a".to_string(), [Outcome::Fail, Outcome::Ok]);
            by.insert("s".to_string(), p);
            Baseline { by_suite: by }
        };
        let combined = shared.with_overlay(Baseline::from_jsonl(""));
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Fail)]), false),
            &res(&[("a", Outcome::Ok)]),
            &combined,
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
    }

    /// A timed-out run keeps the rows it DID emit. Discarding them made the
    /// classifier union the id sets and mint an `[Absent, Ok]` pair for every
    /// oracle row, charging the suite its whole inventory as unexercised —
    /// roughly 1,900 phantom rows across 85 suites in the 2026-08-17 closure.
    #[test]
    fn closure_charges_a_timeout_only_for_rows_it_did_not_reach() {
        let mut truncated = res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]);
        truncated.result = SuiteOutcome::Truncated;
        let oracle = res(&[
            ("a", Outcome::Ok),
            ("b", Outcome::Ok),
            ("c", Outcome::Ok),
            ("d", Outcome::Ok),
        ]);
        let c = classify_closure(&suite(&[]), facts(&truncated, true), &oracle, false);
        assert_eq!(c.verdict, Verdict::Incomplete, "a deadline is never a pass");
        assert!(c.gating);
        let absent = c.pairs.values().filter(|p| p[0] == Outcome::Absent).count();
        assert_eq!(absent, 2, "only the two rows it never reached: c and d");
        assert_eq!(
            c.pairs["a"],
            [Outcome::Ok, Outcome::Ok],
            "reached rows kept"
        );
    }

    /// A truncated run must never reach the exact-match fast path, even if every
    /// row it managed to emit agrees with the oracle.
    #[test]
    fn a_truncated_run_is_never_a_match() {
        let mut truncated = res(&[("a", Outcome::Ok)]);
        truncated.result = SuiteOutcome::Truncated;
        let c = classify_closure(
            &suite(&[]),
            facts(&truncated, true),
            &res(&[("a", Outcome::Ok)]),
            false,
        );
        assert_eq!(c.verdict, Verdict::Incomplete);
    }

    /// A hung ORACLE still never counts against carrick. It produces
    /// `Truncated` now rather than `None`, so the short-circuit has to know
    /// about it or a slow oracle starts reading as a carrick failure.
    #[test]
    fn a_truncated_oracle_is_still_an_oracle_failure() {
        let mut oracle = res(&[("a", Outcome::Ok)]);
        oracle.result = SuiteOutcome::Truncated;
        let combined = Baseline::from_jsonl("").with_overlay(Baseline::from_jsonl(""));
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Ok)]), false),
            &oracle,
            &combined,
        );
        assert_eq!(c.verdict, Verdict::OracleFail);
        assert!(!c.gating, "a broken oracle must not gate carrick");
    }

    #[test]
    fn carrick_crash_storm_is_single_verdict() {
        let mut crashed = res(&[]);
        crashed.result = SuiteOutcome::None;
        let baseline = {
            let mut by = HashMap::new();
            by.insert("s".to_string(), {
                let mut p = BTreeMap::new();
                p.insert("a".to_string(), [Outcome::Ok, Outcome::Ok]);
                p
            });
            Baseline { by_suite: by }
        };
        let c = classify(
            &suite(&[]),
            facts(&crashed, false),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(c.verdict, Verdict::CarrickCrash);
        assert!(c.gating);
        assert!(c.new_diffs.is_empty(), "no per-id diff storm");
    }

    #[test]
    fn current_carrick_crash_against_empty_baseline_entry_gates() {
        let mut crashed = res(&[]);
        crashed.result = SuiteOutcome::None;
        let baseline = {
            let mut by = HashMap::new();
            by.insert("s".to_string(), BTreeMap::new());
            Baseline { by_suite: by }
        };
        let c = classify(
            &suite(&[]),
            facts(&crashed, false),
            &res(&[("a", Outcome::Ok)]),
            &baseline,
        );
        assert_eq!(c.verdict, Verdict::CarrickCrash);
        assert!(c.gating);
    }

    #[test]
    fn oracle_fail_never_blames_carrick() {
        let mut oracle_broke = res(&[]);
        oracle_broke.result = SuiteOutcome::None;
        let c = classify(
            &suite(&[]),
            facts(&res(&[("a", Outcome::Ok)]), false),
            &oracle_broke,
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::OracleFail);
        assert!(!c.gating);
    }

    /// Known-gap excuses never reach closure classification: identical rows
    /// match on EQUALITY (parity is outcome equality, see
    /// `closure_outcome_equality`), never via the excuse list, and a
    /// divergent row is gating regardless of any excuse entry.
    #[test]
    fn closure_ignores_excuses_entirely() {
        let suite = suite(&["assertion#1"]);
        let carrick = res(&[("assertion#1", Outcome::Broken)]);
        let docker = res(&[("assertion#1", Outcome::Ok)]);
        let got = classify_closure(&suite, facts(&carrick, false), &docker, false);
        assert_eq!(got.verdict, Verdict::Incomplete);
        assert!(got.gating);
        assert!(got.known_diffs.is_empty(), "no excuse channel in closure");
    }

    /// Row-outcome DIVERGENCE always gates, for every outcome kind: parity
    /// is equality, and nothing but equality passes.
    #[test]
    fn closure_gates_every_divergent_outcome_kind() {
        let docker = res(&[("assertion#1", Outcome::Ok)]);
        for outcome in [
            Outcome::Fail,
            Outcome::Broken,
            Outcome::Conf,
            Outcome::Skipped,
            Outcome::Xfail,
            Outcome::Uxsuccess,
            Outcome::Other,
            Outcome::Absent,
        ] {
            let carrick = res(&[("assertion#1", outcome)]);
            assert!(
                classify_closure(&suite(&[]), facts(&carrick, false), &docker, false).gating,
                "{outcome:?} vs Ok must gate"
            );
        }
    }

    #[test]
    fn closure_rejects_parseable_docker_timeout() {
        let side = res(&[("assertion#1", Outcome::Ok)]);
        let got = classify_closure(&suite(&[]), facts(&side, false), &side, true);
        assert_eq!(got.verdict, Verdict::Incomplete);
        assert!(got.gating);
    }
}
