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
    Diff,
    Regression,
    New,
    CarrickCrash,
    Timeout,
    OracleFail,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Match => "MATCH",
            Verdict::Diff => "DIFF",
            Verdict::Regression => "REGRESSION",
            Verdict::New => "NEW",
            Verdict::CarrickCrash => "CARRICK_CRASH",
            Verdict::Timeout => "TIMEOUT",
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

fn known_gap_match(id: &str, known_gaps: &[String]) -> bool {
    known_gaps
        .iter()
        .any(|g| !g.is_empty() && (id == g || id.contains(g.as_str())))
}

pub fn classify(
    suite: &Suite,
    carrick: &SuiteResult,
    carrick_timed_out: bool,
    docker: &SuiteResult,
    baseline: &Baseline,
) -> Classification {
    // An empty-pairs baseline entry has no per-id comparisons, so later comparable
    // output should read as NEW rather than REGRESSION. It is still a baseline
    // entry for current crash/timeout classification, otherwise stale crash rows
    // can be blessed again as first observations.
    let baseline_entry = baseline.pairs_for(&suite.name);
    let base = baseline_entry.filter(|p| !p.is_empty());

    // 1. Oracle short-circuit: a hung/broken oracle never counts against carrick.
    if docker.result == SuiteOutcome::None || docker.result == SuiteOutcome::Empty {
        return Classification {
            verdict: Verdict::OracleFail,
            gating: false,
            new_diffs: vec![],
            known_diffs: vec![],
            pairs: BTreeMap::new(),
        };
    }

    // 2. carrick crash/timeout short-circuit (one root-cause verdict, no diff storm).
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

    // 3. Both sides produced comparable output -> per-id diff.
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

    #[test]
    fn clean_match() {
        let c = classify(
            &suite(&[]),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            false,
            &res(&[("a", Outcome::Ok), ("b", Outcome::Ok)]),
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::Match);
        assert!(!c.gating);
    }

    #[test]
    fn known_gap_excuses_diff() {
        let c = classify(
            &suite(&["b"]),
            &res(&[("a", Outcome::Ok), ("b", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail), ("b", Outcome::Fail)]),
            false,
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
            &res(&[("a", Outcome::Fail)]),
            false,
            &res(&[("a", Outcome::Ok)]),
            &combined,
        );
        assert_eq!(c.verdict, Verdict::Diff);
        assert!(!c.gating);
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
            &crashed,
            false,
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
            &crashed,
            false,
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
            &res(&[("a", Outcome::Ok)]),
            false,
            &oracle_broke,
            &Baseline::default(),
        );
        assert_eq!(c.verdict, Verdict::OracleFail);
        assert!(!c.gating);
    }
}
