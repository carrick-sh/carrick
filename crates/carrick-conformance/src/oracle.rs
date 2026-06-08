//! Oracle cache: the docker side of a *deterministic* suite only needs to run
//! once — ever. Its parsed result (totals + per-id outcomes) is cached, keyed by
//! everything that determines docker's behavior (image ref, cmd, docker-side
//! flags/env/mounts/workdir/entrypoint, and the verdict parser). On later gates
//! we skip docker for any suite whose key is already cached and diff carrick
//! against the cached oracle — so a routine run executes ONLY carrick.
//!
//! Re-running docker happens only when (a) a suite is new or its declared docker
//! inputs changed (key miss), or (b) the operator passes `--refresh-oracle`
//! (e.g. after rebuilding an image whose *contents* changed without the suite
//! declaration changing — the key intentionally tracks the suite *declaration*,
//! not the live image digest, so the committed cache stays valid across machines
//! that may not have the images at all).
//!
//! The key is a deterministic `serde_json` serialization of the determinant
//! fields — NOT a `DefaultHasher` digest, which is unstable across Rust versions
//! and so unfit for a committed artifact.

use crate::manifest::{Suite, VerdictKind};
use crate::parsers::{SuiteOutcome, SuiteResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The canonical, stable description of everything that determines docker's
/// output for a suite. Field order is fixed (struct order), so its JSON form is
/// reproducible and usable verbatim as the cache key.
#[derive(Serialize)]
struct OracleKey<'a> {
    image: &'a str,
    cmd: &'a [String],
    docker_flags: &'a [String],
    entrypoint: Option<String>,
    bind_mounts: &'a [String],
    /// docker-side env as `k=v`, in declared order (`env` then `env_docker`).
    env: Vec<String>,
    workdir: Option<&'a str>,
    /// which parser turns docker's raw output into the cached `SuiteResult`.
    verdict: VerdictKind,
}

/// Canonical determinant key for a suite's docker oracle. Carrick-only fields
/// (`carrick_flags`, `env_carrick`, `entrypoint.carrick`) and the per-run
/// `--name`/run-id are deliberately excluded — they cannot change docker output.
pub fn oracle_key(suite: &Suite) -> String {
    let mut env: Vec<String> = Vec::new();
    for kv in suite.env.iter().chain(suite.env_docker.iter()) {
        env.push(format!("{}={}", kv.key, kv.val));
    }
    let key = OracleKey {
        image: &suite.image,
        cmd: &suite.cmd,
        docker_flags: &suite.docker_flags,
        entrypoint: suite.entrypoint.as_ref().and_then(|e| e.for_docker()),
        bind_mounts: &suite.bind_mounts,
        env,
        workdir: suite.workdir.as_deref(),
        verdict: suite.verdict,
    };
    // These are plain owned/borrowed scalars and Vecs — serialization cannot
    // fail; the fallback only exists so a key is always produced.
    serde_json::to_string(&key).unwrap_or_else(|_| format!("name:{}", suite.name))
}

/// One cached docker oracle, one JSONL line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleRecord {
    /// The suite name at cache time — purely for `git diff` legibility; matching
    /// is by `key`, never by name.
    pub name: String,
    /// The canonical determinant key (see [`oracle_key`]).
    pub key: String,
    /// The cached, parsed docker oracle result (totals + per-id outcomes).
    pub result: SuiteResult,
}

/// A committed JSONL cache of docker oracle results, keyed by determinant.
pub struct OracleCache {
    path: PathBuf,
    by_key: BTreeMap<String, OracleRecord>,
    dirty: bool,
}

impl OracleCache {
    /// Load the cache, tolerating a missing file (first run -> empty) and
    /// skipping any unparseable line.
    pub fn load(path: &Path) -> Self {
        let mut by_key = BTreeMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<OracleRecord>(line) {
                    by_key.insert(rec.key.clone(), rec);
                }
            }
        }
        OracleCache {
            path: path.to_path_buf(),
            by_key,
            dirty: false,
        }
    }

    /// The cached docker result for this suite, if its determinant key is present.
    pub fn get(&self, suite: &Suite) -> Option<SuiteResult> {
        self.by_key
            .get(&oracle_key(suite))
            .map(|r| r.result.clone())
    }

    /// Cache a freshly-run docker result. Refuses a non-comparable (crashed /
    /// empty) oracle so a broken run is retried next time, never frozen. Returns
    /// whether it was stored.
    pub fn insert(&mut self, suite: &Suite, result: SuiteResult) -> bool {
        if !is_cacheable(&result) {
            return false;
        }
        let key = oracle_key(suite);
        self.by_key.insert(
            key.clone(),
            OracleRecord {
                name: suite.name.clone(),
                key,
                result,
            },
        );
        self.dirty = true;
        true
    }

    /// Whether any `insert` stored a new record since load.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// Persist, sorted by (name, key), for stable reviewable diffs.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut recs: Vec<&OracleRecord> = self.by_key.values().collect();
        recs.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.key.cmp(&b.key)));
        let mut s = String::new();
        for r in recs {
            s.push_str(&serde_json::to_string(r)?);
            s.push('\n');
        }
        std::fs::write(&self.path, s)?;
        Ok(())
    }
}

/// Only a comparable oracle (the docker side actually produced a verdict) may be
/// cached; a crash/hang/empty must be retried.
fn is_cacheable(result: &SuiteResult) -> bool {
    matches!(result.result, SuiteOutcome::Success | SuiteOutcome::Failure)
}

/// Reconstruct the docker oracle [`SuiteResult`] from a completed gate's
/// [`crate::verdict::SuiteReport`], so a finished run's (expensive) docker work
/// can seed the cache without re-running docker. The report's `pairs` carry the
/// `[carrick, docker]` outcome of every compared id; the docker element rebuilds
/// the oracle's id map exactly (Absent docker entries — carrick-only ids — are
/// dropped, matching what a fresh docker run would record). An empty id map is
/// legitimate (a suite that ran as a single unit with no per-id breakdown).
///
/// The gate is the *verdict*, not whether `pairs` is empty: only Match/Diff/New/
/// Regression mean the per-id comparison actually ran, so `pairs` faithfully
/// reflects docker (even when empty). Crash/timeout SUPPRESS `pairs` before that
/// comparison, and oracle-fail means docker produced nothing comparable — those
/// must be re-run against docker, never frozen, so they return `None`.
pub fn docker_result_from_report(r: &crate::verdict::SuiteReport) -> Option<SuiteResult> {
    use crate::verdict::Verdict;
    let comparison_ran = matches!(
        r.verdict,
        Verdict::Match | Verdict::Diff | Verdict::New | Verdict::Regression
    );
    if !comparison_ran || !is_cacheable_outcome(r.docker.result) {
        return None;
    }
    let mut ids = BTreeMap::new();
    for (id, pair) in &r.pairs {
        let docker_outcome = pair[1];
        if docker_outcome != crate::parsers::Outcome::Absent {
            ids.insert(id.clone(), docker_outcome);
        }
    }
    Some(SuiteResult {
        totals: r.docker.totals.clone(),
        result: r.docker.result,
        ids,
    })
}

fn is_cacheable_outcome(o: SuiteOutcome) -> bool {
    matches!(o, SuiteOutcome::Success | SuiteOutcome::Failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Ecosystem, EnvKv, Suite, Tier, Weight};
    use crate::parsers::{Outcome, Totals};

    fn base_suite() -> Suite {
        Suite {
            name: "s".into(),
            ecosystem: Ecosystem::Cpython,
            image: "localhost:5050/cpython-test:3.12".into(),
            cmd: vec![
                "/usr/local/bin/python3".into(),
                "-m".into(),
                "test".into(),
                "test_x".into(),
            ],
            verdict: VerdictKind::Regrtest,
            tier: Tier::Full,
            weight: Weight::Heavy,
            timeout_s: 60,
            known_gaps: vec![],
            carrick_flags: vec!["--raw".into(), "--fs".into(), "host".into()],
            docker_flags: vec![],
            bind_mounts: vec![],
            env: vec![],
            env_carrick: vec![],
            env_docker: vec![],
            workdir: None,
            entrypoint: None,
        }
    }

    fn result(ids: &[(&str, Outcome)], outcome: SuiteOutcome) -> SuiteResult {
        let mut m = BTreeMap::new();
        for (k, v) in ids {
            m.insert(k.to_string(), *v);
        }
        SuiteResult {
            totals: Totals {
                n: ids.len(),
                passed: ids.iter().filter(|(_, o)| *o == Outcome::Ok).count(),
                ..Default::default()
            },
            result: outcome,
            ids: m,
        }
    }

    #[test]
    fn key_is_stable_and_ignores_carrick_only_fields() {
        let a = base_suite();
        let mut b = base_suite();
        // Differ only in carrick-only / run-irrelevant fields.
        b.name = "different-name".into();
        b.carrick_flags = vec!["--fs".into(), "host".into()];
        b.env_carrick = vec![EnvKv {
            key: "X".into(),
            val: "1".into(),
        }];
        b.tier = Tier::Smoke;
        b.weight = Weight::Light;
        b.timeout_s = 999;
        b.known_gaps = vec!["g".into()];
        assert_eq!(
            oracle_key(&a),
            oracle_key(&b),
            "carrick-only deltas must not change the key"
        );
    }

    #[test]
    fn key_differs_when_docker_inputs_differ() {
        let a = base_suite();
        for mutate in [
            |s: &mut Suite| s.cmd.push("--extra".into()),
            |s: &mut Suite| s.image = "localhost:5050/cpython-test:3.13".into(),
            |s: &mut Suite| s.docker_flags = vec!["--user".into(), "65534".into()],
            |s: &mut Suite| s.workdir = Some("/elsewhere".into()),
            |s: &mut Suite| {
                s.env_docker = vec![EnvKv {
                    key: "TZ".into(),
                    val: "UTC".into(),
                }]
            },
            |s: &mut Suite| s.verdict = VerdictKind::Tap,
        ] {
            let mut b = base_suite();
            mutate(&mut b);
            assert_ne!(
                oracle_key(&a),
                oracle_key(&b),
                "a docker-affecting field must change the key"
            );
        }
    }

    #[test]
    fn round_trips_through_jsonl() {
        let path = std::env::temp_dir().join("carrick-oracle-roundtrip.jsonl");
        let _ = std::fs::remove_file(&path);
        let s = base_suite();
        let r = result(
            &[("t1", Outcome::Ok), ("t2", Outcome::Fail)],
            SuiteOutcome::Failure,
        );

        let mut cache = OracleCache::load(&path);
        assert!(cache.get(&s).is_none(), "empty cache must miss");
        assert!(cache.insert(&s, r.clone()), "comparable result must store");
        assert!(cache.dirty());
        cache.save().expect("save");

        let reloaded = OracleCache::load(&path);
        let got = reloaded.get(&s).expect("hit after reload");
        assert_eq!(got.result, SuiteOutcome::Failure);
        assert_eq!(got.totals.n, 2);
        assert_eq!(got.ids.get("t1").copied(), Some(Outcome::Ok));
        assert_eq!(got.ids.get("t2").copied(), Some(Outcome::Fail));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn miss_when_docker_inputs_change() {
        let path = std::env::temp_dir().join("carrick-oracle-miss.jsonl");
        let _ = std::fs::remove_file(&path);
        let s = base_suite();
        let mut cache = OracleCache::load(&path);
        cache.insert(&s, result(&[("t", Outcome::Ok)], SuiteOutcome::Success));
        cache.save().unwrap();

        let reloaded = OracleCache::load(&path);
        let mut changed = base_suite();
        changed.cmd.push("--new-arg".into());
        assert!(reloaded.get(&changed).is_none(), "changed cmd must miss");
        assert!(reloaded.get(&s).is_some(), "unchanged suite still hits");
        let _ = std::fs::remove_file(&path);
    }

    fn report(
        name: &str,
        verdict: crate::verdict::Verdict,
        docker: SuiteOutcome,
        pairs: &[(&str, [Outcome; 2])],
    ) -> crate::verdict::SuiteReport {
        let mut p = BTreeMap::new();
        for (id, pr) in pairs {
            p.insert(id.to_string(), *pr);
        }
        crate::verdict::SuiteReport {
            name: name.into(),
            ecosystem: "cpython".into(),
            tier: "full".into(),
            verdict,
            gating: false,
            carrick: crate::verdict::SideSummary {
                result: SuiteOutcome::Success,
                totals: Totals::default(),
            },
            docker: crate::verdict::SideSummary {
                result: docker,
                totals: Totals {
                    n: pairs.len(),
                    ..Default::default()
                },
            },
            new_diffs: vec![],
            known_diffs: vec![],
            carrick_run_id: String::new(),
            docker_run_id: String::new(),
            carrick_argv: vec![],
            docker_argv: vec![],
            pairs: p,
        }
    }

    #[test]
    fn reconstructs_docker_oracle_from_report() {
        use crate::verdict::Verdict;
        // docker side reported t1=Ok, t2=Fail; t3 is carrick-only (docker Absent).
        let r = report(
            "s",
            Verdict::Match,
            SuiteOutcome::Failure,
            &[
                ("t1", [Outcome::Ok, Outcome::Ok]),
                ("t2", [Outcome::Ok, Outcome::Fail]),
                ("t3", [Outcome::Ok, Outcome::Absent]),
            ],
        );
        let res = docker_result_from_report(&r).expect("comparable -> Some");
        assert_eq!(res.result, SuiteOutcome::Failure);
        assert_eq!(res.ids.get("t1").copied(), Some(Outcome::Ok));
        assert_eq!(res.ids.get("t2").copied(), Some(Outcome::Fail));
        assert!(
            !res.ids.contains_key("t3"),
            "docker-Absent ids are dropped (carrick-only)"
        );
    }

    #[test]
    fn caches_success_with_no_per_id_breakdown() {
        use crate::verdict::Verdict;
        // A MATCH/SUCCESS suite that ran as a single unit (no per-id ids, so the
        // per-id comparison genuinely produced an empty `pairs`) is a perfectly
        // cacheable oracle: result Success with an empty id map. The full 1228
        // run surfaced 44 such suites being wrongly skipped.
        let r = report("m", Verdict::Match, SuiteOutcome::Success, &[]);
        let res = docker_result_from_report(&r).expect("empty-ids success is cacheable");
        assert_eq!(res.result, SuiteOutcome::Success);
        assert!(res.ids.is_empty());
    }

    #[test]
    fn refuses_to_reconstruct_suppressed_or_broken_report() {
        use crate::verdict::Verdict;
        // Crash/timeout verdicts SUPPRESS pairs (the per-id diff never ran), so the
        // empty id map is not the real docker oracle — must re-run, never seed,
        // even though docker itself succeeded.
        assert!(
            docker_result_from_report(&report(
                "crash",
                Verdict::CarrickCrash,
                SuiteOutcome::Success,
                &[]
            ))
            .is_none()
        );
        assert!(
            docker_result_from_report(&report(
                "timeout",
                Verdict::Timeout,
                SuiteOutcome::Success,
                &[]
            ))
            .is_none()
        );
        // Oracle itself broke (docker None) -> None regardless of verdict.
        assert!(
            docker_result_from_report(&report(
                "oraclefail",
                Verdict::OracleFail,
                SuiteOutcome::None,
                &[]
            ))
            .is_none()
        );
    }

    #[test]
    fn refuses_to_cache_broken_oracle() {
        let path = std::env::temp_dir().join("carrick-oracle-broken.jsonl");
        let _ = std::fs::remove_file(&path);
        let s = base_suite();
        let mut cache = OracleCache::load(&path);
        // docker hung / crashed -> result None, must NOT be cached.
        assert!(!cache.insert(&s, result(&[], SuiteOutcome::None)));
        assert!(!cache.insert(&s, result(&[], SuiteOutcome::Empty)));
        assert!(!cache.dirty(), "nothing stored");
        assert!(cache.get(&s).is_none());
        let _ = std::fs::remove_file(&path);
    }
}
