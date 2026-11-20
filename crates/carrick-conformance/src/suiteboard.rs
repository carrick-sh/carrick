//! Baseline-free language suite census receipts.

use crate::argv::DockerPlatform;
use crate::manifest::{Ecosystem, Suite, Tier, VerdictKind};
use crate::parsers::{self, Outcome, ParseMode, Raw, SuiteOutcome, SuiteResult};
use crate::verdict::{SuiteReport, Verdict};
use anyhow::{Context as _, ensure};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Slice {
    PyFs,
    PyProc,
    GoOs,
    Smoke,
    NodeLibuv,
}

impl Slice {
    pub fn contains(self, suite: &Suite) -> bool {
        match self {
            Self::PyFs => matches!(
                suite.name.as_str(),
                "cpython-fnmatch"
                    | "cpython-glob"
                    | "cpython-os"
                    | "cpython-pathlib"
                    | "cpython-posix"
                    | "cpython-posixpath"
                    | "cpython-shutil"
                    | "cpython-tempfile"
            ),
            Self::PyProc => matches!(
                suite.name.as_str(),
                "cpython-fork1"
                    | "cpython-multiprocessing_fork"
                    | "cpython-multiprocessing_forkserver"
                    | "cpython-multiprocessing_main_handling"
                    | "cpython-multiprocessing_spawn"
                    | "cpython-pty"
                    | "cpython-signal"
                    | "cpython-subprocess"
                    | "cpython-wait3"
                    | "cpython-wait4"
            ),
            Self::GoOs => suite.name == "go-os" || suite.name.starts_with("go-os_"),
            Self::Smoke => suite.tier == Tier::Smoke && suite.ecosystem != Ecosystem::Ltp,
            Self::NodeLibuv => suite.name == "node-libuv",
        }
    }
}

/// Bind both engines and their cache key to the same fixture image.
pub fn pin_images(
    suites: &mut [Suite],
    path: Option<&Path>,
    platform: DockerPlatform,
) -> anyhow::Result<()> {
    let platform = platform.as_str();
    let pins: BTreeMap<String, BTreeMap<String, String>> = match path {
        Some(path) => {
            let display = path.display();
            let text = std::fs::read_to_string(path) // nosemgrep
                .with_context(|| format!("read suiteboard image pins from {display}"))?;
            toml::from_str(&text)
                .with_context(|| format!("parse suiteboard image pins in {display}"))?
        }
        None => BTreeMap::new(),
    };
    let platform_pins = pins.get(platform);
    for suite in suites {
        let pin = platform_pins.and_then(|pins| pins.get(&suite.image));
        let reference = pin.unwrap_or(&suite.image);
        ensure!(
            reference
                .split_once("@sha256:")
                .is_some_and(|(name, digest)| !name.is_empty()
                    && !name.contains('@')
                    && digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))),
            "{} ({}) on {platform} requires a repo@sha256:<digest> reference. Publish the fixture \
             and add its pin under [\"{platform}\"] in the --suiteboard-images file.",
            suite.name,
            suite.image
        );
        if let Some(pin) = pin {
            suite.image.clone_from(pin);
        }
    }
    Ok(())
}

pub fn parse(suite: &Suite, raw: &Raw) -> SuiteResult {
    let mut parsed = parse_by_kind(suite, raw);
    // A run killed by a signal (the harness reports a negative exit code, and
    // it did not hit its deadline) is a carrick crash for EVERY suite kind,
    // however complete its output looked: never a `diff`.
    if raw.exit_code < 0 && !raw.timed_out {
        parsed.result = SuiteOutcome::None;
    }
    parsed
}

fn parse_by_kind(suite: &Suite, raw: &Raw) -> SuiteResult {
    if suite.verdict == VerdictKind::Shell {
        // The shell smoke row is one workload. Transcript hashes include
        // host diagnostics, and a killed command never reported an outcome.
        if raw.timed_out || raw.exit_code < 0 {
            return SuiteResult {
                result: if raw.timed_out {
                    SuiteOutcome::Truncated
                } else {
                    SuiteOutcome::None
                },
                ..SuiteResult::empty()
            };
        }
        parsers::parse(suite.verdict, raw)
    } else {
        parsers::parse_for_mode(suite.verdict, raw, ParseMode::Closure)
    }
}

/// The image wrapper has its own deadline before the outer process bound.
pub fn inner_deadline(suite: &Suite, raw: &crate::parsers::Raw) -> bool {
    suite.ecosystem == Ecosystem::Node
        && suite
            .entrypoint
            .as_ref()
            .and_then(|entry| entry.both.as_deref())
            == Some("/usr/local/bin/nodejs-conformance")
        && raw.exit_code != 0
        && raw
            .stdout
            .lines()
            .chain(raw.stderr.lines())
            .any(|line| line.trim_end() == "# carrick-suite-hung")
}

#[derive(::serde::Serialize)]
pub struct Identity {
    head: String,
    artifact: Artifact,
}

#[derive(::serde::Serialize)]
struct Artifact {
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cdhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lc_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hypervisor_entitlement: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dof_carrick: Option<bool>,
}

impl Identity {
    pub fn capture(bin: &Path, lane: &crate::lane::Lane) -> anyhow::Result<Self> {
        let head = command_text("git", &["rev-parse", "HEAD"], None)?;
        let mut artifact = Artifact {
            sha256: super::binary_identity(bin)?,
            cdhash: None,
            lc_uuid: None,
            hypervisor_entitlement: None,
            dof_carrick: None,
        };
        if matches!(lane, crate::lane::Lane::Hvf) {
            let signature = command_text("codesign", &["-d", "--verbose=4"], Some(bin))?;
            artifact.cdhash = Some(
                signature
                    .lines()
                    .find_map(|line| line.strip_prefix("CDHash="))
                    .context("signed artifact has no CDHash")?
                    .to_owned(),
            );
            let load = command_text("otool", &["-l"], Some(bin))?;
            artifact.lc_uuid = Some(
                load.lines()
                    .find_map(|line| line.trim().strip_prefix("uuid "))
                    .context("signed artifact has no LC_UUID")?
                    .to_owned(),
            );
            let entitlement = command_text("codesign", &["-d", "--entitlements", "-"], Some(bin))?;
            artifact.hypervisor_entitlement =
                Some(entitlement.contains("com.apple.security.hypervisor"));
            artifact.dof_carrick = Some(load.contains("sectname __dof_carrick"));
            ensure!(
                artifact.hypervisor_entitlement == Some(true),
                "missing hypervisor entitlement"
            );
            ensure!(artifact.dof_carrick == Some(true), "missing __dof_carrick");
        }
        Ok(Self {
            head: head.trim().into(),
            artifact,
        })
    }

    pub fn verify(&self, bin: &Path) -> anyhow::Result<()> {
        ensure!(
            self.artifact.sha256 == super::binary_identity(bin)?,
            "Carrick artifact changed during suiteboard run"
        );
        ensure!(
            self.head == command_text("git", &["rev-parse", "HEAD"], None)?.trim(),
            "HEAD changed during suiteboard run"
        );
        Ok(())
    }
}

fn command_text(program: &str, args: &[&str], path: Option<&Path>) -> anyhow::Result<String> {
    let mut command = Command::new(program); // nosemgrep
    command.args(args).args(path);
    let output = command.output().with_context(|| format!("run {program}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    ensure!(output.status.success(), "{program} failed: {stderr}");
    Ok(format!(
        "{}\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    ))
}

#[derive(Default, ::serde::Serialize)]
struct Population {
    suites_started: usize,
    suites_finished: usize,
    tests_observed: usize,
}

fn finished(outcome: SuiteOutcome) -> bool {
    matches!(outcome, SuiteOutcome::Success | SuiteOutcome::Failure)
}

#[derive(PartialEq, ::serde::Serialize)]
#[serde(untagged)]
enum Observation {
    Test(Outcome),
    Suite(Verdict),
}

#[derive(::serde::Serialize)]
struct Sample<'a> {
    run_id: &'a str,
    outcome: Observation,
}

#[derive(::serde::Serialize)]
struct Unstable<'a> {
    suite: &'a str,
    test: Option<&'a str>,
    observations: Vec<Sample<'a>>,
}

fn unstable<'a>(reports: &'a [SuiteReport]) -> Vec<Unstable<'a>> {
    let mut suites = BTreeMap::<&str, Vec<&SuiteReport>>::new();
    for report in reports {
        if !report.carrick_run_id.is_empty() {
            suites.entry(&report.name).or_default().push(report);
        }
    }
    let mut changed = Vec::new();
    for (suite, rows) in suites {
        let mut record = |test, observations: Vec<Sample<'a>>| {
            if observations
                .windows(2)
                .any(|pair| pair[0].outcome != pair[1].outcome)
            {
                changed.push(Unstable {
                    suite,
                    test,
                    observations,
                });
            }
        };
        let ids = rows
            .iter()
            .flat_map(|row| row.pairs.keys().map(String::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        for id in ids {
            record(
                Some(id),
                rows.iter()
                    .filter_map(|row| {
                        let outcome = row.pairs.get(id).map_or(Outcome::Absent, |pair| pair[0]);
                        (outcome != Outcome::Absent || finished(row.carrick.result)).then_some(
                            Sample {
                                run_id: &row.carrick_run_id,
                                outcome: Observation::Test(outcome),
                            },
                        )
                    })
                    .collect(),
            );
        }
        // The suite-verdict series is recorded whenever the samples' verdicts
        // differ: a suite that did not finish in one sample (a deadline or a
        // crash: missing trailing assertions are not test outcomes), AND a
        // suite whose verdict flips between samples that all finished with the
        // same per-test pairs (`record` drops identical series).
        record(
            None,
            rows.iter()
                .map(|row| Sample {
                    run_id: &row.carrick_run_id,
                    outcome: Observation::Suite(row.verdict),
                })
                .collect(),
        );
    }
    changed
}

pub fn write_receipt(
    path: &Path,
    lane: &str,
    platform: crate::lane::DockerPlatform,
    runs: usize,
    identity: Identity,
    reports: &[SuiteReport],
) -> anyhow::Result<bool> {
    let mut carrick = Population::default();
    let mut oracle = Population::default();
    let mut oracle_names = std::collections::BTreeSet::new();
    for row in reports {
        carrick.suites_started += usize::from(!row.carrick_run_id.is_empty());
        carrick.suites_finished += usize::from(finished(row.carrick.result));
        carrick.tests_observed += row
            .pairs
            .values()
            .filter(|pair| pair[0] != Outcome::Absent)
            .count();
        if oracle_names.insert(&row.name) {
            oracle.suites_started += usize::from(!row.docker_run_id.is_empty());
            oracle.suites_finished += usize::from(finished(row.docker.result));
            oracle.tests_observed += row
                .pairs
                .values()
                .filter(|pair| pair[1] != Outcome::Absent)
                .count();
        }
    }
    let unstable = unstable(reports);
    let receipt = serde_json::json!({
        "schema": "carrick.suiteboard.v1",
        "head": identity.head,
        "artifact": identity.artifact,
        "lane": lane,
        "platform": platform.as_str(),
        "runs": runs,
        "carrick": carrick,
        "oracle": oracle,
        "oracle_source": "cache",
        "unstable": unstable,
    });
    std::fs::write(path, serde_json::to_vec_pretty(&receipt)?)?; // nosemgrep
    eprintln!(
        "suiteboard: {} unstable observation set(s), receipt {}",
        unstable.len(),
        path.display()
    );
    Ok(!unstable.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::Totals;

    fn report(run_id: &str, verdict: Verdict) -> SuiteReport {
        SuiteReport {
            name: "planted".into(),
            ecosystem: "node".into(),
            tier: "smoke".into(),
            verdict,
            gating: false,
            carrick: crate::verdict::SideSummary {
                result: SuiteOutcome::Failure,
                totals: Totals::default(),
            },
            docker: crate::verdict::SideSummary {
                result: SuiteOutcome::Success,
                totals: Totals::default(),
            },
            perf: None,
            timeout_kind: None,
            deadline: None,
            confirmation: None,
            new_diffs: vec![],
            known_diffs: vec![],
            carrick_run_id: run_id.into(),
            docker_run_id: String::new(),
            carrick_argv: vec![],
            docker_argv: vec![],
            pairs: BTreeMap::new(),
        }
    }

    /// Review P0 on #2601: a suite verdict that flips between samples that
    /// all FINISHED (same per-test pairs) was missing from `unstable`.
    #[test]
    fn a_suite_verdict_that_flips_between_finished_samples_is_unstable() {
        let reports = [
            report("run-a", Verdict::Match),
            report("run-b", Verdict::Diff),
        ];
        let changed = unstable(&reports);
        assert_eq!(changed.len(), 1, "the verdict series must be recorded");
        assert!(changed[0].test.is_none());
        let same = [
            report("run-a", Verdict::Diff),
            report("run-b", Verdict::Diff),
        ];
        assert!(unstable(&same).is_empty(), "identical verdicts are stable");
    }

    /// Review P0 on #2601: a signal-killed run with complete output was a
    /// `diff`; every kind must report a crash (result None), deadline aside.
    #[test]
    fn a_signal_killed_run_with_complete_output_is_a_crash_for_every_kind() {
        let complete = "TAP version 13\n1..1\nok 1 - done\n";
        for kind in [VerdictKind::Tap, VerdictKind::Shell] {
            let verdict = if kind == VerdictKind::Tap {
                "tap"
            } else {
                "shell"
            };
            let suite: Suite = toml::from_str(&format!(
                r#"
name = "planted"
ecosystem = "node"
image = "localhost:5005/fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000"
cmd = ["planted"]
verdict = "{verdict}"
tier = "smoke"
weight = "light"
timeout_s = 1
carrick_flags = ["--fs", "host"]
"#
            ))
            .unwrap();
            let killed = Raw {
                stdout: complete.into(),
                stderr: String::new(),
                exit_code: -9,
                timed_out: false,
            };
            assert_eq!(
                parse(&suite, &killed).result,
                SuiteOutcome::None,
                "{kind:?}"
            );
            let deadline = Raw {
                timed_out: true,
                ..killed
            };
            assert_ne!(
                parse(&suite, &deadline).result,
                SuiteOutcome::None,
                "a deadline is not a crash: {kind:?}"
            );
        }
    }
}
