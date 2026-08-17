//! Strict, baseline-free policy for a complete conformance discovery run.

use crate::Args;
use crate::manifest::Suite;
use crate::verdict::{SuiteReport, Verdict};

/// Invocation and result requirements for a no-excuse closure run.
pub struct ClosurePolicy;

impl ClosurePolicy {
    /// Reject every option that could turn a full HVF discovery into a partial,
    /// retried, stale-image, or baseline-writing run.
    pub fn validate_args(args: &Args) -> Result<(), Vec<String>> {
        if !args.closure {
            return Ok(());
        }

        let mut errors = Vec::new();
        if args.lane != "hvf" {
            errors.push("--closure requires --lane hvf".to_string());
        }
        if args.tier != "full" {
            errors.push("--closure requires the full tier".to_string());
        }
        if !args.ecosystem.is_empty() || !args.suite.is_empty() {
            errors.push("--closure rejects suite and ecosystem filters".to_string());
        }
        if args.flake_retries != 0 {
            errors.push("--closure rejects flake retries".to_string());
        }
        if !args.force {
            errors.push("--closure requires --force".to_string());
        }
        if !args.allow_hang.is_empty() {
            errors.push("--closure rejects --allow-hang".to_string());
        }
        if args.bless {
            errors.push("--closure rejects --bless".to_string());
        }
        if args.bless_from.is_some() {
            errors.push("--closure rejects --bless-from".to_string());
        }
        if args.seed_oracle.is_some() {
            errors.push("--closure rejects --seed-oracle".to_string());
        }
        if args.no_image_refresh {
            errors.push("--closure rejects --no-image-refresh".to_string());
        }
        if args.dry_run || args.render_matrix || args.check_matrix || args.generate_suites {
            errors.push("--closure requires an executed conformance run".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Ensure a closure run accounted for exactly its selected inventory and no
/// report lets a non-MATCH observation escape the final non-zero status.
pub fn validate_closure_reports(selected: &[Suite], reports: &[SuiteReport]) -> anyhow::Result<()> {
    let expected: std::collections::BTreeSet<&str> =
        selected.iter().map(|suite| suite.name.as_str()).collect();
    let actual: std::collections::BTreeSet<&str> =
        reports.iter().map(|report| report.name.as_str()).collect();
    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();
    let duplicate_reports = reports.len() != actual.len();
    let duplicate_selected = selected.len() != expected.len();

    if !missing.is_empty() || !unexpected.is_empty() || duplicate_reports || duplicate_selected {
        let mut details = Vec::new();
        if !missing.is_empty() {
            details.push(format!("missing: {}", missing.join(", ")));
        }
        if !unexpected.is_empty() {
            details.push(format!("unexpected: {}", unexpected.join(", ")));
        }
        if duplicate_reports {
            details.push("duplicate report names".to_string());
        }
        if duplicate_selected {
            details.push("duplicate selected suite names".to_string());
        }
        anyhow::bail!(
            "closure report inventory differs from the selected manifest ({})",
            details.join("; ")
        );
    }

    let incomplete: Vec<String> = reports
        .iter()
        .filter(|report| report.verdict != Verdict::Match)
        .map(|report| format!("{} ({})", report.name, report.verdict.as_str()))
        .collect();
    if !incomplete.is_empty() {
        anyhow::bail!(
            "closure requires MATCH for every selected suite: {}",
            incomplete.join(", ")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ClosurePolicy, validate_closure_reports};
    use crate::Args;
    use crate::manifest::{Ecosystem, Suite, Tier, VerdictKind, Weight};
    use crate::parsers::{SuiteOutcome, Totals};
    use crate::verdict::{SideSummary, SuiteReport, Verdict};
    use clap::Parser;

    struct ArgsFixture;

    impl ArgsFixture {
        fn closure() -> Args {
            Args::parse_from([
                "carrick-conformance",
                "--closure",
                "--lane",
                "hvf",
                "--tier",
                "full",
                "--force",
            ])
        }
    }

    fn suite_named(name: &str) -> Suite {
        Suite {
            name: name.into(),
            ecosystem: Ecosystem::Ltp,
            image: "localhost:5005/conformance:latest".into(),
            cmd: vec!["true".into()],
            verdict: VerdictKind::Shell,
            tier: Tier::Full,
            weight: Weight::Light,
            timeout_s: 1,
            known_gaps: vec![],
            carrick_flags: vec![],
            docker_flags: vec![],
            bind_mounts: vec![],
            env: vec![],
            env_carrick: vec![],
            env_docker: vec![],
            workdir: None,
            entrypoint: None,
        }
    }

    fn report_named(name: &str, verdict: Verdict) -> SuiteReport {
        SuiteReport {
            name: name.into(),
            ecosystem: "ltp".into(),
            tier: "full".into(),
            verdict,
            gating: verdict != Verdict::Match,
            carrick: SideSummary {
                result: SuiteOutcome::Success,
                totals: Totals::default(),
            },
            docker: SideSummary {
                result: SuiteOutcome::Success,
                totals: Totals::default(),
            },
            perf: None,
            timeout_kind: None,
            new_diffs: vec![],
            known_diffs: vec![],
            carrick_run_id: String::new(),
            docker_run_id: String::new(),
            carrick_argv: vec![],
            docker_argv: vec![],
            pairs: Default::default(),
        }
    }

    #[test]
    fn closure_requires_the_complete_hvf_run() {
        let mut args = ArgsFixture::closure();
        args.tier = "smoke".into();
        args.ecosystem = vec!["ltp".into()];
        args.flake_retries = 1;
        args.force = false;
        let errors = ClosurePolicy::validate_args(&args).unwrap_err();
        for expected in ["full tier", "filters", "flake retries", "--force"] {
            assert!(
                errors.iter().any(|error| error.contains(expected)),
                "{expected}"
            );
        }
    }

    #[test]
    fn closure_report_inventory_must_equal_manifest() {
        let selected = vec![suite_named("a"), suite_named("b")];
        let reports = vec![report_named("a", Verdict::Match)];
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(error.to_string().contains("missing: b"));
    }
}
