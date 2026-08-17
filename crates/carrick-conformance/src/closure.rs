//! Strict, baseline-free policy for a complete conformance discovery run.

use crate::Args;
use crate::manifest::Suite;
use crate::verdict::{SuiteReport, Verdict};

/// The campaign-frozen full HVF manifest denominator. A changed manifest must
/// be deliberately re-scoped rather than silently becoming a closure target.
pub const CLOSURE_SUITE_COUNT: usize = 2_127;

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

/// Reject an empty, drifted, or duplicate closure selection before any run can
/// take the ordinary empty-selection success path.
pub fn validate_closure_selection(selected: &[Suite]) -> anyhow::Result<()> {
    let names: std::collections::BTreeSet<&str> =
        selected.iter().map(|suite| suite.name.as_str()).collect();
    let mut details = Vec::new();
    if names.len() != CLOSURE_SUITE_COUNT {
        details.push(format!(
            "expected exactly {CLOSURE_SUITE_COUNT} unique selected suite names, got {}",
            names.len()
        ));
    }
    if selected.len() != names.len() {
        details.push("duplicate selected suite names".to_string());
    }
    if details.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("closure selection is invalid ({})", details.join("; "));
    }
}

/// Ensure a closure run accounted for exactly its selected inventory and no
/// report lets a non-MATCH observation escape the final non-zero status.
pub fn validate_closure_reports(selected: &[Suite], reports: &[SuiteReport]) -> anyhow::Result<()> {
    validate_closure_selection(selected)?;

    let expected: std::collections::BTreeSet<&str> =
        selected.iter().map(|suite| suite.name.as_str()).collect();
    let actual: std::collections::BTreeSet<&str> =
        reports.iter().map(|report| report.name.as_str()).collect();
    let missing: Vec<&str> = expected.difference(&actual).copied().collect();
    let unexpected: Vec<&str> = actual.difference(&expected).copied().collect();
    let duplicate_reports = reports.len() != actual.len();

    if actual.len() != CLOSURE_SUITE_COUNT
        || !missing.is_empty()
        || !unexpected.is_empty()
        || duplicate_reports
    {
        let mut details = Vec::new();
        if actual.len() != CLOSURE_SUITE_COUNT {
            details.push(format!(
                "expected exactly {CLOSURE_SUITE_COUNT} unique report names, got {}",
                actual.len()
            ));
        }
        if !missing.is_empty() {
            details.push(format!("missing: {}", missing.join(", ")));
        }
        if !unexpected.is_empty() {
            details.push(format!("unexpected: {}", unexpected.join(", ")));
        }
        if duplicate_reports {
            details.push("duplicate report names".to_string());
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
    use super::{
        CLOSURE_SUITE_COUNT, ClosurePolicy, validate_closure_reports, validate_closure_selection,
    };
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

    fn full_inventory() -> Vec<Suite> {
        (0..CLOSURE_SUITE_COUNT)
            .map(|index| suite_named(&format!("suite-{index}")))
            .collect()
    }

    fn matching_reports(selected: &[Suite]) -> Vec<SuiteReport> {
        selected
            .iter()
            .map(|suite| report_named(&suite.name, Verdict::Match))
            .collect()
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
    fn closure_allows_fresh_oracle_discovery_and_frozen_cache_checkpoints() {
        let fresh = Args::try_parse_from([
            "carrick-conformance",
            "--closure",
            "--lane",
            "hvf",
            "--tier",
            "full",
            "--force",
            "--refresh-oracle",
        ])
        .unwrap_or_else(|error| panic!("fresh closure invocation did not parse: {error}"));
        assert!(ClosurePolicy::validate_args(&fresh).is_ok());

        let cached = Args::try_parse_from([
            "carrick-conformance",
            "--closure",
            "--lane",
            "hvf",
            "--tier",
            "full",
            "--force",
            "--require-cached-oracle",
        ])
        .unwrap_or_else(|error| panic!("cached closure invocation did not parse: {error}"));
        assert!(ClosurePolicy::validate_args(&cached).is_ok());
    }

    #[test]
    fn closure_report_inventory_requires_exact_2127_unique_names() {
        let selected = full_inventory();
        let reports = matching_reports(&selected);
        assert!(validate_closure_reports(&selected, &reports).is_ok());
    }

    #[test]
    fn closure_rejects_manifest_relative_inventory() {
        let mut selected = full_inventory();
        selected.pop();
        let reports = matching_reports(&selected);
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("2127 unique selected suite names")
        );
    }

    #[test]
    fn closure_rejects_zero_selected_suite_names() {
        let error = validate_closure_selection(&[]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("2127 unique selected suite names")
        );
        assert!(error.to_string().contains("got 0"));
    }

    #[test]
    fn closure_rejects_duplicate_selected_suite_names() {
        let mut selected = full_inventory();
        selected[CLOSURE_SUITE_COUNT - 1].name = selected[0].name.clone();
        let reports = matching_reports(&selected);
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("2127 unique selected suite names")
        );
    }

    #[test]
    fn closure_rejects_duplicate_report_names() {
        let selected = full_inventory();
        let mut reports = matching_reports(&selected);
        reports.push(report_named("suite-0", Verdict::Match));
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(error.to_string().contains("duplicate report names"));
    }

    #[test]
    fn closure_rejects_unexpected_report_names() {
        let selected = full_inventory();
        let mut reports = matching_reports(&selected);
        reports.push(report_named("unexpected", Verdict::Match));
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(error.to_string().contains("unexpected: unexpected"));
    }

    #[test]
    fn closure_rejects_non_match_reports() {
        let selected = full_inventory();
        let mut reports = matching_reports(&selected);
        reports[0].verdict = Verdict::Incomplete;
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(error.to_string().contains("suite-0 (INCOMPLETE)"));
    }

    #[test]
    fn closure_report_inventory_names_missing_selected_suite() {
        let selected = full_inventory();
        let reports: Vec<SuiteReport> = selected
            .iter()
            .skip(1)
            .map(|suite| report_named(&suite.name, Verdict::Match))
            .collect();
        let error = validate_closure_reports(&selected, &reports).unwrap_err();
        assert!(error.to_string().contains("missing: suite-0"));
    }
}
