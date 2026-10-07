use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use carrick_xtask::shared_kernel_scorecard::{
    CrateScorecard, ScorecardArgs, ScorecardOutput, count_cfg_target_arch_sites, count_code_lines,
    measure_checkout, parse_dep_info, read_defects_ledger, run,
};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = manifest_dir().join("../..").canonicalize()?;
    Ok(path)
}

#[test]
fn test_dep_info_parser() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = manifest_dir().join("tests/fixtures/scorecard/sample.d");
    let content = std::fs::read_to_string(&fixture_path)?;
    let prereqs = parse_dep_info(&content);

    let prereq_set: BTreeSet<PathBuf> = prereqs.into_iter().collect();

    assert!(
        prereq_set.contains(Path::new("crates/carrick-core/src/lib.rs")),
        "missing lib.rs in parsed dep-info"
    );
    assert!(
        prereq_set.contains(Path::new("crates/carrick-core/src/entry.rs")),
        "missing entry.rs in parsed dep-info"
    );
    assert!(
        prereq_set.contains(Path::new("crates/carrick-core/src/mm/mod.rs")),
        "missing mm/mod.rs in parsed dep-info"
    );
    assert!(
        prereq_set.contains(Path::new("crates/carrick-core/src/path with space/foo.rs")),
        "missing escaped-space path in parsed dep-info"
    );
    assert_eq!(
        prereq_set.len(),
        4,
        "unexpected number of distinct prerequisites"
    );
    Ok(())
}

#[test]
fn test_line_counter() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = manifest_dir().join("tests/fixtures/scorecard/sample.rs");
    let content = std::fs::read_to_string(&fixture_path)?;
    let code_lines = count_code_lines(&content);

    // sample.rs has exactly 17 non-blank, non-comment lines
    assert_eq!(code_lines, 17, "expected 17 code lines in sample.rs");

    assert_eq!(count_code_lines(""), 0);
    assert_eq!(count_code_lines("   \n\t\n  \n"), 0);
    assert_eq!(count_code_lines("// comment\n  // indented comment\n"), 0);
    assert_eq!(count_code_lines("/* single line block */"), 0);
    assert_eq!(
        count_code_lines("/*\n * multi\n * line /* nested */\n */"),
        0
    );
    assert_eq!(count_code_lines("let a = 1; // comment"), 1);
    assert_eq!(count_code_lines("let a = /* block */ 1;"), 1);
    assert_eq!(
        count_code_lines("let s = \"// not a comment /* not block */\";"),
        1
    );
    Ok(())
}

#[test]
fn test_cfg_target_arch_scanner() -> Result<(), Box<dyn std::error::Error>> {
    let fixture_path = manifest_dir().join("tests/fixtures/scorecard/sample.rs");
    let content = std::fs::read_to_string(&fixture_path)?;
    let sites = count_cfg_target_arch_sites(&content);

    assert_eq!(
        sites, 4,
        "expected 4 cfg(target_arch ...) sites in sample.rs"
    );

    assert_eq!(
        count_cfg_target_arch_sites("// #[cfg(target_arch = \"aarch64\")]"),
        0
    );
    assert_eq!(
        count_cfg_target_arch_sites("/* #[cfg(target_arch = \"x86_64\")] */"),
        0
    );
    assert_eq!(
        count_cfg_target_arch_sites("let s = \"target_arch = aarch64\";"),
        0
    );
    Ok(())
}

#[test]
fn test_crate_scorecard_metrics() {
    let scorecard = CrateScorecard {
        crate_name: "test-crate".into(),
        shared_lines: 50,
        el1_only_lines: 30,
        cpl0_only_lines: 20,
    };
    assert_eq!(scorecard.total_lines(), 100);
    assert!((scorecard.shared_percent() - 50.0).abs() < 1e-6);

    let empty = CrateScorecard::default();
    assert_eq!(empty.total_lines(), 0);
    assert_eq!(empty.shared_percent(), 0.0);
}

#[test]
fn test_defects_ledger_reader() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let defects = read_defects_ledger(&root)?;
    assert_eq!(defects.total, 0);
    assert_eq!(defects.x86_kvm, 0);
    assert_eq!(defects.arm_hvf, 0);
    Ok(())
}

#[test]
fn test_shared_kernel_scorecard_execution() -> Result<(), Box<dyn std::error::Error>> {
    let root = workspace_root()?;

    // 1. Direct measurement of current checkout
    let report = measure_checkout(&root)?;

    assert!(
        report.shared_lines > 0,
        "expected positive shared line count, got {}",
        report.shared_lines
    );
    assert!(
        report.shared_percent > 0.0 && report.shared_percent <= 100.0,
        "shared percentage {} must be within (0, 100]",
        report.shared_percent
    );
    assert!(
        report.shared_files_count > 0,
        "expected shared source files to be found"
    );
    assert!(
        !report.crates.is_empty(),
        "expected crate breakdown to be populated"
    );

    // 2. Test CLI execution with --json output
    let mut json_buf = Vec::new();
    run(
        &root,
        ScorecardArgs {
            json: true,
            base: None,
        },
        &mut json_buf,
    )?;

    let output_str = String::from_utf8(json_buf)?;
    let output: ScorecardOutput = serde_json::from_str(&output_str)?;

    assert_eq!(output.current.shared_lines, report.shared_lines);
    assert_eq!(output.current.total_lines, report.total_lines);
    assert!(output.base.is_none());

    // 3. Test CLI execution with text table output
    let mut text_buf = Vec::new();
    run(
        &root,
        ScorecardArgs {
            json: false,
            base: None,
        },
        &mut text_buf,
    )?;

    let text_str = String::from_utf8(text_buf)?;
    assert!(
        text_str.contains("Shared Guest Kernel Scorecard"),
        "expected header in text output"
    );
    assert!(
        text_str.contains("Per-Crate Breakdown"),
        "expected breakdown in text output"
    );
    assert!(
        text_str.contains("x86-found shared defects"),
        "expected defects line in text output"
    );
    Ok(())
}
