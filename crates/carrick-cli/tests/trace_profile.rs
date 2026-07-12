#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::str::contains;

fn cli() -> Command {
    Command::cargo_bin("carrick").unwrap()
}

#[test]
fn trace_profile_argument_relationships_are_enforced() {
    cli()
        .args([
            "trace",
            "--summary-jsonl",
            "/tmp/s.jsonl",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("profile"));
    cli()
        .args([
            "trace",
            "--profile",
            "dsr",
            "--summary-jsonl",
            "/tmp/s.jsonl",
            "--script",
            "x.d",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("cannot be used"));
}

#[test]
fn trace_profile_keeps_raw_and_summary_outputs_distinct() {
    cli()
        .args([
            "trace",
            "--profile",
            "dsr",
            "--trace-out",
            "/tmp/same.jsonl",
            "--summary-jsonl",
            "/tmp/same.jsonl",
            "--",
            "run-elf",
            "/tmp/p",
        ])
        .assert()
        .failure()
        .stderr(contains("different files"));
}

#[test]
fn bundled_profile_scripts_emit_one_versioned_completion() {
    for (name, profile) in [
        ("dsr-profile.d", "dsr"),
        ("dsr-indirect.d", "dsr-indirect"),
        ("dsr-fork.d", "dsr-fork"),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/dtrace")
            .join(name);
        let script = std::fs::read_to_string(path).unwrap();
        let completion = format!("DSRPROF1|complete|profile={profile}|bounded=%d");
        assert_eq!(script.matches(&completion).count(), 1);
        assert!(script.contains("proc:::create"));
        assert!(script.contains("progenyof($target)"));
    }
}
