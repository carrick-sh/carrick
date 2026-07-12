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

#[test]
fn broad_profile_pairs_phases_and_emits_exact_metric_shapes() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/dtrace/dsr-profile.d");
    let script = std::fs::read_to_string(path).unwrap();
    for probe in [
        "dsr-prepare-begin",
        "dsr-run-begin",
        "dsr-translate-begin",
        "dsr-resolve-begin",
        "syscall-entry",
        "dsr-cache-event",
        "dsr-cache-capacity",
        "dsr-cache-lifecycle",
    ] {
        assert!(script.contains(probe), "missing {probe}");
    }
    for record in [
        "DSRPROF1|count|phase=run",
        "DSRPROF1|total|phase=run",
        "DSRPROF1|minimum|phase=run",
        "DSRPROF1|maximum|phase=run",
        "DSRPROF1|sample|phase=run",
        "DSRPROF1|incomplete|phase=run",
        "DSRPROF1|high-water|metric=cache-bytes",
    ] {
        assert!(script.contains(record), "missing {record}");
    }
}

#[test]
fn indirect_profile_aggregates_sources_pairs_and_exact_total_once() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/dtrace/dsr-indirect.d");
    let script = std::fs::read_to_string(path).unwrap();
    assert!(script.contains("dsr-resolve-begin"));
    assert!(script.contains("dsr-resolve-end"));
    assert!(script.contains("arg1 == 2"));
    assert!(script.contains("@source[pid, arg2]"));
    assert!(script.contains("@pair[pid, arg2, arg3]"));
    assert_eq!(
        script
            .matches("DSRPROF1|count|phase=indirect-total")
            .count(),
        1
    );
    assert_eq!(
        script
            .matches("DSRPROF1|count|phase=indirect-outcome")
            .count(),
        1
    );
}
