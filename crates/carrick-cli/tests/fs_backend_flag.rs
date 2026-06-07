//! `--fs memory` is gated behind the default-off `fs-memory` Cargo feature.
//! On a stock build, `host` is the only accepted `--fs` value.
#![allow(clippy::unwrap_used, clippy::panic)]

// Both tests below are `#[cfg(not(feature = "fs-memory"))]`, so the import is
// only needed on a default (feature-off) build; gate it to match or a feature-on
// build warns (and CI denies warnings).
#[cfg(not(feature = "fs-memory"))]
use assert_cmd::Command;

/// `carrick run --help` lists the `--fs` possible values. Without the
/// `fs-memory` feature, `memory` must not appear among them. Uses `--help`
/// (no guest boot) so it is fast and deterministic in both the red and green
/// phases.
#[cfg(not(feature = "fs-memory"))]
#[test]
fn run_help_does_not_offer_fs_memory() {
    let out = Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("possible values: memory"),
        "--fs must not offer 'memory' when fs-memory is off; help was:\n{stdout}"
    );
}

/// On a default build, passing `--fs memory` is a clap usage error (exit 2),
/// rejected before any guest boot. Fast because clap fails at parse time.
#[cfg(not(feature = "fs-memory"))]
#[test]
fn run_with_fs_memory_is_a_usage_error() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--fs", "memory", "ubuntu:24.04", "/bin/true"])
        .assert()
        .failure()
        .code(2);
}

/// With the feature on, `--fs memory` is offered again (parity with pre-gate
/// behavior). This test only compiles/runs under `--features fs-memory`.
#[cfg(feature = "fs-memory")]
#[test]
fn run_help_offers_fs_memory_with_feature() {
    let out = assert_cmd::Command::cargo_bin("carrick")
        .unwrap()
        .args(["run", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Possible values:") && stdout.contains("memory"),
        "--fs should offer 'memory' when fs-memory is on; help was:\n{stdout}"
    );
}
