//! `--fs memory` is gated behind the default-off `fs-memory` Cargo feature.
//! On a stock build, `host` is the only accepted `--fs` value.
#![allow(clippy::unwrap_used, clippy::panic)]

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
