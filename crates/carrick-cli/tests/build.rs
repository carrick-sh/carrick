// Test-only crate: the no-panic gate targets production code, so `unwrap` in
// these integration tests is fine (matches tests/serve.rs).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;

/// `carrick build --help` lists the docker-build-shaped flags the wrapper
/// accepts. Mirrors `serve_help_lists_docker_api_flag` — a cheap proof the
/// subcommand is wired into the clap model without running an actual build
/// (which needs codesign + network + kaniko; validated end-to-end elsewhere).
#[test]
fn build_help_lists_docker_build_flags() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--tag"))
        .stdout(predicates::str::contains("--build-arg"))
        .stdout(predicates::str::contains("--no-cache"));
}
