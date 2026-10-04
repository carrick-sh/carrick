#![allow(clippy::unwrap_used, clippy::expect_used)]
use clap::Parser;

#[test]
fn fixtures_command_exposes_build_restore_and_verify() {
    for args in [
        vec!["carrick-xtask", "fixtures", "build", "--sha", "SHA"],
        vec![
            "carrick-xtask",
            "fixtures",
            "restore",
            "--manifest",
            "manifest.json",
        ],
        vec!["carrick-xtask", "fixtures", "verify"],
    ] {
        carrick_xtask::cli::Cli::try_parse_from(args).unwrap();
    }
}

#[test]
fn fixtures_publisher_is_available_to_native_linux_actions() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "fixtures",
        "publish",
        "--sha",
        "SHA",
    ])
    .unwrap();
}

#[test]
fn remote_signed_acceptance_accepts_an_exact_sha_manifest() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "remote-accept",
        "--phase",
        "signed",
        "--fixture-manifest",
        "manifest.json",
    ])
    .unwrap();
}
