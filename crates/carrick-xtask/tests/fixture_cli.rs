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
