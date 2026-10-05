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

#[test]
fn remote_signed_acceptance_accepts_a_remote_bundle() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "remote-accept",
        "--phase",
        "signed",
        "--remote-bundle",
        "/Volumes/carrick-build/fixtures/published/sha/identity.tar.gz",
    ])
    .unwrap();
}

#[test]
fn remote_signed_acceptance_rejects_conflicting_manifest_and_remote_bundle() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "remote-accept",
        "--phase",
        "signed",
        "--fixture-manifest",
        "manifest.json",
        "--remote-bundle",
        "/Volumes/carrick-build/fixtures/published/sha/identity.tar.gz",
    ])
    .unwrap_err();
}

#[test]
fn fixtures_verify_accepts_bundle() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "fixtures",
        "verify",
        "--bundle",
        "bundle.tar.gz",
    ])
    .unwrap();
}

#[test]
fn fixtures_verify_rejects_conflicting_manifest_and_bundle() {
    carrick_xtask::cli::Cli::try_parse_from([
        "carrick-xtask",
        "fixtures",
        "verify",
        "--manifest",
        "manifest.json",
        "--bundle",
        "bundle.tar.gz",
    ])
    .unwrap_err();
}

#[test]
fn remote_accept_rejects_bundle_arguments_on_attach() {
    for flag in ["--remote-bundle", "--fixture-manifest"] {
        assert!(
            carrick_xtask::cli::Cli::try_parse_from([
                "carrick-xtask",
                "remote-accept",
                "--attach",
                "0123456789ab-20261005-120000",
                flag,
                "/unverified/bundle",
            ])
            .is_err()
        );
    }
}
