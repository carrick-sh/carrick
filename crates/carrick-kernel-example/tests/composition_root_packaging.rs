//! Tests guest image packaging from detached composition roots.
//!
//! Verifies that `carrick_xtask::guest_image::package_guest_image` successfully
//! builds and packages images for both supported target architectures (x86_64 and aarch64)
//! from an arbitrary external / detached directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_xtask::guest_image::{
    BuildProfile, GuestImageBuildConfig, GuestImageError, GuestTargetArch, package_guest_image,
};
use std::fs;
use std::path::{Path, PathBuf};

fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/example-composition-root")
        .canonicalize()
        .expect("fixture directory exists")
}

#[test]
fn test_detached_composition_root_packages_x86_64() {
    let fixture = fixture_dir();
    let temp = tempfile::tempdir().expect("tempdir");
    let detached = temp.path().join("detached-pkg-x86_64");
    copy_dir_all(&fixture, &detached).expect("copy fixture");

    let out_dir = temp.path().join("out-x86_64");
    let mut config = GuestImageBuildConfig::new(&detached, GuestTargetArch::X86_64, &out_dir);
    config.profile = BuildProfile::Debug;

    let artifact = package_guest_image(&config).expect("package x86_64 image");
    assert_eq!(artifact.target_arch, GuestTargetArch::X86_64);
    assert!(artifact.binary_path.exists(), "binary exists on disk");
    assert!(artifact.elf_path.exists(), "elf exists on disk");

    let bytes = fs::read(&artifact.binary_path).expect("read binary payload");
    assert!(!bytes.is_empty(), "packaged payload is not empty");
}

#[test]
fn test_detached_composition_root_packages_aarch64() {
    let fixture = fixture_dir();
    let temp = tempfile::tempdir().expect("tempdir");
    let detached = temp.path().join("detached-pkg-aarch64");
    copy_dir_all(&fixture, &detached).expect("copy fixture");

    let out_dir = temp.path().join("out-aarch64");
    let mut config = GuestImageBuildConfig::new(&detached, GuestTargetArch::Aarch64, &out_dir);
    config.profile = BuildProfile::Debug;

    let artifact = package_guest_image(&config).expect("package aarch64 image");
    assert_eq!(artifact.target_arch, GuestTargetArch::Aarch64);
    assert!(artifact.binary_path.exists(), "binary exists on disk");
    assert!(artifact.elf_path.exists(), "elf exists on disk");

    let bytes = fs::read(&artifact.binary_path).expect("read binary payload");
    assert!(!bytes.is_empty(), "packaged payload is not empty");
}

#[test]
fn test_packaging_missing_manifest_fails_cleanly() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing_path = temp.path().join("does-not-exist");
    let out_dir = temp.path().join("out");

    let config = GuestImageBuildConfig::new(&missing_path, GuestTargetArch::X86_64, &out_dir);
    let result = package_guest_image(&config);
    match result {
        Err(GuestImageError::ManifestNotFound(path)) => {
            assert!(path.ends_with("Cargo.toml") || path == missing_path);
        }
        other => panic!("expected ManifestNotFound, got {other:?}"),
    }
}
