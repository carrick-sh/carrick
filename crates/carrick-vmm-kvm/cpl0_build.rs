//! Build the embedded production CPL0 image and its test-support siblings.
//!
//! The one recipe, shared by `build.rs` here and carrick-vmm-soft's
//! `build.rs` (both `#[path]`-include it beside `cpl0_inputs.rs`). The two
//! consumers differ only in which images they publish; the cargo invocations,
//! their order, the env they strip and the files copied out are the same.

use std::path::PathBuf;
use std::process::Command;

use super::cpl0_inputs;

/// What one build script needs from the shared recipe.
pub struct Cpl0Consumer {
    /// The consuming package, for the layout error.
    pub package: &'static str,
    /// This file's directory relative to the consumer's manifest, so the
    /// shared sources are watched from either package.
    pub shared_dir: &'static str,
    /// Publish `CARRICK_X86_CPL0_TEST_IMAGE` (the production binary built
    /// with `test-support`).
    pub test_image: bool,
}

/// The cargo environment the recipe runs in and the host authority it
/// uses. Each build script reads and passes its own: an authority site in
/// this file would have two compilation-target owners.
pub struct Cpl0BuildEnv {
    pub manifest_dir: PathBuf,
    pub out: PathBuf,
    pub cargo: std::ffi::OsString,
    /// `std::fs::copy`, for copying each image out into `out`.
    pub copy: fn(PathBuf, PathBuf) -> std::io::Result<u64>,
}

pub fn build_images(
    consumer: &Cpl0Consumer,
    env: Cpl0BuildEnv,
) -> Result<(), Box<dyn std::error::Error>> {
    let Cpl0BuildEnv {
        manifest_dir,
        out,
        cargo,
        copy,
    } = env;
    // Derived, not listed: the image's path-package closure, the workspace
    // build configuration (including `.cargo/config.toml`'s code-model=kernel),
    // and every file its sources `#[path]`/`include*!` from outside that closure
    // (carrick-x86's cpl0_*.rs). `tests/cpl0_image_inputs.rs` proves coverage.
    let workspace = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| {
            format!(
                "{} is not two levels below the workspace root",
                consumer.package
            )
        })?
        .to_path_buf();
    let inputs = cpl0_inputs::derive(&workspace)?;
    for input in inputs.watch_list(&workspace) {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!(
        "cargo:rerun-if-changed={}cpl0_inputs.rs",
        consumer.shared_dir
    );
    println!(
        "cargo:rerun-if-changed={}cpl0_build.rs",
        consumer.shared_dir
    );
    let target_dir = out.join("cpl0-target");
    let status = Command::new(&cargo)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0",
            "--target",
            "x86_64-unknown-none",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()?;
    if !status.success() {
        return Err(format!("production CPL0 image build failed: {status}").into());
    }
    let built = target_dir.join("x86_64-unknown-none/release");
    let publish_image = |bin: &str, output: &str, variable: &str| {
        let image = out.join(output);
        copy(built.join(bin), image.clone())?;
        println!("cargo:rustc-env={variable}={}", image.display());
        Ok::<(), std::io::Error>(())
    };
    publish_image(
        "carrick-x86-cpl0",
        "carrick-x86-cpl0",
        "CARRICK_X86_CPL0_IMAGE",
    )?;

    // Injection witnesses use a second production entry artifact. Build it
    // only after preserving the feature-free production image above.
    let status = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--release",
            "-p",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0-fixture",
            "--features",
            "test-support",
            "--target",
            "x86_64-unknown-none",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()?;
    if !status.success() {
        return Err(format!("test CPL0 image build failed: {status}").into());
    }
    for (bin, output, variable) in [
        (
            "carrick-x86-cpl0",
            "carrick-x86-cpl0-test",
            "CARRICK_X86_CPL0_TEST_IMAGE",
        ),
        (
            "carrick-x86-cpl0-fixture",
            "carrick-x86-cpl0-fixture",
            "CARRICK_X86_CPL0_FIXTURE_IMAGE",
        ),
    ]
    .into_iter()
    .filter(|(_, _, variable)| consumer.test_image || *variable != "CARRICK_X86_CPL0_TEST_IMAGE")
    {
        publish_image(bin, output, variable)?;
    }
    Ok(())
}
