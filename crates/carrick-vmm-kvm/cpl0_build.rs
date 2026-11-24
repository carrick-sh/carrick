//! Build the embedded production CPL0 image and its test-support siblings.
//!
//! The one recipe, shared by `build.rs` here and carrick-vmm-soft's
//! `build.rs` (both `#[path]`-include it beside `cpl0_inputs.rs`). The two
//! consumers differ only in which images they publish; the cargo invocations,
//! their order, the env they strip and the files copied out are the same.

use std::path::PathBuf;
use std::process::Command;

use super::cpl0_budget::ImageBudget;
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
    /// `std::fs::read`, for reading each published image's budget.
    pub read: fn(PathBuf) -> std::io::Result<Vec<u8>>,
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
        read,
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
    println!(
        "cargo:rerun-if-changed={}cpl0_budget.rs",
        consumer.shared_dir
    );
    let target_dir = out.join("cpl0-target");
    let status = nested_image_build(&cargo, &target_dir)
        .args(["--bin", "carrick-x86-cpl0"])
        .status()?;
    if !status.success() {
        return Err(format!("production CPL0 image build failed: {status}").into());
    }
    let built = target_dir
        .join("x86_64-unknown-none")
        .join(RING_IMAGE_PROFILE);
    let publish_image = |bin: &str, output: &str, variable: &str| {
        let image = out.join(output);
        copy(built.join(bin), image.clone())?;
        report_budget(output, &read(image.clone())?)?;
        println!("cargo:rustc-env={variable}={}", image.display());
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    publish_image(
        "carrick-x86-cpl0",
        "carrick-x86-cpl0",
        "CARRICK_X86_CPL0_IMAGE",
    )?;

    // Injection witnesses use a second production entry artifact. Build it
    // only after preserving the feature-free production image above.
    let status = nested_image_build(&cargo, &target_dir)
        .args([
            "--bin",
            "carrick-x86-cpl0",
            "--bin",
            "carrick-x86-cpl0-fixture",
            "--features",
            "test-support",
        ])
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

/// The workspace profile both ring images build under (`Cargo.toml`):
/// release with one codegen unit per crate, which keeps generic instances
/// from being copied into every partition (#691, #3005).
pub const RING_IMAGE_PROFILE: &str = "el1-image";

/// The nested `cargo build` of the CPL0 image, identical under every outer
/// cargo command. `cargo clippy` hands build scripts its
/// `RUSTC_WORKSPACE_WRAPPER` (clippy-driver), which compiles with MIR
/// optimizations off: under clippy the image grew by about 50 KB and
/// crossed its 2 MiB supervisor extent while `cargo build` fit (#3005).
/// The image is an artifact, so it is built by rustc alone; its sources
/// are linted by `just clippy-linux`'s own `x86_64-unknown-none` pass.
fn nested_image_build(cargo: &std::ffi::OsStr, target_dir: &std::path::Path) -> Command {
    let mut command = Command::new(cargo);
    command
        .args([
            "build",
            "--locked",
            "--profile",
            RING_IMAGE_PROFILE,
            "-p",
            "carrick-x86-cpl0",
            "--target",
            "x86_64-unknown-none",
            "--target-dir",
        ])
        .arg(target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER");
    command
}

/// Print `image`'s loaded bytes against its supervisor extent, as the EL1
/// image does (`EL1 image budget: ...`), so growth is visible before the
/// link assert fails. The link assert stays the enforcement.
fn report_budget(image: &str, elf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let budget = ImageBudget::of(elf).ok_or_else(|| format!("{image}: not a CPL0 ELF64 image"))?;
    println!(
        "cargo:warning=CPL0 image budget ({image}): {} bytes loaded / {} bytes; {} bytes headroom",
        budget.loaded,
        budget.extent,
        budget.extent.saturating_sub(budget.loaded),
    );
    Ok(())
}
