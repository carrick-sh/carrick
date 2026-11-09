use std::path::PathBuf;
use std::process::Command;

// `includes`/`unresolved` are read by tests/cpl0_image_inputs.rs, not here.
#[allow(dead_code)]
#[path = "cpl0_inputs.rs"]
mod cpl0_inputs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }

    // Derived, not listed: the image's path-package closure, the workspace
    // build configuration (including `.cargo/config.toml`'s code-model=kernel),
    // and every file its sources `#[path]`/`include*!` from outside that closure
    // (carrick-x86's cpl0_*.rs). `tests/cpl0_image_inputs.rs` proves coverage.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("carrick-vmm-kvm is not two levels below the workspace root")?
        .to_path_buf();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let inputs = cpl0_inputs::derive(&workspace)?;
    for input in inputs.watch_list(&workspace) {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-changed=cpl0_inputs.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
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
        std::fs::copy(built.join(bin), &image)?;
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
    ] {
        publish_image(bin, output, variable)?;
    }
    Ok(())
}
