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
    let inputs = cpl0_inputs::derive(&workspace, &cargo)?;
    for input in inputs.watch_list(&workspace) {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-changed=cpl0_inputs.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let target_dir = out.join("cpl0-target");
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
            "--target",
            "x86_64-unknown-none",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()?;
    if !status.success() {
        return Err(format!("CPL0 image build failed: {status}").into());
    }
    // Both images come from this one build of the current sources. Tests load
    // them through these exported paths, never from a shared `target/` that a
    // separate (possibly stale) `cargo build` populated. The fixture keeps its
    // file name: the carrier recognises the fixture image by it.
    for (bin, variable) in [
        ("carrick-x86-cpl0", "CARRICK_X86_CPL0_IMAGE"),
        ("carrick-x86-cpl0-fixture", "CARRICK_X86_CPL0_FIXTURE_IMAGE"),
    ] {
        let image = out.join(bin);
        std::fs::copy(
            target_dir.join("x86_64-unknown-none/release").join(bin),
            &image,
        )?;
        println!("cargo:rustc-env={variable}={}", image.display());
    }
    Ok(())
}
