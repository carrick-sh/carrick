//! Build the production CPL0 ring image (and its fixture sibling) that the
//! soft boot probe runs. Same artifact recipe as carrick-vmm-kvm's build; the
//! rebuild inputs come from its one shared derivation.
use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
#[path = "../carrick-vmm-kvm/cpl0_inputs.rs"]
mod cpl0_inputs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let workspace = manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("carrick-vmm-soft is not two levels below the workspace root")?
        .to_path_buf();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    for input in cpl0_inputs::derive(&workspace)?.watch_list(&workspace) {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-changed=../carrick-vmm-kvm/cpl0_inputs.rs");
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let target_dir = out.join("cpl0-target");
    let built = target_dir.join("x86_64-unknown-none/release");
    // The feature-free production image first, then the fixture image with
    // test-support; each is copied out before the next build replaces it.
    for (features, bins) in [
        (None, &[("carrick-x86-cpl0", "CARRICK_X86_CPL0_IMAGE")][..]),
        (
            Some("test-support"),
            &[("carrick-x86-cpl0-fixture", "CARRICK_X86_CPL0_FIXTURE_IMAGE")][..],
        ),
    ] {
        let mut command = Command::new(&cargo);
        command.args([
            "build",
            "--locked",
            "--release",
            "-p",
            cpl0_inputs::IMAGE_PACKAGE,
        ]);
        for (bin, _) in bins {
            command.args(["--bin", bin]);
        }
        if let Some(features) = features {
            command.args(["--features", features]);
        }
        let status = command
            .args(["--target", "x86_64-unknown-none", "--target-dir"])
            .arg(&target_dir)
            .env_remove("CARGO_MAKEFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()?;
        if !status.success() {
            return Err(format!("CPL0 image build failed: {status}").into());
        }
        for (bin, variable) in bins {
            let image = out.join(bin);
            std::fs::copy(built.join(bin), &image)?;
            println!("cargo:rustc-env={variable}={}", image.display());
        }
    }
    Ok(())
}
