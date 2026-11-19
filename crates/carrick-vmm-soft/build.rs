//! Build the production CPL0 ring image (and its fixture sibling) that the
//! soft boot probe runs, through carrick-vmm-kvm's one shared recipe.

#[allow(dead_code)]
#[path = "../carrick-vmm-kvm/cpl0_inputs.rs"]
mod cpl0_inputs;

#[path = "../carrick-vmm-kvm/cpl0_build.rs"]
mod cpl0_build;

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }
    let profile = std::env::var("PROFILE")?;
    let opt_level = std::env::var("OPT_LEVEL")?;
    println!("cargo:rustc-env=SOFT_BUILD_PROFILE_DIR={profile}");
    println!("cargo:rustc-env=SOFT_BUILD_OPT_LEVEL={opt_level}");
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    cpl0_build::build_images(
        &cpl0_build::Cpl0Consumer {
            package: "carrick-vmm-soft",
            shared_dir: "../carrick-vmm-kvm/",
            test_image: false,
        },
        cpl0_build::Cpl0BuildEnv {
            manifest_dir,
            out,
            cargo,
            copy: std::fs::copy::<PathBuf, PathBuf>,
        },
    )
}
