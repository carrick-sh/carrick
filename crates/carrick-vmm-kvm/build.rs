// `includes`/`unresolved` are read by tests/cpl0_image_inputs.rs, not here.
#[allow(dead_code)]
#[path = "cpl0_inputs.rs"]
mod cpl0_inputs;

#[path = "cpl0_build.rs"]
mod cpl0_build;

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    cpl0_build::build_images(
        &cpl0_build::Cpl0Consumer {
            package: "carrick-vmm-kvm",
            shared_dir: "",
            test_image: true,
        },
        cpl0_build::Cpl0BuildEnv {
            manifest_dir,
            out,
            cargo,
            copy: std::fs::copy::<PathBuf, PathBuf>,
        },
    )
}
