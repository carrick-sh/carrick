use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }

    for source in [
        "../../Cargo.lock",
        "../../rust-toolchain.toml",
        "../carrick-x86-cpl0",
        "../carrick-el1",
        "../carrick-personality-linux",
        "../carrick-core",
        "../carrick-core-abi",
        "../carrick-sched-core",
        "../carrick-mmu-core",
        "../carrick-guest-arch",
        "../carrick-el1-abi",
        "../carrick-pipe-core",
        "../carrick-fd-core",
        "../carrick-signal-core",
        "../carrick-inotify-core",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let target_dir = out.join("cpl0-target");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
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
    std::fs::copy(
        target_dir.join("x86_64-unknown-none/release/carrick-x86-cpl0"),
        out.join("carrick-x86-cpl0"),
    )?;
    Ok(())
}
