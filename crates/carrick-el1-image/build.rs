use std::path::{Path, PathBuf};
use std::process::Command;

fn get_sysroot() -> String {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("failed to run rustc --print sysroot");
    String::from_utf8(output.stdout)
        .expect("sysroot is not valid utf-8")
        .trim()
        .to_string()
}

fn find_rust_objcopy(sysroot: &str, host: &str) -> PathBuf {
    let sysroot_path = Path::new(sysroot)
        .join("lib/rustlib")
        .join(host)
        .join("bin/rust-objcopy");
    if sysroot_path.exists() {
        return sysroot_path;
    }

    // Try bare rust-objcopy on PATH
    if Command::new("rust-objcopy")
        .arg("--version")
        .output()
        .is_ok()
    {
        return PathBuf::from("rust-objcopy");
    }

    // Try llvm-objcopy on PATH
    if Command::new("llvm-objcopy")
        .arg("--version")
        .output()
        .is_ok()
    {
        return PathBuf::from("llvm-objcopy");
    }

    panic!(
        "rust-objcopy not found in sysroot ({sysroot_path:?}) or on PATH.\n\
         Install the llvm-tools component with:\n    rustup component add llvm-tools-preview"
    );
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let host = std::env::var("HOST").expect("HOST not set");
    let sysroot = get_sysroot();

    // Verify that the aarch64-unknown-none target is installed
    let target_dir = Path::new(&sysroot).join("lib/rustlib/aarch64-unknown-none");
    if !target_dir.exists() {
        panic!(
            "\n\n======================================================================\n\
             ERROR: Target 'aarch64-unknown-none' is required to build carrick-el1-image.\n\
             Install it with:\n\
                 rustup target add aarch64-unknown-none\n\
             ======================================================================\n\n"
        );
    }

    let rust_objcopy = find_rust_objcopy(&sysroot, &host);

    let el1_target_dir = Path::new(&out_dir).join("el1-target");

    // Build carrick-el1 for aarch64-unknown-none --release
    let mut build_cmd = Command::new(&cargo);
    build_cmd
        .arg("build")
        .arg("-p")
        .arg("carrick-el1")
        .arg("--target")
        .arg("aarch64-unknown-none")
        .arg("--release")
        .arg("--target-dir")
        .arg(&el1_target_dir);

    // Remove cargo env vars that might interfere with nested cargo invocation
    build_cmd.env_remove("CARGO_MAKEFLAGS");
    build_cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");

    let status = build_cmd
        .status()
        .expect("failed to invoke cargo build for carrick-el1");
    if !status.success() {
        panic!("failed to build carrick-el1 for aarch64-unknown-none (exit code: {status})");
    }

    let elf_path = el1_target_dir.join("aarch64-unknown-none/release/carrick-el1");
    let bin_path = Path::new(&out_dir).join("carrick-el1.bin");

    // Convert ELF executable to raw binary using rust-objcopy -O binary
    let mut objcopy_cmd = Command::new(&rust_objcopy);
    objcopy_cmd
        .arg("-O")
        .arg("binary")
        .arg(&elf_path)
        .arg(&bin_path);

    let objcopy_status = objcopy_cmd.status().expect("failed to run rust-objcopy");
    if !objcopy_status.success() {
        panic!("rust-objcopy failed (exit code: {objcopy_status})");
    }

    println!("cargo:rerun-if-changed=../carrick-el1/src");
    println!("cargo:rerun-if-changed=../carrick-el1/link.ld");
    println!("cargo:rerun-if-changed=../carrick-el1/build.rs");
    println!("cargo:rerun-if-changed=../carrick-el1/Cargo.toml");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/src");
    println!("cargo:rerun-if-changed=../carrick-el1-abi/Cargo.toml");
}
