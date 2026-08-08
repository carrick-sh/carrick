//! Builds the Darwin/aarch64 native trap+kick C shim
//! (`csrc/native_darwin.c`) — the same `cc` invocation that used to live in
//! `carrick-runtime/build.rs` before the C file moved here (M0.6 of the
//! seams design). Only compiled for macOS on aarch64: the file's real
//! content is `#if defined(__aarch64__)`-gated (a stub fallback covers the
//! `#else`), and Darwin's MAP_JIT/x18-ABI plumbing has no other target.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os == "macos" && arch == "aarch64" {
        use std::path::PathBuf;
        use std::process::Command;

        println!("cargo:rerun-if-changed=csrc/native_darwin.c");
        let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Cargo did not provide OUT_DIR",
            )
        })?);
        let sdk = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .map_err(|error| std::io::Error::other(format!("locate macOS SDK: {error}")))?;
        if !sdk.status.success() {
            return Err(std::io::Error::other(format!(
                "xcrun --show-sdk-path failed with {}",
                sdk.status
            ))
            .into());
        }
        let sdk = String::from_utf8(sdk.stdout)?.trim().to_owned();
        let defs = PathBuf::from(&sdk).join("usr/include/mach/mach_exc.defs");
        let server = out_dir.join("carrick_mach_exc_server.c");
        let server_header = out_dir.join("carrick_mach_exc_server.h");
        let user = out_dir.join("carrick_mach_exc_user.c");
        let user_header = out_dir.join("carrick_mach_exc_user.h");
        let mig = Command::new("xcrun")
            .args(["--sdk", "macosx", "mig", "-arch", "arm64", "-isysroot"])
            .arg(&sdk)
            .arg("-server")
            .arg(&server)
            .arg("-sheader")
            .arg(&server_header)
            .arg("-user")
            .arg(&user)
            .arg("-header")
            .arg(&user_header)
            .arg(&defs)
            .status()
            .map_err(|error| std::io::Error::other(format!("run mig: {error}")))?;
        if !mig.success() {
            return Err(std::io::Error::other(format!(
                "mig failed for {} with {mig}",
                defs.display()
            ))
            .into());
        }

        cc::Build::new()
            .file("csrc/native_darwin.c")
            .file(server)
            .include(out_dir)
            // Mach exception replies receive kernel-signed opaque thread
            // pointers on PAC-capable XNU. We need the intrinsics (without
            // changing the C ABI to arm64e) to sign a replacement PC in the
            // exact user representation XNU accepts.
            .flag_if_supported("-fptrauth-intrinsics")
            .warnings(true)
            .compile("carrick_native_darwin");
    }
    Ok(())
}
