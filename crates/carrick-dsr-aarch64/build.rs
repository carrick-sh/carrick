// Assemble the AArch64 DSR gateway only for the lane that can link and run
// it (Darwin/AArch64). Everything else in this crate is pure Rust and
// compiles on every host; the extern symbols the gateway declares sit behind
// the matching `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]`
// boundary in src/gateway.rs, so no other target references the assembled
// object.
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os == "macos" && arch == "aarch64" {
        println!("cargo:rerun-if-changed=src/gateway_aarch64.S");
        cc::Build::new()
            .file("src/gateway_aarch64.S")
            .warnings(true)
            .compile("carrick_dsr_gateway_aarch64");
    }
}
