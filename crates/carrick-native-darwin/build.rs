//! Builds the Darwin/aarch64 native trap+kick C shim
//! (`csrc/native_darwin.c`) — the same `cc` invocation that used to live in
//! `carrick-runtime/build.rs` before the C file moved here (M0.6 of the
//! seams design). Only compiled for macOS on aarch64: the file's real
//! content is `#if defined(__aarch64__)`-gated (a stub fallback covers the
//! `#else`), and Darwin's MAP_JIT/x18-ABI plumbing has no other target.
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if os == "macos" && arch == "aarch64" {
        println!("cargo:rerun-if-changed=csrc/native_darwin.c");
        cc::Build::new()
            .file("csrc/native_darwin.c")
            .warnings(true)
            .compile("carrick_native_darwin");
    }
}
