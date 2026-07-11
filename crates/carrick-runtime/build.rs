//! OS-family `cfg` emitter for `carrick-runtime`.
//!
//! Residual ABI-shape branches that don't (yet) live behind `carrick-portable`
//! key on these instead of the banned macOS-negation feature gate (a
//! `not(platform-macos)` cfg used as a synonym for "Linux"):
//!   * `carrick_bsd`   — kqueue / `extattr` / `sockaddr_dl` family (Darwin + the BSDs + illumos)
//!   * `carrick_linux` — Linux ABI shapes (`sockaddr_ll`, …)
//!
//! Adding a host OS to a family is a one-line change to the match below. Prefer
//! pushing a divergence into `carrick-portable` (the sole libc seam); use these
//! cfgs only for in-place structural branches that can't be a function call.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(carrick_bsd)");
    println!("cargo::rustc-check-cfg=cfg(carrick_linux)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    match os.as_str() {
        "macos" | "ios" | "freebsd" | "netbsd" | "openbsd" | "dragonfly" | "solaris"
        | "illumos" => {
            println!("cargo::rustc-cfg=carrick_bsd");
        }
        "linux" | "android" => {
            println!("cargo::rustc-cfg=carrick_linux");
        }
        _ => {}
    }
    if os == "macos" && arch == "aarch64" {
        println!("cargo:rerun-if-changed=csrc/native_darwin.c");
        cc::Build::new()
            .file("csrc/native_darwin.c")
            .file("src/native_darwin/dsr/gateway_aarch64.S")
            .warnings(true)
            .compile("carrick_native_darwin");
    }
}
