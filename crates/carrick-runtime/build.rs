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
}
