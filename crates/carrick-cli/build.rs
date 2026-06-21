//! carrick-cli build script.
//!
//! Asserts the `platform-*` feature matches the build's `target_os`, so e.g.
//! `--features platform-linux` on a macOS target (or vice-versa) fails with a
//! clear message instead of a deep duplicate-symbol / missing-ioctl error far
//! downstream. The two selection axes are deliberately distinct — the
//! `platform-*` feature selects WHICH VMM/host backend is linked, while
//! `target_os` selects the libc ABI shape — but a valid build requires them to
//! agree, and nothing else enforces that. (The exactly-one-platform invariant is
//! enforced separately by `compile_error!` in `main.rs`.)

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // `CARGO_CFG_TARGET_OS` is the OS being compiled FOR (not the host).
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let feat = |name: &str| std::env::var_os(name).is_some();

    let (feature, expected_os) = if feat("CARGO_FEATURE_PLATFORM_MACOS") {
        ("platform-macos", "macos")
    } else if feat("CARGO_FEATURE_PLATFORM_LINUX") {
        ("platform-linux", "linux")
    } else if feat("CARGO_FEATURE_PLATFORM_FREEBSD") {
        ("platform-freebsd", "freebsd")
    } else if feat("CARGO_FEATURE_PLATFORM_NETBSD") {
        ("platform-netbsd", "netbsd")
    } else {
        // No platform selected — `compile_error!` in main.rs already reports it.
        return;
    };

    if target_os != expected_os {
        panic!(
            "carrick-cli: feature `{feature}` requires target_os=`{expected_os}`, \
             but this build targets `{target_os}`. The platform-* feature selects \
             the VMM/host backend; target_os selects the libc ABI — build the \
             matching platform for your target."
        );
    }
}
