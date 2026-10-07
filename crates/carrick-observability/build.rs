//! Selects the `probes::real` (USDT) or `probes::stub` arm for this build.
//!
//! `carrick_usdt_probes` is emitted when BOTH hold:
//!
//! 1. the target is one where carrick fires real probes at all: `macos` (any
//!    arch), or `x86_64` `linux`/`freebsd`. This is the same set the manifest
//!    scopes the `usdt` dependency to; keep the two in step.
//! 2. the BUILD HOST would make `usdt` generate code for that same target.
//!
//! Condition 2 exists because `#[usdt::provider]` is a proc-macro, and a
//! proc-macro and its dependencies (`usdt-attr-macro` -> `usdt-impl`) are
//! compiled for the HOST, not the target. `usdt-impl` 0.6.0 (the newest
//! release) then decides every target-dependent detail of the expansion from
//! its OWN compilation:
//!
//! - the probe backend comes from its build.rs reading `CARGO_CFG_TARGET_OS`,
//!   which for a host-side dependency is the host OS (macOS -> the linker
//!   backend, Linux -> SystemTap SDT, FreeBSD -> the illumos-style backend);
//! - the argument registers come from `#[cfg(target_arch)]` /
//!   `cfg!(target_arch)` inside `usdt-impl`, again the host arch.
//!
//! The expansion therefore carries host register names into the target crate.
//! Checking `x86_64-unknown-linux-gnu` from an aarch64 Mac produced ~900
//! "invalid register `x0`" errors from the macOS/aarch64 linker-backend asm.
//! A proc-macro cannot see the target on stable Rust, so this cannot be fixed
//! by emitting `#[cfg(target_arch)]` into the expansion without forking
//! `usdt-impl`; the build script, which DOES see both host and target, picks
//! the arm instead.
//!
//! Effect: native builds (host == target backend and arch, which includes every
//! signed macOS release and the Linux/FreeBSD x86_64 lanes, gnu or musl) keep
//! exactly the real provider they had. A cross build whose host would emit the
//! wrong asm gets the stub (no probes) instead of failing to compile; before
//! this it could not be built at all, so no working configuration loses probes.
fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(carrick_usdt_probes)");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();

    let target_fires_probes = target_os == "macos"
        || (matches!(target_os.as_str(), "linux" | "freebsd") && target_arch == "x86_64");
    if !target_fires_probes {
        return;
    }

    let Some(host_arch) = host_arch(&host) else {
        return;
    };
    let Some(host_backend) = host_backend(&host) else {
        return;
    };
    if host_arch == target_arch && Some(host_backend) == usdt_backend(&target_os) {
        println!("cargo::rustc-cfg=carrick_usdt_probes");
    }
}

/// The `usdt-impl` backend its build.rs selects for an OS (`target_os` spelling).
fn usdt_backend(os: &str) -> Option<&'static str> {
    match os {
        "macos" => Some("linker"),
        "illumos" | "solaris" | "freebsd" => Some("standard"),
        "linux" => Some("stapsdt"),
        _ => None,
    }
}

/// The `target_arch` spelling of the host triple's architecture.
fn host_arch(host: &str) -> Option<&str> {
    match host.split('-').next()? {
        "arm64" => Some("aarch64"),
        "" => None,
        arch => Some(arch),
    }
}

/// The `usdt-impl` backend a proc-macro built for this host triple will use.
fn host_backend(host: &str) -> Option<&'static str> {
    let parts: Vec<&str> = host.split('-').collect();
    let os = if parts.iter().any(|p| p.starts_with("darwin")) {
        "macos"
    } else if parts.contains(&"linux") {
        "linux"
    } else if parts.iter().any(|p| p.starts_with("freebsd")) {
        "freebsd"
    } else if parts.contains(&"illumos") {
        "illumos"
    } else if parts.iter().any(|p| p.starts_with("solaris")) {
        "solaris"
    } else {
        return None;
    };
    usdt_backend(os)
}
