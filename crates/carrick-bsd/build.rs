//! OS-family `cfg` emitter for `carrick-bsd`.
//!
//! `carrick-bsd` is the BSD-family host layer: the shared `KqueueMultiplexer`,
//! the `bsd_to_linux_errno` table, the `BsdFutex` shared-page futex, and the
//! one BSD `SIGNUM_XLATE` signal-number table (`signum`). Everything in this
//! crate is host-NEUTRAL across the BSD family; per-host kernel-call divergence
//! (`__ulock` vs `_umtx_op` vs `__futex`) is the only place an arm differs, and
//! that is pushed behind `carrick-host`.
//!
//! `carrick_bsd_family` is emitted for every kqueue/BSD-numbered host so a new
//! BSD (NetBSD/OpenBSD/DragonFly) is a one-line addition here rather than a
//! per-arm `cfg(macos)`/`cfg(freebsd)` audit across the crate. This mirrors the
//! `carrick_bsd` cfg the `carrick-runtime` build.rs already emits; it is named
//! `carrick_bsd_family` to avoid colliding with that crate-local cfg.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(carrick_bsd_family)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if matches!(
        os.as_str(),
        "macos" | "ios" | "freebsd" | "netbsd" | "openbsd" | "dragonfly"
    ) {
        println!("cargo::rustc-cfg=carrick_bsd_family");
    }
}
