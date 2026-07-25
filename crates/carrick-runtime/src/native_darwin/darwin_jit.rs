//! Shim: the `carrick_dsr::host::NativeHostJit` seam is now provided by the
//! per-host native-lane crates (M0.6/M0.7 of the seams design). This file
//! re-exports the Darwin one so every existing `darwin_jit::active_host_jit()`
//! call site in this crate resolves unchanged.
//!
//! **Reachability (read this before adding an arm).** This file is a submodule
//! of `native_darwin` (`native_darwin.rs`'s `mod darwin_jit;`), and
//! `native_darwin` itself is `#[cfg(all(target_os = "macos", target_arch =
//! "aarch64"))]` at `lib.rs`. So the single `use` below is the ONLY thing this
//! file ever compiles to, on the only target that compiles it at all. It used
//! to carry a `target_os = "freebsd"` arm and a `not(any(macos, freebsd))`
//! fail-closed stub; both were dead in every configuration, and their presence
//! read as if this shim dispatched the BSD lanes — it does not. The BSD lanes
//! reach their host JIT through `native/mod.rs`'s `NativeLane::Host`
//! (`FreebsdHost`/`NetbsdHost`), and their fail-closed behaviour lives in the
//! host crates themselves. Removed rather than left to mislead again.
//!
//! `carrick-native-darwin` still carries its own internal arm split (a real
//! MAP_JIT impl on Apple Silicon, a fail-closed stub on any other macOS arch),
//! so this re-export is correct for both macOS arches even though only aarch64
//! can reach it today.

pub(crate) use carrick_native_darwin::active_host_jit;
