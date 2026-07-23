//! The single native-lane wiring point (Phase-1 M0.8 graph unification).
//!
//! Before this module, the runtime had **two disjoint native entry graphs**
//! that never touched each other:
//!
//! - macOS: `execute.rs` / `runtime.rs` (both `cfg(feature = "platform-macos")`
//!   files) called `crate::native_darwin::{run_elf_from_dispatcher_debug,
//!   run_static_elf}` directly.
//! - FreeBSD: the inline `execute`/`runtime` modules in `lib.rs` (the
//!   `cfg(feature = "platform-freebsd")` arm) called
//!   `crate::native_freebsd::{run_static_x86_elf, run_static_x86_elf_bytes}`
//!   directly.
//!
//! Nothing forced the two call shapes to agree, and nothing would notice if
//! they drifted further apart. This module is the ONE place `execute.rs`,
//! `runtime.rs`, and `lib.rs` reach into a native backend from now on — see
//! the drift-guard test at the bottom, which fails the build the moment a
//! future edit reintroduces a direct `native_darwin::`/`native_freebsd::` call
//! outside this file.
//!
//! # This is strangler-interim, NOT the end-state
//!
//! [`HostNativeLane`] (plus [`DarwinAarch64Lane`]/`FreebsdX8664Lane` and
//! their `carrick_dsr::lane::NativeLane` impls) is the compile-checked
//! (guest ISA, host) pairing Phase 2 will dispatch through generically (a
//! `ProcessTranslator<HostNativeLane>`-shaped call, replacing the per-lane
//! bodies below with one generic implementation). Phase 1 — this task — only
//! wires the type up and proves it resolves (see the `_assert_host_native_lane_resolves`
//! compile pin in `tests`); the facade FUNCTION BODIES below still branch on
//! `#[cfg(target_os = ..., target_arch = ...)]` and call straight into
//! `native_darwin`/`native_freebsd`, exactly reproducing today's behavior. Do
//! not read the `#[cfg]` arms in `run_oci_native`/`run_static_native`/
//! `run_dispatch_native*` as the intended long-term shape — they are the
//! strangler's temporary scaffolding, kept only until Phase 2 dissolves
//! `native_darwin.rs`/`native_freebsd.rs` into lane-generic code and this
//! module's bodies collapse to a single generic call apiece.
//!
//! # Why four functions, not one
//!
//! The two graphs' call shapes never matched exactly, so forcing them into a
//! single signature would either lose parameters a real caller needs or
//! fabricate arguments no caller has:
//!
//! - [`run_oci_native`] — the OCI/container launch shape (`execute.rs`'s two
//!   `FsBackendKind::Host`/`Memory` arms, byte-identical call sites): a
//!   path *string* the dispatcher itself resolves, plus a debug-state path
//!   and a resolved [`ExecutionPlan`]. Real on macOS/aarch64. FreeBSD has no
//!   entry point of this exact shape yet — its OCI-native path (below) is
//!   wired through a pre-resolved-bytes call instead — so this lane
//!   deliberately returns a typed `Unsupported` rather than faking one.
//! - [`run_static_native`] — the standalone `run-elf` shape (`runtime.rs`'s
//!   one arm): a path `&Path`, no dispatcher-internal resolution. Real on
//!   both lanes: macOS/aarch64 forwards to `native_darwin::run_static_elf`
//!   (debug-state path + plan and all); FreeBSD/x86_64 forwards to
//!   `native_freebsd::run_static_x86_elf`, which has no use for a debug-state
//!   path or a plan, so that arm just drops them (pure indirection with the
//!   two unused params from the macOS-shaped signature discarded, not a
//!   behavior change — `runtime.rs` itself is macOS-only today, so this arm
//!   is presently unreached, staged for the day a unified caller reaches it).
//! - `run_dispatch_native` / `run_dispatch_native_bytes` — the FreeBSD
//!   standalone-workload/LTP-harness surface (`lib.rs`'s
//!   `run_elf_native_dispatch_with_process` and the `run_oci_with_engine`
//!   `ExecutionBackend::Native` early return). Both call shapes are
//!   FreeBSD/x86_64-only in the source graph today (their only callers live
//!   inside `cfg(feature = "platform-freebsd", target_arch = "x86_64")`
//!   blocks), and neither has a Darwin analog to route to or stub — Darwin's
//!   equivalent standalone/OCI-native entries are `run_static_native` and
//!   `run_oci_native` above. Rather than invent a fictitious Darwin arm for a
//!   call shape Darwin has no caller for, these two are gated
//!   `cfg(target_os = "freebsd", target_arch = "x86_64")` at the function
//!   level — the honest minimal shape, flagged here rather than forced.

use std::path::{Path, PathBuf};

pub(crate) mod fork_child;

use crate::dispatch::SyscallDispatcher;
use crate::page_profile::ExecutionPlan;
use crate::run_result::{RunResult, RuntimeError};

/// The native lane this host actually runs. Resolves to a concrete
/// `carrick_dsr::lane::NativeLane` impl on the two lanes the native (DSR)
/// backend targets; does not exist on any other host (there is no third
/// lane to be generic over yet — see the module doc for why the facade
/// bodies below still branch per-target instead of dispatching through this
/// alias).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) type HostNativeLane = DarwinAarch64Lane;
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) type HostNativeLane = FreebsdX8664Lane;

/// The Darwin/aarch64 native lane: AArch64 guest ISA, Darwin host JIT
/// authority (`carrick-native-darwin`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[allow(dead_code)]
pub(crate) struct DarwinAarch64Lane;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_dsr::lane::NativeLane for DarwinAarch64Lane {
    type Isa = carrick_dsr_aarch64::Aarch64Isa;
    type Host = carrick_native_darwin::DarwinHost;
}

/// The FreeBSD/x86_64 native lane: x86_64 guest ISA, FreeBSD host JIT
/// authority (`carrick-native-freebsd`).
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
#[allow(dead_code)]
pub(crate) struct FreebsdX8664Lane;

#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
impl carrick_dsr::lane::NativeLane for FreebsdX8664Lane {
    type Isa = carrick_dsr_x86::X8664Isa;
    type Host = carrick_native_freebsd::FreebsdHost;
}

/// Fallback message for a build where neither known native lane's `cfg`
/// matches (e.g. Linux/KVM). Nothing calls the native facade from such a
/// build today — `execute.rs`/`runtime.rs` are macOS-only files and the
/// `run_dispatch_native*` callers are FreeBSD-only — so this exists purely
/// as a fail-closed complement, matching the pattern already used by
/// `native_darwin.rs`'s own `native_shim_fail_closed` module.
fn no_native_lane_wired() -> RuntimeError {
    RuntimeError::Unsupported(
        "native execution requested on a host with no wired NativeLane \
         (only macOS/aarch64 and FreeBSD/x86_64 are wired)"
            .to_string(),
    )
}

/// OCI/container native-launch entry — the ONLY place `execute.rs` reaches
/// into a native backend (both its `FsBackendKind::Host` and `::Memory`
/// arms call this with byte-identical arguments). See the module doc for why
/// this is not merged with [`run_static_native`].
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
pub(crate) fn run_oci_native<A, E>(
    path: &str,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return crate::native_darwin::run_elf_from_dispatcher_debug(
        path,
        dispatcher,
        argv,
        env,
        max_traps,
        debug_state_path,
        plan,
    );

    #[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
    {
        let _ = (
            path,
            dispatcher,
            argv,
            env,
            max_traps,
            debug_state_path,
            plan,
        );
        return Err(RuntimeError::Unsupported(
            "OCI native path pending phase 2 on this lane".to_string(),
        ));
    }

    #[allow(unreachable_code)]
    {
        let _ = (
            path,
            dispatcher,
            argv,
            env,
            max_traps,
            debug_state_path,
            plan,
        );
        Err(no_native_lane_wired())
    }
}

/// Standalone `run-elf` native-launch entry — the ONLY place `runtime.rs`
/// reaches into a native backend. See the module doc for why this is not
/// merged with [`run_oci_native`].
#[cfg_attr(not(feature = "platform-macos"), allow(dead_code))]
pub(crate) fn run_static_native<A, E>(
    path: &Path,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return crate::native_darwin::run_static_elf(
        path,
        dispatcher,
        argv,
        env,
        max_traps,
        debug_state_path,
        plan,
    );

    // `native_freebsd::run_static_x86_elf` has no use for a debug-state path
    // or a resolved `ExecutionPlan` (it is the same function
    // `run_dispatch_native` below forwards to); drop the two macOS-shaped
    // params rather than inventing FreeBSD-side plumbing for them.
    #[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
    {
        let _ = (debug_state_path, plan);
        return crate::native_freebsd::run_static_x86_elf(path, dispatcher, argv, env, max_traps);
    }

    #[allow(unreachable_code)]
    {
        let _ = (
            path,
            dispatcher,
            argv,
            env,
            max_traps,
            debug_state_path,
            plan,
        );
        Err(no_native_lane_wired())
    }
}

/// FreeBSD standalone-workload/LTP-harness native dispatch — the ONLY place
/// `lib.rs`'s `run_elf_native_dispatch_with_process` reaches into the native
/// backend. FreeBSD/x86_64-only: see the module doc for why this does not
/// carry a Darwin arm.
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
pub(crate) fn run_dispatch_native<A, E>(
    path: &Path,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    crate::native_freebsd::run_static_x86_elf(path, dispatcher, argv, env, max_traps)
}

/// FreeBSD OCI-native dispatch on an already-resolved image — the ONLY place
/// `lib.rs`'s `run_oci_with_engine` reaches into the native backend for its
/// `ExecutionBackend::Native` early return. FreeBSD/x86_64-only: see the
/// module doc for why this does not carry a Darwin arm.
#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
pub(crate) fn run_dispatch_native_bytes(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    crate::native_freebsd::run_static_x86_elf_bytes(bytes, dispatcher, argv, env, max_traps)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Step-1 compile pin: `HostNativeLane` must resolve to a concrete
    /// `NativeLane` impl. Only compiles under the two live lane `cfg`s (see
    /// module doc) — that IS the assertion: there is exactly one wiring-point
    /// type, and it either resolves on a lane host or does not exist at all.
    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "freebsd", target_arch = "x86_64")
    ))]
    #[allow(dead_code)]
    fn _assert_host_native_lane_resolves() {
        fn assert_lane<L: carrick_dsr::lane::NativeLane>() {}
        assert_lane::<HostNativeLane>();
        let _ = core::marker::PhantomData::<HostNativeLane>;
    }

    /// Step-1 drift guard: crude but effective. `execute.rs`/`runtime.rs`
    /// used to call `native_darwin::run_*` directly; `lib.rs`'s FreeBSD arm
    /// used to call `native_freebsd::run_*` directly. Both graphs now route
    /// through this module ONLY — this test reads the actual committed
    /// source text of the three files and fails the moment any of them
    /// reintroduces a direct call, reopening the M0.8 gap this facade
    /// exists to close.
    #[test]
    fn native_entry_points_route_only_through_the_facade() {
        let sources: [(&str, &str); 3] = [
            ("execute.rs", include_str!("../execute.rs")),
            ("runtime.rs", include_str!("../runtime.rs")),
            ("lib.rs", include_str!("../lib.rs")),
        ];

        for (name, src) in sources {
            assert!(
                !src.contains("native_darwin::run_"),
                "{name} calls native_darwin::run_* directly — this reopens \
                 the two-disjoint-native-graphs gap (M0.8). Route through \
                 crate::native (src/native/mod.rs) instead: add/extend a \
                 facade function there and call THAT from {name}.",
            );
            assert!(
                !src.contains("native_freebsd::run_"),
                "{name} calls native_freebsd::run_* directly — this reopens \
                 the two-disjoint-native-graphs gap (M0.8). Route through \
                 crate::native (src/native/mod.rs) instead: add/extend a \
                 facade function there and call THAT from {name}.",
            );
        }
    }
}
