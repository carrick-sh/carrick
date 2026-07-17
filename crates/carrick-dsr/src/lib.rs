//! `carrick-dsr` — the platform-neutral core of the native (DSR) execution
//! backend.
//!
//! The DSR (dynamic syscall rewriter) runs unmodified Linux binaries as
//! host-native processes by selective same-ISA binary translation: most guest
//! instructions copy through verbatim; sensitive instructions (syscalls,
//! counter reads, TLS registers, …) are rewritten into typed gateway exits.
//! The native lane is always same-ISA — guest ISA == host ISA — so a lane is
//! a (host OS, ISA) pair: Darwin/AArch64 (the reference lane) and
//! FreeBSD/x86_64 (bring-up).
//!
//! This crate holds what every lane shares — the translation-cache and
//! publication machinery, block/generation bookkeeping, the profiling census,
//! and the seam TRAITS a lane plugs into:
//!
//!  * the **guest-ISA seam** — decode/emit/gateway, implemented by
//!    `carrick-dsr-aarch64` / `carrick-dsr-x86`. The per-ISA plan/emit IR is
//!    deliberately PRIVATE to each arch crate (the AArch64 IR speaks
//!    X18/X28 virtualization and exclusive-monitor fusion; the x86 IR speaks
//!    variable-length decode and fs/gs — forcing one shared IR would flatten
//!    real semantic differences). The seam is coarser: "translate this block,
//!    give me code bytes + link sites + a typed exit surface".
//!  * the **host-OS seam** — JIT W^X protection, trap transport, kick, and
//!    clocks, implemented by `carrick-native-darwin` / `carrick-native-freebsd`.
//!
//! Extraction from `carrick-runtime/src/native_darwin` is staged (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! while it is in flight the runtime re-exports these modules under their old
//! paths so call sites are unchanged.

pub mod cache;
pub mod host;
pub mod ids;
pub mod profile;
pub mod vocabulary;
