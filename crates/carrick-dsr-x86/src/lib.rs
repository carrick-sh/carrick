//! `carrick-dsr-x86` — the x86_64 guest-ISA lane of the native (DSR)
//! backend (bring-up; M2 of the seams design,
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md).
//!
//! The native lane is same-ISA, so this crate targets Linux/x86_64 guests on
//! x86_64 hosts (FreeBSD/amd64 first). What exists today is the DECODE rung:
//! variable-length instruction classification over `iced-x86` (the `bad64`
//! analog), including the sensitive-instruction catalog fixed in the design
//! doc — `syscall`, `int 0x80`, `rdtsc`/`rdtscp`, `cpuid`,
//! `{rd,wr}{fs,gs}base`, and fs/gs-segment-prefixed accesses (the TLS
//! virtualization surface, x86's analog of TPIDR/X18).
//!
//! Deliberately absent until their design docs exist: the plan IR, the
//! emitter (dynasmrt x64), and the gateway — an x86 `DsrContext`/fsbase-swap
//! design has real open questions (context-register strategy, signal-window
//! phases) that must not be speculated here. Everything callable fails
//! closed with a typed error until then; the block planner cannot
//! accidentally "run" x86 guests through a half-lane.
//!
//! Key structural difference from AArch64 carried by `classify`: x86 has no
//! exclusive monitors — `lock`-prefixed RMWs copy through natively, so the
//! entire exclusive-region fusion apparatus has no analog here — and
//! instructions are variable-length, so every classification carries its
//! decoded length for the planner's stride.

pub mod decode;

pub use decode::{X86Classified, X86DecodeError, X86InstClass, X86SensitiveKind, classify};
