//! `carrick-aarch64` — the shared aarch64 (HVF/KVM) engine scaffold (Axis 1).
//!
//! This crate sits ABOVE `carrick-hal`/`carrick-mem`/`carrick-guest-mem` and
//! BELOW the per-VMM backend crates (`carrick-vmm-hvf`, `carrick-vmm-kvm`'s
//! aarch64 lane). Its job is to own — ONCE — everything the two aarch64 VMM
//! backends currently re-implement by copy: the trap loop, the register/sysreg
//! walk, the stage-1 page-table edits, the snapshot/restore pair, and the
//! threaded lifecycle, all parameterized over the thin
//! [`Aarch64Vmm`](vmm::Aarch64Vmm) + [`Aarch64Vcpu`](vmm::Aarch64Vcpu) trait
//! pair. It mirrors the PROVEN `carrick-x86` crate, but on the aarch64 axis.
//!
//! ## Status — Stage 1 (compile-only scaffold)
//!
//! This is a compile-only scaffold: it DEFINES the trait pair, the exit/snapshot
//! value types, and the [`Aarch64EngineCore`](engine::Aarch64EngineCore) field
//! set, but NOTHING implements the traits yet and NO backend is wired. Later
//! stages migrate the KVM aarch64 lane, then the HVF backend, onto this engine.

// This crate is an as-yet-unconsumed scaffold (Stage 1): the trait pair and the
// engine fields are defined but no backend implements them and no caller drives
// the engine, so the trait methods and most engine accessors are not yet
// reachable. Allowed crate-wide until Stage 2+ wires the callers.
#![allow(dead_code)]
// The aarch64 EL0-fault exit naturally carries the full architectural state both
// backends build `el0_fault()` from (syndrome/elr/far/x16/x17/x29/x30/sp/...);
// the same wide-argument shape appears on the sibling/builder seams.
#![allow(clippy::too_many_arguments)]

pub mod engine;
pub mod vmm;

pub use engine::Aarch64EngineCore;
pub use vmm::{Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy};
