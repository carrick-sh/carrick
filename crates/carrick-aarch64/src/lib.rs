//! `carrick-aarch64` — the shared aarch64 (HVF/KVM) engine scaffold (Axis 1).
//!
//! This crate sits ABOVE `carrick-hal`/`carrick-mem`/`carrick-guest-mem` and
//! BELOW the per-VMM backend crates (`carrick-vmm-hvf`, `carrick-vmm-kvm`'s
//! aarch64 lane). Its job is to own — ONCE — everything the two aarch64 VMM
//! backends currently re-implement by copy: the trap loop, the register/sysreg
//! walk, the stage-1 page-table edits, the snapshot/restore pair, and the
//! threaded lifecycle, all parameterized over the thin
//! [`Aarch64Vmm`] + [`Aarch64Vcpu`] trait
//! pair. It mirrors the PROVEN `carrick-x86` crate, but on the aarch64 axis.
//!
//! ## Status — Stage 2 (KVM aarch64 lane migrated)
//!
//! The trait pair, the exit/snapshot value types, and the
//! [`Aarch64EngineCore`] now carry the FULL shared
//! aarch64 trap engine: the `carrick-hal` engine traits (`SyscallTrap` /
//! `RegAccess` / `GuestMemory` / `ThreadedEngine`) are implemented ONCE over the
//! thin [`Aarch64Vmm`] / [`Aarch64Vcpu`] pair.
//! The KVM aarch64 backend (`carrick-vmm-kvm`'s `kvm_aarch64_engine`) is wired:
//! `KvmTrapEngine` is now a type alias to `Aarch64EngineCore<KvmAarch64Vmm>`. The
//! HVF backend migration onto this engine is a later stage.

// The aarch64 EL0-fault exit naturally carries the full architectural state both
// backends build `el0_fault()` from (syndrome/elr/far/x16/x17/x29/x30/sp/...);
// the same wide-argument shape appears on the sibling/builder seams.
#![allow(clippy::too_many_arguments)]

pub mod engine;
pub mod vmm;

pub use engine::Aarch64EngineCore;
pub use vmm::{Aarch64Exit, Aarch64Vcpu, Aarch64VcpuSnapshot, Aarch64Vmm, ForkRamStrategy};
