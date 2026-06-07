//! carrick-bhyve: the FreeBSD/bhyve HAL backend (third platform).
//!
//! Mirrors `carrick-linux`'s shape — a `carrick-hal` `HvVm`/`HvVcpu` over the
//! host hypervisor, eventually paired with a `SyscallTrap`/`GuestMemory` trap
//! engine and driven by the same platform-agnostic run loop + real dispatcher.
//! The hypervisor layer here FFIs to FreeBSD's userspace **libvmmapi** instead
//! of KVM's ioctls.
//!
//! # Status: scaffolding (see `docs/superpowers/adr/2026-06-06-bhyve-backend-design.md`)
//!
//! bhyve is hardware-assisted, so an aarch64 carrick guest needs an **aarch64
//! FreeBSD host**; the provided VM is amd64 (compile-gate only). This crate is
//! the verifiable hypervisor layer (the `vmm` module); the guest bring-up has a real
//! architectural divergence from KVM that is deferred to the aarch64 host:
//!
//! bhyve's aarch64 register set (`enum vm_reg_name`) exposes X0–X30, SP, PC,
//! CPSR, and the MMU regs SCTLR/TTBR0/TTBR1/TCR/TCR2/MPIDR — but NOT VBAR_EL1,
//! MAIR_EL1, CPACR_EL1, SPSR_EL1, or ELR_EL1, which carrick's KVM bring-up
//! programs from the host. So bhyve cannot install the EL1 sentinel vector or
//! `eret` to EL0 from the host. Instead bhyve starts the vCPU at **EL1** at a
//! carrick guest-side init stub that programs those registers itself (via MSR)
//! and `eret`s to EL0 — the way a real guest kernel sets up its own EL1 state.
//! That stub + the trap-vehicle wiring are the next slice, on the aarch64 host.
//!
//! On every non-FreeBSD host this crate is intentionally empty.
#![cfg(target_os = "freebsd")]

pub mod vmm;

pub use vmm::{BhyveVcpu, BhyveVm};
