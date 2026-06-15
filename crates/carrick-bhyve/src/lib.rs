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
//! # Phase 2: the amd64 arm (x86_64 guests on x86_64 FreeBSD)
//!
//! Since bhyve virtualizes the host's own ISA, an **amd64 FreeBSD host runs
//! x86_64 guests** — and that path is live (the box's nested-virt blocker was
//! resolved; see `docs/superpowers/specs/2026-06-13-x86_64-bhyve-phase2-design.md`).
//! The `vmm_x86` module carries the amd64 model (x86 `vm_exit`/`vm_inout`,
//! amd64 register/exitcode constants, inherent raw-register/descriptor
//! access); on x86_64 the aarch64-named `HvVm`/`HvVcpu` impls are deliberately
//! not provided and the x86 backend uses the inherent surface instead.
//!
//! On every non-FreeBSD host this crate is intentionally empty.
#![cfg(target_os = "freebsd")]

pub mod vmm;
#[cfg(target_arch = "x86_64")]
pub mod vmm_x86;

#[cfg(target_arch = "x86_64")]
pub mod guest_setup_x86;

// The old hand-rolled trap engine. Kept compiled (the M0/M1 `tests/live_vcpu.rs`
// scaffolds reference `BhyveTrapEngine`/`bring_up_x86*`), and selected at the
// run path only under the `bhyve-legacy-engine` instant-revert flag. The DEFAULT
// run path is the shared `X86EngineCore<BhyveVmm>` (`bhyve_x86_engine`).
#[cfg(target_arch = "x86_64")]
pub mod trap_engine;

// The bhyve x86 backend on the shared `carrick-x86` engine scaffold (Stage 4).
#[cfg(target_arch = "x86_64")]
pub mod bhyve_x86_engine;

#[cfg(target_arch = "x86_64")]
pub mod run_elf;

#[cfg(target_arch = "x86_64")]
mod bhyve_futex;
#[cfg(target_arch = "x86_64")]
pub use bhyve_futex::{BhyveFutex, make_bhyve_futex};

#[cfg(target_arch = "x86_64")]
mod bhyve_kicker;
#[cfg(target_arch = "x86_64")]
pub use bhyve_kicker::{BhyveKickHandle, BhyveKicker, install_bhyve_kick_handler, kick_signal};

// SP4.2 cross-process signal host-layer glue (FreeBSD mirrors of the KVM modules).
#[cfg(target_arch = "x86_64")]
pub mod bhyve_disposition;
#[cfg(target_arch = "x86_64")]
pub mod bhyve_signal_pump;
#[cfg(target_arch = "x86_64")]
pub mod bhyve_signum;
#[cfg(target_arch = "x86_64")]
pub mod bhyve_xsig;

#[cfg(target_arch = "x86_64")]
mod bhyve_threaded_glue;
#[cfg(target_arch = "x86_64")]
pub use bhyve_threaded_glue::{BhyveForkCoordinator, BhyveTimerDelivery};

#[cfg(target_arch = "x86_64")]
pub use bhyve_x86_engine::{BhyveVmm, BhyveX86Vcpu, bring_up as bring_up_x86_engine};
#[cfg(target_arch = "x86_64")]
pub use trap_engine::BhyveTrapEngine;
pub use vmm::{BhyveSharedVm, BhyveVcpu, BhyveVm};
#[cfg(target_arch = "x86_64")]
pub use vmm_x86::X86Exit;
