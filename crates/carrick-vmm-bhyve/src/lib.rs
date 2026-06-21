//! carrick-vmm-bhyve: the FreeBSD/bhyve VMM backend.
//!
//! Mirrors `carrick-vmm-kvm`'s shape — a `carrick-hal` `HvVm`/`HvVcpu` over the
//! host hypervisor and supplies FreeBSD-specific glue for the platform runtime
//! loop. The hypervisor layer here FFIs to FreeBSD's userspace **libvmmapi**
//! instead of KVM's ioctls.
//!
//! # Phase 2: the amd64 arm (x86_64 guests on x86_64 FreeBSD)
//!
//! Since bhyve virtualizes the host's own ISA, an **amd64 FreeBSD host runs
//! x86_64 guests**. That lane uses the shared `carrick-x86` engine plus
//! bhyve-specific VMM operations and host glue.
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
pub mod bhyve_signal_backend;
#[cfg(target_arch = "x86_64")]
pub use bhyve_signal_backend::BhyveGlue;
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
pub use vmm::{BhyveSharedVm, BhyveVcpu, BhyveVm};
#[cfg(target_arch = "x86_64")]
pub use vmm_x86::BhyveVmExit;
