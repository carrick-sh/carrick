//! carrick-vmm-nvmm: the NetBSD/NVMM HAL backend (the fourth platform, after
//! macOS/HVF, Linux/KVM, and FreeBSD/bhyve).
//!
//! Mirrors `carrick-vmm-bhyve`'s shape — a raw-hypervisor layer over the host
//! VMM, eventually paired with a `SyscallTrap`/`GuestMemory` trap engine and
//! driven by the shared platform-agnostic run loop + dispatcher. The
//! hypervisor layer here FFIs to NetBSD's userspace **libnvmm** instead of
//! KVM's ioctls or bhyve's libvmmapi.
//!
//! # Status: M0 — core bring-up smoke (see
//! `docs/superpowers/specs/2026-06-14-nvmm-backend-bringup-design.md`).
//!
//! M0 is the foundational de-risk: open NVMM, create a machine + vCPU, map a
//! guest RAM region (userspace HVA), program a minimal vCPU context whose RIP
//! points at a hand-built `out %al,$0xC5` stub, run the vCPU, and assert the
//! exit is `NVMM_VCPU_EXIT_IO` with `port == 0xC5`. This proves
//! state-programming, the syscall doorbell, and the run loop on real nested
//! NVMM. No ELF, no dispatcher, no trait impls yet (those are M1/M2).
//!
//! Clean-room note: NVMM is a HOST API. The bindings in `nvmm` are transcribed
//! from the on-box headers (`/usr/include/nvmm.h`,
//! `/usr/include/dev/nvmm/{nvmm.h,x86/nvmm_x86.h}`) and `man libnvmm` — the
//! host backend, exactly as FreeBSD's libvmmapi was. The Linux GUEST ABI is
//! not involved here.
//!
//! On every non-NetBSD host this crate is intentionally empty.
#![cfg(target_os = "netbsd")]

pub mod nvmm;
pub mod nvmm_disposition;
mod nvmm_futex;
pub mod nvmm_kicker;
pub mod nvmm_signal_pump;
pub mod nvmm_signum;
pub mod nvmm_threaded_glue;
pub mod nvmm_x86_engine;
pub mod nvmm_xsig;
pub mod run_elf;

pub use nvmm::{
    NVMM_PROT_EXEC, NVMM_PROT_READ, NVMM_PROT_WRITE, NVMM_VCPU_EXIT_HALTED, NVMM_VCPU_EXIT_IO,
    NVMM_VCPU_EXIT_MEMORY, NVMM_VCPU_EXIT_NONE, NVMM_VCPU_EXIT_SHUTDOWN, NVMM_X64_STATE_CRS,
    NVMM_X64_STATE_GPRS, NVMM_X64_STATE_MSRS, NVMM_X64_STATE_SEGS,
};
pub use nvmm::{
    NvmmCapability, NvmmError, NvmmMachine, NvmmResult, NvmmVcpu, NvmmX64State, NvmmX86ExitIo,
};
pub use nvmm_futex::{NvmmFutex, make_nvmm_futex};
pub use nvmm_threaded_glue::{NvmmForkCoordinator, NvmmTimerDelivery};
pub use nvmm_x86_engine::{NVMM_X86_LAYOUT, NvmmVmm, bring_up};
pub use run_elf::run_elf_nvmm;
