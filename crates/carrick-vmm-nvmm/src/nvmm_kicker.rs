//! Cross-thread vCPU "kick" for the NVMM backend.
//!
//! The NetBSD/NVMM realisation of the "interrupt a running vCPU" primitive
//! (HVF has `hv_vcpus_exit`; KVM has `pthread_kill(tid, SIGRTMIN)` → `KVM_RUN`
//! EINTR). On NVMM the same vehicle applies: a signal delivered to a vCPU
//! thread makes the in-progress `nvmm_vcpu_run` return EINTR, which the
//! [`crate::nvmm_x86_engine`] run decode maps to [`carrick_x86::X86Exit::Kicked`].
//! The handler is empty and installed WITHOUT `SA_RESTART` so the kick is not
//! silently restarted.
//!
//! M1 (single-threaded hello) never issues a kick; this exists to satisfy the
//! [`carrick_x86::X86Vmm`] threaded-lifecycle surface. The bookkeeping registry
//! is the platform-neutral [`carrick_hal::GenericVcpuRegistry`] (same as KVM);
//! only [`NvmmKickHandle`] (the `pthread_kill` mechanism) is NVMM-specific.

/// NetBSD's `<sys/signal.h>` defines `SIGRTMIN` as 33.
pub const NETBSD_SIGRTMIN: i32 = 33;

#[inline]
pub fn kick_signal() -> i32 {
    carrick_hal::posix_signal_kick::resolve_kick_signal::<NETBSD_SIGRTMIN>()
}

pub fn install_nvmm_kick_handler() {
    carrick_hal::posix_signal_kick::install_posix_kick_handler::<NETBSD_SIGRTMIN>();
}

/// A `Send`/`Sync` kick handle holding the owning vCPU thread's `pthread_t`.
pub type NvmmKickHandle = carrick_hal::PosixSignalKick<NETBSD_SIGRTMIN>;

/// The NVMM vCPU-kick registry.
pub type NvmmKicker = carrick_hal::GenericVcpuRegistry;
