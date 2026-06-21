//! `carrick-hal` — the carrick Hardware Abstraction Layer.
//!
//! Traits-only leaf crate: zero OS / hypervisor dependencies. Holds the
//! runtime↔engine contract (`SyscallTrap`, `TrapError`, `ForkOutcome`),
//! the raw hypervisor traits (`HvVm`/`HvVcpu`/`VcpuExit`), the host-primitive
//! traits (`EventMultiplexer`, `CrossProcessFutex`),
//! errno translation, and shared types (`OsError`, `MemPerms`, `Reg`, `SysReg`).
//! Modules are added by the following tasks.
pub mod aarch64;
pub use aarch64::{
    AARCH64_HVC_EXCEPTION_CLASS, AARCH64_SVC_EXCEPTION_CLASS, ExecLevel, aarch64_exception_class,
    is_aarch64_hvc_exception, is_aarch64_hvc_maintenance, is_aarch64_svc_exception,
    is_aarch64_syscall_exception,
};
pub mod error;
pub use error::{MemPerms, OsError, Reg, SysReg};
pub mod trap;
pub use trap::{ForkOutcome, RawSyscall, SyscallTrap, TrapError};
pub mod hypervisor;
pub use hypervisor::{HvVcpu, HvVm, VcpuExit};
pub mod event;
pub use event::{EventMultiplexer, Interest, PollEvent, Readiness, TriggerMode, VnodeEvents};
pub mod futex;
pub use futex::{SHARED_FUTEX_MAX_SLICE_NS, SharedWaitStep, shared_wait_sliced};
pub mod threaded;
pub use threaded::{
    FutexOutcome, GenericVcpuRegistry, GuestEntryRegs, HostForkCoordinator, PlatformFutex,
    PreparedHostFork, RegAccess, ThreadId, ThreadedEngine, VcpuKick, VcpuKickDyn, VcpuRegistry,
};
pub mod sigframe;
pub mod signal_arrival;
pub use signal_arrival::{GenericSignalArrival, SignalArrival};
/// The platform-NEUTRAL fork-coordinator state machine, generic over the
/// backend's [`pump_fork_coord::HostSignalPump`] (self-pipe or kqueue). Every
/// backend's coordinator is a `PumpForkCoordinator<P>`.
pub mod pump_fork_coord;
pub use pump_fork_coord::{HostSignalPump, PumpForkCoordinator};
/// The shared HostForkCoordinator for kick+futex backends (cfg-empty on macOS/HVF).
pub mod fork_coord;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
pub use fork_coord::GenericForkCoordinator;
/// The shared async host-signal pump (kick+futex backends; cfg-empty on macOS/HVF).
pub mod signal_pump;
/// The pluggable M:N admission scheduler bounding guest threads onto N vCPU slots.
pub mod vcpu_sched;
pub use vcpu_sched::{SlotId, SlotLease, VcpuScheduler, Yield};
pub mod timer_delivery;
pub use timer_delivery::{PosixTimerSpec, TimerArm, TimerDelivery};
pub mod guest_arch;
pub use guest_arch::{GuestArch, PageTableCodec, PtGranule, SyscallRemap, SyscallTable};
pub mod aarch64_arch;
pub use aarch64_arch::{Aarch64BootSysregs, Aarch64GuestArch, Aarch64Mmu, Aarch64SyscallTable};
pub mod x8664_arch;
pub use x8664_arch::{
    GDT_LEN, SYSCALL_DOORBELL_PORT, X8664BootSysregs, X8664GuestArch, X8664Mmu, X8664SyscallTable,
    entry_trampoline_bytes as x8664_entry_trampoline_bytes,
};
