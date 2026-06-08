//! `carrick-hal` — the carrick Hardware Abstraction Layer.
//!
//! Traits-only leaf crate: zero OS / hypervisor dependencies. Holds the
//! runtime↔engine contract (`SyscallTrap`, `TrapError`, `ForkOutcome`),
//! the raw hypervisor traits (`HvVm`/`HvVcpu`/`VcpuExit`), the host-primitive
//! traits (`EventMultiplexer`, `CrossProcessFutex`, `Sendfile`, `HostFacts`),
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
pub use trap::{ForkOutcome, SyscallTrap, TrapError};
pub mod hypervisor;
pub use hypervisor::{HvVcpu, HvVm, VcpuExit};
pub mod event;
pub use event::{EventMultiplexer, Interest, PollEvent, Readiness, TriggerMode, VnodeEvents};
pub mod futex;
pub mod host_info;
pub mod sendfile;
pub use futex::{CrossProcessFutex, SHARED_FUTEX_MAX_SLICE_NS, SharedWaitStep, shared_wait_sliced};
pub use host_info::HostFacts;
pub use sendfile::Sendfile;
pub mod threaded;
pub use threaded::{
    FutexOutcome, HostForkCoordinator, PlatformFutex, PreparedHostFork, RegAccess, ThreadId,
    ThreadedEngine, VcpuKick, VcpuKickDyn, VcpuRegistry,
};
pub mod sigframe;
