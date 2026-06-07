//! `carrick-hal` — the carrick Hardware Abstraction Layer.
//!
//! Traits-only leaf crate: zero OS / hypervisor dependencies. Holds the
//! runtime↔engine contract (`SyscallTrap`, `TrapError`, `ForkOutcome`),
//! the raw hypervisor traits (`HvVm`/`HvVcpu`/`VcpuExit`), the host-primitive
//! traits (`EventMultiplexer`, `CrossProcessFutex`, `Sendfile`, `HostFacts`),
//! errno translation, and shared types (`OsError`, `MemPerms`, `Reg`, `SysReg`).
//! Modules are added by the following tasks.
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
pub use futex::CrossProcessFutex;
pub use host_info::HostFacts;
pub use sendfile::Sendfile;
pub mod threaded;
pub use threaded::{
    FutexOutcome, PlatformFutex, RegAccess, ThreadId, ThreadedEngine, VcpuKick, VcpuKickDyn,
    VcpuRegistry,
};
pub mod sigframe;
