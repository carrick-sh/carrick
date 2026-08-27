//! `carrick-embed`: run a containerized Linux workload from a Rust host
//! application, on Carrick's own kernel.
//!
//! ```text
//! ContainerBuilder
//!   -> carrick_engine::RunRequest -> Engine::resolve (async; tokio)   -> RunSpec
//!   -> Runtime::prepare(&RunSpec, LaunchContext, RuntimeExtensions)   -> PreparedRun
//!   -> PreparedRun::execute()                                         -> RunResult
//!   -> ContainerResult
//! ```
//!
//! The image-resolution half is async (the OCI store uses `tokio::fs` and
//! `oci-client`); the execution half is synchronous and blocking.
//! [`ContainerBuilder::run`] resolves on the ambient tokio runtime and executes
//! on its blocking pool; [`ContainerBuilder::run_blocking`] builds a throwaway
//! current-thread runtime for resolution, drops it, then executes directly.
//!
//! # Entitlement
//!
//! On macOS the executable that calls into this crate must carry the
//! `com.apple.security.hypervisor` entitlement (`scripts/entitlements.plist`);
//! an unsigned test or application binary fails with
//! [`EmbedError::Entitlement`] (`HV_DENIED`, `0xfae94007`). See AGENTS.md
//! Rule 0 and the signed `just test-embed` recipe.
//!
//! # Defaults
//!
//! Both stdio streams default to [`StdioConfig::Captured`] (a library caller
//! wants the bytes); the CLI's default is `Inherit`. No network mocking, VFS
//! injection, observers, time control or tty support is exposed in this
//! version — those arrive with later phases of the embed program
//! (`docs/superpowers/specs/2026-08-25-carrick-embed-program-design.md`).
mod builder;
pub(crate) mod entitlement;
mod error;
mod prepared;
mod result;
pub mod shared_buffer;
pub mod testing;
pub mod vfs;

pub use builder::{ContainerBuilder, StdioConfig};
pub use error::EmbedError;
pub use prepared::PreparedContainer;
pub use result::ContainerResult;
pub use shared_buffer::{SharedBuffer, SharedBufferError, SharedBufferLease};
pub use vfs::{
    DirEnt, EntryKind, FilterVfs, InMemoryFileVfs, LayeredVfs, MAX_IN_MEMORY_FILE_SIZE, Metadata,
    OpenContext, OpenFlags, RecordingVfs, Vfs, VfsError, VfsEvent, VfsHandle, VfsOp, VfsOpOutcome,
};

pub use carrick_engine::{ResolveWarning, RunRequest};
pub use carrick_guest_mem::{Gpa, GuestMemory, GuestVa, HostVa, MemoryError, SharedFutexLocation};
pub use carrick_image::{ImageStore, PullPolicy};
pub use carrick_runtime::compat::CompatReport;
pub use carrick_runtime::dispatch::Signal;
pub use carrick_runtime::kernel::{ClockDomain, SignedDuration, TimeControl, TimeError};
pub use carrick_runtime::network::{
    ConnectionRecord, HttpMock, InterceptRuleBuilder, IntoTargetSpec, MockService,
    NetworkInterposer, TargetSpec,
};
pub use carrick_runtime::observe::{
    ArgFilter, AuditEvent, AuditObserver, BudgetCounters, BudgetResource, BudgetSnapshot,
    ExceedAction, ExitStatus, FastPathVisibility, FaultAction, FaultCondition, FaultInjector,
    FaultPredicate, FaultRule, FaultRuleBuilder, PolicyObserver, PolicyRule, ProcessInfo,
    ResourceBudget, SandboxObserver, SandboxPreset, SyscallAction, SyscallBitset, SyscallInfo,
    SyscallObserver, SyscallOutcome, is_shortable_syscall,
};
pub use carrick_runtime::runtime::{RunResult, RuntimeError, TerminalReason};
pub use carrick_spec::{Mount, Platform, RunSpec, StdioMode};
