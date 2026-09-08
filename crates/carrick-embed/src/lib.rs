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
//! wants the bytes); the CLI's default is `Inherit`.
//!
//! | Interface | Public types and ordering | Current boundary |
//! | --- | --- | --- |
//! | Stdio | [`StdioConfig`] selects captured, inherited, or caller-provided writers independently per stream | interactive embedded TTY is not exposed yet |
//! | Observation/filtering | Repeated [`ContainerBuilder::observer`] calls append [`SyscallObserver`] implementations; they inspect effective calls, receive lifecycle/return callbacks, and the first non-allow [`SyscallAction`] wins | observers filter but do not replace arbitrary results |
//! | Interception | Repeated [`ContainerBuilder::interceptor`] calls append [`SyscallInterceptor`] implementations; cumulative [`InterceptAction::RewriteArgs`] changes flow forward and the first return/errno proposal stops the chain | no syscall-number change, guest-pointer dereference, or guest-memory mutation |
//! | VFS | [`ContainerBuilder::vfs_mount`] installs [`Vfs`] implementations at absolute guest paths, including [`InMemoryFileVfs`], [`LayeredVfs`], [`FilterVfs`], and [`RecordingVfs`] | mount behavior only; no arbitrary private-page access |
//! | Time | [`ContainerBuilder::time`] installs the last [`TimeControl`] value for the container's [`ClockDomain`] | controls Carrick-modeled guest clocks/waits, not host time |
//! | Faults/budgets | [`ContainerBuilder::fault_injector`] installs ordered [`FaultInjector`] rules whose first match wins; [`ContainerBuilder::resource_budget`] installs one [`ResourceBudget`] before user observers | a pure [`FaultAction::Delay`] uses the container clock domain and returns [`SyscallAction::Allow`], so later observers and the handler continue but later rules in that injector do not; only shipped [`FaultAction`], [`ExceedAction`], and resource counters are enforced |
//! | Network | [`ContainerBuilder::network_interposer`] installs the last [`NetworkInterposer`], whose outbound rules can use [`MockService`] or [`HttpMock`] | not a general packet-filter or raw-packet API |
//! | Shared buffers | [`ContainerBuilder::shared_buffer`] exposes a [`SharedBuffer`] at `/dev/carrick/shm/<name>`; [`PreparedContainer::shared_buffer_lease`] returns a generation-stamped [`SharedBufferLease`] | leases fail closed after retirement/generation drift; no arbitrary private-page access |
//! | Carrier concurrency | [`Carrier::new`] owns one VM/kernel graph; [`Carrier::container`] binds builders to it and [`Carrier::shutdown`] drains exact retirement | one carrier/VM per host process; no interactive embedded TTY |
//!
//! Launch policy and guest seccomp validate the interceptor's effective call
//! before a proposed result is honored. Policy outcomes combine monotonically:
//! a later errno cannot downgrade an established signal death. Installing an
//! interceptor routes accelerated identity/time calls through visible syscall
//! traps. A trusted interceptor callback panic becomes
//! [`EmbedError::InterceptorPanicked`] with the calling container's identity;
//! configuration, preparation, and later infrastructure failures remain typed
//! as [`EmbedError::Config`], [`EmbedError::Prepare`], and
//! [`EmbedError::Runtime`].
//!
//! Custom [`Vfs`] mounts replace behavior below an absolute guest path; they do
//! not expose arbitrary private guest pages.
//!
//! # Carrier ownership and concurrency
//!
//! [`ContainerBuilder::from_image`] owns an implicit single-use carrier and
//! retires it before returning. For overlapping non-interactive workloads,
//! create one [`Carrier`], construct every builder through
//! [`Carrier::container`], await the runs, then call [`Carrier::shutdown`] for
//! deterministic cancellation, worker join, VM destruction, and lifecycle
//! publication. Async [`ContainerBuilder::run`] uses the tokio blocking pool;
//! overlapping [`ContainerBuilder::run_blocking`] calls require separate host
//! threads. An implicit builder refuses to run while an explicit carrier is
//! active.
//!
//! Container kernel identity, process tree, namespace state, extensions, VFS,
//! stdio, and time policy are isolated. Reusing the same host `Arc` in multiple
//! builders deliberately shares that application object. Dropping the last
//! carrier handle requests asynchronous close as a fallback; it is not a
//! deterministic replacement for [`Carrier::shutdown`].
mod builder;
mod carrier;
pub(crate) mod entitlement;
mod error;
mod prepared;
mod result;
pub mod shared_buffer;
pub mod testing;
pub mod vfs;

#[cfg(test)]
pub(crate) static CARRIER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub use builder::{ContainerBuilder, StdioConfig};
pub use carrier::Carrier;
pub use error::EmbedError;
pub use prepared::PreparedContainer;
pub use result::ContainerResult;
pub use shared_buffer::{SharedBuffer, SharedBufferError, SharedBufferLease};
pub use vfs::{
    DirEnt, EntryKind, FilterVfs, InMemoryFileVfs, LayeredVfs, MAX_IN_MEMORY_FILE_SIZE, Metadata,
    OpenContext, OpenFlags, RecordingVfs, Vfs, VfsError, VfsEvent, VfsHandle, VfsOp, VfsOpOutcome,
};

pub use carrick_abi::{CanonicalNr, LinuxErrno};
pub use carrick_engine::{ResolveWarning, RunRequest};
pub use carrick_guest_mem::{Gpa, GuestMemory, GuestVa, HostVa, MemoryError, SharedFutexLocation};
pub use carrick_image::{ImageStore, PullPolicy};
pub use carrick_runtime::compat::CompatReport;
pub use carrick_runtime::dispatch::Signal;
pub use carrick_runtime::kernel::{
    ClockDomain, ContainerId, LinuxTid, ObjectIdRegistry, RunId, SignedDuration, TaskId, TaskKey,
    TaskSerial, ThreadKey, ThreadSerial, TimeControl, TimeError,
};
pub use carrick_runtime::network::{
    ConnectionRecord, HttpMock, InterceptRuleBuilder, IntoTargetSpec, MockService,
    NetworkInterposer, TargetSpec,
};
pub use carrick_runtime::observe::{
    ArgFilter, AuditEvent, AuditObserver, AuditReason, AuditVerdict, AuditorChain, BudgetCounters,
    BudgetResource, BudgetSnapshot, ExceedAction, ExitOwner, ExitStatus, FastPathVisibility,
    FaultAction, FaultCondition, FaultInjector, FaultPredicate, FaultRule, FaultRuleBuilder,
    FirstTouchDeliverReason, ForkKind, GuestCpuId, InterceptAction, InterceptedSyscall,
    KernelAuditor, PolicyObserver, PolicyRule, ProcessInfo, ResourceBudget, SandboxObserver,
    SandboxPreset, SyscallAction, SyscallArgIndexError, SyscallArgs, SyscallBitset, SyscallInfo,
    SyscallInterceptor, SyscallObserver, SyscallOutcome, WakeRejectionReason, is_shortable_syscall,
};
pub use carrick_runtime::runtime::{RunResult, RuntimeError, TerminalReason};
pub use carrick_spec::{Mount, Platform, RunSpec, StdioMode};
