//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here while the HVPatch
//! process-bank prototype remains the only multi-task backend implementation.

pub mod address;
pub mod clone_plan;
pub mod core;
pub mod exec;
pub mod ids;
pub mod objects;
pub mod operations;
pub mod registry;

pub use address::{
    Asid, MmBackend, MmBinding, SnapshotError, SnapshotTable, Stage1Root, Stage1RootError, Ttbr0,
    VmaSummary,
};
pub use clone_plan::{
    CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode, ForkParentMode, ForkPidfdMode,
    VforkMode,
};
pub use core::{
    Kernel, KernelContext, KernelError, KernelTaskBinding, Registry, RegistryInvariantError,
    RootBootstrap, TaskExitSubscriber, TaskRevision, VforkParentWait, VforkReleaseReason,
};
pub use exec::{ExecError, PreparedExec};
pub use ids::{
    FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, InvalidFileSlot,
    InvalidLinuxSignal, LinuxSignal, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub use objects::{
    Credentials, FileDescription, FileSlot, FileTable, FsContext, LinuxWaitStatus, Mm,
    ObjectGraphError, PidfdTarget, ProcessGroup, RunnerDirective, Session, Sighand,
    SignalDisposition, Task, TaskKey, TaskLifecycle, TaskPendingSignals, TaskRef, TaskRusage,
    TaskShared, TaskSharedCloneError, Thread, ThreadKey, ThreadRef, ThreadResources, ThreadRunner,
    ThreadSignalState, Zombie,
};
pub use operations::{
    ForkReservation, KernelFailpoint, KernelOperationError, PreparedFork, PreparedTaskExit,
    PreparedThreadClone, PublishedFork, ReservedPidfdSubscription, TaskIdentity,
    TaskOperationReservation, ThreadCloneReservation, WaitMode, WaitOutcome,
};
pub use registry::{
    IdError, IdRegistry, IdRegistryCounts, ProcessGroupClaim, SessionClaim, TaskClaim,
    TaskReservation, ThreadClaim, ThreadReservation,
};
