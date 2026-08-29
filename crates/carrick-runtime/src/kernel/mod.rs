//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here; HVPatch binds each
//! mm to an ASID-owned stage-1 root over globally addressed frames.

pub mod address;
pub mod clone_plan;
pub mod container;
pub mod control;
pub mod core;
pub mod crash_capture;
pub mod debug;
pub mod exec;
pub mod foreign_mm;
pub mod frame_inventory;
pub mod guest_execution;
pub mod ids;
mod mm_access;
pub mod mm_transaction;
pub mod netns;
pub mod objects;
pub mod operations;
pub mod registry;
pub mod scheduler;
pub mod snapshot;
pub(crate) mod tty;

#[cfg(test)]
mod tests;

pub use address::{
    Asid, MmBackend, MmBackendSnapshot, MmBinding, OwnedVmaSnapshot, SharedVmaSnapshotSource,
    SnapshotError, SnapshotTable, Stage1Root, Stage1RootError, Ttbr0, VmaAccess, VmaRevision,
    VmaSnapshotSource, VmaSummary,
};
pub use clone_plan::{
    CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode, ForkParentMode, ForkPidfdMode,
    VforkMode,
};
pub use container::{
    ClockDomain, Container, ContainerId, LaunchAuthorization, LaunchContext, RegistryContainerId,
    RunId, SignedDuration, TimeControl, TimeError,
};
pub use crash_capture::{
    CrashCaptureAuthority, CrashCaptureGeneration, CrashGenerationExhausted, CrashQuorum,
    CrashQuorumPoll, CrashRegisterFile, CrashRegisterVote,
};
pub(crate) use mm_access::MmAccessAuthority;
pub use mm_access::{
    CowBroken, CurrentMm, ForeignMm, ForeignWriteReceipt, MmAccessError, MmReadRange, MmRelation,
    MmToken, MmWriteRange,
};
pub use mm_transaction::{MmTransaction, StagedMmOp};

pub(crate) use core::ReservationChangeSubscription;
pub use core::{
    Kernel, KernelContext, KernelError, KernelTaskBinding, Registry, RegistryInvariantError,
    RootBootstrap, TaskExitSubscriber, TaskRevision, VforkParentWait, VforkReleaseReason,
};
pub use debug::{
    ClientError as KernelDebugClientError, DebugEndpoint,
    EndpointError as KernelDebugEndpointError, KernelDebugAuxProvider, KernelDebugDtoError,
    KernelDebugRequest, KernelDebugServer, KernelDebugSnapshot, KernelDebugTable,
    ServerError as KernelDebugServerError, UnknownTable as UnknownKernelTable,
    fetch as kernel_debug_fetch,
};
pub use exec::{ExecError, PreparedExec};
pub use frame_inventory::{
    FrameInventoryAuthority, FrameInventoryError, FrameInventoryReserveError,
    FrameInventorySnapshot, FrameRow, MappingRow,
};
pub(crate) use guest_execution::ExactMmCensusGuard;
pub use guest_execution::{
    GuestExecutorCensus, GuestExecutorCensusError, GuestExecutorParticipation,
};
pub use ids::{
    CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, InvalidFileSlot,
    InvalidLinuxSignal, LinuxSignal, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub use netns::{NetNs, UtsNs};
pub(crate) use netns::{publish_root_net_view, publish_root_nodename, root_net_ns, root_uts_ns};
pub use objects::{
    Credentials, FileDescription, FileDescriptionBackingKind, FileDescriptionBackingSnapshot,
    FileSlot, FileTable, FsContext, HandlerFrameState, LinuxWaitStatus, Mm, ObjectGraphError,
    OpenDescriptionBackingSnapshot, PendingQueue, PendingSignal, PidfdTarget, ProcessGroup,
    RlimitSet, RunnerDirective, Session, Sighand, SignalAuthority, SignalDequeue,
    SignalDisposition, SignalPendingOwner, Task, TaskKey, TaskLifecycle, TaskParticipantError,
    TaskPendingSignals, TaskRef, TaskRusage, TaskShared, TaskSharedCloneError, TaskWaker, Thread,
    ThreadKey, ThreadRef, ThreadResources, ThreadRunner, ThreadSignalState, Zombie,
};
#[allow(unused_imports)]
pub(crate) use objects::{
    DescriptionCommon, FileDescriptionBacking, JobControlStopInvalidationGeneration,
    NO_READINESS_CONTEXT, NoReadinessContext, ReadinessContext,
};
pub use operations::{
    ChildStartOutcome, ChildStartWait, ForkReservation, KernelFailpoint, KernelOperationError,
    PreparedFork, PreparedTaskExit, PreparedThreadClone, ProcessIdentity, ProcessState,
    PublishedFork, PublishedThreadClone, ReservedPidfdSubscription, SignalTargetAuthorization,
    StartedFork, StartedThreadClone, TaskIdentity, TaskOperationReservation,
    ThreadCloneReservation, ThreadPublicationReservationAttempt, WaitMode, WaitOutcome,
};
pub(crate) use operations::{
    CloseRangeUnshare, ExactSignalTargetAuthorization, ExactThreadSignalPost, TtyControlError,
};
pub use registry::{
    IdError, IdRegistry, IdRegistryCounts, ProcessGroupClaim, SessionClaim, TaskClaim,
    TaskReservation, ThreadClaim, ThreadReservation,
};
pub(crate) use scheduler::SubmissionAuthority;
pub use scheduler::{
    ExecutorBinding, ExecutorKick, ExecutorKickToken, ExecutorRegistration, RunQueue,
    RunQueueError, RunnableThread, Scheduler, SchedulerError, WakeDisposition,
};
pub use snapshot::{
    CredentialsSnapshotRow, FileDescriptionSnapshotKind, FileDescriptionSnapshotRow,
    FileSlotSnapshotRow, FileTableSnapshotRow, FsContextSnapshotRow, KERNEL_SNAPSHOT_V1_SCHEMA,
    KernelSnapshotError, KernelSnapshotV1, MmSnapshotRow, ObjectSnapshotClass,
    ProcessGroupSnapshotRow, SessionSnapshotRow, SighandSnapshotRow, TaskSharedObservationKey,
    TaskSharedSnapshotRow, TaskSignalSnapshotRow, TaskSnapshotRow, ThreadResourcesObservationKey,
    ThreadResourcesSnapshotRow, ThreadSignalSnapshotRow, ThreadSnapshotClass, ThreadSnapshotRow,
    VmaSnapshotRow, ZombieSnapshotRow,
};
