//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here; HVPatch binds each
//! mm to an ASID-owned stage-1 root over globally addressed frames.

pub mod address;
#[cfg(any(test, feature = "test-support"))]
pub mod builder;
pub(crate) mod carrier_process;
pub mod clone_plan;
pub mod container;
pub mod continuation;
pub mod control;
pub mod core;
pub(crate) mod cpu_limit;
pub mod crash_capture;
pub mod debug;
pub mod exec;
pub mod fd_ceiling;
pub mod frame_inventory;
pub mod guest_execution;
pub mod identity_page;
pub mod ids;
pub mod mm_access;
pub(crate) mod mm_proof;
pub mod mm_transaction;
pub mod netns;
pub mod objects;
pub mod operations;
pub mod process_lifecycle;
pub mod registry;
pub mod scheduler;
pub mod snapshot;
pub mod tty;
pub mod wait_set;

#[cfg(test)]
mod tests;

pub use address::{
    Asid, MmBackend, MmBackendSnapshot, MmBinding, OwnedVmaSnapshot, SharedVmaSnapshotSource,
    SnapshotError, SnapshotTable, Stage1Root, Stage1RootError, Ttbr0, VmaAccess, VmaRevision,
    VmaSnapshotSource, VmaSummary,
};
#[cfg(any(test, feature = "test-support"))]
pub use builder::KernelBuilder;
pub use clone_plan::{
    CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode, ForkParentMode, ForkPidfdMode,
    VforkMode,
};
pub use container::{
    AdjtimexState, CarrierScopeId, ClockDomain, Container, ContainerId, LaunchAuthorization,
    LaunchContext, RegistryContainerId, RunId, SignedDuration, TimeControl, TimeError,
};
pub use crash_capture::{
    CrashCaptureAuthority, CrashCaptureGeneration, CrashGenerationExhausted, CrashQuorum,
    CrashQuorumPoll, CrashRegisterFile, CrashRegisterVote,
};
pub use mm_access::MmAccessAuthority;
#[cfg(test)]
pub(crate) use mm_access::test_support::consumer_cow_fixture;
pub use mm_access::{
    CowBroken, CurrentMm, ForeignMm, ForeignWriteReceipt, MmAccessError, MmReadRange, MmRelation,
    MmToken, MmWriteRange,
};
pub use mm_proof::KernelForeignCowProof;
pub use mm_transaction::{MmTransaction, StagedMmOp};

pub use carrier_process::CarrierProcess;
#[cfg(any(test, feature = "test-support"))]
pub use carrier_process::{
    TestCarrierProcess, TestMmBackend, TestStage1MmProjection, test_mm_binding,
};
pub use core::ReservationChangeSubscription;
pub use core::{
    Kernel, KernelContext, KernelError, KernelTaskBinding, Registry, RegistryInvariantError,
    RootBootstrap, TaskExitSubscriber, TaskRevision, VforkParentWait, VforkReleaseReason,
};
pub use debug::{
    ClientError as KernelDebugClientError, DebugEndpoint,
    EndpointError as KernelDebugEndpointError, KernelDebugAuxProvider, KernelDebugDtoError,
    KernelDebugRequest, KernelDebugServer, KernelDebugSnapshot, KernelDebugTable,
    ServerError as KernelDebugServerError, UnknownTable as UnknownKernelTable,
    abort as kernel_debug_abort, fetch as kernel_debug_fetch,
};
pub use exec::{ExecError, ExecPrepareError, PreparedExec};
pub use fd_ceiling::FdCeilingAuthority;
pub use frame_inventory::{
    FrameInventoryAuthority, FrameInventoryError, FrameInventoryReserveError,
    FrameInventorySnapshot, FrameRow, MappingRow,
};
pub(crate) use guest_execution::ExactMmCensusGuard;
pub use guest_execution::{
    GuestExecutorCensus, GuestExecutorCensusError, GuestExecutorParticipation,
};
pub use ids::{
    ChildExitSignal, CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId,
    InvalidFileSlot, InvalidLinuxSignal, LinuxSignal, LinuxTid, MmId, ObjectIdError,
    ObjectIdRegistry, ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub use netns::{NetNs, UtsNs};
pub use objects::{
    Credentials, DumpableMode, FileDescription, FileDescriptionBackingKind,
    FileDescriptionBackingSnapshot, FileSlot, FileTable, FsContext, HandlerFrameState,
    LinuxWaitStatus, Mm, ObjectGraphError, OpenDescriptionBackingSnapshot, PendingQueue,
    PendingSignal, PidfdTarget, ProcessGroup, RlimitSet, RunnerDirective, Session, Sighand,
    SignalAuthority, SignalDeliveryAction, SignalDequeue, SignalDisposition, SignalPendingOwner,
    SocketCork, SocketFlows, SocketPeerCred, Task, TaskKey, TaskLifecycle, TaskParticipantError,
    TaskPendingSignals, TaskRef, TaskRusage, TaskShared, TaskSharedCloneError, TaskWaker, Thread,
    ThreadKey, ThreadRef, ThreadResources, ThreadRunner, ThreadSignalState, UnixDgramCred,
    UnixFlow, UnixLedger, UnixStreamCred, Zombie, evaluate_signal_delivery_action,
    is_default_ignore_signal, is_default_stop_signal,
};
#[allow(unused_imports)]
pub(crate) use objects::{
    DescriptionCommon, FileDescriptionBacking, NO_READINESS_CONTEXT, NoReadinessContext,
    ReadinessContext,
};
#[allow(unused_imports)]
pub use objects::{
    JobControlStopInvalidationGeneration, close_system_charge_window,
    system_charge_window_is_closed,
};
pub use operations::{
    ChildStartOutcome, ChildStartWait, ChildWaitPrecheck, ForkReservation, KernelFailpoint,
    KernelOperationError, PreparedFork, PreparedTaskExit, PreparedThreadClone, ProcessIdentity,
    ProcessState, PublishedFork, PublishedThreadClone, ReservedPidfdSubscription,
    SignalTargetAuthorization, StartedFork, StartedThreadClone, TaskIdentity,
    TaskOperationReservation, ThreadCloneReservation, ThreadPublicationReservationAttempt,
    WaitChildClass, WaitMode, WaitOutcome,
};
pub(crate) use operations::{CloseRangeUnshare, TtyControlError};
pub use operations::{ExactSignalTargetAuthorization, ExactThreadSignalPost};
pub use process_lifecycle::ProcessThreadExit;
pub(crate) use process_lifecycle::RetiredThreadResources;
pub use process_lifecycle::{ChildExit, StopKind, WaitResult, identity_operation_errno};
pub use registry::{
    IdError, IdRegistry, IdRegistryCounts, ProcessGroupClaim, SessionClaim, TaskClaim,
    TaskReservation, ThreadClaim, ThreadReservation,
};
pub use scheduler::HostWaitToken;
pub use scheduler::SubmissionAuthority;
pub use scheduler::{
    DeliveryOutcome, ExecutorBinding, ExecutorKick, ExecutorKickToken, ExecutorRegistration,
    PreemptionDriverError, PreemptionReasons, PreemptionRequest, PreemptionWork, RunQueue,
    RunQueueError, RunnableThread, Scheduler, SchedulerError, SchedulerRetargetError,
    SettlementDisposition, WakeDisposition,
};
pub use snapshot::{
    CredentialsSnapshotRow, FileDescriptionSnapshotKind, FileDescriptionSnapshotRow,
    FileSlotSnapshotRow, FileTableSnapshotRow, ForensicSnapshot, FsContextSnapshotRow,
    KERNEL_SNAPSHOT_V1_SCHEMA, KernelSnapshotError, KernelSnapshotV1, MmSnapshotRow,
    ObjectSnapshotClass, ProcessGroupSnapshotRow, SessionSnapshotRow, SighandSnapshotRow,
    SnapshotFinding, TaskSharedObservationKey, TaskSharedSnapshotRow, TaskSignalSnapshotRow,
    TaskSnapshotRow, ThreadResourcesObservationKey, ThreadResourcesSnapshotRow,
    ThreadSignalSnapshotRow, ThreadSnapshotClass, ThreadSnapshotRow, VmaSnapshotRow,
    ZombieSnapshotRow,
};
pub use wait_set::{WaitCallbackEnrollment, WaitEnrollment, WaitQueue, WaitSet, WaitSetOutcome};
