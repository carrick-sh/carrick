//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here while the HVPatch
//! process-bank prototype remains the only multi-task backend implementation.

pub mod address;
pub mod clone_plan;
pub mod core;
pub mod debug;
pub mod exec;
pub mod frame_inventory;
pub mod ids;
pub mod objects;
pub mod operations;
pub mod registry;
pub mod snapshot;

pub use address::{
    Asid, MmBackend, MmBackendSnapshot, MmBinding, OwnedVmaSnapshot, SharedVmaSnapshotSource,
    SnapshotError, SnapshotTable, Stage1Root, Stage1RootError, Ttbr0, VmaRevision,
    VmaSnapshotSource, VmaSummary,
};
pub use clone_plan::{
    CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode, ForkParentMode, ForkPidfdMode,
    VforkMode,
};
pub use core::{
    Kernel, KernelContext, KernelError, KernelTaskBinding, Registry, RegistryInvariantError,
    RootBootstrap, TaskExitSubscriber, TaskRevision, VforkParentWait, VforkReleaseReason,
};
pub use debug::{
    ClientError as KernelDebugClientError, DebugEndpoint,
    EndpointError as KernelDebugEndpointError, KernelDebugDtoError, KernelDebugRequest,
    KernelDebugServer, KernelDebugSnapshot, KernelDebugTable,
    ServerError as KernelDebugServerError, UnknownTable as UnknownKernelTable,
    fetch as kernel_debug_fetch,
};
pub use exec::{ExecError, PreparedExec};
pub use frame_inventory::{
    FrameInventoryAuthority, FrameInventoryError, FrameInventoryReserveError,
    FrameInventorySnapshot, FrameRow, MappingRow,
};
pub use ids::{
    CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, InvalidFileSlot,
    InvalidLinuxSignal, LinuxSignal, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub(crate) use objects::FileDescriptionBacking;
pub use objects::{
    Credentials, FileDescription, FileDescriptionBackingKind, FileDescriptionBackingSnapshot,
    FileSlot, FileTable, FsContext, HandlerFrameState, LinuxWaitStatus, Mm, ObjectGraphError,
    OpenDescriptionBackingSnapshot, PendingQueue, PendingSignal, PidfdTarget, ProcessGroup,
    RunnerDirective, Session, Sighand, SignalAuthority, SignalDequeue, SignalDisposition,
    SignalPendingOwner, Task, TaskKey, TaskLifecycle, TaskPendingSignals, TaskRef, TaskRusage,
    TaskShared, TaskSharedCloneError, TaskWaker, Thread, ThreadKey, ThreadRef, ThreadResources,
    ThreadRunner, ThreadSignalState, Zombie,
};
pub(crate) use operations::ExactSignalTargetAuthorization;
pub use operations::{
    ChildStartOutcome, ChildStartWait, ForkReservation, KernelFailpoint, KernelOperationError,
    PreparedFork, PreparedTaskExit, PreparedThreadClone, PublishedFork, PublishedThreadClone,
    ReservedPidfdSubscription, SignalTargetAuthorization, StartedFork, StartedThreadClone,
    TaskIdentity, TaskOperationReservation, ThreadCloneReservation, WaitMode, WaitOutcome,
};
pub use registry::{
    IdError, IdRegistry, IdRegistryCounts, ProcessGroupClaim, SessionClaim, TaskClaim,
    TaskReservation, ThreadClaim, ThreadReservation,
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
