//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here while the HVPatch
//! process-bank prototype remains the only multi-task backend implementation.

pub mod address;
pub mod clone_plan;
pub mod ids;
pub mod objects;
pub mod registry;

pub use address::{Asid, Stage1Root, Stage1RootError, Ttbr0};
pub use clone_plan::{CloneObjectMode, ClonePlan, ClonePlanError, CloneTaskMode};
pub use ids::{
    FileDescriptionId, FileTableId, FsContextId, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub use objects::{
    Credentials, FileDescription, FileTable, FsContext, LinuxWaitStatus, Mm, ObjectGraphError,
    PidfdTarget, ProcessGroup, Session, Sighand, Task, TaskKey, TaskLifecycle, TaskPendingSignals,
    TaskRef, TaskRusage, TaskShared, TaskSharedCloneError, Thread, ThreadKey, ThreadRef,
    ThreadResources, Zombie,
};
pub use registry::{
    IdError, IdRegistry, ProcessGroupClaim, SessionClaim, TaskClaim, TaskReservation, ThreadClaim,
    ThreadReservation,
};
