//! Typed Linux kernel-object vocabulary shared by all execution backends.
//!
//! K1 introduces identity and reservation contracts here while the HVPatch
//! process-bank prototype remains the only multi-task backend implementation.

pub mod address;
pub mod ids;
pub mod registry;

pub use address::{Asid, Stage1Root, Stage1RootError, Ttbr0};
pub use ids::{
    FileDescriptionId, FileTableId, FsContextId, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry,
    ProcessGroupId, SessionId, SighandId, TaskId, TaskSerial, ThreadSerial,
};
pub use registry::{
    IdError, IdRegistry, ProcessGroupClaim, SessionClaim, TaskClaim, TaskReservation, ThreadClaim,
    ThreadReservation,
};
