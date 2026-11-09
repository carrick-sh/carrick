//! Host IPC operations retained across another party's held IPC lock (#1845).
//!
//! A host IPC operation that meets a held lock does not spin on it: the lock
//! policy refuses ([`crate::el1_ipc::IpcCreateLockWait`]), and the operation
//! returns [`crate::dispatch::DispatchOutcome::IpcLockContended`] with
//! everything it already did. The runtime enrolls a zone record on the held
//! lock's release ([`RetainedIpcLockOperation::defer`]), releases its
//! execution lease, and resumes this exact operation when the release hands
//! the record back. That is the owner-memory park's zone path and killable
//! gate; only the enrollment differs, and it is kernel-side (no portal or
//! wire cause).
//!
//! Interruption: the retained operations are Linux calls that never sleep
//! interruptibly (`pipe2(2)` never fails with EINTR), so an ordinary caught
//! signal or a job-control stop leaves the operation parked; it is
//! delivered at the syscall boundary after completion. Only terminal
//! cancellation (SIGKILL, group exit, exec, carrier teardown) drops it, and
//! dropping rolls back exactly what it owns.
//!
//! x86/CPL0 venues have no host zone (`crate::el1_zone::zone` is `None`), so
//! they never bind through the refusing policy and never see this outcome
//! (seam #1059).

use crate::dispatch::GuestPtr;
use carrick_sched_core::RecordId;
use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken};

/// One retained host IPC operation, waiting for an IPC lock's release.
pub struct RetainedIpcLockOperation {
    operation: IpcLockOperation,
}

enum IpcLockOperation {
    Pipe2(RetainedPipe2),
}

/// A `pipe2` whose create met a held readiness-lane lock: its validated
/// arguments, the pipe id it was assigned, and the unpublished object with
/// the lanes already bound. No descriptor or output permit is retained.
pub struct RetainedPipe2 {
    pipefd: GuestPtr,
    flags: u64,
    pipe_id: u64,
    create: crate::el1_ipc::PendingPipeCreate,
}

impl RetainedPipe2 {
    pub(crate) fn into_parts(self) -> (GuestPtr, u64, u64, crate::el1_ipc::PendingPipeCreate) {
        (self.pipefd, self.flags, self.pipe_id, self.create)
    }
}

impl RetainedIpcLockOperation {
    pub(crate) fn pipe2(
        pipefd: GuestPtr,
        flags: u64,
        pipe_id: u64,
        create: crate::el1_ipc::PendingPipeCreate,
    ) -> Self {
        Self {
            operation: IpcLockOperation::Pipe2(RetainedPipe2 {
                pipefd,
                flags,
                pipe_id,
                create,
            }),
        }
    }

    /// The syscall this operation completes.
    pub fn syscall(&self) -> carrick_abi::CanonicalNr {
        match &self.operation {
            IpcLockOperation::Pipe2(_) => carrick_abi::syscall::nr::PIPE2,
        }
    }

    /// The zone whose lock this operation waits for.
    pub fn zone(&self) -> &'static carrick_el1_abi::ZoneTables {
        match &self.operation {
            IpcLockOperation::Pipe2(pipe2) => pipe2.create.zone(),
        }
    }

    /// The retained `pipe2` create, for witnesses: its unpublished object and
    /// how many readiness lanes it already owns.
    pub fn pipe2_progress(&self) -> Option<(carrick_el1_abi::ipc::IpcObjectHandle, usize)> {
        match &self.operation {
            IpcLockOperation::Pipe2(pipe2) => pipe2
                .create
                .object()
                .map(|object| (object, pipe2.create.bound_lanes())),
        }
    }

    /// Enroll `record` (holding `token`) on the held lock's existing
    /// admission chain. The operation itself stays with the caller. A
    /// release that already happened hands the record back at once, so the
    /// caller always settles into the zone after success and never misses a
    /// release. On failure nothing was transferred: free the record and
    /// rerun the operation now.
    pub fn defer(
        &self,
        record: RecordId,
        token: OperationToken,
    ) -> Result<(), (ObjectWaitError, OperationToken)> {
        let custody = match &self.operation {
            IpcLockOperation::Pipe2(pipe2) => pipe2.create.readiness_custody(),
        };
        let custody = match custody {
            Ok(custody) => custody,
            Err(error) => return Err((error, token)),
        };
        custody.defer(record, token, &|owned| {
            crate::el1_zone::complete_object_wake(owned.zone(), owned)
        })
    }

    pub(crate) fn into_pipe2(self) -> Option<RetainedPipe2> {
        match self.operation {
            IpcLockOperation::Pipe2(pipe2) => Some(pipe2),
        }
    }
}

impl std::fmt::Debug for RetainedIpcLockOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.operation {
            IpcLockOperation::Pipe2(pipe2) => f
                .debug_struct("RetainedIpcLockOperation::Pipe2")
                .field("pipefd", &pipe2.pipefd)
                .field("flags", &pipe2.flags)
                .field("create", &pipe2.create)
                .finish(),
        }
    }
}

/// A retained operation is unique: equal only to itself.
impl PartialEq for RetainedIpcLockOperation {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}
impl Eq for RetainedIpcLockOperation {}
