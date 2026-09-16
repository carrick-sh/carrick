//! Process-lifecycle facts the kernel graph owns: what a reaped child reports,
//! what a thread exit leaves behind, and how an identity operation lowers to an
//! errno.
//!
//! Every value here is keyed by a `TaskKey`/`TaskId` and carries no carrier
//! state — no stage-1 mm, no VM, no host process — so none of it is HVPatch's
//! to own. They lived in `hvpatch/mod.rs` only because the HVPatch carrier was
//! their first caller; `dispatch/proc.rs`, `dispatch/mqueue.rs`,
//! `kernel/operations/session.rs` and `vcpu_loop/threads.rs` name them too.

/// What a single reaped or observed child transition reports to `wait`.
///
/// `visible_pid` is the PID-namespace identity the guest is owed, captured at
/// wait time: the internal [`crate::kernel::TaskId`] is the carrier-wide key
/// and is not what a guest sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildExit {
    pid: crate::kernel::TaskId,
    visible_pid: i32,
    ruid: carrick_abi::NsUid,
    status: i32,
}

impl ChildExit {
    pub(crate) const fn new(
        pid: crate::kernel::TaskId,
        visible_pid: i32,
        ruid: carrick_abi::NsUid,
        status: i32,
    ) -> Self {
        Self {
            pid,
            visible_pid,
            ruid,
            status,
        }
    }

    #[cfg(test)]
    pub(crate) const fn pid(self) -> crate::kernel::TaskId {
        self.pid
    }

    pub(crate) const fn visible_pid(self) -> i32 {
        self.visible_pid
    }

    pub(crate) const fn status(self) -> i32 {
        self.status
    }

    pub(crate) const fn ruid(self) -> carrick_abi::NsUid {
        self.ruid
    }
}

/// A retiring thread's exact owner and file table, captured as one receipt so a
/// caller draining it names that generation rather than re-reading the graph.
#[derive(Clone, Debug)]
pub(crate) struct RetiredThreadResources {
    owner: crate::kernel::TaskKey,
    files: std::sync::Arc<crate::kernel::FileTable>,
}

impl RetiredThreadResources {
    pub(crate) const fn new(
        owner: crate::kernel::TaskKey,
        files: std::sync::Arc<crate::kernel::FileTable>,
    ) -> Self {
        Self { owner, files }
    }

    pub(crate) const fn owner(&self) -> crate::kernel::TaskKey {
        self.owner
    }

    pub(crate) fn files(&self) -> std::sync::Arc<crate::kernel::FileTable> {
        std::sync::Arc::clone(&self.files)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ProcessThreadExit {
    Retired(RetiredThreadResources),
    AlreadyRetired,
    LastThread,
    /// The kernel graph holds a task reservation (a sibling's exec/fork/exit
    /// transaction in flight). The caller must NOT block an executor waiting
    /// for it: an exec survivor's ASID-ack wait can be the reservation
    /// holder, and it needs THIS executor back at its command-service point
    /// (the execfromthread ABBA wedge: leader parked on the reservation
    /// condvar inside its exit while the survivor's executor waited for the
    /// leader's ack). Carries the observed reservation epoch so the caller
    /// can subscribe for the change and park as a scheduler-visible retry,
    /// exactly like the thread-clone TaskBusy path.
    Busy {
        observed_epoch: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitResult {
    Exited(ChildExit),
    StateChanged(ChildExit),
    StillRunning(crate::kernel::ChildWaitPrecheck),
    NoChild,
}

/// The errno a guest-identity operation on the kernel graph reports.
///
/// Shared with the `setpgid`/`setsid` dispatch paths so an identity failure has
/// ONE spelling: those used to reach this through per-call wrappers on
/// `ProcessContext`, which existed only because the dispatch side could not see
/// the graph directly. It can, so the wrappers are gone.
pub(crate) fn identity_operation_errno(
    error: crate::kernel::KernelOperationError,
) -> crate::linux_abi::LinuxErrno {
    match error {
        crate::kernel::KernelOperationError::UnknownTask(_) => crate::linux_abi::LINUX_ESRCH,
        // setpgid(2) singles this case out: "EACCES — An attempt was made to
        // change the process group ID of one of the children of the calling
        // process and the child had already performed an execve(2)." The kernel
        // graph models it exactly (`ChildExeced` off a real `has_execed` flag),
        // and the pre-HVPatch path already returned EACCES; only this errno
        // mapping collapsed it into the neighbouring EPERM cases.
        crate::kernel::KernelOperationError::ChildExeced(_) => crate::linux_abi::LINUX_EACCES,
        // setsid(2) refuses with EPERM when "the process group ID of any
        // process equals the PID of the calling process" — not only when the
        // caller is still that group's member. LTP `setsid01` leaves its own
        // group behind with a child in it and expects EPERM; the catch-all
        // below reported EINVAL.
        crate::kernel::KernelOperationError::IdentityPermission
        | crate::kernel::KernelOperationError::AlreadyProcessGroupLeader
        | crate::kernel::KernelOperationError::IdentityInUseByCallerPid => {
            crate::linux_abi::LINUX_EPERM
        }
        _ => crate::linux_abi::LINUX_EINVAL,
    }
}
