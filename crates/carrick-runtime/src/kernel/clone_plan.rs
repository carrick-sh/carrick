use carrick_abi::LinuxCloneFlags;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneObjectMode {
    Share,
    Copy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloneTaskMode {
    NewTask,
    JoinThreadGroup,
}

/// Validated Linux clone sharing topology. This deliberately keeps files and
/// fs-context independent from thread-group membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClonePlan {
    task: CloneTaskMode,
    mm: CloneObjectMode,
    sighand: CloneObjectMode,
    files: CloneObjectMode,
    fs_context: CloneObjectMode,
}

impl ClonePlan {
    pub fn from_flags(flags: LinuxCloneFlags) -> Result<Self, ClonePlanError> {
        if flags.contains(LinuxCloneFlags::THREAD) && !flags.contains(LinuxCloneFlags::SIGHAND) {
            return Err(ClonePlanError::ThreadWithoutSighand);
        }
        if flags.contains(LinuxCloneFlags::SIGHAND) && !flags.contains(LinuxCloneFlags::VM) {
            return Err(ClonePlanError::SighandWithoutVm);
        }
        if flags.contains(LinuxCloneFlags::FS) && flags.contains(LinuxCloneFlags::NEWNS) {
            return Err(ClonePlanError::SharedFsWithNewMountNamespace);
        }
        if flags.contains(LinuxCloneFlags::NEWUSER) && flags.contains(LinuxCloneFlags::FS) {
            return Err(ClonePlanError::NewUserWithSharedFs);
        }
        if flags.contains(LinuxCloneFlags::NEWUSER) && flags.contains(LinuxCloneFlags::THREAD) {
            return Err(ClonePlanError::NewUserWithThreadGroup);
        }
        if flags.contains(LinuxCloneFlags::NEWPID) && flags.contains(LinuxCloneFlags::THREAD) {
            return Err(ClonePlanError::NewPidWithThreadGroup);
        }
        if flags.contains(LinuxCloneFlags::PIDFD) && flags.contains(LinuxCloneFlags::THREAD) {
            return Err(ClonePlanError::PidfdWithThreadGroup);
        }

        Ok(Self {
            task: if flags.contains(LinuxCloneFlags::THREAD) {
                CloneTaskMode::JoinThreadGroup
            } else {
                CloneTaskMode::NewTask
            },
            mm: mode(flags.contains(LinuxCloneFlags::VM)),
            sighand: mode(flags.contains(LinuxCloneFlags::SIGHAND)),
            files: mode(flags.contains(LinuxCloneFlags::FILES)),
            fs_context: mode(flags.contains(LinuxCloneFlags::FS)),
        })
    }

    pub const fn task(self) -> CloneTaskMode {
        self.task
    }

    pub const fn mm(self) -> CloneObjectMode {
        self.mm
    }

    pub const fn sighand(self) -> CloneObjectMode {
        self.sighand
    }

    pub const fn files(self) -> CloneObjectMode {
        self.files
    }

    pub const fn fs_context(self) -> CloneObjectMode {
        self.fs_context
    }
}

const fn mode(shared: bool) -> CloneObjectMode {
    if shared {
        CloneObjectMode::Share
    } else {
        CloneObjectMode::Copy
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClonePlanError {
    #[error("CLONE_THREAD requires CLONE_SIGHAND")]
    ThreadWithoutSighand,
    #[error("CLONE_SIGHAND requires CLONE_VM")]
    SighandWithoutVm,
    #[error("CLONE_NEWUSER cannot be combined with CLONE_FS")]
    NewUserWithSharedFs,
    #[error("CLONE_NEWUSER cannot be combined with CLONE_THREAD")]
    NewUserWithThreadGroup,
    #[error("CLONE_NEWPID cannot be combined with CLONE_THREAD")]
    NewPidWithThreadGroup,
    #[error("CLONE_PIDFD cannot be combined with CLONE_THREAD")]
    PidfdWithThreadGroup,
    #[error("CLONE_FS cannot be combined with CLONE_NEWNS")]
    SharedFsWithNewMountNamespace,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_group_does_not_imply_shared_files_or_fs_context() {
        let flags = LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM;
        let plan = ClonePlan::from_flags(flags).expect("valid thread clone");

        assert_eq!(plan.task(), CloneTaskMode::JoinThreadGroup);
        assert_eq!(plan.mm(), CloneObjectMode::Share);
        assert_eq!(plan.sighand(), CloneObjectMode::Share);
        assert_eq!(plan.files(), CloneObjectMode::Copy);
        assert_eq!(plan.fs_context(), CloneObjectMode::Copy);
    }

    #[test]
    fn separate_tasks_may_share_vm_sighand_files_and_fs() {
        let flags = LinuxCloneFlags::VM
            | LinuxCloneFlags::SIGHAND
            | LinuxCloneFlags::FILES
            | LinuxCloneFlags::FS;
        let plan = ClonePlan::from_flags(flags).expect("valid shared process clone");

        assert_eq!(plan.task(), CloneTaskMode::NewTask);
        assert_eq!(plan.mm(), CloneObjectMode::Share);
        assert_eq!(plan.sighand(), CloneObjectMode::Share);
        assert_eq!(plan.files(), CloneObjectMode::Share);
        assert_eq!(plan.fs_context(), CloneObjectMode::Share);
    }

    #[test]
    fn invalid_linux_flag_dependencies_fail_closed() {
        assert_eq!(
            ClonePlan::from_flags(LinuxCloneFlags::THREAD),
            Err(ClonePlanError::ThreadWithoutSighand)
        );
        assert_eq!(
            ClonePlan::from_flags(LinuxCloneFlags::SIGHAND),
            Err(ClonePlanError::SighandWithoutVm)
        );
        assert_eq!(
            ClonePlan::from_flags(LinuxCloneFlags::FS | LinuxCloneFlags::NEWNS),
            Err(ClonePlanError::SharedFsWithNewMountNamespace)
        );
        assert_eq!(
            ClonePlan::from_flags(LinuxCloneFlags::NEWUSER | LinuxCloneFlags::FS),
            Err(ClonePlanError::NewUserWithSharedFs)
        );
        let valid_thread = LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM;
        assert_eq!(
            ClonePlan::from_flags(valid_thread | LinuxCloneFlags::NEWUSER),
            Err(ClonePlanError::NewUserWithThreadGroup)
        );
        assert_eq!(
            ClonePlan::from_flags(valid_thread | LinuxCloneFlags::NEWPID),
            Err(ClonePlanError::NewPidWithThreadGroup)
        );
        assert_eq!(
            ClonePlan::from_flags(valid_thread | LinuxCloneFlags::PIDFD),
            Err(ClonePlanError::PidfdWithThreadGroup)
        );
    }
}
