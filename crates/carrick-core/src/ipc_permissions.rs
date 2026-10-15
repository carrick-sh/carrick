//! Shared SysV IPC access policy. The caller supplies its own credential
//! authority; this module owns the ipcperms(5) class and mode decision.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcUserId(u32);

impl IpcUserId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcGroupId(u32);

impl IpcGroupId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }
    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcPermission {
    pub uid: IpcUserId,
    pub cuid: IpcUserId,
    pub gid: IpcGroupId,
    pub cgid: IpcGroupId,
    pub mode: u16,
}

impl IpcPermission {
    /// `has_group` includes effective and supplementary membership. `bypass`
    /// is the caller authority's effective CAP_IPC_OWNER decision.
    pub fn allows(
        self,
        caller: IpcUserId,
        has_group: impl Fn(IpcGroupId) -> bool,
        bypass: bool,
        requested_mode: u16,
    ) -> bool {
        if bypass {
            return true;
        }
        let req = ((requested_mode >> 6) | (requested_mode >> 3) | requested_mode) & 0o7;
        let granted = if caller == self.uid || caller == self.cuid {
            (self.mode >> 6) & 0o7
        } else if has_group(self.gid) || has_group(self.cgid) {
            (self.mode >> 3) & 0o7
        } else {
            self.mode & 0o7
        };
        req & !granted == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_group_and_other_are_exclusive_classes() {
        let p = IpcPermission {
            uid: IpcUserId::new(10),
            cuid: IpcUserId::new(11),
            gid: IpcGroupId::new(20),
            cgid: IpcGroupId::new(21),
            mode: 0o040,
        };
        assert!(p.allows(
            IpcUserId::new(12),
            |g| g == IpcGroupId::new(21),
            false,
            0o400
        ));
        assert!(!p.allows(IpcUserId::new(10), |_| true, false, 0o400));
        assert!(p.allows(IpcUserId::new(11), |_| false, true, 0o200));
        assert!(!p.allows(IpcUserId::new(12), |_| false, false, 0o400));
    }
}
