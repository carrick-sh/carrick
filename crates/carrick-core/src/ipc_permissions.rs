//! Shared SysV IPC access policy. The caller supplies its own credential
//! authority (`NsUid`/`NsGid` on the host-kernel path, `TaskUid`/`TaskGid` on
//! the Linux personality path); this module owns the `ipcperms(5)` class and
//! mode decision.

use bitflags::bitflags;

bitflags! {
    /// Standard SysV IPC permission bits (`ipcperms(5)` low 9 bits, `0o777`).
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct IpcMode: u16 {
        const OWNER_READ = 0o400;
        const OWNER_WRITE = 0o200;
        const OWNER_EXEC = 0o100;
        const GROUP_READ = 0o040;
        const GROUP_WRITE = 0o020;
        const GROUP_EXEC = 0o010;
        const OTHER_READ = 0o004;
        const OTHER_WRITE = 0o002;
        const OTHER_EXEC = 0o001;
    }
}

impl IpcMode {
    /// Construct an [`IpcMode`] from raw permission bits, retaining only the
    /// `0o777` user/group/other access classes.
    pub const fn from_raw(raw: u16) -> Self {
        Self::from_bits_truncate(raw)
    }

    const fn folded_class_bits(self) -> u16 {
        let bits = self.bits();
        ((bits >> 6) | (bits >> 3) | bits) & 0o7
    }

    const fn owner_class_bits(self) -> u16 {
        (self.bits() >> 6) & 0o7
    }

    const fn group_class_bits(self) -> u16 {
        (self.bits() >> 3) & 0o7
    }

    const fn other_class_bits(self) -> u16 {
        self.bits() & 0o7
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcPermission<U, G> {
    pub uid: U,
    pub cuid: U,
    pub gid: G,
    pub cgid: G,
    pub mode: IpcMode,
}

impl<U: Copy + Eq, G: Copy + Eq> IpcPermission<U, G> {
    /// `has_group` includes effective and supplementary membership. `bypass`
    /// is the caller authority's effective `CAP_IPC_OWNER` decision.
    pub fn allows(
        self,
        caller: U,
        has_group: impl Fn(G) -> bool,
        bypass: bool,
        requested_mode: IpcMode,
    ) -> bool {
        if bypass {
            return true;
        }
        let req = requested_mode.folded_class_bits();
        let granted = if caller == self.uid || caller == self.cuid {
            self.mode.owner_class_bits()
        } else if has_group(self.gid) || has_group(self.cgid) {
            self.mode.group_class_bits()
        } else {
            self.mode.other_class_bits()
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
            uid: 10u32,
            cuid: 11u32,
            gid: 20u32,
            cgid: 21u32,
            mode: IpcMode::GROUP_READ,
        };
        assert!(p.allows(12, |g| g == 21, false, IpcMode::OWNER_READ));
        assert!(!p.allows(10, |_| true, false, IpcMode::OWNER_READ));
        assert!(p.allows(11, |_| false, true, IpcMode::OWNER_WRITE));
        assert!(!p.allows(12, |_| false, false, IpcMode::OWNER_READ));
    }
}
