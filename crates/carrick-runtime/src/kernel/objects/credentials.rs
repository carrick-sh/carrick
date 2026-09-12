use carrick_abi::{NsGid, NsUid};

use crate::kernel::ids::CredentialsId;
use crate::linux_abi::LINUX_DEFAULT_UMASK;

/// Immutable Linux credential register file. A mutation publishes a fresh
/// Thread credentials. `clone` creates an independent copy; `set*uid`/`set*gid`
/// creates a new [`Credentials`] object and replaces only the calling thread's
/// `ThreadResources` association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    id: CredentialsId,
    pub(crate) ruid: NsUid,
    pub(crate) euid: NsUid,
    pub(crate) suid: NsUid,
    pub(crate) rgid: NsGid,
    pub(crate) egid: NsGid,
    pub(crate) sgid: NsGid,
    pub(crate) fsuid: NsUid,
    pub(crate) fsgid: NsGid,
    pub(crate) umask: u32,
    /// `None` preserves launch-time `/etc/group` fallback; `Some`, including an
    /// empty vector, is the complete set installed by `setgroups(2)`.
    supplementary_groups_override: Option<Vec<NsGid>>,
}

impl Credentials {
    pub const fn root(id: CredentialsId) -> Self {
        Self {
            id,
            ruid: NsUid::ROOT,
            euid: NsUid::ROOT,
            suid: NsUid::ROOT,
            rgid: NsGid::ROOT,
            egid: NsGid::ROOT,
            sgid: NsGid::ROOT,
            fsuid: NsUid::ROOT,
            fsgid: NsGid::ROOT,
            umask: LINUX_DEFAULT_UMASK,
            supplementary_groups_override: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn from_values(
        id: CredentialsId,
        ruid: NsUid,
        euid: NsUid,
        suid: NsUid,
        rgid: NsGid,
        egid: NsGid,
        sgid: NsGid,
        fsuid: NsUid,
        fsgid: NsGid,
        umask: u32,
    ) -> Self {
        Self {
            id,
            ruid,
            euid,
            suid,
            rgid,
            egid,
            sgid,
            fsuid,
            fsgid,
            umask,
            supplementary_groups_override: None,
        }
    }

    pub(in crate::kernel) fn for_copy(id: CredentialsId, source: &Self) -> Self {
        let mut copy = source.clone();
        copy.id = id;
        copy
    }

    pub const fn id(&self) -> CredentialsId {
        self.id
    }
    pub const fn ruid(&self) -> NsUid {
        self.ruid
    }
    pub const fn euid(&self) -> NsUid {
        self.euid
    }
    pub const fn suid(&self) -> NsUid {
        self.suid
    }
    pub const fn rgid(&self) -> NsGid {
        self.rgid
    }
    pub const fn egid(&self) -> NsGid {
        self.egid
    }
    pub const fn sgid(&self) -> NsGid {
        self.sgid
    }
    pub const fn fsuid(&self) -> NsUid {
        self.fsuid
    }
    pub const fn fsgid(&self) -> NsGid {
        self.fsgid
    }
    pub const fn umask(&self) -> u32 {
        self.umask
    }
    pub fn supplementary_groups_override(&self) -> Option<&[NsGid]> {
        self.supplementary_groups_override.as_deref()
    }

    pub(crate) fn seed_identity(&mut self, uid: NsUid, gid: NsGid) {
        self.ruid = uid;
        self.euid = uid;
        self.suid = uid;
        self.fsuid = uid;
        self.rgid = gid;
        self.egid = gid;
        self.sgid = gid;
        self.fsgid = gid;
    }

    pub(crate) const fn is_privileged(&self) -> bool {
        self.euid.is_root()
    }
    pub(crate) fn set_uid_triple(&mut self, ruid: NsUid, euid: NsUid, suid: NsUid) {
        self.ruid = ruid;
        self.euid = euid;
        self.suid = suid;
        self.fsuid = euid;
    }
    pub(crate) fn set_gid_triple(&mut self, rgid: NsGid, egid: NsGid, sgid: NsGid) {
        self.rgid = rgid;
        self.egid = egid;
        self.sgid = sgid;
        self.fsgid = egid;
    }
    pub(crate) fn set_fsuid(&mut self, fsuid: NsUid) {
        self.fsuid = fsuid;
    }
    pub(crate) fn set_fsgid(&mut self, fsgid: NsGid) {
        self.fsgid = fsgid;
    }
    pub(crate) fn set_umask(&mut self, umask: u32) {
        self.umask = umask;
    }
    pub(crate) fn set_supplementary_groups(&mut self, groups: Vec<NsGid>) {
        self.supplementary_groups_override = Some(groups);
    }
    pub(crate) fn copy_values_from(&mut self, source: &Self) {
        self.ruid = source.ruid;
        self.euid = source.euid;
        self.suid = source.suid;
        self.rgid = source.rgid;
        self.egid = source.egid;
        self.sgid = source.sgid;
        self.fsuid = source.fsuid;
        self.fsgid = source.fsgid;
        self.umask = source.umask;
        self.supplementary_groups_override = source.supplementary_groups_override.clone();
    }
}
