use super::types::{DescriptionBackingSnapshot, VfsObjectId};

/// Actual authority-owned payload for an open file description.
///
/// This deliberately begins with two fully functional backings rather than a
/// metadata shell. Further host-backed and readiness/transfer variants are
/// added here as their operation families move behind the same closed API.
#[derive(Debug)]
pub(super) enum AuthorityBacking {
    SyntheticFile { contents: Vec<u8> },
    VfsFile { object: VfsObjectId },
}

impl AuthorityBacking {
    pub(super) fn snapshot(&self) -> DescriptionBackingSnapshot {
        match self {
            Self::SyntheticFile { contents } => DescriptionBackingSnapshot::Synthetic {
                length: u64::try_from(contents.len()).unwrap_or(u64::MAX),
            },
            Self::VfsFile { object } => DescriptionBackingSnapshot::VfsFile { object: *object },
        }
    }

    pub(super) const fn vfs_object(&self) -> Option<VfsObjectId> {
        match self {
            Self::SyntheticFile { .. } => None,
            Self::VfsFile { object } => Some(*object),
        }
    }
}
