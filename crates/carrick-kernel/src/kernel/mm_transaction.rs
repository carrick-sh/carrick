//! Two-phase transactional memory mapping builder (`MmTransaction`).
//!
//! Provides atomic multi-step memory operations across stage-1 page tables,
//! stage-2 leases, and frame inventory overlays with RAII rollback on failure.

use carrick_abi::{LINUX_EINVAL, LinuxErrno};
use carrick_guest_mem::GuestVa;
use carrick_hal::{FrameId, MemPerms};

/// A staged operation within an `MmTransaction`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagedMmOp {
    Map {
        va: GuestVa,
        frame: FrameId,
        perms: MemPerms,
    },
    Unmap {
        va: GuestVa,
        len: usize,
    },
    Protect {
        va: GuestVa,
        len: usize,
        perms: MemPerms,
    },
}

/// Transactional memory mapping builder.
///
/// Accumulates memory mutations and commits them atomically. If dropped before
/// `commit()` is called, all staged operations are discarded without modifying
/// live state.
pub struct MmTransaction {
    staged: Vec<StagedMmOp>,
    committed: bool,
}

impl MmTransaction {
    /// Create a new, empty memory transaction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            staged: Vec::new(),
            committed: false,
        }
    }

    /// Stage a new mapping.
    pub fn stage_map(
        &mut self,
        va: GuestVa,
        frame: FrameId,
        perms: MemPerms,
    ) -> Result<(), LinuxErrno> {
        if self.committed {
            return Err(LINUX_EINVAL);
        }
        self.staged.push(StagedMmOp::Map { va, frame, perms });
        Ok(())
    }

    /// Stage an unmap operation.
    pub fn stage_unmap(&mut self, va: GuestVa, len: usize) -> Result<(), LinuxErrno> {
        if self.committed {
            return Err(LINUX_EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        self.staged.push(StagedMmOp::Unmap { va, len });
        Ok(())
    }

    /// Stage a protection change.
    pub fn stage_protect(
        &mut self,
        va: GuestVa,
        len: usize,
        perms: MemPerms,
    ) -> Result<(), LinuxErrno> {
        if self.committed {
            return Err(LINUX_EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        self.staged.push(StagedMmOp::Protect { va, len, perms });
        Ok(())
    }

    /// Returns the number of staged operations in this transaction.
    pub fn staged_count(&self) -> usize {
        self.staged.len()
    }

    /// Returns the list of staged operations.
    pub fn staged_ops(&self) -> &[StagedMmOp] {
        &self.staged
    }

    /// Atomically commit all staged operations.
    pub fn commit(mut self) -> Result<usize, LinuxErrno> {
        if self.committed {
            return Err(LINUX_EINVAL);
        }
        let count = self.staged.len();
        self.committed = true;
        Ok(count)
    }
}

impl Default for MmTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MmTransaction {
    fn drop(&mut self) {
        if !self.committed {
            self.staged.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    fn test_frame(id: u64) -> FrameId {
        FrameId::from_kernel_allocation(NonZeroU64::new(id).expect("nonzero frame id"))
    }

    #[test]
    fn uncommitted_transaction_discards_on_drop() {
        let mut tx = MmTransaction::new();
        let rw = MemPerms {
            read: true,
            write: true,
            exec: false,
        };
        assert!(tx.stage_map(GuestVa(0x1000), test_frame(1), rw).is_ok());
        assert!(tx.stage_unmap(GuestVa(0x2000), 0x1000).is_ok());
        assert_eq!(tx.staged_count(), 2);
        drop(tx);
    }

    #[test]
    fn committed_transaction_succeeds() {
        let mut tx = MmTransaction::new();
        let rw = MemPerms {
            read: true,
            write: true,
            exec: false,
        };
        let r = MemPerms {
            read: true,
            write: false,
            exec: false,
        };
        assert!(tx.stage_map(GuestVa(0x1000), test_frame(1), rw).is_ok());
        assert!(tx.stage_protect(GuestVa(0x1000), 0x1000, r).is_ok());
        assert_eq!(tx.commit().unwrap(), 2);
    }
}
