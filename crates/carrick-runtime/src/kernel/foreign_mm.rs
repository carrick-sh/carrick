//! Typed foreign address-space access for cross-process memory operations
//! (such as `process_vm_readv`, `process_vm_writev`, `/proc/<pid>/mem`).

use super::address::VmaSummary;
use super::core::Kernel;
use super::ids::TaskId;
use carrick_abi::{LINUX_EFAULT, LINUX_ESRCH, LinuxErrno};

/// A validated reference to another process's address space.
#[derive(Clone, Debug)]
pub struct ForeignMmAccess {
    target_pid: TaskId,
    vmas: Vec<VmaSummary>,
}

impl ForeignMmAccess {
    /// Authenticates and creates a foreign MM access handle for `target_pid`.
    pub fn for_task(kernel: &Kernel, target_pid: TaskId) -> Result<Self, LinuxErrno> {
        let task = kernel.registry().task(target_pid).ok_or(LINUX_ESRCH)?;
        let mm = task.shared().mm();
        let backend = mm.backend().ok_or(LINUX_EFAULT)?;
        let snapshot = backend
            .snapshot(std::time::Instant::now() + std::time::Duration::from_millis(50))
            .map_err(|_| LINUX_EFAULT)?;

        Ok(Self {
            target_pid,
            vmas: snapshot.vmas,
        })
    }

    /// Checks if a guest virtual address range is mapped in the target address space.
    pub fn is_range_mapped(&self, va: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let end = match va.checked_add(len as u64) {
            Some(e) => e,
            None => return false,
        };
        let mut cur = va;
        while cur < end {
            if let Some(vma) = self
                .vmas
                .iter()
                .find(|v| cur >= v.start.raw() && cur < v.end.raw())
            {
                cur = vma.end.raw();
            } else {
                return false;
            }
        }
        true
    }

    pub fn target_pid(&self) -> TaskId {
        self.target_pid
    }

    pub fn vmas(&self) -> &[VmaSummary] {
        &self.vmas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_guest_mem::GuestVa;

    #[test]
    fn mapped_range_validation() {
        let access = ForeignMmAccess {
            target_pid: TaskId::from_abi_positive(1).expect("positive task id"),
            vmas: vec![
                VmaSummary {
                    start: GuestVa(0x1000),
                    end: GuestVa(0x3000),
                },
                VmaSummary {
                    start: GuestVa(0x4000),
                    end: GuestVa(0x5000),
                },
            ],
        };

        assert!(access.is_range_mapped(0x1000, 0x2000));
        assert!(access.is_range_mapped(0x1500, 0x500));
        assert!(!access.is_range_mapped(0x2500, 0x1000)); // Crosses into unmapped hole 0x3000..0x4000
        assert!(!access.is_range_mapped(0x3000, 0x100));
        assert!(access.is_range_mapped(0x4000, 0x1000));
    }
}
