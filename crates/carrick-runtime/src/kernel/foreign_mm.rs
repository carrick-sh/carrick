//! Typed foreign address-space access for cross-process memory operations
//! (such as `process_vm_readv`, `process_vm_writev`, `/proc/<pid>/mem`).

use super::address::VmaSummary;
use super::core::Kernel;
use super::ids::TaskId;
use carrick_abi::{LINUX_EFAULT, LINUX_ESRCH, LinuxErrno};

/// Temporary crate-private VMA-only compatibility view for the not-yet-migrated
/// process_vm consumer. It carries no read authority; Task 8 removes it when
/// that consumer switches to `ForeignMm` plus `MmAccessAuthority`.
#[derive(Clone, Debug)]
pub(crate) struct ForeignMmAccess {
    _target_pid: TaskId,
    vmas: Vec<VmaSummary>,
}

impl ForeignMmAccess {
    /// Authenticates and creates a foreign MM access handle for `target_pid`.
    pub(crate) fn for_task(kernel: &Kernel, target_pid: TaskId) -> Result<Self, LinuxErrno> {
        let task = kernel.registry().task(target_pid).ok_or(LINUX_ESRCH)?;
        let mm = task.shared().mm();
        let backend = mm.backend().ok_or(LINUX_EFAULT)?;
        let snapshot = backend
            .snapshot(std::time::Instant::now() + std::time::Duration::from_millis(50))
            .map_err(|_| LINUX_EFAULT)?;

        Ok(Self {
            _target_pid: target_pid,
            vmas: snapshot.vmas,
        })
    }

    /// Checks if a guest virtual address range is mapped in the target address space.
    pub(crate) fn is_range_mapped(&self, va: u64, len: usize) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::super::VmaAccess;
    use super::*;
    use carrick_guest_mem::GuestVa;

    #[test]
    fn mapped_range_validation() {
        let access = ForeignMmAccess {
            _target_pid: TaskId::from_abi_positive(1).expect("positive task id"),
            vmas: vec![
                VmaSummary {
                    start: GuestVa(0x1000),
                    end: GuestVa(0x3000),
                    access: VmaAccess {
                        readable: true,
                        writable: false,
                        executable: false,
                        kernel_visible: true,
                    },
                },
                VmaSummary {
                    start: GuestVa(0x4000),
                    end: GuestVa(0x5000),
                    access: VmaAccess {
                        readable: true,
                        writable: true,
                        executable: false,
                        kernel_visible: true,
                    },
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
