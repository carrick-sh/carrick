//! Linux `arch_prctl(2)` syscall policy.
use carrick_guest_arch::{CurrentMmMemory, SegmentBaseRegs};
pub use carrick_syscall_abi::syscall_x86_64::ARCH_PRCTL_NR;
use carrick_syscall_abi::{LINUX_EFAULT, LINUX_EINVAL, LINUX_ENODEV, LINUX_EPERM};

/// `ARCH_SET_GS` (arch_prctl(2)).
pub const ARCH_SET_GS: u64 = 0x1001;
/// `ARCH_SET_FS` (arch_prctl(2)).
pub const ARCH_SET_FS: u64 = 0x1002;
/// `ARCH_GET_FS` (arch_prctl(2)).
pub const ARCH_GET_FS: u64 = 0x1003;
/// `ARCH_GET_GS` (arch_prctl(2)).
pub const ARCH_GET_GS: u64 = 0x1004;
/// `ARCH_GET_CPUID` (arch_prctl(2)).
pub const ARCH_GET_CPUID: u64 = 0x1011;
/// `ARCH_SET_CPUID` (arch_prctl(2)).
pub const ARCH_SET_CPUID: u64 = 0x1012;

/// Linux policy for `arch_prctl(2)`.
pub fn service_arch_prctl<E>(engine: &mut E, code: u64, addr: u64) -> Result<i64, E::Error>
where
    E: SegmentBaseRegs + CurrentMmMemory,
{
    match code {
        ARCH_SET_FS => {
            if addr >= 0x0000_8000_0000_0000 {
                Ok(LINUX_EPERM.guest_retval())
            } else {
                engine.seg_set_fs_base(addr)?;
                Ok(0)
            }
        }
        ARCH_GET_FS => {
            let base = engine.seg_get_fs_base()?;
            if engine.write_bytes(addr, &base.to_le_bytes()).is_err() {
                Ok(LINUX_EFAULT.guest_retval())
            } else {
                Ok(0)
            }
        }
        ARCH_SET_GS => {
            if addr >= 0x0000_8000_0000_0000 {
                Ok(LINUX_EPERM.guest_retval())
            } else {
                engine.seg_set_gs_base(addr)?;
                Ok(0)
            }
        }
        ARCH_GET_GS => {
            let base = engine.seg_get_gs_base()?;
            if engine.write_bytes(addr, &base.to_le_bytes()).is_err() {
                Ok(LINUX_EFAULT.guest_retval())
            } else {
                Ok(0)
            }
        }
        ARCH_GET_CPUID => {
            // Linux returns -ENODEV when cpuid faulting is not supported on
            // this processor/kernel (arch_prctl(2) manual).
            Ok(LINUX_ENODEV.guest_retval())
        }
        ARCH_SET_CPUID => Ok(LINUX_ENODEV.guest_retval()),
        _ => Ok(LINUX_EINVAL.guest_retval()),
    }
}
