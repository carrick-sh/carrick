//! In-guest signal ABI structures and constants.

use carrick_syscall_abi::LinuxErrno;

pub const RT_SIGSET_SIZE: u64 = 8;
pub const LINUX_SIGSET_WORDS: usize = 1;
pub const LINUX_SIGINFO_SIZE: usize = 128;
pub const LINUX_UCONTEXT_SIGMASK_PAD_BYTES: usize = 120;
pub const LINUX_AARCH64_SIGCONTEXT_RESERVED_BYTES: usize = 4096;

pub const LINUX_SI_USER: i32 = 0;
pub const LINUX_SI_KERNEL: i32 = 128;
pub const LINUX_SI_QUEUE: i32 = -1;
pub const LINUX_SI_TIMER: i32 = -2;
pub const LINUX_SI_MESGQ: i32 = -3;
pub const LINUX_SI_TKILL: i32 = -6;
pub const LINUX_POLL_MSG: i32 = 3;

pub const LINUX_EPERM: LinuxErrno = LinuxErrno::new(1);
pub const LINUX_ESRCH: LinuxErrno = LinuxErrno::new(3);
pub const LINUX_EINTR: LinuxErrno = LinuxErrno::new(4);
pub const LINUX_EBADF: LinuxErrno = LinuxErrno::new(9);
pub const LINUX_ECHILD: LinuxErrno = carrick_syscall_abi::LINUX_ECHILD;
pub const LINUX_EAGAIN: LinuxErrno = carrick_syscall_abi::LINUX_EAGAIN;
pub const LINUX_EFAULT: LinuxErrno = carrick_syscall_abi::LINUX_EFAULT;
pub const LINUX_EINVAL: LinuxErrno = carrick_syscall_abi::LINUX_EINVAL;
pub const LINUX_ENOSYS: LinuxErrno = LinuxErrno::new(38);

// One wire-format definition is shared with host delivery and both ring ISAs.
pub use carrick_abi::{
    CARRICK_SIGFRAME_MAGIC, CarrickSigframe, LinuxSigaction, LinuxSiginfo, LinuxSignalContext,
    LinuxSignalStack, LinuxUcontext, X8664Rtsigframe, X8664Sigcontext, X8664Ucontext,
};
